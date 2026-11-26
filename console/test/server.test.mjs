// node --test console/test/server.test.mjs
//
// 1. UDS framing roundtrip against a mock Unix socket server
// 2. Live integration against target/debug/control-d (skipped if not built),
//    including the Phase 8 actions API over the real admin/investigate sockets
// 3. Demo-mode API walkthrough
// 4. Security headers, Host/Origin validation and XSS hygiene
// 5. Phase 8 mitigations in demo mode (signed intents, approval rules, lifecycle)
// 6. Access gate: --create-user, local sessions, rate limiting, roles
// 7. Access gate: trusted reverse-proxy identity headers
// 8. Mitigation proposals (demo + exact mock frames), stream watches, per-run
//    token isolation against the real control-d (fake agent opens incidents)
// 9. Reasoner activity (demo, mock frames, real control-d)
// 10. Expectation rules (demo, mock frames, real control-d: create, backtest,
//     list, revoke, investigator proposal approved through the console)
// 11. Adaptive investigator P11–P18 (demo, exact mock frames, pre-P11
//     degradation, roles and token isolation, real control-d quiet host)

import { describe, test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import vm from 'node:vm';
import { spawn, spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

import { AdminClient, FrameDecoder, FrameError, InvestigationClient, MAX_FRAME_BYTES, encodeFrame, udsRequest } from '../lib/uds-client.mjs';
import { canonicalJson, computeAuditHash, sha256Hex, verifyEntries } from '../lib/audit-chain.mjs';
import { SESSION_COOKIE, createAuth, createPeerMatcher, normalizeIp, readUsersFile, upsertUser } from '../lib/auth.mjs';
import { createDemoBackend } from '../lib/demo-data.mjs';
import { createLiveBackend } from '../lib/live-backend.mjs';
import { deriveThreeState } from '../lib/domain.mjs';
import { createConsoleServer, parseArgs, runCreateUser } from '../server.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CONSOLE_DIR = path.resolve(HERE, '..');
const REPO = path.resolve(CONSOLE_DIR, '..');
const CONTROL_D = path.join(REPO, 'target', 'debug', 'control-d');
const ALL_COLLECTORS = ['sockets.listening', 'systemd.unit_state', 'files.metadata', 'journal.unit_events'];
/** Every CollectorType in crates/protocol/src/watch.rs (P11 added outbound connections and packages). */
const EVERY_COLLECTOR = [...ALL_COLLECTORS, 'connections.outbound', 'packages.inventory'];

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// sun_path holds 108 bytes on Linux and 104 on macOS, including the NUL. The
// longest socket path these tests build is <dir>/<leaf> with a leaf of at most
// SOCKET_LEAF_BYTES, and mkdtemp appends six characters to the prefix.
const SUN_PATH_MAX = 103;
const SOCKET_LEAF_BYTES = 16; // e.g. "/missing.sock" plus margin

/** A fresh temp directory whose socket paths always fit sun_path, even under a long TMPDIR. */
function shortTmp(prefix = 'dsc-') {
  const fits = (base) => Buffer.byteLength(path.join(base, `${prefix}XXXXXX`)) + SOCKET_LEAF_BYTES <= SUN_PATH_MAX;
  const candidates = [os.tmpdir(), '/tmp', '/var/tmp', '/dev/shm'].filter((b, i, all) => all.indexOf(b) === i);
  for (const base of candidates) {
    if (!fits(base)) continue;
    try {
      return fs.mkdtempSync(path.join(base, prefix));
    } catch {
      /* not writable here: try the next short directory */
    }
  }
  throw new Error(`no writable temp directory short enough for Unix socket paths (TMPDIR=${os.tmpdir()})`);
}

function request(port, method, urlPath, { headers = {}, body, rawBody, host } = {}) {
  return new Promise((resolve, reject) => {
    const payload = rawBody ?? (body === undefined ? undefined : JSON.stringify(body));
    const h = { Host: host ?? `127.0.0.1:${port}`, ...headers };
    if (payload !== undefined) {
      h['Content-Length'] = Buffer.byteLength(payload);
      if (!Object.keys(h).some((k) => k.toLowerCase() === 'content-type')) h['Content-Type'] = 'application/json';
    }
    const req = http.request({ host: '127.0.0.1', port, method, path: urlPath, headers: h }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try {
          json = JSON.parse(text);
        } catch {
          /* not json */
        }
        resolve({ status: res.statusCode, headers: res.headers, text, json });
      });
    });
    req.on('error', reject);
    if (payload !== undefined) req.write(payload);
    req.end();
  });
}

const get = (port, p, opts) => request(port, 'GET', p, opts);
const post = (port, p, body, opts = {}) =>
  request(port, 'POST', p, { ...opts, body, headers: { Origin: `http://127.0.0.1:${port}`, ...(opts.headers ?? {}) } });

async function startConsole(backend, opts = {}) {
  const app = createConsoleServer({ backend, host: '127.0.0.1', port: 0, ...opts });
  const { port } = await app.listen();
  return { app, port };
}

async function waitFor(fn, timeoutMs = 20_000, stepMs = 50) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    if (await fn()) return true;
    await new Promise((r) => setTimeout(r, stepMs));
  }
  return false;
}

/** SIGTERM a daemon and wait for it to exit, so its shutdown cannot race temp-dir removal. */
async function stopChild(child, timeoutMs = 5000) {
  if (!child || child.exitCode !== null || child.signalCode !== null) return;
  const exited = new Promise((resolve) => child.once('exit', resolve));
  child.kill('SIGTERM');
  const timer = setTimeout(() => child.kill('SIGKILL'), timeoutMs);
  await exited;
  clearTimeout(timer);
}

function mockUdsServer(sockPath, handler) {
  const server = net.createServer((sock) => {
    const dec = new FrameDecoder();
    sock.on('data', (chunk) => {
      for (const frame of dec.push(chunk)) {
        const reply = handler(frame);
        if (reply === undefined) {
          sock.end();
          continue;
        }
        const buf = encodeFrame(reply);
        // Deliberately split the reply across writes to exercise reassembly.
        const cut = Math.max(1, Math.floor(buf.length / 3));
        sock.write(buf.subarray(0, 2));
        setTimeout(() => sock.write(buf.subarray(2, cut)), 5);
        setTimeout(() => sock.write(buf.subarray(cut)), 10);
      }
    });
  });
  return new Promise((resolve) => server.listen(sockPath, () => resolve(server)));
}

// ---------------------------------------------------------------------------
// 1. UDS framing
// ---------------------------------------------------------------------------

describe('UDS framing (4-byte big-endian length + UTF-8 JSON)', () => {
  test('encodeFrame writes a big-endian u32 length prefix', () => {
    const msg = { op: 'list_hosts', note: 'édge-ü' };
    const frame = encodeFrame(msg);
    const json = Buffer.from(JSON.stringify(msg), 'utf8');
    assert.equal(frame.readUInt32BE(0), json.length);
    assert.deepEqual(frame.subarray(4), json);
  });

  test('FrameDecoder reassembles frames fed one byte at a time', () => {
    const a = { result: 'hosts', hosts: [{ host_id: 'edge-vm-07' }] };
    const b = { result: 'error', code: 'forbidden', message: 'nope' };
    const bytes = Buffer.concat([encodeFrame(a), encodeFrame(b)]);
    const dec = new FrameDecoder();
    const out = [];
    for (let i = 0; i < bytes.length; i++) out.push(...dec.push(bytes.subarray(i, i + 1)));
    assert.deepEqual(out, [a, b]);
    assert.equal(dec.pending, 0);
  });

  test('oversized and zero-length frames are rejected', () => {
    const header = Buffer.alloc(4);
    header.writeUInt32BE(MAX_FRAME_BYTES + 1, 0);
    assert.throws(() => new FrameDecoder().push(header), FrameError);
    assert.throws(() => new FrameDecoder().push(Buffer.alloc(4)), FrameError);
    assert.throws(() => encodeFrame({ blob: 'x'.repeat(MAX_FRAME_BYTES) }), FrameError);
  });

  test('roundtrip against a mock Unix socket server', async () => {
    const dir = shortTmp();
    const sockPath = path.join(dir, 'inv.sock');
    let seen = null;
    const server = await mockUdsServer(sockPath, (frame) => {
      seen = frame;
      return { result: 'hosts', hosts: [{ host_id: 'edge-vm-07', agent_version: '0.2.0', liveness_status: 'online', active_bundle_version: 3, last_heartbeat_at: null }] };
    });
    try {
      const client = new InvestigationClient({ socketPath: sockPath, token: 'secret-token-abc' });
      const resp = await client.call({ op: 'list_hosts', limit: 5 });
      assert.equal(resp.result, 'hosts');
      assert.equal(resp.hosts[0].host_id, 'edge-vm-07');
      assert.match(seen.request_id, /^console-/);
      assert.equal(seen.capability_token, 'secret-token-abc');
      assert.deepEqual(seen.request, { op: 'list_hosts', limit: 5 });
      assert.deepEqual(Object.keys(seen).sort(), ['capability_token', 'request', 'request_id']);
      assert.ok(!JSON.stringify(client).includes('secret-token-abc'), 'client must not serialise its token');

      const admin = new AdminClient({ socketPath: sockPath });
      await admin.call({ admin_op: 'verify_audit_chain' });
      assert.deepEqual(seen, { admin_op: 'verify_audit_chain' });
    } finally {
      server.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('connection closed without a reply and unreachable sockets surface as errors', async () => {
    const dir = shortTmp();
    const sockPath = path.join(dir, 'x.sock');
    const server = await mockUdsServer(sockPath, () => undefined);
    try {
      await assert.rejects(udsRequest(sockPath, { a: 1 }), /closed before a response/);
      await assert.rejects(udsRequest(path.join(dir, 'missing.sock'), { a: 1 }), /ENOENT/);
    } finally {
      server.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('live backend maps control-d errors to HTTP status and never echoes the token', async () => {
    const dir = shortTmp();
    const sockPath = path.join(dir, 'inv.sock');
    const TOKEN = 'tok-0123456789abcdef-should-never-leak';
    const server = await mockUdsServer(sockPath, (frame) => {
      if (frame.request.op === 'list_hosts') return { result: 'hosts', hosts: [] };
      if (frame.request.op === 'list_active_watches') return { result: 'error', code: 'forbidden', message: "host 'edge-x' is outside capability scope" };
      return { result: 'error', code: 'not_found', message: 'no such incident' };
    });
    const { app, port } = await startConsole(createLiveBackend({ investigateSock: sockPath, token: TOKEN }));
    try {
      const st = await get(port, '/api/status');
      assert.equal(st.status, 200);
      assert.equal(st.json.mode, 'live');
      assert.equal(st.json.admin_enabled, false);
      assert.equal(st.json.sockets.investigate.reachable, true);
      const w = await get(port, '/api/hosts/edge-x/watches');
      assert.equal(w.status, 403);
      assert.equal(w.json.error.code, 'forbidden');
      const inc = await get(port, '/api/incidents/inc-9');
      assert.equal(inc.status, 404);
      const bad = await get(port, '/api/hosts/bad%20host/watches');
      assert.equal(bad.status, 400);
      for (const r of [st, w, inc, bad]) assert.ok(!r.text.includes(TOKEN));
      const adm = await get(port, '/api/admin/audit');
      assert.equal(adm.status, 403);
      assert.equal(adm.json.error.code, 'admin_disabled');
    } finally {
      await app.close();
      server.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('Phase 8 actions over a mock control-d', () => {
  test('investigation list_actions frame and admin detail/approve frames are schema-exact', async () => {
    const dir = shortTmp();
    const invPath = path.join(dir, 'inv.sock');
    const admPath = path.join(dir, 'adm.sock');
    const TOKEN = 'tok-incident-scoped-never-leak';
    const summary = {
      proposal_id: 9, intent_id: '2b1f0b4e-6c1a-4f53-9a77-1d1b0d8f3c21', host_id: 'edge-vm-07', incident_id: 'inc-1',
      auth_mode: 'dual_signed_operator', status: 'pending_approval', verb: { verb: 'host_isolate', preserve_mgmt_cidrs: ['10.0.0.0/24'], ttl_seconds: 600 },
      expected_effect: 'e', blast_radius: 'b', rollback_plan: 'r', created_at: '2026-11-24T10:00:00Z', approver: null,
    };
    const payload = {
      schema_version: 1, intent_id: summary.intent_id, nonce: 'n-1', host_id: 'edge-vm-07', incident_id: 'inc-1', proposal_id: 9,
      auth_mode: 'dual_signed_operator', verb: summary.verb, policy_version: 1, issued_at: '2026-11-24T10:00:00Z',
      expires_at: '2026-11-24T10:10:00Z', rollback_plan: 'r', evidence_observation_ids: [4, 7],
    };
    const seen = [];
    const inv = await mockUdsServer(invPath, (f) => (seen.push(f), { result: 'actions', actions: [summary] }));
    const adm = await mockUdsServer(admPath, (f) => {
      seen.push(f);
      if (f.admin_op === 'get_action_intent') return { admin_result: 'action_intent_detail', payload, authorized_intent: null, status: 'pending_approval' };
      if (f.admin_op === 'list_actions') return { admin_result: 'actions', actions: [summary] };
      if (f.admin_op === 'list_audit_entries') return { admin_result: 'audit_entries', entries: [] };
      if (f.admin_op === 'approve_action') return { admin_result: 'action_approved', intent_id: f.intent_id, authorized_intent: { control_envelope: { domain: 'defsecautmit.action_intent.v1', signing_key_id: 'control-key-01', raw_payload: f.operator_approval.raw_payload, signature_hex: 'cd'.repeat(64) }, operator_approval: f.operator_approval } };
      return { admin_result: 'error', code: 'invalid_request', message: 'unexpected' };
    });
    const scoped = await startConsole(createLiveBackend({ investigateSock: invPath, token: TOKEN }));
    const admin = await startConsole(createLiveBackend({ investigateSock: invPath, token: TOKEN, adminSock: admPath, enableAdmin: true }));
    try {
      const r = await get(scoped.port, '/api/actions?incident_id=inc-1');
      assert.equal(r.status, 200, r.text);
      assert.equal(r.json.source, 'investigate');
      assert.deepEqual(r.json.actions, [summary]);
      assert.equal(r.json.denied, null, 'denials need the admin audit log');
      assert.deepEqual(seen.at(-1).request, { op: 'list_actions', host_id: null, incident_id: 'inc-1' });
      assert.ok(!r.text.includes(TOKEN));

      const d = await get(admin.port, `/api/admin/actions/${summary.intent_id}`);
      assert.equal(d.status, 200, d.text);
      assert.deepEqual(seen.find((f) => f.admin_op === 'get_action_intent'), { admin_op: 'get_action_intent', intent_id: summary.intent_id });
      assert.deepEqual(d.json.payload, payload);
      assert.deepEqual(d.json.summary, summary);
      assert.equal(d.json.signing.canonical_payload, canonicalJson(payload));
      assert.equal(d.json.signing.payload_sha256, sha256Hex(canonicalJson(payload)));

      const envelope = { domain: 'defsecautmit.action_approval.v1', signing_key_id: 'operator-01', raw_payload: canonicalJson(payload), signature_hex: 'AB'.repeat(64) };
      const ok = await post(admin.port, `/api/admin/actions/${summary.intent_id}/approve`, { approver: 'j.rivera', operator_approval: envelope });
      assert.equal(ok.status, 200, ok.text);
      assert.deepEqual(seen.at(-1), { admin_op: 'approve_action', intent_id: summary.intent_id, approver: 'j.rivera', operator_approval: { ...envelope, signature_hex: 'ab'.repeat(64) } });
      assert.equal(ok.json.authorized_intent.operator_approval.signing_key_id, 'operator-01');
    } finally {
      await scoped.app.close();
      await admin.app.close();
      inv.close();
      adm.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// 2. Live integration against the compiled control-d
// ---------------------------------------------------------------------------

describe('live integration with target/debug/control-d', { skip: !fs.existsSync(CONTROL_D) && 'control-d binary not built (cargo build -p control-d)' }, () => {
  let dir;
  let child;
  let adminSock;
  let invSock;
  let token;
  let stderr = '';

  before(async () => {
    dir = shortTmp('dsl-');
    adminSock = path.join(dir, 'ad.sock');
    invSock = path.join(dir, 'iv.sock');
    assert.ok(Buffer.byteLength(adminSock) < 108 && Buffer.byteLength(invSock) < 108, 'socket paths must fit sun_path');
    child = spawn(
      CONTROL_D,
      ['--data-dir', path.join(dir, 'data'), '--agent-sock', path.join(dir, 'ag.sock'), '--admin-sock', adminSock, '--investigate-sock', invSock],
      { stdio: ['ignore', 'ignore', 'pipe'], env: { ...process.env, RUST_LOG: 'warn' } },
    );
    child.stderr.on('data', (c) => {
      stderr += c;
    });
    const up = await waitFor(() => fs.existsSync(adminSock) && fs.existsSync(invSock));
    assert.ok(up, `control-d did not create sockets:\n${stderr}`);

    const admin = new AdminClient({ socketPath: adminSock });
    const enrolled = await admin.call({ admin_op: 'enroll_host', host_id: 'edge-vm-07', agent_public_key_hex: null });
    assert.equal(enrolled.admin_result, 'host_enrolled', JSON.stringify(enrolled));
    const minted = await admin.call({
      admin_op: 'mint_capability_token',
      principal_id: 'console-it',
      role: 'investigator',
      allowed_hosts: ['edge-vm-07'],
      allowed_collectors: ALL_COLLECTORS,
      ttl_seconds: 600,
    });
    assert.equal(minted.admin_result, 'token_minted', JSON.stringify(minted));
    token = minted.token;
  });

  after(async () => {
    await stopChild(child);
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  test('admin-enabled console: status, hosts, capabilities, audit, policy decisions, enrollment', async () => {
    const tokenFile = path.join(dir, 'token');
    fs.writeFileSync(tokenFile, `${token}\n`, { mode: 0o600 });
    const opts = parseArgs(['--investigate-sock', invSock, '--token-file', tokenFile, '--admin-sock', adminSock, '--enable-admin', '--port', '0'], {});
    assert.equal(opts.host, '127.0.0.1');
    assert.equal(opts.token, token);
    assert.equal(opts.tokenWorldReadable, false);

    const backend = createLiveBackend({ investigateSock: invSock, token: opts.token, adminSock, enableAdmin: true });
    const { app, port } = await startConsole(backend);
    const bodies = [];
    const track = (r) => {
      bodies.push(r.text);
      return r;
    };
    try {
      const st = track(await get(port, '/api/status'));
      assert.equal(st.status, 200, st.text);
      assert.equal(st.json.mode, 'live');
      assert.equal(st.json.admin_enabled, true);
      assert.equal(st.json.sockets.investigate.reachable, true);
      assert.equal(st.json.sockets.investigate.authorized, true);
      assert.equal(st.json.audit.valid, true);
      assert.ok(st.json.audit.entries_checked >= 2);

      const hosts = track(await get(port, '/api/hosts'));
      assert.equal(hosts.status, 200, hosts.text);
      assert.deepEqual(hosts.json.hosts.map((h) => h.host_id), ['edge-vm-07']);

      const caps = track(await get(port, '/api/hosts/edge-vm-07/capabilities'));
      assert.equal(caps.status, 200, caps.text);
      assert.deepEqual(caps.json.capabilities.map((c) => c.collector_type).sort(), [...ALL_COLLECTORS].sort());

      const watches = track(await get(port, '/api/hosts/edge-vm-07/watches'));
      assert.equal(watches.status, 200, watches.text);
      assert.ok(Array.isArray(watches.json.watches));

      const baselines = track(await get(port, '/api/hosts/edge-vm-07/baselines'));
      assert.equal(baselines.status, 200, baselines.text);
      assert.ok(Array.isArray(baselines.json.three_state));

      const obs = track(await get(port, '/api/hosts/edge-vm-07/observations?limit=10'));
      assert.equal(obs.status, 200, obs.text);

      const incidents = track(await get(port, '/api/incidents'));
      assert.equal(incidents.status, 200, incidents.text);
      assert.ok(Array.isArray(incidents.json.incidents));

      const outOfScope = track(await get(port, '/api/hosts/edge-vm-99/watches'));
      assert.equal(outOfScope.status, 403);

      const audit = track(await get(port, '/api/admin/audit'));
      assert.equal(audit.status, 200, audit.text);
      assert.equal(audit.json.chain.valid, true);
      const types = audit.json.entries.map((e) => e.event_type);
      assert.ok(types.includes('host_enrolled'));
      assert.ok(types.includes('capability_minted'));
      // The console's independent SHA-256/RFC 8785 recomputation agrees with Rust.
      assert.equal(audit.json.independent.valid, true, audit.json.independent.error);
      assert.equal(audit.json.independent.head, audit.json.chain.latest_hash);

      const decisions = track(await get(port, '/api/admin/policy-decisions'));
      assert.equal(decisions.status, 200, decisions.text);
      assert.ok(Array.isArray(decisions.json.decisions));

      const enroll = track(await post(port, '/api/admin/hosts/enroll', { host_id: 'edge-vm-21' }));
      assert.equal(enroll.status, 200, enroll.text);
      assert.equal(enroll.json.host_id, 'edge-vm-21');
      assert.match(enroll.json.control_public_key_hex, /^[0-9a-f]{64}$/);

      const crossOrigin = await post(port, '/api/admin/hosts/enroll', { host_id: 'edge-vm-22' }, { headers: { Origin: 'http://evil.example' } });
      assert.equal(crossOrigin.status, 403);
      const after = track(await get(port, '/api/admin/audit'));
      const enrolledHosts = after.json.entries.filter((e) => e.event_type === 'host_enrolled').map((e) => e.payload.host_id);
      assert.ok(enrolledHosts.includes('edge-vm-21'));
      assert.ok(!enrolledHosts.includes('edge-vm-22'), 'cross-origin POST must not reach control-d');
      assert.equal(after.json.independent.valid, true);

      for (const text of bodies) assert.ok(!text.includes(token), 'capability token leaked to the browser');
    } finally {
      await app.close();
    }
  });

  test('admin-disabled console gates every admin route with 403', async () => {
    const backend = createLiveBackend({ investigateSock: invSock, token, adminSock, enableAdmin: false });
    const { app, port } = await startConsole(backend);
    try {
      const st = await get(port, '/api/status');
      assert.equal(st.json.admin_enabled, false);
      assert.equal(st.json.audit, null);
      assert.equal((await get(port, '/api/hosts')).status, 200);
      for (const p of ['/api/admin/audit', '/api/admin/policy-decisions']) {
        const r = await get(port, p);
        assert.equal(r.status, 403, p);
        assert.equal(r.json.error.code, 'admin_disabled');
      }
      for (const [p, body] of [
        ['/api/admin/hosts/enroll', { host_id: 'edge-vm-30' }],
        ['/api/admin/baselines/promote', { host_id: 'edge-vm-07', watch_id: 'w', observation_id: 1, approver: 'a', rationale: 'r' }],
        ['/api/admin/incidents/inc-1/close', { actor: 'a', resolution: 'r' }],
      ]) {
        const r = await post(port, p, body);
        assert.equal(r.status, 403, p);
      }
    } finally {
      await app.close();
    }
  });

  test('invalid token and unreachable socket are reported, not hidden', async () => {
    const bad = await startConsole(createLiveBackend({ investigateSock: invSock, token: 'not-a-real-token' }));
    const gone = await startConsole(createLiveBackend({ investigateSock: path.join(dir, 'nope.sock'), token }));
    try {
      const r = await get(bad.port, '/api/hosts');
      assert.equal(r.status, 403);
      assert.equal(r.json.error.code, 'forbidden');
      const st = await get(bad.port, '/api/status');
      assert.equal(st.json.sockets.investigate.reachable, true);
      assert.equal(st.json.sockets.investigate.authorized, false);
      const u = await get(gone.port, '/api/hosts');
      assert.equal(u.status, 503);
      assert.equal(u.json.error.code, 'control_unreachable');
    } finally {
      await bad.app.close();
      await gone.app.close();
    }
  });

  test('Phase 8 actions API speaks control-d\'s exact admin + investigation schema', async () => {
    const adminBackend = createLiveBackend({ investigateSock: invSock, token, adminSock, enableAdmin: true });
    const scopedBackend = createLiveBackend({ investigateSock: invSock, token, adminSock, enableAdmin: false });
    const a = await startConsole(adminBackend);
    const s = await startConsole(scopedBackend);
    const bodies = [];
    const track = (r) => (bodies.push(r.text), r);
    try {
      // Admin interface: ListActions (+ audit-derived denials) for the whole fleet.
      const list = track(await get(a.port, '/api/actions'));
      assert.equal(list.status, 200, list.text);
      assert.equal(list.json.source, 'admin');
      assert.deepEqual(list.json.actions, []);
      assert.deepEqual(list.json.denied, []);
      assert.equal(list.json.admin_sock, adminSock);
      const filtered = track(await get(a.port, '/api/actions?host_id=edge-vm-07&incident_id=inc-none'));
      assert.equal(filtered.status, 200, filtered.text);
      assert.equal((await get(a.port, '/api/actions?host_id=bad%20host')).status, 400);

      // GetActionIntent / ApproveAction frames are accepted by control-d's
      // deny_unknown_fields parser (a malformed frame would close the socket -> 502).
      const intent = crypto.randomUUID();
      const detail = track(await get(a.port, `/api/admin/actions/${intent}`));
      assert.equal(detail.status, 404, detail.text);
      assert.equal(detail.json.error.code, 'not_found');
      assert.match(detail.json.error.message, /action intent not found/);
      const envelope = {
        domain: 'defsecautmit.action_approval.v1',
        signing_key_id: 'operator-01',
        raw_payload: canonicalJson({ intent_id: intent }),
        signature_hex: 'ab'.repeat(64),
      };
      const approve = track(await post(a.port, `/api/admin/actions/${intent}/approve`, { approver: 'j.rivera', operator_approval: envelope }));
      assert.equal(approve.status, 404, approve.text);
      assert.match(approve.json.error.message, /action intent not found/);

      // The BFF validates the envelope before anything reaches control-d.
      for (const [body, re] of [
        [{ approver: 'x' }, /operator_approval/],
        [{ approver: 'x', operator_approval: { ...envelope, extra: 1 } }, /exactly/],
        [{ approver: 'x', operator_approval: { ...envelope, domain: 'defsecautmit.action_intent.v1' } }, /domain/],
        [{ approver: 'x', operator_approval: { ...envelope, signature_hex: 'zz' } }, /signature_hex/],
        [{ approver: 'x', operator_approval: 'not json' }, /SignedEnvelope/],
        [{ operator_approval: envelope }, /approver/],
        [{ approver: 'x', private_key_hex: 'ab'.repeat(32) }, /private keys never reach the console/],
      ]) {
        const r = track(await post(a.port, `/api/admin/actions/${intent}/approve`, body));
        assert.equal(r.status, 400, JSON.stringify(body));
        assert.match(r.json.error.message, re);
      }
      assert.equal((await post(a.port, `/api/admin/actions/${intent}/approve`, { approver: 'x', operator_approval: envelope }, { headers: { Origin: 'http://evil.example' } })).status, 403);

      // Investigation socket: control-d only lists actions for an incident-scoped
      // capability, and the console surfaces that decision verbatim.
      const scoped = track(await get(s.port, '/api/actions'));
      assert.equal(scoped.status, 403, scoped.text);
      assert.equal(scoped.json.error.code, 'forbidden');
      assert.match(scoped.json.error.message, /incident scope/);
      for (const r of [await get(s.port, `/api/admin/actions/${intent}`), await post(s.port, `/api/admin/actions/${intent}/approve`, { approver: 'x', operator_approval: envelope })]) {
        assert.equal(r.status, 403);
        assert.equal(r.json.error.code, 'admin_disabled');
      }

      const audit = (await get(a.port, '/api/admin/audit?limit=500')).json;
      assert.equal(audit.independent.valid, true);
      assert.ok(!audit.entries.some((e) => e.event_type === 'action_approved'), 'no approval may be recorded');
      for (const text of bodies) assert.ok(!text.includes(token), 'capability token leaked');
    } finally {
      await a.app.close();
      await s.app.close();
    }
  });
});

// ---------------------------------------------------------------------------
// 2b. Per-run token isolation against the compiled control-d
// ---------------------------------------------------------------------------

/**
 * Minimal agent-d stand-in on control-d's agent socket: one persistent
 * connection, Register first, then hashed observation deltas. Enough to make
 * control-d open genuine incidents through its own trigger evaluation.
 */
class FakeAgent {
  constructor(socketPath, hostId) {
    this.socketPath = socketPath;
    this.hostId = hostId;
    this.session = `sess-${crypto.randomBytes(4).toString('hex')}`;
    this.seq = 0;
    this.frames = [];
    this.waiters = new Set();
  }

  connect() {
    return new Promise((resolve, reject) => {
      const decoder = new FrameDecoder();
      this.sock = net.createConnection({ path: this.socketPath }, resolve);
      this.sock.on('error', reject);
      this.sock.on('data', (chunk) => {
        for (const f of decoder.push(chunk)) {
          this.frames.push(f);
          for (const w of this.waiters) w();
        }
      });
    });
  }

  waitFrame(match, timeoutMs = 5000) {
    return new Promise((resolve, reject) => {
      const check = () => {
        const f = this.frames.find(match);
        if (!f) return;
        this.waiters.delete(check);
        clearTimeout(timer);
        resolve(f);
      };
      const timer = setTimeout(() => {
        this.waiters.delete(check);
        reject(new Error(`agent frame timeout; got ${JSON.stringify(this.frames.map((x) => x.msg))}`));
      }, timeoutMs);
      this.waiters.add(check);
      check();
    });
  }

  async register() {
    this.sock.write(encodeFrame({
      msg: 'register', protocol_version: 1, host_id: this.hostId, agent_version: 'fake-0.0.1',
      boot_id: 'boot-fake', session_id: this.session, active_bundle_version: 0, active_bundle_digest: null, sent_at: new Date().toISOString(),
    }));
    const ack = await this.waitFrame((f) => f.msg === 'register_ack');
    assert.equal(ack.accepted, true, JSON.stringify(ack));
  }

  async push(watchId, collectorType, payload, { observedAt = new Date() } = {}) {
    const seq = ++this.seq;
    const hashed = payload.kind === 'snapshot' ? payload.data : payload.events;
    this.sock.write(encodeFrame({
      msg: 'push_observation_delta',
      observation: {
        host_id: this.hostId, session_id: this.session, seq_no: seq, watch_id: watchId, spec_version: 1, collector_type: collectorType,
        observed_at: observedAt.toISOString(), status: 'ok', state_hash: sha256Hex(canonicalJson(hashed)), payload, is_reconciliation: false, partial_reasons: [],
      },
    }));
    await this.waitFrame((f) => f.msg === 'observation_ack' && f.acked_seq_no >= seq);
  }

  close() {
    this.sock?.destroy();
  }
}

const liveSocket = (port, comm, unit, inode) => ({
  socket_key: `tcp:0.0.0.0:${port}:uid=0`, protocol: 'tcp', local_addr: '0.0.0.0', local_port: port, uid: 0, inode, pid: 4000 + port % 1000, comm, systemd_unit: unit,
});
const sockSnapshot = (list) => ({ kind: 'snapshot', data: { count: list.length, partial_attribution: false, sockets: list } });

describe('per-run token isolation with target/debug/control-d', { skip: !fs.existsSync(CONTROL_D) && 'control-d binary not built (cargo build -p control-d)' }, () => {
  const HOST = 'edge-live-01';
  let dir;
  let child;
  let adminSock;
  let invSock;
  let agentSock;
  let agent;
  let browseToken;
  let stderr = '';

  const baselineSpec = (id, collector, trigger) => ({
    id, version: 1, host_id: HOST, class: 'baseline', incident_id: null, collector,
    schedule: { interval_seconds: 60, timeout_seconds: 10 }, trigger,
    wake_policy: { cooldown_seconds: 60, max_wakeups_per_hour: 30 }, lifecycle: { enabled: true, expires_at: null, max_runs: null },
  });

  before(async () => {
    dir = shortTmp('dsr-');
    adminSock = path.join(dir, 'ad.sock');
    invSock = path.join(dir, 'iv.sock');
    agentSock = path.join(dir, 'ag.sock');
    child = spawn(CONTROL_D, ['--data-dir', path.join(dir, 'data'), '--agent-sock', agentSock, '--admin-sock', adminSock, '--investigate-sock', invSock], {
      stdio: ['ignore', 'ignore', 'pipe'],
      env: { ...process.env, RUST_LOG: 'warn' },
    });
    child.stderr.on('data', (c) => {
      stderr += c;
    });
    assert.ok(await waitFor(() => fs.existsSync(adminSock) && fs.existsSync(invSock) && fs.existsSync(agentSock)), `control-d did not start:\n${stderr}`);

    const admin = new AdminClient({ socketPath: adminSock });
    assert.equal((await admin.call({ admin_op: 'enroll_host', host_id: HOST, agent_public_key_hex: null })).admin_result, 'host_enrolled');
    for (const spec of [
      baselineSpec('base-sockets', { type: 'sockets.listening', parameters: { include_tcp: true, include_udp: true, include_ipv6: true, resolve_process: true } }, { type: 'set_diff', compare_against: 'last_observed', set_field: 'sockets', identity_key: 'socket_key' }),
      baselineSpec('base-ssh-unit', { type: 'systemd.unit_state', parameters: { unit: 'sshd.service', hash_unit_files: false } }, { type: 'field_changed', compare_against: 'last_observed', fields: ['active_state'] }),
      baselineSpec('base-sshd-journal', { type: 'journal.unit_events', parameters: { unit: 'sshd.service' } }, { type: 'collector_stale_or_error', max_stale_seconds: 600, consecutive_errors: 3 }),
    ]) {
      const r = await admin.call({ admin_op: 'apply_baseline_watch', spec, actor: 'it-operator', rationale: 'integration fixture' });
      assert.equal(r.admin_result, 'watch_applied', JSON.stringify(r));
    }

    agent = new FakeAgent(agentSock, HOST);
    await agent.connect();
    await agent.register();
    const ssh = liveSocket(22, 'sshd', 'ssh.service', 101);
    const rogue = liveSocket(4444, 'helperd', 'custom-helper.service', 202);
    const unitSnap = (active) => ({ kind: 'snapshot', data: { unit: 'sshd.service', load_state: 'loaded', active_state: active, sub_state: active === 'active' ? 'running' : 'dead', unit_file_state: 'enabled', main_pid: active === 'active' ? 101 : null, main_pid_start_time_ticks: null, exec_start_hash: null, unit_files: [] } });
    await agent.push('base-sockets', 'sockets.listening', sockSnapshot([ssh]), { observedAt: new Date(Date.now() - 60_000) });
    await agent.push('base-sockets', 'sockets.listening', sockSnapshot([ssh, rogue])); // incident A
    await agent.push('base-ssh-unit', 'systemd.unit_state', unitSnap('active'), { observedAt: new Date(Date.now() - 60_000) });
    await agent.push('base-ssh-unit', 'systemd.unit_state', unitSnap('inactive')); // incident B
    const event = (i, msg) => ({
      cursor: `s=fake;i=${i}`, timestamp_us: Date.now() * 1000, unit: 'sshd.service', priority: 6, pid: 811, uid: 0,
      message_redacted: msg, truncated: false, redaction_applied: false, classification: 'bounded_redacted_text',
    });
    for (const [i, msg] of [[1, 'Accepted publickey for deploy'], [2, 'session closed for user deploy']]) {
      await agent.push('base-sshd-journal', 'journal.unit_events', { kind: 'stream_batch', events: [event(i, msg)], cursor_before: null, cursor_after: `s=fake;i=${i}`, gap_detected: false });
    }

    const minted = await admin.call({ admin_op: 'mint_capability_token', principal_id: 'console-browse', role: 'investigator', allowed_hosts: [HOST], allowed_collectors: ALL_COLLECTORS, ttl_seconds: 900 });
    assert.equal(minted.admin_result, 'token_minted');
    browseToken = minted.token;
  });

  after(async () => {
    agent?.close();
    await stopChild(child);
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  test('starting a run never narrows the console browse session, before or after closing it', async () => {
    const backend = createLiveBackend({ investigateSock: invSock, token: browseToken, adminSock, enableAdmin: true });
    const { app, port } = await startConsole(backend);
    const bodies = [];
    const track = (r) => (bodies.push(r.text), r);
    try {
      const list = track(await get(port, '/api/incidents'));
      assert.equal(list.status, 200, list.text);
      const open = list.json.incidents.filter((i) => i.status === 'open' && i.host_id === HOST).sort((a, b) => Date.parse(a.created_at) - Date.parse(b.created_at));
      assert.equal(open.length, 2, `fake agent should have opened two incidents: ${list.text}\n${stderr}`);
      const [A, B] = open;

      // Premise check: a token that calls StartInvestigationRun itself is
      // permanently narrowed by control-d to that run's incident and host.
      const admin = new AdminClient({ socketPath: adminSock });
      const victim = await admin.call({ admin_op: 'mint_capability_token', principal_id: 'console-premise-check', role: 'investigator', allowed_hosts: [HOST], allowed_collectors: ALL_COLLECTORS, ttl_seconds: 300 });
      const direct = new InvestigationClient({ socketPath: invSock, token: victim.token });
      const started = await direct.call({ op: 'start_investigation_run', incident_id: A.incident_id, backend_id: 'operator-console', model_id: 'premise-check', prompt_schema_version: 'v1' });
      assert.equal(started.result, 'run_started', JSON.stringify(started));
      const narrowed = await direct.call({ op: 'get_incident_context', incident_id: B.incident_id });
      assert.equal(narrowed.result, 'error', 'control-d narrows the calling token');
      assert.match(narrowed.message, /scope/);

      const hosts = track(await get(port, '/api/hosts'));
      assert.equal(hosts.status, 200, hosts.text);
      assert.equal(hosts.json.hosts[0].watch_count, 3, 'host card shows the real active watch count');
      assert.equal(hosts.json.hosts[0].stream_watch_count, 1);

      const run = track(await post(port, `/api/incidents/${A.incident_id}/runs`, {}));
      assert.equal(run.status, 200, run.text);
      assert.deepEqual(Object.keys(run.json).sort(), ['expires_at', 'incident_id', 'run_id'], 'no token is returned');
      const again = track(await post(port, `/api/incidents/${A.incident_id}/runs`, {}));
      assert.equal(again.json.run_id, run.json.run_id, 'an active run is reused');

      // The browse token still reads every incident and host (this used to be 403).
      const ctxB = track(await get(port, `/api/incidents/${B.incident_id}`));
      assert.equal(ctxB.status, 200, ctxB.text);
      assert.equal(ctxB.json.run, null);
      assert.equal(track(await get(port, '/api/hosts')).status, 200);
      const ctxA = track(await get(port, `/api/incidents/${A.incident_id}`));
      assert.equal(ctxA.json.run.run_id, run.json.run_id);

      // Mutations go through the per-run token, so control-d binds them to run A.
      const evidence = ctxA.json.recent_observations.filter((o) => o.watch_id === 'base-sockets').map((o) => o.observation_id);
      assert.ok(evidence.length, 'incident A has socket evidence');
      const finding = track(await post(port, `/api/incidents/${A.incident_id}/findings`, { kind: 'hypothesis', summary: 'helperd opened 4444', evidence_observation_ids: evidence.slice(0, 1) }));
      assert.equal(finding.status, 200, finding.text);
      const watch = track(await post(port, `/api/incidents/${A.incident_id}/proposals`, { collector_type: 'systemd.unit_state', parameters: { unit: 'custom-helper.service' }, interval_seconds: 30, timeout_seconds: 5, ttl_seconds: 1800, max_runs: 60, rationale: 'track the helper unit' }));
      assert.equal(watch.status, 200, watch.text);
      assert.equal(typeof watch.json.decision.allowed, 'boolean');

      // ProposeAction: exact schema, real gate verdicts.
      const action = (verb, ids = evidence.slice(0, 1)) => post(port, `/api/incidents/${A.incident_id}/actions`, {
        verb, evidence_observation_ids: ids, expected_effect: 'contain helperd', blast_radius: 'one host', rollback_plan: 'TTL expiry',
      });
      const protectedIp = track(await action({ verb: 'nft_block_ip', ip: '10.1.2.3', direction: 'both', ttl_seconds: 600 }));
      assert.equal(protectedIp.status, 200, protectedIp.text);
      assert.equal(protectedIp.json.decision.allowed, false);
      assert.equal(protectedIp.json.decision.rule_id, 'action.protected_ip');
      assert.equal(protectedIp.json.status, 'rejected');
      assert.equal(protectedIp.json.intent_id, null);
      const noEvidence = track(await action({ verb: 'systemd_stop_unit', unit: 'custom-helper.service', ttl_seconds: 600 }, []));
      assert.equal(noEvidence.json.decision.rule_id, 'action.evidence_required');
      const isolate = track(await action({ verb: 'host_isolate', preserve_mgmt_cidrs: '10.20.0.0/24, 10.20.8.15/32', ttl_seconds: 3600 }));
      assert.equal(isolate.status, 200, isolate.text);
      assert.equal(isolate.json.decision.allowed, true, isolate.text);
      assert.equal(isolate.json.decision.rule_id, 'action.pending_dual_approval');
      assert.equal(isolate.json.auth_mode, 'dual_signed_operator');
      assert.equal(isolate.json.status, 'pending_approval');
      assert.match(isolate.json.intent_id, /^[0-9a-f-]{36}$/);
      assert.deepEqual(isolate.json.verb, { verb: 'host_isolate', preserve_mgmt_cidrs: ['10.20.0.0/24', '10.20.8.15/32'], ttl_seconds: 3600 });
      const listed = track(await get(port, '/api/actions'));
      assert.ok(listed.json.actions.some((a) => a.intent_id === isolate.json.intent_id && a.status === 'pending_approval'));
      assert.ok(listed.json.denied.some((d) => d.decision.rule_id === 'action.protected_ip'));
      assert.equal(track(await post(port, `/api/incidents/${A.incident_id}/actions`, { verb: { verb: 'rm_rf' }, expected_effect: 'x', blast_radius: 'y', rollback_plan: 'z' })).status, 400);
      const noRun = track(await post(port, `/api/incidents/${B.incident_id}/actions`, { verb: { verb: 'nft_block_ip', ip: '203.0.113.9', ttl_seconds: 60 }, expected_effect: 'x', blast_radius: 'y', rollback_plan: 'z' }));
      assert.equal(noRun.status, 409);
      assert.equal(noRun.json.error.code, 'run_required');

      // What changed + stream derivation + automation status.
      const changes = track(await get(port, `/api/incidents/${B.incident_id}/changes`));
      assert.equal(changes.status, 200, changes.text);
      const unitChange = changes.json.changes.find((c) => c.watch_id === 'base-ssh-unit');
      assert.equal(unitChange.basis, 'before_incident');
      assert.ok(unitChange.diff.fields.some((f) => f.field === 'active_state' && f.before === 'active' && f.after === 'inactive'));
      const changesA = track(await get(port, `/api/incidents/${A.incident_id}/changes`));
      assert.deepEqual(changesA.json.changes.find((c) => c.watch_id === 'base-sockets').diff.added.map((s) => s.local_port), [4444]);
      const tri = track(await get(port, `/api/hosts/${HOST}/baselines`)).json.three_state;
      const journal = tri.find((r) => r.watch_id === 'base-sshd-journal');
      assert.equal(journal.state, 'stream');
      assert.equal(journal.promotable_observation_id, null);
      assert.equal(journal.stream.batches_in_window, 2);
      assert.equal(tri.find((r) => r.watch_id === 'base-sockets').state, 'baseline_absent');
      const auto = track(await get(port, '/api/automation'));
      assert.equal(auto.json.available, true);
      assert.equal(auto.json.reasoner_runs, 0);
      assert.ok(auto.json.console_runs >= 1);

      // Closing A ends its run but must not brick the console.
      const closed = track(await post(port, `/api/admin/incidents/${A.incident_id}/close`, { actor: 'it-operator', resolution: 'contained' }));
      assert.equal(closed.status, 200, closed.text);
      for (const p of ['/api/hosts', '/api/incidents', `/api/incidents/${B.incident_id}`, `/api/incidents/${A.incident_id}`, `/api/hosts/${HOST}/watches`]) {
        const r = track(await get(port, p));
        assert.equal(r.status, 200, `${p} after closing A: ${r.text}`);
      }
      const after = track(await post(port, `/api/incidents/${A.incident_id}/findings`, { kind: 'hypothesis', summary: 'late' }));
      assert.equal(after.status, 409, 'closed incident run was dropped');
      const runB = track(await post(port, `/api/incidents/${B.incident_id}/runs`, {}));
      assert.equal(runB.status, 200, runB.text);
      assert.notEqual(runB.json.run_id, run.json.run_id);
      assert.equal(track(await get(port, '/api/incidents')).status, 200);

      // Each run used its own minted, incident-scoped principal.
      const audit = track(await get(port, '/api/admin/audit?limit=500')).json;
      const minted = audit.entries.filter((e) => e.event_type === 'capability_minted').map((e) => JSON.stringify(e.payload));
      assert.ok(minted.some((p) => p.includes(`console-run-${A.incident_id.slice(0, 8)}`) && p.includes(A.incident_id)), minted.join('\n'));
      assert.ok(minted.some((p) => p.includes(`console-run-${B.incident_id.slice(0, 8)}`)));
      const starts = audit.entries.filter((e) => e.event_type === 'run_started');
      assert.ok(!starts.some((e) => e.actor === 'console-browse'), 'the browse principal never started a run');
      assert.equal(starts.filter((e) => e.actor.startsWith('console-run-')).length, 2);
      assert.equal(audit.independent.valid, true);
      for (const text of bodies) assert.ok(!text.includes(browseToken), 'browse token leaked');
    } finally {
      await app.close();
    }
  });

  test('Phase 9 reasoner activity endpoints read the real control-d runs, events and trigger queue', async () => {
    const admin = new AdminClient({ socketPath: adminSock });
    const observer = await admin.call({ admin_op: 'mint_capability_token', principal_id: 'console-observer', role: 'observer', allowed_hosts: [HOST], allowed_collectors: ALL_COLLECTORS, ttl_seconds: 300 });
    assert.equal(observer.admin_result, 'token_minted', JSON.stringify(observer));
    const backend = createLiveBackend({ investigateSock: invSock, token: browseToken, adminSock, enableAdmin: true });
    const readOnly = createLiveBackend({ investigateSock: invSock, token: observer.token, adminSock, enableAdmin: false });
    const a = await startConsole(backend);
    const o = await startConsole(readOnly);
    const bodies = [];
    const track = (r) => (bodies.push(r.text), r);
    try {
      const open = track(await get(a.port, '/api/incidents')).json.incidents.find((i) => i.status === 'open' && i.host_id === HOST);
      assert.ok(open, 'an open incident exists');
      const session = track(await post(a.port, `/api/incidents/${open.incident_id}/runs`, {}));
      assert.equal(session.status, 200, session.text);

      for (const port of [a.port, o.port]) {
        const runs = track(await get(port, `/api/runs?incident_id=${open.incident_id}`));
        assert.equal(runs.status, 200, runs.text);
        assert.equal(runs.json.available, true, `control-d Phase 9 runs must be readable: ${runs.text}`);
        const mine = runs.json.runs.find((r) => r.run_id === session.json.run_id);
        assert.ok(mine, runs.text);
        assert.equal(mine.host_id, HOST);
        assert.equal(mine.status, 'active');
        assert.equal(mine.origin, 'operator');
        assert.ok(Number.isFinite(Date.parse(mine.started_at)));
        assert.equal(typeof mine.event_count, 'number');

        const events = track(await get(port, `/api/runs/${session.json.run_id}/events`));
        assert.equal(events.status, 200, events.text);
        assert.equal(events.json.available, true);
        assert.ok(Array.isArray(events.json.events));

        const queue = track(await get(port, '/api/triggers'));
        assert.equal(queue.status, 200, queue.text);
        assert.equal(queue.json.available, true, queue.text);
        assert.ok(queue.json.triggers.length >= 2, 'both incidents queued a trigger');
        assert.ok(queue.json.triggers.every((t) => t.host_id === HOST && typeof t.retry_count === 'number'));
        const pending = track(await get(port, '/api/triggers?status=pending'));
        assert.ok(pending.json.triggers.every((t) => t.status === 'pending'));
      }
      assert.equal((await get(a.port, '/api/runs?incident_id=bad%20id')).status, 400);
      for (const text of bodies) {
        assert.ok(!text.includes(browseToken) && !text.includes(observer.token), 'token leaked');
        assert.ok(!/lease_token|capability_token/.test(text), 'lease or capability token field leaked');
      }
    } finally {
      await a.app.close();
      await o.app.close();
    }
  });

  test('Phase 10 expectation rules: create, backtest, list, revoke; approve an investigator proposal', async () => {
    const admin = new AdminClient({ socketPath: adminSock });
    const backend = createLiveBackend({ investigateSock: invSock, token: browseToken, adminSock, enableAdmin: true });
    const readOnly = createLiveBackend({ investigateSock: invSock, token: browseToken, adminSock, enableAdmin: false });
    const a = await startConsole(backend);
    const o = await startConsole(readOnly);
    const bodies = [];
    const secrets = [browseToken];
    const track = (r) => (bodies.push(r.text), r);
    const rule = (over = {}) => ({
      scope: { host_id: HOST, collector: 'sockets.listening', watch_id: 'base-sockets' },
      // Exactly what "Allow for this service" prefills from the added helperd socket.
      matches: [
        { op: 'eq', field: 'systemd_unit', value: 'custom-helper.service' },
        { op: 'eq', field: 'comm', value: 'helperd' },
        { op: 'eq', field: 'uid', value: 0 },
        { op: 'eq', field: 'protocol', value: 'tcp' },
        { op: 'eq', field: 'local_port', value: 4444 },
        { op: 'eq', field: 'bind_scope', value: 'any' },
      ],
      effect: 'allow_optional',
      rationale: 'Expected service socket: custom-helper.service listens on tcp 0.0.0.0:4444',
      expires_at: inDays(7),
      ...over,
    });
    try {
      // Backtest through the console: the prefill passes the real gate.
      const bt = track(await post(a.port, '/api/admin/rules/backtest', { rule: rule() }));
      assert.equal(bt.status, 200, bt.text);
      assert.equal(bt.json.allowed, true, bt.text);
      assert.deepEqual(Object.keys(bt.json.backtest).sort(), BACKTEST_KEYS);
      assert.ok(bt.json.backtest.observations_scanned >= 2, bt.text);
      assert.equal(bt.json.backtest.items_matched, 1);
      assert.deepEqual(bt.json.backtest.sample_keys, ['tcp:0.0.0.0:4444:uid=0']);
      assert.equal(bt.json.backtest.currently_matching, 1);
      assert.ok(bt.json.backtest.triggered_after < bt.json.backtest.triggered_before, `the rule silences the added listener: ${bt.text}`);

      // Gate denials come back as PolicyDecisions with control-d's rule IDs.
      const noAnchor = track(await post(a.port, '/api/admin/rules/backtest', { rule: rule({ matches: [{ op: 'eq', field: 'protocol', value: 'tcp' }, { op: 'eq', field: 'local_port', value: 4444 }] }) }));
      assert.equal(noAnchor.status, 200, noAnchor.text);
      assert.equal(noAnchor.json.decision.rule_id, 'rule-gate/identity-anchor');
      const wildcard = track(await post(a.port, '/api/admin/rules', { rule: rule({ matches: [{ op: 'eq', field: 'comm', value: 'helperd' }, { op: 'eq', field: 'local_port', value: 4444 }] }), actor: 'it-operator' }));
      assert.equal(wildcard.status, 200, wildcard.text);
      assert.equal(wildcard.json.allowed, false);
      assert.equal(wildcard.json.decision.rule_id, 'rule-gate/wildcard-bind');
      assert.equal(typeof wildcard.json.decision.policy_version, 'number', 'policy_version comes from the gate response');
      const unknownHost = track(await post(a.port, '/api/admin/rules/backtest', { rule: rule({ scope: { host_id: 'edge-nope', collector: 'sockets.listening', watch_id: null } }) }));
      assert.equal(unknownHost.status, 404, unknownHost.text);
      assert.equal(track(await post(a.port, '/api/admin/rules', { rule: { ...rule(), extra: 1 }, actor: 'it-operator' })).status, 400);

      // Create (activates immediately), list, revoke.
      const created = track(await post(a.port, '/api/admin/rules', { rule: rule(), actor: 'it-operator' }));
      assert.equal(created.status, 200, created.text);
      assert.equal(created.json.allowed, true, created.text);
      assert.equal(created.json.status, 'active');
      const ruleId = created.json.rule_id;
      for (const port of [a.port, o.port]) {
        const listed = track(await get(port, `/api/rules?status=active&host_id=${HOST}`));
        assert.equal(listed.status, 200, listed.text);
        assert.equal(listed.json.available, true, listed.text);
        assert.equal(listed.json.source, port === a.port ? 'admin' : 'investigate');
        const mine = listed.json.rules.find((r) => r.rule_id === ruleId);
        assert.ok(mine, listed.text);
        assert.deepEqual(Object.keys(mine).sort(), RULE_KEYS);
        assert.equal(mine.origin, 'operator');
        assert.equal(mine.proposed_by, 'it-operator');
        assert.deepEqual(mine.spec.matches, rule().matches);
      }
      assert.equal(track(await post(o.port, '/api/admin/rules', { rule: rule(), actor: 'it-operator' })).status, 403, 'mutations need --enable-admin');
      assert.equal(track(await post(a.port, `/api/admin/rules/${ruleId}/revoke`, { actor: 'it-operator' })).status, 400, 'a reason is required');
      const revoked = track(await post(a.port, `/api/admin/rules/${ruleId}/revoke`, { reason: 'integration test cleanup', actor: 'it-operator' }));
      assert.equal(revoked.status, 200, revoked.text);
      assert.deepEqual(revoked.json, { rule_id: ruleId, status: 'revoked' });
      const again = track(await post(a.port, `/api/admin/rules/${ruleId}/revoke`, { reason: 'twice', actor: 'it-operator' }));
      assert.equal(again.status, 400);
      assert.match(again.json.error.message, /only active rules/);
      const hist = track(await get(a.port, '/api/rules?status=revoked'));
      assert.equal(hist.json.rules.find((r) => r.rule_id === ruleId).decision_note, 'integration test cleanup');

      // reasoner-d's path: an incident-scoped investigator proposes; it is inert until approved here.
      const incident = track(await get(a.port, '/api/incidents')).json.incidents.find((i) => i.status === 'open' && i.host_id === HOST);
      assert.ok(incident, 'an open incident exists');
      const minted = await admin.call({ admin_op: 'mint_capability_token', principal_id: 'reasoner-it', role: 'investigator', allowed_hosts: [HOST], allowed_collectors: ALL_COLLECTORS, incident_id: incident.incident_id, ttl_seconds: 600 });
      assert.equal(minted.admin_result, 'token_minted', JSON.stringify(minted));
      secrets.push(minted.token);
      const reasoner = new InvestigationClient({ socketPath: invSock, token: minted.token });
      const run = await reasoner.call({ op: 'start_investigation_run', incident_id: incident.incident_id, backend_id: 'it-backend', model_id: 'it-model', prompt_schema_version: 'reasoner.v3' });
      assert.equal(run.result, 'run_started', JSON.stringify(run));
      const proposal = await reasoner.call({ op: 'propose_expectation_rule', run_id: run.run_id, idempotency_key: 'it-rule-1', rule: rule({ rationale: 'helperd listener is part of the sanctioned deployment' }) });
      assert.equal(proposal.result, 'rule_proposal_evaluated', JSON.stringify(proposal));
      assert.equal(proposal.decision.allowed, true, JSON.stringify(proposal));
      const proposedId = proposal.rule_id;
      const pending = track(await get(a.port, '/api/rules?status=proposed'));
      const p = pending.json.rules.find((r) => r.rule_id === proposedId);
      assert.ok(p, pending.text);
      assert.equal(p.origin, 'investigator');
      assert.equal(p.proposed_by, 'reasoner-it');
      assert.equal(p.run_id, run.run_id);
      assert.equal(p.incident_id, incident.incident_id);
      assert.deepEqual(Object.keys(p.backtest).sort(), BACKTEST_KEYS, 'the stored backtest is shown with the proposal');
      assert.equal(track(await post(a.port, `/api/admin/rules/${proposedId}/decide`, { approve: 'yes', actor: 'it-operator' })).status, 400);
      const approved = track(await post(a.port, `/api/admin/rules/${proposedId}/decide`, { approve: true, note: 'confirmed with the host owner', actor: 'it-operator' }));
      assert.equal(approved.status, 200, approved.text);
      assert.deepEqual([approved.json.allowed, approved.json.status], [true, 'active']);
      const active = track(await get(a.port, '/api/rules?status=active')).json.rules.find((r) => r.rule_id === proposedId);
      assert.equal(active.decided_by, 'it-operator');
      assert.equal(active.decision_note, 'confirmed with the host owner');
      const twice = track(await post(a.port, `/api/admin/rules/${proposedId}/decide`, { approve: false, actor: 'it-operator' }));
      assert.equal(twice.status, 400);

      // Audit: the chain stays valid and records every step.
      const audit = track(await get(a.port, '/api/admin/audit?limit=500')).json;
      assert.equal(audit.chain.valid, true);
      assert.equal(audit.independent.valid, true);
      assert.equal(audit.independent.head, audit.chain.latest_hash);
      for (const t of ['rule_proposed', 'rule_activated', 'rule_revoked']) assert.ok(audit.entries.some((e) => e.event_type === t), t);
      const activation = audit.entries.findLast((e) => e.event_type === 'rule_activated' && e.payload.rule_id === proposedId);
      assert.equal(activation.actor, 'it-operator');
      const decisions = track(await get(a.port, '/api/admin/policy-decisions?rule_id=rule-gate/wildcard-bind')).json.decisions;
      assert.ok(decisions.length >= 1);
      for (const text of bodies) for (const secret of secrets) assert.ok(!text.includes(secret), 'token leaked to the browser');
    } finally {
      await a.app.close();
      await o.app.close();
    }
  });

  test('without --enable-admin, runs are refused instead of narrowing the shared token', async () => {
    const backend = createLiveBackend({ investigateSock: invSock, token: browseToken, adminSock, enableAdmin: false });
    const { app, port } = await startConsole(backend);
    try {
      const open = (await get(port, '/api/incidents')).json.incidents.filter((i) => i.status === 'open');
      assert.ok(open.length);
      const r = await post(port, `/api/incidents/${open[0].incident_id}/runs`, {});
      assert.equal(r.status, 403);
      assert.equal(r.json.error.code, 'admin_required_for_runs');
      assert.match(r.json.error.message, /--enable-admin/);
      assert.equal((await get(port, '/api/incidents')).status, 200, 'browse session untouched');
      const auto = await get(port, '/api/automation');
      assert.equal(auto.json.available, false);
    } finally {
      await app.close();
    }
  });
});

// ---------------------------------------------------------------------------
// 3. Demo mode walkthrough
// ---------------------------------------------------------------------------

describe('demo mode API walkthrough', () => {
  let app;
  let port;
  const INC = 'inc-2026-0042';
  const base = {
    collector_type: 'systemd.unit_state',
    parameters: { unit: 'nginx.service', hash_unit_files: true },
    interval_seconds: 30,
    timeout_seconds: 5,
    ttl_seconds: 3600,
    max_runs: 120,
    rationale: 'Track nginx restarts while the helper listener is investigated',
  };
  const propose = (over) => post(port, `/api/incidents/${INC}/proposals`, { ...base, ...over });

  before(async () => {
    ({ app, port } = await startConsole(createDemoBackend()));
  });
  after(() => app.close());

  test('status, fleet, incidents and incident context', async () => {
    const st = await get(port, '/api/status');
    assert.equal(st.json.mode, 'demo');
    assert.equal(st.json.admin_enabled, true);
    assert.equal(st.json.audit.valid, true);

    const hosts = (await get(port, '/api/hosts')).json.hosts;
    assert.equal(hosts.length, 5);
    assert.deepEqual(new Set(hosts.map((h) => h.liveness_status)), new Set(['online', 'stale', 'offline']));

    const incidents = (await get(port, '/api/incidents')).json.incidents;
    const inc = incidents.find((i) => i.incident_id === INC);
    assert.equal(inc.status, 'open');
    assert.equal(inc.priority, 'high');

    const ctx = (await get(port, `/api/incidents/${INC}`)).json;
    assert.equal(ctx.incident.host_id, 'edge-vm-07');
    assert.ok(ctx.active_watches.some((w) => w.class === 'baseline'));
    assert.ok(ctx.active_watches.some((w) => w.class === 'ephemeral'));
    assert.ok(ctx.active_watches.some((w) => w.class === 'ephemeral' && Date.parse(w.lifecycle.expires_at) < Date.now()), 'expired ephemeral watch present');
    const kinds = new Set(ctx.findings.map((f) => f.finding.kind));
    assert.ok(kinds.has('hypothesis') && kinds.has('verified_finding'));
    const collectors = new Set(ctx.active_watches.map((w) => w.collector.type));
    for (const c of ['sockets.listening', 'systemd.unit_state', 'journal.unit_events']) assert.ok(collectors.has(c));
    for (const o of ctx.recent_observations) assert.match(o.state_hash, /^[0-9a-f]{64}$/);
    assert.ok(ctx.recent_observations.some((o) => o.payload.kind === 'stream_batch'));
    assert.equal(ctx.run, null);
  });

  test('capabilities, observations filters and three-state baselines', async () => {
    const caps = (await get(port, '/api/hosts/edge-vm-07/capabilities')).json.capabilities;
    assert.deepEqual(caps.map((c) => c.collector_type), EVERY_COLLECTOR);

    const all = (await get(port, '/api/hosts/edge-vm-07/observations')).json.observations;
    const filtered = (await get(port, '/api/hosts/edge-vm-07/observations?watch_id=base-sockets-listening&limit=2')).json.observations;
    assert.ok(all.length > filtered.length);
    assert.equal(filtered.length, 2);
    assert.ok(filtered.every((o) => o.watch_id === 'base-sockets-listening'));
    assert.equal((await get(port, '/api/hosts/edge-vm-07/observations?limit=0')).status, 400);
    assert.equal((await get(port, '/api/hosts/edge-nope/observations')).status, 404);

    const tri = (await get(port, '/api/hosts/edge-vm-07/baselines')).json.three_state;
    const units = tri.find((r) => r.watch_id === 'base-systemd-units');
    assert.equal(units.state, 'drift');
    const hashes = new Set([units.accepted_baseline.state_hash, units.last_observed.state_hash, units.current_observed.state_hash]);
    assert.equal(hashes.size, 3, 'accepted, last and current are three distinct states');
    assert.equal(tri.find((r) => r.watch_id === 'base-sshd-unit').state, 'in_sync');
    assert.equal(tri.find((r) => r.watch_id === 'ephem-0042-helper-unit').state, 'no_trusted_baseline');
    const v11 = (await get(port, '/api/hosts/edge-vm-11/baselines')).json.three_state;
    assert.equal(v11[0].state, 'collector_error');
  });

  test('proposals: run required, accepted, then denied by real rule IDs', async () => {
    const noRun = await propose({});
    assert.equal(noRun.status, 409);
    assert.equal(noRun.json.error.code, 'run_required');

    const run = await post(port, `/api/incidents/${INC}/runs`, { backend_id: 'operator-console', model_id: 'human-operator' });
    assert.equal(run.status, 200);
    assert.match(run.json.run_id, /^[0-9a-f-]{36}$/);

    const bundleBefore = (await get(port, '/api/hosts')).json.hosts.find((h) => h.host_id === 'edge-vm-07').active_bundle_version;
    const ok = await propose({});
    assert.equal(ok.status, 200, ok.text);
    assert.equal(ok.json.decision.allowed, true);
    assert.equal(ok.json.decision.rule_id, 'policy.accepted');
    assert.equal(ok.json.bundle_version, bundleBefore + 1);
    assert.equal(ok.json.spec.class, 'ephemeral');
    assert.equal(ok.json.spec.incident_id, INC);
    const ctx = (await get(port, `/api/incidents/${INC}`)).json;
    assert.ok(ctx.active_watches.some((w) => w.id === ok.json.watch_id));
    assert.equal(ctx.run.run_id, run.json.run_id);

    const cases = [
      [{}, 'dedup.equivalent_active_watch', /equivalent watch/],
      [{ class: 'baseline', parameters: { unit: 'cron.service' } }, 'baseline.protected', /cannot create or modify baseline/],
      [{ parameters: { unit: 'cron.service' }, interval_seconds: 5, timeout_seconds: 2 }, 'spec.safety_floor', /interval_seconds 5 is below local floor 15/],
      [{ collector_type: 'files.metadata', parameters: { paths: ['/etc/shadow'] } }, 'spec.safety_floor', /sensitive path denylist/],
      [{ collector_type: 'files.metadata', parameters: { paths: ['/etc/ssh/ssh_host_ed25519_key'] } }, 'spec.safety_floor', /denied sensitive suffix/],
      [{ parameters: { unit: 'cron.service' }, ttl_seconds: 5 * 3600 }, 'spec.safety_floor', /exceeds maximum TTL/],
      [{ parameters: { unit: 'cron.service' }, max_runs: 5000 }, 'spec.safety_floor', /max_runs 5000/],
      [{ parameters: { unit: 'cron;rm -rf' } }, 'spec.safety_floor', /forbidden characters/],
      [{ parameters: { unit: 'cron.service' }, trigger: { type: 'field_changed', compare_against: 'accepted_baseline', fields: ['active_state'] } }, 'spec.safety_floor', /cannot compare against accepted_baseline/],
    ];
    for (const [over, rule, reason] of cases) {
      const r = await propose(over);
      assert.equal(r.status, 200, r.text);
      assert.equal(r.json.decision.allowed, false, JSON.stringify(over));
      assert.equal(r.json.decision.rule_id, rule);
      assert.match(r.json.decision.reason, reason);
      assert.equal(r.json.watch_id, null);
    }

    const decisions = (await get(port, '/api/admin/policy-decisions')).json.decisions;
    assert.ok(decisions.some((d) => d.decision.rule_id === 'baseline.protected' && d.actor === 'console-operator'));
    const onlyFloor = (await get(port, '/api/admin/policy-decisions?rule_id=spec.safety_floor')).json.decisions;
    assert.ok(onlyFloor.length >= 7);
    assert.ok(onlyFloor.every((d) => d.decision.rule_id === 'spec.safety_floor'));

    const badBody = await propose({ collector_type: 'shell.exec' });
    assert.equal(badBody.status, 400);
  });

  test('hypotheses and verified findings bind evidence', async () => {
    const ctx = (await get(port, `/api/incidents/${INC}`)).json;
    const evidence = ctx.recent_observations.slice(0, 2).map((o) => o.observation_id);

    const noEvidence = await post(port, `/api/incidents/${INC}/findings`, { kind: 'verified_finding', severity: 'high', summary: 'x', evidence_observation_ids: [] });
    assert.equal(noEvidence.status, 400);
    const badKind = await post(port, `/api/incidents/${INC}/findings`, { kind: 'certainty', summary: 'x' });
    assert.equal(badKind.status, 400);
    const foreign = await post(port, `/api/incidents/${INC}/findings`, { kind: 'hypothesis', summary: 'x', evidence_observation_ids: [ctx.recent_observations.length ? 9999999 : 1] });
    assert.equal(foreign.status, 400);

    const hyp = await post(port, `/api/incidents/${INC}/findings`, { kind: 'hypothesis', severity: 'medium', summary: 'helperd may beacon', uncertainty: 'no egress telemetry', evidence_observation_ids: [] });
    assert.equal(hyp.status, 200, hyp.text);
    assert.equal(hyp.json.verified_evidence_count, 0);

    const ver = await post(port, `/api/incidents/${INC}/findings`, { kind: 'verified_finding', severity: 'high', summary: 'listener owned by helperd', evidence_observation_ids: evidence });
    assert.equal(ver.status, 200, ver.text);
    assert.equal(ver.json.verified_evidence_count, evidence.length);

    const after = (await get(port, `/api/incidents/${INC}`)).json.findings;
    const rec = after.find((f) => f.finding_id === ver.json.finding_id);
    assert.equal(rec.finding.kind, 'verified_finding');
    assert.deepEqual(rec.finding.evidence_observation_ids, [...evidence].sort((a, b) => a - b));
  });

  test('baseline promotion, incident closure and audit verification', async () => {
    const tri = (await get(port, '/api/hosts/edge-vm-07/baselines')).json.three_state;
    const row = tri.find((r) => r.watch_id === 'base-systemd-units');
    const missing = await post(port, '/api/admin/baselines/promote', { host_id: 'edge-vm-07', watch_id: row.watch_id, observation_id: row.promotable_observation_id, approver: 'j.rivera' });
    assert.equal(missing.status, 400, 'rationale is required');
    const ephemeral = await post(port, '/api/admin/baselines/promote', { host_id: 'edge-vm-07', watch_id: 'ephem-0042-helper-unit', observation_id: 1, approver: 'a', rationale: 'r' });
    assert.equal(ephemeral.status, 400);

    const promoted = await post(port, '/api/admin/baselines/promote', {
      host_id: 'edge-vm-07',
      watch_id: row.watch_id,
      observation_id: row.promotable_observation_id,
      approver: 'j.rivera',
      rationale: 'Verified helper rollout',
      ticket_ref: 'CHG-4502',
    });
    assert.equal(promoted.status, 200, promoted.text);
    assert.ok(promoted.json.revision_id > row.accepted_baseline.revision_id);
    assert.equal(promoted.json.state_hash, row.current_observed.state_hash);
    const tri2 = (await get(port, '/api/hosts/edge-vm-07/baselines')).json.three_state;
    const row2 = tri2.find((r) => r.watch_id === 'base-systemd-units');
    assert.equal(row2.state, 'in_sync');
    assert.equal(row2.accepted_baseline.ticket_ref, 'CHG-4502');

    const closed = await post(port, `/api/admin/incidents/${INC}/close`, { actor: 'j.rivera', resolution: 'Unauthorized helper removed; host reimaged' });
    assert.equal(closed.status, 200, closed.text);
    assert.ok(closed.json.retired_ephemeral_watches >= 3, `retired ${closed.json.retired_ephemeral_watches}`);
    const ctx = (await get(port, `/api/incidents/${INC}`)).json;
    assert.equal(ctx.incident.status, 'closed');
    assert.ok(!ctx.active_watches.some((w) => w.class === 'ephemeral'));
    const late = await propose({ parameters: { unit: 'cron.service' } });
    assert.notEqual(late.status, 200);
    assert.equal((await post(port, `/api/admin/incidents/${INC}/close`, { actor: 'a', resolution: 'again' })).status, 400);

    const audit = (await get(port, '/api/admin/audit?limit=500')).json;
    assert.equal(audit.chain.valid, true);
    assert.equal(audit.independent.valid, true);
    assert.equal(audit.independent.head, audit.chain.latest_hash);
    const types = audit.entries.map((e) => e.event_type);
    for (const t of ['run_started', 'watch_proposed', 'policy_decision', 'bundle_issued', 'finding_recorded', 'baseline_promoted', 'incident_closed']) {
      assert.ok(types.includes(t), t);
    }
    for (let i = 1; i < audit.entries.length; i++) assert.equal(audit.entries[i].prev_hash, audit.entries[i - 1].entry_hash);
    for (const e of audit.entries) assert.equal(computeAuditHash(e), e.entry_hash);

    const enroll = await post(port, '/api/admin/hosts/enroll', { host_id: 'edge-vm-21' });
    assert.equal(enroll.status, 200);
    assert.ok((await get(port, '/api/hosts')).json.hosts.some((h) => h.host_id === 'edge-vm-21'));
  });

  test('tamper simulation is detected and reset restores the chain', async () => {
    const t = await post(port, '/api/demo/tamper', {});
    assert.equal(t.status, 200);
    const st = (await get(port, '/api/status')).json;
    assert.equal(st.audit.valid, false);
    assert.match(st.audit.error, new RegExp(`tampered entry at seq ${t.json.tampered_seq_no}`));
    const audit = (await get(port, '/api/admin/audit?limit=500')).json;
    assert.equal(audit.independent.valid, false);
    assert.equal(audit.independent.broken_seq, t.json.tampered_seq_no);

    await post(port, '/api/demo/reset', {});
    assert.equal((await get(port, '/api/status')).json.audit.valid, true);
    assert.equal((await get(port, `/api/incidents/${INC}`)).json.incident.status, 'open');
  });

  test('read-only demo gates admin routes', async () => {
    const ro = await startConsole(createDemoBackend({ enableAdmin: false }));
    try {
      assert.equal((await get(ro.port, '/api/admin/audit')).status, 403);
      assert.equal((await post(ro.port, '/api/admin/hosts/enroll', { host_id: 'x' })).status, 403);
      assert.equal((await get(ro.port, '/api/status')).json.audit, null);
    } finally {
      await ro.app.close();
    }
  });
});

// ---------------------------------------------------------------------------
// 4. Security
// ---------------------------------------------------------------------------

describe('security headers, origin/host validation and XSS hygiene', () => {
  let app;
  let port;
  let backend;
  before(async () => {
    backend = createDemoBackend();
    ({ app, port } = await startConsole(backend));
  });
  after(() => app.close());

  const assertHeaders = (r, label) => {
    const csp = r.headers['content-security-policy'];
    assert.ok(csp, `${label}: CSP missing`);
    assert.match(csp, /default-src 'self'/);
    assert.match(csp, /script-src 'self'(;|$)/);
    assert.match(csp, /frame-ancestors 'none'/);
    assert.doesNotMatch(csp, /unsafe-inline|unsafe-eval/);
    assert.equal(r.headers['x-frame-options'], 'DENY', label);
    assert.equal(r.headers['x-content-type-options'], 'nosniff', label);
  };

  test('every response carries CSP, X-Frame-Options and nosniff', async () => {
    const responses = {
      index: await get(port, '/'),
      script: await get(port, '/app.js'),
      css: await get(port, '/styles.css'),
      api: await get(port, '/api/status'),
      notFound: await get(port, '/nope'),
      apiNotFound: await get(port, '/api/nope'),
      badMethod: await request(port, 'DELETE', '/api/hosts'),
      crossOrigin: await post(port, '/api/demo/reset', {}, { headers: { Origin: 'http://evil.example' } }),
      badHost: await get(port, '/api/status', { host: 'evil.example' }),
    };
    for (const [label, r] of Object.entries(responses)) assertHeaders(r, label);
    assert.equal(responses.index.status, 200);
    assert.match(responses.index.headers['content-type'], /text\/html/);
    assert.match(responses.script.headers['content-type'], /javascript/);
    assert.equal(responses.badMethod.status, 405);
    assert.equal(responses.api.headers['cache-control'], 'no-store');
  });

  test('cross-origin and cross-site POSTs are rejected with 403 before any mutation', async () => {
    const before = (await get(port, '/api/admin/audit?limit=500')).json.entries.length;
    const evil = await post(port, '/api/incidents/inc-2026-0042/runs', {}, { headers: { Origin: 'http://evil.example' } });
    assert.equal(evil.status, 403);
    assert.equal(evil.json.error.code, 'cross_origin_denied');
    const nullOrigin = await post(port, '/api/incidents/inc-2026-0042/runs', {}, { headers: { Origin: 'null' } });
    assert.equal(nullOrigin.status, 403);
    const otherPort = await post(port, '/api/incidents/inc-2026-0042/runs', {}, { headers: { Origin: `http://127.0.0.1:${port + 1}` } });
    assert.equal(otherPort.status, 403);
    const crossSite = await request(port, 'POST', '/api/admin/hosts/enroll', { body: { host_id: 'edge-evil' }, headers: { 'Sec-Fetch-Site': 'cross-site' } });
    assert.equal(crossSite.status, 403);
    const formPost = await post(port, '/api/admin/hosts/enroll', undefined, { rawBody: 'host_id=edge-evil', headers: { 'Content-Type': 'application/x-www-form-urlencoded' } });
    assert.equal(formPost.status, 415);
    const afterCount = (await get(port, '/api/admin/audit?limit=500')).json.entries.length;
    assert.equal(afterCount, before, 'rejected requests must not mutate state');
    assert.ok(!(await get(port, '/api/hosts')).json.hosts.some((h) => h.host_id === 'edge-evil'));

    const same = await post(port, '/api/incidents/inc-2026-0042/runs', {});
    assert.equal(same.status, 200);
    const noOrigin = await request(port, 'POST', '/api/incidents/inc-2026-0042/runs', { body: {} });
    assert.equal(noOrigin.status, 200, 'non-browser local clients without Origin are allowed');
  });

  test('Host header is validated (DNS rebinding defence)', async () => {
    assert.equal((await get(port, '/api/status', { host: `evil.example:${port}` })).status, 403);
    assert.equal((await get(port, '/', { host: 'attacker.test' })).status, 403);
    assert.equal((await get(port, '/api/status', { host: `localhost:${port}` })).status, 200);
    assert.equal((await get(port, '/api/status', { host: `[::1]:${port}` })).status, 200);
  });

  test('oversized and malformed bodies are refused', async () => {
    const big = await post(port, '/api/incidents/inc-2026-0042/findings', { summary: 'x'.repeat(70 * 1024) });
    assert.equal(big.status, 413);
    const malformed = await post(port, '/api/incidents/inc-2026-0042/findings', undefined, { rawBody: '{not json' });
    assert.equal(malformed.status, 400);
    const arr = await post(port, '/api/incidents/inc-2026-0042/findings', [1, 2]);
    assert.equal(arr.status, 400);
  });

  test('static serving is an allowlist: no traversal, no source disclosure', async () => {
    for (const p of ['/../server.mjs', '/%2e%2e/server.mjs', '/..%2fserver.mjs', '/lib/demo-data.mjs', '/test/server.test.mjs', '/public/app.js']) {
      const r = await get(port, p);
      assert.equal(r.status, 404, p);
      assert.ok(!r.text.includes('createConsoleServer'));
    }
  });

  test('server binds to loopback by default', async () => {
    assert.equal(parseArgs(['--demo']).host, '127.0.0.1');
    assert.equal(app.server.address().address, '127.0.0.1');
    assert.throws(() => parseArgs(['--investigate-sock', '/x']), /capability token is required/);
    assert.throws(() => parseArgs(['--investigate-sock', '/x', '--token', 't', '--enable-admin']), /--admin-sock/);
    assert.equal(parseArgs(['--investigate-sock', '/x'], { DEFSEC_CAPABILITY_TOKEN: 'envtok' }).token, 'envtok');
  });

  test('UI never uses innerHTML or inline script/style; adversarial telemetry stays data', async () => {
    const pub = path.join(CONSOLE_DIR, 'public');
    for (const f of fs.readdirSync(pub).filter((n) => n.endsWith('.js'))) {
      const src = fs.readFileSync(path.join(pub, f), 'utf8');
      assert.doesNotMatch(src, /\.(innerHTML|outerHTML)\s*=|insertAdjacentHTML|document\.write|\beval\(|new Function\(/, f);
      assert.doesNotMatch(src, /setAttribute\(\s*['"]style['"]/, f);
    }
    const html = fs.readFileSync(path.join(pub, 'index.html'), 'utf8');
    assert.doesNotMatch(html, /<script(?![^>]*\bsrc=)[^>]*>/i, 'no inline scripts');
    assert.doesNotMatch(html, /\sstyle=|<style/i, 'no inline styles');
    assert.doesNotMatch(html, /\son[a-z]+=/i, 'no inline handlers');

    // The adversarial journal line reaches the browser as an inert JSON string.
    const ctx = await get(port, '/api/incidents/inc-2026-0042');
    const msgs = ctx.json.recent_observations.flatMap((o) => o.payload.events ?? []).map((e) => e.message_redacted);
    assert.ok(msgs.some((m) => m.includes('<img src=x onerror=')), 'fixture contains an XSS probe');
    assert.match(ctx.headers['content-type'], /^application\/json/);
  });

  test('audit hash helper detects single-field tampering', () => {
    const entries = backend._state().audit.slice(0, 5).map((e) => structuredClone(e));
    assert.equal(verifyEntries(entries).valid, true);
    entries[2].actor = 'mallory';
    const v = verifyEntries(entries);
    assert.equal(v.valid, false);
    assert.equal(v.broken_seq, entries[2].seq_no);
  });
});

// ---------------------------------------------------------------------------
// 5. Phase 8 mitigations in demo mode
// ---------------------------------------------------------------------------

const SUMMARY_KEYS = ['approver', 'auth_mode', 'blast_radius', 'created_at', 'expected_effect', 'host_id', 'incident_id', 'intent_id', 'proposal_id', 'rollback_plan', 'status', 'verb'];
const PAYLOAD_KEYS = ['auth_mode', 'evidence_observation_ids', 'expires_at', 'host_id', 'incident_id', 'intent_id', 'issued_at', 'nonce', 'policy_version', 'proposal_id', 'rollback_plan', 'schema_version', 'verb'];
const ENVELOPE_KEYS = ['domain', 'raw_payload', 'signature_hex', 'signing_key_id'];
const STATUSES = ['pending_approval', 'authorized', 'executed', 'dry_run_simulated', 'rolled_back', 'rejected', 'verification_failed', 'expired'];

describe('Phase 8 mitigations (demo)', () => {
  let app;
  let port;
  let clock;
  let backend;
  before(async () => {
    clock = Date.now();
    backend = createDemoBackend({ now: () => clock });
    ({ app, port } = await startConsole(backend));
  });
  after(() => app.close());

  const byVerb = (list, verb) => list.find((a) => a.verb.verb === verb && a.status === 'pending_approval');

  test('list shows every lifecycle state with control-d\'s exact ActionSummary schema', async () => {
    const r = await get(port, '/api/actions');
    assert.equal(r.status, 200, r.text);
    const { actions, denied } = r.json;
    for (const a of actions) {
      assert.deepEqual(Object.keys(a).sort(), SUMMARY_KEYS);
      assert.ok(STATUSES.includes(a.status), a.status);
      assert.ok(['policy_bounded_autonomous', 'dual_signed_operator'].includes(a.auth_mode));
      assert.match(a.intent_id, /^[0-9a-f-]{36}$/);
      assert.ok(['nft_block_ip', 'systemd_stop_unit', 'host_isolate'].includes(a.verb.verb));
    }
    const statuses = new Set(actions.map((a) => a.status));
    for (const s of ['pending_approval', 'executed', 'rolled_back', 'expired']) assert.ok(statuses.has(s), s);
    const auto = actions.find((a) => a.status === 'executed');
    assert.equal(auto.auth_mode, 'policy_bounded_autonomous');
    assert.equal(auto.verb.verb, 'nft_block_ip');
    assert.ok(auto.verb.ttl_seconds <= 1800, 'autonomous TTL bounded by policy');
    const iso = byVerb(actions, 'host_isolate');
    assert.equal(iso.auth_mode, 'dual_signed_operator');
    assert.ok(iso.verb.preserve_mgmt_cidrs.length >= 1, 'host_isolate always preserves management CIDRs');
    assert.ok(byVerb(actions, 'systemd_stop_unit'));

    const rules = denied.map((d) => d.decision.rule_id).sort();
    assert.deepEqual(rules, ['action.protected_ip', 'action.protected_unit']);
    const ssh = denied.find((d) => d.decision.rule_id === 'action.protected_unit');
    assert.equal(ssh.verb.unit, 'ssh.service');
    assert.equal(ssh.decision.allowed, false);
    assert.ok(!actions.some((a) => a.verb.unit === 'ssh.service'), 'a denied proposal never becomes an intent');

    const scoped = (await get(port, '/api/actions?host_id=edge-vm-03')).json;
    assert.ok(scoped.actions.length >= 1 && scoped.actions.every((a) => a.host_id === 'edge-vm-03'));
    assert.deepEqual(scoped.denied, []);
    const inc = (await get(port, '/api/actions?incident_id=inc-2026-0042')).json;
    assert.ok(inc.actions.every((a) => a.incident_id === 'inc-2026-0042'));
    assert.equal((await get(port, '/api/actions?incident_id=..%2F..')).status, 400);

    const decisions = (await get(port, '/api/admin/policy-decisions?rule_id=action.protected_unit')).json.decisions;
    assert.equal(decisions.length, 1);
  });

  test('detail returns the signed intent payload, receipts and offline-signing digest', async () => {
    const { actions } = (await get(port, '/api/actions')).json;
    const pending = byVerb(actions, 'host_isolate');
    const d = (await get(port, `/api/admin/actions/${pending.intent_id}`)).json;
    assert.deepEqual(Object.keys(d.payload).sort(), PAYLOAD_KEYS);
    assert.equal(d.status, 'pending_approval');
    assert.equal(d.authorized_intent, null, 'control envelope is released only once authorized');
    assert.equal(d.payload.intent_id, pending.intent_id);
    assert.equal(d.payload.auth_mode, 'dual_signed_operator');
    assert.equal(Date.parse(d.payload.expires_at) - Date.parse(d.payload.issued_at), pending.verb.ttl_seconds * 1000);
    assert.ok(d.payload.evidence_observation_ids.length >= 1);
    assert.equal(d.signing.domain, 'defsecautmit.action_approval.v1');
    assert.equal(d.signing.canonical_payload, canonicalJson(d.payload));
    assert.equal(d.signing.payload_sha256, sha256Hex(d.signing.canonical_payload));

    const executed = actions.find((a) => a.status === 'executed');
    const e = (await get(port, `/api/admin/actions/${executed.intent_id}`)).json;
    assert.deepEqual(Object.keys(e.authorized_intent.control_envelope).sort(), ENVELOPE_KEYS);
    assert.equal(e.authorized_intent.control_envelope.domain, 'defsecautmit.action_intent.v1');
    assert.equal(e.authorized_intent.control_envelope.raw_payload, canonicalJson(e.payload));
    assert.match(e.authorized_intent.control_envelope.signature_hex, /^[0-9a-f]{128}$/);
    assert.equal(e.authorized_intent.operator_approval, null);
    assert.equal(e.receipts.at(-1).status, 'executed');
    assert.ok(e.receipts.at(-1).rollback_handle);
    assert.equal(e.receipts.at(-1).verification_passed, true);

    const rolled = actions.find((a) => a.status === 'rolled_back');
    const rb = (await get(port, `/api/admin/actions/${rolled.intent_id}`)).json;
    assert.deepEqual(rb.receipts.map((x) => x.status), ['executed', 'rolled_back']);

    assert.equal((await get(port, `/api/admin/actions/${crypto.randomUUID()}`)).status, 404);
  });

  test('approval enforces control-d rules, then authorizes, executes and rolls back', async () => {
    const { actions } = (await get(port, '/api/actions')).json;
    const iso = byVerb(actions, 'host_isolate');
    const stop = byVerb(actions, 'systemd_stop_unit');
    const auditLen = async () => (await get(port, '/api/admin/audit?limit=500')).json.entries.length;
    const before = await auditLen();
    const url = `/api/admin/actions/${iso.intent_id}/approve`;
    const detail = (await get(port, `/api/admin/actions/${iso.intent_id}`)).json;

    assert.equal((await post(port, url, {})).status, 400, 'approver is required');
    const cross = await post(port, url, { approver: 'mallory' }, { headers: { Origin: 'http://evil.example' } });
    assert.equal(cross.status, 403);
    const forged = { domain: 'defsecautmit.action_approval.v1', signing_key_id: 'demo-operator-01', raw_payload: detail.signing.canonical_payload, signature_hex: '00'.repeat(64) };
    const f1 = await post(port, url, { approver: 'mallory', operator_approval: forged });
    assert.equal(f1.status, 403);
    assert.match(f1.json.error.message, /invalid operator approval: signature verification failed/);
    const f2 = await post(port, url, { approver: 'mallory', operator_approval: { ...forged, signing_key_id: 'attacker-key' } });
    assert.match(f2.json.error.message, /unknown signing key id/);
    const f3 = await post(port, url, { approver: 'mallory', operator_approval: { ...forged, raw_payload: canonicalJson({ ...detail.payload, host_id: 'edge-vm-03' }) } });
    assert.match(f3.json.error.message, /payload differs from control intent/);
    const f4 = await post(port, url, { approver: 'mallory', operator_approval: { ...forged, signing_key_id: 'control-key-01' } });
    assert.match(f4.json.error.message, /independent signing key/);
    assert.equal(await auditLen(), before, 'rejected approvals leave no trace in state');

    const ok = await post(port, url, { approver: 'j.rivera', note: 'confirmed with host owner' });
    assert.equal(ok.status, 200, ok.text);
    const ai = ok.json.authorized_intent;
    assert.equal(ai.operator_approval.domain, 'defsecautmit.action_approval.v1');
    assert.equal(ai.operator_approval.raw_payload, ai.control_envelope.raw_payload, 'operator signs the exact control payload');
    assert.notEqual(ai.operator_approval.signing_key_id, ai.control_envelope.signing_key_id);

    const again = await post(port, url, { approver: 'j.rivera' });
    assert.equal(again.status, 403);
    assert.match(again.json.error.message, /not pending dual approval/);
    const cooldown = await post(port, `/api/admin/actions/${stop.intent_id}/approve`, { approver: 'j.rivera' });
    assert.equal(cooldown.status, 403);
    assert.match(cooldown.json.error.message, /rate limit or cooldown/);

    let list = (await get(port, '/api/actions')).json.actions;
    const authorized = list.find((a) => a.intent_id === iso.intent_id);
    assert.equal(authorized.status, 'authorized');
    assert.equal(authorized.approver, 'j.rivera');

    const audit = (await get(port, '/api/admin/audit?limit=500')).json;
    const approved = audit.entries.filter((e) => e.event_type === 'action_approved').at(-1);
    assert.equal(approved.actor, 'j.rivera');
    assert.equal(approved.payload.intent_id, iso.intent_id);
    assert.equal(approved.payload.payload_digest, sha256Hex(ai.operator_approval.raw_payload));
    assert.equal(audit.chain.valid, true);
    assert.equal(audit.independent.valid, true);

    // action-exec-d picks it up a few seconds later, then the TTL lifts it.
    clock += 5_000;
    list = (await get(port, '/api/actions')).json.actions;
    assert.equal(list.find((a) => a.intent_id === iso.intent_id).status, 'executed');
    clock += iso.verb.ttl_seconds * 1000 + 1_000;
    const done = (await get(port, `/api/admin/actions/${iso.intent_id}`)).json;
    assert.equal(done.status, 'rolled_back');
    assert.deepEqual(done.receipts.map((r) => r.status), ['executed', 'rolled_back']);
    const late = await post(port, `/api/admin/actions/${stop.intent_id}/approve`, { approver: 'j.rivera' });
    assert.equal(late.status, 403, 'approval window elapsed');
    assert.match(late.json.error.message, /expired/);
    const final = (await get(port, '/api/admin/audit?limit=500')).json;
    assert.equal(final.independent.valid, true);
    for (const t of ['action_proposed', 'action_approved', 'action_receipt_recorded', 'action_rolled_back']) {
      assert.ok(final.entries.some((e) => e.event_type === t), t);
    }
    await post(port, '/api/demo/reset', {});
  });

  test('read-only demo keeps the list but gates detail and approval', async () => {
    const ro = await startConsole(createDemoBackend({ enableAdmin: false }));
    try {
      const list = await get(ro.port, '/api/actions');
      assert.equal(list.status, 200);
      const id = list.json.actions[0].intent_id;
      assert.equal((await get(ro.port, `/api/admin/actions/${id}`)).json.error.code, 'admin_disabled');
      assert.equal((await post(ro.port, `/api/admin/actions/${id}/approve`, { approver: 'x' })).status, 403);
    } finally {
      await ro.app.close();
    }
  });
});

// ---------------------------------------------------------------------------
// 6. Access gate: local accounts
// ---------------------------------------------------------------------------

const cookieOf = (r) => (r.headers['set-cookie'] ?? [])[0] ?? '';
const cookieHeader = (setCookie) => setCookie.split(';')[0];

describe('access gate: --create-user and local sessions', () => {
  let dir;
  let usersFile;
  let app;
  let port;
  let auth;
  const ADMIN_PW = 'correct horse battery staple';
  const OBS_PW = 'observer pass phrase 1';

  before(async () => {
    dir = shortTmp('dsa-');
    usersFile = path.join(dir, 'users.json');
    // Real CLI, password over stdin (never argv).
    const cli = spawnSync(process.execPath, [path.join(CONSOLE_DIR, 'server.mjs'), '--create-user', '--auth-users-file', usersFile, '--username', 'alice', '--role', 'admin', '--password-stdin'], { input: `${ADMIN_PW}\n`, encoding: 'utf8' });
    assert.equal(cli.status, 0, cli.stderr);
    assert.match(cli.stdout, /created admin account 'alice'/);
    // Password from an environment variable.
    const opts = parseArgs(['--create-user', '--auth-users-file', usersFile, '--username', 'bob', '--role', 'observer', '--password-env', 'BOB_PW'], {});
    const out = { text: '', write(t) { this.text += t; } };
    await runCreateUser(opts, { env: { BOB_PW: OBS_PW }, out });
    assert.match(out.text, /created observer account 'bob'/);
    auth = createAuth({ mode: 'local', usersFile });
    ({ app, port } = await startConsole(createDemoBackend(), { auth }));
  });
  after(async () => {
    await app?.close();
    fs.rmSync(dir, { recursive: true, force: true });
  });

  const login = (username, password, opts = {}) => post(port, '/api/auth/login', { username, password }, opts);

  test('users file is 0600, salted scrypt, no plaintext; CLI rejects weak input', async () => {
    assert.equal(fs.statSync(usersFile).mode & 0o777, 0o600);
    const raw = fs.readFileSync(usersFile, 'utf8');
    assert.ok(!raw.includes(ADMIN_PW) && !raw.includes(OBS_PW));
    const data = readUsersFile(usersFile);
    assert.deepEqual(Object.keys(data.users).sort(), ['alice', 'bob']);
    const a = data.users.alice;
    assert.equal(a.role, 'admin');
    assert.equal(a.algo, 'scrypt');
    assert.equal(Buffer.from(a.salt, 'base64').length, 16);
    assert.notEqual(a.salt, data.users.bob.salt);
    assert.equal(fs.readdirSync(dir).filter((n) => n.endsWith('.tmp')).length, 0, 'atomic write leaves no temp files');

    assert.throws(() => upsertUser(usersFile, { username: 'carol', role: 'admin', password: 'short' }), /at least 12/);
    assert.throws(() => upsertUser(usersFile, { username: '__proto__', role: 'admin', password: 'long enough password' }), /username/);
    assert.throws(() => upsertUser(usersFile, { username: 'carol', role: 'root', password: 'long enough password' }), /role/);
    assert.throws(() => parseArgs(['--create-user', '--auth-users-file', usersFile, '--username', 'x'], {}), /--role/);
    const bad = spawnSync(process.execPath, [path.join(CONSOLE_DIR, 'server.mjs'), '--create-user', '--auth-users-file', usersFile, '--username', 'eve', '--role', 'admin', '--password-env', 'NOPE'], { encoding: 'utf8', env: {} });
    assert.equal(bad.status, 1);
    assert.match(bad.stderr, /NOPE is not set/);
    assert.throws(() => parseArgs(['--demo', '--auth-mode', 'local'], {}), /--auth-users-file/);
    assert.throws(() => parseArgs(['--demo', '--auth-mode', 'kerberos'], {}), /--auth-mode/);
    assert.equal(parseArgs(['--demo', '--auth-mode', 'local', '--auth-users-file', usersFile], {}).authMode, 'local');
    assert.equal(parseArgs(['--demo'], { DEFSEC_CONSOLE_AUTH_MODE: 'local', DEFSEC_CONSOLE_USERS_FILE: usersFile }).authMode, 'local');
  });

  test('unauthenticated: session reachable, every other /api route 401, no telemetry leaks', async () => {
    const s = await get(port, '/api/auth/session');
    assert.equal(s.status, 200);
    assert.deepEqual(s.json, { auth_mode: 'local', authenticated: false, user: null });
    for (const p of ['/api/status', '/api/hosts', '/api/incidents/inc-2026-0042', '/api/actions', '/api/admin/audit', '/api/nope']) {
      const r = await get(port, p);
      assert.equal(r.status, 401, p);
      assert.ok(!r.text.includes('edge-vm-07'), `${p} leaked telemetry`);
    }
    assert.equal((await post(port, '/api/incidents/inc-2026-0042/runs', {})).status, 401);
    const shell = await get(port, '/');
    assert.equal(shell.status, 200, 'static shell loads so the sign-in view can render');
    assert.ok(!shell.text.includes('edge-vm-07'));
    assert.equal((await get(port, '/api/hosts', { headers: { Cookie: `${SESSION_COOKIE}=forged.token` } })).status, 401);
  });

  test('wrong password and unknown user are indistinguishable 401s; login is CSRF-guarded', async () => {
    const wrong = await login('alice', 'not the password');
    const unknown = await login('nobody', 'not the password');
    for (const r of [wrong, unknown]) {
      assert.equal(r.status, 401);
      assert.deepEqual(r.json.error, { code: 'invalid_credentials', message: 'invalid username or password' });
      assert.equal(r.headers['set-cookie'], undefined);
    }
    assert.equal((await login('alice', ADMIN_PW, { headers: { Origin: 'http://evil.example' } })).status, 403);
    assert.equal((await post(port, '/api/auth/login', undefined, { rawBody: 'username=alice', headers: { 'Content-Type': 'application/x-www-form-urlencoded' } })).status, 415);
    assert.equal((await get(port, '/api/auth/login')).status, 405);
  });

  test('successful login sets an HttpOnly SameSite=Strict cookie; roles gate admin routes', async () => {
    const r = await login('bob', OBS_PW);
    assert.equal(r.status, 200, r.text);
    assert.deepEqual(r.json.user, { username: 'bob', role: 'observer' });
    const sc = cookieOf(r);
    assert.match(sc, new RegExp(`^${SESSION_COOKIE}=[A-Za-z0-9_-]{43}\\.[A-Za-z0-9_-]{43};`));
    for (const attr of ['HttpOnly', 'SameSite=Strict', 'Path=/', 'Max-Age=28800']) assert.ok(sc.includes(attr), attr);
    assert.ok(!/;\s*Secure/.test(sc), 'no Secure on plain loopback HTTP');
    const obs = { headers: { Cookie: cookieHeader(sc) } };

    assert.deepEqual((await get(port, '/api/auth/session', obs)).json, { auth_mode: 'local', authenticated: true, user: { username: 'bob', role: 'observer' } });
    assert.equal((await get(port, '/api/hosts', obs)).status, 200);
    assert.equal((await get(port, '/api/actions', obs)).status, 200);
    for (const p of ['/api/admin/audit', '/api/admin/policy-decisions']) {
      const x = await get(port, p, obs);
      assert.equal(x.status, 403, p);
      assert.equal(x.json.error.code, 'admin_role_required');
    }
    const { actions } = (await get(port, '/api/actions', obs)).json;
    const pending = actions.find((a) => a.status === 'pending_approval');
    assert.equal((await get(port, `/api/admin/actions/${pending.intent_id}`, obs)).status, 403);
    assert.equal((await post(port, `/api/admin/actions/${pending.intent_id}/approve`, { approver: 'bob' }, obs)).json.error.code, 'admin_role_required');
    assert.equal((await post(port, '/api/demo/tamper', {}, obs)).status, 403);
    const ro = await post(port, '/api/incidents/inc-2026-0042/runs', {}, obs);
    assert.equal(ro.status, 403);
    assert.equal(ro.json.error.code, 'read_only_role');

    const a = await login('alice', ADMIN_PW);
    const adm = { headers: { Cookie: cookieHeader(cookieOf(a)) } };
    assert.equal(a.json.user.role, 'admin');
    assert.equal((await get(port, '/api/admin/audit', adm)).status, 200);
    assert.equal((await get(port, `/api/admin/actions/${pending.intent_id}`, adm)).status, 200);
    assert.equal((await post(port, '/api/incidents/inc-2026-0042/runs', {}, adm)).status, 200);
  });

  test('logout invalidates the server-side session; credential changes revoke sessions', async () => {
    const a = await login('alice', ADMIN_PW);
    const jar = { headers: { Cookie: cookieHeader(cookieOf(a)) } };
    assert.equal((await get(port, '/api/hosts', jar)).status, 200);
    const out = await post(port, '/api/auth/logout', {}, jar);
    assert.equal(out.status, 200);
    assert.equal(out.json.logged_out, true);
    assert.match(cookieOf(out), new RegExp(`^${SESSION_COOKIE}=;.*Max-Age=0`));
    const reuse = await get(port, '/api/hosts', jar);
    assert.equal(reuse.status, 401, 'replaying the old cookie after logout must fail');
    assert.equal((await get(port, '/api/auth/session', jar)).json.authenticated, false);
    assert.equal((await post(port, '/api/auth/logout', {}, { ...jar, headers: { ...jar.headers, Origin: 'http://evil.example' } })).status, 403);

    const b = await login('bob', OBS_PW);
    const bj = { headers: { Cookie: cookieHeader(cookieOf(b)) } };
    assert.equal((await get(port, '/api/hosts', bj)).status, 200);
    upsertUser(usersFile, { username: 'bob', role: 'observer', password: 'a brand new passphrase' });
    const revoked = await get(port, '/api/hosts', bj);
    assert.equal(revoked.status, 401);
    assert.equal(revoked.json.error.code, 'session_revoked');
    assert.equal((await login('bob', 'a brand new passphrase')).status, 200);
  });

  test('per-IP sliding-window rate limit returns 429 with Retry-After', async () => {
    let t = 1_000_000;
    const limited = createAuth({ mode: 'local', usersFile, now: () => t });
    const s = await startConsole(createDemoBackend(), { auth: limited });
    try {
      const attempt = (pw) => post(s.port, '/api/auth/login', { username: 'alice', password: pw });
      for (let i = 0; i < 10; i++) assert.equal((await attempt(`wrong-${i}`)).status, 401, `attempt ${i}`);
      const blocked = await attempt(ADMIN_PW);
      assert.equal(blocked.status, 429, 'even the right password is refused while limited');
      assert.equal(blocked.json.error.code, 'rate_limited');
      const retry = Number(blocked.headers['retry-after']);
      assert.ok(retry > 0 && retry <= 300, `Retry-After ${retry}`);
      assert.equal(blocked.headers['set-cookie'], undefined);
      t += 301_000; // the window slides past every failure
      assert.equal((await attempt(ADMIN_PW)).status, 200);
    } finally {
      await s.app.close();
    }
  });

  test('Secure cookie with --secure-cookies or https from a trusted proxy only', async () => {
    const secure = await startConsole(createDemoBackend(), { auth: createAuth({ mode: 'local', usersFile, secureCookies: true }) });
    const proxied = await startConsole(createDemoBackend(), { auth: createAuth({ mode: 'local', usersFile, trustForwarded: true }) });
    const untrusted = await startConsole(createDemoBackend(), { auth: createAuth({ mode: 'local', usersFile, trustForwarded: true, trustedProxyIps: ['10.9.9.9'] }) });
    try {
      const body = { username: 'alice', password: ADMIN_PW };
      assert.match(cookieOf(await post(secure.port, '/api/auth/login', body)), /; Secure/);
      assert.match(cookieOf(await post(proxied.port, '/api/auth/login', body, { headers: { 'X-Forwarded-Proto': 'https' } })), /; Secure/);
      assert.doesNotMatch(cookieOf(await post(proxied.port, '/api/auth/login', body)), /Secure/);
      assert.doesNotMatch(cookieOf(await post(untrusted.port, '/api/auth/login', body, { headers: { 'X-Forwarded-Proto': 'https' } })), /Secure/, 'X-Forwarded-Proto from an untrusted peer is ignored');
    } finally {
      await secure.app.close();
      await proxied.app.close();
      await untrusted.app.close();
    }
  });

  test('auth mode none reports open access and keeps the original behaviour', async () => {
    const open = await startConsole(createDemoBackend());
    try {
      assert.deepEqual((await get(open.port, '/api/auth/session')).json, { auth_mode: 'none', authenticated: true, user: null });
      assert.equal((await get(open.port, '/api/admin/audit')).status, 200);
      assert.equal((await post(open.port, '/api/auth/login', { username: 'a', password: 'b' })).json.error.code, 'login_not_supported');
    } finally {
      await open.app.close();
    }
  });
});

// ---------------------------------------------------------------------------
// 7. Access gate: trusted reverse-proxy identity headers
// ---------------------------------------------------------------------------

describe('access gate: --auth-mode proxy-header', () => {
  let app;
  let port;
  before(async () => {
    const auth = createAuth({ mode: 'proxy-header', proxyRoleHeader: 'x-forwarded-groups', proxyAdminGroup: 'defsec-admins' });
    ({ app, port } = await startConsole(createDemoBackend(), { auth }));
  });
  after(() => app.close());

  const as = (user, groups) => ({ headers: { 'X-Forwarded-User': user, ...(groups !== undefined ? { 'X-Forwarded-Groups': groups } : {}) } });

  test('trusted proxy + admin group -> admin; other groups -> observer (403 on admin)', async () => {
    const admin = as('alice@example.com', 'devs, defsec-admins');
    assert.deepEqual((await get(port, '/api/auth/session', admin)).json, { auth_mode: 'proxy-header', authenticated: true, user: { username: 'alice@example.com', role: 'admin' } });
    assert.equal((await get(port, '/api/admin/audit', admin)).status, 200);
    assert.equal((await post(port, '/api/incidents/inc-2026-0042/runs', {}, admin)).status, 200);

    const obs = as('bob@example.com', 'devs,defsec-admins-readonly');
    assert.equal((await get(port, '/api/auth/session', obs)).json.user.role, 'observer');
    assert.equal((await get(port, '/api/hosts', obs)).status, 200);
    const denied = await get(port, '/api/admin/audit', obs);
    assert.equal(denied.status, 403);
    assert.equal(denied.json.error.code, 'admin_role_required');
    assert.equal((await post(port, '/api/incidents/inc-2026-0042/runs', {}, obs)).json.error.code, 'read_only_role');
    assert.equal((await get(port, '/api/admin/audit', as('carol@example.com'))).status, 403, 'no group header -> observer');
  });

  test('trusted proxy without a usable identity -> 401', async () => {
    const none = await get(port, '/api/hosts');
    assert.equal(none.status, 401);
    assert.equal(none.json.error.code, 'proxy_identity_missing');
    assert.equal((await get(port, '/api/hosts', as('   '))).status, 401);
    assert.equal((await get(port, '/api/hosts', as('alice, bob'))).json.error.code, 'proxy_identity_invalid');
    assert.deepEqual((await get(port, '/api/auth/session')).json, { auth_mode: 'proxy-header', authenticated: false, user: null });
    assert.equal((await post(port, '/api/auth/login', { username: 'alice', password: 'x' }, as('alice'))).json.error.code, 'login_not_supported');
  });

  test('untrusted peer is refused with 403 even with spoofed identity headers', async () => {
    const auth = createAuth({ mode: 'proxy-header', trustedProxyIps: ['10.9.9.9', '192.0.2.0/24'], proxyRoleHeader: 'x-forwarded-groups', proxyAdminGroup: 'defsec-admins' });
    const s = await startConsole(createDemoBackend(), { auth });
    try {
      const spoof = as('root', 'defsec-admins');
      for (const r of [await get(s.port, '/api/admin/audit', spoof), await get(s.port, '/api/auth/session', spoof), await get(s.port, '/', spoof), await post(s.port, '/api/demo/reset', {}, spoof)]) {
        assert.equal(r.status, 403);
        assert.equal(r.json.error.code, 'untrusted_proxy');
        assert.ok(!r.text.includes('edge-vm-07'));
      }
    } finally {
      await s.app.close();
    }
  });

  test('default role, peer normalisation and flag validation', async () => {
    const adminDefault = await startConsole(createDemoBackend(), { auth: createAuth({ mode: 'proxy-header', proxyDefaultRole: 'admin', proxyUserHeader: 'remote-user' }) });
    try {
      assert.equal((await get(adminDefault.port, '/api/admin/audit', { headers: { 'Remote-User': 'ops' } })).status, 200);
      assert.equal((await get(adminDefault.port, '/api/admin/audit', as('ops'))).status, 401, 'only the configured header counts');
    } finally {
      await adminDefault.app.close();
    }
    assert.equal(normalizeIp('::ffff:127.0.0.1'), '127.0.0.1');
    assert.equal(normalizeIp('[::1]'), '::1');
    assert.equal(normalizeIp('fe80::1%eth0'), 'fe80::1');
    const match = createPeerMatcher(['127.0.0.1', '::1', '10.0.0.0/8', 'fd00::/8']);
    for (const ok of ['127.0.0.1', '::ffff:127.0.0.1', '::1', '10.20.0.5', 'fd12::4']) assert.ok(match(ok), ok);
    for (const no of ['127.0.0.2', '11.0.0.1', '::2', '', 'not-an-ip']) assert.ok(!match(no), no);
    assert.throws(() => createPeerMatcher(['300.1.1.1']), /invalid trusted proxy/);
    assert.throws(() => parseArgs(['--demo', '--auth-mode', 'proxy-header', '--proxy-role-header', 'x-forwarded-groups'], {}), /--proxy-admin-group/);
    assert.throws(() => parseArgs(['--demo', '--auth-mode', 'proxy-header', '--trusted-proxy-ips', 'nope'], {}), /invalid trusted proxy/);
    assert.throws(() => parseArgs(['--demo', '--auth-mode', 'proxy-header', '--proxy-default-role', 'root'], {}), /--proxy-default-role/);
    const o = parseArgs(['--demo', '--auth-mode', 'proxy-header', '--trusted-proxy-ips', '127.0.0.1,10.0.0.0/8', '--proxy-role-header', 'X-Forwarded-Groups', '--proxy-admin-group', 'defsec-admins'], {});
    assert.deepEqual(o.trustedProxyIps, ['127.0.0.1', '10.0.0.0/8']);
    assert.equal(o.proxyRoleHeader, 'x-forwarded-groups');
  });
});

// ---------------------------------------------------------------------------
// 8. Mitigation proposals, stream watches and automation status
// ---------------------------------------------------------------------------

describe('deriveThreeState: append-only streams are never drift', () => {
  const watch = (id, type, cls = 'baseline') => ({ id, class: cls, collector: { type, parameters: {} } });
  const obs = (id, watchId, payload, hash = `h${id}`) => ({ observation_id: id, host_id: 'h', watch_id: watchId, spec_version: 1, observed_at: new Date(Date.now() - (100 - id) * 1000).toISOString(), status: 'ok', state_hash: hash, payload });
  const batch = (n) => ({ kind: 'stream_batch', events: Array.from({ length: n }, (_, i) => ({ cursor: `c${i}` })), cursor_before: null, cursor_after: 'c', gap_detected: false });

  test('journal.unit_events and stream_batch watches derive as stream, unpromotable', () => {
    const rows = deriveThreeState(
      [watch('j', 'journal.unit_events'), watch('s', 'sockets.listening'), watch('x', 'files.metadata')],
      [{ watch_id: 's', revision_id: 1, state_hash: 'h1' }],
      [obs(1, 's', { kind: 'snapshot', data: {} }), obs(2, 's', { kind: 'snapshot', data: {} }), obs(3, 'j', batch(2)), obs(4, 'j', batch(3)), obs(5, 'x', batch(1))],
    );
    const j = rows.find((r) => r.watch_id === 'j');
    assert.equal(j.state, 'stream');
    assert.equal(j.promotable_observation_id, null);
    assert.equal(j.changed_since_last, false);
    assert.deepEqual([j.stream.latest_observation_id, j.stream.latest_event_count, j.stream.events_in_window, j.stream.batches_in_window], [4, 3, 5, 2]);
    // Any watch whose observations are stream batches is a stream, whatever its collector label.
    assert.equal(rows.find((r) => r.watch_id === 'x').state, 'stream');
    // Snapshot watches keep their three-state semantics.
    const s = rows.find((r) => r.watch_id === 's');
    assert.equal(s.state, 'drift');
    assert.equal(s.promotable_observation_id, 2);
    assert.equal(deriveThreeState([watch('j', 'journal.unit_events')], [], [])[0].state, 'no_data');
  });

  test('demo: baseline journal watch is a stream and never offered for promotion', async () => {
    const backend = createDemoBackend();
    const tri = (await backend.baselines('edge-vm-07')).three_state;
    for (const r of tri.filter((x) => x.collector_type === 'journal.unit_events')) {
      assert.equal(r.state, 'stream', r.watch_id);
      assert.equal(r.promotable_observation_id, null);
    }
    assert.ok(tri.some((r) => r.watch_id === 'base-sshd-journal' && r.class === 'baseline'));
    const v12 = (await backend.baselines('edge-vm-12')).three_state;
    assert.equal(v12.filter((r) => r.state === 'baseline_absent' && r.promotable_observation_id != null).length, 2, 'two never-accepted snapshot baselines');
  });
});

describe('POST /api/incidents/:id/actions (demo)', () => {
  let app;
  let port;
  const INC = 'inc-2026-0039';
  before(async () => {
    ({ app, port } = await startConsole(createDemoBackend()));
  });
  after(() => app.close());

  const body = (verb, extra = {}) => ({ verb, evidence_observation_ids: [], expected_effect: 'contain', blast_radius: 'one host', rollback_plan: 'TTL', ...extra });

  test('needs a run, validates the closed verb catalog and returns the gate verdict', async () => {
    const ctx = (await get(port, `/api/incidents/${INC}`)).json;
    const evidence = ctx.recent_observations.map((o) => o.observation_id);
    assert.ok(evidence.length);
    const noRun = await post(port, `/api/incidents/${INC}/actions`, body({ verb: 'nft_block_ip', ip: '198.51.100.7', direction: 'inbound', ttl_seconds: 600 }));
    assert.equal(noRun.status, 409);
    assert.equal(noRun.json.error.code, 'run_required');
    assert.equal((await post(port, `/api/incidents/${INC}/runs`, {})).status, 200);

    for (const [verb, re] of [
      [{ verb: 'shell_exec', cmd: 'id' }, /verb\.verb must be one of/],
      [{ verb: 'nft_block_ip', ip: '198.51.100.7', direction: 'sideways', ttl_seconds: 60 }, /direction/],
      [{ verb: 'nft_block_ip', ip: '198.51.100.7' }, /ttl_seconds/],
      [{ verb: 'systemd_stop_unit' }, /verb\.unit/],
    ]) {
      const r = await post(port, `/api/incidents/${INC}/actions`, body(verb, { evidence_observation_ids: evidence.slice(0, 1) }));
      assert.equal(r.status, 400, JSON.stringify(verb));
      assert.match(r.json.error.message, re);
    }
    assert.equal((await post(port, `/api/incidents/${INC}/actions`, { verb: { verb: 'host_isolate', preserve_mgmt_cidrs: ['10.0.0.0/8'], ttl_seconds: 60 } })).status, 400, 'justification is required');

    const cite = { evidence_observation_ids: evidence.slice(0, 1) };
    const prot = await post(port, `/api/incidents/${INC}/actions`, body({ verb: 'systemd_stop_unit', unit: 'ssh.service', ttl_seconds: 600 }, cite));
    assert.equal(prot.status, 200, prot.text);
    assert.equal(prot.json.decision.rule_id, 'action.protected_unit');
    assert.equal(prot.json.status, 'rejected');
    assert.equal(prot.json.intent_id, null);
    const foreign = (await get(port, '/api/hosts/edge-vm-07/observations?limit=1')).json.observations[0].observation_id;
    const outside = await post(port, `/api/incidents/${INC}/actions`, body({ verb: 'nft_block_ip', ip: '198.51.100.7', direction: 'inbound', ttl_seconds: 600 }, { evidence_observation_ids: [foreign] }));
    assert.equal(outside.json.decision.rule_id, 'action.evidence_out_of_scope');

    const auto = await post(port, `/api/incidents/${INC}/actions`, body({ verb: 'nft_block_ip', ip: '198.51.100.7', direction: 'inbound', ttl_seconds: 600 }, { ...cite, idempotency_key: 'k-1' }));
    assert.equal(auto.status, 200, auto.text);
    assert.equal(auto.json.decision.rule_id, 'action.autonomous_authorized');
    assert.equal(auto.json.auth_mode, 'policy_bounded_autonomous');
    assert.equal(auto.json.status, 'authorized');
    assert.match(auto.json.intent_id, /^[0-9a-f-]{36}$/);
    const replay = await post(port, `/api/incidents/${INC}/actions`, body({ verb: 'nft_block_ip', ip: '198.51.100.7', direction: 'inbound', ttl_seconds: 600 }, { ...cite, idempotency_key: 'k-1' }));
    assert.equal(replay.json.intent_id, auto.json.intent_id, 'same idempotency key replays the verdict');
    const reused = await post(port, `/api/incidents/${INC}/actions`, body({ verb: 'nft_block_ip', ip: '198.51.100.8', direction: 'inbound', ttl_seconds: 600 }, { ...cite, idempotency_key: 'k-1' }));
    assert.equal(reused.status, 400);
    const cooldown = await post(port, `/api/incidents/${INC}/actions`, body({ verb: 'host_isolate', preserve_mgmt_cidrs: '10.20.0.0/24', ttl_seconds: 3600 }, cite));
    assert.equal(cooldown.json.decision.rule_id, 'action.causal_cooldown');

    const list = (await get(port, `/api/actions?incident_id=${INC}`)).json;
    const intent = list.actions.find((a) => a.intent_id === auto.json.intent_id);
    assert.deepEqual(Object.keys(intent).sort(), SUMMARY_KEYS);
    assert.ok(list.denied.some((d) => d.decision.rule_id === 'action.protected_unit'));
    const detail = (await get(port, `/api/admin/actions/${auto.json.intent_id}`)).json;
    assert.deepEqual(Object.keys(detail.payload).sort(), PAYLOAD_KEYS);
    const audit = (await get(port, '/api/admin/audit?limit=500')).json;
    assert.equal(audit.independent.valid, true);
    assert.ok(audit.entries.some((e) => e.event_type === 'action_proposed' && e.payload.intent_id === auto.json.intent_id));
  });

  test('host watch counts, incident changes and automation status', async () => {
    const hosts = (await get(port, '/api/hosts')).json.hosts;
    const h07 = hosts.find((h) => h.host_id === 'edge-vm-07');
    assert.ok(h07.watch_count >= 7);
    assert.equal(h07.stream_watch_count, 2);
    const changes = (await get(port, '/api/incidents/inc-2026-0042/changes')).json.changes;
    const sock = changes.find((c) => c.watch_id === 'base-sockets-listening');
    assert.equal(sock.basis, 'accepted_baseline');
    assert.deepEqual(sock.diff.added.map((s) => s.local_port), [4444]);
    assert.ok(!changes.some((c) => c.collector_type === 'journal.unit_events'), 'streams are not diffed');
    const auto = (await get(port, '/api/automation')).json;
    assert.equal(auto.available, true);
    assert.equal(auto.reasoner_runs, 3);
    assert.equal(auto.last_run.model_id, 'claude-sonnet-5-5');
  });
});

describe('ProposeAction frames over a mock control-d', () => {
  test('runs mint an isolated incident-scoped token and every run mutation uses it', async () => {
    const dir = shortTmp('dsm-');
    const inv = path.join(dir, 'iv.sock');
    const adm = path.join(dir, 'ad.sock');
    const seen = [];
    const incident = { incident_id: '5bc7e050-0000-4000-8000-000000000001', host_id: 'edge-x', status: 'open', priority: 'medium', summary: 's', created_at: new Date().toISOString(), updated_at: new Date().toISOString() };
    const invSrv = await mockUdsServer(inv, (frame) => {
      seen.push({ sock: 'inv', token: frame.capability_token, request: frame.request });
      switch (frame.request.op) {
        case 'get_incident_context':
          return { result: 'incident_context', incident, active_watches: [], recent_observations: [], findings: [] };
        case 'list_collector_capabilities':
          return { result: 'capabilities', capabilities: [{ collector_type: 'sockets.listening' }, { collector_type: 'journal.unit_events' }] };
        case 'start_investigation_run':
          return { result: 'run_started', run_id: 'run-1', incident_id: incident.incident_id, expires_at: new Date(Date.now() + 3_600_000).toISOString() };
        case 'propose_action':
          return { result: 'action_proposal_evaluated', decision: { allowed: true, rule_id: 'action.pending_dual_approval', reason: 'r', policy_version: 1 }, proposal_id: 7, intent_id: 'i-1', auth_mode: 'dual_signed_operator', status: 'pending_approval', authorized_intent: null };
        default:
          return { result: 'error', code: 'invalid_request', message: 'unexpected' };
      }
    });
    const admSrv = await mockUdsServer(adm, (frame) => {
      seen.push({ sock: 'admin', request: frame });
      return frame.admin_op === 'mint_capability_token' ? { admin_result: 'token_minted', token: 'run-scoped-token', expires_at: new Date(Date.now() + 3_600_000).toISOString() } : { admin_result: 'error', code: 'invalid_request', message: 'unexpected' };
    });
    const { app, port } = await startConsole(createLiveBackend({ investigateSock: inv, token: 'browse-token', adminSock: adm, enableAdmin: true }));
    try {
      const run = await post(port, `/api/incidents/${incident.incident_id}/runs`, {});
      assert.equal(run.status, 200, run.text);
      const mint = seen.find((x) => x.sock === 'admin').request;
      assert.deepEqual(mint, {
        admin_op: 'mint_capability_token', principal_id: 'console-run-5bc7e050', role: 'investigator', allowed_hosts: ['edge-x'],
        allowed_collectors: ['sockets.listening', 'journal.unit_events'], incident_id: incident.incident_id, ttl_seconds: 3600,
      });
      const start = seen.find((x) => x.request.op === 'start_investigation_run');
      assert.equal(start.token, 'run-scoped-token', 'the run starts on its own token');
      const r = await post(port, `/api/incidents/${incident.incident_id}/actions`, {
        verb: { verb: 'systemd_stop_unit', unit: 'custom-helper.service', ttl_seconds: 900, extra: 'dropped' },
        evidence_observation_ids: [3, '2', 3],
        expected_effect: 'e',
        blast_radius: 'b',
        rollback_plan: 'r',
        idempotency_key: 'idem-1',
      });
      assert.equal(r.status, 200, r.text);
      assert.deepEqual(r.json, { decision: { allowed: true, rule_id: 'action.pending_dual_approval', reason: 'r', policy_version: 1 }, proposal_id: 7, intent_id: 'i-1', auth_mode: 'dual_signed_operator', status: 'pending_approval', authorized: false, verb: { verb: 'systemd_stop_unit', unit: 'custom-helper.service', ttl_seconds: 900 }, idempotency_key: 'idem-1' });
      const frame = seen.find((x) => x.request.op === 'propose_action');
      assert.equal(frame.token, 'run-scoped-token');
      assert.deepEqual(frame.request, {
        op: 'propose_action', run_id: 'run-1', incident_id: incident.incident_id, idempotency_key: 'idem-1',
        verb: { verb: 'systemd_stop_unit', unit: 'custom-helper.service', ttl_seconds: 900 },
        evidence_observation_ids: [2, 3], expected_effect: 'e', blast_radius: 'b', rollback_plan: 'r',
      });
      assert.ok(seen.filter((x) => x.sock === 'inv' && x.token === 'browse-token').every((x) => !['start_investigation_run', 'propose_action'].includes(x.request.op)), 'the browse token never starts runs or proposes');
      assert.ok(!r.text.includes('run-scoped-token') && !run.text.includes('run-scoped-token'), 'run token never leaves the BFF');
    } finally {
      await app.close();
      invSrv.close();
      admSrv.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// 9. Phase 9 reasoner activity: runs, run events, trigger queue
// ---------------------------------------------------------------------------

const RUN_KEYS = ['backend_id', 'ended_at', 'event_count', 'expires_at', 'findings_count', 'host_id', 'incident_id', 'last_event', 'model_id', 'origin', 'outcome', 'principal_id', 'proposals_count', 'run_id', 'started_at', 'status'];
const TRIGGER_KEYS = ['created_at', 'event_id', 'host_id', 'incident_id', 'lease_expires_at', 'lease_owner', 'reason', 'retry_count', 'status', 'updated_at', 'watch_id'];

describe('reasoner activity (demo)', () => {
  let app;
  let port;
  let clock;
  before(async () => {
    clock = Date.now();
    ({ app, port } = await startConsole(createDemoBackend({ now: () => clock })));
  });
  after(() => app.close());

  test('runs list automated runs with the RunSummary schema and an origin', async () => {
    const r = await get(port, '/api/runs');
    assert.equal(r.status, 200, r.text);
    assert.equal(r.json.available, true);
    assert.ok(r.json.runs.length >= 3);
    for (const run of r.json.runs) assert.deepEqual(Object.keys(run).sort(), RUN_KEYS);
    const active = r.json.runs.find((x) => x.status === 'active');
    assert.equal(active.run_id, 'run-a41c07d9');
    assert.equal(active.origin, 'automated');
    assert.equal(active.outcome, null);
    assert.equal(active.last_event.kind, 'tool_result');
    const budget = r.json.runs.find((x) => x.run_id === 'run-7f3a91c2');
    assert.equal(budget.status, 'budget_exhausted');
    assert.equal(budget.outcome.status, 'budget_exhausted');
    assert.match(budget.outcome.budget_stop_reason, /tool_calls/);
    assert.deepEqual(
      Object.keys(budget.outcome).sort(),
      ['budget_stop_reason', 'findings', 'input_tokens', 'output_tokens', 'proposals', 'proposals_accepted', 'status', 'summary', 'tool_calls', 'turns'],
    );
    assert.equal(budget.findings_count, 3);
    const scoped = await get(port, '/api/runs?incident_id=inc-2026-0039');
    assert.deepEqual(scoped.json.runs.map((x) => x.run_id), ['run-19bd04e7']);
    assert.equal((await get(port, '/api/runs?host_id=edge-vm-07&limit=1')).json.runs.length, 1);
    assert.equal((await get(port, '/api/runs?incident_id=bad%20id')).status, 400);
    assert.equal((await get(port, '/api/runs?limit=0')).status, 400);
  });

  test('events page with after_seq and the in-progress run advances over time', async () => {
    const all = await get(port, '/api/runs/run-a41c07d9/events');
    assert.equal(all.status, 200, all.text);
    const seqs = all.json.events.map((e) => e.event_seq);
    assert.deepEqual(seqs, [...seqs].sort((a, b) => a - b));
    assert.equal(all.json.next_after_seq, seqs.at(-1));
    for (const e of all.json.events) {
      assert.deepEqual(Object.keys(e).sort(), ['created_at', 'detail', 'event_seq', 'kind']);
      assert.ok(['turn_started', 'tool_call', 'tool_result', 'model_text', 'budget_warning', 'note'].includes(e.kind));
      assert.equal(typeof e.detail, 'object');
    }
    const none = await get(port, `/api/runs/run-a41c07d9/events?after_seq=${seqs.at(-1)}`);
    assert.deepEqual(none.json.events, []);
    assert.equal(none.json.next_after_seq, seqs.at(-1));
    const page = await get(port, '/api/runs/run-7f3a91c2/events?after_seq=3&limit=2');
    assert.deepEqual(page.json.events.map((e) => e.event_seq), [4, 5]);
    assert.equal((await get(port, '/api/runs/run-nope/events')).status, 404);
    assert.equal((await get(port, '/api/runs/run-a41c07d9/events?after_seq=x')).status, 400);

    const findingsBefore = (await get(port, '/api/incidents/inc-2026-0042')).json.findings.length;
    clock += 90_000;
    const more = await get(port, `/api/runs/run-a41c07d9/events?after_seq=${seqs.at(-1)}`);
    assert.ok(more.json.events.length >= 3, 'new events appear as demo time passes');
    assert.ok(more.json.events.every((e) => e.event_seq > seqs.at(-1)));
    assert.ok(more.json.events.some((e) => e.kind === 'model_text'));
    const mid = (await get(port, '/api/runs?incident_id=inc-2026-0042')).json.runs.find((x) => x.run_id === 'run-a41c07d9');
    assert.equal(mid.status, 'active');
    assert.equal(mid.findings_count, 1, 'the model recorded a finding');
    assert.equal((await get(port, '/api/incidents/inc-2026-0042')).json.findings.length, findingsBefore + 1);

    clock += 4 * 60_000;
    const done = (await get(port, '/api/runs?incident_id=inc-2026-0042')).json.runs.find((x) => x.run_id === 'run-a41c07d9');
    assert.equal(done.status, 'completed');
    assert.equal(done.outcome.status, 'completed');
    assert.ok(done.ended_at);
    assert.ok(done.outcome.turns >= 3 && done.outcome.tool_calls >= 4);
    assert.equal(done.outcome.proposals, 1);
    assert.equal(done.outcome.proposals_accepted, 0);
  });

  test('trigger queue: statuses, leases, dead letters and filters', async () => {
    const t = await get(port, '/api/triggers');
    assert.equal(t.status, 200, t.text);
    for (const x of t.json.triggers) assert.deepEqual(Object.keys(x).sort(), TRIGGER_KEYS);
    const byId = Object.fromEntries(t.json.triggers.map((x) => [x.event_id, x]));
    assert.equal(byId[4121].status, 'dead_letter');
    assert.equal(byId[4121].retry_count, 3);
    assert.match(byId[4121].reason, /retry budget exhausted/);
    assert.equal(byId[4129].status, 'pending');
    assert.equal(byId[4127].status, 'done', 'the lease is released when the run completes');
    const open = await get(port, '/api/triggers?status=pending,leased');
    assert.deepEqual(open.json.triggers.map((x) => x.event_id), [4129]);
    assert.deepEqual((await get(port, '/api/triggers?incident_id=inc-2026-0039&status=done')).json.triggers.map((x) => x.event_id), [4102]);
    assert.equal((await get(port, '/api/triggers?host_id=edge-vm-03')).json.triggers.every((x) => x.host_id === 'edge-vm-03'), true);
    const bad = await get(port, '/api/triggers?status=pending,bogus');
    assert.equal(bad.status, 400);
    assert.equal(bad.json.error.code, 'invalid_request');
  });

  test('operator sessions are listed separately and log what the operator submitted', async () => {
    const noRun = await post(port, '/api/incidents/inc-2026-0039/findings', { kind: 'hypothesis', summary: 's' });
    assert.equal(noRun.status, 409);
    assert.match(noRun.json.error.message, /operator session/);
    const s = await post(port, '/api/incidents/inc-2026-0039/runs', {});
    assert.equal(s.status, 200, s.text);
    await post(port, '/api/incidents/inc-2026-0039/findings', { run_id: s.json.run_id, kind: 'hypothesis', summary: 'Probably the CHG-4471 push' });
    const runs = (await get(port, '/api/runs?incident_id=inc-2026-0039')).json.runs;
    const op = runs.find((x) => x.run_id === s.json.run_id);
    assert.equal(op.origin, 'operator');
    assert.equal(op.backend_id, 'operator-console');
    assert.equal(op.status, 'active');
    assert.equal(op.findings_count, 1);
    assert.equal(runs.find((x) => x.run_id === 'run-19bd04e7').origin, 'automated');
    const ev = (await get(port, `/api/runs/${s.json.run_id}/events`)).json.events;
    assert.deepEqual(ev.map((e) => e.kind), ['note', 'tool_call', 'tool_result']);
    await post(port, '/api/admin/incidents/inc-2026-0039/close', { actor: 'j.rivera', resolution: 'approved config push' });
    const ended = (await get(port, '/api/runs?incident_id=inc-2026-0039')).json.runs.find((x) => x.run_id === s.json.run_id);
    assert.equal(ended.status, 'cancelled');
  });

  test('a pending trigger with no active run is visible as a stall', async () => {
    // Long after every demo run ended, trigger 4129 is still pending.
    clock += 10 * 60_000;
    const runs = (await get(port, '/api/runs')).json.runs.filter((x) => x.origin === 'automated');
    assert.ok(runs.every((x) => x.status !== 'active'));
    const pending = (await get(port, '/api/triggers?status=pending')).json.triggers;
    assert.equal(pending.length, 1);
    assert.ok(clock - Date.parse(pending[0].created_at) > 120_000);
  });
});

describe('reasoner activity over a mock control-d', () => {
  test('exact frames on the browse token, secrets stripped, nothing starts a run', async () => {
    const dir = shortTmp('dsr-');
    const inv = path.join(dir, 'iv.sock');
    const seen = [];
    const now = new Date().toISOString();
    const run = {
      run_id: 'run-1', incident_id: 'inc-1', host_id: 'edge-x', principal_id: 'reasoner-d', backend_id: 'anthropic-direct', model_id: 'claude-sonnet-5-5',
      status: 'active', started_at: now, expires_at: now, ended_at: null, outcome: null,
      last_event: { event_seq: 2, kind: 'tool_call', detail: { tool: 'query_observations', args_preview: '{}', capability_token: 'cap-secret-LEAK' }, created_at: now },
      event_count: 2, findings_count: 0, proposals_count: 0, run_token: 'run-secret-LEAK',
    };
    const op = { ...run, run_id: 'run-2', principal_id: 'console-run-5bc7e050', backend_id: 'operator-console', model_id: 'human-operator', status: 'completed', last_event: null };
    const invSrv = await mockUdsServer(inv, (frame) => {
      seen.push({ token: frame.capability_token, request: frame.request });
      switch (frame.request.op) {
        case 'list_investigation_runs':
          return { result: 'runs', runs: [run, op] };
        case 'get_run_events':
          return { result: 'run_events', run_id: frame.request.run_id, events: [
            { event_seq: 4, kind: 'tool_result', detail: { tool: 'query_observations', ok: true, code: null, nested: { lease_token: 'lease-secret-LEAK', tokens: 12 } }, created_at: now },
            { event_seq: 3, kind: 'turn_started', detail: { turn: 2, tokens: 5123 }, created_at: now },
          ] };
        case 'list_trigger_queue':
          return { result: 'trigger_queue', triggers: [{ event_id: 7, incident_id: 'inc-1', host_id: 'edge-x', watch_id: 'w', status: 'leased', created_at: now, updated_at: now, lease_owner: 'reasoner-d@h', lease_expires_at: now, retry_count: 0, reason: null, lease_token: 'lease-secret-LEAK' }] };
        default:
          return { result: 'error', code: 'invalid_request', message: 'unexpected' };
      }
    });
    const { app, port } = await startConsole(createLiveBackend({ investigateSock: inv, token: 'browse-token-LEAK' }));
    try {
      const runs = await get(port, '/api/runs?incident_id=inc-1&limit=5');
      assert.equal(runs.status, 200, runs.text);
      assert.deepEqual(seen.at(-1), { token: 'browse-token-LEAK', request: { op: 'list_investigation_runs', limit: 5, incident_id: 'inc-1' } });
      assert.equal(runs.json.available, true);
      assert.deepEqual(runs.json.runs.map((r) => r.origin), ['automated', 'operator']);
      for (const r of runs.json.runs) assert.deepEqual(Object.keys(r).sort(), RUN_KEYS);
      assert.deepEqual(runs.json.runs[0].last_event.detail, { tool: 'query_observations', args_preview: '{}' });

      const ev = await get(port, '/api/runs/run-1/events?after_seq=2&limit=10');
      assert.equal(ev.status, 200, ev.text);
      assert.deepEqual(seen.at(-1).request, { op: 'get_run_events', run_id: 'run-1', limit: 10, after_seq: 2 });
      assert.deepEqual(ev.json.events.map((e) => e.event_seq), [3, 4], 'sorted by event_seq');
      assert.equal(ev.json.next_after_seq, 4);
      assert.deepEqual(ev.json.events[1].detail.nested, { tokens: 12 }, 'counters stay, tokens go');
      await get(port, '/api/runs/run-1/events');
      assert.deepEqual(seen.at(-1).request, { op: 'get_run_events', run_id: 'run-1', limit: 200 });

      const tq = await get(port, '/api/triggers?host_id=edge-x&status=pending,leased');
      assert.equal(tq.status, 200, tq.text);
      assert.deepEqual(seen.at(-1).request, { op: 'list_trigger_queue', limit: 100, host_id: 'edge-x', statuses: ['pending', 'leased'] });
      assert.deepEqual(Object.keys(tq.json.triggers[0]).sort(), TRIGGER_KEYS);
      assert.equal(tq.json.triggers[0].lease_owner, 'reasoner-d@h');

      for (const r of [runs, ev, tq]) assert.ok(!/LEAK/.test(r.text), `no token in ${r.text.slice(0, 80)}`);
      assert.ok(seen.every((x) => x.token === 'browse-token-LEAK'));
      assert.ok(!seen.some((x) => x.request.op === 'start_investigation_run'), 'reading reasoner activity never starts a run');
    } finally {
      await app.close();
      invSrv.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('an older control-d degrades to "not available" instead of failing the page', async () => {
    const dir = shortTmp('dsr-');
    const old = path.join(dir, 'old.sock');
    const forb = path.join(dir, 'fb.sock');
    // Pre-Phase-9 control-d cannot deserialize the new ops and closes the connection.
    const oldSrv = await mockUdsServer(old, (frame) => (frame.request.op === 'list_hosts' ? { result: 'hosts', hosts: [] } : undefined));
    const fbSrv = await mockUdsServer(forb, (frame) =>
      frame.request.op === 'get_run_events'
        ? { result: 'error', code: 'invalid_request', message: 'unknown variant `get_run_events`' }
        : { result: 'error', code: 'forbidden', message: 'capability does not allow this operation' },
    );
    const a = await startConsole(createLiveBackend({ investigateSock: old, token: 't' }));
    const b = await startConsole(createLiveBackend({ investigateSock: forb, token: 't' }));
    try {
      for (const p of ['/api/runs', '/api/runs/run-1/events', '/api/triggers']) {
        const r = await get(a.port, p);
        assert.equal(r.status, 200, `${p}: ${r.text}`);
        assert.equal(r.json.available, false);
        assert.equal(r.json.reason, 'unsupported');
        assert.match(r.json.message, /control-d ≥ Phase 9/);
      }
      assert.equal((await get(a.port, '/api/status')).status, 200, 'the rest of the console keeps working');
      const f = await get(b.port, '/api/runs');
      assert.equal(f.json.available, false);
      assert.equal(f.json.reason, 'forbidden');
      const u = await get(b.port, '/api/runs/run-1/events');
      assert.equal(u.json.reason, 'unsupported');
      const gone = await startConsole(createLiveBackend({ investigateSock: path.join(dir, 'missing.sock'), token: 't' }));
      try {
        assert.equal((await get(gone.port, '/api/runs')).status, 503, 'an unreachable socket is still an error');
      } finally {
        await gone.app.close();
      }
    } finally {
      await a.app.close();
      await b.app.close();
      oldSrv.close();
      fbSrv.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('operator console copy and identity binding', () => {
  test('the manual session is called an operator session everywhere', () => {
    const files = ['public/app.js', 'public/index.html', 'README.md', 'lib/live-backend.mjs', 'lib/demo-data.mjs'].map((f) => fs.readFileSync(path.join(CONSOLE_DIR, f), 'utf8'));
    for (const text of files) assert.ok(!/start (an )?investigation run/i.test(text), 'old wording is gone');
    const app = files[0];
    assert.ok(app.includes("'Start operator session'"));
    assert.match(app, /does not start the model/);
    assert.ok(files[1].includes('#/reasoner'), 'Reasoner activity is in the navigation');
  });

  test('reconciliation drawer binds receipt detail and drafts to the exact receipt_id', () => {
    const app = fs.readFileSync(path.join(CONSOLE_DIR, 'public/app.js'), 'utf8');
    assert.ok(!/nothing has been executed/.test(app), 'absence of a receipt does not prove nothing executed');
    assert.ok(app.includes("'No receipt recorded yet.'"));
    // Pairing is a pure function: run it in isolation against racing snapshots.
    const src = app.slice(app.indexOf('function pairLatestReceipt('), app.indexOf('function verificationSection('));
    const pair = vm.runInNewContext(`(${src.trim()})`);
    const v = (ids, statuses) => ({ latest_receipt_id: ids.at(-1), receipt_checks: ids.map((receipt_id, i) => ({ receipt_id, receipt_status: statuses[i] })) });
    const executed = { status: 'executed', detail: 'applied' };
    const rolled = { status: 'rolled_back', detail: 'TTL elapsed' };
    assert.equal(pair(v([4], ['executed']), [executed]), executed);
    assert.equal(pair(v([4, 9], ['executed', 'rolled_back']), [executed]), null, 'a new receipt is never labelled with the previous receipt\'s detail');
    assert.equal(pair(v([4], ['executed']), [executed, rolled]), null, 'receipt list ahead of verification');
    assert.equal(pair(v([4, 9], ['executed', 'rolled_back']), [executed, rolled]), rolled);
    assert.equal(pair(v([4, 9], ['executed', 'rolled_back']), [executed, { ...executed }]), null, 'status must agree');
    assert.equal(pair({ latest_receipt_id: null, receipt_checks: [] }, []), null);
    // Each poll re-reads the executor receipts with the verification.
    const section = app.slice(app.indexOf('function verificationSection('), app.indexOf('function renderVerification('));
    assert.match(section, /api\(`\/api\/admin\/actions\/\$\{enc\(a\.intent_id\)\}\/verification`\), api\(`\/api\/admin\/actions\/\$\{enc\(a\.intent_id\)\}`\)/);
    // The form is rebuilt only when the attested receipt changes, and a carried draft needs re-confirmation.
    const render = app.slice(app.indexOf('function renderVerification('), app.indexOf('function reconcileForm('));
    assert.match(render, /if \(key !== ctx\.formKey\)/);
    const form = app.slice(app.indexOf('function reconcileForm('), app.indexOf('// ---------------------------------------------------------------------------\n// Boot'));
    assert.match(form, /f\.reconfirmed = !carried/);
    assert.match(form, /ctx\.latestKey !== key/, 'the receipt is re-checked after the confirmation dialog');
    // Review schedules keep an existing interval to the second.
    assert.match(app, /interval_seconds: intervalEdited \? f\.interval_hours \* 3600 : exact/);
  });

  test('with an access gate, approver and actor are the signed-in account', async () => {
    const backend = createDemoBackend();
    const auth = createAuth({ mode: 'proxy-header', proxyRoleHeader: 'x-forwarded-groups', proxyAdminGroup: 'defsec-admins' });
    const { app, port } = await startConsole(backend, { auth });
    const alice = { headers: { 'X-Forwarded-User': 'alice@example.com', 'X-Forwarded-Groups': 'defsec-admins' } };
    try {
      const rows = (await get(port, '/api/hosts/edge-vm-07/baselines', alice)).json.three_state;
      const r = rows.find((x) => x.promotable_observation_id);
      const p = await post(port, '/api/admin/baselines/promote', { host_id: 'edge-vm-07', watch_id: r.watch_id, observation_id: r.promotable_observation_id, approver: 'mallory', rationale: 'Accept observed change' }, alice);
      assert.equal(p.status, 200, p.text);
      const c = await post(port, '/api/admin/incidents/inc-2026-0039/close', { actor: 'mallory', resolution: 'expected change' }, alice);
      assert.equal(c.status, 200, c.text);
      const audit = backend._state().audit;
      assert.equal(audit.findLast((e) => e.event_type === 'baseline_promoted').actor, 'alice@example.com');
      assert.equal(audit.findLast((e) => e.event_type === 'incident_closed').actor, 'alice@example.com');
      assert.equal((await post(port, '/api/admin/baselines/promote', { host_id: 'edge-vm-07', watch_id: r.watch_id, observation_id: r.promotable_observation_id, approver: 'x' }, alice)).status, 400, 'rationale is still validated server-side');
    } finally {
      await app.close();
    }
  });
});

// ---------------------------------------------------------------------------
// 10. Phase 10 expectation rules
// ---------------------------------------------------------------------------

const RULE_KEYS = ['backtest', 'created_at', 'decided_at', 'decided_by', 'decision_note', 'hit_count', 'incident_id', 'last_matched_at', 'origin', 'proposed_by', 'rule_id', 'run_id', 'spec', 'status'];
const BACKTEST_KEYS = ['currently_matching', 'items_matched', 'observations_scanned', 'sample_keys', 'triggered_after', 'triggered_before'];
const inDays = (d) => new Date(Date.now() + d * 86_400_000).toISOString();

/** The prefill "Allow for this service" builds for a typical service socket. */
const serviceRule = (host, watch, over = {}) => ({
  scope: { host_id: host, collector: 'sockets.listening', watch_id: watch },
  matches: [
    { op: 'eq', field: 'systemd_unit', value: 'custom-helper.service' },
    { op: 'eq', field: 'comm', value: 'helperd' },
    { op: 'eq', field: 'protocol', value: 'tcp' },
    { op: 'eq', field: 'local_port', value: 4444 },
    { op: 'eq', field: 'bind_scope', value: 'any' },
  ],
  effect: 'allow_optional',
  rationale: 'Expected service socket: custom-helper.service listens on tcp 0.0.0.0:4444',
  expires_at: inDays(30),
  ...over,
});

/** Shape errors that would make control-d close the socket (deny_unknown_fields, untagged values). */
const MALFORMED_RULES = [
  ['missing rule', undefined],
  ['unknown top-level key', (r) => ({ ...r, priority: 'high' })],
  ['unknown scope key', (r) => ({ ...r, scope: { ...r.scope, collector_type: 'sockets.listening' } })],
  ['unknown collector', (r) => ({ ...r, scope: { ...r.scope, collector: 'processes.list' } })],
  ['bad host id', (r) => ({ ...r, scope: { ...r.scope, host_id: 'edge 07' } })],
  ['matches not an array', (r) => ({ ...r, matches: { op: 'eq' } })],
  ['unknown op', (r) => ({ ...r, matches: [{ op: 'regex', field: 'comm', value: '.*' }] })],
  ['extra clause key', (r) => ({ ...r, matches: [{ op: 'eq', field: 'comm', value: 'x', negate: true }] })],
  ['float value', (r) => ({ ...r, matches: [{ op: 'eq', field: 'local_port', value: 44.5 }] })],
  ['object value', (r) => ({ ...r, matches: [{ op: 'eq', field: 'comm', value: { a: 1 } }] })],
  ['range with text', (r) => ({ ...r, matches: [{ op: 'range', field: 'local_port', min: '1', max: 2 }] })],
  ['prefix with int', (r) => ({ ...r, matches: [{ op: 'prefix', field: 'comm', value: 5 }] })],
  ['field with spaces', (r) => ({ ...r, matches: [{ op: 'eq', field: 'local port', value: 1 }] })],
  ['unknown effect', (r) => ({ ...r, effect: 'suppress_everything' })],
  ['rationale not text', (r) => ({ ...r, rationale: 42 })],
  ['bad expiry', (r) => ({ ...r, expires_at: 'next tuesday' })],
];

describe('expectation rules (demo)', () => {
  let app;
  let port;
  let backend;
  before(async () => {
    backend = createDemoBackend();
    ({ app, port } = await startConsole(backend));
  });
  after(() => app.close());

  test('list: status and host filters, exact ExpectationRuleRecord keys, closed status set', async () => {
    const all = await get(port, '/api/rules');
    assert.equal(all.status, 200, all.text);
    assert.equal(all.json.available, true);
    assert.equal(all.json.source, 'admin');
    for (const r of all.json.rules) {
      assert.deepEqual(Object.keys(r).sort(), RULE_KEYS);
      assert.deepEqual(Object.keys(r.spec).sort(), ['effect', 'expires_at', 'matches', 'rationale', 'scope']);
      if (r.backtest) assert.deepEqual(Object.keys(r.backtest).sort(), BACKTEST_KEYS);
    }
    const statuses = new Set(all.json.rules.map((r) => r.status));
    for (const s of ['active', 'proposed', 'rejected', 'revoked', 'expired']) assert.ok(statuses.has(s), `fixture covers ${s}`);
    const pending = (await get(port, '/api/rules?status=proposed')).json.rules;
    assert.ok(pending.length && pending.every((r) => r.status === 'proposed'));
    const p = pending[0];
    assert.equal(p.origin, 'investigator');
    assert.ok(p.run_id && p.incident_id && p.backtest, 'investigator proposals carry run, incident and stored backtest');
    const hist = (await get(port, '/api/rules?status=rejected,revoked,expired&host_id=edge-vm-07')).json.rules;
    assert.ok(hist.every((r) => ['rejected', 'revoked', 'expired'].includes(r.status) && r.spec.scope.host_id === 'edge-vm-07'));
    for (const bad of ['/api/rules?status=pending', '/api/rules?status=active,bogus', '/api/rules?limit=0', '/api/rules?limit=101', '/api/rules?host_id=bad%20host']) {
      const r = await get(port, bad);
      assert.equal(r.status, 400, bad);
      assert.equal(r.json.error.code, 'invalid_request');
    }
  });

  test('backtest: allowed returns the RuleBacktest; a gate denial is a PolicyDecision, never a 500', async () => {
    const ok = await post(port, '/api/admin/rules/backtest', { rule: serviceRule('edge-vm-07', 'base-sockets-listening') });
    assert.equal(ok.status, 200, ok.text);
    assert.equal(ok.json.allowed, true);
    assert.equal(ok.json.decision, null);
    assert.deepEqual(Object.keys(ok.json.backtest).sort(), BACKTEST_KEYS);
    assert.ok(ok.json.backtest.observations_scanned >= 2);
    assert.equal(ok.json.backtest.items_matched, 1);
    assert.deepEqual(ok.json.backtest.sample_keys, ['tcp:0.0.0.0:4444']);
    assert.equal(ok.json.backtest.currently_matching, 1);
    assert.ok(ok.json.backtest.triggered_after < ok.json.backtest.triggered_before, 'the rule silences the rogue-listener triggers');

    const cases = [
      [{ matches: [{ op: 'eq', field: 'protocol', value: 'tcp' }, { op: 'eq', field: 'local_port', value: 4444 }] }, 'rule-gate/identity-anchor'],
      [{ matches: [{ op: 'eq', field: 'comm', value: 'helperd' }] }, 'rule-gate/port-bounds'],
      [{ matches: [{ op: 'eq', field: 'comm', value: 'helperd' }, { op: 'eq', field: 'local_port', value: 4444 }] }, 'rule-gate/wildcard-bind'],
      [{ matches: [{ op: 'eq', field: 'comm', value: 'xrdp' }, { op: 'eq', field: 'bind_scope', value: 'loopback' }, { op: 'range', field: 'local_port', min: 1024, max: 65535 }] }, null],
      [{ matches: [{ op: 'eq', field: 'comm', value: 'xrdp' }, { op: 'range', field: 'local_port', min: 1024, max: 65535 }, { op: 'eq', field: 'bind_scope', value: 'specific' }] }, 'rule-gate/port-bounds'],
      [{ matches: [{ op: 'prefix', field: 'local_port', value: '44' }] }, 'rule-gate/fields'],
      [{ matches: [] }, 'rule-gate/shape'],
      [{ rationale: '' }, 'rule-gate/shape'],
      [{ expires_at: new Date(Date.now() - 60_000).toISOString() }, 'rule-gate/expired'],
      [{ scope: { host_id: 'edge-vm-07', collector: 'files.metadata', watch_id: null } }, 'rule-gate/fields'],
    ];
    for (const [over, rule_id] of cases) {
      const r = await post(port, '/api/admin/rules/backtest', { rule: serviceRule('edge-vm-07', 'base-sockets-listening', over) });
      assert.equal(r.status, 200, r.text);
      if (rule_id === null) {
        assert.equal(r.json.allowed, true, `loopback ephemeral range is allowed: ${r.text}`);
        continue;
      }
      assert.equal(r.json.allowed, false, r.text);
      assert.equal(r.json.decision.allowed, false);
      assert.equal(r.json.decision.rule_id, rule_id, JSON.stringify(over));
      assert.equal(typeof r.json.decision.reason, 'string');
      assert.equal(r.json.backtest, null);
    }
  });

  test('bodies are validated against the closed schema before anything reaches the backend', async () => {
    const before = backend._state().audit.length;
    for (const [name, mutate] of MALFORMED_RULES) {
      const rule = mutate ? mutate(serviceRule('edge-vm-07', null)) : undefined;
      for (const p of ['/api/admin/rules/backtest', '/api/admin/rules']) {
        const r = await post(port, p, { rule, actor: 'op' });
        assert.equal(r.status, 400, `${name} → ${p}: ${r.text}`);
        assert.equal(r.json.error.code, 'invalid_request');
      }
    }
    const rule = backend._state().rules.find((r) => r.status === 'proposed');
    for (const body of [{}, { approve: 'yes' }, { approve: 1 }, { approve: true, note: 7 }]) {
      assert.equal((await post(port, `/api/admin/rules/${rule.rule_id}/decide`, body)).status, 400, JSON.stringify(body));
    }
    assert.equal((await post(port, '/api/admin/rules/not-a-rule/decide', { approve: true })).status, 400);
    assert.equal((await post(port, `/api/admin/rules/${rule.rule_id}/revoke`, {})).status, 400, 'revoke needs a reason');
    assert.equal((await post(port, `/api/admin/rules/${rule.rule_id}/revoke`, { reason: '   ' })).status, 400);
    assert.equal(backend._state().audit.length, before, 'nothing was recorded');
  });

  test('create activates immediately; decide approves or rejects; revoke needs an active rule', async () => {
    const created = await post(port, '/api/admin/rules', { rule: serviceRule('edge-vm-07', 'base-sockets-listening'), actor: 'j.rivera' });
    assert.equal(created.status, 200, created.text);
    assert.equal(created.json.allowed, true);
    assert.equal(created.json.status, 'active');
    assert.match(created.json.rule_id, /^rule-[0-9a-f-]{36}$/);
    const listed = (await get(port, '/api/rules?status=active')).json.rules.find((r) => r.rule_id === created.json.rule_id);
    assert.equal(listed.origin, 'operator');
    assert.equal(listed.proposed_by, 'j.rivera');
    assert.equal(listed.hit_count, 0);

    const denied = await post(port, '/api/admin/rules', { rule: serviceRule('edge-vm-07', null, { matches: [{ op: 'eq', field: 'local_port', value: 4444 }] }), actor: 'j.rivera' });
    assert.equal(denied.status, 200);
    assert.equal(denied.json.allowed, false);
    assert.equal(denied.json.decision.rule_id, 'rule-gate/identity-anchor');
    assert.equal(denied.json.decision.policy_version, 1);
    assert.equal(denied.json.rule_id, null);
    const dec = (await get(port, '/api/admin/policy-decisions?rule_id=rule-gate/identity-anchor')).json.decisions;
    assert.ok(dec.length >= 1, 'the denial is a recorded policy decision');

    const [pending] = (await get(port, '/api/rules?status=proposed')).json.rules;
    const approved = await post(port, `/api/admin/rules/${pending.rule_id}/decide`, { approve: true, note: 'CHG-4471 confirmed', actor: 's.lindqvist' });
    assert.equal(approved.status, 200, approved.text);
    assert.deepEqual([approved.json.allowed, approved.json.status], [true, 'active']);
    const after = (await get(port, '/api/rules?status=active')).json.rules.find((r) => r.rule_id === pending.rule_id);
    assert.equal(after.decided_by, 's.lindqvist');
    assert.equal(after.decision_note, 'CHG-4471 confirmed');
    const again = await post(port, `/api/admin/rules/${pending.rule_id}/decide`, { approve: false, actor: 's.lindqvist' });
    assert.equal(again.status, 400);
    assert.match(again.json.error.message, /only proposed rules/);

    const revoked = await post(port, `/api/admin/rules/${created.json.rule_id}/revoke`, { reason: 'helper decommissioned', actor: 'j.rivera' });
    assert.equal(revoked.status, 200, revoked.text);
    assert.equal(revoked.json.status, 'revoked');
    assert.equal((await post(port, `/api/admin/rules/${created.json.rule_id}/revoke`, { reason: 'twice', actor: 'j.rivera' })).status, 400);
    assert.equal((await post(port, '/api/admin/rules/rule-00000000-0000-0000-0000-000000000000/revoke', { reason: 'x', actor: 'j' })).status, 404);

    // A rejected investigator proposal keeps its note in History.
    const s = backend._state();
    s.rules.push({ ...s.rules.find((r) => r.origin === 'investigator'), rule_id: 'rule-11111111-2222-3333-4444-555555555555', status: 'proposed', decided_by: null, decided_at: null, decision_note: null });
    const rejected = await post(port, '/api/admin/rules/rule-11111111-2222-3333-4444-555555555555/decide', { approve: false, note: 'not benign', actor: 'j.rivera' });
    assert.equal(rejected.json.status, 'rejected');
    const audit = (await get(port, '/api/admin/audit?limit=500')).json;
    assert.equal(audit.chain.valid, true);
    assert.equal(audit.independent.valid, true);
    for (const t of ['rule_activated', 'rule_rejected', 'rule_revoked', 'rule_proposed']) assert.ok(audit.entries.some((e) => e.event_type === t), t);
  });

  test('admin gating: read-only demo, cross-origin POSTs and observer accounts', async () => {
    const ro = await startConsole(createDemoBackend({ enableAdmin: false }));
    try {
      assert.equal((await get(ro.port, '/api/rules')).status, 200, 'listing stays available read-only');
      for (const p of ['/api/admin/rules/backtest', '/api/admin/rules']) {
        const r = await post(ro.port, p, { rule: serviceRule('edge-vm-07', null), actor: 'x' });
        assert.equal(r.status, 403);
        assert.equal(r.json.error.code, 'admin_disabled');
      }
    } finally {
      await ro.app.close();
    }
    const count = backend._state().rules.length;
    const cross = await request(port, 'POST', '/api/admin/rules', { body: { rule: serviceRule('edge-vm-07', null), actor: 'x' }, headers: { Origin: 'http://evil.example' } });
    assert.equal(cross.status, 403);
    assert.equal(cross.json.error.code, 'cross_origin_denied');
    const form = await request(port, 'POST', '/api/admin/rules', { rawBody: 'rule=x', headers: { Origin: `http://127.0.0.1:${port}`, 'Content-Type': 'application/x-www-form-urlencoded' } });
    assert.equal(form.status, 415);
    assert.equal(backend._state().rules.length, count, 'no rule created');

    const auth = createAuth({ mode: 'proxy-header', proxyRoleHeader: 'x-forwarded-groups', proxyAdminGroup: 'defsec-admins' });
    const gated = createDemoBackend();
    const g = await startConsole(gated, { auth });
    const alice = { headers: { 'X-Forwarded-User': 'alice@example.com', 'X-Forwarded-Groups': 'defsec-admins' } };
    const bob = { headers: { 'X-Forwarded-User': 'bob@example.com', 'X-Forwarded-Groups': 'staff' } };
    try {
      assert.equal((await get(g.port, '/api/rules', bob)).status, 200, 'observers can read rules');
      const [pending] = (await get(g.port, '/api/rules?status=proposed', alice)).json.rules;
      for (const [p, body] of [['/api/admin/rules/backtest', { rule: serviceRule('edge-vm-07', null) }], ['/api/admin/rules', { rule: serviceRule('edge-vm-07', null), actor: 'bob' }], [`/api/admin/rules/${pending.rule_id}/decide`, { approve: true }]]) {
        const r = await post(g.port, p, body, bob);
        assert.equal(r.status, 403, p);
        assert.equal(r.json.error.code, 'admin_role_required');
      }
      // The actor is the signed-in account, whatever the client sends.
      const c = await post(g.port, '/api/admin/rules', { rule: serviceRule('edge-vm-07', 'base-sockets-listening'), actor: 'mallory' }, alice);
      assert.equal(c.status, 200, c.text);
      const d = await post(g.port, `/api/admin/rules/${pending.rule_id}/decide`, { approve: true, actor: 'mallory' }, alice);
      assert.equal(d.status, 200, d.text);
      const v = await post(g.port, `/api/admin/rules/${c.json.rule_id}/revoke`, { reason: 'done', actor: 'mallory' }, alice);
      assert.equal(v.status, 200, v.text);
      const rules = (await get(g.port, '/api/rules', alice)).json.rules;
      assert.equal(rules.find((r) => r.rule_id === c.json.rule_id).proposed_by, 'alice@example.com');
      assert.equal(rules.find((r) => r.rule_id === c.json.rule_id).decided_by, 'alice@example.com');
      assert.equal(rules.find((r) => r.rule_id === pending.rule_id).decided_by, 'alice@example.com');
      const audit = gated._state().audit;
      for (const t of ['rule_activated', 'rule_revoked']) assert.equal(audit.findLast((e) => e.event_type === t).actor, 'alice@example.com');
      assert.ok(!audit.some((e) => e.actor === 'mallory'));
    } finally {
      await g.app.close();
    }
  });

  test('demo history returns each rule once across pages and validates cursors', async () => {
    const base = '/api/rules?status=rejected,revoked,expired';
    const all = (await get(port, base)).json.rules.map((r) => r.rule_id);
    assert.ok(all.length >= 2);
    const seen = [];
    let before = null;
    do {
      const r = await get(port, `${base}&limit=1${before === null ? '' : `&before=${encodeURIComponent(before)}`}`);
      assert.equal(r.status, 200, r.text);
      assert.equal(r.json.rules.length, 1);
      seen.push(r.json.rules[0].rule_id);
      assert.ok(seen.length <= all.length, 'the cursor always advances');
      before = r.json.next_before;
    } while (before !== null);
    assert.deepEqual(seen, all);
    assert.equal((await get(port, `${base}&before=invalid`)).status, 400);
  });

  test('demo incident context identifies the rule responsible for suppression', async () => {
    const t = (await get(port, '/api/triggers?incident_id=inc-2026-0042')).json.triggers;
    assert.ok(t.some((x) => /\(1 suppressed by rules\)$/.test(x.reason ?? '')));
    const ctx = (await get(port, '/api/incidents/inc-2026-0042')).json;
    const rules = (await get(port, '/api/rules?host_id=edge-vm-07')).json.rules;
    const resolver = rules.find((r) => r.spec.matches.some((c) => c.value === 'systemd-resolved.service'));
    assert.deepEqual(ctx.rule_suppression, {
      total: 1,
      rules: [{ rule_id: resolver.rule_id, rationale: resolver.spec.rationale, suppressed_keys: ['udp:127.0.0.53:53'], count: 1 }],
    });
    assert.equal((await get(port, '/api/incidents/inc-2026-0039')).json.rule_suppression, null);
  });
});

describe('expectation rules over a mock control-d', () => {
  test('exact admin and investigation frames, gate denials as decisions, no token in responses', async () => {
    const dir = shortTmp('dsx-');
    const inv = path.join(dir, 'iv.sock');
    const adm = path.join(dir, 'ad.sock');
    const now = new Date().toISOString();
    const record = {
      rule_id: 'rule-abc', status: 'proposed', origin: 'investigator', proposed_by: 'reasoner-d', run_id: 'run-1', incident_id: 'inc-1',
      spec: serviceRule('edge-x', 'base-sockets'),
      backtest: { observations_scanned: 3, triggered_before: 2, triggered_after: 0, items_matched: 1, sample_keys: ['tcp:0.0.0.0:4444:uid=0'], currently_matching: 1 },
      created_at: now, decided_by: null, decided_at: null, decision_note: null, hit_count: 0, last_matched_at: null,
    };
    const denial = (code, message, policy_version) => ({ admin_result: 'error', code, message, decision: { allowed: false, rule_id: code, reason: message, policy_version } });
    const cursor = JSON.stringify([now, record.rule_id]);
    const rule_suppression = { total: 31, rules: [{ rule_id: record.rule_id, rationale: 'Expected nginx listener', suppressed_keys: ['tcp:127.0.0.1:443'], count: 31 }] };
    const invSeen = [];
    const admSeen = [];
    const invSrv = await mockUdsServer(inv, (frame) => {
      invSeen.push(frame);
      if (frame.request.op === 'get_incident_context') {
        return { result: 'incident_context', incident: { incident_id: 'inc-1', host_id: 'edge-x' }, active_watches: [], recent_observations: [], findings: [],
          rule_suppression: { ...rule_suppression, capability_token: 'cap-LEAK' } };
      }
      return frame.request.op === 'list_expectation_rules' ? { result: 'expectation_rules', rules: [{ ...record, capability_token: 'cap-LEAK' }], next_before: cursor } : { result: 'error', code: 'invalid_request', message: 'unexpected' };
    });
    const admSrv = await mockUdsServer(adm, (frame) => {
      admSeen.push(frame);
      switch (frame.admin_op) {
        case 'list_expectation_rules':
          return frame.before === cursor ? { admin_result: 'expectation_rules', rules: [] } : { admin_result: 'expectation_rules', rules: [record], next_before: cursor };
        case 'backtest_expectation_rule':
          return frame.rule.matches.length === 1
            ? denial('rule-gate/identity-anchor', 'rule must constrain systemd_unit, comm, or uid with eq or in', 6)
            : { admin_result: 'rule_backtest_result', backtest: record.backtest };
        case 'create_expectation_rule':
          return frame.rule.matches.length === 1
            ? denial('rule-gate/port-bounds', 'socket rule must constrain local_port within the allowed bounds', 7)
            : { admin_result: 'rule_decided', rule_id: 'rule-new', status: 'active' };
        case 'decide_expectation_rule':
          return frame.approve ? denial('rule-gate/expired', 'rule has expired', 8) : { admin_result: 'rule_decided', rule_id: frame.rule_id, status: 'rejected' };
        case 'revoke_expectation_rule':
          return frame.rule_id === 'rule-gone' ? { admin_result: 'error', code: 'not_found', message: 'expectation rule does not exist' } : { admin_result: 'rule_decided', rule_id: frame.rule_id, status: 'revoked' };
        default:
          return { admin_result: 'error', code: 'invalid_request', message: 'unexpected' };
      }
    });
    const ro = await startConsole(createLiveBackend({ investigateSock: inv, token: 'browse-token-LEAK' }));
    const rw = await startConsole(createLiveBackend({ investigateSock: inv, token: 'browse-token-LEAK', adminSock: adm, enableAdmin: true }));
    const bodies = [];
    const track = (r) => (bodies.push(r.text), r);
    try {
      // Without admin: the scoped investigation list on the browse token.
      const l1 = track(await get(ro.port, '/api/rules?status=proposed,active&host_id=edge-x&limit=20'));
      assert.equal(l1.status, 200, l1.text);
      assert.equal(l1.json.source, 'investigate');
      assert.equal(l1.json.next_before, cursor);
      assert.deepEqual(invSeen.at(-1).request, { op: 'list_expectation_rules', limit: 20, host_id: 'edge-x', statuses: ['proposed', 'active'] });
      assert.equal(invSeen.at(-1).capability_token, 'browse-token-LEAK');
      assert.deepEqual(Object.keys(l1.json.rules[0]).sort(), RULE_KEYS);
      assert.equal(track(await post(ro.port, '/api/admin/rules/backtest', { rule: serviceRule('edge-x', null) })).status, 403);

      const incident = track(await get(ro.port, '/api/incidents/inc-1'));
      assert.deepEqual(incident.json.rule_suppression, rule_suppression);

      // With admin: every host.
      const l2 = track(await get(rw.port, '/api/rules'));
      assert.equal(l2.json.source, 'admin');
      assert.deepEqual(admSeen.at(-1), { admin_op: 'list_expectation_rules', limit: 100 });

      assert.equal(l2.json.next_before, cursor);
      const l3 = track(await get(rw.port, `/api/rules?before=${encodeURIComponent(cursor)}`));
      assert.deepEqual(admSeen.at(-1), { admin_op: 'list_expectation_rules', limit: 100, before: cursor });
      assert.deepEqual(l3.json.rules, []);
      assert.equal(l3.json.next_before, null);

      const rule = serviceRule('edge-x', 'base-sockets');
      const bt = track(await post(rw.port, '/api/admin/rules/backtest', { rule }));
      assert.equal(bt.status, 200, bt.text);
      assert.deepEqual(admSeen.at(-1), { admin_op: 'backtest_expectation_rule', rule });
      assert.deepEqual(Object.keys(admSeen.at(-1).rule).sort(), ['effect', 'expires_at', 'matches', 'rationale', 'scope']);
      assert.deepEqual(bt.json.backtest, record.backtest);
      const btDenied = track(await post(rw.port, '/api/admin/rules/backtest', { rule: { ...rule, matches: [{ op: 'eq', field: 'local_port', value: 4444 }] } }));
      assert.equal(btDenied.status, 200);
      assert.deepEqual(btDenied.json.decision, { allowed: false, rule_id: 'rule-gate/identity-anchor', reason: 'rule must constrain systemd_unit, comm, or uid with eq or in', policy_version: 6 });

      const created = track(await post(rw.port, '/api/admin/rules', { rule, actor: 'op' }));
      assert.deepEqual(admSeen.at(-1), { admin_op: 'create_expectation_rule', rule, actor: 'op' });
      assert.deepEqual([created.json.allowed, created.json.rule_id, created.json.status], [true, 'rule-new', 'active']);
      const cDenied = track(await post(rw.port, '/api/admin/rules', { rule: { ...rule, matches: [{ op: 'eq', field: 'comm', value: 'x' }] }, actor: 'op' }));
      assert.equal(cDenied.status, 200);
      assert.deepEqual(cDenied.json.decision, { allowed: false, rule_id: 'rule-gate/port-bounds', reason: 'socket rule must constrain local_port within the allowed bounds', policy_version: 7 });

      const approval = track(await post(rw.port, '/api/admin/rules/rule-abc/decide', { approve: true, actor: 'op' }));
      assert.deepEqual(approval.json.decision, { allowed: false, rule_id: 'rule-gate/expired', reason: 'rule has expired', policy_version: 8 });
      assert.equal(approval.json.status, 'proposed');
      assert.ok(!admSeen.some((f) => f.admin_op === 'list_policy_decisions'));
      assert.deepEqual(admSeen.at(-1), { admin_op: 'decide_expectation_rule', rule_id: 'rule-abc', approve: true, actor: 'op' }, 'a null note is omitted');
      track(await post(rw.port, '/api/admin/rules/rule-abc/decide', { approve: false, note: 'noisy', actor: 'op' }));
      assert.deepEqual(admSeen.at(-1), { admin_op: 'decide_expectation_rule', rule_id: 'rule-abc', approve: false, actor: 'op', note: 'noisy' });
      const rv = track(await post(rw.port, '/api/admin/rules/rule-abc/revoke', { reason: 'done', actor: 'op' }));
      assert.deepEqual(admSeen.at(-1), { admin_op: 'revoke_expectation_rule', rule_id: 'rule-abc', actor: 'op', reason: 'done' });
      assert.deepEqual(rv.json, { rule_id: 'rule-abc', status: 'revoked' });
      const gone = track(await post(rw.port, '/api/admin/rules/rule-gone/revoke', { reason: 'done', actor: 'op' }));
      assert.equal(gone.status, 404);

      // Malformed bodies never reach control-d.
      const frames = admSeen.length;
      for (const [name, mutate] of MALFORMED_RULES) {
        const r = track(await post(rw.port, '/api/admin/rules', { rule: mutate ? mutate(rule) : undefined, actor: 'op' }));
        assert.equal(r.status, 400, name);
      }
      assert.equal(track(await post(rw.port, '/api/admin/rules', { rule })).status, 400, 'actor is required without an access gate');
      assert.equal(admSeen.length, frames, 'no frame was sent for an invalid body');
      for (const text of bodies) assert.ok(!/LEAK/.test(text), `no token in ${text.slice(0, 80)}`);
    } finally {
      await ro.app.close();
      await rw.app.close();
      invSrv.close();
      admSrv.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('a control-d before Phase 10 degrades the rules list to "not available"', async () => {
    const dir = shortTmp('dsx-');
    const old = path.join(dir, 'old.sock');
    const oldSrv = await mockUdsServer(old, (frame) => (frame.request.op === 'list_hosts' ? { result: 'hosts', hosts: [] } : undefined));
    const a = await startConsole(createLiveBackend({ investigateSock: old, token: 't' }));
    try {
      const r = await get(a.port, '/api/rules');
      assert.equal(r.status, 200, r.text);
      assert.equal(r.json.available, false);
      assert.equal(r.json.reason, 'unsupported');
      assert.match(r.json.message, /Phase 10/);
      assert.deepEqual(r.json.rules, []);
    } finally {
      await a.app.close();
      oldSrv.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

// ---------------------------------------------------------------------------
// 11. Adaptive investigator (P11–P18): host deep-dive, follow-ups and receipt
//     verification in demo mode, exact wire frames over a mock control-d,
//     graceful degradation, roles, and the real control-d.
// ---------------------------------------------------------------------------

const ASSESSMENT_KEYS = ['collectors', 'deadline', 'host_id', 'interpretations', 'version'];
const FOLLOWUP_KEYS = ['deadline', 'finding_id', 'finding_visible', 'interpretation', 'observation_id', 'origin_run', 'overdue', 'proposal_id', 'question', 'spec_version', 'status', 'summary', 'watch_id'];
const VERIFICATION_KEYS = ['available', 'collateral_coverage', 'concurrent_service_changes', 'expected_effect', 'intent_id', 'latest_receipt_id', 'operator_reconciliations', 'outcome', 'precondition_observation_id', 'receipt_checks', 'reconcile', 'recovery_plan'];
const CHECK_KEYS = ['deadline', 'expected_state', 'observation_id', 'reason', 'receipt_id', 'receipt_status', 'result', 'state_hash'];
const TOKENISH = /"(capability_token|lease_token|run_token|token)"\s*:/;

describe('adaptive investigator (demo)', () => {
  let app;
  let port;
  let clock;
  let backend;
  before(async () => {
    clock = Date.now();
    backend = createDemoBackend({ now: () => clock });
    ({ app, port } = await startConsole(backend));
  });
  after(() => app.close());

  test('P11: profiles and six-collector coverage, including the agent without a profile', async () => {
    const quiet = (await get(port, '/api/hosts/edge-vm-12/profile')).json;
    assert.equal(quiet.available, true);
    assert.deepEqual(quiet.host_profile.expected_services, [], 'the quiet host declares no role');
    assert.equal(quiet.discovery_support, true);
    assert.deepEqual(quiet.coverage.map((c) => c.collector), EVERY_COLLECTOR);
    assert.equal(quiet.coverage.find((c) => c.collector === 'packages.inventory').state, 'sampled', 'sampled by discovery, not watched');
    const web = (await get(port, '/api/hosts/edge-vm-03/profile')).json;
    assert.equal(web.coverage.find((c) => c.collector === 'connections.outbound').state, 'disabled');
    const legacy = (await get(port, '/api/hosts/edge-vm-11/profile')).json;
    assert.equal(legacy.host_profile, null);
    assert.ok(legacy.coverage.every((c) => c.profile === 'unknown'));
    assert.equal(legacy.coverage.find((c) => c.collector === 'sockets.listening').state, 'error');
    const hosts = (await get(port, '/api/hosts')).json.hosts;
    assert.deepEqual(hosts.find((h) => h.host_id === 'edge-vm-12').host_profile.host_tags, ['edge']);
    assert.equal((await get(port, '/api/hosts/nope/profile')).status, 404);
    assert.equal((await get(port, '/api/hosts/..%2Fx/profile')).status, 400);
  });

  test('P15: versioned assessments, citations, samples, attempts and advance', async () => {
    const d = (await get(port, '/api/hosts/edge-vm-12/discovery')).json;
    assert.equal(d.available, true);
    assert.equal(d.latest_version, 4);
    assert.deepEqual(Object.keys(d.assessment).sort(), ASSESSMENT_KEYS);
    const interp = d.assessment.interpretations.at(-1);
    assert.deepEqual(Object.keys(interp.proposal).sort(), ['citations', 'dependencies', 'proposed_watch', 'purpose', 'uncertainty', 'visibility_gaps']);
    assert.ok(interp.proposal.citations.every((id) => d.source_ids.includes(id)), 'citations name current discovery samples');
    assert.deepEqual(d.samples.map((s) => s.collector).sort(), ['packages.inventory', 'sockets.listening']);
    assert.equal(d.samples.find((s) => s.collector === 'sockets.listening').partial_attribution, true);
    assert.ok(d.samples.every((s) => s.entries.length <= 40));
    const attempts = d.attempts.find((g) => JSON.stringify(g.source_ids) === JSON.stringify(d.source_ids)).attempts;
    assert.deepEqual(attempts.map((a) => [a.status, a.error, a.assessment_version]), [['failed', 'provider_retryable', null], ['saved', null, 4]]);
    const v2 = (await get(port, '/api/hosts/edge-vm-12/discovery?version=2')).json;
    assert.equal(v2.assessment.version, 2);
    assert.deepEqual(v2.assessment.collectors.map((c) => c.gap), ['awaiting_sample', 'awaiting_sample']);
    assert.equal((await get(port, '/api/hosts/edge-vm-12/discovery?version=0')).status, 400);
    const offline = (await get(port, '/api/hosts/edge-db-02/discovery')).json;
    assert.equal(offline.assessment.collectors.find((c) => c.collector === 'sockets.listening').gap, 'deadline_elapsed');

    // edge-vm-03 is mid-discovery: the requested package sample arrives on advance.
    const before = (await get(port, '/api/hosts/edge-vm-03/discovery')).json;
    assert.equal(before.latest_version, 2);
    const adv = await post(port, '/api/admin/hosts/edge-vm-03/discovery/advance', {});
    assert.equal(adv.status, 200, adv.text);
    assert.equal(adv.json.assessment_version, 3);
    const after = (await get(port, '/api/hosts/edge-vm-03/discovery')).json;
    assert.ok(after.assessment.collectors.every((c) => c.evidence && !c.gap));
    assert.equal((await post(port, '/api/admin/hosts/edge-vm-03/discovery/advance', {})).json.assessment_version, 3, 'finished discovery does not churn revisions');
  });

  test('P16: grants, managed watches, corroboration and rollback through the audit chain', async () => {
    const m = (await get(port, '/api/hosts/edge-vm-12/monitoring')).json;
    assert.equal(m.available, true);
    assert.equal(m.source, 'audit');
    assert.deepEqual(m.grants.map((g) => [g.principal_id, g.max_watches, g.allow_promotion]), [['reasoner-d:discovery', 3, true]]);
    const w = m.watches.find((x) => x.watch_id === 'mon-cron-service');
    assert.equal(w.baseline_state, 'trusted');
    assert.equal(w.baseline_revision, 36);
    assert.ok(w.purpose && w.expected_signal && w.evidence.length && w.review_at);
    assert.deepEqual(m.candidates.map((c) => [c.candidate_id, c.state]), [[13, 'provisional'], [12, 'trusted'], [11, 'rolled_back']]);
    assert.ok(m.decisions.some((x) => x.allowed === false && /duplicates existing coverage/.test(x.reason)));

    const bad = await post(port, '/api/admin/monitoring/candidates/13/corroborate', { rationale: '' });
    assert.equal(bad.status, 400);
    const ok = await post(port, '/api/admin/monitoring/candidates/13/corroborate', { rationale: 'Matches CHG-4511' });
    assert.deepEqual(ok.json, { allowed: true, candidate_id: 13, reason: null });
    assert.equal((await post(port, '/api/admin/monitoring/candidates/13/corroborate', { rationale: 'again' })).json.allowed, false);
    assert.equal((await post(port, '/api/admin/monitoring/candidates/999/corroborate', { rationale: 'x' })).json.allowed, false);

    const rb = await post(port, '/api/admin/hosts/edge-vm-12/monitoring/mon-cron-service/rollback', { expected_baseline: 36, rationale: 'recapture' });
    assert.equal(rb.status, 200, rb.text);
    assert.deepEqual([rb.json.allowed, rb.json.baseline, rb.json.rolled_back], [true, null, 36]);
    const stale = await post(port, '/api/admin/hosts/edge-vm-12/monitoring/mon-cron-service/rollback', { expected_baseline: 36, rationale: 'twice' });
    assert.deepEqual([stale.json.allowed, stale.json.reason], [false, 'expected managed baseline is no longer current']);
    assert.equal((await post(port, '/api/admin/hosts/edge-vm-12/monitoring/mon-cron-service/rollback', { expected_baseline: 'x', rationale: 'r' })).status, 400);
    const tri = (await get(port, '/api/hosts/edge-vm-12/baselines')).json.three_state.find((r) => r.watch_id === 'mon-cron-service');
    assert.equal(tri.accepted_baseline, null, 'the trusted baseline was rolled back to none');

    // Rollback -> promote -> read: a fresh promotion replaces the rollback override.
    const latestCron = (await get(port, '/api/hosts/edge-vm-12/observations?watch_id=mon-cron-service&limit=1')).json.observations[0];
    const promoted = await post(port, '/api/admin/baselines/promote', { host_id: 'edge-vm-12', watch_id: 'mon-cron-service', observation_id: latestCron.observation_id, approver: 'j.rivera', rationale: 'settled sample after recapture' });
    assert.equal(promoted.status, 200, promoted.text);
    const reread = (await get(port, '/api/hosts/edge-vm-12/baselines')).json;
    assert.equal(reread.baselines.find((b) => b.watch_id === 'mon-cron-service')?.revision_id, promoted.json.revision_id, 'the new revision is current');
    assert.equal(reread.three_state.find((r) => r.watch_id === 'mon-cron-service').accepted_baseline?.revision_id, promoted.json.revision_id);
    assert.equal((await get(port, '/api/hosts/edge-vm-12/monitoring')).json.watches.find((x) => x.watch_id === 'mon-cron-service').current_baseline?.revision_id, promoted.json.revision_id);

    const grant = await post(port, '/api/admin/hosts/edge-vm-03/monitoring/grant', { principal_id: 'reasoner-d:discovery', max_watches: 2, allow_promotion: false });
    assert.deepEqual(grant.json, { allowed: true, host_id: 'edge-vm-03', principal_id: 'reasoner-d:discovery', max_watches: 2, allow_promotion: false });
    assert.equal((await post(port, '/api/admin/hosts/edge-vm-03/monitoring/grant', { principal_id: 'p', max_watches: 99 })).status, 400);
    const after = (await get(port, '/api/hosts/edge-vm-12/monitoring')).json;
    assert.equal(after.candidates.find((c) => c.candidate_id === 13).state, 'corroborated');
    assert.equal(after.candidates.find((c) => c.candidate_id === 12).state, 'rolled_back');
    assert.equal((await get(port, '/api/hosts/edge-vm-03/monitoring')).json.grants.length, 1);
    const audit = (await get(port, '/api/admin/audit?limit=500')).json;
    assert.equal(audit.chain.valid, true);
    assert.equal(audit.independent.valid, true);
  });

  test('P17: latest review, freshness and schedule set/cancel', async () => {
    const r07 = (await get(port, '/api/hosts/edge-vm-07/review')).json;
    assert.deepEqual(Object.keys(r07.review).sort(), ['assessment_version', 'citations', 'completed_at', 'interpretation', 'question', 'review_id', 'summary']);
    assert.equal(r07.review.interpretation, 'contradicts');
    assert.equal((await get(port, '/api/hosts/edge-db-02/review')).json.freshness.state, 'assessment_advanced');
    assert.equal((await get(port, '/api/hosts/edge-vm-12/review')).json.freshness.state, 'current');
    const none = (await get(port, '/api/hosts/edge-vm-03/review')).json;
    assert.deepEqual([none.review, none.schedule, none.freshness.state], [null, null, 'never_reviewed']);
    for (const body of [{ interval_seconds: 30, question: 'q', collectors: ['sockets.listening'] }, { interval_seconds: 3600, question: 'q', collectors: ['files.metadata'] }, { interval_seconds: 3600, question: 'q', collectors: [] }, { interval_seconds: 3600, question: '', collectors: ['sockets.listening'] }]) {
      assert.equal((await post(port, '/api/admin/hosts/edge-vm-03/review-schedule', body)).status, 400, JSON.stringify(body));
    }
    const set = await post(port, '/api/admin/hosts/edge-vm-03/review-schedule', { interval_seconds: 7200, question: 'Still a web host?', collectors: ['sockets.listening', 'packages.inventory'], route: 'host-review' });
    assert.equal(set.status, 200, set.text);
    assert.deepEqual(set.json.schedule.collectors, ['packages.inventory', 'sockets.listening']);
    assert.equal((await get(port, '/api/hosts/edge-vm-03/review')).json.freshness.state, 'awaiting_first_review');
    assert.equal((await post(port, '/api/admin/hosts/edge-vm-03/review-schedule/cancel', {})).json.cancelled, true);
    assert.equal((await get(port, '/api/hosts/edge-vm-03/review')).json.schedule, null);
  });

  test('P14: follow-up questions carry the fresh observation and recorded interpretation', async () => {
    const r = (await get(port, '/api/incidents/inc-2026-0042/followups')).json;
    assert.equal(r.available, true);
    for (const f of r.followups) assert.deepEqual(Object.keys(f).sort(), FOLLOWUP_KEYS);
    const by = Object.fromEntries(r.followups.map((f) => [f.proposal_id, f]));
    assert.deepEqual([by[71].status, by[71].interpretation], ['answered', 'supports']);
    assert.deepEqual([by[72].status, by[72].interpretation], ['answered', 'unresolved']);
    assert.deepEqual([by[76].status, by[76].observation_id, by[76].interpretation], ['awaiting_evidence', null, null]);
    const ctx = (await get(port, '/api/incidents/inc-2026-0042')).json;
    assert.ok(ctx.findings.some((f) => f.finding_id === by[71].finding_id && f.finding.interpretation === 'supports'), 'the answer is an ordinary cited finding');
    const r39 = (await get(port, '/api/incidents/inc-2026-0039/followups')).json.followups;
    assert.deepEqual(r39.map((f) => [f.status, f.interpretation]), [['expired', null], ['answered', 'contradicts']]);
    clock += 30 * 60_000;
    assert.equal((await get(port, '/api/incidents/inc-2026-0042/followups')).json.followups.find((f) => f.proposal_id === 76).status, 'expired');
    clock -= 30 * 60_000;
    assert.equal((await get(port, '/api/incidents/nope/followups')).status, 404);
  });

  test('P18: receipt, observed outcome and reconciliation stay separate records', async () => {
    await post(port, '/api/demo/reset', {});
    const { actions } = (await get(port, '/api/actions')).json;
    const rolled = actions.find((a) => a.status === 'rolled_back');
    const executed = actions.find((a) => a.status === 'executed');
    const expired = actions.find((a) => a.status === 'expired');
    const stop = actions.find((a) => a.verb.verb === 'systemd_stop_unit' && a.status === 'pending_approval');

    const v1 = (await get(port, `/api/admin/actions/${rolled.intent_id}/verification`)).json;
    assert.deepEqual(Object.keys(v1).sort(), VERIFICATION_KEYS);
    for (const c of v1.receipt_checks) assert.deepEqual(Object.keys(c).sort(), CHECK_KEYS);
    assert.deepEqual(v1.receipt_checks.map((c) => c.result), ['indeterminate', 'indeterminate'], 'an nft receipt has no effect sensor: never "verified" from a success bit');
    assert.equal(v1.operator_reconciliations.length, 1);
    assert.equal(v1.reconcile.allowed, false);

    const vx = (await get(port, `/api/admin/actions/${expired.intent_id}/verification`)).json;
    assert.equal(vx.reconcile.allowed, false);
    assert.match(vx.reconcile.reason, /expired/);

    const v2 = (await get(port, `/api/admin/actions/${executed.intent_id}/verification`)).json;
    assert.equal(v2.reconcile.allowed, true);
    const body = { expected_receipt_id: v2.latest_receipt_id, evidence_ref: 'nft list ruleset shows handle 23', rationale: 'checked from the jump host' };
    assert.equal((await post(port, `/api/admin/actions/${executed.intent_id}/reconcile`, { ...body, expected_receipt_id: v2.latest_receipt_id - 1 })).status, 403, 'only the latest receipt');
    assert.equal((await post(port, `/api/admin/actions/${executed.intent_id}/reconcile`, { ...body, evidence_ref: '' })).status, 400);
    const rec = await post(port, `/api/admin/actions/${executed.intent_id}/reconcile`, body);
    assert.equal(rec.status, 200, rec.text);
    assert.equal(rec.json.operator_reconciliations.length, 1);
    assert.equal(rec.json.outcome, 'indeterminate', 'a reconciliation never rewrites the observed outcome');
    assert.equal((await post(port, `/api/admin/actions/${executed.intent_id}/reconcile`, body)).status, 200, 'identical replay is idempotent');
    assert.equal((await post(port, `/api/admin/actions/${executed.intent_id}/reconcile`, { ...body, rationale: 'different' })).status, 400);
    assert.equal((await post(port, `/api/admin/actions/${stop.intent_id}/reconcile`, { expected_receipt_id: null, evidence_ref: 'x', rationale: 'y' })).status, 403, 'nothing to reconcile before execution');

    // Approve the stop; the executor reports, then a fresh sample verifies it.
    assert.equal((await get(port, `/api/admin/actions/${stop.intent_id}/verification`)).json.outcome, 'no_receipt');
    assert.equal((await post(port, `/api/admin/actions/${stop.intent_id}/approve`, { approver: 'j.rivera' })).status, 200);
    clock += 5_000;
    const awaiting = (await get(port, `/api/admin/actions/${stop.intent_id}/verification`)).json;
    assert.deepEqual([awaiting.outcome, awaiting.receipt_checks[0].expected_state], ['awaiting_evidence', 'inactive']);
    assert.ok(awaiting.precondition_observation_id);
    clock += 8_000;
    const verified = (await get(port, `/api/admin/actions/${stop.intent_id}/verification`)).json;
    assert.equal(verified.outcome, 'verified');
    assert.ok(verified.receipt_checks[0].observation_id > awaiting.precondition_observation_id);
    assert.deepEqual(verified.concurrent_service_changes.map((c) => c.watch_id), ['mon-resolved-service']);
    assert.match(verified.collateral_coverage, /Causation unassessed/);
    const audit = (await get(port, '/api/admin/audit?limit=500')).json;
    assert.ok(audit.entries.some((e) => e.event_type === 'action_effect_observed' && e.payload.result === 'verified'));
    assert.ok(audit.entries.some((e) => e.event_type === 'action_outcome_reconciled'));
    assert.equal(audit.independent.valid, true);
    assert.equal((await get(port, `/api/admin/actions/${crypto.randomUUID()}/verification`)).status, 404);
  });

  test('P18 gate: a service stop cites a current active sample of its unit; an unresolved target blocks a duplicate', async () => {
    await post(port, '/api/demo/reset', {});
    const INC = 'inc-2026-0042';
    assert.equal((await post(port, `/api/incidents/${INC}/runs`, {})).status, 200);
    const unitObs = (await get(port, '/api/hosts/edge-vm-07/observations?watch_id=ephem-0042-helper-unit&limit=50')).json.observations.sort((a, b) => b.observation_id - a.observation_id);
    const current = unitObs[0];
    const stale = unitObs.at(-1);
    assert.ok(Date.parse(current.observed_at) > clock - 5 * 60_000 && Date.parse(stale.observed_at) < clock - 5 * 60_000);
    const sock = (await get(port, '/api/hosts/edge-vm-07/observations?watch_id=base-sockets-listening&limit=1')).json.observations[0].observation_id;
    const propose = (verb, ids, key) => post(port, `/api/incidents/${INC}/actions`, { verb, evidence_observation_ids: ids, expected_effect: 'e', blast_radius: 'b', rollback_plan: 'r', idempotency_key: key });
    const stopVerb = { verb: 'systemd_stop_unit', unit: 'custom-helper.service', ttl_seconds: 600 };

    // An executed nft block with an unverified outcome and no reconciliation is outstanding.
    const dup = await propose({ verb: 'nft_block_ip', ip: '203.0.113.47', direction: 'outbound', ttl_seconds: 600 }, [sock], 'dup-nft');
    assert.deepEqual([dup.json.decision.rule_id, dup.json.status, dup.json.intent_id], ['action.awaiting_reconciliation', 'rejected', null]);

    for (const [ids, key] of [[[sock], 'no-unit'], [[stale.observation_id], 'stale-unit']]) {
      const r = await propose(stopVerb, ids, key);
      assert.equal(r.status, 200, r.text);
      assert.deepEqual([r.json.decision.rule_id, r.json.intent_id], ['action.missing_service_precondition', null], key);
    }
    const ok = await propose(stopVerb, [sock, current.observation_id], 'current-unit');
    assert.equal(ok.json.decision.allowed, true, ok.text);
    const v = (await get(port, `/api/admin/actions/${ok.json.intent_id}/verification`)).json;
    assert.equal(v.precondition_observation_id, current.observation_id, 'the precondition is the cited pre-dispatch sample');

    // Every recorded stop precondition predates its intent's issuance, never a later sample.
    for (const a of (await get(port, '/api/actions')).json.actions.filter((x) => x.verb.verb === 'systemd_stop_unit')) {
      const detail = (await get(port, `/api/admin/actions/${a.intent_id}`)).json;
      const pre = (await get(port, `/api/admin/actions/${a.intent_id}/verification`)).json.precondition_observation_id;
      assert.ok(pre, `${a.intent_id} has a precondition`);
      const o = unitObs.find((x) => x.observation_id === pre);
      assert.ok(o && Date.parse(o.observed_at) <= Date.parse(detail.payload.issued_at), 'precondition observed before issuance');
    }

    // The new stop is authorized and unverified, so the fixture stop of the same unit cannot be approved.
    const pending = (await get(port, '/api/actions')).json.actions.find((a) => a.verb.verb === 'systemd_stop_unit' && a.status === 'pending_approval');
    const denied = await post(port, `/api/admin/actions/${pending.intent_id}/approve`, { approver: 'j.rivera' });
    assert.equal(denied.status, 403);
    assert.match(denied.json.error.message, /needs reconciliation/);
    await post(port, '/api/demo/reset', {});
  });

  test('roles: observers read the deep-dive but every adaptive mutation is admin-only; read-only demo degrades', async () => {
    const auth = createAuth({ mode: 'proxy-header', proxyRoleHeader: 'x-forwarded-groups', proxyAdminGroup: 'defsec-admins' });
    const gated = await startConsole(createDemoBackend(), { auth });
    const ro = await startConsole(createDemoBackend({ enableAdmin: false }));
    const obs = { headers: { 'X-Forwarded-User': 'bob', 'X-Forwarded-Groups': 'viewers' } };
    const adm = { headers: { 'X-Forwarded-User': 'alice', 'X-Forwarded-Groups': 'defsec-admins' } };
    const mutations = [
      ['/api/admin/hosts/edge-vm-12/discovery/advance', {}],
      ['/api/admin/hosts/edge-vm-12/monitoring/grant', { principal_id: 'p', max_watches: 1 }],
      ['/api/admin/monitoring/candidates/13/corroborate', { rationale: 'r' }],
      ['/api/admin/hosts/edge-vm-12/monitoring/mon-cron-service/rollback', { expected_baseline: 36, rationale: 'r' }],
      ['/api/admin/hosts/edge-vm-12/review-schedule', { interval_seconds: 3600, question: 'q', collectors: ['sockets.listening'] }],
      ['/api/admin/hosts/edge-vm-12/review-schedule/cancel', {}],
      ['/api/admin/actions/x/reconcile', { evidence_ref: 'e', rationale: 'r' }],
    ];
    try {
      for (const p of ['/api/hosts/edge-vm-12/profile', '/api/hosts/edge-vm-12/discovery', '/api/hosts/edge-vm-12/monitoring', '/api/hosts/edge-vm-12/review', '/api/incidents/inc-2026-0042/followups']) {
        const r = await get(gated.port, p, obs);
        assert.equal(r.status, 200, `${p}: ${r.text}`);
        assert.ok(!TOKENISH.test(r.text), `${p} leaks a token-like key`);
      }
      for (const [p, body] of mutations) {
        const r = await post(gated.port, p, body, obs);
        assert.equal(r.status, 403, p);
        assert.equal(r.json.error.code, 'admin_role_required', p);
        assert.equal((await post(gated.port, p, body, { headers: { ...adm.headers, Origin: 'http://evil.example' } })).status, 403, `${p} cross-origin`);
        const off = await post(ro.port, p, body);
        assert.equal(off.status, 403, p);
        assert.equal(off.json.error.code, 'admin_disabled', p);
      }
      assert.equal((await get(gated.port, '/api/admin/actions/x/verification', obs)).json.error.code, 'admin_role_required');
      const before = (await get(gated.port, '/api/hosts/edge-vm-12/monitoring', adm)).json.candidates.find((c) => c.candidate_id === 13).state;
      assert.equal(before, 'provisional', 'refused observer mutations changed nothing');
      assert.equal((await post(gated.port, '/api/admin/monitoring/candidates/13/corroborate', { rationale: 'ok' }, adm)).json.allowed, true);
      for (const p of ['/api/hosts/edge-vm-12/monitoring', '/api/hosts/edge-vm-12/review']) {
        const r = (await get(ro.port, p)).json;
        assert.deepEqual([r.available, r.reason], [false, 'admin_disabled'], p);
      }
      assert.equal((await get(ro.port, '/api/hosts/edge-vm-12/discovery')).json.available, true, 'discovery reads the investigation interface');
    } finally {
      await gated.app.close();
      await ro.app.close();
    }
  });
});

describe('adaptive investigator over a mock control-d', () => {
  const HOST = 'quiet-01';
  const now = () => new Date().toISOString();
  const hashOf = (c) => sha256Hex(c);
  const assessment = (version) => ({
    host_id: HOST,
    version,
    deadline: now(),
    collectors: [
      { collector: 'sockets.listening', evidence: { watch_id: 'discovery-a', spec_version: 1, observation_id: 11, state_hash: hashOf('s'), status: 'ok' }, gap: null },
      { collector: 'packages.inventory', evidence: null, gap: 'agent_unsupported' },
    ],
    interpretations: [{ source_ids: [11], proposal: { purpose: 'p', dependencies: [], uncertainty: 'u', visibility_gaps: ['g'], proposed_watch: { collector: 'sockets.listening', rationale: 'r' }, citations: [11] } }],
  });
  const policyEntry = (seq, actor, intent, decision) => ({ seq_no: seq, timestamp: now(), prev_hash: '0'.repeat(64), event_type: 'policy_decision', actor, request_id: `r${seq}`, payload: { policy_version: 1, intent, decision }, entry_hash: '0'.repeat(64) });

  test('exact P11–P18 frames, token isolation, and no token in any response', async () => {
    const dir = shortTmp('dsp-');
    const inv = path.join(dir, 'iv.sock');
    const adm = path.join(dir, 'ad.sock');
    const seen = [];
    const MINTED = 'minted-discovery-SECRET-token';
    const invSrv = await mockUdsServer(inv, (frame) => {
      seen.push({ sock: 'inv', token: frame.capability_token, request: frame.request, keys: Object.keys(frame).sort() });
      const r = frame.request;
      switch (r.op) {
        case 'list_hosts':
          return { result: 'hosts', hosts: [{ host_id: HOST, agent_version: '0.2.0+host-discovery-v1', liveness_status: 'online', active_bundle_version: 2, last_heartbeat_at: now(), host_profile: { host_tags: ['edge'], expected_services: [], enabled_collectors: ['packages.inventory', 'sockets.listening'] } }] };
        case 'list_collector_capabilities':
          return { result: 'capabilities', capabilities: [{ collector_type: 'sockets.listening', schema_version: 1, is_stream: false, sensitivity: 'metadata_sensitive', min_interval_seconds: 15, description: 'd', declared_privileges: [] }] };
        case 'list_active_watches':
          return { result: 'watches', watches: [] };
        case 'query_observations':
          return { result: 'observations', observations: [] };
        case 'get_host_baseline_summary':
          return { result: 'baseline_summary', host_id: HOST, baselines: [] };
        case 'get_host_assessment':
          return { result: 'host_assessment', assessment: assessment(r.version ?? 3) };
        case 'get_host_discovery_samples':
          return { result: 'host_discovery_samples', samples: [{ collector: 'sockets.listening', evidence: assessment(3).collectors[0].evidence, sample: { count: 1, partial_attribution: false, sockets: [{ socket_key: 'tcp:0.0.0.0:22', protocol: 'tcp', local_addr: '0.0.0.0', local_port: 22, uid: 0, inode: 1, pid: 1, comm: 'sshd', systemd_unit: 'ssh.service' }] }, omitted_entries: 0 }] };
        case 'list_host_interpretation_attempts':
          return { result: 'host_interpretation_attempts', attempts: [{ status: 'saved', lease_until: now(), retry_at: now(), usage: { input_tokens: 10, output_tokens: 2, cached_input_tokens: 0, reasoning_tokens: 1, cache_creation_input_tokens: 0 }, error: null, assessment_version: 3, lease_token: 'LEASE-LEAK' }] };
        case 'advance_host_discovery':
          return { result: 'host_discovery_advanced', host_id: HOST, bundle_version: 4 };
        case 'list_watch_followups':
          return { result: 'watch_followups', followups: [{ proposal_id: 5, origin_run: 'run-1', watch_id: 'ephem-1', spec_version: 1, question: 'q?', status: 'answered', deadline: now(), observation_id: 12, finding_id: 9, run_token: 'RUN-LEAK' }] };
        case 'get_incident_context':
          return { result: 'incident_context', incident: { incident_id: 'inc-1', host_id: HOST }, active_watches: [], recent_observations: [], findings: [{ finding_id: 9, finding: { kind: 'hypothesis', severity: 'info', summary: 'yes', interpretation: 'supports', evidence_observation_ids: [12] } }] };
        default:
          return { result: 'error', code: 'invalid_request', message: `unexpected ${r.op}` };
      }
    });
    const audit = [
      policyEntry(1, 'operator', { admin_op: 'set_monitoring_grant', host_id: HOST, principal_id: 'inv-1', max_watches: 2, allow_promotion: true }, { allowed: true }),
      policyEntry(2, 'inv-1', { host_id: HOST, watch_id: 'mon-a', change: { operation: 'apply', spec: { version: 1, collector: { type: 'systemd.unit_state', parameters: { unit: 'cron.service' } }, schedule: { interval_seconds: 60 } }, expected_revision: 0, purpose: 'p', expected_signal: 's', evidence: [11], review_at: now() } }, { allowed: true, revision: 1 }),
      policyEntry(3, 'inv-1', { host_id: HOST, watch_id: 'mon-a', change: { operation: 'provisional', observations: [20, 21], rationale: 'stable' } }, { allowed: true, candidate_id: 7 }),
      policyEntry(4, 'operator', { admin_op: 'set_monitoring_grant', host_id: 'other-host', principal_id: 'x', max_watches: 1, allow_promotion: false }, { allowed: true }),
    ];
    const admSrv = await mockUdsServer(adm, (frame) => {
      seen.push({ sock: 'adm', request: frame });
      switch (frame.admin_op) {
        case 'mint_capability_token':
          return { admin_result: 'token_minted', token: MINTED, expires_at: now() };
        case 'list_audit_entries':
          return { admin_result: 'audit_entries', entries: audit };
        case 'set_monitoring_grant':
        case 'corroborate_monitoring':
          return { admin_result: 'monitoring', result: { allowed: true } };
        case 'rollback_monitoring':
          return { admin_result: 'monitoring', result: { allowed: false, reason: 'expected managed baseline is no longer current' } };
        case 'get_latest_host_review':
          return { admin_result: 'latest_host_review', review: { review_id: 'rv-1', question: 'q', assessment_version: 2, completed_at: now(), interpretation: 'unresolved', summary: 's', citations: [11] } };
        case 'set_host_review_schedule':
        case 'cancel_host_review_schedule':
          return { admin_result: 'host_review_schedule_updated' };
        case 'get_action_verification':
        case 'reconcile_action_outcome':
          return { admin_result: 'action_verification', detail: { intent_id: 'i-1', precondition_observation_id: 30, expected_effect: 'e', recovery_plan: 'r', receipt_checks: [{ receipt_id: 4, receipt_status: 'executed', expected_state: 'inactive', result: 'contradicted', reason: 'Observed service state', deadline: now(), observation_id: 31, state_hash: hashOf('x') }], concurrent_service_changes: [{ receipt_id: 4, before: 28, after: 32, watch_id: 'w2', state_hash: hashOf('y') }], collateral_coverage: 'Up to 20 transitions on other monitored units. Causation unassessed.', operator_reconciliations: frame.admin_op === 'reconcile_action_outcome' ? [{ receipt_id: 4, evidence_ref: frame.evidence_ref, rationale: frame.rationale, recorded_at: now() }] : [], capability_token: 'CAP-LEAK' } };
        case 'get_action_intent':
          return { admin_result: 'action_intent_detail', payload: { intent_id: 'i-1', expires_at: new Date(Date.now() + 60_000).toISOString() }, authorized_intent: null, status: 'executed' };
        default:
          return { admin_result: 'error', code: 'invalid_request', message: `unexpected ${frame.admin_op}` };
      }
    });
    const { app, port } = await startConsole(createLiveBackend({ investigateSock: inv, token: 'browse-token', adminSock: adm, enableAdmin: true }));
    const bodies = [];
    const track = (r) => (bodies.push(r.text), r);
    const frame = (pred) => seen.filter(pred).map((x) => x.request);
    try {
      const prof = track(await get(port, `/api/hosts/${HOST}/profile`));
      assert.equal(prof.status, 200, prof.text);
      assert.equal(prof.json.coverage.find((c) => c.collector === 'packages.inventory').state, 'unavailable', 'enabled by profile but not advertised to this scope');
      assert.deepEqual(frame((x) => x.request.op === 'query_observations').at(-1), { op: 'query_observations', host_id: HOST, limit: 200 });

      const disc = track(await get(port, `/api/hosts/${HOST}/discovery`));
      assert.equal(disc.status, 200, disc.text);
      assert.deepEqual(frame((x) => x.request.op === 'get_host_assessment').at(-1), { op: 'get_host_assessment', host_id: HOST }, 'no version key for the latest');
      assert.deepEqual(frame((x) => x.request.op === 'get_host_discovery_samples').at(-1), { op: 'get_host_discovery_samples', host_id: HOST });
      assert.deepEqual(frame((x) => x.request.op === 'list_host_interpretation_attempts').at(-1), { op: 'list_host_interpretation_attempts', host_id: HOST, source_ids: [11] });
      assert.equal(disc.json.attempts[0].attempts[0].usage.input_tokens, 10);
      track(await get(port, `/api/hosts/${HOST}/discovery?version=2`));
      assert.deepEqual(frame((x) => x.request.op === 'get_host_assessment').at(-1), { op: 'get_host_assessment', host_id: HOST, version: 2 });

      const adv = track(await post(port, `/api/admin/hosts/${HOST}/discovery/advance`, {}));
      assert.equal(adv.status, 200, adv.text);
      assert.deepEqual(adv.json, { host_id: HOST, bundle_version: 4, assessment_version: 3 });
      assert.deepEqual(frame((x) => x.sock === 'adm' && x.request.admin_op === 'mint_capability_token').at(-1), {
        admin_op: 'mint_capability_token', principal_id: 'console-discovery', role: 'investigator', allowed_hosts: [HOST], allowed_collectors: ['sockets.listening', 'packages.inventory'], allowed_purposes: ['host_discovery'], ttl_seconds: 300,
      });
      const advFrames = seen.filter((x) => x.request.op === 'advance_host_discovery');
      assert.deepEqual(advFrames.map((x) => [x.token, x.request]), [[MINTED, { op: 'advance_host_discovery', host_id: HOST }]], 'only the minted host-scoped token advances discovery');
      assert.ok(seen.filter((x) => x.sock === 'inv').every((x) => x.keys.join() === 'capability_token,request,request_id'));

      const mon = track(await get(port, `/api/hosts/${HOST}/monitoring`));
      assert.equal(mon.status, 200, mon.text);
      assert.deepEqual(frame((x) => x.sock === 'adm' && x.request.admin_op === 'list_audit_entries').at(-1), { admin_op: 'list_audit_entries', limit: 500 });
      assert.deepEqual(mon.json.grants.map((g) => g.principal_id), ['inv-1'], 'other hosts are not mixed in');
      assert.deepEqual(mon.json.watches.map((w) => [w.watch_id, w.revision, w.target, w.baseline_state]), [['mon-a', 1, 'cron.service', 'provisional']]);
      assert.deepEqual(mon.json.candidates.map((c) => [c.candidate_id, c.observations, c.state]), [[7, [20, 21], 'provisional']]);

      track(await post(port, `/api/admin/hosts/${HOST}/monitoring/grant`, { principal_id: ' inv-1 ', max_watches: 3, allow_promotion: true, extra: 'dropped' }));
      assert.deepEqual(frame((x) => x.request.admin_op === 'set_monitoring_grant').at(-1), { admin_op: 'set_monitoring_grant', host_id: HOST, principal_id: 'inv-1', max_watches: 3, allow_promotion: true });
      track(await post(port, '/api/admin/monitoring/candidates/7/corroborate', { rationale: 'CHG-1' }));
      assert.deepEqual(frame((x) => x.request.admin_op === 'corroborate_monitoring').at(-1), { admin_op: 'corroborate_monitoring', candidate_id: 7, rationale: 'CHG-1' });
      const rb = track(await post(port, `/api/admin/hosts/${HOST}/monitoring/mon-a/rollback`, { expected_baseline: '41', rationale: 'r' }));
      assert.deepEqual(frame((x) => x.request.admin_op === 'rollback_monitoring').at(-1), { admin_op: 'rollback_monitoring', host_id: HOST, watch_id: 'mon-a', expected_baseline: 41, rationale: 'r' });
      assert.deepEqual([rb.json.allowed, rb.json.reason], [false, 'expected managed baseline is no longer current'], 'a denial is a 200 decision');

      const rev = track(await get(port, `/api/hosts/${HOST}/review`));
      assert.deepEqual(frame((x) => x.request.admin_op === 'get_latest_host_review').at(-1), { admin_op: 'get_latest_host_review', host_id: HOST });
      assert.deepEqual([rev.json.freshness.state, rev.json.schedule, rev.json.schedule_visible], ['assessment_advanced', null, false]);
      track(await post(port, `/api/admin/hosts/${HOST}/review-schedule`, { interval_seconds: 86400, question: 'changed?', collectors: ['sockets.listening', 'packages.inventory', 'sockets.listening'], route: 'host-review' }));
      assert.deepEqual(frame((x) => x.request.admin_op === 'set_host_review_schedule').at(-1), { admin_op: 'set_host_review_schedule', schedule: { host_id: HOST, interval_seconds: 86400, question: 'changed?', collectors: ['packages.inventory', 'sockets.listening'], route: 'host-review' } });
      assert.equal(track(await get(port, `/api/hosts/${HOST}/review`)).json.schedule.source, 'console', 'the console remembers what it set; control-d has no read');
      track(await post(port, `/api/admin/hosts/${HOST}/review-schedule/cancel`, {}));
      assert.deepEqual(frame((x) => x.request.admin_op === 'cancel_host_review_schedule').at(-1), { admin_op: 'cancel_host_review_schedule', host_id: HOST });
      assert.equal(track(await get(port, `/api/hosts/${HOST}/review`)).json.schedule, null);

      const fu = track(await get(port, '/api/incidents/inc-1/followups'));
      assert.deepEqual(frame((x) => x.request.op === 'list_watch_followups').at(-1), { op: 'list_watch_followups', incident_id: 'inc-1' });
      assert.deepEqual([fu.json.followups[0].interpretation, fu.json.followups[0].summary, fu.json.followups[0].observation_id], ['supports', 'yes', 12]);

      const ver = track(await get(port, '/api/admin/actions/i-1/verification'));
      assert.deepEqual(frame((x) => x.request.admin_op === 'get_action_verification').at(-1), { admin_op: 'get_action_verification', intent_id: 'i-1' });
      assert.deepEqual([ver.json.outcome, ver.json.latest_receipt_id, ver.json.reconcile.allowed, ver.json.concurrent_service_changes.length], ['contradicted', 4, true, 1]);
      const rc = track(await post(port, '/api/admin/actions/i-1/reconcile', { expected_receipt_id: 4, evidence_ref: 'ticket-9', rationale: 'restarted by hand' }));
      assert.deepEqual(frame((x) => x.request.admin_op === 'reconcile_action_outcome').at(-1), { admin_op: 'reconcile_action_outcome', intent_id: 'i-1', expected_receipt_id: 4, evidence_ref: 'ticket-9', rationale: 'restarted by hand' });
      assert.deepEqual([rc.json.outcome, rc.json.operator_reconciliations.length, rc.json.reconcile.allowed], ['contradicted', 1, false], 'three records: the attestation does not overwrite the outcome');
      track(await post(port, '/api/admin/actions/i-1/reconcile', { evidence_ref: 'e', rationale: 'r' }));
      assert.equal(frame((x) => x.request.admin_op === 'reconcile_action_outcome').at(-1).expected_receipt_id, null, 'null is sent explicitly');

      // Invalid bodies never reach control-d.
      const count = seen.length;
      for (const [p, body] of [
        [`/api/admin/hosts/${HOST}/monitoring/grant`, { principal_id: 'p', max_watches: 33 }],
        [`/api/admin/hosts/${HOST}/monitoring/grant`, { principal_id: '', max_watches: 1 }],
        [`/api/admin/hosts/${HOST}/monitoring/grant`, { principal_id: 'p', max_watches: 1, allow_promotion: 'true' }],
        [`/api/admin/hosts/${HOST}/monitoring/grant`, { principal_id: 'p', max_watches: 1, allow_promotion: 1 }],
        ['/api/admin/monitoring/candidates/abc/corroborate', { rationale: 'r' }],
        [`/api/admin/hosts/${HOST}/monitoring/mon-a/rollback`, { expected_baseline: 1.5, rationale: 'r' }],
        [`/api/admin/hosts/${HOST}/review-schedule`, { interval_seconds: 2_592_001, question: 'q', collectors: ['sockets.listening'] }],
        [`/api/admin/hosts/${HOST}/review-schedule`, { interval_seconds: 3600, question: 'q', collectors: ['journal.unit_events'] }],
        ['/api/admin/actions/i-1/reconcile', { expected_receipt_id: 'x', evidence_ref: 'e', rationale: 'r' }],
        ['/api/admin/actions/i-1/reconcile', { evidence_ref: 'e'.repeat(513), rationale: 'r' }],
      ]) {
        assert.equal((await post(port, p, body)).status, 400, `${p} ${JSON.stringify(body)}`);
      }
      assert.equal(seen.length, count, 'no frame for an invalid body');
      for (const text of bodies) {
        for (const secret of ['browse-token', MINTED, 'LEASE-LEAK', 'RUN-LEAK', 'CAP-LEAK']) assert.ok(!text.includes(secret), `${secret} leaked`);
        assert.ok(!TOKENISH.test(text), `token-like key in ${text.slice(0, 120)}`);
      }
    } finally {
      await app.close();
      invSrv.close();
      admSrv.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('admin-fetched monitoring and review data stay behind the browse token\'s host scope', async () => {
    const dir = shortTmp('dsp-');
    const inv = path.join(dir, 'iv.sock');
    const adm = path.join(dir, 'ad.sock');
    const OUT = 'secret-host';
    const seen = [];
    const scoped = (r, ok) => (r.host_id === OUT ? { result: 'error', code: 'forbidden', message: `host '${OUT}' is outside capability scope` } : ok);
    const invSrv = await mockUdsServer(inv, (frame) => {
      const r = frame.request;
      seen.push({ sock: 'inv', request: r });
      switch (r.op) {
        case 'list_active_watches':
          return scoped(r, { result: 'watches', watches: [] });
        case 'get_host_baseline_summary':
          return scoped(r, { result: 'baseline_summary', host_id: r.host_id, baselines: [] });
        case 'get_host_assessment':
          return scoped(r, { result: 'host_assessment', assessment: assessment(3) });
        case 'advance_host_discovery':
          return { result: 'host_discovery_advanced', host_id: HOST, bundle_version: 5 };
        default:
          return { result: 'error', code: 'invalid_request', message: `unexpected ${r.op}` };
      }
    });
    let mints = 0;
    const admSrv = await mockUdsServer(adm, (frame) => {
      seen.push({ sock: 'adm', request: frame });
      switch (frame.admin_op) {
        case 'list_audit_entries':
          return { admin_result: 'audit_entries', entries: [policyEntry(1, 'operator', { admin_op: 'set_monitoring_grant', host_id: OUT, principal_id: 'hidden-principal', max_watches: 2, allow_promotion: true }, { allowed: true })] };
        case 'get_latest_host_review':
          return { admin_result: 'latest_host_review', review: { review_id: 'rv-HIDDEN', question: 'q', assessment_version: 2, completed_at: now(), interpretation: 'contradicts', summary: 'hidden summary', citations: [] } };
        case 'mint_capability_token':
          mints += 1;
          // A control-d from before purpose-scoped tokens rejects the field.
          if ('allowed_purposes' in frame) return { admin_result: 'error', code: 'invalid_request', message: 'unknown field `allowed_purposes`, expected one of `principal_id`, `role`' };
          return { admin_result: 'token_minted', token: 'legacy-minted', expires_at: now() };
        default:
          return { admin_result: 'error', code: 'invalid_request', message: `unexpected ${frame.admin_op}` };
      }
    });
    const { app, port } = await startConsole(createLiveBackend({ investigateSock: inv, token: 'browse-token', adminSock: adm, enableAdmin: true }));
    try {
      for (const p of [`/api/hosts/${OUT}/monitoring`, `/api/hosts/${OUT}/review`]) {
        const before = seen.filter((x) => x.sock === 'adm').length;
        const r = await get(port, p);
        assert.equal(r.status, 403, `${p}: ${r.text}`);
        assert.equal(r.json.error.code, 'forbidden', p);
        assert.ok(!/hidden|rv-HIDDEN/.test(r.text), `${p} leaked admin data`);
        assert.equal(seen.filter((x) => x.sock === 'adm').length, before, `${p}: no admin read before visibility is established`);
      }
      const mon = await get(port, `/api/hosts/${HOST}/monitoring`);
      assert.equal(mon.status, 200, mon.text);
      assert.deepEqual(mon.json.grants, [], 'other hosts are not mixed in');
      assert.equal((await get(port, `/api/hosts/${HOST}/review`)).status, 200);

      const adv = await post(port, `/api/admin/hosts/${HOST}/discovery/advance`, {});
      assert.equal(adv.status, 200, adv.text);
      const minted = seen.filter((x) => x.sock === 'adm' && x.request.admin_op === 'mint_capability_token').map((x) => x.request);
      assert.equal(mints, 2);
      assert.deepEqual(minted[0].allowed_purposes, ['host_discovery'], 'purpose-scoped first');
      assert.ok(!('allowed_purposes' in minted[1]), 'legacy fallback only after the field is rejected');
      assert.deepEqual(minted[1], { admin_op: 'mint_capability_token', principal_id: 'console-discovery', role: 'investigator', allowed_hosts: [HOST], allowed_collectors: ['sockets.listening', 'packages.inventory'], ttl_seconds: 300 });
    } finally {
      await app.close();
      invSrv.close();
      admSrv.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });

  test('a control-d before P11–P18 degrades every adaptive read to "not available"', async () => {
    const dir = shortTmp('dsp-');
    const old = path.join(dir, 'old.sock');
    const oldAdm = path.join(dir, 'oa.sock');
    // Pre-P11 control-d: only the Phase 1–10 ops deserialize; anything newer closes the connection.
    const known = new Set(['list_hosts', 'list_active_watches', 'query_observations', 'get_incident_context']);
    const oldSrv = await mockUdsServer(old, (f) => {
      if (!known.has(f.request.op)) return undefined;
      if (f.request.op === 'list_hosts') return { result: 'hosts', hosts: [{ host_id: HOST, agent_version: '0.1.0', liveness_status: 'online', active_bundle_version: 1, last_heartbeat_at: null }] };
      if (f.request.op === 'list_active_watches') return { result: 'watches', watches: [] };
      if (f.request.op === 'query_observations') return { result: 'observations', observations: [] };
      return { result: 'incident_context', incident: { incident_id: 'inc-1', host_id: HOST }, active_watches: [], recent_observations: [], findings: [] };
    });
    const oldAdmSrv = await mockUdsServer(oldAdm, (f) => (f.admin_op === 'list_audit_entries' ? { admin_result: 'audit_entries', entries: [] } : f.admin_op === 'get_action_verification' ? { admin_result: 'error', code: 'invalid_request', message: 'unknown variant `get_action_verification`' } : undefined));
    const a = await startConsole(createLiveBackend({ investigateSock: old, token: 't', adminSock: oldAdm, enableAdmin: true }));
    try {
      for (const p of [`/api/hosts/${HOST}/capabilities`, `/api/hosts/${HOST}/baselines`, `/api/hosts/${HOST}/discovery`, `/api/hosts/${HOST}/review`, '/api/incidents/inc-1/followups', '/api/admin/actions/i-1/verification']) {
        const r = await get(a.port, p);
        assert.equal(r.status, 200, `${p}: ${r.text}`);
        assert.equal(r.json.available, false, p);
        assert.equal(r.json.reason, 'unsupported', p);
      }
      const caps = (await get(a.port, `/api/hosts/${HOST}/capabilities`)).json;
      assert.deepEqual(caps.capabilities, [], 'older control-d: empty capability list, not an error');
      assert.deepEqual((await get(a.port, `/api/hosts/${HOST}/baselines`)).json.three_state, []);
      const prof = (await get(a.port, `/api/hosts/${HOST}/profile`)).json;
      assert.deepEqual([prof.available, prof.host_profile, prof.capabilities_available], [true, null, false], 'an agent without a profile: support unknown');
      const mon = (await get(a.port, `/api/hosts/${HOST}/monitoring`)).json;
      assert.deepEqual([mon.available, mon.grants], [true, []], 'an empty audit window is a valid empty state');
      assert.equal((await get(a.port, '/api/status')).status, 200);
    } finally {
      await a.app.close();
      oldSrv.close();
      oldAdmSrv.close();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe('adaptive investigator with target/debug/control-d', { skip: !fs.existsSync(CONTROL_D) && 'control-d binary not built (cargo build -p control-d)' }, () => {
  const HOST = 'quiet-01';
  let dir;
  let child;
  let adminSock;
  let invSock;
  let agentSock;
  let agent;
  let browseToken;
  let stderr = '';
  const unitSnap = (unit, active, pid) => ({ kind: 'snapshot', data: { unit, load_state: 'loaded', active_state: active, sub_state: active === 'active' ? 'running' : 'dead', unit_file_state: 'enabled', main_pid: pid, main_pid_start_time_ticks: null, exec_start_hash: null, unit_files: [] } });

  class DiscoveryAgent extends FakeAgent {
    async register() {
      this.sock.write(encodeFrame({
        msg: 'register', protocol_version: 1, host_id: this.hostId, agent_version: 'fake-0.0.1+host-discovery-v1',
        boot_id: 'boot-fake', session_id: this.session, active_bundle_version: 0, active_bundle_digest: null, sent_at: new Date().toISOString(),
        host_profile: { host_tags: ['edge'], expected_services: [], enabled_collectors: [...EVERY_COLLECTOR].sort() },
      }));
      const ack = await this.waitFrame((f) => f.msg === 'register_ack');
      assert.equal(ack.accepted, true, JSON.stringify(ack));
    }
  }

  before(async () => {
    dir = shortTmp('dsq-');
    adminSock = path.join(dir, 'ad.sock');
    invSock = path.join(dir, 'iv.sock');
    agentSock = path.join(dir, 'ag.sock');
    child = spawn(CONTROL_D, ['--data-dir', path.join(dir, 'data'), '--agent-sock', agentSock, '--admin-sock', adminSock, '--investigate-sock', invSock], { stdio: ['ignore', 'ignore', 'pipe'], env: { ...process.env, RUST_LOG: 'warn' } });
    child.stderr.on('data', (c) => {
      stderr += c;
    });
    assert.ok(await waitFor(() => fs.existsSync(adminSock) && fs.existsSync(invSock) && fs.existsSync(agentSock)), `control-d did not start:\n${stderr}`);
    const admin = new AdminClient({ socketPath: adminSock });
    assert.equal((await admin.call({ admin_op: 'enroll_host', host_id: HOST, agent_public_key_hex: null })).admin_result, 'host_enrolled');
    const spec = {
      id: 'base-sockets', version: 1, host_id: HOST, class: 'baseline', incident_id: null,
      collector: { type: 'sockets.listening', parameters: { include_tcp: true, include_udp: true, include_ipv6: true, resolve_process: true } },
      schedule: { interval_seconds: 60, timeout_seconds: 10 }, trigger: { type: 'set_diff', compare_against: 'last_observed', set_field: 'sockets', identity_key: 'socket_key' },
      wake_policy: { cooldown_seconds: 60, max_wakeups_per_hour: 30 }, lifecycle: { enabled: true, expires_at: null, max_runs: null },
    };
    assert.equal((await admin.call({ admin_op: 'apply_baseline_watch', spec, actor: 'it-operator', rationale: 'fixture' })).admin_result, 'watch_applied');
    agent = new DiscoveryAgent(agentSock, HOST);
    await agent.connect();
    await agent.register();
    await agent.push('base-sockets', 'sockets.listening', sockSnapshot([liveSocket(22, 'sshd', 'ssh.service', 101)]));
    browseToken = (await admin.call({ admin_op: 'mint_capability_token', principal_id: 'console-browse', role: 'investigator', allowed_hosts: [HOST], allowed_collectors: EVERY_COLLECTOR, ttl_seconds: 900 })).token;
    assert.ok(browseToken);
  });

  after(async () => {
    agent?.close();
    await stopChild(child);
    if (dir) fs.rmSync(dir, { recursive: true, force: true });
  });

  test('quiet host: profile, discovery, delegated monitoring, reviews, follow-ups and verification against real control-d', async () => {
    const backend = createLiveBackend({ investigateSock: invSock, token: browseToken, adminSock, enableAdmin: true });
    const { app, port } = await startConsole(backend);
    const bodies = [];
    const track = (r) => (bodies.push(r.text), r);
    const admin = new AdminClient({ socketPath: adminSock });
    const tokens = [browseToken];
    try {
      // P11
      const prof = track(await get(port, `/api/hosts/${HOST}/profile`));
      assert.equal(prof.status, 200, prof.text);
      assert.deepEqual(prof.json.host_profile, { host_tags: ['edge'], expected_services: [], enabled_collectors: prof.json.host_profile.enabled_collectors });
      assert.equal(prof.json.host_profile.enabled_collectors.length, 6);
      assert.equal(prof.json.discovery_support, true);
      assert.equal(prof.json.coverage.find((c) => c.collector === 'sockets.listening').state, 'covered');
      assert.equal(track(await get(port, `/api/hosts/${HOST}/capabilities`)).json.capabilities.length, 6, 'all six collectors advertised to this scope');

      // P15: enrollment queued discovery; the console advances it with a one-call grant.
      const d1 = track(await get(port, `/api/hosts/${HOST}/discovery`)).json;
      assert.equal(d1.available, true, JSON.stringify(d1));
      assert.deepEqual(d1.assessment.collectors.map((c) => c.gap), ['awaiting_agent', 'awaiting_agent']);
      const adv = track(await post(port, `/api/admin/hosts/${HOST}/discovery/advance`, {}));
      assert.equal(adv.status, 200, adv.text);
      assert.equal(adv.json.host_id, HOST);
      assert.equal(typeof adv.json.bundle_version, 'number', 'discovery watches were issued in a signed bundle');
      const watches = track(await get(port, `/api/hosts/${HOST}/watches`)).json.watches.filter((w) => w.id.startsWith('discovery-'));
      assert.deepEqual(watches.map((w) => w.collector.type).sort(), ['packages.inventory', 'sockets.listening']);
      for (const w of watches) {
        const payload = w.collector.type === 'sockets.listening'
          ? sockSnapshot([liveSocket(22, 'sshd', 'ssh.service', 101)])
          : { kind: 'snapshot', data: { packages: [{ package_key: 'cron:amd64', name: 'cron', arch: 'amd64', version: '3.0pl1-184' }, { package_key: 'openssh-server:amd64', name: 'openssh-server', arch: 'amd64', version: '1:9.7p1-7' }], total_packages: 2, status_file_sha256: sha256Hex('dpkg'), malformed_stanzas: 0 } };
        await agent.push(w.id, w.collector.type, payload);
      }
      const adv2 = track(await post(port, `/api/admin/hosts/${HOST}/discovery/advance`, {}));
      assert.equal(adv2.status, 200, adv2.text);
      const d2 = track(await get(port, `/api/hosts/${HOST}/discovery`)).json;
      assert.ok(d2.assessment.collectors.every((c) => c.evidence && c.gap === null), JSON.stringify(d2.assessment));
      assert.deepEqual(d2.samples.map((s) => s.collector).sort(), ['packages.inventory', 'sockets.listening']);
      assert.equal(d2.samples.find((s) => s.collector === 'packages.inventory').entries[0].name, 'cron');
      assert.equal(d2.source_ids.length, 2);
      assert.deepEqual(d2.attempts, [{ source_ids: d2.source_ids, attempts: [] }]);
      const v1 = track(await get(port, `/api/hosts/${HOST}/discovery?version=1`)).json;
      assert.equal(v1.assessment.version, 1, 'earlier revisions stay readable');
      const audit0 = track(await get(port, '/api/admin/audit?limit=500')).json;
      assert.ok(audit0.entries.some((e) => e.event_type === 'capability_minted' && JSON.stringify(e.payload).includes('console-discovery')));

      // P16: grant, then a real investigator applies a watch and records a provisional expectation.
      const grant = track(await post(port, `/api/admin/hosts/${HOST}/monitoring/grant`, { principal_id: 'it-investigator', max_watches: 2, allow_promotion: true }));
      assert.equal(grant.json.allowed, true, grant.text);
      const invToken = (await admin.call({ admin_op: 'mint_capability_token', principal_id: 'it-investigator', role: 'investigator', allowed_hosts: [HOST], allowed_collectors: EVERY_COLLECTOR, ttl_seconds: 600 })).token;
      tokens.push(invToken);
      const investigator = new InvestigationClient({ socketPath: invSock, token: invToken });
      const evidence = track(await get(port, `/api/hosts/${HOST}/observations?watch_id=base-sockets`)).json.observations.map((o) => o.observation_id);
      const mon = {
        id: 'mon-cron', version: 1, host_id: HOST, class: 'baseline', incident_id: null,
        collector: { type: 'systemd.unit_state', parameters: { unit: 'cron.service', hash_unit_files: false } },
        schedule: { interval_seconds: 60, timeout_seconds: 10 }, trigger: { type: 'field_changed', compare_against: 'last_observed', fields: ['active_state'] },
        wake_policy: { cooldown_seconds: 60, max_wakeups_per_hour: 6 }, lifecycle: { enabled: true, expires_at: null, max_runs: null },
      };
      const applied = await investigator.call({ op: 'monitoring', host_id: HOST, watch_id: 'mon-cron', change: { operation: 'apply', spec: mon, expected_revision: 0, purpose: 'quiet batch worker: watch its only scheduler', expected_signal: 'cron leaves active', evidence: evidence.slice(0, 1), review_at: new Date(Date.now() + 7 * 86_400_000).toISOString() } });
      assert.equal(applied.result, 'monitoring', JSON.stringify(applied));
      assert.equal(applied.detail.allowed, true, JSON.stringify(applied));
      await agent.push('mon-cron', 'systemd.unit_state', unitSnap('cron.service', 'active', 702), { observedAt: new Date(Date.now() - 20_000) });
      await agent.push('mon-cron', 'systemd.unit_state', unitSnap('cron.service', 'active', 702));
      const pair = track(await get(port, `/api/hosts/${HOST}/observations?watch_id=mon-cron`)).json.observations.map((o) => o.observation_id).sort((a, b) => a - b);
      const prov = await investigator.call({ op: 'monitoring', host_id: HOST, watch_id: 'mon-cron', change: { operation: 'provisional', observations: pair.slice(-2), rationale: 'stable for twenty seconds' } });
      assert.equal(prov.detail.allowed, true, JSON.stringify(prov));
      const candidate = prov.detail.candidate_id;
      let m = track(await get(port, `/api/hosts/${HOST}/monitoring`)).json;
      assert.deepEqual(m.grants.map((g) => [g.principal_id, g.max_watches, g.allow_promotion]), [['it-investigator', 2, true]]);
      assert.deepEqual(m.watches.map((w) => [w.watch_id, w.revision, w.principal_id, w.target, w.baseline_state]), [['mon-cron', 1, 'it-investigator', 'cron.service', 'provisional']]);
      assert.deepEqual(m.candidates.map((c) => [c.candidate_id, c.state]), [[candidate, 'provisional']]);
      const early = await investigator.call({ op: 'monitoring', host_id: HOST, watch_id: 'mon-cron', change: { operation: 'promote', candidate_id: candidate, expected_baseline: null } });
      assert.equal(early.detail.allowed, false, 'promotion needs operator corroboration first');
      const corr = track(await post(port, `/api/admin/monitoring/candidates/${candidate}/corroborate`, { rationale: 'matches the golden image' }));
      assert.equal(corr.json.allowed, true, corr.text);
      assert.equal(track(await post(port, `/api/admin/monitoring/candidates/${candidate}/corroborate`, { rationale: 'again' })).json.allowed, false);
      const promoted = await investigator.call({ op: 'monitoring', host_id: HOST, watch_id: 'mon-cron', change: { operation: 'promote', candidate_id: candidate, expected_baseline: null } });
      assert.equal(promoted.detail.allowed, true, JSON.stringify(promoted));
      const revision = promoted.detail.baseline;
      m = track(await get(port, `/api/hosts/${HOST}/monitoring`)).json;
      assert.deepEqual([m.watches[0].baseline_state, m.watches[0].baseline_revision, m.candidates[0].state], ['trusted', revision, 'trusted']);
      const rb = track(await post(port, `/api/admin/hosts/${HOST}/monitoring/mon-cron/rollback`, { expected_baseline: revision, rationale: 'recapture after upgrade' }));
      assert.deepEqual([rb.json.allowed, rb.json.baseline, rb.json.rolled_back], [true, null, revision], rb.text);
      const again = track(await post(port, `/api/admin/hosts/${HOST}/monitoring/mon-cron/rollback`, { expected_baseline: revision, rationale: 'twice' }));
      assert.deepEqual([again.status, again.json.allowed], [200, false]);
      assert.equal(track(await get(port, `/api/hosts/${HOST}/monitoring`)).json.candidates[0].state, 'rolled_back');

      // P17
      const r0 = track(await get(port, `/api/hosts/${HOST}/review`)).json;
      assert.deepEqual([r0.available, r0.review, r0.freshness.state], [true, null, 'never_reviewed']);
      assert.equal(track(await post(port, `/api/admin/hosts/${HOST}/review-schedule`, { interval_seconds: 3600, question: 'Has the role changed?', collectors: ['sockets.listening', 'packages.inventory'], route: 'host-review' })).status, 200);
      const r1 = track(await get(port, `/api/hosts/${HOST}/review`)).json;
      assert.deepEqual([r1.schedule.source, r1.freshness.state], ['console', 'awaiting_first_review']);
      assert.equal(track(await post(port, `/api/admin/hosts/${HOST}/review-schedule/cancel`, {})).status, 200);
      assert.equal(track(await post(port, '/api/admin/hosts/nope-9/review-schedule', { interval_seconds: 3600, question: 'q', collectors: ['sockets.listening'] })).status, 404);

      // P14 + P18: a drift opens an incident; an operator session proposes a dual-signed stop.
      await agent.push('base-sockets', 'sockets.listening', sockSnapshot([liveSocket(22, 'sshd', 'ssh.service', 101), liveSocket(4444, 'helperd', 'custom-helper.service', 202)]));
      let incident = null;
      assert.ok(await waitFor(async () => {
        incident = (await get(port, '/api/incidents')).json.incidents.find((i) => i.host_id === HOST && i.status === 'open');
        return Boolean(incident);
      }), `no incident opened:\n${stderr}`);
      const fu = track(await get(port, `/api/incidents/${incident.incident_id}/followups`)).json;
      assert.deepEqual([fu.available, fu.followups], [true, []]);
      assert.equal(track(await post(port, `/api/incidents/${incident.incident_id}/runs`, {})).status, 200);
      const ctx = track(await get(port, `/api/incidents/${incident.incident_id}`)).json;
      const ev = ctx.recent_observations.filter((o) => o.watch_id === 'base-sockets').map((o) => o.observation_id);
      const stop = (unit, ids) => post(port, `/api/incidents/${incident.incident_id}/actions`, { verb: { verb: 'systemd_stop_unit', unit, ttl_seconds: 600 }, evidence_observation_ids: ids, expected_effect: `${unit} stops`, blast_radius: 'one unit', rollback_plan: 'restart on TTL' });
      // P18 precondition: a stop must cite a current active sample of the target unit.
      const blind = track(await stop('custom-helper.service', ev.slice(0, 1)));
      assert.deepEqual([blind.json.decision.allowed, blind.json.decision.rule_id, blind.json.intent_id], [false, 'action.missing_service_precondition', null]);
      const precondition = pair.at(-1);
      const proposed = track(await stop('cron.service', [precondition]));
      assert.equal(proposed.status, 200, proposed.text);
      assert.ok(proposed.json.intent_id, proposed.text);
      const ver = track(await get(port, `/api/admin/actions/${proposed.json.intent_id}/verification`));
      assert.equal(ver.status, 200, ver.text);
      assert.deepEqual(Object.keys(ver.json).sort(), VERIFICATION_KEYS);
      assert.deepEqual([ver.json.outcome, ver.json.receipt_checks, ver.json.operator_reconciliations, ver.json.reconcile.allowed], ['no_receipt', [], [], false]);
      assert.equal(ver.json.precondition_observation_id, precondition, 'control-d bound the pre-dispatch service sample to the intent');
      assert.equal(ver.json.expected_effect, 'cron.service stops');
      const refused = track(await post(port, `/api/admin/actions/${proposed.json.intent_id}/reconcile`, { expected_receipt_id: null, evidence_ref: 'ticket', rationale: 'nothing ran' }));
      assert.equal(refused.status, 403, refused.text);
      assert.match(refused.json.error.message, /latest receipt or expired unreceipted authorization required/);
      assert.equal(track(await get(port, `/api/admin/actions/${crypto.randomUUID()}/verification`)).status, 404);

      const audit = track(await get(port, '/api/admin/audit?limit=500')).json;
      assert.equal(audit.chain.valid, true);
      assert.equal(audit.independent.valid, true, 'the console recomputes the same chain head as Rust');
      for (const op of ['set_monitoring_grant', 'corroborate_monitoring', 'rollback_monitoring']) {
        assert.ok(audit.entries.some((e) => e.event_type === 'policy_decision' && e.payload?.intent?.admin_op === op), op);
      }
      for (const text of bodies) {
        for (const t of tokens) assert.ok(!text.includes(t), 'a capability token leaked');
        assert.ok(!TOKENISH.test(text), `token-like key in ${text.slice(0, 160)}`);
      }
    } finally {
      await app.close();
    }
  });
});
