// node --test console/test/server.test.mjs
//
// 1. UDS framing roundtrip against a mock Unix socket server
// 2. Live integration against target/debug/control-d (skipped if not built)
// 3. Demo-mode API walkthrough
// 4. Security headers, Host/Origin validation and XSS hygiene

import { describe, test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import { AdminClient, FrameDecoder, FrameError, InvestigationClient, MAX_FRAME_BYTES, encodeFrame, udsRequest } from '../lib/uds-client.mjs';
import { computeAuditHash, verifyEntries } from '../lib/audit-chain.mjs';
import { createDemoBackend } from '../lib/demo-data.mjs';
import { createLiveBackend } from '../lib/live-backend.mjs';
import { createConsoleServer, parseArgs } from '../server.mjs';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const CONSOLE_DIR = path.resolve(HERE, '..');
const REPO = path.resolve(CONSOLE_DIR, '..');
const CONTROL_D = path.join(REPO, 'target', 'debug', 'control-d');
const ALL_COLLECTORS = ['sockets.listening', 'systemd.unit_state', 'files.metadata', 'journal.unit_events'];

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

function shortTmp(prefix = 'dsc-') {
  const base = os.tmpdir();
  const dir = fs.mkdtempSync(path.join(base, prefix));
  return dir;
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

  after(() => {
    child?.kill('SIGTERM');
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
    assert.deepEqual(caps.map((c) => c.collector_type), ALL_COLLECTORS);

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
