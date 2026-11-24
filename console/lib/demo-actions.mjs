// Phase 8 demo fixtures: typed mitigation intents with REAL Ed25519 envelopes
// (domain || 0x00 || RFC 8785 payload, as crates/protocol/src/signing.rs),
// the control-d state machine (pending_approval -> authorized -> executed ->
// rolled_back), the action gate's protected-asset denials, and approval rules
// mirrored from crates/control-d/src/actions.rs (independent key, payload
// binding, expiry, open incident, per-host rate limit and causal cooldown).
//
// The demo's "control" and "operator" keys are generated per process and never
// leave it; they exist only so the offline demo produces verifiable envelopes.

import crypto from 'node:crypto';
import { canonicalJson, sha256Hex } from './audit-chain.mjs';
import { ApiError, requireIdent, requireText } from './domain.mjs';

export const DOMAIN_ACTION_INTENT_V1 = 'defsecautmit.action_intent.v1';
export const DOMAIN_ACTION_APPROVAL_V1 = 'defsecautmit.action_approval.v1';
export const ACTION_SAFETY = Object.freeze({
  max_actions_per_host_per_hour: 5,
  causal_loop_cooldown_seconds: 120,
  max_autonomous_ttl_seconds: 1800,
  max_dual_signed_ttl_seconds: 86_400,
});
const MIN = 60_000;
const HOUR = 60 * MIN;
const EXEC_DELAY_MS = 4_000;
const ENVELOPE_KEYS = ['domain', 'raw_payload', 'signature_hex', 'signing_key_id'];

export function createDemoSigner() {
  const control = crypto.generateKeyPairSync('ed25519');
  const operator = crypto.generateKeyPairSync('ed25519');
  const sign = (domain, keyId, privateKey, payload) => {
    const raw_payload = canonicalJson(payload);
    const input = Buffer.concat([Buffer.from(domain, 'utf8'), Buffer.from([0]), Buffer.from(raw_payload, 'utf8')]);
    return { domain, signing_key_id: keyId, raw_payload, signature_hex: crypto.sign(null, input, privateKey).toString('hex') };
  };
  const trusted = new Map([['demo-operator-01', operator.publicKey]]);
  return {
    controlKeyId: 'control-key-01',
    operatorKeyId: 'demo-operator-01',
    signControl: (payload) => sign(DOMAIN_ACTION_INTENT_V1, 'control-key-01', control.privateKey, payload),
    signOperator: (payload) => sign(DOMAIN_ACTION_APPROVAL_V1, 'demo-operator-01', operator.privateKey, payload),
    verifyOperator(env) {
      const key = trusted.get(env.signing_key_id);
      if (!key) return `unknown signing key id: ${env.signing_key_id}`;
      const input = Buffer.concat([Buffer.from(env.domain, 'utf8'), Buffer.from([0]), Buffer.from(env.raw_payload, 'utf8')]);
      const sig = Buffer.from(env.signature_hex, 'hex');
      return sig.length === 64 && crypto.verify(null, input, key, sig) ? null : 'signature verification failed';
    },
  };
}

/** Strict SignedEnvelope check shared by the live and demo backends (deny_unknown_fields). */
export function parseOperatorApproval(value) {
  let env = value;
  if (typeof env === 'string') {
    try {
      env = JSON.parse(env);
    } catch {
      throw new ApiError(400, 'invalid_request', 'operator_approval must be a SignedEnvelope JSON object');
    }
  }
  if (!env || typeof env !== 'object' || Array.isArray(env)) throw new ApiError(400, 'invalid_request', 'operator_approval must be a SignedEnvelope JSON object');
  const keys = Object.keys(env).sort();
  if (keys.join(',') !== ENVELOPE_KEYS.join(',')) {
    throw new ApiError(400, 'invalid_request', `operator_approval must have exactly: ${ENVELOPE_KEYS.join(', ')}`);
  }
  if (env.domain !== DOMAIN_ACTION_APPROVAL_V1) throw new ApiError(400, 'invalid_request', `operator_approval.domain must be ${DOMAIN_ACTION_APPROVAL_V1}`);
  requireIdent(env.signing_key_id, 'operator_approval.signing_key_id');
  if (typeof env.raw_payload !== 'string' || !env.raw_payload || env.raw_payload.length > 64 * 1024) {
    throw new ApiError(400, 'invalid_request', 'operator_approval.raw_payload must be the canonical intent JSON string');
  }
  if (typeof env.signature_hex !== 'string' || !/^[0-9a-f]{128}$/i.test(env.signature_hex)) {
    throw new ApiError(400, 'invalid_request', 'operator_approval.signature_hex must be 128 hex characters (Ed25519)');
  }
  return { domain: env.domain, signing_key_id: env.signing_key_id, raw_payload: env.raw_payload, signature_hex: env.signature_hex.toLowerCase() };
}

/** Values derived by the console for offline signers (admin-cli signs exactly these bytes). */
export function signingInfo(payload) {
  const canonical = canonicalJson(payload);
  return { domain: DOMAIN_ACTION_APPROVAL_V1, payload_sha256: sha256Hex(canonical), canonical_payload: canonical };
}

export function summaryOf(rec) {
  const p = rec.payload;
  return {
    proposal_id: p.proposal_id,
    intent_id: p.intent_id,
    host_id: p.host_id,
    incident_id: p.incident_id,
    auth_mode: p.auth_mode,
    status: rec.status,
    verb: p.verb,
    expected_effect: rec.expected_effect,
    blast_radius: rec.blast_radius,
    rollback_plan: p.rollback_plan,
    created_at: rec.created_at,
    approver: rec.approver,
  };
}

/**
 * Build the fixture set. `ids(...keys)` resolves observation keys to IDs,
 * `iso(ago)` turns "ms ago" into an RFC 3339 string.
 */
export function buildDemoActions({ now, iso, ids, signer }) {
  const intents = [];
  const denied = [];
  const decisions = [];
  const events = [];
  let decisionId = 58;
  const R42 = 'reasoner-d:run-7f3a91c2';
  const R39 = 'reasoner-d:run-19bd04e7';
  const uuid = (seed) => {
    const hx = sha256Hex(`demo-intent-${seed}`);
    return `${hx.slice(0, 8)}-${hx.slice(8, 12)}-4${hx.slice(13, 16)}-a${hx.slice(17, 20)}-${hx.slice(20, 32)}`;
  };
  const decision = (allowed, rule_id, reason) => ({ allowed, rule_id, reason, policy_version: 1 });

  const propose = ({ proposal_id, run, actor, host, incident, ago, verb, evidence, expected_effect, blast_radius, rollback_plan, auth_mode, dec }) => {
    const created_at = iso(ago);
    decisions.push({ decision_id: decisionId++, proposal_id: null, actor, request_id: `req-${sha256Hex(`ap${proposal_id}`).slice(0, 12)}`, decision: dec, created_at });
    let rec = null;
    let status = 'rejected';
    if (auth_mode) {
      const ttl = verb.ttl_seconds ?? 900;
      const payload = {
        schema_version: 1,
        intent_id: uuid(proposal_id),
        nonce: uuid(`nonce-${proposal_id}`),
        host_id: host,
        incident_id: incident,
        proposal_id,
        auth_mode,
        verb,
        policy_version: 1,
        issued_at: created_at,
        expires_at: new Date(Date.parse(created_at) + ttl * 1000).toISOString(),
        rollback_plan,
        evidence_observation_ids: evidence,
      };
      status = auth_mode === 'policy_bounded_autonomous' ? 'authorized' : 'pending_approval';
      rec = {
        payload,
        control_envelope: signer.signControl(payload),
        operator_approval: null,
        status,
        approver: null,
        expected_effect,
        blast_radius,
        created_at,
        updated_at: created_at,
        receipts: [],
        execute_at: null,
      };
      intents.push(rec);
    } else {
      denied.push({ proposal_id, host_id: host, incident_id: incident, verb, decision: dec, expected_effect, blast_radius, rollback_plan, evidence_observation_ids: evidence, actor, created_at });
    }
    events.push({
      ago,
      event_type: 'action_proposed',
      actor,
      payload: {
        proposal_id, run_id: run, host_id: host, incident_id: incident, intent_id: rec?.payload.intent_id ?? null, auth_mode: auth_mode ?? null,
        verb, evidence_observation_ids: evidence, expected_effect, blast_radius, rollback_plan, decision: dec, status,
      },
    });
    return rec;
  };

  const receipt = (rec, ago, status, extra) => {
    const r = {
      intent_id: rec.payload.intent_id,
      host_id: rec.payload.host_id,
      nonce: rec.payload.nonce,
      status,
      dry_run: false,
      executed_at: iso(ago),
      expires_at: null,
      rollback_handle: null,
      verification_passed: true,
      detail: '',
      ...extra,
    };
    rec.receipts.push(r);
    rec.status = status;
    rec.updated_at = r.executed_at;
    events.push({ ago, event_type: status === 'rolled_back' ? 'action_rolled_back' : 'action_receipt_recorded', actor: 'admin', payload: r });
    return r;
  };

  // --- inc-2026-0039 · edge-vm-03 ------------------------------------------
  const p0 = propose({
    proposal_id: 1, run: 'run-19bd04e7', actor: R39, host: 'edge-vm-03', incident: 'inc-2026-0039', ago: 2 * HOUR + 45 * MIN,
    verb: { verb: 'nft_block_ip', ip: '198.51.100.23', direction: 'inbound', ttl_seconds: 600 },
    evidence: ids('v3_conf_2'),
    expected_effect: 'Drop inbound traffic from 198.51.100.23, the SSH peer active when nginx.conf changed, for 10 minutes.',
    blast_radius: 'Single external /32 on edge-vm-03; management and RFC 1918 ranges are protected by the gate.',
    rollback_plan: 'Rule auto-expires after 600 s; action-exec-d deletes the nft handle and verifies removal.',
    auth_mode: 'policy_bounded_autonomous',
    dec: decision(true, 'action.autonomous_authorized', "verb 'nft_block_ip' meets human-owned bounded autonomous containment policy"),
  });
  receipt(p0, 2 * HOUR + 34 * MIN, 'expired', {
    verification_passed: false,
    detail: 'intent expires_at elapsed before local execution (action-exec-d restarted during the CHG-4471 window); nothing applied',
  });

  // --- inc-2026-0042 · edge-vm-07 ------------------------------------------
  const blockEffect = 'Drop outbound traffic from edge-vm-07 to 203.0.113.47, the endpoint helperd checks in with.';
  const blockRadius = 'Single external /32 on one host; no service restarts; protected CIDRs and units untouched.';
  const p1 = propose({
    proposal_id: 2, run: 'run-7f3a91c2', actor: R42, host: 'edge-vm-07', incident: 'inc-2026-0042', ago: 37 * MIN,
    verb: { verb: 'nft_block_ip', ip: '203.0.113.47', direction: 'outbound', ttl_seconds: 600 },
    evidence: ids('sock_new', 'journal_1'),
    expected_effect: blockEffect,
    blast_radius: blockRadius,
    rollback_plan: 'Rule auto-expires after 600 s; action-exec-d deletes the nft handle and verifies removal.',
    auth_mode: 'policy_bounded_autonomous',
    dec: decision(true, 'action.autonomous_authorized', "verb 'nft_block_ip' meets human-owned bounded autonomous containment policy"),
  });
  const r1 = receipt(p1, 37 * MIN - 10_000, 'executed', {
    expires_at: iso(37 * MIN - 10_000 - 600_000),
    rollback_handle: 'nft:inet defsec_contain out_block handle 17',
    detail: 'nft rule inserted; verified present in ruleset (1 match)',
  });
  receipt(p1, 27 * MIN - 8_000, 'rolled_back', {
    expires_at: r1.expires_at,
    rollback_handle: r1.rollback_handle,
    detail: 'TTL elapsed; nft handle 17 deleted and verified absent',
  });

  const p2 = propose({
    proposal_id: 3, run: 'run-7f3a91c2', actor: R42, host: 'edge-vm-07', incident: 'inc-2026-0042', ago: 6 * MIN,
    verb: { verb: 'nft_block_ip', ip: '203.0.113.47', direction: 'outbound', ttl_seconds: 1800 },
    evidence: ids('units_f3', 'unit_u2', 'journal_2'),
    expected_effect: `${blockEffect} Re-applied after the unit file added a 300 s beacon.`,
    blast_radius: blockRadius,
    rollback_plan: 'Rule auto-expires after 1800 s; action-exec-d deletes the nft handle and verifies removal.',
    auth_mode: 'policy_bounded_autonomous',
    dec: decision(true, 'action.autonomous_authorized', "verb 'nft_block_ip' meets human-owned bounded autonomous containment policy"),
  });
  receipt(p2, 6 * MIN - 9_000, 'executed', {
    expires_at: iso(6 * MIN - 9_000 - 1_800_000),
    rollback_handle: 'nft:inet defsec_contain out_block handle 23',
    detail: 'nft rule inserted; verified present in ruleset (1 match)',
  });

  propose({
    proposal_id: 4, run: 'run-7f3a91c2', actor: R42, host: 'edge-vm-07', incident: 'inc-2026-0042', ago: 5 * MIN,
    verb: { verb: 'systemd_stop_unit', unit: 'ssh.service', ttl_seconds: 1800 },
    evidence: ids('sock_new'),
    expected_effect: 'Stop ssh.service to cut a possible interactive foothold.',
    blast_radius: 'Would remove remote administration from edge-vm-07.',
    rollback_plan: 'systemctl start ssh.service after TTL.',
    auth_mode: null,
    dec: decision(false, 'action.protected_unit', "unit 'ssh.service' is protected and cannot be stopped"),
  });

  propose({
    proposal_id: 5, run: 'run-7f3a91c2', actor: R42, host: 'edge-vm-07', incident: 'inc-2026-0042', ago: 4 * MIN,
    verb: { verb: 'systemd_stop_unit', unit: 'custom-helper.service', ttl_seconds: 3600 },
    evidence: ids('sock_new', 'unit_u1', 'units_f3'),
    expected_effect: 'Stop custom-helper.service so helperd releases tcp/4444 and stops beaconing; the unit stays stopped for 1 h.',
    blast_radius: 'One non-protected unit on edge-vm-07; nginx and sshd keep running.',
    rollback_plan: 'action-exec-d restarts custom-helper.service when the 3600 s TTL elapses, unless the incident is resolved first.',
    auth_mode: 'dual_signed_operator',
    dec: decision(true, 'action.pending_dual_approval', "verb 'systemd_stop_unit' requires independent operator Ed25519 approval signature"),
  });

  propose({
    proposal_id: 6, run: 'run-7f3a91c2', actor: R42, host: 'edge-vm-07', incident: 'inc-2026-0042', ago: 3 * MIN,
    verb: { verb: 'host_isolate', preserve_mgmt_cidrs: ['10.20.0.0/24', '10.20.8.15/32'], ttl_seconds: 7200 },
    evidence: ids('sock_latest', 'unit_u2', 'journal_2'),
    expected_effect: 'Isolate edge-vm-07 from all networks except the management subnet and the jump host while helperd is analysed.',
    blast_radius: 'All public traffic to edge-vm-07 (nginx on 443) stops for up to 2 h; management access is preserved.',
    rollback_plan: 'action-exec-d removes the isolation table when the 7200 s TTL elapses and verifies egress is restored.',
    auth_mode: 'dual_signed_operator',
    dec: decision(true, 'action.pending_dual_approval', "verb 'host_isolate' requires independent operator Ed25519 approval signature"),
  });

  propose({
    proposal_id: 7, run: 'run-7f3a91c2', actor: 'operator:t3-mcp-session', host: 'edge-vm-07', incident: 'inc-2026-0042', ago: 2 * MIN,
    verb: { verb: 'nft_block_ip', ip: '10.20.0.5', direction: 'both', ttl_seconds: 600 },
    evidence: ids('sock_latest'),
    expected_effect: 'Block the internal peer seen near the helper restart.',
    blast_radius: 'Would cut a management-subnet address.',
    rollback_plan: 'Rule auto-expires after 600 s.',
    auth_mode: null,
    dec: decision(false, 'action.protected_ip', "IP '10.20.0.5' falls inside protected CIDR '10.0.0.0/8'"),
  });

  return { intents, denied, decisions, events, nextProposalId: 8 };
}

/**
 * Lazy simulation of action-exec-d: approved intents execute shortly after
 * approval, and executed intents roll back when their TTL elapses.
 */
export function advanceDemoActions(S, nowMs, appendAudit) {
  // Audit timestamps stay monotonic even when a transition is applied lazily.
  const stamp = (iso) => new Date(Math.max(Date.parse(iso), Date.parse(S.audit.at(-1)?.timestamp ?? iso))).toISOString();
  for (const rec of S.actions.intents) {
    if (rec.status === 'authorized' && rec.execute_at && rec.execute_at <= nowMs) {
      const at = new Date(rec.execute_at).toISOString();
      const ttl = rec.payload.verb.ttl_seconds;
      const r = {
        intent_id: rec.payload.intent_id,
        host_id: rec.payload.host_id,
        nonce: rec.payload.nonce,
        status: 'executed',
        dry_run: false,
        executed_at: at,
        expires_at: ttl ? new Date(rec.execute_at + ttl * 1000).toISOString() : null,
        rollback_handle: rec.payload.verb.verb === 'host_isolate' ? 'nft:inet defsec_isolate table' : rec.payload.verb.verb === 'systemd_stop_unit' ? `systemd:${rec.payload.verb.unit}` : 'nft:inet defsec_contain handle 31',
        verification_passed: true,
        detail: 'dual signature verified (control + operator); applied and verified by action-exec-d',
      };
      rec.receipts.push(r);
      rec.status = 'executed';
      rec.updated_at = at;
      rec.execute_at = null;
      appendAudit(S.audit, 'action_receipt_recorded', 'admin', r, stamp(at));
    }
    const last = rec.receipts.at(-1);
    if (rec.status === 'executed' && last?.expires_at && Date.parse(last.expires_at) <= nowMs) {
      const r = { ...last, status: 'rolled_back', executed_at: last.expires_at, detail: 'TTL elapsed; containment removed and verified absent' };
      rec.receipts.push(r);
      rec.status = 'rolled_back';
      rec.updated_at = r.executed_at;
      appendAudit(S.audit, 'action_rolled_back', 'admin', r, stamp(r.executed_at));
    }
  }
}

/** Mirror of ControlService::approve_action for the demo backend. */
export function approveDemoAction(S, { intentId, body, signer, nowMs, incidentOpen, appendAudit }) {
  requireIdent(intentId, 'intent_id');
  const approver = requireText(body?.approver, 'approver', 128);
  const rec = S.actions.intents.find((r) => r.payload.intent_id === intentId);
  if (!rec) throw new ApiError(404, 'not_found', 'action intent not found');
  if (rec.status !== 'pending_approval' || rec.payload.auth_mode !== 'dual_signed_operator') {
    throw new ApiError(403, 'forbidden', 'action intent is not pending dual approval');
  }
  if (Date.parse(rec.payload.expires_at) <= nowMs || !incidentOpen(rec.payload.incident_id)) {
    throw new ApiError(403, 'forbidden', 'action intent expired or its incident is closed');
  }
  let approval;
  if (body?.operator_approval !== undefined && body?.operator_approval !== null) {
    approval = parseOperatorApproval(body.operator_approval);
    if (approval.raw_payload !== rec.control_envelope.raw_payload) throw new ApiError(403, 'forbidden', 'operator approval payload differs from control intent');
    if (approval.signing_key_id === signer.controlKeyId) throw new ApiError(403, 'forbidden', 'operator approval requires an independent signing key');
    const err = signer.verifyOperator(approval);
    if (err) throw new ApiError(403, 'forbidden', `invalid operator approval: ${err}`);
  } else {
    approval = signer.signOperator(rec.payload);
  }
  const hourAgo = nowMs - HOUR;
  const acted = S.actions.intents.filter((r) => r.payload.host_id === rec.payload.host_id && r.status !== 'pending_approval');
  const lastAt = Math.max(-Infinity, ...acted.map((r) => Date.parse(r.updated_at)));
  if (acted.filter((r) => Date.parse(r.updated_at) > hourAgo).length >= ACTION_SAFETY.max_actions_per_host_per_hour || nowMs - lastAt < ACTION_SAFETY.causal_loop_cooldown_seconds * 1000) {
    throw new ApiError(403, 'forbidden', 'host action rate limit or cooldown is active');
  }
  const at = new Date(nowMs).toISOString();
  rec.status = 'authorized';
  rec.operator_approval = approval;
  rec.approver = approver;
  rec.updated_at = at;
  rec.execute_at = nowMs + EXEC_DELAY_MS;
  const note = typeof body?.note === 'string' && body.note.trim() ? body.note.slice(0, 1024) : undefined;
  appendAudit(S.audit, 'action_approved', approver, {
    intent_id: intentId,
    host_id: rec.payload.host_id,
    incident_id: rec.payload.incident_id,
    operator_key_id: approval.signing_key_id,
    payload_digest: sha256Hex(approval.raw_payload),
    ...(note ? { note } : {}),
  }, at);
  return { intent_id: intentId, authorized_intent: { control_envelope: rec.control_envelope, operator_approval: approval } };
}

export const DEMO_EXEC_DELAY_MS = EXEC_DELAY_MS;
