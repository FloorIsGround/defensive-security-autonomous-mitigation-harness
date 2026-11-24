// Live backend: every read and mutation flows through control-d's Unix
// sockets. The console never opens SQLite and never talks to edge agents.

import { performance } from 'node:perf_hooks';
import { AdminClient, InvestigationClient } from './uds-client.mjs';
import { verifyEntries } from './audit-chain.mjs';
import { parseOperatorApproval, signingInfo } from './demo-actions.mjs';
import {
  ApiError,
  buildWatchSpec,
  deriveThreeState,
  int,
  parseFindingBody,
  requireIdent,
  requireText,
} from './domain.mjs';

const CODE_STATUS = { forbidden: 403, invalid_request: 400, not_found: 404 };

function transportError(err) {
  if (err instanceof ApiError) return err;
  const msg = String(err?.message ?? err);
  if (/closed before a response/.test(msg)) {
    return new ApiError(502, 'control_rejected_frame', 'control-d closed the connection without a response (frame rejected)');
  }
  return new ApiError(503, 'control_unreachable', `control-d socket unreachable: ${err?.code ?? msg}`);
}

function unwrap(resp, tag, expected) {
  if (!resp || typeof resp !== 'object') throw new ApiError(502, 'unexpected_response', 'empty response from control-d');
  if (resp[tag] === 'error') {
    throw new ApiError(CODE_STATUS[resp.code] ?? 502, resp.code ?? 'control_error', resp.message ?? 'control-d error');
  }
  if (resp[tag] !== expected) {
    throw new ApiError(502, 'unexpected_response', `expected ${expected}, got ${resp[tag]}`);
  }
  return resp;
}

export function createLiveBackend({ investigateSock, token, adminSock = null, enableAdmin = false, timeoutMs = 5000 }) {
  const inv = new InvestigationClient({ socketPath: investigateSock, token, timeoutMs });
  const admin = enableAdmin && adminSock ? new AdminClient({ socketPath: adminSock, timeoutMs }) : null;
  // incident_id -> run metadata started through this console process.
  const runs = new Map();

  async function invCall(request, expected) {
    let resp;
    try {
      resp = await inv.call(request);
    } catch (err) {
      throw transportError(err);
    }
    return unwrap(resp, 'result', expected);
  }

  async function adminCall(request, expected) {
    if (!admin) throw new ApiError(403, 'admin_disabled', 'admin interface is disabled (start the console with --enable-admin --admin-sock)');
    let resp;
    try {
      resp = await admin.call(request);
    } catch (err) {
      throw transportError(err);
    }
    return unwrap(resp, 'admin_result', expected);
  }

  async function probe(fn) {
    const t0 = performance.now();
    try {
      const value = await fn();
      return { reachable: true, authorized: true, latency_ms: Math.round(performance.now() - t0), value };
    } catch (err) {
      const e = transportError(err);
      return {
        reachable: e.status !== 503,
        authorized: e.status !== 403,
        latency_ms: Math.round(performance.now() - t0),
        error: { code: e.code, message: e.message },
      };
    }
  }

  async function incidentSummary(incidentId) {
    const ctx = await invCall({ op: 'get_incident_context', incident_id: incidentId }, 'incident_context');
    return ctx.incident;
  }

  function resolveRun(incidentId, body) {
    const runId = body?.run_id ?? runs.get(incidentId)?.run_id;
    if (!runId) throw new ApiError(409, 'run_required', 'start an investigation run for this incident first');
    return runId;
  }

  /** Rejected action proposals never get an intent row; their full context lives in the audit log. */
  function deniedFromAudit(entries, match) {
    return entries
      .filter((e) => e.event_type === 'action_proposed' && e.payload?.decision && e.payload.decision.allowed === false)
      .map((e) => ({
        proposal_id: e.payload.proposal_id ?? null,
        host_id: e.payload.host_id,
        incident_id: e.payload.incident_id,
        verb: e.payload.verb,
        decision: e.payload.decision,
        expected_effect: e.payload.expected_effect ?? '',
        blast_radius: e.payload.blast_radius ?? '',
        rollback_plan: e.payload.rollback_plan ?? '',
        evidence_observation_ids: e.payload.evidence_observation_ids ?? [],
        actor: e.actor,
        created_at: e.timestamp,
      }))
      .filter(match)
      .sort((a, b) => (b.proposal_id ?? 0) - (a.proposal_id ?? 0));
  }

  return {
    mode: 'live',
    adminEnabled: Boolean(admin),

    async status() {
      const investigate = await probe(() => invCall({ op: 'list_hosts', limit: 1 }, 'hosts'));
      delete investigate.value;
      let audit = null;
      let adminSocket = { configured: Boolean(adminSock), enabled: Boolean(admin) };
      if (admin) {
        const p = await probe(() => adminCall({ admin_op: 'verify_audit_chain' }, 'audit_chain_status'));
        adminSocket = { ...adminSocket, reachable: p.reachable, latency_ms: p.latency_ms, error: p.error };
        if (p.value) {
          const { valid, entries_checked, latest_hash = null, error = null } = p.value;
          audit = { valid, entries_checked, latest_hash, error };
        }
      }
      return {
        mode: 'live',
        admin_enabled: Boolean(admin),
        sockets: { investigate: { configured: true, ...investigate }, admin: adminSocket },
        audit,
        server_time: new Date().toISOString(),
      };
    },

    async hosts() {
      const r = await invCall({ op: 'list_hosts', limit: 500 }, 'hosts');
      return { hosts: r.hosts };
    },

    async watches(hostId) {
      requireIdent(hostId, 'host_id');
      const r = await invCall({ op: 'list_active_watches', host_id: hostId }, 'watches');
      return { host_id: hostId, watches: r.watches };
    },

    async capabilities(hostId) {
      requireIdent(hostId, 'host_id');
      const r = await invCall({ op: 'list_collector_capabilities', host_id: hostId }, 'capabilities');
      return { host_id: hostId, capabilities: r.capabilities };
    },

    async baselines(hostId) {
      requireIdent(hostId, 'host_id');
      const [b, w, o] = await Promise.all([
        invCall({ op: 'get_host_baseline_summary', host_id: hostId }, 'baseline_summary'),
        invCall({ op: 'list_active_watches', host_id: hostId }, 'watches'),
        invCall({ op: 'query_observations', host_id: hostId, limit: 500 }, 'observations'),
      ]);
      return {
        host_id: hostId,
        baselines: b.baselines,
        three_state: deriveThreeState(w.watches, b.baselines, o.observations),
      };
    },

    async observations(hostId, { watch_id = null, limit = null } = {}) {
      requireIdent(hostId, 'host_id');
      const request = { op: 'query_observations', host_id: hostId };
      if (watch_id) request.watch_id = requireIdent(watch_id, 'watch_id');
      if (limit !== null) request.limit = int(limit, 'limit', { min: 1, max: 1000 });
      const r = await invCall(request, 'observations');
      return { host_id: hostId, observations: r.observations };
    },

    async incidents() {
      const r = await invCall({ op: 'list_active_incidents', limit: 200 }, 'incidents');
      let incidents = r.incidents;
      if (admin) {
        // Admin view also surfaces closed incidents for history.
        try {
          const all = await adminCall({ admin_op: 'list_incidents' }, 'incidents');
          const seen = new Set(incidents.map((i) => i.incident_id));
          incidents = incidents.concat(all.incidents.filter((i) => !seen.has(i.incident_id)));
        } catch {
          /* fall back to scoped view */
        }
      }
      return { incidents };
    },

    async incident(incidentId) {
      requireIdent(incidentId, 'incident_id');
      const r = await invCall({ op: 'get_incident_context', incident_id: incidentId }, 'incident_context');
      return {
        incident: r.incident,
        active_watches: r.active_watches,
        recent_observations: r.recent_observations,
        findings: r.findings,
        run: runs.get(incidentId) ?? null,
      };
    },

    async startRun(incidentId, body = {}) {
      requireIdent(incidentId, 'incident_id');
      const r = await invCall(
        {
          op: 'start_investigation_run',
          incident_id: incidentId,
          backend_id: requireText(body.backend_id ?? 'operator-console', 'backend_id', 128),
          model_id: requireText(body.model_id ?? 'human-operator', 'model_id', 128),
          prompt_schema_version: requireText(body.prompt_schema_version ?? 'console.v1', 'prompt_schema_version', 128),
        },
        'run_started',
      );
      const run = { run_id: r.run_id, incident_id: r.incident_id, expires_at: r.expires_at };
      runs.set(incidentId, run);
      return run;
    },

    async propose(incidentId, body = {}) {
      requireIdent(incidentId, 'incident_id');
      const runId = resolveRun(incidentId, body);
      const incident = await incidentSummary(incidentId);
      const spec = buildWatchSpec(body, incident);
      const r = await invCall(
        {
          op: 'propose_ephemeral_watch',
          run_id: runId,
          idempotency_key: requireText(body.idempotency_key ?? `console-${spec.id}`, 'idempotency_key', 128),
          spec,
          rationale: requireText(body.rationale, 'rationale', 4096),
        },
        'proposal_evaluated',
      );
      return { decision: r.decision, watch_id: r.watch_id ?? null, bundle_version: r.bundle_version ?? null, spec };
    },

    async recordFinding(incidentId, body = {}) {
      requireIdent(incidentId, 'incident_id');
      const f = parseFindingBody(body, incidentId);
      f.run_id = resolveRun(incidentId, f);
      const r = await invCall({ op: 'record_hypothesis_or_finding', ...f }, 'finding_recorded');
      return { finding_id: r.finding_id, verified_evidence_count: r.verified_evidence_count };
    },

    async audit({ limit = 200 } = {}) {
      const lim = int(limit, 'limit', { min: 1, max: 500 });
      const chain = await adminCall({ admin_op: 'verify_audit_chain' }, 'audit_chain_status');
      const list = await adminCall({ admin_op: 'list_audit_entries', limit: lim }, 'audit_entries');
      return {
        chain: { valid: chain.valid, entries_checked: chain.entries_checked, latest_hash: chain.latest_hash ?? null, error: chain.error ?? null },
        independent: verifyEntries(list.entries),
        entries: list.entries,
      };
    },

    async policyDecisions({ limit = 200 } = {}) {
      const lim = int(limit, 'limit', { min: 1, max: 500 });
      const r = await adminCall({ admin_op: 'list_policy_decisions', limit: lim }, 'policy_decisions');
      return { decisions: r.decisions };
    },

    async promoteBaseline(body = {}) {
      const request = {
        admin_op: 'promote_baseline',
        host_id: requireIdent(body.host_id, 'host_id'),
        watch_id: requireIdent(body.watch_id, 'watch_id'),
        observation_id: int(body.observation_id, 'observation_id', { min: 1 }),
        approver: requireText(body.approver, 'approver', 256),
        rationale: requireText(body.rationale, 'rationale', 4096),
      };
      const ticket = requireText(body.ticket_ref, 'ticket_ref', 256, { optional: true });
      if (ticket) request.ticket_ref = ticket;
      const r = await adminCall(request, 'baseline_promoted');
      return { revision_id: r.revision_id, host_id: r.host_id, watch_id: r.watch_id, state_hash: r.state_hash };
    },

    async closeIncident(incidentId, body = {}) {
      const r = await adminCall(
        {
          admin_op: 'close_incident',
          incident_id: requireIdent(incidentId, 'incident_id'),
          actor: requireText(body.actor, 'actor', 256),
          resolution: requireText(body.resolution, 'resolution', 4096),
        },
        'incident_closed',
      );
      runs.delete(incidentId);
      return { incident_id: r.incident_id, retired_ephemeral_watches: r.retired_ephemeral_watches };
    },

    // ---- Phase 8 mitigations -------------------------------------------------

    async actions({ host_id = null, incident_id = null } = {}) {
      const filter = {
        host_id: host_id === null ? null : requireIdent(host_id, 'host_id'),
        incident_id: incident_id === null ? null : requireIdent(incident_id, 'incident_id'),
      };
      const match = (x) => (!filter.host_id || x.host_id === filter.host_id) && (!filter.incident_id || x.incident_id === filter.incident_id);
      let actions;
      let source;
      if (admin) {
        // The admin interface sees every intent; the investigation socket only
        // lists actions for an incident-scoped capability.
        actions = (await adminCall({ admin_op: 'list_actions', ...filter }, 'actions')).actions;
        source = 'admin';
      } else {
        actions = (await invCall({ op: 'list_actions', ...filter }, 'actions')).actions;
        source = 'investigate';
      }
      let denied = null;
      if (admin) {
        try {
          const list = await adminCall({ admin_op: 'list_audit_entries', limit: 500 }, 'audit_entries');
          denied = deniedFromAudit(list.entries, match);
        } catch {
          denied = null;
        }
      }
      return { source, actions, denied, admin_sock: adminSock };
    },

    async actionDetail(intentId) {
      requireIdent(intentId, 'intent_id');
      const r = await adminCall({ admin_op: 'get_action_intent', intent_id: intentId }, 'action_intent_detail');
      const [list, audit] = await Promise.allSettled([
        adminCall({ admin_op: 'list_actions', host_id: r.payload.host_id, incident_id: r.payload.incident_id }, 'actions'),
        adminCall({ admin_op: 'list_audit_entries', limit: 500 }, 'audit_entries'),
      ]);
      const summary = list.status === 'fulfilled' ? list.value.actions.find((a) => a.intent_id === intentId) ?? null : null;
      const receipts =
        audit.status === 'fulfilled'
          ? audit.value.entries
              .filter((e) => (e.event_type === 'action_receipt_recorded' || e.event_type === 'action_rolled_back') && e.payload?.intent_id === intentId)
              .sort((a, b) => a.seq_no - b.seq_no)
              .map((e) => e.payload)
          : [];
      return {
        payload: r.payload,
        authorized_intent: r.authorized_intent ?? null,
        status: r.status,
        summary,
        receipts,
        signing: signingInfo(r.payload),
        admin_sock: adminSock,
      };
    },

    async approveAction(intentId, body = {}) {
      requireIdent(intentId, 'intent_id');
      const approver = requireText(body.approver, 'approver', 128);
      if (body.operator_approval === undefined || body.operator_approval === null) {
        throw new ApiError(400, 'invalid_request', 'operator_approval (an offline-signed SignedEnvelope) is required; private keys never reach the console');
      }
      const operator_approval = parseOperatorApproval(body.operator_approval);
      const r = await adminCall({ admin_op: 'approve_action', intent_id: intentId, approver, operator_approval }, 'action_approved');
      return { intent_id: r.intent_id, authorized_intent: r.authorized_intent };
    },

    async enrollHost(body = {}) {
      const key = body.agent_public_key_hex ? String(body.agent_public_key_hex).trim() : null;
      if (key !== null && !/^[0-9a-fA-F]{64}$/.test(key)) {
        throw new ApiError(400, 'invalid_request', 'agent_public_key_hex must be 64 hex characters');
      }
      const r = await adminCall(
        { admin_op: 'enroll_host', host_id: requireIdent(body.host_id, 'host_id'), agent_public_key_hex: key },
        'host_enrolled',
      );
      return {
        host_id: r.host_id,
        control_signing_key_id: r.control_signing_key_id,
        control_public_key_hex: r.control_public_key_hex,
      };
    },
  };
}
