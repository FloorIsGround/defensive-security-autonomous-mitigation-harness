// Live backend: every read and mutation flows through control-d's Unix
// sockets. The console never opens SQLite and never talks to edge agents.

import { performance } from 'node:perf_hooks';
import { AdminClient, InvestigationClient } from './uds-client.mjs';
import { verifyEntries } from './audit-chain.mjs';
import { parseOperatorApproval, signingInfo } from './demo-actions.mjs';
import {
  ADAPTIVE_UNSUPPORTED_MESSAGE,
  ADMIN_VIEW_MESSAGE,
  DISCOVERY_COLLECTORS,
  MONITORING_AUDIT_WINDOW,
  buildCoverage,
  deriveMonitoring,
  discoverySourceIds,
  findingIndex,
  parseAssessmentVersion,
  parseCandidateId,
  parseCorroborateBody,
  parseGrantBody,
  parseReconcileBody,
  parseRollbackBody,
  parseScheduleBody,
  publicAssessment,
  publicAttempt,
  publicFollowup,
  publicHostProfile,
  publicReview,
  publicSample,
  publicVerification,
  reviewFreshness,
  supportsDiscovery,
} from './adaptive.mjs';
import {
  ApiError,
  COLLECTOR_TYPES,
  REASONER_UNSUPPORTED_MESSAGE,
  RULES_UNSUPPORTED_MESSAGE,
  automationSummary,
  buildIncidentChanges,
  buildWatchSpec,
  deriveThreeState,
  int,
  isRuleGateCode,
  isStreamWatch,
  parseActionBody,
  parseEventsQuery,
  parseFindingBody,
  parseRuleBody,
  parseRuleDecision,
  parseRuleId,
  parseRuleRevoke,
  parseRulesQuery,
  parseRunsQuery,
  parseTriggersQuery,
  publicBacktest,
  publicRuleRecord,
  publicRuleSuppression,
  publicRunEvent,
  publicRunSummary,
  publicTrigger,
  requireIdent,
  requireText,
} from './domain.mjs';

const CODE_STATUS = { forbidden: 403, invalid_request: 400, not_found: 404, conflict: 409 };

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

const RUN_TOKEN_TTL_SECONDS = 3600;
/** AdvanceHostDiscovery needs an unbound, host-scoped investigator grant; it lives only for one call. */
const DISCOVERY_TOKEN_TTL_SECONDS = 300;

/**
 * A control-d from before Phase 9 cannot deserialize the new ops: it closes
 * the connection without a reply (control_rejected_frame), or a future build
 * may answer with an "unknown variant" error. Either way the console degrades
 * to "not available" instead of failing the page.
 */
function unsupportedOp(err) {
  if (!(err instanceof ApiError)) return false;
  if (err.code === 'control_rejected_frame') return true;
  return /unknown (variant|op)|unsupported (op|request)/i.test(err.message ?? '');
}

function unavailable(err, message = REASONER_UNSUPPORTED_MESSAGE) {
  if (unsupportedOp(err)) return { available: false, reason: 'unsupported', message };
  if (err instanceof ApiError && err.status === 403) return { available: false, reason: 'forbidden', message: err.message };
  return null;
}

export function createLiveBackend({ investigateSock, token, adminSock = null, enableAdmin = false, timeoutMs = 5000 }) {
  // The shared browse token is only ever used for reads. StartInvestigationRun
  // permanently narrows the calling token to one run/incident/host inside
  // control-d, so every run gets its own freshly minted, incident-scoped token.
  const inv = new InvestigationClient({ socketPath: investigateSock, token, timeoutMs });
  const admin = enableAdmin && adminSock ? new AdminClient({ socketPath: adminSock, timeoutMs }) : null;
  // incident_id -> { run_id, incident_id, host_id, expires_at, client }. The
  // client holds the per-run token in a private field; it never leaves this map.
  const runs = new Map();
  // control-d has no read for review schedules: remember what this console set
  // (host_id -> { schedule, set_at, set_by }) so the UI can say so honestly.
  const schedules = new Map();

  async function clientCall(client, request, expected) {
    let resp;
    try {
      resp = await client.call(request);
    } catch (err) {
      throw transportError(err);
    }
    return unwrap(resp, 'result', expected);
  }

  const invCall = (request, expected) => clientCall(inv, request, expected);

  /**
   * Admin reads are fleet-wide, so a host-scoped route asks the browse token
   * first: an out-of-scope host is a 403 before any admin data is fetched. Any
   * other failure also refuses, since visibility could not be established.
   */
  async function requireVisibleHost(hostId) {
    try {
      return await invCall({ op: 'list_active_watches', host_id: hostId }, 'watches');
    } catch (err) {
      if (err instanceof ApiError && err.status === 403) throw new ApiError(403, 'forbidden', err.message || `host '${hostId}' is outside this console's scope`);
      throw err;
    }
  }
  const publicRun = (r) => (r ? { run_id: r.run_id, incident_id: r.incident_id, expires_at: r.expires_at } : null);

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

  /** The live per-run entry (and its dedicated client) for an incident. */
  function resolveRun(incidentId, runId = null) {
    const run = runs.get(incidentId);
    if (!run) throw new ApiError(409, 'run_required', 'start an operator session for this incident first');
    if (runId && runId !== run.run_id) throw new ApiError(409, 'run_mismatch', 'run_id does not match the active operator session for this incident');
    if (Date.parse(run.expires_at) <= Date.now()) {
      runs.delete(incidentId);
      throw new ApiError(409, 'run_required', 'the operator session expired; start a new one');
    }
    return run;
  }

  async function auditEntries(limit = 500) {
    return (await adminCall({ admin_op: 'list_audit_entries', limit }, 'audit_entries')).entries;
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

  async function ruleGateCall(request, expected) {
    if (!admin) throw new ApiError(403, 'admin_disabled', 'admin interface is disabled (start the console with --enable-admin --admin-sock)');
    let resp;
    try {
      resp = await admin.call(request);
    } catch (err) {
      throw transportError(err);
    }
    if (resp?.admin_result === 'error' && isRuleGateCode(resp.code)) {
      // Older control-d versions still provide the code and reason.
      return { denied: resp.decision ?? { allowed: false, rule_id: resp.code, reason: resp.message ?? '', policy_version: null } };
    }
    return { value: unwrap(resp, 'admin_result', expected) };
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
      // HostSummary carries no watch count; ask control-d per host (bounded fan-out).
      const counts = await Promise.allSettled(r.hosts.map((h) => invCall({ op: 'list_active_watches', host_id: h.host_id }, 'watches')));
      return {
        hosts: r.hosts.map((h, i) => {
          const w = counts[i].status === 'fulfilled' ? counts[i].value.watches : null;
          return w
            ? { ...h, watch_count: w.length, baseline_watch_count: w.filter((x) => x.class === 'baseline').length, stream_watch_count: w.filter((x) => isStreamWatch(x)).length }
            : { ...h, watch_count: null };
        }),
      };
    },

    async watches(hostId) {
      requireIdent(hostId, 'host_id');
      const r = await invCall({ op: 'list_active_watches', host_id: hostId }, 'watches');
      return { host_id: hostId, watches: r.watches };
    },

    async capabilities(hostId) {
      requireIdent(hostId, 'host_id');
      try {
        const r = await invCall({ op: 'list_collector_capabilities', host_id: hostId }, 'capabilities');
        return { available: true, host_id: hostId, capabilities: r.capabilities };
      } catch (err) {
        // An older control-d closes the connection on an op it cannot decode; an
        // out-of-scope host stays a 403 so scope errors are never masked.
        if (!unsupportedOp(err)) throw err;
        return { available: false, reason: 'unsupported', message: ADAPTIVE_UNSUPPORTED_MESSAGE, host_id: hostId, capabilities: [] };
      }
    },

    async baselines(hostId) {
      requireIdent(hostId, 'host_id');
      let b, w, o;
      try {
        [b, w, o] = await Promise.all([
          invCall({ op: 'get_host_baseline_summary', host_id: hostId }, 'baseline_summary'),
          invCall({ op: 'list_active_watches', host_id: hostId }, 'watches'),
          invCall({ op: 'query_observations', host_id: hostId, limit: 500 }, 'observations'),
        ]);
      } catch (err) {
        if (!unsupportedOp(err)) throw err;
        return { available: false, reason: 'unsupported', message: 'baseline summaries are not supported by this control-d', host_id: hostId, baselines: [], three_state: [] };
      }
      return {
        available: true,
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
        rule_suppression: publicRuleSuppression(r.rule_suppression),
        run: publicRun(runs.has(incidentId) && Date.parse(runs.get(incidentId).expires_at) > Date.now() ? runs.get(incidentId) : null),
      };
    },

    async startRun(incidentId, body = {}) {
      requireIdent(incidentId, 'incident_id');
      const backend_id = requireText(body.backend_id ?? 'operator-console', 'backend_id', 128);
      const model_id = requireText(body.model_id ?? 'human-operator', 'model_id', 128);
      const prompt_schema_version = requireText(body.prompt_schema_version ?? 'console.v1', 'prompt_schema_version', 128);
      if (!admin) {
        throw new ApiError(
          403,
          'admin_required_for_runs',
          'Starting an operator session from a multi-incident console requires --enable-admin so each session gets an isolated capability token without narrowing the console\'s browse session.',
        );
      }
      const existing = runs.get(incidentId);
      if (existing && Date.parse(existing.expires_at) > Date.now()) return publicRun(existing);

      const incident = await incidentSummary(incidentId);
      let collectors = [...COLLECTOR_TYPES];
      try {
        const caps = (await invCall({ op: 'list_collector_capabilities', host_id: incident.host_id }, 'capabilities')).capabilities;
        if (caps.length) collectors = caps.map((c) => c.collector_type);
      } catch {
        /* fall back to the full catalog; control-d still enforces its policy */
      }
      const minted = await adminCall(
        {
          admin_op: 'mint_capability_token',
          principal_id: `console-run-${incidentId.slice(0, 8)}`,
          role: 'investigator',
          allowed_hosts: [incident.host_id],
          allowed_collectors: collectors,
          incident_id: incidentId,
          ttl_seconds: RUN_TOKEN_TTL_SECONDS,
        },
        'token_minted',
      );
      const client = new InvestigationClient({ socketPath: investigateSock, token: minted.token, timeoutMs });
      const r = await clientCall(client, { op: 'start_investigation_run', incident_id: incidentId, backend_id, model_id, prompt_schema_version }, 'run_started');
      runs.set(incidentId, { run_id: r.run_id, incident_id: r.incident_id, host_id: incident.host_id, expires_at: r.expires_at, client });
      return publicRun(runs.get(incidentId));
    },

    async propose(incidentId, body = {}) {
      requireIdent(incidentId, 'incident_id');
      const run = resolveRun(incidentId, body.run_id);
      const incident = await incidentSummary(incidentId);
      const spec = buildWatchSpec(body, incident);
      const r = await clientCall(
        run.client,
        {
          op: 'propose_ephemeral_watch',
          run_id: run.run_id,
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
      const run = resolveRun(incidentId, f.run_id);
      f.run_id = run.run_id;
      const r = await clientCall(run.client, { op: 'record_hypothesis_or_finding', ...f }, 'finding_recorded');
      return { finding_id: r.finding_id, verified_evidence_count: r.verified_evidence_count };
    },

    async proposeAction(incidentId, body = {}) {
      requireIdent(incidentId, 'incident_id');
      const a = parseActionBody(body);
      const run = resolveRun(incidentId, a.run_id);
      const r = await clientCall(
        run.client,
        {
          op: 'propose_action',
          run_id: run.run_id,
          incident_id: incidentId,
          idempotency_key: a.idempotency_key,
          verb: a.verb,
          evidence_observation_ids: a.evidence_observation_ids,
          expected_effect: a.expected_effect,
          blast_radius: a.blast_radius,
          rollback_plan: a.rollback_plan,
        },
        'action_proposal_evaluated',
      );
      return {
        decision: r.decision,
        proposal_id: r.proposal_id ?? null,
        intent_id: r.intent_id ?? null,
        auth_mode: r.auth_mode ?? null,
        status: r.status ?? null,
        authorized: Boolean(r.authorized_intent),
        verb: a.verb,
        idempotency_key: a.idempotency_key,
      };
    },

    async changes(incidentId) {
      requireIdent(incidentId, 'incident_id');
      const ctx = await invCall({ op: 'get_incident_context', incident_id: incidentId }, 'incident_context');
      const host = ctx.incident.host_id;
      const snapshotWatches = ctx.active_watches.filter((w) => !isStreamWatch(w));
      const [base, ...perWatch] = await Promise.all([
        invCall({ op: 'get_host_baseline_summary', host_id: host }, 'baseline_summary'),
        ...snapshotWatches.map((w) => invCall({ op: 'query_observations', host_id: host, watch_id: w.id, limit: 100 }, 'observations')),
      ]);
      const observationsByWatch = new Map(snapshotWatches.map((w, i) => [w.id, perWatch[i].observations]));
      return {
        incident_id: incidentId,
        host_id: host,
        changes: buildIncidentChanges({ incident: ctx.incident, watches: snapshotWatches, baselines: base.baselines, observationsByWatch }),
      };
    },

    // ---- Phase 9 reasoner activity (read-only, shared browse token) ----------
    // These ops are allowed for the observer role, so they use the console's
    // browse token. StartInvestigationRun is never sent on that token, and no
    // capability or lease token is ever part of a response.

    async runs(query = {}) {
      const q = parseRunsQuery(query);
      const request = { op: 'list_investigation_runs', limit: q.limit };
      if (q.incident_id) request.incident_id = q.incident_id;
      if (q.host_id) request.host_id = q.host_id;
      try {
        const r = await invCall(request, 'runs');
        return { available: true, runs: (r.runs ?? []).map(publicRunSummary), server_time: new Date().toISOString() };
      } catch (err) {
        const u = unavailable(err);
        if (u) return { ...u, runs: [], server_time: new Date().toISOString() };
        throw err;
      }
    },

    async runEvents(runId, query = {}) {
      const q = parseEventsQuery(runId, query);
      const request = { op: 'get_run_events', run_id: q.run_id, limit: q.limit };
      if (q.after_seq !== null) request.after_seq = q.after_seq;
      try {
        const r = await invCall(request, 'run_events');
        const events = (r.events ?? []).map(publicRunEvent).sort((a, b) => a.event_seq - b.event_seq);
        const last = events.at(-1)?.event_seq ?? q.after_seq ?? null;
        return { available: true, run_id: r.run_id ?? q.run_id, events, next_after_seq: last, server_time: new Date().toISOString() };
      } catch (err) {
        const u = unavailable(err);
        if (u) return { ...u, run_id: q.run_id, events: [], next_after_seq: q.after_seq, server_time: new Date().toISOString() };
        throw err;
      }
    },

    async triggers(query = {}) {
      const q = parseTriggersQuery(query);
      const request = { op: 'list_trigger_queue', limit: q.limit };
      if (q.host_id) request.host_id = q.host_id;
      if (q.incident_id) request.incident_id = q.incident_id;
      if (q.statuses) request.statuses = q.statuses;
      try {
        const r = await invCall(request, 'trigger_queue');
        return { available: true, triggers: (r.triggers ?? []).map(publicTrigger), server_time: new Date().toISOString() };
      } catch (err) {
        const u = unavailable(err);
        if (u) return { ...u, triggers: [], server_time: new Date().toISOString() };
        throw err;
      }
    },

    // ---- Phase 10 expectation rules --------------------------------------------
    // Reads use the admin interface when it is on (every host), otherwise the
    // browse token's investigation scope. Mutations are admin-only; the actor
    // is bound to the signed-in account by server.mjs before it gets here.

    async rules(query = {}) {
      const q = parseRulesQuery(query);
      const filter = { limit: q.limit };
      if (q.before !== null) filter.before = q.before;
      if (q.host_id) filter.host_id = q.host_id;
      if (q.statuses) filter.statuses = q.statuses;
      const server_time = new Date().toISOString();
      let source = admin ? 'admin' : 'investigate';
      let r;
      try {
        r = admin ? await adminCall({ admin_op: 'list_expectation_rules', ...filter }, 'expectation_rules') : await invCall({ op: 'list_expectation_rules', ...filter }, 'expectation_rules');
      } catch (err) {
        if (admin && err instanceof ApiError && err.status !== 503 && !unsupportedOp(err)) {
          // The admin socket refused (e.g. frame limit); the scoped list still works.
          source = 'investigate';
          try {
            r = await invCall({ op: 'list_expectation_rules', ...filter }, 'expectation_rules');
          } catch (inner) {
            const u = unavailable(inner, RULES_UNSUPPORTED_MESSAGE);
            if (u) return { ...u, source, rules: [], server_time };
            throw inner;
          }
        } else {
          const u = unavailable(err, RULES_UNSUPPORTED_MESSAGE);
          if (u) return { ...u, source, rules: [], server_time };
          throw err;
        }
      }
      return { available: true, source, rules: (r.rules ?? []).map(publicRuleRecord), next_before: r.next_before ?? null, server_time };
    },

    async backtestRule(body = {}) {
      const { rule } = parseRuleBody(body);
      const r = await ruleGateCall({ admin_op: 'backtest_expectation_rule', rule }, 'rule_backtest_result');
      if (r.denied) return { allowed: false, decision: r.denied, backtest: null, rule };
      return { allowed: true, decision: null, backtest: publicBacktest(r.value.backtest), rule };
    },

    async createRule(body = {}) {
      const { rule, actor } = parseRuleBody(body, { actor: true });
      const r = await ruleGateCall({ admin_op: 'create_expectation_rule', rule, actor }, 'rule_decided');
      if (r.denied) return { allowed: false, decision: r.denied, rule_id: null, status: null, rule };
      return { allowed: true, decision: null, rule_id: r.value.rule_id, status: r.value.status, rule };
    },

    async decideRule(ruleId, body = {}) {
      const rule_id = parseRuleId(ruleId);
      const d = parseRuleDecision(body);
      const request = { admin_op: 'decide_expectation_rule', rule_id, approve: d.approve, actor: d.actor };
      if (d.note !== null) request.note = d.note;
      const r = await ruleGateCall(request, 'rule_decided');
      if (r.denied) return { allowed: false, decision: r.denied, rule_id, status: 'proposed' };
      return { allowed: true, decision: null, rule_id: r.value.rule_id, status: r.value.status };
    },

    async revokeRule(ruleId, body = {}) {
      const rule_id = parseRuleId(ruleId);
      const v = parseRuleRevoke(body);
      const r = await adminCall({ admin_op: 'revoke_expectation_rule', rule_id, actor: v.actor, reason: v.reason }, 'rule_decided');
      return { rule_id: r.rule_id, status: r.status };
    },

    // ---- Adaptive investigator (P11–P18) ---------------------------------------
    // Reads use the shared browse token (or the admin interface where control-d
    // only exposes an admin read). Mutations are admin-only. No capability,
    // lease or run token ever reaches a response.

    async hostProfile(hostId) {
      requireIdent(hostId, 'host_id');
      const [list, caps, w, o] = await Promise.allSettled([
        invCall({ op: 'list_hosts', limit: 500 }, 'hosts'),
        invCall({ op: 'list_collector_capabilities', host_id: hostId }, 'capabilities'),
        invCall({ op: 'list_active_watches', host_id: hostId }, 'watches'),
        invCall({ op: 'query_observations', host_id: hostId, limit: 200 }, 'observations'),
      ]);
      if (list.status === 'rejected') throw list.reason;
      const host = list.value.hosts.find((x) => x.host_id === hostId);
      if (!host) throw new ApiError(404, 'not_found', `host '${hostId}' is not visible to this console`);
      for (const r of [caps, w, o]) if (r.status === 'rejected' && !unsupportedOp(r.reason)) throw r.reason;
      const profile = publicHostProfile(host.host_profile);
      const watches = w.status === 'fulfilled' ? w.value.watches : [];
      const observations = o.status === 'fulfilled' ? [...o.value.observations].sort((a, b) => b.observation_id - a.observation_id) : [];
      const capabilities = caps.status === 'fulfilled' ? caps.value.capabilities : [];
      return {
        available: true,
        host_id: hostId,
        agent_version: host.agent_version,
        liveness_status: host.liveness_status,
        discovery_support: supportsDiscovery(host.agent_version),
        host_profile: profile,
        capabilities_available: caps.status === 'fulfilled',
        coverage: buildCoverage({ capabilities, profile, watches, observations }),
        server_time: new Date().toISOString(),
      };
    },

    async discovery(hostId, query = {}) {
      requireIdent(hostId, 'host_id');
      const version = parseAssessmentVersion(query.version);
      const server_time = new Date().toISOString();
      let latest;
      let pinned = null;
      try {
        latest = (await invCall({ op: 'get_host_assessment', host_id: hostId }, 'host_assessment')).assessment;
        if (version !== null) pinned = (await invCall({ op: 'get_host_assessment', host_id: hostId, version }, 'host_assessment')).assessment;
      } catch (err) {
        const u = unavailable(err, ADAPTIVE_UNSUPPORTED_MESSAGE);
        if (u) return { ...u, host_id: hostId, server_time };
        throw err;
      }
      let samples = [];
      let samplesAvailable = true;
      try {
        samples = (await invCall({ op: 'get_host_discovery_samples', host_id: hostId }, 'host_discovery_samples')).samples ?? [];
      } catch (err) {
        if (!unavailable(err)) throw err;
        samplesAvailable = false;
      }
      const assessment = publicAssessment(version !== null ? pinned : latest);
      // Interpretation attempts are keyed by the exact source-ID list a worker claimed.
      const keys = new Map();
      const current = discoverySourceIds(samples);
      if (current.length) keys.set(JSON.stringify(current), current);
      for (const i of assessment?.interpretations ?? []) if (i.source_ids.length && keys.size < 4) keys.set(JSON.stringify(i.source_ids), i.source_ids);
      const attempts = [];
      for (const source_ids of keys.values()) {
        try {
          const r = await invCall({ op: 'list_host_interpretation_attempts', host_id: hostId, source_ids }, 'host_interpretation_attempts');
          attempts.push({ source_ids, attempts: (r.attempts ?? []).map(publicAttempt) });
        } catch (err) {
          if (!unavailable(err)) throw err;
        }
      }
      return {
        available: true,
        host_id: hostId,
        latest_version: latest?.version ?? null,
        assessment,
        samples_available: samplesAvailable,
        samples: samples.map(publicSample),
        source_ids: current,
        attempts,
        server_time,
      };
    },

    async advanceDiscovery(hostId) {
      requireIdent(hostId, 'host_id');
      if (!admin) throw new ApiError(403, 'admin_disabled', 'admin interface is disabled (start the console with --enable-admin --admin-sock)');
      // A one-call, host-scoped investigator grant: the browse token is never
      // widened and the minted token never leaves this function.
      const grant = {
        admin_op: 'mint_capability_token',
        principal_id: 'console-discovery',
        role: 'investigator',
        allowed_hosts: [hostId],
        allowed_collectors: [...DISCOVERY_COLLECTORS],
        allowed_purposes: ['host_discovery'],
        ttl_seconds: DISCOVERY_TOKEN_TTL_SECONDS,
      };
      let minted;
      try {
        minted = await adminCall(grant, 'token_minted');
      } catch (err) {
        // A control-d from before purpose-scoped tokens cannot decode the field;
        // only then fall back to the host- and collector-scoped grant.
        if (!(unsupportedOp(err) || /unknown field\W*allowed_purposes/i.test(err?.message ?? ''))) throw err;
        const { allowed_purposes: _omit, ...legacy } = grant;
        minted = await adminCall(legacy, 'token_minted');
      }
      const client = new InvestigationClient({ socketPath: investigateSock, token: minted.token, timeoutMs });
      const r = await clientCall(client, { op: 'advance_host_discovery', host_id: hostId }, 'host_discovery_advanced');
      let version = null;
      try {
        version = (await invCall({ op: 'get_host_assessment', host_id: hostId }, 'host_assessment')).assessment?.version ?? null;
      } catch {
        /* the advance itself succeeded */
      }
      return { host_id: r.host_id ?? null, bundle_version: r.bundle_version ?? null, assessment_version: version };
    },

    async monitoring(hostId) {
      requireIdent(hostId, 'host_id');
      const server_time = new Date().toISOString();
      if (!admin) return { available: false, reason: 'admin_disabled', message: `Monitoring grants and managed watches are ${ADMIN_VIEW_MESSAGE}.`, host_id: hostId, server_time };
      // The admin socket sees every host: the browse token decides visibility first.
      const w = await requireVisibleHost(hostId);
      const [entries, b] = await Promise.all([
        auditEntries(MONITORING_AUDIT_WINDOW),
        invCall({ op: 'get_host_baseline_summary', host_id: hostId }, 'baseline_summary').catch((err) => {
          if (err instanceof ApiError && err.status === 403) throw err;
          return { baselines: [] };
        }),
      ]);
      return {
        available: true,
        source: 'audit',
        window_entries: entries.length,
        host_id: hostId,
        ...deriveMonitoring(entries, hostId, { baselines: b.baselines, watches: w.watches }),
        server_time,
      };
    },

    async setMonitoringGrant(hostId, body = {}) {
      requireIdent(hostId, 'host_id');
      const g = parseGrantBody(body);
      const r = await adminCall({ admin_op: 'set_monitoring_grant', host_id: hostId, principal_id: g.principal_id, max_watches: g.max_watches, allow_promotion: g.allow_promotion }, 'monitoring');
      return { allowed: r.result?.allowed === true, host_id: hostId, ...g };
    },

    async corroborateMonitoring(candidateId, body = {}) {
      const candidate_id = parseCandidateId(candidateId);
      const { rationale } = parseCorroborateBody(body);
      const r = await adminCall({ admin_op: 'corroborate_monitoring', candidate_id, rationale }, 'monitoring');
      const allowed = r.result?.allowed === true;
      return { allowed, candidate_id, reason: allowed ? null : 'candidate is unknown, already corroborated or already promoted' };
    },

    async rollbackMonitoring(hostId, watchId, body = {}) {
      requireIdent(hostId, 'host_id');
      requireIdent(watchId, 'watch_id');
      const v = parseRollbackBody(body);
      const r = await adminCall({ admin_op: 'rollback_monitoring', host_id: hostId, watch_id: watchId, expected_baseline: v.expected_baseline, rationale: v.rationale }, 'monitoring');
      const x = r.result ?? {};
      return { allowed: x.allowed === true, reason: x.reason ?? null, baseline: x.baseline ?? null, rolled_back: x.rolled_back ?? null, host_id: hostId, watch_id: watchId };
    },

    async hostReview(hostId) {
      requireIdent(hostId, 'host_id');
      const server_time = new Date().toISOString();
      const memo = schedules.get(hostId) ?? null;
      const schedule = memo ? { ...memo.schedule, set_at: memo.set_at, set_by: memo.set_by, source: 'console' } : null;
      if (!admin) return { available: false, reason: 'admin_disabled', message: `Periodic host reviews are ${ADMIN_VIEW_MESSAGE}.`, host_id: hostId, schedule, server_time };
      await requireVisibleHost(hostId);
      let review;
      try {
        review = publicReview((await adminCall({ admin_op: 'get_latest_host_review', host_id: hostId }, 'latest_host_review')).review);
      } catch (err) {
        const u = unavailable(err, ADAPTIVE_UNSUPPORTED_MESSAGE);
        if (u) return { ...u, host_id: hostId, schedule, server_time };
        throw err;
      }
      let assessmentVersion = null;
      try {
        assessmentVersion = (await invCall({ op: 'get_host_assessment', host_id: hostId }, 'host_assessment')).assessment?.version ?? null;
      } catch {
        /* freshness falls back to age only */
      }
      return { available: true, host_id: hostId, review, schedule, schedule_visible: false, freshness: reviewFreshness(review, assessmentVersion, schedule), server_time };
    },

    async setReviewSchedule(hostId, body = {}, ctx = {}) {
      const schedule = parseScheduleBody(hostId, body);
      await adminCall({ admin_op: 'set_host_review_schedule', schedule }, 'host_review_schedule_updated');
      const set_at = new Date().toISOString();
      schedules.set(schedule.host_id, { schedule, set_at, set_by: ctx.user?.username ?? null });
      return { host_id: schedule.host_id, schedule: { ...schedule, set_at, source: 'console' } };
    },

    async cancelReviewSchedule(hostId) {
      requireIdent(hostId, 'host_id');
      await adminCall({ admin_op: 'cancel_host_review_schedule', host_id: hostId }, 'host_review_schedule_updated');
      schedules.delete(hostId);
      return { host_id: hostId, cancelled: true };
    },

    async followups(incidentId) {
      requireIdent(incidentId, 'incident_id');
      const server_time = new Date().toISOString();
      let list;
      let ctx;
      try {
        [list, ctx] = await Promise.all([
          invCall({ op: 'list_watch_followups', incident_id: incidentId }, 'watch_followups'),
          invCall({ op: 'get_incident_context', incident_id: incidentId }, 'incident_context').catch(() => ({ findings: [] })),
        ]);
      } catch (err) {
        const u = unavailable(err, ADAPTIVE_UNSUPPORTED_MESSAGE);
        if (u) return { ...u, incident_id: incidentId, followups: [], server_time };
        throw err;
      }
      const findings = findingIndex(ctx.findings ?? []);
      return { available: true, incident_id: incidentId, followups: (list.followups ?? []).map((f) => publicFollowup(f, findings)), server_time };
    },

    async actionVerification(intentId) {
      requireIdent(intentId, 'intent_id');
      let v;
      try {
        v = await adminCall({ admin_op: 'get_action_verification', intent_id: intentId }, 'action_verification');
      } catch (err) {
        if (unsupportedOp(err)) return { available: false, reason: 'unsupported', message: ADAPTIVE_UNSUPPORTED_MESSAGE, intent_id: intentId };
        throw err;
      }
      const intent = await adminCall({ admin_op: 'get_action_intent', intent_id: intentId }, 'action_intent_detail').catch(() => null);
      return { available: true, ...publicVerification(v.detail, intent ? { status: intent.status, expires_at: intent.payload?.expires_at ?? null } : null) };
    },

    async reconcileAction(intentId, body = {}) {
      requireIdent(intentId, 'intent_id');
      const r = parseReconcileBody(body);
      const v = await adminCall({ admin_op: 'reconcile_action_outcome', intent_id: intentId, expected_receipt_id: r.expected_receipt_id, evidence_ref: r.evidence_ref, rationale: r.rationale }, 'action_verification');
      const intent = await adminCall({ admin_op: 'get_action_intent', intent_id: intentId }, 'action_intent_detail').catch(() => null);
      return { available: true, ...publicVerification(v.detail, intent ? { status: intent.status, expires_at: intent.payload?.expires_at ?? null } : null) };
    },

    async automation() {
      if (!admin) return { available: false, reason: 'admin_disabled' };
      return { available: true, ...automationSummary(await auditEntries(500)) };
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
