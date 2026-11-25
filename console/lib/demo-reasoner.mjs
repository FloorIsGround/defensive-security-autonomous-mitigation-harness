// Demo reasoner-d: investigation runs, their event timelines and the trigger
// queue, all keyed to wall-clock time so the in-progress run visibly advances
// while the demo console is open (and finishes a few minutes later, after
// which the still-pending trigger shows what a stopped worker looks like).
//
// Everything here mirrors the Phase 9 wire contract (RunSummary, RunEvent,
// TriggerSummary); the views are computed at query time from `nowMs`.

import { ApiError, parseEventsQuery, parseRunsQuery, parseTriggersQuery, publicRunEvent, publicRunSummary, publicTrigger } from './domain.mjs';

const S_ = 1000;
const MIN = 60 * S_;
const LEASE_OWNER = 'reasoner-d@ops-ctl-01';
const BACKEND = 'anthropic-direct';
const MODEL = 'claude-sonnet-5-5';

const ev = (at, kind, detail, effect = null) => ({ at, kind, detail, effect });
const call = (at, tool, args) => ev(at, 'tool_call', { tool, args_preview: JSON.stringify(args) });
const result = (at, tool, extra = {}, effect = null) => ev(at, 'tool_result', { tool, ok: true, code: null, ...extra }, effect);

/**
 * @param {object} p
 * @param {number} p.now   build time (ms)
 * @param {(...keys: string[]) => number[]} p.ids observation IDs by fixture key
 */
export function buildDemoReasoner({ now, ids }) {
  const T = (offsetMs) => now + offsetMs;

  // --- run A: completed hours ago on the nginx drift --------------------------
  const a0 = T(-(2 * 60 + 49) * MIN);
  const runA = {
    run_id: 'run-19bd04e7', incident_id: 'inc-2026-0039', host_id: 'edge-vm-03', principal_id: 'reasoner-d', backend_id: BACKEND, model_id: MODEL,
    started: a0, expires: a0 + 30 * MIN, ends: a0 + 11 * MIN,
    final: { status: 'completed', budget_stop_reason: null, summary: 'Config drift matches maintenance window CHG-4471. Recorded hypothesis #288 for operator confirmation; no containment proposed.' },
    events: [
      ev(a0, 'note', { text: 'Leased trigger 4102 from base-nginx-config (set_diff against the accepted baseline).' }),
      ev(a0 + 3 * S_, 'turn_started', { turn: 1, tokens: 5120 }),
      call(a0 + 10 * S_, 'get_incident_context', { incident_id: 'inc-2026-0039' }),
      result(a0 + 11 * S_, 'get_incident_context'),
      call(a0 + 25 * S_, 'query_observations', { host_id: 'edge-vm-03', watch_id: 'base-nginx-config', limit: 10 }),
      result(a0 + 26 * S_, 'query_observations'),
      ev(a0 + 60 * S_, 'model_text', { text: 'nginx.conf changed inside maintenance window CHG-4471 and nginx.service did not restart. This looks like an approved config push, but only an operator can promote the new baseline.' }),
      call(a0 + 9 * MIN, 'record_hypothesis_or_finding', { kind: 'hypothesis', severity: 'low', evidence_observation_ids: ids('v3_conf_2') }),
      result(a0 + 9 * MIN + S_, 'record_hypothesis_or_finding', { accepted: true }),
      ev(a0 + 10 * MIN, 'model_text', { text: 'Nothing else to collect without operator context. Ending the run.' }),
    ],
  };

  // --- run B: stopped on its tool budget ---------------------------------------
  const b0 = T(-(39 * MIN + 30 * S_));
  const ago = (m) => T(-m * MIN);
  const runB = {
    run_id: 'run-7f3a91c2', incident_id: 'inc-2026-0042', host_id: 'edge-vm-07', principal_id: 'reasoner-d', backend_id: BACKEND, model_id: MODEL,
    started: b0, expires: b0 + 45 * MIN, ends: ago(11),
    final: {
      status: 'budget_exhausted',
      budget_stop_reason: 'tool_calls: 24 of 24 used',
      summary: 'Attributed tcp/4444 to custom-helper.service (PID 23817, verified finding #302) and noted a 300 s beacon flag (#303). The tool-call budget ran out before persistence could be checked; escalation requested on #301.',
    },
    events: [
      ev(b0, 'note', { text: 'Leased trigger 4119 from base-sockets-listening: new listener tcp/0.0.0.0:4444.' }),
      ev(b0 + 5 * S_, 'turn_started', { turn: 1, tokens: 7340 }),
      call(b0 + 15 * S_, 'get_incident_context', { incident_id: 'inc-2026-0042' }),
      result(b0 + 16 * S_, 'get_incident_context'),
      call(b0 + 40 * S_, 'query_observations', { host_id: 'edge-vm-07', watch_id: 'base-systemd-units', limit: 5 }),
      result(b0 + 41 * S_, 'query_observations'),
      ev(ago(38), 'model_text', { text: 'The listener appeared about two minutes after custom-helper.service was rewritten to run helperd --listen 0.0.0.0:4444. Watching the unit and its journal before concluding anything.' }),
      call(ago(37) - S_, 'propose_ephemeral_watch', { collector: 'systemd.unit_state', unit: 'custom-helper.service', interval_seconds: 30 }),
      result(ago(37), 'propose_ephemeral_watch', { accepted: true, code: 'policy.accepted' }),
      call(ago(36.5) - S_, 'propose_ephemeral_watch', { collector: 'journal.unit_events', unit: 'custom-helper.service', interval_seconds: 30 }),
      result(ago(36.5), 'propose_ephemeral_watch', { accepted: true, code: 'policy.accepted' }),
      call(ago(36) - 3 * S_, 'record_hypothesis_or_finding', { kind: 'hypothesis', severity: 'high', escalation_requested: true }),
      result(ago(36) - 2 * S_, 'record_hypothesis_or_finding', { accepted: true }),
      call(ago(35) - S_, 'propose_ephemeral_watch', { class: 'baseline', collector: 'sockets.listening' }),
      result(ago(35), 'propose_ephemeral_watch', { accepted: false, code: 'baseline.protected' }),
      call(ago(34) - S_, 'propose_ephemeral_watch', { collector: 'files.metadata', paths: ['/etc/shadow'] }),
      result(ago(34), 'propose_ephemeral_watch', { accepted: false, code: 'spec.safety_floor' }),
      ev(ago(33), 'turn_started', { turn: 2, tokens: 12890 }),
      call(ago(32) - S_, 'propose_ephemeral_watch', { collector: 'files.metadata', paths: ['/etc/cron.d/helper-refresh', '/etc/cron.d/e2scrub_all'] }),
      result(ago(32), 'propose_ephemeral_watch', { accepted: true, code: 'policy.accepted' }),
      call(ago(30) - S_, 'record_hypothesis_or_finding', { kind: 'verified_finding', severity: 'high', evidence_observation_ids: ids('sock_new', 'unit_u1', 'journal_1') }),
      result(ago(30), 'record_hypothesis_or_finding', { accepted: true }),
      ev(ago(20), 'budget_warning', { budget: 'tool_calls', used: 20, limit: 24 }),
      ev(ago(16), 'turn_started', { turn: 3, tokens: 18402 }),
      call(ago(12) - S_, 'record_hypothesis_or_finding', { kind: 'hypothesis', severity: 'medium' }),
      result(ago(12), 'record_hypothesis_or_finding', { accepted: true }),
      call(ago(11.5), 'query_observations', { host_id: 'edge-vm-07', watch_id: 'ephem-0042-helper-journal', limit: 5 }),
      result(ago(11.5) + S_, 'query_observations'),
      ev(ago(11) - S_, 'budget_warning', { budget: 'tool_calls', used: 24, limit: 24, stop: true }),
    ],
  };

  // --- run C: in progress when the demo starts, finishes ~4 min later ----------
  const c0 = T(-95 * S_);
  const runC = {
    run_id: 'run-a41c07d9', incident_id: 'inc-2026-0042', host_id: 'edge-vm-07', principal_id: 'reasoner-d', backend_id: BACKEND, model_id: MODEL,
    started: c0, expires: c0 + 30 * MIN, ends: T(240 * S_),
    final: {
      status: 'completed',
      budget_stop_reason: null,
      summary: 'Confirmed Restart=always persistence of helperd; no cron persistence. Recorded a verified finding and recommended an operator-approved stop of custom-helper.service (action proposals are disabled for this worker).',
    },
    events: [
      ev(c0, 'note', { text: 'Leased trigger 4127 from ephem-0042-helper-unit. Resuming inc-2026-0042 with 3 prior findings.' }),
      ev(c0 + 2 * S_, 'turn_started', { turn: 1, tokens: 8216 }),
      call(c0 + 7 * S_, 'get_incident_context', { incident_id: 'inc-2026-0042' }),
      result(c0 + 8 * S_, 'get_incident_context'),
      ev(T(-70 * S_), 'model_text', { text: 'The previous run stopped on its tool budget before checking persistence. Current collectors cannot see outbound connections, so I will check cron entries and the unit file history instead.' }),
      call(T(-55 * S_), 'query_observations', { host_id: 'edge-vm-07', watch_id: 'ephem-0042-cron-scan', limit: 5 }),
      result(T(-54 * S_), 'query_observations'),
      call(T(-30 * S_), 'query_observations', { host_id: 'edge-vm-07', watch_id: 'base-systemd-units', limit: 3 }),
      result(T(-29 * S_), 'query_observations'),
      ev(T(15 * S_), 'turn_started', { turn: 2, tokens: 11630 }),
      ev(T(35 * S_), 'model_text', { text: '/etc/cron.d/helper-refresh is still absent, so there is no cron persistence. The unit file sets Restart=always, which is how helperd survives. One journal line from PID 24410 is addressed to an AI analyst; it is attacker-controlled data, not an instruction.' }),
      call(T(60 * S_), 'record_hypothesis_or_finding', { kind: 'verified_finding', severity: 'high', evidence_observation_ids: ids('units_f3', 'unit_u3', 'journal_2') }),
      result(T(62 * S_), 'record_hypothesis_or_finding', { accepted: true }, {
        type: 'finding',
        actor: 'reasoner-d:run-a41c07d9',
        finding: {
          kind: 'verified_finding',
          severity: 'high',
          summary: 'helperd persists through Restart=always in custom-helper.service (unit file revision 3); no cron entry exists for it.',
          uncertainty: 'Persistence is verified from the unit file hash and the absent cron path. Outbound beaconing is still unobserved.',
          escalation_requested: true,
          evidence_observation_ids: ids('units_f3', 'unit_u3', 'cron_scan'),
        },
      }),
      call(T(95 * S_), 'propose_ephemeral_watch', { collector: 'systemd.unit_state', unit: 'custom-helper.service', interval_seconds: 30 }),
      result(T(96 * S_), 'propose_ephemeral_watch', { accepted: false, code: 'dedup.equivalent_active_watch' }),
      ev(T(120 * S_), 'budget_warning', { budget: 'turns', used: 2, limit: 3 }),
      ev(T(150 * S_), 'turn_started', { turn: 3, tokens: 14980 }),
      ev(T(185 * S_), 'model_text', { text: 'Recommend stopping custom-helper.service under dual-signed approval. Action proposals are disabled in this worker\'s run budget, so the recommendation is left for an operator.' }),
      ev(T(215 * S_), 'note', { text: 'Escalation requested; action proposals disabled in run budget.' }),
    ],
  };

  // --- trigger queue ------------------------------------------------------------
  const phase = (at, status, extra = {}) => ({ at, status, lease_owner: null, lease_expires_at: null, reason: null, ...extra });
  const leased = (at, leaseSeconds) => phase(at, 'leased', { lease_owner: LEASE_OWNER, lease_expires_at: at + leaseSeconds * S_ });
  const triggers = [
    { event_id: 4102, incident_id: 'inc-2026-0039', host_id: 'edge-vm-03', watch_id: 'base-nginx-config', retry_count: 0,
      phases: [phase(a0 - MIN, 'pending'), leased(a0, 900), phase(runA.ends, 'done', { reason: `completed by ${runA.run_id}` })] },
    { event_id: 4119, incident_id: 'inc-2026-0042', host_id: 'edge-vm-07', watch_id: 'base-sockets-listening', retry_count: 0,
      phases: [phase(ago(41), 'pending'), leased(b0, 1800), phase(runB.ends, 'done', { reason: `completed by ${runB.run_id}: budget exhausted` })] },
    { event_id: 4121, incident_id: 'inc-2026-0042', host_id: 'edge-vm-07', watch_id: 'ephem-0042-cron-scan', retry_count: 0,
      phases: [phase(ago(42), 'pending'), leased(ago(41) + 20 * S_, 120), phase(ago(40), 'pending', { retry_count: 1, reason: 'backend error: HTTP 529 overloaded' }), leased(ago(33), 120), phase(ago(31), 'pending', { retry_count: 2, reason: 'backend error: HTTP 529 overloaded' }), leased(ago(27), 120), phase(ago(25), 'dead_letter', { retry_count: 3, reason: 'retry budget exhausted (3 attempts): anthropic-direct returned HTTP 529 overloaded' })] },
    { event_id: 4127, incident_id: 'inc-2026-0042', host_id: 'edge-vm-07', watch_id: 'ephem-0042-helper-unit', retry_count: 0,
      phases: [phase(T(-150 * S_), 'pending'), leased(c0, 600), phase(runC.ends, 'done', { reason: `completed by ${runC.run_id}` })] },
    { event_id: 4129, incident_id: 'inc-2026-0039', host_id: 'edge-vm-03', watch_id: 'base-nginx-unit', retry_count: 0,
      phases: [phase(T(-200 * S_), 'pending')] },
  ];

  const auditEvents = [
    { ago: now - (c0 - 10 * S_), event_type: 'capability_minted', actor: 'operator', payload: { scope: { principal_id: 'reasoner-d', role: 'investigator', incident_id: 'inc-2026-0042' } } },
    { ago: now - c0, event_type: 'run_started', actor: 'reasoner-d', payload: { run_id: runC.run_id, incident_id: 'inc-2026-0042', backend_id: BACKEND, model_id: MODEL, prompt_schema_version: 'reasoner.v3' } },
  ];

  return { reasoner: { runs: [runA, runB, runC], triggers, applied: new Set() }, auditEvents };
}

// ---------------------------------------------------------------------------
// Views at a point in time
// ---------------------------------------------------------------------------

const TOOL_FINDING = 'record_hypothesis_or_finding';
const isProposalTool = (t) => typeof t === 'string' && t.startsWith('propose_');

function visibleEvents(run, nowMs) {
  return run.events.map((e, i) => ({ ...e, event_seq: i + 1 })).filter((e) => e.at <= nowMs);
}

function counts(events) {
  const results = events.filter((e) => e.kind === 'tool_result');
  const proposals = results.filter((e) => isProposalTool(e.detail.tool));
  const text = events.filter((e) => e.kind === 'model_text').reduce((n, e) => n + String(e.detail.text ?? '').length, 0);
  return {
    turns: events.filter((e) => e.kind === 'turn_started').length,
    tool_calls: events.filter((e) => e.kind === 'tool_call').length,
    input_tokens: events.filter((e) => e.kind === 'turn_started').reduce((n, e) => n + (e.detail.tokens ?? 0), 0),
    output_tokens: Math.round(text / 4) + 180 * events.filter((e) => e.kind === 'tool_call').length,
    findings: results.filter((e) => e.detail.tool === TOOL_FINDING && e.detail.accepted).length,
    proposals: proposals.length,
    proposals_accepted: proposals.filter((e) => e.detail.accepted).length,
  };
}

const iso = (ms) => (ms == null ? null : new Date(ms).toISOString());
const wireEvent = (e) => ({ event_seq: e.event_seq, kind: e.kind, detail: e.detail, created_at: iso(e.at) });

function runSummary(run, nowMs) {
  const events = visibleEvents(run, nowMs);
  const c = counts(events);
  let status = 'active';
  let ended = null;
  if (run.ends != null && nowMs >= run.ends) {
    status = run.final.status;
    ended = run.ends;
  } else if (nowMs >= run.expires) {
    status = 'expired';
    ended = run.expires;
  }
  const outcome = ended !== null && status !== 'expired'
    ? { status, summary: run.final.summary, budget_stop_reason: run.final.budget_stop_reason ?? null, ...c }
    : null;
  return publicRunSummary({
    run_id: run.run_id,
    incident_id: run.incident_id,
    host_id: run.host_id,
    principal_id: run.principal_id,
    backend_id: run.backend_id,
    model_id: run.model_id,
    status,
    started_at: iso(run.started),
    expires_at: iso(run.expires),
    ended_at: iso(ended),
    outcome,
    last_event: events.length ? wireEvent(events.at(-1)) : null,
    event_count: events.length,
    findings_count: c.findings,
    proposals_count: c.proposals,
  });
}

function triggerSummary(t, nowMs) {
  const seen = t.phases.filter((p) => p.at <= nowMs);
  if (!seen.length) return null;
  const cur = seen.at(-1);
  return publicTrigger({
    event_id: t.event_id,
    incident_id: t.incident_id,
    host_id: t.host_id,
    watch_id: t.watch_id,
    status: cur.status,
    created_at: iso(seen[0].at),
    updated_at: iso(cur.at),
    lease_owner: cur.status === 'leased' ? cur.lease_owner : null,
    lease_expires_at: cur.status === 'leased' ? iso(cur.lease_expires_at) : null,
    retry_count: cur.retry_count ?? t.retry_count ?? 0,
    reason: cur.reason,
  });
}

/** Apply time-based side effects (a finding recorded by the running model) exactly once. */
export function advanceDemoReasoner(S, nowMs, appendAudit) {
  const R = S.reasoner;
  for (const run of R.runs) {
    run.events.forEach((e, i) => {
      const key = `${run.run_id}:${i}`;
      if (!e.effect || e.at > nowMs || R.applied.has(key)) return;
      R.applied.add(key);
      if (e.effect.type === 'finding') {
        const inc = S.incidents.find((x) => x.incident_id === run.incident_id);
        if (!inc || inc.status !== 'open') return;
        const finding_id = S.nextFindingId++;
        const at = new Date(e.at).toISOString();
        S.findings.push({ finding_id, incident_id: run.incident_id, run_id: run.run_id, created_at: at, finding: e.effect.finding });
        appendAudit(S.audit, 'finding_recorded', e.effect.actor, { finding_id, run_id: run.run_id, incident_id: run.incident_id, kind: e.effect.finding.kind });
        inc.updated_at = new Date(Math.max(Date.parse(inc.updated_at), e.at)).toISOString();
      }
    });
  }
}

/** Track a console operator session alongside reasoner-d runs. */
export function openOperatorSession(S, { run_id, incident_id, host_id, expires_at, principal_id = 'console-operator', nowMs }) {
  S.reasoner.runs.push({
    run_id, incident_id, host_id, principal_id, backend_id: 'operator-console', model_id: 'human-operator',
    started: nowMs, expires: Date.parse(expires_at), ends: null,
    final: { status: 'cancelled', summary: 'Operator session ended when the incident was closed.', budget_stop_reason: null },
    events: [ev(nowMs, 'note', { text: `Operator session opened by ${principal_id}. Manual proposals, findings and mitigations use this session's incident-scoped token.` })],
  });
}

/** Record what an operator did in a session as a tool_result, so the run history reads like a reasoner run. */
export function logOperatorStep(S, runId, nowMs, tool, extra) {
  const run = S.reasoner.runs.find((r) => r.run_id === runId);
  if (!run) return;
  run.events.push(ev(nowMs, 'tool_call', { tool, args_preview: extra.args_preview ?? '' }));
  run.events.push(ev(nowMs, 'tool_result', { tool, ok: true, code: extra.code ?? null, accepted: extra.accepted ?? true }));
}

export function endRunsForIncident(S, incidentId, nowMs) {
  for (const run of S.reasoner.runs) {
    if (run.incident_id !== incidentId || run.backend_id !== 'operator-console' || run.ends != null) continue;
    if (nowMs >= run.expires) continue;
    run.ends = nowMs;
    run.events.push(ev(nowMs, 'note', { text: 'Incident closed; session ended.' }));
  }
}

export function demoRuns(S, nowMs, query = {}) {
  const q = parseRunsQuery(query);
  const runs = S.reasoner.runs
    .filter((r) => r.started <= nowMs && (!q.incident_id || r.incident_id === q.incident_id) && (!q.host_id || r.host_id === q.host_id))
    .sort((a, b) => b.started - a.started)
    .slice(0, q.limit)
    .map((r) => runSummary(r, nowMs));
  return { available: true, runs, server_time: iso(nowMs) };
}

export function demoRunEvents(S, nowMs, runId, query = {}) {
  const q = parseEventsQuery(runId, query);
  const run = S.reasoner.runs.find((r) => r.run_id === q.run_id && r.started <= nowMs);
  if (!run) throw new ApiError(404, 'not_found', `unknown run '${q.run_id}'`);
  const events = visibleEvents(run, nowMs)
    .filter((e) => q.after_seq === null || e.event_seq > q.after_seq)
    .slice(0, q.limit)
    .map((e) => publicRunEvent(wireEvent(e)));
  return { available: true, run_id: run.run_id, events, next_after_seq: events.at(-1)?.event_seq ?? q.after_seq, server_time: iso(nowMs) };
}

export function demoTriggers(S, nowMs, query = {}) {
  const q = parseTriggersQuery(query);
  const triggers = S.reasoner.triggers
    .map((t) => triggerSummary(t, nowMs))
    .filter((t) => t && (!q.incident_id || t.incident_id === q.incident_id) && (!q.host_id || t.host_id === q.host_id) && (!q.statuses || q.statuses.includes(t.status)))
    .sort((a, b) => Date.parse(b.updated_at) - Date.parse(a.updated_at))
    .slice(0, q.limit);
  return { available: true, triggers, server_time: iso(nowMs) };
}
