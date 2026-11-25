// Shared domain helpers for both the live (control-d) and demo backends:
// typed errors, strict WatchSpec construction from the guided composer, input
// validation, and three-state baseline derivation (design doc §6.1).

import { randomBytes } from 'node:crypto';

export class ApiError extends Error {
  constructor(status, code, message, extra = undefined) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.code = code;
    this.extra = extra;
  }
}

export const COLLECTOR_TYPES = Object.freeze([
  'sockets.listening',
  'systemd.unit_state',
  'files.metadata',
  'journal.unit_events',
]);
export const TRIGGER_TYPES = Object.freeze(['field_changed', 'set_diff', 'threshold_sustained', 'collector_stale_or_error']);
export const COMPARE_TARGETS = Object.freeze(['last_observed', 'accepted_baseline']);
export const THRESHOLD_OPS = Object.freeze(['gt', 'gte', 'lt', 'lte', 'eq', 'neq']);
export const SEVERITIES = Object.freeze(['info', 'low', 'medium', 'high', 'critical']);
export const FINDING_KINDS = Object.freeze(['hypothesis', 'verified_finding']);
const VALID_OBS = new Set(['ok', 'partial']);

const IDENT_RE = /^[A-Za-z0-9._-]{1,96}$/;

export function requireIdent(value, name) {
  if (typeof value !== 'string' || !IDENT_RE.test(value)) {
    throw new ApiError(400, 'invalid_request', `${name} must be 1..96 chars of [A-Za-z0-9._-]`);
  }
  return value;
}

export function requireText(value, name, max = 4096, { optional = false } = {}) {
  if (optional && (value === undefined || value === null || value === '')) return null;
  if (typeof value !== 'string' || !value.trim() || value.length > max) {
    throw new ApiError(400, 'invalid_request', `${name} is required (1..${max} chars)`);
  }
  return value;
}

export function requireEnum(value, allowed, name) {
  if (!allowed.includes(value)) {
    throw new ApiError(400, 'invalid_request', `${name} must be one of: ${allowed.join(', ')}`);
  }
  return value;
}

export function int(value, name, { min = 0, max = Number.MAX_SAFE_INTEGER, optional = false } = {}) {
  if (optional && (value === undefined || value === null || value === '')) return null;
  const n = typeof value === 'string' && value.trim() !== '' ? Number(value) : value;
  if (!Number.isSafeInteger(n) || n < min || n > max) {
    throw new ApiError(400, 'invalid_request', `${name} must be an integer within ${min}..${max}`);
  }
  return n;
}

const bool = (v, dflt) => (v === undefined || v === null ? dflt : Boolean(v));

function fieldList(raw) {
  const list = Array.isArray(raw) ? raw : typeof raw === 'string' ? raw.split(',') : [];
  return list.map((s) => String(s).trim()).filter(Boolean).slice(0, 64);
}

/** Build only the schema-conformant collector parameters (control-d denies unknown fields). */
export function buildCollector(type, params = {}) {
  requireEnum(type, COLLECTOR_TYPES, 'collector_type');
  const p = params && typeof params === 'object' ? params : {};
  switch (type) {
    case 'sockets.listening':
      return {
        type,
        parameters: {
          include_tcp: bool(p.include_tcp, true),
          include_udp: bool(p.include_udp, true),
          include_ipv6: bool(p.include_ipv6, true),
          resolve_process: bool(p.resolve_process, true),
        },
      };
    case 'systemd.unit_state':
      return {
        type,
        parameters: { unit: requireText(p.unit, 'unit', 256), hash_unit_files: bool(p.hash_unit_files, true) },
      };
    case 'files.metadata': {
      const paths = Array.isArray(p.paths)
        ? p.paths
        : String(p.paths ?? '').split(/[\n,]/);
      const parameters = {
        paths: paths.map((s) => String(s).trim()).filter(Boolean).slice(0, 128),
        compute_hash: bool(p.compute_hash, true),
      };
      const maxBytes = int(p.max_file_bytes, 'max_file_bytes', { optional: true, max: 2 ** 40 });
      if (maxBytes !== null) parameters.max_file_bytes = maxBytes;
      return { type, parameters };
    }
    case 'journal.unit_events': {
      const parameters = { unit: requireText(p.unit, 'unit', 256) };
      const prio = int(p.min_priority, 'min_priority', { optional: true, max: 255 });
      const events = int(p.max_events_per_batch, 'max_events_per_batch', { optional: true, max: 1_000_000 });
      const bytes = int(p.max_message_bytes, 'max_message_bytes', { optional: true, max: 1_000_000 });
      if (prio !== null) parameters.min_priority = prio;
      if (events !== null) parameters.max_events_per_batch = events;
      if (bytes !== null) parameters.max_message_bytes = bytes;
      return { type, parameters };
    }
  }
}

export function defaultTrigger(collectorType) {
  switch (collectorType) {
    case 'sockets.listening':
      return { type: 'set_diff', compare_against: 'last_observed', set_field: 'sockets', identity_key: 'socket_key' };
    case 'systemd.unit_state':
      return { type: 'field_changed', compare_against: 'last_observed', fields: ['active_state', 'sub_state', 'main_pid', 'exec_start_hash'] };
    case 'files.metadata':
      return { type: 'set_diff', compare_against: 'last_observed', set_field: 'files', identity_key: 'path' };
    default:
      return { type: 'collector_stale_or_error', max_stale_seconds: 300, consecutive_errors: 3 };
  }
}

export function buildTrigger(raw, collectorType) {
  if (!raw || typeof raw !== 'object' || !raw.type) return defaultTrigger(collectorType);
  const t = requireEnum(raw.type, TRIGGER_TYPES, 'trigger.type');
  const compare = () => requireEnum(raw.compare_against ?? 'last_observed', COMPARE_TARGETS, 'trigger.compare_against');
  switch (t) {
    case 'field_changed':
      return { type: t, compare_against: compare(), fields: fieldList(raw.fields) };
    case 'set_diff':
      return {
        type: t,
        compare_against: compare(),
        set_field: String(raw.set_field ?? '').trim(),
        identity_key: String(raw.identity_key ?? '').trim(),
      };
    case 'threshold_sustained':
      return {
        type: t,
        field: String(raw.field ?? '').trim(),
        operator: requireEnum(raw.operator ?? 'gt', THRESHOLD_OPS, 'trigger.operator'),
        threshold: int(raw.threshold ?? 0, 'trigger.threshold', { min: Number.MIN_SAFE_INTEGER }),
        consecutive_samples: int(raw.consecutive_samples ?? 3, 'trigger.consecutive_samples', { max: 1_000_000 }),
      };
    case 'collector_stale_or_error':
      return {
        type: t,
        max_stale_seconds: int(raw.max_stale_seconds ?? 300, 'trigger.max_stale_seconds'),
        consecutive_errors: int(raw.consecutive_errors ?? 3, 'trigger.consecutive_errors', { max: 1_000_000 }),
      };
  }
}

/**
 * Turn the guided composer draft into an exact WatchSpec. Bounds are NOT
 * enforced here on purpose: control-d's deterministic policy gate is the
 * authority, and the operator should see its real PolicyDecision.
 */
export function buildWatchSpec(draft, incident, now = Date.now()) {
  if (!draft || typeof draft !== 'object') throw new ApiError(400, 'invalid_request', 'proposal body must be an object');
  const collector = buildCollector(draft.collector_type, draft.parameters);
  const cls = draft.class === 'baseline' ? 'baseline' : 'ephemeral';
  const shortInc = incident.incident_id.replace(/^inc-?/, '').replace(/[^A-Za-z0-9]/g, '').slice(-6) || 'inc';
  const slug = collector.type.split('.')[0];
  const id = draft.watch_id
    ? String(draft.watch_id).trim()
    : `ephem-${shortInc}-${slug}-${randomBytes(3).toString('hex')}`;
  const ttl = int(draft.ttl_seconds ?? 3600, 'ttl_seconds', { min: 1, max: 30 * 24 * 3600 });
  return {
    id,
    version: 1,
    host_id: incident.host_id,
    class: cls,
    incident_id: incident.incident_id,
    collector,
    schedule: {
      interval_seconds: int(draft.interval_seconds ?? 60, 'interval_seconds', { max: 86_400 * 7 }),
      timeout_seconds: int(draft.timeout_seconds ?? 10, 'timeout_seconds', { max: 86_400 }),
    },
    trigger: buildTrigger(draft.trigger, collector.type),
    wake_policy: {
      cooldown_seconds: int(draft.cooldown_seconds ?? 180, 'cooldown_seconds', { max: 86_400 * 7 }),
      max_wakeups_per_hour: int(draft.max_wakeups_per_hour ?? 4, 'max_wakeups_per_hour', { max: 100_000 }),
    },
    lifecycle: {
      enabled: true,
      expires_at: new Date(now + ttl * 1000).toISOString(),
      max_runs: int(draft.max_runs ?? 120, 'max_runs', { max: 1_000_000_000 }),
    },
  };
}

export function parseFindingBody(body, incidentId) {
  const ids = Array.isArray(body?.evidence_observation_ids) ? body.evidence_observation_ids : [];
  if (ids.length > 100) throw new ApiError(400, 'invalid_request', 'at most 100 evidence observation IDs');
  return {
    run_id: body?.run_id ? requireText(body.run_id, 'run_id', 128) : null,
    incident_id: incidentId,
    kind: requireEnum(body?.kind, FINDING_KINDS, 'kind'),
    severity: requireEnum(body?.severity ?? 'medium', SEVERITIES, 'severity'),
    summary: requireText(body?.summary, 'summary', 4096),
    uncertainty: typeof body?.uncertainty === 'string' ? body.uncertainty.slice(0, 4096) : '',
    evidence_observation_ids: [...new Set(ids.map((v) => int(v, 'evidence_observation_ids[]', { min: 1 })))],
    escalation_requested: Boolean(body?.escalation_requested),
  };
}

const slim = (o) =>
  o && { observation_id: o.observation_id, state_hash: o.state_hash, observed_at: o.observed_at, status: o.status };

/** Append-only collectors: every batch hashes differently, so there is no snapshot to baseline. */
export function isStreamWatch(w, latest = null) {
  return w?.collector?.type === 'journal.unit_events' || latest?.payload?.kind === 'stream_batch';
}

function streamSummary(obs) {
  const latest = obs[0] ?? null;
  const events = (o) => (Array.isArray(o?.payload?.events) ? o.payload.events.length : 0);
  return {
    batches_in_window: obs.length,
    events_in_window: obs.reduce((n, o) => n + events(o), 0),
    latest_observation_id: latest?.observation_id ?? null,
    latest_observed_at: latest?.observed_at ?? null,
    latest_status: latest?.status ?? null,
    latest_event_count: events(latest),
    gap_detected: Boolean(latest?.payload?.gap_detected),
    cursor_after: latest?.payload?.cursor_after ?? null,
  };
}

/** Derive accepted_baseline vs last_observed vs current_observed per watch. */
export function deriveThreeState(watches, baselines, observations) {
  const byWatch = new Map();
  for (const o of observations) {
    if (!byWatch.has(o.watch_id)) byWatch.set(o.watch_id, []);
    byWatch.get(o.watch_id).push(o);
  }
  return watches
    .map((w) => {
      const obs = (byWatch.get(w.id) ?? []).sort((a, b) => b.observation_id - a.observation_id);
      const current = obs[0] ?? null;
      const accepted = baselines.find((b) => b.watch_id === w.id) ?? null;
      if (isStreamWatch(w, current)) {
        return {
          watch_id: w.id,
          class: w.class,
          collector_type: w.collector?.type,
          accepted_baseline: accepted,
          last_observed: null,
          current_observed: slim(current),
          state: current ? 'stream' : 'no_data',
          stream: streamSummary(obs),
          changed_since_last: false,
          promotable_observation_id: null,
        };
      }
      const last = current ? obs.find((o) => o.observation_id < current.observation_id && VALID_OBS.has(o.status)) ?? null : null;
      let state;
      if (!current) state = 'no_data';
      else if (!VALID_OBS.has(current.status)) state = 'collector_error';
      else if (w.class === 'ephemeral') state = 'no_trusted_baseline';
      else if (!accepted) state = 'baseline_absent';
      else state = current.state_hash === accepted.state_hash ? 'in_sync' : 'drift';
      return {
        watch_id: w.id,
        class: w.class,
        collector_type: w.collector?.type,
        accepted_baseline: accepted,
        last_observed: slim(last),
        current_observed: slim(current),
        state,
        changed_since_last: Boolean(current && last && current.state_hash !== last.state_hash),
        promotable_observation_id:
          w.class === 'baseline' && current && VALID_OBS.has(current.status) && state !== 'in_sync'
            ? current.observation_id
            : null,
      };
    })
    .sort((a, b) => (a.class === b.class ? a.watch_id.localeCompare(b.watch_id) : a.class === 'baseline' ? -1 : 1));
}

// ---------------------------------------------------------------------------
// Mitigation proposals (InvestigationRequest::ProposeAction)
// ---------------------------------------------------------------------------

export const ACTION_VERBS = Object.freeze(['nft_block_ip', 'systemd_stop_unit', 'host_isolate']);
export const TRAFFIC_DIRECTIONS = Object.freeze(['inbound', 'outbound', 'both']);

function cidrList(raw) {
  const list = Array.isArray(raw) ? raw : typeof raw === 'string' ? raw.split(/[\s,]+/) : [];
  return list.map((s) => String(s).trim()).filter(Boolean).slice(0, 32);
}

/**
 * Build the exact closed-catalog ActionVerb (crates/protocol/src/action.rs,
 * deny_unknown_fields). Policy limits (protected units/CIDRs, TTL ceilings)
 * are deliberately left to control-d's action gate so the operator sees the
 * real PolicyDecision.
 */
export function buildActionVerb(raw) {
  if (!raw || typeof raw !== 'object') throw new ApiError(400, 'invalid_request', 'verb must be an object');
  const verb = requireEnum(raw.verb, ACTION_VERBS, 'verb.verb');
  const ttl = (optional) => int(raw.ttl_seconds, 'verb.ttl_seconds', { min: 0, max: 10 * 365 * 86_400, optional });
  switch (verb) {
    case 'nft_block_ip':
      return {
        verb,
        ip: requireText(typeof raw.ip === 'string' ? raw.ip.trim() : raw.ip, 'verb.ip', 64),
        direction: requireEnum(raw.direction ?? 'both', TRAFFIC_DIRECTIONS, 'verb.direction'),
        ttl_seconds: ttl(false),
      };
    case 'systemd_stop_unit': {
      const out = { verb, unit: requireText(typeof raw.unit === 'string' ? raw.unit.trim() : raw.unit, 'verb.unit', 256) };
      const t = ttl(true);
      if (t !== null) out.ttl_seconds = t;
      return out;
    }
    case 'host_isolate':
      return { verb, preserve_mgmt_cidrs: cidrList(raw.preserve_mgmt_cidrs), ttl_seconds: ttl(false) };
  }
}

export function parseActionBody(body) {
  if (!body || typeof body !== 'object') throw new ApiError(400, 'invalid_request', 'action proposal body must be an object');
  const ids = Array.isArray(body.evidence_observation_ids) ? body.evidence_observation_ids : [];
  if (ids.length > 100) throw new ApiError(400, 'invalid_request', 'at most 100 evidence observation IDs');
  return {
    run_id: body.run_id ? requireText(body.run_id, 'run_id', 128) : null,
    idempotency_key: body.idempotency_key ? requireText(body.idempotency_key, 'idempotency_key', 128) : `console-action-${randomBytes(8).toString('hex')}`,
    verb: buildActionVerb(body.verb),
    evidence_observation_ids: [...new Set(ids.map((v) => int(v, 'evidence_observation_ids[]', { min: 1 })))].sort((a, b) => a - b),
    expected_effect: requireText(body.expected_effect, 'expected_effect', 4096),
    blast_radius: requireText(body.blast_radius, 'blast_radius', 4096),
    rollback_plan: requireText(body.rollback_plan, 'rollback_plan', 4096),
  };
}

// ---------------------------------------------------------------------------
// "What changed": snapshot diffs for an incident's host
// ---------------------------------------------------------------------------

const FILE_FIELDS = ['status', 'mode_octal', 'uid', 'gid', 'size_bytes', 'sha256', 'mtime_unix'];
const UNIT_FIELDS = ['load_state', 'active_state', 'sub_state', 'unit_file_state', 'main_pid', 'exec_start_hash'];
const SOCKET_FIELDS = ['pid', 'comm', 'systemd_unit', 'uid'];

function setDiff(before, after, key, fields) {
  const a = new Map((before ?? []).map((x) => [x[key], x]));
  const b = new Map((after ?? []).map((x) => [x[key], x]));
  const added = [...b.values()].filter((x) => !a.has(x[key]));
  const removed = [...a.values()].filter((x) => !b.has(x[key]));
  const changed = [];
  for (const [k, now] of b) {
    const was = a.get(k);
    if (!was) continue;
    const delta = fields.filter((f) => (was[f] ?? null) !== (now[f] ?? null)).map((f) => ({ field: f, before: was[f] ?? null, after: now[f] ?? null }));
    if (delta.length) changed.push({ key: k, fields: delta });
  }
  return { added, removed, changed };
}

/** Structured difference between two normalized snapshots of one collector. */
export function diffSnapshot(collectorType, before, after) {
  const b = before ?? {};
  const a = after ?? {};
  switch (collectorType) {
    case 'sockets.listening':
      return { kind: 'set', identity: 'socket_key', ...setDiff(b.sockets, a.sockets, 'socket_key', SOCKET_FIELDS) };
    case 'files.metadata':
      return { kind: 'set', identity: 'path', ...setDiff(b.files, a.files, 'path', FILE_FIELDS) };
    case 'systemd.unit_state': {
      const fields = UNIT_FIELDS.filter((f) => (b[f] ?? null) !== (a[f] ?? null)).map((f) => ({ field: f, before: b[f] ?? null, after: a[f] ?? null }));
      const files = setDiff(b.unit_files, a.unit_files, 'path', ['status', 'sha256', 'size_bytes']);
      return { kind: 'fields', unit: a.unit ?? b.unit ?? null, fields, unit_files: files };
    }
    default:
      return { kind: 'opaque' };
  }
}

const diffSize = (d) =>
  d.kind === 'set'
    ? d.added.length + d.removed.length + d.changed.length
    : d.kind === 'fields'
      ? d.fields.length + d.unit_files.added.length + d.unit_files.removed.length + d.unit_files.changed.length
      : 0;

const snapshotData = (o) => (o && (o.payload?.kind === 'snapshot' || o.payload?.kind === 'delta') ? o.payload.data : null);

/**
 * For each snapshot watch on the incident's host, compare the accepted
 * baseline (when one exists and its observation is still in the window) or,
 * failing that, the state just before the incident opened, against the
 * latest valid observation.
 */
export function buildIncidentChanges({ incident, watches, baselines, observationsByWatch }) {
  const opened = Date.parse(incident.created_at);
  const changes = [];
  for (const w of watches) {
    if (isStreamWatch(w)) continue;
    const type = w.collector?.type;
    const obs = (observationsByWatch.get(w.id) ?? []).filter((o) => VALID_OBS.has(o.status) && snapshotData(o)).sort((x, y) => y.observation_id - x.observation_id);
    const latest = obs[0];
    if (!latest) continue;
    const accepted = baselines.find((b) => b.watch_id === w.id) ?? null;
    let reference = null;
    let basis;
    if (accepted) {
      if (accepted.state_hash === latest.state_hash) continue;
      basis = 'accepted_baseline';
      reference = obs.find((o) => o.state_hash === accepted.state_hash) ?? null;
    } else {
      basis = 'before_incident';
      // State at incident open, and the valid sample right before it.
      const atOpen = obs.find((o) => Date.parse(o.observed_at) <= opened + 2_000) ?? obs.at(-1);
      const prior = obs.find((o) => o.observation_id < atOpen.observation_id);
      // This watch did not change when the incident opened.
      if (!prior || prior.state_hash === atOpen.state_hash) continue;
      reference = prior;
    }
    const diff = reference ? diffSnapshot(type, snapshotData(reference), snapshotData(latest)) : { kind: 'unavailable' };
    if (reference && diff.kind !== 'opaque' && diffSize(diff) === 0) continue;
    changes.push({
      watch_id: w.id,
      class: w.class,
      collector_type: type,
      basis,
      accepted_baseline: accepted ? { revision_id: accepted.revision_id, state_hash: accepted.state_hash, approver: accepted.approver, approved_at: accepted.approved_at } : null,
      reference: reference ? slim(reference) : null,
      latest: slim(latest),
      diff,
      size: reference ? diffSize(diff) : null,
    });
  }
  return changes.sort((a, b) => (b.size ?? 0) - (a.size ?? 0) || a.watch_id.localeCompare(b.watch_id));
}

// ---------------------------------------------------------------------------
// Automation status (derived from the audit log; admin interface only)
// ---------------------------------------------------------------------------

const CONSOLE_BACKENDS = new Set(['operator-console']);
const isConsoleActor = (actor) => /^console[-:]/.test(String(actor ?? '')) || actor === 'console-operator';

/** Summarise reasoner-d activity seen in the audit window, separating console-driven runs. */
export function automationSummary(entries) {
  const runs = entries.filter((e) => e.event_type === 'run_started');
  const auto = runs.filter((e) => !CONSOLE_BACKENDS.has(e.payload?.backend_id) && !isConsoleActor(e.actor));
  const autoActors = new Set(auto.map((e) => e.actor));
  const by = (type) => entries.filter((e) => e.event_type === type && !isConsoleActor(e.actor) && (autoActors.has(e.actor) || /reasoner/i.test(String(e.actor))));
  const last = auto.reduce((m, e) => (!m || e.seq_no > m.seq_no ? e : m), null);
  return {
    window_entries: entries.length,
    reasoner_runs: auto.length,
    console_runs: runs.length - auto.length,
    watch_proposals: by('watch_proposed').length,
    findings: by('finding_recorded').length,
    action_proposals: by('action_proposed').length,
    last_run: last
      ? {
          at: last.timestamp,
          actor: last.actor,
          incident_id: last.payload?.incident_id ?? null,
          backend_id: last.payload?.backend_id ?? null,
          model_id: last.payload?.model_id ?? null,
        }
      : null,
  };
}

// ---------------------------------------------------------------------------
// Reasoner activity (Phase 9): investigation runs, run events, trigger queue
// ---------------------------------------------------------------------------

export const RUN_STATUSES = Object.freeze(['active', 'expired', 'completed', 'budget_exhausted', 'failed', 'cancelled']);
export const TERMINAL_RUN_STATUSES = Object.freeze(['expired', 'completed', 'budget_exhausted', 'failed', 'cancelled']);
export const RUN_EVENT_KINDS = Object.freeze(['turn_started', 'tool_call', 'tool_result', 'model_text', 'budget_warning', 'note']);
export const TRIGGER_STATUSES = Object.freeze(['pending', 'leased', 'done', 'dead_letter']);
export const REASONER_UNSUPPORTED_MESSAGE = 'reasoner activity requires control-d ≥ Phase 9';
/** How long a trigger may sit pending with no active automated run before the UI says reasoner-d looks stopped. */
export const STALL_SECONDS = 120;

const CONSOLE_PRINCIPAL = /^console[-:]/;

/** Operator sessions are opened by this console (or another human frontend); everything else is reasoner-d. */
export function runOrigin(run) {
  const backend = String(run?.backend_id ?? '');
  const principal = String(run?.principal_id ?? '');
  if (CONSOLE_BACKENDS.has(backend) || CONSOLE_PRINCIPAL.test(principal) || principal === 'console-operator' || run?.model_id === 'human-operator') return 'operator';
  return 'automated';
}

// Secrets must never reach the browser even if a future control-d adds them
// to a free-form object: drop token-ish keys anywhere in the tree. Counters such
// as `tokens`, `input_tokens` and `output_tokens` are kept.
const SECRET_KEY = /^(token|lease_token|capability_token|run_token|api_key|secret|password|authorization)$|(^|_)(secret|password)$/i;

export function redactSecrets(value, depth = 0) {
  if (depth > 8) return null;
  if (Array.isArray(value)) return value.slice(0, 200).map((v) => redactSecrets(v, depth + 1));
  if (value && typeof value === 'object') {
    const out = {};
    for (const [k, v] of Object.entries(value)) {
      if (SECRET_KEY.test(k)) continue;
      out[k] = redactSecrets(v, depth + 1);
    }
    return out;
  }
  if (typeof value === 'string' && value.length > 8192) return `${value.slice(0, 8192)}…`;
  return value;
}

export function parseRunsQuery({ incident_id = null, host_id = null, limit = null } = {}) {
  return {
    incident_id: incident_id ? requireIdent(incident_id, 'incident_id') : null,
    host_id: host_id ? requireIdent(host_id, 'host_id') : null,
    limit: int(limit, 'limit', { min: 1, max: 500, optional: true }) ?? 50,
  };
}

export function parseEventsQuery(runId, { after_seq = null, limit = null } = {}) {
  return {
    run_id: requireIdent(runId, 'run_id'),
    after_seq: int(after_seq, 'after_seq', { min: -1, optional: true }),
    limit: int(limit, 'limit', { min: 1, max: 1000, optional: true }) ?? 200,
  };
}

export function parseTriggersQuery({ incident_id = null, host_id = null, status = null, limit = null } = {}) {
  const statuses = status
    ? [...new Set(String(status).split(',').map((s) => s.trim()).filter(Boolean))].map((s) => requireEnum(s, TRIGGER_STATUSES, 'status'))
    : null;
  return {
    incident_id: incident_id ? requireIdent(incident_id, 'incident_id') : null,
    host_id: host_id ? requireIdent(host_id, 'host_id') : null,
    statuses,
    limit: int(limit, 'limit', { min: 1, max: 500, optional: true }) ?? 100,
  };
}

/** Browser-safe RunSummary: the contract's fields plus `origin`, never a token. */
export function publicRunSummary(r) {
  const s = redactSecrets(r ?? {});
  return {
    run_id: s.run_id,
    incident_id: s.incident_id,
    host_id: s.host_id,
    principal_id: s.principal_id ?? null,
    backend_id: s.backend_id ?? null,
    model_id: s.model_id ?? null,
    status: s.status,
    started_at: s.started_at ?? null,
    expires_at: s.expires_at ?? null,
    ended_at: s.ended_at ?? null,
    outcome: s.outcome ?? null,
    last_event: s.last_event ? publicRunEvent(s.last_event) : null,
    event_count: s.event_count ?? 0,
    findings_count: s.findings_count ?? 0,
    proposals_count: s.proposals_count ?? 0,
    origin: runOrigin(s),
  };
}

export function publicRunEvent(e) {
  const s = redactSecrets(e ?? {});
  const detail = s.detail && typeof s.detail === 'object' && !Array.isArray(s.detail) ? s.detail : s.detail == null ? {} : { text: String(s.detail) };
  return { event_seq: s.event_seq, kind: s.kind, detail, created_at: s.created_at ?? null };
}

/** TriggerSummary without lease tokens (the contract has none; this is defence in depth). */
export function publicTrigger(t) {
  const s = redactSecrets(t ?? {});
  return {
    event_id: s.event_id,
    incident_id: s.incident_id ?? null,
    host_id: s.host_id ?? null,
    watch_id: s.watch_id ?? null,
    status: s.status,
    created_at: s.created_at ?? null,
    updated_at: s.updated_at ?? null,
    lease_owner: s.lease_owner ?? null,
    lease_expires_at: s.lease_expires_at ?? null,
    retry_count: s.retry_count ?? 0,
    reason: s.reason ?? null,
  };
}

// ---------------------------------------------------------------------------
// Expectation rules (Phase 10): closed schema, admin bodies, browser-safe records
// ---------------------------------------------------------------------------
//
// control-d deserializes ExpectationRuleSpec with deny_unknown_fields, so a
// stray key or a wrong type makes it close the socket instead of answering.
// The BFF therefore checks the exact *shape* here (keys, types, enums) and
// rebuilds the spec field by field. Policy bounds (clause counts, text sizes,
// identity anchors, port bounds, expiry) are deliberately left to control-d's
// rule gate, so the operator sees its real `rule-gate/*` decision.

/** Every CollectorType value control-d can deserialize; the gate decides which are rule-capable. */
export const RULE_COLLECTORS = Object.freeze(['sockets.listening', 'systemd.unit_state', 'files.metadata', 'journal.unit_events', 'connections.outbound', 'packages.inventory']);
export const RULE_EFFECTS = Object.freeze(['allow_optional', 'require_present', 'ignore_modified']);
export const RULE_OPS = Object.freeze(['eq', 'in', 'range', 'prefix']);
export const RULE_STATUSES = Object.freeze(['active', 'proposed', 'rejected', 'revoked', 'expired']);
export const RULES_UNSUPPORTED_MESSAGE = 'expectation rules require control-d ≥ Phase 10';
const RULE_FIELD_RE = /^[a-z][a-z0-9_]{0,63}$/;
// Transport sanity only (the 64 KiB body limit applies too); the gate enforces 1..=8 and 1..=32.
const MAX_WIRE_CLAUSES = 64;
const MAX_WIRE_VALUES = 256;
const I64_MIN = -(2n ** 63n);
const I64_MAX = 2n ** 63n - 1n;

const bad = (message) => new ApiError(400, 'invalid_request', message);

function exactKeys(obj, allowed, name) {
  if (!obj || typeof obj !== 'object' || Array.isArray(obj)) throw bad(`${name} must be an object`);
  for (const k of Object.keys(obj)) {
    if (!allowed.includes(k)) throw bad(`${name}.${k} is not part of the expectation rule schema (allowed: ${allowed.join(', ')})`);
  }
}

function ruleInt(v, name) {
  if (typeof v !== 'number' || !Number.isSafeInteger(v)) throw bad(`${name} must be an integer`);
  const b = BigInt(v);
  if (b < I64_MIN || b > I64_MAX) throw bad(`${name} is outside the i64 range`);
  return v;
}

/** RuleValue is untagged: an integer, a boolean or a string (floats and objects do not deserialize). */
function ruleValue(v, name) {
  if (typeof v === 'boolean' || typeof v === 'string') return v;
  if (typeof v === 'number') return ruleInt(v, name);
  throw bad(`${name} must be an integer, a boolean or a string`);
}

function ruleField(v, name) {
  if (typeof v !== 'string' || !RULE_FIELD_RE.test(v)) throw bad(`${name} must be a lowercase field name such as systemd_unit or local_port`);
  return v;
}

export function parseMatchClause(raw, i) {
  const name = `rule.matches[${i}]`;
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) throw bad(`${name} must be an object`);
  const op = requireEnum(raw.op, RULE_OPS, `${name}.op`);
  switch (op) {
    case 'eq':
      exactKeys(raw, ['op', 'field', 'value'], name);
      return { op, field: ruleField(raw.field, `${name}.field`), value: ruleValue(raw.value, `${name}.value`) };
    case 'in': {
      exactKeys(raw, ['op', 'field', 'values'], name);
      if (!Array.isArray(raw.values)) throw bad(`${name}.values must be an array`);
      if (raw.values.length > MAX_WIRE_VALUES) throw bad(`${name}.values has more than ${MAX_WIRE_VALUES} entries`);
      return { op, field: ruleField(raw.field, `${name}.field`), values: raw.values.map((v, j) => ruleValue(v, `${name}.values[${j}]`)) };
    }
    case 'range':
      exactKeys(raw, ['op', 'field', 'min', 'max'], name);
      return { op, field: ruleField(raw.field, `${name}.field`), min: ruleInt(raw.min, `${name}.min`), max: ruleInt(raw.max, `${name}.max`) };
    case 'prefix':
      exactKeys(raw, ['op', 'field', 'value'], name);
      if (typeof raw.value !== 'string') throw bad(`${name}.value must be a string`);
      return { op, field: ruleField(raw.field, `${name}.field`), value: raw.value };
  }
}

/** Exact ExpectationRuleSpec (crates/protocol/src/rules.rs) rebuilt from untrusted input. */
export function parseRuleSpec(raw) {
  exactKeys(raw, ['scope', 'matches', 'effect', 'rationale', 'expires_at'], 'rule');
  exactKeys(raw.scope, ['host_id', 'collector', 'watch_id'], 'rule.scope');
  const scope = {
    host_id: requireIdent(raw.scope.host_id, 'rule.scope.host_id'),
    collector: requireEnum(raw.scope.collector, RULE_COLLECTORS, 'rule.scope.collector'),
    watch_id: raw.scope.watch_id === undefined || raw.scope.watch_id === null || raw.scope.watch_id === '' ? null : requireIdent(raw.scope.watch_id, 'rule.scope.watch_id'),
  };
  if (!Array.isArray(raw.matches)) throw bad('rule.matches must be an array of match clauses');
  if (raw.matches.length > MAX_WIRE_CLAUSES) throw bad(`rule.matches has more than ${MAX_WIRE_CLAUSES} clauses`);
  if (typeof raw.rationale !== 'string') throw bad('rule.rationale must be a string');
  if (raw.rationale.length > 4096) throw bad('rule.rationale exceeds 4096 characters');
  let expires_at = null;
  if (raw.expires_at !== undefined && raw.expires_at !== null && raw.expires_at !== '') {
    const t = typeof raw.expires_at === 'string' ? Date.parse(raw.expires_at) : NaN;
    if (!Number.isFinite(t)) throw bad('rule.expires_at must be an RFC 3339 timestamp or null');
    expires_at = new Date(t).toISOString();
  }
  return {
    scope,
    matches: raw.matches.map(parseMatchClause),
    effect: requireEnum(raw.effect, RULE_EFFECTS, 'rule.effect'),
    rationale: raw.rationale,
    expires_at,
  };
}

/** Body of POST /api/admin/rules and /api/admin/rules/backtest: `{ rule, actor? }`. */
export function parseRuleBody(body, { actor = false } = {}) {
  if (!body || typeof body !== 'object') throw bad('request body must be an object');
  const rule = parseRuleSpec(body.rule);
  return actor ? { rule, actor: requireText(body.actor, 'actor', 128) } : { rule };
}

export function parseRuleId(id) {
  if (typeof id !== 'string' || !/^rule-[A-Za-z0-9-]{1,80}$/.test(id)) throw bad('rule_id must look like rule-<uuid>');
  return id;
}

export function parseRuleDecision(body) {
  if (!body || typeof body !== 'object') throw bad('request body must be an object');
  if (typeof body.approve !== 'boolean') throw bad('approve must be true or false');
  const note = body.note === undefined || body.note === null || (typeof body.note === 'string' && !body.note.trim()) ? null : body.note;
  if (note !== null && (typeof note !== 'string' || note.length > 1024)) throw bad('note must be text of at most 1024 characters');
  return { approve: body.approve, note, actor: requireText(body.actor, 'actor', 128) };
}

export function parseRuleRevoke(body) {
  if (!body || typeof body !== 'object') throw bad('request body must be an object');
  if (typeof body.reason !== 'string' || !body.reason.trim()) throw bad('a revocation reason is required');
  return { reason: requireText(body.reason, 'reason', 1024), actor: requireText(body.actor, 'actor', 128) };
}

export function parseRulesQuery({ status = null, host_id = null, limit = null, before = null } = {}) {
  const statuses = status
    ? [...new Set(String(status).split(',').map((s) => s.trim()).filter(Boolean))].map((s) => requireEnum(s, RULE_STATUSES, 'status'))
    : null;
  return {
    statuses,
    host_id: host_id ? requireIdent(host_id, 'host_id') : null,
    limit: int(limit, 'limit', { min: 1, max: 100, optional: true }) ?? 100,
    before: before === null ? null : requireText(before, 'before', 256),
  };
}

export function publicRuleSuppression(suppression) {
  if (!Array.isArray(suppression?.rules) || !suppression.rules.length) return null;
  return {
    total: suppression.total,
    rules: suppression.rules.map(({ rule_id, rationale, suppressed_keys, count }) => ({
      rule_id, rationale, suppressed_keys: suppressed_keys.slice(0, 20), count,
    })),
  };
}

export function publicBacktest(b) {
  if (!b || typeof b !== 'object') return null;
  const n = (v) => (Number.isFinite(v) ? v : 0);
  return {
    observations_scanned: n(b.observations_scanned),
    triggered_before: n(b.triggered_before),
    triggered_after: n(b.triggered_after),
    items_matched: n(b.items_matched),
    sample_keys: Array.isArray(b.sample_keys) ? b.sample_keys.slice(0, 10).map(String) : [],
    currently_matching: n(b.currently_matching),
  };
}

/** Browser-safe ExpectationRuleRecord: exactly the contract's fields, nothing token-like. */
export function publicRuleRecord(r) {
  const s = redactSecrets(r ?? {});
  return {
    rule_id: s.rule_id,
    status: s.status,
    origin: s.origin ?? null,
    proposed_by: s.proposed_by ?? null,
    run_id: s.run_id ?? null,
    incident_id: s.incident_id ?? null,
    spec: s.spec ?? null,
    backtest: publicBacktest(s.backtest),
    created_at: s.created_at ?? null,
    decided_by: s.decided_by ?? null,
    decided_at: s.decided_at ?? null,
    decision_note: s.decision_note ?? null,
    hit_count: Number.isFinite(s.hit_count) ? s.hit_count : 0,
    last_matched_at: s.last_matched_at ?? null,
  };
}

/** Identify legacy and current admin rule gate errors. */
export const isRuleGateCode = (code) => typeof code === 'string' && code.startsWith('rule-gate/');
