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
      const last = current ? obs.find((o) => o.observation_id < current.observation_id && VALID_OBS.has(o.status)) ?? null : null;
      const accepted = baselines.find((b) => b.watch_id === w.id) ?? null;
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
