// Demo expectation rules (Phase 10): a port of control-d's rule gate
// (crates/policy/src/rule_gate.rs), the pure set_diff rule evaluation
// (crates/policy/src/rules.rs) and the rule store lifecycle
// (crates/control-d/src/expectation_rules.rs), so the console behaves the same
// offline as against a real control-d. Rule IDs and reason strings mirror Rust.

import { randomUUID } from 'node:crypto';
import { canonicalJson, sha256Hex } from './audit-chain.mjs';
import { POLICY_VERSION } from './demo-policy.mjs';
import { ApiError, publicRuleRecord } from './domain.mjs';

const MIN = 60_000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;

// Closed registry (rule_gate.rs REGISTRY).
const REGISTRY = {
  'sockets.listening': {
    set_field: 'sockets',
    identity_key: 'socket_key',
    fields: { protocol: 'text', local_addr: 'text', local_port: 'int', uid: 'int', comm: 'text', systemd_unit: 'text', bind_scope: 'text' },
    constraints: 'sockets',
  },
  'connections.outbound': {
    set_field: 'flows',
    identity_key: 'flow_key',
    fields: { protocol: 'text', remote_addr: 'text', remote_port: 'int', uid: 'int', comm: 'text', systemd_unit: 'text', remote_scope: 'text' },
    constraints: 'connections',
  },
  'packages.inventory': {
    set_field: 'packages',
    identity_key: 'package_key',
    fields: { name: 'text', arch: 'text' },
    constraints: 'packages',
  },
};

const bytes = (s) => Buffer.byteLength(String(s), 'utf8');
const isInt = (v) => typeof v === 'number' && Number.isInteger(v);

// ---------------------------------------------------------------------------
// Matching (rules.rs clause_matches / item_matches)
// ---------------------------------------------------------------------------

function clauseMatches(clause, sample) {
  const equals = (value) => {
    if (isInt(value)) return isInt(sample) && sample === value;
    if (typeof value === 'boolean') return sample === value;
    return typeof sample === 'string' && sample === value;
  };
  switch (clause.op) {
    case 'eq':
      return equals(clause.value);
    case 'in':
      return clause.values.some(equals);
    case 'range':
      return isInt(sample) && sample >= clause.min && sample <= clause.max;
    case 'prefix':
      return typeof sample === 'string' && sample.startsWith(clause.value);
    default:
      return false;
  }
}

function parseV4(s) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(s);
  if (!m) return null;
  const o = m.slice(1).map(Number);
  return o.every((x) => x <= 255) ? o : null;
}

/** IPv6 → 8 hextets, or null. An embedded dotted quad (e.g. ::ffff:127.0.0.1) fills the last two. */
function parseV6(s) {
  if (!s.includes(':')) return null;
  let body = s;
  let tail = [];
  const dotted = /:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/.exec(s);
  if (dotted) {
    const o = parseV4(dotted[1]);
    if (!o) return null;
    tail = [(o[0] << 8) | o[1], (o[2] << 8) | o[3]];
    body = s.slice(0, -dotted[1].length);
    if (!body.endsWith('::')) body = body.slice(0, -1);
  }
  const halves = body.split('::');
  if (halves.length > 2) return null;
  const part = (x) => (x ? x.split(':').map((h) => (/^[0-9a-fA-F]{1,4}$/.test(h) ? parseInt(h, 16) : NaN)) : []);
  const head = part(halves[0]);
  const rest = halves.length === 2 ? part(halves[1]) : [];
  let words;
  if (halves.length === 2) {
    const fill = 8 - tail.length - head.length - rest.length;
    if (fill < 1) return null;
    words = [...head, ...Array(fill).fill(0), ...rest, ...tail];
  } else {
    words = [...head, ...tail];
  }
  return words.length === 8 && words.every((w) => Number.isInteger(w)) ? words : null;
}

export function bindScope(addr) {
  if (typeof addr !== 'string') return null;
  const v4 = parseV4(addr);
  if (v4) return v4[0] === 127 ? 'loopback' : v4.every((x) => x === 0) ? 'any' : 'specific';
  const v6 = parseV6(addr);
  if (!v6) return null;
  if (v6.slice(0, 7).every((x) => x === 0) && v6[7] === 1) return 'loopback';
  if (v6.every((x) => x === 0)) return 'any';
  return 'specific';
}

function remoteScope(addr) {
  if (typeof addr !== 'string') return null;
  const v4 = parseV4(addr);
  if (v4) {
    if (v4[0] === 127) return 'loopback';
    const [a, b] = v4;
    const priv = a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168) || (a === 100 && b >= 64 && b <= 127);
    return priv ? 'private' : 'public';
  }
  const v6 = parseV6(addr);
  if (!v6) return null;
  if (v6.slice(0, 7).every((x) => x === 0) && v6[7] === 1) return 'loopback';
  return (v6[0] & 0xfe00) === 0xfc00 || (v6[0] & 0xffc0) === 0xfe80 ? 'private' : 'public';
}

export function itemMatches(spec, item) {
  return spec.matches.every((clause) => {
    let sample;
    if (clause.field === 'bind_scope') sample = bindScope(item?.local_addr);
    else if (clause.field === 'remote_scope') sample = remoteScope(item?.remote_addr);
    else {
      if (!item || !(clause.field in item)) return false;
      sample = item[clause.field];
    }
    return sample !== null && sample !== undefined && clauseMatches(clause, sample);
  });
}

// ---------------------------------------------------------------------------
// Gate (rule_gate.rs validate_rule)
// ---------------------------------------------------------------------------

function validClause(c) {
  const bounded = (v) => !(typeof v === 'string' && bytes(v) > 256);
  switch (c.op) {
    case 'eq':
      return bounded(c.value);
    case 'in':
      return c.values.length >= 1 && c.values.length <= 32 && c.values.every(bounded);
    case 'range':
      return c.min <= c.max;
    case 'prefix':
      return bytes(c.value) <= 256;
    default:
      return false;
  }
}

function wellTyped(c, kind) {
  const t = (v) => (kind === 'int' ? isInt(v) : typeof v === 'string');
  switch (c.op) {
    case 'eq':
      return t(c.value);
    case 'in':
      return c.values.every(t);
    case 'range':
      return kind === 'int';
    case 'prefix':
      return kind === 'text';
    default:
      return false;
  }
}

const allowsValue = (clauses, field, value) => clauses.filter((c) => c.field === field).every((c) => clauseMatches(c, value));

export function validateRule(spec, origin, nowMs, cfg = {}) {
  const policy_version = cfg.policy_version ?? POLICY_VERSION;
  const deny = (id, reason) => ({ allowed: false, rule_id: `rule-gate/${id}`, reason, policy_version });
  const clauses = spec.matches;
  if (clauses.length < 1 || clauses.length > 8 || !spec.rationale || bytes(spec.rationale) > 1024 || !clauses.every(validClause)) {
    return deny('shape', 'rule clauses or rationale exceed schema bounds');
  }
  const entry = REGISTRY[spec.scope.collector];
  if (!entry) return deny('fields', 'collector does not support expectation rules');
  if (clauses.some((c) => !(c.field in entry.fields) || !wellTyped(c, entry.fields[c.field]))) {
    return deny('fields', 'match field or value type is unsupported by this collector');
  }
  const eqOrIn = (c) => c.op === 'eq' || c.op === 'in';
  if (spec.effect !== 'require_present' && (entry.constraints === 'sockets' || entry.constraints === 'connections') && !clauses.some((c) => ['systemd_unit', 'comm', 'uid'].includes(c.field) && eqOrIn(c))) {
    return deny('identity-anchor', 'rule must constrain systemd_unit, comm, or uid with eq or in');
  }
  if (
    spec.effect !== 'require_present' &&
    entry.constraints === 'packages' &&
    !clauses.some((c) => c.field === 'name' && (eqOrIn(c) || (c.op === 'prefix' && [...c.value].length >= 3)))
  ) {
    return deny('package-name', 'package rule requires a name eq, in, or prefix of at least 3 characters');
  }
  if (spec.effect === 'allow_optional') {
    if (entry.constraints === 'sockets') {
      const allowsScope = (v) => allowsValue(clauses, 'bind_scope', v);
      const loopbackOnly = allowsScope('loopback') && !allowsScope('any') && !allowsScope('specific');
      const portOk = clauses.some(
        (c) => c.field === 'local_port' && (eqOrIn(c) || (c.op === 'range' && (c.max - c.min <= 1024 || (loopbackOnly && c.min >= 1024 && c.max <= 65535)))),
      );
      if (!portOk) return deny('port-bounds', 'socket rule must constrain local_port within the allowed bounds');
      if (
        allowsScope('any') &&
        !(clauses.some((c) => c.field === 'systemd_unit' && c.op === 'eq') && clauses.some((c) => c.field === 'local_port' && (c.op === 'eq' || (c.op === 'in' && c.values.length <= 8))))
      ) {
        return deny('wildcard-bind', 'wildcard bind requires systemd_unit eq and at most 8 explicit ports');
      }
    } else if (entry.constraints === 'connections') {
      if (allowsValue(clauses, 'remote_scope', 'public') && !clauses.some((c) => (c.op === 'prefix' ? c.field === 'remote_addr' && c.value !== '' : c.field === 'remote_addr' || c.field === 'remote_port'))) {
        return deny('public-remote', 'public connections require a remote_addr or remote_port constraint');
      }
    }
  }
  if (origin === 'investigator') {
    if (!spec.expires_at || Date.parse(spec.expires_at) - nowMs > 30 * DAY) return deny('investigator-expiry', 'investigator rule must expire within 30 days');
    if ((cfg.prior_run_proposals ?? 0) >= 3) return deny('run-quota', 'run already proposed 3 expectation rules');
    if ((cfg.pending_host_proposals ?? 0) >= 20) return deny('host-quota', 'host already has 20 pending expectation rules');
  }
  if (spec.expires_at && Date.parse(spec.expires_at) <= nowMs) return deny('expired', 'rule expiry must be in the future');
  return { allowed: true, rule_id: 'rule-gate/accepted', reason: 'expectation rule satisfies policy', policy_version };
}

// ---------------------------------------------------------------------------
// Evaluation (rules.rs apply_expectation_rules) over one set_diff sample
// ---------------------------------------------------------------------------

const keyed = (sample, field, key) => {
  const list = sample?.[field];
  if (!Array.isArray(list)) return null;
  return new Map(list.filter((x) => x && typeof x[key] === 'string').map((x) => [x[key], x]));
};

const comparable = (item, ignore) => {
  if (!ignore?.length) return canonicalJson(item);
  const copy = { ...item };
  for (const f of ignore) delete copy[f];
  return canonicalJson(copy);
};

/** Raw set diff, then rule filtering. Returns whether the outcome still triggers. */
export function evaluateSetDiff(trigger, collector, current, reference, rules) {
  const entry = REGISTRY[collector];
  const cur = keyed(current, trigger.set_field, trigger.identity_key) ?? new Map();
  const ref = keyed(reference, trigger.set_field, trigger.identity_key) ?? new Map();
  let added = [...cur.keys()].filter((k) => !ref.has(k));
  let removed = [...ref.keys()].filter((k) => !cur.has(k));
  let modified = [...cur.keys()].filter((k) => ref.has(k) && comparable(ref.get(k), trigger.ignore_fields) !== comparable(cur.get(k), trigger.ignore_fields));
  const missing = [];
  const suppressed = new Map();
  if (entry && trigger.set_field === entry.set_field && trigger.identity_key === entry.identity_key) {
    for (const rule of [...rules].sort((a, b) => a.rule_id.localeCompare(b.rule_id))) {
      const matching = new Set([...cur].filter(([, item]) => itemMatches(rule.spec, item)).map(([k]) => k));
      const refMatches = (k) => ref.has(k) && itemMatches(rule.spec, ref.get(k));
      if (rule.spec.effect === 'require_present') {
        if (!matching.size) missing.push(rule.rule_id);
        continue;
      }
      const hit = new Set();
      const retain = (keys, f) => keys.filter((k) => (f(k) ? (hit.add(k), false) : true));
      if (rule.spec.effect === 'allow_optional') {
        added = retain(added, (k) => matching.has(k));
        removed = retain(removed, refMatches);
      }
      modified = retain(modified, (k) => matching.has(k));
      if (hit.size) suppressed.set(rule.rule_id, [...hit].sort());
    }
  }
  return { triggered: added.length + removed.length + modified.length + missing.length > 0, added, removed, modified, missing, suppressed };
}

// ---------------------------------------------------------------------------
// Store (expectation_rules.rs RuleStore)
// ---------------------------------------------------------------------------

const VALID_OBS = new Set(['ok', 'partial']);
const snapshotData = (o) => (o && (o.payload?.kind === 'snapshot' || o.payload?.kind === 'delta') ? o.payload.data : null);

function effectiveStatus(r, nowMs) {
  return (r.status === 'proposed' || r.status === 'active') && r.spec.expires_at && Date.parse(r.spec.expires_at) <= nowMs ? 'expired' : r.status;
}

function activeRules(S, host, collector, watchId, nowMs) {
  return S.rules
    .filter((r) => r.status === 'active' && r.spec.scope.host_id === host && r.spec.scope.collector === collector && (!r.spec.scope.watch_id || r.spec.scope.watch_id === watchId) && !(r.spec.expires_at && Date.parse(r.spec.expires_at) <= nowMs))
    .map((r) => ({ rule_id: r.rule_id, spec: r.spec }));
}

/** Newest <= 50 valid samples of in-scope set_diff watches, with the prior sample or accepted baseline as reference. */
export function backtestRule(S, rule, nowMs, incidentId = null) {
  const entry = REGISTRY[rule.scope.collector];
  const watches = new Map(S.watches.filter((w) => w.host_id === rule.scope.host_id).map((w) => [w.id, w]));
  const inScope = (w) =>
    w &&
    w.collector?.type === rule.scope.collector &&
    (!rule.scope.watch_id || w.id === rule.scope.watch_id) &&
    w.trigger?.type === 'set_diff' &&
    w.trigger.set_field === entry.set_field &&
    w.trigger.identity_key === entry.identity_key &&
    (!incidentId || !w.incident_id || w.incident_id === incidentId);
  const samples = S.observations
    .filter((o) => o.host_id === rule.scope.host_id && inScope(watches.get(o.watch_id)) && VALID_OBS.has(o.status) && Array.isArray(snapshotData(o)?.[entry.set_field]))
    .sort((a, b) => b.observation_id - a.observation_id)
    .slice(0, 50);
  const out = { observations_scanned: samples.length, triggered_before: 0, triggered_after: 0, items_matched: 0, sample_keys: [], currently_matching: 0 };
  const items = new Set();
  const candidate = { rule_id: 'backtest-candidate', spec: rule };
  samples.forEach((o, index) => {
    const w = watches.get(o.watch_id);
    const sample = snapshotData(o);
    const keys = [...(keyed(sample, entry.set_field, entry.identity_key) ?? new Map())].filter(([, item]) => itemMatches(rule, item)).map(([k]) => k);
    if (index === 0) out.currently_matching = keys.length;
    for (const k of keys) items.add(k);
    let reference = null;
    if (w.trigger.compare_against === 'last_observed') {
      reference = snapshotData(S.observations.filter((p) => p.watch_id === o.watch_id && p.host_id === o.host_id && p.observation_id < o.observation_id && snapshotData(p)).sort((a, b) => b.observation_id - a.observation_id)[0]);
    } else {
      const rev = S.baselineRevisions
        .filter((b) => b.host_id === o.host_id && b.watch_id === o.watch_id && Date.parse(b.approved_at) < Date.parse(o.observed_at))
        .sort((a, b) => b.revision_id - a.revision_id)[0];
      const refObs = rev ? S.observations.find((p) => p.observation_id === rev.observation_id) ?? S.observations.find((p) => p.watch_id === o.watch_id && p.state_hash === rev.state_hash) : null;
      reference = snapshotData(refObs);
    }
    const active = activeRules(S, w.host_id, rule.scope.collector, w.id, nowMs);
    if (evaluateSetDiff(w.trigger, rule.scope.collector, sample, reference, active).triggered) out.triggered_before += 1;
    if (evaluateSetDiff(w.trigger, rule.scope.collector, sample, reference, [...active, candidate]).triggered) out.triggered_after += 1;
  });
  out.items_matched = items.size;
  out.sample_keys = [...items].sort().slice(0, 10);
  return out;
}

export function listRules(S, { statuses = null, host_id = null, limit = 50, before = null } = {}, nowMs) {
  let cutoff = null;
  if (before !== null) {
    try {
      const cursor = JSON.parse(before);
      if (!Array.isArray(cursor) || cursor.length !== 2 || typeof cursor[0] !== 'string' || !Number.isFinite(Date.parse(cursor[0])) ||
          typeof cursor[1] !== 'string' || !/^[a-zA-Z0-9_.-]{1,96}$/.test(cursor[1])) throw new Error();
      cutoff = { created_at: cursor[0], rule_id: cursor[1] };
    } catch {
      throw new ApiError(400, 'invalid_request', 'invalid expectation rule cursor');
    }
  }
  const compare = (a, b) => Date.parse(b.created_at) - Date.parse(a.created_at) ||
    (a.rule_id < b.rule_id ? -1 : Number(a.rule_id > b.rule_id));
  const pageSize = Math.min(limit ?? 50, 100);
  const page = S.rules
    .map((r) => ({ ...r, status: effectiveStatus(r, nowMs) }))
    .filter((r) => (!host_id || r.spec.scope.host_id === host_id) && (!statuses || statuses.includes(r.status)) && (!cutoff || compare(r, cutoff) > 0))
    .sort(compare)
    .slice(0, pageSize + 1);
  const hasMore = page.length > pageSize;
  if (hasMore) page.pop();
  const last = page.at(-1);
  return { rules: page.map(publicRuleRecord), next_before: hasMore && last ? JSON.stringify([last.created_at, last.rule_id]) : null };
}

function recordDecision(S, appendAudit, actor, decision, context, nowIso) {
  const d = { decision_id: S.nextDecisionId++, proposal_id: null, actor, request_id: `req-${randomUUID().slice(0, 12)}`, decision, created_at: nowIso };
  S.policyDecisions.push(d);
  appendAudit(S.audit, 'policy_decision', actor, { decision_id: d.decision_id, proposal_id: null, ...decision, context }, nowIso);
}

function requireHostKnown(S, host) {
  if (!S.hosts.some((h) => h.host_id === host)) throw new ApiError(404, 'not_found', `unknown host '${host}'`);
}

function storedRule(S, id) {
  const r = S.rules.find((x) => x.rule_id === id);
  if (!r) throw new ApiError(404, 'not_found', 'expectation rule does not exist');
  return r;
}

export function demoBacktest(S, rule, nowMs) {
  const decision = validateRule(rule, 'operator', nowMs);
  if (!decision.allowed) return { allowed: false, decision, backtest: null, rule };
  requireHostKnown(S, rule.scope.host_id);
  return { allowed: true, decision: null, backtest: backtestRule(S, rule, nowMs), rule };
}

export function demoCreate(S, appendAudit, rule, actor, nowMs) {
  const nowIso = new Date(nowMs).toISOString();
  const decision = validateRule(rule, 'operator', nowMs);
  if (decision.allowed) requireHostKnown(S, rule.scope.host_id);
  const rule_id = decision.allowed ? `rule-${randomUUID()}` : null;
  recordDecision(S, appendAudit, actor, decision, { operation: 'create', rule_id, spec: rule }, nowIso);
  if (!decision.allowed) return { allowed: false, decision, rule_id: null, status: null, rule };
  S.rules.push({ rule_id, status: 'active', origin: 'operator', proposed_by: actor, run_id: null, incident_id: null, spec: rule, backtest: null, created_at: nowIso, decided_by: actor, decided_at: nowIso, decision_note: null, hit_count: 0, last_matched_at: null });
  appendAudit(S.audit, 'rule_activated', actor, { rule_id, approver: actor, spec_hash: sha256Hex(canonicalJson(rule)), note: null }, nowIso);
  return { allowed: true, decision: null, rule_id, status: 'active', rule };
}

export function demoDecide(S, appendAudit, ruleId, { approve, note, actor }, nowMs) {
  const nowIso = new Date(nowMs).toISOString();
  const r = storedRule(S, ruleId);
  if (r.status !== 'proposed') throw new ApiError(400, 'invalid_request', 'only proposed rules can be decided');
  const decision = approve
    ? validateRule(r.spec, 'operator', nowMs)
    : { allowed: false, rule_id: 'rule-gate/rejected', reason: 'operator rejected the proposal', policy_version: POLICY_VERSION };
  recordDecision(S, appendAudit, actor, decision, { operation: 'decide', rule_id: ruleId, approve, note }, nowIso);
  if (approve && !decision.allowed) return { allowed: false, decision, rule_id: ruleId, status: 'proposed' };
  Object.assign(r, { status: approve ? 'active' : 'rejected', decided_by: actor, decided_at: nowIso, decision_note: note });
  if (approve) appendAudit(S.audit, 'rule_activated', actor, { rule_id: ruleId, approver: actor, spec_hash: sha256Hex(canonicalJson(r.spec)), note }, nowIso);
  else appendAudit(S.audit, 'rule_rejected', actor, { rule_id: ruleId, note }, nowIso);
  return { allowed: true, decision: null, rule_id: ruleId, status: r.status };
}

export function demoRevoke(S, appendAudit, ruleId, { reason, actor }, nowMs) {
  const nowIso = new Date(nowMs).toISOString();
  const r = storedRule(S, ruleId);
  if (r.status !== 'active') throw new ApiError(400, 'invalid_request', 'only active rules can be revoked');
  recordDecision(S, appendAudit, actor, { allowed: true, rule_id: 'rule-gate/revoked', reason: 'operator revoked the rule', policy_version: POLICY_VERSION }, { operation: 'revoke', rule_id: ruleId, reason }, nowIso);
  Object.assign(r, { status: 'revoked', decided_by: actor, decided_at: nowIso, decision_note: reason });
  appendAudit(S.audit, 'rule_revoked', actor, { rule_id: ruleId, reason }, nowIso);
  return { rule_id: ruleId, status: 'revoked' };
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const sockScope = (host, watch = 'base-sockets-listening') => ({ host_id: host, collector: 'sockets.listening', watch_id: watch });

/**
 * One active operator rule per common case, an investigator proposal waiting
 * for approval (with its stored backtest), and a history of rejected, revoked
 * and expired rules. Backtests are computed against the demo observations.
 */
export const RESOLVER_RULE_ID = 'rule-5e2c7a10-3b1d-4f0e-9a44-0c6f1d2b8e71';

export function buildDemoRules(S, nowMs) {
  const iso = (ago) => new Date(nowMs - ago).toISOString();
  const rule = (o) => ({ backtest: null, decided_by: null, decided_at: null, decision_note: null, hit_count: 0, last_matched_at: null, run_id: null, incident_id: null, ...o });
  const rules = [
    rule({
      rule_id: RESOLVER_RULE_ID, status: 'active', origin: 'operator', proposed_by: 'j.rivera',
      spec: { scope: sockScope('edge-vm-07', null), matches: [{ op: 'eq', field: 'systemd_unit', value: 'systemd-resolved.service' }, { op: 'eq', field: 'bind_scope', value: 'loopback' }, { op: 'in', field: 'local_port', values: [53, 5355] }], effect: 'allow_optional', rationale: 'Stub resolver binds and releases its loopback listeners on network changes.', expires_at: null },
      created_at: iso(9 * DAY), decided_by: 'j.rivera', decided_at: iso(9 * DAY), hit_count: 37, last_matched_at: iso(11 * MIN),
    }),
    rule({
      rule_id: 'rule-8d41f2b6-6a0e-4c58-b1f3-7e2a9c0d4f15', status: 'active', origin: 'operator', proposed_by: 's.lindqvist',
      spec: { scope: sockScope('edge-vm-12'), matches: [{ op: 'eq', field: 'systemd_unit', value: 'sshd.service' }, { op: 'eq', field: 'comm', value: 'sshd' }, { op: 'eq', field: 'local_port', value: 22 }], effect: 'ignore_modified', rationale: 'unattended-upgrades restarts sshd; the socket keeps its key but changes inode and PID.', expires_at: iso(-20 * DAY) },
      created_at: iso(2 * DAY - 2 * HOUR), decided_by: 's.lindqvist', decided_at: iso(2 * DAY - 2 * HOUR), hit_count: 4, last_matched_at: iso(2 * DAY - 2 * HOUR + 5 * MIN),
    }),
    rule({
      rule_id: 'rule-c3a9e5d2-1f47-4b6a-8e0d-52b7f9a1c6e3', status: 'proposed', origin: 'investigator', proposed_by: 'reasoner-d', run_id: 'run-19bd04e7', incident_id: 'inc-2026-0039',
      spec: { scope: sockScope('edge-vm-03'), matches: [{ op: 'eq', field: 'systemd_unit', value: 'nginx.service' }, { op: 'eq', field: 'comm', value: 'nginx' }, { op: 'eq', field: 'protocol', value: 'tcp' }, { op: 'in', field: 'local_port', values: [80, 443] }], effect: 'allow_optional', rationale: 'nginx reloads during approved config pushes (CHG-4471) briefly drop and re-open its listeners on 80/443. Benign, service-anchored, recurring.', expires_at: iso(-14 * DAY) },
      created_at: iso(2 * HOUR + 38 * MIN),
    }),
    rule({
      rule_id: 'rule-0b7d3e91-9c2a-4e65-a3f8-1d6c4b2e7a90', status: 'rejected', origin: 'investigator', proposed_by: 'reasoner-d', run_id: 'run-7f3a91c2', incident_id: 'inc-2026-0042',
      spec: { scope: sockScope('edge-vm-07'), matches: [{ op: 'eq', field: 'systemd_unit', value: 'custom-helper.service' }, { op: 'eq', field: 'comm', value: 'helperd' }, { op: 'eq', field: 'local_port', value: 4444 }, { op: 'eq', field: 'bind_scope', value: 'any' }], effect: 'allow_optional', rationale: 'helperd listener appears to be part of the custom-helper deployment.', expires_at: iso(-6 * DAY) },
      created_at: iso(35 * MIN), decided_by: 'j.rivera', decided_at: iso(20 * MIN), decision_note: 'This listener is the subject of the open incident; do not suppress it.',
    }),
    rule({
      rule_id: 'rule-4f6a2c8e-7d13-4b90-8a5e-3c1f0e9d2b64', status: 'revoked', origin: 'operator', proposed_by: 'm.okafor',
      spec: { scope: sockScope('edge-db-02'), matches: [{ op: 'eq', field: 'uid', value: 113 }, { op: 'range', field: 'local_port', min: 5432, max: 5440 }, { op: 'eq', field: 'bind_scope', value: 'specific' }], effect: 'allow_optional', rationale: 'Postgres replicas during migration rehearsal.', expires_at: null },
      created_at: iso(12 * DAY), decided_by: 'm.okafor', decided_at: iso(5 * DAY), decision_note: 'Migration finished; listeners are fixed again.', hit_count: 12, last_matched_at: iso(5 * DAY + 3 * HOUR),
    }),
    rule({
      rule_id: 'rule-a2e8b4c6-5f39-4d17-9b0a-6e3d1c8f2a45', status: 'active', origin: 'investigator', proposed_by: 'reasoner-d', run_id: 'run-19bd04e7', incident_id: 'inc-2026-0039',
      spec: { scope: sockScope('edge-vm-03'), matches: [{ op: 'eq', field: 'systemd_unit', value: 'certbot.service' }, { op: 'eq', field: 'local_port', value: 80 }, { op: 'eq', field: 'bind_scope', value: 'any' }], effect: 'allow_optional', rationale: 'certbot standalone challenge listener during renewal.', expires_at: iso(3 * DAY) },
      created_at: iso(33 * DAY), decided_by: 'j.rivera', decided_at: iso(33 * DAY - HOUR), decision_note: 'Renewal window only.', hit_count: 2, last_matched_at: iso(4 * DAY),
    }),
  ];
  for (const r of rules.filter((x) => x.origin === 'investigator')) r.backtest = backtestRule({ ...S, rules }, r.spec, nowMs, r.incident_id);
  return rules;
}

/** Audit events for the fixtures, so the chain and the rule history agree. */
export function demoRuleAuditEvents(rules, nowMs) {
  const ago = (t) => nowMs - Date.parse(t);
  const out = [];
  for (const r of rules) {
    if (r.origin === 'investigator') out.push({ ago: ago(r.created_at), event_type: 'rule_proposed', actor: r.proposed_by, payload: { rule_id: r.rule_id, spec: r.spec, run_id: r.run_id, incident_id: r.incident_id, idempotency_key: `reasoner-${r.rule_id.slice(5, 13)}` } });
    if (r.decided_at && (r.status === 'active' || r.status === 'revoked' || r.status === 'expired')) {
      const activated = r.status === 'revoked' ? r.created_at : r.decided_at;
      out.push({ ago: ago(activated) - 1, event_type: 'rule_activated', actor: r.decided_by, payload: { rule_id: r.rule_id, approver: r.decided_by, spec_hash: sha256Hex(canonicalJson(r.spec)), note: r.origin === 'investigator' ? r.decision_note : null } });
    }
    if (r.status === 'revoked') out.push({ ago: ago(r.decided_at), event_type: 'rule_revoked', actor: r.decided_by, payload: { rule_id: r.rule_id, reason: r.decision_note } });
    if (r.status === 'rejected') out.push({ ago: ago(r.decided_at), event_type: 'rule_rejected', actor: r.decided_by, payload: { rule_id: r.rule_id, note: r.decision_note } });
  }
  return out;
}
