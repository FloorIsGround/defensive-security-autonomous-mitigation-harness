// Adaptive investigator (P11–P18) contracts shared by the live and demo
// backends: exact request bodies for the new admin operations, browser-safe
// projections of control-d's free-form `detail` objects, and the derived views
// (host coverage, delegated monitoring from the audit log, review freshness,
// receipt verification) the console renders.
//
// Wire names follow crates/protocol/src/rpc.rs exactly. control-d deserializes
// every request with deny_unknown_fields, so bodies are rebuilt field by field.

import { ApiError, COLLECTOR_TYPES, int, redactSecrets, requireEnum, requireIdent, requireText } from './domain.mjs';

/** HostDiscoveryCoverage collectors (control-d discovery::COLLECTORS). */
export const DISCOVERY_COLLECTORS = Object.freeze(['sockets.listening', 'packages.inventory']);
/** verification.rs effect check results. */
export const CHECK_RESULTS = Object.freeze(['awaiting_evidence', 'verified', 'contradicted', 'indeterminate']);
/** ReconcileActionOutcome is accepted only for these intent states (verification.rs). */
export const RECONCILABLE_STATUSES = Object.freeze(['authorized', 'executed', 'verification_failed', 'rolled_back']);
/** host_reviews.rs: 60 s .. 30 days. */
export const REVIEW_INTERVAL = Object.freeze({ min: 60, max: 2_592_000 });
/** Default monitoring grant ceiling: edge floor max_watches_total. */
export const MAX_GRANT_WATCHES = 32;
/** Rows of the admin audit window used to reconstruct delegated monitoring. */
export const MONITORING_AUDIT_WINDOW = 500;

export const ADAPTIVE_UNSUPPORTED_MESSAGE = 'requires control-d with the adaptive investigator contract (P11–P18)';
export const ADMIN_VIEW_MESSAGE = 'read over the separate admin interface; start the console with --enable-admin --admin-sock';

const DISCOVERY_AGENT_SUFFIX = '+host-discovery-v1';
const DISCOVERY_ENTRY_PREVIEW = 40;

const str = (v) => (typeof v === 'string' ? v : v == null ? null : String(v));
const num = (v) => (Number.isFinite(v) ? v : null);
const ids = (list) => (Array.isArray(list) ? list.filter((x) => Number.isSafeInteger(x)) : []);
const strs = (list, max = 64) => (Array.isArray(list) ? list.filter((x) => typeof x === 'string').slice(0, max) : []);

// ---------------------------------------------------------------------------
// P11: host profile and collector coverage
// ---------------------------------------------------------------------------

export function publicHostProfile(p) {
  if (!p || typeof p !== 'object') return null;
  return {
    host_tags: strs(p.host_tags, 16),
    expected_services: strs(p.expected_services, 64),
    enabled_collectors: strs(p.enabled_collectors, 16),
  };
}

export const supportsDiscovery = (agentVersion) => String(agentVersion ?? '').endsWith(DISCOVERY_AGENT_SUFFIX);

function partialFlag(o) {
  const d = o?.payload?.data;
  if (!d || typeof d !== 'object') return false;
  return Boolean(d.partial_attribution || d.attribution_partial);
}

const truncatedFlag = (o) => Boolean(o?.payload?.data?.truncated);

/** Collector of an observation: from its watch when known, else from the payload shape (e.g. retired discovery watches). */
function observedCollector(o, typeOf) {
  const known = typeOf.get(o.watch_id);
  if (known) return known;
  const p = o.payload ?? {};
  const d = p.data ?? {};
  if (p.kind === 'stream_batch') return 'journal.unit_events';
  if (Array.isArray(d.sockets)) return 'sockets.listening';
  if (Array.isArray(d.flows)) return 'connections.outbound';
  if (Array.isArray(d.packages)) return 'packages.inventory';
  if (Array.isArray(d.files)) return 'files.metadata';
  if (d.unit && d.active_state) return 'systemd.unit_state';
  return null;
}

/**
 * One row per collector type: what the profile enables, what the central floor
 * and caller scope advertise, and what the latest evidence shows. Agents push
 * on change, so the age of the last sample is reported but never read as a gap.
 * `observations` must be newest first; `watches` are the active WatchSpecs.
 */
export function buildCoverage({ capabilities = [], profile = null, watches = [], observations = [] }) {
  const advertised = new Map(capabilities.map((c) => [c.collector_type, c]));
  const typeOf = new Map(watches.map((w) => [w.id, w.collector?.type]));
  return COLLECTOR_TYPES.map((collector) => {
    const cap = advertised.get(collector) ?? null;
    const mine = watches.filter((w) => w.collector?.type === collector);
    const latest = observations.find((o) => observedCollector(o, typeOf) === collector) ?? null;
    let profileState = 'unknown';
    if (profile) profileState = profile.enabled_collectors.includes(collector) ? 'enabled' : 'disabled';
    let state;
    if (profileState === 'disabled') state = 'disabled';
    else if (!cap) state = 'unavailable';
    else if (latest && !['ok', 'partial'].includes(latest.status)) state = 'error';
    else if (latest && (latest.status === 'partial' || partialFlag(latest))) state = 'partial';
    else if (!mine.length) state = latest ? 'sampled' : 'idle';
    else if (!latest) state = 'awaiting_sample';
    else state = 'covered';
    return {
      collector,
      profile: profileState,
      advertised: Boolean(cap),
      sensitivity: cap?.sensitivity ?? null,
      min_interval_seconds: cap?.min_interval_seconds ?? null,
      description: cap?.description ?? null,
      watches: mine.length,
      latest_observation_id: latest?.observation_id ?? null,
      latest_observed_at: latest?.observed_at ?? null,
      latest_status: latest?.status ?? null,
      partial_attribution: latest ? partialFlag(latest) : false,
      truncated: latest ? truncatedFlag(latest) : false,
      state,
    };
  });
}

// ---------------------------------------------------------------------------
// P15: versioned discovery assessments
// ---------------------------------------------------------------------------

function publicEvidence(e) {
  if (!e || typeof e !== 'object') return null;
  return { watch_id: str(e.watch_id), spec_version: num(e.spec_version), observation_id: num(e.observation_id), state_hash: str(e.state_hash), status: str(e.status) };
}

function publicProposal(p) {
  if (!p || typeof p !== 'object') return null;
  const w = p.proposed_watch ?? {};
  return {
    purpose: str(p.purpose) ?? '',
    dependencies: strs(p.dependencies, 8),
    uncertainty: str(p.uncertainty) ?? '',
    visibility_gaps: strs(p.visibility_gaps, 8),
    proposed_watch: { collector: str(w.collector), service_unit: str(w.service_unit), rationale: str(w.rationale) ?? '' },
    citations: ids(p.citations),
  };
}

/** HostAssessment (rpc.rs) without anything outside the contract. */
export function publicAssessment(a) {
  if (!a || typeof a !== 'object') return null;
  return {
    host_id: str(a.host_id),
    version: num(a.version),
    deadline: str(a.deadline),
    collectors: (Array.isArray(a.collectors) ? a.collectors : []).map((c) => ({ collector: str(c.collector), evidence: publicEvidence(c.evidence), gap: str(c.gap) })),
    interpretations: (Array.isArray(a.interpretations) ? a.interpretations : []).map((i) => ({ source_ids: ids(i.source_ids), proposal: publicProposal(i.proposal) })),
  };
}

/** HostDiscoverySample, with only a bounded, typed preview of its entries. */
export function publicSample(s) {
  const sample = s?.sample && typeof s.sample === 'object' ? s.sample : {};
  const isSockets = s?.collector === 'sockets.listening';
  const list = Array.isArray(isSockets ? sample.sockets : sample.packages) ? (isSockets ? sample.sockets : sample.packages) : [];
  const entries = list.slice(0, DISCOVERY_ENTRY_PREVIEW).map((e) =>
    isSockets
      ? { key: str(e.socket_key), protocol: str(e.protocol), local_addr: str(e.local_addr), local_port: num(e.local_port), comm: str(e.comm), systemd_unit: str(e.systemd_unit) }
      : { key: str(e.package_key), name: str(e.name), arch: str(e.arch), version: str(e.version) },
  );
  return {
    collector: str(s?.collector),
    evidence: publicEvidence(s?.evidence),
    omitted_entries: num(s?.omitted_entries) ?? 0,
    total: num(isSockets ? sample.count : sample.total_packages) ?? list.length,
    shown: list.length,
    partial_attribution: Boolean(sample.partial_attribution),
    truncated: Boolean(sample.truncated) || (num(s?.omitted_entries) ?? 0) > 0,
    entries,
  };
}

export function publicAttempt(a) {
  const u = a?.usage && typeof a.usage === 'object' ? a.usage : null;
  return {
    status: str(a?.status),
    lease_until: str(a?.lease_until),
    retry_at: str(a?.retry_at),
    usage: u ? { input_tokens: num(u.input_tokens) ?? 0, output_tokens: num(u.output_tokens) ?? 0, cached_input_tokens: num(u.cached_input_tokens) ?? 0, reasoning_tokens: num(u.reasoning_tokens) ?? 0, cache_creation_input_tokens: num(u.cache_creation_input_tokens) ?? 0 } : null,
    error: str(a?.error),
    assessment_version: num(a?.assessment_version),
  };
}

/** The source IDs a ClaimHostInterpretation must name: the current samples' observations, in assessment order. */
export const discoverySourceIds = (samples) => samples.map((s) => s.evidence?.observation_id).filter((x) => Number.isSafeInteger(x));

export function parseAssessmentVersion(v) {
  return int(v, 'version', { min: 1, max: 4_294_967_295, optional: true });
}

// ---------------------------------------------------------------------------
// P14: incident follow-up questions
// ---------------------------------------------------------------------------

/** ListWatchFollowups item joined with the interpretation recorded in its finding. */
export function publicFollowup(f, findingsById = new Map(), now = Date.now()) {
  const s = redactSecrets(f ?? {});
  const finding = s.finding_id != null ? findingsById.get(s.finding_id) ?? null : null;
  const deadline = str(s.deadline);
  return {
    proposal_id: num(s.proposal_id),
    origin_run: str(s.origin_run),
    watch_id: str(s.watch_id),
    spec_version: num(s.spec_version),
    question: str(s.question) ?? '',
    status: str(s.status),
    deadline,
    overdue: Boolean(deadline && Date.parse(deadline) <= now && s.status !== 'answered'),
    observation_id: num(s.observation_id),
    finding_id: num(s.finding_id),
    interpretation: finding ? str(finding.interpretation) : null,
    summary: finding ? str(finding.summary) : null,
    finding_visible: Boolean(finding),
  };
}

export const findingIndex = (findings = []) => new Map(findings.map((f) => [f.finding_id, f.finding ?? f]));

// ---------------------------------------------------------------------------
// P16: delegated monitoring and corroborated baselines
// ---------------------------------------------------------------------------

function optionalBool(value, name) {
  if (value === undefined || value === null) return false;
  if (typeof value !== 'boolean') throw new ApiError(400, 'invalid_request', `${name} must be a boolean`);
  return value;
}

export function parseGrantBody(body = {}) {
  return {
    principal_id: requireText(body.principal_id, 'principal_id', 128).trim(),
    max_watches: int(body.max_watches, 'max_watches', { min: 0, max: MAX_GRANT_WATCHES }),
    allow_promotion: optionalBool(body.allow_promotion, 'allow_promotion'),
  };
}

export function parseCandidateId(id) {
  return int(id, 'candidate_id', { min: 1 });
}

export function parseCorroborateBody(body = {}) {
  return { rationale: requireText(body.rationale, 'rationale', 512) };
}

export function parseRollbackBody(body = {}) {
  return { expected_baseline: int(body.expected_baseline, 'expected_baseline', { min: 1 }), rationale: requireText(body.rationale, 'rationale', 512) };
}

const isMonitoringIntent = (i) => i && typeof i === 'object' && typeof i.host_id === 'string' && typeof i.watch_id === 'string' && i.change && typeof i.change.operation === 'string';

/**
 * control-d exposes no admin read for monitoring grants or investigator-managed
 * watches, but records every decision as a `policy_decision` audit entry
 * ({policy_version, intent, decision}). Rebuild the host's state from that
 * window, oldest first; `baselines` (BaselineSummaryEntry[]) and `watches`
 * (active WatchSpec[]) cross-check it against current control-d state.
 */
export function deriveMonitoring(entries, hostId, { baselines = [], watches = [], now = Date.now() } = {}) {
  const grants = new Map();
  const managed = new Map();
  const candidates = new Map();
  const decisions = [];
  const sorted = [...entries].sort((a, b) => a.seq_no - b.seq_no);
  for (const e of sorted) {
    if (e.event_type !== 'policy_decision' || !e.payload || typeof e.payload !== 'object') continue;
    const { intent, decision } = e.payload;
    if (!intent || typeof intent !== 'object' || !decision || typeof decision !== 'object') continue;
    const allowed = decision.allowed === true;
    if (intent.admin_op === 'set_monitoring_grant' && intent.host_id === hostId) {
      if (allowed) grants.set(intent.principal_id, { principal_id: str(intent.principal_id), max_watches: num(intent.max_watches) ?? 0, allow_promotion: intent.allow_promotion === true, updated_at: e.timestamp, revoked: !intent.max_watches });
      decisions.push({ at: e.timestamp, actor: e.actor, operation: 'set_grant', watch_id: null, allowed, reason: str(decision.reason), seq_no: e.seq_no });
    } else if (intent.admin_op === 'corroborate_monitoring') {
      const c = candidates.get(intent.candidate_id);
      if (!c) continue;
      if (allowed) Object.assign(c, { corroborated: true, corroboration: str(intent.rationale), corroborated_at: e.timestamp });
      decisions.push({ at: e.timestamp, actor: e.actor, operation: 'corroborate', watch_id: c.watch_id, allowed, reason: allowed ? null : 'candidate already corroborated, promoted or unknown', seq_no: e.seq_no });
    } else if (intent.admin_op === 'rollback_monitoring' && intent.host_id === hostId) {
      if (allowed) {
        for (const c of candidates.values()) if (c.watch_id === intent.watch_id && c.promoted_revision === intent.expected_baseline) Object.assign(c, { rolled_back: true, rolled_back_at: e.timestamp, rollback_rationale: str(intent.rationale) });
        const w = managed.get(intent.watch_id);
        if (w) w.baseline_revision = decision.baseline ?? null;
      }
      decisions.push({ at: e.timestamp, actor: e.actor, operation: 'rollback', watch_id: str(intent.watch_id), allowed, reason: str(decision.reason), seq_no: e.seq_no });
    } else if (isMonitoringIntent(intent) && intent.host_id === hostId) {
      const op = intent.change.operation;
      const watchId = intent.watch_id;
      if (allowed && op === 'apply') {
        const ch = intent.change;
        managed.set(watchId, {
          watch_id: watchId,
          principal_id: e.actor,
          revision: num(decision.revision),
          spec_version: num(ch.spec?.version),
          collector: str(ch.spec?.collector?.type),
          target: str(ch.spec?.collector?.parameters?.unit),
          interval_seconds: num(ch.spec?.schedule?.interval_seconds),
          purpose: str(ch.purpose) ?? '',
          expected_signal: str(ch.expected_signal) ?? '',
          evidence: ids(ch.evidence),
          review_at: str(ch.review_at),
          applied_at: e.timestamp,
          bundle_version: num(decision.bundle_version),
          baseline_revision: managed.get(watchId)?.baseline_revision ?? null,
        });
      } else if (allowed && op === 'provisional' && Number.isSafeInteger(decision.candidate_id)) {
        candidates.set(decision.candidate_id, {
          candidate_id: decision.candidate_id,
          watch_id: watchId,
          principal_id: e.actor,
          observations: ids(intent.change.observations),
          rationale: str(intent.change.rationale) ?? '',
          created_at: e.timestamp,
          corroborated: false,
          corroboration: null,
          corroborated_at: null,
          promoted_revision: null,
          promoted_at: null,
          rolled_back: false,
          rolled_back_at: null,
          rollback_rationale: null,
        });
      } else if (allowed && op === 'promote') {
        const c = candidates.get(intent.change.candidate_id);
        if (c) Object.assign(c, { promoted_revision: num(decision.baseline), promoted_at: e.timestamp });
        const w = managed.get(watchId);
        if (w) w.baseline_revision = num(decision.baseline);
      }
      if (op !== 'inspect' && op !== 'test') decisions.push({ at: e.timestamp, actor: e.actor, operation: op, watch_id: watchId, allowed, reason: str(decision.reason), seq_no: e.seq_no });
    }
  }
  const baselineFor = new Map(baselines.map((b) => [b.watch_id, b]));
  const active = new Set(watches.map((w) => w.id));
  const candidateList = [...candidates.values()].filter((c) => managed.has(c.watch_id) || active.has(c.watch_id)).map((c) => ({
    ...c,
    state: c.rolled_back ? 'rolled_back' : c.promoted_revision != null ? 'trusted' : c.corroborated ? 'corroborated' : 'provisional',
  }));
  const watchList = [...managed.values()].map((w) => {
    const mine = candidateList.filter((c) => c.watch_id === w.watch_id);
    const trusted = mine.find((c) => c.state === 'trusted' && c.promoted_revision === w.baseline_revision) ?? null;
    const pending = mine.find((c) => c.state === 'provisional' || c.state === 'corroborated') ?? null;
    return {
      ...w,
      active: active.has(w.watch_id),
      review_overdue: Boolean(w.review_at && Date.parse(w.review_at) <= now),
      current_baseline: baselineFor.get(w.watch_id) ?? null,
      baseline_state: trusted ? 'trusted' : pending ? pending.state : w.baseline_revision != null ? 'trusted' : 'none',
    };
  });
  return {
    grants: [...grants.values()].sort((a, b) => a.principal_id.localeCompare(b.principal_id)),
    watches: watchList.sort((a, b) => a.watch_id.localeCompare(b.watch_id)),
    candidates: candidateList.sort((a, b) => b.candidate_id - a.candidate_id),
    decisions: decisions.sort((a, b) => b.seq_no - a.seq_no).slice(0, 12).map(({ seq_no, ...d }) => d),
  };
}

// ---------------------------------------------------------------------------
// P17: periodic host reviews
// ---------------------------------------------------------------------------

export function parseScheduleBody(hostId, body = {}) {
  const collectors = Array.isArray(body.collectors) ? [...new Set(body.collectors)] : [];
  if (!collectors.length) throw new ApiError(400, 'invalid_request', 'collectors must name at least one discovery collector');
  for (const c of collectors) requireEnum(c, DISCOVERY_COLLECTORS, 'collectors[]');
  return {
    host_id: requireIdent(hostId, 'host_id'),
    interval_seconds: int(body.interval_seconds, 'interval_seconds', REVIEW_INTERVAL),
    question: requireText(body.question, 'question', 2048),
    collectors: collectors.sort(),
    route: requireText(body.route ?? 'host-review', 'route', 128),
  };
}

/** HostReviewResult (rpc.rs). */
export function publicReview(r) {
  if (!r || typeof r !== 'object') return null;
  return {
    review_id: str(r.review_id),
    question: str(r.question) ?? '',
    assessment_version: num(r.assessment_version),
    completed_at: str(r.completed_at),
    interpretation: str(r.interpretation),
    summary: str(r.summary) ?? '',
    citations: ids(r.citations),
  };
}

/** Whether the latest review still describes the current assessment. */
export function reviewFreshness(review, assessmentVersion, schedule = null, now = Date.now()) {
  if (!review) return { state: schedule ? 'awaiting_first_review' : 'never_reviewed', assessment_version: assessmentVersion ?? null };
  const age = (now - Date.parse(review.completed_at)) / 1000;
  if (assessmentVersion != null && review.assessment_version != null && assessmentVersion > review.assessment_version) {
    return { state: 'assessment_advanced', assessment_version: assessmentVersion, age_seconds: Math.round(age) };
  }
  if (schedule?.interval_seconds && age > schedule.interval_seconds * 1.5) return { state: 'overdue', assessment_version: assessmentVersion ?? null, age_seconds: Math.round(age) };
  return { state: 'current', assessment_version: assessmentVersion ?? null, age_seconds: Math.round(age) };
}

// ---------------------------------------------------------------------------
// P18: receipt postcondition verification and operator reconciliation
// ---------------------------------------------------------------------------

export function parseReconcileBody(body = {}) {
  const raw = body.expected_receipt_id;
  return {
    expected_receipt_id: raw === null || raw === undefined || raw === '' ? null : int(raw, 'expected_receipt_id', { min: 1 }),
    evidence_ref: requireText(body.evidence_ref, 'evidence_ref', 512),
    rationale: requireText(body.rationale, 'rationale', 2048),
  };
}

/**
 * GetActionVerification's free-form `detail` as three separate records:
 * what the executor reported (receipt), what an independent fresh sample
 * observed (outcome), and what an operator attested (reconciliation).
 * `intent` = { status, expires_at } decides whether a reconciliation is admissible.
 */
export function publicVerification(detail, intent = null, now = Date.now()) {
  const d = redactSecrets(detail ?? {});
  const checks = (Array.isArray(d.receipt_checks) ? d.receipt_checks : []).map((c) => ({
    receipt_id: num(c.receipt_id),
    receipt_status: str(c.receipt_status),
    expected_state: str(c.expected_state),
    result: CHECK_RESULTS.includes(c.result) ? c.result : 'indeterminate',
    reason: str(c.reason),
    deadline: str(c.deadline),
    observation_id: num(c.observation_id),
    state_hash: str(c.state_hash),
  }));
  const reconciliations = (Array.isArray(d.operator_reconciliations) ? d.operator_reconciliations : []).map((r) => ({
    receipt_id: num(r.receipt_id),
    evidence_ref: str(r.evidence_ref) ?? '',
    rationale: str(r.rationale) ?? '',
    recorded_at: str(r.recorded_at),
  }));
  const concurrent = (Array.isArray(d.concurrent_service_changes) ? d.concurrent_service_changes : []).map((c) => ({
    receipt_id: num(c.receipt_id),
    before: num(c.before),
    after: num(c.after),
    watch_id: str(c.watch_id),
    state_hash: str(c.state_hash),
  }));
  const latest = checks.reduce((m, c) => (c.receipt_id != null && (m === null || c.receipt_id > m) ? c.receipt_id : m), null);
  const cursor = latest ?? 0;
  const already = reconciliations.find((r) => (r.receipt_id ?? 0) === cursor) ?? null;
  let reconcile = { allowed: false, reason: 'intent state unknown', expected_receipt_id: latest };
  if (intent) {
    if (!RECONCILABLE_STATUSES.includes(intent.status)) reconcile = { allowed: false, reason: `intent status '${intent.status}' has no executed outcome to reconcile`, expected_receipt_id: latest };
    else if (latest === null && intent.expires_at && Date.parse(intent.expires_at) > now) reconcile = { allowed: false, reason: 'an unreceipted authorization can be reconciled only after it expires', expected_receipt_id: null };
    else if (already) reconcile = { allowed: false, reason: 'the latest receipt already has an operator reconciliation', expected_receipt_id: latest, existing: already };
    else reconcile = { allowed: true, reason: null, expected_receipt_id: latest };
  }
  const latestCheck = checks.find((c) => c.receipt_id === latest) ?? null;
  return {
    intent_id: str(d.intent_id),
    precondition_observation_id: num(d.precondition_observation_id),
    expected_effect: str(d.expected_effect) ?? '',
    recovery_plan: str(d.recovery_plan) ?? '',
    receipt_checks: checks,
    concurrent_service_changes: concurrent,
    collateral_coverage: str(d.collateral_coverage),
    operator_reconciliations: reconciliations,
    latest_receipt_id: latest,
    outcome: latestCheck ? latestCheck.result : checks.length ? 'indeterminate' : 'no_receipt',
    reconcile,
  };
}
