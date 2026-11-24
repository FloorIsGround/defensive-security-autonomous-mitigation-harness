// Demo-mode port of control-d's deterministic proposal gate
// (crates/policy/src/control_gate.rs + edge_floor.rs). Rule IDs, ordering and
// reason strings mirror the Rust implementation so the console behaves the
// same offline as it does against a real control-d.

import { canonicalJson } from './audit-chain.mjs';

export const POLICY_VERSION = 1;

export const EDGE_FLOOR = Object.freeze({
  min_interval_seconds: 15,
  max_timeout_seconds: 30,
  max_watches_total: 32,
  max_ephemeral_watches: 10,
  max_ephemeral_ttl_seconds: 4 * 3600,
  max_clock_skew_seconds: 300,
  max_ephemeral_runs: 1000,
  max_paths_per_file_watch: 64,
  max_file_hash_bytes: 10 * 1024 * 1024,
  max_journal_batch_events: 100,
  max_journal_message_bytes: 512,
  allowed_collectors: ['sockets.listening', 'systemd.unit_state', 'files.metadata', 'journal.unit_events'],
  approved_file_roots: ['/etc/systemd/system', '/etc/ssh', '/etc/nginx', '/etc/cron.d', '/usr/lib/systemd/system'],
  denied_path_prefixes: ['/etc/shadow', '/etc/gshadow', '/etc/sudoers', '/etc/sudoers.d', '/etc/ssl/private', '/home', '/root', '/proc', '/sys', '/dev'],
  denied_filename_suffixes: ['.key', '.pem', '.p12', '.pfx', '_key'],
  denied_exact_filenames: ['id_rsa', 'id_ed25519', 'id_ecdsa', 'id_dsa', 'authorized_keys', 'shadow', 'gshadow'],
});

export const CONTROL_QUOTAS = Object.freeze({
  max_ephemeral_per_incident: 5,
  max_ephemeral_per_host: 10,
  max_proposals_per_incident: 25,
  max_equivalent_renewals_per_incident: 1,
});

const isIdent = (s) => typeof s === 'string' && /^[A-Za-z0-9._-]{1,96}$/.test(s);
const isField = (s) => typeof s === 'string' && /^[A-Za-z0-9_.]{1,64}$/.test(s);
const UNIT_SUFFIXES = ['.service', '.socket', '.timer', '.target', '.path', '.mount', '.scope', '.slice'];

export function validateUnitName(unit) {
  if (typeof unit !== 'string' || unit.length === 0 || Buffer.byteLength(unit) > 128) return 'systemd unit name must be 1..=128 bytes';
  if (unit.startsWith('-') || unit.includes('..')) return `unsafe systemd unit name '${unit}'`;
  if (!/^[A-Za-z0-9\-_.@:]+$/.test(unit)) return `systemd unit name '${unit}' contains forbidden characters`;
  if (!UNIT_SUFFIXES.some((s) => unit.endsWith(s))) return `systemd unit name '${unit}' must end with an allowed unit suffix`;
  return null;
}

const components = (p) => p.split('/').filter((c) => c.length > 0);
function startsWithPath(path, root) {
  const a = components(path);
  const b = components(root);
  return b.length <= a.length && b.every((c, i) => a[i] === c);
}

export function validateFilePath(raw, cfg = EDGE_FLOOR) {
  if (typeof raw !== 'string' || raw.length === 0 || Buffer.byteLength(raw) > 512) return 'file path length must be 1..=512 bytes';
  // eslint-disable-next-line no-control-regex
  if (/[\x00-\x1f]/.test(raw)) return 'file path contains control characters or NUL';
  if (!raw.startsWith('/')) return `file path '${raw}' must be absolute`;
  if (components(raw).some((c) => c === '.' || c === '..')) return `file path '${raw}' contains forbidden traversal component`;
  if (cfg.denied_path_prefixes.some((d) => startsWithPath(raw, d))) return `file path '${raw}' is blocked by local sensitive path denylist`;
  const parts = components(raw);
  const fname = parts[parts.length - 1];
  if (!fname) return `file path '${raw}' must refer to a regular file`;
  const lower = fname.toLowerCase();
  if (cfg.denied_exact_filenames.some((d) => d.toLowerCase() === lower)) return `filename '${fname}' is blocked by local sensitive filename denylist`;
  if (cfg.denied_filename_suffixes.some((s) => lower.endsWith(s.toLowerCase()))) return `filename '${fname}' matches a denied sensitive suffix`;
  const under = cfg.approved_file_roots.some((root) => startsWithPath(raw, root) && components(raw).length > components(root).length);
  if (!under) return `file path '${raw}' is outside all locally approved file roots`;
  return null;
}

function collectorParamsError(collector, cfg) {
  const p = collector.parameters ?? {};
  switch (collector.type) {
    case 'sockets.listening':
      return !p.include_tcp && !p.include_udp ? 'sockets.listening must include at least one of tcp or udp' : null;
    case 'systemd.unit_state':
      return validateUnitName(p.unit);
    case 'files.metadata': {
      if (!p.paths?.length) return 'files.metadata requires at least one path';
      if (p.paths.length > cfg.max_paths_per_file_watch) return `files.metadata path count ${p.paths.length} exceeds ceiling ${cfg.max_paths_per_file_watch}`;
      if (p.max_file_bytes != null && (p.max_file_bytes === 0 || p.max_file_bytes > cfg.max_file_hash_bytes)) {
        return `max_file_bytes ${p.max_file_bytes} must be within 1..=${cfg.max_file_hash_bytes}`;
      }
      for (const path of p.paths) {
        const e = validateFilePath(path, cfg);
        if (e) return e;
      }
      return null;
    }
    case 'journal.unit_events': {
      const e = validateUnitName(p.unit);
      if (e) return e;
      if (p.min_priority != null && p.min_priority > 7) return 'journal.unit_events min_priority must be 0..=7';
      if (p.max_events_per_batch != null && (p.max_events_per_batch === 0 || p.max_events_per_batch > cfg.max_journal_batch_events)) {
        return `max_events_per_batch ${p.max_events_per_batch} must be within 1..=${cfg.max_journal_batch_events}`;
      }
      if (p.max_message_bytes != null && (p.max_message_bytes === 0 || p.max_message_bytes > cfg.max_journal_message_bytes)) {
        return `max_message_bytes ${p.max_message_bytes} must be within 1..=${cfg.max_journal_message_bytes}`;
      }
      return null;
    }
    default:
      return `collector '${collector.type}' is not allowed by local safety floor`;
  }
}

function triggerError(t, collectorType) {
  switch (t.type) {
    case 'field_changed':
      if (!t.fields?.length || t.fields.length > 32) return 'field_changed must specify 1..=32 fields';
      for (const f of t.fields) if (!isField(f)) return `invalid field name '${f}'`;
      return null;
    case 'set_diff':
      return !isField(t.set_field) || !isField(t.identity_key) ? 'set_diff field names must be valid identifiers' : null;
    case 'threshold_sustained':
      if (!isField(t.field)) return `invalid threshold field '${t.field}'`;
      if (t.consecutive_samples === 0 || t.consecutive_samples > 1000) return 'consecutive_samples must be within 1..=1000';
      if (collectorType === 'journal.unit_events') return 'threshold_sustained is only valid on snapshot collectors';
      return null;
    case 'collector_stale_or_error':
      return t.max_stale_seconds === 0 || t.consecutive_errors === 0 ? 'collector_stale_or_error thresholds must be >= 1' : null;
    default:
      return 'unknown trigger type';
  }
}

/** Port of edge_floor::validate_watch_spec. Returns an error string or null. */
export function safetyFloorError(spec, now = Date.now(), cfg = EDGE_FLOOR) {
  const err = (reason) => `invalid watch '${spec.id}': ${reason}`;
  if (!isIdent(spec.id)) return err('watch id must be 1..=96 chars of [A-Za-z0-9._-]');
  if (!(spec.version >= 1)) return err('watch version must be >= 1');
  if (!cfg.allowed_collectors.includes(spec.collector.type)) return err(`collector '${spec.collector.type}' is not allowed by local safety floor`);
  const { interval_seconds: iv, timeout_seconds: to } = spec.schedule;
  if (iv < cfg.min_interval_seconds) return err(`interval_seconds ${iv} is below local floor ${cfg.min_interval_seconds}`);
  if (to === 0 || to > cfg.max_timeout_seconds) return err(`timeout_seconds ${to} must be within 1..=${cfg.max_timeout_seconds}`);
  if (to >= iv) return err('timeout_seconds must be strictly less than interval_seconds');
  if (spec.class === 'ephemeral') {
    if (!spec.lifecycle.expires_at) return err('ephemeral watch must declare lifecycle.expires_at');
    const maxExpiry = now + (cfg.max_ephemeral_ttl_seconds + cfg.max_clock_skew_seconds) * 1000;
    if (Date.parse(spec.lifecycle.expires_at) > maxExpiry) return err(`ephemeral watch expires_at exceeds maximum TTL of ${cfg.max_ephemeral_ttl_seconds}s`);
    const mr = spec.lifecycle.max_runs;
    if (mr == null) return err('ephemeral watch must declare lifecycle.max_runs');
    if (mr === 0 || mr > cfg.max_ephemeral_runs) return err(`ephemeral watch max_runs ${mr} must be within 1..=${cfg.max_ephemeral_runs}`);
    if ((spec.trigger.type === 'field_changed' || spec.trigger.type === 'set_diff') && spec.trigger.compare_against === 'accepted_baseline') {
      return err('ephemeral watch cannot compare against accepted_baseline; use last_observed');
    }
  }
  const pe = collectorParamsError(spec.collector, cfg);
  if (pe) return err(pe);
  const te = triggerError(spec.trigger, spec.collector.type);
  if (te) return err(te);
  return null;
}

export const watchFingerprint = (spec) => canonicalJson({ host_id: spec.host_id, collector: spec.collector });

export function isActiveWatch(w, now = Date.now()) {
  return w.lifecycle.enabled && !w.retired && (!w.lifecycle.expires_at || Date.parse(w.lifecycle.expires_at) > now);
}

/**
 * Port of control_gate::evaluate_watch_proposal for an investigator-role
 * capability scoped to one incident, plus control-d's post-checks.
 */
export function evaluateProposal({ capability, spec, incident, hostWatches, priorProposalCount, priorEquivalent, now = Date.now() }) {
  const deny = (rule_id, reason) => ({ allowed: false, rule_id, reason, policy_version: POLICY_VERSION });
  if (Date.parse(capability.expires_at) <= now) return deny('cap.expired', 'capability token has expired');
  if (capability.role === 'observer') return deny('role.observer_readonly', 'observer role cannot submit watch proposals');
  if (spec.class === 'baseline') {
    return deny('baseline.protected', 'reasoning/investigator identities cannot create or modify baseline watches');
  }
  if (!capability.allowed_hosts.includes(spec.host_id)) return deny('scope.host_denied', `host '${spec.host_id}' is outside capability scope`);
  if (!capability.allowed_collectors.includes(spec.collector.type)) {
    return deny('scope.collector_denied', `collector '${spec.collector.type}' is outside capability scope`);
  }
  if (!capability.incident_id) return deny('scope.missing_incident', 'ephemeral watch proposal requires an incident-scoped capability');
  if (spec.incident_id !== capability.incident_id) return deny('scope.incident_mismatch', 'watch incident_id must match capability incident scope');

  const floor = safetyFloorError(spec, now);
  if (floor) return deny('spec.safety_floor', floor);

  const active = hostWatches.filter((w) => isActiveWatch(w, now));
  const incidentEphemeral = active.filter((w) => w.class === 'ephemeral' && w.incident_id === incident.incident_id);
  if (incidentEphemeral.length >= CONTROL_QUOTAS.max_ephemeral_per_incident) {
    return deny('quota.incident_ephemeral_cap', `incident already has ${incidentEphemeral.length} active ephemeral watches (cap ${CONTROL_QUOTAS.max_ephemeral_per_incident})`);
  }
  const hostEphemeral = active.filter((w) => w.class === 'ephemeral').length;
  if (hostEphemeral >= CONTROL_QUOTAS.max_ephemeral_per_host) {
    return deny('quota.host_ephemeral_cap', `host '${spec.host_id}' already has ${hostEphemeral} active ephemeral watches (cap ${CONTROL_QUOTAS.max_ephemeral_per_host})`);
  }
  if (priorProposalCount >= CONTROL_QUOTAS.max_proposals_per_incident) {
    return deny('quota.incident_proposal_cap', `incident proposal limit (${CONTROL_QUOTAS.max_proposals_per_incident}) reached`);
  }
  const fp = watchFingerprint(spec);
  if (active.some((w) => watchFingerprint(w) === fp)) {
    return deny('dedup.equivalent_active_watch', 'an equivalent watch with the same host and collector target is already active');
  }
  if ((priorEquivalent.get(fp) ?? 0) > CONTROL_QUOTAS.max_equivalent_renewals_per_incident) {
    return deny('quota.renewal_loop_blocked', 'equivalent ephemeral watch renewal limit exceeded for this incident');
  }
  // control-d post-checks (crates/control-d/src/investigation.rs::propose)
  if (hostWatches.some((w) => w.id === spec.id)) return deny('spec.watch_id_exists', 'watch ID already exists on this host');
  if (active.length >= EDGE_FLOOR.max_watches_total || hostEphemeral >= EDGE_FLOOR.max_ephemeral_watches) {
    return deny('quota.bundle_safety', 'host bundle has reached its safety limit');
  }
  return { allowed: true, rule_id: 'policy.accepted', reason: 'watch specification satisfies central policy and safety floor', policy_version: POLICY_VERSION };
}
