// Demo fixtures and in-memory behaviour for the adaptive investigator
// (P11–P18): host profiles, versioned discovery assessments, delegated
// monitoring with corroborated baselines, periodic host reviews, incident
// follow-up questions and receipt postcondition verification.
//
// Monitoring decisions are written to the demo audit chain in exactly the
// shape control-d records them ({policy_version, intent, decision}), and the
// demo reads them back through the same deriveMonitoring() as live mode.

import { canonicalJson, sha256Hex } from './audit-chain.mjs';
import { ApiError, requireIdent } from './domain.mjs';
import { isActiveWatch } from './demo-policy.mjs';
import {
  DISCOVERY_COLLECTORS,
  RECONCILABLE_STATUSES,
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

const MIN = 60_000;
const HOUR = 60 * MIN;
const DAY = 24 * HOUR;
const POLICY_VERSION = 1;
const DISCOVERY_PRINCIPAL = 'reasoner-d:discovery';
export const DISCOVERY_AGENT = '0.2.0+host-discovery-v1';

// ---------------------------------------------------------------------------
// P11 host profiles (admin-owned, reported on Register)
// ---------------------------------------------------------------------------

const ALL = ['connections.outbound', 'files.metadata', 'journal.unit_events', 'packages.inventory', 'sockets.listening', 'systemd.unit_state'];
const PROFILES = {
  'edge-vm-07': { host_tags: ['dmz', 'edge', 'web'], expected_services: ['nginx.service', 'sshd.service'], enabled_collectors: ALL },
  'edge-vm-03': { host_tags: ['edge', 'web'], expected_services: ['nginx.service'], enabled_collectors: ['files.metadata', 'packages.inventory', 'sockets.listening', 'systemd.unit_state'] },
  // The quiet host: enrolled with no declared role or expected services.
  'edge-vm-12': { host_tags: ['edge'], expected_services: [], enabled_collectors: ALL },
  'edge-db-02': { host_tags: ['data', 'postgres'], expected_services: ['postgresql.service'], enabled_collectors: ['packages.inventory', 'sockets.listening', 'systemd.unit_state'] },
  // edge-vm-11 runs an agent from before host profiles: support is unknown.
};

export const demoHostProfile = (hostId) => PROFILES[hostId] ?? null;

// ---------------------------------------------------------------------------
// Watch and observation fixtures (merged into the demo state by demo-data.mjs)
// ---------------------------------------------------------------------------

const managedSpec = (host, id, unit, version, interval) => ({
  id,
  version,
  host_id: host,
  class: 'baseline',
  incident_id: null,
  collector: { type: 'systemd.unit_state', parameters: { unit, hash_unit_files: true } },
  schedule: { interval_seconds: interval, timeout_seconds: 10 },
  trigger: { type: 'field_changed', compare_against: 'last_observed', fields: ['active_state', 'sub_state', 'main_pid'] },
  wake_policy: { cooldown_seconds: 300, max_wakeups_per_hour: 6 },
  lifecycle: { enabled: true, expires_at: null, max_runs: null },
});

const discoverySpec = (host, collector, startedAgo, iso) => ({
  id: `discovery-${sha256Hex(`${host}-${collector}`).slice(0, 8)}-${sha256Hex(`${collector}-${host}`).slice(0, 4)}`,
  version: 1,
  host_id: host,
  class: 'ephemeral',
  incident_id: null,
  collector: collector === 'sockets.listening'
    ? { type: collector, parameters: { include_tcp: true, include_udp: true, include_ipv6: true, resolve_process: false } }
    : { type: collector, parameters: {} },
  schedule: { interval_seconds: 15, timeout_seconds: 1 },
  trigger: { type: 'field_changed', compare_against: 'last_observed', fields: ['count'] },
  wake_policy: { cooldown_seconds: 60, max_wakeups_per_hour: 0 },
  lifecycle: { enabled: true, expires_at: iso(startedAgo - 2 * MIN), max_runs: 1 },
  // control-d retires discovery watches once they expire; keep them out of watch lists.
  retired: true,
});

const DISCOVERY_RUNS = {
  'edge-vm-12': 9 * DAY - 2 * MIN,
  'edge-vm-07': 3 * DAY,
  'edge-vm-03': 26 * MIN,
  'edge-db-02': 5 * DAY,
};

export const discoveryWatchId = (host, collector) => discoverySpec(host, collector, 0, () => null).id;

export function demoAdaptiveWatches(iso) {
  const out = [
    managedSpec('edge-vm-12', 'mon-cron-service', 'cron.service', 1, 60),
    managedSpec('edge-vm-07', 'mon-resolved-service', 'systemd-resolved.service', 2, 30),
  ];
  for (const [host, ago] of Object.entries(DISCOVERY_RUNS)) {
    for (const c of DISCOVERY_COLLECTORS) {
      if (host === 'edge-db-02' && c === 'sockets.listening') continue; // agent went offline first
      if (host === 'edge-vm-03' && c === 'packages.inventory') continue; // issued on first advance
      out.push(discoverySpec(host, c, ago, iso));
    }
  }
  return out;
}

const pkg = (name, version, arch = 'amd64') => ({ package_key: `${name}:${arch}`, name, arch, version });
const pkgSnap = (list, total) => ({
  packages: list,
  total_packages: total,
  status_file_sha256: sha256Hex(`dpkg-status-${list.map((p) => p.package_key).join(',')}`),
  malformed_stanzas: 0,
  truncated: true,
  omitted_packages: total - list.length,
});
const BASE_PKGS = [
  pkg('base-files', '13.1'), pkg('bash', '5.2.21-2'), pkg('coreutils', '9.4-3'), pkg('cron', '3.0pl1-184'), pkg('dbus', '1.14.10-4'),
  pkg('e2fsprogs', '1.47.0-2'), pkg('libc6', '2.39-6'), pkg('libssl3t64', '3.2.2-1'), pkg('openssh-server', '1:9.7p1-7'), pkg('systemd', '256.5-1'),
  pkg('systemd-timesyncd', '256.5-1'), pkg('unattended-upgrades', '2.10'),
];

/** Raw observation rows: [key, host, watch, agoMs, status, payload]. */
export function demoAdaptiveRaw({ sock, sockSnap, unitSnap, BASE_SOCKETS }) {
  const snap = (data) => ({ kind: 'snapshot', data });
  const did = (host, c) => discoveryWatchId(host, c);
  const cron = (pid) => unitSnap('cron.service', pid, '/usr/sbin/cron -f -P', '[Service]\nExecStart=/usr/sbin/cron -f -P\n', 316);
  const resolved = (pid) => unitSnap('systemd-resolved.service', pid, '/usr/lib/systemd/systemd-resolved', '[Service]\nExecStart=!!/usr/lib/systemd/systemd-resolved\n', 1984);
  const dhcp = sock('udp', '0.0.0.0', 68, 0, 14410, null, null, null);
  return [
    // Discovery samples (bounded one-shot snapshots on short-lived discovery watches).
    ['disc12_sock', 'edge-vm-12', did('edge-vm-12', 'sockets.listening'), DISCOVERY_RUNS['edge-vm-12'] - 40_000, 'ok', snap(sockSnap([...BASE_SOCKETS.slice(0, 2), dhcp], true))],
    ['disc12_pkg', 'edge-vm-12', did('edge-vm-12', 'packages.inventory'), DISCOVERY_RUNS['edge-vm-12'] - 45_000, 'ok', snap(pkgSnap([...BASE_PKGS, pkg('popularity-contest', '1.77'), pkg('needrestart', '3.6-8')], 418))],
    ['disc07_sock', 'edge-vm-07', did('edge-vm-07', 'sockets.listening'), DISCOVERY_RUNS['edge-vm-07'] - 30_000, 'ok', snap(sockSnap(BASE_SOCKETS))],
    ['disc07_pkg', 'edge-vm-07', did('edge-vm-07', 'packages.inventory'), DISCOVERY_RUNS['edge-vm-07'] - 35_000, 'ok', snap(pkgSnap([...BASE_PKGS, pkg('nginx', '1.26.2-1'), pkg('nginx-common', '1.26.2-1', 'all'), pkg('systemd-resolved', '256.5-1')], 457))],
    ['disc03_sock', 'edge-vm-03', did('edge-vm-03', 'sockets.listening'), DISCOVERY_RUNS['edge-vm-03'] - 30_000, 'ok', snap(sockSnap(BASE_SOCKETS.slice(0, 3)))],
    ['disc02_pkg', 'edge-db-02', did('edge-db-02', 'packages.inventory'), DISCOVERY_RUNS['edge-db-02'] - 30_000, 'ok', snap(pkgSnap([...BASE_PKGS, pkg('postgresql-16', '16.4-1'), pkg('postgresql-common', '262', 'all'), pkg('pgbackrest', '2.53-1')], 389))],
    // Investigator-managed service watches.
    ['cron_r1', 'edge-vm-12', 'mon-cron-service', 4 * DAY + 20 * MIN, 'ok', snap(cron(655))],
    ['cron_r2', 'edge-vm-12', 'mon-cron-service', 4 * DAY + 10 * MIN, 'ok', snap(cron(655))],
    ['cron_a', 'edge-vm-12', 'mon-cron-service', 2 * DAY + 10 * MIN, 'ok', snap(cron(702))],
    ['cron_b', 'edge-vm-12', 'mon-cron-service', 2 * DAY, 'ok', snap(cron(702))],
    ['cron_c', 'edge-vm-12', 'mon-cron-service', 55 * MIN, 'ok', snap(cron(2210))],
    ['cron_d', 'edge-vm-12', 'mon-cron-service', 45 * MIN, 'ok', snap(cron(2210))],
    ['resolved_m1', 'edge-vm-07', 'mon-resolved-service', 3 * HOUR + 30 * MIN, 'ok', snap(resolved(602))],
    ['resolved_m2', 'edge-vm-07', 'mon-resolved-service', 3 * HOUR, 'ok', snap(resolved(602))],
    ['resolved_m3', 'edge-vm-07', 'mon-resolved-service', 4 * MIN, 'ok', snap(resolved(602))],
  ].map((row) => {
    // Managed watch revision 2 on edge-vm-07 (the interval was strengthened).
    if (row[2] === 'mon-resolved-service') row.push({ spec_version: 2 });
    return row;
  });
}

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------

const coverage = (collector, evidence = null, gap = null) => ({ collector, evidence, gap });
const evidenceOf = (o) => ({ watch_id: o.watch_id, spec_version: o.spec_version, observation_id: o.observation_id, state_hash: o.state_hash, status: o.status });

/**
 * Build the adaptive state. `obsByKey` maps raw keys to stored observations.
 * Returns extra findings, baseline revisions and audit events for the chain.
 */
export function buildDemoAdaptive({ now, iso, obsByKey }) {
  const O = obsByKey;
  const ev = (ago, event_type, actor, payload) => ({ ago, event_type, actor, payload });
  const auditEvents = [];
  const deadline = (ago) => iso(ago - DAY);

  // ---- P15 discovery assessments (every revision kept) ----------------------
  const s = (k) => evidenceOf(O[k]);
  const quiet = {
    purpose: 'Batch maintenance worker: scheduled cron jobs (e2scrub, popularity-contest) with time synchronisation and SSH administration. No inbound application service.',
    dependencies: ['cron.service', 'systemd-timesyncd.service', 'sshd.service'],
    uncertainty: 'Which cron jobs run, and whether any of them reach the network, is not visible: package and socket samples cannot enumerate crontab contents or outbound flows.',
    visibility_gaps: ['UDP 0.0.0.0:68 has no owning process (socket attribution is partial)', 'No service-enumeration collector: running units are inferred from installed packages', 'Outbound connections were not sampled during discovery'],
    proposed_watch: { collector: 'packages.inventory', service_unit: 'cron.service', rationale: 'cron is the only scheduler and the host’s apparent purpose; a failed or restarted cron.service is the most useful signal.' },
    citations: [O.disc12_pkg.observation_id, O.disc12_sock.observation_id],
  };
  const proxy = {
    purpose: 'Public HTTPS reverse proxy (nginx on 443) with SSH administration and a local stub resolver.',
    dependencies: ['nginx.service', 'sshd.service', 'systemd-resolved.service'],
    uncertainty: 'Upstream application servers behind nginx are unknown; nginx configuration is outside the discovery collectors.',
    visibility_gaps: ['Outbound flows to upstreams were not sampled', 'nginx site configuration is not part of the package inventory'],
    proposed_watch: { collector: 'sockets.listening', service_unit: 'nginx.service', rationale: 'nginx owns the only public listener; a stopped or failing unit removes the host’s purpose.' },
    citations: [O.disc07_sock.observation_id, O.disc07_pkg.observation_id],
  };
  const db = {
    purpose: 'PostgreSQL 16 database server with pgBackRest backups.',
    dependencies: ['postgresql.service'],
    uncertainty: 'Listener addresses and client hosts are unconfirmed: the agent went offline before its socket sample.',
    visibility_gaps: ['No socket sample (agent offline before collection)', 'Database clients and replication peers are not observable'],
    proposed_watch: { collector: 'packages.inventory', service_unit: 'postgresql.service', rationale: 'postgresql-16 is installed and expected by the host profile.' },
    citations: [O.disc02_pkg.observation_id],
  };
  const versions = {
    'edge-vm-12': [
      { v: 1, cols: [coverage('sockets.listening', null, 'awaiting_agent'), coverage('packages.inventory', null, 'awaiting_agent')] },
      { v: 2, cols: [coverage('sockets.listening', null, 'awaiting_sample'), coverage('packages.inventory', null, 'awaiting_sample')] },
      { v: 3, cols: [coverage('sockets.listening', s('disc12_sock')), coverage('packages.inventory', s('disc12_pkg'))] },
      { v: 4, cols: [coverage('sockets.listening', s('disc12_sock')), coverage('packages.inventory', s('disc12_pkg'))], interp: [{ source_ids: [O.disc12_sock.observation_id, O.disc12_pkg.observation_id], proposal: quiet }] },
    ],
    'edge-vm-07': [
      { v: 1, cols: [coverage('sockets.listening', null, 'awaiting_sample'), coverage('packages.inventory', null, 'awaiting_sample')] },
      { v: 2, cols: [coverage('sockets.listening', s('disc07_sock')), coverage('packages.inventory', s('disc07_pkg'))] },
      { v: 3, cols: [coverage('sockets.listening', s('disc07_sock')), coverage('packages.inventory', s('disc07_pkg'))], interp: [{ source_ids: [O.disc07_sock.observation_id, O.disc07_pkg.observation_id], proposal: proxy }] },
    ],
    'edge-vm-03': [
      { v: 1, cols: [coverage('sockets.listening', null, 'awaiting_agent'), coverage('packages.inventory', null, 'awaiting_agent')] },
      { v: 2, cols: [coverage('sockets.listening', s('disc03_sock')), coverage('packages.inventory', null, 'awaiting_sample')] },
    ],
    'edge-db-02': [
      { v: 1, cols: [coverage('sockets.listening', null, 'awaiting_sample'), coverage('packages.inventory', s('disc02_pkg'))] },
      { v: 2, cols: [coverage('sockets.listening', null, 'awaiting_agent'), coverage('packages.inventory', s('disc02_pkg'))], interp: [{ source_ids: [O.disc02_pkg.observation_id], proposal: db }] },
      { v: 3, cols: [coverage('sockets.listening', null, 'deadline_elapsed'), coverage('packages.inventory', s('disc02_pkg'))], interp: [{ source_ids: [O.disc02_pkg.observation_id], proposal: db }] },
    ],
    'edge-vm-11': [
      { v: 1, cols: [coverage('sockets.listening', null, 'awaiting_agent'), coverage('packages.inventory', null, 'awaiting_agent')] },
      { v: 2, cols: [coverage('sockets.listening', null, 'agent_unsupported'), coverage('packages.inventory', null, 'agent_unsupported')] },
    ],
  };
  const assessments = new Map();
  for (const [host, list] of Object.entries(versions)) {
    const started = DISCOVERY_RUNS[host] ?? 12 * DAY;
    assessments.set(host, list.map((x) => ({ host_id: host, version: x.v, deadline: deadline(started), collectors: x.cols, interpretations: x.interp ?? [] })));
  }

  const attempts = new Map([
    [`edge-vm-12:${JSON.stringify([O.disc12_sock.observation_id, O.disc12_pkg.observation_id])}`, [
      { status: 'failed', lease_until: iso(9 * DAY - 6 * MIN), retry_at: iso(9 * DAY - 6 * MIN - 30_000), usage: null, error: 'provider_retryable', assessment_version: null },
      { status: 'saved', lease_until: iso(9 * DAY - 9 * MIN), retry_at: iso(9 * DAY - 10 * MIN), usage: { input_tokens: 6120, output_tokens: 842, cached_input_tokens: 3072, reasoning_tokens: 512, cache_creation_input_tokens: 0 }, error: null, assessment_version: 4 },
    ]],
    [`edge-vm-07:${JSON.stringify([O.disc07_sock.observation_id, O.disc07_pkg.observation_id])}`, [
      { status: 'saved', lease_until: iso(3 * DAY - 4 * MIN), retry_at: iso(3 * DAY - 5 * MIN), usage: { input_tokens: 7004, output_tokens: 911, cached_input_tokens: 0, reasoning_tokens: 640, cache_creation_input_tokens: 2048 }, error: null, assessment_version: 3 },
    ]],
    [`edge-db-02:${JSON.stringify([O.disc02_pkg.observation_id])}`, [
      { status: 'failed', lease_until: iso(5 * DAY - 3 * MIN), retry_at: iso(5 * DAY - 3 * MIN - 30_000), usage: { input_tokens: 48_000, output_tokens: 4095, cached_input_tokens: 0, reasoning_tokens: 3900, cache_creation_input_tokens: 0 }, error: 'budget_exhausted', assessment_version: null },
      { status: 'saved', lease_until: iso(5 * DAY - 8 * MIN), retry_at: iso(5 * DAY - 9 * MIN), usage: { input_tokens: 5230, output_tokens: 604, cached_input_tokens: 0, reasoning_tokens: 384, cache_creation_input_tokens: 0 }, error: null, assessment_version: 2 },
    ]],
  ]);

  // ---- P16 delegated monitoring (as policy_decision audit entries) ---------
  const decision = (ago, actor, intent, dec) => auditEvents.push(ev(ago, 'policy_decision', actor, { policy_version: POLICY_VERSION, intent, decision: dec }));
  const change = (host, watch, c) => ({ host_id: host, watch_id: watch, change: c });
  const cronSpec = managedSpec('edge-vm-12', 'mon-cron-service', 'cron.service', 1, 60);
  const resolvedV1 = managedSpec('edge-vm-07', 'mon-resolved-service', 'systemd-resolved.service', 1, 60);
  const resolvedV2 = managedSpec('edge-vm-07', 'mon-resolved-service', 'systemd-resolved.service', 2, 30);
  const id = (k) => O[k].observation_id;

  decision(6 * DAY, 'operator', { admin_op: 'set_monitoring_grant', host_id: 'edge-vm-12', principal_id: DISCOVERY_PRINCIPAL, max_watches: 3, allow_promotion: true }, { allowed: true });
  decision(5 * DAY, DISCOVERY_PRINCIPAL, change('edge-vm-12', 'mon-cron-service', {
    operation: 'apply', spec: cronSpec, expected_revision: 0,
    purpose: 'Assessment v4 found a quiet batch worker whose only scheduler is cron; watch it for failure or unexpected restarts.',
    expected_signal: 'active_state leaves active, or main_pid changes outside the unattended-upgrades window (06:00–06:30 UTC).',
    evidence: [id('disc12_pkg'), id('disc12_sock')], review_at: iso(-25 * DAY),
  }), { allowed: true, revision: 1, bundle_version: 10 });
  decision(4 * DAY + 5 * MIN, DISCOVERY_PRINCIPAL, change('edge-vm-12', 'mon-cron-service', { operation: 'provisional', observations: [id('cron_r1'), id('cron_r2')], rationale: 'Two identical samples ten minutes apart: cron active as PID 655.' }), { allowed: true, candidate_id: 11 });
  decision(4 * DAY + 2 * MIN, 'operator', { admin_op: 'corroborate_monitoring', candidate_id: 11, rationale: 'Matches the hardening checklist for batch workers (CHG-4388).' }, { allowed: true });
  decision(4 * DAY, DISCOVERY_PRINCIPAL, change('edge-vm-12', 'mon-cron-service', { operation: 'promote', candidate_id: 11, expected_baseline: null }), { allowed: true, baseline: 35 });
  auditEvents.push(ev(4 * DAY - 1, 'baseline_promoted', DISCOVERY_PRINCIPAL, { host_id: 'edge-vm-12', watch_id: 'mon-cron-service', revision_id: 35, predecessor_id: null, candidate_id: 11, observation_id: id('cron_r2'), corroboration: 'Matches the hardening checklist for batch workers (CHG-4388).' }));
  decision(3 * DAY, 'operator', { admin_op: 'rollback_monitoring', host_id: 'edge-vm-12', watch_id: 'mon-cron-service', expected_baseline: 35, rationale: 'PID 655 was captured mid-restart by unattended-upgrades; the trusted state must come from a settled sample.' }, { allowed: true, baseline: null, rolled_back: 35 });
  decision(2 * DAY - 5 * MIN, DISCOVERY_PRINCIPAL, change('edge-vm-12', 'mon-cron-service', { operation: 'provisional', observations: [id('cron_a'), id('cron_b')], rationale: 'Stable for ten minutes after the upgrade window: cron active as PID 702.' }), { allowed: true, candidate_id: 12 });
  decision(2 * DAY - 20 * MIN, 'operator', { admin_op: 'corroborate_monitoring', candidate_id: 12, rationale: 'Settled after unattended-upgrades; same unit file hash as the golden image.' }, { allowed: true });
  decision(2 * DAY - 25 * MIN, DISCOVERY_PRINCIPAL, change('edge-vm-12', 'mon-cron-service', { operation: 'promote', candidate_id: 12, expected_baseline: null }), { allowed: true, baseline: 36 });
  auditEvents.push(ev(2 * DAY - 25 * MIN - 1, 'baseline_promoted', DISCOVERY_PRINCIPAL, { host_id: 'edge-vm-12', watch_id: 'mon-cron-service', revision_id: 36, predecessor_id: null, candidate_id: 12, observation_id: id('cron_b'), corroboration: 'Settled after unattended-upgrades; same unit file hash as the golden image.' }));
  decision(26 * HOUR, DISCOVERY_PRINCIPAL, change('edge-vm-12', 'mon-sshd-service', {
    operation: 'apply', spec: managedSpec('edge-vm-12', 'mon-sshd-service', 'sshd.service', 1, 60), expected_revision: 0,
    purpose: 'Watch sshd.service as the only inbound service.', expected_signal: 'sshd.service leaves active/running.',
    evidence: [id('disc12_sock')], review_at: iso(-29 * DAY),
  }), { allowed: false, reason: 'watch exceeds host budget or duplicates existing coverage' });
  decision(40 * MIN, DISCOVERY_PRINCIPAL, change('edge-vm-12', 'mon-cron-service', { operation: 'provisional', observations: [id('cron_c'), id('cron_d')], rationale: 'cron restarted at 06:12 UTC with the package upgrade and has been stable as PID 2210 for ten minutes.' }), { allowed: true, candidate_id: 13 });

  decision(3 * DAY + HOUR, 'operator', { admin_op: 'set_monitoring_grant', host_id: 'edge-vm-07', principal_id: DISCOVERY_PRINCIPAL, max_watches: 4, allow_promotion: false }, { allowed: true });
  decision(2 * DAY, DISCOVERY_PRINCIPAL, change('edge-vm-07', 'mon-resolved-service', {
    operation: 'apply', spec: resolvedV1, expected_revision: 0,
    purpose: 'Assessment v3 lists systemd-resolved as a dependency: nginx resolves every upstream through the 127.0.0.53 stub listener.',
    expected_signal: 'systemd-resolved.service leaves active/running, or its main_pid changes outside a package upgrade.',
    evidence: [id('disc07_sock'), id('disc07_pkg')], review_at: iso(-12 * DAY),
  }), { allowed: true, revision: 1, bundle_version: 11 });
  decision(20 * HOUR, DISCOVERY_PRINCIPAL, change('edge-vm-07', 'mon-resolved-service', {
    operation: 'apply', spec: resolvedV2, expected_revision: 1,
    purpose: 'Strengthen the resolver watch: a 60 s interval missed a 40 s restart loop during CHG-4402 testing.',
    expected_signal: 'systemd-resolved.service leaves active/running, or its main_pid changes outside a package upgrade.',
    evidence: [id('disc07_sock'), id('disc07_pkg')], review_at: iso(-6 * DAY),
  }), { allowed: true, revision: 2, bundle_version: 12 });
  decision(2 * HOUR + 50 * MIN, DISCOVERY_PRINCIPAL, change('edge-vm-07', 'mon-resolved-service', { operation: 'provisional', observations: [id('resolved_m1'), id('resolved_m2')], rationale: 'systemd-resolved active as PID 602 across two samples thirty minutes apart.' }), { allowed: true, candidate_id: 14 });

  const revisions = [
    { revision_id: 35, host_id: 'edge-vm-12', watch_id: 'mon-cron-service', state_hash: O.cron_r2.state_hash, approver: 'operator', approved_at: iso(4 * DAY), ticket_ref: null, rationale: 'Matches the hardening checklist for batch workers (CHG-4388).', observation_id: id('cron_r2') },
    { revision_id: 36, host_id: 'edge-vm-12', watch_id: 'mon-cron-service', state_hash: O.cron_b.state_hash, approver: 'operator', approved_at: iso(2 * DAY - 25 * MIN), ticket_ref: null, rationale: 'Settled after unattended-upgrades; same unit file hash as the golden image.', observation_id: id('cron_b') },
  ];
  // Current pointer per watch when it differs from "latest revision" (rollbacks).
  const baselinePointers = new Map();

  // ---- P17 periodic host reviews -------------------------------------------
  const schedules = new Map([
    ['edge-vm-12', { host_id: 'edge-vm-12', interval_seconds: 86_400, question: 'Has this host’s role, exposure or package set changed since the last assessment?', collectors: ['packages.inventory', 'sockets.listening'], route: 'host-review', set_at: iso(6 * DAY), next_due_at: iso(-(21 * HOUR)) }],
    ['edge-vm-07', { host_id: 'edge-vm-07', interval_seconds: 21_600, question: 'Do the listeners and packages still match a public reverse proxy?', collectors: ['packages.inventory', 'sockets.listening'], route: 'host-review', set_at: iso(3 * DAY), next_due_at: iso(-(5 * HOUR + 35 * MIN)) }],
    ['edge-db-02', { host_id: 'edge-db-02', interval_seconds: 43_200, question: 'Is PostgreSQL still the only service, listening on the data VLAN?', collectors: ['packages.inventory', 'sockets.listening'], route: 'host-review', set_at: iso(5 * DAY), next_due_at: iso(14 * HOUR) }],
  ]);
  const reviews = new Map([
    ['edge-vm-12', { review_id: 'rvw-12-0007', question: schedules.get('edge-vm-12').question, assessment_version: 4, completed_at: iso(3 * HOUR), interpretation: 'supports', summary: 'Package set and listeners are unchanged since assessment v4: SSH is the only inbound service and cron the only scheduler. No new role evidence.', citations: [id('disc12_pkg'), id('disc12_sock'), id('cron_d')] }],
    ['edge-vm-07', { review_id: 'rvw-07-0011', question: schedules.get('edge-vm-07').question, assessment_version: 3, completed_at: iso(25 * MIN), interpretation: 'contradicts', summary: 'A new listener tcp/0.0.0.0:4444 owned by helperd (custom-helper.service) is not explained by the reverse-proxy role in assessment v3, and no installed package owns that unit.', citations: [O.sock_new.observation_id, id('disc07_pkg')] }],
    ['edge-db-02', { review_id: 'rvw-02-0004', question: schedules.get('edge-db-02').question, assessment_version: 2, completed_at: iso(26 * HOUR), interpretation: 'unresolved', summary: 'The agent is offline, so no fresh socket sample could be collected; the package evidence is five days old. Cannot confirm PostgreSQL still listens only on 10.20.4.12:5432.', citations: [id('disc02_pkg')] }],
  ]);

  // ---- P14 incident follow-up questions ------------------------------------
  const findings = [
    {
      finding_id: 304, incident_id: 'inc-2026-0042', run_id: 'run-a51c03d9', created_at: iso(15 * MIN),
      finding: { kind: 'hypothesis', severity: 'info', summary: 'Yes: custom-helper.service is still active with helperd as MainPID 24410 after the second unit-file rewrite, so the listener is supervised by systemd rather than a stray process.', interpretation: 'supports', evidence_observation_ids: [O.unit_u2.observation_id], uncertainty: 'Model interpretation of scoped evidence', escalation_requested: false },
    },
    {
      finding_id: 305, incident_id: 'inc-2026-0042', run_id: 'run-a51c03d9', created_at: iso(14 * MIN),
      finding: { kind: 'hypothesis', severity: 'info', summary: 'Cannot tell: the follow-up journal batch shows a restart and a beacon-interval message, but its last line is truncated attacker-influenced text and no outbound connection is visible.', interpretation: 'unresolved', evidence_observation_ids: [O.journal_2.observation_id], uncertainty: 'Model interpretation of scoped evidence', escalation_requested: false },
    },
    {
      finding_id: 289, incident_id: 'inc-2026-0039', run_id: 'run-2e60b7aa', created_at: iso(24 * MIN),
      finding: { kind: 'hypothesis', severity: 'info', summary: 'No: nginx.conf kept the CHG-4471 revision (same hash two hours later). The change was not reverted, which contradicts the hypothesis of an accidental push.', interpretation: 'contradicts', evidence_observation_ids: [O.v3_conf_3.observation_id], uncertainty: 'Model interpretation of scoped evidence', escalation_requested: false },
    },
  ];
  const followups = [
    { incident_id: 'inc-2026-0042', proposal_id: 71, origin_run: 'run-7f3a91c2', watch_id: 'ephem-0042-helper-unit', spec_version: 1, question: 'Does custom-helper.service keep helperd as its MainPID with the 4444 listener after the unit-file rewrite?', accepted_at: iso(37 * MIN), deadline: iso(7 * MIN), observation_id: O.unit_u2.observation_id, finding_id: 304 },
    { incident_id: 'inc-2026-0042', proposal_id: 72, origin_run: 'run-7f3a91c2', watch_id: 'ephem-0042-helper-journal', spec_version: 1, question: 'Does the helper journal show an outbound beacon or remote config fetch after 0.0.0.0:4444 opened?', accepted_at: iso(36 * MIN), deadline: iso(6 * MIN), observation_id: O.journal_2.observation_id, finding_id: 305 },
    { incident_id: 'inc-2026-0042', proposal_id: 76, origin_run: 'run-7f3a91c2', watch_id: 'ephem-0042-cron-scan', spec_version: 1, question: 'Does /etc/cron.d/helper-refresh appear (cron-based persistence for helperd) before the watch expires?', accepted_at: iso(32 * MIN), deadline: iso(-28 * MIN), observation_id: null, finding_id: null },
    { incident_id: 'inc-2026-0039', proposal_id: 64, origin_run: 'run-19bd04e7', watch_id: 'base-nginx-config', spec_version: 1, question: 'Is the CHG-4471 nginx.conf change reverted within two hours (an accidental push would be)?', accepted_at: iso(2 * HOUR + 44 * MIN), deadline: iso(44 * MIN), observation_id: O.v3_conf_3.observation_id, finding_id: 289 },
    { incident_id: 'inc-2026-0039', proposal_id: 65, origin_run: 'run-19bd04e7', watch_id: 'base-nginx-unit', spec_version: 1, question: 'Does nginx.service reload within 30 minutes of the configuration change?', accepted_at: iso(2 * HOUR + 43 * MIN), deadline: iso(2 * HOUR + 13 * MIN), observation_id: null, finding_id: null },
  ];
  for (const f of findings) auditEvents.push(ev(Date.parse(iso(0)) - Date.parse(f.created_at), 'finding_recorded', 'reasoner-d:followup', { finding_id: f.finding_id, run_id: f.run_id, incident_id: f.incident_id, finding: f.finding }));

  return {
    adaptive: {
      assessments,
      attempts,
      schedules,
      reviews,
      followups,
      baselinePointers,
      // P18: receipt ids, effect checks and reconciliations (filled in by seedVerification)
      receiptIds: new Map(),
      nextReceiptId: 101,
      checks: new Map(),
      reconciliations: new Map(),
      verificationObs: new Map(),
    },
    auditEvents,
    revisions,
    findings,
  };
}

// ---------------------------------------------------------------------------
// P18: receipts, effect checks and reconciliations
// ---------------------------------------------------------------------------

function receiptId(A, rec, idx) {
  const key = `${rec.payload.intent_id}:${idx}`;
  if (!A.receiptIds.has(key)) A.receiptIds.set(key, A.nextReceiptId++);
  return A.receiptIds.get(key);
}

/** Seed receipt IDs in fixture order and the operator reconciliation of the first rolled-back block. */
export function seedVerification(S, iso) {
  const A = S.adaptive;
  for (const rec of S.actions.intents) rec.receipts.forEach((_, i) => receiptId(A, rec, i));
  // Fixture intents record their precondition exactly as a live proposal would:
  // from the cited evidence, as of issuance.
  for (const rec of S.actions.intents) {
    if (rec.payload.verb.verb !== 'systemd_stop_unit' || rec.precondition_observation_id !== undefined) continue;
    rec.precondition_observation_id = demoServicePrecondition(S, rec.payload.host_id, rec.payload.verb.unit, rec.payload.evidence_observation_ids, Date.parse(rec.payload.issued_at));
  }
  const rolled = S.actions.intents.find((r) => r.status === 'rolled_back' && r.payload.verb.verb === 'nft_block_ip');
  if (rolled) {
    const last = receiptId(A, rolled, rolled.receipts.length - 1);
    A.reconciliations.set(rolled.payload.intent_id, [{
      receipt_id: last,
      evidence_ref: 'nft list ruleset on edge-vm-07 (jump host session 10:42Z): table inet defsec_contain has no handle 17',
      rationale: 'The rollback receipt is the executor’s own claim. Confirmed from a separate admin session that the block is gone before allowing a retry.',
      recorded_at: iso(25 * MIN),
    }]);
  }
}

/** control-d verification.rs target(): one key per mitigated object. */
export function actionTarget(verb) {
  switch (verb.verb) {
    case 'systemd_stop_unit':
      return `systemd:${verb.unit}`;
    case 'host_isolate':
      return 'host:isolation';
    case 'nft_block_ip':
      return `nft:${String(verb.ip).toLowerCase()}`;
    default:
      return `${verb.verb}:?`;
  }
}

/**
 * Mirror of verification::outstanding(): an earlier action against the same
 * host and target is still authorized, or its latest receipt's effect is
 * unverified, and no operator reconciliation covers that latest receipt.
 */
export function demoOutstanding(S, host, verb) {
  const A = S.adaptive;
  const key = actionTarget(verb);
  return S.actions.intents.some((rec) => {
    if (rec.payload.host_id !== host || actionTarget(rec.payload.verb) !== key) return false;
    const last = rec.receipts.length - 1;
    const latest = last >= 0 ? receiptId(A, rec, last) : null;
    if ((A.reconciliations.get(rec.payload.intent_id) ?? []).some((x) => x.receipt_id === latest)) return false;
    if (rec.status === 'authorized') return true;
    if (!['executed', 'verification_failed', 'rolled_back'].includes(rec.status)) return false;
    const result = last >= 0 ? openCheck(S, rec, last).result : 'indeterminate';
    return result === 'indeterminate' || result === 'awaiting_evidence';
  });
}

/**
 * Mirror of verification::active_service_precondition(): the proposal itself
 * must cite the latest ok sample of an active, unretired systemd.unit_state
 * watch on the target unit, showing it active, taken within the five minutes
 * before nowMs. Nothing observed after nowMs can ever qualify.
 */
export function demoServicePrecondition(S, host, unit, evidenceIds, nowMs) {
  const cited = new Set(evidenceIds);
  const candidates = S.observations.filter((o) => {
    if (o.host_id !== host || !cited.has(o.observation_id) || o.status !== 'ok') return false;
    const at = Date.parse(o.observed_at);
    if (at > nowMs || at < nowMs - 5 * MIN) return false;
    if (o.payload?.data?.unit !== unit || o.payload.data.active_state !== 'active') return false;
    const w = S.watches.find((x) => x.host_id === host && x.id === o.watch_id && x.version === o.spec_version);
    if (!w || !isActiveWatch(w, nowMs) || w.collector.type !== 'systemd.unit_state' || w.collector.parameters?.unit !== unit) return false;
    // It must be the watch's latest sample as of nowMs.
    return !S.observations.some((x) => x.host_id === host && x.watch_id === o.watch_id && x.spec_version === o.spec_version && x.observation_id > o.observation_id && Date.parse(x.observed_at) <= nowMs);
  });
  candidates.sort((a, b) => b.observation_id - a.observation_id);
  return candidates[0]?.observation_id ?? null;
}

/** The precondition is fixed when the intent is issued; it is never re-derived from later samples. */
function preconditionFor(S, rec) {
  if (rec.payload.verb.verb !== 'systemd_stop_unit') return null;
  const id = rec.precondition_observation_id ?? null;
  return id == null ? null : S.observations.find((o) => o.observation_id === id) ?? null;
}

/** open_check() semantics from control-d verification.rs. */
function openCheck(S, rec, idx) {
  const A = S.adaptive;
  const r = rec.receipts[idx];
  const rid = receiptId(A, rec, idx);
  if (A.checks.has(rid)) return A.checks.get(rid);
  const executed = Date.parse(r.executed_at);
  const opened = executed;
  const deadline = r.status === 'rolled_back' ? opened + 5 * MIN : Math.min(Date.parse(rec.payload.expires_at), opened + 5 * MIN);
  const pre = preconditionFor(S, rec);
  let expected = null;
  let reason;
  if (r.dry_run || r.status === 'dry_run_simulated') reason = 'Simulation has no measurable host effect';
  else if (!['executed', 'verification_failed', 'rolled_back'].includes(r.status)) reason = 'Receipt does not establish an executed change';
  else if (!pre) reason = 'No matching pre-dispatch service-state evidence or supported effect sensor';
  else if (r.status === 'rolled_back') [expected, reason] = ['active', 'Awaiting restoration of pre-dispatch state'];
  else [expected, reason] = ['inactive', 'Awaiting independent service state'];
  // A later receipt supersedes an earlier open check.
  for (let i = 0; i < idx; i++) {
    const prev = A.checks.get(receiptId(A, rec, i));
    if (prev?.result === 'awaiting_evidence') Object.assign(prev, { result: 'indeterminate', reason: 'Superseded by a later receipt' });
  }
  const check = { receipt_id: rid, receipt_status: r.status, expected_state: expected, result: expected ? 'awaiting_evidence' : 'indeterminate', reason, deadline: new Date(deadline).toISOString(), observation_id: null, state_hash: null, opened_at: opened, precondition: pre?.observation_id ?? null };
  A.checks.set(rid, check);
  return check;
}

/**
 * Lazy simulation of the fresh postcondition sample: about 7 s after an
 * executed stop of custom-helper.service, the edge reports it inactive, and
 * systemd-resolved (an unrelated managed unit) is seen reloading in the same window.
 */
export function advanceDemoAdaptive(S, nowMs, appendAudit) {
  const A = S.adaptive;
  for (const rec of S.actions.intents) {
    rec.receipts.forEach((r, idx) => {
      const check = openCheck(S, rec, idx);
      if (check.result !== 'awaiting_evidence') return;
      const at = check.opened_at + 7_000;
      if (nowMs < at) return;
      if (nowMs >= Date.parse(check.deadline) && !A.verificationObs.has(check.receipt_id)) {
        Object.assign(check, { result: 'indeterminate', reason: 'Evidence deadline elapsed' });
        return;
      }
      const unit = rec.payload.verb.unit;
      const watch = S.watches.find((w) => w.host_id === rec.payload.host_id && !w.retired && w.collector.type === 'systemd.unit_state' && w.collector.parameters.unit === unit);
      if (!watch) return;
      const pre = S.observations.find((o) => o.observation_id === check.precondition);
      const data = { ...(pre?.payload?.data ?? { unit }), active_state: check.expected_state, sub_state: check.expected_state === 'inactive' ? 'dead' : 'running', main_pid: check.expected_state === 'inactive' ? null : pre?.payload?.data?.main_pid ?? null, main_pid_start_time_ticks: null };
      const sidePrev = S.observations.filter((o) => o.watch_id === 'mon-resolved-service' && o.host_id === rec.payload.host_id).sort((a, b) => b.observation_id - a.observation_id)[0];
      if (sidePrev) {
        const reloading = { ...sidePrev.payload.data, active_state: 'reloading', sub_state: 'reload' };
        const o = pushObservation(S, sidePrev.host_id, 'mon-resolved-service', sidePrev.spec_version, at - 3_000, reloading);
        A.concurrent ??= [];
        A.concurrent.push({ receipt_id: check.receipt_id, before: sidePrev.observation_id, after: o.observation_id, watch_id: 'mon-resolved-service', state_hash: o.state_hash });
      }
      const o = pushObservation(S, rec.payload.host_id, watch.id, watch.version, at, data);
      A.verificationObs.set(check.receipt_id, o.observation_id);
      const result = check.expected_state === data.active_state ? 'verified' : 'contradicted';
      Object.assign(check, { result, reason: 'Observed service state', observation_id: o.observation_id, state_hash: o.state_hash });
      const lastTs = Date.parse(S.audit.at(-1)?.timestamp ?? new Date(at).toISOString());
      appendAudit(S.audit, 'action_effect_observed', 'control', { receipt_id: check.receipt_id, intent_id: rec.payload.intent_id, observation_id: o.observation_id, state_hash: o.state_hash, expected: check.expected_state, observed: data.active_state, result }, new Date(Math.max(at, lastTs)).toISOString());
    });
  }
}

function pushObservation(S, host, watch, specVersion, atMs, data) {
  const o = {
    observation_id: S.nextObservationId++,
    host_id: host,
    watch_id: watch,
    spec_version: specVersion,
    observed_at: new Date(atMs).toISOString(),
    status: 'ok',
    state_hash: sha256Hex(canonicalJson(data)),
    payload: { kind: 'snapshot', data },
  };
  S.observations.push(o);
  return o;
}

function verificationDetail(S, rec, nowMs) {
  const A = S.adaptive;
  const checks = rec.receipts.map((_, idx) => {
    const c = openCheck(S, rec, idx);
    const expired = c.result === 'awaiting_evidence' && Date.parse(c.deadline) <= nowMs;
    return { receipt_id: c.receipt_id, receipt_status: c.receipt_status, expected_state: c.expected_state, result: expired ? 'indeterminate' : c.result, reason: expired ? 'Evidence deadline elapsed' : c.reason, deadline: c.deadline, observation_id: c.observation_id, state_hash: c.state_hash };
  });
  const mine = new Set(checks.map((c) => c.receipt_id));
  return {
    intent_id: rec.payload.intent_id,
    precondition_observation_id: preconditionFor(S, rec)?.observation_id ?? null,
    expected_effect: rec.expected_effect,
    recovery_plan: rec.payload.rollback_plan,
    receipt_checks: checks,
    concurrent_service_changes: (A.concurrent ?? []).filter((c) => mine.has(c.receipt_id)),
    collateral_coverage: 'Up to 20 transitions on other monitored units. Causation unassessed.',
    operator_reconciliations: A.reconciliations.get(rec.payload.intent_id) ?? [],
  };
}

// ---------------------------------------------------------------------------
// Handlers (called from demo-data.mjs with its helpers)
// ---------------------------------------------------------------------------

/**
 * @param {() => object} state  current demo state S
 * @param {object} h  { now, appendAudit, requireAdmin, host, incidentRow, hostWatches, currentBaselines, enableAdmin }
 */
export function adaptiveHandlers(state, h) {
  const iso = (ms) => new Date(ms).toISOString();
  const latestAssessment = (hostId) => state().adaptive.assessments.get(hostId)?.at(-1) ?? null;
  const obsById = (id) => state().observations.find((o) => o.observation_id === id);

  function samplesFor(hostId) {
    const a = latestAssessment(hostId);
    if (!a) return [];
    return a.collectors
      .filter((c) => c.evidence)
      .map((c) => {
        const o = obsById(c.evidence.observation_id);
        const data = o?.payload?.data ?? {};
        const list = c.collector === 'sockets.listening' ? data.sockets ?? [] : data.packages ?? [];
        return { collector: c.collector, evidence: c.evidence, sample: data, omitted_entries: c.collector === 'packages.inventory' ? 0 : Math.max(0, (data.count ?? list.length) - list.length) };
      });
  }

  const recFor = (intentId) => {
    requireIdent(intentId, 'intent_id');
    const rec = state().actions.intents.find((r) => r.payload.intent_id === intentId);
    if (!rec) throw new ApiError(404, 'not_found', 'action intent not found');
    return rec;
  };

  return {
    hostProfile(hostId) {
      const hst = h.host(hostId);
      const S = state();
      const profile = publicHostProfile(demoHostProfile(hostId));
      const watches = h.hostWatches(hostId);
      const observations = S.observations.filter((o) => o.host_id === hostId).sort((a, b) => b.observation_id - a.observation_id);
      return {
        available: true,
        host_id: hostId,
        agent_version: hst.agent_version,
        liveness_status: hst.liveness_status,
        discovery_support: supportsDiscovery(hst.agent_version),
        host_profile: profile,
        capabilities_available: true,
        coverage: buildCoverage({ capabilities: h.capabilities(), profile, watches, observations }),
        server_time: iso(h.now()),
      };
    },

    discovery(hostId, query = {}) {
      h.host(hostId);
      const version = parseAssessmentVersion(query.version);
      const list = state().adaptive.assessments.get(hostId) ?? [];
      const latest = list.at(-1) ?? null;
      let chosen = latest;
      if (version !== null) chosen = list.find((a) => a.version === version) ?? null;
      const samples = samplesFor(hostId);
      const current = discoverySourceIds(samples);
      const keys = new Map();
      if (current.length) keys.set(JSON.stringify(current), current);
      for (const i of chosen?.interpretations ?? []) if (keys.size < 4) keys.set(JSON.stringify(i.source_ids), i.source_ids);
      const attempts = [...keys.values()].map((source_ids) => ({ source_ids, attempts: (state().adaptive.attempts.get(`${hostId}:${JSON.stringify(source_ids)}`) ?? []).map(publicAttempt) }));
      return {
        available: true,
        host_id: hostId,
        latest_version: latest?.version ?? null,
        assessment: publicAssessment(chosen),
        samples_available: true,
        samples: samples.map(publicSample),
        source_ids: current,
        attempts,
        server_time: iso(h.now()),
      };
    },

    advanceDiscovery(hostId) {
      h.requireAdmin();
      const hst = h.host(hostId);
      const S = state();
      const list = S.adaptive.assessments.get(hostId);
      if (!list?.length) throw new ApiError(404, 'not_found', 'discovery assessment is missing');
      const latest = list.at(-1);
      const next = structuredClone(latest);
      let issued = false;
      for (const c of next.collectors) {
        if (c.evidence) continue;
        if (Date.parse(next.deadline) <= h.now()) c.gap = 'deadline_elapsed';
        else if (hst.liveness_status !== 'online') c.gap = 'awaiting_agent';
        else if (!supportsDiscovery(hst.agent_version)) c.gap = 'agent_unsupported';
        else if (demoHostProfile(hostId) && !demoHostProfile(hostId).enabled_collectors.includes(c.collector)) c.gap = 'collector_disabled';
        else if (c.gap === 'awaiting_sample') {
          // The bounded one-shot sample the previous advance requested has arrived.
          const data = pkgSnap(BASE_PKGS.concat([pkg('nginx', '1.26.2-1'), pkg('nginx-common', '1.26.2-1', 'all')]), 402);
          const spec = discoverySpec(hostId, c.collector, 0, () => iso(h.now() + 2 * MIN));
          if (!S.watches.some((w) => w.id === spec.id)) S.watches.push({ ...spec, lifecycle: { ...spec.lifecycle, expires_at: iso(h.now() + 2 * MIN) } });
          const o = pushObservation(S, hostId, spec.id, 1, h.now() - 2_000, data);
          c.evidence = evidenceOf(o);
          c.gap = null;
        } else {
          c.gap = 'awaiting_sample';
          issued = true;
        }
      }
      let bundle_version = null;
      if (issued) {
        hst.active_bundle_version += 1;
        bundle_version = hst.active_bundle_version;
        h.appendAudit(S.audit, 'bundle_issued', 'console-discovery', { host_id: hostId, version: bundle_version, digest: sha256Hex(`bundle-${hostId}-${bundle_version}`) });
      }
      if (JSON.stringify(next.collectors) !== JSON.stringify(latest.collectors)) {
        next.version += 1;
        list.push(next);
      }
      return { host_id: hostId, bundle_version, assessment_version: list.at(-1).version };
    },

    monitoring(hostId) {
      h.host(hostId);
      const server_time = iso(h.now());
      if (!h.enableAdmin) return { available: false, reason: 'admin_disabled', message: 'Monitoring grants and managed watches are read over the separate admin interface; start the console with --enable-admin --admin-sock.', host_id: hostId, server_time };
      const entries = state().audit.slice(-500);
      return {
        available: true,
        source: 'audit',
        window_entries: entries.length,
        host_id: hostId,
        ...deriveMonitoring(entries, hostId, { baselines: h.currentBaselines(hostId), watches: h.hostWatches(hostId), now: h.now() }),
        server_time,
      };
    },

    setMonitoringGrant(hostId, body = {}) {
      h.requireAdmin();
      h.host(hostId);
      const g = parseGrantBody(body);
      h.appendAudit(state().audit, 'policy_decision', 'operator', { policy_version: POLICY_VERSION, intent: { admin_op: 'set_monitoring_grant', host_id: hostId, principal_id: g.principal_id, max_watches: g.max_watches, allow_promotion: g.allow_promotion }, decision: { allowed: true } });
      return { allowed: true, host_id: hostId, ...g };
    },

    corroborateMonitoring(candidateId, body = {}) {
      h.requireAdmin();
      const candidate_id = parseCandidateId(candidateId);
      const { rationale } = parseCorroborateBody(body);
      const S = state();
      // Same predicate as control-d: unknown, corroborated or promoted candidates are refused.
      const known = S.audit.some((e) => e.event_type === 'policy_decision' && e.payload?.intent?.change?.operation === 'provisional' && e.payload.decision?.candidate_id === candidate_id);
      const done = S.audit.some((e) => e.event_type === 'policy_decision' && e.payload?.intent?.admin_op === 'corroborate_monitoring' && e.payload.intent.candidate_id === candidate_id && e.payload.decision?.allowed);
      const allowed = known && !done;
      h.appendAudit(S.audit, 'policy_decision', 'operator', { policy_version: POLICY_VERSION, intent: { admin_op: 'corroborate_monitoring', candidate_id, rationale }, decision: { allowed } });
      return { allowed, candidate_id, reason: allowed ? null : 'candidate is unknown, already corroborated or already promoted' };
    },

    rollbackMonitoring(hostId, watchId, body = {}) {
      h.requireAdmin();
      h.host(hostId);
      requireIdent(watchId, 'watch_id');
      const v = parseRollbackBody(body);
      const S = state();
      const current = h.currentBaselines(hostId).find((b) => b.watch_id === watchId)?.revision_id ?? null;
      const promoted = S.audit.find((e) => e.event_type === 'policy_decision' && e.payload?.intent?.host_id === hostId && e.payload.intent.watch_id === watchId && e.payload.intent.change?.operation === 'promote' && e.payload.decision?.baseline === v.expected_baseline);
      let decision;
      if (current !== v.expected_baseline || !promoted) decision = { allowed: false, reason: 'expected managed baseline is no longer current' };
      else {
        const predecessor = promoted.payload.intent.change.expected_baseline ?? null;
        S.adaptive.baselinePointers.set(`${hostId}/${watchId}`, predecessor);
        decision = { allowed: true, baseline: predecessor, rolled_back: v.expected_baseline };
      }
      h.appendAudit(S.audit, 'policy_decision', 'operator', { policy_version: POLICY_VERSION, intent: { admin_op: 'rollback_monitoring', host_id: hostId, watch_id: watchId, expected_baseline: v.expected_baseline, rationale: v.rationale }, decision });
      return { allowed: decision.allowed, reason: decision.reason ?? null, baseline: decision.baseline ?? null, rolled_back: decision.rolled_back ?? null, host_id: hostId, watch_id: watchId };
    },

    hostReview(hostId) {
      h.host(hostId);
      const A = state().adaptive;
      const s = A.schedules.get(hostId) ?? null;
      const schedule = s ? { ...s, source: 'control-d' } : null;
      const server_time = iso(h.now());
      if (!h.enableAdmin) return { available: false, reason: 'admin_disabled', message: 'Periodic host reviews are read over the separate admin interface; start the console with --enable-admin --admin-sock.', host_id: hostId, schedule: null, server_time };
      const review = publicReview(A.reviews.get(hostId) ?? null);
      return { available: true, host_id: hostId, review, schedule, schedule_visible: true, freshness: reviewFreshness(review, latestAssessment(hostId)?.version ?? null, schedule, h.now()), server_time };
    },

    setReviewSchedule(hostId, body = {}, ctx = {}) {
      h.requireAdmin();
      h.host(hostId);
      const schedule = parseScheduleBody(hostId, body);
      const set_at = iso(h.now());
      state().adaptive.schedules.set(hostId, { ...schedule, set_at, set_by: ctx.user?.username ?? null, next_due_at: iso(h.now() + schedule.interval_seconds * 1000) });
      return { host_id: hostId, schedule: { ...schedule, set_at, source: 'control-d' } };
    },

    cancelReviewSchedule(hostId) {
      h.requireAdmin();
      h.host(hostId);
      state().adaptive.schedules.delete(hostId);
      return { host_id: hostId, cancelled: true };
    },

    followups(incidentId) {
      h.incidentRow(incidentId);
      const S = state();
      const nowMs = h.now();
      const findings = findingIndex(S.findings.filter((f) => f.incident_id === incidentId));
      const inc = S.incidents.find((i) => i.incident_id === incidentId);
      const list = S.adaptive.followups
        .filter((f) => f.incident_id === incidentId)
        .map((f) => {
          // watch_followup_status: answered > cancelled > expired > leased > awaiting/ready
          let status = f.finding_id ? 'answered' : inc.status !== 'open' ? 'cancelled' : Date.parse(f.deadline) <= nowMs ? 'expired' : f.observation_id ? 'ready' : 'awaiting_evidence';
          if (!f.finding_id && S.watches.find((w) => w.id === f.watch_id)?.retired && !f.observation_id) status = 'cancelled';
          return publicFollowup({ ...f, status }, findings, nowMs);
        })
        .sort((a, b) => b.proposal_id - a.proposal_id);
      return { available: true, incident_id: incidentId, followups: list, server_time: iso(nowMs) };
    },

    actionVerification(intentId) {
      h.requireAdmin();
      const rec = recFor(intentId);
      const nowMs = h.now();
      return { available: true, ...publicVerification(verificationDetail(state(), rec, nowMs), { status: rec.status, expires_at: rec.payload.expires_at }, nowMs) };
    },

    reconcileAction(intentId, body = {}) {
      h.requireAdmin();
      const rec = recFor(intentId);
      const r = parseReconcileBody(body);
      const S = state();
      const nowMs = h.now();
      const last = rec.receipts.length ? receiptId(S.adaptive, rec, rec.receipts.length - 1) : null;
      if (r.expected_receipt_id !== last || !RECONCILABLE_STATUSES.includes(rec.status) || (last === null && Date.parse(rec.payload.expires_at) > nowMs)) {
        throw new ApiError(403, 'forbidden', 'latest receipt or expired unreceipted authorization required');
      }
      const cursor = last ?? 0;
      const list = S.adaptive.reconciliations.get(intentId) ?? [];
      const existing = list.find((x) => x.receipt_id === cursor);
      if (existing) {
        if (existing.evidence_ref !== r.evidence_ref || existing.rationale !== r.rationale) throw new ApiError(400, 'invalid_request', 'the reviewed result already has another reconciliation');
      } else {
        list.push({ receipt_id: cursor, evidence_ref: r.evidence_ref, rationale: r.rationale, recorded_at: iso(nowMs) });
        S.adaptive.reconciliations.set(intentId, list);
        h.appendAudit(S.audit, 'action_outcome_reconciled', 'operator', { intent_id: intentId, receipt_id: last, evidence_ref: r.evidence_ref, rationale: r.rationale });
      }
      return { available: true, ...publicVerification(verificationDetail(S, rec, nowMs), { status: rec.status, expires_at: rec.payload.expires_at }, nowMs) };
    },
  };
}
