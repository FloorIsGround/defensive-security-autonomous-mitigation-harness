// DefSecAutMit Operator Console: browser application.
// All untrusted strings are rendered through dom.js (Text nodes only).

import { el, append, clear, replace, icon, hydrateIcons } from './dom.js';

// ---------------------------------------------------------------------------
// State & API
// ---------------------------------------------------------------------------

const state = {
  status: null,
  hosts: [],
  incidents: [],
  capabilities: new Map(),
  evidence: new Map(), // incident_id -> Set<observation_id>
  drafts: new Map(), // incident_id -> { proposal, finding }
  decisions: new Map(), // incident_id -> [{decision, watch_id, spec, at}]
  expanded: new Set(),
  baselines: { host: null, watch: '', limit: 50 },
  audit: { tab: 'decisions', ruleFilter: null, verdict: 'all', newestFirst: true },
  lastRefresh: null,
};

const FLOOR = { min_interval: 15, max_timeout: 30, max_ttl_min: 240, max_runs: 1000 };
const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
const VALID_OBS = new Set(['ok', 'partial']);

class HttpError extends Error {
  constructor(status, code, message) {
    super(message);
    this.status = status;
    this.code = code;
  }
}

async function api(path, { method = 'GET', body } = {}) {
  const res = await fetch(path, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
    credentials: 'same-origin',
    cache: 'no-store',
  });
  let data = null;
  try {
    data = await res.json();
  } catch {
    /* non-JSON */
  }
  if (!res.ok) throw new HttpError(res.status, data?.error?.code ?? 'http_error', data?.error?.message ?? res.statusText);
  return data;
}

const adminEnabled = () => Boolean(state.status?.admin_enabled);
const isDemo = () => state.status?.mode === 'demo';

// ---------------------------------------------------------------------------
// Formatting
// ---------------------------------------------------------------------------

const clockFmt = new Intl.DateTimeFormat(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
const dateFmt = new Intl.DateTimeFormat(undefined, { month: 'short', day: '2-digit' });
const fullFmt = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'medium' });

function fmtTime(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return '—';
  const today = new Date().toDateString() === d.toDateString();
  return today ? clockFmt.format(d) : `${dateFmt.format(d)} ${clockFmt.format(d)}`;
}

function rel(iso, now = Date.now()) {
  if (!iso) return 'never';
  const s = Math.round((now - Date.parse(iso)) / 1000);
  const fut = s < 0;
  const a = Math.abs(s);
  let txt;
  if (a < 60) txt = `${a}s`;
  else if (a < 3600) txt = `${Math.floor(a / 60)}m ${a % 60 ? `${a % 60}s` : ''}`.trim();
  else if (a < 86400) txt = `${Math.floor(a / 3600)}h ${Math.floor((a % 3600) / 60)}m`;
  else txt = `${Math.floor(a / 86400)}d ${Math.floor((a % 86400) / 3600)}h`;
  return fut ? `in ${txt}` : `${txt} ago`;
}

function untilText(iso, now = Date.now()) {
  const s = Math.round((Date.parse(iso) - now) / 1000);
  if (s <= 0) return `expired ${rel(iso, now)}`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60}s left`;
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m left`;
}

function bytes(n) {
  if (n === null || n === undefined) return '—';
  const u = ['B', 'KiB', 'MiB', 'GiB'];
  let i = 0;
  let v = n;
  while (v >= 1024 && i < u.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(i === 0 ? 0 : 1)} ${u[i]}`;
}

const shortHash = (h) => (h ? `${h.slice(0, 10)}…${h.slice(-4)}` : '—');

function hashHue(h) {
  return parseInt(String(h).slice(0, 6), 16) % 360;
}

// ---------------------------------------------------------------------------
// Small components
// ---------------------------------------------------------------------------

function toast(message, kind = '') {
  const node = el('div', { class: ['toast', kind] }, message);
  document.getElementById('toasts').append(node);
  setTimeout(() => node.remove(), kind === 'bad' ? 7000 : 4200);
}

async function copy(text, node) {
  try {
    await navigator.clipboard.writeText(text);
    node?.classList.add('copied');
    setTimeout(() => node?.classList.remove('copied'), 1100);
    toast('Copied to clipboard');
  } catch {
    toast('Clipboard unavailable', 'bad');
  }
}

function hashChip(hash, { full = false, label = null } = {}) {
  if (!hash) return el('span', { class: 'hash is-null' }, '— none —');
  const sw = el('span', { class: 'sw' });
  sw.style.setProperty('background', `hsl(${hashHue(hash)} 68% 58%)`);
  const node = el('button', { class: 'hash', type: 'button', title: `SHA-256 ${hash}\nClick to copy`, attrs: { 'aria-label': `Copy hash ${hash}` } }, sw, label ?? (full ? hash : shortHash(hash)));
  node.addEventListener('click', (e) => {
    e.stopPropagation();
    copy(hash, node);
  });
  return node;
}

const sevBadge = (s) => el('span', { class: ['badge', 'sev', `sev-${s}`] }, s);

function livenessBadge(status) {
  const map = { online: 'ok', healthy: 'ok', connected: 'ok', stale: 'warn', degraded: 'warn', pending: 'warn', offline: 'bad', lost: 'bad' };
  const cls = map[status] ?? '';
  return el('span', { class: ['badge', cls] }, el('span', { class: ['dot', cls] }), status || 'unknown');
}

function obsStatusBadge(status) {
  const cls = status === 'ok' ? 'ok' : status === 'partial' ? 'warn' : 'bad';
  return el('span', { class: ['badge', cls] }, status.replace(/_/g, ' '));
}

function classBadge(cls) {
  return cls === 'baseline'
    ? el('span', { class: 'badge solid', title: 'Immutable operator-approved baseline watch' }, icon('lock'), 'Baseline')
    : el('span', { class: 'badge eph', title: 'Bounded, incident-scoped ephemeral watch' }, icon('clock'), 'Ephemeral');
}

function rulePill(decision) {
  return el('span', { class: ['rule-pill', decision.allowed ? 'ok' : 'bad'], title: decision.reason }, decision.rule_id);
}

function emptyState(title, text) {
  return el('div', { class: 'empty' }, el('strong', null, title), text);
}

function errorBox(err) {
  return el('div', { class: 'err-box', attrs: { role: 'alert' } }, el('span', { class: 'mono' }, err.code ?? 'error'), ' — ', err.message ?? String(err));
}

function relTime(iso, { until = false } = {}) {
  return el('span', { class: 'num', title: iso ? fullFmt.format(new Date(iso)) : '', dataset: { ts: iso ?? '', until: until ? '1' : null } }, iso ? (until ? untilText(iso) : rel(iso)) : 'never');
}

function meter(fraction, cls = '') {
  const bar = el('span');
  bar.style.setProperty('width', `${Math.max(0, Math.min(1, fraction)) * 100}%`);
  return el('div', { class: ['meter', cls] }, bar);
}

function card(title, sub, body, actions = null) {
  return el(
    'section',
    { class: 'card' },
    el('div', { class: 'card-head' }, el('div', null, el('h2', null, title), sub ? el('div', { class: 'sub' }, sub) : null), actions),
    body,
  );
}

function loading(lines = 3) {
  return el('div', { class: 'card-body stack' }, Array.from({ length: lines }, () => el('div', { class: 'skeleton' })));
}

// ---------------------------------------------------------------------------
// Shell: status, rail, chain pill
// ---------------------------------------------------------------------------

async function loadStatus() {
  try {
    state.status = await api('/api/status');
  } catch (err) {
    state.status = { mode: 'unknown', admin_enabled: false, sockets: {}, audit: null, error: err };
  }
  renderShell();
}

function renderShell() {
  const s = state.status;
  const rail = document.getElementById('rail-status');
  const inv = s?.sockets?.investigate ?? {};
  const adm = s?.sockets?.admin ?? {};
  const sockLine = (label, info, enabled = true) => {
    let cls = 'bad';
    let txt = 'unreachable';
    if (!enabled) {
      cls = '';
      txt = 'disabled';
    } else if (info.simulated) {
      cls = 'eph';
      txt = 'simulated';
    } else if (info.reachable && info.authorized !== false) {
      cls = 'ok';
      txt = `${info.latency_ms ?? 0} ms`;
    } else if (info.reachable) {
      cls = 'warn';
      txt = 'unauthorized';
    }
    return el('div', { class: 'rail-row' }, el('span', { class: 'row' }, el('span', { class: ['dot', cls] }), label), el('span', { class: 'mono' }, txt));
  };
  replace(
    rail,
    el(
      'div',
      { class: 'rail-row' },
      el('span', { class: 'eyebrow' }, 'Mode'),
      el('span', { class: ['badge', s?.mode === 'live' ? 'ok' : s?.mode === 'demo' ? 'eph' : 'bad'] }, s?.mode ?? '…'),
    ),
    sockLine('investigate.sock', inv),
    sockLine('admin.sock', adm, Boolean(s?.admin_enabled)),
    el('div', { class: 'rail-row' }, el('span', null, 'Admin role'), el('span', { class: ['badge', s?.admin_enabled ? 'warn' : ''] }, s?.admin_enabled ? 'enabled' : 'off')),
  );

  const pill = document.getElementById('chain-pill');
  const a = s?.audit;
  if (!a) {
    replace(pill, el('a', { class: 'chain-pill', href: '#/audit', title: 'Audit chain requires the admin interface' }, icon('lock'), 'Audit chain unavailable'));
  } else if (a.valid) {
    replace(pill, el('a', { class: 'chain-pill ok', href: '#/audit', title: `Chain head ${a.latest_hash}` }, el('span', { class: 'dot ok' }), 'Chain verified', el('span', { class: 'mono' }, `${a.entries_checked} · ${String(a.latest_hash ?? '').slice(0, 8)}`)));
  } else {
    replace(pill, el('a', { class: 'chain-pill bad', href: '#/audit', title: a.error ?? '' }, el('span', { class: 'dot bad' }), 'Audit chain broken'));
  }

  const open = state.incidents.filter((i) => i.status === 'open').length;
  document.getElementById('nav-incidents').textContent = open ? String(open) : '';
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

const VIEWS = {
  fleet: { title: 'Fleet & Posture', sub: 'Edge agent liveness, bundle state and audit integrity', render: renderFleet },
  investigations: { title: 'Investigations', sub: 'Observed facts, model hypotheses and verified findings', render: renderInvestigations },
  baselines: { title: 'Baselines & Telemetry', sub: 'Accepted baseline vs. last observed vs. current observed', render: renderBaselines },
  audit: { title: 'Policy Gate & Audit', sub: 'Deterministic policy decisions and the tamper-evident audit chain', render: renderAudit },
};

function parseRoute() {
  const [, view = 'fleet', arg = null] = (location.hash || '#/fleet').split('/');
  return { view: VIEWS[view] ? view : 'fleet', arg: arg ? decodeURIComponent(arg) : null };
}

let renderToken = 0;
async function render() {
  const route = parseRoute();
  const v = VIEWS[route.view];
  document.getElementById('view-title').textContent = v.title;
  document.getElementById('view-sub').textContent = v.sub;
  for (const a of document.querySelectorAll('#nav a')) {
    if (a.dataset.view === route.view) a.setAttribute('aria-current', 'page');
    else a.removeAttribute('aria-current');
  }
  const token = ++renderToken;
  const main = document.getElementById('main');
  try {
    const node = await v.render(route.arg, () => token !== renderToken);
    if (token !== renderToken || !node) return;
    replace(main, node);
  } catch (err) {
    if (token !== renderToken) return;
    replace(main, errorBox(err));
  }
}

async function refreshAll() {
  await Promise.all([loadStatus(), loadCore()]);
  state.lastRefresh = Date.now();
  renderShell();
  await render();
}

async function loadCore() {
  const [h, i] = await Promise.allSettled([api('/api/hosts'), api('/api/incidents')]);
  if (h.status === 'fulfilled') state.hosts = h.value.hosts;
  if (i.status === 'fulfilled') state.incidents = i.value.incidents;
}

// ---------------------------------------------------------------------------
// View: Fleet & Posture
// ---------------------------------------------------------------------------

function integrityBanner(audit) {
  if (!audit) {
    return el(
      'div',
      { class: 'banner' },
      el('div', { class: 'banner-ico' }, icon('lock')),
      el('div', null, el('div', { class: 'banner-title' }, 'Audit chain not visible'), el('div', { class: 'banner-meta' }, 'VerifyAuditChain runs on the separate admin interface. Start the console with --enable-admin --admin-sock to show integrity here.')),
    );
  }
  if (audit.valid) {
    return el(
      'div',
      { class: 'banner ok' },
      el('div', { class: 'banner-ico' }, icon('shield')),
      el(
        'div',
        null,
        el('div', { class: 'banner-title' }, 'Audit chain intact'),
        el('div', { class: 'banner-meta' }, el('span', null, el('span', { class: 'num' }, String(audit.entries_checked)), ' entries verified from genesis'), el('span', null, 'head ', hashChip(audit.latest_hash))),
      ),
      el('span', { class: 'spacer' }),
      el('a', { class: 'btn btn-sm', href: '#/audit' }, 'Inspect chain'),
    );
  }
  return el(
    'div',
    { class: 'banner bad', attrs: { role: 'alert' } },
    el('div', { class: 'banner-ico' }, icon('alert')),
    el('div', null, el('div', { class: 'banner-title' }, 'Tamper evidence: audit chain verification failed'), el('div', { class: 'banner-meta' }, el('span', { class: 'mono' }, audit.error ?? 'unknown error'))),
    el('span', { class: 'spacer' }),
    el('a', { class: 'btn btn-sm btn-danger', href: '#/audit' }, 'Investigate'),
  );
}

function kpi(label, value, foot) {
  return el('div', { class: 'kpi' }, el('div', { class: 'label' }, label), el('div', { class: 'value' }, value), foot ? el('div', { class: 'foot' }, foot) : null);
}

async function renderFleet() {
  const hosts = state.hosts;
  const open = state.incidents.filter((i) => i.status === 'open');
  const online = hosts.filter((h) => h.liveness_status === 'online').length;
  const degraded = hosts.filter((h) => h.liveness_status !== 'online');
  const sevCounts = SEV_ORDER.map((s) => [s, open.filter((i) => i.priority === s).length]).filter(([, n]) => n);

  const kpis = el(
    'div',
    { class: 'kpis' },
    kpi('Agents online', [String(online), el('small', null, ` / ${hosts.length}`)], hosts.length ? `${Math.round((online / hosts.length) * 100)}% of enrolled fleet` : 'no hosts enrolled'),
    kpi('Degraded or offline', String(degraded.length), degraded.length ? degraded.map((h) => el('span', { class: 'mono' }, h.host_id)) : 'all agents heart-beating'),
    kpi('Open incidents', String(open.length), sevCounts.length ? sevCounts.map(([s, n]) => el('span', null, `${n} ${s}`)) : 'quiet'),
    kpi(
      'Audit entries',
      state.status?.audit ? String(state.status.audit.entries_checked) : '—',
      state.status?.audit ? (state.status.audit.valid ? 'hash chain verified' : 'VERIFICATION FAILED') : 'admin interface off',
    ),
  );

  const enroll = adminEnabled() ? el('button', { class: 'btn btn-sm', type: 'button', on: { click: openEnrollDrawer } }, icon('plus'), 'Enroll host') : null;

  const grid = hosts.length
    ? el('div', { class: 'host-grid' }, hosts.map((h) => hostCard(h, open.filter((i) => i.host_id === h.host_id))))
    : emptyState('No hosts in scope', 'The capability token may not include any hosts, or none are enrolled yet.');

  return el(
    'div',
    null,
    integrityBanner(state.status?.audit),
    kpis,
    el('div', { class: 'section-title' }, el('h2', null, 'Edge fleet'), el('div', { class: 'row' }, el('span', { class: 'muted' }, `${hosts.length} enrolled`), enroll)),
    grid,
  );
}

function hostCard(h, incidents) {
  const ageS = h.last_heartbeat_at ? (Date.now() - Date.parse(h.last_heartbeat_at)) / 1000 : Infinity;
  const freshCls = ageS < 45 ? '' : ageS < 600 ? 'warn' : 'bad';
  const cardCls = h.liveness_status === 'online' ? '' : h.liveness_status === 'offline' ? 'is-bad' : 'is-warn';
  const health = h.health;
  const spoolFrac = health ? health.spool_bytes_used / Math.max(1, health.spool_bytes_cap) : 0;
  const worst = incidents.map((i) => i.priority).sort((a, b) => SEV_ORDER.indexOf(a) - SEV_ORDER.indexOf(b))[0];

  const freshMeter = meter(Math.max(0.04, 1 - ageS / 120), freshCls);
  freshMeter.dataset.hb = h.last_heartbeat_at ?? '';

  return el(
    'article',
    { class: ['card', 'host-card', cardCls] },
    el(
      'div',
      { class: 'host-top' },
      el('div', null, el('div', { class: 'host-id' }, h.host_id), h.placement ? el('div', { class: 'host-place' }, h.placement) : null),
      livenessBadge(h.liveness_status),
    ),
    el(
      'div',
      { class: 'host-stats' },
      el('div', { class: 'stat' }, el('div', { class: 'k' }, 'Agent'), el('div', { class: 'v' }, h.agent_version)),
      el('div', { class: 'stat' }, el('div', { class: 'k' }, 'Bundle'), el('div', { class: 'v' }, `v${h.active_bundle_version}`)),
      el('div', { class: 'stat' }, el('div', { class: 'k' }, health ? 'Agent RSS' : 'Watches'), el('div', { class: 'v' }, health ? bytes(health.rss_bytes) : '—')),
    ),
    el(
      'div',
      { class: 'fresh' },
      el('div', { class: 'fresh-row' }, el('span', null, 'Heartbeat'), relTime(h.last_heartbeat_at)),
      freshMeter,
    ),
    health
      ? el(
          'div',
          { class: 'fresh' },
          el('div', { class: 'fresh-row' }, el('span', null, 'Spool'), el('span', { class: 'num' }, `${bytes(health.spool_bytes_used)} / ${bytes(health.spool_bytes_cap)}`)),
          meter(spoolFrac, spoolFrac > 0.8 ? 'bad' : spoolFrac > 0.5 ? 'warn' : ''),
          el(
            'div',
            { class: 'fresh-row' },
            el('span', null, `${health.active_watches} active watches`),
            el('span', { class: health.dropped_events_total ? 'num' : 'num muted' }, health.dropped_events_total ? `${health.dropped_events_total} dropped events` : '0 dropped'),
          ),
        )
      : null,
    el(
      'div',
      { class: 'host-foot' },
      incidents.length
        ? incidents.map((i) => el('a', { class: 'chip', href: `#/investigations/${encodeURIComponent(i.incident_id)}`, title: i.summary }, el('span', { class: ['dot', i.priority === 'high' || i.priority === 'critical' ? 'bad' : 'warn'] }), el('span', { class: 'mono' }, i.incident_id)))
        : el('span', { class: 'muted' }, 'No open incidents'),
      el('span', { class: 'spacer' }),
      worst ? sevBadge(worst) : null,
      el('a', { class: 'btn btn-sm btn-ghost', href: `#/baselines/${encodeURIComponent(h.host_id)}` }, 'Telemetry'),
    ),
  );
}

// ---------------------------------------------------------------------------
// View: Investigations
// ---------------------------------------------------------------------------

async function renderInvestigations(arg) {
  const incidents = [...state.incidents].sort((a, b) => {
    if (a.status !== b.status) return a.status === 'open' ? -1 : 1;
    const s = SEV_ORDER.indexOf(a.priority) - SEV_ORDER.indexOf(b.priority);
    return s || Date.parse(b.updated_at) - Date.parse(a.updated_at);
  });
  if (!arg && incidents.length) {
    history.replaceState(null, '', `#/investigations/${encodeURIComponent(incidents[0].incident_id)}`);
    arg = incidents[0].incident_id;
  }
  const list = el(
    'nav',
    { class: 'card inc-list', attrs: { 'aria-label': 'Incidents' } },
    ['open', 'closed'].map((status) => {
      const group = incidents.filter((i) => (status === 'open' ? i.status === 'open' : i.status !== 'open'));
      if (!group.length) return null;
      return [
        el('div', { class: 'inc-group eyebrow' }, `${status} · ${group.length}`),
        group.map((i) =>
          el(
            'a',
            { class: ['inc-item', i.status !== 'open' && 'closed'], href: `#/investigations/${encodeURIComponent(i.incident_id)}`, attrs: { 'aria-current': i.incident_id === arg ? 'true' : null } },
            el('div', { class: 'top' }, sevBadge(i.priority), el('span', { class: 'id' }, i.incident_id), el('span', { class: 'spacer' }), i.status !== 'open' ? el('span', { class: 'badge ghost' }, i.status) : null),
            el('div', { class: 'summary' }, i.summary),
            el('div', { class: 'meta' }, el('span', { class: 'mono' }, i.host_id), el('span', null, 'updated ', relTime(i.updated_at))),
          ),
        ),
      ];
    }),
    incidents.length ? null : emptyState('No incidents', 'No active incidents in this capability scope.'),
  );

  const workspace = el('div', { class: 'workspace' }, arg ? loading(6) : emptyState('Select an incident', ''));
  if (arg) loadWorkspace(arg, workspace);
  return el('div', { class: 'split' }, list, workspace);
}

async function loadWorkspace(incidentId, container) {
  try {
    const ctx = await api(`/api/incidents/${encodeURIComponent(incidentId)}`);
    let caps = state.capabilities.get(ctx.incident.host_id);
    if (!caps) {
      try {
        caps = (await api(`/api/hosts/${encodeURIComponent(ctx.incident.host_id)}/capabilities`)).capabilities;
        state.capabilities.set(ctx.incident.host_id, caps);
      } catch {
        caps = [];
      }
    }
    if (!container.isConnected && parseRoute().arg !== incidentId) return;
    replace(container, workspaceView(ctx, caps));
  } catch (err) {
    replace(container, errorBox(err));
  }
}

function reloadWorkspace(incidentId) {
  const container = document.querySelector('.workspace');
  if (container) loadWorkspace(incidentId, container);
}

function draftsFor(id) {
  if (!state.drafts.has(id)) {
    state.drafts.set(id, {
      proposal: {
        collector_type: 'systemd.unit_state',
        class: 'ephemeral',
        parameters: { unit: '', paths: '', include_tcp: true, include_udp: true, include_ipv6: true, resolve_process: true, hash_unit_files: true, compute_hash: true, min_priority: 6, max_events_per_batch: 50, max_message_bytes: 512 },
        interval_seconds: 30,
        timeout_seconds: 5,
        ttl_minutes: 60,
        max_runs: 120,
        cooldown_seconds: 180,
        max_wakeups_per_hour: 4,
        trigger: null,
        rationale: '',
      },
      finding: { kind: 'hypothesis', severity: 'medium', summary: '', uncertainty: '', escalation_requested: false },
    });
  }
  return state.drafts.get(id);
}

function evidenceFor(id) {
  if (!state.evidence.has(id)) state.evidence.set(id, new Set());
  return state.evidence.get(id);
}

function workspaceView(ctx, caps) {
  const inc = ctx.incident;
  const isOpen = inc.status === 'open';
  const watchMap = new Map(ctx.active_watches.map((w) => [w.id, w]));
  const obs = [...ctx.recent_observations].sort((a, b) => b.observation_id - a.observation_id);
  const obsMap = new Map(obs.map((o) => [o.observation_id, o]));
  const findings = ctx.findings.map((f) => ({ id: f.finding_id, created_at: f.created_at, ...(f.finding ?? f) }));
  const hyps = findings.filter((f) => f.kind === 'hypothesis');
  const vers = findings.filter((f) => f.kind === 'verified_finding');
  const selected = evidenceFor(inc.incident_id);
  const findingComposer = findingComposerView(inc, ctx.run, obsMap);

  const runControls = !isOpen
    ? el('span', { class: 'badge' }, 'closed · runs ended')
    : ctx.run
      ? el('span', { class: 'run-chip', title: `Run ${ctx.run.run_id}` }, el('span', { class: 'dot eph' }), 'Run ', el('span', { class: 'mono' }, ctx.run.run_id.slice(0, 8)), ' · ', relTime(ctx.run.expires_at, { until: true }))
      : el('button', { class: 'btn btn-primary btn-sm', type: 'button', on: { click: () => startRun(inc.incident_id) } }, icon('flask'), 'Start investigation run');

  const head = el(
    'section',
    { class: 'card ws-head' },
    el(
      'div',
      { class: 'row' },
      sevBadge(inc.priority),
      el('span', { class: ['badge', isOpen ? 'bad' : ''] }, inc.status),
      el('span', { class: 'mono dim' }, inc.incident_id),
      el('span', { class: 'muted' }, 'on'),
      el('a', { class: 'mono', href: `#/baselines/${encodeURIComponent(inc.host_id)}` }, inc.host_id),
      el('span', { class: 'spacer' }),
      runControls,
      isOpen && adminEnabled() ? el('button', { class: 'btn btn-sm btn-danger', type: 'button', on: { click: () => openCloseDrawer(inc) } }, 'Close incident') : null,
    ),
    el('h2', { class: 'ws-title' }, inc.summary),
    el(
      'div',
      { class: 'row' },
      el('span', { class: 'muted' }, 'Opened ', el('span', { class: 'num dim' }, fmtTime(inc.created_at))),
      el('span', { class: 'muted' }, '· updated ', relTime(inc.updated_at)),
      el('span', { class: 'spacer' }),
      el('div', { class: 'legend' }, el('span', null, el('i', { class: 'l-fact' }), 'Observed fact'), el('span', null, el('i', { class: 'l-hyp' }), 'Model hypothesis'), el('span', null, el('i', { class: 'l-ver' }), 'Verified finding')),
    ),
  );

  const lane = (title, cls, items, emptyText) =>
    el(
      'div',
      null,
      el('div', { class: 'lane-head' }, el('span', { class: ['eyebrow'] }, title), el('span', { class: 'count' }, String(items.length))),
      items.length ? items.map((f) => findingCard(f, cls, obsMap)) : el('div', { class: 'card' }, emptyState('None recorded', emptyText)),
    );

  const factList = el(
    'div',
    { class: 'fact-list' },
    obs.length ? obs.map((o) => factRow(o, watchMap, obs, selected, findingComposer.refreshEvidence)) : emptyState('No observations in window', 'No observations since the incident opened.'),
  );

  const main = el(
    'div',
    { class: 'stack' },
    el('div', { class: 'assess' }, lane('Model hypotheses', 'hyp', hyps, 'Unverified model or operator assertions appear here.'), lane('Verified findings', 'ver', vers, 'Evidence-bound conclusions appear here.')),
    card(
      'Observed facts',
      'Immutable observation slices from control-d. Tick facts to cite them as evidence.',
      el('div', { class: 'card-body flush' }, factList),
      el('span', { class: 'badge eph' }, `${obs.length} slices`),
    ),
  );

  const side = el(
    'div',
    { class: 'ws-side' },
    watchesCard(ctx.active_watches, ctx.watch_runtime ?? {}, inc),
    el(
      'div',
      { class: 'ws-compose' },
      isOpen ? proposalComposer(inc, ctx.run, caps) : card('Ephemeral watch proposals', null, el('div', { class: 'card-body muted' }, 'Incident closed. Its ephemeral watches were retired; no new proposals are accepted.')),
      isOpen ? findingComposer.node : null,
    ),
  );

  return el('div', null, head, el('div', { class: 'ws-grid' }, main, side));
}

function findingCard(f, cls, obsMap) {
  const ids = f.evidence_observation_ids ?? [];
  return el(
    'article',
    { class: ['finding', cls] },
    el(
      'div',
      { class: 'row' },
      el('span', { class: 'kind' }, cls === 'hyp' ? 'Model hypothesis · unverified' : 'Verified finding · evidence-bound'),
      el('span', { class: 'spacer' }),
      sevBadge(f.severity),
      f.escalation_requested ? el('span', { class: 'badge bad' }, 'escalation') : null,
    ),
    el('p', null, f.summary),
    f.uncertainty ? el('div', { class: 'unc' }, el('b', null, 'Uncertainty: '), f.uncertainty) : null,
    el(
      'div',
      { class: 'ev-row' },
      el('span', { class: 'muted mono' }, `#${f.id}`),
      ids.length ? el('span', { class: 'muted' }, '· evidence') : el('span', { class: 'muted' }, '· no evidence cited'),
      ids.map((id) => {
        const o = obsMap.get(id);
        return el(
          'button',
          { class: ['ev-badge', !o && 'missing'], type: 'button', title: o ? `Observation ${id}\n${o.watch_id}\nstate_hash ${o.state_hash}` : `Observation ${id} is outside the loaded window`, on: { click: () => focusFact(id) } },
          `obs ${id}`,
          o ? el('span', { class: 'h' }, o.state_hash.slice(0, 8)) : null,
        );
      }),
    ),
  );
}

function focusFact(id) {
  const node = document.getElementById(`fact-${id}`);
  if (!node) {
    toast(`Observation ${id} is not in the current window`, 'bad');
    return;
  }
  const toggle = node.querySelector('.toggle');
  if (toggle?.getAttribute('aria-expanded') !== 'true') toggle?.click();
  node.scrollIntoView({ behavior: 'smooth', block: 'center' });
  node.classList.remove('flash');
  void node.offsetWidth;
  node.classList.add('flash');
}

function collectorOf(o, watchMap) {
  const w = watchMap.get(o.watch_id);
  if (w) return w.collector.type;
  const d = o.payload?.data;
  if (o.payload?.kind === 'stream_batch') return 'journal.unit_events';
  if (Array.isArray(d?.sockets)) return 'sockets.listening';
  if (d?.active_state) return 'systemd.unit_state';
  if (Array.isArray(d?.files)) return 'files.metadata';
  return 'unknown';
}

function summarize(o) {
  const p = o.payload ?? {};
  if (p.kind === 'snapshot' || p.kind === 'delta') {
    const d = p.data ?? {};
    if (Array.isArray(d.sockets)) return `${d.count ?? d.sockets.length} listening sockets${d.partial_attribution ? ' · partial attribution' : ''}`;
    if (d.unit && d.active_state) return `${d.unit} ${d.active_state}/${d.sub_state}${d.main_pid ? ` · pid ${d.main_pid}` : ''}`;
    if (Array.isArray(d.files)) {
      const bad = d.files.filter((f) => f.status !== 'ok').length;
      return `${d.files.length} file${d.files.length === 1 ? '' : 's'}${bad ? ` · ${bad} not ok` : ''}`;
    }
    return p.kind;
  }
  if (p.kind === 'stream_batch') return `${p.events?.length ?? 0} journal events${p.gap_detected ? ' · GAP DETECTED' : ''}`;
  if (p.kind === 'error_detail') return `${p.code}: ${p.message}`;
  return 'observation';
}

function prevOf(o, list) {
  return list
    .filter((x) => x.watch_id === o.watch_id && x.host_id === o.host_id && x.observation_id < o.observation_id && VALID_OBS.has(x.status))
    .sort((a, b) => b.observation_id - a.observation_id)[0];
}

function factRow(o, watchMap, list, selected, onSelect) {
  const key = `fact:${o.observation_id}`;
  const detail = el('div', { class: 'fact-detail', hidden: !state.expanded.has(key) });
  if (state.expanded.has(key)) append(detail, payloadView(o, prevOf(o, list)));
  const toggle = el('button', { class: 'toggle', type: 'button', attrs: { 'aria-expanded': state.expanded.has(key) ? 'true' : 'false', 'aria-label': `Toggle observation ${o.observation_id} detail` } }, icon('chevron'));
  toggle.addEventListener('click', () => {
    const open = toggle.getAttribute('aria-expanded') !== 'true';
    toggle.setAttribute('aria-expanded', String(open));
    detail.hidden = !open;
    if (open) {
      state.expanded.add(key);
      if (!detail.firstChild) append(detail, payloadView(o, prevOf(o, list)));
    } else state.expanded.delete(key);
  });
  const box = el('input', { type: 'checkbox', checked: selected.has(o.observation_id), title: 'Cite as evidence', attrs: { 'aria-label': `Cite observation ${o.observation_id} as evidence` } });
  box.addEventListener('change', () => {
    if (box.checked) selected.add(o.observation_id);
    else selected.delete(o.observation_id);
    onSelect?.();
  });
  const w = watchMap.get(o.watch_id);
  return el(
    'div',
    { class: 'fact', id: `fact-${o.observation_id}` },
    el(
      'div',
      { class: 'fact-row' },
      box,
      el('span', { class: 'oid', title: 'observation_id' }, `#${o.observation_id}`),
      el(
        'div',
        { class: 'what' },
        el('div', { class: 'w' }, o.watch_id, el('span', { class: 'muted' }, ` · ${collectorOf(o, watchMap)}`)),
        el('div', { class: 's' }, summarize(o)),
        el('div', { class: 'meta-line' }, w ? classBadge(w.class) : null, obsStatusBadge(o.status), hashChip(o.state_hash), el('span', { class: 'num muted' }, fmtTime(o.observed_at))),
      ),
      toggle,
    ),
    detail,
  );
}

// ----- payload renderers (structured, text-only) -----

const JPRIO = ['emerg', 'alert', 'crit', 'err', 'warning', 'notice', 'info', 'debug'];

function payloadView(o, prev) {
  const p = o.payload ?? {};
  const parts = [];
  if (p.kind === 'snapshot' || p.kind === 'delta') {
    const d = p.data ?? {};
    if (p.kind === 'delta') parts.push(el('div', { class: 'row' }, el('span', { class: 'muted' }, 'delta against'), hashChip(p.base_hash)));
    if (Array.isArray(d.sockets)) parts.push(socketsTable(d, prev?.payload?.data?.sockets));
    else if (d.unit && d.active_state) parts.push(unitView(d));
    else if (Array.isArray(d.files)) parts.push(filesTable(d.files));
    else parts.push(jsonBlock(d));
  } else if (p.kind === 'stream_batch') {
    parts.push(journalView(p));
  } else if (p.kind === 'error_detail') {
    parts.push(el('div', { class: 'err-box' }, el('span', { class: 'mono' }, p.code), ' — ', p.message));
  } else {
    parts.push(jsonBlock(p));
  }
  parts.push(
    el(
      'dl',
      { class: 'kv' },
      el('dt', null, 'observed_at'),
      el('dd', { class: 'num' }, o.observed_at),
      el('dt', null, 'spec_version'),
      el('dd', { class: 'num' }, String(o.spec_version)),
      el('dt', null, 'state_hash'),
      el('dd', null, hashChip(o.state_hash, { full: true })),
    ),
  );
  return el('div', { class: 'stack' }, parts);
}

function socketsTable(d, prevSockets) {
  const prevKeys = prevSockets ? new Set(prevSockets.map((s) => s.socket_key)) : null;
  const rows = [...d.sockets].sort((a, b) => a.local_port - b.local_port);
  return el(
    'div',
    { class: 'pwrap' },
    el(
      'table',
      { class: 'ptable' },
      el('thead', null, el('tr', null, ['proto', 'local', 'pid', 'comm', 'unit', 'uid', 'inode', ''].map((h) => el('th', null, h)))),
      el(
        'tbody',
        null,
        rows.map((s) => {
          const isNew = prevKeys && !prevKeys.has(s.socket_key);
          return el(
            'tr',
            { class: isNew ? 'is-new' : null },
            el('td', null, s.protocol),
            el('td', null, `${s.local_addr.includes(':') ? `[${s.local_addr}]` : s.local_addr}:${s.local_port}`),
            el('td', null, s.pid ?? '—'),
            el('td', null, s.comm ?? '—'),
            el('td', null, s.systemd_unit ?? '—'),
            el('td', null, String(s.uid)),
            el('td', null, String(s.inode)),
            el('td', null, isNew ? el('span', { class: 'badge bad' }, 'new') : ''),
          );
        }),
      ),
    ),
  );
}

function unitView(d) {
  const kv = [
    ['unit', d.unit],
    ['load / active / sub', `${d.load_state} / ${d.active_state} / ${d.sub_state}`],
    ['unit_file_state', d.unit_file_state ?? '—'],
    ['main_pid', d.main_pid ?? '—'],
  ];
  return el(
    'div',
    { class: 'stack' },
    el('dl', { class: 'kv' }, kv.map(([k, v]) => [el('dt', null, k), el('dd', { class: 'mono' }, String(v))]), el('dt', null, 'exec_start_hash'), el('dd', null, hashChip(d.exec_start_hash))),
    d.unit_files?.length ? filesTable(d.unit_files) : null,
  );
}

function filesTable(files) {
  return el(
    'div',
    { class: 'pwrap' },
    el(
      'table',
      { class: 'ptable' },
      el('thead', null, el('tr', null, ['path', 'status', 'mode', 'uid:gid', 'size', 'sha256', 'mtime'].map((h) => el('th', null, h)))),
      el(
        'tbody',
        null,
        files.map((f) =>
          el(
            'tr',
            null,
            el('td', null, f.path),
            el('td', null, obsStatusBadge(f.status)),
            el('td', null, f.mode_octal ?? '—'),
            el('td', null, f.uid != null ? `${f.uid}:${f.gid ?? '?'}` : '—'),
            el('td', null, f.size_bytes != null ? String(f.size_bytes) : '—'),
            el('td', null, f.sha256 ? hashChip(f.sha256) : '—'),
            el('td', null, f.mtime_unix ? fmtTime(new Date(f.mtime_unix * 1000).toISOString()) : f.detail ?? '—'),
          ),
        ),
      ),
    ),
  );
}

function journalView(p) {
  return el(
    'div',
    null,
    el('p', { class: 'untrusted-note' }, icon('alert'), 'Journal text is untrusted, attacker-influenced data. It is shown verbatim and cannot execute or instruct.'),
    p.gap_detected ? el('div', { class: 'err-box' }, 'Cursor gap detected — events may be missing between batches.') : null,
    el(
      'div',
      { class: 'journal' },
      (p.events ?? []).map((e) => {
        const pr = JPRIO[e.priority] ?? String(e.priority);
        const pcls = e.priority <= 3 ? 'p-err' : e.priority === 4 ? 'p-warn' : 'p-info';
        return el(
          'div',
          { class: 'jline' },
          el('span', { class: 't' }, fmtTime(new Date(Math.floor(e.timestamp_us / 1000)).toISOString())),
          el('span', { class: ['p', pcls] }, pr),
          el(
            'div',
            null,
            el('div', { class: 'm' }, e.message_redacted),
            e.redaction_applied || e.truncated
              ? el('div', { class: 'flags' }, e.redaction_applied ? el('span', { class: 'badge warn' }, 'redacted') : null, e.truncated ? el('span', { class: 'badge' }, 'truncated') : null, el('span', { class: 'badge ghost' }, e.classification.replace(/_/g, ' ')))
              : null,
          ),
        );
      }),
    ),
    el('div', { class: 'row muted mono' }, `cursor ${p.cursor_before ?? '∅'} → ${p.cursor_after ?? '∅'}`),
  );
}

function jsonBlock(value) {
  return el('pre', { class: 'json' }, JSON.stringify(value, null, 2));
}

// ----- watches -----

function watchTarget(w) {
  const p = w.collector.parameters ?? {};
  switch (w.collector.type) {
    case 'systemd.unit_state':
    case 'journal.unit_events':
      return p.unit;
    case 'files.metadata':
      return (p.paths ?? []).join(', ');
    case 'sockets.listening':
      return [p.include_tcp && 'tcp', p.include_udp && 'udp', p.include_ipv6 && 'ipv6'].filter(Boolean).join(' + ');
    default:
      return '';
  }
}

function watchesCard(watches, runtime, inc) {
  const sorted = [...watches].sort((a, b) => (a.class === b.class ? a.id.localeCompare(b.id) : a.class === 'ephemeral' ? -1 : 1));
  const eph = sorted.filter((w) => w.class === 'ephemeral');
  return card(
    'Watches in scope',
    `${eph.length} ephemeral · ${sorted.length - eph.length} baseline on ${inc.host_id}`,
    el('div', { class: 'card-body flush' }, sorted.length ? sorted.map((w) => watchRow(w, runtime[w.id])) : emptyState('No active watches', '')),
  );
}

function watchRow(w, rt) {
  const expired = w.lifecycle.expires_at && Date.parse(w.lifecycle.expires_at) <= Date.now();
  const retired = rt && rt.active === false && !expired;
  const runs = rt?.completed_runs;
  return el(
    'div',
    { class: ['watch', (expired || retired) && 'is-expired'] },
    el('div', { class: 'row' }, classBadge(w.class), expired ? el('span', { class: 'badge' }, 'expired') : null, el('span', { class: 'spacer' }), el('span', { class: 'mono muted' }, `v${w.version}`)),
    el('div', { class: 'wid' }, w.id),
    el('div', { class: 'target' }, el('span', { class: 'muted' }, `${w.collector.type} · `), watchTarget(w)),
    el(
      'div',
      { class: 'bounds' },
      el('span', { class: 'badge ghost' }, `every ${w.schedule.interval_seconds}s`),
      el('span', { class: 'badge ghost' }, w.trigger.type.replace(/_/g, ' ')),
      w.trigger.compare_against ? el('span', { class: 'badge ghost' }, `vs ${w.trigger.compare_against.replace(/_/g, ' ')}`) : null,
      w.class === 'ephemeral' && w.lifecycle.expires_at ? el('span', { class: ['badge', expired ? '' : 'eph'] }, icon('clock'), relTime(w.lifecycle.expires_at, { until: true })) : null,
    ),
    w.class === 'ephemeral' && w.lifecycle.max_runs
      ? el(
          'div',
          { class: 'mini' },
          el('span', null, 'runs'),
          meter(runs != null ? runs / w.lifecycle.max_runs : 0, 'eph'),
          el('span', { class: 'num' }, runs != null ? `${runs} / ${w.lifecycle.max_runs}` : `max ${w.lifecycle.max_runs}`),
        )
      : null,
  );
}

// ----- run lifecycle -----

async function startRun(incidentId) {
  try {
    const run = await api(`/api/incidents/${encodeURIComponent(incidentId)}/runs`, {
      method: 'POST',
      body: { backend_id: 'operator-console', model_id: 'human-operator', prompt_schema_version: 'console.v1' },
    });
    toast(`Investigation run ${run.run_id.slice(0, 8)} started`, 'ok');
    reloadWorkspace(incidentId);
  } catch (err) {
    toast(`${err.code}: ${err.message}`, 'bad');
  }
}

function runLock(inc, label) {
  return el(
    'div',
    { class: 'lock-overlay' },
    icon('lock'),
    el('p', null, `${label} requires an active investigation run. Runs are scoped to this incident and host, and expire automatically.`),
    el('button', { class: 'btn btn-primary btn-sm', type: 'button', on: { click: () => startRun(inc.incident_id) } }, icon('flask'), 'Start investigation run'),
  );
}

// ----- proposal composer -----

function triggerDefaults(type) {
  switch (type) {
    case 'sockets.listening':
      return { type: 'set_diff', compare_against: 'last_observed', set_field: 'sockets', identity_key: 'socket_key' };
    case 'systemd.unit_state':
      return { type: 'field_changed', compare_against: 'last_observed', fields: 'active_state, sub_state, main_pid, exec_start_hash' };
    case 'files.metadata':
      return { type: 'set_diff', compare_against: 'last_observed', set_field: 'files', identity_key: 'path' };
    default:
      return { type: 'collector_stale_or_error', max_stale_seconds: 300, consecutive_errors: 3 };
  }
}

function numInput(obj, key, { min, max, onInput } = {}) {
  const input = el('input', { type: 'number', value: String(obj[key] ?? ''), min, max });
  input.addEventListener('input', () => {
    obj[key] = input.value === '' ? '' : Number(input.value);
    onInput?.();
  });
  return input;
}

function textInput(obj, key, { placeholder = '', mono = false, onInput } = {}) {
  const input = el('input', { type: 'text', value: String(obj[key] ?? ''), placeholder, class: mono ? 'mono-input' : null });
  input.addEventListener('input', () => {
    obj[key] = input.value;
    onInput?.();
  });
  return input;
}

function textArea(obj, key, { placeholder = '', rows = 3, mono = false } = {}) {
  const t = el('textarea', { placeholder, rows, class: mono ? 'mono-input' : null, value: String(obj[key] ?? '') });
  t.addEventListener('input', () => {
    obj[key] = t.value;
  });
  return t;
}

function selectInput(obj, key, options, onChange) {
  const s = el('select', null, options.map(([v, label]) => el('option', { value: v, selected: obj[key] === v }, label)));
  s.addEventListener('change', () => {
    obj[key] = s.value;
    onChange?.();
  });
  return s;
}

function check(obj, key, label) {
  const c = el('input', { type: 'checkbox', checked: Boolean(obj[key]) });
  c.addEventListener('change', () => {
    obj[key] = c.checked;
  });
  return el('label', null, c, label);
}

function field(label, control, hint = null) {
  return el('div', { class: 'field' }, el('label', null, label), control, hint);
}

function proposalComposer(inc, run, caps) {
  const d = draftsFor(inc.incident_id).proposal;
  if (!d.trigger) d.trigger = triggerDefaults(d.collector_type);
  const body = el('div', { class: 'card-body' });
  const result = el('div', { class: 'stack' });
  const capFor = (t) => caps.find((c) => c.collector_type === t);

  function paramsFields() {
    const p = d.parameters;
    switch (d.collector_type) {
      case 'sockets.listening':
        return el('div', { class: 'checks' }, check(p, 'include_tcp', 'TCP'), check(p, 'include_udp', 'UDP'), check(p, 'include_ipv6', 'IPv6'), check(p, 'resolve_process', 'Resolve owning process'));
      case 'systemd.unit_state':
        return el('div', { class: 'stack' }, field('Unit', textInput(p, 'unit', { placeholder: 'custom-helper.service', mono: true }), el('span', { class: 'hint' }, 'Must end in .service, .socket, .timer, …')), el('div', { class: 'checks' }, check(p, 'hash_unit_files', 'Hash unit files')));
      case 'files.metadata':
        return el('div', { class: 'stack' }, field('Paths (one per line)', textArea(p, 'paths', { placeholder: '/etc/systemd/system/custom-helper.service', rows: 3, mono: true }), el('span', { class: 'hint' }, 'Approved roots: /etc/systemd/system, /etc/ssh, /etc/nginx, /etc/cron.d, /usr/lib/systemd/system')), el('div', { class: 'checks' }, check(p, 'compute_hash', 'Compute SHA-256')));
      case 'journal.unit_events':
        return el('div', { class: 'stack' }, field('Unit', textInput(p, 'unit', { placeholder: 'custom-helper.service', mono: true })), el('div', { class: 'grid-3' }, field('Min priority', numInput(p, 'min_priority', { min: 0, max: 7 })), field('Max events', numInput(p, 'max_events_per_batch', { min: 1 })), field('Max bytes', numInput(p, 'max_message_bytes', { min: 1 }))));
      default:
        return null;
    }
  }

  function triggerFields() {
    const t = d.trigger;
    const typeSel = selectInput(t, 'type', [['field_changed', 'field_changed'], ['set_diff', 'set_diff'], ['threshold_sustained', 'threshold_sustained'], ['collector_stale_or_error', 'collector_stale_or_error']], () => {
      const keep = t.type;
      Object.assign(t, triggerDefaults(d.collector_type), { type: keep });
      draw();
    });
    const compareHint = t.compare_against === 'accepted_baseline' && d.class === 'ephemeral' ? el('span', { class: 'hint warn' }, 'Ephemeral watches cannot compare against accepted_baseline (spec.safety_floor).') : null;
    const compare = t.type === 'field_changed' || t.type === 'set_diff' ? field('Compare against', selectInput(t, 'compare_against', [['last_observed', 'last_observed'], ['accepted_baseline', 'accepted_baseline']], draw), compareHint) : null;
    let extra = null;
    if (t.type === 'field_changed') extra = field('Fields (comma separated)', textInput(t, 'fields', { mono: true }));
    if (t.type === 'set_diff') extra = el('div', { class: 'grid-2' }, field('Set field', textInput(t, 'set_field', { mono: true })), field('Identity key', textInput(t, 'identity_key', { mono: true })));
    if (t.type === 'threshold_sustained') {
      t.operator ??= 'gt';
      t.threshold ??= 0;
      t.consecutive_samples ??= 3;
      t.field ??= 'count';
      extra = el('div', { class: 'grid-2' }, field('Field', textInput(t, 'field', { mono: true })), field('Operator', selectInput(t, 'operator', ['gt', 'gte', 'lt', 'lte', 'eq', 'neq'].map((x) => [x, x]))), field('Threshold', numInput(t, 'threshold')), field('Consecutive samples', numInput(t, 'consecutive_samples', { min: 1 })));
    }
    if (t.type === 'collector_stale_or_error') {
      t.max_stale_seconds ??= 300;
      t.consecutive_errors ??= 3;
      extra = el('div', { class: 'grid-2' }, field('Max stale (s)', numInput(t, 'max_stale_seconds', { min: 1 })), field('Consecutive errors', numInput(t, 'consecutive_errors', { min: 1 })));
    }
    return el('div', { class: 'stack' }, el('div', { class: 'grid-2' }, field('Trigger', typeSel), compare), extra);
  }

  function boundsHints() {
    const cap = capFor(d.collector_type);
    const minIv = cap?.min_interval_seconds ?? FLOOR.min_interval;
    const hints = [];
    if (d.interval_seconds < minIv) hints.push(`interval below floor ${minIv}s`);
    if (d.timeout_seconds < 1 || d.timeout_seconds > FLOOR.max_timeout) hints.push(`timeout must be 1–${FLOOR.max_timeout}s`);
    if (d.timeout_seconds >= d.interval_seconds) hints.push('timeout must be < interval');
    if (d.class === 'ephemeral' && d.ttl_minutes > FLOOR.max_ttl_min) hints.push(`TTL above ${FLOOR.max_ttl_min} min ceiling`);
    if (d.max_runs < 1 || d.max_runs > FLOOR.max_runs) hints.push(`max runs must be 1–${FLOOR.max_runs}`);
    return hints;
  }

  const hintNode = el('div', { class: 'field' });
  function updateHints() {
    const hints = boundsHints();
    replace(
      hintNode,
      hints.length
        ? el('span', { class: 'hint warn' }, `Outside the safety floor: ${hints.join(' · ')}. Submit anyway to see control-d deny it.`)
        : el('span', { class: 'hint' }, `Within floor: interval ≥ ${capFor(d.collector_type)?.min_interval_seconds ?? FLOOR.min_interval}s, TTL ≤ ${FLOOR.max_ttl_min} min, max runs ≤ ${FLOOR.max_runs}. control-d decides.`),
    );
  }

  function requestBody() {
    const p = d.parameters;
    const params = {
      'sockets.listening': { include_tcp: p.include_tcp, include_udp: p.include_udp, include_ipv6: p.include_ipv6, resolve_process: p.resolve_process },
      'systemd.unit_state': { unit: p.unit, hash_unit_files: p.hash_unit_files },
      'files.metadata': { paths: String(p.paths ?? '').split('\n').map((s) => s.trim()).filter(Boolean), compute_hash: p.compute_hash },
      'journal.unit_events': { unit: p.unit, min_priority: p.min_priority, max_events_per_batch: p.max_events_per_batch, max_message_bytes: p.max_message_bytes },
    }[d.collector_type];
    const t = { ...d.trigger };
    if (typeof t.fields === 'string') t.fields = t.fields.split(',').map((s) => s.trim()).filter(Boolean);
    return {
      run_id: run?.run_id,
      class: d.class,
      collector_type: d.collector_type,
      parameters: params,
      interval_seconds: d.interval_seconds,
      timeout_seconds: d.timeout_seconds,
      ttl_seconds: Math.round(Number(d.ttl_minutes) * 60),
      max_runs: d.max_runs,
      cooldown_seconds: d.cooldown_seconds,
      max_wakeups_per_hour: d.max_wakeups_per_hour,
      trigger: t,
      rationale: d.rationale,
    };
  }

  function renderResult() {
    const log = state.decisions.get(inc.incident_id) ?? [];
    const last = log[0];
    replace(
      result,
      last
        ? el(
            'div',
            { class: ['decision', last.decision.allowed ? 'ok' : 'bad'], attrs: { role: 'status' } },
            el('div', { class: 'row' }, el('span', { class: 'verdict' }, last.decision.allowed ? 'Accepted by policy gate' : 'Denied by policy gate'), el('span', { class: 'spacer' }), el('span', { class: 'mono muted' }, `policy v${last.decision.policy_version}`)),
            el('div', { class: 'rule' }, last.decision.rule_id),
            el('div', { class: 'reason' }, last.decision.reason),
            last.watch_id ? el('div', { class: 'row' }, el('span', { class: 'badge eph' }, 'watch'), el('span', { class: 'mono' }, last.watch_id), last.bundle_version != null ? el('span', { class: 'badge ghost' }, `bundle v${last.bundle_version}`) : null) : null,
            last.spec ? el('details', { class: 'preview' }, el('summary', null, 'Submitted WatchSpec (exact)'), jsonBlock(last.spec)) : null,
          )
        : null,
      log.length > 1
        ? el(
            'div',
            { class: 'history' },
            el('span', { class: 'eyebrow' }, 'This session'),
            log.slice(1, 6).map((x) => el('div', { class: 'h-item' }, el('span', { class: ['dot', x.decision.allowed ? 'ok' : 'bad'] }), el('span', { class: 'mono' }, x.decision.rule_id), el('span', { class: 'num muted' }, fmtTime(x.at)))),
          )
        : null,
    );
  }

  async function submit(btn) {
    btn.disabled = true;
    try {
      const r = await api(`/api/incidents/${encodeURIComponent(inc.incident_id)}/proposals`, { method: 'POST', body: requestBody() });
      const log = state.decisions.get(inc.incident_id) ?? [];
      log.unshift({ ...r, at: new Date().toISOString() });
      state.decisions.set(inc.incident_id, log);
      renderResult();
      if (r.decision.allowed) {
        toast(`Accepted: ${r.watch_id} → bundle v${r.bundle_version}`, 'ok');
        setTimeout(() => reloadWorkspace(inc.incident_id), 600);
      } else {
        toast(`Denied: ${r.decision.rule_id}`, 'bad');
      }
    } catch (err) {
      toast(`${err.code}: ${err.message}`, 'bad');
    } finally {
      btn.disabled = false;
    }
  }

  function draw() {
    const classSeg = el(
      'div',
      { class: 'seg', attrs: { role: 'group', 'aria-label': 'Watch class' } },
      el('button', { type: 'button', class: 'emerald', attrs: { 'aria-pressed': String(d.class === 'ephemeral') }, on: { click: () => { d.class = 'ephemeral'; draw(); } } }, 'Ephemeral'),
      el('button', { type: 'button', class: 'crimson', attrs: { 'aria-pressed': String(d.class === 'baseline') }, on: { click: () => { d.class = 'baseline'; draw(); } } }, 'Baseline (policy test)'),
    );
    const capButtons = el(
      'div',
      { class: 'cap-list' },
      (caps.length ? caps : [{ collector_type: 'sockets.listening' }, { collector_type: 'systemd.unit_state' }, { collector_type: 'files.metadata' }, { collector_type: 'journal.unit_events' }]).map((c) =>
        el(
          'button',
          {
            class: 'cap',
            type: 'button',
            title: c.description ?? '',
            attrs: { 'aria-pressed': String(d.collector_type === c.collector_type) },
            on: {
              click: () => {
                d.collector_type = c.collector_type;
                d.trigger = triggerDefaults(c.collector_type);
                draw();
              },
            },
          },
          el('span', { class: 'ct' }, c.collector_type),
          el('span', { class: 'cd' }, c.sensitivity ? `${c.sensitivity.replace(/_/g, ' ')} · ≥${c.min_interval_seconds}s` : 'catalog unavailable'),
        ),
      ),
    );
    const iv = numInput(d, 'interval_seconds', { min: 1, onInput: updateHints });
    const to = numInput(d, 'timeout_seconds', { min: 1, onInput: updateHints });
    const ttl = numInput(d, 'ttl_minutes', { min: 1, onInput: updateHints });
    const mr = numInput(d, 'max_runs', { min: 1, onInput: updateHints });
    const submitBtn = el('button', { class: 'btn btn-primary', type: 'submit' }, 'Submit to policy gate');
    const form = el(
      'form',
      { class: 'form', attrs: { novalidate: true } },
      field('Watch class', classSeg, d.class === 'baseline' ? el('span', { class: 'hint bad' }, 'Investigator identities cannot create baseline watches — expect baseline.protected.') : el('span', { class: 'hint' }, 'Bounded by TTL and max runs; retired on incident closure.')),
      el('div', { class: 'field' }, el('span', { class: 'lbl' }, 'Collector capability', el('span', { class: 'muted' }, `${inc.host_id} catalog`)), capButtons),
      paramsFields(),
      triggerFields(),
      el('div', { class: 'grid-2' }, field('Interval (s)', iv), field('Timeout (s)', to), field('TTL (min)', ttl), field('Max runs', mr)),
      hintNode,
      field('Rationale', textArea(d, 'rationale', { placeholder: 'Why this temporary watch is needed for the investigation…', rows: 2 })),
      el('details', { class: 'preview' }, el('summary', null, 'Request preview'), jsonBlock({ ...requestBody(), run_id: run?.run_id ? `${run.run_id.slice(0, 8)}…` : null })),
      el('div', { class: 'form-actions' }, submitBtn),
    );
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      submit(submitBtn);
    });
    replace(body, form, result);
    updateHints();
    renderResult();
  }

  if (!run) {
    append(body, runLock(inc, 'Proposing an ephemeral watch'));
    renderResult();
    append(body, result);
  } else {
    draw();
  }
  return card('Propose ephemeral watch', 'Constrained to the host capability catalog; control-d returns the deterministic PolicyDecision.', body);
}

// ----- finding composer -----

function findingComposerView(inc, run, obsMap) {
  const d = draftsFor(inc.incident_id).finding;
  const selected = evidenceFor(inc.incident_id);
  const body = el('div', { class: 'card-body' });
  const evNode = el('div', { class: 'ev-row' });
  const evHint = el('span', { class: 'hint' });

  function refreshEvidence() {
    const ids = [...selected].sort((a, b) => a - b);
    replace(
      evNode,
      ids.length
        ? ids.map((id) => {
            const o = obsMap.get(id);
            return el(
              'button',
              { class: 'ev-badge', type: 'button', title: 'Remove from evidence', on: { click: () => { selected.delete(id); const box = document.querySelector(`#fact-${id} input[type="checkbox"]`); if (box) box.checked = false; refreshEvidence(); } } },
              `obs ${id}`,
              o ? el('span', { class: 'h' }, o.state_hash.slice(0, 8)) : null,
              icon('close'),
            );
          })
        : el('span', { class: 'muted' }, 'Tick observed facts on the left to cite them.'),
    );
    const needs = d.kind === 'verified_finding' && ids.length === 0;
    evHint.className = needs ? 'hint warn' : 'hint';
    evHint.textContent = needs ? 'A verified finding must cite at least one observation.' : `${ids.length} observation${ids.length === 1 ? '' : 's'} will be bound by ID and state_hash.`;
  }

  function draw() {
    const seg = el(
      'div',
      { class: 'seg', attrs: { role: 'group', 'aria-label': 'Finding kind' } },
      el('button', { type: 'button', class: 'amber', attrs: { 'aria-pressed': String(d.kind === 'hypothesis') }, on: { click: () => { d.kind = 'hypothesis'; draw(); } } }, 'Hypothesis'),
      el('button', { type: 'button', class: 'emerald', attrs: { 'aria-pressed': String(d.kind === 'verified_finding') }, on: { click: () => { d.kind = 'verified_finding'; draw(); } } }, 'Verified finding'),
    );
    const btn = el('button', { class: d.kind === 'verified_finding' ? 'btn btn-ok' : 'btn btn-primary', type: 'submit' }, d.kind === 'verified_finding' ? 'Record verified finding' : 'Record hypothesis');
    const form = el(
      'form',
      { class: 'form', attrs: { novalidate: true } },
      el('div', { class: 'grid-2' }, field('Kind', seg), field('Severity', selectInput(d, 'severity', SEV_ORDER.slice().reverse().map((s) => [s, s])))),
      field('Summary', textArea(d, 'summary', { placeholder: 'What is asserted, in one or two sentences…', rows: 3 })),
      field('Uncertainty', textArea(d, 'uncertainty', { placeholder: 'What is not yet established, alternative explanations…', rows: 2 })),
      el('div', { class: 'field' }, el('span', { class: 'lbl' }, 'Evidence observations'), evNode, evHint),
      el('div', { class: 'checks' }, check(d, 'escalation_requested', 'Request escalation to operator')),
      el('div', { class: 'form-actions' }, btn),
    );
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      btn.disabled = true;
      try {
        const r = await api(`/api/incidents/${encodeURIComponent(inc.incident_id)}/findings`, {
          method: 'POST',
          body: { run_id: run?.run_id, kind: d.kind, severity: d.severity, summary: d.summary, uncertainty: d.uncertainty, escalation_requested: d.escalation_requested, evidence_observation_ids: [...selected] },
        });
        toast(`Finding #${r.finding_id} recorded · ${r.verified_evidence_count} evidence hash${r.verified_evidence_count === 1 ? '' : 'es'} bound`, 'ok');
        d.summary = '';
        d.uncertainty = '';
        selected.clear();
        reloadWorkspace(inc.incident_id);
      } catch (err) {
        toast(`${err.code}: ${err.message}`, 'bad');
        btn.disabled = false;
      }
    });
    replace(body, form);
    refreshEvidence();
  }

  if (!run) append(body, runLock(inc, 'Recording a hypothesis or finding'));
  else draw();
  return {
    node: card('Record hypothesis / finding', 'Hypotheses are unverified assertions; verified findings must bind evidence.', body),
    refreshEvidence: () => (run ? refreshEvidence() : undefined),
  };
}

// ---------------------------------------------------------------------------
// View: Baselines & Telemetry
// ---------------------------------------------------------------------------

const TRI_STATE = {
  in_sync: ['ok', 'In sync'],
  drift: ['warn', 'Drift'],
  collector_error: ['bad', 'Collector error'],
  no_trusted_baseline: ['eph', 'No trusted baseline'],
  baseline_absent: ['warn', 'Baseline absent'],
  no_data: ['', 'No data'],
};

async function renderBaselines(arg, stale) {
  const b = state.baselines;
  if (arg) b.host = arg;
  if (!b.host || !state.hosts.some((h) => h.host_id === b.host)) b.host = state.hosts[0]?.host_id ?? null;
  if (!b.host) return emptyState('No hosts in scope', '');
  if (arg !== b.host) history.replaceState(null, '', `#/baselines/${encodeURIComponent(b.host)}`);

  const host = b.host;
  const q = new URLSearchParams({ limit: String(b.limit) });
  if (b.watch) q.set('watch_id', b.watch);
  const [base, watches, obs] = await Promise.all([
    api(`/api/hosts/${encodeURIComponent(host)}/baselines`),
    api(`/api/hosts/${encodeURIComponent(host)}/watches`),
    api(`/api/hosts/${encodeURIComponent(host)}/observations?${q}`),
  ]);
  if (stale()) return null;
  if (b.watch && !watches.watches.some((w) => w.id === b.watch)) b.watch = '';
  const watchMap = new Map(watches.watches.map((w) => [w.id, w]));

  const hostChips = el(
    'div',
    { class: 'host-chips', attrs: { role: 'group', 'aria-label': 'Host' } },
    state.hosts.map((h) =>
      el(
        'button',
        { class: 'chip', type: 'button', attrs: { 'aria-pressed': String(h.host_id === host) }, on: { click: () => { b.watch = ''; location.hash = `#/baselines/${encodeURIComponent(h.host_id)}`; } } },
        el('span', { class: ['dot', h.liveness_status === 'online' ? 'ok' : h.liveness_status === 'offline' ? 'bad' : 'warn'] }),
        el('span', { class: 'mono' }, h.host_id),
      ),
    ),
  );
  const watchSel = el('select', null, el('option', { value: '' }, 'All watches'), watches.watches.map((w) => el('option', { value: w.id, selected: w.id === b.watch }, `${w.class === 'baseline' ? '◼' : '◇'} ${w.id}`)));
  watchSel.addEventListener('change', () => {
    b.watch = watchSel.value;
    render();
  });
  const limitSel = el('select', null, [25, 50, 100, 200, 500].map((n) => el('option', { value: String(n), selected: n === b.limit }, `${n} rows`)));
  limitSel.addEventListener('change', () => {
    b.limit = Number(limitSel.value);
    render();
  });

  const tri = base.three_state.filter((r) => !b.watch || r.watch_id === b.watch);
  const triCard = card(
    'Three-state baseline',
    'accepted_baseline is never advanced automatically; promotion is an attributable admin action.',
    el(
      'div',
      { class: 'tri' },
      el('div', { class: 'tri-row head' }, el('div', null, 'Watch'), el('div', null, 'Accepted baseline'), el('div', null, 'Last observed'), el('div', null, 'Current observed'), el('div', { class: 'tri-state' }, 'State')),
      tri.length ? tri.map((r) => triRow(host, r)) : emptyState('No watches', ''),
    ),
  );

  const rows = [];
  const sortedObs = [...obs.observations].sort((a, b2) => b2.observation_id - a.observation_id);
  for (const o of sortedObs) {
    const key = `obs:${o.observation_id}`;
    const open = state.expanded.has(key);
    const toggle = el('button', { class: 'toggle', type: 'button', attrs: { 'aria-expanded': String(open), 'aria-label': `Toggle observation ${o.observation_id}` } }, icon('chevron'));
    const w = watchMap.get(o.watch_id);
    const tr = el(
      'tr',
      null,
      el('td', null, toggle),
      el('td', { class: 'mono' }, `#${o.observation_id}`),
      el('td', { class: 'mono' }, fmtTime(o.observed_at)),
      el('td', { class: 'mono' }, o.watch_id),
      el('td', null, w ? classBadge(w.class) : el('span', { class: 'muted' }, 'retired')),
      el('td', null, obsStatusBadge(o.status)),
      el('td', null, hashChip(o.state_hash)),
      el('td', { class: 'sum' }, summarize(o)),
    );
    const detailCell = el('td', { attrs: { colspan: '8' } });
    const detail = el('tr', { class: 'detail', hidden: !open }, detailCell);
    if (open) append(detailCell, payloadView(o, prevOf(o, sortedObs)));
    toggle.addEventListener('click', () => {
      const now = toggle.getAttribute('aria-expanded') !== 'true';
      toggle.setAttribute('aria-expanded', String(now));
      detail.hidden = !now;
      if (now) {
        state.expanded.add(key);
        if (!detailCell.firstChild) append(detailCell, payloadView(o, prevOf(o, sortedObs)));
      } else state.expanded.delete(key);
    });
    rows.push(tr, detail);
  }

  const obsCard = card(
    'Observations',
    'QueryObservations via control-d · bounded, classified evidence slices',
    el(
      'div',
      { class: 'card-body flush table-wrap' },
      sortedObs.length
        ? el('table', { class: 'obs-table' }, el('thead', null, el('tr', null, ['', 'ID', 'Observed', 'Watch', 'Class', 'Status', 'state_hash', 'Summary'].map((h) => el('th', null, h)))), el('tbody', null, rows))
        : emptyState('No observations', 'Nothing collected for this filter yet.'),
    ),
    el('span', { class: 'badge ghost' }, `${sortedObs.length} rows`),
  );

  return el(
    'div',
    null,
    el('div', { class: 'toolbar' }, el('div', { class: 'field' }, el('span', { class: 'lbl' }, 'Host'), hostChips), el('span', { class: 'spacer' }), field('Watch', watchSel), field('Limit', limitSel)),
    el('div', { class: 'stack' }, triCard, obsCard),
  );
}

function triCell(entry, extra) {
  if (!entry) return el('div', { class: 'tri-cell' }, el('span', { class: 'hash is-null' }, '— none —'), el('span', { class: 'meta' }, extra ?? ''));
  return el('div', { class: 'tri-cell' }, hashChip(entry.state_hash), el('span', { class: 'meta', title: extra ?? '' }, extra));
}

function triRow(host, r) {
  const [cls, label] = TRI_STATE[r.state] ?? ['', r.state];
  const a = r.accepted_baseline;
  const promote =
    r.promotable_observation_id != null
      ? el(
          'button',
          {
            class: 'btn btn-sm btn-ok',
            type: 'button',
            disabled: !adminEnabled(),
            title: adminEnabled() ? `Promote observation ${r.promotable_observation_id} to accepted baseline` : 'Admin interface disabled',
            on: { click: () => openPromoteDrawer(host, r) },
          },
          adminEnabled() ? null : icon('lock'),
          'Promote',
        )
      : null;
  return el(
    'div',
    { class: 'tri-row' },
    el('div', { class: 'tri-cell tri-watch' }, el('div', { class: 'row' }, classBadge(r.class)), el('span', { class: 'wid' }, r.watch_id), el('span', { class: 'meta' }, r.collector_type ?? '')),
    triCell(a, a ? `rev ${a.revision_id} · ${a.approver}${a.ticket_ref ? ` · ${a.ticket_ref}` : ''}` : r.class === 'ephemeral' ? 'ephemeral: cannot hold a trusted baseline' : 'never promoted'),
    triCell(r.last_observed, r.last_observed ? `#${r.last_observed.observation_id} · ${fmtTime(r.last_observed.observed_at)}` : 'no prior valid sample'),
    triCell(r.current_observed, r.current_observed ? `#${r.current_observed.observation_id} · ${r.current_observed.status} · ${fmtTime(r.current_observed.observed_at)}` : 'no data'),
    el('div', { class: 'tri-state' }, el('div', { class: 'row' }, el('span', { class: ['badge', cls] }, label), r.changed_since_last ? el('span', { class: 'badge warn', title: 'current_observed differs from last_observed' }, 'changed') : null), promote),
  );
}

// ---------------------------------------------------------------------------
// View: Policy Gate & Audit
// ---------------------------------------------------------------------------

async function renderAudit(_arg, stale) {
  if (!adminEnabled()) {
    return el(
      'div',
      { class: 'card' },
      el(
        'div',
        { class: 'locked-panel' },
        icon('lock'),
        el('h2', null, 'Admin interface disabled'),
        el('p', { class: 'muted' }, 'Policy decisions and the hash-chained audit log are only readable over control-d\'s separate admin socket. The console never reads SQLite directly.'),
        el('code', null, 'node console/server.mjs --investigate-sock … --token-file … --enable-admin --admin-sock /run/defsec/admin.sock'),
      ),
    );
  }
  const [audit, decisions] = await Promise.all([api('/api/admin/audit?limit=500'), api('/api/admin/policy-decisions?limit=500')]);
  if (stale()) return null;
  const a = state.audit;
  const ind = audit.independent;

  const verdict = (ok, text) => el('div', { class: ['verdict-line', ok ? 'ok' : 'bad'] }, icon(ok ? 'shield' : 'alert'), text);
  const integrity = el(
    'div',
    { class: 'integrity' },
    card(
      'control-d · VerifyAuditChain',
      'Full chain from genesis, verified inside the control plane',
      el(
        'div',
        { class: 'card-body' },
        verdict(audit.chain.valid, audit.chain.valid ? 'Chain valid' : 'Chain verification failed'),
        el('dl', { class: 'kv' }, el('dt', null, 'entries checked'), el('dd', { class: 'num' }, String(audit.chain.entries_checked)), audit.chain.error ? [el('dt', null, 'error'), el('dd', { class: 'mono' }, audit.chain.error)] : null),
        audit.chain.latest_hash ? el('button', { class: 'head-hash', type: 'button', title: 'Copy chain head', on: { click: (e) => copy(audit.chain.latest_hash, e.currentTarget) } }, audit.chain.latest_hash) : null,
      ),
    ),
    card(
      'Console · independent re-verification',
      'SHA-256 recomputed in this BFF over RFC 8785 canonical entries',
      el(
        'div',
        { class: 'card-body' },
        verdict(ind.valid, ind.valid ? 'Window recomputed, links intact' : 'Mismatch detected'),
        el(
          'dl',
          { class: 'kv' },
          el('dt', null, 'window'),
          el('dd', { class: 'num' }, ind.first_seq != null ? `seq ${ind.first_seq} → ${ind.last_seq ?? ind.broken_seq}` : 'empty'),
          el('dt', null, 'recomputed'),
          el('dd', { class: 'num' }, `${ind.checked} entries`),
          ind.error ? [el('dt', null, 'error'), el('dd', { class: 'mono' }, ind.error)] : null,
          el('dt', null, 'agrees with control-d'),
          el('dd', null, ind.valid && audit.chain.valid && ind.head === audit.chain.latest_hash ? el('span', { class: 'badge ok' }, 'head matches') : el('span', { class: 'badge warn' }, ind.valid && audit.chain.valid ? 'window head differs' : 'no')),
        ),
      ),
    ),
  );

  const demoTools = isDemo()
    ? el(
        'div',
        { class: 'row' },
        el('span', { class: 'muted' }, 'Demo tools:'),
        el('button', { class: 'btn btn-sm btn-danger', type: 'button', on: { click: () => demoAction('/api/demo/tamper', 'Rewrote an audit entry payload without re-hashing') } }, 'Simulate tamper'),
        el('button', { class: 'btn btn-sm', type: 'button', on: { click: () => demoAction('/api/demo/reset', 'Demo state reset') } }, 'Reset demo'),
      )
    : null;

  const tabs = el(
    'div',
    { class: 'tabs', attrs: { role: 'tablist' } },
    [
      ['decisions', `Policy decisions · ${decisions.decisions.length}`],
      ['audit', `Audit log · ${audit.entries.length}`],
    ].map(([id, label]) => el('button', { type: 'button', attrs: { role: 'tab', 'aria-selected': String(a.tab === id) }, on: { click: () => { a.tab = id; render(); } } }, label)),
  );

  return el('div', null, integrity, demoTools ? el('div', { class: 'section-title' }, demoTools) : null, tabs, a.tab === 'decisions' ? decisionsPanel(decisions.decisions) : auditPanel(audit));
}

async function demoAction(path, msg) {
  try {
    await api(path, { method: 'POST' });
    toast(msg, path.endsWith('tamper') ? 'bad' : 'ok');
    state.drafts.clear();
    state.decisions.clear();
    state.evidence.clear();
    await refreshAll();
  } catch (err) {
    toast(`${err.code}: ${err.message}`, 'bad');
  }
}

function decisionsPanel(all) {
  const a = state.audit;
  const counts = new Map();
  for (const d of all) counts.set(d.decision.rule_id, (counts.get(d.decision.rule_id) ?? 0) + 1);
  const shown = all.filter((d) => (a.verdict === 'all' || (a.verdict === 'allowed') === d.decision.allowed) && (!a.ruleFilter || d.decision.rule_id === a.ruleFilter));
  const chip = (label, pressed, onClick, extra = null) => el('button', { class: 'chip', type: 'button', attrs: { 'aria-pressed': String(pressed) }, on: { click: onClick } }, label, extra);
  const filters = el(
    'div',
    { class: 'row' },
    chip('All', a.verdict === 'all', () => { a.verdict = 'all'; render(); }),
    chip('Accepted', a.verdict === 'allowed', () => { a.verdict = 'allowed'; render(); }, el('span', { class: 'dot ok' })),
    chip('Denied', a.verdict === 'denied', () => { a.verdict = 'denied'; render(); }, el('span', { class: 'dot bad' })),
    el('span', { class: 'muted' }, '·'),
    [...counts.entries()].sort().map(([rule, n]) => chip(el('span', { class: 'mono' }, rule), a.ruleFilter === rule, () => { a.ruleFilter = a.ruleFilter === rule ? null : rule; render(); }, el('span', { class: 'num muted' }, String(n)))),
  );
  return card(
    'Policy gate decisions',
    'Every proposal passes the same deterministic validator, regardless of who submitted it.',
    el(
      'div',
      null,
      el('div', { class: 'card-body' }, filters),
      el(
        'div',
        { class: 'table-wrap' },
        shown.length
          ? el(
              'table',
              { class: 'dec-table' },
              el('thead', null, el('tr', null, ['#', 'When', 'Actor', 'Rule', 'Reason', 'Proposal', 'Policy'].map((h) => el('th', null, h)))),
              el(
                'tbody',
                null,
                shown.map((d) =>
                  el(
                    'tr',
                    null,
                    el('td', { class: 'mono' }, String(d.decision_id)),
                    el('td', { class: 'mono' }, fmtTime(d.created_at)),
                    el('td', { class: 'mono' }, d.actor),
                    el('td', null, rulePill(d.decision)),
                    el('td', { class: 'reason' }, d.decision.reason),
                    el('td', { class: 'mono' }, d.proposal_id != null ? String(d.proposal_id) : '—'),
                    el('td', { class: 'mono' }, `v${d.decision.policy_version}`),
                  ),
                ),
              ),
            )
          : emptyState('No matching decisions', ''),
      ),
    ),
  );
}

function auditPanel(audit) {
  const a = state.audit;
  const broken = audit.independent.broken_seq;
  const entries = a.newestFirst ? [...audit.entries].reverse() : audit.entries;
  const order = el('button', { class: 'btn btn-sm btn-ghost', type: 'button', on: { click: () => { a.newestFirst = !a.newestFirst; render(); } } }, a.newestFirst ? 'Newest first' : 'Oldest first');
  return card(
    'Hash-chained audit outbox',
    'entry_hash = SHA-256("defsecautmit.audit_entry.v1\\0" ‖ canonical(entry)); each prev_hash links to the prior entry_hash.',
    el(
      'div',
      { class: 'audit-list' },
      entries.length
        ? entries.map((e) => {
            const key = `audit:${e.seq_no}`;
            const open = state.expanded.has(key);
            const detail = el('div', { class: 'aentry-detail', hidden: !open }, open ? jsonBlock(e.payload) : null);
            const toggle = el('button', { class: 'toggle', type: 'button', attrs: { 'aria-expanded': String(open), 'aria-label': `Toggle audit entry ${e.seq_no}` } }, icon('chevron'));
            toggle.addEventListener('click', () => {
              const now = toggle.getAttribute('aria-expanded') !== 'true';
              toggle.setAttribute('aria-expanded', String(now));
              detail.hidden = !now;
              if (now) {
                state.expanded.add(key);
                if (!detail.firstChild) append(detail, jsonBlock(e.payload));
              } else state.expanded.delete(key);
            });
            return el(
              'div',
              null,
              el(
                'div',
                { class: ['aentry', broken != null && e.seq_no === broken && 'broken'] },
                el('span', { class: 'seq' }, `#${e.seq_no}`),
                el('span', { class: 'when', title: e.timestamp }, fmtTime(e.timestamp)),
                el(
                  'div',
                  { class: 'what' },
                  el('div', { class: 'row' }, el('span', { class: ['evt', `e-${e.event_type}`] }, e.event_type), el('span', { class: 'actor' }, e.actor), broken != null && e.seq_no === broken ? el('span', { class: 'badge bad' }, 'hash mismatch') : null),
                  el('div', { class: 'link' }, hashChip(e.prev_hash, { label: e.prev_hash === '0'.repeat(64) ? 'genesis' : shortHash(e.prev_hash) }), el('span', { class: 'arrow' }, '→'), hashChip(e.entry_hash)),
                ),
                toggle,
              ),
              detail,
            );
          })
        : emptyState('No audit entries', ''),
    ),
    order,
  );
}

// ---------------------------------------------------------------------------
// Drawers (admin mutations)
// ---------------------------------------------------------------------------

const drawer = () => document.getElementById('drawer');

function openDrawer(title, sub, bodyNodes, footNodes) {
  const d = drawer();
  const closeBtn = el('button', { class: 'btn btn-sm btn-ghost btn-icon', type: 'button', title: 'Close', attrs: { 'aria-label': 'Close' }, on: { click: () => d.close() } }, icon('close'));
  replace(
    d,
    el(
      'div',
      { class: 'drawer-inner' },
      el('div', { class: 'drawer-head' }, el('div', null, el('h2', { id: 'drawer-title' }, title), sub ? el('div', { class: 'muted' }, sub) : null), closeBtn),
      el('div', { class: 'drawer-body' }, bodyNodes),
      el('div', { class: 'drawer-foot' }, footNodes),
    ),
  );
  d.showModal();
}

function openPromoteDrawer(host, r) {
  const form = { approver: '', rationale: '', ticket_ref: '' };
  const errNode = el('div');
  const submit = el('button', { class: 'btn btn-ok', type: 'button' }, 'Promote to accepted baseline');
  submit.addEventListener('click', async () => {
    submit.disabled = true;
    replace(errNode);
    try {
      const res = await api('/api/admin/baselines/promote', {
        method: 'POST',
        body: { host_id: host, watch_id: r.watch_id, observation_id: r.promotable_observation_id, approver: form.approver, rationale: form.rationale, ticket_ref: form.ticket_ref || null },
      });
      drawer().close();
      toast(`Baseline revision ${res.revision_id} accepted for ${res.watch_id}`, 'ok');
      await refreshAll();
    } catch (err) {
      replace(errNode, errorBox(err));
      submit.disabled = false;
    }
  });
  openDrawer(
    'Promote baseline',
    'Creates a new immutable, attributable revision. The old revision is kept.',
    [
      el('dl', { class: 'kv' }, el('dt', null, 'host'), el('dd', { class: 'mono' }, host), el('dt', null, 'watch'), el('dd', { class: 'mono' }, r.watch_id), el('dt', null, 'observation'), el('dd', { class: 'mono' }, `#${r.promotable_observation_id}`)),
      el(
        'div',
        { class: 'diff' },
        el('div', { class: 'col' }, el('span', { class: 'eyebrow' }, `Accepted${r.accepted_baseline ? ` · rev ${r.accepted_baseline.revision_id}` : ''}`), hashChip(r.accepted_baseline?.state_hash)),
        el('span', { class: 'rel-arrow' }, '→'),
        el('div', { class: 'col' }, el('span', { class: 'eyebrow' }, 'New accepted state'), hashChip(r.current_observed?.state_hash)),
      ),
      field('Approver', textInput(form, 'approver', { placeholder: 'your operator identity' })),
      field('Rationale', textArea(form, 'rationale', { placeholder: 'Why this observed state is known-good…', rows: 3 })),
      field('Change ticket (optional)', textInput(form, 'ticket_ref', { placeholder: 'CHG-4471', mono: true })),
      errNode,
    ],
    [el('button', { class: 'btn btn-ghost', type: 'button', on: { click: () => drawer().close() } }, 'Cancel'), submit],
  );
}

function openCloseDrawer(inc) {
  const form = { actor: '', resolution: '' };
  const errNode = el('div');
  const submit = el('button', { class: 'btn btn-danger', type: 'button' }, 'Close incident');
  submit.addEventListener('click', async () => {
    submit.disabled = true;
    replace(errNode);
    try {
      const res = await api(`/api/admin/incidents/${encodeURIComponent(inc.incident_id)}/close`, { method: 'POST', body: form });
      drawer().close();
      toast(`${res.incident_id} closed · ${res.retired_ephemeral_watches} ephemeral watch${res.retired_ephemeral_watches === 1 ? '' : 'es'} retired`, 'ok');
      await refreshAll();
    } catch (err) {
      replace(errNode, errorBox(err));
      submit.disabled = false;
    }
  });
  openDrawer(
    'Close incident',
    'Closing ends active runs and retires the incident\'s ephemeral watches.',
    [
      el('dl', { class: 'kv' }, el('dt', null, 'incident'), el('dd', { class: 'mono' }, inc.incident_id), el('dt', null, 'host'), el('dd', { class: 'mono' }, inc.host_id)),
      el('p', { class: 'dim' }, inc.summary),
      field('Actor', textInput(form, 'actor', { placeholder: 'your operator identity' })),
      field('Resolution', textArea(form, 'resolution', { placeholder: 'Outcome, verification performed, follow-ups…', rows: 4 })),
      errNode,
    ],
    [el('button', { class: 'btn btn-ghost', type: 'button', on: { click: () => drawer().close() } }, 'Cancel'), submit],
  );
}

function openEnrollDrawer() {
  const form = { host_id: '', agent_public_key_hex: '' };
  const errNode = el('div');
  const submit = el('button', { class: 'btn btn-primary', type: 'button' }, 'Enroll host');
  submit.addEventListener('click', async () => {
    submit.disabled = true;
    replace(errNode);
    try {
      const res = await api('/api/admin/hosts/enroll', { method: 'POST', body: { host_id: form.host_id, agent_public_key_hex: form.agent_public_key_hex || null } });
      replace(
        errNode,
        el(
          'div',
          { class: 'decision ok' },
          el('span', { class: 'verdict' }, 'Host enrolled'),
          el('dl', { class: 'kv' }, el('dt', null, 'host'), el('dd', { class: 'mono' }, res.host_id), el('dt', null, 'control key id'), el('dd', { class: 'mono' }, res.control_signing_key_id), el('dt', null, 'control public key'), el('dd', null, hashChip(res.control_public_key_hex, { full: true }))),
        ),
      );
      submit.disabled = false;
      loadCore().then(() => render());
    } catch (err) {
      replace(errNode, errorBox(err));
      submit.disabled = false;
    }
  });
  openDrawer(
    'Enroll host',
    'Registers an edge agent identity with control-d. Bundles are signed with the control key returned here.',
    [field('Host ID', textInput(form, 'host_id', { placeholder: 'edge-vm-21', mono: true })), field('Agent Ed25519 public key (hex, optional)', textInput(form, 'agent_public_key_hex', { placeholder: '64 hex characters', mono: true })), errNode],
    [el('button', { class: 'btn btn-ghost', type: 'button', on: { click: () => drawer().close() } }, 'Close'), submit],
  );
}

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------

function tick() {
  const now = Date.now();
  for (const node of document.querySelectorAll('[data-ts]')) {
    const ts = node.dataset.ts;
    if (ts) node.textContent = node.dataset.until ? untilText(ts, now) : rel(ts, now);
  }
  for (const m of document.querySelectorAll('.meter[data-hb]')) {
    const ts = m.dataset.hb;
    const age = ts ? (now - Date.parse(ts)) / 1000 : Infinity;
    m.firstChild.style.setProperty('width', `${Math.max(0.04, 1 - age / 120) * 100}%`);
    m.classList.toggle('warn', age >= 45 && age < 600);
    m.classList.toggle('bad', age >= 600);
  }
}

async function poll() {
  if (document.hidden) return;
  await Promise.all([loadStatus(), loadCore()]);
  renderShell();
  if (parseRoute().view === 'fleet') render();
}

function boot() {
  hydrateIcons();
  document.getElementById('refresh-btn').addEventListener('click', () => refreshAll().then(() => toast('Refreshed')));
  window.addEventListener('hashchange', () => {
    render();
    document.getElementById('main').focus({ preventScroll: true });
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'r' && !e.metaKey && !e.ctrlKey && !e.altKey && !/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName ?? '') && !drawer().open) {
      refreshAll();
    }
  });
  drawer().addEventListener('click', (e) => {
    if (e.target === drawer()) drawer().close();
  });
  refreshAll();
  setInterval(tick, 1000);
  setInterval(poll, 15_000);
}

boot();
