// Defensive Security Autonomous Mitigation Harness: operator console (browser).
// All untrusted strings are rendered through dom.js (Text nodes only).

import { el, append, clear, replace, icon, hydrateIcons } from './dom.js';

// ---------------------------------------------------------------------------
// State & API
// ---------------------------------------------------------------------------

const state = {
  status: null,
  hosts: [],
  incidents: [],
  automation: null,
  capabilities: new Map(),
  evidence: new Map(), // incident_id -> Set<observation_id>
  drafts: new Map(), // incident_id -> { proposal, finding, action }
  decisions: new Map(), // incident_id -> [{decision, watch_id, spec, at}]
  actionResults: new Map(), // incident_id -> [{decision, intent_id, ...}]
  wsTab: new Map(), // incident_id -> side-panel tab
  expanded: new Set(),
  tableFilters: new Map(), // observation_id -> socket filter text
  inv: { q: '', host: '' },
  baselines: { host: null, watch: '', limit: 50 },
  audit: { tab: 'decisions', ruleFilter: null, verdict: 'all', newestFirst: true },
  auth: null, // { auth_mode, authenticated, user }
  actions: { list: [], denied: null, source: null, admin_sock: null, error: null, loaded: false },
  mit: { filter: 'all', host: '', incident: null },
  approval: { approver: '', keyFile: null, keyId: null, note: '', envelope: '' },
  changeIndex: new Map(), // `${incident_id}:${observation_id}` -> { addedKeys, removed } from "What changed"
  reasoner: { loaded: false, available: false, reason: null, message: null, runs: [], triggers: [] },
  runEvents: new Map(), // run_id -> { events, after, loaded } (fetched incrementally with after_seq)
  runOpen: new Set(), // run timelines the operator expanded
  runClosed: new Set(), // active run timelines the operator collapsed
  rq: { status: 'open', host: '', incident: '' }, // trigger queue / runs filters
  rules: { loaded: false, available: false, message: null, source: null, list: [] }, // active + proposed expectation rules (fleet glance, nav)
  rv: { tab: 'active', host: '' }, // rules view filters
  hostTab: 'profile', // host deep-dive tab
  lastRefresh: null,
};

const FLOOR = { min_interval: 15, max_timeout: 30, max_ttl_min: 240, max_runs: 1000 };
const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
const VALID_OBS = new Set(['ok', 'partial']);
const ALL_COLLECTORS = ['sockets.listening', 'systemd.unit_state', 'files.metadata', 'journal.unit_events', 'connections.outbound', 'packages.inventory'];

// ----- per-viewer conveniences (browser storage may be unavailable) -----

function stored(key, fallback = null) {
  try {
    return localStorage.getItem(key) ?? fallback;
  } catch {
    return fallback;
  }
}

function store(key, value) {
  try {
    localStorage.setItem(key, value);
  } catch {
    /* private window or blocked storage: keep the in-memory value only */
  }
}

/** The name an operator signs mutations with; remembered so it is typed once. */
function operatorName() {
  return state.auth?.user?.username || stored('defsec.operator') || 'operator';
}

function rememberOperator(name) {
  const v = String(name ?? '').trim();
  if (v) store('defsec.operator', v);
}

function applyTheme(theme) {
  const t = theme === 'dark' ? 'dark' : 'light';
  document.documentElement.dataset.theme = t;
  for (const b of document.querySelectorAll('[data-theme-choice]')) b.setAttribute('aria-pressed', String(b.dataset.themeChoice === t));
}
applyTheme(stored('defsec.theme', 'dark'));
state.approval.keyFile = stored('defsec.keyFile', '~/.config/defsec/operator.key');
state.approval.keyId = stored('defsec.keyId', 'operator-01');
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
  if (!res.ok) {
    const err = new HttpError(res.status, data?.error?.code ?? 'http_error', data?.error?.message ?? res.statusText);
    if (res.status === 401 && !path.startsWith('/api/auth/')) sessionLost(err);
    throw err;
  }
  return data;
}

const roleAdmin = () => !state.auth || state.auth.auth_mode === 'none' || state.auth.user?.role === 'admin';
/** Admin interface on AND the signed-in user may use it. */
const adminEnabled = () => Boolean(state.status?.admin_enabled) && roleAdmin();
const canMutate = () => roleAdmin();
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

/** UUIDs read as 8 characters (#5bc7e050); readable IDs such as inc-2026-0042 stay whole. */
const isUuid = (id) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(String(id ?? ''));
const shortId = (id) => (isUuid(id) ? `#${String(id).slice(0, 8)}` : String(id ?? '—'));

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
  if (!hash) return el('span', { class: 'hash is-null' }, 'none');
  const sw = el('span', { class: 'sw' });
  sw.style.setProperty('background', `hsl(${hashHue(hash)} 38% 52%)`);
  const node = el('button', { class: 'hash', type: 'button', title: `SHA-256 ${hash}\nClick to copy`, attrs: { 'aria-label': `Copy hash ${hash}` } }, sw, el('span', { class: 'hash-text' }, label ?? (full ? hash : shortHash(hash))));
  node.addEventListener('click', (e) => {
    e.stopPropagation();
    e.preventDefault();
    copy(hash, node);
  });
  return node;
}

/** Short identifier that copies the full value on click. */
function idChip(id, { title = null } = {}) {
  const node = el('button', { class: 'id-chip', type: 'button', title: `${title ?? 'ID'} ${id}\nClick to copy`, attrs: { 'aria-label': `Copy ${title ?? 'ID'} ${id}` } }, shortId(id), isUuid(id) ? icon('copy') : null);
  node.addEventListener('click', (e) => {
    e.stopPropagation();
    e.preventDefault();
    copy(String(id), node);
  });
  return node;
}

const SEV_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low', info: 'Info' };
const sevBadge = (s) => el('span', { class: ['badge', `sev-${s}`] }, SEV_LABEL[s] ?? s);
const cap = (s) => (s ? s.charAt(0).toUpperCase() + s.slice(1) : s);

function livenessBadge(status) {
  const map = { online: 'ok', healthy: 'ok', connected: 'ok', stale: 'warn', degraded: 'warn', pending: 'warn', offline: 'bad', lost: 'bad' };
  const cls = map[status] ?? '';
  return el('span', { class: ['badge', cls] }, el('span', { class: ['dot', cls] }), cap(status || 'unknown'));
}

function obsStatusBadge(status) {
  const cls = status === 'ok' ? 'ok' : status === 'partial' ? 'warn' : 'bad';
  return el('span', { class: ['badge', cls] }, status === 'ok' ? 'OK' : cap(status.replace(/_/g, ' ')));
}

function classBadge(cls) {
  return cls === 'baseline'
    ? el('span', { class: 'badge solid', title: 'Immutable operator-approved baseline watch' }, icon('lock'), 'Baseline')
    : el('span', { class: 'badge ghost', title: 'Bounded, incident-scoped ephemeral watch' }, icon('clock'), 'Ephemeral');
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

function card(title, sub, body, actions = null, extraClass = null) {
  return el(
    'section',
    { class: ['card', extraClass] },
    el('div', { class: 'card-head' }, el('div', null, el('h2', null, title), sub ? el('div', { class: 'sub' }, sub) : null), actions ? el('div', { class: 'card-head-actions' }, actions) : null),
    body,
  );
}

function notice(kind, iconName, text, action = null) {
  return el('div', { class: ['notice', kind], attrs: kind === 'bad' ? { role: 'alert' } : null }, icon(iconName), el('div', { class: 'notice-text' }, text), action);
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

function sockState(info, enabled = true) {
  if (!enabled) return ['', 'off'];
  if (info.simulated) return ['accent', 'simulated'];
  if (info.reachable && info.authorized !== false) return ['ok', `${info.latency_ms ?? 0} ms`];
  if (info.reachable) return ['warn', 'unauthorized'];
  return ['bad', 'unreachable'];
}

function renderShell() {
  const s = state.status;
  const inv = s?.sockets?.investigate ?? {};
  const adm = s?.sockets?.admin ?? {};
  const row = (label, [cls, txt]) => el('div', { class: 'status-row' }, el('span', null, el('span', { class: ['dot', cls] }), label), el('span', { class: 'mono' }, txt));
  const mode = s?.mode === 'live' ? 'Live' : s?.mode === 'demo' ? 'Demo' : 'Unknown';
  replace(
    document.getElementById('rail-status'),
    el('div', { class: 'status-row' }, el('span', null, el('span', { class: ['dot', s?.mode === 'live' ? 'ok' : s?.mode === 'demo' ? 'accent' : 'bad'] }), `${mode} mode`), el('span', { class: 'mono' }, s?.admin_enabled ? 'admin on' : 'admin off')),
    row('investigate.sock', sockState(inv)),
    row('admin.sock', sockState(adm, Boolean(s?.admin_enabled))),
  );

  const route = parseRoute();
  const [invCls, invTxt] = sockState(inv);
  replace(
    document.getElementById('topbar-ctx'),
    el('span', { class: 'ctx-title' }, VIEWS[route.view].title),
    el('span', { class: 'ctx-item' }, el('span', { class: ['dot', invCls] }), s?.mode === 'demo' ? 'Demo data · no daemons' : `control-d · ${invTxt}`),
    state.lastRefresh ? el('span', { class: 'ctx-sep' }, '·') : null,
    state.lastRefresh ? el('span', { class: 'ctx-item' }, 'Updated ', relTime(new Date(state.lastRefresh).toISOString())) : null,
  );

  const pill = document.getElementById('chain-pill');
  const a = s?.audit;
  if (!a) {
    replace(pill, el('a', { class: 'chain-pill', href: '#/audit', title: 'Audit chain requires the admin interface' }, icon('lock'), 'Audit chain not visible'));
  } else if (a.valid) {
    replace(pill, el('a', { class: 'chain-pill', href: '#/audit', title: `Chain head ${a.latest_hash}` }, el('span', { class: 'dot ok' }), 'Chain verified', el('span', { class: 'mono' }, `${a.entries_checked} · ${String(a.latest_hash ?? '').slice(0, 8)}`)));
  } else {
    replace(pill, el('a', { class: 'chain-pill bad', href: '#/audit', title: a.error ?? '' }, el('span', { class: 'dot bad' }), 'Audit chain broken'));
  }

  const open = state.incidents.filter((i) => i.status === 'open').length;
  document.getElementById('nav-incidents').textContent = open ? String(open) : '';
  const pending = awaitingApproval().length;
  document.getElementById('nav-mitigations').textContent = pending ? String(pending) : '';
  refreshNavReasoner();
  const pendingRules = state.rules.list.filter((r) => r.status === 'proposed').length;
  document.getElementById('nav-rules').textContent = pendingRules ? String(pendingRules) : '';
  renderUserSlot();
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

const VIEWS = {
  fleet: { title: 'Fleet & posture', sub: 'Edge agent liveness, automation and audit integrity', render: renderFleet },
  investigations: { title: 'Investigations', sub: 'Observed facts, model hypotheses and verified findings', render: renderInvestigations },
  reasoner: { title: 'Reasoner activity', sub: 'Automated reasoner-d runs, operator sessions and the trigger queue', render: renderReasoner },
  mitigations: { title: 'Mitigations', sub: 'Typed, TTL-bounded containment: autonomous within policy, dual-signed beyond it', render: renderMitigations },
  rules: { title: 'Expectation rules', sub: 'Typed, auditable allowances for expected changes in socket sets, approved by an operator', render: renderRules },
  baselines: { title: 'Baselines & telemetry', sub: 'Accepted baseline against last and current observed state', render: renderBaselines },
  audit: { title: 'Policy & audit', sub: 'Deterministic policy decisions and the tamper-evident audit chain', render: renderAudit },
};

function parseRoute() {
  const raw = location.hash || '#/fleet';
  const [pathPart, queryPart = ''] = raw.split('?');
  const [, view = 'fleet', arg = null] = pathPart.split('/');
  return { view: VIEWS[view] ? view : 'fleet', arg: arg ? decodeURIComponent(arg) : null, query: new URLSearchParams(queryPart) };
}

function setPageActions(...nodes) {
  replace(document.getElementById('page-actions'), nodes);
}

let renderToken = 0;
let lastView = null;
async function render() {
  const route = parseRoute();
  const v = VIEWS[route.view];
  document.getElementById('view-title').textContent = v.title;
  document.getElementById('view-sub').textContent = v.sub;
  for (const a of document.querySelectorAll('#nav a')) {
    if (a.dataset.view === route.view) a.setAttribute('aria-current', 'page');
    else a.removeAttribute('aria-current');
  }
  const ctxTitle = document.querySelector('#topbar-ctx .ctx-title');
  if (ctxTitle) ctxTitle.textContent = v.title;
  const token = ++renderToken;
  const view = document.getElementById('view');
  if (route.view !== lastView) {
    lastView = route.view;
    setPageActions();
  }
  try {
    const node = await v.render(route.arg, () => token !== renderToken, route);
    if (token !== renderToken || !node) return;
    replace(view, node);
  } catch (err) {
    if (token !== renderToken) return;
    setPageActions();
    replace(view, errorBox(err));
  }
}

async function refreshAll() {
  await Promise.all([loadStatus(), loadCore()]);
  state.lastRefresh = Date.now();
  renderShell();
  await render();
}

async function loadCore() {
  const [h, i] = await Promise.allSettled([api('/api/hosts'), api('/api/incidents'), loadActions(), loadAutomation(), loadReasoner(), loadRules()]);
  if (h.status === 'fulfilled') state.hosts = h.value.hosts;
  if (i.status === 'fulfilled') state.incidents = i.value.incidents;
}

async function loadAutomation() {
  try {
    state.automation = await api('/api/automation');
  } catch (err) {
    state.automation = { available: false, reason: err.code, error: err };
  }
}

async function loadActions() {
  try {
    const r = await api('/api/actions');
    state.actions = { list: r.actions, denied: r.denied, source: r.source, admin_sock: r.admin_sock ?? null, error: null, loaded: true };
  } catch (err) {
    state.actions = { ...state.actions, list: [], denied: null, error: err, loaded: true };
  }
}

// ---------------------------------------------------------------------------
// View: Fleet & Posture
// ---------------------------------------------------------------------------

function integrityNotice(audit) {
  if (!audit) {
    return notice('', 'lock', [el('strong', null, 'Audit chain not visible.'), el('span', null, 'VerifyAuditChain runs on the separate admin interface; start the console with --enable-admin --admin-sock to check integrity here.')]);
  }
  if (audit.valid) {
    return notice(
      '',
      'shield',
      [el('strong', null, 'Audit chain intact'), el('span', null, `${audit.entries_checked} entries verified from genesis`), el('span', { class: 'row' }, 'head', hashChip(audit.latest_hash))],
      el('a', { class: 'btn btn-sm', href: '#/audit' }, 'Inspect'),
    );
  }
  return notice('bad', 'alert', [el('strong', null, 'Audit chain verification failed.'), el('span', { class: 'mono' }, audit.error ?? 'unknown error')], el('a', { class: 'btn btn-sm btn-danger', href: '#/audit' }, 'Investigate'));
}

function kpi(label, value, foot) {
  return el('div', { class: 'kpi' }, el('div', { class: 'label' }, label), el('div', { class: 'value' }, value), foot ? el('div', { class: 'foot' }, foot) : null);
}

const sum = (list, f) => list.reduce((n, x) => n + (f(x) ?? 0), 0);
const hostWatchCount = (h) => h.watch_count ?? h.health?.active_watches ?? null;

function sevSummary(incidents) {
  return SEV_ORDER.map((s) => [s, incidents.filter((i) => i.priority === s).length])
    .filter(([, n]) => n)
    .map(([s, n]) => `${n} ${s}`)
    .join(' · ');
}

async function renderFleet(_arg, _stale, route) {
  const hosts = state.hosts;
  const wanted = route?.query?.get('host');
  if (wanted && !drawer().open && hosts.some((h) => h.host_id === wanted)) queueMicrotask(() => openHostDrawer(wanted, route.query.get('tab') || undefined));
  const open = state.incidents.filter((i) => i.status === 'open');
  const online = hosts.filter((h) => h.liveness_status === 'online').length;
  const degraded = hosts.filter((h) => h.liveness_status !== 'online');
  const counts = hosts.map(hostWatchCount);
  const knownCounts = counts.filter((c) => c != null);

  setPageActions(adminEnabled() ? el('button', { class: 'btn', type: 'button', on: { click: openEnrollDrawer } }, icon('plus'), 'Enroll host') : null);

  const kpis = el(
    'div',
    { class: 'kpis' },
    kpi('Agents online', [String(online), el('small', null, ` / ${hosts.length}`)], degraded.length ? degraded.map((h) => el('span', { class: 'mono' }, `${h.host_id} ${h.liveness_status}`)) : hosts.length ? 'All agents heart-beating' : 'No hosts enrolled'),
    kpi('Open incidents', String(open.length), open.length ? sevSummary(open) : 'Quiet'),
    mitigationKpi(),
    kpi('Active watches', knownCounts.length ? String(sum(knownCounts, (x) => x)) : el('span', { class: 'muted' }, '—'), knownCounts.length ? `${hosts.length} host${hosts.length === 1 ? '' : 's'} · ${sum(hosts, (h) => h.stream_watch_count)} stream` : 'Watch counts unavailable'),
  );

  const grid = hosts.length
    ? el('div', { class: 'host-grid' }, hosts.map((h) => hostCard(h, open.filter((i) => i.host_id === h.host_id))))
    : el('div', { class: 'empty-slot' }, 'No hosts in scope. The capability token may not include any hosts, or none are enrolled yet.');

  return el(
    'div',
    null,
    integrityNotice(state.status?.audit),
    approvalNotice(),
    kpis,
    automationCard(),
    el('div', { class: 'section-title' }, el('h2', null, 'Edge fleet'), el('div', { class: 'row' }, rulesGlance(), el('span', { class: 'muted' }, `${hosts.length} enrolled`))),
    grid,
  );
}

/** Honest status of the automated side: deterministic monitoring always, reasoner-d only if seen. */
function automationCard() {
  const a = state.automation;
  const hosts = state.hosts;
  const watches = sum(hosts, hostWatchCount);
  const cell = (k, dotCls, v, s) => el('div', { class: 'auto-cell' }, el('div', { class: 'k' }, el('span', { class: ['dot', dotCls] }), k), el('div', { class: 'v' }, v), el('div', { class: 's' }, s));
  const incLink = (id) => el('a', { class: 'mono', href: `#/investigations/${encodeURIComponent(id)}` }, shortId(id));
  const monitoring = cell(
    'Deterministic monitoring',
    hosts.some((h) => h.liveness_status === 'online') ? 'ok' : 'warn',
    hosts.some((h) => h.liveness_status === 'online') ? 'Active' : 'No agent online',
    `${watches} watch${watches === 1 ? '' : 'es'} on ${hosts.length} host${hosts.length === 1 ? '' : 's'}. control-d evaluates triggers and opens incidents without any model.`,
  );
  const health = reasonerHealth();
  let reasoner;
  let queue = null;
  if (health.state !== 'unavailable' && health.state !== 'loading') {
    // Live view from control-d's run and trigger tables (Phase 9).
    const r = health.active[0];
    const last = health.lastRun;
    if (health.state === 'working') {
      reasoner = cell('reasoner-d worker', 'accent', r ? ['Investigating ', incLink(r.incident_id)] : 'Working', r ? [`${plain(r.model_id)} · started `, relTime(r.started_at), health.active.length > 1 ? ` · ${health.active.length} active runs` : ''] : `${plural(health.leased.length, 'trigger')} leased`);
    } else if (health.state === 'stalled') {
      reasoner = cell('reasoner-d worker', 'warn', 'Not running?', [`${plural(health.pending.length, 'trigger')} waiting (oldest queued `, relTime(health.oldest), ') with no active run. Start reasoner-d, or work incidents with an operator session.']);
    } else {
      reasoner = cell(
        'reasoner-d worker',
        last ? 'ok' : '',
        health.state === 'queued' ? 'Queued' : last ? 'Idle' : 'No automated runs yet',
        last ? ['Last run ', relTime(last.started_at), ' on ', incLink(last.incident_id), ` · ${plain(last.model_id)}`] : 'No reasoner-d run has been recorded. Incidents wait for an operator until reasoner-d is started.',
      );
    }
    queue = cell(
      'Trigger queue',
      health.state === 'stalled' ? 'warn' : health.pending.length || health.leased.length ? 'accent' : '',
      el('a', { class: 'text-link', href: '#/reasoner' }, `${health.pending.length} pending · ${health.leased.length} leased`),
      health.dead.length ? el('span', { class: 'warn-text' }, `${plural(health.dead.length, 'trigger')} dead-lettered after retries`) : 'Watch triggers waiting for or held by reasoner-d.',
    );
  } else if (!a?.available) {
    reasoner = cell('reasoner-d worker', '', 'Not visible', health.message ? `${health.message}. Worker runs are otherwise read from the audit log, which needs --enable-admin.` : 'Worker runs are read from the audit log over the admin interface. Start the console with --enable-admin to see them.');
  } else if (!a.reasoner_runs) {
    reasoner = cell('reasoner-d worker', '', 'No automated runs seen yet', `Deterministic monitoring is active, but no reasoner-d run appears in the last ${a.window_entries} audit entries. Incidents wait for an operator until reasoner-d is started.`);
  } else {
    const last = a.last_run;
    reasoner = cell('reasoner-d worker', 'ok', ['Last run ', relTime(last.at)], [`${a.reasoner_runs} run${a.reasoner_runs === 1 ? '' : 's'} in window · `, el('span', { class: 'mono' }, last.model_id ?? 'model'), ` via ${last.backend_id ?? 'backend'}`, last.incident_id ? [' on ', incLink(last.incident_id)] : null]);
  }
  let proposals;
  if (!a?.available) proposals = cell('Model-proposed actions', '', '—', 'Counted from the audit log, which needs the admin interface.');
  else if (!a.action_proposals) proposals = cell('Model-proposed actions', '', '0', a.reasoner_runs ? 'reasoner-d proposes mitigations only when action proposals are enabled in its run budgets (off by default).' : 'Operators can propose mitigations from an operator session on any open incident.');
  else proposals = cell('Model-proposed actions', 'accent', `${a.action_proposals} proposed`, `${a.watch_proposals} watch proposals and ${a.findings} findings from reasoner-d in the audit window.`);
  return card(
    'Automation',
    null,
    el('div', { class: ['auto-grid', queue && 'has-queue'] }, monitoring, reasoner, queue, proposals),
    el('a', { class: 'btn btn-sm btn-ghost', href: '#/reasoner' }, 'Reasoner activity', icon('arrow')),
  );
}

function hostCard(h, incidents) {
  const ageS = h.last_heartbeat_at ? (Date.now() - Date.parse(h.last_heartbeat_at)) / 1000 : Infinity;
  const freshCls = ageS < 45 ? '' : ageS < 600 ? 'warn' : 'bad';
  const health = h.health;
  const spoolFrac = health ? health.spool_bytes_used / Math.max(1, health.spool_bytes_cap) : 0;
  const watches = hostWatchCount(h);
  const freshMeter = meter(Math.max(0.04, 1 - ageS / 120), freshCls);
  freshMeter.dataset.hb = h.last_heartbeat_at ?? '';
  const stat = (k, v) => el('div', { class: 'stat' }, el('div', { class: 'k' }, k), el('div', { class: 'v' }, v));

  return el(
    'article',
    { class: ['card', 'host-card'] },
    el(
      'div',
      { class: 'host-top' },
      el(
        'div',
        { class: 'host-name' },
        el('button', { class: 'host-id host-open', type: 'button', title: `Open the ${h.host_id} deep-dive: profile, discovery, monitoring and reviews`, on: { click: () => openHostDrawer(h.host_id) } }, h.host_id),
        h.placement ? el('div', { class: 'host-place' }, h.placement) : null,
      ),
      livenessBadge(h.liveness_status),
    ),
    hostTags(h),
    el(
      'div',
      { class: 'host-stats' },
      stat('Agent', h.agent_version),
      stat('Bundle', `v${h.active_bundle_version}`),
      stat('Watches', watches == null ? el('span', { class: 'muted' }, '—') : [String(watches), h.stream_watch_count ? el('span', { class: 'unit' }, ` · ${h.stream_watch_count} stream`) : null]),
    ),
    el('div', { class: 'fresh' }, el('div', { class: 'fresh-row' }, el('span', null, 'Heartbeat'), relTime(h.last_heartbeat_at)), freshMeter),
    health
      ? el(
          'div',
          { class: 'fresh' },
          el('div', { class: 'fresh-row' }, el('span', null, `Spool · RSS ${bytes(health.rss_bytes)}`), el('span', { class: 'num' }, `${bytes(health.spool_bytes_used)} / ${bytes(health.spool_bytes_cap)}`)),
          meter(spoolFrac, spoolFrac > 0.8 ? 'bad' : spoolFrac > 0.5 ? 'warn' : ''),
          health.dropped_events_total ? el('div', { class: 'fresh-row' }, el('span', { class: 'warn-text' }, `${health.dropped_events_total} dropped events`)) : null,
        )
      : null,
    el(
      'div',
      { class: 'host-foot' },
      incidents.length
        ? el(
            'a',
            { class: 'inc-summary', href: `#/investigations?host=${encodeURIComponent(h.host_id)}`, title: `Show the ${incidents.length} open incident${incidents.length === 1 ? '' : 's'} on ${h.host_id}` },
            el('span', { class: ['dot', incidents.some((i) => i.priority === 'high' || i.priority === 'critical') ? 'bad' : 'warn'] }),
            el('span', { class: 'num' }, `${incidents.length} open`),
            el('span', { class: 'sevs' }, sevSummary(incidents)),
          )
        : el('span', { class: 'muted' }, 'No open incidents'),
      el('span', { class: 'spacer' }),
      el('button', { class: 'btn btn-sm btn-ghost', type: 'button', on: { click: () => openHostDrawer(h.host_id) } }, 'Host details'),
      el('a', { class: 'btn btn-sm btn-ghost', href: `#/baselines/${encodeURIComponent(h.host_id)}` }, 'Telemetry', icon('arrow')),
    ),
  );
}

// ---------------------------------------------------------------------------
// View: Investigations
// ---------------------------------------------------------------------------

function sortIncidents(list) {
  return [...list].sort((a, b) => {
    if (a.status !== b.status) return a.status === 'open' ? -1 : 1;
    const s = SEV_ORDER.indexOf(a.priority) - SEV_ORDER.indexOf(b.priority);
    return s || Date.parse(b.updated_at) - Date.parse(a.updated_at);
  });
}

function incidentMatches(i) {
  const f = state.inv;
  if (f.host && i.host_id !== f.host) return false;
  const q = f.q.trim().toLowerCase();
  return !q || [i.incident_id, i.summary, i.host_id, i.priority].some((v) => String(v).toLowerCase().includes(q));
}

function incidentItem(i, current) {
  return el(
    'a',
    { class: ['inc-item', i.status !== 'open' && 'closed'], href: `#/investigations/${encodeURIComponent(i.incident_id)}`, title: i.incident_id, attrs: { 'aria-current': i.incident_id === current ? 'true' : null } },
    el('div', { class: 'top' }, sevBadge(i.priority), el('span', { class: 'id' }, shortId(i.incident_id)), el('span', { class: 'spacer' }), i.status !== 'open' ? el('span', { class: 'badge ghost' }, cap(i.status)) : null),
    i.status === 'open' ? el('div', { class: 'inc-marker', dataset: { reasonerSlot: i.incident_id } }, incidentReasonerBadge(i.incident_id)) : null,
    el('div', { class: 'summary' }, i.summary),
    el('div', { class: 'meta' }, el('span', { class: 'mono' }, i.host_id), el('span', null, 'updated ', relTime(i.updated_at))),
  );
}

async function renderInvestigations(arg, _stale, route) {
  const hostQ = route?.query?.get('host');
  if (hostQ !== null && hostQ !== undefined) state.inv.host = hostQ;
  const all = sortIncidents(state.incidents);
  const visible = () => all.filter(incidentMatches);
  const phone = window.matchMedia('(max-width: 760px)').matches;
  if (!arg && visible().length && !phone) {
    arg = visible()[0].incident_id;
    history.replaceState(null, '', `#/investigations/${encodeURIComponent(arg)}`);
  }

  const scroll = el('div', { class: 'inc-scroll' });
  const drawList = () => {
    const shown = visible();
    replace(
      scroll,
      ['open', 'closed'].map((status) => {
        const group = shown.filter((i) => (status === 'open' ? i.status === 'open' : i.status !== 'open'));
        if (!group.length) return null;
        return [el('div', { class: 'inc-group' }, `${status === 'open' ? 'Open' : 'Closed'} · ${group.length}`), group.map((i) => incidentItem(i, arg))];
      }),
      shown.length ? null : emptyState(all.length ? 'No matching incidents' : 'No incidents', all.length ? 'Clear the filter to see every incident.' : 'No active incidents in this capability scope.'),
    );
  };
  const search = el('input', { type: 'search', placeholder: 'Filter incidents', value: state.inv.q, attrs: { 'aria-label': 'Filter incidents by summary, ID or host' } });
  search.addEventListener('input', () => {
    state.inv.q = search.value;
    drawList();
  });
  const hosts = [...new Set(all.map((i) => i.host_id))].sort();
  const hostSel = el('select', { attrs: { 'aria-label': 'Filter incidents by host' } }, el('option', { value: '' }, 'All hosts'), hosts.map((h) => el('option', { value: h, selected: state.inv.host === h }, h)));
  hostSel.addEventListener('change', () => {
    state.inv.host = hostSel.value;
    drawList();
  });
  drawList();
  const list = el(
    'nav',
    { class: 'card inc-list', attrs: { 'aria-label': 'Incidents' } },
    el('div', { class: 'inc-tools' }, el('label', { class: 'search' }, icon('search'), search), hosts.length > 1 || state.inv.host ? hostSel : null),
    scroll,
  );

  const workspace = el('div', { class: 'workspace' }, arg ? el('div', { class: 'card' }, loading(6)) : el('div', { class: 'empty-slot' }, 'Select an incident to open its workspace.'));
  if (arg) loadWorkspace(arg, workspace);
  return el('div', { class: ['split', arg && 'has-selection'] }, list, workspace);
}

async function loadWorkspace(incidentId, container) {
  try {
    const [ctx, changes, triggers, followups] = await Promise.all([
      api(`/api/incidents/${encodeURIComponent(incidentId)}`),
      api(`/api/incidents/${encodeURIComponent(incidentId)}/changes`).catch((error) => ({ error })),
      api(`/api/triggers?incident_id=${encodeURIComponent(incidentId)}&limit=50`).catch(() => null),
      api(`/api/incidents/${encodeURIComponent(incidentId)}/followups`).catch(() => null),
    ]);
    ctx.changes = changes;
    ctx.followups = followups;
    ctx.triggers = triggers?.available ? triggers.triggers : [];
    let caps = state.capabilities.get(ctx.incident.host_id);
    if (!caps) {
      try {
        caps = (await api(`/api/hosts/${encodeURIComponent(ctx.incident.host_id)}/capabilities`)).capabilities;
        state.capabilities.set(ctx.incident.host_id, caps);
      } catch {
        caps = [];
      }
    }
    const r = parseRoute();
    if (r.view !== 'investigations' || r.arg !== incidentId) return;
    const known = state.incidents.find((i) => i.incident_id === incidentId);
    if (known) Object.assign(known, ctx.incident);
    replace(container, workspaceView(ctx, caps));
  } catch (err) {
    if (parseRoute().arg === incidentId) replace(container, errorBox(err));
  }
}

function reloadWorkspace(incidentId) {
  const container = document.querySelector('.workspace');
  if (container && parseRoute().view === 'investigations') loadWorkspace(incidentId, container);
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
      action: null,
    });
  }
  return state.drafts.get(id);
}

function evidenceFor(id) {
  if (!state.evidence.has(id)) state.evidence.set(id, new Set());
  return state.evidence.get(id);
}

const WS_TABS = [
  ['watches', 'Watches', 'Watches in scope'],
  ['propose', 'Propose watch', 'Propose an ephemeral watch'],
  ['finding', 'Finding', 'Record a hypothesis or verified finding'],
  ['action', 'Mitigation', 'Propose mitigation'],
];

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
  const evidenceListeners = new Set();
  const onEvidence = () => {
    for (const fn of evidenceListeners) fn();
  };
  // Built first: it indexes added/removed sockets that the fact tables below mark.
  const changesSlot = changesCard(inc, ctx.changes, { watchMap, triggers: ctx.triggers ?? [], ruleSuppression: ctx.rule_suppression });

  const incActions = state.actions.list.filter((a) => a.incident_id === inc.incident_id);
  const incPending = incActions.filter(isAwaiting).length;
  const mitChip = incActions.length
    ? el(
        'a',
        { class: 'chip', href: '#/mitigations', title: 'Mitigation intents for this incident', on: { click: () => { state.mit = { filter: 'all', host: '', incident: inc.incident_id }; } } },
        icon('bolt'),
        `${incActions.length} mitigation${incActions.length === 1 ? '' : 's'}`,
        incPending ? el('span', { class: 'badge warn' }, `${incPending} awaiting`) : null,
      )
    : null;

  const runControls = !isOpen
    ? el('span', { class: 'badge ghost' }, 'Closed · sessions ended')
    : !canMutate()
      ? el('span', { class: 'badge ghost', title: 'Observer accounts are read-only' }, icon('eye'), 'Read-only')
      : ctx.run
        ? el('span', { class: 'run-chip', title: `Your operator session ${ctx.run.run_id}: a manual session, separate from automated reasoner-d runs` }, el('span', { class: 'dot accent' }), 'Operator session ', el('span', { class: 'mono' }, String(ctx.run.run_id).slice(0, 8)), el('span', { class: 'muted' }, '·'), relTime(ctx.run.expires_at, { until: true }))
        : startSessionButton(inc.incident_id);

  const head = el(
    'header',
    { class: 'ws-head' },
    el(
      'div',
      { class: 'row' },
      sevBadge(inc.priority),
      el('span', { class: ['badge', isOpen ? '' : 'ghost'] }, cap(inc.status)),
      idChip(inc.incident_id, { title: 'Incident' }),
      el('span', { class: 'muted' }, 'on'),
      el('a', { class: 'mono', href: `#/baselines/${encodeURIComponent(inc.host_id)}` }, inc.host_id),
      el('span', { class: 'spacer' }),
      mitChip,
    ),
    el('h2', { class: 'ws-title' }, inc.summary),
    el(
      'div',
      { class: 'ws-meta' },
      el('span', null, 'Opened ', el('span', { class: 'num' }, fmtTime(inc.created_at))),
      el('span', null, 'Updated ', relTime(inc.updated_at)),
      el('span', { class: 'spacer' }),
      el('div', { class: 'ws-actions' }, runControls, isOpen && adminEnabled() ? el('button', { class: 'btn btn-sm btn-danger', type: 'button', on: { click: () => openCloseDrawer(inc) } }, 'Close incident') : null),
    ),
  );
  const backLink = el('a', { class: 'btn btn-sm btn-ghost back-link', href: '#/investigations?all=1' }, icon('chevron'), 'All incidents');

  const lane = (title, cls, items, emptyText) =>
    el(
      'div',
      null,
      el('div', { class: 'lane-head' }, title, el('span', { class: 'count' }, String(items.length))),
      items.length ? items.map((f) => findingCard(f, cls, obsMap)) : el('div', { class: 'empty-slot' }, emptyText),
    );

  const factList = el(
    'div',
    { class: 'fact-list' },
    obs.length ? obs.map((o) => factRow(o, watchMap, obs, selected, onEvidence, inc.incident_id)) : emptyState('No observations in window', 'No observations since the incident opened.'),
  );


  const main = el(
    'div',
    { class: 'ws-main' },
    reasonerCard(inc),
    followupsCard(ctx.followups, obsMap),
    changesSlot,
    el('div', { class: 'assess' }, lane('Model hypotheses', 'hyp', hyps, 'Unverified model or operator assertions appear here.'), lane('Verified findings', 'ver', vers, 'Evidence-bound conclusions appear here.')),
    card(
      'Observed facts',
      `${obs.length} immutable observation slice${obs.length === 1 ? '' : 's'} from control-d. Tick facts to cite them as evidence.`,
      el('div', { class: 'card-body flush' }, factList),
      el('div', { class: 'legend' }, el('span', null, el('i', { class: 'l-fact' }), 'Fact'), el('span', null, el('i', { class: 'l-hyp' }), 'Hypothesis'), el('span', null, el('i', { class: 'l-ver' }), 'Verified')),
    ),
  );

  // Side panel: underline tabs, panels built lazily and kept while the workspace lives.
  const tabState = state.wsTab.get(inc.incident_id) ?? 'watches';
  const panels = new Map();
  const panelSlot = el('div');
  const evidenceCtx = { selected, obs, obsMap, listeners: evidenceListeners };
  const buildPanel = (id) => {
    if (id === 'watches') return watchesPanel(ctx.active_watches, ctx.watch_runtime ?? {}, inc);
    if (!isOpen) return tabPanel('Incident closed. Its ephemeral watches were retired; operator sessions, proposals and findings are no longer accepted.', null);
    if (!canMutate()) return tabPanel('Observer accounts can review evidence, findings, reasoner runs and mitigations, but cannot start operator sessions, propose watches or actions, or record findings.', null);
    if (id === 'propose') return proposalComposer(inc, ctx.run, caps);
    if (id === 'finding') return findingComposerView(inc, ctx.run, obsMap, evidenceCtx);
    return actionComposer(inc, ctx.run, evidenceCtx);
  };
  const tabButtons = WS_TABS.map(([id, label, full]) =>
    el(
      'button',
      { type: 'button', id: `wstab-${id}`, title: full, attrs: { role: 'tab', 'aria-selected': String(tabState === id), 'aria-controls': 'ws-tabpanel', 'aria-label': full }, on: { click: () => selectTab(id) } },
      label,
      id === 'watches' ? el('span', { class: 'tab-count' }, String(ctx.active_watches.length)) : null,
    ),
  );
  function selectTab(id) {
    state.wsTab.set(inc.incident_id, id);
    for (const b of tabButtons) b.setAttribute('aria-selected', String(b.id === `wstab-${id}`));
    if (!panels.has(id)) panels.set(id, buildPanel(id));
    replace(panelSlot, panels.get(id));
    panelSlot.setAttribute('aria-labelledby', `wstab-${id}`);
  }
  panelSlot.id = 'ws-tabpanel';
  panelSlot.setAttribute('role', 'tabpanel');
  selectTab(tabState);

  const side = el('aside', { class: 'ws-side' }, el('section', { class: 'card ws-panel' }, el('div', { class: 'tabs', attrs: { role: 'tablist', 'aria-label': 'Investigation tools' } }, tabButtons), panelSlot));

  return el('div', null, backLink, head, el('div', { class: 'ws-grid' }, main, side));
}

function tabPanel(sub, body, flush = false) {
  return el('div', { class: ['tab-panel', flush && 'flush'] }, sub ? el('p', { class: 'panel-sub' }, sub) : null, body);
}

function findingCard(f, cls, obsMap) {
  const ids = f.evidence_observation_ids ?? [];
  return el(
    'article',
    { class: ['finding', cls] },
    el(
      'div',
      { class: 'row' },
      el('span', { class: 'kind' }, el('span', { class: ['dot', cls === 'hyp' ? 'warn' : 'ok'] }), cls === 'hyp' ? 'Hypothesis · unverified' : 'Verified finding · evidence-bound'),
      el('span', { class: 'spacer' }),
      f.interpretation ? el('span', { class: 'muted small' }, 'follow-up') : null,
      f.interpretation ? interpBadge(f.interpretation) : null,
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
  if (Array.isArray(d?.flows)) return 'connections.outbound';
  if (Array.isArray(d?.packages)) return 'packages.inventory';
  if (d?.active_state) return 'systemd.unit_state';
  if (Array.isArray(d?.files)) return 'files.metadata';
  return 'unknown';
}

function summarize(o) {
  const p = o.payload ?? {};
  if (p.kind === 'snapshot' || p.kind === 'delta') {
    const d = p.data ?? {};
    if (Array.isArray(d.sockets)) return `${d.count ?? d.sockets.length} listening sockets${d.partial_attribution ? ' · partial attribution' : ''}`;
    if (Array.isArray(d.flows)) return `${d.total_flows ?? d.flows.length} outbound flow groups${d.attribution_partial ? ' · partial attribution' : ''}`;
    if (Array.isArray(d.packages)) return `${d.total_packages ?? d.packages.length} installed packages${d.truncated ? ` · ${d.packages.length} kept` : ''}`;
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

function factRow(o, watchMap, list, selected, onSelect, incidentId = null) {
  const key = `fact:${o.observation_id}`;
  const detail = el('div', { class: 'fact-detail', hidden: !state.expanded.has(key) });
  if (state.expanded.has(key)) append(detail, payloadView(o, prevOf(o, list), incidentId));
  const toggle = el('button', { class: 'toggle', type: 'button', attrs: { 'aria-expanded': state.expanded.has(key) ? 'true' : 'false', 'aria-label': `Toggle observation ${o.observation_id} detail` } }, icon('chevron'));
  toggle.addEventListener('click', () => {
    const open = toggle.getAttribute('aria-expanded') !== 'true';
    toggle.setAttribute('aria-expanded', String(open));
    detail.hidden = !open;
    if (open) {
      state.expanded.add(key);
      if (!detail.firstChild) append(detail, payloadView(o, prevOf(o, list), incidentId));
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

function payloadView(o, prev, incidentId = null) {
  const p = o.payload ?? {};
  const parts = [];
  if (p.kind === 'snapshot' || p.kind === 'delta') {
    const d = p.data ?? {};
    if (p.kind === 'delta') parts.push(el('div', { class: 'row' }, el('span', { class: 'muted' }, 'delta against'), hashChip(p.base_hash)));
    if (Array.isArray(d.sockets)) parts.push(socketsTable(d, prev?.payload?.data?.sockets, o.observation_id, incidentId));
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
      el('dt', null, 'Observed'),
      el('dd', { class: 'mono' }, o.observed_at),
      el('dt', null, 'Spec version'),
      el('dd', { class: 'num' }, String(o.spec_version)),
      el('dt', null, 'State hash'),
      el('dd', null, hashChip(o.state_hash, { full: true })),
    ),
  );
  return el('div', { class: 'stack' }, parts);
}

const sockAddr = (s) => `${String(s.local_addr).includes(':') ? `[${s.local_addr}]` : s.local_addr}:${s.local_port}`;

function socketsTable(d, prevSockets, filterKey = null, incidentId = null) {
  // Compare with the previous sample in the window, or else with the reference
  // this incident's "What changed" panel used (accepted baseline / state before it opened).
  const markers = !prevSockets && incidentId && filterKey != null ? state.changeIndex.get(`${incidentId}:${filterKey}`) : null;
  const prevKeys = prevSockets ? new Set(prevSockets.map((s) => s.socket_key)) : null;
  const curKeys = new Set(d.sockets.map((s) => s.socket_key));
  const byPort = (a, b) => a.local_port - b.local_port || String(a.protocol).localeCompare(String(b.protocol));
  const isAdded = (s) => (prevKeys ? !prevKeys.has(s.socket_key) : Boolean(markers?.addedKeys.has(s.socket_key)));
  const added = d.sockets.filter(isAdded).sort(byPort);
  const removed = (prevSockets ? prevSockets.filter((s) => !curKeys.has(s.socket_key)) : markers?.removed ?? []).sort(byPort);
  const rest = d.sockets.filter((s) => !isAdded(s)).sort(byPort);
  const diffRows = [...added.map((s) => [s, 'new']), ...removed.map((s) => [s, 'gone'])];
  const rows = [...diffRows, ...rest.map((s) => [s, null])];
  const hasDiff = diffRows.length > 0 && rest.length > 0;
  let showAll = !hasDiff;
  let currentQuery = filterKey ? state.tableFilters.get(filterKey) ?? '' : '';

  const tbody = el('tbody');
  const countNode = el('span', { class: 'count' });
  const toggleBtn = hasDiff
    ? el(
        'button',
        {
          class: 'btn btn-sm',
          type: 'button',
          on: {
            click: () => {
              showAll = !showAll;
              draw(currentQuery);
            },
          },
        },
        `Show all ${d.sockets.length} (${rest.length} unchanged)`,
      )
    : null;
  const text = (s) => [s.protocol, sockAddr(s), s.pid, s.comm, s.systemd_unit, s.uid].filter((v) => v != null).join(' ').toLowerCase();
  const draw = (q = '') => {
    currentQuery = q;
    const needle = q.trim().toLowerCase();
    const base = needle || showAll ? rows : diffRows;
    const shown = needle ? base.filter(([s]) => text(s).includes(needle)) : base;
    replace(
      tbody,
      shown.map(([s, mark]) =>
        el(
          'tr',
          { class: mark === 'new' ? 'is-new' : mark === 'gone' ? 'is-gone' : null },
          el('td', null, s.protocol),
          el('td', null, sockAddr(s)),
          el('td', null, s.pid ?? '—'),
          el('td', null, s.comm ?? '—'),
          el('td', null, s.systemd_unit ?? '—'),
          el('td', null, String(s.uid)),
          el('td', null, mark === 'new' ? el('span', { class: 'badge ok' }, 'Added') : mark === 'gone' ? el('span', { class: 'badge bad' }, 'Removed') : ''),
        ),
      ),
      shown.length ? null : el('tr', null, el('td', { attrs: { colspan: '7' }, class: 'muted' }, 'No sockets match this filter.')),
    );
    if (toggleBtn) {
      toggleBtn.textContent = showAll ? `Changes only (${diffRows.length})` : `Show all ${d.sockets.length} (${rest.length} unchanged)`;
    }
    const delta = prevKeys || markers ? ` · ${added.length} added · ${removed.length} removed${markers ? ' vs reference' : ''}` : '';
    countNode.textContent = needle
      ? `${shown.length} of ${d.sockets.length} sockets${delta}`
      : showAll
        ? `${d.sockets.length} sockets${delta}`
        : `${diffRows.length} changed of ${d.sockets.length} sockets`;
  };

  let tools = el('div', { class: 'ptools' }, countNode, toggleBtn);
  if (rows.length > 12) {
    const input = el('input', { type: 'search', placeholder: 'Filter port, process, unit…', value: currentQuery, attrs: { 'aria-label': 'Filter sockets' } });
    input.addEventListener('input', () => {
      if (filterKey) state.tableFilters.set(filterKey, input.value);
      draw(input.value);
    });
    tools = el('div', { class: 'ptools' }, el('label', { class: 'search' }, icon('search'), input), countNode, toggleBtn);
    draw(currentQuery);
  } else {
    draw();
  }
  return el(
    'div',
    null,
    tools,
    el('div', { class: 'pwrap' }, el('table', { class: 'ptable' }, el('thead', null, el('tr', null, ['Proto', 'Local', 'PID', 'Process', 'Unit', 'UID', ''].map((h) => el('th', null, h)))), tbody)),
  );
}

function unitView(d) {
  const kv = [
    ['Unit', d.unit],
    ['Load / active / sub', `${d.load_state} / ${d.active_state} / ${d.sub_state}`],
    ['Unit file state', d.unit_file_state ?? '—'],
    ['Main PID', d.main_pid ?? '—'],
  ];
  return el(
    'div',
    { class: 'stack' },
    el('dl', { class: 'kv' }, kv.map(([k, v]) => [el('dt', null, k), el('dd', { class: 'mono' }, String(v))]), el('dt', null, 'ExecStart hash'), el('dd', null, hashChip(d.exec_start_hash))),
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
      el('thead', null, el('tr', null, ['Path', 'Status', 'Mode', 'UID:GID', 'Size', 'SHA-256', 'Modified'].map((h) => el('th', null, h)))),
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
    p.gap_detected ? el('div', { class: 'err-box' }, 'Cursor gap detected: events may be missing between batches.') : null,
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
    case 'connections.outbound':
      return [p.include_tcp && 'tcp', p.include_udp && 'udp', p.include_ipv6 && 'ipv6'].filter(Boolean).join(' + ');
    case 'packages.inventory':
      return p.max_packages ? `up to ${p.max_packages} packages` : 'installed packages';
    default:
      return '';
  }
}

function watchesPanel(watches, runtime, inc) {
  const sorted = [...watches].sort((a, b) => (a.class === b.class ? a.id.localeCompare(b.id) : a.class === 'ephemeral' ? -1 : 1));
  const eph = sorted.filter((w) => w.class === 'ephemeral');
  return tabPanel(
    `${eph.length} ephemeral · ${sorted.length - eph.length} baseline on ${inc.host_id}`,
    el('div', null, sorted.length ? sorted.map((w) => watchRow(w, runtime[w.id])) : emptyState('No active watches', '')),
    true,
  );
}

function watchRow(w, rt) {
  const expired = w.lifecycle.expires_at && Date.parse(w.lifecycle.expires_at) <= Date.now();
  const retired = rt && rt.active === false && !expired;
  const runs = rt?.completed_runs;
  const stream = w.collector.type === 'journal.unit_events';
  return el(
    'div',
    { class: ['watch', (expired || retired) && 'is-expired'] },
    el('div', { class: 'row' }, classBadge(w.class), stream ? el('span', { class: 'badge stream' }, icon('stream'), 'Stream') : null, expired ? el('span', { class: 'badge' }, 'Expired') : null, el('span', { class: 'spacer' }), el('span', { class: 'mono muted' }, `v${w.version}`)),
    el('div', { class: 'wid' }, w.id),
    el('div', { class: 'target' }, el('span', { class: 'muted' }, `${w.collector.type} · `), watchTarget(w)),
    el(
      'div',
      { class: 'bounds' },
      el('span', { class: 'badge ghost' }, `Every ${w.schedule.interval_seconds}s`),
      el('span', { class: 'badge ghost' }, w.trigger.type.replace(/_/g, ' ')),
      w.trigger.compare_against ? el('span', { class: 'badge ghost' }, `vs ${w.trigger.compare_against.replace(/_/g, ' ')}`) : null,
      w.class === 'ephemeral' && w.lifecycle.expires_at ? el('span', { class: 'badge ghost' }, icon('clock'), relTime(w.lifecycle.expires_at, { until: true })) : null,
    ),
    w.class === 'ephemeral' && w.lifecycle.max_runs
      ? el('div', { class: 'mini' }, el('span', null, 'Runs'), meter(runs != null ? runs / w.lifecycle.max_runs : 0, 'eph'), el('span', { class: 'num' }, runs != null ? `${runs} / ${w.lifecycle.max_runs}` : `max ${w.lifecycle.max_runs}`))
      : null,
  );
}

// ----- run lifecycle -----

const SESSION_HELP =
  'Opens a manual session for you, the human operator, so you can propose watches, record findings and propose mitigations yourself. It does not start the model: automated reasoner-d runs begin on their own when a trigger is leased from the queue (see Reasoner activity).';

function startSessionButton(incidentId) {
  return el('button', { class: 'btn btn-primary btn-sm', type: 'button', title: SESSION_HELP, on: { click: (e) => startRun(incidentId, e.currentTarget) } }, icon('user'), 'Start operator session');
}

async function startRun(incidentId, btn = null) {
  if (btn) btn.disabled = true;
  try {
    const run = await api(`/api/incidents/${encodeURIComponent(incidentId)}/runs`, {
      method: 'POST',
      body: { backend_id: 'operator-console', model_id: 'human-operator', prompt_schema_version: 'console.v1' },
    });
    toast(`Operator session ${String(run.run_id).slice(0, 8)} started`, 'ok');
    reloadWorkspace(incidentId);
    return null;
  } catch (err) {
    toast(`${err.code}: ${err.message}`, 'bad');
    if (btn) btn.disabled = false;
    return err;
  }
}

function runLock(inc, label) {
  const errSlot = el('div');
  const btn = el('button', { class: 'btn btn-primary btn-sm', type: 'button', title: SESSION_HELP }, icon('user'), 'Start operator session');
  btn.addEventListener('click', async () => {
    replace(errSlot);
    const err = await startRun(inc.incident_id, btn);
    if (err) replace(errSlot, errorBox(err));
  });
  return el(
    'div',
    { class: 'lock-overlay' },
    icon('lock'),
    el('p', null, `${label} needs an operator session: a manual, time-limited session for you, separate from automated reasoner-d runs. It gets its own token scoped to this incident and host and expires on its own.`),
    btn,
    errSlot,
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
    case 'connections.outbound':
      return { type: 'set_diff', compare_against: 'last_observed', set_field: 'flows', identity_key: 'flow_key' };
    case 'packages.inventory':
      return { type: 'set_diff', compare_against: 'last_observed', set_field: 'packages', identity_key: 'package_key' };
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

/**
 * Keep a submit button disabled, with the reason beside it, until the form has
 * the input the backend genuinely requires. Server-side validation still runs.
 */
function guardSubmit(form, btn, note, missing, idle = 'control-d decides') {
  const check = () => {
    const m = missing();
    btn.disabled = Boolean(m);
    note.textContent = m ?? idle;
    note.classList.toggle('warn-text', Boolean(m));
  };
  form.addEventListener('input', check);
  form.addEventListener('change', check);
  check();
  return check;
}

const watchTargetText = (d) => {
  const p = d.parameters;
  if (d.collector_type === 'files.metadata') return String(p.paths ?? '').split(/[\n,]/).map((x) => x.trim()).filter(Boolean).join(', ');
  if (d.collector_type === 'sockets.listening') return 'listening sockets';
  if (d.collector_type === 'connections.outbound') return 'outbound connections';
  if (d.collector_type === 'packages.inventory') return 'installed packages';
  return String(p.unit ?? '').trim();
};

function proposalComposer(inc, run, caps) {
  const d = draftsFor(inc.incident_id).proposal;
  if (!d.trigger) d.trigger = triggerDefaults(d.collector_type);
  const body = el('div', { class: 'stack' });
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
      case 'connections.outbound':
        p.include_udp ??= false;
        p.exclude_loopback ??= true;
        return el('div', { class: 'checks' }, check(p, 'include_tcp', 'TCP'), check(p, 'include_udp', 'Connected UDP'), check(p, 'include_ipv6', 'IPv6'), check(p, 'resolve_process', 'Resolve owning process'), check(p, 'exclude_loopback', 'Exclude loopback'));
      case 'packages.inventory':
        return el('p', { class: 'hint' }, 'Installed packages from the dpkg status file. The agent caps the entries it keeps and reports anything omitted.');
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
      'connections.outbound': { include_tcp: p.include_tcp, include_udp: p.include_udp ?? false, include_ipv6: p.include_ipv6, resolve_process: p.resolve_process, exclude_loopback: p.exclude_loopback ?? true },
      'packages.inventory': {},
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
            el('div', { class: 'row' }, el('span', { class: 'verdict' }, last.decision.allowed ? 'Accepted by the policy gate' : 'Denied by the policy gate'), el('span', { class: 'spacer' }), el('span', { class: 'mono muted' }, `policy v${last.decision.policy_version}`)),
            el('div', { class: 'rule' }, last.decision.rule_id),
            el('div', { class: 'reason' }, last.decision.reason),
            last.watch_id ? el('div', { class: 'row' }, el('span', { class: 'mono' }, last.watch_id), last.bundle_version != null ? el('span', { class: 'badge ghost' }, `Bundle v${last.bundle_version}`) : null) : null,
            last.spec ? el('details', { class: 'preview' }, el('summary', null, 'Submitted WatchSpec (exact)'), jsonBlock(last.spec)) : null,
          )
        : null,
      log.length > 1
        ? el(
            'div',
            { class: 'history' },
            el('span', { class: 'eyebrow' }, 'Earlier in this session'),
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
      el('button', { type: 'button', attrs: { 'aria-pressed': String(d.class === 'ephemeral') }, on: { click: () => { d.class = 'ephemeral'; draw(); } } }, 'Ephemeral'),
      el('button', { type: 'button', attrs: { 'aria-pressed': String(d.class === 'baseline') }, on: { click: () => { d.class = 'baseline'; draw(); } } }, 'Baseline (policy test)'),
    );
    const capButtons = el(
      'div',
      { class: 'cap-list' },
      (caps.length ? caps : ALL_COLLECTORS.map((collector_type) => ({ collector_type }))).map((c) =>
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
    const note = el('span', { class: 'form-note' });
    // A sensible rationale is generated from the target until the operator edits it.
    const autoRationale = () => `Temporary ${d.collector_type} watch on ${watchTargetText(d) || 'the target'} while ${shortId(inc.incident_id)} is investigated.`;
    if (!d.rationaleEdited) d.rationale = autoRationale();
    const rationale = textArea(d, 'rationale', { placeholder: 'Why this temporary watch is needed for the investigation…', rows: 2 });
    rationale.addEventListener('input', () => (d.rationaleEdited = Boolean(rationale.value.trim())));
    const form = el(
      'form',
      { class: 'form', attrs: { novalidate: true } },
      field('Watch class', classSeg, d.class === 'baseline' ? el('span', { class: 'hint bad' }, 'Investigator identities cannot create baseline watches — expect baseline.protected.') : el('span', { class: 'hint' }, 'Bounded by TTL and max runs; retired on incident closure.')),
      el('div', { class: 'field' }, el('span', { class: 'lbl' }, 'Collector', el('span', { class: 'muted' }, `${inc.host_id} catalog`)), capButtons),
      paramsFields(),
      triggerFields(),
      el('div', { class: 'grid-2' }, field('Interval (s)', iv), field('Timeout (s)', to), field('TTL (min)', ttl), field('Max runs', mr)),
      hintNode,
      field('Rationale', rationale, el('span', { class: 'hint' }, 'Pre-filled from the target; edit it if there is more to say.')),
      el('details', { class: 'preview' }, el('summary', null, 'Request preview'), jsonBlock({ ...requestBody(), run_id: run?.run_id ? `${run.run_id.slice(0, 8)}…` : null })),
      el('div', { class: 'form-actions' }, note, submitBtn),
    );
    form.addEventListener('input', (e) => {
      if (e.target !== rationale && !d.rationaleEdited) rationale.value = d.rationale = autoRationale();
    });
    const recheck = guardSubmit(form, submitBtn, note, () => {
      if ((d.collector_type === 'systemd.unit_state' || d.collector_type === 'journal.unit_events') && !String(d.parameters.unit ?? '').trim()) return 'Enter the unit to watch.';
      if (d.collector_type === 'files.metadata' && !watchTargetText(d)) return 'Enter at least one path.';
      if (!String(d.rationale ?? '').trim()) return 'Add a rationale.';
      return null;
    });
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      await submit(submitBtn);
      recheck();
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
  return tabPanel('Constrained to the host capability catalog. control-d returns the deterministic PolicyDecision.', body);
}

// ----- finding composer -----

function evidenceToggle(id, on, ev) {
  if (on) ev.selected.add(id);
  else ev.selected.delete(id);
  const box = document.querySelector(`#fact-${id} input[type="checkbox"]`);
  if (box) box.checked = on;
  for (const fn of ev.listeners) fn();
}

function findingComposerView(inc, run, obsMap, ev) {
  const d = draftsFor(inc.incident_id).finding;
  const selected = ev.selected;
  const body = el('div', { class: 'stack' });
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
              { class: 'ev-badge', type: 'button', title: 'Remove from evidence', on: { click: () => evidenceToggle(id, false, ev) } },
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
      el('button', { type: 'button', attrs: { 'aria-pressed': String(d.kind === 'hypothesis') }, on: { click: () => { d.kind = 'hypothesis'; draw(); } } }, 'Hypothesis'),
      el('button', { type: 'button', attrs: { 'aria-pressed': String(d.kind === 'verified_finding') }, on: { click: () => { d.kind = 'verified_finding'; draw(); } } }, 'Verified finding'),
    );
    const btn = el('button', { class: 'btn btn-primary', type: 'submit' }, d.kind === 'verified_finding' ? 'Record verified finding' : 'Record hypothesis');
    const note = el('span', { class: 'form-note' });
    const form = el(
      'form',
      { class: 'form', attrs: { novalidate: true } },
      el('div', { class: 'grid-2' }, field('Kind', seg), field('Severity', selectInput(d, 'severity', SEV_ORDER.slice().reverse().map((s) => [s, s])))),
      field('Summary', textArea(d, 'summary', { placeholder: 'What is asserted, in one or two sentences…', rows: 3 })),
      field('Uncertainty', textArea(d, 'uncertainty', { placeholder: 'What is not yet established, alternative explanations…', rows: 2 })),
      el('div', { class: 'field' }, el('span', { class: 'lbl' }, 'Evidence observations'), evNode, evHint),
      el('div', { class: 'checks' }, check(d, 'escalation_requested', 'Request escalation to operator')),
      el('div', { class: 'form-actions' }, note, btn),
    );
    const recheck = guardSubmit(form, btn, note, () => (!d.summary.trim() ? 'Write a summary.' : d.kind === 'verified_finding' && !selected.size ? 'Cite at least one observation.' : null), 'Bound to the cited evidence');
    ev.listeners.add(recheck);
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
        state.wsTab.set(inc.incident_id, 'finding');
        reloadWorkspace(inc.incident_id);
      } catch (err) {
        toast(`${err.code}: ${err.message}`, 'bad');
        recheck();
      }
    });
    replace(body, form);
    refreshEvidence();
  }

  if (!run) append(body, runLock(inc, 'Recording a hypothesis or finding'));
  else {
    draw();
    ev.listeners.add(() => refreshEvidence());
  }
  return tabPanel('Hypotheses are unverified assertions; verified findings must bind evidence.', body);
}

// ----- mitigation composer (InvestigationRequest::ProposeAction) -----

const VERB_CHOICES = [
  ['nft_block_ip', 'Block IP'],
  ['systemd_stop_unit', 'Stop unit'],
  ['host_isolate', 'Isolate host'],
];

/** A unit worth suggesting: the newest non-protected unit seen in this incident's evidence. */
function suggestedUnit(obs) {
  const protectedUnits = /^(sshd?|systemd-(journald|networkd|resolved)|NetworkManager|dbus|agent-d|control-d|action-exec-d)\.service$/;
  for (const o of obs) {
    const d = o.payload?.data;
    const units = [d?.unit, ...(d?.sockets ?? []).map((s) => s.systemd_unit)].filter(Boolean);
    const u = units.find((x) => !protectedUnits.test(x));
    if (u) return u;
  }
  return '';
}

function actionDefaults(d, host) {
  const minutes = (m) => `${m} min`;
  switch (d.verb) {
    case 'nft_block_ip': {
      const ip = d.ip.trim() || 'the address';
      const dir = d.direction === 'inbound' ? `inbound traffic from ${ip}` : d.direction === 'outbound' ? `outbound traffic to ${ip}` : `all traffic to and from ${ip}`;
      return {
        expected_effect: `Drop ${dir} on ${host} for ${minutes(d.ip_ttl_min)}.`,
        blast_radius: `One address on ${host}; no services restart. The gate refuses loopback, link-local and private management ranges.`,
        rollback_plan: `The rule expires after ${minutes(d.ip_ttl_min)}; action-exec-d deletes it and verifies removal.`,
      };
    }
    case 'systemd_stop_unit': {
      const unit = d.unit.trim() || 'the unit';
      return {
        expected_effect: `Stop ${unit} on ${host} for ${minutes(d.unit_ttl_min)} to contain the suspected process.`,
        blast_radius: `Only ${unit} and anything that depends on it. Protected units (SSH, journald, networking, the harness itself) are refused by the gate.`,
        rollback_plan: `action-exec-d restarts ${unit} when the ${minutes(d.unit_ttl_min)} TTL elapses, unless the incident is resolved first.`,
      };
    }
    default: {
      const keep = d.cidrs.trim() ? d.cidrs.split(/[\s,]+/).filter(Boolean).join(', ') : 'the management ranges';
      return {
        expected_effect: `Isolate ${host} from every network except ${keep} for ${minutes(d.iso_ttl_min)} while the incident is analysed.`,
        blast_radius: `All traffic to and from ${host} outside ${keep} stops, including public services.`,
        rollback_plan: `action-exec-d removes the isolation rules when the ${minutes(d.iso_ttl_min)} TTL elapses and verifies connectivity.`,
      };
    }
  }
}

const AUTH_TEXT = { policy_bounded_autonomous: 'Bounded autonomous', dual_signed_operator: 'Dual-signed operator' };

function actionResultView(r, inc) {
  const allowed = r.decision.allowed;
  const pending = r.status === 'pending_approval';
  const kind = !allowed ? 'bad' : pending ? 'warn' : 'ok';
  const verdict = !allowed ? 'Denied by the action gate' : pending ? 'Intent created · awaiting dual-signed approval' : 'Authorized by bounded policy';
  const open = r.intent_id
    ? el(
        'button',
        {
          class: 'btn btn-sm',
          type: 'button',
          on: {
            click: () => {
              state.mit = { filter: 'all', host: '', incident: inc.incident_id };
              state.openIntent = r.intent_id;
              location.hash = '#/mitigations';
            },
          },
        },
        'Open in Mitigations',
        icon('arrow'),
      )
    : null;
  return el(
    'div',
    { class: ['decision', kind], attrs: { role: 'status' } },
    el('div', { class: 'verdict' }, verdict),
    el('div', { class: 'rule' }, r.decision.rule_id, el('span', { class: 'muted' }, ` · policy v${r.decision.policy_version}`)),
    el('div', { class: 'reason' }, r.decision.reason),
    el(
      'dl',
      { class: 'kv' },
      el('dt', null, 'Action'),
      el('dd', null, el('b', null, VERB_LABEL[r.verb?.verb] ?? r.verb?.verb), ' ', el('span', { class: 'mono' }, verbTarget(r.verb))),
      el('dt', null, 'Status'),
      el('dd', null, actionStatusBadge(r.status ?? 'rejected')),
      r.auth_mode ? [el('dt', null, 'Authorization'), el('dd', null, AUTH_TEXT[r.auth_mode] ?? r.auth_mode)] : null,
      r.proposal_id != null ? [el('dt', null, 'Proposal'), el('dd', { class: 'mono' }, `#${r.proposal_id}`)] : null,
      r.intent_id ? [el('dt', null, 'Intent'), el('dd', null, idChip(r.intent_id, { title: 'Intent' }))] : null,
    ),
    open ? el('div', { class: 'row' }, open) : null,
  );
}

function actionComposer(inc, run, ev) {
  const drafts = draftsFor(inc.incident_id);
  drafts.action ??= {
    verb: 'nft_block_ip',
    ip: '',
    direction: 'outbound',
    ip_ttl_min: 15,
    unit: suggestedUnit(ev.obs),
    unit_ttl_min: 30,
    cidrs: '',
    iso_ttl_min: 60,
    expected_effect: '',
    blast_radius: '',
    rollback_plan: '',
    edited: {},
  };
  const d = drafts.action;
  const body = el('div', { class: 'stack' });
  const result = el('div', { class: 'stack' });
  const texts = {};

  function syncDefaults() {
    const def = actionDefaults(d, inc.host_id);
    for (const k of ['expected_effect', 'blast_radius', 'rollback_plan']) {
      if (d.edited[k] && d[k].trim()) continue;
      d[k] = def[k];
      d.edited[k] = false;
      if (texts[k]) texts[k].value = def[k];
    }
  }

  function renderResult() {
    const log = state.actionResults.get(inc.incident_id) ?? [];
    replace(
      result,
      log[0] ? actionResultView(log[0], inc) : null,
      log.length > 1
        ? el('div', { class: 'history' }, el('span', { class: 'eyebrow' }, 'Earlier in this session'), log.slice(1, 6).map((x) => el('div', { class: 'h-item' }, el('span', { class: ['dot', x.decision.allowed ? 'ok' : 'bad'] }), el('span', { class: 'mono' }, x.decision.rule_id), el('span', { class: 'num muted' }, fmtTime(x.at)))))
        : null,
    );
  }

  const evNode = el('div', { class: 'ev-row' });
  const evHint = el('span', { class: 'hint' });
  function refreshEvidence() {
    const ids = [...ev.selected].sort((a, b) => a - b);
    replace(
      evNode,
      ids.length
        ? ids.map((id) => {
            const o = ev.obsMap.get(id);
            return el('button', { class: 'ev-badge', type: 'button', title: 'Remove from evidence', on: { click: () => evidenceToggle(id, false, ev) } }, `obs ${id}`, o ? el('span', { class: 'h' }, o.state_hash.slice(0, 8)) : null, icon('close'));
          })
        : el('span', { class: 'muted small' }, 'None cited yet.'),
    );
    evHint.className = ids.length ? 'hint' : 'hint warn';
    evHint.textContent = ids.length ? `${ids.length} observation${ids.length === 1 ? '' : 's'} bound by ID; control-d checks each is inside this incident's scope.` : 'The gate denies proposals without evidence (action.evidence_required). Tick facts on the left or cite the latest.';
  }

  function textField(key, label, rows = 3) {
    const t = el('textarea', { rows, value: d[key] });
    t.addEventListener('input', () => {
      d[key] = t.value;
      d.edited[key] = true;
    });
    texts[key] = t;
    return field(label, t);
  }

  function verbFields() {
    const onChange = () => syncDefaults();
    const ttl = (key) => numInput(d, key, { min: 1, onInput: onChange });
    switch (d.verb) {
      case 'nft_block_ip':
        return el(
          'div',
          { class: 'grid-2' },
          field('IP address', textInput(d, 'ip', { placeholder: '203.0.113.47', mono: true, onInput: onChange })),
          field('Direction', selectInput(d, 'direction', [['outbound', 'Outbound'], ['inbound', 'Inbound'], ['both', 'Both']], onChange)),
          field('TTL (min)', ttl('ip_ttl_min')),
          el('span', { class: 'hint span-2' }, 'Within policy, short blocks may auto-authorize; everything else waits for an operator co-signature.'),
        );
      case 'systemd_stop_unit':
        return el(
          'div',
          { class: 'grid-2' },
          field('Unit', textInput(d, 'unit', { placeholder: 'custom-helper.service', mono: true, onInput: onChange })),
          field('TTL (min)', ttl('unit_ttl_min')),
        );
      default:
        return el(
          'div',
          { class: 'stack' },
          field('Keep reachable (management CIDRs)', textInput(d, 'cidrs', { placeholder: '10.20.0.0/24, 10.20.8.15/32', mono: true, onInput: onChange }), el('span', { class: 'hint' }, 'Comma separated, 1–16 ranges. Host isolation is always dual-signed.')),
          el('div', { class: 'grid-2' }, field('TTL (min)', ttl('iso_ttl_min'))),
        );
    }
  }

  function requestBody() {
    const mins = (m) => Math.round(Number(m) * 60);
    const verb =
      d.verb === 'nft_block_ip'
        ? { verb: d.verb, ip: d.ip.trim(), direction: d.direction, ttl_seconds: mins(d.ip_ttl_min) }
        : d.verb === 'systemd_stop_unit'
          ? { verb: d.verb, unit: d.unit.trim(), ttl_seconds: mins(d.unit_ttl_min) }
          : { verb: d.verb, preserve_mgmt_cidrs: d.cidrs.split(/[\s,]+/).filter(Boolean), ttl_seconds: mins(d.iso_ttl_min) };
    return { run_id: run?.run_id, verb, evidence_observation_ids: [...ev.selected], expected_effect: d.expected_effect, blast_radius: d.blast_radius, rollback_plan: d.rollback_plan };
  }

  function draw() {
    syncDefaults();
    if (!ev.selected.size && ev.obs.length) {
      evidenceToggle(ev.obs[0].observation_id, true, ev);
    }
    const seg = el(
      'div',
      { class: 'seg', attrs: { role: 'group', 'aria-label': 'Mitigation verb' } },
      VERB_CHOICES.map(([v, label]) => el('button', { type: 'button', attrs: { 'aria-pressed': String(d.verb === v) }, on: { click: () => { d.verb = v; d.edited = {}; draw(); } } }, label)),
    );
    const citeLatest = el(
      'button',
      {
        class: 'btn btn-sm',
        type: 'button',
        disabled: !ev.obs.length,
        title: ev.obs.length ? `Cite observation ${ev.obs[0].observation_id}, the newest in this incident` : 'No observations in this incident window',
        on: { click: () => ev.obs.length && evidenceToggle(ev.obs[0].observation_id, true, ev) },
      },
      'Cite latest',
    );
    const justification = el(
      'details',
      { class: 'more' },
      el('summary', null, 'Review audit justification (auto-filled)'),
      el(
        'div',
        { class: 'stack' },
        textField('expected_effect', 'Expected effect', 2),
        textField('blast_radius', 'Blast radius', 2),
        textField('rollback_plan', 'Rollback plan', 2),
      ),
    );
    const submitBtn = el('button', { class: 'btn btn-primary', type: 'submit' }, 'Submit to action gate');
    const note = el('span', { class: 'form-note' });
    const form = el(
      'form',
      { class: 'form', attrs: { novalidate: true } },
      field('Action', seg),
      verbFields(),
      el('div', { class: 'field' }, el('span', { class: 'lbl' }, 'Evidence', citeLatest), evNode, evHint),
      justification,
      el('div', { class: 'form-actions' }, note, submitBtn),
    );
    const recheck = guardSubmit(form, submitBtn, note, () =>
      d.verb === 'nft_block_ip' && !d.ip.trim() ? 'Enter the IP address to block.' : d.verb === 'systemd_stop_unit' && !d.unit.trim() ? 'Enter the unit to stop.' : null,
    );
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      submitBtn.disabled = true;
      try {
        const r = await api(`/api/incidents/${encodeURIComponent(inc.incident_id)}/actions`, { method: 'POST', body: requestBody() });
        const log = state.actionResults.get(inc.incident_id) ?? [];
        log.unshift({ ...r, at: new Date().toISOString() });
        state.actionResults.set(inc.incident_id, log);
        renderResult();
        toast(r.decision.allowed ? `${r.status === 'pending_approval' ? 'Awaiting approval' : 'Authorized'}: ${r.decision.rule_id}` : `Denied: ${r.decision.rule_id}`, r.decision.allowed ? 'ok' : 'bad');
        await loadActions();
        renderShell();
      } catch (err) {
        toast(`${err.code}: ${err.message}`, 'bad');
      } finally {
        recheck();
      }
    });
    replace(body, form, result);
    refreshEvidence();
    renderResult();
  }

  if (!run) {
    append(body, runLock(inc, 'Proposing a mitigation'));
    renderResult();
    append(body, result);
  } else {
    draw();
    ev.listeners.add(() => refreshEvidence());
  }
  return tabPanel([el('strong', null, 'Propose mitigation. '), 'A closed catalog of typed, TTL-bounded verbs. The deterministic action gate signs, queues for co-signature, or denies.'], body);
}

// ----- what changed -----

function describeEntry(type, x) {
  if (type === 'sockets.listening') {
    return [`${x.protocol} ${sockAddr(x)}`, el('span', { class: 'muted' }, ` · ${x.comm ?? 'unknown process'}${x.pid ? ` (pid ${x.pid})` : ''} · ${x.systemd_unit ?? 'no unit'} · uid ${x.uid}`)];
  }
  return [x.path, el('span', { class: 'muted' }, ` · ${x.status ?? '?'}${x.size_bytes != null ? ` · ${x.size_bytes} B` : ''}${x.sha256 ? ` · ${x.sha256.slice(0, 10)}…` : ''}`)];
}

const fmtVal = (v) => (v === null || v === undefined ? '∅' : typeof v === 'string' && /^[0-9a-f]{64}$/.test(v) ? `${v.slice(0, 10)}…` : String(v));

function diffItems(c, actionFor = () => null) {
  const items = [];
  const d = c.diff;
  if (d.kind === 'set') {
    for (const x of d.added) items.push(['add', 'Added', describeEntry(c.collector_type, x), actionFor(x)]);
    for (const x of d.removed) items.push(['del', 'Removed', describeEntry(c.collector_type, x)]);
    for (const x of d.changed) items.push(['mod', 'Changed', [x.key, el('span', { class: 'muted' }, ` · ${x.fields.map((f) => `${f.field} ${fmtVal(f.before)} → ${fmtVal(f.after)}`).join(', ')}`)]]);
  } else if (d.kind === 'fields') {
    for (const f of d.fields) items.push(['mod', 'Changed', [f.field, el('span', { class: 'muted' }, ` · ${fmtVal(f.before)} → ${fmtVal(f.after)}`)]]);
    for (const x of d.unit_files.added) items.push(['add', 'Added', describeEntry('files', x)]);
    for (const x of d.unit_files.removed) items.push(['del', 'Removed', describeEntry('files', x)]);
    for (const x of d.unit_files.changed) items.push(['mod', 'Changed', [x.key, el('span', { class: 'muted' }, ` · ${x.fields.map((f) => `${f.field} ${fmtVal(f.before)} → ${fmtVal(f.after)}`).join(', ')}`)]]);
  }
  return items;
}

function changeView(c, actionFor) {
  const basis =
    c.basis === 'accepted_baseline'
      ? [`vs accepted baseline rev ${c.accepted_baseline.revision_id}`, c.accepted_baseline.approver ? ` (${c.accepted_baseline.approver})` : '']
      : [`vs #${c.reference.observation_id}, just before this incident opened`];
  const items = diffItems(c, actionFor);
  const LIMIT = 8;
  return el(
    'div',
    { class: 'change' },
    el(
      'div',
      { class: 'change-head' },
      el('span', { class: 'wid' }, c.watch_id),
      el('span', { class: 'muted' }, c.collector_type),
      el('span', { class: 'spacer' }),
      el('span', null, basis, ' → latest ', el('button', { class: 'ev-badge', type: 'button', title: 'Show this observation', on: { click: () => focusFact(c.latest.observation_id) } }, `#${c.latest.observation_id}`)),
    ),
    c.diff.kind === 'unavailable'
      ? el('div', { class: 'empty-slot' }, 'The accepted baseline observation is outside the loaded window, so only hashes can be compared: ', hashChip(c.accepted_baseline.state_hash), ' → ', hashChip(c.latest.state_hash))
      : items.length
        ? el('ul', { class: 'diff-list' }, items.slice(0, LIMIT).map(([cls, tag, what, action]) => el('li', { class: [cls, action && 'has-action'] }, el('span', { class: 'tag' }, tag), el('span', { class: 'what' }, what), action ? el('span', { class: 'diff-action' }, action) : null)))
        : el('div', { class: 'empty-slot' }, 'Hashes differ, but no field-level difference is modelled for this collector.'),
    items.length > LIMIT ? el('div', { class: 'diff-more' }, `${items.length - LIMIT} more difference${items.length - LIMIT === 1 ? '' : 's'} in the observation detail below.`) : null,
  );
}

function changesCard(inc, r, { watchMap = new Map(), triggers = [], ruleSuppression = null } = {}) {
  const suppressed = suppressionNote(inc, triggers, ruleSuppression);
  if (!r || r.error) return card('What changed', null, el('div', { class: 'card-body' }, suppressed, errorBox(r?.error ?? new Error('unavailable'))), null, 'changes');
  {
    // "Allow for this service": only on set_diff socket watches, only for admins.
    // A socket an active rule already covers is marked instead (matched here in
    // the browser against the currently active rules).
    const allowFor = (c) => {
      const w = watchMap.get(c.watch_id);
      if (c.collector_type !== 'sockets.listening' || c.diff.kind !== 'set' || w?.trigger?.type !== 'set_diff') return () => null;
      const rules = activeSocketRules(inc.host_id, c.watch_id);
      return (x) => {
        const hit = rules.find((r) => socketMatchesRule(r.spec, x));
        if (hit) return el('a', { class: 'badge ok rule-hit', href: `#/rules?host=${enc(inc.host_id)}`, title: ruleSentence(hit.spec) }, icon('rules'), `Allowed by rule ${hit.rule_id.replace(/^rule-/, '').slice(0, 8)}`);
        if (!adminEnabled()) return null;
        return el(
          'button',
          { class: 'btn btn-sm btn-ghost', type: 'button', title: `Draft an expectation rule that allows ${x.systemd_unit ?? x.comm ?? 'this process'} to listen here`, on: { click: () => openRuleComposer({ host_id: inc.host_id, watch_id: c.watch_id, item: x, incident: inc }) } },
          icon('rules'),
          'Allow for this service',
        );
      };
    };
    const n = r.changes.length;
    for (const c of r.changes) {
      if (c.diff.kind === 'set' && c.collector_type === 'sockets.listening') {
        state.changeIndex.set(`${inc.incident_id}:${c.latest.observation_id}`, { addedKeys: new Set(c.diff.added.map((x) => x.socket_key)), removed: c.diff.removed });
      }
    }
    return card(
      'What changed',
      n ? `${n} snapshot watch${n === 1 ? '' : 'es'} on ${inc.host_id} differ${n === 1 ? 's' : ''} from the accepted baseline or the state before this incident` : null,
      n ? el('div', { class: 'card-body' }, suppressed, r.changes.map((c) => changeView(c, allowFor(c)))) : el('div', { class: 'card-body' }, suppressed, el('div', { class: 'empty-slot' }, 'No snapshot differences against an accepted baseline or the state just before this incident opened. Stream watches (journal) are append-only and not compared.')),
      null,
      'changes',
    );
  }
}

// ---------------------------------------------------------------------------
// Reasoner activity: automated reasoner-d runs, operator sessions, trigger queue
// ---------------------------------------------------------------------------

const RUN_STATUS = {
  active: ['live', 'Active'],
  completed: ['ok', 'Completed'],
  budget_exhausted: ['warn', 'Budget exhausted'],
  failed: ['bad', 'Failed'],
  cancelled: ['ghost', 'Cancelled'],
  expired: ['ghost', 'Expired'],
};
const TRIGGER_STATUS = { pending: ['warn', 'Pending'], leased: ['live', 'Leased'], done: ['ok', 'Done'], dead_letter: ['bad', 'Dead letter'] };
const EVENT_KINDS = { turn_started: 'Turn', tool_call: 'Tool call', tool_result: 'Result', model_text: 'Model', budget_warning: 'Budget', note: 'Note' };
const STALL_MS = 120_000;
const QUEUE_FILTERS = [
  ['open', 'Open', 'pending,leased'],
  ['pending', 'Pending', 'pending'],
  ['leased', 'Leased', 'leased'],
  ['dead_letter', 'Dead letter', 'dead_letter'],
  ['done', 'Done', 'done'],
  ['all', 'All', ''],
];

const enc = encodeURIComponent;
const plural = (n, one, many = `${one}s`) => `${n} ${n === 1 ? one : many}`;

/** Any free-form value as readable text: never "undefined", "null" or "[object Object]". */
function plain(v, max = 400) {
  if (v === null || v === undefined || v === '') return '—';
  if (typeof v === 'number') return Number.isFinite(v) ? v.toLocaleString() : '—';
  if (typeof v === 'boolean') return v ? 'yes' : 'no';
  let s;
  try {
    s = typeof v === 'string' ? v : JSON.stringify(v);
  } catch {
    s = '—';
  }
  return s.length > max ? `${s.slice(0, max)}…` : s;
}

const detailText = (d) =>
  Object.entries(d ?? {})
    .map(([k, v]) => `${k.replace(/_/g, ' ')}: ${plain(v, 160)}`)
    .join(' · ') || '—';

function fmtTokens(n) {
  if (!Number.isFinite(n)) return '—';
  return n >= 10_000 ? `${Math.round(n / 1000)}k` : n >= 1000 ? `${(n / 1000).toFixed(1)}k` : String(n);
}

function duration(fromIso, toIso) {
  const s = Math.max(0, Math.round((Date.parse(toIso) - Date.parse(fromIso)) / 1000));
  if (!Number.isFinite(s)) return '—';
  if (s < 60) return `${s}s`;
  if (s < 3600) return `${Math.floor(s / 60)}m ${s % 60 ? `${s % 60}s` : ''}`.trim();
  return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`;
}

function runStatusBadge(status) {
  const [cls, label] = RUN_STATUS[status] ?? ['', cap(String(status ?? 'unknown').replace(/_/g, ' '))];
  return el('span', { class: ['badge', cls] }, cls === 'live' ? el('span', { class: 'dot accent pulse' }) : null, label);
}

function triggerStatusBadge(status) {
  const [cls, label] = TRIGGER_STATUS[status] ?? ['', cap(String(status ?? 'unknown').replace(/_/g, ' '))];
  return el('span', { class: ['badge', cls] }, cls === 'live' ? el('span', { class: 'dot accent pulse' }) : null, label);
}

function originBadge(run) {
  return run.origin === 'operator'
    ? el('span', { class: 'badge ghost', title: `Manual session opened by ${plain(run.principal_id)} from an operator console` }, icon('user'), 'Operator session')
    : el('span', { class: 'badge solid', title: `Automated run by ${plain(run.principal_id)} via ${plain(run.backend_id)}` }, icon('cpu'), 'reasoner-d');
}

async function loadReasoner() {
  try {
    const [r, t] = await Promise.all([api('/api/runs?limit=100'), api('/api/triggers?status=pending,leased,dead_letter&limit=200')]);
    const off = r.available === false ? r : t.available === false ? t : null;
    state.reasoner = { loaded: true, available: !off, reason: off?.reason ?? null, message: off?.message ?? null, runs: r.runs ?? [], triggers: t.triggers ?? [] };
  } catch (err) {
    state.reasoner = { loaded: true, available: false, reason: err.code, message: err.message, runs: [], triggers: [] };
  }
}

/** Is reasoner-d doing anything? `stalled` = triggers waiting > 2 min with no active run or lease. */
function reasonerHealth(now = Date.now()) {
  const R = state.reasoner;
  if (!R.loaded) return { state: 'loading' };
  if (!R.available) return { state: 'unavailable', message: R.message };
  const auto = R.runs.filter((r) => r.origin === 'automated');
  const active = auto.filter((r) => r.status === 'active');
  const pending = R.triggers.filter((t) => t.status === 'pending');
  const leased = R.triggers.filter((t) => t.status === 'leased');
  const dead = R.triggers.filter((t) => t.status === 'dead_letter');
  const oldestMs = pending.reduce((m, t) => Math.min(m, Date.parse(t.created_at) || Infinity), Infinity);
  const lastActivity = auto.reduce((m, r) => Math.max(m, Date.parse(r.ended_at ?? r.started_at) || 0), 0);
  const quiet = !active.length && !leased.length && now - lastActivity > STALL_MS;
  const stalled = pending.length > 0 && quiet && now - oldestMs > STALL_MS;
  return {
    state: active.length || leased.length ? 'working' : stalled ? 'stalled' : pending.length ? 'queued' : 'idle',
    active,
    pending,
    leased,
    dead,
    quiet,
    oldest: Number.isFinite(oldestMs) ? new Date(oldestMs).toISOString() : null,
    lastRun: auto.reduce((m, r) => (!m || Date.parse(r.started_at) > Date.parse(m.started_at) ? r : m), null),
  };
}

const pendingStalled = (t, health) => t.status === 'pending' && health.quiet && Date.now() - Date.parse(t.created_at) > STALL_MS;

/** "Queued for reasoner" / "Reasoner working" marker for an incident (list rows and the workspace head). */
function incidentReasonerBadge(incidentId) {
  const R = state.reasoner;
  if (!R.available) return null;
  const trig = R.triggers.filter((t) => t.incident_id === incidentId);
  const working = trig.some((t) => t.status === 'leased') || R.runs.some((r) => r.incident_id === incidentId && r.origin === 'automated' && r.status === 'active');
  if (working) return el('span', { class: 'badge live', title: 'reasoner-d is investigating this incident now' }, el('span', { class: 'dot accent pulse' }), 'Reasoner working');
  const pending = trig.filter((t) => t.status === 'pending');
  if (!pending.length) return null;
  const stuck = pending.some((t) => pendingStalled(t, reasonerHealth()));
  return el(
    'span',
    { class: ['badge', 'warn'], title: stuck ? 'Waiting for reasoner-d for more than 2 minutes; it may not be running' : `${plural(pending.length, 'trigger')} waiting for reasoner-d` },
    icon('clock'),
    stuck ? 'Queued · reasoner idle' : 'Queued for reasoner',
  );
}

/** Update incident-list markers in place after a background refresh (the list itself is not re-rendered). */
function refreshIncidentMarkers() {
  for (const slot of document.querySelectorAll('[data-reasoner-slot]')) replace(slot, incidentReasonerBadge(slot.dataset.reasonerSlot));
}

// ----- live polling with backoff -----

const pollers = new Set();

/**
 * Re-run `fn` while `node` stays in the document: every `fast` ms while
 * `busy()` (an active run), otherwise every `slow` ms. While the tab is hidden
 * the delay doubles each round (up to 2 min); it snaps back when visible.
 */
function livePoll(node, fn, { fast = 4000, slow = 20_000, busy = () => false } = {}) {
  let timer = null;
  let hidden = 0;
  let first = true;
  let stopped = false;
  const p = {
    async run() {
      clearTimeout(timer);
      if (stopped) return;
      if (!first && !node.isConnected) return p.stop();
      first = false;
      try {
        await fn();
      } catch {
        /* fn renders its own errors */
      }
      if (stopped || !node.isConnected) return p.stop();
      const base = busy() ? fast : slow;
      const delay = document.hidden ? Math.min(120_000, base * 2 ** Math.min(5, ++hidden)) : ((hidden = 0), base);
      timer = setTimeout(p.run, delay);
    },
    stop() {
      stopped = true;
      clearTimeout(timer);
      pollers.delete(p);
    },
    kick() {
      if (!stopped && !document.hidden) p.run();
    },
  };
  pollers.add(p);
  return p;
}

document.addEventListener('visibilitychange', () => {
  if (!document.hidden) for (const p of pollers) p.kick();
});

// ----- one run: summary + expandable timeline -----

function eventSummary(e) {
  const d = e.detail ?? {};
  switch (e.kind) {
    case 'turn_started':
      return `Turn ${plain(d.turn)} started${d.tokens != null ? ` · ${plain(d.tokens)} tokens` : ''}`;
    case 'tool_call':
      return `Calling ${plain(d.tool)}`;
    case 'tool_result':
      return `${plain(d.tool)} ${d.ok === false ? 'failed' : d.accepted === false ? `denied${d.code ? ` (${plain(d.code)})` : ''}` : d.accepted ? 'accepted' : 'returned'}`;
    case 'model_text':
      return plain(d.text, 160);
    case 'budget_warning':
      return `${plain(d.budget)} budget${d.used != null ? ` ${plain(d.used)} of ${plain(d.limit)}` : ''}${d.stop ? ' · stopped' : ''}`;
    case 'note':
      return plain(d.text ?? detailText(d), 160);
    default:
      return detailText(d);
  }
}

function eventRow(e) {
  const d = e.detail ?? {};
  let main;
  switch (e.kind) {
    case 'turn_started':
      main = [el('b', null, `Turn ${plain(d.turn)}`), d.tokens != null ? el('span', { class: 'muted' }, ` · ${plain(d.tokens)} tokens in context`) : null];
      break;
    case 'tool_call':
      main = [el('span', { class: 'mono tl-tool' }, plain(d.tool)), d.args_preview ? el('code', { class: 'tl-args' }, plain(d.args_preview, 600)) : null];
      break;
    case 'tool_result': {
      const failed = d.ok === false;
      const verdict = failed ? ['bad', 'error'] : d.accepted === false ? ['warn', 'denied'] : d.accepted === true ? ['ok', 'accepted'] : ['', 'ok'];
      main = el(
        'div',
        { class: 'row' },
        el('span', { class: 'mono tl-tool' }, plain(d.tool)),
        el('span', { class: ['badge', verdict[0]] }, verdict[1]),
        d.code ? el('span', { class: ['rule-pill', failed || d.accepted === false ? 'bad' : 'ok'], title: 'Gate rule or error code' }, plain(d.code, 120)) : null,
      );
      break;
    }
    case 'model_text':
      main = el('p', { class: 'tl-text' }, plain(d.text, 4000));
      break;
    case 'budget_warning':
      main = el(
        'div',
        { class: 'row' },
        el('b', null, `${cap(plain(d.budget).replace(/_/g, ' '))} budget`),
        d.used != null ? el('span', { class: 'num' }, `${plain(d.used)} of ${plain(d.limit)} used`) : null,
        d.stop ? el('span', { class: 'badge warn' }, 'Run stopped') : null,
      );
      break;
    case 'note':
      main = el('span', null, plain(d.text ?? detailText(d), 2000));
      break;
    default:
      main = el('span', { class: 'dim' }, detailText(d));
  }
  const known = Object.hasOwn(EVENT_KINDS, e.kind);
  return el(
    'li',
    { class: ['tl-item', known && `k-${e.kind}`] },
    el('span', { class: 'tl-time num', title: e.created_at ? fullFmt.format(new Date(e.created_at)) : '' }, fmtTime(e.created_at)),
    el('span', { class: 'tl-kind' }, known ? EVENT_KINDS[e.kind] : plain(e.kind, 24)),
    el('div', { class: 'tl-main' }, main),
  );
}

function runStats(run, events) {
  const o = run.outcome;
  if (run.origin === 'operator') {
    // A human session has no turns or tokens: show what the operator submitted.
    const steps = events.length ? events.filter((e) => e.kind === 'tool_call').length : null;
    const chip = (label, value) => el('span', { class: 'stat-chip' }, el('b', { class: 'num' }, value), ` ${label}`);
    return el(
      'div',
      { class: 'run-stats' },
      steps !== null ? chip(steps === 1 ? 'submission' : 'submissions', String(steps)) : null,
      chip(run.findings_count === 1 ? 'finding' : 'findings', String(run.findings_count ?? 0)),
      chip(run.proposals_count === 1 ? 'proposal' : 'proposals', String(run.proposals_count ?? 0)),
    );
  }
  const derived = !o && events.length
    ? {
        turns: events.filter((e) => e.kind === 'turn_started').length,
        tool_calls: events.filter((e) => e.kind === 'tool_call').length,
      }
    : null;
  const s = o ?? derived;
  const chip = (label, value, title = null) => el('span', { class: 'stat-chip', title }, el('b', { class: 'num' }, value), ` ${label}`);
  return el(
    'div',
    { class: 'run-stats' },
    s ? chip(s.turns === 1 ? 'turn' : 'turns', String(s.turns)) : null,
    s ? chip(s.tool_calls === 1 ? 'tool call' : 'tool calls', String(s.tool_calls)) : null,
    o ? chip('tokens', `${fmtTokens(o.input_tokens)} in · ${fmtTokens(o.output_tokens)} out`, `${plain(o.input_tokens)} input / ${plain(o.output_tokens)} output tokens`) : null,
    !s ? chip(run.event_count === 1 ? 'event' : 'events', String(run.event_count ?? 0)) : null,
    chip(run.findings_count === 1 ? 'finding' : 'findings', String(run.findings_count ?? 0)),
    chip(
      run.proposals_count === 1 ? 'proposal' : 'proposals',
      o && o.proposals ? `${o.proposals_accepted}/${o.proposals}` : String(run.proposals_count ?? 0),
      o && o.proposals ? `${o.proposals_accepted} of ${o.proposals} proposals accepted by the gate` : null,
    ),
  );
}

/**
 * A run card with live state. `update(run)` redraws the summary in place;
 * `pull()` fetches only events after the last seen event_seq.
 */
function runItem(initial, { showIncident = false } = {}) {
  let run = initial;
  if (!state.runEvents.has(run.run_id)) state.runEvents.set(run.run_id, { events: [], after: null, loaded: false, loading: false });
  const cache = state.runEvents.get(run.run_id);
  const head = el('div', { class: 'run-head' });
  const summary = el('div', { class: 'run-summary' });
  const list = el('ol', { class: 'timeline', attrs: { 'aria-label': 'Run events, newest first' } });
  const tlNote = el('div', { class: 'tl-note' });
  const toggle = el('button', { class: 'toggle run-toggle', type: 'button', attrs: { 'aria-expanded': 'false' } }, icon('chevron'), el('span', null, 'Timeline'));
  const timeline = el('div', { class: 'run-timeline', hidden: true }, tlNote, list);
  // Automated runs in progress open on their live timeline; operator sessions stay compact.
  let expanded = state.runOpen.has(run.run_id) || (run.status === 'active' && run.origin === 'automated' && !state.runClosed.has(run.run_id));

  function drawTimeline() {
    replace(list, [...cache.events].reverse().map(eventRow));
    replace(
      tlNote,
      !cache.loaded
        ? el('span', { class: 'muted small' }, 'Loading events…')
        : cache.error
          ? errorBox(cache.error)
          : !cache.events.length
            ? el('span', { class: 'muted small' }, run.status === 'active' ? 'No events yet. They appear here as the run works.' : 'This run recorded no events.')
            : run.status === 'active'
              ? el('span', { class: 'muted small live-note' }, el('span', { class: 'dot accent pulse' }), 'Live · newest first · refreshes every few seconds')
              : el('span', { class: 'muted small' }, `${plural(cache.events.length, 'event')} · newest first`),
    );
  }

  async function pull() {
    if (cache.loading) return;
    cache.loading = true;
    try {
      for (let page = 0; page < 10; page++) {
        const qs = new URLSearchParams({ limit: '200' });
        if (cache.after !== null && cache.after !== undefined) qs.set('after_seq', String(cache.after));
        const r = await api(`/api/runs/${enc(run.run_id)}/events?${qs}`);
        if (r.available === false) {
          cache.error = { code: r.reason ?? 'unavailable', message: r.message ?? 'run events are not available' };
          break;
        }
        cache.error = null;
        const fresh = (r.events ?? []).filter((e) => cache.after === null || e.event_seq > cache.after);
        cache.events.push(...fresh);
        if (fresh.length) cache.after = fresh.at(-1).event_seq;
        if ((r.events ?? []).length < 200) break;
      }
    } catch (err) {
      cache.error = err;
    } finally {
      cache.loaded = true;
      cache.loading = false;
    }
    if (expanded) drawTimeline();
    drawSummary();
  }

  function setExpanded(open) {
    expanded = open;
    toggle.setAttribute('aria-expanded', String(open));
    timeline.hidden = !open;
    if (open) {
      state.runOpen.add(run.run_id);
      state.runClosed.delete(run.run_id);
      drawTimeline();
      if (!cache.loaded || run.status === 'active') pull();
    } else {
      state.runOpen.delete(run.run_id);
      state.runClosed.add(run.run_id);
    }
    drawSummary();
  }
  toggle.addEventListener('click', () => setExpanded(!expanded));

  function drawHead() {
    const ended = run.ended_at;
    replace(
      head,
      el(
        'div',
        { class: 'row' },
        runStatusBadge(run.status),
        originBadge(run),
        idChip(run.run_id, { title: 'Run' }),
        showIncident && run.incident_id ? el('a', { class: 'mono small', href: `#/investigations/${enc(run.incident_id)}`, title: `Open incident ${run.incident_id}` }, shortId(run.incident_id)) : null,
        el('span', { class: 'spacer' }),
        toggle,
      ),
      el(
        'div',
        { class: 'run-meta' },
        run.origin === 'automated'
          ? el('span', { class: 'mono' }, plain(run.model_id))
          : el('span', null, 'by ', el('span', { class: 'mono' }, plain(run.principal_id))),
        run.origin === 'automated' && run.backend_id ? el('span', null, 'via ', el('span', { class: 'mono' }, run.backend_id)) : null,
        showIncident && run.host_id ? el('span', { class: 'mono' }, run.host_id) : null,
        el('span', null, 'started ', relTime(run.started_at)),
        ended
          ? el('span', null, `ran ${duration(run.started_at, ended)}`)
          : run.status === 'active' && run.expires_at
            ? el('span', null, 'expires ', relTime(run.expires_at, { until: true }))
            : null,
      ),
    );
  }

  function drawSummary() {
    const latest = cache.events.at(-1) ?? run.last_event;
    replace(
      summary,
      runStats(run, cache.events),
      run.outcome?.summary ? el('p', { class: 'run-outcome' }, run.outcome.summary) : null,
      run.outcome?.budget_stop_reason ? el('div', { class: 'small warn-text' }, 'Stopped on budget: ', el('span', { class: 'mono' }, run.outcome.budget_stop_reason)) : null,
      !expanded && run.status === 'active' && latest
        ? el('div', { class: 'run-latest' }, el('span', { class: 'dot accent pulse' }), el('span', { class: 'muted' }, 'Latest'), el('span', { class: 'txt' }, eventSummary(latest)), relTime(latest.created_at))
        : null,
    );
  }

  const node = el('article', { class: ['run', run.origin === 'operator' && 'is-operator'] }, head, summary, timeline);

  function update(next) {
    const wasActive = run.status === 'active';
    run = next;
    node.classList.toggle('is-operator', run.origin === 'operator');
    drawHead();
    drawSummary();
    // One last fetch when a run finishes, so the timeline ends with its final events.
    if (expanded && (run.status === 'active' || wasActive)) pull();
  }

  drawHead();
  drawSummary();
  if (expanded) setExpanded(true);
  return { node, update, get run() { return run; } };
}

/** Keyed list of runItems that keeps expanded timelines across refreshes. */
function runList({ showIncident = false, empty }) {
  const root = el('div', { class: 'run-list' });
  const items = new Map();
  let runs = [];
  return {
    node: root,
    get runs() {
      return runs;
    },
    draw(list) {
      runs = list;
      if (!list.length) {
        items.clear();
        replace(root, empty);
        return;
      }
      const nodes = list.map((r) => {
        let item = items.get(r.run_id);
        if (item) item.update(r);
        else items.set(r.run_id, (item = runItem(r, { showIncident })));
        return item.node;
      });
      for (const id of [...items.keys()]) if (!list.some((r) => r.run_id === id)) items.delete(id);
      replace(root, nodes);
    },
  };
}

/** Active automated runs first, then active operator sessions, then newest first. */
const runRank = (r) => (r.status === 'active' ? (r.origin === 'automated' ? 0 : 1) : 2);
const sortRuns = (list) => [...list].sort((a, b) => runRank(a) - runRank(b) || Date.parse(b.started_at) - Date.parse(a.started_at));

// ----- incident workspace: "Reasoner activity" -----

function queueLines(triggers, health) {
  return triggers
    .filter((t) => t.status !== 'done')
    .sort((a, b) => ['leased', 'pending', 'dead_letter'].indexOf(a.status) - ['leased', 'pending', 'dead_letter'].indexOf(b.status))
    .map((t) => {
      const what = [el('span', { class: 'mono' }, `#${t.event_id}`), t.watch_id ? [' from ', el('span', { class: 'mono' }, t.watch_id)] : null];
      if (t.status === 'leased') {
        return el('div', { class: 'q-line' }, triggerStatusBadge('leased'), el('span', null, el('span', { class: 'mono' }, plain(t.lease_owner)), ' holds trigger ', what, ' · lease ', relTime(t.lease_expires_at, { until: true })));
      }
      if (t.status === 'pending') {
        if (pendingStalled(t, health)) {
          return notice('warn', 'alert', [
            el('strong', null, 'reasoner-d does not appear to be running.'),
            el('span', null, 'Trigger ', what, ' has waited ', relTime(t.created_at).textContent.replace(/ ago$/, ''), ' and no automated run is active. Start reasoner-d on the control host, or start an operator session to work this incident yourself.'),
          ]);
        }
        return el('div', { class: 'q-line' }, triggerStatusBadge('pending'), el('span', null, 'Queued for reasoner-d: trigger ', what, ', queued ', relTime(t.created_at)));
      }
      return el(
        'div',
        { class: 'q-line' },
        triggerStatusBadge(t.status),
        el('span', null, 'Trigger ', what, t.status === 'dead_letter' ? ` gave up after ${plural(t.retry_count ?? 0, 'retry', 'retries')}` : '', t.reason ? [': ', el('span', { class: 'dim' }, t.reason)] : null),
      );
    });
}

function reasonerCard(inc) {
  const R = state.reasoner;
  const body = el('div', { class: 'card-body reasoner-body' });
  const queueSlot = el('div', { class: 'q-lines' });
  const list = runList({
    empty: el(
      'div',
      { class: 'empty-slot' },
      inc.status === 'open'
        ? 'No reasoner-d run has picked up this incident yet. Automated runs start on their own when a watch trigger is leased from the queue; an operator session is your own manual session.'
        : 'No reasoner-d run or operator session was recorded for this incident.',
    ),
  });
  const headBadge = el('span');
  let runs = sortRuns(R.runs.filter((r) => r.incident_id === inc.incident_id));
  let triggers = R.triggers.filter((t) => t.incident_id === inc.incident_id);

  const draw = (unavailable = null) => {
    if (unavailable) {
      replace(body, el('div', { class: 'muted small' }, unavailable));
      replace(headBadge);
      return;
    }
    replace(queueSlot, queueLines(triggers, reasonerHealth()));
    list.draw(runs);
    replace(body, queueSlot, list.node);
    const active = runs.filter((r) => r.status === 'active');
    replace(headBadge, active.length ? el('span', { class: 'badge live' }, el('span', { class: 'dot accent pulse' }), `${active.length} active`) : runs.length ? el('span', { class: 'badge ghost' }, plural(runs.length, 'run')) : null);
  };

  const node = card(
    'Reasoner activity',
    'What reasoner-d and operator sessions did on this incident',
    body,
    [headBadge, el('a', { class: 'btn btn-sm btn-ghost', href: `#/reasoner?incident=${enc(inc.incident_id)}` }, 'Queue', icon('arrow'))],
    'reasoner-card',
  );

  if (R.loaded && !R.available) draw(R.message ?? 'Reasoner activity is not available.');
  else draw();

  const poll = livePoll(
    node,
    async () => {
      const [r, t] = await Promise.all([api(`/api/runs?incident_id=${enc(inc.incident_id)}&limit=50`), api(`/api/triggers?incident_id=${enc(inc.incident_id)}&limit=50`)]);
      if (r.available === false || t.available === false) return draw((r.available === false ? r : t).message ?? 'Reasoner activity is not available.');
      runs = sortRuns(r.runs);
      triggers = t.triggers;
      draw();
    },
    { fast: 3500, slow: 15_000, busy: () => runs.some((r) => r.status === 'active') || triggers.some((x) => x.status === 'pending' || x.status === 'leased') },
  );
  setTimeout(() => poll.run(), 0);
  return node;
}

// ----- fleet-wide view: #/reasoner -----

function triggerRow(t, health) {
  const stuck = pendingStalled(t, health);
  let detail;
  if (t.status === 'leased') detail = [el('span', { class: 'mono' }, plain(t.lease_owner)), el('span', { class: 'muted small' }, 'lease ', relTime(t.lease_expires_at, { until: true }))];
  else if (t.status === 'pending') detail = [el('span', { class: stuck ? 'warn-text' : 'muted' }, stuck ? 'Waiting, no active reasoner run' : 'Waiting for a reasoner-d lease'), el('span', { class: 'muted small' }, 'queued ', relTime(t.created_at))];
  else detail = [el('span', { class: t.status === 'dead_letter' ? 'bad-text' : 'dim' }, t.reason ?? (t.status === 'done' ? 'Completed' : '—')), el('span', { class: 'muted small' }, 'updated ', relTime(t.updated_at))];
  return el(
    'div',
    { class: ['q-row', stuck && 'is-stuck'], attrs: { role: 'listitem' } },
    el('div', { class: 'q-status' }, triggerStatusBadge(t.status)),
    el('div', { class: 'q-what' }, el('span', null, el('span', { class: 'mono' }, `#${t.event_id}`), ' ', el('span', { class: 'mono dim' }, plain(t.watch_id))), el('span', { class: 'muted small' }, 'queued ', relTime(t.created_at), t.retry_count ? ` · ${plural(t.retry_count, 'retry', 'retries')}` : '')),
    el('div', { class: 'q-scope' }, t.incident_id ? el('a', { class: 'mono', href: `#/investigations/${enc(t.incident_id)}`, title: t.incident_id }, shortId(t.incident_id)) : el('span', { class: 'muted' }, '—'), el('span', { class: 'mono muted small' }, plain(t.host_id))),
    el('div', { class: 'q-detail' }, detail),
  );
}

function healthNotice(health) {
  switch (health.state) {
    case 'working': {
      const r = health.active[0];
      return notice('', 'cpu', [
        el('strong', null, 'reasoner-d is working.'),
        r
          ? el('span', null, `${plural(health.active.length, 'active run')}, latest on `, el('a', { class: 'mono', href: `#/investigations/${enc(r.incident_id)}` }, shortId(r.incident_id)), ` · ${plain(r.model_id)}`)
          : el('span', null, `${plural(health.leased.length, 'trigger')} leased`),
      ]);
    }
    case 'stalled':
      return notice('warn', 'alert', [
        el('strong', null, 'reasoner-d does not appear to be running.'),
        el('span', null, `${plural(health.pending.length, 'trigger')} pending, the oldest for `, relTime(health.oldest).textContent.replace(/ ago$/, ''), ', with no active run or lease. Start reasoner-d on the control host; until then incidents wait for an operator.'),
      ]);
    case 'queued':
      return notice('', 'clock', [el('strong', null, 'Triggers queued.'), el('span', null, `${plural(health.pending.length, 'trigger')} waiting for reasoner-d to lease ${health.pending.length === 1 ? 'it' : 'them'}.`)]);
    case 'unavailable':
      return notice('', 'cpu', [el('strong', null, 'Reasoner activity is not available.'), el('span', null, health.message ?? '')]);
    default:
      return notice('', 'check', [
        el('strong', null, 'Queue empty.'),
        health.lastRun ? el('span', null, 'Last automated run ', relTime(health.lastRun.started_at), ' on ', el('a', { class: 'mono', href: `#/investigations/${enc(health.lastRun.incident_id)}` }, shortId(health.lastRun.incident_id))) : el('span', null, 'No automated run has been recorded yet.'),
      ]);
  }
}

async function renderReasoner(_arg, stale, route) {
  const q = route?.query;
  for (const [key, param] of [['incident', 'incident'], ['host', 'host']]) {
    const v = q?.get(param);
    if (v !== null && v !== undefined) state.rq[key] = v;
  }
  await loadReasoner();
  if (stale()) return null;
  const R = state.reasoner;
  if (!R.available) {
    return el(
      'div',
      { class: 'stack' },
      healthNotice(reasonerHealth()),
      card(
        'What this page shows',
        null,
        el('div', { class: 'card-body dim' }, 'Automated reasoner-d runs, their step-by-step events and the trigger queue they lease from. control-d serves these over the investigation socket from Phase 9 on; this console falls back to the audit-log summary on Fleet until then.'),
      ),
    );
  }
  const f = state.rq;
  const health = reasonerHealth();
  const statusSel = QUEUE_FILTERS.find(([id]) => id === f.status) ?? QUEUE_FILTERS[0];

  const kpis = el(
    'div',
    { class: 'kpis' },
    kpi('Active runs', String(health.active.length), health.active.length ? 'reasoner-d is investigating' : 'No automated run in progress'),
    kpi('Pending triggers', String(health.pending.length), health.oldest ? ['oldest ', relTime(health.oldest)] : 'Nothing waiting'),
    kpi('Leased', String(health.leased.length), health.leased[0] ? el('span', { class: 'mono' }, plain(health.leased[0].lease_owner)) : 'No lease held'),
    kpi('Dead-lettered', String(health.dead.length), health.dead.length ? el('span', { class: 'warn-text' }, 'Gave up after retries') : 'None'),
  );

  // Filters shared by the queue and the run list.
  const knownIncidents = [...new Set([...state.incidents.map((i) => i.incident_id), ...R.runs.map((r) => r.incident_id), ...R.triggers.map((t) => t.incident_id)].filter(Boolean))].sort();
  const knownHosts = [...new Set([...state.hosts.map((h) => h.host_id), ...R.runs.map((r) => r.host_id), ...R.triggers.map((t) => t.host_id)].filter(Boolean))].sort();
  const hostSel = el('select', { attrs: { 'aria-label': 'Filter by host' } }, el('option', { value: '' }, 'All hosts'), knownHosts.map((h) => el('option', { value: h, selected: f.host === h }, h)));
  const incSel = el('select', { attrs: { 'aria-label': 'Filter by incident' } }, el('option', { value: '' }, 'All incidents'), knownIncidents.map((i) => el('option', { value: i, selected: f.incident === i }, shortId(i))));
  const setFilter = (k, v) => {
    f[k] = v;
    history.replaceState(null, '', '#/reasoner');
    render();
  };
  hostSel.addEventListener('change', () => setFilter('host', hostSel.value));
  incSel.addEventListener('change', () => setFilter('incident', incSel.value));
  const seg = el(
    'div',
    { class: 'seg q-seg', attrs: { role: 'group', 'aria-label': 'Trigger status' } },
    QUEUE_FILTERS.map(([id, label]) => el('button', { type: 'button', attrs: { 'aria-pressed': String(statusSel[0] === id) }, on: { click: () => setFilter('status', id) } }, label)),
  );
  const toolbar = el('div', { class: 'mit-toolbar' }, seg, el('span', { class: 'spacer' }), hostSel, incSel);

  const scope = () => {
    const qs = new URLSearchParams();
    if (f.host) qs.set('host_id', f.host);
    if (f.incident) qs.set('incident_id', f.incident);
    return qs;
  };
  const queueBody = el('div', { class: 'q-list', attrs: { role: 'list' } });
  let triggers = [];
  const drawQueue = () => {
    const h = reasonerHealth();
    replace(
      queueBody,
      triggers.length
        ? [el('div', { class: 'q-row head', attrs: { 'aria-hidden': 'true' } }, ['Status', 'Trigger · watch', 'Incident · host', 'Lease or outcome'].map((t) => el('div', null, t))), triggers.map((t) => triggerRow(t, h))]
        : el('div', { class: 'card-body' }, emptyState('Nothing here', statusSel[0] === 'open' ? 'No trigger is waiting for or held by reasoner-d in this scope.' : 'No trigger in this state and scope.')),
    );
  };
  const order = { leased: 0, pending: 1, dead_letter: 2, done: 3 };
  const queueCard = card('Trigger queue', 'Watch triggers control-d queued for reasoner-d. A worker leases one, runs an investigation, then marks it done or dead-letters it after repeated failures.', queueBody);

  const runs = runList({ showIncident: true, empty: emptyState('No runs', 'No reasoner-d run or operator session in this scope yet.') });
  const runsCard = card('Runs', 'Newest first. Active runs expand to a live timeline of turns, tool calls and gate results.', el('div', { class: 'card-body' }, runs.node));

  const node = el('div', { class: 'stack reasoner-view' }, el('div', { class: 'health-slot' }, healthNotice(health)), kpis, toolbar, queueCard, runsCard);
  const healthSlot = node.firstChild;

  async function refresh() {
    const qs = scope();
    const tq = new URLSearchParams(qs);
    tq.set('limit', '200');
    if (statusSel[2]) tq.set('status', statusSel[2]);
    const rq = new URLSearchParams(qs);
    rq.set('limit', '50');
    const [t, r] = await Promise.all([api(`/api/triggers?${tq}`), api(`/api/runs?${rq}`), loadReasoner()]);
    triggers = (t.triggers ?? []).sort((a, b) => (order[a.status] ?? 9) - (order[b.status] ?? 9) || Date.parse(b.updated_at) - Date.parse(a.updated_at));
    drawQueue();
    runs.draw(sortRuns(r.runs ?? []));
    replace(healthSlot, healthNotice(reasonerHealth()));
    refreshNavReasoner();
  }
  replace(queueBody, el('div', { class: 'card-body' }, loading(3)));
  runs.draw([]);
  const poll = livePoll(node, refresh, { fast: 4000, slow: 15_000, busy: () => runs.runs.some((x) => x.status === 'active') || triggers.some((x) => x.status === 'leased') });
  setTimeout(() => poll.run(), 0);
  return node;
}

function refreshNavReasoner() {
  const nav = document.getElementById('nav-reasoner');
  if (!nav) return;
  const h = reasonerHealth();
  const n = h.state === 'unavailable' || h.state === 'loading' ? 0 : h.pending.length + h.leased.length;
  nav.textContent = n ? String(n) : '';
  nav.classList.toggle('warn', h.state === 'stalled');
  nav.title = h.state === 'stalled' ? 'Triggers waiting and reasoner-d looks stopped' : 'Triggers pending or leased';
}

// ---------------------------------------------------------------------------
// View: Expectation rules (Phase 10)
// ---------------------------------------------------------------------------

const EFFECTS = {
  allow_optional: { label: 'Allow optional', help: 'Matching sockets may appear, disappear or change without alerting.' },
  ignore_modified: { label: 'Ignore modified', help: 'Changes to matching sockets (PID, inode) are ignored; sockets that appear or disappear still alert.' },
  require_present: { label: 'Require present', help: 'Alerts when no current socket matches, for a service that must stay up.' },
};
const RULE_STATUS = { active: ['ok', 'Active'], proposed: ['warn', 'Pending approval'], rejected: ['bad', 'Rejected'], revoked: ['', 'Revoked'], expired: ['', 'Expired'] };
const COLLECTOR_NOUN = { 'sockets.listening': 'sockets', 'connections.outbound': 'outbound connections', 'packages.inventory': 'packages' };
const RULE_TABS = [
  ['active', 'Active'],
  ['pending', 'Pending'],
  ['history', 'History'],
];
const EXPIRY_CHOICES = [
  ['7', '7 days'],
  ['30', '30 days'],
  ['90', '90 days'],
  ['never', 'No expiry'],
];
/** Which composer row a gate denial belongs to (crates/policy/src/rule_gate.rs). */
const DENIAL_TARGET = {
  'rule-gate/identity-anchor': 'identity',
  'rule-gate/port-bounds': 'local_port',
  'rule-gate/wildcard-bind': 'bind_scope',
  'rule-gate/expired': 'expiry',
  'rule-gate/investigator-expiry': 'expiry',
  'rule-gate/scope': 'scope',
  'rule-gate/shape': 'rationale',
};

async function loadRules() {
  try {
    const r = await api('/api/rules?status=active,proposed&limit=100');
    state.rules = { loaded: true, available: r.available !== false, message: r.message ?? null, source: r.source ?? null, list: r.rules ?? [] };
  } catch (err) {
    state.rules = { loaded: true, available: false, message: err.message, source: null, list: [] };
  }
}

const ruleValueText = (v) => (typeof v === 'string' ? v : String(v));

function clauseText(c) {
  switch (c.op) {
    case 'eq':
      return `${c.field} = ${ruleValueText(c.value)}`;
    case 'in':
      return `${c.field} in ${c.values.map(ruleValueText).join(', ')}`;
    case 'range':
      return `${c.field} ${c.min}–${c.max}`;
    case 'prefix':
      return `${c.field} starts with ${c.value}`;
    default:
      return String(c.field ?? '');
  }
}

/** "Allow optional: sockets on edge-01 where systemd_unit = nginx.service and local_port in 80, 443" */
function ruleSentence(spec) {
  const noun = COLLECTOR_NOUN[spec.scope.collector] ?? spec.scope.collector;
  const watch = spec.scope.watch_id ? ` (${spec.scope.watch_id})` : '';
  return `${EFFECTS[spec.effect]?.label ?? spec.effect}: ${noun} on ${spec.scope.host_id}${watch} where ${spec.matches.map(clauseText).join(' and ')}`;
}

function ruleSentenceNode(spec) {
  const noun = COLLECTOR_NOUN[spec.scope.collector] ?? spec.scope.collector;
  const parts = [];
  spec.matches.forEach((c, i) => {
    if (i) parts.push(' and ');
    parts.push(el('code', { class: 'clause' }, clauseText(c)));
  });
  return el(
    'p',
    { class: 'rule-sentence', title: ruleSentence(spec) },
    el('b', null, `${EFFECTS[spec.effect]?.label ?? spec.effect}:`),
    ` ${noun} on `,
    el('span', { class: 'mono' }, spec.scope.host_id),
    spec.scope.watch_id ? [' (', el('span', { class: 'mono' }, spec.scope.watch_id), ')'] : null,
    parts.length ? [' where ', parts] : ' (no clauses)',
  );
}

/** Fleet glance: active rules and proposals waiting for an operator. */
function rulesGlance() {
  const R = state.rules;
  if (!R.loaded || !R.available) return null;
  const active = R.list.filter((r) => r.status === 'active').length;
  const pending = R.list.filter((r) => r.status === 'proposed').length;
  return el(
    'a',
    { class: 'chip rules-glance', href: pending ? '#/rules?tab=pending' : '#/rules', title: 'Expectation rules: active, and proposals waiting for an operator' },
    icon('rules'),
    `Rules · ${active} active`,
    pending ? el('span', { class: 'badge warn' }, `${pending} pending`) : el('span', { class: 'muted' }, '· 0 pending'),
  );
}

const suppressedCount = (reason) => {
  const m = /\((\d+) suppressed by rules\)/.exec(String(reason ?? ''));
  return m ? Number(m[1]) : 0;
};

function suppressionNote(inc, triggers, ruleSuppression) {
  const href = `#/rules?host=${enc(inc.host_id)}`;
  if (ruleSuppression?.rules.length) {
    const { rules, total } = ruleSuppression;
    return notice('', 'rules', [
      el('strong', null, `Suppressed by ${plural(rules.length, 'rule')} (${plural(total, 'item')} total)`),
      el('ul', null, rules.map((r) => el('li', null,
        el('a', { href, title: r.rule_id }, r.rationale),
        ` (${plural(r.count, 'item')})`,
      ))),
    ]);
  }
  // Older triggers carry the count in the reason.
  const sets = triggers.filter((t) => /^set '/.test(t.reason ?? '')).sort((a, b) => b.event_id - a.event_id);
  const latest = sets[0] ?? null;
  const n = latest ? suppressedCount(latest.reason) : suppressedCount(inc.summary);
  if (!n) return null;
  return notice(
    '',
    'rules',
    [
      el('strong', null, `Expectation rules suppressed ${plural(n, 'item')} in this observation.`),
      el('span', null, latest ? ['control-d filtered ', n === 1 ? 'it' : 'them', ' out of the ', el('span', { class: 'mono' }, latest.watch_id), ` diff before queueing trigger #${latest.event_id}. The comparison below is the console's own, so sockets an active rule covers are marked “Allowed by rule”.`] : "control-d filtered them out of the socket diff before opening or updating this incident. The comparison below is the console's own, so sockets an active rule covers are marked “Allowed by rule”."),
    ],
    el('a', { class: 'btn btn-sm', href: `#/rules?host=${enc(inc.host_id)}` }, 'View rules'),
  );
}

function activeSocketRules(host, watchId) {
  const now = Date.now();
  return state.rules.list.filter(
    (r) =>
      r.status === 'active' &&
      r.spec.effect !== 'require_present' &&
      r.spec.scope.host_id === host &&
      r.spec.scope.collector === 'sockets.listening' &&
      (!r.spec.scope.watch_id || r.spec.scope.watch_id === watchId) &&
      !(r.spec.expires_at && Date.parse(r.spec.expires_at) <= now),
  );
}

/** Same semantics as crates/policy/src/rules.rs item_matches, for display only. */
function socketMatchesRule(spec, item) {
  const eq = (v, sample) => (typeof v === 'number' ? Number.isInteger(sample) && sample === v : sample === v);
  return spec.matches.every((c) => {
    const sample = c.field === 'bind_scope' ? socketBindScope(item.local_addr) : item[c.field];
    if (sample === null || sample === undefined) return false;
    if (c.op === 'eq') return eq(c.value, sample);
    if (c.op === 'in') return c.values.some((v) => eq(v, sample));
    if (c.op === 'range') return Number.isInteger(sample) && sample >= c.min && sample <= c.max;
    if (c.op === 'prefix') return typeof sample === 'string' && sample.startsWith(c.value);
    return false;
  });
}

function decisionBox(d, verdict) {
  return el(
    'div',
    { class: ['decision', d.allowed ? 'ok' : 'bad'], attrs: { role: 'status' } },
    el('div', { class: 'row' }, el('span', { class: 'verdict' }, verdict), el('span', { class: 'spacer' }), d.policy_version != null ? el('span', { class: 'mono muted' }, `policy v${d.policy_version}`) : null),
    el('div', { class: 'rule' }, d.rule_id),
    el('div', { class: 'reason' }, d.reason),
  );
}

function backtestView(b, { title = 'Backtest' } = {}) {
  if (!b) return el('div', { class: 'empty-slot' }, 'No backtest was stored with this proposal.');
  const cell = (k, v, sub) => el('div', { class: 'bt-cell' }, el('div', { class: 'k' }, k), el('div', { class: 'v' }, v), el('div', { class: 's' }, sub));
  const fewer = b.triggered_before - b.triggered_after;
  return el(
    'div',
    { class: 'backtest' },
    el('div', { class: 'bt-head' }, el('span', { class: 'eyebrow' }, title), el('span', { class: 'muted small' }, `${plural(b.observations_scanned, 'recent observation')} scanned`)),
    el(
      'div',
      { class: 'bt-grid' },
      cell('Would trigger', [String(b.triggered_before), el('span', { class: 'muted' }, ' → '), String(b.triggered_after)], fewer > 0 ? `${plural(fewer, 'trigger')} fewer with this rule` : 'No fewer triggers'),
      cell('Items matched', String(b.items_matched), 'distinct socket keys'),
      cell('Matching now', String(b.currently_matching), 'in the newest observation'),
    ),
    b.sample_keys.length
      ? el('div', { class: 'bt-keys' }, el('span', { class: 'muted small' }, 'Sample keys'), b.sample_keys.map((k) => el('code', { class: 'key-chip' }, k)))
      : el('div', { class: 'muted small' }, b.observations_scanned ? 'No item in the scanned observations matches this rule.' : 'No set_diff observation in scope yet; the rule applies from the next observation.'),
    b.items_matched > 3 ? el('div', { class: 'hint warn' }, `Matches ${b.items_matched} distinct sockets. Check that every sample key belongs to this service.`) : null,
  );
}

function ruleDecideForm(r) {
  if (!adminEnabled()) {
    return el('div', { class: 'muted small' }, roleAdmin() ? 'Approving or rejecting needs the admin interface (start the console with --enable-admin).' : 'Observer accounts can review proposals but not approve or reject them.');
  }
  const form = { note: '', actor: operatorName() };
  const out = el('div');
  const note = textInput(form, 'note', { placeholder: 'Note for the audit log (optional)' });
  note.setAttribute('aria-label', `Decision note for ${r.rule_id} (optional)`);
  const approve = el('button', { class: 'btn btn-primary btn-sm', type: 'button' }, icon('check'), 'Approve');
  const reject = el('button', { class: 'btn btn-sm', type: 'button' }, 'Reject');
  const go = async (yes) => {
    approve.disabled = true;
    reject.disabled = true;
    replace(out);
    try {
      const res = await api(`/api/admin/rules/${enc(r.rule_id)}/decide`, { method: 'POST', body: { approve: yes, note: form.note.trim() || null, actor: form.actor } });
      if (!res.allowed) {
        replace(out, decisionBox(res.decision, 'Approval denied by the rule gate'));
        approve.disabled = false;
        reject.disabled = false;
        return;
      }
      rememberOperator(form.actor);
      toast(yes ? 'Rule approved; it applies from the next observation' : 'Proposal rejected', yes ? 'ok' : '');
      await loadRules();
      renderShell();
      render();
    } catch (err) {
      replace(out, errorBox(err));
      approve.disabled = false;
      reject.disabled = false;
    }
  };
  approve.addEventListener('click', () => go(true));
  reject.addEventListener('click', () => go(false));
  return el('div', { class: 'rule-actions' }, el('div', { class: 'rule-decide' }, note, el('div', { class: 'row' }, reject, approve)), identityLine(form, 'actor', 'Decided by'), out);
}

function ruleRevokeForm(r) {
  if (!adminEnabled()) return null;
  const slot = el('div', { class: 'rule-actions' });
  const closed = () => replace(slot, el('div', { class: 'row' }, el('span', { class: 'spacer' }), el('button', { class: 'btn btn-sm', type: 'button', on: { click: open } }, 'Revoke…')));
  function open() {
    const form = { reason: '', actor: operatorName() };
    const out = el('div');
    const reason = textInput(form, 'reason', { placeholder: 'Why this rule no longer applies' });
    reason.setAttribute('aria-label', `Revocation reason for ${r.rule_id}`);
    const btn = el('button', { class: 'btn btn-sm btn-danger', type: 'submit' }, 'Revoke rule');
    const note = el('span', { class: 'form-note' });
    const f = el(
      'form',
      { class: 'form rule-revoke', attrs: { novalidate: true } },
      field('Reason (required, recorded in the audit log)', reason),
      identityLine(form, 'actor', 'Revoked by'),
      el('div', { class: 'form-actions' }, note, el('button', { class: 'btn btn-sm btn-ghost', type: 'button', on: { click: closed } }, 'Cancel'), btn),
      out,
    );
    const recheck = guardSubmit(f, btn, note, () => (form.reason.trim() ? null : 'A reason is required to revoke.'), 'Applies from the next observation');
    f.addEventListener('submit', async (e) => {
      e.preventDefault();
      btn.disabled = true;
      replace(out);
      try {
        await api(`/api/admin/rules/${enc(r.rule_id)}/revoke`, { method: 'POST', body: { reason: form.reason, actor: form.actor } });
        rememberOperator(form.actor);
        toast('Rule revoked', 'ok');
        await loadRules();
        renderShell();
        render();
      } catch (err) {
        replace(out, errorBox(err));
        recheck();
      }
    });
    replace(slot, f);
    reason.focus();
  }
  closed();
  return slot;
}

function ruleCard(r) {
  const spec = r.spec;
  const [cls, label] = RULE_STATUS[r.status] ?? ['', cap(r.status)];
  const investigator = r.origin === 'investigator';
  const meta = (k, v) => el('div', null, el('dt', null, k), el('dd', null, v));
  const noun = COLLECTOR_NOUN[spec.scope.collector] ?? spec.scope.collector;
  const decidedVerb = { active: 'Approved', expired: 'Approved', rejected: 'Rejected', revoked: 'Revoked' }[r.status];
  const showDecision = r.decided_by && decidedVerb && (investigator || r.status !== 'active');
  return el(
    'article',
    { class: ['card', 'rule-card', `is-${r.status}`] },
    el(
      'div',
      { class: 'rule-head' },
      el('span', { class: ['badge', cls] }, label),
      el('span', { class: 'badge ghost', title: EFFECTS[spec.effect]?.help ?? '' }, EFFECTS[spec.effect]?.label ?? spec.effect),
      el('span', { class: 'badge ghost' }, investigator ? 'Investigator proposal' : 'Operator rule'),
      el('span', { class: 'spacer' }),
      el('button', { class: 'id-chip', type: 'button', title: `Copy ${r.rule_id}`, on: { click: (e) => copy(r.rule_id, e.currentTarget) } }, r.rule_id.replace(/^rule-/, '').slice(0, 8)),
    ),
    ruleSentenceNode(spec),
    spec.rationale ? el('p', { class: 'rule-why' }, spec.rationale) : null,
    el(
      'dl',
      { class: 'rule-meta' },
      meta('Scope', [el('a', { class: 'mono', href: `#/baselines/${enc(spec.scope.host_id)}` }, spec.scope.host_id), ' · ', spec.scope.watch_id ? el('span', { class: 'mono' }, spec.scope.watch_id) : `every ${noun} watch`]),
      meta(r.status === 'expired' ? 'Expired' : 'Expires', spec.expires_at ? relTime(spec.expires_at) : 'Never'),
      meta('Hits', String(r.hit_count)),
      meta('Last matched', r.last_matched_at ? relTime(r.last_matched_at) : 'Never'),
    ),
    el(
      'div',
      { class: 'rule-origin' },
      icon(investigator ? 'cpu' : 'user'),
      el(
        'span',
        null,
        investigator ? 'Proposed by ' : 'Created by ',
        el('b', null, r.proposed_by ?? 'unknown'),
        r.run_id ? [' in run ', el('a', { class: 'mono', href: r.incident_id ? `#/reasoner?incident=${enc(r.incident_id)}` : '#/reasoner', title: r.run_id }, shortId(r.run_id))] : null,
        r.incident_id ? [' on ', el('a', { class: 'mono', href: `#/investigations/${enc(r.incident_id)}`, title: r.incident_id }, shortId(r.incident_id))] : null,
        ' · ',
        relTime(r.created_at),
      ),
    ),
    showDecision
      ? el('div', { class: 'rule-origin' }, icon(r.status === 'rejected' || r.status === 'revoked' ? 'close' : 'check'), el('span', null, `${decidedVerb} by `, el('b', null, r.decided_by), ' · ', relTime(r.decided_at), r.decision_note ? [' · ', el('span', { class: 'dim' }, `“${r.decision_note}”`)] : null))
      : null,
    r.status === 'proposed' ? [backtestView(r.backtest, { title: 'Backtest stored with the proposal' }), ruleDecideForm(r)] : null,
    r.status === 'active' ? ruleRevokeForm(r) : null,
  );
}

async function renderRules(_arg, stale, route) {
  const q = route?.query;
  const tabQ = q?.get('tab');
  if (tabQ && RULE_TABS.some(([id]) => id === tabQ)) state.rv.tab = tabQ;
  const hostQ = q?.get('host');
  if (hostQ !== null && hostQ !== undefined) state.rv.host = hostQ;
  const f = state.rv;
  const currentStatuses = 'active,proposed';
  const historyStatuses = 'rejected,revoked,expired';
  const qs = (statuses, before = null) => {
    const p = new URLSearchParams({ status: statuses, limit: '100' });
    if (f.host) p.set('host_id', f.host);
    if (before !== null) p.set('before', before);
    return p;
  };
  const [cur, hist] = await Promise.all([api(`/api/rules?${qs(currentStatuses)}`), api(`/api/rules?${qs(historyStatuses)}`)]);
  if (stale()) return null;
  if (cur.available === false) {
    return el(
      'div',
      { class: 'stack' },
      notice('', 'rules', [el('strong', null, 'Expectation rules are not available.'), el('span', null, cur.message ?? '')]),
      card('What this page shows', null, el('div', { class: 'card-body dim' }, 'Small, typed rules that tell control-d which changes in a socket set are expected, for example a service that opens and closes its listeners on demand. control-d serves them from Phase 10 on.')),
    );
  }
  if (!f.host) {
    state.rules = { loaded: true, available: true, message: null, source: cur.source ?? null, list: cur.rules };
    renderShell();
  }
  const lists = {
    active: cur.rules.filter((r) => r.status === 'active'),
    pending: cur.rules.filter((r) => r.status === 'proposed'),
    history: hist.rules,
  };
  const go = (patch) => {
    Object.assign(f, patch);
    history.replaceState(null, '', '#/rules');
    render();
  };
  const tabs = el(
    'div',
    { class: 'tabs', attrs: { role: 'tablist', 'aria-label': 'Rule status' } },
    RULE_TABS.map(([id, label]) =>
      el('button', { type: 'button', attrs: { role: 'tab', 'aria-selected': String(f.tab === id) }, on: { click: () => go({ tab: id }) } }, label, el('span', { class: ['tab-count', id === 'pending' && lists.pending.length && 'warn-text'] }, String(lists[id].length))),
    ),
  );
  const hosts = [...new Set([...state.hosts.map((h) => h.host_id), ...cur.rules.map((r) => r.spec.scope.host_id), ...hist.rules.map((r) => r.spec.scope.host_id), f.host].filter(Boolean))].sort();
  const hostSel = el('select', { attrs: { 'aria-label': 'Filter rules by host' } }, el('option', { value: '' }, 'All hosts'), hosts.map((h) => el('option', { value: h, selected: f.host === h }, h)));
  hostSel.addEventListener('change', () => go({ host: hostSel.value }));

  const notes = [];
  if (!adminEnabled()) {
    notes.push(
      notice('', 'lock', [
        el('strong', null, 'Read-only.'),
        el('span', null, roleAdmin() ? `Rules are listed through the ${cur.source === 'admin' ? 'admin' : "console's browse"} scope. Creating, approving and revoking rules use control-d's admin interface; start the console with --enable-admin.` : 'Observer accounts can review rules but not create, approve or revoke them.'),
      ]),
    );
  }
  const empty = {
    active: emptyState('No active rules', 'Rules start from an incident: in its What changed card, use “Allow for this service” on an added socket, check the backtest, then create the rule.'),
    pending: emptyState('Nothing waiting for approval', 'reasoner-d may propose a rule for benign, recurring noise. Proposals are inert until an operator approves them here.'),
    history: emptyState('No history yet', 'Rejected, revoked and expired rules stay here for the audit trail.'),
  }[f.tab];
  const tab = f.tab;
  const list = lists[tab];
  const cards = el('div', { class: 'rule-list' }, list.map(ruleCard));
  const emptyCard = el('div', { class: 'card', hidden: list.length > 0 }, el('div', { class: 'card-body' }, empty));
  const errors = el('div');
  let before = (tab === 'history' ? hist : cur).next_before ?? null;
  const more = el('button', { class: 'btn', type: 'button', hidden: before === null }, 'Load more');
  more.addEventListener('click', async () => {
    more.disabled = true;
    replace(errors);
    try {
      const page = await api(`/api/rules?${qs(tab === 'history' ? historyStatuses : currentStatuses, before)}`);
      if (stale()) return;
      if (page.available === false) throw new Error(page.message ?? 'Rules unavailable');
      const shown = new Set(list.map((r) => r.rule_id));
      const added = page.rules.filter((r) => !shown.has(r.rule_id) && (tab === 'history' || r.status === (tab === 'pending' ? 'proposed' : 'active')));
      list.push(...added);
      cards.append(...added.map(ruleCard));
      emptyCard.hidden = list.length > 0;
      tabs.querySelectorAll('.tab-count')[RULE_TABS.findIndex(([id]) => id === tab)].textContent = String(list.length);
      before = page.next_before ?? null;
      more.hidden = before === null;
    } catch (err) {
      if (!stale()) replace(errors, errorBox(err));
    } finally {
      more.disabled = false;
    }
  });
  return el(
    'div',
    { class: 'stack rules-view' },
    notes,
    el('div', { class: 'rules-toolbar' }, tabs, el('span', { class: 'spacer' }), hosts.length > 1 || f.host ? hostSel : null),
    cards,
    emptyCard,
    errors,
    more,
  );
}

// ----- "Allow for this service" composer -----

function socketBindScope(addr) {
  const a = String(addr ?? '').toLowerCase();
  if (/^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(a) || a === '::1' || a === '0:0:0:0:0:0:0:1') return 'loopback';
  if (a === '0.0.0.0' || a === '::' || a === '0:0:0:0:0:0:0:0') return 'any';
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(a) || a.includes(':')) return 'specific';
  return null;
}

const expiryIso = (choice) => (choice === 'never' ? null : new Date(Date.now() + Number(choice) * 86_400_000).toISOString());

function openRuleComposer({ host_id, watch_id, item, incident = null }) {
  const scope = socketBindScope(item.local_addr);
  const d = {
    actor: operatorName(),
    watchOnly: true,
    effect: 'allow_optional',
    expiry: '30',
    expires_at: expiryIso('30'),
    portMode: 'exact',
    rationale: '',
    rationaleEdited: false,
    clauses: [
      item.systemd_unit ? { key: 'systemd_unit', label: 'Unit', value: item.systemd_unit, on: true } : null,
      item.comm ? { key: 'comm', label: 'Process', value: item.comm, on: true } : null,
      Number.isInteger(item.uid) ? { key: 'uid', label: 'UID', value: item.uid, on: true } : null,
      item.protocol ? { key: 'protocol', label: 'Protocol', value: item.protocol, on: true } : null,
      Number.isInteger(item.local_port) ? { key: 'local_port', label: 'Port', value: item.local_port, on: true } : null,
      scope ? { key: 'bind_scope', label: 'Bind scope', value: scope, on: true } : null,
    ].filter(Boolean),
  };
  const service = item.systemd_unit ?? item.comm ?? `uid ${item.uid}`;
  const loopbackPinned = () => d.clauses.some((c) => c.key === 'bind_scope' && c.on && c.value === 'loopback');
  const autoRationale = () =>
    `Expected service socket: ${service} listens on ${item.protocol} ${sockAddr(item)} on ${host_id}${incident ? ` (seen in ${shortId(incident.incident_id)})` : ''}.`;
  d.rationale = autoRationale();
  const spec = () => ({
    scope: { host_id, collector: 'sockets.listening', watch_id: d.watchOnly ? watch_id : null },
    matches: d.clauses
      .filter((c) => c.on)
      .map((c) => (c.key === 'local_port' && d.portMode === 'ephemeral' && loopbackPinned() ? { op: 'range', field: 'local_port', min: 1024, max: 65535 } : { op: 'eq', field: c.key, value: c.value })),
    effect: d.effect,
    rationale: d.rationale,
    expires_at: d.expires_at,
  });

  // Backtest state: re-run (debounced) whenever the candidate spec changes.
  let bt = { key: null, status: 'idle', res: null, err: null };
  let timer = null;
  let seq = 0;
  const specKey = () => JSON.stringify(spec());

  const sentenceSlot = el('div', { class: 'rule-preview' });
  const resultSlot = el('div', { class: 'stack' });
  const denySlots = new Map();
  const denySlot = (key) => {
    const node = el('div', { class: 'clause-deny', hidden: true, attrs: { role: 'alert' } });
    denySlots.set(key, node);
    return node;
  };
  const createBtn = el('button', { class: 'btn btn-primary', type: 'button', disabled: true }, 'Create rule');
  const rerunBtn = el('button', { class: 'btn', type: 'button', on: { click: () => run() } }, icon('refresh'), 'Re-run backtest');
  const footNote = el('span', { class: 'foot-note' });

  function missing() {
    if (!d.clauses.some((c) => c.on)) return 'Keep at least one match clause.';
    if (!d.rationale.trim()) return 'Add a rationale.';
    if (bt.status === 'error') return 'The backtest failed; re-run it.';
    if (bt.key !== specKey() || bt.status !== 'done') return 'Running the backtest…';
    if (!bt.res.allowed) return `Denied by ${bt.res.decision.rule_id}; adjust the rule.`;
    return null;
  }
  function recheck() {
    const m = missing();
    createBtn.disabled = Boolean(m);
    footNote.textContent = m ?? 'Backtest done · control-d decides';
    footNote.classList.toggle('warn-text', Boolean(m) && bt.status !== 'running' && bt.status !== 'pending');
  }

  function markDenial(decision) {
    for (const node of denySlots.values()) {
      node.hidden = true;
      clear(node);
    }
    if (!decision || decision.allowed) return;
    let target = DENIAL_TARGET[decision.rule_id] ?? 'general';
    if (target === 'identity') target = ['systemd_unit', 'comm', 'uid'].find((k) => denySlots.has(k)) ?? 'clauses';
    if (target === 'bind_scope' && !d.clauses.some((c) => c.key === 'bind_scope' && c.on)) target = denySlots.has('bind_scope') ? 'bind_scope' : 'clauses';
    if (target === 'local_port' && !denySlots.has('local_port')) target = 'clauses';
    if (target === 'rationale' && d.rationale.trim() && new TextEncoder().encode(d.rationale).length <= 1024) target = 'clauses';
    const node = denySlots.get(target);
    if (!node) return;
    replace(node, el('span', { class: 'rule-pill bad' }, decision.rule_id), el('span', null, decision.reason));
    node.hidden = false;
  }

  function drawResult() {
    if (bt.status === 'pending' || bt.status === 'running') {
      replace(resultSlot, el('div', { class: 'backtest is-loading' }, el('span', { class: 'eyebrow' }, 'Backtest'), el('div', { class: 'skeleton' }), el('div', { class: 'skeleton' })));
    } else if (bt.status === 'error') {
      replace(resultSlot, errorBox(bt.err));
    } else if (bt.status === 'done' && bt.res.allowed) {
      replace(resultSlot, backtestView(bt.res.backtest, { title: 'Backtest against recent observations' }));
    } else if (bt.status === 'done') {
      replace(resultSlot, decisionBox(bt.res.decision, 'Denied by the rule gate'));
    } else {
      replace(resultSlot, el('div', { class: 'empty-slot' }, 'Keep at least one clause and a rationale to run the backtest.'));
    }
    markDenial(bt.status === 'done' ? bt.res.decision : null);
  }

  async function run() {
    clearTimeout(timer);
    const s = spec();
    const key = JSON.stringify(s);
    const mine = ++seq;
    if (!s.matches.length) {
      bt = { key: null, status: 'idle', res: null, err: null };
      drawResult();
      recheck();
      return;
    }
    bt = { key, status: 'running', res: null, err: null };
    drawResult();
    recheck();
    try {
      const res = await api('/api/admin/rules/backtest', { method: 'POST', body: { rule: s } });
      if (mine !== seq) return;
      bt = { key, status: 'done', res, err: null };
    } catch (err) {
      if (mine !== seq) return;
      bt = { key, status: 'error', res: null, err };
    }
    drawResult();
    recheck();
  }
  function changed({ rerender = false } = {}) {
    if (!d.rationaleEdited) {
      d.rationale = autoRationale();
      rationale.value = d.rationale;
    }
    if (rerender) drawForm();
    replace(sentenceSlot, ruleSentenceNode(spec()));
    clearTimeout(timer);
    bt = { ...bt, status: 'pending' };
    drawResult();
    recheck();
    timer = setTimeout(run, 350);
  }

  const rationale = textArea(d, 'rationale', { rows: 3 });
  rationale.setAttribute('aria-label', 'Rationale');
  rationale.addEventListener('input', () => {
    d.rationaleEdited = Boolean(rationale.value.trim());
    changed();
  });

  const formSlot = el('div', { class: 'stack' });
  function drawForm() {
    denySlots.clear();
    const seg = (label, options, current, onPick) =>
      el(
        'div',
        { class: 'seg', attrs: { role: 'group', 'aria-label': label } },
        options.map(([v, text]) => el('button', { type: 'button', attrs: { 'aria-pressed': String(current === v) }, on: { click: () => onPick(v) } }, text)),
      );
    const clauseRow = (c) => {
      const box = el('input', { type: 'checkbox', checked: c.on, attrs: { 'aria-label': `Match on ${c.key}` } });
      box.addEventListener('change', () => {
        c.on = box.checked;
        changed({ rerender: c.key === 'bind_scope' });
      });
      const portChoice =
        c.key === 'local_port' && c.on && loopbackPinned()
          ? seg('Port match', [['exact', `Only ${c.value}`], ['ephemeral', 'Any 1024–65535']], d.portMode, (v) => {
              d.portMode = v;
              changed({ rerender: true });
            })
          : null;
      const shown = c.key === 'local_port' && d.portMode === 'ephemeral' && loopbackPinned() ? 'local_port 1024–65535' : `${c.key} = ${ruleValueText(c.value)}`;
      return el(
        'div',
        { class: ['clause-row', !c.on && 'is-off'] },
        el('label', { class: 'clause-main' }, box, el('span', { class: 'clause-label' }, c.label), el('code', { class: 'clause' }, shown)),
        portChoice ? el('div', { class: 'clause-extra' }, portChoice, el('span', { class: 'hint' }, 'A loopback-only rule may cover the ephemeral range.')) : null,
        denySlot(c.key),
      );
    };
    replace(
      formSlot,
      el(
        'dl',
        { class: 'kv' },
        el('dt', null, 'Socket'),
        el('dd', { class: 'mono' }, `${item.protocol} ${sockAddr(item)}`),
        el('dt', null, 'Owner'),
        el('dd', null, `${item.comm ?? 'unknown process'}${item.pid ? ` (pid ${item.pid})` : ''} · ${item.systemd_unit ?? 'no unit'} · uid ${item.uid}`),
        el('dt', null, 'Host'),
        el('dd', { class: 'mono' }, host_id),
      ),
      field(
        'Applies to',
        seg('Rule scope', [['watch', 'This watch'], ['all', 'Every socket watch']], d.watchOnly ? 'watch' : 'all', (v) => {
          d.watchOnly = v === 'watch';
          changed({ rerender: true });
        }),
        el('span', { class: 'hint' }, d.watchOnly ? ['Only ', el('span', { class: 'mono' }, watch_id), ' on this host.'] : `Every set_diff sockets.listening watch on ${host_id}, including ones added later.`),
      ),
      denySlot('scope'),
      el(
        'div',
        { class: 'field' },
        el('span', { class: 'lbl' }, 'Match when all of these hold', el('span', { class: 'muted' }, 'untick to widen')),
        el('div', { class: 'clause-list' }, d.clauses.map(clauseRow)),
        denySlot('clauses'),
      ),
      field(
        'Effect',
        seg('Effect', Object.entries(EFFECTS).map(([k, v]) => [k, v.label]), d.effect, (v) => {
          d.effect = v;
          changed({ rerender: true });
        }),
        el('span', { class: 'hint' }, EFFECTS[d.effect].help),
      ),
      field(
        'Expiry',
        seg('Expiry', EXPIRY_CHOICES, d.expiry, (v) => {
          d.expiry = v;
          d.expires_at = expiryIso(v);
          changed({ rerender: true });
        }),
        el('span', { class: 'hint' }, d.expires_at ? `Stops applying ${fmtTime(d.expires_at)}; it then moves to History as expired.` : 'Stays active until an operator revokes it.'),
      ),
      denySlot('expiry'),
      field('Rationale (recorded with the rule)', rationale),
      denySlot('rationale'),
      identityLine(d, 'actor', 'Created by'),
    );
  }

  createBtn.addEventListener('click', async () => {
    if (missing()) return;
    createBtn.disabled = true;
    const s = spec();
    try {
      const res = await api('/api/admin/rules', { method: 'POST', body: { rule: s, actor: d.actor } });
      if (!res.allowed) {
        bt = { key: JSON.stringify(s), status: 'done', res: { allowed: false, decision: res.decision }, err: null };
        drawResult();
        recheck();
        return;
      }
      rememberOperator(d.actor);
      drawer().close();
      toast(`Rule active for ${service} on ${host_id}; it applies from the next observation`, 'ok');
      await loadRules();
      renderShell();
      if (incident) reloadWorkspace(incident.incident_id);
    } catch (err) {
      replace(resultSlot, errorBox(err));
      recheck();
    }
  });

  drawForm();
  replace(sentenceSlot, ruleSentenceNode(spec()));
  openDrawer(
    'Allow for this service',
    'Drafts an expectation rule from this socket. control-d backtests it against recent observations before you create it.',
    [sentenceSlot, formSlot, resultSlot],
    [footNote, el('button', { class: 'btn btn-ghost', type: 'button', on: { click: () => drawer().close() } }, 'Cancel'), rerunBtn, createBtn],
  );
  drawer().addEventListener('close', () => {
    clearTimeout(timer);
    seq += 1;
  }, { once: true });
  run();
}

// ---------------------------------------------------------------------------
// View: Baselines & Telemetry
// ---------------------------------------------------------------------------

const TRI_STATE = {
  in_sync: ['ok', 'In sync'],
  drift: ['warn', 'Drift'],
  collector_error: ['bad', 'Collector error'],
  no_trusted_baseline: ['', 'No trusted baseline'],
  baseline_absent: ['', 'Not yet accepted'],
  stream: ['stream', 'Stream'],
  no_data: ['', 'No data'],
};

/** Snapshot baseline watches that have never been accepted and can be promoted now. */
const initialBaselines = (rows) => rows.filter((r) => r.state !== 'stream' && r.class === 'baseline' && !r.accepted_baseline && r.promotable_observation_id != null);

async function renderBaselines(arg, stale) {
  const b = state.baselines;
  if (arg) b.host = arg;
  if (!b.host || !state.hosts.some((h) => h.host_id === b.host)) b.host = state.hosts[0]?.host_id ?? null;
  if (!b.host) return el('div', { class: 'empty-slot' }, 'No hosts in scope.');
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
  const watchSel = el('select', { attrs: { 'aria-label': 'Watch' } }, el('option', { value: '' }, 'All watches'), watches.watches.map((w) => el('option', { value: w.id, selected: w.id === b.watch }, `${w.id} (${w.class})`)));
  watchSel.addEventListener('change', () => {
    b.watch = watchSel.value;
    render();
  });
  const limitSel = el('select', { attrs: { 'aria-label': 'Rows' } }, [25, 50, 100].map((n) => el('option', { value: String(n), selected: n === b.limit }, `${n} rows`)));
  limitSel.addEventListener('change', () => {
    b.limit = Number(limitSel.value);
    render();
  });

  const tri = base.three_state.filter((r) => !b.watch || r.watch_id === b.watch);
  const initial = initialBaselines(base.three_state);
  const acceptAll =
    adminEnabled() && initial.length >= 2
      ? el('button', { class: 'btn btn-sm', type: 'button', title: 'Promote the current observation of every never-accepted snapshot watch on this host', on: { click: () => openAcceptAllDrawer(host, initial) } }, icon('check'), `Accept all initial baselines (${initial.length})`)
      : null;
  const triCard = card(
    'Three-state baseline',
    'The accepted baseline never advances on its own; promotion is an attributable admin action. Stream watches are append-only and have no baseline.',
    el(
      'div',
      { class: 'tri' },
      el('div', { class: 'tri-row head' }, el('div', null, 'Watch'), el('div', null, 'Accepted baseline'), el('div', null, 'Last observed'), el('div', null, 'Current observed'), el('div', { class: 'tri-state' }, 'State')),
      tri.length ? tri.map((r) => triRow(host, r)) : emptyState('No watches', ''),
    ),
    acceptAll,
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
      el('td', null, w ? classBadge(w.class) : el('span', { class: 'muted' }, 'Retired')),
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
    'QueryObservations via control-d: bounded, classified evidence slices',
    el(
      'div',
      { class: 'card-body flush table-wrap' },
      sortedObs.length
        ? el('table', { class: 'obs-table' }, el('thead', null, el('tr', null, ['', 'ID', 'Observed', 'Watch', 'Class', 'Status', 'State hash', 'Summary'].map((h) => el('th', null, h)))), el('tbody', null, rows))
        : emptyState('No observations', 'Nothing collected for this filter yet.'),
    ),
    el('span', { class: 'muted small' }, `${sortedObs.length} rows`),
  );

  return el(
    'div',
    null,
    el('div', { class: 'toolbar' }, el('div', { class: 'field grow' }, el('span', { class: 'lbl' }, 'Host'), hostChips), field('Watch', watchSel), field('Rows', limitSel)),
    el('div', { class: 'stack' }, triCard, obsCard),
  );
}

function triCell(entry, extra, label) {
  if (!entry) return el('div', { class: 'tri-cell', dataset: { label } }, el('span', { class: 'hash is-null' }, 'none'), el('span', { class: 'meta' }, extra ?? ''));
  return el('div', { class: 'tri-cell', dataset: { label } }, hashChip(entry.state_hash), el('span', { class: 'meta', title: extra ?? '' }, extra));
}

function triRow(host, r) {
  const [cls, label] = TRI_STATE[r.state] ?? ['', r.state];
  const watchCell = el('div', { class: 'tri-cell tri-watch' }, el('div', { class: 'row' }, classBadge(r.class)), el('span', { class: 'wid' }, r.watch_id), el('span', { class: 'meta' }, r.collector_type ?? ''));
  if (r.state === 'stream') {
    const st = r.stream ?? {};
    const latestBad = st.latest_status && !VALID_OBS.has(st.latest_status);
    return el(
      'div',
      { class: 'tri-row is-stream' },
      watchCell,
      el(
        'div',
        { class: 'tri-span stream-line' },
        el('span', null, 'Append-only cursor stream'),
        el('span', null, 'latest ', el('span', { class: 'mono' }, `#${st.latest_observation_id}`), ' · ', relTime(st.latest_observed_at)),
        el('span', null, `${st.latest_event_count} event${st.latest_event_count === 1 ? '' : 's'} in latest batch · ${st.events_in_window} in ${st.batches_in_window} batch${st.batches_in_window === 1 ? '' : 'es'}`),
        st.gap_detected ? el('span', { class: 'badge warn' }, 'Cursor gap') : null,
      ),
      el('div', { class: 'tri-state' }, el('div', { class: 'row' }, el('span', { class: 'badge stream' }, icon('stream'), label), latestBad ? obsStatusBadge(st.latest_status) : null)),
    );
  }
  const promote =
    r.promotable_observation_id != null
      ? el(
          'button',
          {
            class: 'btn btn-sm',
            type: 'button',
            disabled: !adminEnabled(),
            title: adminEnabled() ? `Promote observation ${r.promotable_observation_id} to accepted baseline` : 'Admin interface disabled',
            on: { click: () => openPromoteDrawer(host, r) },
          },
          adminEnabled() ? null : icon('lock'),
          r.accepted_baseline ? 'Promote' : 'Accept',
        )
      : null;
  return el(
    'div',
    { class: 'tri-row' },
    watchCell,
    triCell(r.accepted_baseline, r.accepted_baseline ? `rev ${r.accepted_baseline.revision_id} · ${r.accepted_baseline.approver}${r.accepted_baseline.ticket_ref ? ` · ${r.accepted_baseline.ticket_ref}` : ''}` : r.class === 'ephemeral' ? 'Ephemeral: cannot hold a trusted baseline' : 'Never accepted', 'Accepted baseline'),
    triCell(r.last_observed, r.last_observed ? `#${r.last_observed.observation_id} · ${fmtTime(r.last_observed.observed_at)}` : 'No prior valid sample', 'Last observed'),
    triCell(r.current_observed, r.current_observed ? `#${r.current_observed.observation_id} · ${r.current_observed.status} · ${fmtTime(r.current_observed.observed_at)}` : 'No data', 'Current observed'),
    el('div', { class: 'tri-state' }, el('div', { class: 'row' }, el('span', { class: ['badge', cls] }, label), r.changed_since_last ? el('span', { class: 'badge ghost', title: 'Current observed differs from last observed' }, 'Changed') : null), promote),
  );
}

// ---------------------------------------------------------------------------
// View: Policy Gate & Audit
// ---------------------------------------------------------------------------

async function renderAudit(_arg, stale) {
  if (state.status?.admin_enabled && !roleAdmin()) {
    return el(
      'div',
      { class: 'card' },
      el(
        'div',
        { class: 'locked-panel' },
        icon('lock'),
        el('h2', null, 'Admin role required'),
        el('p', { class: 'muted' }, `Signed in as ${state.auth?.user?.username ?? 'unknown'} (observer). Policy decisions and the audit log are restricted to admin accounts.`),
      ),
    );
  }
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

function openDrawer(title, sub, bodyNodes, footNodes, { wide = false } = {}) {
  const d = drawer();
  d.classList.toggle('drawer-wide', wide);
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

const defaultRationale = (r) => (r.accepted_baseline ? 'Accept observed change' : 'Accept initial observed state');

/**
 * Who the audit entry is attributed to. Signed in: the account name, fixed
 * (the server binds it too). Open console: the name remembered on this
 * browser, shown as text with a "Change" link instead of a required field.
 */
function identityLine(form, key, verb = 'Recorded as') {
  const user = state.auth?.user?.username;
  form[key] = user || form[key] || operatorName();
  if (user) return el('div', { class: 'signed-as' }, icon('user'), verb, ' ', el('b', null, user), el('span', { class: 'muted' }, '· your signed-in account'));
  const slot = el('div', { class: 'signed-as' });
  const showText = () =>
    replace(
      slot,
      icon('user'),
      verb,
      ' ',
      el('b', null, form[key]),
      el('button', { class: 'btn btn-sm btn-ghost', type: 'button', on: { click: showInput } }, 'Change'),
    );
  function showInput() {
    const input = textInput(form, key, { placeholder: 'your operator name' });
    input.setAttribute('aria-label', 'Your operator name');
    replace(slot, field('Your name (recorded in the audit log, remembered on this browser)', input));
    input.focus();
  }
  showText();
  return slot;
}

/** Rationale and change ticket: pre-filled and optional to touch, so they live behind one disclosure. */
function justificationFields(form, { ticket = true } = {}) {
  const preview = el('span', { class: 'muted' });
  const sync = () => (preview.textContent = `“${form.rationale.trim() || '…'}”${form.ticket_ref ? ` · ${form.ticket_ref}` : ''}`);
  const rationale = textInput(form, 'rationale', { onInput: sync });
  const ticketInput = ticket ? textInput(form, 'ticket_ref', { placeholder: 'CHG-4471 (optional)', mono: true, onInput: sync }) : null;
  sync();
  return el(
    'details',
    { class: 'more' },
    el('summary', null, 'Rationale ', preview),
    field('Rationale (recorded in the audit log)', rationale),
    ticket ? field('Change ticket (optional)', ticketInput) : null,
  );
}

function openPromoteDrawer(host, r) {
  const form = { approver: operatorName(), rationale: defaultRationale(r), ticket_ref: '' };
  const errNode = el('div');
  const submit = el('button', { class: 'btn btn-primary', type: 'button' }, r.accepted_baseline ? 'Promote to accepted baseline' : 'Accept as baseline');
  submit.addEventListener('click', async () => {
    submit.disabled = true;
    replace(errNode);
    try {
      const res = await api('/api/admin/baselines/promote', {
        method: 'POST',
        body: { host_id: host, watch_id: r.watch_id, observation_id: r.promotable_observation_id, approver: form.approver, rationale: form.rationale, ticket_ref: form.ticket_ref || null },
      });
      rememberOperator(form.approver);
      drawer().close();
      toast(`Baseline revision ${res.revision_id} accepted for ${res.watch_id}`, 'ok');
      await refreshAll();
    } catch (err) {
      replace(errNode, errorBox(err));
      submit.disabled = false;
    }
  });
  openDrawer(
    r.accepted_baseline ? 'Promote baseline' : 'Accept initial baseline',
    'Creates a new immutable, attributable revision. Earlier revisions are kept.',
    [
      el('dl', { class: 'kv' }, el('dt', null, 'Host'), el('dd', { class: 'mono' }, host), el('dt', null, 'Watch'), el('dd', { class: 'mono' }, r.watch_id), el('dt', null, 'Observation'), el('dd', { class: 'mono' }, `#${r.promotable_observation_id}`)),
      el(
        'div',
        { class: 'diff' },
        el('div', { class: 'col' }, el('span', { class: 'eyebrow' }, r.accepted_baseline ? `Accepted · rev ${r.accepted_baseline.revision_id}` : 'Accepted'), hashChip(r.accepted_baseline?.state_hash)),
        el('span', { class: 'rel-arrow' }, '→'),
        el('div', { class: 'col' }, el('span', { class: 'eyebrow' }, 'New accepted state'), hashChip(r.current_observed?.state_hash)),
      ),
      identityLine(form, 'approver', 'Approved by'),
      justificationFields(form),
      errNode,
    ],
    [el('button', { class: 'btn btn-ghost', type: 'button', on: { click: () => drawer().close() } }, 'Cancel'), submit],
  );
}

function openAcceptAllDrawer(host, rows) {
  const form = { approver: operatorName(), rationale: 'Accept initial observed state', ticket_ref: '' };
  const errNode = el('div');
  const marks = new Map(rows.map((r) => [r.watch_id, el('span', { class: 'badge ghost' }, 'Waiting')]));
  const list = el('ul', { class: 'progress-list' }, rows.map((r) => el('li', null, el('span', { class: 'mono' }, r.watch_id), el('span', { class: 'muted small' }, `#${r.promotable_observation_id}`), marks.get(r.watch_id))));
  const submit = el('button', { class: 'btn btn-primary', type: 'button' }, `Accept ${rows.length} baselines`);
  submit.addEventListener('click', async () => {
    submit.disabled = true;
    replace(errNode);
    let ok = 0;
    for (const r of rows) {
      const mark = marks.get(r.watch_id);
      if (mark.dataset.done) {
        ok += 1;
        continue;
      }
      mark.className = 'badge';
      mark.textContent = 'Promoting…';
      try {
        const res = await api('/api/admin/baselines/promote', {
          method: 'POST',
          body: { host_id: host, watch_id: r.watch_id, observation_id: r.promotable_observation_id, approver: form.approver, rationale: form.rationale, ticket_ref: form.ticket_ref || null },
        });
        mark.className = 'badge ok';
        mark.textContent = `rev ${res.revision_id}`;
        mark.dataset.done = '1';
        ok += 1;
      } catch (err) {
        mark.className = 'badge bad';
        mark.textContent = 'Failed';
        replace(errNode, errorBox(err));
        break;
      }
    }
    if (ok) rememberOperator(form.approver);
    if (ok === rows.length) {
      toast(`${ok} initial baselines accepted on ${host}`, 'ok');
      drawer().close();
      await refreshAll();
    } else {
      submit.disabled = false;
      submit.textContent = 'Retry remaining';
    }
  });
  openDrawer(
    'Accept all initial baselines',
    `Promotes the current observation of ${rows.length} never-accepted snapshot watches on ${host}, one attributable revision each.`,
    [
      list,
      identityLine(form, 'approver', 'Approved by'),
      justificationFields(form),
      errNode,
    ],
    [el('button', { class: 'btn btn-ghost', type: 'button', on: { click: () => drawer().close() } }, 'Cancel'), submit],
  );
}

function openCloseDrawer(inc) {
  const form = { actor: operatorName(), resolution: '' };
  const resolution = textArea(form, 'resolution', { placeholder: 'Outcome, verification performed, follow-ups…', rows: 4 });
  const presets = [
    ['Expected change', 'Expected change confirmed with the host owner; baseline to be promoted.'],
    ['Contained', 'Contained: mitigation applied and verified; no further activity observed.'],
    ['False positive', 'False positive: no malicious activity found after review of the evidence.'],
  ];
  const presetRow = el(
    'div',
    { class: 'row preset-row' },
    el('span', { class: 'muted small' }, 'Start from'),
    presets.map(([label, text]) =>
      el('button', { class: 'chip', type: 'button', on: { click: () => { form.resolution = text; resolution.value = text; resolution.focus(); } } }, label),
    ),
  );
  const errNode = el('div');
  const submit = el('button', { class: 'btn btn-danger', type: 'button' }, 'Close incident');
  submit.addEventListener('click', async () => {
    submit.disabled = true;
    replace(errNode);
    try {
      const res = await api(`/api/admin/incidents/${encodeURIComponent(inc.incident_id)}/close`, { method: 'POST', body: form });
      rememberOperator(form.actor);
      drawer().close();
      toast(`${shortId(res.incident_id)} closed · ${res.retired_ephemeral_watches} ephemeral watch${res.retired_ephemeral_watches === 1 ? '' : 'es'} retired`, 'ok');
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
      el('dl', { class: 'kv' }, el('dt', null, 'Incident'), el('dd', null, idChip(inc.incident_id, { title: 'Incident' })), el('dt', null, 'Host'), el('dd', { class: 'mono' }, inc.host_id)),
      el('p', { class: 'dim' }, inc.summary),
      identityLine(form, 'actor', 'Closed by'),
      field('Resolution', resolution),
      presetRow,
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
// Access gate: sign-in, proxy identity, session loss, user badge
// ---------------------------------------------------------------------------

const PRODUCT = 'Defensive Security Autonomous Mitigation Harness';

function brandMark() {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', '0 0 32 32');
  svg.setAttribute('aria-hidden', 'true');
  svg.setAttribute('class', 'brand-mark');
  for (const d of ['M16 2.5 4.5 7v8.2c0 7.1 4.9 12.6 11.5 14.3 6.6-1.7 11.5-7.2 11.5-14.3V7L16 2.5Z', 'M10.5 16.2 14.4 20l7.1-8']) {
    const p = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    p.setAttribute('d', d);
    p.setAttribute('fill', 'none');
    p.setAttribute('stroke', 'currentColor');
    p.setAttribute('stroke-width', '1.8');
    p.setAttribute('stroke-linecap', 'round');
    p.setAttribute('stroke-linejoin', 'round');
    svg.append(p);
  }
  return svg;
}

/** Replace the dashboard with a focused gate. No telemetry is fetched or kept while it shows. */
function showGate({ kind, message = null }) {
  const shell = document.getElementById('shell');
  shell.hidden = true;
  clear(document.getElementById('view'));
  if (drawer().open) drawer().close();
  clear(drawer());
  state.hosts = [];
  state.incidents = [];
  state.actions = { list: [], denied: null, source: null, admin_sock: null, error: null, loaded: false };
  state.status = null;
  const gate = document.getElementById('gate');
  const head = el('div', { class: 'gate-head' }, brandMark(), el('div', null, el('h1', null, PRODUCT), el('p', { class: 'muted' }, 'Operator console')));
  let body;
  if (kind === 'login') {
    const form = { username: '', password: '' };
    const err = el('div', { class: 'gate-err', attrs: { role: 'alert', 'aria-live': 'assertive' } }, message ?? '');
    const user = el('input', { type: 'text', id: 'gate-user', attrs: { autocomplete: 'username', autocapitalize: 'none', spellcheck: 'false', required: true } });
    const pass = el('input', { type: 'password', id: 'gate-pass', attrs: { autocomplete: 'current-password', required: true } });
    const submit = el('button', { class: 'btn btn-primary gate-submit', type: 'submit' }, 'Sign in');
    user.addEventListener('input', () => (form.username = user.value));
    pass.addEventListener('input', () => (form.password = pass.value));
    const node = el(
      'form',
      { class: 'form', attrs: { novalidate: true } },
      el('div', { class: 'field' }, el('label', { htmlFor: 'gate-user' }, 'Username'), user),
      el('div', { class: 'field' }, el('label', { htmlFor: 'gate-pass' }, 'Password'), pass),
      err,
      submit,
    );
    node.addEventListener('submit', async (e) => {
      e.preventDefault();
      if (!form.username || !form.password) {
        err.textContent = 'Enter your username and password.';
        return;
      }
      submit.disabled = true;
      err.textContent = '';
      try {
        state.auth = await api('/api/auth/login', { method: 'POST', body: { username: form.username, password: form.password } });
        pass.value = '';
        startDashboard();
      } catch (ex) {
        pass.value = '';
        form.password = '';
        err.textContent = ex.status === 429 ? 'Too many failed attempts. Wait a few minutes and try again.' : ex.status === 401 ? 'Invalid username or password.' : `${ex.code}: ${ex.message}`;
        submit.disabled = false;
        pass.focus();
      }
    });
    body = [node, el('p', { class: 'gate-foot' }, icon('lock'), 'Local account · HttpOnly, SameSite=Strict session')];
    replace(gate, el('main', { class: 'gate-card', attrs: { 'aria-labelledby': 'gate-title' } }, head, el('h2', { id: 'gate-title', class: 'gate-title' }, 'Sign in'), body));
    gate.hidden = false;
    user.focus();
    return;
  }
  const title = kind === 'blocked' ? 'Access refused' : 'Identity required';
  const text =
    kind === 'blocked'
      ? message ?? 'This console only accepts requests through its trusted identity proxy.'
      : 'This console takes your identity from the single sign-on proxy in front of it, and none was provided. Sign in through your SSO portal, then retry.';
  body = [
    el('p', { class: 'dim' }, text),
    kind === 'blocked' ? null : el('button', { class: 'btn btn-primary gate-submit', type: 'button', on: { click: () => location.reload() } }, 'Retry'),
  ];
  replace(gate, el('main', { class: 'gate-card' }, head, el('h2', { class: 'gate-title' }, title), body));
  gate.hidden = false;
}

let losing = false;
function sessionLost(err) {
  if (losing || !state.auth || state.auth.auth_mode === 'none') return;
  losing = true;
  setTimeout(() => {
    losing = false;
    state.auth = { ...state.auth, authenticated: false, user: null };
    showGate({ kind: state.auth.auth_mode === 'local' ? 'login' : 'proxy', message: err.code === 'session_revoked' ? 'Your account changed. Sign in again.' : 'Your session ended. Sign in again.' });
  }, 0);
}

async function signOut() {
  try {
    await api('/api/auth/logout', { method: 'POST', body: {} });
  } catch {
    /* the cookie is cleared server-side either way */
  }
  location.reload();
}

function renderUserSlot() {
  const slot = document.getElementById('user-slot');
  const a = state.auth;
  if (!a || a.auth_mode === 'none' || !a.user) return replace(slot);
  replace(
    slot,
    el(
      'span',
      { class: 'user-badge', title: a.auth_mode === 'proxy-header' ? 'Identity asserted by the trusted reverse proxy' : 'Local account' },
      icon('user'),
      el('span', { class: 'mono' }, a.user.username),
      el('span', { class: 'sep' }, '·'),
      el('span', { class: ['role', a.user.role === 'admin' ? 'is-admin' : ''] }, a.user.role),
    ),
    a.auth_mode === 'local' ? el('button', { class: 'btn btn-ghost btn-sm', type: 'button', on: { click: signOut } }, icon('logout'), 'Sign out') : null,
  );
}

// ---------------------------------------------------------------------------
// Mitigations (Phase 8): typed, TTL-bounded action intents
// ---------------------------------------------------------------------------

const VERB_LABEL = { nft_block_ip: 'Block IP', systemd_stop_unit: 'Stop unit', host_isolate: 'Isolate host' };
const ACTION_STATUS = {
  pending_approval: ['warn', 'Pending approval'],
  authorized: ['', 'Authorized'],
  executed: ['ok', 'Executed'],
  dry_run_simulated: ['', 'Dry run'],
  rolled_back: ['', 'Rolled back'],
  rejected: ['bad', 'Rejected'],
  verification_failed: ['bad', 'Verification failed'],
  expired: ['', 'Expired'],
};
const ACTIVE_STATUSES = new Set(['authorized', 'executed', 'dry_run_simulated']);

function verbTarget(v) {
  switch (v?.verb) {
    case 'nft_block_ip':
      return `${v.ip} · ${v.direction}`;
    case 'systemd_stop_unit':
      return v.unit;
    case 'host_isolate':
      return `keep ${v.preserve_mgmt_cidrs.join(', ')}`;
    default:
      return '—';
  }
}

function ttlText(seconds) {
  if (seconds == null) return 'no TTL';
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  return `${Math.floor(seconds / 3600)}h${seconds % 3600 ? ` ${Math.round((seconds % 3600) / 60)}m` : ''}`;
}

/** issued_at + TTL (control-d issues 900 s intents for TTL-less verbs). */
const actionDeadline = (a) => new Date(Date.parse(a.created_at) + (a.verb?.ttl_seconds ?? 900) * 1000).toISOString();
const lapsed = (a) => Date.parse(actionDeadline(a)) <= Date.now();
const isAwaiting = (a) => a.status === 'pending_approval' && !lapsed(a);
const awaitingApproval = () => state.actions.list.filter(isAwaiting);

function actionStatusBadge(status, a = null) {
  if (a && status === 'pending_approval' && lapsed(a)) return el('span', { class: 'badge', title: 'Approval window elapsed' }, 'Approval lapsed');
  const [cls, label] = ACTION_STATUS[status] ?? ['', status];
  return el('span', { class: ['badge', cls], title: status }, el('span', { class: ['dot', cls || (status === 'authorized' ? 'accent' : '')] }), label);
}

function authModeBadge(mode) {
  return mode === 'dual_signed_operator'
    ? el('span', { class: 'badge solid', title: 'Requires control-d signature AND an independent operator Ed25519 approval' }, icon('key'), 'Dual-signed')
    : el('span', { class: 'badge ghost', title: 'Pre-authorised by human-owned, bounded auto-mitigation policy' }, icon('clock'), 'Autonomous · bounded');
}

function scopeLinks(a) {
  return el(
    'div',
    { class: 'act-scope' },
    el('a', { class: 'mono', href: `#/baselines/${encodeURIComponent(a.host_id)}` }, a.host_id),
    el('a', { class: 'mono dim', href: `#/investigations/${encodeURIComponent(a.incident_id)}`, title: a.incident_id }, shortId(a.incident_id)),
  );
}

function windowCell(a) {
  const ttl = el('span', { class: 'num dim' }, `TTL ${ttlText(a.verb?.ttl_seconds ?? null)}`);
  if (a.status === 'pending_approval') {
    return el('div', { class: 'act-window' }, ttl, lapsed(a) ? el('span', { class: 'muted' }, 'window closed') : el('span', { class: 'warn-text' }, relTime(actionDeadline(a), { until: true })));
  }
  if (ACTIVE_STATUSES.has(a.status) && a.verb?.ttl_seconds) {
    return el('div', { class: 'act-window' }, ttl, el('span', null, 'lifts ', relTime(actionDeadline(a))));
  }
  return el('div', { class: 'act-window' }, ttl, el('span', { class: 'muted' }, 'Proposed ', relTime(a.created_at)));
}

function mitigationKpi() {
  const a = state.actions;
  if (a.error) return kpi('Active containment', el('span', { class: 'muted' }, '—'), el('span', null, a.error.code === 'forbidden' ? 'Needs incident scope or the admin interface' : 'Unavailable'));
  const active = a.list.filter((x) => ACTIVE_STATUSES.has(x.status)).length;
  const pending = awaitingApproval().length;
  return kpi(
    'Active containment',
    String(active),
    [
      pending ? el('a', { class: 'warn-text', href: '#/mitigations', on: { click: () => (state.mit = { filter: 'awaiting', host: '', incident: null }) } }, `${pending} awaiting approval`) : el('span', null, 'None awaiting approval'),
      a.denied ? el('span', null, `${a.denied.length} denied by the gate`) : null,
    ],
  );
}

function approvalNotice() {
  const pending = awaitingApproval();
  if (!pending.length) return null;
  return notice(
    'warn',
    'key',
    [
      el('strong', null, `${pending.length} mitigation${pending.length === 1 ? '' : 's'} awaiting dual-signed approval`),
      pending.slice(0, 2).map((a) => el('span', null, `${VERB_LABEL[a.verb.verb] ?? a.verb.verb} `, el('span', { class: 'mono' }, verbTarget(a.verb)), ` on ${a.host_id}`)),
    ],
    el('a', { class: 'btn btn-sm', href: '#/mitigations', on: { click: () => (state.mit = { filter: 'awaiting', host: '', incident: null }) } }, 'Review'),
  );
}

function mitigationGuide() {
  const open = state.incidents.filter((i) => i.status === 'open');
  const step = (n, title, text, foot) => el('div', { class: 'guide-step' }, el('h3', null, el('span', { class: 'n' }, String(n)), title), text, foot);
  return card(
    'How mitigations arrive',
    'Nothing has been proposed in this scope yet. Every proposal, whoever makes it, passes the same deterministic action gate before anything is signed.',
    el(
      'div',
      { class: 'guide' },
      step(
        1,
        'Automatically, from reasoner-d',
        el('p', null, 'When reasoner-d investigates an incident with action proposals enabled (', el('code', null, 'enable_action_proposals'), ' in its run budgets, off by default), it may propose one typed containment step per run: block an IP, stop a unit or isolate a host.'),
        el('div', { class: 'row' }, el('a', { class: 'text-link', href: '#/fleet' }, 'Check automation status on Fleet')),
      ),
      step(
        2,
        'Manually, from an investigation',
        el('p', null, 'Open an incident, start an operator session, then use the ', el('b', null, 'Mitigation'), ' tab. Cite the observed facts that justify it; the gate answers at once with its rule and verdict.'),
        el(
          'div',
          { class: 'row' },
          open.length
            ? el('a', { class: 'btn btn-sm', href: `#/investigations/${encodeURIComponent(sortIncidents(open)[0].incident_id)}` }, `Open incidents (${open.length})`, icon('arrow'))
            : el('span', { class: 'muted small' }, 'No open incidents right now.'),
        ),
      ),
    ),
  );
}

async function renderMitigations(_arg, stale) {
  if (!state.actions.loaded || state.openIntent) await loadActions();
  if (stale()) return null;
  const A = state.actions;
  const m = state.mit;
  if (A.error) {
    const scopeHint =
      A.error.code === 'forbidden'
        ? 'control-d lists actions on the investigation socket only for an incident-scoped capability token. Start the console with --enable-admin --admin-sock for the fleet-wide view.'
        : null;
    return el('div', { class: 'stack' }, errorBox(A.error), scopeHint ? el('p', { class: 'muted' }, scopeHint) : null, mitigationGuide());
  }
  if (state.openIntent) {
    const want = state.openIntent;
    state.openIntent = null;
    const target = A.list.find((x) => x.intent_id === want);
    if (target) setTimeout(() => openActionDrawer(target), 0);
  }

  const inScope = (x) => (!m.host || x.host_id === m.host) && (!m.incident || x.incident_id === m.incident);
  const list = A.list.filter(inScope);
  const denied = (A.denied ?? []).filter(inScope);
  const buckets = {
    awaiting: list.filter(isAwaiting),
    active: list.filter((a) => ACTIVE_STATUSES.has(a.status)),
    closed: list.filter((a) => !isAwaiting(a) && !ACTIVE_STATUSES.has(a.status)),
    denied,
  };
  const tile = (id, label, n, cls, note) =>
    el(
      'button',
      { class: ['mit-tile', cls], type: 'button', attrs: { 'aria-pressed': String(m.filter === id) }, on: { click: () => { m.filter = m.filter === id ? 'all' : id; render(); } } },
      el('span', { class: 'label' }, el('span', { class: ['dot', Number(n) > 0 ? cls : ''] }), label),
      el('span', { class: 'value' }, n),
      el('span', { class: 'note' }, note),
    );
  const stats = el(
    'div',
    { class: 'mit-tiles' },
    tile('awaiting', 'Awaiting approval', String(buckets.awaiting.length), 'warn', 'Operator co-signature needed'),
    tile('active', 'Active containment', String(buckets.active.length), 'ok', 'Authorized or applied, TTL running'),
    tile('closed', 'Closed', String(buckets.closed.length), '', 'Rolled back, expired or failed'),
    tile('denied', 'Denied by the gate', A.denied ? String(buckets.denied.length) : '—', 'bad', A.denied ? 'Never became an intent' : 'Needs the admin interface'),
  );

  const hosts = [...new Set([...A.list, ...(A.denied ?? [])].map((x) => x.host_id))].sort();
  const hostSel = el('select', { attrs: { 'aria-label': 'Filter by host' } }, el('option', { value: '' }, 'All hosts'), hosts.map((h) => el('option', { value: h, selected: m.host === h }, h)));
  hostSel.addEventListener('change', () => {
    m.host = hostSel.value;
    render();
  });
  const toolbar = el(
    'div',
    { class: 'mit-toolbar' },
    el('div', { class: 'row' }, m.filter !== 'all' ? el('button', { class: 'chip', type: 'button', attrs: { 'aria-pressed': 'true' }, on: { click: () => { m.filter = 'all'; render(); } } }, `${cap(m.filter)} ×`) : null, m.incident ? el('button', { class: 'chip', type: 'button', attrs: { 'aria-pressed': 'true' }, title: `Clear incident filter (${m.incident})`, on: { click: () => { m.incident = null; render(); } } }, 'Incident ', el('span', { class: 'mono' }, shortId(m.incident)), ' ×') : null),
    el('span', { class: 'spacer' }),
    el('span', { class: 'muted src' }, A.source === 'admin' ? 'control-d admin · ListActions' : A.source === 'investigate' ? 'investigation socket · scoped ListActions' : 'demo fixtures'),
    hostSel,
  );

  const showIntents = m.filter === 'denied' ? [] : m.filter === 'all' ? list : buckets[m.filter];
  const order = (a) => (isAwaiting(a) ? 0 : ACTIVE_STATUSES.has(a.status) ? 1 : 2);
  const rows = [...showIntents].sort((a, b) => order(a) - order(b) || b.proposal_id - a.proposal_id);
  const intentsCard =
    m.filter === 'denied'
      ? null
      : card(
          'Action intents',
          'Closed verb catalog · every intent signed by control-d · executed only by action-exec-d',
          rows.length ? el('div', { class: 'act-list', attrs: { role: 'list' } }, el('div', { class: 'act-row head', attrs: { 'aria-hidden': 'true' } }, ['Status', 'Action', 'Authorization', 'Host · incident', 'Window', ''].map((t) => el('div', null, t))), rows.map(actionRow)) : el('div', { class: 'card-body' }, emptyState('No intents', m.filter === 'all' ? 'No mitigation has been proposed in this scope.' : 'Nothing in this state.')),
          el('span', { class: 'badge' }, `${rows.length}`),
        );

  const deniedCard =
    m.filter === 'all' || m.filter === 'denied'
      ? card(
          'Denied by the action gate',
          'Protected units and CIDRs, TTL ceilings, rate limits and cooldowns are enforced before any signature exists',
          A.denied === null
            ? el('div', { class: 'card-body muted' }, 'Denied proposals are read from the audit log over the admin interface.')
            : denied.length
              ? el('div', { class: 'act-list' }, denied.map(deniedRow))
              : el('div', { class: 'card-body' }, emptyState('No denials', 'Every proposal in this scope passed the gate.')),
        )
      : null;

  if (!A.list.length && !(A.denied ?? []).length) return el('div', { class: 'mit' }, stats, mitigationGuide());
  return el('div', { class: 'mit' }, stats, toolbar, intentsCard, deniedCard);
}

function rowActivate(node, open) {
  node.addEventListener('click', (e) => {
    if (e.target.closest('a, button, select, input')) return;
    open();
  });
}

function actionRow(a) {
  const open = () => openActionDrawer(a);
  const node = el(
    'div',
    { class: ['act-row', isAwaiting(a) && 'is-awaiting'], attrs: { role: 'listitem' } },
    el('div', null, actionStatusBadge(a.status, a)),
    el(
      'div',
      { class: 'act-what' },
      el('button', { class: 'act-open', type: 'button', on: { click: open } }, el('b', null, VERB_LABEL[a.verb?.verb] ?? a.verb?.verb), ' ', el('span', { class: 'mono' }, verbTarget(a.verb))),
      el('div', { class: 'act-effect' }, a.expected_effect),
    ),
    el('div', { class: 'act-auth' }, authModeBadge(a.auth_mode), a.approver ? el('span', { class: 'muted' }, 'approved by ', el('span', { class: 'mono' }, a.approver)) : null),
    scopeLinks(a),
    windowCell(a),
    el('span', { class: 'act-chev', attrs: { 'aria-hidden': 'true' } }, icon('chevron')),
  );
  rowActivate(node, open);
  return node;
}

function deniedRow(d) {
  const open = () => openDeniedDrawer(d);
  const node = el(
    'div',
    { class: 'act-row is-denied', attrs: { role: 'listitem' } },
    el('div', null, actionStatusBadge('rejected')),
    el(
      'div',
      { class: 'act-what' },
      el('button', { class: 'act-open', type: 'button', on: { click: open } }, el('b', null, VERB_LABEL[d.verb?.verb] ?? d.verb?.verb), ' ', el('span', { class: 'mono' }, verbTarget(d.verb))),
      el('div', { class: 'act-effect' }, d.decision.reason),
    ),
    el('div', { class: 'act-auth' }, rulePill(d.decision)),
    scopeLinks(d),
    el('div', { class: 'act-window' }, el('span', { class: 'mono dim' }, d.actor), el('span', { class: 'muted' }, relTime(d.created_at))),
    el('span', { class: 'act-chev', attrs: { 'aria-hidden': 'true' } }, icon('chevron')),
  );
  rowActivate(node, open);
  return node;
}

// ----- action drawers -----

function section(title, ...children) {
  return el('section', { class: 'dsec' }, el('h3', { class: 'eyebrow' }, title), children);
}

function verbParams(v) {
  const rows = Object.entries(v ?? {}).filter(([k]) => k !== 'verb');
  return el(
    'dl',
    { class: 'kv' },
    el('dt', null, 'verb'),
    el('dd', { class: 'mono' }, v?.verb ?? '—'),
    rows.map(([k, val]) => [
      el('dt', null, k),
      el('dd', { class: 'mono' }, Array.isArray(val) ? val.map((x) => el('span', { class: 'chip-static' }, x)) : val === null ? 'none' : k === 'ttl_seconds' ? `${val} s (${ttlText(val)})` : String(val)),
    ]),
  );
}

function evidenceBadges(ids, incidentId) {
  if (!ids?.length) return el('span', { class: 'muted' }, 'no evidence cited');
  return el(
    'div',
    { class: 'ev-row' },
    ids.map((id) => el('a', { class: 'ev-badge', href: `#/investigations/${encodeURIComponent(incidentId)}`, title: `Open ${incidentId} to inspect observation ${id}`, on: { click: () => drawer().close() } }, `obs ${id}`)),
  );
}

function justification(a) {
  return section(
    'Justification',
    el('dl', { class: 'kv kv-wide' }, el('dt', null, 'expected effect'), el('dd', null, a.expected_effect || '—'), el('dt', null, 'blast radius'), el('dd', null, a.blast_radius || '—'), el('dt', null, 'rollback plan'), el('dd', null, a.rollback_plan || '—')),
  );
}

function openDeniedDrawer(d) {
  openDrawer(
    `${VERB_LABEL[d.verb?.verb] ?? 'Action'} · ${verbTarget(d.verb)}`,
    'Denied by the deterministic action gate. No intent was signed, nothing reached the host.',
    [
      el('div', { class: 'row' }, actionStatusBadge('rejected'), el('a', { class: 'mono', href: `#/baselines/${encodeURIComponent(d.host_id)}` }, d.host_id), el('a', { class: 'mono dim', href: `#/investigations/${encodeURIComponent(d.incident_id)}`, title: d.incident_id }, shortId(d.incident_id))),
      el('div', { class: 'decision bad' }, el('span', { class: 'verdict' }, 'Denied'), el('span', { class: 'rule' }, d.decision.rule_id), el('span', { class: 'reason' }, d.decision.reason), el('span', { class: 'muted' }, `policy v${d.decision.policy_version} · proposed by `, el('span', { class: 'mono' }, d.actor), ' · ', fmtTime(d.created_at))),
      section('Proposed verb', verbParams(d.verb)),
      justification(d),
      section('Evidence', evidenceBadges(d.evidence_observation_ids, d.incident_id)),
    ],
    [el('button', { class: 'btn btn-ghost', type: 'button', on: { click: () => drawer().close() } }, 'Close')],
  );
}

const shq = (v) => (/^[A-Za-z0-9_@%+=:,./~-]+$/.test(v) ? v : `'${String(v).replace(/'/g, `'\\''`)}'`);

function approveCommand(intentId) {
  const f = state.approval;
  const sock = state.actions.admin_sock || '/run/defsec/admin.sock';
  return [
    `admin-cli --admin-sock ${shq(sock)} \\`,
    `  approve-action ${shq(intentId)} \\`,
    `  --approver ${shq(f.approver.trim() || state.auth?.user?.username || '<your-name>')} \\`,
    `  --operator-key-file ${shq(f.keyFile.trim() || '<operator.key>')} \\`,
    `  --operator-key-id ${shq(f.keyId.trim() || '<key-id>')}`,
  ].join('\n');
}

function approvalPanel(a, detail) {
  const f = state.approval;
  if (state.auth?.user?.username) f.approver = state.auth.user.username;
  if (!f.approver) f.approver = operatorName();
  const cmd = el('code', null, approveCommand(a.intent_id));
  const refreshCmd = () => {
    cmd.textContent = approveCommand(a.intent_id);
    store('defsec.keyFile', f.keyFile);
    store('defsec.keyId', f.keyId);
    rememberOperator(f.approver);
  };
  const keyFile = field('Operator key file', textInput(f, 'keyFile', { mono: true, onInput: refreshCmd }));
  keyFile.classList.add('span-2');
  const inputs = el(
    'details',
    { class: 'more' },
    el('summary', null, 'Approver and key settings ', el('span', { class: 'muted' }, `${f.approver} · ${f.keyId}`)),
    el(
      'div',
      { class: 'grid-2' },
      state.auth?.user?.username
        ? field('Approver', el('div', { class: 'signed-as' }, icon('user'), el('b', null, f.approver)))
        : field('Approver', textInput(f, 'approver', { placeholder: 'your name', onInput: refreshCmd })),
      field('Operator key ID', textInput(f, 'keyId', { mono: true, onInput: refreshCmd })),
      keyFile,
    ),
  );
  const parts = [
    el(
      'div',
      { class: 'approve-head' },
      icon('key'),
      el('div', null, el('strong', null, 'Independent operator signature required'), el('div', { class: 'muted' }, 'Approval window ', relTime(detail?.payload?.expires_at ?? actionDeadline(a), { until: true }))),
    ),
    el('p', { class: 'dim' }, 'control-d has already signed this intent. action-exec-d runs it only once an operator Ed25519 key co-signs the exact canonical payload. Sign on your own workstation: private keys never reach this console.'),
    inputs,
    el('div', { class: 'cmd' }, el('div', { class: 'cmd-head' }, icon('terminal'), el('span', null, 'Run locally'), el('span', { class: 'spacer' }), el('button', { class: 'btn btn-sm btn-ghost', type: 'button', on: { click: (e) => copy(cmd.textContent, e.currentTarget) } }, icon('copy'), 'Copy')), el('pre', null, cmd)),
    detail?.signing ? el('div', { class: 'row sign-line' }, el('span', { class: 'muted' }, 'Signs payload sha256'), hashChip(detail.signing.payload_sha256), el('span', { class: 'muted' }, 'under'), el('span', { class: 'mono dim' }, detail.signing.domain)) : null,
  ];

  if (!adminEnabled()) {
    parts.push(el('p', { class: 'muted small' }, state.status?.admin_enabled ? 'Submitting approvals through the console needs an admin account.' : 'Start the console with --enable-admin to submit approvals here, or run the command above.'));
    return el('section', { class: 'approve-box' }, parts);
  }

  const errNode = el('div');
  const done = async (res) => {
    toast(`Intent authorized · co-signed by ${res.authorized_intent?.operator_approval?.signing_key_id ?? 'operator key'}`, 'ok');
    await loadActions();
    renderShell();
    const updated = state.actions.list.find((x) => x.intent_id === a.intent_id) ?? a;
    openActionDrawer(updated);
    if (parseRoute().view === 'mitigations' || parseRoute().view === 'fleet') render();
    if (isDemo()) setTimeout(() => poll(), 4600);
  };

  if (isDemo()) {
    const btn = el('button', { class: 'btn btn-ok', type: 'button' }, icon('check'), 'Approve with demo operator key');
    btn.addEventListener('click', async () => {
      btn.disabled = true;
      replace(errNode);
      try {
        await done(await api(`/api/admin/actions/${encodeURIComponent(a.intent_id)}/approve`, { method: 'POST', body: { approver: f.approver.trim() || state.auth?.user?.username || 'demo-operator', note: f.note || undefined } }));
      } catch (err) {
        replace(errNode, errorBox(err));
        btn.disabled = false;
      }
    });
    parts.push(
      el(
        'div',
        { class: 'demo-approve' },
        el('p', { class: 'muted small' }, 'Demo mode: the console holds a simulated operator key (demo-operator-01) so you can walk through the flow. Approvals still pass the real checks: payload binding, independent key, expiry, open incident, rate limit and the 120 s causal cooldown.'),
        field('Note (optional)', textInput(f, 'note', { placeholder: 'e.g. confirmed with host owner' })),
        el('div', { class: 'form-actions' }, btn),
        errNode,
      ),
    );
    return el('section', { class: 'approve-box' }, parts);
  }

  // Live: accept an envelope that was signed offline.
  const checks = el('ul', { class: 'env-checks' });
  const submit = el('button', { class: 'btn btn-ok', type: 'button', disabled: true }, 'Submit signed approval');
  const area = el('textarea', { class: 'mono-input', rows: 6, placeholder: '{"domain":"defsecautmit.action_approval.v1","signing_key_id":"…","raw_payload":"…","signature_hex":"…"}', value: f.envelope, attrs: { spellcheck: 'false', 'aria-label': 'Offline-signed operator_approval envelope (JSON)' } });
  let parsed = null;
  const validate = () => {
    f.envelope = area.value;
    parsed = null;
    const items = [];
    const ok = (cond, text) => items.push(el('li', { class: cond ? 'ok' : 'bad' }, icon(cond ? 'check' : 'close'), text));
    if (area.value.trim()) {
      try {
        const v = JSON.parse(area.value);
        const keys = v && typeof v === 'object' && !Array.isArray(v) ? Object.keys(v).sort().join(',') : '';
        ok(keys === 'domain,raw_payload,signature_hex,signing_key_id', 'exact SignedEnvelope fields');
        ok(v?.domain === 'defsecautmit.action_approval.v1', 'approval signature domain');
        ok(/^[0-9a-f]{128}$/i.test(v?.signature_hex ?? ''), '64-byte Ed25519 signature');
        if (detail?.signing) ok(v?.raw_payload === detail.signing.canonical_payload, 'signs this exact intent payload');
        if (items.every((n) => n.classList.contains('ok'))) parsed = v;
      } catch {
        ok(false, 'valid JSON');
      }
    }
    replace(checks, items);
    submit.disabled = !parsed;
  };
  area.addEventListener('input', validate);
  validate();
  submit.addEventListener('click', async () => {
    submit.disabled = true;
    replace(errNode);
    try {
      await done(await api(`/api/admin/actions/${encodeURIComponent(a.intent_id)}/approve`, { method: 'POST', body: { approver: f.approver.trim() || state.auth?.user?.username || '', operator_approval: parsed } }));
      f.envelope = '';
    } catch (err) {
      replace(errNode, errorBox(err));
      submit.disabled = false;
    }
  });
  const copyPayload = detail?.signing
    ? el('button', { class: 'btn btn-sm btn-ghost', type: 'button', title: 'RFC 8785 canonical payload, for signing with other offline tooling', on: { click: (e) => copy(detail.signing.canonical_payload, e.currentTarget) } }, icon('copy'), 'Copy canonical payload')
    : null;
  parts.push(
    el(
      'details',
      { class: 'env-submit' },
      el('summary', null, 'Or submit an envelope you already signed offline'),
      el('p', { class: 'muted small' }, 'Paste the operator_approval SignedEnvelope. control-d verifies the signature against its trusted operator keys and rejects keys that match the control key.'),
      area,
      checks,
      el('div', { class: 'form-actions' }, copyPayload, el('span', { class: 'spacer' }), submit),
      errNode,
    ),
  );
  return el('section', { class: 'approve-box' }, parts);
}

function receiptsView(receipts) {
  if (!receipts?.length) return el('span', { class: 'muted' }, 'No receipts from action-exec-d yet.');
  return el(
    'ol',
    { class: 'receipts' },
    receipts.map((r) =>
      el(
        'li',
        null,
        el('div', { class: 'row' }, actionStatusBadge(r.status), r.dry_run ? el('span', { class: 'badge eph' }, 'dry run') : null, el('span', { class: ['badge', r.verification_passed ? 'ok' : 'warn'] }, r.verification_passed ? 'verified' : 'not verified'), el('span', { class: 'spacer' }), el('span', { class: 'num muted', title: r.executed_at }, fmtTime(r.executed_at))),
        el('div', { class: 'r-detail' }, r.detail),
        el('dl', { class: 'kv' }, r.rollback_handle ? [el('dt', null, 'rollback handle'), el('dd', { class: 'mono' }, r.rollback_handle)] : null, r.expires_at ? [el('dt', null, 'expires'), el('dd', { class: 'num' }, fmtTime(r.expires_at))] : null),
      ),
    ),
  );
}

function signaturesView(detail) {
  const ai = detail.authorized_intent;
  const p = detail.payload;
  const sig = (env, label) =>
    env
      ? [el('dt', null, label), el('dd', null, el('span', { class: 'mono' }, env.signing_key_id), ' ', hashChip(env.signature_hex, { label: `${env.signature_hex.slice(0, 12)}…` }))]
      : [el('dt', null, label), el('dd', { class: 'muted' }, p.auth_mode === 'dual_signed_operator' ? 'not yet co-signed' : 'not required (bounded autonomous)')];
  return el(
    'dl',
    { class: 'kv' },
    el('dt', null, 'intent_id'),
    el('dd', null, hashChip(p.intent_id, { full: true })),
    el('dt', null, 'nonce'),
    el('dd', { class: 'mono' }, p.nonce),
    el('dt', null, 'issued → expires'),
    el('dd', { class: 'num' }, `${fmtTime(p.issued_at)} → ${fmtTime(p.expires_at)}`),
    el('dt', null, 'policy'),
    el('dd', { class: 'mono' }, `v${p.policy_version} · schema v${p.schema_version} · proposal #${p.proposal_id}`),
    el('dt', null, 'payload sha256'),
    el('dd', null, hashChip(detail.signing.payload_sha256)),
    ai ? sig(ai.control_envelope, 'control-d') : [el('dt', null, 'control-d'), el('dd', { class: 'muted' }, detail.status === 'pending_approval' ? 'signed; envelope released after approval' : 'envelope not released (inactive intent)')],
    sig(ai?.operator_approval ?? null, 'operator'),
  );
}

function openActionDrawer(a) {
  const detailSlot = el('div', { class: 'stack' }, adminEnabled() ? loading(4) : el('p', { class: 'muted small' }, 'The signed intent, receipts and signatures are read over the admin interface.'));
  const approveSlot = el('div');
  const statusSlot = el('span', { class: 'status-slot' }, actionStatusBadge(a.status, a));
  if (a.status === 'pending_approval' && !lapsed(a)) replace(approveSlot, approvalPanel(a, null));
  openDrawer(
    `${VERB_LABEL[a.verb?.verb] ?? 'Action'} · ${verbTarget(a.verb)}`,
    a.auth_mode === 'dual_signed_operator' ? 'Dual-signed intent: control-d plus an independent operator key' : 'Bounded autonomous intent pre-authorised by human-owned policy',
    [
      el('div', { class: 'row' }, statusSlot, authModeBadge(a.auth_mode), a.approver ? el('span', { class: 'muted small' }, 'approved by ', el('span', { class: 'mono' }, a.approver)) : null, el('span', { class: 'spacer' }), el('a', { class: 'mono', href: `#/baselines/${encodeURIComponent(a.host_id)}`, on: { click: () => drawer().close() } }, a.host_id), el('a', { class: 'mono dim', href: `#/investigations/${encodeURIComponent(a.incident_id)}`, title: a.incident_id, on: { click: () => drawer().close() } }, shortId(a.incident_id))),
      approveSlot,
      section('Typed parameters', verbParams(a.verb)),
      justification(a),
      detailSlot,
    ],
    [el('button', { class: 'btn btn-ghost', type: 'button', on: { click: () => drawer().close() } }, 'Close')],
  );
  if (!adminEnabled() || !a.intent_id) return;
  const want = a.intent_id;
  api(`/api/admin/actions/${encodeURIComponent(a.intent_id)}`)
    .then((d) => {
      if (!drawer().open || !detailSlot.isConnected || want !== a.intent_id) return;
      replace(statusSlot, actionStatusBadge(d.status, { ...a, status: d.status }));
      if (d.status === 'pending_approval' && !lapsed(a)) replace(approveSlot, approvalPanel(a, d));
      else if (d.status !== 'pending_approval') replace(approveSlot);
      const receiptsSlot = el('div', null, receiptsView(d.receipts));
      // Verification polls re-read the detail; keep the receipt list and status in step with it.
      const onDetail = (nd) => {
        if (!receiptsSlot.isConnected) return;
        replace(receiptsSlot, receiptsView(nd.receipts));
        replace(statusSlot, actionStatusBadge(nd.status, { ...a, status: nd.status }));
      };
      replace(
        detailSlot,
        section('Evidence', evidenceBadges(d.payload.evidence_observation_ids, d.payload.incident_id)),
        section('Execution receipts', receiptsSlot),
        verificationSection(a, onDetail),
        section('Signed intent', signaturesView(d)),
        el('details', { class: 'preview' }, el('summary', null, 'Canonical payload (RFC 8785)'), jsonBlock(d.payload)),
      );
    })
    .catch((err) => replace(detailSlot, errorBox(err)));
}

// ---------------------------------------------------------------------------
// Adaptive investigator (P11–P18): host deep-dive, follow-ups, verification
// ---------------------------------------------------------------------------

const COLLECTOR_NAME = {
  'sockets.listening': 'Listening sockets',
  'systemd.unit_state': 'Unit state',
  'files.metadata': 'File metadata',
  'journal.unit_events': 'Journal events',
  'connections.outbound': 'Outbound connections',
  'packages.inventory': 'Package inventory',
};
const collectorName = (c) => COLLECTOR_NAME[c] ?? String(c ?? 'unknown collector');
const words = (v) => String(v ?? '').replace(/_/g, ' ');

const COVERAGE_STATE = {
  covered: ['ok', 'Covered'],
  sampled: ['solid', 'Sampled, not watched'],
  partial: ['warn', 'Partial attribution'],
  error: ['bad', 'Collector error'],
  awaiting_sample: ['warn', 'Awaiting first sample'],
  idle: ['ghost', 'Not watched'],
  disabled: ['ghost', 'Disabled by profile'],
  unavailable: ['ghost', 'Not advertised'],
};
const GAP_TEXT = {
  awaiting_agent: 'Waiting for the agent (offline or not yet connected)',
  agent_unsupported: 'The agent predates host discovery',
  collector_disabled: 'Disabled by the host profile',
  awaiting_capacity: 'Waiting for watch capacity on this host',
  awaiting_sample: 'Sample requested, not yet received',
  sample_window_elapsed: 'Sample window elapsed without data',
  deadline_elapsed: 'Discovery deadline elapsed',
  incomplete_sample: 'The sample was partial or failed',
};
const INTERP = { supports: ['ok', 'Supports'], contradicts: ['bad', 'Contradicts'], unresolved: ['warn', 'Unresolved'] };
const FOLLOWUP_STATUS = {
  awaiting_evidence: ['warn', 'Awaiting fresh evidence'],
  ready: ['accent', 'Evidence ready'],
  leased: ['accent', 'Being interpreted'],
  answered: ['ok', 'Answered'],
  expired: ['ghost', 'Expired unanswered'],
  cancelled: ['ghost', 'Cancelled'],
  exhausted: ['bad', 'Attempts exhausted'],
  policy_changed: ['warn', 'Policy changed'],
};
const CHECK_RESULT = {
  verified: ['ok', 'Verified'],
  contradicted: ['bad', 'Contradicted'],
  awaiting_evidence: ['accent', 'Awaiting evidence'],
  indeterminate: ['warn', 'Indeterminate'],
  no_receipt: ['ghost', 'No receipt recorded yet'],
};
const ATTEMPT_STATUS = { saved: ['ok', 'Saved'], failed: ['bad', 'Failed'], leased: ['accent', 'In progress'], cancelled: ['ghost', 'Cancelled'] };
const FRESHNESS = {
  current: ['ok', 'Current'],
  assessment_advanced: ['warn', 'Assessment changed'],
  overdue: ['warn', 'Overdue'],
  awaiting_first_review: ['accent', 'Awaiting first review'],
  never_reviewed: ['ghost', 'Never reviewed'],
};
const BASELINE_STATE = { trusted: ['ok', 'Trusted'], corroborated: ['accent', 'Corroborated'], provisional: ['warn', 'Provisional'], rolled_back: ['ghost', 'Rolled back'], none: ['ghost', 'No baseline'] };

function stateBadge(map, key, fallback = null) {
  const [cls, label] = map[key] ?? ['ghost', fallback ?? cap(words(key)) ?? '—'];
  return el('span', { class: ['badge', cls] }, label);
}
const interpBadge = (i) => stateBadge(INTERP, i, i ? cap(words(i)) : 'Not answered');
const obsTag = (id, title = null) => (id == null ? el('span', { class: 'muted' }, '—') : el('span', { class: 'ev-badge static', title: title ?? `Observation ${id}` }, `obs ${id}`));
const chipList = (list, empty) => (list?.length ? el('div', { class: 'chip-row' }, list.map((x) => el('span', { class: 'chip-static' }, x))) : el('span', { class: 'muted' }, empty));
const subhead = (title, ...extra) => el('div', { class: 'subhead' }, el('h3', null, title), extra.length ? el('div', { class: 'row' }, extra) : null);

/** Modal confirmation stacked above the drawer; resolves true only on an explicit confirm. */
function confirmDialog({ title, body, confirm = 'Confirm', danger = false }) {
  return new Promise((resolve) => {
    const dlg = el('dialog', { class: 'confirm', attrs: { 'aria-labelledby': 'confirm-title' } });
    const done = (value) => {
      if (dlg.open) dlg.close();
      dlg.remove();
      resolve(value);
    };
    const ok = el('button', { class: ['btn', danger ? 'btn-danger' : 'btn-primary'], type: 'button', on: { click: () => done(true) } }, confirm);
    append(
      dlg,
      el(
        'div',
        { class: 'confirm-inner' },
        el('h2', { id: 'confirm-title' }, title),
        el('div', { class: 'confirm-body' }, body),
        el('div', { class: 'confirm-foot' }, el('button', { class: 'btn btn-ghost', type: 'button', on: { click: () => done(false) } }, 'Cancel'), ok),
      ),
    );
    dlg.addEventListener('cancel', (e) => {
      e.preventDefault();
      done(false);
    });
    dlg.addEventListener('click', (e) => {
      if (e.target === dlg) done(false);
    });
    document.body.append(dlg);
    dlg.showModal();
    ok.focus();
  });
}

/**
 * POST behind a confirmation; returns the response, or null when cancelled or
 * failed (the error lands in errNode). `body` may be a function so fields typed
 * into the dialog itself are read after it closes.
 */
async function confirmedPost(btn, errNode, path, body, dialog) {
  if (!(await confirmDialog(dialog))) return null;
  btn.disabled = true;
  replace(errNode);
  try {
    return await api(path, { method: 'POST', body: typeof body === 'function' ? body() : body });
  } catch (err) {
    replace(errNode, errorBox(err));
    return null;
  } finally {
    btn.disabled = false;
  }
}

function unavailableNotice(r, what) {
  if (r?.error) return errorBox(r.error);
  if (r?.reason === 'admin_disabled') return notice('', 'lock', [el('strong', null, `${what} not visible.`), el('span', null, r.message ?? 'This view needs the admin interface (--enable-admin).')]);
  if (r?.reason === 'forbidden') return notice('', 'lock', [el('strong', null, `${what} not visible to this console token.`), el('span', null, r.message ?? '')]);
  return notice('', 'alert', [el('strong', null, `${what} not available.`), el('span', null, `This control-d ${r?.message ?? 'predates the adaptive investigator contract'}.`)]);
}

function hostTags(h) {
  const p = h.host_profile;
  if (!p) return null;
  return el(
    'div',
    { class: 'host-tags' },
    p.host_tags.map((t) => el('span', { class: 'chip-static' }, t)),
    p.expected_services.length ? null : el('span', { class: 'badge ghost', title: 'The admin profile names no expected services: discovery infers the role' }, 'No declared role'),
  );
}

// ----- host deep-dive -----

const HOST_TABS = [
  ['profile', 'Profile & coverage'],
  ['discovery', 'Discovery'],
  ['monitoring', 'Monitoring'],
  ['review', 'Reviews'],
];
const HOST_SOURCES = {
  profile: (h) => `/api/hosts/${enc(h)}/profile`,
  discovery: (h, v) => `/api/hosts/${enc(h)}/discovery${v ? `?version=${enc(v)}` : ''}`,
  monitoring: (h) => `/api/hosts/${enc(h)}/monitoring`,
  review: (h) => `/api/hosts/${enc(h)}/review`,
};

function openHostDrawer(hostId, tab = state.hostTab) {
  const h = state.hosts.find((x) => x.host_id === hostId) ?? { host_id: hostId, liveness_status: 'unknown', agent_version: '—' };
  const dive = { host: hostId, data: {}, version: null, tab: HOST_TABS.some(([t]) => t === tab) ? tab : 'profile' };
  const summarySlot = el('div', { class: 'dive-summary' }, Array.from({ length: 4 }, () => el('div', { class: 'skeleton' })));
  const panelSlot = el('div', { class: 'dive-panel', attrs: { role: 'tabpanel' } }, loading(4));
  const buttons = HOST_TABS.map(([id, label]) =>
    el('button', { type: 'button', id: `hosttab-${id}`, attrs: { role: 'tab', 'aria-selected': String(dive.tab === id), 'aria-controls': 'host-tabpanel' }, on: { click: () => select(id) } }, label),
  );
  panelSlot.id = 'host-tabpanel';
  const live = () => drawer().open && panelSlot.isConnected;

  function draw() {
    if (!live()) return;
    replace(summarySlot, diveSummary(dive));
    const d = dive.data[dive.tab];
    if (!d) return replace(panelSlot, loading(4));
    const build = { profile: profilePanel, discovery: discoveryPanel, monitoring: monitoringPanel, review: reviewPanel }[dive.tab];
    replace(panelSlot, build(d, dive, reload));
    panelSlot.setAttribute('aria-labelledby', `hosttab-${dive.tab}`);
  }
  function select(id) {
    dive.tab = id;
    state.hostTab = id;
    for (const b of buttons) b.setAttribute('aria-selected', String(b.id === `hosttab-${id}`));
    draw();
  }
  async function reload(...keys) {
    await Promise.all(
      keys.map(async (k) => {
        try {
          dive.data[k] = await api(HOST_SOURCES[k](hostId, k === 'discovery' ? dive.version : null));
        } catch (error) {
          dive.data[k] = { error };
        }
      }),
    );
    draw();
  }
  dive.reload = reload;

  openDrawer(
    hostId,
    [livenessBadge(h.liveness_status), ' ', el('span', { class: 'mono' }, h.agent_version), ' · what this host appears to do, what we can see, and who may change its monitoring'],
    [summarySlot, el('div', { class: 'tabs', attrs: { role: 'tablist', 'aria-label': 'Host deep-dive sections' } }, buttons), panelSlot],
    [
      el('a', { class: 'btn btn-ghost', href: `#/baselines/${enc(hostId)}`, on: { click: () => drawer().close() } }, 'Baselines & telemetry'),
      el('button', { class: 'btn', type: 'button', on: { click: () => drawer().close() } }, 'Close'),
    ],
    { wide: true },
  );
  drawer().addEventListener(
    'close',
    () => {
      if (parseRoute().view === 'fleet' && parseRoute().query.get('host')) history.replaceState(null, '', '#/fleet');
    },
    { once: true },
  );
  reload('profile', 'discovery', 'monitoring', 'review');
}

function diveSummary(dive) {
  const d = dive.data;
  const cell = (k, v, s) => el('div', { class: 'dive-cell' }, el('div', { class: 'k' }, k), el('div', { class: 'v' }, v), s ? el('div', { class: 's' }, s) : null);
  const disc = d.discovery;
  const latestA = disc?.available ? disc : null;
  const interp = latestA?.assessment?.interpretations?.at(-1)?.proposal ?? null;
  const role = interp ? cell('Inferred role', el('span', { class: 'clamp-2', title: interp.purpose }, interp.purpose), `assessment v${latestA.assessment.version}`) : cell('Inferred role', el('span', { class: 'muted' }, disc && !disc.available ? 'Not available' : 'Not inferred yet'), latestA?.latest_version ? `assessment v${latestA.latest_version}` : null);
  const cov = d.profile?.coverage ?? [];
  const covered = cov.filter((c) => ['covered', 'partial'].includes(c.state)).length;
  const gaps = (latestA?.assessment?.collectors ?? []).filter((c) => c.gap).length + cov.filter((c) => ['partial', 'error', 'awaiting_sample'].includes(c.state)).length;
  const coverage = !d.profile ? cell('Coverage', el('span', { class: 'muted' }, '…')) : d.profile.error ? cell('Coverage', el('span', { class: 'muted' }, 'Unavailable')) : cell('Coverage', `${covered} of ${cov.length || 6} collectors`, gaps ? el('span', { class: 'warn-text' }, plural(gaps, 'visibility gap')) : 'no open gaps');
  const m = d.monitoring;
  const monitoring = !m
    ? cell('Monitoring', el('span', { class: 'muted' }, '…'))
    : !m.available
      ? cell('Monitoring', el('span', { class: 'muted' }, 'Needs admin view'))
      : cell('Monitoring', plural(m.watches.length, 'managed watch', 'managed watches'), m.grants.filter((g) => !g.revoked).length ? `${plural(m.grants.filter((g) => !g.revoked).length, 'grant')} · ${m.candidates.filter((c) => c.state === 'provisional').length} awaiting corroboration` : 'no delegation grant');
  const r = d.review;
  const review = !r
    ? cell('Last review', el('span', { class: 'muted' }, '…'))
    : !r.available
      ? cell('Last review', el('span', { class: 'muted' }, 'Needs admin view'))
      : r.review
        ? cell('Last review', interpBadge(r.review.interpretation), [relTime(r.review.completed_at), ' · ', stateBadge(FRESHNESS, r.freshness?.state)])
        : cell('Last review', el('span', { class: 'muted' }, 'None yet'), r.schedule ? 'scheduled' : 'no schedule');
  return [role, coverage, monitoring, review];
}

// P11 -----------------------------------------------------------------------

function profilePanel(p) {
  if (p.error || p.available === false) return unavailableNotice(p, 'Host profile');
  const prof = p.host_profile;
  const profileBlock = prof
    ? el(
        'dl',
        { class: 'kv kv-wide' },
        el('dt', null, 'Host tags'),
        el('dd', null, chipList(prof.host_tags, 'none')),
        el('dt', null, 'Expected services'),
        el('dd', null, prof.expected_services.length ? chipList(prof.expected_services) : el('span', null, 'None declared. ', el('span', { class: 'muted' }, 'A quiet host: discovery infers its role from evidence.'))),
        el('dt', null, 'Enabled collectors'),
        el('dd', null, `${prof.enabled_collectors.length} of ${ALL_COLLECTORS.length}`),
      )
    : notice('warn', 'alert', [el('strong', null, 'No host profile reported.'), el('span', null, 'This agent registered without a profile (it predates P11), so which collectors it supports is unknown.')]);
  const rows = p.coverage.map((c) =>
    el(
      'tr',
      null,
      el('td', null, el('div', { class: 'cov-name' }, collectorName(c.collector)), el('div', { class: 'mono muted small' }, c.collector)),
      el('td', null, c.profile === 'unknown' ? el('span', { class: 'muted' }, 'unknown') : c.profile === 'enabled' ? 'enabled' : el('span', { class: 'muted' }, 'disabled')),
      el('td', null, stateBadge(COVERAGE_STATE, c.state)),
      el('td', { class: 'num' }, String(c.watches)),
      el(
        'td',
        null,
        c.latest_observed_at ? [relTime(c.latest_observed_at), ' ', obsTag(c.latest_observation_id)] : el('span', { class: 'muted' }, 'none'),
        c.partial_attribution ? el('div', { class: 'warn-text small' }, 'some entries have no owning process') : null,
        c.truncated ? el('div', { class: 'muted small' }, 'agent cap reached; entries omitted') : null,
      ),
    ),
  );
  const gaps = p.coverage.filter((c) => !['covered', 'sampled', 'idle'].includes(c.state));
  return el(
    'div',
    { class: 'stack' },
    el('div', { class: 'row' }, el('span', { class: 'muted small' }, 'Agent'), el('span', { class: 'mono' }, p.agent_version), p.discovery_support ? el('span', { class: 'badge ok' }, 'Supports host discovery') : el('span', { class: 'badge ghost', title: 'Host discovery needs an agent built with +host-discovery-v1' }, 'No host discovery')),
    section('Admin-owned profile', profileBlock),
    section(
      'Collector coverage',
      el('p', { class: 'muted small' }, 'What the profile enables, what control-d advertises to this console, and what the latest sample shows. Agents report on change, so an old sample is not a gap by itself.'),
      el('div', { class: 'table-wrap' }, el('table', { class: 'obs-table cov-table' }, el('thead', null, el('tr', null, ['Collector', 'Profile', 'Coverage', 'Watches', 'Latest sample'].map((x) => el('th', null, x)))), el('tbody', null, rows))),
      p.capabilities_available ? null : el('p', { class: 'muted small' }, 'This control-d does not list collector capabilities; advertised support is unknown.'),
    ),
    gaps.length
      ? section(
          'Visibility gaps',
          el(
            'ul',
            { class: 'gap-list' },
            gaps.map((c) => el('li', null, stateBadge(COVERAGE_STATE, c.state), ' ', collectorName(c.collector), c.state === 'unavailable' ? el('span', { class: 'muted' }, ' · outside the central floor or this console’s scope') : null)),
          ),
        )
      : null,
  );
}

// P15 -----------------------------------------------------------------------

function discoveryPanel(d, dive) {
  if (d.error || d.available === false) return unavailableNotice(d, 'Host discovery');
  const a = d.assessment;
  const latest = d.latest_version;
  const viewingLatest = !a || a.version === latest;
  const versionSel = latest > 1
    ? el(
        'select',
        { attrs: { 'aria-label': 'Assessment revision' }, on: { change: (e) => { dive.version = Number(e.target.value) === latest ? null : Number(e.target.value); dive.reload('discovery'); } } },
        Array.from({ length: latest }, (_, i) => latest - i).map((v) => el('option', { value: String(v), selected: a?.version === v }, v === latest ? `v${v} (latest)` : `v${v}`)),
      )
    : null;
  const advance = adminEnabled() ? el('button', { class: 'btn btn-sm', type: 'button', title: 'Ask control-d to schedule or collect the next bounded discovery samples for this host', on: { click: (e) => advanceDiscovery(e.currentTarget, dive) } }, icon('refresh'), 'Advance discovery') : null;
  const head = el('div', { class: 'row wrap' }, el('span', { class: 'badge solid' }, a ? `Assessment v${a.version}` : 'No assessment'), versionSel, a?.deadline ? el('span', { class: 'muted small' }, 'deadline ', relTime(a.deadline, { until: true })) : null, el('span', { class: 'spacer' }), advance);
  const advanceErr = el('div', { class: 'advance-err' });
  if (!a) return el('div', { class: 'stack' }, head, advanceErr, emptyState('No discovery assessment', 'control-d queues discovery once per enrollment generation. This host has none yet.'));

  const evidenceBy = new Map(a.collectors.filter((c) => c.evidence).map((c) => [c.evidence.observation_id, c.collector]));
  const interp = a.interpretations.at(-1) ?? null;
  const p = interp?.proposal;
  const cite = (id) => obsTag(id, `Observation ${id}${evidenceBy.has(id) ? ` · ${collectorName(evidenceBy.get(id))}` : ''}`);
  const roleCard = p
    ? el(
        'div',
        { class: 'role-card' },
        el('div', { class: 'eyebrow' }, 'Inferred role'),
        el('p', { class: 'role' }, p.purpose),
        el(
          'dl',
          { class: 'kv kv-wide' },
          el('dt', null, 'Depends on'),
          el('dd', null, chipList(p.dependencies, 'none identified')),
          el('dt', null, 'Cited evidence'),
          el('dd', null, el('div', { class: 'ev-row' }, p.citations.map((id) => [cite(id), evidenceBy.has(id) ? el('span', { class: 'muted small' }, collectorName(evidenceBy.get(id))) : null]))),
          el('dt', null, 'Proposed watch'),
          el('dd', null, el('span', { class: 'mono' }, p.proposed_watch.service_unit ?? collectorName(p.proposed_watch.collector)), el('span', { class: 'muted' }, ` · from ${collectorName(p.proposed_watch.collector)}`), el('div', { class: 'small' }, p.proposed_watch.rationale)),
        ),
        p.uncertainty ? el('div', { class: 'unc' }, el('b', null, 'Unanswered: '), p.uncertainty) : null,
        p.visibility_gaps.length ? el('div', null, el('div', { class: 'eyebrow' }, 'What it cannot see'), el('ul', { class: 'gap-list' }, p.visibility_gaps.map((g) => el('li', null, g)))) : null,
      )
    : notice('', 'clock', [el('strong', null, 'No interpretation for this revision.'), el('span', null, d.attempts.some((g) => g.attempts.length) ? 'See the interpretation attempts below.' : 'A worker has not interpreted the current samples yet.')]);

  const evidenceRows = a.collectors.map((c) =>
    el(
      'tr',
      null,
      el('td', null, collectorName(c.collector)),
      el('td', null, c.evidence ? [obsTag(c.evidence.observation_id), ' ', el('span', { class: 'mono muted small' }, `${c.evidence.watch_id} v${c.evidence.spec_version}`)] : el('span', { class: 'warn-text' }, GAP_TEXT[c.gap] ?? words(c.gap))),
      el('td', null, c.evidence ? obsStatusBadge(c.evidence.status) : stateBadge({}, c.gap, 'Gap')),
      el('td', null, c.evidence ? hashChip(c.evidence.state_hash) : el('span', { class: 'muted' }, '—')),
    ),
  );

  const samples = viewingLatest && d.samples.length
    ? section(
        'Discovery samples',
        d.samples.map((s) =>
          el(
            'details',
            { class: 'sample' },
            el('summary', null, el('b', null, collectorName(s.collector)), ' ', obsTag(s.evidence?.observation_id), el('span', { class: 'muted' }, ` · showing ${s.entries.length} of ${s.total}`), s.partial_attribution ? el('span', { class: 'badge warn' }, 'partial attribution') : null, s.truncated ? el('span', { class: 'badge ghost' }, 'truncated') : null),
            sampleTable(s),
          ),
        ),
      )
    : null;

  const attemptGroups = d.attempts.filter((g) => g.attempts.length);
  const attempts = attemptGroups.length
    ? section(
        'Interpretation attempts',
        attemptGroups.map((g) =>
          el(
            'div',
            { class: 'attempts' },
            el('div', { class: 'muted small' }, 'Sources ', g.source_ids.map((id) => [obsTag(id), ' '])),
            el(
              'ol',
              { class: 'attempt-list' },
              g.attempts.map((t, i) =>
                el(
                  'li',
                  null,
                  el('span', { class: 'mono muted' }, `#${i + 1}`),
                  stateBadge(ATTEMPT_STATUS, t.status),
                  t.error ? el('span', { class: 'mono warn-text' }, words(t.error)) : null,
                  t.assessment_version ? el('span', { class: 'small' }, `saved as v${t.assessment_version}`) : null,
                  el('span', { class: 'spacer' }),
                  t.usage ? el('span', { class: 'mono muted small', title: `cached ${t.usage.cached_input_tokens} · cache writes ${t.usage.cache_creation_input_tokens}` }, `${fmtTokens(t.usage.input_tokens)} in · ${fmtTokens(t.usage.output_tokens)} out · ${fmtTokens(t.usage.reasoning_tokens)} reasoning`) : el('span', { class: 'muted small' }, 'no usage reported'),
                  el('span', { class: 'muted small' }, 'lease ', relTime(t.lease_until)),
                ),
              ),
            ),
          ),
        ),
      )
    : null;

  return el(
    'div',
    { class: 'stack' },
    head,
    advanceErr,
    viewingLatest ? null : notice('', 'clock', [el('strong', null, `Viewing revision v${a.version}.`), el('span', null, `The latest is v${latest}. Earlier revisions are kept unchanged.`)]),
    roleCard,
    section('Evidence by collector', el('div', { class: 'table-wrap' }, el('table', { class: 'obs-table' }, el('thead', null, el('tr', null, ['Collector', 'Evidence or gap', 'Status', 'State hash'].map((x) => el('th', null, x)))), el('tbody', null, evidenceRows)))),
    samples,
    attempts,
  );
}

function sampleTable(s) {
  const sockets = s.collector === 'sockets.listening';
  const head = sockets ? ['Protocol', 'Address', 'Process', 'Unit'] : ['Package', 'Version', 'Arch'];
  const row = (e) =>
    sockets
      ? [el('td', { class: 'mono' }, e.protocol ?? '—'), el('td', { class: 'mono' }, `${e.local_addr ?? '?'}:${e.local_port ?? '?'}`), el('td', { class: 'mono' }, e.comm ?? el('span', { class: 'warn-text' }, 'no owner')), el('td', { class: 'mono' }, e.systemd_unit ?? '—')]
      : [el('td', { class: 'mono' }, e.name ?? '—'), el('td', { class: 'mono' }, e.version ?? '—'), el('td', { class: 'mono' }, e.arch ?? '—')];
  return el('div', { class: 'table-wrap' }, el('table', { class: 'obs-table' }, el('thead', null, el('tr', null, head.map((x) => el('th', null, x)))), el('tbody', null, s.entries.map((e) => el('tr', null, row(e))))));
}

async function advanceDiscovery(btn, dive) {
  btn.disabled = true;
  const errNode = btn.closest('.stack')?.querySelector('.advance-err');
  if (errNode) replace(errNode);
  try {
    const r = await api(`/api/admin/hosts/${enc(dive.host)}/discovery/advance`, { method: 'POST', body: {} });
    toast(r.bundle_version ? `Discovery samples requested (bundle v${r.bundle_version}); assessment v${r.assessment_version}` : `Discovery advanced; assessment v${r.assessment_version ?? '—'}`, 'ok');
    dive.version = null;
    await dive.reload('discovery', 'profile');
  } catch (err) {
    if (errNode) replace(errNode, errorBox(err));
    btn.disabled = false;
  }
}

// P16 -----------------------------------------------------------------------

function monitoringPanel(m, dive) {
  if (m.error || m.available === false) return unavailableNotice(m, 'Delegated monitoring');
  const admin = adminEnabled();
  const errNode = el('div');
  const reload = async (msg) => {
    toast(msg, 'ok');
    await dive.reload('monitoring', 'profile');
  };

  const grantRows = m.grants.length
    ? el(
        'div',
        { class: 'grant-list' },
        m.grants.map((g) =>
          el(
            'div',
            { class: ['grant', g.revoked && 'revoked'] },
            el('div', { class: 'grant-who' }, el('span', { class: 'mono' }, g.principal_id), g.revoked ? el('span', { class: 'badge ghost' }, 'revoked') : null),
            el('div', { class: 'small' }, g.revoked ? 'no watches allowed' : `up to ${plural(g.max_watches, 'persistent watch', 'persistent watches')}`, ' · ', g.allow_promotion ? el('span', { class: 'warn-text' }, 'may promote corroborated baselines') : 'no baseline promotion'),
            el('div', { class: 'muted small' }, 'set ', relTime(g.updated_at)),
            admin && !g.revoked ? el('button', { class: 'btn btn-sm btn-ghost', type: 'button', on: { click: (e) => revokeGrant(e.currentTarget, g) } }, 'Revoke') : null,
          ),
        ),
      )
    : el('div', { class: 'empty-slot' }, 'No monitoring grant on this host: investigators can only propose incident-scoped ephemeral watches here.');

  async function revokeGrant(btn, g) {
    const r = await confirmedPost(btn, errNode, `/api/admin/hosts/${enc(dive.host)}/monitoring/grant`, { principal_id: g.principal_id, max_watches: 0, allow_promotion: false }, {
      title: 'Revoke monitoring grant?',
      body: [el('p', null, el('span', { class: 'mono' }, g.principal_id), ` will no longer add, strengthen or renew persistent watches on ${dive.host}. Existing watches stay until they are retired.`)],
      confirm: 'Revoke grant',
      danger: true,
    });
    if (r) await reload(`Grant for ${g.principal_id} revoked`);
  }

  const grantForm = admin ? monitoringGrantForm(dive, errNode, reload) : null;

  const watchCards = m.watches.length
    ? m.watches.map((w) =>
        el(
          'article',
          { class: 'managed' },
          el('div', { class: 'row wrap' }, el('span', { class: 'mono strong' }, w.watch_id), el('span', { class: 'badge solid' }, `rev ${w.revision ?? '—'}`), stateBadge(BASELINE_STATE, w.baseline_state), w.active ? null : el('span', { class: 'badge ghost' }, 'inactive'), el('span', { class: 'spacer' }), el('span', { class: 'muted small' }, 'owner ', el('span', { class: 'mono' }, w.principal_id))),
          el('div', { class: 'small' }, el('span', { class: 'mono' }, w.target ?? collectorName(w.collector)), w.interval_seconds ? el('span', { class: 'muted' }, ` · every ${w.interval_seconds}s`) : null),
          el('dl', { class: 'kv kv-wide' }, el('dt', null, 'Why'), el('dd', null, w.purpose), el('dt', null, 'Expected signal'), el('dd', null, w.expected_signal), el('dt', null, 'Evidence'), el('dd', null, el('div', { class: 'ev-row' }, w.evidence.map((id) => obsTag(id)))), el('dt', null, 'Review by'), el('dd', null, w.review_at ? [el('span', { class: 'num' }, fmtTime(w.review_at)), ' · ', relTime(w.review_at), w.review_overdue ? [' ', el('span', { class: 'badge warn' }, 'review overdue')] : null] : '—')),
        ),
      )
    : el('div', { class: 'empty-slot' }, 'No investigator-managed watches in the audit window.');

  const candRows = m.candidates.map((c) => {
    const watch = m.watches.find((w) => w.watch_id === c.watch_id);
    const actions = [];
    if (admin && c.state === 'provisional') actions.push(el('button', { class: 'btn btn-sm', type: 'button', on: { click: (e) => corroborate(e.currentTarget, c) } }, 'Corroborate…'));
    if (admin && c.state === 'trusted' && watch?.baseline_revision === c.promoted_revision) actions.push(el('button', { class: 'btn btn-sm btn-danger', type: 'button', on: { click: (e) => rollback(e.currentTarget, c) } }, 'Roll back…'));
    return el(
      'article',
      { class: 'candidate' },
      el('div', { class: 'row wrap' }, el('span', { class: 'mono' }, `#${c.candidate_id}`), stateBadge(BASELINE_STATE, c.state), el('span', { class: 'mono muted small' }, c.watch_id), el('span', { class: 'spacer' }), actions),
      el('p', { class: 'small' }, c.rationale),
      el(
        'div',
        { class: 'row wrap muted small' },
        'samples ',
        c.observations.map((id) => obsTag(id)),
        ' · proposed ',
        relTime(c.created_at),
        c.corroborated ? [' · corroborated ', relTime(c.corroborated_at)] : null,
        c.promoted_revision != null ? [' · baseline rev ', el('span', { class: 'mono' }, String(c.promoted_revision))] : null,
      ),
      c.corroboration ? el('div', { class: 'unc' }, el('b', null, 'Operator: '), c.corroboration) : null,
      c.rolled_back ? el('div', { class: 'unc' }, el('b', null, 'Rolled back: '), c.rollback_rationale ?? '') : null,
    );
  });

  async function corroborate(btn, c) {
    const f = { rationale: '' };
    const input = textArea(f, 'rationale', { rows: 3, placeholder: 'Independent evidence, e.g. the change ticket or golden-image hash this matches' });
    const r = await confirmedPost(btn, errNode, `/api/admin/monitoring/candidates/${enc(c.candidate_id)}/corroborate`, () => ({ rationale: f.rationale.trim() }), {
      title: `Corroborate candidate #${c.candidate_id}?`,
      body: [el('p', null, 'Corroboration is the independent operator input a delegated promotion requires. It does not promote anything by itself.'), el('p', { class: 'small' }, c.rationale), field('Your corroboration (recorded in the audit log)', input)],
      confirm: 'Corroborate',
    });
    if (r) {
      if (r.allowed) await reload(`Candidate #${c.candidate_id} corroborated`);
      else replace(errNode, notice('bad', 'alert', [el('strong', null, 'Refused.'), el('span', null, r.reason ?? 'control-d did not record the corroboration')]));
    }
  }

  async function rollback(btn, c) {
    const f = { rationale: '' };
    const input = textArea(f, 'rationale', { rows: 3, placeholder: 'Why this trusted state is wrong' });
    const r = await confirmedPost(btn, errNode, `/api/admin/hosts/${enc(dive.host)}/monitoring/${enc(c.watch_id)}/rollback`, () => ({ expected_baseline: c.promoted_revision, rationale: f.rationale.trim() }), {
      title: `Roll back baseline rev ${c.promoted_revision}?`,
      body: [el('p', null, `The trusted baseline for `, el('span', { class: 'mono' }, c.watch_id), ' returns to its predecessor. The revision is kept and the rollback is audited.'), field('Rationale (recorded in the audit log)', input)],
      confirm: 'Roll back',
      danger: true,
    });
    if (r) {
      if (r.allowed) await reload(`Baseline rev ${c.promoted_revision} rolled back`);
      else replace(errNode, notice('bad', 'alert', [el('strong', null, 'Refused.'), el('span', null, r.reason ?? 'the baseline changed')]));
    }
  }

  return el(
    'div',
    { class: 'stack' },
    errNode,
    section('Monitoring grants', grantRows, grantForm),
    section('Investigator-managed watches', watchCards),
    section('Baseline candidates', m.candidates.length ? candRows : el('div', { class: 'empty-slot' }, 'No provisional or trusted candidates. Provisional expectations guide collection only; nothing is trusted until an operator corroborates it.')),
    m.decisions.length
      ? el(
          'details',
          { class: 'more' },
          el('summary', null, `Recent monitoring decisions (${m.decisions.length})`),
          el('ul', { class: 'decision-log' }, m.decisions.map((x) => el('li', null, el('span', { class: ['dot', x.allowed ? 'ok' : 'bad'] }), el('span', { class: 'mono' }, words(x.operation)), x.watch_id ? el('span', { class: 'mono muted' }, x.watch_id) : null, el('span', { class: 'muted' }, x.actor), x.reason ? el('span', { class: 'warn-text' }, x.reason) : null, el('span', { class: 'spacer' }), relTime(x.at)))),
        )
      : null,
    el('p', { class: 'muted small' }, `Reconstructed from the last ${m.window_entries} audit entries: control-d records every grant, watch change, corroboration and rollback there, but has no direct read for them.`),
  );
}

function monitoringGrantForm(dive, errNode, reload) {
  const f = { principal_id: 'reasoner-d:discovery', max_watches: 3, allow_promotion: false };
  const form = el('div', { class: 'subform' });
  const submit = el('button', { class: 'btn btn-primary btn-sm', type: 'button' }, 'Set grant…');
  const note = el('span', { class: 'hint' });
  append(form, [
    el('div', { class: 'grid-2' }, field('Principal', textInput(f, 'principal_id', { mono: true })), field('Max persistent watches', numInput(f, 'max_watches', { min: 0, max: 32 }))),
    el('div', { class: 'checks' }, check(f, 'allow_promotion', 'Also allow promoting operator-corroborated baselines')),
    el('div', { class: 'form-actions' }, note, el('span', { class: 'spacer' }), submit),
  ]);
  guardSubmit(form, submit, note, () => (!String(f.principal_id).trim() ? 'Name the investigator principal.' : !(Number.isInteger(f.max_watches) && f.max_watches >= 0 && f.max_watches <= 32) ? 'Max watches must be 0–32.' : null), 'control-d enforces the host watch limit');
  submit.addEventListener('click', async () => {
    const r = await confirmedPost(submit, errNode, `/api/admin/hosts/${enc(dive.host)}/monitoring/grant`, { ...f, principal_id: f.principal_id.trim() }, {
      title: 'Set monitoring grant?',
      body: [
        el('p', null, el('span', { class: 'mono' }, f.principal_id.trim()), ` may add, test, strengthen and renew up to ${plural(f.max_watches, 'persistent service watch', 'persistent service watches')} on `, el('span', { class: 'mono' }, dive.host), ' without per-watch approval.'),
        f.allow_promotion ? notice('warn', 'alert', [el('strong', null, 'Promotion allowed.'), el('span', null, 'It may also promote a baseline to trusted once an operator has corroborated the candidate.')]) : el('p', { class: 'muted small' }, 'Trusted baseline promotion stays with operators.'),
      ],
      confirm: 'Set grant',
      danger: f.allow_promotion,
    });
    if (r) await reload(`Monitoring grant set for ${r.principal_id ?? f.principal_id}`);
  });
  return el('details', { class: 'more' }, el('summary', null, 'Set monitoring grant'), form);
}

// P17 -----------------------------------------------------------------------

function reviewPanel(r, dive) {
  if (r.error) return errorBox(r.error);
  const admin = adminEnabled();
  const errNode = el('div');
  const schedule = r.schedule;
  const scheduleBlock = schedule
    ? el(
        'dl',
        { class: 'kv kv-wide' },
        el('dt', null, 'Every'),
        el('dd', null, ttlText(schedule.interval_seconds)),
        el('dt', null, 'Question'),
        el('dd', null, schedule.question),
        el('dt', null, 'Collectors'),
        el('dd', null, chipList(schedule.collectors.map(collectorName))),
        el('dt', null, 'Route'),
        el('dd', { class: 'mono' }, schedule.route),
        schedule.next_due_at ? [el('dt', null, 'Next due'), el('dd', null, el('span', { class: 'num' }, fmtTime(schedule.next_due_at)), ' · ', relTime(schedule.next_due_at))] : null,
        el('dt', null, 'Set'),
        el('dd', null, relTime(schedule.set_at), schedule.set_by ? [' by ', el('span', { class: 'mono' }, schedule.set_by)] : null),
      )
    : el('div', { class: 'empty-slot' }, r.schedule_visible === false ? 'control-d does not expose review schedules. None was set from this console since it started.' : 'No periodic review is scheduled for this host.');
  const scheduleNote = schedule?.source === 'console' ? el('p', { class: 'muted small' }, 'control-d has no read for schedules: this is the schedule this console last set.') : null;

  const cancelBtn = admin && (schedule || r.schedule_visible === false)
    ? el('button', { class: 'btn btn-sm btn-ghost', type: 'button', on: { click: async (e) => {
        const res = await confirmedPost(e.currentTarget, errNode, `/api/admin/hosts/${enc(dive.host)}/review-schedule/cancel`, {}, {
          title: 'Cancel periodic reviews?',
          body: el('p', null, 'Pending reviews for ', el('span', { class: 'mono' }, dive.host), ' are cancelled and the schedule is removed. Completed reviews are kept.'),
          confirm: 'Cancel schedule',
          danger: true,
        });
        if (res) {
          toast('Review schedule cancelled', 'ok');
          await dive.reload('review');
        }
      } } }, 'Cancel schedule…')
    : null;

  let latest;
  if (r.available === false) latest = unavailableNotice(r, 'Host reviews');
  else if (!r.review) latest = el('div', { class: 'empty-slot' }, schedule ? 'No review has completed yet.' : 'This host has never been reviewed. Schedule a review to have a worker re-check it against its assessment.');
  else {
    const v = r.review;
    latest = el(
      'div',
      { class: ['review-card', `i-${v.interpretation}`] },
      el('div', { class: 'row wrap' }, interpBadge(v.interpretation), stateBadge(FRESHNESS, r.freshness?.state), el('span', { class: 'spacer' }), el('span', { class: 'muted small' }, 'completed ', relTime(v.completed_at))),
      el('div', { class: 'muted small' }, 'Q: ', v.question),
      el('p', null, v.summary),
      el(
        'div',
        { class: 'row wrap small' },
        el('span', { class: 'muted' }, 'against assessment'),
        el('button', { class: 'btn btn-sm btn-ghost', type: 'button', title: 'Open this revision in Discovery', on: { click: () => { dive.version = v.assessment_version === r.freshness?.assessment_version ? null : v.assessment_version; dive.reload('discovery').then(() => document.getElementById('hosttab-discovery')?.click()); } } }, `v${v.assessment_version}`),
        r.freshness?.state === 'assessment_advanced' ? el('span', { class: 'warn-text' }, `now v${r.freshness.assessment_version}`) : null,
        el('span', { class: 'muted' }, '· cites'),
        v.citations.length ? v.citations.map((id) => obsTag(id)) : el('span', { class: 'muted' }, 'nothing'),
      ),
    );
  }

  return el(
    'div',
    { class: 'stack' },
    errNode,
    section('Latest review', latest),
    section('Schedule', el('div', { class: 'row wrap' }, el('span', { class: 'spacer' }), cancelBtn), scheduleBlock, scheduleNote, admin ? reviewScheduleForm(dive, schedule, errNode) : null),
  );
}

function reviewScheduleForm(dive, current, errNode) {
  // An existing interval is kept to the second (e.g. 5400 s) unless the operator edits it.
  const exact = Number.isInteger(current?.interval_seconds) ? current.interval_seconds : null;
  let intervalEdited = exact === null;
  const f = {
    interval_hours: exact !== null ? Number((exact / 3600).toFixed(4)) : 24,
    question: current?.question ?? 'Has this host’s role, exposure or package set changed since the last assessment?',
    route: current?.route ?? 'host-review',
    sockets: current ? current.collectors.includes('sockets.listening') : true,
    packages: current ? current.collectors.includes('packages.inventory') : true,
  };
  const form = el('div', { class: 'subform' });
  const submit = el('button', { class: 'btn btn-primary btn-sm', type: 'button' }, current ? 'Update schedule…' : 'Schedule reviews…');
  const note = el('span', { class: 'hint' });
  append(form, [
    el(
      'div',
      { class: 'grid-2' },
      field('Every (hours)', numInput(f, 'interval_hours', { min: 1, max: 720, onInput: () => (intervalEdited = true) }), exact !== null && exact % 3600 ? el('div', { class: 'hint' }, `Currently ${ttlText(exact)} (${exact} s); kept exactly unless you change it.`) : null),
      field('Model route', textInput(f, 'route', { mono: true })),
    ),
    field('Question for the reviewer', textArea(f, 'question', { rows: 2 })),
    el('div', { class: 'checks' }, check(f, 'sockets', 'Refresh listening sockets'), check(f, 'packages', 'Refresh package inventory')),
    el('div', { class: 'form-actions' }, note, el('span', { class: 'spacer' }), submit),
  ]);
  guardSubmit(form, submit, note, () => (intervalEdited && !(Number.isInteger(f.interval_hours) && f.interval_hours >= 1 && f.interval_hours <= 720) ? 'Interval must be 1–720 hours.' : !String(f.question).trim() ? 'Ask the reviewer a question.' : !f.sockets && !f.packages ? 'Pick at least one discovery collector.' : !String(f.route).trim() ? 'Name the model route.' : null), 'control-d validates 60 s – 30 days');
  submit.addEventListener('click', async () => {
    const body = { interval_seconds: intervalEdited ? f.interval_hours * 3600 : exact, question: f.question.trim(), route: f.route.trim(), collectors: [f.packages && 'packages.inventory', f.sockets && 'sockets.listening'].filter(Boolean) };
    const r = await confirmedPost(submit, errNode, `/api/admin/hosts/${enc(dive.host)}/review-schedule`, body, {
      title: current ? 'Replace the review schedule?' : 'Schedule periodic reviews?',
      body: el('p', null, `Every ${ttlText(body.interval_seconds)}, a review worker re-collects ${body.collectors.map(collectorName).join(' and ').toLowerCase()} on `, el('span', { class: 'mono' }, dive.host), ' and records a cited conclusion against the current assessment.', current ? ' Pending reviews under the old schedule are cancelled.' : ''),
      confirm: current ? 'Replace schedule' : 'Schedule',
    });
    if (r) {
      toast('Review schedule saved', 'ok');
      await dive.reload('review', 'discovery');
    }
  });
  return el('details', { class: 'more' }, el('summary', null, current ? 'Change schedule' : 'Schedule reviews'), form);
}

// P14 -----------------------------------------------------------------------

function followupsCard(r, obsMap) {
  if (!r || r.available === false || !r.followups?.length) return null;
  const list = r.followups;
  const open = list.filter((f) => ['awaiting_evidence', 'ready', 'leased'].includes(f.status)).length;
  return card(
    'Follow-up questions',
    `${plural(list.length, 'question')} from accepted watches${open ? ` · ${open} open` : ''}. Each is answered by a fresh observation and a recorded interpretation.`,
    el(
      'div',
      { class: 'card-body flush fu-list' },
      list.map((f) => {
        const inWindow = f.observation_id != null && obsMap.has(f.observation_id);
        return el(
          'article',
          { class: ['fu-item', `fu-${f.status}`] },
          el('div', { class: 'row wrap' }, stateBadge(FOLLOWUP_STATUS, f.status), el('span', { class: 'mono muted small', title: `spec v${f.spec_version}` }, f.watch_id), el('span', { class: 'spacer' }), f.status === 'answered' ? null : el('span', { class: 'small muted' }, 'deadline ', relTime(f.deadline, { until: true }))),
          el('p', { class: 'fu-q' }, f.question),
          f.interpretation
            ? el('div', { class: ['fu-a', `i-${f.interpretation}`] }, interpBadge(f.interpretation), el('span', null, f.summary ?? ''))
            : f.status === 'answered'
              ? el('div', { class: 'fu-a muted' }, 'Answered by a finding outside this console’s collector scope.')
              : el('div', { class: 'fu-a muted' }, f.observation_id ? 'Fresh evidence collected; waiting for an interpretation.' : 'Waiting for a fresh observation on this watch.'),
          el(
            'div',
            { class: 'row wrap small muted' },
            'fresh evidence ',
            f.observation_id == null ? el('span', null, 'none yet') : inWindow ? el('button', { class: 'ev-badge', type: 'button', title: `Show observation ${f.observation_id}`, on: { click: () => focusFact(f.observation_id) } }, `obs ${f.observation_id}`) : obsTag(f.observation_id),
            f.finding_id != null ? [' · finding ', el('span', { class: 'mono' }, `#${f.finding_id}`)] : null,
            ' · asked by ',
            el('span', { class: 'mono' }, shortId(f.origin_run)),
          ),
        );
      }),
    ),
    null,
    'fu-card',
  );
}

// P18 -----------------------------------------------------------------------

/**
 * The latest executor receipt from the same refresh as the verification, or
 * null when the two snapshots disagree (a receipt arrived between the reads).
 * The check's receipt_id and receipt_status are authoritative; executor detail
 * is shown only when it provably belongs to that receipt.
 */
function pairLatestReceipt(v, receipts) {
  if (v.latest_receipt_id == null || !receipts?.length) return null;
  const checks = [...v.receipt_checks].sort((x, y) => x.receipt_id - y.receipt_id);
  const latest = checks.at(-1);
  if (receipts.length !== checks.length || latest?.receipt_id !== v.latest_receipt_id) return null;
  const r = receipts.at(-1);
  return r.status === latest.receipt_status ? r : null;
}

function verificationSection(a, onDetail = null) {
  const slot = el('div', { class: 'stack' }, loading(3));
  // Persistent across polls: the reconciliation form and its draft, keyed by receipt.
  const ctx = { view: null, form: null, formKey: null, draft: { evidence_ref: '', rationale: '' }, draftKey: null, latestKey: null };
  let timer = null;
  let seq = 0;
  const load = async () => {
    clearTimeout(timer);
    const mine = ++seq;
    try {
      // Re-read the executor receipts with every verification so a new receipt
      // can never be labelled with the previous receipt's details.
      const [v, d] = await Promise.all([api(`/api/admin/actions/${enc(a.intent_id)}/verification`), api(`/api/admin/actions/${enc(a.intent_id)}`).catch(() => null)]);
      if (!slot.isConnected || mine !== seq) return;
      if (d) onDetail?.(d);
      const paired = v.available ? pairLatestReceipt(v, d?.receipts) : null;
      renderVerification(slot, ctx, a, v, d?.receipts ?? null, paired, load);
      // Snapshots that disagree are re-read a few times; an older ledger whose
      // receipts predate verification checks never converges, so stop there.
      const mismatched = v.available && v.latest_receipt_id != null && !paired && d != null;
      ctx.retries = mismatched ? (ctx.retries ?? 0) + 1 : 0;
      const retry = mismatched && ctx.retries <= 3;
      if (drawer().open && v.available && (v.outcome === 'awaiting_evidence' || retry)) timer = setTimeout(() => slot.isConnected && load(), retry ? 1500 : 4000);
    } catch (err) {
      if (slot.isConnected && mine === seq) {
        ctx.view = null;
        replace(slot, errorBox(err));
      }
    }
  };
  load();
  return section('Outcome verification', slot);
}

function renderVerification(slot, ctx, a, v, receipts, paired, reload) {
  if (!v.available) {
    ctx.view = null;
    replace(slot, unavailableNotice(v, 'Receipt verification'));
    return;
  }
  if (!ctx.view) {
    const refresh = el('button', { class: 'btn btn-sm btn-ghost', type: 'button', title: 'Reload verification', on: { click: reload } }, icon('refresh'), 'Refresh');
    ctx.view = {
      receipt: el('section', { class: 'vrec v-receipt' }),
      outcome: el('section', { class: 'vrec v-outcome' }),
      reconList: el('div'),
      formHolder: el('div'),
      errNode: el('div'),
      history: el('div'),
    };
    const V = ctx.view;
    replace(
      slot,
      el('div', { class: 'row' }, el('span', { class: 'muted small' }, 'Three separate records: a receipt is not an outcome, and an outcome is not an attestation.'), el('span', { class: 'spacer' }), refresh),
      V.receipt,
      V.outcome,
      el('section', { class: 'vrec v-recon' }, el('div', { class: 'vrec-head' }, el('span', { class: 'eyebrow' }, '3 · Operator reconciliation'), el('span', { class: 'muted small' }, 'attested by an operator from independent evidence')), V.reconList, V.formHolder, V.errNode),
      V.history,
    );
  }
  const V = ctx.view;
  const check = v.receipt_checks.find((c) => c.receipt_id === v.latest_receipt_id) ?? null;

  replace(
    V.receipt,
    el('div', { class: 'vrec-head' }, el('span', { class: 'eyebrow' }, '1 · Executor receipt'), el('span', { class: 'muted small' }, 'what action-exec-d reported')),
    paired
      ? [
          el('div', { class: 'row wrap' }, actionStatusBadge(paired.status), el('span', { class: ['badge', paired.verification_passed ? 'solid' : 'ghost'] }, paired.verification_passed ? 'executor self-check passed' : 'executor self-check failed'), el('span', { class: 'mono muted small' }, `receipt #${v.latest_receipt_id}`), el('span', { class: 'spacer' }), el('span', { class: 'num muted small' }, fmtTime(paired.executed_at))),
          el('div', { class: 'r-detail' }, paired.detail || '—'),
          el('p', { class: 'muted small' }, 'A receipt is the executor’s own claim. It never discharges the postcondition check below.'),
        ]
      : check
        ? [
            el('div', { class: 'row wrap' }, actionStatusBadge(check.receipt_status), el('span', { class: 'mono muted small' }, `receipt #${check.receipt_id}`)),
            el('div', { class: 'muted small' }, receipts ? 'Executor detail for this receipt is not in the same snapshot yet; it is shown once the receipt list catches up.' : 'Executor detail could not be loaded; the execution receipts list above may be stale.'),
          ]
        : el('div', { class: 'muted' }, 'No receipt recorded yet.'),
  );

  const concurrent = v.concurrent_service_changes;
  V.outcome.className = ['vrec', 'v-outcome', `o-${v.outcome}`].join(' ');
  replace(
    V.outcome,
    el('div', { class: 'vrec-head' }, el('span', { class: 'eyebrow' }, '2 · Observed outcome'), el('span', { class: 'muted small' }, 'independent fresh sample after the receipt')),
    el('div', { class: 'row wrap' }, stateBadge(CHECK_RESULT, v.outcome), check?.expected_state ? el('span', { class: 'small' }, 'expected ', el('span', { class: 'mono' }, check.expected_state)) : null, el('span', { class: 'spacer' }), check?.result === 'awaiting_evidence' && check.deadline ? el('span', { class: 'small muted' }, 'deadline ', relTime(check.deadline, { until: true })) : null),
    check ? el('div', { class: 'small' }, check.reason ?? '') : null,
    el(
      'dl',
      { class: 'kv' },
      el('dt', null, 'Precondition'),
      el('dd', null, v.precondition_observation_id != null ? obsTag(v.precondition_observation_id, 'Pre-dispatch service-state evidence') : el('span', { class: 'muted' }, 'none recorded (no supported effect sensor)')),
      el('dt', null, 'Postcondition'),
      el('dd', null, check?.observation_id != null ? [obsTag(check.observation_id, 'Fresh postcondition sample'), ' ', hashChip(check.state_hash)] : el('span', { class: 'muted' }, 'no sample')),
      el('dt', null, 'Expected effect'),
      el('dd', null, v.expected_effect || '—'),
    ),
    el(
      'div',
      { class: 'concurrent' },
      el('div', { class: 'small strong' }, 'Concurrent changes on other monitored units'),
      concurrent.length
        ? el('ul', { class: 'decision-log' }, concurrent.map((c) => el('li', null, el('span', { class: 'mono' }, c.watch_id), obsTag(c.before), el('span', { class: 'rel-arrow' }, '→'), obsTag(c.after), el('span', { class: 'muted small' }, `receipt #${c.receipt_id}`))))
        : el('div', { class: 'muted small' }, 'None seen in the verification window.'),
      el('div', { class: 'muted small' }, v.collateral_coverage ?? 'Causation unassessed.'),
    ),
  );

  replace(
    V.reconList,
    v.operator_reconciliations.length
      ? el(
          'ul',
          { class: 'recon-list' },
          v.operator_reconciliations.map((x) => el('li', null, el('div', { class: 'row wrap small' }, el('span', { class: 'mono' }, x.receipt_id ? `receipt #${x.receipt_id}` : 'unreceipted'), el('span', { class: 'spacer' }), el('span', { class: 'muted' }, 'recorded ', relTime(x.recorded_at))), el('div', { class: 'mono small' }, x.evidence_ref), el('div', { class: 'small' }, x.rationale))),
        )
      : el('div', { class: 'muted small' }, 'None recorded.'),
  );

  // The form is rebuilt only when what it would attest changes; otherwise the
  // operator's draft, caret and focus stay exactly where they were.
  const rec = v.reconcile;
  const key = rec.allowed && adminEnabled() ? `receipt:${rec.expected_receipt_id ?? 'none'}` : `closed:${rec.reason ?? ''}`;
  ctx.latestKey = key;
  if (key !== ctx.formKey) {
    ctx.formKey = key;
    ctx.form = rec.allowed && adminEnabled() ? reconcileForm(ctx, a, rec, key, reload) : null;
    replace(V.formHolder, rec.allowed ? (ctx.form ?? el('div', { class: 'muted small' }, 'An admin can reconcile this outcome.')) : el('div', { class: 'muted small' }, rec.reason ?? ''));
  }

  replace(
    V.history,
    v.receipt_checks.length > 1
      ? el(
          'details',
          { class: 'more' },
          el('summary', null, `Checks for all ${v.receipt_checks.length} receipts`),
          el('div', { class: 'table-wrap' }, el('table', { class: 'obs-table' }, el('thead', null, el('tr', null, ['Receipt', 'Receipt status', 'Expected', 'Observed outcome', 'Reason'].map((x) => el('th', null, x)))), el('tbody', null, v.receipt_checks.map((c) => el('tr', null, el('td', { class: 'mono' }, `#${c.receipt_id}`), el('td', null, words(c.receipt_status)), el('td', { class: 'mono' }, c.expected_state ?? '—'), el('td', null, stateBadge(CHECK_RESULT, c.result)), el('td', { class: 'small' }, c.reason ?? '—')))))),
        )
      : null,
  );
}

function reconcileForm(ctx, a, rec, key, reload) {
  const receiptId = rec.expected_receipt_id;
  const label = receiptId != null ? `receipt #${receiptId}` : 'the unreceipted expired authorization';
  // A draft written against another receipt is kept, but must be re-confirmed.
  const carried = ctx.draftKey !== null && ctx.draftKey !== key && (ctx.draft.evidence_ref.trim() || ctx.draft.rationale.trim());
  const f = ctx.draft;
  f.reconfirmed = !carried;
  ctx.draftKey = key;
  const submit = el('button', { class: 'btn btn-primary btn-sm', type: 'button', dataset: { receiptId: receiptId ?? '' } }, 'Record reconciliation…');
  const note = el('span', { class: 'hint' });
  const form = el(
    'div',
    { class: 'subform', dataset: { receiptKey: key } },
    carried ? el('div', { class: 'notice warn', attrs: { role: 'alert' } }, `A new receipt arrived: this form now attests ${label}. Your draft was written against an earlier receipt; check it still holds before recording it.`) : null,
    field('Independent evidence reference', textInput(f, 'evidence_ref', { placeholder: 'e.g. nft list ruleset from a jump-host session, ticket, observation ID', mono: true })),
    field('Rationale', textArea(f, 'rationale', { rows: 2, placeholder: 'What you checked and what it shows' })),
    carried ? el('div', { class: 'checks' }, check(f, 'reconfirmed', `I re-checked this evidence against ${label}`)) : null,
    el('div', { class: 'form-actions' }, note, el('span', { class: 'spacer' }), submit),
  );
  guardSubmit(form, submit, note, () => (!f.evidence_ref.trim() ? 'Cite the independent evidence.' : !f.rationale.trim() ? 'Explain what it shows.' : !f.reconfirmed ? `Confirm the draft against ${label}.` : null), receiptId != null ? `against receipt #${receiptId}` : 'unreceipted expired authorization');
  const errNode = ctx.view.errNode;
  submit.addEventListener('click', async () => {
    const r = await confirmedPost(
      submit,
      errNode,
      `/api/admin/actions/${enc(a.intent_id)}/reconcile`,
      () => {
        // The receipt may have changed while the dialog was open.
        if (ctx.latestKey !== key) throw Object.assign(new Error(`a newer receipt arrived after you opened this dialog; review the form against it and confirm again`), { code: 'receipt_changed' });
        return { expected_receipt_id: receiptId, evidence_ref: f.evidence_ref.trim(), rationale: f.rationale.trim() };
      },
      {
        title: 'Attest this outcome?',
        body: [el('p', null, receiptId != null ? `You attest the outcome of receipt #${receiptId} from independent evidence.` : 'You attest the outcome of an authorization that expired without a receipt.'), el('p', { class: 'muted small' }, 'control-d records it as an operator reconciliation in the audit log. It admits a retry of this target until a later receipt arrives; it does not change the observed outcome.')],
        confirm: 'Record reconciliation',
      },
    );
    if (r) {
      toast('Operator reconciliation recorded', 'ok');
      ctx.draft = { evidence_ref: '', rationale: '' };
      ctx.draftKey = null;
      reload();
    }
  });
  return form;
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
  if (document.hidden || !dashboardStarted) return;
  await Promise.all([loadStatus(), loadCore()]);
  renderShell();
  refreshIncidentMarkers();
  const view = parseRoute().view;
  if (view === 'fleet' || (view === 'mitigations' && !drawer().open)) render();
}

let dashboardStarted = false;

function startDashboard() {
  document.getElementById('gate').hidden = true;
  clear(document.getElementById('gate'));
  document.getElementById('shell').hidden = false;
  refreshAll();
  if (dashboardStarted) return;
  dashboardStarted = true;
  setInterval(tick, 1000);
  setInterval(poll, 15_000);
}

function setNavOpen(open) {
  const shell = document.getElementById('shell');
  shell.classList.toggle('nav-open', open);
  document.getElementById('nav-open').setAttribute('aria-expanded', String(open));
  if (open) document.querySelector('#nav a[aria-current="page"], #nav a')?.focus();
}

async function boot() {
  hydrateIcons();
  applyTheme(document.documentElement.dataset.theme);
  document.getElementById('refresh-btn').addEventListener('click', () => refreshAll().then(() => toast('Refreshed')));
  for (const b of document.querySelectorAll('[data-theme-choice]')) {
    b.addEventListener('click', () => {
      applyTheme(b.dataset.themeChoice);
      store('defsec.theme', b.dataset.themeChoice);
    });
  }
  document.getElementById('nav-open').addEventListener('click', () => setNavOpen(true));
  document.getElementById('nav-close').addEventListener('click', () => setNavOpen(false));
  document.getElementById('shell').addEventListener('click', (e) => {
    // The scrim is the shell's ::after; a click on the shell itself closes the sheet.
    if (e.target.id === 'shell') setNavOpen(false);
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape' && document.getElementById('shell').classList.contains('nav-open')) setNavOpen(false);
  });
  window.addEventListener('hashchange', () => {
    setNavOpen(false);
    render();
    const main = document.getElementById('main');
    main.focus({ preventScroll: true });
    main.scrollTop = 0;
  });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'r' && dashboardStarted && !document.getElementById('shell').hidden && !e.metaKey && !e.ctrlKey && !e.altKey && !/^(INPUT|TEXTAREA|SELECT)$/.test(document.activeElement?.tagName ?? '') && !drawer().open) {
      refreshAll();
    }
  });
  drawer().addEventListener('click', (e) => {
    if (e.target === drawer()) drawer().close();
  });
  // Lists may have advanced while a detail drawer was open (polls skip re-rendering under it).
  drawer().addEventListener('close', () => {
    if (dashboardStarted && parseRoute().view === 'mitigations') render();
  });
  try {
    state.auth = await api('/api/auth/session');
  } catch (err) {
    state.auth = null;
    if (err.code === 'untrusted_proxy') return showGate({ kind: 'blocked', message: err.message });
  }
  if (state.auth && !state.auth.authenticated) return showGate({ kind: state.auth.auth_mode === 'local' ? 'login' : 'proxy' });
  startDashboard();
}

boot();
