#!/usr/bin/env node
// Defensive Security Autonomous Mitigation Harness — Operator Console.
// Zero-dependency localhost BFF.
//
// Trust boundaries:
//  * Binds to 127.0.0.1 by default. Any other bind address must be given
//    explicitly and prints a warning.
//  * Optional access gate (lib/auth.mjs): local accounts with HMAC-tagged
//    session cookies, or identity headers from a trusted OAuth/OIDC reverse
//    proxy. When enabled, every /api/* route except /api/auth/* needs a user,
//    /api/admin/* needs the admin role, and observers cannot mutate.
//  * Operator Ed25519 private keys never reach this process: dual-signed
//    action approvals are signed offline (admin-cli approve-action) or
//    submitted as an already-signed envelope.
//  * All live data flows through control-d's Unix sockets. The console never
//    opens SQLite and never talks to edge agents.
//  * The capability token stays inside this process and is never sent to the
//    browser, logged, or echoed in errors.
//  * The admin socket is used only with --enable-admin.
//  * Host is validated on every request (DNS-rebinding defence). State-changing
//    POSTs also need a same-origin Origin and a JSON content type.

import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { ApiError } from './lib/domain.mjs';
import { AUTH_MODES, DEFAULT_TRUSTED_PROXIES, ROLES, createAuth, parseDuration, readUsersFile, upsertUser, validHeaderName, validatePassword } from './lib/auth.mjs';
import { createDemoBackend } from './lib/demo-data.mjs';
import { createLiveBackend } from './lib/live-backend.mjs';

export const CONSOLE_VERSION = '0.2.0';
export const PRODUCT_NAME = 'Defensive Security Autonomous Mitigation Harness';
const HERE = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC_DIR = path.join(HERE, 'public');
const MAX_BODY_BYTES = 64 * 1024;

export const SECURITY_HEADERS = Object.freeze({
  'Content-Security-Policy': [
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self'",
    "img-src 'self' data:",
    "font-src 'self'",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'none'",
    "form-action 'self'",
    "frame-ancestors 'none'",
  ].join('; '),
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'Referrer-Policy': 'no-referrer',
  'Cross-Origin-Opener-Policy': 'same-origin',
  'Cross-Origin-Resource-Policy': 'same-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=(), usb=(), payment=()',
});

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.mjs': 'text/javascript; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.json': 'application/json; charset=utf-8',
  '.ico': 'image/x-icon',
};

function loadStatic() {
  const files = new Map();
  if (!fs.existsSync(PUBLIC_DIR)) return files;
  for (const name of fs.readdirSync(PUBLIC_DIR)) {
    const full = path.join(PUBLIC_DIR, name);
    const ext = path.extname(name);
    if (!fs.statSync(full).isFile() || !MIME[ext]) continue;
    files.set(`/${name}`, { body: fs.readFileSync(full), type: MIME[ext] });
  }
  if (files.has('/index.html')) files.set('/', files.get('/index.html'));
  return files;
}

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------

const ID = '([^/]+)';
const routes = [
  ['GET', '/api/status', (b) => b.status()],
  ['GET', '/api/hosts', (b) => b.hosts()],
  ['GET', `/api/hosts/${ID}/watches`, (b, [h]) => b.watches(h)],
  ['GET', `/api/hosts/${ID}/capabilities`, (b, [h]) => b.capabilities(h)],
  ['GET', `/api/hosts/${ID}/baselines`, (b, [h]) => b.baselines(h)],
  ['GET', `/api/hosts/${ID}/observations`, (b, [h], q) => b.observations(h, { watch_id: q.get('watch_id') || null, limit: q.get('limit') || null })],
  ['GET', '/api/incidents', (b) => b.incidents()],
  ['GET', `/api/incidents/${ID}`, (b, [i]) => b.incident(i)],
  ['POST', `/api/incidents/${ID}/runs`, (b, [i], _q, body) => b.startRun(i, body)],
  ['POST', `/api/incidents/${ID}/proposals`, (b, [i], _q, body) => b.propose(i, body)],
  ['POST', `/api/incidents/${ID}/findings`, (b, [i], _q, body) => b.recordFinding(i, body)],
  ['GET', '/api/actions', (b, _p, q) => b.actions({ host_id: q.get('host_id') || null, incident_id: q.get('incident_id') || null })],
  ['GET', `/api/admin/actions/${ID}`, (b, [i]) => b.actionDetail(i)],
  ['POST', `/api/admin/actions/${ID}/approve`, (b, [i], _q, body, ctx) => b.approveAction(i, body, ctx)],
  ['GET', '/api/admin/audit', (b, _p, q) => b.audit({ limit: q.get('limit') || 200 })],
  [
    'GET',
    '/api/admin/policy-decisions',
    async (b, _p, q) => {
      const r = await b.policyDecisions({ limit: q.get('limit') || 200 });
      const rule = q.get('rule_id');
      return rule ? { decisions: r.decisions.filter((d) => d.decision.rule_id === rule) } : r;
    },
  ],
  ['POST', '/api/admin/baselines/promote', (b, _p, _q, body) => b.promoteBaseline(body)],
  ['POST', `/api/admin/incidents/${ID}/close`, (b, [i], _q, body) => b.closeIncident(i, body)],
  ['POST', '/api/admin/hosts/enroll', (b, _p, _q, body) => b.enrollHost(body)],
  ['POST', '/api/demo/tamper', (b) => demoOnly(b, 'demoTamper')],
  ['POST', '/api/demo/reset', (b) => demoOnly(b, 'demoReset')],
].map(([method, pattern, handler]) => [method, new RegExp(`^${pattern}$`), handler]);

function demoOnly(backend, fn) {
  if (backend.mode !== 'demo' || typeof backend[fn] !== 'function') throw new ApiError(404, 'not_found', 'demo-only route');
  return backend[fn]();
}

function matchRoute(method, pathname) {
  let pathMatched = false;
  for (const [m, re, handler] of routes) {
    const hit = re.exec(pathname);
    if (!hit) continue;
    pathMatched = true;
    if (m === method || (m === 'GET' && method === 'HEAD')) {
      return { handler, params: hit.slice(1).map((p) => decodeURIComponent(p)) };
    }
  }
  return pathMatched ? { methodNotAllowed: true } : null;
}

// ---------------------------------------------------------------------------
// HTTP helpers
// ---------------------------------------------------------------------------

function send(res, status, body, type, extra = {}) {
  const buf = Buffer.isBuffer(body) ? body : Buffer.from(body, 'utf8');
  res.writeHead(status, { ...SECURITY_HEADERS, 'Content-Type': type, 'Content-Length': buf.length, ...extra });
  res.end(res.req.method === 'HEAD' ? undefined : buf);
}

function sendJson(res, status, value, headers = {}) {
  send(res, status, JSON.stringify(value), 'application/json; charset=utf-8', { 'Cache-Control': 'no-store', ...headers });
}

function sendError(res, status, code, message, headers = {}) {
  send(res, status, JSON.stringify({ error: { code, message } }), 'application/json; charset=utf-8', { 'Cache-Control': 'no-store', ...headers });
}

function readJsonBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    const tooLarge = () => new ApiError(413, 'payload_too_large', `request body exceeds ${MAX_BODY_BYTES} bytes`);
    req.on('data', (c) => {
      size += c.length;
      // Drain (and discard) moderately oversized bodies so the client gets a
      // clean 413; abort outright beyond 1 MiB.
      if (size > 1024 * 1024) {
        reject(tooLarge());
        req.destroy();
        return;
      }
      if (size <= MAX_BODY_BYTES) chunks.push(c);
    });
    req.on('end', () => {
      if (size > MAX_BODY_BYTES) return reject(tooLarge());
      if (!size) return resolve({});
      try {
        const v = JSON.parse(Buffer.concat(chunks).toString('utf8'));
        if (!v || typeof v !== 'object' || Array.isArray(v)) throw new Error('not an object');
        resolve(v);
      } catch {
        reject(new ApiError(400, 'invalid_json', 'request body must be a JSON object'));
      }
    });
    req.on('error', reject);
  });
}

const LOOPBACK = new Set(['127.0.0.1', 'localhost', '::1', '[::1]']);

export function isLoopbackHost(host) {
  return LOOPBACK.has(host) || /^127\.\d+\.\d+\.\d+$/.test(host);
}

// ---------------------------------------------------------------------------
// Server factory
// ---------------------------------------------------------------------------

/**
 * @param {object} opts
 * @param {object} opts.backend          live or demo backend
 * @param {string} [opts.host]           bind address (default 127.0.0.1)
 * @param {number} [opts.port]           bind port (0 = ephemeral)
 * @param {string[]} [opts.allowedHosts] extra Host header values (host[:port])
 * @param {object} [opts.auth]         access gate from lib/auth.mjs (default: none)
 * @param {(line: string) => void} [opts.log]
 */
export function createConsoleServer({ backend, host = '127.0.0.1', port = 8787, allowedHosts = [], auth = createAuth({ mode: 'none' }), log = () => {} }) {
  const staticFiles = loadStatic();
  let boundPort = port;

  const hostAllowed = (hdr) => {
    if (!hdr) return false;
    const h = hdr.toLowerCase();
    const names = ['127.0.0.1', 'localhost', '[::1]'];
    if (!isLoopbackHost(host) && host !== '0.0.0.0' && host !== '::') names.push(host);
    const ok = new Set(names.map((n) => `${n}:${boundPort}`));
    for (const extra of allowedHosts) {
      const e = extra.toLowerCase();
      ok.add(/^(\[[^\]]+\]|[^:]+):\d+$/.test(e) ? e : `${e}:${boundPort}`);
    }
    return ok.has(h);
  };

  const originAllowed = (req) => {
    const origin = req.headers.origin;
    if (origin !== undefined) {
      if (origin === 'null') return false;
      let u;
      try {
        u = new URL(origin);
      } catch {
        return false;
      }
      return u.protocol === 'http:' && u.host.toLowerCase() === String(req.headers.host).toLowerCase();
    }
    // No Origin (e.g. curl). Browsers always send Origin on cross-site POSTs;
    // additionally refuse anything a browser marks as cross-site.
    const site = req.headers['sec-fetch-site'];
    return site === undefined || site === 'same-origin' || site === 'none';
  };

  async function handleAuthRoute(req, res, pathname, readBody) {
    const routeMethods = { '/api/auth/session': 'GET', '/api/auth/login': 'POST', '/api/auth/logout': 'POST' };
    const want = routeMethods[pathname];
    if (!want) return sendError(res, 404, 'not_found', 'unknown API route');
    if (req.method !== want && !(want === 'GET' && req.method === 'HEAD')) return sendError(res, 405, 'method_not_allowed', 'method not allowed');
    if (pathname === '/api/auth/session') return sendJson(res, 200, auth.session(req));
    const body = await readBody();
    if (pathname === '/api/auth/login') {
      const r = await auth.login(req, body);
      log(`auth: ${r.user.username} (${r.user.role}) signed in`);
      return sendJson(res, 200, { auth_mode: auth.mode, authenticated: true, user: r.user, expires_in: r.expires_in }, { 'Set-Cookie': r.setCookie });
    }
    const r = auth.logout(req);
    return sendJson(res, 200, { auth_mode: auth.mode, logged_out: r.logged_out }, r.setCookie ? { 'Set-Cookie': r.setCookie } : {});
  }

  const server = http.createServer(async (req, res) => {
    const started = Date.now();
    res.on('finish', () => log(`${req.method} ${req.url?.split('?')[0]} ${res.statusCode} ${Date.now() - started}ms`));
    try {
      if (!hostAllowed(req.headers.host)) {
        return sendError(res, 403, 'host_not_allowed', 'Host header is not an allowed console address');
      }
      // proxy-header mode: identity headers are only meaningful from the proxy,
      // so any other TCP peer is refused before anything else happens.
      if (!auth.peerAllowed(req)) {
        return sendError(res, 403, 'untrusted_proxy', 'requests must arrive through the trusted identity proxy');
      }
      const url = new URL(req.url, 'http://console.invalid');
      const pathname = url.pathname;

      if (pathname.startsWith('/api/')) {
        const readBody = async () => {
          if (!originAllowed(req)) throw new ApiError(403, 'cross_origin_denied', 'cross-origin state-changing requests are refused');
          const ctype = String(req.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
          const len = Number(req.headers['content-length'] ?? 0);
          if ((len > 0 || req.headers['transfer-encoding'] || ctype) && ctype !== 'application/json') {
            throw new ApiError(415, 'unsupported_media_type', 'POST bodies must be application/json');
          }
          return readJsonBody(req);
        };

        if (pathname.startsWith('/api/auth/')) return await handleAuthRoute(req, res, pathname, readBody);

        const who = auth.identify(req);
        if (auth.mode !== 'none' && !who.user) {
          const e = who.error ?? { status: 401, code: 'unauthenticated', message: 'authentication required' };
          return sendError(res, e.status, e.code, e.message);
        }
        const route = matchRoute(req.method, pathname);
        if (!route) return sendError(res, 404, 'not_found', 'unknown API route');
        if (route.methodNotAllowed) return sendError(res, 405, 'method_not_allowed', 'method not allowed');
        const isAdminRoute = pathname.startsWith('/api/admin/') || pathname.startsWith('/api/demo/');
        if (who.user && who.user.role !== 'admin') {
          if (isAdminRoute) return sendError(res, 403, 'admin_role_required', `user '${who.user.username}' has the observer role; admin routes need the admin role`);
          if (req.method === 'POST') return sendError(res, 403, 'read_only_role', 'observer accounts are read-only');
        }
        const body = req.method === 'POST' ? await readBody() : {};
        if (pathname.startsWith('/api/admin/') && !backend.adminEnabled) {
          return sendError(res, 403, 'admin_disabled', 'admin routes require starting the console with --enable-admin');
        }
        const result = await route.handler(backend, route.params, url.searchParams, body, { user: who.user ?? null });
        return sendJson(res, 200, result);
      }

      if (req.method !== 'GET' && req.method !== 'HEAD') return sendError(res, 405, 'method_not_allowed', 'method not allowed');
      const file = staticFiles.get(pathname);
      if (!file) return send(res, 404, 'Not found', 'text/plain; charset=utf-8');
      return send(res, 200, file.body, file.type, { 'Cache-Control': 'no-cache' });
    } catch (err) {
      if (err instanceof ApiError) return sendError(res, err.status, err.code, err.message, err.extra?.headers);
      log(`internal error: ${err?.message ?? err}`);
      if (!res.headersSent) sendError(res, 500, 'internal_error', 'internal console error');
    }
  });
  server.headersTimeout = 10_000;
  server.requestTimeout = 30_000;

  return {
    server,
    listen() {
      return new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(port, host, () => {
          boundPort = server.address().port;
          const shown = host.includes(':') ? `[${host}]` : host === '0.0.0.0' ? '127.0.0.1' : host;
          resolve({ port: boundPort, url: `http://${shown}:${boundPort}/` });
        });
      });
    },
    close() {
      return new Promise((resolve) => {
        server.closeAllConnections?.();
        server.close(() => resolve());
      });
    },
  };
}

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------


const USAGE = `${PRODUCT_NAME} — Operator Console ${CONSOLE_VERSION}

Usage:
  node console/server.mjs --demo [--port 8787]
  node console/server.mjs --investigate-sock PATH (--token-file PATH | --token TOKEN)
                          [--enable-admin --admin-sock PATH] [--port 8787]
  node console/server.mjs --create-user --auth-users-file PATH --username NAME
                          --role observer|admin [--password-env VAR | --password-stdin]

Data source:
  --demo                     Serve realistic offline fixtures (no daemons needed)
  --demo-readonly            Demo mode with admin routes disabled
  --investigate-sock PATH    control-d investigation socket
  --token-file PATH          File holding the capability token (preferred)
  --token TOKEN              Capability token (visible in process listings!)
                             Env fallback: DEFSEC_CAPABILITY_TOKEN
  --admin-sock PATH          control-d admin socket
  --enable-admin             Allow the console to use the admin socket

Access gate:
  --auth-mode MODE           none (default) | local | proxy-header
                             Env: DEFSEC_CONSOLE_AUTH_MODE
  --auth-users-file PATH     Local accounts file (mode local). Env: DEFSEC_CONSOLE_USERS_FILE
  --session-ttl DURATION     Session lifetime, e.g. 8h, 30m, 3600 (default 8h)
  --session-secret-file PATH HMAC key for session IDs (>= 32 bytes; default random
                             per process). Env: DEFSEC_CONSOLE_SESSION_SECRET
  --secure-cookies           Always mark the session cookie Secure (behind TLS)
  --trusted-proxy-ips CSV    Proxy peers whose X-Forwarded-* headers are trusted
                             (default 127.0.0.1,::1,::ffff:127.0.0.1; CIDRs allowed)
  --proxy-user-header H      Identity header (default x-forwarded-user)
  --proxy-role-header H      Group/role header, e.g. x-forwarded-groups
  --proxy-admin-group G      Group in the role header that grants admin
  --proxy-default-role R     Role when no role header is configured (default observer)

Account management (writes the users file atomically with mode 0600):
  --create-user              Create or reset an account, then exit
  --username NAME            Account name
  --role ROLE                observer | admin
  --password-env VAR         Read the password from environment variable VAR
  --password-stdin           Read the password from stdin (first line)
                             Without either, prompts on the terminal (no echo)

Network:
  --host ADDR                Bind address (default 127.0.0.1)
  --port N                   Bind port (default 8787, 0 = ephemeral)
  --allowed-host H[:P]       Extra accepted Host header (repeatable)
  --timeout-ms N             Per-RPC socket timeout (default 5000)
  --quiet                    Disable access logging
  -h, --help                 Show this help
`;

export function parseArgs(argv, env = process.env) {
  const opts = {
    demo: false,
    demoReadonly: false,
    enableAdmin: false,
    host: '127.0.0.1',
    port: 8787,
    allowedHosts: [],
    timeoutMs: 5000,
    quiet: false,
    authMode: null,
    authUsersFile: null,
    sessionTtlSeconds: 8 * 3600,
    sessionSecretFile: null,
    secureCookies: false,
    trustedProxyIps: [...DEFAULT_TRUSTED_PROXIES],
    trustedProxyExplicit: false,
    proxyUserHeader: 'x-forwarded-user',
    proxyRoleHeader: null,
    proxyAdminGroup: null,
    proxyDefaultRole: 'observer',
    createUser: false,
  };
  const need = (i, flag) => {
    if (i >= argv.length || argv[i].startsWith('--')) throw new Error(`${flag} requires a value`);
    return argv[i];
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case '--demo': opts.demo = true; break;
      case '--demo-readonly': opts.demo = true; opts.demoReadonly = true; break;
      case '--enable-admin': opts.enableAdmin = true; break;
      case '--quiet': opts.quiet = true; break;
      case '--investigate-sock': opts.investigateSock = need(++i, a); break;
      case '--admin-sock': opts.adminSock = need(++i, a); break;
      case '--token': opts.token = need(++i, a); opts.tokenSource = 'argv'; break;
      case '--token-file': opts.tokenFile = need(++i, a); break;
      case '--host': opts.host = need(++i, a); opts.hostExplicit = true; break;
      case '--port': opts.port = Number(need(++i, a)); break;
      case '--allowed-host': opts.allowedHosts.push(need(++i, a)); break;
      case '--timeout-ms': opts.timeoutMs = Number(need(++i, a)); break;
      case '--auth-mode': opts.authMode = need(++i, a); break;
      case '--auth-users-file': opts.authUsersFile = need(++i, a); break;
      case '--session-ttl': opts.sessionTtlSeconds = parseDuration(need(++i, a)); break;
      case '--session-secret-file': opts.sessionSecretFile = need(++i, a); break;
      case '--secure-cookies': opts.secureCookies = true; break;
      case '--trusted-proxy-ips':
        opts.trustedProxyIps = need(++i, a).split(',').map((s) => s.trim()).filter(Boolean);
        opts.trustedProxyExplicit = true;
        break;
      case '--proxy-user-header': opts.proxyUserHeader = need(++i, a).toLowerCase(); break;
      case '--proxy-role-header': opts.proxyRoleHeader = need(++i, a).toLowerCase(); break;
      case '--proxy-admin-group': opts.proxyAdminGroup = need(++i, a); break;
      case '--proxy-default-role': opts.proxyDefaultRole = need(++i, a); break;
      case '--create-user': opts.createUser = true; break;
      case '--username': opts.username = need(++i, a); break;
      case '--role': opts.role = need(++i, a); break;
      case '--password-env': opts.passwordEnv = need(++i, a); break;
      case '--password-stdin': opts.passwordStdin = true; break;
      case '-h': case '--help': opts.help = true; break;
      default: throw new Error(`unknown argument: ${a}`);
    }
  }
  if (!Number.isInteger(opts.port) || opts.port < 0 || opts.port > 65535) throw new Error('--port must be 0..65535');
  opts.authUsersFile ??= env.DEFSEC_CONSOLE_USERS_FILE || null;
  if (opts.help) return opts;

  if (opts.createUser) {
    if (!opts.authUsersFile) throw new Error('--create-user requires --auth-users-file');
    if (!opts.username) throw new Error('--create-user requires --username');
    if (!ROLES.includes(opts.role)) throw new Error(`--create-user requires --role ${ROLES.join('|')}`);
    if (opts.passwordEnv && opts.passwordStdin) throw new Error('use only one of --password-env and --password-stdin');
    return opts;
  }

  opts.authMode ??= env.DEFSEC_CONSOLE_AUTH_MODE || 'none';
  if (!AUTH_MODES.includes(opts.authMode)) throw new Error(`--auth-mode must be one of: ${AUTH_MODES.join(', ')}`);
  if (opts.authMode === 'local') {
    if (!opts.authUsersFile) throw new Error('--auth-mode local requires --auth-users-file (create one with --create-user)');
    const data = readUsersFile(opts.authUsersFile);
    if (!Object.keys(data.users).length) throw new Error(`${opts.authUsersFile} has no accounts; add one with --create-user`);
    opts.usersFileWorldReadable = (fs.statSync(opts.authUsersFile).mode & 0o077) !== 0;
  }
  if (opts.sessionSecretFile) {
    opts.sessionSecret = fs.readFileSync(opts.sessionSecretFile, 'utf8').trim();
    opts.sessionSecretWorldReadable = (fs.statSync(opts.sessionSecretFile).mode & 0o077) !== 0;
  } else if (env.DEFSEC_CONSOLE_SESSION_SECRET) {
    opts.sessionSecret = env.DEFSEC_CONSOLE_SESSION_SECRET.trim();
  }
  if (opts.sessionSecret !== undefined && Buffer.byteLength(opts.sessionSecret) < 32) throw new Error('session secret must be at least 32 bytes');
  if (opts.authMode === 'proxy-header') {
    if (!validHeaderName(opts.proxyUserHeader)) throw new Error('--proxy-user-header must be a lowercase header name');
    if (opts.proxyRoleHeader && !validHeaderName(opts.proxyRoleHeader)) throw new Error('--proxy-role-header must be a lowercase header name');
    if (opts.proxyRoleHeader && !opts.proxyAdminGroup) throw new Error('--proxy-role-header requires --proxy-admin-group');
    if (!ROLES.includes(opts.proxyDefaultRole)) throw new Error(`--proxy-default-role must be one of: ${ROLES.join(', ')}`);
  }
  authFromOptions(opts); // validates trusted proxy addresses early

  if (opts.demo) return opts;
  if (!opts.investigateSock) throw new Error('--investigate-sock is required in live mode (or use --demo)');
  if (opts.tokenFile) {
    const st = fs.statSync(opts.tokenFile);
    opts.tokenWorldReadable = (st.mode & 0o077) !== 0;
    opts.token = fs.readFileSync(opts.tokenFile, 'utf8').trim();
    opts.tokenSource = 'file';
  } else if (!opts.token && env.DEFSEC_CAPABILITY_TOKEN) {
    opts.token = env.DEFSEC_CAPABILITY_TOKEN.trim();
    opts.tokenSource = 'env';
  }
  if (!opts.token) throw new Error('a capability token is required: --token-file, --token or DEFSEC_CAPABILITY_TOKEN');
  if (opts.enableAdmin && !opts.adminSock) throw new Error('--enable-admin requires --admin-sock');
  return opts;
}

export function authFromOptions(opts) {
  return createAuth({
    mode: opts.authMode ?? 'none',
    usersFile: opts.authUsersFile,
    sessionTtlSeconds: opts.sessionTtlSeconds,
    sessionSecret: opts.sessionSecret ?? null,
    secureCookies: opts.secureCookies,
    trustedProxyIps: opts.trustedProxyIps,
    trustForwarded: opts.trustedProxyExplicit,
    proxyUserHeader: opts.proxyUserHeader,
    proxyRoleHeader: opts.proxyRoleHeader,
    proxyAdminGroup: opts.proxyAdminGroup,
    proxyDefaultRole: opts.proxyDefaultRole,
  });
}

export function backendFromOptions(opts) {
  if (opts.demo) return createDemoBackend({ enableAdmin: !opts.demoReadonly });
  return createLiveBackend({
    investigateSock: opts.investigateSock,
    token: opts.token,
    adminSock: opts.adminSock ?? null,
    enableAdmin: opts.enableAdmin,
    timeoutMs: opts.timeoutMs,
  });
}

// ---------------------------------------------------------------------------
// --create-user
// ---------------------------------------------------------------------------

function readStdinLine(stream = process.stdin) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    stream.on('data', (c) => chunks.push(c));
    stream.on('end', () => resolve(Buffer.concat(chunks).toString('utf8').split(/\r?\n/)[0]));
    stream.on('error', reject);
  });
}

function promptHidden(question) {
  const stdin = process.stdin;
  if (!stdin.isTTY) return Promise.reject(new Error('no terminal for a password prompt; use --password-env VAR or --password-stdin'));
  process.stderr.write(question);
  return new Promise((resolve, reject) => {
    let buf = '';
    const done = (err) => {
      stdin.setRawMode(false);
      stdin.pause();
      stdin.off('data', onData);
      process.stderr.write('\n');
      err ? reject(err) : resolve(buf);
    };
    const onData = (chunk) => {
      for (const c of chunk) {
        if (c === '\r' || c === '\n') return done();
        if (c === '\u0003' || c === '\u0004') return done(new Error('aborted'));
        if (c === '\u007f' || c === '\b') buf = buf.slice(0, -1);
        else if (c >= ' ') buf += c;
      }
    };
    stdin.setEncoding('utf8');
    stdin.setRawMode(true);
    stdin.resume();
    stdin.on('data', onData);
  });
}

export async function runCreateUser(opts, { env = process.env, stdin = process.stdin, out = process.stdout } = {}) {
  let password;
  if (opts.passwordEnv) {
    password = env[opts.passwordEnv];
    if (password === undefined) throw new Error(`environment variable ${opts.passwordEnv} is not set`);
  } else if (opts.passwordStdin) {
    password = await readStdinLine(stdin);
  } else {
    password = await promptHidden(`Password for ${opts.username}: `);
    validatePassword(password);
    const again = await promptHidden('Repeat password: ');
    if (again !== password) throw new Error('passwords do not match');
  }
  const { created } = upsertUser(opts.authUsersFile, { username: opts.username, role: opts.role, password });
  out.write(`${created ? 'created' : 'updated'} ${opts.role} account '${opts.username}' in ${opts.authUsersFile} (mode 0600)\n`);
  return { created };
}

async function main() {
  let opts;
  try {
    opts = parseArgs(process.argv.slice(2));
  } catch (err) {
    process.stderr.write(`error: ${err.message}\n\n${USAGE}`);
    process.exit(2);
  }
  if (opts.help) {
    process.stdout.write(USAGE);
    return;
  }
  if (opts.createUser) {
    try {
      await runCreateUser(opts);
      process.exit(0);
    } catch (err) {
      process.stderr.write(`error: ${err.message}\n`);
      process.exit(1);
    }
  }
  const warn = (m) => process.stderr.write(`\x1b[33mwarning:\x1b[0m ${m}\n`);
  const exposed = !isLoopbackHost(opts.host);
  if (exposed) {
    warn(`binding to non-loopback address ${opts.host}.`);
    if (opts.authMode === 'none') {
      const lines = [
        'UNAUTHENTICATED CONSOLE ON A NETWORK ADDRESS (--auth-mode none)',
        'Anyone who can reach this port can read telemetry and act with',
        "the capability token's scope. Use --auth-mode local or",
        '--auth-mode proxy-header, or bind to 127.0.0.1.',
      ];
      const w = Math.max(...lines.map((l) => l.length)) + 4;
      const box = [`┌${'─'.repeat(w)}┐`, ...lines.map((l) => `│  ${l.padEnd(w - 4)}  │`), `└${'─'.repeat(w)}┘`];
      process.stderr.write(`\n\x1b[1;31m${box.map((l) => `  ${l}`).join('\n')}\x1b[0m\n\n`);
    } else if (opts.authMode === 'local' && !opts.secureCookies) {
      warn('session cookies travel over plain HTTP unless a TLS proxy sets X-Forwarded-Proto: https (with --trusted-proxy-ips) or you pass --secure-cookies.');
    }
    if (!opts.allowedHosts.length) warn('add --allowed-host <name[:port]> for the address clients will use.');
  }
  if (opts.authMode === 'proxy-header' && opts.trustedProxyIps.some((ip) => !/^(127\.|::1$|::ffff:127\.)/.test(ip))) {
    warn(`trusting identity headers from ${opts.trustedProxyIps.join(', ')}; make sure only your proxy can reach this port.`);
  }
  if (opts.tokenSource === 'argv') warn('--token is visible in process listings; prefer --token-file or DEFSEC_CAPABILITY_TOKEN.');
  if (opts.tokenWorldReadable) warn(`token file ${opts.tokenFile} is readable by group/other; chmod 600 it.`);
  if (opts.usersFileWorldReadable) warn(`users file ${opts.authUsersFile} is readable by group/other; chmod 600 it.`);
  if (opts.sessionSecretWorldReadable) warn(`session secret file ${opts.sessionSecretFile} is readable by group/other; chmod 600 it.`);
  if (!opts.demo && opts.adminSock && !opts.enableAdmin) warn('--admin-sock given without --enable-admin; admin routes stay disabled.');

  const backend = backendFromOptions(opts);
  const auth = authFromOptions(opts);
  const app = createConsoleServer({
    backend,
    auth,
    host: opts.host,
    port: opts.port,
    allowedHosts: opts.allowedHosts,
    log: opts.quiet ? () => {} : (line) => process.stderr.write(`${new Date().toISOString()} ${line}\n`),
  });
  const { url } = await app.listen();
  process.stdout.write(
    `${PRODUCT_NAME} console (${backend.mode} mode, admin ${backend.adminEnabled ? 'enabled' : 'disabled'}, auth ${auth.describe()}) listening on ${url}\n`,
  );
  const stop = () => app.close().then(() => process.exit(0));
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main();
}
