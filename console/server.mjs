#!/usr/bin/env node
// DefSecAutMit Operator Console: zero-dependency localhost BFF.
//
// Trust boundaries:
//  * Binds to 127.0.0.1 by default. Any other bind address must be given
//    explicitly and prints a warning.
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
import { createDemoBackend } from './lib/demo-data.mjs';
import { createLiveBackend } from './lib/live-backend.mjs';

export const CONSOLE_VERSION = '0.1.0';
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

function sendJson(res, status, value) {
  send(res, status, JSON.stringify(value), 'application/json; charset=utf-8', { 'Cache-Control': 'no-store' });
}

function sendError(res, status, code, message) {
  sendJson(res, status, { error: { code, message } });
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
 * @param {(line: string) => void} [opts.log]
 */
export function createConsoleServer({ backend, host = '127.0.0.1', port = 8787, allowedHosts = [], log = () => {} }) {
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

  const server = http.createServer(async (req, res) => {
    const started = Date.now();
    res.on('finish', () => log(`${req.method} ${req.url?.split('?')[0]} ${res.statusCode} ${Date.now() - started}ms`));
    try {
      if (!hostAllowed(req.headers.host)) {
        return sendError(res, 403, 'host_not_allowed', 'Host header is not an allowed console address');
      }
      const url = new URL(req.url, 'http://console.invalid');
      const pathname = url.pathname;

      if (pathname.startsWith('/api/')) {
        const route = matchRoute(req.method, pathname);
        if (!route) return sendError(res, 404, 'not_found', 'unknown API route');
        if (route.methodNotAllowed) return sendError(res, 405, 'method_not_allowed', 'method not allowed');
        let body = {};
        if (req.method === 'POST') {
          if (!originAllowed(req)) return sendError(res, 403, 'cross_origin_denied', 'cross-origin state-changing requests are refused');
          const ctype = String(req.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
          const len = Number(req.headers['content-length'] ?? 0);
          if (len > 0 || req.headers['transfer-encoding']) {
            if (ctype !== 'application/json') return sendError(res, 415, 'unsupported_media_type', 'POST bodies must be application/json');
          } else if (ctype && ctype !== 'application/json') {
            return sendError(res, 415, 'unsupported_media_type', 'POST bodies must be application/json');
          }
          body = await readJsonBody(req);
        }
        if (pathname.startsWith('/api/admin/') && !backend.adminEnabled) {
          return sendError(res, 403, 'admin_disabled', 'admin routes require starting the console with --enable-admin');
        }
        const result = await route.handler(backend, route.params, url.searchParams, body);
        return sendJson(res, 200, result);
      }

      if (req.method !== 'GET' && req.method !== 'HEAD') return sendError(res, 405, 'method_not_allowed', 'method not allowed');
      const file = staticFiles.get(pathname);
      if (!file) return send(res, 404, 'Not found', 'text/plain; charset=utf-8');
      return send(res, 200, file.body, file.type, { 'Cache-Control': 'no-cache' });
    } catch (err) {
      if (err instanceof ApiError) return sendError(res, err.status, err.code, err.message);
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

const USAGE = `DefSecAutMit Operator Console ${CONSOLE_VERSION}

Usage:
  node console/server.mjs --demo [--port 8787]
  node console/server.mjs --investigate-sock PATH (--token-file PATH | --token TOKEN)
                          [--enable-admin --admin-sock PATH] [--port 8787]

Options:
  --demo                     Serve realistic offline fixtures (no daemons needed)
  --demo-readonly            Demo mode with admin routes disabled
  --investigate-sock PATH    control-d investigation socket
  --token-file PATH          File holding the capability token (preferred)
  --token TOKEN              Capability token (visible in process listings!)
                             Env fallback: DEFSEC_CAPABILITY_TOKEN
  --admin-sock PATH          control-d admin socket
  --enable-admin             Allow the console to use the admin socket
  --host ADDR                Bind address (default 127.0.0.1)
  --port N                   Bind port (default 8787, 0 = ephemeral)
  --allowed-host H[:P]       Extra accepted Host header (repeatable)
  --timeout-ms N             Per-RPC socket timeout (default 5000)
  --quiet                    Disable access logging
  -h, --help                 Show this help
`;

export function parseArgs(argv, env = process.env) {
  const opts = { demo: false, demoReadonly: false, enableAdmin: false, host: '127.0.0.1', port: 8787, allowedHosts: [], timeoutMs: 5000, quiet: false };
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
      case '-h': case '--help': opts.help = true; break;
      default: throw new Error(`unknown argument: ${a}`);
    }
  }
  if (!Number.isInteger(opts.port) || opts.port < 0 || opts.port > 65535) throw new Error('--port must be 0..65535');
  if (opts.help || opts.demo) return opts;
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
  const warn = (m) => process.stderr.write(`\x1b[33mwarning:\x1b[0m ${m}\n`);
  if (!isLoopbackHost(opts.host)) {
    warn(`binding to non-loopback address ${opts.host}. The console has no user authentication;`);
    warn('anyone who can reach this port can read telemetry and use the capability token\'s scope.');
    if (!opts.allowedHosts.length) warn('add --allowed-host <name[:port]> for the address clients will use.');
  }
  if (opts.tokenSource === 'argv') warn('--token is visible in process listings; prefer --token-file or DEFSEC_CAPABILITY_TOKEN.');
  if (opts.tokenWorldReadable) warn(`token file ${opts.tokenFile} is readable by group/other; chmod 600 it.`);
  if (!opts.demo && opts.adminSock && !opts.enableAdmin) warn('--admin-sock given without --enable-admin; admin routes stay disabled.');

  const backend = backendFromOptions(opts);
  const app = createConsoleServer({
    backend,
    host: opts.host,
    port: opts.port,
    allowedHosts: opts.allowedHosts,
    log: opts.quiet ? () => {} : (line) => process.stderr.write(`${new Date().toISOString()} ${line}\n`),
  });
  const { url } = await app.listen();
  process.stdout.write(
    `DefSecAutMit console (${backend.mode} mode, admin ${backend.adminEnabled ? 'enabled' : 'disabled'}) listening on ${url}\n`,
  );
  const stop = () => app.close().then(() => process.exit(0));
  process.on('SIGINT', stop);
  process.on('SIGTERM', stop);
}

if (process.argv[1] && import.meta.url === pathToFileURL(path.resolve(process.argv[1])).href) {
  main();
}
