// Access gate for the operator console.
//
// Three explicit modes:
//   none          No user authentication (default; meant for loopback binds).
//   local         Accounts in a 0600 JSON users file (scrypt + random salt),
//                 HMAC-signed server-tracked session cookies, per-IP login
//                 rate limiting.
//   proxy-header  Identity asserted by an OAuth2/OIDC reverse proxy (Caddy +
//                 Authelia/Authentik, oauth2-proxy, Tailscale serve, …). Headers
//                 are trusted ONLY when the TCP peer is a configured proxy IP;
//                 any other peer is refused outright.
//
// Roles: `observer` (read-only) and `admin` (admin routes + mutations).

import crypto from 'node:crypto';
import fs from 'node:fs';
import net from 'node:net';
import path from 'node:path';
import { promisify } from 'node:util';
import { ApiError } from './domain.mjs';

const scryptAsync = promisify(crypto.scrypt);

export const AUTH_MODES = Object.freeze(['none', 'local', 'proxy-header']);
export const ROLES = Object.freeze(['observer', 'admin']);
export const SESSION_COOKIE = 'dsc_session';
export const DEFAULT_SESSION_TTL_SECONDS = 8 * 3600;
export const DEFAULT_TRUSTED_PROXIES = Object.freeze(['127.0.0.1', '::1', '::ffff:127.0.0.1']);
export const MIN_PASSWORD_LENGTH = 12;
const MAX_PASSWORD_LENGTH = 1024;
const USERNAME_RE = /^[A-Za-z0-9][A-Za-z0-9._@-]{0,63}$/;
const HEADER_NAME_RE = /^[a-z0-9][a-z0-9-]{0,63}$/;
const SCRYPT = Object.freeze({ N: 16384, r: 8, p: 1, keylen: 64 });
const SCRYPT_MAXMEM = 128 * 1024 * 1024;
const SESSION_MAC_DOMAIN = 'defsecautmit.console.session.v1\0';

export const validUsername = (u) => typeof u === 'string' && USERNAME_RE.test(u);
export const validHeaderName = (h) => typeof h === 'string' && HEADER_NAME_RE.test(h);

// ---------------------------------------------------------------------------
// Passwords (scrypt, 16-byte random salt, constant-time comparison)
// ---------------------------------------------------------------------------

export function hashPassword(password) {
  const salt = crypto.randomBytes(16);
  const hash = crypto.scryptSync(String(password).normalize('NFC'), salt, SCRYPT.keylen, { ...SCRYPT, maxmem: SCRYPT_MAXMEM });
  return { algo: 'scrypt', N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p, salt: salt.toString('base64'), hash: hash.toString('base64') };
}

function sane(rec) {
  return (
    rec &&
    rec.algo === 'scrypt' &&
    Number.isInteger(rec.N) && rec.N >= 2 ** 14 && rec.N <= 2 ** 20 && (rec.N & (rec.N - 1)) === 0 &&
    Number.isInteger(rec.r) && rec.r >= 1 && rec.r <= 32 &&
    Number.isInteger(rec.p) && rec.p >= 1 && rec.p <= 16 &&
    typeof rec.salt === 'string' && typeof rec.hash === 'string'
  );
}

export async function verifyPassword(password, rec) {
  if (!sane(rec)) return false;
  const salt = Buffer.from(rec.salt, 'base64');
  const expected = Buffer.from(rec.hash, 'base64');
  if (salt.length < 16 || expected.length < 32 || expected.length > 128) return false;
  const got = await scryptAsync(String(password).normalize('NFC'), salt, expected.length, { N: rec.N, r: rec.r, p: rec.p, maxmem: SCRYPT_MAXMEM });
  return crypto.timingSafeEqual(got, expected);
}

let dummyRecord = null;
const dummy = () => (dummyRecord ??= hashPassword(crypto.randomBytes(24).toString('base64')));

/** Short fingerprint of the stored credential: a password reset or role change revokes sessions. */
const credentialFingerprint = (rec) => crypto.createHash('sha256').update(`${rec.role}\0${rec.hash}`).digest('base64url').slice(0, 22);

// ---------------------------------------------------------------------------
// Users file: { version: 1, users: { <name>: { role, algo, N, r, p, salt, hash, created_at, updated_at } } }
// ---------------------------------------------------------------------------

export function readUsersFile(file) {
  const data = JSON.parse(fs.readFileSync(file, 'utf8'));
  if (!data || data.version !== 1 || !data.users || typeof data.users !== 'object' || Array.isArray(data.users)) {
    throw new Error(`${file} is not a console users file (expected {"version":1,"users":{…}})`);
  }
  return data;
}

/** Write via a 0600 temp file in the same directory, fsync, then rename over the target. */
export function writeFileAtomic600(file, text) {
  const target = path.resolve(file);
  const dir = path.dirname(target);
  const tmp = path.join(dir, `.${path.basename(target)}.${crypto.randomBytes(6).toString('hex')}.tmp`);
  const fd = fs.openSync(tmp, 'wx', 0o600);
  try {
    fs.writeSync(fd, text);
    fs.fsyncSync(fd);
  } catch (err) {
    fs.closeSync(fd);
    fs.rmSync(tmp, { force: true });
    throw err;
  }
  fs.closeSync(fd);
  try {
    fs.chmodSync(tmp, 0o600);
    fs.renameSync(tmp, target);
  } catch (err) {
    fs.rmSync(tmp, { force: true });
    throw err;
  }
  try {
    const dfd = fs.openSync(dir, 'r');
    fs.fsyncSync(dfd);
    fs.closeSync(dfd);
  } catch {
    /* directory fsync is best effort */
  }
}

export function validatePassword(password) {
  if (typeof password !== 'string' || password.length < MIN_PASSWORD_LENGTH) {
    throw new Error(`password must be at least ${MIN_PASSWORD_LENGTH} characters`);
  }
  if (password.length > MAX_PASSWORD_LENGTH) throw new Error(`password must be at most ${MAX_PASSWORD_LENGTH} characters`);
}

/** Create or replace one account. Returns { created } (false = password/role reset). */
export function upsertUser(file, { username, role, password }, now = new Date()) {
  if (!validUsername(username)) throw new Error('username must be 1..64 chars of [A-Za-z0-9._@-], starting with a letter or digit');
  if (!ROLES.includes(role)) throw new Error(`role must be one of: ${ROLES.join(', ')}`);
  validatePassword(password);
  const data = fs.existsSync(file) ? readUsersFile(file) : { version: 1, users: {} };
  const prior = Object.hasOwn(data.users, username) ? data.users[username] : null;
  const stamp = now.toISOString();
  data.users[username] = { role, ...hashPassword(password), created_at: prior?.created_at ?? stamp, updated_at: stamp };
  writeFileAtomic600(file, `${JSON.stringify(data, null, 2)}\n`);
  return { created: !prior };
}

/** Users are re-read whenever the file changes, so `--create-user` takes effect without a restart. */
function createUserStore(file) {
  let users = new Map();
  let stamp = null;
  const reload = () => {
    let st;
    try {
      st = fs.statSync(file);
    } catch {
      users = new Map();
      stamp = null;
      return;
    }
    const key = `${st.ino}:${st.size}:${st.mtimeMs}`;
    if (key === stamp) return;
    try {
      const data = readUsersFile(file);
      users = new Map(Object.entries(data.users).filter(([name, rec]) => validUsername(name) && ROLES.includes(rec?.role)));
      stamp = key;
    } catch {
      /* keep the last good copy while a writer is mid-flight */
    }
  };
  reload();
  return {
    get(name) {
      reload();
      return users.get(name) ?? null;
    },
    get size() {
      reload();
      return users.size;
    },
  };
}

// ---------------------------------------------------------------------------
// Sessions: random 256-bit IDs, HMAC-SHA256 tagged, tracked server-side
// ---------------------------------------------------------------------------

function createSessionStore({ secret, ttlMs, now, max = 10_000 }) {
  const sessions = new Map();
  const mac = (id) => crypto.createHmac('sha256', secret).update(SESSION_MAC_DOMAIN).update(id).digest('base64url');
  const sweep = () => {
    const t = now();
    for (const [id, s] of sessions) if (s.expires <= t) sessions.delete(id);
    while (sessions.size >= max) sessions.delete(sessions.keys().next().value);
  };
  const parse = (token) => {
    if (typeof token !== 'string' || token.length > 200) return null;
    const dot = token.indexOf('.');
    if (dot !== 43) return null;
    const id = token.slice(0, dot);
    const given = Buffer.from(token.slice(dot + 1));
    const want = Buffer.from(mac(id));
    if (given.length !== want.length || !crypto.timingSafeEqual(given, want)) return null;
    return id;
  };
  return {
    create(data) {
      sweep();
      const id = crypto.randomBytes(32).toString('base64url');
      sessions.set(id, { ...data, created: now(), expires: now() + ttlMs });
      return `${id}.${mac(id)}`;
    },
    get(token) {
      const id = parse(token);
      if (!id) return null;
      const s = sessions.get(id);
      if (!s) return null;
      if (s.expires <= now()) {
        sessions.delete(id);
        return null;
      }
      return { id, ...s };
    },
    revoke(token) {
      const id = parse(token);
      return id ? sessions.delete(id) : false;
    },
    revokeId(id) {
      sessions.delete(id);
    },
    get size() {
      return sessions.size;
    },
  };
}

// ---------------------------------------------------------------------------
// Login rate limiting: sliding window of failures per client IP
// ---------------------------------------------------------------------------

export function createRateLimiter({ max = 10, windowMs = 5 * 60_000, maxKeys = 10_000, now = Date.now } = {}) {
  const fails = new Map();
  const live = (key, t) => {
    const list = (fails.get(key) ?? []).filter((ts) => t - ts < windowMs);
    if (list.length) fails.set(key, list);
    else fails.delete(key);
    return list;
  };
  return {
    check(key) {
      const t = now();
      const list = live(key, t);
      if (list.length < max) return { limited: false, retryAfterSeconds: 0 };
      return { limited: true, retryAfterSeconds: Math.max(1, Math.ceil((list[0] + windowMs - t) / 1000)) };
    },
    fail(key) {
      const t = now();
      const list = live(key, t);
      list.push(t);
      fails.delete(key);
      fails.set(key, list);
      while (fails.size > maxKeys) fails.delete(fails.keys().next().value);
    },
    reset(key) {
      fails.delete(key);
    },
  };
}

// ---------------------------------------------------------------------------
// Peer address matching (normalised IPv4 / IPv6 / IPv4-mapped, optional CIDR)
// ---------------------------------------------------------------------------

export function normalizeIp(addr) {
  if (!addr) return '';
  let a = String(addr).trim().toLowerCase();
  if (a.startsWith('[') && a.endsWith(']')) a = a.slice(1, -1);
  const zone = a.indexOf('%');
  if (zone >= 0) a = a.slice(0, zone);
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(a);
  return mapped ? mapped[1] : a;
}

const family = (ip) => (net.isIPv4(ip) ? 'ipv4' : net.isIPv6(ip) ? 'ipv6' : null);

export function createPeerMatcher(entries) {
  const list = new net.BlockList();
  for (const raw of entries) {
    const entry = String(raw).trim();
    if (!entry) continue;
    const [addr, prefix, extra] = entry.split('/');
    const ip = normalizeIp(addr);
    const fam = family(ip);
    if (!fam || extra !== undefined) throw new Error(`invalid trusted proxy address '${entry}'`);
    if (prefix === undefined) {
      list.addAddress(ip, fam);
    } else {
      const bits = Number(prefix);
      if (!Number.isInteger(bits) || bits < 0 || bits > (fam === 'ipv4' ? 32 : 128)) throw new Error(`invalid prefix in '${entry}'`);
      list.addSubnet(ip, bits, fam);
    }
  }
  return (addr) => {
    const ip = normalizeIp(addr);
    const fam = family(ip);
    return fam ? list.check(ip, fam) : false;
  };
}

function cookieValue(header, name) {
  if (!header) return null;
  for (const part of String(header).split(';')) {
    const eq = part.indexOf('=');
    if (eq > 0 && part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim();
  }
  return null;
}

const firstHeader = (req, name) => {
  const v = req.headers[name];
  return Array.isArray(v) ? v[0] : v;
};

// ---------------------------------------------------------------------------
// Gate
// ---------------------------------------------------------------------------

/**
 * @param {object} o
 * @param {'none'|'local'|'proxy-header'} [o.mode]
 * @param {string} [o.usersFile]               local mode
 * @param {number} [o.sessionTtlSeconds]
 * @param {Buffer|string} [o.sessionSecret]    HMAC key for session IDs (random when omitted)
 * @param {boolean} [o.secureCookies]          always add `Secure`
 * @param {string[]} [o.trustedProxyIps]
 * @param {boolean} [o.trustForwarded]         honour X-Forwarded-* from trusted peers (always on in proxy-header mode)
 * @param {string} [o.proxyUserHeader]
 * @param {string|null} [o.proxyRoleHeader]
 * @param {string|null} [o.proxyAdminGroup]
 * @param {'observer'|'admin'} [o.proxyDefaultRole]
 * @param {{max:number, windowMs:number}} [o.loginLimit]
 * @param {() => number} [o.now]
 */
export function createAuth({
  mode = 'none',
  usersFile = null,
  sessionTtlSeconds = DEFAULT_SESSION_TTL_SECONDS,
  sessionSecret = null,
  secureCookies = false,
  trustedProxyIps = DEFAULT_TRUSTED_PROXIES,
  trustForwarded = false,
  proxyUserHeader = 'x-forwarded-user',
  proxyRoleHeader = null,
  proxyAdminGroup = null,
  proxyDefaultRole = 'observer',
  loginLimit = { max: 10, windowMs: 5 * 60_000 },
  now = Date.now,
} = {}) {
  if (!AUTH_MODES.includes(mode)) throw new Error(`auth mode must be one of: ${AUTH_MODES.join(', ')}`);
  const isTrustedPeer = createPeerMatcher(trustedProxyIps);
  const forwardedTrusted = (req) => (mode === 'proxy-header' || trustForwarded) && isTrustedPeer(req.socket.remoteAddress);

  let users = null;
  let sessions = null;
  let limiter = null;
  const ttlSeconds = Math.max(60, Math.floor(sessionTtlSeconds));
  if (mode === 'local') {
    if (!usersFile) throw new Error('--auth-mode local requires --auth-users-file');
    users = createUserStore(usersFile);
    const secret = sessionSecret ? Buffer.from(sessionSecret) : crypto.randomBytes(32);
    if (secret.length < 32) throw new Error('session secret must be at least 32 bytes');
    sessions = createSessionStore({ secret, ttlMs: ttlSeconds * 1000, now });
    limiter = createRateLimiter({ ...loginLimit, now });
    dummy(); // precompute so the first unknown-user login costs the same as any other
  }
  if (mode === 'proxy-header') {
    if (!validHeaderName(proxyUserHeader)) throw new Error('invalid --proxy-user-header');
    if (proxyRoleHeader !== null && !validHeaderName(proxyRoleHeader)) throw new Error('invalid --proxy-role-header');
    if (proxyRoleHeader && !proxyAdminGroup) throw new Error('--proxy-role-header requires --proxy-admin-group');
    if (!ROLES.includes(proxyDefaultRole)) throw new Error(`--proxy-default-role must be one of: ${ROLES.join(', ')}`);
  }

  /** Client IP for rate limiting; X-Forwarded-For only counts from a trusted proxy. */
  const clientIp = (req) => {
    const peer = normalizeIp(req.socket.remoteAddress);
    if (!forwardedTrusted(req)) return peer;
    const xff = String(firstHeader(req, 'x-forwarded-for') ?? '').split(',').map((s) => normalizeIp(s)).filter(Boolean);
    return xff.at(-1) ?? peer;
  };

  const isHttps = (req) => secureCookies || (forwardedTrusted(req) && String(firstHeader(req, 'x-forwarded-proto') ?? '').toLowerCase() === 'https');

  const cookie = (req, value, maxAge) =>
    [`${SESSION_COOKIE}=${value}`, 'Path=/', 'HttpOnly', 'SameSite=Strict', `Max-Age=${maxAge}`, isHttps(req) ? 'Secure' : null].filter(Boolean).join('; ');

  function proxyIdentity(req) {
    const raw = firstHeader(req, proxyUserHeader);
    const name = typeof raw === 'string' ? raw.trim() : '';
    if (!name) return { user: null, error: { status: 401, code: 'proxy_identity_missing', message: `trusted proxy did not assert a user in ${proxyUserHeader}` } };
    if (name.length > 256 || /[\x00-\x1f\x7f,]/.test(name)) {
      return { user: null, error: { status: 401, code: 'proxy_identity_invalid', message: `${proxyUserHeader} is not a single printable identity` } };
    }
    let role = proxyDefaultRole;
    if (proxyRoleHeader) {
      const groups = String(firstHeader(req, proxyRoleHeader) ?? '').split(/[,;\s]+/).filter(Boolean);
      role = groups.includes(proxyAdminGroup) ? 'admin' : 'observer';
    }
    return { user: { username: name, role } };
  }

  function sessionIdentity(req) {
    const token = cookieValue(req.headers.cookie, SESSION_COOKIE);
    const s = token ? sessions.get(token) : null;
    if (!s) return { user: null, error: { status: 401, code: 'unauthenticated', message: 'sign in to use the console' } };
    const rec = users.get(s.username);
    // A removed account, password reset or role change ends existing sessions.
    if (!rec || credentialFingerprint(rec) !== s.fp) {
      sessions.revokeId(s.id);
      return { user: null, error: { status: 401, code: 'session_revoked', message: 'session ended because the account changed; sign in again' } };
    }
    return { user: { username: s.username, role: rec.role } };
  }

  return {
    mode,
    usersFile,

    /** proxy-header mode refuses every request whose TCP peer is not a trusted proxy. */
    peerAllowed(req) {
      return mode !== 'proxy-header' || isTrustedPeer(req.socket.remoteAddress);
    },

    /** -> { user } | { user: null, error } ; mode none yields { user: null } with no error. */
    identify(req) {
      if (mode === 'none') return { user: null };
      if (mode === 'proxy-header') return proxyIdentity(req);
      return sessionIdentity(req);
    },

    session(req) {
      const id = this.identify(req);
      if (mode === 'none') return { auth_mode: mode, authenticated: true, user: null };
      return { auth_mode: mode, authenticated: Boolean(id.user), user: id.user ?? null };
    },

    async login(req, body) {
      if (mode !== 'local') throw new ApiError(400, 'login_not_supported', `password sign-in is not used in auth mode '${mode}'`);
      const ip = clientIp(req);
      const gate = limiter.check(ip);
      if (gate.limited) {
        throw new ApiError(429, 'rate_limited', 'too many failed sign-in attempts; try again later', { headers: { 'Retry-After': String(gate.retryAfterSeconds) } });
      }
      const username = typeof body?.username === 'string' ? body.username.trim() : '';
      const password = typeof body?.password === 'string' ? body.password : '';
      const rec = validUsername(username) && password.length <= MAX_PASSWORD_LENGTH ? users.get(username) : null;
      // Always pay the scrypt cost so unknown usernames are not distinguishable by timing.
      const ok = (await verifyPassword(password.slice(0, MAX_PASSWORD_LENGTH), rec ?? dummy())) && rec !== null;
      if (!ok) {
        limiter.fail(ip);
        throw new ApiError(401, 'invalid_credentials', 'invalid username or password');
      }
      limiter.reset(ip);
      const token = sessions.create({ username, fp: credentialFingerprint(rec) });
      return { user: { username, role: rec.role }, setCookie: cookie(req, token, ttlSeconds), expires_in: ttlSeconds };
    },

    logout(req) {
      if (mode !== 'local') return { logged_out: false, setCookie: null };
      const token = cookieValue(req.headers.cookie, SESSION_COOKIE);
      const revoked = token ? sessions.revoke(token) : false;
      return { logged_out: revoked, setCookie: cookie(req, '', 0) };
    },

    describe() {
      if (mode === 'local') return `local accounts (${users.size} in ${usersFile}), session TTL ${Math.round(ttlSeconds / 60)} min`;
      if (mode === 'proxy-header') {
        const roles = proxyRoleHeader ? `role from ${proxyRoleHeader} (admin group '${proxyAdminGroup}')` : `all users ${proxyDefaultRole}`;
        return `reverse-proxy identity from ${proxyUserHeader}; ${roles}; trusted peers ${trustedProxyIps.join(', ')}`;
      }
      return 'none';
    },

    _sessions: () => sessions,
  };
}

/** Parse "28800", "8h", "30m", "90s" into seconds. */
export function parseDuration(text) {
  const m = /^(\d+)\s*([smhd]?)$/i.exec(String(text).trim());
  if (!m) throw new Error(`invalid duration '${text}' (use e.g. 8h, 30m, 3600)`);
  const n = Number(m[1]) * { '': 1, s: 1, m: 60, h: 3600, d: 86400 }[m[2].toLowerCase()];
  if (n < 60 || n > 30 * 86400) throw new Error('session TTL must be between 1 minute and 30 days');
  return n;
}
