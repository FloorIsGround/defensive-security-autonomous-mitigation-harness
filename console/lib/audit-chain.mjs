// Independent re-verification of control-d's hash-chained audit outbox.
//
// Mirrors crates/protocol/src/{canonical,audit}.rs:
//   entry_hash = sha256("defsecautmit.audit_entry.v1\0" || RFC8785(body))
// where body is the entry without `entry_hash`. The console recomputes every
// returned entry so the operator does not have to trust a single "valid" flag.

import { createHash } from 'node:crypto';

export const GENESIS_PREV_HASH = '0'.repeat(64);
const DOMAIN = Buffer.from('defsecautmit.audit_entry.v1\0', 'utf8');

function utf16Compare(a, b) {
  // JS strings are UTF-16; plain comparison orders by code units (RFC 8785 §3.2.3).
  return a < b ? -1 : a > b ? 1 : 0;
}

/** RFC 8785 canonical JSON for values produced by control-d (integers, strings, objects). */
export function canonicalJson(value) {
  if (value === null) return 'null';
  switch (typeof value) {
    case 'boolean':
      return value ? 'true' : 'false';
    case 'number':
      if (!Number.isFinite(value)) throw new Error('non-finite number');
      return Object.is(value, -0) ? '0' : JSON.stringify(value);
    case 'string':
      return JSON.stringify(value);
    case 'object': {
      if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
      const keys = Object.keys(value).sort(utf16Compare);
      return `{${keys.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
    }
    default:
      throw new Error(`unsupported JSON type ${typeof value}`);
  }
}

export function sha256Hex(data) {
  return createHash('sha256').update(data).digest('hex');
}

export function computeAuditHash(entry) {
  const body = {
    seq_no: entry.seq_no,
    timestamp: entry.timestamp,
    prev_hash: entry.prev_hash,
    event_type: entry.event_type,
    actor: entry.actor,
    request_id: entry.request_id,
    payload: entry.payload,
  };
  return sha256Hex(Buffer.concat([DOMAIN, Buffer.from(canonicalJson(body), 'utf8')]));
}

/**
 * Verify a contiguous (possibly windowed) run of entries. If the window does
 * not start at seq 1, the first entry's prev_hash is accepted as the anchor.
 * Returns { valid, checked, first_seq, last_seq, head, error, broken_seq }.
 */
export function verifyEntries(entries) {
  const out = { valid: true, checked: 0, first_seq: null, last_seq: null, head: null, error: null, broken_seq: null };
  if (!entries.length) return out;
  let prev = entries[0].seq_no === 1 ? GENESIS_PREV_HASH : entries[0].prev_hash;
  let nextSeq = entries[0].seq_no;
  out.first_seq = entries[0].seq_no;
  for (const entry of entries) {
    const fail = (msg) => {
      out.valid = false;
      out.error = msg;
      out.broken_seq = entry.seq_no;
      return out;
    };
    if (entry.seq_no !== nextSeq) return fail(`sequence gap: expected ${nextSeq}, got ${entry.seq_no}`);
    if (entry.prev_hash !== prev) return fail(`broken link at seq ${entry.seq_no}: prev_hash does not match previous entry_hash`);
    let recomputed;
    try {
      recomputed = computeAuditHash(entry);
    } catch (err) {
      return fail(`canonicalization error at seq ${entry.seq_no}: ${err.message}`);
    }
    if (recomputed !== entry.entry_hash) return fail(`tampered entry at seq ${entry.seq_no}: recomputed hash differs`);
    prev = entry.entry_hash;
    nextSeq += 1;
    out.checked += 1;
    out.last_seq = entry.seq_no;
    out.head = entry.entry_hash;
  }
  return out;
}
