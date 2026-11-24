// Unix Domain Socket client for control-d's framed JSON RPC.
//
// Wire format (crates/protocol/src/wire.rs): every frame is a 4-byte
// big-endian uint32 length prefix followed by that many bytes of UTF-8 JSON.
// Frames of length 0 or larger than 2 MiB are rejected in both directions.

import net from 'node:net';
import { randomUUID } from 'node:crypto';

export const MAX_FRAME_BYTES = 2 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 5000;

export class FrameError extends Error {
  constructor(message) {
    super(message);
    this.name = 'FrameError';
  }
}

/** Encode one value as a length-prefixed JSON frame. */
export function encodeFrame(value) {
  const payload = Buffer.from(JSON.stringify(value), 'utf8');
  if (payload.length === 0 || payload.length > MAX_FRAME_BYTES) {
    throw new FrameError(`frame size ${payload.length} outside 1..=${MAX_FRAME_BYTES}`);
  }
  const header = Buffer.alloc(4);
  header.writeUInt32BE(payload.length, 0);
  return Buffer.concat([header, payload]);
}

/**
 * Incremental decoder: push arbitrary chunks, receive whole decoded frames.
 * Throws FrameError on an oversized/zero frame or malformed JSON.
 */
export class FrameDecoder {
  #buf = Buffer.alloc(0);

  push(chunk) {
    this.#buf = this.#buf.length ? Buffer.concat([this.#buf, chunk]) : chunk;
    const frames = [];
    while (this.#buf.length >= 4) {
      const len = this.#buf.readUInt32BE(0);
      if (len === 0 || len > MAX_FRAME_BYTES) {
        throw new FrameError(`frame size ${len} outside 1..=${MAX_FRAME_BYTES}`);
      }
      if (this.#buf.length < 4 + len) break;
      const body = this.#buf.subarray(4, 4 + len);
      this.#buf = this.#buf.subarray(4 + len);
      try {
        frames.push(JSON.parse(body.toString('utf8')));
      } catch {
        throw new FrameError('frame payload is not valid JSON');
      }
    }
    return frames;
  }

  get pending() {
    return this.#buf.length;
  }
}

/**
 * Send exactly one request frame over a fresh connection and resolve with the
 * first response frame. The connection is closed afterwards.
 */
export function udsRequest(socketPath, message, { timeoutMs = DEFAULT_TIMEOUT_MS } = {}) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const decoder = new FrameDecoder();
    const sock = net.createConnection({ path: socketPath });
    const finish = (err, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      sock.destroy();
      err ? reject(err) : resolve(value);
    };
    const timer = setTimeout(
      () => finish(new FrameError(`timed out after ${timeoutMs} ms waiting for ${socketPath}`)),
      timeoutMs,
    );
    sock.on('connect', () => {
      try {
        sock.write(encodeFrame(message));
      } catch (err) {
        finish(err);
      }
    });
    sock.on('data', (chunk) => {
      try {
        const frames = decoder.push(chunk);
        if (frames.length) finish(null, frames[0]);
      } catch (err) {
        finish(err);
      }
    });
    sock.on('error', (err) => finish(err));
    sock.on('end', () => finish(new FrameError('connection closed before a response frame arrived')));
  });
}

/**
 * Investigation RPC client. The capability token lives only in a private
 * field and is attached to outgoing frames; it is never returned, logged or
 * serialised by this object.
 */
export class InvestigationClient {
  #token;

  constructor({ socketPath, token, timeoutMs = DEFAULT_TIMEOUT_MS }) {
    if (!socketPath) throw new Error('investigation socket path is required');
    if (!token) throw new Error('capability token is required');
    this.socketPath = socketPath;
    this.timeoutMs = timeoutMs;
    this.#token = token;
  }

  async call(request) {
    const call = {
      request_id: `console-${randomUUID()}`,
      capability_token: this.#token,
      request,
    };
    return udsRequest(this.socketPath, call, { timeoutMs: this.timeoutMs });
  }

  toJSON() {
    return { socketPath: this.socketPath };
  }
}

/** Administrative RPC client (filesystem permissions are the authority). */
export class AdminClient {
  constructor({ socketPath, timeoutMs = DEFAULT_TIMEOUT_MS }) {
    if (!socketPath) throw new Error('admin socket path is required');
    this.socketPath = socketPath;
    this.timeoutMs = timeoutMs;
  }

  async call(request) {
    return udsRequest(this.socketPath, request, { timeoutMs: this.timeoutMs });
  }
}
