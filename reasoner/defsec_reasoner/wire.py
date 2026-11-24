"""4-byte big-endian length-prefixed UTF-8 JSON framing.

Mirrors ``crates/protocol/src/wire.rs`` exactly:

* each frame is ``u32`` big-endian payload length followed by the payload,
* the payload is UTF-8 JSON,
* ``len == 0`` or ``len > MAX_FRAME_BYTES`` is a protocol violation,
* the maximum single frame payload is 2 MiB.
"""

from __future__ import annotations

import json
import socket
from typing import Any

#: Maximum permitted single wire frame payload size (2 MiB), matching
#: ``defsec_protocol::wire::MAX_FRAME_BYTES``.
MAX_FRAME_BYTES = 2 * 1024 * 1024


class FrameError(Exception):
    """Raised for framing or socket-level protocol violations."""


class FrameTooLargeError(FrameError):
    """A frame length of zero or a length above the 2 MiB ceiling."""

    def __init__(self, size: int, max_bytes: int = MAX_FRAME_BYTES) -> None:
        self.size = size
        self.max_bytes = max_bytes
        super().__init__(f"frame exceeds maximum size ({size} > {max_bytes})")


def encode_frame(message: Any, max_bytes: int = MAX_FRAME_BYTES) -> bytes:
    """Serialize ``message`` to JSON and wrap it in a length-prefixed frame."""
    payload = json.dumps(message, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    if len(payload) > max_bytes:
        raise FrameTooLargeError(len(payload), max_bytes)
    return len(payload).to_bytes(4, "big") + payload


def read_exact(sock: socket.socket, count: int, timeout: float | None = None) -> bytes:
    """Read exactly ``count`` bytes from ``sock`` or raise ``FrameError``."""
    if timeout is not None:
        sock.settimeout(timeout)
    chunks = bytearray()
    while len(chunks) < count:
        try:
            chunk = sock.recv(count - len(chunks))
        except socket.timeout as exc:  # pragma: no cover - timing dependent
            raise FrameError("timed out while reading a frame") from exc
        except OSError as exc:
            raise FrameError(f"socket error while reading a frame: {exc}") from exc
        if not chunk:
            raise FrameError("unexpected EOF while reading a frame")
        chunks.extend(chunk)
    return bytes(chunks)


def read_frame(sock: socket.socket, max_bytes: int = MAX_FRAME_BYTES, timeout: float | None = None) -> Any:
    """Read one length-prefixed JSON frame from ``sock`` and decode it."""
    header = read_exact(sock, 4, timeout=timeout)
    length = int.from_bytes(header, "big")
    if length == 0 or length > max_bytes:
        raise FrameTooLargeError(length, max_bytes)
    payload = read_exact(sock, length, timeout=timeout)
    try:
        return json.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise FrameError(f"frame payload is not valid UTF-8 JSON: {exc}") from exc


def send_frame(sock: socket.socket, message: Any, max_bytes: int = MAX_FRAME_BYTES) -> None:
    """Encode and write one frame to ``sock``."""
    try:
        sock.sendall(encode_frame(message, max_bytes))
    except FrameTooLargeError:
        raise
    except OSError as exc:
        raise FrameError(f"socket error while writing a frame: {exc}") from exc
