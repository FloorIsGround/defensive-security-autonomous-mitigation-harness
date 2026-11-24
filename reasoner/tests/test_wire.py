"""Wire framing tests: 4-byte big-endian length-prefixed UTF-8 JSON."""

from __future__ import annotations

import json
import socket
import sys
import threading
from pathlib import Path

REASONER_ROOT = Path(__file__).resolve().parents[1]
if str(REASONER_ROOT) not in sys.path:
    sys.path.insert(0, str(REASONER_ROOT))

import unittest  # noqa: E402

from defsec_reasoner.wire import (  # noqa: E402
    MAX_FRAME_BYTES,
    FrameError,
    FrameTooLargeError,
    encode_frame,
    read_frame,
    read_exact,
    send_frame,
)


class TestFrameCodec(unittest.TestCase):
    def test_roundtrip_basic(self) -> None:
        message = {"op": "list_hosts", "limit": 5}
        frame = encode_frame(message)
        self.assertEqual(frame[:4], (len(frame) - 4).to_bytes(4, "big"))
        self.assertEqual(json.loads(frame[4:].decode()), message)

    def test_roundtrip_over_socketpair(self) -> None:
        a, b = socket.socketpair()
        with a, b:
            send_frame(a, {"msg": "register", "x": [1, 2, {"y": None}]})
            decoded = read_frame(b, timeout=5.0)
        self.assertEqual(decoded, {"msg": "register", "x": [1, 2, {"y": None}]})

    def test_multi_frame_streaming(self) -> None:
        a, b = socket.socketpair()
        with a, b:
            for i in range(5):
                send_frame(a, {"seq": i})
            for i in range(5):
                self.assertEqual(read_frame(b, timeout=5.0), {"seq": i})

    def test_utf8_payload(self) -> None:
        a, b = socket.socketpair()
        with a, b:
            send_frame(a, {"text": "ünïcödé → ok"})
            self.assertEqual(read_frame(b, timeout=5.0)["text"], "ünïcödé → ok")

    def test_encode_rejects_oversize(self) -> None:
        with self.assertRaises(FrameTooLargeError):
            encode_frame({"blob": "x" * (MAX_FRAME_BYTES + 1)})

    def test_read_rejects_zero_and_oversized_length(self) -> None:
        a, b = socket.socketpair()
        with a, b:
            a.sendall((0).to_bytes(4, "big"))
            with self.assertRaises(FrameTooLargeError):
                read_frame(b, timeout=5.0)
        a, b = socket.socketpair()
        with a, b:
            a.sendall((MAX_FRAME_BYTES + 1).to_bytes(4, "big"))
            with self.assertRaises(FrameTooLargeError):
                read_frame(b, timeout=5.0)

    def test_eof_midframe_raises(self) -> None:
        a, b = socket.socketpair()
        with a, b:
            payload = json.dumps({"k": 1}).encode()
            a.sendall(len(payload).to_bytes(4, "big") + payload[:3])
            a.close()
            with self.assertRaises(FrameError):
                read_frame(b, timeout=5.0)

    def test_clean_eof_before_header_is_none_frame(self) -> None:
        # read_exact raises FrameError on EOF; callers treat it as disconnect.
        a, b = socket.socketpair()
        with a, b:
            a.close()
            with self.assertRaises(FrameError):
                read_frame(b, timeout=5.0)

    def test_invalid_utf8_raises(self) -> None:
        a, b = socket.socketpair()
        with a, b:
            payload = b"\xff\xfe\xfa"
            a.sendall(len(payload).to_bytes(4, "big") + payload)
            with self.assertRaises(FrameError):
                read_frame(b, timeout=5.0)

    def test_send_frame_socket_error(self) -> None:
        a, b = socket.socketpair()
        a.close()
        b.close()
        with self.assertRaises(FrameError):
            send_frame(a, {"x": 1})

    def test_read_exact_partial(self) -> None:
        a, b = socket.socketpair()
        with a, b:

            def slow_write() -> None:
                a.sendall(b"ab")
                a.sendall(b"cd")

            threading.Thread(target=slow_write, daemon=True).start()
            self.assertEqual(read_exact(b, 4, timeout=5.0), b"abcd")


if __name__ == "__main__":
    unittest.main()
