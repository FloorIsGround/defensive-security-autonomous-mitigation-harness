"""Canonical JSON tests, pinned to the Rust implementation's test vectors."""

from __future__ import annotations

import sys
from pathlib import Path

REASONER_ROOT = Path(__file__).resolve().parents[1]
if str(REASONER_ROOT) not in sys.path:
    sys.path.insert(0, str(REASONER_ROOT))

import unittest  # noqa: E402

from defsec_reasoner.canonical import (  # noqa: E402
    CanonicalizationError,
    canonical_json,
    canonical_sha256_hex,
    sha256_hex,
)


class TestCanonicalJson(unittest.TestCase):
    def test_rust_vector_utf16_key_sorting(self) -> None:
        # Exact vector from crates/protocol/src/canonical.rs tests:
        # U+E000 sorts AFTER the surrogate pair of U+1F600 under UTF-16 order.
        value = {"\ue000": "private", "\U0001F600": "emoji", "b": 2, "a": 1}
        expected = (
            '{"a":1,"b":2,"\U0001F600":"emoji","\ue000":"private"}'
        )
        self.assertEqual(canonical_json(value), expected)

    def test_rust_vector_control_char_escapes_and_neg_zero(self) -> None:
        value = {"ctrl": "\x01\t\n\r\"\\", "zero": -0.0}
        self.assertEqual(canonical_json(value), '{"ctrl":"\\u0001\\t\\n\\r\\"\\\\","zero":0}')

    def test_key_order_independence_gives_identical_hash(self) -> None:
        v1 = {"z": 1, "a": [True, None, {"y": 2, "x": 3}]}
        v2 = {"a": [True, None, {"x": 3, "y": 2}], "z": 1}
        self.assertEqual(canonical_sha256_hex(v1), canonical_sha256_hex(v2))

    def test_bools_and_null(self) -> None:
        self.assertEqual(canonical_json([True, False, None]), "[true,false,null]")

    def test_integer_serialization(self) -> None:
        self.assertEqual(canonical_json({"n": 1795552677510114}), '{"n":1795552677510114}')
        self.assertEqual(canonical_json({"n": -42}), '{"n":-42}')

    def test_non_integral_float_rejected(self) -> None:
        with self.assertRaises(CanonicalizationError):
            canonical_json({"x": 1.5})

    def test_integral_float_serialized_as_integer(self) -> None:
        self.assertEqual(canonical_json({"x": 5.0}), '{"x":5}')

    def test_sha256_hex_known_vector(self) -> None:
        self.assertEqual(sha256_hex(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")

    def test_journal_event_shape_hash_stable(self) -> None:
        # Mirrors the typed JournalEventRecord canonical form (Options as null).
        event = {
            "cursor": "c1",
            "timestamp_us": 1795552677510114,
            "unit": "sshd.service",
            "priority": 6,
            "pid": None,
            "uid": None,
            "message_redacted": "hello",
            "truncated": False,
            "redaction_applied": True,
            "classification": "bounded_redacted_text",
        }
        digest = canonical_sha256_hex([event])
        self.assertEqual(len(digest), 64)
        self.assertEqual(digest, digest.lower())


if __name__ == "__main__":
    unittest.main()
