"""RFC 8785 (JCS) canonical JSON and SHA-256 helpers.

Python port of the subset of ``crates/protocol/src/canonical.rs`` needed by
the reasoning plane and the synthetic benchmark harness:

* object keys sorted by UTF-16 code units,
* strings escaped exactly like the Rust implementation
  (``"``, ``\\`` and control characters with the JSON short escapes),
* integers serialized verbatim; non-integral floats rejected
  (the monitoring contracts only ever hash integers, strings, booleans,
  ``null`` and arrays/objects of those),
* ``sha256_hex`` / ``canonical_sha256_hex`` producing the same lowercase hex
  digests the Rust ledger computes for observation ``state_hash`` values.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

__all__ = ["canonical_json", "sha256_hex", "canonical_sha256_hex", "CanonicalizationError"]

_MAX_SAFE_INTEGER = 9_007_199_254_740_992  # 2**53


class CanonicalizationError(ValueError):
    """Raised for values that cannot be represented in canonical JSON."""


def _canonical_number(value: Any) -> str:
    if isinstance(value, bool):  # bool is an int subclass; handled by caller
        raise CanonicalizationError("bools are not numbers here")
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if value != value or value in (float("inf"), float("-inf")):
            raise CanonicalizationError("non-finite floating point value is forbidden")
        if value == 0.0:  # RFC 8785: -0.0 serializes as "0".
            return "0"
        if value.is_integer() and abs(value) < _MAX_SAFE_INTEGER:
            return str(int(value))
        raise CanonicalizationError(
            "non-integral floats are outside the supported canonical JSON subset"
        )
    raise CanonicalizationError(f"unsupported number type: {type(value).__name__}")


def _canonical_string(value: str) -> str:
    # json.dumps matches the Rust escaper for ASCII-range data:
    # only '"', '\\' and control characters are escaped, with \b \t \n \f \r
    # shortcuts and lowercase \u00xx for other control characters.
    return json.dumps(value, ensure_ascii=False)


def _sort_key(key: str) -> bytes:
    # RFC 8785 section 3.2.3: sort by UTF-16 code units. Comparing UTF-16-BE
    # byte sequences is equivalent to comparing UTF-16 code unit sequences.
    return key.encode("utf-16-be")


def canonical_json(value: Any) -> str:
    """Serialize ``value`` to an RFC 8785 canonical JSON string."""
    if value is None:
        return "null"
    if value is True:
        return "true"
    if value is False:
        return "false"
    if isinstance(value, str):
        return _canonical_string(value)
    if isinstance(value, (int, float)):
        return _canonical_number(value)
    if isinstance(value, (list, tuple)):
        return "[" + ",".join(canonical_json(item) for item in value) + "]"
    if isinstance(value, dict):
        entries = sorted(value.items(), key=lambda kv: _sort_key(kv[0]))
        out = []
        for key, item in entries:
            if not isinstance(key, str):
                raise CanonicalizationError("canonical JSON object keys must be strings")
            out.append(_canonical_string(key) + ":" + canonical_json(item))
        return "{" + ",".join(out) + "}"
    raise CanonicalizationError(f"unsupported value type: {type(value).__name__}")


def sha256_hex(data: bytes) -> str:
    """Lowercase hex SHA-256 digest of raw bytes."""
    return hashlib.sha256(data).hexdigest()


def canonical_sha256_hex(value: Any) -> str:
    """Lowercase hex SHA-256 digest of the canonical JSON of ``value``."""
    return sha256_hex(canonical_json(value).encode("utf-8"))
