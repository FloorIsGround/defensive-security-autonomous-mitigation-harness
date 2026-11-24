//! RFC 8785 JSON Canonicalization Scheme (JCS) and SHA-256 helpers.
//!
//! All cryptographically signed payloads and deterministic state hashes use
//! canonical UTF-8 JSON bytes independent of transport or wire encoding.

use serde::Serialize;
use serde_json::{Number, Value};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CanonicalError {
    #[error("failed to serialize value to JSON: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("non-finite floating point value is forbidden in canonical JSON")]
    NonFiniteNumber,
}

/// Serialize any `Serialize` type into RFC 8785 canonical JSON bytes.
pub fn to_canonical_json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>, CanonicalError> {
    let json_val = serde_json::to_value(value)?;
    let mut out = String::new();
    write_canonical_value(&json_val, &mut out)?;
    Ok(out.into_bytes())
}

/// Serialize a `serde_json::Value` into an RFC 8785 canonical JSON string.
pub fn value_to_canonical_json(value: &Value) -> Result<String, CanonicalError> {
    let mut out = String::new();
    write_canonical_value(value, &mut out)?;
    Ok(out)
}

/// Compute lowercase hex SHA-256 digest of raw bytes.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

/// Compute lowercase hex SHA-256 digest of the canonical JSON representation of `value`.
pub fn canonical_sha256_hex<T: Serialize>(value: &T) -> Result<String, CanonicalError> {
    let bytes = to_canonical_json_bytes(value)?;
    Ok(sha256_hex(&bytes))
}

fn write_canonical_value(value: &Value, out: &mut String) -> Result<(), CanonicalError> {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        Value::Number(n) => write_canonical_number(n, out)?,
        Value::String(s) => write_canonical_string(s, out),
        Value::Array(arr) => {
            out.push('[');
            for (idx, item) in arr.iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                write_canonical_value(item, out)?;
            }
            out.push(']');
        }
        Value::Object(map) => {
            // RFC 8785 Section 3.2.3: sort object keys by UTF-16 code units.
            let mut entries: Vec<(&String, &Value)> = map.iter().collect();
            entries.sort_by(|(a, _), (b, _)| a.encode_utf16().cmp(b.encode_utf16()));
            out.push('{');
            for (idx, (k, v)) in entries.into_iter().enumerate() {
                if idx > 0 {
                    out.push(',');
                }
                write_canonical_string(k, out);
                out.push(':');
                write_canonical_value(v, out)?;
            }
            out.push('}');
        }
    }
    Ok(())
}

fn write_canonical_number(n: &Number, out: &mut String) -> Result<(), CanonicalError> {
    if let Some(u) = n.as_u64() {
        out.push_str(&u.to_string());
        return Ok(());
    }
    if let Some(i) = n.as_i64() {
        out.push_str(&i.to_string());
        return Ok(());
    }
    let f = n.as_f64().ok_or(CanonicalError::NonFiniteNumber)?;
    if !f.is_finite() {
        return Err(CanonicalError::NonFiniteNumber);
    }
    if f == 0.0 {
        // RFC 8785: -0.0 serializes as "0".
        out.push('0');
        return Ok(());
    }
    // Format exact integer-valued floats without ".0" when within safe integer range.
    if f.fract() == 0.0 && f.abs() < 9_007_199_254_740_992.0 {
        out.push_str(&(f as i64).to_string());
        return Ok(());
    }
    // Use Rust's shortest round-trip representation (Ryū-backed).
    out.push_str(&f.to_string());
    Ok(())
}

fn write_canonical_string(s: &str, out: &mut String) {
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{0008}' => out.push_str("\\b"),
            '\u{0009}' => out.push_str("\\t"),
            '\u{000A}' => out.push_str("\\n"),
            '\u{000C}' => out.push_str("\\f"),
            '\u{000D}' => out.push_str("\\r"),
            c if (c as u32) < 0x20 => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn sorts_keys_by_utf16_code_units() {
        // RFC 8785 Section 3.2.3 example:
        // U+E000 (\u{e000}) vs U+1F600 (surrogate pair D83D DE00).
        // In UTF-8, U+E000 < U+1F600, whereas in UTF-16, 0xD83D < 0xE000.
        let val = json!({
            "\u{e000}": "private",
            "\u{1f600}": "emoji",
            "b": 2,
            "a": 1
        });
        let canon = value_to_canonical_json(&val).unwrap();
        assert_eq!(canon, "{\"a\":1,\"b\":2,\"\u{1f600}\":\"emoji\",\"\u{e000}\":\"private\"}");
    }

    #[test]
    fn escapes_control_characters_and_normalizes_neg_zero() {
        let val = json!({
            "ctrl": "\u{0001}\t\n\r\"\\",
            "zero": -0.0
        });
        let canon = value_to_canonical_json(&val).unwrap();
        assert_eq!(canon, "{\"ctrl\":\"\\u0001\\t\\n\\r\\\"\\\\\",\"zero\":0}");
    }

    #[test]
    fn identical_objects_with_different_key_order_have_identical_hash() {
        let v1: Value = serde_json::from_str(r#"{"z": 1, "a": [true, null, {"y": 2, "x": 3}]}"#).unwrap();
        let v2: Value = serde_json::from_str(r#"{"a": [true, null, {"x": 3, "y": 2}], "z": 1}"#).unwrap();
        assert_eq!(canonical_sha256_hex(&v1).unwrap(), canonical_sha256_hex(&v2).unwrap());
    }
}
