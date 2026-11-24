//! Domain-separated Ed25519 signing and verification over canonical JSON bytes.
//!
//! Envelopes carry exact signed UTF-8 canonical JSON bytes (`raw_payload`) so
//! receivers verify the signature before parsing and can persist the exact
//! signed bytes without re-serialization drift.

use std::collections::BTreeMap;

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;

use crate::canonical::{CanonicalError, sha256_hex, to_canonical_json_bytes};

pub const DOMAIN_WATCH_BUNDLE_V1: &str = "defsecautmit.watch_bundle.v1";
pub const DOMAIN_AUDIT_ENTRY_V1: &str = "defsecautmit.audit_entry.v1";
/// Reserved for Phase 8 gated remediation; never verified or dispatched in MVP.
pub const DOMAIN_ACTION_INTENT_V1: &str = "defsecautmit.action_intent.v1";

#[derive(Debug, Error)]
pub enum SigningError {
    #[error("canonicalization failed: {0}")]
    Canonical(#[from] CanonicalError),
    #[error("invalid key material: {0}")]
    InvalidKey(String),
    #[error("unknown signing key id: {0}")]
    UnknownKeyId(String),
    #[error("domain mismatch: expected {expected}, got {actual}")]
    DomainMismatch { expected: String, actual: String },
    #[error("invalid hex signature encoding: {0}")]
    InvalidSignatureEncoding(String),
    #[error("signature verification failed")]
    InvalidSignature,
    #[error("failed to decode verified payload JSON: {0}")]
    DecodePayload(#[from] serde_json::Error),
}

/// Ed25519 signing key paired with an explicit key identifier for rotation.
pub struct SigningKeyPair {
    key_id: String,
    signing_key: SigningKey,
}

impl SigningKeyPair {
    pub fn generate(key_id: impl Into<String>) -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self {
            key_id: key_id.into(),
            signing_key,
        }
    }

    pub fn from_secret_hex(key_id: impl Into<String>, secret_hex: &str) -> Result<Self, SigningError> {
        let bytes = hex::decode(secret_hex)
            .map_err(|e| SigningError::InvalidKey(format!("bad secret hex: {e}")))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| SigningError::InvalidKey("secret key must be 32 bytes".into()))?;
        Ok(Self {
            key_id: key_id.into(),
            signing_key: SigningKey::from_bytes(&arr),
        })
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn secret_hex(&self) -> String {
        hex::encode(self.signing_key.to_bytes())
    }

    pub fn public_hex(&self) -> String {
        hex::encode(self.signing_key.verifying_key().to_bytes())
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        self.signing_key.verifying_key()
    }

    /// Sign a serializable payload under an explicit domain separator.
    pub fn sign_payload<T: Serialize>(
        &self,
        domain: &str,
        payload: &T,
    ) -> Result<SignedEnvelope, SigningError> {
        let raw_bytes = to_canonical_json_bytes(payload)?;
        let raw_payload = String::from_utf8(raw_bytes)
            .map_err(|e| SigningError::InvalidKey(format!("non-utf8 canonical json: {e}")))?;
        let signing_input = build_signing_input(domain, raw_payload.as_bytes());
        let sig: Signature = self.signing_key.sign(&signing_input);
        Ok(SignedEnvelope {
            domain: domain.to_string(),
            signing_key_id: self.key_id.clone(),
            raw_payload,
            signature_hex: hex::encode(sig.to_bytes()),
        })
    }
}

/// Trust store holding trusted public verifying keys indexed by `key_id`.
#[derive(Debug, Default, Clone)]
pub struct VerifyingKeyStore {
    keys: BTreeMap<String, VerifyingKey>,
}

impl VerifyingKeyStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert_key(&mut self, key_id: impl Into<String>, key: VerifyingKey) {
        self.keys.insert(key_id.into(), key);
    }

    pub fn insert_public_hex(
        &mut self,
        key_id: impl Into<String>,
        public_hex: &str,
    ) -> Result<(), SigningError> {
        let bytes = hex::decode(public_hex)
            .map_err(|e| SigningError::InvalidKey(format!("bad public hex: {e}")))?;
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|_| SigningError::InvalidKey("public key must be 32 bytes".into()))?;
        let vk = VerifyingKey::from_bytes(&arr)
            .map_err(|e| SigningError::InvalidKey(format!("invalid ed25519 key: {e}")))?;
        self.keys.insert(key_id.into(), vk);
        Ok(())
    }

    pub fn get(&self, key_id: &str) -> Option<&VerifyingKey> {
        self.keys.get(key_id)
    }

    /// Verify envelope domain and Ed25519 signature over exact `raw_payload`
    /// bytes BEFORE deserializing the payload.
    pub fn verify_and_decode<T: DeserializeOwned>(
        &self,
        expected_domain: &str,
        envelope: &SignedEnvelope,
    ) -> Result<(T, String), SigningError> {
        if envelope.domain != expected_domain {
            return Err(SigningError::DomainMismatch {
                expected: expected_domain.to_string(),
                actual: envelope.domain.clone(),
            });
        }
        let vk = self
            .keys
            .get(&envelope.signing_key_id)
            .ok_or_else(|| SigningError::UnknownKeyId(envelope.signing_key_id.clone()))?;
        let sig_bytes = hex::decode(&envelope.signature_hex)
            .map_err(|e| SigningError::InvalidSignatureEncoding(e.to_string()))?;
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| SigningError::InvalidSignatureEncoding("signature must be 64 bytes".into()))?;
        let sig = Signature::from_bytes(&sig_arr);
        let signing_input = build_signing_input(&envelope.domain, envelope.raw_payload.as_bytes());
        vk.verify(&signing_input, &sig)
            .map_err(|_| SigningError::InvalidSignature)?;

        let payload_digest = sha256_hex(envelope.raw_payload.as_bytes());
        let decoded: T = serde_json::from_str(&envelope.raw_payload)?;
        Ok((decoded, payload_digest))
    }
}

/// Transport-independent signed envelope containing exact canonical JSON bytes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedEnvelope {
    pub domain: String,
    pub signing_key_id: String,
    /// Exact RFC 8785 canonical UTF-8 JSON bytes covered by `signature_hex`.
    pub raw_payload: String,
    pub signature_hex: String,
}

impl SignedEnvelope {
    pub fn payload_sha256_hex(&self) -> String {
        sha256_hex(self.raw_payload.as_bytes())
    }
}

fn build_signing_input(domain: &str, payload: &[u8]) -> Vec<u8> {
    let mut buf = Vec::with_capacity(domain.len() + 1 + payload.len());
    buf.extend_from_slice(domain.as_bytes());
    buf.push(0u8);
    buf.extend_from_slice(payload);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Sample {
        b: u32,
        a: String,
    }

    #[test]
    fn roundtrip_sign_and_verify() {
        let kp = SigningKeyPair::generate("control-key-01");
        let mut store = VerifyingKeyStore::new();
        store.insert_public_hex(kp.key_id(), &kp.public_hex()).unwrap();

        let payload = Sample {
            b: 42,
            a: "edge-vm-07".into(),
        };
        let env = kp.sign_payload(DOMAIN_WATCH_BUNDLE_V1, &payload).unwrap();
        assert_eq!(env.raw_payload, r#"{"a":"edge-vm-07","b":42}"#);

        let (decoded, digest): (Sample, String) =
            store.verify_and_decode(DOMAIN_WATCH_BUNDLE_V1, &env).unwrap();
        assert_eq!(decoded, payload);
        assert_eq!(digest, env.payload_sha256_hex());
    }

    #[test]
    fn rejects_tampered_payload_wrong_domain_and_unknown_key() {
        let kp = SigningKeyPair::generate("control-key-01");
        let mut store = VerifyingKeyStore::new();
        store.insert_key(kp.key_id(), kp.verifying_key());

        let payload = Sample { b: 1, a: "ok".into() };
        let env = kp.sign_payload(DOMAIN_WATCH_BUNDLE_V1, &payload).unwrap();

        // Wrong domain
        let err = store
            .verify_and_decode::<Sample>(DOMAIN_AUDIT_ENTRY_V1, &env)
            .unwrap_err();
        assert!(matches!(err, SigningError::DomainMismatch { .. }));

        // Tampered payload
        let mut tampered = env.clone();
        tampered.raw_payload = r#"{"a":"evil","b":1}"#.into();
        let err = store
            .verify_and_decode::<Sample>(DOMAIN_WATCH_BUNDLE_V1, &tampered)
            .unwrap_err();
        assert!(matches!(err, SigningError::InvalidSignature));

        // Unknown key
        let mut wrong_key = env;
        wrong_key.signing_key_id = "other-key".into();
        let err = store
            .verify_and_decode::<Sample>(DOMAIN_WATCH_BUNDLE_V1, &wrong_key)
            .unwrap_err();
        assert!(matches!(err, SigningError::UnknownKeyId(_)));
    }
}
