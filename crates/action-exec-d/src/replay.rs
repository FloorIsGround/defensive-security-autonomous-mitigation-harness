//! Crash-safe nonce replay protection.
//!
//! The store durably records `(nonce -> intent_id, executed_at)` BEFORE any
//! driver effect is dispatched, so a crash between recording and execution —
//! or any later retry with the same signed intent — can never execute the
//! same intent twice. Persistence is atomic (`0o600` temp file, `sync_all`,
//! `rename`) and survives restarts.

use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Filename of the persisted store inside the state directory.
const FILE_NAME: &str = "executed_nonces.json";
/// On-disk schema version; a mismatch fails closed as corruption.
const FILE_VERSION: u32 = 1;

#[derive(Debug, Error)]
pub enum ReplayStoreError {
    #[error("replay store io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("replay store serialization failed: {0}")]
    Serde(#[from] serde_json::Error),
    #[error("replay store corrupt: {0}")]
    Corrupt(String),
    #[error("nonce '{0}' was already recorded")]
    DuplicateNonce(String),
}

/// Attributable record of when a nonce was first accepted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NonceRecord {
    pub intent_id: String,
    pub executed_at: DateTime<Utc>,
}

#[derive(Debug, Serialize, Deserialize)]
struct PersistedStore {
    version: u32,
    nonces: BTreeMap<String, NonceRecord>,
}

/// Persistent `nonce -> record` map guarding against intent replay.
///
/// `record` commits the nonce to disk atomically BEFORE the caller dispatches
/// any host effect; a persistence failure rolls the in-memory insert back so
/// the store never claims durability it did not achieve.
#[derive(Debug)]
pub struct NonceReplayStore {
    path: PathBuf,
    nonces: BTreeMap<String, NonceRecord>,
}

impl NonceReplayStore {
    /// Open (or create) the store under `state_dir/executed_nonces.json`.
    ///
    /// A corrupt or version-mismatched file is a hard error: the executor must
    /// fail closed rather than silently forget already-executed nonces.
    pub fn open(state_dir: &Path) -> Result<Self, ReplayStoreError> {
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(state_dir)?;
        let path = state_dir.join(FILE_NAME);
        let nonces = if path.exists() {
            let raw = fs::read_to_string(&path)?;
            let parsed: PersistedStore = serde_json::from_str(&raw)
                .map_err(|e| ReplayStoreError::Corrupt(e.to_string()))?;
            if parsed.version != FILE_VERSION {
                return Err(ReplayStoreError::Corrupt(format!(
                    "unsupported store schema version {} (expected {FILE_VERSION})",
                    parsed.version
                )));
            }
            parsed.nonces
        } else {
            BTreeMap::new()
        };
        Ok(Self { path, nonces })
    }

    /// Returns `true` if the nonce has already been recorded.
    pub fn contains(&self, nonce: &str) -> bool {
        self.nonces.contains_key(nonce)
    }

    /// Atomically and durably record a nonce BEFORE dispatching its effect.
    ///
    /// Returns [`ReplayStoreError::DuplicateNonce`] if the nonce is already
    /// present; any persistence failure removes the tentative in-memory entry
    /// so the caller can safely reject the intent without a phantom record.
    pub fn record(
        &mut self,
        nonce: &str,
        intent_id: &str,
        executed_at: DateTime<Utc>,
    ) -> Result<(), ReplayStoreError> {
        if self.nonces.contains_key(nonce) {
            return Err(ReplayStoreError::DuplicateNonce(nonce.to_string()));
        }
        self.nonces.insert(
            nonce.to_string(),
            NonceRecord {
                intent_id: intent_id.to_string(),
                executed_at,
            },
        );
        if let Err(e) = self.persist() {
            self.nonces.remove(nonce);
            return Err(e);
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.nonces.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nonces.is_empty()
    }

    /// Atomic durable write: fresh `0o600` temp file in the same directory,
    /// `sync_all`, then `rename` over the live file.
    fn persist(&self) -> Result<(), ReplayStoreError> {
        use std::os::unix::fs::OpenOptionsExt;
        let bytes = serde_json::to_vec_pretty(&PersistedStore {
            version: FILE_VERSION,
            nonces: self.nonces.clone(),
        })?;
        let dir = self
            .path
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or_else(|| Path::new("."));
        let tmp = dir.join(format!(
            ".{FILE_NAME}.{}.tmp",
            uuid::Uuid::new_v4().simple()
        ));
        {
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&tmp)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
        }
        fs::rename(&tmp, &self.path)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "action-exec-replay-{tag}-{}",
            uuid::Uuid::new_v4()
        ));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn record_persists_and_survives_restart() {
        let dir = temp_dir("restart");
        let now = Utc::now();
        {
            let mut store = NonceReplayStore::open(&dir).unwrap();
            assert!(store.is_empty());
            store.record("nonce-1", "intent-1", now).unwrap();
            assert!(store.contains("nonce-1"));
            assert_eq!(store.len(), 1);
        }
        // Simulate a full process restart: reopen from disk.
        let reopened = NonceReplayStore::open(&dir).unwrap();
        assert!(reopened.contains("nonce-1"));
        assert_eq!(reopened.len(), 1);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn duplicate_nonce_is_rejected() {
        let dir = temp_dir("dup");
        let mut store = NonceReplayStore::open(&dir).unwrap();
        store.record("nonce-1", "intent-1", Utc::now()).unwrap();
        let err = store
            .record("nonce-1", "intent-2", Utc::now())
            .unwrap_err();
        assert!(matches!(err, ReplayStoreError::DuplicateNonce(_)));
        // The original record is untouched.
        let reopened = NonceReplayStore::open(&dir).unwrap();
        assert_eq!(reopened.len(), 1);
        let rec = &reopened.nonces["nonce-1"];
        assert_eq!(rec.intent_id, "intent-1");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn persisted_file_is_valid_json_with_mode_0600_and_no_temp_residue() {
        use std::os::unix::fs::PermissionsExt;
        let dir = temp_dir("perms");
        let mut store = NonceReplayStore::open(&dir).unwrap();
        store.record("nonce-a", "intent-a", Utc::now()).unwrap();
        store.record("nonce-b", "intent-b", Utc::now()).unwrap();

        let path = dir.join(FILE_NAME);
        let mode = fs::metadata(&path).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);

        let raw = fs::read_to_string(&path).unwrap();
        let parsed: PersistedStore = serde_json::from_str(&raw).unwrap();
        assert_eq!(parsed.version, FILE_VERSION);
        assert_eq!(parsed.nonces.len(), 2);

        // No leftover temp files from the atomic rename.
        let residue: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .filter(|n| n != FILE_NAME)
            .collect();
        assert!(residue.is_empty(), "unexpected residue: {residue:?}");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn corrupt_store_fails_closed() {
        let dir = temp_dir("corrupt");
        fs::write(dir.join(FILE_NAME), "not json at all").unwrap();
        let err = NonceReplayStore::open(&dir).unwrap_err();
        assert!(matches!(err, ReplayStoreError::Corrupt(_)));

        // Version mismatch is equally fatal.
        fs::write(
            dir.join(FILE_NAME),
            r#"{"version":99,"nonces":{}}"#,
        )
        .unwrap();
        assert!(matches!(
            NonceReplayStore::open(&dir),
            Err(ReplayStoreError::Corrupt(_))
        ));
        fs::remove_dir_all(&dir).unwrap();
    }
}
