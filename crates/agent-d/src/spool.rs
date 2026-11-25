//! Bounded observation spooling and atomic metadata persistence.
//!
//! - `Minimal`: bounded RAM ring (`VecDeque`) within `max_ram_bytes`.
//! - `Durable`: bounded append-only NDJSON segment files under
//!   `state_dir/spool/` within `max_disk_bytes`, surviving restarts.
//!
//! On saturation, high-priority records (error / reconciliation) are
//! preserved where possible and `dropped_events_total` counts every eviction.
//! Retransmission is explicit: `pending()` returns unacknowledged records and
//! `prune_acked()` removes records with `seq_no <= acked_seq_no` for the
//! acknowledged session.

use std::collections::VecDeque;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use defsec_protocol::observation::ObservationRecord;
use serde::{Deserialize, Serialize};

/// Per-segment target size before rolling to a new segment file.
const SEGMENT_ROLL_BYTES: usize = 1024 * 1024;

/// Durability profile for the outbound observation buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DurabilityProfile {
    /// Fixed RAM ring; unacknowledged events may be lost on restart.
    Minimal {
        max_ram_bytes: usize,
    },
    /// Bounded append-only disk segments; survives agent restart.
    Durable {
        max_disk_bytes: usize,
    },
}

impl DurabilityProfile {
    pub fn cap_bytes(&self) -> usize {
        match self {
            Self::Minimal { max_ram_bytes } => *max_ram_bytes,
            Self::Durable { max_disk_bytes } => *max_disk_bytes,
        }
    }

    pub fn is_durable(&self) -> bool {
        matches!(self, Self::Durable { .. })
    }
}

/// Atomically write bytes to `path`:
/// temp file (0o600) in the same directory -> `sync_all` -> `rename`.
pub fn atomic_write(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir)?;
    let file_name = path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "state".to_string());
    let tmp = dir.join(format!(".{file_name}.tmp"));
    {
        let mut f = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    // Persist the rename itself where the platform allows it.
    if let Ok(dirfd) = File::open(dir) {
        let _ = dirfd.sync_all();
    }
    Ok(())
}

/// Atomically persist any serializable state file.
pub fn atomic_write_json<T: Serialize>(path: &Path, value: &T) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(value)
        .map_err(|e| std::io::Error::other(format!("serialization failed: {e}")))?;
    atomic_write(path, &bytes)
}

/// Load a previously persisted state file, if present and well-formed.
pub fn load_json<T: for<'de> Deserialize<'de>>(path: &Path) -> Option<T> {
    let bytes = std::fs::read(path).ok()?;
    serde_json::from_slice(&bytes).ok()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct SpooledRecord {
    seq_no: u64,
    session_id: String,
    encoded_len: usize,
    is_error: bool,
    is_reconciliation: bool,
    record: ObservationRecord,
}

/// Bounded outbound observation buffer.
pub struct ObservationSpool {
    profile: DurabilityProfile,
    dir: PathBuf,
    records: VecDeque<SpooledRecord>,
    bytes_used: usize,
    dropped_events_total: u64,
    next_segment_id: u64,
    current_segment_bytes: usize,
}

impl ObservationSpool {
    /// Create (or reload, for the Durable profile) the spool for a state dir.
    pub fn new(profile: DurabilityProfile, state_dir: &Path) -> std::io::Result<Self> {
        let dir = state_dir.join("spool");
        let mut spool = Self {
            profile,
            dir,
            records: VecDeque::new(),
            bytes_used: 0,
            dropped_events_total: 0,
            next_segment_id: 1,
            current_segment_bytes: 0,
        };
        if profile.is_durable() {
            spool.reload_from_disk()?;
        }
        Ok(spool)
    }

    fn reload_from_disk(&mut self) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        let mut segment_ids: Vec<u64> = Vec::new();
        for entry in std::fs::read_dir(&self.dir)? {
            let entry = entry?;
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let Some(stripped) = name.strip_prefix("seg-") else {
                // Clean up interrupted compaction temporaries.
                if name.ends_with(".tmp") {
                    let _ = std::fs::remove_file(entry.path());
                }
                continue;
            };
            let Some(id_str) = stripped.strip_suffix(".ndjson") else {
                continue;
            };
            if let Ok(id) = id_str.parse::<u64>() {
                segment_ids.push(id);
            }
        }
        segment_ids.sort_unstable();

        for id in segment_ids {
            let path = self.dir.join(format!("seg-{id:08}.ndjson"));
            let text = match std::fs::read_to_string(&path) {
                Ok(t) => t,
                Err(_) => continue,
            };
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() {
                    continue;
                }
                let Ok(record) = serde_json::from_str::<ObservationRecord>(line) else {
                    // Lost/unreadable record: count it honestly.
                    self.dropped_events_total += 1;
                    continue;
                };
                let encoded_len = line.len();
                self.bytes_used += encoded_len;
                self.records.push_back(SpooledRecord {
                    seq_no: record.seq_no,
                    session_id: record.session_id.clone(),
                    encoded_len,
                    is_error: !record.status.is_valid_sample(),
                    is_reconciliation: record.is_reconciliation,
                    record,
                });
            }
            self.next_segment_id = self.next_segment_id.max(id + 1);
        }
        // Enforce the cap on reload (crash may have left an over-full spool).
        self.evict_to_fit()?;
        Ok(())
    }

    /// Push a new observation record. For Durable, the record is appended and
    /// fsynced to the active segment before returning (durability guarantee).
    pub fn push(&mut self, record: ObservationRecord) -> std::io::Result<()> {
        let line = serde_json::to_vec(&record)
            .map_err(|e| std::io::Error::other(format!("serialization failed: {e}")))?;
        let spooled = SpooledRecord {
            seq_no: record.seq_no,
            session_id: record.session_id.clone(),
            encoded_len: line.len(),
            is_error: !record.status.is_valid_sample(),
            is_reconciliation: record.is_reconciliation,
            record,
        };
        self.bytes_used += spooled.encoded_len;
        self.records.push_back(spooled);

        if self.profile.is_durable() {
            self.append_segment(&line).inspect_err(|_| {
                // Roll back the in-memory push: the durability guarantee was
                // NOT satisfied, so the sequence must not advance silently.
                if let Some(back) = self.records.pop_back() {
                    self.bytes_used = self.bytes_used.saturating_sub(back.encoded_len);
                }
            })?;
        }

        self.evict_to_fit()?;
        Ok(())
    }

    fn append_segment(&mut self, line: &[u8]) -> std::io::Result<()> {
        if self.current_segment_bytes >= SEGMENT_ROLL_BYTES {
            self.next_segment_id += 1;
            self.current_segment_bytes = 0;
        }
        let path = self.dir.join(format!("seg-{:08}.ndjson", self.next_segment_id));
        let mut f = OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(&path)?;
        f.write_all(line)?;
        f.write_all(b"\n")?;
        f.sync_all()?;
        self.current_segment_bytes += line.len() + 1;
        Ok(())
    }

    /// Evict oldest records until within the byte cap, protecting error and
    /// reconciliation records where possible. Durable spills rewrite segments.
    fn evict_to_fit(&mut self) -> std::io::Result<()> {
        let cap = self.profile.cap_bytes();
        let mut evicted = false;
        while self.bytes_used > cap {
            let candidate = self
                .records
                .iter()
                .position(|r| !r.is_error && !r.is_reconciliation)
                .or(if self.records.is_empty() {
                    None
                } else {
                    Some(0)
                });
            let Some(idx) = candidate else {
                break;
            };
            if let Some(removed) = self.records.remove(idx) {
                self.bytes_used = self.bytes_used.saturating_sub(removed.encoded_len);
                self.dropped_events_total += 1;
                evicted = true;
            }
        }
        if evicted && self.profile.is_durable() {
            self.compact_disk()?;
        }
        Ok(())
    }

    /// Rewrite all live records into a single fresh segment and delete the
    /// old ones. Used after eviction and after ack pruning.
    fn compact_disk(&mut self) -> std::io::Result<()> {
        std::fs::create_dir_all(&self.dir)?;
        let old_ids: Vec<u64> = (1..self.next_segment_id).collect();
        self.next_segment_id += 1;
        self.current_segment_bytes = 0;
        let path = self.dir.join(format!("seg-{:08}.ndjson", self.next_segment_id));
        let tmp = self.dir.join(format!(".seg-{:08}.ndjson.tmp", self.next_segment_id));
        {
            let mut f = OpenOptions::new()
                .create(true)
                .write(true)
                .truncate(true)
                .mode(0o600)
                .open(&tmp)?;
            for record in &self.records {
                let line = serde_json::to_vec(&record.record)
                    .map_err(|e| std::io::Error::other(format!("serialization failed: {e}")))?;
                f.write_all(&line)?;
                f.write_all(b"\n")?;
                self.current_segment_bytes += line.len() + 1;
            }
            f.sync_all()?;
        }
        std::fs::rename(&tmp, &path)?;
        for id in old_ids {
            let _ = std::fs::remove_file(self.dir.join(format!("seg-{id:08}.ndjson")));
        }
        Ok(())
    }

    /// Remove records of `session_id` with `seq_no <= acked_seq_no`.
    /// Returns the number of records pruned.
    pub fn prune_acked(&mut self, session_id: &str, acked_seq_no: u64) -> std::io::Result<usize> {
        let mut removed_bytes = 0usize;
        let mut pruned = 0usize;
        self.records.retain(|r| {
            if r.session_id == session_id && r.seq_no <= acked_seq_no {
                removed_bytes += r.encoded_len;
                pruned += 1;
                false
            } else {
                true
            }
        });
        if pruned > 0 {
            self.bytes_used = self.bytes_used.saturating_sub(removed_bytes);
            if self.profile.is_durable() {
                self.compact_disk()?;
            }
        }
        Ok(pruned)
    }

    /// Pending unacknowledged observations in FIFO order (for retransmission).
    pub fn pending(&self) -> Vec<ObservationRecord> {
        self.records.iter().map(|r| r.record.clone()).collect()
    }

    pub fn dropped_events_total(&self) -> u64 {
        self.dropped_events_total
    }

    pub fn bytes_used(&self) -> usize {
        self.bytes_used
    }

    pub fn bytes_cap(&self) -> usize {
        self.profile.cap_bytes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use defsec_protocol::observation::ObservationStatus;
    use defsec_protocol::observation::ObservationPayload;
    use defsec_protocol::watch::CollectorType;

    fn record(seq: u64, session: &str, status: ObservationStatus, recon: bool) -> ObservationRecord {
        ObservationRecord {
            host_id: "edge-01".into(),
            session_id: session.into(),
            seq_no: seq,
            watch_id: "w1".into(),
            spec_version: 1,
            collector_type: CollectorType::SocketsListening,
            observed_at: chrono::Utc::now(),
            status,
            state_hash: format!("{seq:064x}"),
            payload: ObservationPayload::Snapshot {
                data: serde_json::json!({ "seq": seq }),
            },
            is_reconciliation: recon,
            sustained_count: None,
            sustained_active: None,
            partial_reasons: Vec::new(),
        }
    }

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join("agent-d-tests/spool").join(tag);
        std::fs::remove_dir_all(&dir).ok();
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn minimal_ram_ring_is_bounded_and_counts_drops() {
        let dir = temp_dir("minimal");
        let mut spool =
            ObservationSpool::new(DurabilityProfile::Minimal { max_ram_bytes: 1400 }, &dir).unwrap();

        for seq in 1..=10 {
            spool.push(record(seq, "s1", ObservationStatus::Ok, false)).unwrap();
        }
        // Each record is a few hundred bytes; the 1400-byte ring must have
        // evicted several of the oldest and counted them.
        assert!(spool.dropped_events_total() > 0);
        assert!(spool.bytes_used() <= 1400);
        let pending = spool.pending();
        assert!(!pending.is_empty());
        assert!(pending.len() < 10);
        // The newest records survive.
        assert_eq!(pending.last().unwrap().seq_no, 10);
        // Nothing is on disk for the Minimal profile.
        assert!(!dir.join("spool").exists());
    }

    #[test]
    fn minimal_ring_protects_error_and_reconciliation_records() {
        let dir = temp_dir("protect");
        let mut spool =
            ObservationSpool::new(DurabilityProfile::Minimal { max_ram_bytes: 1200 }, &dir).unwrap();

        // Protected records pushed FIRST (oldest) still survive saturation.
        spool.push(record(1, "s1", ObservationStatus::Error, false)).unwrap();
        spool.push(record(2, "s1", ObservationStatus::Ok, true)).unwrap();
        for seq in 3..=10 {
            spool.push(record(seq, "s1", ObservationStatus::Ok, false)).unwrap();
        }
        let pending = spool.pending();
        let seqs: Vec<u64> = pending.iter().map(|r| r.seq_no).collect();
        assert!(seqs.contains(&1), "error record must be protected: {seqs:?}");
        assert!(seqs.contains(&2), "reconciliation record must be protected: {seqs:?}");
        assert!(spool.dropped_events_total() > 0);
    }

    #[test]
    fn durable_spool_survives_restart_and_acks_prune() {
        let dir = temp_dir("durable");
        let profile = DurabilityProfile::Durable {
            max_disk_bytes: 1024 * 1024,
        };
        {
            let mut spool = ObservationSpool::new(profile, &dir).unwrap();
            spool.push(record(1, "s1", ObservationStatus::Ok, false)).unwrap();
            spool.push(record(2, "s1", ObservationStatus::Ok, false)).unwrap();
            spool.push(record(3, "s1", ObservationStatus::Ok, false)).unwrap();
        }
        // Simulate a crash: fresh spool instance from the same state dir.
        {
            let mut spool = ObservationSpool::new(profile, &dir).unwrap();
            let pending = spool.pending();
            assert_eq!(pending.len(), 3);
            assert_eq!(pending[0].seq_no, 1);

            // Ack seq 1..=2 of session s1.
            let pruned = spool.prune_acked("s1", 2).unwrap();
            assert_eq!(pruned, 2);
            assert_eq!(spool.pending().len(), 1);
            assert_eq!(spool.pending()[0].seq_no, 3);
        }
        // Another restart: the pruning must persist.
        {
            let spool = ObservationSpool::new(profile, &dir).unwrap();
            let pending = spool.pending();
            assert_eq!(pending.len(), 1, "pruned records must not resurrect");
            assert_eq!(pending[0].seq_no, 3);
        }
    }

    #[test]
    fn durable_overflow_counts_dropped_and_keeps_newest() {
        let dir = temp_dir("overflow");
        let profile = DurabilityProfile::Durable {
            max_disk_bytes: 1500,
        };
        let mut spool = ObservationSpool::new(profile, &dir).unwrap();
        for seq in 1..=8 {
            spool.push(record(seq, "s1", ObservationStatus::Ok, false)).unwrap();
        }
        assert!(spool.bytes_used() <= 1500);
        assert!(spool.dropped_events_total() > 0);
        let pending = spool.pending();
        assert!(!pending.is_empty());
        assert_eq!(pending.last().unwrap().seq_no, 8);
        // Restart: state consistent, drops already accounted.
        let spool2 = ObservationSpool::new(profile, &dir).unwrap();
        assert_eq!(spool2.pending().len(), pending.len());
    }

    #[test]
    fn ack_for_other_session_prunes_nothing() {
        let dir = temp_dir("sessions");
        let profile = DurabilityProfile::Durable {
            max_disk_bytes: 1024 * 1024,
        };
        let mut spool = ObservationSpool::new(profile, &dir).unwrap();
        spool.push(record(1, "s1", ObservationStatus::Ok, false)).unwrap();
        spool.push(record(1, "s2", ObservationStatus::Ok, false)).unwrap();
        let pruned = spool.prune_acked("s9", 99).unwrap();
        assert_eq!(pruned, 0);
        let pruned = spool.prune_acked("s1", 0).unwrap();
        assert_eq!(pruned, 0);
        let pruned = spool.prune_acked("s1", 1).unwrap();
        assert_eq!(pruned, 1);
        assert_eq!(spool.pending().len(), 1);
        assert_eq!(spool.pending()[0].session_id, "s2");
    }

    #[test]
    fn atomic_write_replaces_content_atomically() {
        let dir = temp_dir("atomic");
        let path = dir.join("state.json");
        atomic_write(&path, b"{\"v\":1}").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"{\"v\":1}");
        atomic_write(&path, b"{\"v\":2}").unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), b"{\"v\":2}");
        // No temp leftovers.
        let leftovers: Vec<_> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect();
        assert_eq!(leftovers.len(), 1);

        #[derive(Serialize, Deserialize, PartialEq, Debug)]
        struct St {
            v: u32,
        }
        atomic_write_json(&path, &St { v: 7 }).unwrap();
        let loaded: Option<St> = load_json(&path);
        assert_eq!(loaded, Some(St { v: 7 }));
        assert!(load_json::<St>(&dir.join("missing.json")).is_none());
    }
}
