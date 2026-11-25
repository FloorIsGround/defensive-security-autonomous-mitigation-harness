//! `AgentEngine`: signed bundle lifecycle, hash-staggered scheduling,
//! edge-lite diffing with sustained counters, and bounded spool emission.
//!
//! The engine is generic over [`CollectorBackend`] so integration tests can
//! drive it in-process with `FakeHostCollectors` (or the real Linux
//! collectors) and over any transport.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use defsec_policy::edge_floor::{
    BundleHighWaterMark, BundleValidationOutcome, EdgeSafetyConfig, validate_bundle,
    validate_cached_bundle,
};
use defsec_policy::predicate::SustainedCounterState;
use defsec_protocol::observation::{ObservationPayload, ObservationRecord, ObservationStatus};
use defsec_protocol::profile::HostProfileSummary;
use defsec_protocol::signing::{
    SignedEnvelope, VerifyingKeyStore, DOMAIN_WATCH_BUNDLE_V1,
};
use defsec_protocol::watch::{TriggerPredicate, WatchBundlePayload, WatchClass, WatchSpec};
use defsec_protocol::wire::{
    AgentResourceHealth, AgentToControl, BundleAckStatus, ControlToAgent, WatchRunSummary,
    WIRE_PROTOCOL_VERSION,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::Semaphore;

use crate::collectors::{CollectorBackend, CollectorOutput};
use crate::read_boot_id;
use crate::spool::{atomic_write_json, load_json, DurabilityProfile, ObservationSpool};

/// Default periodic full-reconciliation interval (design §5.1: ~15 minutes).
pub const RECONCILIATION_INTERVAL_SECONDS: i64 = 15 * 60;

const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const BUNDLE_FILE: &str = "bundle.signed.json";
const BUNDLE_HWM_FILE: &str = "bundle_hwm.json";
const AGENT_STATE_FILE: &str = "agent_state.json";
const CURSORS_FILE: &str = "cursors.json";

#[derive(Debug, Error)]
pub enum EngineError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("json error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Deterministic hash-staggered poll phase:
/// `sha256(host_id || 0x00 || watch_id) % interval_seconds`.
pub fn poll_phase(host_id: &str, watch_id: &str, interval_seconds: u64) -> u64 {
    crate::collectors::sockets::stagger_phase(host_id, watch_id, interval_seconds)
}

#[derive(Debug, Clone)]
struct ActiveBundle {
    payload: WatchBundlePayload,
    payload_digest: String,
}

/// Per-watch runtime state (run counters, diffing state, sustained counters).
struct WatchRuntime {
    spec: WatchSpec,
    completed_runs: u64,
    success_runs: u64,
    error_runs: u64,
    /// Ephemeral run budget consumption (survives restarts via agent_state).
    runs_executed: u64,
    last_status: ObservationStatus,
    last_run_at: Option<DateTime<Utc>>,
    last_success_at: Option<DateTime<Utc>>,
    retired: bool,
    next_due_unix: i64,
    last_hash: Option<String>,
    last_snapshot: Option<serde_json::Value>,
    sustained: SustainedCounterState,
}

impl WatchRuntime {
    fn new(
        spec: WatchSpec,
        now: &DateTime<Utc>,
        host_id: &str,
        persisted: Option<PersistedWatchRuntime>,
    ) -> Self {
        let phase = poll_phase(host_id, &spec.id, spec.schedule.interval_seconds);
        let mut rt = Self {
            next_due_unix: now.timestamp() + phase as i64,
            sustained: SustainedCounterState {
                spec_version: spec.version,
                consecutive_matches: 0,
                active: false,
            },
            spec,
            completed_runs: 0,
            success_runs: 0,
            error_runs: 0,
            runs_executed: 0,
            last_status: ObservationStatus::Ok,
            last_run_at: None,
            last_success_at: None,
            retired: false,
            last_hash: None,
            last_snapshot: None,
        };
        // Overlay persisted counters only for the identical spec version.
        if let Some(p) = persisted
            && p.spec_version == rt.spec.version
        {
            rt.completed_runs = p.completed_runs;
            rt.success_runs = p.success_runs;
            rt.error_runs = p.error_runs;
            rt.runs_executed = p.runs_executed;
            rt.last_status = p.last_status;
            rt.last_run_at = p.last_run_at;
            rt.last_success_at = p.last_success_at;
            rt.retired = p.retired;
            rt.sustained = p.sustained;
        }
        rt
    }

    fn to_persisted(&self) -> PersistedWatchRuntime {
        PersistedWatchRuntime {
            spec_version: self.spec.version,
            completed_runs: self.completed_runs,
            success_runs: self.success_runs,
            error_runs: self.error_runs,
            runs_executed: self.runs_executed,
            last_status: self.last_status,
            last_run_at: self.last_run_at,
            last_success_at: self.last_success_at,
            retired: self.retired,
            sustained: self.sustained.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedWatchRuntime {
    spec_version: u32,
    completed_runs: u64,
    success_runs: u64,
    error_runs: u64,
    runs_executed: u64,
    last_status: ObservationStatus,
    last_run_at: Option<DateTime<Utc>>,
    last_success_at: Option<DateTime<Utc>>,
    retired: bool,
    sustained: SustainedCounterState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedAgentState {
    schema_version: u32,
    session_id: String,
    previous_session_id: Option<String>,
    watch_runtime: BTreeMap<String, PersistedWatchRuntime>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedHwm {
    bundle_version: u64,
    payload_digest: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistedCursors {
    schema_version: u32,
    cursors: BTreeMap<String, String>,
}

/// The edge agent engine. Generic over the collector backend.
pub struct AgentEngine<C: CollectorBackend> {
    cfg: EdgeSafetyConfig,
    host_id: String,
    durability: DurabilityProfile,
    state_dir: PathBuf,
    store: VerifyingKeyStore,
    collector: Arc<C>,
    session_id: String,
    previous_session_id: Option<String>,
    next_seq_no: u64,
    active_bundle: Option<ActiveBundle>,
    cached_bundle_rejection: Option<AgentToControl>,
    hwm: Option<BundleHighWaterMark>,
    stale_desired_state: bool,
    boot_id: String,
    watches: BTreeMap<String, WatchRuntime>,
    cursors: BTreeMap<String, String>,
    last_reconciliation: BTreeMap<String, DateTime<Utc>>,
    reconcile_requested: BTreeSet<String>,
    spool: ObservationSpool,
    semaphore: Arc<Semaphore>,
    /// Summary of the admin-owned host profile applied at startup (if any);
    /// reported on Register for the control plane. Informational only.
    host_profile_summary: Option<HostProfileSummary>,
}

impl<C: CollectorBackend> AgentEngine<C> {
    /// Load persisted bundle, high-water mark, cursors, run counts, and
    /// spool; generate a fresh `session_id` (restart differentiation) and
    /// read the kernel boot id (with fallback).
    pub fn new(
        cfg: EdgeSafetyConfig,
        host_id: String,
        durability: DurabilityProfile,
        state_dir: PathBuf,
        store: VerifyingKeyStore,
        collector: Arc<C>,
    ) -> Result<Self, EngineError> {
        std::fs::create_dir_all(&state_dir)?;
        let now = Utc::now();

        // Session continuity: a new session per process start; remember the
        // previous one so RegisterAck can prune its spooled records.
        let persisted_state: Option<PersistedAgentState> =
            load_json(&state_dir.join(AGENT_STATE_FILE));
        let previous_session_id = persisted_state.as_ref().map(|s| s.session_id.clone());
        let session_id = uuid::Uuid::new_v4().to_string();
        let boot_id = read_boot_id().unwrap_or_else(|| "unknown-boot-id".to_string());

        // Cached verified bundle (verified BEFORE trusting it).
        let mut active_bundle: Option<ActiveBundle> = None;
        let mut hwm: Option<BundleHighWaterMark> = None;
        let mut cached_bundle_rejection = None;
        if let Some(envelope) = load_json::<SignedEnvelope>(&state_dir.join(BUNDLE_FILE))
            && let Ok((payload, digest)) = self_verify(&store, &envelope)
        {
            hwm = load_json::<PersistedHwm>(&state_dir.join(BUNDLE_HWM_FILE))
                .map(|p| BundleHighWaterMark {
                    bundle_version: p.bundle_version,
                    payload_digest: p.payload_digest,
                })
                .or_else(|| {
                    Some(BundleHighWaterMark {
                        bundle_version: payload.bundle_version,
                        payload_digest: digest.clone(),
                    })
                });
            match validate_cached_bundle(&payload, &host_id, &cfg, now) {
                Ok(()) => {
                    active_bundle = Some(ActiveBundle {
                        payload,
                        payload_digest: digest,
                    });
                }
                Err(error) => {
                    tracing::warn!(%error, bundle_version = payload.bundle_version, "cached bundle rejected");
                    cached_bundle_rejection = Some(AgentToControl::BundleAck {
                        host_id: host_id.clone(),
                        bundle_id: payload.bundle_id,
                        bundle_version: payload.bundle_version,
                        payload_digest: digest,
                        status: BundleAckStatus::Rejected,
                        reason: Some(format!("cached bundle rejected: {error}")),
                        acked_at: now,
                    });
                }
            }
        }

        // Journal cursors: durable profile only — cursors are checkpointed
        // strictly after the durability guarantee is satisfied.
        let cursors: BTreeMap<String, String> = if durability.is_durable() {
            load_json::<PersistedCursors>(&state_dir.join(CURSORS_FILE))
                .map(|p| p.cursors)
                .unwrap_or_default()
        } else {
            BTreeMap::new()
        };

        let spool = ObservationSpool::new(durability, &state_dir)?;

        // Watch runtimes from the active bundle, overlaid with persisted
        // run-count state so ephemeral max_runs/expires_at survive restarts.
        let persisted_runtime = persisted_state
            .map(|s| s.watch_runtime)
            .unwrap_or_default();
        let mut watches = BTreeMap::new();
        if let Some(bundle) = &active_bundle {
            for spec in &bundle.payload.watches {
                watches.insert(
                    spec.id.clone(),
                    WatchRuntime::new(
                        spec.clone(),
                        &now,
                        &host_id,
                        persisted_runtime.get(&spec.id).cloned(),
                    ),
                );
            }
        }

        // Preserve baseline monitoring while disconnected, but retire
        // ephemeral watches conservatively once the bundle itself expired.
        let mut stale_desired_state = cached_bundle_rejection.is_some();
        if let Some(bundle) = &active_bundle {
            let skew = cfg.max_clock_skew_seconds;
            if bundle.payload.expires_at + Duration::seconds(skew) < now {
                stale_desired_state = true;
                for rt in watches.values_mut() {
                    if rt.spec.class == WatchClass::Ephemeral {
                        rt.retired = true;
                    }
                }
            }
        }

        Ok(Self {
            semaphore: Arc::new(Semaphore::new(cfg.max_concurrent_collectors.max(1))),
            cfg,
            host_id,
            durability,
            state_dir,
            store,
            collector,
            session_id,
            previous_session_id,
            next_seq_no: 1,
            active_bundle,
            cached_bundle_rejection,
            hwm,
            stale_desired_state,
            boot_id,
            watches,
            cursors,
            last_reconciliation: BTreeMap::new(),
            reconcile_requested: BTreeSet::new(),
            spool,
            host_profile_summary: None,
        })
    }

    /// Attach the summary of an applied admin-owned host profile. Reported on
    /// Register; the control plane may ignore it.
    pub fn set_host_profile_summary(&mut self, summary: Option<HostProfileSummary>) {
        self.host_profile_summary = summary;
    }

    /// The applied host profile summary, if any (for tests and callers).
    pub fn host_profile_summary(&self) -> Option<&HostProfileSummary> {
        self.host_profile_summary.as_ref()
    }

    // ------------------------------------------------------------------
    // Introspection
    // ------------------------------------------------------------------

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn boot_id(&self) -> &str {
        &self.boot_id
    }

    pub fn stale_desired_state(&self) -> bool {
        self.stale_desired_state
    }

    pub fn active_bundle_version(&self) -> u64 {
        self.active_bundle
            .as_ref()
            .map(|b| b.payload.bundle_version)
            .unwrap_or(0)
    }

    pub fn active_bundle_digest(&self) -> Option<&str> {
        self.active_bundle
            .as_ref()
            .map(|b| b.payload_digest.as_str())
    }

    pub fn watch_ids(&self) -> Vec<String> {
        self.watches.keys().cloned().collect()
    }

    /// Pending unacknowledged observations (for retransmission on connect).
    pub fn pending_observations(&self) -> Vec<ObservationRecord> {
        self.spool.pending()
    }

    pub fn dropped_events_total(&self) -> u64 {
        self.spool.dropped_events_total()
    }

    // ------------------------------------------------------------------
    // Outbound message builders
    // ------------------------------------------------------------------

    pub fn make_register(&self, now: DateTime<Utc>) -> AgentToControl {
        AgentToControl::Register {
            protocol_version: WIRE_PROTOCOL_VERSION,
            host_id: self.host_id.clone(),
            agent_version: AGENT_VERSION.to_string(),
            boot_id: self.boot_id.clone(),
            session_id: self.session_id.clone(),
            active_bundle_version: self.active_bundle_version(),
            active_bundle_digest: self.active_bundle_digest().map(str::to_string),
            sent_at: now,
            host_profile: self.host_profile_summary.clone(),
        }
    }

    pub fn make_heartbeat(&self, now: DateTime<Utc>) -> AgentToControl {
        let watch_summaries: Vec<WatchRunSummary> = self
            .watches
            .values()
            .map(|rt| WatchRunSummary {
                watch_id: rt.spec.id.clone(),
                spec_version: rt.spec.version,
                completed_runs: rt.completed_runs,
                success_runs: rt.success_runs,
                error_runs: rt.error_runs,
                last_status: rt.last_status,
                last_run_at: rt.last_run_at,
                last_success_at: rt.last_success_at,
                sustained_count: rt.sustained.consecutive_matches,
                sustained_active: rt.sustained.active,
                retired: rt.retired,
            })
            .collect();
        let active_watches = self
            .watches
            .values()
            .filter(|rt| !rt.retired && rt.spec.lifecycle.enabled)
            .count() as u32;
        AgentToControl::Heartbeat {
            host_id: self.host_id.clone(),
            session_id: self.session_id.clone(),
            sent_at: now,
            active_bundle_version: self.active_bundle_version(),
            last_seq_no: self.next_seq_no.saturating_sub(1),
            dropped_events_total: self.spool.dropped_events_total(),
            stale_desired_state: self.stale_desired_state,
            health: AgentResourceHealth {
                rss_bytes: crate::read_self_rss_bytes(),
                spool_bytes_used: self.spool.bytes_used() as u64,
                spool_bytes_cap: self.spool.bytes_cap() as u64,
                active_watches,
                dropped_events_total: self.spool.dropped_events_total(),
            },
            watch_summaries,
        }
    }

    // ------------------------------------------------------------------
    // Control message handling
    // ------------------------------------------------------------------

    /// Handle one control-plane message; returns immediate replies.
    pub async fn handle_control(
        &mut self,
        msg: ControlToAgent,
        now: DateTime<Utc>,
    ) -> Vec<AgentToControl> {
        match msg {
            ControlToAgent::RegisterAck {
                accepted: true,
                last_acked_seq_no,
                ..
            } => {
                // The control plane durably committed up to this sequence
                // number of the PREVIOUS session; prune its spooled records.
                if let Some(prev) = self.previous_session_id.clone() {
                    let _ = self.spool.prune_acked(&prev, last_acked_seq_no);
                }
                self.cached_bundle_rejection.iter().cloned().collect()
            }
            ControlToAgent::RegisterAck {
                accepted: false, ..
            } => Vec::new(),
            ControlToAgent::ObservationAck {
                session_id,
                acked_seq_no,
                ..
            } => {
                // Advance the durable ack pointer and prune the spool.
                let _ = self.spool.prune_acked(&session_id, acked_seq_no);
                Vec::new()
            }
            ControlToAgent::RequestReconciliation { watch_ids, .. } => {
                if watch_ids.is_empty() {
                    // Empty list reconciles all active snapshot watches.
                    for (id, rt) in &self.watches {
                        if !rt.spec.collector.collector_type().is_stream() {
                            self.reconcile_requested.insert(id.clone());
                        }
                    }
                } else {
                    for id in watch_ids {
                        if let Some(rt) = self.watches.get(&id)
                            && !rt.spec.collector.collector_type().is_stream()
                        {
                            self.reconcile_requested.insert(id);
                        }
                    }
                }
                Vec::new()
            }
            ControlToAgent::SyncWatchBundle { envelope } => {
                vec![self.sync_bundle(envelope, now)]
            }
        }
    }

    fn sync_bundle(&mut self, envelope: SignedEnvelope, now: DateTime<Utc>) -> AgentToControl {
        let (payload, digest) = match self
            .store
            .verify_and_decode::<WatchBundlePayload>(DOMAIN_WATCH_BUNDLE_V1, &envelope)
        {
            Ok(v) => v,
            Err(e) => {
                return self.bundle_rejected(
                    &envelope,
                    format!("signature verification failed: {e}"),
                );
            }
        };

        match validate_bundle(
            &payload,
            &digest,
            &self.host_id,
            self.hwm.as_ref(),
            &self.cfg,
            now,
        ) {
            Ok(BundleValidationOutcome::IdenticalRetransmission)
                if self.active_bundle_digest() == Some(digest.as_str()) =>
            {
                AgentToControl::BundleAck {
                    host_id: self.host_id.clone(),
                    bundle_id: payload.bundle_id.clone(),
                    bundle_version: payload.bundle_version,
                    payload_digest: digest,
                    status: BundleAckStatus::AlreadyActive,
                    reason: Some("identical retransmission of active bundle".to_string()),
                    acked_at: now,
                }
            }
            Ok(_) => {
                let bundle_id = payload.bundle_id.clone();
                let bundle_version = payload.bundle_version;

                // Durable-then-activate: persist the exact signed bytes and
                // the new high-water mark BEFORE switching the watch set.
                if let Err(e) = atomic_write_json(&self.state_dir.join(BUNDLE_FILE), &envelope) {
                    return self.bundle_rejected(
                        &envelope,
                        format!("persisting bundle failed: {e}"),
                    );
                }
                if let Err(e) = atomic_write_json(
                    &self.state_dir.join(BUNDLE_HWM_FILE),
                    &PersistedHwm {
                        bundle_version,
                        payload_digest: digest.clone(),
                    },
                ) {
                    return self.bundle_rejected(
                        &envelope,
                        format!("persisting high-water mark failed: {e}"),
                    );
                }

                // Rebuild the watch set, preserving run-count state for
                // identical (version, collector, trigger) specs.
                let old_persisted: BTreeMap<String, PersistedWatchRuntime> = self
                    .watches
                    .iter()
                    .map(|(id, rt)| (id.clone(), rt.to_persisted()))
                    .collect();
                let mut new_watches = BTreeMap::new();
                for spec in &payload.watches {
                    let preserved = old_persisted.get(&spec.id).filter(|p| {
                        p.spec_version == spec.version
                            && self
                                .watches
                                .get(&spec.id)
                                .map(|rt| {
                                    rt.spec.collector == spec.collector
                                        && rt.spec.trigger == spec.trigger
                                })
                                .unwrap_or(false)
                    });
                    new_watches.insert(
                        spec.id.clone(),
                        WatchRuntime::new(spec.clone(), &now, &self.host_id, preserved.cloned()),
                    );
                }
                self.watches = new_watches;
                self.hwm = Some(BundleHighWaterMark {
                    bundle_version,
                    payload_digest: digest.clone(),
                });
                self.active_bundle = Some(ActiveBundle {
                    payload,
                    payload_digest: digest.clone(),
                });
                self.stale_desired_state = false;
                self.cached_bundle_rejection = None;
                self.reconcile_requested.clear();
                let _ = self.persist_agent_state();
                let _ = self.persist_cursors();

                AgentToControl::BundleAck {
                    host_id: self.host_id.clone(),
                    bundle_id,
                    bundle_version,
                    payload_digest: digest,
                    status: BundleAckStatus::Accepted,
                    reason: None,
                    acked_at: now,
                }
            }
            Err(e) => self.bundle_rejected(&envelope, e.to_string()),
        }
    }

    fn bundle_rejected(&self, envelope: &SignedEnvelope, reason: String) -> AgentToControl {
        // Best-effort bundle identity from the (unverified) envelope payload.
        let identity: Option<(String, u64)> =
            serde_json::from_str::<WatchBundlePayload>(&envelope.raw_payload)
                .ok()
                .map(|p| (p.bundle_id, p.bundle_version));
        AgentToControl::BundleAck {
            host_id: self.host_id.clone(),
            bundle_id: identity.as_ref().map(|(id, _)| id.clone()).unwrap_or_default(),
            bundle_version: identity.map(|(_, v)| v).unwrap_or(0),
            payload_digest: envelope.payload_sha256_hex(),
            status: BundleAckStatus::Rejected,
            reason: Some(reason),
            acked_at: Utc::now(),
        }
    }

    // ------------------------------------------------------------------
    // Scheduling and ticking
    // ------------------------------------------------------------------

    /// Run every due watch once. Returns emitted `PushObservationDelta`s.
    pub async fn run_due_watches(&mut self, now: DateTime<Utc>) -> Vec<AgentToControl> {
        let expiry_retired_any = self.refresh_bundle_expiry(now);

        let now_ts = now.timestamp();
        let due: Vec<String> = self
            .watches
            .iter()
            .filter(|(_, rt)| {
                !rt.retired && rt.spec.lifecycle.enabled && rt.next_due_unix <= now_ts
            })
            .map(|(id, _)| id.clone())
            .collect();

        let mut out = Vec::new();
        let mut state_changed = expiry_retired_any;
        for id in &due {
            match self.tick_watch(id, now).await {
                Ok(msgs) => {
                    state_changed = true;
                    out.extend(msgs);
                }
                Err(e) => {
                    // Persistence failure: keep monitoring; the spool holds
                    // the record for later retransmission.
                    tracing::warn!(watch = id, error = %e, "tick persistence failure");
                    state_changed = true;
                }
            }
        }
        if state_changed {
            let _ = self.persist_agent_state();
        }
        out
    }

    /// Flag stale desired state and retire ephemeral watches conservatively
    /// once the active bundle has expired (baseline monitoring continues).
    /// Returns whether any watch was retired.
    fn refresh_bundle_expiry(&mut self, now: DateTime<Utc>) -> bool {
        if self.stale_desired_state {
            return false;
        }
        let expired = self
            .active_bundle
            .as_ref()
            .map(|b| b.payload.expires_at + Duration::seconds(self.cfg.max_clock_skew_seconds) < now)
            .unwrap_or(false);
        if !expired {
            return false;
        }
        self.stale_desired_state = true;
        let mut retired_any = false;
        for rt in self.watches.values_mut() {
            if rt.spec.class == WatchClass::Ephemeral {
                rt.retired = true;
                retired_any = true;
            }
        }
        retired_any
    }

    /// Tick a single watch: enforce lifecycle bounds, run the collector under
    /// the concurrency semaphore and the watch timeout, update the sustained
    /// counter on every completed sample, and emit per the diffing rules.
    async fn tick_watch(
        &mut self,
        watch_id: &str,
        now: DateTime<Utc>,
    ) -> Result<Vec<AgentToControl>, EngineError> {
        // Lifecycle enforcement before any collection.
        {
            let Some(rt) = self.watches.get(watch_id) else {
                return Ok(Vec::new());
            };
            if rt.retired || !rt.spec.lifecycle.enabled {
                return Ok(Vec::new());
            }
            if rt.spec.class == WatchClass::Ephemeral {
                let expired = rt
                    .spec
                    .lifecycle
                    .expires_at
                    .map(|exp| now >= exp)
                    .unwrap_or(false);
                let exhausted = rt
                    .spec
                    .lifecycle
                    .max_runs
                    .map(|max| rt.runs_executed >= max)
                    .unwrap_or(false);
                if expired || exhausted {
                    if let Some(rt) = self.watches.get_mut(watch_id) {
                        rt.retired = true;
                    }
                    return Ok(Vec::new());
                }
            }
        }

        // Gather what we need without holding a mutable borrow across the
        // collector await.
        let (spec, timeout_dur, is_stream) = {
            let rt = self
                .watches
                .get(watch_id)
                .expect("watch existence checked above");
            (
                rt.spec.clone(),
                std::time::Duration::from_secs(rt.spec.schedule.timeout_seconds),
                rt.spec.collector.collector_type().is_stream(),
            )
        };
        let cursor = self.cursors.get(watch_id).cloned();

        // Concurrency ceiling across all in-flight collectors.
        let permit = self
            .semaphore
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| EngineError::Io(std::io::Error::other("semaphore closed")))?;
        let collector = self.collector.clone();
        let cfg_snapshot = self.cfg.clone();
        let collected = tokio::time::timeout(
            timeout_dur,
            collector.collect(&spec.collector, &cfg_snapshot, cursor.as_deref()),
        )
        .await;
        drop(permit);

        let output = match collected {
            Ok(output) => output,
            Err(_) => {
                tracing::warn!(
                    watch = watch_id,
                    timeout_seconds = spec.schedule.timeout_seconds,
                    "collector timed out"
                );
                let payload = ObservationPayload::ErrorDetail {
                    code: "collector_timeout".to_string(),
                    message: format!(
                        "collector exceeded timeout of {}s",
                        spec.schedule.timeout_seconds
                    ),
                };
                CollectorOutput {
                    status: ObservationStatus::Timeout,
                    state_hash: defsec_protocol::canonical::canonical_sha256_hex(&payload)
                        .unwrap_or_default(),
                    payload,
                    next_cursor: None,
                    partial_reasons: vec![format!(
                        "collector timed out after {}s",
                        spec.schedule.timeout_seconds
                    )],
                }
            }
        };

        // Update journal cursors whenever the collector advances them.
        if let Some(next_cursor) = &output.next_cursor {
            self.cursors.insert(watch_id.to_string(), next_cursor.clone());
        }

        let valid_sample = output.status.is_valid_sample();

        // Sustained counters advance on every completed sample, even when the
        // snapshot hash is unchanged.
        let mut sustained_transitioned = false;
        let mut sustained_count = None;
        let mut sustained_active = None;
        if let TriggerPredicate::ThresholdSustained {
            field,
            operator,
            threshold,
            consecutive_samples,
        } = &spec.trigger
        {
            let sample_value = match &output.payload {
                ObservationPayload::Snapshot { data } => Some(data.clone()),
                _ => None,
            };
            let (count, active) = {
                let rt = self.watches.get_mut(watch_id).expect("watch exists");
                sustained_transitioned = rt.sustained.record_sample(
                    spec.version,
                    output.status,
                    sample_value.as_ref(),
                    field,
                    *operator,
                    *threshold,
                    *consecutive_samples,
                );
                (rt.sustained.consecutive_matches, rt.sustained.active)
            };
            sustained_count = Some(count);
            sustained_active = Some(active);
        }

        // Runtime counters.
        {
            let rt = self.watches.get_mut(watch_id).expect("watch exists");
            rt.completed_runs += 1;
            rt.runs_executed += 1;
            rt.last_run_at = Some(now);
            rt.last_status = output.status;
            if valid_sample {
                rt.success_runs += 1;
                rt.last_success_at = Some(now);
            } else {
                rt.error_runs += 1;
            }
        }

        // Emission decision.
        let mut is_reconciliation = false;
        let emit = if is_stream {
            match &output.payload {
                ObservationPayload::StreamBatch {
                    events, gap_detected, ..
                } => {
                    // Streams always emit non-empty batches and gap events,
                    // even when identical text recurs.
                    !events.is_empty()
                        || *gap_detected
                        || self.reconcile_requested.contains(watch_id)
                }
                // Stream timeouts / collector errors must never be silently dropped.
                _ => !valid_sample,
            }
        } else if valid_sample {
            let recon_due = self
                .last_reconciliation
                .get(watch_id)
                .map(|t| (now - *t).num_seconds() >= RECONCILIATION_INTERVAL_SECONDS)
                .unwrap_or(true)
                || self.reconcile_requested.contains(watch_id);
            let hash_unchanged = {
                let rt = self.watches.get(watch_id).expect("watch exists");
                rt.last_hash.as_deref() == Some(output.state_hash.as_str())
            };
            if recon_due {
                is_reconciliation = true;
            }
            !hash_unchanged || recon_due || sustained_transitioned
        } else {
            // Errors, permission denials, timeouts, truncations: always
            // explicit, never suppressed into silence.
            true
        };

        // Update diffing state and advance the schedule.
        {
            let rt = self.watches.get_mut(watch_id).expect("watch exists");
            if valid_sample {
                if let ObservationPayload::Snapshot { data } = &output.payload {
                    rt.last_snapshot = Some(data.clone());
                }
                rt.last_hash = Some(output.state_hash.clone());
            }
            // Catch the schedule up without bursting missed intervals.
            let interval = rt.spec.schedule.interval_seconds.max(1) as i64;
            rt.next_due_unix += interval;
            while rt.next_due_unix <= now.timestamp() {
                rt.next_due_unix += interval;
            }
        }
        self.reconcile_requested.remove(watch_id);
        if is_reconciliation {
            self.last_reconciliation.insert(watch_id.to_string(), now);
        }

        if !emit {
            return Ok(Vec::new());
        }

        let seq_no = self.next_seq_no;
        self.next_seq_no += 1;
        let record = ObservationRecord {
            host_id: self.host_id.clone(),
            session_id: self.session_id.clone(),
            seq_no,
            watch_id: watch_id.to_string(),
            spec_version: spec.version,
            collector_type: spec.collector.collector_type(),
            observed_at: now,
            status: output.status,
            state_hash: output.state_hash,
            payload: output.payload,
            is_reconciliation,
            sustained_count,
            sustained_active,
            partial_reasons: output.partial_reasons,
        };

        // The spool push satisfies the durability guarantee (Durable syncs
        // the segment); only then may cursors be checkpointed.
        let to_send = record.clone();
        self.spool.push(record)?;
        let _ = self.persist_cursors();

        Ok(vec![AgentToControl::PushObservationDelta {
            observation: to_send,
        }])
    }

    // ------------------------------------------------------------------
    // Persistence
    // ------------------------------------------------------------------

    fn persist_agent_state(&self) -> Result<(), EngineError> {
        let mut watch_runtime = BTreeMap::new();
        for (id, rt) in &self.watches {
            watch_runtime.insert(id.clone(), rt.to_persisted());
        }
        let state = PersistedAgentState {
            schema_version: 1,
            session_id: self.session_id.clone(),
            previous_session_id: self.previous_session_id.clone(),
            watch_runtime,
        };
        atomic_write_json(&self.state_dir.join(AGENT_STATE_FILE), &state)?;
        Ok(())
    }

    /// Journal cursors are checkpointed only after the durability guarantee
    /// (spool sync) is satisfied, and only for the Durable profile: the
    /// Minimal profile must not pretend to checkpoint cursors it may lose.
    fn persist_cursors(&self) -> Result<(), EngineError> {
        if !self.durability.is_durable() {
            return Ok(());
        }
        let state = PersistedCursors {
            schema_version: 1,
            cursors: self.cursors.clone(),
        };
        atomic_write_json(&self.state_dir.join(CURSORS_FILE), &state)?;
        Ok(())
    }
}

/// Verify a persisted envelope against the trust store (used at startup).
fn self_verify(
    store: &VerifyingKeyStore,
    envelope: &SignedEnvelope,
) -> Result<(WatchBundlePayload, String), defsec_protocol::signing::SigningError> {
    store.verify_and_decode(DOMAIN_WATCH_BUNDLE_V1, envelope)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poll_phase_is_bounded_and_deterministic() {
        for interval in [15u64, 30, 60] {
            for w in ["w1", "w2", "w-socket-01"] {
                let phase = poll_phase("edge-01", w, interval);
                assert!(phase < interval);
                assert_eq!(phase, poll_phase("edge-01", w, interval));
            }
        }
        assert_eq!(poll_phase("h", "w", 0), 0);
    }
}
