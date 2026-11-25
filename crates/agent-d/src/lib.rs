//! `agent-d`: the DefSecAutMit edge agent.
//!
//! Milestone 3 scope plus Phase 11 edge collectors:
//! - Six Ubuntu/Debian Linux snapshot/stream collectors
//!   (`sockets.listening`, `systemd.unit_state`, `files.metadata`,
//!   `journal.unit_events`, `connections.outbound`, `packages.inventory`)
//!   behind a single async `CollectorBackend` trait.
//! - `FakeHostCollectors`: deterministic in-process simulator for tests.
//! - Bounded observation spooling with `Minimal` (RAM) and `Durable` (disk)
//!   profiles and atomic metadata persistence.
//! - `AgentEngine`: signed watch bundle verification, hash-staggered
//!   scheduling, edge-lite diffing, sustained counters, heartbeats.
//! - Admin-owned host profile loading (`--profile`) that can only tighten
//!   the local edge safety floor.

pub mod collectors;
pub mod engine;
pub mod profile;
pub mod spool;

pub use collectors::{
    CollectorBackend, CollectorOutput, FakeCollectorCall, FakeHostCollectors, FakeHostState,
    RealLinuxCollectors,
};
pub use engine::{AgentEngine, EngineError, RECONCILIATION_INTERVAL_SECONDS};
pub use spool::{DurabilityProfile, ObservationSpool};

/// Read this process's resident set size in bytes from `/proc/self/statm`.
pub fn read_self_rss_bytes() -> Option<u64> {
    let statm = std::fs::read_to_string("/proc/self/statm").ok()?;
    let rss_pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
    Some(rss_pages.saturating_mul(4096))
}

/// Read the kernel boot id from `/proc/sys/kernel/random/boot_id`.
pub fn read_boot_id() -> Option<String> {
    let raw = std::fs::read_to_string("/proc/sys/kernel/random/boot_id").ok()?;
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}
