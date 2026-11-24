//! `action-exec-d` — the isolated, privileged mitigation executor for
//! DefSecAutMit (Phase 8).
//!
//! This process is the ONLY component permitted to change host state, and it
//! does so exclusively through a closed catalog of typed, TTL-bounded verbs:
//! no shell, no scripts, no model-generated commands. Every intent must carry
//! a valid `control-d` Ed25519 signature, and dual-signed verbs additionally
//! require an independent operator approval signature over the exact same
//! canonical intent bytes signed by a distinct key.
//!
//! Modules:
//! - [`driver`]: shell-free verb executors (`nft` / `systemctl` argv drivers,
//!   plus dry-run and test drivers).
//! - [`executor`]: signature verification, local policy floor, replay
//!   protection, TTL expiry and rollback receipts.
//! - [`replay`]: crash-safe nonce replay store (intent-before-effect).

pub mod driver;
pub mod executor;
pub mod replay;
