//! Shell-free mitigation drivers.
//!
//! The [`ActionDriver`] trait maps a validated [`ActionIntentPayload`] verb
//! onto either a pure simulation ([`DryRunDriver`]), a scripted test double
//! ([`FakeActionDriver`]), or real host effects ([`LinuxActionDriver`]).
//!
//! The Linux driver never invokes a shell and never resolves binaries through
//! `PATH`: it executes the fixed paths `/usr/sbin/nft` and
//! `/usr/bin/systemctl` with strictly static, allowlisted argv vectors built
//! from already-validated typed fields. nftables IP blocks live in a
//! dedicated table with kernel-enforced element timeouts (`flags timeout`), so
//! TTL expiry does not depend on this process staying alive; host isolation
//! lives in a dedicated table whose management-CIDR accept rules are always
//! inserted above the terminal drop rule, and whose rollback deletes the whole
//! table.

use std::future::Future;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use defsec_policy::action_gate::is_valid_cidr;
use defsec_policy::edge_floor::validate_systemd_unit_name;
use defsec_protocol::action::{ActionIntentPayload, ActionVerb, TrafficDirection};
use tokio::process::Command;

/// Fixed nftables binary path; never resolved through `PATH`.
pub const NFT_BIN: &str = "/usr/sbin/nft";
/// Fixed systemd control binary path; never resolved through `PATH`.
pub const SYSTEMCTL_BIN: &str = "/usr/bin/systemctl";

/// Dedicated nftables table holding time-bounded IP blocks.
const BLOCK_TABLE: &str = "defsecautmit";
/// Dedicated nftables table for host isolation; rollback deletes it wholesale.
const ISOLATE_TABLE: &str = "defsecautmit_isolate";
const V4_SET: &str = "blocked_v4";
const V6_SET: &str = "blocked_v6";
const INPUT_CHAIN: &str = "input_hook";
const OUTPUT_CHAIN: &str = "output_hook";
const ISOLATE_INPUT_CHAIN: &str = "isolate_input";
const ISOLATE_OUTPUT_CHAIN: &str = "isolate_output";

/// Result of one driver execution attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DriverExecution {
    /// `true` when the host was not mutated (simulation).
    pub dry_run: bool,
    /// Opaque handle the driver later needs to roll the effect back.
    pub rollback_handle: String,
    /// `true` only if the driver independently re-verified the post-state.
    pub verification_passed: bool,
    /// Human-readable, bounded description of what happened.
    pub detail: String,
}

/// Async mitigation driver contract implemented by simulations, test doubles
/// and the real Linux executor.
///
/// Methods are desugared to `impl Future + Send` so every driver's futures
/// are `Send` and usable from multi-threaded runtimes and `tokio::spawn`.
pub trait ActionDriver: Send + Sync {
    /// Execute one validated intent verb. `Err` means the effect was NOT
    /// (verifiably) applied; `Ok` with `verification_passed == false` means
    /// the effect may be partially applied and must be treated as failed.
    fn execute<'a>(
        &'a self,
        intent: &'a ActionIntentPayload,
    ) -> impl Future<Output = Result<DriverExecution, String>> + Send + 'a;
    /// Roll back a previously executed verb via its rollback handle.
    fn rollback<'a>(
        &'a self,
        intent_id: &'a str,
        verb: &'a ActionVerb,
        rollback_handle: &'a str,
    ) -> impl Future<Output = Result<String, String>> + Send + 'a;
}

/// Structural (non-policy) validation every driver applies before acting.
fn validate_verb_shape(verb: &ActionVerb) -> Result<(), String> {
    match verb {
        ActionVerb::NftBlockIp { ip, .. } => ip
            .parse::<IpAddr>()
            .map_err(|_| format!("invalid IP address '{ip}'"))
            .map(|_| ()),
        ActionVerb::SystemdStopUnit { unit, .. } => validate_systemd_unit_name(unit)
            .map_err(|reason| format!("invalid systemd unit name: {reason}")),
        ActionVerb::HostIsolate {
            preserve_mgmt_cidrs,
            ..
        } => {
            for cidr in preserve_mgmt_cidrs {
                if !is_valid_cidr(cidr) {
                    return Err(format!("invalid management CIDR '{cidr}'"));
                }
            }
            Ok(())
        }
    }
}

/// Safe default driver: validates the verb shape and simulates execution
/// without mutating the host.
#[derive(Debug, Clone, Copy, Default)]
pub struct DryRunDriver;

impl DryRunDriver {
    pub fn new() -> Self {
        Self
    }
}

impl ActionDriver for DryRunDriver {
    async fn execute(&self, intent: &ActionIntentPayload) -> Result<DriverExecution, String> {
        validate_verb_shape(&intent.verb)?;
        Ok(DriverExecution {
            dry_run: true,
            rollback_handle: format!("dry-run:{}", intent.intent_id),
            verification_passed: true,
            detail: format!(
                "dry-run simulation of {} intent '{}' (no host effect)",
                intent.verb.kind().as_str(),
                intent.intent_id
            ),
        })
    }

    async fn rollback(
        &self,
        intent_id: &str,
        verb: &ActionVerb,
        rollback_handle: &str,
    ) -> Result<String, String> {
        Ok(format!(
            "dry-run rollback of intent '{intent_id}' ({}) via handle '{rollback_handle}'",
            verb.kind().as_str()
        ))
    }
}

/// One recorded `rollback` invocation on [`FakeActionDriver`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RollbackCall {
    pub intent_id: String,
    pub verb: ActionVerb,
    pub rollback_handle: String,
}

/// Mutable state behind [`FakeActionDriver`].
#[derive(Debug, Default)]
pub struct FakeActionState {
    /// Payloads whose verbs were dispatched, in execution order.
    pub executed: Vec<ActionIntentPayload>,
    /// Rollback invocations, in order.
    pub rollbacks: Vec<RollbackCall>,
    /// Script every execution to report failed post-exec verification.
    pub fail_verification: bool,
    /// Script every execution to fail outright (no effect applied).
    pub fail_execute: bool,
}

/// Thread-safe scripted driver for tests and in-process integration harnesses.
#[derive(Debug, Clone, Default)]
pub struct FakeActionDriver {
    state: Arc<Mutex<FakeActionState>>,
}

impl FakeActionDriver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Direct handle to the shared state for scripted failure injection.
    pub fn handle(&self) -> Arc<Mutex<FakeActionState>> {
        Arc::clone(&self.state)
    }

    pub fn executed_intents(&self) -> Vec<ActionIntentPayload> {
        self.state.lock().unwrap().executed.clone()
    }

    pub fn rollback_calls(&self) -> Vec<RollbackCall> {
        self.state.lock().unwrap().rollbacks.clone()
    }

    pub fn set_fail_verification(&self, value: bool) {
        self.state.lock().unwrap().fail_verification = value;
    }

    pub fn set_fail_execute(&self, value: bool) {
        self.state.lock().unwrap().fail_execute = value;
    }
}

impl ActionDriver for FakeActionDriver {
    async fn execute(&self, intent: &ActionIntentPayload) -> Result<DriverExecution, String> {
        let mut state = self.state.lock().unwrap();
        if state.fail_execute {
            return Err("scripted execute failure".to_string());
        }
        state.executed.push(intent.clone());
        let rollback_handle = format!("fake:{}", intent.intent_id);
        if state.fail_verification {
            return Ok(DriverExecution {
                dry_run: false,
                rollback_handle,
                verification_passed: false,
                detail: "scripted verification failure".to_string(),
            });
        }
        Ok(DriverExecution {
            dry_run: false,
            rollback_handle,
            verification_passed: true,
            detail: format!("fake execution of intent '{}'", intent.intent_id),
        })
    }

    async fn rollback(
        &self,
        intent_id: &str,
        verb: &ActionVerb,
        rollback_handle: &str,
    ) -> Result<String, String> {
        self.state.lock().unwrap().rollbacks.push(RollbackCall {
            intent_id: intent_id.to_string(),
            verb: verb.clone(),
            rollback_handle: rollback_handle.to_string(),
        });
        Ok(format!("fake rollback of intent '{intent_id}'"))
    }
}

// ---------------------------------------------------------------------------
// Linux driver: fixed-path, shell-free argv construction
// ---------------------------------------------------------------------------

fn nft_add_table_argv(table: &str) -> Vec<String> {
    vec![
        NFT_BIN.into(),
        "add".into(),
        "table".into(),
        "inet".into(),
        table.into(),
    ]
}

fn nft_list_table_argv(table: &str) -> Vec<String> {
    vec![
        NFT_BIN.into(),
        "list".into(),
        "table".into(),
        "inet".into(),
        table.into(),
    ]
}

fn nft_delete_table_argv(table: &str) -> Vec<String> {
    vec![
        NFT_BIN.into(),
        "delete".into(),
        "table".into(),
        "inet".into(),
        table.into(),
    ]
}

fn nft_add_set_argv(table: &str, set: &str, addr_type: &str) -> Vec<String> {
    vec![
        NFT_BIN.into(),
        "add".into(),
        "set".into(),
        "inet".into(),
        table.into(),
        set.into(),
        "{".into(),
        "type".into(),
        addr_type.into(),
        ";".into(),
        "flags".into(),
        "timeout".into(),
        ";".into(),
        "}".into(),
    ]
}

fn nft_list_set_argv(table: &str, set: &str) -> Vec<String> {
    vec![
        NFT_BIN.into(),
        "list".into(),
        "set".into(),
        "inet".into(),
        table.into(),
        set.into(),
    ]
}

fn nft_add_base_chain_argv(table: &str, chain: &str, hook: &str, priority: &str) -> Vec<String> {
    vec![
        NFT_BIN.into(),
        "add".into(),
        "chain".into(),
        "inet".into(),
        table.into(),
        chain.into(),
        "{".into(),
        "type".into(),
        "filter".into(),
        "hook".into(),
        hook.into(),
        "priority".into(),
        priority.into(),
        ";".into(),
        "}".into(),
    ]
}

fn nft_list_chain_argv(table: &str, chain: &str) -> Vec<String> {
    vec![
        NFT_BIN.into(),
        "list".into(),
        "chain".into(),
        "inet".into(),
        table.into(),
        chain.into(),
    ]
}

fn nft_block_rule_argv(table: &str, chain: &str, family: &str, keyword: &str, set: &str) -> Vec<String> {
    vec![
        NFT_BIN.into(),
        "add".into(),
        "rule".into(),
        "inet".into(),
        table.into(),
        chain.into(),
        family.into(),
        keyword.into(),
        format!("@{set}"),
        "drop".into(),
    ]
}

fn nft_add_element_argv(table: &str, set: &str, ip: &str, ttl_seconds: u64) -> Vec<String> {
    vec![
        NFT_BIN.into(),
        "add".into(),
        "element".into(),
        "inet".into(),
        table.into(),
        set.into(),
        "{".into(),
        ip.into(),
        "timeout".into(),
        format!("{ttl_seconds}s"),
        "}".into(),
    ]
}

fn nft_delete_element_argv(table: &str, set: &str, ip: &str) -> Vec<String> {
    vec![
        NFT_BIN.into(),
        "delete".into(),
        "element".into(),
        "inet".into(),
        table.into(),
        set.into(),
        "{".into(),
        ip.into(),
        "}".into(),
    ]
}

fn nft_insert_accept_argv(table: &str, chain: &str, family: &str, keyword: &str, cidr: &str) -> Vec<String> {
    vec![
        NFT_BIN.into(),
        "insert".into(),
        "rule".into(),
        "inet".into(),
        table.into(),
        chain.into(),
        family.into(),
        keyword.into(),
        cidr.into(),
        "accept".into(),
    ]
}

fn nft_add_drop_rule_argv(table: &str, chain: &str) -> Vec<String> {
    vec![
        NFT_BIN.into(),
        "add".into(),
        "rule".into(),
        "inet".into(),
        table.into(),
        chain.into(),
        "drop".into(),
    ]
}

fn systemctl_stop_argv(unit: &str) -> Vec<String> {
    vec![SYSTEMCTL_BIN.into(), "stop".into(), "--".into(), unit.into()]
}

fn systemctl_start_argv(unit: &str) -> Vec<String> {
    vec![SYSTEMCTL_BIN.into(), "start".into(), "--".into(), unit.into()]
}

fn systemctl_is_active_argv(unit: &str) -> Vec<String> {
    vec![
        SYSTEMCTL_BIN.into(),
        "is-active".into(),
        "--".into(),
        unit.into(),
    ]
}

/// Returns the timeout set, address type and rule family keyword for an IP.
fn set_for_ip(ip: IpAddr) -> (&'static str, &'static str, &'static str) {
    match ip {
        IpAddr::V4(_) => (V4_SET, "ipv4_addr", "ip"),
        IpAddr::V6(_) => (V6_SET, "ipv6_addr", "ip6"),
    }
}

/// Returns the nftables family keyword (`ip` / `ip6`) for a CIDR.
fn cidr_family(cidr: &str) -> Result<&'static str, String> {
    let (ip_str, _) = cidr
        .split_once('/')
        .ok_or_else(|| format!("invalid management CIDR '{cidr}'"))?;
    match ip_str.parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => Ok("ip"),
        Ok(IpAddr::V6(_)) => Ok("ip6"),
        Err(_) => Err(format!("invalid management CIDR '{cidr}'")),
    }
}

struct FixedCmd {
    success: bool,
    stdout: String,
    stderr: String,
}

/// Execute one fixed-binary argv vector. No shell, no `PATH` lookup.
async fn run_fixed_argv(argv: &[String]) -> Result<FixedCmd, String> {
    let (bin, rest) = argv.split_first().ok_or("empty argv")?;
    let output = Command::new(bin)
        .args(rest)
        .output()
        .await
        .map_err(|e| format!("failed to spawn '{bin}': {e}"))?;
    Ok(FixedCmd {
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
        stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
    })
}

/// Ensure an nft object exists: probe first, create if missing, tolerate a
/// lost creation race by re-probing once.
async fn ensure_nft_object(what: &str, probe: Vec<String>, create: Vec<String>) -> Result<(), String> {
    if run_fixed_argv(&probe)
        .await
        .map(|c| c.success)
        .unwrap_or(false)
    {
        return Ok(());
    }
    let created = run_fixed_argv(&create).await?;
    if created.success {
        return Ok(());
    }
    if run_fixed_argv(&probe)
        .await
        .map(|c| c.success)
        .unwrap_or(false)
    {
        return Ok(());
    }
    Err(format!(
        "failed to ensure {what}: {}",
        created.stderr.trim()
    ))
}

/// Ensure a chain contains exactly one set-referencing drop rule.
async fn ensure_block_rule(
    table: &str,
    chain: &str,
    family: &str,
    keyword: &str,
    set: &str,
) -> Result<(), String> {
    let listing = run_fixed_argv(&nft_list_chain_argv(table, chain)).await?;
    if !listing.success {
        return Err(format!(
            "failed to list chain inet/{table}/{chain}: {}",
            listing.stderr.trim()
        ));
    }
    if listing.stdout.contains(&format!("@{set}")) {
        return Ok(());
    }
    let added = run_fixed_argv(&nft_block_rule_argv(table, chain, family, keyword, set)).await?;
    if added.success {
        return Ok(());
    }
    Err(format!(
        "failed to install block rule in inet/{table}/{chain}: {}",
        added.stderr.trim()
    ))
}

/// `true` when the last non-brace listing line is the terminal `drop` rule.
fn listing_ends_with_drop(stdout: &str) -> bool {
    stdout
        .lines()
        .rev()
        .map(str::trim)
        .find(|l| !l.is_empty() && *l != "}")
        .is_some_and(|l| l == "drop" || l.starts_with("drop "))
}

/// Enforce a time-bounded nftables IP block in the dedicated table.
///
/// The block is a set element carrying `timeout <ttl>s`, so the kernel itself
/// expires the block even if this process dies.
async fn execute_nft_block(
    ip: &str,
    direction: TrafficDirection,
    ttl_seconds: u64,
) -> Result<DriverExecution, String> {
    let parsed: IpAddr = ip
        .parse()
        .map_err(|_| format!("invalid IP address '{ip}'"))?;
    if ttl_seconds == 0 {
        return Err("nft_block_ip requires a positive ttl_seconds".into());
    }
    let (set, addr_type, family) = set_for_ip(parsed);
    let dir_label = match direction {
        TrafficDirection::Inbound => "inbound",
        TrafficDirection::Outbound => "outbound",
        TrafficDirection::Both => "inbound+outbound",
    };

    ensure_nft_object(
        "nft block table",
        nft_list_table_argv(BLOCK_TABLE),
        nft_add_table_argv(BLOCK_TABLE),
    )
    .await?;
    ensure_nft_object(
        "nft timeout set",
        nft_list_set_argv(BLOCK_TABLE, set),
        nft_add_set_argv(BLOCK_TABLE, set, addr_type),
    )
    .await?;
    if matches!(direction, TrafficDirection::Inbound | TrafficDirection::Both) {
        ensure_nft_object(
            "nft input chain",
            nft_list_chain_argv(BLOCK_TABLE, INPUT_CHAIN),
            nft_add_base_chain_argv(BLOCK_TABLE, INPUT_CHAIN, "input", "-1"),
        )
        .await?;
        ensure_block_rule(BLOCK_TABLE, INPUT_CHAIN, family, "saddr", set).await?;
    }
    if matches!(direction, TrafficDirection::Outbound | TrafficDirection::Both) {
        ensure_nft_object(
            "nft output chain",
            nft_list_chain_argv(BLOCK_TABLE, OUTPUT_CHAIN),
            nft_add_base_chain_argv(BLOCK_TABLE, OUTPUT_CHAIN, "output", "-1"),
        )
        .await?;
        ensure_block_rule(BLOCK_TABLE, OUTPUT_CHAIN, family, "daddr", set).await?;
    }

    let added = run_fixed_argv(&nft_add_element_argv(BLOCK_TABLE, set, ip, ttl_seconds)).await?;
    if !added.success {
        return Err(format!(
            "failed to install nftables block for '{ip}': {}",
            added.stderr.trim()
        ));
    }

    // Post-exec verification: the kernel state must actually contain the block.
    let listing = run_fixed_argv(&nft_list_set_argv(BLOCK_TABLE, set)).await?;
    let verified = listing.success && listing.stdout.contains(ip);
    let rollback_handle = format!("nft:set:inet:{BLOCK_TABLE}:{set}:{ip}");
    let detail = if verified {
        format!(
            "nftables block of {ip} ({dir_label}) installed in inet/{BLOCK_TABLE} with kernel-enforced TTL {ttl_seconds}s; verified via `nft list set`"
        )
    } else {
        format!(
            "post-exec verification failed: `nft list set inet {BLOCK_TABLE} {set}` output does not contain '{ip}'"
        )
    };
    Ok(DriverExecution {
        dry_run: false,
        rollback_handle,
        verification_passed: verified,
        detail,
    })
}

/// Stop a validated non-protected systemd unit and verify it is inactive.
async fn execute_systemd_stop(unit: &str) -> Result<DriverExecution, String> {
    validate_systemd_unit_name(unit)
        .map_err(|reason| format!("refusing invalid systemd unit name: {reason}"))?;
    let stopped = run_fixed_argv(&systemctl_stop_argv(unit)).await?;
    if !stopped.success {
        return Err(format!(
            "systemctl stop failed for unit '{unit}': {}",
            stopped.stderr.trim()
        ));
    }
    // Post-exec verification: a successful command is not proof of mitigation.
    let probe = run_fixed_argv(&systemctl_is_active_argv(unit)).await?;
    let state = probe.stdout.trim();
    let verified = state != "active";
    let rollback_handle = format!("systemctl:start:{unit}");
    let detail = if verified {
        format!(
            "systemd unit '{unit}' stopped; `systemctl is-active` reports '{state}'"
        )
    } else {
        format!(
            "post-exec verification failed: unit '{unit}' still reports 'active' after stop"
        )
    };
    Ok(DriverExecution {
        dry_run: false,
        rollback_handle,
        verification_passed: verified,
        detail,
    })
}

/// Isolate the host in a dedicated nftables table while explicitly accepting
/// every preserved management CIDR above the terminal drop rule.
async fn execute_host_isolate(
    preserve_mgmt_cidrs: &[String],
    ttl_seconds: u64,
) -> Result<DriverExecution, String> {
    if ttl_seconds == 0 {
        return Err("host_isolate requires a positive ttl_seconds".into());
    }
    for cidr in preserve_mgmt_cidrs {
        if !is_valid_cidr(cidr) {
            return Err(format!("invalid management CIDR '{cidr}'"));
        }
    }
    ensure_nft_object(
        "nft isolation table",
        nft_list_table_argv(ISOLATE_TABLE),
        nft_add_table_argv(ISOLATE_TABLE),
    )
    .await?;

    let mut verified = true;
    for (chain, hook, keyword) in [
        (ISOLATE_INPUT_CHAIN, "input", "saddr"),
        (ISOLATE_OUTPUT_CHAIN, "output", "daddr"),
    ] {
        ensure_nft_object(
            "nft isolation chain",
            nft_list_chain_argv(ISOLATE_TABLE, chain),
            nft_add_base_chain_argv(ISOLATE_TABLE, chain, hook, "0"),
        )
        .await?;
        // Management accepts are INSERTED at position 0 so they always sit
        // above the terminal drop rule, whatever else the chain contains.
        for cidr in preserve_mgmt_cidrs {
            let family = cidr_family(cidr)?;
            let listing = run_fixed_argv(&nft_list_chain_argv(ISOLATE_TABLE, chain)).await?;
            if !listing.success {
                return Err(format!(
                    "failed to list chain inet/{ISOLATE_TABLE}/{chain}: {}",
                    listing.stderr.trim()
                ));
            }
            if !listing.stdout.contains(cidr) {
                let inserted = run_fixed_argv(&nft_insert_accept_argv(
                    ISOLATE_TABLE, chain, family, keyword, cidr,
                ))
                .await?;
                if !inserted.success {
                    return Err(format!(
                        "failed to install management accept rule for '{cidr}': {}",
                        inserted.stderr.trim()
                    ));
                }
            }
        }
        // Terminal drop rule, appended last if not already present.
        let listing = run_fixed_argv(&nft_list_chain_argv(ISOLATE_TABLE, chain)).await?;
        if !listing_ends_with_drop(&listing.stdout) {
            let added = run_fixed_argv(&nft_add_drop_rule_argv(ISOLATE_TABLE, chain)).await?;
            if !added.success {
                return Err(format!(
                    "failed to install isolation drop rule in inet/{ISOLATE_TABLE}/{chain}: {}",
                    added.stderr.trim()
                ));
            }
        }
        // Post-exec verification: accepts present and drop is terminal.
        let final_listing = run_fixed_argv(&nft_list_chain_argv(ISOLATE_TABLE, chain)).await?;
        if !final_listing.success {
            verified = false;
            continue;
        }
        for cidr in preserve_mgmt_cidrs {
            if !final_listing.stdout.contains(cidr) {
                verified = false;
            }
        }
        if !listing_ends_with_drop(&final_listing.stdout) {
            verified = false;
        }
    }

    let rollback_handle = format!("nft:table:inet:{ISOLATE_TABLE}");
    let detail = if verified {
        format!(
            "host isolation active in inet/{ISOLATE_TABLE}: {} management CIDR(s) explicitly accepted above the terminal drop rule; TTL {ttl_seconds}s enforced by executor rollback",
            preserve_mgmt_cidrs.len()
        )
    } else {
        format!(
            "post-exec verification failed: inet/{ISOLATE_TABLE} chain listing does not confirm all management accepts plus a terminal drop rule"
        )
    };
    Ok(DriverExecution {
        dry_run: false,
        rollback_handle,
        verification_passed: verified,
        detail,
    })
}

async fn rollback_verb(verb: &ActionVerb, rollback_handle: &str) -> Result<String, String> {
    match verb {
        ActionVerb::NftBlockIp { ip, .. } => {
            let parsed: IpAddr = ip
                .parse()
                .map_err(|_| format!("invalid IP '{ip}' in rollback"))?;
            let set = match parsed {
                IpAddr::V4(_) => V4_SET,
                IpAddr::V6(_) => V6_SET,
            };
            match run_fixed_argv(&nft_delete_element_argv(BLOCK_TABLE, set, ip)).await? {
                c if c.success => Ok(format!(
                    "removed nftables element '{ip}' via handle '{rollback_handle}'"
                )),
                // The kernel timeout already expired the element: success.
                c if c.stderr.contains("No such file") => Ok(format!(
                    "nftables element '{ip}' already expired (kernel TTL enforced)"
                )),
                c => Err(format!(
                    "failed to remove nftables element '{ip}': {}",
                    c.stderr.trim()
                )),
            }
        }
        ActionVerb::SystemdStopUnit { unit, .. } => {
            validate_systemd_unit_name(unit)
                .map_err(|reason| format!("refusing invalid systemd unit name: {reason}"))?;
            let started = run_fixed_argv(&systemctl_start_argv(unit)).await?;
            if started.success {
                Ok(format!(
                    "restarted systemd unit '{unit}' via handle '{rollback_handle}'"
                ))
            } else {
                Err(format!(
                    "failed to restart unit '{unit}': {}",
                    started.stderr.trim()
                ))
            }
        }
        ActionVerb::HostIsolate { .. } => {
            // Rollback removes the whole dedicated isolation table, restoring
            // normal traffic flow without touching the IP-block table.
            match run_fixed_argv(&nft_delete_table_argv(ISOLATE_TABLE)).await? {
                c if c.success => Ok(format!(
                    "deleted nftables isolation table inet/{ISOLATE_TABLE} via handle '{rollback_handle}'"
                )),
                c if c.stderr.contains("No such file") => Ok(format!(
                    "isolation table inet/{ISOLATE_TABLE} already absent"
                )),
                c => Err(format!(
                    "failed to delete isolation table inet/{ISOLATE_TABLE}: {}",
                    c.stderr.trim()
                )),
            }
        }
    }
}

/// Real host-effect driver over the fixed `nft` / `systemctl` binaries.
#[derive(Debug, Clone, Copy, Default)]
pub struct LinuxActionDriver;

impl LinuxActionDriver {
    pub fn new() -> Self {
        Self
    }
}

impl ActionDriver for LinuxActionDriver {
    async fn execute(&self, intent: &ActionIntentPayload) -> Result<DriverExecution, String> {
        match &intent.verb {
            ActionVerb::NftBlockIp {
                ip,
                direction,
                ttl_seconds,
            } => execute_nft_block(ip, *direction, *ttl_seconds).await,
            ActionVerb::SystemdStopUnit { unit, .. } => execute_systemd_stop(unit).await,
            ActionVerb::HostIsolate {
                preserve_mgmt_cidrs,
                ttl_seconds,
            } => execute_host_isolate(preserve_mgmt_cidrs, *ttl_seconds).await,
        }
    }

    async fn rollback(
        &self,
        _intent_id: &str,
        verb: &ActionVerb,
        rollback_handle: &str,
    ) -> Result<String, String> {
        rollback_verb(verb, rollback_handle).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use defsec_protocol::action::ActionAuthMode;
    use uuid::Uuid;

    fn intent(verb: ActionVerb) -> ActionIntentPayload {
        let uid = Uuid::new_v4().simple().to_string();
        ActionIntentPayload {
            schema_version: 1,
            intent_id: format!("intent-{uid}"),
            nonce: format!("nonce-{uid}"),
            host_id: "edge-01".into(),
            incident_id: "inc-1".into(),
            proposal_id: 1,
            auth_mode: ActionAuthMode::DualSignedOperator,
            verb,
            policy_version: 1,
            issued_at: chrono::Utc::now() - chrono::Duration::seconds(60),
            expires_at: chrono::Utc::now() + chrono::Duration::seconds(600),
            rollback_plan: "manual".into(),
            evidence_observation_ids: vec![1],
        }
    }

    #[tokio::test]
    async fn dry_run_driver_simulates_without_host_effects() {
        let driver = DryRunDriver::new();
        let payload = intent(ActionVerb::NftBlockIp {
            ip: "203.0.113.42".into(),
            direction: TrafficDirection::Inbound,
            ttl_seconds: 900,
        });
        let exec = driver.execute(&payload).await.unwrap();
        assert!(exec.dry_run);
        assert!(exec.verification_passed);
        assert_eq!(exec.rollback_handle, format!("dry-run:{}", payload.intent_id));
        assert!(exec.detail.contains("dry-run simulation of nft_block_ip"));

        let detail = driver
            .rollback("intent-1", &payload.verb, &exec.rollback_handle)
            .await
            .unwrap();
        assert!(detail.contains("dry-run rollback of intent 'intent-1'"));
    }

    #[tokio::test]
    async fn dry_run_driver_rejects_malformed_verbs() {
        let driver = DryRunDriver::new();
        let evil_unit = intent(ActionVerb::SystemdStopUnit {
            unit: "sshd.service; rm -rf /".into(),
            ttl_seconds: Some(600),
        });
        let err = driver.execute(&evil_unit).await.unwrap_err();
        assert!(err.contains("invalid systemd unit name"), "got: {err}");

        let bad_ip = intent(ActionVerb::NftBlockIp {
            ip: "999.1.2.3".into(),
            direction: TrafficDirection::Both,
            ttl_seconds: 600,
        });
        assert!(driver.execute(&bad_ip).await.unwrap_err().contains("invalid IP"));

        let bad_cidr = intent(ActionVerb::HostIsolate {
            preserve_mgmt_cidrs: vec!["10.0.0.0; reboot".into()],
            ttl_seconds: 600,
        });
        assert!(driver
            .execute(&bad_cidr)
            .await
            .unwrap_err()
            .contains("invalid management CIDR"));
    }

    #[tokio::test]
    async fn fake_driver_records_and_scripts_failures() {
        let driver = FakeActionDriver::new();
        let payload = intent(ActionVerb::HostIsolate {
            preserve_mgmt_cidrs: vec!["10.10.0.0/24".into()],
            ttl_seconds: 900,
        });

        let exec = driver.execute(&payload).await.unwrap();
        assert!(!exec.dry_run);
        assert!(exec.verification_passed);
        assert_eq!(driver.executed_intents().len(), 1);

        driver.set_fail_verification(true);
        let exec = driver.execute(&payload).await.unwrap();
        assert!(!exec.verification_passed);
        assert_eq!(driver.executed_intents().len(), 2);

        driver.set_fail_execute(true);
        assert!(driver.execute(&payload).await.is_err());
        assert_eq!(driver.executed_intents().len(), 2, "failed execute must not record an effect");
        driver.set_fail_execute(false);

        driver
            .rollback("intent-9", &payload.verb, "fake:intent-9")
            .await
            .unwrap();
        let calls = driver.rollback_calls();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].intent_id, "intent-9");
        assert_eq!(calls[0].rollback_handle, "fake:intent-9");
    }

    #[test]
    fn linux_argv_vectors_are_static_and_allowlisted() {
        assert_eq!(
            nft_add_table_argv(BLOCK_TABLE),
            vec!["/usr/sbin/nft", "add", "table", "inet", "defsecautmit"]
        );
        assert_eq!(
            nft_delete_table_argv(ISOLATE_TABLE),
            vec![
                "/usr/sbin/nft", "delete", "table", "inet", "defsecautmit_isolate"
            ]
        );
        assert_eq!(
            nft_add_set_argv(BLOCK_TABLE, V4_SET, "ipv4_addr"),
            vec![
                "/usr/sbin/nft", "add", "set", "inet", "defsecautmit", "blocked_v4", "{",
                "type", "ipv4_addr", ";", "flags", "timeout", ";", "}",
            ]
        );
        assert_eq!(
            nft_add_base_chain_argv(BLOCK_TABLE, INPUT_CHAIN, "input", "-1"),
            vec![
                "/usr/sbin/nft", "add", "chain", "inet", "defsecautmit", "input_hook", "{",
                "type", "filter", "hook", "input", "priority", "-1", ";", "}",
            ]
        );
        assert_eq!(
            nft_block_rule_argv(BLOCK_TABLE, INPUT_CHAIN, "ip", "saddr", V4_SET),
            vec![
                "/usr/sbin/nft", "add", "rule", "inet", "defsecautmit", "input_hook",
                "ip", "saddr", "@blocked_v4", "drop",
            ]
        );
        assert_eq!(
            nft_add_element_argv(BLOCK_TABLE, V4_SET, "203.0.113.42", 900),
            vec![
                "/usr/sbin/nft", "add", "element", "inet", "defsecautmit", "blocked_v4",
                "{", "203.0.113.42", "timeout", "900s", "}",
            ]
        );
        assert_eq!(
            nft_delete_element_argv(BLOCK_TABLE, V6_SET, "2001:db8::1"),
            vec![
                "/usr/sbin/nft", "delete", "element", "inet", "defsecautmit", "blocked_v6",
                "{", "2001:db8::1", "}",
            ]
        );
        assert_eq!(
            nft_insert_accept_argv(ISOLATE_TABLE, ISOLATE_INPUT_CHAIN, "ip", "saddr", "10.10.0.0/24"),
            vec![
                "/usr/sbin/nft", "insert", "rule", "inet", "defsecautmit_isolate",
                "isolate_input", "ip", "saddr", "10.10.0.0/24", "accept",
            ]
        );
        assert_eq!(
            nft_add_drop_rule_argv(ISOLATE_TABLE, ISOLATE_OUTPUT_CHAIN),
            vec![
                "/usr/sbin/nft", "add", "rule", "inet", "defsecautmit_isolate",
                "isolate_output", "drop",
            ]
        );
        assert_eq!(
            systemctl_stop_argv("nginx.service"),
            vec!["/usr/bin/systemctl", "stop", "--", "nginx.service"]
        );
        assert_eq!(
            systemctl_is_active_argv("nginx.service"),
            vec!["/usr/bin/systemctl", "is-active", "--", "nginx.service"]
        );
        assert_eq!(
            systemctl_start_argv("nginx.service"),
            vec!["/usr/bin/systemctl", "start", "--", "nginx.service"]
        );
    }

    #[tokio::test]
    async fn linux_driver_validates_before_spawning_anything() {
        let driver = LinuxActionDriver::new();
        // These verbs fail structural validation before a single binary runs.
        let bad_unit = intent(ActionVerb::SystemdStopUnit {
            unit: "-n".into(),
            ttl_seconds: Some(600),
        });
        assert!(driver.execute(&bad_unit).await.unwrap_err().contains("unit name"));
        let bad_ip = intent(ActionVerb::NftBlockIp {
            ip: "not-an-ip".into(),
            direction: TrafficDirection::Inbound,
            ttl_seconds: 600,
        });
        assert!(driver.execute(&bad_ip).await.unwrap_err().contains("invalid IP"));
        let zero_ttl = intent(ActionVerb::NftBlockIp {
            ip: "203.0.113.42".into(),
            direction: TrafficDirection::Inbound,
            ttl_seconds: 0,
        });
        assert!(driver.execute(&zero_ttl).await.unwrap_err().contains("positive ttl"));
        let bad_cidr = intent(ActionVerb::HostIsolate {
            preserve_mgmt_cidrs: vec!["../etc/passwd".into()],
            ttl_seconds: 600,
        });
        assert!(driver
            .execute(&bad_cidr)
            .await
            .unwrap_err()
            .contains("invalid management CIDR"));
    }

    #[test]
    fn set_and_family_selection_follows_ip_kind() {
        assert_eq!(set_for_ip("192.0.2.9".parse().unwrap()), (V4_SET, "ipv4_addr", "ip"));
        assert_eq!(
            set_for_ip("2001:db8::1".parse().unwrap()),
            (V6_SET, "ipv6_addr", "ip6")
        );
        assert_eq!(cidr_family("10.10.0.0/24").unwrap(), "ip");
        assert_eq!(cidr_family("fe80::/10").unwrap(), "ip6");
        assert!(cidr_family("bogus/24").is_err());
    }

    #[test]
    fn drop_detection_requires_terminal_drop_rule() {
        let with_drop = "chain isolate_input {\n\tip saddr 10.10.0.0/24 accept\n\tdrop\n}\n";
        assert!(listing_ends_with_drop(with_drop));
        let without_drop = "chain isolate_input {\n\tip saddr 10.10.0.0/24 accept\n}\n";
        assert!(!listing_ends_with_drop(without_drop));
        let empty = "chain isolate_input {\n}\n";
        assert!(!listing_ends_with_drop(empty));
        // A drop that is NOT terminal does not satisfy isolation ordering.
        let drop_not_last = "chain isolate_input {\n\tdrop\n\tip saddr 10.10.0.0/24 accept\n}\n";
        assert!(!listing_ends_with_drop(drop_not_last));
    }
}
