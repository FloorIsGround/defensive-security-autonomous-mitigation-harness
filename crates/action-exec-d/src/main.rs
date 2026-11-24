//! `action-exec-d` CLI: a single-shot, isolated privileged executor.
//!
//! Verifies and executes one signed intent JSON file and prints the
//! [`ActionReceipt`] JSON to stdout. Defaults to the non-mutating dry-run
//! driver; `--mode enforce` selects the real `nft` / `systemctl` driver.

use std::path::PathBuf;
use std::sync::Arc;

use chrono::Utc;
use clap::{Parser, ValueEnum};
use defsec_policy::action_gate::ActionSafetyConfig;
use defsec_protocol::action::AuthorizedActionIntent;
use defsec_protocol::signing::VerifyingKeyStore;

use action_exec_d::driver::{ActionDriver, DryRunDriver, LinuxActionDriver};
use action_exec_d::executor::ActionExecutor;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
#[value(rename_all = "kebab-case")]
enum Mode {
    /// Simulate every verb; never mutate the host.
    DryRun,
    /// Apply real host effects via the fixed `nft` / `systemctl` drivers.
    Enforce,
}

#[derive(Debug, Parser)]
#[command(about = "DefSecAutMit isolated privileged action executor (Phase 8)")]
struct Args {
    /// Local host identity this executor is bound to.
    #[arg(long)]
    host_id: String,
    /// Directory holding the durable replay store.
    #[arg(long, default_value = "./action-exec-state")]
    state_dir: PathBuf,
    /// Trusted control-plane signing key identifier.
    #[arg(long)]
    control_key_id: String,
    /// Trusted control-plane Ed25519 public key (hex).
    #[arg(long)]
    control_pub_hex: String,
    /// Independent operator approval signing key identifier.
    #[arg(long)]
    operator_key_id: String,
    /// Independent operator Ed25519 public key (hex).
    #[arg(long)]
    operator_pub_hex: String,
    /// Execution mode: simulate (default) or enforce real effects.
    #[arg(long, default_value = "dry-run")]
    mode: Mode,
    /// Opt in to policy-bounded autonomous containment verbs locally.
    #[arg(long)]
    enable_autonomous_containment: bool,
    /// Signed intent JSON file to verify and execute (single-shot).
    #[arg(long)]
    intent_file: Option<PathBuf>,
}

fn key_store(key_id: &str, public_hex: &str, flag: &str) -> Result<VerifyingKeyStore, String> {
    let mut store = VerifyingKeyStore::new();
    store
        .insert_public_hex(key_id, public_hex)
        .map_err(|e| format!("invalid {flag}: {e}"))?;
    Ok(store)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();
    let args = Args::parse();

    let cfg = if args.enable_autonomous_containment {
        ActionSafetyConfig::with_bounded_autonomous_containment()
    } else {
        ActionSafetyConfig::default()
    };
    let control_keys = key_store(
        &args.control_key_id,
        &args.control_pub_hex,
        "--control-pub-hex",
    )?;
    let operator_keys = key_store(
        &args.operator_key_id,
        &args.operator_pub_hex,
        "--operator-pub-hex",
    )?;

    match args.mode {
        Mode::DryRun => {
            execute_once(&args, cfg, control_keys, operator_keys, Arc::new(DryRunDriver::new()))
                .await
        }
        Mode::Enforce => {
            execute_once(
                &args,
                cfg,
                control_keys,
                operator_keys,
                Arc::new(LinuxActionDriver::new()),
            )
            .await
        }
    }
}

async fn execute_once<D: ActionDriver>(
    args: &Args,
    cfg: ActionSafetyConfig,
    control_keys: VerifyingKeyStore,
    operator_keys: VerifyingKeyStore,
    driver: Arc<D>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let Some(intent_path) = &args.intent_file else {
        return Err(
            "missing --intent-file: provide a signed intent JSON file to verify and execute"
                .into(),
        );
    };
    let raw = std::fs::read_to_string(intent_path)?;
    let intent: AuthorizedActionIntent = serde_json::from_str(&raw)?;
    let mut executor = ActionExecutor::new(
        args.host_id.clone(),
        cfg,
        control_keys,
        operator_keys,
        args.state_dir.clone(),
        driver,
    )
    .map_err(|e| format!("failed to open replay store: {e}"))?;

    tracing::info!(
        host_id = %args.host_id,
        intent_file = %intent_path.display(),
        "executing signed action intent"
    );
    let receipt = executor.execute_intent(&intent, Utc::now()).await;
    println!("{}", serde_json::to_string_pretty(&receipt)?);
    if receipt.verification_passed {
        Ok(())
    } else {
        std::process::exit(1);
    }
}
