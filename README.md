<img src="assets/icon.svg" width="64" height="64" alt="">

# DefSecAutMit — Adaptive Defensive Monitoring Harness

A persistent, event-driven defensive monitoring harness for Linux hosts that separates **deterministic telemetry collection and policy enforcement** from **episodic, evidence-backed reasoning**.

See [adaptive_defensive_monitoring_harness_design_v0.2.md](docs/adaptive_defensive_monitoring_harness_design_v0.2.md) for the full system design.

## Workspace Layout

| Crate | Purpose |
|---|---|
| `crates/protocol` | Zero-I/O domain schemas, non-Turing-complete Watch DSL (`deny_unknown_fields`), RFC 8785 Canonical JSON + domain-separated Ed25519 signing, wire framing, Investigation/Admin RPC contracts, and hash-chained audit records |
| `crates/policy` | Deterministic `edge_floor` (agent-local safety ceilings & sensitive path/unit denylists), `control_gate` (baseline protection, ephemeral quotas, wake circuit breaker), and predicate evaluation (`field_changed`, `set_diff`, `threshold_sustained`, `collector_stale_or_error`) |
| `crates/agent-d` | Lightweight Linux edge daemon (`tokio` single-threaded runtime), 4 built-in collectors (`sockets.listening`, `systemd.unit_state` via `zbus`, `files.metadata` via `openat2`, `journal.unit_events`), `FakeHost` test simulator, edge-lite diffing, and `minimal` (RAM) / `durable` (disk) spools |
| `crates/control-d` | Authoritative control server: SQLite WAL ledger (`synchronous=FULL`), three-state baseline engine, Ed25519 bundle signer, hash-chained `audit_outbox`, and `SO_PEERCRED`-authenticated UDS servers (`agent.sock`, `admin.sock`, `investigate.sock`) |
| `crates/admin-cli` | Operator CLI for host enrollment, baseline watch management, attributable baseline promotion, scoped capability token minting, incident closure, and audit chain verification |
| `crates/mcp-adapter` | Thin Rust stdio MCP server (`--mode read-only` default or `--mode investigator`) bridging external agent clients (T3 Code, Codex, Claude) to `control-d`'s `investigate.sock` |
| `crates/action-exec-d` | Isolated privileged mitigation executor (`--mode dry-run` default or `enforce`) verifying Ed25519 control + independent operator dual signatures, local protected-asset denylists, atomic nonce replay protection, and automatic TTL rollback (`nft_block_ip`, `systemd_stop_unit`, `host_isolate`) |
| `reasoner/` | Zero-dependency Python 3.12 episodic reasoning worker (`reasoner-d`), replaceable model adapters (OpenAI-compatible/Ollama/vLLM, Anthropic, ScriptedMock), provenance envelopes, optional bounded mitigation proposals, and 4-scenario adaptive-vs-static benchmark suite |
| `console/` | Zero-dependency Node 24 localhost BFF + responsive Operator Web Console (`--demo` or live `control-d` UDS mode) with three-state baseline inspector, guided watch proposal composer, and independent audit-chain verifier |

## Build & Test

```bash
# Rust workspace (all 6 crates: unit, collector, control-plane, MCP, and E2E adversarial tests)
cargo test --workspace

# Python reasoner-d & adaptive-vs-static benchmark suite
PYTHONPATH=reasoner python3 -m unittest discover -s reasoner/tests -v

# Node 24 Operator Web Console suite
node --test console/test/server.test.mjs

# Try the Operator Web Console immediately in demo mode
node console/server.mjs --demo

# Build release binaries
cargo build --release --workspace
```

## Quick Single-Host Smoke Flow

```bash
# 1. Start control-d
./target/release/control-d --data-dir ./run-data

# 2. Enroll a host (returns control signing key ID + public hex)
./target/release/admin-cli --admin-sock ./run-data/admin.sock enroll edge-01

# 3. Start agent-d pointing at control-d's agent.sock
./target/release/agent-d \
  --host-id edge-01 \
  --state-dir ./run-agent \
  --control-sock ./run-data/agent.sock \
  --control-key-id control-key-01 \
  --control-pub-hex <CONTROL_PUBLIC_KEY_HEX>

# 4. Apply a baseline watch & verify the hash-chained audit log
./target/release/admin-cli --admin-sock ./run-data/admin.sock apply-watch watch.json --actor ops --rationale "initial baseline"
./target/release/admin-cli --admin-sock ./run-data/admin.sock verify-audit
```
