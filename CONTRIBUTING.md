# Contributing to Defensive Security Autonomous Mitigation Harness

Thank you for your interest in contributing to the Defensive Security Autonomous Mitigation Harness!

## Repository Layout

- `crates/protocol` — Zero-I/O schemas, Watch DSL, Action DSL, RFC 8785 Canonical JSON + Ed25519 signing, wire framing, RPC types, and audit chain structures.
- `crates/policy` — Deterministic `edge_floor`, `control_gate`, `action_gate`, and `predicate` evaluators.
- `crates/agent-d` — Lightweight Linux edge daemon, 4 built-in collectors, `FakeHost` test simulator, diffing, and bounded spooling.
- `crates/control-d` — Authoritative SQLite WAL control plane, three-state baseline engine, bundle/intent signer, audit outbox, and `SO_PEERCRED` UDS servers.
- `crates/admin-cli` — Operator CLI for enrollment, baseline management, token minting, dual-signed action approval, and audit verification.
- `crates/mcp-adapter` — Thin Rust stdio MCP bridge over `investigate.sock`.
- `crates/action-exec-d` — Isolated privileged mitigation executor (`dry-run` default, atomic nonce replay store, automatic TTL rollback).
- `reasoner/` — Zero-dependency Python 3.12 episodic reasoning worker (`reasoner-d`) and adaptive-vs-static benchmark suite.
- `console/` — Zero-dependency Node 24 localhost BFF and Operator Web Console.

## Prerequisites

- Rust toolchain (`rustc` / `cargo`, edition 2024)
- Python 3.12+ (stdlib only — no `pip` dependencies required)
- Node.js 24+ (built-in modules only — no `npm` dependencies required)

## Running the Full Test Suite

Before opening a pull request, verify all three stacks pass cleanly with zero warnings:

```bash
# 1. Rust workspace (unit, collector, control-plane, MCP, action-exec-d, and E2E suites)
cargo test --workspace

# 2. Build binaries used by Python and Node live-daemon integration tests
cargo build -p control-d -p admin-cli -p action-exec-d

# 3. Python reasoner-d & adaptive-vs-static benchmark suite
PYTHONPATH=reasoner python3 -m unittest discover -s reasoner/tests -v

# 4. Node 24 Operator Web Console suite
node --test console/test/server.test.mjs
```

## Design & Security Guardrails for PRs

1. **Preserve physical trust-domain separation:** Never add SQLite or LLM client dependencies to `agent-d` or `action-exec-d`, and never add shell execution to collectors, `mcp-adapter`, `reasoner/`, or `console/`.
2. **Closed typed schemas:** Keep `#[serde(deny_unknown_fields)]` on untrusted inputs and validate parameters against both `control-d` and local edge floors.
3. **Never commit secrets or local runtime state:** Do not commit `.env` files, Ed25519 `.hex` keys, SQLite ledgers, Unix sockets, or real host telemetry/IPs. Use RFC 5737 documentation IPs (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and synthetic hostnames in tests and docs.
4. **Tests for every security invariant:** Any new collector, predicate, RPC operation, or mitigation verb should include deterministic unit tests plus adversarial rejection cases.
