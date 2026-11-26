# Architecture

The Defensive Security Autonomous Mitigation Harness separates continuous deterministic monitoring from episodic model-assisted investigation. The model has typed investigation operations, not a shell or direct access to the database. Local IPC is the present deployment boundary.

## Components

| Component | Responsibility |
|---|---|
| `defsec-protocol` | Watch and action contracts, canonicalization, signing, audit and wire types |
| `defsec-policy` | Deterministic control, edge and action gates and predicates |
| `agent-d` | Single-threaded Linux collection, signed bundle verification, local floors and spool |
| `control-d` | Authoritative policy, persistence, baseline and investigation state, signing and audit |
| `admin-cli` | Local administrative operations |
| `mcp-adapter` | Restricted stdio MCP bridge to investigation RPC |
| `reasoner/` | Bounded Python worker and synthetic benchmark |
| `console/` | Local Node HTTP backend-for-frontend and browser UI |
| `action-exec-d` | Separate single-shot signed action verifier and executor |

The edge crate does not depend on SQLite; the action executor has no model or database dependency. This is dependency separation, not an operating-system sandbox by itself.

## Transport and identity

The local Unix socket protocol uses a four-byte big-endian length followed by UTF-8 JSON, bounded to 2 MiB. Control checks peer credentials (`SO_PEERCRED`) and socket policy; investigation calls additionally use scoped capability tokens. Socket filesystem permissions and allowed UIDs must match the deployment. This is not a remote authenticated fleet transport.

Signed payloads use RFC 8785 canonical JSON and Ed25519 with distinct domains: `defsecautmit.watch_bundle.v1`, `defsecautmit.audit_entry.v1`, `defsecautmit.action_intent.v1`, and `defsecautmit.action_approval.v1`. Domains prevent a signature for one purpose from being accepted for another. Audit entries form a SHA-256 hash chain; verification detects changes to the examined chain, but does not independently prove that an entire ledger was not replaced or truncated.

## Collection and state

The closed collector catalog consists of `sockets.listening`, `systemd.unit_state`, `files.metadata`, `journal.unit_events`, `connections.outbound`, and `packages.inventory`. The two network collectors can report partial process attribution when an unprivileged agent cannot inspect other processes. `connections.outbound` snapshots grouped remote endpoints and `packages.inventory` snapshots installed packages from the local dpkg status database. Systemd state uses D-Bus. File collection confines resolution with `openat2` and `RESOLVE_BENEATH`, `RESOLVE_NO_SYMLINKS`, `RESOLVE_NO_MAGICLINKS`, and `RESOLVE_NO_XDEV`. Journal collection is bounded and requires appropriate read access.

A watch has a schedule, typed collector, deterministic trigger, wake policy and lifecycle. The control baseline engine distinguishes accepted baseline, last observed, and current observed state; promotion is an attributable operator operation, not an automatic consequence of drift. SQLite uses WAL and `synchronous=FULL`; the schema includes hosts, watches, observations, baseline revisions, incidents, trigger events and evidence, capability tokens, runs, policy decisions, findings, and audit outbox. Schema v2 adds action proposals, intents and receipts.

Trigger events are leased for bounded worker runs. Lease fencing prevents an expired worker from committing as the current owner; retries and dead-letter handling limit provider failures. The reasoner wraps telemetry as untrusted data, proposes through typed RPC, and remains subject to deterministic policy decisions.

Schema v6 stores the last registered host profile summary and its receipt time. Control exposes the summary through admin and scoped investigation host listings, audits changes to it, and checks its collector allowlist when admitting operator baseline watches. The agent still independently enforces its local safety floor on signed bundles.

## Interfaces and containment

The MCP adapter exposes a restricted investigation interface over stdio. The console's Node BFF connects to control sockets and holds the capability token server-side; admin access requires explicit enablement. The browser does not open SQLite or communicate directly with agents.

Phase 8 distinguishes `PolicyBoundedAutonomous` from `DualSignedOperator` actions. The first requires explicit local enablement and policy bounds; the second requires a control signature and separate operator approval. The executor independently checks signatures, host binding, expiry, local protected assets and a durable nonce store, then uses fixed drivers. It defaults to dry-run. Enforced containment and rollback require careful operational validation; see the [security model](security-model.md).
