# Security model

The Defensive Security Autonomous Mitigation Harness is a defense-in-depth monitoring system, not a guarantee against a compromised host. Trust in signing keys, local control, host identity and the operating system remains essential.

## Boundaries

`control-d` decides whether a proposed watch or action meets central policy. The edge independently verifies signed bundles and enforces local floors on schedules, paths and units; the separate action executor applies its own action safety configuration, protected CIDRs and units, signatures, expiry and replay checks. These gates reduce reliance on any one reasoning client. They do not protect against local root, who can alter processes, keys, configuration, evidence or the host itself.

Telemetry is untrusted: the reasoner wraps it in `<untrusted_telemetry>` envelopes, clips it and neutralizes closing tags. Model instructions and typed tools narrow the available behavior, while deterministic policy makes the actual authorization decision. Prompt injection can still affect analysis or consume resources. The console renders telemetry as text nodes and applies CSP, origin and Host checks; its BFF keeps the token out of browser responses. Keep the console on loopback and protect its socket credentials.

Containment is disabled by default. Autonomous containment requires opt-in at both control and executor. Dual-signed actions require an independent operator key; protect it separately from the control key. The executor's persistent nonce store supports replay rejection; preserve that state across restarts. Dry-run is the default, and enforcement can disrupt workloads. Validate rollback and recovery in your environment before use.

## Operator MCP and delegated runs

An investigator token needs an explicit run-spawn grant. The control daemon
scopes each delegated child to one open incident and its host, copies the
parent's collector scope, caps the lifetime, and enforces four active children
per parent principal. The child cannot delegate or manage trigger leases.
Cancellation by the run token or by an unbound, in-scope investigator token
with the run-spawn grant and matching principal revokes the run token. The ledger keeps token hashes for
credential lookup, and the run-start audit records the delegation metadata
without the child token.

The operator MCP adapter uses its base token for fleet reads and selects each
child token by explicit run ID for run-scoped tools. The adapter keeps child
credentials in memory. Run IDs become unknown to the adapter after TTL or
restart, and the run rows remain queryable through authorized reads. The
adapter handles calls serially, so a slow control daemon RPC can stall the
session for the default 15-second timeout.

A transport cut can leave a recorded `tool_call` without a `tool_result`.
The operation may have applied. Check the timeline and current state before
retrying. Watch and action proposals replay safely with the same idempotency
key. Findings and notes have no idempotency key.

The control and edge policy gates govern temporary watches. Expectation rules
require operator approval, and actions proposed
from a delegated run require an independent operator signature. Codex shell
tools have their own security boundary. Run Codex under a dedicated OS user
with a read-only sandbox and empty working directory. Keep admin and signing
access outside that account. See the [operator setup](operator-agent.md).

## Limitations and verification

File observations report the hard link count. The collector refuses to read regular files with multiple links under roots added by a host profile. Built-in roots rely on administrative control and the host's hard link protections. With `fs.protected_hardlinks=1`, the default on Ubuntu and Debian, an unprivileged user cannot link to a sensitive file owned by someone else when the user lacks read or write access. Linux allows links to otherwise eligible ordinary files the user can both read and write. [Ubuntu file handling](https://documentation.ubuntu.com/security/security-features/process-memory/file-handling/) · [Debian kernel default](https://sources.debian.org/src/linux/7.0.4-1/fs/namei.c) · [Linux hard link rules](https://sources.debian.org/src/manpages/6.9.1-1/man/man5/proc_sys_fs.5)

Polling can miss short-lived events and is not syscall-level eBPF monitoring. Unprivileged socket ownership and journal visibility can be incomplete. Unix sockets and peer credentials are local; fleet mTLS, PKI, remote transport and external telemetry adapters are planned. A hash chain detects changes within the verified sequence but needs an independently retained checkpoint to make replacement or truncation evident.

Run the workspace tests, including adversarial integration coverage, and the synthetic benchmark:

```sh
cargo build --workspace
cargo test --workspace
PYTHONPATH=reasoner python3 -m unittest discover -s reasoner/tests -v
node --test console/test/server.test.mjs
PYTHONPATH=reasoner python3 -m defsec_reasoner benchmark
```

The benchmark uses a real local control process and synthetic inputs; its results are not evidence of production detection coverage. See [reasoner/README.md](../reasoner/README.md) for scenarios and [SECURITY.md](../SECURITY.md) for reporting.
