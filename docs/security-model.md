# Security model

DefSecAutMit is a defense-in-depth monitoring system, not a guarantee against a compromised host. Trust in signing keys, local control, host identity and the operating system remains essential.

## Boundaries

`control-d` decides whether a proposed watch or action meets central policy. The edge independently verifies signed bundles and enforces local floors on schedules, paths and units; the separate action executor applies its own action safety configuration, protected CIDRs and units, signatures, expiry and replay checks. These gates reduce reliance on any one reasoning client. They do not protect against local root, who can alter processes, keys, configuration, evidence or the host itself.

Telemetry is untrusted: the reasoner wraps it in `<untrusted_telemetry>` envelopes, clips it and neutralizes closing tags. Model instructions and typed tools narrow the available behavior, while deterministic policy makes the actual authorization decision. Prompt injection can still affect analysis or consume resources. The console renders telemetry as text nodes and applies CSP, origin and Host checks; its BFF keeps the token out of browser responses. Keep the console on loopback and protect its socket credentials.

Containment is disabled by default. Autonomous containment requires opt-in at both control and executor. Dual-signed actions require an independent operator key; protect it separately from the control key. The executor's persistent nonce store supports replay rejection; preserve that state across restarts. Dry-run is the default, and enforcement can disrupt workloads. Validate rollback and recovery in your environment before use.

## Limitations and verification

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
