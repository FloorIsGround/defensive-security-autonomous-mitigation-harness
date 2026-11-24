# Security Policy

## Scope & Operational Posture

DefSecAutMit is an active defensive monitoring and policy-bounded mitigation harness. It is designed around **physical trust-domain separation**, **read-only-first defaults**, and **deterministic policy enforcement** rather than prompt-only guardrails.

Important safety defaults to preserve in any deployment:
- **`agent-d`** runs unprivileged with zero Linux capabilities (`CapEff=0`) and enforces its own local safety floor (`crates/policy/src/edge_floor.rs`) independently of `control-d`.
- **`mcp-adapter`** defaults to `--mode read-only` (7 discovery/query tools); `--mode investigator` is explicit opt-in.
- **`reasoner-d`** defaults to `enable_action_proposals=False`.
- **`action-exec-d`** defaults to `--mode dry-run` with autonomous containment disabled; `--mode enforce` and `--enable-autonomous-containment` require explicit administrator opt-in.
- **`console/`** binds strictly to `127.0.0.1` and disables administrative mutations unless `--enable-admin` is passed.

See [docs/security-model.md](docs/security-model.md) for the full threat model and known limitations.

## Reporting a Vulnerability

Please **do not** open a public GitHub issue for security vulnerabilities, signing/verification bypasses, path-traversal escapes (`openat2`/denylist), privilege-escalation bugs, or policy-gate bypasses.

Instead:
1. Use GitHub **Private Vulnerability Reporting** (Security tab -> *Report a vulnerability*) on this repository.
2. Include a clear description of the affected component (`agent-d`, `control-d`, `policy`, `mcp-adapter`, `action-exec-d`, `reasoner`, or `console`), minimal reproduction steps or a failing unit test, and potential impact.
3. Never include live API keys, private signing keys, or production host telemetry in your report.

## Security Expectations for Contributions

Pull requests touching untrusted parsing, signing, collectors, policy validation, or execution drivers must maintain:
- Strict `#[serde(deny_unknown_fields)]` on external/untrusted wire and spec schemas.
- Domain-separated Ed25519 signing over RFC 8785 Canonical JSON bytes (`raw_payload` verified before deserialization).
- Zero shell invocation (`sh -c`) in collectors or action drivers.
- Zero `innerHTML` or unsanitized HTML interpolation in `console/public/`.
- Regression tests covering both valid behavior and adversarial rejection paths.
