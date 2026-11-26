# Expectation Rules (Phase 10) — Design Contract

Status: frozen contract for Phase 10 implementation lanes.

## Problem

Set-based watches (`set_diff`, used for `sockets.listening` and, from Phase 11, `connections.outbound` and `packages.inventory`) compare the current set against the accepted baseline (or last observation) exactly. On desktops and dynamic servers this produces constant noise:

* applications open and close listening sockets on demand (e.g. a remote-desktop server's loopback ports, a browser's local helper, ephemeral UDP);
* a restarted service keeps the same socket but changes `inode`, `pid` and `pid_start_time_ticks`, which shows up as `modified`;
* the only way to silence it today is to re-promote the whole baseline, which also hides real changes.

Operators want to say "this service may listen on these ports — whether or not it is currently up — and that is fine", and more generally have small, auditable, SIEM-like rules, ideally drafted by an LLM and approved by a human.

## Non-goals

* No query language, regexes or scripting. Rules are a closed typed schema.
* Rules never affect collector errors, staleness, liveness or non-set predicates. They are applied only inside `set_diff` evaluation of a *valid* sample.
* A model can never activate a rule. Model and MCP proposals are inert until an operator approves them on the admin interface.

## Schema (`crates/protocol/src/rules.rs`)

```rust
#[serde(deny_unknown_fields)]
pub struct ExpectationRuleSpec {
    pub scope: RuleScope,
    pub matches: Vec<MatchClause>,          // 1..=8 clauses, AND-ed
    pub effect: RuleEffect,
    pub rationale: String,                  // 1..=1024 bytes
    #[serde(default)]
    pub expires_at: Option<DateTime<Utc>>,
}

#[serde(deny_unknown_fields)]
pub struct RuleScope {
    pub host_id: String,
    pub collector: CollectorType,           // must be a set-producing collector
    #[serde(default)]
    pub watch_id: Option<String>,           // None = every set_diff watch of that collector on the host
}

#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum MatchClause {
    Eq { field: String, value: RuleValue },
    In { field: String, values: Vec<RuleValue> },        // 1..=32 values
    Range { field: String, min: i64, max: i64 },         // inclusive, min <= max
    Prefix { field: String, value: String },             // string fields only
}

#[serde(untagged)]
pub enum RuleValue { Int(i64), Bool(bool), Text(String) }   // Text <= 256 bytes

#[serde(rename_all = "snake_case")]
pub enum RuleEffect {
    /// Matching items may appear or disappear freely; their modifications are ignored.
    AllowOptional,
    /// At least one current item must match; otherwise report `missing_required`.
    RequirePresent,
    /// Ignore `modified` changes for matching items (adds/removes still alert).
    IgnoreModified,
}
```

### Matchable fields (closed registry in `crates/policy/src/rule_gate.rs`)

| Collector | Set field / identity | Matchable fields |
|---|---|---|
| `sockets.listening` | `sockets` / `socket_key` | `protocol`, `local_addr`, `local_port`, `uid`, `comm`, `systemd_unit`, `bind_scope` (derived) |
| `connections.outbound` (P11) | `flows` / `flow_key` | `protocol`, `remote_addr`, `remote_port`, `uid`, `comm`, `systemd_unit`, `remote_scope` (derived) |
| `packages.inventory` (P11) | `packages` / `package_key` | `name`, `arch` |

Flow keys use `<protocol>:<remote-address>:<port>:<uid>:<comm>`, with brackets around IPv6 addresses and percent encoding for process name bytes outside the URI unreserved set. A bare `?` means attribution is unavailable. A literal question mark is `%3F`. Package keys use validated `<name>:<arch>` fields. IPv4-mapped IPv6 addresses use their IPv4 meaning for `remote_scope`.

A partial or truncated current snapshot can show additions and modifications of entries it contains. It cannot establish removals or that a `require_present` rule is missing a match.

When a set-diff snapshot reports `truncated: true` and the comparison snapshot and previous valid sample were untruncated, the watch emits `truncation_began` with any known omitted counts. The previous sample prevents repeated alerts when the comparison uses a fixed accepted baseline. Recovery by itself does not trigger. Expectation rules filter item changes and preserve the truncation signal.

Derived fields are computed by the evaluator, never sent by the agent:

* `bind_scope`: `loopback` (127.0.0.0/8, ::1), `any` (0.0.0.0, ::), otherwise `specific`.
* `remote_scope`: `loopback`, `private` (RFC 1918, fc00::/7, fe80::/10, 100.64.0.0/10), otherwise `public`.

Unknown fields, type mismatches (e.g. `Prefix` on an integer field) and clauses for a collector not in the registry are rejected by the gate. A collector whose registry entry is missing (e.g. P11 collectors before P11 merges) is simply not rule-capable yet.

## Evaluation (pure function in `crates/policy/src/rules.rs`)

```rust
pub struct RuleEvaluation {
    pub outcome: PredicateOutcome,                 // filtered outcome
    pub suppressed: BTreeMap<String, Vec<String>>, // rule_id -> identity keys suppressed (<= 50 keys per rule)
    pub suppressed_counts: BTreeMap<String, usize>, // exact counts before key sampling
    pub missing_required: Vec<String>,             // rule_ids whose RequirePresent had no match
    pub matched_rule_ids: Vec<String>,             // rules that matched at least one item (for hit counts)
}

pub fn apply_expectation_rules(
    predicate: &TriggerPredicate,
    collector: CollectorType,
    raw: PredicateOutcome,
    current: Option<&Value>,
    reference: Option<&Value>,
    rules: &[ActiveRule],                          // (rule_id, spec), already filtered to scope and unexpired
) -> RuleEvaluation
```

* Only applies when `predicate` is `SetDiff` using the collector registry’s set field and identity key, and `raw` is `Triggered` or `NotTriggered` with a valid sample. Every other outcome is returned unchanged.
* `AllowOptional`: drop added keys whose *current* item matches, removed keys whose *reference* item matches, and modified keys whose current item matches.
* `IgnoreModified`: drop modified keys whose current item matches.
* `RequirePresent`: if no current item matches, record the rule in `missing_required`. A non-empty `missing_required` makes the outcome `Triggered` even when the diff is empty after filtering.
* If all diffs are filtered, nothing is missing, and truncation did not begin, the outcome becomes `NotTriggered`.
* The `Triggered` details keep the existing `added` / `removed` / `modified` arrays (filtered) and add `missing_required` and `suppressed_by_rules` when they are non-empty. The reason string keeps the `set '<field>' diff: +a -r ~m` form, with ` (k suppressed by rules)` and ` missing required: <n>` appended when relevant.
* The evaluation is deterministic: rules are applied in `rule_id` order and every key list is sorted.

### `set_diff` volatile fields

`TriggerPredicate::SetDiff` gains `#[serde(default, skip_serializing_if = "Vec::is_empty")] ignore_fields: Vec<String>`. These top-level item fields are removed from both items before the `modified` comparison. Existing signed specs serialize identically. The edge floor validates it: ≤ 8 entries, each a valid field identifier. Recommended for sockets: `["inode","pid","pid_start_time_ticks"]`.

## Gate (`crates/policy/src/rule_gate.rs`)

`pub fn validate_rule(spec: &ExpectationRuleSpec, origin: RuleOrigin, now: DateTime<Utc>, cfg: &RuleGateConfig) -> PolicyDecision`, where `RuleOrigin` is `Operator` or `Investigator`. Rule IDs are of the form `rule-gate/...` and the policy version follows the existing control gate. The gate rejects:

1. Empty `matches`, more than 8 clauses, `In` with 0 or more than 32 values, `Range` with min > max, oversize text, or an empty rationale.
2. Unknown fields or type mismatches for the collector.
3. **Identity anchor.** An `AllowOptional` or `IgnoreModified` rule on sockets or connections must constrain at least one of `systemd_unit`, `comm` or `uid` with `Eq` or `In`.
4. **Port bounds.** An `AllowOptional` sockets rule must constrain `local_port` (an `Eq`, `In`, or `Range` of width ≤ 1024). The exception is a rule that also pins `bind_scope = loopback`, which may use a range up to the full ephemeral span 1024–65535.
5. **Wildcard binds.** A sockets `AllowOptional` rule that can match `bind_scope = any` (no `bind_scope` clause, or one allowing `any`) must have `systemd_unit` `Eq` and `local_port` `Eq` or `In` (≤ 8 ports).
6. **Connections.** An `AllowOptional` rule that can match `remote_scope = public` must constrain `remote_addr` or `remote_port`.
7. **Packages.** An `AllowOptional` or `IgnoreModified` rule must pin `name` with `Eq`, `In`, or a `Prefix` of at least 3 characters.
8. **Investigator origin.** `expires_at` is required and must be at most 30 days in the future. At most 3 rule proposals per run, and at most 20 pending proposals per host.
9. `expires_at` in the past.

## Lifecycle and storage (control-d, `schema_v5.sql`)

```sql
CREATE TABLE expectation_rules (
    rule_id TEXT PRIMARY KEY,                 -- "rule-" + uuid
    host_id TEXT NOT NULL REFERENCES hosts,
    collector_type TEXT NOT NULL,
    watch_id TEXT,
    spec_json TEXT NOT NULL,                  -- canonical ExpectationRuleSpec
    status TEXT NOT NULL CHECK (status IN ('proposed','active','rejected','revoked')),
    origin TEXT NOT NULL CHECK (origin IN ('operator','investigator')),
    proposed_by TEXT NOT NULL,
    run_id TEXT REFERENCES agent_runs,
    incident_id TEXT REFERENCES incidents,
    idempotency_key TEXT,
    backtest_json TEXT,
    created_at TEXT NOT NULL,
    decided_by TEXT,
    decided_at TEXT,
    decision_note TEXT,
    expires_at TEXT,
    hit_count INTEGER NOT NULL DEFAULT 0,
    last_matched_at TEXT,
    UNIQUE (run_id, idempotency_key)
);
CREATE INDEX expectation_rules_scope ON expectation_rules (host_id, collector_type, status);
```

* Migration v5 also stores proposal receipts keyed by run and idempotency key, so retries return the original policy decision and backtest. Denied submissions get receipts and policy decisions. Only stored proposals consume the per-run quota, and only unexpired pending proposals consume the host quota.
* An expired rule is never applied. A `proposed` or `active` rule past its expiry is reported as `expired` (computed, not stored). `rejected` and `revoked` rules keep their terminal status.
* `hit_count` and `last_matched_at` update in the same transaction as the observation that matched.
* Audit events (new `AuditEventType` variants): `RuleProposed`, `RuleActivated`, `RuleRejected`, `RuleRevoked`. Activation records the approver and the canonical spec hash.
* Every proposal and decision writes a `policy_decisions` row, like watch proposals.
* When a rule is activated or revoked, nothing is retroactively re-evaluated. It applies from the next observation.

## RPC (`crates/protocol/src/rpc.rs`)

Investigation interface:

* `ProposeExpectationRule { run_id, idempotency_key, rule: ExpectationRuleSpec }`. Requires the investigator role and run scope; the rule host must be within the capability. The gate runs with `Investigator` origin. If allowed, the rule is stored as `proposed` with a backtest. Response: `RuleProposalEvaluated { decision: PolicyDecision, rule_id: Option<String>, backtest: Option<RuleBacktest> }`.
* `ListExpectationRules { host_id: Option<String>, statuses: Option<Vec<String>>, limit: Option<u32>, before: Option<String> }`. Any role, scoped to the capability's hosts. Response: `ExpectationRules { rules: Vec<ExpectationRuleRecord>, next_before: Option<String> }`.

* `GetIncidentContext` can include `rule_suppression: { rules: [{ rule_id, rationale, suppressed_keys, count }], total }`. This is the suppression recorded on the newest set-diff trigger event visible to the caller within the incident's collector scope. Each contributing rule is listed in rule ID order, with up to 20 sorted identity keys and the full count of suppressed changes. `total` sums those counts. The rationale identifies the rule even after revocation or expiry. The field is omitted for older triggers and when the newest visible set-diff trigger recorded no suppression.

Admin interface:

* `CreateExpectationRule { rule, actor }`. Uses the `Operator` gate and activates immediately. Response: `RuleDecided { rule_id, status }`.
* `DecideExpectationRule { rule_id, approve: bool, actor, note: Option<String> }`. Only valid on `proposed` rules. Approval re-runs the gate with `Operator` origin.
* `RevokeExpectationRule { rule_id, actor, reason }`. Only valid on `active` rules.
* `BacktestExpectationRule { rule }`. Response: `RuleBacktestResult { backtest: RuleBacktest }`.
* `ListExpectationRules { host_id, statuses, limit, before }`. Response: `ExpectationRules { .. }`.

Both list interfaces order by creation time descending and rule ID ascending, with a default of 50 and a maximum of 100 records per page. When another page exists, pass the opaque `next_before` string as `before` with the same filters and scope. The boundary is exclusive, including when several rules share a creation timestamp.

Create, approval and backtest gate denials return `Error { code, message, decision: PolicyDecision }`. The decision contains the policy version used for that request. Other admin failures omit `decision`.

Shared types:

```rust
pub struct RuleBacktest {
    pub observations_scanned: u32,   // newest <= 50 valid observations of in-scope set_diff watches
    pub triggered_before: u32,       // how many of those would have triggered with current active rules
    pub triggered_after: u32,        // ... with current active rules + this rule
    pub items_matched: u32,          // distinct identity keys the rule matches in the scanned observations
    pub sample_keys: Vec<String>,    // <= 10
    pub currently_matching: u32,     // matches in the newest observation
}
pub struct ExpectationRuleRecord {
    pub rule_id: String, pub status: String /* proposed|active|rejected|revoked|expired */,
    pub origin: String, pub proposed_by: String,
    pub run_id: Option<String>, pub incident_id: Option<String>,
    pub spec: ExpectationRuleSpec, pub backtest: Option<RuleBacktest>,
    pub created_at: DateTime<Utc>, pub decided_by: Option<String>, pub decided_at: Option<DateTime<Utc>>,
    pub decision_note: Option<String>, pub hit_count: u64, pub last_matched_at: Option<DateTime<Utc>>,
}
```

Backtests order observations by ledger receipt order and use the watch revision associated with each observation. They reconstruct the prior successful sample by receipt order and the accepted baseline by promotion time. Historical-session samples that did not advance the live checkpoint can affect this reconstruction. A promotion timestamp equal to the receipt timestamp is treated as later. Investigator backtests include baseline watches and watches from the investigator's incident.

## Surfaces

* **admin-cli**: `list-rules [--host HOST] [--status STATUS] [--limit N] [--before CURSOR]`, `create-rule RULE_JSON --actor`, `decide-rule RULE_ID --approve|--reject --actor [--note]`, `revoke-rule RULE_ID --actor --reason`, `backtest-rule RULE_JSON`.
* **mcp-adapter**: `list_expectation_rules` in both modes. `propose_expectation_rule` in investigator (and later operator) mode.
* **reasoner-d**: a `propose_expectation_rule` tool. Proposals are inert, so it is enabled by default, capped at 3 per run, and the system prompt explains when to use it: benign recurring noise with a clear service anchor, not suspicious activity.
* **Console**: a Rules view (active, pending with backtest and Approve/Reject, history). The incident diff gains inline "Allow for this service" actions that prefill a rule (unit, comm, uid, protocol, port, loopback scope) and show the backtest before creation.
