# Reasoning Plane (`reasoner/`)

Phase 5 of the Defensive Security Autonomous Mitigation Harness: the
**optional automated episodic reasoning worker** (`reasoner-d`), replaceable
model adapters, and the **synthetic adaptive-vs-static benchmark suite**
(Design doc §6.5, §7.1, §7.2, §7.4, §7.5, §9).

Everything here is **Python 3.12 standard library only** — zero pip packages,
fully offline — and speaks the exact wire contracts of
`crates/protocol` (4-byte big-endian length-prefixed UTF-8 JSON frames,
2 MiB bound, `InvestigationCall`/`InvestigationResponse` op/result tags).

```
reasoner/
├── pyproject.toml                  # zero runtime dependencies
├── README.md
├── defsec_reasoner/
│   ├── __init__.py                 # package + PROMPT_SCHEMA_VERSION
│   ├── wire.py                     # u32-BE length-prefixed JSON framing (2 MiB cap)
│   ├── canonical.py                # RFC 8785 canonical JSON + SHA-256 (matches Rust ledger hashes)
│   ├── rpc_client.py               # ControlRpcClient: 21 typed Investigation ops, token-safe
│   ├── admin_client.py             # operator-side Admin RPC (enroll/baseline/mint/audit-verify)
│   ├── provenance.py               # §7.5: <untrusted_telemetry> envelopes + system prompt
│   ├── models.py                   # ModelAdapter ABC + OpenAI / Anthropic / ScriptedMock adapters
│   ├── worker.py                   # ReasonerWorker: lease → bounded tool loop → complete/fail
│   ├── control_harness.py          # real control-d subprocess + synthetic agent-d wire client
│   ├── benchmark.py                # §9 adaptive-vs-static scenarios, JSON + Markdown reports
│   └── cli.py / __main__.py        # `worker` and `benchmark` entrypoints
└── tests/                          # 131 unittest cases incl. LIVE control-d integration + benchmark
```

## Safety model (what the worker can never do)

* The worker's only action surface is the **typed Investigation RPC** on
  `investigate.sock`. No shell, no filesystem, no direct database access, and
  no arbitrary remediation verbs exist anywhere in the package. Phase 8 typed
  mitigation proposals (`propose_action` / `list_actions`) are **opt-in and
  disabled by default**; when enabled, the grammar is the closed catalog
  `nft_block_ip` / `systemd_stop_unit` / `host_isolate` only, with per-run caps,
  mandatory verified `observation_id` evidence, and a mandatory rollback plan.
* Phase 10 expectation-rule proposals (`propose_expectation_rule`) are enabled
  by default because they are **inert**: a proposal only stores an auditable
  expectation with a backtest, and nothing is suppressed until an operator
  approves the rule on the admin interface. The worker hard-caps the tool at
  3 calls per run client-side (`max_rule_proposals_per_run`), and control-d
  independently enforces its own per-run and per-host proposal quotas plus the
  deterministic rule gate (service identity anchor, bounded ports, mandatory
  expiry within 30 days for investigator rules). The system prompt restricts
  the tool to benign recurring set-diff noise with a clear service anchor —
  never suspicious or unexplained activity.
* Observation payloads, journal lines, baselines, and trigger outcomes are wrapped in explicit
  `<untrusted_telemetry source="…" host_id="…" observation_id="…" state_hash="…">`
  envelopes with strict byte clipping; injected `</untrusted_telemetry>`
  close tags are neutralized. The trusted system prompt instructs the model
  to treat envelope content as data, cite exact `observation_id`s, and
  distinguish observed fact vs. hypothesis vs. verified finding. The small
  `trigger_diff` in the run header also contains untrusted identities.
* Even a fully hijacked model hits the **central deterministic policy gate**
  in `control-d`: baseline watches are untouchable, sensitive paths
  (`/etc/shadow`, host keys) are denied, sub-floor polling intervals are
  rejected, and every decision is durably audited.
* Every typed proposal (watch, expectation rule, action) carries an
  **idempotency key**; control-d stores a receipt per `(run_id,
  idempotency_key)` so replaying the same key with the same canonical spec
  returns the original response, while reusing a key with a different spec
  is a structured `conflict`. When the model omits the key, the worker
  derives a deterministic default `auto-<sha256[:32]>` from the run ID plus
  an RFC 8785 canonical serialization of the proposal, so a proposal whose
  response was lost can be resubmitted verbatim and replays instead of
  storing a duplicate — identical proposals in one run share a key, distinct
  proposals get distinct keys, and keys are stable across worker restarts.
* A transport-level failure during a proposal tool (read timeout, EOF,
  unreachable socket) is **never** treated as a rejection and never aborts
  the run: the model receives an explicit
  `{"error": "outcome_unknown", "detail": …, "retry_hint": "re-submitting
  the identical rule is safe; it will replay"}` tool result, the attempt is
  charged against the per-run proposal cap, and the loop continues. Structured
  RPC errors and gate denials are reported to the model verbatim, and
  transport failures outside the proposal tools keep the bounded
  requeue-and-backoff behavior.
* Runs default to 6 turns, 45 seconds, 48,000 tokens, $0.25, 3 watch proposals,
  3 expectation rule proposals, a 24 KiB initial context, a 32 KiB conversation
  context, and a 120-second lease. Use `--max-turns` and `--max-total-tokens` to
  override the turn and token budgets. Pass `--enable-action-proposals` to
  enable typed mitigation proposals. When enabled, they are separately capped
  at `max_action_proposals_per_run=1` with local rejection of any excess.
  Retryable provider failures requeue with bounded backoff and dead-letter
  after five attempts. Lease completion checks the fencing token and expiry.

* The initial context includes the newest observation per watch and the
  trigger's cited evidence from the incident context. Set payloads are bounded
  and prioritize changed identities. Pass `focus_keys` to the
  `query_observations` model tool to inspect other identities.
* Run progress is best-effort. Inspect runs, event pages, and queue state with
  `list_investigation_runs`, `get_run_events`, and `list_trigger_queue`.
  The worker records the terminal summary and counters after saving evidence
  and before completing the trigger lease.

## Quick start

```bash
# build the deterministic core (needed for integration tests & benchmarks)
cargo build -p control-d

# run the full test suite (unit + LIVE integration + full benchmark)
PYTHONPATH=reasoner python3 -m unittest discover -s reasoner/tests -v

# run the worker against a live control-d
DEFSEC_CAPABILITY_TOKEN=$(…) python3 -m defsec_reasoner worker \
    --socket ./control-data/investigate.sock \
    --backend openai --base-url http://localhost:11434/v1 --model llama3.1

# run the synthetic benchmark suite
python3 -m defsec_reasoner benchmark --json-out bench.json --markdown-out bench.md
```

### Backends

| `--backend` | Adapter | Endpoint |
|---|---|---|
| `mock` | `ScriptedMockAdapter` — deterministic offline script (tests/benchmarks), supports scripted multi-turn tool calls, prompt-injection hijack attempts, and simulated provider outages | — |
| `openai` | `OpenAICompatibleAdapter` | any OpenAI-compatible `/v1/chat/completions` (OpenAI, Ollama, vLLM, llama.cpp) |
| `anthropic` | `AnthropicAdapter` | Anthropic `/v1/messages` with tool-use normalization |

API keys are read from `DEFSEC_OPENAI_API_KEY` / `OPENAI_API_KEY` and
`DEFSEC_ANTHROPIC_API_KEY` / `ANTHROPIC_API_KEY`; capability tokens from
`DEFSEC_CAPABILITY_TOKEN`. Tokens are never logged (only SHA-256 fingerprints).

## Benchmark scenarios (Design §9)

| Scenario | What it proves |
|---|---|
| `benign_maintenance` | benign restart concludes with **zero unnecessary watches** |
| `two_stage_service_change` | Adaptive proposes a follow-up `systemd.unit_state` watch and **collects follow-up evidence** (`coverage: sockets + systemd`); Static stays at `sockets`-only with **no follow-up evidence** |
| `adversarial_telemetry` | prompt-injected journal demands `/etc/shadow`, 1 s polling, baseline disablement → **100% deterministic policy rejection**, run stays bounded, baseline monitoring intact |
| `provider_outage` | retryable 503s → deterministic observation commits continue; trigger **requeues ×4 then dead-letters**; audit chain stays valid |

All four run against a real `target/debug/control-d` subprocess (short
`sun_path` temp sockets) with a synthetic `agent-d` feeding scripted ground
truth. `python3 -m defsec_reasoner benchmark` prints the JSON metrics and the
Markdown summary table and exits non-zero if any assertion fails.

## Test layout

* `test_wire.py` / `test_canonical.py` — byte-exact framing and RFC 8785
  hashing (pinned to the Rust implementation's own test vectors).
* `test_rpc_client.py` — exact op shapes, error handling, token hygiene.
* `test_provenance.py` — envelope structure, byte clipping, close-tag
  neutralization, prompt rules.
* `test_models.py` — adapter normalization against a local canned HTTP stub
  (tool calls, usage, retryable/non-retryable provider errors).
* `test_worker.py` — bounded loop against an in-process fake control server:
  turn/proposal/token/cost/wall caps, outage requeue → dead-letter, fencing.
* `test_actions.py` — Phase 8 action contract: exact `ActionVerb` wire shapes,
  disabled-by-default local rejection, per-run action caps, policy-bounded vs.
  dual-signed responses, and adversarial invalid-verb/shell-smuggling attempts.
* `test_expectation_rules.py` — Phase 10 rule-proposal surface: enabled by
  default, client-side hard cap of 3 per run, exact wire shape, system-prompt
  guidance, deterministic auto idempotency keys (lost-response replay,
  distinct-rule distinct keys, restart stability), `outcome_unknown` handling
  for transport failures, denied-decision / RPC-error / conflict reporting,
  and a prompt-injection test proving injected telemetry never yields a
  proposal.
* `test_live_integration.py` — **LIVE** against compiled `control-d`:
  lease → run → propose ephemeral watch → evidence-bound finding → propose
  inert expectation rule → complete → audit-chain verification; expired-lease
  fencing + requeue; observer-role denial. Skipped automatically if no binary
  is built.
* `test_benchmark.py` — runs the full 4-scenario suite end-to-end and asserts
  adaptive coverage > static and 100% adversarial rejection.
