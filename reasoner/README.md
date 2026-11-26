# Reasoning Plane (`reasoner/`)

Phase 5 of the Defensive Security Autonomous Mitigation Harness: the
**optional automated episodic reasoning worker** (`reasoner-d`), replaceable
model adapters, and the **synthetic adaptive-vs-static benchmark suite**
(Design doc §6.5, §7.1, §7.2, §7.4, §7.5, §9).

The worker and offline fixtures use the Python 3.12 standard library. Direct ChatGPT
sign-in adds the optional `chatgpt` dependency for identity-token verification.
The worker speaks the wire contracts of
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
│   ├── codex_worker.py             # Phase 12 codex-worker: lease → delegated run → codex exec
│   ├── control_harness.py          # real control-d subprocess + synthetic agent-d wire client
│   ├── benchmark.py                # §9 adaptive-vs-static scenarios, JSON + Markdown reports
│   └── cli.py / __main__.py        # `worker`, `codex-worker`, and `benchmark` entrypoints
└── tests/                          # unittest cases incl. live control-d integration + benchmark
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

## Codex CLI investigator

`python3 -m defsec_reasoner codex-worker` leases triggers like `reasoner-d`
but runs each investigation inside the official **Codex CLI**: it starts a
delegated run with a `may_spawn_runs` parent token, writes the child token to
a 0600 file in a private 0700 temp dir, and spawns
`codex exec --json --ephemeral --sandbox read-only --ignore-user-config` with
an `mcp-adapter --mode investigator --token-file …` MCP server bound to that
run, the prompt on stdin, and a scrubbed environment (`PATH`, `HOME`,
`CODEX_HOME` if set, `LANG`, `TERM` only). The model's JSONL events are mapped
into run progress (agent messages → `model_text`, MCP tool calls →
`tool_call`/`tool_result`, turns → `turn_started`, unknown event types ignored
but counted), a wall-clock budget is enforced by killing the process group,
and the run finishes `completed`/`budget_exhausted`/`failed` with the last
agent message as the summary before the lease completes or dead-letters.

Sessions are ephemeral by default. Pass `--persist-sessions` to resume completed sessions for the same incident and grant, or supply `--session-dir PATH` to enable persistence at a specific location. Each wake opens a fresh delegated run.

Safety properties, all verified by tests:

* Neither the parent nor the child token ever appears on a command line, in
  the environment passed to Codex, or in a log line — the child token reaches
  the adapter only through its 0600 token file, which is always deleted
  (including on exceptions and SIGTERM).
* Startup fails closed unless `get_capability` shows an unbound investigator
  token with `may_spawn_runs`. The parent token is never narrowed, and the
  delegated child cannot manage leases, spawn runs, or approve anything.
* The controller validates ephemeral watches and gates rule and action proposals. The prompt reuses the
  provenance envelopes and injection-defense rules from `worker.py`.
* Missing codex binary or ChatGPT auth failure is non-retryable (dead-letter
  plus an `ALERT:` log); crashes requeue with control-d's retry cap; timeouts
  end the run `budget_exhausted` with the lease completed.

See `docs/operator-agent.md` (autonomous worker) for the systemd unit, the
dedicated-user setup with its own `CODEX_HOME`, and the event-mapping table.
Tests live in `tests/test_codex_worker.py` with the fake
`tests/fixtures/fake_codex.py`, which performs real MCP calls through the
compiled `mcp-adapter`; an opt-in smoke test against the real Codex CLI is
gated behind `DEFSEC_LIVE_CODEX=1`.

## Quick start

```bash
# build the controller and the investigator’s MCP adapter
cargo build -p control-d -p mcp-adapter

# run the full test suite (unit + LIVE integration + full benchmark)
PYTHONPATH=reasoner python3 -m unittest discover -s reasoner/tests -v

# run the custom model-adapter worker (defaults to mock)
DEFSEC_CAPABILITY_TOKEN=$(…) python3 -m defsec_reasoner worker \
    --socket ./control-data/investigate.sock \
    --backend openai --base-url http://localhost:11434/v1 --model llama3.1

# run the Codex CLI investigator against a live control-d (needs a
# may_spawn_runs investigator token and a logged-in Codex CLI)
DEFSEC_CAPABILITY_TOKEN=$(…) python3 -m defsec_reasoner codex-worker \
    --socket ./control-data/investigate.sock \
    --codex-bin codex \
    --mcp-adapter-bin ./target/debug/mcp-adapter

# run the synthetic benchmark suite
python3 -m defsec_reasoner benchmark --json-out bench.json --markdown-out bench.md
```

### Backends

| `--backend` | Adapter | Endpoint |
|---|---|---|
| `mock` | `ScriptedMockAdapter` — deterministic offline script (tests/benchmarks), supports scripted multi-turn tool calls, prompt-injection hijack attempts, and simulated provider outages | — |
| `openai` | `OpenAICompatibleAdapter` | any OpenAI-compatible `/v1/chat/completions` (OpenAI, Ollama, vLLM, llama.cpp) |
| `anthropic` | `AnthropicAdapter` | Anthropic `/v1/messages` with tool-use normalization |
| `chatgpt` | Direct Sign in with ChatGPT | First-party streaming Responses with the selected ChatGPT profile |
| `opencode-go` | OpenCode Go | Go Chat Completions gateway, with one session header per conversation |

API keys are read from `DEFSEC_OPENAI_API_KEY` / `OPENAI_API_KEY` and
`DEFSEC_ANTHROPIC_API_KEY` / `ANTHROPIC_API_KEY`; capability tokens from
`DEFSEC_CAPABILITY_TOKEN`. Tokens are never logged (only SHA-256 fingerprints).

### Subscription-backed investigators

Choose one backend and an explicit model per worker process. The same choices apply to `worker --followups-only` and `host-review-worker`. The normal control-d capability, policy and evidence grants still apply. For external discovery and follow-ups, use the exact endpoint in `DEFSEC_DISCOVERY_EXPORT_GRANTS`. For scheduled reviews use `DEFSEC_REVIEW_EXPORT_GRANTS` with the matching purpose. ChatGPT uses `https://api.openai.com/v1`. Go uses `https://opencode.ai/inference/go/openai/v1`. A provider error stays on the selected route.

**ChatGPT plan usage.** Install the optional identity-verification dependency and sign in as the OS user that runs the worker. The browser callback targets loopback on that machine. Each profile has its own app-issued client registration and verified account identity. Choose a model slug from the profile’s live catalog. The example uses Luna High when offered.

```sh
python3 -m pip install './reasoner[chatgpt]'
defsec-reasoner chatgpt login --profile default
defsec-reasoner chatgpt models --profile default
defsec-reasoner worker --socket ./control-data/investigate.sock \
  --backend chatgpt --chatgpt-profile default --model gpt-6-luna --effort high
```

Use `chatgpt profiles` to inspect connection state and `chatgpt logout --profile default` to disconnect. Add a separate named profile to connect another account. The CLI keeps credentials under `$XDG_STATE_HOME/defsec-reasoner/chatgpt` (default `~/.local/state/defsec-reasoner/chatgpt`). Refreshes are locked across worker processes. The adapter streams stateless Responses, retains the tool history for the current investigation, and dispatches only completed calls from the worker’s tool catalog. The plan endpoint does not accept a server-side output cap. The worker checks its estimate before sending and discards tool calls when returned usage exceeds its local allowance. Account-side plan limits and credit settings govern actual consumption. [Plan integration](https://developers.openai.com/siwc/token-sharing-open-source/models-and-inference) · [Preview limits](https://developers.openai.com/siwc/token-sharing-open-source/preview-limitations) · [ChatGPT usage](https://chatgpt.com/settings/usage)

**OpenCode Go.** Supply the workspace key through `OPENCODE_GO_API_KEY`, a service credential file through `OPENCODE_GO_API_KEY_FILE`, or an owner-readable file at `~/.local/state/defsec-reasoner/opencode-go.key` (honors `XDG_STATE_HOME`). Run `defsec-reasoner opencode-go models` to list the workspace’s tool-capable Go chat model IDs. Listing uses metadata only. Select a Go model ID such as `beam-free` or `glm-5.3-flash`. Availability, free promotions and extra usage settings are controlled by OpenCode.

Investigator testing currently focuses on `beam-free` and `hungerg-free`. The Go benchmark requests high reasoning effort for Beam and records the setting on each request. Use `--beam-effort default` to replay the original provider-default cases. The runner checks the workspace’s listed input and output prices before sending synthetic cases. [Free-model comparison](../docs/evaluation/go-free-selection-2026-11-25.md) · [Beam High turn-budget results and replay](../docs/evaluation/beam-high-turns-2026-11-25.md)

First-party OpenAI benchmark runs request the Flex tier by default. The evidence-selection runner defaults to Luna Max and gives the initial investigation four turns and 192,000 tokens, followed by a one-turn, 16,384-token reassessment. Use `--profile luna-high --tier default --original-limits` on that runner to reproduce the historical Standard configuration. [Flex results and replay commands](../docs/evaluation/openai-flex-selection-2026-11-25.md)

```sh
defsec-reasoner worker --socket ./control-data/investigate.sock \
  --backend opencode-go --model beam-free
```

The adapter sends its own User-Agent and a stable `x-opencode-session` derived from the trigger, follow-up, discovery or review identity. Multiple turns and retries of the same conversation reuse it. A separate work item gets its own session. The gateway applies model eligibility to the investigator as a third-party harness. Subscription adapters report token usage. Their local USD estimate is zero, so a worker dollar budget cannot cap provider-side credits or overage charges. [Go model offerings](https://opencode.ai/docs/console/go/) · [Session requirements](https://opencode.ai/docs/console/harnesses)

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
* `test_codex_worker.py` — Phase 12 autonomous worker: fake `codex` CLI
  (fixtures/fake_codex.py) asserting the hygiene contract from inside the
  child (scrubbed env, token-free argv, 0600/0700 token file) while making
  real MCP calls through the compiled `mcp-adapter`; happy path, timeout with
  process-group kill, event cap, missing-binary/auth dead-letter, crash
  requeue, cleanup after exceptions, delegated-token scope; LIVE variants
  against compiled `control-d`; opt-in real-CLI smoke (`DEFSEC_LIVE_CODEX=1`).
* `test_benchmark.py` — runs the full 4-scenario suite end-to-end and asserts
  adaptive coverage > static and 100% adversarial rejection.

### Model turn budgets

The worker option `--max-completion-tokens` sets the per-request output ceiling (default 4,096). Onboarding also accepts `--onboarding-max-total-tokens` and `--onboarding-max-wall-seconds` (defaults 24,000 and 15). Each must fit inside the worker’s overall token and wall-clock limits.

Onboarding leases each exact host and discovery observation set before calling a model. The worker uses the configured time limits and leaves 15 seconds of the controller’s 900-second maximum lease for completion. Failed attempts wait 30 seconds after the first failure and 60 seconds after the second. A lost worker's backoff starts when its lease expires. Three attempts exhaust that observation set, while a saved interpretation remains available for watch installation without another model call.

Operators with a host-scoped capability covering all sources can call `list_host_interpretation_attempts(host_id, source_ids)` on `ControlRpcClient`. It returns attempt status, lease and retry deadlines, usage counts when available, and an error class or saved assessment version.

A remote follow-up worker uses the same `DEFSEC_DISCOVERY_EXPORT_GRANTS` as onboarding. A single grant must cover the host and the original question’s collector scope on that HTTPS endpoint. Ineligible questions stay available to another worker. Local scripted and loopback models can process questions in their RPC scope.

Before a worker turn, the HTTP adapters estimate input tokens from the encoded
request, including tool schemas and conversation history. A turn starts only
if the remaining run allowance leaves room for completion. The adapters
request at most the configured completion ceiling and cap the HTTP socket timeout at
the time remaining on the investigation loop's deadline. OpenAI-compatible
endpoints that require `max_tokens` can set
`DEFSEC_OPENAI_COMPLETION_TOKEN_FIELD=max_tokens` for the worker CLI.

The estimate uses serialized JSON bytes and can differ from the provider's
tokenizer. Providers can also omit usage, ignore completion limits, or
continue processing after the client times out. The socket timeout bounds
blocking operations and is not an absolute cancellation deadline. The worker
uses reported totals when available, records overruns as reported, and
blocks tool dispatch when the response reaches the token limit or exceeds
the cost or wall-time allowance. Cached input and reasoning counts are
available on the adapter result and worker outcome as subsets of the totals.
Anthropic cache reads and writes are added to its uncached input count.

Custom `ModelAdapter` implementations can override `chat_with_budget` to
apply the supplied token allowance and monotonic deadline to their own
provider requests. Existing `chat` implementations receive a generic
preflight and the same worker-side response checks.

### Resume a question when a watch delivers evidence

A newly accepted ephemeral watch creates a pending question from its rationale.
Run a second worker with `worker --followups-only`, using the normal model and
socket options and a fresh investigator token with the run-spawn grant. The
parent polls for eligible evidence. Control binds each attempt to one question,
one incident and the first usable observation from the exact watch revision.
The model receives the question and bounded evidence and returns its
interpretation and citation. Submission atomically finishes the attempt and
records a finding. Repeating an identical submission reuses the finding.

The original worker can finish or exhaust its budget while the watch is
running. The MCP tool `list_watch_followups` shows pending, ready, leased,
answered, expired, cancelled and exhausted questions for an incident. Three
unsuccessful attempts exhaust a question. Operators choose the model endpoint
and token scope for this worker as they do for the incident worker.

### Periodic host reviews

Use `admin-cli set-host-review-schedule schedule.json` for an enrolled host.

```json
{
  "host_id": "edge",
  "interval_seconds": 3600,
  "route": "supervisory",
  "question": "Which gaps in discovery coverage still need review?",
  "collectors": ["sockets.listening", "packages.inventory"]
}
```

One schedule per host becomes due immediately and repeats at the configured interval.
Material changes to the reported host profile make the schedule due again.
Changes and missed intervals coalesce while a review is outstanding.

Run a worker for the configured purpose with an unbound investigator token
that grants run spawning and covers the host and every scheduled collector.

```bash
python3 -m defsec_reasoner host-review-worker --socket ./control-data/investigate.sock \
  --purpose supervisory --backend openai --base-url http://127.0.0.1:11434/v1 \
  --model local-model --max-total-tokens 4096 --max-wall-seconds 15 --concurrency 1
```

Each worker process applies its own token, time, and concurrency limits to its
purpose. Use `--effort` with an OpenAI-compatible endpoint that accepts
`reasoning_effort`. The model transport defaults to loopback endpoints or the scripted adapter.
An external HTTPS review route requires a separate `DEFSEC_REVIEW_EXPORT_GRANTS`
JSON array. Each entry specifies the exact `endpoint`, `purpose`, `host_id` and
`collectors`. One entry must cover the full scheduled question. The controller
filters before leasing so local-only work remains available to another process. The worker sends the question and scoped samples without
credentials or watch handles. The reactive `worker` can run alongside it.

When scoped evidence is missing or older than the schedule interval, the worker
requests one discovery refresh with a window of up to 30 seconds. Control
persists the window and the question. The worker releases the lease while
waiting. A successor can continue the refresh or assess the pinned evidence
after claiming a new lease, including after a provider failure. The model has
no tools and submits a summary and an advisory interpretation.

Use `admin-cli get-latest-host-review HOST` to read the latest completed review
and `admin-cli cancel-host-review-schedule HOST` to cancel outstanding work
and stop the schedule.
