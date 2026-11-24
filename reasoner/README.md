# DefSecAutMit Reasoning Plane (`reasoner/`)

Phase 5 of the DefSecAutMit adaptive defensive monitoring harness: the
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
│   ├── rpc_client.py               # ControlRpcClient: 13 typed Investigation ops, token-safe
│   ├── admin_client.py             # operator-side Admin RPC (enroll/baseline/mint/audit-verify)
│   ├── provenance.py               # §7.5: <untrusted_telemetry> envelopes + system prompt
│   ├── models.py                   # ModelAdapter ABC + OpenAI / Anthropic / ScriptedMock adapters
│   ├── worker.py                   # ReasonerWorker: lease → bounded tool loop → complete/fail
│   ├── control_harness.py          # real control-d subprocess + synthetic agent-d wire client
│   ├── benchmark.py                # §9 adaptive-vs-static scenarios, JSON + Markdown reports
│   └── cli.py / __main__.py        # `worker` and `benchmark` entrypoints
└── tests/                          # 90 unittest cases incl. LIVE control-d integration + benchmark
```

## Safety model (what the worker can never do)

* The worker's only action surface is the **typed Investigation RPC** on
  `investigate.sock`. No shell, no filesystem, no direct database access, no
  remediation verbs exist anywhere in the package.
* All monitored host data (observations, journal lines, socket fields,
  baselines, trigger outcomes) is wrapped in explicit
  `<untrusted_telemetry source="…" host_id="…" observation_id="…" state_hash="…">`
  envelopes with strict byte clipping; injected `</untrusted_telemetry>`
  close tags are neutralized. The trusted system prompt instructs the model
  to treat envelope content as data, cite exact `observation_id`s, and
  distinguish observed fact vs. hypothesis vs. verified finding.
* Even a fully hijacked model hits the **central deterministic policy gate**
  in `control-d`: baseline watches are untouchable, sensitive paths
  (`/etc/shadow`, host keys) are denied, sub-floor polling intervals are
  rejected, and every decision is durably audited.
* Runs are bounded by `RunBudgets` (default: 6 turns, 45 s wall, 16 000
  tokens, $0.25, 3 proposals, 32 KiB context, 120 s lease). Provider failure
  requeues with bounded backoff (5 attempts → dead-letter); expired leases
  are fenced so stale workers can never commit results.

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
* `test_live_integration.py` — **LIVE** against compiled `control-d`:
  lease → run → propose ephemeral watch → evidence-bound finding → complete →
  audit-chain verification; expired-lease fencing + requeue; observer-role
  denial. Skipped automatically if no binary is built.
* `test_benchmark.py` — runs the full 4-scenario suite end-to-end and asserts
  adaptive coverage > static and 100% adversarial rejection.
