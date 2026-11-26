# Phase 18 synthetic episode pilot

The [frozen protocol](phase18-protocol.md) defines four episodes and their pass
criteria. The [runner](run_phase18.py) provisions a disposable local control
ledger and synthetic Unix-socket agent per attempt. Raw outcomes, findings,
observation references, audit checks and request measurements are retained
outside the repository.

## Results

All 20 planned attempts executed, with zero harness failures and 20 valid audit
chains. All five lanes had zero quiet or maintenance triggers, one maintenance
rule hit, and one trigger for each of the two unexpected socket changes. The
episode score also requires the applicable evidence outcome.

| Lane | Quiet | Maintenance | New service | Missing evidence | Passed | Failed | Verified claims | Actual operator interventions | No durable question after trigger |
| --- | --- | --- | --- | --- | --- | ---: | ---: | ---: | ---: | ---: |
| Static | Fail | Pass | Fail | Fail | 1/4 | 3 | 0 | 1 | 2 |
| P12 reactive proxy, scripted | Fail | Pass | Fail | Pass | 2/4 | 2 | 0 | 1 | 0 |
| Adaptive, scripted | Pass | Pass | Pass | Pass | 4/4 | 0 | 2 | 1 | 0 |
| P12 reactive proxy, live GLM Flash | Fail | Pass | Fail | Fail | 1/4 | 3 | 0 | 1 | 1 |
| Adaptive, live GLM Flash | Pass | Pass | Fail | Pass | 3/4 | 1 | 1 | 1 | 0 |

The only actual operator intervention in each lane was activating the existing
maintenance permission before the episode. The final column counts cases that
would need a manual intervention to open the missing evidence question. A
reactive episode with a `ready` question still needs someone to assess it.

- **Monitoring and coverage.** Static detected both changes and opened no watch.
  Both reactive lanes received the new-service sample at observation 3 and left
  its question `ready`. Only the adaptive lanes interpreted the quiet host.
  Both cited observations 2 and 3 for the likely PostgreSQL purpose.
- **Present evidence.** Both adaptive lanes completed the new-service follow-up
  and cited fresh observation 3. The scripted assessor classified the
  active/running sample as `supports`. GLM Flash accurately restated those fields
  but marked the question `unresolved`, requiring independent integrity
  verification and unit-file hashes. The frozen question concerns the observed
  state, so this fails the score. The live initial run also cited observations 1
  and 2 for the socket-set change, outside the scored claim targets.
- **Absent evidence.** Adaptive GLM Flash queued its watch and kept the missing
  sample's question `awaiting_evidence` without a second model stage. The
  reactive GLM Flash response reached the provider's length limit with no
  accepted watch. The planned withholding and the failure to open a question
  are separate conditions.
- **Provider and export.** Both live lanes executed through the configured
  OpenRouter endpoint using `z-ai/glm-5.3-flash`. Quiet adaptive discovery
  exported under the synthetic host grant and persisted its interpretation.
  All ten requests returned usage and cost, with zero HTTP failures. The first
  reactive new-service response contained incomplete tool arguments, and that
  investigation hit the three-turn limit after accepting its watch. The reactive
  missing-evidence response ended with `length`.

| Live lane | Requests | Input tokens | Output tokens | Sum of request time | OpenRouter cost |
| --- | ---: | ---: | ---: | ---: | ---: |
| Reactive proxy | 4 | 15,872 | 9,328 | 67.219 s | $0.005920596 |
| Adaptive | 6 | 17,554 | 14,680 | 101.824 s | $0.007427517 |

Total reported spend was $0.013348113. Across all attempts, observed spend per
scored verified claim was $0.007427517 for live adaptive and undefined for live
reactive. Requests took 3.014–33.634 seconds. Some exceeded the configured
25-second socket timeout in elapsed time, including discovery with its shorter
budget. The timeout does not bound the entire HTTP exchange.

## Reproduce

```sh
cargo build --locked -p control-d
out=$(mktemp -d)
PYTHONPATH=reasoner:reasoner/tests python3 docs/evaluation/run_phase18.py \
  --output "$out/phase18-repeat.jsonl"
```

The runner writes every row before returning nonzero if a scored case fails.
The static and reactive baselines include expected failures. Add `--live` with an existing
`OPENROUTER_API_KEY` to run the two GLM Flash lanes. Only the synthetic fixture
and its local control context are sent. Each live lane receives the same operator
objective and watch template. The initial model emits the proposal, control-d
decides it, the fixture agent conditionally delivers evidence, and the adaptive
follow-up model interprets it. Scripted lanes use canned initial tool calls and
a deterministic follow-up assessor. Audit validation checks the local event
chain. Episode timing includes disposable harness startup and polling overhead.

## Qualification limits

The reactive proxy uses the current trigger worker and ledger, so it inherits
durable-question persistence even with reassessment disabled. It isolates the
discovery and follow-up boundaries and does not measure the historical Codex CLI
path. Quiet host scheduling and the collection fixtures are scripted for all
lanes. The watch template and operator objective make this a tool-use and
episode-continuity pilot. The experiment supplies one host per episode, one
example per case and one live model route with provider-selected backends.
It does not establish fleet behavior, generalization to novel objectives,
release readiness, or remediation efficacy. The missing-sample endpoint is an
unanswered question at the episode cutoff. Expiration and delayed recovery
require separate measurements.
