# Beam Free and HungerG Free as investigators

Beam Free selected the correct service watch in five of six port-only investigations and passed four end to end. HungerG Free installed zero watches under the same budget. When a scripted investigator supplied the observation and left only the verdict to the model, each passed two of three. Both had previously passed a guided end-to-end case. [Guided results](opencode-go-availability-2026-11-25.md)

Raw attempt traces are retained outside the repository.

## Test conditions

Each model received the target TCP port and the same investigative question. The worker had to identify the service from socket evidence, request a signed unit-state watch, then assess a fresh observation or keep the question open if no sample arrived. The initial run allowed four turns, one watch proposal, 24,000 tokens and 75 seconds. Reassessment allowed one turn, 4,096 tokens and 60 seconds. Each Go request had a 25-second timeout. Only synthetic evidence went to the gateway. The runner used the production Go adapter and default model effort. [Selection protocol](luna-selection-protocol.md) · [Supplied-sample controls](followup-pilot-protocol.md)

Each case ran once per model with a fresh local control ledger. Independent case groups overlapped in time, so gateway load may have affected availability. Requeued cases counted as failures. All 18 audit chains verified.

## What happened in each investigation

| Case | Hidden outcome | Beam Free | HungerG Free |
| --- | --- | --- | --- |
| Archive | Active | Passed, cited the fresh sample | HTTP 429 before a watch |
| Index | Inactive | Cited the fresh sample but recorded `unresolved` | Token budget stopped the run before a watch |
| Mail | Unknown | Provider timeout before a watch | Token budget stopped the run before a watch |
| Ledger | Sample withheld | Passed, left the question pending | HTTP 429 before a watch |
| Media | Inactive | Passed, cited the fresh sample | Token budget stopped the run before a watch |
| Metrics | Active | Passed, cited the fresh sample | Provider timeout before a watch |

Beam cited the exact observation in all four investigations that received one. Its weakest result was interpreting an inactive service. It got one of the two inactive investigations right. In the separate inactive control, its summary accurately described the service as inactive/dead, but its stored verdict was `supports`. That same disagreement appeared in the earlier Beam pilot via OpenRouter. Beam passed the active and unknown controls. [Earlier follow-up pilot](followup-pilot-2026-11-25.md)

HungerG passed the inactive and unknown controls with exact citations. In the active control it called the assessment tool, but the worker marked the follow-up failed and persisted no finding. The trace records the tool name only, so the cause of that failure is undetermined. Half its port-only investigations stopped on provider errors. In the other half it spent its available budget inspecting context without installing a watch.

## Usage

| Model | Requests attempted | Replies with usage | Reported input tokens | Reported output tokens | Reported cost |
| --- | ---: | ---: | ---: | ---: | ---: |
| Beam Free | 25 | 24 | 86,776 | 20,373 | $0 |
| HungerG Free | 19 | 16 | 68,003 | 7,272 | $0 |

The totals include both investigations and supplied-sample controls. The workspace catalog listed zero input and output prices before each batch. All 40 successful replies reported zero cost and zero Go allowance consumption. The four failed requests returned no usage. HungerG's lower token count reflects fewer completed steps and cannot establish greater efficiency.

Beam is the better lead for open-ended evidence-selection tests on this fixture. Its inactive verdicts deserve an explicit regression check. For HungerG, separately measure successful watch requests under a fixed budget and success at interpreting a supplied sample. Six investigations per model cover one kind of incident and give no estimate of fleet-wide reliability.

## Replay

From the repository root with a configured OpenCode Go workspace key, use a fresh output path for each model. This serial replay uses the same fixtures and limits and avoids overlapping requests between models.

```sh
cargo build -p control-d --offline
out=$(mktemp -d)
export PYTHONPATH=reasoner:reasoner/tests
python3 docs/evaluation/run_go_free_selection.py --beam-effort default beam-free "$out/beam-free.jsonl" archive index mail ledger media metrics active inactive unknown
python3 docs/evaluation/run_go_free_selection.py hungerg-free "$out/hungerg-free.jsonl" archive index mail ledger media metrics active inactive unknown
```
