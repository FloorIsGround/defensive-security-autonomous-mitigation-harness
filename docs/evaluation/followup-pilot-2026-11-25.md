# Phase 14/18 follow-up model economics pilot · 25 November 2026

The production follow-up worker resumed a persisted question in a fresh disposable control-d ledger for each case. A scripted origin opened the question and requested unit state. Only fabricated service evidence went to the providers. The score used the persisted decision and citation to the fresh observation. [Frozen protocol](followup-pilot-protocol.md) · [Fixtures](followup-cases-v1.json)

## Replay

From the repository root, build `control-d` and run with existing credentials loaded in the environment. The scored comparison uses `OPENROUTER_API_KEY` and writes a new JSONL file.

```sh
cargo build -p control-d
out=$(mktemp -d)
PYTHONPATH=reasoner:reasoner/tests python3 docs/evaluation/run_followup_pilot.py --beam-effort default --openrouter --output "$out/followup-openrouter.jsonl"
```

All scored attempts used the OpenRouter route. Raw attempt traces are retained outside the repository.

## Results

All nine OpenRouter requests completed and returned the requested model ID, a usable tool call and provider usage. All nine findings cited the fresh observation, and **eight of nine** passed both gates, including **five of six** verified determinate conclusions and **three of three** correct unresolved decisions. There were no retries or interventions during the follow-up runs. All nine scored disposable ledgers passed audit verification. The two scripted follow-up restart tests also passed.

| OpenRouter model ID | Upstream providers | Decision | Citation | Verified determinate | Honest unresolved |
|---|---|---:|---:|---:|---:|
| `reflection/beam-1.0-501b-a23b` | Nebius, Together | 2/3 | 3/3 | 1/2 | 1/1 |
| `z-ai/glm-5.3` | CoreWeave, Wafer | 3/3 | 3/3 | 2/2 | 1/1 |
| `z-ai/glm-5.3-flash` | BaseTen, CoreWeave, River | 3/3 | 3/3 | 2/2 | 1/1 |

Beam's inactive sample correctly described the service as inactive in the summary and persisted `supports` as its interpretation. The frozen rubric scored that decision as a failure. The question's yes/no wording leaves the positive hypothesis implicit, which may contribute to label ambiguity.

| Model | Uncached input | Cached input | Output (reasoning subset) | HTTP latency in fixture order (ms) | Reported total USD | USD per verified conclusion |
|---|---:|---:|---:|---|---:|---:|
| Beam | 749 | 208 | 984 (757) | 1,435 / 1,429 / 839 | $0.00125749 | $0.00125749 |
| GLM-5.3 | 1,210 | 0 | 3,442 (2,818) | 10,249 / 12,596 / 3,437 | $0.00867666 | $0.00433833 |
| GLM-5.3-Flash | 1,210 | 0 | 3,664 (3,034) | 5,690 / 9,460 / 1,657 | $0.00160641 | $0.00080321 |

Costs sum OpenRouter's on-wire `usage.cost` over all three attempts per model, including failed decisions and unresolved cases. Each response's input plus output matched its total, cached reads fit within input, reasoning fit within output, and cache writes were zero. No credits were purchased. [OpenRouter usage accounting](https://openrouter.ai/support/)

Three samples per model cannot establish an operational quality ranking. Default reasoning, varying upstreams and cache state affect these observations. The pilot measures a resumed turn after scripted admission, with unknown state represented by a delivered sample. Quiet onboarding, maintenance suppression, absent-sample expiry, first-party Beam economics, and end-to-end cost from initial investigation through verification remain open.
