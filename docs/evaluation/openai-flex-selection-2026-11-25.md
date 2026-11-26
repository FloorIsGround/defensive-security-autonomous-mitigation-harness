# OpenAI Flex investigator comparison

GPT-6 Luna Max and GPT-6.1 Terra Medium and High ran the same six synthetic service-state investigations as Luna High and Beam High. Each investigator sees a TCP port and must identify the service, request the correct signed watch, and persist a verdict citing the fresh observation. The Ledger case withholds the sample and requires the question to stay open. A pass requires a verified controller audit. [Scoring protocol](luna-selection-protocol.md) · [Original Luna results](luna-selection-2026-11-25.md) · [Beam turn comparison](beam-high-turns-2026-11-25.md)

Raw attempt traces are retained outside the repository.

## Results

| Configuration | Passes | HTTP requests | Total tokens | Tokens/pass | Estimated USD | USD/pass | Median successful turn |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Luna High · Standard, 4 turns | 3/6 | 27 | 113,294 | 37,765 | $0.007950 | $0.002650 | 1.92 s |
| Beam High · Go, 4 turns | 5/6 | 28 | 155,509 | 31,102 | $0.000000 | $0.000000 | 5.76 s |
| Beam High · Go, 8 turns | 6/6 | 33 | 189,734 | 31,622 | $0.000000 | $0.000000 | 4.48 s |
| Luna Max · Flex, 4 turns | 5/6 | 43 | 183,843 | 36,769 | $0.012902 | $0.002580 | 32.08 s |
| Terra Medium · Flex, 4 turns | 4/6 | 60 | 93,896 | 23,474 | $0.016613 | $0.004153 | 13.97 s |
| Terra High · Flex, 4 turns | 3/6 | 51 | 113,705 | 37,902 | $0.031448 | $0.010483 | 12.59 s |

The main table uses one scored attempt per case, including failures, consistent with the historical table. For a case with a capacity replay, the replay is its scored attempt. Tokens and cost per pass divide the six scored attempts’ usage by the number of passes. The availability table includes the first batch and its scored replays. Median successful turn time includes waiting for Flex retries within the turn. HTTP counts include rejected calls. The older Luna High pilot allowed 24,000 initial tokens and Beam allowed 96,000. The older cohorts had shorter deadlines and different scheduling.

### Cases

| Configuration | Archive (active) | Index (inactive) | Mail (unknown) | Ledger (withheld) | Media (inactive) | Metrics (active) |
| --- | --- | --- | --- | --- | --- | --- |
| Luna High · Standard, 4 turns | Pass | unresolved | Pass | Pass | No correct watch | No correct watch |
| Beam High · Go, 4 turns | Pass | supports | Pass | Pass | Pass | Pass |
| Beam High · Go, 8 turns | Pass | Pass | Pass | Pass | Pass | Pass |
| Luna Max · Flex, 4 turns | Pass | Pass | Pass | Pass | supports | Pass |
| Terra Medium · Flex, 4 turns | Flex capacity | Pass | Pass | Pass | unresolved | Pass |
| Terra High · Flex, 4 turns | unresolved | unresolved | Pass | Pass | supports | Pass |

### Flex usage and availability

| Profile | First-batch passes | Replayed cases | Completed replies | Capacity rejections | Other request errors | First-batch USD | Replay USD | Initial + replay USD | Initial + replay tokens/pass | Initial + replay USD/pass |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Luna Max | 0/6 | 6 | 32 | 20 | 0 | $0.000921 | $0.012902 | $0.013823 | 39,186 | $0.002765 |
| Terra Medium | 0/6 | 6 | 25 | 42 | 0 | $0.002483 | $0.016613 | $0.019097 | 24,296 | $0.004774 |
| Terra High | 2/6 | 5 | 35 | 27 | 0 | $0.018649 | $0.023950 | $0.042600 | 42,975 | $0.014200 |

An additional, unscored Terra Medium Archive diagnostic returned **Pass**. It used 17,426 tokens across 5 successful replies and 3 capacity rejections for an estimated $0.003438. All Flex attempts including the diagnostic cost an estimated **$0.078957**.

Luna Max had the lowest estimated cost per pass among the three new OpenAI configurations. It installed the correct watch in all six investigations and passed five. On Media it cited the fresh inactive/dead sample and described it accurately, but stored `supports` for the question of whether the unit was running. Beam High passed that case in both earlier arms.

Terra Medium spent the fewest tokens per pass. Its Archive score includes a capacity rejection with zero model replies, which lowers its observed token use. On Media it cited the right observation and stored `unresolved`. Terra High selected all six correct watches, but marked both active Archive and inactive Index unresolved and chose `supports` on inactive Media. Raising Terra's effort produced fewer passes on this sample.

None of the 18 scored workers stopped on the total-token cap. Eleven initial investigations reached their four-turn limit. A run could still pass after reaching that limit if it had already requested a watch and its resumed worker answered correctly. With one scored attempt per profile per case, differences across models or efforts are descriptive.

## Conditions and costing

The three new profiles used four initial turns, 192,000 total initial tokens, 8,192 output tokens per call, one watch, and one follow-up turn with a 16,384-token budget. Each HTTP call had up to 180 seconds within the initial 480-second or follow-up 240-second deadline. All three used the first-party Responses API with explicit Flex service and the requested effort. The API field for this tier is `service_tier="flex"`. Each case used a fresh synthetic ledger. The three profiles ran concurrently. Recovery began as interrupted cases finished, overlapping the tail of the first batch. Later Luna cases reused slots freed by Terra.

The first batch exposed repeated Flex capacity rejections. We replayed cases with an explicit `429 flex_unavailable` in a fresh ledger, with the same model, synthetic evidence and scoring. Within each replay, a rejected call could retry its original payload on Flex up to six times with delays of 2, 4, 8, 16, 16 and 16 seconds, subject to the original request deadline. Other errors and incorrect model decisions did not trigger recovery. The trace preserves the initial attempt as well as its replay. Both are included when computing total resource use. [Flex processing guide](https://developers.openai.com/api/docs/guides/flex-processing)

Estimated costs use reported usage and the short-context Flex rates per million tokens. For Luna, ordinary input, cache reads, 30-minute writes, 12-hour writes and output cost $0.05, $0.005, $0.0625, $0.125 and $0.25, respectively. Terra rates in the same order are $0.50, $0.025, $0.625, $1.25 and $2.50. Input categories are mutually exclusive. Reasoning is already included in output. OpenAI states that Flex capacity rejections carry no charge. They returned no token usage in this trial. Values are estimates from API responses. [OpenAI API pricing](https://developers.openai.com/api/docs/pricing)

## Replay

Build `control-d` and inject `OPENAI_API_KEY` into the benchmark process. The current runner defaults to Flex, the larger budgets, and bounded retries on explicit capacity rejections. Use a fresh path for each profile.

```sh
cargo build -p control-d --offline
out=$(mktemp -d)
export PYTHONPATH=reasoner:reasoner/tests
(
status=0
for profile in luna-max terra-medium terra-high; do
  python3 docs/evaluation/run_luna_selection.py --profile "$profile" \
    "$out/flex-$profile.jsonl" archive index mail ledger media metrics || status=$?
done
exit "$status"
)
```
