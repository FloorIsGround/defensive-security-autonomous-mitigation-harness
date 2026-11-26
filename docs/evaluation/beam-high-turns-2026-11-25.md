# Does Beam High benefit from more investigation turns?

Beam High passed five of six cases with a four-turn ceiling and all six with eight. Both arms selected all six correct watches, cited all five delivered samples, and left the withheld sample pending. The one improved verdict came from an eight-turn run that used only three initial turns. This trial shows no increase in evidence coverage attributable to turns five through eight.

Raw attempt traces are retained outside the repository.

| Case | Four-turn verdict | Eight-turn verdict | Initial turns used (four / eight) |
| --- | --- | --- | --- |
| Archive, active | Supports | Supports | 4 / 6 |
| Index, inactive | Supports (incorrect) | Contradicts | 4 / 3 |
| Mail, unknown | Unresolved | Unresolved | 4 / 5 |
| Ledger, withheld | Pending | Pending | 4 / 4 |
| Media, inactive | Contradicts | Contradicts | 3 / 4 |
| Metrics, active | Supports | Supports | 4 / 6 |

All six four-turn runs called `finish` within budget. Three eight-turn runs used turns beyond four. On Archive and Metrics those calls recorded a finding and finished. On Mail the fifth turn only finished. All six eight-turn runs proposed their watches by turn three. The independent verdict came from the single resumed turn in both arms.

Including reassessment, the four-turn arm used 28 requests and 155,509 tokens (132,255 input and 23,254 output). The eight-turn arm used 33 requests and 189,734 tokens (167,387 input and 22,347 output), an increase of 22%. The five additional requests primarily increased input from replaying conversation history. Both arms reported $0. All 12 ledgers verified.

## Method

This paired test uses OpenCode Go's zero-priced `beam-free` route. Each of the six synthetic listener incidents starts with only a TCP port and an operator question. The score requires the correct signed service watch and either a correct verdict citing the exact new observation or an unanswered question when no sample arrives. Each service permits one new watch, so evidence coverage is the number of cases with a relevant watch and an appropriate outcome. [Case definitions and scoring](luna-selection-protocol.md)

Both arms request high reasoning effort. The initial worker gets either four or eight model turns, 96,000 total tokens, 180 seconds, and one watch proposal. The resumed worker gets one turn, 4,096 tokens and 60 seconds. Individual model requests have a 25-second timeout. Each case starts in a fresh controller ledger. Pairs run serially and alternate which cap goes first. Each case gets one attempt per cap, including provider failures. Tool calls after the fourth initial turn indicate what Beam actually used the additional time for.

The earlier four-turn Go pilot omitted the effort field and allowed 24,000 tokens and 75 seconds. Four of its six initial runs stopped at the token limit after three turns. One finished in three, and one timed out after two. None reached turn four. Its 4/6 outcome is historical context. The estimate of the turn effect comes from the two matched high-effort arms. [Earlier free-model evaluation](go-free-selection-2026-11-25.md)

The authenticated Go catalog advertised low, medium, high, xhigh and max for Beam. The earlier Go and OpenRouter pilots left effort to the provider, and the recorded responses did not identify its internal default. High is the first explicitly requested level in this investigator comparison. The current trace records the request field. [Go catalog API](https://opencode.ai/docs/console/api/models)

## Replay

Build `control-d` and configure the Go workspace key. These commands reproduce the paired order with fresh output files. The benchmark defaults Beam to high and records the effort on the outgoing request.

```sh
cargo build -p control-d --offline
export PYTHONPATH=reasoner:reasoner/tests
out=$(mktemp -d)
(
status=0
for pair in archive/4 archive/8 index/8 index/4 mail/4 mail/8 ledger/8 ledger/4 media/4 media/8 metrics/8 metrics/4; do
  case_id=${pair%/*}
  turns=${pair#*/}
  python3 docs/evaluation/run_go_free_selection.py --beam-effort high \
    --initial-turns "$turns" --initial-tokens 96000 --initial-seconds 180 \
    beam-free "$out/$case_id-$turns.jsonl" "$case_id" || status=$?
done
exit "$status"
)
```
