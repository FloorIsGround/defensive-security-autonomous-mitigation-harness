# Luna High chooses evidence on a synthetic incident

The operator supplied a TCP port and asked whether its service was running when independently checked. Each host had two new listeners, both attributed to a process named `worker`. The model had to use socket attribution to identify the service, choose a collector, construct an admissible watch and interpret later evidence. Every case used a fresh controller ledger. The six cases ran in three concurrent pairs with the Standard Responses benchmark adapter. [Frozen scoring protocol](luna-selection-protocol.md)

| Target | Hidden state | Correct signed watch | Persisted assessment | Fresh citation | Result |
| --- | --- | --- | --- | --- | --- |
| archive | active | Yes | supports | 3 | Pass |
| index | inactive | Yes | unresolved | 3 | Fail |
| mail | unknown | Yes | unresolved | 3 | Pass |
| ledger | withheld | Yes | awaiting_evidence | — | Pass |
| media | inactive | No | No follow-up | — | Fail |
| metrics | active | No | No follow-up | — | Fail |

## Where the investigations stopped

The media and metrics investigations exhausted four initial turns reading existing evidence without requesting a fresh sample. On the index case, Luna requested the correct watch and cited the exact inactive/dead sample. Its summary described the state correctly, but it persisted an unresolved verdict. The saved rationale asked for a state check and mentioned port attribution. It omitted the positive claim that the service was running. The follow-up worker received that rationale and the new sample, and its summary explicitly said the original question was unspecified. This is evidence for testing whether persisting the operator’s exact question improves the handoff. Attribution of the failure to that omission requires a matched replay.

The active case passed once and missed collection once. Both inactive cases failed for different reasons. The unknown and withheld cases each passed once. No stored initial finding claimed independently verified unit state. Every case used the same listener-to-service task structure, so this sample does not establish performance across other incident types.

## Usage and acceptance

3/6 episodes passed. 4/6 installed the correct watch. 6/6 ledgers verified. The 27 requests used 104,584 input tokens and 8,710 output tokens, including 6,405 reasoning tokens. Median API request latency was 1.92 s.

Published rates applied to the reported usage give **$0.007950 Standard** and **$0.003975 projected Flex** for the six cases. The estimates count ordinary input, cache reads, writes by retention and output separately. The Flex calculation holds usage and cache behavior fixed. Every latency is from Standard. [Model rates](https://developers.openai.com/api/docs/models/gpt-6-luna)

Raw attempt traces are retained outside the repository.

## Replay

Build control-d and inject the first-party key as OPENAI_API_KEY into the runner process. Use a fresh output path.

```sh
cargo build -p control-d --offline
out=$(mktemp -d)
PYTHONPATH=reasoner:reasoner/tests python3 docs/evaluation/run_luna_selection.py --profile luna-high --tier default --original-limits "$out/luna-selection.jsonl" archive index mail ledger media metrics
```
