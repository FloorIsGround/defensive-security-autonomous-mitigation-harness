# OpenAI investigator pilot, 25 November 2026

All four Standard configurations passed four investigation episodes and three evidence reassessments on the first-party Responses API. Luna High had the lowest cost for this workload. Sol Low had the shortest median request time. One pass through these synthetic cases provides little evidence about differences in investigation quality.

Raw attempt traces are retained outside the repository.

| Configuration | Episodes | Reassessments | Requests | Median request | Standard estimate | Flex estimate |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| GPT-6 Luna High | 4/4 | 3/3 | 9 | 3.07 s | $0.002583 | $0.001292 |
| GPT-6 Luna Max | 4/4 | 3/3 | 9 | 3.01 s | $0.003919 | $0.001959 |
| GPT-6.2 Sol Low | 4/4 | 3/3 | 10 | 1.97 s | $0.032972 | Unavailable |
| GPT-6.2 Sol Medium | 4/4 | 3/3 | 10 | 2.44 s | $0.036896 | Unavailable |

## What the workers did

Each configuration inferred a likely PostgreSQL host role from a package and a listening socket, citing both observations. On the new-service episode, the investigator requested a scoped watch and later cited the fresh active/running sample in its assessment. With the sample withheld, it left the question pending. The maintenance rule handled the expected listener change locally with zero model calls. In three isolated follow-ups, each configuration recorded the expected supports, contradicts and unresolved labels with the exact fresh observation ID. All 28 Responses episode and follow-up ledgers passed audit verification.

The operator prompt supplied the unit name, question and watch specification. These results cover requesting, waiting for and interpreting evidence under that guidance. They leave autonomous choice of which evidence to collect unmeasured. Each profile ran its cases serially, while the four profiles ran concurrently. Cache reuse, request mix and provider load can influence the observed latencies. Luna Max took 12.33 s on quiet discovery against a 15 s request deadline. Luna High took 4.94 s on that case.

## Usage and pricing

| Configuration | Input | Cache reads | Cache writes (30 min) | Output | Reasoning | Four episodes | Three reassessments |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Luna High | 16,083 | 6,602 | 7,883 | 2,744 | 1,703 | $0.002352 | $0.000231 |
| Luna Max | 17,059 | 6,608 | 8,860 | 5,172 | 4,079 | $0.003527 | $0.000391 |
| Sol Low | 19,105 | 10,201 | 7,307 | 1,049 | 0 | $0.029598 | $0.003374 |
| Sol Medium | 19,359 | 10,289 | 7,474 | 1,399 | 171 | $0.032942 | $0.003954 |

Input includes reads and writes. Output includes reasoning. The estimates multiply ordinary input, cache reads, cache writes and output by their respective short-context prices per million tokens. In that order, the Standard rates were $0.10, $0.01, $0.125 and $0.50 for Luna, and $2.00, $0.10, $2.50 and $10.00 for Sol. Each completed request reported the default service tier. The Luna Flex projection holds token counts and cache behavior fixed at half the Standard rates. OpenAI excludes GPT-6.2 Sol from Flex. All latency values come from Standard. [Pricing](https://developers.openai.com/api/docs/pricing) · [Prompt cache accounting](https://developers.openai.com/api/docs/guides/prompt-caching) · [Flex availability](https://developers.openai.com/api/docs/guides/flex-processing)

The 38 matched requests account for an estimated $0.076369. A preceding Chat Completions compatibility run made 24 requests. Three discovery requests completed ($0.007206 combined), and 21 returned HTTP 400 without usage. One separate Luna Max Responses compatibility probe used 39 input and 56 output tokens, including 47 reasoning tokens ($0.000032). The combined Standard estimate across all reported usage is **$0.083607**. Invoice reconciliation and Flex latency were outside this pilot.

## Endpoint compatibility and replay

Chat Completions rejected Luna Max. At the other three settings it accepted tool-free discovery and rejected investigator requests that combined tools and reasoning effort. The comparison therefore used Responses for every profile. The evaluation runner translates the existing worker's messages and function calls to Responses items, replays tool results and encrypted reasoning within an episode, and requests the exact effort with Standard processing. The deployed worker still uses its existing Chat Completions adapter. Native Responses support is the integration work required to run these configurations in production.

Each run used a disposable control daemon and synthetic agent on the local machine. The runner used the existing fixture budgets, one attempt per case, and the scoring criteria in the [Phase 18 protocol](phase18-protocol.md) and [follow-up protocol](followup-pilot-protocol.md). Model IDs and efforts returned by Responses matched all 38 requests.

With the first-party key injected as OPENAI_API_KEY, use a fresh output path for each run.

```sh
cargo build -p control-d --offline
out=$(mktemp -d)
(
status=0
for profile in luna-high luna-max sol-low sol-medium; do
  PYTHONPATH=reasoner:reasoner/tests python3 docs/evaluation/run_openai_investigator.py \
    --tier default "$profile" "$out/investigator-$profile.jsonl" || status=$?
done
exit "$status"
)
```
