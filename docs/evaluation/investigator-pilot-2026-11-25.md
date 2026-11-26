# Investigator pilot · 25 November 2026

Two experiments used the P12 product at `f6a611c` and the fleet fixtures at `d975774`. The Proxmox run tested collection and wake decisions on disposable guests. The Beam run sent synthetic observations from a separate local control daemon to Reflection's first-party API. These answer different questions. A correctly suppressed maintenance wake saves a whole model run. An investigation that starts must still earn its token spend by collecting and using relevant evidence.

Raw attempt traces are retained outside the repository.

## Beam on the two-stage service change

In each fresh lab, the agent observed the initial socket inventory and then a new listener. Both arms could query observations and record findings. The fixed-monitoring arm could only inspect the existing evidence. The adaptive arm could also propose one bounded watch. The fixture supplied unit state if the watch for the relevant service was admitted. A new sample in the ledger, a finding citing that sample and a correct diagnosis are three distinct outcomes.

We ran two pairs with `Beam-1.0-501B-A23B`, first fixed then adaptive, then adaptive then fixed. Each started a fresh control daemon. Both used six turns, a 110-second worker budget, a 48,000-token run budget checked between calls, and a requested 4,096-token completion limit per call. The earlier P13 comparison used another product revision and is historical context only. The sample has one fixture and two trials per arm. Ordering did not isolate provider cache state.

| Trial | Monitoring | Input (cached subset) | Output (reasoning subset) | Total tokens | Requests | New unit samples | Result |
|---|---|---:|---:|---:|---:|---:|---|
| 1 | Fixed | 17,829 (5,056) | 2,514 (2,087) | 20,343 | 4 | 0 | Finished |
| 1 | Adaptive | 34,886 (14,016) | 5,893 (4,479) | 40,779 | 6 | 0 | Turn limit |
| 2 | Adaptive | 20,692 (4,224) | 3,737 (3,027) | 24,429 | 4 | 1 | Finished |
| 2 | Fixed | 17,145 (8,576) | 2,888 (2,307) | 20,033 | 4 | 0 | Finished |

Across the two pairs, adaptive monitoring used 65,208 tokens versus 40,376 with fixed monitoring. The extra 24,832 tokens yielded one additional sample. The fixed runs recorded findings on existing evidence. In the first adaptive run the worker reached its turn limit with two findings and zero accepted watches. In the second it collected observation 3, a unit-state sample, at 30.252 seconds. Its finding cited observations 1 and 2, the original socket snapshots. A follow-up citation check therefore scores zero successes across the two adaptive trials. This fixture establishes sample availability and citation use. It does not grade the correctness of the original listener finding.

## What a run costs

Reflection describes the first-party public beta as free with limits. A deployment still consumes requests, daily tokens, uncached input and output allowances. Reasoning is part of reported output and cache hits are part of reported input. Adding either subset to its parent would double count. For a given workload mix, divide each available allowance by the corresponding measured consumption per run. The smallest quotient bounds capacity, with minute limits, concurrency, shared traffic and retries reducing practical throughput. [Beta terms](https://reflection.ai/legal/beta-pricing-information) · [Rate-limit accounting](https://developers.reflection.ai/rate-limits)

The two adaptive traces consumed 16,468 and 20,870 uncached input tokens respectively when ordered by total consumption. At 100 investigations per day of those respective sizes, plan for 1.65–2.09 million uncached input tokens plus 374,000–589,000 output tokens. This is a workload scenario. Quiet hosts running deterministic watches incur model usage only when a worker is invoked.

For a paid-route sensitivity check, hold the two adaptive Beam traces fixed and price all input as uncached. At OpenCode's listed GLM-5.3 rates of $1.40 per million input and $4.40 per million output, the traces price at **$0.0454–$0.0748 per investigation**. At GLM-5.3-Flash rates of $0.15 and $0.50, they price at **$0.0050–$0.0082**. These are list-price equivalents. Actual GLM tokenization, tool choices, cache hits, findings and Go allowance usage require a matched run. Go subscriptions have shared usage windows and may use workspace credits when extra usage is enabled. Prices checked 25 November 2026. [Model price catalog](https://opencode.ai/inference/go/v1/models) · [Go allowances](https://opencode.ai/docs/console/go/)

For the next comparison, use identical held-out cases across Beam, GLM-5.3 and Flash. Score factual accuracy and citations before examining spend. Include quiet onboarding, a permitted maintenance change and an incomplete observation. Report total spend across all attempts divided by independently verified conclusions, along with unresolved cases and operator interventions. Where no run reaches the evidence target, report zero successes and the tokens consumed. Preserve the current tool loop as a comparison arm and test resuming when fresh evidence arrives. The existing worker already compacts tool history, so measure repeated input and cache hits before changing that behavior.

## Proxmox monitoring states

The current release build ran on three disposable Ubuntu 24.04.5 guests on a lab hypervisor. Each had two vCPUs and 1 GiB of memory. The fleet harness assigned server, bastion and desktop profiles, installed 12 watches and authenticated agents over mTLS. This exercise used known roles on one distribution. It establishes a monitoring baseline for a future blind-onboarding trial.

| Check | Direct observation |
|---|---|
| Enrollment and collection | All three agents ran as an unprivileged service with zero effective Linux capabilities. All expected non-journal watches produced initial usable observations. |
| Maintenance | Installing the desktop fixture package produced a matching observation after 14.133 seconds. After removal and creation of a package-scoped rule, reinstalling it increased the rule hit count from zero to one and produced zero repeat wake decisions for that watch. |
| Offline and reconnected | Stopping the desktop agent opened a liveness incident 41.164 seconds after its last heartbeat. Its status returned to online after restart. |
| Resource use and audit | Agent cgroup peaks ranged from 3.13 to 8.13 MiB across the sampled service lifetimes. The control audit chain verified. |
| Teardown | The harness exited successfully and compared before/after inventory. All six previously tracked guests remained running. A subsequent check confirmed the disposable VMID range was free and found no matching VM disks or cloud-init snippets on the test storage. |

For the next fleet comparison, vary the actual service workload and collector visibility independently of role labels. A host with unavailable package evidence should produce an explicit gap. Count a maintenance wake avoided, a correctly recognized loss of visibility, and a newly corroborated finding separately when estimating operator workload and model demand.
