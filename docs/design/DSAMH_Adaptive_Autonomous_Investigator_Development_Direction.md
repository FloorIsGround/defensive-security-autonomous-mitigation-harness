# Defensive Security Autonomous Mitigation Harness (DSAMH)
## Product direction: autonomous investigation, baseline intelligence, and adaptive defense

**Status:** Proposed development steering charter for the next major implementation phase  
**Audience:** Project leads, implementation agents, reviewers, and operators  
**Relationship to existing design:** Extends the v0.2 architecture and the Phase 9–13 work; does not replace the established protocol, policy, or trust model.

---

## 1. Intent and course correction

DSAMH should become an autonomous defensive security analyst backed by deterministic monitoring and enforcement infrastructure, not merely a deterministic monitoring system with an AI-assisted alert handler.

The current implementation has made substantial progress in the areas of signed monitoring policies, scoped investigation credentials, baseline comparison, incident management, bounded follow-up watches, expectation rules, auditing, and controlled mitigation. These are valuable foundations and should be preserved. However, development has increasingly emphasized constraining the investigator over expanding its ability to understand and protect a host. The next phase should correct that imbalance.

The investigator should be capable of discovering an unfamiliar host, establishing a useful understanding of its operational purpose, designing its own monitoring strategy, building and maintaining baselines, initiating investigations proactively, and adapting its monitoring as new information becomes available. When an investigation establishes that intervention is warranted, the system should support authorized mitigation and verification of its outcome.

The project should not assume that model inference must be minimized at all costs. The operator is willing to use capable, potentially expensive models for substantial investigations, onboarding, and periodic assessments. The primary optimization objective is **defensive effectiveness, evidence quality, and reduced operator workload**, with latency, resource consumption, and inference expenditure measured and controlled rather than treated as overriding goals.

### Core product principles

- The model decides what questions to ask, what evidence is needed, and how monitoring should evolve. Deterministic components enforce the limits of that authority and perform the actual collection and execution.
- Autonomous investigation, autonomous monitoring administration, trusted baseline changes, and host mutation are distinct authorities. A restriction on one must not automatically restrict the others.
- Human approval should be required for genuinely consequential or out-of-policy decisions, not for every routine investigative step.
- The absence of an alert is not evidence that a host is secure. Discovery and monitoring-coverage assessment are core functions.
- A successful deployment should not require an administrator to enumerate every security-relevant service, path, rule, and watch before the model becomes useful.
- Security controls must be justified against concrete failure modes. Reviewers should propose ways to preserve useful capabilities under enforceable constraints, rather than reflexively removing them.

## 2. Target operating model

A deployment should support the following lifecycle:

1. **Enroll:** The operator establishes host identity, authorization, collection scope, resource limits, and the applicable trust and action policies. Minimal bootstrap monitoring begins immediately.
2. **Discover:** The investigator examines the host through the available investigation interface. It builds a working understanding of services, packages, processes, network behavior, configuration dependencies, and known visibility limitations.
3. **Learn:** The investigator establishes evidence-backed candidate baselines and identifies behavior that remains unexplained. It designs and installs monitoring appropriate to the host's apparent role.
4. **Monitor:** Deterministic agents continuously collect and compare observations against the applicable baselines and expectations. The investigator wakes on events and independently scheduled assessments.
5. **Investigate:** The model forms hypotheses, requests immediate observations, creates follow-up watches, correlates evidence, and revises its conclusions as needed.
6. **Respond:** The investigator selects a proportionate response, proposes or executes authorized mitigations through the existing action gate, and collects evidence of the outcome.
7. **Improve:** Findings, resolved hypotheses, coverage gaps, and relevant operational knowledge are retained. The model revises its monitoring strategy without losing previous evidence or silently accepting suspicious drift.

The deterministic monitoring plane remains active during model outages, rate limits, restarts, and investigation delays. The model is an adaptive intelligence layer, not a dependency for every sample or alert.

## 3. Autonomous host discovery and understanding

Introduce a first-class discovery run that does not depend on an existing incident. An enrollment event, explicit operator request, scheduled assessment, or significant host-profile change should be able to initiate it.

Within the host's authorized data scope, the investigator should be able to examine:

| Domain | Examples of useful evidence |
| --- | --- |
| Host identity and role | OS and version, installed software, active services, administrative role hints |
| Process and service inventory | Process metadata, service identities, execution paths, startup configuration, dependency relationships |
| Network posture | Listening endpoints, observed outbound connections, interfaces, routes, relevant service-to-network relationships |
| Software and configuration | Package inventory and provenance, relevant configuration metadata and selectively authorized content, changes over time |
| Operational behavior | Maintenance events, normal restarts, scheduled workloads, resource patterns and recurring changes |
| Monitoring coverage | Active watches, collection capabilities, denied or unavailable sources, stale observations, unsupported capabilities |

Prioritize the ability to answer security-relevant questions over collecting every possible field. Provide bounded queries, sampling and filtering, pagination, and explicit attribution/coverage information. Where permissions prevent an observation, return an honest limitation rather than an empty result that implies absence.

The investigator should infer a proposed role and dependencies, cite observations, state uncertainty, and revise the profile when evidence changes. Human-provided service inventories and infrastructure records should be usable as additional evidence, not mandatory prerequisites to discovery.

Do not treat telemetry, logs, configuration text, or a host's self-reported profile as trusted instructions. Preserve the distinction between host observations and independently authenticated operator intent.

## 4. Autonomous baseline intelligence

Manual baseline promotion should remain available, but it must not be the only viable path to meaningful host monitoring. Introduce policy-delegated baseline administration so the investigator can establish and maintain baselines on its own where the operator has granted that authority.

Extend the existing baseline lifecycle rather than discarding its current integrity guarantees. A proposed baseline should retain observation references, creation time, scope, rationale, corroborating evidence, confidence and provenance, unresolved exceptions, and promotion history. Confidence should be an evidence assessment, not a model-generated number that independently confers trust.

Separate three questions:

- **What is observed?** A factual record of the host's reported state.
- **What is expected?** A working model of normal behavior that can guide monitoring, with uncertainty explicitly preserved.
- **What is trusted?** A versioned security expectation established under the applicable promotion policy.

A newly enrolled or unfamiliar host can be monitored against provisional expectations immediately. Provisional observations must not automatically become allowlists, suppress alerts, or authorize mitigation. The investigator should identify unexplained behavior and pursue corroboration rather than simply marking every initially observed item as benign.

Under an opt-in policy, permit automatic promotion of eligible, sufficiently corroborated low-risk baseline candidates. Define eligibility using independently checkable conditions where practical: authenticated inventory or configuration intent, package provenance, repeated observations over a suitable period, maintenance evidence, and absence of unresolved relevant findings. Repeated observation alone is not proof of legitimacy. Security-critical expectations, broad suppression, changes related to active incidents, and ambiguous high-impact changes should remain subject to stronger validation or separate approval.

Preserve prior versions and make promotions, denials, overrides, and rollbacks auditable. The investigator should be able to identify inconsistencies between current state and prior baselines even after a new baseline is adopted.

## 5. Monitoring strategy as a model-managed capability

A model should be able to manage a host's monitoring strategy as an ongoing responsibility, not only create temporary watches while investigating existing alerts.

Within delegated policy, it should be able to autonomously create, update, renew, retire, test, and inspect monitoring specifications. This includes persistent role-specific watches and ephemeral investigative watches. Model-created monitoring should not require per-watch human approval when the requested collector, scope, frequency, retention, and resource use are permitted.

Store intent and lifecycle metadata for each watch: why it exists, which host/profile/hypothesis it relates to, expected signal, evidence references, priority, duration or review deadline, and outcome. Persist the actual enforcement decision separately from the model's reasoning.

Implement a distinction between **additive monitoring** and **monitoring reduction**. The latter includes disabling protected watches, broadening suppression rules, reducing sensitivity, or retiring controls that establish minimum coverage. These changes need stronger policy conditions than adding a bounded observation. An investigator must never be able to remove the controls that constrain its own authority.

The model should periodically evaluate whether its monitoring is useful. It should be able to detect redundant or noisy watches, stale baselines, missing coverage, and monitoring blind spots, then propose or implement improvements within its delegated authority.

## 6. Make the investigation interface a real investigative environment

Expand the shared Investigation RPC and MCP adapter in parallel so API reasoners, Codex/operator sessions, and future model providers have access to the same authoritative capabilities. Do not build a privileged second path just because a model has access to a coding agent frontend.

The following are **capability categories**, not prescribed final RPC names. Implementation agents should inspect existing contracts and reuse compatible operations rather than duplicating them.

| Capability | Target behavior |
| --- | --- |
| Discover and inspect | Enumerate available collectors, host capabilities, current state, and observation limitations; request scoped one-shot observations |
| Query and correlate | Filter historical evidence, compare snapshots, inspect related incidents, reconstruct event timelines, and request authorized cross-host context |
| Manage monitoring | Create and manage eligible persistent and temporary watches, evaluate predicates, inspect lifecycle and coverage |
| Manage baselines | Create candidates, attach evidence, compare versions, evaluate promotion eligibility, and promote when policy permits |
| Manage expectations | Propose or apply narrowly scoped expectation rules under delegated policy; backtest and explain suppression effects |
| Maintain knowledge | Record and revise host understanding, hypotheses, dependencies, evidence relationships, and unresolved questions |
| Manage investigations | Start authorized non-incident runs, suspend/resume investigations, schedule follow-ups, and record outcomes |
| Respond and verify | Inspect action capabilities, propose or request policy-authorized actions, observe receipts and verify postconditions |

**One-shot observation is particularly important.** A model should not have to create a persistent watch and wait for a collection interval simply to answer a factual investigative question. Reuse collector implementations where possible, but provide a bounded request/response or asynchronous job interface with explicit status, timeouts, output limits, and provenance.

### Extensible investigative capabilities

The fixed collector catalog is a sensible starting point, not a permanent ceiling on what the system can investigate. Provide a capability registry that describes available operations, input schemas, required permissions, output semantics, sensitivity, resource cost, and supported environments. Let the model discover and request new capabilities rather than hallucinating tool availability.

When an investigation identifies a genuine capability gap, record it and support an operator-reviewed extension process. New collector modules or constrained declarative query capabilities should be reviewed, tested, versioned, and deployed through a separate trusted extension lifecycle. Do not give the remote investigator unrestricted command execution or the ability to install its own privileged code as a shortcut to extensibility. A controlled local lab mode can evaluate new extensions before they become approved fleet capabilities.

## 7. Persistent and proactive reasoning

Support multiple run types in the durable control plane. Run identity, evidence scope, authorization, limits, progress, cancellation, and outcomes must remain explicit regardless of which model frontend is used.

| Mode | Initiation | Responsibility |
| --- | --- | --- |
| Discovery | Enrollment, operator request, material host change | Understand host and establish initial monitoring |
| Reactive | Deterministic event or incident | Investigate and adapt monitoring in response to changes |
| Proactive assessment | Scheduled or policy-authorized investigator request | Search for unexplained conditions, coverage gaps, and posture changes |
| Follow-up | Persisted unresolved hypothesis or timed condition | Gather further evidence and close or escalate open questions |
| Response verification | Action receipt or operator request | Confirm mitigation outcome, detect adverse effects, and recommend next steps |
| Supervisory review | Periodic schedule or high-risk decision | Reassess prior findings, monitoring strategy, and baseline decisions using a capable model |

Support configurable model routing, reasoning effort, tool-call/time/token budgets, concurrent run limits, and prioritization. A deep discovery or complex investigation may legitimately require significantly more effort than routine triage. Avoid hard-coded low ceilings that prevent the investigator from gathering sufficient evidence. Preserve explicit exhaustion, cancellation, and resumption semantics so open investigations remain visible and recoverable.

Store long-term host knowledge in structured, versioned records rather than relying on the context window. At a minimum, retain operational purpose, services and dependencies, monitoring inventory, known maintenance patterns, historical incidents, unresolved hypotheses, evidence references, and confidence/provenance. Treat model-generated knowledge as fallible and revisable. Do not allow it to become a hidden source of authorization or persistent trusted instructions.

The persistent worker should be able to resume from durable state after model/provider changes. Long-lived agent sessions are a useful interface, but not the authoritative memory or policy store.

## 8. Authority model: independent, configurable dimensions

Do not implement autonomy as a single on/off switch. Allow operators to configure authority per host or host group, per capability, and per risk class. Prefer understandable capability policies to an abstract numerical autonomy score.

| Authority | Observer | Adaptive investigator (recommended target) | Authorized response profile |
| --- | --- | --- | --- |
| Scoped discovery and one-shot observations | Allowed | Allowed | Allowed |
| Proactive investigation and host knowledge | Allowed within budget | Autonomous | Autonomous |
| Additive monitoring and watch maintenance | Propose | Autonomous within policy | Autonomous within policy |
| Provisional baseline establishment | Propose | Autonomous | Autonomous |
| Trusted baseline and expectation changes | Operator-approved | Delegated for eligible low-risk changes | Delegated for eligible low-risk changes |
| Mitigation requests | Propose | Propose | Policy-authorized reversible actions; others require approval |
| Privilege expansion or policy modification | Never | Never | Never through investigator authority |

These profiles are starting points, not fixed product limitations. The operator can grant greater or lesser authority based on the operational environment. Separate read access from the authority to export telemetry to an external model provider; sensitive evidence may require local processing, minimization, redaction, or explicit additional authorization.

Reuse the existing short-lived scoped credentials, deterministic gates, local safety floors, signed desired state, audit ledger, and separate action executor. If a run needs broader scope or an otherwise prohibited capability, it should explain the need and request an explicit policy decision instead of quietly failing or attempting a bypass.

Phase 8 already established typed containment and mitigation machinery. Expand its usefulness through better investigation and response selection rather than giving the model arbitrary system administration privileges. Authorized mitigation should include a clear rationale and evidence, preconditions, bounded effect, verification, and rollback or recovery plan. Higher-impact actions remain separately authorized; unknown execution outcomes must be reconciled before retrying.

## 9. Validation: evaluate the intelligence, not just the guardrails

Passing unit and integration tests proves important implementation properties. It does not, by itself, prove the model is a useful security analyst.

Build an experimental evaluation suite using disposable, authorized Linux environments with known ground truth. Scenario definitions and expected outcomes should be separate from what the investigator sees. Include held-out variations rather than letting the investigator memorize a fixed set of tests.

| Scenario | Required evaluation |
| --- | --- |
| Blind onboarding of unfamiliar hosts | Host-role inference, meaningful monitoring established, coverage gaps identified |
| Mixed benign changes and unexplained initial behavior | False-positive rate and whether suspicious state is prematurely normalized |
| Previously unseen incident variations | Correct hypotheses, evidence-linked findings, appropriate additional monitoring |
| Routine maintenance and software updates | Noise reduction without suppressing security-relevant events |
| Multiple related hosts | Correlation quality without exceeding authorized evidence scope |
| Incomplete or deceptive telemetry | Honest uncertainty, attribution limits, and appropriate escalation |
| Provider outage, process restart, or budget exhaustion | Continued deterministic monitoring, durable investigation resumption |
| Authorized response in a disposable lab | Appropriate action selection, verification, recovery, and unintended effects |

Compare at least three configurations: a static monitoring baseline, the existing incident-triggered reasoner, and the expanded adaptive investigator. Use comparable initial telemetry and resource budgets where appropriate; separately measure the benefit of richer collection and larger reasoning budgets. Record which advantages come from additional sensors versus better reasoning or monitoring adaptation.

Measure:

- Detection recall/precision against known events and false alerts per host-day.
- Time to detection, investigation completion, and verified conclusion.
- Grounded finding accuracy, unresolved ambiguity, unsupported conclusions, and evidence coverage.
- Baseline establishment quality, incorrect acceptance of suspicious behavior, and legitimate-change handling.
- Quality and usefulness of autonomously created watches, monitoring coverage, and resource overhead.
- Human interventions required, model calls, tokens, cost, and latency.
- Unauthorized actions or scope violations, policy rejections, and successful recovery from interrupted runs.

Define acceptance criteria before evaluating results. Report actual results, failures, uncertainties, scenario limits, and model versions. Do not present a synthetic benchmark or an individual successful investigation as proof of production readiness. The security and correctness regression suites remain mandatory, but effectiveness must become an equally visible release criterion.

## 10. Suggested implementation sequence

The next phase should be explicitly scoped to expanding investigative effectiveness. The following sequence is proposed; adapt the numbering and branch structure to the actual repository state. Complete the existing Phase 12–13 integration and review work without unnecessarily blocking design or independent implementation preparation for this direction.

| Milestone | Deliverable | Exit criterion |
| --- | --- | --- |
| A. Capability and gap inventory | Map existing RPCs, MCP tools, collectors, policy gates, run types, baseline state and action machinery against this charter | Identify reuse opportunities, genuine gaps, and security-sensitive changes |
| B. Discovery and one-shot observation | Non-incident discovery runs, capability discovery, bounded on-demand evidence collection, durable host profile | An investigator autonomously develops a meaningful profile for an unfamiliar test host |
| C. Adaptive monitoring and baseline lifecycle | Model-managed persistent watches, provisional baselines, evidence-backed promotion policies, coverage assessment | The investigator establishes useful monitoring without manual watch-by-watch configuration and avoids blindly trusting unexplained state |
| D. Proactive and persistent reasoning | Scheduled assessments, durable hypotheses, follow-ups, model routing and supervisory review | Investigations can initiate without an incident and resume after restart without relying on transcript memory |
| E. Expanded response and evaluation | Use existing action machinery for authorized response and verification; expand benchmark suite and compare configurations | Demonstrate measured investigative benefit and report limitations before considering broader deployments |

Each milestone should produce executable tests, documented interfaces, reproducible evidence, and a clear comparison against the existing behavior. Preserve disjoint implementation ownership and independent cross-model review where appropriate. Prioritize vertical slices that demonstrate real end-to-end investigator usefulness over large numbers of isolated APIs with no meaningful workflow.

## 11. Direction to the development team

Treat this charter as a correction to the project's optimization priorities, not a mandate to weaken its trust boundaries. Before implementation, assess the current state against the target operating model and propose the smallest coherent set of changes needed to realize it. Distinguish existing functionality from genuine gaps and from optional future improvements.

When reviewing a proposed feature, ask both:

1. What concrete failure or abuse does the control prevent, and does the enforcement actually prevent it?
2. Can a capable investigator still accomplish its legitimate objective without unnecessary operator intervention?

A feature should not be judged successful solely because unsafe requests are rejected. It should also demonstrate that authorized investigative work can be completed effectively. Conversely, effective investigation is not grounds to bypass the control plane, grant privileges to a model, or treat its confidence as an authorization decision.

The intended outcome is a system that can be entrusted with substantial responsibility for understanding, monitoring, investigating, and improving the defensive posture of authorized infrastructure while keeping consequential execution within explicitly configured, independently enforced authority.

**Development scope:** This charter expresses desired architecture and behavior. It does not itself authorize deployment changes, access to new hosts or data sources, expanded production credentials, or live mitigation. Validate new authority profiles in disposable environments before considering opt-in use on real infrastructure.
