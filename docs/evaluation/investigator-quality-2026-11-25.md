# Investigator quality across five models and seven configurations

Luna High is the best-supported low-cost choice for guided reassessment. Luna High, Luna Max, Sol Low and Sol Medium all produced correct findings on the supplied evidence and passed the same guided investigations. Only Luna High has completed the six-case independent watch-selection test. Its 3/6 there leaves the choice of an autonomous lead investigator open.

Raw attempt traces are retained outside the repository.

## What each test measures

| Configuration | Interpret a supplied sample | Guided episodes requiring a model | Independent watch selection |
| --- | ---: | ---: | --- |
| GPT-6 Luna High | 3/3 | 3/3 | Correct watch 4/6, full outcome 3/6 |
| GPT-6 Luna Max | 3/3 | 3/3 | Untested |
| GPT-6.2 Sol Low | 3/3 | 3/3 | Untested |
| GPT-6.2 Sol Medium | 3/3 | 3/3 | Untested |
| GLM-5.3 | 3/3 | Untested | Untested |
| GLM-5.3 Flash | 3/3 | 2/3 | Untested |
| Beam 1.0 501B A23B | 2/3 | Untested on this protocol | Earlier, different two-stage trial described below |

The supplied samples represented active/running, inactive/dead and unknown. Success required the correct persisted interpretation and exactly the fresh observation ID. All seven configurations cited the correct sample on all three cases. Active and unknown were correct in 7/7 configurations each. Inactive was correct in 6/7. The only error was Beam's positive label on the inactive case. These are 21 attempts on three repeated fixtures. The OpenAI routes used explicitly requested efforts on first-party Responses. The GLM and Beam routes used OpenRouter with provider-selected backends.

The three guided model cases covered quiet-host interpretation, a delivered sample after an unexpected listener, and a withheld sample. The new-service and withheld cases supplied the watch specification. A fourth maintenance episode in the original scores passed deterministically with zero model calls. The table omits that episode from model credit. A withheld-sample pass credits opening the durable question and avoiding a premature verdict at cutoff. The worker waits for a sample before calling the assessor again. [Episode protocol](phase18-protocol.md)

## Quality of the findings

**Luna High and Max.** Both described PostgreSQL as a likely host role while distinguishing an installed package and a listener from proof that PostgreSQL owned the socket. Both left the dependency list empty when the samples did not establish a dependency. High gave a concise negative answer on inactive/dead. Max more explicitly limited the answer to the time of sampling. The extra qualification changed no scored decision. Max used 4,079 reasoning tokens to High’s 1,703 across the seven guided and reassessment cases. The evidence gives little reason to pay for Max on those tasks.

**Sol Low and Medium.** Both distinguished package presence, socket ownership and external reachability. Both kept the installed package in the dependency field while marking runtime use as unverified. Low recorded a tentative hypothesis before the active sample and later recorded the cited assessment. Medium recorded an interim hypothesis on the withheld case and left the evidence question open. Those extra records can help an operator see what the model knows at each stage. Neither effort improved the final verdict over Luna High. Sol Low makes a useful challenger for independent selection because it matched guided quality with the shortest median request time in the OpenAI pilot. [Matched timing](openai-investigator-2026-11-25.md)

**GLM-5.3.** Full GLM correctly distinguished a loaded unit from a running unit, returned the right label in all three isolated cases, and included host, observation and sample details in its explanations. On the inactive case it described an empty unit-file list as a minor inconsistency. The fixture supplies no rule requiring a loaded unit to have a populated file list. That caveat adds an unsupported inference to an otherwise correct finding. The available runs qualify it as a candidate for interpreting supplied evidence. Its ability to obtain that evidence independently is unmeasured.

**GLM-5.3 Flash.** Flash correctly inferred a likely PostgreSQL host and explicitly qualified process ownership. Its discovery record also inferred *intent* from an all-interface bind. The bind establishes the address observed, while intent requires other evidence. In the guided active-service case, Flash cited the correct observation and accurately described active/running, then persisted `unresolved` because it wanted integrity checks and unit-file hashes. The question asked what the sample reported at that instant. In this case the extra caution withheld an answer the evidence supported. The same model scored 3/3 with the simpler supplied questions.

**Beam.** Its inactive summary accurately named the inactive/dead state, but the persisted label was `supports` for the question asking whether the unit was active. An operator reading the summary and a consumer acting on the enum would receive opposite answers. An earlier first-party trial exposed a different problem. In two adaptive runs, Beam obtained fresh unit-state evidence once. The finding in that run cited only the two older socket observations. Both trials therefore missed the fresh-citation target. Their older worker revision, fixture and budgets preclude a direct comparison with Luna’s 4/6 selection score. [First-party adaptive trial](investigator-pilot-2026-11-25.md)

## Evidence selection and handoff

In the scored Luna High runs the operator supplied only a port and a question. Two listeners were new and their process names matched. Four of six runs selected the correct service and installed a signed watch. All six initial investigations reached the four-turn cap. Media and metrics spent their turns querying existing evidence or recording a hypothesis and never requested a new sample. Repeated reads also occurred after successful watch proposals. In this fixture collection could begin only after the initial investigation returned. This suggests a concrete place to test whether finishing the initial run after an accepted proposal saves turns. [Protocol](luna-selection-protocol.md)

Three selected watches received a sample. Luna cited the exact new observation in all three, and persisted the expected label in two. The fourth selected watch correctly stayed pending when the sample was withheld. On the inactive index service, Luna correctly described inactive/dead but recorded `unresolved`. The saved rationale asked to check the unit’s state and mentioned socket attribution. It omitted the operator’s original yes/no question. The assessor expressly identified the missing question. A matched replay preserving the operator's exact proposition would test whether that omission caused the error. The alternate possibility is that the assessor still conflates unit state with socket ownership. [Selection outcomes](luna-selection-2026-11-25.md)

## Decision for the next comparison

Use Luna High as the baseline and Sol Low as the first challenger on the same independent-selection cases. Compare each stage separately: correct target and collector, accepted watch, a fresh citation when a sample arrives, agreement between prose and stored decision, and a pending question when evidence is withheld. Preserve the original question for both routes and keep a matched replay of the existing handoff. Count extra queries after a watch is accepted and inspect whether they supplied new information. Increase the effort setting only if it improves one of these outcomes on repeated cases. GLM-5.3 is the remaining candidate with clean supplied-sample decisions and no guided-episode result.

This review used existing model outputs and retained the original scoring. The qualitative observations about caveats and operator usefulness are retrospective judgments. The results cover bounded synthetic monitoring questions with small samples. None of the models has demonstrated reliable open-ended fleet investigation on this evidence.
