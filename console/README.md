# Operator Console

A localhost operator console for the Defensive Security Autonomous Mitigation Harness: a small Node 24 backend-for-frontend (BFF) plus a hand-built, responsive security-operations UI.

It has **zero dependencies**. It uses only Node built-ins (`node:http`, `node:net`, `node:fs`, `node:path`, `node:crypto`, `node:test`, `node:assert`) and vanilla HTML/CSS/ES modules. Nothing to `npm install`, and it runs and tests fully offline.

```
console/
├── server.mjs              HTTP BFF, routing, security headers, CLI
├── lib/
│   ├── auth.mjs            Access gate: local accounts (scrypt, HMAC sessions) or proxy headers
│   ├── uds-client.mjs      4-byte BE length-prefixed JSON framing over Unix sockets
│   ├── live-backend.mjs    All live data via control-d investigate/admin sockets
│   ├── demo-data.mjs       Offline fixtures + in-memory mutations
│   ├── demo-actions.mjs    Phase 8 demo intents with real Ed25519 envelopes + approval rules
│   ├── demo-reasoner.mjs   Phase 9 demo reasoner-d runs, run events and trigger queue (time-driven)
│   ├── demo-rules.mjs      Phase 10 port of rule_gate.rs, rules.rs and the rule store for demo mode
│   ├── demo-policy.mjs     Port of control_gate.rs + edge_floor.rs for demo mode
│   ├── adaptive.mjs        P11–P18 request bodies, browser-safe projections, derived host views
│   ├── demo-adaptive.mjs   P11–P18 demo fixtures: quiet host, discovery, monitoring, reviews, verification
│   ├── audit-chain.mjs     RFC 8785 canonical JSON + SHA-256 audit-chain verifier
│   └── domain.mjs          WatchSpec builder, input validation, three-state baseline
├── public/                 index.html, styles.css, app.js, dom.js, favicon.svg
└── test/server.test.mjs    node --test suite
```

## Run

```sh
# Offline demo: no daemons needed
node console/server.mjs --demo                 # http://127.0.0.1:8787/
node console/server.mjs --demo-readonly        # demo with admin routes disabled

# Live, read-only browsing (admin routes return 403; operator sessions need --enable-admin)
node console/server.mjs \
  --investigate-sock /run/defsec/investigate.sock \
  --token-file ~/.config/defsec/console.token

# Live, with the separate admin interface explicitly enabled
node console/server.mjs \
  --investigate-sock /run/defsec/investigate.sock \
  --token-file ~/.config/defsec/console.token \
  --enable-admin --admin-sock /run/defsec/admin.sock
```

The token comes from `--token-file` (preferred; the console warns if the file is group- or world-readable), `--token` (the console warns because it is visible in `ps`), or the `DEFSEC_CAPABILITY_TOKEN` environment variable. Mint one with control-d's `MintCapabilityToken` admin op, without an `incident_id`, covering every host the console should show. It is used only for reads (including reasoner activity: runs, run events and the trigger queue): each operator session gets its own minted incident-scoped token (see *Per-run tokens* below), which is why starting a session requires `--enable-admin`.

Other flags: `--host` (default `127.0.0.1`), `--port` (default `8787`, `0` picks a free port), `--allowed-host H[:P]`, `--timeout-ms`, `--quiet`.

## Access gate

`--auth-mode` picks one of three modes. The default is `none`, which suits a loopback bind; binding `none` to a network address prints a prominent warning.

**Local accounts** (`--auth-mode local`):

```sh
# Create or reset an account. The password never goes in argv: it comes from a hidden prompt, stdin or an env var.
node console/server.mjs --create-user --auth-users-file /etc/defsec/console-users.json \
  --username alice --role admin                       # interactive prompt
printf '%s\n' "$PW" | node console/server.mjs --create-user --auth-users-file … --username bob --role observer --password-stdin
CONSOLE_PW=… node console/server.mjs --create-user --auth-users-file … --username carol --role observer --password-env CONSOLE_PW

node console/server.mjs --demo --auth-mode local --auth-users-file /etc/defsec/console-users.json
```

- The users file is written atomically (0600 temp file, fsync, rename). Each entry is scrypt (N=16384, r=8, p=1) with a random 16-byte salt and is compared with `timingSafeEqual`. Unknown usernames pay the same scrypt cost as known ones.
- Sessions use a random 256-bit ID with an HMAC-SHA256 tag, tracked server-side. The cookie is `dsc_session; HttpOnly; SameSite=Strict; Path=/`, and `Secure` is added with `--secure-cookies` or when a trusted proxy sends `X-Forwarded-Proto: https`. The TTL is set with `--session-ttl` (default `8h`). Logout deletes the server session. A password reset, role change or account removal ends that user's sessions.
- The HMAC key is random per process unless you pass `--session-secret-file` or set `DEFSEC_CONSOLE_SESSION_SECRET` (at least 32 bytes). Sessions are held in memory, so a restart signs everyone out.
- Failed sign-ins are rate-limited per client IP: 10 failures in a sliding 5-minute window return `429` with `Retry-After`. `X-Forwarded-For` is honoured only from `--trusted-proxy-ips`.

**Reverse-proxy identity** (`--auth-mode proxy-header`), for Caddy + Authelia/Authentik, oauth2-proxy, Tailscale and similar:

```sh
node console/server.mjs --investigate-sock … --token-file … \
  --auth-mode proxy-header --trusted-proxy-ips 127.0.0.1,::1 \
  --proxy-user-header x-forwarded-user \
  --proxy-role-header x-forwarded-groups --proxy-admin-group defsec-admins
```

Identity headers count **only** when the TCP peer (`req.socket.remoteAddress`, normalised across IPv4, IPv6 and IPv4-mapped forms; CIDRs allowed) is a trusted proxy. Any other peer gets `403 untrusted_proxy` on every route, whatever headers it sends. A trusted peer without a user header gets `401`. A user is `admin` only if the role header contains `--proxy-admin-group`; everyone else is `observer`. Without a role header, every user gets `--proxy-default-role` (default `observer`).

**Identity on mutations.** Whenever a gate is active, the `approver` of a baseline promotion or action approval and the `actor` of an incident closure are the signed-in account name. The BFF overwrites whatever the client sent, so the UI shows "Approved by alice" instead of asking, and the audit log cannot be attributed to someone else. With `--auth-mode none` the UI pre-fills the name remembered in this browser (default `operator`) behind a **Change** link.

**Authorization.** Whenever a gate is active, every `/api/*` route except `/api/auth/*` returns `401` until the user is identified. `/api/admin/*` and `/api/demo/*` also need the `admin` role (otherwise `403 admin_role_required`), on top of `--enable-admin`. Observers are read-only: any state-changing POST returns `403 read_only_role`. The UI shows a focused sign-in view and fetches no telemetry until the user is signed in. It also shows a `username · role` badge and a **Sign out** button.

| Method & path | Purpose |
|---|---|
| `GET /api/auth/session` | `{ auth_mode, authenticated, user: { username, role } \| null }`, always reachable (except from an untrusted peer in proxy mode) |
| `POST /api/auth/login` | `{ username, password }`. Sets the session cookie. Origin and JSON checks apply. |
| `POST /api/auth/logout` | Deletes the server session and expires the cookie |

## Trust boundaries

| Boundary | Enforcement |
|---|---|
| Network exposure | Binds to `127.0.0.1` by default. Binding to any non-loopback address needs an explicit `--host` and prints a warning. |
| Data path | Live data comes **only** from control-d's Unix sockets. The console never opens SQLite and never talks to edge agents. |
| Admin role | The admin socket is used only with `--enable-admin`. Otherwise every `/api/admin/*` route returns `403 admin_disabled`. |
| Capability token | Kept in a private class field of the UDS client. It is never sent to the browser, logged, or echoed in errors. Tests assert that no response body contains it. |
| Per-run tokens | The `--token-file` token is a **browse** token and is only ever used for reads. control-d permanently narrows whichever token calls `StartInvestigationRun` to that run's incident and host, so `POST /api/incidents/:id/runs` (the **Start operator session** button) mints a fresh incident-scoped `investigator` token over the admin socket (`principal_id` `console-run-<first 8 of incident id>`, 1 h TTL, the host's collectors) and starts the run with it. Proposals, findings and mitigation proposals for that incident go through the run's own token; it stays in memory, is dropped when the incident is closed, and is never returned to the browser. Without `--enable-admin` the route returns `403 admin_required_for_runs` instead of narrowing the shared token. |
| DNS rebinding | The `Host` header must be an allowed loopback name plus the bound port, on **every** request. |
| CSRF | A `POST` needs an `Origin` equal to its own `Host`. If `Origin` is absent, `Sec-Fetch-Site` must not be cross-site. The body must be `application/json`, at most 64 KiB, and a JSON object. Otherwise the server returns 403 or 415 before any mutation. |
| Browser hardening | Every response carries `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; … frame-ancestors 'none'`, plus `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, COOP/CORP and `Permissions-Policy`. |
| Untrusted telemetry | Journal text, host IDs, unit names and summaries are rendered only as DOM `Text` nodes, through `public/dom.js`. The UI has no `innerHTML`, no inline scripts and no inline styles; the tests check this. The demo includes a journal line carrying an `<img onerror>` XSS probe plus a prompt-injection string, and both render as inert text. |
| Static files | Served from an in-memory allowlist of the top-level files in `public/`. No path is ever resolved from user input. |

## REST API

| Method & path | control-d call |
|---|---|
| `GET /api/status` | `ListHosts` probe (+ `VerifyAuditChain` when admin is on). Returns mode, admin flag, socket reachability and latency, and an audit summary. |
| `GET /api/hosts` | `ListHosts`, each enriched with `watch_count` / `baseline_watch_count` / `stream_watch_count` from `ListActiveWatches` |
| `GET /api/hosts/:host/watches` | `ListActiveWatches` |
| `GET /api/hosts/:host/capabilities` | `ListCollectorCapabilities` |
| `GET /api/hosts/:host/baselines` | `GetHostBaselineSummary` + `ListActiveWatches` + `QueryObservations`, reduced to an `accepted_baseline` / `last_observed` / `current_observed` row per watch. `journal.unit_events` (or any `stream_batch`) watches are append-only streams: they derive as `state: "stream"` with a cursor summary and are never promotable. |
| `GET /api/hosts/:host/observations?watch_id=&limit=` | `QueryObservations` |
| `GET /api/incidents` | `ListActiveIncidents` (+ admin `ListIncidents` for closed history when admin is on) |
| `GET /api/incidents/:id` | `GetIncidentContext` + the run this console started for the incident |
| `GET /api/incidents/:id/changes` | "What changed": for each snapshot watch on the incident's host, the latest observation compared with the accepted baseline (or, if none, the sample just before the incident opened) as added / removed / changed sockets, files and unit fields. Stream (journal) watches are not compared. |
| `POST /api/incidents/:id/runs` | Admin `MintCapabilityToken` (incident-scoped) + `StartInvestigationRun` on that new token. Requires `--enable-admin`. |
| `POST /api/incidents/:id/proposals` | `ProposeEphemeralWatch`. Returns the exact `PolicyDecision` (`rule_id`, `reason`, `policy_version`) and the submitted `WatchSpec`. |
| `POST /api/incidents/:id/findings` | `RecordHypothesisOrFinding` (`kind`: `hypothesis` or `verified_finding`, `evidence_observation_ids`) |
| `POST /api/incidents/:id/actions` | `ProposeAction` on the run's token: `{ verb, evidence_observation_ids, expected_effect, blast_radius, rollback_plan, idempotency_key? }`, where `verb` is exactly one of `{verb:"nft_block_ip", ip, direction, ttl_seconds}`, `{verb:"systemd_stop_unit", unit, ttl_seconds?}` or `{verb:"host_isolate", preserve_mgmt_cidrs, ttl_seconds}`. Returns the gate's `decision` (`rule_id`, `reason`), `auth_mode`, `status`, `proposal_id` and `intent_id`. Protected units/CIDRs and TTL ceilings are left to control-d, so the operator sees the real verdict. |
| `GET /api/runs?incident_id=&host_id=&limit=` | Phase 9 `ListInvestigationRuns` on the browse token. Each `RunSummary` gains `origin`: `operator` for console sessions (`backend_id` `operator-console`, `console-*` principals), otherwise `automated`. |
| `GET /api/runs/:run_id/events?after_seq=&limit=` | Phase 9 `GetRunEvents`: events sorted by `event_seq`, plus `next_after_seq` for incremental polling. `detail` is free-form and rendered as text only. |
| `GET /api/triggers?incident_id=&host_id=&status=&limit=` | Phase 9 `ListTriggerQueue`; `status` is a comma list of `pending`, `leased`, `done`, `dead_letter`. |
| `GET /api/rules?status=&host_id=&limit=` | Phase 10 `ListExpectationRules`: admin interface when `--enable-admin` is on (every host), otherwise the browse token's investigation scope (`source` says which). `status` is a comma list of `active`, `proposed`, `rejected`, `revoked`, `expired`; `limit` 1–100 (control-d's cap). Records keep exactly the `ExpectationRuleRecord` fields. Against a control-d before Phase 10 it answers `200 {"available": false, "reason": "unsupported"}`. |
| `POST /api/admin/rules/backtest` | `BacktestExpectationRule` with `{ rule }`. Returns `{ allowed, decision, backtest, rule }`: the `RuleBacktest` when the operator gate accepts the rule, otherwise `decision` is the gate's `PolicyDecision`. |
| `POST /api/admin/rules` | `CreateExpectationRule` with `{ rule, actor }` (operator origin, active immediately). Returns `{ allowed, decision, rule_id, status, rule }`. |
| `POST /api/admin/rules/:rule_id/decide` | `DecideExpectationRule` with `{ approve: boolean, note?, actor }`. Approval re-runs the gate; a denial comes back as `decision` and the rule stays `proposed`. |
| `POST /api/admin/rules/:rule_id/revoke` | `RevokeExpectationRule` with `{ reason, actor }`. The reason is required. |
| `GET /api/automation` | Summary of the audit window (admin only): automated `run_started` / `watch_proposed` / `finding_recorded` / `action_proposed` entries from non-console principals, kept apart from console-driven runs. `available:false` without the admin interface. |
| `GET /api/admin/audit?limit=` | `VerifyAuditChain` + `ListAuditEntries`, plus the console's **independent** recomputation of every returned hash |
| `GET /api/admin/policy-decisions?limit=&rule_id=` | `ListPolicyDecisions` |
| `POST /api/admin/baselines/promote` | `PromoteBaseline` (`approver`, `rationale`, optional `ticket_ref`) |
| `POST /api/admin/incidents/:id/close` | `CloseIncident` |
| `POST /api/admin/hosts/enroll` | `EnrollHost` |
| `GET /api/actions?host_id=&incident_id=` | Phase 8 `ActionSummary` list. With admin on it uses admin `ListActions` (fleet-wide) plus denied proposals taken from `action_proposed` audit entries. Otherwise it uses investigation `{op:"list_actions"}`, which control-d answers only for an incident-scoped capability. |
| `GET /api/admin/actions/:intent_id` | `GetActionIntent` (`payload`, `authorized_intent`, `status`), the matching summary, receipts from the audit log, and `signing` (RFC 8785 canonical payload + SHA-256) for offline signers |
| `POST /api/admin/actions/:intent_id/approve` | `ApproveAction` with `{ approver, operator_approval }`, where `operator_approval` is a **pre-signed** `SignedEnvelope` (exactly `domain`, `signing_key_id`, `raw_payload`, `signature_hex`; domain `defsecautmit.action_approval.v1`). Demo mode also accepts `{ approver, note? }` and co-signs with a simulated in-process demo key. |
| `POST /api/demo/tamper`, `POST /api/demo/reset` | Demo mode only. Rewrites one audit entry without re-hashing, or restores the fixtures. |

**Adaptive investigator (P11–P18).** Every read degrades to `200 {"available": false, "reason": "unsupported" \| "forbidden" \| "admin_disabled", "message"}` against a control-d without the op, a token that may not read it, or a console without the admin interface. Every mutation is an admin route (`--enable-admin` and the admin role), and bodies are rebuilt field by field because control-d uses `deny_unknown_fields`.

| Method & path | control-d call |
|---|---|
| `GET /api/hosts/:host/profile` | P11: `ListHosts` (`host_profile`) + `ListCollectorCapabilities` + `ListActiveWatches` + `QueryObservations`, reduced to one coverage row per collector (enabled/disabled by profile, advertised, watches, latest sample, partial attribution, truncation). An agent without a profile reports support as unknown. |
| `GET /api/hosts/:host/discovery?version=` | P15: `GetHostAssessment` (latest, and `version` when pinned) + `GetHostDiscoverySamples` + `ListHostInterpretationAttempts` for the current samples' source IDs and each interpretation's. Samples are cut to a typed 40-entry preview. |
| `POST /api/admin/hosts/:host/discovery/advance` | Admin `MintCapabilityToken` (`console-discovery`, investigator, this host, the two discovery collectors, 300 s) + `AdvanceHostDiscovery` on that token only. |
| `GET /api/hosts/:host/monitoring` | P16: admin `ListAuditEntries` (500) + `GetHostBaselineSummary` + `ListActiveWatches`. control-d has no read for grants or managed watches, so the console rebuilds them from the `policy_decision` entries control-d writes for every grant, apply, provisional, corroborate, promote and rollback. |
| `POST /api/admin/hosts/:host/monitoring/grant` | `SetMonitoringGrant` `{ principal_id, max_watches (0–32; 0 revokes), allow_promotion }` |
| `POST /api/admin/monitoring/candidates/:id/corroborate` | `CorroborateMonitoring` `{ rationale }`. A refused corroboration is `200 { allowed: false }`. |
| `POST /api/admin/hosts/:host/monitoring/:watch/rollback` | `RollbackMonitoring` `{ expected_baseline, rationale }`. A stale baseline is `200 { allowed: false, reason }`. |
| `GET /api/hosts/:host/review` | P17: admin `GetLatestHostReview` + `GetHostAssessment`, with freshness (`current`, `assessment_advanced`, `overdue`, `awaiting_first_review`, `never_reviewed`). control-d has no read for schedules, so live mode shows the schedule this console last set (`source: "console"`). |
| `POST /api/admin/hosts/:host/review-schedule`, `…/cancel` | `SetHostReviewSchedule` `{ schedule: { host_id, interval_seconds (60 s–30 d), question, collectors (discovery collectors, sorted), route } }`, `CancelHostReviewSchedule` |
| `GET /api/incidents/:id/followups` | P14: `ListWatchFollowups` joined with the incident's findings, so each accepted watch's question carries its fresh observation ID, deadline, status and the recorded interpretation (`supports`, `contradicts`, `unresolved`). |
| `GET /api/admin/actions/:intent_id/verification` | P18: `GetActionVerification` + `GetActionIntent`. Returns the receipt checks, precondition, concurrent changes on other monitored units, operator reconciliations, the latest receipt's outcome and whether a reconciliation is admissible. |
| `POST /api/admin/actions/:intent_id/reconcile` | `ReconcileActionOutcome` `{ expected_receipt_id (latest, or null), evidence_ref, rationale }`. control-d records the actor as `operator`. |

**Operator private keys never reach the console.** For a `pending_approval` intent, the UI shows the exact command to run on the operator's own workstation:

```sh
admin-cli --admin-sock /run/defsec/admin.sock \
  approve-action <intent_id> \
  --approver alice \
  --operator-key-file ~/.config/defsec/operator.key \
  --operator-key-id operator-01
```

An admin can instead paste an envelope signed elsewhere. The UI checks the field set, the domain, the signature length and that `raw_payload` matches the intent's canonical payload before it sends anything. control-d still does the authoritative checks: trusted independent key, signature, expiry, open incident, per-host rate limit and causal cooldown.

The three reasoner-activity routes never send a capability or lease token to the browser: responses are rebuilt field by field from the contract, and token-like keys (`token`, `lease_token`, `capability_token`, `run_token`, `*_secret`, …) are dropped from free-form `detail` objects as well; counters such as `tokens` and `input_tokens` are kept. They never call `StartInvestigationRun`. Against a control-d from before Phase 9 (which closes the connection on an unknown op) or a token that may not read them, they answer `200 {"available": false, "reason": "unsupported" | "forbidden", "message": "reasoner activity requires control-d ≥ Phase 9"}` so the rest of the console keeps working; an unreachable socket is still `503`.

**Expectation rules.** control-d deserializes `ExpectationRuleSpec` with `deny_unknown_fields` (an unknown key or a float value makes it close the socket), so the BFF checks the exact shape first: the five spec keys, the three scope keys, the four clause ops with exactly their own keys, `RuleValue` as an integer, boolean or string, the effect enum and an RFC 3339 `expires_at`. A malformed body is a `400` that never reaches control-d. Policy bounds (1–8 clauses, 1–32 `in` values, text sizes, identity anchor, port bounds, wildcard binds, expiry) are left to control-d's rule gate. control-d answers a denied create, decide or backtest with `Error { code: "rule-gate/<id>", message }`; the console returns that as `{ allowed: false, decision: { allowed, rule_id, reason, policy_version } }` with status 200, never a 5xx. The error frame has no `policy_version`, so for create and decide the BFF reads it back from the `PolicyDecision` row control-d just recorded; a denied backtest records nothing, so its `policy_version` is `null`. The `actor` of create, decide and revoke is the signed-in account whenever an access gate is active, exactly like the P9 approver and actor.

Errors use one shape: `{"error": {"code", "message"}}`. control-d codes map to HTTP statuses as `forbidden` → 403, `invalid_request` → 400 and `not_found` → 404. An unreachable socket gives 503 `control_unreachable`.

The proposal composer sends a guided draft (`collector_type`, `parameters`, `interval_seconds`, `timeout_seconds`, `ttl_seconds`, `max_runs`, `trigger`, `rationale`, optional `class`). The BFF turns that draft into a schema-exact `WatchSpec`, keeping only the fields each collector declares, because control-d uses `deny_unknown_fields`. The BFF deliberately does **not** pre-enforce the safety bounds. control-d's deterministic gate decides, and the operator sees its real `rule_id`, for example `spec.safety_floor`, `baseline.protected` or `dedup.equivalent_active_watch`.

## The UI

The look follows a "framed sheet" direction: one cool-slate frame holds the sidebar and the 48 px top bar (no rule between them), and every view sits on a white sheet inset 8 px from the right and bottom edges, with flat 1 px cards and no shadows, blur or gradients. Chrome stays grey; the steel-teal accent marks the brand, the active tab and focus, and colour on data is kept for real signals. A Light / Dark switch in the sidebar footer is remembered per browser. Below 1100 px the sidebar becomes a slide-over sheet; at phone width the sheet becomes the screen and the incident list and workspace show one at a time.

1. **Fleet & posture**: a quiet audit-integrity line, a divided KPI strip (agents online, open incidents, active containment, active watches), an **Automation** card and one card per host with its real watch count and a single incident summary chip (`4 open · 4 medium`) that opens Investigations filtered to that host. Each card shows the profile's host tags (and *No declared role* for a quiet host); the host name opens the **host deep-dive** sheet (`#/fleet?host=…` deep-links it). It opens on a four-cell summary (inferred role, coverage, monitoring, last review) with four tabs: **Profile & coverage** (P11 tags, expected services, per-collector coverage and visibility gaps), **Discovery** (P15 assessment revision picker, inferred role with dependencies, cited evidence, proposed watch, unanswered question and what it cannot see; evidence or gap per collector; bounded sample tables; interpretation attempts with errors and token usage; **Advance discovery** for admins), **Monitoring** (P16 grants, investigator-managed watches with purpose, expected signal, evidence and review date; provisional, corroborated, trusted and rolled-back candidates with **Corroborate…** and **Roll back…**; **Set monitoring grant** and **Revoke**) and **Reviews** (P17 latest conclusion, freshness, cited evidence and the schedule, with **Schedule reviews** / **Cancel schedule…**). Every admin action asks for confirmation first. The Automation card says whether deterministic monitoring is running and what reasoner-d is doing right now: *Investigating #inc…* with its model, *Idle* with the last run, or *Not running?* when triggers have waited more than 2 minutes with no active run or lease. A **Trigger queue** cell (`1 pending · 1 leased`, dead letters called out) links to Reasoner activity. Without Phase 9 it falls back to the audit-log summary (admin only).
2. **Investigations**: a filterable incident list with short IDs (`#5bc7e050`, click to copy the full UUID) and a workspace. Incidents with work queued for the model carry **Queued for reasoner** (or **Queued · reasoner idle** once it has waited over 2 minutes with no worker active), and **Reasoner working** while a run or lease is live; the markers update with the 15 s poll. The workspace opens with **Reasoner activity**: the incident's queued, leased and dead-lettered triggers (lease owner with a live countdown; an explicit *reasoner-d does not appear to be running* notice for a stall) and every run on the incident, automated (`reasoner-d`, model, backend) and operator sessions (dashed, `Operator session`) told apart. Each run shows a status pill (active / completed / budget exhausted / failed / cancelled / expired), when it started and how long it ran, turns, tool calls, tokens in/out, findings and proposals accepted, and the outcome summary with any budget stop reason. Active automated runs open on a live timeline (turns, tool calls with argument previews, results with gate codes, model text, budget warnings, notes; newest first) that polls `GET /api/runs/:id/events?after_seq=` every few seconds, stops once the run is terminal, backs off while the tab is hidden and resumes when it is visible again. Then **Follow-up questions** (P14: each accepted watch's question, deadline, fresh observation and recorded interpretation), **What changed** (added / removed sockets, changed file and unit fields against the accepted baseline or the pre-incident state), hypotheses, verified findings and **Observed facts**. Socket tables with more than 12 rows get an inline filter and list added and removed rows first. The side panel has underline tabs: **Watches**, **Propose watch**, **Finding** and **Mitigation** (propose a typed `nft_block_ip` / `systemd_stop_unit` / `host_isolate`; effect, blast radius and rollback are generated from the verb and tucked under *Review audit justification*; the latest observation is cited by default; the gate's verdict links straight to the new intent in Mitigations). Evidence ticks are shared between the finding and mitigation composers. **Start operator session** opens a manual, time-limited session for the human operator that unlocks those three tabs. It does not start the model: reasoner-d runs start on their own when a trigger is leased.
3. **Reasoner activity** (`#/reasoner`, `?incident=` / `?host=` pre-filter): a health line (working / queued / idle / not running), KPIs for active runs, pending (with the oldest's age), leased and dead-lettered triggers, the **Trigger queue** (Open / Pending / Leased / Dead letter / Done / All, host and incident filters; lease owner and expiry countdown, retries and dead-letter reason) and the fleet-wide **Runs** list with the same live timelines.
4. **Baselines & telemetry**: host and watch filters and a three-state table. Stream watches show a neutral **Stream** badge with their cursor summary instead of a drift state. Promoting needs one click: the drawer shows *Approved by &lt;you&gt;* (fixed to the signed-in account; otherwise the remembered name with a **Change** link), and the pre-filled rationale and optional change ticket sit behind one **Rationale** disclosure. When two or more snapshot watches on a host have never been accepted, **Accept all initial baselines (N)** promotes them in sequence with per-watch progress. Closing an incident works the same way, with *Expected change* / *Contained* / *False positive* resolution starters.
5. **Expectation rules** (`#/rules`, `?tab=active|pending|history&host=`): one card per rule with its spec in plain language (*Allow optional: sockets on edge-01 (base-sockets) where systemd_unit = nginx.service and local_port in 80, 443*), effect, scope, expiry, hit count and last match. **Pending** proposals from reasoner-d show their origin (proposer, run and incident links) and the backtest stored with the proposal, with **Approve** / **Reject** and an optional note. **Active** rules have **Revoke…**, which stays disabled until a reason is given. **History** keeps rejected, revoked and expired rules with who decided and their note. The Fleet page shows a `Rules · N active · M pending` chip and the navigation counts pending proposals.

   On an incident, each added socket in **What changed** (for `set_diff` socket watches) has **Allow for this service**. It opens a composer prefilled from the socket: this watch (or every socket watch on the host), and `systemd_unit`, `comm`, `uid`, `protocol` and `local_port` equality clauses plus the derived `bind_scope` (`loopback`, `any` or `specific`), which satisfies the gate's identity-anchor, port-bound and wildcard-bind rules for a typical service socket. A loopback socket may widen its port to the ephemeral range 1024–65535. Clauses can be unticked; effect defaults to *Allow optional* and expiry to 30 days. control-d backtests the candidate on every change (triggered before → after, items matched, sample keys, matching now) and **Create rule** stays disabled, with the reason beside it, until the current spec has a clean backtest. A gate denial appears inline next to the clause that caused it (`rule-gate/identity-anchor` by the unit/process/UID clauses, `port-bounds` by the port, `wildcard-bind` by the bind scope, `expired` by the expiry). Sockets that an active rule already covers are marked *Allowed by rule* instead (matched in the browser against the listed rules). When control-d reports `(k suppressed by rules)` in the incident's trigger reason, the card says how many items rules suppressed in that observation; control-d does not expose which rules, so the note links to the host's rules.
6. **Mitigations**: filter tiles, the intent list, gate denials and the approval drawer (copyable `admin-cli approve-action` command, with approver, key ID and key file under one remembered *Approver and key settings* disclosure; signed-envelope form for admins; demo approval button). The drawer's **Outcome verification** (P18) shows three separate records: the **executor receipt** (what action-exec-d claimed), the **observed outcome** (verified, contradicted, indeterminate or awaiting evidence from a fresh postcondition sample, the precondition, and concurrent changes on other monitored units, causation unassessed) and the **operator reconciliation**, with a **Record reconciliation…** form when control-d would accept one. With nothing proposed yet it explains the two ways mitigations arrive: from reasoner-d with action proposals enabled, or manually from an operator session.
7. **Policy & audit**: control-d's `VerifyAuditChain` beside the console's independent recomputation, the filterable policy-decision log and the hash-chained outbox, with a broken entry highlighted.

In demo mode reasoner-d has three runs: one completed hours ago on the nginx drift, one that stopped on its tool-call budget after three findings and five watch proposals (two denied by the gate), and one **in progress** when the console starts. Its events appear in real time over the next four minutes (a verified finding lands in the incident about a minute in), then it completes and its lease is released. The queue also holds a dead-lettered trigger (HTTP 529 retries) and a pending trigger on `inc-2026-0039`, which turns into the *not running* hint two minutes after the active run ends. Operator sessions opened from the console appear beside them and log each proposal, finding and mitigation the operator submits.

The mitigation fixtures cover every lifecycle state. An autonomous `nft_block_ip` was executed and then rolled back when its TTL elapsed. Another is executing now with a running countdown. One autonomous intent expired before the executor ran it. Two dual-signed intents (`host_isolate`, `systemd_stop_unit`) are pending approval. Two proposals were denied by the gate (`action.protected_unit` for `ssh.service`, and `action.protected_ip`). Envelopes are real Ed25519 signatures over `domain ‖ 0x00 ‖ RFC 8785 payload`. Approving an intent leads to `authorized`, then about 4 s later a simulated `executed` receipt, then `rolled_back` when the TTL expires. The demo also enforces control-d's 120 s causal cooldown, so approving the second pending intent straight away is refused, as it would be in production.

## Tests

```sh
node --test console/test/server.test.mjs
```

The suite covers:

1. **UDS framing:** a big-endian length prefix, byte-at-a-time reassembly, oversize and zero-length rejection, and a roundtrip against a mock Unix socket server that splits its replies.
2. **Live integration** against `target/debug/control-d`, skipped if the binary is not built (`cargo build -p control-d`). The test starts control-d in a short temp dir, enrolls a host and mints a token. It then checks `/api/status`, the host, capability, watch, baseline and observation routes, `/api/admin/audit` (including that the console's independent RFC 8785 + SHA-256 chain head **matches Rust's**), policy decisions and enrollment. It also confirms that a cross-origin POST never reaches control-d, that every admin route returns 403 when `--enable-admin` is off, that a bad token surfaces as 403 and an unreachable socket as 503, and that the token never leaks.
3. **Demo walkthrough:** fleet, incidents and three-state drift; `run_required`; an accepted proposal followed by denials under `dedup.equivalent_active_watch`, `baseline.protected` and several `spec.safety_floor` cases; evidence-bound findings; baseline promotion; incident closure that retires ephemeral watches; audit verification; tamper detection and reset.
4. **Phase 8:** the exact `ActionSummary` / `ActionIntentPayload` / `SignedEnvelope` key sets. Live control-d accepts the console's `list_actions`, `get_action_intent` and `approve_action` frames, and enforces incident scope on the investigation socket. In demo mode, forged, mis-bound and control-key approvals are refused. Valid approvals go through authorized → executed → rolled_back. The cooldown and expiry rules hold, and the audit chain stays valid.
5. **Access gate:** the `--create-user` CLI (stdin and env), the 0600 salted users file, 401 before sign-in, indistinguishable wrong-password and unknown-user responses, CSRF on login, `HttpOnly; SameSite=Strict` cookies, observer 403s, admin access, logout invalidation, revocation on password reset, the 429 rate limit with `Retry-After`, and `Secure` handling. For proxy-header mode: admin and observer mapping, missing or invalid identity → 401, and an untrusted peer with spoofed headers → 403.
6. **Security:** CSP, XFO and nosniff on every response class; cross-origin, `null`-origin, cross-site and form-encoded POSTs refused with no state change; Host validation; body limits; static traversal; the loopback default; no `innerHTML` and no inline script or style in the UI.
7. **Per-run isolation against the real control-d:** a fake agent on control-d's agent socket pushes hashed socket and journal observations so control-d opens two genuine incidents. The test first proves the premise (a token that calls `StartInvestigationRun` is narrowed by control-d), then shows that a console run on incident A leaves incident B, the host list and the incident list readable, that findings, watch proposals and `ProposeAction` (`action.protected_ip`, `action.evidence_required`, `action.pending_dual_approval`) go through the run's minted token, that "What changed" and the stream baseline are derived correctly, and that closing A keeps every route at 200. Without `--enable-admin`, starting a run returns `403 admin_required_for_runs`.
8. **Mitigation proposals and streams:** exact `mint_capability_token` / `start_investigation_run` / `propose_action` frames over a mock control-d (the browse token never starts a run or proposes), the demo action gate (closed verb catalog, protected unit, out-of-scope evidence, autonomous authorization, idempotency replay, causal cooldown), and `deriveThreeState` treating `journal.unit_events` / `stream_batch` watches as `stream`, never drift or promotable.
9. **Reasoner activity:** demo runs, events and queue with the exact `RunSummary` / `RunEvent` / `TriggerSummary` key sets, `after_seq` paging, the in-progress run advancing with an injected clock (new events, a recorded finding, completion and lease release), filters and validation, operator sessions listed with `origin: operator`, and a stalled pending trigger. Over a mock control-d: the exact `list_investigation_runs` / `get_run_events` / `list_trigger_queue` frames on the browse token, token-like keys stripped from every response, no `start_investigation_run`, and graceful `available: false` for a pre-Phase-9 control-d (connection closed or `unknown variant`) or a forbidden token, while an unreachable socket stays `503`. Also: the *operator session* wording everywhere, and approver/actor bound to the signed-in account behind an access gate.
10. **Expectation rules:** demo list filters and the exact `ExpectationRuleRecord` / `RuleBacktest` key sets; backtests that pass and that are denied by `identity-anchor`, `port-bounds`, `wildcard-bind`, `fields`, `shape` and `expired` (always a 200 decision, never a 5xx), with the loopback ephemeral range accepted; sixteen malformed bodies refused with 400 before the backend sees them; create, approve with a note, reject, revoke with a required reason, decide-twice and revoke-twice errors; read-only demo, cross-origin and form POSTs, observer 403s and the actor bound to the signed-in account. Over a mock control-d: the exact `list_expectation_rules` (admin, or investigation on the browse token), `backtest_expectation_rule`, `create_expectation_rule`, `decide_expectation_rule` (note omitted when empty) and `revoke_expectation_rule` frames, `rule-gate/*` errors turned into decisions with the recorded `policy_version`, no frame for an invalid body, no token in responses, and "not available" against a pre-Phase-10 control-d. Against the real control-d: backtest the prefilled rule, gate denials, create, list through both interfaces, revoke, then an incident-scoped investigator starts a run and sends `propose_expectation_rule`, and the console approves it; the audit chain stays valid and no token reaches the browser.
11. **Adaptive investigator (P11–P18):** demo profiles and six-collector coverage (including an agent without a profile), versioned assessments with citations, samples, attempts and an advance that completes a pending sample; grants, corroboration, rollback and their audit entries; reviews, freshness and schedule validation; follow-up statuses and interpretations (with an injected clock for expiry); P18 receipts, outcomes and reconciliations kept separate, including an approved stop that verifies from a fresh sample. Over a mock control-d: the exact `list_hosts` / `get_host_assessment` (no `version` key for the latest) / `get_host_discovery_samples` / `list_host_interpretation_attempts` / `advance_host_discovery` / `list_watch_followups` frames and every new admin frame, discovery advanced only on a freshly minted host-scoped token, token-like keys and tokens absent from every response, eight invalid bodies refused before any frame, and `available: false` from a pre-P11 control-d for capabilities, baselines, discovery, reviews, follow-ups and verification. Observers read the deep-dive but every adaptive mutation returns `403 admin_role_required` (`admin_disabled` in a read-only console). Against the real control-d: a quiet host with a discovery-capable fake agent and profile is advanced through discovery from the console, a real investigator applies a managed watch and records a provisional expectation that the console corroborates and then rolls back after promotion, a review schedule is set and cancelled, and a `systemd_stop_unit` proposal is refused without a current active sample and accepted with one, which control-d binds as the verification precondition.

The suite keeps Unix socket paths inside `sun_path` under any `TMPDIR`: `shortTmp()` falls back to `/tmp`, `/var/tmp` or `/dev/shm` when the temp directory is too long.
