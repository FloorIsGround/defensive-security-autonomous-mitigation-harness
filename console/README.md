# Operator Console

A localhost operator console for the Defensive Security Autonomous Mitigation Harness: a small Node 24 backend-for-frontend (BFF) plus a hand-built, responsive security-operations UI.

It has **zero dependencies**. It uses only Node built-ins (`node:http`, `node:net`, `node:fs`, `node:path`, `node:crypto`, `node:test`, `node:assert`) and vanilla HTML/CSS/ES modules. Nothing to `npm install`, and it runs and tests fully offline.

```
console/
├── server.mjs              HTTP BFF, routing, security headers, CLI
├── lib/
│   ├── uds-client.mjs      4-byte BE length-prefixed JSON framing over Unix sockets
│   ├── live-backend.mjs    All live data via control-d investigate/admin sockets
│   ├── demo-data.mjs       Offline fixtures + in-memory mutations
│   ├── demo-policy.mjs     Port of control_gate.rs + edge_floor.rs for demo mode
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

# Live, read + investigate only (admin routes return 403)
node console/server.mjs \
  --investigate-sock /run/defsec/investigate.sock \
  --token-file ~/.config/defsec/console.token

# Live, with the separate admin interface explicitly enabled
node console/server.mjs \
  --investigate-sock /run/defsec/investigate.sock \
  --token-file ~/.config/defsec/console.token \
  --enable-admin --admin-sock /run/defsec/admin.sock
```

The token comes from `--token-file` (preferred; the console warns if the file is group- or world-readable), `--token` (the console warns because it is visible in `ps`), or the `DEFSEC_CAPABILITY_TOKEN` environment variable. Mint one with control-d's `MintCapabilityToken` admin op. Use role `investigator` for proposals and findings, or `observer` for read-only access.

Other flags: `--host` (default `127.0.0.1`), `--port` (default `8787`, `0` picks a free port), `--allowed-host H[:P]`, `--timeout-ms`, `--quiet`.

## Trust boundaries

| Boundary | Enforcement |
|---|---|
| Network exposure | Binds to `127.0.0.1` by default. Binding to any non-loopback address needs an explicit `--host` and prints a warning. |
| Data path | Live data comes **only** from control-d's Unix sockets. The console never opens SQLite and never talks to edge agents. |
| Admin role | The admin socket is used only with `--enable-admin`. Otherwise every `/api/admin/*` route returns `403 admin_disabled`. |
| Capability token | Kept in a private class field of the UDS client. It is never sent to the browser, logged, or echoed in errors. Tests assert that no response body contains it. |
| DNS rebinding | The `Host` header must be an allowed loopback name plus the bound port, on **every** request. |
| CSRF | A `POST` needs an `Origin` equal to its own `Host`. If `Origin` is absent, `Sec-Fetch-Site` must not be cross-site. The body must be `application/json`, at most 64 KiB, and a JSON object. Otherwise the server returns 403 or 415 before any mutation. |
| Browser hardening | Every response carries `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self'; … frame-ancestors 'none'`, plus `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, COOP/CORP and `Permissions-Policy`. |
| Untrusted telemetry | Journal text, host IDs, unit names and summaries are rendered only as DOM `Text` nodes, through `public/dom.js`. The UI has no `innerHTML`, no inline scripts and no inline styles; the tests check this. The demo includes a journal line carrying an `<img onerror>` XSS probe plus a prompt-injection string, and both render as inert text. |
| Static files | Served from an in-memory allowlist of the top-level files in `public/`. No path is ever resolved from user input. |

## REST API

| Method & path | control-d call |
|---|---|
| `GET /api/status` | `ListHosts` probe (+ `VerifyAuditChain` when admin is on). Returns mode, admin flag, socket reachability and latency, and an audit summary. |
| `GET /api/hosts` | `ListHosts` |
| `GET /api/hosts/:host/watches` | `ListActiveWatches` |
| `GET /api/hosts/:host/capabilities` | `ListCollectorCapabilities` |
| `GET /api/hosts/:host/baselines` | `GetHostBaselineSummary` + `ListActiveWatches` + `QueryObservations`, reduced to an `accepted_baseline` / `last_observed` / `current_observed` row per watch |
| `GET /api/hosts/:host/observations?watch_id=&limit=` | `QueryObservations` |
| `GET /api/incidents` | `ListActiveIncidents` (+ admin `ListIncidents` for closed history when admin is on) |
| `GET /api/incidents/:id` | `GetIncidentContext` + the run this console started for the incident |
| `POST /api/incidents/:id/runs` | `StartInvestigationRun` |
| `POST /api/incidents/:id/proposals` | `ProposeEphemeralWatch`. Returns the exact `PolicyDecision` (`rule_id`, `reason`, `policy_version`) and the submitted `WatchSpec`. |
| `POST /api/incidents/:id/findings` | `RecordHypothesisOrFinding` (`kind`: `hypothesis` or `verified_finding`, `evidence_observation_ids`) |
| `GET /api/admin/audit?limit=` | `VerifyAuditChain` + `ListAuditEntries`, plus the console's **independent** recomputation of every returned hash |
| `GET /api/admin/policy-decisions?limit=&rule_id=` | `ListPolicyDecisions` |
| `POST /api/admin/baselines/promote` | `PromoteBaseline` (`approver`, `rationale`, optional `ticket_ref`) |
| `POST /api/admin/incidents/:id/close` | `CloseIncident` |
| `POST /api/admin/hosts/enroll` | `EnrollHost` |
| `POST /api/demo/tamper`, `POST /api/demo/reset` | Demo mode only. Rewrites one audit entry without re-hashing, or restores the fixtures. |

Errors use one shape: `{"error": {"code", "message"}}`. control-d codes map to HTTP statuses as `forbidden` → 403, `invalid_request` → 400 and `not_found` → 404. An unreachable socket gives 503 `control_unreachable`.

The proposal composer sends a guided draft (`collector_type`, `parameters`, `interval_seconds`, `timeout_seconds`, `ttl_seconds`, `max_runs`, `trigger`, `rationale`, optional `class`). The BFF turns that draft into a schema-exact `WatchSpec`, keeping only the fields each collector declares, because control-d uses `deny_unknown_fields`. The BFF deliberately does **not** pre-enforce the safety bounds. control-d's deterministic gate decides, and the operator sees its real `rule_id`, for example `spec.safety_floor`, `baseline.protected` or `dedup.equivalent_active_watch`.

## The UI

1. **Fleet & Posture** shows the audit-integrity banner, KPI strip and one card per host: liveness, agent version, active bundle version, live-ticking heartbeat freshness, spool, RSS and dropped events (when reported), and open incidents.
2. **Investigations** is a split pane: an incident list on one side and a workspace on the other. The workspace separates **Observed facts** (immutable slices with `observation_id` and a copyable `state_hash`, rendered as structured socket, unit, file and journal tables), **Model hypotheses** (amber, dashed) and **Verified findings** (emerald, with clickable evidence badges that jump to and expand the cited fact). The watch list distinguishes immutable `BASELINE` from bounded `EPHEMERAL` watches, with TTL countdowns and run meters. The workspace also has the guided **ephemeral watch composer**, constrained to the host's collector catalog with live floor hints and the returned PolicyDecision, and the **hypothesis / finding composer**, whose evidence comes from fact checkboxes. Both composers require an explicit, expiring investigation run.
3. **Baselines & Telemetry** has a host and watch filter and a three-state table in which hash swatches are colored from the hash itself, so equal states line up visually. It flags drift, collector errors and "no trusted baseline" (ephemeral). The admin-gated **Promote** drawer asks for an approver, a rationale and an optional change ticket. Below that is an expandable observation table.
4. **Policy Gate & Audit** shows control-d's `VerifyAuditChain` result beside the console's independent recomputation. It has a policy-decision log you can filter by verdict and `rule_id`, and the hash-chained outbox (`seq_no`, `prev_hash → entry_hash`, actor, event type, payload), where a broken entry is highlighted.

## Tests

```sh
node --test console/test/server.test.mjs
```

The suite covers:

1. **UDS framing:** a big-endian length prefix, byte-at-a-time reassembly, oversize and zero-length rejection, and a roundtrip against a mock Unix socket server that splits its replies.
2. **Live integration** against `target/debug/control-d`, skipped if the binary is not built (`cargo build -p control-d`). The test starts control-d in a short temp dir, enrolls a host and mints a token. It then checks `/api/status`, the host, capability, watch, baseline and observation routes, `/api/admin/audit` (including that the console's independent RFC 8785 + SHA-256 chain head **matches Rust's**), policy decisions and enrollment. It also confirms that a cross-origin POST never reaches control-d, that every admin route returns 403 when `--enable-admin` is off, that a bad token surfaces as 403 and an unreachable socket as 503, and that the token never leaks.
3. **Demo walkthrough:** fleet, incidents and three-state drift; `run_required`; an accepted proposal followed by denials under `dedup.equivalent_active_watch`, `baseline.protected` and several `spec.safety_floor` cases; evidence-bound findings; baseline promotion; incident closure that retires ephemeral watches; audit verification; tamper detection and reset.
4. **Security:** CSP, XFO and nosniff on every response class; cross-origin, `null`-origin, cross-site and form-encoded POSTs refused with no state change; Host validation; body limits; static traversal; the loopback default; no `innerHTML` and no inline script or style in the UI.
