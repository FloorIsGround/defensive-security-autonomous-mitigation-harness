# Persistent Operator Agent (Phase 12) — Design Contract

Status: frozen contract for Phase 12 implementation lanes. It depends on the Phase 9 run-progress RPCs and the Phase 10 expectation-rule RPCs.

## Goal

The user wants a persistent agent, for example Codex using a ChatGPT subscription through its OAuth login, that can work with "everything in the centralized portion of the app". It should be able to:

* investigate incidents;
* draft watches, expectation rules and mitigations;
* answer fleet questions;

all without becoming a second authority. The deterministic gates stay authoritative. The agent can **propose** but never approve, activate, sign or execute. A ChatGPT subscription is accessed only through the official Codex CLI login; this project never handles ChatGPT credentials.

## Two supported modes

1. **Interactive.** The operator runs `codex` (or any MCP client) with `mcp-adapter --mode operator` configured as an MCP server, and converses with it.
2. **Autonomous worker.** `python3 -m defsec_reasoner codex-worker` leases triggers like `reasoner-d`. For each trigger it starts a delegated run and launches `codex exec` non-interactively, with an MCP server bound to that run only. It streams Codex's JSONL events into run progress and finishes the run. This is the "wakes on thresholds" persistent agent from the original design, using the ChatGPT-authenticated Codex CLI as its model backend.

## control-d: delegated run tokens (`schema_v7.sql` if storage is needed)

* `ScopedCapability` gains `#[serde(default)] may_spawn_runs: bool`. Admin `MintCapabilityToken` gains `#[serde(default)] may_spawn_runs: bool`, and admin-cli gains `mint-token --allow-run-spawn`. Only `investigator` tokens may carry it.
* New investigation op: `StartDelegatedRun { incident_id, backend_id, model_id, prompt_schema_version, ttl_seconds: Option<u64> }`. It requires `investigator` and `may_spawn_runs`, and the incident must be within the caller's host scope and open.
  * It creates an `agent_runs` row and a **new child token**: investigator role, `run_id`/`incident_id` bound, `allowed_hosts = [incident host]`, collectors ⊆ parent, `may_spawn_runs = false`, expiry ≤ min(parent expiry, now + ttl, now + 3600 s).
  * The parent token is **not** narrowed. Response: `DelegatedRunStarted { run_id, incident_id, expires_at, run_token }`. This is the only RPC that returns a token; it is audited without the token value.
  * Quota: at most 4 active delegated runs per parent principal.
* `CancelInvestigationRun { run_id, reason }` is allowed for the run's own token, and for the parent principal of a delegated run. It sets status `cancelled` and revokes the child token.
* The console uses `StartDelegatedRun` for operator sessions once available, which removes its admin-mint dependency. That is optional in P12.

## mcp-adapter `--mode operator`

* It requires a base token with `may_spawn_runs` (it checks this at startup with a harmless call and fails closed).
* Tools:
  * all read tools: hosts, incidents, watches, capabilities, incident context, observations, baselines, runs, run events, trigger queue, actions, expectation rules;
  * `start_investigation(incident_id, note?)` returns `{run_id, expires_at}`. The **adapter keeps the run token in memory** keyed by `run_id`; it is never shown to the model.
  * run-scoped tools that take `run_id`: `propose_ephemeral_watch`, `record_hypothesis_or_finding`, `propose_expectation_rule`, `propose_action`, `finish_investigation(run_id, summary, status?)`, `cancel_investigation(run_id, reason)`.
* Every run-scoped tool call is auto-reported as a `tool_call`/`tool_result` run event, so the console timeline shows what the agent did.
* `finish_investigation` calls `FinishInvestigationRun` with counts tracked by the adapter.
* There are no admin tools: no approve, revoke, promote, enroll or mint.

## `defsec_reasoner codex-worker` (stdlib Python)

Loop:

1. Lease a trigger.
2. `StartDelegatedRun`.
3. Write the child token to a 0600 temp file in a private 0700 temp dir.
4. Spawn:
   ```
   codex exec --json --ephemeral --skip-git-repo-check --sandbox read-only \
     --ignore-user-config -C <empty private dir> \
     -c 'mcp_servers.defsec.command="<mcp-adapter>"' \
     -c 'mcp_servers.defsec.args=["--investigate-sock","<sock>","--mode","investigator","--token-file","<tmp>"]' \
     [-m MODEL] -
   ```
   The prompt arrives on stdin. It contains the provenance-wrapped compact trigger context (reuse `context.py` and `provenance.py`), the tool rules, and instructions to finish by calling `finish`.
5. Parse JSONL events. Map agent messages to `model_text`, MCP tool calls to `tool_call`/`tool_result`, and turn boundaries to `turn_started`, all clipped. Enforce a wall-clock budget by killing the process group, plus a max event count.
6. Call `FinishInvestigationRun` with status `completed`, or `failed`/`budget_exhausted`, using the last agent message as the summary.
7. Complete the trigger lease, or fail it as retryable or terminal depending on the failure class (Codex binary missing or auth failure means non-retryable plus an alert log; timeout means `budget_exhausted` with the lease completed).
8. Always delete the temp token and dir.

Further rules for the worker:

* The environment passed to Codex is scrubbed to `PATH`, `HOME`, `CODEX_HOME` (if set), `LANG` and `TERM`. Docs recommend a dedicated OS user with its own `CODEX_HOME` that has completed `codex login`.
* `--codex-bin`, `--model`, `--max-wall-seconds`, `--mcp-adapter-bin`, `--socket` and `--lease-owner` are configurable, and the token comes from `DEFSEC_CAPABILITY_TOKEN`, which must have `may_spawn_runs`.
* Tests use a fake `codex` executable (a Python script emitting recorded JSONL and making real MCP calls, or simulated ones) so CI never needs a ChatGPT account. One opt-in live smoke test (`DEFSEC_LIVE_CODEX=1`) is run manually.

## Docs

* `docs/operator-agent.md`: interactive setup (a Codex `config.toml` snippet with `[mcp_servers.defsec]`), autonomous worker setup as a systemd unit, the security boundary (the MCP boundary does not sandbox Codex's own shell tool, so use a read-only sandbox, an empty cwd and a dedicated user), and the ChatGPT entitlement/terms caveat.
