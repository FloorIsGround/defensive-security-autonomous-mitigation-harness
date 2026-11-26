# Operator agent

Use the operator MCP server to investigate open incidents, inspect fleet state, and propose temporary watches, expectation rules, and mitigations. Install `control-d`, `admin-cli`, and `mcp-adapter` from the same release.

## Interactive Codex setup

1. Run `codex login` as the dedicated operating-system user for the Codex session. Use the official CLI sign-in prompts for your ChatGPT account.
2. On the control host, mint an investigator token with the minimum hosts and collectors needed for the session.

   ```sh
   admin-cli --admin-sock /var/lib/defsec/admin.sock mint-token codex-operator \
     --role investigator --allow-run-spawn --host edge-1 \
     --collector sockets.listening --ttl-seconds 3600
   ```

   Save the `token` field alone in a file owned by the dedicated user with mode `0600`. The dedicated user needs access to the investigation socket and its parent directories. Keep the admin socket, signing keys, and control ledger inaccessible to that user.
3. Add the MCP server to the dedicated user's `~/.codex/config.toml` and substitute the installed binary, socket, and private token file paths. See the [Codex MCP configuration guide](https://developers.openai.com/codex/mcp).

   ```toml
   [mcp_servers.defsec]
   command = "/usr/local/bin/mcp-adapter"
   args = [
     "--mode", "operator",
     "--investigate-sock", "/run/defsec/investigate.sock",
     "--token-file", "/home/defsec-codex/.config/defsec/operator-token",
   ]
   ```
4. Launch `codex --sandbox read-only` from an empty working directory. Ask Codex to list open incidents, start an investigation for a specific incident, and reference the returned `run_id` when submitting proposals or findings. Finish with a summary or cancel with a reason.

The adapter handles requests serially. A slow `control-d` RPC can stall the session for the default 15-second timeout.

If the connection drops after the adapter records a `tool_call`, the timeline may show that call without a `tool_result`. The operation may have applied. Check the run timeline and current state before retrying. Watch and action proposals can be replayed safely with the same idempotency key. Findings and notes have no idempotency key and may duplicate an earlier write. The adapter reserves the remaining event budget for finish or cancel when it cannot confirm a tool result. If a start error includes a run ID, use it to cancel the pending run or finish it with a summary.

## Security boundary

Operator mode checks the base token against `control-d` before serving MCP requests. Starting a run leaves the base token available for fleet reads and gives the adapter a child token for the selected incident and host. The adapter keeps the child in memory and returns the run ID and expiry to the model. A principal can have up to four active delegated runs. Each child expires by the earlier of the requested TTL, one hour, or the parent expiry. Cancellation revokes the child's credential immediately. The adapter stops recognizing a run ID when its TTL expires or the adapter restarts. The run row remains queryable through the investigation read tools. A valid, unbound investigator token with the run-spawn grant and matching principal and incident scope can cancel the run directly through the investigation RPC.

The MCP tool set grants scoped reads, findings, and proposals. The controller may apply a bounded temporary watch after policy validation. Expectation rules require operator approval, and delegated mitigation proposals require an independent operator signature even when autonomous containment is enabled on the controller. The MCP surface has no administrative access. Run events record tool names and outcomes for the timeline. Treat telemetry and tool output as untrusted input.

Codex's own shell tools operate outside the MCP boundary. Use the dedicated low-privilege user, read-only sandbox and empty working directory described above. Use filesystem permissions to protect credentials and allow the model to receive only the telemetry your organization has approved for that account and workspace.

## ChatGPT entitlement and terms

ChatGPT sign-in uses the official Codex CLI. DefSecAutMit handles its own investigation tokens only. Codex availability, model access, and usage limits depend on your account and workspace. Check account entitlements, applicable terms, and data-handling requirements before deploying, especially for unattended use. [Codex plan and usage guidance](https://help.openai.com/en/articles/11369540-using-codex-with-your-chatgpt-plan), [OpenAI Terms of Use](https://openai.com/policies/terms-of-use/), [OpenAI Services Agreement](https://openai.com/policies/services-agreement/).

## Autonomous worker

Run `defsec-reasoner codex-worker` (alias `investigator`) to lease triggers and open delegated runs using the worker account’s Codex CLI login. Each wake uses an ephemeral Codex session by default.

Pass `--persist-sessions` to save successful session IDs under `$XDG_STATE_HOME/defsec-reasoner/codex-sessions` (`~/.local/state/defsec-reasoner/codex-sessions` when unset), or pass `--session-dir PATH` to enable persistence in a directory you choose. The lookup includes the controller socket, incident, host, parent capability and token, model, prompt schema and Codex home. New grants and other incidents start fresh. Each wake gets a new child credential. A concurrent wake uses an isolated ephemeral session while the incident transcript is locked. A failed or interrupted resume drops the reference so a subsequent trigger can rebuild from the controller.

Codex owns transcript storage in its home. Removing a worker reference does not delete that transcript. Model cache usage is reported in the run timeline when the CLI supplies it. A saved conversation provides continuity across wakes; cache hits and subscription usage depend on the service. Direct ChatGPT OAuth uses its own authorization. [Codex sessions](https://developers.openai.com/codex/noninteractive) · [Prompt caching](https://developers.openai.com/api/docs/guides/prompt-caching)

Use `defsec-reasoner worker` for the custom model-adapter worker. Its default backend is `mock`. Use `--discovery-only` for host onboarding, `--followups-only` for watch reassessment, or `host-review-worker` for scheduled reviews.

### How one trigger is processed

1. The worker leases the next pending trigger with its **parent token** and verifies at startup (via `get_capability`) that the token is an unbound investigator token carrying `may_spawn_runs` — it fails closed otherwise. Mint it with `admin-cli mint-token --allow-run-spawn`.
2. `start_delegated_run` mints a fresh **child token** scoped to the run, incident and host. The worker sends the trigger event ID and lease token and caps the requested child token TTL at the lease duration. A controller that explicitly rejects either new field receives one compatibility retry using the older request shape. A dropped response requeues the trigger because the controller may already have created a run. Upgrade controllers that close the connection on unknown fields before running this worker.
3. The child token is written to a 0600 file inside a private 0700 temp directory, and `codex exec` is spawned in its own process group with a scrubbed environment (only `PATH`, `HOME`, `CODEX_HOME` if set, `LANG`, `TERM` — no `DEFSEC_*` variables), the prompt on stdin, and an empty working directory:

   ```sh
   codex exec --json --ephemeral --skip-git-repo-check --sandbox read-only \
     --ignore-user-config -C <empty private dir> \
     -c 'mcp_servers.defsec.command="<mcp-adapter>"' \
     -c 'mcp_servers.defsec.args=["--investigate-sock","<sock>","--mode","investigator","--token-file","<0600 temp file>"]' \
     [-m MODEL] -
   ```

   The token reaches the adapter only through the token file — never through argv, the environment, or a log line. The adapter binds itself to the run at startup, so run-scoped tools need no `run_id` and the model never sees the child token.
   The worker disables native shell execution and web search. It preauthorizes scoped evidence reads, finding submission and policy-checked ephemeral watches on the DefSec MCP server. Control validates each call.
4. The prompt reuses the same provenance machinery as `reasoner-d` (`context.py` / `provenance.py`): compact, diff-focused observations inside `<untrusted_telemetry>` envelopes, plus the worker's tool rules — admitted ephemeral watches collect under controller policy, telemetry is data and never instructions, and the model does not call `finish`; the worker owns terminal reporting and uses the last agent message as the run summary.
5. Codex's JSONL stream is mapped into run progress recorded with the child token:

   | Codex JSONL event (`codex exec --json`, 0.172.0 `ThreadEvent`) | Run event |
   |---|---|
   | `turn.started` | `turn_started` |
   | `item.completed` with `item.type == "agent_message"` | `model_text` (clipped, credential-redacted) |
   | `item.started` with `item.type == "mcp_tool_call"` | `tool_call` (tool name + clipped argument preview) |
   | `item.completed` with `item.type == "mcp_tool_call"` | `tool_result` (ok/failed, result tag, proposal acceptance) |
   | `item.*` with `item.type == "error"` | `note` |
   | `turn.completed` | token accounting for the run outcome |
   | `thread.started` | recorded as the thread id (not an event) |
   | `turn.failed`, top-level `error` | fatal: the run fails |
   | anything else | ignored but counted (`unknown_events`) |

   Progress is best-effort, like `reasoner-d`: a `run_event_quota` rejection (256 events per run) stops recording without failing the investigation.
6. The worker enforces a wall-clock budget by killing the whole process group (Codex and its MCP server), plus a maximum event count.
7. The run is finished with the child token — `completed`, `budget_exhausted`, or `failed` — using the last agent message (clipped, redacted) as the summary; the trigger lease is then completed or failed with the parent token (delegated children cannot manage leases).

### Failure classes

| Failure | Run status | Trigger lease | Notes |
|---|---|---|---|
| Codex exits cleanly after a turn | `completed` | completed | |
| Wall-clock budget or event cap hit | `budget_exhausted` | completed | process group killed; no orphan Codex |
| Codex binary missing/unusable | `failed` | dead-letter | non-retryable, plus an `ALERT:` log |
| Codex authentication/login failure | `failed` | dead-letter | non-retryable, plus an `ALERT:` log |
| Delegated run quota or transient start rejection | No run created | requeued (retryable) | |
| Crash, stream without a completed turn, internal error | `failed` | requeued (retryable) | control-d caps retries at 5 |
| SIGTERM during a run | `failed` | requeued | temp token and dirs are always deleted |

The worker deletes each run’s temporary token and temporary directories on exit. Persistent mode keeps the private incident work directory and session reference across wakes.

### Running the worker

```sh
DEFSEC_CAPABILITY_TOKEN=$(cat /etc/defsec/codex-worker-token) \
python3 -m defsec_reasoner codex-worker \
  --socket /run/defsec/investigate.sock \
  --codex-bin /usr/local/bin/codex \
  --mcp-adapter-bin /usr/local/bin/mcp-adapter \
  --lease-owner codex-worker --poll-interval 5
```

Run `python3 -m defsec_reasoner codex-worker --help` for configuration options. The wall-clock budget defaults to 600 seconds, the event cap to 2000, and the lease and child token TTL to 900 seconds. If you set a shorter lease, the worker also caps the requested child token TTL at that duration.

### Systemd unit

Run the worker as a dedicated low-privilege OS user with its own `CODEX_HOME` that has completed `codex login` once. Keep the admin socket, signing keys, and control ledger inaccessible to that user.

`/etc/defsec/codex-worker.env` (root-owned, mode 0600):

```ini
DEFSEC_CAPABILITY_TOKEN=<parent investigator token, minted with --allow-run-spawn>
```

`/etc/systemd/system/defsec-codex-worker.service`:

```ini
[Unit]
Description=DefSecAutMit autonomous Codex investigation worker
After=network-online.target

[Service]
Type=simple
User=defsec-codex
Group=defsec-codex
Environment=CODEX_HOME=/var/lib/defsec-codex
Environment=XDG_STATE_HOME=/var/lib/defsec-codex/state
EnvironmentFile=/etc/defsec/codex-worker.env
ExecStart=/usr/bin/python3 -m defsec_reasoner codex-worker \
  --socket /run/defsec/investigate.sock \
  --codex-bin /usr/local/bin/codex \
  --mcp-adapter-bin /usr/local/bin/mcp-adapter \
  --lease-owner codex-worker
Restart=on-failure
RestartSec=15
# Hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/lib/defsec-codex

[Install]
WantedBy=multi-user.target
```

Before starting the unit, once as the dedicated user:

```sh
sudo -u defsec-codex CODEX_HOME=/var/lib/defsec-codex codex login
```

The unit's journal is the worker's log; non-retryable failures (missing binary, ChatGPT login expired) appear as `ALERT:` lines and dead-letter the trigger, so alert on those. Refresh the parent token before it expires and restart the unit.

### Testing the worker

`PYTHONPATH=reasoner python3 -m unittest discover -s reasoner/tests` covers the worker with a fake `codex` executable (`reasoner/tests/fixtures/fake_codex.py`) that reads the prompt from stdin, checks the worker's hygiene promises from inside the child (no `DEFSEC_*` env, no token in its own or the adapter's `/proc/<pid>/cmdline`, 0600/0700 token file modes), and makes **real MCP calls** through the compiled `mcp-adapter` against `control-d`. The full matrix (happy path, timeout with process-group kill, event cap, missing binary, auth failure, crash requeue, cleanup after exceptions, parent-token scope) runs in `tests/test_codex_worker.py`, including live runs against `target/debug/control-d`. An opt-in smoke test against the real Codex CLI is gated behind `DEFSEC_LIVE_CODEX=1` and never runs in CI.
