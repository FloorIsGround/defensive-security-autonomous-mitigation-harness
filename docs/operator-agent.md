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

## Autonomous worker (stub)

The `defsec_reasoner codex-worker` command and its systemd unit are reserved for a later implementation. See the [worker design](design/operator-agent.md#defsec_reasoner-codex-worker-stdlib-python).
