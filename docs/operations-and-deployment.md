# Operations and deployment

This guide describes a local Ubuntu/Debian deployment. Build with `cargo build --release --workspace`; install the resulting binaries under `/usr/local/bin` using your normal package or deployment process. Python 3.12 and Node 24 are needed only for the reasoner and console. Check `--help` for the installed version before deployment.

## Service profiles

The following are starting templates, not universal production limits. Create service accounts and writable state directories first. The agent must be able to traverse the control socket directory and connect to `agent.sock`; align filesystem ownership, `--socket-mode`, and `--agent-uid` with your local access policy. Control defaults to socket mode `0600`. Do not widen admin socket access to solve agent connectivity; use separate socket paths and directory permissions as appropriate.

`/etc/systemd/system/defsec-control.service`:

```ini
[Unit]
Description=DefSecAutMit control
After=local-fs.target
[Service]
User=defsec-control
Group=defsec-control
ExecStart=/usr/local/bin/control-d --data-dir /var/lib/defsecautmit/control
StateDirectory=defsecautmit/control
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
Restart=on-failure
[Install]
WantedBy=multi-user.target
```

`/etc/systemd/system/defsec-agent.service` (replace the public key and arrange socket access):

```ini
[Unit]
Description=DefSecAutMit agent
After=defsec-control.service
[Service]
User=defsec-agent
Group=defsec-agent
SupplementaryGroups=systemd-journal
ExecStart=/usr/local/bin/agent-d --host-id edge-01 --state-dir /var/lib/defsecautmit/agent --control-sock /var/lib/defsecautmit/control/agent.sock --control-key-id control-key-01 --control-pub-hex REPLACE_WITH_PUBLIC_KEY_HEX
StateDirectory=defsecautmit/agent
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
MemoryHigh=16M
MemoryMax=24M
CPUQuota=5%
Restart=on-failure
[Install]
WantedBy=multi-user.target
```

Measure peak memory and throttling under representative journal, D-Bus and spool loads; restrictive limits can interrupt monitoring. `SupplementaryGroups` grants journal access only where local journal permissions allow it. Start with `systemctl daemon-reload` and enable the services after provisioning.

## Enrollment and watches

For a first local test as the same user, start `control-d --data-dir ./run-data`, then:

```sh
./target/release/admin-cli --admin-sock ./run-data/admin.sock enroll edge-01
./target/release/agent-d --host-id edge-01 --state-dir ./run-agent \
  --control-sock ./run-data/agent.sock --control-key-id control-key-01 \
  --control-pub-hex CONTROL_PUBLIC_KEY_HEX
```

Use the returned public key in place of `CONTROL_PUBLIC_KEY_HEX`. Enrollment and peer UID permissions are separate controls. Do not use a production control key or state directory for a disposable test.

## Multi-host mTLS transport and PKI

For remote edge hosts, `agent-d` initiates an outbound TLS 1.3 mTLS connection to `control-d` (zero inbound ports on edge hosts). Each host certificate embeds a `spiffe://defsecautmit/host/<host_id>` URI SAN, and `control-d` rejects any `Register` frame whose `host_id` does not match the peer certificate. TLS session resumption is disabled so serial revocations take effect immediately on the next connection without restarting `control-d`.

Issue an internal ECDSA P-256 CA, control server certificate, and host client certificate with `admin-cli pki` (private keys are written with mode `0600`):

```sh
admin-cli pki init-ca --out-dir ./pki --common-name "defsec-internal-ca"
admin-cli pki issue-server --ca-cert ./pki/ca.crt --ca-key ./pki/ca.key \
  --out-dir ./pki --common-name "control.internal" --dns control.internal --ip 10.0.0.10
admin-cli pki issue-host edge-01 --ca-cert ./pki/ca.crt --ca-key ./pki/ca.key --out-dir ./pki
```

Start `control-d` with the optional mTLS listener and off-host heartbeat liveness watchdog (default `--liveness-grace-seconds 90` marks silent hosts `offline`, opens a single `high`-priority liveness incident per host, and records `host_liveness_offline` in the hash-chained audit log):

```sh
control-d --data-dir ./run-data \
  --agent-mtls-addr 0.0.0.0:7443 \
  --tls-ca-cert ./pki/ca.crt \
  --tls-server-cert ./pki/server.crt \
  --tls-server-key ./pki/server.key \
  --tls-revoked-file ./pki/revoked_serials.json \
  --liveness-grace-seconds 90
```

Start `agent-d` pointing at the mTLS listener:

```sh
agent-d --host-id edge-01 --state-dir ./run-agent \
  --control-mtls-addr control.internal:7443 \
  --tls-server-name control.internal \
  --tls-ca-cert ./pki/ca.crt \
  --tls-client-cert ./pki/edge-01.crt \
  --tls-client-key ./pki/edge-01.key \
  --control-key-id control-key-01 \
  --control-pub-hex CONTROL_PUBLIC_KEY_HEX
```

To revoke a compromised host certificate immediately for new connections:

```sh
admin-cli pki revoke <SERIAL_HEX> --revoked-file ./pki/revoked_serials.json --reason "host decommissioned"
```

A baseline watch file has this shape. Collector parameters are a closed schema; replace the `collector` object with one of the examples below and use a unique `id` per watch. Check local policy floors and choose paths and units appropriate to the host.

```json
{
  "id": "baseline-sockets", "version": 1, "host_id": "edge-01", "class": "baseline",
  "collector": {"type": "sockets.listening", "parameters": {"include_tcp": true, "include_udp": true, "include_ipv6": true, "resolve_process": true}},
  "schedule": {"interval_seconds": 300, "timeout_seconds": 30},
  "trigger": {"type": "collector_stale_or_error", "max_stale_seconds": 900, "consecutive_errors": 3},
  "wake_policy": {"cooldown_seconds": 300, "max_wakeups_per_hour": 4},
  "lifecycle": {"enabled": true}
}
```

Other collector objects:

```json
{"type":"systemd.unit_state","parameters":{"unit":"sshd.service","hash_unit_files":true}}
```

```json
{"type":"files.metadata","parameters":{"paths":["/etc/ssh/sshd_config"],"compute_hash":true,"max_file_bytes":1048576}}
```

```json
{"type":"journal.unit_events","parameters":{"unit":"sshd.service","min_priority":6,"max_events_per_batch":100,"max_message_bytes":512}}
```

```json
{"type":"connections.outbound","parameters":{"include_tcp":true,"include_udp":true,"include_ipv6":true,"resolve_process":true,"exclude_loopback":true,"max_flows":256}}
```

```json
{"type":"packages.inventory","parameters":{"max_packages":4096}}
```

Apply and manage with the admin socket; use IDs returned by the system:

```sh
admin-cli --admin-sock ./run-data/admin.sock apply-watch watch.json --actor ops --rationale 'initial monitoring'
admin-cli --admin-sock ./run-data/admin.sock promote-baseline edge-01 WATCH_ID OBSERVATION_ID --approver ops --rationale 'approved change' --ticket-ref CHANGE-123
admin-cli --admin-sock ./run-data/admin.sock mint-token investigator-01 --role investigator --host edge-01 --collector sockets.listening --collector systemd.unit_state --collector files.metadata --collector journal.unit_events --ttl-seconds 3600
admin-cli --admin-sock ./run-data/admin.sock verify-audit
admin-cli --admin-sock ./run-data/admin.sock close-incident INCIDENT_ID --actor ops --resolution 'investigation complete'
```

Store tokens securely; token output is sensitive. Scope hosts, collectors and incident as narrowly as needed. Use `list-hosts` and `list-incidents` for discovery. Audit verification checks the stored chain; retain an external checkpoint if you need to detect ledger replacement or truncation.

## Host profiles and additional collectors

Two zero-root snapshot collectors extend the baseline view on Ubuntu/Debian hosts:

- `connections.outbound` groups `/proc/net/{tcp,tcp6,udp,udp6}` rows by remote endpoint (`<proto>:<remote_addr>:<remote_port>:<uid>:<comm or '?'>`). Listening sockets, TCP `TIME_WAIT`/`CLOSE`, unconnected (zero-address) remotes and — by default — loopback remotes are excluded as noise. More flow groups than the cap (default 256, hard max 1024, local ceiling 512) produce an explicit `partial` observation carrying `truncated: true` and the omitted count. Unprivileged agents report process attribution explicitly as `partial`/`none`, exactly like `sockets.listening`.
- `packages.inventory` parses `/var/lib/dpkg/status` (32 MiB hard read cap; over-cap files are explicit errors, never partial parses) and reports installed packages as `<name>:<arch>` entries with the file's SHA-256. Malformed stanzas are skipped and counted. More packages than the cap (default 4096, hard max 16384, local ceiling 16384) produce an explicit `partial` observation with the omitted count.

Both collectors are part of the default allowlist and honor the same interval, timeout and ephemeral bounds as the original four.

`agent-d --profile <PATH>` optionally applies an admin-owned host profile at startup. The profile is local configuration, never part of a signed bundle, and can only tighten the built-in edge safety floor: collector caps take `min(builtin, profile)`, and `enabled_collectors` intersects the built-in allowlist. `approved_file_roots` is the one additive field — profile roots beneath a denied prefix (for example `/etc/shadow`, `/root`, `/home/x`) or the filesystem root itself are rejected at load. Bundles containing a watch whose collector the profile disabled are rejected with an explicit reason through the normal bundle acknowledgment path.

Example profile:

```json
{
  "schema_version": 1,
  "host_tags": ["prod", "dc:eu-west-1"],
  "expected_services": ["sshd.service", "nginx.service"],
  "approved_file_roots": ["/etc/myapp"],
  "enabled_collectors": ["sockets.listening", "connections.outbound", "packages.inventory"],
  "collector_caps": { "max_outbound_flows": 128, "max_packages": 2048, "max_file_hash_bytes": 1048576 }
}
```

`host_tags` must match `^[a-z0-9][a-z0-9:._-]{0,63}$` (at most 16); `expected_services` are validated systemd unit names (at most 64); `approved_file_roots` holds at most 32 normalized absolute paths. Load-time safety follows sshd's `StrictModes`: the agent refuses to start when the profile file is group- or world-writable, owned by anyone other than root or the agent's own user, larger than 64 KiB, or fails validation. The applied summary (tags, expected services, effective collectors) is reported to the control plane on registration; the control plane treats it as informational.

## Interactive clients and reasoner

Configure an MCP client to launch `mcp-adapter --investigate-sock ./run-data/investigate.sock --mode read-only --token-file TOKEN_FILE`. Use `--mode investigator` with a suitably scoped investigator token for investigation mutations. The adapter communicates over stdio; avoid printing tokens in process arguments. The console can be tried without daemons with `node console/server.mjs --demo`. For live operation:

```sh
node console/server.mjs --investigate-sock ./run-data/investigate.sock --token-file TOKEN_FILE
```

Add `--enable-admin --admin-sock ./run-data/admin.sock` only for a trusted local operator session. The default listener is loopback. See [console/README.md](../console/README.md) for options and security boundaries.

Set `DEFSEC_CAPABILITY_TOKEN` in the worker's protected environment, then run:

```sh
PYTHONPATH=reasoner python3 -m defsec_reasoner worker --socket ./run-data/investigate.sock --backend openai --base-url http://localhost:11434/v1 --model MODEL_NAME
```

The OpenAI-compatible backend supports compatible OpenAI, Ollama and vLLM endpoints; configure provider credentials via `DEFSEC_OPENAI_API_KEY` or `OPENAI_API_KEY` as appropriate. For Anthropic use `--backend anthropic --model MODEL_NAME` and `DEFSEC_ANTHROPIC_API_KEY` or `ANTHROPIC_API_KEY`. The OpenAI-compatible adapter preserves `reasoning_content` for thinking-model messages. See [reasoner/README.md](../reasoner/README.md) for budgets and provider details.

## Mitigation

Generate a separate operator key and protect the resulting private key file:

```sh
admin-cli generate-operator-key --key-id operator-01 --out operator-key.hex
```

Configure control with `--operator-key-id` and `--operator-pub-hex` from the generated key's public output. List and inspect actions with `list-actions` and `get-action INTENT_ID`; approve an eligible action using `approve-action INTENT_ID --approver ops --operator-key-file operator-key.hex --operator-key-id operator-01`. Transfer the authorized intent to the target executor through a trusted operational channel. The executor is single-shot:

```sh
action-exec-d --host-id edge-01 --state-dir /var/lib/defsecautmit/action-exec \
  --control-key-id control-key-01 --control-pub-hex CONTROL_PUBLIC_KEY_HEX \
  --operator-key-id operator-01 --operator-pub-hex OPERATOR_PUBLIC_KEY_HEX \
  --mode dry-run --intent-file intent.json
```

Capture the JSON receipt and submit it with `admin-cli record-receipt RECEIPT_JSON_FILE`. `--mode enforce` invokes real fixed drivers and can affect availability. Autonomous containment requires `--enable-autonomous-containment` on both control and executor in addition to applicable policy; leave it off unless deliberately enabled. Test expiry, rollback and recovery with the intended environment and privileges first.
