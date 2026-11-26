# Phase 13 fleet validation

Copy the example configuration and replace its documentation values with the
settings for your disposable Proxmox lab.

```bash
cp deploy/fleet-test/lab.example.env deploy/fleet-test/lab.local.env
deploy/fleet-test/bootstrap.sh
```

The harness loads `lab.local.env` from this directory. Set `DEFSEC_FLEET_CONFIG`
to use another Bash configuration file. Exported settings take precedence over
file values. You can also supply all required settings through the environment.

| Setting | Value |
| --- | --- |
| `PVE_SSH` | SSH destination in `user@host` form, for example `root@pve.example.invalid`. The account needs permission to manage the disposable guests and their storage. |
| `PVE_SSH_KEY` | Optional path to the Proxmox SSH identity. When empty, SSH uses the workstation's SSH configuration and agent. |
| `PVE_NODE` | Expected short hostname on the Proxmox side of the SSH connection. |
| `PVE_STORAGE` | File-backed Proxmox storage ID supporting images, ISO files and snippets. Cache `noble-server-cloudimg-amd64.img` in its ISO content directory. |
| `PVE_BRIDGE` | Proxmox bridge connecting the guests to the test subnet. The guests use DHCP. |
| `FLEET_CIDR` | IPv4 subnet used for guest discovery, for example `198.51.100.0/24`. |
| `FLEET_LAN` | Workstation IPv4 address on that subnet. Guests must be able to reach its mTLS listener on TCP port 17443. |
| `PVE_VMID_MIN` and `PVE_VMID_MAX` | Inclusive range reserved for this harness. The whole range must be free across the cluster before provisioning. Fleet mode takes the first three IDs. Blind mode takes only the first. |
| `DEFSEC_FLEET_OUT_DIR` | Optional results root. The default is `${XDG_STATE_HOME:-$HOME/.local/state}/defsec-fleet-test/results`. |

The Proxmox SSH host key must already be trusted in the workstation's SSH
known hosts. Both SSH paths run in batch mode with strict host-key checking.
The harness generates a private guest login key and pins each guest's distinct
host key for the run.

Install Python, Node, and the standard OpenSSH utilities on the workstation and
cache the Cargo dependencies for an offline build. The default benchmark is
scripted. To include live Reflection inference on disposable guest telemetry,
set `DEFSEC_FLEET_LIVE_BEAM=1` and supply `REFLECTION_API_KEY` in the
workstation environment.

Bootstrap creates private PKI and ledger state in a temporary directory.
The service profiles are applied through admin-cli and watch schedules are
shortened to 15 seconds. The console and MCP smokes share a read-only
capability. The worker runs with proposals disabled. The adaptive synthetic
benchmark can submit one ephemeral observation watch for comparison with the
static arm.

Each run creates a private subdirectory of the results root using UTC date and
time. Pass an unused directory as the first argument to select a destination.
Keep the logs and results outside the checkout since they can contain lab
details. Bootstrap exits nonzero on scenario or teardown failure. Before
stopping or destroying a VM, it verifies the VMID, name, tag, and current run's
ownership marker. If teardown fails, bootstrap prints a retry command. Use the
retained run state and the same lab settings for the retry.

## Blind-host acceptance

```bash
FLEET_BLIND=1 deploy/fleet-test/bootstrap.sh
```

This mode uses the same exclusive lock, ownership checks and teardown. It
creates one guest with a neutral hostname and without a host profile or
operator-installed baseline. The guest installer seeds a disposable package
and service and hides `/proc/self/net` from the agent service. The local
scripted reasoner reads fresh discovery evidence over the scoped investigation
socket, infers a candidate unit from the fixture package naming convention,
and requests one persistent state watch under a host-specific operator grant.
The scenario interrupts the disposable worker after the first active sample
and checks for a failed unit state.

Review `blind.json`, `exit-status.txt`, `teardown-status.txt`, and the
before/after inventory. Both status files must report zero exit status.
The blind scenario uses only local sockets and pinned SSH, with no model
provider calls.
