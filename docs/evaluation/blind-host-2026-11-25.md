# Blind-host acceptance · 25 November 2026

The fleet harness enrolled one disposable Ubuntu 24.04.5 VM on a lab hypervisor at
product revision `c6af436`. The agent used mTLS, ran as an unprivileged service
with zero effective capabilities, and enrolled as `defsec-p13-node` with no
role profile or preinstalled baseline watch. Cloud provisioning installed a
local package and inert worker unknown to the controller. A systemd sandbox
masked the socket tables from the agent. All telemetry remained inside the
lab.

The first capability was restricted to one host and package discovery. Its
assessment exposed only the package collector. After an agent restart, the
script obtained a fresh host-scoped capability, advanced discovery, and
queried the resulting package observation by watch ID. The socket read
returned `permission_denied`, which the assessment recorded as an
`incomplete_sample` gap.

The local script inferred a candidate systemd unit using a known fixture
package naming convention. The unit name came from the package inventory.
The test validates the discovery-to-monitoring path under a fixed script.
General workload inference and model performance remain unmeasured.

A preliminary run reached managed watch revision 1 and collected an active
sample. A normal stop unloaded the unit, so systemd D-Bus `GetUnit` yielded
`not_found` and the scenario timed out waiting for an inactive sample. The
final fixture interrupts its own inert worker to keep the unit loaded in a
failed state.

| Check | Final run |
| --- | --- |
| Discovery | Assessment advanced from version 1 to 5 in 16.423 s, measured from the start of the online check through unit selection. |
| Evidence | Socket observation 1 reported `permission_denied`. Package observation 2 was `ok` and contained the fixture package. |
| Delegated monitoring | A pre-grant test was denied. After the operator granted one watch with baseline promotion disabled, the script cited observation 2 to apply revision 1 of the watch for `acceptance-queue.service` in bundle 3. |
| Service transition | Observation 3 was `active`. Observation 4 was `failed`, received by the script 13.611 s after the fixture interruption command returned. |
| Audit and model use | The controller verified 16 audit entries. The script made zero model requests. |
| Teardown | Both runs verified that the disposable VM's configuration, disks and cloud-init seed were gone. The final harness exited 0. Before/after inventory matched, and all six tracked guests stayed running with increased uptime. |

Reproduce with the [blind-host fleet harness](../../deploy/fleet-test/README.md#blind-host-acceptance).
