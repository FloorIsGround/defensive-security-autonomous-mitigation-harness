# Phase 18 Proxmox acceptance · 25 November 2026

The trial ran the merged blind fleet harness at product revision `d69eea7`
on a lab hypervisor. It used the harness lock, ownership markers and teardown path.
The only disposable guest was a Proxmox VM, running Ubuntu
24.04.5. The only action target was `acceptance-queue.service`, a package-owned
fixture that runs `/usr/bin/sleep infinity`. The trial used pinned SSH and
local mTLS. There were zero external model requests and no network or
isolation action intents.

The first attempt discovered the fixture in 14.825 s. The scenario stopped
before dispatch because control-d rejected overlapping service watches.
The second attempt used the single granted `blind-service` watch for both
the fixture incident and independent verification. The temporary reference
unit used an ordering dependency to retain the fixture in systemd after
stop.

## Live result

Package observation 2 identified the fixture in 7.698 s and supported applying
watch revision 1 in bundle 3. Setup observation 4 showed the unit loaded and
inactive. Starting it again yielded the active precondition in observation 5.

| Check | Evidence |
| --- | --- |
| Authorization | Proposal 1 required dual signatures. The controller and the run-local operator key signed intent `dc03cab1-8979-4d68-88c0-345043aed15c` for the typed `systemd_stop_unit` verb with a 110 s authorization TTL. |
| Real stop | `action-exec-d --mode enforce` returned `executed` at 18:04:17.702 UTC and reported `inactive` with recovery handle `systemctl:start:acceptance-queue.service`. A separate SSH read showed `loaded/inactive/dead` and PID 0. |
| Independent verification | Control-d acknowledged receipt 1. `get-action-verification` cited active observation 5 and inactive observation 6, marking receipt 1 `verified` 10.521 s after dispatch began. Observation 6 hash was `aa69e2db3ca1c6f4045b5f36dd5bbd44a295d4e48c41f62d6f8f56092016b098`. |
| Recovery | A 50 s guest-local timer bounded the stop. The operator-side harness started the fixture as soon as verification completed. SSH showed `loaded/active/running`, with PID 2526 replacing PID 1957. Observation 7 confirmed `active` 16.348 s after the start command was initiated. The operator reconciled receipt 1 with `observation:7` at 18:04:44.244 UTC. Recovery used systemd directly, so this trial has no executor rollback receipt. |
| Audit | Control-d verified all 24 audit entries. |

## Simulations

On the same guest, the signed intent first ran through the typed executor's
dry-run mode with a separate replay store. The `dry_run_simulated` receipt
reported no host effect. Direct systemd checks showed the same active PID
1957 before and after. This simulation receipt stayed outside the control-d
ledger so the real dispatch could use its authorized intent.

The local `independent_service_observations_verify_receipts_and_recovery`
integration test passed. It simulated a success receipt followed by an
`active` sample and verified that control-d reported `contradicted`. A
temporary extension simulated an unavailable service sample using a timeout
status. The receipt check stayed `awaiting_evidence`. Moving the test-only
evidence deadline into the past yielded `indeterminate` with reason
`Evidence deadline elapsed` and an empty observation citation. These
controller cases used synthetic receipts and observations.

## Teardown

Both runs verified removal of the disposable VM's configuration, imported disk,
cloud-init disk and run-owned snippet. The final scenario and both teardown
checks exited 0. The before/after inventory matched by guest identity, placement
and state. All six pre-existing guests were running
in both snapshots, with each uptime advancing by 220 s on the final run.
