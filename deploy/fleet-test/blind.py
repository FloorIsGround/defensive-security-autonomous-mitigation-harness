"""Local scripted reasoner for one real, unprofiled fleet guest."""
import datetime as dt
import re
import shlex
import time

from defsec_reasoner.admin_client import AdminClient
from defsec_reasoner.rpc_client import ControlRpcClient
from guests import HOSTS, STATE, UNIT, guest
from scenarios import check, sample, wait_for, write_json


def main():
    host = HOSTS["node"]
    principal = "fleet-local-script"
    packages = "packages.inventory"
    sockets = "sockets.listening"
    unit_state = "systemd.unit_state"
    admin = AdminClient(STATE / "control/admin.sock")

    def client(collectors):
        token = admin.mint_capability_token(
            principal, "investigator", [host], collectors,
        )["token"]
        return ControlRpcClient(STATE / "control/investigate.sock", token)

    def assessment():
        rpc.advance_host_discovery(host)
        return rpc.get_host_assessment(host)["assessment"]

    def pid():
        return guest("node", f"systemctl show -p MainPID --value {UNIT}").stdout.strip()

    rpc = client([packages, sockets, unit_state])
    narrow = client([packages])
    started = time.monotonic()
    metrics = {"reasoner": "local scripted", "external_model_requests": 0}

    def record(**values):
        metrics.update(values)
        write_json("blind.json", metrics)

    online = wait_for("online unprofiled host", lambda: next((
        row for row in rpc.list_hosts() if row["host_id"] == host
        and row["liveness_status"] == "online"
    ), None))
    check(not online.get("host_profile"), "expected no host profile")
    check(not rpc.list_active_watches(host), "expected no initial watches")
    original = rpc.get_host_assessment(host)["assessment"]
    before_restart = narrow.advance_host_discovery(host)
    check(before_restart["bundle_version"], "scoped discovery did not schedule a watch")
    check([entry["collector"] for entry in narrow.get_host_assessment(host)["assessment"]["collectors"]]
          == [packages], "assessment leaked a collector outside token scope")

    old_pid = pid()
    guest("node", f"sudo -n systemctl restart {UNIT}")
    new_pid = pid()
    check(new_pid not in (old_pid, "0", ""), "agent process did not restart")
    rpc = client([packages, sockets, unit_state])
    record(initial_assessment=original["version"], initial_durable_watches=0,
           scoped_discovery_bundle=before_restart["bundle_version"], agent_restarted=True)

    def collected():
        result = assessment()
        return result if all(entry["evidence"] for entry in result["collectors"]) else None

    result = wait_for("live package and socket evidence", collected, timeout=100)
    coverage = {entry["collector"]: entry for entry in result["collectors"]}
    record(assessment=result)
    check(coverage[sockets]["gap"] == "incomplete_sample", "socket visibility gap missing")
    check(coverage[packages]["gap"] is None, "package evidence incomplete")
    evidence = coverage[packages]["evidence"]
    observation = next(row for row in rpc.query_observations(host, evidence["watch_id"])
                       if row["observation_id"] == evidence["observation_id"])
    candidates = [pkg["name"] for pkg in sample(observation)["packages"]
                  if re.fullmatch(r"acceptance-[a-z0-9-]+", pkg["name"])]
    check(len(candidates) == 1, "expected one package in the fixture naming convention")
    unit = candidates[0] + ".service"
    record(selected_unit=unit, discovery_seconds=round(time.monotonic() - started, 3))

    watch = "blind-service"
    spec = {
        "id": watch, "version": 1, "host_id": host, "class": "baseline",
        "collector": {"type": unit_state, "parameters": {"unit": unit, "hash_unit_files": False}},
        "schedule": {"interval_seconds": 15, "timeout_seconds": 5},
        "trigger": {"type": "field_changed", "compare_against": "last_observed",
                    "fields": ["active_state", "sub_state"]},
        "wake_policy": {"cooldown_seconds": 60, "max_wakeups_per_hour": 0},
        "lifecycle": {"enabled": True},
    }
    test = {"operation": "test", "spec": spec}
    check(not rpc.monitoring(host, watch, test)["allowed"], "monitoring allowed without grant")
    grant = admin.call({"admin_op": "set_monitoring_grant", "host_id": host,
                        "principal_id": principal, "max_watches": 1, "allow_promotion": False})
    check(grant["result"]["allowed"], str(grant))
    tested = rpc.monitoring(host, watch, test)
    check(tested["allowed"], str(tested))
    applied = rpc.monitoring(host, watch, {
        "operation": "apply", "spec": spec, "expected_revision": 0,
        "purpose": f"Monitor the service hypothesized from installed package {candidates[0]}",
        "expected_signal": "A change from active to failed after interrupting the disposable worker",
        "evidence": [evidence["observation_id"]],
        "review_at": (dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=1)).isoformat(),
    })
    check(applied.get("revision") == 1, str(applied))
    record(grant_required=True, monitoring=applied)

    def state(wanted, after=0):
        return next(({"observation_id": row["observation_id"], "state": wanted}
                     for row in rpc.query_observations(host, watch)
                     if row["observation_id"] > after and row["status"] == "ok"
                     and sample(row).get("unit") == unit
                     and sample(row).get("active_state") == wanted), None)

    active = wait_for("active service sample", lambda: state("active"))
    fragment = f"/lib/systemd/system/{unit}"
    owner = guest("node", f"dpkg-query -S {shlex.quote(fragment)}").stdout.strip()
    check(owner == f"{candidates[0]}: {fragment}", "selected unit is outside the fixture")
    guest("node", f"sudo -n systemctl kill --kill-whom=main --signal=SIGKILL {shlex.quote(unit)}")
    changed = time.monotonic()
    failed = wait_for("failed service sample", lambda: state("failed", active["observation_id"]))
    audit = admin.verify_audit_chain()
    record(active=active, failed=failed, change_seconds=round(time.monotonic() - changed, 3),
           audit=audit)
    check(audit["valid"], "controller audit chain failed verification")


if __name__ == "__main__":
    main()
