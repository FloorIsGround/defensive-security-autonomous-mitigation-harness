"""Run bounded fleet scenarios through the deployed agent and public sockets."""
import datetime as dt
import json
import os
import re
import shlex
import sqlite3
import subprocess
import sys
import time
import urllib.request

from defsec_reasoner.admin_client import AdminClient
from defsec_reasoner.rpc_client import ControlRpcClient
from guests import BIN, HOSTS, LAN, PORT, RESULTS, STATE, UNIT, guest, run
from measure import footprint

COLLECTORS = [
    "sockets.listening", "connections.outbound", "packages.inventory",
    "files.metadata", "journal.unit_events", "systemd.unit_state",
]
GRACE = int(os.environ["FLEET_GRACE"])
SSH_CONFIG = "/etc/ssh/sshd_config"


def utc():
    return dt.datetime.now(dt.timezone.utc)


def seconds(end, start):
    return round((dt.datetime.fromisoformat(end) - dt.datetime.fromisoformat(start)).total_seconds(), 3)


def wait_for(description, predicate, timeout=48):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(0.8)
    raise AssertionError(f"Timed out after {timeout}s waiting for {description}")


def check(condition, message):
    if not condition:
        raise AssertionError(message)


def write_json(filename, value):
    (RESULTS / filename).write_text(json.dumps(value, indent=2) + "\n")


def sample(observation):
    return observation["payload"].get("data", {})


class Fleet:
    def __init__(self):
        self.admin = AdminClient(STATE / "control/admin.sock")
        self.token = self.admin.mint_capability_token(
            "fleet-p13-observer", "observer", list(HOSTS.values()), COLLECTORS,
        )["token"]
        self.rpc = ControlRpcClient(STATE / "control/investigate.sock", self.token)
        self.scenarios = {}
        self.row = {}
        self.watches = {}

    def cli(self, *args):
        res = run([str(BIN / "admin-cli"), "--admin-sock",
                   str(STATE / "control/admin.sock"), *args])
        value = json.loads(res.stdout)
        check(value.get("admin_result") != "error", str(value))
        return value

    def execute(self, name, test):
        self.row = {"status": "pass"}
        self.scenarios[name] = self.row
        print(f"Running {name}", flush=True)
        try:
            test()
        except subprocess.CalledProcessError as exc:
            self.row.update(status="fail", error=f"exit {exc.returncode}: {exc.stderr}")
        except Exception as exc:
            self.row.update(status="fail", error=f"{type(exc).__name__}: {exc}")
        finally:
            print(f"{name}: {self.row['status']} {self.row.get('error', '')}", flush=True)
            write_json("scenarios.json", self.scenarios)

    def action(self, role, command, **kwargs):
        self.row["action_at"] = utc().isoformat()
        return guest(role, command, **kwargs)

    def setup(self):
        def online_hosts():
            ready = [x for x in self.rpc.list_hosts(tag="defsec-p13")
                     if x["liveness_status"] == "online" and x.get("host_profile")]
            return ready if len(ready) == len(HOSTS) else None

        hosts = wait_for(
            "all three agents online with reported role profiles",
            online_hosts,
        )
        self.row["hosts"] = hosts
        for role in HOSTS:
            host = HOSTS[role]
            for spec in self.rpc.list_active_watches(host):
                collector = spec["collector"]["type"]
                self.watches[role, collector] = spec
                # Role defaults go up to 900s. Keep the same role watch IDs
                # and predicates, with an explicit fleet-only interval.
                spec["version"] += 1
                spec["schedule"]["interval_seconds"] = 15
                self.row.setdefault("watch_revisions", []).append(
                    self.admin.apply_baseline_watch(spec, "fleet-p13", "bounded fleet test interval"))
        check(len(self.watches) == 12, f"expected 12 role watches, got {len(self.watches)}")
        for role, collector in self.watches:
            if collector == "journal.unit_events":
                continue
            wait_for(f"initial {role} {collector} sample",
                     lambda: next((x for x in self.observations(role, collector)
                                   if x["status"] in ("ok", "partial")), None))
        self.row["footprint_before"] = footprint()

    def observations(self, role, collector):
        spec = self.watches[role, collector]
        return [row for row in self.rpc.query_observations(
            HOSTS[role], watch_id=spec["id"], limit=4
        ) if row["spec_version"] == spec["version"]]

    def latest_id(self, role, collector):
        return max((x["observation_id"] for x in self.observations(role, collector)), default=0)

    def observe(self, role, collector, baseline, match, *, select=lambda obs: obs):
        def search():
            observations = self.observations(role, collector)
            if observations:
                self.row["last_sample"] = select(observations[0])
            return next((x for x in observations if x["observation_id"] > baseline and match(x)), None)

        observation = wait_for(f"matching {role} {collector} observation", search)
        self.row["observation"] = select(observation)
        self.row.pop("last_sample", None)
        return observation

    def correlate(self, role, collector, observation, *, timeout=8):
        host = HOSTS[role]
        watch = self.watches[role, collector]["id"]
        observation_id = observation["observation_id"]

        def search():
            entries = self.admin.list_audit_entries(250)
            opened = next((entry for entry in entries
                           if entry["event_type"] == "incident_opened"
                           and entry["payload"].get("observation_id") == observation_id), None)
            # A watch can reuse an open incident. A wake denied by cooldown
            # is visible in the admin audit, outside the worker trigger queue.
            for entry in entries:
                data = entry["payload"]
                context = data.get("context", {})
                if (context.get("host_id") != host or context.get("watch_id") != watch
                    or data.get("decision", {}).get("rule_id") != "wake.budget"
                    or seconds(entry["timestamp"], observation["observed_at"]) < 0):
                    continue
                incident_id = context["incident_id"]
                if opened:
                    if incident_id == opened["payload"]["incident_id"] and entry["seq_no"] > opened["seq_no"]:
                        return opened, entry
                    continue
                details = self.rpc.get_incident_context(incident_id)
                if abs(seconds(entry["timestamp"], details["incident"]["updated_at"])) < 1 and any(
                    x["observation_id"] == observation_id for x in details["recent_observations"]
                ):
                    return None, entry
            return None

        self.row["recent_watch_triggers"] = [
            x for x in self.rpc.list_trigger_queue(host_id=host, limit=50)
            if x["watch_id"] == watch
        ]
        opened, updated = wait_for(f"incident created or updated for observation {observation_id}", search, timeout)
        context = updated["payload"]["context"]
        incident_id = context["incident_id"]
        self.row["incident_audit"] = opened
        self.row["wake_audit"] = updated
        self.row["reused_incident"] = opened is None
        default_trigger = {**context, "created_at": updated["timestamp"],
                           "status": "admitted" if updated["payload"]["decision"]["allowed"] else "suppressed"}
        self.row["trigger"] = next((x for x in self.row["recent_watch_triggers"]
                                    if x["event_id"] == context["event_id"]), default_trigger)
        self.row["incident"] = self.rpc.get_incident_context(incident_id)["incident"]
        self.row.pop("recent_watch_triggers")
        return incident_id

    def close_watch_incidents(self, role, collector):
        host = HOSTS[role]
        watch = self.watches[role, collector]["id"]
        ids = {x["incident_id"] for x in self.rpc.list_trigger_queue(host_id=host, limit=100)
               if x["watch_id"] == watch}
        for incident in self.rpc.list_active_incidents(host):
            if incident["incident_id"] in ids:
                self.admin.close_incident(incident["incident_id"], "fleet-p13", "Reset fixture baseline")

    def package(self):
        role, collector = "desktop", "packages.inventory"
        name = "hello"

        def has_package(obs):
            return any(pkg["name"] == name for pkg in sample(obs).get("packages", []))

        def excerpt(obs):
            data = sample(obs)
            return {**obs, "payload": {**obs["payload"], "data": {
                **data, "packages": [pkg for pkg in data.get("packages", []) if pkg["name"] == name]
            }}}

        prior = self.latest_id(role, collector)
        check(not has_package(self.observations(role, collector)[0]), "hello is already installed")
        install = ("sudo -n env DEBIAN_FRONTEND=noninteractive apt-get "
                   "-o Acquire::Retries=0 -o Acquire::http::Timeout=8 install -y hello")
        first = self.action(role, f"timeout 22 {install}", check=False, timeout=30)
        self.row["apt_attempt"] = {"exit": first.returncode, "stdout": first.stdout,
                                   "stderr": first.stderr}
        if first.returncode:
            name = "defsec-p13-maint"
            script = f"""set -eu
build=$(mktemp -d)
trap 'rm -rf -- "$build"' EXIT
mkdir "$build/DEBIAN"
printf 'Package: {name}\\nVersion: 1.0\\nArchitecture: all\\nMaintainer: Fleet Test <test@example.invalid>\\nDescription: Disposable fleet package inventory fixture\\n' > "$build/DEBIAN/control"
dpkg-deb --build "$build" /tmp/{name}.deb
sudo -n dpkg -i /tmp/{name}.deb
"""
            self.action(role, f"bash -c {shlex.quote(script)}")
            install = f"sudo -n dpkg -i /tmp/{name}.deb"
            self.row["package_method"] = "locally built empty .deb"
        else:
            self.row["package_method"] = "apt-get install hello"
        observed = self.observe(role, collector, prior, has_package, select=excerpt)
        self.correlate(role, collector, observed)
        self.row["initial_package"] = name

        guest(role, f"sudo -n dpkg -r {name}")
        absent = self.observe(role, collector, observed["observation_id"],
                              lambda obs: obs["status"] == "ok" and not has_package(obs), select=excerpt)
        self.row["observation"] = excerpt(observed)
        self.row["removed_package_observation"] = excerpt(absent)
        self.close_watch_incidents(role, collector)

        spec = dict(scope={"host_id": HOSTS[role], "collector": collector},
                    matches=[{"op": "eq", "field": "name", "value": name}],
                    effect="allow_optional", rationale="Expected Phase 13 maintenance fixture")
        rule = STATE / "maintenance-rule.json"
        rule.write_text(json.dumps(spec))
        created = self.cli("create-rule", str(rule), "--actor", "fleet-p13")

        def rule_state():
            return next(x for x in self.cli("list-rules", "--host", HOSTS[role])["rules"]
                        if x["rule_id"] == created["rule_id"])

        rule_before = rule_state()
        mark = max(e["seq_no"] for e in self.admin.list_audit_entries(10))
        self.row["repeat_action_at"] = utc().isoformat()
        guest(role, install, timeout=25)
        again = self.observe(role, collector, absent["observation_id"], has_package, select=excerpt)
        self.row["repeat_observation"] = excerpt(again)
        self.row["observation"] = excerpt(observed)
        self.row["rule_before"] = rule_before
        self.row["rule_after"] = rule_state()
        check(self.row["rule_after"]["hit_count"] > rule_before["hit_count"], "Rule did not register a hit")
        self.row["repeat_watch_decisions"] = [
            e for e in self.admin.list_audit_entries(120)
            if e["seq_no"] > mark and e["payload"].get("decision", {}).get("rule_id") == "wake.budget"
            and e["payload"].get("context", {}).get("watch_id") == self.watches[role, collector]["id"]
            and e["payload"]["context"]["host_id"] == HOSTS[role]
        ]
        check(not self.row["repeat_watch_decisions"],
              "The expected package change still generated a wake decision")

    def listener(self):
        role, collector = "desktop", "sockets.listening"
        self.close_watch_incidents(role, collector)
        prior = self.latest_id(role, collector)
        # Keep the synthetic listener on loopback inside the disposable VM.
        response = self.action(role, "sudo -n systemd-run --unit=fleet-listen "
                               "--property=RuntimeMaxSec=75s /usr/bin/python3 "
                               "-m http.server --bind 127.0.0.1 4444")
        self.row["fixture"] = response.stderr.strip()
        try:
            observed = self.observe(role, collector, prior, lambda x: any(
                sock["local_port"] == 4444 for sock in sample(x).get("sockets", [])))
            self.correlate(role, collector, observed)
        finally:
            guest(role, "sudo -n systemctl stop fleet-listen.service", check=False)

    def outbound(self):
        role, collector = "server", "connections.outbound"
        self.close_watch_incidents(role, collector)
        prior = self.latest_id(role, collector)
        code = """import socket, time
end = time.monotonic() + 65
while time.monotonic() < end:
    with socket.socket() as s:
        s.settimeout(3)
        try:
            s.connect(('203.0.113.10', 443))
        except OSError:
            pass
    time.sleep(.1)
"""
        self.action(role, f"sudo -n systemd-run --unit=fleet-outbound --uid=ubuntu "
                    f"--property=RuntimeMaxSec=70s /usr/bin/python3 -c {shlex.quote(code)}")
        try:
            observed = self.observe(role, collector, prior, lambda x: any(
                (f["remote_addr"], f["remote_port"]) == ("203.0.113.10", 443)
                and "SYN_SENT" in f["states"] for f in sample(x).get("flows", [])))
            self.correlate(role, collector, observed)
        finally:
            guest(role, "sudo -n systemctl stop fleet-outbound.service", check=False)

    def tamper(self):
        role, collector = "server", "files.metadata"
        previous = self.observations(role, collector)[0]

        def file_hash(obs):
            return next((f.get("sha256") for f in sample(obs).get("files", [])
                         if f["path"] == SSH_CONFIG), None)

        old_hash = file_hash(previous)
        self.row["before_hash"] = old_hash
        check(old_hash, "Initial sshd configuration hash missing")
        self.action(role, f"printf '\\n# defsec-p13 fleet fixture\\n' | sudo -n tee -a {SSH_CONFIG} >/dev/null")
        observed = self.observe(role, collector, previous["observation_id"],
                                lambda obs: file_hash(obs) and file_hash(obs) != old_hash)
        self.correlate(role, collector, observed)

    def truncation(self):
        role, collector = "bastion", "sockets.listening"
        self.close_watch_incidents(role, collector)
        prior = self.latest_id(role, collector)
        fixture = """import socket, time
sockets = []
for _ in range(4112):
    s = socket.socket()
    s.bind(('127.0.0.1', 0))
    s.listen(1)
    sockets.append(s)
print(len(sockets), flush=True)
time.sleep(80)
"""
        self.action(role, "sudo -n systemd-run --unit=fleet-truncation --uid=ubuntu "
                    "--property=LimitNOFILE=8192 --property=RuntimeMaxSec=85s "
                    f"/usr/bin/python3 -c {shlex.quote(fixture)}")
        try:
            observed = self.observe(role, collector, prior,
                                    lambda x: x["status"] == "truncated_rejected")
            try:
                self.correlate(role, collector, observed)
            except AssertionError:
                self.row.update(status="observed", note=(
                    "4112 listeners produced truncated_rejected. The role set-diff watch "
                    "generated no incident for the rejected sample."))
        finally:
            guest(role, "sudo -n systemctl stop fleet-truncation.service", check=False)
            self.row["fixture_journal"] = guest(
                role, "sudo -n journalctl -u fleet-truncation.service -n 8 --no-pager").stdout
            if "observation" not in self.row:
                self.row["diagnostics"] = self.truncation_diagnostics(role)

    def truncation_diagnostics(self, role):
        records = """import glob, json
for path in glob.glob('/var/lib/defsec-p13/spool/*.ndjson'):
    with open(path) as stream:
        for line in stream:
            row = json.loads(line)
            if row['status'] == 'truncated_rejected':
                print(line.rstrip())
"""
        result = guest(role, "sudo -n python3 -", input=records)
        spool = [json.loads(line) for line in result.stdout.splitlines()]
        with sqlite3.connect(f"file:{STATE}/control/ledger.sqlite3?mode=ro", uri=True) as db:
            db.row_factory = sqlite3.Row
            sessions = [dict(row) for row in db.execute(
                "SELECT session_id, acked_seq_no FROM agent_sessions WHERE host_id=?",
                (HOSTS[role],),
            )]
        return {"agent_truncation_records": spool, "controller_acknowledgments": sessions}

    def liveness(self):
        role = "desktop"
        host = HOSTS[role]
        self.row["footprint_before_stop"] = footprint()["agents"][role]
        self.action(role, f"sudo -n systemctl stop {UNIT}")
        try:
            incident = wait_for(
                "liveness incident",
                lambda: next((x for x in self.rpc.list_active_incidents(host)
                              if "missed heartbeats" in x["summary"]), None),
                GRACE + GRACE // 3 + 5,
            )
            self.row["incident"] = incident
            entry = next(x for x in self.admin.list_audit_entries(200)
                         if x["payload"].get("action") == "host_liveness_offline"
                         and x["payload"].get("incident_id") == incident["incident_id"])
            self.row["incident_audit"] = entry
            self.row["last_heartbeat_at"] = heartbeat = entry["payload"]["last_heartbeat_at"]
            delay = seconds(incident["created_at"], heartbeat)
            self.row["heartbeat_to_incident_seconds"] = delay
            check(GRACE <= delay <= GRACE + GRACE // 3 + 3, f"liveness detected after {delay}s")
        finally:
            guest(role, f"sudo -n systemctl start {UNIT}")
        self.row["reconnected"] = wait_for(
            "agent back online", lambda: next((x for x in self.rpc.list_hosts()
            if x["host_id"] == host and x["liveness_status"] == "online"), None))

    def mtls(self):
        pki = STATE / "pki"
        cert_host, claimed_host = HOSTS["desktop"], HOSTS["server"]
        enroll = self.cli("enroll", claimed_host)
        log = RESULTS / "control.log"
        start = log.stat().st_size
        cmd = [
            str(BIN / "agent-d"), "--host-id", claimed_host, "--state-dir", str(STATE / "wrong-host"),
            "--control-mtls-addr", f"{LAN}:{PORT}", "--tls-server-name", "p13.control.internal",
            "--tls-ca-cert", str(pki / "ca.crt"), "--tls-client-cert", str(pki / f"{cert_host}.crt"),
            "--tls-client-key", str(pki / f"{cert_host}.key"), "--control-key-id",
            enroll["control_signing_key_id"], "--control-pub-hex", enroll["control_public_key_hex"],
        ]
        self.row["action_at"] = utc().isoformat()
        with subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) as proc:
            try:
                def match():
                    with log.open() as stream:
                        stream.seek(start)
                        return next((line.strip() for line in stream
                                     if "mTLS agent host ID mismatch" in line
                                     and cert_host in line and claimed_host in line), None)
                self.row["control_log"] = wait_for("certificate SAN mismatch rejection", match, 12)
            finally:
                proc.terminate()
                try:
                    proc.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()

    def adapters(self):
        env = {**os.environ, "DEFSEC_CAPABILITY_TOKEN": self.token}
        sock = str(STATE / "control/investigate.sock")
        request = {"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                   "params": {"name": "list_hosts", "arguments": {"tag": "defsec-p13"}}}
        mcp = subprocess.run(
            [str(BIN / "mcp-adapter"), "--mode", "read-only", "--investigate-sock", sock],
            env=env, input=json.dumps(request) + "\n", capture_output=True, text=True,
            check=True, timeout=15,
        )
        reply = json.loads(mcp.stdout)["result"]
        self.row["mcp_hosts"] = json.loads(reply["content"][0]["text"])["hosts"]
        check({x["host_id"] for x in self.row["mcp_hosts"]} == set(HOSTS.values()),
              "MCP host inventory differs from fleet")
        with subprocess.Popen(["node", "console/server.mjs", "--investigate-sock", sock,
                               "--host", "127.0.0.1", "--auth-mode", "none", "--port", "0"],
                              env=env, text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL) as console:
            try:
                import select
                ready, _, _ = select.select([console.stdout], [], [], 10)
                check(ready, "Console startup timed out")
                line = console.stdout.readline()
                parsed = re.search(r"http://127\.0\.0\.1:(\d+)/", line)
                check(parsed, "Console did not announce a loopback listener")
                with urllib.request.urlopen(f"http://127.0.0.1:{parsed[1]}/api/hosts", timeout=8) as response:
                    self.row["console_hosts"] = json.load(response)["hosts"]
                check({x["host_id"] for x in self.row["console_hosts"]} == set(HOSTS.values()),
                      "Console host inventory differs from fleet")
            finally:
                console.terminate()
                try:
                    console.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    console.kill()


def benchmark():
    cmd = [sys.executable, "-m", "defsec_reasoner", "benchmark", "--quiet",
           "--binary", str(BIN / "control-d"), "--json-out", str(RESULTS / "benchmark.json"),
           "--markdown-out", str(RESULTS / "benchmark.md")]
    response = run(cmd, check=False, timeout=120)
    return {"exit": response.returncode, "stdout": response.stdout, "stderr": response.stderr}


def live_reasoner():
    if os.environ.get("DEFSEC_FLEET_LIVE_BEAM") != "1":
        return {"status": "skipped", "note": "Live Beam telemetry export is disabled."}
    cmd = [sys.executable, os.path.join(os.path.dirname(__file__), "beam.py")]
    try:
        response = subprocess.run(cmd, capture_output=True, timeout=420, check=False)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        return {"status": "skipped", "note": f"Beam launcher unavailable ({type(exc).__name__})."}
    if response.returncode:
        return {"status": "fail", "note": f"Beam launcher exited {response.returncode}. See partial beam.json."}
    return json.loads((RESULTS / "beam.json").read_text())


def main():
    fleet = Fleet()
    fleet.execute("role_profiles", fleet.setup)
    if fleet.scenarios["role_profiles"]["status"] != "pass":
        return 1
    # Add Phase 12 scenarios here once the operator agent and codex-worker land.
    for name, test in (
        ("rogue_listener", fleet.listener), ("outbound_beacon", fleet.outbound),
        ("config_tamper", fleet.tamper), ("maintenance_noise", fleet.package),
        ("forced_truncation", fleet.truncation), ("agent_liveness", fleet.liveness),
        ("mtls_wrong_host", fleet.mtls), ("console_and_mcp", fleet.adapters),
    ):
        fleet.execute(name, test)
    fleet.execute("footprint", lambda: fleet.row.update(final=footprint()))
    def audit():
        fleet.row.update(fleet.admin.verify_audit_chain())
        check(fleet.row["valid"], "Audit chain verification failed")

    def scripted_benchmark():
        fleet.row.update(benchmark())
        check(fleet.row["exit"] == 0, "Scripted benchmark assertions failed")

    fleet.execute("scripted_benchmark", scripted_benchmark)
    live = live_reasoner()
    if live["status"] in ("skipped", "fail"):
        print(live["note"], flush=True)
        if not (RESULTS / "beam.json").exists():
            write_json("beam.json", live)
    fleet.scenarios["beam_live"] = {"status": live["status"], "note": live.get("note", "")}
    write_json("scenarios.json", fleet.scenarios)
    fleet.execute("audit", audit)
    return int(any(x["status"] == "fail" for x in fleet.scenarios.values()))


if __name__ == "__main__":
    sys.exit(main())
