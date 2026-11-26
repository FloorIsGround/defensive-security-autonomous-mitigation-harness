"""Discover pinned cloud guests and install the test agent."""
import concurrent.futures
import ipaddress
import json
import os
import pathlib
import re
import shlex
import subprocess
import time

STATE = pathlib.Path(os.environ["FLEET_STATE"])
RESULTS = pathlib.Path(os.environ["FLEET_RESULTS"])
BIN = pathlib.Path(os.environ["FLEET_BIN"])
LAN = os.environ["FLEET_LAN"]
PORT = int(os.environ["FLEET_PORT"])
CIDR = ipaddress.IPv4Network(os.environ["FLEET_CIDR"])
BRIDGE = os.environ["PVE_BRIDGE"]
VMID_MIN = int(os.environ["PVE_VMID_MIN"])
PVE = pathlib.Path(__file__).with_name("pve.sh")
BLIND = os.environ.get("FLEET_BLIND") == "1"
ROLES = ("node",) if BLIND else ("server", "bastion", "desktop")
HOSTS = {role: f"defsec-p13-{role}" for role in ROLES}
SSH_OPTS = [
    "-F", "/dev/null", "-i", str(STATE / "guest-login"), "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes",
    "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=3",
    "-o", "ControlMaster=no", "-o", "ControlPath=none",
    "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=2",
]
UNIT = "defsec-p13-agent.service"
CONFIG = "/etc/defsec-p13"


def run(args, *, timeout=30, input=None, check=True):
    return subprocess.run(args, capture_output=True, text=not isinstance(input, bytes),
                          timeout=timeout, input=input, check=check)


def ssh_args(role, address):
    return ["ssh", *SSH_OPTS, "-o", f"UserKnownHostsFile={STATE / 'known_hosts'}",
            "-o", "GlobalKnownHostsFile=/dev/null", "-o", f"HostKeyAlias={HOSTS[role]}",
            f"ubuntu@{address}"]


def guest(role, command, *, address=None, **kwargs):
    if address is None:
        address = json.loads((STATE / "guests.json").read_text())[role]["address"]
    return run([*ssh_args(role, address), command], **kwargs)


def discover(role, index):
    host = HOSTS[role]
    config = (STATE / f"{host}.conf").read_text()
    nic = re.search(r"^net0: virtio=([0-9a-fA-F:]+),([^\n]+)$", config, re.MULTILINE)
    if not nic or f"bridge={BRIDGE}" not in nic[2].split(","):
        raise RuntimeError(f"{host}: no virtio interface on the configured fleet bridge")
    mac = nic[1].lower()
    deadline = time.monotonic() + 150
    last = ""
    while time.monotonic() < deadline:
        neighbors = json.loads(run(["ip", "-j", "-4", "neigh"], timeout=4).stdout)
        addresses = [x["dst"] for x in neighbors if x.get("lladdr", "").lower() == mac]
        if not addresses:
            # A cached cloud image can already have the QEMU guest agent.
            try:
                response = run([str(PVE), "network", str(STATE), str(index)],
                               check=False, timeout=10)
            except subprocess.TimeoutExpired:
                continue
            if response.returncode == 0:
                addresses = [
                    ip["ip-address"] for iface in json.loads(response.stdout)
                    if iface.get("hardware-address", "").lower() == mac
                    for ip in iface.get("ip-addresses", []) if ip["ip-address-type"] == "ipv4"
                ]
        for address in addresses:
            if ipaddress.ip_address(address) not in CIDR:
                continue
            try:
                response = guest(role, "hostname -s", address=address, check=False, timeout=15)
            except subprocess.TimeoutExpired:
                last = f"SSH command timed out on {address}"
                continue
            if response.returncode == 0 and response.stdout.strip() == host:
                print(f"{host} reached over pinned SSH at {address}", flush=True)
                return address, mac
            last = response.stderr.strip()
        time.sleep(3)
    raise RuntimeError(f"{host}: no pinned SSH connection for MAC {mac}. {last}")


def install(role, index):
    host = HOSTS[role]
    address, mac = discover(role, index)
    # Check the real guest-to-controller path before configuring systemd.
    reachability = guest(role, f"timeout 6 bash -c {shlex.quote(f'</dev/tcp/{LAN}/{PORT}')}",
                         address=address, timeout=15, check=False)
    if reachability.returncode:
        raise RuntimeError(f"Guest TCP probe to {LAN}:{PORT} failed "
                           f"with status {reachability.returncode}: {reachability.stderr.strip()}")
    admin = [str(BIN / "admin-cli"), "--admin-sock", str(STATE / "control/admin.sock")]
    enrollment = json.loads(run([*admin, "enroll", host]).stdout)
    if enrollment["admin_result"] != "host_enrolled":
        raise RuntimeError(f"Enrollment failed for {host}: {enrollment}")
    pki = STATE / "pki"
    run([*admin, "pki", "issue-host", host, "--ca-cert", str(pki / "ca.crt"),
         "--ca-key", str(pki / "ca.key"), "--out-dir", str(pki)])
    staging = STATE / f"files-{role}"
    staging.mkdir()
    profile_args = ""
    profile_files = []
    if not BLIND:
        profile = run([*admin, "profile-template", "--role", role, "--tag", "defsec-p13",
                       "--expected-service", "ssh.service"]).stdout
        (staging / "profile.json").write_text(profile)
        profile_args = f" --profile {CONFIG}/profile.json"
        profile_files = ["profile.json"]
    visibility = "InaccessiblePaths=/proc/self/net" if BLIND else ""
    unit = f"""[Unit]
Description=DefSec Phase 13 fleet agent
After=network-online.target
Wants=network-online.target
[Service]
Type=exec
User=defsec-p13
Group=defsec-p13
SupplementaryGroups=systemd-journal
StateDirectory=defsec-p13
ExecStart=/usr/local/bin/defsec-p13-agent --host-id {host} --state-dir /var/lib/defsec-p13 --control-mtls-addr {LAN}:{PORT} --tls-server-name p13.control.internal --tls-ca-cert {CONFIG}/ca.crt --tls-client-cert {CONFIG}/{host}.crt --tls-client-key {CONFIG}/{host}.key --control-key-id {enrollment['control_signing_key_id']} --control-pub-hex {enrollment['control_public_key_hex']}{profile_args} --heartbeat-seconds 8
{visibility}
NoNewPrivileges=yes
CapabilityBoundingSet=
AmbientCapabilities=
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
MemoryAccounting=yes
MemoryHigh=24M
MemoryMax=64M
CPUAccounting=yes
CPUQuota=20%
Restart=on-failure
RestartSec=2
[Install]
WantedBy=multi-user.target
"""
    (staging / UNIT).write_text(unit)
    archive = run(["tar", "-c", "-C", str(BIN), "agent-d", "-C", str(staging),
                   *profile_files, UNIT, "-C", str(pki), "ca.crt", f"{host}.crt", f"{host}.key"],
                  input=b"").stdout
    fixture = (pathlib.Path(__file__).with_name("blind-fixture.sh").read_text()
               if BLIND else "")
    install_script = f"""
cloud-init status --wait
sshd -T | grep -Fx 'passwordauthentication no'
dpkg --audit
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
tar -x -C "$tmp"
useradd --system --user-group --no-create-home --shell /usr/sbin/nologin defsec-p13
install -d -m 0750 -o root -g defsec-p13 {CONFIG}
if [[ -f "$tmp/profile.json" ]]; then
    install -m 0640 -o root -g defsec-p13 "$tmp/profile.json" {CONFIG}
fi
install -m 0640 -o root -g defsec-p13 "$tmp/ca.crt" \
    "$tmp/{host}.crt" "$tmp/{host}.key" {CONFIG}
install -m 0755 "$tmp/agent-d" /usr/local/bin/defsec-p13-agent
install -m 0644 "$tmp/{UNIT}" /etc/systemd/system/{UNIT}
{fixture}
systemctl daemon-reload
systemctl enable --now {UNIT}
uid=$(id -u defsec-p13)
test "$uid" -gt 0
verified=0
for attempt in $(seq 1 15); do
    pid=$(systemctl show -p MainPID --value {UNIT})
    if [[ "$pid" != 0 && -r "/proc/$pid/status" ]] &&
       awk -v "uid=$uid" '
         /^Uid:/ {{ user_ok = ($2 == uid && $3 == uid) }}
         /^CapEff:/ {{ cap_ok = ($2 == "0000000000000000") }}
         END {{ exit !(user_ok && cap_ok) }}
       ' "/proc/$pid/status"; then
        verified=1
        break
    fi
    sleep 1
done
if [[ "$verified" != 1 ]]; then
    systemctl status {UNIT} --no-pager >&2
    exit 1
fi
systemctl is-active {UNIT}
grep -E '^(Uid|CapEff):' "/proc/$pid/status"
cat /etc/os-release
"""
    response = guest(role, f"sudo -n bash -ec {shlex.quote(install_script)}",
                     address=address, input=archive, timeout=90)
    print(response.stdout.decode(), end="", flush=True)
    if not BLIND:
        applied = run([*admin, "apply-profile", "--host", host, "--role", role, "--actor", "fleet-p13"])
        (RESULTS / f"{role}-profile-applied.json").write_text(applied.stdout)
    return {"address": address, "mac": mac, "vmid": index, "host": host,
            "platform_and_hardening": response.stdout.decode()}


def main():
    with concurrent.futures.ThreadPoolExecutor(max_workers=3) as executor:
        futures = {role: executor.submit(install, role, index)
                   for index, role in enumerate(ROLES, VMID_MIN)}
        guests = {}
        failures = []
        for role, future in futures.items():
            try:
                guests[role] = future.result()
            except subprocess.CalledProcessError as error:
                details = error.stderr.decode() if isinstance(error.stderr, bytes) else error.stderr
                output = error.stdout.decode() if isinstance(error.stdout, bytes) else error.stdout
                failures.append(f"{role}: exit {error.returncode}: {details}{output}")
            except Exception as error:
                failures.append(f"{role}: {error}")
        (STATE / "guests.json").write_text(json.dumps(guests))
        (RESULTS / "guests.json").write_text(json.dumps(guests, indent=2) + "\n")
        if failures:
            raise SystemExit("\n".join(failures))


if __name__ == "__main__":
    main()
