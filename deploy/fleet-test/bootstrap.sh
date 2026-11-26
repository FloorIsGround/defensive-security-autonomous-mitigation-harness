#!/usr/bin/env bash
set -euo pipefail
umask 077

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=$(cd -- "$here/../.." && pwd)
# shellcheck source=lab-config.sh
source "$here/lab-config.sh"
load_fleet_config "$here"
cd "$repo"
run_at=$(date -u +%F/%H%M%S%NZ)
results=${1:-"$DEFSEC_FLEET_OUT_DIR/$run_at"}
mkdir -p "$(dirname -- "$results")"
mkdir "$results"
results=$(realpath "$results")
state=$(mktemp -d /tmp/defsec-p13.XXXXXXXX)
trap 'rm -rf -- "$state"' EXIT
python3 -c 'import secrets; print(secrets.token_hex(12))' > "$state/owner"
exec 9>"${XDG_RUNTIME_DIR:-/tmp}/defsec-p13-$(id -u).lock"
flock -n 9
phase=preflight
pve_attempted=0
pids=()
export PYTHONPATH="$repo/reasoner"
export PYTHONDONTWRITEBYTECODE=1
export FLEET_STATE="$state" FLEET_RESULTS="$results"
export FLEET_BIN="$(realpath -m "${CARGO_TARGET_DIR:-"$repo/target"}")/release"
export FLEET_PORT=17443 FLEET_GRACE=36

cleanup() {
  local rc=$? teardown=0 pid attempt
  trap - EXIT
  trap '' HUP INT TERM
  set +e
  printf '%s\n%s\n' "$phase" "$rc" > "$results/exit-status.txt"
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null; done
  for pid in "${pids[@]}"; do wait "$pid" 2>/dev/null; done
  if ((pve_attempted)); then
    teardown=1
    for attempt in 1 2 3; do
      if "$here/pve.sh" down "$state" >> "$results/provision.log" 2>&1; then
        teardown=0
        break
      fi
      sleep 2
    done
  fi
  "$here/pve.sh" inventory "$state" > "$results/after.txt" || teardown=1
  if ((teardown)); then
    printf 'Teardown needs attention. Retry %s down %s\n' "$here/pve.sh" "$state" >&2
  else
    rm -rf -- "$state"
  fi
  report_rc=0
  if [[ ${FLEET_BLIND:-0} == 1 ]]; then
    printf '%s\n' "$teardown" > "$results/teardown-status.txt"
    printf 'Results: %s\n' "$results"
  else
    python3 "$here/measure.py" report "$results" "$teardown"
    report_rc=$?
    printf 'Report: %s/report.md\n' "$results"
  fi
  if ((rc == 0)); then rc=$((teardown || report_rc)); fi
  exit "$rc"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP

"$here/pve.sh" inventory "$state" > "$results/before.txt"
git rev-parse HEAD > "$results/base.txt"
{
  getconf GNU_LIBC_VERSION
  uname -srm
  python3 --version
  node --version
} > "$results/workstation.txt"
phase=build
cargo build --release --workspace --offline > "$results/build.log" 2>&1
mkdir "$state/pki"
admin="$FLEET_BIN/admin-cli"
"$admin" pki init-ca --out-dir "$state/pki" --common-name 'DefSec Phase 13' > "$state/pki-init.json"
"$admin" pki issue-server --ca-cert "$state/pki/ca.crt" --ca-key "$state/pki/ca.key" \
  --out-dir "$state/pki" --common-name p13.control.internal --dns p13.control.internal \
  --ip "$FLEET_LAN" > "$state/pki-server.json"

phase=control
RUST_LOG=warn NO_COLOR=1 "$FLEET_BIN/control-d" --data-dir "$state/control" --liveness-grace-seconds "$FLEET_GRACE" \
  --agent-mtls-addr "$FLEET_LAN:$FLEET_PORT" --tls-ca-cert "$state/pki/ca.crt" \
  --tls-server-cert "$state/pki/server.crt" --tls-server-key "$state/pki/server.key" \
  --tls-revoked-file "$state/pki/revoked_serials.json" > "$results/control.log" 2>&1 &
export FLEET_CONTROL_PID=$!
pids+=("$FLEET_CONTROL_PID")
for ((i=0; i<100; i++)); do
  [[ -S "$state/control/admin.sock" && -S "$state/control/investigate.sock" ]] && break
  kill -0 "$FLEET_CONTROL_PID"
  sleep .1
done
"$admin" --admin-sock "$state/control/admin.sock" verify-audit > "$state/audit-start.json"

phase=provision
pve_attempted=1
"$here/pve.sh" up "$state" > "$results/provision.log" 2>&1

phase=guests
python3 -u "$here/guests.py" | tee "$results/bootstrap.log"
phase=scenarios
scenario=scenarios.py
if [[ ${FLEET_BLIND:-0} == 1 ]]; then scenario=blind.py; fi
python3 -u "$here/$scenario" 2>&1 | tee "$results/scenarios.log"
phase=complete
