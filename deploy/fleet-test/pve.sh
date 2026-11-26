#!/usr/bin/env bash
set -euo pipefail
umask 077

here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=lab-config.sh
source "$here/lab-config.sh"
load_fleet_config "$here"
operation=${1:?inventory, up, network, or down}
state=${2:?run state directory}
token=$(cat "$state/owner")
[[ $token =~ ^[a-f0-9]{24}$ ]]
pve_ssh=(ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=8
  -o ServerAliveInterval=10 -o ServerAliveCountMax=3 -o ControlMaster=no -o ControlPath=none)
if [[ -n $PVE_SSH_KEY ]]; then pve_ssh+=(-i "$PVE_SSH_KEY" -o IdentitiesOnly=yes); fi

pve() {
  local command
  printf -v command '%q ' bash -s -- "$PVE_NODE" "$PVE_STORAGE" "$PVE_BRIDGE" \
    "$PVE_VMID_MIN" "$PVE_VMID_MAX" "$token" "$@"
  {
    cat <<'REMOTE'
set -euo pipefail
umask 077
node=$1 storage=$2 bridge=$3 vmid_min=$4 vmid_max=$5 token=$6 operation=$7
shift 7
[[ $(hostname -s) == "$node" && $token =~ ^[a-f0-9]{24}$ ]]

check_id() {
  if [[ ! $1 =~ ^[1-9][0-9]{2,8}$ ]] || (( $1 < vmid_min || $1 > vmid_max )); then
    printf 'Refused VMID %s outside the disposable range\n' "$1" >&2
    return 2
  fi
}
qm_vm() {
  local verb=$1 id=$2
  shift 2
  check_id "$id" || return
  command qm "$verb" "$id" "$@"
}
verify_owner() {
  local cfg
  cfg=$(qm_vm config "$1") || return 1
  if ! grep -Eq '^name: defsec-p13-[a-z]+$' <<<"$cfg" ||
     ! grep -Eq '^tags: ([^;]+;)*defsec-p13(;[^;]+)*$' <<<"$cfg" ||
     ! grep -Fxq "description: fleet-run-$token" <<<"$cfg"; then
    echo "Refused VM $1 because the config ownership markers differ" >&2
    return 1
  fi
}
resources() {
  pvesh get /cluster/resources --type vm --output-format json |
    python3 -c '
import json, sys
node, low, high, mode = sys.argv[1:]
rows = json.load(sys.stdin)
occupied = [row["vmid"] for row in rows if int(low) <= row["vmid"] <= int(high)]
if mode == "empty":
    if occupied:
        sys.exit(f"Disposable VMIDs already in use: {sorted(occupied)}")
else:
    fields = ("vmid", "node", "type", "status", "uptime")
    print(json.dumps([{key: row.get(key) for key in fields} for row in rows
                      if row["node"] == node or row["vmid"] in occupied], sort_keys=True))
' "$node" "$vmid_min" "$vmid_max" "$1"
}
storage_path() {
  local path
  path=$(pvesm path "$storage:$1") || return
  [[ $path == /* && $(realpath -m -- "$path") == "$path" ]] || return 1
  printf '%s\n' "$path"
}
main() {
case $operation in
  inventory)
    resources inventory
    ;;
  empty)
    resources empty
    ;;
  preflight)
    free -m
    pvesm status --storage "$storage"
    image=$(storage_path iso/noble-server-cloudimg-amd64.img)
    test -r "$image"
    sha256sum "$image"
    ;;
  create)
    id=$1 role=$2
    check_id "$id"
    case "$id:$role" in
      "$vmid_min:server"|"$((vmid_min + 1)):bastion"|"$((vmid_min + 2)):desktop"|"$vmid_min:node") ;;
      *) exit 2 ;;
    esac
    [[ $(pvesh get /cluster/nextid --vmid "$id") == "$id" ]]
    image=$(storage_path iso/noble-server-cloudimg-amd64.img)
    snippet=snippets/defsec-p13-$token-$id.yaml
    seed=$(storage_path "$snippet")
    (set -o noclobber; write_seed > "$seed")
    qm_vm create "$id" --name "defsec-p13-$role" --tags defsec-p13 \
      --description "fleet-run-$token" --memory 1024 --balloon 0 --cores 2 \
      --onboot 0 --net0 "virtio,bridge=$bridge" --scsihw virtio-scsi-pci \
      --serial0 socket --agent 1 >&2
    verify_owner "$id"
    qm_vm set "$id" --scsi0 "$storage:0,import-from=$image,format=qcow2" >&2
    verify_owner "$id"
    qm_vm set "$id" --ide2 "$storage:cloudinit" --ipconfig0 ip=dhcp \
      --cicustom "user=$storage:$snippet" --boot order=scsi0 >&2
    free -m >&2
    awk '/^MemAvailable:/ {ok = ($2 >= (3072+1024)*1024)} END {exit !ok}' /proc/meminfo ||
      { echo 'VM start would leave less than 3072 MiB MemAvailable' >&2; exit 1; }
    verify_owner "$id"
    qm_vm start "$id" >&2
    qm_vm config "$id"
    ;;
  network)
    verify_owner "$1"
    command qm guest cmd "$1" network-get-interfaces
    ;;
  down)
    id=$1
    check_id "$id"
    if [[ -e /etc/pve/qemu-server/$id.conf ]]; then
      verify_owner "$id"
      if [[ $(qm_vm status "$id") != 'status: stopped' ]]; then
        verify_owner "$id"
        qm_vm stop "$id" >&2
      fi
      verify_owner "$id"
      qm_vm destroy "$id" --purge 1 >&2
    fi
    seed=$(storage_path "snippets/defsec-p13-$token-$id.yaml")
    rm -f -- "$seed"
    [[ $(pvesh get /cluster/nextid --vmid "$id") == "$id" ]]
    [[ ! -e $seed ]]
    volumes=$(pvesm list "$storage" --vmid "$id")
    awk -v id="$id" '$NF == id || index($1, ":" id "/") { found=1 } END { exit found }' <<<"$volumes"
    echo "VM $id configuration, seed and storage cleanup verified"
    ;;
  *) exit 2;;
esac
}
REMOTE
    if [[ $1 == create ]]; then
      printf "write_seed() { cat <<'P13_CLOUD_INIT'\n"
      cat
      printf '\nP13_CLOUD_INIT\n}\n'
    fi
    printf 'main "$@"\n'
  } | "${pve_ssh[@]}" "$PVE_SSH" "$command"
}

case $operation in
  inventory) pve inventory ;;
  network) pve network "${3:?VMID}" ;;
  up)
    roles=(server bastion desktop)
    if [[ ${FLEET_BLIND:-0} == 1 ]]; then roles=(node); fi
    if ((PVE_VMID_MAX - PVE_VMID_MIN + 1 < ${#roles[@]})); then
      printf 'Fleet mode requires at least three disposable VMIDs.\n' >&2
      exit 1
    fi
    pve preflight >&2
    pve empty
    ssh-keygen -q -t ed25519 -N '' -f "$state/guest-login"
    id=$PVE_VMID_MIN
    for role in "${roles[@]}"; do
      host=defsec-p13-$role
      ssh-keygen -q -t ed25519 -N '' -f "$state/$host"
      read -r keytype keydata _ < "$state/$host.pub"
      printf '%s %s %s\n' "$host" "$keytype" "$keydata" >> "$state/known_hosts"
      config=$(
        # JSON is valid YAML for cloud-init. The generated host key attests SSH
        # through the authenticated hypervisor, even when DHCP reuses an IP.
        printf '#cloud-config\n'
        python3 - "$host" "$state/$host" "$FLEET_LAN" "$state/guest-login.pub" <<'PY'
import json
import pathlib
import sys
host, key_file, controller, user_key = sys.argv[1:]
key = pathlib.Path(key_file)
print(json.dumps(dict(
    hostname=host, users=["default"], ssh_pwauth=False, disable_root=True,
    ssh_authorized_keys=[pathlib.Path(user_key).read_text().strip()],
    ssh_deletekeys=True, ssh_genkeytypes=["ed25519"],
    ssh_keys=dict(ed25519_private=key.read_text(),
                  ed25519_public=key.with_suffix(".pub").read_text()),
    runcmd=[["ping", "-c", "3", "-W", "1", controller]],
)))
PY
      )
      # Stream the seed through SSH without putting host-key material in argv.
      printf '%s\n' "$id" >> "$state/attempted"
      printf '%s' "$config" | pve create "$id" "$role" > "$state/$host.conf"
      rm -f -- "$state/$host"
      id=$((id + 1))
    done
    ;;
  down)
    rc=0
    if [[ -f $state/attempted ]]; then
      while read -r id; do pve down "$id" || rc=1; done < "$state/attempted"
    fi
    pve empty || rc=1
    exit "$rc"
    ;;
  *) exit 2;;
esac
