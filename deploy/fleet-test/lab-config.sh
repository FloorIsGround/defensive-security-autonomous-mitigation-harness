# Load trusted local Bash assignments. Exported values override file settings.
load_fleet_config() {
  local here=$1 config name
  config=${DEFSEC_FLEET_CONFIG:-"$here/lab.local.env"}
  local -a required=(PVE_SSH PVE_NODE PVE_STORAGE PVE_BRIDGE FLEET_CIDR FLEET_LAN
    PVE_VMID_MIN PVE_VMID_MAX)
  local -A overrides=()
  for name in "${required[@]}" PVE_SSH_KEY DEFSEC_FLEET_OUT_DIR; do
    if [[ -v $name ]]; then overrides[$name]=${!name}; fi
  done
  if [[ -e $config || -L $config || -n ${DEFSEC_FLEET_CONFIG:-} ]]; then
    if [[ ! -f $config || ! -r $config ]]; then
      printf 'Cannot read fleet config %s\n' "$config" >&2
      return 1
    fi
    config=$(realpath -- "$config") || return
    if [[ -n ${DEFSEC_FLEET_CONFIG:-} ]]; then export DEFSEC_FLEET_CONFIG="$config"; fi
    # shellcheck source=/dev/null
    source "$config" || return
  fi
  for name in "${!overrides[@]}"; do
    printf -v "$name" '%s' "${overrides[$name]}"
  done
  for name in "${required[@]}"; do
    if [[ -z ${!name:-} ]]; then
      printf 'Set %s in %s or export it before running the fleet harness.\n' "$name" "$config" >&2
      return 1
    fi
  done
  : "${PVE_SSH_KEY:=}"
  : "${DEFSEC_FLEET_OUT_DIR:=${XDG_STATE_HOME:-$HOME/.local/state}/defsec-fleet-test/results}"

  if [[ ! $PVE_SSH =~ ^[a-zA-Z0-9_][a-zA-Z0-9_.-]*@[a-zA-Z0-9:][a-zA-Z0-9_.:-]*$ ]]; then
    printf 'PVE_SSH must be an SSH destination in user@host form.\n' >&2
    return 1
  fi
  for name in PVE_NODE PVE_STORAGE PVE_BRIDGE; do
    if [[ ! ${!name} =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]*$ ]]; then
      printf 'Invalid identifier for %s.\n' "$name" >&2
      return 1
    fi
  done
  if [[ -n $PVE_SSH_KEY && ( ! -f $PVE_SSH_KEY || ! -r $PVE_SSH_KEY ) ]]; then
    printf 'Cannot read the configured PVE_SSH_KEY.\n' >&2
    return 1
  fi
  if [[ ! $PVE_VMID_MIN =~ ^[1-9][0-9]{2,8}$ || ! $PVE_VMID_MAX =~ ^[1-9][0-9]{2,8}$ ]] ||
     ((PVE_VMID_MAX < PVE_VMID_MIN)); then
    printf 'Set valid, ordered endpoints for the disposable VMID range.\n' >&2
    return 1
  fi
  if [[ -n $PVE_SSH_KEY ]]; then PVE_SSH_KEY=$(realpath -- "$PVE_SSH_KEY") || return; fi
  python3 - "$FLEET_CIDR" "$FLEET_LAN" <<'PY' || return
import ipaddress
import sys

try:
    network = ipaddress.IPv4Network(sys.argv[1])
    controller = ipaddress.IPv4Address(sys.argv[2])
    if "/" not in sys.argv[1] or controller not in network:
        raise ValueError("the controller IPv4 address must belong to the fleet CIDR")
    if controller in (network.network_address, network.broadcast_address):
        raise ValueError("the controller must use a host address on the fleet subnet")
except ValueError as error:
    raise SystemExit(f"Invalid FLEET_CIDR or FLEET_LAN: {error}")
PY
  export "${required[@]}" PVE_SSH_KEY DEFSEC_FLEET_OUT_DIR
}
