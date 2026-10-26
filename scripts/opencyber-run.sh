#!/usr/bin/env bash
#
# Start an OpenCyber container with the right host exposure for a task.
# Read-only rootfs, dropped capabilities, and explicit device flags by default.
#
set -Eeuo pipefail

readonly DEFAULT_IMAGE="opencyber:0.5.0"
readonly DEFAULT_NAME="opencyber"
readonly DEFAULT_VOLUME="opencyber-workspace"
readonly DEFAULT_WORKSPACE="/workspace"

image="${OPENCYBER_IMAGE:-$DEFAULT_IMAGE}"
name="${OPENCYBER_CONTAINER_NAME:-$DEFAULT_NAME}"
volume="${OPENCYBER_VOLUME_NAME:-$DEFAULT_VOLUME}"
workspace="${OPENCYBER_WORKSPACE_PATH:-$DEFAULT_WORKSPACE}"
profile="software"
dry_run=false
read_only=true
offline=false
devices=()
command=(sleep infinity)

usage() {
  cat <<'EOF'
OpenCyber hardware-aware launcher

Usage:
  scripts/opencyber-run.sh [options]

Profiles:
  software     Network/web/software tools only (default)
  blue-team    Offline artifact triage; no network, capabilities, or devices
  usb          USB bus surfaced for lsusb/usbguard
  sdr          HackRF, RTL-SDR, LimeSDR, bladeRF, Ubertooth
  wifi         Host network namespace + NET_ADMIN/NET_RAW
  bluetooth    Host Bluetooth stack + Ubertooth USB
  nfc          Proxmark3 and PC/SC readers
  jtag         OpenOCD, ST-Link, J-Link, FT2232, flashrom
  serial       UART adapters (default /dev/ttyUSB0 and /dev/ttyACM0)
  can          SocketCAN interfaces + USB-CAN adapters
  logic        sigrok/sigrok-cli analyzers
  gps          GNSS receivers
  ir           /dev/lirc0
  full         All of the above (still not --privileged)

Options:
  --profile NAME       Select a profile (default: software).
  --image IMAGE        Image reference (default: opencyber:0.5.0).
  --name NAME          Container name (default: opencyber).
  --volume NAME        Workspace volume (default: opencyber-workspace).
  --device PATH        Add a device (repeatable).
  --offline            Set OPENCYBER_OFFLINE=1 inside the container.
  --no-read-only       Allow writes to the container rootfs.
  --dry-run            Print the command without running it.
  --command ...        Override the container command.
  -h, --help           Show this help.

Examples:
  scripts/opencyber-run.sh --profile sdr --dry-run
  scripts/opencyber-run.sh --profile serial --device /dev/ttyUSB1
  scripts/opencyber-run.sh --profile full --offline
EOF
}

die() {
  printf 'opencyber-run: %s\n' "$*" >&2
  exit 1
}

require_docker() {
  command -v docker >/dev/null 2>&1 || die "docker is required but was not found"
}

add_device() {
  local device="$1"
  [[ -e "$device" ]] || die "device does not exist on this host: $device"
  devices+=("--device" "$device")
}

add_usb() {
  if [[ -e /dev/bus/usb ]]; then
    devices+=("--device" "/dev/bus/usb")
  else
    printf 'opencyber-run: warning: /dev/bus/usb not found; USB hardware will not be visible\n' >&2
  fi
}

add_lirc() {
  if [[ -e /dev/lirc0 ]]; then
    devices+=("--device" "/dev/lirc0")
  else
    printf 'opencyber-run: warning: /dev/lirc0 not found; IR hardware will not be visible\n' >&2
  fi
}

add_serial() {
  local found=false
  for device in /dev/ttyUSB* /dev/ttyACM* /dev/ttyAMA*; do
    if [[ -e "$device" ]]; then
      devices+=("--device" "$device")
      found=true
    fi
  done
  if [[ "$found" == false ]]; then
    printf 'opencyber-run: warning: no serial adapters found; pass --device explicitly\n' >&2
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --profile)
      [[ $# -ge 2 ]] || die "--profile requires a value"
      profile="$2"
      shift 2
      ;;
    --image)
      [[ $# -ge 2 ]] || die "--image requires a value"
      image="$2"
      shift 2
      ;;
    --name)
      [[ $# -ge 2 ]] || die "--name requires a value"
      name="$2"
      shift 2
      ;;
    --volume)
      [[ $# -ge 2 ]] || die "--volume requires a value"
      volume="$2"
      shift 2
      ;;
    --device)
      [[ $# -ge 2 ]] || die "--device requires a path"
      add_device "$2"
      shift 2
      ;;
    --offline)
      offline=true
      shift
      ;;
    --no-read-only)
      read_only=false
      shift
      ;;
    --dry-run)
      dry_run=true
      shift
      ;;
    --command)
      shift
      [[ $# -gt 0 ]] || die "--command requires at least one token"
      command=("$@")
      break
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown argument: $1 (use --help)"
      ;;
  esac
done

if [[ "$profile" == "blue-team" ]]; then
  [[ ${#devices[@]} -eq 0 ]] || die "blue-team does not allow device passthrough"
  [[ "$read_only" == true ]] || die "blue-team does not allow --no-read-only"
  offline=true
fi

args=(
  --cap-drop=ALL
  --security-opt no-new-privileges
  -v "${volume}:${workspace}"
  -e "OPENCYBER_WORKSPACE=${workspace}"
  --name "$name"
)

if [[ "$profile" != "blue-team" ]]; then
  args+=(--cap-add=NET_RAW --cap-add=NET_ADMIN --cap-add=NET_BIND_SERVICE)
fi

if [[ "$read_only" == true ]]; then
  args+=(
    --read-only
    --tmpfs /tmp
    --tmpfs /run
    --tmpfs /root/.config
    --tmpfs /root/.cache
    --tmpfs /root/.local/share
    --tmpfs /root/.nxc
    --tmpfs /root/.msf4
  )
fi

if [[ "$offline" == true ]]; then
  args+=(-e OPENCYBER_OFFLINE=1)
fi

case "$profile" in
  blue-team)
    args+=(--network none)
    ;;
  software)
    ;;
  usb)
    add_usb
    ;;
  sdr)
    add_usb
    ;;
  wifi)
    args+=(--network host --cap-add SYS_RAWIO)
    ;;
  bluetooth)
    args+=(--network host)
    add_usb
    ;;
  nfc)
    add_usb
    ;;
  jtag)
    add_usb
    ;;
  serial)
    add_serial
    ;;
  can)
    args+=(--network host)
    add_usb
    ;;
  logic)
    add_usb
    ;;
  gps)
    add_usb
    add_serial
    ;;
  ir)
    add_lirc
    ;;
  full)
    args+=(--network host --cap-add SYS_RAWIO)
    add_usb
    add_serial
    add_lirc
    ;;
  *)
    die "unknown profile: $profile (use --help)"
    ;;
esac

args+=("${devices[@]}")
args+=("$image" "${command[@]}")

if [[ "$dry_run" == true ]]; then
  printf 'docker run -d'
  printf ' %q' "${args[@]}"
  printf '\n'
  exit 0
fi

require_docker
exec docker run -d "${args[@]}"
