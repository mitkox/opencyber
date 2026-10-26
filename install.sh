#!/usr/bin/env bash

set -Eeuo pipefail

readonly DEFAULT_VERSION="0.5.0"
readonly DEFAULT_IMAGE="ghcr.io/mitkox-dev/opencyber"
readonly DEFAULT_CONTAINER="opencyber"
readonly DEFAULT_VOLUME="opencyber-workspace"
readonly MANAGED_LABEL="com.opencyber.harness.managed"

version="${OPENCYBER_VERSION:-$DEFAULT_VERSION}"
digest="${OPENCYBER_DIGEST:-}"
image_repository="${OPENCYBER_IMAGE:-$DEFAULT_IMAGE}"
container_name="${OPENCYBER_CONTAINER_NAME:-$DEFAULT_CONTAINER}"
volume_name="${OPENCYBER_VOLUME_NAME:-$DEFAULT_VOLUME}"
mode="install"
purge_workspace=false
offline=false
read_only=true
verify_attestation=false
backup_container=""

usage() {
  cat <<'EOF'
OpenCyber Harness installer

Usage:
  install.sh [--version VERSION] [--digest SHA256] [--offline] [--no-read-only]
  install.sh --uninstall [--purge-workspace]

Options:
  --version VERSION     Install a specific release (default: 0.5.0).
  --digest SHA256       Pin the image by digest instead of tag (sha256:<64 hex>).
  --uninstall           Remove the installer-managed OpenCyber container.
  --purge-workspace     Also remove its Docker volume during uninstall.
  --offline             Do not pull; use a locally imported image and set OPENCYBER_OFFLINE=1.
  --verify-attestation  Verify the GitHub build attestation with `gh` before starting.
  --no-read-only        Keep the container root filesystem writable (less hardened).
  -h, --help            Show this help.

The default container is hardened: capabilities dropped except NET_RAW/NET_ADMIN/
NET_BIND_SERVICE, no-new-privileges, and a read-only root filesystem with tmpfs
for /tmp, /run, /root/.config, and /root/.cache.
AutoRecon, NetExec and Metasploit also receive disposable state mounts at
/root/.local/share, /root/.nxc and /root/.msf4.

Environment overrides:
  OPENCYBER_VERSION, OPENCYBER_DIGEST, OPENCYBER_IMAGE, OPENCYBER_CONTAINER_NAME,
  OPENCYBER_VOLUME_NAME
EOF
}

die() {
  printf 'opencyber: %s\n' "$*" >&2
  exit 1
}

log() {
  printf 'opencyber: %s\n' "$*"
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "$1 is required but was not found."
}

is_managed_container() {
  local candidate="$1"
  [[ "$(docker inspect --format "{{ index .Config.Labels \"${MANAGED_LABEL}\" }}" "$candidate" 2>/dev/null || true)" == "true" ]]
}

is_managed_volume() {
  local candidate="$1"
  [[ "$(docker volume inspect --format "{{ index .Labels \"${MANAGED_LABEL}\" }}" "$candidate" 2>/dev/null || true)" == "true" ]]
}

restore_backup() {
  if [[ -z "$backup_container" ]]; then
    return
  fi

  log "installation failed; restoring the previous managed container"
  docker rm -f "$container_name" >/dev/null 2>&1 || true
  docker rename "$backup_container" "$container_name" >/dev/null 2>&1 || true
  docker start "$container_name" >/dev/null 2>&1 || true
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --version)
      [[ $# -ge 2 ]] || die "--version requires a value."
      version="$2"
      shift 2
      ;;
    --uninstall)
      mode="uninstall"
      shift
      ;;
    --purge-workspace)
      purge_workspace=true
      shift
      ;;
    --digest)
      [[ $# -ge 2 ]] || die "--digest requires a value."
      digest="$2"
      shift 2
      ;;
    --offline)
      offline=true
      shift
      ;;
    --verify-attestation)
      verify_attestation=true
      shift
      ;;
    --no-read-only)
      read_only=false
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "version must look like 1.0.0."
if [[ -n "$digest" && ! "$digest" =~ ^sha256:[0-9a-f]{64}$ ]]; then
  die "--digest must look like sha256:<64 lowercase hex characters>."
fi
if [[ "$verify_attestation" == true && "$offline" == true ]]; then
  die "--verify-attestation requires network access and cannot be combined with --offline."
fi
if [[ "$purge_workspace" == true && "$mode" != "uninstall" ]]; then
  die "--purge-workspace may only be used with --uninstall."
fi
require_command docker

docker info >/dev/null 2>&1 || die "Docker is installed but its daemon is not available."

if [[ "$mode" == "uninstall" ]]; then
  if docker container inspect "$container_name" >/dev/null 2>&1; then
    is_managed_container "$container_name" || die "container '$container_name' exists but is not managed by this installer."
    log "removing managed container '$container_name'"
    docker rm -f "$container_name" >/dev/null
  else
    log "managed container '$container_name' is already absent"
  fi

  if [[ "$purge_workspace" == true ]]; then
    if docker volume inspect "$volume_name" >/dev/null 2>&1; then
      is_managed_volume "$volume_name" || die "volume '$volume_name' exists but is not managed by this installer."
      log "removing workspace volume '$volume_name'"
      docker volume rm "$volume_name" >/dev/null
    fi
  else
    log "preserved workspace volume '$volume_name'"
  fi

  log "uninstall complete"
  exit 0
fi

architecture="$(docker info --format '{{.Architecture}}' 2>/dev/null || true)"
case "$architecture" in
  x86_64|amd64|aarch64|arm64) ;;
  *) die "unsupported Docker architecture '$architecture'; use linux/amd64 or linux/arm64." ;;
esac

if [[ -n "$digest" ]]; then
  image="${image_repository}@${digest}"
else
  image="${image_repository}:${version}"
fi

if [[ "$verify_attestation" == true ]]; then
  require_command gh
  log "verifying the build attestation for ${image}"
  gh attestation verify "oci://${image}" --repo mitkox-dev/opencyber
fi

if [[ "$offline" == true ]]; then
  docker image inspect "$image" >/dev/null 2>&1 || die "offline install requires the image to be imported first: $image (see scripts/opencyber-airgap.sh)"
  log "using locally imported ${image}"
else
  log "pulling ${image}"
  docker pull "$image"
fi

image_version="$(docker image inspect --format '{{ index .Config.Labels "com.opencyber.harness.version" }}' "$image" 2>/dev/null || true)"
if [[ "$image_version" != "$version" ]]; then
  die "image version label is '${image_version:-missing}', but ${version} was requested. Refusing to install an unverified image."
fi

docker volume inspect "$volume_name" >/dev/null 2>&1 || \
  docker volume create --label "${MANAGED_LABEL}=true" "$volume_name" >/dev/null

if docker container inspect "$container_name" >/dev/null 2>&1; then
  is_managed_container "$container_name" || die "container '$container_name' already exists and is not managed by this installer. Rename or remove it, then run the installer again."
  backup_container="${container_name}-rollback-$(date +%s)"
  log "preserving the current managed container as '$backup_container' during the upgrade"
  docker stop "$container_name" >/dev/null 2>&1 || true
  docker rename "$container_name" "$backup_container"
  trap restore_backup ERR INT TERM
fi

env_args=()
if [[ "$offline" == true ]]; then
  env_args+=(--env OPENCYBER_OFFLINE=1)
fi

hardening_args=(
  --cap-drop=ALL
  --cap-add=NET_RAW
  --cap-add=NET_ADMIN
  --cap-add=NET_BIND_SERVICE
  --security-opt no-new-privileges
)
if [[ "$read_only" == true ]]; then
  hardening_args+=(
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

log "starting '$container_name'"
docker run -d \
  --name "$container_name" \
  --restart unless-stopped \
  --label "${MANAGED_LABEL}=true" \
  --label "com.opencyber.harness.version=${version}" \
  "${hardening_args[@]}" \
  -v "${volume_name}:/workspace" \
  "${env_args[@]}" \
  "$image" >/dev/null

log "verifying the MCP server"
docker exec "$container_name" opencyber-mcp --self-test >/dev/null

if [[ -n "$backup_container" ]]; then
  docker rm "$backup_container" >/dev/null
  backup_container=""
fi
trap - ERR INT TERM

log "OpenCyber Harness ${version} is ready"
printf '\nMCP command:\n  docker exec -i %s opencyber-mcp\n' "$container_name"
