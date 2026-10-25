#!/usr/bin/env bash
#
# Move an OpenCyber image across an airgap with checksums and a release
# manifest. No network access is used or required at any point.
#
set -Eeuo pipefail

readonly DEFAULT_IMAGE="opencyber:0.5.0"
readonly DEFAULT_OUTPUT="opencyber-airgap"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
REPO_ROOT="$(dirname "$SCRIPT_DIR")"
readonly REPO_ROOT

usage() {
  cat <<'EOF'
OpenCyber airgap transfer

Usage:
  scripts/opencyber-airgap.sh export [--image IMAGE] [--output DIR]
  scripts/opencyber-airgap.sh verify [--input DIR]
  scripts/opencyber-airgap.sh import [--input DIR]

Options:
  --image IMAGE   Image reference to export (default: opencyber:0.5.0).
  --output DIR    Destination directory for export (default: opencyber-airgap).
  --input DIR     Source directory for verify/import (default: opencyber-airgap).
  --force         Overwrite an existing export archive.
  -h, --help      Show this help.

The export directory contains:
  opencyber-<tag>.tar          docker save archive
  opencyber-<tag>.tar.sha256   archive-relative checksum
  release.json                 image ID, digest, creation time, archive metadata
  docs/                        HARDWARE.md, AIRGAP.md, notices, source offer
  sbom/                        SPDX/CycloneDX inventories when present
EOF
}

die() {
  printf 'opencyber-airgap: %s\n' "$*" >&2
  exit 1
}

require_docker() {
  command -v docker >/dev/null 2>&1 || die "docker is required but was not found"
}

require_sha256sum() {
  command -v sha256sum >/dev/null 2>&1 || die "sha256sum is required but was not found"
}

image="$DEFAULT_IMAGE"
directory="$DEFAULT_OUTPUT"
force=false
command_name=""

if [[ $# -eq 0 || "$1" == "-h" || "$1" == "--help" ]]; then
  usage
  [[ $# -eq 0 ]] && exit 1
  exit 0
fi

command_name="$1"
shift

while [[ $# -gt 0 ]]; do
  case "$1" in
    --image)
      [[ $# -ge 2 ]] || die "--image requires a value"
      image="$2"
      shift 2
      ;;
    --output)
      [[ $# -ge 2 ]] || die "--output requires a directory"
      directory="$2"
      shift 2
      ;;
    --input)
      [[ $# -ge 2 ]] || die "--input requires a directory"
      directory="$2"
      shift 2
      ;;
    --force)
      force=true
      shift
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

tag="${image##*:}"
archive_name="opencyber-${tag}.tar"
archive="${directory}/${archive_name}"

export_image() {
  require_docker
  require_sha256sum
  if ! docker image inspect "$image" >/dev/null 2>&1; then
    die "image is not present locally: $image"
  fi
  if [[ -e "$archive" && "$force" != true ]]; then
    die "archive already exists: $archive (use --force to replace)"
  fi
  mkdir -p "$directory/docs"
  docker save -o "$archive" "$image"
  ( cd "$directory" && sha256sum "$archive_name" > "${archive_name}.sha256" )
  cp -f "$REPO_ROOT/docs/HARDWARE.md" "$REPO_ROOT/docs/AIRGAP.md" "$directory/docs/"
  if [[ -d "$REPO_ROOT/sbom" ]]; then
    mkdir -p "$directory/sbom"
    cp -f "$REPO_ROOT"/sbom/* "$directory/sbom/" 2>/dev/null || true
  fi
  cp -f "$REPO_ROOT/THIRD_PARTY_NOTICES.md" "$REPO_ROOT/SOURCE_OFFER.md" "$directory/docs/" 2>/dev/null || true
  local image_id image_digest created size
  image_id="$(docker image inspect --format '{{.Id}}' "$image")"
  image_digest="$(docker image inspect --format '{{join .RepoDigests ","}}' "$image")"
  created="$(docker image inspect --format '{{.Created}}' "$image")"
  size="$(stat -c '%s' "$archive" 2>/dev/null || stat -f '%z' "$archive")"
  cat > "$directory/release.json" <<JSON
{
  "schema_version": 1,
  "image": "${image}",
  "image_id": "${image_id}",
  "repo_digests": "${image_digest}",
  "created": "${created}",
  "archive": "${archive_name}",
  "archive_bytes": ${size},
  "checksum_file": "${archive_name}.sha256",
  "offline": true
}
JSON
  printf 'opencyber-airgap: exported %s to %s\n' "$image" "$directory"
  printf 'opencyber-airgap: verify on the far side with: %s verify --input %s\n' "$0" "$directory"
}

verify_archive() {
  require_sha256sum
  [[ -d "$directory" ]] || die "input directory does not exist: $directory"
  local resolved_archive_name="$archive_name"
  local resolved_archive="$archive"
  if [[ -f "$directory/release.json" ]]; then
    local recorded
    recorded="$(sed -n 's/.*"archive"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$directory/release.json" | head -n 1)"
    if [[ -n "$recorded" ]]; then
      resolved_archive_name="$recorded"
      resolved_archive="$directory/$recorded"
    fi
    if [[ "$image" == "$DEFAULT_IMAGE" ]]; then
      local recorded_image
      recorded_image="$(sed -n 's/.*"image"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$directory/release.json" | head -n 1)"
      [[ -n "$recorded_image" ]] && image="$recorded_image"
    fi
  fi
  [[ -f "$directory/${resolved_archive_name}.sha256" ]] || die "checksum file is missing in $directory"
  [[ -f "$resolved_archive" ]] || die "archive is missing: $resolved_archive"
  archive_name="$resolved_archive_name"
  archive="$resolved_archive"
  ( cd "$directory" && sha256sum -c "${resolved_archive_name}.sha256" )
  [[ -f "$directory/release.json" ]] || printf 'opencyber-airgap: warning: release.json is missing\n' >&2
  printf 'opencyber-airgap: checksum OK for %s\n' "$resolved_archive"
}

import_image() {
  require_docker
  verify_archive
  docker load -i "$archive"
  printf 'opencyber-airgap: loaded %s\n' "$image"
  if docker image inspect "$image" >/dev/null 2>&1; then
    if docker run --rm --entrypoint sh "$image" -c 'command -v opencyber-doctor >/dev/null 2>&1' >/dev/null 2>&1; then
      if docker run --rm --entrypoint opencyber-doctor "$image" --quiet; then
        printf 'opencyber-airgap: doctor OK\n'
      else
        die "doctor failed after import; do not deploy this image"
      fi
    else
      printf 'opencyber-airgap: warning: image does not expose opencyber-doctor; skipped doctor\n' >&2
    fi
  fi
}

case "$command_name" in
  export)
    export_image
    ;;
  verify)
    verify_archive
    ;;
  import)
    import_image
    ;;
  *)
    die "unknown command: $command_name (use export, verify, or import)"
    ;;
esac
