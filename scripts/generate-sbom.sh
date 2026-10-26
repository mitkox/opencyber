#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 3 ]]; then
  echo "usage: $0 IMAGE [OUTPUT_DIRECTORY] [PLATFORM]" >&2
  echo "example: $0 registry:ghcr.io/mitkox-dev/opencyber@sha256:... sbom linux/amd64" >&2
  exit 2
fi

image=$1
output_directory=${2:-sbom}
platform=${3:-}

if ! command -v syft >/dev/null 2>&1; then
  echo "error: syft is required: https://github.com/anchore/syft" >&2
  exit 1
fi

mkdir -p "$output_directory"

suffix=${platform//\//-}
if [[ -z "$suffix" ]]; then
  suffix=default
fi

cyclonedx="$output_directory/opencyber-$suffix.cdx.json"
spdx="$output_directory/opencyber-$suffix.spdx.json"

# Freeze local Docker input before scanning and collecting file-specific facts.
scan_image="$image"
runtime_image_id=""
if [[ "$image" == docker:* ]]; then
  runtime_image_id=$(docker image inspect --format '{{.Id}}' "${image#docker:}")
  scan_image="docker:$runtime_image_id"
fi

arguments=(
  scan
  "$scan_image"
  --override-default-catalogers image
  --select-catalogers=-file
  --enrich "golang,java,python"
  --output "cyclonedx-json=$cyclonedx"
  --output "spdx-json=$spdx"
)

if [[ -n "$platform" ]]; then
  arguments+=(--platform "$platform")
fi

SYFT_CHECK_FOR_APP_UPDATE=false \
SYFT_FILE_METADATA_SELECTION=none \
SYFT_PACKAGE_EXCLUDE_BINARY_OVERLAP_BY_OWNERSHIP=false \
SYFT_RELATIONSHIPS_PACKAGE_FILE_OWNERSHIP=false \
SYFT_RELATIONSHIPS_PACKAGE_FILE_OWNERSHIP_OVERLAP=false \
  syft "${arguments[@]}"

if [[ -n "$runtime_image_id" ]]; then
  script_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
  cyclonedx_absolute=$(realpath "$cyclonedx")
  enriched=$(mktemp "$output_directory/enriched-cdx.XXXXXX")
  trap 'rm -f -- "$enriched"' EXIT
  docker run --rm --network none --cap-drop=ALL --read-only --tmpfs /tmp \
    --mount "type=bind,source=$script_directory/enrich-sbom-licenses.py,target=/enrich-sbom-licenses.py,readonly" \
    --mount "type=bind,source=$cyclonedx_absolute,target=/input.cdx.json,readonly" \
    --entrypoint python3 "$runtime_image_id" /enrich-sbom-licenses.py \
    --root / --input /input.cdx.json --output - >"$enriched"
  mv -- "$enriched" "$cyclonedx"
  trap - EXIT
fi

cyclonedx_name=$(basename "$cyclonedx")
spdx_name=$(basename "$spdx")
if command -v sha256sum >/dev/null 2>&1; then
  (cd "$output_directory" && sha256sum "$cyclonedx_name" "$spdx_name" >"SHA256SUMS-$suffix")
else
  (cd "$output_directory" && shasum -a 256 "$cyclonedx_name" "$spdx_name" >"SHA256SUMS-$suffix")
fi

python3 scripts/check-license-policy.py "$cyclonedx"

echo "wrote $cyclonedx"
echo "wrote $spdx"
