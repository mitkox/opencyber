#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 3 ]]; then
  echo "usage: $0 IMAGE [OUTPUT_DIRECTORY] [PLATFORM]" >&2
  exit 2
fi

image=$1
output_directory=${2:-licenses}
platform=${3:-}
mkdir -p "$output_directory"
script_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)

docker_arguments=(run --rm --read-only --network none --cap-drop ALL --security-opt no-new-privileges)
if [[ -n "$platform" ]]; then
  docker_arguments+=(--platform "$platform")
fi
docker "${docker_arguments[@]}" --entrypoint dpkg-query "$image" \
  -W '-f=${source:Package}\t${source:Version}\t${binary:Package}\t${Version}\n' \
  | LC_ALL=C sort -u \
  >"$output_directory/debian-source-packages.tsv"

# The collector is supplied on stdin; the image receives no host filesystem mount.
collection_status=0
docker "${docker_arguments[@]}" -i --entrypoint python3 "$image" - \
  <"$script_directory/collect-license-bundle.py" \
  >"$output_directory/third-party-license-texts.tar.gz" || collection_status=$?

# Read only the named inventory member; never extract arbitrary image-supplied paths.
python3 - "$output_directory" <<'PY'
import pathlib
import sys
import tarfile

output = pathlib.Path(sys.argv[1])
with tarfile.open(output / "third-party-license-texts.tar.gz", "r:gz") as archive:
    member = archive.getmember("LICENSE-INVENTORY.json")
    if not member.isfile() or member.size > 64 * 1024 * 1024:
        raise SystemExit("invalid license inventory")
    with archive.extractfile(member) as source:
        (output / "LICENSE-INVENTORY.json").write_bytes(source.read())
PY

if command -v sha256sum >/dev/null 2>&1; then
  (cd "$output_directory" && sha256sum \
    debian-source-packages.tsv \
    third-party-license-texts.tar.gz \
    LICENSE-INVENTORY.json \
    >LICENSE-SHA256SUMS)
else
  (cd "$output_directory" && shasum -a 256 \
    debian-source-packages.tsv \
    third-party-license-texts.tar.gz \
    LICENSE-INVENTORY.json \
    >LICENSE-SHA256SUMS)
fi

echo "wrote $output_directory/debian-source-packages.tsv"
echo "wrote $output_directory/third-party-license-texts.tar.gz"
echo "wrote $output_directory/LICENSE-INVENTORY.json"
if [[ $collection_status -ne 0 ]]; then
  echo "license material collection is partial; inspect LICENSE-INVENTORY.json" >&2
fi
exit "$collection_status"
