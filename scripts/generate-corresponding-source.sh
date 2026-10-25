#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 4 ]]; then
  echo "usage: $0 IMAGE OUTPUT_DIRECTORY PLATFORM CAPTURED_SOURCE_DIRECTORY" >&2
  exit 2
fi
image=$1
output_directory=$2
platform=$3
captured_directory=$4
script_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
mkdir -p "$output_directory"
temporary=$(mktemp -d)
trap 'rm -rf "$temporary"' EXIT
runtime_image_id=$(docker image inspect --format '{{.Id}}' "$image")

# Compare the sidecar against the exact tested candidate, without network or
# host mounts. The release receipt associates its immutable local image ID with the
# registry digest after private staging.
docker run --rm --platform "$platform" --network none --cap-drop=ALL --read-only \
  --entrypoint python3 "$runtime_image_id" -c '
import subprocess
fmt="${db:Status-Status}\t${source:Package}\t${source:Version}\t${binary:Package}\t${Version}\n"
raw=subprocess.check_output(["dpkg-query","-W","-f="+fmt],text=True)
print("".join(line.split("\t",1)[1]+"\n" for line in raw.splitlines() if line.startswith("installed\t")),end="")
' \
  >"$temporary/runtime-dpkg.tsv"
docker run --rm -i --platform "$platform" --network none --cap-drop=ALL --read-only \
  --entrypoint python3 "$runtime_image_id" - --inventory-only \
  <"$script_directory/capture-corresponding-source.py" >"$temporary/runtime-ecosystems.json"
python3 "$script_directory/verify-corresponding-source.py" "$captured_directory" \
  --runtime-inventory "$temporary/runtime-dpkg.tsv" --runtime-ecosystems "$temporary/runtime-ecosystems.json" \
  --platform "$platform"

docker run --rm --platform "$platform" --network none --cap-drop=ALL --read-only \
  --entrypoint python3 "$runtime_image_id" -c '
import hashlib,json,pathlib
names=["anew","urlfinder","subzy","jaeles","kube-bench","x8","pwninit","hashpump","yq"]
print(json.dumps({"/usr/local/bin/"+n:hashlib.file_digest(pathlib.Path("/usr/local/bin/"+n).open("rb"),"sha256").hexdigest() for n in names}))
' >"$temporary/runtime-binaries.json"
printf '%s\n' "$runtime_image_id" >"$temporary/image-id"
python3 - "$captured_directory" "$output_directory" "$temporary" "$image" "$platform" <<'PY'
import hashlib,json,pathlib,sys
captured,output,temporary=map(pathlib.Path,sys.argv[1:4])
manifest=json.loads((captured/"source-manifest.json").read_text())
actual=json.loads((temporary/"runtime-binaries.json").read_text())
expected={p["binary"]:p["binary_sha256"] for p in manifest["packages"] if p.get("binary_sha256")}
if expected != actual:
    raise SystemExit("captured build sources do not match tested runtime binaries")
receipt={"schema":"opencyber.release-source/v1","platform":sys.argv[5],"image_reference":sys.argv[4],
         "image_id":(temporary/"image-id").read_text().strip(),
         "source_manifest_sha256":hashlib.sha256((captured/"source-manifest.json").read_bytes()).hexdigest(),
         "complete":True}
(output/"release-source-manifest.json").write_text(json.dumps(receipt,indent=2,sort_keys=True)+"\n")
PY
tar -czf "$output_directory/corresponding-source.tar.gz.partial" -C "$captured_directory" .
mv "$output_directory/corresponding-source.tar.gz.partial" "$output_directory/corresponding-source.tar.gz"
cp "$captured_directory/source-manifest.json" "$output_directory/source-manifest.json"
(cd "$output_directory" && sha256sum corresponding-source.tar.gz source-manifest.json release-source-manifest.json >SOURCE-SHA256SUMS)
echo "verified and exported exact corresponding source to $output_directory"
