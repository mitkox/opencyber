#!/usr/bin/env bash
set -Eeuo pipefail
readonly EXPECTED_VERSION="0.5.1"

[[ $# == 2 ]] || { echo "usage: $0 IMAGE JSON_OUTPUT" >&2; exit 2; }
image=$1
output=$2
script_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
temporary=$(mktemp -d "${TMPDIR:-/tmp}/opencyber-airgap-tools.XXXXXX")
container="opencyber-airgap-tools-$$-${RANDOM}"
cleanup() {
  docker rm -f "$container" >/dev/null 2>&1 || true
  rm -rf -- "$temporary"
}
trap cleanup EXIT

# Qualification records must stay outside the source snapshot.
python3 - "$output" "$script_directory/.." <<'PY'
from pathlib import Path
import sys
if Path(sys.argv[1]).resolve().is_relative_to(Path(sys.argv[2]).resolve()):
    raise SystemExit("JSON_OUTPUT must be outside the source tree")
PY

status=0
docker image inspect --format \
  '{"id":{{json .Id}},"architecture":{{json .Architecture}},"os":{{json .Os}},"version":{{json (index .Config.Labels "org.opencontainers.image.version")}}}' \
  "$image" >"$temporary/image.json" 2>"$temporary/stderr" || status=$?

if [[ "$status" == 0 ]]; then
  image_id=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["id"])' "$temporary/image.json")
  timeout --signal=TERM --kill-after=10s 660s \
  docker run --rm --name "$container" --no-healthcheck --network none \
  --cap-drop=ALL --security-opt no-new-privileges --read-only \
  --tmpfs /tmp --tmpfs /run --tmpfs /workspace --tmpfs /root/.config --tmpfs /root/.cache \
  --tmpfs /root/.local/share --tmpfs /root/.nxc --tmpfs /root/.msf4 \
  -e OPENCYBER_OFFLINE=1 -e OPENCYBER_STRICT_CATALOG=1 -e OPENCYBER_MCP_MODE=full \
  -e OPENCYBER_TOOL_CATEGORIES= -e TMPDIR=/tmp -e WPSCAN_API_TOKEN= \
  --mount "type=bind,source=$script_directory/airgap-tools-lab.py,target=/airgap-tools-lab.py,readonly" \
  --entrypoint python3 "$image_id" /airgap-tools-lab.py \
  >"$temporary/result.json" 2>"$temporary/stderr" || status=$?
fi

python3 - "$temporary" "$image" "$output" "$status" "$EXPECTED_VERSION" <<'PY'
import json
from pathlib import Path
import sys
directory, image, output, status = Path(sys.argv[1]), sys.argv[2], Path(sys.argv[3]), int(sys.argv[4])
try:
    report = json.loads((directory / "result.json").read_text())
except (ValueError, OSError):
    report = {"schema_version": 1, "suite": "opencyber.airgap-tools/v1", "passed": False, "checks": []}
stderr = (directory / "stderr").read_bytes()
try:
    identity = json.loads((directory / "image.json").read_text())
except (ValueError, OSError):
    identity = {}
report["image"] = {"reference": image, **identity}
report["container_exit_code"] = status
report["container_stderr"] = stderr[:32768].decode("utf-8", errors="replace")
report["container_stderr_bytes"] = len(stderr)
report["container_stderr_limited"] = len(stderr) > 32768
report["checks"].append({"name": "image_identity", "passed": bool(identity.get("id"))
                         and identity.get("version") == sys.argv[5]})
report["checks"].append({"name": "container_execution", "passed": status == 0})
report["passed"] = bool(report.get("passed")) and all(check["passed"] for check in report["checks"])
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
print(f"Airgap tool acceptance {'passed' if report['passed'] else 'failed'}: {output}")
raise SystemExit(0 if report["passed"] else 1)
PY
