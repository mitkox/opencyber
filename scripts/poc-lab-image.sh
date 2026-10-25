#!/usr/bin/env bash
set -Eeuo pipefail

[[ $# == 2 ]] || { echo "usage: $0 IMAGE JSON_OUTPUT" >&2; exit 2; }
image=$1
output=$2
script_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
container="opencyber-qualification-poc-$$"
trap 'docker rm -f "$container" >/dev/null 2>&1 || true' EXIT

docker run --rm -d --name "$container" --no-healthcheck --network none \
  --cap-drop=ALL --security-opt no-new-privileges --read-only \
  --tmpfs /tmp --tmpfs /run --tmpfs /workspace --tmpfs /root/.config --tmpfs /root/.cache \
  -e OPENCYBER_STRICT_CATALOG=1 \
  --mount "type=bind,source=$script_directory/poc-lab-target.py,target=/poc-target.py,readonly" \
  "$image"
docker exec "$container" sh -c \
  'mkdir -p /run/secrets; head -c 48 /dev/urandom | base64 > /run/secrets/opencyber-poc.key; chmod 0600 /run/secrets/opencyber-poc.key'
docker exec -d "$container" python3 /poc-target.py --port 8099
ready=false
for _ in {1..30}; do
  if docker exec "$container" curl --max-time 1 -fsS http://127.0.0.1:8099/version >/dev/null; then
    ready=true
    break
  fi
  sleep 0.2
done
[[ "$ready" == true ]] || { echo "PoC fixture did not become ready" >&2; exit 1; }
python3 "$script_directory/poc-lab-run.py" --mode image --container "$container" --json-out "$output"
