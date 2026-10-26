#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
  echo "usage: $0 IMAGE [PLATFORM]" >&2
  exit 2
fi

image=$1
platform=${2:-}
docker_arguments=(run --rm)
if [[ -n "$platform" ]]; then
  docker_arguments+=(--platform "$platform")
fi
docker_arguments+=(--entrypoint sh "$image" -c)

docker "${docker_arguments[@]}" '
  set -eu
  for forbidden in burpsuite maltego waybackurls terrascan scout; do
    if command -v "$forbidden" >/dev/null 2>&1; then
      echo "forbidden executable present: $forbidden" >&2
      exit 1
    fi
  done
  for forbidden_package in terrascan scoutsuite python3-sqlitedict; do
    if dpkg-query -W -f="\${db:Status-Status}" "$forbidden_package" 2>/dev/null | grep -qx installed; then
      echo "excluded unmaintained or vulnerable package present: $forbidden_package" >&2
      exit 1
    fi
  done
  for required in whatweb urlfinder subzy vol nmap ncat ndiff nping autorecon rustscan msfconsole msfvenom nxc wpscan; do
    command -v "$required" >/dev/null 2>&1 || {
      echo "required executable missing: $required" >&2
      exit 1
    }
  done
  test -f /usr/share/opencyber/licenses/opencyber/THIRD_PARTY_NOTICES.md
  test -f /usr/share/opencyber/licenses/opencyber/SOURCE_OFFER.md
  test -d /usr/share/opencyber/licenses/go
  test -d /usr/share/opencyber/licenses/rust
  test -f /usr/share/opencyber/docs/HARDWARE.md
  test -f /usr/share/opencyber/docs/AIRGAP.md
  test -f /usr/share/opencyber/docs/TOOLS.md
  test -f /usr/share/opencyber/docs/CONFIGURATION.md
  test -f /usr/share/opencyber/docs/SECURITY_MODEL.md
  test -f /usr/share/opencyber/docs/INSTALL.md
  test -f /usr/share/opencyber/docs/README.md
  test -f /usr/share/opencyber/host/99-opencyber-hw.rules
  test -f /usr/share/opencyber/asset-manifest.json
  echo "image compliance smoke check passed"
'
