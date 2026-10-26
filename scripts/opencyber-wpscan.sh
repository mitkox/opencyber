#!/usr/bin/env bash
set -euo pipefail

# The package's normal cache is hidden by the hardened runtime's tmpfs mount.
# Offline runs read the immutable database staged at image build time instead.
offline="${OPENCYBER_OFFLINE:-0}"
case "${offline,,}" in
  1|true|yes|on)
    export XDG_CACHE_HOME=/usr/share/opencyber/wpscan-cache
    export TMPDIR=/tmp
    exec /usr/bin/wpscan "$@" --no-update
    ;;
esac

exec /usr/bin/wpscan "$@"
