#!/usr/bin/env bash
# Build the pinned upstream releases with reviewed security dependency graphs.
set -euo pipefail

if [[ $# -ne 3 ]]; then
  echo "usage: $0 TOOL BUILD_DIRECTORY OUTPUT_DIRECTORY" >&2
  exit 2
fi

tool=$1
build_directory=$2
output_directory=$3
script_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
lock_directory="$script_directory/../compliance/patches/go/$tool"

case "$tool" in
  jaeles)
    module=github.com/jaeles-project/jaeles
    version=v0.0.0-20260620125341-d40305ffe42a
    package=.
    ;;
  kube-bench)
    module=github.com/aquasecurity/kube-bench
    version=v0.16.0
    package=.
    ;;
  urlfinder)
    module=github.com/projectdiscovery/urlfinder
    version=v0.0.3
    package=./cmd/urlfinder
    ;;
  yq)
    module=github.com/mikefarah/yq/v4
    version=v4.54.1
    package=.
    ;;
  *)
    echo "error: unsupported Go security build: $tool" >&2
    exit 2
    ;;
esac

export GOTOOLCHAIN=local
go mod download "$module@$version"
upstream_directory=$(go list -m -f '{{.Dir}}' "$module@$version")
mkdir -p "$build_directory" "$output_directory"
build_directory=$(cd -- "$build_directory" && pwd)
output_directory=$(cd -- "$output_directory" && pwd)
source_directory="$build_directory/$tool"
mkdir -p "$source_directory" "$output_directory/sources"
cp -a "$upstream_directory/." "$source_directory/"
chmod -R u+w "$source_directory"
cp "$lock_directory/go.mod" "$lock_directory/go.sum" "$source_directory/"

if [[ -f "$lock_directory/source.patch" ]]; then
  patch --batch --forward -d "$source_directory" -p1 < "$lock_directory/source.patch"
  cp "$lock_directory/source.patch" "$source_directory/opencyber-source.patch"
fi

(
  cd "$source_directory"
  CGO_ENABLED=0 GOOS="${TARGETOS:?TARGETOS must be set}" GOARCH="${TARGETARCH:?TARGETARCH must be set}" \
    go build -mod=readonly -trimpath -o "$output_directory/$tool" "$package"
)
tar --exclude=.git -czf "$output_directory/sources/$tool-patched.tar.gz" \
  -C "$build_directory" "$tool"
