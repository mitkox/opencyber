#!/usr/bin/env bash
set -euo pipefail

image_repository=${1:-ghcr.io/mitkox/opencyber}
version=${2:-0.5.0}

declared_version="$(python3 scripts/check-version-consistency.py --print)"
if [[ "$version" != "$declared_version" ]]; then
  echo "error: requested version ${version}, but the tree declares ${declared_version}" >&2
  echo "bump src/opencyber/__init__.py and its aliases first" >&2
  exit 1
fi

if [[ -n "$(git status --porcelain)" ]]; then
  echo "error: refusing to publish from a dirty worktree" >&2
  exit 1
fi

if [[ "$image_repository" != "ghcr.io/mitkox/opencyber" ]]; then
  echo "error: the signed release workflow publishes ghcr.io/mitkox/opencyber" >&2
  exit 1
fi

if ! command -v gh >/dev/null 2>&1; then
  echo "error: the GitHub CLI is required to dispatch the signed release workflow" >&2
  exit 1
fi

ref=$(git symbolic-ref --quiet --short HEAD || git rev-parse HEAD)
gh workflow run build-candidate.yml \
  --repo mitkox/opencyber \
  --ref "$ref" \
  --field "version=$version"

echo "dispatched candidate validation for $image_repository:$version; publication requires a selected qualified software run; hardware evidence is optional (docs/RELEASE.md)"
echo "watch it with: gh run list --repo mitkox/opencyber --workflow build-candidate.yml"
