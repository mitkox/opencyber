#!/usr/bin/env python3
"""Promote validated private candidates by digest; never builds an image."""
from __future__ import annotations

import json
import os
from pathlib import Path
import re
import subprocess
import sys


def registry_digest(reference: str) -> str | None:
    probe = subprocess.run(["skopeo", "inspect", "--format", "{{.Digest}}", "docker://" + reference],
                           text=True, capture_output=True, check=False)
    if probe.returncode:
        if re.search(r"manifest unknown|name unknown|status code: 404", probe.stderr, re.I):
            return None
        raise ValueError("registry inspection failed; authentication or network errors are not absence")
    digest = probe.stdout.strip()
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
        raise ValueError("registry returned an invalid digest")
    return digest


def ensure_version_tag(reference: str, digest: str) -> None:
    if not re.fullmatch(r"ghcr\.io/[a-z0-9_.-]+/[a-z0-9_.-]+:[0-9]+\.[0-9]+\.[0-9]+", reference):
        raise ValueError("only an explicit version tag can be finalized")
    if not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
        raise ValueError("invalid qualified manifest digest")
    existing = registry_digest(reference)
    if existing is not None:
        if existing != digest:
            raise ValueError("version reference is immutable; changed bytes require a new version")
        return
    image = reference.rsplit(":", 1)[0]
    subprocess.run(["skopeo", "copy", "--all", "--preserve-digests", "docker://" + image + "@" + digest,
                    "docker://" + reference], check=True)
    if registry_digest(reference) != digest:
        raise ValueError("finalized version digest differs from qualified manifest")


def main() -> None:
    if len(sys.argv) == 4 and sys.argv[1] == "finalize":
        ensure_version_tag(sys.argv[2], sys.argv[3])
        return
    records = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    commit = os.environ["GITHUB_SHA"]
    public = f"{os.environ['REGISTRY']}/{os.environ['IMAGE_NAME']}"
    staging = f"{os.environ['REGISTRY']}/{os.environ['STAGING_NAME']}"
    if os.environ.get("GITHUB_REF_TYPE") != "tag":
        raise SystemExit("public promotion requires a release tag")
    if len(records) != 2 or {r.get("platform") for r in records} != {"linux/amd64", "linux/arm64"}:
        raise SystemExit("both native architecture receipts are required")
    for record in records:
        digest = record.get("digest", "")
        if record.get("commit") != commit or not re.fullmatch(r"sha256:[a-f0-9]{64}", digest):
            raise SystemExit("candidate receipt is not bound to this release commit")
        if record.get("staging_reference") != f"{staging}@{digest}":
            raise SystemExit("candidate must come from the verified private staging package")
    digests = {}
    for record in records:
        digest = record["digest"]
        arch = record["platform"].split("/")[1]
        destination = f"{public}:sha-{commit}-{arch}"
        existing = registry_digest(destination)
        if existing is not None and existing != digest:
            raise ValueError("published platform reference is immutable")
        if existing is None:
            subprocess.run([
                "skopeo", "copy", "--preserve-digests", "docker://" + record["staging_reference"],
                "docker://" + destination,
            ], check=True)
        actual = subprocess.check_output([
            "skopeo", "inspect", "--format", "{{.Digest}}", "docker://" + destination,
        ], text=True).strip()
        if actual != digest:
            raise SystemExit("promoted digest differs from tested candidate")
        subprocess.run(["cosign", "sign", "--yes", f"{public}@{digest}"], check=True)
        digests[arch] = digest
    candidate_tag = f"{public}:verified-{commit}"
    existing = registry_digest(candidate_tag)
    if existing is None:
        subprocess.run([
            "docker", "buildx", "imagetools", "create", "--tag", candidate_tag,
            *[f"{public}@{record['digest']}" for record in sorted(records, key=lambda r: r["platform"])],
        ], check=True)
    raw = json.loads(subprocess.check_output(["skopeo", "inspect", "--raw", "docker://" + candidate_tag]))
    children = raw.get("manifests", [])
    expected = {r["platform"]: r["digest"] for r in records}
    actual_children = {f"{m.get('platform', {}).get('os')}/{m.get('platform', {}).get('architecture')}":
                       m.get("digest") for m in children}
    if len(children) != 2 or actual_children != expected:
        raise ValueError("published manifest does not contain exactly the qualified platform digests")
    manifest = subprocess.check_output([
        "skopeo", "inspect", "--format", "{{.Digest}}", "docker://" + candidate_tag,
    ], text=True).strip()
    subprocess.run(["cosign", "sign", "--yes", f"{public}@{manifest}"], check=True)
    Path(sys.argv[2]).write_text(json.dumps({
        "schema_version": 1, "commit": commit, "image": public,
        "manifest_digest": manifest, "platforms": records,
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        output.write(f"digest={manifest}\n")
        for arch, digest in digests.items():
            output.write(f"{arch}_digest={digest}\n")


if __name__ == "__main__":
    main()
