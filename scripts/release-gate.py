#!/usr/bin/env python3
"""Validate private staging and bind release evidence to tested image bytes."""
from __future__ import annotations

import argparse
from datetime import date
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parent))
from lib.release_candidates import fetch_selection, safe_extract, selection_for, sha256 as file_sha256, upload_assets
from lib.qualification import validate_qualification


DIGEST = re.compile(r"sha256:[a-f0-9]{64}")
PLATFORMS = {"linux/amd64", "linux/arm64"}


def verify_source_receipt(source: Path, image_id: str) -> None:
    receipt = json.loads(source.read_text(encoding="utf-8"))
    manifest = source.parent / "source-manifest.json"
    if receipt.get("complete") is not True or receipt.get("image_id") != image_id:
        raise ValueError("source evidence must be complete and belong to the tested image")
    if receipt.get("source_manifest_sha256") != file_sha256(manifest):
        raise ValueError("captured source manifest checksum mismatch")
    if json.loads(manifest.read_text(encoding="utf-8")).get("complete") is not True:
        raise ValueError("captured corresponding source is incomplete")
    expected = {"corresponding-source.tar.gz", "source-manifest.json", "release-source-manifest.json"}
    entries = (source.parent / "SOURCE-SHA256SUMS").read_text(encoding="utf-8").splitlines()
    seen = set()
    for entry in entries:
        digest, name = entry.split("  ", 1)
        if name not in expected or name in seen or file_sha256(source.parent / name) != digest:
            raise ValueError("corresponding-source payload checksum mismatch")
        seen.add(name)
    if seen != expected:
        raise ValueError("corresponding-source payload checksum inventory is incomplete")


def command(*args: str) -> bytes:
    return subprocess.run(args, check=True, capture_output=True).stdout


def verify_registry(package: str, reference: str, visibility: str) -> None:
    owner, name = package.split("/", 1)
    if reference.split(":", 1)[0].split("@", 1)[0] != f"ghcr.io/{package}":
        raise ValueError("registry probe must address the selected package")
    metadata = json.loads(command("gh", "api", f"orgs/{quote(owner)}/packages/container/{quote(name, safe='')}"))
    if metadata.get("visibility") != visibility:
        raise ValueError(f"package visibility must be verified {visibility}; received {metadata.get('visibility')!r}")
    with tempfile.TemporaryDirectory() as directory:
        auth = Path(directory, "anonymous.json")
        auth.write_text('{"auths":{}}', encoding="utf-8")
        probe = subprocess.run(
            ["skopeo", "inspect", "--authfile", str(auth), f"docker://{reference}"],
            capture_output=True, text=True, check=False,
        )
    if visibility == "public":
        if probe.returncode:
            raise ValueError("public package bootstrap must be anonymously accessible before promotion")
        return
    denial = re.search(r"unauthorized|denied|authentication required|status code: (401|403)", probe.stderr, re.I)
    if probe.returncode == 0 or not denial:
        raise ValueError("anonymous staging access must be denied; network errors are not proof of privacy")


def verify_staging(package: str, reference: str) -> None:
    verify_registry(package, reference, "private")


def record_image(image: str, staged: str, platform: str, source: Path, commit: str, output: Path) -> None:
    if platform not in PLATFORMS:
        raise ValueError("unsupported release platform")
    local = json.loads(command("docker", "image", "inspect", image))[0]
    verify_source_receipt(source, local["Id"])
    remote = json.loads(command("skopeo", "inspect", f"docker://{staged}"))
    digest = remote["Digest"]
    manifest = json.loads(command("skopeo", "inspect", "--raw", f"docker://{staged.split(':')[0]}@{digest}"))
    config_digest = manifest.get("config", {}).get("digest", "")
    descriptor = local.get("Descriptor")
    if descriptor:
        # Containerd reports the manifest ID; the classic Docker store reports
        # the config ID. Require the corresponding identity, never interchange
        # them. Candidate builds disable provenance and load one platform.
        same_image = (descriptor.get("mediaType") in {
            "application/vnd.oci.image.manifest.v1+json",
            "application/vnd.docker.distribution.manifest.v2+json",
        } and descriptor.get("digest") == local["Id"] == digest)
    else:
        same_image = config_digest == local["Id"]
    if not DIGEST.fullmatch(digest) or not DIGEST.fullmatch(config_digest) or not same_image:
        raise ValueError("staged single-platform image differs from the tested image")
    if f"{remote['Os']}/{remote['Architecture']}" != platform:
        raise ValueError("staged image platform mismatch")
    report = json.loads(command("docker", "run", "--rm", "--network", "none", "--entrypoint",
                                "opencyber-mcp", image, "--self-test"))
    catalog = report.get("catalog", {})
    if catalog.get("matches") is not True or not re.fullmatch(r"[a-f0-9]{64}", catalog.get("advertised_sha256", "")):
        raise ValueError("candidate must advertise its recorded catalog")
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps({
        "schema_version": 1, "platform": platform, "commit": commit,
        "image_id": local["Id"], "digest": digest, "config_digest": config_digest,
        "staging_reference": f"{staged.split(':')[0]}@{digest}",
        "source_manifest": source.name,
        "source_manifest_sha256": file_sha256(source),
        "catalog_sha256": catalog["advertised_sha256"],
        "repository_id": int(os.environ["GITHUB_REPOSITORY_ID"]),
        "run_id": int(os.environ["GITHUB_RUN_ID"]),
        "run_attempt": int(os.environ["GITHUB_RUN_ATTEMPT"]),
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def validate_records(directory: Path, commit: str) -> list[dict]:
    records = []
    seen = set()
    for path in sorted(directory.rglob("*.record.json")):
        record = json.loads(path.read_text(encoding="utf-8"))
        platform = record.get("platform")
        if platform not in PLATFORMS or platform in seen or record.get("commit") != commit:
            raise ValueError("release requires distinct platforms verified at the same commit")
        if not DIGEST.fullmatch(record.get("digest", "")) or not DIGEST.fullmatch(record.get("image_id", "")):
            raise ValueError("invalid candidate image digest")
        source_name = record.get("source_manifest", "")
        if not source_name or Path(source_name).name != source_name:
            raise ValueError("invalid source manifest path")
        source = path.parent / source_name
        if file_sha256(source) != record.get("source_manifest_sha256"):
            raise ValueError("source manifest checksum mismatch")
        verify_source_receipt(source, record["image_id"])
        seen.add(platform)
        records.append(record)
    if seen != PLATFORMS:
        raise ValueError("both amd64 and arm64 must pass before public promotion")
    return records


def verify_exceptions(path: Path) -> None:
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        owner = re.search(r"\bowner:\s*(@[\w-]+)", line)
        expiry = re.search(r"\bexpires:\s*(\d{4}-\d{2}-\d{2})", line)
        reason = re.search(r"\breason:\s*\S", line)
        if not owner or not expiry or not reason or date.fromisoformat(expiry[1]) < date.today():
            raise ValueError(f"{path}:{number}: vulnerability exception requires an owner, unexpired date and reason")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    staging = sub.add_parser("staging")
    staging.add_argument("package")
    staging.add_argument("reference")
    public = sub.add_parser("public")
    public.add_argument("package")
    public.add_argument("reference")
    record = sub.add_parser("record")
    for flag in ("image", "staged", "platform", "commit"):
        record.add_argument(f"--{flag}", required=True)
    record.add_argument("--source", required=True, type=Path)
    record.add_argument("--output", required=True, type=Path)
    validate = sub.add_parser("validate")
    validate.add_argument("directory", type=Path)
    validate.add_argument("--commit", required=True)
    select = sub.add_parser("select", help="freeze a successful native candidate build")
    select.add_argument("--run-id", required=True, type=int)
    select.add_argument("--commit", required=True)
    select.add_argument("--output", required=True, type=Path)
    fetch = sub.add_parser("fetch", help="revalidate and download a frozen cross-run selection")
    fetch.add_argument("--selection", required=True, type=Path)
    fetch.add_argument("--sha256", required=True)
    fetch.add_argument("--run-id", required=True, type=int)
    fetch.add_argument("--commit", required=True)
    fetch.add_argument("--output", required=True, type=Path)
    qualify = sub.add_parser("qualify", help="validate a checksummed operator evidence archive")
    qualify.add_argument("--archive", required=True, type=Path)
    qualify.add_argument("--sha256", required=True)
    qualify.add_argument("--records", required=True, type=Path)
    qualify.add_argument("--run-id", required=True, type=int)
    qualify.add_argument("--commit", required=True)
    qualify.add_argument("--output", required=True, type=Path)
    assets = sub.add_parser("assets", help="upload release assets without replacing existing bytes")
    assets.add_argument("tag")
    assets.add_argument("directory", type=Path)
    exceptions = sub.add_parser("exceptions")
    exceptions.add_argument("path", type=Path)
    args = parser.parse_args()
    if args.action == "staging":
        verify_staging(args.package, args.reference)
    elif args.action == "public":
        verify_registry(args.package, args.reference, "public")
    elif args.action == "record":
        record_image(args.image, args.staged, args.platform, args.source, args.commit, args.output)
    elif args.action == "validate":
        print(json.dumps(validate_records(args.directory, args.commit), sort_keys=True))
    elif args.action == "select":
        selected = selection_for(os.environ.get("GITHUB_REPOSITORY", "mitkox-dev/opencyber"), args.run_id, args.commit)
        with args.output.open("x", encoding="utf-8") as output:
            output.write(json.dumps(selected, indent=2, sort_keys=True) + "\n")
        print(file_sha256(args.output))
    elif args.action == "fetch":
        selected = fetch_selection(args.selection, args.sha256, args.output,
                                   repository=os.environ["GITHUB_REPOSITORY"], run_id=args.run_id, commit=args.commit)
        records = validate_records(args.output, args.commit)
        for record in records:
            for key in ("repository_id", "run_id", "run_attempt"):
                if record.get(key) != selected[key]:
                    raise ValueError("receipt belongs to another repository, run or build attempt")
        print(json.dumps(records, sort_keys=True))
    elif args.action == "qualify":
        if not re.fullmatch(r"[a-f0-9]{64}", args.sha256) or file_sha256(args.archive) != args.sha256:
            raise ValueError("qualification archive checksum mismatch")
        safe_extract(args.archive, args.output)
        qualification = validate_qualification(args.output / "qualification.json", commit=args.commit,
                                               records=json.loads(args.records.read_text(encoding="utf-8")))
        if qualification["candidate_run_id"] != args.run_id:
            raise ValueError("hardware qualification belongs to a different candidate run")
        print(json.dumps({"schema_version": 1, "status": "qualified", "commit": args.commit,
                          "candidate_run_id": args.run_id, "catalog_sha256": qualification["catalog_sha256"],
                          "domains": [{"domain": r["domain"], "platform": r["platform"],
                                       "device": r["device"]} for r in qualification["domains"]]}))
    elif args.action == "assets":
        upload_assets(os.environ["GITHUB_REPOSITORY"], args.tag, args.directory)
    else:
        verify_exceptions(args.path)


if __name__ == "__main__":
    main()
