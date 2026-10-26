#!/usr/bin/env python3
"""Verify a captured source tree, optionally against a tested runtime inventory."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import tarfile


DIRECT_ASSETS = {"docker-bench-security", "nuclei-templates", "seclists", "wpscan-metadata"}


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            value.update(chunk)
    return value.hexdigest()


def direct_archive_digest(path: Path) -> str:
    records = {}
    root_name = None
    total_bytes = 0
    try:
        with tarfile.open(path, "r:gz") as archive:
            for index, member in enumerate(archive):
                name = PurePosixPath(member.name)
                if (index >= 100_000 or name.is_absolute() or ".." in name.parts
                        or str(name) != member.name or ".git" in name.parts):
                    raise ValueError("unsafe direct source archive member")
                if root_name is None:
                    if not member.isdir() or len(name.parts) != 1:
                        raise ValueError("direct source archive must start with its root directory")
                    root_name = name.parts[0]
                    continue
                if not name.parts or name.parts[0] != root_name or len(name.parts) < 2:
                    raise ValueError("direct source archive has inconsistent root")
                relative = PurePosixPath(*name.parts[1:]).as_posix()
                if relative in records:
                    raise ValueError("duplicate direct source archive member")
                if member.issym():
                    record = ("symlink", member.linkname)
                elif member.islnk():
                    target = PurePosixPath(member.linkname)
                    if (not target.parts or target.is_absolute() or ".." in target.parts
                            or target.parts[0] != root_name):
                        raise ValueError("unsafe direct source archive hard link")
                    record = records.get(PurePosixPath(*target.parts[1:]).as_posix())
                    if record is None or record[0] != "file-sha256":
                        raise ValueError("unresolved direct source archive hard link")
                elif member.isfile():
                    if member.size > 16 * 1024 ** 3:
                        raise ValueError("direct source archive exceeds data limit")
                    value = hashlib.sha256()
                    with archive.extractfile(member) as handle:
                        while chunk := handle.read(1024 * 1024):
                            total_bytes += len(chunk)
                            if total_bytes > 16 * 1024 ** 3:
                                raise ValueError("direct source archive exceeds data limit")
                            value.update(chunk)
                    record = ("file-sha256", value.hexdigest())
                elif member.isdir():
                    record = ("directory", "")
                else:
                    raise ValueError("unsupported direct source archive member")
                records[relative] = record
    except (tarfile.TarError, OSError, KeyError) as error:
        raise ValueError(f"invalid direct source archive: {path.name}") from error
    if root_name is None:
        raise ValueError("empty direct source archive")
    return hashlib.sha256(json.dumps(records, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def verify(root: Path, runtime_inventory: Path | None = None, platform: str | None = None,
           runtime_ecosystems: Path | None = None) -> dict:
    if root.is_symlink() or not root.is_dir():
        raise ValueError("source root must be a real directory")
    manifest_path = root / "source-manifest.json"
    if manifest_path.is_symlink():
        raise ValueError("source manifest must not be a symlink")
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("schema") != "opencyber.corresponding-source/v1" or manifest.get("complete") is not True:
        raise ValueError("missing or incomplete versioned source manifest")
    if manifest.get("platform") not in {"linux/amd64", "linux/arm64"}:
        raise ValueError("unsupported source platform")
    if platform and manifest["platform"] != platform:
        raise ValueError("source platform does not match tested runtime")
    recorded: dict[str, dict] = {}
    for item in manifest["artifacts"]:
        name = item["path"]
        relative = PurePosixPath(name)
        if not name or relative.is_absolute() or ".." in relative.parts or str(relative) != name or name in recorded:
            raise ValueError("unsafe or duplicate source artifact")
        path = root / name
        if any(parent.is_symlink() for parent in [path, *path.parents] if parent != root.parent):
            raise ValueError("symlink source artifact")
        if not path.is_file() or path.stat().st_size != item["bytes"] or digest(path) != item["sha256"]:
            raise ValueError(f"missing or modified source artifact: {name}")
        recorded[name] = item
    actual = {str(path.relative_to(root)) for path in root.rglob("*") if not path.is_dir() or path.is_symlink()}
    if actual != set(recorded) | {"source-manifest.json"}:
        raise ValueError("unlisted or missing source artifacts")
    if "runtime-dpkg.tsv" not in recorded or "runtime-ecosystems.json" not in recorded:
        raise ValueError("runtime inventory missing")
    inventory = (root / "runtime-dpkg.tsv").read_text()
    ecosystems = json.loads((root / "runtime-ecosystems.json").read_text())
    first_party = ecosystems.get("first_party_sha256", {})
    if not isinstance(first_party, dict) or "src/opencyber/__init__.py" not in first_party or any(
        not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value) for value in first_party.values()
    ):
        raise ValueError("first-party source hash inventory is missing or invalid")
    direct_assets = ecosystems.get("direct_assets_sha256")
    if (not isinstance(direct_assets, dict)
            or set(direct_assets) != DIRECT_ASSETS
            or any(not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value)
                   for value in direct_assets.values())):
        raise ValueError("direct asset hash inventory is missing or invalid")
    if runtime_inventory and inventory != runtime_inventory.read_text():
        raise ValueError("captured source inventory differs from tested runtime")
    if runtime_ecosystems and ecosystems != json.loads(runtime_ecosystems.read_text()):
        raise ValueError("captured ecosystem inventory differs from tested runtime")
    covered = set()
    seen = set()
    for package in manifest["packages"]:
        identity = (package["kind"], package["name"], package["version"])
        if identity in seen or not package["name"] or not package["version"]:
            raise ValueError("duplicate or incomplete source package identity")
        seen.add(identity)
        archives = package.get("archives", [])
        if package["source_status"] == "captured":
            if not archives or any(name not in recorded for name in archives):
                raise ValueError(f"source payload missing for {identity}")
        elif package["source_status"] == "notice-only":
            # A release can waive source only for an explicit permissive license.
            expression = package.get("license_expression", "")
            classifiers = package.get("license_classifiers", [])
            allowed = {"MIT", "ISC", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "PSF-2.0", "Zlib", "Unlicense"}
            classifier_allowed = {"License :: OSI Approved :: MIT License", "License :: OSI Approved :: Apache Software License",
                                  "License :: OSI Approved :: BSD License", "License :: OSI Approved :: ISC License (ISCL)",
                                  "License :: OSI Approved :: Python Software Foundation License"}
            if not package.get("decision") or (expression not in allowed and not (
                not expression and classifiers and all(value in classifier_allowed for value in classifiers)
            )):
                raise ValueError(f"unresolved source exemption: {identity}")
        else:
            raise ValueError(f"unresolved source package: {identity}")
        if package["kind"] == "debian":
            if not any(name.endswith(".dsc") for name in archives):
                raise ValueError("Debian source descriptor missing")
            for binary in package["binaries"]:
                covered.add((package["name"], package["version"], binary["name"], binary["version"]))
        if package.get("binary_sha256") and not re.fullmatch(r"[0-9a-f]{64}", package["binary_sha256"]):
            raise ValueError("invalid source binary identity")
    expected = {tuple(line.split("\t")) for line in inventory.splitlines() if line}
    if not expected or any(len(item) != 4 for item in expected) or expected != covered:
        raise ValueError("installed Debian package source coverage is incomplete")
    for ecosystem in ("python", "ruby"):
        expected_packages = {(item["name"], item["version"]) for item in ecosystems[ecosystem]}
        actual_packages = {(package["name"], package["version"]) for package in manifest["packages"]
                           if package["kind"] == ecosystem}
        if expected_packages != actual_packages:
            raise ValueError(f"installed {ecosystem} source coverage is incomplete")
    direct_entries = [package for package in manifest["packages"]
                      if package["kind"] == "direct" and package["name"] in DIRECT_ASSETS]
    direct_packages = {package["name"]: package for package in direct_entries}
    if len(direct_entries) != len(DIRECT_ASSETS) or set(direct_packages) != DIRECT_ASSETS:
        raise ValueError("direct source archive coverage is incomplete")
    for name, package in direct_packages.items():
        archives = package["archives"]
        if (len(archives) != 1 or package["source_status"] != "captured"
                or package["version"] != "sha256:" + recorded[archives[0]]["sha256"]):
            raise ValueError(f"direct source archive identity mismatch: {name}")
        if direct_archive_digest(root / archives[0]) != direct_assets[name]:
            raise ValueError(f"direct source archive differs from recorded assets: {name}")
    return manifest


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--runtime-inventory", type=Path)
    parser.add_argument("--platform")
    parser.add_argument("--runtime-ecosystems", type=Path)
    args = parser.parse_args()
    try:
        manifest = verify(args.directory, args.runtime_inventory, args.platform, args.runtime_ecosystems)
    except (ValueError, OSError, KeyError, TypeError) as exc:
        raise SystemExit(f"corresponding-source verification failed: {exc}") from exc
    print(f"Verified {len(manifest['packages'])} source components and {len(manifest['artifacts'])} artifacts.")


if __name__ == "__main__":
    main()
