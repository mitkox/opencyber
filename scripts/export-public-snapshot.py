#!/usr/bin/env python3
"""Export reviewed committed bytes without importing development history."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import subprocess


DIRECTORIES = {".github", "compliance", "docs", "integrations", "packaging", "scripts", "src", "tests"}
FILES = {".dockerignore", ".editorconfig", ".gitignore", ".pre-commit-config.yaml", ".trivyignore", "AGENTS.md",
         "CHANGELOG.md", "CODE_OF_CONDUCT.md", "CONTRIBUTING.md", "Dockerfile", "LICENSE", "Makefile",
         "README.md", "SECURITY.md", "SOURCE_OFFER.md", "SUPPORT.md", "THIRD_PARTY_NOTICES.md", "pyproject.toml", "install.sh"}


def git(root: Path, *arguments: str) -> bytes:
    return subprocess.check_output(["git", "-C", str(root), *arguments])


def export(root: Path, output: Path, manifest: Path) -> None:
    if git(root, "status", "--porcelain", "--untracked-files=all").strip():
        raise ValueError("public export requires a clean, reviewed committed snapshot")
    if output.exists() or output.is_symlink() or manifest.exists() or manifest.is_symlink():
        raise ValueError("export output and manifest must not already exist")
    if manifest.resolve().is_relative_to(output.resolve()):
        raise ValueError("export manifest must remain outside the frozen public tree")
    selected = []
    for entry in git(root, "ls-tree", "-rz", "HEAD").split(b"\0"):
        if not entry:
            continue
        metadata, raw_path = entry.split(b"\t", 1)
        mode, kind, identity = metadata.decode().split()
        name = raw_path.decode("utf-8")
        path = PurePosixPath(name)
        if name.startswith("docs/verification/"):
            continue
        if (path.is_absolute() or ".." in path.parts or "\n" in name or "\\" in name
                or (path.parts[0] not in DIRECTORIES and name not in FILES)
                or kind != "blob" or mode not in {"100644", "100755"}):
            raise ValueError(f"tracked path needs explicit public-export review: {name}")
        content = git(root, "cat-file", "blob", identity)
        selected.append((name, mode, content))
    if not selected:
        raise ValueError("public snapshot cannot be empty")
    output.mkdir(parents=True)
    records = []
    for name, mode, content in selected:
        destination = output / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        with destination.open("xb") as handle:
            handle.write(content)
        destination.chmod(0o755 if mode == "100755" else 0o644)
        records.append({"path": name, "mode": mode, "sha256": hashlib.sha256(content).hexdigest()})
    with manifest.open("x", encoding="utf-8") as handle:
        json.dump({"schema_version": 1, "files": records}, handle, indent=2, sort_keys=True)
        handle.write("\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args()
    export(args.root, args.output, args.manifest)
    print(f"exported reviewed source to {args.output}; manifest: {args.manifest}")


if __name__ == "__main__":
    main()
