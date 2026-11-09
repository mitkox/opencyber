#!/usr/bin/env python3
"""Fail when a release version is declared somewhere other than the package.

`src/opencyber/__init__.py` is the source of truth. Shell scripts, the
Dockerfile, and the publish workflow cannot import Python, so they carry an
alias that this script keeps honest.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION_SOURCE = ROOT / "src" / "opencyber" / "__init__.py"

# (path, regex with one capture group holding the declared version)
ALIASES = [
    (ROOT / "Dockerfile", r"^ARG OPENCYBER_VERSION=(\S+)$"),
    (ROOT / "install.sh", r'^readonly DEFAULT_VERSION="([^"]+)"$'),
    (ROOT / "scripts" / "opencyber-run.sh", r'^readonly DEFAULT_IMAGE="opencyber:([^"]+)"$'),
    (ROOT / "scripts" / "opencyber-airgap.sh", r'^readonly DEFAULT_IMAGE="opencyber:([^"]+)"$'),
    (ROOT / "scripts" / "publish-image.sh", r"^version=\$\{2:-(\S+)\}$"),
    (ROOT / "scripts" / "airgap-tools-lab.py", r'^EXPECTED_VERSION = "([^"]+)"$'),
    (ROOT / "scripts" / "airgap-tools-image.sh", r'^readonly EXPECTED_VERSION="([^"]+)"$'),
    (ROOT / ".github" / "workflows" / "build-candidate.yml", r"^\s+default: (\S+)$"),
    (ROOT / ".github" / "workflows" / "publish-container.yml", r"^\s+default: (\S+)$"),
]


def read_source_version() -> str:
    match = re.search(r'^__version__\s*=\s*"([^"]+)"', VERSION_SOURCE.read_text(encoding="utf-8"), re.MULTILINE)
    if not match:
        raise SystemExit(f"could not find __version__ in {VERSION_SOURCE}")
    return match.group(1)


def check() -> list[str]:
    expected = read_source_version()
    problems: list[str] = []
    for path, pattern in ALIASES:
        text = path.read_text(encoding="utf-8")
        match = re.search(pattern, text, re.MULTILINE)
        if not match:
            problems.append(f"{path.relative_to(ROOT)}: could not find version declaration matching {pattern!r}")
            continue
        found = match.group(1)
        if found != expected:
            problems.append(
                f"{path.relative_to(ROOT)}: declares {found}, but src/opencyber/__init__.py declares {expected}"
            )
    return problems


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--print", action="store_true", help="print the source-of-truth version and exit")
    args = parser.parse_args()

    version = read_source_version()
    if args.print:
        print(version)
        return 0

    problems = check()
    if problems:
        print("version declarations disagree:", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        return 1

    print(f"version {version} is consistent across {len(ALIASES)} declarations")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
