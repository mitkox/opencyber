#!/usr/bin/env python3
"""Verify every file under ``tests/`` is either discovered or explicitly manual.

``python -m unittest discover -s tests`` uses the ``test*.py`` default pattern,
which is wider than pytest's ``test_*.py``. A file can therefore look like a
test but silently never run. This script loads the discovery suite in-process
and compares the modules that actually contributed tests with the files tracked
in ``tests/``. Manual stdio harnesses must be listed below, so adding another
one is a deliberate review edit instead of a silently skipped file.
"""

from __future__ import annotations

import subprocess
import sys
import unittest
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TESTS = ROOT / "tests"

# Manual JSON-RPC stdio harnesses driven by the image smoke workflow. They need
# a live server or container and are not unit tests, so discovery must skip them.
MANUAL = {"mcp_smoke.py", "mcp_epic_smoke.py", "blue_team_smoke.py"}


@dataclass(frozen=True)
class Report:
    """Test files that discovery did not account for, grouped by cause."""

    uncollected: list[str]
    empty: list[str]
    missing: list[str]

    @property
    def ok(self) -> bool:
        return not (self.uncollected or self.empty or self.missing)


def classify(
    discovered: set[str],
    tracked: set[str],
    manual: set[str] = MANUAL,
    missing: list[str] | None = None,
) -> Report:
    """Bucket test files relative to the files that contributed a TestCase.

    ``discovered`` holds basenames that yielded at least one test. A tracked
    ``test_*.py`` file that yielded none is ``empty``; any other tracked file
    that discovery never loaded is ``uncollected`` unless it is a manual
    harness. ``missing`` covers loaded modules that had no source file on disk.
    """
    empty = sorted(name for name in tracked - discovered if name.startswith("test_"))
    uncollected = sorted(tracked - discovered - set(manual) - set(empty) - {"__init__.py"})
    return Report(uncollected=uncollected, empty=empty, missing=sorted(missing or []))


def _walk(suite: unittest.TestSuite) -> tuple[set[str], list[str], int]:
    modules: set[str] = set()
    broken: list[str] = []
    count = 0

    def visit(node: unittest.TestSuite) -> None:
        nonlocal count
        for item in node:
            if isinstance(item, unittest.TestSuite):
                visit(item)
            elif type(item).__name__ == "_FailedTest":
                broken.append(str(getattr(item, "_exception", "import failed")))
            else:
                modules.add(type(item).__module__)
                count += 1

    visit(suite)
    return modules, broken, count


def discover(test_dir: Path = TESTS) -> tuple[set[str], list[str], list[str], int]:
    """Run unittest discovery and resolve its modules back to ``tests/*.py``."""
    # Tests may import repository-owned script helpers as well as the package.
    sys.path.insert(0, str(test_dir.resolve().parent))
    suite = unittest.TestLoader().discover(str(test_dir))
    module_names, broken, count = _walk(suite)
    resolved: set[str] = set()
    missing: list[str] = []
    root = test_dir.resolve()
    for name in sorted(module_names):
        module = sys.modules.get(name)
        source = getattr(module, "__file__", None)
        if not source:
            missing.append(f"{name} (no source file)")
            continue
        path = Path(source).resolve()
        try:
            relative = path.relative_to(root)
        except ValueError:
            missing.append(f"{name} -> {path} (outside tests/)")
            continue
        if relative.parent != Path("."):
            missing.append(f"{name} -> {relative} (not a top-level test file)")
            continue
        resolved.add(relative.name)
    return resolved, missing, broken, count


def tracked_files() -> set[str]:
    """Return ``tests/*.py`` from git, falling back to a glob outside a checkout."""
    try:
        result = subprocess.run(
            ["git", "ls-files", "tests/*.py"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError:
        result = None
    if result is not None and result.returncode == 0:
        return {Path(line).name for line in result.stdout.splitlines() if line.strip()}
    return {path.name for path in TESTS.glob("*.py")}


def main() -> int:
    discovered, missing, broken, test_count = discover()
    report = classify(discovered, tracked_files(), MANUAL, missing)

    if broken or not report.ok:
        print("test discovery check failed:", file=sys.stderr)
        for name in report.uncollected:
            print(f"  uncollected: tests/{name} is not discovered and is not in MANUAL", file=sys.stderr)
        for name in report.empty:
            print(f"  empty: tests/{name} is named like a test but contributes no TestCase", file=sys.stderr)
        for name in report.missing:
            print(f"  missing: {name}", file=sys.stderr)
        for failure in broken:
            print(f"  import error: {failure}", file=sys.stderr)
        print(
            "Add tests to the file, rename it, or add it to MANUAL in scripts/check-test-discovery.py.",
            file=sys.stderr,
        )
        return 1

    print(
        f"test discovery OK: {len(discovered)} modules / {test_count} tests; "
        f"{len(MANUAL)} manual harness(es) allowlisted"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
