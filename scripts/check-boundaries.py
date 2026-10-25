#!/usr/bin/env python3
"""Enforce the import boundaries that keep the package layered.

Three rules (each output as ``path:line: rule: detail``):

``mcp-only-in-server``
    Only ``server.py`` may import ``mcp`` (MCPServer or its types).
``no-server-imports``
    No package module may import ``opencyber.server``; the server wires the
    package, never the other way round.
``contract-modules-stay-light``
    ``errors``, ``limits``, ``contracts``, ``catalog_identity``, and ``envelope``
    are imported by the doctor and the doc generators, so they must not pull in
    Playwright, HTTP, browser, hardware, or native-tool dependencies.
"""

from __future__ import annotations

import argparse
import ast
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src" / "opencyber"

MCP_RULE = "mcp-only-in-server"
SERVER_RULE = "no-server-imports"
LIGHT_RULE = "contract-modules-stay-light"
LIGHT_MODULES = {"errors.py", "limits.py", "contracts.py", "catalog_identity.py", "envelope.py"}
LIGHT_FORBIDDEN = {"playwright", "requests", "opencyber.browser", "opencyber.hardware", "opencyber.native_tools"}

# Keyed by (module filename, rule). Empty today: keep exceptions visible and
# narrow rather than adding a blanket ignore to the checker.
ALLOWLIST: dict[tuple[str, str], str] = {}

# (line, rule, detail)
Violation = tuple[int, str, str]


def _matches(name: str, prefix: str) -> bool:
    return name == prefix or name.startswith(f"{prefix}.")


def _targets(node: ast.AST) -> list[tuple[str, int]]:
    """Expand one import node into the fully qualified names it can reach."""
    if isinstance(node, ast.Import):
        return [(alias.name, node.lineno) for alias in node.names]
    if isinstance(node, ast.ImportFrom):
        base = node.module or ""
        if node.level == 1:
            base = f"opencyber.{base}" if base else "opencyber"
        elif node.level > 1:
            base = base  # above the package root: no local module to resolve
        targets = [(base, node.lineno)] if base else []
        targets.extend(
            (f"{base}.{alias.name}" if base else alias.name, node.lineno)
            for alias in node.names
            if alias.name != "*"
        )
        return targets
    return []


def scan_source(source: str, path: str) -> list[Violation]:
    """Return the boundary violations in one module, sorted by source location."""
    filename = Path(path).name
    tree = ast.parse(source, filename=path)
    violations: list[Violation] = []
    for node in ast.walk(tree):
        targets = _targets(node)
        if not targets:
            continue
        line = targets[0][1]

        if filename != "server.py":
            hit = next((target for target, _ in targets if _matches(target, "mcp")), None)
            if hit:
                violations.append((line, MCP_RULE, f"{hit} may only be imported from server.py"))

        hit = next((target for target, _ in targets if _matches(target, "opencyber.server")), None)
        if hit:
            violations.append((line, SERVER_RULE, f"{hit} imports the server; dependencies point the other way"))

        if filename in LIGHT_MODULES:
            forbidden = sorted(
                item for item in LIGHT_FORBIDDEN if any(_matches(target, item) for target, _ in targets)
            )
            if forbidden:
                violations.append((line, LIGHT_RULE, f"{', '.join(forbidden)} not allowed in {filename}"))

    return sorted(set(violations))


def scan_tree(root: Path = SOURCE) -> list[tuple[str, int, str, str]]:
    """Scan every top-level package module and apply the narrow allowlist."""
    violations: list[tuple[str, int, str, str]] = []
    for path in sorted(root.glob("*.py")):
        relative = path.relative_to(ROOT).as_posix()
        try:
            found = scan_source(path.read_text(encoding="utf-8"), relative)
        except SyntaxError as error:
            violations.append((relative, error.lineno or 0, "syntax-error", str(error)))
            continue
        for line, rule, detail in found:
            if (path.name, rule) not in ALLOWLIST:
                violations.append((relative, line, rule, detail))
    return violations


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json", action="store_true", help="emit a machine-readable JSON array")
    args = parser.parse_args()

    violations = scan_tree()
    if args.json:
        print(
            json.dumps(
                [
                    {"path": path, "line": line, "rule": rule, "detail": detail}
                    for path, line, rule, detail in violations
                ],
                indent=2,
            )
        )
    else:
        for path, line, rule, detail in violations:
            print(f"{path}:{line}: {rule}: {detail}", file=sys.stderr)
        if violations:
            print(f"{len(violations)} import boundary violation(s)", file=sys.stderr)

    if violations:
        return 1
    if not args.json:
        print(f"import boundaries OK: {len(list(SOURCE.glob('*.py')))} modules, {len(ALLOWLIST)} allowlisted")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
