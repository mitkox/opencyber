#!/usr/bin/env python3
"""Record the advertised MCP catalog identity.

Imports the real server registration, projects every advertised tool into the
digested form, and writes ``src/opencyber/data/catalog.json``. ``--check`` fails
when the tracked file is stale, so a contract change is always a deliberate,
reviewable diff rather than a silent drift.

The recorder refuses to run under a narrowed tool mode: the tracked manifest is
the full catalog, and a compact-mode manifest would make every aligned server
look changed.
"""

from __future__ import annotations

import argparse
import importlib
import os
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "scripts"))

from lib.generated import StaleGeneratedFile, ensure_generated_file  # noqa: E402


MANIFEST = ROOT / "src" / "opencyber" / "data" / "catalog.json"
GENERATE_COMMAND = "python scripts/record-catalog.py"


def _full_mode_server():
    """Import the server with every narrowing environment variable removed."""
    for variable in ("OPENCYBER_MCP_MODE", "OPENCYBER_TOOL_CATEGORIES"):
        os.environ.pop(variable, None)
    return importlib.import_module("opencyber.server")


def render() -> str:
    from opencyber import __version__
    from opencyber.catalog_identity import project_tools, render_manifest
    from opencyber.contracts import CONTRACTS

    server = _full_mode_server()
    tools = server.mcp._tool_manager._tools
    entries = project_tools(tools)
    expected = {contract.name for contract in CONTRACTS.values()}
    missing = sorted(expected - set(tools))
    if missing:
        raise SystemExit(
            "refusing to record a partial catalog; these contracted tools are not registered: "
            + ", ".join(missing[:10])
        )
    return render_manifest(entries, server_version=__version__)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if the tracked manifest is stale instead of writing it")
    args = parser.parse_args()
    try:
        wrote = ensure_generated_file(MANIFEST, render(), check=args.check, generate_command=GENERATE_COMMAND)
    except StaleGeneratedFile as error:
        print(str(error), file=sys.stderr)
        return 1
    if args.check:
        print(f"{MANIFEST.relative_to(ROOT)} is current")
    else:
        print(f"{'wrote' if wrote else 'unchanged'} {MANIFEST.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
