from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
SCRIPTS = ROOT / "scripts"


def _load_script(filename: str, module_name: str):
    """Import a hyphenated script as a module without running its CLI."""
    spec = importlib.util.spec_from_file_location(module_name, SCRIPTS / filename)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def _run(script: str, *arguments: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join(filter(None, [str(ROOT / "src"), env.get("PYTHONPATH")]))
    return subprocess.run(
        [sys.executable, str(SCRIPTS / script), *arguments],
        cwd=ROOT,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )


class GuardScriptTests(unittest.TestCase):
    def test_test_discovery_guard_passes(self) -> None:
        result = _run("check-test-discovery.py")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("test discovery OK", result.stdout)

    def test_boundary_guard_passes(self) -> None:
        result = _run("check-boundaries.py")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("import boundaries OK", result.stdout)

    def test_boundary_json_output_is_machine_readable(self) -> None:
        result = _run("check-boundaries.py", "--json")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(json.loads(result.stdout), [])


class DiscoveryClassificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.discovery = _load_script("check-test-discovery.py", "guards_test_discovery")

    def test_manual_harness_is_allowlisted(self) -> None:
        report = self.discovery.classify({"test_a.py"}, {"test_a.py", "mcp_smoke.py"}, manual={"mcp_smoke.py"})
        self.assertTrue(report.ok)

    def test_a_new_harness_must_be_allowlisted(self) -> None:
        report = self.discovery.classify({"test_a.py"}, {"test_a.py", "new_smoke.py"})
        self.assertEqual(report.uncollected, ["new_smoke.py"])
        self.assertFalse(report.ok)

    def test_a_test_named_file_without_tests_is_empty(self) -> None:
        report = self.discovery.classify({"test_a.py"}, {"test_a.py", "test_empty.py"})
        self.assertEqual(report.empty, ["test_empty.py"])
        self.assertEqual(report.uncollected, [])

    def test_unresolved_module_is_missing(self) -> None:
        report = self.discovery.classify(
            {"test_a.py"},
            {"test_a.py"},
            missing=["test_ghost.py (no source file)"],
        )
        self.assertEqual(report.missing, ["test_ghost.py (no source file)"])

    def test_package_marker_is_not_a_test_file(self) -> None:
        report = self.discovery.classify({"test_a.py"}, {"test_a.py", "__init__.py"})
        self.assertTrue(report.ok)


class BoundaryRuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.boundaries = _load_script("check-boundaries.py", "guards_check_boundaries")

    def _rules(self, source: str, path: str) -> set[str]:
        return {rule for _, rule, _ in self.boundaries.scan_source(source, path)}

    def test_mcp_is_confined_to_server(self) -> None:
        source = "from mcp.server.fastmcp import FastMCP\n"
        self.assertEqual(self._rules(source, "src/opencyber/api_audit.py"), {"mcp-only-in-server"})
        self.assertEqual(self._rules(source, "src/opencyber/server.py"), set())

    def test_importing_the_server_is_rejected(self) -> None:
        sources = (
            "from .server import main\n",
            "from . import server\n",
            "import opencyber.server\n",
            "from opencyber import server\n",
        )
        for source in sources:
            with self.subTest(source=source):
                self.assertEqual(self._rules(source, "src/opencyber/policy.py"), {"no-server-imports"})

    def test_contract_modules_reject_heavy_dependencies(self) -> None:
        sources = (
            "import requests\n",
            "from playwright.sync_api import sync_playwright\n",
            "from .browser import BROWSER_MANAGER\n",
            "from . import hardware\n",
            "from .native_tools import something\n",
            "from opencyber import native_tools\n",
        )
        for source in sources:
            with self.subTest(source=source):
                self.assertEqual(self._rules(source, "src/opencyber/contracts.py"), {"contract-modules-stay-light"})

    def test_light_contract_module_imports_are_allowed(self) -> None:
        self.assertEqual(self._rules("from .errors import OcError\n", "src/opencyber/limits.py"), set())

    def test_violation_reports_the_import_line(self) -> None:
        violations = self.boundaries.scan_source("\n\nfrom mcp import types\n", "src/opencyber/contracts.py")
        self.assertEqual(
            violations,
            [(3, "mcp-only-in-server", "mcp may only be imported from server.py")],
        )


if __name__ == "__main__":
    unittest.main()
