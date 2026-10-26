from __future__ import annotations

import json
from pathlib import Path
import os
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from opencyber import __version__
from opencyber import diagnostics
from opencyber.catalog import CATALOG
from opencyber.diagnostics import FIXED_TOOL_CATEGORIES
from opencyber.doctor import main as doctor_main


ROOT = Path(__file__).resolve().parents[1]


class DoctorTests(unittest.TestCase):
    def test_optional_integrations_do_not_degrade_ready_image(self) -> None:
        with mock.patch("opencyber.catalog.shutil.which", side_effect=lambda name: None if name in {"scout", "terrascan"} else f"/usr/bin/{name}"):
            base = diagnostics.self_test()
        base["analysis_runtime"] = {"angr": True, "volatility3": True}
        assets = {"missing_required": [], "ready": True, "summary": {"ok": 1, "total": 1}}
        hardware = {"summary": {}, "ready_domains": [], "tooling_only_domains": [], "unavailable_domains": [],
                    "inventory": {"summary": {}, "access": {}, "known_devices": []}, "host_flags": []}
        rockyou = mock.Mock()
        rockyou.is_file.return_value = False
        rockyou.stat.return_value.st_size = 10
        baseline = mock.Mock()
        baseline.is_file.return_value = True
        baseline.stat.return_value.st_size = 4_678_976
        seclists = mock.Mock()
        seclists.is_dir.return_value = True
        with mock.patch.object(diagnostics, "self_test", return_value=base), \
             mock.patch.object(diagnostics, "templates_summary", return_value={"count": 5001, "version": "fixture"}), \
             mock.patch.object(diagnostics, "assets_status", return_value=assets), \
             mock.patch.object(diagnostics, "verify_manifest", return_value={"available": True, "valid": True}), \
             mock.patch.object(diagnostics, "hardware_readiness", return_value=hardware), \
             mock.patch.object(diagnostics, "_tool_version", return_value="fixture"), \
             mock.patch.object(diagnostics, "ROCKYOU", rockyou), \
             mock.patch.object(diagnostics, "BASELINE_WORDLIST", baseline), \
             mock.patch.object(diagnostics, "SECLISTS", seclists):
            report = diagnostics.doctor_report()
        self.assertEqual(report["status"], "ok")
        self.assertEqual(report["problems"], [])
        self.assertFalse(report["wordlists"]["rockyou"])
        self.assertTrue(report["wordlists"]["baseline"])
        self.assertIn("oc_scout_suite", report["mcp"]["missing_optional_tools"])

    def test_missing_optional_integrations_are_distinguished(self) -> None:
        with mock.patch("opencyber.catalog.shutil.which", side_effect=lambda name: None if name in {"scout", "terrascan"} else f"/usr/bin/{name}"):
            result = diagnostics.self_test()
        self.assertEqual(result["missing_required_tools"], [])
        self.assertIn("oc_scout_suite", result["missing_optional_tools"])
        self.assertIn("oc_terrascan", result["missing_optional_tools"])
        self.assertEqual(result["blue_team_tools"], len(FIXED_TOOL_CATEGORIES["blue_team"]))

    def test_missing_required_integration_is_not_optional(self) -> None:
        with mock.patch("opencyber.catalog.shutil.which", side_effect=lambda name: None if name == "tshark" else f"/usr/bin/{name}"):
            result = diagnostics.self_test()
        self.assertEqual(result["missing_required_tools"], ["oc_packet_analysis"])
        self.assertNotIn("oc_packet_analysis", result["missing_optional_tools"])

    def test_fixed_tool_budget_matches_the_advertised_total(self) -> None:
        self.assertEqual(diagnostics.FIXED_MCP_TOOL_COUNT, len(diagnostics.FIXED_TOOL_NAMES))
        self.assertEqual(diagnostics.NATIVE_AND_WORKSPACE_TOOL_COUNT, 23)
        self.assertGreaterEqual(len(CATALOG), 170)
        self.assertGreaterEqual(diagnostics.FIXED_MCP_TOOL_COUNT, 60)
        self.assertGreaterEqual(
            diagnostics.FIXED_MCP_TOOL_COUNT + len(CATALOG),
            230,
        )

    def test_bare_host_is_reported_as_degraded(self) -> None:
        report = diagnostics.doctor_report()
        self.assertEqual(report["status"], "degraded")
        self.assertTrue(report["problems"])

    def test_report_is_json_serialisable_and_names_problems(self) -> None:
        report = diagnostics.doctor_report()
        json.dumps(report)
        self.assertIn("mcp", report)
        self.assertIn("nuclei_templates", report)
        self.assertIn("wordlists", report)
        self.assertIn("agent_tools", report)
        self.assertEqual(report["version"], __version__)

    def test_templates_summary_counts_yaml_under_home(self) -> None:
        with tempfile.TemporaryDirectory() as tempdir:
            store = Path(tempdir) / ".local" / "nuclei-templates"
            (store / "http").mkdir(parents=True)
            (store / "http" / "one.yaml").write_text("id: one\n", encoding="utf-8")
            (store / "http" / "two.yaml").write_text("id: two\n", encoding="utf-8")
            (store / "http" / "ignore.txt").write_text("nope\n", encoding="utf-8")
            (store / ".opencyber-version").write_text("v9.9.9\n", encoding="utf-8")
            with mock.patch.dict(os.environ, {"HOME": tempdir}):
                summary = diagnostics.templates_summary()
        self.assertEqual(summary["count"], 2)
        self.assertEqual(summary["version"], "v9.9.9")

    def test_format_report_is_human_readable(self) -> None:
        text = diagnostics.format_report(diagnostics.doctor_report())
        self.assertIn("opencyber-doctor", text)
        self.assertIn("status", text)
        self.assertIn("nuclei templates", text)

    def test_cli_exits_non_zero_when_degraded(self) -> None:
        with mock.patch.object(sys, "argv", ["opencyber-doctor", "--quiet"]):
            with self.assertRaises(SystemExit) as raised:
                doctor_main()
        self.assertEqual(raised.exception.code, 1)

    def test_cli_json_mode_emits_parseable_report(self) -> None:
        result = subprocess.run(
            [sys.executable, "-m", "opencyber.doctor", "--json"],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 1)
        report = json.loads(result.stdout)
        self.assertEqual(report["status"], "degraded")


class AdvertisedToolTests(unittest.TestCase):
    def test_every_advertised_tool_is_prefixed_and_unique(self) -> None:
        from opencyber.server import mcp

        names = list(mcp._tool_manager._tools)
        self.assertEqual(len(names), len(CATALOG) + diagnostics.FIXED_MCP_TOOL_COUNT)
        self.assertEqual(len(names), len(set(names)))
        self.assertTrue(all(name.startswith("oc_") for name in names))

    def test_native_tool_count_matches_the_diagnostics_budget(self) -> None:
        from opencyber.server import REGISTERED_CATALOG, mcp

        advertised = len(mcp._tool_manager._tools)
        self.assertEqual(advertised, len(REGISTERED_CATALOG) + diagnostics.FIXED_MCP_TOOL_COUNT)

    def test_fixed_tool_names_match_the_live_registrations(self) -> None:
        from opencyber.server import mcp

        live = set(mcp._tool_manager._tools)
        catalog_names = {spec.name for spec in CATALOG}
        self.assertEqual(live - catalog_names, set(diagnostics.FIXED_TOOL_NAMES))

    def test_catalog_hardware_filter_includes_executables_and_native_tools(self) -> None:
        from opencyber.server import oc_catalog

        result = oc_catalog(category="hardware")
        names = {entry["name"] for entry in result["tools"]}
        self.assertIn("oc_hackrf_info", names)
        self.assertIn("oc_hardware_inventory", names)
        self.assertIn("oc_serial_open", names)
        self.assertIn("rf", result["hardware_categories"])


class VersionTests(unittest.TestCase):
    def test_package_and_project_versions_agree(self) -> None:
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('dynamic = ["version"]', text)
        self.assertIn('version = { attr = "opencyber.__version__" }', text)

    def test_server_advertises_the_package_version(self) -> None:
        from opencyber.server import mcp

        self.assertEqual(mcp.version, __version__)
        self.assertEqual(mcp.name, "OpenCyber Harness")


if __name__ == "__main__":
    unittest.main()
