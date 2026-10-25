from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from opencyber.catalog_identity import (
    alignment,
    catalog_sha256,
    count_summary,
    load_manifest,
    payload_bytes,
    project_tools,
    render_manifest,
)
from opencyber.server import mcp, self_test


ROOT = Path(__file__).resolve().parents[1]


class _FakeTool:
    """A tool-like object: the projection reads attributes, not SDK types."""

    def __init__(self, description: str = "fake", parameter: str = "value") -> None:
        self.description = description
        self.parameters = {
            "type": "object",
            "properties": {parameter: {"type": "string"}},
            "required": [],
        }
        self.output_schema = {"type": "object", "additionalProperties": True}
        self.annotations = None
        self.meta = None


class ManifestTests(unittest.TestCase):
    def test_manifest_is_tracked_and_complete(self):
        manifest = load_manifest()
        self.assertIsNotNone(manifest)
        assert manifest is not None
        self.assertEqual(manifest["schema_version"], 1)
        self.assertEqual(manifest["contract_schema_version"], 1)
        self.assertEqual(manifest["counts"]["by_kind"], {"executable": 173, "native": 82})
        self.assertEqual(manifest["counts"]["total"], 255)
        self.assertEqual(len(manifest["tools"]), 255)
        names = [entry["name"] for entry in manifest["tools"]]
        self.assertEqual(names, sorted(names))
        for entry in manifest["tools"]:
            self.assertEqual(len(entry["digest"]), 64)

    def test_manifest_is_current(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "record-catalog.py"), "--check"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_render_is_deterministic_and_one_tool_per_line(self):
        entries = project_tools(mcp._tool_manager._tools)
        first = render_manifest(entries, server_version="0.0.0")
        second = render_manifest(project_tools(mcp._tool_manager._tools), server_version="0.0.0")
        self.assertEqual(first, second)
        tool_lines = [line for line in first.splitlines() if line.lstrip().startswith('{"annotations"')]
        self.assertEqual(len(tool_lines), len(entries))
        self.assertEqual(json.loads(first)["catalog_sha256"], catalog_sha256(entries))

    def test_server_version_is_metadata_not_contract(self):
        entries = project_tools(mcp._tool_manager._tools)
        one = json.loads(render_manifest(entries, server_version="0.3.0"))
        two = json.loads(render_manifest(entries, server_version="9.9.9"))
        self.assertEqual(one["catalog_sha256"], two["catalog_sha256"])
        self.assertNotEqual(one["server_version"], two["server_version"])

    def test_count_summary_matches_the_manifest(self):
        manifest = load_manifest()
        assert manifest is not None
        self.assertEqual(count_summary(manifest["tools"]), manifest["counts"])


class AlignmentTests(unittest.TestCase):
    def test_tampered_manifest_header_cannot_pass_as_a_subset(self):
        recorded = json.loads(render_manifest(project_tools(mcp._tool_manager._tools), server_version="0.5.0"))
        recorded["catalog_sha256"] = "0" * 64
        for tools in (mcp._tool_manager._tools, {"oc_catalog": mcp._tool_manager._tools["oc_catalog"]}):
            report = alignment(tools, recorded)
            self.assertFalse(report["matches"])
            self.assertFalse(report["subset_matches"])

    def setUp(self):
        self.manifest = load_manifest()
        assert self.manifest is not None
        self.tools = mcp._tool_manager._tools

    def test_a_full_registration_matches_the_record(self):
        report = alignment(self.tools, self.manifest)
        self.assertEqual(report["profile"], "full")
        self.assertTrue(report["matches"])
        self.assertTrue(report["subset_matches"])
        self.assertEqual(report["advertised_sha256"], report["recorded_sha256"])
        self.assertEqual(report["unexpected_tools"], [])
        self.assertEqual(report["changed_tools"], [])

    def test_a_narrowed_registration_is_a_honest_subset(self):
        subset = {name: tool for name, tool in self.tools.items() if not name.startswith("oc_browser_")}
        report = alignment(subset, self.manifest)
        self.assertEqual(report["profile"], "compact")
        self.assertFalse(report["matches"])
        self.assertTrue(report["subset_matches"])
        self.assertEqual(report["missing_tool_count"], 13)
        self.assertEqual(report["unexpected_tools"], [])

    def test_a_changed_tool_is_named(self):
        tool = self.tools["oc_catalog"]
        original = tool.description
        try:
            tool.description = (original or "") + " changed"
            report = alignment(self.tools, self.manifest)
        finally:
            tool.description = original
        self.assertEqual(report["changed_tools"], ["oc_catalog"])
        self.assertFalse(report["matches"])
        self.assertFalse(report["subset_matches"])

    def test_an_unexpected_tool_is_named(self):
        from dataclasses import replace

        from opencyber.contracts import CONTRACTS

        fake = dict(self.tools)
        fake["oc_not_recorded"] = _FakeTool()
        CONTRACTS["oc_not_recorded"] = replace(CONTRACTS["oc_catalog"], name="oc_not_recorded")
        try:
            report = alignment(fake, self.manifest)
        finally:
            del CONTRACTS["oc_not_recorded"]
        self.assertEqual(report["unexpected_tools"], ["oc_not_recorded"])
        self.assertFalse(report["subset_matches"])

    def test_an_unrecorded_catalog_is_not_a_match(self):
        report = alignment(self.tools, None)
        self.assertEqual(report["profile"], "unrecorded")
        self.assertFalse(report["matches"])
        self.assertFalse(report["subset_matches"])
        self.assertIsNone(report["recorded_sha256"])

    def test_payload_bytes_is_the_advertised_context_cost(self):
        size = payload_bytes(self.tools)
        self.assertGreater(size, 100_000)


class CatalogToolTests(unittest.TestCase):
    def _catalog(self, **arguments):
        return asyncio.run(mcp.call_tool("oc_catalog", arguments)).structured_content

    def test_catalog_reports_digests_and_alignment(self):
        payload = self._catalog()
        self.assertTrue(payload["ok"])
        self.assertEqual(payload["catalog_digest"], payload["recorded_catalog_digest"])
        self.assertTrue(payload["catalog_matches_release"])
        self.assertTrue(payload["catalog_subset_matches_release"])
        self.assertEqual(payload["catalog_profile"], "full")
        self.assertEqual(payload["catalog_contract_schema_version"], 1)
        self.assertEqual(payload["catalog_alignment"]["changed_tools"], [])
        self.assertIsNone(payload["catalog_alignment"]["matches_expected"])
        self.assertGreater(payload["advertised_payload_bytes"], 100_000)

    def test_expected_digest_pins_a_client(self):
        digest = self._catalog()["catalog_digest"]
        matched = self._catalog(expected_catalog_digest=digest)
        self.assertTrue(matched["catalog_alignment"]["matches_expected"])
        mismatched = self._catalog(expected_catalog_digest="0" * 64)
        self.assertFalse(mismatched["catalog_alignment"]["matches_expected"])
        self.assertEqual(mismatched["catalog_alignment"]["expected_digest"], "0" * 64)

    def test_self_test_reports_the_catalog_block(self):
        report = self_test()
        catalog = report["catalog"]
        self.assertEqual(catalog["profile"], "full")
        self.assertTrue(catalog["matches"])
        self.assertFalse(catalog["strict_mismatch"])
        self.assertEqual(catalog["changed_tools"], [])

    def test_strict_mode_turns_a_mismatch_into_a_failure(self):
        tool = mcp._tool_manager._tools["oc_catalog"]
        original = tool.description
        try:
            tool.description = "tampered contract"
            with patch.dict(os.environ, {"OPENCYBER_STRICT_CATALOG": "1"}):
                report = self_test()
        finally:
            tool.description = original
        self.assertFalse(report["catalog"]["matches"])
        self.assertTrue(report["catalog"]["strict_mismatch"])
        self.assertIn("oc_catalog", report["catalog"]["changed_tools"])


if __name__ == "__main__":
    unittest.main()
