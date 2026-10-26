import asyncio
from pathlib import Path
import unittest
from unittest.mock import patch

from opencyber.catalog import CATALOG, HARDWARE_CATEGORIES, TOOL_GROUPS, category_counts
from opencyber.coverage import REFERENCE_FUNCTIONS, reference_coverage, uncovered_reference_functions
from opencyber.diagnostics import FIXED_TOOL_NAMES
from opencyber.workflows import WORKFLOW_STEPS


class CatalogTests(unittest.TestCase):
    def test_catalog_is_large_and_unique(self):
        names = [spec.name for spec in CATALOG]
        self.assertGreaterEqual(len(names), 100)
        self.assertEqual(len(names), len(set(names)))

    def test_every_major_category_has_tools(self):
        counts = category_counts()
        self.assertEqual(set(counts), set(TOOL_GROUPS))
        self.assertTrue(all(count > 0 for count in counts.values()))

    def test_names_are_oc_owned(self):
        self.assertTrue(all(spec.name.startswith("oc_") for spec in CATALOG))
        self.assertIn("oc_jq", {spec.name for spec in CATALOG})

    def test_unbundled_integrations_are_optional_and_dependency_aware(self):
        optional = {spec.name: spec for spec in CATALOG if not spec.required}
        expected = {"oc_scout_suite", "oc_terrascan"}
        self.assertEqual(set(optional), expected)
        rustscan = next(spec for spec in CATALOG if spec.name == "oc_rustscan")
        with patch("opencyber.catalog.shutil.which", side_effect=lambda name: None if name == "nmap" else f"/bin/{name}"):
            self.assertFalse(rustscan.availability()["available"])
            self.assertEqual(rustscan.availability()["missing_dependencies"], ["nmap"])
        self.assertTrue(rustscan.as_dict()["required"])
        self.assertIn("oc_wpscan", {spec.name for spec in CATALOG if spec.required})

    def test_bundled_dependency_failure_is_actionable_before_execution(self):
        from opencyber.executor import execute_tool

        with patch("opencyber.executor.resolve_engagement_path", return_value=Path("/tmp")), \
             patch("opencyber.executor.enforce_scope", return_value={"enforced": False}), \
             patch("opencyber.executor.offline_network_decision", return_value={"blocked": False}), \
             patch("opencyber.executor._record", return_value=None), \
             patch("opencyber.catalog.shutil.which", side_effect=lambda name: None if name == "nmap" else f"/bin/{name}"), \
             patch("opencyber.executor.asyncio.create_subprocess_exec") as launch:
            result = asyncio.run(execute_tool("rustscan", [], "fixture"))
        self.assertFalse(result["success"])
        self.assertFalse(result["ok"])
        self.assertFalse(result["optional"])
        self.assertEqual(result["missing_dependencies"], ["nmap"])
        self.assertEqual(result["error"]["code"], "integration_unavailable")
        self.assertEqual(result["error"]["category"], "unavailable")
        self.assertIn("nmap", result["error"]["message"])
        launch.assert_not_called()


    def test_restricted_executables_are_not_shipped(self):
        executables = {spec.executable for spec in CATALOG}
        self.assertTrue({"burpsuite", "waybackurls", "maltego"}.isdisjoint(executables))
        self.assertTrue({"whatweb", "urlfinder", "subzy"}.issubset(executables))

    def test_reference_functional_inventory_is_accounted_for(self):
        self.assertEqual(uncovered_reference_functions(), [])
        self.assertEqual(len(reference_coverage()), len(REFERENCE_FUNCTIONS))

    def test_workflow_steps_reference_real_catalog_tools(self):
        names = {spec.name for spec in CATALOG}
        names.update(FIXED_TOOL_NAMES)
        referenced = {step["tool"] for steps in WORKFLOW_STEPS.values() for step in steps}
        self.assertEqual(sorted(referenced - names), [])

    def test_hardware_categories_cover_physical_domains(self):
        self.assertTrue(
            {"rf", "wireless_attack", "nfc_rfid", "usb", "embedded", "automotive"}
            .issubset(HARDWARE_CATEGORIES)
        )
        self.assertTrue(all(spec.name.startswith("oc_") for spec in CATALOG))
        self.assertGreaterEqual(len([spec for spec in CATALOG if spec.category in HARDWARE_CATEGORIES]), 50)


if __name__ == "__main__":
    unittest.main()
