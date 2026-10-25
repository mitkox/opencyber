from __future__ import annotations

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts" / "check-license-policy.py"


class LicensePolicyTests(unittest.TestCase):
    def test_unknown_or_absent_license_is_a_release_blocker(self) -> None:
        result = self.run_checker(["unreviewed-component"], {})
        self.assertEqual(result.returncode, 1)
        self.assertIn("UNRESOLVED", result.stderr)

    def run_checker(self, component_names: list[str], policy: dict) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sbom_path = root / "sbom.json"
            policy_path = root / "policy.json"
            sbom_path.write_text(
                json.dumps(
                    {
                        "bomFormat": "CycloneDX",
                        "components": [
                            name if isinstance(name, dict) else {"type": "application", "name": name}
                            for name in component_names
                        ],
                    }
                ),
                encoding="utf-8",
            )
            policy_path.write_text(json.dumps(policy), encoding="utf-8")
            return subprocess.run(
                [
                    sys.executable,
                    str(CHECKER),
                    str(sbom_path),
                    "--policy",
                    str(policy_path),
                ],
                check=False,
                capture_output=True,
                text=True,
            )

    def test_known_spdx_license_passes_but_unknown_expressions_fail(self) -> None:
        for license_id, expected in (("MIT", 0), ("NOASSERTION", 1), ("Not-A-Real-License", 1),
                                     ("licenseref-proprietary", 1), ("MIT OR licenseref-custom", 1)):
            with self.subTest(license_id=license_id):
                result = self.run_checker([{"name": "fixture", "licenses": [{"license": {"id": license_id}}]}], {})
                self.assertEqual(result.returncode, expected, result.stderr)

    def test_review_decision_is_bound_to_the_exact_package_version(self) -> None:
        from datetime import date

        component = {"name": "fixture", "purl": "pkg:generic/fixture@1.0", "licenses": []}
        decision = {"purl": component["purl"], "owner": "@reviewer", "basis": "Fixture license text review",
                    "reviewed_at": str(date.today()), "license_expression": "MIT"}
        self.assertEqual(self.run_checker([component], {"reviewed_license_components": [decision]}).returncode, 0)
        component["purl"] = "pkg:generic/fixture@2.0"
        self.assertEqual(self.run_checker([component], {"reviewed_license_components": [decision]}).returncode, 1)

    def test_exact_spdx_in_license_name_is_recognized_without_guessing_aliases(self) -> None:
        for name, expected in (("Apache-2.0", 0), ("MIT", 0), ("MIT License", 1),
                               ("BSD", 1), ("licenseref-custom", 1)):
            with self.subTest(name=name):
                result = self.run_checker([{"name": "fixture", "licenses": [{"license": {"name": name}}]}], {})
                self.assertEqual(result.returncode, expected, result.stderr)

    def test_blocked_component_fails_release(self) -> None:
        result = self.run_checker(
            ["burpsuite"],
            {
                "blocked_components": [
                    {"name": "burpsuite", "reason": "redistribution unresolved"}
                ],
                "review_required_components": [],
            },
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("BLOCKED: burpsuite", result.stderr)

    def test_go_module_path_matches_component_basename(self) -> None:
        result = self.run_checker(
            ["github.com/tomnomnom/waybackurls"],
            {
                "blocked_components": [
                    {"name": "waybackurls", "reason": "no upstream license"}
                ],
                "review_required_components": [],
            },
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("BLOCKED: waybackurls", result.stderr)

    def test_wpscan_is_blocked(self) -> None:
        result = self.run_checker(
            ["wpscan"],
            {
                "blocked_components": [
                    {
                        "name": "wpscan",
                        "reason": "distribution terms are incompatible",
                    }
                ],
                "review_required_components": [],
            },
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("BLOCKED: wpscan", result.stderr)

    def test_unresolved_review_item_fails_release(self) -> None:
        result = self.run_checker(
            ["nmap"],
            {
                "blocked_components": [],
                "review_required_components": [
                    {"name": "nmap", "reason": "review NPSL terms"}
                ],
            },
        )
        self.assertEqual(result.returncode, 1)
        self.assertIn("REVIEW: nmap", result.stdout)


if __name__ == "__main__":
    unittest.main()
