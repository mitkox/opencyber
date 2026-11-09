from __future__ import annotations

from datetime import date
import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "scripts" / "check-license-policy.py"


class LicensePolicyTests(unittest.TestCase):
    def test_removed_vendor_components_are_forbidden_if_they_return(self) -> None:
        policy = json.loads((ROOT / "compliance/license-policy.json").read_text(encoding="utf-8"))
        for name in ("pyxdia", "oracle-instantclient-basic", "metasploit-framework"):
            with self.subTest(name=name):
                result = self.run_checker(
                    [{"name": name, "licenses": [{"license": {"id": "MIT"}}]}], policy,
                )
                self.assertEqual(result.returncode, 1, result.stdout)
                self.assertIn(f"REMOVED: {name}:", result.stderr)

    def test_unknown_or_absent_license_is_a_release_blocker(self) -> None:
        result = self.run_checker(["unreviewed-component"], {})
        self.assertEqual(result.returncode, 1)
        self.assertIn("UNRESOLVED", result.stderr)

    def run_checker(
        self, component_names: list[str | dict], policy: dict,
        evidence: dict[str, bytes] | None = None,
        evidence_root: str | None = None,
    ) -> subprocess.CompletedProcess[str]:
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
            for path, content in (evidence or {}).items():
                evidence_path = root / path
                evidence_path.parent.mkdir(parents=True, exist_ok=True)
                evidence_path.write_bytes(content)
            command = [
                    sys.executable,
                    str(CHECKER),
                    str(sbom_path),
                    "--policy",
                    str(policy_path),
                ]
            if evidence_root is not None:
                command.extend(["--license-evidence-root", str(root / evidence_root)])
            return subprocess.run(
                command,
                check=False,
                capture_output=True,
                text=True,
            )

    def test_recorded_unknown_set_is_accepted_only_for_the_exact_components(self) -> None:
        policy = json.loads((ROOT / "compliance/license-policy.json").read_text(encoding="utf-8"))
        recorded = policy["recorded_unknown_licenses"]
        names = ["pkg:generic/fixture-a@1", "pkg:generic/fixture-b@2"]
        import hashlib

        policy = {
            **policy,
            "recorded_unknown_licenses": {
                **recorded,
                "count": len(names),
                "sha256": hashlib.sha256("\n".join(sorted(names)).encode()).hexdigest(),
            },
        }
        accepted = self.run_checker(
            [{"name": name.split("/")[-1].split("@")[0], "purl": name} for name in names], policy,
        )
        self.assertEqual(accepted.returncode, 0, accepted.stderr)
        self.assertIn("RECORDED: 2", accepted.stdout)
        changed = self.run_checker(
            [{"name": "fixture-a", "purl": "pkg:generic/fixture-a@1"},
             {"name": "fixture-c", "purl": "pkg:generic/fixture-c@3"}], policy,
        )
        self.assertEqual(changed.returncode, 1)
        self.assertIn("UNRESOLVED", changed.stderr)

    def test_recorded_unknown_component_list_matches_the_policy(self) -> None:
        policy = json.loads((ROOT / "compliance/license-policy.json").read_text(encoding="utf-8"))
        recorded = policy["recorded_unknown_licenses"]
        names = (ROOT / recorded["component_list"]).read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(names), recorded["count"])
        self.assertEqual(
            hashlib.sha256("\n".join(sorted(names)).encode("utf-8")).hexdigest(),
            recorded["sha256"],
        )

    def test_known_spdx_license_passes_but_unknown_expressions_fail(self) -> None:
        for license_id, expected in (("MIT", 0), ("NOASSERTION", 1), ("Not-A-Real-License", 1),
                                     ("licenseref-proprietary", 1), ("MIT OR licenseref-custom", 1)):
            with self.subTest(license_id=license_id):
                result = self.run_checker([{"name": "fixture", "licenses": [{"license": {"id": license_id}}]}], {})
                self.assertEqual(result.returncode, expected, result.stderr)

    def test_review_decision_is_bound_to_the_exact_package_version(self) -> None:
        component = {"name": "fixture", "purl": "pkg:generic/fixture@1.0", "licenses": []}
        decision = {"purl": component["purl"], "owner": "@reviewer", "basis": "Fixture license text review",
                    "reviewed_at": str(date.today()), "license_expression": "MIT"}
        self.assertEqual(self.run_checker([component], {"reviewed_license_components": [decision]}).returncode, 0)
        component["purl"] = "pkg:generic/fixture@2.0"
        self.assertEqual(self.run_checker([component], {"reviewed_license_components": [decision]}).returncode, 1)

    def custom_review(self) -> tuple[dict, dict, dict[str, bytes]]:
        text = b"Fixture custom terms: redistribution permitted with this notice.\n"
        component = {"name": "fixture", "purl": "pkg:generic/fixture@1.0", "licenses": []}
        decision = {
            "purl": component["purl"], "owner": "@reviewer",
            "basis": "Inspected the exact fixture package copyright file.",
            "reviewed_at": str(date.today()), "license_expression": "LicenseRef-Fixture",
            "redistribution_basis": "The license expressly permits redistribution with its notice.",
            "required_notices": ["Retain the complete fixture license text."],
            "source_obligations": "No source distribution requirement.",
            "license_evidence": {
                "path": "licenses/fixture-copyright.txt",
                "sha256": hashlib.sha256(text).hexdigest(),
                "source_url": "https://example.org/fixture/1.0/LICENSE",
            },
        }
        return component, decision, {decision["license_evidence"]["path"]: text}

    def test_custom_license_review_accepts_exact_version_with_license_text_evidence(self) -> None:
        component, decision, evidence = self.custom_review()
        policy = {"reviewed_license_components": [decision]}
        result = self.run_checker([component], policy, evidence)
        self.assertEqual(result.returncode, 0, result.stderr)
        component["purl"] = "pkg:generic/fixture@2.0"
        self.assertEqual(self.run_checker([component], policy, evidence).returncode, 1)

    def test_custom_license_review_can_use_an_extracted_license_bundle(self) -> None:
        component, decision, evidence = self.custom_review()
        evidence = {"captured/" + path: content for path, content in evidence.items()}
        result = self.run_checker(
            [component], {"reviewed_license_components": [decision]}, evidence, evidence_root="captured",
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_custom_license_review_requires_exact_version_and_attribution(self) -> None:
        for field, value in (("purl", "pkg:generic/fixture@"), ("owner", " "), ("basis", " ")):
            with self.subTest(field=field):
                component, decision, evidence = self.custom_review()
                decision[field] = value
                if field == "purl":
                    component[field] = value
                result = self.run_checker([component], {"reviewed_license_components": [decision]}, evidence)
                self.assertEqual(result.returncode, 1, result.stdout)

    def test_custom_license_review_requires_rights_notices_and_matching_evidence(self) -> None:
        for field in ("redistribution_basis", "required_notices", "source_obligations"):
            with self.subTest(missing=field):
                component, decision, evidence = self.custom_review()
                decision.pop(field)
                result = self.run_checker([component], {"reviewed_license_components": [decision]}, evidence)
                self.assertEqual(result.returncode, 1, result.stdout)
        for invalid_evidence in (
            {}, {"path": "missing.txt"}, {"sha256": "0" * 64},
            {"path": "../outside.txt"}, {"source_url": ""},
        ):
            with self.subTest(evidence=invalid_evidence):
                component, decision, evidence = self.custom_review()
                if invalid_evidence:
                    decision["license_evidence"].update(invalid_evidence)
                else:
                    decision.pop("license_evidence")
                result = self.run_checker([component], {"reviewed_license_components": [decision]}, evidence)
                self.assertEqual(result.returncode, 1, result.stdout)

    def test_unknown_review_identity_and_missing_distribution_grant_stay_blocked(self) -> None:
        for expression in ("NOASSERTION", "Unknown license"):
            with self.subTest(expression=expression):
                component, decision, evidence = self.custom_review()
                decision["license_expression"] = expression
                self.assertEqual(self.run_checker(
                    [component], {"reviewed_license_components": [decision]}, evidence,
                ).returncode, 1)
        component, decision, evidence = self.custom_review()
        result = self.run_checker([component], {
            "reviewed_license_components": [decision],
            "blocked_components": [{"name": "fixture", "reason": "Missing redistribution grant."}],
        }, evidence)
        self.assertEqual(result.returncode, 1)
        self.assertIn("BLOCKED: fixture", result.stderr)

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

    def test_nmap_and_wpscan_are_eligible_with_exact_reviews_and_notices(self) -> None:
        policy = json.loads((ROOT / "compliance" / "license-policy.json").read_text(encoding="utf-8"))
        for name in ("nmap", "nmap-common", "ncat", "ndiff", "nping", "wpscan"):
            with self.subTest(name=name):
                component, decision, evidence = self.custom_review()
                component.update(name=name, purl=f"pkg:generic/{name}@1.0")
                decision["purl"] = component["purl"]
                unresolved = self.run_checker([component], policy, evidence)
                self.assertEqual(unresolved.returncode, 1)
                self.assertIn("UNRESOLVED:", unresolved.stderr)
                reviewed = dict(policy, reviewed_license_components=[decision])
                result = self.run_checker([component], reviewed, evidence)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn(f"NOTICE: {name}", result.stdout)

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
