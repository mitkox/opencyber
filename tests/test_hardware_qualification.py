from __future__ import annotations

import copy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from scripts.lib.qualification import (
    REQUIRED_DOMAINS,
    collect_qualification,
    qualification_template,
    validate_qualification,
)


ROOT = Path(__file__).resolve().parents[1]
COMMIT = "a" * 40
CATALOG = "b" * 64
RECORDS = [
    {"platform": "linux/amd64", "digest": "sha256:" + "1" * 64,
     "commit": COMMIT, "catalog_sha256": CATALOG}
]


class HardwareQualificationTests(unittest.TestCase):
    """Fixture records test validation only; they are never hardware evidence."""

    def bundle(self, root: Path) -> dict:
        bundle = qualification_template(commit=COMMIT, candidate_run_id=123, records=RECORDS)
        for record in [*bundle["domains"], bundle["firmware"]]:
            name = record["domain"]
            artifact = root / "evidence" / (name + ".txt")
            artifact.parent.mkdir(exist_ok=True)
            artifact.write_text("Unit-test report for " + name, encoding="utf-8")
            record.update({
                "status": "passed", "kind": "board_sample" if name == "firmware" else "real_device",
                "device": {"model": "Reference board", "firmware": "1.2.3"},
                "host": {"architecture": "amd64", "os": "Linux reference host", "kernel": "6.8"},
                "launcher_flags": ["--read-only", "--cap-drop=ALL", "--device=/dev/lab-reference"],
                "operation": "Bounded reference operation", "expected": "Known reference response",
                "observed": "Known reference response", "cleanup": "Handles closed and host state restored",
                "limits": {"timeout_s": 30, "max_output_bytes": 1048576},
                "operator": "@lab-operator", "operator_attested": True,
                "completed_at": datetime.now(timezone.utc).isoformat(),
                "negative_checks": {
                    check: {"status": "passed", "detail": "Observed bounded refusal and cleanup"}
                    for check in ("missing_device", "insufficient_permissions", "disconnect", "timeout", "cleanup")
                },
                "evidence": [{"path": "evidence/" + name + ".txt",
                              "sha256": hashlib.sha256(artifact.read_bytes()).hexdigest()}],
            })
        return bundle

    def write_bundle(self, root: Path, bundle: dict) -> Path:
        path = root / "qualification.json"
        path.write_text(json.dumps(bundle), encoding="utf-8")
        return path

    def validate(self, root: Path, bundle: dict, records: list[dict] | None = None) -> dict:
        return validate_qualification(self.write_bundle(root, bundle), commit=COMMIT, records=records or RECORDS)

    def test_domain_inventory_matches_advertised_hardware(self):
        from opencyber.hardware import HARDWARE_DOMAINS
        self.assertEqual(set(REQUIRED_DOMAINS), set(HARDWARE_DOMAINS))

    def test_complete_bundle_accepts_one_real_host_per_domain(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = self.bundle(root)
            result = self.validate(root, bundle)
            self.assertEqual(result, bundle)
            self.assertEqual({r["platform"] for r in result["domains"]}, {"linux/amd64"})

    def test_missing_duplicate_unknown_failed_and_skipped_domain_refuse(self):
        for change in ("missing", "duplicate", "unknown", "failed", "skipped"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                bundle = self.bundle(root)
                if change == "missing":
                    bundle["domains"].pop()
                elif change == "duplicate":
                    bundle["domains"].append(copy.deepcopy(bundle["domains"][0]))
                elif change == "unknown":
                    bundle["domains"][0]["domain"] = "unknown"
                else:
                    bundle["domains"][0]["status"] = change
                with self.assertRaises(ValueError):
                    self.validate(root, bundle)

    def test_firmware_and_real_device_kind_are_required(self):
        for change in ("missing_firmware", "synthetic", "fixture", "wrong_firmware_kind"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                bundle = self.bundle(root)
                if change == "missing_firmware":
                    del bundle["firmware"]
                elif change == "wrong_firmware_kind":
                    bundle["firmware"]["kind"] = "real_device"
                else:
                    bundle["domains"][0]["kind"] = change
                with self.assertRaises(ValueError):
                    self.validate(root, bundle)

    def test_commit_catalog_image_and_host_architecture_are_bound(self):
        for change in ("commit", "catalog", "image", "platform", "architecture", "candidate_catalog"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                bundle = self.bundle(root)
                records = copy.deepcopy(RECORDS)
                if change == "commit":
                    bundle["commit"] = "c" * 40
                elif change == "catalog":
                    bundle["catalog_sha256"] = "c" * 64
                elif change == "image":
                    bundle["domains"][0]["image_digest"] = "sha256:" + "2" * 64
                elif change == "platform":
                    bundle["domains"][0]["platform"] = "linux/other"
                elif change == "architecture":
                    bundle["domains"][0]["host"]["architecture"] = "arm64"
                else:
                    del records[0]["catalog_sha256"]
                with self.assertRaises(ValueError):
                    self.validate(root, bundle, records)

    def test_invalid_candidate_identity_or_run_id_refuses(self):
        for field, value in (("schema_version", True), ("candidate_run_id", True),
                             ("candidate_run_id", 0), ("candidate_run_id", "123"),
                             ("commit", "candidate"), ("catalog_sha256", "invalid")):
            with self.subTest(field=field, value=value), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                bundle = self.bundle(root)
                bundle[field] = value
                with self.assertRaises(ValueError):
                    self.validate(root, bundle)

    def test_missing_identity_attestation_limits_or_timestamp_refuses(self):
        mutations = (
            lambda r: r.update(operator=""), lambda r: r.update(operator_attested=False),
            lambda r: r.update(completed_at="2026-10-25T12:00:00"),
            lambda r: r.update(completed_at="2099-01-01T00:00:00+00:00"),
            lambda r: r["device"].update(model=""), lambda r: r["device"].update(firmware=""),
            lambda r: r.update(observed=""), lambda r: r.update(launcher_flags=[]),
            lambda r: r["limits"].update(timeout_s=0), lambda r: r["limits"].update(max_output_bytes=True),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                bundle = self.bundle(root)
                mutation(bundle["domains"][0])
                with self.assertRaises(ValueError):
                    self.validate(root, bundle)

    def test_negative_checks_require_results_and_reasoned_applicability(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = self.bundle(root)
            checks = bundle["domains"][0]["negative_checks"]
            checks["disconnect"] = {"status": "not_applicable", "detail": "Host controller cannot be detached safely"}
            self.validate(root, bundle)
            checks["timeout"] = {"status": "not_applicable", "detail": "Not attempted"}
            with self.assertRaises(ValueError):
                self.validate(root, bundle)
            checks["timeout"] = {"status": "passed", "detail": "Bounded operation ended"}
            checks["disconnect"]["detail"] = ""
            with self.assertRaises(ValueError):
                self.validate(root, bundle)

    def test_evidence_must_exist_and_match_its_digest(self):
        for action in ("missing", "tampered", "empty"):
            with self.subTest(action=action), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                bundle = self.bundle(root)
                if action == "empty":
                    bundle["domains"][0]["evidence"] = []
                else:
                    path = root / bundle["domains"][0]["evidence"][0]["path"]
                    if action == "missing":
                        path.unlink()
                    else:
                        path.write_text("changed")
                with self.assertRaises(ValueError):
                    self.validate(root, bundle)

    def test_unsafe_evidence_paths_refuse(self):
        for value in (".", "../secret", "/etc/passwd", "evidence/../secret", "evidence//usb.txt", "evidence\\usb.txt"):
            with self.subTest(path=value), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                bundle = self.bundle(root)
                bundle["domains"][0]["evidence"][0]["path"] = value
                with self.assertRaises(ValueError):
                    self.validate(root, bundle)

    def test_symlinked_bundle_evidence_or_directory_refuses(self):
        for kind in ("bundle", "evidence", "directory"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                bundle = self.bundle(root)
                path = self.write_bundle(root, bundle)
                original = path if kind == "bundle" else root / "evidence/usb.txt" if kind == "evidence" else root / "evidence"
                moved = root / "moved"
                original.rename(moved)
                original.symlink_to(moved, target_is_directory=kind == "directory")
                with self.assertRaises(ValueError):
                    validate_qualification(path, commit=COMMIT, records=RECORDS)

    def test_nonregular_evidence_refuses_without_waiting_for_a_writer(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = self.bundle(root)
            artifact = root / "evidence/usb.txt"
            artifact.unlink()
            os.mkfifo(artifact)
            with self.assertRaisesRegex(ValueError, "regular file"):
                self.validate(root, bundle)

    def test_repeated_evidence_entry_and_missing_negative_disposition_refuse(self):
        for mode in ("duplicate_evidence", "missing_check"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                bundle = self.bundle(root)
                record = bundle["domains"][0]
                if mode == "duplicate_evidence":
                    record["evidence"].append(copy.deepcopy(record["evidence"][0]))
                else:
                    del record["negative_checks"]["disconnect"]
                with self.assertRaises(ValueError):
                    self.validate(root, bundle)

    def test_template_is_pending_and_cannot_satisfy_release(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            bundle = qualification_template(commit=COMMIT, candidate_run_id=123, records=RECORDS)
            self.assertEqual({r["status"] for r in bundle["domains"]}, {"pending"})
            self.assertFalse(bundle["domains"][0]["operator_attested"])
            with self.assertRaises(ValueError):
                self.validate(root, bundle)

    def test_collector_hashes_copies_and_verifies_without_changing_outcomes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source, output = root / "private", root / "portable"
            source.mkdir()
            bundle = self.bundle(source)
            for record in [*bundle["domains"], bundle["firmware"]]:
                record["evidence"][0].pop("sha256")
            manifest = self.write_bundle(source, bundle)
            result_path = collect_qualification(manifest, evidence_root=source, output=output, records=RECORDS)
            result = validate_qualification(result_path, commit=COMMIT, records=RECORDS)
            self.assertEqual(result["domains"][0]["observed"], bundle["domains"][0]["observed"])
            self.assertEqual((output / "evidence/usb.txt").read_bytes(), (source / "evidence/usb.txt").read_bytes())
            with self.assertRaises(ValueError):
                collect_qualification(manifest, evidence_root=source, output=output, records=RECORDS)

    def test_collector_refuses_pending_or_previously_hashed_changed_evidence(self):
        for mode in ("pending", "tampered"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                source = root / "private"
                source.mkdir()
                bundle = self.bundle(source)
                if mode == "pending":
                    bundle["domains"][0]["status"] = "pending"
                else:
                    (source / "evidence/usb.txt").write_text("changed")
                with self.assertRaises(ValueError):
                    collect_qualification(self.write_bundle(source, bundle), evidence_root=source,
                                          output=root / "portable", records=RECORDS)
                self.assertFalse((root / "portable").exists())

    def test_cli_verify_rejects_pending_and_accepts_complete_bundle(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipts = root / "records.json"
            receipts.write_text(json.dumps(RECORDS))
            bundle_path = self.write_bundle(root, qualification_template(commit=COMMIT, candidate_run_id=123, records=RECORDS))
            command = [sys.executable, str(ROOT / "scripts/hardware-qualification.py"), "verify", str(bundle_path),
                       "--commit", COMMIT, "--records", str(receipts)]
            refused = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(refused.returncode, 0)
            self.assertIn("qualification", refused.stderr.lower())
            self.write_bundle(root, self.bundle(root))
            passed = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(passed.returncode, 0, passed.stderr)
            self.assertEqual(json.loads(passed.stdout)["candidate_run_id"], 123)

    def test_cli_template_is_pending_and_will_not_overwrite_observations(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            receipts, output = root / "records.json", root / "observations.json"
            receipts.write_text(json.dumps(RECORDS))
            command = [sys.executable, str(ROOT / "scripts/hardware-qualification.py"), "template",
                       "--commit", COMMIT, "--candidate-run-id", "123", "--records", str(receipts),
                       "--output", str(output)]
            result = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["status"], "pending")
            original = output.read_bytes()
            repeated = subprocess.run(command, capture_output=True, text=True)
            self.assertNotEqual(repeated.returncode, 0)
            self.assertEqual(output.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
