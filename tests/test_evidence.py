from __future__ import annotations

from concurrent.futures import CancelledError
import asyncio
import hashlib
import gzip
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import threading
import unittest
from unittest.mock import patch

import opencyber.engagements as engagements
from opencyber.audit import read_audit, record_event
from opencyber.errors import OcError
from opencyber.evidence import export_evidence, verify_evidence


class EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.patch = patch.object(engagements, "WORKSPACE", Path(self.temporary.name))
        self.patch.start()
        self.engagement = engagements.create_engagement("Synthetic investigation", ["lab.example.test"])
        self.engagement_id = self.engagement["engagement_id"]
        self.root = Path(self.engagement["workspace"])
        (self.root / "artifacts" / "sample.bin").write_bytes(b"synthetic\x00evidence\xff")
        record_event(self.engagement_id, {"event": "fixture.created"})

    def tearDown(self):
        self.patch.stop()
        self.temporary.cleanup()

    def export(self, **kwargs):
        return export_evidence(self.engagement_id, ["artifacts/sample.bin"], **kwargs)

    def rewrite(self, result, transform):
        path = self.root / result["path"]
        with tarfile.open(path, "r:gz") as archive:
            entries = [(member.name, archive.extractfile(member).read()) for member in archive]
        entries = transform(entries)
        with tarfile.open(path, "w:gz") as archive:
            for name, data in entries:
                member = tarfile.TarInfo(name)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))

    def test_round_trip_has_exact_members_and_snapshot_before_export_event(self):
        (self.root / ".opencyber" / "session-secret").write_text("do not include")
        result = self.export()
        archive_path = self.root / result["path"]
        self.assertEqual(hashlib.sha256(archive_path.read_bytes()).hexdigest(), result["sha256"])
        self.assertEqual((self.root / "artifacts" / "sample.bin").read_bytes(), b"synthetic\x00evidence\xff")
        report = verify_evidence(self.engagement_id, result["path"], result["sha256"])
        self.assertTrue(report["valid"], report)
        self.assertEqual(report["audit"]["events"], 1)
        self.assertEqual(read_audit(self.engagement_id)["events"][-1]["event"], "evidence.export")
        with tarfile.open(archive_path, "r:gz") as archive:
            self.assertEqual(set(archive.getnames()), {
                "manifest.json", "engagement.json", "audit/events.jsonl", "files/artifacts/sample.bin",
            })
            manifest = json.load(archive.extractfile("manifest.json"))
        self.assertEqual(manifest["schema_version"], 1)
        self.assertEqual(manifest["audit"]["events"], 1)

    def test_external_hash_mismatch_is_a_typed_integrity_refusal(self):
        result = self.export()
        with self.assertRaises(OcError) as raised:
            verify_evidence(self.engagement_id, result["path"], "f" * 64)
        self.assertEqual(raised.exception.code, "integrity_mismatch")
        self.assertIn("SHA-256", str(raised.exception))
        self.assertEqual(raised.exception.details["expected_sha256"], "f" * 64)

    def test_export_and_verify_declare_complete_coverage_and_integrity_only(self):
        result = self.export()
        self.assertEqual(result["coverage"]["status"], "complete")
        self.assertTrue(any("integrity-only" in item for item in result["limitations"]))
        report = verify_evidence(self.engagement_id, result["path"], result["sha256"])
        self.assertTrue(report["valid"])
        self.assertEqual(report["coverage"]["status"], "complete")
        self.assertIsNone(report["error_code"])
        self.assertTrue(any("integrity-only" in item for item in report["limitations"]))

    def test_damaged_bundle_is_a_finding_with_typed_code_and_unknown_coverage(self):
        result = self.export()
        self.rewrite(
            result,
            lambda entries: [
                (name, b"tampered" if name.startswith("files/") else data) for name, data in entries
            ],
        )
        report = verify_evidence(self.engagement_id, result["path"])
        self.assertFalse(report["valid"])
        self.assertEqual(report["error_code"], "integrity_mismatch")
        self.assertEqual(report["coverage"]["status"], "unknown")
        self.assertTrue(any("must not be trusted" in item for item in report["limitations"]))

    def test_existing_output_and_missing_input_are_typed_refusals(self):
        result = self.export()
        with self.assertRaises(OcError) as raised:
            self.export(output_path=result["path"])
        self.assertEqual(raised.exception.code, "already_exists")
        with self.assertRaises(OcError) as missing:
            export_evidence(self.engagement_id, ["artifacts/missing.bin"])
        self.assertEqual(missing.exception.code, "not_found")

    def test_live_evidence_tool_refusal_carries_already_exists(self):
        from opencyber.server import mcp

        result = self.export()
        envelope = asyncio.run(mcp.call_tool("oc_evidence_export", {
                "engagement_id": self.engagement_id,
                "paths": ["artifacts/sample.bin"],
                "output_path": result["path"],
            })).structured_content
        self.assertFalse(envelope["ok"])
        self.assertEqual(envelope["error"]["code"], "already_exists")

    def test_tampered_missing_extra_duplicate_and_unsafe_members_are_invalid(self):
        transforms = [
            lambda entries: [(name, b"tampered" if name.startswith("files/") else data) for name, data in entries],
            lambda entries: [(name, data) for name, data in entries if not name.startswith("files/")],
            lambda entries: entries + [("files/unselected.txt", b"extra")],
            lambda entries: entries + [entries[0]],
            lambda entries: entries + [("../escape", b"unsafe")],
        ]
        for index, transform in enumerate(transforms):
            with self.subTest(index=index):
                result = self.export(output_path=f"evidence/case-{index}.tar.gz")
                self.rewrite(result, transform)
                report = verify_evidence(self.engagement_id, result["path"])
                self.assertFalse(report["valid"], report)

    def test_tar_links_and_invalid_manifest_are_invalid(self):
        result = self.export()
        self.rewrite(result, lambda entries: [(name, b"{}" if name == "manifest.json" else data) for name, data in entries])
        self.assertFalse(verify_evidence(self.engagement_id, result["path"])["valid"])

    def test_oversized_pax_and_gnu_headers_are_rejected_before_payload_read(self):
        for extension in (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK):
            with self.subTest(extension=extension):
                header = tarfile.TarInfo("extended-header")
                header.type = extension
                header.size = 96 * 1024 * 1024
                path = self.root / "artifacts/hostile.tar.gz"
                # Header only: rejection must precede reading/allocating its payload.
                path.write_bytes(gzip.compress(header.tobuf()))
                result = verify_evidence(self.engagement_id, "artifacts/hostile.tar.gz")
                self.assertFalse(result["valid"])
                self.assertIn("extension metadata", result["error"])

    def test_pax_sparse_variants_are_rejected(self):
        for headers in ({"GNU.sparse.map": "0,1"}, {"GNU.sparse.size": "1"},
                        {"GNU.sparse.major": "1", "GNU.sparse.minor": "0"}):
            with self.subTest(headers=headers):
                path = self.root / "artifacts/sparse.tar.gz"
                with tarfile.open(path, "w:gz", format=tarfile.PAX_FORMAT) as archive:
                    member = tarfile.TarInfo("files/sparse")
                    member.pax_headers = headers
                    archive.addfile(member)
                result = verify_evidence(self.engagement_id, "artifacts/sparse.tar.gz")
                self.assertFalse(result["valid"])
                self.assertIn("sparse", result["error"])
        result = self.export(output_path="evidence/link.tar.gz")
        with tarfile.open(self.root / result["path"], "w:gz") as archive:
            member = tarfile.TarInfo("files/link")
            member.type = tarfile.SYMTYPE
            member.linkname = "../../outside"
            archive.addfile(member)
        self.assertFalse(verify_evidence(self.engagement_id, result["path"])["valid"])

    def test_missing_invalid_and_other_engagement_audit_fail_without_bundle(self):
        audit = self.root / ".opencyber" / "audit" / "events.jsonl"
        original = audit.read_bytes()
        for index, data in enumerate((None, b"not json\n", original.replace(self.engagement_id.encode(), b"other-engagement"))):
            with self.subTest(index=index):
                if data is None:
                    audit.unlink()
                else:
                    audit.write_bytes(data)
                with self.assertRaises((ValueError, OSError)):
                    self.export(output_path=f"evidence/bad-{index}.tar.gz")
                self.assertFalse((self.root / f"evidence/bad-{index}.tar.gz").exists())
        audit.write_bytes(original)

    def test_audit_write_failure_rolls_back_bundle(self):
        with patch("opencyber.evidence.record_event", side_effect=OSError("read-only audit")):
            with self.assertRaises(OSError):
                self.export(output_path="evidence/failure.tar.gz")
        self.assertEqual(list((self.root / "evidence").iterdir()), [])

    def test_paths_reject_traversal_absolute_symlinks_special_files_and_overlap(self):
        (self.root / "artifacts" / "link").symlink_to("sample.bin")
        (self.root / "alias").symlink_to("artifacts", target_is_directory=True)
        os.mkfifo(self.root / "artifacts" / "pipe")
        bad_paths = ["../outside", str(self.root / "artifacts/sample.bin"), "artifacts/link", "alias/sample.bin", "artifacts/pipe", "artifacts"]
        for path in bad_paths:
            with self.subTest(path=path), self.assertRaises((ValueError, OSError)):
                export_evidence(self.engagement_id, [path])
        with self.assertRaises(ValueError):
            self.export(output_path="artifacts/sample.bin")
        with self.assertRaises((ValueError, OSError)):
            self.export(output_path="alias/output.tar.gz")
        result = self.export()
        link = self.root / "evidence" / "bundle-link.tar.gz"
        link.symlink_to(Path(result["path"]).name)
        with self.assertRaises((ValueError, OSError)):
            verify_evidence(self.engagement_id, "evidence/bundle-link.tar.gz")

    def test_cancellation_leaves_no_completed_or_temporary_bundle(self):
        cancel = threading.Event()
        cancel.set()
        with self.assertRaises(CancelledError):
            self.export(cancel_event=cancel)
        self.assertEqual(list((self.root / "evidence").iterdir()), [])
        result = self.export()
        with self.assertRaises(CancelledError):
            verify_evidence(self.engagement_id, result["path"], cancel_event=cancel)

    def test_cancellation_during_payload_copy_cleans_temporary_output(self):
        from opencyber import evidence

        cancel = threading.Event()
        original = evidence._copy_regular

        def cancel_copy(*args, **kwargs):
            if args[2] == "files/artifacts/sample.bin":
                cancel.set()
            return original(*args, **kwargs)

        with patch("opencyber.evidence._copy_regular", side_effect=cancel_copy):
            with self.assertRaises(CancelledError):
                self.export(cancel_event=cancel)
        self.assertEqual(list((self.root / "evidence").iterdir()), [])

    def test_broken_audit_chain_and_head_are_rejected_even_with_updated_member_hashes(self):
        def corrupt_chain(entries):
            changed = []
            snapshot = None
            for name, data in entries:
                if name == "audit/events.jsonl":
                    record = json.loads(data)
                    record["event"] = "rewritten"
                    data = (json.dumps(record) + "\n").encode()
                    snapshot = data
                changed.append((name, data))
            result = []
            for name, data in changed:
                if name == "manifest.json":
                    manifest = json.loads(data)
                    entry = next(item for item in manifest["files"] if item["path"] == "audit/events.jsonl")
                    entry.update(size=len(snapshot), sha256=hashlib.sha256(snapshot).hexdigest())
                    data = json.dumps(manifest).encode()
                result.append((name, data))
            return result

        result = self.export()
        self.rewrite(result, corrupt_chain)
        report = verify_evidence(self.engagement_id, result["path"])
        self.assertFalse(report["valid"])
        self.assertIn("record hash", report["error"])
        result = self.export(output_path="evidence/bad-head.tar.gz")

        def corrupt_head(entries):
            changed = []
            for name, data in entries:
                if name == "manifest.json":
                    manifest = json.loads(data)
                    manifest["audit"]["last_hash"] = "0" * 64
                    data = json.dumps(manifest).encode()
                changed.append((name, data))
            return changed

        self.rewrite(result, corrupt_head)
        self.assertFalse(verify_evidence(self.engagement_id, result["path"])["valid"])

    def test_corrupt_compressed_archive_and_foreign_engagement_are_invalid(self):
        result = self.export()
        content = (self.root / result["path"]).read_bytes()
        other = engagements.create_engagement("Other", ["other.example.test"])
        other_root = Path(other["workspace"])
        (other_root / "evidence" / "foreign.tar.gz").write_bytes(content)
        self.assertFalse(verify_evidence(other["engagement_id"], "evidence/foreign.tar.gz")["valid"])
        corrupt = bytearray(content)
        corrupt[-8] ^= 0xff
        (self.root / result["path"]).write_bytes(corrupt)
        self.assertFalse(verify_evidence(self.engagement_id, result["path"])["valid"])

    def test_mutation_during_copy_fails_and_removes_partial_bundle(self):
        from opencyber import evidence

        original = evidence._copy_regular

        def mutate(*args, **kwargs):
            result = original(*args, **kwargs)
            if args[2] == "files/artifacts/sample.bin":
                (self.root / "artifacts" / "sample.bin").write_bytes(b"changed")
            return result

        with patch("opencyber.evidence._copy_regular", side_effect=mutate):
            with self.assertRaises(ValueError):
                self.export()
        self.assertEqual(list((self.root / "evidence").iterdir()), [])

    def test_concurrent_appends_do_not_corrupt_snapshot(self):
        errors = []

        def append():
            try:
                for index in range(25):
                    record_event(self.engagement_id, {"event": "concurrent", "index": index})
            except Exception as exc:
                errors.append(exc)

        thread = threading.Thread(target=append)
        thread.start()
        try:
            result = self.export()
        finally:
            thread.join()
        self.assertEqual(errors, [])
        self.assertTrue(verify_evidence(self.engagement_id, result["path"])["valid"])


if __name__ == "__main__":
    unittest.main()
