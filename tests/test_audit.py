from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import opencyber.engagements as engagements
from opencyber.audit import read_audit, record_event, verify_audit
from opencyber.executor import execute_tool


class AuditTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.patch = patch.object(engagements, "WORKSPACE", self.root)
        self.patch.start()
        self.engagement = engagements.create_engagement("Audit", ["example.test"])
        self.engagement_id = self.engagement["engagement_id"]

    def tearDown(self):
        self.patch.stop()
        self.temporary.cleanup()

    def test_hash_chain_is_valid_and_detects_tampering(self):
        record_event(self.engagement_id, {"event": "test.one", "value": 1})
        record_event(self.engagement_id, {"event": "test.two", "value": 2})
        record_event(self.engagement_id, {"event": "test.three", "value": 3})
        report = verify_audit(self.engagement_id)
        self.assertTrue(report["valid"])
        self.assertEqual(report["events"], 3)

        path = Path(self.engagement["workspace"]) / ".opencyber" / "audit" / "events.jsonl"
        lines = path.read_text(encoding="utf-8").splitlines()
        tampered = json.loads(lines[1])
        tampered["value"] = 99
        lines[1] = json.dumps(tampered, sort_keys=True)
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        broken = verify_audit(self.engagement_id)
        self.assertFalse(broken["valid"])
        self.assertEqual(broken["first_invalid_seq"], 2)
        self.assertIn("hash", broken["error"])

    def test_audit_writes_reject_cross_engagement_links_and_special_files(self):
        other = engagements.create_engagement("Other", ["other.example.test"])
        record_event(other["engagement_id"], {"event": "other.original"})
        other_path = Path(other["workspace"]) / ".opencyber/audit/events.jsonl"
        original = other_path.read_bytes()
        root = Path(self.engagement["workspace"])
        directory = root / ".opencyber/audit"
        directory.mkdir(parents=True)
        path = directory / "events.jsonl"
        for kind in ("symlink", "hardlink", "fifo"):
            with self.subTest(kind=kind):
                if kind == "symlink":
                    path.symlink_to(other_path)
                elif kind == "hardlink":
                    os.link(other_path, path)
                else:
                    os.mkfifo(path)
                try:
                    with self.assertRaises((OSError, ValueError)):
                        record_event(self.engagement_id, {"event": "must.not.append"})
                    self.assertEqual(other_path.read_bytes(), original)
                finally:
                    path.unlink()
        directory.rmdir()
        directory.symlink_to(other_path.parent, target_is_directory=True)
        with self.assertRaises((OSError, ValueError)):
            record_event(self.engagement_id, {"event": "must.not.append"})
        self.assertEqual(other_path.read_bytes(), original)

    def test_removed_event_breaks_the_chain(self):
        for index in range(3):
            record_event(self.engagement_id, {"event": "test", "index": index})
        path = Path(self.engagement["workspace"]) / ".opencyber" / "audit" / "events.jsonl"
        lines = path.read_text(encoding="utf-8").splitlines()
        path.write_text("\n".join([lines[0], lines[2]]) + "\n", encoding="utf-8")
        report = verify_audit(self.engagement_id)
        self.assertFalse(report["valid"])
        self.assertEqual(report["first_invalid_seq"], 2)

    def test_large_argument_event_does_not_restart_the_next_hash_chain(self):
        record_event(self.engagement_id, {"event": "test.large", "argument": "x" * 100_000})
        second = record_event(self.engagement_id, {"event": "test.after_large"})
        self.assertEqual(second["seq"], 2)
        report = verify_audit(self.engagement_id)
        self.assertTrue(report["valid"], report)
        self.assertEqual(report["events"], 2)

    def test_unreadable_trailing_record_is_not_treated_as_an_empty_audit(self):
        record_event(self.engagement_id, {"event": "test.one"})
        path = Path(self.engagement["workspace"]) / ".opencyber/audit/events.jsonl"
        with path.open("ab") as handle:
            handle.write(b"not-json\n")
        original = path.read_bytes()
        with self.assertRaises(ValueError):
            record_event(self.engagement_id, {"event": "must.not.restart"})
        self.assertEqual(path.read_bytes(), original)

    def test_public_audit_reader_and_verifier_do_not_call_a_symlink_empty(self):
        other = engagements.create_engagement("Other", ["other.test"])
        record_event(other["engagement_id"], {"event": "other.original"})
        directory = Path(self.engagement["workspace"]) / ".opencyber/audit"
        directory.mkdir(parents=True)
        path = directory / "events.jsonl"
        path.symlink_to(Path(other["workspace"]) / ".opencyber/audit/events.jsonl")
        with self.assertRaises((OSError, ValueError)):
            read_audit(self.engagement_id)
        report = verify_audit(self.engagement_id)
        self.assertFalse(report["valid"], report)

    def test_credentials_are_redacted(self):
        record_event(
            self.engagement_id,
            {
                "event": "test.secret",
                "password": "hunter2",
                "headers": {"Authorization": "Bearer abcdef"},
                "note": "token=deadbeef password=hunter2",
            },
        )
        entry = read_audit(self.engagement_id)["events"][0]
        self.assertEqual(entry["password"], "***")
        self.assertEqual(entry["headers"]["Authorization"], "***")
        self.assertNotIn("hunter2", entry["note"])
        self.assertNotIn("deadbeef", entry["note"])

    def test_executor_writes_tool_events(self):
        result = asyncio.run(
            execute_tool("printf", ["audit-me"], engagement_id=self.engagement_id)
        )
        self.assertTrue(result["success"])
        events = read_audit(self.engagement_id)["events"]
        tool_events = [event for event in events if event["event"] == "tool.exec"]
        self.assertEqual(len(tool_events), 1)
        self.assertEqual(tool_events[0]["executable"], "printf")
        self.assertEqual(tool_events[0]["arguments"], ["audit-me"])
        self.assertEqual(tool_events[0]["seq"], 1)
        self.assertIn("audit_seq", result)
        self.assertTrue(verify_audit(self.engagement_id)["valid"])

    def test_audit_can_be_disabled(self):
        with patch.dict("os.environ", {"OPENCYBER_AUDIT": "0"}):
            asyncio.run(
                execute_tool("printf", ["quiet"], engagement_id=self.engagement_id)
            )
        self.assertEqual(read_audit(self.engagement_id)["total"], 0)


if __name__ == "__main__":
    unittest.main()
