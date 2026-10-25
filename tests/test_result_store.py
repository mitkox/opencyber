from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest
from unittest.mock import patch

import opencyber.engagements as engagements
import opencyber.result_store as result_store
from opencyber.errors import OcError
from opencyber.result_store import (
    RETENTION_ENV,
    get_result,
    list_results,
    retention_mode,
)
from opencyber.server import mcp


class ResultStoreTests(unittest.TestCase):
    def test_async_finalization_does_not_block_event_loop_on_another_process_lock(self):
        from opencyber import envelope
        from opencyber.contracts import contract_for

        root = self._results_dir()
        root.mkdir(parents=True)
        program = "import fcntl,sys,time; f=open(sys.argv[1],'a'); fcntl.flock(f,fcntl.LOCK_EX); print('locked',flush=True); time.sleep(0.6)"
        holder = subprocess.Popen([sys.executable, "-c", program, str(root / ".lock")], stdout=subprocess.PIPE, text=True)
        try:
            self.assertEqual(holder.stdout.readline().strip(), "locked")

            async def handler(engagement_id):
                return {"observation": "completed"}

            wrapped = envelope.wrap(contract_for("oc_workspace_read"), handler)

            async def verify():
                start = time.monotonic()
                task = asyncio.create_task(wrapped(self.engagement_id))
                await asyncio.sleep(0.02)
                heartbeat_elapsed = time.monotonic() - start
                result = await task
                self.assertEqual(result["observation"], "completed")
                self.assertLess(heartbeat_elapsed, 0.3, "retention must not stall unrelated MCP work")

            with patch.dict(os.environ, {RETENTION_ENV: "digest"}):
                asyncio.run(verify())
        finally:
            holder.wait(timeout=3)
            holder.stdout.close()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.patch = patch.object(engagements, "WORKSPACE", self.root)
        self.patch.start()
        engagement = engagements.create_engagement("Results", ["example.test"])
        self.engagement_id = engagement["engagement_id"]
        self.workspace = Path(engagement["workspace"])

    def tearDown(self):
        self.patch.stop()
        self.temporary.cleanup()

    def _write(self, name: str, content: str) -> None:
        path = self.workspace / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def _call(self, tool: str, arguments: dict):
        payload = {"engagement_id": self.engagement_id, **arguments}
        result = asyncio.run(mcp.call_tool(tool, payload)).structured_content
        self.assertTrue(result["ok"], result)
        return result

    def _results_dir(self) -> Path:
        return self.workspace / ".opencyber" / "results"

    def test_retention_mode_defaults_to_digest(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop(RETENTION_ENV, None)
            self.assertEqual(retention_mode(), "digest")

    def test_invalid_retention_mode_fails_closed(self):
        with patch.dict(os.environ, {RETENTION_ENV: "everything"}):
            with self.assertRaises(OcError) as raised:
                retention_mode()
        self.assertEqual(raised.exception.code, "invalid_argument")
        self.assertEqual(raised.exception.details["setting"], RETENTION_ENV)

    def test_off_retains_neither_content_nor_index(self):
        self._write("note.txt", "hello")
        with patch.dict(os.environ, {RETENTION_ENV: "off"}):
            result = self._call("oc_workspace_read", {"path": "note.txt"})
        self.assertFalse(result["evidence"]["retained"])
        self.assertFalse((self._results_dir() / "index.jsonl").exists())

    def test_digest_mode_indexes_without_content(self):
        self._write("note.txt", "hello")
        with patch.dict(os.environ, {RETENTION_ENV: "digest"}):
            result = self._call("oc_workspace_read", {"path": "note.txt"})
        evidence_id = result["evidence"]["id"]
        self.assertFalse(result["evidence"]["retained"])
        index = (self._results_dir() / "index.jsonl").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(index), 1)
        self.assertEqual(json.loads(index[0])["id"], evidence_id)
        self.assertFalse((self._results_dir() / f"{evidence_id}.json").exists())
        stored = get_result(self.engagement_id, evidence_id)
        self.assertFalse(stored["retained"])
        self.assertIsNone(stored["result"])
        self.assertEqual(stored["evidence"]["tool"], "oc_workspace_read")

    def test_full_mode_stores_the_redacted_payload(self):
        self._write("secrets.txt", "password=hunter2\n")
        with patch.dict(os.environ, {RETENTION_ENV: "full"}):
            result = self._call("oc_workspace_read", {"path": "secrets.txt"})
        evidence_id = result["evidence"]["id"]
        self.assertTrue(result["evidence"]["retained"])
        stored = get_result(self.engagement_id, evidence_id)
        self.assertTrue(stored["retained"])
        content = stored["result"]["content"]
        self.assertNotIn("hunter2", content)
        self.assertIn("***", content)
        self.assertEqual(stored["result"]["path"], "secrets.txt")

    def test_identical_payloads_share_one_retained_record(self):
        self._write("note.txt", "stable")
        with patch.dict(os.environ, {RETENTION_ENV: "digest"}):
            first = self._call("oc_workspace_read", {"path": "note.txt"})
            second = self._call("oc_workspace_read", {"path": "note.txt"})
        self.assertEqual(first["evidence"]["id"], second["evidence"]["id"])
        self.assertEqual(list_results(self.engagement_id)["total"], 1)

    def test_unknown_evidence_id_is_not_found(self):
        unknown = "oc_ev_" + "0" * 40
        with self.assertRaises(OcError) as raised:
            get_result(self.engagement_id, unknown)
        self.assertEqual(raised.exception.code, "not_found")
        self.assertEqual(raised.exception.details["retention"], "digest")

    def test_malformed_evidence_id_is_rejected(self):
        for value in ("nope", "oc_ev_short", "oc_ev_" + "z" * 40):
            with self.subTest(value=value):
                with self.assertRaises(OcError) as raised:
                    get_result(self.engagement_id, value)
                self.assertEqual(raised.exception.code, "invalid_argument")

    def test_list_reports_coverage_and_pages(self):
        with patch.dict(os.environ, {RETENTION_ENV: "digest"}):
            for index in range(3):
                self._write("note.txt", f"hello {index}")
                self._call("oc_workspace_read", {"path": "note.txt"})
        first = list_results(self.engagement_id, limit=2)
        self.assertEqual(first["total"], 3)
        self.assertEqual(first["coverage"]["status"], "partial")
        self.assertEqual(first["coverage"]["examined"], 2)
        second = list_results(self.engagement_id, limit=2, offset=2)
        self.assertEqual(second["coverage"]["status"], "complete")
        self.assertEqual(len(second["results"]), 1)
        filtered = list_results(self.engagement_id, tool="oc_workspace_read")
        self.assertEqual(filtered["total"], 3)
        empty = list_results(self.engagement_id, tool="oc_not_run")
        self.assertEqual(empty["coverage"]["status"], "empty")

    def test_list_rejects_a_bad_limit(self):
        with self.assertRaises(OcError) as raised:
            list_results(self.engagement_id, limit=0)
        self.assertEqual(raised.exception.code, "invalid_argument")

    def test_pruning_drops_the_oldest_records(self):
        with patch.dict(os.environ, {RETENTION_ENV: "digest"}):
            with patch.object(result_store, "MAX_RETAINED_RECORDS", 2):
                for index in range(4):
                    self._write("note.txt", f"hello {index}")
                    self._call("oc_workspace_read", {"path": "note.txt"})
        index = (self._results_dir() / "index.jsonl").read_text(encoding="utf-8").splitlines()
        self.assertEqual(len(index), 2)

    def test_independent_server_processes_do_not_lose_or_corrupt_results(self):
        start = self.root / "start"
        code = """
import hashlib,sys,time
from pathlib import Path
from opencyber import result_store
engagement_id,prefix,start = sys.argv[1:]
deadline = time.monotonic() + 5
while not Path(start).exists():
    if time.monotonic() > deadline:
        raise RuntimeError('start not signalled')
    time.sleep(.01)
for number in range(30):
    digest = hashlib.sha256(f'{prefix}:{number}'.encode()).hexdigest()
    result_store.retain(engagement_id, {
        'contract': {'tool': 'oc_workspace_read'},
        'content': f'result {prefix}:{number}',
        'evidence': {'id': 'oc_ev_' + digest[:40], 'sha256': digest, 'bytes': 20},
    })
"""
        with patch.dict(os.environ, {RETENTION_ENV: "full"}):
            processes = [subprocess.Popen(
                [sys.executable, "-c", code, self.engagement_id, str(i), str(start)],
                env={**os.environ, "OPENCYBER_WORKSPACE": str(self.root)},
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            ) for i in range(4)]
            try:
                start.touch()
                for process in processes:
                    _, error = process.communicate(timeout=20)
                    self.assertEqual(process.returncode, 0, error.decode())
                results = list_results(self.engagement_id, limit=500)
                self.assertEqual(results["total"], 120)
                for record in results["results"]:
                    self.assertTrue(get_result(self.engagement_id, record["id"])["retained"])
            finally:
                for process in processes:
                    if process.poll() is None:
                        process.kill()
                    process.communicate()

    def test_digest_replacement_does_not_expose_previously_retained_content(self):
        from opencyber.contracts import contract_for
        from opencyber.envelope import finalize

        with patch.dict(os.environ, {RETENTION_ENV: "full"}):
            first = finalize(contract_for("oc_workspace_read"), {"content": "hello"},
                             engagement_id=self.engagement_id)
        with patch.dict(os.environ, {RETENTION_ENV: "digest"}):
            second = finalize(contract_for("oc_workspace_read"), {"content": "hello"},
                              engagement_id=self.engagement_id)
        self.assertEqual(first["evidence"]["id"], second["evidence"]["id"])
        stored = get_result(self.engagement_id, second["evidence"]["id"])
        self.assertFalse(stored["retained"])
        self.assertIsNone(stored["result"])

    def test_corrupt_index_is_not_silently_reported_as_complete(self):
        self._write(".opencyber/results/index.jsonl", "not-json\n")
        with self.assertRaises(OcError) as raised:
            list_results(self.engagement_id)
        self.assertEqual(raised.exception.code, "integrity_mismatch")

    def test_retained_payload_symlink_cannot_read_outside_the_engagement(self):
        from opencyber.contracts import contract_for
        from opencyber.envelope import finalize

        with patch.dict(os.environ, {RETENTION_ENV: "full"}):
            result = finalize(contract_for("oc_workspace_read"), {"content": "hello"},
                              engagement_id=self.engagement_id)
        evidence_id = result["evidence"]["id"]
        outside = self.root / "outside.json"
        outside.write_text('{"private": "outside"}')
        path = self._results_dir() / f"{evidence_id}.json"
        path.unlink()
        path.symlink_to(outside)
        with self.assertRaises(OcError) as raised:
            get_result(self.engagement_id, evidence_id)
        self.assertEqual(raised.exception.code, "integrity_mismatch")

    def test_finding_cites_retained_results(self):
        self._write("note.txt", "hello")
        with patch.dict(os.environ, {RETENTION_ENV: "full"}):
            result = self._call("oc_workspace_read", {"path": "note.txt"})
            evidence_id = result["evidence"]["id"]
            finding = self._call(
                "oc_finding_report",
                {
                    "path": "findings/finding.md",
                    "title": "Test finding",
                    "target": "example.test",
                    "severity": "low",
                    "summary": "Synthetic.",
                    "evidence": ["Observed the note file."],
                    "evidence_ids": [evidence_id],
                },
            )
        report = (self.workspace / "findings" / "finding.md").read_text(encoding="utf-8")
        self.assertIn(evidence_id, report)
        self.assertIn("oc_workspace_read", report)
        self.assertIn("retained", report)
        self.assertEqual(finding["evidence_ids"], [evidence_id])

    def test_finding_with_an_unknown_evidence_id_refuses(self):
        result = asyncio.run(mcp.call_tool("oc_finding_report", {
                    "engagement_id": self.engagement_id,
                    "path": "findings/bad.md",
                    "title": "Bad",
                    "target": "example.test",
                    "severity": "low",
                    "summary": "Synthetic.",
                    "evidence": [],
                    "evidence_ids": ["oc_ev_" + "f" * 40],
                })).structured_content
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"]["code"], "not_found")
        self.assertFalse((self.workspace / "findings" / "bad.md").exists())


if __name__ == "__main__":
    unittest.main()
