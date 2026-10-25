from __future__ import annotations

import asyncio
from concurrent.futures import CancelledError
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from opencyber import engagements, server


class BlueTeamMCPTests(unittest.TestCase):
    def test_registered_mcp_tools_triage_export_and_verify_real_files(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(engagements, "WORKSPACE", Path(directory)):
            case = engagements.create_engagement("Synthetic case", ["192.0.2.0/24"])
            eid = case["engagement_id"]
            Path(case["workspace"], "artifacts/events.jsonl").write_text(
                '{"timestamp":"2026-10-25T12:00:00Z","message":"source 192.0.2.1"}\n'
            )

            async def exercise():
                triage = await server.oc_file_triage(eid, "artifacts/events.jsonl")
                timeline = await server.oc_log_timeline(eid, "artifacts/events.jsonl")
                self.assertTrue(triage["complete"])
                self.assertTrue(timeline["complete"])
                bundle = await server.oc_evidence_export(eid, ["artifacts/events.jsonl", triage["report_path"], timeline["report_path"]])
                result = await server.oc_evidence_verify(eid, bundle["path"], bundle["sha256"])
                self.assertTrue(result["valid"], result)

            asyncio.run(exercise())
        catalog = server.oc_catalog(category="blue_team", include_contracts=True)
        from opencyber.diagnostics import FIXED_TOOL_CATEGORIES

        self.assertEqual(catalog["matched_tool_count"], len(FIXED_TOOL_CATEGORIES["blue_team"]))
        for tool in catalog["tools"]:
            self.assertIn("engagement_id", tool["input_schema"]["required"])

    def test_cancellation_waits_for_worker_cleanup(self):
        started = threading.Event()
        cleaned = threading.Event()

        def worker(*, cancel_event):
            started.set()
            try:
                if cancel_event.wait(10):
                    raise CancelledError()
                return {"unexpected_completion": True}
            finally:
                cleaned.set()

        async def exercise():
            task = asyncio.create_task(server._analysis_call(worker))
            while not started.is_set():
                await asyncio.sleep(0)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
            self.assertTrue(cleaned.is_set())

        asyncio.run(exercise())


if __name__ == "__main__":
    unittest.main()
