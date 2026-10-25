from __future__ import annotations

import asyncio
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import opencyber.audit as audit
import opencyber.engagements as engagements
from opencyber.audit import read_audit, record_event


class AuditPaginationTests(unittest.TestCase):
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

    def _seed(self, count: int) -> None:
        for index in range(count):
            record_event(self.engagement_id, {"event": "test.event", "value": index})

    def test_first_page_reports_partial_coverage(self):
        self._seed(10)
        result = read_audit(self.engagement_id, limit=4)
        self.assertEqual(result["total"], 10)
        self.assertTrue(result["total_exact"])
        self.assertEqual(len(result["events"]), 4)
        self.assertEqual(result["coverage"]["status"], "partial")
        self.assertEqual(result["coverage"]["examined"], 10)
        self.assertEqual(result["coverage"]["next_offset"], 4)
        self.assertTrue(result["limitations"])

    def test_last_page_is_complete(self):
        self._seed(10)
        result = read_audit(self.engagement_id, limit=4, offset=8)
        self.assertEqual(len(result["events"]), 2)
        self.assertEqual(result["coverage"]["status"], "complete")
        self.assertEqual(result["coverage"]["exhausted"], True)
        self.assertIsNone(result["coverage"]["next_offset"])

    def test_event_filter_pages_only_matching_records(self):
        self._seed(3)
        for index in range(3):
            record_event(self.engagement_id, {"event": "other.event", "value": index})
        result = read_audit(self.engagement_id, limit=10, event="other.event")
        self.assertEqual(result["total"], 3)
        self.assertTrue(all(entry["event"] == "other.event" for entry in result["events"]))
        self.assertEqual(result["coverage"]["status"], "complete")

    def test_an_oversized_trail_is_bounded_and_honest(self):
        self._seed(20)
        with patch.object(audit, "MAX_READ_EVENTS", 5):
            result = read_audit(self.engagement_id, limit=100)
        self.assertEqual(result["total"], 5)
        self.assertFalse(result["total_exact"])
        self.assertEqual(result["coverage"]["status"], "partial")
        self.assertIsNone(result["coverage"]["total"])
        self.assertEqual(result["limit"]["id"], "audit.max_events")
        self.assertEqual(result["limit"]["effective"], 5)
        self.assertIn("more records remain", result["limitations"][0])

    def test_offset_beyond_the_end_is_empty_not_an_error(self):
        self._seed(3)
        result = read_audit(self.engagement_id, limit=10, offset=99)
        self.assertEqual(result["events"], [])
        self.assertEqual(result["coverage"]["status"], "complete")
        self.assertTrue(result["coverage"]["exhausted"])


if __name__ == "__main__":
    unittest.main()


class CatalogPaginationTests(unittest.TestCase):
    def _catalog(self, **arguments):
        from opencyber.server import mcp

        return asyncio.run(mcp.call_tool("oc_catalog", arguments)).structured_content

    def test_a_filtered_query_pages_with_a_continuation(self):
        first = self._catalog(query="oc_", limit=5)
        self.assertTrue(first["ok"])
        self.assertEqual(first["returned_tool_count"], 5)
        self.assertGreater(first["matched_tool_count"], 5)
        self.assertEqual(first["coverage"]["status"], "partial")
        self.assertEqual(first["coverage"]["next_offset"], 5)
        self.assertIsNotNone(first["continuation"])
        second = self._catalog(**first["continuation"]["arguments"])
        self.assertEqual(len(second["tools"]), 5)
        first_names = {entry["name"] for entry in first["tools"]}
        second_names = {entry["name"] for entry in second["tools"]}
        self.assertTrue(first_names.isdisjoint(second_names))

    def test_unbounded_call_still_returns_every_match(self):
        result = self._catalog(query="oc_")
        self.assertEqual(result["returned_tool_count"], result["matched_tool_count"])
        self.assertEqual(result["coverage"]["status"], "complete")
        self.assertIsNone(result["continuation"])

    def test_an_empty_match_set_is_reported_empty(self):
        result = self._catalog(query="definitely-not-a-tool")
        self.assertEqual(result["matched_tool_count"], 0)
        self.assertEqual(result["coverage"]["status"], "empty")

    def test_invalid_paging_is_a_typed_refusal(self):
        result = self._catalog(query="oc_", limit=-1)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"]["code"], "invalid_argument")


class WorkspacePaginationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.patch = patch.object(engagements, "WORKSPACE", self.root)
        self.patch.start()
        # Retention writes an index under .opencyber/ and would change the listing
        # between pages; this test is about paging, not retention.
        self.retention = patch.dict("os.environ", {"OPENCYBER_RESULT_RETENTION": "off"})
        self.retention.start()
        engagement = engagements.create_engagement("List", ["example.test"])
        self.engagement_id = engagement["engagement_id"]
        self.workspace = Path(engagement["workspace"])
        for index in range(7):
            (self.workspace / f"file-{index}.txt").write_text(str(index), encoding="utf-8")
        self.expected_entries = len(list(self.workspace.iterdir()))

    def tearDown(self):
        self.retention.stop()
        self.patch.stop()
        self.temporary.cleanup()

    def _list(self, **arguments):
        from opencyber.server import mcp

        return asyncio.run(mcp.call_tool("oc_workspace_list", {"engagement_id": self.engagement_id, **arguments})).structured_content

    def test_a_bounded_listing_pages_and_completes(self):
        collected: list[str] = []
        request = {"limit": 3}
        pages = 0
        while True:
            page = self._list(**request)
            self.assertTrue(page["ok"])
            collected.extend(entry["path"] for entry in page["entries"])
            pages += 1
            self.assertLessEqual(pages, 5)
            if page["continuation"] is None:
                self.assertEqual(page["coverage"]["status"], "complete")
                break
            self.assertEqual(page["coverage"]["status"], "partial")
            request = {key: value for key, value in page["continuation"]["arguments"].items() if key != "engagement_id"}
        self.assertEqual(len(collected), self.expected_entries)
        self.assertEqual(len(set(collected)), self.expected_entries)

    def test_unbounded_listing_returns_every_entry(self):
        page = self._list()
        self.assertEqual(len(page["entries"]), self.expected_entries)
        self.assertEqual(page["total_entries"], self.expected_entries)
        self.assertEqual(page["coverage"]["status"], "complete")

    def test_recursive_listing_pages_work(self):
        (self.workspace / "sub").mkdir()
        (self.workspace / "sub" / "nested.txt").write_text("x", encoding="utf-8")
        page = self._list(recursive=True, limit=2)
        self.assertEqual(page["total_entries"], self.expected_entries + 2)
        self.assertEqual(len(page["entries"]), 2)
        self.assertIsNotNone(page["continuation"])

    def test_missing_path_is_not_found(self):
        result = self._list(path="does-not-exist", limit=1)
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"]["code"], "not_found")
