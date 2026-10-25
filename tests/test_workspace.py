from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import opencyber.engagements as engagements
from opencyber.errors import OcError
from opencyber.workspace import read_workspace_file


class WorkspaceReadTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.patch = patch.object(engagements, "WORKSPACE", self.root)
        self.patch.start()
        self.engagement = engagements.create_engagement("Read", ["example.test"])
        self.engagement_id = self.engagement["engagement_id"]
        self.workspace = Path(self.engagement["workspace"])

    def tearDown(self):
        self.patch.stop()
        self.temporary.cleanup()

    def _write(self, name: str, content: str) -> None:
        path = self.workspace / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def test_complete_read_reports_no_truncation(self):
        self._write("notes.txt", "hello\n")
        result = read_workspace_file(self.engagement_id, "notes.txt")
        self.assertEqual(result["content"], "hello\n")
        self.assertEqual(result["offset"], 0)
        self.assertEqual(result["total_bytes"], 6)
        self.assertFalse(result["truncated"])
        self.assertIsNone(result["next_offset"])
        self.assertNotIn("coverage", result)

    def test_bounded_read_pages_with_an_explicit_continuation(self):
        content = "0123456789"
        self._write("page.txt", content)
        first = read_workspace_file(self.engagement_id, "page.txt", max_bytes=4)
        self.assertEqual(first["content"], "0123")
        self.assertTrue(first["truncated"])
        self.assertEqual(first["total_bytes"], 10)
        self.assertEqual(first["next_offset"], 4)
        self.assertEqual(first["coverage"]["status"], "partial")
        self.assertEqual(first["coverage"]["examined"], 4)
        self.assertEqual(first["coverage"]["total"], 10)
        self.assertIn("not evidence that it is empty", first["limitations"][0])
        self.assertEqual(first["continuation"]["tool"], "oc_workspace_read")
        self.assertEqual(first["continuation"]["arguments"]["offset"], 4)

        pages = [first["content"]]
        request = first["continuation"]["arguments"]
        while True:
            page = read_workspace_file(
                self.engagement_id,
                request["path"],
                max_bytes=request["max_bytes"],
                offset=request["offset"],
            )
            pages.append(page["content"])
            if not page["truncated"]:
                break
            request = page["continuation"]["arguments"]
        self.assertEqual("".join(pages), content)

    def test_zero_max_bytes_returns_the_whole_file(self):
        content = "x" * 5000
        self._write("whole.bin", content)
        result = read_workspace_file(self.engagement_id, "whole.bin", max_bytes=0)
        self.assertEqual(result["content"], content)
        self.assertFalse(result["truncated"])

    def test_ceiling_above_the_registry_maximum_is_a_limit_refusal(self):
        self._write("small.txt", "x")
        with self.assertRaises(OcError) as raised:
            read_workspace_file(self.engagement_id, "small.txt", max_bytes=10**9)
        error = raised.exception
        self.assertEqual(error.code, "limit_exceeded")
        self.assertEqual(error.limit["id"], "workspace.read_max_bytes")
        self.assertEqual(error.limit["requested"], 10**9)
        self.assertEqual(error.limit["maximum"], 67108864)
        json.dumps(error.to_dict())

    def test_invalid_arguments_are_named(self):
        self._write("small.txt", "x")
        for kwargs, code in (
            ({"max_bytes": -1}, "invalid_argument"),
            ({"offset": -1}, "invalid_argument"),
            ({"offset": 99}, "invalid_argument"),
        ):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(OcError) as raised:
                    read_workspace_file(self.engagement_id, "small.txt", **kwargs)
                self.assertEqual(raised.exception.code, code)

    def test_missing_file_is_not_found(self):
        with self.assertRaises(OcError) as raised:
            read_workspace_file(self.engagement_id, "missing.txt")
        self.assertEqual(raised.exception.code, "not_found")


if __name__ == "__main__":
    unittest.main()
