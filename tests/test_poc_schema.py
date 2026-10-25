from __future__ import annotations

import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import opencyber.engagements as engagements
from opencyber import poc_schema
from opencyber.workspace import delete_workspace_path, write_workspace_file


KEY = "k" * 64


class PocSchemaTests(unittest.TestCase):
    def test_canonical_json_is_key_order_independent(self):
        left = poc_schema.canonical_sha256({"b": 2, "a": [1, {"d": 4, "c": 3}]})
        right = poc_schema.canonical_sha256({"a": [1, {"c": 3, "d": 4}], "b": 2})
        self.assertEqual(left, right)
        self.assertEqual(len(left), 64)

    def test_record_ids_round_trip(self):
        for prefix in ("chain", "spec", "apr", "run"):
            value = poc_schema.new_record_id(prefix)
            self.assertEqual(poc_schema.validate_record_id(prefix, value), value)
        with self.assertRaises(poc_schema.PocError):
            poc_schema.validate_record_id("chain", "chain_bad")
        with self.assertRaises(poc_schema.PocError):
            poc_schema.validate_record_id("spec", poc_schema.new_record_id("chain"))

    def test_cve_normalization(self):
        self.assertEqual(poc_schema.normalize_cve_id(" cve-2026-1234 "), "CVE-2026-1234")
        with self.assertRaises(poc_schema.PocError):
            poc_schema.normalize_cve_id("CVE-26-1")

    def test_capability_vocabulary(self):
        accepted = [
            "net:http:8080",
            "net:internal:6379",
            "auth:none",
            "exec:container",
            "file:read:/var/www/*",
            "creds:api_key",
            "secret:read:db_password",
            "info:version",
            "position:internet",
        ]
        for token in accepted:
            self.assertEqual(poc_schema.validate_capability(token), token)
        refused = ["net:http:99999", "net:http:0", "exec:kernel", "auth:root", "unknown:value", ""]
        for token in refused:
            with self.assertRaises(poc_schema.PocError):
                poc_schema.validate_capability(token)
        self.assertEqual(
            poc_schema.normalize_capabilities(["net:http:80", "net:http:80", "auth:none"]),
            ["auth:none", "net:http:80"],
        )

    def test_redaction_covers_secret_headers_only(self):
        redacted = poc_schema.redact_headers(
            {"Authorization": "Bearer x", "Cookie": "a=b", "Server": "nginx"}
        )
        self.assertEqual(redacted["Authorization"], poc_schema.REDACTED)
        self.assertEqual(redacted["Cookie"], poc_schema.REDACTED)
        self.assertEqual(redacted["Server"], "nginx")

    def test_approval_key_resolution(self):
        with patch.dict(os.environ, {}, clear=True):
            with self.assertRaises(poc_schema.PocError) as missing:
                poc_schema.resolve_approval_key()
            self.assertEqual(missing.exception.reason, "approval_key_unavailable")
            self.assertFalse(poc_schema.approval_key_available())
        with patch.dict(os.environ, {poc_schema.APPROVAL_KEY_ENV: "short"}, clear=True):
            with self.assertRaises(poc_schema.PocError):
                poc_schema.resolve_approval_key()
        with patch.dict(os.environ, {poc_schema.APPROVAL_KEY_ENV: KEY}, clear=True):
            key, key_id = poc_schema.resolve_approval_key()
            self.assertEqual(key.decode(), KEY)
            self.assertEqual(len(key_id), 16)
            self.assertTrue(poc_schema.approval_key_available())

    def test_approval_key_file_fallback(self):
        with tempfile.TemporaryDirectory() as raw:
            path = Path(raw) / "key"
            path.write_text(KEY + "\n", encoding="utf-8")
            with patch.dict(
                os.environ,
                {poc_schema.APPROVAL_KEY_FILE_ENV: str(path)},
                clear=True,
            ):
                key, _ = poc_schema.resolve_approval_key()
            self.assertEqual(key.decode(), KEY)

    def test_limits_can_only_be_lowered(self):
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(poc_schema.resolved_limits()["max_requests"], poc_schema.DEFAULT_MAX_REQUESTS)
        with patch.dict(
            os.environ,
            {poc_schema.MAX_REQUESTS_ENV: "5", poc_schema.TIMEOUT_ENV: "10"},
            clear=True,
        ):
            limits = poc_schema.resolved_limits()
            self.assertEqual(limits["max_requests"], 5)
            self.assertEqual(limits["timeout_s"], 10)
        for bad in ("0", "999", "abc"):
            with patch.dict(os.environ, {poc_schema.MAX_REQUESTS_ENV: bad}, clear=True):
                with self.assertRaises(poc_schema.PocError):
                    poc_schema.resolved_limits()

    def test_parse_utc_requires_timezone(self):
        parsed = poc_schema.parse_utc("2026-10-25T10:00:00Z")
        self.assertEqual(poc_schema.iso_utc(parsed), "2026-10-25T10:00:00Z")
        with self.assertRaises(poc_schema.PocError):
            poc_schema.parse_utc("2026-10-25T10:00:00")

    def test_server_managed_paths(self):
        self.assertTrue(poc_schema.server_managed_path("engagement.json"))
        self.assertTrue(poc_schema.server_managed_path("poc"))
        self.assertTrue(poc_schema.server_managed_path("poc/authorization.json"))
        self.assertTrue(poc_schema.server_managed_path("./poc/runs/run_20261025_deadbeef/result.json"))
        self.assertFalse(poc_schema.server_managed_path("artifacts/nuclei.jsonl"))
        self.assertFalse(poc_schema.server_managed_path("findings/report.md"))


class WorkspacePocGuardTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.patch = patch.object(engagements, "WORKSPACE", self.root)
        self.patch.start()
        self.engagement = engagements.create_engagement("Guard", ["127.0.0.1"])
        self.engagement_id = self.engagement["engagement_id"]

    def tearDown(self):
        self.patch.stop()
        self.temporary.cleanup()

    def test_regular_artifact_writes_still_work(self):
        result = write_workspace_file(self.engagement_id, "artifacts/report.md", "ok")
        self.assertEqual(result["path"], "artifacts/report.md")

    def test_poc_subtree_is_server_managed(self):
        for path in (
            "poc/authorization.json",
            "poc/approvals/apr_20261025_deadbeef.json",
            "poc/chains/chain_20261025_deadbeef.json",
            "poc/specs/spec_20261025_deadbeef.json",
        ):
            with self.assertRaises(ValueError):
                write_workspace_file(self.engagement_id, path, "tampered")
        with self.assertRaises(ValueError):
            delete_workspace_path(self.engagement_id, "poc")


if __name__ == "__main__":
    unittest.main()
