import base64
import json
import asyncio
import gzip
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import opencyber.engagements as engagements
import opencyber.workspace as workspace
from opencyber.native_tools import decode_jwt, encode_payload, extract_indicators, technology_hints
from opencyber.workflows import attack_chain, engagement_plan, recommend_tools, scan_summary

import requests
import urllib3


class BodyTransport(requests.adapters.BaseAdapter):
    def __init__(self, body, *, redirect=False, compressed=False):
        self.body = body
        self.redirect = redirect
        self.compressed = compressed
        self.responses = []

    def send(self, request, **kwargs):
        response = requests.Response()
        response.request = request
        response.url = request.url
        response.status_code = 302 if self.redirect and request.url.endswith("/redirect") else 200
        response.encoding = "utf-8"
        if response.status_code == 302:
            response.headers["location"] = "/final"
        wire = gzip.compress(self.body) if self.compressed else self.body
        response.headers["Content-Length"] = str(len(wire))
        if self.compressed:
            response.headers["Content-Encoding"] = "gzip"
        response.raw = urllib3.response.HTTPResponse(
            body=io.BytesIO(wire), headers=response.headers, preload_content=False,
        )
        self.responses.append(response)
        return response

    def close(self):
        pass


class HttpBodyTests(unittest.TestCase):
    def call(self, body, *, redirect=False, follow_redirects=True, compressed=False):
        from opencyber.server import mcp

        adapter = BodyTransport(body, redirect=redirect, compressed=compressed)
        with patch.object(requests.Session, "get_adapter", return_value=adapter):
            result = asyncio.run(mcp.call_tool("oc_http_request", {
                "method": "GET", "url": "https://owned.test/redirect" if redirect else "https://owned.test/",
                "follow_redirects": follow_redirects,
            })).structured_content
        return result, adapter

    def test_five_megabyte_body_is_bounded_and_reports_partial_coverage(self):
        result, adapter = self.call(b"x" * (5 * 1024 * 1024))
        self.assertTrue(result["ok"])
        self.assertLessEqual(len(result["body"].encode()), 262144)
        self.assertTrue(result["truncated"])
        self.assertEqual(result["coverage"]["status"], "partial")
        self.assertFalse(result["coverage"]["exhausted"])
        self.assertEqual(result["limit"]["id"], "http.response_max_bytes")
        self.assertTrue(result["limitations"])
        self.assertIsNotNone(result["evidence"]["sha256"])
        self.assertLess(adapter.responses[0].raw.tell(), 5 * 1024 * 1024)
        self.assertTrue(adapter.responses[0].raw.closed)

    def test_empty_small_and_exact_limit_bodies_remain_complete(self):
        for body in (b"", "hello \u2713".encode(), b"x" * 262144):
            with self.subTest(size=len(body)):
                result, _ = self.call(body)
                self.assertEqual(result["body"], body.decode())
                self.assertFalse(result["truncated"])
                self.assertEqual(result["coverage"]["status"], "complete")
                self.assertIsNotNone(result["evidence"]["sha256"])

    def test_compressed_body_is_limited_after_decompression(self):
        result, _ = self.call(b"x" * (5 * 1024 * 1024), compressed=True)
        self.assertTrue(result["truncated"])
        self.assertEqual(len(result["body"]), 262144)

    def test_redirect_bodies_are_bounded_before_requests_drains_them(self):
        for follow in (True, False):
            with self.subTest(follow=follow):
                result, adapter = self.call(b"x" * (5 * 1024 * 1024), redirect=True, follow_redirects=follow)
                self.assertEqual(result["status"], 200 if follow else 302)
                self.assertTrue(result["truncated"])
                for response in adapter.responses:
                    self.assertLess(response.raw.tell(), 5 * 1024 * 1024)
                    self.assertTrue(response.raw.closed)


def b64url(payload):
    raw = json.dumps(payload, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


class NativeToolTests(unittest.TestCase):
    def test_jwt_decode_is_explicitly_unverified(self):
        token = f"{b64url({'alg': 'none'})}.{b64url({'sub': 'test'})}.signature"
        result = decode_jwt(token)
        self.assertEqual(result["payload"]["sub"], "test")
        self.assertFalse(result["verified"])

    def test_payload_encoding_and_indicator_extraction(self):
        self.assertEqual(encode_payload("opencyber", "base64")["encoded"], "b3BlbmN5YmVy")
        result = extract_indicators("See CVE-2026-12345 at https://example.test and 127.0.0.1")
        self.assertEqual(result["cves"], ["CVE-2026-12345"])
        self.assertEqual(result["ipv4"], ["127.0.0.1"])

    def test_technology_hints_only_use_supplied_evidence(self):
        result = technology_hints({"server": "nginx", "cf-ray": "abc"}, "")
        self.assertEqual(result["detected"], ["cloudflare", "nginx"])

    def test_deterministic_workflows(self):
        self.assertEqual(engagement_plan("recon", "example.test")["kind"], "recon")
        self.assertEqual(recommend_tools("audit an AWS account")["selected_workflow"], "cloud")
        chain = attack_chain([{"severity": "low"}, {"severity": "critical"}])
        self.assertEqual(chain["steps"][0]["finding"]["severity"], "critical")
        summary = scan_summary([{"success": True}, {"success": False}])
        self.assertEqual((summary["succeeded"], summary["failed"]), (1, 1))

    def test_finding_report_stays_in_workspace(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw).resolve()
            with patch.object(engagements, "WORKSPACE", root):
                engagement = engagements.create_engagement("Test", ["example.test"])
                result = workspace.write_finding_report(
                    engagement["engagement_id"],
                    "findings/test.md",
                    "Test finding",
                    "example.test",
                    "high",
                    "Summary",
                    ["Evidence"],
                    "Fix it",
                )
            self.assertEqual(result["path"], "findings/test.md")
            report = Path(engagement["workspace"]) / "findings/test.md"
            self.assertIn("Test finding", report.read_text())


if __name__ == "__main__":
    unittest.main()
