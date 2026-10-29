from __future__ import annotations

import asyncio
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import opencyber.engagements as engagements
from opencyber.executor import execute_tool
from opencyber.policy import (
    enforcement_decision,
    extract_candidates,
    scope_check,
    target_matches,
)


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.patch = patch.object(engagements, "WORKSPACE", self.root)
        self.patch.start()
        self.engagement = engagements.create_engagement(
            "Scope", ["10.0.0.0/24", "example.com", "*.partner.test"]
        )
        self.engagement_id = self.engagement["engagement_id"]

    def tearDown(self):
        self.patch.stop()
        self.temporary.cleanup()

    def test_target_matching_supports_cidr_domains_and_subdomains(self):
        self.assertTrue(target_matches("10.0.0.7", "10.0.0.0/24"))
        self.assertFalse(target_matches("10.0.1.7", "10.0.0.0/24"))
        self.assertTrue(target_matches("api.example.com", "example.com"))
        self.assertTrue(target_matches("example.com", "example.com"))
        self.assertFalse(target_matches("example.org", "example.com"))
        self.assertTrue(target_matches("app.partner.test", "*.partner.test"))
        self.assertFalse(target_matches("10.0.0.7", "example.com"))

    def test_scope_check_reports_the_matched_target(self):
        allowed = scope_check(self.engagement_id, "https://api.example.com/v1")
        self.assertTrue(allowed["allowed"])
        self.assertEqual(allowed["matched_target"], "example.com")
        denied = scope_check(self.engagement_id, "https://evil.test/")
        self.assertFalse(denied["allowed"])

    def test_candidate_extraction_is_narrow(self):
        candidates = extract_candidates(
            [
                "https://api.example.com/path",
                "10.0.0.5",
                "10.0.0.0/24",
                "payload.txt",
                "--script=http-title.nse",
                "example.com:8443",
                "not-a-host",
            ]
        )
        self.assertIn("https://api.example.com/path", candidates)
        self.assertIn("10.0.0.5", candidates)
        self.assertIn("10.0.0.0/24", candidates)
        self.assertIn("example.com:8443", candidates)
        self.assertNotIn("payload.txt", candidates)
        self.assertNotIn("--script=http-title.nse", candidates)

    def test_enforcement_is_off_by_default_and_blocks_out_of_scope(self):
        decision = enforcement_decision(self.engagement_id, "printf", ["8.8.8.8"])
        self.assertFalse(decision["enforced"])
        self.assertIn("8.8.8.8", decision["denied"])

        with patch.dict("os.environ", {"OPENCYBER_ENFORCE_SCOPE": "1"}):
            with self.assertRaises(ValueError):
                asyncio.run(
                    execute_tool(
                        "printf", ["8.8.8.8"], engagement_id=self.engagement_id
                    )
                )
            allowed = asyncio.run(
                execute_tool(
                    "printf", ["example.com"], engagement_id=self.engagement_id
                )
            )
            self.assertTrue(allowed["success"])
            self.assertTrue(allowed["scope_enforced"])

    def test_offline_mode_blocks_known_internet_only_executables(self):
        with patch.dict("os.environ", {"OPENCYBER_OFFLINE": "1"}):
            with self.assertRaises(ValueError):
                asyncio.run(
                    execute_tool("shodan", ["info"], engagement_id=self.engagement_id)
                )

            with patch.dict(
                "os.environ", {"OPENCYBER_OFFLINE_ALLOW_NETWORK_TOOLS": "1"}
            ):
                result = asyncio.run(
                    execute_tool("shodan", ["info"], engagement_id=self.engagement_id)
                )
                self.assertEqual(result["executable"], "shodan")

    def test_live_policy_refusals_use_advertised_codes(self):
        from opencyber.contracts import contract_for
        from opencyber.server import mcp

        cases = (
            ("oc_nmap", {"engagement_id": self.engagement_id, "arguments": ["evil.test", "-sT"]},
             {"OPENCYBER_ENFORCE_SCOPE": "1"}, "scope_denied"),
            ("oc_shodan", {"engagement_id": self.engagement_id, "arguments": ["info"]},
             {"OPENCYBER_OFFLINE": "1"}, "offline_blocked"),
            ("oc_hibp_password_check", {"password": "synthetic-not-a-secret"},
             {"OPENCYBER_OFFLINE": "1"}, "offline_blocked"),
            ("oc_cve_lookup", {"cve_id": "CVE-2026-0001"},
             {"OPENCYBER_OFFLINE": "1", "OPENCYBER_CVE_DB": str(self.root / "missing.sqlite")}, "offline_blocked"),
        )
        for name, arguments, environment, expected in cases:
            with self.subTest(tool=name), patch.dict("os.environ", environment):
                result = asyncio.run(mcp.call_tool(name, arguments)).structured_content
                self.assertFalse(result["ok"])
                self.assertEqual(result["error"]["code"], expected)
                self.assertIn(expected, contract_for(name).error_codes)

    def test_unscoped_execution_is_refused_under_enforcement(self):
        with patch.dict("os.environ", {"OPENCYBER_ENFORCE_SCOPE": "1"}):
            with self.assertRaises(ValueError):
                asyncio.run(
                    execute_tool(
                        "bash", ["-c", "true"], engagement_id=self.engagement_id
                    )
                )
            with patch.dict("os.environ", {"OPENCYBER_ALLOW_UNSCOPED_EXECUTION": "1"}):
                result = asyncio.run(
                    execute_tool(
                        "bash", ["-c", "true"], engagement_id=self.engagement_id
                    )
                )
                self.assertTrue(result["success"])


class OfflineContractTests(unittest.TestCase):
    def test_reported_blocked_executables_match_the_policy_constant(self):
        from opencyber.assets import OFFLINE_NETWORK_EXECUTABLES, offline_status
        from opencyber.policy import OFFLINE_NETWORK_EXECUTABLES as POLICY_SET

        self.assertIs(POLICY_SET, OFFLINE_NETWORK_EXECUTABLES)
        self.assertEqual(
            offline_status()["blocked_executables"],
            sorted(OFFLINE_NETWORK_EXECUTABLES),
        )

    def test_sherlock_is_reported_as_internet_dependent(self):
        from opencyber.assets import offline_status

        self.assertIn("oc_sherlock", offline_status()["internet_dependent_features"])


if __name__ == "__main__":
    unittest.main()


class UrlScopeTests(unittest.TestCase):
    """Native HTTP tools cross the same scope boundary as argv tools."""

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.patch = patch.object(engagements, "WORKSPACE", self.root)
        self.patch.start()
        self.engagement = engagements.create_engagement("Scope", ["10.0.0.0/24", "example.com"])
        self.engagement_id = self.engagement["engagement_id"]
        self.enforce = patch.dict("os.environ", {"OPENCYBER_ENFORCE_SCOPE": "1"})
        self.enforce.start()

    def tearDown(self):
        self.enforce.stop()
        self.patch.stop()
        self.temporary.cleanup()

    def test_decision_allows_an_in_scope_url(self):
        from opencyber.policy import url_scope_decision

        decision = url_scope_decision(self.engagement_id, "https://api.example.com/v1")
        self.assertTrue(decision["enforced"])
        self.assertTrue(decision["allowed"])
        self.assertEqual(decision["matched_target"], "example.com")

    def test_decision_denies_an_out_of_scope_url(self):
        from opencyber.policy import url_scope_decision

        decision = url_scope_decision(self.engagement_id, "https://example.org/v1")
        self.assertTrue(decision["enforced"])
        self.assertFalse(decision["allowed"])
        self.assertIn("out-of-scope", decision["reason"])

    def test_missing_engagement_is_named(self):
        from opencyber.errors import OcError
        from opencyber.policy import enforce_url_scope

        with self.assertRaises(OcError) as raised:
            enforce_url_scope(None, "https://example.com/", tool="oc_http_request")
        self.assertEqual(raised.exception.code, "engagement_required")

    def test_denied_url_raises_scope_denied_with_context(self):
        from opencyber.errors import OcError
        from opencyber.policy import enforce_url_scope

        with self.assertRaises(OcError) as raised:
            enforce_url_scope(self.engagement_id, "https://example.org/", tool="oc_http_request")
        error = raised.exception
        self.assertEqual(error.code, "scope_denied")
        self.assertEqual(error.details["host"], "example.org")
        self.assertEqual(error.details["tool"], "oc_http_request")

    def test_http_request_refuses_before_any_fetch(self):
        from opencyber.errors import OcError
        from opencyber.native_tools import http_request

        with patch("requests.request") as fetch:
            with self.assertRaises(OcError) as raised:
                http_request("GET", "https://example.org/", engagement_id=self.engagement_id)
        self.assertEqual(raised.exception.code, "scope_denied")
        fetch.assert_not_called()

    def test_http_request_reports_scope_enforcement_in_the_result(self):
        from opencyber.native_tools import http_request

        response = type(
            "Response",
            (),
            {"status_code": 200, "url": "https://example.com/", "headers": {}, "text": "ok", "_opencyber_body_truncated": False},
        )()
        with patch("requests.request", return_value=response):
            result = http_request("GET", "https://example.com/", engagement_id=self.engagement_id)
        self.assertTrue(result["scope_enforced"])
        self.assertEqual(result["requested_url"], "https://example.com/")

    def test_api_fuzz_refuses_an_out_of_scope_base_url_before_sending(self):
        from opencyber.api_audit import fuzz_api_parameter
        from opencyber.errors import OcError

        with patch("requests.request") as fetch:
            with self.assertRaises(OcError) as raised:
                fuzz_api_parameter(
                    self.engagement_id,
                    "https://example.org",
                    "/search",
                    "GET",
                    "query",
                    "q",
                    ["a"],
                    1,
                )
        self.assertEqual(raised.exception.code, "scope_denied")
        fetch.assert_not_called()

    def test_workbench_repeater_checks_engagement_scope(self):
        from opencyber.errors import OcError
        from opencyber.http_workbench import create_http_session, repeat_http_request

        # The session may be created in scope, then the target leaves scope.
        session = create_http_session(self.engagement_id, "test", "https://example.com")
        with patch("requests.Session.request") as fetch:
            with self.assertRaises(OcError) as raised:
                repeat_http_request(
                    self.engagement_id,
                    session["session_id"],
                    "GET",
                    "https://example.org/",
                )
        self.assertEqual(raised.exception.code, "scope_denied")
        fetch.assert_not_called()

    def test_enforcement_off_allows_an_unscoped_url_and_says_so(self):
        from opencyber.native_tools import http_request

        self.enforce.stop()
        response = type(
            "Response",
            (),
            {"status_code": 200, "url": "https://example.org/", "headers": {}, "text": "ok", "_opencyber_body_truncated": False},
        )()
        with patch("requests.request", return_value=response):
            result = http_request("GET", "https://example.org/")
        self.assertFalse(result["scope_enforced"])
        self.enforce.start()
