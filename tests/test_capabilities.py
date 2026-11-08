import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
from pathlib import Path
import tempfile
import socket
import threading
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, urlparse

import opencyber.engagements as engagements
from opencyber import native_tools
from opencyber.api_audit import audit_graphql, audit_jwt, audit_openapi, fuzz_api_parameter
from opencyber.errors import OcError
from opencyber.http_workbench import (
    create_http_session,
    get_http_session,
    intrude_http_parameter,
    read_http_history,
    repeat_http_request,
    update_http_session,
)


class FixtureHandler(BaseHTTPRequestHandler):
    def _send(self, status, payload, headers=None):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        for key, value in (headers or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/slow":
            import time as _time
            _time.sleep(0.3)
        if parsed.path == "/huge":
            self._send(200, {"data": "x" * (300 * 1024)})
            return
        if parsed.path == "/redirect-out":
            self.send_response(302)
            self.send_header("location", "https://example.com/")
            self.end_headers()
            return
        if parsed.path == "/set-restricted-cookies":
            self.send_response(200)
            self.send_header("Set-Cookie", "hostsecret=synthetic; Path=/")
            self.send_header("Set-Cookie", "pathsecret=synthetic; Path=/private")
            self.send_header("Set-Cookie", "securesecret=synthetic; Secure; Path=/")
            self.end_headers()
            return
        if parsed.path in {"/set-domain-cookies", "/delete-cookie"}:
            self.send_response(200)
            if parsed.path == "/set-domain-cookies":
                self.send_header("Set-Cookie", "hostsecret=synthetic; Path=/")
                self.send_header("Set-Cookie", "domainsecret=synthetic; Domain=allowed.test; Path=/")
            else:
                self.send_header("Set-Cookie", "hostsecret=; Max-Age=0; Path=/")
            self.end_headers()
            return
        self._send(
            200,
            {
                "path": parsed.path,
                "query": parse_qs(parsed.query),
                "header": self.headers.get("x-test", ""),
                "cookie": self.headers.get("Cookie", ""),
            },
            {"set-cookie": "fixture=1; Path=/"},
        )

    def do_POST(self):
        length = int(self.headers.get("content-length", "0"))
        raw = self.rfile.read(length).decode()
        if self.path == "/huge":
            self._send(200, {"data": "x" * (300 * 1024)})
            return
        if self.path == "/redirect-303":
            self.send_response(303)
            self.send_header("location", "/echo")
            self.end_headers()
            return
        if self.path == "/graphql":
            self._send(
                200,
                {
                    "data": {
                        "__schema": {
                            "queryType": {"name": "Query"},
                            "mutationType": {"name": "Mutation"},
                            "types": [
                                {"name": "Query", "kind": "OBJECT", "fields": [{"name": "viewer", "args": []}]},
                                {"name": "Mutation", "kind": "OBJECT", "fields": [{"name": "updateUser", "args": [{"name": "role"}]}]},
                            ],
                        }
                    }
                },
            )
            return
        self._send(200, {"body": raw, "header": self.headers.get("x-test", "")})

    def log_message(self, format, *args):
        return


class CapabilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if importlib.util.find_spec("requests") is None:
            raise unittest.SkipTest("requests is installed in the OpenCyber image, not this host interpreter")
        cls.server = ThreadingHTTPServer(("127.0.0.1", 0), FixtureHandler)
        cls.thread = threading.Thread(target=cls.server.serve_forever, daemon=True)
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.server.server_port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.thread.join(timeout=2)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.patch = patch.object(engagements, "WORKSPACE", self.root)
        self.patch.start()
        self.engagement = engagements.create_engagement("Test", ["127.0.0.1"])
        self.engagement_id = self.engagement["engagement_id"]

    def tearDown(self):
        self.patch.stop()
        self.temporary.cleanup()

    def test_openapi_graphql_and_jwt_audits_preserve_evidence(self):
        document = {
            "openapi": "3.1.0",
            "info": {"title": "Fixture", "version": "1"},
            "servers": [{"url": self.base_url}],
            "paths": {
                "/users/{user_id}": {
                    "get": {
                        "parameters": [{"name": "token", "in": "query"}],
                        "responses": {"200": {"description": "ok"}},
                    }
                }
            },
        }
        source = Path(self.engagement["workspace"]) / "openapi.json"
        source.write_text(json.dumps(document), encoding="utf-8")
        openapi = audit_openapi(self.engagement_id, "openapi.json")
        self.assertEqual(openapi["operation_count"], 1)
        self.assertTrue(openapi["review_items"])
        self.assertTrue((Path(self.engagement["workspace"]) / openapi["artifact_path"]).is_file())

        graphql = audit_graphql(self.engagement_id, self.base_url + "/graphql")
        self.assertTrue(graphql["introspection_available"])
        self.assertEqual(graphql["mutation_fields"][0]["name"], "updateUser")

        def encode(payload: dict[str, str]) -> str:
            return base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")

        token = f"{encode({'alg': 'none'})}.{encode({'sub': 'test'})}.signature"
        jwt = audit_jwt(self.engagement_id, token)
        self.assertEqual({item["code"] for item in jwt["review_items"]}, {"jwt_alg_none", "jwt_missing_exp"})
        self.assertFalse(jwt["verified"])
        self.assertEqual(jwt["coverage"]["status"], "complete")
        self.assertTrue(any("not cryptographically verified" in item for item in jwt["limitations"]))

    def test_http_consumers_bound_and_typed_response_failures(self):
        huge = self.base_url + "/huge"
        with patch.dict("os.environ", {"NO_PROXY": "127.0.0.1"}):
            graph = native_tools.graphql_request(huge, "{ x }")
            self.assertTrue(graph["truncated"])
            self.assertEqual(graph["coverage"]["status"], "partial")
            self.assertEqual(graph["limit"]["id"], "http.response_max_bytes")
            for call in (
                lambda: native_tools.inspect_openapi(self.engagement_id, huge),
                lambda: audit_openapi(self.engagement_id, huge),
                lambda: audit_graphql(self.engagement_id, huge),
            ):
                with self.subTest(call=call), self.assertRaises(OcError) as raised:
                    call()
                self.assertEqual(raised.exception.code, "truncated")
            fuzz = fuzz_api_parameter(
                self.engagement_id, self.base_url, "/huge", "GET", "query", "value", ["one"], 1
            )
            self.assertTrue(fuzz["results"][0]["truncated"])
            self.assertEqual(fuzz["results"][0]["limit"]["id"], "http.response_max_bytes")

    def test_workbench_response_is_bounded_with_partial_evidence(self):
        state = create_http_session(self.engagement_id, "Bounded", self.base_url)
        session_id = state["session_id"]
        with patch.dict("os.environ", {"NO_PROXY": "127.0.0.1"}):
            result = repeat_http_request(self.engagement_id, session_id, "GET", "/huge")
        self.assertTrue(result["response"]["truncated"])
        self.assertLessEqual(len(result["response"]["body"].encode()), 262144)
        self.assertEqual(result["response"]["limit"]["id"], "http.response_max_bytes")

    def test_cancelled_intruder_and_fuzz_stop_before_the_next_payload(self):
        state = create_http_session(self.engagement_id, "Cancelled", self.base_url)
        cancelled = threading.Event()
        cancelled.set()
        intruder = intrude_http_parameter(
            self.engagement_id, state["session_id"], "GET", "/echo", "query", "probe",
            ["a", "b"], 2, cancel_event=cancelled,
        )
        self.assertEqual(intruder["request_count"], 0)
        self.assertTrue(intruder["cancelled"])
        fuzz = fuzz_api_parameter(
            self.engagement_id, self.base_url, "/echo", "GET", "query", "value",
            ["a", "b"], 2, cancel_event=cancelled,
        )
        self.assertEqual(fuzz["request_count"], 0)
        self.assertTrue(fuzz["cancelled"])

    def test_api_fuzzing_is_caller_bounded(self):
        result = fuzz_api_parameter(
            self.engagement_id,
            self.base_url,
            "/echo",
            "GET",
            "query",
            "value",
            ["one", "two"],
            2,
        )
        self.assertEqual(result["request_count"], 2)
        with self.assertRaises(ValueError):
            fuzz_api_parameter(
                self.engagement_id,
                self.base_url,
                "/echo",
                "GET",
                "query",
                "value",
                ["one", "two"],
                1,
            )

    def test_http_workbench_scope_rules_cookies_intruder_and_history(self):
        state = create_http_session(
            self.engagement_id,
            "Fixture",
            self.base_url,
            default_headers={"x-test": "before"},
        )
        session_id = state["session_id"]
        update_http_session(
            self.engagement_id,
            session_id,
            rules=[{"location": "header", "match": "before", "replace": "after"}],
        )
        repeated = repeat_http_request(self.engagement_id, session_id, "GET", "/echo?base=1")
        parsed = json.loads(repeated["response"]["body"])
        self.assertEqual(parsed["header"], "after")
        self.assertEqual(get_http_session(self.engagement_id, session_id)["cookies"], {"fixture": "1"})

        intruder = intrude_http_parameter(
            self.engagement_id,
            session_id,
            "GET",
            "/echo",
            "query",
            "probe",
            ["a", "b"],
            2,
        )
        self.assertEqual(intruder["request_count"], 2)
        self.assertEqual(len(read_http_history(self.engagement_id, session_id)["entries"]), 3)
        from opencyber.errors import OcError

        for url in ("https://example.com/", "/redirect-out"):
            with self.subTest(url=url), self.assertRaises(OcError) as raised:
                repeat_http_request(self.engagement_id, session_id, "GET", url)
            self.assertEqual(raised.exception.code, "scope_denied")

    def test_redirect_evidence_records_final_body_and_original_body(self):
        state = create_http_session(self.engagement_id, "Redirect evidence", self.base_url)
        session_id = state["session_id"]
        repeat_http_request(
            self.engagement_id, session_id, "POST", "/redirect-303", body="original-body"
        )
        entry = read_http_history(self.engagement_id, session_id)["entries"][-1]
        self.assertEqual(entry["request"]["method"], "GET")
        self.assertIsNone(entry["request"]["body"])
        self.assertEqual(entry["request"]["original_body"], "original-body")
        final = json.loads(entry["response"]["body"])
        self.assertEqual(final["path"], "/echo")

    def test_concurrent_session_update_is_not_overwritten_by_inflight_request(self):
        state = create_http_session(self.engagement_id, "Session race", self.base_url)
        session_id = state["session_id"]
        started = threading.Event()

        def update_during_request():
            started.set()
            update_http_session(
                self.engagement_id,
                session_id,
                default_headers={"x-racy": "updated"},
                follow_redirects=False,
            )

        thread = threading.Thread(target=update_during_request)
        request_thread = threading.Thread(
            target=lambda: repeat_http_request(self.engagement_id, session_id, "GET", "/slow")
        )
        request_thread.start()
        started.wait(timeout=1)
        thread.start()
        thread.join(timeout=2)
        request_thread.join(timeout=2)
        current = get_http_session(self.engagement_id, session_id)
        self.assertEqual(current["default_headers"], {"x-racy": "updated"})
        self.assertFalse(current["follow_redirects"])

    def test_persisted_cookies_keep_host_path_and_secure_restrictions(self):
        base = self.base_url.replace("127.0.0.1", "localhost")
        with patch.dict("os.environ", {"NO_PROXY": "localhost,127.0.0.1"}):
            state = create_http_session(
                self.engagement_id, "Cookie boundaries", base, scope_hosts=["localhost", "127.0.0.1"],
            )
            sid = state["session_id"]
            repeat_http_request(self.engagement_id, sid, "GET", "/set-restricted-cookies")
            public = json.loads(repeat_http_request(self.engagement_id, sid, "GET", "/public")["response"]["body"])["cookie"]
            private = json.loads(repeat_http_request(self.engagement_id, sid, "GET", "/private/check")["response"]["body"])["cookie"]
            other = json.loads(repeat_http_request(self.engagement_id, sid, "GET", self.base_url + "/public")["response"]["body"])["cookie"]
        self.assertIn("hostsecret=synthetic", public)
        self.assertNotIn("pathsecret", public)
        self.assertNotIn("securesecret", public)
        self.assertIn("pathsecret=synthetic", private)
        self.assertNotIn("hostsecret", other)
        self.assertNotIn("_cookie_jar", get_http_session(self.engagement_id, sid))

    def test_manual_cookies_are_base_host_only_and_legacy_cookies_are_cleared(self):
        base = self.base_url.replace("127.0.0.1", "localhost")
        with patch.dict("os.environ", {"NO_PROXY": "localhost,127.0.0.1"}):
            state = create_http_session(
                self.engagement_id, "Manual cookies", base, scope_hosts=["localhost", "127.0.0.1"],
            )
            sid = state["session_id"]
            update_http_session(self.engagement_id, sid, cookies={"manual": "synthetic"})
            same = repeat_http_request(self.engagement_id, sid, "GET", "/echo")
            other = repeat_http_request(self.engagement_id, sid, "GET", self.base_url + "/echo")
            self.assertIn("manual=synthetic", json.loads(same["response"]["body"])["cookie"])
            self.assertNotIn("manual", json.loads(other["response"]["body"])["cookie"])
            path = Path(self.engagement["workspace"]) / ".opencyber" / "http-sessions" / (sid + ".json")
            legacy = json.loads(path.read_text())
            legacy.pop("_cookie_jar")
            legacy["cookies"] = {"legacy": "synthetic"}
            path.write_text(json.dumps(legacy))
            result = repeat_http_request(self.engagement_id, sid, "GET", "/echo")
            self.assertNotIn("legacy", json.loads(result["response"]["body"])["cookie"])

    def test_localhost_cookie_does_not_leak_to_distinct_localhost_local_host(self):
        original = socket.getaddrinfo

        def owned_dns(host, *args, **kwargs):
            return original("127.0.0.1" if host == "localhost.local" else host, *args, **kwargs)

        base = self.base_url.replace("127.0.0.1", "localhost")
        with patch.dict("os.environ", {"NO_PROXY": "localhost,localhost.local"}), patch("socket.getaddrinfo", side_effect=owned_dns):
            state = create_http_session(
                self.engagement_id, "Exact host", base, scope_hosts=["localhost", "localhost.local"],
            )
            sid = state["session_id"]
            repeat_http_request(self.engagement_id, sid, "GET", "/set-restricted-cookies")
            other = repeat_http_request(self.engagement_id, sid, "GET", base.replace("localhost", "localhost.local") + "/echo")
            self.assertNotIn("hostsecret", json.loads(other["response"]["body"])["cookie"])

    def test_host_only_cookie_is_withheld_from_subdomain_but_domain_cookie_is_sent(self):
        original = socket.getaddrinfo

        def owned_dns(host, *args, **kwargs):
            return original("127.0.0.1" if host in {"allowed.test", "sub.allowed.test"} else host, *args, **kwargs)

        base = self.base_url.replace("127.0.0.1", "allowed.test")
        with patch.dict("os.environ", {"NO_PROXY": "allowed.test,sub.allowed.test"}), patch("socket.getaddrinfo", side_effect=owned_dns):
            state = create_http_session(self.engagement_id, "Domain boundary", base, scope_hosts=["allowed.test", "sub.allowed.test"])
            sid = state["session_id"]
            repeat_http_request(self.engagement_id, sid, "GET", "/set-domain-cookies")
            result = repeat_http_request(self.engagement_id, sid, "GET", base.replace("allowed.test", "sub.allowed.test") + "/echo")
            cookies = json.loads(result["response"]["body"])["cookie"]
            self.assertNotIn("hostsecret", cookies)
            self.assertIn("domainsecret=synthetic", cookies)

    def test_server_deleted_cookie_does_not_reappear_after_reloading_session(self):
        state = create_http_session(self.engagement_id, "Deleted cookie", self.base_url)
        sid = state["session_id"]
        repeat_http_request(self.engagement_id, sid, "GET", "/set-restricted-cookies")
        repeat_http_request(self.engagement_id, sid, "GET", "/delete-cookie")
        result = repeat_http_request(self.engagement_id, sid, "GET", "/echo")
        self.assertNotIn("hostsecret", json.loads(result["response"]["body"])["cookie"])
        self.assertNotIn("hostsecret", get_http_session(self.engagement_id, sid)["cookies"])


if __name__ == "__main__":
    unittest.main()
