"""Exercise requests' real redirect machinery without opening a socket."""
from __future__ import annotations

import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import urlsplit

import requests

from opencyber import api_audit, engagements, http_workbench, native_tools
from opencyber.errors import OcError


class FixtureTransport(requests.adapters.BaseAdapter):
    def __init__(self, destination="https://outside.test/target"):
        self.destination = destination
        self.sent = []
        self.sent_headers = []

    def send(self, request, **kwargs):
        self.sent.append(request.url)
        self.sent_headers.append(dict(request.headers))
        response = requests.Response()
        response.request = request
        response.url = request.url
        response.raw = io.BytesIO(b"{}")
        response._content = b"{}"
        response.status_code = 302 if urlsplit(request.url).path == "/redirect" else 200
        if response.status_code == 302:
            response.headers["location"] = self.destination
        return response

    def close(self):
        pass


class HttpRedirectScopeTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        workspace = patch.object(engagements, "WORKSPACE", Path(temporary.name))
        workspace.start()
        self.addCleanup(workspace.stop)
        self.engagement_id = engagements.create_engagement("Redirects", ["allowed.test"])["engagement_id"]

    def calls(self):
        eid = self.engagement_id
        url = "https://allowed.test/redirect"
        return {
            "http": lambda: native_tools.http_request("GET", url, engagement_id=eid),
            "graphql": lambda: native_tools.graphql_request(url, "{ x }", engagement_id=eid),
            "openapi_inspect": lambda: native_tools.inspect_openapi(eid, url),
            "openapi_audit": lambda: api_audit.audit_openapi(eid, url),
            "graphql_audit": lambda: api_audit.audit_graphql(eid, url),
            "fuzz": lambda: api_audit.fuzz_api_parameter(
                eid, "https://allowed.test", "/redirect", "GET", "query", "probe", ["x"], 1
            ),
        }

    def test_every_scoped_native_http_path_refuses_before_following_outside_scope(self):
        for name, call in self.calls().items():
            with self.subTest(tool=name):
                adapter = FixtureTransport()
                with patch.dict("os.environ", {"OPENCYBER_ENFORCE_SCOPE": "1"}), patch.object(
                    requests.Session, "get_adapter", return_value=adapter
                ):
                    with self.assertRaises(OcError) as raised:
                        call()
                self.assertEqual(raised.exception.code, "scope_denied")
                self.assertEqual(len(adapter.sent), 1)
                self.assertNotIn("outside.test", adapter.sent[0])

    def test_allowed_redirect_and_relative_redirect_keep_requests_semantics(self):
        for destination in ("https://allowed.test/target", "/target"):
            with self.subTest(destination=destination):
                adapter = FixtureTransport(destination)
                with patch.dict("os.environ", {"OPENCYBER_ENFORCE_SCOPE": "1"}), patch.object(
                    requests.Session, "get_adapter", return_value=adapter
                ):
                    result = native_tools.http_request(
                        "POST", "https://allowed.test/redirect", body="test", engagement_id=self.engagement_id
                    )
                self.assertEqual(result["status"], 200)
                self.assertEqual(adapter.sent, ["https://allowed.test/redirect", "https://allowed.test/target"])

    def test_unfollowed_redirect_does_not_contact_or_require_scope_for_destination(self):
        adapter = FixtureTransport()
        with patch.dict("os.environ", {"OPENCYBER_ENFORCE_SCOPE": "1"}), patch.object(
            requests.Session, "get_adapter", return_value=adapter
        ):
            result = native_tools.http_request(
                "GET", "https://allowed.test/redirect", follow_redirects=False, engagement_id=self.engagement_id
            )
        self.assertEqual(result["status"], 302)
        self.assertEqual(len(adapter.sent), 1)

    def test_enforcement_off_preserves_unscoped_redirects(self):
        adapter = FixtureTransport()
        with patch.dict("os.environ", {"OPENCYBER_ENFORCE_SCOPE": "0"}), patch.object(
            requests.Session, "get_adapter", return_value=adapter
        ):
            result = native_tools.http_request("GET", "https://allowed.test/redirect")
        self.assertFalse(result["scope_enforced"])
        self.assertEqual(adapter.sent[-1], "https://outside.test/target")

    def test_workbench_does_not_forward_credentials_to_a_redirected_origin(self):
        for destination in ("https://outside.test/target", "http://allowed.test/target"):
            with self.subTest(destination=destination):
                adapter = FixtureTransport(destination)
                with patch.dict("os.environ", {"OPENCYBER_ENFORCE_SCOPE": "0"}):
                    session = http_workbench.create_http_session(
                        self.engagement_id, "Redirect credentials", "https://allowed.test/",
                        scope_hosts=["allowed.test", "outside.test"],
                        default_headers={"Authorization": "Bearer private", "X-Trace": "keep"},
                    )
                    http_workbench.update_http_session(
                        self.engagement_id, session["session_id"], cookies={"private-session": "secret"}
                    )
                    with patch.object(requests.Session, "get_adapter", return_value=adapter):
                        result = http_workbench.repeat_http_request(
                            self.engagement_id, session["session_id"], "GET", "/redirect"
                        )
                self.assertEqual(result["response"]["status"], 200)
                self.assertIn("Authorization", adapter.sent_headers[0])
                self.assertIn("Cookie", adapter.sent_headers[0])
                self.assertNotIn("Authorization", adapter.sent_headers[1])
                self.assertNotIn("Cookie", adapter.sent_headers[1])
                self.assertEqual(adapter.sent_headers[1]["X-Trace"], "keep")

    def test_workbench_preserves_credentials_on_same_origin_redirects(self):
        adapter = FixtureTransport("/target")
        with patch.dict("os.environ", {"OPENCYBER_ENFORCE_SCOPE": "0"}):
            session = http_workbench.create_http_session(
                self.engagement_id, "Same origin", "https://allowed.test/",
                default_headers={"Authorization": "Bearer private"},
            )
            with patch.object(requests.Session, "get_adapter", return_value=adapter):
                http_workbench.repeat_http_request(self.engagement_id, session["session_id"], "GET", "/redirect")
        self.assertEqual(adapter.sent_headers[1]["Authorization"], "Bearer private")
