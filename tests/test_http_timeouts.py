from __future__ import annotations

import os
import asyncio
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import socket
import threading
import time
import unittest
from unittest import mock

from opencyber.http_client import (
    DEFAULT_TIMEOUT_SECONDS,
    MAX_TIMEOUT_SECONDS,
    resolve_timeout,
)
from opencyber import native_tools


class SlowHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/headers":
            time.sleep(0.2)
        self.send_response(200)
        self.send_header("Content-Length", "2")
        self.end_headers()
        if self.path == "/body":
            time.sleep(0.2)
        try:
            self.wfile.write(b"ok")
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, *args):
        pass


class LoopbackFailureTests(unittest.TestCase):
    def test_header_and_streamed_body_timeouts_are_typed(self):
        from opencyber.errors import OcError

        with ThreadingHTTPServer(("127.0.0.1", 0), SlowHandler) as server:
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            try:
                with mock.patch.dict(os.environ, {"NO_PROXY": "127.0.0.1"}):
                    for path in ("headers", "body"):
                        with self.subTest(path=path), self.assertRaises(OcError) as raised:
                            native_tools.http_request("GET", f"http://127.0.0.1:{server.server_port}/{path}", timeout=0.03)
                        self.assertEqual(raised.exception.code, "timed_out")
            finally:
                server.shutdown()
                thread.join(timeout=2)

    def test_connection_refusal_is_typed(self):
        from opencyber.errors import OcError

        with socket.socket() as unused:
            unused.bind(("127.0.0.1", 0))
            with mock.patch.dict(os.environ, {"NO_PROXY": "127.0.0.1"}), self.assertRaises(OcError) as raised:
                native_tools.http_request("GET", f"http://127.0.0.1:{unused.getsockname()[1]}/", timeout=0.1)
            self.assertEqual(raised.exception.code, "connection_failed")


class ResolveTimeoutTests(unittest.TestCase):
    def test_default_is_thirty_seconds(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("OPENCYBER_HTTP_TIMEOUT", None)
            self.assertEqual(resolve_timeout(), DEFAULT_TIMEOUT_SECONDS)

    def test_environment_sets_the_default(self) -> None:
        with mock.patch.dict(os.environ, {"OPENCYBER_HTTP_TIMEOUT": "7.5"}):
            self.assertEqual(resolve_timeout(), 7.5)

    def test_caller_value_wins(self) -> None:
        with mock.patch.dict(os.environ, {"OPENCYBER_HTTP_TIMEOUT": "7"}):
            self.assertEqual(resolve_timeout(2), 2.0)

    def test_invalid_values_are_rejected(self) -> None:
        for value in (0, -1, MAX_TIMEOUT_SECONDS + 1, float("nan"), float("inf"), True, "soon"):
            with self.subTest(value=value):
                with self.assertRaises(ValueError):
                    resolve_timeout(value)  # type: ignore[arg-type]

    def test_invalid_environment_is_rejected(self) -> None:
        with mock.patch.dict(os.environ, {"OPENCYBER_HTTP_TIMEOUT": "later"}):
            with self.assertRaises(ValueError):
                resolve_timeout()


class RequestsTimeoutTests(unittest.TestCase):
    def test_live_http_transport_failures_use_advertised_codes(self):
        import requests
        from opencyber.contracts import contract_for
        from opencyber.server import mcp

        for error, expected in (
            (requests.exceptions.ConnectionError("refused"), "connection_failed"),
            (requests.exceptions.ConnectTimeout("slow connect"), "timed_out"),
            (requests.exceptions.ReadTimeout("slow read"), "timed_out"),
        ):
            with self.subTest(error=type(error).__name__), mock.patch("requests.request", side_effect=error):
                result = asyncio.run(mcp.call_tool("oc_http_request", {
                    "method": "GET", "url": "http://127.0.0.1/", "timeout": 0.1,
                })).structured_content
                self.assertEqual(result["error"]["code"], expected)
                self.assertIn(expected, contract_for("oc_http_request").error_codes)

    def test_http_request_passes_the_resolved_timeout(self) -> None:
        response = mock.Mock(status_code=200, url="https://example.test/", headers={}, text="ok")
        with mock.patch("requests.request", return_value=response) as request:
            native_tools.http_request("GET", "https://example.test/", timeout=12)
        self.assertEqual(request.call_args.kwargs["timeout"], 12.0)

    def test_graphql_request_passes_the_resolved_timeout(self) -> None:
        response = mock.Mock(status_code=200, url="https://example.test/graphql", headers={}, text="{}")
        response.json.return_value = {"data": {}}
        with mock.patch("requests.post", return_value=response) as post:
            native_tools.graphql_request("https://example.test/graphql", "{ x }", timeout=9)
        self.assertEqual(post.call_args.kwargs["timeout"], 9.0)

    def test_environment_applies_when_the_caller_is_silent(self) -> None:
        response = mock.Mock(status_code=200, url="https://example.test/", headers={}, text="ok")
        with mock.patch.dict(os.environ, {"OPENCYBER_HTTP_TIMEOUT": "4"}):
            with mock.patch("requests.request", return_value=response) as request:
                native_tools.http_request("GET", "https://example.test/")
        self.assertEqual(request.call_args.kwargs["timeout"], 4.0)


if __name__ == "__main__":
    unittest.main()
