from __future__ import annotations

import os
import unittest
from unittest import mock

from opencyber.http_client import (
    DEFAULT_TIMEOUT_SECONDS,
    MAX_TIMEOUT_SECONDS,
    resolve_timeout,
)
from opencyber import native_tools


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
