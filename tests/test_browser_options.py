from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from opencyber.browser import (
    MAX_NETWORK_EVENTS,
    MAX_TIMEOUT_MS,
    BrowserSession,
    _paginate_events,
    _record_network_event,
    _validate_timeout,
    build_context_options,
)
from opencyber.errors import OcError


class BrowserContextOptionTests(unittest.TestCase):
    def test_tls_verification_is_ignored_by_default(self) -> None:
        options = build_context_options(1280, 720)
        self.assertTrue(options["ignore_https_errors"])

    def test_tls_verification_can_be_required(self) -> None:
        options = build_context_options(1280, 720, ignore_https_errors=False)
        self.assertFalse(options["ignore_https_errors"])

    def test_optional_fields_are_only_set_when_supplied(self) -> None:
        options = build_context_options(800, 600)
        self.assertEqual(options["viewport"], {"width": 800, "height": 600})
        self.assertNotIn("user_agent", options)
        self.assertNotIn("extra_http_headers", options)

        decorated = build_context_options(
            800,
            600,
            user_agent="opencyber-test",
            extra_headers={"x-test": "1"},
            ignore_https_errors=False,
        )
        self.assertEqual(decorated["user_agent"], "opencyber-test")
        self.assertEqual(decorated["extra_http_headers"], {"x-test": "1"})

    def test_deadlines_are_finite_and_validated(self) -> None:
        self.assertEqual(_validate_timeout(1), 1)
        self.assertEqual(_validate_timeout(MAX_TIMEOUT_MS), MAX_TIMEOUT_MS)
        for invalid in (0, -1, MAX_TIMEOUT_MS + 1, True, "later", None):
            with self.subTest(value=invalid), self.assertRaises(OcError) as raised:
                _validate_timeout(invalid)
            self.assertEqual(raised.exception.code, "invalid_argument")

    def test_network_capture_stops_at_the_cap_and_counts_drops(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            session = BrowserSession(
                session_id="browser_test",
                engagement_id="eng_test",
                name="test",
                context=None,
                page=None,
                created_at="2026-01-01T00:00:00Z",
                network_log_path=Path(temporary) / "network.jsonl",
            )
            for index in range(MAX_NETWORK_EVENTS + 3):
                _record_network_event(session, {"index": index})
            self.assertEqual(len(session.network_events), MAX_NETWORK_EVENTS)
            self.assertEqual(session.network_dropped, 3)
            self.assertEqual(
                len(session.network_log_path.read_text().splitlines()), MAX_NETWORK_EVENTS
            )

    def test_network_log_pages_with_a_continuation(self) -> None:
        events = [{"index": index} for index in range(5)]
        page, next_offset = _paginate_events(events, 0, 2)
        self.assertEqual(page, events[:2])
        self.assertEqual(next_offset, 2)
        page, next_offset = _paginate_events(events, 2, 2)
        self.assertEqual(page, events[2:4])
        self.assertEqual(next_offset, 4)
        page, next_offset = _paginate_events(events, 4, 2)
        self.assertEqual(page, events[4:])
        self.assertIsNone(next_offset)
        for offset, limit in ((-1, 2), (0, 0), (0, 1001)):
            with self.subTest(offset=offset, limit=limit), self.assertRaises(OcError):
                _paginate_events(events, offset, limit)


if __name__ == "__main__":
    unittest.main()
