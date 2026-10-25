from __future__ import annotations

import unittest

from opencyber.browser import build_context_options


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


if __name__ == "__main__":
    unittest.main()
