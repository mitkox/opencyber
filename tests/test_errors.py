from __future__ import annotations

import asyncio
import json
from pathlib import Path
import subprocess
import sys
import unittest

from opencyber.errors import (
    ERROR_CODES,
    ErrorCategory,
    OcError,
    describe_codes,
    error_schema,
    internal_error,
    limit_exceeded,
    translate,
)


ROOT = Path(__file__).resolve().parents[1]


class ErrorRegistryTests(unittest.TestCase):
    def test_every_code_has_a_complete_spec(self):
        self.assertEqual(len(ERROR_CODES), len(set(ERROR_CODES)))
        for code, spec in ERROR_CODES.items():
            self.assertEqual(code, spec.code)
            self.assertIsInstance(spec.category, ErrorCategory)
            self.assertIsInstance(spec.retryable, bool)
            self.assertTrue(spec.summary.strip(), code)
            self.assertTrue(spec.remediation.strip(), code)

    def test_describe_codes_is_sorted_and_serializable(self):
        rows = describe_codes()
        self.assertEqual([row["code"] for row in rows], sorted(ERROR_CODES))
        for row in rows:
            self.assertEqual(set(row), {"code", "category", "retryable", "summary", "remediation"})
            self.assertIn(row["retryable"], {"yes", "no"})
            json.dumps(row)

    def test_schema_is_derived_from_the_registry(self):
        schema = error_schema()
        self.assertFalse(schema["additionalProperties"])
        self.assertEqual(schema["properties"]["code"]["enum"], sorted(ERROR_CODES))
        self.assertEqual(
            schema["properties"]["category"]["enum"],
            sorted(category.value for category in ErrorCategory),
        )
        self.assertEqual(
            set(schema["required"]),
            {"code", "category", "message", "retryable", "remediation"},
        )

    def test_category_vocabulary_is_stable(self):
        # A rename here changes what clients can branch on. Treat it as a
        # contract change and update docs/ERRORS.md with it.
        self.assertEqual(
            {category.value for category in ErrorCategory},
            {
                "invalid_input",
                "denied",
                "unavailable",
                "not_found",
                "conflict",
                "integrity_mismatch",
                "truncated",
                "timeout",
                "cancelled",
                "resource_constraint",
                "execution_failure",
                "internal",
            },
        )

    def test_generated_reference_is_current(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "generate-error-docs.py"), "--check"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class OcErrorTests(unittest.TestCase):
    def test_error_is_a_value_error_for_historical_callers(self):
        error = OcError("invalid_argument", "bad input")
        self.assertIsInstance(error, ValueError)
        self.assertEqual(str(error), "bad input")

    def test_unregistered_code_fails_closed(self):
        with self.assertRaises(KeyError):
            OcError("not_a_registered_code", "nope")

    def test_empty_message_is_rejected(self):
        with self.assertRaises(ValueError):
            OcError("invalid_argument", "")

    def test_to_dict_is_the_stable_wire_shape(self):
        error = OcError(
            "scope_denied",
            "host outside scope",
            details={"denied": ["10.0.0.9"]},
            remediation="Add the host to the engagement.",
        )
        payload = error.to_dict()
        self.assertEqual(
            list(payload),
            ["code", "category", "message", "retryable", "remediation", "limit", "details"],
        )
        self.assertEqual(payload["code"], "scope_denied")
        self.assertEqual(payload["category"], "denied")
        self.assertFalse(payload["retryable"])
        self.assertEqual(payload["remediation"], {"action": "Add the host to the engagement."})
        self.assertIsNone(payload["limit"])
        self.assertEqual(payload["details"], {"denied": ["10.0.0.9"]})
        json.dumps(payload)

    def test_default_remediation_and_retryability_come_from_the_registry(self):
        error = OcError("timed_out", "nmap exceeded 1800 seconds")
        payload = error.to_dict()
        self.assertTrue(payload["retryable"])
        self.assertIn("deadline", payload["remediation"]["action"])
        overridden = OcError("timed_out", "nmap exceeded 1800 seconds", retryable=False)
        self.assertFalse(overridden.to_dict()["retryable"])

    def test_limit_facts_are_preserved(self):
        facts = {
            "id": "tool.max_output_bytes",
            "unit": "bytes",
            "effective": 4194304,
            "source": "environment",
        }
        error = limit_exceeded(facts, "output exceeded the capture ceiling", executable="nmap")
        payload = error.to_dict()
        self.assertEqual(payload["code"], "limit_exceeded")
        self.assertEqual(payload["category"], "resource_constraint")
        self.assertEqual(payload["limit"], facts)
        self.assertEqual(payload["details"], {"executable": "nmap"})

    def test_details_are_copied_not_aliased(self):
        details = {"denied": ["a"]}
        error = OcError("scope_denied", "denied", details=details)
        details["denied"].append("b")
        self.assertEqual(error.to_dict()["details"], {"denied": ["a"]})


class TranslateTests(unittest.TestCase):
    def test_registered_errors_pass_through_unchanged(self):
        original = OcError("not_found", "missing record")
        self.assertIs(translate(original), original)

    def test_value_and_type_errors_become_invalid_argument(self):
        for exception in (ValueError("bad value"), TypeError("bad type"), KeyError("missing key")):
            with self.subTest(exception=type(exception).__name__):
                translated = translate(exception)
                self.assertEqual(translated.code, "invalid_argument")
                self.assertIn("exception", translated.details)

    def test_os_and_runtime_errors_map_to_specific_codes(self):
        cases = (
            (FileNotFoundError("gone"), "not_found"),
            (FileExistsError("exists"), "already_exists"),
            (PermissionError("denied"), "permission_denied"),
            (ConnectionError("refused"), "connection_failed"),
            (TimeoutError("too slow"), "timed_out"),
            (OSError("disk"), "execution_failed"),
        )
        for exception, expected in cases:
            with self.subTest(exception=exception.__class__.__name__):
                self.assertEqual(translate(exception).code, expected)

    def test_unexpected_errors_become_internal_error(self):
        translated = translate(RuntimeError("boom"))
        self.assertEqual(translated.code, "internal_error")
        self.assertEqual(translated.category, ErrorCategory.INTERNAL)
        self.assertEqual(translated.details, {"exception": "RuntimeError"})
        self.assertFalse(translated.retryable)

    def test_cancellation_is_re_raised_not_translated(self):
        with self.assertRaises(asyncio.CancelledError):
            translate(asyncio.CancelledError())

    def test_internal_error_keeps_the_exception_type_only_in_details(self):
        error = internal_error(RuntimeError("boom"))
        self.assertIn("RuntimeError", error.message)
        self.assertEqual(error.details, {"exception": "RuntimeError"})


if __name__ == "__main__":
    unittest.main()
