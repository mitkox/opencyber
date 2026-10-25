from __future__ import annotations

import inspect
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from opencyber import audit, envelope, evidence, http_client, poc_schema, triage
from opencyber.limits import LIMITS, LimitSource, describe, facts, limit_for, raise_exceeded, settings
from opencyber.server import mcp


ROOT = Path(__file__).resolve().parents[1]


class LimitRegistryTests(unittest.TestCase):
    def test_ids_are_unique_and_complete(self):
        self.assertEqual(len(LIMITS), len(set(LIMITS)))
        for limit_id, limit in LIMITS.items():
            with self.subTest(limit=limit_id):
                self.assertEqual(limit.id, limit_id)
                self.assertTrue(limit.unit)
                self.assertTrue(limit.description)
                self.assertTrue(limit.recovery)
                self.assertTrue(limit.does_not_raise)
                self.assertIsInstance(limit.source, LimitSource)
                self.assertTrue(limit.applies_to)

    def test_bounds_are_consistent(self):
        for limit_id, limit in LIMITS.items():
            with self.subTest(limit=limit_id):
                if limit.minimum is not None and limit.maximum is not None:
                    self.assertLessEqual(limit.minimum, limit.maximum)
                if limit.minimum is not None:
                    self.assertGreaterEqual(limit.default, limit.minimum)
                if limit.maximum is not None:
                    self.assertLessEqual(limit.default, limit.maximum)

    def test_argument_limits_name_their_parameter(self):
        for limit_id, limit in LIMITS.items():
            with self.subTest(limit=limit_id):
                if limit.source is LimitSource.ARGUMENT:
                    self.assertTrue(limit.parameter, f"{limit_id} must name its parameter")
                if limit.source is LimitSource.ENVIRONMENT:
                    self.assertTrue(limit.env, f"{limit_id} must name its environment variable")

    def test_describe_is_sorted_and_serializable(self):
        rows = describe()
        self.assertEqual([row["id"] for row in rows], sorted(LIMITS))
        for row in rows:
            json.dumps(row)
            self.assertEqual(
                set(row),
                {
                    "id",
                    "unit",
                    "description",
                    "default",
                    "minimum",
                    "maximum",
                    "source",
                    "setting",
                    "applies_to",
                    "recovery",
                    "does_not_raise",
                },
            )

    def test_settings_only_lists_environment_limits(self):
        for variable, limit in settings().items():
            self.assertEqual(variable, limit.env)
            self.assertEqual(limit.source, LimitSource.ENVIRONMENT)

    def test_unknown_limit_fails_closed(self):
        with self.assertRaises(KeyError):
            limit_for("does.not.exist")

    def test_registry_matches_owner_module_constants(self):
        self.assertEqual(LIMITS["triage.max_bytes"].default, triage.DEFAULT_MAX_BYTES)
        self.assertEqual(LIMITS["triage.max_records"].default, triage.DEFAULT_MAX_RECORDS)
        self.assertEqual(LIMITS["audit.max_events"].default, audit.MAX_READ_EVENTS)
        self.assertEqual(LIMITS["evidence.max_files"].default, evidence.MAX_SELECTED_FILES)
        self.assertEqual(LIMITS["evidence.max_manifest_bytes"].default, evidence.MAX_MANIFEST_BYTES)
        self.assertEqual(LIMITS["http.timeout"].default, http_client.DEFAULT_TIMEOUT_SECONDS)
        self.assertEqual(LIMITS["http.timeout"].maximum, http_client.MAX_TIMEOUT_SECONDS)
        self.assertEqual(LIMITS["poc.max_requests"].maximum, poc_schema.HARD_MAX_REQUESTS)
        self.assertEqual(LIMITS["poc.timeout_s"].maximum, poc_schema.HARD_MAX_TIMEOUT_S)
        self.assertEqual(LIMITS["poc.max_bytes"].default, poc_schema.HARD_MAX_BYTES)
        self.assertEqual(LIMITS["envelope.evidence_max_bytes"].default, envelope.MAX_EVIDENCE_BYTES)

    def test_registry_matches_advertised_tool_defaults(self):
        for limit_id, limit in LIMITS.items():
            if not limit.parameter:
                continue
            for tool_name in limit.applies_to:
                with self.subTest(limit=limit_id, tool=tool_name):
                    signature = inspect.signature(mcp._tool_manager._tools[tool_name].fn)
                    self.assertIn(limit.parameter, signature.parameters)
                    self.assertEqual(signature.parameters[limit.parameter].default, limit.default)

    def test_generated_reference_is_current(self):
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "generate-limit-docs.py"), "--check"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class LimitResolutionTests(unittest.TestCase):
    def test_nonfinite_environment_values_fail_closed(self):
        from opencyber.errors import OcError

        for value in ("NaN", "Infinity", "-Infinity"):
            with self.subTest(value=value), patch.dict(os.environ, {"OPENCYBER_TOOL_TIMEOUT_S": value}):
                with self.assertRaises(OcError):
                    LIMITS["tool.timeout_s"].document_effective()

    def test_environment_limit_defaults_when_unset(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop("OPENCYBER_HTTP_TIMEOUT", None)
            self.assertEqual(LIMITS["http.timeout"].document_effective(), 30)

    def test_environment_limit_honors_a_valid_override(self):
        with patch.dict(os.environ, {"OPENCYBER_HTTP_TIMEOUT": "45"}):
            self.assertEqual(LIMITS["http.timeout"].document_effective(), 45)

    def test_invalid_environment_value_fails_closed(self):
        from opencyber.errors import OcError

        with patch.dict(os.environ, {"OPENCYBER_HTTP_TIMEOUT": "soon"}):
            with self.assertRaises(OcError) as raised:
                LIMITS["http.timeout"].document_effective()
        self.assertEqual(raised.exception.code, "invalid_argument")
        self.assertEqual(raised.exception.details["setting"], "OPENCYBER_HTTP_TIMEOUT")

    def test_out_of_bounds_environment_value_fails_closed(self):
        from opencyber.errors import OcError

        with patch.dict(os.environ, {"OPENCYBER_HTTP_TIMEOUT": "9000"}):
            with self.assertRaises(OcError) as raised:
                LIMITS["http.timeout"].document_effective()
        self.assertEqual(raised.exception.code, "invalid_argument")
        self.assertIn("300", raised.exception.message)


class LimitFactTests(unittest.TestCase):
    def test_facts_report_the_enforced_value(self):
        record = facts("workspace.read_max_bytes", 4096, requested=8192, parameter="max_bytes")
        self.assertEqual(record["id"], "workspace.read_max_bytes")
        self.assertEqual(record["unit"], "bytes")
        self.assertEqual(record["effective"], 4096)
        self.assertEqual(record["requested"], 8192)
        self.assertEqual(record["default"], 1048576)
        self.assertEqual(record["maximum"], 67108864)
        self.assertEqual(record["source"], "argument")
        self.assertIsNone(record["setting"])
        self.assertEqual(record["parameter"], "max_bytes")
        self.assertTrue(record["recovery"])
        self.assertTrue(record["does_not_raise"])

    def test_facts_default_to_the_registered_parameter(self):
        record = facts("audit.read_limit", 10)
        self.assertEqual(record["parameter"], "limit")

    def test_facts_use_the_documented_default_when_no_value_is_given(self):
        record = facts("triage.max_bytes")
        self.assertEqual(record["effective"], 16777216)

    def test_whole_numbers_lose_the_float_suffix(self):
        record = facts("serial.read_timeout", 2.0)
        self.assertEqual(record["effective"], 2)
        self.assertIsInstance(record["effective"], int)

    def test_integer_units_stay_integers(self):
        for limit_id in ("triage.max_bytes", "evidence.max_files", "audit.read_limit"):
            self.assertIsInstance(facts(limit_id)["effective"], int)


class LimitRefusalTests(unittest.TestCase):
    def test_raise_exceeded_builds_a_limit_exceeded_refusal(self):
        error = raise_exceeded(
            "triage.max_bytes",
            "file exceeds the inspection ceiling",
            effective=16777216,
            requested=33554432,
            parameter="max_bytes",
            path="evidence/big.bin",
        )
        payload = error.to_dict()
        self.assertEqual(payload["code"], "limit_exceeded")
        self.assertEqual(payload["category"], "resource_constraint")
        self.assertTrue(payload["retryable"])
        self.assertEqual(payload["limit"]["effective"], 16777216)
        self.assertEqual(payload["limit"]["requested"], 33554432)
        self.assertEqual(payload["details"], {"path": "evidence/big.bin"})


if __name__ == "__main__":
    unittest.main()
