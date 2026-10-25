from __future__ import annotations

import asyncio
import inspect
import unittest
from unittest.mock import patch

from opencyber import envelope
from opencyber.contracts import contract_for
from opencyber.envelope import (
    EVIDENCE_PREFIX,
    ENVELOPE_SCHEMA_VERSION,
    coverage,
    finalize,
    refusal,
    wrap,
)
from opencyber.errors import OcError


CATALOG = contract_for("oc_catalog")
BASH = contract_for("oc_bash")
JWT = contract_for("oc_jwt_decode")


class CoverageTests(unittest.TestCase):
    def test_coverage_has_every_field(self):
        declaration = coverage("complete", examined=3, total=3, exhausted=True)
        self.assertEqual(
            list(declaration),
            ["status", "examined", "total", "exhausted", "next_offset"],
        )
        self.assertEqual(declaration["examined"], 3)

    def test_unknown_status_and_field_fail_closed(self):
        with self.assertRaises(ValueError):
            coverage("finished")
        with self.assertRaises(ValueError):
            coverage("complete", nonsense=1)


class FinalizeTests(unittest.TestCase):
    def test_unavailable_execution_defaults_to_unknown_coverage(self):
        result = finalize(BASH, {"available": False, "error": OcError("integration_unavailable", "missing").to_dict()})
        self.assertFalse(result["ok"])
        self.assertEqual(result["coverage"]["status"], "unknown")

    def test_envelope_is_additive(self):
        result = finalize(CATALOG, {"success": True, "stdout": "hello", "returncode": 0})
        self.assertEqual(result["stdout"], "hello")
        self.assertEqual(result["returncode"], 0)
        self.assertTrue(result["success"])
        for key in ("ok", "contract", "coverage", "limitations", "provenance", "continuation", "evidence"):
            self.assertIn(key, result)

    def test_contract_block_identifies_the_tool(self):
        result = finalize(JWT, {})
        self.assertEqual(result["contract"]["tool"], "oc_jwt_decode")
        self.assertEqual(result["contract"]["schema_version"], ENVELOPE_SCHEMA_VERSION)
        self.assertEqual(result["contract"]["contract_schema_version"], 1)

    def test_ok_defaults_to_true_and_honours_success(self):
        self.assertTrue(finalize(CATALOG, {})["ok"])
        self.assertTrue(finalize(CATALOG, {"success": True})["ok"])
        self.assertFalse(finalize(CATALOG, {"success": False})["ok"])

    def test_an_error_object_forces_ok_false(self):
        error = OcError("not_found", "missing").to_dict()
        result = finalize(CATALOG, {"error": error})
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"]["code"], "not_found")

    def test_poc_style_refusal_payload_keeps_history_and_gains_error(self):
        payload = {
            "status": "refused",
            "reason": "authorization_required",
            "message": "no signed authorization",
            "ok": False,
            "error": OcError("authorization_required", "no signed authorization").to_dict(),
        }
        result = finalize(contract_for("oc_poc_run"), payload)
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "refused")
        self.assertEqual(result["reason"], "authorization_required")
        self.assertEqual(result["error"]["code"], "authorization_required")

    def test_coverage_defaults_complete_and_truncation_makes_it_partial(self):
        self.assertEqual(finalize(CATALOG, {})["coverage"]["status"], "complete")
        self.assertEqual(finalize(BASH, {"truncated": True})["coverage"]["status"], "partial")

    def test_explicit_coverage_is_normalized_with_every_field(self):
        result = finalize(CATALOG, {"coverage": {"status": "partial", "examined": 10, "total": 20}})
        self.assertEqual(result["coverage"]["status"], "partial")
        self.assertEqual(result["coverage"]["examined"], 10)
        self.assertIsNone(result["coverage"]["exhausted"])

    def test_limitations_default_to_empty_and_are_preserved(self):
        self.assertEqual(finalize(CATALOG, {})["limitations"], [])
        self.assertEqual(finalize(CATALOG, {"limitations": ["only first page"]})["limitations"], ["only first page"])

    def test_provenance_is_derived_from_the_contract(self):
        self.assertEqual(finalize(CATALOG, {})["provenance"], {"untrusted_content": False, "source": "server"})
        self.assertEqual(finalize(JWT, {})["provenance"], {"untrusted_content": True, "source": "target"})

    def test_explicit_provenance_is_not_overwritten(self):
        declared = {"untrusted_content": True, "source": "engagement"}
        self.assertEqual(finalize(CATALOG, {"provenance": declared})["provenance"], declared)

    def test_non_dict_results_are_wrapped_rather_than_dropped(self):
        self.assertEqual(finalize(CATALOG, ["a"])["value"], ["a"])


class EvidenceTests(unittest.TestCase):
    def test_digest_is_deterministic_and_prefixed(self):
        first = finalize(CATALOG, {"value": 1})["evidence"]
        second = finalize(CATALOG, {"value": 1})["evidence"]
        self.assertEqual(first, second)
        self.assertTrue(first["id"].startswith(EVIDENCE_PREFIX))
        self.assertEqual(len(first["sha256"]), 64)
        self.assertFalse(first["retained"])

    def test_digest_changes_with_the_payload(self):
        first = finalize(CATALOG, {"value": 1})["evidence"]["id"]
        second = finalize(CATALOG, {"value": 2})["evidence"]["id"]
        self.assertNotEqual(first, second)

    def test_oversized_results_report_a_reason_instead_of_a_digest(self):
        with patch.object(envelope, "MAX_EVIDENCE_BYTES", 64):
            evidence = finalize(CATALOG, {"value": "x" * 4096})["evidence"]
        self.assertIsNone(evidence["id"])
        self.assertFalse(evidence["retained"])
        self.assertEqual(evidence["reason"], "result_too_large")
        self.assertGreater(evidence["bytes"], 64)


class RefusalTests(unittest.TestCase):
    def test_refusal_shape(self):
        payload = refusal(BASH, OcError("scope_denied", "outside scope", details={"host": "10.0.0.9"}))
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"]["code"], "scope_denied")
        self.assertEqual(payload["error"]["category"], "denied")
        self.assertEqual(payload["coverage"]["status"], "unknown")
        self.assertEqual(payload["limitations"], ["The tool did not run."])
        self.assertTrue(payload["provenance"]["untrusted_content"])
        self.assertTrue(payload["evidence"]["id"].startswith(EVIDENCE_PREFIX))

    def test_refusal_can_state_partial_coverage(self):
        payload = refusal(
            BASH,
            OcError("timed_out", "stopped"),
            coverage_declaration=coverage("partial", examined=10),
            limitations=["The scan stopped after the deadline; partial output is included."],
        )
        self.assertEqual(payload["coverage"]["status"], "partial")
        self.assertEqual(len(payload["limitations"]), 1)


class WrapTests(unittest.TestCase):
    def test_sync_handler_stays_sync(self):
        wrapped = wrap(CATALOG, lambda: {"value": 1})
        self.assertFalse(inspect.iscoroutinefunction(wrapped))
        self.assertTrue(wrapped()["ok"])

    def test_async_handler_stays_async(self):
        async def handler():
            return {"value": 1}

        wrapped = wrap(CATALOG, handler)
        self.assertTrue(inspect.iscoroutinefunction(wrapped))
        self.assertTrue(asyncio.run(wrapped())["ok"])

    def test_signature_is_preserved_for_schema_generation(self):
        def handler(engagement_id: str, limit: int = 5) -> dict:
            return {}

        signature = inspect.signature(wrap(CATALOG, handler))
        self.assertEqual(list(signature.parameters), ["engagement_id", "limit"])
        self.assertEqual(signature.parameters["limit"].default, 5)

    def test_oc_error_becomes_a_refusal(self):
        def handler():
            raise OcError("scope_denied", "outside scope")

        payload = wrap(BASH, handler)()
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"]["code"], "scope_denied")

    def test_value_error_becomes_invalid_argument(self):
        def handler():
            raise ValueError("bad input")

        payload = wrap(CATALOG, handler)()
        self.assertEqual(payload["error"]["code"], "invalid_argument")
        self.assertEqual(payload["error"]["category"], "invalid_input")

    def test_unexpected_error_becomes_internal_error(self):
        def handler():
            raise RuntimeError("boom")

        payload = wrap(CATALOG, handler)()
        self.assertFalse(payload["ok"])
        self.assertEqual(payload["error"]["code"], "internal_error")
        self.assertEqual(payload["error"]["details"], {"exception": "RuntimeError"})

    def test_cancellation_is_re_raised_from_an_async_handler(self):
        async def handler():
            raise asyncio.CancelledError()

        with self.assertRaises(asyncio.CancelledError):
            asyncio.run(wrap(CATALOG, handler)())

    def test_cancellation_is_re_raised_from_a_sync_handler(self):
        def handler():
            raise asyncio.CancelledError()

        with self.assertRaises(asyncio.CancelledError):
            wrap(CATALOG, handler)()


if __name__ == "__main__":
    unittest.main()
