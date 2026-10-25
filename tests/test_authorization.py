from __future__ import annotations

from datetime import timedelta
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from opencyber import authorization, engagements
from opencyber.authorization import (
    AUTHORIZATION_SIGNED_FIELDS,
    authorization_path,
    authorization_signed_payload,
    archive_previous,
    describe_authorization,
    is_public_target,
    load_authorization,
    read_authorization,
    validate_for_run,
    write_authorization,
)
from opencyber.poc_schema import (
    PocError,
    iso_utc,
    resolve_approval_key,
    sign_payload,
    utc_now,
)


APPROVAL_KEY_ENV = "OPENCYBER_APPROVAL_KEY"
TEST_KEY_TEXT = "opencyber-unit-test-approval-key-0123456789abcdef"


class AuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        workspace_patch = patch.object(engagements, "WORKSPACE", self.root)
        workspace_patch.start()
        self.addCleanup(workspace_patch.stop)
        environment_patch = patch.dict(
            os.environ,
            {
                APPROVAL_KEY_ENV: TEST_KEY_TEXT,
                "OPENCYBER_APPROVAL_KEY_FILE": "",
            },
        )
        environment_patch.start()
        self.addCleanup(environment_patch.stop)
        self.engagement = engagements.create_engagement(
            "Signed engagement",
            ["10.0.0.0/24", "app.example.test", "*.partner.test"],
        )
        self.engagement_id = self.engagement["engagement_id"]
        self.key, self.key_id = resolve_approval_key()

    # -- helpers ------------------------------------------------------------

    def _record(self, **overrides):
        now = utc_now()
        record = {
            "schema_version": 1,
            "engagement_id": self.engagement_id,
            "authorized_by": "Jane Operator",
            "reference": "AUTH-2026-001",
            "scope_targets": ["10.0.0.0/24", "app.example.test"],
            "valid_from": iso_utc(now - timedelta(hours=1)),
            "valid_until": iso_utc(now + timedelta(hours=2)),
            "allowed_techniques": ["version_assert", "tcp_probe"],
            "custom_code_allowed": False,
            "prohibited_effects": ["persistence", "data_destruction"],
            "acknowledgement": "I am authorized in writing by the asset owner.",
            "created_at": iso_utc(now),
        }
        record.update(overrides)
        return record

    def _write(self, record=None, **overrides):
        return write_authorization(
            self.engagement_id,
            self._record(**overrides) if record is None else record,
            self.key,
            self.key_id,
        )

    def _assert_reason(self, reason, function, *args, **kwargs):
        with self.assertRaises(PocError) as caught:
            function(*args, **kwargs)
        self.assertEqual(caught.exception.reason, reason, caught.exception.message)
        return caught.exception

    def _patched_now(self, value):
        return patch.object(authorization, "utc_now", lambda: value)

    def _read_raw(self):
        return json.loads(authorization_path(self.engagement_id).read_text(encoding="utf-8"))

    def _write_raw(self, record):
        authorization_path(self.engagement_id).write_text(
            json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    # -- record lifecycle ---------------------------------------------------

    def test_write_and_load_roundtrip(self):
        stored = self._write()
        self.assertEqual(stored["engagement_id"], self.engagement_id)
        self.assertEqual(stored["scope_targets"], ["10.0.0.0/24", "app.example.test"])
        self.assertEqual(stored["allowed_techniques"], ["tcp_probe", "version_assert"])
        self.assertIn("hmac_sha256", stored)
        self.assertEqual(len(stored["hmac_sha256"]), 64)

        loaded = load_authorization(self.engagement_id)
        self.assertEqual(loaded, stored)
        self.assertEqual(
            stored["hmac_sha256"],
            sign_payload(self.key, authorization_signed_payload(stored)),
        )

        path = authorization_path(self.engagement_id)
        self.assertEqual(path.name, "authorization.json")
        self.assertEqual(path.parent.name, "poc")
        self.assertEqual(
            path.parent.resolve(), self.root / "engagements" / self.engagement_id / "poc"
        )

    def test_signed_payload_is_the_exact_field_set(self):
        stored = self._write()
        payload = authorization_signed_payload(stored)
        self.assertEqual(
            set(payload),
            set(AUTHORIZATION_SIGNED_FIELDS) - {"reference_sha256"},
        )
        self.assertNotIn("hmac_sha256", payload)

        without_reference = {
            key: value
            for key, value in stored.items()
            if key != "reference_sha256"
        }
        self.assertNotIn(
            "reference_sha256", authorization_signed_payload(without_reference)
        )

        with_reference = dict(stored, reference_sha256="d" * 64)
        self.assertEqual(
            set(authorization_signed_payload(with_reference)),
            set(AUTHORIZATION_SIGNED_FIELDS),
        )
        self.assertEqual(
            authorization_signed_payload(with_reference)["reference_sha256"], "d" * 64
        )

    def test_reference_sha256_is_optional_and_signed(self):
        self._write(reference_sha256="e" * 64)
        self.assertEqual(load_authorization(self.engagement_id)["reference_sha256"], "e" * 64)

        tampered = self._read_raw()
        tampered["reference_sha256"] = "f" * 64
        self._write_raw(tampered)
        self._assert_reason(
            "authorization_invalid", load_authorization, self.engagement_id
        )

        self._assert_reason(
            "authorization_invalid", self._write, reference_sha256="not-a-digest"
        )

    def test_absent_record_never_raises_when_describing(self):
        self.assertIsNone(read_authorization(self.engagement_id))
        description = describe_authorization(self.engagement_id)
        self.assertEqual(description["status"], "required")
        self.assertFalse(description["valid"])
        self.assertIsNone(description["authorization"])
        self.assertEqual(description["remaining_seconds"], 0)
        self.assertEqual(description["reason"], "authorization_required")
        self.assertTrue(description["key_available"])
        self._assert_reason(
            "authorization_required", load_authorization, self.engagement_id
        )

    def test_tampering_with_the_record_breaks_verification(self):
        stored = self._write()
        tampered = self._read_raw()
        tampered["scope_targets"] = ["10.0.0.0/8"]
        self._write_raw(tampered)
        description = describe_authorization(self.engagement_id)
        self.assertEqual(description["status"], "invalid")
        self.assertFalse(description["valid"])
        self.assertEqual(description["reason"], "authorization_invalid")
        self.assertEqual(description["authorization"]["scope_targets"], ["10.0.0.0/8"])
        self._assert_reason(
            "authorization_invalid", load_authorization, self.engagement_id
        )

        self._write_raw(dict(stored, hmac_sha256="0" * 64))
        self._assert_reason(
            "authorization_invalid", load_authorization, self.engagement_id
        )

    def test_unknown_or_extra_fields_are_refused(self):
        stored = self._write()
        self._write_raw(dict(stored, extra_privilege=True))
        self._assert_reason(
            "authorization_invalid", load_authorization, self.engagement_id
        )
        self._assert_reason(
            "authorization_invalid", self._write, unexpected_field=1
        )

    def test_schema_version_is_enforced(self):
        self._assert_reason(
            "authorization_invalid", self._write, schema_version=2
        )
        stored = self._write()
        self._write_raw(dict(stored, schema_version=2))
        self._assert_reason(
            "authorization_invalid", load_authorization, self.engagement_id
        )

    def test_expired_authorization_is_refused_and_described(self):
        self._write()
        valid_until = authorization.parse_utc(
            self._read_raw()["valid_until"], "valid_until"
        )
        with self._patched_now(valid_until + timedelta(seconds=1)):
            error = self._assert_reason(
                "authorization_expired", load_authorization, self.engagement_id
            )
            self.assertEqual(error.details["valid_until"], self._read_raw()["valid_until"])
            description = describe_authorization(self.engagement_id)
        self.assertEqual(description["status"], "expired")
        self.assertFalse(description["valid"])
        self.assertEqual(description["remaining_seconds"], 0)
        self.assertIsNotNone(description["authorization"])

    def test_not_yet_valid_authorization_is_refused(self):
        now = utc_now()
        self._write(
            valid_from=iso_utc(now + timedelta(hours=1)),
            valid_until=iso_utc(now + timedelta(hours=2)),
        )
        self._assert_reason(
            "authorization_not_yet_valid", load_authorization, self.engagement_id
        )
        description = describe_authorization(self.engagement_id)
        self.assertEqual(description["status"], "not_yet_valid")
        self.assertFalse(description["valid"])

    def test_valid_window_bounds(self):
        now = utc_now()
        self._assert_reason(
            "authorization_invalid",
            self._write,
            valid_until=iso_utc(now - timedelta(minutes=1)),
        )
        self._assert_reason(
            "authorization_invalid",
            self._write,
            valid_until=iso_utc(now + timedelta(days=400)),
        )
        self._assert_reason(
            "authorization_invalid",
            self._write,
            valid_from=iso_utc(now + timedelta(hours=3)),
            valid_until=iso_utc(now + timedelta(hours=2)),
        )
        self._assert_reason(
            "authorization_invalid", self._write, valid_until="not-a-timestamp"
        )

    def test_missing_key_makes_records_unverified(self):
        stored = self._write()
        with patch.dict(
            os.environ,
            {APPROVAL_KEY_ENV: "", "OPENCYBER_APPROVAL_KEY_FILE": ""},
        ):
            description = describe_authorization(self.engagement_id)
            self.assertFalse(description["key_available"])
            self.assertEqual(description["status"], "unverified")
            self.assertEqual(description["reason"], "approval_key_unavailable")
            self.assertFalse(description["valid"])
            self.assertEqual(description["authorization"], stored)
            self._assert_reason(
                "approval_key_unavailable", load_authorization, self.engagement_id
            )
            self._assert_reason(
                "approval_key_unavailable",
                validate_for_run,
                self.engagement_id,
                ["10.0.0.7"],
                "version_assert",
                False,
            )

    def test_unknown_engagement_is_reported_cleanly(self):
        missing = "eng_20260101_" + "0" * 32
        self._assert_reason("unknown_engagement", load_authorization, missing)
        self._assert_reason("unknown_engagement", load_authorization, "not-an-id")
        description = describe_authorization(missing)
        self.assertEqual(description["status"], "invalid")
        self.assertFalse(description["valid"])
        self.assertEqual(description["reason"], "unknown_engagement")

    # -- scope enforcement --------------------------------------------------

    def test_scope_targets_must_be_a_subset_of_engagement_targets(self):
        self._assert_reason(
            "scope_violation", self._write, scope_targets=["10.0.0.0/8"]
        )
        self._assert_reason(
            "scope_violation", self._write, scope_targets=["evil.test"]
        )
        self._assert_reason("authorization_invalid", self._write, scope_targets=[])
        # A narrower CIDR, a host inside the engagement CIDR, and a subdomain
        # of an engagement domain are all acceptable subsets.
        for scope in (["10.0.0.128/25"], ["10.0.0.42"], ["api.app.example.test"]):
            stored = self._write(scope_targets=scope)
            self.assertEqual(load_authorization(self.engagement_id), stored)
        wildcard = self._write(scope_targets=["*.partner.test"])
        self.assertEqual(load_authorization(self.engagement_id), wildcard)

    def test_scope_targets_are_deduplicated(self):
        stored = self._write(
            scope_targets=["10.0.0.0/24", "10.0.0.0/24", " app.example.test "]
        )
        self.assertEqual(stored["scope_targets"], ["10.0.0.0/24", "app.example.test"])

    def test_technique_subset_and_custom_flag_are_enforced(self):
        self._assert_reason(
            "authorization_invalid",
            self._write,
            allowed_techniques=["version_assert", "not_a_real_technique"],
        )
        self._assert_reason(
            "authorization_invalid",
            self._write,
            allowed_techniques=["custom"],
            custom_code_allowed=False,
        )
        stored = self._write(
            allowed_techniques=["version_assert", "custom"], custom_code_allowed=True
        )
        self.assertEqual(stored["allowed_techniques"], ["custom", "version_assert"])
        self.assertTrue(stored["custom_code_allowed"])

    def test_public_target_detection(self):
        self.assertTrue(is_public_target("example.com"))
        self.assertTrue(is_public_target("https://example.com/path"))
        self.assertTrue(is_public_target("8.8.8.8"))
        self.assertTrue(is_public_target("203.0.113.10"))
        self.assertFalse(is_public_target("10.1.2.3"))
        self.assertFalse(is_public_target("172.16.0.9"))
        self.assertFalse(is_public_target("192.168.1.5"))
        self.assertFalse(is_public_target("127.0.0.1"))
        self.assertFalse(is_public_target("http://127.0.0.1:8080/"))
        self.assertFalse(is_public_target("localhost"))
        self.assertFalse(is_public_target("db.internal.local"))
        self.assertFalse(is_public_target("app.partner.test"))
        self.assertFalse(is_public_target("10.0.0.0/24"))
        self.assertTrue(is_public_target("203.0.113.0/24"))

    # -- run validation -----------------------------------------------------

    def test_validate_for_run_accepts_covered_targets_and_techniques(self):
        stored = self._write()
        for target in ("10.0.0.7", "http://10.0.0.7:8080/", "app.example.test",
                       "api.app.example.test"):
            self.assertEqual(
                validate_for_run(self.engagement_id, [target], "version_assert", False),
                stored,
            )

    def test_validate_for_run_refuses_out_of_scope_targets(self):
        self._write()
        for target in ("192.168.1.5", "http://evil.test/", "10.1.0.5"):
            self._assert_reason(
                "scope_violation",
                validate_for_run,
                self.engagement_id,
                [target],
                "version_assert",
                False,
            )
        self._assert_reason(
            "scope_violation",
            validate_for_run,
            self.engagement_id,
            [],
            "version_assert",
            False,
        )

    def test_validate_for_run_refuses_unauthorized_techniques_and_custom_code(self):
        self._write(allowed_techniques=["version_assert"], custom_code_allowed=False)
        self._assert_reason(
            "technique_not_authorized",
            validate_for_run,
            self.engagement_id,
            ["10.0.0.7"],
            "tcp_probe",
            False,
        )
        self._assert_reason(
            "technique_not_authorized",
            validate_for_run,
            self.engagement_id,
            ["10.0.0.7"],
            "nonsense",
            False,
        )
        self._assert_reason(
            "technique_not_authorized",
            validate_for_run,
            self.engagement_id,
            ["10.0.0.7"],
            "version_assert",
            True,
        )
        self._assert_reason(
            "technique_not_authorized",
            validate_for_run,
            self.engagement_id,
            ["10.0.0.7"],
            "custom",
            False,
        )

    def test_validate_for_run_requires_a_live_authorization(self):
        self._assert_reason(
            "authorization_required",
            validate_for_run,
            self.engagement_id,
            ["10.0.0.7"],
            "version_assert",
            False,
        )
        self._write()
        valid_until = authorization.parse_utc(
            self._read_raw()["valid_until"], "valid_until"
        )
        with self._patched_now(valid_until + timedelta(seconds=1)):
            self._assert_reason(
                "authorization_expired",
                validate_for_run,
                self.engagement_id,
                ["10.0.0.7"],
                "version_assert",
                False,
            )

    # -- persistence and superseding ---------------------------------------

    def test_superseding_archives_the_previous_record(self):
        first = self._write()
        first_path = authorization_path(self.engagement_id)
        first_bytes = first_path.read_bytes()
        first_digest = hashlib.sha256(first_bytes).hexdigest()

        second = self._write(reference="AUTH-2026-002")
        history = first_path.parent / "authorization-history"
        self.assertEqual(
            sorted(path.name for path in history.iterdir()),
            [f"{first_digest}.json"],
        )
        self.assertEqual((history / f"{first_digest}.json").read_bytes(), first_bytes)
        loaded = load_authorization(self.engagement_id)
        self.assertEqual(loaded["reference"], "AUTH-2026-002")
        self.assertNotEqual(first["hmac_sha256"], second["hmac_sha256"])

    def test_archive_previous_is_a_no_op_without_a_record(self):
        self.assertIsNone(archive_previous(self.engagement_id))
        self.assertFalse(authorization_path(self.engagement_id).exists())

    def test_writes_are_atomic_and_leave_no_temporary_files(self):
        self._write()
        self._write(reference="AUTH-2026-003")
        poc_directory = authorization_path(self.engagement_id).parent
        self.assertEqual(list(poc_directory.glob(".*.tmp")), [])
        self.assertEqual(
            [
                item.name
                for item in poc_directory.iterdir()
                if item.is_file()
            ],
            ["authorization.json"],
        )
        # The record on disk is complete JSON, never a partial write.
        self.assertIsInstance(self._read_raw(), dict)

    def test_symlinked_authorization_is_refused(self):
        stored = self._write()
        path = authorization_path(self.engagement_id)
        path.unlink()
        outside = self.root / "outside-authorization.json"
        outside.write_text(json.dumps(stored), encoding="utf-8")
        path.symlink_to(outside)
        with self.assertRaises(PocError):
            load_authorization(self.engagement_id)

    def test_written_record_can_be_read_back_byte_for_byte(self):
        stored = self._write()
        raw = self._read_raw()
        self.assertEqual(raw, stored)
        self.assertEqual(
            authorization_signed_payload(raw), authorization_signed_payload(stored)
        )


if __name__ == "__main__":
    unittest.main()
