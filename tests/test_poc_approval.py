from __future__ import annotations

import asyncio
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from datetime import timedelta
import hashlib
import importlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import types
import unittest
from unittest.mock import patch
import uuid

from opencyber import audit, engagements, poc_approval
from opencyber.authorization import load_authorization
from opencyber.poc_approval import (
    approval_path,
    approval_signed_payload,
    approval_status,
    consume_approval,
    create_approval,
    load_approval,
    main,
    revoke_approval,
    verify_approval,
)
from opencyber.poc_schema import (
    PocError,
    iso_utc,
    new_record_id,
    poc_path,
    resolve_approval_key,
    sha256_hex,
    sign_payload,
    utc_now,
)


APPROVAL_KEY_ENV = "OPENCYBER_APPROVAL_KEY"
TEST_KEY_TEXT = "opencyber-unit-test-approval-key-0123456789abcdef"
SPEC_SHA256 = "a" * 64
CODE_SHA256 = "b" * 64


@contextmanager
def fake_module(name, **attributes):
    """Temporarily inject ``opencyber.<name>`` for the lazily-imported engine."""
    module = types.ModuleType(f"opencyber.{name}")
    for attribute, value in attributes.items():
        setattr(module, attribute, value)
    package = importlib.import_module("opencyber")
    missing = object()
    previous_module = sys.modules.get(f"opencyber.{name}", missing)
    previous_attribute = getattr(package, name, missing)
    sys.modules[f"opencyber.{name}"] = module
    setattr(package, name, module)
    try:
        yield module
    finally:
        if previous_module is missing:
            sys.modules.pop(f"opencyber.{name}", None)
        else:
            sys.modules[f"opencyber.{name}"] = previous_module
        if previous_attribute is missing:
            try:
                delattr(package, name)
            except AttributeError:
                pass
        else:
            setattr(package, name, previous_attribute)


@contextmanager
def missing_module(name):
    """Simulate a teammate module that is not installed (yet)."""
    package = importlib.import_module("opencyber")
    missing = object()
    previous_module = sys.modules.get(f"opencyber.{name}", missing)
    previous_attribute = getattr(package, name, missing)
    sys.modules[f"opencyber.{name}"] = None
    if previous_attribute is not missing:
        try:
            delattr(package, name)
        except AttributeError:
            pass
    try:
        yield
    finally:
        if previous_module is missing:
            sys.modules.pop(f"opencyber.{name}", None)
        else:
            sys.modules[f"opencyber.{name}"] = previous_module
        if previous_attribute is not missing:
            setattr(package, name, previous_attribute)


class _WorkspaceTestCase(unittest.TestCase):
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
            "Approval engagement", ["10.0.0.0/24", "app.example.test"]
        )
        self.engagement_id = self.engagement["engagement_id"]
        self.key, self.key_id = resolve_approval_key()
        self.chain_id = new_record_id("chain")
        self.spec_id = new_record_id("spec")

    # -- helpers ------------------------------------------------------------

    def _create(self, **overrides):
        arguments = {
            "chain_id": self.chain_id,
            "spec_id": self.spec_id,
            "spec_sha256": SPEC_SHA256,
            "code_sha256": CODE_SHA256,
            "technique": "version_assert",
            "targets": ["10.0.0.7"],
            "custom_code": False,
            "issued_by": "Jane Operator",
            "ttl_hours": 8.0,
            "key": self.key,
            "key_id": self.key_id,
        }
        arguments.update(overrides)
        return create_approval(self.engagement_id, **arguments)

    def _verify(self, approval_id, **overrides):
        arguments = {
            "chain_id": self.chain_id,
            "spec_id": self.spec_id,
            "spec_sha256": SPEC_SHA256,
            "code_sha256": CODE_SHA256,
            "technique": "version_assert",
            "targets": ["10.0.0.7"],
            "custom_code": False,
        }
        arguments.update(overrides)
        return verify_approval(self.engagement_id, approval_id, **arguments)

    def _assert_reason(self, reason, function, *args, **kwargs):
        with self.assertRaises(PocError) as caught:
            function(*args, **kwargs)
        self.assertEqual(caught.exception.reason, reason, caught.exception.message)
        return caught.exception

    def _patched_now(self, value):
        return patch.object(poc_approval, "utc_now", lambda: value)

    def _run_cli(self, argv):
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            code = main(argv)
        return code, stdout.getvalue(), stderr.getvalue()

    def _store_signed(self, **overrides):
        now = utc_now()
        record = {
            "schema_version": 1,
            "approval_id": new_record_id("apr"),
            "nonce": uuid.uuid4().hex,
            "engagement_id": self.engagement_id,
            "chain_id": self.chain_id,
            "spec_id": self.spec_id,
            "spec_sha256": SPEC_SHA256,
            "code_sha256": CODE_SHA256,
            "technique": "version_assert",
            "targets": ["10.0.0.7"],
            "custom_code": False,
            "issued_by": "Jane Operator",
            "issued_at": iso_utc(now),
            "expires_at": iso_utc(now + timedelta(hours=1)),
            "ttl_hours": 1.0,
            "key_id": self.key_id,
            "used_at": None,
            "revoked": False,
            "revoked_at": None,
            "revoked_reason": None,
        }
        record.update(overrides)
        record["hmac_sha256"] = sign_payload(
            self.key, approval_signed_payload(record)
        )
        path = poc_path(
            self.engagement_id, "approvals", f"{record['approval_id']}.json"
        )
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        return record

    def _approvals_directory(self):
        return poc_path(self.engagement_id, "approvals")

    def _authorize_argv(self, **overrides):
        now = utc_now()
        values = {
            "engagement": self.engagement_id,
            "authorized-by": "Jane Operator",
            "reference": "AUTH-2026-001",
            "scope": ["10.0.0.0/24"],
            "valid-from": iso_utc(now - timedelta(hours=1)),
            "valid-until": iso_utc(now + timedelta(hours=2)),
            "techniques": "version_assert,tcp_probe",
            "acknowledgement": "I am authorized in writing by the asset owner.",
        }
        values.update(overrides)
        argv = ["authorize"]
        for flag, value in values.items():
            if value is None:
                continue
            if isinstance(value, list):
                for item in value:
                    argv.extend([f"--{flag}", item])
            else:
                argv.extend([f"--{flag}", value])
        return argv

    def _approve_argv(self, extra=None):
        argv = [
            "approve",
            "--engagement",
            self.engagement_id,
            "--chain",
            self.chain_id,
            "--spec",
            self.spec_id,
            "--issued-by",
            "Jane Operator",
            "--expires",
            iso_utc(utc_now() + timedelta(hours=2)),
        ]
        return argv + list(extra or [])


class ApprovalRecordTests(_WorkspaceTestCase):
    def test_create_and_load_roundtrip(self):
        approval = self._create()
        self.assertRegex(
            approval["approval_id"], r"^apr_\d{8}_[0-9a-f]{32}$"
        )
        self.assertRegex(approval["nonce"], r"^[0-9a-f]{32}$")
        second = self._create()
        self.assertNotEqual(approval["nonce"], second["nonce"])
        self.assertNotEqual(approval["approval_id"], second["approval_id"])
        self.assertEqual(approval["engagement_id"], self.engagement_id)
        self.assertEqual(approval["chain_id"], self.chain_id)
        self.assertEqual(approval["spec_id"], self.spec_id)
        self.assertEqual(approval["spec_sha256"], SPEC_SHA256)
        self.assertEqual(approval["code_sha256"], CODE_SHA256)
        self.assertFalse(approval["custom_code"])
        self.assertFalse(approval["revoked"])
        self.assertIsNone(approval["used_at"])
        self.assertEqual(
            approval["hmac_sha256"],
            sign_payload(self.key, approval_signed_payload(approval)),
        )
        self.assertEqual(load_approval(self.engagement_id, approval["approval_id"]), approval)

        path = approval_path(self.engagement_id, approval["approval_id"])
        self.assertEqual(path.name, f"{approval['approval_id']}.json")
        self.assertEqual(path.parent.name, "approvals")
        self.assertTrue(path.is_file())

    def test_signed_payload_excludes_used_at_and_hmac(self):
        approval = self._create()
        payload = approval_signed_payload(approval)
        self.assertEqual(
            set(payload), set(poc_approval.APPROVAL_SIGNED_FIELDS)
        )
        self.assertNotIn("hmac_sha256", payload)
        self.assertNotIn("used_at", payload)

    def test_invalid_or_unknown_approval_ids(self):
        self._assert_reason(
            "approval_invalid", load_approval, self.engagement_id, "not-an-id"
        )
        self._assert_reason(
            "approval_invalid",
            load_approval,
            self.engagement_id,
            "apr_20260101_" + "0" * 32,
        )
        self._assert_reason(
            "approval_invalid", consume_approval, self.engagement_id, "not-an-id"
        )

    def test_tampered_record_is_refused(self):
        approval = self._create()
        path = approval_path(self.engagement_id, approval["approval_id"])
        tampered = json.loads(path.read_text(encoding="utf-8"))
        tampered["targets"] = ["10.0.0.0/8"]
        path.write_text(json.dumps(tampered), encoding="utf-8")
        self._assert_reason(
            "approval_invalid",
            load_approval,
            self.engagement_id,
            approval["approval_id"],
        )
        self._assert_reason(
            "approval_invalid", self._verify, approval["approval_id"]
        )
        status = approval_status(self.engagement_id, approval["approval_id"])
        self.assertEqual(status["status"], "invalid")
        self.assertEqual(status["reason"], "approval_invalid")

    def test_unknown_fields_are_rejected(self):
        forged = self._store_signed(extra_privilege=True)
        self._assert_reason(
            "approval_invalid", load_approval, self.engagement_id, forged["approval_id"]
        )
        bad_nonce = self._store_signed(nonce="not-a-nonce")
        self._assert_reason(
            "approval_invalid",
            load_approval,
            self.engagement_id,
            bad_nonce["approval_id"],
        )

    def test_approval_lifetime_ceiling(self):
        self._assert_reason("approval_invalid", self._create, ttl_hours=25.0)
        self._assert_reason("approval_invalid", self._create, ttl_hours=0)
        self._assert_reason("approval_invalid", self._create, ttl_hours=-1)

        now = utc_now()
        forged = self._store_signed(
            issued_at=iso_utc(now),
            expires_at=iso_utc(now + timedelta(hours=30)),
            ttl_hours=30.0,
        )
        self._assert_reason(
            "approval_invalid", load_approval, self.engagement_id, forged["approval_id"]
        )
        mismatched = self._store_signed(
            issued_at=iso_utc(now),
            expires_at=iso_utc(now + timedelta(hours=1)),
            ttl_hours=2.0,
        )
        self._assert_reason(
            "approval_invalid",
            load_approval,
            self.engagement_id,
            mismatched["approval_id"],
        )
        inconsistent = self._store_signed(
            revoked=False, revoked_at=iso_utc(now), revoked_reason="should not exist"
        )
        self._assert_reason(
            "approval_invalid",
            load_approval,
            self.engagement_id,
            inconsistent["approval_id"],
        )

    # -- verification ------------------------------------------------------

    def test_verify_happy_path(self):
        approval = self._create()
        self.assertEqual(self._verify(approval["approval_id"]), approval)

    def test_verify_binds_to_spec_and_code_hashes(self):
        approval = self._create()
        self._assert_reason(
            "artifact_hash_mismatch",
            self._verify,
            approval["approval_id"],
            spec_sha256="c" * 64,
        )
        self._assert_reason(
            "artifact_hash_mismatch",
            self._verify,
            approval["approval_id"],
            code_sha256="d" * 64,
        )
        self._assert_reason(
            "approval_invalid",
            self._verify,
            approval["approval_id"],
            spec_sha256="not-a-hash",
        )

    def test_verify_binds_to_chain_spec_and_technique(self):
        approval = self._create()
        self._assert_reason(
            "approval_invalid",
            self._verify,
            approval["approval_id"],
            chain_id=new_record_id("chain"),
        )
        self._assert_reason(
            "approval_invalid",
            self._verify,
            approval["approval_id"],
            spec_id=new_record_id("spec"),
        )
        self._assert_reason(
            "technique_not_authorized",
            self._verify,
            approval["approval_id"],
            technique="tcp_probe",
        )

    def test_verify_target_subset(self):
        approval = self._create(targets=["10.0.0.0/24"])
        self.assertTrue(
            self._verify(approval["approval_id"], targets=["10.0.0.7"])
        )
        self._assert_reason(
            "scope_violation",
            self._verify,
            approval["approval_id"],
            targets=["192.168.1.5"],
        )
        self._assert_reason(
            "approval_invalid",
            self._verify,
            approval["approval_id"],
            targets=[],
        )
        domain_approval = self._create(targets=["app.example.test"])
        self.assertTrue(
            self._verify(
                domain_approval["approval_id"], targets=["api.app.example.test"]
            )
        )

    def test_verify_custom_code_flag(self):
        approval = self._create()
        self._assert_reason(
            "technique_not_authorized",
            self._verify,
            approval["approval_id"],
            custom_code=True,
        )
        custom = self._create(
            technique="custom", custom_code=True, code_sha256="e" * 64
        )
        self.assertEqual(
            self._verify(
                custom["approval_id"],
                technique="custom",
                custom_code=True,
                code_sha256="e" * 64,
            )["approval_id"],
            custom["approval_id"],
        )
        # Creating a custom approval without the custom flag is refused.
        self._assert_reason(
            "approval_invalid",
            self._create,
            technique="custom",
            custom_code=False,
        )

    def test_expired_approval_is_refused(self):
        approval = self._create(ttl_hours=1.0)
        issued_at = poc_approval.parse_utc(approval["issued_at"], "issued_at")
        with self._patched_now(issued_at + timedelta(minutes=90)):
            error = self._assert_reason(
                "approval_invalid", self._verify, approval["approval_id"]
            )
            self.assertIn("expired", error.message)
            status = approval_status(self.engagement_id, approval["approval_id"])
        self.assertEqual(status["status"], "expired")
        self.assertFalse(status["valid"])

    def test_approval_is_single_use(self):
        approval = self._create()
        before = approval_signed_payload(
            load_approval(self.engagement_id, approval["approval_id"])
        )
        consumed = consume_approval(self.engagement_id, approval["approval_id"])
        self.assertIsNotNone(consumed["used_at"])
        self.assertEqual(approval_signed_payload(consumed), before)
        self._assert_reason(
            "approval_consumed",
            consume_approval,
            self.engagement_id,
            approval["approval_id"],
        )
        self._assert_reason(
            "approval_consumed", self._verify, approval["approval_id"]
        )
        self.assertEqual(
            approval_status(self.engagement_id, approval["approval_id"])["status"],
            "used",
        )

    def test_run_reservation_rechecks_expiry_and_bindings_without_consuming(self):
        approval = self._create(ttl_hours=1)
        bindings = {name: approval[name] for name in (
            "chain_id", "spec_id", "spec_sha256", "code_sha256", "technique", "targets", "custom_code"
        )}
        self._verify(approval["approval_id"])
        with self._patched_now(poc_approval.parse_utc(approval["expires_at"], "expires_at")):
            with self.assertRaises(PocError) as caught:
                consume_approval(self.engagement_id, approval["approval_id"], **bindings)
        self.assertEqual(caught.exception.reason, "approval_invalid")
        self.assertIn("expired", caught.exception.message)
        self.assertIsNone(load_approval(self.engagement_id, approval["approval_id"])["used_at"])
        bindings["code_sha256"] = "c" * 64
        with self.assertRaises(PocError) as caught:
            consume_approval(self.engagement_id, approval["approval_id"], **bindings)
        self.assertEqual(caught.exception.reason, "artifact_hash_mismatch")
        self.assertIsNone(load_approval(self.engagement_id, approval["approval_id"])["used_at"])

    def test_concurrent_process_reservations_allow_only_one_consumer(self):
        approval = self._create()
        bindings = {name: approval[name] for name in (
            "chain_id", "spec_id", "spec_sha256", "code_sha256", "technique", "targets", "custom_code"
        )}
        program = """
import json, sys
from pathlib import Path
from opencyber import engagements, poc_approval
from opencyber.poc_schema import PocError
engagements.WORKSPACE = Path(sys.argv[1])
try:
    record = poc_approval.consume_approval(sys.argv[2], sys.argv[3], **json.loads(sys.argv[4]))
    print(json.dumps({'status': 'reserved', 'used_at': record['used_at']}))
except PocError as error:
    print(json.dumps({'status': error.reason}))
"""
        command = [sys.executable, "-c", program, str(self.root), self.engagement_id,
                   approval["approval_id"], json.dumps(bindings)]
        children = [subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    for _ in range(2)]
        self.addCleanup(lambda: [child.kill() for child in children if child.poll() is None])
        outcomes = []
        for child in children:
            output, error = child.communicate(timeout=5)
            self.assertEqual(child.returncode, 0, error)
            outcomes.append(json.loads(output)["status"])
        self.assertCountEqual(outcomes, ["reserved", "approval_consumed"])
        self.assertIsNotNone(load_approval(self.engagement_id, approval["approval_id"])["used_at"])

    def test_revoke_is_signed_idempotent_and_blocks_verification(self):
        approval = self._create()
        revoked = revoke_approval(
            self.engagement_id,
            approval["approval_id"],
            "credential rotated",
            self.key,
            self.key_id,
        )
        self.assertTrue(revoked["revoked"])
        self.assertEqual(revoked["revoked_reason"], "credential rotated")
        self.assertIsNotNone(revoked["revoked_at"])
        self.assertTrue(
            load_approval(self.engagement_id, approval["approval_id"])["revoked"]
        )
        self._assert_reason(
            "approval_invalid", self._verify, approval["approval_id"]
        )
        self._assert_reason(
            "approval_invalid",
            consume_approval,
            self.engagement_id,
            approval["approval_id"],
        )
        again = revoke_approval(
            self.engagement_id,
            approval["approval_id"],
            "second reason",
            self.key,
            self.key_id,
        )
        self.assertEqual(again["revoked_at"], revoked["revoked_at"])
        self.assertEqual(again["revoked_reason"], "credential rotated")
        self.assertEqual(
            approval_status(self.engagement_id, approval["approval_id"])["status"],
            "revoked",
        )

    def test_revoke_requires_matching_key(self):
        approval = self._create()
        wrong_key = b"z" * 40
        wrong_key_id = hashlib.sha256(wrong_key).hexdigest()[:16]
        self._assert_reason(
            "approval_invalid",
            revoke_approval,
            self.engagement_id,
            approval["approval_id"],
            "compromised",
            wrong_key,
            wrong_key_id,
        )
        self.assertFalse(
            load_approval(self.engagement_id, approval["approval_id"])["revoked"]
        )

    def test_missing_approval_key(self):
        approval = self._create()
        with patch.dict(
            os.environ,
            {APPROVAL_KEY_ENV: "", "OPENCYBER_APPROVAL_KEY_FILE": ""},
        ):
            self._assert_reason(
                "approval_key_unavailable",
                load_approval,
                self.engagement_id,
                approval["approval_id"],
            )
            self._assert_reason(
                "approval_key_unavailable", self._verify, approval["approval_id"]
            )
            status = approval_status(self.engagement_id)
            self.assertFalse(status["key_available"])
            self.assertFalse(status["verified"])
            # Minting still works with an explicitly supplied operator key.
            explicit = self._create()
            self.assertEqual(explicit["engagement_id"], self.engagement_id)

    def test_approval_status_listing_counts_states(self):
        unused = self._create()
        used = self._create()
        consume_approval(self.engagement_id, used["approval_id"])
        revoked = self._create()
        revoke_approval(
            self.engagement_id,
            revoked["approval_id"],
            "test revocation",
            self.key,
            self.key_id,
        )
        expired = self._create(ttl_hours=1.0)
        corrupt_path = poc_path(
            self.engagement_id, "approvals", f"{new_record_id('apr')}.json"
        )
        corrupt_path.write_text("{not-json", encoding="utf-8")

        issued_at = poc_approval.parse_utc(expired["issued_at"], "issued_at")
        with self._patched_now(issued_at + timedelta(hours=2)):
            status = approval_status(self.engagement_id)
        self.assertEqual(status["total"], 5)
        self.assertEqual(status["counts"]["unused"], 1)
        self.assertEqual(status["counts"]["used"], 1)
        self.assertEqual(status["counts"]["revoked"], 1)
        self.assertEqual(status["counts"]["expired"], 1)
        self.assertEqual(status["counts"]["invalid"], 1)
        self.assertTrue(status["key_available"])
        self.assertEqual(
            {item["approval_id"] for item in status["approvals"]},
            {
                unused["approval_id"],
                used["approval_id"],
                revoked["approval_id"],
                expired["approval_id"],
                corrupt_path.stem,
            },
        )
        self.assertEqual(
            approval_status(self.engagement_id, unused["approval_id"])["status"],
            "unused",
        )
        self.assertEqual(
            approval_status(self.engagement_id, "not-an-id")["status"], "invalid"
        )

    def test_persistence_is_atomic_and_leaves_no_temporary_files(self):
        approval = self._create()
        consume_approval(self.engagement_id, approval["approval_id"])
        revoke_approval(
            self.engagement_id,
            approval["approval_id"],
            "cleanup test",
            self.key,
            self.key_id,
        )
        directory = self._approvals_directory()
        self.assertEqual(list(directory.glob(".*.tmp")), [])
        self.assertTrue((directory / ".lock").is_file())
        self.assertEqual(
            sorted(path.name for path in directory.glob("apr_*.json")),
            [f"{approval['approval_id']}.json"],
        )

    def test_symlinked_approval_is_refused(self):
        approval = self._create()
        path = approval_path(self.engagement_id, approval["approval_id"])
        raw = path.read_bytes()
        outside = self.root / "outside-approval.json"
        outside.write_bytes(raw)
        path.unlink()
        path.symlink_to(outside)
        with self.assertRaises(PocError):
            load_approval(self.engagement_id, approval["approval_id"])


class ApprovalCliTests(_WorkspaceTestCase):
    # -- gating ------------------------------------------------------------

    def test_every_subcommand_requires_the_approval_key(self):
        with patch.dict(
            os.environ,
            {APPROVAL_KEY_ENV: "", "OPENCYBER_APPROVAL_KEY_FILE": ""},
        ):
            for argv in (
                self._authorize_argv(),
                self._approve_argv(),
                [
                    "revoke",
                    "--engagement",
                    self.engagement_id,
                    "--approval",
                    "apr_20260101_" + "0" * 32,
                ],
                ["status", "--engagement", self.engagement_id],
            ):
                code, stdout, stderr = self._run_cli(argv)
                self.assertEqual(code, 2, argv)
                self.assertEqual(stdout, "")
                self.assertIn("approval_key_unavailable", stderr)

    def test_usage_errors_exit_two_and_help_exits_zero(self):
        self.assertEqual(self._run_cli([])[0], 2)
        code, _, stderr = self._run_cli(["not-a-command"])
        self.assertEqual(code, 2)
        self.assertIn("invalid choice", stderr)
        self.assertEqual(self._run_cli(["--help"])[0], 0)

    # -- authorize ---------------------------------------------------------

    def test_cli_authorize_and_status_happy_path(self):
        code, stdout, stderr = self._run_cli(self._authorize_argv())
        self.assertEqual(code, 0, stderr)
        record = json.loads(stdout)
        self.assertEqual(record["engagement_id"], self.engagement_id)
        self.assertEqual(record["scope_targets"], ["10.0.0.0/24"])
        self.assertIn("hmac_sha256", record)
        self.assertEqual(load_authorization(self.engagement_id), record)
        self.assertEqual(
            audit.read_audit(
                self.engagement_id, event="poc.authorization.created"
            )["total"],
            1,
        )

        code, stdout, stderr = self._run_cli(
            ["status", "--engagement", self.engagement_id]
        )
        self.assertEqual(code, 0, stderr)
        status = json.loads(stdout)
        self.assertEqual(status["engagement_id"], self.engagement_id)
        self.assertEqual(status["authorization"]["status"], "valid")
        self.assertTrue(status["authorization"]["valid"])
        self.assertIn("chains", status)
        self.assertIn("runs", status)
        self.assertIn("available", status["chains"])
        self.assertEqual(status["approvals"]["counts"]["unused"], 0)
        self.assertEqual(status["approvals"]["total"], 0)

    def test_cli_authorize_supersedes_previous_record(self):
        self.assertEqual(self._run_cli(self._authorize_argv())[0], 0)
        code, stdout, stderr = self._run_cli(
            self._authorize_argv(reference="AUTH-2026-002")
        )
        self.assertEqual(code, 0, stderr)
        self.assertEqual(json.loads(stdout)["reference"], "AUTH-2026-002")
        poc_directory = poc_path(self.engagement_id)
        self.assertEqual(
            len(list((poc_directory / "authorization-history").iterdir())), 1
        )

    def test_cli_authorize_public_scope_requires_acknowledgement(self):
        public_engagement = engagements.create_engagement(
            "Public engagement", ["example.com"]
        )
        public_id = public_engagement["engagement_id"]
        argv = self._authorize_argv(
            engagement=public_id, scope=["example.com"]
        )
        code, stdout, stderr = self._run_cli(argv)
        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn("written_authorization_required", stderr)
        self.assertFalse(
            (poc_path(public_id, "authorization.json")).exists()
        )

        code, stdout, stderr = self._run_cli(
            argv + ["--i-have-written-authorization"]
        )
        self.assertEqual(code, 0, stderr)
        self.assertEqual(load_authorization(public_id)["scope_targets"], ["example.com"])

    def test_cli_authorize_refuses_out_of_engagement_scope(self):
        argv = self._authorize_argv(scope=["evil.test"]) + [
            "--i-have-written-authorization"
        ]
        code, _, stderr = self._run_cli(argv)
        self.assertEqual(code, 2)
        self.assertIn("scope_violation", stderr)

    def test_cli_authorize_rejects_unknown_techniques(self):
        code, _, stderr = self._run_cli(
            self._authorize_argv(techniques="version_assert,not-a-technique")
        )
        self.assertEqual(code, 2)
        self.assertIn("invalid_techniques", stderr)

    def test_cli_authorize_custom_code_adds_custom_technique(self):
        argv = self._authorize_argv(techniques="version_assert")
        argv.append("--custom-code")
        code, stdout, stderr = self._run_cli(argv)
        self.assertEqual(code, 0, stderr)
        record = json.loads(stdout)
        self.assertEqual(record["allowed_techniques"], ["custom", "version_assert"])
        self.assertTrue(record["custom_code_allowed"])

    # -- approve -----------------------------------------------------------

    def _engine_stub(self, spec, lint_result=None, calls=None, render_result=None):
        calls = calls if calls is not None else []

        def load_spec(engagement_id, spec_id):
            calls.append("load_spec")
            return dict(spec)

        def lint(engagement_id, spec_id):
            calls.append("lint")
            return dict(lint_result or {"blocking": [], "warnings": [], "passed": True})

        def render(engagement_id, spec_id):
            calls.append("render")
            return dict(render_result or {"code_sha256": CODE_SHA256})

        return fake_module("poc", load_spec=load_spec, lint=lint, render=render)

    def _spec(self, **overrides):
        spec = {
            "spec_id": self.spec_id,
            "chain_id": self.chain_id,
            "technique": "version_assert",
            "target": "10.0.0.7",
            "spec_sha256": SPEC_SHA256,
        }
        spec.update(overrides)
        return spec

    def test_cli_approve_happy_path_then_verify(self):
        calls = []
        with self._engine_stub(self._spec(), calls=calls):
            code, stdout, stderr = self._run_cli(self._approve_argv())
        self.assertEqual(code, 0, stderr)
        record = json.loads(stdout)
        self.assertEqual(record["spec_sha256"], SPEC_SHA256)
        self.assertEqual(record["code_sha256"], CODE_SHA256)
        self.assertEqual(record["targets"], ["10.0.0.7"])
        self.assertEqual(record["chain_id"], self.chain_id)
        self.assertEqual(record["spec_id"], self.spec_id)
        self.assertEqual(calls, ["load_spec", "lint", "render"])
        self.assertEqual(
            load_approval(self.engagement_id, record["approval_id"]), record
        )
        self.assertEqual(
            self._verify(record["approval_id"])["approval_id"],
            record["approval_id"],
        )
        self.assertEqual(
            audit.read_audit(self.engagement_id, event="poc.approval.created")[
                "total"
            ],
            1,
        )

    def test_cli_approve_refuses_blocking_lint_findings(self):
        calls = []
        lint_result = {
            "blocking": [{"code": "forbidden_pattern", "message": "subprocess"}],
            "warnings": [],
            "passed": False,
        }
        with self._engine_stub(
            self._spec(), lint_result=lint_result, calls=calls
        ):
            code, stdout, stderr = self._run_cli(self._approve_argv())
        self.assertEqual(code, 2)
        self.assertEqual(stdout, "")
        self.assertIn("lint_blocking", stderr)
        self.assertEqual(calls, ["load_spec", "lint"])
        directory = self._approvals_directory()
        self.assertEqual(list(directory.glob("apr_*.json")) if directory.exists() else [], [])

    def test_cli_approve_custom_tier_requires_flag(self):
        calls = []
        spec = self._spec(technique="custom")
        with self._engine_stub(spec, calls=calls):
            code, _, stderr = self._run_cli(self._approve_argv())
            self.assertEqual(code, 2)
            self.assertIn("custom_code_requires_separate_approval", stderr)
            self.assertNotIn("render", calls)

            code, stdout, stderr = self._run_cli(
                self._approve_argv(["--allow-custom-code"])
            )
            self.assertEqual(code, 0, stderr)
            record = json.loads(stdout)
        self.assertTrue(record["custom_code"])
        self.assertEqual(record["technique"], "custom")
        self.assertEqual(
            self._verify(
                record["approval_id"], technique="custom", custom_code=True
            )["approval_id"],
            record["approval_id"],
        )

    def test_cli_approve_hashes_rendered_code_file(self):
        payload = b"print('POC_RESULT {}')\n"
        expected = sha256_hex(payload)

        def render(engagement_id, spec_id):
            path = poc_path(engagement_id, "code", f"{spec_id}.py")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(payload)
            return {}

        with fake_module(
            "poc",
            load_spec=lambda engagement_id, spec_id: self._spec(),
            lint=lambda engagement_id, spec_id: {
                "blocking": [],
                "warnings": [],
                "passed": True,
            },
            render=render,
        ):
            code, stdout, stderr = self._run_cli(self._approve_argv())
        self.assertEqual(code, 0, stderr)
        self.assertEqual(json.loads(stdout)["code_sha256"], expected)

    def test_cli_approve_refuses_spec_chain_mismatch(self):
        spec = self._spec(chain_id=new_record_id("chain"))
        with self._engine_stub(spec):
            code, _, stderr = self._run_cli(self._approve_argv())
        self.assertEqual(code, 2)
        self.assertIn("spec_chain_mismatch", stderr)

    def test_cli_approve_without_poc_engine_is_a_refusal(self):
        with missing_module("poc"):
            code, _, stderr = self._run_cli(self._approve_argv())
        self.assertEqual(code, 2)
        self.assertIn("poc_engine_unavailable", stderr)

    def test_cli_unexpected_engine_error_exits_one(self):
        def load_spec(engagement_id, spec_id):
            raise RuntimeError("engine exploded")

        with fake_module(
            "poc",
            load_spec=load_spec,
            lint=lambda *args: {},
            render=lambda *args: {},
        ):
            code, _, stderr = self._run_cli(self._approve_argv())
        self.assertEqual(code, 1)
        self.assertIn("unexpected error", stderr)

    def test_cli_approve_refuses_invalid_ids(self):
        argv = self._approve_argv()
        argv[argv.index("--chain") + 1] = "not-a-chain-id"
        code, _, stderr = self._run_cli(argv)
        self.assertEqual(code, 2)
        self.assertIn("invalid_id", stderr)

    # -- revoke ------------------------------------------------------------

    def test_cli_revoke(self):
        approval = self._create()
        code, stdout, stderr = self._run_cli(
            [
                "revoke",
                "--engagement",
                self.engagement_id,
                "--approval",
                approval["approval_id"],
                "--reason",
                "credential rotated",
            ]
        )
        self.assertEqual(code, 0, stderr)
        record = json.loads(stdout)
        self.assertTrue(record["revoked"])
        self.assertEqual(record["revoked_reason"], "credential rotated")
        self._assert_reason(
            "approval_invalid", self._verify, approval["approval_id"]
        )
        self.assertEqual(
            audit.read_audit(self.engagement_id, event="poc.approval.revoked")[
                "total"
            ],
            1,
        )

    # -- status ------------------------------------------------------------

    def test_cli_status_exits_zero_when_engine_modules_are_missing(self):
        self.assertEqual(self._run_cli(self._authorize_argv())[0], 0)
        with missing_module("cve_chain"), missing_module("poc"):
            code, stdout, stderr = self._run_cli(
                ["status", "--engagement", self.engagement_id]
            )
        self.assertEqual(code, 0, stderr)
        status = json.loads(stdout)
        self.assertFalse(status["chains"]["available"])
        self.assertFalse(status["runs"]["available"])
        self.assertEqual(status["authorization"]["status"], "valid")

    def test_cli_status_reports_chain_verdicts_and_runs(self):
        with fake_module(
            "cve_chain",
            list_chains=lambda engagement_id: {
                "chains": [
                    {"chain_id": new_record_id("chain"), "verdict": "complete"}
                ],
                "invalid": [],
            },
        ), fake_module(
            "poc",
            list_runs=lambda engagement_id: {
                "runs": [{"run_id": "run_20260101_" + "0" * 32, "status": "verified"}]
            },
        ):
            code, stdout, stderr = self._run_cli(
                ["status", "--engagement", self.engagement_id]
            )
        self.assertEqual(code, 0, stderr)
        status = json.loads(stdout)
        self.assertTrue(status["chains"]["available"])
        self.assertEqual(status["chains"]["items"][0]["verdict"], "complete")
        self.assertTrue(status["runs"]["available"])
        self.assertEqual(status["runs"]["items"][0]["status"], "verified")


class RunGateContractTests(_WorkspaceTestCase):
    """A refused run keeps its refusal payload and declares what it did not cover."""

    def _chain_and_spec(self):
        from opencyber import cve_chain, poc

        chain = cve_chain.plan_chain(
            self.engagement_id,
            [
                {
                    "cve_id": "CVE-2026-1234",
                    "asset": "10.0.0.7",
                    "requires": [],
                    "provides": ["info:version"],
                    "basis": "Advisory: the version endpoint reports the build.",
                }
            ],
            [],
        )
        spec = poc.create_spec(
            self.engagement_id,
            chain_id=chain["chain_id"],
            step_order=1,
            technique="version_assert",
            target="http://10.0.0.7",
        )
        return chain, spec

    def test_refused_run_declares_unknown_coverage_and_no_target_interaction(self):
        from opencyber import poc

        chain, spec = self._chain_and_spec()
        self.assertEqual(spec["coverage"]["status"], "complete")
        result = asyncio.run(
            poc.run(
                self.engagement_id,
                chain_id=chain["chain_id"],
                spec_id=spec["spec_id"],
                approval_id=new_record_id("apr"),
            )
        )
        self.assertEqual(result["status"], "refused")
        self.assertEqual(result["reason"], "authorization_required")
        self.assertEqual(result["coverage"]["status"], "unknown")
        self.assertTrue(any("did not run" in item for item in result["limitations"]))

    def test_live_run_tool_keeps_refusal_payload_and_coverage(self):
        from opencyber.server import mcp

        chain, spec = self._chain_and_spec()
        envelope = asyncio.run(mcp.call_tool("oc_poc_run", {
                    "engagement_id": self.engagement_id,
                    "chain_id": chain["chain_id"],
                    "spec_id": spec["spec_id"],
                    "approval_id": new_record_id("apr"),
                })).structured_content
        self.assertEqual(envelope["status"], "refused")
        self.assertEqual(envelope["reason"], "authorization_required")
        self.assertEqual(envelope["coverage"]["status"], "unknown")
        self.assertTrue(envelope["limitations"])
        self.assertNotIn("error", envelope)


if __name__ == "__main__":
    unittest.main()
