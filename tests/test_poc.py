"""Tests for the CVE-chain PoC spec/render/lint/run engine (opencyber.poc)."""

from __future__ import annotations

import asyncio
import contextlib
from datetime import timedelta
import io
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import fcntl
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import types
import unittest
from unittest.mock import patch
from contextlib import redirect_stderr, redirect_stdout

import opencyber
import opencyber.audit as audit
import opencyber.engagements as engagements
import opencyber.poc as poc
import opencyber.poc_schema as poc_schema
from opencyber.poc_schema import PocError


CHAIN_ID = "chain_20260101_" + "a" * 32
OTHER_CHAIN_ID = "chain_20260101_" + "c" * 32
APPROVAL_ID = "apr_20260101_" + "b" * 32
CALLBACK_TOKEN = "callbacktoken12345"
CALLBACK_URL = "https://app.example.test/listener"


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def read_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------
# In-process fake authorization / approval / chain modules
# ---------------------------------------------------------------------------


class FakeBackend:
    """Stand-in for the modules written by the authorization and chain tasks."""

    def __init__(self) -> None:
        self.calls: dict[str, list] = {
            "validate_for_run": [],
            "verify_approval": [],
            "consume_approval": [],
        }
        self.chain_error: Exception | None = None
        self.chain: dict = {
            "verdict": "complete",
            "steps": [
                {
                    "order": 1,
                    "cve_id": "CVE-2026-1234",
                    "asset": "app.example.test",
                    "satisfied": True,
                },
                {
                    "order": 2,
                    "cve_id": "CVE-2026-5678",
                    "asset": "127.0.0.1",
                    "satisfied": True,
                },
            ],
        }
        self.authorization_error: Exception | None = None
        self.approval_error: Exception | None = None
        self.consume_error: Exception | None = None
        self.describe_error: Exception | None = None
        self.describe: dict = {
            "status": "active",
            "valid": True,
            "custom_code_allowed": True,
            "allowed_techniques": list(poc.ALL_TECHNIQUES),
            "scope_targets": ["app.example.test", "127.0.0.1"],
            "key_available": True,
        }

    def load_chain(self, engagement_id: str, chain_id: str) -> dict:
        if self.chain_error is not None:
            raise self.chain_error
        record = dict(self.chain)
        record["chain_id"] = chain_id
        return record

    def validate_for_run(
        self,
        engagement_id: str,
        targets: list[str],
        technique: str,
        custom_code: bool,
    ) -> dict:
        self.calls["validate_for_run"].append(
            {
                "engagement_id": engagement_id,
                "targets": list(targets),
                "technique": technique,
                "custom_code": custom_code,
            }
        )
        if self.authorization_error is not None:
            raise self.authorization_error
        return {"authorized_by": "operator", "reference": "ENG-1", "key_id": "k" * 16}

    def describe_authorization(self, engagement_id: str) -> dict:
        if self.describe_error is not None:
            raise self.describe_error
        return dict(self.describe)

    def verify_approval(self, engagement_id: str, approval_id: str, **kwargs) -> dict:
        self.calls["verify_approval"].append({"approval_id": approval_id, **kwargs})
        if self.approval_error is not None:
            raise self.approval_error
        return {"approval_id": approval_id}

    def consume_approval(self, engagement_id: str, approval_id: str, **kwargs) -> dict:
        self.calls["consume_approval"].append(approval_id)
        if self.consume_error is not None:
            raise self.consume_error
        return {"approval_id": approval_id}

    def modules(self) -> dict[str, types.ModuleType]:
        chain_module = types.ModuleType("opencyber.cve_chain")
        chain_module.load_chain = self.load_chain
        authorization_module = types.ModuleType("opencyber.authorization")
        authorization_module.validate_for_run = self.validate_for_run
        authorization_module.describe_authorization = self.describe_authorization
        approval_module = types.ModuleType("opencyber.poc_approval")
        approval_module.verify_approval = self.verify_approval
        approval_module.consume_approval = self.consume_approval
        return {
            "cve_chain": chain_module,
            "authorization": authorization_module,
            "poc_approval": approval_module,
        }


class WorkspaceMixin:
    """Temp workspace + fake sibling modules for one test."""

    USE_FAKE_MODULES = True

    def setUp(self) -> None:  # noqa: D401 - unittest hook
        super().setUp()
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.stack = contextlib.ExitStack()
        self.stack.enter_context(patch.object(engagements, "WORKSPACE", self.root))
        self.engagement = engagements.create_engagement(
            "PoC", ["127.0.0.1", "app.example.test"]
        )
        self.engagement_id = self.engagement["engagement_id"]
        self.workspace = Path(self.engagement["workspace"])
        self.fakes = FakeBackend()
        if self.USE_FAKE_MODULES:
            modules = self.fakes.modules()
            for name, module in modules.items():
                self.stack.enter_context(
                    patch.dict(sys.modules, {f"opencyber.{name}": module})
                )
            for name, module in modules.items():
                self.stack.enter_context(
                    patch.object(opencyber, name, module, create=True)
                )
        self.addCleanup(self._cleanup_workspace)

    def _cleanup_workspace(self) -> None:
        self.stack.close()
        self.temporary.cleanup()

    # -- helpers -------------------------------------------------------

    def make_spec(self, technique: str, **overrides):
        kwargs = {
            "chain_id": CHAIN_ID,
            "step_order": 1,
            "technique": technique,
            "target": "https://app.example.test",
        }
        kwargs.update(overrides)
        return poc.create_spec(self.engagement_id, **kwargs)

    def spec_path(self, spec_id: str) -> Path:
        return self.workspace / "poc" / "specs" / f"{spec_id}.json"

    def run_dir(self, run_id: str) -> Path:
        return self.workspace / "poc" / "runs" / run_id

    def valid_technique_kwargs(self) -> dict[str, dict]:
        return {
            "version_assert": {},
            "http_sequence": {
                "requests": [
                    {"method": "GET", "path": "/one"},
                    {"method": "GET", "path": "/two"},
                ],
                "assertions": [{"type": "status_in", "statuses": [200], "request": 1}],
            },
            "http_auth_diff": {
                "requests": [
                    {"method": "GET", "path": "/protected"},
                    {
                        "method": "GET",
                        "path": "/protected",
                        "headers": {"X-Api-Key": "sekrit"},
                    },
                ],
            },
            "oob_callback": {
                "assertions": [
                    {
                        "type": "callback_received",
                        "url": CALLBACK_URL,
                        "token": CALLBACK_TOKEN,
                        "polls": 3,
                        "interval_ms": 50,
                    }
                ]
            },
            "file_read_canary": {
                "requests": [{"method": "GET", "path": "/canary"}],
                "assertions": [{"type": "body_regex", "pattern": "CANARY-OK"}],
            },
            "tcp_probe": {
                "target": "127.0.0.1:9",
                "step_order": 2,
                "assertions": [{"type": "body_regex", "pattern": ".+"}],
            },
        }


# ---------------------------------------------------------------------------
# Local HTTP fixture
# ---------------------------------------------------------------------------


class ProbeHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        return

    def _respond(self, status: int, body: bytes, **headers: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Canary", "CANARY-HEADER")
        for name, value in headers.items():
            self.send_header(name.replace("_", "-"), value)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def do_GET(self) -> None:
        path = self.path.split("?")[0]
        if path == "/canary":
            self._respond(200, b"prefix CANARY-OK suffix")
        elif path == "/protected":
            if self.headers.get("X-Api-Key") == "sekrit":
                self._respond(200, b"welcome authorized")
            else:
                self._respond(403, b"denied")
        elif path == "/sequence/one":
            self._respond(200, b"step-one")
        elif path == "/sequence/two":
            self._respond(200, b"step-two")
        elif path == "/listener":
            self._respond(200, ("callback hit " + CALLBACK_TOKEN).encode())
        else:
            self._respond(200, b"root route")


class HttpFixtureMixin:
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls.http_server = ThreadingHTTPServer(("127.0.0.1", 0), ProbeHandler)
        cls.http_server.daemon_threads = True
        cls.http_thread = threading.Thread(
            target=cls.http_server.serve_forever, daemon=True
        )
        cls.http_thread.start()
        cls.http_port = cls.http_server.server_address[1]

    @classmethod
    def tearDownClass(cls) -> None:
        cls.http_server.shutdown()
        cls.http_server.server_close()
        cls.http_thread.join(timeout=5)
        super().tearDownClass()

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.http_port}"


class SlowBannerFixture:
    """Send a banner, then keep the connection open without more data."""

    def __init__(self, banner: bytes = b"SSH-2.0-OpenCyberTest\r\n") -> None:
        self.banner = banner
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen(4)
        self.port = self.socket.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        while True:
            try:
                client, _address = self.socket.accept()
            except OSError:
                return
            try:
                client.sendall(self.banner)
                threading.Event().wait(5)
            except OSError:
                pass
            finally:
                client.close()

    def close(self) -> None:
        with contextlib.suppress(OSError):
            self.socket.close()
        self.thread.join(timeout=2)


class TcpBannerFixture:
    def __init__(self, banner: bytes = b"SSH-2.0-OpenCyberTest\r\n") -> None:
        self.banner = banner
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen(4)
        self.port = self.socket.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self) -> None:
        while True:
            try:
                client, _address = self.socket.accept()
            except OSError:
                return
            try:
                client.sendall(self.banner)
            except OSError:
                pass
            finally:
                client.close()

    def close(self) -> None:
        with contextlib.suppress(OSError):
            self.socket.close()
        self.thread.join(timeout=2)


# ---------------------------------------------------------------------------
# Payload helpers for the server-side evaluator
# ---------------------------------------------------------------------------


def build_record(
    index: int = 0,
    *,
    status: int | None = 200,
    body_text: str = "",
    headers: dict | None = None,
    latency_ms: float = 5.0,
    body_sha256: str | None = None,
    url: str = "https://app.example.test/path",
    truncated: bool = False,
    error: str | None = None,
) -> dict:
    return {
        "index": index,
        "method": "GET",
        "url": url,
        "status": status,
        "reason": "OK" if status else "",
        "headers": dict(headers or {}),
        "body_text": body_text,
        "body_bytes": len(body_text.encode("utf-8")),
        "body_sha256": body_sha256
        if body_sha256 is not None
        else hashlib.sha256(body_text.encode("utf-8")).hexdigest(),
        "truncated": truncated,
        "latency_ms": latency_ms,
        "error": error,
    }


def build_payload(
    spec: dict,
    records: list[dict] | None = None,
    *,
    callbacks: list[dict] | None = None,
    error: str | None = None,
    truncated: bool = False,
) -> dict:
    return {
        "schema_version": 1,
        "spec_id": spec["spec_id"],
        "technique": spec["technique"],
        "target": spec["target"],
        "transcript_path": "transcript.jsonl",
        "started_at": "2026-01-01T00:00:00Z",
        "completed_at": "2026-01-01T00:00:01Z",
        "duration_ms": 1000.0,
        "requests": list(records or []),
        "callbacks": list(callbacks or []),
        "technique_data": {},
        "error": error,
        "truncated": truncated,
    }


def poc_result_line(payload: dict) -> str:
    return "POC_RESULT " + json.dumps(
        payload, sort_keys=True, separators=(",", ":")
    )


# ---------------------------------------------------------------------------
# Spec validation
# ---------------------------------------------------------------------------


class SpecValidationTests(WorkspaceMixin, unittest.TestCase):
    def test_tls_verification_is_the_default_and_opt_out_is_explicit(self):
        default = self.make_spec("version_assert")
        self.assertFalse(default["allow_insecure_tls"])
        insecure = self.make_spec("version_assert", allow_insecure_tls=True)
        self.assertTrue(insecure["allow_insecure_tls"])
        with self.assertRaises(poc.PocError):
            self.make_spec("version_assert", allow_insecure_tls="yes")

    def test_create_spec_defaults_and_round_trip(self):
        spec = self.make_spec("version_assert")
        self.assertEqual(spec["schema_version"], 1)
        self.assertEqual(spec["chain_id"], CHAIN_ID)
        self.assertEqual(spec["step_order"], 1)
        self.assertEqual(spec["cve_id"], "CVE-2026-1234")
        self.assertEqual(spec["technique"], "version_assert")
        self.assertEqual(spec["target"], "https://app.example.test")
        self.assertEqual(
            spec["requests"],
            [{"method": "GET", "path": "/", "headers": {}, "body": ""}],
        )
        self.assertEqual(
            spec["assertions"], [{"type": "status_in", "statuses": [200]}]
        )
        self.assertEqual(spec["limits"], poc_schema.resolved_limits())
        self.assertEqual(spec["capture"], {"redact_headers": True})
        self.assertEqual(spec["source"], "")
        self.assertEqual(spec["notes"], "")
        self.assertRegex(spec["spec_sha256"], r"^[0-9a-f]{64}$")
        loaded = poc.load_spec(self.engagement_id, spec["spec_id"])
        self.assertEqual(loaded, spec)
        # The digest must cover every persisted field except itself. Coverage and
        # limitations are result-envelope decoration, not part of the stored record.
        body = {
            key: value
            for key, value in spec.items()
            if key not in ("spec_sha256", "coverage", "limitations")
        }
        self.assertEqual(
            spec["spec_sha256"],
            hashlib.sha256(
                json.dumps(
                    body,
                    sort_keys=True,
                    separators=(",", ":"),
                    ensure_ascii=False,
                    allow_nan=False,
                ).encode("utf-8")
            ).hexdigest(),
        )

    def test_create_spec_for_each_non_custom_technique(self):
        for technique, overrides in self.valid_technique_kwargs().items():
            with self.subTest(technique=technique):
                spec = self.make_spec(technique, **overrides)
                self.assertEqual(spec["technique"], technique)
                self.assertEqual(
                    poc.load_spec(self.engagement_id, spec["spec_id"])["technique"],
                    technique,
                )

    def test_invalid_technique_and_step_order(self):
        with self.assertRaises(PocError) as caught:
            self.make_spec("sql_injection")
        self.assertEqual(caught.exception.reason, "invalid_spec")
        with self.assertRaises(PocError) as caught:
            self.make_spec("version_assert", step_order=99)
        self.assertEqual(caught.exception.reason, "invalid_spec")
        with self.assertRaises(PocError) as caught:
            self.make_spec("version_assert", step_order=True)
        self.assertEqual(caught.exception.reason, "invalid_spec")

    def test_unknown_keys_are_rejected(self):
        with self.assertRaises(PocError) as caught:
            self.make_spec(
                "version_assert",
                requests=[
                    {"method": "GET", "path": "/", "extra": "nope"}
                ],
            )
        self.assertEqual(caught.exception.reason, "invalid_spec")
        with self.assertRaises(PocError) as caught:
            self.make_spec("version_assert", limits={"max_requests": 1, "bogus": 1})
        self.assertEqual(caught.exception.reason, "invalid_limit")
        with self.assertRaises(PocError) as caught:
            self.make_spec(
                "version_assert",
                assertions=[{"type": "status_in", "statuses": [200], "x": 1}],
            )
        self.assertEqual(caught.exception.reason, "invalid_spec")

    def test_limits_are_capped(self):
        with self.assertRaises(PocError) as caught:
            self.make_spec("version_assert", limits={"max_requests": 21})
        self.assertEqual(caught.exception.reason, "invalid_limit")
        with self.assertRaises(PocError) as caught:
            self.make_spec("version_assert", limits={"timeout_s": 61})
        self.assertEqual(caught.exception.reason, "invalid_limit")
        with self.assertRaises(PocError) as caught:
            self.make_spec("version_assert", limits={"max_bytes": 2 * 1024 * 1024})
        self.assertEqual(caught.exception.reason, "invalid_limit")

    def test_limits_respect_lowered_environment_cap(self):
        with patch.dict("os.environ", {"OPENCYBER_POC_MAX_REQUESTS": "2"}):
            with self.assertRaises(PocError) as caught:
                self.make_spec(
                    "http_sequence",
                    requests=[
                        {"method": "GET", "path": "/a"},
                        {"method": "GET", "path": "/b"},
                        {"method": "GET", "path": "/c"},
                    ],
                    limits={"max_requests": 3},
                )
            self.assertEqual(caught.exception.reason, "invalid_limit")
            self.assertEqual(
                self.make_spec("version_assert")["limits"]["max_requests"], 2
            )

    def test_scope_refusals(self):
        with self.assertRaises(PocError) as caught:
            self.make_spec("version_assert", target="https://evil.test")
        self.assertEqual(caught.exception.reason, "scope_violation")
        # In engagement scope but not the chain step asset.
        with self.assertRaises(PocError) as caught:
            self.make_spec("version_assert", target="https://127.0.0.1")
        self.assertEqual(caught.exception.reason, "scope_violation")

    def test_target_validation(self):
        with self.assertRaises(PocError):
            self.make_spec("version_assert", target="ftp://app.example.test")
        with self.assertRaises(PocError):
            self.make_spec("version_assert", target="https://user:pw@app.example.test")
        with self.assertRaises(PocError):
            self.make_spec("version_assert", target="app.example.test")
        with self.assertRaises(PocError):
            self.make_spec("tcp_probe", target="127.0.0.1", step_order=2)
        spec = self.make_spec(
            "tcp_probe",
            target="tcp://127.0.0.1:8443",
            step_order=2,
            assertions=[{"type": "body_regex", "pattern": ".+"}],
        )
        self.assertEqual(spec["target"], "127.0.0.1:8443")

    def test_assertion_validation(self):
        cases = [
            ("version_assert", [{"type": "bogus"}]),
            (
                "version_assert",
                [
                    {
                        "type": "callback_received",
                        "url": CALLBACK_URL,
                        "token": CALLBACK_TOKEN,
                    }
                ],
            ),
            ("oob_callback", []),
            (
                "oob_callback",
                [
                    {
                        "type": "callback_received",
                        "url": CALLBACK_URL,
                        "token": "short",
                    }
                ],
            ),
            ("file_read_canary", [{"type": "status_in", "statuses": [200]}]),
            (
                "tcp_probe",
                [{"type": "status_in", "statuses": [200]}],
                {"target": "127.0.0.1:9", "step_order": 2},
            ),
            ("version_assert", [{"type": "body_regex", "pattern": "("}]),
            ("version_assert", [{"type": "status_in", "statuses": [99]}]),
        ]
        for case in cases:
            technique, assertions = case[0], case[1]
            extra = case[2] if len(case) > 2 else {}
            with self.subTest(technique=technique, assertions=assertions):
                with self.assertRaises(PocError):
                    self.make_spec(technique, assertions=assertions, **extra)

    def test_oob_callback_token_is_generated(self):
        spec = self.make_spec(
            "oob_callback",
            assertions=[
                {
                    "type": "callback_received",
                    "url": CALLBACK_URL,
                    "polls": 2,
                    "interval_ms": 100,
                }
            ],
        )
        assertion = spec["assertions"][0]
        self.assertRegex(assertion["token"], r"^[A-Za-z0-9._-]{8,64}$")
        self.assertEqual(assertion["polls"], 2)
        self.assertEqual(poc.load_spec(self.engagement_id, spec["spec_id"]), spec)

    def test_custom_source_rules(self):
        with self.assertRaises(PocError) as caught:
            self.make_spec("version_assert", source="print('x')")
        self.assertEqual(caught.exception.reason, "invalid_spec")
        with self.assertRaises(PocError) as caught:
            self.make_spec("custom", source="   ")
        self.assertEqual(caught.exception.reason, "invalid_spec")
        with self.assertRaises(PocError):
            self.make_spec(
                "custom",
                source="print('x')",
                requests=[{"method": "GET", "path": "/"}],
            )
        spec = self.make_spec("custom", source="print('custom')\n", notes="unit")
        self.assertEqual(spec["source"], "print('custom')\n")
        self.assertEqual(spec["requests"], [])
        self.assertEqual(spec["assertions"], [])
        # Custom sources may target a bare host:port when they do not speak HTTP.
        raw_target = self.make_spec(
            "custom", source="print('custom')\n", target="127.0.0.1:445", step_order=2
        )
        self.assertEqual(raw_target["target"], "127.0.0.1:445")

    def test_unknown_spec_and_tampered_spec(self):
        with self.assertRaises(PocError) as caught:
            poc.load_spec(self.engagement_id, "spec_20260101_" + "f" * 32)
        self.assertEqual(caught.exception.reason, "unknown_spec")

        spec = self.make_spec("version_assert")
        path = self.spec_path(spec["spec_id"])
        tampered = read_json(path)
        tampered["notes"] = "changed after creation"
        path.write_text(json.dumps(tampered), encoding="utf-8")
        with self.assertRaises(PocError) as caught:
            poc.load_spec(self.engagement_id, spec["spec_id"])
        self.assertEqual(caught.exception.reason, "spec_invalid")

        spec = self.make_spec("version_assert")
        path = self.spec_path(spec["spec_id"])
        tampered = read_json(path)
        tampered.pop("limits")
        path.write_text(json.dumps(tampered), encoding="utf-8")
        with self.assertRaises(PocError) as caught:
            poc.load_spec(self.engagement_id, spec["spec_id"])
        self.assertEqual(caught.exception.reason, "spec_invalid")


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


class RenderTests(WorkspaceMixin, unittest.TestCase):
    def test_render_is_deterministic(self):
        spec = self.make_spec(
            "http_sequence",
            requests=[
                {"method": "GET", "path": "/one"},
                {"method": "POST", "path": "/two", "body": "payload"},
            ],
        )
        first = poc.render(self.engagement_id, spec["spec_id"])
        first_bytes = Path(first["code_path"]).read_bytes()
        second = poc.render(self.engagement_id, spec["spec_id"])
        second_bytes = Path(second["code_path"]).read_bytes()
        self.assertEqual(first_bytes, second_bytes)
        self.assertEqual(first["code_sha256"], second["code_sha256"])
        self.assertEqual(
            first["code_sha256"],
            hashlib.sha256(first_bytes).hexdigest(),
        )
        self.assertEqual(first["spec_sha256"], spec["spec_sha256"])
        self.assertTrue(first["code_path_relative"].startswith("poc/code/"))

    def test_all_techniques_render_safe_stdlib_code(self):
        for technique, overrides in self.valid_technique_kwargs().items():
            with self.subTest(technique=technique):
                spec = self.make_spec(technique, **overrides)
                rendered = poc.render(self.engagement_id, spec["spec_id"])
                code = Path(rendered["code_path"]).read_text(encoding="utf-8")
                compile(code, f"{spec['spec_id']}.py", "exec")
                self.assertEqual(code.count("POC_RESULT "), 1)
                self.assertIn('sys.stdout.write("POC_RESULT "', code)
                self.assertNotIn("import opencyber", code)
                self.assertNotIn("subprocess", code)
                self.assertEqual(poc._forbidden_matches(code), [])
                self.assertFalse(poc._has_unbounded_while_true(code))
                self.assertIn("transcript.jsonl", code)
                for header in ("authorization", "cookie", "x-api-key"):
                    self.assertIn(header, code)

    def test_custom_render_stores_source_verbatim(self):
        source = "print('POC_RESULT {}')\n"
        spec = self.make_spec("custom", source=source)
        rendered = poc.render(self.engagement_id, spec["spec_id"])
        path = Path(rendered["code_path"])
        self.assertEqual(path.read_bytes(), source.encode("utf-8"))
        self.assertEqual(
            rendered["code_sha256"], hashlib.sha256(source.encode("utf-8")).hexdigest()
        )

    def test_render_refuses_forbidden_custom_source(self):
        spec = self.make_spec(
            "custom", source="import subprocess\nsubprocess.run(['id'])\n"
        )
        with self.assertRaises(PocError) as caught:
            poc.render(self.engagement_id, spec["spec_id"])
        self.assertEqual(caught.exception.reason, "lint_failed")
        blocking = caught.exception.details["blocking"]
        self.assertIn("forbidden_pattern", [item["code"] for item in blocking])

    def test_render_refuses_non_compiling_custom_source(self):
        spec = self.make_spec("custom", source="def broken(:\n")
        with self.assertRaises(PocError) as caught:
            poc.render(self.engagement_id, spec["spec_id"])
        self.assertEqual(caught.exception.reason, "invalid_source")

    def test_render_refuses_when_custom_is_not_authorized(self):
        self.fakes.describe["custom_code_allowed"] = False
        spec = self.make_spec("custom", source="print('x')\n")
        with self.assertRaises(PocError) as caught:
            poc.render(self.engagement_id, spec["spec_id"])
        self.assertEqual(caught.exception.reason, "lint_failed")
        self.assertIn(
            "custom_code_not_authorized",
            [item["code"] for item in caught.exception.details["blocking"]],
        )


# ---------------------------------------------------------------------------
# Linting
# ---------------------------------------------------------------------------


class LintTests(WorkspaceMixin, unittest.TestCase):
    def test_lint_passes_with_in_scope_hosts(self):
        spec = self.make_spec(
            "http_sequence",
            requests=[
                {"method": "GET", "path": "/one"},
                {
                    "method": "POST",
                    "path": "/two",
                    "headers": {"Referer": "https://app.example.test/one"},
                    "body": "callback https://api.app.example.test:8443/hook",
                },
            ],
        )
        result = poc.lint(self.engagement_id, spec["spec_id"])
        self.assertTrue(result["passed"])
        self.assertEqual(result["blocking"], [])
        self.assertTrue(result["hosts"])
        self.assertTrue(all(entry["allowed"] for entry in result["hosts"]))
        hosts = {entry["host"] for entry in result["hosts"]}
        self.assertIn("app.example.test", hosts)

    def test_lint_blocks_out_of_scope_hosts(self):
        spec = self.make_spec(
            "http_sequence",
            requests=[
                {"method": "GET", "path": "/one"},
                {
                    "method": "POST",
                    "path": "/two",
                    "headers": {"X-Target": "internal.evil.test:8080"},
                    "body": "see http://evil.test/payload",
                },
            ],
        )
        result = poc.lint(self.engagement_id, spec["spec_id"])
        self.assertFalse(result["passed"])
        codes = [item["code"] for item in result["blocking"]]
        self.assertIn("out_of_scope_host", codes)
        blocked_hosts = {
            item["evidence"]["host"]
            for item in result["blocking"]
            if item["code"] == "out_of_scope_host"
        }
        self.assertIn("evil.test", blocked_hosts)
        self.assertIn("internal.evil.test", blocked_hosts)
        self.assertFalse(
            next(
                entry for entry in result["hosts"] if entry["host"] == "evil.test"
            )["allowed"]
        )

    def test_lint_blocks_forbidden_custom_patterns(self):
        source = (
            "import subprocess\n"
            "open('/etc/shadow')\n"
            "while True:\n"
            "    pass\n"
            "subprocess.run(['bash', '-i'])\n"
        )
        spec = self.make_spec("custom", source=source)
        result = poc.lint(self.engagement_id, spec["spec_id"])
        self.assertFalse(result["passed"])
        patterns = {
            item["evidence"]["pattern"]
            for item in result["blocking"]
            if item["code"] == "forbidden_pattern"
        }
        self.assertIn("subprocess", patterns)
        self.assertIn("/etc/shadow credential read", patterns)
        self.assertIn("unbounded while True", patterns)

    def test_lint_custom_warning_and_authorization_gate(self):
        spec = self.make_spec("custom", source="import json\nprint(json.dumps({}))\n")
        result = poc.lint(self.engagement_id, spec["spec_id"])
        self.assertTrue(result["passed"])
        warning_codes = [item["code"] for item in result["warnings"]]
        self.assertIn("custom_code_requires_separate_approval", warning_codes)
        self.assertIn("custom_spec_has_no_assertions", warning_codes)

        self.fakes.describe["custom_code_allowed"] = False
        result = poc.lint(self.engagement_id, spec["spec_id"])
        self.assertFalse(result["passed"])
        self.assertIn(
            "custom_code_not_authorized",
            [item["code"] for item in result["blocking"]],
        )

        self.fakes.describe_error = RuntimeError("module broken")
        result = poc.lint(self.engagement_id, spec["spec_id"])
        self.assertFalse(result["passed"])
        self.assertIn(
            "custom_authorization_unavailable",
            [item["code"] for item in result["blocking"]],
        )

    def test_lint_ignores_code_identifiers_in_custom_source(self):
        self.fakes.describe["custom_code_allowed"] = True
        spec = self.make_spec(
            "custom",
            source="import json\nvalue = json.dumps({'a': 1})\nprint(value)\n",
        )
        result = poc.lint(self.engagement_id, spec["spec_id"])
        self.assertTrue(result["passed"], result["blocking"])

    def test_lint_reports_limits_above_current_cap(self):
        spec = self.make_spec("version_assert", limits={"max_requests": 5})
        with patch.dict("os.environ", {"OPENCYBER_POC_MAX_REQUESTS": "2"}):
            result = poc.lint(self.engagement_id, spec["spec_id"])
        self.assertFalse(result["passed"])
        self.assertIn("limits_exceeded", [item["code"] for item in result["blocking"]])

    def test_lint_rejects_unknown_technique_directly(self):
        spec = self.make_spec("version_assert")
        forged = dict(spec)
        forged["technique"] = "sql_injection"
        result = poc._lint_spec(forged)
        self.assertFalse(result["passed"])
        self.assertIn(
            "technique_not_allowed", [item["code"] for item in result["blocking"]]
        )

    def test_lint_warns_when_callback_budget_exceeds_timeout(self):
        spec = self.make_spec(
            "oob_callback",
            assertions=[
                {
                    "type": "callback_received",
                    "url": CALLBACK_URL,
                    "token": CALLBACK_TOKEN,
                    "polls": 20,
                    "interval_ms": 5000,
                }
            ],
            limits={"timeout_s": 10},
        )
        result = poc.lint(self.engagement_id, spec["spec_id"])
        self.assertTrue(result["passed"])
        self.assertIn(
            "callback_polling_exceeds_timeout",
            [item["code"] for item in result["warnings"]],
        )


# ---------------------------------------------------------------------------
# Server-side evaluator
# ---------------------------------------------------------------------------


class EvaluatorTests(WorkspaceMixin, unittest.TestCase):
    def _http_sequence_spec(self):
        return self.make_spec(
            "http_sequence",
            requests=[
                {"method": "GET", "path": "/one"},
                {"method": "GET", "path": "/two"},
            ],
            assertions=[
                {"type": "status_in", "statuses": [200], "request": 0},
                {"type": "body_regex", "pattern": "marker", "request": 1},
                {
                    "type": "header_regex",
                    "header": "server",
                    "pattern": "nginx",
                    "request": 1,
                },
                {"type": "latency_lt_ms", "ms": 500, "request": 1},
            ],
        )

    def test_assertions_pass_on_matching_observations(self):
        spec = self._http_sequence_spec()
        payload = build_payload(
            spec,
            [
                build_record(0, status=200, body_text="one"),
                build_record(
                    1,
                    status=200,
                    body_text="marker here",
                    headers={"Server": "nginx/1.20"},
                ),
            ],
        )
        findings = poc._evaluate_assertions(spec, payload)
        self.assertTrue(all(item["passed"] for item in findings), findings)
        types = [item["type"] for item in findings]
        self.assertIn("status_in", types)
        self.assertIn("body_regex", types)
        self.assertIn("header_regex", types)
        self.assertIn("latency_lt_ms", types)

    def test_assertions_fail_on_mismatched_observations(self):
        spec = self._http_sequence_spec()
        payload = build_payload(
            spec,
            [
                build_record(0, status=500, body_text="one"),
                build_record(
                    1,
                    status=200,
                    body_text="nothing useful",
                    headers={"Server": "apache"},
                    latency_ms=900.0,
                ),
            ],
        )
        findings = poc._evaluate_assertions(spec, payload)
        failed = {item["type"] for item in findings if not item["passed"]}
        self.assertIn("status_in", failed)
        self.assertIn("body_regex", failed)
        self.assertIn("header_regex", failed)
        self.assertIn("latency_lt_ms", failed)

    def test_truncated_body_is_reported(self):
        spec = self.make_spec(
            "version_assert",
            assertions=[{"type": "body_regex", "pattern": "marker"}],
        )
        payload = build_payload(
            spec,
            [
                build_record(
                    0, status=200, body_text="partial", truncated=True
                )
            ],
        )
        findings = poc._evaluate_assertions(spec, payload)
        body = next(item for item in findings if item["type"] == "body_regex")
        self.assertFalse(body["passed"])
        self.assertIn("truncated", body["detail"])

    def test_callback_received_uses_observed_token(self):
        spec = self.make_spec(
            "oob_callback",
            assertions=[
                {
                    "type": "callback_received",
                    "url": CALLBACK_URL,
                    "token": CALLBACK_TOKEN,
                    "polls": 2,
                    "interval_ms": 100,
                }
            ],
        )
        good = build_payload(
            spec,
            callbacks=[
                {
                    "attempt": 0,
                    "url": CALLBACK_URL,
                    "status": 200,
                    "matched": True,
                    "body_text": "callback hit " + CALLBACK_TOKEN,
                    "error": None,
                }
            ],
        )
        findings = poc._evaluate_assertions(spec, good)
        callback = next(
            item for item in findings if item["type"] == "callback_received"
        )
        self.assertTrue(callback["passed"], callback)

        bad = build_payload(
            spec,
            callbacks=[
                {
                    "attempt": 0,
                    "url": CALLBACK_URL,
                    "status": 200,
                    "matched": True,
                    "body_text": "no token here",
                    "error": None,
                }
            ],
        )
        findings = poc._evaluate_assertions(spec, bad)
        callback = next(
            item for item in findings if item["type"] == "callback_received"
        )
        self.assertFalse(callback["passed"])

    def test_auth_diff_requires_an_actual_difference(self):
        spec = self.make_spec(
            "http_auth_diff",
            requests=[
                {"method": "GET", "path": "/protected"},
                {
                    "method": "GET",
                    "path": "/protected",
                    "headers": {"X-Api-Key": "sekrit"},
                },
            ],
        )
        same = build_payload(
            spec,
            [
                build_record(0, status=403, body_text="denied"),
                build_record(1, status=403, body_text="denied"),
            ],
        )
        findings = poc._evaluate_assertions(spec, same)
        access = next(item for item in findings if item["type"] == "access_diff")
        self.assertFalse(access["passed"])

        different = build_payload(
            spec,
            [
                build_record(0, status=403, body_text="denied"),
                build_record(1, status=200, body_text="welcome"),
            ],
        )
        findings = poc._evaluate_assertions(spec, different)
        access = next(item for item in findings if item["type"] == "access_diff")
        self.assertTrue(access["passed"])

    def test_out_of_scope_observation_is_flagged(self):
        spec = self.make_spec("version_assert")
        payload = build_payload(
            spec,
            [build_record(0, status=200, body_text="x", url="http://evil.test/")],
        )
        findings = poc._evaluate_assertions(spec, payload)
        scope = next(
            item for item in findings if item["type"] == "observation_scope"
        )
        self.assertFalse(scope["passed"])

    def test_probe_error_fails_evaluation(self):
        spec = self.make_spec("version_assert")
        payload = build_payload(
            spec,
            [build_record(0, status=200, body_text="x")],
            error="socket.timeout: timed out",
        )
        findings = poc._evaluate_assertions(spec, payload)
        probe = next(item for item in findings if item["type"] == "probe_error")
        self.assertFalse(probe["passed"])

    def test_parse_poc_result_requires_exactly_one_final_line(self):
        spec = self.make_spec("version_assert")
        payload = build_payload(
            spec, [build_record(0, status=200, body_text="ok")]
        )
        line = poc_result_line(payload)

        parsed, findings = poc._parse_poc_result("noise\n" + line + "\n", spec)
        self.assertIsNotNone(parsed)
        self.assertEqual(findings, [])

        parsed, findings = poc._parse_poc_result("noise only\n", spec)
        self.assertIsNone(parsed)
        self.assertFalse(findings[0]["passed"])

        parsed, findings = poc._parse_poc_result(line + "\n" + line + "\n", spec)
        self.assertIsNone(parsed)
        self.assertIn("exactly one", findings[0]["detail"])

        parsed, findings = poc._parse_poc_result(line + "\ntrailing output\n", spec)
        self.assertIsNone(parsed)
        self.assertIn("final non-empty", findings[0]["detail"])

        other = dict(payload)
        other["spec_id"] = "spec_20260101_" + "e" * 32
        parsed, findings = poc._parse_poc_result(poc_result_line(other), spec)
        self.assertIsNone(parsed)

        parsed, findings = poc._parse_poc_result("POC_RESULT {broken", spec)
        self.assertIsNone(parsed)


# ---------------------------------------------------------------------------
# Run pipeline (real subprocess against a loopback fixture)
# ---------------------------------------------------------------------------


class RunTests(HttpFixtureMixin, WorkspaceMixin, unittest.IsolatedAsyncioTestCase):
    async def _async_run(self, spec, approval_id: str = APPROVAL_ID):
        return await poc.run(
            self.engagement_id,
            chain_id=CHAIN_ID,
            spec_id=spec["spec_id"],
            approval_id=approval_id,
        )

    def assert_verified(self, result, spec):
        self.assertEqual(result["status"], "verified", result["assertions"])
        self.assertEqual(result["coverage"]["status"], "complete")
        self.assertNotIn("limit", result)
        self.assertTrue(result["approval_consumed"])
        self.assertTrue(all(item["passed"] for item in result["assertions"]))
        run_dir = self.run_dir(result["run_id"])
        for name in (
            "result.json",
            "evidence.json",
            "stdout.txt",
            "stderr.txt",
            "transcript.jsonl",
        ):
            self.assertTrue((run_dir / name).is_file(), name)
        evidence = read_json(run_dir / "evidence.json")
        self.assertEqual(evidence["status"], "verified")
        self.assertFalse(evidence["allow_insecure_tls"])
        self.assertEqual(evidence["spec_id"], spec["spec_id"])
        self.assertEqual(evidence["chain_id"], CHAIN_ID)
        self.assertEqual(
            evidence["assertions_passed"], evidence["assertions_total"]
        )
        self.assertGreaterEqual(evidence["assertions_total"], 1)
        stdout = (run_dir / "stdout.txt").read_text(encoding="utf-8")
        self.assertEqual(sha256_text(stdout), result["output_sha256"])
        self.assertIn("POC_RESULT ", stdout)
        self.assertEqual((run_dir / "stdout.txt").read_bytes(), stdout.encode())
        recorded = read_json(run_dir / "result.json")
        self.assertEqual(recorded["status"], "verified")
        self.assertEqual(recorded["run_id"], result["run_id"])
        report = audit.verify_audit(self.engagement_id)
        self.assertTrue(report["valid"], report)
        events = audit.audit_summary(self.engagement_id)["events"]
        self.assertIn("poc.run.started", events)
        self.assertIn("poc.run.completed", events)
        return evidence

    async def test_run_version_assert_verified(self):
        spec = self.make_spec(
            "version_assert",
            step_order=2,
            target=self.base_url,
            requests=[{"method": "GET", "path": "/canary"}],
            assertions=[
                {"type": "status_in", "statuses": [200]},
                {"type": "body_regex", "pattern": "CANARY-OK"},
                {"type": "header_regex", "header": "X-Canary", "pattern": "CANARY"},
                {"type": "latency_lt_ms", "ms": 5000},
            ],
        )
        rendered = poc.render(self.engagement_id, spec["spec_id"])
        result = await self._async_run(spec)
        self.assert_verified(result, spec)
        self.assertEqual(result["request_count"], 1)
        verify_call = self.fakes.calls["verify_approval"][0]
        self.assertEqual(verify_call["approval_id"], APPROVAL_ID)
        self.assertEqual(verify_call["chain_id"], CHAIN_ID)
        self.assertEqual(verify_call["spec_id"], spec["spec_id"])
        self.assertEqual(verify_call["spec_sha256"], spec["spec_sha256"])
        self.assertEqual(verify_call["code_sha256"], rendered["code_sha256"])
        self.assertEqual(verify_call["technique"], "version_assert")
        self.assertEqual(verify_call["targets"], [spec["target"]])
        self.assertIs(verify_call["custom_code"], False)
        self.assertEqual(self.fakes.calls["consume_approval"], [APPROVAL_ID])
        self.assertEqual(
            len(self.fakes.calls["validate_for_run"]), 2
        )

    async def test_run_http_sequence_verified(self):
        spec = self.make_spec(
            "http_sequence",
            step_order=2,
            target=self.base_url,
            requests=[
                {"method": "GET", "path": "/sequence/one"},
                {"method": "GET", "path": "/sequence/two"},
            ],
            assertions=[
                {"type": "status_in", "statuses": [200], "request": 0},
                {"type": "body_regex", "pattern": "step-two", "request": 1},
            ],
        )
        result = await self._async_run(spec)
        self.assert_verified(result, spec)
        self.assertEqual(result["request_count"], 2)

    async def test_run_http_auth_diff_verified(self):
        spec = self.make_spec(
            "http_auth_diff",
            step_order=2,
            target=self.base_url,
            requests=[
                {"method": "GET", "path": "/protected"},
                {
                    "method": "GET",
                    "path": "/protected",
                    "headers": {"X-Api-Key": "sekrit"},
                },
            ],
            assertions=[
                {"type": "status_in", "statuses": [200], "request": 1},
                {"type": "body_regex", "pattern": "welcome", "request": 1},
            ],
        )
        result = await self._async_run(spec)
        evidence = self.assert_verified(result, spec)
        access = next(
            item for item in evidence["assertions"] if item["type"] == "access_diff"
        )
        self.assertTrue(access["passed"])
        transcript = (
            self.run_dir(result["run_id"]) / "transcript.jsonl"
        ).read_text(encoding="utf-8")
        request_entries = [
            json.loads(line)
            for line in transcript.splitlines()
            if json.loads(line).get("phase") == "request"
        ]
        redacted = [
            entry
            for entry in request_entries
            if entry["headers"].get("X-Api-Key") == "<redacted>"
        ]
        self.assertTrue(redacted, request_entries)
        self.assertNotIn("sekrit", transcript)

    async def test_run_file_read_canary_verified(self):
        spec = self.make_spec(
            "file_read_canary",
            step_order=2,
            target=self.base_url,
            requests=[{"method": "GET", "path": "/canary"}],
            assertions=[{"type": "body_regex", "pattern": "CANARY-OK"}],
        )
        result = await self._async_run(spec)
        self.assert_verified(result, spec)

    async def test_run_oob_callback_verified(self):
        spec = self.make_spec(
            "oob_callback",
            step_order=2,
            target=self.base_url,
            requests=[{"method": "GET", "path": "/root"}],
            assertions=[
                {
                    "type": "callback_received",
                    "url": f"{self.base_url}/listener",
                    "token": CALLBACK_TOKEN,
                    "polls": 3,
                    "interval_ms": 50,
                }
            ],
        )
        result = await self._async_run(spec)
        evidence = self.assert_verified(result, spec)
        callback = next(
            item
            for item in evidence["assertions"]
            if item["type"] == "callback_received"
        )
        self.assertTrue(callback["passed"])
        self.assertTrue(
            any(entry["phase"] == "callback" for entry in evidence["transcript_entries"])
        )

    async def test_tcp_banner_before_the_deadline_is_retained(self):
        fixture = SlowBannerFixture()
        self.addCleanup(fixture.close)
        spec = self.make_spec(
            "tcp_probe",
            target=f"127.0.0.1:{fixture.port}",
            step_order=2,
            assertions=[{"type": "body_regex", "pattern": "SSH-2.0"}],
            limits={"timeout_s": 1},
        )
        result = await self._async_run(spec)
        self.assertEqual(result["status"], "not_verified")
        probe = next(item for item in result["assertions"] if item["type"] == "probe_error")
        self.assertFalse(probe["passed"])
        stdout = (self.run_dir(result["run_id"]) / "stdout.txt").read_text()
        self.assertIn("SSH-2.0-OpenCyberTest", stdout)
        self.assertIn("timed_out_after_partial_body", stdout)

    async def test_run_tcp_probe_verified(self):
        fixture = TcpBannerFixture()
        self.addCleanup(fixture.close)
        spec = self.make_spec(
            "tcp_probe",
            step_order=2,
            target=f"127.0.0.1:{fixture.port}",
            assertions=[{"type": "body_regex", "pattern": "OpenCyberTest"}],
        )
        result = await self._async_run(spec)
        self.assert_verified(result, spec)

    async def test_run_failed_assertions_is_not_verified_but_consumes(self):
        spec = self.make_spec(
            "version_assert",
            step_order=2,
            target=self.base_url,
            requests=[{"method": "GET", "path": "/missing"}],
            assertions=[{"type": "body_regex", "pattern": "never-present"}],
        )
        result = await self._async_run(spec)
        self.assertEqual(result["status"], "not_verified")
        self.assertTrue(result["approval_consumed"])
        self.assertFalse(all(item["passed"] for item in result["assertions"]))
        self.assertEqual(self.fakes.calls["consume_approval"], [APPROVAL_ID])
        self.assertTrue(self.run_dir(result["run_id"]).is_dir())
        events = audit.audit_summary(self.engagement_id)["events"]
        self.assertIn("poc.run.completed", events)

    async def test_run_timeout(self):
        spec = self.make_spec(
            "version_assert",
            step_order=2,
            target=self.base_url,
            limits={"timeout_s": 1, "max_requests": 20, "max_bytes": 65536},
        )

        async def hang(*args, **kwargs):
            await asyncio.sleep(30)

        with patch.object(poc.executor, "execute_tool", hang):
            result = await self._async_run(spec)
        self.assertEqual(result["status"], "timeout")
        self.assertEqual(result["coverage"]["status"], "partial")
        self.assertTrue(any("timeout" in item for item in result["limitations"]))
        self.assertEqual(result["limit"]["id"], "poc.timeout_s")
        self.assertEqual(result["limit"]["effective"], 1)
        self.assertTrue(result["approval_consumed"])
        evidence = read_json(self.run_dir(result["run_id"]) / "evidence.json")
        self.assertTrue(evidence["timed_out"])
        self.assertEqual(evidence["status"], "timeout")
        self.assertEqual(
            (self.run_dir(result["run_id"]) / "stdout.txt").read_text(), ""
        )
        self.assertEqual(self.fakes.calls["consume_approval"], [APPROVAL_ID])

    async def test_run_truncated_capture_is_partial_with_byte_limit_facts(self):
        spec = self.make_spec(
            "version_assert",
            step_order=2,
            target=self.base_url,
            requests=[{"method": "GET", "path": "/canary"}],
            assertions=[{"type": "status_in", "statuses": [200]}],
            limits={"max_bytes": 8},
        )
        result = await self._async_run(spec)
        self.assertEqual(result["status"], "verified")
        self.assertTrue(result["truncated"])
        self.assertEqual(result["coverage"]["status"], "partial")
        self.assertEqual(result["limit"]["id"], "poc.max_bytes")
        self.assertEqual(result["limit"]["effective"], 8)
        self.assertTrue(any("truncated" in item for item in result["limitations"]))
        recorded = poc.get_run(self.engagement_id, result["run_id"])
        self.assertEqual(recorded["coverage"]["status"], "partial")
        self.assertEqual(recorded["limit"]["id"], "poc.max_bytes")

    async def test_executor_output_cap_is_reported_as_partial_coverage(self):
        spec = self.make_spec(
            "version_assert",
            step_order=2,
            target=self.base_url,
            requests=[{"method": "GET", "path": "/canary"}],
            assertions=[{"type": "status_in", "statuses": [200]}],
        )
        payload = build_payload(spec, [build_record(0, status=200, body_text="ok")])
        capped_output = poc_result_line(payload) + "\n"
        received_bytes = 4 * 1024 * 1024 + 17

        async def capped(*args, **kwargs):
            return {
                "available": True,
                "success": True,
                "returncode": 0,
                "stdout": capped_output,
                "stderr": "",
                "stdout_bytes": received_bytes,
                "stderr_bytes": 0,
                "truncated": True,
                "max_output_bytes": 4 * 1024 * 1024,
            }

        with patch.object(poc.executor, "execute_tool", capped):
            result = await self._async_run(spec)
        self.assertTrue(result["truncated"])
        self.assertEqual(result["coverage"]["status"], "partial")
        self.assertEqual(result["limit"]["id"], "tool.max_output_bytes")
        self.assertEqual(result["limit"]["effective"], 4 * 1024 * 1024)
        evidence = read_json(self.run_dir(result["run_id"]) / "evidence.json")
        self.assertTrue(evidence["executor_truncated"])
        self.assertEqual(evidence["stdout_bytes"], received_bytes)
        self.assertTrue(any("executor output cap" in item for item in result["limitations"]))

    async def test_run_refuses_multiple_poc_result_lines(self):
        spec = self.make_spec(
            "version_assert", step_order=2, target=self.base_url
        )
        payload = build_payload(
            spec, [build_record(0, status=200, body_text="ok")]
        )
        line = poc_result_line(payload)

        async def forged(*args, **kwargs):
            return {
                "success": True,
                "available": True,
                "returncode": 0,
                "stdout": line + "\n" + line + "\n",
                "stderr": "",
            }

        with patch.object(poc.executor, "execute_tool", forged):
            result = await self._async_run(spec)
        self.assertEqual(result["status"], "not_verified")
        self.assertIn(
            "poc_result", [item["type"] for item in result["assertions"]]
        )

    async def test_run_refuses_nonzero_child_exit(self):
        spec = self.make_spec(
            "version_assert", step_order=2, target=self.base_url
        )
        payload = build_payload(
            spec, [build_record(0, status=200, body_text="ok")]
        )

        async def forged(*args, **kwargs):
            return {
                "success": False,
                "available": True,
                "returncode": 3,
                "stdout": poc_result_line(payload) + "\n",
                "stderr": "boom",
            }

        with patch.object(poc.executor, "execute_tool", forged):
            result = await self._async_run(spec)
        self.assertEqual(result["status"], "not_verified")
        self.assertEqual(result["returncode"], 3)

    async def test_run_refuses_execution_unavailable(self):
        async def unavailable(*args, **kwargs):
            return {
                "success": False,
                "available": False,
                "error": "executable is not installed: python3",
            }

        spec = self.make_spec(
            "version_assert", step_order=2, target=self.base_url
        )
        with patch.object(poc.executor, "execute_tool", unavailable):
            result = await self._async_run(spec)
        self.assertEqual(result["status"], "refused")
        self.assertEqual(result["reason"], "execution_unavailable")
        self.assertTrue(result["approval_consumed"])
        self.assertEqual(self.fakes.calls["consume_approval"], [APPROVAL_ID])
        self.assertTrue(self.run_dir(result["run_id"]).is_dir())

    async def test_run_refusals_do_not_consume_approval(self):
        spec = self.make_spec("version_assert", step_order=2, target=self.base_url)

        self.fakes.chain["verdict"] = "incomplete"
        result = await self._async_run(spec)
        self.assertEqual(result["status"], "refused")
        self.assertEqual(result["reason"], "chain_incomplete")
        self.assertEqual(result["coverage"]["status"], "unknown")
        self.assertTrue(any("did not run" in item for item in result["limitations"]))
        self.assertEqual(self.fakes.calls["validate_for_run"], [])

        self.fakes.chain["verdict"] = "complete"
        self.fakes.authorization_error = PocError(
            "authorization_required", "sign an authorization first"
        )
        result = await self._async_run(spec)
        self.assertEqual(result["status"], "refused")
        self.assertEqual(result["reason"], "authorization_required")

        self.fakes.authorization_error = None
        self.fakes.approval_error = PocError("approval_consumed", "already used")
        result = await self._async_run(spec)
        self.assertEqual(result["status"], "refused")
        self.assertEqual(result["reason"], "approval_consumed")
        self.assertEqual(self.fakes.calls["consume_approval"], [])

        bad_chain = await poc.run(
            self.engagement_id,
            chain_id=OTHER_CHAIN_ID,
            spec_id=spec["spec_id"],
            approval_id=APPROVAL_ID,
        )
        self.assertEqual(bad_chain["status"], "refused")
        self.assertEqual(bad_chain["reason"], "chain_mismatch")

        bad_approval = await poc.run(
            self.engagement_id,
            chain_id=CHAIN_ID,
            spec_id=spec["spec_id"],
            approval_id="not-an-approval",
        )
        self.assertEqual(bad_approval["status"], "refused")
        self.assertEqual(bad_approval["reason"], "invalid_id")
        events = audit.audit_summary(self.engagement_id)["events"]
        self.assertGreaterEqual(events.get("poc.run.refused", 0), 1)
        self.assertFalse((self.workspace / "poc" / "runs").exists())

    async def test_run_refuses_lint_blocking(self):
        spec = self.make_spec(
            "custom",
            source="import subprocess\nsubprocess.run(['id'])\n",
        )
        result = await self._async_run(spec)
        self.assertEqual(result["status"], "refused")
        self.assertEqual(result["reason"], "lint_failed")
        self.assertIn("blocking", result)
        self.assertEqual(self.fakes.calls["consume_approval"], [])

    async def test_run_in_progress_lock(self):
        lock_path = poc_schema.poc_path(self.engagement_id, ".lock")
        lock_path.parent.mkdir(parents=True, exist_ok=True)
        descriptor = os.open(lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        try:
            spec = self.make_spec(
                "version_assert", step_order=2, target=self.base_url
            )
            result = await self._async_run(spec)
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)
        self.assertEqual(result["status"], "refused")
        self.assertEqual(result["reason"], "run_in_progress")
        self.assertEqual(self.fakes.calls["consume_approval"], [])

    async def test_list_and_get_run(self):
        spec = self.make_spec(
            "version_assert",
            step_order=2,
            target=self.base_url,
            requests=[{"method": "GET", "path": "/canary"}],
            assertions=[{"type": "body_regex", "pattern": "CANARY-OK"}],
        )
        result = await self._async_run(spec)
        self.assertEqual(result["status"], "verified")
        listing = poc.list_runs(self.engagement_id)
        self.assertEqual(len(listing["runs"]), 1)
        summary = listing["runs"][0]
        self.assertEqual(summary["run_id"], result["run_id"])
        self.assertEqual(summary["status"], "verified")
        self.assertEqual(listing["invalid"], [])
        self.assertEqual(listing["coverage"]["status"], "complete")
        recorded = poc.get_run(self.engagement_id, result["run_id"])
        self.assertEqual(recorded["status"], "verified")
        self.assertEqual(recorded["coverage"]["status"], "complete")
        self.assertIn("payload", recorded)
        self.assertEqual(recorded["evidence_path"], result["evidence_path"])
        with self.assertRaises(PocError) as caught:
            poc.get_run(self.engagement_id, "run_20260101_" + "d" * 32)
        self.assertEqual(caught.exception.reason, "unknown_run")
        broken = self.workspace / "poc" / "runs" / ("run_20260101_" + "e" * 32)
        broken.mkdir(parents=True)
        (broken / "result.json").write_text("{not json", encoding="utf-8")
        damaged = poc.list_runs(self.engagement_id)
        self.assertEqual(damaged["coverage"]["status"], "partial")
        self.assertEqual(len(damaged["invalid"]), 1)
        self.assertTrue(any("could not be read" in item for item in damaged["limitations"]))



class RunToolEnvelopeTests(unittest.TestCase):
    """The live MCP envelope for PoC tools, without the fake sibling modules."""

    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.workspace_patch = patch.object(
            engagements, "WORKSPACE", Path(self.temporary.name)
        )
        self.workspace_patch.start()
        self.addCleanup(self.workspace_patch.stop)
        self.engagement = engagements.create_engagement("Envelope", ["127.0.0.1"])
        self.engagement_id = self.engagement["engagement_id"]

    def test_live_run_tool_refusal_carries_typed_code(self):
        from opencyber.server import mcp

        envelope = asyncio.run(mcp.call_tool("oc_poc_evidence", {
            "engagement_id": self.engagement_id,
            "run_id": "run_20260101_" + "d" * 32,
        })).structured_content
        self.assertFalse(envelope["ok"])
        self.assertEqual(envelope["error"]["code"], "not_found")
        self.assertEqual(envelope["error"]["category"], "not_found")

    def test_stored_refused_run_uses_an_advertised_evidence_error(self):
        from opencyber.contracts import contract_for
        from opencyber.server import mcp

        run_id = "run_20260101_" + "e" * 32
        run_dir = Path(self.engagement["workspace"]) / "poc" / "runs" / run_id
        run_dir.mkdir(parents=True)
        (run_dir / "result.json").write_text(json.dumps({
            "run_id": run_id, "status": "refused", "reason": "execution_error",
            "message": "synthetic executor failure", "approval_consumed": True,
        }), encoding="utf-8")
        result = asyncio.run(mcp.call_tool("oc_poc_evidence", {
            "engagement_id": self.engagement_id, "run_id": run_id,
        })).structured_content
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"]["code"], "execution_failed")
        self.assertIn(result["error"]["code"], contract_for("oc_poc_evidence").error_codes)
        self.assertEqual(result["run_id"], run_id)
        self.assertTrue(result["approval_consumed"])
        self.assertEqual(result["coverage"]["status"], "partial")


class RunRefusalTests(WorkspaceMixin, unittest.IsolatedAsyncioTestCase):
    """Refusal paths that do not need the HTTP fixture."""

    async def test_authorization_and_approval_verification_arguments(self):
        spec = self.make_spec("version_assert")
        rendered = poc.render(self.engagement_id, spec["spec_id"])

        async def fake_execute(*args, **kwargs):
            return {
                "success": True,
                "available": True,
                "returncode": 0,
                "stdout": "",
                "stderr": "",
            }

        with patch.object(poc.executor, "execute_tool", fake_execute):
            result = await poc.run(
                self.engagement_id,
                chain_id=CHAIN_ID,
                spec_id=spec["spec_id"],
                approval_id=APPROVAL_ID,
            )
        # No POC_RESULT means the engine must not trust the exit code.
        self.assertEqual(result["status"], "not_verified")
        self.assertEqual(result["approval_consumed"], True)
        verify_call = self.fakes.calls["verify_approval"][0]
        self.assertEqual(verify_call["code_sha256"], rendered["code_sha256"])
        self.assertEqual(verify_call["custom_code"], False)
        self.assertEqual(
            self.fakes.calls["validate_for_run"][0]["targets"], [spec["target"]]
        )
        self.assertFalse(
            (self.workspace / "poc" / "code" / "missing.py").exists()
        )

    async def test_custom_spec_without_assertions_is_not_verified(self):
        spec = self.make_spec("custom", source="print('custom')\n")
        payload = build_payload(
            spec, [build_record(0, status=200, body_text="ok")]
        )

        async def forged(*args, **kwargs):
            return {
                "success": True,
                "available": True,
                "returncode": 0,
                "stdout": poc_result_line(payload) + "\n",
                "stderr": "",
            }

        with patch.object(poc.executor, "execute_tool", forged):
            result = await poc.run(
                self.engagement_id,
                chain_id=CHAIN_ID,
                spec_id=spec["spec_id"],
                approval_id=APPROVAL_ID,
            )
        # A custom POC_RESULT with no assertions is not verifiable server-side.
        self.assertEqual(result["status"], "not_verified")
        self.assertIn(
            "assertions", [item["type"] for item in result["assertions"]]
        )
        self.assertTrue(result["approval_consumed"])

    async def test_custom_run_passes_custom_flag_and_refuses_lint(self):
        spec = self.make_spec(
            "custom",
            source="print('hello from the custom tier')\n",
        )
        result = await poc.run(
            self.engagement_id,
            chain_id=CHAIN_ID,
            spec_id=spec["spec_id"],
            approval_id=APPROVAL_ID,
        )
        # The source prints nothing parseable, so the engine must not verify it.
        self.assertEqual(result["status"], "not_verified")
        self.assertEqual(self.fakes.calls["validate_for_run"][0]["custom_code"], True)
        self.assertEqual(self.fakes.calls["verify_approval"][0]["custom_code"], True)
        self.assertEqual(result["approval_consumed"], True)

        blocked = self.make_spec(
            "custom",
            source="import subprocess\nsubprocess.run(['id'])\n",
        )
        result = await poc.run(
            self.engagement_id,
            chain_id=CHAIN_ID,
            spec_id=blocked["spec_id"],
            approval_id=APPROVAL_ID,
        )
        self.assertEqual(result["status"], "refused")
        self.assertEqual(result["reason"], "lint_failed")
        self.assertEqual(self.fakes.calls["consume_approval"], [APPROVAL_ID])



class CrossModuleIntegrationTests(
    HttpFixtureMixin, WorkspaceMixin, unittest.IsolatedAsyncioTestCase
):
    """End-to-end run against the real chain, authorization, and approval modules."""

    USE_FAKE_MODULES = False
    APPROVAL_KEY = "poc-engine-integration-key-" + "k" * 40

    def setUp(self) -> None:
        super().setUp()
        import opencyber.cve_chain as cve_chain
        import opencyber.poc_approval as cli

        self.cve_chain = cve_chain
        self.cli = cli
        self.stack.enter_context(
            patch.dict("os.environ", {"OPENCYBER_APPROVAL_KEY": self.APPROVAL_KEY})
        )

    def approved_probe(self):
        """Prepare real signed records without involving an external target."""
        from opencyber.authorization import write_authorization

        chain = self.cve_chain.plan_chain(
            self.engagement_id,
            [{"cve_id": "CVE-2026-1234", "asset": "127.0.0.1", "requires": [],
              "provides": [], "basis": "approval interruption regression"}], [],
        )
        spec = poc.create_spec(
            self.engagement_id, chain_id=chain["chain_id"], step_order=1,
            technique="version_assert", target=self.base_url,
        )
        rendered = poc.render(self.engagement_id, spec["spec_id"])
        key, key_id = poc_schema.resolve_approval_key()
        write_authorization(self.engagement_id, {
            "authorized_by": "Regression operator", "reference": "TEST-INTERRUPTION",
            "acknowledgement": "I have written authorization for this engagement",
            "scope_targets": ["127.0.0.1"], "allowed_techniques": ["version_assert"],
            "prohibited_effects": [],
            "valid_until": poc_schema.iso_utc(poc_schema.utc_now() + timedelta(hours=2)),
        }, key, key_id)
        approval = self.cli.create_approval(
            self.engagement_id, chain_id=chain["chain_id"], spec_id=spec["spec_id"],
            spec_sha256=spec["spec_sha256"], code_sha256=rendered["code_sha256"],
            technique="version_assert", targets=[spec["target"]], custom_code=False,
            issued_by="Regression operator", ttl_hours=1, key=key, key_id=key_id,
        )
        return spec, {"chain_id": chain["chain_id"], "spec_id": spec["spec_id"],
                      "approval_id": approval["approval_id"]}

    async def test_cancellation_after_launch_durably_consumes_approval(self):
        _spec, arguments = self.approved_probe()
        launched = asyncio.Event()

        async def probe(*args, **kwargs):
            launched.set()
            await asyncio.sleep(30)

        with patch.object(poc.executor, "execute_tool", probe):
            task = asyncio.create_task(poc.run(self.engagement_id, **arguments))
            await asyncio.wait_for(launched.wait(), 2)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        self.assertIsNotNone(self.cli.load_approval(
            self.engagement_id, arguments["approval_id"])["used_at"])
        recorded = poc.list_runs(self.engagement_id)["runs"]
        self.assertEqual([item["status"] for item in recorded], ["cancelled"])
        reused = await poc.run(self.engagement_id, **arguments)
        self.assertEqual(reused["reason"], "approval_consumed")

    async def test_consumption_write_failure_prevents_launch(self):
        spec, arguments = self.approved_probe()
        launches = []

        async def probe(*args, **kwargs):
            launches.append(True)
            return {"available": True, "returncode": 0,
                    "stdout": poc_result_line(build_payload(spec)), "stderr": ""}

        with patch.object(self.cli, "_atomic_write_json", side_effect=OSError("disk full")), \
             patch.object(poc.executor, "execute_tool", probe):
            result = await poc.run(self.engagement_id, **arguments)
        self.assertEqual(launches, [], "no target process may start before durable reservation")
        self.assertEqual(result["status"], "refused")
        self.assertIsNone(self.cli.load_approval(
            self.engagement_id, arguments["approval_id"])["used_at"])

    async def test_output_write_failure_cannot_replay_a_launched_probe(self):
        spec, arguments = self.approved_probe()

        async def probe(*args, **kwargs):
            return {"available": True, "returncode": 0,
                    "stdout": poc_result_line(build_payload(spec)), "stderr": ""}

        with patch.object(poc, "_write_bounded_text", side_effect=OSError("disk full")), \
             patch.object(poc.executor, "execute_tool", probe):
            result = await poc.run(self.engagement_id, **arguments)
        self.assertEqual(result["status"], "refused")
        self.assertIsNotNone(self.cli.load_approval(
            self.engagement_id, arguments["approval_id"])["used_at"])
        self.assertTrue(result["approval_consumed"])
        self.assertEqual(result["coverage"]["status"], "partial")
        self.assertFalse(any("did not run" in text for text in result["limitations"]))
        reused = await poc.run(self.engagement_id, **arguments)
        self.assertEqual(reused["reason"], "approval_consumed")

    async def test_pending_record_failure_reports_durable_reservation_without_launch(self):
        _spec, arguments = self.approved_probe()
        with patch.object(poc, "_write_json", side_effect=OSError("disk full")), \
             patch.object(poc.executor, "execute_tool") as execute:
            result = await poc.run(self.engagement_id, **arguments)
        execute.assert_not_called()
        self.assertEqual(result["reason"], "run_failed")
        self.assertTrue(result["approval_consumed"])
        self.assertTrue(result["run_id"].startswith("run_"))
        self.assertFalse(result["execution_started"])
        self.assertEqual(result["coverage"]["status"], "unknown")
        self.assertIsNotNone(self.cli.load_approval(self.engagement_id, arguments["approval_id"])["used_at"])

    async def test_process_death_after_target_request_cannot_replay_approval(self):
        _spec, arguments = self.approved_probe()
        program = """
import asyncio, json, os, sys
from pathlib import Path
from urllib.request import urlopen
from opencyber import engagements, poc
engagements.WORKSPACE = Path(sys.argv[1])
arguments = json.loads(sys.argv[3])
async def probe(*args, **kwargs):
    target = poc.load_spec(sys.argv[2], arguments['spec_id'])['target']
    with urlopen(target, timeout=2) as response:
        response.read(64)
    os._exit(71)
poc.executor.execute_tool = probe
asyncio.run(poc.run(sys.argv[2], **arguments))
"""
        crashed = subprocess.run(
            [sys.executable, "-c", program, str(self.root), self.engagement_id, json.dumps(arguments)],
            capture_output=True, text=True, timeout=5,
        )
        self.assertEqual(crashed.returncode, 71, crashed.stderr)
        self.assertIsNotNone(self.cli.load_approval(
            self.engagement_id, arguments["approval_id"])["used_at"])
        recorded = poc.list_runs(self.engagement_id)["runs"]
        self.assertEqual([item["status"] for item in recorded], ["running"])
        persisted = poc.get_run(self.engagement_id, recorded[0]["run_id"])
        self.assertEqual(persisted["coverage"]["status"], "partial")
        reused = await poc.run(self.engagement_id, **arguments)
        self.assertEqual(reused["reason"], "approval_consumed")

    async def test_real_chain_authorization_approval_and_run(self):
        chain = self.cve_chain.plan_chain(
            self.engagement_id,
            [
                {
                    "cve_id": "CVE-2026-1234",
                    "asset": "127.0.0.1",
                    "requires": [],
                    "provides": [],
                    "basis": "integration test step",
                }
            ],
            [],
        )
        self.assertEqual(chain["verdict"], "complete")
        self.assertEqual(chain["steps"][0]["order"], 1)
        spec = poc.create_spec(
            self.engagement_id,
            chain_id=chain["chain_id"],
            step_order=chain["steps"][0]["order"],
            technique="version_assert",
            target=self.base_url,
            requests=[{"method": "GET", "path": "/canary"}],
            assertions=[
                {"type": "status_in", "statuses": [200]},
                {"type": "body_regex", "pattern": "CANARY-OK"},
            ],
        )
        self.assertTrue(poc.lint(self.engagement_id, spec["spec_id"])["passed"])
        rendered = poc.render(self.engagement_id, spec["spec_id"])

        valid_until = poc_schema.iso_utc(poc_schema.utc_now() + timedelta(hours=2))
        expires = poc_schema.iso_utc(poc_schema.utc_now() + timedelta(hours=1))
        output, error = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(error):
            code = self.cli.main(
                [
                    "authorize",
                    "--engagement",
                    self.engagement_id,
                    "--authorized-by",
                    "Integration Operator",
                    "--reference",
                    "ENG-INTEGRATION-1",
                    "--scope",
                    "127.0.0.1",
                    "--valid-until",
                    valid_until,
                    "--techniques",
                    "version_assert",
                    "--acknowledgement",
                    "I have written authorization for this engagement",
                ]
            )
        self.assertEqual(code, 0, error.getvalue())
        authorization = json.loads(output.getvalue())
        self.assertTrue(authorization.get("hmac_sha256"))

        output, error = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(error):
            code = self.cli.main(
                [
                    "approve",
                    "--engagement",
                    self.engagement_id,
                    "--chain",
                    chain["chain_id"],
                    "--spec",
                    spec["spec_id"],
                    "--issued-by",
                    "Integration Operator",
                    "--expires",
                    expires,
                ]
            )
        self.assertEqual(code, 0, error.getvalue())
        approval = json.loads(output.getvalue())
        self.assertEqual(approval["code_sha256"], rendered["code_sha256"])
        self.assertEqual(approval["spec_sha256"], spec["spec_sha256"])

        result = await poc.run(
            self.engagement_id,
            chain_id=chain["chain_id"],
            spec_id=spec["spec_id"],
            approval_id=approval["approval_id"],
        )
        self.assertEqual(result["status"], "verified", result.get("assertions"))
        self.assertTrue(result["approval_consumed"])
        self.assertTrue(all(item["passed"] for item in result["assertions"]))

        # The real approval is single use: the second run must be refused.
        reused = await poc.run(
            self.engagement_id,
            chain_id=chain["chain_id"],
            spec_id=spec["spec_id"],
            approval_id=approval["approval_id"],
        )
        self.assertEqual(reused["status"], "refused")
        self.assertEqual(reused["reason"], "approval_consumed")

        # The CLI status view consumes poc.list_runs and cve_chain.list_chains.
        output, error = io.StringIO(), io.StringIO()
        with redirect_stdout(output), redirect_stderr(error):
            code = self.cli.main(["status", "--engagement", self.engagement_id])
        self.assertEqual(code, 0, error.getvalue())
        status = json.loads(output.getvalue())
        self.assertEqual(status["authorization"]["status"], "valid")
        self.assertEqual(
            [item["verdict"] for item in status["chains"]["items"]], ["complete"]
        )
        self.assertEqual(
            [item["status"] for item in status["runs"]["items"]], ["verified"]
        )
        listing = poc.list_runs(self.engagement_id)
        self.assertEqual([run["run_id"] for run in listing["runs"]], [result["run_id"]])
        self.assertTrue(
            audit.verify_audit(self.engagement_id)["valid"]
        )
        events = audit.audit_summary(self.engagement_id)["events"]
        for event in (
            "poc.authorization.created",
            "poc.approval.created",
            "poc.run.started",
            "poc.run.completed",
            "poc.run.refused",
        ):
            self.assertIn(event, events)


if __name__ == "__main__":
    unittest.main()
