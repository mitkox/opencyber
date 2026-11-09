"""Deterministic spec, rendering, lint, and execution engine for PoC chains.

The engine is deliberately boring and auditable:

- A *spec* is a small, strictly validated JSON document stored at
  ``poc/specs/<spec_id>.json``. Unknown keys are refused, limits are capped by
  :mod:`opencyber.poc_schema`, and the target must be inside both the engagement
  scope and the chain step asset.
- Rendering is deterministic: the same spec always produces byte-identical
  ``poc/code/<spec_id>.py``. Only six fixed, stdlib-only techniques can be
  rendered. The ``custom`` tier never executes model-written code from the
  spec; it is only stored verbatim after a separate approval flag is present.
- Linting is conservative and machine readable. Any host appearing anywhere in
  the spec (including the custom source) must be inside the engagement scope.
- Execution is a single bounded subprocess. The engine re-lints immediately
  before running, holds a per-engagement lock, and evaluates every assertion
  itself from the raw ``POC_RESULT`` observations. The child's own notion of
  success is never trusted.

Public API (also used by ``server.py`` and the ``opencyber-poc`` CLI)::

    create_spec(...) -> dict
    render(engagement_id, spec_id) -> dict
    lint(engagement_id, spec_id) -> dict
    run(engagement_id, *, chain_id, spec_id, approval_id) -> dict  (async)
    load_spec(engagement_id, spec_id) -> dict
    list_runs(engagement_id) -> dict
    get_run(engagement_id, run_id) -> dict
"""

from __future__ import annotations

from collections.abc import Iterable, Iterator, Mapping
import asyncio
import contextlib
import fcntl
import json
import os
from pathlib import Path
import re
import tempfile
import time
from typing import Any, TypeGuard
from urllib.parse import urlsplit
import uuid

from . import audit, envelope, executor, limits, poc_schema, policy
from .poc_schema import (
    ALL_TECHNIQUES,
    CUSTOM_TECHNIQUE,
    HARD_MAX_BYTES,
    HARD_MAX_REQUESTS,
    HARD_MAX_TIMEOUT_S,
    PocError,
    canonical_json,
    canonical_sha256,
    file_sha256,
    iso_utc,
    new_record_id,
    normalize_cve_id,
    parse_utc,
    poc_path,
    redact_headers,
    resolved_limits,
    sha256_hex,
    utc_now,
    validate_record_id,
)


__all__ = [
    "create_spec",
    "render",
    "lint",
    "run",
    "load_spec",
    "list_runs",
    "get_run",
]


SCHEMA_VERSION = 1
SPEC_PREFIX = "spec"
RUN_PREFIX = "run"
APPROVAL_PREFIX = "apr"

MAX_NOTES = 2000
MAX_TARGET_LENGTH = 2048
MAX_REQUESTS_PER_SPEC = HARD_MAX_REQUESTS
MAX_ASSERTIONS = 20
MAX_PATTERN_LENGTH = 500
MAX_HEADERS = 64
MAX_HEADER_NAME = 128
MAX_HEADER_VALUE = 8192
MAX_PATH_LENGTH = 2048
MAX_BODY_BYTES = 65536
MAX_SOURCE_BYTES = 200_000
MAX_CALLBACK_POLLS = 20
MAX_CALLBACK_INTERVAL_MS = 5000
MIN_CALLBACK_INTERVAL_MS = 50
MAX_POC_RESULT_BYTES = 24 * 1024 * 1024
MAX_SAVED_OUTPUT_BYTES = 8 * 1024 * 1024
MAX_TRANSCRIPT_BYTES = 512 * 1024
MAX_TRANSCRIPT_ENTRIES = 128
TRANSCRIPT_FILENAME = "transcript.jsonl"

ALLOWED_METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"})
ASSERTION_TYPES = frozenset(
    {
        "status_in",
        "body_regex",
        "header_regex",
        "latency_lt_ms",
        "callback_received",
    }
)

SPEC_RECORD_KEYS = (
    "schema_version",
    "spec_id",
    "engagement_id",
    "chain_id",
    "step_order",
    "cve_id",
    "technique",
    "target",
    "requests",
    "assertions",
    "limits",
    "capture",
    "allow_insecure_tls",
    "source",
    "notes",
    "created_at",
    "spec_sha256",
)

REQUEST_KEYS = frozenset({"method", "path", "headers", "body"})
LIMIT_KEYS = ("max_requests", "timeout_s", "max_bytes")
CAPTURE_RECORD = {"redact_headers": True}

ASSERTION_KEYS: dict[str, frozenset[str]] = {
    "status_in": frozenset({"type", "statuses", "request"}),
    "body_regex": frozenset({"type", "pattern", "request"}),
    "header_regex": frozenset({"type", "header", "pattern", "request"}),
    "latency_lt_ms": frozenset({"type", "ms", "request"}),
    "callback_received": frozenset(
        {"type", "url", "token", "polls", "interval_ms"}
    ),
}

DEFAULT_ASSERTIONS: dict[str, tuple[dict[str, Any], ...]] = {
    "version_assert": ({"type": "status_in", "statuses": [200]},),
    "http_sequence": ({"type": "status_in", "statuses": [200]},),
    "http_auth_diff": (),
    "oob_callback": (),
    "file_read_canary": (
        {"type": "body_regex", "pattern": "root:x:0:0:"},
    ),
    "tcp_probe": ({"type": "body_regex", "pattern": ".+"},),
}

CALLBACK_TOKEN_PLACEHOLDER = "{{POC_TOKEN}}"
CALLBACK_TOKEN_HEADER = "X-PoC-Callback"

DEFAULT_REQUESTS: dict[str, tuple[dict[str, Any], ...]] = {
    "version_assert": ({"method": "GET", "path": "/", "headers": {}, "body": ""},),
    "http_sequence": ({"method": "GET", "path": "/", "headers": {}, "body": ""},),
    "http_auth_diff": (),
    "oob_callback": ({"method": "GET", "path": "/", "headers": {}, "body": ""},),
    "file_read_canary": (
        {
            "method": "GET",
            "path": "/download?file=../../../../../../etc/passwd",
            "headers": {},
            "body": "",
        },
    ),
    "tcp_probe": (),
    CUSTOM_TECHNIQUE: (),
}

_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_CALLBACK_TOKEN_RE = re.compile(r"^[A-Za-z0-9._-]{8,64}$")
_URL_HOST_PORT_RE = re.compile(
    r"(?i)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}:\d{1,5}"
    r"|(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}"
    r"|localhost:\d{1,5}"
)
_ABSOLUTE_URL_RE = re.compile(r"(?i)\bhttps?://[^\s'\"<>]+")
_WHILE_TRUE_RE = re.compile(r"^(\s*)while\s+(?:True|1)\s*:")

FORBIDDEN_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("subprocess", re.compile(r"\bsubprocess\b")),
    ("os.system", re.compile(r"\bos\s*\.\s*system\s*\(")),
    ("os.popen", re.compile(r"\bos\s*\.\s*popen\s*\(")),
    ("pty", re.compile(r"\bpty\b")),
    ("ctypes", re.compile(r"\bctypes\b")),
    ("/dev/tcp", re.compile(r"/dev/tcp")),
    ("bash -i", re.compile(r"\bbash\s+-i\b")),
    ("sh -i", re.compile(r"(?<![\w-])sh\s+-i\b")),
    ("nc -e", re.compile(r"\bnc\s+-e\b")),
    ("ncat -e", re.compile(r"\bncat\s+-e\b")),
    ("msfvenom", re.compile(r"\bmsfvenom\b")),
    ("reverse shell", re.compile(r"reverse[\s_-]?shell", re.IGNORECASE)),
    ("cron persistence", re.compile(r"\bcrontab\b|/etc/cron|\bcron\.d\b")),
    ("systemd persistence", re.compile(r"\bsystemctl\b|\bsystemd\b")),
    ("ssh authorized_keys persistence", re.compile(r"authorized_keys")),
    (".bashrc persistence", re.compile(r"\.bashrc\b")),
    ("/etc/shadow credential read", re.compile(r"/etc/shadow")),
    ("id_rsa private key", re.compile(r"\bid_rsa\b")),
    ("rm -rf", re.compile(r"\brm\s+-[A-Za-z]*[rf][A-Za-z]*\b")),
    ("dd if=", re.compile(r"\bdd\s+if\s*=")),
    ("mkfs", re.compile(r"\bmkfs(?:\.\w+)?\b")),
    ("fork bomb", re.compile(r":\s*\(\s*\)\s*\{|\bfork\s*bomb\b")),
)


# ``@@CONFIG@@`` is replaced with a Python string literal holding the canonical
# JSON configuration. The template is deliberately self-contained: the child
# runs with ``PYTHONPATH=""`` and only the standard library is available.
_TEMPLATE = r'''#!/usr/bin/env python3
# Generated by the OpenCyber PoC engine. Re-render from the signed spec instead
# of editing this file by hand.
"""Bounded, deterministic probe generated for one signed PoC spec."""
import hashlib
import http.client
import json
import re
import socket
import ssl
import sys
import time
from urllib.parse import urlsplit

CONFIG = json.loads(@@CONFIG@@)
REDACTED = "<redacted>"
SECRET_HEADERS = frozenset(
    {
        "authorization",
        "proxy-authorization",
        "cookie",
        "set-cookie",
        "x-api-key",
        "x-auth-token",
        "x-csrf-token",
    }
)
TRANSCRIPT_FILE = "transcript.jsonl"


def _canonical(value, ascii_only=False):
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=bool(ascii_only),
        default=str,
    )


def _redact(headers):
    cleaned = {}
    for name, value in (headers or {}).items():
        key = str(name)
        cleaned[key] = REDACTED if key.strip().lower() in SECRET_HEADERS else str(value)
    return cleaned


def _transcript(record):
    try:
        with open(TRANSCRIPT_FILE, "a", encoding="utf-8") as handle:
            handle.write(_canonical(record) + "\n")
    except OSError:
        pass


def _utc_now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _remaining(deadline):
    return deadline - time.monotonic()


def _split_url(url):
    parsed = urlsplit(url)
    scheme = (parsed.scheme or "http").lower()
    host = parsed.hostname or ""
    port = parsed.port or (443 if scheme == "https" else 80)
    return scheme, host, port, parsed.path.rstrip("/"), parsed.netloc


def _path_with_query(url):
    parsed = urlsplit(url)
    path = parsed.path or "/"
    if parsed.query:
        path = path + "?" + parsed.query
    return path


def _blank_record(index, method, url):
    return {
        "index": index,
        "method": method,
        "url": url,
        "status": None,
        "reason": "",
        "headers": {},
        "body_text": "",
        "body_bytes": 0,
        "body_sha256": "",
        "truncated": False,
        "latency_ms": 0.0,
        "error": None,
    }


def _send(url, method, headers, body_bytes, deadline, limit):
    scheme, host, port, _base_path, _netloc = _split_url(url)
    record = _blank_record(-1, method, url)
    timeout = _remaining(deadline)
    if timeout <= 0.05:
        record["error"] = "deadline_exhausted"
        return record
    timeout = min(timeout, 15.0)
    started = time.monotonic()
    connection = None
    try:
        if scheme == "https":
            context = ssl.create_default_context()
            if CONFIG.get("allow_insecure_tls") is True:
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
            connection = http.client.HTTPSConnection(
                host, port, timeout=timeout, context=context
            )
        else:
            connection = http.client.HTTPConnection(host, port, timeout=timeout)
        connection.request(method, _path_with_query(url), body=body_bytes, headers=headers)
        response = connection.getresponse()
        response_headers = {}
        for name, value in response.getheaders():
            key = str(name)
            if key in response_headers:
                response_headers[key] = response_headers[key] + ", " + str(value)
            else:
                response_headers[key] = str(value)
        record["status"] = int(response.status)
        record["reason"] = str(response.reason or "")
        record["headers"] = _redact(response_headers)
        chunks = []
        total = 0
        read_error = None
        try:
            while total <= limit:
                block = response.read1(min(65536, limit + 1 - total))
                if not block:
                    break
                chunks.append(block)
                total += len(block)
        except TimeoutError:
            read_error = "timed_out_after_partial_body" if chunks else "timed_out_before_data"
        except (OSError, http.client.HTTPException, ssl.SSLError, ValueError) as exc:
            read_error = type(exc).__name__ + ": " + str(exc)
        raw = b"".join(chunks)
        truncated = len(raw) > limit
        if truncated:
            raw = raw[:limit]
        record["body_bytes"] = len(raw)
        record["body_sha256"] = hashlib.sha256(raw).hexdigest()
        record["body_text"] = raw.decode("utf-8", "replace")
        record["truncated"] = truncated
        record["body_complete"] = read_error is None
        if read_error is not None:
            record["error"] = read_error
    except (OSError, http.client.HTTPException, ssl.SSLError, ValueError) as exc:
        record["error"] = type(exc).__name__ + ": " + str(exc)
    finally:
        if connection is not None:
            try:
                connection.close()
            except OSError:
                pass
    record["latency_ms"] = round((time.monotonic() - started) * 1000.0, 2)
    return record


def _request_url(request):
    parsed = urlsplit(CONFIG["target"])
    scheme = (parsed.scheme or "http").lower()
    base_path = parsed.path.rstrip("/")
    return scheme + "://" + parsed.netloc + base_path + request["path"]


def _request_headers(request):
    headers = dict(request.get("headers") or {})
    technique_config = CONFIG.get("technique_config") or {}
    token = technique_config.get("token")
    header_name = technique_config.get("token_header")
    if token and header_name:
        lowered = str(header_name).lower()
        if not any(str(name).lower() == lowered for name in headers):
            headers[header_name] = token
    return headers


def _perform(index, request, deadline):
    url = _request_url(request)
    method = request["method"]
    headers = _request_headers(request)
    body = request.get("body") or ""
    body_bytes = body.encode("utf-8") if body else None
    _transcript(
        {
            "phase": "request",
            "index": index,
            "method": method,
            "url": url,
            "headers": _redact(headers),
            "body_bytes": len(body_bytes) if body_bytes else 0,
        }
    )
    record = _send(url, method, headers, body_bytes, deadline, int(CONFIG["max_bytes"]))
    record["index"] = index
    _transcript(
        {
            "phase": "response",
            "index": index,
            "url": url,
            "status": record["status"],
            "headers": _redact(record["headers"]),
            "latency_ms": record["latency_ms"],
            "body_bytes": record["body_bytes"],
            "truncated": record["truncated"],
            "error": record["error"],
        }
    )
    return record


def _perform_requests(deadline, payload):
    records = []
    for index, request in enumerate(CONFIG["requests"]):
        if _remaining(deadline) <= 0.05:
            payload["truncated"] = True
            break
        records.append(_perform(index, request, deadline))
    return records


def _run_callbacks(deadline, payload):
    technique_config = CONFIG.get("technique_config") or {}
    token = technique_config.get("token") or ""
    url = technique_config.get("callback_url") or ""
    polls = int(technique_config.get("polls") or 0)
    interval = max(0.05, float(technique_config.get("interval_ms") or 0) / 1000.0)
    observations = []
    if not url or polls < 1:
        return observations
    limit = min(int(CONFIG["max_bytes"]), 65536)
    for attempt in range(polls):
        if _remaining(deadline) <= 0.05:
            payload["truncated"] = True
            break
        record = _send(url, "GET", {}, None, deadline, limit)
        body_text = record.get("body_text") or ""
        matched = bool(token) and token in body_text
        _transcript(
            {
                "phase": "callback",
                "attempt": attempt,
                "url": url,
                "status": record["status"],
                "matched": matched,
                "error": record["error"],
            }
        )
        observations.append(
            {
                "attempt": attempt,
                "url": url,
                "status": record["status"],
                "matched": matched,
                "body_text": body_text,
                "error": record["error"],
            }
        )
        if matched:
            break
        wait = min(interval, max(0.0, _remaining(deadline)))
        if wait > 0:
            time.sleep(wait)
    return observations


def _access_diff(records):
    data = {
        "unauthenticated_status": None,
        "authorized_status": None,
        "status_differs": False,
        "body_differs": False,
        "length_differs": False,
        "access_differs": False,
    }
    if len(records) >= 2:
        first = records[0]
        second = records[1]
        data["unauthenticated_status"] = first.get("status")
        data["authorized_status"] = second.get("status")
        data["status_differs"] = first.get("status") != second.get("status")
        data["body_differs"] = first.get("body_sha256") != second.get("body_sha256")
        data["length_differs"] = first.get("body_bytes") != second.get("body_bytes")
        data["access_differs"] = bool(data["status_differs"] or data["body_differs"])
    return data


def _canary_match(records):
    canary = (CONFIG.get("technique_config") or {}).get("canary") or ""
    matched = False
    if canary:
        for record in records:
            try:
                if re.search(canary, record.get("body_text") or ""):
                    matched = True
                    break
            except re.error:
                break
    return {"canary": canary, "matched": matched}


def _tcp_target():
    target = CONFIG["target"]
    if target.lower().startswith("tcp://"):
        target = target[6:]
    host, _separator, port_text = target.rpartition(":")
    return host.strip("[]"), int(port_text)


def _run_tcp(deadline, payload):
    host, port = _tcp_target()
    record = _blank_record(0, "TCP", CONFIG["target"])
    timeout = _remaining(deadline)
    if timeout <= 0.05:
        record["error"] = "deadline_exhausted"
        return [record]
    timeout = min(timeout, 15.0)
    limit = int(CONFIG["max_bytes"])
    started = time.monotonic()
    connection = None
    chunks = []
    read_error = None
    try:
        connection = socket.create_connection((host, port), timeout=timeout)
        connection.settimeout(timeout)
        total = 0
        while total <= limit:
            block = connection.recv(min(65536, limit + 1 - total))
            if not block:
                break
            chunks.append(block)
            total += len(block)
    except TimeoutError:
        read_error = "timed_out_after_partial_body" if chunks else "timed_out_before_data"
    except (OSError, ValueError) as exc:
        read_error = type(exc).__name__ + ": " + str(exc)
    finally:
        raw = b"".join(chunks)
        if len(raw) > limit:
            raw = raw[:limit]
            record["truncated"] = True
        record["body_bytes"] = len(raw)
        record["body_sha256"] = hashlib.sha256(raw).hexdigest()
        record["body_text"] = raw.decode("utf-8", "replace")
        record["body_complete"] = read_error is None
        if read_error is not None:
            record["error"] = read_error
        if connection is not None:
            try:
                connection.close()
            except OSError:
                pass
    record["latency_ms"] = round((time.monotonic() - started) * 1000.0, 2)
    _transcript(
        {
            "phase": "tcp",
            "host": host,
            "port": port,
            "body_bytes": record["body_bytes"],
            "truncated": record["truncated"],
            "latency_ms": record["latency_ms"],
            "error": record["error"],
        }
    )
    return [record]


def main():
    started = time.time()
    deadline = time.monotonic() + max(0.5, float(CONFIG["timeout_s"]) - 0.25)
    payload = {
        "schema_version": 1,
        "spec_id": CONFIG["spec_id"],
        "technique": CONFIG["technique"],
        "target": CONFIG["target"],
        "transcript_path": TRANSCRIPT_FILE,
        "started_at": _utc_now(),
        "requests": [],
        "callbacks": [],
        "technique_data": {},
        "error": None,
        "truncated": False,
    }
    technique = CONFIG["technique"]
    try:
        if technique == "tcp_probe":
            payload["requests"] = _run_tcp(deadline, payload)
        else:
            payload["requests"] = _perform_requests(deadline, payload)
            if technique == "oob_callback":
                payload["callbacks"] = _run_callbacks(deadline, payload)
            elif technique == "http_auth_diff":
                payload["technique_data"] = _access_diff(payload["requests"])
            elif technique == "file_read_canary":
                payload["technique_data"] = _canary_match(payload["requests"])
    except Exception as exc:
        payload["error"] = type(exc).__name__ + ": " + str(exc)
    for record in payload["requests"]:
        if record.get("error"):
            payload["error"] = payload["error"] or record["error"]
            break
    payload["completed_at"] = _utc_now()
    payload["duration_ms"] = round((time.time() - started) * 1000.0, 2)
    return payload


def _emit(payload):
    sys.stdout.write("POC_RESULT " + _canonical(payload, True) + "\n")
    sys.stdout.flush()


if __name__ == "__main__":
    try:
        RESULT = main()
    except Exception as exc:
        RESULT = {
            "schema_version": 1,
            "spec_id": CONFIG["spec_id"],
            "technique": CONFIG["technique"],
            "target": CONFIG["target"],
            "requests": [],
            "callbacks": [],
            "technique_data": {},
            "error": type(exc).__name__ + ": " + str(exc),
            "truncated": True,
        }
    try:
        _emit(RESULT)
    except Exception:
        sys.exit(1)
'''


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def _is_int(value: Any) -> TypeGuard[int]:
    return isinstance(value, int) and not isinstance(value, bool)


def _run_contract(record: Mapping[str, Any]) -> dict[str, Any]:
    """Derive coverage, limitations, and any limit facts from one run record."""
    status = record.get("status")
    truncated = bool(record.get("truncated"))
    request_count = record.get("request_count") if _is_int(record.get("request_count")) else 0
    limitations: list[str] = []
    limit: dict[str, Any] | None = None
    if status == "refused" and record.get("execution_started") is False:
        coverage = envelope.coverage("unknown", exhausted=False)
        limitations.append(
            "The approval was consumed but the executor did not start because its pending record "
            "could not be persisted. Repair storage and mint a new approval before retrying."
        )
    elif status == "refused" and record.get("approval_consumed"):
        coverage = envelope.coverage("partial", examined=request_count, exhausted=False)
        limitations.append(
            "The approval was reserved for an execution attempt; target interaction may have occurred "
            "even though the run could not finish or retain its evidence."
        )
    elif status == "refused":
        coverage = envelope.coverage("unknown", exhausted=False)
        limitations.append(
            "The probe did not run; no target interaction was observed, and status/reason records why."
        )
    elif status in {"running", "cancelled"}:
        coverage = envelope.coverage("partial", examined=request_count, exhausted=False)
        limitations.append(
            "This reserved execution has no completed result; target interaction may have occurred "
            "and its approval cannot be reused."
        )
    elif status == "timeout":
        coverage = envelope.coverage("partial", examined=request_count, exhausted=False)
        timeout_s = record.get("timeout_s")
        deadline = f"{timeout_s}s" if timeout_s is not None else "configured"
        limitations.append(
            f"The probe exceeded its {deadline} timeout and was stopped; only requests observed before "
            "the deadline are included and the remainder did not run."
        )
        limit = limits.facts("poc.timeout_s", effective=timeout_s)
    elif status == "verified" and not truncated:
        coverage = envelope.coverage("complete", examined=request_count, total=request_count, exhausted=True)
        limitations.append(
            "A verified run establishes only the configured assertions over this run's observations; it "
            "does not prove exploitability beyond them or that the target was otherwise unaffected."
        )
    elif status == "not_verified" and not truncated:
        if request_count:
            coverage = envelope.coverage("complete", examined=request_count, total=request_count, exhausted=True)
        else:
            coverage = envelope.coverage("unknown", exhausted=False)
            limitations.append(
                "No request observations were recorded, so the run cannot state what the target did."
            )
    else:
        coverage = envelope.coverage("partial", examined=request_count, exhausted=False)
    if status == "not_verified":
        limitations.append(
            "Not every configured assertion passed; this run does not establish the vulnerability claim."
        )
    if truncated:
        if record.get("executor_truncated") is True:
            limitations.append(
                "The probe's captured output exceeded the executor output cap; bytes beyond it "
                "were read and discarded, so the retained output is incomplete."
            )
            if limit is None:
                limit = limits.facts(
                    "tool.max_output_bytes",
                    effective=record.get("executor_max_output_bytes"),
                )
        limitations.append(
            "Captured output was truncated at a per-run byte ceiling; retained bodies are incomplete."
        )
        if limit is None:
            limit = limits.facts("poc.max_bytes", effective=record.get("max_bytes"))
    block: dict[str, Any] = {"coverage": coverage, "limitations": limitations}
    if status == "refused":
        error = PocError(
            str(record.get("reason") or "run_failed"),
            str(record.get("message") or "The PoC run was refused."),
            **{key: record[key] for key in ("run_id", "approval_consumed", "execution_started") if key in record},
        )
        block.update(ok=False, error=error.to_error().to_dict())
    if limit is not None:
        block["limit"] = limit
    return block


def _finding(code: str, message: str, **evidence: Any) -> dict[str, Any]:
    finding: dict[str, Any] = {"code": code, "message": message}
    if evidence:
        finding["evidence"] = evidence
    return finding


def _engagement_path(engagement_id: str, *parts: str) -> Path:
    try:
        return poc_path(engagement_id, *parts)
    except ValueError as exc:
        raise PocError("unknown_engagement", str(exc)) from exc


def _ensure_directory(path: Path) -> None:
    path.mkdir(mode=0o700, parents=True, exist_ok=True)


def _atomic_write(path: Path, data: bytes) -> None:
    _ensure_directory(path.parent)
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.", dir=str(path.parent)
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(temporary_name, 0o600)
        os.replace(temporary_name, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(temporary_name)
        raise


def _write_json(path: Path, payload: Mapping[str, Any]) -> None:
    _atomic_write(path, canonical_json(payload) + b"\n")


def _read_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _write_bounded_text(path: Path, text: str) -> tuple[int, bool]:
    data = text.encode("utf-8", errors="replace")
    truncated = len(data) > MAX_SAVED_OUTPUT_BYTES
    if truncated:
        data = data[:MAX_SAVED_OUTPUT_BYTES]
    _atomic_write(path, data)
    return len(data), truncated


# ---------------------------------------------------------------------------
# Validation primitives
# ---------------------------------------------------------------------------


def _invalid(message: str, **details: Any) -> PocError:
    return PocError("invalid_spec", message, **details)


def _normalize_notes(notes: Any) -> str:
    if notes is None:
        return ""
    if not isinstance(notes, str):
        raise _invalid("notes must be a string")
    if len(notes) > MAX_NOTES:
        raise _invalid(f"notes must be at most {MAX_NOTES} characters")
    return notes


def _normalize_source(technique: str, source: Any) -> str:
    if source is None:
        source = ""
    if not isinstance(source, str):
        raise _invalid("source must be a string")
    if technique != CUSTOM_TECHNIQUE:
        if source.strip():
            raise _invalid("source is only allowed for the custom technique")
        return ""
    if not source.strip():
        raise _invalid("the custom technique requires non-empty source")
    encoded = source.encode("utf-8")
    if len(encoded) > MAX_SOURCE_BYTES:
        raise _invalid(f"custom source must be at most {MAX_SOURCE_BYTES} bytes")
    if "\x00" in source:
        raise _invalid("custom source must not contain NUL bytes")
    return source


def _normalize_limits(limits: Any, *, enforce_caps: bool = True) -> dict[str, int]:
    if enforce_caps:
        try:
            caps = resolved_limits()
        except PocError:
            raise
        defaults = dict(caps)
    else:
        caps = {
            "max_requests": HARD_MAX_REQUESTS,
            "timeout_s": HARD_MAX_TIMEOUT_S,
            "max_bytes": HARD_MAX_BYTES,
        }
        defaults = dict(caps)
    if limits is None:
        limits = {}
    if not isinstance(limits, Mapping):
        raise PocError("invalid_limit", "limits must be an object")
    unknown = set(limits) - set(LIMIT_KEYS)
    if unknown:
        raise PocError(
            "invalid_limit", f"unknown limit keys: {sorted(unknown)}", unknown=sorted(unknown)
        )
    normalized: dict[str, int] = {}
    for key in LIMIT_KEYS:
        value = limits.get(key, defaults[key])
        if not _is_int(value):
            raise PocError("invalid_limit", f"limits.{key} must be an integer")
        cap = caps[key]
        if value < 1 or value > cap:
            raise PocError(
                "invalid_limit",
                f"limits.{key} must be between 1 and {cap}: {value}",
                limit=key,
                value=value,
                cap=cap,
            )
        normalized[key] = value
    return normalized


def _validate_pattern(pattern: Any, index: int) -> str:
    if not isinstance(pattern, str) or not pattern:
        raise _invalid("assertion patterns must be non-empty strings", assertion=index)
    if len(pattern) > MAX_PATTERN_LENGTH:
        raise _invalid(
            f"assertion patterns must be at most {MAX_PATTERN_LENGTH} characters",
            assertion=index,
        )
    try:
        re.compile(pattern)
    except (re.error, OverflowError, RecursionError) as exc:
        raise _invalid(
            f"assertion pattern is not a valid regular expression: {exc}", assertion=index
        ) from exc
    return pattern


def _validate_header_name(header: Any, index: int) -> str:
    if not isinstance(header, str) or not header or len(header) > MAX_HEADER_NAME:
        raise _invalid("assertion header names must be short non-empty strings", assertion=index)
    if not _HEADER_NAME_RE.fullmatch(header):
        raise _invalid(f"invalid header name in assertion: {header!r}", assertion=index)
    return header


def _validate_callback_url(url: Any) -> str:
    if not isinstance(url, str) or not url.strip():
        raise _invalid("callback_received assertions require a listener URL")
    candidate = url.strip()
    if len(candidate) > MAX_TARGET_LENGTH or re.search(r"\s", candidate):
        raise _invalid("callback listener URL is not valid")
    try:
        parsed = urlsplit(candidate)
        parsed.port
    except ValueError as exc:
        raise _invalid(f"callback listener URL has an invalid port: {exc}") from exc
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
        raise _invalid("callback listener URL must be an http(s) URL with a hostname")
    if parsed.fragment:
        raise _invalid("callback listener URL must not contain a fragment")
    return candidate


def _add_request_index(
    raw: Mapping[str, Any], normalized: dict[str, Any], index: int
) -> None:
    if "request" not in raw:
        return
    value = raw.get("request")
    if not _is_int(value) or value < 0:
        raise _invalid("assertion request indexes must be non-negative integers", assertion=index)
    if value >= MAX_REQUESTS_PER_SPEC:
        raise _invalid(
            f"assertion request index must be below {MAX_REQUESTS_PER_SPEC}",
            assertion=index,
        )
    normalized["request"] = value


def _normalize_assertion(
    raw: Any, index: int, *, generate_token: bool
) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        raise _invalid("assertions must be objects", assertion=index)
    kind = raw.get("type")
    if not isinstance(kind, str) or kind not in ASSERTION_TYPES:
        raise _invalid(
            f"assertion type must be one of {sorted(ASSERTION_TYPES)}", assertion=index
        )
    unknown = set(raw) - ASSERTION_KEYS[kind]
    if unknown:
        raise _invalid(
            f"unknown assertion keys: {sorted(unknown)}", assertion=index, type=kind
        )
    normalized: dict[str, Any] = {"type": kind}
    if kind == "status_in":
        statuses = raw.get("statuses")
        if not isinstance(statuses, list) or not statuses or len(statuses) > 20:
            raise _invalid("status_in requires a non-empty statuses list", assertion=index)
        cleaned: list[int] = []
        for status in statuses:
            if not _is_int(status) or not 100 <= status <= 599:
                raise _invalid("status_in statuses must be HTTP status integers", assertion=index)
            cleaned.append(status)
        normalized["statuses"] = cleaned
        _add_request_index(raw, normalized, index)
        return normalized
    if kind == "body_regex":
        normalized["pattern"] = _validate_pattern(raw.get("pattern"), index)
        _add_request_index(raw, normalized, index)
        return normalized
    if kind == "header_regex":
        normalized["header"] = _validate_header_name(raw.get("header"), index)
        normalized["pattern"] = _validate_pattern(raw.get("pattern"), index)
        _add_request_index(raw, normalized, index)
        return normalized
    if kind == "latency_lt_ms":
        value = raw.get("ms")
        if (
            not _is_int(value)
            or value < 1
            or value > HARD_MAX_TIMEOUT_S * 1000
        ):
            raise _invalid(
                f"latency_lt_ms requires ms between 1 and {HARD_MAX_TIMEOUT_S * 1000}",
                assertion=index,
            )
        normalized["ms"] = value
        _add_request_index(raw, normalized, index)
        return normalized

    # callback_received
    normalized["url"] = _validate_callback_url(raw.get("url"))
    token = raw.get("token")
    if token is None:
        if not generate_token:
            raise _invalid("callback_received requires a token", assertion=index)
        token = "poc" + uuid.uuid4().hex
    if not isinstance(token, str) or not _CALLBACK_TOKEN_RE.fullmatch(token):
        raise _invalid(
            "callback tokens must be 8-64 characters from [A-Za-z0-9._-]", assertion=index
        )
    polls = raw.get("polls", 5)
    if not _is_int(polls) or not 1 <= polls <= MAX_CALLBACK_POLLS:
        raise _invalid(
            f"callback polls must be between 1 and {MAX_CALLBACK_POLLS}", assertion=index
        )
    interval = raw.get("interval_ms", 250)
    if (
        not _is_int(interval)
        or not MIN_CALLBACK_INTERVAL_MS <= interval <= MAX_CALLBACK_INTERVAL_MS
    ):
        raise _invalid(
            f"callback interval_ms must be between {MIN_CALLBACK_INTERVAL_MS} "
            f"and {MAX_CALLBACK_INTERVAL_MS}",
            assertion=index,
        )
    normalized["token"] = token
    normalized["polls"] = polls
    normalized["interval_ms"] = interval
    return normalized


def _normalize_assertions(
    technique: str,
    assertions: Any,
    limits: Mapping[str, int],
    *,
    generate_token: bool,
) -> list[dict[str, Any]]:
    if assertions is None:
        assertions = [dict(item) for item in DEFAULT_ASSERTIONS.get(technique, ())]
    if not isinstance(assertions, list):
        raise _invalid("assertions must be a list")
    if len(assertions) > MAX_ASSERTIONS:
        raise _invalid(f"at most {MAX_ASSERTIONS} assertions are allowed")
    normalized = [
        _normalize_assertion(raw, index, generate_token=generate_token)
        for index, raw in enumerate(assertions)
    ]
    kinds = [assertion["type"] for assertion in normalized]
    if technique == CUSTOM_TECHNIQUE:
        return normalized
    if technique == "tcp_probe":
        disallowed = [
            kind for kind in kinds if kind not in {"body_regex", "latency_lt_ms"}
        ]
        if disallowed:
            raise _invalid(
                f"tcp_probe only supports body_regex and latency_lt_ms assertions: {disallowed}"
            )
    elif technique == "oob_callback":
        if kinds.count("callback_received") != 1:
            raise _invalid(
                "oob_callback requires exactly one callback_received assertion with the "
                "operator-supplied in-scope listener URL"
            )
    elif "callback_received" in kinds:
        raise _invalid(
            "callback_received assertions are only allowed for the oob_callback technique"
        )
    if technique == "file_read_canary" and "body_regex" not in kinds:
        raise _invalid(
            "file_read_canary requires a body_regex assertion holding the canary marker"
        )
    if not normalized and technique != "http_auth_diff":
        raise _invalid(f"{technique} requires at least one assertion")
    return normalized


def _normalize_headers(headers: Any, index: int) -> dict[str, str]:
    if headers is None:
        return {}
    if not isinstance(headers, Mapping):
        raise _invalid("request headers must be an object", request=index)
    if len(headers) > MAX_HEADERS:
        raise _invalid(f"at most {MAX_HEADERS} request headers are allowed", request=index)
    normalized: dict[str, str] = {}
    for name, value in headers.items():
        if not isinstance(name, str) or not name or len(name) > MAX_HEADER_NAME:
            raise _invalid("request header names must be short non-empty strings", request=index)
        if not _HEADER_NAME_RE.fullmatch(name):
            raise _invalid(f"invalid request header name: {name!r}", request=index)
        if not isinstance(value, str):
            raise _invalid("request header values must be strings", request=index)
        if len(value) > MAX_HEADER_VALUE or any(
            character in value for character in ("\x00", "\r", "\n")
        ):
            raise _invalid("request header values must be single-line strings", request=index)
        normalized[name] = value
    return normalized


def _normalize_requests(
    technique: str,
    requests: Any,
    limits: Mapping[str, int],
    *,
    enforce_counts: bool = True,
) -> list[dict[str, Any]]:
    if requests is None:
        requests = [dict(item) for item in DEFAULT_REQUESTS.get(technique, ())]
    if not isinstance(requests, list):
        raise _invalid("requests must be a list")
    normalized: list[dict[str, Any]] = []
    for index, raw in enumerate(requests):
        if not isinstance(raw, Mapping):
            raise _invalid("requests must be objects", request=index)
        unknown = set(raw) - REQUEST_KEYS
        if unknown:
            raise _invalid(f"unknown request keys: {sorted(unknown)}", request=index)
        method = raw.get("method")
        if not isinstance(method, str) or not method.strip():
            raise _invalid("request method must be a non-empty string", request=index)
        method = method.strip().upper()
        if method not in ALLOWED_METHODS:
            raise _invalid(
                f"request method must be one of {sorted(ALLOWED_METHODS)}", request=index
            )
        path = raw.get("path")
        if not isinstance(path, str) or not path.startswith("/"):
            raise _invalid("request path must start with '/'", request=index)
        if len(path) > MAX_PATH_LENGTH or re.search(r"[\s\x00]", path):
            raise _invalid("request path is not valid", request=index)
        headers = _normalize_headers(raw.get("headers"), index)
        body = raw.get("body", "")
        if body is None:
            body = ""
        if not isinstance(body, str):
            raise _invalid("request body must be a string", request=index)
        if len(body.encode("utf-8")) > MAX_BODY_BYTES:
            raise _invalid(
                f"request body must be at most {MAX_BODY_BYTES} bytes", request=index
            )
        if "\x00" in body:
            raise _invalid("request body must not contain NUL bytes", request=index)
        normalized.append(
            {"method": method, "path": path, "headers": headers, "body": body}
        )
    if enforce_counts:
        count = len(normalized)
        if count > limits["max_requests"]:
            raise PocError(
                "invalid_limit",
                f"the spec declares {count} requests but limits.max_requests is "
                f"{limits['max_requests']}",
                requests=count,
                max_requests=limits["max_requests"],
            )
        if technique == "tcp_probe":
            if count:
                raise _invalid("tcp_probe does not accept HTTP requests")
        elif technique == CUSTOM_TECHNIQUE:
            if count:
                raise _invalid("the custom technique does not accept structured requests")
        elif technique == "version_assert":
            if count != 1:
                raise _invalid("version_assert requires exactly one request")
        elif technique == "http_auth_diff":
            if count != 2:
                raise _invalid(
                    "http_auth_diff requires exactly two requests: the unauthenticated "
                    "request followed by the request carrying the credential header"
                )
        elif count < 1:
            raise _invalid(f"{technique} requires at least one request")
    return normalized


def _parse_http_target(target: Any) -> str:
    if not isinstance(target, str) or not target.strip():
        raise _invalid("target must be a non-empty URL or host:port string")
    candidate = target.strip()
    if len(candidate) > MAX_TARGET_LENGTH or re.search(r"\s", candidate):
        raise _invalid("target is not valid")
    try:
        parsed = urlsplit(candidate)
        parsed.port
    except ValueError as exc:
        raise _invalid(f"target has an invalid port: {exc}") from exc
    if parsed.scheme.lower() not in {"http", "https"}:
        raise _invalid("HTTP techniques require an http:// or https:// target URL")
    if not parsed.hostname:
        raise _invalid("target URL must include a hostname")
    if parsed.username or parsed.password:
        raise _invalid("target URLs must not embed credentials")
    if parsed.fragment:
        raise _invalid("target URLs must not contain a fragment")
    if parsed.query:
        raise _invalid("target URLs must not contain a query string")
    scheme = parsed.scheme.lower()
    path = parsed.path.rstrip("/")
    return f"{scheme}://{parsed.netloc.lower()}{path}"


def _parse_tcp_target(target: Any) -> str:
    if not isinstance(target, str) or not target.strip():
        raise _invalid("tcp_probe target must be host:port")
    candidate = target.strip()
    if candidate.lower().startswith("tcp://"):
        candidate = candidate[6:]
    if len(candidate) > 512 or re.search(r"[\s/?#]", candidate):
        raise _invalid("tcp_probe target must be host:port")
    if candidate.startswith("["):
        host, separator, port_text = candidate[1:].partition("]:")
        if not separator:
            raise _invalid("tcp_probe target must be host:port")
    else:
        host, separator, port_text = candidate.rpartition(":")
        if not separator:
            raise _invalid("tcp_probe target must be host:port")
    if not host or not port_text.isdigit():
        raise _invalid("tcp_probe target must be host:port")
    port = int(port_text)
    if not 1 <= port <= 65535:
        raise _invalid("tcp_probe target port must be between 1 and 65535")
    if ":" in host:
        return f"[{host}]:{port}"
    return f"{host}:{port}"


def _normalize_target(technique: str, target: Any) -> str:
    if technique == "tcp_probe":
        return _parse_tcp_target(target)
    if technique == CUSTOM_TECHNIQUE and "://" not in str(target):
        # A custom source may speak any protocol; its declared target is
        # metadata for scope and approval, so a bare host:port is accepted.
        return _parse_tcp_target(target)
    return _parse_http_target(target)


def _check_target_step(
    engagement_id: str, target: str, step: Mapping[str, Any]
) -> dict[str, Any]:
    check = policy.scope_check(engagement_id, target)
    if not check.get("allowed") or not check.get("host"):
        raise PocError(
            "scope_violation",
            f"target {target!r} is not inside the engagement scope",
            target=target,
            engagement_id=engagement_id,
        )
    asset = step.get("asset")
    if not isinstance(asset, str) or not asset.strip():
        raise PocError(
            "chain_invalid",
            "the chain step does not declare an asset",
            step_order=step.get("order"),
        )
    host = str(check["host"])
    if not policy.target_matches(host, asset):
        raise PocError(
            "scope_violation",
            f"target {target!r} does not belong to the chain step asset {asset!r}",
            target=target,
            asset=asset,
        )
    return check


def _resolve_chain_step(
    chain: Mapping[str, Any], step_order: Any, chain_id: str
) -> dict[str, Any]:
    if not _is_int(step_order) or step_order < 1:
        raise _invalid("step_order must be a positive 1-based integer")
    steps = chain.get("steps")
    if not isinstance(steps, list) or not steps:
        raise PocError("chain_invalid", f"chain {chain_id} has no steps")
    order_annotated = any(
        isinstance(step, Mapping) and _is_int(step.get("order")) for step in steps
    )
    for step in steps:
        if isinstance(step, Mapping) and step.get("order") == step_order:
            return dict(step)
    # Real chain records are ordered by satisfaction order, so step_order must
    # name a satisfied step there. Hand-made/simple chain dicts without order
    # annotations fall back to plain list position.
    if not order_annotated and step_order <= len(steps):
        step = steps[step_order - 1]
        if isinstance(step, Mapping):
            return dict(step)
    raise _invalid(
        f"step_order {step_order} is not a satisfied step in chain {chain_id}",
        step_order=step_order,
        chain_id=chain_id,
    )


# ---------------------------------------------------------------------------
# Lazy cross-module imports (written by other team modules in parallel)
# ---------------------------------------------------------------------------


def _load_chain(engagement_id: str, chain_id: str) -> dict[str, Any]:
    try:
        from .cve_chain import load_chain
    except Exception as exc:  # pragma: no cover - only when the module is absent
        raise PocError(
            "chain_unavailable",
            "the CVE chain module is not available in this build",
        ) from exc
    chain = load_chain(engagement_id, chain_id)
    if not isinstance(chain, Mapping):
        raise PocError("chain_invalid", "the chain module returned a malformed record")
    return dict(chain)


def _authorization_module() -> Any:
    try:
        from . import authorization
    except Exception as exc:  # pragma: no cover - only when the module is absent
        raise PocError(
            "authorization_unavailable",
            "the authorization module is not available in this build",
        ) from exc
    return authorization


def _approval_module() -> Any:
    try:
        from . import poc_approval
    except Exception as exc:  # pragma: no cover - only when the module is absent
        raise PocError(
            "approval_unavailable",
            "the PoC approval module is not available in this build",
        ) from exc
    return poc_approval


def _describe_authorization(engagement_id: str) -> dict[str, Any] | None:
    try:
        from . import authorization
    except Exception:
        return None
    try:
        description = authorization.describe_authorization(engagement_id)
    except Exception:
        return None
    return dict(description) if isinstance(description, Mapping) else None


def _custom_code_authorization_problem(engagement_id: str) -> dict[str, Any] | None:
    description = _describe_authorization(engagement_id)
    if description is None:
        return _finding(
            "custom_authorization_unavailable",
            "custom code needs a signed authorization record, but the authorization "
            "module could not report one; render and run are blocked for the custom tier",
        )
    valid = description.get("valid") is True
    custom_allowed = description.get("custom_code_allowed") is True
    techniques = description.get("allowed_techniques")
    technique_allowed = not (
        isinstance(techniques, list) and CUSTOM_TECHNIQUE not in techniques
    )
    if valid and custom_allowed and technique_allowed:
        return None
    return _finding(
        "custom_code_not_authorized",
        "the current authorization record does not allow custom code; sign a new "
        "authorization with the custom flag and a separate approval before running it",
        status=description.get("status"),
        custom_code_allowed=description.get("custom_code_allowed"),
    )


# ---------------------------------------------------------------------------
# Host extraction and forbidden-pattern scanning (lint)
# ---------------------------------------------------------------------------


def _spec_string_tokens(spec: Mapping[str, Any]) -> list[str]:
    tokens: list[str] = [str(spec.get("target") or "")]
    source = spec.get("source")
    if isinstance(source, str) and source:
        tokens.append(source)
    for request in spec.get("requests") or []:
        if not isinstance(request, Mapping):
            continue
        tokens.append(str(request.get("path") or ""))
        tokens.append(str(request.get("body") or ""))
        for value in (request.get("headers") or {}).values():
            tokens.append(str(value))
    for assertion in spec.get("assertions") or []:
        if not isinstance(assertion, Mapping):
            continue
        for key in ("pattern", "url", "header", "token"):
            value = assertion.get(key)
            if isinstance(value, str):
                tokens.append(value)
    return tokens


def _extract_hosts(spec: Mapping[str, Any]) -> list[dict[str, Any]]:
    engagement_id = str(spec["engagement_id"])
    candidates: list[str] = []
    seen: set[str] = set()

    def add(value: str) -> None:
        if value and value not in seen:
            seen.add(value)
            candidates.append(value)

    for token in _spec_string_tokens(spec):
        for candidate in policy.extract_candidates([token]):
            add(candidate)
        for match in _ABSOLUTE_URL_RE.findall(token):
            add(match)
        for match in _URL_HOST_PORT_RE.findall(token):
            add(match)

    hosts: list[dict[str, Any]] = []
    seen_hosts: set[str] = set()
    for candidate in candidates:
        check = policy.scope_check(engagement_id, candidate)
        host = check.get("host") or candidate
        if host in seen_hosts:
            continue
        seen_hosts.add(host)
        hosts.append(
            {
                "host": host,
                "allowed": bool(check.get("allowed")),
                "matched_target": check.get("matched_target"),
            }
        )
    hosts.sort(key=lambda entry: str(entry["host"]))
    return hosts


def _forbidden_matches(source: str) -> list[tuple[str, str]]:
    matches: list[tuple[str, str]] = []
    for label, pattern in FORBIDDEN_PATTERNS:
        match = pattern.search(source)
        if match:
            snippet = source[max(0, match.start() - 20) : match.end() + 20]
            matches.append((label, snippet.replace("\n", " ")[:160]))
    return matches


def _has_unbounded_while_true(source: str) -> bool:
    lines = source.splitlines()
    for index, line in enumerate(lines):
        match = _WHILE_TRUE_RE.match(line)
        if not match:
            continue
        base_indent = len(match.group(1))
        bounded = False
        for body_line in lines[index + 1 :]:
            if not body_line.strip():
                continue
            indent = len(body_line) - len(body_line.lstrip())
            if indent <= base_indent:
                break
            if re.search(r"\b(break|return|raise)\b", body_line):
                bounded = True
                break
        if not bounded:
            return True
    return False


def _lint_spec(spec: Mapping[str, Any]) -> dict[str, Any]:
    engagement_id = str(spec["engagement_id"])
    technique = str(spec["technique"])
    blocking: list[dict[str, Any]] = []
    warnings: list[dict[str, Any]] = []

    if technique not in ALL_TECHNIQUES:
        blocking.append(
            _finding(
                "technique_not_allowed",
                f"technique {technique!r} is not one of {list(ALL_TECHNIQUES)}",
                technique=technique,
            )
        )

    limits = spec.get("limits") or {}
    try:
        caps = resolved_limits()
    except PocError as exc:
        caps = None
        blocking.append(_finding("limits_invalid", exc.message, reason=exc.reason))
    if caps is not None:
        for key, cap in caps.items():
            value = limits.get(key)
            if not _is_int(value) or value < 1 or value > cap:
                blocking.append(
                    _finding(
                        "limits_exceeded",
                        f"limits.{key}={value!r} exceeds the current cap {cap}",
                        limit=key,
                        value=value,
                        cap=cap,
                    )
                )
    request_count = len(spec.get("requests") or [])
    stored_max_requests = limits.get("max_requests")
    if _is_int(stored_max_requests) and request_count > stored_max_requests:
        blocking.append(
            _finding(
                "request_count_exceeded",
                f"the spec declares {request_count} requests but limits.max_requests "
                f"is {stored_max_requests}",
                requests=request_count,
                max_requests=stored_max_requests,
            )
        )
    if request_count > HARD_MAX_REQUESTS:
        blocking.append(
            _finding(
                "request_count_exceeded",
                f"the spec declares {request_count} requests but the hard cap is "
                f"{HARD_MAX_REQUESTS}",
                requests=request_count,
                max_requests=HARD_MAX_REQUESTS,
            )
        )

    try:
        hosts = _extract_hosts(spec)
        target_check = policy.scope_check(engagement_id, str(spec.get("target") or ""))
    except PocError:
        raise
    except ValueError as exc:
        hosts = []
        target_check = {"host": None, "allowed": False}
        blocking.append(_finding("host_extraction_failed", str(exc)))
    if not target_check.get("host") or not target_check.get("allowed"):
        blocking.append(
            _finding(
                "out_of_scope_host",
                "the spec target did not yield an in-scope hostname",
                target=spec.get("target"),
            )
        )
    for entry in hosts:
        if not entry.get("allowed"):
            blocking.append(
                _finding(
                    "out_of_scope_host",
                    f"host {entry.get('host')!r} is not inside the engagement scope",
                    host=entry.get("host"),
                    candidate=entry.get("host"),
                )
            )

    source = spec.get("source") if technique == CUSTOM_TECHNIQUE else ""
    if isinstance(source, str) and source:
        for label, snippet in _forbidden_matches(source):
            blocking.append(
                _finding(
                    "forbidden_pattern",
                    f"forbidden pattern in custom source: {label}",
                    pattern=label,
                    match=snippet,
                )
            )
        if _has_unbounded_while_true(source):
            blocking.append(
                _finding(
                    "forbidden_pattern",
                    "custom source contains an unbounded 'while True' loop",
                    pattern="unbounded while True",
                )
            )

    if technique == CUSTOM_TECHNIQUE:
        warnings.append(
            _finding(
                "custom_code_requires_separate_approval",
                "custom code always requires a separate, signed PoC approval and a "
                "signed authorization record with the custom flag",
            )
        )
        problem = _custom_code_authorization_problem(engagement_id)
        if problem is not None:
            blocking.append(problem)
        if not spec.get("assertions"):
            warnings.append(
                _finding(
                    "custom_spec_has_no_assertions",
                    "the custom spec has no assertions, so run() cannot verify it "
                    "server-side and will report not_verified",
                )
            )

    if technique == "oob_callback":
        callbacks = [
            assertion
            for assertion in spec.get("assertions") or []
            if isinstance(assertion, Mapping)
            and assertion.get("type") == "callback_received"
        ]
        if callbacks:
            budget_ms = int(callbacks[0].get("polls") or 0) * int(
                callbacks[0].get("interval_ms") or 0
            )
            timeout_s = limits.get("timeout_s")
            if _is_int(timeout_s) and budget_ms > timeout_s * 1000:
                warnings.append(
                    _finding(
                        "callback_polling_exceeds_timeout",
                        "callback polling budget exceeds limits.timeout_s; the probe "
                        "will stop polling when the timeout is reached",
                        budget_ms=budget_ms,
                        timeout_s=timeout_s,
                    )
                )

    passed = not blocking
    limitations = [
        "Lint is best-effort defense in depth, not a sandbox: a spec that passes can still be unsafe or "
        "wrong about the target.",
    ]
    if blocking:
        limitations.append(
            f"{len(blocking)} blocking finding(s) must be resolved before the spec can be rendered or run."
        )
    if not hosts:
        limitations.append(
            "No host could be resolved from the target, so the scope verdict covers no host."
        )
    return {
        "engagement_id": engagement_id,
        "spec_id": spec.get("spec_id"),
        "blocking": blocking,
        "warnings": warnings,
        "hosts": hosts,
        "passed": passed,
        "coverage": envelope.coverage("complete", examined=len(hosts), exhausted=True),
        "limitations": limitations,
    }


# ---------------------------------------------------------------------------
# Spec persistence
# ---------------------------------------------------------------------------


def _spec_digest(record: Mapping[str, Any]) -> str:
    payload = {key: value for key, value in record.items() if key != "spec_sha256"}
    return canonical_sha256(payload)


def _validate_stored_spec(
    record: Any, engagement_id: str, spec_id: str
) -> dict[str, Any]:
    if not isinstance(record, Mapping):
        raise PocError("spec_invalid", "the stored spec is not a JSON object")
    keys = set(record)
    missing = set(SPEC_RECORD_KEYS) - keys
    unknown = keys - set(SPEC_RECORD_KEYS)
    if missing or unknown:
        raise PocError(
            "spec_invalid",
            f"stored spec keys do not match the schema (missing={sorted(missing)}, "
            f"unknown={sorted(unknown)})",
            missing=sorted(missing),
            unknown=sorted(unknown),
        )
    if not _is_int(record["schema_version"]) or record["schema_version"] != SCHEMA_VERSION:
        raise PocError("spec_invalid", "unsupported stored spec schema_version")
    if record["spec_id"] != spec_id or record["engagement_id"] != engagement_id:
        raise PocError("spec_invalid", "stored spec identifiers do not match its location")
    try:
        validate_record_id("chain", record["chain_id"])
        normalize_cve_id(record["cve_id"])
    except PocError as exc:
        raise PocError("spec_invalid", f"stored spec identifiers are invalid: {exc.message}") from exc
    technique = record["technique"]
    if not isinstance(technique, str) or technique not in ALL_TECHNIQUES:
        raise PocError("spec_invalid", "stored spec technique is not recognized")
    _resolve_chain_step(
        {"steps": [{"order": record["step_order"]}]},
        record["step_order"],
        str(record["chain_id"]),
    )
    if _normalize_target(technique, record["target"]) != record["target"]:
        raise PocError("spec_invalid", "stored spec target is not normalized")
    limits = _normalize_limits(record["limits"], enforce_caps=False)
    if dict(record["limits"]) != limits:
        raise PocError("spec_invalid", "stored spec limits are not normalized")
    requests = _normalize_requests(technique, record["requests"], limits)
    if requests != record["requests"]:
        raise PocError("spec_invalid", "stored spec requests are not normalized")
    assertions = _normalize_assertions(
        technique, record["assertions"], limits, generate_token=False
    )
    if assertions != record["assertions"]:
        raise PocError("spec_invalid", "stored spec assertions are not normalized")
    if record["capture"] != CAPTURE_RECORD:
        raise PocError("spec_invalid", "stored spec capture settings are not recognized")
    if not isinstance(record["allow_insecure_tls"], bool):
        raise PocError("spec_invalid", "stored spec allow_insecure_tls must be a boolean")
    if not isinstance(record["source"], str):
        raise PocError("spec_invalid", "stored spec source must be a string")
    if not isinstance(record["notes"], str):
        raise PocError("spec_invalid", "stored spec notes must be a string")
    parse_utc(record["created_at"], "created_at")
    digest = record["spec_sha256"]
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise PocError("spec_invalid", "stored spec_sha256 is not a SHA-256 hex digest")
    if digest != _spec_digest(record):
        raise PocError("spec_invalid", "stored spec_sha256 does not match its contents")
    return dict(record)


def _safe_poc_dir(engagement_id: str, *parts: str) -> Path:
    return _engagement_path(engagement_id, *parts)


def _spec_contract(record: Mapping[str, Any]) -> dict[str, Any]:
    """Declare what a persisted spec does and does not establish."""
    limitations = [
        "This spec is declarative: it states a technique, bounded requests, and assertions but does not "
        "show that the vulnerability exists or that the target behaves as written.",
        "Nothing was rendered or executed, and the run gate still requires a signed authorization and a "
        "single-use approval.",
    ]
    if record.get("technique") == CUSTOM_TECHNIQUE:
        limitations.append(
            "The custom technique stores caller-supplied source verbatim; it runs unsandboxed as the "
            "agent after the separate custom-code approval tier."
        )
    return {"coverage": envelope.coverage("complete", exhausted=True), "limitations": limitations}


def create_spec(
    engagement_id: str,
    *,
    chain_id: str,
    step_order: int,
    technique: str,
    target: str,
    requests: Any = None,
    assertions: Any = None,
    limits: Any = None,
    source: str = "",
    notes: str = "",
    allow_insecure_tls: bool = False,
) -> dict[str, Any]:
    """Validate and persist one PoC spec for a chain step."""
    validate_record_id("chain", chain_id)
    if not isinstance(technique, str) or technique not in ALL_TECHNIQUES:
        raise _invalid(
            f"technique must be one of {list(ALL_TECHNIQUES)}: {technique!r}"
        )
    chain = _load_chain(engagement_id, chain_id)
    step = _resolve_chain_step(chain, step_order, chain_id)
    cve_id = normalize_cve_id(step.get("cve_id"))
    limits_normalized = _normalize_limits(limits)
    requests_normalized = _normalize_requests(technique, requests, limits_normalized)
    assertions_normalized = _normalize_assertions(
        technique,
        assertions,
        limits_normalized,
        generate_token=technique == "oob_callback",
    )
    target_normalized = _normalize_target(technique, target)
    _check_target_step(engagement_id, target_normalized, step)
    source_normalized = _normalize_source(technique, source)
    notes_normalized = _normalize_notes(notes)
    if not isinstance(allow_insecure_tls, bool):
        raise _invalid("allow_insecure_tls must be a boolean")

    spec_id = new_record_id(SPEC_PREFIX)
    record: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "spec_id": spec_id,
        "engagement_id": engagement_id,
        "chain_id": chain_id,
        "step_order": step_order,
        "cve_id": cve_id,
        "technique": technique,
        "target": target_normalized,
        "requests": requests_normalized,
        "assertions": assertions_normalized,
        "limits": limits_normalized,
        "capture": dict(CAPTURE_RECORD),
        "allow_insecure_tls": allow_insecure_tls,
        "source": source_normalized,
        "notes": notes_normalized,
        "created_at": iso_utc(utc_now()),
    }
    record["spec_sha256"] = _spec_digest(record)
    path = _safe_poc_dir(engagement_id, "specs", f"{spec_id}.json")
    _write_json(path, record)
    audit.safe_record(
        engagement_id,
        {
            "event": "poc.spec.created",
            "spec_id": spec_id,
            "chain_id": chain_id,
            "step_order": step_order,
            "cve_id": cve_id,
            "technique": technique,
            "target": target_normalized,
            "spec_sha256": record["spec_sha256"],
        },
    )
    return {**record, **_spec_contract(record)}


def load_spec(engagement_id: str, spec_id: str) -> dict[str, Any]:
    """Load and fully re-validate a stored spec, including its SHA-256."""
    validate_record_id(SPEC_PREFIX, spec_id)
    path = _safe_poc_dir(engagement_id, "specs", f"{spec_id}.json")
    if not path.is_file() or path.is_symlink():
        raise PocError("unknown_spec", f"unknown PoC spec: {spec_id}")
    try:
        record = _read_json(path)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise PocError("spec_invalid", f"cannot read the stored spec: {exc}") from exc
    validated = _validate_stored_spec(record, engagement_id, spec_id)
    return {**validated, **_spec_contract(validated)}


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def _callback_assertion(spec: Mapping[str, Any]) -> Mapping[str, Any]:
    callbacks = [
        assertion
        for assertion in spec.get("assertions") or []
        if isinstance(assertion, Mapping)
        and assertion.get("type") == "callback_received"
    ]
    if len(callbacks) != 1:
        raise _invalid("oob_callback requires exactly one callback_received assertion")
    return callbacks[0]


def _substitute_callback_token(
    requests: list[dict[str, Any]], token: str
) -> list[dict[str, Any]]:
    substituted: list[dict[str, Any]] = []
    for request in requests:
        headers = {
            name: value.replace(CALLBACK_TOKEN_PLACEHOLDER, token)
            for name, value in request["headers"].items()
        }
        substituted.append(
            {
                "method": request["method"],
                "path": request["path"].replace(CALLBACK_TOKEN_PLACEHOLDER, token),
                "headers": headers,
                "body": request["body"].replace(CALLBACK_TOKEN_PLACEHOLDER, token),
            }
        )
    return substituted


def _render_config(spec: Mapping[str, Any]) -> dict[str, Any]:
    technique = str(spec["technique"])
    requests = [dict(request) for request in spec["requests"]]
    technique_config: dict[str, Any] = {}
    if technique == "oob_callback":
        assertion = _callback_assertion(spec)
        token = str(assertion["token"])
        requests = _substitute_callback_token(requests, token)
        technique_config = {
            "token": token,
            "token_header": CALLBACK_TOKEN_HEADER,
            "callback_url": str(assertion["url"]),
            "polls": int(assertion["polls"]),
            "interval_ms": int(assertion["interval_ms"]),
        }
    elif technique == "file_read_canary":
        canary = next(
            (
                assertion["pattern"]
                for assertion in spec["assertions"]
                if assertion["type"] == "body_regex"
            ),
            "",
        )
        technique_config = {"canary": canary}
    return {
        "schema_version": SCHEMA_VERSION,
        "spec_id": spec["spec_id"],
        "technique": technique,
        "target": spec["target"],
        "requests": requests,
        "max_requests": int(spec["limits"]["max_requests"]),
        "timeout_s": int(spec["limits"]["timeout_s"]),
        "max_bytes": int(spec["limits"]["max_bytes"]),
        "allow_insecure_tls": bool(spec.get("allow_insecure_tls", False)),
        "technique_config": technique_config,
    }


def _code_bytes(spec: Mapping[str, Any]) -> bytes:
    technique = str(spec["technique"])
    if technique == CUSTOM_TECHNIQUE:
        source = spec.get("source") or ""
        if not isinstance(source, str) or not source.strip():
            raise PocError("invalid_source", "the custom technique requires non-empty source")
        try:
            compile(source, f"{spec['spec_id']}.py", "exec")
        except (SyntaxError, ValueError) as exc:
            raise PocError(
                "invalid_source", f"custom source does not compile: {exc}"
            ) from exc
        return source.encode("utf-8")
    config_json = canonical_json(_render_config(spec)).decode("utf-8")
    return _TEMPLATE.replace("@@CONFIG@@", repr(config_json), 1).encode("utf-8")


def _render_spec(spec: Mapping[str, Any]) -> dict[str, Any]:
    engagement_id = str(spec["engagement_id"])
    spec_id = str(spec["spec_id"])
    lint_result = _lint_spec(spec)
    if lint_result["blocking"]:
        raise PocError(
            "lint_failed",
            "the spec has blocking lint findings and cannot be rendered",
            blocking=lint_result["blocking"],
        )
    code = _code_bytes(spec)
    code_path = _safe_poc_dir(engagement_id, "code", f"{spec_id}.py")
    _atomic_write(code_path, code)
    code_sha256 = file_sha256(code_path)
    audit.safe_record(
        engagement_id,
        {
            "event": "poc.spec.rendered",
            "spec_id": spec_id,
            "technique": spec["technique"],
            "code_sha256": code_sha256,
            "bytes": len(code),
        },
    )
    return {
        "spec_id": spec_id,
        "engagement_id": engagement_id,
        "chain_id": spec["chain_id"],
        "technique": spec["technique"],
        "target": spec["target"],
        "code_path": str(code_path),
        "code_path_relative": f"{poc_schema.POC_DIRECTORY}/code/{spec_id}.py",
        "code_sha256": code_sha256,
        "spec_sha256": spec["spec_sha256"],
        "bytes": len(code),
        "warnings": lint_result["warnings"],
        "coverage": envelope.coverage("complete", exhausted=True),
        "limitations": [
            "Rendering proves only that bounded verifier code was written and hashed; it does not prove "
            "the spec is safe, the target reachable, or the vulnerability real.",
            "The returned code_sha256 is the digest a run approval must bind; a later rewrite changes it.",
        ],
    }


def render(engagement_id: str, spec_id: str) -> dict[str, Any]:
    """Deterministically render (or store, for custom) the spec's probe code."""
    spec = load_spec(engagement_id, spec_id)
    if spec["technique"] == CUSTOM_TECHNIQUE:
        problem = _custom_code_authorization_problem(engagement_id)
        if problem is not None:
            raise PocError(
                "lint_failed",
                "custom code cannot be rendered until a signed authorization allows it",
                blocking=[problem],
            )
    return _render_spec(spec)


def lint(engagement_id: str, spec_id: str) -> dict[str, Any]:
    """Validate the spec and report machine-readable blocking findings."""
    spec = load_spec(engagement_id, spec_id)
    return _lint_spec(spec)


# ---------------------------------------------------------------------------
# Server-side POC_RESULT parsing and assertion evaluation
# ---------------------------------------------------------------------------


def _server_scope_check(engagement_id: str, host: str) -> bool:
    try:
        return bool(policy.scope_check(engagement_id, host).get("allowed"))
    except (PocError, ValueError):
        return False


def _url_hostname(url: str) -> str | None:
    try:
        parsed = urlsplit(url)
    except ValueError:
        return None
    if parsed.scheme.lower() not in {"http", "https"}:
        return None
    return parsed.hostname


def _parse_poc_result(
    stdout: str, spec: Mapping[str, Any]
) -> tuple[dict[str, Any] | None, list[dict[str, Any]]]:
    lines = (stdout or "").splitlines()
    result_indexes = [
        index for index, line in enumerate(lines) if line.startswith("POC_RESULT ")
    ]
    if not result_indexes:
        return None, [
            {
                "type": "poc_result",
                "passed": False,
                "detail": "the probe did not print a POC_RESULT line",
            }
        ]
    if len(result_indexes) > 1:
        return None, [
            {
                "type": "poc_result",
                "passed": False,
                "detail": f"the probe printed {len(result_indexes)} POC_RESULT lines; "
                "exactly one is required",
            }
        ]
    result_index = result_indexes[0]
    last_non_empty = max(
        (index for index, line in enumerate(lines) if line.strip()), default=-1
    )
    if result_index != last_non_empty:
        return None, [
            {
                "type": "poc_result",
                "passed": False,
                "detail": "the POC_RESULT line must be the final non-empty output line",
            }
        ]
    raw_line = lines[result_index][len("POC_RESULT ") :]
    if len(raw_line.encode("utf-8")) > MAX_POC_RESULT_BYTES:
        return None, [
            {
                "type": "poc_result",
                "passed": False,
                "detail": f"the POC_RESULT payload exceeds {MAX_POC_RESULT_BYTES} bytes",
            }
        ]
    try:
        payload = json.loads(raw_line)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        return None, [
            {
                "type": "poc_result",
                "passed": False,
                "detail": f"the POC_RESULT line is not valid JSON: {exc}",
            }
        ]
    if not isinstance(payload, Mapping):
        return None, [
            {
                "type": "poc_result",
                "passed": False,
                "detail": "the POC_RESULT payload is not a JSON object",
            }
        ]
    if payload.get("schema_version") != SCHEMA_VERSION:
        return None, [
            {
                "type": "poc_result",
                "passed": False,
                "detail": "the POC_RESULT payload has an unsupported schema_version",
            }
        ]
    if payload.get("spec_id") != spec["spec_id"]:
        return None, [
            {
                "type": "poc_result",
                "passed": False,
                "detail": "the POC_RESULT payload does not belong to this spec",
            }
        ]
    if payload.get("technique") != spec["technique"]:
        return None, [
            {
                "type": "poc_result",
                "passed": False,
                "detail": "the POC_RESULT payload reports a different technique",
            }
        ]
    raw_requests = payload.get("requests")
    if not isinstance(raw_requests, list):
        return None, [
            {
                "type": "poc_result",
                "passed": False,
                "detail": "the POC_RESULT payload has no request observations",
            }
        ]
    max_requests = int(spec["limits"]["max_requests"])
    if len(raw_requests) > max_requests:
        return None, [
            {
                "type": "poc_result",
                "passed": False,
                "detail": "the POC_RESULT payload reports more requests than the "
                "declared request limit",
            }
        ]
    requests: list[dict[str, Any]] = []
    for raw_record in raw_requests:
        if not isinstance(raw_record, Mapping):
            continue
        headers_raw = raw_record.get("headers")
        headers: dict[str, str] = {}
        if isinstance(headers_raw, Mapping):
            for name, value in list(headers_raw.items())[:MAX_HEADERS]:
                headers[str(name)[:MAX_HEADER_NAME]] = str(value)[:MAX_HEADER_VALUE]
        latency = raw_record.get("latency_ms")
        if not isinstance(latency, (int, float)) or isinstance(latency, bool):
            latency = 0.0
        requests.append(
            {
                "index": raw_record.get("index")
                if _is_int(raw_record.get("index"))
                else len(requests),
                "method": str(raw_record.get("method") or "")[:16],
                "url": str(raw_record.get("url") or "")[:MAX_TARGET_LENGTH],
                "status": raw_record.get("status")
                if _is_int(raw_record.get("status"))
                else None,
                "reason": str(raw_record.get("reason") or "")[:200],
                "headers": headers,
                "body_text": raw_record.get("body_text")
                if isinstance(raw_record.get("body_text"), str)
                else "",
                "body_bytes": raw_record.get("body_bytes")
                if _is_int(raw_record.get("body_bytes"))
                else 0,
                "body_sha256": str(raw_record.get("body_sha256") or "")[:64],
                "truncated": bool(raw_record.get("truncated")),
                "latency_ms": float(latency),
                "error": str(raw_record.get("error"))[:512]
                if raw_record.get("error")
                else None,
            }
        )
    callbacks: list[dict[str, Any]] = []
    raw_callbacks = payload.get("callbacks")
    if isinstance(raw_callbacks, list):
        for raw_callback in raw_callbacks[:MAX_CALLBACK_POLLS]:
            if not isinstance(raw_callback, Mapping):
                continue
            callbacks.append(
                {
                    "attempt": raw_callback.get("attempt")
                    if _is_int(raw_callback.get("attempt"))
                    else len(callbacks),
                    "url": str(raw_callback.get("url") or "")[:MAX_TARGET_LENGTH],
                    "status": raw_callback.get("status")
                    if _is_int(raw_callback.get("status"))
                    else None,
                    "matched": bool(raw_callback.get("matched")),
                    "body_text": raw_callback.get("body_text")
                    if isinstance(raw_callback.get("body_text"), str)
                    else "",
                    "error": str(raw_callback.get("error"))[:512]
                    if raw_callback.get("error")
                    else None,
                }
            )
    technique_data = payload.get("technique_data")
    normalized: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "spec_id": spec["spec_id"],
        "technique": spec["technique"],
        "target": str(payload.get("target") or "")[:MAX_TARGET_LENGTH],
        "transcript_path": str(payload.get("transcript_path") or "")[:256],
        "started_at": str(payload.get("started_at") or "")[:64],
        "completed_at": str(payload.get("completed_at") or "")[:64],
        "duration_ms": payload.get("duration_ms")
        if isinstance(payload.get("duration_ms"), (int, float))
        and not isinstance(payload.get("duration_ms"), bool)
        else 0.0,
        "requests": requests,
        "callbacks": callbacks,
        "technique_data": dict(technique_data)
        if isinstance(technique_data, Mapping)
        else {},
        "error": str(payload.get("error"))[:1000] if payload.get("error") else None,
        "truncated": bool(payload.get("truncated")),
    }
    return normalized, []


def _select_record(
    records: list[dict[str, Any]], assertion: Mapping[str, Any]
) -> tuple[dict[str, Any] | None, str]:
    if not records:
        return None, "the probe reported no request observations"
    if "request" in assertion:
        wanted = assertion["request"]
        for record in records:
            if record.get("index") == wanted:
                return record, ""
        if wanted < len(records):
            return records[wanted], ""
        return None, f"request index {wanted} was not observed"
    return records[-1], ""


def _assertion_result(
    kind: str, passed: bool, detail: str, **extra: Any
) -> dict[str, Any]:
    result = {"type": kind, "passed": bool(passed), "detail": detail}
    if extra:
        result["evidence"] = extra
    return result


def _evaluate_one_assertion(
    spec: Mapping[str, Any], payload: Mapping[str, Any], assertion: Mapping[str, Any]
) -> dict[str, Any]:
    kind = str(assertion["type"])
    records = list(payload.get("requests") or [])
    if kind == "status_in":
        record, error = _select_record(records, assertion)
        if record is None:
            return _assertion_result(kind, False, error)
        status = record.get("status")
        expected = ", ".join(str(item) for item in assertion["statuses"])
        if status is None:
            return _assertion_result(
                kind,
                False,
                f"request {record.get('index')} produced no HTTP status "
                f"({record.get('error') or 'unknown probe error'}); expected one of {expected}",
            )
        passed = status in assertion["statuses"]
        return _assertion_result(
            kind,
            passed,
            f"request {record.get('index')} returned status {status}; expected one of {expected}",
        )
    if kind == "body_regex":
        record, error = _select_record(records, assertion)
        if record is None:
            return _assertion_result(kind, False, error)
        pattern = assertion["pattern"]
        body = record.get("body_text") or ""
        try:
            matched = re.search(pattern, body) is not None
        except re.error:
            matched = False
        detail = (
            f"request {record.get('index')} body "
            f"{'matched' if matched else 'did not match'} pattern {pattern!r}"
        )
        if not matched and record.get("truncated"):
            detail += f" (the response was truncated to {len(body)} captured bytes)"
        return _assertion_result(kind, matched, detail)
    if kind == "header_regex":
        record, error = _select_record(records, assertion)
        if record is None:
            return _assertion_result(kind, False, error)
        wanted = str(assertion["header"]).lower()
        headers = record.get("headers") or {}
        value = next(
            (str(item) for name, item in headers.items() if str(name).lower() == wanted),
            None,
        )
        if value is None:
            return _assertion_result(
                kind,
                False,
                f"request {record.get('index')} response has no {assertion['header']!r} header",
            )
        pattern = assertion["pattern"]
        try:
            matched = re.search(pattern, value) is not None
        except re.error:
            matched = False
        return _assertion_result(
            kind,
            matched,
            f"header {assertion['header']!r} value {value[:120]!r} "
            f"{'matched' if matched else 'did not match'} pattern {pattern!r}",
        )
    if kind == "latency_lt_ms":
        threshold = int(assertion["ms"])
        if "request" in assertion:
            record, error = _select_record(records, assertion)
            if record is None:
                return _assertion_result(kind, False, error)
            selected = [record]
            scope_text = f"request {record.get('index')}"
        else:
            selected = records
            scope_text = "all requests"
        if not selected:
            return _assertion_result(kind, False, "the probe reported no request latencies")
        measured = max(float(record.get("latency_ms") or 0.0) for record in selected)
        passed = measured < threshold
        return _assertion_result(
            kind,
            passed,
            f"max latency for {scope_text} was {measured:.2f} ms; threshold {threshold} ms",
        )

    # callback_received
    callbacks = list(payload.get("callbacks") or [])
    url = assertion["url"]
    token = assertion["token"]
    matching = [entry for entry in callbacks if entry.get("url") == url]
    if not matching:
        return _assertion_result(
            kind,
            False,
            f"the probe reported no callback observations for {url}",
        )
    observed = [
        entry
        for entry in matching
        if entry.get("status") is not None
        and bool(token)
        and token in (entry.get("body_text") or "")
    ]
    passed = bool(observed)
    detail = (
        f"the callback listener {url} "
        f"{'returned the token' if passed else 'never returned the token'} "
        f"across {len(matching)} poll(s)"
    )
    return _assertion_result(kind, passed, detail)


def _evaluate_access_diff(payload: Mapping[str, Any]) -> dict[str, Any]:
    records = list(payload.get("requests") or [])
    if len(records) < 2:
        return _assertion_result(
            "access_diff",
            False,
            "http_auth_diff requires two observed requests (unauthenticated and authorized)",
        )
    first, second = records[0], records[1]
    status_differs = (
        first.get("status") is not None
        and second.get("status") is not None
        and first.get("status") != second.get("status")
    )
    body_differs = (
        bool(first.get("body_sha256"))
        and bool(second.get("body_sha256"))
        and first.get("body_sha256") != second.get("body_sha256")
    )
    passed = bool(status_differs or body_differs)
    detail = (
        f"unauthenticated status {first.get('status')}, authorized status "
        f"{second.get('status')}, body differs {body_differs}"
    )
    return _assertion_result("access_diff", passed, detail)


def _evaluate_assertions(
    spec: Mapping[str, Any], payload: Mapping[str, Any]
) -> list[dict[str, Any]]:
    engagement_id = str(spec["engagement_id"])
    findings: list[dict[str, Any]] = []
    observed_urls = [
        str(record.get("url") or "") for record in payload.get("requests") or []
    ]
    observed_urls.extend(
        str(callback.get("url") or "") for callback in payload.get("callbacks") or []
    )
    for url in observed_urls:
        host = _url_hostname(url)
        if host and not _server_scope_check(engagement_id, host):
            findings.append(
                _assertion_result(
                    "observation_scope",
                    False,
                    f"the probe reported an observation for out-of-scope host {host!r}",
                )
            )
    child_error = payload.get("error")
    findings.append(
        _assertion_result(
            "probe_error",
            not bool(child_error),
            f"the probe reported a transport error: {str(child_error)[:300]}"
            if child_error
            else "the probe reported no transport error",
        )
    )
    verifiable = len(spec["assertions"])
    for assertion in spec["assertions"]:
        findings.append(_evaluate_one_assertion(spec, payload, assertion))
    if spec["technique"] == "http_auth_diff":
        findings.append(_evaluate_access_diff(payload))
        verifiable += 1
    if verifiable == 0:
        findings.append(
            _assertion_result(
                "assertions",
                False,
                "no verifiable assertions were configured; a bare POC_RESULT line "
                "cannot verify anything",
            )
        )
    return findings


# ---------------------------------------------------------------------------
# Run pipeline
# ---------------------------------------------------------------------------


def _refused_result(
    exc: PocError,
    *,
    chain_id: str | None = None,
    spec_id: str | None = None,
    approval_id: str | None = None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "refused",
        "reason": exc.reason,
        "message": exc.message,
        "run_id": None,
        "chain_id": chain_id,
        "spec_id": spec_id,
        "approval_id": approval_id,
        "assertions": [],
        "evidence_path": None,
        "output_sha256": None,
        "duration_ms": None,
        "request_count": 0,
        "truncated": False,
    }
    for key, value in exc.details.items():
        if key not in result or result[key] is None:
            result[key] = value
    result.update(_run_contract(result))
    return result


def _record_refusal(
    engagement_id: str,
    exc: PocError,
    *,
    chain_id: str | None,
    spec_id: str | None,
    approval_id: str | None,
) -> None:
    audit.safe_record(
        engagement_id,
        {
            "event": "poc.run.refused",
            "chain_id": chain_id,
            "spec_id": spec_id,
            "approval_id": approval_id,
            "reason": exc.reason,
            "message": exc.message,
        },
    )


@contextlib.contextmanager
def _engagement_lock(engagement_id: str) -> Iterator[None]:
    path = _safe_poc_dir(engagement_id, ".lock")
    _ensure_directory(path.parent)
    descriptor = os.open(path, os.O_CREAT | os.O_RDWR, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise PocError(
                "run_in_progress",
                "another PoC run holds this engagement's run lock; wait for it to finish",
            ) from exc
        try:
            yield
        finally:
            with contextlib.suppress(OSError):
                fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def _transcript_request_count(entries: Iterable[Mapping[str, Any]]) -> int:
    return sum(
        1 for entry in entries if entry.get("phase") in {"request", "tcp"}
    )


def _transcript_summary_entry(entry: Mapping[str, Any]) -> dict[str, Any]:
    headers = entry.get("headers")
    raw_latency = entry.get("latency_ms")
    latency_ms = (
        float(raw_latency)
        if isinstance(raw_latency, (int, float)) and not isinstance(raw_latency, bool)
        else None
    )
    summary: dict[str, Any] = {
        "phase": str(entry.get("phase") or "")[:16],
        "index": entry.get("index") if _is_int(entry.get("index")) else None,
        "method": str(entry.get("method") or "")[:16],
        "url": str(entry.get("url") or "")[:MAX_TARGET_LENGTH],
        "status": entry.get("status") if _is_int(entry.get("status")) else None,
        "latency_ms": latency_ms,
        "body_bytes": entry.get("body_bytes")
        if _is_int(entry.get("body_bytes"))
        else None,
        "truncated": bool(entry.get("truncated")),
        "matched": bool(entry.get("matched")),
        "error": str(entry.get("error"))[:512] if entry.get("error") else None,
        "headers": redact_headers(headers) if isinstance(headers, Mapping) else {},
    }
    return summary


def _read_transcript(run_dir: Path) -> tuple[list[dict[str, Any]], str | None, bool]:
    path = run_dir / TRANSCRIPT_FILENAME
    if not path.is_file() or path.is_symlink():
        return [], None, False
    try:
        digest = file_sha256(path)
        raw = path.read_bytes()
    except OSError:
        return [], None, False
    truncated = len(raw) > MAX_TRANSCRIPT_BYTES
    if truncated:
        raw = raw[:MAX_TRANSCRIPT_BYTES]
    entries: list[dict[str, Any]] = []
    text = raw.decode("utf-8", errors="replace")
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        if len(entries) >= MAX_TRANSCRIPT_ENTRIES:
            truncated = True
            break
        try:
            entry = json.loads(stripped)
        except json.JSONDecodeError:
            truncated = True
            continue
        if not isinstance(entry, Mapping):
            continue
        entries.append(_transcript_summary_entry(entry))
    return entries, digest, truncated


async def _run_impl(
    engagement_id: str,
    *,
    chain_id: str,
    spec_id: str,
    approval_id: str,
) -> dict[str, Any]:
    spec = load_spec(engagement_id, spec_id)
    if spec["chain_id"] != chain_id:
        raise PocError(
            "chain_mismatch",
            f"spec {spec_id} belongs to chain {spec['chain_id']}, not {chain_id}",
            spec_chain_id=spec["chain_id"],
        )
    chain = _load_chain(engagement_id, chain_id)
    verdict = chain.get("verdict")
    if verdict != "complete":
        raise PocError(
            "chain_incomplete",
            f"chain {chain_id} verdict is {verdict!r}; a PoC requires a complete chain",
            verdict=verdict,
        )
    step = _resolve_chain_step(chain, spec["step_order"], chain_id)
    _check_target_step(engagement_id, spec["target"], step)

    technique = str(spec["technique"])
    custom_code = technique == CUSTOM_TECHNIQUE
    authorization = _authorization_module()
    authorization.validate_for_run(
        engagement_id,
        targets=[spec["target"]],
        technique=technique,
        custom_code=custom_code,
    )

    code = _code_bytes(spec)
    code_sha256 = sha256_hex(code)
    approval = _approval_module()
    approval_arguments: dict[str, Any] = {
        "chain_id": chain_id, "spec_id": spec_id, "spec_sha256": spec["spec_sha256"],
        "code_sha256": code_sha256, "technique": technique, "targets": [spec["target"]],
        "custom_code": custom_code,
    }
    approval.verify_approval(engagement_id, approval_id, **approval_arguments)

    lint_result = _lint_spec(spec)
    if lint_result["blocking"]:
        raise PocError(
            "lint_failed",
            "the spec has blocking lint findings and was refused before execution",
            blocking=lint_result["blocking"],
        )
    hosts = sorted(
        {
            str(entry["host"])
            for entry in lint_result["hosts"]
            if entry.get("host") and entry.get("allowed")
        }
    )
    if not hosts:
        raise PocError(
            "scope_violation",
            "the spec did not yield any in-scope host for the execution preflight",
        )
    for host in hosts:
        check = policy.scope_check(engagement_id, host)
        if not check.get("allowed"):
            raise PocError(
                "scope_violation",
                f"host {host!r} is not inside the engagement scope",
                host=host,
            )

    with _engagement_lock(engagement_id):
        run_id = new_record_id(RUN_PREFIX)
        run_dir = _safe_poc_dir(engagement_id, "runs", run_id)
        _ensure_directory(run_dir)
        started_at = iso_utc(utc_now())
        audit.safe_record(
            engagement_id,
            {
                "event": "poc.run.started",
                "run_id": run_id,
                "chain_id": chain_id,
                "spec_id": spec_id,
                "approval_id": approval_id,
                "technique": technique,
                "target": spec["target"],
                "limits": dict(spec["limits"]),
            },
        )
        code_path = _safe_poc_dir(engagement_id, "code", f"{spec_id}.py")
        _atomic_write(code_path, code)
        if file_sha256(code_path) != code_sha256:
            raise PocError(
                "artifact_hash_mismatch",
                "the rendered code changed between approval verification and execution",
                code_sha256=code_sha256,
            )
        # Reserve durably before handing control to the executor. Cancellation,
        # process death and output/evidence failures must never enable replay.
        authorization.validate_for_run(
            engagement_id, targets=[spec["target"]], technique=technique,
            custom_code=custom_code,
        )
        approval.consume_approval(engagement_id, approval_id, **approval_arguments)
        pending_result = {
            "schema_version": SCHEMA_VERSION, "status": "running", "run_id": run_id,
            "chain_id": chain_id, "spec_id": spec_id, "approval_id": approval_id,
            "technique": technique, "target": spec["target"], "started_at": started_at,
            "approval_consumed": True, "spec_sha256": spec["spec_sha256"],
            "code_sha256": code_sha256, "request_count": 0, "assertions": [],
        }
        try:
            _write_json(run_dir / "result.json", pending_result)
        except OSError as exc:
            raise PocError(
                "run_failed", f"cannot persist the reserved run before launch: {exc}",
                run_id=run_id, approval_consumed=True, execution_started=False,
            ) from exc
        started_monotonic = time.monotonic()
        exec_result: dict[str, Any] | None = None
        exec_error: str | None = None
        timed_out = False
        timeout_s = float(spec["limits"]["timeout_s"])
        try:
            exec_result = await asyncio.wait_for(
                executor.execute_tool(
                    "python3",
                    [str(code_path)],
                    engagement_id,
                    working_directory=f"{poc_schema.POC_DIRECTORY}/runs/{run_id}",
                    environment={"PYTHONPATH": ""},
                    preflight={"candidates": hosts},
                ),
                timeout=timeout_s,
            )
        except asyncio.TimeoutError:
            timed_out = True
        except asyncio.CancelledError:
            pending_result.update(status="cancelled", completed_at=iso_utc(utc_now()))
            with contextlib.suppress(OSError):
                _write_json(run_dir / "result.json", pending_result)
            audit.safe_record(engagement_id, {
                "event": "poc.run.cancelled", "run_id": run_id,
                "approval_id": approval_id, "approval_consumed": True,
            })
            raise
        except Exception as exc:  # the runner refused or crashed before execution
            exec_error = f"{type(exc).__name__}: {exc}"
        duration_ms = round((time.monotonic() - started_monotonic) * 1000.0, 2)
        completed_at = iso_utc(utc_now())

        transcript_entries, transcript_sha256, transcript_truncated = _read_transcript(
            run_dir
        )
        stdout_text = str((exec_result or {}).get("stdout") or "")
        stderr_text = str((exec_result or {}).get("stderr") or "")
        output_sha256 = sha256_hex(stdout_text)
        executor_truncated = bool((exec_result or {}).get("truncated"))
        executor_stdout_bytes = (exec_result or {}).get("stdout_bytes")
        if isinstance(executor_stdout_bytes, bool) or not isinstance(executor_stdout_bytes, int):
            executor_stdout_bytes = None
        executor_max_output_bytes = (exec_result or {}).get("max_output_bytes")
        if isinstance(executor_max_output_bytes, bool) or not isinstance(executor_max_output_bytes, int):
            executor_max_output_bytes = None

        payload: dict[str, Any] | None = None
        findings: list[dict[str, Any]] = []
        status: str
        reason: str | None = None
        message: str | None = None
        returncode: int | None = None
        if exec_error is not None:
            status = "refused"
            reason = "execution_error"
            message = exec_error
        elif exec_result is not None and exec_result.get("available") is False:
            status = "refused"
            reason = "execution_unavailable"
            message = str(
                exec_result.get("error") or "the python3 runner is not available"
            )
        elif timed_out:
            status = "timeout"
            findings = [
                {
                    "type": "execution",
                    "passed": False,
                    "detail": f"the probe exceeded the {spec['limits']['timeout_s']}s timeout",
                }
            ]
        else:
            if exec_result is not None:
                returncode = exec_result.get("returncode")
            payload, parse_findings = _parse_poc_result(stdout_text, spec)
            findings = list(parse_findings)
            if payload is not None:
                findings.extend(_evaluate_assertions(spec, payload))
            all_passed = bool(findings) and all(
                bool(item.get("passed")) for item in findings
            )
            if payload is None or returncode != 0 or not all_passed:
                status = "not_verified"
                if returncode not in (None, 0):
                    message = f"the probe exited with status {returncode}"
            else:
                status = "verified"

        request_count = (
            len(payload["requests"])
            if payload is not None
            else _transcript_request_count(transcript_entries)
        )
        request_truncated = any(
            bool(record.get("truncated"))
            for record in (payload or {}).get("requests") or []
        )
        truncated = bool(
            transcript_truncated
            or request_truncated
            or (payload or {}).get("truncated")
            or executor_truncated
        )
        try:
            saved_stdout_bytes, stdout_truncated = _write_bounded_text(
                run_dir / "stdout.txt", stdout_text
            )
            saved_stderr_bytes, stderr_truncated = _write_bounded_text(
                run_dir / "stderr.txt", stderr_text
            )
        except OSError as exc:
            raise PocError(
                "run_failed", f"cannot retain probe output: {exc}",
                run_id=run_id, approval_consumed=True,
            ) from exc
        truncated = truncated or stdout_truncated or stderr_truncated
        assertions = [
            {
                "type": str(item.get("type") or "assertion"),
                "passed": bool(item.get("passed")),
                "detail": str(item.get("detail") or ""),
                **({"evidence": item["evidence"]} if "evidence" in item else {}),
            }
            for item in findings
        ]
        evidence_path = f"{poc_schema.POC_DIRECTORY}/runs/{run_id}/evidence.json"
        result: dict[str, Any] = {
            "status": status,
            "run_id": run_id,
            "chain_id": chain_id,
            "spec_id": spec_id,
            "approval_id": approval_id,
            "technique": technique,
            "target": spec["target"],
            "assertions": assertions,
            "evidence_path": evidence_path,
            "output_sha256": output_sha256,
            "duration_ms": duration_ms,
            "request_count": request_count,
            "truncated": truncated,
            "executor_truncated": executor_truncated,
            **({"executor_stdout_bytes": executor_stdout_bytes} if executor_stdout_bytes is not None else {}),
            **({"executor_max_output_bytes": executor_max_output_bytes} if executor_max_output_bytes is not None else {}),
            "started_at": started_at,
            "completed_at": completed_at,
            "timeout_s": spec["limits"]["timeout_s"],
            "max_bytes": spec["limits"]["max_bytes"],
        }
        if reason is not None:
            result["reason"] = reason
        if message is not None:
            result["message"] = message
        if returncode is not None:
            result["returncode"] = returncode

        result["approval_consumed"] = True

        evidence: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "run_id": run_id,
            "engagement_id": engagement_id,
            "chain_id": chain_id,
            "spec_id": spec_id,
            "approval_id": approval_id,
            "technique": technique,
            "target": spec["target"],
            "status": status,
            "reason": reason,
            "message": message,
            "started_at": started_at,
            "completed_at": completed_at,
            "duration_ms": duration_ms,
            "timeout_s": spec["limits"]["timeout_s"],
            "timed_out": timed_out,
            "returncode": returncode,
            "output_sha256": output_sha256,
            "stdout_bytes": (
                executor_stdout_bytes
                if executor_stdout_bytes is not None
                else len(stdout_text.encode("utf-8", errors="replace"))
            ),
            "stderr_bytes": len(stderr_text.encode("utf-8", errors="replace")),
            "executor_truncated": executor_truncated,
            "executor_max_output_bytes": executor_max_output_bytes,
            "allow_insecure_tls": bool(spec.get("allow_insecure_tls", False)),
            "stdout_saved_bytes": saved_stdout_bytes,
            "stderr_saved_bytes": saved_stderr_bytes,
            "stdout_truncated": stdout_truncated,
            "stderr_truncated": stderr_truncated,
            "request_count": request_count,
            "truncated": truncated,
            "transcript_path": (
                f"{poc_schema.POC_DIRECTORY}/runs/{run_id}/{TRANSCRIPT_FILENAME}"
                if transcript_sha256 is not None
                else None
            ),
            "transcript_sha256": transcript_sha256,
            "transcript_entries": transcript_entries,
            "assertions_total": len(assertions),
            "assertions_passed": sum(1 for item in assertions if item["passed"]),
            "assertions": assertions,
            "spec_sha256": spec["spec_sha256"],
            "code_sha256": code_sha256,
            "limits": dict(spec["limits"]),
            "hosts": lint_result["hosts"],
        }
        if reason is not None:
            evidence["refusal_reason"] = reason
        stored_result = dict(result)
        stored_result["spec_sha256"] = spec["spec_sha256"]
        stored_result["code_sha256"] = code_sha256
        stored_result["payload"] = payload
        try:
            _write_json(run_dir / "evidence.json", evidence)
            _write_json(run_dir / "result.json", stored_result)
        except OSError as exc:
            raise PocError(
                "run_failed", f"cannot retain probe evidence: {exc}",
                run_id=run_id, approval_consumed=True,
            ) from exc

        if status == "refused":
            audit.safe_record(
                engagement_id,
                {
                    "event": "poc.run.refused",
                    "run_id": run_id,
                    "chain_id": chain_id,
                    "spec_id": spec_id,
                    "approval_id": approval_id,
                    "reason": reason,
                    "message": message,
                },
            )
        else:
            audit.safe_record(
                engagement_id,
                {
                    "event": "poc.run.completed",
                    "run_id": run_id,
                    "chain_id": chain_id,
                    "spec_id": spec_id,
                    "approval_id": approval_id,
                    "technique": technique,
                    "target": spec["target"],
                    "status": status,
                    "assertions_total": len(assertions),
                    "assertions_passed": sum(
                        1 for item in assertions if item["passed"]
                    ),
                    "duration_ms": duration_ms,
                    "request_count": request_count,
                    "output_sha256": output_sha256,
                    "evidence_path": evidence_path,
                },
            )
        result.update(_run_contract(result))
        return result


async def run(
    engagement_id: str,
    *,
    chain_id: str,
    spec_id: str,
    approval_id: str,
) -> dict[str, Any]:
    """Verify gates, execute the rendered probe, and evaluate it server-side.

    Refusals are returned as structured ``{"status": "refused", ...}`` records
    (and audited) rather than raised, mirroring the MCP tool convention.
    """
    try:
        validate_record_id("chain", chain_id)
        validate_record_id(APPROVAL_PREFIX, approval_id)
        return await _run_impl(
            engagement_id,
            chain_id=chain_id,
            spec_id=spec_id,
            approval_id=approval_id,
        )
    except PocError as exc:
        _record_refusal(
            engagement_id,
            exc,
            chain_id=chain_id,
            spec_id=spec_id,
            approval_id=approval_id,
        )
        return _refused_result(
            exc,
            chain_id=chain_id,
            spec_id=spec_id,
            approval_id=approval_id,
        )
    except OSError as exc:
        wrapped = PocError("run_failed", str(exc))
        _record_refusal(
            engagement_id,
            wrapped,
            chain_id=chain_id,
            spec_id=spec_id,
            approval_id=approval_id,
        )
        return _refused_result(
            wrapped,
            chain_id=chain_id,
            spec_id=spec_id,
            approval_id=approval_id,
        )


# ---------------------------------------------------------------------------
# Run listing
# ---------------------------------------------------------------------------


def _run_summary(record: Mapping[str, Any]) -> dict[str, Any]:
    assertions = record.get("assertions")
    total = record.get("assertions_total")
    passed = record.get("assertions_passed")
    if not _is_int(total) and isinstance(assertions, list):
        total = len(assertions)
    if not _is_int(passed) and isinstance(assertions, list):
        passed = sum(
            1
            for item in assertions
            if isinstance(item, Mapping) and item.get("passed")
        )
    return {
        "run_id": record.get("run_id"),
        "chain_id": record.get("chain_id"),
        "spec_id": record.get("spec_id"),
        "approval_id": record.get("approval_id"),
        "technique": record.get("technique"),
        "target": record.get("target"),
        "status": record.get("status"),
        "reason": record.get("reason"),
        "started_at": record.get("started_at"),
        "completed_at": record.get("completed_at"),
        "duration_ms": record.get("duration_ms"),
        "request_count": record.get("request_count"),
        "truncated": record.get("truncated"),
        "assertions_total": total or 0,
        "assertions_passed": passed or 0,
        "evidence_path": record.get("evidence_path"),
    }


def list_runs(engagement_id: str) -> dict[str, Any]:
    """List recorded PoC runs for an engagement, newest first."""
    root = _engagement_path(engagement_id, "runs")
    runs: list[dict[str, Any]] = []
    invalid: list[dict[str, Any]] = []
    if root.is_dir():
        for item in sorted(root.iterdir()):
            if not item.is_dir() or item.is_symlink():
                continue
            try:
                validate_record_id(RUN_PREFIX, item.name)
            except PocError:
                continue
            result_path = item / "result.json"
            if not result_path.is_file() or result_path.is_symlink():
                continue
            try:
                record = _read_json(result_path)
            except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
                invalid.append({"run_id": item.name, "error": str(exc)})
                continue
            if not isinstance(record, Mapping) or record.get("run_id") != item.name:
                invalid.append(
                    {"run_id": item.name, "error": "result.json is malformed"}
                )
                continue
            runs.append(_run_summary(record))
    runs.sort(key=lambda item: str(item.get("started_at") or ""), reverse=True)
    total = len(runs) + len(invalid)
    limitations: list[str] = []
    coverage = envelope.coverage("complete", examined=len(runs), total=total, exhausted=True)
    if invalid:
        coverage = envelope.coverage("partial", examined=len(runs), total=total, exhausted=False)
        limitations.append(
            f"{len(invalid)} run record(s) could not be read or verified; they are listed under invalid "
            "and are not evidence that those runs did not occur."
        )
    return {
        "engagement_id": engagement_id,
        "runs": runs,
        "invalid": invalid,
        "coverage": coverage,
        "limitations": limitations,
    }


def get_run(engagement_id: str, run_id: str) -> dict[str, Any]:
    """Return the recorded result for one run, including its evidence summary."""
    validate_record_id(RUN_PREFIX, run_id)
    result_path = _engagement_path(engagement_id, "runs", run_id, "result.json")
    if not result_path.is_file() or result_path.is_symlink():
        raise PocError("unknown_run", f"unknown PoC run: {run_id}")
    try:
        record = _read_json(result_path)
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise PocError("run_invalid", f"cannot read the recorded run: {exc}") from exc
    if not isinstance(record, Mapping) or record.get("run_id") != run_id:
        raise PocError("run_invalid", "the recorded run does not match its directory")
    stored = dict(record)
    stored.update(_run_contract(stored))
    return stored
