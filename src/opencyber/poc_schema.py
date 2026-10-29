"""Shared schema, limits, and canonical hashing for the PoC chain subsystem.

This module is the seam between the authorization, chain, PoC engine, and
operator CLI modules. It depends only on the standard library and the
engagement resolver so the other modules never import the MCP server.

Conventions used across the subsystem:

- Public MCP tools convert :class:`PocError` into a ``{"status": "refused",
  "reason": <code>, ...}`` result instead of raising, so an agent gets an
  actionable refusal rather than transport noise.
- Records are persisted as canonical JSON (sorted keys, no whitespace) and
  hashed with SHA-256. Signatures are HMAC-SHA256 over the canonical payload
  with ``OPENCYBER_APPROVAL_KEY`` (or ``OPENCYBER_APPROVAL_KEY_FILE``).
- The server never signs anything. Signing happens in the operator CLI only.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path, PurePosixPath
import re
from typing import Any, Iterable, Mapping
import uuid

from .engagements import resolve_engagement_path
from .errors import OcError


SCHEMA_VERSION = 1

POC_DIRECTORY = "poc"
AUTHORIZATION_FILENAME = "authorization.json"

CHAIN_PREFIX = "chain"
SPEC_PREFIX = "spec"
APPROVAL_PREFIX = "apr"
RUN_PREFIX = "run"

RECORD_ID_PATTERNS: dict[str, re.Pattern[str]] = {
    CHAIN_PREFIX: re.compile(r"chain_\d{8}_[0-9a-f]{32}"),
    SPEC_PREFIX: re.compile(r"spec_\d{8}_[0-9a-f]{32}"),
    APPROVAL_PREFIX: re.compile(r"apr_\d{8}_[0-9a-f]{32}"),
    RUN_PREFIX: re.compile(r"run_\d{8}_[0-9a-f]{32}"),
}

# Technique classes the engine can render without arbitrary code. ``custom`` is
# the opt-in tier that runs agent-authored Python after a separate approval.
ALLOWED_TECHNIQUES: tuple[str, ...] = (
    "version_assert",
    "http_sequence",
    "http_auth_diff",
    "oob_callback",
    "file_read_canary",
    "tcp_probe",
)
CUSTOM_TECHNIQUE = "custom"
ALL_TECHNIQUES: tuple[str, ...] = (*ALLOWED_TECHNIQUES, CUSTOM_TECHNIQUE)

# Hard ceilings. Environment variables may lower these but never raise them.
HARD_MAX_REQUESTS = 20
HARD_MAX_TIMEOUT_S = 60
HARD_MAX_BYTES = 1024 * 1024
DEFAULT_MAX_REQUESTS = 20
DEFAULT_TIMEOUT_S = 60
DEFAULT_MAX_BYTES = 1024 * 1024
APPROVAL_TTL_HOURS = 24
MIN_APPROVAL_KEY_BYTES = 32

APPROVAL_KEY_ENV = "OPENCYBER_APPROVAL_KEY"
APPROVAL_KEY_FILE_ENV = "OPENCYBER_APPROVAL_KEY_FILE"
MAX_REQUESTS_ENV = "OPENCYBER_POC_MAX_REQUESTS"
TIMEOUT_ENV = "OPENCYBER_POC_TIMEOUT"

CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")

_CAPABILITY_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"net:(?:tcp|udp|http):[1-9]\d{0,4}"),
    re.compile(r"net:internal:[1-9]\d{0,4}"),
    re.compile(r"auth:(?:none|user|admin)"),
    re.compile(r"exec:(?:container|host)"),
    re.compile(r"file:(?:read|write):[A-Za-z0-9._/*\-]+"),
    re.compile(r"creds:[A-Za-z0-9._\-]+"),
    re.compile(r"secret:read:[A-Za-z0-9._\-]+"),
    re.compile(r"info:[A-Za-z0-9._\-]+"),
    re.compile(r"position:(?:internet|adjacent|local)"),
)

_SECRET_HEADERS = frozenset(
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

# Child processes never need the approval key, and exposing it to ``oc_bash``
# or ``oc_python`` would expose it accidentally. Container root remains trusted.
SCRUBBED_ENVIRONMENT_PREFIXES = ("OPENCYBER_APPROVAL_KEY",)

REDACTED = "<redacted>"


# PoC reasons predate the shared error contract. Map them onto registered codes
# once, in the shared schema, so every refusal carries both the historical payload and the
# structured error block. Unknown reasons fail closed as invalid_argument.
_POC_ERROR_CODES: dict[str, str] = {
    "approval_invalid": "approval_invalid",
    "artifact_invalid": "invalid_argument",
    "authorization_expired": "authorization_invalid",
    "authorization_invalid": "authorization_invalid",
    "authorization_not_yet_valid": "authorization_invalid",
    "authorization_required": "authorization_required",
    "chain_invalid": "conflict",
    "invalid_capability": "invalid_argument",
    "invalid_chain_name": "invalid_argument",
    "invalid_cve": "invalid_argument",
    "invalid_expiry": "invalid_argument",
    "invalid_id": "invalid_argument",
    "invalid_limit": "invalid_argument",
    "invalid_request": "invalid_argument",
    "invalid_source": "invalid_argument",
    "invalid_spec": "invalid_argument",
    "invalid_step": "invalid_argument",
    "invalid_steps": "invalid_argument",
    "invalid_timestamp": "invalid_argument",
    "lint_failed": "invalid_argument",
    "execution_error": "execution_failed",
    "execution_unavailable": "capability_unavailable",
    "run_failed": "execution_failed",
    "run_invalid": "conflict",
    "scope_violation": "scope_denied",
    "spec_invalid": "invalid_argument",
    "technique_not_authorized": "authorization_invalid",
    "unknown_engagement": "engagement_not_found",
    "unknown_run": "not_found",
    "unknown_spec": "not_found",
}



class PocError(Exception):
    """A structured, user-facing refusal from the PoC chain subsystem."""

    def __init__(self, reason: str, message: str, **details: Any) -> None:
        super().__init__(message)
        self.reason = reason
        self.message = message
        self.details = details

    def to_error(self) -> OcError:
        return OcError(
            _POC_ERROR_CODES.get(self.reason, "invalid_argument"),
            self.message,
            details=dict(self.details),
        )

    def as_dict(self) -> dict[str, Any]:
        return {
            "status": "refused",
            "reason": self.reason,
            "message": self.message,
            **self.details,
        }


# ---------------------------------------------------------------------------
# Time and identifiers
# ---------------------------------------------------------------------------


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def parse_utc(value: Any, field: str = "timestamp") -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise PocError("invalid_timestamp", f"{field} must be an ISO-8601 timestamp")
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise PocError("invalid_timestamp", f"{field} is not ISO-8601: {value!r}") from exc
    if parsed.tzinfo is None:
        raise PocError("invalid_timestamp", f"{field} must include a timezone: {value!r}")
    return parsed.astimezone(timezone.utc)


def new_record_id(prefix: str) -> str:
    if prefix not in RECORD_ID_PATTERNS:
        raise ValueError(f"unknown record prefix: {prefix}")
    return f"{prefix}_{utc_now():%Y%m%d}_{uuid.uuid4().hex}"


def validate_record_id(prefix: str, value: Any) -> str:
    pattern = RECORD_ID_PATTERNS.get(prefix)
    if pattern is None:
        raise ValueError(f"unknown record prefix: {prefix}")
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise PocError(
            "invalid_id",
            f"{prefix}_id must look like {prefix}_YYYYMMDD_<32 lowercase hex>: {value!r}",
        )
    return value


def normalize_cve_id(value: Any) -> str:
    if not isinstance(value, str):
        raise PocError("invalid_cve", "cve_id must be a string such as CVE-2026-1234")
    normalized = value.strip().upper()
    if not CVE_PATTERN.fullmatch(normalized):
        raise PocError("invalid_cve", f"cve_id must look like CVE-2026-1234: {value!r}")
    return normalized


# ---------------------------------------------------------------------------
# Canonical JSON and hashing
# ---------------------------------------------------------------------------


def canonical_json(value: Any) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def canonical_sha256(value: Any) -> str:
    return sha256_hex(canonical_json(value))


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


# ---------------------------------------------------------------------------
# Approval key and signatures
# ---------------------------------------------------------------------------


def _key_id(key: bytes) -> str:
    return sha256_hex(key)[:16]


def resolve_approval_key() -> tuple[bytes, str]:
    """Return ``(key, key_id)`` or raise ``approval_key_unavailable``."""
    raw = os.environ.get(APPROVAL_KEY_ENV, "")
    if not raw.strip():
        file_name = os.environ.get(APPROVAL_KEY_FILE_ENV, "").strip()
        if file_name:
            try:
                raw = Path(file_name).read_text(encoding="utf-8").strip()
            except OSError as exc:
                raise PocError(
                    "approval_key_unavailable",
                    f"cannot read {APPROVAL_KEY_FILE_ENV}: {exc}",
                ) from exc
    if not raw.strip():
        raise PocError(
            "approval_key_unavailable",
            f"set {APPROVAL_KEY_ENV} (at least {MIN_APPROVAL_KEY_BYTES} bytes) or "
            f"{APPROVAL_KEY_FILE_ENV} to enable signed authorization and approvals",
        )
    key = raw.strip().encode("utf-8")
    if len(key) < MIN_APPROVAL_KEY_BYTES:
        raise PocError(
            "approval_key_unavailable",
            f"{APPROVAL_KEY_ENV} must be at least {MIN_APPROVAL_KEY_BYTES} bytes",
        )
    return key, _key_id(key)


def approval_key_available() -> bool:
    try:
        resolve_approval_key()
    except PocError:
        return False
    return True


def sign_payload(key: bytes, payload: Mapping[str, Any]) -> str:
    return hmac.new(key, canonical_json(payload), hashlib.sha256).hexdigest()


def verify_payload(key: bytes, payload: Mapping[str, Any], expected: Any) -> bool:
    if not isinstance(expected, str) or not expected:
        return False
    return hmac.compare_digest(sign_payload(key, payload), expected)


# ---------------------------------------------------------------------------
# Limits
# ---------------------------------------------------------------------------


def _env_int(name: str, default: int, minimum: int, maximum: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise PocError("invalid_limit", f"{name} must be an integer: {raw!r}") from exc
    if value < minimum or value > maximum:
        raise PocError(
            "invalid_limit", f"{name} must be between {minimum} and {maximum}: {value}"
        )
    return value


def resolved_limits() -> dict[str, int]:
    """Effective caps after environment overrides (which may only lower them)."""
    return {
        "max_requests": _env_int(
            MAX_REQUESTS_ENV, DEFAULT_MAX_REQUESTS, 1, HARD_MAX_REQUESTS
        ),
        "timeout_s": _env_int(TIMEOUT_ENV, DEFAULT_TIMEOUT_S, 1, HARD_MAX_TIMEOUT_S),
        "max_bytes": DEFAULT_MAX_BYTES,
    }


# ---------------------------------------------------------------------------
# Capability tokens and headers
# ---------------------------------------------------------------------------


def validate_capability(token: Any) -> str:
    if not isinstance(token, str) or not token.strip():
        raise PocError("invalid_capability", "capability tokens must be non-empty strings")
    normalized = token.strip()
    for pattern in _CAPABILITY_PATTERNS:
        if pattern.fullmatch(normalized):
            if normalized.split(":")[0] in {"net"}:
                port = normalized.rsplit(":", 1)[1]
                if int(port) > 65535:
                    break
            return normalized
    raise PocError(
        "invalid_capability",
        f"unknown capability token {token!r}; see docs/POC_CHAINS.md for the vocabulary",
    )


def normalize_capabilities(values: Iterable[Any]) -> list[str]:
    if isinstance(values, (str, bytes)):
        raise PocError("invalid_capability", "capabilities must be a list, not a string")
    return sorted({validate_capability(value) for value in values})


def redact_headers(headers: Mapping[str, Any] | None) -> dict[str, str]:
    redacted: dict[str, str] = {}
    for name, value in (headers or {}).items():
        key = str(name)
        redacted[key] = REDACTED if key.strip().lower() in _SECRET_HEADERS else str(value)
    return redacted


# ---------------------------------------------------------------------------
# Engagement-relative paths
# ---------------------------------------------------------------------------


def poc_root(engagement_id: str) -> Path:
    return resolve_engagement_path(engagement_id, POC_DIRECTORY, must_exist=False)


def poc_path(engagement_id: str, *parts: str) -> Path:
    relative = PurePosixPath(POC_DIRECTORY, *parts).as_posix()
    return resolve_engagement_path(engagement_id, relative, must_exist=False)


def server_managed_path(relative: str) -> bool:
    """True for paths the workspace tools must never write or delete.

    The whole ``poc/`` subtree is written by the PoC engine, the authorization
    loader, and the operator CLI. Letting an MCP client write there would let a
    model overwrite a signed record or its own evidence.
    """
    normalized = PurePosixPath(relative).as_posix().lstrip("./")
    if normalized in {"", "."}:
        return False
    if normalized == "engagement.json":
        return True
    return normalized == POC_DIRECTORY or normalized.startswith(POC_DIRECTORY + "/")
