"""One-shot, operator-signed approvals for CVE-chain PoC runs.

An approval binds one rendered PoC artifact (chain id, spec id, spec hash, and
code hash) to one technique, one target list, a random anti-replay nonce, and a
lifetime capped at :data:`opencyber.poc_schema.APPROVAL_TTL_HOURS`. The server
verifies approvals but never mints one: signing lives in the operator CLI
``opencyber-poc`` (implemented by :func:`main` below).

The approval file at ``<engagement>/poc/approvals/<approval_id>.json`` is
HMAC-signed over every field except ``hmac_sha256`` and ``used_at``. ``used_at``
is the single-use marker written by :func:`consume_approval`; it is deliberately
outside the signature because consumption happens in the verification process
without the signing key. Consumption and revocation are serialized with an
``fcntl`` lock on ``poc/approvals/.lock`` and persisted with atomic
temp-file-plus-:func:`os.replace` writes.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import timedelta
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
from typing import Any, Iterator
import uuid

from . import audit
from .authorization import describe_authorization, is_public_target, write_authorization
from .engagements import get_engagement
from .policy import target_matches
from .poc_schema import (
    ALL_TECHNIQUES,
    APPROVAL_PREFIX,
    APPROVAL_TTL_HOURS,
    CUSTOM_TECHNIQUE,
    PocError,
    SCHEMA_VERSION,
    file_sha256,
    iso_utc,
    new_record_id,
    parse_utc,
    poc_path,
    resolve_approval_key,
    sha256_hex,
    sign_payload,
    utc_now,
    validate_record_id,
    verify_payload,
)


APPROVAL_DIRECTORY = "approvals"
APPROVAL_LOCK_NAME = ".lock"
APPROVAL_SUFFIX = ".json"
MAX_APPROVAL_LIFETIME = timedelta(hours=APPROVAL_TTL_HOURS)

#: Approval fields covered by the HMAC. ``hmac_sha256`` and the mutable
#: single-use marker ``used_at`` are excluded.
APPROVAL_SIGNED_FIELDS: tuple[str, ...] = (
    "schema_version",
    "approval_id",
    "nonce",
    "engagement_id",
    "chain_id",
    "spec_id",
    "spec_sha256",
    "code_sha256",
    "technique",
    "targets",
    "custom_code",
    "issued_by",
    "issued_at",
    "expires_at",
    "ttl_hours",
    "key_id",
    "revoked",
    "revoked_at",
    "revoked_reason",
)

_ALLOWED_APPROVAL_FIELDS = frozenset(APPROVAL_SIGNED_FIELDS) | {
    "hmac_sha256",
    "used_at",
}
_HEX64 = re.compile(r"[0-9a-f]{64}")
_HEX32 = re.compile(r"[0-9a-f]{32}")
_TTL_TOLERANCE_HOURS = 1e-6


# ---------------------------------------------------------------------------
# Paths, atomic writes, and the approval lock
# ---------------------------------------------------------------------------


def _approval_file(engagement_id: str, approval_id: Any) -> Path:
    try:
        identifier = validate_record_id(APPROVAL_PREFIX, approval_id)
    except PocError as exc:
        raise PocError(
            "approval_invalid",
            f"invalid approval_id: {approval_id!r}",
            approval_id=approval_id,
        ) from exc
    try:
        return poc_path(
            engagement_id, APPROVAL_DIRECTORY, f"{identifier}{APPROVAL_SUFFIX}"
        )
    except ValueError as exc:
        raise PocError(
            "unknown_engagement",
            f"unknown engagement_id {engagement_id!r}: {exc}",
            engagement_id=engagement_id,
        ) from exc


def approval_path(engagement_id: str, approval_id: str) -> Path:
    """Return ``<engagement>/poc/approvals/<approval_id>.json`` without writing."""
    return _approval_file(engagement_id, approval_id)


def _approval_directory(engagement_id: str) -> Path:
    try:
        return poc_path(engagement_id, APPROVAL_DIRECTORY)
    except ValueError as exc:
        raise PocError(
            "unknown_engagement",
            f"unknown engagement_id {engagement_id!r}: {exc}",
            engagement_id=engagement_id,
        ) from exc


@contextmanager
def _approval_lock(engagement_id: str) -> Iterator[None]:
    lock_path = _approval_directory(engagement_id) / APPROVAL_LOCK_NAME
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        descriptor = os.open(
            lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600
        )
    except OSError as exc:
        raise PocError(
            "approval_invalid", f"cannot open approval lock: {exc}"
        ) from exc
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
    finally:
        os.close(descriptor)


def _atomic_write_bytes(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise


def _atomic_write_json(path: Path, record: dict[str, Any]) -> None:
    payload = (
        json.dumps(record, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode("utf-8")
    _atomic_write_bytes(path, payload)


def _read_regular_file(path: Path) -> bytes:
    if path.is_symlink():
        raise PocError(
            "approval_invalid", "approval file must not be a symlink"
        )
    try:
        info = path.lstat()
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise PocError("approval_invalid", f"cannot read approval file: {exc}") from exc
    if not stat.S_ISREG(info.st_mode):
        raise PocError("approval_invalid", "approval record must be a regular file")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise PocError("approval_invalid", f"cannot read approval file: {exc}") from exc


# ---------------------------------------------------------------------------
# Validation and signature helpers
# ---------------------------------------------------------------------------


def _invalid(message: str, **details: Any) -> PocError:
    return PocError("approval_invalid", message, **details)


def _non_empty_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise _invalid(f"approval field {field!r} must be a non-empty string")
    return value.strip()


def _hex_digest(value: Any, field: str) -> str:
    if not isinstance(value, str) or not _HEX64.fullmatch(value.strip().lower()):
        raise _invalid(
            f"approval field {field!r} must be a lowercase SHA-256 hex digest"
        )
    return value.strip().lower()


def _record_id(prefix: str, value: Any) -> str:
    try:
        return validate_record_id(prefix, value)
    except PocError as exc:
        raise _invalid(f"{prefix}_id is invalid: {value!r}") from exc


def _target_list(value: Any) -> list[str]:
    if not isinstance(value, (list, tuple)):
        raise _invalid("approval field 'targets' must be a list of strings")
    targets: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise _invalid("approval targets must be non-empty strings")
        if item.strip() not in targets:
            targets.append(item.strip())
    if not targets:
        raise _invalid("approval targets must not be empty")
    return targets


def _record_timestamp(record: dict[str, Any], field: str) -> Any:
    try:
        return parse_utc(record.get(field), field)
    except PocError as exc:
        raise _invalid(f"approval field {field!r} must be an ISO-8601 timestamp") from exc


def approval_signed_payload(record: dict[str, Any]) -> dict[str, Any]:
    """Return the exact field set covered by the approval's HMAC."""
    if not isinstance(record, dict):
        raise _invalid("approval record must be a JSON object")
    return {
        field: record[field]
        for field in APPROVAL_SIGNED_FIELDS
        if field in record
    }


def _derive_key_id(key: bytes) -> str:
    return hashlib.sha256(key).hexdigest()[:16]


def _verify_signature(record: dict[str, Any], key: bytes, key_id: str) -> None:
    if not isinstance(key, (bytes, bytearray)) or not key:
        raise _invalid("approval key must be non-empty bytes")
    key_bytes = bytes(key)
    if not isinstance(key_id, str) or key_id != _derive_key_id(key_bytes):
        raise _invalid("key_id does not match the supplied approval key")
    if record.get("key_id") != key_id:
        raise _invalid("approval was signed with a different approval key")
    if not verify_payload(
        key_bytes, approval_signed_payload(record), record.get("hmac_sha256")
    ):
        raise _invalid("approval signature does not match its contents")


def _validate_approval(
    record: Any,
    engagement_id: str,
    approval_id: str | None = None,
) -> None:
    if not isinstance(record, dict):
        raise _invalid("approval record must be a JSON object")
    unknown = sorted(set(record) - _ALLOWED_APPROVAL_FIELDS)
    if unknown:
        raise _invalid("approval record contains unknown field(s): " + ", ".join(unknown))
    if record.get("schema_version") != SCHEMA_VERSION:
        raise _invalid(
            f"unsupported approval schema_version: {record.get('schema_version')!r}"
        )
    if record.get("engagement_id") != engagement_id:
        raise _invalid("approval engagement_id does not match the request")
    record_approval_id = _record_id(APPROVAL_PREFIX, record.get("approval_id"))
    if approval_id is not None and record_approval_id != approval_id:
        raise _invalid("approval_id does not match its file name")
    nonce = record.get("nonce")
    if not isinstance(nonce, str) or not _HEX32.fullmatch(nonce):
        raise _invalid(
            "approval field 'nonce' must be a 32 character lowercase hex string"
        )
    _record_id("chain", record.get("chain_id"))
    _record_id("spec", record.get("spec_id"))
    _hex_digest(record.get("spec_sha256"), "spec_sha256")
    _hex_digest(record.get("code_sha256"), "code_sha256")
    technique = record.get("technique")
    if technique not in ALL_TECHNIQUES:
        raise _invalid(f"approval technique is not recognized: {technique!r}")
    _target_list(record.get("targets"))
    if type(record.get("custom_code")) is not bool:
        raise _invalid("approval field 'custom_code' must be a boolean")
    _non_empty_string(record.get("issued_by"), "issued_by")
    issued_at = _record_timestamp(record, "issued_at")
    expires_at = _record_timestamp(record, "expires_at")
    window = expires_at - issued_at
    if window <= timedelta(0):
        raise _invalid("approval expires_at must be after issued_at")
    if window > MAX_APPROVAL_LIFETIME:
        raise _invalid(
            f"approval lifetime exceeds the {APPROVAL_TTL_HOURS} hour ceiling"
        )
    ttl_hours = record.get("ttl_hours")
    if isinstance(ttl_hours, bool) or not isinstance(ttl_hours, (int, float)):
        raise _invalid("approval field 'ttl_hours' must be a number")
    ttl_hours = float(ttl_hours)
    if ttl_hours <= 0 or ttl_hours > APPROVAL_TTL_HOURS:
        raise _invalid(
            f"approval ttl_hours must be greater than 0 and at most "
            f"{APPROVAL_TTL_HOURS}"
        )
    if abs(window.total_seconds() / 3600 - ttl_hours) > _TTL_TOLERANCE_HOURS:
        raise _invalid("approval ttl_hours does not match issued_at/expires_at")
    key_id = record.get("key_id")
    if not isinstance(key_id, str) or not key_id.strip():
        raise _invalid("approval field 'key_id' must be a non-empty string")
    hmac_sha256 = record.get("hmac_sha256")
    if not isinstance(hmac_sha256, str) or not _HEX64.fullmatch(hmac_sha256):
        raise _invalid(
            "approval field 'hmac_sha256' must be a lowercase SHA-256 hex digest"
        )
    used_at = record.get("used_at")
    if used_at is not None:
        try:
            parse_utc(used_at, "used_at")
        except PocError as exc:
            raise _invalid("approval field 'used_at' must be null or a timestamp") from exc
    revoked = record.get("revoked")
    if type(revoked) is not bool:
        raise _invalid("approval field 'revoked' must be a boolean")
    if revoked:
        _record_timestamp(record, "revoked_at")
        reason = record.get("revoked_reason")
        if not isinstance(reason, str) or not reason.strip():
            raise _invalid(
                "revoked approvals require a non-empty 'revoked_reason'"
            )
    elif record.get("revoked_at") is not None or record.get("revoked_reason") is not None:
        raise _invalid(
            "approval has revocation metadata but 'revoked' is false"
        )


def approval_status_label(record: dict[str, Any]) -> str:
    """Return ``used``, ``revoked``, ``expired``, or ``unused`` for a record."""
    if record.get("used_at"):
        return "used"
    if record.get("revoked"):
        return "revoked"
    try:
        expires_at = parse_utc(record.get("expires_at"), "expires_at")
    except PocError:
        return "invalid"
    return "expired" if utc_now() >= expires_at else "unused"


def _summarize(record: dict[str, Any]) -> dict[str, Any]:
    return {
        "approval_id": record.get("approval_id"),
        "nonce": record.get("nonce"),
        "chain_id": record.get("chain_id"),
        "spec_id": record.get("spec_id"),
        "spec_sha256": record.get("spec_sha256"),
        "code_sha256": record.get("code_sha256"),
        "technique": record.get("technique"),
        "targets": list(record.get("targets") or []),
        "custom_code": bool(record.get("custom_code")),
        "issued_by": record.get("issued_by"),
        "issued_at": record.get("issued_at"),
        "expires_at": record.get("expires_at"),
        "used_at": record.get("used_at"),
        "revoked": bool(record.get("revoked")),
        "revoked_at": record.get("revoked_at"),
        "revoked_reason": record.get("revoked_reason"),
    }


# ---------------------------------------------------------------------------
# Load, verify, consume, create, and revoke
# ---------------------------------------------------------------------------


def _read_approval_file(path: Path, approval_id: str) -> dict[str, Any]:
    try:
        raw = _read_regular_file(path)
    except FileNotFoundError:
        raise PocError(
            "approval_invalid",
            f"unknown approval_id: {approval_id}",
            approval_id=approval_id,
        ) from None
    try:
        record = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _invalid(f"approval record is not valid JSON: {exc}") from exc
    if not isinstance(record, dict):
        raise _invalid("approval record must be a JSON object")
    return record


def _load_verified_approval(
    path: Path, engagement_id: str, approval_id: str
) -> dict[str, Any]:
    record = _read_approval_file(path, approval_id)
    _validate_approval(record, engagement_id, approval_id)
    key, key_id = resolve_approval_key()
    _verify_signature(record, key, key_id)
    return record


def load_approval(engagement_id: str, approval_id: str) -> dict[str, Any]:
    """Load and verify a signed approval; raise ``approval_invalid`` otherwise."""
    path = _approval_file(engagement_id, approval_id)
    return _load_verified_approval(path, engagement_id, approval_id)


def verify_approval(
    engagement_id: str,
    approval_id: str,
    *,
    chain_id: str,
    spec_id: str,
    spec_sha256: str,
    code_sha256: str,
    technique: str,
    targets: list[str],
    custom_code: bool = False,
) -> dict[str, Any]:
    """Verify that ``approval_id`` authorizes this exact run.

    Raises ``approval_consumed`` for a used approval, ``artifact_hash_mismatch``
    when the spec/code hashes changed, ``technique_not_authorized`` for a
    technique or custom-code tier the approval does not cover,
    ``scope_violation`` for an out-of-approval target, and ``approval_invalid``
    for an expired, revoked, or structurally invalid record.
    """
    record = load_approval(engagement_id, approval_id)
    if record.get("revoked"):
        raise PocError(
            "approval_invalid",
            "approval has been revoked",
            approval_id=approval_id,
            revoked_at=record.get("revoked_at"),
            revoked_reason=record.get("revoked_reason"),
        )
    if record.get("used_at"):
        raise PocError(
            "approval_consumed",
            f"approval was already consumed at {record.get('used_at')}",
            approval_id=approval_id,
            used_at=record.get("used_at"),
        )
    issued_at = _record_timestamp(record, "issued_at")
    expires_at = _record_timestamp(record, "expires_at")
    window = expires_at - issued_at
    if window <= timedelta(0) or window > MAX_APPROVAL_LIFETIME:
        raise _invalid(
            f"approval lifetime exceeds the {APPROVAL_TTL_HOURS} hour ceiling",
            approval_id=approval_id,
        )
    if utc_now() >= expires_at:
        raise PocError(
            "approval_invalid",
            f"approval expired at {record.get('expires_at')}",
            approval_id=approval_id,
            expires_at=record.get("expires_at"),
        )
    if record.get("chain_id") != chain_id:
        raise _invalid(
            "approval chain_id does not match the requested chain",
            approval_id=approval_id,
            expected=record.get("chain_id"),
            actual=chain_id,
        )
    if record.get("spec_id") != spec_id:
        raise _invalid(
            "approval spec_id does not match the requested spec",
            approval_id=approval_id,
            expected=record.get("spec_id"),
            actual=spec_id,
        )
    expected_spec_hash = _hex_digest(spec_sha256, "spec_sha256")
    if record.get("spec_sha256") != expected_spec_hash:
        raise PocError(
            "artifact_hash_mismatch",
            "approval was minted for different spec contents",
            approval_id=approval_id,
            recorded_sha256=record.get("spec_sha256"),
            actual_sha256=expected_spec_hash,
        )
    expected_code_hash = _hex_digest(code_sha256, "code_sha256")
    if record.get("code_sha256") != expected_code_hash:
        raise PocError(
            "artifact_hash_mismatch",
            "approval was minted for different rendered code",
            approval_id=approval_id,
            recorded_sha256=record.get("code_sha256"),
            actual_sha256=expected_code_hash,
        )
    if record.get("technique") != technique:
        raise PocError(
            "technique_not_authorized",
            "approval was minted for a different technique",
            approval_id=approval_id,
            expected=record.get("technique"),
            actual=technique,
        )
    if isinstance(targets, str):
        targets = [targets]
    if not isinstance(targets, (list, tuple)) or not targets:
        raise _invalid("at least one target is required to verify an approval")
    approved_targets = [str(value) for value in record.get("targets", [])]
    for target in targets:
        if not isinstance(target, str) or not target.strip():
            raise _invalid("approval targets must be non-empty strings")
        normalized = target.strip()
        if not any(
            target_matches(normalized, approved) for approved in approved_targets
        ):
            raise PocError(
                "scope_violation",
                f"target is outside the approved target list: {normalized}",
                target=normalized,
                approved_targets=approved_targets,
            )
    if bool(custom_code) and not record.get("custom_code"):
        raise PocError(
            "technique_not_authorized",
            "approval does not cover custom code execution",
            approval_id=approval_id,
        )
    return record


def consume_approval(
    engagement_id: str, approval_id: str, **run: Any
) -> dict[str, Any]:
    """Mark an approval used, atomically and at most once.

    Raises ``approval_consumed`` when another caller already consumed it.
    When run bindings are supplied, verify them again under the same lock as
    consumption so expiry, revocation and replacement cannot race reservation.
    Callers must consume before launching the probe, never after it completes.
    """
    path = _approval_file(engagement_id, approval_id)
    with _approval_lock(engagement_id):
        record = (
            verify_approval(engagement_id, approval_id, **run)
            if run else _load_verified_approval(path, engagement_id, approval_id)
        )
        if record.get("used_at"):
            raise PocError(
                "approval_consumed",
                f"approval was already consumed at {record.get('used_at')}",
                approval_id=approval_id,
                used_at=record.get("used_at"),
            )
        if record.get("revoked"):
            raise _invalid(
                "approval has been revoked",
                approval_id=approval_id,
                revoked_reason=record.get("revoked_reason"),
            )
        updated = dict(record)
        updated["used_at"] = iso_utc(utc_now())
        _atomic_write_json(path, updated)
        return updated


def create_approval(
    engagement_id: str,
    *,
    chain_id: str,
    spec_id: str,
    spec_sha256: str,
    code_sha256: str,
    technique: str,
    targets: list[str],
    custom_code: bool,
    issued_by: str,
    ttl_hours: float,
    key: bytes,
    key_id: str,
) -> dict[str, Any]:
    """Mint and atomically store a signed one-shot approval (operator CLI only)."""
    if not isinstance(key, (bytes, bytearray)) or not key:
        raise _invalid("approval key must be non-empty bytes")
    key_bytes = bytes(key)
    if not isinstance(key_id, str) or key_id != _derive_key_id(key_bytes):
        raise _invalid("key_id does not match the supplied approval key")
    try:
        get_engagement(engagement_id)
    except ValueError as exc:
        raise PocError(
            "unknown_engagement",
            f"unknown engagement_id {engagement_id!r}: {exc}",
            engagement_id=engagement_id,
        ) from exc
    normalized_technique = technique
    if normalized_technique not in ALL_TECHNIQUES:
        raise _invalid(f"unknown technique: {technique!r}")
    if type(custom_code) is not bool:
        raise _invalid("approval field 'custom_code' must be a boolean")
    if normalized_technique == CUSTOM_TECHNIQUE and not custom_code:
        raise _invalid("custom technique requires custom_code=true")
    if isinstance(ttl_hours, bool) or not isinstance(ttl_hours, (int, float)):
        raise _invalid("approval field 'ttl_hours' must be a number")
    normalized_ttl = float(ttl_hours)
    if normalized_ttl <= 0 or normalized_ttl > APPROVAL_TTL_HOURS:
        raise _invalid(
            f"approval ttl_hours must be greater than 0 and at most "
            f"{APPROVAL_TTL_HOURS}"
        )
    issued_at = utc_now()
    record: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "approval_id": new_record_id(APPROVAL_PREFIX),
        "nonce": uuid.uuid4().hex,
        "engagement_id": engagement_id,
        "chain_id": _record_id("chain", chain_id),
        "spec_id": _record_id("spec", spec_id),
        "spec_sha256": _hex_digest(spec_sha256, "spec_sha256"),
        "code_sha256": _hex_digest(code_sha256, "code_sha256"),
        "technique": normalized_technique,
        "targets": _target_list(targets),
        "custom_code": custom_code,
        "issued_by": _non_empty_string(issued_by, "issued_by"),
        "issued_at": iso_utc(issued_at),
        "expires_at": iso_utc(issued_at + timedelta(hours=normalized_ttl)),
        "ttl_hours": normalized_ttl,
        "key_id": key_id,
        "used_at": None,
        "revoked": False,
        "revoked_at": None,
        "revoked_reason": None,
    }
    record["hmac_sha256"] = sign_payload(
        key_bytes, approval_signed_payload(record)
    )
    path = _approval_file(engagement_id, record["approval_id"])
    _atomic_write_json(path, record)
    return record


def revoke_approval(
    engagement_id: str,
    approval_id: str,
    reason: str,
    key: bytes,
    key_id: str,
) -> dict[str, Any]:
    """Revoke an approval (idempotent) and persist the reason in its signed record."""
    if not isinstance(key, (bytes, bytearray)) or not key:
        raise _invalid("approval key must be non-empty bytes")
    key_bytes = bytes(key)
    if reason is None or (isinstance(reason, str) and not reason.strip()):
        reason_text = "revoked by operator"
    elif isinstance(reason, str):
        reason_text = reason.strip()
    else:
        raise _invalid("revocation reason must be a string")
    path = _approval_file(engagement_id, approval_id)
    with _approval_lock(engagement_id):
        record = _read_approval_file(path, approval_id)
        _validate_approval(record, engagement_id, approval_id)
        _verify_signature(record, key_bytes, key_id)
        if record.get("revoked"):
            return record
        updated = dict(record)
        updated["revoked"] = True
        updated["revoked_at"] = iso_utc(utc_now())
        updated["revoked_reason"] = reason_text
        updated["hmac_sha256"] = sign_payload(
            key_bytes, approval_signed_payload(updated)
        )
        _atomic_write_json(path, updated)
        return updated


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------


def _status_for_record(record: dict[str, Any]) -> str:
    return approval_status_label(record)


def approval_status(
    engagement_id: str, approval_id: str | None = None
) -> dict[str, Any]:
    """Summarize one approval or every approval stored for an engagement."""
    if approval_id is not None:
        try:
            record = load_approval(engagement_id, approval_id)
        except PocError as exc:
            return {
                "engagement_id": engagement_id,
                "approval_id": str(approval_id),
                "status": "invalid",
                "valid": False,
                "reason": exc.reason,
                "message": exc.message,
            }
        status = _status_for_record(record)
        return {
            "engagement_id": engagement_id,
            "approval_id": record.get("approval_id"),
            "status": status,
            "valid": status == "unused",
            "verified": True,
            "approval": _summarize(record),
        }

    key: bytes | None = None
    key_id: str | None = None
    try:
        key, key_id = resolve_approval_key()
    except PocError:
        key = None
    counts = {"unused": 0, "used": 0, "expired": 0, "revoked": 0, "invalid": 0}
    approvals: list[dict[str, Any]] = []
    directory = _approval_directory(engagement_id)
    if directory.is_dir():
        for path in sorted(directory.iterdir()):
            if (
                path.is_symlink()
                or not path.is_file()
                or path.suffix != APPROVAL_SUFFIX
            ):
                continue
            candidate_id = path.stem
            try:
                record = _read_approval_file(path, candidate_id)
                _validate_approval(record, engagement_id, candidate_id)
                if key is not None and key_id is not None:
                    _verify_signature(record, key, key_id)
            except PocError as exc:
                counts["invalid"] += 1
                approvals.append(
                    {
                        "approval_id": candidate_id,
                        "status": "invalid",
                        "reason": exc.reason,
                        "message": exc.message,
                    }
                )
                continue
            status = _status_for_record(record)
            counts[status] = counts.get(status, 0) + 1
            approvals.append({**_summarize(record), "status": status})
    approvals.sort(key=lambda item: item.get("issued_at") or "", reverse=True)
    return {
        "engagement_id": engagement_id,
        "approvals": approvals,
        "counts": counts,
        "total": len(approvals),
        "key_available": key is not None,
        "verified": key is not None,
    }


# ---------------------------------------------------------------------------
# Operator CLI: opencyber-poc
# ---------------------------------------------------------------------------


def _optional_listing(
    module_name: str, function_name: str, engagement_id: str
) -> dict[str, Any]:
    """Best-effort listing from a module that may not be importable yet."""
    import importlib

    qualified = f"{__package__}.{module_name}" if __package__ else module_name
    try:
        module = importlib.import_module(qualified)
    except Exception as exc:  # noqa: BLE001 - status must never crash
        return {
            "available": False,
            "reason": "module_unavailable",
            "message": str(exc),
            "items": [],
            "invalid": [],
        }
    function = getattr(module, function_name, None)
    if not callable(function):
        return {
            "available": False,
            "reason": "function_unavailable",
            "items": [],
            "invalid": [],
        }
    try:
        payload = function(engagement_id)
    except PocError as exc:
        return {
            "available": True,
            "error": exc.reason,
            "message": exc.message,
            "items": [],
            "invalid": [],
        }
    except ValueError as exc:
        return {
            "available": True,
            "error": "invalid_request",
            "message": str(exc),
            "items": [],
            "invalid": [],
        }
    except Exception as exc:  # noqa: BLE001 - status must never crash
        return {
            "available": True,
            "error": "listing_failed",
            "message": str(exc),
            "items": [],
            "invalid": [],
        }
    if isinstance(payload, dict):
        items = payload.get("chains")
        if items is None:
            items = payload.get("runs")
        if items is None:
            items = payload.get("items")
        invalid = payload.get("invalid")
        section: dict[str, Any] = {
            key: value
            for key, value in payload.items()
            if key not in {"chains", "runs", "items", "invalid", "engagement_id"}
        }
        section.update(
            available=True,
            items=list(items) if isinstance(items, (list, tuple)) else [],
            invalid=list(invalid) if isinstance(invalid, (list, tuple)) else [],
        )
        return section
    if isinstance(payload, (list, tuple)):
        return {"available": True, "items": list(payload), "invalid": []}
    return {"available": True, "items": [], "invalid": []}


def _poc_module() -> Any:
    try:
        from . import poc as module
    except ImportError as exc:
        raise PocError(
            "poc_engine_unavailable",
            f"the PoC engine module is unavailable: {exc}",
        ) from exc
    return module


def _poc_function(module: Any, name: str) -> Any:
    function = getattr(module, name, None)
    if not callable(function):
        raise PocError(
            "poc_engine_unavailable", f"poc.{name}() is unavailable"
        )
    return function


def _coerce_rendered_path(engagement_id: str, candidate: Any) -> Path | None:
    if not isinstance(candidate, str) or not candidate.strip():
        return None
    path = Path(candidate)
    if path.is_absolute():
        return path
    try:
        engagement_root = Path(get_engagement(engagement_id)["workspace"])
    except ValueError:
        return None
    return engagement_root / path


def _rendered_code_sha256(
    engagement_id: str, spec_id: str, render_result: Any
) -> str:
    if isinstance(render_result, dict):
        digest = render_result.get("code_sha256")
        if isinstance(digest, str) and _HEX64.fullmatch(digest.strip().lower()):
            return digest.strip().lower()
        for key in ("code_path", "path", "rendered_path", "code_file"):
            path = _coerce_rendered_path(engagement_id, render_result.get(key))
            if path is not None and path.is_file():
                return file_sha256(path)
    if isinstance(render_result, str):
        path = _coerce_rendered_path(engagement_id, render_result)
        if path is not None and path.is_file():
            return file_sha256(path)
    try:
        default_path = poc_path(engagement_id, "code", f"{spec_id}.py")
    except ValueError as exc:
        raise PocError(
            "unknown_engagement",
            f"unknown engagement_id {engagement_id!r}: {exc}",
            engagement_id=engagement_id,
        ) from exc
    if default_path.is_file():
        return file_sha256(default_path)
    raise PocError(
        "render_failed",
        f"render did not produce code for spec {spec_id}",
        spec_id=spec_id,
    )


def _parse_scope(values: list[str] | None) -> list[str]:
    scope: list[str] = []
    for value in values or []:
        for target in value.split(","):
            normalized = target.strip()
            if normalized and normalized not in scope:
                scope.append(normalized)
    if not scope:
        raise PocError(
            "invalid_scope", "authorize requires at least one --scope target"
        )
    return scope


def _parse_techniques(value: str | None, custom_code: bool) -> list[str]:
    if value is None or not value.strip():
        techniques = list(ALL_TECHNIQUES[:-1])
    else:
        techniques = []
        for item in value.split(","):
            normalized = item.strip()
            if not normalized:
                continue
            if normalized not in ALL_TECHNIQUES:
                raise PocError(
                    "invalid_techniques",
                    f"unknown technique: {normalized!r}; "
                    f"expected one of {', '.join(ALL_TECHNIQUES)}",
                )
            if normalized not in techniques:
                techniques.append(normalized)
        if not techniques:
            raise PocError(
                "invalid_techniques", "authorize requires at least one technique"
            )
    if custom_code and CUSTOM_TECHNIQUE not in techniques:
        techniques.append(CUSTOM_TECHNIQUE)
    if CUSTOM_TECHNIQUE in techniques and not custom_code:
        raise PocError(
            "custom_code_not_authorized",
            "--custom-code is required when 'custom' is included in --techniques",
        )
    return techniques


def _cmd_authorize(
    args: argparse.Namespace, key: bytes, key_id: str
) -> dict[str, Any]:
    now = utc_now()
    valid_from = parse_utc(args.valid_from, "valid_from") if args.valid_from else now
    valid_until = parse_utc(args.valid_until, "valid_until")
    scope = _parse_scope(args.scope)
    public_targets = sorted({target for target in scope if is_public_target(target)})
    if public_targets and not args.i_have_written_authorization:
        raise PocError(
            "written_authorization_required",
            "public-looking scope target(s) require explicit written "
            "authorization; re-run with --i-have-written-authorization only if "
            "that written authorization exists: " + ", ".join(public_targets),
            public_targets=public_targets,
        )
    techniques = _parse_techniques(args.techniques, bool(args.custom_code))
    record = {
        "schema_version": SCHEMA_VERSION,
        "engagement_id": args.engagement,
        "authorized_by": args.authorized_by,
        "reference": args.reference,
        "scope_targets": scope,
        "valid_from": iso_utc(valid_from),
        "valid_until": iso_utc(valid_until),
        "allowed_techniques": techniques,
        "custom_code_allowed": bool(args.custom_code),
        "prohibited_effects": [],
        "acknowledgement": args.acknowledgement,
        "created_at": iso_utc(now),
    }
    if args.reference_sha256:
        record["reference_sha256"] = args.reference_sha256
    stored = write_authorization(args.engagement, record, key, key_id)
    audit.safe_record(
        args.engagement,
        {
            "event": "poc.authorization.created",
            "authorization_sha256": sha256_hex(
                json.dumps(
                    {
                        field: stored.get(field)
                        for field in stored
                        if field != "hmac_sha256"
                    },
                    sort_keys=True,
                    separators=(",", ":"),
                ).encode("utf-8")
            ),
            "authorized_by": stored.get("authorized_by"),
            "reference": stored.get("reference"),
            "scope_targets": stored.get("scope_targets"),
            "allowed_techniques": stored.get("allowed_techniques"),
            "custom_code_allowed": stored.get("custom_code_allowed"),
            "valid_from": stored.get("valid_from"),
            "valid_until": stored.get("valid_until"),
            "key_id": key_id,
        },
    )
    return stored


def _cmd_approve(
    args: argparse.Namespace, key: bytes, key_id: str
) -> dict[str, Any]:
    engagement_id = args.engagement
    try:
        chain_id = validate_record_id("chain", args.chain)
        spec_id = validate_record_id("spec", args.spec)
    except PocError as exc:
        raise PocError("invalid_id", exc.message) from exc
    module = _poc_module()
    spec = _poc_function(module, "load_spec")(engagement_id, spec_id)
    if not isinstance(spec, dict):
        raise PocError(
            "invalid_spec", f"poc.load_spec returned {type(spec).__name__}"
        )
    recorded_chain_id = spec.get("chain_id")
    if recorded_chain_id != chain_id:
        raise PocError(
            "spec_chain_mismatch",
            f"spec {spec_id} belongs to chain {recorded_chain_id!r}, "
            f"not {chain_id!r}",
        )
    technique = spec.get("technique")
    if technique not in ALL_TECHNIQUES:
        raise PocError(
            "invalid_spec", f"spec technique is not recognized: {technique!r}"
        )
    target = spec.get("target")
    if not isinstance(target, str) or not target.strip():
        raise PocError("invalid_spec", "spec target must be a non-empty string")
    spec_sha256 = spec.get("spec_sha256")
    if not isinstance(spec_sha256, str) or not _HEX64.fullmatch(
        spec_sha256.strip().lower()
    ):
        raise PocError(
            "invalid_spec", "spec record is missing a valid spec_sha256"
        )
    lint_result = _poc_function(module, "lint")(engagement_id, spec_id)
    if not isinstance(lint_result, dict):
        raise PocError(
            "lint_failed",
            f"poc.lint returned {type(lint_result).__name__}",
        )
    blocking = lint_result.get("blocking")
    if blocking is None:
        blocking = []
    if not isinstance(blocking, (list, tuple)):
        raise PocError("lint_failed", "poc.lint returned a non-list blocking field")
    if blocking or lint_result.get("passed") is False:
        raise PocError(
            "lint_blocking",
            f"spec {spec_id} has blocking lint findings; fix them before "
            "minting an approval",
            spec_id=spec_id,
            blocking=list(blocking),
        )
    if technique == CUSTOM_TECHNIQUE and not args.allow_custom_code:
        raise PocError(
            "custom_code_requires_separate_approval",
            "this spec uses the custom code tier; re-run with "
            "--allow-custom-code only after reviewing the generated source",
            spec_id=spec_id,
        )
    expires_at = parse_utc(args.expires, "expires")
    ttl_hours = (expires_at - utc_now()).total_seconds() / 3600
    if ttl_hours <= 0:
        raise PocError("invalid_expiry", "--expires must be in the future")
    if ttl_hours > APPROVAL_TTL_HOURS:
        raise PocError(
            "invalid_expiry",
            f"approval lifetime must not exceed {APPROVAL_TTL_HOURS} hours",
        )
    render_result = _poc_function(module, "render")(engagement_id, spec_id)
    code_sha256 = _rendered_code_sha256(engagement_id, spec_id, render_result)
    approval = create_approval(
        engagement_id,
        chain_id=chain_id,
        spec_id=spec_id,
        spec_sha256=spec_sha256,
        code_sha256=code_sha256,
        technique=technique,
        targets=[target.strip()],
        custom_code=(technique == CUSTOM_TECHNIQUE),
        issued_by=args.issued_by,
        ttl_hours=ttl_hours,
        key=key,
        key_id=key_id,
    )
    audit.safe_record(
        engagement_id,
        {
            "event": "poc.approval.created",
            "approval_id": approval.get("approval_id"),
            "nonce": approval.get("nonce"),
            "chain_id": approval.get("chain_id"),
            "spec_id": approval.get("spec_id"),
            "spec_sha256": approval.get("spec_sha256"),
            "code_sha256": approval.get("code_sha256"),
            "technique": approval.get("technique"),
            "targets": approval.get("targets"),
            "custom_code": approval.get("custom_code"),
            "issued_by": approval.get("issued_by"),
            "expires_at": approval.get("expires_at"),
            "key_id": key_id,
        },
    )
    return approval


def _cmd_revoke(
    args: argparse.Namespace, key: bytes, key_id: str
) -> dict[str, Any]:
    record = revoke_approval(
        args.engagement, args.approval, args.reason, key, key_id
    )
    audit.safe_record(
        args.engagement,
        {
            "event": "poc.approval.revoked",
            "approval_id": record.get("approval_id"),
            "revoked_at": record.get("revoked_at"),
            "revoked_reason": record.get("revoked_reason"),
            "key_id": key_id,
        },
    )
    return record


def _cmd_status(
    args: argparse.Namespace, key: bytes, key_id: str
) -> dict[str, Any]:
    del key, key_id  # status is read-only; the key only gates the CLI entry point
    return {
        "engagement_id": args.engagement,
        "authorization": describe_authorization(args.engagement),
        "chains": _optional_listing("cve_chain", "list_chains", args.engagement),
        "approvals": approval_status(args.engagement, args.approval),
        "runs": _optional_listing("poc", "list_runs", args.engagement),
    }


def _print_refusal(error: PocError) -> None:
    print(
        f"opencyber-poc: refusal [{error.reason}]: {error.message}",
        file=sys.stderr,
    )


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="opencyber-poc",
        description=(
            "Operator-only signing tool for the OpenCyber CVE-chain PoC "
            "subsystem. The server never signs authorization or approvals."
        ),
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    authorize = subcommands.add_parser(
        "authorize",
        help="sign a human authorization record for an engagement",
        description=(
            "Write and sign the engagement authorization record. Re-running "
            "supersedes and archives the previous record."
        ),
    )
    authorize.add_argument("--engagement", required=True)
    authorize.add_argument("--authorized-by", required=True)
    authorize.add_argument("--reference", required=True)
    authorize.add_argument("--reference-sha256", default=None)
    authorize.add_argument(
        "--scope",
        action="append",
        required=True,
        help="authorized target; repeatable and comma-separated values allowed",
    )
    authorize.add_argument("--valid-from", default=None)
    authorize.add_argument("--valid-until", required=True)
    authorize.add_argument(
        "--techniques",
        default=None,
        help="comma-separated technique classes (default: non-custom techniques)",
    )
    authorize.add_argument(
        "--custom-code",
        action="store_true",
        help="allow the custom code tier (implies the 'custom' technique)",
    )
    authorize.add_argument("--acknowledgement", required=True)
    authorize.add_argument(
        "--i-have-written-authorization",
        action="store_true",
        help="confirm written authorization exists for public-looking targets",
    )
    authorize.set_defaults(handler=_cmd_authorize)

    approve = subcommands.add_parser(
        "approve",
        help="mint a one-shot approval for a rendered spec",
        description=(
            "Load and lint a spec, render it, and sign a single-use approval "
            "bound to the spec and rendered-code hashes."
        ),
    )
    approve.add_argument("--engagement", required=True)
    approve.add_argument("--chain", required=True)
    approve.add_argument("--spec", required=True)
    approve.add_argument("--issued-by", required=True)
    approve.add_argument("--expires", required=True)
    approve.add_argument(
        "--allow-custom-code",
        action="store_true",
        help="required to approve a spec that uses the custom code tier",
    )
    approve.set_defaults(handler=_cmd_approve)

    revoke = subcommands.add_parser(
        "revoke", help="revoke a previously minted approval"
    )
    revoke.add_argument("--engagement", required=True)
    revoke.add_argument("--approval", required=True)
    revoke.add_argument(
        "--reason", default="revoked by operator", help="recorded revocation reason"
    )
    revoke.set_defaults(handler=_cmd_revoke)

    status = subcommands.add_parser(
        "status",
        help="print authorization, chain, approval, and run status as JSON",
    )
    status.add_argument("--engagement", required=True)
    status.add_argument("--approval", default=None)
    status.set_defaults(handler=_cmd_status)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Console-script entry point for ``opencyber-poc``.

    Returns 0 on success, 2 for usage errors or structured refusals, and 1 for
    unexpected failures.
    """
    parser = _build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:  # argparse --help/usage handling without raising
        return int(exc.code) if exc.code is not None else 0
    try:
        key, key_id = resolve_approval_key()
    except PocError as exc:
        _print_refusal(exc)
        return 2
    try:
        payload = args.handler(args, key, key_id)
    except PocError as exc:
        _print_refusal(exc)
        return 2
    except ValueError as exc:
        _print_refusal(PocError("invalid_request", str(exc)))
        return 2
    except Exception as exc:  # noqa: BLE001 - maps to the documented exit code 1
        print(f"opencyber-poc: unexpected error: {exc}", file=sys.stderr)
        return 1
    json.dump(payload, sys.stdout, indent=2, sort_keys=True, default=str)
    sys.stdout.write("\n")
    return 0


if __name__ == "__main__":  # pragma: no cover - console-script parity
    raise SystemExit(main())
