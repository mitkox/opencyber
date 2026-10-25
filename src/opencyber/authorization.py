"""Human-signed engagement authorization for CVE-chain PoC runs.

The authorization record is the operator's written permission to exercise the
PoC subsystem against a subset of an engagement's targets. It is signed with
the :envvar:`OPENCYBER_APPROVAL_KEY` HMAC key and stored at
``<engagement>/poc/authorization.json``. The MCP server can verify it but never
signs one; only the operator CLI (``opencyber-poc authorize``) writes it.

Design notes:

- The signature covers every field except ``hmac_sha256`` (see
  :func:`authorization_signed_payload`). Changing anything else breaks
  verification and yields ``authorization_invalid``.
- Superseding an authorization archives the previous file under
  ``poc/authorization-history/<sha256-of-file-bytes>.json`` so the chain of
  operator approvals is retained.
- Writes are atomic (unique temp file in the destination directory followed by
  :func:`os.replace`) so a crash never leaves a half-written record.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from typing import Any
import uuid
from urllib.parse import urlparse

from .engagements import get_engagement
from .policy import target_matches
from .poc_schema import (
    ALL_TECHNIQUES,
    AUTHORIZATION_FILENAME,
    CUSTOM_TECHNIQUE,
    PocError,
    SCHEMA_VERSION,
    approval_key_available,
    iso_utc,
    parse_utc,
    poc_path,
    resolve_approval_key,
    sha256_hex,
    sign_payload,
    utc_now,
    verify_payload,
)


AUTHORIZATION_HISTORY_DIRECTORY = "authorization-history"
MAX_AUTHORIZATION_LIFETIME = timedelta(days=365)

#: Fields covered by the HMAC, in a fixed documented order. ``hmac_sha256`` is
#: deliberately excluded and ``reference_sha256`` is only included when set.
AUTHORIZATION_SIGNED_FIELDS: tuple[str, ...] = (
    "schema_version",
    "engagement_id",
    "authorized_by",
    "reference",
    "reference_sha256",
    "scope_targets",
    "valid_from",
    "valid_until",
    "allowed_techniques",
    "custom_code_allowed",
    "prohibited_effects",
    "acknowledgement",
    "created_at",
    "key_id",
)

_ALLOWED_RECORD_FIELDS = frozenset(AUTHORIZATION_SIGNED_FIELDS) | {"hmac_sha256"}
_HEX64 = re.compile(r"[0-9a-f]{64}")

# Local-scope vocabulary for the CLI acknowledgement gate. Anything that is not
# RFC1918, loopback, IPv6 loopback/link-local/ULA, or a ``.local``/``.test``
# name is treated as "public-looking" and requires --i-have-written-authorization.
_RFC1918_NETWORKS = tuple(
    ip_network(value) for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
_LOCAL_IPV6_NETWORKS = (
    ip_network("::1/128"),
    ip_network("fc00::/7"),
    ip_network("fe80::/10"),
)
_LOCAL_HOSTNAME_SUFFIXES = (".local", ".test", ".localhost")
_TRAILING_PUNCTUATION = ",;:)]}'\""


def _invalid(message: str, **details: Any) -> PocError:
    return PocError("authorization_invalid", message, **details)


def _unknown_engagement(engagement_id: str, error: Exception) -> PocError:
    return PocError(
        "unknown_engagement",
        f"unknown engagement_id {engagement_id!r}: {error}",
        engagement_id=engagement_id,
    )


# ---------------------------------------------------------------------------
# Paths and atomic file helpers
# ---------------------------------------------------------------------------


def authorization_path(engagement_id: str) -> Path:
    """Return ``<engagement>/poc/authorization.json`` without creating it."""
    return poc_path(engagement_id, AUTHORIZATION_FILENAME)


def _authorization_file(engagement_id: str) -> Path:
    try:
        return authorization_path(engagement_id)
    except ValueError as exc:  # malformed id, unknown engagement, unsafe path
        raise _unknown_engagement(engagement_id, exc) from exc


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


def _read_regular_file(path: Path, *, reason_message: str) -> bytes:
    if path.is_symlink():
        raise _invalid(f"{reason_message}: file must not be a symlink")
    try:
        info = path.lstat()
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise _invalid(f"{reason_message}: {exc}") from exc
    if not stat.S_ISREG(info.st_mode):
        raise _invalid(f"{reason_message}: not a regular file")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise _invalid(f"{reason_message}: {exc}") from exc


# ---------------------------------------------------------------------------
# Validation and the signed payload
# ---------------------------------------------------------------------------


def authorization_signed_payload(record: dict[str, Any]) -> dict[str, Any]:
    """Return the exact field set covered by the record's HMAC."""
    if not isinstance(record, dict):
        raise _invalid("authorization record must be a JSON object")
    payload: dict[str, Any] = {}
    for field in AUTHORIZATION_SIGNED_FIELDS:
        if field == "reference_sha256" and not record.get(field):
            continue
        if field in record:
            payload[field] = record[field]
    return payload


def _non_empty_string(record: dict[str, Any], field: str) -> str:
    value = record.get(field)
    if not isinstance(value, str) or not value.strip():
        raise _invalid(f"authorization field {field!r} must be a non-empty string")
    return value.strip()


def _string_list(
    record: dict[str, Any], field: str, *, allow_empty: bool
) -> list[str]:
    value = record.get(field)
    if not isinstance(value, list):
        raise _invalid(f"authorization field {field!r} must be a list of strings")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise _invalid(
                f"authorization field {field!r} entries must be non-empty strings"
            )
        result.append(item.strip())
    if not result and not allow_empty:
        raise _invalid(f"authorization field {field!r} must not be empty")
    return result


def _record_timestamp(
    record: dict[str, Any], field: str, *, default: datetime | None = None
) -> datetime:
    raw = record.get(field)
    if raw is None:
        if default is not None:
            return default
        raise _invalid(f"authorization field {field!r} is required")
    try:
        return parse_utc(raw, field)
    except PocError as exc:
        raise _invalid(
            f"authorization field {field!r} must be an ISO-8601 timestamp",
            field=field,
        ) from exc


def _dedupe(values: list[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        result.append(value)
    return result


def _validate_authorization(record: dict[str, Any], engagement_id: str) -> None:
    """Validate a stored record's schema without checking the signature."""
    if not isinstance(record, dict):
        raise _invalid("authorization record must be a JSON object")
    unknown = sorted(set(record) - _ALLOWED_RECORD_FIELDS)
    if unknown:
        raise _invalid(
            "authorization record contains unknown field(s): " + ", ".join(unknown)
        )
    if record.get("schema_version") != SCHEMA_VERSION:
        raise _invalid(
            f"unsupported authorization schema_version: {record.get('schema_version')!r}"
        )
    if record.get("engagement_id") != engagement_id:
        raise _invalid("authorization engagement_id does not match the request")
    _non_empty_string(record, "authorized_by")
    _non_empty_string(record, "reference")
    _non_empty_string(record, "acknowledgement")
    reference_sha256 = record.get("reference_sha256")
    if reference_sha256 is not None:
        if not isinstance(reference_sha256, str) or not _HEX64.fullmatch(
            reference_sha256
        ):
            raise _invalid(
                "authorization field 'reference_sha256' must be a lowercase "
                "SHA-256 hex digest"
            )
    scope_targets = _string_list(record, "scope_targets", allow_empty=False)
    del scope_targets  # validated above; value is projected by describe_authorization
    allowed_techniques = _string_list(
        record, "allowed_techniques", allow_empty=False
    )
    unknown_techniques = sorted(
        {value for value in allowed_techniques if value not in ALL_TECHNIQUES}
    )
    if unknown_techniques:
        raise _invalid(
            "authorization contains unknown technique(s): "
            + ", ".join(unknown_techniques)
        )
    if type(record.get("custom_code_allowed")) is not bool:
        raise _invalid("authorization field 'custom_code_allowed' must be a boolean")
    _string_list(record, "prohibited_effects", allow_empty=True)
    valid_from = _record_timestamp(record, "valid_from")
    valid_until = _record_timestamp(record, "valid_until")
    if valid_until <= valid_from:
        raise _invalid("authorization valid_until must be after valid_from")
    _record_timestamp(record, "created_at")
    key_id = record.get("key_id")
    if not isinstance(key_id, str) or not key_id.strip():
        raise _invalid("authorization field 'key_id' must be a non-empty string")
    hmac_sha256 = record.get("hmac_sha256")
    if not isinstance(hmac_sha256, str) or not _HEX64.fullmatch(hmac_sha256):
        raise _invalid(
            "authorization field 'hmac_sha256' must be a lowercase SHA-256 hex digest"
        )


# ---------------------------------------------------------------------------
# Target scope helpers
# ---------------------------------------------------------------------------


def _target_host(value: Any) -> str | None:
    """Normalize a URL, host:port, wildcard, IP, or CIDR into a bare host."""
    if not isinstance(value, str):
        return None
    text = value.strip().strip(_TRAILING_PUNCTUATION).strip()
    if not text:
        return None
    if "://" in text:
        try:
            parsed = urlparse(text)
        except ValueError:
            return None
        text = parsed.hostname or ""
        if not text:
            return None
    if text.startswith("*."):
        text = text[2:]
    if "@" in text:
        text = text.rsplit("@", 1)[1]
    if text.startswith("["):
        end = text.find("]")
        if end == -1:
            return None
        text = text[1:end]
    elif text.count(":") == 1:
        host, _, port = text.rpartition(":")
        if port.isdigit():
            text = host
    return text.strip().lower().rstrip(".") or None


def _is_local_address(address: Any) -> bool:
    if address.version == 4:
        if address.is_loopback:
            return True
        return any(address in network for network in _RFC1918_NETWORKS)
    return (
        address.is_loopback
        or address.is_link_local
        or any(address in network for network in _LOCAL_IPV6_NETWORKS)
    )


def _network_within(
    network: IPv4Network | IPv6Network, candidate: IPv4Network | IPv6Network
) -> bool:
    if isinstance(network, IPv4Network):
        return isinstance(candidate, IPv4Network) and network.subnet_of(candidate)
    return isinstance(candidate, IPv6Network) and network.subnet_of(candidate)


def _is_local_network(network: IPv4Network | IPv6Network) -> bool:
    candidates = _RFC1918_NETWORKS + _LOCAL_IPV6_NETWORKS
    return any(_network_within(network, local) for local in candidates)


def is_public_target(target: Any) -> bool:
    """Return True when a scope target looks internet-facing.

    Used by the operator CLI to require an explicit
    ``--i-have-written-authorization`` acknowledgement before signing an
    authorization that reaches outside private/local address space.
    """
    host = _target_host(target)
    if host is None:
        return True
    if host == "*":
        return False
    if "/" in host:
        try:
            network = ip_network(host, strict=False)
        except ValueError:
            return True
        return not _is_local_network(network)
    try:
        address = ip_address(host)
    except ValueError:
        lowered = host.lower()
        if lowered == "localhost" or lowered.endswith(_LOCAL_HOSTNAME_SUFFIXES):
            return False
        return True
    return not _is_local_address(address)


def _authorized_target_within_engagement(
    authorized: str, engagement_targets: list[str]
) -> bool:
    """True when ``authorized`` does not exceed any declared engagement target."""
    host = _target_host(authorized)
    if not host:
        return False
    if host == "*":
        return any((_target_host(target) or "") == "*" for target in engagement_targets)
    if "/" in host:
        try:
            network = ip_network(host, strict=False)
        except ValueError:
            return False
        for target in engagement_targets:
            target_host = _target_host(target)
            if not target_host:
                continue
            if "/" in target_host:
                try:
                    target_network = ip_network(target_host, strict=False)
                except ValueError:
                    continue
                if _network_within(network, target_network):
                    return True
                continue
            try:
                address = ip_address(target_host)
            except ValueError:
                continue
            if (
                address.version == network.version
                and network.num_addresses == 1
                and address in network
            ):
                return True
        return False
    return any(
        target_matches(host, target)
        for target in engagement_targets
        if _target_host(target)
    )


# ---------------------------------------------------------------------------
# Reading and writing
# ---------------------------------------------------------------------------


def read_authorization(engagement_id: str) -> dict[str, Any] | None:
    """Read the raw authorization record, or ``None`` when none exists.

    Corrupt or unsafe records raise :class:`PocError` with
    ``authorization_invalid``; absence never raises.
    """
    path = _authorization_file(engagement_id)
    try:
        raw = _read_regular_file(
            path, reason_message="cannot read authorization record"
        )
    except FileNotFoundError:
        return None
    try:
        record = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise _invalid(f"authorization record is not valid JSON: {exc}") from exc
    if not isinstance(record, dict):
        raise _invalid("authorization record must be a JSON object")
    return record


def load_authorization(engagement_id: str) -> dict[str, Any]:
    """Load and verify the signed authorization, or raise a structured refusal."""
    record = read_authorization(engagement_id)
    if record is None:
        raise PocError(
            "authorization_required",
            "no signed authorization exists for this engagement; run "
            f"'opencyber-poc authorize --engagement {engagement_id} ...' first",
            engagement_id=engagement_id,
        )
    _validate_authorization(record, engagement_id)
    key, key_id = resolve_approval_key()
    if record.get("key_id") != key_id:
        raise _invalid(
            "authorization was signed with a different approval key; re-sign it "
            "with the current OPENCYBER_APPROVAL_KEY"
        )
    if not verify_payload(
        key, authorization_signed_payload(record), record.get("hmac_sha256")
    ):
        raise _invalid("authorization signature does not match its contents")
    valid_from = _record_timestamp(record, "valid_from")
    valid_until = _record_timestamp(record, "valid_until")
    now = utc_now()
    if now >= valid_until:
        raise PocError(
            "authorization_expired",
            f"authorization expired at {record.get('valid_until')}",
            engagement_id=engagement_id,
            valid_until=record.get("valid_until"),
        )
    if now < valid_from:
        raise PocError(
            "authorization_not_yet_valid",
            f"authorization is not valid before {record.get('valid_from')}",
            engagement_id=engagement_id,
            valid_from=record.get("valid_from"),
        )
    return record


def describe_authorization(engagement_id: str) -> dict[str, Any]:
    """Return a non-raising status view for ``oc_authorization_get``.

    ``status`` is one of ``required`` (no signed record exists), ``valid``,
    ``expired``, ``not_yet_valid``, ``unverified`` (record exists but the
    approval key is unavailable), or ``invalid``. The raw ``authorization``
    record is included when one exists so an operator can inspect what failed
    to verify.
    """
    description: dict[str, Any] = {
        "engagement_id": engagement_id,
        "status": "required",
        "authorization": None,
        "valid": False,
        "valid_until": None,
        "remaining_seconds": 0,
        "allowed_techniques": [],
        "custom_code_allowed": False,
        "scope_targets": [],
        "key_available": approval_key_available(),
        "reason": None,
    }
    try:
        record = read_authorization(engagement_id)
    except PocError as exc:
        description.update(
            status="invalid", reason=exc.reason, message=exc.message
        )
        return description
    if record is None:
        description["reason"] = "authorization_required"
        return description

    description["authorization"] = record
    techniques = record.get("allowed_techniques")
    if isinstance(techniques, list):
        description["allowed_techniques"] = [
            value for value in techniques if isinstance(value, str)
        ]
    scope_targets = record.get("scope_targets")
    if isinstance(scope_targets, list):
        description["scope_targets"] = [
            value for value in scope_targets if isinstance(value, str)
        ]
    if type(record.get("custom_code_allowed")) is bool:
        description["custom_code_allowed"] = record["custom_code_allowed"]
    if isinstance(record.get("valid_until"), str):
        description["valid_until"] = record["valid_until"]
        try:
            valid_until = parse_utc(record["valid_until"], "valid_until")
        except PocError:
            valid_until = None
        if valid_until is not None:
            description["remaining_seconds"] = max(
                0, int((valid_until - utc_now()).total_seconds())
            )

    status_by_reason = {
        "authorization_expired": "expired",
        "authorization_not_yet_valid": "not_yet_valid",
        "approval_key_unavailable": "unverified",
    }
    try:
        load_authorization(engagement_id)
    except PocError as exc:
        description["status"] = status_by_reason.get(exc.reason, "invalid")
        description["reason"] = exc.reason
        description["message"] = exc.message
        return description
    description["status"] = "valid"
    description["valid"] = True
    return description


def _normalize_new_record(
    engagement_id: str,
    record: dict[str, Any],
    key_id: str,
    engagement_targets: list[str],
) -> dict[str, Any]:
    if not isinstance(record, dict):
        raise _invalid("authorization record must be a JSON object")
    unknown = sorted(set(record) - _ALLOWED_RECORD_FIELDS)
    if unknown:
        raise _invalid(
            "authorization record contains unknown field(s): " + ", ".join(unknown)
        )
    declared_schema = record.get("schema_version", SCHEMA_VERSION)
    if declared_schema != SCHEMA_VERSION:
        raise _invalid(f"unsupported authorization schema_version: {declared_schema!r}")

    now = utc_now()
    authorized_by = _non_empty_string(record, "authorized_by")
    reference = _non_empty_string(record, "reference")
    acknowledgement = _non_empty_string(record, "acknowledgement")

    reference_sha256 = record.get("reference_sha256")
    if reference_sha256 in (None, ""):
        reference_sha256 = None
    elif isinstance(reference_sha256, str) and _HEX64.fullmatch(
        reference_sha256.strip().lower()
    ):
        reference_sha256 = reference_sha256.strip().lower()
    else:
        raise _invalid(
            "authorization field 'reference_sha256' must be a lowercase SHA-256 "
            "hex digest"
        )

    scope_targets = _dedupe(
        _string_list(record, "scope_targets", allow_empty=False)
    )
    for target in scope_targets:
        if not _authorized_target_within_engagement(target, engagement_targets):
            raise PocError(
                "scope_violation",
                "authorization scope target is outside the engagement targets: "
                f"{target}",
                target=target,
                engagement_targets=engagement_targets,
            )

    allowed_techniques = sorted(
        set(_string_list(record, "allowed_techniques", allow_empty=False))
    )
    unknown_techniques = [
        value for value in allowed_techniques if value not in ALL_TECHNIQUES
    ]
    if unknown_techniques:
        raise _invalid(
            "authorization contains unknown technique(s): "
            + ", ".join(unknown_techniques)
        )

    custom_code_allowed = record.get("custom_code_allowed", False)
    if type(custom_code_allowed) is not bool:
        raise _invalid("authorization field 'custom_code_allowed' must be a boolean")
    if CUSTOM_TECHNIQUE in allowed_techniques and not custom_code_allowed:
        raise _invalid(
            "allowed_techniques includes 'custom' but custom_code_allowed is false"
        )

    prohibited_effects = _dedupe(
        _string_list(record, "prohibited_effects", allow_empty=True)
    )
    valid_from = _record_timestamp(record, "valid_from", default=now)
    valid_until = _record_timestamp(record, "valid_until")
    if valid_until <= now:
        raise _invalid("authorization valid_until must be in the future")
    if valid_until > now + MAX_AUTHORIZATION_LIFETIME:
        raise _invalid(
            "authorization valid_until cannot exceed 365 days from now"
        )
    if valid_from >= valid_until:
        raise _invalid("authorization valid_from must be before valid_until")
    created_at = _record_timestamp(record, "created_at", default=now)

    normalized: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "engagement_id": engagement_id,
        "authorized_by": authorized_by,
        "reference": reference,
        "scope_targets": scope_targets,
        "valid_from": iso_utc(valid_from),
        "valid_until": iso_utc(valid_until),
        "allowed_techniques": allowed_techniques,
        "custom_code_allowed": custom_code_allowed,
        "prohibited_effects": prohibited_effects,
        "acknowledgement": acknowledgement,
        "created_at": iso_utc(created_at),
        "key_id": key_id,
    }
    if reference_sha256 is not None:
        normalized["reference_sha256"] = reference_sha256
    return normalized


def _derive_key_id(key: bytes) -> str:
    return hashlib.sha256(key).hexdigest()[:16]


def write_authorization(
    engagement_id: str,
    record: dict[str, Any],
    key: bytes,
    key_id: str,
) -> dict[str, Any]:
    """Validate, sign, archive the previous record, and atomically store ``record``.

    Operator CLI only: the server never calls this. Raises
    ``scope_violation`` when the requested scope exceeds the engagement's
    targets and ``authorization_invalid`` for schema or timestamp problems.
    """
    if not isinstance(key, (bytes, bytearray)) or not key:
        raise _invalid("approval key must be non-empty bytes")
    key_bytes = bytes(key)
    if not isinstance(key_id, str) or key_id != _derive_key_id(key_bytes):
        raise _invalid("key_id does not match the supplied approval key")
    try:
        engagement = get_engagement(engagement_id)
    except ValueError as exc:
        raise _unknown_engagement(engagement_id, exc) from exc
    engagement_targets = [
        str(target) for target in engagement.get("targets", [])
    ]
    normalized = _normalize_new_record(
        engagement_id, record, key_id, engagement_targets
    )
    archive_previous(engagement_id)
    normalized["hmac_sha256"] = sign_payload(
        key_bytes, authorization_signed_payload(normalized)
    )
    _atomic_write_json(_authorization_file(engagement_id), normalized)
    return normalized


def archive_previous(engagement_id: str) -> None:
    """Copy the current authorization file into the immutable history directory."""
    path = _authorization_file(engagement_id)
    try:
        raw = _read_regular_file(
            path, reason_message="cannot archive authorization record"
        )
    except FileNotFoundError:
        return
    digest = sha256_hex(raw)
    try:
        history_dir = poc_path(engagement_id, AUTHORIZATION_HISTORY_DIRECTORY)
    except ValueError as exc:
        raise _unknown_engagement(engagement_id, exc) from exc
    history_dir.mkdir(parents=True, exist_ok=True)
    destination = history_dir / f"{digest}.json"
    try:
        existing = destination.read_bytes()
    except FileNotFoundError:
        existing = None
    except OSError as exc:
        raise _invalid(f"cannot read authorization history entry: {exc}") from exc
    if existing == raw:
        return
    _atomic_write_bytes(destination, raw)


def validate_for_run(
    engagement_id: str,
    targets: list[str],
    technique: str,
    custom_code: bool = False,
) -> dict[str, Any]:
    """Verify the run's target(s), technique, and custom-code tier.

    Returns the verified authorization record. Raises ``authorization_*`` for
    record problems, ``scope_violation`` when a target is outside the signed
    scope, and ``technique_not_authorized`` for a disallowed technique or
    custom-code tier.
    """
    record = load_authorization(engagement_id)
    if not isinstance(targets, (list, tuple)) or not targets:
        raise PocError(
            "scope_violation",
            "at least one run target is required to validate authorization",
        )
    normalized_targets: list[str] = []
    for target in targets:
        if not isinstance(target, str) or not target.strip():
            raise PocError(
                "scope_violation", "run targets must be non-empty strings"
            )
        normalized_targets.append(target.strip())
    authorized_targets = [
        str(value) for value in record.get("scope_targets", [])
    ]
    for target in normalized_targets:
        if not any(
            target_matches(target, scope_target) for scope_target in authorized_targets
        ):
            raise PocError(
                "scope_violation",
                f"target is outside the signed authorization scope: {target}",
                target=target,
                authorized_targets=authorized_targets,
            )
    if not isinstance(technique, str) or technique not in ALL_TECHNIQUES:
        raise PocError(
            "technique_not_authorized",
            f"unknown or unauthorized technique: {technique!r}",
            technique=technique,
        )
    if technique not in record.get("allowed_techniques", []):
        raise PocError(
            "technique_not_authorized",
            f"technique {technique!r} is not allowed by the authorization",
            technique=technique,
            allowed_techniques=record.get("allowed_techniques", []),
        )
    requires_custom = bool(custom_code) or technique == CUSTOM_TECHNIQUE
    if requires_custom and not record.get("custom_code_allowed"):
        raise PocError(
            "technique_not_authorized",
            "custom code execution is not authorized for this engagement",
            technique=technique,
        )
    return record
