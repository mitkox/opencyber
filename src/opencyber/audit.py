"""Tamper-evident engagement audit trail.

Every executable call, HTTP interaction, browser action, and hardware session
is appended to ``<engagement>/.opencyber/audit/events.jsonl``. Each record
contains the SHA-256 of the previous record, so removing, reordering, or editing
an event breaks the chain and is reported by ``oc_audit_verify``.

This is an evidence-integrity control, not a blockchain. An operator with root
inside the container can rewrite the whole file; the guarantee is that a
partial edit is detectable and that the trail can be copied out and compared.
"""

from __future__ import annotations

from concurrent.futures import CancelledError
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import threading
from typing import Any, BinaryIO, Iterable

from . import engagements, envelope, limits
from .engagements import get_engagement, resolve_engagement_path


AUDIT_SCHEMA_VERSION = 1
GENESIS_HASH = "0" * 64
MAX_READ_EVENTS = 5000
MAX_AUDIT_RECORD_BYTES = 1024 * 1024

_SECRET_KEY = re.compile(
    r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|apikey|authorization|cookie|"
    r"private[_-]?key|credential|passphrase|bearer)"
)
_SECRET_VALUE = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|apikey|authorization|"
    r"cookie|passphrase|bearer)(\s*[:=]\s*)([^\s,;\"']+)"
)
_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _audit_root(engagement_id: str) -> Path:
    get_engagement(engagement_id)
    path = resolve_engagement_path(engagement_id, ".opencyber/audit", must_exist=False)
    path.mkdir(parents=True, exist_ok=True)
    return path


def _events_path(engagement_id: str) -> Path:
    return _audit_root(engagement_id) / "events.jsonl"


def _canonical(payload: dict[str, Any]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")


def _digest(payload: dict[str, Any]) -> str:
    return hashlib.sha256(_canonical(payload)).hexdigest()


def _redact_scalar(value: str) -> str:
    value = _BEARER.sub("Bearer ***", value)
    return _SECRET_VALUE.sub(lambda match: f"{match.group(1)}{match.group(2)}***", value)


def redact(value: Any, key: str = "") -> Any:
    """Recursively redact values that look like credentials or bearer tokens."""
    if isinstance(value, dict):
        output: dict[str, Any] = {}
        for child_key, child_value in value.items():
            if _SECRET_KEY.search(str(child_key)):
                output[child_key] = "***"
            else:
                output[child_key] = redact(child_value, str(child_key))
        return output
    if isinstance(value, (list, tuple)):
        return [redact(item, key) for item in value]
    if isinstance(value, str):
        return _redact_scalar(value)
    return value


def _last_record(handle: Any) -> dict[str, Any] | None:
    handle.seek(0, os.SEEK_END)
    size = handle.tell()
    if size == 0:
        return None
    # A valid record can be much larger than a scanner's usual argv. Read the
    # complete bounded final row, including its preceding newline if present.
    window = min(size, MAX_AUDIT_RECORD_BYTES + 1)
    handle.seek(size - window)
    tail = handle.read()
    lines = [line for line in tail.splitlines() if line.strip()]
    if not lines:
        raise ValueError("existing audit has no readable final record")
    if len(lines[-1]) + 1 > MAX_AUDIT_RECORD_BYTES:
        raise ValueError("existing audit record exceeds the 1 MiB limit")
    try:
        record = json.loads(lines[-1])
    except (ValueError, UnicodeError) as exc:
        raise ValueError("existing audit has an invalid final record") from exc
    if not isinstance(record, dict):
        raise ValueError("existing audit final record is not an object")
    return record


def _open_events(engagement_id: str, *, create: bool = False) -> BinaryIO:
    get_engagement(engagement_id)
    descriptor = os.open(engagements.WORKSPACE, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in ("engagements", engagement_id, ".opencyber", "audit"):
            if create and component in (".opencyber", "audit"):
                try:
                    os.mkdir(component, mode=0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        flags = os.O_NOFOLLOW | os.O_NONBLOCK | (os.O_RDWR | os.O_CREAT | os.O_APPEND if create else os.O_RDONLY)
        event_fd = os.open("events.jsonl", flags, mode=0o600, dir_fd=descriptor)
    finally:
        os.close(descriptor)
    info = os.fstat(event_fd)
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
        os.close(event_fd)
        raise ValueError("audit requires a regular file with a single link")
    return os.fdopen(event_fd, "a+b" if create else "rb")


def record_event(
    engagement_id: str, event: dict[str, Any], *, cancel_event: threading.Event | None = None
) -> dict[str, Any]:
    """Append one event and return the stored record.

    Raises ``ValueError`` for an invalid engagement and ``OSError`` when the
    audit file cannot be written. Callers decide whether that is fatal.
    """
    if not isinstance(event, dict):
        raise ValueError("audit event must be a dictionary")
    if "event" not in event or not isinstance(event["event"], str):
        raise ValueError("audit event requires a string 'event' field")
    with _open_events(engagement_id, create=True) as handle:
        while True:
            if cancel_event is not None and cancel_event.is_set():
                raise CancelledError("audit operation cancelled")
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if cancel_event is None:
                    fcntl.flock(handle.fileno(), fcntl.LOCK_EX)
                    break
                cancel_event.wait(0.05)
        try:
            previous = _last_record(handle)
            sequence = int(previous.get("seq", 0)) + 1 if previous else 1
            previous_hash = previous.get("hash", GENESIS_HASH) if previous else GENESIS_HASH
            payload = {
                "schema_version": AUDIT_SCHEMA_VERSION,
                "seq": sequence,
                "ts": _now(),
                "engagement_id": engagement_id,
                "prev_hash": previous_hash,
                **redact(event),
            }
            payload.pop("hash", None)
            payload["hash"] = _digest(payload)
            encoded = _canonical(payload) + b"\n"
            if len(encoded) > MAX_AUDIT_RECORD_BYTES:
                raise ValueError("audit record exceeds the 1 MiB verification limit")
            handle.seek(0, os.SEEK_END)
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
            return payload
        finally:
            fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


def safe_record(engagement_id: str, event: dict[str, Any]) -> dict[str, Any] | None:
    """Best-effort audit write for optional instrumentation points."""
    try:
        return record_event(engagement_id, event)
    except (OSError, ValueError):
        return None


def _iter_records(engagement_id: str) -> Iterable[dict[str, Any]]:
    try:
        source = _open_events(engagement_id)
    except FileNotFoundError:
        return
    with source as handle:
        for number, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            yield {"line": number, "record": json.loads(stripped)}


def read_audit(
    engagement_id: str, limit: int = 100, offset: int = 0, event: str | None = None
) -> dict[str, Any]:
    """Read a window of the audit trail without materializing the whole file.

    At most ``MAX_READ_EVENTS`` matching records are examined. When more exist,
    the result is ``partial`` and says so: the count is a floor, not the total,
    and the caller is told to export the trail for a complete read.
    """
    if not 1 <= limit <= 1000:
        raise ValueError("limit must be between 1 and 1000")
    if offset < 0:
        raise ValueError("offset must not be negative")
    selected: list[dict[str, Any]] = []
    matched = 0
    total_exact = True
    for entry in _iter_records(engagement_id):
        record = entry["record"]
        if event and record.get("event") != event:
            continue
        matched += 1
        if matched > MAX_READ_EVENTS:
            matched = MAX_READ_EVENTS
            total_exact = False
            break
        if offset <= matched - 1 < offset + limit:
            selected.append(record)
    exhausted = offset + len(selected) >= matched
    result: dict[str, Any] = {
        "engagement_id": engagement_id,
        "total": matched,
        "total_exact": total_exact,
        "offset": offset,
        "limit": limit,
        "events": selected,
        "coverage": envelope.coverage(
            "complete" if total_exact and exhausted else "partial",
            examined=matched,
            total=matched if total_exact else None,
            exhausted=exhausted,
            next_offset=None if exhausted else offset + len(selected),
        ),
    }
    if not total_exact:
        result["limit"] = limits.facts("audit.max_events", effective=MAX_READ_EVENTS)
        result["limitations"] = [
            f"Examined the first {MAX_READ_EVENTS} matching events; more records remain on disk. "
            "Export the audit trail for an unfiltered read."
        ]
    elif not exhausted:
        result["limitations"] = [
            f"Returned events {offset} to {offset + len(selected)} of {matched}; "
            "continue with the next_offset value."
        ]
    return result


def verify_audit(engagement_id: str) -> dict[str, Any]:
    """Recompute the hash chain and report the first inconsistency."""
    try:
        source = _open_events(engagement_id)
    except FileNotFoundError:
        return {
            "engagement_id": engagement_id,
            "valid": True,
            "events": 0,
            "first_invalid_seq": None,
            "error": None,
            "note": "audit trail is empty",
        }
    except (OSError, ValueError) as exc:
        return {"engagement_id": engagement_id, "valid": False, "events": 0,
                "first_invalid_seq": 1, "error": f"unsafe or unreadable audit file: {exc}"}
    with source:
        return verify_audit_stream(source, engagement_id)


def audit_summary(engagement_id: str) -> dict[str, Any]:
    events: dict[str, int] = {}
    for entry in _iter_records(engagement_id):
        name = str(entry["record"].get("event", "unknown"))
        events[name] = events.get(name, 0) + 1
    return {
        "engagement_id": engagement_id,
        "events": events,
        "total": sum(events.values()),
        "path": str(_events_path(engagement_id)),
    }


def verify_audit_stream(
    handle: BinaryIO, engagement_id: str, *, cancel_event: threading.Event | None = None
) -> dict[str, Any]:
    """Verify a bounded-memory snapshot, including its engagement binding.

    This verifies internal consistency. A separately retained hash is needed
    to detect replacement of an entire chain or removal of its final records.
    """
    previous_hash = GENESIS_HASH
    count = 0
    number = 0
    while True:
        if cancel_event is not None and cancel_event.is_set():
            raise CancelledError("evidence operation cancelled")
        line = handle.readline(MAX_AUDIT_RECORD_BYTES + 1)
        if not line:
            break
        number += 1
        error = None
        record: dict[str, Any] = {}
        if len(line) > MAX_AUDIT_RECORD_BYTES:
            error = "audit record exceeds the 1 MiB verification limit"
        elif line.strip():
            try:
                loaded = json.loads(line)
            except (json.JSONDecodeError, UnicodeDecodeError, ValueError, RecursionError) as exc:
                error = f"invalid JSON: {exc}"
            else:
                if not isinstance(loaded, dict):
                    error = "record is not an object"
                else:
                    record = loaded
                    if type(record.get("seq")) is not int or record["seq"] != count + 1:
                        error = f"expected seq {count + 1}"
                    elif type(record.get("schema_version")) is not int or record["schema_version"] != AUDIT_SCHEMA_VERSION:
                        error = "unsupported audit schema_version"
                    elif record.get("engagement_id") != engagement_id:
                        error = "audit engagement_id does not match"
                    elif record.get("prev_hash") != previous_hash:
                        error = "prev_hash does not match the previous record"
                    elif _digest({key: value for key, value in record.items() if key != "hash"}) != record.get("hash"):
                        error = "record hash does not match its contents"
        else:
            continue
        if error:
            return {
                "engagement_id": engagement_id,
                "valid": False,
                "events": count,
                "first_invalid_seq": count + 1,
                "error": f"line {number}: {error}",
            }
        count += 1
        previous_hash = record["hash"]
    return {
        "engagement_id": engagement_id,
        "valid": True,
        "events": count,
        "first_invalid_seq": None,
        "error": None,
        "last_hash": previous_hash,
    }


def snapshot_audit(
    engagement_id: str, destination: BinaryIO, *, cancel_event: threading.Event | None = None
) -> dict[str, Any]:
    """Copy and verify an existing audit file while holding its shared lock.

    Unlike the public audit reader, evidence export must fail when the audit
    is missing. Directory-relative opens reject every symlink below the
    engagement root, including a link substituted during traversal.
    """
    with _open_events(engagement_id) as source:
        if cancel_event is None:
            fcntl.flock(source.fileno(), fcntl.LOCK_SH)
        else:
            while True:
                if cancel_event.is_set():
                    raise CancelledError("evidence operation cancelled")
                try:
                    fcntl.flock(source.fileno(), fcntl.LOCK_SH | fcntl.LOCK_NB)
                    break
                except BlockingIOError:
                    cancel_event.wait(0.05)
        try:
            before = os.fstat(source.fileno())
            while True:
                if cancel_event is not None and cancel_event.is_set():
                    raise CancelledError("evidence operation cancelled")
                block = source.read(1024 * 1024)
                if not block:
                    break
                destination.write(block)
            after = os.fstat(source.fileno())
            if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
                after.st_size, after.st_mtime_ns, after.st_ctime_ns
            ):
                raise ValueError("audit changed while its snapshot was copied")
            destination.flush()
            destination.seek(0)
            report = verify_audit_stream(destination, engagement_id, cancel_event=cancel_event)
            if not report["valid"]:
                raise ValueError(f"invalid audit snapshot: {report['error']}")
            destination.seek(0)
            return report
        finally:
            fcntl.flock(source.fileno(), fcntl.LOCK_UN)
