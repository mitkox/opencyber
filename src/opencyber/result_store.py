"""Retained tool results and their content-addressed identity.

Every result already carries an ``evidence`` block with an id and digest (see
``envelope``). This module makes that id retrievable: it optionally persists the
returned payload under the engagement and answers ``oc_result_get`` and
``oc_result_list``.

Retention is explicit and bounded, because tool output can contain credentials,
target data, and operator secrets:

``OPENCYBER_RESULT_RETENTION``
    ``off``    - no index and no content; only the per-result digest exists.
    ``digest`` - default. The index records id, tool, digest, size, and time, so
                 a digest can be looked up and cited without retaining bytes.
    ``full``   - the redacted payload is stored as JSON, capped per record and
                 pruned by count and total size.

A stored record is not a signature. The digest proves the payload returned for
one call; it does not prove the target's state, and a whole-record rewrite is
not detectable without a separately retained copy of the digest.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
import fcntl
import json
import os
from pathlib import Path
import stat
import tempfile
import threading
from typing import Any, Iterator

from . import envelope as envelope_module
from .audit import redact
from .engagements import get_engagement, resolve_engagement_path
from .errors import OcError


RETENTION_ENV = "OPENCYBER_RESULT_RETENTION"
RETENTION_MODES = ("off", "digest", "full")
DEFAULT_RETENTION = "digest"

MAX_RETAINED_RECORDS = 500
MAX_RETAINED_BYTES = 32 * 1024 * 1024
MAX_RECORD_BYTES = 1024 * 1024
INDEX_NAME = "index.jsonl"

_lock = threading.Lock()


def retention_mode() -> str:
    """Resolve the configured retention mode, failing closed on a typo."""
    raw = os.environ.get(RETENTION_ENV, "").strip().lower()
    if not raw:
        return DEFAULT_RETENTION
    if raw not in RETENTION_MODES:
        raise OcError(
            "invalid_argument",
            f"{RETENTION_ENV} must be one of {', '.join(RETENTION_MODES)}, got {raw!r}",
            details={"setting": RETENTION_ENV, "value": raw},
            remediation=f"Set {RETENTION_ENV} to off, digest, or full, or unset it.",
        )
    return raw


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _results_root(engagement_id: str) -> Path:
    get_engagement(engagement_id)
    path = resolve_engagement_path(engagement_id, ".opencyber/results", must_exist=False)
    path.mkdir(parents=True, exist_ok=True)
    return path


def _index_path(engagement_id: str) -> Path:
    return _results_root(engagement_id) / INDEX_NAME


def _record_path(engagement_id: str, evidence_id: str) -> Path:
    return _results_root(engagement_id) / f"{evidence_id}.json"


@contextmanager
def _store_lock(engagement_id: str) -> Iterator[None]:
    """Serialize index, payload and pruning transactions across MCP processes."""
    path = _results_root(engagement_id) / ".lock"
    with _lock:
        descriptor = os.open(path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise OcError("integrity_mismatch", "result store lock must be a regular file")
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
        finally:
            os.close(descriptor)


def _read_regular(path: Path) -> str:
    """Never follow a retained record or index symlink outside its workspace."""
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "r", encoding="utf-8") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise OcError("integrity_mismatch", "retained data must be a regular file")
            return handle.read()
    except FileNotFoundError:
        raise
    except (OSError, UnicodeError) as exc:
        raise OcError("integrity_mismatch", "retained data could not be read safely",
                      details={"record": path.name}) from exc


def _atomic_write(path: Path, content: str) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=".result-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass


def _validate_evidence_id(evidence_id: object) -> str:
    if not isinstance(evidence_id, str) or not evidence_id.startswith("oc_ev_"):
        raise OcError("invalid_argument", "evidence_id must be an oc_ev_ identifier", details={"evidence_id": evidence_id})
    if len(evidence_id) != len("oc_ev_") + 40 or not all(char in "0123456789abcdef" for char in evidence_id[6:]):
        raise OcError("invalid_argument", "evidence_id does not match the recorded shape", details={"evidence_id": evidence_id})
    return evidence_id


def _read_index(engagement_id: str) -> list[dict[str, Any]]:
    path = _index_path(engagement_id)
    try:
        contents = _read_regular(path)
    except FileNotFoundError:
        return []
    records: list[dict[str, Any]] = []
    for number, line in enumerate(contents.splitlines(), 1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
            if not isinstance(record, dict):
                raise ValueError("index row must be an object")
            _validate_evidence_id(record.get("id"))
        except (ValueError, OcError) as exc:
            raise OcError("integrity_mismatch", "retained result index is corrupt",
                          details={"line": number}) from exc
        records.append(record)
    return records


def _write_index(engagement_id: str, records: list[dict[str, Any]]) -> None:
    path = _index_path(engagement_id)
    _atomic_write(path, "".join(json.dumps(record, sort_keys=True) + "\n" for record in records))


def _prune(engagement_id: str, records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    kept: list[dict[str, Any]] = []
    total = 0
    for record in reversed(records):
        size = int(record.get("bytes") or 0)
        if len(kept) >= MAX_RETAINED_RECORDS or total + size > MAX_RETAINED_BYTES:
            path = _record_path(engagement_id, record["id"])
            try:
                path.unlink()
            except FileNotFoundError:
                pass
            continue
        kept.append(record)
        total += size
    return list(reversed(kept))


def retain(engagement_id: str | None, payload: dict[str, Any]) -> dict[str, Any]:
    """Record one finalized result according to the retention mode.

    Returns the ``evidence`` block to advertise, with ``retained`` set
    truthfully. A payload above the per-record cap is indexed without content
    and reports why.
    """
    evidence = dict(payload.get("evidence") or {})
    mode = retention_mode()
    if mode == "off" or not evidence.get("id") or not engagement_id:
        evidence["retained"] = False
        return evidence
    evidence_id = _validate_evidence_id(evidence["id"])
    record = {
        "id": evidence_id,
        "tool": str((payload.get("contract") or {}).get("tool") or ""),
        "sha256": evidence.get("sha256"),
        "bytes": evidence.get("bytes"),
        "created_at": _now(),
        "retained": mode == "full",
    }
    with _store_lock(engagement_id):
        records = [existing for existing in _read_index(engagement_id) if existing.get("id") != evidence_id]
        if mode == "full":
            material = {key: value for key, value in payload.items() if key != "evidence"}
            encoded = envelope_module.canonical_json(redact(material))
            if len(encoded.encode("utf-8")) > MAX_RECORD_BYTES:
                record["retained"] = False
                record["reason"] = "record_too_large"
            else:
                path = _record_path(engagement_id, evidence_id)
                _atomic_write(path, encoded)
        if not record["retained"]:
            # A repeated digest must not expose content from an earlier full
            # record after it was replaced by a digest-only/over-cap record.
            _record_path(engagement_id, evidence_id).unlink(missing_ok=True)
        records.append(record)
        records = _prune(engagement_id, records)
        _write_index(engagement_id, records)
    evidence["retained"] = bool(record["retained"])
    if not evidence["retained"]:
        evidence["retention_note"] = (
            "Content was not retained; the digest still identifies what this call returned."
            if mode == "digest"
            else "Content exceeded the per-record cap and was not retained."
        )
    return evidence


def get_result(engagement_id: str, evidence_id: str) -> dict[str, Any]:
    """Return one retained result, or explain why only the digest exists."""
    _validate_evidence_id(evidence_id)
    with _store_lock(engagement_id):
        records = _read_index(engagement_id)
        record = next((entry for entry in records if entry["id"] == evidence_id), None)
        if record is None:
            raise OcError(
                "not_found",
                f"no retained result for {evidence_id} in this engagement",
                details={"engagement_id": engagement_id, "evidence_id": evidence_id, "retention": retention_mode()},
                remediation="Check the identifier, or set OPENCYBER_RESULT_RETENTION=full before running the tool again.",
            )
        payload: dict[str, Any] | None = None
        if record.get("retained"):
            try:
                payload = json.loads(_read_regular(_record_path(engagement_id, evidence_id)))
                if not isinstance(payload, dict):
                    raise ValueError("retained result must be an object")
            except (FileNotFoundError, ValueError) as exc:
                raise OcError("integrity_mismatch", "retained result is missing or corrupt",
                              details={"evidence_id": evidence_id}) from exc
    return {
        "engagement_id": engagement_id,
        "evidence": dict(record),
        "retained": payload is not None,
        "result": payload,
    }


def list_results(
    engagement_id: str,
    tool: str | None = None,
    limit: int = 50,
    offset: int = 0,
) -> dict[str, Any]:
    """List indexed results with coverage the caller can trust."""
    if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 500:
        raise OcError("invalid_argument", "limit must be between 1 and 500", details={"parameter": "limit"})
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise OcError("invalid_argument", "offset must be a non-negative integer", details={"parameter": "offset"})
    with _store_lock(engagement_id):
        records = _read_index(engagement_id)
    if tool:
        records = [record for record in records if record.get("tool") == tool]
    total = len(records)
    selected = records[offset : offset + limit]
    next_offset = offset + len(selected)
    exhausted = next_offset >= total
    return {
        "engagement_id": engagement_id,
        "retention": retention_mode(),
        "tool": tool,
        "total": total,
        "offset": offset,
        "limit": limit,
        "results": selected,
        "coverage": envelope_module.coverage(
            "empty" if total == 0 else ("complete" if exhausted else "partial"),
            examined=next_offset,
            total=total,
            exhausted=exhausted,
            next_offset=None if exhausted else next_offset,
        ),
    }
