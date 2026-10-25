"""Offline, engagement-scoped evidence bundles with streaming integrity checks."""

from __future__ import annotations

from concurrent.futures import CancelledError
from contextlib import contextmanager
from datetime import datetime, timezone
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import tarfile
import tempfile
import threading
from typing import Any, BinaryIO, IO, Iterator, cast
import uuid

from .audit import record_event, snapshot_audit, verify_audit_stream
from . import engagements, envelope, limits
from .engagements import get_engagement
from .errors import OcError


EVIDENCE_SCHEMA_VERSION = 1
MAX_SELECTED_FILES = 10000
MAX_MANIFEST_BYTES = 8 * 1024 * 1024
CHUNK_BYTES = 1024 * 1024
INTEGRITY_NOTE = (
    "Checks establish archive and audit-chain consistency. Retain the archive SHA-256 "
    "separately to detect whole-bundle replacement; an internally valid audit chain "
    "alone cannot establish authenticity or completeness."
)
_INTEGRITY_LIMITATION = (
    "This bundle is integrity-only: the checks establish internal archive and audit-chain consistency, "
    "not authenticity. Retain the archive SHA-256 separately to detect whole-bundle replacement."
)
_SHA256 = re.compile(r"[0-9a-f]{64}")


def _check_cancel(cancel_event: threading.Event | None) -> None:
    if cancel_event is not None and cancel_event.is_set():
        raise CancelledError("evidence operation cancelled")


def _relative(value: str) -> tuple[str, ...]:
    if not isinstance(value, str) or not value or len(value) > 4096:
        raise OcError(
            "invalid_argument",
            "evidence paths must be non-empty engagement-relative paths of at most 4096 characters",
        )
    if "\x00" in value or "\\" in value or value.startswith("/"):
        raise OcError("invalid_argument", "evidence paths must be engagement-relative POSIX paths")
    parts = tuple(value.split("/"))
    if any(part in ("", ".", "..") for part in parts):
        raise OcError("invalid_argument", "evidence paths must not contain traversal or empty components")
    return parts


@contextmanager
def _parent(root: Path, parts: tuple[str, ...], *, create: bool = False) -> Iterator[int]:
    expected = engagements.WORKSPACE / "engagements" / root.name
    if root != expected or expected.resolve() != expected:
        raise OcError("invalid_argument", "engagement namespace must not contain symlinks")
    descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for component in parts[:-1]:
            if create:
                try:
                    os.mkdir(component, mode=0o700, dir_fd=descriptor)
                except FileExistsError:
                    pass
            child = os.open(component, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        yield descriptor
    finally:
        os.close(descriptor)


@contextmanager
def _open_regular(root: Path, path: str) -> Iterator[BinaryIO]:
    parts = _relative(path)
    with _parent(root, parts) as descriptor:
        try:
            source_fd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
        except FileNotFoundError as exc:
            raise OcError("not_found", f"evidence input does not exist: {path}", details={"path": path}) from exc
        except PermissionError as exc:
            raise OcError(
                "permission_denied", f"evidence input cannot be opened: {path}", details={"path": path}
            ) from exc
        except OSError as exc:
            raise OcError("invalid_argument", f"evidence input must be a regular file: {path}",
                          details={"path": path}) from exc
    if not stat.S_ISREG(os.fstat(source_fd).st_mode):
        os.close(source_fd)
        raise OcError("invalid_argument", f"evidence input must be a regular file: {path}")
    with os.fdopen(source_fd, "rb") as source:
        yield source


def _identity(value: os.stat_result) -> tuple[int, ...]:
    return value.st_dev, value.st_ino, value.st_size, value.st_mtime_ns, value.st_ctime_ns


def _unchanged(source: BinaryIO, before: os.stat_result) -> None:
    if _identity(os.fstat(source.fileno())) != _identity(before):
        raise OcError("conflict", "evidence source changed while it was being read")


def _hash_stream(source: BinaryIO, cancel_event: threading.Event | None) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    while True:
        _check_cancel(cancel_event)
        block = source.read(CHUNK_BYTES)
        if not block:
            return digest.hexdigest(), size
        digest.update(block)
        size += len(block)


class _HashingReader:
    def __init__(self, source: IO[bytes], cancel_event: threading.Event | None):
        self.source = source
        self.cancel_event = cancel_event
        self.digest = hashlib.sha256()
        self.size = 0

    def _record(self, block: bytes) -> bytes:
        self.digest.update(block)
        self.size += len(block)
        return block

    def read(self, size: int = -1) -> bytes:
        _check_cancel(self.cancel_event)
        return self._record(self.source.read(size))

    def readline(self, size: int = -1) -> bytes:
        _check_cancel(self.cancel_event)
        return self._record(self.source.readline(size))


def _bounded_tarinfo(cancel_event: threading.Event | None) -> type[tarfile.TarInfo]:
    extension_bytes = 0
    extension_count = 0

    class BoundedTarInfo(tarfile.TarInfo):
        def _reject_sparse(self, *args: Any, **kwargs: Any) -> None:
            raise ValueError("archive sparse members are unsupported")

        _proc_gnusparse_00 = _reject_sparse
        _proc_gnusparse_01 = _reject_sparse
        _proc_gnusparse_10 = _reject_sparse

        def _proc_member(self, archive: tarfile.TarFile) -> tarfile.TarInfo | None:
            nonlocal extension_bytes, extension_count
            _check_cancel(cancel_event)
            if self.type in (tarfile.XHDTYPE, tarfile.XGLTYPE, tarfile.SOLARIS_XHDTYPE,
                             tarfile.GNUTYPE_LONGNAME, tarfile.GNUTYPE_LONGLINK):
                extension_bytes += self.size
                extension_count += 1
                # tarfile consumes extension payloads before yielding members.
                # Bound these before its parser can allocate the declared size.
                if self.size > CHUNK_BYTES or extension_bytes > MAX_MANIFEST_BYTES or extension_count > 100:
                    raise ValueError("archive extension metadata exceeds verification limits")
            elif self.type not in (tarfile.REGTYPE, tarfile.AREGTYPE):
                raise ValueError("archive members must be regular files")
            else:
                extension_count = 0
            return super()._proc_member(archive)  # type: ignore[misc]  # tarfile's pre-allocation hook is absent from typeshed.

    return BoundedTarInfo


class _CancellableReader:
    def __init__(self, source: gzip.GzipFile, cancel_event: threading.Event | None):
        self.source = source
        self.cancel_event = cancel_event

    def read(self, size: int = -1) -> bytes:
        _check_cancel(self.cancel_event)
        return self.source.read(size)


def _copy_regular(
    archive: tarfile.TarFile, source: BinaryIO, name: str, size: int, cancel_event: threading.Event | None
) -> dict[str, Any]:
    member = tarfile.TarInfo(name)
    member.size = size
    member.mode = 0o600
    reader = _HashingReader(source, cancel_event)
    archive.addfile(member, reader)  # type: ignore[arg-type]
    _check_cancel(cancel_event)
    if reader.size != size:
        raise OcError("conflict", "evidence source changed while it was being copied")
    return {"path": name, "size": size, "sha256": reader.digest.hexdigest()}


def _json_bytes(value: dict[str, Any]) -> bytes:
    encoded = (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True) + "\n").encode("utf-8")
    if len(encoded) > MAX_MANIFEST_BYTES:
        raise limits.raise_exceeded(
            "evidence.max_manifest_bytes",
            "evidence JSON metadata exceeds the 8 MiB limit",
            effective=MAX_MANIFEST_BYTES,
            requested=len(encoded),
        )
    return encoded


def export_evidence(
    engagement_id: str,
    paths: list[str],
    output_path: str | None = None,
    *,
    cancel_event: threading.Event | None = None,
) -> dict[str, Any]:
    """Bundle selected regular files, engagement metadata, and a locked audit snapshot.

    Reports are included only when explicitly selected. Session configuration,
    credentials, and other workspace files are never discovered automatically.
    Existing outputs are never overwritten.
    """
    _check_cancel(cancel_event)
    try:
        engagement = get_engagement(engagement_id)
    except ValueError as exc:
        raise OcError("engagement_not_found", str(exc), details={"engagement_id": engagement_id}) from exc
    root = Path(engagement["workspace"])
    if not isinstance(paths, list) or not paths:
        raise OcError("invalid_argument", "paths must select between 1 and 10000 regular files")
    if len(paths) > MAX_SELECTED_FILES:
        raise limits.raise_exceeded(
            "evidence.max_files",
            "paths must select between 1 and 10000 regular files",
            effective=MAX_SELECTED_FILES,
            requested=len(paths),
            parameter="paths",
        )
    for path in paths:
        _relative(path)
    if len(set(paths)) != len(paths):
        raise OcError("invalid_argument", "paths must not contain duplicates")
    output_path = output_path or f"evidence/export-{uuid.uuid4().hex}.tar.gz"
    output_parts = _relative(output_path)
    if output_path in paths:
        raise OcError("invalid_argument", "evidence output must not overlap an input")
    if not output_path.endswith(".tar.gz"):
        raise OcError("invalid_argument", "evidence output must use the .tar.gz extension")
    metadata = {key: engagement[key] for key in (
        "schema_version", "engagement_id", "name", "targets", "objective", "created_at"
    )}
    metadata_bytes = _json_bytes(metadata)
    # Bound manifest growth before reading payloads or creating the output.
    selected_bytes = sum(len(path.encode("utf-8")) for path in paths)
    if selected_bytes > MAX_MANIFEST_BYTES // 4:
        raise limits.raise_exceeded(
            "evidence.max_manifest_bytes",
            "selected evidence paths exceed the manifest size limit",
            effective=MAX_MANIFEST_BYTES // 4,
            requested=selected_bytes,
        )

    with _parent(root, output_parts, create=True) as destination:
        try:
            os.stat(output_parts[-1], dir_fd=destination, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise OcError("already_exists", "evidence output already exists", details={"path": output_path})
        temporary_name = f".evidence-{uuid.uuid4().hex}.tmp"
        descriptor = os.open(
            temporary_name, os.O_CREAT | os.O_EXCL | os.O_RDWR | os.O_NOFOLLOW, 0o600, dir_fd=destination
        )
        published = False
        try:
            with os.fdopen(descriptor, "w+b") as output, tempfile.TemporaryFile(mode="w+b") as snapshot:
                try:
                    audit = snapshot_audit(engagement_id, snapshot, cancel_event=cancel_event)
                except ValueError as exc:
                    raise OcError(
                        "integrity_mismatch",
                        str(exc),
                        details={"engagement_id": engagement_id},
                    ) from exc
                entries = []
                with tarfile.open(fileobj=output, mode="w|gz", format=tarfile.PAX_FORMAT) as archive:
                    entries.append(_copy_regular(archive, io.BytesIO(metadata_bytes), "engagement.json", len(metadata_bytes), cancel_event))
                    snapshot.seek(0, os.SEEK_END)
                    snapshot_size = snapshot.tell()
                    snapshot.seek(0)
                    entries.append(_copy_regular(archive, snapshot, "audit/events.jsonl", snapshot_size, cancel_event))
                    for path in paths:
                        _check_cancel(cancel_event)
                        with _open_regular(root, path) as source:
                            before = os.fstat(source.fileno())
                            entry = _copy_regular(archive, source, f"files/{path}", before.st_size, cancel_event)
                            _unchanged(source, before)
                            entries.append(entry)
                    audit_head = {"path": "audit/events.jsonl", "events": audit["events"], "last_hash": audit["last_hash"]}
                    manifest = {
                        "schema_version": EVIDENCE_SCHEMA_VERSION,
                        "engagement_id": engagement_id,
                        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                        "files": entries,
                        "selected_paths": paths,
                        "audit": audit_head,
                        "integrity_note": INTEGRITY_NOTE,
                    }
                    manifest_bytes = _json_bytes(manifest)
                    _copy_regular(archive, io.BytesIO(manifest_bytes), "manifest.json", len(manifest_bytes), cancel_event)
                output.flush()
                os.fsync(output.fileno())
                output.seek(0)
                archive_hash, archive_size = _hash_stream(output, cancel_event)
                _check_cancel(cancel_event)
                # A hard link publishes a complete file atomically and refuses
                # to overwrite a destination created concurrently.
                os.link(temporary_name, output_parts[-1], src_dir_fd=destination, dst_dir_fd=destination, follow_symlinks=False)
                published = True
                _check_cancel(cancel_event)
                record_event(engagement_id, {
                    "event": "evidence.export", "path": output_path, "sha256": archive_hash,
                    "files": len(paths), "audit_events": audit["events"], "audit_last_hash": audit["last_hash"],
                }, cancel_event=cancel_event)
                _check_cancel(cancel_event)
                return {
                    "schema_version": EVIDENCE_SCHEMA_VERSION,
                    "engagement_id": engagement_id,
                    "path": output_path,
                    "sha256": archive_hash,
                    "size": archive_size,
                    "files": len(paths),
                    "audit": audit_head,
                    "integrity_note": INTEGRITY_NOTE,
                    "coverage": envelope.coverage("complete", exhausted=True),
                    "limitations": [
                        _INTEGRITY_LIMITATION,
                        "The bundle contains only the paths the caller selected; absence of a file from it "
                        "is not evidence that the file does not exist.",
                    ],
                }
        except BaseException:
            if published:
                os.unlink(output_parts[-1], dir_fd=destination)
            raise
        finally:
            os.unlink(temporary_name, dir_fd=destination)


def _validate_manifest(
    manifest: Any, actual: dict[str, dict[str, Any]], engagement_id: str, audit: dict[str, Any] | None
) -> None:
    if not isinstance(manifest, dict) or type(manifest.get("schema_version")) is not int or manifest["schema_version"] != EVIDENCE_SCHEMA_VERSION:
        raise ValueError("invalid or unsupported evidence manifest")
    if manifest.get("engagement_id") != engagement_id:
        raise ValueError("manifest engagement_id does not match")
    entries = manifest.get("files")
    selected = manifest.get("selected_paths")
    if not isinstance(entries, list) or not isinstance(selected, list) or not 1 <= len(selected) <= MAX_SELECTED_FILES:
        raise ValueError("manifest requires files and selected_paths")
    for value in selected:
        _relative(value)
    if len(set(selected)) != len(selected):
        raise ValueError("manifest contains duplicate selected paths")
    expected_names = {"engagement.json", "audit/events.jsonl", *(f"files/{path}" for path in selected)}
    expected: dict[str, dict[str, Any]] = {}
    for entry in entries:
        if not isinstance(entry, dict) or not isinstance(entry.get("path"), str):
            raise ValueError("invalid manifest file entry")
        name = entry["path"]
        _relative(name)
        if name in expected:
            raise ValueError("duplicate manifest file entry")
        if type(entry.get("size")) is not int or entry["size"] < 0 or not isinstance(entry.get("sha256"), str) or not _SHA256.fullmatch(entry["sha256"]):
            raise ValueError("invalid manifest file size or SHA-256")
        expected[name] = {"path": name, "size": entry["size"], "sha256": entry["sha256"]}
    if set(expected) != expected_names or set(actual) != expected_names:
        raise ValueError("archive contains missing or extra members")
    if expected != actual:
        raise ValueError("archive file sizes or SHA-256 hashes do not match the manifest")
    if audit is None or not audit["valid"]:
        raise ValueError(f"invalid audit snapshot: {audit['error'] if audit else 'missing audit'}")
    expected_head = {"path": "audit/events.jsonl", "events": audit["events"], "last_hash": audit["last_hash"]}
    head = manifest.get("audit")
    if not isinstance(head, dict) or type(head.get("events")) is not int or head != expected_head:
        raise ValueError("audit snapshot head does not match the manifest")


def verify_evidence(
    engagement_id: str,
    path: str,
    expected_sha256: str | None = None,
    *,
    cancel_event: threading.Event | None = None,
) -> dict[str, Any]:
    """Verify a bundle without extracting files or trusting its member paths.

    A caller-supplied ``expected_sha256`` that does not match is a refusal
    (``integrity_mismatch``): the archive is not the artifact the caller named,
    so verifying its members would certify the wrong bundle. Damage found while
    inspecting the archive stays a finding (``valid`` false plus ``error`` and
    ``error_code``), because the computed digest and the failing check are the
    evidence the caller needs.
    """
    _check_cancel(cancel_event)
    try:
        root = Path(get_engagement(engagement_id)["workspace"])
    except ValueError as exc:
        raise OcError("engagement_not_found", str(exc), details={"engagement_id": engagement_id}) from exc
    _relative(path)
    if expected_sha256 is not None:
        if not isinstance(expected_sha256, str) or not _SHA256.fullmatch(expected_sha256.lower()):
            raise OcError(
                "invalid_argument",
                "expected_sha256 must be a 64-character SHA-256 hex digest",
                details={"parameter": "expected_sha256"},
            )
        expected_sha256 = expected_sha256.lower()
    result: dict[str, Any] = {
        "schema_version": EVIDENCE_SCHEMA_VERSION, "engagement_id": engagement_id,
        "path": path, "valid": False, "error": None, "error_code": None,
        "expected_sha256": expected_sha256, "integrity_note": INTEGRITY_NOTE,
    }
    with _open_regular(root, path) as source:
        before = os.fstat(source.fileno())
        archive_hash, size = _hash_stream(source, cancel_event)
        result.update({"sha256": archive_hash, "size": size})
        if expected_sha256 is not None and archive_hash != expected_sha256:
            raise OcError(
                "integrity_mismatch",
                "archive SHA-256 does not match the independently supplied hash",
                details={"path": path, "sha256": archive_hash, "expected_sha256": expected_sha256},
            )
        source.seek(0)
        actual: dict[str, dict[str, Any]] = {}
        seen: set[str] = set()
        manifest: Any = None
        audit = None
        try:
            # GzipFile checks stream CRCs; ignore_zeros also discovers members
            # appended after ordinary tar end markers, rather than hiding them.
            with gzip.GzipFile(fileobj=source, mode="rb") as decoded:
                with tarfile.open(name=None, fileobj=cast(Any, _CancellableReader(decoded, cancel_event)), mode="r|",
                                  tarinfo=_bounded_tarinfo(cancel_event), ignore_zeros=True) as archive:
                    for member in archive:
                        _check_cancel(cancel_event)
                        _relative(member.name)
                        if member.name in seen:
                            raise ValueError("archive contains duplicate members")
                        seen.add(member.name)
                        if len(seen) > MAX_SELECTED_FILES + 3:
                            raise ValueError("archive exceeds the 10000 selected-file limit")
                        if not member.isreg():
                            raise ValueError("archive members must be regular files")
                        if member.name not in ("manifest.json", "engagement.json", "audit/events.jsonl") and not member.name.startswith("files/"):
                            raise ValueError("archive contains an unexpected member")
                        payload = archive.extractfile(member)
                        if payload is None:
                            raise ValueError("archive member cannot be read")
                        reader = _HashingReader(payload, cancel_event)
                        if member.name in ("manifest.json", "engagement.json"):
                            if member.size > MAX_MANIFEST_BYTES:
                                raise ValueError("archive JSON metadata exceeds the 8 MiB limit")
                            value = json.loads(reader.read(MAX_MANIFEST_BYTES + 1))
                            if member.name == "manifest.json":
                                manifest = value
                            elif not isinstance(value, dict) or value.get("engagement_id") != engagement_id:
                                raise ValueError("engagement metadata does not match engagement_id")
                        elif member.name == "audit/events.jsonl":
                            audit = verify_audit_stream(reader, engagement_id, cancel_event=cancel_event)  # type: ignore[arg-type]
                            if not audit["valid"]:
                                raise ValueError(f"invalid audit snapshot: {audit['error']}")
                        else:
                            while reader.read(CHUNK_BYTES):
                                pass
                        if reader.size != member.size:
                            raise ValueError("archive member length does not match its header")
                        if member.name != "manifest.json":
                            actual[member.name] = {"path": member.name, "size": reader.size, "sha256": reader.digest.hexdigest()}
            _validate_manifest(manifest, actual, engagement_id, audit)
            _unchanged(source, before)
        except (ValueError, TypeError, KeyError, tarfile.TarError, OSError, EOFError, UnicodeError, RecursionError) as exc:
            result["error"] = str(exc)
            result["error_code"] = "integrity_mismatch"
            result["coverage"] = envelope.coverage("unknown", examined=size, exhausted=False)
            result["limitations"] = [
                f"Verification failed: {exc}. The bundle must not be trusted; re-export it and compare "
                "against a separately retained digest.",
                _INTEGRITY_LIMITATION,
            ]
            return result
        result.update({"valid": True, "files": len(actual) - 2, "audit": manifest["audit"]})
        result["coverage"] = envelope.coverage("complete", examined=size, total=size, exhausted=True)
        result["limitations"] = [_INTEGRITY_LIMITATION]
        return result
