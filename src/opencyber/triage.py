"""Offline, bounded analysis of engagement artifacts without executing inputs."""

from __future__ import annotations

from concurrent.futures import CancelledError
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone as datetime_timezone
from decimal import Decimal, InvalidOperation, ROUND_FLOOR, localcontext
import csv
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import stat
import subprocess
import tempfile
import threading
from typing import Any, BinaryIO, Iterator
import uuid
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from . import __version__, engagements, envelope, limits
from .audit import record_event
from .engagements import resolve_engagement_path
from .errors import OcError
from .indicators import extract_indicators


DEFAULT_MAX_BYTES = 16 * 1024 * 1024
DEFAULT_MAX_RECORDS = 10_000
_MAX_STRINGS = 10_000
_OUTPUT_LIMIT = 16 * 1024 * 1024
#: Incomplete-analysis reason -> (registry id, parameter) for the cap that caused it.
_CAP_REASONS: tuple[tuple[str, str, str], ...] = (
    ("content_limit", "triage.max_bytes", "max_bytes"),
    ("record_limit", "triage.max_records", "max_records"),
    ("packet_limit", "triage.max_packets", "max_packets"),
)
_TIMESTAMP = re.compile(r"^(\d{4}-\d\d-\d\d[Tt ]\d\d:\d\d:\d\d)"
                        r"(?:\.(\d+))?([Zz]|[+-]\d\d:\d\d)?$")
_TEXT_PREFIX = re.compile(r"^(\d{4}-\d\d-\d\d[Tt ]\d\d:\d\d:\d\d"
                         r"(?:\.\d+)?(?:[Zz]|[+-]\d\d:\d\d)?)(?=\s|$)")
_PCAP_FIELDS = (
    "frame.number", "frame.time_epoch", "frame.len", "frame.protocols",
    "ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "tcp.srcport", "udp.srcport",
    "tcp.dstport", "udp.dstport", "dns.qry.name", "dns.a", "dns.aaaa",
    "http.request.method", "http.host", "http.request.uri", "tls.handshake.extensions_server_name",
)


def _check_cancel(cancel_event: threading.Event | None) -> None:
    if cancel_event is not None and cancel_event.is_set():
        raise CancelledError("artifact analysis cancelled")


def _positive(value: int, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise OcError("invalid_argument", f"{name} must be a positive integer", details={"parameter": name})
    return value


def _bounded(value: int, name: str, limit_id: str) -> int:
    """Reject a request above the registered ceiling for this dimension."""
    _positive(value, name)
    maximum = limits.limit_for(limit_id).maximum
    if maximum is not None and value > maximum:
        raise limits.raise_exceeded(
            limit_id,
            f"{name} exceeds the supported maximum of {int(maximum)}",
            effective=maximum,
            requested=value,
            parameter=name,
        )
    return value


@contextmanager
def _directory(path: Path) -> Iterator[int]:
    """Open an absolute directory without following any symlink component."""
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    descriptor = os.open(path.anchor, flags)
    try:
        try:
            for part in path.parts[1:]:
                next_descriptor = os.open(part, flags, dir_fd=descriptor)
                os.close(descriptor)
                descriptor = next_descriptor
        except OSError as exc:
            raise OcError(
                "invalid_argument",
                "engagement paths must use real directories without symlinks",
                details={"path": path.name},
            ) from exc
        yield descriptor
    finally:
        os.close(descriptor)


def _relative_path(value: str) -> Path:
    if not isinstance(value, str) or not value or "\x00" in value:
        raise OcError("invalid_argument", "path must be a non-empty engagement-relative path")
    raw = Path(value)
    if raw.is_absolute() or ".." in raw.parts or raw == Path("."):
        raise OcError("invalid_argument", "path must be engagement-relative without traversal")
    return raw


@contextmanager
def _source(engagement_id: str, value: str) -> Iterator[tuple[BinaryIO, Path, str]]:
    relative = _relative_path(value)
    root = resolve_engagement_path(engagement_id, ".")
    if root != engagements.WORKSPACE / "engagements" / engagement_id:
        raise OcError("invalid_argument", "engagement namespace must not contain symlinks")
    # Keep the existing namespace check, then use descriptors to prevent a
    # symlink substitution between checking a component and opening the file.
    resolved = resolve_engagement_path(engagement_id, value)
    if resolved != root / relative:
        raise OcError("invalid_argument", "artifact paths must not contain symlinks")
    with _directory(root / relative.parent) as parent:
        try:
            descriptor = os.open(relative.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
        except FileNotFoundError as exc:
            raise OcError(
                "not_found",
                f"artifact does not exist: {value}",
                details={"path": value, "engagement_id": engagement_id},
            ) from exc
        except OSError as exc:
            raise OcError(
                "invalid_argument",
                "artifact must be a regular file without symlinks",
                details={"path": value},
            ) from exc
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            os.close(descriptor)
            raise OcError("invalid_argument", "artifact must be a regular file", details={"path": value})
        with os.fdopen(descriptor, "rb") as handle:
            yield handle, root, relative.as_posix()


def _read_source(
    handle: BinaryIO, path: str, max_bytes: int, cancel_event: threading.Event | None,
) -> tuple[dict[str, Any], bytes]:
    before = os.fstat(handle.fileno())
    digest = hashlib.sha256()
    content = bytearray()
    size = 0
    while True:
        _check_cancel(cancel_event)
        chunk = handle.read(1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
        size += len(chunk)
        content.extend(chunk[:max(0, max_bytes - len(content))])
    _check_cancel(cancel_event)
    after = os.fstat(handle.fileno())
    if (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (
        after.st_size, after.st_mtime_ns, after.st_ctime_ns,
    ) or size != after.st_size:
        raise OcError("conflict", "source changed during analysis; retry on an immutable copy",
                      details={"path": path})
    return {
        "path": path,
        "size": size,
        "sha256": digest.hexdigest(),
        "hash_complete": True,
        "modified_at_ns": after.st_mtime_ns,
    }, bytes(content)


def _new_report(kind: str, engagement_id: str, source: dict[str, Any], parameters: dict[str, Any],
                content: bytes) -> dict[str, Any]:
    reasons = ["content_limit"] if source["size"] > len(content) else []
    return {
        "schema_version": 1,
        "kind": kind,
        "engagement_id": engagement_id,
        "created_at": datetime.now(datetime_timezone.utc).isoformat().replace("+00:00", "Z"),
        "tool": {"name": "OpenCyber", "version": __version__},
        "source": source,
        "parameters": parameters,
        "analysis_bytes": len(content),
        "complete": not reasons,
        "incomplete_reasons": reasons,
        "errors": [],
    }


def _incomplete(report: dict[str, Any], reason: str) -> None:
    report["complete"] = False
    if reason not in report["incomplete_reasons"]:
        report["incomplete_reasons"].append(reason)


def _limitations(report: dict[str, Any]) -> list[str]:
    """Translate incomplete-analysis reasons into concrete caller assumptions."""
    reasons = report["incomplete_reasons"]
    parameters = report["parameters"]
    examined = int(report["analysis_bytes"])
    total = int(report["source"]["size"])
    statements: list[str] = []
    if "content_limit" in reasons:
        statements.append(
            f"Analysis covered the first {examined} of {total} bytes; the remaining "
            f"{total - examined} bytes were not inspected and are not evidence of absence."
        )
    if "record_limit" in reasons:
        statements.append(
            f"Timeline analysis stopped at the {parameters['max_records']}-record cap after "
            f"{report['records_encountered']} records; later records are unexamined."
        )
    if "packet_limit" in reasons:
        statements.append(
            f"Packet analysis stopped at the {parameters['max_packets']}-packet cap after "
            f"{report['packets_processed']} packets; later packets are unexamined."
        )
    if "string_limit" in reasons:
        statements.append(
            f"Only the first {_MAX_STRINGS} printable strings were reported; the inspected bytes may hold more."
        )
    if "record_errors" in reasons:
        statements.append(
            f"{len(report['errors'])} record(s) could not be decoded, parsed, or resolved and are omitted from "
            "the timeline; they are inventoried under errors and do not prove the log is clean."
        )
    if "tool_unavailable" in reasons:
        statements.append("The capture could not be decoded with tshark; no packet facts were observed.")
    if "invalid_capture" in reasons:
        statements.append(
            "The input did not match a PCAP or PCAPNG signature; no packet facts were observed and the "
            "file must not be described as a parsed capture."
        )
    if "capture_parse_error" in reasons:
        statements.append(
            "The capture could not be fully decoded by tshark; packet facts are incomplete and errors "
            "names the decode failure."
        )
    if "output_limit" in reasons:
        statements.append(
            f"tshark output exceeded the {_OUTPUT_LIMIT}-byte capture cap and was truncated; "
            "packet facts beyond the cap were discarded."
        )
    return statements


def _limit_facts(report: dict[str, Any]) -> dict[str, Any] | None:
    """Return facts for the first cap that cut this analysis short, if any."""
    reasons = report["incomplete_reasons"]
    parameters = report["parameters"]
    for reason, limit_id, parameter in _CAP_REASONS:
        if reason in reasons and parameter in parameters:
            return limits.facts(limit_id, effective=parameters[parameter], parameter=parameter)
    return None


def _coverage_block(report: dict[str, Any]) -> dict[str, Any]:
    """Map the report's own completeness facts onto the result contract."""
    examined = int(report["analysis_bytes"])
    total = int(report["source"]["size"])
    complete = bool(report["complete"]) and examined >= total
    block: dict[str, Any] = {
        "coverage": envelope.coverage(
            "complete" if complete else "partial",
            examined=examined,
            total=total,
            exhausted=complete,
        ),
        "limitations": _limitations(report),
    }
    limit = _limit_facts(report)
    if limit is not None:
        block["limit"] = limit
    return block


def _save_report(root: Path, report: dict[str, Any], cancel_event: threading.Event | None) -> dict[str, Any]:
    """Publish a complete JSON file atomically in the fixed report directory."""
    _check_cancel(cancel_event)
    # No caller-selected output can overlap an input. Each report gets a fresh
    # unpredictable name, and all output components are opened with NOFOLLOW.
    with _directory(root / "evidence") as evidence:
        try:
            os.mkdir("triage", mode=0o700, dir_fd=evidence)
        except FileExistsError:
            pass
        try:
            directory = os.open("triage", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=evidence)
        except OSError as exc:
            raise OcError(
                "invalid_argument",
                "evidence/triage must be a real directory without symlinks",
                details={"path": "evidence/triage"},
            ) from exc
        name = f"{report['kind']}-{uuid.uuid4().hex}.json"
        temporary = f".{name}.tmp"
        published = False
        try:
            descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=directory)
            with os.fdopen(descriptor, "w", encoding="utf-8") as output:
                encoder = json.JSONEncoder(ensure_ascii=True, separators=(",", ":"), allow_nan=False)
                for chunk in encoder.iterencode(report):
                    _check_cancel(cancel_event)
                    output.write(chunk)
                output.write("\n")
                output.flush()
                os.fsync(output.fileno())
            _check_cancel(cancel_event)
            os.replace(temporary, name, src_dir_fd=directory, dst_dir_fd=directory)
            published = True
            audit = record_event(report["engagement_id"], {
                "event": "triage.analysis", "kind": report["kind"],
                "source": report["source"]["path"], "source_sha256": report["source"]["sha256"],
                "report_path": f"evidence/triage/{name}", "complete": report["complete"],
            }, cancel_event=cancel_event)
            _check_cancel(cancel_event)
        except BaseException:
            for candidate in (temporary, name) if published else (temporary,):
                try:
                    os.unlink(candidate, dir_fd=directory)
                except FileNotFoundError:
                    pass
            raise
        finally:
            os.close(directory)
    return {
        "engagement_id": report["engagement_id"],
        "source": report["source"],
        "report_path": f"evidence/triage/{name}",
        "complete": report["complete"],
        "incomplete_reasons": report["incomplete_reasons"],
        "error_count": len(report["errors"]),
        "summary": report["summary"],
        "audit": {"seq": audit["seq"], "hash": audit["hash"]},
        **_coverage_block(report),
    }


def _identify(content: bytes) -> str:
    for signature, label in ((b"\x7fELF", "ELF"), (b"MZ", "PE/DOS"), (b"%PDF-", "PDF"),
                             (b"PK\x03\x04", "ZIP"), (b"\x1f\x8b", "gzip"),
                             (b"\x89PNG\r\n\x1a\n", "PNG"), (b"\x0a\x0d\x0d\x0a", "PCAPNG")):
        if content.startswith(signature):
            return label
    if content[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
        return "PCAP"
    if not content:
        return "empty"
    try:
        content.decode("utf-8")
        return "UTF-8 text" if b"\0" not in content else "binary data"
    except UnicodeDecodeError:
        return "binary data"


def file_triage(
    engagement_id: str, path: str, max_bytes: int = DEFAULT_MAX_BYTES, min_string_length: int = 4,
    cancel_event: threading.Event | None = None,
) -> dict[str, Any]:
    """Hash the complete file and inspect only a bounded prefix as inert data."""
    _bounded(max_bytes, "max_bytes", "triage.max_bytes")
    _positive(min_string_length, "min_string_length")
    with _source(engagement_id, path) as (handle, root, relative):
        source, content = _read_source(handle, relative, max_bytes, cancel_event)
    report = _new_report("file_triage", engagement_id, source, {
        "max_bytes": max_bytes, "min_string_length": min_string_length, "max_strings": _MAX_STRINGS,
    }, content)
    strings: list[dict[str, Any]] = []
    pattern = re.compile(rb"[\x20-\x7e]{" + str(min_string_length).encode("ascii") + rb",}")
    for match in pattern.finditer(content):
        _check_cancel(cancel_event)
        if len(strings) >= _MAX_STRINGS:
            _incomplete(report, "string_limit")
            break
        text = match.group().decode("ascii")
        strings.append({"byte_offset": match.start(), "byte_length": len(text), "text": text,
                        "indicators": extract_indicators(text, extended=True)})
    indicators = extract_indicators(content.decode("utf-8", errors="replace"), extended=True)
    _check_cancel(cancel_event)
    identification = _identify(content)
    report.update({"identification": identification, "strings": strings, "indicators": indicators,
                   "summary": {"identification": identification, "strings_reported": len(strings),
                               "indicator_counts": {name: len(values) for name, values in indicators.items()}}})
    return _save_report(root, report, cancel_event)


def _timezone(value: str | None):
    if value is None:
        return None
    if value.upper() in {"Z", "UTC"}:
        return datetime_timezone.utc
    if re.fullmatch(r"[+-]\d\d:\d\d", value):
        hours, minutes = (int(item) for item in value[1:].split(":"))
        if hours > 23 or minutes > 59:
            raise OcError("invalid_argument", "timezone offset is invalid", details={"parameter": "timezone"})
        delta = timedelta(hours=hours, minutes=minutes) * (-1 if value[0] == "-" else 1)
        return datetime_timezone(delta)
    try:
        return ZoneInfo(value)
    except (ZoneInfoNotFoundError, ValueError) as exc:
        raise OcError(
            "invalid_argument",
            "timezone must be an IANA timezone or an offset such as +01:00",
            details={"parameter": "timezone", "value": value},
        ) from exc


def _timestamp(value: Any, default_timezone) -> tuple[str, Decimal]:
    if not isinstance(value, str) or (match := _TIMESTAMP.fullmatch(value)) is None:
        raise ValueError("timestamp must be an ISO-8601 date/time")
    base, fraction, zone = match.groups()
    parsed = datetime.fromisoformat(base.replace("t", "T"))
    if zone:
        selected_timezone = _timezone(zone.upper())
    elif default_timezone is None:
        raise ValueError("timestamp has no timezone; supply timezone explicitly")
    else:
        selected_timezone = default_timezone
    parsed = parsed.replace(tzinfo=selected_timezone)
    if not zone and isinstance(selected_timezone, ZoneInfo):
        # An explicit zone still cannot disambiguate a repeated wall-clock
        # hour; nonexistent wall times must not silently become invented UTC.
        alternate = parsed.replace(fold=1)
        roundtrip = parsed.astimezone(datetime_timezone.utc).astimezone(selected_timezone)
        if roundtrip.replace(tzinfo=None) != parsed.replace(tzinfo=None):
            raise ValueError("timestamp is a nonexistent local time; supply an explicit UTC offset")
        if parsed.utcoffset() != alternate.utcoffset():
            raise ValueError("timestamp is ambiguous in this timezone; supply an explicit UTC offset")
    utc = parsed.astimezone(datetime_timezone.utc)
    delta = utc - datetime(1970, 1, 1, tzinfo=datetime_timezone.utc)
    epoch = Decimal(delta.days * 86400 + delta.seconds)
    if fraction:
        with localcontext() as context:
            context.prec = max(30, len(fraction) + 20)
            epoch += Decimal("0." + fraction)
    rendered = utc.strftime("%Y-%m-%dT%H:%M:%S") + (f".{fraction}" if fraction else "") + "Z"
    return rendered, epoch


def _invalid_json_constant(value: str) -> Any:
    raise ValueError(f"non-finite JSON number: {value}")


def _finite_json_float(value: str) -> float:
    number = float(value)
    if not math.isfinite(number):
        raise ValueError(f"JSON number is outside the supported finite range: {value}")
    return number


def log_timeline(
    engagement_id: str, path: str, format: str = "auto", timestamp_field: str = "timestamp",
    timezone: str | None = None, max_bytes: int = DEFAULT_MAX_BYTES, max_records: int = DEFAULT_MAX_RECORDS,
    cancel_event: threading.Event | None = None,
) -> dict[str, Any]:
    """Build a timeline from JSONL or ISO-8601-prefixed text, preserving errors."""
    _bounded(max_bytes, "max_bytes", "triage.max_bytes")
    _bounded(max_records, "max_records", "triage.max_records")
    if format not in {"auto", "jsonl", "text"}:
        raise OcError("invalid_argument", "format must be auto, jsonl, or text", details={"parameter": "format"})
    if not isinstance(timestamp_field, str) or not timestamp_field:
        raise OcError(
            "invalid_argument",
            "timestamp_field must be a non-empty string",
            details={"parameter": "timestamp_field"},
        )
    zone = _timezone(timezone)
    with _source(engagement_id, path) as (handle, root, relative):
        source, content = _read_source(handle, relative, max_bytes, cancel_event)
    selected_format = ("jsonl" if Path(path).suffix.lower() in {".jsonl", ".ndjson"} else "text") if format == "auto" else format
    report = _new_report("log_timeline", engagement_id, source, {
        "max_bytes": max_bytes, "max_records": max_records, "format": selected_format,
        "timestamp_field": timestamp_field, "timezone": timezone,
    }, content)
    lines = content.splitlines(keepends=True)
    if source["size"] > len(content) and lines and not lines[-1].endswith((b"\n", b"\r")):
        lines.pop()  # The byte limit cut a record: do not treat it as a whole event.
    events = []
    encountered = 0
    offset = 0
    for line_number, raw in enumerate(lines, 1):
        _check_cancel(cancel_event)
        if encountered >= max_records:
            _incomplete(report, "record_limit")
            break
        encountered += 1
        locator = {"line_number": line_number, "byte_offset": offset}
        offset += len(raw)
        try:
            text = raw.decode("utf-8").rstrip("\r\n")
        except UnicodeDecodeError:
            text = raw.decode("utf-8", errors="replace").rstrip("\r\n")
            report["errors"].append({**locator, "kind": "invalid_encoding", "message": "record is not valid UTF-8"})
            _incomplete(report, "record_errors")
        try:
            if selected_format == "jsonl":
                record = json.loads(text, parse_constant=_invalid_json_constant, parse_float=_finite_json_float)
                if not isinstance(record, dict):
                    raise ValueError("JSONL record must be an object")
                timestamp_raw = record.get(timestamp_field)
            else:
                prefix = _TEXT_PREFIX.match(text)
                timestamp_raw = prefix.group(1) if prefix else None
                record = text
        except (ValueError, RecursionError) as exc:
            report["errors"].append({**locator, "kind": "malformed_record", "message": str(exc), "raw": text})
            _incomplete(report, "record_errors")
            continue
        timestamp_utc = None
        sort_timestamp = None
        try:
            timestamp_utc, sort_timestamp = _timestamp(timestamp_raw, zone)
        except (ValueError, OverflowError) as exc:
            report["errors"].append({**locator, "kind": "unresolved_timestamp", "message": str(exc),
                                     "timestamp_raw": timestamp_raw})
            _incomplete(report, "record_errors")
        events.append({**locator, "timestamp_raw": timestamp_raw, "timestamp_utc": timestamp_utc,
                       "record": record, "indicators": extract_indicators(text, extended=True),
                       "_sort": sort_timestamp})
    events.sort(key=lambda item: (item["_sort"] is None, item["_sort"] or Decimal(0), item["line_number"]))
    for event in events:
        event.pop("_sort")
    report.update({"events": events, "records_encountered": encountered,
                   "summary": {"format": selected_format, "records_encountered": encountered,
                               "events_reported": len(events),
                               "unresolved_timestamps": sum(item["timestamp_utc"] is None for item in events)}})
    return _save_report(root, report, cancel_event)


def _terminate(process: subprocess.Popen) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
        process.wait(timeout=1)
    except ProcessLookupError:
        pass
    except subprocess.TimeoutExpired:
        pass
    # The group leader may have exited while a descendant ignores TERM and
    # still holds a pipe open. Kill the remaining group even in that case.
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


def _capture_process(argv: list[str], cancel_event: threading.Event | None,
                     *, pass_fds: tuple[int, ...] = (), output_limit: int = _OUTPUT_LIMIT) -> dict[str, Any]:
    """Drain both pipes in bounded chunks, polling cancellation without threads."""
    _check_cancel(cancel_event)
    with subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          start_new_session=True, pass_fds=pass_fds) as process:
        stdout = bytearray()
        stderr = bytearray()
        limited = False
        try:
            with selectors.DefaultSelector() as selector:
                assert process.stdout is not None and process.stderr is not None
                selector.register(process.stdout, selectors.EVENT_READ, (stdout, output_limit))
                selector.register(process.stderr, selectors.EVENT_READ, (stderr, 64 * 1024))
                while selector.get_map():
                    _check_cancel(cancel_event)
                    for key, _ in selector.select(timeout=0.1):
                        chunk = os.read(key.fd, 64 * 1024)
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        buffer, limit = key.data
                        remaining = limit - len(buffer)
                        buffer.extend(chunk[:remaining])
                        if len(chunk) > remaining:
                            limited = True
                            _terminate(process)
                    if limited:
                        break
            while True:
                _check_cancel(cancel_event)
                try:
                    returncode = process.wait(timeout=0.1)
                    break
                except subprocess.TimeoutExpired:
                    pass
            _check_cancel(cancel_event)
            return {"stdout": bytes(stdout), "stderr": bytes(stderr), "returncode": returncode,
                    "output_limited": limited}
        finally:
            _terminate(process)


def _packet_timestamp(raw: str) -> str | None:
    try:
        epoch = Decimal(raw)
        whole = int(epoch.to_integral_value(rounding=ROUND_FLOOR))
        base = datetime.fromtimestamp(whole, datetime_timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
        fraction = format(epoch - whole, "f").partition(".")[2].rstrip("0")
        return base + (f".{fraction}" if fraction else "") + "Z"
    except (ValueError, OverflowError, InvalidOperation):
        return None


def pcap_triage(
    engagement_id: str, path: str, max_bytes: int = DEFAULT_MAX_BYTES, max_packets: int = DEFAULT_MAX_RECORDS,
    cancel_event: threading.Event | None = None,
) -> dict[str, Any]:
    """Read a bounded PCAP/PCAPNG prefix with fixed, offline tshark arguments."""
    _bounded(max_bytes, "max_bytes", "triage.max_bytes")
    _bounded(max_packets, "max_packets", "triage.max_packets")
    with _source(engagement_id, path) as (handle, root, relative):
        source, content = _read_source(handle, relative, max_bytes, cancel_event)
    report = _new_report("pcap_triage", engagement_id, source, {
        "max_bytes": max_bytes, "max_packets": max_packets,
        "stdout_limit_bytes": _OUTPUT_LIMIT, "network_resolution": False,
    }, content)
    executable = shutil.which("tshark")
    report["available"] = executable is not None
    packets: list[dict[str, Any]] = []
    encountered = 0
    if executable is None:
        _incomplete(report, "tool_unavailable")
        report["errors"].append({"kind": "tool_unavailable", "message":
                                 "tshark is not installed; install the optional tshark integration and retry"})
    elif _identify(content) not in {"PCAP", "PCAPNG"}:
        _incomplete(report, "invalid_capture")
        report["errors"].append({"kind": "invalid_capture", "message": "input is not PCAP or PCAPNG"})
    else:
        version = _capture_process([executable, "--version"], cancel_event, output_limit=8192)
        report["tool"]["tshark_version"] = version["stdout"].decode("utf-8", errors="replace").splitlines()[:1]
        # An anonymous bounded snapshot keeps the parser off the original file
        # and gives max_bytes its literal meaning even for very large captures.
        with tempfile.TemporaryFile(mode="w+b") as bounded_capture:
            bounded_capture.write(content)
            bounded_capture.flush()
            descriptor = bounded_capture.fileno()
            argv = [executable, "-n", "-r", f"/proc/self/fd/{descriptor}", "-c", str(max_packets + 1),
                    "-T", "fields", "-E", "separator=\t", "-E", "quote=d", "-E", "occurrence=a"]
            for field in _PCAP_FIELDS:
                argv.extend(["-e", field])
            captured = _capture_process(argv, cancel_event, pass_fds=(descriptor,))
        report["tool"]["arguments"] = [item if not item.startswith("/proc/self/fd/") else "<bounded-capture>" for item in argv[1:]]
        report["tool"]["returncode"] = captured["returncode"]
        if captured["output_limited"]:
            _incomplete(report, "output_limit")
        if captured["returncode"] != 0:
            _incomplete(report, "capture_parse_error")
            report["errors"].append({"kind": "capture_parse_error", "message":
                                     captured["stderr"].decode("utf-8", errors="replace")})
        rows = csv.reader(io.StringIO(captured["stdout"].decode("utf-8", errors="replace")), delimiter="\t")
        while True:
            _check_cancel(cancel_event)
            try:
                row = next(rows)
            except StopIteration:
                break
            except csv.Error as exc:
                _incomplete(report, "capture_parse_error")
                report["errors"].append({"kind": "malformed_packet", "message": str(exc)})
                break
            if encountered >= max_packets:
                _incomplete(report, "packet_limit")
                break
            encountered += 1
            if len(row) != len(_PCAP_FIELDS):
                _incomplete(report, "capture_parse_error")
                report["errors"].append({"kind": "malformed_packet", "message": "unexpected tshark field count"})
                continue
            fields = dict(zip(_PCAP_FIELDS, row))
            packets.append({
                "packet_number": fields["frame.number"], "timestamp_raw": fields["frame.time_epoch"],
                "timestamp_utc": _packet_timestamp(fields["frame.time_epoch"]),
                "length": fields["frame.len"], "protocols": fields["frame.protocols"].split(":"),
                "source": fields["ip.src"] or fields["ipv6.src"],
                "destination": fields["ip.dst"] or fields["ipv6.dst"],
                "source_port": fields["tcp.srcport"] or fields["udp.srcport"],
                "destination_port": fields["tcp.dstport"] or fields["udp.dstport"],
                "dns": {"query": fields["dns.qry.name"], "ipv4": fields["dns.a"], "ipv6": fields["dns.aaaa"]},
                "http": {"method": fields["http.request.method"], "host": fields["http.host"], "uri": fields["http.request.uri"]},
                "tls": {"server_name": fields["tls.handshake.extensions_server_name"]},
            })
    report.update({"packets": packets, "packets_encountered": encountered,
                   "packets_processed": len(packets), "summary": {
        "packets_encountered": encountered,
        "packets_processed": len(packets),
        "protocols": sorted({protocol for packet in packets for protocol in packet["protocols"]}),
        "endpoint_count": len({packet[key] for packet in packets for key in ("source", "destination") if packet[key]}),
        "dns_observations": sum(bool(packet["dns"]["query"]) for packet in packets),
        "http_observations": sum(bool(packet["http"]["method"]) for packet in packets),
        "tls_observations": sum(bool(packet["tls"]["server_name"]) for packet in packets),
    }})
    result = _save_report(root, report, cancel_event)
    result["available"] = report["available"]
    return result
