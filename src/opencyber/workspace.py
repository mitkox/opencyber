"""Engagement workspace operations confined to the container workspace."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from . import envelope, limits
from .audit import safe_record
from .engagements import get_engagement, resolve_engagement_path
from .errors import OcError
from .poc_schema import server_managed_path


def _relative(engagement_root: Path, target: Path) -> str:
    return target.relative_to(engagement_root).as_posix()


def _refuse_server_managed(engagement_root: Path, target: Path, action: str) -> None:
    relative = _relative(engagement_root, target)
    if relative == "engagement.json":
        raise ValueError("engagement.json is managed by the OpenCyber server")
    if server_managed_path(relative):
        raise ValueError(
            f"{relative} is managed by the PoC subsystem and cannot be {action} "
            "through the workspace tools; use the oc_poc_* tools or the opencyber-poc CLI"
        )


def list_workspace(
    engagement_id: str,
    path: str = ".",
    recursive: bool = False,
    limit: int = 0,
    offset: int = 0,
) -> dict[str, Any]:
    """List workspace entries with optional paging.

    ``limit=0`` (the default) returns every entry. A bounded listing reports
    examined/total, the next offset, and a ready-to-call continuation, so a
    large or recursive listing can be paged instead of flooded into context.
    """
    engagement_root = Path(get_engagement(engagement_id)["workspace"])
    root = resolve_engagement_path(engagement_id, path)
    if not root.is_dir():
        raise OcError("not_found", f"not a directory: {path}", details={"path": path})
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
        raise OcError("invalid_argument", "limit must be a non-negative integer; 0 returns every entry",
                      details={"parameter": "limit"})
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise OcError("invalid_argument", "offset must be a non-negative integer", details={"parameter": "offset"})
    iterator = root.rglob("*") if recursive else root.iterdir()
    all_entries = []
    for item in sorted(iterator):
        stat = item.stat()
        all_entries.append(
            {
                "path": str(item.relative_to(engagement_root)),
                "type": "directory" if item.is_dir() else "file",
                "size": stat.st_size if item.is_file() else 0,
            }
        )
    total = len(all_entries)
    selected = all_entries[offset : offset + limit] if limit else all_entries[offset:]
    examined = offset + len(selected)
    exhausted = examined >= total
    result: dict[str, Any] = {
        "engagement_id": engagement_id,
        "workspace": str(engagement_root),
        "entries": selected,
        "total_entries": total,
        "coverage": envelope.coverage(
            "empty" if total == 0 else ("complete" if exhausted else "partial"),
            examined=examined,
            total=total,
            exhausted=exhausted,
            next_offset=None if exhausted else examined,
        ),
    }
    if not exhausted:
        result["limitations"] = [
            "The page reflects the directory at call time; entries written between pages can "
            "shift later offsets, so a paged list is a snapshot series, not one atomic inventory."
        ]
        result["continuation"] = {
            "tool": "oc_workspace_list",
            "arguments": {
                "engagement_id": engagement_id,
                "path": path,
                "recursive": recursive,
                "limit": limit,
                "offset": examined,
            },
        }
    return result


def read_workspace_file(
    engagement_id: str, path: str, max_bytes: int = 1048576, offset: int = 0
) -> dict[str, Any]:
    """Read a UTF-8 text file under a named size ceiling.

    ``max_bytes=0`` returns the whole file. A bounded read that stops early
    reports the complete size, the next byte offset, and a ready-to-call
    continuation, so a caller pages instead of guessing whether content is
    missing. Offsets are byte offsets; a multi-byte character split at a page
    boundary decodes as a replacement character.
    """
    engagement_root = Path(get_engagement(engagement_id)["workspace"])
    target = resolve_engagement_path(engagement_id, path)
    if not target.is_file():
        raise OcError("not_found", f"not a file: {target}", details={"path": path})
    limit = limits.limit_for("workspace.read_max_bytes")
    if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 0:
        raise OcError(
            "invalid_argument",
            "max_bytes must be a non-negative integer of bytes; 0 returns the whole file",
            details={"parameter": "max_bytes"},
        )
    maximum = int(limit.maximum) if limit.maximum is not None else None
    if maximum is not None and max_bytes > maximum:
        raise limits.raise_exceeded(
            "workspace.read_max_bytes",
            f"max_bytes exceeds the supported ceiling of {maximum} bytes",
            effective=maximum,
            requested=max_bytes,
            parameter="max_bytes",
        )
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise OcError("invalid_argument", "offset must be a non-negative integer", details={"parameter": "offset"})
    total_bytes = target.stat().st_size
    if offset > total_bytes:
        raise OcError(
            "invalid_argument",
            f"offset {offset} is past the end of a {total_bytes}-byte file",
            details={"offset": offset, "total_bytes": total_bytes},
        )
    if max_bytes == 0:
        with target.open("rb") as handle:
            handle.seek(offset)
            data = handle.read()
    else:
        with target.open("rb") as handle:
            handle.seek(offset)
            data = handle.read(max_bytes)
    relative = str(target.relative_to(engagement_root))
    truncated = offset + len(data) < total_bytes
    result: dict[str, Any] = {
        "engagement_id": engagement_id,
        "path": relative,
        "content": data.decode("utf-8", errors="replace"),
        "offset": offset,
        "total_bytes": total_bytes,
        "truncated": truncated,
        "next_offset": offset + len(data) if truncated else None,
    }
    if truncated:
        result["coverage"] = envelope.coverage("partial", examined=offset + len(data), total=total_bytes, exhausted=False)
        result["limitations"] = [
            f"Returned bytes {offset} to {offset + len(data)} of {total_bytes}; "
            "the remainder is unread, which is not evidence that it is empty."
        ]
        result["continuation"] = {
            "tool": "oc_workspace_read",
            "arguments": {
                "engagement_id": engagement_id,
                "path": relative,
                "max_bytes": max_bytes,
                "offset": offset + len(data),
            },
        }
    return result


def write_workspace_file(engagement_id: str, path: str, content: str, append: bool = False) -> dict[str, Any]:
    engagement_root = Path(get_engagement(engagement_id)["workspace"])
    target = resolve_engagement_path(engagement_id, path, must_exist=False)
    _refuse_server_managed(engagement_root, target, "written")
    target.parent.mkdir(parents=True, exist_ok=True)
    mode = "a" if append else "w"
    with target.open(mode, encoding="utf-8") as handle:
        handle.write(content)
    result = {
        "engagement_id": engagement_id,
        "path": str(target.relative_to(engagement_root)),
        "size": target.stat().st_size,
        "appended": append,
    }
    safe_record(
        engagement_id,
        {
            "event": "workspace.write",
            "path": result["path"],
            "size": result["size"],
            "appended": append,
            "sha256": hashlib.sha256(content.encode("utf-8")).hexdigest(),
        },
    )
    return result


def delete_workspace_path(engagement_id: str, path: str) -> dict[str, Any]:
    engagement_root = Path(get_engagement(engagement_id)["workspace"])
    target = resolve_engagement_path(engagement_id, path)
    if target == engagement_root:
        raise ValueError("cannot delete the engagement root")
    _refuse_server_managed(engagement_root, target, "deleted")
    if target.is_dir():
        target.rmdir()
    else:
        target.unlink()
    deleted = str(target.relative_to(engagement_root))
    safe_record(
        engagement_id,
        {"event": "workspace.delete", "path": deleted},
    )
    return {"engagement_id": engagement_id, "deleted": deleted}


def write_finding_report(
    engagement_id: str,
    path: str,
    title: str,
    target: str,
    severity: str,
    summary: str,
    evidence: list[str],
    remediation: str = "",
    evidence_ids: list[str] | None = None,
) -> dict[str, Any]:
    from .result_store import get_result

    retained = [get_result(engagement_id, evidence_id) for evidence_id in (evidence_ids or [])]
    lines = [f"- {item}" for item in evidence]
    for entry in retained:
        record = entry["evidence"]
        provenance = "retained" if entry["retained"] else "digest only"
        lines.append(
            f"- tool result `{record['id']}` from `{record.get('tool')}` "
            f"(sha256 `{record.get('sha256')}`, {record.get('bytes')} bytes, {provenance})"
        )
    evidence_lines = "\n".join(lines) or "- No evidence supplied"
    content = (
        f"# {title}\n\n"
        f"- Target: `{target}`\n"
        f"- Severity: **{severity.upper()}**\n\n"
        f"## Summary\n\n{summary}\n\n"
        f"## Evidence\n\n{evidence_lines}\n\n"
        f"## Remediation\n\n{remediation or 'Not supplied'}\n"
    )
    result = write_workspace_file(engagement_id, path, content, append=False)
    result.update({"title": title, "target": target, "severity": severity, "evidence_ids": list(evidence_ids or [])})
    return result
