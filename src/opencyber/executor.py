"""Safe direct executable runner for OpenCyber MCP tools."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import os
import signal
import shutil
import time
from typing import Any, Mapping, Sequence

from . import envelope, limits
from .audit import record_event, safe_record
from .catalog import CATALOG
from .errors import OcError
from .engagements import resolve_engagement_path
from .policy import enforce_scope, offline_network_decision
from .poc_schema import SCRUBBED_ENVIRONMENT_PREFIXES


def validate_arguments(arguments: Sequence[str]) -> list[str]:
    validated: list[str] = []
    for argument in arguments:
        if not isinstance(argument, str):
            raise TypeError("every argument must be a string")
        if "\x00" in argument:
            raise ValueError("arguments cannot contain NUL bytes")
        validated.append(argument)
    return validated


def build_environment(overrides: Mapping[str, str] | None = None) -> dict[str, str]:
    # The approval key signs authorizations and PoC run approvals. A tool child
    # process (including oc_bash and oc_python) must not inherit it. This limits
    # accidental disclosure; arbitrary container-root code is still trusted.
    environment = {
        key: value
        for key, value in os.environ.items()
        if not key.startswith(SCRUBBED_ENVIRONMENT_PREFIXES)
    }
    for key, value in (overrides or {}).items():
        if not isinstance(key, str) or not key or "=" in key or "\x00" in key:
            raise ValueError("environment names must be non-empty strings without '=' or NUL")
        if not isinstance(value, str) or "\x00" in value:
            raise ValueError("environment values must be strings without NUL")
        environment[key] = value
    return environment


def executable_status(executable: str) -> dict[str, Any]:
    resolved = shutil.which(executable)
    return {
        "executable": executable,
        "available": resolved is not None,
        "path": resolved,
    }


async def _terminate_process_group(process: asyncio.subprocess.Process) -> None:
    """Terminate a cancelled tool and any descendants it started."""
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        await process.wait()
        return
    try:
        await asyncio.wait_for(process.wait(), timeout=2.0)
    except asyncio.TimeoutError:
        pass
    finally:
        # The leader can exit on SIGTERM while a descendant ignores it or has
        # closed the inherited pipes. Reaping the leader is not group cleanup.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    await process.wait()


def _audit_required() -> bool:
    return os.environ.get("OPENCYBER_AUDIT_REQUIRED", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _audit_enabled() -> bool:
    return os.environ.get("OPENCYBER_AUDIT", "1").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _record(
    engagement_id: str,
    event: dict[str, Any],
    *,
    required: bool | None = None,
) -> dict[str, Any] | None:
    if not _audit_enabled():
        return None
    required = _audit_required() if required is None else required
    if required:
        return record_event(engagement_id, event)
    return safe_record(engagement_id, event)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


class _CappedReader:
    """Drain one child pipe while retaining at most ``cap`` bytes.

    The excess is still read and discarded: leaving it in the pipe would block
    the child once the OS buffer filled. ``truncated`` therefore means "more
    output existed than was retained", not "the child was stopped".
    """

    def __init__(self, stream: asyncio.StreamReader, cap: int) -> None:
        self._stream = stream
        self._cap = cap
        self._buffer = bytearray()
        self.received = 0
        self.truncated = False

    async def drain(self) -> None:
        while True:
            try:
                chunk = await self._stream.read(65536)
            except (asyncio.IncompleteReadError, ValueError, OSError):
                break
            if not chunk:
                break
            self.received += len(chunk)
            if self._cap == 0:
                self._buffer.extend(chunk)
                continue
            room = self._cap - len(self._buffer)
            if room <= 0:
                self.truncated = True
                continue
            if len(chunk) > room:
                self.truncated = True
                self._buffer.extend(chunk[:room])
            else:
                self._buffer.extend(chunk)

    def text(self) -> str:
        return bytes(self._buffer).decode("utf-8", errors="replace")


def _limit_seconds(limit_id: str) -> float:
    """Resolve a deadline, keeping fractional seconds; 0 disables it."""
    return float(limits.limit_for(limit_id).document_effective())


def _limit_bytes(limit_id: str) -> int:
    """Resolve a byte ceiling; 0 disables it."""
    return int(limits.limit_for(limit_id).document_effective())


async def _drain_readers(tasks: list["asyncio.Task[None]"]) -> None:
    """Wait for pipe closure, but never let a leaked grandchild hold the call."""
    for task in tasks:
        try:
            await asyncio.wait_for(task, timeout=5.0)
        except asyncio.TimeoutError:
            task.cancel()


async def execute_tool(
    executable: str,
    arguments: Sequence[str],
    engagement_id: str,
    working_directory: str = ".",
    stdin: str | None = None,
    environment: Mapping[str, str] | None = None,
    preflight: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Execute one binary without a shell, under a named deadline and output cap.

    ``ok`` means the harness completed the call; ``success`` keeps the historical
    meaning "the child exited 0". A scanner that exits non-zero after reporting
    findings therefore has ``ok: true`` and ``success: false``, while a timeout,
    spawn failure, or unavailable integration is ``ok: false`` with a typed
    ``error`` object. ``OPENCYBER_TOOL_TIMEOUT_S=0`` and
    ``OPENCYBER_TOOL_MAX_OUTPUT_BYTES=0`` disable the two ceilings.

    Scope enforcement is optional and fails closed before the process starts.
    Every call is written to the engagement's tamper-evident audit trail unless
    ``OPENCYBER_AUDIT=0`` is set.

    ``preflight`` is reserved for subsystems that performed and audited their own
    stricter scope review before calling the runner (the PoC engine does). When
    supplied, it replaces the optional argv-based check; it never weakens the
    offline decision and it is recorded in the audit trail as such.
    """
    cwd = resolve_engagement_path(engagement_id, working_directory)
    validated = validate_arguments(arguments)
    started = time.monotonic()
    started_at = _now()

    if preflight is not None:
        decision: dict[str, Any] = {
            "enforced": True,
            "allowed": True,
            "candidates": list(preflight.get("candidates", [])),
            "source": "poc_preflight",
        }
        _record(
            engagement_id,
            {
                "event": "tool.scope_checked",
                "executable": executable,
                "arguments": validated,
                "candidates": decision["candidates"],
                "allowed": True,
                "source": "poc_preflight",
                "ts": started_at,
            },
        )
    else:
        try:
            decision = enforce_scope(engagement_id, executable, validated)
        except ValueError as exc:
            _record(
                engagement_id,
                {
                    "event": "tool.denied",
                    "executable": executable,
                    "arguments": validated,
                    "working_directory": working_directory,
                    "reason": str(exc),
                    "ts": started_at,
                },
            )
            raise
        if decision.get("enforced"):
            _record(
                engagement_id,
                {
                    "event": "tool.scope_checked",
                    "executable": executable,
                    "arguments": validated,
                    "candidates": decision.get("candidates", []),
                    "allowed": decision.get("allowed"),
                    "ts": started_at,
                },
            )

    offline = offline_network_decision(executable)
    if offline["blocked"]:
        _record(
            engagement_id,
            {
                "event": "tool.denied",
                "executable": executable,
                "arguments": validated,
                "working_directory": working_directory,
                "reason": offline["reason"],
                "ts": started_at,
            },
        )
        raise ValueError(offline["reason"])

    def finish(result: dict[str, Any], event: str = "tool.exec") -> dict[str, Any]:
        elapsed_ms = round((time.monotonic() - started) * 1000, 2)
        record = _record(
            engagement_id,
            {
                "event": event,
                "executable": executable,
                "arguments": validated,
                "working_directory": working_directory,
                "cwd": str(cwd),
                "started_at": started_at,
                "duration_ms": elapsed_ms,
                "ok": result.get("ok"),
                "success": result.get("success"),
                "returncode": result.get("returncode"),
                "stdout_bytes": result.get("stdout_bytes", len(result.get("stdout", "").encode("utf-8"))),
                "stderr_bytes": result.get("stderr_bytes", len(result.get("stderr", "").encode("utf-8"))),
                "stdin_bytes": len(stdin.encode("utf-8")) if stdin else 0,
                "truncated": result.get("truncated"),
                "timed_out": result.get("timed_out"),
                "error": result.get("error_message"),
            },
        )
        if record:
            result["audit_seq"] = record.get("seq")
        result["scope_enforced"] = bool(decision.get("enforced"))
        return result

    spec = next((item for item in CATALOG if item.executable == executable), None)
    availability: dict[str, Any] = spec.availability() if spec else executable_status(executable)
    resolved = availability["path"]
    if not availability["available"]:
        reason = spec.optional_reason if spec and not spec.required else ""
        missing_dependencies: list[str] = availability.get("missing_dependencies", [])
        message = (
            f"integration unavailable: {executable}; {reason} "
            f"Missing: {', '.join(missing_dependencies) if resolved else executable}. "
            "Install the integration and its dependencies in an operator-managed image."
            if reason else f"executable is not installed: {executable}"
        )
        error = OcError(
            "integration_unavailable",
            message,
            details={
                "executable": executable,
                "optional": bool(spec and not spec.required),
                "missing_dependencies": missing_dependencies,
            },
        )
        return finish(
            {
                "ok": False,
                "success": False,
                "engagement_id": engagement_id,
                "executable": executable,
                "available": False,
                "cwd": str(cwd),
                "optional": bool(spec and not spec.required),
                "missing_dependencies": missing_dependencies,
                "error": error.to_dict(),
                "error_message": message,
                "limitations": ["The tool did not run."],
            }
        )

    assert resolved is not None
    # Validate configuration before spawning: a refused call must not run code.
    timeout_s = _limit_seconds("tool.timeout_s")
    output_cap = _limit_bytes("tool.max_output_bytes")
    argv = [resolved, *validated]
    try:
        process = await asyncio.create_subprocess_exec(
            *argv,
            cwd=cwd,
            env=build_environment(environment),
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
    except OSError as exc:
        error = OcError("execution_failed", str(exc), details={"executable": executable, "argv": argv})
        return finish(
            {
                "ok": False,
                "success": False,
                "engagement_id": engagement_id,
                "executable": executable,
                "available": True,
                "argv": argv,
                "cwd": str(cwd),
                "error": error.to_dict(),
                "error_message": str(exc),
                "limitations": ["The process did not start."],
            }
        )

    assert process.stdout is not None and process.stderr is not None
    stdout_reader = _CappedReader(process.stdout, output_cap)
    stderr_reader = _CappedReader(process.stderr, output_cap)
    reader_tasks = [asyncio.create_task(stdout_reader.drain()), asyncio.create_task(stderr_reader.drain())]
    timed_out = False
    async def communicate() -> None:
        if process.stdin is not None:
            try:
                if stdin is not None:
                    process.stdin.write(stdin.encode("utf-8"))
                    await process.stdin.drain()
            except (BrokenPipeError, ConnectionResetError):
                pass
            finally:
                process.stdin.close()
        await process.wait()

    try:
        try:
            if timeout_s == 0:
                await communicate()
            else:
                await asyncio.wait_for(communicate(), timeout=timeout_s)
        except asyncio.TimeoutError:
            timed_out = True
            await _terminate_process_group(process)
        await _drain_readers(reader_tasks)
    except asyncio.CancelledError:
        await _terminate_process_group(process)
        await _drain_readers(reader_tasks)
        _record(
            engagement_id,
            {
                "event": "tool.cancelled",
                "executable": executable,
                "arguments": validated,
                "working_directory": working_directory,
                "cwd": str(cwd),
                "started_at": started_at,
                "duration_ms": round((time.monotonic() - started) * 1000, 2),
            },
        )
        raise

    truncated = stdout_reader.truncated or stderr_reader.truncated
    result: dict[str, Any] = {
        "ok": not timed_out,
        "success": process.returncode == 0 and not timed_out,
        "engagement_id": engagement_id,
        "executable": executable,
        "available": True,
        "argv": argv,
        "cwd": str(cwd),
        "returncode": process.returncode,
        "stdout": stdout_reader.text(),
        "stderr": stderr_reader.text(),
        "stdout_bytes": stdout_reader.received,
        "stderr_bytes": stderr_reader.received,
        "truncated": truncated,
        "timed_out": timed_out,
        "timeout_s": timeout_s,
        "max_output_bytes": output_cap,
    }
    if timed_out:
        message = f"{executable} exceeded the {timeout_s:g}-second server deadline and was stopped"
        error = OcError(
            "timed_out",
            message,
            details={"executable": executable, "timeout_s": timeout_s},
            limit=limits.facts("tool.timeout_s", effective=timeout_s),
        )
        result.update(
            {
                "ok": False,
                "success": False,
                "error": error.to_dict(),
                "error_message": message,
                "coverage": envelope.coverage("partial", exhausted=False),
                "limitations": [
                    "The run stopped at the server deadline. Output captured so far is included; "
                    "the run is incomplete and the target may still be processing it."
                ],
            }
        )
    elif truncated:
        result["coverage"] = envelope.coverage("partial", exhausted=False)
        result["limitations"] = [
            f"Output was capped at {output_cap} bytes per stream; bytes beyond the cap were read "
            "and discarded, so the captured text is incomplete rather than empty."
        ]
        result["limit"] = limits.facts("tool.max_output_bytes", effective=output_cap)
    return finish(result)
