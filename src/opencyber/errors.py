"""Machine-actionable failure contract shared by every MCP tool.

Every user-facing refusal maps onto one registered code in :data:`ERROR_CODES`.
A refusal carries a coarse ``category``, an honest ``retryable`` flag, one
concrete ``remediation.action`` and, when a ceiling caused the failure, the
``limit`` facts that name the ceiling and its recovery.

The server must never leak a bare ``ValueError`` string to a client. The tool
envelope calls :func:`translate` for anything that escapes a handler, so an
unexpected exception still reaches the caller as ``internal_error`` instead of
an opaque transport failure.

This module is import-light on purpose: the doctor, the CLI and the generated
error reference import it without pulling in MCPServer or any tool module.
"""

from __future__ import annotations

import asyncio
import copy
from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Mapping


class ErrorCategory(StrEnum):
    """Coarse failure family used for routing and reporting.

    Categories are deliberately fewer than codes: a client can branch on the
    category without knowing every specific code, while a precise code stays
    available for remediation and tests.
    """

    INVALID_INPUT = "invalid_input"
    DENIED = "denied"
    UNAVAILABLE = "unavailable"
    NOT_FOUND = "not_found"
    CONFLICT = "conflict"
    INTEGRITY_MISMATCH = "integrity_mismatch"
    TRUNCATED = "truncated"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"
    RESOURCE_CONSTRAINT = "resource_constraint"
    EXECUTION_FAILURE = "execution_failure"
    INTERNAL = "internal"


@dataclass(frozen=True, slots=True)
class ErrorSpec:
    """One registered refusal: what it means and what the caller should do."""

    code: str
    category: ErrorCategory
    retryable: bool
    summary: str
    remediation: str


_SPECS: tuple[ErrorSpec, ...] = (
    ErrorSpec(
        code="invalid_argument",
        category=ErrorCategory.INVALID_INPUT,
        retryable=False,
        summary="An argument is missing, malformed, or out of range.",
        remediation="Correct the reported argument and repeat the call unchanged otherwise.",
    ),
    ErrorSpec(
        code="missing_parameter",
        category=ErrorCategory.INVALID_INPUT,
        retryable=False,
        summary="A required parameter was not supplied.",
        remediation="Supply the named parameter; inspect the tool schema for its type.",
    ),
    ErrorSpec(
        code="unknown_tool",
        category=ErrorCategory.INVALID_INPUT,
        retryable=False,
        summary="No catalog tool matches the requested oc_* name.",
        remediation="Call oc_catalog with an exact name, substring query, or category first.",
    ),
    ErrorSpec(
        code="engagement_required",
        category=ErrorCategory.INVALID_INPUT,
        retryable=False,
        summary="Scope enforcement is on and the call did not name an engagement.",
        remediation="Create or select an engagement and pass its engagement_id.",
    ),
    ErrorSpec(
        code="engagement_not_found",
        category=ErrorCategory.NOT_FOUND,
        retryable=False,
        summary="No engagement exists for the supplied identifier.",
        remediation="Call oc_engagement_list and use a server-generated engagement_id.",
    ),
    ErrorSpec(
        code="scope_denied",
        category=ErrorCategory.DENIED,
        retryable=False,
        summary="The target is outside the engagement's authorized scope.",
        remediation="Add the target to the engagement scope, or call oc_scope_check before retrying.",
    ),
    ErrorSpec(
        code="permission_denied",
        category=ErrorCategory.DENIED,
        retryable=False,
        summary="The container refused the filesystem or process operation.",
        remediation="Check the owning path and file mode inside the engagement workspace.",
    ),
    ErrorSpec(
        code="authorization_required",
        category=ErrorCategory.DENIED,
        retryable=False,
        summary="The engagement has no signed operator authorization for this action.",
        remediation="Run `opencyber-poc authorize` on the host with OPENCYBER_APPROVAL_KEY set.",
    ),
    ErrorSpec(
        code="authorization_invalid",
        category=ErrorCategory.DENIED,
        retryable=False,
        summary="The signed authorization is invalid, expired, or does not cover this action.",
        remediation="Re-run `opencyber-poc authorize` for the current engagement and technique set.",
    ),
    ErrorSpec(
        code="approval_invalid",
        category=ErrorCategory.DENIED,
        retryable=False,
        summary="The single-use run approval is missing, consumed, expired, or does not match.",
        remediation="Mint a new approval with `opencyber-poc approve` for this exact spec and code hash.",
    ),
    ErrorSpec(
        code="capability_unavailable",
        category=ErrorCategory.UNAVAILABLE,
        retryable=False,
        summary="A capability this tool needs is not present in this deployment.",
        remediation="Inspect oc_doctor for the failing capability and use an operator-managed image that provides it.",
    ),
    ErrorSpec(
        code="integration_unavailable",
        category=ErrorCategory.UNAVAILABLE,
        retryable=False,
        summary="The executable backing this tool is not installed or lacks a dependency.",
        remediation="Install the integration and its dependencies in the operator-managed image, then restart.",
    ),
    ErrorSpec(
        code="offline_blocked",
        category=ErrorCategory.UNAVAILABLE,
        retryable=False,
        summary="Offline mode refuses this internet-dependent operation.",
        remediation="Unset OPENCYBER_OFFLINE, or use an offline data source such as the local CVE index.",
    ),
    ErrorSpec(
        code="not_found",
        category=ErrorCategory.NOT_FOUND,
        retryable=False,
        summary="The named object does not exist in this engagement.",
        remediation="List the owning collection first and use an identifier it returns.",
    ),
    ErrorSpec(
        code="already_exists",
        category=ErrorCategory.CONFLICT,
        retryable=False,
        summary="The target already exists and this operation never overwrites.",
        remediation="Choose another name or path, or inspect the existing object first.",
    ),
    ErrorSpec(
        code="conflict",
        category=ErrorCategory.CONFLICT,
        retryable=False,
        summary="The request contradicts current state, such as a hash or revision mismatch.",
        remediation="Re-read the current state, then repeat the call with the current identifiers.",
    ),
    ErrorSpec(
        code="integrity_mismatch",
        category=ErrorCategory.INTEGRITY_MISMATCH,
        retryable=False,
        summary="Stored hashes or the audit chain do not match the recorded value.",
        remediation="Treat the artifact as untrusted; re-export it and compare against a separately retained digest.",
    ),
    ErrorSpec(
        code="truncated",
        category=ErrorCategory.TRUNCATED,
        retryable=True,
        summary="The complete result could not be returned and the partial result is unusable.",
        remediation="Raise the named limit or narrow the request, then repeat the call.",
    ),
    ErrorSpec(
        code="timed_out",
        category=ErrorCategory.TIMEOUT,
        retryable=True,
        summary="The operation exceeded its deadline and was stopped.",
        remediation="Raise the named deadline, narrow the request, or run the scan as a background artifact.",
    ),
    ErrorSpec(
        code="cancelled",
        category=ErrorCategory.CANCELLED,
        retryable=True,
        summary="The caller cancelled the operation.",
        remediation="Repeat the call if the work is still wanted; partial side effects may remain.",
    ),
    ErrorSpec(
        code="resource_constraint",
        category=ErrorCategory.RESOURCE_CONSTRAINT,
        retryable=True,
        summary="A named size, count, or request ceiling ended the operation early.",
        remediation="Use the limit facts in this error to raise the ceiling or narrow the request.",
    ),
    ErrorSpec(
        code="limit_exceeded",
        category=ErrorCategory.RESOURCE_CONSTRAINT,
        retryable=True,
        summary="The request exceeded a named ceiling and nothing ran.",
        remediation="Use the limit facts in this error to raise the ceiling or narrow the request.",
    ),
    ErrorSpec(
        code="connection_failed",
        category=ErrorCategory.UNAVAILABLE,
        retryable=True,
        summary="A network connection to the named endpoint failed.",
        remediation="Confirm the endpoint is reachable from the container and that the engagement scopes it.",
    ),
    ErrorSpec(
        code="execution_failed",
        category=ErrorCategory.EXECUTION_FAILURE,
        retryable=True,
        summary="The operation ran but did not complete successfully.",
        remediation="Read the captured diagnostics; correct the input before repeating the call.",
    ),
    ErrorSpec(
        code="child_failed",
        category=ErrorCategory.EXECUTION_FAILURE,
        retryable=True,
        summary="The child process exited non-zero.",
        remediation="Read stderr and the exit code; many tools use non-zero exits for partial findings.",
    ),
    ErrorSpec(
        code="internal_error",
        category=ErrorCategory.INTERNAL,
        retryable=False,
        summary="The server hit an unexpected condition. This is a harness bug.",
        remediation="Report the tool name and exception type with a reproduction; do not retry blindly.",
    ),
)

ERROR_CODES: dict[str, ErrorSpec] = {spec.code: spec for spec in _SPECS}

if len(ERROR_CODES) != len(_SPECS):  # pragma: no cover - import-time invariant
    raise RuntimeError("duplicate error code in OpenCyber error registry")


def describe_codes() -> list[dict[str, str]]:
    """Return the registry as sorted, serializable rows for documentation."""
    return [
        {
            "code": spec.code,
            "category": spec.category.value,
            "retryable": "yes" if spec.retryable else "no",
            "summary": spec.summary,
            "remediation": spec.remediation,
        }
        for spec in sorted(_SPECS, key=lambda item: item.code)
    ]


def error_schema() -> dict[str, Any]:
    """JSON Schema (draft 2020-12) for the ``error`` object carried in results."""
    categories = sorted(category.value for category in ErrorCategory)
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/mitkox/opencyber/schemas/error-contract.schema.json",
        "title": "OpenCyber tool error",
        "description": (
            "A refusal returned in a tool result. Codes are a closed set; category, "
            "retryable, and remediation are always present so a client never parses prose."
        ),
        "type": "object",
        "additionalProperties": False,
        "required": ["code", "category", "message", "retryable", "remediation"],
        "properties": {
            "code": {"type": "string", "enum": sorted(ERROR_CODES)},
            "category": {"type": "string", "enum": categories},
            "message": {"type": "string", "minLength": 1},
            "retryable": {"type": "boolean"},
            "remediation": {
                "type": "object",
                "additionalProperties": False,
                "required": ["action"],
                "properties": {"action": {"type": "string", "minLength": 1}},
            },
            "limit": {"type": ["object", "null"]},
            "details": {"type": "object"},
        },
    }


class OcError(ValueError):
    """A refusal with a registered code.

    Subclasses :class:`ValueError` so existing callers that catch the historical
    exception type keep working while new code can branch on ``code``.
    """

    def __init__(
        self,
        code: str,
        message: str,
        *,
        details: Mapping[str, Any] | None = None,
        limit: Mapping[str, Any] | None = None,
        remediation: str | None = None,
        retryable: bool | None = None,
    ) -> None:
        spec = ERROR_CODES.get(code)
        if spec is None:
            raise KeyError(f"unregistered OpenCyber error code: {code}")
        if not isinstance(message, str) or not message:
            raise ValueError("an OcError message must be a non-empty string")
        super().__init__(message)
        self.code = code
        self.message = message
        self.category = spec.category
        self.retryable = spec.retryable if retryable is None else bool(retryable)
        self.remediation = {"action": remediation or spec.remediation}
        self.limit = copy.deepcopy(dict(limit)) if limit is not None else None
        self.details = copy.deepcopy(dict(details or {}))

    def to_dict(self) -> dict[str, Any]:
        """Serialize the refusal into the stable ``error`` object shape."""
        return {
            "code": self.code,
            "category": self.category.value,
            "message": self.message,
            "retryable": self.retryable,
            "remediation": dict(self.remediation),
            "limit": copy.deepcopy(self.limit),
            "details": copy.deepcopy(self.details),
        }


def limit_exceeded(limit: Mapping[str, Any], message: str, **details: Any) -> OcError:
    """Build a refusal whose ``limit`` facts name the ceiling and its recovery."""
    return OcError("limit_exceeded", message, details=details, limit=limit)


def internal_error(exc: BaseException) -> OcError:
    """Wrap an unexpected exception without inventing a cause for the caller."""
    return OcError(
        "internal_error",
        f"unexpected {type(exc).__name__}: {exc}",
        details={"exception": type(exc).__name__},
    )


def translate(exc: BaseException) -> OcError:
    """Map an exception escaping a tool handler onto the registered contract.

    Cancellation is never translated: the envelope re-raises it so the SDK can
    report a cancelled request instead of a failed one.
    """
    if isinstance(exc, OcError):
        return exc
    if isinstance(exc, asyncio.CancelledError):
        raise exc
    if isinstance(exc, (TimeoutError, asyncio.TimeoutError)):
        return OcError("timed_out", str(exc) or "operation timed out")
    if isinstance(exc, FileNotFoundError):
        return OcError("not_found", str(exc) or "path not found")
    if isinstance(exc, FileExistsError):
        return OcError("already_exists", str(exc) or "path already exists")
    if isinstance(exc, PermissionError):
        return OcError("permission_denied", str(exc) or "permission denied")
    if isinstance(exc, ConnectionError):
        return OcError("connection_failed", str(exc) or "connection failed")
    if isinstance(exc, (ValueError, TypeError, KeyError)):
        return OcError("invalid_argument", str(exc) or type(exc).__name__, details={"exception": type(exc).__name__})
    if isinstance(exc, OSError):
        return OcError("execution_failed", str(exc) or type(exc).__name__, details={"exception": type(exc).__name__})
    return internal_error(exc)
