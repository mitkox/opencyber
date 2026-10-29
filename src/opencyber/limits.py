"""Named ceilings, their units, and their recovery.

A limit is only honest when the failure names it: which ceiling, in what unit,
what value was enforced, where that value came from, and what raises it. This
registry is the single owner of that metadata. The module that enforces a
ceiling stays the owner of the enforced value; it builds the facts here instead
of inventing a sentence.

Numeric defaults are repeated as literals on purpose: importing the enforcing
modules here would create an import cycle, because they import this module to
build their failures. ``tests/test_limits.py`` cross-checks every literal
against the owning module constant so the two cannot drift.

This module is import-light: it has no third-party imports.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
import math
import os
from typing import Any, Mapping

from .errors import OcError


class LimitSource(StrEnum):
    """Who can change a ceiling."""

    ARGUMENT = "argument"
    ENVIRONMENT = "environment"
    FIXED = "fixed"


@dataclass(frozen=True, slots=True)
class Limit:
    """One enforced ceiling."""

    id: str
    unit: str
    description: str
    default: float
    minimum: float | None
    maximum: float | None
    source: LimitSource
    applies_to: tuple[str, ...]
    recovery: str
    does_not_raise: str
    env: str | None = None
    parameter: str | None = None

    def document_effective(self) -> float:
        """Resolve the documented default, honoring an environment override.

        Enforcement remains with the owning module; this value is for
        documentation, the doctor, and pre-flight inspection. An unparsable or
        out-of-bounds environment value fails closed rather than silently
        falling back, so a typo cannot quietly tighten or loosen a ceiling.
        """
        if self.source is not LimitSource.ENVIRONMENT or not self.env:
            return self.default
        raw = os.environ.get(self.env, "").strip()
        if not raw:
            return self.default
        try:
            value = float(raw)
        except ValueError:
            raise OcError(
                "invalid_argument",
                f"{self.env} must be a number of {self.unit}, got {raw!r}",
                details={"setting": self.env, "limit": self.id},
                remediation=f"Set {self.env} to a number between {self._bounds_text()} or unset it.",
            ) from None
        if not self._in_bounds(value):
            raise OcError(
                "invalid_argument",
                f"{self.env} must be between {self._bounds_text()}, got {value:g}",
                details={"setting": self.env, "limit": self.id},
                remediation=f"Set {self.env} to a number between {self._bounds_text()} or unset it.",
            )
        return value

    def facts(
        self,
        effective: float | None = None,
        *,
        requested: float | None = None,
        parameter: str | None = None,
    ) -> dict[str, Any]:
        """Build the ``details.limit`` object for one enforced decision.

        ``effective`` is the value the owner actually enforced. When it is
        omitted the documented default is used, which is only correct for
        inspection output.
        """
        resolved = self.document_effective() if effective is None else effective
        return {
            "id": self.id,
            "unit": self.unit,
            "effective": _number(resolved),
            "requested": None if requested is None else _number(requested),
            "default": _number(self.default),
            "minimum": None if self.minimum is None else _number(self.minimum),
            "maximum": None if self.maximum is None else _number(self.maximum),
            "source": self.source.value,
            "setting": self.env,
            "parameter": parameter if parameter is not None else self.parameter,
            "recovery": self.recovery,
            "does_not_raise": self.does_not_raise,
        }

    def _in_bounds(self, value: float) -> bool:
        if not math.isfinite(value):
            return False
        if self.minimum is not None and value < self.minimum:
            return False
        if self.maximum is not None and value > self.maximum:
            return False
        return True

    def _bounds_text(self) -> str:
        low = "0" if self.minimum is None else f"{self.minimum:g}"
        high = "unbounded" if self.maximum is None else f"{self.maximum:g}"
        return f"{low} and {high}"


def _number(value: float) -> int | float:
    """Render whole numbers without a trailing ``.0`` in the wire shape."""
    return int(value) if float(value).is_integer() else value


_LIMITS: tuple[Limit, ...] = (
    Limit(
        id="triage.max_bytes",
        unit="bytes",
        description="Bytes inspected from a supplied file, log, or capture.",
        default=16777216,
        minimum=1,
        maximum=268435456,
        source=LimitSource.ARGUMENT,
        applies_to=("oc_file_triage", "oc_log_timeline", "oc_pcap_triage"),
        recovery="Pass a larger max_bytes value in the same call.",
        does_not_raise="The source file's own size on disk.",
        parameter="max_bytes",
    ),
    Limit(
        id="triage.max_records",
        unit="records",
        description="Timeline records returned from a log.",
        default=10000,
        minimum=1,
        maximum=1000000,
        source=LimitSource.ARGUMENT,
        applies_to=("oc_log_timeline",),
        recovery="Pass a larger max_records value or narrow the time window.",
        does_not_raise="The number of records present in the source.",
        parameter="max_records",
    ),
    Limit(
        id="triage.max_packets",
        unit="packets",
        description="Packets examined in a capture.",
        default=10000,
        minimum=1,
        maximum=1000000,
        source=LimitSource.ARGUMENT,
        applies_to=("oc_pcap_triage",),
        recovery="Pass a larger max_packets value or pre-filter the capture.",
        does_not_raise="The number of packets present in the capture.",
        parameter="max_packets",
    ),
    Limit(
        id="workspace.read_max_bytes",
        unit="bytes",
        description="Bytes returned by one workspace read.",
        default=1048576,
        minimum=1,
        maximum=67108864,
        source=LimitSource.ARGUMENT,
        applies_to=("oc_workspace_read",),
        recovery="Pass a larger max_bytes value, or page with the returned offset.",
        does_not_raise="The client's own response or context budget.",
        parameter="max_bytes",
    ),
    Limit(
        id="audit.read_limit",
        unit="events",
        description="Audit events returned by one read.",
        default=100,
        minimum=1,
        maximum=1000,
        source=LimitSource.ARGUMENT,
        applies_to=("oc_audit_log",),
        recovery="Page with the returned offset or reduce the request size.",
        does_not_raise="The number of events retained for the engagement.",
        parameter="limit",
    ),
    Limit(
        id="audit.max_events",
        unit="events",
        description="Retained audit events available to one read.",
        default=5000,
        minimum=None,
        maximum=None,
        source=LimitSource.FIXED,
        applies_to=("oc_audit_log", "oc_audit_verify"),
        recovery="Export the audit trail and read it outside the tool.",
        does_not_raise="Events already written; they remain on disk.",
    ),
    Limit(
        id="evidence.max_files",
        unit="files",
        description="Files selected into one evidence bundle.",
        default=10000,
        minimum=1,
        maximum=None,
        source=LimitSource.FIXED,
        applies_to=("oc_evidence_export",),
        recovery="Export in several bundles and retain each archive digest.",
        does_not_raise="Files present in the engagement workspace.",
    ),
    Limit(
        id="evidence.max_manifest_bytes",
        unit="bytes",
        description="Manifest size for one evidence bundle.",
        default=8388608,
        minimum=None,
        maximum=None,
        source=LimitSource.FIXED,
        applies_to=("oc_evidence_export", "oc_evidence_verify"),
        recovery="Export fewer paths per bundle.",
        does_not_raise="The size of the files being exported.",
    ),
    Limit(
        id="http.response_max_bytes",
        unit="bytes",
        description="Decompressed response body bytes retained by one native HTTP request, including redirect responses.",
        default=262144,
        minimum=None,
        maximum=None,
        source=LimitSource.FIXED,
        applies_to=("oc_http_request",),
        recovery="Request a smaller resource or use server-supported Range requests to retrieve specific bytes.",
        does_not_raise="HTTP headers, other HTTP tools, or the envelope evidence ceiling.",
    ),
    Limit(
        id="http.timeout",
        unit="seconds",
        description="Deadline for one native HTTP request.",
        default=30,
        minimum=0,
        maximum=300,
        source=LimitSource.ENVIRONMENT,
        env="OPENCYBER_HTTP_TIMEOUT",
        applies_to=(
            "oc_http_request",
            "oc_graphql_request",
            "oc_openapi_inspect",
            "oc_hibp_password_check",
            "oc_cve_lookup",
        ),
        recovery="Pass a per-call timeout, or raise OPENCYBER_HTTP_TIMEOUT up to 300 seconds.",
        does_not_raise="The server's own deadline for executable-backed tools.",
    ),
    Limit(
        id="serial.read_max_bytes",
        unit="bytes",
        description="Bytes returned by one serial read.",
        default=4096,
        minimum=1,
        maximum=65536,
        source=LimitSource.ARGUMENT,
        applies_to=("oc_serial_read",),
        recovery="Pass a larger max_bytes value or read again.",
        does_not_raise="The bytes already buffered on the device.",
        parameter="max_bytes",
    ),
    Limit(
        id="serial.read_timeout",
        unit="seconds",
        description="Blocking window for one serial read.",
        default=1,
        minimum=0,
        maximum=30,
        source=LimitSource.ARGUMENT,
        applies_to=("oc_serial_read",),
        recovery="Pass a larger timeout value or poll again.",
        does_not_raise="The device's own response time.",
        parameter="timeout",
    ),
    Limit(
        id="poc.max_requests",
        unit="requests",
        description="Requests one approved PoC run may send.",
        default=20,
        minimum=1,
        maximum=20,
        source=LimitSource.ENVIRONMENT,
        env="OPENCYBER_POC_MAX_REQUESTS",
        applies_to=("oc_poc_run",),
        recovery="Lower the spec limit; the environment cannot raise the hard ceiling.",
        does_not_raise="The evidence-to-claim requirement of the engagement.",
    ),
    Limit(
        id="poc.timeout_s",
        unit="seconds",
        description="Deadline for one approved PoC run.",
        default=60,
        minimum=1,
        maximum=60,
        source=LimitSource.ENVIRONMENT,
        env="OPENCYBER_POC_TIMEOUT",
        applies_to=("oc_poc_run",),
        recovery="Lower the spec timeout; the environment cannot raise the hard ceiling.",
        does_not_raise="The client's own request deadline.",
    ),
    Limit(
        id="poc.max_bytes",
        unit="bytes",
        description="Response bytes one PoC run may retain.",
        default=1048576,
        minimum=None,
        maximum=None,
        source=LimitSource.FIXED,
        applies_to=("oc_poc_run",),
        recovery="Narrow the assertions or the request set.",
        does_not_raise="The target's response size.",
    ),
    Limit(
        id="tool.timeout_s",
        unit="seconds",
        description="Deadline for one executable-backed tool call.",
        default=1800,
        minimum=0,
        maximum=86400,
        source=LimitSource.ENVIRONMENT,
        env="OPENCYBER_TOOL_TIMEOUT_S",
        applies_to=("*",),
        recovery="Raise OPENCYBER_TOOL_TIMEOUT_S, or set it to 0 to run without a server deadline.",
        does_not_raise="The client's own cancellation or request deadline.",
    ),
    Limit(
        id="tool.max_output_bytes",
        unit="bytes",
        description="Output retained per stream from one executable-backed tool call.",
        default=4194304,
        minimum=0,
        maximum=268435456,
        source=LimitSource.ENVIRONMENT,
        env="OPENCYBER_TOOL_MAX_OUTPUT_BYTES",
        applies_to=("*",),
        recovery="Raise OPENCYBER_TOOL_MAX_OUTPUT_BYTES, or redirect the tool's output to an engagement file.",
        does_not_raise="The child process's own write path; the excess is read and discarded.",
    ),
    Limit(
        id="envelope.evidence_max_bytes",
        unit="bytes",
        description="Result size above which no evidence digest is computed.",
        default=4194304,
        minimum=None,
        maximum=None,
        source=LimitSource.FIXED,
        applies_to=("*",),
        recovery="Request a smaller page or inspect the persisted artifact instead.",
        does_not_raise="The result itself; it is still returned.",
    ),
)

LIMITS: dict[str, Limit] = {limit.id: limit for limit in _LIMITS}

if len(LIMITS) != len(_LIMITS):  # pragma: no cover - import-time invariant
    raise RuntimeError("duplicate limit id in OpenCyber limit registry")


def limit_for(limit_id: str) -> Limit:
    try:
        return LIMITS[limit_id]
    except KeyError:
        raise KeyError(f"no registered limit: {limit_id}") from None


def facts(
    limit_id: str,
    effective: float | None = None,
    *,
    requested: float | None = None,
    parameter: str | None = None,
) -> dict[str, Any]:
    """Build ``details.limit`` facts for one enforced decision."""
    return limit_for(limit_id).facts(effective, requested=requested, parameter=parameter)


def raise_exceeded(
    limit_id: str,
    message: str,
    *,
    effective: float | None = None,
    requested: float | None = None,
    parameter: str | None = None,
    **details: Any,
) -> OcError:
    """Build the refusal for a request that exceeded a named ceiling."""
    return OcError(
        "limit_exceeded",
        message,
        details=details,
        limit=facts(limit_id, effective, requested=requested, parameter=parameter),
    )


def describe() -> list[dict[str, Any]]:
    """Return the registry as sorted, serializable rows for documentation."""
    rows: list[dict[str, Any]] = []
    for limit in sorted(_LIMITS, key=lambda item: item.id):
        rows.append(
            {
                "id": limit.id,
                "unit": limit.unit,
                "description": limit.description,
                "default": _number(limit.default),
                "minimum": None if limit.minimum is None else _number(limit.minimum),
                "maximum": None if limit.maximum is None else _number(limit.maximum),
                "source": limit.source.value,
                "setting": limit.env or "",
                "applies_to": ", ".join(limit.applies_to),
                "recovery": limit.recovery,
                "does_not_raise": limit.does_not_raise,
            }
        )
    return rows


def settings() -> Mapping[str, Limit]:
    """Environment-backed limits, keyed by variable name."""
    return {limit.env: limit for limit in _LIMITS if limit.env}
