"""What every tool is allowed to do, declared once.

A contract is not decoration. The same facts drive:

* the MCP ``ToolAnnotations`` a client sees (read-only, destructive, open-world),
* the ``_meta.opencyber`` contract block,
* the catalog identity digest that proves which contract revision a server serves,
* the generated tool reference, and
* the doctor's inventory checks.

Every advertised tool must have a contract. :func:`validate` fails at import when
a registered tool has none, so a new tool cannot ship without declaring its
authority.

This module is import-light: it imports the declarative catalog only, never
FastMCP, Playwright, or a tool module.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Iterable

from .catalog import CATALOG, ToolSpec


CONTRACT_SCHEMA_VERSION = 1


class Shape(StrEnum):
    """The analyst task shape a tool serves.

    Names describe the outcome, not a required prefix. A tool mixing discovery,
    execution, and mutation belongs in two tools.
    """

    INSPECT = "inspect"
    SEARCH = "search"
    TRACE = "trace"
    COMPARE = "compare"
    WORKFLOW = "workflow"
    OBSERVE = "observe"
    EXECUTE = "execute"
    MANAGE = "manage"


class Effect(StrEnum):
    """Observable side effects a caller must assume before invoking the tool."""

    PROCESS = "process"
    FILESYSTEM = "filesystem"
    NETWORK = "network"
    DEVICE = "device"
    SECRET = "secret"
    MUTATION = "mutation"


class Scope(StrEnum):
    """Which enforcement boundary the tool's target crosses."""

    NONE = "none"
    ARGV = "argv"
    URL = "url"
    DEVICE = "device"
    ENGAGEMENT = "engagement"


@dataclass(frozen=True, slots=True)
class ToolContract:
    """The declared authority of one advertised tool."""

    name: str
    kind: str
    group: str
    shape: Shape
    effects: frozenset[Effect]
    scope: Scope
    requires_engagement: bool
    destructive: bool
    open_world: bool
    idempotent: bool
    returns_target_content: bool
    error_codes: tuple[str, ...] = ()

    @property
    def read_only(self) -> bool:
        """True only when the declared authority cannot mutate state."""
        return not self.destructive and Effect.MUTATION not in self.effects

    @property
    def provenance_source(self) -> str:
        """Where the returned facts came from, for untrusted-content marking."""
        if self.returns_target_content:
            return "target"
        if self.requires_engagement:
            return "engagement"
        return "server"

    def title(self) -> str:
        return " ".join(part.capitalize() for part in self.name.removeprefix("oc_").split("_"))

    def annotations(self) -> dict[str, Any]:
        """Keyword arguments for ``mcp.types.ToolAnnotations``."""
        return {
            "title": self.title(),
            "readOnlyHint": self.read_only,
            "destructiveHint": self.destructive,
            "idempotentHint": self.idempotent,
            "openWorldHint": self.open_world,
        }

    def meta(self) -> dict[str, Any]:
        """The ``_meta.opencyber`` advertisement for this tool.

        Deliberately compact: this block is repeated for every advertised tool,
        so context cost is real. ``error_codes`` stays server-side in the
        recorded catalog and the error reference; a caller learns the exact code
        from the refusal itself.
        """
        return {
            "opencyber": {
                "contract_schema_version": CONTRACT_SCHEMA_VERSION,
                "kind": self.kind,
                "group": self.group,
                "shape": self.shape.value,
                "effects": sorted(effect.value for effect in self.effects),
                "scope": self.scope.value,
                "requires_engagement": self.requires_engagement,
                "returns_target_content": self.returns_target_content,
            }
        }

    def as_dict(self) -> dict[str, Any]:
        """Serializable projection used by the catalog digest and docs."""
        return {
            "name": self.name,
            "kind": self.kind,
            "group": self.group,
            "shape": self.shape.value,
            "effects": sorted(effect.value for effect in self.effects),
            "scope": self.scope.value,
            "requires_engagement": self.requires_engagement,
            "destructive": self.destructive,
            "open_world": self.open_world,
            "idempotent": self.idempotent,
            "returns_target_content": self.returns_target_content,
            "error_codes": list(self.error_codes),
        }


def _base_error_codes(scope: Scope, requires_engagement: bool, kind: str) -> tuple[str, ...]:
    codes = {"invalid_argument", "capability_unavailable", "internal_error"}
    if requires_engagement:
        codes.add("engagement_not_found")
    if scope is not Scope.NONE:
        codes.add("scope_denied")
    if kind == "executable":
        codes.update({"integration_unavailable", "child_failed", "timed_out", "limit_exceeded", "offline_blocked"})
    return tuple(sorted(codes))


def _native(
    name: str,
    group: str,
    shape: Shape,
    effects: Iterable[Effect] = (),
    scope: Scope = Scope.NONE,
    *,
    engagement: bool = False,
    destructive: bool = False,
    open_world: bool = False,
    idempotent: bool = True,
    target: bool = False,
    errors: Iterable[str] = (),
) -> ToolContract:
    """Declare one native tool. Defaults describe a read-only in-process query."""
    effect_set = frozenset(effects)
    return ToolContract(
        name=name,
        kind="native",
        group=group,
        shape=shape,
        effects=effect_set,
        scope=scope,
        requires_engagement=engagement,
        destructive=destructive,
        open_world=open_world,
        idempotent=idempotent,
        returns_target_content=target,
        error_codes=tuple(sorted(set(_base_error_codes(scope, engagement, "native")) | set(errors))),
    )


FILESYSTEM = Effect.FILESYSTEM
PROCESS = Effect.PROCESS
NETWORK = Effect.NETWORK
DEVICE = Effect.DEVICE
SECRET = Effect.SECRET
MUTATION = Effect.MUTATION

# Native tools, in registration order. The order is part of the generated tool
# reference and the count aliases, so append new tools rather than reordering.
_NATIVE: tuple[ToolContract, ...] = (
    # native_and_workspace
    _native("oc_catalog", "native_and_workspace", Shape.SEARCH),
    _native("oc_workspace_list", "native_and_workspace", Shape.INSPECT, [FILESYSTEM], Scope.ENGAGEMENT, engagement=True, target=True),
    _native(
        "oc_workspace_read",
        "native_and_workspace",
        Shape.INSPECT,
        [FILESYSTEM],
        Scope.ENGAGEMENT,
        engagement=True,
        target=True,
        errors=["limit_exceeded", "not_found"],
    ),
    _native(
        "oc_workspace_write",
        "native_and_workspace",
        Shape.MANAGE,
        [FILESYSTEM, MUTATION],
        Scope.ENGAGEMENT,
        engagement=True,
        destructive=True,
        idempotent=False,
        errors=["permission_denied", "limit_exceeded"],
    ),
    _native(
        "oc_workspace_delete",
        "native_and_workspace",
        Shape.MANAGE,
        [FILESYSTEM, MUTATION],
        Scope.ENGAGEMENT,
        engagement=True,
        destructive=True,
        idempotent=False,
        errors=["not_found", "permission_denied"],
    ),
    _native(
        "oc_finding_report",
        "native_and_workspace",
        Shape.MANAGE,
        [FILESYSTEM, MUTATION],
        Scope.ENGAGEMENT,
        engagement=True,
        idempotent=False,
        destructive=True,
    ),
    _native(
        "oc_http_request",
        "native_and_workspace",
        Shape.OBSERVE,
        [NETWORK, MUTATION],
        Scope.URL,
        engagement=False,
        destructive=True,
        open_world=True,
        idempotent=False,
        target=True,
        errors=["connection_failed", "timed_out", "engagement_required", "engagement_not_found"],
    ),
    _native(
        "oc_graphql_request",
        "native_and_workspace",
        Shape.OBSERVE,
        [NETWORK, MUTATION],
        Scope.URL,
        engagement=False,
        destructive=True,
        open_world=True,
        idempotent=False,
        target=True,
        errors=["connection_failed", "timed_out", "engagement_required", "engagement_not_found"],
    ),
    _native("oc_jwt_decode", "native_and_workspace", Shape.INSPECT, [SECRET], target=True),
    _native(
        "oc_openapi_inspect",
        "native_and_workspace",
        Shape.INSPECT,
        [NETWORK, FILESYSTEM],
        Scope.URL,
        engagement=True,
        open_world=True,
        target=True,
        errors=["connection_failed", "timed_out", "not_found"],
    ),
    _native(
        "oc_hibp_password_check",
        "native_and_workspace",
        Shape.INSPECT,
        [NETWORK, SECRET],
        Scope.NONE,
        open_world=True,
        errors=["offline_blocked", "connection_failed", "timed_out"],
    ),
    _native("oc_process_snapshot", "native_and_workspace", Shape.INSPECT, [PROCESS], Scope.NONE, engagement=False, target=True),
    _native(
        "oc_angr_analyze",
        "native_and_workspace",
        Shape.INSPECT,
        [PROCESS, FILESYSTEM],
        Scope.ENGAGEMENT,
        engagement=True,
        target=True,
        errors=["capability_unavailable", "not_found"],
    ),
    _native(
        "oc_cve_lookup",
        "native_and_workspace",
        Shape.INSPECT,
        [NETWORK],
        Scope.NONE,
        open_world=True,
        errors=["offline_blocked", "connection_failed", "not_found"],
    ),
    _native(
        "oc_file_hashes",
        "native_and_workspace",
        Shape.INSPECT,
        [FILESYSTEM],
        Scope.ENGAGEMENT,
        engagement=True,
        target=True,
        errors=["not_found"],
    ),
    _native("oc_payload_encode", "native_and_workspace", Shape.INSPECT),
    _native("oc_extract_indicators", "native_and_workspace", Shape.INSPECT, target=True),
    _native("oc_technology_hints", "native_and_workspace", Shape.INSPECT, target=True),
    _native("oc_engagement_plan", "native_and_workspace", Shape.WORKFLOW),
    _native("oc_recommend_tools", "native_and_workspace", Shape.WORKFLOW),
    _native("oc_attack_chain", "native_and_workspace", Shape.WORKFLOW),
    _native("oc_scan_summary", "native_and_workspace", Shape.WORKFLOW, target=True),
    _native(
        "oc_execute",
        "native_and_workspace",
        Shape.EXECUTE,
        [PROCESS, FILESYSTEM, NETWORK, MUTATION],
        Scope.ARGV,
        engagement=True,
        open_world=True,
        idempotent=False,
        target=True,
        errors=["integration_unavailable", "unknown_tool", "child_failed", "timed_out", "limit_exceeded"],
        destructive=True,
    ),
    # engagement_management
    _native(
        "oc_engagement_create",
        "engagement_management",
        Shape.MANAGE,
        [FILESYSTEM, MUTATION],
        Scope.NONE,
        idempotent=False,
        errors=["already_exists"],
    ),
    _native("oc_engagement_list", "engagement_management", Shape.INSPECT, [FILESYSTEM]),
    _native(
        "oc_engagement_get",
        "engagement_management",
        Shape.INSPECT,
        [FILESYSTEM],
        Scope.NONE,
        engagement=True,
    ),
    # general_execution
    _native(
        "oc_bash",
        "general_execution",
        Shape.EXECUTE,
        [PROCESS, FILESYSTEM, NETWORK, MUTATION],
        Scope.NONE,
        engagement=True,
        destructive=True,
        open_world=True,
        idempotent=False,
        target=True,
        errors=["scope_denied", "timed_out", "limit_exceeded", "child_failed"],
    ),
    _native(
        "oc_python",
        "general_execution",
        Shape.EXECUTE,
        [PROCESS, FILESYSTEM, NETWORK, MUTATION],
        Scope.NONE,
        engagement=True,
        destructive=True,
        open_world=True,
        idempotent=False,
        target=True,
        errors=["scope_denied", "timed_out", "limit_exceeded", "child_failed"],
    ),
    # api_audit
    _native(
        "oc_openapi_audit",
        "api_audit",
        Shape.WORKFLOW,
        [NETWORK, FILESYSTEM, MUTATION],
        Scope.URL,
        engagement=True,
        open_world=True,
        target=True,
        errors=["connection_failed", "timed_out", "not_found"],
        idempotent=False,
    ),
    _native(
        "oc_graphql_audit",
        "api_audit",
        Shape.WORKFLOW,
        [NETWORK, FILESYSTEM, MUTATION],
        Scope.URL,
        engagement=True,
        open_world=True,
        target=True,
        errors=["connection_failed", "timed_out"],
        idempotent=False,
    ),
    _native(
        "oc_jwt_audit", "api_audit", Shape.INSPECT,
        [SECRET, MUTATION, FILESYSTEM], Scope.ENGAGEMENT,
        target=True, idempotent=False, engagement=True,
    ),
    _native(
        "oc_api_fuzz",
        "api_audit",
        Shape.OBSERVE,
        [NETWORK, FILESYSTEM, MUTATION],
        Scope.URL,
        engagement=True,
        destructive=True,
        open_world=True,
        idempotent=False,
        target=True,
        errors=["limit_exceeded", "connection_failed", "timed_out"],
    ),
    # http_workbench
    _native(
        "oc_http_session_create",
        "http_workbench",
        Shape.MANAGE,
        [FILESYSTEM, MUTATION],
        Scope.ENGAGEMENT,
        engagement=True,
        destructive=True,
        idempotent=False,
        errors=["already_exists"],
    ),
    _native("oc_http_session_list", "http_workbench", Shape.SEARCH, [FILESYSTEM], Scope.ENGAGEMENT, engagement=True, target=True),
    _native(
        "oc_http_session_get",
        "http_workbench",
        Shape.INSPECT,
        [FILESYSTEM],
        Scope.ENGAGEMENT,
        engagement=True,
        errors=["not_found"],
        target=True,
    ),
    _native(
        "oc_http_session_update",
        "http_workbench",
        Shape.MANAGE,
        [FILESYSTEM, MUTATION],
        Scope.ENGAGEMENT,
        engagement=True,
        destructive=True,
        idempotent=False,
        errors=["not_found"],
        target=True,
    ),
    _native(
        "oc_http_repeater",
        "http_workbench",
        Shape.OBSERVE,
        [NETWORK, FILESYSTEM, MUTATION],
        Scope.URL,
        engagement=True,
        destructive=True,
        open_world=True,
        idempotent=False,
        target=True,
        errors=["not_found", "connection_failed", "timed_out"],
    ),
    _native(
        "oc_http_intruder",
        "http_workbench",
        Shape.OBSERVE,
        [NETWORK, FILESYSTEM, MUTATION],
        Scope.URL,
        engagement=True,
        destructive=True,
        open_world=True,
        idempotent=False,
        target=True,
        errors=["limit_exceeded", "not_found", "connection_failed", "timed_out"],
    ),
    _native("oc_http_history", "http_workbench", Shape.INSPECT, [FILESYSTEM], Scope.ENGAGEMENT, engagement=True, target=True),
    # browser
    _native(
        "oc_browser_create",
        "browser",
        Shape.MANAGE,
        [PROCESS, NETWORK, MUTATION, FILESYSTEM],
        Scope.ENGAGEMENT,
        engagement=True,
        open_world=True,
        idempotent=False,
        errors=["capability_unavailable"],
    ),
    _native("oc_browser_list", "browser", Shape.SEARCH, [PROCESS], Scope.ENGAGEMENT, engagement=True, target=True),
    _native("oc_browser_get", "browser", Shape.INSPECT, [PROCESS], Scope.ENGAGEMENT, engagement=True, errors=["not_found"], target=True),
    _native(
        "oc_browser_close",
        "browser",
        Shape.MANAGE,
        [PROCESS, MUTATION],
        Scope.ENGAGEMENT,
        engagement=True,
        idempotent=False,
        errors=["not_found"],
    ),
    _native(
        "oc_browser_navigate",
        "browser",
        Shape.OBSERVE,
        [PROCESS, NETWORK, MUTATION, FILESYSTEM],
        Scope.URL,
        engagement=True,
        destructive=True,
        open_world=True,
        idempotent=False,
        target=True,
        errors=["not_found", "timed_out", "connection_failed"],
    ),
    _native("oc_browser_snapshot", "browser", Shape.INSPECT, [PROCESS], Scope.ENGAGEMENT, engagement=True, target=True, errors=["not_found"]),
    _native(
        "oc_browser_action",
        "browser",
        Shape.OBSERVE,
        [PROCESS, NETWORK, MUTATION, FILESYSTEM],
        Scope.ENGAGEMENT,
        engagement=True,
        destructive=True,
        open_world=True,
        idempotent=False,
        target=True,
        errors=["not_found"],
    ),
    _native(
        "oc_browser_screenshot",
        "browser",
        Shape.INSPECT,
        [PROCESS, FILESYSTEM, MUTATION],
        Scope.ENGAGEMENT,
        engagement=True,
        idempotent=False,
        target=True,
        errors=["not_found"],
        destructive=True,
    ),
    _native(
        "oc_browser_evaluate",
        "browser",
        Shape.OBSERVE,
        [PROCESS, NETWORK, MUTATION, FILESYSTEM],
        Scope.ENGAGEMENT,
        engagement=True,
        destructive=True,
        open_world=True,
        idempotent=False,
        target=True,
        errors=["not_found"],
    ),
    _native("oc_browser_state", "browser", Shape.INSPECT, [PROCESS, SECRET], Scope.ENGAGEMENT, engagement=True, target=True, errors=["not_found"]),
    _native(
        "oc_browser_set_state",
        "browser",
        Shape.MANAGE,
        [PROCESS, SECRET, MUTATION],
        Scope.ENGAGEMENT,
        engagement=True,
        destructive=True,
        idempotent=False,
        errors=["not_found"],
        target=True,
    ),
    _native(
        "oc_browser_network_rules",
        "browser",
        Shape.MANAGE,
        [PROCESS, NETWORK, MUTATION],
        Scope.ENGAGEMENT,
        engagement=True,
        destructive=True,
        idempotent=False,
        errors=["not_found"],
    ),
    _native(
        "oc_browser_network_log",
        "browser",
        Shape.INSPECT,
        [PROCESS, MUTATION, FILESYSTEM],
        Scope.ENGAGEMENT,
        engagement=True,
        target=True,
        errors=["not_found", "limit_exceeded"],
        idempotent=False,
        destructive=True,
    ),
    # hardware
    _native("oc_hardware_inventory", "hardware", Shape.INSPECT, [DEVICE, FILESYSTEM], target=True),
    _native("oc_hardware_readiness", "hardware", Shape.INSPECT, [DEVICE, FILESYSTEM], target=True),
    _native("oc_hardware_plan", "hardware", Shape.WORKFLOW, [DEVICE]),
    _native(
        "oc_serial_open",
        "hardware",
        Shape.MANAGE,
        [DEVICE, PROCESS, MUTATION, FILESYSTEM],
        Scope.DEVICE,
        engagement=True,
        idempotent=False,
        errors=["capability_unavailable", "already_exists"],
        destructive=True,
    ),
    _native("oc_serial_list", "hardware", Shape.SEARCH, [DEVICE], Scope.ENGAGEMENT, engagement=True),
    _native(
        "oc_serial_read",
        "hardware",
        Shape.OBSERVE,
        [DEVICE, MUTATION, FILESYSTEM],
        Scope.ENGAGEMENT,
        engagement=True,
        idempotent=False,
        target=True,
        errors=["not_found", "timed_out", "limit_exceeded"],
    ),
    _native(
        "oc_serial_write",
        "hardware",
        Shape.MANAGE,
        [DEVICE, MUTATION, FILESYSTEM],
        Scope.DEVICE,
        engagement=True,
        destructive=True,
        idempotent=False,
        errors=["not_found"],
    ),
    _native("oc_serial_close", "hardware", Shape.MANAGE, [DEVICE, MUTATION, FILESYSTEM], Scope.ENGAGEMENT, engagement=True, idempotent=False, errors=["not_found"]),
    _native(
        "oc_firmware_analyze",
        "hardware",
        Shape.INSPECT,
        [FILESYSTEM, PROCESS, MUTATION],
        Scope.ENGAGEMENT,
        engagement=True,
        target=True,
        errors=["not_found", "capability_unavailable"],
        idempotent=False,
        destructive=True,
    ),
    # audit
    _native("oc_audit_log", "audit", Shape.INSPECT, [FILESYSTEM], Scope.ENGAGEMENT, engagement=True, errors=["limit_exceeded"], target=True),
    _native("oc_audit_verify", "audit", Shape.INSPECT, [FILESYSTEM], Scope.ENGAGEMENT, engagement=True, errors=["integrity_mismatch"]),
    # policy
    _native("oc_scope_check", "policy", Shape.INSPECT, scope=Scope.ENGAGEMENT, engagement=True),
    # assets
    _native("oc_assets_status", "assets", Shape.INSPECT, [FILESYSTEM]),
    _native("oc_offline_status", "assets", Shape.INSPECT),
    # blue_team
    _native(
        "oc_file_triage",
        "blue_team",
        Shape.INSPECT,
        [FILESYSTEM, PROCESS, MUTATION],
        Scope.ENGAGEMENT,
        engagement=True,
        target=True,
        errors=["not_found", "limit_exceeded"],
        idempotent=False,
    ),
    _native(
        "oc_log_timeline",
        "blue_team",
        Shape.INSPECT,
        [FILESYSTEM, MUTATION],
        Scope.ENGAGEMENT,
        engagement=True,
        target=True,
        errors=["not_found", "limit_exceeded"],
        idempotent=False,
    ),
    _native(
        "oc_pcap_triage",
        "blue_team",
        Shape.INSPECT,
        [FILESYSTEM, PROCESS, MUTATION],
        Scope.ENGAGEMENT,
        engagement=True,
        target=True,
        errors=["not_found", "limit_exceeded", "capability_unavailable"],
        idempotent=False,
    ),
    _native(
        "oc_evidence_export",
        "blue_team",
        Shape.MANAGE,
        [FILESYSTEM, MUTATION],
        Scope.ENGAGEMENT,
        engagement=True,
        idempotent=False,
        errors=["already_exists", "limit_exceeded"],
    ),
    _native(
        "oc_evidence_verify",
        "blue_team",
        Shape.INSPECT,
        [FILESYSTEM],
        Scope.ENGAGEMENT,
        engagement=True,
        errors=["not_found", "integrity_mismatch"],
    ),
    # poc_chain
    _native("oc_authorization_get", "poc_chain", Shape.INSPECT, [FILESYSTEM], Scope.ENGAGEMENT, engagement=True),
    _native(
        "oc_chain_plan",
        "poc_chain",
        Shape.WORKFLOW,
        [FILESYSTEM, MUTATION],
        Scope.ENGAGEMENT,
        engagement=True,
        idempotent=False,
        target=True,
    ),
    _native("oc_chain_get", "poc_chain", Shape.INSPECT, [FILESYSTEM], Scope.ENGAGEMENT, engagement=True, target=True, errors=["not_found", "integrity_mismatch"]),
    _native(
        "oc_poc_spec_create",
        "poc_chain",
        Shape.MANAGE,
        [FILESYSTEM, MUTATION],
        Scope.ENGAGEMENT,
        engagement=True,
        idempotent=False,
        errors=["invalid_argument", "already_exists"],
    ),
    _native("oc_poc_render", "poc_chain", Shape.INSPECT, [FILESYSTEM, MUTATION], Scope.ENGAGEMENT, engagement=True, idempotent=False, errors=["not_found", "invalid_argument"]),
    _native("oc_poc_lint", "poc_chain", Shape.INSPECT, [], Scope.ENGAGEMENT, engagement=True, errors=["not_found", "scope_denied"]),
    _native(
        "oc_poc_run",
        "poc_chain",
        Shape.EXECUTE,
        [PROCESS, NETWORK, FILESYSTEM, MUTATION],
        Scope.ENGAGEMENT,
        engagement=True,
        open_world=True,
        idempotent=False,
        target=True,
        errors=[
            "not_found",
            "execution_failed",
            "authorization_required",
            "authorization_invalid",
            "approval_invalid",
            "conflict",
            "timed_out",
            "limit_exceeded",
            "scope_denied",
        ],
        destructive=True,
    ),
    _native("oc_poc_evidence", "poc_chain", Shape.INSPECT, [FILESYSTEM], Scope.ENGAGEMENT, engagement=True, target=True, errors=["not_found", "execution_failed"]),
    _native(
        "oc_result_get",
        "blue_team",
        Shape.INSPECT,
        [FILESYSTEM],
        Scope.ENGAGEMENT,
        engagement=True,
        target=True,
        errors=["not_found", "integrity_mismatch"],
    ),
    _native(
        "oc_result_list",
        "blue_team",
        Shape.SEARCH,
        [FILESYSTEM],
        Scope.ENGAGEMENT,
        engagement=True,
        target=True,
        errors=["limit_exceeded", "integrity_mismatch"],
    ),
    # diagnostics
    _native("oc_doctor", "diagnostics", Shape.INSPECT),
)


NETWORK_CATEGORIES = frozenset(
    {
        "automotive",
        "cloud_container_iac",
        "credentials",
        "enumeration",
        "exploitation",
        "gps",
        "ir",
        "mobile",
        "network",
        "web",
        "wireless",
        "wireless_attack",
    }
)
DEVICE_CATEGORIES = frozenset({"automotive", "embedded", "gps", "nfc_rfid", "rf", "usb", "wireless", "wireless_attack"})


def _for_executable(spec: ToolSpec) -> ToolContract:
    """Derive the contract for one executable-backed catalog entry.

    These tools share one argv-only schema and one authority model: they run a
    child process inside the container, read and write the engagement, and may
    reach a target. The category adds the network or device effect and marks
    whether the tool reaches the network or a device. Arbitrary argv cannot
    promise non-destructive behavior: updates, writes and code execution are
    possible outside the actively offensive categories as well.
    """
    effects = {PROCESS, FILESYSTEM, MUTATION}
    if spec.category in NETWORK_CATEGORIES:
        effects.add(NETWORK)
    if spec.category in DEVICE_CATEGORIES:
        effects.add(DEVICE)
    return ToolContract(
        name=spec.name,
        kind="executable",
        group=spec.category,
        shape=Shape.EXECUTE,
        effects=frozenset(effects),
        scope=Scope.ARGV,
        requires_engagement=True,
        destructive=True,
        open_world=bool(effects & {NETWORK, DEVICE}),
        idempotent=False,
        returns_target_content=True,
        error_codes=_base_error_codes(Scope.ARGV, True, "executable"),
    )


NATIVE_CONTRACTS_COUNT = len(_NATIVE)

CONTRACTS: dict[str, ToolContract] = {
    contract.name: contract for contract in (*_NATIVE, *(_for_executable(spec) for spec in CATALOG))
}

if len(CONTRACTS) != len(_NATIVE) + len(CATALOG):  # pragma: no cover - import-time invariant
    raise RuntimeError("duplicate tool name in OpenCyber contract registry")


def native_groups() -> dict[str, tuple[str, ...]]:
    """Group native tool names in registration order, for docs and counts."""
    groups: dict[str, list[str]] = {}
    for contract in _NATIVE:
        groups.setdefault(contract.group, []).append(contract.name)
    return {group: tuple(names) for group, names in groups.items()}


def contract_for(name: str) -> ToolContract:
    try:
        return CONTRACTS[name]
    except KeyError:
        raise KeyError(f"no contract registered for tool {name}") from None


def validate(advertised: Iterable[str]) -> None:
    """Fail at import when an advertised tool has no declared contract."""
    missing = sorted(set(advertised) - set(CONTRACTS))
    if missing:
        raise RuntimeError(f"advertised tools without a contract: {', '.join(missing)}")
