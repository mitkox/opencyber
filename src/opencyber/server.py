"""Direct stdio MCP server for OpenCyber Harness."""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import threading
from typing import Any, Awaitable, Callable

from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from . import __version__
from .api_audit import audit_graphql, audit_jwt, audit_openapi, fuzz_api_parameter
from .assets import assets_status, offline_status, verify_manifest
from .audit import read_audit, verify_audit
from .authorization import describe_authorization
from .browser import BROWSER_MANAGER
from .catalog import CATALOG, HARDWARE_CATEGORIES, ToolSpec, category_counts
from .catalog_identity import alignment as catalog_alignment, payload_bytes as catalog_payload_bytes
from .contracts import CONTRACTS, contract_for, validate as validate_contracts
from .envelope import coverage as envelope_coverage, wrap as wrap_tool
from .errors import OcError
from .cve_chain import list_chains, load_chain, plan_chain
from .diagnostics import (
    API_AUDIT_TOOL_COUNT,
    ASSET_TOOL_COUNT,
    AUDIT_TOOL_COUNT,
    BROWSER_TOOL_COUNT,
    ENGAGEMENT_MANAGEMENT_TOOL_COUNT,
    FIXED_MCP_TOOL_COUNT,
    FIXED_TOOL_CATEGORIES,
    GENERAL_EXECUTION_TOOL_COUNT,
    HARDWARE_TOOL_COUNT,
    HTTP_WORKBENCH_TOOL_COUNT,
    NATIVE_AND_WORKSPACE_TOOL_COUNT as LEGACY_NATIVE_AND_WORKSPACE_TOOL_COUNT,
    POLICY_TOOL_COUNT,
    doctor_report as diagnostics_doctor_report,
    self_test as diagnostics_self_test,
)
from .engagements import WORKSPACE, create_engagement, get_engagement, list_engagements
from .evidence import export_evidence, verify_evidence
from .hardware import (
    analyze_firmware,
    hardware_inventory,
    hardware_plan,
    hardware_readiness,
    serial_close,
    serial_list,
    serial_open,
    serial_read,
    serial_write,
)
from .policy import enforcement_enabled, enforcement_decision, scope_check
from .result_store import get_result as get_retained_result, list_results as list_retained_results
from .poc import create_spec, get_run, lint as lint_poc, list_runs, render as render_poc, run as run_poc
from .poc_schema import PocError
from .execution_tools import execute_bash, execute_python
from .http_workbench import create_http_session, get_http_session, intrude_http_parameter, list_http_sessions, read_http_history, repeat_http_request, update_http_session
from .executor import execute_tool
from .native_tools import analyze_binary_with_angr, decode_jwt, encode_payload, extract_indicators, graphql_request, hash_workspace_file, hibp_password_range, http_request, inspect_openapi, lookup_cve, process_snapshot, technology_hints
from .workspace import delete_workspace_path, list_workspace, read_workspace_file, write_finding_report, write_workspace_file
from .triage import file_triage, log_timeline, pcap_triage
from .workflows import WORKFLOW_STEPS, attack_chain, engagement_plan, recommend_tools, scan_summary


mcp = MCPServer(
    "OpenCyber Harness",
    version=__version__,
    instructions=(
        "OpenCyber Harness is a container-native red and blue team security toolkit. Use tools only for "
        "authorized targets. Executable-backed tools accept explicit argv tokens and never "
        "invoke a shell unless the caller explicitly selects oc_bash. Before using an "
        "executable or workspace-backed tool, create an "
        "engagement with oc_engagement_create or select an existing ID returned by "
        "oc_engagement_list. Supply that engagement_id on every relevant tool call. In "
        "full mode prefer direct named OpenCyber tools. Use oc_execute only with an exact "
        "oc_* name returned by a filtered oc_catalog query. Prefer oc_jq or "
        "oc_python over grep for structured JSON, and prefer specialized API/browser "
        "tools over ad-hoc parsing when they match the task. For physical-layer work, "
        "call oc_hardware_inventory or oc_hardware_readiness first: the binary being "
        "installed does not mean the host passed the device through. Prefer "
        "oc_serial_open/read/write over interactive minicom so transcripts are "
        "persisted. Airgapped deployments should set OPENCYBER_OFFLINE=1; internet-only "
        "tools then fail with an actionable message instead of hanging. For supplied evidence, "
        "use oc_file_triage, oc_log_timeline, or oc_pcap_triage; these never execute the input. "
        "Reports and evidence bundles contain sensitive data and stay in the engagement. "
        "Chain planning and PoC tools (oc_chain_*, oc_poc_*) are for authorized research only: "
        "oc_poc_run requires a signed operator authorization and a signed single-use approval, "
        "and refuses without them. Never attempt to bypass that gate."
    ),
)


def _registered_catalog() -> tuple[ToolSpec, ...]:
    mode = os.environ.get("OPENCYBER_MCP_MODE", "full").strip().lower()
    if mode == "compact":
        return ()
    raw_categories = os.environ.get("OPENCYBER_TOOL_CATEGORIES", "").strip()
    if not raw_categories:
        return CATALOG
    selected = {category.strip() for category in raw_categories.split(",") if category.strip()}
    unknown = selected - set(category_counts())
    if unknown:
        raise ValueError(f"unknown OPENCYBER_TOOL_CATEGORIES: {sorted(unknown)}")
    return tuple(spec for spec in CATALOG if spec.category in selected)


REGISTERED_CATALOG = _registered_catalog()


def _external_tool(spec: ToolSpec) -> Callable[..., Awaitable[dict[str, Any]]]:
    async def run(
        engagement_id: str,
        arguments: list[str],
        working_directory: str = ".",
        stdin: str | None = None,
    ) -> dict[str, Any]:
        """Run a OpenCyber container executable with explicit argv tokens."""
        result = await execute_tool(
            spec.executable,
            arguments,
            engagement_id=engagement_id,
            working_directory=working_directory,
            stdin=stdin,
        )
        result["oc_tool"] = spec.name
        result["category"] = spec.category
        return result

    run.__name__ = spec.name
    run.__qualname__ = spec.name
    run.__doc__ = spec.description
    return run


for _spec in REGISTERED_CATALOG:
    mcp.tool(
        name=_spec.name,
        description=(
            f"{_spec.description} Runs from the selected engagement namespace; "
            "use relative paths for engagement artifacts."
        ),
        structured_output=True,
    )(
        _external_tool(_spec)
    )


@mcp.tool(name="oc_catalog", description="Search every OpenCyber executable and native MCP tool by exact `oc_*` name, substring query, or category. Also reports the catalog digest: recorded_catalog_digest is the contract this release shipped, catalog_digest is what this process advertises, and catalog_matches_release says whether they agree. An unfiltered call returns only counts; set include_all=true only when the complete catalog is genuinely required.", structured_output=True)
def oc_catalog(name: str | None = None, query: str | None = None, category: str | None = None, missing_only: bool = False, registered_only: bool = False, include_all: bool = False, include_contracts: bool = False, expected_catalog_digest: str | None = None, limit: int = 0, offset: int = 0) -> dict[str, Any]:
    if name and query:
        raise ValueError("choose either exact name or substring query, not both")
    registered_names = {spec.name for spec in REGISTERED_CATALOG}
    managed_tools = mcp._tool_manager._tools
    external_names = {spec.name for spec in CATALOG}
    candidates: list[dict[str, Any]] = []
    for spec in CATALOG:
        managed = managed_tools.get(spec.name)
        availability = spec.availability()
        entry: dict[str, Any] = {
            **spec.as_dict(),
            "available": availability["available"],
            "path": availability["path"],
            "registered_individually": spec.name in registered_names,
            "kind": "executable",
        }
        if include_contracts:
            entry["input_schema"] = managed.parameters if managed else {
                "required": ["tool", "engagement_id", "arguments"],
                "properties": {
                    "tool": {"const": spec.name},
                    "engagement_id": {"type": "string"},
                    "arguments": {"type": "array", "items": {"type": "string"}},
                    "working_directory": {"type": "string", "default": "."},
                    "stdin": {"type": ["string", "null"], "default": None},
                },
            }
        candidates.append(entry)
    for tool_name, managed in managed_tools.items():
        if tool_name in external_names:
            continue
        entry = {
            "name": tool_name,
            "executable": None,
            "category": contract_for(tool_name).group,
            "description": managed.description or "",
            "available": True,
            "path": None,
            "registered_individually": True,
            "kind": "native",
        }
        if include_contracts:
            entry["input_schema"] = managed.parameters
        candidates.append(entry)
    exact_exists = name is None or any(entry["name"] == name for entry in candidates)
    if not exact_exists:
        raise ValueError(f"unknown OpenCyber catalog tool: {name}")
    tools = []
    for entry in candidates:
        if name and entry["name"] != name:
            continue
        if query:
            haystack = " ".join(
                str(entry.get(field) or "")
                for field in ("name", "executable", "category", "description", "kind")
            ).lower()
            if query.strip().lower() not in haystack:
                continue
        if category:
            category_match = entry["category"] == category
            if category == "hardware" and entry["category"] in HARDWARE_CATEGORIES:
                category_match = True
            if not category_match:
                continue
        if registered_only and not entry["registered_individually"]:
            continue
        if missing_only and entry["available"]:
            continue
        if include_all or name or query or category or missing_only or registered_only:
            tools.append(entry)
    if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
        raise OcError("invalid_argument", "limit must be a non-negative integer; 0 returns every match",
                      details={"parameter": "limit"})
    if isinstance(offset, bool) or not isinstance(offset, int) or offset < 0:
        raise OcError("invalid_argument", "offset must be a non-negative integer", details={"parameter": "offset"})
    matched_total = len(tools)
    selected_tools = tools[offset : offset + limit] if limit else tools[offset:]
    examined = offset + len(selected_tools)
    exhausted = examined >= matched_total
    native_counts: dict[str, int] = {}
    for entry in candidates:
        if entry["kind"] == "native":
            native_counts[entry["category"]] = native_counts.get(entry["category"], 0) + 1
    advertised = mcp._tool_manager._tools
    alignment = catalog_alignment(advertised)
    alignment["expected_digest"] = expected_catalog_digest
    alignment["matches_expected"] = (
        None if expected_catalog_digest is None else expected_catalog_digest == alignment["advertised_sha256"]
    )
    return {
        "version": __version__,
        "workspace": str(WORKSPACE),
        "engagements_root": str(WORKSPACE / "engagements"),
        "catalog_digest": alignment["advertised_sha256"],
        "recorded_catalog_digest": alignment["recorded_sha256"],
        "catalog_matches_release": alignment["matches"],
        "catalog_subset_matches_release": alignment["subset_matches"],
        "catalog_profile": alignment["profile"],
        "catalog_contract_schema_version": alignment["contract_schema_version"],
        "advertised_payload_bytes": catalog_payload_bytes(advertised),
        "catalog_alignment": alignment,
        "external_tool_count": len(CATALOG),
        "registered_external_tool_count": len(REGISTERED_CATALOG),
        "native_and_workspace_tool_count": LEGACY_NATIVE_AND_WORKSPACE_TOOL_COUNT,
        "engagement_management_tool_count": ENGAGEMENT_MANAGEMENT_TOOL_COUNT,
        "general_execution_tool_count": GENERAL_EXECUTION_TOOL_COUNT,
        "api_audit_tool_count": API_AUDIT_TOOL_COUNT,
        "http_workbench_tool_count": HTTP_WORKBENCH_TOOL_COUNT,
        "browser_tool_count": BROWSER_TOOL_COUNT,
        "hardware_tool_count": HARDWARE_TOOL_COUNT,
        "audit_tool_count": AUDIT_TOOL_COUNT,
        "policy_tool_count": POLICY_TOOL_COUNT,
        "blue_team_tool_count": len(FIXED_TOOL_CATEGORIES["blue_team"]),
        "asset_tool_count": ASSET_TOOL_COUNT,
        "advertised_mcp_tool_count": len(REGISTERED_CATALOG) + FIXED_MCP_TOOL_COUNT,
        "mcp_mode": os.environ.get("OPENCYBER_MCP_MODE", "full"),
        "workflow_kinds": sorted(WORKFLOW_STEPS),
        "category_counts": category_counts(),
        "hardware_categories": sorted(HARDWARE_CATEGORIES),
        "native_category_counts": dict(sorted(native_counts.items())),
        "complete_catalog_count": len(candidates),
        "matched_tool_count": matched_total,
        "returned_tool_count": len(selected_tools),
        "coverage": envelope_coverage(
            "empty" if matched_total == 0 else ("complete" if exhausted else "partial"),
            examined=examined,
            total=matched_total,
            exhausted=exhausted,
            next_offset=None if exhausted else examined,
        ),
        "continuation": (
            None
            if exhausted
            else {
                "tool": "oc_catalog",
                "arguments": {
                    "name": name,
                    "query": query,
                    "category": category,
                    "missing_only": missing_only,
                    "registered_only": registered_only,
                    "include_all": include_all,
                    "include_contracts": include_contracts,
                    "limit": limit,
                    "offset": examined,
                },
            }
        ),
        "hint": (
            "Use name for one exact oc_* contract, query for substring discovery, "
            "category for a tool family, or include_all=true for every entry. "
            "Page a large match set with limit/offset."
        ),
        "tools": selected_tools,
    }


@mcp.tool(name="oc_execute", description="Dispatch one executable-backed catalog entry by its exact `oc_*` name returned by oc_catalog. This is primarily a compact-mode fallback; in full mode prefer the direct named tool. Use relative paths for engagement artifacts.", structured_output=True)
async def oc_execute(tool: str, engagement_id: str, arguments: list[str], working_directory: str = ".", stdin: str | None = None) -> dict[str, Any]:
    spec = next((entry for entry in CATALOG if entry.name == tool), None)
    if spec is None:
        raise ValueError(f"unknown OpenCyber catalog tool: {tool}")
    result = await execute_tool(spec.executable, arguments, engagement_id=engagement_id, working_directory=working_directory, stdin=stdin)
    result["oc_tool"] = spec.name
    result["category"] = spec.category
    return result


@mcp.tool(name="oc_bash", description="Run an arbitrary Bash script inside the OpenCyber container from the selected engagement directory. Supports pipelines and redirection; the container is the trust boundary. Execution is asynchronous and client-cancellable.", structured_output=True)
async def oc_bash(engagement_id: str, script: str, working_directory: str = ".", stdin: str | None = None, environment: dict[str, str] | None = None) -> dict[str, Any]:
    return await execute_bash(engagement_id, script, working_directory, stdin, environment)


@mcp.tool(name="oc_python", description="Run inline Python source or an engagement-relative Python file inside the OpenCyber container. Provide exactly one of source or path. Execution uses the OpenCyber Python environment and is asynchronous and client-cancellable.", structured_output=True)
async def oc_python(engagement_id: str, source: str = "", path: str = "", script_arguments: list[str] | None = None, working_directory: str = ".", stdin: str | None = None, environment: dict[str, str] | None = None) -> dict[str, Any]:
    return await execute_python(engagement_id, source, path, script_arguments, working_directory, stdin, environment)


@mcp.tool(name="oc_engagement_create", description="Create a persistent engagement namespace and return its server-generated ID.", structured_output=True)
async def oc_engagement_create(name: str, targets: list[str], objective: str = "") -> dict[str, Any]:
    return await asyncio.to_thread(create_engagement, name, targets, objective)


@mcp.tool(name="oc_engagement_list", description="List persistent OpenCyber engagements available for client-side selection.", structured_output=True)
async def oc_engagement_list() -> dict[str, Any]:
    return await asyncio.to_thread(list_engagements)


@mcp.tool(name="oc_engagement_get", description="Return metadata for one server-generated OpenCyber engagement ID.", structured_output=True)
async def oc_engagement_get(engagement_id: str) -> dict[str, Any]:
    return await asyncio.to_thread(get_engagement, engagement_id)


@mcp.tool(name="oc_workspace_list", description="List files within the OpenCyber engagement workspace. Reports total_entries and coverage; a bounded page returns next_offset and a continuation. limit=0 (default) returns every entry.", structured_output=True)
async def oc_workspace_list(engagement_id: str, path: str = ".", recursive: bool = False, limit: int = 0, offset: int = 0) -> dict[str, Any]:
    return await asyncio.to_thread(list_workspace, engagement_id, path, recursive, limit, offset)


@mcp.tool(name="oc_workspace_read", description="Read a UTF-8 text file from the OpenCyber engagement workspace. Returns at most max_bytes (default 1 MiB); a bounded read reports total_bytes, next_offset, and a continuation. Set max_bytes=0 for the whole file.", structured_output=True)
async def oc_workspace_read(engagement_id: str, path: str, max_bytes: int = 1048576, offset: int = 0) -> dict[str, Any]:
    return await asyncio.to_thread(read_workspace_file, engagement_id, path, max_bytes=max_bytes, offset=offset)


@mcp.tool(name="oc_workspace_write", description="Write or append a UTF-8 text file inside the OpenCyber engagement workspace.", structured_output=True)
async def oc_workspace_write(engagement_id: str, path: str, content: str, append: bool = False) -> dict[str, Any]:
    return await asyncio.to_thread(write_workspace_file, engagement_id, path, content, append)


@mcp.tool(name="oc_workspace_delete", description="Delete one file or empty directory inside the OpenCyber engagement workspace.", structured_output=True)
async def oc_workspace_delete(engagement_id: str, path: str) -> dict[str, Any]:
    return await asyncio.to_thread(delete_workspace_path, engagement_id, path)


@mcp.tool(name="oc_finding_report", description="Write a structured Markdown security finding inside the engagement workspace. Pass evidence_ids to cite retained tool results by their evidence digest; each is resolved and rendered with its digest and retention state.", structured_output=True)
async def oc_finding_report(engagement_id: str, path: str, title: str, target: str, severity: str, summary: str, evidence: list[str], remediation: str = "", evidence_ids: list[str] | None = None) -> dict[str, Any]:
    return await asyncio.to_thread(write_finding_report, engagement_id, path, title, target, severity, summary, evidence, remediation, evidence_ids)


@mcp.tool(name="oc_http_request", description="Send an HTTP request and return its status, headers and up to 256 KiB of decompressed response body. Larger bodies report truncation and partial coverage. When OPENCYBER_ENFORCE_SCOPE is on, engagement_id is required and the requested host must be in the engagement targets.", structured_output=True)
async def oc_http_request(method: str, url: str, headers: dict[str, str] | None = None, body: str | None = None, follow_redirects: bool = True, timeout: float | None = None, engagement_id: str | None = None) -> dict[str, Any]:
    return await asyncio.to_thread(http_request, method, url, headers, body, follow_redirects, timeout, engagement_id)


@mcp.tool(name="oc_graphql_request", description="Send a GraphQL query and return the full server response. When OPENCYBER_ENFORCE_SCOPE is on, engagement_id is required and the requested host must be in the engagement targets.", structured_output=True)
async def oc_graphql_request(url: str, query: str, variables: dict[str, Any] | None = None, headers: dict[str, str] | None = None, timeout: float | None = None, engagement_id: str | None = None) -> dict[str, Any]:
    return await asyncio.to_thread(graphql_request, url, query, variables, headers, timeout, engagement_id)


@mcp.tool(name="oc_jwt_decode", description="Decode JWT header and payload fields without claiming signature verification.", structured_output=True)
def oc_jwt_decode(token: str) -> dict[str, Any]:
    return decode_jwt(token)


@mcp.tool(name="oc_openapi_inspect", description="Extract operations from a JSON OpenAPI document at a URL or engagement-relative path. Prefer this over grep, jq, or Python when the task is OpenAPI operation inventory.", structured_output=True)
async def oc_openapi_inspect(engagement_id: str, source: str, timeout: float | None = None) -> dict[str, Any]:
    return await asyncio.to_thread(inspect_openapi, engagement_id, source, timeout)


@mcp.tool(name="oc_hibp_password_check", description="Check a password against HIBP using its k-anonymity range API.", structured_output=True)
async def oc_hibp_password_check(password: str, timeout: float | None = None) -> dict[str, Any]:
    return await asyncio.to_thread(hibp_password_range, password, timeout)


@mcp.tool(name="oc_process_snapshot", description="Return the container process table and active network connections.", structured_output=True)
async def oc_process_snapshot(include_connections: bool = True) -> dict[str, Any]:
    return await asyncio.to_thread(process_snapshot, include_connections)


@mcp.tool(name="oc_angr_analyze", description="Analyze a workspace binary with the angr Python library.", structured_output=True)
async def oc_angr_analyze(engagement_id: str, path: str, auto_load_libs: bool = False) -> dict[str, Any]:
    return await asyncio.to_thread(analyze_binary_with_angr, engagement_id, path, auto_load_libs)


@mcp.tool(name="oc_cve_lookup", description="Retrieve a CVE record from NVD without inventing intelligence.", structured_output=True)
async def oc_cve_lookup(cve_id: str, timeout: float | None = None) -> dict[str, Any]:
    return await asyncio.to_thread(lookup_cve, cve_id, timeout)


@mcp.tool(name="oc_file_hashes", description="Calculate complete cryptographic hashes for a workspace file.", structured_output=True)
async def oc_file_hashes(engagement_id: str, path: str, algorithms: list[str] | None = None) -> dict[str, Any]:
    return await asyncio.to_thread(hash_workspace_file, engagement_id, path, algorithms)


async def _analysis_call(function: Callable[..., dict[str, Any]], *args: Any, **kwargs: Any) -> dict[str, Any]:
    """Signal cancellation to file/process workers and wait for their cleanup."""
    cancelled = threading.Event()
    worker = asyncio.create_task(asyncio.to_thread(function, *args, cancel_event=cancelled, **kwargs))
    try:
        return await asyncio.shield(worker)
    except asyncio.CancelledError:
        cancelled.set()
        while not worker.done():
            try:
                await asyncio.shield(worker)
            except asyncio.CancelledError:
                continue
            except Exception:
                break
        if not worker.cancelled():
            worker.exception()
        raise


@mcp.tool(name="oc_file_triage", description="Triage a supplied engagement file offline: complete SHA-256, file identification, bounded strings and indicators. Never executes the input; returns a persisted report path and explicit analysis limits.", structured_output=True)
async def oc_file_triage(engagement_id: str, path: str, max_bytes: int = 16777216, min_string_length: int = 4) -> dict[str, Any]:
    return await _analysis_call(file_triage, engagement_id, path, max_bytes=max_bytes, min_string_length=min_string_length)


@mcp.tool(name="oc_log_timeline", description="Build an offline timeline from JSONL or ISO-8601-prefixed text in an engagement. Preserves raw timestamps and source lines, reports malformed or unresolved records, and never invents a timezone.", structured_output=True)
async def oc_log_timeline(engagement_id: str, path: str, format: str = "auto", timestamp_field: str = "timestamp", timezone: str | None = None, max_bytes: int = 16777216, max_records: int = 10000) -> dict[str, Any]:
    return await _analysis_call(log_timeline, engagement_id, path, format=format, timestamp_field=timestamp_field, timezone=timezone, max_bytes=max_bytes, max_records=max_records)


@mcp.tool(name="oc_pcap_triage", description="Analyze a supplied PCAP/PCAPNG offline with fixed tshark arguments and name resolution disabled. Reports packet, endpoint, protocol and DNS/HTTP/TLS observations; never captures or replays traffic.", structured_output=True)
async def oc_pcap_triage(engagement_id: str, path: str, max_bytes: int = 16777216, max_packets: int = 10000) -> dict[str, Any]:
    return await _analysis_call(pcap_triage, engagement_id, path, max_bytes=max_bytes, max_packets=max_packets)


@mcp.tool(name="oc_doctor", description="Report harness readiness as a typed check list: every check has an id, a pass/warn/fail status, a message, and a remediation when it fails. Includes catalog identity alignment, required and optional integrations, assets, wordlists, browser, analysis runtime, hardware domains, and limit environment validity. Read-only and engagement-free.", structured_output=True)
async def oc_doctor() -> dict[str, Any]:
    report = await asyncio.to_thread(diagnostics_doctor_report, mcp._tool_manager._tools)
    return report


@mcp.tool(name="oc_result_get", description="Read one retained tool result by its evidence_id. Retention is controlled by OPENCYBER_RESULT_RETENTION: off keeps nothing, digest (default) keeps an index entry, and full keeps the redacted payload. When only the digest exists, the response says so instead of pretending content is missing.", structured_output=True)
async def oc_result_get(engagement_id: str, evidence_id: str) -> dict[str, Any]:
    return await asyncio.to_thread(get_retained_result, engagement_id, evidence_id)


@mcp.tool(name="oc_result_list", description="List retained tool results in the engagement, newest last, with total/offset coverage and the active retention mode. Filter by exact tool name.", structured_output=True)
async def oc_result_list(engagement_id: str, tool: str | None = None, limit: int = 50, offset: int = 0) -> dict[str, Any]:
    return await asyncio.to_thread(list_retained_results, engagement_id, tool, limit, offset)


@mcp.tool(name="oc_evidence_export", description="Export explicitly selected engagement files to a sensitive tar.gz evidence bundle with per-file hashes, engagement metadata and a verified audit snapshot. Session credentials are not automatically included; retain the returned archive hash independently.", structured_output=True)
async def oc_evidence_export(engagement_id: str, paths: list[str], output_path: str | None = None) -> dict[str, Any]:
    return await _analysis_call(export_evidence, engagement_id, paths, output_path=output_path)


@mcp.tool(name="oc_evidence_verify", description="Verify an engagement evidence archive without extraction: exact member inventory, file sizes and hashes, and audit snapshot integrity. Supply an independently retained expected_sha256 for an external comparison point.", structured_output=True)
async def oc_evidence_verify(engagement_id: str, path: str, expected_sha256: str | None = None) -> dict[str, Any]:
    return await _analysis_call(verify_evidence, engagement_id, path, expected_sha256=expected_sha256)


@mcp.tool(name="oc_openapi_audit", description="Audit an OpenAPI JSON document from a URL or engagement-relative path for operation inventory, declared authentication coverage, path-parameter consistency, sensitive fields, and transport review items. Results are evidence-backed leads and are persisted in the engagement.", structured_output=True)
async def oc_openapi_audit(engagement_id: str, source: str, timeout: float | None = None) -> dict[str, Any]:
    return await asyncio.to_thread(audit_openapi, engagement_id, source, timeout)


@mcp.tool(name="oc_graphql_audit", description="Assess a GraphQL endpoint using introspection evidence and enumerate query/mutation fields. Results are persisted and do not claim vulnerabilities without response evidence.", structured_output=True)
async def oc_graphql_audit(engagement_id: str, url: str, headers: dict[str, str] | None = None, timeout: float | None = None) -> dict[str, Any]:
    return await asyncio.to_thread(audit_graphql, engagement_id, url, headers, timeout)


@mcp.tool(name="oc_jwt_audit", description="Audit JWT structure and claims for evidence-backed review items such as alg=none, missing expiry, issuer mismatch, and audience mismatch. Signature verification is never implied.", structured_output=True)
async def oc_jwt_audit(engagement_id: str, token: str, expected_issuer: str = "", expected_audience: str = "") -> dict[str, Any]:
    return await asyncio.to_thread(audit_jwt, engagement_id, token, expected_issuer, expected_audience)


@mcp.tool(name="oc_api_fuzz", description="Run a caller-bounded, single-parameter API fuzz matrix against an authorized target and preserve complete response evidence. The caller selects payloads and max_requests.", structured_output=True)
async def oc_api_fuzz(engagement_id: str, base_url: str, path: str, method: str, location: str, parameter: str, payloads: list[str], max_requests: int, headers: dict[str, str] | None = None, base_body: str = "", follow_redirects: bool = True, timeout: float | None = None) -> dict[str, Any]:
    return await _analysis_call(
        fuzz_api_parameter, engagement_id, base_url, path, method, location,
        parameter, payloads, max_requests, headers, base_body, follow_redirects, timeout,
    )


@mcp.tool(name="oc_http_session_create", description="Create a persistent engagement-scoped HTTP workbench session with declared target scope, default headers, cookies, TLS, and redirect behavior.", structured_output=True)
async def oc_http_session_create(engagement_id: str, name: str, base_url: str, scope_hosts: list[str] | None = None, include_subdomains: bool = False, default_headers: dict[str, str] | None = None, verify_tls: bool = True, follow_redirects: bool = True, timeout_seconds: float | None = None) -> dict[str, Any]:
    return await asyncio.to_thread(create_http_session, engagement_id, name, base_url, scope_hosts, include_subdomains, default_headers, verify_tls, follow_redirects, timeout_seconds)


@mcp.tool(name="oc_http_session_list", description="List persistent HTTP workbench sessions in one engagement.", structured_output=True)
async def oc_http_session_list(engagement_id: str) -> dict[str, Any]:
    return await asyncio.to_thread(list_http_sessions, engagement_id)


@mcp.tool(name="oc_http_session_get", description="Inspect one engagement-scoped HTTP workbench session and its history count.", structured_output=True)
async def oc_http_session_get(engagement_id: str, session_id: str) -> dict[str, Any]:
    return await asyncio.to_thread(get_http_session, engagement_id, session_id)


@mcp.tool(name="oc_http_session_update", description="Update an HTTP workbench session's scope, headers, cookies, match/replace rules, TLS verification, or redirect behavior.", structured_output=True)
async def oc_http_session_update(engagement_id: str, session_id: str, scope_hosts: list[str] | None = None, include_subdomains: bool | None = None, default_headers: dict[str, str] | None = None, cookies: dict[str, str] | None = None, rules: list[dict[str, str]] | None = None, verify_tls: bool | None = None, follow_redirects: bool | None = None, timeout_seconds: float | None = None) -> dict[str, Any]:
    return await asyncio.to_thread(update_http_session, engagement_id, session_id, scope_hosts, include_subdomains, default_headers, cookies, rules, verify_tls, follow_redirects, timeout_seconds)


@mcp.tool(name="oc_http_repeater", description="Replay one crafted HTTP request through an engagement workbench session, enforcing scope and applying persisted headers, cookies, and match/replace rules. Complete evidence is retained.", structured_output=True)
async def oc_http_repeater(engagement_id: str, session_id: str, method: str, url: str, headers: dict[str, str] | None = None, body: str | None = None, timeout: float | None = None) -> dict[str, Any]:
    return await asyncio.to_thread(repeat_http_request, engagement_id, session_id, method, url, headers, body, timeout)


@mcp.tool(name="oc_http_intruder", description="Run caller-bounded sniper-style payload iteration through an HTTP workbench session against one query, header, body, or path location.", structured_output=True)
async def oc_http_intruder(engagement_id: str, session_id: str, method: str, url: str, location: str, parameter: str, payloads: list[str], max_requests: int, headers: dict[str, str] | None = None, body: str = "", timeout: float | None = None) -> dict[str, Any]:
    return await _analysis_call(
        intrude_http_parameter, engagement_id, session_id, method, url, location,
        parameter, payloads, max_requests, headers, body, timeout,
    )


@mcp.tool(name="oc_http_history", description="Read the complete persisted request/response history for one engagement HTTP workbench session.", structured_output=True)
async def oc_http_history(engagement_id: str, session_id: str) -> dict[str, Any]:
    return await asyncio.to_thread(read_http_history, engagement_id, session_id)


@mcp.tool(name="oc_browser_create", description="Launch an isolated headless Chromium context inside the OpenCyber container and return a server-generated browser session ID bound to the engagement.", structured_output=True)
async def oc_browser_create(engagement_id: str, name: str, viewport_width: int = 1440, viewport_height: int = 900, user_agent: str = "", extra_headers: dict[str, str] | None = None, ignore_https_errors: bool = True) -> dict[str, Any]:
    return await BROWSER_MANAGER.create(engagement_id, name, viewport_width, viewport_height, user_agent, extra_headers, ignore_https_errors)


@mcp.tool(name="oc_browser_list", description="List live browser sessions owned by this MCP process for one engagement.", structured_output=True)
async def oc_browser_list(engagement_id: str) -> dict[str, Any]:
    return await BROWSER_MANAGER.list(engagement_id)


@mcp.tool(name="oc_browser_get", description="Inspect one live OpenCyber browser session, including URL, title, network event count, and interception rules.", structured_output=True)
async def oc_browser_get(engagement_id: str, session_id: str) -> dict[str, Any]:
    return await BROWSER_MANAGER.get(engagement_id, session_id)


@mcp.tool(name="oc_browser_close", description="Close a live browser context and release its Chromium resources. Unlike engagement close, this has real process lifecycle semantics.", structured_output=True)
async def oc_browser_close(engagement_id: str, session_id: str) -> dict[str, Any]:
    return await BROWSER_MANAGER.close(engagement_id, session_id)


@mcp.tool(name="oc_browser_navigate", description="Navigate a live OpenCyber browser session to a URL and return the resulting status, headers, URL, and title.", structured_output=True)
async def oc_browser_navigate(engagement_id: str, session_id: str, url: str, wait_until: str = "load", timeout_ms: int = 30000) -> dict[str, Any]:
    return await BROWSER_MANAGER.navigate(engagement_id, session_id, url, wait_until, timeout_ms)


@mcp.tool(name="oc_browser_snapshot", description="Return the current page text and accessibility-oriented ARIA snapshot, with optional complete HTML.", structured_output=True)
async def oc_browser_snapshot(engagement_id: str, session_id: str, include_html: bool = False) -> dict[str, Any]:
    return await BROWSER_MANAGER.snapshot(engagement_id, session_id, include_html)


@mcp.tool(name="oc_browser_action", description="Perform a selector-based browser action: click, fill, type, clear, press, check, uncheck, select, or hover.", structured_output=True)
async def oc_browser_action(engagement_id: str, session_id: str, action: str, selector: str, value: str = "", timeout_ms: int = 30000) -> dict[str, Any]:
    return await BROWSER_MANAGER.action(engagement_id, session_id, action, selector, value, timeout_ms)


@mcp.tool(name="oc_browser_screenshot", description="Capture a browser screenshot into the selected engagement and return its relative artifact path.", structured_output=True)
async def oc_browser_screenshot(engagement_id: str, session_id: str, path: str = "", full_page: bool = True) -> dict[str, Any]:
    return await BROWSER_MANAGER.screenshot(engagement_id, session_id, path, full_page)


@mcp.tool(name="oc_browser_evaluate", description="Evaluate JavaScript in the active page and return its serializable result.", structured_output=True)
async def oc_browser_evaluate(engagement_id: str, session_id: str, expression: str, argument: Any = None) -> dict[str, Any]:
    return await BROWSER_MANAGER.evaluate(engagement_id, session_id, expression, argument)


@mcp.tool(name="oc_browser_state", description="Read cookies, localStorage, and sessionStorage from a live browser session.", structured_output=True)
async def oc_browser_state(engagement_id: str, session_id: str) -> dict[str, Any]:
    return await BROWSER_MANAGER.state(engagement_id, session_id)


@mcp.tool(name="oc_browser_set_state", description="Set cookies, localStorage, and sessionStorage in a live browser session.", structured_output=True)
async def oc_browser_set_state(engagement_id: str, session_id: str, cookies: list[dict[str, Any]] | None = None, local_storage: dict[str, str] | None = None, session_storage: dict[str, str] | None = None) -> dict[str, Any]:
    return await BROWSER_MANAGER.set_state(engagement_id, session_id, cookies, local_storage, session_storage)


@mcp.tool(name="oc_browser_network_rules", description="Configure browser request interception with blocked URL patterns, URL replacements, and extra request headers.", structured_output=True)
async def oc_browser_network_rules(engagement_id: str, session_id: str, blocked_patterns: list[str] | None = None, url_replacements: list[dict[str, str]] | None = None, extra_headers: dict[str, str] | None = None) -> dict[str, Any]:
    return await BROWSER_MANAGER.network_rules(engagement_id, session_id, blocked_patterns, url_replacements, extra_headers)


@mcp.tool(name="oc_browser_network_log", description="Return complete request/response metadata captured by a live browser session, optionally clearing the in-memory log afterward.", structured_output=True)
async def oc_browser_network_log(engagement_id: str, session_id: str, clear: bool = False, offset: int = 0, limit: int = 500) -> dict[str, Any]:
    return await BROWSER_MANAGER.network_log(engagement_id, session_id, clear, offset, limit)


@mcp.tool(name="oc_payload_encode", description="Encode text as base64, base64url, hex, URL, or form data.", structured_output=True)
def oc_payload_encode(data: str, encoding: str) -> dict[str, str]:
    return encode_payload(data, encoding)


@mcp.tool(name="oc_extract_indicators", description="Extract URLs, IPv4 addresses, CVEs, and common hashes from supplied text.", structured_output=True)
def oc_extract_indicators(text: str) -> dict[str, list[str]]:
    return extract_indicators(text)


@mcp.tool(name="oc_technology_hints", description="Detect deterministic technology hints in supplied HTTP headers and body text.", structured_output=True)
def oc_technology_hints(headers: dict[str, str] | None = None, body: str = "") -> dict[str, Any]:
    return technology_hints(headers, body)


@mcp.tool(name="oc_engagement_plan", description="Create a deterministic OpenCyber engagement plan using catalog tool names.", structured_output=True)
def oc_engagement_plan(kind: str, target: str, objective: str = "") -> dict[str, Any]:
    return engagement_plan(kind, target, objective)


@mcp.tool(name="oc_recommend_tools", description="Recommend OpenCyber tools using deterministic objective matching.", structured_output=True)
def oc_recommend_tools(objective: str, target_type: str = "web") -> dict[str, Any]:
    return recommend_tools(objective, target_type)


@mcp.tool(name="oc_attack_chain", description="Order caller-supplied findings into a reviewable severity-based attack chain.", structured_output=True)
def oc_attack_chain(findings: list[dict[str, Any]]) -> dict[str, Any]:
    return attack_chain(findings)


@mcp.tool(name="oc_scan_summary", description="Summarize complete OpenCyber tool results without discarding their output.", structured_output=True)
def oc_scan_summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    return scan_summary(results)


# ---------------------------------------------------------------------------
# Physical-layer / hardware tools
# ---------------------------------------------------------------------------


@mcp.tool(name="oc_hardware_inventory", description="Enumerate hardware visible inside the container: USB devices with SDR/NFC/JTAG/serial classification, serial ports, wireless and CAN interfaces, Bluetooth adapters, video/input devices, GPIO/I2C/SPI nodes, and container capabilities. Call this before hardware tools.", structured_output=True)
async def oc_hardware_inventory() -> dict[str, Any]:
    return await asyncio.to_thread(hardware_inventory)


@mcp.tool(name="oc_hardware_readiness", description="Report per-domain hardware readiness (SDR, Wi-Fi, Bluetooth, NFC, JTAG, serial, CAN, logic, GPS, IR) with the host docker flags needed to expose missing devices. Separate from tool installation readiness.", structured_output=True)
async def oc_hardware_readiness() -> dict[str, Any]:
    return await asyncio.to_thread(hardware_readiness)


@mcp.tool(name="oc_hardware_plan", description="Return a deterministic physical-layer playbook (usb, sdr, wifi, bluetooth, nfc, jtag, serial, automotive, logic, gps, ir, firmware) using catalog tool names and prerequisites.", structured_output=True)
def oc_hardware_plan(domain: str, target: str = "", objective: str = "") -> dict[str, Any]:
    return hardware_plan(domain, target, objective)


@mcp.tool(name="oc_serial_open", description="Open a raw, persistent serial/UART session on a device passed into the container. Captures a transcript under hardware/serial/<session_id>.jsonl. Device must be a character device under /dev/ttyUSB*, /dev/ttyACM*, /dev/ttyS*, /dev/serial/, /dev/rfcomm*, or /dev/lirc*.", structured_output=True)
async def oc_serial_open(engagement_id: str, device: str, baudrate: int = 115200, bytesize: int = 8, parity: str = "none", stopbits: int = 1) -> dict[str, Any]:
    return await asyncio.to_thread(serial_open, engagement_id, device, baudrate, bytesize, parity, stopbits)


@mcp.tool(name="oc_serial_list", description="List live serial sessions owned by this MCP process for one engagement.", structured_output=True)
def oc_serial_list(engagement_id: str) -> dict[str, Any]:
    return serial_list(engagement_id)


@mcp.tool(name="oc_serial_read", description="Read pending bytes from a live serial session with a bounded timeout; returns text, hexadecimal, and buffer depth without losing bytes.", structured_output=True)
async def oc_serial_read(engagement_id: str, session_id: str, max_bytes: int = 4096, timeout: float = 1.0) -> dict[str, Any]:
    return await asyncio.to_thread(serial_read, engagement_id, session_id, max_bytes, timeout)


@mcp.tool(name="oc_serial_write", description="Write text or hexadecimal bytes to a live serial session. Writes are limited to 65536 bytes per call and persisted in the transcript.", structured_output=True)
async def oc_serial_write(engagement_id: str, session_id: str, data: str = "", hex_data: str = "") -> dict[str, Any]:
    return await asyncio.to_thread(serial_write, engagement_id, session_id, data, hex_data)


@mcp.tool(name="oc_serial_close", description="Close a live serial session, restore terminal attributes, and return the transcript path.", structured_output=True)
async def oc_serial_close(engagement_id: str, session_id: str) -> dict[str, Any]:
    return await asyncio.to_thread(serial_close, engagement_id, session_id)


@mcp.tool(name="oc_firmware_analyze", description="Triage a firmware image inside the engagement: cryptographic hashes, magic/architecture identity, entropy map, interesting strings, binwalk signatures, review items, and a persisted JSON report. Never executes the image.", structured_output=True)
async def oc_firmware_analyze(engagement_id: str, path: str, run_binwalk: bool = True) -> dict[str, Any]:
    return await asyncio.to_thread(analyze_firmware, engagement_id, path, run_binwalk)


# ---------------------------------------------------------------------------
# Evidence integrity and scope policy
# ---------------------------------------------------------------------------


@mcp.tool(name="oc_audit_log", description="Read the tamper-evident engagement audit trail (tool executions, HTTP requests, browser actions, workspace writes, hardware sessions). Events are returned in append order with hash-chain fields.", structured_output=True)
async def oc_audit_log(engagement_id: str, limit: int = 100, offset: int = 0, event: str | None = None) -> dict[str, Any]:
    return await asyncio.to_thread(read_audit, engagement_id, limit, offset, event)


@mcp.tool(name="oc_audit_verify", description="Recompute the engagement audit hash chain and report the first removed, reordered, or edited event.", structured_output=True)
async def oc_audit_verify(engagement_id: str) -> dict[str, Any]:
    return await asyncio.to_thread(verify_audit, engagement_id)


@mcp.tool(name="oc_scope_check", description="Check one value against the engagement targets, or check a proposed executable call under optional scope enforcement. Reports the match without executing anything.", structured_output=True)
def oc_scope_check(engagement_id: str, value: str = "", executable: str = "", arguments: list[str] | None = None) -> dict[str, Any]:
    if value:
        return scope_check(engagement_id, value)
    if executable:
        return enforcement_decision(engagement_id, executable, arguments or [])
    return {
        "engagement_id": engagement_id,
        "enforcement_enabled": enforcement_enabled(),
        "note": (
            "Set OPENCYBER_ENFORCE_SCOPE=1 to inspect executable calls before they run. "
            "Set value or executable+arguments to check a specific call."
        ),
    }


@mcp.tool(name="oc_assets_status", description="Report every offline asset (nuclei templates, exploitdb, Seclists, wordlists, nmap scripts, hardware rules, CVE index), its size/count, and whether required assets are missing. deep adds content hashes; verify also compares the build-time manifest.", structured_output=True)
async def oc_assets_status(deep: bool = False, verify: bool = False) -> dict[str, Any]:
    def collect() -> dict[str, Any]:
        result = assets_status(deep)
        if verify:
            result["manifest"] = verify_manifest(result, deep=deep)
        return result

    return await asyncio.to_thread(collect)


@mcp.tool(name="oc_offline_status", description="Report airgap posture: offline mode, required asset readiness, local CVE database presence, and which features still require internet access.", structured_output=True)
async def oc_offline_status() -> dict[str, Any]:
    return await asyncio.to_thread(offline_status)


# ---------------------------------------------------------------------------
# CVE chain proof-of-concept (authorized research)
# ---------------------------------------------------------------------------


def _poc_refusal(exc: PocError) -> dict[str, Any]:
    """Return a structured refusal instead of an MCP transport error."""
    payload = exc.as_dict()
    payload["ok"] = False
    payload["error"] = exc.to_error().to_dict()
    payload["coverage"] = envelope_coverage("unknown", exhausted=False)
    payload["limitations"] = [
        "The PoC tool refused before performing target work; status and reason record why."
    ]
    return payload


@mcp.tool(name="oc_authorization_get", description="Read and verify the engagement's operator-signed PoC authorization record: targets, validity window, allowed technique classes, and custom-code allowance. Read-only; this tool never creates or edits an authorization. A missing signed record is reported as status=required, not invented.", structured_output=True)
def oc_authorization_get(engagement_id: str) -> dict[str, Any]:
    try:
        return describe_authorization(engagement_id)
    except PocError as exc:
        return _poc_refusal(exc)


@mcp.tool(name="oc_chain_plan", description="Validate a CVE capability chain deterministically. Each step supplies requires/provides capability tokens, a written basis, and an optional evidence source; the tool computes satisfaction closure, missing tokens, and cycles, attaches nuclei/trivy artifact observations, and persists the chain. It never invents CVE semantics: annotate only what the advisory or evidence supports.", structured_output=True)
def oc_chain_plan(
    engagement_id: str,
    steps: list[dict[str, Any]],
    entry_capabilities: list[str],
    artifacts: list[str] | None = None,
    chain_name: str = "",
) -> dict[str, Any]:
    try:
        return plan_chain(engagement_id, steps, entry_capabilities, artifacts, chain_name)
    except PocError as exc:
        return _poc_refusal(exc)


@mcp.tool(name="oc_chain_get", description="Read one persisted CVE capability chain by chain_id, or list chain summaries (verdict, step count, created_at) when chain_id is omitted.", structured_output=True)
def oc_chain_get(engagement_id: str, chain_id: str = "") -> dict[str, Any]:
    try:
        if chain_id:
            return load_chain(engagement_id, chain_id)
        return list_chains(engagement_id)
    except PocError as exc:
        return _poc_refusal(exc)


@mcp.tool(name="oc_poc_spec_create", description="Create one declarative PoC spec for a chain step: technique class, in-scope target, bounded request list, closed assertion language, and limits. Validates the target against the engagement and the chain step. Does not render or execute anything.", structured_output=True)
def oc_poc_spec_create(
    engagement_id: str,
    chain_id: str,
    step_order: int,
    technique: str,
    target: str,
    requests: list[dict[str, Any]] | None = None,
    assertions: list[dict[str, Any]] | None = None,
    limits: dict[str, Any] | None = None,
    source: str = "",
    notes: str = "",
    allow_insecure_tls: bool = False,
) -> dict[str, Any]:
    try:
        return create_spec(
            engagement_id,
            chain_id=chain_id,
            step_order=step_order,
            technique=technique,
            target=target,
            requests=requests,
            assertions=assertions,
            limits=limits,
            source=source,
            notes=notes,
            allow_insecure_tls=allow_insecure_tls,
        )
    except PocError as exc:
        return _poc_refusal(exc)


@mcp.tool(name="oc_poc_render", description="Render a PoC spec into a bounded stdlib-only Python verifier under the engagement, or store custom source verbatim for the separate approval tier. Returns the code path and SHA-256 bound by the run approval; does not execute anything.", structured_output=True)
def oc_poc_render(engagement_id: str, spec_id: str) -> dict[str, Any]:
    try:
        return render_poc(engagement_id, spec_id)
    except PocError as exc:
        return _poc_refusal(exc)


@mcp.tool(name="oc_poc_lint", description="Static review of a PoC spec and its code: engagement scope for every host, supported technique class, hard request/time/output caps, and forbidden destructive or weaponized patterns. Returns blocking findings, warnings, and per-host scope verdicts. Signed-authorization coverage is enforced at run time, not here. Best-effort defense in depth, not a sandbox.", structured_output=True)
def oc_poc_lint(engagement_id: str, spec_id: str) -> dict[str, Any]:
    try:
        return lint_poc(engagement_id, spec_id)
    except PocError as exc:
        return _poc_refusal(exc)


@mcp.tool(name="oc_poc_run", description="Execute one approved PoC spec. Requires a complete chain, a valid signed authorization covering the target and technique, and a signed single-use approval whose spec/code hashes still match; re-lints and preflights scope, then runs under hard limits and captures evidence. Refusals return a machine-readable reason. Never bypass the gate.", structured_output=True)
async def oc_poc_run(engagement_id: str, chain_id: str, spec_id: str, approval_id: str) -> dict[str, Any]:
    try:
        return await run_poc(engagement_id, chain_id=chain_id, spec_id=spec_id, approval_id=approval_id)
    except PocError as exc:
        return _poc_refusal(exc)


@mcp.tool(name="oc_poc_evidence", description="List PoC runs in the engagement with verdict and evidence paths, or read one run's structured result and artifacts when run_id is supplied.", structured_output=True)
def oc_poc_evidence(engagement_id: str, run_id: str = "") -> dict[str, Any]:
    try:
        if run_id:
            return get_run(engagement_id, run_id)
        return list_runs(engagement_id)
    except PocError as exc:
        return _poc_refusal(exc)


def _bind_contracts() -> None:
    """Attach the declared contract and result envelope to every registered tool.

    Registration stays declarative (one decorator per tool); this single pass is
    the only place that applies authority metadata and the envelope, so a tool
    cannot be advertised without a contract or without structured results.
    Tests assert the generated input schema is unchanged by the binding.
    """
    tools = mcp._tool_manager._tools
    validate_contracts(tools)
    if len(REGISTERED_CATALOG) == len(CATALOG):
        unregistered = sorted(set(CONTRACTS) - set(tools))
        if unregistered:
            raise RuntimeError(f"contracts without a registered tool: {', '.join(unregistered)}")
    for name, tool in tools.items():
        contract = contract_for(name)
        tool.annotations = ToolAnnotations(**contract.annotations())
        tool.meta = contract.meta()
        tool.fn = wrap_tool(contract, tool.fn)


_bind_contracts()


def _strict_catalog() -> bool:
    return os.environ.get("OPENCYBER_STRICT_CATALOG", "").strip().lower() in {"1", "true", "yes", "on"}


def self_test() -> dict[str, Any]:
    result = diagnostics_self_test(len(REGISTERED_CATALOG))
    alignment = catalog_alignment(mcp._tool_manager._tools)
    result["catalog"] = {
        "profile": alignment["profile"],
        "recorded_sha256": alignment["recorded_sha256"],
        "advertised_sha256": alignment["advertised_sha256"],
        "matches": alignment["matches"],
        "subset_matches": alignment["subset_matches"],
        "unexpected_tools": alignment["unexpected_tools"],
        "changed_tools": alignment["changed_tools"],
        "strict_mismatch": _strict_catalog() and not (alignment["matches"] or alignment["subset_matches"]),
    }
    return result


def main() -> None:
    parser = argparse.ArgumentParser(prog="opencyber-mcp")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--catalog-json", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        result = self_test()
        print(json.dumps(result, indent=2, sort_keys=True))
        if result["missing_required_tools"] or result["catalog"]["strict_mismatch"]:
            raise SystemExit(1)
        return
    if args.catalog_json:
        print(json.dumps([spec.as_dict() for spec in CATALOG], indent=2, sort_keys=True))
        return
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
