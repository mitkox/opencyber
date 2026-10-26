"""Shared diagnostics for the MCP server and the doctor CLI.

Everything here is import-light on purpose: the doctor probe runs inside the
container's healthcheck and must not pay for importing MCPServer or the tool
modules just to answer "is this image healthy".
"""

from __future__ import annotations

from itertools import chain
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
from typing import Any

from . import __version__
from .assets import assets_status, offline_status, verify_manifest
from .catalog import CATALOG, HARDWARE_CATEGORIES
from .contracts import native_groups
from .engagements import WORKSPACE
from .hardware import hardware_readiness


# Fixed (non-catalog) MCP tools. The contract registry owns the inventory and
# the grouping, so adding a tool cannot leave this table stale. Tests compare
# these names against the live tool manager.
FIXED_TOOL_CATEGORIES: dict[str, tuple[str, ...]] = native_groups()

FIXED_TOOL_NAMES = frozenset(chain.from_iterable(FIXED_TOOL_CATEGORIES.values()))
FIXED_MCP_TOOL_COUNT = len(FIXED_TOOL_NAMES)

NATIVE_AND_WORKSPACE_TOOL_COUNT = len(FIXED_TOOL_CATEGORIES["native_and_workspace"])
ENGAGEMENT_MANAGEMENT_TOOL_COUNT = len(FIXED_TOOL_CATEGORIES["engagement_management"])
GENERAL_EXECUTION_TOOL_COUNT = len(FIXED_TOOL_CATEGORIES["general_execution"])
API_AUDIT_TOOL_COUNT = len(FIXED_TOOL_CATEGORIES["api_audit"])
HTTP_WORKBENCH_TOOL_COUNT = len(FIXED_TOOL_CATEGORIES["http_workbench"])
BROWSER_TOOL_COUNT = len(FIXED_TOOL_CATEGORIES["browser"])
HARDWARE_TOOL_COUNT = len(FIXED_TOOL_CATEGORIES["hardware"])
AUDIT_TOOL_COUNT = len(FIXED_TOOL_CATEGORIES["audit"])
POLICY_TOOL_COUNT = len(FIXED_TOOL_CATEGORIES["policy"])
ASSET_TOOL_COUNT = len(FIXED_TOOL_CATEGORIES["assets"])
POC_CHAIN_TOOL_COUNT = len(FIXED_TOOL_CATEGORIES["poc_chain"])

NUCLEI_TEMPLATES_DIRNAME = Path(".local") / "nuclei-templates"
ROCKYOU = Path("/usr/share/wordlists/rockyou.txt")
BASELINE_WORDLIST = Path("/usr/share/wordlists/opencyber-keyboard-patterns.txt")
SECLISTS = Path("/usr/share/seclists")


def _tool_version(executable: str, *args: str) -> str | None:
    path = shutil.which(executable)
    if path is None:
        return None
    try:
        result = subprocess.run(
            [path, *args],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    output = (result.stdout or result.stderr).strip().splitlines()
    return output[0] if output else path


def templates_summary() -> dict[str, Any]:
    templates_dir = Path.home() / NUCLEI_TEMPLATES_DIRNAME
    count = 0
    if templates_dir.is_dir():
        count = sum(1 for path in templates_dir.rglob("*.yaml") if path.is_file())
    version_file = templates_dir / ".opencyber-version"
    version = version_file.read_text(encoding="utf-8").strip() if version_file.is_file() else None
    return {"path": str(templates_dir), "version": version, "count": count}


def self_test(registered_external: int | None = None) -> dict[str, Any]:
    """Report whether every catalog executable and runtime dependency is present."""
    availability = {spec.name: spec.availability() for spec in CATALOG}
    missing = [spec.name for spec in CATALOG if not availability[spec.name]["available"]]
    missing_required = [spec.name for spec in CATALOG if spec.required and spec.name in missing]
    missing_optional = [spec.name for spec in CATALOG if not spec.required and spec.name in missing]
    registered = len(CATALOG) if registered_external is None else registered_external
    hardware_tool_count = sum(
        1 for spec in CATALOG if spec.category in HARDWARE_CATEGORIES
    )
    return {
        "status": "degraded" if missing_required else "healthy",
        "version": __version__,
        "external_tools": len(CATALOG),
        "hardware_external_tools": hardware_tool_count,
        "native_and_workspace_tools": NATIVE_AND_WORKSPACE_TOOL_COUNT,
        "engagement_management_tools": ENGAGEMENT_MANAGEMENT_TOOL_COUNT,
        "general_execution_tools": GENERAL_EXECUTION_TOOL_COUNT,
        "api_audit_tools": API_AUDIT_TOOL_COUNT,
        "http_workbench_tools": HTTP_WORKBENCH_TOOL_COUNT,
        "browser_tools": BROWSER_TOOL_COUNT,
        "hardware_tools": HARDWARE_TOOL_COUNT,
        "audit_tools": AUDIT_TOOL_COUNT,
        "policy_tools": POLICY_TOOL_COUNT,
        "asset_tools": ASSET_TOOL_COUNT,
        "blue_team_tools": len(FIXED_TOOL_CATEGORIES["blue_team"]),
        "poc_chain_tools": POC_CHAIN_TOOL_COUNT,
        "total_mcp_tools": registered + FIXED_MCP_TOOL_COUNT,
        "registered_external_tools": registered,
        "mcp_mode": os.environ.get("OPENCYBER_MCP_MODE", "full"),
        "available_external_tools": len(CATALOG) - len(missing),
        "missing_external_tools": missing,
        "missing_required_tools": missing_required,
        "missing_optional_tools": missing_optional,
        "optional_integrations": [
            {"name": spec.name, **availability[spec.name]}
            for spec in CATALOG if not spec.required
        ],
        "workspace": str(WORKSPACE),
        "engagements_root": str(WORKSPACE / "engagements"),
        "browser_runtime": {
            "playwright": importlib.util.find_spec("playwright") is not None,
            "chromium": shutil.which("chromium") or shutil.which("chromium-browser"),
        },
        # angr and volatility3 live in a separate analysis venv in the image.
        # A missing .pth exposes them to the CLI but not to native tools.
        "analysis_runtime": {
            "angr": importlib.util.find_spec("angr") is not None,
            "volatility3": importlib.util.find_spec("volatility3") is not None,
        },
    }


def doctor_report(advertised_tools: Any = None) -> dict[str, Any]:
    """Full harness readiness report: catalog, offline assets, hardware, tooling.

    ``advertised_tools`` is the live MCP tool mapping when the caller has a
    server in this process. The CLI doctor does not import MCPServer, so it
    reports the recorded catalog digest and defers live alignment to
    ``opencyber-mcp --self-test``; that difference is stated by the check
    itself rather than hidden.
    """
    from . import limits
    from .catalog_identity import alignment as catalog_alignment, load_manifest

    base = self_test()
    templates = templates_summary()
    assets = assets_status()
    manifest = verify_manifest(assets)
    hardware = hardware_readiness()
    agent_tools = {
        "rg": _tool_version("rg", "--version"),
        "yq": _tool_version("yq", "--version"),
        "jq": _tool_version("jq", "--version"),
    }
    wordlists = {
        "baseline": BASELINE_WORDLIST.is_file() and BASELINE_WORDLIST.stat().st_size > 0,
        "rockyou": ROCKYOU.is_file() and ROCKYOU.stat().st_size > 0,
        "seclists": SECLISTS.is_dir(),
    }
    checks: list[dict[str, Any]] = []

    def check(check_id: str, status: str, message: str, *, remediation: str = "", details: Any = None) -> None:
        entry: dict[str, Any] = {"id": check_id, "status": status, "message": message}
        if remediation:
            entry["remediation"] = remediation
        if details is not None:
            entry["details"] = details
        checks.append(entry)

    check("version", "pass", f"OpenCyber Harness {__version__}", details={"version": __version__})
    check("mcp-mode", "pass", f"MCP mode is {base['mcp_mode']}", details={"mode": base["mcp_mode"]})

    if advertised_tools is None:
        alignment = None
        recorded = load_manifest()
        recorded_sha = None if recorded is None else recorded.get("catalog_sha256")
        if recorded_sha is None:
            check(
                "catalog-identity",
                "fail",
                "the recorded MCP catalog manifest is missing",
                remediation="Reinstall the package; the manifest ships with it.",
            )
        else:
            check(
                "catalog-identity",
                "warn",
                "live catalog alignment is not inspected by this CLI process",
                remediation="Run `opencyber-mcp --self-test` to compare the live catalog with the recorded digest.",
                details={"recorded_sha256": recorded_sha},
            )
    else:
        alignment = catalog_alignment(advertised_tools)
        if alignment["matches"] or alignment["subset_matches"]:
            check(
                "catalog-identity",
                "pass",
                f"advertised catalog matches the recorded contract ({alignment['profile']} profile)",
                details=alignment,
            )
        else:
            check(
                "catalog-identity",
                "fail",
                "advertised catalog does not match the recorded contract",
                remediation="Reinstall the image; a changed or unexpected tool means the deployment is not this release.",
                details=alignment,
            )

    if base["missing_required_tools"]:
        check(
            "required-executables",
            "fail",
            f"{len(base['missing_required_tools'])} required catalog executables missing",
            remediation="Use the published image, or install the missing integrations in an operator-managed image.",
            details={"missing": base["missing_required_tools"]},
        )
    else:
        check("required-executables", "pass", "every required catalog executable is present")
    check(
        "optional-integrations",
        "pass",
        f"{len(base['missing_optional_tools'])} optional integrations unavailable",
        details={"missing": base["missing_optional_tools"]},
    )
    if templates["count"] == 0:
        check("nuclei-templates", "fail", "no nuclei templates installed", remediation="Use the published image or install templates.")
    else:
        check("nuclei-templates", "pass", f"{templates['count']} nuclei templates ({templates['version'] or 'unknown'})")
    missing_wordlists = [name for name in ("baseline", "seclists") if not wordlists[name]]
    if missing_wordlists:
        check("wordlists", "fail", "wordlists missing: " + ", ".join(missing_wordlists), remediation="Use the published image or install the wordlists.")
    else:
        check("wordlists", "pass", "wordlists present")
    if assets["missing_required"]:
        check(
            "offline-assets",
            "fail",
            "required offline assets missing: " + ", ".join(assets["missing_required"]),
            remediation="Use the published image or run `opencyber-assets --write` with local mirrors.",
        )
    else:
        check("offline-assets", "pass", f"offline assets ready ({assets['summary']['ok']}/{assets['summary']['total']})")
    if manifest.get("available") and not manifest.get("valid"):
        check(
            "asset-manifest",
            "fail",
            "offline asset manifest does not match the image",
            remediation="Reinstall the image; the manifest is build-time evidence.",
        )
    elif manifest.get("valid"):
        check("asset-manifest", "pass", "offline asset manifest matches the image")
    else:
        check("asset-manifest", "warn", "no offline asset manifest to verify")
    missing_agent_tools = [name for name, version in agent_tools.items() if version is None]
    if missing_agent_tools:
        check(
            "agent-tools",
            "fail",
            "agent shell tools missing: " + ", ".join(missing_agent_tools),
            remediation="Use the published image; the server instructions recommend rg, jq, and yq.",
        )
    else:
        check("agent-tools", "pass", "agent shell tools present")
    unavailable_runtime = [name for name, present in base["analysis_runtime"].items() if not present]
    if unavailable_runtime:
        check(
            "analysis-runtime",
            "fail",
            "analysis runtime unavailable: " + ", ".join(unavailable_runtime),
            remediation="Use the published image; angr and volatility3 live in its analysis virtualenv.",
        )
    else:
        check("analysis-runtime", "pass", "analysis runtime importable")
    browser = base["browser_runtime"]
    if browser["playwright"] and browser["chromium"]:
        check("browser", "pass", f"Chromium at {browser['chromium']}")
    else:
        check(
            "browser",
            "warn",
            "browser tools are unavailable in this environment",
            remediation="Use the published image; browser tools need Playwright and Chromium.",
            details=browser,
        )
    invalid_limits: list[str] = []
    for variable, limit in limits.settings().items():
        try:
            limit.document_effective()
        except Exception as error:  # noqa: BLE001 - report every invalid setting, not the first
            invalid_limits.append(f"{variable}: {error}")
    if invalid_limits:
        check(
            "limits",
            "fail",
            "invalid limit environment values: " + "; ".join(invalid_limits),
            remediation="Correct or unset the named variables; an invalid value fails closed.",
        )
    else:
        check("limits", "pass", "limit environment values are valid")
    check(
        "hardware",
        "pass",
        f"{len(hardware['ready_domains'])} ready hardware domains, {len(hardware['tooling_only_domains'])} tooling-only",
        details={
            "ready_domains": hardware["ready_domains"],
            "tooling_only_domains": hardware["tooling_only_domains"],
            "unavailable_domains": hardware["unavailable_domains"],
        },
    )

    failures = [entry for entry in checks if entry["status"] == "fail"]
    warnings = [entry for entry in checks if entry["status"] == "warn"]
    return {
        "schema_version": 1,
        "status": "degraded" if failures else "ok",
        "version": __version__,
        "checks": checks,
        "problems": [entry["message"] for entry in failures],
        "warnings": [entry["message"] for entry in warnings],
        "mcp": base,
        "nuclei_templates": templates,
        "offline_assets": assets,
        "asset_manifest": manifest,
        "hardware": {
            "summary": hardware["summary"],
            "ready_domains": hardware["ready_domains"],
            "tooling_only_domains": hardware["tooling_only_domains"],
            "unavailable_domains": hardware["unavailable_domains"],
            "devices": hardware["inventory"]["summary"],
            "access": hardware["inventory"]["access"],
            "known_devices": hardware["inventory"]["known_devices"],
            "host_flags": hardware["host_flags"],
        },
        "offline_mode": offline_status(assets)["mode"],
        "wordlists": wordlists,
        "agent_tools": agent_tools,
        "analysis_runtime": base["analysis_runtime"],
    }


def format_report(report: dict[str, Any]) -> str:
    mcp = report["mcp"]
    templates = report["nuclei_templates"]
    assets = report["offline_assets"]
    hardware = report["hardware"]
    wordlists = report["wordlists"]
    agent_tools = report["agent_tools"]
    manifest = report["asset_manifest"]
    lines = [
        "opencyber-doctor",
        f"  version                {report['version']}",
        f"  mcp tools              {mcp['total_mcp_tools']} "
        f"({mcp['available_external_tools']}/{mcp['external_tools']} executable-backed)",
        f"  hardware tools         {mcp['hardware_external_tools']} executable-backed, "
        f"{mcp['hardware_tools']} native",
        f"  missing executables    {len(mcp['missing_external_tools'])}",
        f"  optional unavailable   {len(mcp['missing_optional_tools'])}",
        f"  nuclei templates       {templates['count']} ({templates['version'] or 'unknown'})",
        f"  baseline dictionary    {'ok' if wordlists['baseline'] else 'MISSING'}",
        f"  rockyou (optional)     {'present' if wordlists['rockyou'] else 'not supplied'}",
        f"  seclists               {'ok' if wordlists['seclists'] else 'MISSING'}",
        f"  offline assets         {'ok' if assets['ready'] else 'MISSING'}"
        f" ({assets['summary']['ok']}/{assets['summary']['total']})",
        f"  asset manifest         "
        f"{'ok' if manifest.get('valid') else ('MISSING' if manifest.get('available') is False else 'MISMATCH')}",
        f"  mode                   {report['offline_mode']}",
        f"  browser                {mcp['browser_runtime']['chromium'] or 'none'}"
        f" (playwright: {mcp['browser_runtime']['playwright']})",
        f"  analysis               angr: {mcp['analysis_runtime']['angr']}"
        f", volatility3: {mcp['analysis_runtime']['volatility3']}",
        "hardware",
        f"  ready domains          {', '.join(hardware['ready_domains']) or 'none'}",
        f"  tooling only           {', '.join(hardware['tooling_only_domains']) or 'none'}",
        f"  devices                {hardware['devices'] or 'none visible'}"
        f" (usb accessible: {hardware.get('access', {}).get('usb_accessible', 0)})",
        "agent shell",
        f"  rg                     {agent_tools['rg'] or 'MISSING'}",
        f"  yq                     {agent_tools['yq'] or 'MISSING'}",
        f"  jq                     {agent_tools['jq'] or 'MISSING'}",
        "checks",
    ]
    for entry in report.get("checks", []):
        lines.append(f"  {entry['status']:<6} {entry['id']:<20} {entry['message']}")
    lines.extend(
        [
            f"status                 {report['status']}",
        ]
    )
    return "\n".join(lines)
