"""Content identity for the advertised MCP contract.

The catalog digest answers one question: *is this running server serving the
contract this release recorded?* It closes the gap between what a release
shipped and what a container, client registration, or cached process is actually
advertising.

The projection is a deterministic, sorted view of everything a client receives
per tool: contract metadata, description, input schema, output schema, and MCP
annotations. ``data/catalog.json`` is recorded from a real registration and
committed; CI fails when it is stale, so a contract change is always a visible
diff and a deliberate decision.

The digest covers the contract, not the release: ``server_version`` is recorded
as metadata and excluded from the hash, so a version-only bump does not look
like a contract change.

This module imports no MCP SDK types; it reads the attributes a registered tool
exposes and accepts any mapping of name to tool-like object. The server passes
its live tool manager in.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any, Mapping

from .contracts import CONTRACT_SCHEMA_VERSION, CONTRACTS, ToolContract


CATALOG_SCHEMA_VERSION = 1
MANIFEST_PATH = Path(__file__).resolve().parent / "data" / "catalog.json"


def canonical_json(value: Any) -> str:
    """Deterministic JSON for digests. Values are JSON scalars only."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _contract_projection(contract: ToolContract) -> dict[str, Any]:
    return contract.as_dict()


def _annotations(tool: Any) -> dict[str, Any]:
    annotations = getattr(tool, "annotations", None)
    if annotations is None:
        return {}
    if hasattr(annotations, "model_dump"):
        return annotations.model_dump(by_alias=True, exclude_none=True)
    return dict(annotations)


def project_tool(contract: ToolContract, tool: Any) -> dict[str, Any]:
    """Project one registered tool into its digested form."""
    entry: dict[str, Any] = {
        **_contract_projection(contract),
        "description": getattr(tool, "description", "") or "",
        "input_schema": getattr(tool, "parameters", {}),
        "output_schema": getattr(tool, "output_schema", None),
        "annotations": _annotations(tool),
        "meta": getattr(tool, "meta", None) or {},
    }
    entry["digest"] = _sha256(canonical_json(entry).encode("utf-8"))
    return entry


def project_tools(tools: Mapping[str, Any]) -> list[dict[str, Any]]:
    """Project every advertised tool, sorted by name."""
    entries = [project_tool(CONTRACTS[name], tool) for name, tool in tools.items()]
    return sorted(entries, key=lambda entry: entry["name"])


def catalog_sha256(entries: list[dict[str, Any]]) -> str:
    """Digest the contract set: every per-tool entry plus the schema version."""
    material = {"contract_schema_version": CONTRACT_SCHEMA_VERSION, "tools": entries}
    return _sha256(canonical_json(material).encode("utf-8"))


def count_summary(entries: list[dict[str, Any]]) -> dict[str, Any]:
    by_group: dict[str, int] = {}
    by_shape: dict[str, int] = {}
    by_kind: dict[str, int] = {}
    for entry in entries:
        by_group[entry["group"]] = by_group.get(entry["group"], 0) + 1
        by_shape[entry["shape"]] = by_shape.get(entry["shape"], 0) + 1
        by_kind[entry["kind"]] = by_kind.get(entry["kind"], 0) + 1
    return {
        "total": len(entries),
        "by_kind": dict(sorted(by_kind.items())),
        "by_group": dict(sorted(by_group.items())),
        "by_shape": dict(sorted(by_shape.items())),
    }


def render_manifest(entries: list[dict[str, Any]], *, server_version: str) -> str:
    """Render the tracked manifest with one tool per line.

    A per-tool line keeps a 250-tool contract reviewable: changing one tool
    changes one line in review, and the digest banner changes with it.
    """
    header = {
        "schema_version": CATALOG_SCHEMA_VERSION,
        "contract_schema_version": CONTRACT_SCHEMA_VERSION,
        "generated_by": "scripts/record-catalog.py",
        "server_version": server_version,
        "catalog_sha256": catalog_sha256(entries),
        "counts": count_summary(entries),
    }
    lines = ["{"]
    for key, value in header.items():
        lines.append(f'  {json.dumps(key)}: {json.dumps(value, sort_keys=True, ensure_ascii=False)},')
    lines.append('  "tools": [')
    for index, entry in enumerate(entries):
        comma = "," if index < len(entries) - 1 else ""
        lines.append(f"    {json.dumps(entry, sort_keys=True, separators=(',', ':'), ensure_ascii=False)}{comma}")
    lines.append("  ]")
    lines.append("}")
    return "\n".join(lines) + "\n"


def load_manifest(path: Path | None = None) -> dict[str, Any] | None:
    """Load the recorded manifest, or ``None`` when it has not been recorded."""
    target = path or MANIFEST_PATH
    if not target.is_file():
        return None
    return json.loads(target.read_text(encoding="utf-8"))


_UNSET: Any = object()


def alignment(tools: Mapping[str, Any], manifest: Any = _UNSET) -> dict[str, Any]:
    """Compare the advertised catalog with the recorded contract.

    ``profile`` describes what this process advertises: ``full`` when every
    recorded tool is present, ``compact``/``subset`` when the deployment
    narrows the advertised set. ``matches`` is only true for an unmodified full
    advertisement; ``subset_matches`` is true when every advertised tool
    matches its recorded digest, which is the meaningful check for a narrowed
    mode.
    """
    recorded = load_manifest() if manifest is _UNSET else manifest
    entries = project_tools(tools)
    counts = count_summary(entries)
    if recorded is None:
        return {
            "recorded": False,
            "profile": "unrecorded",
            "matches": False,
            "subset_matches": False,
            "recorded_sha256": None,
            "advertised_sha256": catalog_sha256(entries),
            "recorded_tool_count": None,
            "advertised_tool_count": counts["total"],
            "missing_tool_count": 0,
            "unexpected_tools": [],
            "changed_tools": [],
            "contract_schema_version": CONTRACT_SCHEMA_VERSION,
        }
    recorded_entries = [entry for entry in recorded.get("tools", []) if isinstance(entry, dict)]
    recorded_by_name = {entry["name"]: entry for entry in recorded_entries if "name" in entry}
    manifest_valid = (
        recorded.get("schema_version") == CATALOG_SCHEMA_VERSION
        and len(recorded_entries) == len(recorded.get("tools", [])) == len(recorded_by_name)
        and recorded.get("catalog_sha256") == catalog_sha256(recorded_entries)
        and all(entry.get("digest") == _sha256(canonical_json(
            {key: value for key, value in entry.items() if key != "digest"}
        ).encode("utf-8")) for entry in recorded_entries)
    )
    advertised_by_name = {entry["name"]: entry for entry in entries}
    unexpected = sorted(set(advertised_by_name) - set(recorded_by_name))
    missing = sorted(set(recorded_by_name) - set(advertised_by_name))
    changed = sorted(
        name
        for name in set(advertised_by_name) & set(recorded_by_name)
        if advertised_by_name[name]["digest"] != recorded_by_name[name]["digest"]
    )
    if len(entries) == len(recorded_entries):
        profile = "full"
    elif missing and not unexpected and not changed:
        profile = "compact" if len(entries) < len(recorded_entries) else "subset"
    else:
        profile = "subset"
    advertised_sha = catalog_sha256(entries)
    recorded_sha = recorded.get("catalog_sha256")
    matches = (
        manifest_valid and profile == "full"
        and not unexpected
        and not changed
        and recorded_sha == advertised_sha
        and recorded.get("contract_schema_version") == CONTRACT_SCHEMA_VERSION
    )
    subset_matches = manifest_valid and not unexpected and not changed and (
        recorded.get("contract_schema_version") == CONTRACT_SCHEMA_VERSION
    )
    return {
        "recorded": True,
        "profile": profile,
        "matches": matches,
        "subset_matches": subset_matches,
        "recorded_sha256": recorded_sha,
        "advertised_sha256": advertised_sha,
        "recorded_tool_count": len(recorded_entries),
        "advertised_tool_count": counts["total"],
        "missing_tool_count": len(missing),
        "unexpected_tools": unexpected,
        "changed_tools": changed,
        "contract_schema_version": CONTRACT_SCHEMA_VERSION,
    }


def payload_bytes(tools: Mapping[str, Any]) -> int:
    """Size of the tool list a client receives, so an operator can see context cost.

    This is the wire projection (name, description, input and output schema,
    annotations, and ``_meta``), not the digested catalog: digests and contract
    duplication are server-side and would overstate what the model pays for.
    """
    wire = [
        {
            "name": name,
            "description": getattr(tool, "description", "") or "",
            "inputSchema": getattr(tool, "parameters", {}),
            "outputSchema": getattr(tool, "output_schema", None),
            "annotations": _annotations(tool),
            "meta": getattr(tool, "meta", None) or {},
        }
        for name, tool in tools.items()
    ]
    return len(canonical_json(sorted(wire, key=lambda entry: entry["name"])).encode("utf-8"))
