"""Deterministic CVE exploit-chain planning for the PoC subsystem.

The chain model is deliberately simple and auditable: one step (a CVE on one
asset) declares the capability tokens it *requires* before it can be attempted
and the tokens it *provides* once it succeeds. Starting from the operator's
entry capabilities, steps are satisfied in repeated passes over the input order
until no further progress is possible. The resulting plan is persisted as
canonical JSON under ``<engagement>/poc/chains/`` and content-addressed with
``chain_sha256`` so tampering is detected on load.

Determinism is a hard requirement: identical inputs produce byte-identical
canonical payloads apart from ``chain_id`` and ``created_at``. The hash covers
every other field::

    chain_sha256 = canonical_sha256(payload without
                                    chain_id / created_at / chain_sha256)

Public API
----------
``plan_chain(engagement_id, steps, entry_capabilities, artifacts=None,
chain_name="")``
    Validate, evaluate, and persist a chain; returns the full record.

``load_chain(engagement_id, chain_id)``
    Load one persisted chain and verify its content hash.

``list_chains(engagement_id)``
    Summarise the persisted chains, reporting corrupt files under ``invalid``.

``parse_artifacts(engagement_id, paths)``
    Parse nuclei/trivy/generic artefacts into ``{cve_id: {observed,
    locations}}``.

Chain record shape (schema_version 1)::

    {
      "schema_version": 1,
      "chain_id": "chain_YYYYMMDD_<32 hex>",
      "chain_name": str,
      "engagement_id": str,
      "created_at": "2026-01-01T00:00:00Z",
      "entry_capabilities": [sorted tokens],
      "artifacts": [sorted engagement-relative paths],
      "verdict": "complete" | "incomplete" | "cyclic",
      "missing": [sorted unsatisfied tokens],
      "cycle": [cve ids demonstrating the cycle, empty unless cyclic],
      "execution_order": [cve ids of satisfied steps, in order],
      "assumptions": [str, empty unless entry capabilities were inferred],
      "warnings": [sorted warning codes],
      "unobserved_cves": [sorted cve ids],
      "unverified_cves": [sorted cve ids],
      "steps": [step records in satisfaction order],
      "chain_sha256": "<64 hex>",
    }

Step record shape::

    {
      "index": 0,                     # position in the caller's input list
      "cve_id": "CVE-2026-1234",
      "asset": "app.example.test",
      "requires": [sorted tokens],
      "provides": [sorted tokens],
      "basis": str,
      "source": "nvd"|"nuclei"|"trivy"|"manual"|"exploitdb",
      "evidence_path": str | None,
      "satisfied": bool,
      "order": int | None,            # 1..n for satisfied steps
      "missing": [sorted tokens still required],
      "observed": bool,               # CVE seen in a parsed artefact
      "observation_locations": [{"path", "line", "source", "detail"}],
      "warnings": [sorted warning codes],
    }

All refusals raise :class:`opencyber.poc_schema.PocError` with an actionable
``reason`` so the MCP layer can return a structured refusal.
"""

from __future__ import annotations

import hmac
import json
import os
from pathlib import Path, PurePosixPath
import tempfile
from typing import Any, Iterable, NoReturn

from . import envelope
from .audit import safe_record
from .engagements import get_engagement
from .poc_schema import (
    CVE_PATTERN,
    PocError,
    canonical_json,
    canonical_sha256,
    iso_utc,
    new_record_id,
    normalize_capabilities,
    normalize_cve_id,
    poc_path,
    utc_now,
    validate_record_id,
)
from .workspace import read_workspace_file


__all__ = ["plan_chain", "load_chain", "list_chains", "parse_artifacts"]

SCHEMA_VERSION = 1
CHAIN_DIRECTORY = "chains"
CHAIN_CREATED_EVENT = "poc.chain.created"
MAX_CHAIN_NAME_LENGTH = 200

STEP_SOURCES: tuple[str, ...] = ("nvd", "nuclei", "trivy", "manual", "exploitdb")
VERDICTS: tuple[str, ...] = ("complete", "incomplete", "cyclic")

_STEP_FIELDS = frozenset(
    {"cve_id", "asset", "requires", "provides", "basis", "source", "evidence_path"}
)
_REQUIRED_STEP_FIELDS: tuple[str, ...] = ("cve_id", "asset", "basis")
_UNHASHED_FIELDS = frozenset({"chain_id", "created_at", "chain_sha256"})

_WARNING_UNOBSERVED = "unobserved_cve"
_WARNING_UNVERIFIED = "unverified_cve"

_SUPPORTED_ARTIFACT_SUFFIXES = (".jsonl", ".json")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def _chain_contract(record: dict[str, Any]) -> dict[str, Any]:
    """Derive coverage and limitations from a chain record's own verdict facts.

    The declaration is added to the record before it is hashed, so it is
    content-addressed with the plan rather than recomputed from untrusted state.
    """
    raw_steps = record.get("steps")
    steps: list[Any] = raw_steps if isinstance(raw_steps, list) else []
    satisfied = len([step for step in steps if isinstance(step, dict) and step.get("satisfied")])
    verdict = record.get("verdict")
    limitations: list[str] = []
    if verdict == "incomplete":
        missing = [str(token) for token in record.get("missing") or []]
        limitations.append(
            "The chain is incomplete: no supplied step provides "
            + ", ".join(missing)
            + ", so the unsatisfied steps cannot be executed in this plan."
        )
    elif verdict == "cyclic":
        cycle = [str(cve_id) for cve_id in record.get("cycle") or []]
        limitations.append(
            "The chain is cyclic: " + ", ".join(cycle) + " each require a capability that another step "
            "in the cycle provides, so no execution order exists."
        )
    unobserved = [str(cve_id) for cve_id in record.get("unobserved_cves") or []]
    if unobserved:
        limitations.append(
            f"{len(unobserved)} CVE step(s) were not observed in any supplied artifact "
            f"({', '.join(unobserved)}); the chain rests on each written basis rather than on observed "
            "exploitation."
        )
    unverified = [str(cve_id) for cve_id in record.get("unverified_cves") or []]
    if unverified:
        limitations.append(
            f"{len(unverified)} CVE(s) could not be verified against the local offline index "
            f"({', '.join(unverified)}); their existence is unconfirmed and no network lookup was attempted."
        )
    for assumption in record.get("assumptions") or []:
        limitations.append(f"Planning assumption: {assumption}.")
    complete = verdict == "complete"
    return {
        "coverage": envelope.coverage(
            "complete" if complete else "partial",
            examined=satisfied,
            total=len(steps),
            exhausted=complete,
        ),
        "limitations": limitations,
    }


def plan_chain(
    engagement_id: str,
    steps: list[dict[str, Any]],
    entry_capabilities: list[str],
    artifacts: list[str] | None = None,
    chain_name: str = "",
) -> dict[str, Any]:
    """Validate, evaluate, and persist one exploit chain.

    ``entry_capabilities`` is the capability set the engagement starts from.
    ``artifacts`` are engagement-relative nuclei/trivy/generic files used to
    mark steps as observed; each step may additionally name its own
    ``evidence_path``. Returns the persisted record (see module docstring).
    """
    _require_engagement(engagement_id)
    normalized_steps = _normalize_steps(steps)

    assumptions: list[str] = []
    if entry_capabilities is None:
        # Defensive only: the documented signature requires an explicit list.
        normalized_entry: list[str] = []
        assumptions.append("entry_capabilities were not supplied; assumed empty")
    else:
        normalized_entry = _normalize_capability_list(
            entry_capabilities, "entry_capabilities"
        )

    artifact_paths = _normalize_artifact_paths(artifacts)
    normalized_name = _normalize_chain_name(chain_name)

    evidence_paths = [
        step["evidence_path"] for step in normalized_steps if step["evidence_path"]
    ]
    observation_paths = _dedupe_strings([*artifact_paths, *evidence_paths])
    observations = (
        parse_artifacts(engagement_id, observation_paths) if observation_paths else {}
    )

    available = set(normalized_entry)
    satisfied = [False] * len(normalized_steps)
    order: list[int | None] = [None] * len(normalized_steps)
    next_order = 1
    progress = True
    while progress:
        progress = False
        for index, step in enumerate(normalized_steps):
            if satisfied[index]:
                continue
            if set(step["requires"]) <= available:
                satisfied[index] = True
                order[index] = next_order
                next_order += 1
                available.update(step["provides"])
                progress = True

    remaining = [index for index, done in enumerate(satisfied) if not done]
    missing_by_step = {
        index: set(normalized_steps[index]["requires"]) - available
        for index in remaining
    }
    missing = sorted(
        {token for tokens in missing_by_step.values() for token in tokens}
    )

    cycle_step_indexes: list[int] = []
    if remaining:
        remaining_provides: set[str] = set()
        for index in remaining:
            remaining_provides.update(normalized_steps[index]["provides"])
        # A cycle is demonstrable when the closure has stalled and every
        # remaining step's missing tokens can only be supplied by another
        # remaining step: no external step can ever unblock the group.
        if all(
            missing_by_step[index]
            and missing_by_step[index] <= remaining_provides
            for index in remaining
        ):
            cycle_step_indexes = _find_dependency_cycle(
                remaining, missing_by_step, normalized_steps
            )

    if not remaining:
        verdict = "complete"
    elif cycle_step_indexes:
        verdict = "cyclic"
    else:
        verdict = "incomplete"

    unique_cves = sorted({step["cve_id"] for step in normalized_steps})
    unverified = _unverified_cves(unique_cves)

    step_records = [
        _build_step_record(
            index, step, satisfied[index], order[index], missing_by_step, observations, unverified
        )
        for index, step in enumerate(normalized_steps)
    ]
    step_records.sort(key=_step_sort_key)

    execution_order = [
        step_record["cve_id"]
        for step_record in step_records
        if step_record["satisfied"]
    ]
    warnings = sorted(
        {code for step_record in step_records for code in step_record["warnings"]}
    )
    unobserved_cves = sorted(
        {step_record["cve_id"] for step_record in step_records if not step_record["observed"]}
    )

    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "chain_name": normalized_name,
        "engagement_id": engagement_id,
        "entry_capabilities": normalized_entry,
        "artifacts": sorted(artifact_paths),
        "verdict": verdict,
        "missing": missing,
        "cycle": [
            normalized_steps[index]["cve_id"] for index in cycle_step_indexes
        ],
        "execution_order": execution_order,
        "assumptions": assumptions,
        "warnings": warnings,
        "unobserved_cves": unobserved_cves,
        "unverified_cves": sorted(unverified),
        "steps": step_records,
    }
    payload.update(_chain_contract(payload))

    chain_id = new_record_id("chain")
    record: dict[str, Any] = {
        **payload,
        "chain_id": chain_id,
        "created_at": iso_utc(utc_now()),
        "chain_sha256": canonical_sha256(payload),
    }
    _persist_record(engagement_id, record)
    safe_record(
        engagement_id,
        {
            "event": CHAIN_CREATED_EVENT,
            "chain_id": record["chain_id"],
            "verdict": record["verdict"],
            "steps": len(record["steps"]),
        },
    )
    return record


def load_chain(engagement_id: str, chain_id: str) -> dict[str, Any]:
    """Load a persisted chain and verify its content hash.

    Raises ``PocError`` with ``invalid_id`` for a malformed chain id,
    ``unknown_chain`` when no record exists, and ``chain_invalid`` when the
    file is corrupt or its ``chain_sha256`` no longer matches its contents.
    """
    validate_record_id("chain", chain_id)
    _require_engagement(engagement_id)
    record = _read_chain_record(engagement_id, chain_id)
    # Recompute rather than trust stored presentation fields so a record written
    # by an earlier release still returns a truthful declaration.
    return {**record, **_chain_contract(record)}


def list_chains(engagement_id: str) -> dict[str, Any]:
    """Return chain summaries newest-first, tolerating corrupt records.

    ``invalid`` lists files that could not be read or verified so an operator
    sees damage instead of silently losing a plan.
    """
    _require_engagement(engagement_id)
    directory = _chains_directory(engagement_id)
    chains: list[dict[str, Any]] = []
    invalid: list[dict[str, Any]] = []
    if directory.is_dir():
        try:
            entries = sorted(directory.iterdir(), key=lambda item: item.name)
        except OSError as exc:
            raise PocError(
                "chain_listing_failed", f"cannot list chain records: {exc}"
            ) from exc
        for item in entries:
            if item.name.startswith(".") or item.suffix != ".json":
                continue
            chain_id = item.stem
            try:
                validate_record_id("chain", chain_id)
                if item.is_symlink() or not item.is_file():
                    raise ValueError("chain record is not a regular file")
                record = _read_chain_record(engagement_id, chain_id)
            except (PocError, ValueError, OSError) as exc:
                invalid.append(
                    {"file": item.name, "chain_id": chain_id, "error": _error_text(exc)}
                )
                continue
            chains.append(
                {
                    "chain_id": record["chain_id"],
                    "chain_name": record.get("chain_name", ""),
                    "verdict": record.get("verdict"),
                    "steps": len(record["steps"]),
                    "created_at": record["created_at"],
                }
            )
    elif directory.exists():
        invalid.append(
            {"file": directory.name, "chain_id": None, "error": "not a directory"}
        )
    chains.sort(key=lambda item: (item["created_at"], item["chain_id"]), reverse=True)
    return {"engagement_id": engagement_id, "chains": chains, "invalid": invalid}


def parse_artifacts(engagement_id: str, paths: list[str]) -> dict[str, dict[str, Any]]:
    """Parse engagement-relative artefact files into observations by CVE id.

    Supported inputs are nuclei JSONL (``.jsonl``) and trivy or generic JSON
    (``.json``). Returns ``{cve_id: {"observed": True, "locations": [...]}}``
    with locations sorted deterministically. Malformed content raises
    ``PocError("artifact_invalid", ..., path=..., line=...)``; unknown
    extensions are refused rather than silently ignored.
    """
    _require_engagement(engagement_id)
    normalized_paths = _normalize_artifact_paths(paths)
    results: dict[str, dict[str, Any]] = {}
    for path in normalized_paths:
        content_info = _read_artifact(engagement_id, path)
        relative_path = content_info["path"]
        entries = _parse_artifact_content(relative_path, content_info["content"])
        for cve_id, location in entries:
            bucket = results.setdefault(cve_id, {"observed": True, "locations": []})
            if location not in bucket["locations"]:
                bucket["locations"].append(location)
    for bucket in results.values():
        bucket["locations"].sort(key=_location_sort_key)
    return results


# ---------------------------------------------------------------------------
# Chain evaluation helpers
# ---------------------------------------------------------------------------


def _build_step_record(
    index: int,
    step: dict[str, Any],
    is_satisfied: bool,
    step_order: int | None,
    missing_by_step: dict[int, set[str]],
    observations: dict[str, dict[str, Any]],
    unverified: set[str],
) -> dict[str, Any]:
    cve_id = step["cve_id"]
    observation = observations.get(cve_id, {})
    observed = bool(observation.get("observed"))
    locations = [
        dict(location) for location in observation.get("locations", [])
    ]
    warnings: list[str] = []
    if not observed:
        warnings.append(_WARNING_UNOBSERVED)
    if cve_id in unverified:
        warnings.append(_WARNING_UNVERIFIED)
    return {
        "index": index,
        "cve_id": cve_id,
        "asset": step["asset"],
        "requires": list(step["requires"]),
        "provides": list(step["provides"]),
        "basis": step["basis"],
        "source": step["source"],
        "evidence_path": step["evidence_path"],
        "satisfied": is_satisfied,
        "order": step_order,
        "missing": sorted(missing_by_step.get(index, set())),
        "observed": observed,
        "observation_locations": locations,
        "warnings": sorted(warnings),
    }


def _step_sort_key(step_record: dict[str, Any]) -> tuple[int, int, int]:
    if step_record["satisfied"]:
        return (0, step_record["order"] or 0, step_record["index"])
    return (1, step_record["index"], 0)


def _find_dependency_cycle(
    remaining: list[int],
    missing_by_step: dict[int, set[str]],
    steps: list[dict[str, Any]],
) -> list[int]:
    """Return one dependency cycle among the remaining steps, if discoverable.

    An edge ``i -> j`` exists when step *i* still misses a capability that
    step *j* provides. The walk is deterministic: nodes are visited in input
    order and neighbours keep the same order.
    """
    successors: dict[int, list[int]] = {}
    for index in remaining:
        successors[index] = [
            other
            for other in remaining
            if missing_by_step[index] & set(steps[other]["provides"])
        ]
    state = {index: 0 for index in remaining}
    for start in remaining:
        if state[start] != 0:
            continue
        path = [start]
        state[start] = 1
        stack: list[tuple[int, Iterable[int]]] = [(start, iter(successors[start]))]
        while stack:
            node, iterator = stack[-1]
            advanced = False
            for neighbour in iterator:
                if state.get(neighbour) == 1:
                    return path[path.index(neighbour):]
                if state.get(neighbour) == 0:
                    state[neighbour] = 1
                    path.append(neighbour)
                    stack.append((neighbour, iter(successors[neighbour])))
                    advanced = True
                    break
            if not advanced:
                state[node] = 2
                stack.pop()
                path.pop()
    return []


def _unverified_cves(cve_ids: list[str]) -> set[str]:
    return {cve_id for cve_id in cve_ids if not _cve_exists(cve_id)}


def _cve_exists(cve_id: str) -> bool:
    """Best-effort offline existence check against a local NVD SQLite index.

    The import is lazy and every failure (missing DB, unreadable schema, import
    error) counts as "unverified" only -- planning never touches the network
    and never fails because the offline index is absent.
    """
    try:
        from .native_tools import _local_cve_lookup
    except Exception:
        return False
    try:
        record = _local_cve_lookup(cve_id)
    except Exception:
        return False
    return bool(record and record.get("found"))


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------


def _require_engagement(engagement_id: str) -> None:
    if not isinstance(engagement_id, str) or not engagement_id.strip():
        raise PocError(
            "unknown_engagement",
            "engagement_id must be a server-generated identifier such as "
            "eng_20261009_9f8d4c1a6b2743f4a2c11bb8d02a91a7",
        )
    try:
        get_engagement(engagement_id)
    except ValueError as exc:
        raise PocError(
            "unknown_engagement", str(exc), engagement_id=engagement_id
        ) from exc
    except OSError as exc:
        raise PocError(
            "unknown_engagement",
            f"cannot read engagement {engagement_id!r}: {exc}",
            engagement_id=engagement_id,
        ) from exc


def _normalize_chain_name(chain_name: Any) -> str:
    if not isinstance(chain_name, str):
        raise PocError("invalid_chain_name", "chain_name must be a string")
    name = chain_name.strip()
    if len(name) > MAX_CHAIN_NAME_LENGTH:
        raise PocError(
            "invalid_chain_name",
            f"chain_name must be {MAX_CHAIN_NAME_LENGTH} characters or fewer",
        )
    return name


def _normalize_capability_list(
    values: Any, field: str, index: int | None = None
) -> list[str]:
    details = {"index": index} if index is not None else {}
    if isinstance(values, (str, bytes)) or not isinstance(values, (list, tuple)):
        raise PocError(
            "invalid_capability",
            f"{field} must be a list of capability tokens",
            **details,
        )
    try:
        return normalize_capabilities(values)
    except PocError as exc:
        suffix = f" (step {index})" if index is not None else ""
        raise PocError(exc.reason, f"{field}{suffix}: {exc.message}", **details) from exc


def _normalize_steps(steps: Any) -> list[dict[str, Any]]:
    if isinstance(steps, (str, bytes, dict)) or not isinstance(steps, (list, tuple)):
        raise PocError(
            "invalid_steps",
            "steps must be a list of step objects; each step is an object with "
            "cve_id, asset, requires, provides, basis, source and optional evidence_path",
        )
    if not steps:
        raise PocError("invalid_steps", "steps must contain at least one step")
    return [_normalize_step(raw_step, index) for index, raw_step in enumerate(steps)]


def _normalize_step(raw_step: Any, index: int) -> dict[str, Any]:
    if not isinstance(raw_step, dict):
        raise PocError("invalid_step", "step must be a JSON object", index=index)
    unknown = sorted(set(raw_step) - _STEP_FIELDS)
    if unknown:
        raise PocError(
            "invalid_step",
            f"unknown step field(s) {', '.join(unknown)}; allowed fields: "
            f"{', '.join(sorted(_STEP_FIELDS))}",
            index=index,
            fields=unknown,
        )
    for field in _REQUIRED_STEP_FIELDS:
        if field not in raw_step:
            raise PocError(
                "invalid_step",
                f"step is missing the required field {field!r}",
                index=index,
                field=field,
            )

    try:
        cve_id = normalize_cve_id(raw_step["cve_id"])
    except PocError as exc:
        raise PocError(exc.reason, f"{exc.message} (step {index})", index=index) from exc

    asset = raw_step["asset"]
    if not isinstance(asset, str) or not asset.strip():
        raise PocError(
            "invalid_step",
            "asset must be a non-empty string naming the authorized target the step applies to",
            index=index,
            field="asset",
        )
    basis = raw_step["basis"]
    if not isinstance(basis, str) or not basis.strip():
        raise PocError(
            "invalid_step",
            "basis must be a non-empty string explaining why the capability tokens "
            "follow from the advisory",
            index=index,
            field="basis",
        )

    requires = _normalize_capability_list(raw_step.get("requires", []), "requires", index)
    provides = _normalize_capability_list(raw_step.get("provides", []), "provides", index)

    source = raw_step.get("source", "manual")
    if not isinstance(source, str):
        raise PocError(
            "invalid_step", "source must be a string", index=index, field="source"
        )
    normalized_source = source.strip().lower()
    if normalized_source not in STEP_SOURCES:
        raise PocError(
            "invalid_step",
            f"source must be one of {', '.join(STEP_SOURCES)}: {source!r}",
            index=index,
            field="source",
        )

    evidence_path = raw_step.get("evidence_path")
    if evidence_path is None:
        normalized_evidence: str | None = None
    else:
        if not isinstance(evidence_path, str) or not evidence_path.strip():
            raise PocError(
                "invalid_step",
                "evidence_path must be a non-empty engagement-relative string",
                index=index,
                field="evidence_path",
            )
        normalized_evidence = _normalize_relative_path(
            evidence_path, field="evidence_path", reason="invalid_step", index=index
        )

    return {
        "index": index,
        "cve_id": cve_id,
        "asset": asset.strip(),
        "requires": requires,
        "provides": provides,
        "basis": basis.strip(),
        "source": normalized_source,
        "evidence_path": normalized_evidence,
    }


def _normalize_artifact_paths(paths: Any) -> list[str]:
    if paths is None:
        return []
    if isinstance(paths, (str, bytes)) or not isinstance(paths, (list, tuple)):
        raise PocError(
            "artifact_invalid",
            "artifact paths must be a list of engagement-relative files",
        )
    normalized: list[str] = []
    seen: set[str] = set()
    for index, value in enumerate(paths):
        if not isinstance(value, str) or not value.strip():
            raise PocError(
                "artifact_invalid",
                f"artifact path at index {index} must be a non-empty string",
            )
        path = _normalize_relative_path(
            value, field=f"artifact path at index {index}", reason="artifact_invalid"
        )
        if path not in seen:
            seen.add(path)
            normalized.append(path)
    return normalized


def _normalize_relative_path(
    value: str, *, field: str, reason: str, index: int | None = None
) -> str:
    details = {"index": index} if index is not None else {}
    pure = PurePosixPath(value.strip())
    if pure.is_absolute() or ".." in pure.parts:
        raise PocError(
            reason,
            f"{field} must be an engagement-relative path without '..': {value!r}",
            **details,
        )
    normalized = pure.as_posix()
    if normalized in ("", "."):
        raise PocError(reason, f"{field} must name a file: {value!r}", **details)
    return normalized


def _dedupe_strings(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    deduped: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            deduped.append(value)
    return deduped


# ---------------------------------------------------------------------------
# Artefact parsing
# ---------------------------------------------------------------------------


def _read_artifact(engagement_id: str, path: str) -> dict[str, str]:
    try:
        info = read_workspace_file(engagement_id, path)
    except (ValueError, OSError) as exc:
        raise PocError(
            "artifact_invalid", f"cannot read artifact {path!r}: {exc}", path=path
        ) from exc
    if info.get("truncated"):
        raise PocError(
            "artifact_invalid",
            f"artifact {path!r} exceeds the workspace read limit; split it into complete smaller artifacts",
            path=path, truncated=True, total_bytes=info.get("total_bytes"),
        )
    return {"path": info["path"], "content": info["content"]}


def _parse_artifact_content(
    relative_path: str, content: str
) -> list[tuple[str, dict[str, Any]]]:
    suffix = PurePosixPath(relative_path).suffix.lower()
    if suffix == ".jsonl":
        return _parse_nuclei_jsonl(relative_path, content)
    if suffix == ".json":
        return _parse_json_artifact(relative_path, content)
    raise PocError(
        "artifact_invalid",
        f"unsupported artifact extension {suffix or '<none>'!r} for {relative_path!r}; "
        "supported extensions are .jsonl (nuclei) and .json (trivy/generic)",
        path=relative_path,
    )


def _parse_json_artifact(
    relative_path: str, content: str
) -> list[tuple[str, dict[str, Any]]]:
    try:
        data = json.loads(content)
    except json.JSONDecodeError as exc:
        raise PocError(
            "artifact_invalid",
            f"{relative_path}: invalid JSON: {exc.msg}",
            path=relative_path,
            line=exc.lineno,
        ) from exc
    except RecursionError as exc:
        raise PocError(
            "artifact_invalid", f"{relative_path}: JSON is nested too deeply", path=relative_path
        ) from exc
    if isinstance(data, list):
        return _parse_generic_json(relative_path, data)
    if isinstance(data, dict):
        results = data.get("Results")
        if isinstance(results, list):
            return _parse_trivy_results(relative_path, results)
        vulnerabilities = data.get("Vulnerabilities")
        if isinstance(vulnerabilities, list):
            return _parse_trivy_results(
                relative_path,
                [
                    {
                        "Target": data.get("ArtifactName") or data.get("Target"),
                        "Vulnerabilities": vulnerabilities,
                    }
                ],
            )
    raise PocError(
        "artifact_invalid",
        f"unrecognized JSON artifact structure in {relative_path!r}: expected a trivy "
        "'Results' list or a JSON list of objects with cve_id/CVE keys",
        path=relative_path,
    )


def _parse_nuclei_jsonl(
    relative_path: str, content: str
) -> list[tuple[str, dict[str, Any]]]:
    entries: list[tuple[str, dict[str, Any]]] = []
    for number, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            record = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise PocError(
                "artifact_invalid",
                f"{relative_path}: line {number} is not valid JSON: {exc.msg}",
                path=relative_path,
                line=number,
            ) from exc
        if not isinstance(record, dict):
            raise PocError(
                "artifact_invalid",
                f"{relative_path}: line {number} must be a JSON object",
                path=relative_path,
                line=number,
            )
        detail = _nuclei_location_detail(record)
        for cve_id in _nuclei_cve_values(record, relative_path, number):
            entries.append(
                (
                    cve_id,
                    {
                        "path": relative_path,
                        "line": number,
                        "source": "nuclei",
                        "detail": detail,
                    },
                )
            )
    return entries


def _nuclei_cve_values(record: dict[str, Any], path: str, line: int) -> list[str]:
    info = record.get("info")
    classification = info.get("classification") if isinstance(info, dict) else None
    raw: Any = None
    if isinstance(classification, dict):
        raw = classification.get("cve-id")
        if raw is None:
            raw = classification.get("cve_id")
    if raw is None:
        raw = record.get("cve_id", record.get("CVE"))
    return _iterate_cve_values(
        raw, path=path, line=line, context=f"line {line} cve-id"
    )


def _nuclei_location_detail(record: dict[str, Any]) -> str:
    parts: list[str] = []
    template_id = record.get("template-id")
    if isinstance(template_id, str) and template_id.strip():
        parts.append(f"template-id={template_id.strip()}")
    matched_at = record.get("matched-at")
    if isinstance(matched_at, str) and matched_at.strip():
        parts.append(f"matched-at={matched_at.strip()}")
    else:
        host = record.get("host")
        if isinstance(host, str) and host.strip():
            parts.append(f"host={host.strip()}")
    return "; ".join(parts)


def _parse_trivy_results(
    relative_path: str, results: list[Any]
) -> list[tuple[str, dict[str, Any]]]:
    entries: list[tuple[str, dict[str, Any]]] = []
    for result_index, result in enumerate(results):
        if not isinstance(result, dict):
            raise PocError(
                "artifact_invalid",
                f"{relative_path}: Results[{result_index}] must be a JSON object",
                path=relative_path,
            )
        target = result.get("Target")
        vulnerabilities = result.get("Vulnerabilities")
        if vulnerabilities is None:
            vulnerabilities = []
        if not isinstance(vulnerabilities, list):
            raise PocError(
                "artifact_invalid",
                f"{relative_path}: Results[{result_index}].Vulnerabilities must be a list",
                path=relative_path,
            )
        for vulnerability_index, vulnerability in enumerate(vulnerabilities):
            if not isinstance(vulnerability, dict):
                raise PocError(
                    "artifact_invalid",
                    f"{relative_path}: Results[{result_index}].Vulnerabilities"
                    f"[{vulnerability_index}] must be a JSON object",
                    path=relative_path,
                )
            cve_id = _coerce_cve(
                vulnerability.get("VulnerabilityID"),
                path=relative_path,
                context=(
                    f"Results[{result_index}].Vulnerabilities"
                    f"[{vulnerability_index}].VulnerabilityID"
                ),
            )
            if cve_id is None:
                continue
            parts: list[str] = []
            if isinstance(target, str) and target.strip():
                parts.append(f"Target={target.strip()}")
            package_name = vulnerability.get("PkgName")
            if isinstance(package_name, str) and package_name.strip():
                parts.append(f"PkgName={package_name.strip()}")
            entries.append(
                (
                    cve_id,
                    {
                        "path": relative_path,
                        "line": None,
                        "source": "trivy",
                        "detail": "; ".join(parts),
                    },
                )
            )
    return entries


def _parse_generic_json(
    relative_path: str, data: list[Any]
) -> list[tuple[str, dict[str, Any]]]:
    entries: list[tuple[str, dict[str, Any]]] = []
    for index, item in enumerate(data):
        if not isinstance(item, dict):
            raise PocError(
                "artifact_invalid",
                f"{relative_path}: entry {index} must be a JSON object",
                path=relative_path,
            )
        if "cve_id" in item:
            raw = item["cve_id"]
        elif "CVE" in item:
            raw = item["CVE"]
        else:
            continue
        detail_parts: list[str] = []
        for key in ("asset", "host", "target"):
            value = item.get(key)
            if isinstance(value, str) and value.strip():
                detail_parts.append(f"{key}={value.strip()}")
        detail = "; ".join(detail_parts)
        for cve_id in _iterate_cve_values(
            raw, path=relative_path, line=None, context=f"entry {index} cve_id"
        ):
            entries.append(
                (
                    cve_id,
                    {
                        "path": relative_path,
                        "line": None,
                        "source": "generic",
                        "detail": detail,
                    },
                )
            )
    return entries


def _iterate_cve_values(
    raw: Any, *, path: str, line: int | None, context: str
) -> list[str]:
    if raw is None:
        return []
    if isinstance(raw, str):
        cve_id = _coerce_cve(raw, path=path, line=line, context=context)
        return [cve_id] if cve_id else []
    if isinstance(raw, list):
        values: list[str] = []
        for item in raw:
            if not isinstance(item, str):
                raise _artifact_value_error(
                    path, line, f"{context} entries must be strings"
                )
            cve_id = _coerce_cve(item, path=path, line=line, context=context)
            if cve_id:
                values.append(cve_id)
        return values
    raise _artifact_value_error(
        path, line, f"{context} must be a string or a list of strings"
    )


def _coerce_cve(
    value: Any, *, path: str, context: str, line: int | None = None
) -> str | None:
    """Normalize a CVE id, tolerating non-CVE identifiers from scanners."""
    if value is None:
        return None
    if not isinstance(value, str):
        raise _artifact_value_error(path, line, f"{context} must be a string")
    text = value.strip()
    if not text:
        return None
    upper = text.upper()
    if CVE_PATTERN.fullmatch(upper):
        return normalize_cve_id(upper)
    if not upper.startswith("CVE-"):
        # Not a CVE id at all (e.g. a GHSA id); scanners legitimately emit these.
        return None
    raise _artifact_value_error(
        path, line, f"{context} is not a valid CVE identifier: {value!r}"
    )


def _artifact_value_error(path: str, line: int | None, message: str) -> PocError:
    details: dict[str, Any] = {"path": path}
    if line is not None:
        details["line"] = line
    return PocError("artifact_invalid", f"{path}: {message}", **details)


def _location_sort_key(location: dict[str, Any]) -> tuple[str, int, str, str]:
    line = location.get("line")
    return (
        str(location.get("path", "")),
        line if isinstance(line, int) else 0,
        str(location.get("source", "")),
        str(location.get("detail", "")),
    )


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


def _chains_directory(engagement_id: str) -> Path:
    try:
        return poc_path(engagement_id, CHAIN_DIRECTORY)
    except ValueError as exc:
        raise PocError(
            "unknown_engagement", str(exc), engagement_id=engagement_id
        ) from exc


def _read_chain_record(engagement_id: str, chain_id: str) -> dict[str, Any]:
    target = _chains_directory(engagement_id) / f"{chain_id}.json"
    if target.is_symlink() or not target.is_file():
        raise PocError(
            "unknown_chain",
            f"no chain record for {chain_id} in engagement {engagement_id}",
            chain_id=chain_id,
        )
    try:
        raw = target.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise PocError(
            "chain_invalid",
            f"cannot read chain record {target.name}: {exc}",
            chain_id=chain_id,
        ) from exc
    try:
        record = json.loads(raw)
    except (json.JSONDecodeError, RecursionError) as exc:
        raise PocError(
            "chain_invalid",
            f"chain record {target.name} is not valid JSON: {exc}",
            chain_id=chain_id,
        ) from exc
    if not isinstance(record, dict):
        raise PocError(
            "chain_invalid",
            f"chain record {target.name} is not a JSON object",
            chain_id=chain_id,
        )
    _verify_chain_record(record, chain_id, engagement_id)
    return record


def _verify_chain_record(
    record: dict[str, Any], chain_id: str, engagement_id: str
) -> None:
    def invalid(message: str) -> NoReturn:
        raise PocError("chain_invalid", f"chain {chain_id}: {message}", chain_id=chain_id)

    if type(record.get("schema_version")) is not int or record["schema_version"] != SCHEMA_VERSION:
        invalid(f"unsupported schema_version {record.get('schema_version')!r}")
    if record.get("chain_id") != chain_id:
        invalid("stored chain_id does not match the file name")
    if record.get("engagement_id") != engagement_id:
        invalid("stored engagement_id does not match the requested engagement")
    stored_hash = record.get("chain_sha256")
    if not isinstance(stored_hash, str) or len(stored_hash) != 64:
        invalid("missing or malformed chain_sha256")
    if not hmac.compare_digest(stored_hash, _payload_sha256(record)):
        invalid("chain_sha256 does not match the record contents; the file was modified")
    if record.get("verdict") not in VERDICTS:
        invalid(f"unknown verdict {record.get('verdict')!r}")
    if not isinstance(record.get("steps"), list):
        invalid("steps must be a list")
    if not isinstance(record.get("created_at"), str) or not record["created_at"]:
        invalid("created_at is missing")


def _payload_sha256(record: dict[str, Any]) -> str:
    payload = {
        key: value for key, value in record.items() if key not in _UNHASHED_FIELDS
    }
    return canonical_sha256(payload)


def _persist_record(engagement_id: str, record: dict[str, Any]) -> None:
    chain_id = record["chain_id"]
    try:
        target = poc_path(engagement_id, CHAIN_DIRECTORY, f"{chain_id}.json")
    except ValueError as exc:
        raise PocError(
            "unknown_engagement", str(exc), engagement_id=engagement_id
        ) from exc
    try:
        _atomic_write(target, canonical_json(record) + b"\n")
    except OSError as exc:
        raise PocError(
            "chain_persist_failed",
            f"cannot persist chain record {target.name}: {exc}",
            chain_id=chain_id,
        ) from exc


def _atomic_write(target: Path, data: bytes) -> None:
    parent = target.parent
    parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(
        dir=str(parent), prefix=f".{target.name}.", suffix=".tmp"
    )
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary_name, target)
    except BaseException:
        try:
            os.unlink(temporary_name)
        except OSError:
            pass
        raise
    try:
        directory_descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
    except OSError:
        return
    try:
        os.fsync(directory_descriptor)
    except OSError:
        pass
    finally:
        os.close(directory_descriptor)


def _error_text(exc: BaseException) -> str:
    if isinstance(exc, PocError):
        return f"{exc.reason}: {exc.message}"
    text = str(exc).strip()
    return text or exc.__class__.__name__
