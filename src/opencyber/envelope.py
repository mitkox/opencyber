"""Uniform result envelope applied to every advertised tool.

Every tool result carries the same contract block: whether the call succeeded,
which contract revision produced it, what was and was not covered, the
limitations the caller must assume, whether the payload contains untrusted
target content, and an evidence digest that identifies exactly what was
returned.

The envelope is additive. Historical keys such as ``success`` (executable
tools) and ``status``/``reason`` (PoC refusals) stay exactly as they were, so a
0.3-era client keeps working while a newer client reads the contract fields.

This module is import-light: the doctor and the catalog recorder import it
without pulling in MCPServer or a tool module.
"""

from __future__ import annotations

import asyncio
import functools
import hashlib
import inspect
import json
from typing import Any, Callable

from . import __version__
from .contracts import CONTRACT_SCHEMA_VERSION, ToolContract
from .errors import OcError, translate


ENVELOPE_SCHEMA_VERSION = 1

#: Results larger than this report no evidence digest instead of hashing an
#: unbounded buffer. The reason is stated in the envelope rather than guessed.
MAX_EVIDENCE_BYTES = 4 * 1024 * 1024
EVIDENCE_PREFIX = "oc_ev_"

_COVERAGE_FIELDS = ("status", "examined", "total", "exhausted", "next_offset")
_COVERAGE_STATUSES = frozenset({"complete", "partial", "unknown", "empty"})


def canonical_json(value: Any) -> str:
    """Deterministic JSON used for digests and identity comparison."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def coverage(status: str = "complete", **fields: Any) -> dict[str, Any]:
    """Build a coverage declaration with every field present."""
    if status not in _COVERAGE_STATUSES:
        raise ValueError(f"unknown coverage status: {status}")
    declaration: dict[str, Any] = {field: None for field in _COVERAGE_FIELDS}
    declaration["status"] = status
    for field, value in fields.items():
        if field not in declaration:
            raise ValueError(f"unknown coverage field: {field}")
        declaration[field] = value
    return declaration


def _normalized_coverage(raw: Any, *, truncated: bool = False) -> dict[str, Any]:
    if isinstance(raw, dict):
        status = raw.get("status", "partial" if truncated else "complete")
        declaration = coverage(status)
        for field in _COVERAGE_FIELDS:
            if field in raw:
                declaration[field] = raw[field]
        return declaration
    return coverage("partial" if truncated else "complete")


def _provenance(contract: ToolContract, raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    return {
        "untrusted_content": contract.returns_target_content,
        "source": contract.provenance_source,
    }


def contract_block(contract: ToolContract) -> dict[str, Any]:
    return {
        "schema_version": ENVELOPE_SCHEMA_VERSION,
        "contract_schema_version": CONTRACT_SCHEMA_VERSION,
        "tool": contract.name,
        "server_version": __version__,
    }


def _evidence(payload: dict[str, Any]) -> dict[str, Any]:
    """Digest what the caller receives, excluding the evidence field itself."""
    material = {key: value for key, value in payload.items() if key != "evidence"}
    try:
        encoded = canonical_json(material).encode("utf-8")
    except (TypeError, ValueError):
        return {
            "id": None,
            "sha256": None,
            "bytes": None,
            "retained": False,
            "reason": "result_not_serializable",
        }
    if len(encoded) > MAX_EVIDENCE_BYTES:
        return {
            "id": None,
            "sha256": None,
            "bytes": len(encoded),
            "retained": False,
            "reason": "result_too_large",
        }
    digest = hashlib.sha256(encoded).hexdigest()
    return {
        "id": EVIDENCE_PREFIX + digest[:40],
        "sha256": digest,
        "bytes": len(encoded),
        "retained": False,
    }


def finalize(contract: ToolContract, result: Any, *, engagement_id: str | None = None) -> dict[str, Any]:
    """Return ``result`` with the contract envelope added and nothing removed."""
    payload: dict[str, Any] = dict(result) if isinstance(result, dict) else {"value": result}
    ok = payload.get("ok")
    if ok is None:
        ok = payload.get("success", True)
    if payload.get("error") is not None:
        ok = False
    payload["ok"] = bool(ok)
    payload["contract"] = contract_block(contract)
    declared_coverage = payload.get("coverage")
    if declared_coverage is None and not payload["ok"]:
        declared_coverage = coverage("unknown", exhausted=False)
    payload["coverage"] = _normalized_coverage(declared_coverage, truncated=bool(payload.get("truncated")))
    limitations = payload.get("limitations")
    payload["limitations"] = list(limitations) if isinstance(limitations, list) else []
    payload["provenance"] = _provenance(contract, payload.get("provenance"))
    payload.setdefault("continuation", None)
    payload["evidence"] = _evidence(payload)
    if engagement_id:
        payload["evidence"] = _retain(engagement_id, payload)
    return payload


def _retain(engagement_id: str, payload: dict[str, Any]) -> dict[str, Any]:
    """Attach retention state without ever failing the tool call.

    Retention is auxiliary: an unwritable workspace or an invalid
    ``OPENCYBER_RESULT_RETENTION`` value must not turn a successful tool call
    into a failure. The block says what happened instead.
    """
    from .result_store import retain

    try:
        return retain(engagement_id, payload)
    except Exception as error:  # noqa: BLE001 - retention must not break the result
        evidence = dict(payload.get("evidence") or {})
        evidence["retained"] = False
        evidence["retention_error"] = f"{type(error).__name__}: {error}"
        return evidence


def refusal(
    contract: ToolContract,
    error: OcError,
    *,
    coverage_declaration: dict[str, Any] | None = None,
    limitations: list[str] | None = None,
) -> dict[str, Any]:
    """Return a structured failure envelope instead of raising into the transport."""
    payload: dict[str, Any] = {
        "ok": False,
        "error": error.to_dict(),
        "contract": contract_block(contract),
        "coverage": coverage_declaration or coverage("unknown"),
        "limitations": limitations if limitations is not None else ["The tool did not run."],
        "provenance": {
            "untrusted_content": contract.returns_target_content,
            "source": contract.provenance_source,
        },
        "continuation": None,
    }
    payload["evidence"] = _evidence(payload)
    return payload


def _engagement_id(handler: Callable[..., Any], args: tuple[Any, ...], kwargs: dict[str, Any]) -> str | None:
    """Find the engagement a call names, so its result can be retained there."""
    try:
        bound = inspect.signature(handler).bind_partial(*args, **kwargs)
    except TypeError:
        return None
    value = bound.arguments.get("engagement_id")
    return value if isinstance(value, str) and value else None


def wrap(contract: ToolContract, handler: Callable[..., Any]) -> Callable[..., Any]:
    """Wrap a handler so its result and its failures both carry the envelope.

    Sync handlers keep a sync wrapper and async handlers keep an async wrapper,
    so MCPServer's ``is_async`` row and the generated input schema are unchanged.
    Cancellation is re-raised: a cancelled request is not a failed tool.
    """
    if inspect.iscoroutinefunction(handler):

        @functools.wraps(handler)
        async def async_wrapper(*args: Any, **kwargs: Any) -> dict[str, Any]:
            try:
                result = await handler(*args, **kwargs)
            except OcError as error:
                return refusal(contract, error)
            except asyncio.CancelledError:
                raise
            except Exception as error:  # noqa: BLE001 - every failure must reach the caller typed
                return refusal(contract, translate(error))
            return await asyncio.to_thread(
                finalize, contract, result, engagement_id=_engagement_id(handler, args, kwargs)
            )

        return async_wrapper

    @functools.wraps(handler)
    def sync_wrapper(*args: Any, **kwargs: Any) -> dict[str, Any]:
        try:
            result = handler(*args, **kwargs)
        except OcError as error:
            return refusal(contract, error)
        except asyncio.CancelledError:
            raise
        except Exception as error:  # noqa: BLE001 - every failure must reach the caller typed
            return refusal(contract, translate(error))
        return finalize(contract, result, engagement_id=_engagement_id(handler, args, kwargs))

    return sync_wrapper
