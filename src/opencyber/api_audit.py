"""Deterministic, evidence-backed API security assessment helpers."""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import json
import time
from typing import Any
from urllib.parse import urljoin
import uuid

from . import envelope
from .audit import safe_record
from .engagements import resolve_engagement_path
from .errors import OcError
from .http_client import bounded_response, redirect_scope_hooks, request_errors, resolve_timeout
from .limits import facts
from .policy import enforce_url_scope
from .workspace import write_workspace_file


HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head"}
SENSITIVE_NAMES = {"admin", "api_key", "apikey", "authorization", "password", "role", "secret", "token"}


def _load_json(engagement_id: str, source: str, timeout: float | None = None) -> tuple[dict[str, Any], str]:
    if source.startswith(("http://", "https://")):
        enforce_url_scope(engagement_id, source, tool="oc_openapi_audit")
        import requests

        hooks = redirect_scope_hooks(engagement_id, tool="oc_openapi_audit")
        hooks.setdefault("response", []).append(bounded_response)
        with request_errors():
            response = requests.get(
                source,
                timeout=resolve_timeout(timeout),
                hooks=hooks,
                stream=True,
            )
            truncated = getattr(response, "_opencyber_body_truncated", False) is True
            response.raise_for_status()
            if truncated:
                raise OcError(
                    "truncated",
                    "the API document exceeded http.response_max_bytes and is unusable",
                )
            document = response.json()
            origin = response.url
        safe_record(
            engagement_id,
            {
                "event": "api.fetch",
                "url": origin,
                "status": response.status_code,
                "response_bytes": len(response.content),
            },
        )
    else:
        path = resolve_engagement_path(engagement_id, source)
        document = json.loads(path.read_text(encoding="utf-8"))
        origin = str(path)
    if not isinstance(document, dict):
        raise ValueError("API document must be a JSON object")
    return document, origin


def _persist(engagement_id: str, kind: str, result: dict[str, Any]) -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = f"evidence/api/{kind}-{stamp}-{uuid.uuid4().hex[:8]}.json"
    write_workspace_file(engagement_id, path, json.dumps(result, indent=2, sort_keys=True) + "\n")
    return path


def _schema_property_names(value: Any) -> set[str]:
    names: set[str] = set()
    if isinstance(value, dict):
        properties = value.get("properties")
        if isinstance(properties, dict):
            names.update(str(name) for name in properties)
        for child in value.values():
            names.update(_schema_property_names(child))
    elif isinstance(value, list):
        for child in value:
            names.update(_schema_property_names(child))
    return names


def audit_openapi(engagement_id: str, source: str, timeout: float | None = None) -> dict[str, Any]:
    document, origin = _load_json(engagement_id, source, timeout=timeout)
    paths = document.get("paths", {})
    if not isinstance(paths, dict):
        raise ValueError("OpenAPI paths must be an object")
    components = document.get("components", {})
    schemes = components.get("securitySchemes", {}) if isinstance(components, dict) else {}
    global_security = document.get("security")
    operations = []
    review_items: list[dict[str, Any]] = []
    for route, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        shared_parameters = path_item.get("parameters", [])
        for method, operation in path_item.items():
            if method.lower() not in HTTP_METHODS or not isinstance(operation, dict):
                continue
            effective_security = operation.get("security", global_security)
            parameters = [
                item for item in [*shared_parameters, *operation.get("parameters", [])]
                if isinstance(item, dict)
            ]
            parameter_names = {str(item.get("name", "")) for item in parameters}
            placeholders = {
                segment[1:-1]
                for segment in str(route).split("/")
                if segment.startswith("{") and segment.endswith("}")
            }
            missing_path_parameters = sorted(placeholders - parameter_names)
            sensitive_fields = sorted(
                name
                for name in parameter_names | _schema_property_names(operation.get("requestBody", {}))
                if name.lower() in SENSITIVE_NAMES
            )
            entry = {
                "method": method.upper(),
                "path": route,
                "operation_id": operation.get("operationId"),
                "security": effective_security,
                "parameter_names": sorted(name for name in parameter_names if name),
                "sensitive_fields": sensitive_fields,
                "missing_path_parameters": missing_path_parameters,
            }
            operations.append(entry)
            if effective_security in (None, []):
                review_items.append(
                    {
                        "code": "operation_without_declared_security",
                        "operation": f"{method.upper()} {route}",
                        "evidence": "No global or operation-level OpenAPI security requirement is declared.",
                        "classification": "review",
                    }
                )
            if missing_path_parameters:
                review_items.append(
                    {
                        "code": "undefined_path_parameter",
                        "operation": f"{method.upper()} {route}",
                        "evidence": missing_path_parameters,
                        "classification": "schema-quality",
                    }
                )
    insecure_servers = [
        server.get("url")
        for server in document.get("servers", [])
        if isinstance(server, dict) and str(server.get("url", "")).startswith("http://")
    ]
    if insecure_servers:
        review_items.append(
            {
                "code": "plaintext_server_url",
                "evidence": insecure_servers,
                "classification": "review",
            }
        )
    result = {
        "engagement_id": engagement_id,
        "source": origin,
        "title": document.get("info", {}).get("title") if isinstance(document.get("info"), dict) else None,
        "version": document.get("info", {}).get("version") if isinstance(document.get("info"), dict) else None,
        "security_schemes": schemes,
        "operation_count": len(operations),
        "operations": operations,
        "review_items": review_items,
        "finding_policy": "Review items are evidence-backed leads, not validated vulnerabilities.",
    }
    result["artifact_path"] = _persist(engagement_id, "openapi-audit", result)
    return result


def audit_graphql(
    engagement_id: str,
    url: str,
    headers: dict[str, str] | None = None,
    timeout: float | None = None,
) -> dict[str, Any]:
    enforce_url_scope(engagement_id, url, tool="oc_graphql_audit")
    import requests

    query = """
    query OpenCyberIntrospection {
      __schema {
        queryType { name }
        mutationType { name }
        types { name kind fields { name args { name } } }
      }
    }
    """
    hooks = redirect_scope_hooks(engagement_id, tool="oc_graphql_audit")
    hooks.setdefault("response", []).append(bounded_response)
    with request_errors():
        response = requests.post(
            url,
            headers={"content-type": "application/json", **(headers or {})},
            json={"query": query},
            timeout=resolve_timeout(timeout),
            hooks=hooks,
            stream=True,
        )
        truncated = getattr(response, "_opencyber_body_truncated", False) is True
        if truncated:
            raise OcError(
                "truncated",
                "the GraphQL introspection response exceeded http.response_max_bytes and is unusable",
            )
        try:
            payload: Any = response.json()
        except ValueError:
            payload = response.text
    schema = payload.get("data", {}).get("__schema") if isinstance(payload, dict) else None
    types = schema.get("types", []) if isinstance(schema, dict) else []
    type_map = {item.get("name"): item for item in types if isinstance(item, dict)}
    query_name = schema.get("queryType", {}).get("name") if isinstance(schema, dict) else None
    mutation_name = schema.get("mutationType", {}).get("name") if isinstance(schema, dict) else None
    query_fields = (type_map.get(query_name) or {}).get("fields", []) if query_name else []
    mutation_fields = (type_map.get(mutation_name) or {}).get("fields", []) if mutation_name else []
    review_items: list[dict[str, Any]] = []
    if schema:
        review_items.append(
            {
                "code": "graphql_introspection_enabled",
                "evidence": "The endpoint returned __schema data.",
                "classification": "review",
            }
        )
    result = {
        "engagement_id": engagement_id,
        "url": url,
        "status": response.status_code,
        "response_headers": dict(response.headers),
        "introspection_available": bool(schema),
        "query_type": query_name,
        "mutation_type": mutation_name,
        "query_fields": query_fields,
        "mutation_fields": mutation_fields,
        "type_count": len(types),
        "review_items": review_items,
        "raw_response": payload,
        "finding_policy": "Review items are evidence-backed leads, not validated vulnerabilities.",
    }
    result["artifact_path"] = _persist(engagement_id, "graphql-audit", result)
    safe_record(
        engagement_id,
        {
            "event": "api.graphql_audit",
            "url": url,
            "status": response.status_code,
            "introspection_available": bool(schema),
            "response_bytes": len(response.content),
        },
    )
    return result


def _decode_jwt_part(value: str) -> Any:
    padded = value + "=" * (-len(value) % 4)
    return json.loads(base64.urlsafe_b64decode(padded.encode("ascii")).decode("utf-8"))


def audit_jwt(engagement_id: str, token: str, expected_issuer: str = "", expected_audience: str = "") -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("JWT must contain header, payload, and signature segments")
    header = _decode_jwt_part(parts[0])
    payload = _decode_jwt_part(parts[1])
    now = int(time.time())
    review_items: list[dict[str, Any]] = []
    algorithm = str(header.get("alg", ""))
    if algorithm.lower() == "none":
        review_items.append({"code": "jwt_alg_none", "evidence": algorithm, "classification": "high-confidence"})
    if "exp" not in payload:
        review_items.append({"code": "jwt_missing_exp", "evidence": "No exp claim", "classification": "review"})
    elif isinstance(payload["exp"], (int, float)) and payload["exp"] < now:
        review_items.append({"code": "jwt_expired", "evidence": payload["exp"], "classification": "informational"})
    if isinstance(payload.get("nbf"), (int, float)) and payload["nbf"] > now:
        review_items.append({"code": "jwt_not_yet_valid", "evidence": payload["nbf"], "classification": "informational"})
    if expected_issuer and payload.get("iss") != expected_issuer:
        review_items.append({"code": "jwt_issuer_mismatch", "evidence": payload.get("iss"), "classification": "review"})
    audience = payload.get("aud")
    if expected_audience and expected_audience not in ([audience] if isinstance(audience, str) else audience or []):
        review_items.append({"code": "jwt_audience_mismatch", "evidence": audience, "classification": "review"})
    result = {
        "engagement_id": engagement_id,
        "header": header,
        "payload": payload,
        "signature_base64url": parts[2],
        "verified": False,
        "review_items": review_items,
        "warning": "Claims were audited but the signature was not cryptographically verified.",
        "coverage": envelope.coverage("complete", exhausted=True),
        "limitations": [
            "The signature was not cryptographically verified: every claim is decoded but unauthenticated, "
            "so a forged token produces the same audit as a genuine one.",
            "Expiry, not-before, issuer, and audience checks use this host's clock and the caller's expected "
            "values; they do not establish that the issuer made the claims.",
        ],
    }
    result["artifact_path"] = _persist(engagement_id, "jwt-audit", result)
    return result


def fuzz_api_parameter(
    engagement_id: str,
    base_url: str,
    path: str,
    method: str,
    location: str,
    parameter: str,
    payloads: list[str],
    max_requests: int,
    headers: dict[str, str] | None = None,
    base_body: str = "",
    follow_redirects: bool = True,
    timeout: float | None = None,
    cancel_event: Any = None,
) -> dict[str, Any]:
    import requests

    if max_requests < 1 or len(payloads) > max_requests:
        raise ValueError("payload count exceeds caller-selected max_requests")
    normalized_location = location.lower()
    if normalized_location not in {"query", "header", "body", "path", "json"}:
        raise ValueError("location must be query, header, body, path, or json")
    results = []
    for payload in payloads:
        if cancel_event is not None and cancel_event.is_set():
            break
        url = urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))
        request_headers = dict(headers or {})
        params = None
        body: Any = base_body or None
        json_body = None
        if normalized_location == "query":
            params = {parameter: payload}
        elif normalized_location == "header":
            request_headers[parameter] = payload
        elif normalized_location == "body":
            body = base_body.replace("{{FUZZ}}", payload) if "{{FUZZ}}" in base_body else payload
        elif normalized_location == "path":
            if "{{FUZZ}}" not in url:
                raise ValueError("path fuzzing requires {{FUZZ}} in path")
            url = url.replace("{{FUZZ}}", payload)
        else:
            json_body = json.loads(base_body) if base_body else {}
            if not isinstance(json_body, dict):
                raise ValueError("JSON fuzzing requires an object base_body")
            json_body[parameter] = payload
        enforce_url_scope(engagement_id, url, tool="oc_api_fuzz")
        started = time.monotonic()
        hooks = redirect_scope_hooks(
            engagement_id, tool="oc_api_fuzz", follow_redirects=follow_redirects
        )
        hooks.setdefault("response", []).append(bounded_response)
        with request_errors():
            response = requests.request(
                method.upper(),
                url,
                headers=request_headers,
                params=params,
                data=body,
                json=json_body,
                allow_redirects=follow_redirects,
                timeout=resolve_timeout(timeout),
                hooks=hooks,
                stream=True,
            )
        truncated = getattr(response, "_opencyber_body_truncated", False) is True
        safe_record(
            engagement_id,
            {
                "event": "api.fuzz_request",
                "url": response.request.url,
                "method": response.request.method,
                "parameter": parameter,
                "payload": payload,
                "status": response.status_code,
                "response_bytes": len(response.content),
            },
        )
        results.append(
            {
                "payload": payload,
                "request_url": response.request.url,
                "request_method": response.request.method,
                "status": response.status_code,
                "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
                "headers": dict(response.headers),
                **(
                    {
                        "truncated": True,
                        "coverage": envelope.coverage("partial", exhausted=False),
                        "limitations": [
                            "The response body exceeded http.response_max_bytes; only its prefix is retained."
                        ],
                        "limit": facts("http.response_max_bytes"),
                    }
                    if truncated
                    else {}
                ),
                "body": response.text,
            }
        )
    result = {
        "engagement_id": engagement_id,
        "base_url": base_url,
        "path": path,
        "method": method.upper(),
        "location": normalized_location,
        "parameter": parameter,
        "request_count": len(results),
        "cancelled": bool(cancel_event is not None and cancel_event.is_set()),
        "results": results,
        "finding_policy": "Responses are evidence; the caller must validate security impact.",
    }
    result["artifact_path"] = _persist(engagement_id, "api-fuzz", result)
    return result
