"""OpenCyber-native network, token and data-analysis tools."""

from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import re
from typing import Any, Callable
from urllib.parse import quote, quote_plus

from . import __version__
from .assets import local_cve_db, require_online
from .engagements import resolve_engagement_path
from .http_client import redirect_scope_hooks, resolve_timeout
from .indicators import extract_indicators as _extract_indicators
from .policy import enforce_url_scope


def process_snapshot(include_connections: bool = True) -> dict[str, Any]:
    import psutil

    processes = []
    for process in psutil.process_iter(["pid", "ppid", "name", "username", "cmdline", "status"]):
        try:
            processes.append(process.info)
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            continue
    connections = []
    if include_connections:
        for connection in psutil.net_connections(kind="inet"):
            connections.append(
                {
                    "fd": connection.fd,
                    "family": str(connection.family),
                    "type": str(connection.type),
                    "local": list(connection.laddr) if connection.laddr else None,
                    "remote": list(connection.raddr) if connection.raddr else None,
                    "status": connection.status,
                    "pid": connection.pid,
                }
            )
    return {"processes": processes, "connections": connections}


def analyze_binary_with_angr(engagement_id: str, path: str, auto_load_libs: bool = False) -> dict[str, Any]:
    import angr

    target = resolve_engagement_path(engagement_id, path)
    project = angr.Project(str(target), auto_load_libs=auto_load_libs)
    main = project.loader.main_object
    return {
        "path": str(target),
        "engagement_id": engagement_id,
        "architecture": project.arch.name,
        "bits": project.arch.bits,
        "entry": project.entry,
        "binary_format": type(main).__name__,
        "min_addr": main.min_addr,
        "max_addr": main.max_addr,
        "sections": [section.name for section in main.sections],
        "auto_load_libs": auto_load_libs,
    }


def http_request(
    method: str,
    url: str,
    headers: dict[str, str] | None = None,
    body: str | None = None,
    follow_redirects: bool = True,
    timeout: float | None = None,
    engagement_id: str | None = None,
) -> dict[str, Any]:
    scope = enforce_url_scope(engagement_id, url, tool="oc_http_request")
    import requests

    response = requests.request(
        method=method.upper(),
        url=url,
        headers=headers or {},
        data=body,
        allow_redirects=follow_redirects,
        timeout=resolve_timeout(timeout),
        hooks=redirect_scope_hooks(engagement_id, tool="oc_http_request", follow_redirects=follow_redirects),
    )
    return {
        "status": response.status_code,
        "url": response.url,
        "headers": dict(response.headers),
        "body": response.text,
        "scope_enforced": bool(scope["enforced"]),
        "requested_url": url,
    }


def graphql_request(
    url: str,
    query: str,
    variables: dict[str, Any] | None = None,
    headers: dict[str, str] | None = None,
    timeout: float | None = None,
    engagement_id: str | None = None,
) -> dict[str, Any]:
    scope = enforce_url_scope(engagement_id, url, tool="oc_graphql_request")
    import requests

    merged_headers = {"content-type": "application/json", **(headers or {})}
    response = requests.post(
        url,
        headers=merged_headers,
        json={"query": query, "variables": variables or {}},
        timeout=resolve_timeout(timeout),
        hooks=redirect_scope_hooks(engagement_id, tool="oc_graphql_request"),
    )
    try:
        payload: Any = response.json()
    except ValueError:
        payload = response.text
    return {
        "status": response.status_code,
        "url": response.url,
        "headers": dict(response.headers),
        "response": payload,
        "scope_enforced": bool(scope["enforced"]),
        "requested_url": url,
    }


def decode_jwt(token: str) -> dict[str, Any]:
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("JWT must contain header, payload, and signature segments")

    def decode_part(value: str) -> Any:
        padded = value + "=" * (-len(value) % 4)
        decoded = base64.urlsafe_b64decode(padded.encode("ascii"))
        return json.loads(decoded.decode("utf-8"))

    return {
        "header": decode_part(parts[0]),
        "payload": decode_part(parts[1]),
        "signature_base64url": parts[2],
        "verified": False,
        "warning": "The token was decoded but its signature was not verified.",
    }


def inspect_openapi(engagement_id: str, source: str, timeout: float | None = None) -> dict[str, Any]:
    if source.startswith(("http://", "https://")):
        enforce_url_scope(engagement_id, source, tool="oc_openapi_inspect")
        import requests

        response = requests.get(source, timeout=resolve_timeout(timeout),
                                hooks=redirect_scope_hooks(engagement_id, tool="oc_openapi_inspect"))
        response.raise_for_status()
        document = response.json()
        origin = response.url
    else:
        path = resolve_engagement_path(engagement_id, source)
        document = json.loads(Path(path).read_text(encoding="utf-8"))
        origin = str(path)
    paths = document.get("paths", {}) if isinstance(document, dict) else {}
    operations = []
    for route, path_item in paths.items():
        if not isinstance(path_item, dict):
            continue
        for method, operation in path_item.items():
            if method.lower() in {"get", "post", "put", "patch", "delete", "options", "head"}:
                operations.append(
                    {
                        "method": method.upper(),
                        "path": route,
                        "operation_id": operation.get("operationId") if isinstance(operation, dict) else None,
                    }
                )
    return {
        "source": origin,
        "engagement_id": engagement_id,
        "title": document.get("info", {}).get("title") if isinstance(document, dict) else None,
        "version": document.get("info", {}).get("version") if isinstance(document, dict) else None,
        "operation_count": len(operations),
        "operations": operations,
    }


def hibp_password_range(password: str, timeout: float | None = None) -> dict[str, Any]:
    require_online("oc_hibp_password_check")
    import requests

    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix, suffix = digest[:5], digest[5:]
    response = requests.get(
        f"https://api.pwnedpasswords.com/range/{prefix}",
        headers={"Add-Padding": "true", "User-Agent": f"opencyber/{__version__}"},
        timeout=resolve_timeout(timeout),
    )
    response.raise_for_status()
    count = 0
    for line in response.text.splitlines():
        candidate, raw_count = line.split(":", 1)
        if candidate == suffix:
            count = int(raw_count)
            break
    return {
        "sha1_prefix": prefix,
        "found": count > 0,
        "count": count,
        "privacy": "Only the first five SHA-1 characters were sent to the range API.",
    }


def _local_cve_lookup(cve_id: str) -> dict[str, Any] | None:
    """Read a build-time CVE index without touching the network."""
    path = local_cve_db()
    if not path.is_file() or path.is_symlink():
        return None
    import sqlite3

    connection = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    try:
        row = connection.execute(
            "SELECT cve_id, description, cvss, published, json FROM cves WHERE cve_id = ?",
            (cve_id,),
        ).fetchone()
    except sqlite3.DatabaseError as exc:
        raise ValueError(f"local CVE database is unreadable: {exc}") from exc
    finally:
        connection.close()
    if row is None:
        return {
            "source": "local-sqlite",
            "cve_id": cve_id,
            "found": False,
            "records": [],
        }
    return {
        "source": "local-sqlite",
        "cve_id": cve_id,
        "found": True,
        "description": row[1],
        "cvss": row[2],
        "published": row[3],
        "response": json.loads(row[4]) if row[4] else None,
    }


def lookup_cve(cve_id: str, timeout: float | None = None) -> dict[str, Any]:
    normalized = cve_id.strip().upper()
    if not re.fullmatch(r"CVE-\d{4}-\d{4,}", normalized):
        raise ValueError("cve_id must look like CVE-2026-1234")
    local = _local_cve_lookup(normalized)
    if local is not None:
        return local
    require_online("oc_cve_lookup")
    import requests

    response = requests.get(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"cveId": normalized},
        headers={"User-Agent": f"opencyber/{__version__}"},
        timeout=resolve_timeout(timeout),
    )
    response.raise_for_status()
    return {"source": "NVD", "cve_id": normalized, "response": response.json()}


def hash_workspace_file(engagement_id: str, path: str, algorithms: list[str] | None = None) -> dict[str, Any]:
    target = resolve_engagement_path(engagement_id, path)
    requested = algorithms or ["md5", "sha1", "sha256", "sha512"]
    hashers = {}
    for algorithm in requested:
        try:
            hashers[algorithm] = hashlib.new(algorithm)
        except ValueError as exc:
            raise ValueError(f"unsupported hash algorithm: {algorithm}") from exc
    with Path(target).open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            for hasher in hashers.values():
                hasher.update(chunk)
    return {
        "path": str(target),
        "engagement_id": engagement_id,
        "size": Path(target).stat().st_size,
        "hashes": {name: hasher.hexdigest() for name, hasher in hashers.items()},
    }


def encode_payload(data: str, encoding: str) -> dict[str, str]:
    normalized = encoding.strip().lower()
    encoders: dict[str, Callable[[str], str]] = {
        "base64": lambda value: base64.b64encode(value.encode("utf-8")).decode("ascii"),
        "base64url": lambda value: base64.urlsafe_b64encode(value.encode("utf-8")).decode("ascii"),
        "hex": lambda value: value.encode("utf-8").hex(),
        "url": quote,
        "form": quote_plus,
    }
    if normalized not in encoders:
        raise ValueError(f"unknown encoding: {encoding}; choose from {sorted(encoders)}")
    return {"encoding": normalized, "encoded": encoders[normalized](data)}


def extract_indicators(text: str) -> dict[str, list[str]]:
    return _extract_indicators(text)


def technology_hints(headers: dict[str, str] | None = None, body: str = "") -> dict[str, Any]:
    normalized_headers = {key.lower(): value for key, value in (headers or {}).items()}
    haystack = "\n".join([*(f"{key}: {value}" for key, value in normalized_headers.items()), body]).lower()
    signatures = {
        "nginx": ["nginx"],
        "apache": ["apache"],
        "iis": ["microsoft-iis", "asp.net"],
        "wordpress": ["wp-content", "wp-includes"],
        "drupal": ["drupal-settings-json", "sites/default/files"],
        "react": ["__next_data__", "data-reactroot", "react"],
        "nextjs": ["__next_data__", "/_next/"],
        "vue": ["data-v-", "__vue__"],
        "cloudflare": ["cf-ray", "cloudflare"],
    }
    detected = [name for name, needles in signatures.items() if any(needle in haystack for needle in needles)]
    return {"detected": sorted(detected), "evidence_source": "provided headers and body only"}
