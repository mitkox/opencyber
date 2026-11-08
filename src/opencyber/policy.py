"""Optional engagement scope enforcement.

The default harness behavior is unchanged: the engagement target list is
metadata, and the operator's MCP client is the policy point. Production
deployments that need a guardrail can set::

    OPENCYBER_ENFORCE_SCOPE=1

Then every executable-backed call is inspected for URL, IP, CIDR, and hostname
tokens. Tokens that do not match an engagement target are refused before the
process starts. ``oc_bash`` and ``oc_python`` are refused under enforcement
unless ``OPENCYBER_ALLOW_UNSCOPED_EXECUTION=1``, because arbitrary code cannot
be scope-checked.

This is deliberately conservative, not a firewall. It raises the cost of an
accidental out-of-scope command; it does not replace network egress controls.
"""

from __future__ import annotations

from ipaddress import ip_address, ip_network
import os
import re
from typing import Any, Iterable

from .errors import OcError
from urllib.parse import urlparse, urlsplit

from .assets import OFFLINE_NETWORK_EXECUTABLES, offline_enabled
from .engagements import get_engagement


TRUTHY = {"1", "true", "yes", "on"}
SCOPE_ENV = "OPENCYBER_ENFORCE_SCOPE"
UNSCOPED_ENV = "OPENCYBER_ALLOW_UNSCOPED_EXECUTION"
OFFLINE_NETWORK_ALLOW_ENV = "OPENCYBER_OFFLINE_ALLOW_NETWORK_TOOLS"
UNSCOPED_EXECUTABLES = frozenset({"bash", "python3", "python"})

# Offline-blocked executables live in assets.OFFLINE_NETWORK_EXECUTABLES:
# Amass, recon-ng, spiderfoot, and wafw00f are intentionally absent because they
# have local modes that are useful against internal networks.

_FILE_EXTENSIONS = frozenset(
    {
        "txt", "json", "yaml", "yml", "xml", "csv", "tsv", "log", "md", "html",
        "htm", "js", "css", "php", "asp", "aspx", "jsp", "sh", "py", "pl", "rb",
        "go", "rs", "c", "h", "cpp", "nse", "lua", "conf", "config", "ini",
        "db", "sqlite", "sqlite3", "bin", "elf", "exe", "dll", "so", "img",
        "iso", "tar", "gz", "tgz", "bz2", "xz", "zip", "7z", "pcap", "pcapng",
        "cap", "der", "pem", "crt", "key", "pub", "lst", "dict", "rules",
        "service", "proto", "war", "jar", "apk", "dex", "o", "a", "ko",
    }
)

_URL = re.compile(r"(?i)\bhttps?://[^\s'\"<>]+")
_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?(?![\w.])")
_HOSTNAME = re.compile(
    r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}",
    re.IGNORECASE,
)
_TRAILING = ",;:)]}'\""


def enforcement_enabled() -> bool:
    return os.environ.get(SCOPE_ENV, "").strip().lower() in TRUTHY


def unscoped_execution_allowed() -> bool:
    return os.environ.get(UNSCOPED_ENV, "").strip().lower() in TRUTHY


_AMBIGUOUS_AUTHORITY = re.compile(r"[\\\s\x00-\x1f\x7f@]")


def canonical_http_url(url: str) -> str:
    """Validate one HTTP target so the parsed authority is the sent authority.

    ``requests`` re-quotes a URL before sending it, so a raw backslash or
    userinfo authority can be parsed as one host for scope checks and sent to
    another. Those forms, plus control characters, whitespace and encoded
    separators in the authority, are refused here before any caller makes a
    scope or credential decision.
    """
    if not isinstance(url, str) or not url:
        raise OcError("invalid_argument", "URL must be a non-empty string")
    try:
        parts = urlsplit(url)
        parsed_port = parts.port
    except ValueError as exc:
        raise OcError("invalid_argument", f"invalid URL: {exc}") from exc
    if parts.scheme.lower() not in {"http", "https"}:
        raise OcError("invalid_argument", "URL must use http or https")
    if not parts.netloc:
        raise OcError("invalid_argument", "URL must include an authority")
    if _AMBIGUOUS_AUTHORITY.search(parts.netloc) or "%" in parts.netloc:
        raise OcError(
            "invalid_argument",
            "URL authority is ambiguous: backslash, userinfo, whitespace, control "
            "characters and encoded separators are refused",
        )
    if not parts.hostname:
        raise OcError("invalid_argument", "URL must include a host")
    if parsed_port is not None and not (0 < parsed_port < 65536):
        raise OcError("invalid_argument", "URL port is out of range")
    return url


def credential_boundary_changed(current_url: str, next_url: str) -> bool:
    """Return True when a hop must drop authorization and cookies.

    Credentials are kept only while the effective host stays the same and the
    scheme does not downgrade. A same-host HTTP-to-HTTPS upgrade therefore keeps
    them, matching the documented redirect rule.
    """
    current = urlsplit(canonical_http_url(current_url))
    following = urlsplit(canonical_http_url(next_url))
    if (current.hostname or "").lower() != (following.hostname or "").lower():
        return True
    return current.scheme.lower() == "https" and following.scheme.lower() == "http"


def _normalize_host(value: str) -> str | None:
    if not isinstance(value, str):
        return None
    text = value.strip().strip(_TRAILING).strip("[]").lower().rstrip(".")
    if not text:
        return None
    if "://" in text:
        parsed = urlparse(text)
        text = (parsed.hostname or "").lower().rstrip(".")
    if text.startswith("*."):
        text = text[2:]
    if "@" in text:
        text = text.rsplit("@", 1)[1]
    if text.startswith("[") and "]" in text:
        text = text[1 : text.index("]")]
    elif text.count(":") == 1:
        host, port = text.rsplit(":", 1)
        if port.isdigit():
            text = host
    return text or None


def _target_host(target: str) -> str | None:
    if not isinstance(target, str):
        return None
    return _normalize_host(target)


def _is_ip(value: str) -> bool:
    try:
        ip_address(value)
        return True
    except ValueError:
        return False


def target_matches(host: str, target: str) -> bool:
    """Return True when ``host`` is inside the declared ``target``."""
    normalized_host = _normalize_host(host)
    normalized_target = _normalize_host(target)
    if not normalized_host or not normalized_target:
        return False
    if normalized_target == "*":
        return True

    # CIDR target: only IP hosts can match.
    if "/" in normalized_target:
        try:
            network = ip_network(normalized_target, strict=False)
        except ValueError:
            return False
        try:
            return ip_address(normalized_host) in network
        except ValueError:
            return False

    target_is_ip = _is_ip(normalized_target)
    host_is_ip = _is_ip(normalized_host)
    if target_is_ip or host_is_ip:
        return target_is_ip and host_is_ip and normalized_host == normalized_target

    # Bare domain targets include their subdomains. This matches how scopes are
    # usually written: "example.com and anything under it".
    return normalized_host == normalized_target or normalized_host.endswith(
        "." + normalized_target
    )


def _valid_hostname(token: str) -> bool:
    if not _HOSTNAME.fullmatch(token):
        return False
    labels = token.lower().split(".")
    if any(label in {"", "localhost"} for label in labels):
        return token.lower() == "localhost"
    if labels[-1] in _FILE_EXTENSIONS:
        return False
    if token.lower().startswith(("http-", "https-", "dns-", "ssl-")):
        return False
    return True


def extract_candidates(arguments: Iterable[str]) -> list[str]:
    """Extract plausible network targets from argv tokens.

    The extraction is intentionally narrow: URLs, IPv4/CIDR, and dotted
    hostnames that are not known file extensions. Anything else is left to the
    operator's network controls.
    """
    candidates: list[str] = []
    seen: set[str] = set()

    def add(value: str) -> None:
        cleaned = value.strip().strip(_TRAILING).strip("[]")
        if not cleaned or cleaned in seen:
            return
        host = _normalize_host(cleaned)
        if not host:
            return
        if "/" in cleaned and "://" not in cleaned:
            try:
                ip_network(cleaned, strict=False)
            except ValueError:
                return
        elif not (_is_ip(host) or _valid_hostname(host)):
            return
        seen.add(cleaned)
        candidates.append(cleaned)

    for raw in arguments:
        if not isinstance(raw, str):
            continue
        for match in _URL.findall(raw):
            add(match)
        for match in _IPV4.findall(raw):
            add(match)
        # A token that is itself a dotted hostname (with an optional :port).
        stripped = raw.strip().strip(_TRAILING)
        if stripped and not stripped.startswith("-") and "=" not in stripped:
            host = _normalize_host(stripped)
            if host and _valid_hostname(host):
                add(stripped)
    return candidates


def scope_check(engagement_id: str, value: str) -> dict[str, Any]:
    engagement = get_engagement(engagement_id)
    targets = [str(target) for target in engagement.get("targets", [])]
    host = _normalize_host(value)
    matched = None
    if host:
        matched = next((target for target in targets if target_matches(host, target)), None)
    return {
        "engagement_id": engagement_id,
        "value": value,
        "host": host,
        "allowed": matched is not None,
        "matched_target": matched,
        "targets": targets,
    }


def offline_network_decision(executable: str) -> dict[str, Any]:
    """Refuse well-known internet-only executables when the harness is airgapped."""
    blocked = (
        offline_enabled()
        and executable in OFFLINE_NETWORK_EXECUTABLES
        and os.environ.get(OFFLINE_NETWORK_ALLOW_ENV, "").strip().lower() not in TRUTHY
    )
    return {
        "offline": offline_enabled(),
        "executable": executable,
        "blocked": blocked,
        "reason": (
            f"{executable} requires internet access and OPENCYBER_OFFLINE=1 is set; "
            f"set {OFFLINE_NETWORK_ALLOW_ENV}=1 only if the target network provides "
            "the required services"
        )
        if blocked
        else None,
    }


def enforcement_decision(
    engagement_id: str,
    executable: str,
    arguments: Iterable[str],
) -> dict[str, Any]:
    """Check one call without raising. Used by tests and oc_scope_check."""
    arguments = list(arguments)
    candidates = extract_candidates(arguments)
    denied = [candidate for candidate in candidates if not scope_check(engagement_id, candidate)["allowed"]]
    unscoped = executable in UNSCOPED_EXECUTABLES
    allowed = not denied and (not unscoped or unscoped_execution_allowed())
    reason = None
    if unscoped and not unscoped_execution_allowed():
        reason = (
            f"{executable} executes arbitrary code and cannot be scope-checked; "
            f"set {UNSCOPED_ENV}=1 to allow it under enforcement"
        )
    elif denied:
        reason = "out-of-scope network target(s): " + ", ".join(sorted(set(denied)))
    return {
        "engagement_id": engagement_id,
        "executable": executable,
        "enforced": enforcement_enabled(),
        "allowed": allowed,
        "candidates": candidates,
        "denied": sorted(set(denied)),
        "unscoped_executable": unscoped,
        "reason": reason,
    }


def url_scope_decision(engagement_id: str | None, url: str) -> dict[str, Any]:
    """Check one native HTTP target without raising.

    Native tools do not scrape argv, so they cross the same boundary through
    this decision instead. When enforcement is off the call is allowed and the
    decision says so, which the result echoes as ``scope_enforced: false``.
    """
    canonical_http_url(url)
    host = _normalize_host(url)
    if not enforcement_enabled():
        return {
            "enforced": False,
            "allowed": True,
            "url": url,
            "host": host,
            "matched_target": None,
            "targets": [],
            "reason": None,
        }
    if not engagement_id:
        return {
            "enforced": True,
            "allowed": False,
            "url": url,
            "host": host,
            "matched_target": None,
            "targets": [],
            "reason": "engagement_required",
        }
    check = scope_check(engagement_id, url)
    allowed = bool(check["allowed"])
    return {
        "enforced": True,
        "allowed": allowed,
        "url": url,
        "host": check["host"],
        "matched_target": check["matched_target"],
        "targets": check["targets"],
        "reason": None if allowed else f"out-of-scope network target: {check['host'] or url}",
    }


def enforce_url_scope(engagement_id: str | None, url: str, *, tool: str) -> dict[str, Any]:
    """Raise the typed refusal when a native HTTP target is out of scope."""
    decision = url_scope_decision(engagement_id, url)
    if decision["enforced"] and not decision["allowed"]:
        if decision["reason"] == "engagement_required":
            raise OcError(
                "engagement_required",
                f"{tool} requires engagement_id while OPENCYBER_ENFORCE_SCOPE is on",
                details={"tool": tool, "url": url},
            )
        raise OcError(
            "scope_denied",
            f"scope enforcement refused {tool}: {decision['reason']}",
            details={
                "tool": tool,
                "url": url,
                "host": decision["host"],
                "targets": decision["targets"],
            },
        )
    return decision


def enforce_scope(
    engagement_id: str,
    executable: str,
    arguments: Iterable[str],
) -> dict[str, Any]:
    """Raise when scope enforcement is enabled and the call is out of scope."""
    decision = enforcement_decision(engagement_id, executable, arguments)
    if decision["enforced"] and not decision["allowed"]:
        raise OcError(
            "scope_denied", f"scope enforcement refused {executable}: {decision['reason']}",
            details={"executable": executable, "denied": decision["denied"]},
        )
    return decision
