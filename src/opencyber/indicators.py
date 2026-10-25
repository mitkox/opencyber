"""Text-only indicator extraction shared by native tools and artifact triage."""

from __future__ import annotations

import ipaddress
import re


_PATTERNS = {
    "urls": r"https?://[^\s\"'<>]+",
    "ipv4": r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])",
    "cves": r"(?i)\bCVE-\d{4}-\d{4,}\b",
    "md5": r"(?i)\b[a-f0-9]{32}\b",
    "sha1": r"(?i)\b[a-f0-9]{40}\b",
    "sha256": r"(?i)\b[a-f0-9]{64}\b",
}
_IPV6 = re.compile(r"(?i)(?<![\w:])[a-f0-9:.]+(?![\w:])")
_DOMAIN = re.compile(r"(?i)(?<![\w.-])(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
                     r"(?:[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?)(?![\w.-])")


def extract_indicators(text: str, *, extended: bool = False) -> dict[str, list[str]]:
    """Extract candidates without resolving names or contacting any service.

    The default keeps the six historical ``oc_extract_indicators`` keys. Triage
    requests additional IPv6 and domain groups; IP candidates always pass the
    standard library's address parser before they are reported.
    """
    result = {name: sorted(set(re.findall(pattern, text))) for name, pattern in _PATTERNS.items()}
    valid_ipv4 = []
    for candidate in result["ipv4"]:
        try:
            ipaddress.IPv4Address(candidate)
        except ipaddress.AddressValueError:
            continue
        valid_ipv4.append(candidate)
    result["ipv4"] = valid_ipv4
    if extended:
        ipv6 = set()
        for match in _IPV6.finditer(text):
            candidate = match.group().rstrip(".")
            if len(candidate) > 45 or candidate.count(":") < 2:
                continue
            try:
                ipv6.add(str(ipaddress.IPv6Address(candidate)))
            except ipaddress.AddressValueError:
                continue
        result["ipv6"] = sorted(ipv6)
        result["domains"] = sorted({match.group().lower() for match in _DOMAIN.finditer(text)
                                     if len(match.group()) <= 253})
    return result
