#!/usr/bin/env python3
"""Check a CycloneDX JSON SBOM against OpenCyber's release license policy."""

from __future__ import annotations

import argparse
from datetime import date
import hashlib
import json
from pathlib import Path
import sys
from urllib.parse import unquote, urlsplit

from packaging.licenses import InvalidLicenseExpression, canonicalize_license_expression


def known_license(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        canonical = canonicalize_license_expression(value)
    except InvalidLicenseExpression:
        return False
    return "licenseref-" not in canonical.casefold()


def custom_license_review(decision: dict, evidence_root: Path) -> bool:
    try:
        expression = canonicalize_license_expression(decision.get("license_expression", ""))
    except (InvalidLicenseExpression, TypeError):
        return False
    if "licenseref-" not in expression.casefold():
        return False
    for field in ("redistribution_basis", "source_obligations"):
        value = decision.get(field)
        if not isinstance(value, str) or not value.strip():
            return False
    notices = decision.get("required_notices")
    if not isinstance(notices, list) or not notices or not all(
        isinstance(notice, str) and notice.strip() for notice in notices
    ):
        return False
    evidence = decision.get("license_evidence")
    if not isinstance(evidence, dict):
        return False
    path, digest, source = (evidence.get(key) for key in ("path", "sha256", "source_url"))
    if not all(isinstance(value, str) and value.strip() for value in (path, digest, source)):
        return False
    try:
        origin = urlsplit(source)
        root = evidence_root.resolve()
        relative = Path(path)
        license_path = (root / relative).resolve()
        if (relative.is_absolute() or not license_path.is_relative_to(root)
                or origin.scheme not in {"http", "https"} or not origin.netloc):
            return False
        content = license_path.read_bytes()
    except (OSError, ValueError):
        return False
    return bool(content.strip()) and hashlib.sha256(content).hexdigest() == digest


def unresolved_licenses(sbom: dict, policy: dict, evidence_root: Path = Path(".")) -> list[str]:
    """Unknown identities need a version-bound, attributed review decision."""
    decisions = policy.get("reviewed_license_components", [])
    approved: set[str] = set()
    for decision in decisions:
        purl = decision.get("purl", "")
        expression = decision.get("license_expression", "")
        if not isinstance(purl, str) or not purl.startswith("pkg:") or "@" not in purl:
            continue
        version = unquote(purl.rsplit("@", 1)[1].split("?", 1)[0].split("#", 1)[0])
        if not version or any(char.isspace() or char in "*<>" for char in version):
            continue
        if not all(isinstance(decision.get(field), str) and decision[field].strip()
                   for field in ("owner", "basis")):
            continue
        try:
            reviewed = date.fromisoformat(decision.get("reviewed_at", ""))
        except (TypeError, ValueError):
            continue
        if (reviewed <= date.today()
                and (known_license(expression) or custom_license_review(decision, evidence_root))):
            approved.add(purl)
    unresolved = []
    components = sbom.get("components")
    if not isinstance(components, list) or not components:
        return ["SBOM has no component license inventory"]
    for component in components:
        licenses = component.get("licenses", [])
        values = [entry.get("expression") or entry.get("license", {}).get("id")
                  or entry.get("license", {}).get("name")
                  for entry in licenses if isinstance(entry, dict)]
        resolved = bool(values) and all(known_license(value) for value in values)
        if not resolved and component.get("purl") not in approved:
            unresolved.append(component.get("purl") or component.get("name") or "unnamed component")
    return unresolved


def component_names(sbom: dict) -> set[str]:
    names: set[str] = set()
    for component in sbom.get("components", []):
        name = component.get("name")
        if isinstance(name, str):
            names.add(name.casefold())
            names.add(name.rsplit("/", 1)[-1].casefold())
        purl = component.get("purl")
        if isinstance(purl, str) and purl.startswith("pkg:"):
            package_part = purl.split("?", 1)[0].rsplit("/", 1)[-1]
            package_name = package_part.split("@", 1)[0]
            names.add(unquote(package_name).casefold())
    metadata_component = sbom.get("metadata", {}).get("component", {})
    name = metadata_component.get("name")
    if isinstance(name, str):
        names.add(name.casefold())
    return names


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("sbom", type=Path, help="CycloneDX JSON SBOM")
    parser.add_argument(
        "--policy",
        type=Path,
        default=Path("compliance/license-policy.json"),
        help="license policy JSON",
    )
    parser.add_argument(
        "--license-evidence-root", type=Path,
        help="root for reviewed custom-license text paths (default: policy directory)",
    )
    args = parser.parse_args()

    with args.sbom.open(encoding="utf-8") as handle:
        sbom = json.load(handle)
    with args.policy.open(encoding="utf-8") as handle:
        policy = json.load(handle)

    names = component_names(sbom)
    unresolved = unresolved_licenses(sbom, policy, args.license_evidence_root or args.policy.parent)
    blocked = [
        entry
        for entry in policy.get("blocked_components", [])
        if entry["name"].casefold() in names
    ]
    review = [
        entry
        for entry in policy.get("review_required_components", [])
        if entry["name"].casefold() in names
    ]
    notices = [
        entry
        for entry in policy.get("notice_required_components", [])
        if entry["name"].casefold() in names
    ]

    print(f"SBOM components: {len(sbom.get('components', []))}")
    for entry in review:
        print(f"REVIEW: {entry['name']}: {entry['reason']}")
    for entry in notices:
        print(f"NOTICE: {entry['name']}: {entry['reason']}")
    for entry in blocked:
        print(f"BLOCKED: {entry['name']}: {entry['reason']}", file=sys.stderr)
    for name in unresolved:
        print(f"UNRESOLVED: {name}: missing license identity or version-bound review", file=sys.stderr)

    if blocked or review or unresolved:
        print(
            f"Release blocked by {len(blocked)} forbidden, {len(review)} review and {len(unresolved)} unknown-license component(s).",
            file=sys.stderr,
        )
        return 1
    print("No blocked components detected.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
