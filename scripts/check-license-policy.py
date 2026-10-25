#!/usr/bin/env python3
"""Check a CycloneDX JSON SBOM against OpenCyber's release license policy."""

from __future__ import annotations

import argparse
from datetime import date
import json
from pathlib import Path
import sys
from urllib.parse import unquote

from packaging.licenses import InvalidLicenseExpression, canonicalize_license_expression


def known_license(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        canonical = canonicalize_license_expression(value)
    except InvalidLicenseExpression:
        return False
    return "licenseref-" not in canonical.casefold()


def unresolved_licenses(sbom: dict, policy: dict) -> list[str]:
    """Unknown identities need a version-bound, attributed review decision."""
    decisions = policy.get("reviewed_license_components", [])
    approved: set[str] = set()
    for decision in decisions:
        purl = decision.get("purl", "")
        expression = decision.get("license_expression", "")
        try:
            reviewed = date.fromisoformat(decision.get("reviewed_at", ""))
        except (TypeError, ValueError):
            continue
        if ("@" in purl and decision.get("owner") and decision.get("basis")
                and reviewed <= date.today() and known_license(expression)):
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
    args = parser.parse_args()

    with args.sbom.open(encoding="utf-8") as handle:
        sbom = json.load(handle)
    with args.policy.open(encoding="utf-8") as handle:
        policy = json.load(handle)

    names = component_names(sbom)
    unresolved = unresolved_licenses(sbom, policy)
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
