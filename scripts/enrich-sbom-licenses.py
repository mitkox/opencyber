#!/usr/bin/env python3
"""Append offline, byte-attributed license facts; retain all scanner license terms.

This is metadata enrichment, not a redistribution approval. Unknown terms remain
in the licenses array and therefore remain subject to the release policy gate.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
from urllib.parse import unquote
import xml.etree.ElementTree as ET
import zipfile

from packaging.licenses import InvalidLicenseExpression, canonicalize_license_expression


EVIDENCE = "opencyber:license-evidence"
MAX_METADATA_BYTES = 2 * 1024 * 1024
GHIDRA = PurePosixPath("/usr/share/ghidra")
# Reviewed full Apache text bytes: Ghidra's bundled rendering and this source's
# standard Apache license rendering. A filename or matching heading is insufficient.
APACHE_TEXT_SHA256 = {
    "8f1dd6568acc5537cccd1ab96a96a5c1b3b018b2bec4ba20ea1aea0007e9cd0f",
    "c71d239df91726fc519c6eb72d318ec65820627232b2f796219e87dcf35d0ab4",
}
OFFICIAL_URLS = {
    f"{scheme}://{host}/licenses/LICENSE-2.0{suffix}": "Apache-2.0"
    for scheme in ("http", "https")
    for host in ("apache.org", "www.apache.org")
    for suffix in ("", ".txt", ".html")
}
OFFICIAL_URLS.update({
    "https://opensource.org/licenses/MIT": "MIT",
    "https://opensource.org/license/mit/": "MIT",
    "https://opensource.org/licenses/BSD-2-Clause": "BSD-2-Clause",
    "https://opensource.org/licenses/BSD-3-Clause": "BSD-3-Clause",
})


def sha256(content: bytes) -> str:
    return hashlib.sha256(content).hexdigest()


def file_sha256(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def known(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        expression = canonicalize_license_expression(value)
    except InvalidLicenseExpression:
        return False
    return "licenseref-" not in expression.casefold()


def license_value(entry: dict) -> object:
    return entry.get("expression") or entry.get("license", {}).get("id") or entry.get("license", {}).get("name")


def identity(component: dict) -> str | None:
    purl = component.get("purl", "")
    if not isinstance(purl, str) or not purl.startswith("pkg:") or "@" not in purl:
        return None
    base = purl.split("?", 1)[0].split("#", 1)[0]
    if base.rfind("@") < base.rfind("/"):
        return None
    version = unquote(base.rsplit("@", 1)[1])
    if (not version or version.casefold() in {"unknown", "none", "noassertion"}
            or any(c.isspace() or c in "*<>" for c in version)
            or component.get("version") != version):
        return None
    return purl


def safe_path(root: Path, location: str) -> Path | None:
    path = PurePosixPath(location)
    if not path.is_absolute() or ".." in path.parts or "\x00" in location:
        return None
    try:
        resolved = (root / location.lstrip("/")).resolve(strict=True)
        return resolved if resolved.is_relative_to(root) and resolved.is_file() else None
    except (OSError, ValueError, RuntimeError):
        return None


def locations(component: dict) -> list[str]:
    return sorted({p["value"] for p in component.get("properties", [])
                   if isinstance(p, dict) and re.fullmatch(r"syft:location:[0-9]+:path", p.get("name", ""))
                   and isinstance(p.get("value"), str)})


def attach(component: dict, entries: list[dict], evidence: dict) -> None:
    licenses = component.setdefault("licenses", [])
    for entry in entries:
        if entry not in licenses:
            licenses.append(entry)
    prop = {"name": EVIDENCE, "value": json.dumps(evidence, sort_keys=True, separators=(",", ":"))}
    properties = component.setdefault("properties", [])
    if prop not in properties:
        properties.append(prop)


def pom_fact(component: dict, archive_path: Path, location: str) -> tuple[list[dict], dict] | None:
    purl = identity(component)
    if not purl or not purl.startswith("pkg:maven/"):
        return None
    coordinate = purl[len("pkg:maven/"):].rsplit("@", 1)[0]
    parts = coordinate.split("/")
    if len(parts) != 2:
        return None
    group, artifact = map(unquote, parts)
    if any(not value or "/" in value or value in {".", ".."} for value in (group, artifact)):
        return None
    member = f"META-INF/maven/{group}/{artifact}/pom.xml"
    try:
        with zipfile.ZipFile(archive_path) as archive:
            info = archive.getinfo(member)
            if info.file_size > MAX_METADATA_BYTES:
                return None
            content = archive.read(info)
        # DTDs/entities are unnecessary for a license declaration and untrusted.
        if b"<!DOCTYPE" in content.upper() or b"<!ENTITY" in content.upper():
            return None
        project = ET.fromstring(content)
    except (OSError, KeyError, ValueError, zipfile.BadZipFile, ET.ParseError):
        return None
    namespace = "{http://maven.apache.org/POM/4.0.0}" if project.tag.startswith("{") else ""
    def text(node: ET.Element, key: str) -> str:
        return (node.findtext(namespace + key) or "").strip()
    parent = project.find(namespace + "parent")
    actual_group = text(project, "groupId") or (text(parent, "groupId") if parent is not None else "")
    actual_version = text(project, "version") or (text(parent, "version") if parent is not None else "")
    if (actual_group, text(project, "artifactId"), actual_version) != (group, artifact, component["version"]):
        return None
    declarations = project.findall(f"{namespace}licenses/{namespace}license")
    urls = [text(declaration, "url") for declaration in declarations]
    if not urls or not all(url in OFFICIAL_URLS for url in urls):
        return None
    entries = [{"license": {"id": value}} for value in sorted({OFFICIAL_URLS[url] for url in urls})]
    return entries, {"method": "embedded-pom", "purl": purl, "path": location,
                     "member": member, "member_sha256": sha256(content),
                     "archive_sha256": file_sha256(archive_path), "declared_urls": urls,
                     "licenses": entries, "scope": "matching Maven coordinates in this archive"}


def ghidra_fact(component: dict, root: Path, location: str, archive_path: Path) -> tuple[list[dict], dict] | None:
    path = PurePosixPath(location)
    if not path.is_relative_to(GHIDRA):
        return None
    # A module file declaration does not relicense separately cataloged contents.
    virtual = [p.get("value") for p in component.get("properties", [])
               if p.get("name") == "syft:metadata:virtualPath"]
    if virtual and virtual != [location]:
        return None
    for directory in path.parents:
        if directory == GHIDRA:
            break
        manifest_location = str(directory / "Module.manifest")
        manifest = safe_path(root, manifest_location)
        if manifest is None:
            continue
        try:
            with manifest.open("rb") as handle:
                content = handle.read(MAX_METADATA_BYTES + 1)
            if len(content) > MAX_METADATA_BYTES:
                return None
            lines = content.decode("utf-8").splitlines()
        except (OSError, UnicodeError):
            return None
        relative = str(path.relative_to(directory))
        expected = f"MODULE FILE LICENSE: {relative} Apache License 2.0"
        declarations = [line for line in lines if line.startswith(f"MODULE FILE LICENSE: {relative} ")]
        if declarations != [expected]:
            continue
        license_location = str(GHIDRA / "licenses/Apache_License_2.0.txt")
        license_file = safe_path(root, license_location)
        if license_file is None:
            return None
        digest = file_sha256(license_file)
        if digest not in APACHE_TEXT_SHA256:
            return None
        entries = [{"license": {"id": "Apache-2.0"}}]
        return entries, {"method": "ghidra-file-manifest", "path": location,
                         "file_sha256": file_sha256(archive_path), "manifest": manifest_location,
                         "manifest_sha256": sha256(content), "declaration": expected,
                         "license_path": license_location, "license_sha256": digest,
                         "licenses": entries, "scope": "exact module file only"}
    return None


def enrich(sbom: dict, root: Path) -> Counter:
    counts: Counter = Counter()
    components = sbom.get("components", [])
    original_scanner_donors: dict[str, list[dict]] = {}
    for item in components:
        purl, entries = identity(item), item.get("licenses", [])
        enriched = any(p.get("name") == EVIDENCE for p in item.get("properties", []))
        if (purl and entries and not enriched
                and all(isinstance(entry, dict) and known(license_value(entry)) for entry in entries)):
            original_scanner_donors.setdefault(purl, []).append(item)
    original_license_signatures_by_purl = {
        purl: {json.dumps(donor["licenses"], sort_keys=True) for donor in matches}
        for purl, matches in original_scanner_donors.items()
    }
    for item in components:
        purl = identity(item)
        matches = original_scanner_donors.get(purl, [])
        signatures = original_license_signatures_by_purl.get(purl, set())
        if len(signatures) == 1 and not item.get("licenses") == matches[0]["licenses"]:
            donor = matches[0]
            serialized = json.dumps(donor["licenses"], sort_keys=True, separators=(",", ":")).encode()
            attach(item, donor["licenses"], {"method": "exact-purl", "purl": purl,
                   "source_bom_ref": donor.get("bom-ref"), "source_licenses_sha256": sha256(serialized),
                   "licenses": donor["licenses"], "scope": "same complete versioned purl in this SBOM"})
            counts["exact-purl"] += 1
        entries = item.get("licenses", [])
        if entries and all(isinstance(entry, dict) and known(license_value(entry)) for entry in entries):
            continue
        for location in locations(item):
            if PurePosixPath(location).suffix.lower() not in {".jar", ".zip", ".zap"}:
                continue
            archive_path = safe_path(root, location)
            if archive_path is None:
                continue
            fact = pom_fact(item, archive_path, location) or ghidra_fact(item, root, location, archive_path)
            if fact:
                entries, evidence = fact
                attach(item, entries, evidence)
                counts[evidence["method"]] += 1
    return counts


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True, help="original CycloneDX JSON")
    parser.add_argument("--root", type=Path, required=True, help="scanned image filesystem root")
    parser.add_argument("--output", default="-", help="enriched CycloneDX JSON, or - for stdout")
    args = parser.parse_args()
    with args.input.open(encoding="utf-8") as handle:
        sbom = json.load(handle)
    counts = enrich(sbom, args.root.resolve(strict=True))
    rendered = json.dumps(sbom, indent=2) + "\n"
    if args.output == "-":
        sys.stdout.write(rendered)
    else:
        Path(args.output).write_text(rendered, encoding="utf-8")
    print("License metadata evidence: " + json.dumps(dict(counts), sort_keys=True), file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
