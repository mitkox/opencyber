from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "enrich-sbom-licenses.py"
EVIDENCE = "opencyber:license-evidence"


def component(ref: str, purl: str, path: str | None = None, licenses: list | None = None) -> dict:
    result = {"type": "library", "bom-ref": ref, "name": "fixture", "version": "1.0", "purl": purl}
    if path:
        result["properties"] = [{"name": "syft:location:0:path", "value": path}]
    if licenses is not None:
        result["licenses"] = licenses
    return result


class SbomLicenseEnrichmentTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.root = Path(self.directory.name)

    def run_enricher(self, components: list[dict]) -> dict:
        sbom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "serialNumber": "urn:uuid:fixture",
                "components": components, "dependencies": [{"ref": "a", "dependsOn": ["b"]}]}
        source = self.root / "input.json"
        source.write_text(json.dumps(sbom), encoding="utf-8")
        result = subprocess.run([sys.executable, str(SCRIPT), "--input", str(source),
                                 "--root", str(self.root), "--output", "-"],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 0, result.stderr)
        output = json.loads(result.stdout)
        self.assertEqual(output["dependencies"], sbom["dependencies"])
        self.assertEqual([c["bom-ref"] for c in output["components"]], [c["bom-ref"] for c in components])
        return output

    def jar(self, path: str, *, artifact: str = "fixture", version: str = "1.0", url: str | None = None) -> bytes:
        pom = (f'<project xmlns="http://maven.apache.org/POM/4.0.0"><parent>'
               f'<groupId>example</groupId><version>{version}</version></parent>'
               f'<artifactId>{artifact}</artifactId><licenses><license><name>Apache License, Version 2.0</name>'
               f'<url>{url or "https://www.apache.org/licenses/LICENSE-2.0.txt"}</url>'
               f'</license></licenses></project>').encode()
        target = self.root / path.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        with zipfile.ZipFile(target, "w") as archive:
            archive.writestr(f"META-INF/maven/example/{artifact}/pom.xml", pom)
        return pom

    def facts(self, item: dict) -> list[dict]:
        return [json.loads(p["value"]) for p in item.get("properties", []) if p["name"] == EVIDENCE]

    def test_exact_versioned_purl_reuses_explicit_facts_and_preserves_unknown_terms(self) -> None:
        mit = {"license": {"id": "MIT"}}
        unknown = {"license": {"name": "Project-specific restriction"}}
        items = [component("a", "pkg:maven/example/fixture@1.0", licenses=[mit]),
                 component("b", "pkg:maven/example/fixture@1.0"),
                 component("c", "pkg:maven/example/fixture@1.0", licenses=[unknown])]
        output = self.run_enricher(items)["components"]
        self.assertEqual(output[1]["licenses"], [mit])
        self.assertEqual(output[2]["licenses"], [unknown, mit])
        fact = self.facts(output[1])[0]
        self.assertEqual(fact["method"], "exact-purl")
        self.assertEqual(fact["source_bom_ref"], "a")
        self.assertEqual(len(fact["source_licenses_sha256"]), 64)

    def test_cross_version_versionless_and_conflicting_identity_are_not_reused(self) -> None:
        donor = component("a", "pkg:maven/example/fixture@1.0", licenses=[{"license": {"id": "MIT"}}])
        items = [donor, component("b", "pkg:maven/example/fixture@2.0"),
                 component("c", "pkg:maven/example/fixture"),
                 component("d", "pkg:maven/example/fixture@1.0")]
        items[3]["version"] = "2.0"
        for item in self.run_enricher(items)["components"][1:]:
            self.assertNotIn("licenses", item)
            self.assertEqual(self.facts(item), [])

    def test_scope_at_sign_is_not_a_version_delimiter(self) -> None:
        source = component("a", "pkg:npm/@scope/fixture", licenses=[{"license": {"id": "MIT"}}])
        target = component("b", "pkg:npm/@scope/fixture")
        source["version"] = target["version"] = "scope/fixture"
        self.assertNotIn("licenses", self.run_enricher([source, target])["components"][1])

    def test_pom_official_apache_url_is_bound_to_coordinates_and_bytes(self) -> None:
        path = "/usr/share/java/fixture.jar"
        pom = self.jar(path)
        item = component("a", "pkg:maven/example/fixture@1.0", path,
                         [{"license": {"name": "Apache License, Version 2.0"}}])
        result = self.run_enricher([item])["components"][0]
        self.assertEqual(result["licenses"][0], item["licenses"][0])
        self.assertIn({"license": {"id": "Apache-2.0"}}, result["licenses"])
        fact = self.facts(result)[0]
        self.assertEqual(fact["method"], "embedded-pom")
        self.assertEqual(fact["path"], path)
        self.assertEqual(fact["member_sha256"], hashlib.sha256(pom).hexdigest())
        self.assertEqual(fact["archive_sha256"], hashlib.sha256((self.root / path.lstrip("/")).read_bytes()).hexdigest())

    def test_pom_other_artifact_or_version_cannot_license_component(self) -> None:
        self.jar("/other.jar", artifact="other")
        self.jar("/version.jar", version="2.0")
        self.jar("/untrusted.jar", url="https://example.invalid/Apache-2.0")
        items = [component(str(i), "pkg:maven/example/fixture@1.0", path)
                 for i, path in enumerate(("/other.jar", "/version.jar", "/untrusted.jar"))]
        for item in self.run_enricher(items)["components"]:
            self.assertNotIn("licenses", item)

    def test_location_traversal_and_symlink_escape_are_not_read(self) -> None:
        with tempfile.TemporaryDirectory() as outside:
            target = Path(outside) / "outside.jar"
            self.jar("/valid.jar")
            target.write_bytes((self.root / "valid.jar").read_bytes())
            (self.root / "escape.jar").symlink_to(target)
            items = [component("a", "pkg:maven/example/fixture@1.0", f"/../{Path(outside).name}/outside.jar"),
                     component("b", "pkg:maven/example/fixture@1.0", "/escape.jar")]
            for item in self.run_enricher(items)["components"]:
                self.assertNotIn("licenses", item)
                self.assertEqual(self.facts(item), [])

    def ghidra(self, license_text: bytes) -> tuple[str, str]:
        base = self.root / "usr/share/ghidra"
        (base / "licenses").mkdir(parents=True)
        (base / "licenses/Apache_License_2.0.txt").write_bytes(license_text)
        module = base / "Ghidra/Features/Fixture"
        (module / "lib").mkdir(parents=True)
        (module / "Module.manifest").write_text(
            "MODULE FILE LICENSE: lib/exact.jar Apache License 2.0\n", encoding="utf-8")
        for name in ("exact.jar", "unmapped.jar"):
            with zipfile.ZipFile(module / "lib" / name, "w"):
                pass
        return ("/usr/share/ghidra/Ghidra/Features/Fixture/lib/exact.jar",
                "/usr/share/ghidra/Ghidra/Features/Fixture/lib/unmapped.jar")

    def test_ghidra_mapping_applies_only_to_named_file_with_verified_full_text(self) -> None:
        license_text = (ROOT / "LICENSE").read_bytes()
        paths = self.ghidra(license_text)
        items = [component(str(i), "pkg:maven/example/fixture@1.0", path) for i, path in enumerate(paths)]
        output = self.run_enricher(items)["components"]
        self.assertEqual(output[0]["licenses"], [{"license": {"id": "Apache-2.0"}}])
        self.assertNotIn("licenses", output[1])
        fact = self.facts(output[0])[0]
        self.assertEqual(fact["method"], "ghidra-file-manifest")
        self.assertEqual(fact["license_sha256"], hashlib.sha256(license_text).hexdigest())
        self.assertEqual(fact["path"], paths[0])

    def test_file_specific_facts_never_propagate_by_purl_on_a_second_run(self) -> None:
        paths = self.ghidra((ROOT / "LICENSE").read_bytes())
        items = [component(str(i), "pkg:maven/example/fixture@1.0", path) for i, path in enumerate(paths)]
        first = self.run_enricher(items)
        second = self.run_enricher(first["components"])
        self.assertEqual(first, second)
        self.assertNotIn("licenses", second["components"][1])

    def test_ghidra_conflicting_file_terms_and_nested_contents_are_not_inherited(self) -> None:
        paths = self.ghidra((ROOT / "LICENSE").read_bytes())
        manifest = self.root / "usr/share/ghidra/Ghidra/Features/Fixture/Module.manifest"
        with manifest.open("a", encoding="utf-8") as handle:
            handle.write("MODULE FILE LICENSE: lib/exact.jar Additional license required\n")
        item = component("a", "pkg:maven/example/fixture@1.0", paths[0])
        self.assertNotIn("licenses", self.run_enricher([item])["components"][0])
        manifest.write_text("MODULE FILE LICENSE: lib/exact.jar Apache License 2.0\n", encoding="utf-8")
        item["properties"].append({"name": "syft:metadata:virtualPath", "value": paths[0] + ":libs/embedded.jar"})
        self.assertNotIn("licenses", self.run_enricher([item])["components"][0])

    def test_ghidra_filename_or_heading_alone_is_not_license_identity(self) -> None:
        paths = self.ghidra(b"Apache License Version 2.0, modified with a prohibition on redistribution")
        output = self.run_enricher([component("a", "pkg:maven/example/fixture@1.0", paths[0])])["components"][0]
        self.assertNotIn("licenses", output)


if __name__ == "__main__":
    unittest.main()
