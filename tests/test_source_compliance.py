from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


def load_script(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / (name.replace("_", "-") + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


verifier = load_script("verify_corresponding_source")
collector = load_script("capture_corresponding_source")


class SourceComplianceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        inventory = b"fixture\t1.2-3\tfixture-bin:amd64\t1.2-3\n"
        (self.root / "runtime-dpkg.tsv").write_bytes(inventory)
        self.ecosystems = {"python": [], "ruby": [], "first_party_sha256": {"src/opencyber/__init__.py": "a" * 64}}
        (self.root / "runtime-ecosystems.json").write_text(json.dumps(self.ecosystems))
        (self.root / "fixture.dsc").write_text("Source: fixture\nVersion: 1.2-3\n")
        (self.root / "fixture.tar.gz").write_bytes(b"synthetic source payload")
        self.manifest = {
            "schema": "opencyber.corresponding-source/v1", "platform": "linux/amd64", "complete": True,
            "packages": [{"kind": "debian", "name": "fixture", "version": "1.2-3", "source_status": "captured",
                          "binaries": [{"name": "fixture-bin:amd64", "version": "1.2-3"}],
                          "archives": ["fixture.dsc", "fixture.tar.gz"]}],
            "artifacts": [{"path": path.name, "bytes": path.stat().st_size,
                           "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                          for path in sorted(self.root.iterdir())],
        }
        self.save()

    def tearDown(self):
        self.temporary.cleanup()

    def save(self):
        (self.root / "source-manifest.json").write_text(json.dumps(self.manifest))

    def test_exact_package_coverage_and_payload_hashes_pass(self):
        result = verifier.verify(self.root, self.root / "runtime-dpkg.tsv", "linux/amd64")
        self.assertTrue(result["complete"])

    def test_inventory_for_another_build_or_platform_fails(self):
        with self.assertRaisesRegex(ValueError, "platform"):
            verifier.verify(self.root, platform="linux/arm64")
        other = self.root.parent / (self.root.name + "-inventory")
        try:
            other.write_text("fixture\t1.2-4\tfixture-bin:amd64\t1.2-4\n")
            with self.assertRaisesRegex(ValueError, "differs"):
                verifier.verify(self.root, runtime_inventory=other)
        finally:
            other.unlink(missing_ok=True)

    def test_missing_modified_and_extra_payloads_fail(self):
        original = (self.root / "fixture.tar.gz").read_bytes()
        (self.root / "fixture.tar.gz").write_bytes(b"modified")
        with self.assertRaisesRegex(ValueError, "modified"):
            verifier.verify(self.root)
        (self.root / "fixture.tar.gz").write_bytes(original)
        (self.root / "extra").write_text("unlisted")
        with self.assertRaisesRegex(ValueError, "unlisted"):
            verifier.verify(self.root)
        (self.root / "extra").unlink()
        (self.root / "fixture.tar.gz").unlink()
        with self.assertRaisesRegex(ValueError, "missing"):
            verifier.verify(self.root)

    def test_duplicate_unsafe_and_symlink_payloads_fail(self):
        saved = copy.deepcopy(self.manifest)
        self.manifest["artifacts"].append(self.manifest["artifacts"][0])
        self.save()
        with self.assertRaisesRegex(ValueError, "duplicate"):
            verifier.verify(self.root)
        self.manifest = saved
        self.manifest["artifacts"][0]["path"] = "../outside"
        self.save()
        with self.assertRaisesRegex(ValueError, "unsafe"):
            verifier.verify(self.root)
        self.manifest = copy.deepcopy(saved)
        # saved was changed above; restore only the modified record path.
        self.manifest["artifacts"][0]["path"] = "fixture.dsc"
        self.save()
        target = self.root / "fixture.tar.gz"
        target.unlink()
        target.symlink_to(self.root / "fixture.dsc")
        with self.assertRaisesRegex(ValueError, "symlink"):
            verifier.verify(self.root)

    def test_uncovered_installed_binary_fails(self):
        self.manifest["packages"][0]["binaries"][0]["version"] = "other"
        self.save()
        with self.assertRaisesRegex(ValueError, "coverage"):
            verifier.verify(self.root)

    def test_python_and_ruby_package_coverage_cannot_be_omitted(self):
        for ecosystem in ("python", "ruby"):
            changed = copy.deepcopy(self.ecosystems)
            changed[ecosystem] = [{"name": "fixture", "version": "1"}]
            path = self.root / "runtime-ecosystems.json"
            path.write_text(json.dumps(changed))
            entry = next(item for item in self.manifest["artifacts"] if item["path"] == path.name)
            entry.update(bytes=path.stat().st_size, sha256=hashlib.sha256(path.read_bytes()).hexdigest())
            self.save()
            with self.assertRaisesRegex(ValueError, f"{ecosystem} source coverage"):
                verifier.verify(self.root)

    def test_same_package_versions_with_different_first_party_source_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            runtime = Path(directory) / "runtime.json"
            changed = copy.deepcopy(self.ecosystems)
            changed["first_party_sha256"]["src/opencyber/__init__.py"] = "b" * 64
            runtime.write_text(json.dumps(changed))
            with self.assertRaisesRegex(ValueError, "differs from tested runtime"):
                verifier.verify(self.root, runtime_ecosystems=runtime)

    def test_names_or_urls_without_source_do_not_pass(self):
        self.manifest["packages"][0]["archives"] = []
        self.manifest["packages"][0]["url"] = "https://example.invalid/source"
        self.save()
        with self.assertRaisesRegex(ValueError, "payload"):
            verifier.verify(self.root)

    def test_reciprocal_or_unknown_license_cannot_skip_source(self):
        package = {"kind": "python", "name": "fixture-py", "version": "1", "source_status": "notice-only",
                   "license_expression": "GPL-3.0-only", "decision": "No upstream sdist", "archives": []}
        self.manifest["packages"].append(package)
        self.save()
        with self.assertRaisesRegex(ValueError, "exemption"):
            verifier.verify(self.root)
        self.assertFalse(collector.permissive_license({"license_expression": "GPL-3.0-only"}))
        self.assertFalse(collector.permissive_license({"license_expression": "MIT OR GPL-3.0-only"}))
        self.assertFalse(collector.permissive_license({}))
        self.assertTrue(collector.permissive_license({"license_expression": "Apache-2.0"}))

    def test_builder_must_preserve_source_before_cache_disappears(self):
        with self.assertRaisesRegex(ValueError, "preserve exact go"):
            collector.capture_builds(self.root, self.root / "missing-inputs")


if __name__ == "__main__":
    unittest.main()
