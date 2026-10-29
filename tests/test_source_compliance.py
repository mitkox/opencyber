from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import tarfile
import unittest
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]


def load_script(name: str):
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / (name.replace("_", "-") + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


verifier = load_script("verify_corresponding_source")
collector = load_script("capture_corresponding_source")


class SourceComplianceTests(unittest.TestCase):
    def test_build_context_archive_excludes_local_secrets_and_private_reports(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "context"
            allowed = ("Dockerfile", "pyproject.toml", "src/opencyber/__init__.py", "docs/SECURITY_MODEL.md")
            private = (".ssh/id_ed25519", ".npmrc", ".git-credentials", "notes-private.txt",
                       "docs/verification/local-private.json", "src/.env", "scripts/.netrc")
            for name in (*allowed, *private):
                path = source / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("synthetic fixture")
            target = root / "build-context.tar.gz"
            collector.archive_build_context(source, target)
            with tarfile.open(target) as archive:
                names = set(archive.getnames())
            for name in allowed:
                self.assertIn("context/" + name, names)
            for name in private:
                self.assertNotIn("context/" + name, names)

    def test_forward_hardlinks_do_not_preload_unvalidated_tar_headers(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "forward-link.tar.gz"
            with tarfile.open(path, "w:gz") as archive:
                root = tarfile.TarInfo("assets")
                root.type = tarfile.DIRTYPE
                archive.addfile(root)
                link = tarfile.TarInfo("assets/hard-link")
                link.type = tarfile.LNKTYPE
                link.linkname = "assets/later"
                archive.addfile(link)
                archive.addfile(tarfile.TarInfo("assets/later"))
            with patch.object(tarfile.TarFile, "getmembers", side_effect=AssertionError("unvalidated header preload")):
                with self.assertRaisesRegex(ValueError, "unresolved direct source archive hard link"):
                    verifier.direct_archive_digest(path)

    def test_direct_asset_bytes_and_paths_are_bound_to_runtime_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            tree = Path(directory) / "wpscan-cache"
            tree.mkdir()
            database = tree / "metadata.json"
            database.write_bytes(b"first database")
            first = collector.tree_digest(tree)
            database.write_bytes(b"other database")
            self.assertNotEqual(first, collector.tree_digest(tree))
            database.write_bytes(b"first database")
            database.rename(tree / "renamed.json")
            self.assertNotEqual(first, collector.tree_digest(tree))
            (tree / "empty").mkdir()
            (tree / "linked.json").symlink_to("./renamed.json")
            os.link(tree / "renamed.json", tree / "hard-linked.json")
            (tree / ".git").mkdir()
            (tree / ".git/private").write_text("excluded")
            archive = Path(directory) / "assets.tar.gz"
            collector.archive_tree(tree, archive)
            self.assertEqual(collector.tree_digest(tree), verifier.direct_archive_digest(archive))
            project = Path(directory) / "opencyber"
            (project / "src/opencyber").mkdir(parents=True)
            (project / "src/opencyber/__init__.py").write_text("__version__ = '0.5.0'\n")
            with patch.object(collector, "DIRECT_SOURCE_TREES", {"wpscan-metadata": tree}), \
                 patch.object(collector, "python_inventory", return_value={}), \
                 patch.object(collector, "ruby_inventory", return_value=[]), \
                 patch.object(collector, "Path", return_value=project):
                first_identity = collector.ecosystem_inventory()
                (tree / "renamed.json").write_bytes(b"changed without a package-version change")
                second_identity = collector.ecosystem_inventory()
            self.assertEqual(first_identity["python"], second_identity["python"])
            self.assertEqual(first_identity["ruby"], second_identity["ruby"])
            self.assertEqual(first_identity["first_party_sha256"], second_identity["first_party_sha256"])
            self.assertNotEqual(first_identity["direct_assets_sha256"], second_identity["direct_assets_sha256"])

    def test_direct_assets_cannot_be_missing_or_differ_from_tested_runtime(self):
        path = self.root / "runtime-ecosystems.json"
        changed = copy.deepcopy(self.ecosystems)
        changed["direct_assets_sha256"] = {"wpscan-metadata": "a" * 64}
        path.write_text(json.dumps(changed))
        entry = next(item for item in self.manifest["artifacts"] if item["path"] == path.name)
        entry.update(bytes=path.stat().st_size, sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        self.save()
        with self.assertRaisesRegex(ValueError, "direct asset"):
            verifier.verify(self.root)
        changed = copy.deepcopy(self.ecosystems)
        changed["direct_assets_sha256"]["wpscan-metadata"] = "b" * 64
        runtime = self.root.parent / (self.root.name + "-runtime.json")
        runtime.write_text(json.dumps(changed))
        path.write_text(json.dumps(self.ecosystems))
        entry.update(bytes=path.stat().st_size, sha256=hashlib.sha256(path.read_bytes()).hexdigest())
        self.save()
        try:
            with self.assertRaisesRegex(ValueError, "differs from tested runtime"):
                verifier.verify(self.root, runtime_ecosystems=runtime)
        finally:
            runtime.unlink()

    def test_local_data_package_sources_match_installed_identity_and_checksums(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "local" / "opencyber-offline-wordlists"
            source.mkdir(parents=True)
            payload = b"exact first-party data package source"
            archive = "opencyber-offline-wordlists_2026.1+opencyber1.tar.gz"
            (source / archive).write_bytes(payload)
            descriptor = ("Source: opencyber-offline-wordlists\nVersion: 2026.1+opencyber1\n"
                          f"Checksums-Sha256:\n {hashlib.sha256(payload).hexdigest()} {len(payload)} {archive}\n")
            dsc = source / "opencyber-offline-wordlists_2026.1+opencyber1.dsc"
            dsc.write_text(descriptor)
            inventory = "installed\topencyber-offline-wordlists\t2026.1+opencyber1\topencyber-offline-wordlists\t2026.1+opencyber1"
            for valid in (True, False):
                with self.subTest(valid=valid):
                    output = root / ("valid" if valid else "wrong-version")
                    output.mkdir()
                    if not valid:
                        dsc.write_text(descriptor.replace("Version: 2026.1+opencyber1", "Version: 2025.3"))
                    with patch.object(collector, "run", return_value=inventory), \
                         patch.object(collector, "enable_source_repositories"), \
                         patch.object(collector.subprocess, "run") as apt:
                        if valid:
                            records = collector.capture_debian(output, local_sources=root / "local")
                            self.assertEqual(records[0]["version"], "2026.1+opencyber1")
                            self.assertEqual(records[0]["source_status"], "captured")
                            self.assertEqual(len(records[0]["archives"]), 2)
                        else:
                            with self.assertRaisesRegex(ValueError, "identity mismatch"):
                                collector.capture_debian(output, local_sources=root / "local")
                        apt.assert_not_called()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        inventory = b"fixture\t1.2-3\tfixture-bin:amd64\t1.2-3\n"
        (self.root / "runtime-dpkg.tsv").write_bytes(inventory)
        self.ecosystems = {
            "python": [], "ruby": [], "first_party_sha256": {"src/opencyber/__init__.py": "a" * 64},
            "direct_assets_sha256": {name: "a" * 64 for name in (
                "docker-bench-security", "nuclei-templates", "seclists", "wpscan-metadata",
            )},
        }
        direct_packages = []
        for name in self.ecosystems["direct_assets_sha256"]:
            archive = self.root / ("source-" + name + ".tar.gz")
            with tempfile.TemporaryDirectory() as directory:
                tree = Path(directory) / "assets"
                tree.mkdir()
                (tree / "metadata").write_text("fixture bytes for " + name)
                self.ecosystems["direct_assets_sha256"][name] = collector.tree_digest(tree)
                collector.archive_tree(tree, archive)
            direct_packages.append({
                "kind": "direct", "name": name, "version": "sha256:" + collector.digest(archive),
                "source_status": "captured", "archives": [archive.name],
            })
        (self.root / "runtime-ecosystems.json").write_text(json.dumps(self.ecosystems))
        (self.root / "fixture.dsc").write_text("Source: fixture\nVersion: 1.2-3\n")
        (self.root / "fixture.tar.gz").write_bytes(b"synthetic source payload")
        self.manifest = {
            "schema": "opencyber.corresponding-source/v1", "platform": "linux/amd64", "complete": True,
            "packages": [{"kind": "debian", "name": "fixture", "version": "1.2-3", "source_status": "captured",
                          "binaries": [{"name": "fixture-bin:amd64", "version": "1.2-3"}],
                          "archives": ["fixture.dsc", "fixture.tar.gz"]}, *direct_packages],
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

    def test_direct_source_archive_omission_or_different_contents_fail(self):
        saved = copy.deepcopy(self.manifest)
        self.manifest["packages"] = [package for package in self.manifest["packages"]
                                     if package["kind"] != "direct"]
        self.save()
        with self.assertRaisesRegex(ValueError, "direct source archive coverage"):
            verifier.verify(self.root)
        self.manifest = saved
        package = next(package for package in self.manifest["packages"] if package["name"] == "wpscan-metadata")
        archive = self.root / package["archives"][0]
        with tempfile.TemporaryDirectory() as directory:
            tree = Path(directory) / "assets"
            tree.mkdir()
            (tree / "metadata").write_text("different downloaded database")
            collector.archive_tree(tree, archive)
        entry = next(item for item in self.manifest["artifacts"] if item["path"] == archive.name)
        entry.update(bytes=archive.stat().st_size, sha256=collector.digest(archive))
        package["version"] = "sha256:" + entry["sha256"]
        self.save()
        with self.assertRaisesRegex(ValueError, "direct source archive differs"):
            verifier.verify(self.root)

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
