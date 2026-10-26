from __future__ import annotations

import hashlib
import io
import json
from pathlib import Path
import subprocess
import sys
import tarfile
import tempfile
import unittest
import zipfile


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/collect-license-bundle.py"


class LicenseBundleTests(unittest.TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)

    def write(self, path: str, content: bytes) -> Path:
        target = self.root / path.lstrip("/")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        return target

    def collect(self, *arguments: str, status: int = 0) -> tuple[bytes, dict, dict[str, bytes]]:
        result = subprocess.run([sys.executable, str(SCRIPT), "--root", str(self.root), *arguments],
                                capture_output=True, check=False)
        self.assertEqual(result.returncode, status, result.stderr.decode())
        with tarfile.open(fileobj=io.BytesIO(result.stdout), mode="r:gz") as archive:
            self.assertTrue(all(member.isfile() for member in archive))
            files = {member.name: archive.extractfile(member).read() for member in archive}
        inventory = json.loads(files.pop("LICENSE-INVENTORY.json"))
        for item in inventory["materials"]:
            content = files[item["archive_path"]]
            self.assertEqual(item["size_bytes"], len(content))
            self.assertEqual(item["sha256"], hashlib.sha256(content).hexdigest())
        self.assertEqual(len(files), len(inventory["materials"]))
        self.assertFalse(inventory["redistribution_approval"])
        return result.stdout, inventory, files

    def test_retains_actual_package_material_bytes_and_file_mappings(self) -> None:
        paths = (
            "/usr/share/doc/fixture/copyright",
            "/usr/share/common-licenses/GPL-2",
            "/usr/share/metasploit-framework/vendor/bundle/ruby/gems/fixture/LICENSE",
            "/usr/share/rubygems-integration/all/gems/fixture/xdia.LICENSE.txt",
            "/usr/share/ghidra/licenses/LICENSE-texts/fixture.txt",
            "/usr/share/ghidra/Ghidra/Features/Fixture/Module.manifest",
            "/usr/share/zaproxy/NOTICE.txt",
            "/usr/share/jadx/NOTICE",
            "/usr/lib/fixture/REDIST.txt",
            "/usr/local/lib/python3.12/site-packages/fixture.dist-info/licenses/full.txt",
            "/opt/fixture/EULA.txt",
            "/var/lib/gems/fixture/COPYING",
        )
        for index, path in enumerate(paths):
            self.write(path, f"specific material {index}\r\n".encode() + b"\x00\xff")
        self.write("/usr/share/fixture/unrelated.txt", b"not a notice")
        _, inventory, files = self.collect()
        self.assertEqual(set(files), {path.lstrip("/") for path in paths})
        self.assertEqual({entry["source_path"] for entry in inventory["materials"]}, set(paths))
        self.assertEqual(inventory["collection"]["status"], "complete")

    def test_bundle_is_deterministic(self) -> None:
        self.write("/opt/fixture/LICENSE", b"retained bytes")
        self.assertEqual(self.collect()[0], self.collect()[0])

    def test_filesystem_names_cannot_create_portable_archive_traversal(self) -> None:
        self.write("/opt/fixture/..\\..\\LICENSE", b"escape")
        _, inventory, files = self.collect(status=1)
        self.assertEqual(files, {})
        self.assertEqual(inventory["collection"]["omissions"][0]["reason"], "unsafe-source-path")

    def test_retains_safe_file_symlinks_as_bytes_but_refuses_scope_escape(self) -> None:
        self.write("/usr/share/common-licenses/MIT", b"actual common terms")
        link = self.write("/usr/share/doc/fixture/LICENSE", b"")
        link.unlink()
        link.symlink_to("../../common-licenses/MIT")
        secret = self.write("/etc/hidden", b"outside declared scope")
        escape = self.root / "usr/share/doc/fixture/NOTICE"
        escape.symlink_to(secret)
        with tempfile.TemporaryDirectory() as outside:
            target = Path(outside) / "secret"
            target.write_bytes(b"outside collection root")
            (self.root / "usr/share/doc/fixture/NOTICE-outside").symlink_to(target)
            _, inventory, files = self.collect(status=1)
        self.assertEqual(files["usr/share/doc/fixture/LICENSE"], b"actual common terms")
        self.assertNotIn(b"outside declared scope", files.values())
        self.assertNotIn(b"outside collection root", files.values())
        self.assertEqual(inventory["collection"]["status"], "partial")
        self.assertIn("symlink-outside-scope", {item["reason"] for item in inventory["collection"]["omissions"]})

    def jar(self, members: dict[str, bytes]) -> Path:
        path = self.write("/usr/share/jadx/lib/fixture.jar", b"")
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for name, content in members.items():
                archive.writestr(name, content)
        return path

    def test_embedded_notices_and_pom_are_bound_to_exact_archive_and_member(self) -> None:
        members = {"META-INF/LICENSE": b"full license\r\n", "META-INF/NOTICE": b"attribution",
                   "META-INF/maven/example/fixture/pom.xml": b"<project><licenses>terms</licenses></project>"}
        path = self.jar({**members, "payload.class": b"not license material"})
        _, inventory, files = self.collect()
        jar_hash = hashlib.sha256(path.read_bytes()).hexdigest()
        self.assertEqual(set(files.values()), set(members.values()))
        for item in inventory["materials"]:
            self.assertEqual(item["kind"], "jar-member")
            self.assertEqual(item["source_path"], "/usr/share/jadx/lib/fixture.jar")
            self.assertEqual(item["source_sha256"], jar_hash)
            self.assertEqual(files[item["archive_path"]], members[item["member_path"]])
            self.assertIn(jar_hash, item["archive_path"])

    def test_generic_notice_matching_excludes_compiled_files_but_retains_notice_documents(self) -> None:
        compiled_names = ("CopyingBinder.class", "Copyright.CLASS", "license.pyc", "license.pyo",
                          "notice.dll", "copyright.exe", "license.so", "license.so.1.2", "license.dylib",
                          "copying.o", "copying.obj", "license.a", "license.lib", "notice.pdb",
                          "license.wasm", "license.ko")
        binary = b"\xca\xfe\xba\xbecompiled code"
        for name in compiled_names:
            self.write("/opt/fixture/" + name, binary)
        documents = {"xdia.LICENSE.txt": b"full xdia terms", "COPYING": b"full copying terms",
                     "COPYING.LIB": b"full LGPL library terms",
                     "NOTICE.pdf": b"notice document", "licenses/third-party.md": b"full third-party terms"}
        for name, content in documents.items():
            self.write("/opt/fixture/" + name, content)
        members = {"oracle/jdbc/driver/" + name: binary for name in compiled_names}
        members.update({"META-INF/" + name: content for name, content in documents.items()})
        self.jar(members)
        _, inventory, files = self.collect()
        self.assertEqual(len(files), 2 * len(documents))
        self.assertNotIn(binary, files.values())
        self.assertEqual({item["member_path"] for item in inventory["materials"] if item["kind"] == "jar-member"},
                         {"META-INF/" + name for name in documents})
        self.assertEqual(inventory["collection"]["status"], "complete")

    def test_unsafe_jar_paths_and_symlink_members_are_never_exported(self) -> None:
        path = self.jar({"../LICENSE": b"escape", "/NOTICE": b"absolute", "META-INF/LICENSE": b"good",
                         "./META-INF/LICENSE": b"good"})
        with zipfile.ZipFile(path, "a") as archive:
            link = zipfile.ZipInfo("META-INF/NOTICE-link")
            link.external_attr = 0o120777 << 16
            archive.writestr(link, b"/etc/passwd")
        _, inventory, files = self.collect(status=1)
        self.assertEqual(list(files.values()), [b"good"])
        reasons = {item["reason"] for item in inventory["collection"]["omissions"]}
        self.assertTrue({"unsafe-jar-member", "jar-member-symlink"}.issubset(reasons))

    def test_file_member_and_total_limits_preserve_partial_inventory(self) -> None:
        self.write("/opt/fixture/LICENSE", b"x" * 65)
        self.jar({"META-INF/LICENSE": b"y" * 65, "META-INF/NOTICE": b"good"})
        _, inventory, files = self.collect("--max-file-bytes", "64", "--max-member-bytes", "64", status=1)
        self.assertEqual(list(files.values()), [b"good"])
        reasons = {item["reason"] for item in inventory["collection"]["omissions"]}
        self.assertTrue({"file-size-limit", "jar-member-size-limit"}.issubset(reasons))
        _, inventory, files = self.collect("--max-total-bytes", "3", status=1)
        self.assertEqual(files, {})
        self.assertIn("total-size-limit", {item["reason"] for item in inventory["collection"]["omissions"]})

    def test_archive_member_count_limit_refuses_oversized_directory(self) -> None:
        self.jar({"META-INF/LICENSE": b"one", "META-INF/NOTICE": b"two"})
        _, inventory, files = self.collect("--max-archive-members", "1", status=1)
        self.assertEqual(files, {})
        self.assertEqual(inventory["collection"]["omissions"][0]["reason"], "jar-directory-limit")

    def test_opaque_payload_bytes_are_retained_without_zip_or_license_interpretation(self) -> None:
        content = b"opaque non-ZIP payload"
        self.write("/opt/COPYING-payload.jar", content)
        _, inventory, files = self.collect()
        self.assertEqual(list(files.values()), [content])
        self.assertEqual(inventory["materials"][0]["kind"], "opaque-archive")
        self.assertEqual(inventory["materials"][0]["source_path"], "/opt/COPYING-payload.jar")
        self.assertEqual(inventory["materials"][0]["archive_interpretation"], "not-a-valid-zip")
        self.assertEqual(inventory["collection"]["status"], "complete")

    def test_oversized_valid_archives_and_opaque_material_remain_omissions(self) -> None:
        self.write("/opt/payload.jar", b"opaque non-ZIP payload")
        self.jar({"META-INF/LICENSE": b"license"})
        _, inventory, files = self.collect("--max-archive-bytes", "64", "--max-file-bytes", "16", status=1)
        self.assertEqual(files, {})
        reasons = {item["reason"] for item in inventory["collection"]["omissions"]}
        self.assertEqual(reasons, {"opaque-archive-size-limit", "jar-size-limit"})

    def test_traversal_and_material_count_caps_report_partial_collection(self) -> None:
        for index in range(4):
            self.write(f"/opt/fixture/LICENSE-{index}", b"license")
        _, inventory, files = self.collect("--max-materials", "1", status=1)
        self.assertEqual(len(files), 1)
        self.assertIn("material-count-limit", {item["reason"] for item in inventory["collection"]["omissions"]})
        _, inventory, _ = self.collect("--max-visited-paths", "2", status=1)
        self.assertEqual(inventory["collection"]["visited_paths"], 3)
        self.assertIn("visited-path-limit", {item["reason"] for item in inventory["collection"]["omissions"]})

    def test_wrapper_hardens_both_container_reads_and_hashes_inventory(self) -> None:
        wrapper = (ROOT / "scripts/generate-license-bundle.sh").read_text(encoding="utf-8")
        for argument in ("--read-only", "--network none", "--cap-drop ALL", "no-new-privileges"):
            self.assertIn(argument, wrapper)
        self.assertIn("LICENSE-INVENTORY.json", wrapper)
        self.assertNotIn("--privileged", wrapper)


if __name__ == "__main__":
    unittest.main()
