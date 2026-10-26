from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "scripts/build-offline-wordlists.py"
PACKAGE = "opencyber-offline-wordlists"
VERSION = "2026.1+opencyber1"
LICENSE = "MIT License\n\nCopyright (c) synthetic test fixture\nPermission is hereby granted for this fixture.\n"


@unittest.skipUnless(shutil.which("dpkg-deb"), "dpkg-deb is required for real package checks")
class WordlistPackageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "input"
        keyboard = self.source / "Passwords/Keyboard-Walks/walk-the-line.txt"
        keyboard.parent.mkdir(parents=True)
        keyboard.write_bytes(b"qwerty\nasdfgh\n")
        (self.source / "LICENSE").write_text(LICENSE)
        (self.source / "NOTICE.custom").write_text("File-specific terms must survive.\n")
        (self.source / "keyboard-link.txt").symlink_to("Passwords/Keyboard-Walks/walk-the-line.txt")
        self.output = self.root / "output"

    def build(self, *extra: str, output: Path | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(BUILDER), "--source", str(self.source), "--output", str(output or self.output),
             "--version", VERSION, *extra],
            text=True, capture_output=True, check=False,
        )

    def assert_builds(self) -> Path:
        result = self.build()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        return self.output / f"{PACKAGE}.deb"

    def test_package_has_honest_identity_and_preserves_data_and_terms(self) -> None:
        package = self.assert_builds()
        fields = subprocess.check_output(
            ["dpkg-deb", "--field", str(package), "Package", "Source", "Version", "Architecture",
             "Provides", "Conflicts", "Replaces"], text=True,
        )
        for field in (
            f"Package: {PACKAGE}", f"Source: {PACKAGE}", f"Version: {VERSION}", "Architecture: all",
            "Provides: seclists, wordlists", "Conflicts: seclists, wordlists", "Replaces: seclists, wordlists",
        ):
            self.assertIn(field, fields)
        extracted = self.root / "binary"
        subprocess.run(["dpkg-deb", "--extract", str(package), str(extracted)], check=True, capture_output=True)
        data = extracted / "usr/share/seclists"
        self.assertEqual((data / "LICENSE").read_text(), LICENSE)
        self.assertEqual((data / "NOTICE.custom").read_bytes(), (self.source / "NOTICE.custom").read_bytes())
        self.assertTrue((data / "keyboard-link.txt").is_symlink())
        self.assertEqual((data / "keyboard-link.txt").read_bytes(), b"qwerty\nasdfgh\n")
        wordlists = extracted / "usr/share/wordlists"
        self.assertEqual((wordlists / "opencyber-keyboard-patterns.txt").read_bytes(), b"qwerty\nasdfgh\n")
        self.assertEqual(os.readlink(wordlists / "seclists"), "/usr/share/seclists")
        documentation = extracted / f"usr/share/doc/{PACKAGE}"
        self.assertIn(LICENSE, (documentation / "copyright").read_text())
        self.assertEqual((documentation / "LICENSE").read_text(), LICENSE)
        self.assertEqual((documentation / "LICENSE.packaging").read_bytes(), (ROOT / "LICENSE").read_bytes())
        provenance = json.loads((documentation / "provenance.json").read_text())
        self.assertEqual(provenance["package"], PACKAGE)
        self.assertEqual(provenance["version"], VERSION)
        self.assertEqual(provenance["upstream_release"], "2026.1")
        self.assertNotIn(str(self.root), json.dumps(provenance))

    @unittest.skipUnless(shutil.which("dpkg-source") and shutil.which("dpkg-buildpackage"), "Debian source tools required")
    def test_native_source_checksums_extract_and_rebuild_the_exact_binary(self) -> None:
        package = self.assert_builds()
        source_directory = self.output / "source"
        descriptor = source_directory / f"{PACKAGE}_{VERSION}.dsc"
        archive = source_directory / f"{PACKAGE}_{VERSION}.tar.gz"
        text = descriptor.read_text()
        self.assertIn("Format: 3.0 (native)\n", text)
        self.assertIn(f"Source: {PACKAGE}\n", text)
        self.assertIn(f"Version: {VERSION}\n", text)
        payload = archive.read_bytes()
        self.assertIn(f" {hashlib.sha256(payload).hexdigest()} {len(payload)} {archive.name}\n", text)
        self.assertIn(f" {hashlib.md5(payload, usedforsecurity=False).hexdigest()} {len(payload)} {archive.name}\n", text)
        with tarfile.open(archive) as source:
            names = source.getnames()
            prefix = f"{PACKAGE}-{VERSION}"
            builder = source.extractfile(f"{prefix}/scripts/{BUILDER.name}")
            self.assertIsNotNone(builder)
            self.assertEqual(builder.read(), BUILDER.read_bytes())
            self.assertEqual(source.extractfile(f"{prefix}/LICENSE").read(), (ROOT / "LICENSE").read_bytes())
            self.assertTrue(all(name == prefix or name.startswith(prefix + "/") for name in names))
            self.assertFalse(any("rockyou" in name.casefold() for name in names))
            self.assertTrue(all(member.uid == member.gid == 0 for member in source))
        rebuilt_source = self.root / "rebuilt"
        extraction = subprocess.run(
            ["dpkg-source", "--no-check", "-x", str(descriptor), str(rebuilt_source)],
            text=True, capture_output=True, check=False,
        )
        self.assertEqual(extraction.returncode, 0, extraction.stdout + extraction.stderr)
        self.assertEqual((rebuilt_source / "seclists/NOTICE.custom").read_text(), "File-specific terms must survive.\n")
        rebuild = subprocess.run(
            ["dpkg-buildpackage", "-us", "-uc", "-b"], cwd=rebuilt_source,
            text=True, capture_output=True, check=False,
        )
        self.assertEqual(rebuild.returncode, 0, rebuild.stdout + rebuild.stderr)
        self.assertEqual((self.root / f"{PACKAGE}_{VERSION}_all.deb").read_bytes(), package.read_bytes())

    def test_repeated_builds_are_identical(self) -> None:
        self.assert_builds()
        for path in self.source.rglob("*"):
            os.utime(path, (987654321, 987654321), follow_symlinks=False)
        second_output = self.root / "second"
        result = self.build(output=second_output)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for path in self.output.rglob("*"):
            if path.is_file():
                self.assertEqual(path.read_bytes(), (second_output / path.relative_to(self.output)).read_bytes(), path.name)

    def test_rejects_rockyou_in_any_input_path(self) -> None:
        forbidden = self.source / "Passwords/Other/ROCKYOU-corpus.txt"
        forbidden.parent.mkdir()
        forbidden.write_text("must never be packaged\n")
        result = self.build()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("rockyou", result.stderr.casefold())
        self.assertFalse(self.output.exists())

    def test_rejects_output_inside_source_before_writing(self) -> None:
        result = self.build(output=self.source / "generated")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("output", result.stderr.casefold())
        self.assertFalse((self.source / "generated").exists())

    def test_rejects_escaping_and_absolute_symlinks(self) -> None:
        for target in ("../private.txt", "/etc/passwd"):
            with self.subTest(target=target):
                link = self.source / "unsafe"
                link.symlink_to(target)
                result = self.build()
                link.unlink()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("symlink", result.stderr.casefold())
                self.assertFalse(self.output.exists())

    def test_rejects_native_version_path_traversal(self) -> None:
        result = self.build("--version", "1/../../escape")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("version", result.stderr.casefold())
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
