from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


SPEC = importlib.util.spec_from_file_location("public_snapshot", Path(__file__).resolve().parents[1] / "scripts/export-public-snapshot.py")
assert SPEC and SPEC.loader
snapshot = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(snapshot)


class PublicSnapshotTests(unittest.TestCase):
    def repository(self, root):
        subprocess.run(["git", "init", "-q", str(root)], check=True)
        subprocess.run(["git", "-C", str(root), "config", "user.name", "Snapshot test"], check=True)
        subprocess.run(["git", "-C", str(root), "config", "user.email", "snapshot@example.test"], check=True)
        (root / "README.md").write_text("public documentation\n")
        (root / "LICENSE").write_text("original attribution\n")
        (root / "AGENTS.md").write_text("public contributor instructions\n")
        (root / "install.sh").write_text("#!/bin/sh\nexit 0\n")
        (root / "install.sh").chmod(0o755)
        old = root / "docs/verification"
        old.mkdir(parents=True)
        (old / "private.json").write_text("historical internal evidence")
        self.commit(root)

    def commit(self, root):
        subprocess.run(["git", "-C", str(root), "add", "--all"], check=True)
        subprocess.run(["git", "-C", str(root), "commit", "-qm", "Snapshot fixture"], check=True)

    def test_only_reviewed_tracked_bytes_leave_without_git_history(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "development"
            root.mkdir()
            self.repository(root)
            output, manifest = Path(temporary) / "public", Path(temporary) / "manifest.json"
            snapshot.export(root, output, manifest)
            self.assertEqual((output / "LICENSE").read_text(), "original attribution\n")
            self.assertFalse((output / ".git").exists())
            self.assertFalse((output / "docs/verification").exists())
            self.assertEqual({x["path"] for x in json.loads(manifest.read_text())["files"]},
                             {"README.md", "LICENSE", "AGENTS.md", "install.sh"})
            self.assertEqual((output / "install.sh").stat().st_mode & 0o777, 0o755)

    def test_dirty_unknown_or_symlinked_tracked_material_blocks_export(self):
        for kind in ("dirty", "unknown", "symlink"):
            with self.subTest(kind=kind), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary) / "development"
                root.mkdir()
                self.repository(root)
                if kind == "dirty":
                    (root / "README.md").write_text("unreviewed edit")
                elif kind == "unknown":
                    (root / ".env").write_text("PRIVATE_FIXTURE=value")
                    self.commit(root)
                else:
                    (root / "README.md").unlink()
                    (root / "README.md").symlink_to("LICENSE")
                    self.commit(root)
                output = Path(temporary) / "public"
                with self.assertRaises(ValueError):
                    snapshot.export(root, output, Path(temporary) / "manifest.json")
                self.assertFalse(output.exists())
