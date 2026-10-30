from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock


ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "check-version-consistency.py"


class VersionConsistencyTests(unittest.TestCase):
    def test_declarations_agree(self) -> None:
        result = subprocess.run(
            [sys.executable, str(SCRIPT)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_pyproject_derives_the_version(self) -> None:
        text = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        self.assertIn('dynamic = ["version"]', text)
        self.assertIn('version = { attr = "opencyber.__version__" }', text)
        self.assertNotRegex(text, r'(?m)^version = "')

    def test_airgap_catalog_accepts_current_version_and_rejects_mismatch(self) -> None:
        spec = importlib.util.spec_from_file_location("airgap_tools_lab", ROOT / "scripts" / "airgap-tools-lab.py")
        assert spec is not None and spec.loader is not None
        lab = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(lab)
        # Binary availability has separate image acceptance; exercise the actual
        # installed-package subprocess and catalog alignment here.
        with mock.patch.object(lab, "REQUIRED_TOOLS", {}):
            result = lab.catalog_check()
            self.assertTrue(result["passed"], result)
            with mock.patch.object(lab, "EXPECTED_VERSION", "0.0.0"):
                result = lab.catalog_check()
                self.assertFalse(result["passed"], result)

    def test_airgap_image_accepts_current_version_and_rejects_mismatch(self) -> None:
        from opencyber import __version__

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            docker = root / "docker"
            docker.write_text(
                f"#!{sys.executable}\n"
                "import json, os, sys\n"
                "if sys.argv[1:3] == ['image', 'inspect']:\n"
                " print(json.dumps({'id': 'sha256:fixture', 'version': os.environ['TEST_IMAGE_VERSION']}))\n"
                "elif sys.argv[1] == 'run':\n"
                " print(json.dumps({'passed': True, 'checks': []}))\n",
                encoding="utf-8",
            )
            docker.chmod(0o755)
            for version, success in ((__version__, True), ("0.0.0", False)):
                with self.subTest(version=version):
                    result = subprocess.run(
                        ["bash", str(ROOT / "scripts" / "airgap-tools-image.sh"), "fixture", str(root / "report.json")],
                        env={**os.environ, "PATH": str(root) + os.pathsep + os.environ["PATH"],
                             "TMPDIR": str(root), "TEST_IMAGE_VERSION": version},
                        capture_output=True, text=True, check=False,
                    )
                    self.assertEqual(result.returncode == 0, success, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
