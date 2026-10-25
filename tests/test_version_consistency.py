from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path


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


if __name__ == "__main__":
    unittest.main()
