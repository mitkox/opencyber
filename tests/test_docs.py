from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess
import sys
import unittest


ROOT = Path(__file__).resolve().parents[1]
DOCS = ROOT / "docs"
LAUNCH_DOCS = [
    ROOT / "README.md",
    ROOT / "AGENTS.md",
    ROOT / "CONTRIBUTING.md",
    ROOT / "SECURITY.md",
    ROOT / "CODE_OF_CONDUCT.md",
    ROOT / "CHANGELOG.md",
    ROOT / "SUPPORT.md",
    *sorted(DOCS.glob("*.md")),
]

LINK_PATTERN = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
ENV_PATTERN = re.compile(r"\bOPENCYBER_[A-Z0-9_]+\b")


class DocumentationTests(unittest.TestCase):
    def test_generated_tool_reference_is_current(self) -> None:
        result = subprocess.run(
            [sys.executable, str(ROOT / "scripts" / "generate-tool-docs.py"), "--check"],
            cwd=ROOT,
            env={"PYTHONPATH": str(ROOT / "src"), "PATH": "/usr/bin:/bin"},
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_relative_markdown_links_resolve(self) -> None:
        missing: list[str] = []
        for document in LAUNCH_DOCS:
            if not document.is_file():
                continue
            for target in LINK_PATTERN.findall(document.read_text(encoding="utf-8")):
                if target.startswith(("http://", "https://", "mailto:", "#")):
                    continue
                path = target.split("#", 1)[0].split("?", 1)[0]
                if not path:
                    continue
                resolved = (document.parent / path).resolve()
                if not resolved.exists():
                    missing.append(f"{document.relative_to(ROOT)} -> {target}")
        self.assertEqual(missing, [], "broken relative links")

    def test_configuration_documents_every_runtime_variable(self) -> None:
        configuration = (DOCS / "CONFIGURATION.md").read_text(encoding="utf-8")
        documented = set(ENV_PATTERN.findall(configuration))

        sources = sorted((ROOT / "src" / "opencyber").glob("*.py"))
        sources += [ROOT / "install.sh", *sorted((ROOT / "scripts").glob("*.sh")), ROOT / "Dockerfile"]
        referenced: set[str] = set()
        for source in sources:
            referenced.update(ENV_PATTERN.findall(source.read_text(encoding="utf-8", errors="ignore")))

        self.assertEqual(sorted(referenced - documented), [], "undocumented OPENCYBER_* variables")

    def test_security_model_discloses_known_limitations(self) -> None:
        text = (DOCS / "SECURITY_MODEL.md").read_text(encoding="utf-8")
        for claim in (
            "oc_http_request",
            "oc_graphql_request",
            "OPENCYBER_ENFORCE_SCOPE",
            "--no-sandbox",
            "OPENCYBER_AUDIT=0",
            "environment",
            "unredacted",
            "offline",
        ):
            self.assertIn(claim, text.replace("`", ""), f"security model omits {claim}")

    def test_optional_development_verification_records_pair_with_evidence(self) -> None:
        records = sorted((DOCS / "verification").glob("*.md"))
        for record in records:
            text = record.read_text(encoding="utf-8")
            evidence = record.with_suffix(".json")
            self.assertTrue(evidence.is_file(), f"{record.name} has no machine-readable evidence")
            self.assertIn(evidence.name, text, f"{record.name} does not link {evidence.name}")
            json.loads(evidence.read_text(encoding="utf-8"))
            self.assertIn("What this does not establish", text)

    def test_launch_docs_have_no_placeholders(self) -> None:
        offenders: list[str] = []
        for document in LAUNCH_DOCS:
            if not document.is_file():
                continue
            for number, line in enumerate(document.read_text(encoding="utf-8").splitlines(), 1):
                if re.search(r"\b(TODO|TBD|FIXME|XXX|PLACEHOLDER)\b", line):
                    offenders.append(f"{document.relative_to(ROOT)}:{number}: {line.strip()}")
        self.assertEqual(offenders, [])


if __name__ == "__main__":
    unittest.main()
