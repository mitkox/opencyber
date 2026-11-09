from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import io
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from scripts.lib.release_candidates import fetch_selection, immutable_bytes, safe_extract, upload_assets, validate_candidate_run


class CandidateIdentityTests(unittest.TestCase):
    def fixtures(self):
        run = {
            "id": 12, "run_attempt": 2, "workflow_id": 99,
            "status": "completed", "conclusion": "success", "event": "workflow_dispatch",
            "head_sha": "a" * 40, "path": ".github/workflows/build-candidate.yml",
            "repository": {"id": 42, "full_name": "owner/public"},
            "head_repository": {"id": 42},
        }
        artifacts = [{
            "id": index, "name": "release-evidence-" + arch,
            "expired": False, "digest": "sha256:" + str(index) * 64,
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=20)).isoformat(),
            "workflow_run": {"id": 12, "repository_id": 42, "head_sha": "a" * 40},
        } for index, arch in ((1, "amd64"),)]
        return run, artifacts

    def validate(self, run, artifacts):
        return validate_candidate_run(run, artifacts, repository="owner/public", repository_id=42,
                                      commit="a" * 40, workflow_id=99, run_id=12)

    def test_only_successful_canonical_build_and_exact_artifacts_are_selected(self):
        run, artifacts = self.fixtures()
        selected = self.validate(run, artifacts + [{"name": "coverage-xml"}])
        self.assertEqual([a["id"] for a in selected], [1])

    def test_wrong_identity_incomplete_or_replaced_run_is_rejected(self):
        run, artifacts = self.fixtures()
        changes = [
            {"id": 13}, {"run_attempt": 0}, {"conclusion": "failure"},
            {"status": "in_progress"}, {"event": "pull_request"}, {"head_sha": "b" * 40},
            {"repository": {"id": 7, "full_name": "owner/public"}},
            {"head_repository": {"id": 7}}, {"workflow_id": 100},
            {"path": ".github/workflows/ci.yml"},
        ]
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.validate(dict(run, **change), artifacts)

    def test_missing_duplicate_expired_or_unchecksummed_artifacts_are_rejected(self):
        run, artifacts = self.fixtures()
        bad = []
        for field, value in (("expired", True), ("digest", ""), ("id", 0),
                             ("expires_at", "2000-01-01T00:00:00+00:00"),
                             ("workflow_run", {"id": 13, "repository_id": 42, "head_sha": "a" * 40})):
            changed = deepcopy(artifacts)
            changed[0][field] = value
            bad.append(changed)
        bad.extend([[], artifacts + [artifacts[0]]])
        for changed in bad:
            with self.subTest(artifacts=changed), self.assertRaises(ValueError):
                self.validate(run, changed)

    def test_retries_allow_identical_bytes_and_reject_replacement(self):
        self.assertTrue(immutable_bytes(None, b"qualified", "asset"))
        self.assertFalse(immutable_bytes(b"qualified", b"qualified", "asset"))
        with self.assertRaisesRegex(ValueError, "immutable"):
            immutable_bytes(b"qualified", b"different", "asset")

    def archive(self, name, mode=0o100644):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            member = zipfile.ZipInfo(name)
            member.external_attr = mode << 16
            archive.writestr(member, b"evidence")
        return buffer.getvalue()

    def test_archive_extraction_rejects_escape_symlink_and_duplicate_members(self):
        for name, mode in (("../escape", 0o100644), ("/escape", 0o100644), ("link", 0o120777)):
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                archive = Path(directory) / "artifact.zip"
                archive.write_bytes(self.archive(name, mode))
                with self.assertRaises(ValueError):
                    safe_extract(archive, Path(directory) / "evidence")

    def test_valid_artifact_is_extracted(self):
        with tempfile.TemporaryDirectory() as directory:
            archive = Path(directory) / "artifact.zip"
            archive.write_bytes(self.archive("evidence/receipt.json"))
            safe_extract(archive, Path(directory) / "out")
            self.assertEqual((Path(directory) / "out/evidence/receipt.json").read_bytes(), b"evidence")

    def test_same_source_rerun_cannot_replace_selected_attempt(self):
        import hashlib
        import json

        with tempfile.TemporaryDirectory() as directory:
            selected = {"run_id": 12, "run_attempt": 1}
            path = Path(directory) / "selection.json"
            path.write_text(json.dumps(selected))
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            with patch("scripts.lib.release_candidates.selection_for", return_value=dict(selected, run_attempt=2)):
                with self.assertRaisesRegex(ValueError, "selection changed"):
                    fetch_selection(path, digest, Path(directory) / "out", repository="owner/public",
                                    run_id=12, commit="a" * 40)
            self.assertFalse((Path(directory) / "out").exists())

    def test_existing_release_asset_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            (Path(directory) / "source.tar").write_bytes(b"changed")
            metadata = {"assets": [{"name": "source.tar", "digest": "sha256:" + "a" * 64}]}
            with patch("scripts.lib.release_candidates.api", return_value=metadata), \
                 patch("scripts.lib.release_candidates.subprocess.run") as mutation:
                with self.assertRaisesRegex(ValueError, "immutable"):
                    upload_assets("owner/public", "v0.5.0", Path(directory))
                mutation.assert_not_called()
