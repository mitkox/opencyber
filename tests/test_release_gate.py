from __future__ import annotations

from datetime import date, timedelta
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location("release_gate", Path(__file__).resolve().parents[1] / "scripts/release-gate.py")
assert SPEC and SPEC.loader
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)
PROMOTION_SPEC = importlib.util.spec_from_file_location("promote_images", Path(__file__).resolve().parents[1] / "scripts/promote-images.py")
assert PROMOTION_SPEC and PROMOTION_SPEC.loader
promotion = importlib.util.module_from_spec(PROMOTION_SPEC)
PROMOTION_SPEC.loader.exec_module(promotion)


class ReleaseGateTests(unittest.TestCase):
    def test_containerd_manifest_id_binds_the_exact_staged_manifest(self):
        manifest_digest, config_digest = "sha256:" + "a" * 64, "sha256:" + "b" * 64
        with tempfile.TemporaryDirectory() as directory:
            source, output = Path(directory) / "source.json", Path(directory) / "candidate.record.json"
            source.write_text("source receipt")
            responses = [json.dumps([{"Id": manifest_digest, "Descriptor": {
                "mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": manifest_digest}}]).encode(),
                json.dumps({"Digest": manifest_digest, "Os": "linux", "Architecture": "amd64"}).encode(),
                json.dumps({"config": {"digest": config_digest}}).encode(),
                json.dumps({"catalog": {"matches": True, "advertised_sha256": "c" * 64}}).encode()]
            env = {"GITHUB_REPOSITORY_ID": "10", "GITHUB_RUN_ID": "20", "GITHUB_RUN_ATTEMPT": "1"}
            with patch.object(gate, "command", side_effect=responses), \
                 patch.object(gate, "verify_source_receipt"), patch.dict("os.environ", env):
                gate.record_image("candidate", "ghcr.io/owner/staging:tag", "linux/amd64", source, "commit", output)
            record = json.loads(output.read_text())
            self.assertEqual(record["image_id"], manifest_digest)
            self.assertEqual(record["config_digest"], config_digest)

    def test_containerd_descriptor_cannot_accept_a_substituted_manifest(self):
        tested, substituted, config = ("sha256:" + value * 64 for value in "abc")
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "candidate.record.json"
            responses = [json.dumps([{"Id": tested, "Descriptor": {
                "mediaType": "application/vnd.oci.image.manifest.v1+json", "digest": tested}}]).encode(),
                json.dumps({"Digest": substituted, "Os": "linux", "Architecture": "amd64"}).encode(),
                json.dumps({"config": {"digest": config}}).encode()]
            with patch.object(gate, "command", side_effect=responses), patch.object(gate, "verify_source_receipt"):
                with self.assertRaises(ValueError):
                    gate.record_image("candidate", "ghcr.io/owner/staging:tag", "linux/amd64",
                                      Path("source"), "commit", output)
            self.assertFalse(output.exists())

    def test_staged_config_or_platform_mismatch_cannot_produce_a_receipt(self):
        digest = "sha256:" + "a" * 64
        for config, architecture in (("sha256:" + "b" * 64, "amd64"), (digest, "arm64")):
            with self.subTest(config=config, architecture=architecture), tempfile.TemporaryDirectory() as directory:
                output = Path(directory) / "candidate.record.json"
                responses = [json.dumps([{"Id": digest}]).encode(),
                             json.dumps({"Digest": digest, "Os": "linux", "Architecture": architecture}).encode(),
                             json.dumps({"config": {"digest": config}}).encode()]
                with patch.object(gate, "command", side_effect=responses), patch.object(gate, "verify_source_receipt"):
                    with self.assertRaises(ValueError):
                        gate.record_image("candidate", "ghcr.io/owner/staging:tag", "linux/amd64", Path("source"), "commit", output)
                self.assertFalse(output.exists())

    def test_bad_staging_reference_copy_digest_or_signing_failure_stops_promotion(self):
        digest = "sha256:" + "a" * 64
        records = [{"platform": "linux/amd64", "commit": "candidate", "digest": digest,
                    "staging_reference": "ghcr.io/owner/staging@" + digest}]
        for failure in ("reference", "copy_digest", "sign"):
            with self.subTest(failure=failure), tempfile.TemporaryDirectory() as directory:
                inputs, output = Path(directory) / "records.json", Path(directory) / "digests.json"
                selected = [dict(record) for record in records]
                if failure == "reference":
                    selected[0]["staging_reference"] = "ghcr.io/other/public@" + digest
                inputs.write_text(json.dumps(selected))
                env = {"GITHUB_SHA": "candidate", "GITHUB_REF_TYPE": "tag", "REGISTRY": "ghcr.io",
                       "IMAGE_NAME": "owner/public", "STAGING_NAME": "owner/staging", "GITHUB_OUTPUT": str(Path(directory) / "outputs")}
                def run(arguments, **kwargs):
                    if failure == "sign" and arguments[0] == "cosign":
                        raise subprocess.CalledProcessError(1, arguments)
                actual = ("sha256:" + "b" * 64) if failure == "copy_digest" else digest
                with patch.dict("os.environ", env), patch("sys.argv", ["promote-images.py", str(inputs), str(output)]), \
                     patch.object(promotion.subprocess, "run", side_effect=run) as calls, \
                     patch.object(promotion, "registry_digest", return_value=None, create=True), \
                     patch.object(promotion.subprocess, "check_output", return_value=actual + "\n"):
                    with self.assertRaises((SystemExit, subprocess.CalledProcessError)):
                        promotion.main()
                    commands = [call.args[0] for call in calls.call_args_list]
                    self.assertFalse(any(command[0] == "docker" for command in commands))
                    self.assertEqual(sum(command[:2] == ["skopeo", "copy"] for command in commands), 0 if failure == "reference" else 1)
                self.assertFalse(output.exists())

    def test_existing_version_reference_cannot_be_replaced(self):
        with patch.object(promotion, "registry_digest", return_value="sha256:" + "a" * 64, create=True), \
             patch.object(promotion.subprocess, "run") as publish:
            with self.assertRaisesRegex(ValueError, "immutable"):
                promotion.ensure_version_tag("ghcr.io/owner/public:0.5.0", "sha256:" + "b" * 64)
            publish.assert_not_called()

    def test_identical_version_reference_is_an_idempotent_retry(self):
        digest = "sha256:" + "a" * 64
        with patch.object(promotion, "registry_digest", return_value=digest, create=True), \
             patch.object(promotion.subprocess, "run") as publish:
            promotion.ensure_version_tag("ghcr.io/owner/public:0.5.0", digest)
            publish.assert_not_called()

    def test_public_destination_requires_metadata_and_anonymous_access(self):
        for visibility, status in (("private", 0), ("public", 1)):
            with self.subTest(visibility=visibility, status=status), patch.object(
                gate, "command", return_value=json.dumps({"visibility": visibility}).encode()
            ), patch.object(gate.subprocess, "run", return_value=subprocess.CompletedProcess([], status, "", "denied")):
                with self.assertRaises(ValueError):
                    gate.verify_registry("owner/public", "ghcr.io/owner/public:bootstrap", "public")
        with patch.object(gate, "command", return_value=b'{"visibility":"public"}'), patch.object(
            gate.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "{}", "")
        ):
            gate.verify_registry("owner/public", "ghcr.io/owner/public:bootstrap", "public")

    def test_public_staging_is_rejected_before_accessing_candidate(self):
        with patch.object(gate, "command", return_value=b'{"visibility":"public"}'), patch.object(gate.subprocess, "run") as probe:
            with self.assertRaisesRegex(ValueError, "private"):
                gate.verify_staging("owner/staging", "ghcr.io/owner/staging:bootstrap")
            probe.assert_not_called()

    def test_user_staging_uses_user_package_metadata(self):
        def metadata(*args):
            if args != ("gh", "api", "users/mitkox/packages/container/opencyber-beta-candidates"):
                raise subprocess.CalledProcessError(404, args)
            return b'{"visibility":"private"}'

        with patch.object(gate, "command", side_effect=metadata), patch.object(
            gate.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", "unauthorized")
        ):
            gate.verify_staging("mitkox/opencyber-beta-candidates",
                                "ghcr.io/mitkox/opencyber-beta-candidates:bootstrap")

    def test_network_failure_does_not_prove_staging_privacy(self):
        with patch.object(gate, "command", return_value=b'{"visibility":"private"}'), patch.object(
            gate.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", "network timeout")
        ):
            with self.assertRaisesRegex(ValueError, "network errors"):
                gate.verify_staging("owner/staging", "ghcr.io/owner/staging:bootstrap")

    def receipts(self, root):
        for arch, character in (("amd64", "a"),):
            directory = root / arch
            directory.mkdir()
            image = "sha256:" + character * 64
            (directory / "corresponding-source.tar.gz").write_bytes(b"synthetic source archive")
            (directory / "source-manifest.json").write_text(json.dumps({"complete": True}))
            source = directory / "release-source-manifest.json"
            source.write_text(json.dumps({"complete": True, "image_id": image, "source_manifest_sha256": gate.file_sha256(directory / "source-manifest.json")}))
            (directory / "SOURCE-SHA256SUMS").write_text("".join(
                f"{gate.file_sha256(directory / name)}  {name}\n" for name in
                ("corresponding-source.tar.gz", "source-manifest.json", "release-source-manifest.json")
            ))
            (directory / (arch + ".record.json")).write_text(json.dumps({
                "platform": "linux/" + arch, "commit": "candidate", "image_id": image,
                "digest": image, "source_manifest": source.name,
                "source_manifest_sha256": hashlib.sha256(source.read_bytes()).hexdigest(),
            }))

    def test_amd64_and_exact_source_bytes_are_required(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.receipts(root)
            self.assertEqual(len(gate.validate_records(root, "candidate")), 1)
            with self.assertRaisesRegex(ValueError, "same commit"):
                gate.validate_records(root, "different")
            (root / "amd64/corresponding-source.tar.gz").write_bytes(b"tampered")
            with self.assertRaisesRegex(ValueError, "checksum"):
                gate.validate_records(root, "candidate")

    def test_amd64_receipt_is_required_for_promotion(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.receipts(root)
            (root / "amd64/amd64.record.json").unlink()
            with self.assertRaisesRegex(ValueError, "amd64"):
                gate.validate_records(root, "candidate")

    def test_vulnerability_exceptions_require_owner_reason_and_current_expiry(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "exceptions"
            path.write_text("CVE-2026-1234 # owner: @maintainer expires: 2000-01-01 reason: expired\n")
            with self.assertRaisesRegex(ValueError, "unexpired"):
                gate.verify_exceptions(path)
            path.write_text(f"CVE-2026-1234 # owner: @maintainer expires: {date.today() + timedelta(days=7)} reason: reviewed\n")
            gate.verify_exceptions(path)


if __name__ == "__main__":
    unittest.main()
