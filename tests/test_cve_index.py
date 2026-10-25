from __future__ import annotations

from contextlib import redirect_stdout
import gzip
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from opencyber import cve_index


class NvdFeedTests(unittest.TestCase):
    def feed(self, root: Path, *, compressed: bool = True) -> tuple[Path, bytes]:
        raw = json.dumps({"vulnerabilities": []}).encode("utf-8")
        path = root / ("nvdcve-2.0-2025.json.gz" if compressed else "nvdcve-2.0-2025.json")
        path.write_bytes(gzip.compress(raw) if compressed else raw)
        return path, raw

    def metadata(self, raw: bytes, *, digest: str | None = None) -> bytes:
        checksum = digest if digest is not None else hashlib.sha256(raw).hexdigest().upper()
        return ("lastModifiedDate:2026-10-23T03:01:05-04:00\r\n"
                f"size:{len(raw)}\r\nzipSize:123\r\ngzSize:111\r\nsha256:{checksum}\r\n").encode()

    def cli(self, *arguments: str) -> None:
        with patch("sys.argv", ["opencyber.cve_index", *arguments]), redirect_stdout(io.StringIO()):
            cve_index.main()

    def test_gzip_checksum_is_over_the_uncompressed_feed(self):
        with tempfile.TemporaryDirectory() as temporary:
            feed, raw = self.feed(Path(temporary))
            cve_index.verify_feed(feed, hashlib.sha256(raw).hexdigest())
            with self.assertRaisesRegex(ValueError, "checksum mismatch"):
                cve_index.verify_feed(feed, hashlib.sha256(feed.read_bytes()).hexdigest())

    def test_download_uses_canonical_metadata_url_and_plaintext(self):
        raw = json.dumps({"vulnerabilities": []}).encode()
        requested = []

        def fetch(request, timeout):
            requested.append(request.full_url)
            if request.full_url.endswith("nvdcve-2.0-2025.json.gz"):
                return io.BytesIO(gzip.compress(raw))
            self.assertTrue(request.full_url.endswith("nvdcve-2.0-2025.meta"), request.full_url)
            return io.BytesIO(self.metadata(raw))

        with tempfile.TemporaryDirectory() as temporary, patch.object(cve_index, "urlopen", side_effect=fetch):
            root = Path(temporary)
            feed = cve_index.download_feed(2025, root)
            self.assertEqual(gzip.decompress(feed.read_bytes()), raw)
            self.assertTrue((root / "nvdcve-2.0-2025.meta").is_file())
        self.assertEqual(requested, [
            "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2025.json.gz",
            "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-2025.meta",
        ])

    def test_local_compressed_and_plain_feeds_use_adjacent_canonical_metadata(self):
        for compressed in (True, False):
            with self.subTest(compressed=compressed), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                feed, raw = self.feed(root, compressed=compressed)
                (root / "nvdcve-2.0-2025.meta").write_bytes(self.metadata(raw))
                output = root / "cve.sqlite"
                self.cli("--feed", str(feed), "--output", str(output))
                self.assertTrue(output.is_file())

    def test_missing_malformed_or_wrong_local_metadata_blocks_index_creation(self):
        for content in (None, b"size:25\n", b"sha256:not-a-digest\n", self.metadata(b"", digest="0" * 64)):
            with self.subTest(content=content), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                feed, _ = self.feed(root)
                if content is not None:
                    (root / "nvdcve-2.0-2025.meta").write_bytes(content)
                output = root / "cve.sqlite"
                with self.assertRaises((ValueError, SystemExit)):
                    self.cli("--feed", str(feed), "--output", str(output))
                self.assertFalse(output.exists())

    def test_local_unverified_feed_requires_explicit_opt_out(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            feed, _ = self.feed(root)
            output = root / "cve.sqlite"
            self.cli("--feed", str(feed), "--no-verify", "--output", str(output))
            self.assertTrue(output.is_file())

    def test_download_opt_out_does_not_request_metadata(self):
        raw = json.dumps({"vulnerabilities": []}).encode()
        with tempfile.TemporaryDirectory() as temporary, patch.object(
            cve_index, "urlopen", return_value=io.BytesIO(gzip.compress(raw))
        ) as fetch:
            root = Path(temporary)
            self.cli("--year", "2025", "--download-dir", str(root), "--no-verify",
                     "--output", str(root / "cve.sqlite"))
            self.assertEqual(fetch.call_count, 1)
