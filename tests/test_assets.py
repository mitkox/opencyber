from __future__ import annotations

import gzip
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

import opencyber.assets as assets
import opencyber.cve_index as cve_index
import opencyber.native_tools as native_tools
from opencyber.assets import AssetSpec, assets_status, offline_status, require_online, verify_manifest


class AssetTests(unittest.TestCase):
    def test_deep_verification_refuses_a_missing_content_hash(self):
        manifest = self.root / "deep-manifest.json"
        manifest.write_text(json.dumps({"assets": {"tree": {"count": 2, "bytes": 6, "sha256": "a" * 64}}}))
        status = {"assets": [{"name": "tree", "count": 2, "bytes": 6, "sha256": None}]}
        with patch.object(assets, "MANIFEST_PATH", manifest), patch.object(assets, "assets_status", return_value=status):
            self.assertFalse(verify_manifest(deep=True)["valid"])

    def test_bundled_integrations_require_their_offline_assets(self):
        specs = {spec.name: spec for spec in assets.ASSET_SPECS}
        self.assertTrue(specs["nmap-scripts"].required)
        self.assertTrue(specs["baseline-password-dictionary"].required)
        self.assertFalse(specs["rockyou"].required)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.tree = self.root / "tree"
        (self.tree / "nested").mkdir(parents=True)
        (self.tree / "one.txt").write_text("one", encoding="utf-8")
        (self.tree / "nested" / "two.txt").write_text("two", encoding="utf-8")
        self.file = self.root / "rockyou.txt"
        self.file.write_text("password\n", encoding="utf-8")

    def tearDown(self):
        self.temporary.cleanup()

    def specs(self):
        return (
            AssetSpec("tree", self.tree, "tree", min_count=2, min_bytes=6, required=True),
            AssetSpec("file", self.file, "file", min_bytes=1, required=True),
            AssetSpec("optional", self.root / "missing", "tree", min_count=1, required=False),
        )

    def test_assets_status_requires_counts_and_sizes(self):
        status = assets_status(specs=self.specs())
        self.assertTrue(status["ready"])
        self.assertEqual(status["missing_optional"], ["optional"])
        by_name = {entry["name"]: entry for entry in status["assets"]}
        self.assertEqual(by_name["tree"]["count"], 2)
        self.assertTrue(by_name["file"]["ok"])

    def test_deep_status_hashes_tree_contents(self):
        before = assets_status(deep=True, specs=self.specs())
        before_hash = next(entry["sha256"] for entry in before["assets"] if entry["name"] == "tree")
        (self.tree / "one.txt").write_text("changed", encoding="utf-8")
        after = assets_status(deep=True, specs=self.specs())
        after_hash = next(entry["sha256"] for entry in after["assets"] if entry["name"] == "tree")
        self.assertNotEqual(before_hash, after_hash)

    def test_manifest_detects_truncation(self):
        manifest = self.root / "manifest.json"
        manifest.write_text(
            json.dumps(
                {
                    "assets": {
                        "tree": {"count": 2, "bytes": 6},
                        "file": {"count": 1, "bytes": 9},
                    }
                }
            ),
            encoding="utf-8",
        )
        with patch.object(assets, "ASSET_SPECS", self.specs()), patch.object(
            assets, "MANIFEST_PATH", manifest
        ):
            report = verify_manifest()
            self.assertTrue(report["valid"])
            (self.tree / "one.txt").unlink()
            broken = verify_manifest()
            self.assertFalse(broken["valid"])
            self.assertTrue(broken["mismatches"])

    def test_deep_manifest_verification_detects_content_changes(self):
        specs = self.specs()
        current = assets_status(deep=True, specs=specs)
        manifest = self.root / "deep-manifest.json"
        manifest.write_text(
            json.dumps(
                {
                    "assets": {
                        entry["name"]: {
                            "count": entry["count"],
                            "bytes": entry["bytes"],
                            "sha256": entry["sha256"],
                        }
                        for entry in current["assets"]
                    }
                }
            ),
            encoding="utf-8",
        )
        with patch.object(assets, "ASSET_SPECS", specs), patch.object(
            assets, "MANIFEST_PATH", manifest
        ):
            self.assertTrue(verify_manifest(deep=True)["valid"])
            (self.tree / "one.txt").write_text("different", encoding="utf-8")
            broken = verify_manifest(deep=True)
            self.assertFalse(broken["valid"])
            self.assertTrue(any(item.get("field") == "sha256" for item in broken["mismatches"]))

    def test_offline_mode_blocks_internet_only_features(self):
        with patch.dict("os.environ", {"OPENCYBER_OFFLINE": "1"}):
            self.assertTrue(assets.offline_enabled())
            with self.assertRaises(ValueError):
                require_online("oc_hibp_password_check")
            status = offline_status()
            self.assertEqual(status["mode"], "airgapped")
            self.assertTrue(status["internet_dependent_features"])

    def test_local_cve_database_is_used_offline(self):
        database = self.root / "cve.sqlite"
        connection = sqlite3.connect(database)
        connection.execute(
            "CREATE TABLE cves (cve_id TEXT PRIMARY KEY, description TEXT, cvss REAL, published TEXT, json TEXT)"
        )
        connection.execute(
            "INSERT INTO cves VALUES (?, ?, ?, ?, ?)",
            ("CVE-2026-1234", "Fixture vulnerability", 9.8, "2026-01-01", json.dumps({"id": "CVE-2026-1234"})),
        )
        connection.commit()
        connection.close()
        with patch.object(native_tools, "local_cve_db", return_value=database), patch.dict(
            "os.environ", {"OPENCYBER_OFFLINE": "1"}
        ):
            result = native_tools.lookup_cve("cve-2026-1234")
        self.assertEqual(result["source"], "local-sqlite")
        self.assertTrue(result["found"])
        self.assertEqual(result["cvss"], 9.8)

    def test_offline_cve_lookup_without_database_fails_fast(self):
        with patch.object(native_tools, "local_cve_db", return_value=self.root / "absent.sqlite"), patch.dict(
            "os.environ", {"OPENCYBER_OFFLINE": "1"}
        ):
            with self.assertRaises(ValueError):
                native_tools.lookup_cve("CVE-2026-9999")

    def test_cve_index_builds_and_verifies_a_feed(self):
        feed = self.root / "nvdcve-2.0-2026.json.gz"
        document = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2026-1234",
                        "published": "2026-01-01T00:00:00.000",
                        "descriptions": [{"lang": "en", "value": "Fixture vulnerability"}],
                        "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]},
                    }
                }
            ]
        }
        raw = json.dumps(document).encode()
        with gzip.open(feed, "wb") as handle:
            handle.write(raw)
        meta = self.root / "nvdcve-2.0-2026.meta"
        expected_sha256 = __import__("hashlib").sha256(raw).hexdigest()
        meta.write_text(f"size:{len(raw)}\nsha256:{expected_sha256}\n", encoding="utf-8")
        cve_index.verify_feed(feed, expected_sha256)
        output = self.root / "cve.sqlite"
        result = cve_index.build_index([feed], output)
        self.assertEqual(result["records"], 1)
        with sqlite3.connect(output) as connection:
            row = connection.execute("SELECT cve_id, cvss FROM cves").fetchone()
        self.assertEqual(row, ("CVE-2026-1234", 9.8))
        with patch.object(native_tools, "local_cve_db", return_value=output):
            lookup = native_tools.lookup_cve("CVE-2026-1234")
        self.assertTrue(lookup["found"])
        self.assertEqual(lookup["cvss"], 9.8)

    def test_cve_index_rejects_a_bad_checksum(self):
        feed = self.root / "bad.json.gz"
        with gzip.open(feed, "wb") as handle:
            handle.write(b"{}")
        with self.assertRaises(ValueError):
            cve_index.verify_feed(feed, "0" * 64)


if __name__ == "__main__":
    unittest.main()
