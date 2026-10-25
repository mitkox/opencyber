"""Build a small local CVE index for airgapped ``oc_cve_lookup``.

The index is deliberately minimal: id, English description, CVSS base score,
published timestamp, and the original NVD record as JSON. It is not a
replacement for exploitdb, nuclei, or Metasploit; it is the offline fallback
for "what is this CVE?" questions.

Build on a connected host, then copy the SQLite file into the image or mount it
at ``OPENCYBER_CVE_DB``. Feeds are verified against the SHA-256 published in the
NVD ``.meta`` file before parsing.
"""

from __future__ import annotations

from datetime import datetime, timezone
import gzip
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import tempfile
from typing import Any, Iterable, Iterator
from urllib.request import Request, urlopen

from . import __version__


NVD_FEED = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.json.gz"
NVD_META = "https://nvd.nist.gov/feeds/json/cve/2.0/nvdcve-2.0-{year}.meta"
USER_AGENT = f"opencyber-cve-index/{__version__}"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _english_description(cve: dict[str, Any]) -> str:
    for description in cve.get("descriptions", []):
        if description.get("lang") == "en":
            return str(description.get("value", ""))
    return ""


def _cvss_score(cve: dict[str, Any]) -> float | None:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key) or []
        if not entries:
            continue
        for entry in entries:
            data = entry.get("cvssData") or {}
            score = data.get("baseScore")
            if isinstance(score, (int, float)):
                return float(score)
    return None


def iter_feed(path: Path) -> Iterator[dict[str, Any]]:
    """Yield normalized records from an NVD 2.0 gzip or plain JSON feed."""
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rt", encoding="utf-8") as handle:
        document = json.load(handle)
    for item in document.get("vulnerabilities", []):
        cve = item.get("cve") or {}
        cve_id = cve.get("id")
        if not cve_id:
            continue
        yield {
            "cve_id": cve_id,
            "description": _english_description(cve),
            "cvss": _cvss_score(cve),
            "published": cve.get("published"),
            "json": json.dumps(item, sort_keys=True, separators=(",", ":")),
        }


def verify_feed(path: Path, expected_sha256: str) -> None:
    """Check the uncompressed JSON bytes described by NVD's metadata."""
    if not isinstance(expected_sha256, str) or not re.fullmatch(r"[a-fA-F0-9]{64}", expected_sha256):
        raise ValueError("NVD metadata must contain a valid SHA-256 checksum")
    digest = hashlib.sha256()
    opener = gzip.open if path.suffix == ".gz" else open
    with opener(path, "rb") as handle:
        while chunk := handle.read(1024 * 1024):
            digest.update(chunk)
    actual = digest.hexdigest()
    if actual.lower() != expected_sha256.lower():
        raise ValueError(
            f"feed checksum mismatch for {path}: expected {expected_sha256}, got {actual}"
        )


def _meta_sha256(meta: str) -> str:
    """Read the single SHA-256 field from NVD's key:value plaintext."""
    checksums = []
    for line in meta.splitlines():
        key, separator, value = line.partition(":")
        if separator and key.strip().lower() == "sha256":
            checksums.append(value.strip())
    if len(checksums) != 1 or not re.fullmatch(r"[a-fA-F0-9]{64}", checksums[0]):
        raise ValueError("NVD metadata must contain one valid SHA-256 checksum")
    return checksums[0]


def _metadata_path(feed: Path) -> Path:
    plain = feed.with_suffix("") if feed.suffix == ".gz" else feed
    return plain.with_suffix(".meta")


def _verify_metadata(feed: Path) -> None:
    meta_path = _metadata_path(feed)
    try:
        expected = _meta_sha256(meta_path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError) as exc:
        raise ValueError(
            f"cannot verify {feed}: valid adjacent NVD metadata is required at {meta_path}; "
            "use --no-verify only to explicitly allow unverified input"
        ) from exc
    verify_feed(feed, expected)


def download_feed(year: int, directory: Path, timeout: float = 120.0, *, verify: bool = True) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    feed_path = directory / f"nvdcve-2.0-{year}.json.gz"
    downloads = [(NVD_FEED.format(year=year), feed_path)]
    if verify:
        downloads.append((NVD_META.format(year=year), _metadata_path(feed_path)))
    for url, target in downloads:
        request = Request(url, headers={"User-Agent": USER_AGENT})
        with urlopen(request, timeout=timeout) as response, target.open("wb") as output:
            while chunk := response.read(1024 * 1024):
                output.write(chunk)
    if verify:
        _verify_metadata(feed_path)
    return feed_path


def build_index(
    feeds: Iterable[Path],
    output: Path,
    max_records: int | None = None,
) -> dict[str, Any]:
    output.parent.mkdir(parents=True, exist_ok=True)
    temporary = output.with_suffix(output.suffix + ".tmp")
    if temporary.exists():
        temporary.unlink()
    connection = sqlite3.connect(temporary)
    try:
        connection.execute(
            "CREATE TABLE cves ("
            "cve_id TEXT PRIMARY KEY, description TEXT, cvss REAL, published TEXT, json TEXT)"
        )
        connection.execute("CREATE INDEX idx_cves_published ON cves(published)")
        total = 0
        for feed in feeds:
            for record in iter_feed(feed):
                connection.execute(
                    "INSERT OR REPLACE INTO cves (cve_id, description, cvss, published, json) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        record["cve_id"],
                        record["description"],
                        record["cvss"],
                        record["published"],
                        record["json"],
                    ),
                )
                total += 1
                if max_records is not None and total >= max_records:
                    break
                if total % 5000 == 0:
                    connection.commit()
            connection.commit()
            if max_records is not None and total >= max_records:
                break
        connection.execute(
            "CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT)"
        )
        connection.executemany(
            "INSERT OR REPLACE INTO metadata (key, value) VALUES (?, ?)",
            [
                ("schema_version", "1"),
                ("generated_at", _now()),
                ("records", str(total)),
                ("feeds", json.dumps([str(feed) for feed in feeds])),
            ],
        )
        connection.commit()
        connection.execute("VACUUM")
    finally:
        connection.close()
    temporary.replace(output)
    return {
        "output": str(output),
        "records": total,
        "bytes": output.stat().st_size,
        "generated_at": _now(),
    }


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        prog="python -m opencyber.cve_index",
        description="Build an offline SQLite CVE index from NVD 2.0 feeds.",
    )
    parser.add_argument("--year", action="append", type=int, default=[], help="NVD year to download (repeatable)")
    parser.add_argument("--years", default="", help="Space- or comma-separated NVD years to download")
    parser.add_argument("--feed", action="append", default=[], help="Use an existing .json.gz feed (repeatable)")
    parser.add_argument("--output", default="/usr/share/opencyber/cve/cve.sqlite", help="SQLite output path")
    parser.add_argument("--download-dir", default="", help="Directory for downloaded feeds")
    parser.add_argument("--max-records", type=int, default=None, help="Stop after N records (testing)")
    parser.add_argument("--no-verify", action="store_true", help="Explicitly allow input without NVD .meta checksum verification")
    args = parser.parse_args()

    feeds: list[Path] = []
    if args.feed:
        feeds.extend(Path(value) for value in args.feed)
    years = list(args.year)
    years.extend(int(value) for value in args.years.replace(",", " ").split() if value)
    if years:
        download_dir = Path(args.download_dir) if args.download_dir else Path(tempfile.mkdtemp(prefix="opencyber-cve-"))
        for year in years:
            feeds.append(download_feed(year, download_dir, verify=not args.no_verify))
    if not feeds:
        parser.error("provide --year or --feed")

    for feed in feeds:
        if not feed.is_file():
            raise SystemExit(f"feed does not exist: {feed}")
        if not args.no_verify:
            _verify_metadata(feed)

    result = build_index(feeds, Path(args.output), args.max_records)
    print(json.dumps(result, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
