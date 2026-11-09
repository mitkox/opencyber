"""Portable, operator-attested real-device qualification evidence.

The validator proves completeness and artifact identity. It trusts the named
operator's observations; hashes cannot prove that hardware was exercised.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
import math
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import tempfile
from typing import Any


REQUIRED_DOMAINS = (
    "usb", "sdr", "wifi", "bluetooth", "nfc", "jtag", "serial",
    "automotive", "logic", "gps", "ir",
)
PLATFORMS = {"linux/amd64"}
NEGATIVE_CHECKS = ("missing_device", "insufficient_permissions", "disconnect", "timeout", "cleanup")
HEX_SHA256 = re.compile(r"[a-f0-9]{64}")
IMAGE_DIGEST = re.compile(r"sha256:[a-f0-9]{64}")
COMMIT_SHA = re.compile(r"[a-f0-9]{40}")


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError("hardware qualification: " + message)


def _text(value: Any, label: str) -> str:
    _require(isinstance(value, str) and bool(value.strip()), label + " must be nonempty text")
    return value


def _matches(pattern: re.Pattern[str], value: Any) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def _no_symlinks(path: Path) -> None:
    for component in (path.absolute(), *path.absolute().parents):
        _require(not component.is_symlink(), "symlinked evidence or bundle path is forbidden")


def _open_regular(path: Path):
    _no_symlinks(path)
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        raise ValueError("hardware qualification: evidence file cannot be opened") from exc
    if not stat.S_ISREG(os.fstat(descriptor).st_mode):
        os.close(descriptor)
        raise ValueError("hardware qualification: evidence must be a regular file")
    return os.fdopen(descriptor, "rb")


def _load(path: Path) -> dict:
    try:
        with _open_regular(path) as handle:
            value = json.load(handle)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("hardware qualification: bundle must be readable JSON") from exc
    _require(isinstance(value, dict), "bundle must be an object")
    return value


def _evidence_path(root: Path, raw: Any) -> Path:
    _require(isinstance(raw, str) and bool(raw) and "\\" not in raw, "invalid evidence path")
    path = PurePosixPath(raw)
    _require(
        not path.is_absolute() and len(path.parts) > 1 and path.parts[0] == "evidence"
        and ".." not in path.parts and str(path) == raw,
        "evidence path must be a normalized relative path beneath evidence/",
    )
    result = root.joinpath(*path.parts)
    _no_symlinks(result)
    return result


def _candidates(commit: str, records: list[dict]) -> tuple[dict[str, dict], str]:
    _require(_matches(COMMIT_SHA, commit), "commit must be a full source commit SHA")
    _require(isinstance(records, list) and len(records) == 1, "the amd64 candidate receipt is required")
    candidates: dict[str, dict] = {}
    catalogs = set()
    for record in records:
        _require(isinstance(record, dict), "candidate receipt must be an object")
        platform = record.get("platform")
        _require(isinstance(platform, str) and platform in PLATFORMS and platform not in candidates,
                 "candidate platform must be amd64")
        _require(record.get("commit") == commit, "candidate source commit mismatch")
        _require(_matches(IMAGE_DIGEST, record.get("digest")), "invalid candidate image digest")
        catalog = record.get("catalog_sha256")
        _require(_matches(HEX_SHA256, catalog), "candidate catalog digest is required")
        catalogs.add(catalog)
        candidates[platform] = record
    _require(len(catalogs) == 1, "candidate catalog digests differ")
    return candidates, catalogs.pop()


def qualification_template(*, commit: str, candidate_run_id: int, records: list[dict]) -> dict:
    """Create an intentionally incomplete checklist; never manufacture a pass."""
    candidates, catalog = _candidates(commit, records)
    _require(type(candidate_run_id) is int and candidate_run_id > 0, "candidate_run_id must be a positive integer")
    selected = candidates["linux/amd64"]

    def pending(domain: str) -> dict:
        return {
            "domain": domain, "status": "pending",
            "kind": "board_sample" if domain == "firmware" else "real_device",
            "platform": "linux/amd64", "image_digest": selected["digest"],
            "device": {"model": "", "firmware": ""},
            "host": {"architecture": "amd64", "os": "", "kernel": ""},
            "launcher_flags": [], "limits": {"timeout_s": 60, "max_output_bytes": 1048576},
            "operation": "", "expected": "", "observed": "", "cleanup": "",
            "operator": "", "operator_attested": False, "completed_at": "",
            "negative_checks": {check: {"status": "pending", "detail": ""} for check in NEGATIVE_CHECKS},
            "evidence": [],
        }

    return {
        "schema_version": 1, "commit": commit, "candidate_run_id": candidate_run_id,
        "catalog_sha256": catalog, "domains": [pending(domain) for domain in REQUIRED_DOMAINS],
        "firmware": pending("firmware"),
    }


def _validate_record(record: dict, *, root: Path, candidates: dict[str, dict], firmware: bool = False) -> None:
    _require(record.get("status") == "passed", "every hardware domain and firmware record must pass")
    kind = "board_sample" if firmware else "real_device"
    _require(record.get("kind") == kind, "synthetic or fixture evidence cannot qualify hardware")
    platform = record.get("platform")
    _require(isinstance(platform, str) and platform in candidates, "record platform has no candidate")
    _require(record.get("image_digest") == candidates[platform]["digest"], "qualified image digest mismatch")
    device, host = record.get("device"), record.get("host")
    _require(isinstance(device, dict) and isinstance(host, dict), "device and host identities are required")
    for key in ("model", "firmware"):
        _text(device.get(key), "device." + key)
    for key in ("os", "kernel"):
        _text(host.get(key), "host." + key)
    _require(host.get("architecture") == platform.split("/")[1], "host architecture does not match the image")
    flags = record.get("launcher_flags")
    _require(isinstance(flags, list) and bool(flags), "launcher_flags must record the runtime flags")
    for flag in flags:
        _text(flag, "launcher flag")
    for key in ("operation", "expected", "observed", "cleanup", "operator"):
        _text(record.get(key), key)
    _require(record.get("operator_attested") is True, "operator attestation is required")
    completed = _text(record.get("completed_at"), "completed_at")
    try:
        timestamp = datetime.fromisoformat(completed.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("hardware qualification: invalid completion timestamp") from exc
    _require(timestamp.utcoffset() == timedelta(0), "completed_at must carry an explicit UTC offset")
    _require(timestamp <= datetime.now(timezone.utc) + timedelta(minutes=5), "completion timestamp is in the future")
    limits = record.get("limits")
    _require(isinstance(limits, dict), "bounded operation limits are required")
    timeout, maximum = limits.get("timeout_s"), limits.get("max_output_bytes")
    _require(type(timeout) in (int, float) and 0 < timeout <= 3600 and math.isfinite(timeout),
             "timeout_s must be positive and at most 3600")
    _require(type(maximum) is int and 0 < maximum <= 268435456,
             "max_output_bytes must be positive and at most 256 MiB")
    checks = record.get("negative_checks")
    _require(isinstance(checks, dict) and set(checks) == set(NEGATIVE_CHECKS), "all negative checks need dispositions")
    for name, check in checks.items():
        _require(isinstance(check, dict), "negative check must be an object")
        allowed = {"passed"} if name in {"timeout", "cleanup"} else {"passed", "not_applicable"}
        _require(isinstance(check.get("status"), str) and check["status"] in allowed,
                 "negative check failed, skipped or has invalid applicability")
        _text(check.get("detail"), "negative check detail")
    evidence = record.get("evidence")
    _require(isinstance(evidence, list) and bool(evidence), "checksummed evidence is required")
    seen = set()
    for item in evidence:
        _require(isinstance(item, dict), "evidence entry must be an object")
        path = _evidence_path(root, item.get("path"))
        _require(item["path"] not in seen, "duplicate evidence path in one record")
        seen.add(item["path"])
        _require(_matches(HEX_SHA256, item.get("sha256")), "invalid evidence SHA-256")
        with _open_regular(path) as handle:
            digest = hashlib.file_digest(handle, "sha256").hexdigest()
        _require(digest == item["sha256"], "evidence checksum mismatch")


def validate_qualification(bundle_path: Path, *, commit: str, records: list[dict]) -> dict:
    """Fail closed unless all device domains and firmware match both candidates.

    The caller must additionally bind candidate_run_id to the selected trusted
    workflow run and verify the checksum of this whole portable bundle.
    """
    candidates, catalog = _candidates(commit, records)
    bundle = _load(bundle_path)
    _require(type(bundle.get("schema_version")) is int and bundle["schema_version"] == 1, "unsupported schema_version")
    _require(bundle.get("commit") == commit, "bundle source commit mismatch")
    run_id = bundle.get("candidate_run_id")
    _require(type(run_id) is int and run_id > 0, "candidate_run_id must be a positive integer")
    _require(bundle.get("catalog_sha256") == catalog, "bundle catalog digest mismatch")
    domains = bundle.get("domains")
    _require(isinstance(domains, list) and len(domains) == len(REQUIRED_DOMAINS), "all 11 hardware domains are required")
    seen = set()
    for record in domains:
        _require(isinstance(record, dict), "domain record must be an object")
        domain = record.get("domain")
        _require(isinstance(domain, str) and domain in REQUIRED_DOMAINS and domain not in seen,
                 "unknown or duplicate hardware domain")
        seen.add(domain)
        _validate_record(record, root=bundle_path.parent, candidates=candidates)
    firmware = bundle.get("firmware")
    _require(isinstance(firmware, dict) and firmware.get("domain") == "firmware", "board-derived firmware evidence is required")
    _validate_record(firmware, root=bundle_path.parent, candidates=candidates, firmware=True)
    return bundle


def collect_qualification(manifest: Path, *, evidence_root: Path, output: Path, records: list[dict]) -> Path:
    """Copy operator-supplied observations and hash evidence, without operating devices."""
    _no_symlinks(evidence_root)
    _no_symlinks(output)
    _require(not output.exists(), "collection output already exists; use a new directory")
    _require(output.parent.is_dir(), "collection output parent must already exist")
    bundle = _load(manifest)
    _require(isinstance(bundle.get("domains"), list) and isinstance(bundle.get("firmware"), dict),
             "collection requires domain and firmware observations")
    observations = [*bundle["domains"], bundle["firmware"]]
    with tempfile.TemporaryDirectory(prefix=".hardware-qualification-", dir=output.parent) as temporary:
        staging = Path(temporary)
        copied: dict[str, str] = {}
        for record in observations:
            _require(isinstance(record, dict) and isinstance(record.get("evidence"), list), "record evidence must be a list")
            for item in record["evidence"]:
                _require(isinstance(item, dict), "evidence entry must be an object")
                source = _evidence_path(evidence_root, item.get("path"))
                destination = _evidence_path(staging, item["path"])
                if item["path"] not in copied:
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    with _open_regular(source) as incoming, destination.open("xb") as outgoing:
                        shutil.copyfileobj(incoming, outgoing)
                    with _open_regular(destination) as handle:
                        copied[item["path"]] = hashlib.file_digest(handle, "sha256").hexdigest()
                digest = copied[item["path"]]
                if item.get("sha256"):
                    _require(item["sha256"] == digest, "previously checksummed evidence changed")
                item["sha256"] = digest
        selected = staging / "qualification.json"
        selected.write_text(json.dumps(bundle, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        validate_qualification(selected, commit=bundle.get("commit"), records=records)
        try:
            output.mkdir(mode=0o700)
        except FileExistsError as exc:
            raise ValueError("hardware qualification: collection output already exists") from exc
        try:
            for path in staging.iterdir():
                path.rename(output / path.name)
        except OSError:
            shutil.rmtree(output)
            raise
    return output / "qualification.json"
