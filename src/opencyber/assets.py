"""Offline asset inventory and integrity checks.

An airgapped harness is only as good as the assets baked into the image. This
module is the single source of truth for "what must be present for offline
work", and it turns silent degradation (an empty nuclei template store, a
truncated wordlist) into a doctor problem with a stable name.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
from typing import Any, Callable, Iterable


TRUTHY = {"1", "true", "yes", "on"}
OFFLINE_ENV = "OPENCYBER_OFFLINE"
CVE_DB_ENV = "OPENCYBER_CVE_DB"
DEFAULT_CVE_DB = Path("/usr/share/opencyber/cve/cve.sqlite")
MANIFEST_PATH = Path(
    os.environ.get("OPENCYBER_ASSET_MANIFEST", "/usr/share/opencyber/asset-manifest.json")
)

# The single source of truth for executables refused while OPENCYBER_OFFLINE=1.
# policy.py imports this set; offline_status() publishes it so documentation and
# runtime behavior cannot drift.
OFFLINE_NETWORK_EXECUTABLES = frozenset(
    {"shodan", "censys", "subfinder", "theHarvester", "sherlock"}
)


@dataclass(frozen=True)
class AssetSpec:
    name: str
    path: Path | str | Callable[[], Path]
    kind: str
    min_count: int = 0
    min_bytes: int = 0
    required: bool = True
    description: str = ""
    internet_dependent: bool = False

    def resolved(self) -> Path:
        if callable(self.path):
            return Path(self.path())
        return Path(self.path)


def _nuclei_path() -> Path:
    return Path.home() / ".local" / "nuclei-templates"


ASSET_SPECS: tuple[AssetSpec, ...] = (
    AssetSpec(
        "nuclei-templates",
        _nuclei_path,
        "tree",
        min_count=5000,
        required=True,
        description="Nuclei template store; scanning is meaningless without it.",
    ),
    AssetSpec(
        "seclists",
        Path("/usr/share/seclists"),
        "tree",
        min_count=1000,
        required=True,
        description="Discovery, fuzzing, payload, and password lists.",
    ),
    AssetSpec(
        "baseline-password-dictionary",
        Path("/usr/share/wordlists/opencyber-keyboard-patterns.txt"),
        "file",
        min_bytes=1_000_000,
        required=True,
        description="SecLists generated keyboard-pattern dictionary; not a breach-password corpus.",
    ),
    AssetSpec(
        "rockyou",
        Path("/usr/share/wordlists/rockyou.txt"),
        "file",
        min_bytes=100_000_000,
        required=False,
        description="Optional operator-provided RockYou corpus; not included without a redistribution basis.",
    ),
    AssetSpec(
        "exploitdb",
        Path("/usr/share/exploitdb"),
        "tree",
        min_count=40_000,
        required=True,
        description="Local exploit database used by searchsploit.",
        internet_dependent=False,
    ),
    AssetSpec(
        "metasploit-modules",
        Path("/usr/share/metasploit-framework/modules"),
        "tree",
        min_count=1000,
        required=True,
        description="Bundled Metasploit modules and payloads for authorized local assessments.",
    ),
    AssetSpec(
        "nmap-scripts",
        Path("/usr/share/nmap/scripts"),
        "tree",
        min_count=500,
        required=True,
        description="Bundled Nmap NSE scripts for authorized local-network assessments.",
    ),
    AssetSpec(
        "wpscan-database",
        Path("/usr/share/opencyber/wpscan-cache/wpscan/db"),
        "tree",
        min_count=8,
        required=True,
        description="WPScan local detection metadata and its license; vulnerability API/enterprise data is separate.",
    ),
    AssetSpec(
        "webshells",
        Path("/usr/share/webshells"),
        "tree",
        min_count=10,
        required=False,
        description="Webshell collection for authorized post-exploitation testing.",
    ),
    AssetSpec(
        "wordlists",
        Path("/usr/share/wordlists"),
        "tree",
        min_count=2,
        required=True,
        description="Shared wordlist directory.",
    ),
    AssetSpec(
        "wireshark-data",
        Path("/usr/share/wireshark"),
        "tree",
        min_count=50,
        required=False,
        description="Wireshark profiles, filters, and OUI data for passive attribution.",
    ),
    AssetSpec(
        "hardware-udev-rules",
        Path("/usr/share/opencyber/host/99-opencyber-hw.rules"),
        "file",
        min_bytes=200,
        required=False,
        description="Host udev rules for SDR, NFC, JTAG, and serial adapters.",
    ),
    AssetSpec(
        "hardware-playbook",
        Path("/usr/share/opencyber/docs/HARDWARE.md"),
        "file",
        min_bytes=1000,
        required=False,
        description="Offline hardware and device-passthrough playbook.",
    ),
    AssetSpec(
        "airgap-playbook",
        Path("/usr/share/opencyber/docs/AIRGAP.md"),
        "file",
        min_bytes=1000,
        required=False,
        description="Offline install, export, import, and verification procedure.",
    ),
    AssetSpec(
        "cve-database",
        lambda: Path(os.environ.get(CVE_DB_ENV, DEFAULT_CVE_DB)),
        "file",
        min_bytes=100_000,
        required=False,
        description="Optional local CVE index for offline oc_cve_lookup.",
    ),
)


def offline_enabled() -> bool:
    return os.environ.get(OFFLINE_ENV, "").strip().lower() in TRUTHY


def local_cve_db() -> Path:
    return Path(os.environ.get(CVE_DB_ENV, DEFAULT_CVE_DB))


def require_online(feature: str) -> None:
    """Fail fast and clearly when an internet-only feature is used airgapped."""
    if offline_enabled():
        raise ValueError(
            f"{feature} requires internet access, but {OFFLINE_ENV}=1 is set. "
            "Use the local exploit database, nuclei templates, or a locally built "
            f"CVE index ({CVE_DB_ENV}) instead."
        )


def _measure(path: Path, kind: str) -> dict[str, Any]:
    result: dict[str, Any] = {
        "path": str(path),
        "exists": False,
        "kind": kind,
        "count": 0,
        "bytes": 0,
        "sha256": None,
    }
    try:
        if kind == "file":
            if not path.is_file() or path.is_symlink():
                return result
            stat = path.stat()
            result.update({"exists": True, "count": 1, "bytes": stat.st_size})
            return result
        if not path.is_dir():
            return result
        result["exists"] = True
        for root, _directories, files in os.walk(path, followlinks=False):
            for name in files:
                candidate = Path(root) / name
                try:
                    if candidate.is_symlink():
                        continue
                    result["bytes"] += candidate.stat().st_size
                    result["count"] += 1
                except OSError:
                    continue
    except OSError:
        return result
    return result


def _file_digest(path: Path) -> str | None:
    try:
        if not path.is_file() or path.is_symlink():
            return None
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                digest.update(chunk)
        return digest.hexdigest()
    except OSError:
        return None


def _tree_index(path: Path) -> str | None:
    try:
        if not path.is_dir():
            return None
        digest = hashlib.sha256()
        count = 0
        for root, directories, files in os.walk(path, followlinks=False):
            directories.sort()
            for name in sorted(files):
                candidate = Path(root) / name
                if candidate.is_symlink():
                    continue
                digest.update(str(candidate.relative_to(path)).encode("utf-8"))
                digest.update(b"\0")
                try:
                    with candidate.open("rb") as handle:
                        while chunk := handle.read(1024 * 1024):
                            digest.update(chunk)
                except OSError:
                    continue
                count += 1
        return digest.hexdigest() if count else None
    except OSError:
        return None


def assets_status(deep: bool = False, specs: Iterable[AssetSpec] | None = None) -> dict[str, Any]:
    entries = []
    missing_required: list[str] = []
    missing_optional: list[str] = []
    for spec in specs or ASSET_SPECS:
        path = spec.resolved()
        measured = _measure(path, spec.kind)
        count_ok = measured["count"] >= spec.min_count
        bytes_ok = measured["bytes"] >= spec.min_bytes
        ok = measured["exists"] and count_ok and bytes_ok
        entry = {
            "name": spec.name,
            "description": spec.description,
            "required": spec.required,
            "internet_dependent": spec.internet_dependent,
            "min_count": spec.min_count,
            "min_bytes": spec.min_bytes,
            **measured,
            "ok": ok,
        }
        if deep and measured["exists"]:
            entry["sha256"] = (
                _file_digest(path) if spec.kind == "file" else _tree_index(path)
            )
        entries.append(entry)
        if not ok:
            (missing_required if spec.required else missing_optional).append(spec.name)
    return {
        "assets": entries,
        "missing_required": missing_required,
        "missing_optional": missing_optional,
        "ready": not missing_required,
        "summary": {
            "total": len(entries),
            "ok": sum(1 for entry in entries if entry["ok"]),
            "missing_required": len(missing_required),
            "missing_optional": len(missing_optional),
        },
    }


def verify_manifest(
    current_status: dict[str, Any] | None = None,
    deep: bool = False,
) -> dict[str, Any]:
    """Compare measured assets with the build-time manifest, when present.

    ``deep=True`` also compares content hashes; it is intentionally not the
    healthcheck default because hashing Seclists and exploitdb is expensive.
    """
    if not MANIFEST_PATH.is_file() or MANIFEST_PATH.is_symlink():
        return {
            "available": False,
            "valid": None,
            "path": str(MANIFEST_PATH),
            "note": "no build-time asset manifest installed",
        }
    try:
        manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        return {
            "available": True,
            "valid": False,
            "path": str(MANIFEST_PATH),
            "error": f"invalid manifest: {exc}",
        }
    recorded = manifest.get("assets", {})
    current_status = current_status or assets_status(deep=deep)
    current = {entry["name"]: entry for entry in current_status["assets"]}
    mismatches = []
    for name, expected in recorded.items():
        # Optional assets are allowed to appear at runtime (for example a CVE
        # database mounted into an airgapped container).
        if not expected.get("required", True):
            continue
        actual = current.get(name)
        if actual is None:
            mismatches.append({"name": name, "error": "asset is no longer in the catalog"})
            continue
        for field in ("count", "bytes"):
            if expected.get(field) != actual.get(field):
                mismatches.append(
                    {
                        "name": name,
                        "field": field,
                        "expected": expected.get(field),
                        "actual": actual.get(field),
                    }
                )
        expected_hash = expected.get("sha256")
        actual_hash = actual.get("sha256")
        if deep and ((expected_hash and expected_hash != actual_hash)
                     or (actual.get("bytes", 0) and not expected_hash)):
            mismatches.append(
                {
                    "name": name,
                    "field": "sha256",
                    "expected": expected_hash,
                    "actual": actual_hash,
                }
            )
    return {
        "available": True,
        "valid": not mismatches,
        "path": str(MANIFEST_PATH),
        "mismatches": mismatches,
    }


def offline_status(status: dict[str, Any] | None = None) -> dict[str, Any]:
    status = status or assets_status()
    cve_db = local_cve_db()
    return {
        "mode": "airgapped" if offline_enabled() else "connected",
        "offline_env": OFFLINE_ENV,
        "assets_ready": status["ready"],
        "missing_required_assets": status["missing_required"],
        "local_cve_database": {
            "path": str(cve_db),
            "present": cve_db.is_file() and not cve_db.is_symlink(),
        },
        "blocked_executables": sorted(OFFLINE_NETWORK_EXECUTABLES),
        "internet_dependent_features": [
            "oc_cve_lookup without a local CVE database",
            "oc_hibp_password_check",
            "oc_shodan",
            "oc_censys",
            "oc_subfinder passive sources",
            "oc_theharvester online sources",
            "oc_sherlock",
        ],
        "guidance": (
            "Set OPENCYBER_OFFLINE=1 on airgapped deployments so internet-only "
            "features fail with an actionable message instead of hanging. Keep "
            "the nuclei template store, exploitdb, Seclists, and wordlists in the "
            "image; mount a local CVE SQLite index if you need oc_cve_lookup."
        ),
    }


def write_manifest(path: Path | None = None, deep: bool = True) -> dict[str, Any]:
    status = assets_status(deep=deep)
    manifest = {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "assets": {
            entry["name"]: {
                "count": entry["count"],
                "bytes": entry["bytes"],
                "sha256": entry.get("sha256"),
                "required": entry["required"],
            }
            for entry in status["assets"]
        },
        "missing_required": status["missing_required"],
        "missing_optional": status["missing_optional"],
    }
    target = Path(path) if path else MANIFEST_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    manifest["path"] = str(target)
    return manifest


def _format_human(payload: dict[str, Any], mode: str) -> str:
    lines: list[str] = []
    if mode == "verify":
        status = "unavailable" if payload.get("valid") is None else ("ok" if payload.get("valid") else "invalid")
        lines.append(f"asset manifest  {payload.get('path')}")
        lines.append(f"status          {status}")
        for mismatch in payload.get("mismatches", []):
            lines.append(f"  mismatch      {mismatch}")
        if payload.get("note"):
            lines.append(f"  note          {payload['note']}")
        if payload.get("error"):
            lines.append(f"  error         {payload['error']}")
        return "\n".join(lines)

    if mode == "offline":
        lines.append(f"mode            {payload.get('mode')}")
        lines.append(f"assets ready    {'yes' if payload.get('assets_ready') else 'no'}")
        missing = payload.get("missing_required", [])
        lines.append(f"missing         {', '.join(missing) if missing else 'none'}")
        blocked = payload.get("blocked_executables", [])
        lines.append(f"blocked tools   {', '.join(blocked) if blocked else 'none'}")
        return "\n".join(lines)

    if mode == "write":
        lines.append(f"wrote           {payload.get('path')}")
        lines.append(f"missing         {len(payload.get('missing_required', []))} required asset(s)")
        return "\n".join(lines)

    lines.append(f"status          {'ok' if payload.get('ready') else 'degraded'}")
    assets = payload.get("assets", [])
    missing_required = payload.get("missing_required", [])
    missing_optional = payload.get("missing_optional", [])
    lines.append(f"assets          {len(assets) - len(missing_required)}/{len(assets)} required present")
    if missing_required:
        lines.append(f"missing required {', '.join(missing_required)}")
    if missing_optional:
        lines.append(f"missing optional {', '.join(missing_optional)}")
    return "\n".join(lines)


def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        prog="opencyber-assets",
        description="Inspect, verify, or write the OpenCyber offline asset manifest.",
    )
    parser.add_argument("--json", action="store_true", help="emit JSON")
    parser.add_argument("--deep", action="store_true", help="hash asset contents")
    parser.add_argument("--verify", action="store_true", help="verify the installed manifest")
    parser.add_argument("--write", metavar="PATH", help="write a manifest to PATH")
    parser.add_argument("--offline", action="store_true", help="print offline posture")
    args = parser.parse_args()

    if args.write:
        payload = write_manifest(Path(args.write), deep=args.deep)
        mode = "write"
        code = 0
    elif args.verify:
        payload = verify_manifest(deep=args.deep)
        mode = "verify"
        code = 0 if payload.get("valid") else 1
    elif args.offline:
        payload = offline_status()
        mode = "offline"
        code = 0 if payload["assets_ready"] else 1
    else:
        payload = assets_status(deep=args.deep)
        mode = "status"
        code = 0 if payload["ready"] else 1

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(_format_human(payload, mode))
    raise SystemExit(code)


if __name__ == "__main__":
    main()
