"""Immutable cross-run candidate selection and safe artifact transport."""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import tempfile
import zipfile


DIGEST = re.compile(r"sha256:[a-f0-9]{64}")
ARTIFACTS = {"release-evidence-amd64"}
WORKFLOW = ".github/workflows/build-candidate.yml"


def sha256(path: Path) -> str:
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def api(path: str) -> dict:
    return json.loads(subprocess.check_output(["gh", "api", path]))


def artifacts_for(repository: str, run_id: int) -> list[dict]:
    pages = json.loads(subprocess.check_output([
        "gh", "api", f"repos/{repository}/actions/runs/{run_id}/artifacts?per_page=100",
        "--paginate", "--slurp",
    ]))
    return [artifact for page in pages for artifact in page["artifacts"]]


def validate_candidate_run(run: dict, artifacts: list[dict], *, repository: str,
                           repository_id: int, commit: str, workflow_id: int, run_id: int) -> list[dict]:
    if not re.fullmatch(r"[a-f0-9]{40}", commit):
        raise ValueError("candidate commit must be a complete Git SHA")
    expected = {"id": run_id, "workflow_id": workflow_id, "head_sha": commit,
                "status": "completed", "conclusion": "success", "event": "workflow_dispatch",
                "path": WORKFLOW}
    if any(run.get(key) != value for key, value in expected.items()):
        raise ValueError("candidate must be a successful canonical build at the selected commit")
    if (run.get("repository", {}).get("id") != repository_id
            or run.get("repository", {}).get("full_name") != repository
            or run.get("head_repository", {}).get("id") != repository_id
            or type(run.get("run_attempt")) is not int or run["run_attempt"] < 1):
        raise ValueError("candidate repository identity or attempt mismatch")
    selected = [a for a in artifacts if a.get("name", "").startswith("release-evidence-")]
    if len(selected) != 1 or {a.get("name") for a in selected} != ARTIFACTS:
        raise ValueError("exactly one immutable candidate evidence artifact is required")
    for artifact in selected:
        try:
            expires = datetime.fromisoformat(artifact["expires_at"].replace("Z", "+00:00"))
        except (KeyError, TypeError, ValueError) as exc:
            raise ValueError("artifact expiration is missing or invalid") from exc
        identity = artifact.get("workflow_run", {})
        if (type(artifact.get("id")) is not int or artifact["id"] <= 0
                or artifact.get("expired") is not False
                or not DIGEST.fullmatch(artifact.get("digest", ""))
                or expires.tzinfo is None or expires <= datetime.now(timezone.utc)
                or identity.get("id") != run_id or identity.get("repository_id") != repository_id
                or identity.get("head_sha") != commit):
            raise ValueError("artifact is expired, unchecksummed, or belongs to another candidate")
    return sorted(selected, key=lambda a: a["name"])


def selection_for(repository: str, run_id: int, commit: str) -> dict:
    repository_info = api(f"repos/{repository}")
    workflow = api(f"repos/{repository}/actions/workflows/build-candidate.yml")
    run = api(f"repos/{repository}/actions/runs/{run_id}")
    artifacts = validate_candidate_run(run, artifacts_for(repository, run_id), repository=repository,
                                       repository_id=repository_info["id"], commit=commit,
                                       workflow_id=workflow["id"], run_id=run_id)
    return {"schema_version": 1, "repository": repository, "repository_id": repository_info["id"],
            "commit": commit, "run_id": run_id, "run_attempt": run["run_attempt"],
            "workflow_id": workflow["id"], "artifacts": [
                {key: artifact[key] for key in ("id", "name", "digest", "expires_at")}
                for artifact in artifacts]}


def immutable_bytes(existing: bytes | None, desired: bytes, label: str) -> bool:
    if existing is None:
        return True
    if existing != desired:
        raise ValueError(f"{label} is immutable; changed bytes require a new version")
    return False


def safe_extract(archive: Path, destination: Path) -> None:
    if destination.exists() and any(destination.iterdir()):
        raise ValueError("artifact extraction requires an empty directory")
    with zipfile.ZipFile(archive) as source:
        seen: set[str] = set()
        total = 0
        for member in source.infolist():
            path = PurePosixPath(member.filename)
            total += member.file_size
            if (path.is_absolute() or ".." in path.parts or "\\" in member.filename
                    or ":" in member.filename or not path.parts or member.filename in seen
                    or stat.S_ISLNK(member.external_attr >> 16) or total > 100 * 1024**3):
                raise ValueError("unsafe or oversized release artifact")
            seen.add(member.filename)
        destination.mkdir(parents=True, exist_ok=True)
        source.extractall(destination)


def fetch_selection(path: Path, expected_sha256: str, destination: Path, *, repository: str,
                    run_id: int, commit: str) -> dict:
    if not re.fullmatch(r"[a-f0-9]{64}", expected_sha256) or sha256(path) != expected_sha256:
        raise ValueError("candidate selection checksum mismatch")
    selected = json.loads(path.read_text(encoding="utf-8"))
    current = selection_for(repository, run_id, commit)
    if selected != current:
        raise ValueError("candidate run, attempt or immutable artifact selection changed")
    if destination.exists() and any(destination.iterdir()):
        raise ValueError("candidate destination must be empty")
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as temporary:
        for artifact in selected["artifacts"]:
            archive = Path(temporary) / f"{artifact['id']}.zip"
            with archive.open("wb") as output:
                subprocess.run(["gh", "api", f"repos/{repository}/actions/artifacts/{artifact['id']}/zip"],
                               stdout=output, check=True)
            if "sha256:" + sha256(archive) != artifact["digest"]:
                raise ValueError("downloaded artifact checksum mismatch")
            safe_extract(archive, destination / artifact["name"])
    return selected


def upload_assets(repository: str, tag: str, directory: Path) -> None:
    """Upload absent assets; an existing name can only have identical bytes."""
    release = api(f"repos/{repository}/releases/tags/{tag}")
    existing = {a["name"]: a for a in release["assets"]}
    for path in sorted(directory.iterdir()):
        if not path.is_file() or path.is_symlink():
            raise ValueError("release assets must be regular files")
        asset = existing.get(path.name)
        if asset is not None:
            digest = asset.get("digest")
            if digest is None:
                with tempfile.TemporaryDirectory() as temporary:
                    downloaded = Path(temporary) / path.name
                    with downloaded.open("wb") as output:
                        subprocess.run(["gh", "api", "-H", "Accept: application/octet-stream",
                                        f"repos/{repository}/releases/assets/{asset['id']}"],
                                       stdout=output, check=True)
                    digest = "sha256:" + sha256(downloaded)
            if digest != "sha256:" + sha256(path):
                raise ValueError(f"release asset {path.name} is immutable")
        else:
            subprocess.run(["gh", "release", "upload", tag, str(path), "--repo", repository], check=True)
