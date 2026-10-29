#!/usr/bin/env python3
"""Capture actual source inputs in the dedicated Docker source target.

This intentionally captures every installed Debian source package, rather than
guessing which transitive binaries have reciprocal-license obligations. A
missing exact source version or an unavailable required sdist fails the build.
"""

from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
from urllib.parse import quote, urlparse
from urllib.request import urlopen


SCHEMA = "opencyber.corresponding-source/v1"
DPKG_FORMAT = "${db:Status-Status}\t${source:Package}\t${source:Version}\t${binary:Package}\t${Version}\n"
DIRECT_SOURCE_TREES = {
    "docker-bench-security": Path("/opt/docker-bench-security"),
    "nuclei-templates": Path("/root/.local/nuclei-templates"),
    "seclists": Path("/usr/share/seclists"),
    "wpscan-metadata": Path("/usr/share/opencyber/wpscan-cache"),
}


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1024 * 1024):
            value.update(chunk)
    return value.hexdigest()


def tree_digest(root: Path) -> str:
    if root.is_symlink() or not root.is_dir():
        raise ValueError(f"direct source tree missing or unsafe: {root}")
    records = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if ".git" in relative.parts:
            continue
        if path.is_symlink():
            record = ("symlink", os.readlink(path))
        elif path.is_file():
            record = ("file-sha256", digest(path))
        elif path.is_dir():
            record = ("directory", "")
        else:
            raise ValueError(f"unsupported direct source input: {path}")
        records[relative.as_posix()] = record
    return hashlib.sha256(json.dumps(records, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def run(arguments: list[str], **kwargs: object) -> str:
    return subprocess.check_output(arguments, text=True, **kwargs).strip()


def download(url: str, target: Path, expected: str | None = None) -> None:
    if urlparse(url).scheme != "https":
        raise ValueError(f"source download requires HTTPS: {url}")
    temporary = target.with_name(target.name + ".partial")
    try:
        with urlopen(url, timeout=120) as response, temporary.open("wb") as output:
            shutil.copyfileobj(response, output)
        if expected and digest(temporary) != expected:
            raise ValueError(f"upstream source checksum mismatch: {target.name}")
        temporary.replace(target)
    finally:
        temporary.unlink(missing_ok=True)


def enable_source_repositories() -> None:
    for path in [Path("/etc/apt/sources.list"), *Path("/etc/apt/sources.list.d").glob("*.list")]:
        if path.is_file():
            additions = [re.sub(r"^deb\s", "deb-src ", line)
                         for line in path.read_text().splitlines() if line.startswith("deb ")]
            if additions:
                with path.open("a") as handle:
                    handle.write("\n" + "\n".join(additions) + "\n")
    for path in Path("/etc/apt/sources.list.d").glob("*.sources"):
        text = path.read_text()
        text = re.sub(r"(?m)^Types:\s*deb\s*$", "Types: deb deb-src", text)
        path.write_text(text)
    subprocess.run(["apt-get", "update"], check=True)


def capture_debian(output: Path, local_sources: Path | None = None) -> list[dict]:
    raw = run(["dpkg-query", "-W", "-f=" + DPKG_FORMAT])
    inventory = "".join(line.split("\t", 1)[1] + "\n" for line in raw.splitlines()
                        if line.startswith("installed\t"))
    (output / "runtime-dpkg.tsv").write_text(inventory)
    sources: dict[tuple[str, str], list[dict]] = {}
    for line in inventory.splitlines():
        source, version, binary, binary_version = line.split("\t")
        if not source or not version:
            raise ValueError(f"installed package has no exact source identity: {line}")
        sources.setdefault((source, version), []).append({"name": binary, "version": binary_version})
    enable_source_repositories()

    def capture(item: tuple[tuple[str, str], list[dict]]) -> dict:
        (name, version), binaries = item
        # Encode epochs/slashes to ensure a single component beneath the root.
        folder = output / "debian" / quote(name + "@" + version, safe="")
        folder.mkdir(parents=True)
        local = local_sources / quote(name, safe="") if local_sources is not None else None
        if local is not None and (local.exists() or local.is_symlink()):
            if local.is_symlink() or not local.is_dir():
                raise ValueError(f"unsafe local source directory: {name}")
            for path in local.iterdir():
                if path.is_symlink() or not path.is_file():
                    raise ValueError(f"unsafe local source input: {name}/{path.name}")
                shutil.copy2(path, folder / path.name)
        else:
            subprocess.run(["apt-get", "-y", "--download-only", "--only-source", "source", f"{name}={version}"],
                           cwd=folder, check=True)
        dsc = list(folder.glob("*.dsc"))
        if len(dsc) != 1:
            raise ValueError(f"exact source descriptor missing for {name}={version}")
        descriptor = dsc[0].read_text()
        fields = re.findall(r"(?m)^ ([0-9a-f]{64}) +(\d+) +(\S+)$", descriptor)
        if not fields:
            raise ValueError(f"source descriptor lacks SHA-256 input checksums: {name}={version}")
        files = [dsc[0]]
        for expected, size, filename in fields:
            if Path(filename).name != filename:
                raise ValueError("unsafe Debian source filename")
            path = folder / filename
            if not path.is_file() or path.stat().st_size != int(size) or digest(path) != expected:
                raise ValueError(f"incomplete Debian source set: {name}={version}/{filename}")
            files.append(path)
        # The .dsc must identify the requested source version and name.
        if f"Source: {name}\n" not in descriptor or f"Version: {version}\n" not in descriptor:
            raise ValueError(f"source descriptor identity mismatch: {name}={version}")
        return {"kind": "debian", "name": name, "version": version, "binaries": binaries,
                "source_status": "captured", "archives": [str(path.relative_to(output)) for path in files]}

    with ThreadPoolExecutor(max_workers=4) as pool:
        return list(pool.map(capture, sorted(sources.items())))


def permissive_license(metadata: dict) -> bool:
    """Allow source-optional decisions only from explicit standard metadata."""
    labels = [metadata.get("license_expression", ""), *metadata.get("classifiers", [])]
    labels = [value.strip() for value in labels if value]
    permitted = {"MIT", "ISC", "Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "PSF-2.0", "Zlib", "Unlicense",
                 "License :: OSI Approved :: MIT License", "License :: OSI Approved :: Apache Software License",
                 "License :: OSI Approved :: BSD License", "License :: OSI Approved :: ISC License (ISCL)",
                 "License :: OSI Approved :: Python Software Foundation License"}
    license_labels = [value for value in labels if value.startswith("License ::") or value in permitted]
    # Unknown, mixed, and reciprocal expressions require an actual source archive.
    expression = metadata.get("license_expression")
    return bool(license_labels) and (not expression or expression in permitted) and all(
        value in permitted for value in license_labels
    )


def python_inventory() -> dict[tuple[str, str], dict]:
    inventory_code = (
        "import importlib.metadata as m,json; print(json.dumps(["
        "{'name':d.metadata['Name'],'version':d.version,'location':str(d.locate_file('')),'license_expression':"
        "d.metadata.get('License-Expression',''),'classifiers':d.metadata.get_all('Classifier',[]),"
        "'direct_url':d.read_text('direct_url.json')} for d in m.distributions()]))"
    )
    installed: dict[tuple[str, str], dict] = {}
    for python in sorted(Path("/opt").glob("opencyber-*/bin/python")):
        for item in json.loads(run([str(python), "-c", inventory_code])):
            if not item["location"].startswith("/opt/") or item["name"].lower() == "opencyber":
                continue
            installed[(item["name"], item["version"])] = item
    return installed


def ruby_inventory() -> list[dict]:
    code = "require 'json'; puts Gem::Specification.map {|s| {name:s.name,version:s.version.to_s,path:s.full_gem_path,default:s.default_gem?}}.to_json"
    return [item for item in json.loads(run(["ruby", "-e", code]))
            if not item["default"] and item["path"].startswith("/var/lib/gems/")]


def ecosystem_inventory() -> dict:
    root = Path("/opt/opencyber")
    first_party = {
        str(path.relative_to(root)): digest(path)
        for path in sorted(root.rglob("*"))
        if path.is_file() and "__pycache__" not in path.parts
        and not any(part.endswith(".egg-info") for part in path.parts)
        and (path.parent == root or path.relative_to(root).parts[0] in {"src", "docs", "packaging"})
    }
    if "src/opencyber/__init__.py" not in first_party:
        raise ValueError("first-party runtime source inventory is missing")
    return {"python": [{"name": name, "version": version} for name, version in sorted(python_inventory())],
            "ruby": sorted([{"name": item["name"], "version": item["version"]} for item in ruby_inventory()],
                           key=lambda item: (item["name"], item["version"])),
            "first_party_sha256": first_party,
            "direct_assets_sha256": {name: tree_digest(path) for name, path in DIRECT_SOURCE_TREES.items()}}


def capture_python(output: Path) -> list[dict]:
    installed = python_inventory()
    packages = []
    for (name, version), metadata in sorted(installed.items()):
        if metadata.get("direct_url"):
            raise ValueError(f"non-index Python input requires explicit source review: {name}={version}")
        url = f"https://pypi.org/pypi/{quote(name, safe='')}/{quote(version, safe='')}/json"
        with urlopen(url, timeout=120) as response:
            release = json.load(response)
        sdists = [item for item in release["urls"] if item["packagetype"] == "sdist"]
        record = {"kind": "python", "name": name, "version": version, "archives": [],
                  "license_expression": metadata.get("license_expression", ""),
                  "license_classifiers": [value for value in metadata["classifiers"] if value.startswith("License ::")]}
        if not sdists:
            if not permissive_license(metadata):
                raise ValueError(f"required Python source unavailable: {name}={version}")
            record.update(source_status="notice-only", decision="Explicit permissive installed license metadata; no sdist published.")
        else:
            item = sorted(sdists, key=lambda value: value["filename"])[0]
            folder = output / "python" / quote(name + "@" + version, safe="")
            folder.mkdir(parents=True)
            filename = item["filename"]
            if Path(filename).name != filename:
                raise ValueError("unsafe Python source filename")
            target = folder / filename
            download(item["url"], target, item["digests"]["sha256"])
            record.update(source_status="captured", archives=[str(target.relative_to(output))])
        packages.append(record)
    return packages


def archive_tree(source: Path, target: Path) -> None:
    with tarfile.open(target, "w:gz") as archive:
        archive.add(source, arcname=source.name, filter=lambda item: None if ".git" in Path(item.name).parts else item)


def archive_build_context(source: Path, target: Path) -> None:
    """Capture reviewed build inputs, excluding local credentials and reports."""
    directories = {"compliance", "docs", "integrations", "packaging", "scripts", "src"}
    files = {".dockerignore", ".editorconfig", ".gitignore", "AGENTS.md", "CHANGELOG.md",
             "CODE_OF_CONDUCT.md", "CONTRIBUTING.md", "Dockerfile", "LICENSE", "README.md",
             "SECURITY.md", "SOURCE_OFFER.md", "SUPPORT.md", "THIRD_PARTY_NOTICES.md", "pyproject.toml", "install.sh"}
    private = {".git", ".ssh", ".aws", ".azure", ".gnupg", ".kube", ".config", ".codex",
               ".claude", ".agents", ".npmrc", ".netrc", ".pypirc", ".git-credentials",
               "engagements", "workspace", "workspaces", "release-evidence", "__pycache__"}

    def reviewed(item: tarfile.TarInfo) -> tarfile.TarInfo | None:
        parts = Path(item.name).parts[1:]
        if not parts:
            return item
        if parts[0] not in directories and not (len(parts) == 1 and parts[0] in files):
            return None
        if any(part in private or part == ".env" or part.startswith(".env.") or part.endswith((".pem", ".key")) for part in parts):
            return None
        if parts[:2] == ("docs", "verification"):
            return None
        if not (item.isfile() or item.isdir()):
            raise ValueError(f"build context contains a link or special file: {item.name}")
        return item

    with tarfile.open(target, "w:gz") as archive:
        archive.add(source, arcname=source.name, filter=reviewed)


def capture_builds(output: Path, inputs: Path) -> list[dict]:
    packages = []
    for ecosystem in ("go", "rust", "hashpump"):
        source = inputs / ecosystem
        if not source.is_dir() or not (source / "binaries.sha256").is_file():
            raise ValueError(f"builder did not preserve exact {ecosystem} source inputs")
        destination = output / "builds" / ecosystem
        shutil.copytree(source, destination)
        archives = [str(path.relative_to(output)) for path in sorted(destination.glob("*.tar.gz"))]
        if not archives:
            raise ValueError(f"builder source archives missing: {ecosystem}")
        for line in (source / "binaries.sha256").read_text().splitlines():
            expected, name = line.split()
            actual = Path("/usr/local/bin") / name
            if not actual.is_file() or digest(actual) != expected:
                raise ValueError(f"builder source/binary mismatch: {name}")
            packages.append({"kind": ecosystem, "name": name, "version": "sha256:" + expected,
                             "binary": str(actual), "binary_sha256": expected,
                             "source_status": "captured", "archives": archives})
    destination = output / "builds"
    shutil.copy2(inputs / "Dockerfile", destination / "Dockerfile")
    for name in ("capture-corresponding-source.py", "verify-corresponding-source.py"):
        shutil.copy2(inputs / name, destination / name)
    context = inputs / "context"
    for required in ("Dockerfile", "compliance/apt-public-exclusions.pref", "pyproject.toml",
                     "src/opencyber/__init__.py", "packaging/99-opencyber-hw.rules",
                     "scripts/capture-corresponding-source.py", "scripts/verify-corresponding-source.py",
                     "scripts/build-go-tools.sh", "compliance/patches/go/yq/go.mod"):
        if not (context / required).is_file():
            raise ValueError(f"required first-party Docker build input missing: {required}")
    archive_build_context(context, destination / "build-context.tar.gz")
    for name, source in (("opencyber", Path("/opt/opencyber")), *DIRECT_SOURCE_TREES.items()):
        target = destination / (name + ".tar.gz")
        if not source.is_dir():
            raise ValueError(f"direct source tree missing: {name}")
        archive_tree(source, target)
        packages.append({"kind": "direct", "name": name, "version": "sha256:" + digest(target),
                         "source_status": "captured", "archives": [str(target.relative_to(output))]})
    return packages


def capture_ruby(output: Path) -> list[dict]:
    packages = []
    for item in ruby_inventory():
        name, version = item["name"], item["version"]
        folder = output / "ruby" / quote(name + "@" + version, safe="")
        folder.mkdir(parents=True)
        subprocess.run(["gem", "fetch", "--clear-sources", "--source", "https://rubygems.org", "--platform", "ruby", name, "--version", version],
                       cwd=folder, check=True)
        archives = list(folder.glob("*.gem"))
        if len(archives) != 1:
            raise ValueError(f"exact Ruby source archive missing: {name}={version}")
        packages.append({"kind": "ruby", "name": name, "version": version, "source_status": "captured",
                         "archives": [str(path.relative_to(output)) for path in archives]})
    return packages


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--inputs", type=Path, default=Path("/source-inputs"))
    parser.add_argument("--platform", choices=("linux/amd64", "linux/arm64"))
    parser.add_argument("--inventory-only", action="store_true")
    args = parser.parse_args()
    if args.inventory_only:
        print(json.dumps(ecosystem_inventory(), sort_keys=True))
        return
    if not args.output or not args.platform:
        parser.error("--output and --platform are required for source capture")
    if args.output.exists():
        raise SystemExit("source output must not already exist")
    args.output.mkdir(parents=True)
    (args.output / "runtime-ecosystems.json").write_text(json.dumps(ecosystem_inventory(), sort_keys=True) + "\n")
    packages = capture_builds(args.output, args.inputs)
    packages.extend(capture_debian(args.output, args.inputs / "local"))
    packages.extend(capture_python(args.output))
    packages.extend(capture_ruby(args.output))
    artifacts = [{"path": str(path.relative_to(args.output)), "bytes": path.stat().st_size, "sha256": digest(path)}
                 for path in sorted(args.output.rglob("*")) if path.is_file()]
    manifest = {"schema": SCHEMA, "platform": args.platform, "complete": True,
                "packages": packages, "artifacts": artifacts}
    (args.output / "source-manifest.json").write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")


if __name__ == "__main__":
    main()
