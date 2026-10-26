#!/usr/bin/env python3
"""Package an already sanitized SecLists tree and its rebuildable native source.

The caller verifies the pinned upstream archive before extraction and removes
RockYou paths. This builder refuses those paths; it does not verify upstream
archive bytes or infer permission to redistribute individual files.
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import tarfile
import tempfile


PACKAGE = "opencyber-offline-wordlists"
DEFAULT_VERSION = "2026.1+opencyber1"
MAINTAINER = "OpenCyber Maintainers <noreply@opencyber.invalid>"
UPSTREAM_URL = "https://github.com/danielmiessler/SecLists/archive/refs/tags/2026.1.tar.gz"
UPSTREAM_SHA256 = "226c49d04974ec6c39dadbf38ba78e67fec8824d729e66907f6050329da98932"
KEYBOARD = Path("Passwords/Keyboard-Walks/walk-the-line.txt")


def validate(source: Path, output: Path, version: str) -> list[Path]:
    if not re.fullmatch(r"[0-9][A-Za-z0-9.+~]*", version):
        raise ValueError("version must be a native Debian version without a revision or path separators")
    if not source.is_dir():
        raise ValueError("source must be a sanitized SecLists directory")
    if output == source or output.is_relative_to(source):
        raise ValueError("output must be outside the source directory")
    paths = sorted(source.rglob("*"))
    for path in paths:
        relative = path.relative_to(source)
        if "rockyou" in relative.as_posix().casefold():
            raise ValueError(f"unexpected RockYou path in sanitized input: {relative}")
        mode = path.lstat().st_mode
        if stat.S_ISLNK(mode):
            target = os.readlink(path)
            if (Path(target).is_absolute() or "rockyou" in target.casefold()
                    or not path.resolve().is_relative_to(source)):
                raise ValueError(f"unsafe symlink in sanitized input: {relative}")
            if not path.exists():
                raise ValueError(f"dangling symlink in sanitized input: {relative}")
        elif not (stat.S_ISDIR(mode) or stat.S_ISREG(mode)):
            raise ValueError(f"unsupported data file in sanitized input: {relative}")
    for required in (Path("LICENSE"), KEYBOARD):
        if not (source / required).is_file():
            raise ValueError(f"required SecLists data file is missing: {required}")
    return paths


def data_digest(source: Path, paths: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in paths:
        relative = path.relative_to(source).as_posix().encode()
        if path.is_symlink():
            value = os.readlink(path).encode()
            kind = b"symlink"
        elif path.is_file():
            value = bytes.fromhex(hash_file(path))
            kind = b"file-sha256"
        else:
            value = b""
            kind = b"directory"
        digest.update(kind + b"\0" + relative + b"\0" + value + b"\0")
    return digest.hexdigest()


def hash_file(path: Path, algorithm: str = "sha256") -> str:
    digest = hashlib.new(algorithm, usedforsecurity=False)
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write(path: Path, value: str, executable: bool = False) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")
    path.chmod(0o755 if executable else 0o644)


def normalize(tree: Path) -> None:
    for path in [tree, *tree.rglob("*")]:
        if not path.is_symlink():
            executable = path.relative_to(tree).as_posix() in ("debian/rules", "scripts/build-offline-wordlists.py")
            path.chmod(0o755 if path.is_dir() or executable else 0o644)
        os.utime(path, (0, 0), follow_symlinks=False)


def copyright_text(license_text: str) -> str:
    return (
        "OpenCyber offline wordlists\n\n"
        "This is a first-party data package, not the Kali seclists or wordlists package.\n"
        "Upstream: SecLists 2026.1, https://github.com/danielmiessler/SecLists\n"
        "The upstream root MIT license covers the collection. File-specific terms and\n"
        "copyright notices remain applicable and are preserved in /usr/share/seclists.\n"
        "RockYou paths are excluded from this package and its corresponding source.\n"
        "Packaging builder: Apache-2.0, https://www.apache.org/licenses/LICENSE-2.0\n\n"
        "Upstream root LICENSE (verbatim):\n\n" + license_text
    )


def packaging_license() -> Path:
    for candidate in (Path(__file__).resolve().parents[1] / "LICENSE",
                      Path("/usr/share/common-licenses/Apache-2.0")):
        if candidate.is_file() and "Version 2.0, January 2004" in candidate.read_text(encoding="utf-8"):
            return candidate
    raise ValueError("Apache-2.0 packaging LICENSE is required beside scripts/ or in Debian common-licenses")


def build_binary(source: Path, output: Path, version: str, paths: list[Path]) -> None:
    with tempfile.TemporaryDirectory(prefix="wordlists-") as temporary:
        tree = Path(temporary) / "package"
        shutil.copytree(source, tree / "usr/share/seclists", symlinks=True)
        wordlists = tree / "usr/share/wordlists"
        wordlists.mkdir()
        shutil.copyfile(source / KEYBOARD, wordlists / "opencyber-keyboard-patterns.txt")
        (wordlists / "seclists").symlink_to("/usr/share/seclists")
        documentation = tree / f"usr/share/doc/{PACKAGE}"
        license_text = (source / "LICENSE").read_text(encoding="utf-8")
        write(documentation / "copyright", copyright_text(license_text))
        shutil.copyfile(source / "LICENSE", documentation / "LICENSE")
        shutil.copyfile(packaging_license(), documentation / "LICENSE.packaging")
        provenance = {
            "package": PACKAGE,
            "version": version,
            "upstream_release": "2026.1",
            "upstream_archive_url": UPSTREAM_URL,
            "expected_upstream_archive_sha256": UPSTREAM_SHA256,
            "upstream_archive_verification": "Caller must verify before extraction; builder receives only sanitized data.",
            "excluded_paths": "Any path containing rockyou (case-insensitive).",
            "sanitized_tree_sha256": data_digest(source, paths),
            "tree_hash_format": "Sorted path records: type NUL relative-path NUL value NUL; value is raw SHA256 for files, link target for symlinks, empty for directories.",
            "upstream_license_sha256": hash_file(source / "LICENSE"),
            "keyboard_source": KEYBOARD.as_posix(),
        }
        write(documentation / "provenance.json", json.dumps(provenance, indent=2, sort_keys=True) + "\n")
        write(tree / "DEBIAN/control", (
            f"Package: {PACKAGE}\nSource: {PACKAGE}\nVersion: {version}\nArchitecture: all\n"
            f"Maintainer: {MAINTAINER}\nSection: misc\nPriority: optional\n"
            "Provides: seclists, wordlists\nConflicts: seclists, wordlists\nReplaces: seclists, wordlists\n"
            "Homepage: https://github.com/danielmiessler/SecLists\n"
            "Description: OpenCyber sanitized offline wordlist data\n"
            " SecLists data with RockYou paths excluded, plus a keyboard-pattern alias.\n"
            " Upstream root license and file-specific notices are preserved.\n"
        ))
        normalize(tree)
        subprocess.run(
            ["dpkg-deb", "--build", "--root-owner-group", "--uniform-compression", "-Zgzip",
             str(tree), str(output / f"{PACKAGE}.deb")],
            check=True, env={**os.environ, "SOURCE_DATE_EPOCH": "0"},
        )


def build_source(source: Path, output: Path, version: str) -> None:
    destination = output / "source"
    destination.mkdir(exist_ok=True)
    basename = f"{PACKAGE}_{version}"
    archive = destination / f"{basename}.tar.gz"
    with tempfile.TemporaryDirectory(prefix="wordlists-source-") as temporary:
        tree = Path(temporary) / f"{PACKAGE}-{version}"
        shutil.copytree(source, tree / "seclists", symlinks=True)
        shutil.copyfile(packaging_license(), tree / "LICENSE")
        builder = tree / "scripts/build-offline-wordlists.py"
        builder.parent.mkdir()
        shutil.copyfile(Path(__file__), builder)
        write(tree / "debian/source/format", "3.0 (native)\n")
        write(tree / "debian/control", (
            f"Source: {PACKAGE}\nSection: misc\nPriority: optional\nMaintainer: {MAINTAINER}\n"
            "Build-Depends: python3 (>= 3.11), dpkg-dev\nStandards-Version: 4.7.0\n"
            "Rules-Requires-Root: no\nHomepage: https://github.com/danielmiessler/SecLists\n\n"
            f"Package: {PACKAGE}\nArchitecture: all\n"
            "Provides: seclists, wordlists\nConflicts: seclists, wordlists\nReplaces: seclists, wordlists\n"
            "Description: OpenCyber sanitized offline wordlist data\n"
            " SecLists data with RockYou paths excluded; original terms are preserved.\n"
        ))
        write(tree / "debian/changelog", (
            f"{PACKAGE} ({version}) unstable; urgency=medium\n\n"
            "  * Package sanitized SecLists data with upstream and file-specific terms.\n\n"
            f" -- {MAINTAINER}  Thu, 01 Jan 1970 00:00:00 +0000\n"
        ))
        write(tree / "debian/copyright", copyright_text((source / "LICENSE").read_text(encoding="utf-8")))
        write(tree / "debian/rules", (
            "#!/usr/bin/make -f\n"
            ".PHONY: clean build build-indep build-arch binary binary-indep binary-arch\n"
            "clean:\n\trm -rf debian/build debian/files\n"
            "build build-indep build-arch:\n"
            "binary: binary-indep\n"
            "binary-arch:\n"
            "binary-indep:\n"
            "\tpython3 scripts/build-offline-wordlists.py --source seclists --output debian/build "
            f"--version {version} --binary-only\n"
            f"\tcp debian/build/{PACKAGE}.deb ../{basename}_all.deb\n"
            f"\tdpkg-distaddfile {basename}_all.deb misc optional\n"
        ), executable=True)
        normalize(tree)
        with archive.open("wb") as raw:
            with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
                with tarfile.open(fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT) as bundle:
                    for path in [tree, *sorted(tree.rglob("*"))]:
                        info = bundle.gettarinfo(str(path), arcname=path.relative_to(tree.parent).as_posix())
                        info.uid = info.gid = 0
                        info.uname = info.gname = ""
                        info.mtime = 0
                        if info.isfile():
                            with path.open("rb") as stream:
                                bundle.addfile(info, stream)
                        else:
                            bundle.addfile(info)
    size = archive.stat().st_size
    write(destination / f"{basename}.dsc", (
        f"Format: 3.0 (native)\nSource: {PACKAGE}\nBinary: {PACKAGE}\nArchitecture: all\n"
        f"Version: {version}\nMaintainer: {MAINTAINER}\n"
        "Homepage: https://github.com/danielmiessler/SecLists\n"
        f"Checksums-Sha256:\n {hash_file(archive)} {size} {archive.name}\n"
        f"Files:\n {hash_file(archive, 'md5')} {size} {archive.name}\n"
    ))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--version", default=DEFAULT_VERSION)
    parser.add_argument("--binary-only", action="store_true", help="used by captured native-source debian/rules")
    args = parser.parse_args()
    try:
        source, output = args.source.resolve(), args.output.resolve()
        paths = validate(source, output, args.version)
        output.mkdir(parents=True, exist_ok=True)
        build_binary(source, output, args.version, paths)
        if not args.binary_only:
            build_source(source, output, args.version)
    except (OSError, ValueError, RuntimeError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"wordlist package build failed: {error}\n")


if __name__ == "__main__":
    main()
