#!/usr/bin/env python3
"""Stream bounded, byte-preserving license material and its scoped inventory."""
from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import struct
import sys
import tarfile
import zipfile


SCAN_ROOTS = ("/usr/share", "/usr/lib", "/usr/local", "/opt", "/var/lib/gems")
TOKENS = ("license", "licence", "copyright", "copying", "notice", "eula", "redist")
BINARY_SUFFIXES = frozenset({".class", ".pyc", ".pyo", ".pyd", ".dll", ".exe", ".so", ".dylib", ".o",
                             ".obj", ".a", ".lib", ".pdb", ".wasm", ".ko", ".dex", ".elf", ".jar"})
LIMITS = {"max_file_bytes": 16 * 1024 * 1024, "max_member_bytes": 4 * 1024 * 1024,
          "max_total_bytes": 512 * 1024 * 1024, "max_archive_bytes": 256 * 1024 * 1024,
          "max_archive_members": 100000, "max_visited_paths": 1000000, "max_materials": 100000}
MAX_DIRECTORY_BYTES = 8 * 1024 * 1024
MAX_OMISSIONS = 2000


def material_name(name: str) -> bool:
    return any(token in name.lower() for token in TOKENS)


def generic_material_path(path: PurePosixPath) -> bool:
    if path.name.lower() == "copying.lib":
        return True
    if path.suffix.lower() in BINARY_SUFFIXES or re.search(r"\.so(?:\.\d+)+$", path.name.lower()):
        return False
    return any(material_name(part) for part in path.parts)


def safe_relative(name: str) -> bool:
    path = PurePosixPath(name)
    return (bool(path.parts) and not path.is_absolute() and ".." not in path.parts
            and "\\" not in name and "\x00" not in name and all(":" not in part for part in path.parts))


class Collector:
    def __init__(self, root: Path, limits: dict[str, int], archive: tarfile.TarFile):
        self.root = root.resolve(strict=True)
        self.limits = limits
        self.archive = archive
        self.materials: list[dict] = []
        self.omissions: list[dict] = []
        self.omission_count = 0
        self.total_bytes = 0
        self.visited_paths = 0
        self.directory_symlinks = 0

    def omit(self, path: str, reason: str, **details: object) -> None:
        self.omission_count += 1
        if len(self.omissions) < MAX_OMISSIONS:
            self.omissions.append({"source_path": path, "reason": reason, **details})

    def source_path(self, path: Path) -> str:
        return "/" + path.relative_to(self.root).as_posix()

    def in_scope(self, path: Path) -> bool:
        return any(path.is_relative_to(self.root / base.lstrip("/")) for base in SCAN_ROOTS)

    def add(self, archive_path: str, content: bytes, **source: object) -> None:
        if len(self.materials) >= self.limits["max_materials"]:
            self.omit(str(source["source_path"]), "material-count-limit")
            return
        if self.total_bytes + len(content) > self.limits["max_total_bytes"]:
            self.omit(str(source["source_path"]), "total-size-limit", member_path=source.get("member_path"))
            return
        info = tarfile.TarInfo(archive_path)
        info.size = len(content)
        info.mode = 0o644
        self.archive.addfile(info, io.BytesIO(content))
        self.materials.append({"archive_path": archive_path, "size_bytes": len(content),
                               "sha256": hashlib.sha256(content).hexdigest(), **source})
        self.total_bytes += len(content)

    def file(self, path: Path, selected: bool) -> None:
        source = self.source_path(path)
        if not safe_relative(source.lstrip("/")):
            self.omit(source, "unsafe-source-path")
            return
        try:
            resolved = path.resolve(strict=True)
            if not self.in_scope(resolved):
                self.omit(source, "symlink-outside-scope")
                return
            if not resolved.is_file():
                self.omit(source, "not-regular-file")
                return
            if selected:
                if resolved.stat().st_size > self.limits["max_file_bytes"]:
                    self.omit(source, "file-size-limit")
                else:
                    with resolved.open("rb") as handle:
                        content = handle.read(self.limits["max_file_bytes"] + 1)
                    if len(content) > self.limits["max_file_bytes"]:
                        self.omit(source, "file-size-limit")
                    else:
                        self.add(source.lstrip("/"), content, kind="file", source_path=source,
                                 resolved_source_path=self.source_path(resolved))
            if path.suffix.lower() == ".jar":
                self.jar(resolved, source)
        except (OSError, RuntimeError) as error:
            self.omit(source, "file-read-error", error=type(error).__name__)

    def jar(self, path: Path, source: str) -> None:
        """Check ZIP directory bounds before ZipFile allocates its entry objects."""
        size = path.stat().st_size
        if size > self.limits["max_archive_bytes"]:
            self.omit(source, "jar-size-limit")
            return
        with path.open("rb") as handle:
            handle.seek(max(0, size - 65557))
            tail = handle.read(65557)
        offset = tail.rfind(b"PK\x05\x06")
        if offset < 0 or len(tail) - offset < 22:
            self.opaque_archive(path, source)
            return
        _, disk, cd_disk, disk_entries, entries, cd_size, cd_offset, comment_size = struct.unpack_from(
            "<4s4H2LH", tail, offset)
        if (disk or cd_disk or disk_entries != entries or entries == 65535 or cd_size == 0xFFFFFFFF
                or cd_offset == 0xFFFFFFFF or cd_size > MAX_DIRECTORY_BYTES
                or entries > self.limits["max_archive_members"]):
            self.omit(source, "jar-directory-limit")
            return
        if offset + 22 + comment_size != len(tail) or cd_offset + cd_size > size - len(tail) + offset:
            self.opaque_archive(path, source)
            return
        try:
            with zipfile.ZipFile(path) as jar:
                # Verify the parsed directory too; malformed entry counts must not bypass the bound.
                if len(jar.infolist()) > self.limits["max_archive_members"]:
                    self.omit(source, "jar-directory-limit")
                    return
                members = [item for item in jar.infolist() if not item.is_dir() and
                           (generic_material_path(PurePosixPath(item.orig_filename))
                            or PurePosixPath(item.orig_filename).name.lower() == "pom.xml")]
                if not members:
                    return
                with path.open("rb") as handle:
                    jar_hash = hashlib.file_digest(handle, "sha256").hexdigest()
                seen = set()
                for item in sorted(members, key=lambda member: member.orig_filename):
                    name = item.orig_filename
                    parts = PurePosixPath(name)
                    if not safe_relative(name) or parts.as_posix() in seen:
                        self.omit(source, "unsafe-jar-member", member_path=name)
                        continue
                    seen.add(parts.as_posix())
                    if stat.S_ISLNK(item.external_attr >> 16):
                        self.omit(source, "jar-member-symlink", member_path=name)
                        continue
                    if item.file_size > self.limits["max_member_bytes"]:
                        self.omit(source, "jar-member-size-limit", member_path=name)
                        continue
                    with jar.open(item) as handle:
                        content = handle.read(self.limits["max_member_bytes"] + 1)
                    if len(content) > self.limits["max_member_bytes"]:
                        self.omit(source, "jar-member-size-limit", member_path=name)
                        continue
                    self.add(f"embedded-jars/{jar_hash}/{source.lstrip('/')}/{parts.as_posix()}", content,
                             kind="jar-member", source_path=source, source_sha256=jar_hash, member_path=name)
        except zipfile.BadZipFile:
            self.opaque_archive(path, source)
        except (OSError, ValueError, RuntimeError, NotImplementedError) as error:
            self.omit(source, "jar-read-error", error=type(error).__name__)

    def opaque_archive(self, path: Path, source: str) -> None:
        # Some exploit/payload files use .jar names but cannot be interpreted as ZIPs.
        # Preserve their full bytes without classifying their contents or license.
        if path.stat().st_size > self.limits["max_file_bytes"]:
            self.omit(source, "opaque-archive-size-limit")
            return
        with path.open("rb") as handle:
            content = handle.read(self.limits["max_file_bytes"] + 1)
        if len(content) > self.limits["max_file_bytes"]:
            self.omit(source, "opaque-archive-size-limit")
            return
        self.add("opaque-archives/" + source.lstrip("/"), content, kind="opaque-archive",
                 source_path=source, archive_interpretation="not-a-valid-zip")

    def collect(self) -> dict:
        stack = [self.root / name.lstrip("/") for name in reversed(SCAN_ROOTS)]
        while stack:
            directory = stack.pop()
            if directory.is_symlink():
                self.directory_symlinks += 1
                continue
            if not directory.exists():
                continue
            try:
                children = []
                with os.scandir(directory) as scanner:
                    for entry in scanner:
                        self.visited_paths += 1
                        if self.visited_paths > self.limits["max_visited_paths"]:
                            self.omit(self.source_path(directory), "visited-path-limit")
                            stack.clear()
                            break
                        children.append(entry)
                directories = []
                for entry in sorted(children, key=lambda item: item.name):
                    path = Path(entry.path)
                    if entry.is_dir(follow_symlinks=False):
                        directories.append(path)
                    elif entry.is_symlink() and path.is_dir():
                        self.directory_symlinks += 1
                    else:
                        parts = path.relative_to(self.root).parts
                        selected = generic_material_path(path.relative_to(self.root)) or (
                            entry.name == "Module.manifest" and "ghidra" in parts)
                        if selected or path.suffix.lower() == ".jar":
                            self.file(path, selected)
                if self.visited_paths <= self.limits["max_visited_paths"]:
                    stack.extend(reversed(directories))
            except OSError as error:
                self.omit(self.source_path(directory), "directory-read-error", error=type(error).__name__)
        return {"schema": "opencyber.license-materials/v1", "redistribution_approval": False,
                "scope": {"roots": list(SCAN_ROOTS), "name_contains": list(TOKENS),
                          "generic_name_binary_suffix_exclusions": sorted(BINARY_SUFFIXES),
                          "generic_name_binary_suffix_exceptions": ["COPYING.LIB"],
                          "versioned_shared_libraries": "excluded from generic name matching: .so.<numeric version>",
                          "additional_files": ["Ghidra Module.manifest", "JAR pom.xml", "opaque non-ZIP .jar bytes"],
                          "directory_symlinks": "not followed; targets inside roots are scanned independently",
                          "nested_archives": "not recursively inspected",
                          "meaning": "Observed bytes only; no parent-license inheritance or component approval. "
                                     "Complete collection within this scope does not establish redistribution rights."},
                "collection": {"status": "partial" if self.omission_count else "complete", "limits": self.limits,
                               "max_jar_directory_bytes": MAX_DIRECTORY_BYTES, "visited_paths": self.visited_paths,
                               "directory_symlinks_not_followed": self.directory_symlinks,
                               "retained_bytes": self.total_bytes, "omission_count": self.omission_count,
                               "omissions": self.omissions,
                               "omissions_truncated": self.omission_count > len(self.omissions)},
                "materials": sorted(self.materials, key=lambda item: item["archive_path"])}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path("/"))
    for name, default in LIMITS.items():
        parser.add_argument("--" + name.replace("_", "-"), type=int, default=default)
    arguments = parser.parse_args()
    limits = {name: getattr(arguments, name) for name in LIMITS}
    if any(value < 1 for value in limits.values()):
        parser.error("collection limits must be positive")
    with gzip.GzipFile(filename="", mode="wb", fileobj=sys.stdout.buffer, mtime=0) as compressed:
        with tarfile.open(fileobj=compressed, mode="w|") as archive:
            collector = Collector(arguments.root, limits, archive)
            inventory = collector.collect()
            content = (json.dumps(inventory, indent=2, sort_keys=True) + "\n").encode("utf-8")
            info = tarfile.TarInfo("LICENSE-INVENTORY.json")
            info.size = len(content)
            info.mode = 0o644
            archive.addfile(info, io.BytesIO(content))
    return 1 if collector.omission_count else 0


if __name__ == "__main__":
    raise SystemExit(main())
