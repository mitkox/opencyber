"""Shared helpers for the repository's generated-file scripts."""

from __future__ import annotations

from pathlib import Path


class StaleGeneratedFile(RuntimeError):
    """Raised in check mode when a tracked generated file is missing or stale."""


def ensure_generated_file(path: Path, source: str, *, check: bool, generate_command: str) -> bool:
    """Write ``source`` to ``path``, or verify the tracked file is current.

    Line endings are normalized before comparison so a checkout with CRLF does
    not report a false drift. Returns ``True`` when the file was written.
    """
    current: str | None = None
    if path.is_file():
        current = path.read_text(encoding="utf-8").replace("\r\n", "\n")
    if check:
        if current is None:
            raise StaleGeneratedFile(f"{path} is missing. Run `{generate_command}` and commit the result.")
        if current != source:
            raise StaleGeneratedFile(f"{path} is stale. Run `{generate_command}` and commit the result.")
        return False
    if current == source:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(source, encoding="utf-8")
    return True
