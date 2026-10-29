#!/usr/bin/env python3
"""Check Docker's real context filter with synthetic credential markers."""
from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
PRIVATE_PATHS = (
    ".ssh/id_ed25519", ".npmrc", ".git-credentials", ".aws/credentials",
    "src/.aws/credentials", "src/.env", "src/.env.local", "docs/.config/test-token",
    "docs/verification/local-private.json", "scripts/.netrc", "src/.ssh/id_ed25519",
    "src/operator.key", "src/.git/config",
)


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="opencyber-context-") as directory:
        root = Path(directory)
        context = root / "context"
        context.mkdir()
        shutil.copyfile(ROOT / ".dockerignore", context / ".dockerignore")
        (context / "Dockerfile").write_text("FROM scratch\nCOPY . /context/\n")
        allowed = context / "src" / "safe-source.txt"
        allowed.parent.mkdir()
        allowed.write_text("synthetic public source\n")
        for name in PRIVATE_PATHS:
            path = context / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("synthetic private marker\n")
        output = root / "export"
        subprocess.run([
            "docker", "buildx", "build", "--network=none", "--progress=plain",
            "--output", f"type=local,dest={output}", str(context),
        ], check=True)
        exported = output / "context"
        leaked = [name for name in PRIVATE_PATHS if (exported / name).exists()]
        if leaked:
            raise SystemExit("Docker context admitted private markers: " + ", ".join(leaked))
        if (exported / "src" / "safe-source.txt").read_text() != allowed.read_text():
            raise SystemExit("Docker context omitted the public-source control")
    print(f"Docker context security passed: {len(PRIVATE_PATHS)} private markers excluded")


if __name__ == "__main__":
    main()
