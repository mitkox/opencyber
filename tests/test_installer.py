from __future__ import annotations

import os
import re
from pathlib import Path
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "install.sh"


class InstallerTests(unittest.TestCase):
    def test_private_development_version_is_accepted(self):
        self.env["FAKE_DOCKER_IMAGE_VERSION"] = "0.5.1.dev0"
        result = self.run_installer("--version", "0.5.1.dev0", "--offline")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_arbitrary_version_suffixes_are_rejected_before_docker(self):
        for version in ("0.5.1.dev", "0.5.1.dev-1", "0.5.1/dev0", "latest"):
            with self.subTest(version=version):
                result = self.run_installer("--version", version)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("version must look like", result.stderr)

    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        root = Path(self.tempdir.name)
        self.state = root / "state"
        self.state.mkdir()
        bindir = root / "bin"
        bindir.mkdir()
        docker = bindir / "docker"
        docker.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/env bash
                set -eu
                printf '%s\\n' "$*" >> "$FAKE_DOCKER_STATE/commands"

                case "${1:-}" in
                  info)
                    if [[ "${2:-}" == "--format" ]]; then
                      printf 'amd64\\n'
                    fi
                    ;;
                  pull|start|stop)
                    ;;
                  exec)
                    [[ "${FAKE_DOCKER_FAIL_EXEC:-0}" != "1" ]]
                    ;;
                  run)
                    touch "$FAKE_DOCKER_STATE/container"
                    ;;
                  inspect)
                    if [[ "${2:-}" == "--format" ]]; then
                      printf '%s\\n' "${FAKE_DOCKER_MANAGED:-true}"
                    fi
                    ;;
                  image)
                    [[ "${2:-}" == "inspect" ]] || exit 2
                    if [[ "${3:-}" == "--format" ]]; then
                      printf '%s\\n' "${FAKE_DOCKER_IMAGE_VERSION:-0.3.0}"
                    fi
                    ;;
                  container)
                    [[ "${2:-}" == "inspect" ]]
                    test -f "$FAKE_DOCKER_STATE/container"
                    ;;
                  rename)
                    mv "$FAKE_DOCKER_STATE/container" "$FAKE_DOCKER_STATE/${3}"
                    ;;
                  rm)
                    target="${@: -1}"
                    rm -f "$FAKE_DOCKER_STATE/${target}" "$FAKE_DOCKER_STATE/container"
                    ;;
                  volume)
                    case "${2:-}" in
                      inspect)
                        if [[ "${3:-}" == "--format" ]]; then
                          test -f "$FAKE_DOCKER_STATE/volume"
                          printf 'true\\n'
                        else
                          test -f "$FAKE_DOCKER_STATE/volume"
                        fi
                        ;;
                      create)
                        touch "$FAKE_DOCKER_STATE/volume"
                        printf 'opencyber-workspace\\n'
                        ;;
                      rm)
                        rm -f "$FAKE_DOCKER_STATE/volume"
                        ;;
                    esac
                    ;;
                  *)
                    printf 'unexpected docker invocation: %s\\n' "$*" >&2
                    exit 2
                    ;;
                esac
                """
            )
        )
        docker.chmod(0o755)
        # The fake image reports the label of the current installer default, so a
        # version bump does not require editing the fixture. Tests that verify a
        # mismatch override this explicitly.
        self.env = {
            **os.environ,
            "PATH": f"{bindir}:{os.environ['PATH']}",
            "FAKE_DOCKER_STATE": str(self.state),
            "FAKE_DOCKER_IMAGE_VERSION": re.search(
                r'DEFAULT_VERSION="([^"]+)"', INSTALLER.read_text()
            ).group(1),
        }

    def run_installer(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(INSTALLER), *arguments],
            cwd=ROOT,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
        )

    def commands(self) -> str:
        return (self.state / "commands").read_text()

    def test_fresh_install_pulls_versioned_image_and_self_tests(self) -> None:
        version = re.search(r'DEFAULT_VERSION="([^"]+)"', INSTALLER.read_text()).group(1)
        result = self.run_installer()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"OpenCyber Harness {version} is ready", result.stdout)
        calls = self.commands()
        self.assertIn(f"pull ghcr.io/mitkox-dev/opencyber:{version}", calls)
        self.assertIn("volume create --label com.opencyber.harness.managed=true opencyber-workspace", calls)
        self.assertIn("--label com.opencyber.harness.managed=true", calls)
        self.assertIn("exec opencyber opencyber-mcp --self-test", calls)

    def test_install_is_hardened_by_default(self) -> None:
        result = self.run_installer()

        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.commands()
        for flag in (
            "--cap-drop=ALL",
            "--cap-add=NET_RAW",
            "--cap-add=NET_ADMIN",
            "--cap-add=NET_BIND_SERVICE",
            "--security-opt no-new-privileges",
            "--read-only",
            "--tmpfs /tmp",
            "--tmpfs /run",
            "--tmpfs /root/.config",
            "--tmpfs /root/.cache",
            "--tmpfs /root/.local/share",
            "--tmpfs /root/.nxc",
            "--tmpfs /root/.msf4",
        ):
            self.assertIn(flag, calls)

    def test_no_read_only_keeps_the_root_filesystem_writable(self) -> None:
        result = self.run_installer("--no-read-only")

        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.commands()
        self.assertIn("--cap-drop=ALL", calls)
        self.assertNotIn("--read-only", calls)
        self.assertNotIn("--tmpfs /root/.config", calls)

    def test_digest_install_uses_the_pinned_reference(self) -> None:
        digest = "sha256:" + "a" * 64

        result = self.run_installer("--digest", digest)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"pull ghcr.io/mitkox-dev/opencyber@{digest}", self.commands())

    def test_digest_environment_override_is_honored(self) -> None:
        digest = "sha256:" + "b" * 64
        self.env["OPENCYBER_DIGEST"] = digest

        result = self.run_installer()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"pull ghcr.io/mitkox-dev/opencyber@{digest}", self.commands())

    def test_invalid_digest_is_rejected(self) -> None:
        result = self.run_installer("--digest", "sha256:short")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--digest must look like sha256:", result.stderr)

    def test_version_label_mismatch_is_rejected(self) -> None:
        self.env["FAKE_DOCKER_IMAGE_VERSION"] = "0.1.0"

        result = self.run_installer()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("image version label is '0.1.0'", result.stderr)
        self.assertNotIn("run -d", self.commands())

    def test_offline_install_skips_pull_and_sets_offline_mode(self) -> None:
        result = self.run_installer("--offline")

        self.assertEqual(result.returncode, 0, result.stderr)
        calls = self.commands()
        self.assertNotIn("pull ", calls)
        self.assertIn("image inspect", calls)
        self.assertIn("OPENCYBER_OFFLINE=1", calls)

    def test_repeat_install_replaces_only_managed_container(self) -> None:
        first = self.run_installer()
        self.assertEqual(first.returncode, 0, first.stderr)

        second = self.run_installer()

        self.assertEqual(second.returncode, 0, second.stderr)
        calls = self.commands()
        self.assertIn("stop opencyber", calls)
        self.assertIn("rename opencyber opencyber-rollback-", calls)
        self.assertNotIn("volume rm", calls)

    def test_upgrade_and_rollback_preserve_workspace_data(self) -> None:
        first = self.run_installer()
        self.assertEqual(first.returncode, 0, first.stderr)
        marker = self.state / "workspace-data"
        marker.write_text("engagement-data")

        upgraded = self.run_installer()
        self.assertEqual(upgraded.returncode, 0, upgraded.stderr)
        self.assertTrue(marker.exists(), "upgrade replaced the workspace volume")

        rolled_back = self.run_installer()
        self.assertEqual(rolled_back.returncode, 0, rolled_back.stderr)
        self.assertTrue(marker.exists(), "rollback replaced the workspace volume")

        removed = self.run_installer("--uninstall")
        self.assertEqual(removed.returncode, 0, removed.stderr)
        self.assertTrue(marker.exists(), "uninstall removed the workspace without purge")
        self.assertNotIn("volume rm", self.commands())

    def test_existing_unmanaged_container_is_not_replaced(self) -> None:
        (self.state / "container").touch()
        self.env["FAKE_DOCKER_MANAGED"] = "false"

        result = self.run_installer()

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("not managed by this installer", result.stderr)
        calls = self.commands()
        self.assertNotIn("stop opencyber", calls)
        self.assertNotIn("rename opencyber", calls)

    def test_uninstall_preserves_workspace_unless_purge_is_explicit(self) -> None:
        installed = self.run_installer()
        self.assertEqual(installed.returncode, 0, installed.stderr)

        removed = self.run_installer("--uninstall")

        self.assertEqual(removed.returncode, 0, removed.stderr)
        self.assertTrue((self.state / "volume").exists())
        self.assertIn("preserved workspace volume", removed.stdout)

    def test_explicit_purge_removes_managed_workspace(self) -> None:
        installed = self.run_installer()
        self.assertEqual(installed.returncode, 0, installed.stderr)

        removed = self.run_installer("--uninstall", "--purge-workspace")

        self.assertEqual(removed.returncode, 0, removed.stderr)
        self.assertFalse((self.state / "volume").exists())
        self.assertIn("volume rm opencyber-workspace", self.commands())

    def test_purge_without_uninstall_is_rejected(self) -> None:
        result = self.run_installer("--purge-workspace")

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("may only be used with --uninstall", result.stderr)


if __name__ == "__main__":
    unittest.main()
