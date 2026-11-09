from __future__ import annotations

from pathlib import Path
import json
import os
import shlex
import subprocess
import tempfile
import textwrap
import unittest


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "scripts" / "opencyber-run.sh"
AIRGAP = ROOT / "scripts" / "opencyber-airgap.sh"


def run(*arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(RUNNER), *arguments],
        cwd=ROOT,
        text=True,
        capture_output=True,
        check=False,
    )


class LauncherTests(unittest.TestCase):
    def test_blue_team_profile_disables_network_and_host_exposure(self) -> None:
        result = run("--profile", "blue-team", "--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = shlex.split(result.stdout)
        self.assertIn("--cap-drop=ALL", arguments)
        self.assertIn("--read-only", arguments)
        self.assertEqual(arguments[arguments.index("--network") + 1], "none")
        self.assertIn("OPENCYBER_OFFLINE=1", arguments)
        self.assertFalse(any(value.startswith("--cap-add") for value in arguments))
        self.assertNotIn("--device", arguments)

    def test_blue_team_rejects_device_and_writable_root_in_any_order(self) -> None:
        for override in (("--device", "/dev/null"), ("--no-read-only",)):
            for arguments in (("--profile", "blue-team", *override), (*override, "--profile", "blue-team")):
                with self.subTest(arguments=arguments):
                    result = run(*arguments, "--dry-run")
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("blue-team does not allow", result.stderr)

    def test_custom_workspace_is_passed_to_the_server(self) -> None:
        result = subprocess.run(
            [str(RUNNER), "--profile", "blue-team", "--dry-run"],
            cwd=ROOT, env={**os.environ, "OPENCYBER_WORKSPACE_PATH": "/cases"},
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        arguments = shlex.split(result.stdout)
        self.assertIn("opencyber-workspace:/cases", arguments)
        self.assertIn("OPENCYBER_WORKSPACE=/cases", arguments)

    def test_software_profile_is_hardened_and_offline_capable(self) -> None:
        result = run("--profile", "software", "--offline", "--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        command = result.stdout
        self.assertIn("--cap-drop=ALL", command)
        self.assertIn("--read-only", command)
        self.assertIn("--tmpfs /root/.cache", command)
        self.assertIn("--tmpfs /root/.local/share", command)
        self.assertIn("--tmpfs /root/.nxc", command)
        self.assertIn("--tmpfs /root/.msf4", command)
        self.assertIn("OPENCYBER_OFFLINE=1", command)
        self.assertNotIn("--privileged", command)

    def test_wifi_profile_adds_host_network_and_capabilities(self) -> None:
        result = run("--profile", "wifi", "--dry-run")
        self.assertEqual(result.returncode, 0, result.stderr)
        command = result.stdout
        self.assertIn("--network host", command)
        self.assertIn("--cap-add NET_ADMIN", command.replace("--cap-add=NET_ADMIN", "--cap-add NET_ADMIN"))
        self.assertIn("--cap-add NET_RAW", command.replace("--cap-add=NET_RAW", "--cap-add NET_RAW"))
        self.assertNotIn("--privileged", command)

    def test_unknown_profile_and_argument_fail_closed(self) -> None:
        self.assertNotEqual(run("--profile", "teleport", "--dry-run").returncode, 0)
        self.assertNotEqual(run("--nonsense").returncode, 0)

    def test_airgap_help_is_available(self) -> None:
        result = subprocess.run(
            [str(AIRGAP), "--help"],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0)
        self.assertIn("export", result.stdout)
        self.assertIn("verify", result.stdout)
        self.assertIn("import", result.stdout)


class AirgapTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.state = root / "state"
        self.state.mkdir()
        self.bundle = root / "bundle"
        bindir = root / "bin"
        bindir.mkdir()
        (self.state / "image_id").write_text("sha256:" + "a" * 64 + "\n")
        (self.state / "repo_digests").write_text("opencyber@sha256:" + "b" * 64 + "\n")
        docker = bindir / "docker"
        docker.write_text(
            textwrap.dedent(
                """\
                #!/usr/bin/env bash
                set -eu
                state="$FAKE_DOCKER_STATE"
                printf '%s\n' "$*" >> "$state/commands"
                case "${1:-}" in
                  image)
                    case "${2:-}" in
                      inspect)
                        shift 2
                        fmt=""
                        if [[ "${1:-}" == "--format" ]]; then
                          fmt="$2"
                          shift 2
                        fi
                        if [[ ! -f "$state/image_id" ]]; then
                          exit 1
                        fi
                        case "$fmt" in
                          '{{.Id}}') cat "$state/image_id" ;;
                          '{{join .RepoDigests ","}}') cat "$state/repo_digests" ;;
                          *) : ;;
                        esac
                        ;;
                      save)
                        shift 2
                        output=""
                        if [[ "${1:-}" == "-o" ]]; then
                          output="$2"
                          shift 2
                        fi
                        printf 'fake archive\n' > "$output"
                        ;;
                      *) printf 'unexpected image invocation: %s\n' "$*" >&2; exit 2 ;;
                    esac
                    ;;
                  save)
                    shift
                    output=""
                    if [[ "${1:-}" == "-o" ]]; then
                      output="$2"
                      shift 2
                    fi
                    printf 'fake archive\n' > "$output"
                    ;;
                  load)
                    if [[ "${FAKE_FAIL_LOAD:-0}" == "1" ]]; then
                      exit 1
                    fi
                    touch "$state/loaded"
                    ;;
                  run)
                    entry=""
                    arguments=()
                    shift
                    while [[ $# -gt 0 ]]; do
                      case "$1" in
                        --rm) shift ;;
                        --entrypoint)
                          entry="$2"
                          shift 2
                          ;;
                        *)
                          arguments+=("$1")
                          shift
                          ;;
                      esac
                    done
                    if [[ "$entry" == "opencyber-mcp" && "${FAKE_FAIL_SELF_TEST:-0}" == "1" ]]; then
                      exit 1
                    fi
                    if [[ "$entry" == "opencyber-doctor" && "${FAKE_FAIL_DOCTOR:-0}" == "1" ]]; then
                      exit 1
                    fi
                    ;;
                  *) printf 'unexpected docker invocation: %s\n' "$*" >&2; exit 2 ;;
                esac
                """
            )
        )
        docker.chmod(0o755)
        self.env = {
            **os.environ,
            "PATH": f"{bindir}:{os.environ['PATH']}",
            "FAKE_DOCKER_STATE": str(self.state),
            "FAKE_DOCKER_IMAGE_PRESENT": "1",
        }

    def run_airgap(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [str(AIRGAP), *arguments],
            cwd=ROOT,
            env=self.env,
            text=True,
            capture_output=True,
            check=False,
        )

    def export_bundle(self) -> None:
        result = self.run_airgap("export", "--image", "opencyber:1.0.0-beta.1", "--output", str(self.bundle))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_checksum_filename_mismatch_fails_before_load(self):
        self.export_bundle()
        checksum = self.bundle / "opencyber-1.0.0-beta.1.tar.sha256"
        checksum.write_text("0" * 64 + "  different.tar\n")
        result = self.run_airgap("import", "--input", str(self.bundle))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("checksum file names", result.stderr)
        commands = (self.state / "commands").read_text()
        self.assertNotIn("load", commands)

    def test_loaded_image_identity_mismatch_fails_closed(self):
        self.export_bundle()
        release = json.loads((self.bundle / "release.json").read_text())
        release["image_id"] = "sha256:" + "c" * 64
        (self.bundle / "release.json").write_text(json.dumps(release))
        result = self.run_airgap("import", "--input", str(self.bundle))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("image ID does not match", result.stderr)

    def test_successful_import_runs_doctor_and_strict_self_test(self):
        self.export_bundle()
        result = self.run_airgap("import", "--input", str(self.bundle))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("identity OK", result.stdout)
        self.assertIn("strict MCP self-test OK", result.stdout)
        self.assertIn("doctor OK", result.stdout)
        commands = (self.state / "commands").read_text()
        self.assertIn("--entrypoint opencyber-mcp", commands)
        self.assertIn("--self-test", commands)
        self.assertIn("--entrypoint opencyber-doctor", commands)

    def test_missing_release_manifest_fails_closed(self):
        self.export_bundle()
        (self.bundle / "release.json").unlink()
        result = self.run_airgap("import", "--input", str(self.bundle))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("release.json is required", result.stderr)

    def test_failed_doctor_or_self_test_aborts_import(self):
        self.export_bundle()
        for variable in ("FAKE_FAIL_SELF_TEST", "FAKE_FAIL_DOCTOR"):
            with self.subTest(variable=variable):
                env = {**self.env, variable: "1"}
                result = subprocess.run(
                    [str(AIRGAP), "import", "--input", str(self.bundle)],
                    cwd=ROOT, env=env, text=True, capture_output=True, check=False,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("do not deploy this image", result.stderr)



if __name__ == "__main__":
    unittest.main()
