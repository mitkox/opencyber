from __future__ import annotations

from pathlib import Path
import os
import shlex
import subprocess
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


if __name__ == "__main__":
    unittest.main()
