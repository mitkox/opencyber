from __future__ import annotations

import importlib.util
import json
from pathlib import Path
import socket
import subprocess
import sys
import time
import unittest
import urllib.error
import urllib.request


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "scripts" / "poc-lab-target.py"
DRIVER = ROOT / "scripts" / "poc-lab-run.py"
LAB_CONFIG = ROOT / "integrations" / "opencode" / "opencode.poc-lab.json.example"


def _load_driver():
    spec = importlib.util.spec_from_file_location("poc_lab_run", DRIVER)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


class FixtureTargetTests(unittest.TestCase):
    """The lab fixture must stay deterministic; the driver depends on it."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.port = _free_port()
        cls.process = subprocess.Popen(
            [sys.executable, str(FIXTURE), "--host", "127.0.0.1", "--port", str(cls.port)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            try:
                urllib.request.urlopen(f"http://127.0.0.1:{cls.port}/health", timeout=1).read()
                return
            except OSError:
                time.sleep(0.05)
        cls.process.terminate()
        raise AssertionError("the lab fixture did not start")

    @classmethod
    def tearDownClass(cls) -> None:
        cls.process.terminate()
        try:
            cls.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            cls.process.kill()

    def _get(self, path: str) -> tuple[int, str]:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{self.port}{path}", timeout=2) as response:
                return response.status, response.read().decode("utf-8")
        except urllib.error.HTTPError as error:
            return error.code, error.read().decode("utf-8")

    def test_version_banner_matches_the_spec_assertion(self) -> None:
        status, body = self._get("/version")
        self.assertEqual(status, 200)
        self.assertEqual(body, "FixtureApp 1.4.2")

    def test_traversal_path_returns_a_fixed_canary(self) -> None:
        status, body = self._get("/download?file=../../../../etc/opencyber-canary")
        self.assertEqual(status, 200)
        self.assertRegex(body, r"^OPENCYBER-CANARY-[0-9a-f]{16}$")
        # Deterministic: the same request returns the same canary.
        self.assertEqual(body, self._get("/download?file=../../../../etc/opencyber-canary")[1])

    def test_plain_download_is_not_found(self) -> None:
        status, _ = self._get("/download?file=report.txt")
        self.assertEqual(status, 404)


class DriverContractTests(unittest.TestCase):
    """Guards for the lab driver's transport contract and evidence shape."""

    def test_container_command_attaches_stdin(self) -> None:
        # Regression: without `-i`, docker exec closes stdin and the stdio MCP
        # server exits before answering `initialize`.
        driver = _load_driver()
        self.assertIn("-i", driver._container_env())

    def test_lab_config_is_valid_json_with_code_mode_and_guards(self) -> None:
        config = json.loads(LAB_CONFIG.read_text(encoding="utf-8"))
        server = config["mcp"]["servers"]["opencyber"]
        self.assertIs(server["codemode"], True)
        self.assertIn("docker", server["command"])
        self.assertIn("-i", server["command"])
        actions = {(row["action"], row["effect"]) for row in config["permissions"]}
        self.assertIn(("opencyber_oc_bash", "deny"), actions)
        self.assertIn(("opencyber_oc_python", "deny"), actions)
        self.assertIn(("opencyber_oc_poc_run", "ask"), actions)

    def test_image_mode_uses_the_installed_console_scripts(self) -> None:
        driver = _load_driver()
        saved = dict(driver.SETTINGS)
        try:
            driver.SETTINGS["mode"] = "image"
            self.assertEqual(driver._server_command(), ["opencyber-mcp"])
            self.assertEqual(driver._cli_command(), ["opencyber-poc"])
            self.assertNotIn("PYTHONPATH", " ".join(driver._container_env()))
        finally:
            driver.SETTINGS.clear()
            driver.SETTINGS.update(saved)

    def test_source_mode_pins_the_checkout_on_pythonpath(self) -> None:
        driver = _load_driver()
        saved = dict(driver.SETTINGS)
        try:
            driver.SETTINGS["mode"] = "source"
            self.assertIn("PYTHONPATH=/opt/opencyber-050", driver._container_env())
            self.assertEqual(driver._server_command(), ["python3", "-m", "opencyber.server"])
        finally:
            driver.SETTINGS.clear()
            driver.SETTINGS.update(saved)

    def test_driver_has_no_hardcoded_approval_key(self) -> None:
        text = DRIVER.read_text(encoding="utf-8")
        self.assertNotIn("OPENCYBER_APPROVAL_KEY=", text)
        self.assertIn("OPENCYBER_APPROVAL_KEY_FILE", text)


if __name__ == "__main__":
    unittest.main()
