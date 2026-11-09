#!/usr/bin/env python3
"""Exercise installed security tools against owned fixtures inside the image.

Run through airgap-tools-image.sh: the host removes networking, capabilities,
host credentials and device access before this lab starts.
"""

from __future__ import annotations

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import subprocess
import sys
import threading
import time
from typing import Any, Iterator
from urllib.parse import urlsplit
import xml.etree.ElementTree as ET


STREAM_LIMIT = 32 * 1024
EXPECTED_VERSION = "0.5.1"
WORDPRESS_VERSION = "6.8.3"
REQUIRED_TOOLS = {
    "oc_nmap": "nmap",
    "oc_rustscan": "rustscan",
    "oc_autorecon": "autorecon",
    "oc_netexec": "nxc",
    "oc_wpscan": "wpscan",
}


def execute(argv: list[str], timeout: float = 30) -> dict[str, Any]:
    """Capture bounded output and kill the whole process group on timeout."""
    started = time.monotonic()
    result: dict[str, Any] = {"argv": argv, "timeout_seconds": timeout}
    environment = dict(os.environ)
    environment.pop("WPSCAN_API_TOKEN", None)
    try:
        process = subprocess.Popen(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            env=environment, start_new_session=True,
        )
    except OSError as error:
        return {**result, "returncode": None, "stdout": "", "stderr": str(error), "timed_out": False,
                "stdout_bytes": 0, "stderr_bytes": 0, "output_limited": False, "elapsed_seconds": 0}

    retained: dict[str, bytearray] = {"stdout": bytearray(), "stderr": bytearray()}
    sizes = {"stdout": 0, "stderr": 0}
    timed_out = False
    deadline = started + timeout
    with selectors.DefaultSelector() as selector:
        for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
            assert stream is not None
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, name)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            for key, _ in selector.select(min(remaining, 0.1)):
                block = os.read(key.fileobj.fileno(), 8192)
                if not block:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                name = key.data
                sizes[name] += len(block)
                retained[name].extend(block[:max(0, STREAM_LIMIT - len(retained[name]))])
        if not timed_out:
            try:
                process.wait(timeout=max(0.01, deadline - time.monotonic()))
            except subprocess.TimeoutExpired:
                timed_out = True
        # Also reap descendants whose parent exited before they closed pipes.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        for key in list(selector.get_map().values()):
            key.fileobj.close()
    process.wait()
    return {
        **result, "returncode": process.returncode, "timed_out": timed_out,
        "stdout": retained["stdout"].decode("utf-8", errors="replace"),
        "stderr": retained["stderr"].decode("utf-8", errors="replace"),
        "stdout_bytes": sizes["stdout"], "stderr_bytes": sizes["stderr"],
        "output_limited": any(size > STREAM_LIMIT for size in sizes.values()),
        "elapsed_seconds": round(time.monotonic() - started, 3),
    }


def command_check(name: str, argv: list[str], *, timeout: float = 30,
                  markers: tuple[str, ...] = ()) -> dict[str, Any]:
    result = execute(argv, timeout)
    text = (result["stdout"] + result["stderr"]).lower()
    result.update(name=name, passed=result["returncode"] == 0 and not result["timed_out"]
                  and all(marker.lower() in text for marker in markers))
    return result


def isolation_check() -> dict[str, Any]:
    status = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
    interfaces = sorted(name for _, name in socket.if_nameindex())
    capabilities = {key: status.get(key, "").strip() for key in ("CapEff", "CapPrm", "CapBnd")}
    root_readonly = any(
        len(fields) > 3 and fields[1] == "/" and "ro" in fields[3].split(",")
        for fields in (line.split() for line in Path("/proc/mounts").read_text().splitlines())
    )
    passed = (interfaces == ["lo"] and all(value == "0000000000000000" for value in capabilities.values())
              and status.get("NoNewPrivs", "").strip() == "1" and root_readonly
              and os.environ.get("OPENCYBER_OFFLINE") == "1"
              and os.environ.get("OPENCYBER_STRICT_CATALOG") == "1")
    return {"name": "container_isolation", "passed": passed, "interfaces": interfaces,
            "capabilities": capabilities, "no_new_privileges": status.get("NoNewPrivs", "").strip(),
            "root_readonly": root_readonly, "offline_mode": os.environ.get("OPENCYBER_OFFLINE")}


def catalog_check() -> dict[str, Any]:
    # Import the installed package in a child, never a bind-mounted source tree.
    program = """
import json
from opencyber import __version__
from opencyber.catalog import CATALOG
from opencyber.catalog_identity import alignment
from opencyber.server import mcp
expected = json.loads(__import__('sys').argv[1])
expected_version = __import__('sys').argv[2]
specs = {spec.name: spec for spec in CATALOG}
missing = [name for name, executable in expected.items() if name not in specs
           or not specs[name].required or specs[name].executable != executable]
unavailable = [name for name in expected if name in specs and not specs[name].availability()['available']]
live = alignment(mcp._tool_manager._tools)
report = {'version': __version__, 'missing_required_tools': missing,
          'unavailable_required_tools': unavailable, 'alignment': live}
print(json.dumps(report))
raise SystemExit(bool(missing or unavailable or not live['matches'] or __version__ != expected_version))
"""
    result = command_check("installed_mcp_catalog", [sys.executable, "-c", program, json.dumps(REQUIRED_TOOLS), EXPECTED_VERSION],
                           timeout=45)
    try:
        result["catalog"] = json.loads(result["stdout"])
    except (ValueError, TypeError):
        result["passed"] = False
    return result


@contextmanager
def wordpress_fixture() -> Iterator[tuple[int, list[str]]]:
    requests: list[str] = []

    class Fixture(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            if len(requests) >= 128:
                self.send_error(429)
                return
            requests.append(self.path[:256])
            path = urlsplit(self.path).path
            code, content_type = 200, "text/html; charset=utf-8"
            if path == "/":
                body = (f'<!doctype html><html><head><meta name="generator" content="WordPress {WORDPRESS_VERSION}" />'
                        '</head><body><a href="/wp-content/">Owned synthetic WordPress fixture</a>'
                        '<a href="/wp-login.php">Log in</a></body></html>')
            elif path == "/readme.html":
                body = f"<html><body>WordPress <h1>Version {WORDPRESS_VERSION}</h1></body></html>"
            elif path == "/wp-login.php":
                body = '<html><body><form id="loginform">WordPress</form></body></html>'
            elif path == "/wp-content/":
                body = "<html><body>Owned fixture</body></html>"
            elif path == "/wp-json/":
                content_type, body = "application/json", '{"name":"Owned synthetic fixture","namespaces":["wp/v2"]}'
            else:
                code, body = 404, "Fixture resource not found"
            payload = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def do_HEAD(self) -> None:
            self.send_response(200 if urlsplit(self.path).path == "/" else 404)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_args: Any) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_port, requests
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


def nmap_check(port: int) -> dict[str, Any]:
    result = command_check("nmap_loopback_tcp_connect", [
        "nmap", "--unprivileged", "-sT", "-Pn", "-n", "--max-retries", "0", "--host-timeout", "15s",
        "-p", str(port), "-oX", "-", "127.0.0.1",
    ], timeout=20)
    try:
        root = ET.fromstring(result["stdout"])
        states = [entry.find("state").get("state") for entry in root.findall("./host/ports/port")
                  if entry.get("portid") == str(port) and entry.find("state") is not None]
    except (ValueError, ET.ParseError):
        states = []
    result.update(passed=result["passed"] and states == ["open"], fixture_port=port, observed_states=states)
    return result


def wpscan_check(port: int, requests: list[str]) -> dict[str, Any]:
    result = command_check("wpscan_loopback_passive_detection", [
        "wpscan", "--url", f"http://127.0.0.1:{port}/", "--no-update", "--force",
        "--wp-content-dir", "wp-content", "--wp-plugins-dir", "wp-content/plugins",
        "--detection-mode", "passive", "--plugins-detection", "passive", "--plugins-version-detection", "passive",
        "--max-threads", "1", "--connect-timeout", "2", "--request-timeout", "3", "--no-banner", "--format", "json",
    ], timeout=60)
    try:
        payload = json.loads(result["stdout"])
        detected = (payload.get("version") or {}).get("number")
    except (ValueError, AttributeError, TypeError):
        detected = None
    result.update(passed=result["passed"] and detected == WORDPRESS_VERSION,
                  expected_version=WORDPRESS_VERSION, detected_version=detected,
                  fixture_requests=list(requests), vulnerability_intelligence_validated=False)
    return result


def main() -> int:
    checks = [isolation_check()]
    # Refuse to run scanners unless the disposable container boundary is present.
    if checks[0]["passed"]:
        checks.append(catalog_check())
        commands = [
            ("nmap", ["nmap", "--version"], ("nmap",)),
            ("ncat", ["ncat", "--version"], ("ncat",)),
            ("ndiff", ["ndiff", "-h"], ("ndiff",)),
            ("nping", ["nping", "--version"], ("nping",)),
            ("rustscan", ["rustscan", "--version"], ("rustscan",)),
            ("autorecon", ["autorecon", "--help"], ("autorecon",)),
            ("netexec", ["nxc", "--help"], ("netexec",)),
            ("wpscan", ["wpscan", "--version", "--no-update"], ("wordpress security scanner",)),
        ]
        for name, argv, markers in commands:
            checks.append(command_check(f"{name}_cli_startup", argv, timeout=45, markers=markers))
        with wordpress_fixture() as (port, requests):
            checks.append(nmap_check(port))
            checks.append(wpscan_check(port, requests))
    report = {
        "schema_version": 1, "suite": "opencyber.airgap-tools/v1",
        "passed": all(check["passed"] for check in checks), "checks": checks,
        "limitations": [
            "This local image test does not qualify another architecture or any hardware device.",
            "CLI startup checks do not validate every tool feature or third-party service integration.",
            "WPScan checks synthetic local WordPress detection without API credentials; vulnerability intelligence is unqualified.",
        ],
    }
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
