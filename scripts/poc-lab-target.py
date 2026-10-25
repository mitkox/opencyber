#!/usr/bin/env python3
"""Deterministic synthetic target for the CVE-chain PoC lab.

This server exists so the PoC workflow can be exercised end to end without a
real target: it serves a fixed "vulnerable" version banner and returns a fixed
canary for traversal-shaped download paths. It implements no vulnerability; the
CVE ids used by the lab are annotations over fixture behaviour, not claims about
this process.

Endpoints:

``GET /health``
    ``{"status": "ok"}``
``GET /version``
    ``FixtureApp 1.4.2`` as text, for ``version_assert``.
``GET /download?file=...``
    Returns ``OPENCYBER-CANARY-<16 hex>`` when the file parameter contains
    ``..`` and ``opencyber-canary``; 404 otherwise. For ``file_read_canary``.

Run with ``--host``/``--port`` and optionally ``--log`` to append one JSON line
per request.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


CANARY = "OPENCYBER-CANARY-" + hashlib.sha256(b"opencyber-poc-lab").hexdigest()[:16]
VERSION_BANNER = "FixtureApp 1.4.2"
LOG_PATH: Path | None = None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _log(entry: dict[str, object]) -> None:
    line = json.dumps({"ts": _now(), **entry}, sort_keys=True)
    print(line, flush=True)
    if LOG_PATH is not None:
        with LOG_PATH.open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")


class LabHandler(BaseHTTPRequestHandler):
    server_version = "OpenCyberPoCLab/1.0"
    sys_version = ""

    def log_message(self, format: str, *args: object) -> None:  # noqa: A002 - stdlib signature
        # The deterministic JSON log below is the only output.
        return

    def _send(self, status: int, body: str, content_type: str = "text/plain; charset=utf-8") -> None:
        encoded = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:  # noqa: N802 - stdlib handler API
        parsed = urlparse(self.path)
        path = parsed.path
        query = parse_qs(parsed.query)
        _log({"method": "GET", "path": path, "query": parsed.query, "client": self.client_address[0]})
        if path == "/health":
            self._send(200, json.dumps({"status": "ok"}))
            return
        if path == "/version":
            self._send(200, VERSION_BANNER)
            return
        if path == "/download":
            requested = (query.get("file") or [""])[0]
            if ".." in requested and "opencyber-canary" in requested:
                self._send(200, CANARY)
                return
            self._send(404, "not found")
            return
        self._send(404, "not found")


def main() -> int:
    global LOG_PATH
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8099)
    parser.add_argument("--log", type=Path, default=None)
    args = parser.parse_args()
    if args.log is not None:
        args.log.parent.mkdir(parents=True, exist_ok=True)
        LOG_PATH = args.log
    server = ThreadingHTTPServer((args.host, args.port), LabHandler)
    print(f"poc lab target listening on http://{args.host}:{args.port} canary={CANARY}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
