#!/usr/bin/env python3
"""Run the OpenCyber CVE-chain PoC lab end to end against a synthetic fixture.

This is a *lab operator* script, not an agent: it drives the real MCP server over
stdio and stands in for the human operator by invoking the signing CLI
(``opencyber.poc_approval``) inside the disposable lab container. The server
still enforces every gate; the script asserts the expected refusals as part of
the run.

It expects the lab container from ``docs/POC_LAB.md``:

* container ``opencyber-poc-lab`` running the built ``opencyber:0.5.0`` image,
  or a container with the working tree's ``src/opencyber`` copied to
  ``/opt/opencyber-050`` (``--mode source``),
* ``scripts/poc-lab-target.py`` running on ``127.0.0.1:8099`` in that container,
* an approval key at ``/run/secrets/opencyber-poc.key`` (lab-only, disposable).

``--mode image`` (default) calls the installed ``opencyber-mcp`` and
``opencyber-poc`` console scripts; ``--mode source`` runs ``python3 -m
opencyber.server`` with ``PYTHONPATH`` so a checkout can be tested in an image
that only has the dependencies.

The script writes ``docs/verification/poc-lab-<date>.json`` and exits non-zero if
any expected outcome did not hold.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import shlex
import subprocess
import sys
from typing import Any


ROOT = Path(__file__).resolve().parents[1]
TARGET_PORT = 8099
TARGET = f"http://127.0.0.1:{TARGET_PORT}"

DEFAULT_SETTINGS: dict[str, str] = {
    "mode": "image",
    "container": "opencyber-poc-lab",
    "workspace": "/workspace",
    "key_file": "/run/secrets/opencyber-poc.key",
    "source_path": "/opt/opencyber-050",
}
SETTINGS: dict[str, str] = dict(DEFAULT_SETTINGS)

CVE_EXPOSURE = "CVE-2021-41773"
CVE_READ = "CVE-2021-42013"
CANARY_PATTERN = r"OPENCYBER-CANARY-[0-9a-f]{16}"
VERSION_PATTERN = r"FixtureApp 1\.4\.2"


def _utc(delta: timedelta) -> str:
    return (datetime.now(timezone.utc) + delta).strftime("%Y-%m-%dT%H:%M:%SZ")


def _container_env() -> list[str]:
    """Return the ``docker exec`` prefix carrying the lab environment."""
    command = [
        "docker",
        "exec",
        "-i",
        "-e",
        f"OPENCYBER_WORKSPACE={SETTINGS['workspace']}",
        "-e",
        f"OPENCYBER_APPROVAL_KEY_FILE={SETTINGS['key_file']}",
    ]
    if SETTINGS["mode"] == "source":
        command += ["-e", f"PYTHONPATH={SETTINGS['source_path']}"]
    command.append(SETTINGS["container"])
    return command


def _server_command() -> list[str]:
    if SETTINGS["mode"] == "image":
        return ["opencyber-mcp"]
    return ["python3", "-m", "opencyber.server"]


def _cli_command() -> list[str]:
    if SETTINGS["mode"] == "image":
        return ["opencyber-poc"]
    return ["python3", "-m", "opencyber.poc_approval"]


def _python_snippet(script: str) -> str:
    """Shell fragment that runs a helper script with the package importable."""
    if SETTINGS["mode"] == "image":
        return f"/opt/opencyber-venv/bin/python -c {shlex.quote(script)}"
    return f"PYTHONPATH={SETTINGS['source_path']} python3 -c {shlex.quote(script)}"


def _cli(*arguments: str) -> dict[str, Any]:
    """Run the operator signing CLI inside the lab container."""
    command = [*_container_env(), *_cli_command(), *arguments]
    completed = subprocess.run(command, text=True, capture_output=True, check=False)
    if completed.returncode != 0:
        raise RuntimeError(
            f"opencyber-poc {' '.join(arguments)} failed ({completed.returncode}): "
            f"{completed.stderr.strip() or completed.stdout.strip()}"
        )
    return json.loads(completed.stdout)


def _exec_shell(script: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", "exec", SETTINGS["container"], "sh", "-c", script],
        text=True,
        capture_output=True,
        check=False,
    )


class MCPClient:
    """Minimal JSON-RPC stdio client for the lab MCP server."""

    def __init__(self) -> None:
        command = [*_container_env(), *_server_command()]
        self.process = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        self._counter = 0
        self._rpc(
            "initialize",
            {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "opencyber-poc-lab", "version": "1"},
            },
        )

    def _rpc(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        """Send one request and block for its matching response.

        A blocking readline is deliberate: the lab server answers every request
        exactly once, and a selector adds a failure mode without adding value.
        """
        assert self.process.stdin is not None and self.process.stdout is not None
        self._counter += 1
        request_id = self._counter
        self.process.stdin.write(
            json.dumps({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params}) + "\n"
        )
        self.process.stdin.flush()
        while True:
            line = self.process.stdout.readline()
            if not line:
                stderr = ""
                if self.process.stderr is not None:
                    stderr = self.process.stderr.read()
                raise RuntimeError(
                    f"{method}: server closed stdout (returncode={self.process.poll()}): {stderr[-2000:]}"
                )
            message = json.loads(line)
            if message.get("id") != request_id:
                continue
            if "error" in message:
                raise RuntimeError(f"{method} failed: {message['error']}")
            return message["result"]

    def call(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        result = self._rpc("tools/call", {"name": name, "arguments": arguments})
        return result.get("structuredContent") or result

    def close(self) -> None:
        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()


class Evidence:
    """Collects pass/fail checks and the identifiers the run produced."""

    def __init__(self) -> None:
        self.checks: list[dict[str, Any]] = []
        self.facts: dict[str, Any] = {}

    def check(self, name: str, condition: bool, *, expected: Any = None, actual: Any = None) -> None:
        record = {"name": name, "ok": bool(condition)}
        if expected is not None:
            record["expected"] = expected
        if actual is not None:
            record["actual"] = actual
        self.checks.append(record)
        status = "PASS" if condition else "FAIL"
        detail = ""
        if not condition:
            detail = f" (expected {expected!r}, got {actual!r})"
        print(f"[{status}] {name}{detail}", flush=True)

    def failed(self) -> list[str]:
        return [check["name"] for check in self.checks if not check["ok"]]


def _refusal_reason(result: dict[str, Any]) -> str:
    return str(result.get("reason") or (result.get("error") or {}).get("code") or "")


def _assert_refused(evidence: Evidence, name: str, result: dict[str, Any], reason: str) -> None:
    actual = _refusal_reason(result)
    evidence.check(
        name,
        result.get("status") == "refused" and actual == reason,
        expected={"status": "refused", "reason": reason},
        actual={"status": result.get("status"), "reason": actual, "message": result.get("message")},
    )


def run(evidence: Evidence) -> dict[str, Any]:
    client = MCPClient()
    try:
        server = client.call("oc_catalog", {})
        evidence.facts["server"] = {
            "version": server.get("version"),
            "advertised_tool_count": server.get("advertised_mcp_tool_count"),
            "catalog_matches_release": server.get("catalog_matches_release"),
            "catalog_digest": server.get("catalog_digest"),
        }
        evidence.check(
            "server is the working tree at 0.5.x",
            str(server.get("version", "")).startswith("0.5."),
            expected="0.5.x",
            actual=server.get("version"),
        )
        evidence.check(
            "advertised catalog matches the recorded contract",
            bool(server.get("catalog_matches_release")),
            expected=True,
            actual=server.get("catalog_matches_release"),
        )

        # --- positive setup -------------------------------------------------
        engagement = client.call(
            "oc_engagement_create",
            {"name": "poc-lab", "targets": ["127.0.0.1"], "objective": "synthetic PoC lab"},
        )
        engagement_id = engagement["engagement_id"]
        evidence.facts["engagement_id"] = engagement_id

        artifact_lines = [
            json.dumps(
                {
                    "template-id": CVE_EXPOSURE,
                    "info": {"classification": {"cve-id": [CVE_EXPOSURE]}},
                    "matched-at": f"{TARGET}/version",
                },
                separators=(",", ":"),
            ),
            json.dumps(
                {
                    "template-id": CVE_READ,
                    "info": {"classification": {"cve-id": [CVE_READ]}},
                    "matched-at": f"{TARGET}/download",
                },
                separators=(",", ":"),
            ),
        ]
        write = client.call(
            "oc_workspace_write",
            {
                "engagement_id": engagement_id,
                "path": "artifacts/nuclei.jsonl",
                "content": "\n".join(artifact_lines) + "\n",
            },
        )
        evidence.check("artifact written", bool(write.get("ok")), expected=True, actual=write.get("ok"))

        steps = [
            {
                "cve_id": CVE_EXPOSURE,
                "asset": "127.0.0.1",
                "requires": ["position:local", f"net:http:{TARGET_PORT}", "auth:none"],
                "provides": ["info:version"],
                "basis": "fixture: /version exposes the vulnerable build string",
                "source": "nuclei",
            },
            {
                "cve_id": CVE_READ,
                "asset": "127.0.0.1",
                "requires": ["info:version", f"net:http:{TARGET_PORT}"],
                "provides": ["file:read:/etc/opencyber-canary"],
                "basis": "fixture: /download consults a traversal-shaped file parameter",
                "source": "nuclei",
            },
        ]
        chain = client.call(
            "oc_chain_plan",
            {
                "engagement_id": engagement_id,
                "steps": steps,
                "entry_capabilities": ["position:local", f"net:http:{TARGET_PORT}", "auth:none"],
                "artifacts": ["artifacts/nuclei.jsonl"],
                "chain_name": "poc-lab",
            },
        )
        chain_id = chain["chain_id"]
        evidence.facts["chain"] = {
            "chain_id": chain_id,
            "verdict": chain.get("verdict"),
            "execution_order": chain.get("execution_order"),
            "warnings": chain.get("warnings"),
            "steps": [
                {"cve_id": step.get("cve_id"), "observed": step.get("observed"), "warnings": step.get("warnings")}
                for step in chain.get("steps", [])
            ],
        }
        evidence.check("chain closes", chain.get("verdict") == "complete", expected="complete", actual=chain.get("verdict"))
        evidence.check(
            "artifact marks both steps observed",
            all(step.get("observed") for step in chain.get("steps", [])),
            expected=True,
            actual=[step.get("observed") for step in chain.get("steps", [])],
        )
        evidence.check(
            "unverified CVE warning is expected without a local NVD index",
            "unverified_cve" in (chain.get("warnings") or []),
            expected="unverified_cve",
            actual=chain.get("warnings"),
        )

        exposure_spec = client.call(
            "oc_poc_spec_create",
            {
                "engagement_id": engagement_id,
                "chain_id": chain_id,
                "step_order": 1,
                "technique": "version_assert",
                "target": TARGET,
                "requests": [{"method": "GET", "path": "/version", "headers": {}}],
                "assertions": [
                    {"type": "status_in", "statuses": [200]},
                    {"type": "body_regex", "pattern": VERSION_PATTERN},
                ],
                "limits": {"max_requests": 2, "timeout_s": 10, "max_bytes": 65536},
                "notes": "poc-lab fixture run against the synthetic target",
            },
        )
        read_spec = client.call(
            "oc_poc_spec_create",
            {
                "engagement_id": engagement_id,
                "chain_id": chain_id,
                "step_order": 2,
                "technique": "file_read_canary",
                "target": TARGET,
                "requests": [{"method": "GET", "path": "/download?file=../../../../etc/opencyber-canary", "headers": {}}],
                "assertions": [
                    {"type": "status_in", "statuses": [200]},
                    {"type": "body_regex", "pattern": CANARY_PATTERN},
                ],
                "limits": {"max_requests": 2, "timeout_s": 10, "max_bytes": 65536},
                "notes": "poc-lab fixture run against the synthetic target",
            },
        )
        exposure_id = exposure_spec["spec_id"]
        read_id = read_spec["spec_id"]
        evidence.facts["specs"] = {
            "exposure": {"spec_id": exposure_id, "spec_sha256": exposure_spec.get("spec_sha256")},
            "read": {"spec_id": read_id, "spec_sha256": read_spec.get("spec_sha256")},
        }
        for label, spec_id in (("exposure", exposure_id), ("read", read_id)):
            rendered = client.call("oc_poc_render", {"engagement_id": engagement_id, "spec_id": spec_id})
            linted = client.call("oc_poc_lint", {"engagement_id": engagement_id, "spec_id": spec_id})
            evidence.facts["specs"][label].update(
                {
                    "code_sha256": rendered.get("code_sha256"),
                    "code_path_relative": rendered.get("code_path_relative"),
                    "lint_passed": linted.get("passed"),
                    "blocking": linted.get("blocking"),
                    "hosts": linted.get("hosts"),
                }
            )
            evidence.check(f"{label} spec renders", bool(rendered.get("code_sha256")), expected=True, actual=bool(rendered.get("code_sha256")))
            evidence.check(f"{label} spec lints clean", bool(linted.get("passed")), expected=True, actual=linted.get("blocking"))

        # --- authorization: exposure technique only ------------------------
        authorization = _cli(
            "authorize",
            "--engagement",
            engagement_id,
            "--authorized-by",
            "PoC lab operator <lab@example.test>",
            "--reference",
            "POC-LAB-001",
            "--scope",
            "127.0.0.1",
            "--valid-until",
            _utc(timedelta(days=7)),
            "--techniques",
            "version_assert",
            "--acknowledgement",
            "Synthetic loopback fixture for an OpenCyber lab test only",
        )
        auth_get = client.call("oc_authorization_get", {"engagement_id": engagement_id})
        evidence.facts["authorization"] = {
            "reference": authorization.get("reference"),
            "status": auth_get.get("status"),
            "scope_targets": auth_get.get("scope_targets"),
            "allowed_techniques": auth_get.get("allowed_techniques"),
            "valid_until": auth_get.get("valid_until"),
            "key_id": authorization.get("key_id"),
        }
        evidence.check(
            "operator authorization is valid and scoped to the fixture",
            auth_get.get("status") == "valid" and "127.0.0.1" in (auth_get.get("scope_targets") or []),
            expected={"status": "valid", "scope_targets": ["127.0.0.1"]},
            actual={"status": auth_get.get("status"), "scope_targets": auth_get.get("scope_targets")},
        )

        # --- gate: no approval yet -----------------------------------------
        unapproved = client.call(
            "oc_poc_run",
            {
                "engagement_id": engagement_id,
                "chain_id": chain_id,
                "spec_id": exposure_id,
                "approval_id": "apr_20260101_" + "0" * 32,
            },
        )
        _assert_refused(evidence, "unapproved run is refused", unapproved, "approval_invalid")

        # --- exposure run ---------------------------------------------------
        exposure_approval = _cli(
            "approve",
            "--engagement",
            engagement_id,
            "--chain",
            chain_id,
            "--spec",
            exposure_id,
            "--issued-by",
            "PoC lab operator <lab@example.test>",
            "--expires",
            _utc(timedelta(minutes=30)),
        )
        evidence.facts.setdefault("approvals", {})["exposure"] = {
            "approval_id": exposure_approval.get("approval_id"),
            "expires": exposure_approval.get("expires"),
        }
        exposure_run = client.call(
            "oc_poc_run",
            {
                "engagement_id": engagement_id,
                "chain_id": chain_id,
                "spec_id": exposure_id,
                "approval_id": exposure_approval["approval_id"],
            },
        )
        evidence.facts.setdefault("runs", {})["exposure"] = {
            key: exposure_run.get(key)
            for key in ("status", "reason", "run_id", "evidence_path", "output_sha256", "request_count", "approval_consumed", "assertions")
        }
        evidence.check("exposure run is verified", exposure_run.get("status") == "verified", expected="verified", actual=exposure_run.get("status"))
        evidence.check(
            "exposure assertions all passed server-side",
            bool(exposure_run.get("assertions")) and all(item.get("passed") for item in exposure_run["assertions"]),
            expected="all passed",
            actual=[(item.get("type"), item.get("passed")) for item in exposure_run.get("assertions") or []],
        )
        evidence.check(
            "exposure approval was consumed",
            exposure_run.get("approval_consumed") is True,
            expected=True,
            actual=exposure_run.get("approval_consumed"),
        )

        replay = client.call(
            "oc_poc_run",
            {
                "engagement_id": engagement_id,
                "chain_id": chain_id,
                "spec_id": exposure_id,
                "approval_id": exposure_approval["approval_id"],
            },
        )
        _assert_refused(evidence, "replaying a consumed approval is refused", replay, "approval_consumed")

        # --- gate: technique not authorized ---------------------------------
        read_approval = _cli(
            "approve",
            "--engagement",
            engagement_id,
            "--chain",
            chain_id,
            "--spec",
            read_id,
            "--issued-by",
            "PoC lab operator <lab@example.test>",
            "--expires",
            _utc(timedelta(minutes=30)),
        )
        evidence.facts.setdefault("approvals", {})["read"] = {"approval_id": read_approval.get("approval_id")}
        unauthorized = client.call(
            "oc_poc_run",
            {
                "engagement_id": engagement_id,
                "chain_id": chain_id,
                "spec_id": read_id,
                "approval_id": read_approval["approval_id"],
            },
        )
        _assert_refused(
            evidence,
            "technique outside the signed authorization is refused",
            unauthorized,
            "technique_not_authorized",
        )

        # --- re-authorize with both techniques, then the read run -----------
        authorization = _cli(
            "authorize",
            "--engagement",
            engagement_id,
            "--authorized-by",
            "PoC lab operator <lab@example.test>",
            "--reference",
            "POC-LAB-001-r2",
            "--scope",
            "127.0.0.1",
            "--valid-until",
            _utc(timedelta(days=7)),
            "--techniques",
            "version_assert,file_read_canary",
            "--acknowledgement",
            "Synthetic loopback fixture for an OpenCyber lab test only",
        )
        evidence.facts["authorization"]["superseded_reference"] = authorization.get("reference")
        read_approval = _cli(
            "approve",
            "--engagement",
            engagement_id,
            "--chain",
            chain_id,
            "--spec",
            read_id,
            "--issued-by",
            "PoC lab operator <lab@example.test>",
            "--expires",
            _utc(timedelta(minutes=30)),
        )
        evidence.facts["approvals"]["read"] = {"approval_id": read_approval.get("approval_id")}
        read_run = client.call(
            "oc_poc_run",
            {
                "engagement_id": engagement_id,
                "chain_id": chain_id,
                "spec_id": read_id,
                "approval_id": read_approval["approval_id"],
            },
        )
        evidence.facts["runs"]["read"] = {
            key: read_run.get(key)
            for key in ("status", "reason", "run_id", "evidence_path", "output_sha256", "request_count", "approval_consumed", "assertions")
        }
        evidence.check("canary run is verified", read_run.get("status") == "verified", expected="verified", actual=read_run.get("status"))
        evidence.check(
            "canary assertion observed the canary marker",
            any(item.get("type") == "body_regex" and item.get("passed") for item in read_run.get("assertions") or []),
            expected="body_regex passed",
            actual=[(item.get("type"), item.get("passed")) for item in read_run.get("assertions") or []],
        )

        # --- evidence readback ----------------------------------------------
        listed = client.call("oc_poc_evidence", {"engagement_id": engagement_id})
        run_ids = [run.get("run_id") for run in listed.get("runs", [])]
        evidence.check(
            "evidence lists both runs",
            {exposure_run.get("run_id"), read_run.get("run_id")}.issubset(set(run_ids)),
            expected="both run ids",
            actual=run_ids,
        )
        stored = client.call("oc_poc_evidence", {"engagement_id": engagement_id, "run_id": exposure_run["run_id"]})
        evidence.check(
            "evidence readback matches the run result",
            stored.get("status") == "verified" and stored.get("run_id") == exposure_run.get("run_id"),
            expected="verified",
            actual={"status": stored.get("status"), "run_id": stored.get("run_id")},
        )
        evidence_path = str(exposure_run.get("evidence_path") or "")
        exists = _exec_shell(
            f"test -f /workspace/engagements/{engagement_id}/{evidence_path} && echo present || echo missing"
        )
        evidence.check(
            "evidence file exists in the workspace",
            exists.stdout.strip() == "present",
            expected="present",
            actual=exists.stdout.strip(),
        )

        # --- gate: rendered code changed after approval ---------------------
        tamper_approval = _cli(
            "approve",
            "--engagement",
            engagement_id,
            "--chain",
            chain_id,
            "--spec",
            exposure_id,
            "--issued-by",
            "PoC lab operator <lab@example.test>",
            "--expires",
            _utc(timedelta(minutes=30)),
        )
        tamper_script = (
            "import json;"
            "from opencyber.poc import _spec_digest;"
            f"path='/workspace/engagements/{engagement_id}/poc/specs/{exposure_id}.json';"
            "record=json.load(open(path,encoding='utf-8'));"
            "record['requests'][0]['path']='/health';"
            "record['spec_sha256']=_spec_digest(record);"
            "open(path,'w',encoding='utf-8').write(json.dumps(record,indent=2,sort_keys=True)+chr(10))"
        )
        tampered = _exec_shell(_python_snippet(tamper_script))
        evidence.check(
            "spec re-hashed after approval (consistent but no longer approved)",
            tampered.returncode == 0,
            expected=0,
            actual={"returncode": tampered.returncode, "stderr": tampered.stderr[-300:]},
        )
        hash_mismatch = client.call(
            "oc_poc_run",
            {
                "engagement_id": engagement_id,
                "chain_id": chain_id,
                "spec_id": exposure_id,
                "approval_id": tamper_approval["approval_id"],
            },
        )
        _assert_refused(
            evidence,
            "code changed after approval is refused",
            hash_mismatch,
            "artifact_hash_mismatch",
        )

        # --- gate: out-of-scope target ---------------------------------------
        other = client.call(
            "oc_engagement_create",
            {"name": "poc-lab-out-of-scope", "targets": ["example.test"], "objective": "scope refusal"},
        )
        other_id = other["engagement_id"]
        other_chain = client.call(
            "oc_chain_plan",
            {
                "engagement_id": other_id,
                "steps": [
                    {
                        "cve_id": CVE_EXPOSURE,
                        "asset": "example.test",
                        "requires": ["position:local"],
                        "provides": ["info:version"],
                        "basis": "fixture: scope refusal path",
                        "source": "nuclei",
                    }
                ],
                "entry_capabilities": ["position:local"],
                "chain_name": "out-of-scope",
            },
        )
        other_spec = client.call(
            "oc_poc_spec_create",
            {
                "engagement_id": other_id,
                "chain_id": other_chain["chain_id"],
                "step_order": 1,
                "technique": "version_assert",
                "target": TARGET,
                "requests": [{"method": "GET", "path": "/version", "headers": {}}],
                "assertions": [{"type": "status_in", "statuses": [200]}],
            },
        )
        evidence.facts["out_of_scope"] = {
            "engagement_id": other_id,
            "reason": _refusal_reason(other_spec),
            "message": other_spec.get("message"),
        }
        evidence.check(
            "target outside the engagement scope is refused at spec creation",
            other_spec.get("ok") is False and _refusal_reason(other_spec) == "scope_violation",
            expected="scope_violation",
            actual=_refusal_reason(other_spec),
        )

        status = _cli("status", "--engagement", engagement_id)
        chains_listing = status.get("chains") or {}
        runs_listing = status.get("runs") or {}
        chain_summaries = chains_listing.get("items") or [] if isinstance(chains_listing, dict) else chains_listing
        run_summaries = runs_listing.get("items") or [] if isinstance(runs_listing, dict) else runs_listing
        evidence.facts["status"] = {
            "authorization": (status.get("authorization") or {}).get("status"),
            "chain_verdicts": [chain.get("verdict") for chain in chain_summaries],
            "run_count": len(run_summaries),
        }
        evidence.check(
            "operator status sees the superseding authorization",
            (status.get("authorization") or {}).get("status") == "valid",
            expected="valid",
            actual=(status.get("authorization") or {}).get("status"),
        )
        return evidence.facts
    finally:
        client.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--mode",
        choices=("image", "source"),
        default=DEFAULT_SETTINGS["mode"],
        help="image: installed console scripts; source: PYTHONPATH checkout copy",
    )
    parser.add_argument("--container", default=DEFAULT_SETTINGS["container"])
    parser.add_argument("--workspace", default=DEFAULT_SETTINGS["workspace"])
    parser.add_argument("--key-file", default=DEFAULT_SETTINGS["key_file"])
    parser.add_argument("--source-path", default=DEFAULT_SETTINGS["source_path"])
    parser.add_argument("--json-out", type=Path, default=None, help="write the evidence record here")
    args = parser.parse_args()
    SETTINGS.update(
        {
            "mode": args.mode,
            "container": args.container,
            "workspace": args.workspace,
            "key_file": args.key_file,
            "source_path": args.source_path,
        }
    )
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    output = args.json_out or ROOT / "docs" / "verification" / f"poc-lab-{stamp}.json"

    evidence = Evidence()
    try:
        facts = run(evidence)
    except Exception as error:  # noqa: BLE001 - a lab harness reports the whole failure
        print(f"[FAIL] lab run aborted: {type(error).__name__}: {error}", flush=True)
        evidence.check("lab run completed", False, expected=True, actual=f"{type(error).__name__}: {error}")
        facts = evidence.facts

    record = {
        "recorded_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "mode": SETTINGS["mode"],
        "container": SETTINGS["container"],
        "target": TARGET,
        "server_command": _server_command(),
        "source_path": SETTINGS["source_path"] if SETTINGS["mode"] == "source" else None,
        "facts": facts,
        "checks": evidence.checks,
        "failed_checks": evidence.failed(),
        "passed": not evidence.failed(),
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(f"\n{len(evidence.checks) - len(evidence.failed())}/{len(evidence.checks)} checks passed", flush=True)
    print(f"evidence: {output.relative_to(ROOT) if output.is_relative_to(ROOT) else output}", flush=True)
    if evidence.failed():
        print("failed: " + ", ".join(evidence.failed()), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
