#!/usr/bin/env python3
"""Small MCP stdio client used to verify OpenCyber without an MCP SDK."""

from __future__ import annotations

import json
import base64
import os
import selectors
import subprocess
import sys
import time


def send(process: subprocess.Popen[str], payload: dict) -> None:
    assert process.stdin is not None
    process.stdin.write(json.dumps(payload) + "\n")
    process.stdin.flush()


def receive(process: subprocess.Popen[str], request_id: int, timeout: float = 30.0) -> dict:
    assert process.stdout is not None
    selector = selectors.DefaultSelector()
    selector.register(process.stdout, selectors.EVENT_READ)
    while selector.select(timeout):
        line = process.stdout.readline()
        if not line:
            break
        payload = json.loads(line)
        if payload.get("id") == request_id:
            return payload
    raise RuntimeError(f"no MCP response for request {request_id}")


def structured_result(response: dict) -> dict:
    result = response.get("result", {})
    structured = result.get("structuredContent")
    if isinstance(structured, dict):
        return structured
    for item in result.get("content", []):
        if item.get("type") == "text":
            try:
                payload = json.loads(item["text"])
            except (KeyError, json.JSONDecodeError):
                continue
            if isinstance(payload, dict):
                return payload
    raise RuntimeError(f"MCP response has no structured object: {response}")


def call_tool(process: subprocess.Popen[str], request_id: int, name: str, arguments: dict) -> dict:
    send(process, {"jsonrpc": "2.0", "id": request_id, "method": "tools/call",
                   "params": {"name": name, "arguments": arguments}})
    response = receive(process, request_id)
    if "error" in response or response.get("result", {}).get("isError"):
        raise RuntimeError(f"{name} failed: {response}")
    return structured_result(response)


def main() -> None:
    if len(sys.argv) < 2:
        raise SystemExit("usage: mcp_smoke.py COMMAND [ARG ...]")
    process = subprocess.Popen(
        sys.argv[1:],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    compact = os.environ.get("OPENCYBER_SMOKE_COMPACT") == "1"
    try:
        send(
            process,
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "opencyber-smoke", "version": "1"},
                },
            },
        )
        initialized = receive(process, 1)
        if "error" in initialized:
            raise RuntimeError(initialized["error"])
        send(process, {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}})
        send(process, {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
        listed = receive(process, 2)
        tools = listed["result"]["tools"]
        names = [tool["name"] for tool in tools]
        from opencyber.catalog import CATALOG
        from opencyber.diagnostics import FIXED_MCP_TOOL_COUNT

        expected_tool_count = FIXED_MCP_TOOL_COUNT if compact else FIXED_MCP_TOOL_COUNT + len(CATALOG)
        if len(names) != expected_tool_count:
            raise RuntimeError(f"expected {expected_tool_count} MCP tools; found {len(names)}")
        if len(names) != len(set(names)):
            raise RuntimeError("duplicate MCP tool names")
        if not all(name.startswith("oc_") for name in names):
            raise RuntimeError("non-OpenCyber tool name found")
        engagement_tools = {"oc_engagement_create", "oc_engagement_list", "oc_engagement_get"}
        if not engagement_tools.issubset(names):
            raise RuntimeError(f"missing engagement tools: {sorted(engagement_tools - set(names))}")
        executable_name = "oc_execute" if compact else "oc_nmap"
        executable_definition = next(tool for tool in tools if tool["name"] == executable_name)
        executable_schema = executable_definition["inputSchema"]
        expected_properties = {"tool", "engagement_id", "arguments", "working_directory", "stdin"} if compact else {"engagement_id", "arguments", "working_directory", "stdin"}
        if set(executable_schema.get("properties", {})) != expected_properties:
            raise RuntimeError(f"unexpected OpenCyber executable schema: {executable_schema}")
        expected_required = {"tool", "engagement_id", "arguments"} if compact else {"engagement_id", "arguments"}
        if set(executable_schema.get("required", [])) != expected_required:
            raise RuntimeError(f"unexpected required fields: {executable_schema}")
        send(
            process,
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {"name": "oc_catalog", "arguments": {"query": "grep"}},
            },
        )
        called = receive(process, 3)
        if "error" in called:
            raise RuntimeError(called["error"])
        catalog_payload = structured_result(called)
        if "oc_grep" not in {tool["name"] for tool in catalog_payload["tools"]}:
            raise RuntimeError("oc_grep is missing from the complete catalog")
        send(
            process,
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "oc_engagement_create",
                    "arguments": {
                        "name": "OpenCyber MCP smoke test",
                        "targets": ["127.0.0.1"],
                        "objective": "Validate engagement isolation",
                    },
                },
            },
        )
        engagement_called = receive(process, 4)
        if "error" in engagement_called or engagement_called["result"].get("isError", False):
            raise RuntimeError(engagement_called.get("error") or engagement_called["result"])
        engagement = structured_result(engagement_called)
        engagement_id = engagement["engagement_id"]
        send(
            process,
            {
                "jsonrpc": "2.0",
                "id": 5,
                "method": "tools/call",
                "params": {
                    "name": executable_name,
                    "arguments": (
                        {"tool": "oc_nmap", "engagement_id": engagement_id, "arguments": ["--version"]}
                        if compact
                        else {"engagement_id": engagement_id, "arguments": ["--version"]}
                    ),
                },
            },
        )
        nmap_called = receive(process, 5)
        if "error" in nmap_called or nmap_called["result"].get("isError", False):
            raise RuntimeError(nmap_called.get("error") or nmap_called["result"])
        nmap_result = structured_result(nmap_called)
        nmap_available = nmap_result.get("available", True)
        if nmap_available:
            if not nmap_result.get("success"):
                raise RuntimeError(f"installed Nmap version call failed: {nmap_result}")
        else:
            error = nmap_result.get("error") or {}
            if (nmap_result.get("optional") is not True or error.get("code") != "integration_unavailable"
                    or not error.get("remediation", {}).get("action")):
                raise RuntimeError(f"optional Nmap result is not actionable: {nmap_result}")
        send(
            process,
            {
                "jsonrpc": "2.0",
                "id": 6,
                "method": "tools/call",
                "params": {
                    "name": "oc_engagement_plan",
                    "arguments": {"kind": "recon", "target": "127.0.0.1"},
                },
            },
        )
        plan_called = receive(process, 6)
        if "error" in plan_called or plan_called["result"].get("isError", False):
            raise RuntimeError(plan_called.get("error") or plan_called["result"])
        send(
            process,
            {
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": {
                    "name": "oc_workspace_write",
                    "arguments": {"engagement_id": engagement_id, "path": "smoke/mcp.txt", "content": "first-engagement\n"},
                },
            },
        )
        write_called = receive(process, 7)
        if "error" in write_called or write_called["result"].get("isError", False):
            raise RuntimeError(write_called.get("error") or write_called["result"])
        send(
            process,
            {
                "jsonrpc": "2.0",
                "id": 8,
                "method": "tools/call",
                "params": {"name": "oc_workspace_read", "arguments": {"engagement_id": engagement_id, "path": "smoke/mcp.txt"}},
            },
        )
        read_called = receive(process, 8)
        if "error" in read_called or read_called["result"].get("isError", False):
            raise RuntimeError(read_called.get("error") or read_called["result"])
        if structured_result(read_called)["content"] != "first-engagement\n":
            raise RuntimeError("first engagement returned unexpected workspace content")
        send(
            process,
            {
                "jsonrpc": "2.0",
                "id": 9,
                "method": "tools/call",
                "params": {
                    "name": "oc_engagement_create",
                    "arguments": {"name": "Second smoke engagement", "targets": ["localhost"]},
                },
            },
        )
        second_called = receive(process, 9)
        if "error" in second_called or second_called["result"].get("isError", False):
            raise RuntimeError(second_called.get("error") or second_called["result"])
        second_id = structured_result(second_called)["engagement_id"]
        if second_id == engagement_id:
            raise RuntimeError("server generated duplicate engagement IDs")
        send(
            process,
            {
                "jsonrpc": "2.0",
                "id": 10,
                "method": "tools/call",
                "params": {
                    "name": "oc_workspace_write",
                    "arguments": {"engagement_id": second_id, "path": "smoke/mcp.txt", "content": "second-engagement\n"},
                },
            },
        )
        second_write = receive(process, 10)
        if "error" in second_write or second_write["result"].get("isError", False):
            raise RuntimeError(second_write.get("error") or second_write["result"])
        send(
            process,
            {
                "jsonrpc": "2.0",
                "id": 11,
                "method": "tools/call",
                "params": {"name": "oc_workspace_read", "arguments": {"engagement_id": engagement_id, "path": "smoke/mcp.txt"}},
            },
        )
        isolated_read = receive(process, 11)
        if structured_result(isolated_read)["content"] != "first-engagement\n":
            raise RuntimeError("engagement workspace isolation failed")
        send(
            process,
            {
                "jsonrpc": "2.0",
                "id": 12,
                "method": "tools/call",
                "params": {
                    "name": "oc_execute" if compact else "oc_grep",
                    "arguments": (
                        {
                            "tool": "oc_grep",
                            "engagement_id": engagement_id,
                            "arguments": ["-n", "first-engagement", "smoke/mcp.txt"],
                        }
                        if compact
                        else {
                            "engagement_id": engagement_id,
                            "arguments": ["-n", "first-engagement", "smoke/mcp.txt"],
                        }
                    ),
                },
            },
        )
        grep_called = receive(process, 12)
        if "first-engagement" not in structured_result(grep_called)["stdout"]:
            raise RuntimeError("oc_grep did not search the engagement workspace")
        from test_triage import synthetic_capture

        capture = base64.b64encode(synthetic_capture()).decode()
        prepared = call_tool(process, 20, "oc_python", {
            "engagement_id": engagement_id,
            "source": (
                "import pathlib,base64; "
                "pathlib.Path('artifacts/wire.txt').write_text('synthetic IOC 192.0.2.1\\n'); "
                "pathlib.Path('artifacts/wire.log').write_text('2026-10-25T12:00:00Z synthetic event\\n'); "
                f"pathlib.Path('artifacts/wire.pcap').write_bytes(base64.b64decode({capture!r}))"
            ),
        })
        if not prepared.get("success"):
            raise RuntimeError("could not prepare synthetic MCP evidence")
        reports = []
        selected = ["artifacts/wire.txt", "artifacts/wire.log", "artifacts/wire.pcap"]
        for request_id, tool, path in zip((21, 22, 23), ("oc_file_triage", "oc_log_timeline", "oc_pcap_triage"), selected):
            report = call_tool(process, request_id, tool, {"engagement_id": engagement_id, "path": path})
            if not report.get("complete") or not report.get("source", {}).get("hash_complete"):
                raise RuntimeError(f"incomplete synthetic MCP analysis: {report}")
            reports.append(report["report_path"])
        bundle = call_tool(process, 24, "oc_evidence_export", {"engagement_id": engagement_id, "paths": selected + reports})
        verified = call_tool(process, 25, "oc_evidence_verify", {
            "engagement_id": engagement_id, "path": bundle["path"], "expected_sha256": bundle["sha256"],
        })
        if not verified.get("valid"):
            raise RuntimeError(f"MCP evidence round trip failed: {verified}")
        send(process, {"jsonrpc": "2.0", "id": 26, "method": "tools/call", "params": {
            "name": "oc_file_triage", "arguments": {"engagement_id": engagement_id, "path": "../outside"},
        }})
        rejected = receive(process, 26)
        refused = structured_result(rejected)
        if refused.get("ok") is not False or refused.get("error", {}).get("code") != "invalid_argument":
            raise RuntimeError("MCP triage accepted traversal")
        cancellation_marker = "opencyber-cancellation-" + engagement_id
        send(
            process,
            {
                "jsonrpc": "2.0",
                "id": 13,
                "method": "tools/call",
                "params": {
                    "name": "oc_python",
                    "arguments": {
                        "engagement_id": engagement_id,
                        "source": "import time; time.sleep(60)",
                        "script_arguments": [cancellation_marker],
                    },
                },
            },
        )
        time.sleep(0.3)
        send(
            process,
            {
                "jsonrpc": "2.0",
                "id": 14,
                "method": "tools/call",
                "params": {"name": "oc_process_snapshot", "arguments": {"include_connections": False}},
            },
        )
        concurrent_called = receive(process, 14, timeout=5.0)
        if "error" in concurrent_called or concurrent_called["result"].get("isError", False):
            raise RuntimeError("long executable blocked a concurrent MCP call")
        active = structured_result(concurrent_called)["processes"]
        if not any(cancellation_marker in (item.get("cmdline") or []) for item in active):
            raise RuntimeError("cancellation smoke executable did not start")
        send(
            process,
            {
                "jsonrpc": "2.0",
                "method": "notifications/cancelled",
                "params": {"requestId": 13, "reason": "OpenCyber cancellation smoke test"},
            },
        )
        time.sleep(0.3)
        send(
            process,
            {
                "jsonrpc": "2.0",
                "id": 15,
                "method": "tools/call",
                "params": {
                    "name": "oc_process_snapshot",
                    "arguments": {"include_connections": False},
                },
            },
        )
        snapshot_called = receive(process, 15, timeout=5.0)
        processes = structured_result(snapshot_called)["processes"]
        if any(cancellation_marker in (item.get("cmdline") or []) for item in processes):
            raise RuntimeError("cancelled executable remained alive in the container")
        print(
            json.dumps(
                {
                    "server": initialized["result"]["serverInfo"],
                    "tool_count": len(names),
                    "first_tools": names[:5],
                    "executable_schema": executable_schema,
                    "compact_mode": compact,
                    "catalog_call_ok": not called["result"].get("isError", False),
                    "optional_nmap_available": nmap_available,
                    "optional_nmap_result_ok": True,
                    "engagement_plan_ok": True,
                    "workspace_roundtrip_ok": True,
                    "engagement_isolation_ok": True,
                    "grep_call_ok": True,
                    "concurrent_call_ok": True,
                    "cancellation_cleanup_ok": True,
                    "blue_team_wire_roundtrip_ok": True,
                    "engagement_id": engagement_id,
                    "second_engagement_id": second_id,
                },
                indent=2,
            )
        )
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()


if __name__ == "__main__":
    main()
