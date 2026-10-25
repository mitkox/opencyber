#!/usr/bin/env python3
"""Run real synthetic PCAP and evidence checks in a network-isolated image."""
from __future__ import annotations

import base64
import json
import subprocess
import sys

from test_triage import synthetic_capture, synthetic_capture_ng


def main() -> None:
    if len(sys.argv) != 2:
        raise SystemExit("usage: blue_team_smoke.py IMAGE")
    fixtures = {name: base64.b64encode(data).decode() for name, data in (
        ("capture.pcap", synthetic_capture()), ("capture.pcapng", synthetic_capture_ng()),
    )}
    source = '''
import base64,json,hashlib,pathlib,socket
from opencyber.engagements import create_engagement
from opencyber.triage import file_triage,log_timeline,pcap_triage
from opencyber.evidence import export_evidence,verify_evidence
fixtures=FIXTURES
case=create_engagement("Synthetic offline blue-team acceptance",["192.0.2.0/24"])
eid=case["engagement_id"]; root=pathlib.Path(case["workspace"])
socket.getaddrinfo=lambda *a,**k: (_ for _ in ()).throw(AssertionError("DNS forbidden"))
paths=[]
for name,data in fixtures.items():
    relative="artifacts/"+name; payload=base64.b64decode(data)
    (root/relative).write_bytes(payload)
    result=pcap_triage(eid,relative)
    report=json.loads((root/result["report_path"]).read_text())
    assert result["complete"],report
    assert report["packets_processed"]==1,report
    assert report["packets"][0]["source"]=="192.0.2.1",report
    assert report["packets"][0]["destination"]=="192.0.2.2",report
    assert (root/relative).read_bytes()==payload
    paths.extend([relative,result["report_path"]])
relative="artifacts/events.jsonl"
(root/relative).write_text('{"timestamp":"2026-10-25T12:00:00Z","message":"synthetic source 192.0.2.1"}\\n')
timeline=log_timeline(eid,relative); triage=file_triage(eid,relative)
assert timeline["complete"] and triage["complete"]
paths.extend([relative,timeline["report_path"],triage["report_path"]])
bundle=export_evidence(eid,paths)
assert verify_evidence(eid,bundle["path"],bundle["sha256"])["valid"]
assert hashlib.sha256((root/bundle["path"]).read_bytes()).hexdigest()==bundle["sha256"]
print(json.dumps({"status":"passed","captures":len(fixtures),"files":bundle["files"],"archive_sha256":bundle["sha256"]}))
'''.replace("FIXTURES", repr(fixtures))
    completed = subprocess.run([
        "docker", "run", "--rm", "-i", "--network", "none", "--cap-drop=ALL",
        "--security-opt", "no-new-privileges", "--read-only", "--tmpfs", "/workspace",
        "--tmpfs", "/tmp", "--entrypoint", "python3", sys.argv[1], "-",
    ], input=source, capture_output=True, text=True, check=True)
    report = json.loads(completed.stdout)
    assert report["status"] == "passed", report
    print(json.dumps(report, sort_keys=True))


if __name__ == "__main__":
    main()
