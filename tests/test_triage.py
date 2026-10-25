"""Synthetic, offline regression coverage for artifact triage."""

from concurrent.futures import CancelledError
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import asyncio

import opencyber.engagements as engagements
from opencyber import triage
from opencyber.errors import OcError
from opencyber.native_tools import extract_indicators


class TriageTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.workspace = Path(self.temporary.name)
        self.workspace_patch = patch.object(engagements, "WORKSPACE", self.workspace)
        self.workspace_patch.start()
        self.addCleanup(self.workspace_patch.stop)
        self.engagement = engagements.create_engagement("Synthetic triage", ["192.0.2.0/24"])
        self.engagement_id = self.engagement["engagement_id"]
        self.root = Path(self.engagement["workspace"])

    def source(self, name, content):
        path = self.root / "artifacts" / name
        path.write_bytes(content)
        return str(path.relative_to(self.root))

    def report(self, result):
        return json.loads((self.root / result["report_path"]).read_text())

    def test_complete_hash_is_separate_from_bounded_analysis(self):
        data = b"first 192.0.2.1\n" + b"hidden.example.test\n" * 20
        relative = self.source("evidence.bin", data)
        result = triage.file_triage(self.engagement_id, relative, max_bytes=16)
        report = self.report(result)
        self.assertEqual(report["schema_version"], 1)
        self.assertEqual(report["source"]["sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(report["source"]["size"], len(data))
        self.assertTrue(report["source"]["hash_complete"])
        self.assertFalse(result["complete"])
        self.assertEqual(report["analysis_bytes"], 16)
        self.assertIn("content_limit", report["incomplete_reasons"])
        self.assertNotIn("hidden.example.test", report["indicators"]["domains"])
        self.assertEqual((self.root / relative).read_bytes(), data)

    def test_hash_streams_past_multiple_read_chunks(self):
        data = b"first line\n" + b"\x00" * (2 * 1024 * 1024) + b"last line\n"
        result = triage.file_triage(self.engagement_id, self.source("large.bin", data), max_bytes=32)
        self.assertEqual(result["source"]["sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(self.report(result)["analysis_bytes"], 32)

    def test_strings_have_byte_locations_and_indicators_are_validated(self):
        data = b"\x00seen 192.0.2.4 999.1.2.3 2001:db8::1 evidence.example.test\xff\n"
        result = triage.file_triage(self.engagement_id, self.source("sample.dat", data))
        report = self.report(result)
        self.assertEqual(report["indicators"]["ipv4"], ["192.0.2.4"])
        self.assertEqual(report["indicators"]["ipv6"], ["2001:db8::1"])
        self.assertIn("evidence.example.test", report["indicators"]["domains"])
        self.assertEqual(report["strings"][0]["byte_offset"], 1)
        self.assertTrue(result["complete"])
        old = extract_indicators("999.1.2.3 192.0.2.4 2001:db8::1 evidence.example.test")
        self.assertEqual(set(old), {"urls", "ipv4", "cves", "md5", "sha1", "sha256"})
        self.assertEqual(old["ipv4"], ["192.0.2.4"])

    def test_path_traversal_absolute_symlinks_and_special_files_are_rejected(self):
        relative = self.source("source.txt", b"unchanged")
        (self.root / "alias").symlink_to(self.root / "artifacts", target_is_directory=True)
        (self.root / "artifacts" / "alias.txt").symlink_to(self.root / relative)
        os.mkfifo(self.root / "artifacts" / "pipe")
        for value in ("../engagement.json", "artifacts/../artifacts/source.txt", str(self.root / relative),
                      "alias/source.txt", "artifacts/alias.txt", "artifacts/pipe", "artifacts"):
            with self.subTest(path=value), self.assertRaises(ValueError):
                triage.file_triage(self.engagement_id, value)
        other = engagements.create_engagement("Other", ["192.0.2.1"])
        with self.assertRaises(ValueError):
            triage.file_triage(self.engagement_id, f"../{other['engagement_id']}/engagement.json")

    def test_output_directory_symlink_is_rejected(self):
        (self.root / "evidence" / "triage").symlink_to(self.root / "artifacts", target_is_directory=True)
        with self.assertRaises(ValueError):
            triage.file_triage(self.engagement_id, self.source("source.txt", b"unchanged"))
        self.assertEqual(sorted(path.name for path in (self.root / "artifacts").iterdir()), ["source.txt"])

    def test_symlinked_namespace_parent_is_rejected(self):
        relative = self.source("sample.txt", b"hello")
        namespace = self.workspace / "engagements"
        moved = self.workspace / "moved-engagements"
        namespace.rename(moved)
        namespace.symlink_to(moved, target_is_directory=True)
        with self.assertRaises(ValueError):
            triage.file_triage(self.engagement_id, relative)

    def test_cancellation_leaves_no_report(self):
        cancelled = threading.Event()
        cancelled.set()
        with self.assertRaises(CancelledError):
            triage.file_triage(self.engagement_id, self.source("source.txt", b"hello"), cancel_event=cancelled)

    def test_audit_storage_error_is_preserved_and_report_is_removed(self):
        relative = self.source("source.txt", b"hello")
        failure = OSError("synthetic audit storage failure")
        with patch.object(triage, "record_event", side_effect=failure):
            with self.assertRaises(OSError) as raised:
                triage.file_triage(self.engagement_id, relative)
        self.assertIs(raised.exception, failure)
        self.assertEqual(list((self.root / "evidence/triage").iterdir()), [])
        self.assertEqual(list((self.root / "evidence").rglob("*.json")), [])

    def test_cancellation_during_atomic_publication_removes_output(self):
        cancelled = threading.Event()
        replace = os.replace

        def cancel_after_replace(*args, **kwargs):
            replace(*args, **kwargs)
            cancelled.set()

        with patch.object(triage.os, "replace", side_effect=cancel_after_replace), self.assertRaises(CancelledError):
            triage.file_triage(self.engagement_id, self.source("sample.txt", b"hello"), cancel_event=cancelled)
        self.assertEqual(list((self.root / "evidence" / "triage").iterdir()), [])

    def test_subprocess_cancellation_kills_process_group(self):
        cancelled = threading.Event()
        pid_file = self.workspace / "child.pid"
        source = ("import os, pathlib, subprocess, sys, time; "
                  "child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'], "
                  "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); os.close(1); os.close(2); "
                  "pathlib.Path(sys.argv[1]).write_text(str(child.pid)); time.sleep(30)")
        errors = []

        def run():
            try:
                triage._capture_process([sys.executable, "-c", source, str(pid_file)], cancelled)
            except BaseException as exc:
                errors.append(exc)

        worker = threading.Thread(target=run)
        worker.start()
        deadline = time.monotonic() + 3
        while not pid_file.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        cancelled.set()
        worker.join(timeout=3)
        self.assertFalse(worker.is_alive())
        self.assertTrue(errors and isinstance(errors[0], CancelledError), errors)
        self.assertTrue(pid_file.exists())
        child_status = Path(f"/proc/{pid_file.read_text()}/stat")
        if child_status.exists():
            self.assertEqual(child_status.read_text().split()[2], "Z", "descendant is still running")

    def test_subprocess_stdout_is_bounded(self):
        captured = triage._capture_process([sys.executable, "-c", "import sys; sys.stdout.write('x' * 1000000)"],
                                          None, output_limit=100)
        self.assertTrue(captured["output_limited"])
        self.assertEqual(len(captured["stdout"]), 100)

    def test_log_jsonl_records_timezone_errors_and_encountered_limits(self):
        data = (b'{"timestamp":"2026-01-02T00:00:01Z","message":"later"}\n'
                b'not-json\n'
                b'{"timestamp":"2026-01-02T00:00:00+00:00","message":"first"}\n'
                b'{"timestamp":"2026-01-02T00:00:02","message":"naive"}\n'
                b'{"timestamp":"2026-01-02T00:00:03Z","message":"beyond-limit"}\n')
        result = triage.log_timeline(self.engagement_id, self.source("sample.jsonl", data), max_records=4)
        report = self.report(result)
        self.assertEqual(report["records_encountered"], 4)
        self.assertEqual([event["line_number"] for event in report["events"]], [3, 1, 4])
        self.assertEqual(report["events"][-1]["timestamp_raw"], "2026-01-02T00:00:02")
        self.assertIsNone(report["events"][-1]["timestamp_utc"])
        self.assertIn("record_limit", report["incomplete_reasons"])
        self.assertEqual({error["line_number"] for error in report["errors"]}, {2, 4})
        self.assertFalse(result["complete"])
        self.assertEqual(report["source"]["sha256"], hashlib.sha256(data).hexdigest())

    def test_text_timeline_explicit_timezone_and_exact_subsecond_order(self):
        data = (b"2026-01-02T00:00:00.123456789+00:00 later\n"
                b"2026-01-02T00:00:00.123456788+00:00 first\n"
                b"2026-01-02T01:00:00 naive\n")
        result = triage.log_timeline(self.engagement_id, self.source("sample.log", data), timezone="+01:00")
        events = self.report(result)["events"]
        self.assertEqual([item["line_number"] for item in events], [3, 2, 1])
        self.assertEqual(events[1]["timestamp_utc"], "2026-01-02T00:00:00.123456788Z")
        self.assertEqual(events[0]["timestamp_utc"], "2026-01-02T00:00:00Z")

    def test_invalid_encoding_and_partial_last_record_are_visible(self):
        data = b"2026-01-02T00:00:00Z good\n2026-01-02T00:00:01Z bad\xff\n"
        relative = self.source("sample.log", data)
        full = self.report(triage.log_timeline(self.engagement_id, relative))
        self.assertTrue(any(error["kind"] == "invalid_encoding" for error in full["errors"]))
        limited = self.report(triage.log_timeline(self.engagement_id, relative, max_bytes=30))
        self.assertFalse(limited["complete"])
        self.assertEqual(limited["records_encountered"], 1)
        self.assertIn("content_limit", limited["incomplete_reasons"])

    def test_timestamp_field_override_and_invalid_options(self):
        relative = self.source("sample.data", b'{"when":"2026-01-02T00:00:00Z"}\n')
        result = triage.log_timeline(self.engagement_id, relative, format="jsonl", timestamp_field="when")
        self.assertEqual(self.report(result)["events"][0]["timestamp_raw"], "2026-01-02T00:00:00Z")
        for options in ({"max_bytes": 0}, {"max_records": -1}, {"format": "xml"}, {"timezone": "unknown/timezone"}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                triage.log_timeline(self.engagement_id, relative, **options)

    def test_json_errors_include_excessive_nesting_and_unrepresentable_numbers(self):
        data = (b'{"timestamp":"2026-01-02T00:00:00Z","value":1e999}\n'
                + b'[' * 2000 + b'0' + b']' * 2000 + b'\n')
        report = self.report(triage.log_timeline(self.engagement_id, self.source("hostile.jsonl", data)))
        self.assertEqual(report["records_encountered"], 2)
        self.assertEqual(len(report["errors"]), 2)
        self.assertFalse(report["complete"])

    def test_ambiguous_and_nonexistent_wall_times_stay_unresolved(self):
        data = (b"2026-10-25T03:30:00 ambiguous\n"
                b"2026-03-29T03:30:00 nonexistent\n")
        report = self.report(triage.log_timeline(self.engagement_id, self.source("dst.log", data),
                                                timezone="Europe/Sofia"))
        self.assertEqual([event["timestamp_utc"] for event in report["events"]], [None, None])
        self.assertEqual(len(report["errors"]), 2)

    def test_pcap_uses_fixed_offline_arguments_and_bounded_snapshot(self):
        data = synthetic_capture()
        relative = self.source("capture.pcap", data)
        row = {field: "" for field in triage._PCAP_FIELDS}
        row.update({"frame.number": "1", "frame.time_epoch": "1767312000.123456789",
                    "frame.len": "46", "frame.protocols": "eth:ip:udp:dns", "ip.src": "192.0.2.1",
                    "ip.dst": "192.0.2.2", "dns.qry.name": "evidence.example.test"})
        encoded = ("\t".join(row.values()) + "\n").encode()
        calls = []

        def fake_process(argv, cancel_event, **kwargs):
            calls.append(argv)
            if "--version" in argv:
                return {"stdout": b"TShark test-version\n", "stderr": b"", "returncode": 0, "output_limited": False}
            self.assertIn("-n", argv)
            self.assertNotIn("-i", argv)
            self.assertEqual(argv[argv.index("-c") + 1], "2")
            descriptor = kwargs["pass_fds"][0]
            os.lseek(descriptor, 0, os.SEEK_SET)
            self.assertEqual(os.read(descriptor, 1000), data[:40])
            return {"stdout": encoded + encoded, "stderr": b"", "returncode": 0, "output_limited": False}

        with patch.object(triage.shutil, "which", return_value="/usr/bin/tshark"), \
             patch.object(triage, "_capture_process", side_effect=fake_process):
            result = triage.pcap_triage(self.engagement_id, relative, max_bytes=40, max_packets=1)
        report = self.report(result)
        self.assertEqual(len(calls), 2)
        self.assertEqual(report["packets_processed"], 1)
        self.assertEqual(report["packets"][0]["timestamp_utc"], "2026-01-02T00:00:00.123456789Z")
        self.assertEqual(report["packets"][0]["dns"]["query"], "evidence.example.test")
        self.assertEqual(set(report["incomplete_reasons"]), {"content_limit", "packet_limit"})
        self.assertEqual(report["source"]["sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual(result["coverage"]["status"], "partial")
        self.assertEqual(result["coverage"]["examined"], 40)
        self.assertEqual(result["limit"]["id"], "triage.max_bytes")
        self.assertTrue(any("packet cap" in item for item in result["limitations"]))

    def test_complete_analysis_declares_complete_coverage_without_limitations(self):
        result = triage.file_triage(self.engagement_id, self.source("whole.bin", b"hello 192.0.2.9\n"))
        self.assertTrue(result["complete"])
        self.assertEqual(result["coverage"]["status"], "complete")
        self.assertEqual(result["coverage"]["examined"], len(b"hello 192.0.2.9\n"))
        self.assertEqual(result["coverage"]["total"], len(b"hello 192.0.2.9\n"))
        self.assertTrue(result["coverage"]["exhausted"])
        self.assertEqual(result["limitations"], [])
        self.assertNotIn("limit", result)

    def test_bounded_analysis_reports_partial_coverage_and_byte_limit_facts(self):
        data = b"first 192.0.2.1\n" + b"hidden.example.test\n" * 20
        result = triage.file_triage(self.engagement_id, self.source("bounded.bin", data), max_bytes=16)
        self.assertEqual(result["coverage"]["status"], "partial")
        self.assertEqual(result["coverage"]["examined"], 16)
        self.assertEqual(result["coverage"]["total"], len(data))
        self.assertFalse(result["coverage"]["exhausted"])
        self.assertEqual(result["limit"]["id"], "triage.max_bytes")
        self.assertEqual(result["limit"]["effective"], 16)
        self.assertTrue(any("16 of" in item and "not evidence of absence" in item
                            for item in result["limitations"]))

    def test_record_and_packet_limits_are_reported_as_partial_with_facts(self):
        data = b"".join(b"2026-01-02T00:00:0%dZ event\n" % index for index in range(4))
        timeline = triage.log_timeline(self.engagement_id, self.source("many.log", data), max_records=2)
        self.assertEqual(timeline["coverage"]["status"], "partial")
        self.assertEqual(timeline["limit"]["id"], "triage.max_records")
        self.assertTrue(any("record cap" in item for item in timeline["limitations"]))

    def test_oversized_cap_is_a_typed_limit_refusal(self):
        relative = self.source("source.txt", b"hello")
        with self.assertRaises(OcError) as raised:
            triage.file_triage(self.engagement_id, relative, max_bytes=268435457)
        self.assertEqual(raised.exception.code, "limit_exceeded")
        self.assertEqual(raised.exception.limit["id"], "triage.max_bytes")
        self.assertEqual(raised.exception.limit["requested"], 268435457)

    def test_live_tool_refusal_carries_not_found_and_unknown_coverage(self):
        from opencyber.server import mcp

        result = asyncio.run(mcp.call_tool("oc_file_triage", {"engagement_id": self.engagement_id, "path": "artifacts/missing.bin"})).structured_content
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"]["code"], "not_found")
        self.assertEqual(result["coverage"]["status"], "unknown")

    def test_pcap_unavailable_is_actionable_and_hash_is_still_complete(self):
        relative = self.source("capture.pcap", synthetic_capture())
        with patch.object(triage.shutil, "which", return_value=None):
            result = triage.pcap_triage(self.engagement_id, relative)
        report = self.report(result)
        self.assertFalse(result["complete"])
        self.assertFalse(result["available"])
        self.assertIn("tshark", report["errors"][0]["message"])
        self.assertTrue(report["source"]["hash_complete"])
        self.assertEqual(result["coverage"]["status"], "partial")
        self.assertTrue(any("tshark" in item for item in result["limitations"]))

    @unittest.skipUnless(shutil.which("tshark"), "host tshark is not installed")
    def test_real_offline_capture_and_corrupt_input(self):
        for filename, data in (("capture.pcap", synthetic_capture()), ("capture.pcapng", synthetic_capture_ng())):
            with self.subTest(format=filename), \
                 patch.object(socket, "getaddrinfo", side_effect=AssertionError("network resolution forbidden")):
                result = triage.pcap_triage(self.engagement_id, self.source(filename, data))
            report = self.report(result)
            self.assertTrue(result["complete"], report)
            self.assertEqual(report["packets_processed"], 1)
            self.assertEqual(report["packets"][0]["source"], "192.0.2.1")
            self.assertEqual(report["packets"][0]["destination"], "192.0.2.2")
            self.assertIn("udp", report["packets"][0]["protocols"])
            self.assertEqual((self.root / "artifacts" / filename).read_bytes(), data)
        data = synthetic_capture()
        bad = triage.pcap_triage(self.engagement_id, self.source("corrupt.pcap", data[:30]))
        self.assertFalse(bad["complete"])
        self.assertTrue(self.report(bad)["errors"])


def synthetic_capture():
    """One Ethernet/IPv4/UDP packet with documentation-only addresses."""
    udp = struct.pack("!HHHH", 1234, 4321, 12, 0) + b"test"
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(udp), 1, 0, 64, 17, 0,
                     socket.inet_aton("192.0.2.1"), socket.inet_aton("192.0.2.2"))
    frame = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x08\x00" + ip + udp
    return (struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1)
            + struct.pack("<IIII", 1767312000, 123456, len(frame), len(frame)) + frame)


def synthetic_capture_ng():
    frame = synthetic_capture()[40:]
    timestamp = 1767312000 * 1_000_000 + 123456
    padding = b"\0" * (-len(frame) % 4)
    packet_length = 32 + len(frame) + len(padding)
    return (struct.pack("<IIIHHqI", 0x0a0d0d0a, 28, 0x1a2b3c4d, 1, 0, -1, 28)
            + struct.pack("<IIHHII", 1, 20, 1, 0, 65535, 20)
            + struct.pack("<IIIIIII", 6, packet_length, 0, timestamp >> 32, timestamp & 0xffffffff, len(frame), len(frame))
            + frame + padding + struct.pack("<I", packet_length))


if __name__ == "__main__":
    unittest.main()
