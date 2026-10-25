from __future__ import annotations

import asyncio
import os
from pathlib import Path
import pty
import tempfile
import termios
import time
import unittest
from unittest.mock import patch

import opencyber.engagements as engagements
from opencyber.errors import OcError
from opencyber.hardware import (
    analyze_firmware,
    hardware_inventory,
    hardware_plan,
    hardware_readiness,
    serial_close,
    serial_list,
    serial_open,
    serial_read,
    serial_write,
)


def _write(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(value, encoding="utf-8")


class HardwareInventoryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.sysfs = self.root / "sys"
        self.dev = self.root / "dev"
        self.engagement_root = self.root / "workspace"
        self.engagement_root.mkdir()
        self.env = patch.dict(
            os.environ,
            {
                "OPENCYBER_SYSFS": str(self.sysfs),
                "OPENCYBER_DEV": str(self.dev),
            },
        )
        self.env.start()
        self.workspace_patch = patch.object(engagements, "WORKSPACE", self.engagement_root)
        self.workspace_patch.start()
        self.engagement = engagements.create_engagement("Hardware", ["example.test"])
        self.engagement_id = self.engagement["engagement_id"]
        self._build_fixture()

    def tearDown(self):
        self.workspace_patch.stop()
        self.env.stop()
        self.temporary.cleanup()

    def _build_fixture(self):
        usb = self.sysfs / "bus" / "usb" / "devices"
        _write(usb / "usb1" / "idVendor", "1d6b")
        _write(usb / "usb1" / "idProduct", "0002")
        _write(usb / "1-1" / "idVendor", "1d50")
        _write(usb / "1-1" / "idProduct", "6089")
        _write(usb / "1-1" / "product", "HackRF One")
        _write(usb / "1-1" / "manufacturer", "Great Scott Gadgets")
        _write(usb / "1-1" / "serial", "0000000000000000")
        _write(usb / "1-1" / "bDeviceClass", "ff")
        _write(usb / "1-1" / "busnum", "1")
        _write(usb / "1-1" / "devnum", "2")
        _write(usb / "1-1" / "speed", "480")
        _write(usb / "1-1" / "1-1:1.0" / "bInterfaceClass", "ff")

        _write(self.sysfs / "class" / "tty" / "ttyUSB0" / "type", "0")
        _write(self.dev / "ttyUSB0", "fixture")

        _write(self.sysfs / "class" / "net" / "wlan0" / "address", "00:11:22:33:44:55")
        _write(self.sysfs / "class" / "net" / "wlan0" / "operstate", "up")
        _write(self.sysfs / "class" / "net" / "wlan0" / "type", "1")
        (self.sysfs / "class" / "net" / "wlan0" / "wireless").mkdir(parents=True)
        _write(self.sysfs / "class" / "net" / "can0" / "type", "280")
        _write(self.sysfs / "class" / "net" / "can0" / "address", "00:00:00:00:00:00")
        _write(self.sysfs / "class" / "bluetooth" / "hci0" / "address", "AA:BB:CC:DD:EE:FF")
        _write(self.sysfs / "class" / "video4linux" / "video0" / "name", "USB Camera")
        _write(self.sysfs / "class" / "input" / "input0" / "name", "USB Keyboard")

        (self.dev / "bus" / "usb" / "001").mkdir(parents=True)
        _write(self.dev / "bus" / "usb" / "001" / "002", "")
        _write(self.dev / "gpiochip0", "")
        _write(self.dev / "i2c-1", "")
        _write(self.dev / "spidev0.0", "")
        _write(self.dev / "lirc0", "")

    def test_inventory_classifies_known_usb_and_buses(self):
        inventory = hardware_inventory()
        self.assertEqual(inventory["platform"]["system"], os.uname().sysname)
        hackrf = next(device for device in inventory["usb"] if device["label"] == "HackRF One")
        self.assertEqual(hackrf["class"], "sdr")
        self.assertTrue(hackrf["known"])
        self.assertEqual(inventory["serial"][0]["device"], str(self.dev / "ttyUSB0"))
        self.assertEqual(
            {item["kind"] for item in inventory["network"]},
            {"wifi", "can"},
        )
        self.assertEqual(inventory["bluetooth"][0]["address"], "AA:BB:CC:DD:EE:FF")
        self.assertEqual(inventory["device_nodes"]["gpio"], [str(self.dev / "gpiochip0")])
        self.assertIn("sdr", inventory["summary"])

    def test_readiness_separates_tooling_from_devices(self):
        ready_tools = {
            "lsusb", "hackrf_info", "rtl_test", "SoapySDRUtil", "iw", "airmon-ng",
            "hcxdumptool", "bluetoothctl", "btmon", "ubertooth-util", "proxmark3",
            "nfc-list", "openocd", "jtag", "flashrom", "picocom", "python3",
            "candump", "cansend", "sigrok-cli", "gpsmon", "gpspipe", "lircd",
        }
        inventory = hardware_inventory()
        inventory["capabilities"]["granted"] = ["NET_ADMIN", "NET_RAW"]
        with patch("opencyber.hardware.shutil.which", side_effect=lambda name: f"/usr/bin/{name}" if name in ready_tools else None):
            report = hardware_readiness(inventory)
        self.assertIn("sdr", report["ready_domains"])
        self.assertIn("wifi", report["ready_domains"])
        self.assertIn("automotive", report["ready_domains"])
        self.assertIn("serial", report["ready_domains"])
        self.assertIn("nfc", report["tooling_only_domains"])
        self.assertIn("--device /dev/bus/usb", report["domains"]["sdr"]["host_flags"])
        self.assertEqual(report["summary"]["ready"] + report["summary"]["tooling_ready"] + report["summary"]["unavailable"], len(report["domains"]))

        inventory["capabilities"]["granted"] = []
        with patch("opencyber.hardware.shutil.which", side_effect=lambda name: f"/usr/bin/{name}" if name in ready_tools else None):
            limited = hardware_readiness(inventory)
        self.assertNotIn("wifi", limited["ready_domains"])
        self.assertNotIn("bluetooth", limited["ready_domains"])
        self.assertIn("--cap-add NET_ADMIN", limited["domains"]["wifi"]["remediation"])

    def test_inventory_and_readiness_declare_coverage_and_exposure_limits(self):
        inventory = hardware_inventory()
        self.assertEqual(inventory["coverage"]["status"], "complete")
        self.assertTrue(any("exposure gap" in item for item in inventory["limitations"]))
        with patch("opencyber.hardware.shutil.which", return_value=None):
            report = hardware_readiness(inventory)
        self.assertEqual(report["coverage"]["status"], "complete")
        self.assertTrue(any("catalog binary is missing" in item for item in report["limitations"]))

    def test_hardware_plan_states_that_it_is_advisory_only(self):
        plan = hardware_plan("firmware")
        self.assertEqual(plan["coverage"]["status"], "complete")
        self.assertTrue(any("not a capability check" in item for item in plan["limitations"]))
        with self.assertRaises(OcError) as raised:
            hardware_plan("teleportation")
        self.assertEqual(raised.exception.code, "invalid_argument")

    def test_hardware_plan_is_bounded_and_deterministic(self):
        plan = hardware_plan("serial", "target board")
        self.assertEqual(plan["domain"], "serial")
        self.assertEqual(plan["steps"][1]["tool"], "oc_serial_open")
        self.assertTrue(plan["prerequisites"])
        with self.assertRaises(ValueError):
            hardware_plan("teleportation")

    def test_serial_session_reads_and_writes_a_pty(self):
        master, slave = pty.openpty()
        device = os.ttyname(slave)
        original_attributes = termios.tcgetattr(slave)
        try:
            with patch.dict(os.environ, {"OPENCYBER_ALLOW_PTY": "1"}):
                session = serial_open(self.engagement_id, device, baudrate=115200)
                self.assertEqual(serial_list(self.engagement_id)["sessions"][0]["session_id"], session["session_id"])
                os.write(master, b"boot: \r\n")
                time.sleep(0.05)
                read = serial_read(self.engagement_id, session["session_id"], timeout=2)
                self.assertIn("boot:", read["data"])
                write = serial_write(self.engagement_id, session["session_id"], data="help\r\n")
                self.assertEqual(write["bytes"], 6)
                self.assertEqual(os.read(master, 64), b"help\r\n")
                closed = serial_close(self.engagement_id, session["session_id"])
                self.assertTrue(closed["closed"])
                self.assertEqual(termios.tcgetattr(slave), original_attributes)
                self.assertTrue(Path(closed["transcript"]).is_file())
                self.assertEqual(serial_list(self.engagement_id)["sessions"], [])
        finally:
            os.close(master)
            os.close(slave)

    def test_serial_device_allowlist_rejects_memory_and_block_devices(self):
        with self.assertRaises(ValueError):
            serial_open(self.engagement_id, "/dev/mem")
        with self.assertRaises(ValueError):
            serial_open(self.engagement_id, "/dev/sda")

    def test_serial_read_timeout_is_unknown_coverage_with_a_buffer_limitation(self):
        master, slave = pty.openpty()
        device = os.ttyname(slave)
        try:
            with patch.dict(os.environ, {"OPENCYBER_ALLOW_PTY": "1"}):
                session = serial_open(self.engagement_id, device)
                read = serial_read(self.engagement_id, session["session_id"], timeout=0.05)
                self.assertTrue(read["timed_out"])
                self.assertEqual(read["bytes"], 0)
                self.assertEqual(read["coverage"]["status"], "unknown")
                self.assertTrue(any("buffer may still hold data" in item for item in read["limitations"]))
                self.assertEqual(read["limit"]["id"], "serial.read_timeout")
                os.write(master, b"x" * 64)
                time.sleep(0.05)
                capped = serial_read(self.engagement_id, session["session_id"], max_bytes=16, timeout=2)
                self.assertEqual(capped["bytes"], 16)
                self.assertEqual(capped["coverage"]["status"], "partial")
                self.assertEqual(capped["limit"]["id"], "serial.read_max_bytes")
                self.assertTrue(any("remain unread" in item for item in capped["limitations"]))
                closed = serial_close(self.engagement_id, session["session_id"])
                self.assertEqual(closed["coverage"]["status"], "complete")
        finally:
            os.close(master)
            os.close(slave)

    def test_live_serial_read_refusal_carries_not_found(self):
        from opencyber.server import mcp

        result = asyncio.run(mcp.call_tool("oc_serial_read", {
                "engagement_id": self.engagement_id,
                "session_id": "ser_20260101_" + "0" * 32,
            })).structured_content
        self.assertFalse(result["ok"])
        self.assertEqual(result["error"]["code"], "not_found")

    def test_firmware_analysis_reports_partial_when_signatures_are_skipped(self):
        image = Path(self.engagement["workspace"]) / "partial.bin"
        image.write_bytes(b"\x7fELF\x01\x01\x01\x00" + b"\x00" * 64)
        report = analyze_firmware(self.engagement_id, "partial.bin", run_binwalk=False)
        self.assertEqual(report["coverage"]["status"], "partial")
        self.assertEqual(report["coverage"]["total"], image.stat().st_size)
        self.assertTrue(any("not requested" in item for item in report["limitations"]))

    def test_firmware_analysis_reports_unknown_when_magic_is_unrecognized(self):
        image = Path(self.engagement["workspace"]) / "opaque.bin"
        image.write_bytes(b"\x01\x02\x03\x04" + b"\xff" * 64)
        report = analyze_firmware(self.engagement_id, "opaque.bin", run_binwalk=False)
        self.assertEqual(report["identity"]["format"], "unknown")
        self.assertEqual(report["coverage"]["status"], "unknown")
        self.assertTrue(any("unidentified" in item for item in report["limitations"]))
        with self.assertRaises(OcError) as raised:
            analyze_firmware(self.engagement_id, "missing.bin")
        self.assertEqual(raised.exception.code, "not_found")

    def test_firmware_analysis_hashes_and_persists_report(self):
        image = Path(self.engagement["workspace"]) / "firmware.bin"
        payload = (
            b"\x7fELF\x01\x01\x01\x00" + b"\x00" * 8 + b"\x02\x00"
            + (183).to_bytes(2, "little")
            + b"\x00" * 200
            + b"admin password=hunter2 http://example.test/console\n"
            + bytes(range(256)) * 32
        )
        image.write_bytes(payload)
        report = analyze_firmware(self.engagement_id, "firmware.bin", run_binwalk=False)
        self.assertEqual(report["identity"]["format"], "ELF executable")
        self.assertEqual(report["identity"]["architecture"], "AArch64")
        self.assertEqual(report["identity"]["sha256"], __import__("hashlib").sha256(payload).hexdigest())
        self.assertGreater(report["entropy"]["blocks"], 0)
        self.assertTrue(any("admin" in item for item in report["strings"]["interesting"]))
        artifact = Path(self.engagement["workspace"]) / report["artifact_path"]
        self.assertTrue(artifact.is_file())

    def test_firmware_strings_do_not_exceed_reported_analysis_window(self):
        image = Path(self.engagement["workspace"]) / "bounded.bin"
        image.write_bytes(b"\0" * 8192 + b"api_key=AFTER_REPORTED_WINDOW")
        report = analyze_firmware(self.engagement_id, "bounded.bin", max_entropy_bytes=4096, run_binwalk=False)
        self.assertEqual(report["strings"]["interesting"], [])


if __name__ == "__main__":
    unittest.main()
