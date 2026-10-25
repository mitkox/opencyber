"""Physical-layer inventory, serial consoles, and firmware triage.

The harness runs inside a container, so hardware is only visible when the
operator passes it through from the host. This module answers two separate
questions that are easy to confuse:

* Is the *tooling* installed? (catalog / doctor)
* Is the *device* present and usable? (this module)

Nothing here assumes a device exists. A missing radio is reported as a
capability gap with the host flags needed to expose it, never as a crashed
tool call.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import select
import shutil
import stat
import subprocess
import threading
import time
from typing import Any
import uuid

from . import envelope, limits
from .audit import safe_record
from .engagements import resolve_engagement_path
from .errors import OcError


# ---------------------------------------------------------------------------
# Device knowledge
# ---------------------------------------------------------------------------

# USB IDs that show up in real red-team kits. The class drives both the
# inventory summary and the domain readiness report.
KNOWN_USB_DEVICES: dict[tuple[str, str], dict[str, Any]] = {
    ("1d50", "6089"): {"name": "HackRF One", "class": "sdr", "tools": ["hackrf_info"]},
    ("1d50", "604b"): {"name": "HackRF Jawbreaker", "class": "sdr", "tools": ["hackrf_info"]},
    ("0bda", "2838"): {"name": "Realtek RTL2838 RTL-SDR", "class": "sdr", "tools": ["rtl_test"]},
    ("0bda", "2832"): {"name": "Realtek RTL2832U RTL-SDR", "class": "sdr", "tools": ["rtl_test"]},
    ("2cf0", "5250"): {"name": "Nuand bladeRF", "class": "sdr", "tools": ["bladeRF-cli"]},
    ("1d19", "6109"): {"name": "LimeSDR", "class": "sdr", "tools": ["LimeUtil"]},
    ("1d19", "0011"): {"name": "LimeSDR USB", "class": "sdr", "tools": ["LimeUtil"]},
    ("2500", "0020"): {"name": "Ettus USRP B200", "class": "sdr", "tools": ["SoapySDRUtil"]},
    ("1d50", "6002"): {"name": "Ubertooth One", "class": "bluetooth", "tools": ["ubertooth-util"]},
    ("9ac4", "4b8f"): {"name": "Proxmark3", "class": "nfc", "tools": ["proxmark3"]},
    ("072f", "2200"): {"name": "ACS ACR122U NFC reader", "class": "nfc", "tools": ["nfc-list"]},
    ("04e6", "5591"): {"name": "SCM SCL3711 NFC reader", "class": "nfc", "tools": ["nfc-list"]},
    ("1366", "0105"): {"name": "SEGGER J-Link", "class": "jtag", "tools": ["openocd"]},
    ("1366", "1015"): {"name": "SEGGER J-Link OB", "class": "jtag", "tools": ["openocd"]},
    ("0d28", "0204"): {"name": "DAPLink CMSIS-DAP", "class": "jtag", "tools": ["openocd"]},
    ("0483", "3748"): {"name": "ST-Link V1", "class": "jtag", "tools": ["st-info"]},
    ("0483", "374b"): {"name": "ST-Link V2", "class": "jtag", "tools": ["st-info"]},
    ("0483", "374e"): {"name": "ST-Link V2-1", "class": "jtag", "tools": ["st-info"]},
    ("0483", "374f"): {"name": "ST-Link V3", "class": "jtag", "tools": ["st-info"]},
    ("1fc9", "0132"): {"name": "NXP LPC-Link2", "class": "jtag", "tools": ["openocd"]},
    ("0403", "6014"): {"name": "FTDI FT2232 debug adapter", "class": "jtag", "tools": ["openocd"]},
    ("0925", "3881"): {"name": "Saleae Logic", "class": "logic", "tools": ["sigrok-cli"]},
    ("21a9", "1001"): {"name": "Saleae Logic16", "class": "logic", "tools": ["sigrok-cli"]},
    ("04b4", "8613"): {"name": "Cypress FX2 logic analyzer", "class": "logic", "tools": ["sigrok-cli"]},
    ("1546", "01a7"): {"name": "u-blox GNSS receiver", "class": "gps", "tools": ["gpsmon"]},
    ("091e", "0003"): {"name": "Garmin GPS", "class": "gps", "tools": ["gpsmon"]},
    ("10c4", "ea60"): {"name": "CP210x USB serial", "class": "serial", "tools": ["picocom"]},
    ("1a86", "7523"): {"name": "CH340 USB serial", "class": "serial", "tools": ["picocom"]},
    ("0403", "6001"): {"name": "FTDI FT232 USB serial", "class": "serial", "tools": ["picocom"]},
    ("0483", "5740"): {"name": "STM32 USB CDC", "class": "serial", "tools": ["picocom"]},
    ("239a", "000f"): {"name": "Adafruit Feather/RP2040", "class": "serial", "tools": ["picocom"]},
    ("2e8a", "000a"): {"name": "Raspberry Pi Pico", "class": "serial", "tools": ["picocom"]},
    ("2341", "0043"): {"name": "Arduino Uno", "class": "serial", "tools": ["picocom"]},
    ("2341", "0001"): {"name": "Arduino", "class": "serial", "tools": ["picocom"]},
    ("0483", "df11"): {"name": "STM32 DFU", "class": "embedded", "tools": ["dfu-util"]},
    ("1d50", "6018"): {"name": "GreatFET", "class": "embedded", "tools": ["greatfet"]},
    ("1d50", "60e6"): {"name": "DSLogic", "class": "logic", "tools": ["sigrok-cli"]},
    ("1050", "0407"): {"name": "YubiKey", "class": "usb", "tools": ["lsusb"]},
}

USB_CLASS_NAMES = {
    "01": "audio",
    "02": "cdc",
    "03": "hid",
    "06": "imaging",
    "07": "printer",
    "08": "mass-storage",
    "09": "hub",
    "0a": "cdc-data",
    "0b": "smart-card",
    "0d": "content-security",
    "0e": "video",
    "dc": "diagnostic",
    "e0": "wireless",
    "ef": "misc",
    "fe": "application",
    "ff": "vendor",
}

# Domains exposed by oc_hardware_readiness. ``device_class`` is matched
# against the classes discovered from sysfs; ``tools`` are the binaries that
# make the domain useful.
HARDWARE_DOMAINS: dict[str, dict[str, Any]] = {
    "usb": {
        "label": "USB device inventory",
        "tools": ["lsusb"],
        "device_class": None,
        "host_flags": ["--device /dev/bus/usb"],
    },
    "sdr": {
        "label": "Software-defined radio",
        "tools": ["hackrf_info", "rtl_test", "SoapySDRUtil"],
        "device_class": "sdr",
        "host_flags": ["--device /dev/bus/usb"],
    },
    "wifi": {
        "label": "Wi-Fi monitor/injection",
        "tools": ["iw", "airmon-ng", "hcxdumptool"],
        "device_class": "wifi",
        "host_flags": [
            "--network host",
            "--cap-add NET_ADMIN",
            "--cap-add NET_RAW",
        ],
    },
    "bluetooth": {
        "label": "Bluetooth / BLE",
        "tools": ["bluetoothctl", "btmon", "ubertooth-util"],
        "device_class": "bluetooth",
        "host_flags": [
            "--network host",
            "--cap-add NET_ADMIN",
            "--cap-add NET_RAW",
            "--device /dev/bus/usb",
        ],
    },
    "nfc": {
        "label": "NFC / RFID",
        "tools": ["proxmark3", "nfc-list"],
        "device_class": "nfc",
        "host_flags": ["--device /dev/bus/usb"],
    },
    "jtag": {
        "label": "JTAG / SWD / SPI flash",
        "tools": ["openocd", "jtag", "flashrom"],
        "device_class": "jtag",
        "host_flags": ["--device /dev/bus/usb"],
    },
    "serial": {
        "label": "UART / serial console",
        "tools": ["picocom", "python3"],
        "device_class": "serial",
        "host_flags": ["--device /dev/ttyUSB0", "--device /dev/ttyACM0"],
    },
    "automotive": {
        "label": "CAN / automotive",
        "tools": ["candump", "cansend"],
        "device_class": "can",
        "host_flags": [
            "--network host",
            "--cap-add NET_ADMIN",
            "--device /dev/bus/usb",
        ],
    },
    "logic": {
        "label": "Logic analyzer",
        "tools": ["sigrok-cli"],
        "device_class": "logic",
        "host_flags": ["--device /dev/bus/usb"],
    },
    "gps": {
        "label": "GNSS / GPS",
        "tools": ["gpsmon", "gpspipe"],
        "device_class": "gps",
        "host_flags": ["--device /dev/ttyUSB0", "--device /dev/bus/usb"],
    },
    "ir": {
        "label": "Infrared",
        "tools": ["lircd"],
        "device_class": "ir",
        "host_flags": ["--device /dev/lirc0"],
    },
}


# ---------------------------------------------------------------------------
# sysfs/dev helpers
# ---------------------------------------------------------------------------


def _sysfs_root() -> Path:
    return Path(os.environ.get("OPENCYBER_SYSFS", "/sys"))


def _dev_root() -> Path:
    return Path(os.environ.get("OPENCYBER_DEV", "/dev"))


def _read(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None


def _read_int(path: Path) -> int | None:
    raw = _read(path)
    if raw is None:
        return None
    try:
        return int(raw, 0)
    except ValueError:
        return None


def _driver_name(device: Path) -> str | None:
    driver = device / "driver"
    try:
        if driver.is_symlink() or driver.exists():
            return driver.resolve().name
    except OSError:
        return None
    return None


def _usb_interface_classes(device: Path) -> list[str]:
    classes: list[str] = []
    try:
        entries = list(device.iterdir())
    except OSError:
        return classes
    for entry in entries:
        if ":" not in entry.name:
            continue
        raw = _read(entry / "bInterfaceClass")
        if raw is None:
            continue
        try:
            code = f"{int(raw, 16):02x}"
        except ValueError:
            continue
        classes.append(USB_CLASS_NAMES.get(code, code))
    return sorted(set(classes))


def _classify_usb(vendor: str, product: str, interface_classes: list[str]) -> tuple[str, str]:
    known = KNOWN_USB_DEVICES.get((vendor.lower(), product.lower()))
    if known:
        return known["class"], known["name"]
    if "wireless" in interface_classes:
        return "wifi", "Wireless USB device"
    if "vendor" in interface_classes and vendor.lower() in {"0bda", "148f", "0e8d", "8087"}:
        return "wifi", "Wireless USB device"
    if "smart-card" in interface_classes:
        return "nfc", "Smart-card reader"
    if "mass-storage" in interface_classes:
        return "storage", "USB mass storage"
    if "hid" in interface_classes:
        return "hid", "USB HID device"
    if "video" in interface_classes:
        return "video", "USB video device"
    if "cdc" in interface_classes or "cdc-data" in interface_classes:
        return "serial", "USB CDC serial device"
    return "usb", "USB device"


def _enumerate_usb() -> list[dict[str, Any]]:
    root = _sysfs_root() / "bus" / "usb" / "devices"
    devices: list[dict[str, Any]] = []
    try:
        entries = sorted(root.iterdir())
    except OSError:
        return devices
    for entry in entries:
        if not entry.is_dir():
            continue
        vendor = _read(entry / "idVendor")
        product = _read(entry / "idProduct")
        if not vendor or not product:
            continue
        interfaces = _usb_interface_classes(entry)
        device_class, label = _classify_usb(vendor, product, interfaces)
        known = KNOWN_USB_DEVICES.get((vendor.lower(), product.lower()))
        bus = _read_int(entry / "busnum")
        number = _read_int(entry / "devnum")
        node = (
            _dev_root() / "bus" / "usb" / f"{bus:03d}" / f"{number:03d}"
            if bus is not None and number is not None
            else None
        )
        devices.append(
            {
                "bus": bus,
                "device": number,
                "vendor_id": f"{vendor.lower()}",
                "product_id": f"{product.lower()}",
                "accessible": bool(node and node.exists()),
                "vendor": _read(entry / "manufacturer") or "",
                "product": _read(entry / "product") or "",
                "serial": _read(entry / "serial") or "",
                "speed_mbps": _read(entry / "speed") or "",
                "usb_class": _read(entry / "bDeviceClass") or "",
                "interface_classes": interfaces,
                "class": device_class,
                "label": label,
                "known": known is not None,
                "sysfs": str(entry),
            }
        )
    return devices


def _enumerate_serial() -> list[dict[str, Any]]:
    root = _sysfs_root() / "class" / "tty"
    dev_root = _dev_root()
    devices: list[dict[str, Any]] = []
    try:
        entries = sorted(root.iterdir())
    except OSError:
        return devices
    prefixes = (
        "ttyUSB", "ttyACM", "ttyAMA", "ttyS", "ttyO", "ttyPS", "ttyGS",
        "ttyHS", "ttySC", "ttyTHS", "ttyRPMSG", "rfcomm",
    )
    for entry in entries:
        if not entry.name.startswith(prefixes):
            continue
        device_path = dev_root / entry.name
        if not device_path.exists():
            continue
        device = entry / "device"
        devices.append(
            {
                "device": str(device_path),
                "name": entry.name,
                "driver": _driver_name(device),
                "sysfs": str(entry),
                "type": _read(entry / "type") or "",
            }
        )
    by_id = dev_root / "serial" / "by-id"
    try:
        for link in sorted(by_id.iterdir()):
            devices.append(
                {
                    "device": str(link),
                    "name": link.name,
                    "driver": None,
                    "sysfs": str(link.parent),
                    "type": "by-id",
                    "target": os.path.realpath(link),
                }
            )
    except OSError:
        pass
    return devices


def _enumerate_network() -> list[dict[str, Any]]:
    root = _sysfs_root() / "class" / "net"
    interfaces: list[dict[str, Any]] = []
    try:
        entries = sorted(root.iterdir())
    except OSError:
        return interfaces
    for entry in entries:
        if entry.name == "lo":
            continue
        raw_type = _read_int(entry / "type")
        wireless = (entry / "wireless").exists() or (entry / "phy80211").exists()
        if raw_type == 280:
            kind = "can"
        elif wireless:
            kind = "wifi"
        elif entry.name.startswith(("wwan", "rmnet", "ppp")):
            kind = "cellular"
        elif entry.name.startswith(("tun", "tap")):
            kind = "tunnel"
        elif entry.name.startswith("usb"):
            kind = "usb"
        else:
            kind = "ethernet"
        interfaces.append(
            {
                "name": entry.name,
                "kind": kind,
                "type": raw_type,
                "address": _read(entry / "address") or "",
                "operstate": _read(entry / "operstate") or "",
                "mtu": _read_int(entry / "mtu"),
                "driver": _driver_name(entry / "device"),
                "wireless": wireless,
                "can": raw_type == 280,
                "sysfs": str(entry),
            }
        )
    return interfaces


def _enumerate_bluetooth() -> list[dict[str, Any]]:
    root = _sysfs_root() / "class" / "bluetooth"
    adapters: list[dict[str, Any]] = []
    try:
        entries = sorted(root.iterdir())
    except OSError:
        return adapters
    for entry in entries:
        adapters.append(
            {
                "name": entry.name,
                "address": _read(entry / "address") or "",
                "bus": _read(entry / "bus") or "",
                "type": _read(entry / "type") or "",
                "sysfs": str(entry),
            }
        )
    return adapters


def _enumerate_video() -> list[dict[str, Any]]:
    root = _sysfs_root() / "class" / "video4linux"
    devices: list[dict[str, Any]] = []
    try:
        entries = sorted(root.iterdir())
    except OSError:
        return devices
    for entry in entries:
        devices.append(
            {
                "device": f"/dev/{entry.name}",
                "name": _read(entry / "name") or entry.name,
                "sysfs": str(entry),
            }
        )
    return devices


def _enumerate_input() -> list[dict[str, Any]]:
    root = _sysfs_root() / "class" / "input"
    devices: list[dict[str, Any]] = []
    try:
        entries = sorted(root.iterdir())
    except OSError:
        return devices
    for entry in entries:
        if not entry.name.startswith("input"):
            continue
        name = _read(entry / "name")
        if not name:
            continue
        devices.append(
            {
                "name": name,
                "phys": _read(entry / "phys") or "",
                "uniq": _read(entry / "uniq") or "",
                "sysfs": str(entry),
            }
        )
    return devices


def _enumerate_device_nodes() -> dict[str, list[str]]:
    dev = _dev_root()
    groups = {
        "gpio": sorted(str(path) for path in dev.glob("gpiochip*")),
        "i2c": sorted(str(path) for path in dev.glob("i2c-*")),
        "spi": sorted(str(path) for path in dev.glob("spidev*")),
        "lirc": sorted(str(path) for path in dev.glob("lirc*")),
        "video": sorted(str(path) for path in dev.glob("video*")),
        "usb": sorted(str(path) for path in dev.glob("bus/usb/*/*")),
    }
    return groups


def _capabilities() -> dict[str, Any]:
    raw = _read(Path("/proc/self/status"))
    effective = None
    if raw:
        match = re.search(r"^CapEff:\s*([0-9a-fA-F]+)$", raw, re.MULTILINE)
        if match:
            effective = int(match.group(1), 16)
    names = {
        "NET_ADMIN": 12,
        "NET_RAW": 13,
        "SYS_MODULE": 16,
        "SYS_RAWIO": 17,
        "SYS_ADMIN": 21,
        "BPF": 39,
    }
    granted = []
    if effective is not None:
        granted = [name for name, bit in names.items() if effective & (1 << bit)]
    return {
        "effective_hex": f"{effective:x}" if effective is not None else None,
        "granted": granted,
        "privileged": effective is not None and (effective & ((1 << 21) - 1)) == ((1 << 21) - 1),
    }


def _platform() -> dict[str, Any]:
    return {
        "system": os.uname().sysname,
        "machine": os.uname().machine,
        "release": os.uname().release,
        "container": Path("/.dockerenv").exists()
        or "docker" in (_read(Path("/proc/1/cgroup")) or "").lower()
        or "kubepods" in (_read(Path("/proc/1/cgroup")) or "").lower(),
    }


# ---------------------------------------------------------------------------
# Public inventory / readiness
# ---------------------------------------------------------------------------


def hardware_inventory() -> dict[str, Any]:
    usb = _enumerate_usb()
    serial = _enumerate_serial()
    network = _enumerate_network()
    bluetooth = _enumerate_bluetooth()
    devices = _enumerate_device_nodes()

    known = [
        {
            "class": device["class"],
            "label": device["label"],
            "vendor_id": device["vendor_id"],
            "product_id": device["product_id"],
            "serial": device["serial"],
            "accessible": device["accessible"],
        }
        for device in usb
        if device["known"]
    ]
    summary: dict[str, int] = {}
    for device in usb:
        summary[device["class"]] = summary.get(device["class"], 0) + 1
    for interface in network:
        summary[interface["kind"]] = summary.get(interface["kind"], 0) + 1
    if bluetooth:
        summary["bluetooth"] = len(bluetooth)
    if serial:
        summary["serial"] = len(serial)
    if devices["lirc"]:
        summary["ir"] = len(devices["lirc"])
    if devices["gpio"]:
        summary["gpio"] = len(devices["gpio"])
    if devices["i2c"]:
        summary["i2c"] = len(devices["i2c"])
    if devices["spi"]:
        summary["spi"] = len(devices["spi"])

    return {
        "platform": _platform(),
        "capabilities": _capabilities(),
        "usb": usb,
        "serial": serial,
        "network": network,
        "bluetooth": bluetooth,
        "video": _enumerate_video(),
        "input": _enumerate_input(),
        "device_nodes": devices,
        "known_devices": known,
        "summary": dict(sorted(summary.items())),
        "access": {
            "usb_devices": len(usb),
            "usb_accessible": sum(1 for device in usb if device.get("accessible")),
            "serial": len(serial),
            "network": len(network),
            "bluetooth": len(bluetooth),
            "lirc": len(devices["lirc"]),
        },
        "notes": [
            "Device visibility is controlled by the host. A missing device is an "
            "exposure problem, not a tooling failure.",
            "Run oc_hardware_readiness for per-domain host flags and remediation.",
        ],
        "coverage": envelope.coverage("complete", exhausted=True),
        "limitations": [
            "Device visibility is controlled by the host container: a device absent from this inventory is "
            "an exposure gap, not evidence that the device does not exist on the host.",
            "Enumeration reads sysfs and /dev only. A device that is present but not accessible is counted "
            "separately under access instead of being reported as working.",
        ],
    }


def _domain_devices(domain: str, inventory: dict[str, Any]) -> list[dict[str, Any]]:
    device_class = HARDWARE_DOMAINS[domain].get("device_class")
    if domain == "usb":
        return [
            device
            for device in inventory["usb"]
            if device.get("accessible")
            and device.get("usb_class") != "09"
            and device.get("interface_classes") != ["hub"]
        ]
    if domain == "sdr":
        return [
            device
            for device in inventory["usb"]
            if device["class"] == "sdr" and device.get("accessible")
        ]
    capabilities = set(inventory.get("capabilities", {}).get("granted", []))
    if domain == "wifi":
        if "NET_ADMIN" not in capabilities:
            return []
        return [interface for interface in inventory["network"] if interface["kind"] == "wifi"]
    if domain == "bluetooth":
        # An Ubertooth only needs USB. A host HCI adapter needs NET_ADMIN to
        # open raw HCI sockets; without it, sysfs visibility is misleading.
        ubertooth = [
            device
            for device in inventory["usb"]
            if device["class"] == "bluetooth" and device.get("accessible")
        ]
        adapters = list(inventory["bluetooth"]) if "NET_ADMIN" in capabilities else []
        return adapters + ubertooth
    if domain == "nfc":
        return [
            device
            for device in inventory["usb"]
            if device["class"] == "nfc" and device.get("accessible")
        ]
    if domain == "jtag":
        return [
            device
            for device in inventory["usb"]
            if device["class"] == "jtag" and device.get("accessible")
        ]
    if domain == "serial":
        return list(inventory["serial"]) + [
            device
            for device in inventory["usb"]
            if device["class"] == "serial" and device.get("accessible")
        ]
    if domain == "automotive":
        if "NET_ADMIN" not in capabilities:
            return []
        return [interface for interface in inventory["network"] if interface["kind"] == "can"]
    if domain == "logic":
        return [
            device
            for device in inventory["usb"]
            if device["class"] == "logic" and device.get("accessible")
        ]
    if domain == "gps":
        return [
            device
            for device in inventory["usb"]
            if device["class"] == "gps" and device.get("accessible")
        ] + [
            item for item in inventory["serial"] if "gps" in item.get("name", "").lower()
        ]
    if domain == "ir":
        return [{"device": path, "name": Path(path).name} for path in inventory["device_nodes"]["lirc"]]
    if device_class is None:
        return []
    return [
        device
        for device in inventory["usb"]
        if device["class"] == device_class and device.get("accessible")
    ]


def _readiness_limitations(tooling_only: list[str], unavailable: list[str]) -> list[str]:
    """State domain-level gaps without implying the tool itself is broken."""
    statements: list[str] = []
    if tooling_only:
        statements.append(
            f"{len(tooling_only)} domain(s) have their tooling installed but no visible device "
            f"({', '.join(tooling_only)}); the host has not passed the hardware through, which is an "
            "exposure gap rather than a tool failure."
        )
    if unavailable:
        statements.append(
            f"{len(unavailable)} domain(s) cannot run because a catalog binary is missing "
            f"({', '.join(unavailable)}); install the integration in the operator-managed image."
        )
    statements.append(
        "Readiness reflects this container's view at call time. A device added or removed afterwards "
        "is not represented here."
    )
    return statements


def hardware_readiness(inventory: dict[str, Any] | None = None) -> dict[str, Any]:
    inventory = inventory or hardware_inventory()
    domains: dict[str, Any] = {}
    ready: list[str] = []
    tooling_only: list[str] = []
    unavailable: list[str] = []
    for name, spec in HARDWARE_DOMAINS.items():
        missing_tools = [tool for tool in spec["tools"] if shutil.which(tool) is None]
        devices = _domain_devices(name, inventory)
        tools_ok = not missing_tools
        devices_ok = bool(devices)
        if tools_ok and devices_ok:
            status = "ready"
            ready.append(name)
        elif tools_ok:
            status = "tooling_ready"
            tooling_only.append(name)
        else:
            status = "unavailable"
            unavailable.append(name)
        domains[name] = {
            "label": spec["label"],
            "status": status,
            "tools": spec["tools"],
            "missing_tools": missing_tools,
            "device_count": len(devices),
            "devices": devices[:20],
            "host_flags": spec["host_flags"],
            "remediation": (
                None
                if status == "ready"
                else "Pass the device through from the host: "
                + " ".join(spec["host_flags"])
            ),
        }
    return {
        "inventory": inventory,
        "domains": domains,
        "ready_domains": ready,
        "tooling_only_domains": tooling_only,
        "unavailable_domains": unavailable,
        "summary": {
            "ready": len(ready),
            "tooling_ready": len(tooling_only),
            "unavailable": len(unavailable),
        },
        "host_flags": sorted(
            {
                flag
                for name in ready + tooling_only
                for flag in HARDWARE_DOMAINS[name]["host_flags"]
            }
        ),
        "note": (
            "ready means the tools are installed and a matching device is visible. "
            "tooling_ready means the tools are installed but the host has not exposed "
            "hardware. unavailable means a catalog binary is missing."
        ),
        "coverage": envelope.coverage("complete", examined=len(domains), total=len(domains), exhausted=True),
        "limitations": _readiness_limitations(tooling_only, unavailable),
    }


# ---------------------------------------------------------------------------
# Deterministic hardware playbooks
# ---------------------------------------------------------------------------


HARDWARE_PLAYBOOKS: dict[str, dict[str, Any]] = {
    "usb": {
        "prerequisites": ["USB bus exposed with --device /dev/bus/usb"],
        "steps": [
            {"tool": "oc_hardware_inventory", "purpose": "Enumerate visible USB devices and classify them"},
            {"tool": "oc_lsusb", "purpose": "Capture the container's view of the USB tree"},
            {"tool": "oc_usbguard", "purpose": "Review device authorization policy when USBGuard is present"},
        ],
    },
    "sdr": {
        "prerequisites": ["USB SDR passed through", "Authorized frequency and power limits"],
        "steps": [
            {"tool": "oc_hardware_readiness", "purpose": "Confirm the SDR is visible before transmitting"},
            {"tool": "oc_hackrf_info", "purpose": "Identify board, firmware, and serial"},
            {"tool": "oc_rtl_test", "purpose": "Verify RTL-SDR tuning and sample rates"},
            {"tool": "oc_hackrf_sweep", "purpose": "Survey the authorized band for activity"},
            {"tool": "oc_hackrf_transfer", "purpose": "Capture IQ samples or replay an authorized signal"},
            {"tool": "oc_rtl_433", "purpose": "Decode sub-GHz sensors and remotes"},
        ],
    },
    "wifi": {
        "prerequisites": [
            "Wireless PHY exposed with --network host",
            "CAP_NET_ADMIN and CAP_NET_RAW",
            "Adapter supports monitor mode and injection",
        ],
        "steps": [
            {"tool": "oc_hardware_readiness", "purpose": "Confirm a wireless interface is visible"},
            {"tool": "oc_iw", "purpose": "Inspect PHY capabilities and interface state"},
            {"tool": "oc_airmon", "purpose": "Create a monitor-mode interface"},
            {"tool": "oc_airodump", "purpose": "Capture authorized frames and handshakes"},
            {"tool": "oc_hcxdumptool", "purpose": "Capture PMKID/EAPOL material where supported"},
            {"tool": "oc_hcxpcapngtool", "purpose": "Convert captures for hashcat"},
            {"tool": "oc_hashcat", "purpose": "Recover keys from captured material"},
        ],
    },
    "bluetooth": {
        "prerequisites": [
            "Bluetooth adapter or Ubertooth exposed",
            "--network host for the host Bluetooth stack",
        ],
        "steps": [
            {"tool": "oc_hardware_readiness", "purpose": "Confirm Bluetooth or Ubertooth hardware"},
            {"tool": "oc_bluetoothctl", "purpose": "Scan and enumerate authorized BLE devices"},
            {"tool": "oc_btmon", "purpose": "Capture HCI traffic for pairing and GATT analysis"},
            {"tool": "oc_ubertooth_scan", "purpose": "Discover classic Bluetooth and BLE devices"},
            {"tool": "oc_ubertooth_rx", "purpose": "Follow an authorized BLE connection"},
        ],
    },
    "nfc": {
        "prerequisites": ["NFC reader or Proxmark3 passed through", "Tags you own or are authorized to test"],
        "steps": [
            {"tool": "oc_hardware_readiness", "purpose": "Confirm the reader or Proxmark3 is visible"},
            {"tool": "oc_nfc_list", "purpose": "List readers and tags"},
            {"tool": "oc_nfc_poll", "purpose": "Capture a tag UID and technology"},
            {"tool": "oc_mfoc", "purpose": "Recover MIFARE Classic keys on authorized tags"},
            {"tool": "oc_proxmark3", "purpose": "Run tag-specific Proxmark3 commands and dumps"},
        ],
    },
    "jtag": {
        "prerequisites": ["Debug probe passed through", "Target powered and wired", "Target voltage confirmed"],
        "steps": [
            {"tool": "oc_hardware_readiness", "purpose": "Confirm the debug probe is visible"},
            {"tool": "oc_openocd", "purpose": "Identify the target and halt the core"},
            {"tool": "oc_urjtag", "purpose": "Detect the JTAG chain when OpenOCD config is unknown"},
            {"tool": "oc_st_info", "purpose": "Read STM32 device information through ST-Link"},
            {"tool": "oc_flashrom", "purpose": "Read or verify external SPI flash"},
            {"tool": "oc_gdb_multiarch", "purpose": "Debug the halted target and inspect memory"},
        ],
    },
    "serial": {
        "prerequisites": ["UART adapter passed through", "Correct voltage and baud rate"],
        "steps": [
            {"tool": "oc_hardware_readiness", "purpose": "Confirm a serial device is visible"},
            {"tool": "oc_serial_open", "purpose": "Open a raw, persisted serial session"},
            {"tool": "oc_serial_read", "purpose": "Capture boot output without losing bytes"},
            {"tool": "oc_serial_write", "purpose": "Send commands and collect the response"},
            {"tool": "oc_serial_close", "purpose": "Release the device and flush the transcript"},
        ],
    },
    "automotive": {
        "prerequisites": ["SocketCAN interface exposed with --network host", "CAP_NET_ADMIN", "Authorized vehicle or bench"],
        "steps": [
            {"tool": "oc_hardware_readiness", "purpose": "Confirm a CAN interface is visible"},
            {"tool": "oc_ip", "purpose": "Bring the interface up at the authorized bitrate"},
            {"tool": "oc_candump", "purpose": "Capture baseline bus traffic"},
            {"tool": "oc_cansniffer", "purpose": "Identify changing frames and payloads"},
            {"tool": "oc_cansend", "purpose": "Send a single authorized frame"},
            {"tool": "oc_isotpsend", "purpose": "Exercise ISO-TP diagnostic services"},
            {"tool": "oc_isotprecv", "purpose": "Capture diagnostic responses"},
        ],
    },
    "logic": {
        "prerequisites": ["Logic analyzer passed through", "sigrok firmware installed", "Target signal levels verified"],
        "steps": [
            {"tool": "oc_hardware_readiness", "purpose": "Confirm the analyzer is visible"},
            {"tool": "oc_sigrok_cli", "purpose": "List devices, capture, and decode a protocol"},
        ],
    },
    "gps": {
        "prerequisites": ["GNSS receiver passed through", "Clear sky view or recorded NMEA"],
        "steps": [
            {"tool": "oc_hardware_readiness", "purpose": "Confirm the receiver is visible"},
            {"tool": "oc_gpsmon", "purpose": "Inspect live fix, satellites, and NMEA"},
            {"tool": "oc_gpspipe", "purpose": "Persist a JSON/NMEA track"},
            {"tool": "oc_gpsfake", "purpose": "Replay NMEA for parser and spoof testing"},
        ],
    },
    "ir": {
        "prerequisites": ["IR receiver/transmitter exposed as /dev/lirc0"],
        "steps": [
            {"tool": "oc_hardware_readiness", "purpose": "Confirm the IR device is visible"},
            {"tool": "oc_lircd", "purpose": "Start the LIRC daemon for authorized capture or transmit"},
        ],
    },
    "firmware": {
        "prerequisites": ["Firmware image copied into the engagement workspace"],
        "steps": [
            {"tool": "oc_firmware_analyze", "purpose": "Hash, identify, entropy-map, and triage the image"},
            {"tool": "oc_binwalk", "purpose": "Scan embedded signatures and filesystems"},
            {"tool": "oc_unblob", "purpose": "Recursively extract the firmware"},
            {"tool": "oc_strings", "purpose": "Extract credentials, paths, and protocol hints"},
            {"tool": "oc_qemu_arm", "purpose": "Emulate an extracted ARM service for analysis"},
            {"tool": "oc_gdb_multiarch", "purpose": "Debug an extracted binary at the target architecture"},
        ],
    },
}


def hardware_plan(domain: str, target: str = "", objective: str = "") -> dict[str, Any]:
    normalized = domain.strip().lower() if isinstance(domain, str) else ""
    if normalized not in HARDWARE_PLAYBOOKS:
        raise OcError(
            "invalid_argument",
            f"unknown hardware domain: {domain}; choose from {sorted(HARDWARE_PLAYBOOKS)}",
            details={"parameter": "domain", "value": domain},
        )
    playbook = HARDWARE_PLAYBOOKS[normalized]
    return {
        "domain": normalized,
        "target": target,
        "objective": objective,
        "prerequisites": list(playbook["prerequisites"]),
        "steps": list(playbook["steps"]),
        "note": (
            "Deterministic plan only. Every step still requires an explicit MCP call, "
            "and transmit/power operations require authorization and local spectrum rules."
        ),
        "coverage": envelope.coverage("complete", exhausted=True),
        "limitations": [
            "This is a deterministic playbook, not a capability check: it installs nothing and verifies "
            "neither tool availability nor device access. Call oc_hardware_readiness first.",
            "The plan names tools and prerequisites only; it does not assert that the target is in scope "
            "or that transmitting is lawful in the current environment.",
        ],
    }


# ---------------------------------------------------------------------------
# Serial sessions
# ---------------------------------------------------------------------------

SERIAL_ID_PATTERN = re.compile(r"ser_\d{8}_[0-9a-f]{32}")
_SERIAL_BUFFER_BYTES = 4_000_000
_SERIAL_WRITE_BYTES = 65536
_BAUD_RATES = {
    300, 600, 1200, 2400, 4800, 9600, 14400, 19200, 28800, 38400, 57600,
    115200, 230400, 460800, 500000, 576000, 921600, 1000000, 1152000,
    1500000, 2000000, 2500000, 3000000, 3500000, 4000000,
}
_ALLOWED_DEVICE_PREFIXES = (
    "/dev/ttyUSB",
    "/dev/ttyACM",
    "/dev/ttyAMA",
    "/dev/ttyS",
    "/dev/ttyO",
    "/dev/ttyPS",
    "/dev/ttyGS",
    "/dev/ttyHS",
    "/dev/ttySC",
    "/dev/ttyTHS",
    "/dev/ttyRPMSG",
    "/dev/serial/",
    "/dev/rfcomm",
    "/dev/lirc",
)
_SERIAL_LOCK = threading.Lock()
_SERIAL_SESSIONS: dict[str, "SerialSession"] = {}


def _validate_device(device: str) -> Path:
    if not isinstance(device, str) or not device:
        raise OcError("invalid_argument", "device must be a non-empty path such as /dev/ttyUSB0",
                      details={"parameter": "device"})
    candidate = Path(device)
    try:
        resolved = Path(os.path.realpath(candidate))
    except OSError as exc:
        raise OcError("invalid_argument", f"cannot resolve device path: {device}",
                      details={"parameter": "device"}) from exc
    allowed = any(str(resolved).startswith(prefix) for prefix in _ALLOWED_DEVICE_PREFIXES)
    if not allowed and os.environ.get("OPENCYBER_ALLOW_PTY") == "1":
        allowed = str(resolved).startswith("/dev/pts/")
    if not allowed:
        raise OcError(
            "invalid_argument",
            "device must be a serial, RFCOMM, LIRC, or PTY path under /dev; "
            "block devices and memory devices are not allowed",
            details={"parameter": "device", "value": device},
        )
    if not resolved.exists():
        raise OcError(
            "not_found",
            f"device does not exist inside the container: {resolved}",
            details={"parameter": "device", "device": str(resolved)},
        )
    try:
        mode = resolved.stat().st_mode
    except OSError as exc:
        raise OcError("not_found", f"cannot stat device: {resolved}",
                      details={"device": str(resolved)}) from exc
    if not stat.S_ISCHR(mode):
        raise OcError("invalid_argument", f"not a character device: {resolved}",
                      details={"device": str(resolved)})
    return resolved


def _serial_transcript_path(engagement_id: str, session_id: str) -> Path:
    path = resolve_engagement_path(
        engagement_id, f"hardware/serial/{session_id}.jsonl", must_exist=False
    )
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


class SerialSession:
    """One raw, non-blocking serial session with a persisted transcript."""

    def __init__(
        self,
        engagement_id: str,
        device: Path,
        baudrate: int,
        bytesize: int,
        parity: str,
        stopbits: int,
    ) -> None:
        import termios

        if baudrate not in _BAUD_RATES:
            raise OcError("invalid_argument", f"unsupported baudrate: {baudrate}",
                          details={"parameter": "baudrate", "value": baudrate})
        if bytesize not in {5, 6, 7, 8}:
            raise OcError("invalid_argument", "bytesize must be 5, 6, 7, or 8",
                          details={"parameter": "bytesize", "value": bytesize})
        if parity not in {"none", "even", "odd"}:
            raise OcError("invalid_argument", "parity must be none, even, or odd",
                          details={"parameter": "parity", "value": parity})
        if stopbits not in {1, 2}:
            raise OcError("invalid_argument", "stopbits must be 1 or 2",
                          details={"parameter": "stopbits", "value": stopbits})

        self.engagement_id = engagement_id
        self.device = str(device)
        self.baudrate = baudrate
        self.bytesize = bytesize
        self.parity = parity
        self.stopbits = stopbits
        self.date = datetime.now(timezone.utc).strftime("%Y%m%d")
        self.session_id = f"ser_{self.date}_{uuid.uuid4().hex}"
        self.created_at = _now()
        self._lock = threading.Lock()
        self._buffer = bytearray()
        self.buffer_truncated = False
        self._transcript = _serial_transcript_path(engagement_id, self.session_id)
        self._fd = os.open(
            str(device),
            os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            attributes = termios.tcgetattr(self._fd)
            self._saved = [*attributes[:6], list(attributes[6])]
            speed = getattr(termios, f"B{baudrate}")
            size = getattr(termios, f"CS{bytesize}")
            control = termios.CREAD | termios.CLOCAL | size
            if parity == "even":
                control |= termios.PARENB
            elif parity == "odd":
                control |= termios.PARENB | termios.PARODD
            if stopbits == 2:
                control |= termios.CSTOPB
            attributes[0] = 0
            attributes[1] = 0
            attributes[2] = control
            attributes[3] = 0
            attributes[4] = speed
            attributes[5] = speed
            attributes[6] = list(attributes[6])
            attributes[6][termios.VMIN] = 0
            attributes[6][termios.VTIME] = 0
            termios.tcsetattr(self._fd, termios.TCSANOW, attributes)
            termios.tcflush(self._fd, termios.TCIOFLUSH)
        except Exception:
            os.close(self._fd)
            raise
        self._record("open", {"baudrate": baudrate, "device": str(device)})

    def info(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "engagement_id": self.engagement_id,
            "device": self.device,
            "baudrate": self.baudrate,
            "bytesize": self.bytesize,
            "parity": self.parity,
            "stopbits": self.stopbits,
            "created_at": self.created_at,
            "buffered_bytes": len(self._buffer),
            "transcript": str(self._transcript),
        }

    def _record(self, direction: str, payload: dict[str, Any]) -> None:
        record = {
            "ts": _now(),
            "session_id": self.session_id,
            "direction": direction,
            **payload,
        }
        try:
            with self._transcript.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, sort_keys=True) + "\n")
        except OSError:
            pass

    def read(self, max_bytes: int = 4096, timeout: float = 1.0) -> dict[str, Any]:
        if isinstance(max_bytes, bool) or not isinstance(max_bytes, int) or max_bytes < 1:
            raise OcError("invalid_argument", "max_bytes must be between 1 and 65536",
                          details={"parameter": "max_bytes", "value": max_bytes})
        if max_bytes > 65536:
            raise limits.raise_exceeded(
                "serial.read_max_bytes",
                "max_bytes must be between 1 and 65536",
                effective=65536,
                requested=max_bytes,
                parameter="max_bytes",
            )
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout < 0:
            raise OcError("invalid_argument", "timeout must be between 0 and 30 seconds",
                          details={"parameter": "timeout", "value": timeout})
        if timeout > 30:
            raise limits.raise_exceeded(
                "serial.read_timeout",
                "timeout must be between 0 and 30 seconds",
                effective=30,
                requested=timeout,
                parameter="timeout",
            )
        with self._lock:
            ready, _, _ = select.select([self._fd], [], [], timeout)
            if not ready:
                return {
                    "session_id": self.session_id,
                    "bytes": 0,
                    "data": "",
                    "hex": "",
                    "timed_out": True,
                    "buffered_bytes": len(self._buffer),
                    "buffer_truncated": self.buffer_truncated,
                    "coverage": envelope.coverage("unknown", examined=0, exhausted=False),
                    "limitations": [
                        "The read timed out without returning bytes; the device buffer may still hold data. "
                        "An empty read is not evidence that the device sent nothing.",
                        f"Only a {timeout:g}s window was observed; poll again or pass a larger timeout "
                        "to keep listening.",
                    ],
                    "limit": limits.facts("serial.read_timeout", effective=timeout, parameter="timeout"),
                }
            try:
                chunk = os.read(self._fd, max_bytes)
            except BlockingIOError:
                chunk = b""
            self._buffer.extend(chunk)
            if len(self._buffer) > _SERIAL_BUFFER_BYTES:
                del self._buffer[: len(self._buffer) - _SERIAL_BUFFER_BYTES]
                self.buffer_truncated = True
            text = chunk.decode("utf-8", errors="replace")
            exhausted = len(chunk) < max_bytes
            limitations: list[str] = []
            limit: dict[str, Any] | None = None
            if not exhausted:
                limitations.append(
                    f"The read filled the {max_bytes}-byte cap exactly; more bytes may remain unread in the "
                    "device buffer and must be fetched with another read."
                )
                limit = limits.facts("serial.read_max_bytes", effective=max_bytes, parameter="max_bytes")
            if self.buffer_truncated:
                limitations.append(
                    f"The session's retained buffer exceeded its {_SERIAL_BUFFER_BYTES}-byte cap and the "
                    "oldest buffered bytes were discarded; buffered_bytes is a lower bound, though the "
                    "transcript still records every received chunk."
                )
            payload = {
                "session_id": self.session_id,
                "bytes": len(chunk),
                "data": text,
                "hex": chunk.hex(),
                "timed_out": False,
                "buffered_bytes": len(self._buffer),
                "buffer_truncated": self.buffer_truncated,
                "coverage": envelope.coverage(
                    "complete" if exhausted and not self.buffer_truncated else "partial",
                    examined=len(chunk),
                    exhausted=exhausted,
                ),
                "limitations": limitations,
            }
            if limit is not None:
                payload["limit"] = limit
            if chunk:
                self._record("rx", {"bytes": len(chunk), "hex": chunk.hex(), "data": text})
            return payload

    def write(self, data: str = "", hex_data: str = "") -> dict[str, Any]:
        if data and hex_data:
            raise OcError("invalid_argument", "provide either data or hex_data, not both")
        if hex_data:
            try:
                payload = bytes.fromhex(hex_data)
            except ValueError as exc:
                raise OcError("invalid_argument", "hex_data must be valid hexadecimal",
                              details={"parameter": "hex_data"}) from exc
        else:
            payload = data.encode("utf-8")
        if not payload:
            raise OcError("invalid_argument", "nothing to write")
        if len(payload) > _SERIAL_WRITE_BYTES:
            raise OcError(
                "limit_exceeded",
                "write is limited to 65536 bytes per call",
                details={"max_bytes": _SERIAL_WRITE_BYTES, "requested": len(payload)},
            )
        written = 0
        deadline = time.monotonic() + 5.0
        with self._lock:
            while written < len(payload):
                try:
                    count = os.write(self._fd, payload[written:])
                except BlockingIOError:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise OcError(
                            "timed_out",
                            f"serial write timed out after {written} of {len(payload)} bytes",
                            details={"written_bytes": written, "requested_bytes": len(payload)},
                        )
                    select.select([], [self._fd], [], remaining)
                    continue
                if count <= 0:
                    break
                written += count
        self._record("tx", {"bytes": written, "hex": payload.hex(), "data": payload.decode("utf-8", errors="replace")})
        complete = written == len(payload)
        result: dict[str, Any] = {
            "session_id": self.session_id,
            "bytes": written,
            "hex": payload.hex(),
            "buffered_bytes": len(self._buffer),
            "coverage": envelope.coverage("complete" if complete else "partial",
                                          examined=written, total=len(payload), exhausted=complete),
            "limitations": [
                "A successful write only means the kernel accepted the bytes; it does not prove the device "
                "received or acted on them."
            ],
        }
        if not complete:
            result["limitations"].append(
                f"Only {written} of {len(payload)} bytes were written; the remainder was not transmitted."
            )
        return result

    def close(self) -> dict[str, Any]:
        import termios

        with self._lock:
            if self._fd >= 0:
                try:
                    termios.tcsetattr(self._fd, termios.TCSANOW, self._saved)
                except Exception:
                    pass
                os.close(self._fd)
                self._fd = -1
        self._record("close", {})
        return {
            "session_id": self.session_id,
            "device": self.device,
            "closed": True,
            "transcript": str(self._transcript),
            "coverage": envelope.coverage("complete", exhausted=True),
            "limitations": [
                "Restoring the saved terminal attributes and appending the final transcript record are "
                "best effort; a failure is not surfaced by this call.",
                "Collected bytes are described by the transcript file, which is not hashed or signed here.",
            ],
        }


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def serial_open(
    engagement_id: str,
    device: str,
    baudrate: int = 115200,
    bytesize: int = 8,
    parity: str = "none",
    stopbits: int = 1,
) -> dict[str, Any]:
    path = _validate_device(device)
    session = SerialSession(engagement_id, path, baudrate, bytesize, parity, stopbits)
    with _SERIAL_LOCK:
        _SERIAL_SESSIONS[session.session_id] = session
    safe_record(
        engagement_id,
        {
            "event": "hardware.serial_open",
            "session_id": session.session_id,
            "device": str(path),
            "baudrate": baudrate,
            "bytesize": bytesize,
            "parity": parity,
            "stopbits": stopbits,
        },
    )
    payload = session.info()
    payload["coverage"] = envelope.coverage("complete", exhausted=True)
    payload["limitations"] = [
        "The session is owned by this server process: it is not usable after a restart and is not "
        "visible to other processes.",
        "Pending device input was discarded when the session opened (TCIOFLUSH); bytes the device sent "
        "before this call are not in the transcript.",
        "Transcript appends are best effort; a failed write is not reported by this tool.",
    ]
    return payload


def _get_serial_session(engagement_id: str, session_id: str) -> SerialSession:
    if not isinstance(session_id, str) or not SERIAL_ID_PATTERN.fullmatch(session_id):
        raise OcError(
            "invalid_argument",
            "session_id must be a server-generated serial session identifier",
            details={"parameter": "session_id"},
        )
    with _SERIAL_LOCK:
        session = _SERIAL_SESSIONS.get(session_id)
    if session is None or session.engagement_id != engagement_id:
        raise OcError(
            "not_found",
            f"unknown serial session: {session_id}",
            details={"session_id": session_id, "engagement_id": engagement_id},
        )
    return session


def serial_read(
    engagement_id: str, session_id: str, max_bytes: int = 4096, timeout: float = 1.0
) -> dict[str, Any]:
    return _get_serial_session(engagement_id, session_id).read(max_bytes, timeout)


def serial_write(
    engagement_id: str, session_id: str, data: str = "", hex_data: str = ""
) -> dict[str, Any]:
    return _get_serial_session(engagement_id, session_id).write(data, hex_data)


def serial_close(engagement_id: str, session_id: str) -> dict[str, Any]:
    session = _get_serial_session(engagement_id, session_id)
    result = session.close()
    with _SERIAL_LOCK:
        _SERIAL_SESSIONS.pop(session_id, None)
    safe_record(
        engagement_id,
        {
            "event": "hardware.serial_close",
            "session_id": session_id,
            "device": result["device"],
            "transcript": result["transcript"],
        },
    )
    return result


def serial_list(engagement_id: str) -> dict[str, Any]:
    with _SERIAL_LOCK:
        sessions = [
            session.info()
            for session in _SERIAL_SESSIONS.values()
            if session.engagement_id == engagement_id
        ]
    sessions.sort(key=lambda item: item["created_at"], reverse=True)
    return {
        "engagement_id": engagement_id,
        "sessions": sessions,
        "coverage": envelope.coverage("complete", exhausted=True),
        "limitations": [
            "Only sessions owned by this server process are listed; a session from another process or a "
            "previous server run is not visible and is not evidence that no device is attached."
        ],
    }


# ---------------------------------------------------------------------------
# Firmware triage
# ---------------------------------------------------------------------------

FIRMWARE_MAGIC: tuple[tuple[bytes, str], ...] = (
    (b"\x7fELF", "ELF executable"),
    (b"MZ", "PE/COFF executable"),
    (b"\xfe\xed\xfa\xce", "Mach-O 32-bit big-endian"),
    (b"\xfe\xed\xfa\xcf", "Mach-O 64-bit big-endian"),
    (b"\xce\xfa\xed\xfe", "Mach-O 32-bit little-endian"),
    (b"\xcf\xfa\xed\xfe", "Mach-O 64-bit little-endian"),
    (b"hsqs", "SquashFS filesystem"),
    (b"sqsh", "SquashFS filesystem (big-endian)"),
    (b"\x45\x3d\xcd\x28", "CramFS filesystem (little-endian)"),
    (b"\x28\xcd\x3d\x45", "CramFS filesystem (big-endian)"),
    (b"\x85\x19", "JFFS2 filesystem"),
    (b"\x31\x18\x10\x06", "UBIFS filesystem"),
    (b"\x1f\x8b", "gzip stream"),
    (b"\xfd7zXZ\x00", "xz stream"),
    (b"\x28\xb5\x2f\xfd", "zstd stream"),
    (b"BZh", "bzip2 stream"),
    (b"\x04\x22\x4d\x18", "LZ4 frame"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    (b"PK\x03\x04", "ZIP archive"),
    (b"\xd0\x0d\xfe\xed", "Android boot image"),
    (b"ANDROID!", "Android boot image"),
    (b"UBI#", "UBI image"),
    (b"U-Boot", "U-Boot image"),
    (b"\x27\x05\x19\x56", "uImage"),
    (b"\x00\x00\x00\x00\x00\x00\x00\x00", "zero-filled region"),
)

ELF_MACHINES = {
    3: "x86",
    8: "MIPS",
    20: "PowerPC",
    40: "ARM",
    42: "SuperH",
    50: "IA-64",
    62: "x86-64",
    183: "AArch64",
    243: "RISC-V",
}

PE_MACHINES = {
    0x014C: "x86",
    0x8664: "x86-64",
    0x01C0: "ARM",
    0x01C4: "ARMv7",
    0xAA64: "AArch64",
}

INTERESTING_STRINGS = re.compile(
    r"(?i)(password|passwd|secret|token|api[_-]?key|private[_-]?key|"
    r"telnet|ssh|uart|console|admin|root|wifi|wpa|psk|factory|debug|"
    r"http://|https://|/bin/|/etc/|/tmp/)"
)


def _shannon(data: bytes) -> float:
    if not data:
        return 0.0
    counts: dict[int, int] = {}
    for byte in data:
        counts[byte] = counts.get(byte, 0) + 1
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counts.values())


def _firmware_identity(head: bytes, size: int) -> dict[str, Any]:
    identity: dict[str, Any] = {
        "magic": None,
        "format": "unknown",
        "architecture": None,
        "endianness": None,
        "size": size,
        "sha256": None,
    }
    for magic, label in FIRMWARE_MAGIC:
        if head.startswith(magic):
            identity["magic"] = magic.hex()
            identity["format"] = label
            break
    if head.startswith(b"\x7fELF") and len(head) >= 20:
        identity["format"] = "ELF executable"
        identity["endianness"] = "little" if head[5] == 1 else "big"
        machine = int.from_bytes(head[18:20], "little" if head[5] == 1 else "big")
        identity["architecture"] = ELF_MACHINES.get(machine, f"machine-{machine}")
        identity["elf_type"] = {1: "relocatable", 2: "executable", 3: "shared", 4: "core"}.get(
            int.from_bytes(head[16:18], "little" if head[5] == 1 else "big"), "unknown"
        )
    elif head.startswith(b"MZ") and len(head) >= 0x40:
        offset = int.from_bytes(head[0x3C:0x40], "little")
        if offset + 6 <= len(head) and head[offset : offset + 4] == b"PE\x00\x00":
            machine = int.from_bytes(head[offset + 4 : offset + 6], "little")
            identity["format"] = "PE/COFF executable"
            identity["architecture"] = PE_MACHINES.get(machine, f"machine-{machine}")
    elif head.startswith(b"\x1f\x8b"):
        identity["format"] = "gzip-compressed data"
    elif len(head) > 2 and head[:1] == b":" and all(
        32 <= byte < 127 or byte in (10, 13) for byte in head[:64]
    ):
        identity["format"] = "Intel HEX firmware"
    elif head.startswith(b"S0") or head.startswith(b"S1") or head.startswith(b"S2"):
        identity["format"] = "Motorola S-record firmware"
    elif head.startswith(b"#!") and b"sh" in head[:64]:
        identity["format"] = "shell script"
    return identity


def _run_command(argv: list[str], timeout: float = 120.0) -> dict[str, Any]:
    try:
        result = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return {"command": argv, "error": str(exc), "stdout": "", "stderr": ""}
    return {
        "command": argv,
        "returncode": result.returncode,
        "stdout": result.stdout,
        "stderr": result.stderr,
    }


def analyze_firmware(
    engagement_id: str,
    path: str,
    run_binwalk: bool = True,
    max_entropy_bytes: int = 64 * 1024 * 1024,
) -> dict[str, Any]:
    target = resolve_engagement_path(engagement_id, path)
    if not target.is_file():
        raise OcError("not_found", f"not a file: {target}", details={"path": path})
    size = target.stat().st_size
    if size == 0:
        raise OcError("invalid_argument", "firmware image is empty", details={"path": path})
    limit = max(4096, min(int(max_entropy_bytes), 512 * 1024 * 1024))

    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    md5 = hashlib.md5()
    head = b""
    entropy_blocks: list[tuple[int, float]] = []
    string_count = 0
    interesting: list[str] = []
    seen_strings: set[str] = set()
    read_total = 0
    block_size = 4096
    pending = b""
    with target.open("rb") as handle:
        while True:
            chunk = handle.read(1024 * 1024)
            if not chunk:
                break
            sha256.update(chunk)
            sha1.update(chunk)
            md5.update(chunk)
            if len(head) < 4096:
                head += chunk[: 4096 - len(head)]
            if read_total < limit:
                window = min(len(chunk), limit - read_total)
                pending += chunk[:window]
                read_total += window
                while len(pending) >= block_size:
                    block, pending = pending[:block_size], pending[block_size:]
                    entropy_blocks.append((len(entropy_blocks) * block_size, _shannon(block)))
                for match in re.finditer(rb"[ -~]{6,}", chunk[:window]):
                    string_count += 1
                    if len(interesting) >= 200:
                        continue
                    text = match.group(0).decode("utf-8", errors="replace")
                    if text in seen_strings or not _interesting_string(text):
                        continue
                    seen_strings.add(text)
                    interesting.append(text[:300])
    if pending:
        entropy_blocks.append((len(entropy_blocks) * block_size, _shannon(pending)))

    identity = _firmware_identity(head, size)
    identity.update(
        {
            "sha256": sha256.hexdigest(),
            "sha1": sha1.hexdigest(),
            "md5": md5.hexdigest(),
        }
    )
    entropies = [value for _, value in entropy_blocks]
    high_entropy = sorted(entropy_blocks, key=lambda item: item[1], reverse=True)[:8]
    low_entropy = sorted(entropy_blocks, key=lambda item: item[1])[:8]
    report: dict[str, Any] = {
        "engagement_id": engagement_id,
        "path": path,
        "identity": identity,
        "entropy": {
            "blocks": len(entropy_blocks),
            "block_size": block_size,
            "min": round(min(entropies), 4) if entropies else None,
            "max": round(max(entropies), 4) if entropies else None,
            "mean": round(sum(entropies) / len(entropies), 4) if entropies else None,
            "high_blocks": [
                {"offset": offset, "entropy": round(value, 4)} for offset, value in high_entropy
            ],
            "low_blocks": [
                {"offset": offset, "entropy": round(value, 4)} for offset, value in low_entropy
            ],
            "truncated": size > limit,
        },
        "strings": {"count": string_count, "interesting": interesting},
        "review_items": [],
        "artifacts": [],
    }
    if identity["format"] == "unknown":
        report["review_items"].append(
            "No known container magic matched; run oc_binwalk or oc_unblob for signature-level analysis."
        )
    if entropies and max(entropies) > 7.5:
        report["review_items"].append(
            "High-entropy regions detected; likely compressed or encrypted content. Extract before concluding."
        )
    if interesting:
        report["review_items"].append(
            "Interesting strings were found. Treat credentials, keys, and debug paths as leads requiring confirmation."
        )
    binwalk_complete = False
    if run_binwalk:
        report["binwalk"] = _run_command(["binwalk", "-B", "-q", str(target)])
        binwalk_failed = bool(report["binwalk"].get("error")) or report["binwalk"].get("returncode") not in (0, None)
        binwalk_complete = not binwalk_failed
        if binwalk_failed and not report["binwalk"].get("error"):
            report["review_items"].append("binwalk returned a non-zero status; inspect stderr.")

    limitations = [
        "Analysis covers hashing, magic identification, entropy, printable strings, and optional binwalk "
        "signatures only; the image was never extracted, disassembled, or executed.",
        "Format and architecture are inferred from leading magic and header fields; a crafted or "
        "compressed header can make that identification wrong.",
    ]
    entropy_truncated = size > limit
    if entropy_truncated:
        limitations.append(
            f"Entropy and string analysis covered the first {limit} of {size} bytes; the remaining "
            f"{size - limit} bytes are uninspected and their entropy is unknown."
        )
    if run_binwalk:
        if not binwalk_complete:
            limitations.append(
                "binwalk did not complete successfully; embedded filesystems and compressed regions were "
                "not enumerated and signatures may be missing."
            )
    else:
        limitations.append(
            "Signature analysis (binwalk) was not requested; embedded filesystems and compressed regions "
            "were not enumerated."
        )
    format_known = identity["format"] != "unknown"
    if not format_known:
        limitations.append(
            "No known container magic matched; the image's structure is unidentified and unparsed."
        )
    complete = format_known and not entropy_truncated and (binwalk_complete if run_binwalk else False)
    report["coverage"] = envelope.coverage(
        "unknown" if not format_known else ("complete" if complete else "partial"),
        examined=min(size, limit),
        total=size,
        exhausted=complete,
    )
    report["limitations"] = limitations

    report_path = resolve_engagement_path(
        engagement_id, f"artifacts/firmware/{target.stem}.report.json", must_exist=False
    )
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    report["artifact_path"] = str(report_path.relative_to(Path(resolve_engagement_path(engagement_id, "."))))
    report["artifacts"].append(report["artifact_path"])
    safe_record(
        engagement_id,
        {
            "event": "hardware.firmware_analyze",
            "path": path,
            "sha256": identity["sha256"],
            "format": identity["format"],
            "architecture": identity["architecture"],
            "artifact_path": report["artifact_path"],
        },
    )
    return report


def _interesting_string(text: str) -> bool:
    return bool(INTERESTING_STRINGS.search(text))


def main() -> None:
    """CLI for host-side hardware diagnosis without an MCP client."""
    import argparse

    parser = argparse.ArgumentParser(
        prog="opencyber-hardware",
        description="Inspect hardware visibility and per-domain readiness.",
    )
    parser.add_argument("--inventory", action="store_true", help="emit the full inventory")
    parser.add_argument("--readiness", action="store_true", help="emit domain readiness (default)")
    parser.add_argument("--plan", metavar="DOMAIN", help="emit a deterministic hardware playbook")
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args()

    if args.plan:
        try:
            payload: Any = hardware_plan(args.plan)
        except ValueError as exc:
            parser.error(str(exc))
    elif args.inventory:
        payload = hardware_inventory()
    else:
        payload = hardware_readiness()

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
        return

    if args.plan:
        print(f"hardware plan: {payload['domain']}")
        for step in payload["steps"]:
            print(f"  {step['tool']:<24} {step['purpose']}")
        return
    if args.inventory:
        print("hardware inventory")
        for key in ("platform", "capabilities", "summary", "access"):
            print(f"  {key:<14} {payload[key]}")
        for device in payload["known_devices"]:
            print(
                f"  {device['class']:<10} {device['label']} "
                f"[{device['vendor_id']}:{device['product_id']}] "
                f"accessible={device['accessible']}"
            )
        return

    print("opencyber-hardware")
    for name, domain in payload["domains"].items():
        print(
            f"  {name:<12} {domain['status']:<15} "
            f"{domain['device_count']} device(s)"
            + (f"  missing: {', '.join(domain['missing_tools'])}" if domain["missing_tools"] else "")
        )
    print("host flags")
    for flag in payload["host_flags"]:
        print(f"  {flag}")


if __name__ == "__main__":
    main()
