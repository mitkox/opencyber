"""Declarative catalog of executable-backed security tools."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import re
import shutil
from typing import Any, Iterable


@dataclass(frozen=True, slots=True)
class ToolSpec:
    name: str
    executable: str
    category: str
    description: str
    required: bool = True
    optional_reason: str = ""
    dependencies: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)

    def availability(self) -> dict[str, Any]:
        path = shutil.which(self.executable)
        missing = [name for name in self.dependencies if shutil.which(name) is None]
        return {"available": path is not None and not missing, "path": path,
                "missing_dependencies": missing, "required": self.required,
                "optional_reason": self.optional_reason}


# Keep adapters for tools excluded by the maintenance or vulnerability policy.
OPTIONAL_INTEGRATIONS: dict[str, tuple[str, tuple[str, ...]]] = {
    "terrascan": ("Upstream is archived and no longer maintained.", ()),
    "scout": ("ScoutSuite's sqlitedict dependency has unresolved CVE-2024-35515, rated critical by CISA-ADP.", ()),
}

TOOL_DEPENDENCIES: dict[str, tuple[str, ...]] = {
    "rustscan": ("nmap",),
    "autorecon": ("nmap",),
    "msfconsole": ("nmap",),
    "msfvenom": ("nmap",),
    "nxc": ("nmap",),
}


# This inventory describes capabilities, not a tool's CLI surface. Each entry
# becomes one MCP tool with the shared, explicit argv schema defined by
# opencyber.server.
TOOL_GROUPS: dict[str, tuple[tuple[str, str], ...]] = {
    "network": (
        ("nmap", "nmap"),
        ("rustscan", "rustscan"),
        ("masscan", "masscan"),
        ("autorecon", "autorecon"),
        ("arp_scan", "arp-scan"),
        ("netbios_scan", "nbtscan"),
        ("packet_capture", "tcpdump"),
        ("packet_analysis", "tshark"),
        ("network_mapper", "netdiscover"),
        ("socat", "socat"),
        ("ip", "ip"),
    ),
    "enumeration": (
        ("amass", "amass"),
        ("subfinder", "subfinder"),
        ("fierce", "fierce"),
        ("dnsenum", "dnsenum"),
        ("theharvester", "theHarvester"),
        ("enum4linux", "enum4linux"),
        ("enum4linux_ng", "enum4linux-ng"),
        ("rpcclient", "rpcclient"),
        ("smbmap", "smbmap"),
        ("netexec", "nxc"),
        ("responder", "responder"),
        ("recon_ng", "recon-ng"),
        ("spiderfoot", "spiderfoot"),
        ("sherlock", "sherlock"),
        ("shodan", "shodan"),
        ("censys", "censys"),
    ),
    "web": (
        ("gobuster", "gobuster"),
        ("ffuf", "ffuf"),
        ("feroxbuster", "feroxbuster"),
        ("dirb", "dirb"),
        ("dirsearch", "dirsearch"),
        ("nikto", "nikto"),
        ("nuclei", "nuclei"),
        ("sqlmap", "sqlmap"),
        ("whatweb", "whatweb"),
        ("wpscan", "wpscan"),
        ("wfuzz", "wfuzz"),
        ("xsser", "xsser"),
        ("dotdotpwn", "dotdotpwn"),
        ("katana", "katana"),
        ("hakrawler", "hakrawler"),
        ("gau", "gau"),
        ("urlfinder", "urlfinder"),
        ("arjun", "arjun"),
        ("paramspider", "paramspider"),
        ("x8", "x8"),
        ("jaeles", "jaeles"),
        ("dalfox", "dalfox"),
        ("httpx", "httpx"),
        ("anew", "anew"),
        ("qsreplace", "qsreplace"),
        ("uro", "uro"),
        ("wafw00f", "wafw00f"),
        ("zap", "zaproxy"),
        ("subzy", "subzy"),
        ("curl", "curl"),
        ("httpie", "http"),
    ),
    "credentials": (
        ("hydra", "hydra"),
        ("medusa", "medusa"),
        ("patator", "patator"),
        ("john", "john"),
        ("hashcat", "hashcat"),
        ("hash_identifier", "hash-identifier"),
        ("ophcrack", "ophcrack"),
        ("evil_winrm", "evil-winrm"),
    ),
    "exploitation": (
        ("metasploit", "msfconsole"),
        ("msfvenom", "msfvenom"),
        ("exploit_search", "searchsploit"),
    ),
    "binary": (
        ("gdb", "gdb"),
        ("radare2", "radare2"),
        ("ghidra", "ghidra"),
        ("binwalk", "binwalk"),
        ("ropgadget", "ROPgadget"),
        ("ropper", "ropper"),
        ("checksec", "checksec"),
        ("objdump", "objdump"),
        ("strings", "strings"),
        ("xxd", "xxd"),
        ("file", "file"),
        ("one_gadget", "one_gadget"),
        ("pwninit", "pwninit"),
        ("pwntools", "pwn"),
    ),
    "forensics": (
        ("volatility", "vol"),
        ("foremost", "foremost"),
        ("steghide", "steghide"),
        ("exiftool", "exiftool"),
        ("testdisk", "testdisk"),
        ("scalpel", "scalpel"),
        ("bulk_extractor", "bulk_extractor"),
        ("zsteg", "zsteg"),
        ("hashpump", "hashpump"),
        ("sleuthkit_fls", "fls"),
        ("sleuthkit_icat", "icat"),
    ),
    "cloud_container_iac": (
        ("prowler", "prowler"),
        ("scout_suite", "scout"),
        ("trivy", "trivy"),
        ("kube_hunter", "kube-hunter"),
        ("kube_bench", "kube-bench"),
        ("docker_bench", "docker-bench-security"),
        ("checkov", "checkov"),
        ("terrascan", "terrascan"),
    ),
    "wireless": (
        ("aircrack", "aircrack-ng"),
        ("airmon", "airmon-ng"),
        ("airodump", "airodump-ng"),
        ("aireplay", "aireplay-ng"),
        ("kismet", "kismet"),
    ),
    # Physical-layer tools. These require host device passthrough (USB, serial,
    # wireless PHY, CAN, GPIO) and are reported separately by the hardware
    # inventory instead of being assumed present just because the binary is.
    "rf": (
        ("hackrf_info", "hackrf_info"),
        ("hackrf_transfer", "hackrf_transfer"),
        ("hackrf_sweep", "hackrf_sweep"),
        ("rtl_sdr", "rtl_sdr"),
        ("rtl_test", "rtl_test"),
        ("rtl_power", "rtl_power"),
        ("rtl_433", "rtl_433"),
        ("soapy_sdr", "SoapySDRUtil"),
        ("limesdr", "LimeUtil"),
        ("bladerf", "bladeRF-cli"),
        ("ubertooth_util", "ubertooth-util"),
        ("ubertooth_rx", "ubertooth-rx"),
        ("ubertooth_scan", "ubertooth-scan"),
    ),
    "wireless_attack": (
        ("iw", "iw"),
        ("iwconfig", "iwconfig"),
        ("wifite", "wifite"),
        ("hcxdumptool", "hcxdumptool"),
        ("hcxpcapngtool", "hcxpcapngtool"),
        ("reaver", "reaver"),
        ("bully", "bully"),
        ("pixiewps", "pixiewps"),
        ("mdk4", "mdk4"),
        ("cowpatty", "cowpatty"),
        ("bettercap", "bettercap"),
        ("bluetoothctl", "bluetoothctl"),
        ("btmon", "btmon"),
        ("hcitool", "hcitool"),
        ("btmgmt", "btmgmt"),
    ),
    "nfc_rfid": (
        ("proxmark3", "proxmark3"),
        ("nfc_list", "nfc-list"),
        ("nfc_poll", "nfc-poll"),
        ("nfc_mfclassic", "nfc-mfclassic"),
        ("mfoc", "mfoc"),
        ("mfcuk", "mfcuk"),
        ("pcsc_scan", "pcsc_scan"),
    ),
    "usb": (
        ("lsusb", "lsusb"),
        ("usbguard", "usbguard"),
    ),
    "embedded": (
        ("openocd", "openocd"),
        ("urjtag", "jtag"),
        ("avrdude", "avrdude"),
        ("dfu_util", "dfu-util"),
        ("esptool", "esptool"),
        ("st_info", "st-info"),
        ("st_flash", "st-flash"),
        ("minicom", "minicom"),
        ("picocom", "picocom"),
        ("screen", "screen"),
        ("flashrom", "flashrom"),
        ("sigrok_cli", "sigrok-cli"),
        ("qemu_arm", "qemu-arm"),
        ("qemu_system_arm", "qemu-system-arm"),
        ("gdb_multiarch", "gdb-multiarch"),
        ("unblob", "unblob"),
    ),
    "automotive": (
        ("candump", "candump"),
        ("cansend", "cansend"),
        ("cansniffer", "cansniffer"),
        ("canbusload", "canbusload"),
        ("isotpsend", "isotpsend"),
        ("isotprecv", "isotprecv"),
    ),
    "gps": (
        ("gpsmon", "gpsmon"),
        ("gpspipe", "gpspipe"),
        ("gpsfake", "gpsfake"),
    ),
    "ir": (
        ("lircd", "lircd"),
    ),
    "mobile": (
        ("apktool", "apktool"),
        ("jadx", "jadx"),
    ),
    "utilities": (
        ("grep", "grep"),
        ("jq", "jq"),
    ),
}

# Categories that represent physical-layer work. They are still ordinary
# executable-backed MCP tools, but the doctor and the hardware inventory report
# device readiness separately from binary presence.
HARDWARE_CATEGORIES = frozenset(
    {"rf", "wireless_attack", "nfc_rfid", "usb", "embedded", "automotive", "gps", "ir"}
)


SPECIAL_DESCRIPTIONS = {
    "grep": (
        "Search text files inside the selected engagement with GNU grep. "
        "Prefer oc_jq for structured JSON and oc_python for custom parsing."
    ),
    "jq": (
        "Parse, query, transform, and validate JSON inside the selected engagement with jq. "
        "Use this instead of brittle regular expressions for JSON and OpenAPI documents."
    ),
    "ip": (
        "Inspect and configure network interfaces, addresses, routes, and SocketCAN links. "
        "Use this to bring can0 up or put a wireless interface into monitor mode without "
        "dropping into oc_bash."
    ),
    # Physical-layer tools. The container must receive the device from the host
    # (USB, serial, wireless PHY, CAN); call oc_hardware_inventory first.
    "hackrf_info": (
        "Enumerate a HackRF SDR and report board, firmware, and serial information. "
        "Run oc_hardware_inventory first; the device requires host USB passthrough."
    ),
    "hackrf_transfer": (
        "Transmit or receive raw IQ samples with a HackRF. Transmit is a licensed "
        "radio operation: confirm frequency, power, and authorization before use."
    ),
    "hackrf_sweep": (
        "Sweep a frequency range with a HackRF and report observed power levels."
    ),
    "rtl_sdr": (
        "Capture raw IQ samples from a Realtek RTL-SDR dongle into an engagement artifact."
    ),
    "rtl_433": (
        "Decode 433/315/868/915 MHz sensor and remote-control protocols with rtl_433. "
        "Common first step for sub-GHz physical security assessments."
    ),
    "soapy_sdr": (
        "Query and probe SDR hardware through the SoapySDR abstraction layer."
    ),
    "limesdr": (
        "Query LimeSDR hardware and gateware through LimeUtil."
    ),
    "bladerf": (
        "Control and query a Nuand bladeRF SDR through the bladeRF-cli."
    ),
    "ubertooth_util": (
        "Query and control an Ubertooth One Bluetooth/BLE radio."
    ),
    "ubertooth_rx": (
        "Receive and follow Bluetooth Low Energy connections with an Ubertooth One."
    ),
    "ubertooth_scan": (
        "Discover classic Bluetooth and BLE devices with an Ubertooth One."
    ),
    "iw": (
        "Inspect and configure Linux wireless interfaces, including monitor mode. "
        "Requires a wireless PHY inside the container and CAP_NET_ADMIN."
    ),
    "iwconfig": (
        "Legacy wireless interface configuration and status."
    ),
    "hcxdumptool": (
        "Capture Wi-Fi management frames and PMKID/EAPOL material for authorized "
        "wireless assessments. Requires monitor-mode capable hardware."
    ),
    "hcxpcapngtool": (
        "Convert hcxdumptool/hcxtools captures into hashcat-compatible material."
    ),
    "wifite": (
        "Automated authorized wireless audit wrapper around aircrack-ng, reaver, "
        "and hashcat. Prefer explicit per-step tools when evidence quality matters."
    ),
    "proxmark3": (
        "Interact with a Proxmark3 RFID/NFC research device. Requires host USB "
        "passthrough and the matching Proxmark3 firmware."
    ),
    "nfc_list": (
        "List NFC devices and tags visible to a PC/SC or libnfc reader."
    ),
    "nfc_poll": (
        "Poll for one NFC tag and report its UID and technology."
    ),
    "mfoc": (
        "Recover MIFARE Classic keys with the nested authentication attack. "
        "Only use on tags you are authorized to test."
    ),
    "mfcuk": (
        "Recover MIFARE Classic keys with the darkside attack when nested auth fails."
    ),
    "openocd": (
        "Drive JTAG/SWD targets through OpenOCD using an interface and target config. "
        "Requires the debug probe to be passed into the container."
    ),
    "urjtag": (
        "Detect and interact with JTAG chains through UrJTAG."
    ),
    "avrdude": (
        "Read, write, and verify AVR microcontrollers through an authorized programmer."
    ),
    "dfu_util": (
        "List, read, and flash USB DFU devices."
    ),
    "esptool": (
        "Read, write, erase, and inspect ESP8266/ESP32 flash and eFuses."
    ),
    "st_info": (
        "Probe STM32 devices through an ST-Link debug probe."
    ),
    "st_flash": (
        "Read, write, and verify STM32 flash through an ST-Link probe."
    ),
    "flashrom": (
        "Detect, read, write, and verify SPI/parallel flash chips and firmware."
    ),
    "sigrok_cli": (
        "Capture and decode digital and analog signals with sigrok-compatible "
        "logic analyzers and oscilloscopes."
    ),
    "unblob": (
        "Extract and recursively unpack firmware images with unblob."
    ),
    "qemu_arm": (
        "Emulate a single ARM user-space binary. Useful for firmware binaries that "
        "cannot run in the container directly."
    ),
    "qemu_system_arm": (
        "Emulate a full ARM system for firmware and embedded target analysis."
    ),
    "gdb_multiarch": (
        "Debug ARM, MIPS, and other foreign-architecture firmware with GDB."
    ),
    "minicom": (
        "Interactive serial console. Prefer oc_serial_open/read/write for "
        "agent-driven UART sessions with persisted transcripts."
    ),
    "picocom": (
        "Interactive serial console. Prefer oc_serial_open/read/write for "
        "agent-driven UART sessions with persisted transcripts."
    ),
    "candump": (
        "Capture CAN bus frames from a SocketCAN interface into an engagement artifact."
    ),
    "cansend": (
        "Send one CAN frame on a SocketCAN interface."
    ),
    "cansniffer": (
        "Display changing CAN bus frames and payloads."
    ),
    "isotpsend": (
        "Send ISO-TP (ISO 15765-2) diagnostic payloads over CAN."
    ),
    "isotprecv": (
        "Receive ISO-TP diagnostic responses over CAN."
    ),
    "gpsmon": (
        "Inspect a live GPS/GNSS receiver and its NMEA output."
    ),
    "gpspipe": (
        "Stream GPSD JSON or NMEA data into an engagement artifact."
    ),
    "gpsfake": (
        "Replay or simulate NMEA data through GPSD for parser and spoof testing."
    ),
    "lircd": (
        "IR receive/transmit daemon for LIRC-compatible infrared hardware."
    ),
    "apktool": (
        "Decode, rebuild, and inspect Android APK resources and smali."
    ),
    "jadx": (
        "Decompile Android DEX/APK bytecode for mobile application review."
    ),
    "lsusb": (
        "List USB devices visible inside the container, including known SDR, NFC, "
        "debug-probe, and serial adapters."
    ),
    "usbguard": (
        "Inspect and enforce USB device authorization policy."
    ),
}


def _tool_name(slug: str) -> str:
    normalized = re.sub(r"[^a-z0-9_]+", "_", slug.lower()).strip("_")
    return f"oc_{normalized}"


def _description(slug: str, executable: str, category: str) -> str:
    if slug in SPECIAL_DESCRIPTIONS:
        return SPECIAL_DESCRIPTIONS[slug]
    label = slug.replace("_", " ")
    return (
        f"Run {label} from the OpenCyber {category.replace('_', ' ')} toolkit. "
        f"The container executes `{executable}` directly with the supplied argv tokens; "
        "shell parsing is never used."
    )


def build_catalog() -> tuple[ToolSpec, ...]:
    specs: list[ToolSpec] = []
    seen: set[str] = set()
    for category, entries in TOOL_GROUPS.items():
        for slug, executable in entries:
            name = _tool_name(slug)
            if name in seen:
                raise ValueError(f"duplicate OpenCyber tool name: {name}")
            seen.add(name)
            optional = OPTIONAL_INTEGRATIONS.get(executable)
            specs.append(
                ToolSpec(
                    name=name,
                    executable=executable,
                    category=category,
                    description=_description(slug, executable, category),
                    required=optional is None,
                    optional_reason=optional[0] if optional else "",
                    dependencies=optional[1] if optional else TOOL_DEPENDENCIES.get(executable, ()),
                )
            )
    return tuple(specs)


CATALOG = build_catalog()


def category_counts(specs: Iterable[ToolSpec] = CATALOG) -> dict[str, int]:
    counts: dict[str, int] = {}
    for spec in specs:
        counts[spec.category] = counts.get(spec.category, 0) + 1
    return dict(sorted(counts.items()))
