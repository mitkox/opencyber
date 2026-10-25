"""Deterministic OpenCyber engagement planning helpers."""

from __future__ import annotations

from typing import Any


WORKFLOW_STEPS: dict[str, tuple[dict[str, Any], ...]] = {
    "recon": (
        {"tool": "oc_subfinder", "purpose": "Enumerate subdomains"},
        {"tool": "oc_amass", "purpose": "Expand passive and active asset discovery"},
        {"tool": "oc_httpx", "purpose": "Identify responsive HTTP services"},
        {"tool": "oc_nmap", "purpose": "Map exposed services"},
        {"tool": "oc_nuclei", "purpose": "Run template-based checks"},
    ),
    "web": (
        {"tool": "oc_httpx", "purpose": "Probe the application and collect metadata"},
        {"tool": "oc_katana", "purpose": "Crawl reachable content"},
        {"tool": "oc_ffuf", "purpose": "Discover routes and resources"},
        {"tool": "oc_arjun", "purpose": "Discover request parameters"},
        {"tool": "oc_nuclei", "purpose": "Run web-focused checks"},
        {"tool": "oc_sqlmap", "purpose": "Validate suspected SQL injection"},
    ),
    "api": (
        {"tool": "oc_openapi_inspect", "purpose": "Inventory the documented API operations"},
        {"tool": "oc_http_request", "purpose": "Exercise requests and inspect complete responses"},
        {"tool": "oc_graphql_request", "purpose": "Exercise GraphQL operations when present"},
        {"tool": "oc_jwt_decode", "purpose": "Inspect token claims without claiming verification"},
        {"tool": "oc_arjun", "purpose": "Discover undocumented parameters"},
        {"tool": "oc_nuclei", "purpose": "Run API-relevant templates"},
    ),
    "vulnerability_assessment": (
        {"tool": "oc_nmap", "purpose": "Inventory exposed services"},
        {"tool": "oc_nuclei", "purpose": "Run reproducible vulnerability checks"},
        {"tool": "oc_nikto", "purpose": "Assess web-server configuration"},
        {"tool": "oc_trivy", "purpose": "Assess filesystems, images, and configuration"},
        {"tool": "oc_scan_summary", "purpose": "Preserve and summarize complete tool results"},
    ),
    "bug_bounty": (
        {"tool": "oc_subfinder", "purpose": "Discover in-scope subdomains"},
        {"tool": "oc_httpx", "purpose": "Identify responsive properties"},
        {"tool": "oc_katana", "purpose": "Crawl reachable application content"},
        {"tool": "oc_gau", "purpose": "Collect historical URLs"},
        {"tool": "oc_arjun", "purpose": "Discover parameters"},
        {"tool": "oc_dalfox", "purpose": "Test XSS candidates"},
        {"tool": "oc_nuclei", "purpose": "Run scoped templates"},
        {"tool": "oc_finding_report", "purpose": "Persist validated findings"},
    ),
    "cloud": (
        {"tool": "oc_prowler", "purpose": "Assess configured cloud accounts"},
        {"tool": "oc_scout_suite", "purpose": "Build a cloud security inventory"},
        {"tool": "oc_trivy", "purpose": "Scan images, filesystems, and configuration"},
        {"tool": "oc_checkov", "purpose": "Scan infrastructure as code"},
        {"tool": "oc_kube_bench", "purpose": "Check Kubernetes CIS controls"},
    ),
    "binary": (
        {"tool": "oc_file", "purpose": "Identify the artifact"},
        {"tool": "oc_checksec", "purpose": "Inspect binary protections"},
        {"tool": "oc_strings", "purpose": "Extract printable content"},
        {"tool": "oc_binwalk", "purpose": "Identify embedded data"},
        {"tool": "oc_radare2", "purpose": "Perform static and dynamic analysis"},
        {"tool": "oc_gdb", "purpose": "Debug runtime behavior"},
    ),
    "forensics": (
        {"tool": "oc_file", "purpose": "Classify input artifacts"},
        {"tool": "oc_exiftool", "purpose": "Extract metadata"},
        {"tool": "oc_bulk_extractor", "purpose": "Extract forensic features"},
        {"tool": "oc_foremost", "purpose": "Carve files"},
        {"tool": "oc_volatility", "purpose": "Analyze memory images"},
    ),
    "ctf": (
        {"tool": "oc_file", "purpose": "Classify challenge artifacts"},
        {"tool": "oc_strings", "purpose": "Extract initial clues"},
        {"tool": "oc_exiftool", "purpose": "Inspect metadata"},
        {"tool": "oc_binwalk", "purpose": "Find embedded content"},
        {"tool": "oc_checksec", "purpose": "Inspect binary protections when applicable"},
    ),
    "credentials": (
        {"tool": "oc_hash_identifier", "purpose": "Classify supplied hashes"},
        {"tool": "oc_john", "purpose": "Run wordlist and rule-based cracking"},
        {"tool": "oc_hashcat", "purpose": "Run accelerated hash recovery"},
        {"tool": "oc_hydra", "purpose": "Test explicitly authorized network authentication"},
    ),
    "wireless": (
        {"tool": "oc_airmon", "purpose": "Prepare a compatible wireless interface"},
        {"tool": "oc_airodump", "purpose": "Capture authorized wireless traffic"},
        {"tool": "oc_aircrack", "purpose": "Analyze captured handshakes"},
        {"tool": "oc_kismet", "purpose": "Perform wireless discovery and monitoring"},
    ),
    "hardware": (
        {"tool": "oc_hardware_readiness", "purpose": "Confirm tooling and device visibility before physical testing"},
        {"tool": "oc_hardware_inventory", "purpose": "Enumerate USB, serial, radio, and bus interfaces"},
        {"tool": "oc_hardware_plan", "purpose": "Select a domain-specific playbook with prerequisites"},
    ),
    "rf": (
        {"tool": "oc_hardware_readiness", "purpose": "Confirm the SDR is visible and authorized"},
        {"tool": "oc_hackrf_info", "purpose": "Identify the radio and firmware"},
        {"tool": "oc_rtl_test", "purpose": "Verify RTL-SDR tuning and sample rates"},
        {"tool": "oc_hackrf_sweep", "purpose": "Survey the authorized band"},
        {"tool": "oc_rtl_433", "purpose": "Decode sub-GHz sensors and remotes"},
    ),
    "wireless_attack": (
        {"tool": "oc_hardware_readiness", "purpose": "Confirm wireless or Bluetooth hardware is exposed"},
        {"tool": "oc_iw", "purpose": "Inspect the wireless PHY and monitor-mode support"},
        {"tool": "oc_airmon", "purpose": "Create a monitor-mode interface"},
        {"tool": "oc_hcxdumptool", "purpose": "Capture authorized PMKID/EAPOL material"},
        {"tool": "oc_hcxpcapngtool", "purpose": "Convert captures for offline cracking"},
        {"tool": "oc_hashcat", "purpose": "Recover keys from captured material"},
    ),
    "embedded": (
        {"tool": "oc_hardware_readiness", "purpose": "Confirm the debug probe or serial adapter is visible"},
        {"tool": "oc_openocd", "purpose": "Identify and halt the target"},
        {"tool": "oc_urjtag", "purpose": "Detect the JTAG chain when the target config is unknown"},
        {"tool": "oc_flashrom", "purpose": "Read or verify external flash"},
        {"tool": "oc_firmware_analyze", "purpose": "Triage the dumped image"},
        {"tool": "oc_qemu_arm", "purpose": "Emulate extracted ARM code for analysis"},
    ),
    "automotive": (
        {"tool": "oc_hardware_readiness", "purpose": "Confirm a SocketCAN interface is exposed"},
        {"tool": "oc_ip", "purpose": "Bring the interface up at the authorized bitrate"},
        {"tool": "oc_candump", "purpose": "Capture baseline CAN traffic"},
        {"tool": "oc_cansniffer", "purpose": "Identify changing frames"},
        {"tool": "oc_cansend", "purpose": "Send one authorized frame"},
        {"tool": "oc_isotpsend", "purpose": "Exercise ISO-TP diagnostic services"},
    ),
    "nfc": (
        {"tool": "oc_hardware_readiness", "purpose": "Confirm the NFC reader or Proxmark3 is visible"},
        {"tool": "oc_nfc_list", "purpose": "List readers and tags"},
        {"tool": "oc_nfc_poll", "purpose": "Capture a tag UID and technology"},
        {"tool": "oc_mfoc", "purpose": "Recover MIFARE Classic keys on authorized tags"},
        {"tool": "oc_proxmark3", "purpose": "Run tag-specific commands and dumps"},
    ),
}


def engagement_plan(kind: str, target: str, objective: str = "") -> dict[str, Any]:
    normalized = kind.strip().lower()
    if normalized not in WORKFLOW_STEPS:
        raise ValueError(f"unknown workflow kind: {kind}; choose from {sorted(WORKFLOW_STEPS)}")
    return {
        "kind": normalized,
        "target": target,
        "objective": objective,
        "steps": list(WORKFLOW_STEPS[normalized]),
        "note": "This is a deterministic plan. Each step requires an explicit MCP tool call.",
    }


def recommend_tools(objective: str, target_type: str = "web") -> dict[str, Any]:
    text = objective.lower()
    scores: dict[str, int] = {kind: 0 for kind in WORKFLOW_STEPS}
    keywords = {
        "recon": ("recon", "asset", "domain", "subdomain", "network", "port"),
        "web": ("web", "http", "api", "url", "application", "xss", "sqli"),
        "api": ("api", "graphql", "openapi", "swagger", "jwt"),
        "vulnerability_assessment": ("vulnerability", "assessment", "scan", "cve"),
        "bug_bounty": ("bug bounty", "bounty", "scope", "program"),
        "cloud": ("cloud", "aws", "azure", "gcp", "kubernetes", "container", "iac"),
        "binary": ("binary", "reverse", "pwn", "elf", "executable"),
        "forensics": ("forensic", "memory", "disk", "image", "artifact"),
        "ctf": ("ctf", "challenge", "flag", "puzzle"),
        "credentials": ("password", "credential", "hash", "authentication"),
        "wireless": ("wireless", "wifi", "802.11", "wpa"),
        "hardware": ("hardware", "physical", "device", "usb", "rfid", "nfc", "jtag", "uart"),
        "rf": ("sdr", "rf", "radio", "sub-ghz", "433", "hackrf", "rtl", "lora"),
        "wireless_attack": ("wi-fi", "wifi", "wpa", "wlan", "bluetooth", "ble", "pmkid", "handshake"),
        "embedded": ("firmware", "embedded", "jtag", "swd", "uart", "spi", "flash", "esp", "stm32", "arm"),
        "automotive": ("can", "obd", "automotive", "vehicle", "iso-tp", "socketcan"),
        "nfc": ("nfc", "rfid", "mifare", "proxmark", "tag"),
    }
    for kind, needles in keywords.items():
        scores[kind] = sum(needle in text for needle in needles)
    if max(scores.values()) == 0 and target_type.lower() in scores:
        scores[target_type.lower()] = 1
    selected = max(scores, key=lambda name: scores[name])
    return {
        "selected_workflow": selected,
        "scores": scores,
        "tools": list(WORKFLOW_STEPS[selected]),
        "basis": "deterministic keyword matching over the supplied objective and target type",
    }


def attack_chain(findings: list[dict[str, Any]]) -> dict[str, Any]:
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    ordered = sorted(
        findings,
        key=lambda finding: severity_order.get(str(finding.get("severity", "info")).lower(), 5),
    )
    steps = [
        {
            "order": index,
            "finding": finding,
            "reason": "ordered by supplied severity; validate reachability and prerequisites before execution",
        }
        for index, finding in enumerate(ordered, start=1)
    ]
    return {"steps": steps, "generated": False, "basis": "caller-supplied findings"}


def scan_summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    succeeded = [result for result in results if result.get("success") is True]
    failed = [result for result in results if result.get("success") is False]
    return {
        "total": len(results),
        "succeeded": len(succeeded),
        "failed": len(failed),
        "return_codes": [result.get("returncode") for result in results],
        "tools": [result.get("oc_tool") or result.get("tool") for result in results],
        "results": results,
    }
