"""Trace the reference functional inventory to OpenCyber tools."""

from __future__ import annotations

from .catalog import CATALOG


REFERENCE_FUNCTIONS = frozenset(
    """
    nmap gobuster dirb nikto sqlmap hydra john hashcat
    rustscan masscan autorecon nbtscan arp-scan responder nxc enum4linux-ng rpcclient enum4linux
    ffuf feroxbuster dirsearch dotdotpwn xsser wfuzz gau waybackurls arjun paramspider x8 jaeles dalfox
    httpx wafw00f burpsuite zaproxy katana hakrawler
    nuclei wpscan graphql-scanner jwt-analyzer
    medusa patator hash-identifier ophcrack hashcat-utils
    gdb radare2 binwalk ropgadget checksec objdump ghidra pwntools one-gadget ropper angr libc-database pwninit
    volatility3 vol steghide hashpump foremost exiftool strings xxd file photorec testdisk scalpel bulk-extractor
    stegsolve zsteg outguess
    prowler scout-suite trivy kube-hunter kube-bench docker-bench-security checkov terrascan falco clair
    amass subfinder fierce dnsenum theharvester sherlock social-analyzer recon-ng maltego spiderfoot shodan-cli
    censys-cli have-i-been-pwned
    api-schema-analyzer postman insomnia curl httpie anew qsreplace uro
    kismet wireshark tshark tcpdump
    smbmap volatility sleuthkit autopsy evil-winrm airmon-ng airodump-ng aireplay-ng aircrack-ng
    """.split()
)


REFERENCE_ALIASES: dict[str, str] = {
    "angr": "oc_angr_analyze",
    "api-schema-analyzer": "oc_openapi_inspect",
    "autopsy": "oc_sleuthkit_fls",
    "bulk-extractor": "oc_bulk_extractor",
    "censys-cli": "oc_censys",
    "clair": "oc_trivy",
    "exploit-db": "oc_exploit_search",
    "graphql-scanner": "oc_graphql_request",
    "hashcat-utils": "oc_hashcat",
    "have-i-been-pwned": "oc_hibp_password_check",
    "insomnia": "oc_http_request",
    "httpie": "oc_httpie",
    "jwt-analyzer": "oc_jwt_decode",
    "libc-database": "oc_pwninit",
    "maltego": "oc_spiderfoot",
    "one-gadget": "oc_one_gadget",
    "outguess": "oc_steghide",
    "photorec": "oc_testdisk",
    "postman": "oc_http_request",
    "pwntools": "oc_pwntools",
    "ropgadget": "oc_ropgadget",
    "scout-suite": "oc_scout_suite",
    "searchsploit": "oc_exploit_search",
    "shodan-cli": "oc_shodan",
    "sleuthkit": "oc_sleuthkit_fls",
    "social-analyzer": "oc_sherlock",
    "stegsolve": "oc_zsteg",
    "theharvester": "oc_theharvester",
    "burpsuite": "oc_zap",
    "waybackurls": "oc_urlfinder",
    "wpscan": "oc_whatweb",
    "falco": "oc_process_snapshot",
    "volatility": "oc_volatility",
    "volatility3": "oc_volatility",
    "wireshark": "oc_packet_analysis",
}


def reference_coverage() -> dict[str, str]:
    by_executable = {spec.executable: spec.name for spec in CATALOG}
    coverage: dict[str, str] = {}
    for reference in sorted(REFERENCE_FUNCTIONS):
        if reference in REFERENCE_ALIASES:
            coverage[reference] = REFERENCE_ALIASES[reference]
        elif reference in by_executable:
            coverage[reference] = by_executable[reference]
    return coverage


def uncovered_reference_functions() -> list[str]:
    covered = reference_coverage()
    return sorted(REFERENCE_FUNCTIONS - covered.keys())
