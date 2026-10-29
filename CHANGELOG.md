# Changelog

## 0.5.1 - next beta source, unreleased

- Preserve cookie domain, host-only, path, Secure, expiry and other attributes
  across HTTP workbench calls. Existing sessions with old flat cookie records
  must re-authenticate; their lost restrictions cannot be reconstructed safely.
  Explicit cookie updates remain supported and bind cookies to the base host.
- Restrict corresponding-source capture to build inputs and exclude local
  credentials and historical private verification records from Docker context.
- Correct PoC refusal envelopes and policy/HTTP error codes; preserve consumed
  approvals and run identity in direct calls and stored-run evidence.
- Cap native HTTP response bodies at 256 KiB after decompression, including
  redirects, with explicit truncation, partial coverage and a named limit.
- Pin the image MCP SDK to 2.3.0.
- The `v0.5.0-private-beta.1` release remains unchanged and does not contain
  these fixes. New binary sharing remains subject to vulnerability, license,
  source and native acceptance gates.

## 0.5.0 — private pre-production beta

OpenCyber Harness 0.5.0 is preparing for its first open-source prerelease under
Apache-2.0. It is currently available to invited private beta testers. The clean
repository starts with a fresh source snapshot; development history stays in a
separate private repository. No public release or production qualification is
claimed.

### Private beta access

- Published [v0.5.0-private-beta.1](https://github.com/mitkox-dev/opencyber/releases/tag/v0.5.0-private-beta.1)
  on 2026-10-26: the full Linux amd64 image, frozen first-party source, matched
  corresponding source, notices, SBOMs, checksum lists and offline import helper.
  Its 38 assets total about 13.3 GB. The image remains an unqualified preview;
  vendor/license follow-ups, arm64 and device qualification remain open.
- The complete reviewed source is hosted privately at `mitkox-dev/opencyber`.
  External beta testers receive the Read role as outside collaborators; the
  private development repository and its history remain separate.
- The current preview uses private GitHub release assets, accessible through
  repository Read without GHCR permission. Future qualified candidates use the
  `mitkox-dev` GHCR namespace and the full license/software qualification gates.

### Capabilities

- 256 security MCP tools over stdio: 174 executable integrations and 82 native tools for authorized red-team and blue-team work.
- MCP Python SDK 2.x (`mcp>=2.3,<3`) with MCPServer, structured results, explicit error codes, declared tool authority, coverage, provenance and verifiable catalog identity.
- Engagement workspaces, file and PCAP triage, timelines, verifiable evidence export, bounded result retention, and a hash-chained audit trail.
- Native HTTP/API auditing and workbench tools with engagement checks on each request and redirect hop; browser sessions remain outside engagement scope enforcement.
- Bounded process execution, cancellation and descendant cleanup, offline assets, airgap export/import, hardware readiness and firmware analysis.
- Eleven hardware domains: USB, SDR, Wi-Fi, Bluetooth/BLE, NFC/RFID, JTAG/SWD/SPI, UART, CAN, logic analyzers, GNSS and IR. Hardware integrations are supported for beta use; real-device qualification is recorded separately.
- Operator-signed PoC authorization and single-use approvals with hash binding and durable consumption before launch. These are workflow controls within a trusted container-root boundary.
- MCP client configuration, an OpenCode research adapter and guard, and a synthetic PoC lab.
- A beta guide with a synthetic first exercise and expected results, plus
  AGENTS.md for contributors using coding agents.
- Security-updated source builds of Jaeles, kube-bench, URLFinder and yq with
  frozen dependency graphs; Prowler 5.45 uses its supported Python 3.13 runtime.
  Terrascan and ScoutSuite remain optional, unbundled adapters while their
  dependencies cannot satisfy the vulnerability gate.

### Airgapped toolkit

- Restore bundled Nmap, RustScan, AutoRecon, Metasploit, NetExec and WPScan.
  Nmap scripts, Metasploit modules and WPScan local-detection metadata are
  required assets. Add `oc_wpscan` while preserving existing tool names.
- Remove package-added Nmap file capabilities that prevent startup in hardened
  containers. Add disposable state mounts for AutoRecon, NetExec and Metasploit.
- Validate actual offline CLI startup, capless Nmap loopback scanning and
  WPScan local detection through a disposable container acceptance suite.
- Replace the unverified RockYou corpus with a pinned, attributed SecLists
  generated baseline dictionary, retaining the other qualified lists. Keep the
  legacy `rockyou` status as optional rather than mislabeling the replacement.
- Permit evidence-backed custom license decisions. Preserve original terms,
  notices and corresponding source; a research-use notice grants no rights.
- Keep archived Terrascan and the critically vulnerable ScoutSuite/sqlitedict
  stack excluded. Missing vendor redistribution grants remain explicit.

### Release verification

- Source checks cover Python 3.11–3.13. Qualified candidates require native
  amd64/arm64 software acceptance; the current preview has local amd64 evidence.
- Separate private candidate builds and digest-preserving promotion with SBOMs, corresponding source, license checks, signatures and source receipts.
- Explicit qualification status: real-device evidence is deferred for 0.5.0. Optional device claims require checksummed observations; synthetic fixtures do not qualify hardware.
- Fixed preview image `opencyber:0.5.0-private-beta.1-amd64` and a private GitHub
  prerelease. Qualified public `0.5.0` promotion remains pending; moving
  `latest`, `0` and `0.5` aliases remain untouched.
- Immutable release assets and version references; a changed published candidate requires a new version.

### Operating requirements

- Trust the MCP client and its code: arbitrary execution runs as container root. Environment scrubbing does not isolate signing material from root.
- Scope enforcement and offline mode are guardrails; use host network policy for hard egress boundaries.
- Device passthrough and hardware authorization remain operator responsibilities. Evidence can contain sensitive target data.
- Read [the security model](docs/SECURITY_MODEL.md), [installation guide](docs/INSTALL.md) and [release evidence procedure](docs/RELEASE.md) before use.
