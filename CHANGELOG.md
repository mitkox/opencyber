# Changelog

## 0.5.0 — private pre-production beta

OpenCyber Harness 0.5.0 is preparing for its first open-source prerelease under
Apache-2.0. It is currently available to invited private beta testers. The clean
repository starts with a fresh source snapshot; development history stays in a
separate private repository. No public release or production qualification is
claimed.

### Capabilities

- 255 security MCP tools over stdio: 173 executable integrations and 82 native tools for authorized red-team and blue-team work.
- MCP Python SDK 2.x (`mcp>=2.3,<3`) with MCPServer, structured results, explicit error codes, declared tool authority, coverage, provenance and verifiable catalog identity.
- Engagement workspaces, file and PCAP triage, timelines, verifiable evidence export, bounded result retention, and a hash-chained audit trail.
- Native HTTP/API auditing and workbench tools with engagement checks on each request and redirect hop; browser sessions remain outside engagement scope enforcement.
- Bounded process execution, cancellation and descendant cleanup, offline assets, airgap export/import, hardware readiness and firmware analysis.
- Eleven hardware domains: USB, SDR, Wi-Fi, Bluetooth/BLE, NFC/RFID, JTAG/SWD/SPI, UART, CAN, logic analyzers, GNSS and IR. Hardware interfaces are experimental; real-device qualification is deferred.
- Operator-signed PoC authorization and single-use approvals with hash binding and durable consumption before launch. These are workflow controls within a trusted container-root boundary.
- MCP client configuration, an OpenCode research adapter and guard, and a synthetic PoC lab.
- A beta guide with a synthetic first exercise and expected results, plus
  AGENTS.md for contributors using coding agents.
- Security-updated source builds of Jaeles, kube-bench, URLFinder and yq with
  frozen dependency graphs; Prowler 5.45 uses its supported Python 3.13 runtime.
  Terrascan and ScoutSuite remain optional, unbundled adapters while their
  dependencies cannot satisfy the vulnerability gate.

### Release verification

- Python 3.11–3.13 checks and native amd64/arm64 software acceptance.
- Separate private candidate builds and digest-preserving promotion with SBOMs, corresponding source, license checks, signatures and source receipts.
- Explicit qualification status: real-device evidence is deferred for 0.5.0. Optional device claims require checksummed observations; synthetic fixtures do not qualify hardware.
- A versioned `0.5.0` container reference and a GitHub prerelease. Moving `latest`, `0` and `0.5` aliases remain untouched.
- Immutable release assets and version references; a changed published candidate requires a new version.

### Operating requirements

- Trust the MCP client and its code: arbitrary execution runs as container root. Environment scrubbing does not isolate signing material from root.
- Scope enforcement and offline mode are guardrails; use host network policy for hard egress boundaries.
- Device passthrough and hardware authorization remain operator responsibilities. Evidence can contain sensitive target data.
- Read [the security model](docs/SECURITY_MODEL.md), [installation guide](docs/INSTALL.md) and [release evidence procedure](docs/RELEASE.md) before use.
