# OpenCyber Harness documentation

Documentation for OpenCyber Harness 0.5.0, a container-native red- and blue-team
MCP toolkit currently in private beta preparation. Access is by maintainer
invitation. The first public open source prerelease is still planned.

> Use OpenCyber Harness only against systems you own or are explicitly authorized to test. The software provides capability, not permission.

OpenCyber Harness is the execution substrate for authorized security work. One container exposes 255 security MCP tools over stdio: 173 executable-backed tools and 82 native tools. That covers network, web, API, binary, forensics, cloud, and physical-layer work (SDR, Wi-Fi, Bluetooth/BLE, NFC/RFID, USB, JTAG/SWD, UART, CAN, logic analyzers, GPS, and IR). It is not an agent: it has no planner, no model, and no network listener.

## Start here

New testers should follow [BETA_TESTING.md](BETA_TESTING.md): authenticate,
check out the selected source, install an assigned image by platform digest,
connect a client, analyze a synthetic log and verify the saved evidence. Shared
images remain blocked by license review and native platform qualification.
Invited contributors can use the source development path meanwhile. The guide
explains expected results and what to send with a bug.

| If you are... | Start here |
| --- | --- |
| A beta tester trying OpenCyber for the first time | [BETA_TESTING.md](BETA_TESTING.md) |
| A security practitioner running assessments | [USER_GUIDE.md](USER_GUIDE.md), then [INSTALL.md](INSTALL.md) |
| An MCP or AI developer wiring a client | [MCP_INTEGRATION.md](MCP_INTEGRATION.md), then [ARCHITECTURE.md](ARCHITECTURE.md) |

## All documents

| Document | Purpose |
| --- | --- |
| [BETA_TESTING.md](BETA_TESTING.md) | Requirements, install, MCP setup, synthetic first exercise, reporting and cleanup. |
| [BLUE_TEAM.md](BLUE_TEAM.md) | Offline analysis of supplied logs, files and PCAPs with evidence export. |
| [INSTALL.md](INSTALL.md) | Supported install paths, verification, upgrade, rollback, and uninstall. |
| [USER_GUIDE.md](USER_GUIDE.md) | Engagements, scans, catalog discovery, HTTP and browser work, hardware, airgaps, and evidence. |
| [MCP_INTEGRATION.md](MCP_INTEGRATION.md) | Stdio transport, client configuration, tool modes, discovery, cancellation, and remote-host limits. |
| [ARCHITECTURE.md](ARCHITECTURE.md) | Components, registration and counting, process model, storage layout, and the trust boundary. |
| [TOOLS.md](TOOLS.md) | Complete generated reference for all 255 tools, grouped by category. |
| [CONTRACTS.md](CONTRACTS.md) | Result envelope, coverage, provenance, evidence identity, declared authority, catalog identity, and the compatibility rules. |
| [ERRORS.md](ERRORS.md) | Generated refusal contract: codes, categories, retryability, remediation, and the JSON Schema. |
| [LIMITS.md](LIMITS.md) | Generated registry of every resource ceiling, what raises it, and what does not. |
| [POC_CHAINS.md](POC_CHAINS.md) | CVE-chain planning, signed authorizations and approvals, bounded PoCs, and evidence. |
| [POC_LAB.md](POC_LAB.md) | Disposable lab: synthetic target, 0.5.0 source container, deterministic gate driver, and Code Mode two-turn run. |
| [INTEGRATIONS.md](INTEGRATIONS.md) | OpenCode V2 Code Mode and DeepSeek Harness adapters for the PoC workflow. |
| [HARDWARE.md](HARDWARE.md) | Per-domain host flags, device passthrough, serial sessions, and hardware troubleshooting. |
| [AIRGAP.md](AIRGAP.md) | Building, exporting, verifying, and importing an image across an airgap. |
| [CONFIGURATION.md](CONFIGURATION.md) | Every `OPENCYBER_*` environment variable and its effect. |
| [SECURITY_MODEL.md](SECURITY_MODEL.md) | Threat model, isolation limits, scope enforcement, offline limits, and audit guarantees. |
| [OPERATIONS.md](OPERATIONS.md) | Running the container in practice: health checks, workspaces, retention, and upgrades. |
| [CLI_REFERENCE.md](CLI_REFERENCE.md) | Five console scripts, the CVE index builder and host release helpers. |
| [TROUBLESHOOTING.md](TROUBLESHOOTING.md) | Diagnosing startup, tool, browser, hardware, and asset failures. |
| [RELEASE.md](RELEASE.md) | Maintainer release, signing, attestation, and publishing workflow. |
| [HARDWARE_QUALIFICATION.md](HARDWARE_QUALIFICATION.md) | Optional real-device observations, evidence collector and tested matrix. |
| [PUBLIC_RELEASE_REVIEW.md](PUBLIC_RELEASE_REVIEW.md) | Findings, regressions and the distinction between source review and release acceptance. |

## Release qualification

The [review record](PUBLIC_RELEASE_REVIEW.md) describes source findings and local validation. The [release procedure](RELEASE.md) binds new software and hardware evidence to the frozen source commit and exact image digests. [Optional hardware qualification](HARDWARE_QUALIFICATION.md) requires real-device observations; readiness enumeration and synthetic lab fixtures do not satisfy it. The first prerelease defers this evidence and labels hardware interfaces experimental.

Private candidate records accompany the maintainer's assigned source commit
and platform digest. Eventual public qualification records will be release
assets. Historical development records do not establish MCP 2.x compatibility
or acceptance of a shared image.

## Orientation

The harness code is Apache-2.0. The image bundles independently licensed software; check the notices before redistribution.

- [README.md](../README.md) is the project front page and 60-second quick start.
- [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md) lists the licenses of software shipped in the image.
- [SOURCE_OFFER.md](../SOURCE_OFFER.md) explains how to obtain corresponding source.
- [CONTRIBUTING.md](../CONTRIBUTING.md) and [AGENTS.md](../AGENTS.md) describe
  development, testing, documentation and release responsibilities.

## Version

These documents describe OpenCyber Harness 0.5.0. The MCP surface is still pre-1.0, so tool names, arguments, and result fields may change between minor releases.

For offline investigations of supplied files, logs and captures, start with [BLUE_TEAM.md](BLUE_TEAM.md). Its evidence bundles stay in the engagement and are never release artifacts.
