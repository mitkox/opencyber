<p align="center"><strong>OpenCyber Harness</strong><br>
A container-native red and blue team security MCP toolkit for agent runtimes.</p>

> **0.5.0 has an invited-tester private preview for Linux amd64.** Download
> [v0.5.0-private-beta.1](https://github.com/mitkox/opencyber/releases/tag/v0.5.0-private-beta.1)
> with repository Read access. This preview is unqualified; native arm64,
> hardware and production acceptance remain open. Public publication and
> broader distribution require separate approval.

Repository source is preparing `0.5.1` with contract and security fixes. The
published `v0.5.0-private-beta.1` preview remains unchanged and does not include
those fixes. A new image has not been cleared for sharing.

**Beta testers: start with the [beta guide](docs/BETA_TESTING.md).**
External testers receive Read access to `mitkox/opencyber`; maintainers
manage invitations using the [beta access guide](docs/BETA_ACCESS.md). The beta
guide covers the published archive, MCP client setup and a synthetic first
exercise. The public beta image removes Oracle, Microsoft DIA and Metasploit components that lacked a recorded redistribution agreement; the rest of the toolkit is included. Oracle tooling and
PDB components. Vendor reviews and license metadata follow-ups remain open;
private access does not establish legal clearance or waive third-party terms.

OpenCyber Harness is the execution substrate for authorized security work: one
container that exposes **253 security MCP tools** over stdio — 171
executable-backed tools and 82 native ones — across the software and physical
layers: SDR, Wi-Fi, Bluetooth/BLE, NFC/RFID, USB, JTAG/SWD, UART, CAN/automotive,
logic analyzers, GPS, and IR. It ships isolated engagement workspaces, serial
sessions, firmware triage, a scoped HTTP workbench, browser automation, an
audit trail, and offline-ready scanning assets.

It is not an agent. It has no planner, no model, and no network listener. You
bring an MCP client; the harness supplies the tools, the container, and the
evidence trail.

> Use this only against systems you own or are explicitly authorized to test.
> The software provides capability, not permission.

Red teams can run authorized assessments through the existing network, web,
API and hardware integrations. Blue teams can analyze supplied files, logs and
PCAPs offline, build timelines, and export independently verifiable evidence.
Start with the [blue-team guide](docs/BLUE_TEAM.md) for that workflow.

The catalog has 171 executable integrations and 82 native tools. The image
includes Nmap, Ncat, Ndiff, Nping, RustScan, AutoRecon, NetExec and
WPScan, with their local assets. Terrascan is excluded because upstream is
archived; ScoutSuite is excluded because its sqlitedict dependency has an unresolved critical
advisory. Their optional adapters report the reason when unavailable.
Custom licenses are permitted with their own notices, source and use terms;
see the [third-party notices](THIRD_PARTY_NOTICES.md).

## Choose your path

| You want to… | Start here |
| --- | --- |
| Try the beta and report a reproducible problem | [Beta testing](docs/BETA_TESTING.md) |
| Run assessments with an MCP-capable agent | [Install](docs/INSTALL.md) → [User guide](docs/USER_GUIDE.md) |
| Investigate supplied evidence offline | [Blue-team guide](docs/BLUE_TEAM.md) |
| Integrate OpenCyber into an MCP client or agent runtime | [MCP integration](docs/MCP_INTEGRATION.md) |
| Understand the design and trust boundary | [Architecture](docs/ARCHITECTURE.md) → [Security model](docs/SECURITY_MODEL.md) |
| Plan deployment or airgapped operation | [Operations](docs/OPERATIONS.md) → [Airgap](docs/AIRGAP.md) |

## Quick start

### 1. Download the private preview

Use a Linux amd64 Docker engine, Bash and Python 3. After accepting the
maintainer's repository invitation, download all release assets while connected:

```sh
gh auth login
gh release download v0.5.0-private-beta.1 \
  --repo mitkox/opencyber --dir opencyber-beta
cd opencyber-beta
```

The 38 assets total about 13.3 GB. For an offline host, transfer the **whole
folder**, including all 14 numbered image/source parts and the checksums,
helper, source snapshot, notices and metadata. Allow additional storage for the
assembled image archive and Docker's expanded image. GitHub CLI is needed only
on the connected side; no GHCR token, Docker login or registry pull is required.

### 2. Verify and import locally

From the downloaded folder, on the Linux amd64 Docker host:

```sh
bash beta-import.sh --verify-only
bash beta-import.sh
```

The helper checks the parts and assembled archive, imports
`opencyber:0.5.0-private-beta.1-amd64`, and verifies the image layers,
configuration, platform and labels against source commit
`c1201976caf49c45068bb507032aee75e4509e20`. It runs offline doctor and strict MCP
checks in disposable containers and leaves no persistent container or volume.
It makes no network requests. See the [beta guide](docs/BETA_TESTING.md) for
source assembly, storage and retry details.

### 3. Start an offline workspace

Extract the supplied first-party source into a new directory, then use its
launcher with unused container and volume names:

```sh
mkdir source-c120197
tar -xzf opencyber-source-c120197.tar.gz -C source-c120197
if docker container inspect opencyber-beta >/dev/null 2>&1 || \
   docker volume inspect opencyber-beta >/dev/null 2>&1; then
  echo "opencyber-beta already exists; choose unused container and volume names" >&2
else
  bash source-c120197/opencyber/scripts/opencyber-run.sh \
    --profile blue-team --offline \
    --image opencyber:0.5.0-private-beta.1-amd64 \
    --name opencyber-beta --volume opencyber-beta
fi
```

The blue-team profile removes networking, capabilities and device passthrough.
The named volume keeps evidence across container removal. The source snapshot
and image remain frozen at `c120197`; newer repository documentation does not
change those release bytes. For development, use the separate
[source install](docs/INSTALL.md#path-c-source-install-for-development).

### 4. Check the running container

```sh
docker exec opencyber-beta opencyber-doctor --json
docker exec -e OPENCYBER_STRICT_CATALOG=1 opencyber-beta opencyber-mcp --self-test
```

Both checks should exit 0. Doctor reports required tools and assets; the MCP
self-test checks the advertised catalog. These checks do not qualify every
tool, device or live integration.

### 5. Connect an MCP client

The server speaks MCP over stdio and publishes no ports:

```sh
docker exec -i opencyber-beta opencyber-mcp
```

Claude Code, Codex, OpenCode, Gemini CLI, Cursor, and VS Code can launch that
command directly. Exact snippets and the full client matrix are in
[MCP integration](docs/MCP_INTEGRATION.md). Use the container name
`opencyber-beta` and do not add `-t`.

## What a tool result looks like

Every one of the 253 tools returns the same contract block, so a client can
branch on outcome, coverage, and provenance without special-casing tools:

```json
{
  "ok": true,
  "contract": {"schema_version": 1, "tool": "oc_file_triage", "server_version": "0.5.0"},
  "coverage": {"status": "complete", "examined": null, "total": null, "exhausted": null, "next_offset": null},
  "limitations": [],
  "provenance": {"untrusted_content": true, "source": "target"},
  "evidence": {"id": "oc_ev_9f2c…", "sha256": "9f2c…", "bytes": 4210, "retained": false}
}
```

A refusal is a result too: `ok: false` with a registered `error` code, a
retryability flag, and a concrete `remediation.action` instead of an opaque
transport error. Coverage is explicit, so a capped or paged result says
`partial` rather than looking empty. `provenance.untrusted_content` marks
target-derived text as data, not instructions.

`oc_catalog` reports the contract digest this server advertises, and
`opencyber-mcp --self-test` fails closed on a mismatch when
`OPENCYBER_STRICT_CATALOG=1`. That catches the stale-container failure where an
old process keeps serving an old tool contract after an upgrade. The full rules
are in [tool result contracts](docs/CONTRACTS.md), [errors](docs/ERRORS.md), and
[limits](docs/LIMITS.md).

## What is in the image

- **Software toolchain.** 171 executable integrations across network,
  enumeration, web, credentials, exploitation, binary analysis, forensics,
  cloud/container/IaC, and utilities. Optional adapters remain catalogued even
  when their binaries are excluded for the reasons above.
  See the generated [tool reference](docs/TOOLS.md).
- **Physical-layer toolchain.** 63 hardware-category executables and native
  inventory, readiness, playbook, serial, and firmware tools. Host device
  passthrough is separate; see [Hardware](docs/HARDWARE.md).
- **Offline assets.** Nuclei templates, pinned SecLists dictionaries, exploitdb and a generated keyboard-pattern dictionary are baked in and recorded in an asset
  manifest. See [Airgap](docs/AIRGAP.md).
- **Engagements.** Every artifact lands under
  `/workspace/engagements/<engagement_id>/`; there is no shared "current
  engagement" state.
- **Evidence.** Executable calls, workspace writes, HTTP workbench requests,
  browser actions, serial sessions, firmware analysis, and API audit requests
  are recorded in a hash-chained audit log. Coverage and limits are documented
  precisely in the [security model](docs/SECURITY_MODEL.md).
- **CVE-chain PoCs.** CVE chain planning, signed engagement authorizations,
  single-use run approvals, bounded non-destructive verifiers, and evidence, for
  authorized research only. See [PoC chains](docs/POC_CHAINS.md) and the
  [agent integrations](docs/INTEGRATIONS.md).

## Tool modes

Full mode advertises all 253 tools. Tool schemas cost context; if that is too
much, compact mode advertises the 82 native tools and dispatches executable
tools through `oc_execute`. `oc_catalog` reports both the advertised payload
size and the catalog digest, so you can see the context cost and whether the
running server matches the release you pinned:

```sh
docker run -d --name opencyber-beta -e OPENCYBER_MCP_MODE=compact ...
```

Narrow the advertised executable set by category:

```sh
-e OPENCYBER_TOOL_CATEGORIES=network,web,enumeration
-e OPENCYBER_TOOL_CATEGORIES=rf,wireless_attack,nfc_rfid,embedded,automotive,gps,ir,usb
```

`OPENCYBER_TOOL_CATEGORIES` has no effect in compact mode; native tools are
always registered. All configuration variables are documented in
[Configuration](docs/CONFIGURATION.md).

Executable-backed tools take explicit argv arrays and never invoke a shell:

```json
{"engagement_id": "eng_…", "arguments": ["-sT", "-p", "80,443", "10.0.0.5"]}
```

Arbitrary shell behavior is available only when the caller deliberately selects
`oc_bash`.

## Security posture

- The container is the trust boundary and runs as root because several of the
  included tools need privileged network access inside it. Harden from the host
  with the [documented launcher profiles](docs/INSTALL.md#path-b-manual-container);
  do not use `--privileged`.
- Scope enforcement is opt-in (`OPENCYBER_ENFORCE_SCOPE=1`) and applies to
  executable-backed calls, native HTTP tools (`oc_http_request`,
  `oc_graphql_request`, OpenAPI/GraphQL audits, API fuzz, and every HTTP
  workbench request and redirect hop), and the workbench's own session scope.
  Browser tools remain outside engagement scope enforcement.
- `OPENCYBER_OFFLINE=1` fails fast for named internet-dependent features. It is
  not an egress firewall; enforce that at the network layer.
- The audit log is tamper-evident, not tamper-proof, and executor auditing can
  be disabled with `OPENCYBER_AUDIT=0`. Some non-executor events are
  best-effort.
- Evidence artifacts can contain live credentials. Treat the workspace volume as
  sensitive data.

Read the full [security model](docs/SECURITY_MODEL.md) before exposing the
harness to untrusted clients or targets.

## Documentation

| Document | Purpose |
| --- | --- |
| [Beta testing](docs/BETA_TESTING.md) | First installation, synthetic exercise, expected results and bug reports |
| [docs/README.md](docs/README.md) | Documentation index |
| [Install](docs/INSTALL.md) | All supported install paths and verification |
| [User guide](docs/USER_GUIDE.md) | Engagements, scans, discovery, evidence |
| [MCP integration](docs/MCP_INTEGRATION.md) | Transports, client config, tool modes |
| [CVE chain PoCs](docs/POC_CHAINS.md) | Chain planning, signed authorizations and approvals, bounded runs |
| [Agent integrations](docs/INTEGRATIONS.md) | OpenCode V2 Code Mode and DeepSeek Harness adapters |
| [Configuration](docs/CONFIGURATION.md) | Every environment variable and default |
| [Architecture](docs/ARCHITECTURE.md) | Components, data flow, storage layout |
| [Security model](docs/SECURITY_MODEL.md) | Trust boundary, controls, limitations |
| [Operations](docs/OPERATIONS.md) | Deployment, hardening, backup, upgrades |
| [CLI reference](docs/CLI_REFERENCE.md) | Console commands and exit codes |
| [Tool reference](docs/TOOLS.md) | Generated list of all 253 tools |
| [Hardware](docs/HARDWARE.md) | Device passthrough and physical-layer work |
| [Airgap](docs/AIRGAP.md) | Offline build, export, import, CVE index |
| [Troubleshooting](docs/TROUBLESHOOTING.md) | Diagnosis and common failures |
| [Release](docs/RELEASE.md) | Versioning, build, signing, publishing |

## Development

```sh
python -m venv .venv && . .venv/bin/activate
pip install -e '.[test,dev]'
make check            # lint, typecheck, docs drift, version aliases, tests
python -m unittest discover -s tests -v
```

The test suite covers the catalog contract, argv execution and cancellation,
path isolation, workspace operations, API auditing, the HTTP workbench, hardware
inventory and serial sessions, firmware triage, audit-chain tamper detection,
scope enforcement, offline assets, the installer, distribution compliance, and
the doctor probe. Source installs are for development: the Kali toolchain,
browser runtime, and baked assets come from the container image.

See [CONTRIBUTING.md](CONTRIBUTING.md) for the repository layout, how to add a
catalog tool, and the documentation rules. [AGENTS.md](AGENTS.md) gives coding
agents the same setup commands, contract requirements and release boundaries.

## Licensing

The harness source is Apache-2.0. The image is a collection of independently
licensed software; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md),
[SOURCE_OFFER.md](SOURCE_OFFER.md), and
[`compliance/license-policy.json`](compliance/license-policy.json). Components
whose terms do not permit redistribution in this container are deliberately
excluded.

## Versioning

`0.x` while the MCP tool contracts settle. Once the surface is frozen, the
project moves to `1.0.0` and follows semantic versioning for tool names,
arguments, and result fields. Release history is in
[CHANGELOG.md](CHANGELOG.md).
