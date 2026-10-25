<p align="center"><strong>OpenCyber Harness</strong><br>
A container-native red and blue team security MCP toolkit for agent runtimes.</p>

> **0.5.0 is in private beta preparation.** Repository access is by maintainer
> invitation. The first public open source prerelease is still planned; images
> are not yet cleared for distribution. Hardware interfaces are experimental
> and unqualified. Production qualification is separate.

**Beta testers: start with the [beta guide](docs/BETA_TESTING.md).** It covers
installation, MCP client setup and a synthetic first exercise with expected
results. The maintainer will provide an approved source commit and platform
image digest when image qualification and license review pass. Source testing
is available to invited contributors now; local builds remain development builds.

OpenCyber Harness is the execution substrate for authorized security work: one
container that exposes **255 security MCP tools** over stdio — 173
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

The catalog has 173 executable integrations and 82 native tools. The image
configuration omits eight optional adapters' binaries. Nmap and its dependent adapters
(`rustscan`, `autorecon`, `metasploit`, `msfvenom`, `netexec`) await redistribution
review. Terrascan and ScoutSuite do not meet the dependency vulnerability gate.
Catalog and doctor output distinguish registered, bundled and
available tools; see the [third-party notices](THIRD_PARTY_NOTICES.md).

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

### 1. Access the private source

After accepting the maintainer's repository invitation:

```sh
gh auth login
gh repo clone mitkox/opencyber
cd opencyber
```

For development now, follow the [source install](docs/INSTALL.md#path-c-source-install-for-development).
For the intended container runtime, follow the [beta guide](docs/BETA_TESTING.md)
once the maintainer supplies `BETA_SOURCE_COMMIT` and the qualified
`BETA_PLATFORM_DIGEST` for your architecture. Private GHCR access needs a
separate package permission and Docker login. There is no public release tag
or anonymous image installation to use yet.

### 2. Install the assigned candidate

From the source commit selected in the beta guide, after authenticating Docker:

```sh
OPENCYBER_IMAGE=ghcr.io/mitkox/opencyber-beta-candidates \
  bash install.sh --version 0.5.0 --digest "$BETA_PLATFORM_DIGEST"
```

`install.sh` starts a hardened container, creates a labelled workspace volume,
verifies the image version label and runs the MCP self-test. Keep the source
checkout for cleanup. See [Install](docs/INSTALL.md) for options and a manual
container alternative.

### 3. Check the running container

```sh
docker exec opencyber opencyber-doctor
docker exec -e OPENCYBER_STRICT_CATALOG=1 opencyber opencyber-mcp --self-test
```

`opencyber-doctor` exits non-zero when degraded, which makes it both a
healthcheck and a release gate. Use `--json` for machine output and `--quiet`
for probes.

### 4. Connect an MCP client

The server speaks MCP over stdio and publishes no ports:

```sh
docker exec -i opencyber opencyber-mcp
```

Claude Code, Codex, OpenCode, Gemini CLI, Cursor, and VS Code can launch that
command directly. Exact snippets and the full client matrix are in
[MCP integration](docs/MCP_INTEGRATION.md).

## What a tool result looks like

Every one of the 255 tools returns the same contract block, so a client can
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

- **Software toolchain.** 173 executable integrations across network,
  enumeration, web, credentials, exploitation, binary analysis, forensics,
  cloud/container/IaC, and utilities, including the optional integrations above.
  See the generated [tool reference](docs/TOOLS.md).
- **Physical-layer toolchain.** 63 hardware-category executables and native
  inventory, readiness, playbook, serial, and firmware tools. Host device
  passthrough is separate; see [Hardware](docs/HARDWARE.md).
- **Offline assets.** Nuclei templates, Seclists, rockyou, exploitdb and wordlists are baked in and recorded in an asset
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

Full mode advertises all 255 tools. Tool schemas cost context; if that is too
much, compact mode advertises the 82 native tools and dispatches executable
tools through `oc_execute`. `oc_catalog` reports both the advertised payload
size and the catalog digest, so you can see the context cost and whether the
running server matches the release you pinned:

```sh
docker run -d --name opencyber -e OPENCYBER_MCP_MODE=compact ...
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
  with the installer or [documented flags](docs/INSTALL.md#path-b-manual-container);
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
| [Tool reference](docs/TOOLS.md) | Generated list of all 255 tools |
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
