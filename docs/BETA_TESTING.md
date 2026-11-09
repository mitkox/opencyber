# Start beta testing 0.5.0

The repository source is preparing `0.5.1`. It includes the HTTP cookie,
response-limit and refusal-contract fixes described in the changelog. There is
no updated binary preview yet. The download below remains the frozen 0.5.0
preview and does not contain those fixes.

Testers run their own local copies. Do not connect an untrusted tester to a
maintainer's Docker socket, backend, workspace, approval keys or host credentials.
Use synthetic evidence first, separate workspace volumes, no host-directory
mounts or devices, and the network-disabled profile below. Keep tokens outside
the backend; tool results can still reach the tester's chosen model provider.

The invited-tester [v0.5.0-private-beta.1 release](https://github.com/mitkox/opencyber/releases/tag/v0.5.0-private-beta.1)
is available for **Linux amd64**. The maintainer adds beta testers; accept the
private repository invitation before downloading. Use an owned lab and
synthetic evidence.

| Preview identity | Value |
| --- | --- |
| Source and runtime revision | `c1201976caf49c45068bb507032aee75e4509e20` |
| Local image tag | `opencyber:0.5.0-private-beta.1-amd64` |
| First-party source archive | `opencyber-source-c120197.tar.gz` |

This preview retains the full toolkit, including Oracle tooling and PDB
components. It is **unqualified**. Recorded amd64 checks include 689 tests
with one skip and 81% coverage, actual offline image checks, and a Trivy scan
with no HIGH or CRITICAL findings. They do not qualify all features or live
Oracle/PDB integrations. Native arm64, hardware and production acceptance remain
open. Two vendor reviews and 2,086 unknown license metadata records across
5,129 components remain open; private access does not establish legal clearance
or waive third-party terms. Public publication and broader distribution need
separate approval. See the release's `release-manifest.json`, SBOM, license
inventory and captured gate results for the recorded limits.

## What you need

- A native Linux `amd64` Docker engine, and a user who can already run
  `docker info`. This preview is not an arm64 image.
- Bash and Python 3 on the Docker host. GitHub CLI (`gh`) is needed only on
  the connected download machine.
- Read access to `mitkox/opencyber` and all 38 private release assets
  (13,310,405,014 bytes, about 13.3 GB). Allow additional space for the assembled
  image archive, Docker's expanded image, evidence and any source assembly.
- An MCP client that can launch a local stdio server. OpenCyber supplies tools;
  the client supplies the agent and model.

The repository belongs to the `mitkox` organization. External beta testers
join as **outside collaborators with Read access**. You can browse, clone and
download the complete reviewed source, read documentation and report issues;
you cannot push or change repository settings. Organization membership is not
required. The private release download uses that repository access directly;
no GHCR token, Docker login or package grant is needed. Keep the assets private
and retain all original license, source and use restrictions; see
[vendor terms](BETA_VENDOR_TERMS.md). Maintainers: see [beta access](BETA_ACCESS.md).

This first exercise needs no hardware, target credentials, API keys or PoC
signing key. It writes and analyzes one synthetic log without contacting a
target. The launch command below uses the
[blue-team profile](BLUE_TEAM.md#start-an-isolated-case), with no container network.

## 1. Download, verify and start the preview

Authenticate with the GitHub account that received the invitation:

```sh
gh auth login
gh release download v0.5.0-private-beta.1 \
  --repo mitkox/opencyber --dir opencyber-beta
```

For an offline machine, transfer the **whole `opencyber-beta` folder**. Keep
all 14 numbered image/source parts, checksum lists, helper, source snapshot,
notices, SBOMs and metadata together. The numbered parts are no larger than
1 GiB each. Do not extract or load individual parts.

On the Linux amd64 Docker host, use a normal Linux filesystem with room for
the assembled files:

```sh
cd opencyber-beta
bash beta-import.sh --verify-only
bash beta-import.sh
```

`--verify-only` checks the downloaded parts and metadata without assembling
archives or using Docker. The default command verifies and assembles the image,
checks the complete archive hash, and imports it with `docker load`. It checks
the platform, RootFS layers, runtime configuration and source/version labels.
Doctor and the strict MCP self-test then run in disposable containers with no
network, capabilities, devices or host directory mounts, a read-only root and
temporary scratch directories. The helper installs nothing, makes no pulls or
network requests, and creates no persistent container or workspace volume.

An existing archive or image tag is reused only when it matches the recorded
identity. A mismatch stops the helper and preserves the existing bytes or tag.
A pre-existing `.partial` file is preserved; inspect and move or remove that
incomplete file before retrying. Keep the original parts until import passes.
Checksums detect damaged or changed bytes; obtain the bundle and its expected
identity through the maintainer's authenticated release.

To assemble the captured third-party source archive as well, allow more disk
space and run:

```sh
bash beta-import.sh --assemble-source
```

The complete first-party archive is already supplied. Extract it into a **new**
directory:

```sh
mkdir source-c120197
tar -xzf opencyber-source-c120197.tar.gz -C source-c120197
```

Use unused container and volume names. If either name exists, choose different
names in both the check and launch command:

```sh
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

This creates container `opencyber-beta` and persistent workspace volume
`opencyber-beta`. The blue-team profile disables container networking,
capabilities and device passthrough. Other profiles retain the image's tools
but require the operator's authorization for real targets, network exposure
or hardware. See [Install](INSTALL.md) for the development path and future
qualified candidates. Repository documentation may advance while the supplied
source snapshot and image remain frozen at `c120197`.

Check readiness:

```sh
docker exec opencyber-beta opencyber-doctor --json
docker exec -e OPENCYBER_STRICT_CATALOG=1 opencyber-beta opencyber-mcp --self-test
```

Both commands should exit 0. Doctor should report `status: "ok"` with no problems; the self-test's
`catalog.matches` should be `true` in default full mode. Optional integrations
may be unavailable and are listed separately from `missing_required_tools`,
which should be empty. A healthy container does not prove that a passed-through
device works.

If a check fails, stop here and use [Troubleshooting](TROUBLESHOOTING.md).

## 2. Connect your MCP client

Configure the client to launch this command:

```sh
docker exec -i opencyber-beta opencyber-mcp
```

For clients using a `mcpServers` JSON configuration, the server entry is:

```json
{
  "mcpServers": {
    "opencyber": {
      "command": "docker",
      "args": ["exec", "-i", "opencyber-beta", "opencyber-mcp"]
    }
  }
}
```

Use the appropriate configuration location and format for your client from
[MCP integration](MCP_INTEGRATION.md). Restart or reconnect the client after
changing its configuration. Do not add `-t`: a terminal corrupts the stdio
protocol. Starting the command in a terminal opens a protocol stream, not an
interactive chat.

Ask the client to call `oc_catalog()` and `oc_doctor()`. In default full mode
the catalog advertises 254 tools. Tool availability depends on the image;
registered optional adapters can return `integration_unavailable` with a
remediation. Do not ask the agent to install missing integrations automatically.

## 3. Produce a first result

The `oc_*` examples below are MCP tool calls made by your client, not shell
commands. Have it perform these calls in order. Save the actual engagement ID
from the first response and use it in place of `eng_...` throughout.

```text
oc_engagement_create(
  name="Beta synthetic log",
  targets=["127.0.0.1"],
  objective="Check local evidence handling without target traffic"
)

oc_workspace_write(
  engagement_id="eng_...",
  path="artifacts/beta-events.jsonl",
  content="{\"timestamp\":\"2026-10-25T12:00:00Z\",\"message\":\"Synthetic beta event from 192.0.2.1\"}\n"
)

oc_file_triage(engagement_id="eng_...", path="artifacts/beta-events.jsonl")
oc_log_timeline(engagement_id="eng_...", path="artifacts/beta-events.jsonl", format="jsonl")
oc_audit_verify(engagement_id="eng_...")
```

The triage responses summarize saved reports. Read each returned `report_path`
with `oc_workspace_read` to inspect the individual indicators and event times.
Check the following results:

| Call | What to check |
| --- | --- |
| Create/write | `ok: true`, a new engagement ID, and the file under that engagement |
| File triage | A source SHA-256, `complete: true`, and a `report_path` under `evidence/triage/`; the IPv4 indicators include `192.0.2.1` |
| Timeline | One event at `2026-10-25T12:00:00Z`, complete analysis, and a saved report path |
| Audit verification | `valid: true` for the engagement's hash chain |

To test evidence transfer, select actual report paths returned above together
with the synthetic log:

```text
oc_evidence_export(
  engagement_id="eng_...",
  paths=["artifacts/beta-events.jsonl", "evidence/triage/ACTUAL_REPORT.json"]
)
```

Retain the returned `sha256` separately. Then call `oc_evidence_verify` using
the returned archive `path` and that independently retained value as
`expected_sha256`. Expect `valid: true`. The verifier reads the archive without
extracting it. A successful verification establishes internal consistency and
agreement with your retained hash; it does not establish who originally
produced the evidence.

For the next exercise, use the [blue-team guide](BLUE_TEAM.md) for supplied
PCAPs and logs or the [user guide](USER_GUIDE.md) for an authorized lab target.
Read [PoC chains](POC_CHAINS.md) before using approval-gated execution.

## 4. Send a useful report

Use the private repository's [bug report form](https://github.com/mitkox/opencyber/issues/new/choose)
for ordinary defects. Other invited collaborators may read those reports.
Email suspected vulnerabilities or conduct concerns privately to
[tech@mitkox.com](mailto:tech@mitkox.com); follow [Security](../SECURITY.md)
for the security report details. Keep exploit details and secrets out of issues.

Include:

- Source commit, host architecture, Docker version, image reference/digest and
  MCP client version. Identify a source install or local image build as such.
- The tool name and minimal synthetic arguments needed to reproduce it.
- Expected and observed results, including `error.code`, `coverage` and
  `limitations` when present.
- Whether the failure repeats in a fresh engagement, and which setup step
  first failed.

These commands collect a small starting record:

```sh
docker version --format '{{.Server.Version}}'
docker info --format '{{.Architecture}}'
docker inspect --format '{{.Config.Image}} {{.Image}}' opencyber-beta
docker exec opencyber-beta opencyber-doctor --json > beta-doctor.json
docker exec -e OPENCYBER_STRICT_CATALOG=1 opencyber-beta opencyber-mcp --self-test > beta-self-test.json
```

Review and redact those files before attaching them. Device serial numbers,
paths, target data and credentials can appear in diagnostics and tool results.
Share a synthetic reproduction instead of an engagement workspace, HTTP/browser
state or a full `docker inspect` dump. MCP server stderr is normally in the
client's server log; `docker logs opencyber-beta` does not collect a separate
`docker exec` session's stderr.

## 5. Stop or remove the beta

```sh
docker stop opencyber-beta
docker start opencyber-beta
```

To stop and remove the launcher-created container while keeping its evidence:

```sh
docker stop opencyber-beta
docker rm opencyber-beta
```

The named workspace volume `opencyber-beta` remains. Do not use installer
uninstall commands for this launcher-created container. Removing the volume
destroys every engagement in it; only do so explicitly after saving anything
you need. See [Install](INSTALL.md#uninstall) for that destructive command.
