# Start beta testing 0.5.0

OpenCyber 0.5.0 is being prepared in a private repository. The maintainer adds
beta testers; accept that invitation before cloning. The first public open
source prerelease remains planned. Use an owned lab and synthetic evidence.
Hardware interfaces are experimental and unqualified; production acceptance is
separate.

**Shared container images are not ready yet.** License review and native
platform qualification still block distribution, including private sharing.
Until the maintainer supplies the source commit and image digest below, invited
contributors can use the [source development path](INSTALL.md#path-c-source-install-for-development).
A source install or local image build is an unqualified development build.

## What you need

- A Linux host with Docker Engine on `amd64` or `arm64`, and a user who can
  already run `docker info`.
- Git, GitHub CLI (`gh`), Bash and enough free Docker storage for a large
  Kali-based image and your evidence. The first pull can take time.
- Access to `mitkox/opencyber` and, once images are shared, read access to
  the private GHCR package. Repository access and package access are separate.
- An MCP client that can launch a local stdio server. OpenCyber supplies tools;
  the client supplies the agent and model.

The repository belongs to a personal GitHub account. Its collaborator
invitations include write access, even when you only intend to test. Follow the
contribution process before pushing changes; use the assigned frozen commit
for beta results. Package permissions are configured separately.

This first exercise needs no hardware, target credentials, API keys or PoC
signing key. It writes and analyzes one synthetic log without contacting a
target. For a container with no network at all, use the
[blue-team profile](BLUE_TEAM.md#start-an-isolated-case).

## 1. Access the source and install the assigned candidate

Authenticate with the GitHub account that received the invitation:

```sh
gh auth login
gh repo clone mitkox/opencyber
cd opencyber
```

Before installing a shared image, get these two values from the maintainer:

| Value | Required identity |
| --- | --- |
| `BETA_SOURCE_COMMIT` | Full commit ID for the reviewed source snapshot |
| `BETA_PLATFORM_DIGEST` | Complete `sha256:` digest qualified for your host's `linux/amd64` or `linux/arm64` platform |

Check your architecture with `docker info --format '{{.Architecture}}'`.
Replace both placeholders below with the supplied values. Do not substitute a
tag, a digest for another architecture or a locally built image.

```sh
BETA_SOURCE_COMMIT='REPLACE_WITH_FULL_COMMIT_FROM_MAINTAINER'
BETA_PLATFORM_DIGEST='sha256:REPLACE_WITH_PLATFORM_DIGEST_FROM_MAINTAINER'
git checkout --detach "$BETA_SOURCE_COMMIT"
git rev-parse HEAD
```

For GHCR authentication, create a GitHub personal access token **(classic)**
with `read:packages`. Use an account that has read access to the private
package. Enter the token at Docker's password prompt:

```sh
docker login ghcr.io --username YOUR_GITHUB_USERNAME
```

Use the token as the password, not your GitHub account password. Keep it out of
shell commands, MCP configuration, images and reports. `gh auth login` and
`docker login` authenticate different clients; doing one does not replace the
other. A denied pull can mean missing package permission even when cloning works.

From the pinned source checkout:

```sh
docker info
less install.sh
OPENCYBER_IMAGE=ghcr.io/mitkox/opencyber-beta-candidates \
  bash install.sh --version 0.5.0 --digest "$BETA_PLATFORM_DIGEST"
```

The installer creates container `opencyber` and persistent volume
`opencyber-workspace`. It refuses to replace an unrelated container with that
name. Keep this checkout for uninstall. See [Install](INSTALL.md) for custom
names, manual containers and local development builds. Public release tags and
promotion attestations are not prerequisites for this private candidate path.

Check readiness:

```sh
docker exec opencyber opencyber-doctor --json
docker exec -e OPENCYBER_STRICT_CATALOG=1 opencyber opencyber-mcp --self-test
```

Both commands should exit 0. Doctor should report `healthy`; the self-test's
`catalog.matches` should be `true` in default full mode. Optional integrations
may be unavailable and are listed separately from `missing_required_tools`,
which should be empty. A healthy container does not prove that a passed-through
device works.

If a check fails, stop here and use [Troubleshooting](TROUBLESHOOTING.md).

## 2. Connect your MCP client

Configure the client to launch this command:

```sh
docker exec -i opencyber opencyber-mcp
```

For clients using a `mcpServers` JSON configuration, the server entry is:

```json
{
  "mcpServers": {
    "opencyber": {
      "command": "docker",
      "args": ["exec", "-i", "opencyber", "opencyber-mcp"]
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
the catalog advertises 255 tools. Tool availability depends on the image;
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
docker inspect --format '{{.Config.Image}} {{.Image}}' opencyber
docker exec opencyber opencyber-doctor --json > beta-doctor.json
docker exec -e OPENCYBER_STRICT_CATALOG=1 opencyber opencyber-mcp --self-test > beta-self-test.json
```

Review and redact those files before attaching them. Device serial numbers,
paths, target data and credentials can appear in diagnostics and tool results.
Share a synthetic reproduction instead of an engagement workspace, HTTP/browser
state or a full `docker inspect` dump. MCP server stderr is normally in the
client's server log; `docker logs opencyber` does not collect a separate
`docker exec` session's stderr.

## 5. Stop or remove the beta

```sh
docker stop opencyber
docker start opencyber
```

To remove the installer-managed container while keeping all evidence:

```sh
bash install.sh --uninstall
```

The workspace volume remains. `--purge-workspace` also destroys the managed
volume and every engagement in it; use it only after saving anything you need.
See [Install](INSTALL.md#uninstall) for the destructive removal command.
