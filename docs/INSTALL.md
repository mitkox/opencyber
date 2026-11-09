# Installing OpenCyber Harness

The invited-tester [v0.5.0-private-beta.1 release](https://github.com/mitkox/opencyber/releases/tag/v0.5.0-private-beta.1)
is available for Linux amd64. Start with [Beta testing](BETA_TESTING.md) for a
synthetic first result. The preview is unqualified: native amd64, hardware and
production acceptance, vendor reviews and license metadata follow-ups remain
open. Private access does not establish legal clearance or waive third-party
terms. Public publication and broader distribution require separate approval.

> Install and use OpenCyber Harness only on systems you own or are explicitly authorized to assess. The software provides capability, not permission.

## Support matrix

OpenCyber Harness is Linux/POSIX only. There is no PyPI package and no Windows-native install path.

| Path | Best for | Requirements | What you get |
| --- | --- | --- | --- |
| Published private preview | Invited beta testing today | Native Linux amd64 Docker engine, Bash, Python 3 and the complete release download | Full toolkit, browser and offline assets; launcher-created offline container and persistent volume |
| `install.sh` for a future qualified candidate | A managed local container after the maintainer supplies a qualified digest | Docker Engine, Bash, matching source and platform digest, supported registry access or an assigned archive | Selected image, started hardened, with a managed workspace volume and a self-test |
| Source install | Development and MCP-contract work | Python 3.11 through 3.13, a POSIX system | The Python package and entry points only; no Kali toolchain, browser binary, or offline asset store |

The private preview retains the full toolkit, including Oracle tooling and
PDB components. Terrascan and ScoutSuite remain optional and excluded because
of their maintenance and vulnerability status. A source install is useful for
unit tests and server development; executable-backed tools report
`available: false` when their binaries are absent.

## Private preview: download and import

After accepting the repository invitation, download while connected:

```sh
gh auth login
gh release download v0.5.0-private-beta.1 \
  --repo mitkox/opencyber --dir opencyber-beta
```

Outside collaborators with repository **Read access** can download these
assets. GitHub CLI is needed only on the connected machine. No GHCR token,
Docker login or registry pull is required. The 38 assets total 13,310,405,014
bytes (about 13.3 GB). Transfer the **whole folder** to an offline machine,
including all 14 numbered image/source parts, checksum lists, source snapshot,
notices, SBOMs, metadata and helper. Keep it private. See
[beta access](BETA_ACCESS.md) for invitations.

On the native Linux amd64 Docker host, use Bash and Python 3 on a normal Linux
filesystem with additional space for the assembled image archive and Docker's
expanded image:

```sh
cd opencyber-beta
bash beta-import.sh --verify-only
bash beta-import.sh
```

The first command verifies parts and metadata without using Docker or
assembling archives. The default command verifies and assembles the image,
checks its complete hash, and uses `docker load`. It verifies the archive and
imported image against the supplied platform, RootFS layers, runtime
configuration and source/version labels, then runs doctor and the strict MCP
self-test in disposable containers with a read-only root, no network or
capabilities, and temporary scratch directories. It makes no network requests
and leaves no persistent container or volume.

Existing archives and the image tag are reused only when their identities
match. Mismatches stop without replacing existing bytes or the tag. A
pre-existing `.partial` file is preserved; inspect and move or remove that
incomplete file before retrying. Keep the original parts until import passes.
Checksums detect damaged or changed bytes; obtain the bundle and its expected
identity from the maintainer's authenticated release.

To assemble the captured third-party source archive too, allow more storage:

```sh
bash beta-import.sh --assemble-source
```

The first-party source is already complete as
`opencyber-source-c120197.tar.gz`, at revision
`c1201976caf49c45068bb507032aee75e4509e20`. The local image is
`opencyber:0.5.0-private-beta.1-amd64`. Continue with
[Path B](#path-b-manual-container) to start the preview. New repository
documentation does not change the frozen source snapshot or image parts.

## Path A: installer-managed candidate

**For a future qualified candidate.** The published private-beta.1 bundle uses
the helper and launcher above. `install.sh` expects a `X.Y.Z` version and does
not select its suffixed local preview tag.

After the maintainer supplies a qualified candidate, obtain its full
`BETA_SOURCE_COMMIT` and complete `BETA_PLATFORM_DIGEST` for your architecture.
Authenticate and select that source:

```sh
gh auth login
gh repo clone mitkox/opencyber
cd opencyber
BETA_SOURCE_COMMIT='REPLACE_WITH_FULL_QUALIFIED_COMMIT_FROM_MAINTAINER'
BETA_PLATFORM_DIGEST='sha256:REPLACE_WITH_QUALIFIED_PLATFORM_DIGEST_FROM_MAINTAINER'
git checkout --detach "$BETA_SOURCE_COMMIT"
git rev-parse HEAD
docker info --format '{{.Architecture}}'
```

Registry delivery also requires supported package access verified by the
maintainer. Repository Read access does not automatically grant private GHCR
access. For that future path, use a GitHub personal access token **(classic)**
with `read:packages` and an account with package permission:

```sh
docker login ghcr.io --username YOUR_GITHUB_USERNAME
```

Enter the token at Docker's password prompt. Keep it out of commands, MCP
configuration, images and reports. This separate login is not needed for the
published archive preview.

`install.sh` pulls the selected image, creates the workspace volume, starts a
hardened container and runs the MCP self-test. Run it as a host user who can
already access Docker. It labels what it creates and refuses to replace a
container it does not manage; uninstall also refuses to purge an unmanaged volume.

```sh
less install.sh
OPENCYBER_IMAGE=ghcr.io/mitkox/opencyber-beta-candidates \
  bash install.sh --version 0.5.0 --digest "$BETA_PLATFORM_DIGEST"
```

Keep this source checkout for uninstall. The installer defaults to container `opencyber` and volume
`opencyber-workspace`; it does not install software into the host system.

The default install is hardened:

- All capabilities dropped, then only `NET_RAW`, `NET_ADMIN`, and `NET_BIND_SERVICE` added.
- `no-new-privileges`.
- Read-only root filesystem with disposable tmpfs mounts at `/tmp`, `/run`, `/root/.config`, `/root/.cache`, `/root/.local/share`, `/root/.nxc`, and `/root/.msf4`. The last three support AutoRecon and NetExec state.
- A persistent Docker volume mounted at `/workspace`.

### Options

| Option | Effect |
| --- | --- |
| `--version VERSION` | Install a specific release. Default: `0.5.0`. Must look like `X.Y.Z`. |
| `--digest SHA256` | Pin the image by digest instead of tag. Format: `sha256:` followed by 64 lowercase hex characters. |
| `--offline` | Do not pull. Use a locally imported image and set `OPENCYBER_OFFLINE=1` in the container. |
| `--verify-attestation` | Run `gh attestation verify` before starting. Requires `gh` and network access. Cannot be combined with `--offline`. |
| `--no-read-only` | Keep the container root filesystem writable. Less hardened; use only when a tool needs it. |
| `--uninstall` | Remove the installer-managed container. |
| `--purge-workspace` | With `--uninstall`, also remove the workspace volume. |
| `-h`, `--help` | Print usage. |

Environment overrides: `OPENCYBER_VERSION`, `OPENCYBER_DIGEST`, `OPENCYBER_IMAGE`, `OPENCYBER_CONTAINER_NAME`, `OPENCYBER_VOLUME_NAME`.

The installer verifies that the image's `com.opencyber.harness.version` label equals the requested version before starting anything. When you pin a digest, pass the matching `--version` as well; the default is `0.5.0`.

### Install a digest

Use the complete `sha256:` platform digest supplied by the maintainer and
`--version 0.5.0`, with `OPENCYBER_IMAGE` set to the private candidate repository
as shown above. Do not use an example, an abbreviated digest or the digest for
another architecture.

Digest pinning protects against a moving tag. `--verify-attestation` is for
images with a recorded GitHub build attestation. The published archive preview
is a separate, unqualified delivery and does not supply public promotion
attestations. Public release gates remain in [Release](RELEASE.md).

## Path B: manual container

For the published private preview, stay in the downloaded `opencyber-beta`
folder after import. Extract the first-party snapshot into a **new** directory:

```sh
mkdir source-c120197
tar -xzf opencyber-source-c120197.tar.gz -C source-c120197
```

Use unused container and volume names. If either exists, choose different names
in both the check and launch command:

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

The blue-team profile uses no network, capabilities or device passthrough, a
read-only root, temporary scratch directories and the persistent named volume
`opencyber-beta` at `/workspace`. The image command is `sleep infinity`; MCP
clients use `docker exec -i opencyber-beta opencyber-mcp`, without `-t`, to
start the stdio server. See [MCP integration](MCP_INTEGRATION.md) and substitute
this container name in client examples.

For an authorized network or hardware lab, inspect the launcher's `--dry-run`
output for the chosen profile before starting it. Profiles are listed in
[Hardware](HARDWARE.md). `--offline` by itself sets a feature flag; the
blue-team profile's `--network none` removes networking. Manual and
launcher-created containers are not installer-managed. Use the Docker cleanup
commands in [Uninstall](#uninstall), which preserve the named volume.

## Path C: source install for development

Use this separate path for Python development. After accepting the repository
invitation, clone and record the commit you test. Use a source commit requested
by the maintainer, or record the current `HEAD` for development:

```sh
gh auth login
gh repo clone mitkox/opencyber
cd opencyber
git rev-parse HEAD
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[test,dev]'
```

This installs the Python package, including MCP Python SDK 2.x, and these
console entry points:

| Command | Purpose |
| --- | --- |
| `opencyber-mcp` | The stdio MCP server. |
| `opencyber-doctor` | Readiness probe; exits non-zero when degraded. |
| `opencyber-assets` | Inspect and verify offline assets. |
| `opencyber-hardware` | Host-side hardware inventory and readiness. |
| `opencyber-poc` | Operator authorization and single-use PoC approval CLI. |

Run the test suite with:

```sh
python -m unittest discover -s tests -v
```

A source install lacks the Kali toolchain, the Chromium browser binary installed by the image build, and the offline asset store. `opencyber-doctor` will report those gaps. Use it to develop the MCP contract, not to run real assessments.

### Local image development

To exercise the image build on your own host:

```sh
docker build --provenance=false -t opencyber-beta:0.5.0 .
OPENCYBER_IMAGE=opencyber-beta bash install.sh --offline --version 0.5.0
```

This may download substantial build dependencies. It produces an unqualified
development image and does not satisfy the redistribution or release gates.
The `--offline` installer option uses that local image without pulling and sets
the runtime's offline feature flag; it does not disable the container network.

## Verify the install

From the host, check the running preview container. For a future installer
candidate, substitute its container name (default `opencyber`):

```sh
docker exec opencyber-beta opencyber-doctor
docker exec -e OPENCYBER_STRICT_CATALOG=1 opencyber-beta opencyber-mcp --self-test
docker exec opencyber-beta opencyber-assets --verify
```

| Check | What it proves | Failure behavior |
| --- | --- | --- |
| `opencyber-doctor` | Catalog executables, templates, wordlists, offline assets, asset manifest, browser, analysis runtime, agent shell | Prints `status degraded`, lists problems, exits 1 |
| `opencyber-mcp --self-test` | Required executables resolve; optional omissions and tool counts are reported | Exits 1 for missing required executables; with `OPENCYBER_STRICT_CATALOG=1`, also fails a recorded-catalog mismatch |
| `opencyber-assets --verify` | Installed offline assets match the build-time manifest | Exits 1 on a missing or mismatched required asset |
| `opencyber-doctor --quiet` | Health-probe form; prints only problems | Exits 1 when degraded |
| `opencyber-doctor --json` | Machine-readable full report | Exits 1 when degraded |

Record the image used by your running container:

```sh
docker inspect --format '{{.Config.Image}} {{.Image}}' opencyber-beta
```

The preview reference should be `opencyber:0.5.0-private-beta.1-amd64`; the
helper checks its runtime identity against the release metadata. For a future
qualified registry candidate, the configured reference should contain the
platform digest supplied by the maintainer. A local image ID is a separate
identity; do not substitute it for a registry digest in `install.sh --digest`.

Passing these probes does not establish live Oracle/PDB, hardware or all-tool
acceptance. Candidate qualification requires matching source and platform identities,
vulnerability and license checks, native software acceptance, provenance and
SBOMs. Eventual public publication also requires acceptance on both
`linux/amd64` and public access checks. The installer self-test
does not replace those gates. See [Release](RELEASE.md) for the maintainer process.

## Upgrade

Re-run the installer with the new version or digest. The managed container is replaced, but the `opencyber-workspace` volume is never recreated, so engagements and evidence survive the upgrade. To roll back, re-run the installer with the previous version or digest; the workspace is preserved the same way. `--uninstall` keeps the volume unless `--purge-workspace` is also supplied.


The private-beta.1 assets remain frozen. Repository documentation updates do
not update the installed image. For a later preview, use its release-specific
download, import and upgrade instructions, and back up the workspace first.

For a future **installer-managed qualified candidate**, keep its matching
source checkout and digest to reinstall it:

```sh
OPENCYBER_IMAGE=ghcr.io/mitkox/opencyber-beta-candidates \
  bash install.sh --version 0.5.0 --digest "$BETA_PLATFORM_DIGEST"
```

For an updated candidate, use the new source commit and matching platform
digest supplied by the maintainer, and read its change notes. For a future
version, also pass its matching `--version`. Back up the workspace first. The
installer preserves the existing managed container during replacement as
`<name>-rollback-<epoch>`. If the replacement fails to start or fails the MCP
self-test, the trap attempts to restore the previous container. After a
successful replacement, the backup container is removed. The workspace volume
is preserved; the installer does not migrate its contents.

The installer refuses to replace a container that lacks its management label, and uninstall refuses to purge a volume that lacks it. If the name is already taken by something else, rename or remove that container first.

## Roll back

The private preview launcher has no upgrade or rollback operation. Retain the
release parts and source snapshot, and back up evidence before changing images.

For an installer-managed candidate, there is no separate rollback flag. A failed replacement attempts to restore
the previous managed container automatically. An operator can reinstall a
previously retained candidate/version/digest pair after checking data compatibility.
Keep its complete digest and validation records; do not guess a previous tag.

Engagement data lives in the workspace volume and is not migrated or deleted by a version change. Before downgrading across a schema change, copy any evidence you need out of the volume.

## Uninstall

For the published preview's launcher-created container:

```sh
docker stop opencyber-beta
docker rm opencyber-beta
```

The named volume `opencyber-beta` remains with all evidence. To restart a
stopped container, use `docker start opencyber-beta` before removing it.

Only when the operator explicitly intends to delete that evidence, after
saving anything needed:

```sh
docker volume rm opencyber-beta
```

**This destroys every engagement in that volume**, including findings,
HTTP/browser state, serial transcripts and audit logs. Docker volume removal
does not guarantee secure erasure. Do not use `install.sh --uninstall` for a
launcher-created container.

For a future installer-managed candidate, from its retained source checkout:

```sh
bash install.sh --uninstall
```

This removes only the installer-managed container. The workspace volume is preserved.

```sh
bash install.sh --uninstall --purge-workspace
```

This also removes the managed volume. **All engagements, evidence, findings, HTTP history, browser artifacts, serial transcripts, and audit logs are destroyed.** The installer refuses to remove an unmanaged volume. Docker volume removal does not guarantee secure erasure of the underlying storage.

## Airgapped install

For the published private preview, download the whole release folder while
connected, transfer it intact, and run `beta-import.sh` as described
[above](#private-preview-download-and-import). Neither import nor the
blue-team launch requires network access. No registry login or pull is needed
on the offline machine.

For a **local development build**, the separate airgap script moves your image:

```sh
./scripts/opencyber-airgap.sh export --image opencyber-beta:0.5.0 --output /media/usb/opencyber
./scripts/opencyber-airgap.sh verify --input /media/usb/opencyber
./scripts/opencyber-airgap.sh import --input /media/usb/opencyber
OPENCYBER_IMAGE=opencyber-beta bash install.sh --offline --version 0.5.0
```

`verify` checks the archive checksum and `import` runs `opencyber-doctor --quiet` before declaring success. `install.sh --offline` refuses to pull and requires the matching image to be present locally. Offline mode is not an egress firewall; see [AIRGAP.md](AIRGAP.md) and [SECURITY_MODEL.md](SECURITY_MODEL.md).

The example exports `opencyber-beta:0.5.0`, so it also overrides the installer's
repository to `opencyber-beta`. Keep export and install references consistent.
Transfer to another user remains subject to the image redistribution gates;
airgap export does not establish qualification or license clearance.

## Command-line entry points

| Command | Main options | Notes |
| --- | --- | --- |
| `opencyber-mcp` | `--self-test`, `--catalog-json` | Default action runs the stdio MCP server. `--catalog-json` prints the 174 executable-backed catalog entries. |
| `opencyber-doctor` | `--quiet`, `--json` | Exit 1 when degraded. Used as the container healthcheck. |
| `opencyber-assets` | `--json`, `--deep`, `--verify`, `--offline`, `--write PATH` | Human-readable text by default. Status, verify, and offline modes exit non-zero when required assets are missing or mismatched. |
| `opencyber-hardware` | `--inventory`, `--readiness` (default), `--plan DOMAIN`, `--json` | Works without an MCP client. |
| `python -m opencyber.cve_index` | `--year`, `--years`, `--feed`, `--output`, `--download-dir`, `--max-records`, `--no-verify` | Builds a local NVD-derived SQLite index for offline `oc_cve_lookup`. |

## Next steps

- [USER_GUIDE.md](USER_GUIDE.md): create an engagement and run the first scan.
- [BETA_TESTING.md](BETA_TESTING.md): synthetic first exercise and a useful bug report.
- [MCP_INTEGRATION.md](MCP_INTEGRATION.md): connect a client to the stdio server.
- [HARDWARE.md](HARDWARE.md): pass radios, serial adapters, and debug probes into the container.
