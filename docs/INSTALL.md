# Installing OpenCyber Harness

OpenCyber 0.5.0 is in private beta preparation. The maintainer invites testers
to the private repository; a public release is still planned. Start with
[Beta testing](BETA_TESTING.md) for authentication and a synthetic first result.

Shared images are not ready yet: license review and native platform
qualification still block distribution, including private sharing. The image
paths below apply only after the maintainer provides a qualified source commit
and exact platform digest. Invited contributors can use the source development
path now. A local image build remains an unqualified development artifact.

> Install and use OpenCyber Harness only on systems you own or are explicitly authorized to assess. The software provides capability, not permission.

## Support matrix

OpenCyber Harness is Linux/POSIX only. There is no PyPI package and no Windows-native install path.

| Path | Best for | Requirements | What you get |
| --- | --- | --- | --- |
| Assigned private candidate | Authorized lab and beta testing after image distribution is cleared | Docker Engine on the qualified `linux/amd64` or `linux/arm64` platform, private package read access | Bundled executable integrations, browser, wordlists, templates, and experimental hardware tooling; optional adapters are identified by the catalog |
| `install.sh` | A managed local container with verification | Docker Engine, Bash, the selected image | The same image, started hardened, with a persistent workspace volume and a self-test |
| Source install | Development and MCP-contract work | Python 3.11 through 3.13, a POSIX system | The Python package and entry points only; no Kali toolchain, browser binary, or offline asset store |

The container image is the intended beta runtime. The maintainer's candidate
records identify which platform digests passed software acceptance. Hardware
interfaces remain experimental and unqualified unless qualification records
identify a tested device/platform combination. This prerelease does not
establish production suitability. A source install is useful for unit tests
and server development; executable-backed tools report `available: false`
when their binaries are absent.

## Authenticate and select the source

After accepting the repository invitation:

```sh
gh auth login
gh repo clone mitkox/opencyber
cd opencyber
```

For a shared image, obtain `BETA_SOURCE_COMMIT` and `BETA_PLATFORM_DIGEST` from
the maintainer. Replace these placeholders with the supplied full commit and
the complete `sha256:` digest for your architecture:

```sh
BETA_SOURCE_COMMIT='REPLACE_WITH_FULL_COMMIT_FROM_MAINTAINER'
BETA_PLATFORM_DIGEST='sha256:REPLACE_WITH_PLATFORM_DIGEST_FROM_MAINTAINER'
git checkout --detach "$BETA_SOURCE_COMMIT"
git rev-parse HEAD
docker info --format '{{.Architecture}}'
```

For GHCR, create a GitHub personal access token **(classic)** with
`read:packages`, using the invited account with package read permission:

```sh
docker login ghcr.io --username YOUR_GITHUB_USERNAME
```

Enter the token at the password prompt, not your GitHub password. Keep it out
of shell commands, MCP configuration, images and reports. GitHub CLI login
does not authenticate Docker; repository read access does not automatically
grant private package access. The maintainer adds beta users and grants access.

Choose one container path below. The installer and manual/launcher paths use
the same default container name, so do not combine them for one installation.

## Path A: installer-managed candidate

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
- Read-only root filesystem with tmpfs mounts at `/tmp`, `/run`, `/root/.config`, and `/root/.cache`.
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

Digest pinning protects against a moving tag. Public promotion attestations
and the canonical release tag do not exist yet. `--verify-attestation` is for
images with a recorded GitHub build attestation; it is not required for this
private candidate path.

## Path B: manual container

After Docker login, pull the exact assigned image and apply these hardened flags:

```sh
BETA_IMAGE="ghcr.io/mitkox/opencyber-beta-candidates@$BETA_PLATFORM_DIGEST"
docker pull "$BETA_IMAGE"
docker run -d --name opencyber \
  --restart unless-stopped \
  --cap-drop=ALL \
  --cap-add=NET_RAW --cap-add=NET_ADMIN --cap-add=NET_BIND_SERVICE \
  --security-opt no-new-privileges \
  --read-only \
  --tmpfs /tmp --tmpfs /run --tmpfs /root/.config --tmpfs /root/.cache \
  -v opencyber-workspace:/workspace \
  "$BETA_IMAGE"
```

The image command is `sleep infinity`; MCP clients use `docker exec` to start
the stdio server. The `/root/.config` and `/root/.cache` tmpfs mounts are required
under a read-only root filesystem because Chromium's crashpad handler needs them.

The launcher is an alternative that adds device passthrough for a profile:

```sh
./scripts/opencyber-run.sh --image "$BETA_IMAGE" --profile software --dry-run
```

Inspect the printed command, then remove `--dry-run` to start it. Profiles are
listed in [HARDWARE.md](HARDWARE.md). Manual and launcher-created containers
are not installer-managed. Remove them with `docker rm -f opencyber` when you
intend to stop and delete the container; its named workspace volume remains.

## Path C: source install for development

From the authenticated source checkout above, record the commit you test.
This path can be used before candidate images are available; use the source
commit requested by the maintainer, or record the current `HEAD` for development.

```sh
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

From the host, check the running container:

```sh
docker exec opencyber opencyber-doctor
docker exec -e OPENCYBER_STRICT_CATALOG=1 opencyber opencyber-mcp --self-test
docker exec opencyber opencyber-assets --verify
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
docker inspect --format '{{.Config.Image}} {{.Image}}' opencyber
```

The configured reference should contain the platform digest supplied by the
maintainer. The local image ID is a separate identity; do not substitute it
for the registry platform digest in `install.sh --digest`.

Candidate qualification requires matching source and platform identities,
vulnerability and license checks, native software acceptance, provenance and
SBOMs. Eventual public publication also requires acceptance on both
`linux/amd64` and `linux/arm64` and public access checks. The installer self-test
does not replace those gates. See [Release](RELEASE.md) for the maintainer process.

## Upgrade

To reinstall the same assigned candidate, keep its source checkout and digest:

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

There is no separate rollback flag. A failed replacement attempts to restore
the previous managed container automatically. An operator can reinstall a
previously retained candidate/version/digest pair after checking data compatibility.
Keep its complete digest and validation records; do not guess a previous tag.

Engagement data lives in the workspace volume and is not migrated or deleted by a version change. Before downgrading across a schema change, copy any evidence you need out of the volume.

## Uninstall

```sh
bash install.sh --uninstall
```

This removes only the installer-managed container. The workspace volume is preserved.

```sh
bash install.sh --uninstall --purge-workspace
```

This also removes the managed volume. **All engagements, evidence, findings, HTTP history, browser artifacts, serial transcripts, and audit logs are destroyed.** The installer refuses to remove an unmanaged volume. Docker volume removal does not guarantee secure erasure of the underlying storage.

## Airgapped install

For a local development build, move your image with the airgap script:

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
| `opencyber-mcp` | `--self-test`, `--catalog-json` | Default action runs the stdio MCP server. `--catalog-json` prints the 173 executable-backed catalog entries. |
| `opencyber-doctor` | `--quiet`, `--json` | Exit 1 when degraded. Used as the container healthcheck. |
| `opencyber-assets` | `--json`, `--deep`, `--verify`, `--offline`, `--write PATH` | Human-readable text by default. Status, verify, and offline modes exit non-zero when required assets are missing or mismatched. |
| `opencyber-hardware` | `--inventory`, `--readiness` (default), `--plan DOMAIN`, `--json` | Works without an MCP client. |
| `python -m opencyber.cve_index` | `--year`, `--years`, `--feed`, `--output`, `--download-dir`, `--max-records`, `--no-verify` | Builds a local NVD-derived SQLite index for offline `oc_cve_lookup`. |

## Next steps

- [USER_GUIDE.md](USER_GUIDE.md): create an engagement and run the first scan.
- [BETA_TESTING.md](BETA_TESTING.md): synthetic first exercise and a useful bug report.
- [MCP_INTEGRATION.md](MCP_INTEGRATION.md): connect a client to the stdio server.
- [HARDWARE.md](HARDWARE.md): pass radios, serial adapters, and debug probes into the container.
