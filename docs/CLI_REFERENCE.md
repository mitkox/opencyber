# CLI reference

The connection examples use the current beta guide's container name,
`opencyber-beta`. Complete [beta setup](BETA_TESTING.md) first; substitute your
container name if you chose a different one. The MCP server ID stays `opencyber`.

Flags, output behavior, and exit codes for the 0.5.0 private pre-production beta. New testers should begin with [BETA_TESTING.md](BETA_TESTING.md); this page is the lookup reference.

## Conventions

| Code | Meaning |
| ---: | --- |
| `0` | Success, healthy, or consistent. |
| `1` | Operational failure: degraded doctor, missing or mismatched asset, failed check, refused operation, or an uncaught error. |
| `2` | Usage error reported by `argparse` or a script's argument check. |

- All commands write human-readable output to stdout by default unless a command says otherwise.
- `--json` selects machine-readable output on the commands that support it. It changes formatting, not the exit code.
- None of these commands starts a daemon or opens a listening port. `opencyber-mcp` is a stdio process.
- Inside the image, the console scripts are on `PATH` through `/opt/opencyber-venv/bin`.

## `opencyber-mcp`

The MCP server and its self-test entry points. With no arguments it serves MCP over stdio until stdin closes.

| Flag | Effect |
| --- | --- |
| `--self-test` | Print a JSON readiness object and exit. Checks required catalog executables and reports optional integrations, reports tool counts, workspace, browser runtime, and analysis runtime. |
| `--catalog-json` | Print the complete 174-entry executable catalog as a JSON array, regardless of `OPENCYBER_MCP_MODE` or `OPENCYBER_TOOL_CATEGORIES`. |
| `-h`, `--help` | Print usage and exit 0. |

```sh
docker exec -i opencyber-beta opencyber-mcp
docker exec opencyber-beta opencyber-mcp --self-test
docker exec opencyber-beta opencyber-mcp --catalog-json | jq 'length'
```

| Situation | Exit |
| --- | ---: |
| Normal server shutdown or successful self-test/catalog print | `0` |
| `--self-test` finds a missing required executable or a real catalog mismatch under `OPENCYBER_STRICT_CATALOG=1` | `1` |
| Unknown option or missing argument value | `2` |
| Import-time failure, for example an unknown `OPENCYBER_TOOL_CATEGORIES` value | `1` (Python traceback) |

`--self-test` output includes `status`, `version`, `external_tools`, `available_external_tools`, `missing_external_tools`, `registered_external_tools`, `total_mcp_tools`, `mcp_mode`, `workspace`, `browser_runtime`, and `analysis_runtime`. It also reports the live/recorded catalog digests, profile and alignment. It checks required executable presence, not offline assets, templates, browser launch, hardware operation, or audit validity. Use `opencyber-doctor` for the full readiness decision.

`--self-test` and `--catalog-json` are mutually independent, but `--self-test` is evaluated first if both are supplied. The server has no `--version` flag; the version is reported by `--self-test` and in the MCP initialize response.

Do not pass `-t` to `docker exec` for a live session. A TTY can corrupt stdio framing. Use `-i`.

## `opencyber-doctor`

Full harness readiness: catalog, nuclei templates, wordlists, offline assets, asset manifest, hardware readiness, browser, analysis runtimes, and agent shell tools.

| Flag | Effect |
| --- | --- |
| `--quiet` | Print only problems, to stderr. Used by the Docker healthcheck. |
| `--json` | Print the full report as JSON. Takes precedence over `--quiet` when both are passed. |
| `-h`, `--help` | Print usage and exit 0. |

```sh
docker exec opencyber-beta opencyber-doctor
docker exec opencyber-beta opencyber-doctor --json
docker exec opencyber-beta opencyber-doctor --quiet
```

| Report state | Exit |
| --- | ---: |
| `status: ok` | `0` |
| `status: degraded` | `1` |
| Usage error | `2` |

Top-level JSON keys: `status`, `version`, `mcp`, `nuclei_templates`, `offline_assets`, `asset_manifest`, `hardware`, `offline_mode`, `wordlists`, `agent_tools`, `analysis_runtime`, `problems`. `problems` is the list that drives the exit code and the quiet output.

A missing asset manifest (`asset_manifest.available: false`) is reported but is not itself a doctor problem. A present manifest that does not match makes the doctor degraded. Hardware domains that are `tooling_ready` but have no device do not make the doctor degraded; a container without radios can be a healthy software harness.

## `opencyber-assets`

Inspect, verify, or write the offline asset inventory. Human-readable output is the default; `--json` is the machine interface.

| Flag | Effect |
| --- | --- |
| `--json` | Emit JSON instead of human-readable text. |
| `--deep` | Hash asset contents. Expensive on Seclists, exploitdb, and the template store; intended for spot checks. |
| `--verify` | Compare measured required assets with the installed build manifest. Optional assets are not compared. |
| `--write PATH` | Measure the assets and write a new manifest to `PATH`. |
| `--offline` | Print offline posture: mode, asset readiness, missing required assets, and blocked executables. |
| `-h`, `--help` | Print usage and exit 0. |

If more than one mode flag is supplied, precedence is `--write` > `--verify` > `--offline` > status.

| Invocation | Meaning | Exit |
| --- | --- | ---: |
| `opencyber-assets` | Measure all assets | `0` if all required assets are ready, otherwise `1` |
| `opencyber-assets --json --deep` | Same, with content hashes | Same as above |
| `opencyber-assets --verify` | Compare with the manifest | `0` if valid, `1` if invalid or no manifest is available |
| `opencyber-assets --verify --deep` | Include content-hash comparison | Same as above |
| `opencyber-assets --offline` | Print airgap posture | `0` if required assets are ready, otherwise `1` |
| `opencyber-assets --write /path/manifest.json` | Write a fresh manifest | `0` unless the write fails |

`--write` does not validate first; it records what it measures, including missing required assets. Writing a manifest over a deployed image without understanding the change can mask a truncated asset store and makes future verification meaningless.

Human output differs by mode:

```text
# default
status          ok
assets          13/13 required present

# --verify
asset manifest  /usr/share/opencyber/asset-manifest.json
status          ok

# --offline
mode            airgapped
assets ready    yes
missing         none
blocked tools   censys, sherlock, shodan, subfinder, theHarvester
```

`--json` returns the full `assets`, `missing_required`, `missing_optional`, `ready`, and `summary` structure for status; `available`, `valid`, `path`, and `mismatches` for verify; the offline posture object for `--offline`; and `path` plus missing counts for `--write`.

## `opencyber-hardware`

Hardware inventory and per-domain readiness without an MCP client.

| Flag | Effect |
| --- | --- |
| `--inventory` | Emit the full inventory: platform, capabilities, USB, serial, network, Bluetooth, video, input, device nodes, known devices, summary, and access counts. |
| `--readiness` | Emit per-domain readiness. This is the default. |
| `--plan DOMAIN` | Emit the deterministic playbook for one domain. |
| `--json` | Emit JSON instead of human-readable text. |
| `-h`, `--help` | Print usage and exit 0. |

If flags are combined, precedence is `--plan` > `--inventory` > readiness.

`--plan` domains: `usb`, `sdr`, `wifi`, `bluetooth`, `nfc`, `jtag`, `serial`, `automotive`, `logic`, `gps`, `ir`, `firmware`.

```sh
docker exec opencyber-beta opencyber-hardware
docker exec opencyber-beta opencyber-hardware --inventory --json
docker exec opencyber-beta opencyber-hardware --plan sdr
docker exec opencyber-beta opencyber-hardware --plan serial --json
```

| Situation | Exit |
| --- | ---: |
| Report printed | `0` |
| Unknown plan domain | `2` (`argparse` error) |
| Usage error | `2` |
| Uncaught inventory error | `1` |

Human readiness output lists each domain, its status (`ready`, `tooling_ready`, or `unavailable`), device count, missing tools, and the host flags that would expose the missing hardware. `ready` means the tools are installed and a matching device is visible; `tooling_ready` means the tools are present but the host has not passed hardware through. Neither status establishes real-device qualification. Hardware integrations are supported for beta use; qualification records describe tested devices.

## `opencyber-poc`

Operator-side signing CLI for the CVE-chain PoC workflow. It is the supported
creator of signed engagement authorizations and PoC run approvals; MCP exposes
no signing tool. Container-root code remains trusted. Run the CLI inside the
container so it sees the same workspace and
`OPENCYBER_APPROVAL_KEY`:

```sh
docker exec -i opencyber-beta opencyber-poc --help
docker exec -i opencyber-beta opencyber-poc authorize --help
docker exec -i opencyber-beta opencyber-poc approve --help
```

| Subcommand | Purpose |
| --- | --- |
| `authorize` | Write the HMAC-signed engagement authorization: targets, validity window, allowed techniques, optional custom-code allowance. Refuses targets outside the engagement, or public-looking targets without `--i-have-written-authorization`. |
| `approve` | Lint the spec, then mint a single-use approval bound to the spec and code hashes. Prints the signed approval record as JSON; `approval_id` is the top-level field. |
| `revoke` | Mark an approval unusable with a reason; recorded in the audit chain. |
| `status` | Print authorization validity, chain verdicts, approval states, and runs as JSON. |

Set `AUTHORIZATION_VALID_UNTIL` to the UTC expiry allowed by your written
authorization. Set `APPROVAL_EXPIRES` to a future UTC timestamp at most 24 hours
away. Replace the example engagement, chain and spec IDs with returned IDs;
these commands are templates, not an authorization for the example targets.

```sh
docker exec -i opencyber-beta opencyber-poc authorize \
  --engagement eng_20261025_9f8d4c1a6b2743f4a2c11bb8d02a91a7 \
  --authorized-by "Jane Doe <jane@example.test>" \
  --reference "ROE-2026-014" \
  --scope 10.10.0.0/24 \
  --valid-until "$AUTHORIZATION_VALID_UNTIL" \
  --techniques version_assert,http_sequence,http_auth_diff,oob_callback,file_read_canary,tcp_probe \
  --acknowledgement "I confirm written authorization for these targets and techniques"

docker exec -i opencyber-beta opencyber-poc approve \
  --engagement eng_… --chain chain_… --spec spec_… \
  --issued-by "Jane Doe <jane@example.test>" --expires "$APPROVAL_EXPIRES"
```

| Situation | Exit |
| --- | ---: |
| Success (record written or JSON printed) | `0` |
| Missing/short approval key, usage error, refusal (authorization, lint, scope) | `2` |
| Uncaught error | `1` |

Without `OPENCYBER_APPROVAL_KEY` (or `OPENCYBER_APPROVAL_KEY_FILE`) every
subcommand refuses with `approval_key_unavailable`. Full workflow and schemas:
[POC_CHAINS.md](POC_CHAINS.md).

## `python -m opencyber.cve_index`

Build a local SQLite CVE index from NVD 2.0 feeds. This is a build-time and airgap-preparation tool; it is not used by the running MCP server.

| Flag | Effect |
| --- | --- |
| `--year YEAR` | Download one NVD year. Repeatable. |
| `--years "2024 2025 2026"` | Space- or comma-separated years. Can be combined with `--year`. |
| `--feed PATH` | Use an existing NVD 2.0 `.json.gz` or plain JSON feed. Repeatable. |
| `--output PATH` | SQLite output path. Default: `/usr/share/opencyber/cve/cve.sqlite`. |
| `--download-dir PATH` | Directory for downloaded feeds. Default: a temporary directory. |
| `--max-records N` | Stop after N records. Intended for testing. |
| `--no-verify` | Explicitly skip required NVD `.meta` checksum verification for inputs. Use only for independently trusted fixture/preparation data. |
| `-h`, `--help` | Print usage and exit 0. |

At least one of `--year`, `--years`, or `--feed` is required. Verification requires adjacent official NVD metadata, such as `nvdcve-2.0-2025.meta` for `nvdcve-2.0-2025.json.gz`. Its SHA-256 covers the uncompressed JSON bytes. Missing, malformed or mismatched metadata is refused unless the operator explicitly selects `--no-verify`.

```sh
python -m opencyber.cve_index \
  --years "2024 2025 2026" \
  --download-dir /tmp/nvd \
  --output /tmp/cve.sqlite

python -m opencyber.cve_index --feed ./nvdcve-2.0-2025.json.gz --output /tmp/cve.sqlite
```

On success it prints JSON with `output`, `records`, `bytes`, and `generated_at`, and exits 0.

| Situation | Exit |
| --- | ---: |
| Index built | `0` |
| No feed source supplied | `2` (`--year`, `--years`, or `--feed` required) |
| Usage error | `2` |
| Download, checksum, feed, or SQLite failure | `1` |

The output is a SQLite database with `cves(cve_id, description, cvss, published, json)`, an index on `published`, and a `metadata(key, value)` table. `--output` must be writable by the invoking user; the default path requires root in the image.

## Repository scripts

### `scripts/opencyber-run.sh`

Hardware-aware launcher. Builds the hardened `docker run` line and starts a detached container unless `--dry-run` is given.

| Flag | Effect |
| --- | --- |
| `--profile NAME` | Select a profile. Default: `software`. |
| `--image IMAGE` | Image reference. Default: `opencyber:0.5.0`. |
| `--name NAME` | Container name. Default: `opencyber`. |
| `--volume NAME` | Workspace volume. Default: `opencyber-workspace`. |
| `--device PATH` | Add a device. Repeatable; the path must exist on the host. |
| `--offline` | Add `-e OPENCYBER_OFFLINE=1`. |
| `--no-read-only` | Leave the container rootfs writable. |
| `--dry-run` | Print the command and exit without requiring Docker. |
| `--command ...` | Replace the default `sleep infinity`; consumes the remaining arguments. |
| `-h`, `--help` | Print usage and exit 0. |

Profiles: `software`, `usb`, `sdr`, `wifi`, `bluetooth`, `nfc`, `jtag`, `serial`, `can`, `logic`, `gps`, `ir`, `full`.

| Situation | Exit |
| --- | ---: |
| `--dry-run` printed a command | `0` |
| `--help` | `0` |
| Launcher started | Docker's exit status (normally `0`; the script `exec`s `docker run`) |
| Unknown profile or argument, missing value, missing explicit device, or Docker absent | `1` |

`OPENCYBER_IMAGE`, `OPENCYBER_CONTAINER_NAME`, `OPENCYBER_VOLUME_NAME`, and `OPENCYBER_WORKSPACE_PATH` override the corresponding defaults. The launcher does not set `OPENCYBER_WORKSPACE`.

### `scripts/opencyber-airgap.sh`

Move an image across an airgap with a checksum and release manifest. It uses no network.

| Command / flag | Effect |
| --- | --- |
| `export` | `docker save` the image, write `<archive>.sha256` and `release.json`, and copy docs, notices, and a local `sbom/` directory when present. |
| `verify` | Check the archive checksum and required files. Does not establish provenance. |
| `import` | Verify, `docker load`, and run `opencyber-doctor --quiet` against the loaded image. |
| `--image IMAGE` | Image to export. Default: `opencyber:0.5.0`. |
| `--output DIR` | Export destination. Default: `opencyber-airgap`. |
| `--input DIR` | Source for `verify` and `import`. Default: `opencyber-airgap`. |
| `--force` | Overwrite an existing export archive. |
| `-h`, `--help` | Print usage. |

| Situation | Exit |
| --- | ---: |
| Export, verify, or import succeeded | `0` |
| No command supplied (usage only) | `1` |
| `--help` | `0` |
| Missing image, missing directory, missing archive or checksum, checksum mismatch, `docker load` failure, or doctor failure after import | `1` |

A doctor failure during import prints `doctor failed after import; do not deploy this image`.

### `install.sh`

| Flag | Effect |
| --- | --- |
| `--version VERSION` | Release to install. Default: `0.5.0`; must match `X.Y.Z`. |
| `--digest SHA256` | Pin by digest, `sha256:` plus 64 lowercase hex characters. |
| `--uninstall` | Remove the installer-managed container. |
| `--purge-workspace` | With `--uninstall`, also remove the managed workspace volume. |
| `--offline` | Do not pull; require a locally imported image and set `OPENCYBER_OFFLINE=1`. |
| `--verify-attestation` | Run `gh attestation verify` before starting. Requires `gh` and network access. |
| `--no-read-only` | Keep the rootfs writable. |
| `-h`, `--help` | Print usage and exit 0. |

| Situation | Exit |
| --- | ---: |
| Install, uninstall, or help | `0` |
| Validation failure, Docker missing or daemon unavailable, unsupported architecture, image label mismatch, unmanaged container or volume, failed self-test, or failed attestation | `1` |
| Unknown option | `1` |

`--purge-workspace` without `--uninstall`, and `--verify-attestation` with `--offline`, are rejected with exit 1.

### `scripts/check-image-compliance.sh`

```text
scripts/check-image-compliance.sh IMAGE [PLATFORM]
```

Runs a container from the image and checks the policy-sensitive executable set and required license/documentation paths.

| Situation | Exit |
| --- | ---: |
| All checks pass | `0` |
| Wrong argument count | `2` |
| Forbidden executable present, required executable missing, or required file missing | `1` |

The check rejects unapproved Burp Suite, Maltego and waybackurls binaries,
archived Terrascan, and the vulnerable ScoutSuite/sqlitedict stack. It requires
Nmap, Ncat, Ndiff, Nping, RustScan, AutoRecon, Metasploit, NetExec, WPScan,
WhatWeb, URLFinder, subzy and Volatility, together with the installed notices,
source offer, Go/Rust license trees, playbooks, udev rules and asset manifest.

### `scripts/airgap-tools-image.sh`

```text
scripts/airgap-tools-image.sh IMAGE JSON_OUTPUT
```

Tests the inspected immutable local image in a disposable container with no
network, no capabilities and a read-only root filesystem. It checks the
installed catalog, starts the restored tools, and exercises Nmap and WPScan
against owned loopback fixtures. Output contains bounded per-check evidence;
an image, command, isolation or detection failure exits nonzero. Keep the JSON
outside the source tree. WPScan vulnerability API data and hardware devices are
not qualified by this test.

### `scripts/publish-image.sh`

```text
scripts/publish-image.sh [IMAGE_REPOSITORY] [VERSION]
```

Dispatches `build-candidate.yml` for the current Git ref. It validates and stages private native candidates; it does not publish the prerelease. Publication separately selects an exact successful candidate run and immutable artifact checksums. See [RELEASE.md](RELEASE.md).

| Situation | Exit |
| --- | ---: |
| Workflow dispatched | `0` |
| Dirty worktree, repository other than `ghcr.io/mitkox-dev/opencyber`, or `gh` absent | `1` |

Arguments default to `ghcr.io/mitkox-dev/opencyber` and `0.5.0`.

### Candidate and evidence scripts

These are maintainer commands, not installation steps. [RELEASE.md](RELEASE.md)
provides their required order and trusted inputs.

| Command | Purpose |
| --- | --- |
| `bash scripts/poc-lab-image.sh IMAGE JSON_OUTPUT` | Run the disposable, hardened loopback lab; write its JSON outside the source checkout. Exits nonzero when a check fails. |
| `python scripts/export-public-snapshot.py --output DIR --manifest FILE` | Export only a clean committed reviewed snapshot, without Git history or private verification records. Both output paths must be new; the manifest stays outside the exported source. `--root` selects a checkout. |
| `python scripts/hardware-qualification.py template/collect/verify …` | Prepare or verify optional operator evidence. See [HARDWARE_QUALIFICATION.md](HARDWARE_QUALIFICATION.md) for exact arguments. The tool does not operate devices or invent results. |
| `python scripts/release-gate.py --help` | List receipt, run-selection, artifact-fetch, optional qualification, immutable-asset and exception-validation commands. Missing or mismatched required evidence refuses publication. |
| `python scripts/promote-images.py RECORDS OUTPUT` | Workflow-only digest promotion using the frozen platform receipt list and GitHub environment. Does not rebuild images. |
| `python scripts/promote-images.py finalize IMAGE:VERSION DIGEST` | Finalize an explicit `X.Y.Z` reference only; a changed existing digest is refused. Moving aliases are invalid. |

A hardware bundle is optional for 0.5.0. Omission records device qualification
as `not_qualified`; hardware integrations remain supported for beta use. A
submitted bundle must still pass its complete validation. Native software,
source, licensing and vulnerability gates still
apply to private beta images. Public acceptance remains required before a
future public release.

### `scripts/check-version-consistency.py`

```text
python scripts/check-version-consistency.py [--print]
```

Compares `src/opencyber/__init__.py:__version__` with the Dockerfile, installer, both launcher scripts, and `publish-image.sh` defaults.

| Situation | Exit |
| --- | ---: |
| All aliases match, or `--print` | `0` |
| Any alias is missing or different | `1` |

`--print` writes only the source-of-truth version to stdout. Without it, a mismatch lists each problem on stderr.

## Related documents

- [CONFIGURATION.md](CONFIGURATION.md): environment variables and their lifecycle.
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md): what to do when an exit code is unexpected.
- [RELEASE.md](RELEASE.md): how the release commands are sequenced.
