# Offline and airgapped beta use

The published [v0.5.0-private-beta.1 private preview](https://github.com/mitkox/opencyber/releases/tag/v0.5.0-private-beta.1)
supplies the full toolkit for native **Linux amd64**. Its frozen source is
`c1201976caf49c45068bb507032aee75e4509e20`, and its local image tag is
`opencyber:0.5.0-private-beta.1-amd64`. It is an **unqualified private preview**:
vendor reviews and license metadata remain unresolved, and native arm64,
physical hardware, live Oracle/PDB workflows and production are unqualified.
Private access does not waive component terms. See [RELEASE.md](RELEASE.md)
for the recorded evidence and the separate qualified-candidate gates.

## Download and import the published preview

After accepting the maintainer's repository Read invitation, download all
**38 release assets, about 13.3 GB**, while connected. No GHCR access is needed:

```sh
gh auth login
gh release download v0.5.0-private-beta.1 \
  --repo mitkox/opencyber --dir opencyber-beta
```

Carry the **whole directory** to the offline host, including all 14 numbered
image/source parts (split at 1 GiB), both checksum lists, `beta-import.sh`,
`release-manifest.json`, first-party source, captured corresponding source,
notices, SBOMs and the actual license-gate report. Use a normal Linux filesystem
with space for the parts, assembled image archive and Docker's expanded image.
Assembling the captured source needs additional space.

On a native Linux amd64 Docker host with Bash and Python 3:

```sh
cd opencyber-beta
bash beta-import.sh --verify-only
bash beta-import.sh
# Optional: also assemble the captured third-party source archive.
bash beta-import.sh --assemble-source
```

The helper verifies the checksummed files and complete assembled image, checks
the archive and loaded image against the supplied runtime layers/configuration,
architecture, revision and version, then runs doctor and the strict MCP
self-test in disposable containers with networking disabled. It installs
nothing and performs no pulls. Existing archives or image tags are reused only
when they match; a mismatch stops without replacement. It creates no persistent
container or workspace volume. Keep the numbered parts and inspect any
pre-existing `.partial` file before retrying. These checks establish local
bundle integrity and runtime identity, not vendor approval or signed public
provenance.

The first-party source archive is already complete. Extract it into a new
directory, then use unused container and volume names:

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

The blue-team profile disables networking and device passthrough. Connect an
MCP client with `docker exec -i opencyber-beta opencyber-mcp` (no PTY), and
follow [BETA_TESTING.md](BETA_TESTING.md) for a synthetic first exercise.
The generic `scripts/opencyber-airgap.sh import` command below does **not**
assemble this release's split parts; use the supplied `beta-import.sh` for this
drop. Repository Read also exposes its private release assets; see
[BETA_ACCESS.md](BETA_ACCESS.md) before inviting testers.

## Included assets and offline-mode limits

The image includes nuclei templates, SecLists dictionaries, exploitdb, a generated baseline dictionary
and host udev rules. Nmap NSE scripts and fingerprints and the
restored local assessment tools are included in the image. Use the catalog's
availability and omission reasons for the two excluded adapters. Hardware playbooks are not loose files: they are deterministic data and functions in
`src/opencyber/hardware.py`, returned by `oc_hardware_plan` and
`opencyber-hardware --plan`. The host guide is [HARDWARE.md](HARDWARE.md); a
copy is installed at `/usr/share/opencyber/docs/` in the image.

Before relying on offline mode, understand what it is. `OPENCYBER_OFFLINE=1` is
a fail-fast switch for features that are known to require the internet. It is
not an egress firewall, a DNS sinkhole, or a scope enforcement boundary. Native
HTTP, browser, and API tools (for example `oc_http_request`,
`oc_http_repeater`, `oc_browser_*`, `oc_graphql_request`, `oc_openapi_audit`,
and `oc_api_fuzz`) still open sockets in offline mode, and catalog executables
outside the named blocklist run normally.
A hard airgap needs host or network controls; see
[Hard isolation](#hard-isolation).

## Build a local development image on a connected host

The following build and custom-export instructions are separate from importing
the frozen published preview. Do not rebuild or replace its published assets,
tag or source snapshot. A local build is a development artifact.

```sh
gh auth login
gh repo clone mitkox/opencyber
cd opencyber
git switch --detach BETA_SOURCE_COMMIT
docker build --provenance=false -t opencyber:0.5.0 .

# Optional: bake a local NVD CVE index for offline oc_cve_lookup.
docker build \
  --build-arg OPENCYBER_CVE_YEARS="2024 2025 2026" \
  -t opencyber:0.5.0-cve .

docker run --rm --entrypoint opencyber-doctor opencyber:0.5.0
docker run --rm --entrypoint opencyber-assets opencyber:0.5.0 --verify
```

Replace `BETA_SOURCE_COMMIT` with the maintainer-provided full source commit
SHA. These build commands produce local development images. Building and
passing doctor does not authorize distribution of an image while license
metadata remains unresolved.

`opencyber-doctor` exits non-zero when required tooling or offline assets are
missing. A local doctor pass is useful development evidence; release acceptance
also requires vulnerability, license, provenance and both native-platform
checks. Prefer the exact qualified candidate digest supplied by the maintainer
for private beta testing.

For a custom export, carry the image, matching source/compliance records and
checksums described below. Carry the launcher source too if using it to start
the container on the airgapped side.

## Export and import a custom local bundle

If you want SBOM files in the transfer bundle, generate them first. The export
script copies a local `sbom/` directory when it exists but does not create one:

```sh
# Optional, on the connected source checkout. Requires syft and the Python dev environment.
./scripts/generate-sbom.sh opencyber:0.5.0 sbom
```

Then export, verify, and import:

```sh
# Connected side
./scripts/opencyber-airgap.sh export --image opencyber:0.5.0 --output /media/usb/opencyber

# Airgapped side
./scripts/opencyber-airgap.sh verify --input /media/usb/opencyber
./scripts/opencyber-airgap.sh import --input /media/usb/opencyber
```

The export directory contains:

- `opencyber-<tag>.tar`: the `docker save` archive.
- `opencyber-<tag>.tar.sha256`: SHA-256 of the archive, recorded with an
  archive-relative path.
- `release.json`: schema version, image reference, image ID, repo digests,
  creation time, archive name and byte size, and the checksum filename.
- `docs/`: `HARDWARE.md`, `AIRGAP.md`, and the notices and source offer when
  those files exist in the repo.
- `sbom/`: the CDX/SPDX inventories and their `SHA256SUMS-*` files, only when
  `scripts/generate-sbom.sh` was run before export.

`export` refuses to overwrite an existing archive unless you pass `--force`.
`import` requires `release.json`, verifies that the checksum file names the
selected archive and that exactly one entry is present, then runs `docker load`.
After loading it compares the loaded image ID and any recorded repo digest with
`release.json` and aborts on a mismatch. A successful load must then pass the
strict `opencyber-mcp --self-test` and `opencyber-doctor`; both checks run in
the importing daemon's store, so use a clean store for a candidate import.

`verify` checks archive integrity, that the archive and checksum file are
present, and that the checksum file names the selected archive; a missing
`release.json` is a warning for `verify` but a failure for `import`. It does **not**
establish provenance: `release.json` is an unsigned manifest, and the SHA-256
file only proves the archive matches the copy recorded beside it. Anyone who
can replace both can produce a consistent bundle. Compare the recorded repo
digest against the independently retained candidate record. Verify any supplied attestation before importing; a local export does
not create one. Private registry access also does not prove qualification.
For a future public release, [RELEASE.md](RELEASE.md) requires signed provenance
and SBOM attestations on the qualified platform images and multi-platform
manifest, plus public-access acceptance.

## Run a custom image with offline mode asserted

For an evidence-only beta session, the blue-team profile provides a complete
no-network command:

```sh
./scripts/opencyber-run.sh --profile blue-team --image opencyber:0.5.0
```

It adds `--network none`, drops every capability and asserts offline mode.
For an internal lab that needs network access, the launcher and installer can
assert the offline feature switch while retaining their usual network setup:

```sh
./scripts/opencyber-run.sh --offline --profile software --image opencyber:0.5.0
OPENCYBER_IMAGE=opencyber bash install.sh --offline --version 0.5.0
```

Choose one startup method. These examples use the local repository
`opencyber`, matching the export above. If you exported a GHCR image, pass that
same repository to the installer or the full reference to the launcher.

`install.sh --offline` requires the image to be imported locally first, skips
the pull, and refuses an image whose `com.opencyber.harness.version` label does
not match the requested version.

With `OPENCYBER_OFFLINE=1`:

- `oc_cve_lookup` reads the local SQLite index first, whether or not offline
  mode is on. If the database is absent and the harness is offline, the call
  fails immediately with instructions instead of waiting on a network timeout.
  When a local database is present but does not contain the requested CVE, the
  result is `found: false`; it does not fall back to the network.
- `oc_hibp_password_check` fails immediately.
- `oc_shodan`, `oc_censys`, `oc_subfinder`, `oc_theharvester`, and
  `oc_sherlock` are refused before the process starts. The blocked executables
  are exactly `shodan`, `censys`, `subfinder`, `theHarvester`, and `sherlock`.
  If the internal network provides the required services, set
  `OPENCYBER_OFFLINE_ALLOW_NETWORK_TOOLS=1` to allow them.
- `oc_amass`, `oc_recon_ng`, `oc_spiderfoot`, and `oc_wafw00f` are not blocked:
  amass, recon-ng, spiderfoot, and wafw00f have local modes that are useful
  against internal networks. Constrain them with scope enforcement and the
  network policy instead.
- `oc_offline_status` reports the mode, required-asset readiness, local CVE
  database presence, `blocked_executables` (the exact list), and the features
  that still need internet access.

Scope enforcement (`OPENCYBER_ENFORCE_SCOPE=1`) is also a guardrail, not a
firewall. It inspects executable-backed calls for URL, IP, CIDR, and hostname
tokens and checks native HTTP/API request and redirect hosts against engagement
targets. The workbench also enforces its session scope. Browser tools, proxy
destinations, DNS changes and redirects inside external executables remain
outside that host check. See [Security model](SECURITY_MODEL.md).

### Hard isolation

For a real airgap, remove the container's ability to route traffic. Use
`--network none` for file-only work. Docker's
default bridge provides outbound connectivity even when `OPENCYBER_OFFLINE=1`
is set. Use an internal network:

```sh
docker network create --internal opencyber-airgap
docker run --network opencyber-airgap -e OPENCYBER_OFFLINE=1 ...
```

An internal network has no default route. If you need host-network access for
Wi-Fi, Bluetooth, or CAN, enforce isolation with host firewall rules or a
dedicated lab VLAN, and keep the offline switch on as a second layer. Verify
from inside the container rather than assuming:

```sh
docker exec opencyber sh -c 'ip route; getent hosts example.com || true'
```

## Offline assets and integrity

`oc_assets_status` reports counts and sizes for every required asset.
`oc_assets_status(deep=True)` adds content hashes, which is slower and should
be used for spot checks rather than every healthcheck.

The build writes `/usr/share/opencyber/asset-manifest.json`. At runtime,
`opencyber-doctor` compares measured counts and sizes against it and reports a
mismatch instead of silently accepting a truncated template store or wordlist.
Required assets include the nuclei template store, SecLists, the generated baseline dictionary,
exploitdb, the shared wordlist directory, Nmap
scripts and WPScan local-detection metadata. Optional entries include the webshell collection,
Wireshark data, the host udev rules, playbook documents and the CVE database.

To inspect on the airgapped host:

```sh
docker exec opencyber opencyber-assets --json
docker exec opencyber opencyber-assets --verify --json
docker exec opencyber opencyber-assets --verify --deep --json   # content hashes
docker exec opencyber opencyber-assets --offline --json
```

`--verify` exits non-zero when required assets no longer match the manifest.
Use `--write PATH` only as part of an intentional image/asset build. Replacing
the manifest to silence a mismatch does not repair or qualify an image.

## Local CVE database

`oc_cve_lookup` supports an offline SQLite index at
`/usr/share/opencyber/cve/cve.sqlite` (override with `OPENCYBER_CVE_DB`). Build
it on a connected host with the image build argument:

```sh
docker build \
  --build-arg OPENCYBER_CVE_YEARS="2024 2025 2026" \
  -t opencyber:0.5.0-cve .
```

Or build it directly with the module, which is useful when you want to carry
only the SQLite file across the airgap:

```sh
python -m opencyber.cve_index \
  --years "2024 2025 2026" \
  --download-dir /tmp/nvd \
  --output /tmp/cve.sqlite
```

The module accepts:

- `--year YEAR`: download one NVD year; repeatable.
- `--years "2024 2025 2026"`: space- or comma-separated years.
- `--feed PATH`: use an existing NVD 2.0 `.json.gz` or plain JSON feed;
  repeatable. Keep the matching NVD `.meta` file beside it, for example
  `nvdcve-2.0-2025.meta` beside `nvdcve-2.0-2025.json.gz` or `.json`.
  Combine with `--year`/`--years` if you want both.
- `--output PATH`: SQLite output path (default
  `/usr/share/opencyber/cve/cve.sqlite`).
- `--download-dir PATH`: where downloaded feeds are kept (default: a temporary
  directory).
- `--max-records N`: stop after N records, for testing.
- `--no-verify`: explicitly allow unverified input. Downloads omit metadata
  requests and local feeds do not require an adjacent `.meta` file.

By default, feeds are verified before parsing against the `sha256:` field in
NVD's plaintext `key:value` metadata. The checksum describes the uncompressed
JSON, so gzip feeds are decompressed while hashing. Missing, malformed or
mismatched metadata blocks index creation; bypassing verification requires
`--no-verify`. At least one `--year`, `--years`, or `--feed` is required.

The schema is intentionally small:

```sql
CREATE TABLE cves (
  cve_id TEXT PRIMARY KEY,
  description TEXT,
  cvss REAL,
  published TEXT,
  json TEXT
);
CREATE INDEX idx_cves_published ON cves(published);
CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT);
```

`metadata` records `schema_version`, `generated_at`, `records`, and the source
feeds. Any pipeline that produces the same tables works. Keep the database on a
read-only mount and verify its hash before use. `searchsploit` and nuclei
templates provide local vulnerability references without this database;
operator-supplied integrations have their own asset requirements.

## Password dictionary provenance

The default dictionary is `/usr/share/wordlists/opencyber-keyboard-patterns.txt`,
copied from SecLists' generated `Keyboard-Walks/walk-the-line.txt`. It contains
keyboard patterns, not measured breach-password coverage. Other included
SecLists lists remain available for target-specific selection.

SecLists is pinned to upstream 2026.1 with a verified archive SHA-256 and its
actual MIT license. The imported RockYou corpus and its named subsets are
removed in the asset build stage before any files enter final image layers.
Kali's old RockYou data notice did not establish the GPL grant previously
claimed here. A separately supplied corpus needs its own applicable rights;
the optional `rockyou` status reports actual presence without gating readiness.

## WPScan without public internet access

The image stages the public WPScan local-detection database and its original
license under `/usr/share/opencyber/wpscan-cache`. With `OPENCYBER_OFFLINE=1`,
the packaged wrapper reads that immutable snapshot and appends `--no-update`;
HTTP scratch files stay in `/tmp`. The build captures the database bytes and
hashes so they can be audited and replaced with a new image when stale.

This supports local WordPress detection and enumeration. Vulnerability
intelligence from the WPScan API or enterprise database is a separate service
and entitlement; no token or enterprise dataset is bundled. An internet API
cannot be made offline merely by installing its client. Cloud assessment and
public OSINT clients likewise retain their service dependencies.

Before sharing a candidate, run `scripts/airgap-tools-image.sh IMAGE JSON_OUTPUT`
on the connected build host. It starts a disposable container with no network,
checks the installed catalog and restored CLIs, and tests Nmap and WPScan only
against owned loopback fixtures. Transfer the checksummed image and matching
source/license evidence after the release gates pass.

## Updating an airgapped install

For a subsequent published preview, download its entire new release bundle,
follow its supplied import instructions and use new container/volume names.
Keep the existing preview's parts, tag and snapshot unchanged. Do not combine
parts or source evidence from different releases.

For a custom local build/export:

1. Build and doctor-gate a new image on a connected host.
2. Optionally run `scripts/generate-sbom.sh IMAGE sbom` so the bundle includes
   inventories.
3. Export with `scripts/opencyber-airgap.sh export`.
4. Transfer the archive, checksum file, and `release.json` on removable media.
5. On the airgapped host: run `verify`, then `import`.
6. Start a new container; keep the old image until the new doctor passes.
7. Check workspace compatibility in the release notes before sharing an
   existing volume or downgrading. `engagement.json` records a schema version;
   plain directories alone do not guarantee future compatibility.

The harness has no telemetry, license check, model download or background
update process. Independently bundled tools can still attempt network requests
when invoked; enforce isolation at the container or network boundary.

## Evidence handling

The audit trail is append-only JSONL with a SHA-256 chain. It lives inside the
engagement workspace, so it moves with the evidence:

```sh
docker exec opencyber opencyber-mcp --self-test
docker exec opencyber opencyber-doctor --json
```

Call `oc_audit_verify` before exporting an engagement. Copy the whole
engagement directory, not just `findings/`, so the hash chain, HTTP history,
browser network logs, and serial transcripts (`hardware/serial/*.jsonl`) stay
together. Evidence artifacts are not redacted by default; treat the copied
workspace as sensitive.
