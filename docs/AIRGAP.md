# Offline and airgapped beta use

This guide targets the 0.5.0 private pre-production beta. Use the maintainer's
selected source commit and exact platform image digest after the license and
software qualification gates pass. No 0.5.0 release or image tag has been
published. Complete authenticated access through [BETA_TESTING.md](BETA_TESTING.md)
before transferring a candidate. A locally built image is a development
artifact. Hardware interfaces remain experimental and unqualified.

The image includes nuclei templates, SecLists, rockyou, exploitdb, wordlists
and host udev rules. Optional operator-supplied integrations and their assets
are separate from the distributed image; use the catalog's availability and
omission reasons instead of assuming Nmap scripts or Metasploit modules are
present. Hardware playbooks are not loose files: they are deterministic data and functions in
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

## Build once on a connected host

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

The source tree is not required on the airgapped side. Carry the image, the
candidate compliance records, and the checksums described below.

## Export and import

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
`import` verifies the checksum, runs `docker load`, and then runs
`opencyber-doctor`; a doctor failure aborts with "do not deploy this image".

`verify` checks archive integrity and that the archive and checksum file are
present; a missing `release.json` is a warning, not a failure. It does **not**
establish provenance: `release.json` is an unsigned manifest, and the SHA-256
file only proves the archive matches the copy recorded beside it. Anyone who
can replace both can produce a consistent bundle. Compare the recorded repo
digest against the independently retained candidate record. Verify any supplied attestation before importing; a local export does
not create one. Private registry access also does not prove qualification.
For a future public release, [RELEASE.md](RELEASE.md) requires signed provenance
and SBOM attestations on the qualified platform images and multi-platform
manifest, plus public-access acceptance.

## Run with offline mode asserted

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
Required assets include the nuclei template store, SecLists, rockyou,
exploitdb and the shared wordlist directory. Optional entries include
operator-supplied Metasploit modules and Nmap scripts, the webshell collection,
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

## Updating an airgapped install

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
