# OpenCyber Harness third-party notices

OpenCyber Harness source code is licensed under the Apache License 2.0. The
container image is a collection of independently licensed software. The
repository's Apache-2.0 license does not replace or override any third-party
license.

OpenCyber is intended for security research, defensive analysis and explicitly
authorized testing. This purpose statement grants no rights to third-party
software, databases, services or target systems. Each component's original
license, copyright notices, source obligations and use restrictions remain in
effect, including custom and commercial terms.

## Release evidence

The full-toolkit [v0.5.0-private-beta.1 private preview](https://github.com/mitkox/opencyber/releases/tag/v0.5.0-private-beta.1)
is published for native `linux/amd64`, from source commit
`c1201976caf49c45068bb507032aee75e4509e20`, with local tag
`opencyber:0.5.0-private-beta.1-amd64`. Its catalog has 256 MCP tools: 174
executable integrations and 82 native tools. The maintainer chose to retain
the full toolkit for a small invited group. Oracle connectivity and optional
Microsoft PDB components remain included with vendor review unresolved; no
accepted agreement or redistribution entitlement is asserted.

The preview is **unqualified**. The recorded amd64 offline runtime, MCP,
export/import and source checks passed, and the recorded Trivy scan found zero
HIGH/CRITICAL vulnerabilities, including unfixed findings. However, the strict
license gate is not green: the 5,129-component inventory contains 2,086
unresolved license records and two vendor reviews. Unknown scanner metadata
does not by itself establish that a component is unlicensed. Native arm64,
physical hardware, live Oracle/PDB workflows and production remain unqualified.
Private access does not waive original terms or resolve those obligations.

All 38 release assets (about 13.3 GB) include the numbered image and captured
source parts, first-party snapshot, notices, SBOMs, checksums, actual license-gate
report and offline import helper. Every reader of the private source repository
can retrieve these release assets; no separate GHCR grant or recipient-specific
release permission applies. See [docs/BETA_ACCESS.md](docs/BETA_ACCESS.md),
[docs/BETA_VENDOR_TERMS.md](docs/BETA_VENDOR_TERMS.md),
[docs/AIRGAP.md](docs/AIRGAP.md) and [SOURCE_OFFER.md](SOURCE_OFFER.md).

Qualified candidates still require all source, license, vulnerability and
native amd64/arm64 runtime gates under [docs/RELEASE.md](docs/RELEASE.md). The
private `ghcr.io/mitkox/opencyber-beta-candidates` package is a separate
candidate workflow channel, not required for this preview. A configured
Dockerfile, catalog entry or private download does not prove qualification.

A future public release will publish versioned multi-platform images at
`ghcr.io/mitkox/opencyber` after additional public acceptance. No such
publication is claimed here.

For a qualified registry candidate or future public image, resolve immutable
index and platform digests with `docker buildx imagetools inspect`. The candidate
receipt binds the Git revision recorded in OCI metadata to the tested platform digest and
SBOMs. Future public promotion adds signatures and attestations without
rebuilding the qualified images. Digests are registry-generated evidence and are
therefore not embedded recursively inside the image whose digest they identify.

Generate release-specific SPDX and CycloneDX inventories with
[`scripts/generate-sbom.sh`](scripts/generate-sbom.sh). The SBOM, the installed
license files, and this document must be considered together; this document is
not a substitute for the complete package-level inventory.

## License material retained in the image

Kali and Debian packages retain their package copyright files at
`/usr/share/doc/<package>/copyright` and common license texts at
`/usr/share/common-licenses`. Python distributions generally retain license
and metadata files in their `.dist-info` directories, and Ruby gems retain
license metadata in their gem specifications or installed source trees.

The Dockerfile additionally copies license and notice files found in the Go and
Rust module caches and the direct source builds into
`/usr/share/opencyber/licenses`. Release verification checks that this material
and the project's corresponding-source offer are present.

## Direct non-Kali additions

The following components are installed directly by the Dockerfile rather than
solely through Kali's package manager. Pinning is not uniform, and this table
states what is actually enforced:

- **Version + SHA-256:** the nuclei template tarball.
- **Source builds:** Go modules use pinned upstream versions and Go checksum
  verification. Security-updated Jaeles, kube-bench, URLFinder and yq retain
  frozen `go.mod`/`go.sum` graphs, patched source and binary fingerprints. Rust,
  Ruby and Python inputs retain version identities and captured source; their
  package-manager verification is distinct from an explicit Dockerfile checksum.
- **Kali packages:** resolved by `apt-get` from the apt sources configured in
  the digest-pinned `kalilinux/kali-rolling` base image. Individual package versions
  are whatever the repository served at build time; the exact set is recorded in
  the release SBOM. The build is therefore not bit-for-bit reproducible.

| Component | Audited version | Upstream | Declared license | Current status |
| --- | --- | --- | --- | --- |
| OpenCyber Harness | 0.5.0 | <https://github.com/mitkox/opencyber> | Apache-2.0 | Independently written project source |
| MCP Python SDK | Python SDK (`mcp>=2.3,<3` declared; exact version in SBOM) | <https://github.com/modelcontextprotocol/python-sdk> | MIT | Notice required |
| Playwright for Python | 1.64.1 | <https://github.com/microsoft/playwright-python> | Apache-2.0 | Notice required |
| Requests | Kali package (`requests>=2.31` declared; exact version in SBOM) | <https://github.com/psf/requests> | Apache-2.0 | Notice required |
| angr | 10.0.0 | <https://github.com/angr/angr> | BSD-2-Clause | Notice required |
| Volatility 3 | 2.28.0 | <https://github.com/volatilityfoundation/volatility3> | Volatility Software License 1.0 | Include full custom license |
| Checkov | 3.3.20 | <https://github.com/bridgecrewio/checkov> | Apache-2.0 | Notice required |
| kube-hunter | 0.6.8 | <https://github.com/aquasecurity/kube-hunter> | Apache-2.0 | Notice required |
| Prowler | 5.45.0, isolated Python 3.13, PyMongo 4.18.2 | <https://github.com/prowler-cloud/prowler> | Apache-2.0 | Notice required; Python supplied by Kali; apply upstream's PyMongo security override explicitly because pip does not read its uv override section |
| zsteg | 0.2.14 | <https://github.com/zed-0xff/zsteg> | MIT | Notice required |
| one_gadget | 2.1.1 | <https://github.com/david942j/one_gadget> | MIT | Notice required |
| anew | 0.1.1 | <https://github.com/tomnomnom/anew> | MIT | Pinned module; module licenses copied |
| URLFinder | 0.0.3 | <https://github.com/projectdiscovery/urlfinder> | MIT | URL discovery alternative to waybackurls; copy module licenses |
| subzy | 1.2.1 | <https://github.com/PentestPad/subzy> | GPL | Subdomain takeover checks; source obligations apply |
| Jaeles | commit `d40305ffe42a`, maintained go-git v5, Gorilla WebSocket `e064f32e3674` | <https://github.com/jaeles-project/jaeles> | MIT | Narrow import migration and frozen security dependency graph; modified source retained |
| kube-bench | 0.16.0 | <https://github.com/aquasecurity/kube-bench> | Apache-2.0 | Copy module licenses and NOTICE |
| x8 | 4.3.2 | <https://github.com/Sh1Yo/x8> | GPL-3.0-or-later | Source obligations apply; crate licenses copied |
| pwninit | 3.3.3 | <https://github.com/io12/pwninit> | MIT | Built from pinned crate; crate licenses copied |
| HashPump-partialhash | commit `b822764fa71209858c91378736d43d082c674e96` | <https://github.com/mheistermann/HashPump-partialhash> | MIT | License copied |
| Docker Bench for Security | commit `154869da6418089decf7e1ab0cfca0e1cdfc5c49` | <https://github.com/docker/docker-bench-security> | Apache-2.0 | Pinned commit; license retained in cloned tree |
| nuclei-templates | v10.5.1 | <https://github.com/projectdiscovery/nuclei-templates> | MIT | Pinned tarball with SHA-256; license retained in the template tree |
| yq (mikefarah) | v4.54.1 | <https://github.com/mikefarah/yq> | MIT | Built from source with patched Go/dependencies; source and binary fingerprint retained |
| ripgrep | Kali package | <https://github.com/BurntSushi/ripgrep> | MIT/Unlicense | Installed via apt; package copyright retained |
| Generated baseline dictionary | SecLists 2026.1 `Keyboard-Walks/walk-the-line.txt` | <https://github.com/danielmiessler/SecLists/tree/2026.1/Passwords/Keyboard-Walks> | MIT | Retain upstream license; generated patterns are not RockYou-equivalent empirical coverage |
| SecLists | 2026.1, source archive pinned by SHA-256 | <https://github.com/danielmiessler/SecLists/tree/2026.1> | MIT, with any file-specific terms retained | Only the selected data tree is copied into runtime layers; imported RockYou files are excluded |
| WPScan local detection metadata | Build-time snapshot; exact content bound to the tested image and source bundle | <https://data.wpscan.org/> | WPScan Public Source License; full captured text retained | Public detection metadata only; API and enterprise vulnerability data are separate |

WPScan's update endpoint is mutable. A connected rebuild can receive different
metadata. Candidate matching therefore checks the expanded tree's paths and
content against the tested runtime and supplied source archive, rather than
treating the WPScan package version as the database identity. This snapshot is
not an input pinned in advance; pin it before satisfying the future public
release condition below.

Each component also has transitive dependencies. Their package URLs, versions,
checksums, and detected license expressions belong in the release SBOM.

The earlier GPL claim for the RockYou data was unsupported: Kali's package
copyright covers its Debian packaging under GPL, while describing the corpus
only as free and widely accessible. This image does not redistribute that
corpus or its named SecLists subsets without an applicable grant. The default
is an honestly named generated dictionary; cracking tools remain included.

## Required assessment tools and custom licenses

The Dockerfile includes Nmap, Ncat, Ndiff, Nping (supplied by the Nmap package),
RustScan, AutoRecon, Metasploit, NetExec and WPScan. Nmap scripts and Metasploit
modules are required offline assets. Exact installed versions, licenses and
asset hashes must come from the built image and its qualification bundle.
These tools are not excluded merely because they use custom or reciprocal
licenses.

The reviewed Kali Nmap candidate is `7.991+dfsg-1kali1`; this is not a claim that
it is the latest upstream version or a qualified image input. Preserve its
packaged license text, notices and exact corresponding source, including
distribution patches and build scripts. The
[NPSL annotation](https://nmap.org/npsl/npsl-annotated.html) describes an
aggregation route and additional conditions for Nmap-specific integration.
The [upstream changelog](https://nmap.org/changelog.html#7.94) permits older
NPSL releases under 0.95. Record the applicable terms and integration assessment
for the exact package; an Apache-2.0 label on OpenCyber does not relicense Nmap
or resolve those conditions. Do not add restrictions to recipients' rights
under the applicable component license.

[WPScan 4.1.0's license](https://github.com/wpscanteam/wpscan/blob/v4.1.0/LICENSE)
permits redistribution with unchanged license and copyright notices when its
commercialization clause is satisfied, and explicitly includes penetration
testing distributions and assessment toolkits among its permitted examples.
This free private beta must retain those terms. Commercial product,
managed-service, SaaS or value-added distribution needs the appropriate grant;
calling a distribution research does not settle that question. WPScan API and
database access or redistribution rights are separate from the software license.

Custom licenses with incomplete SBOM metadata need an attributed decision in
`compliance/license-policy.json` for the exact versioned package URL. Preserve
the captured license file, its SHA-256, its source URL, the redistribution basis
and the notice/source obligations. Unknown metadata without that evidence,
unfulfilled obligations and missing required source remain release blockers.
There is no blanket waiver for custom licenses or unknown metadata.

## Hardware and physical-layer additions

The physical-layer toolchain is installed from Kali/Debian packages. Each
package retains its copyright and license text under
`/usr/share/doc/<package>/copyright`; the release SBOM and license bundle
include them. The suite includes, among others:

| Group | Packages |
| --- | --- |
| SDR | `hackrf`, `rtl-sdr`, `rtl-433`, `bladerf`, `limesuite`, `soapysdr-tools`, `ubertooth` |
| Wireless / BLE | `iw`, `wireless-tools`, `wifite`, `hcxdumptool`, `hcxtools`, `reaver`, `bully`, `pixiewps`, `mdk4`, `cowpatty`, `bettercap`, `bluez`, `bluez-tools` |
| NFC / RFID | `proxmark3`, `libnfc-bin`, `libnfc-examples`, `mfoc`, `mfcuk`, `pcsc-tools` |
| Embedded / JTAG | `openocd`, `urjtag`, `avrdude`, `dfu-util`, `esptool`, `stlink-tools`, `flashrom`, `sigrok-cli`, `unblob`, `qemu-user`, `qemu-system-arm`, `gdb-multiarch` |
| Serial | `minicom`, `picocom`, `screen`, `iproute2` |
| Automotive | `can-utils`, `python3-can` |
| GNSS / IR / mobile | `gpsd`, `gpsd-clients`, `lirc`, `apktool`, `jadx` |
| USB | `usbutils`, `usbguard` |

The hardware inventory, serial-session manager, firmware triage, audit chain,
and scope policy are original OpenCyber code under Apache-2.0.


## Components deliberately excluded

The build excludes the components below for the stated reasons. The license
policy blocks Burp Suite Community Edition, waybackurls and Maltego until an
applicable redistribution grant is recorded. Terrascan and ScoutSuite have
separate maintenance and vulnerability blockers; their adapters remain optional.

| Component | Evidence | Required resolution |
| --- | --- | --- |
| Burp Suite Community Edition | Redistribution permission is not established for the exact binary. [Current PortSwigger terms](https://portswigger.net/burp/eula) restrict third-party availability; older packaged terms contain a conditional transfer provision whose applicability to a current binary is unresolved. | Capture the applicable grant and satisfy its conditions, or obtain written permission. ZAP, mitmproxy, the HTTP workbench and browser tooling remain available. |
| waybackurls | No license or affirmative redistribution grant was established for the [upstream source](https://github.com/tomnomnom/waybackurls). Source visibility alone supplies no grant. | Obtain permission; URLFinder and GAU remain available. |
| Maltego | [Vendor terms](https://www.maltego.com/license-agreement/) restrict copying and third-party distribution. No grant covering the proposed image and recipients is recorded. | Obtain an applicable written grant; SpiderFoot remains available. |
| Terrascan | [Upstream](https://github.com/tenable/terrascan) is archived and explicitly no longer maintained. | Binary excluded; `oc_terrascan` remains an optional adapter for separately supplied installations. Reintroduction requires a maintained, qualified replacement or fork. |
| ScoutSuite | Its sqlitedict dependency is affected by [CVE-2024-35515](https://nvd.nist.gov/vuln/detail/CVE-2024-35515). NVD records CISA-ADP's CVSS 3.1 score of 9.8 critical; [GitHub's advisory](https://github.com/advisories/GHSA-g4r7-86gm-pgqc) scores it 8.6 high under CVSS 4.0 and lists no patched version. | Binary excluded; `oc_scout_suite` remains an optional adapter. A secure dependency graph must pass the unchanged HIGH/CRITICAL gate before inclusion. |

## Components with special obligations

| Component | Reason |
| --- | --- |
| Nmap family | Preserve the exact applicable NPSL terms, notices, source and distribution/integration assessment described above. |
| WPScan | Preserve its custom license and copyright notices and comply with commercialization and database/API terms. |
| Volatility 3 | Preserve the complete Volatility Software License 1.0 text and corresponding source information. |
| GPL/AGPL/CPL components | The image contains GPL, AGPL, LGPL, CPL, and other reciprocal licenses. Preserve notices and provide complete corresponding source or the published source offer for the exact binaries distributed. |
| Nikto databases | The database files are all-rights-reserved and may be distributed and used only with the full Nikto package. Keep the package intact and preserve its license text. |

The corresponding-source payload includes a `builds/build-context.tar.gz`
archive containing the first-party Docker build context, including the apt
exclusion policy, packaging files, source, documentation and build/install
scripts. Extract it and build from its `context/` directory.

## Release requirements

Qualified private candidates require completed software, vulnerability, license
and source gates, including matching native amd64/arm64 software acceptance.
The published unqualified preview does not satisfy or change those gates, and
its pending obligations remain unresolved. Public promotion additionally
requires anonymous public acceptance and resolution of vendor reviews under
the release procedure. A public image is ready for promotion only when all of
the following are true:

1. Every direct non-package-manager build input is pinned to a version, commit,
   or digest as appropriate; the Kali package set is resolved by `apt-get` from
   the sources in the digest-pinned `kali-rolling` image, and the exact installed versions are recorded in
   the release SBOM/source manifest.
2. The excluded components above are absent from both platform images.
3. SPDX and CycloneDX SBOMs are generated for both published platform digests.
4. License and notice texts for source-built and downloaded binaries are copied
   into the final image.
5. Actual source archives, distribution patches, dependency inputs, and build
   scripts are published for reciprocal-license components. Exact-version
   package identifiers and upstream URLs alone do not satisfy this gate.
6. The OCI license label describes the mixed-license image accurately rather
   than implying that every image component is Apache-2.0.
7. The SBOMs, notice bundle, image digests, and provenance attestations are
   attached to the release and verified after publication.

## Captured corresponding source

Build the `corresponding-source` Docker target with the same platform, build
arguments, and build cache as the tested runtime. It exports a versioned
`source-manifest.json`, the exact installed package inventory, and actual source
payloads. The default runtime image does not contain the large source payloads.

- Debian/Kali packages: exact-version `.dsc` files and all checked source inputs,
  including upstream tarballs and Debian patch/build archives. Every installed
  binary package, including base-image packages, must have source coverage.
- Go and Rust builds: module/crate sources and caches, downloaded source
  archives, direct checkout source, and fingerprints of the built binaries,
  preserved before ephemeral build mounts disappear.
- Python: exact-version sdists for directly installed distributions and their
  installed dependencies. A missing sdist blocks release unless explicit
  installed permissive-license metadata establishes a notice-only decision.
- Ruby: exact-version gem archives for non-distro installed gems. Distro gems
  are covered by their Debian source packages.
- Direct source trees: harness/build scripts, Docker Bench, and the exact
  expanded nuclei template inputs. yq is included in the source-built Go
  inventory with its locked dependency graph and exact binary fingerprint.

`scripts/generate-corresponding-source.sh` compares the source inventory and
source-built binary fingerprints against the tested image, then creates the
source archive, checked manifest, runtime local-image-ID receipt, and SHA-256 sums.
The publication workflow associates that local image ID and config digest with the tested registry
digest and publishes source payloads before image promotion. Missing versions,
unavailable required archives, modified source payloads, or unmatched runtime
binaries stop publication. Large source archives are split into 1 GiB release
assets; concatenate the parts in order before verifying the original checksum.
