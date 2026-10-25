# OpenCyber Harness third-party notices

OpenCyber Harness source code is licensed under the Apache License 2.0. The
container image is a collection of independently licensed software. The
repository's Apache-2.0 license does not replace or override any third-party
license.

## Release evidence

0.5.0 is currently a private beta. Qualified candidates may be shared from the
private `ghcr.io/mitkox/opencyber-beta-candidates` package only after source,
license and runtime gates pass; the maintainer supplies the exact platform
digest and compliance bundle. Repository access does not by itself prove
package access. Unresolved obligations block private binary sharing too.

A future public release will publish versioned multi-platform images at
`ghcr.io/mitkox/opencyber` after additional public acceptance. No such
publication is claimed here.

Resolve the current immutable index and platform digests directly from the
registry with `docker buildx imagetools inspect`. The candidate receipt binds
the Git revision recorded in OCI metadata to the tested platform digest and
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
| URLFinder | 0.0.3 | <https://github.com/projectdiscovery/urlfinder> | MIT | Replaces unlicensed waybackurls; copy module licenses |
| subzy | 1.2.1 | <https://github.com/PentestPad/subzy> | GPL | Replaces WPScan; source obligations apply |
| Jaeles | commit `d40305ffe42a`, maintained go-git v5, Gorilla WebSocket `e064f32e3674` | <https://github.com/jaeles-project/jaeles> | MIT | Narrow import migration and frozen security dependency graph; modified source retained |
| kube-bench | 0.16.0 | <https://github.com/aquasecurity/kube-bench> | Apache-2.0 | Copy module licenses and NOTICE |
| x8 | 4.3.2 | <https://github.com/Sh1Yo/x8> | GPL-3.0-or-later | Source obligations apply; crate licenses copied |
| pwninit | 3.3.3 | <https://github.com/io12/pwninit> | MIT | Built from pinned crate; crate licenses copied |
| HashPump-partialhash | commit `b822764fa71209858c91378736d43d082c674e96` | <https://github.com/mheistermann/HashPump-partialhash> | MIT | License copied |
| Docker Bench for Security | commit `154869da6418089decf7e1ab0cfca0e1cdfc5c49` | <https://github.com/docker/docker-bench-security> | Apache-2.0 | Pinned commit; license retained in cloned tree |
| nuclei-templates | v10.5.1 | <https://github.com/projectdiscovery/nuclei-templates> | MIT | Pinned tarball with SHA-256; license retained in the template tree |
| yq (mikefarah) | v4.54.1 | <https://github.com/mikefarah/yq> | MIT | Built from source with patched Go/dependencies; source and binary fingerprint retained |
| ripgrep | Kali package | <https://github.com/BurntSushi/ripgrep> | MIT/Unlicense | Installed via apt; package copyright retained |
| rockyou wordlist | Kali `wordlists` package | <https://www.kali.org/tools/wordlists/> | GPL-2.0-or-later | Decompressed at build time from the packaged archive |
| SecLists | Kali `seclists` package | <https://github.com/danielmiessler/SecLists> | MIT | Symlinked at `/usr/share/wordlists/seclists` |

Each component also has transitive dependencies. Their package URLs, versions,
checksums, and detected license expressions belong in the release SBOM.

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

The remediated image deliberately excludes these components. The license policy
fails a release if any of them reappear, including as a transitive package.

| Component | Evidence | Required resolution |
| --- | --- | --- |
| Burp Suite Community Edition | No clean public-container redistribution grant was established. | Replaced at the catalog level by the existing ZAP, mitmproxy, HTTP workbench, and browser tooling; `subzy` occupies the released executable slot. |
| waybackurls | No upstream license or affirmative redistribution grant was found. | Replaced by MIT-licensed URLFinder; GAU also remains available. |
| Maltego | Redistribution rights were not established and it was not exposed as a distinct MCP tool. | Removed; SpiderFoot remains the graph/OSINT-oriented alternative. |
| WPScan | Its public-source terms restrict commercialization and value-added products. | Removed; GPL-licensed WhatWeb provides CMS and web-technology fingerprinting. |
| Nmap, nmap-common, Ncat, Ndiff, Nping | The inspected Kali package `7.99+dfsg-1kali1` declares `NPSL-0.94`; the package copyright explicitly identifies Kali's non-free classification. Public-image redistribution review remains unresolved. | Excluded until an exact packaged-license decision is recorded. `oc_nmap` remains an optional adapter for operator-supplied installations. |
| AutoRecon, Metasploit, NetExec, RustScan | AutoRecon and Metasploit depend directly on the Nmap package; NetExec depends on `python3-libnmap`, which depends on Nmap. RustScan's default scan pipeline invokes Nmap. | Excluded from the base image; adapters remain optional and report missing binaries or dependencies. |
| Terrascan | Upstream is archived; its dependency graph has unresolved high/critical advisories that require a broad maintenance fork. | Binary excluded; `oc_terrascan` remains an optional adapter. |
| ScoutSuite | The latest upstream release requires sqlitedict 2.1.0, which has an unresolved high-severity deserialization advisory. | Binary excluded; `oc_scout_suite` remains an optional adapter. |

## Components with special obligations

| Component | Reason |
| --- | --- |
| Volatility 3 | Preserve the complete Volatility Software License 1.0 text and corresponding source information. |
| GPL/AGPL/CPL components | The image contains GPL, AGPL, LGPL, CPL, and other reciprocal licenses. Preserve notices and provide complete corresponding source or the published source offer for the exact binaries distributed. |
| Nikto databases | The database files are all-rights-reserved and may be distributed and used only with the full Nikto package. Keep the package intact and preserve its license text. |

The corresponding-source payload includes a `builds/build-context.tar.gz`
archive containing the first-party Docker build context, including the apt
exclusion policy, packaging files, source, documentation and build/install
scripts. Extract it and build from its `context/` directory.

## Release requirements

A public image is ready for promotion only when all of the following are true:

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
