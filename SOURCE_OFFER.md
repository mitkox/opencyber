# Corresponding source offer

OpenCyber Harness images contain independently licensed programs, including
software distributed under the GPL, AGPL, LGPL, CPL, Nmap Public Source License,
Volatility Software License and other licenses that require source availability
or preservation of specific terms.

The image is intended for research, defensive analysis and authorized testing.
That purpose does not grant redistribution rights or change any component's
license. The Apache-2.0 license on OpenCyber source and this source offer do not
override custom terms, commercialization restrictions or database/API licenses.

For each OpenCyber Harness container image distributed by this project, the
maintainers will provide the complete corresponding source code that they are
required to provide under those licenses. This offer is valid for at least three
years from the date the applicable image version was last distributed.
Any longer period required by an applicable component license remains in effect.

During the private beta, request the corresponding source bundle from
[tech@mitkox.com](mailto:tech@mitkox.com), or open an issue in the private
[repository](https://github.com/mitkox-dev/opencyber/issues) if you have access, with:

- the title `Corresponding source request`;
- the image reference and immutable identity (the private preview's image ID,
  or a qualified registry image's digest);
- the requested component or source package;
- whether electronic delivery is sufficient.

Electronic delivery is provided without charge. If physical media is requested
and legally required, the maintainers may charge no more than the reasonable
cost of performing that distribution.

Where an applicable license extends this offer to any third party, private
repository membership or a beta invitation is not required to request that
source. Initial beta access controls do not restrict recipients' rights under
the licenses of the components they receive.

## Published private preview source

Invited repository readers can obtain the exact source and image bundle from
[v0.5.0-private-beta.1](https://github.com/mitkox-dev/opencyber/releases/tag/v0.5.0-private-beta.1).
Download all 38 assets, about 13.3 GB, while connected and carry the complete
directory for airgapped use:

```sh
gh auth login
gh release download v0.5.0-private-beta.1 \
  --repo mitkox-dev/opencyber --dir opencyber-beta
```

`opencyber-source-c120197.tar.gz` is the complete first-party source snapshot
for commit `c1201976caf49c45068bb507032aee75e4509e20`; it is separate from the
captured third-party corresponding source. The latter is supplied as
`opencyber-0.5.0-private-beta.1-corresponding-source.tar.gz.part-000` through
`.part-007`. From the downloaded directory, the supplied helper verifies the
bundle, imports/checks the image offline and optionally assembles that source:

```sh
cd opencyber-beta
bash beta-import.sh --assemble-source
```

Use [docs/AIRGAP.md](docs/AIRGAP.md) for prerequisites and the verification-only
option. `SHA256SUMS` covers the parts and metadata; `ASSEMBLED-SHA256SUMS` covers
the complete image and corresponding-source archives. Retain the source
manifest, notices, SBOMs and actual license-gate report with the bundle. The
captured source matched 1,428 components and 3,717 artifacts against the tested
amd64 image. This records source matching, not completion of the remaining
license metadata or Oracle/PDB vendor reviews.

This private preview uses local image tag
`opencyber:0.5.0-private-beta.1-amd64`; `release-manifest.json` records its image
ID `sha256:a059c5ecd9d59489f8f99039dd237910a9c90b38a575aab58e2e7b8606344e8a`.
No published registry digest is required to request its source. The preview is
unqualified; private access does not waive third-party obligations. Its source
is supplied under each component's original terms, with no added vendor
agreement or repository-membership condition on separately licensed source
rights. Use the contact above if you hold a source entitlement without private
repository access.

## Source capture and qualified releases

- Harness source and build scripts are available to invited testers in this
  private repository. Its Apache-2.0 license remains in effect.
- A qualified beta candidate must be accompanied by its captured
  corresponding-source payloads, checksummed manifests, SBOMs and license bundle. Obtain them from the
  maintainer with the candidate receipt; a source checkout alone does not cover
  every bundled component. Unresolved source or license obligations block
  qualification and public promotion. Their presence in a private preview does
  not resolve them or confer a redistribution grant.
- Nmap, Ncat, Ndiff, Nping and the bundled Nmap scripts require the exact
  applicable license and source coverage. Include the Kali source package,
  patches and build inputs for the binary version actually distributed.
  Metasploit modules and the other required offline assets retain their own
  notices and source coverage. WPScan retains its unmodified custom license and
  copyright notices; this offer does not confer commercial or database rights.
- For future public releases, those payloads and manifests will be publicly
  downloadable [release assets](https://github.com/mitkox-dev/opencyber/releases)
  for each published version.
- Build the Docker `corresponding-source` target with the same platform and
  arguments as the runtime to capture exact Kali source archives, Debian
  patches and build scripts, source-built dependencies, Python sdists, Ruby gem
  sources, and direct build trees before ephemeral inputs are discarded.
- `scripts/generate-corresponding-source.sh IMAGE OUTPUT_DIRECTORY PLATFORM
  CAPTURED_SOURCE_DIRECTORY` verifies source coverage and binary identity
  against the tested candidate and exports the actual source archive. Package
  names, versions, license texts, and upstream URLs alone are not corresponding
  source delivery.
- `scripts/generate-license-bundle.sh` separately exports installed notices and
  source-package identifiers; that notice bundle supplements the source
  archives rather than replacing them.
- Go/Rust dependency sources, exact direct source inputs, and the Dockerfile
  controlling compilation and installation are included in the captured
  payloads. Explicit permissive-license source exemptions are recorded in the
  manifest; an unresolved obligation fails the release gate.

For airgapped delivery, transfer the verified source payloads, notices,
checksums, SBOMs and candidate receipt alongside the image archive on the
approved media. Source reconstruction may require a connected build environment;
the runtime image and local assets must be qualified separately with networking
disabled. A source offer, configured build or local probe is not a completed
image qualification.

For future workflow-generated candidate/public archives split into `.part-*`
assets, concatenate all parts in lexical order before checking their recorded
complete-archive checksum and then the extracted `SOURCE-SHA256SUMS`. For the
published private preview, use the helper and checksum names above. The source
receipt identifies the runtime local image ID, platform, and manifest hash; release evidence maps
that identity to the immutable published registry digest.

Qualified candidates and public releases require the source manifest, SPDX
SBOM, CycloneDX SBOM, license bundle, checksums and image provenance under
[docs/RELEASE.md](docs/RELEASE.md). The private preview's manifest is not a
signed provenance attestation. No public 0.5.0 release is currently claimed.
Source requests should identify the image and component; do not attach
engagement data or credentials.
