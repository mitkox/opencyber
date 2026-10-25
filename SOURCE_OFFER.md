# Corresponding source offer

OpenCyber Harness images contain independently licensed programs, including
software distributed under the GPL, AGPL, LGPL, CPL, Volatility Software License,
and other licenses that require source
availability or preservation of specific terms.

For each OpenCyber Harness container image distributed by this project, the
maintainers will provide the complete corresponding source code that they are
required to provide under those licenses. This offer is valid for at least three
years from the date the applicable image version was last distributed.

During the private beta, request the corresponding source bundle from
[tech@mitkox.com](mailto:tech@mitkox.com), or open an issue in the private
[repository](https://github.com/mitkox/opencyber/issues) if you have access, with:

- the title `Corresponding source request`;
- the image reference and immutable digest;
- the requested component or source package;
- whether electronic delivery is sufficient.

Electronic delivery is provided without charge. If physical media is requested
and legally required, the maintainers may charge no more than the reasonable
cost of performing that distribution.

## Source locations

- Harness source and build scripts are available to invited testers in this
  private repository. Its Apache-2.0 license remains in effect.
- A shared beta image must be accompanied by its captured corresponding-source
  payloads, checksummed manifests, SBOMs and license bundle. Obtain them from the
  maintainer with the candidate receipt; a source checkout alone does not cover
  every bundled component. Unresolved source or license obligations block
  binary distribution, including private beta distribution.
- For future public releases, those payloads and manifests will be assets at
  <https://github.com/mitkox/opencyber/releases> for each published version.
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

If a source archive is split into `.part-*` assets, concatenate all parts in
lexical order before checking `SOURCE-SHA256SUMS`. The source receipt identifies
the runtime local image ID, platform, and manifest hash; release evidence maps
that identity to the immutable published registry digest.

The source manifest, SPDX SBOM, CycloneDX SBOM, license bundle, checksums, and
image provenance accompany each distributed candidate or release. No public
0.5.0 release is currently claimed. Source requests need an image digest and
component identity; do not attach engagement data or credentials.
