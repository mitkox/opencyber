# Release OpenCyber Harness 0.5.0

0.5.0 is currently a **private pre-production beta**, preparing for its first
public release. Keep the repository and candidate package private. The
maintainer adds beta users; this guide does not authorize public publication.
Source review, native software acceptance and future public digest acceptance
are separate gates. Real-device qualification is deferred; hardware interfaces
are experimental. Missing software or integrity evidence blocks distribution.
There is no PyPI publication; 0.5.0 never advances `latest`, `0` or `0.5` tags.

The source is Apache-2.0; bundled software retains its own licensing terms. Do not distribute unresolved components or omit their corresponding source.

## Review and freeze the source

The package requires Python 3.11–3.13 and MCP Python SDK `mcp>=2.3,<3`. MCP 1.x and the removed FastMCP API are unsupported. `src/opencyber/__init__.py` owns the version; aliases and generated catalog must agree.

```sh
make check
make shellcheck
make test-cov
make build
python -m twine check dist/*
gitleaks dir --redact --no-banner .
```

Inspect tracked source, examples, package contents, metadata and notices for credentials, real engagement material and private identifiers. Review findings and independent-review coverage belong in [PUBLIC_RELEASE_REVIEW.md](PUBLIC_RELEASE_REVIEW.md).

For the first public repository, preserve development history privately as `mitkox/opencyber-development` and disable its publishing workflows. Update existing clones to that address **before** recreating `mitkox/opencyber`: reusing the name removes the old redirect. Export only the reviewed tracked snapshot using `scripts/export-public-snapshot.py`; import no `.git`, old refs or historical local verification files. Preserve licenses and authorship. Create a fresh, initially private repository with one initial commit and verify its tree against the export manifest.

Configure Actions permissions, available repository protections, security reporting and package access for the new numeric repository identity. Freeze that source commit before building. Historical development CI and local-image records do not qualify the new root. Keep subsequent qualification outputs outside the frozen source tree.

## Build candidates privately

```sh
gh workflow run build-candidate.yml --repo mitkox/opencyber --ref main -f version=0.5.0
```

The workflow runs full CI and builds on native amd64 and arm64 runners. Each platform must pass doctor, strict catalog alignment, actual MCP stdio, synthetic blue-team and PoC fixtures, hardened runtime, airgap export/import, assets, image compliance and exact corresponding-source capture. SBOMs describe the tested runtime. HIGH and CRITICAL vulnerabilities, including unfixed findings, block the build. For 0.5.0, update or exclude affected components rather than adding vulnerability exceptions. License policy and missing source archives remain blocking. Valid SPDX identifiers are accepted from either CycloneDX license IDs or names; ambiguous aliases are not guessed. Unknown SPDX expressions or missing license identities require an exact-version `purl` decision in `reviewed_license_components`, naming `license_expression`, `owner`, `basis` and `reviewed_at`; unresolved entries are never waived by a component-name allowlist.

Images upload only to `ghcr.io/mitkox/opencyber-beta-candidates`. This fresh
package belongs to the clean repository, keeping beta access separate from
historical development packages. It must remain private; anonymous access must
receive an authentication denial. A network error is not proof of privacy.
Receipts bind source commit, numeric repository identity, run ID and attempt,
platform, image/config digest, catalog digest and source checksums. Evidence
artifacts are retained for 90 days. Expired evidence requires a new candidate
and new qualification.

SBOM generation is a connected build step. Syft retrieves version-specific Go,
Java and Python license metadata from upstream package services to fill gaps in
installed metadata. This enriches the recorded inventory; it does not waive an
unknown license, substitute for license texts or establish redistribution
permission. Unrecognized aliases, missing license information and custom terms
still require source-based review before the license gate can pass.

The candidate workflow bootstraps only the private candidate package with
harmless metadata. It does not touch the canonical release package. Repository
visibility, package visibility and Actions access are separate settings. Grant
the new repository explicit package access and verify its linked repository
identity. Keep the candidate package private even if the source becomes public.

After the entire candidate build succeeds, freeze its artifact selection:

```sh
GITHUB_REPOSITORY=mitkox/opencyber python scripts/release-gate.py select --run-id BUILD_RUN_ID --commit FULL_FROZEN_COMMIT --output /private/release/candidate-selection.json
```

Retain the printed SHA-256 independently. A changed run attempt, replaced artifact, missing checksum or expired artifact invalidates the selection. Fetch receipts for the lab:

```sh
GITHUB_REPOSITORY=mitkox/opencyber python scripts/release-gate.py fetch --selection /private/release/candidate-selection.json --sha256 SELECTION_SHA256 --run-id BUILD_RUN_ID --commit FULL_FROZEN_COMMIT --output /private/release/candidate-evidence > /private/release/records.json
```

## Give invited testers access

The maintainer manages invitations to `mitkox/opencyber`; do not invite testers
to `mitkox/opencyber-development`. This is a personal-account repository:
GitHub collaborator invitations grant **write access**, including the ability
to push branches and run workflows. They cannot grant a read-only repository
role. Invite trusted collaborators only and configure available branch
protection before they contribute. A true Read role requires an
organization-owned repository; moving ownership is a separate maintainer
decision. See [GitHub's personal repository permissions](https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/repository-access-and-collaboration/permission-levels-for-a-personal-account-repository).

At private-beta setup, GitHub refused branch-protection configuration for this
private repository because the account plan does not include it. CI therefore
does not enforce a protected-branch merge boundary. Keep invitations limited to
people trusted with repository write access. A plan upgrade or an appropriately
configured organization is a maintainer decision; do not make the repository
public to work around this restriction.

For the candidate package, grant testers Read explicitly when they only need
image pulls. Repository permission inheritance may grant broader package
access to write-capable collaborators; inspect it rather than assuming it is
read-only. Confirm the package is linked to the new repository and that its
Actions access permits candidate builds. See
[GitHub's package permissions](https://docs.github.com/en/packages/learn-github-packages/about-permissions-for-github-packages).

After a complete successful candidate run, provide each tester with the frozen
source commit, selected run ID, their host architecture, its exact platform
digest, checksummed compliance/source bundle and the [beta guide](BETA_TESTING.md).
The guide uses authenticated GitHub source access and GHCR login with a classic
token limited to `read:packages`. Never include tokens in invitations, issue
reports, MCP configuration or evidence. Confirm an invited account can clone
and pull the selected digest and an anonymous client cannot.

Failed license, source or software checks block sharing the image, even during
a private beta. Until those checks pass, offer source testing or clearly labelled
local development builds rather than a qualified binary. Keeping the repository
private does not waive bundled components' licensing obligations.

## Optional real-device qualification

Follow [HARDWARE_QUALIFICATION.md](HARDWARE_QUALIFICATION.md). Real-device evidence is optional for 0.5.0. If supplying it, all 11 domains need passing observations on at least one native host, plus a known board-derived firmware sample. Software acceptance still covers both architectures. Device enumeration, fake sysfs, PTYs and synthetic fixtures cannot qualify a device.

The collector creates `qualification.json` and checksummed `evidence/` files. Remove credentials, private targets and unnecessary operator identifiers before collecting portable evidence; retain raw records privately. Zip the **contents** of the directory as `hardware-qualification.zip` and retain its SHA-256 independently. Verification checks identities, completeness and integrity; it trusts the operator's attested physical observations.

## Future public publication — maintainer decision required

The public publication workflow remains disabled during private beta. Only
after the maintainer explicitly authorizes opening the repository should it be
enabled and the remaining public gates completed. Configure the canonical
`ghcr.io/mitkox/opencyber` package separately for the new repository identity;
verify visibility and workflow access. Its harmless `bootstrap` reference must
be available for the publisher's anonymous visibility check. Do not grant beta
testers access to historical canonical package versions as a shortcut.

Create an annotated `v0.5.0` tag on the frozen commit and push it. Tag pushes do not publish automatically. Prepare a draft prerelease for that tag and upload `candidate-selection.json` without replacing existing assets. Include `hardware-qualification.zip` only when supplying optional real-device evidence. Complete private acceptance before opening the fresh repository and making the release package public.

```sh
gh workflow run publish-container.yml --repo mitkox/opencyber --ref v0.5.0 -f version=0.5.0 -f candidate_run_id=BUILD_RUN_ID -f selection_sha256=SELECTION_SHA256
```

Publication validates the successful canonical workflow run, exact selected artifact IDs and archive hashes, both source receipts and build attempt before any public copy. When `qualification_sha256` is supplied it also validates the complete hardware archive; otherwise `qualification-status.json` explicitly records `not_qualified`. It never builds an image. It then:

1. Publishes deterministic source/compliance archives in 1 GiB parts, the selection, qualification status, any supplied sanitized device bundle and `SHA256SUMS`. Anonymous downloads must work before image promotion; the prerelease is labelled verification pending.
2. Copies platform digests with `--preserve-digests`, verifies them, constructs the two-platform manifest and signs the promoted digests. Receipts identify the original build; signatures/attestations identify the promotion workflow at the canonical tag.
3. Verifies anonymous registry access, signatures, provenance and real native runtime, MCP, blue-team and PoC acceptance on fresh runners.
4. Publishes only `ghcr.io/mitkox/opencyber:0.5.0` and retains the GitHub prerelease label. Hardware interfaces are experimental unless the attached status and device matrix prove qualification. Production qualification remains separate.

Existing version references and release assets are immutable: identical retries are allowed; replacement bytes are refused. A changed published candidate needs a new version. Failed public acceptance leaves the release pending. Do not finalize manually or treat a private candidate as public acceptance evidence.

## Verify a release

```sh
docker buildx imagetools inspect ghcr.io/mitkox/opencyber:0.5.0
gh attestation verify oci://ghcr.io/mitkox/opencyber:0.5.0 --repo mitkox/opencyber
gh release download v0.5.0 --repo mitkox/opencyber --dir release-evidence
```

Check `SHA256SUMS`, concatenate each platform's `compliance.tar.part-*` files in lexical order and extract the tar. Verify its source checksums and retain corresponding source for the period promised in [SOURCE_OFFER.md](../SOURCE_OFFER.md). Exercise the documented installer against the published digest before accepting the release for use.
