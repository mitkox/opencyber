# Release OpenCyber Harness 0.5.0

0.5.0 is currently a **private pre-production beta**. The full-toolkit
`v0.5.0-private-beta.1` amd64 preview is published privately; it is not a
qualified candidate or public release. Keep the repository and candidate
package private. The maintainer adds beta users; this guide does not authorize
public publication. Source review, native software acceptance and future public
digest acceptance are separate gates. Hardware integrations are supported for
beta use; real-device qualification is recorded separately.
There is no PyPI publication; 0.5.0 never advances `latest`, `0` or `0.5` tags.

The source is Apache-2.0; bundled software retains its own licensing terms.
Private access does not waive those terms or resolve redistribution obligations.
Preserve corresponding source and notices for the exact delivered bytes.

## Published unqualified private preview

The maintainer chose to keep the full toolkit in a private preview for a small
invited group, retaining Oracle connectivity and optional Microsoft PDB
components while vendor reviews remain pending. This decision is not evidence
of vendor acceptance or legal clearance. The published drop is:

- [Release v0.5.0-private-beta.1](https://github.com/mitkox/opencyber/releases/tag/v0.5.0-private-beta.1).
- Frozen source commit `c1201976caf49c45068bb507032aee75e4509e20`.
- Native `linux/amd64` image `opencyber:0.5.0-private-beta.1-amd64`, with image
  ID `sha256:a059c5ecd9d59489f8f99039dd237910a9c90b38a575aab58e2e7b8606344e8a`.
- 38 assets, about 13.3 GB: 14 numbered image/source parts split at 1 GiB,
  complete first-party `opencyber-source-c120197.tar.gz`, captured corresponding
  source, notices, SBOMs, checksums, the actual license-gate report and
  `beta-import.sh`.

The recorded amd64 validation ran 689 tests with one skip and 81% coverage.
Actual offline tool, MCP, blue-team, export/import, doctor and source-matching
checks passed. The recorded Trivy scan found zero HIGH/CRITICAL findings,
including unfixed findings. Captured source matched 1,428 components and 3,717
artifacts. These are the supplied build's observations, not all-feature or
future vulnerability guarantees.

The strict license gate is **not green**: its 5,129-component inventory has
2,086 unresolved license records and two vendor reviews. Unknown scanner
metadata is not itself proof that a component is unlicensed, but the unresolved
records still need review. No vendor agreement or entitlement is asserted.
Native arm64, hardware, live Oracle/PDB workflows and production remain
unqualified. The normal candidate and public-promotion gates below remain
blocking; this preview does not satisfy or change them.

Source and release assets are in the same private repository. Every repository
reader can retrieve the image and source/compliance archives, without GHCR
access or a separate release-asset permission. Invite only selected testers;
see [BETA_ACCESS.md](BETA_ACCESS.md), [BETA_VENDOR_TERMS.md](BETA_VENDOR_TERMS.md)
and [AIRGAP.md](AIRGAP.md). Preserve the published parts, tag and source snapshot;
do not rebuild or overwrite them. Corrections to the delivered artifact need
a new version and matching evidence.

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

The reviewed source snapshot is hosted privately at `mitkox/opencyber`,
transferred from `mitkox/opencyber` with its numeric repository identity and
clean history intact. Keep development history in `mitkox/opencyber-development`;
never merge or push its historical Git objects into the beta repository. The
snapshot export procedure (`scripts/export-public-snapshot.py`) remains the
way to create a fresh reviewed root if one is needed. Preserve licenses and
authorship. Do not recreate the old repository name: that removes its redirect.

Update beta clones with `git remote set-url origin https://github.com/mitkox/opencyber.git`.
Check Actions permissions, available protections and package access after the
transfer. Freeze the source commit before building; evidence must match the
current repository name, numeric ID, commit, workflow, run and attempt.
Historical development CI and local images do not qualify this repository.
Keep subsequent qualification outputs outside the frozen source tree.

## Build qualified candidates privately

This procedure is separate from the published unqualified preview. Its
vulnerability, license, source and both native-platform gates remain required.

```sh
gh workflow run build-candidate.yml --repo mitkox/opencyber --ref main -f version=0.5.0
```

The workflow runs full CI and builds on native amd64 and arm64 runners. Each platform must pass doctor, strict catalog alignment, actual MCP stdio, synthetic blue-team and PoC fixtures, hardened runtime, airgap export/import, assets, image compliance and exact corresponding-source capture. SBOMs describe the tested runtime. HIGH and CRITICAL vulnerabilities, including unfixed findings, block the build. For 0.5.0, update or exclude affected components rather than adding vulnerability exceptions. License policy and missing source archives remain blocking. Valid SPDX identifiers are accepted from either CycloneDX license IDs or names; ambiguous aliases are not guessed. Unknown SPDX expressions or missing license identities require an exact-version `purl` decision in `reviewed_license_components`, naming `license_expression`, `owner`, `basis` and `reviewed_at`. A custom-license decision also records the actual redistribution basis, required notices, source obligations and a captured license file with its SHA-256 and upstream URL. `--license-evidence-root` selects the retained evidence directory (default: the policy directory). Unresolved entries are never waived by a component-name allowlist. SBOM generation uses installed-image catalogers; source-only workflow and lockfile references are not falsely reported as installed dependencies.

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

Corresponding-source matching includes content/path hashes of the direct asset
trees, including WPScan metadata. Matching package versions alone cannot prove
those downloaded bytes match the tested image. Older source inventories without
these hashes must be regenerated; they cannot qualify this candidate.

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

The maintainer invites external testers to `mitkox/opencyber` as
**outside collaborators with Read access**. They can clone the complete reviewed
source and report issues without receiving push access or organization
membership. Do not invite testers to `mitkox/opencyber-development`.
Follow [BETA_ACCESS.md](BETA_ACCESS.md) for the 30-tester setup, invitation
commands and permission verification. Keep private forking disabled.

The organization uses GitHub Free, which supports this private Read-access
setup. Protected branches on private repositories require a suitable paid plan;
The maintainer chose to keep Free and defer branch protection. CI alone does
not enforce a protected-branch merge boundary. Read-only testers
cannot push, but existing maintainers and contributors retain their own grants.
Do not make the repository public to obtain additional plan features.

The current preview is delivered through the same repository's private release
assets. A Read invitation grants those assets automatically; it cannot serve
as a source-only or recipient-specific vendor gate. Its supplied helper handles
the split bundle without GHCR. Follow [AIRGAP.md](AIRGAP.md).

For future qualified candidates that need a recipient-specific approval
boundary, arrange binary delivery separately. Direct private organization-package
grants are limited to organization members and teams; an outside collaborator cannot
simply receive a direct package Read grant. Use an approved archive channel,
or verify a supported registry permission arrangement as described in
[BETA_ACCESS.md](BETA_ACCESS.md). Complete [BETA_VENDOR_TERMS.md](BETA_VENDOR_TERMS.md)
before delivery of conditional vendor binaries. Disable automatic repository
permission inheritance where it could bypass recipient-specific checks.
Repository transfer does not move
personal GHCR packages into the organization. New candidates and future release
images use `ghcr.io/mitkox/opencyber-beta-candidates` and
`ghcr.io/mitkox/opencyber`, respectively. Link each organization package to
`mitkox/opencyber`, inspect permission inheritance, and grant the repository
Actions access for builds. Do not relabel historical images as qualified
organization candidates. Keep candidate storage private and verify anonymous
pulls are denied. See [GitHub's package permissions](https://docs.github.com/en/packages/learn-github-packages/about-permissions-for-github-packages).

After a complete successful qualified candidate run, provide each approved
tester with the frozen source commit, selected run ID, their host architecture, its exact platform
digest, checksummed compliance/source bundle and the [beta guide](BETA_TESTING.md).
The guide uses authenticated GitHub source access and archive import, with
GHCR login only when supported access has been verified. Never include tokens
in invitations, issue reports, MCP configuration or evidence. Confirm an
approved recipient can clone and retrieve the assigned binary, while an
unapproved recipient and an anonymous client cannot retrieve those separately
gated vendor deliveries. That source-only distinction is unavailable for the
current same-repository preview.

Failed license, source or software checks block qualified-candidate status and
promotion, including during private beta. The published preview is explicitly
unqualified and retains unresolved obligations; its private availability is not
a passing gate or authorization for broader distribution. Keeping the repository
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
4. Publishes only `ghcr.io/mitkox/opencyber:0.5.0` and retains the GitHub prerelease label. Hardware integrations are supported for beta use; the attached status and device matrix identify any qualified combinations. Production qualification remains separate.

Existing version references and release assets are immutable: identical retries are allowed; replacement bytes are refused. A changed published candidate needs a new version. Failed public acceptance leaves the release pending. Do not finalize manually or treat a private candidate as public acceptance evidence.

## Verify a release

```sh
docker buildx imagetools inspect ghcr.io/mitkox/opencyber:0.5.0
gh attestation verify oci://ghcr.io/mitkox/opencyber:0.5.0 --repo mitkox/opencyber
gh release download v0.5.0 --repo mitkox/opencyber --dir release-evidence
```

Check `SHA256SUMS`, concatenate each platform's `compliance.tar.part-*` files in lexical order and extract the tar. Verify its source checksums and retain corresponding source for the period promised in [SOURCE_OFFER.md](../SOURCE_OFFER.md). Exercise the documented installer against the published digest before accepting the release for use.
