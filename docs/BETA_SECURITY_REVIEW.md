# Beta security review - 2026-10-28

The repository source is preparing 0.5.1. The frozen
`v0.5.0-private-beta.1` image does not contain these fixes and is not cleared by
this review for further binary distribution. Its bytes and tag are unchanged.

Testers download and run their own copies. They receive no maintainer backend,
Docker socket, workspace, approval key or host credentials. Repository Read
includes every existing release asset; access removal cannot erase downloaded
copies. Repository visibility remains private. The maintainer confirmed that
the existing non-owner Write grant belongs to a trusted contributor.

## Repairs in the next source version

- HTTP workbench cookie persistence now retains origin, host-only/domain,
  Path, Secure, expiry and other attributes. Redirects suppress credentials
  without erasing the original host's stored cookies. Exact origins remain
  distinct even when Python's cookie jar uses a synthetic `.local` domain.
- Older flat cookie records are cleared on first use because their security
  attributes were lost. Re-authenticate or explicitly update cookies.
- Docker input filters exclude root and nested credential directories/files
  and private verification records. Corresponding-source capture uses explicit
  build-input copies and a second archive allowlist. A network-disabled scratch
  build checks 13 synthetic private markers and a retained public-source control
  in image CI.
- The previous refusal/error-code and 256 KiB HTTP response-limit fixes are
  included. The container MCP SDK is pinned to 2.3.0.
- Prowler's PyMongo pin advances from 4.18.2 to 4.18.3 for
  [CVE-2026-106435](https://www.mongodb.com/docs/languages/python/pymongo-driver/current/reference/release-notes/).
  An offline disposable-container check verifies BSON round-trip and Prowler
  provider imports with the fixed wheel. Build-generated snakeoil TLS key and
  certificate files are removed during package installation; operators must
  provision their own keys before starting any TLS service.

## Scan results for the existing preview

Trivy 0.76.1 used vulnerability database update `2026-10-28T13:01:10Z`.
The inspected local image ID is
`sha256:a059c5ecd9d59489f8f99039dd237910a9c90b38a575aab58e2e7b8606344e8a`.
The downloaded metadata/source assets matched their GitHub asset digests.

| Scope | Result |
| --- | --- |
| Tester-repository history and working source, Gitleaks | No detected secrets |
| Published first-party source archive, Gitleaks | No detected secrets; no private Git or credential paths found |
| Captured first-party build context and source, matched to the published source-manifest hashes | No detected secrets |
| Downloaded release metadata/SBOMs and image configuration/history, Gitleaks | No detected secrets |
| Image filesystem, default precise vulnerability detection | One HIGH finding: PyMongo 4.18.2, fixed upstream in 4.18.3 |
| Published CycloneDX SBOM vulnerability scan | 306 package/advisory matches: 286 HIGH, 20 CRITICAL; 172 distinct advisories |
| Image filesystem, comprehensive vulnerability detection | 373 package/advisory matches: 350 HIGH, 23 CRITICAL; 192 distinct advisories |
| Image filesystem, secret detection | 34 hits requiring classification: 25 in Nuclei payload/template data, eight in OCI SDK source/bytecode, one generated snakeoil TLS key |

The comprehensive scan includes dependencies bundled inside distribution-owned
tools that precise detection can omit. The two modes do not establish the same
coverage. Candidate scans now select comprehensive detection; the HIGH/CRITICAL
gate still includes unfixed findings. None of these results establishes that
every advisory is exploitable in this deployment. Package backports, bundled
code and intentionally supplied assessment payloads need attributed review;
the findings are not waived here.

No maintainer credential leak was confirmed in the inspected material. Secret
detector hits in assessment payloads and SDK documentation are not evidence of
maintainer credentials, and absence of a scanner finding does not prove that
all sensitive data is absent. Raw scanner output stays outside the source tree;
no secret values or operator evidence are included in this report.
The complete third-party source bundle was not exhaustively reviewed for
embedded test credentials or private third-party data.

## Remaining distribution gates

A new image needs a matching source commit, complete rebuilt-image acceptance,
current comprehensive vulnerability triage/remediation, corresponding source,
license/vendor clearance and native architecture evidence. The current preview
still has unresolved vendor/license records and unqualified architectures.
Source tests and an offline compatibility probe do not clear these gates.

Keep first exercises synthetic and use the network-disabled blue-team profile.
Tools intentionally execute as container root, evidence can contain credentials,
and the tester's MCP/model client may transmit returned data to its provider.
This review does not establish hostile-client isolation or production readiness.

## Public-beta review assignment (2026-11-09)

- **Reviewer:** `mitkox-ai`, assigned by the maintainer as the independent reviewer for the public-beta delta.
- **Review package:** pull request https://github.com/mitkox/opencyber/pull/4 (head `feat/public-beta-readiness`, vendor-removal commit `a9544e0`). The reviewer records the final reviewed commit here after the review.
- **Required coverage:** cookie handling, response cap, refusal codes, redirect canonicalization, PoC truncation and TLS defaults, browser bounds, airgap identity, MCP contract/authority changes, installer and release tooling.
- **Status:** review requested; sign-off is not yet recorded. This section must be replaced with the reviewer's covered-surface statement, finding dispositions and final reviewed commit before the go/no-go record can cite a completed review.
