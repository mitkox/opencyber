# OpenCyber 0.5.0 public release review

This records source review and validation toward the first open-source prerelease.
0.5.0 is currently a private pre-production beta; no public release is claimed.
It is separate from native image qualification, optional operator hardware evidence and public digest acceptance. Software,
source integrity and public acceptance remain required; hardware is experimental.

## Review coverage

Separate implementation and independent review passes covered process execution;
authorization, approval and PoC state; HTTP/API/browser access; workspaces,
audit, evidence and retention; all MCP authority declarations; remaining
catalog, asset, triage, hardware, CVE and diagnostic modules; adapters; installer,
launcher, airgap and packaging; source/license capture and release workflows.
Focused regressions reproduced the findings below before behavioral repairs.

| Finding | Consequence | Repair and regression evidence |
| --- | --- | --- |
| Approval replay after interruption | Target traffic could occur while approval remained reusable | Revalidate and consume durably under a cross-process lock before launch; cancellation, crash, failed persistence and concurrent-consumer tests |
| Native redirect scope escape | Initially in-scope requests could contact another host | Check native HTTP/API redirect hosts before sending; six real requests redirect paths tested |
| Redirect credential forwarding | Cross-origin and downgrade workbench requests retained credentials | Strip authorization/proxy credentials and explicit or hostless cookies; redirect regressions |
| Process cleanup/deadline gaps | Descendants survived leader exit; blocked stdin escaped the deadline | Process-group cleanup, bounded stdin and pre-spawn limit validation; actual subprocess regressions |
| Misleading authority metadata | Mutation-capable tools advertised read-only behavior or incorrect engagement needs | Correct native/executable authority and target-content declarations; public registration tests |
| Retained evidence races and stale content | Independent processes could lose index rows; digest-only replacement exposed old full content | File locking, unique atomic writes and explicit integrity refusals; concurrent-process and tampering tests |
| Audit chain discontinuity | Large records restarted sequence numbering; malformed/symlinked trails appeared empty | Secure tail/stream handling and bounded records; large-record, corruption and symlink regressions |
| Catalog/asset integrity gaps | Invalid header or unavailable content hash could pass verification | Validate manifest self-consistency and require expected deep hashes; tampering regressions |
| Hardware cleanup and coverage | Serial settings remained altered; strings exceeded the stated firmware window | Restore independent termios snapshot and enforce the analysis window; PTY and bounded-file regressions |
| Invalid numeric limits | NaN was accepted by diagnostics but refused by execution | Require finite values; non-finite setting tests |
| Truncated CVE-chain input | Partial scanner artifacts were treated as complete | Refuse truncated input explicitly and require complete smaller artifacts |
| Incorrect NVD feed verification | Official metadata naming, format and digest semantics were unsupported | Canonical plaintext metadata and uncompressed-byte SHA-256; official-format hermetic fixtures |
| Unknown license metadata accepted | Unresolved redistribution decisions passed the release gate | Unknown/NOASSERTION/LicenseRef identities require explicit version-bound reviewed decisions |
| Publication rebuilt candidates and advanced stable aliases | Hardware evidence did not bind final builds; prerelease became stable | Select immutable build artifacts, record optional hardware evidence explicitly, promote exact digests and finalize only the versioned prerelease |
| Release retries replaced bytes | Existing assets or image references could be overwritten | Reject changed bytes, verify manifest children and permit identical retries only |

The following dispositions refer to the repaired source. Reproduce each case
with `PYTHONPATH=src python -m unittest tests.<module>` using the module names
below; the assertions describe the former failure and the required behavior.
Severity describes the reachable consequence in the trusted-client model.

| Finding | Severity | Source location | Regression module | Disposition |
| --- | --- | --- | --- | --- |
| Approval replay | High | `src/opencyber/poc.py`, `poc_approval.py` | `test_poc`, `test_poc_approval` | Fixed |
| Redirect scope escape | High | `src/opencyber/http_client.py` | `test_http_redirect_scope` | Fixed |
| Redirect credentials | High | `src/opencyber/http_workbench.py` | `test_http_redirect_scope` | Fixed |
| Descendant/deadline gaps | High | `src/opencyber/executor.py` | `test_executor` | Fixed |
| Authority declarations | Medium | `src/opencyber/contracts.py` | `test_authority_behavior`, `test_contracts` | Fixed |
| Retention races/stale content | Medium | `src/opencyber/result_store.py` | `test_result_store` | Fixed |
| Audit discontinuity | Medium | `src/opencyber/audit.py` | `test_audit` | Fixed |
| Catalog/asset integrity | Medium | `src/opencyber/catalog_identity.py`, `assets.py` | `test_catalog_identity`, `test_assets` | Fixed |
| Hardware cleanup/coverage | Medium | `src/opencyber/hardware.py` | `test_hardware` | Fixed; real devices unqualified |
| Non-finite limits | Medium | `src/opencyber/limits.py` | `test_limits`, `test_http_timeouts` | Fixed |
| Truncated CVE input | Medium | `src/opencyber/cve_chain.py` | `test_cve_chain` | Fixed |
| Official feed verification | Medium | `src/opencyber/cve_index.py` | `test_cve_index` | Fixed |
| Unknown license gate | High | `scripts/check-license-policy.py` | `test_license_policy` | Gate fixed; image licenses still require review |
| Candidate substitution/stable aliases | High | `scripts/lib/release_candidates.py`, `promote-images.py` | `test_release_candidates`, `test_release_gate` | Fixed |
| Mutable release retries | High | `scripts/lib/release_candidates.py`, `promote-images.py` | `test_release_candidates`, `test_release_gate` | Fixed |
| Retention lock stalled MCP | Medium | `src/opencyber/envelope.py` | `test_result_store` | Fixed; independent-process lock contention |
| Failed results claimed complete coverage | Medium | `src/opencyber/envelope.py` | `test_envelope` | Fixed; unknown unless explicitly measured |
| Public export omitted installer | Medium | `scripts/export-public-snapshot.py` | `test_public_snapshot` | Fixed; exact bytes and executable mode checked |
| Containerd image IDs refused | Medium | `scripts/release-gate.py` | `test_release_gate` | Fixed; bind manifest IDs and classic config IDs according to Docker's descriptor and refuse substitution |

## Compatibility and documentation

The implementation uses MCP Python SDK 2.3 and `MCPServer`. Tests cover actual
stdio initialization, structured refusal/results, camelCase wire annotations,
catalog identity and all 255 registered tools. Client launch commands remain
stdio-based. The operator/client is trusted; environment scrubbing does not
isolate signing authority from container root.

Public documentation starts at 0.5.0. The public export contains a single
reviewed source snapshot and excludes prior verification history. Any device matrix describes tested combinations only; no synthetic run qualifies
hardware. Real-device qualification is deferred for this prerelease.

## Validation and outstanding gates

The final source suite passed 647 tests (one skip) on Python 3.11, 3.12 and
3.13. Combined statement/branch coverage is 81%, above the 70% gate. Ruff,
mypy, discovery/boundary guards, generated references, catalog/version checks,
ShellCheck and actionlint passed. Wheel and sdist metadata validation passed.
Independent review completed with no current actionable source findings.

Local amd64 runtime checks exercised actual MCP stdio, strict catalog identity,
blue-team evidence, the disposable PoC lab and a hardened Chromium session.
These are development checks. Image qualification must be repeated at the new
clean repository's frozen root commit and exact platform digests. License
inventory, vulnerability assessment, corresponding source and both native
platform receipts must pass before publication; this document does not attest
that those gates or anonymous public acceptance have passed.

The updated local amd64 image passed the HIGH/CRITICAL vulnerability gate with
zero findings and no exceptions. This follows patched Go builds and Kali
libraries, Prowler 5.45 on Python 3.13, and its upstream PyMongo 4.18.2 override.
The vulnerable URI-parser behavior was reproduced before the update and refused
afterward; BSON roundtrips and Huawei SDK imports passed. Terrascan and
ScoutSuite remain optional adapters because their bundled dependency graphs
could not meet the gate without a broader fork. The beta guide's actual MCP
triage, timeline, audit and evidence exercise passed in an isolated container.

Enriched license metadata remains a distribution gate, including private beta
images. The original 3,925 unresolved inventory entries represented missing or
unrecognized license metadata, not 3,925 proven violations. Version-specific
metadata enrichment and component updates reduced the local amd64 inventory to
2,147 unresolved entries, including 849 with no license metadata. Those counts
are development evidence and must be regenerated for the frozen candidates.
Missing identities,
ambiguous labels and custom license terms require attributable evidence; they
are not automatically proven license violations or a reason to waive the gate.

Real-device qualification is deferred by release policy. All hardware interfaces
remain experimental; this does not block the 0.5.0 prerelease. Native image and
public acceptance must still pass. No production qualification is claimed.
