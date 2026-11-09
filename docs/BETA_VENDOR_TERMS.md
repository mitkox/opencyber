# Vendor terms and unresolved beta reviews

The published [v0.5.0-private-beta.1 private preview](https://github.com/mitkox/opencyber/releases/tag/v0.5.0-private-beta.1)
retains Oracle connectivity and optional Microsoft PDB analysis. The maintainer
chose a full-toolkit preview for a small invited group, with vendor reviews
still pending. It is **unqualified**. No accepted vendor agreement, signature,
acquisition entitlement or completed redistribution review is asserted.
Private access does not waive original terms, and choosing to retain a feature
does not accept an agreement or clear distribution.

The source and binary assets currently share one private repository. Every
repository reader can download the release image and source/compliance assets;
GitHub Releases offers no separate recipient-specific asset permission. The
approval process below remains unresolved, rather than being an access control
already implemented by this preview. The normal qualified-candidate and public
gates in [RELEASE.md](RELEASE.md) remain unchanged.

## Future separation of source access and binary delivery

The tracked first-party source contains no Oracle Instant Client or Microsoft
DIA binaries, but the repository's published image does. A current invitation
therefore supplies both source and binary access, as described in
[BETA_ACCESS.md](BETA_ACCESS.md). Disabling package inheritance cannot restrict
GitHub release assets in that same repository.

For a future delivery that enforces recipient-specific approvals separately
from source access, the requirements are:

| Delivery | Access requirement |
| --- | --- |
| First-party source and documentation | Maintainer-approved repository Read invitation |
| Candidate image, saved image or offline image bundle | Completed release gates and vendor delivery record for that recipient |
| Source/compliance archive containing vendor binaries or binary package inputs | The same recipient-specific vendor gate as the image; keep it outside the source repository |
| Open-source corresponding source without vendor binaries | Supply under the applicable component licenses and [SOURCE_OFFER.md](../SOURCE_OFFER.md) |

Inspect archive contents rather than relying on a filename such as "source" or
"licenses". Download links, workflow artifacts, release assets and shared
storage for such a delivery must enforce the same boundary. The current
same-repository preview does not provide that separation.

[GitHub's package-access rules](https://docs.github.com/en/packages/learn-github-packages/configuring-a-packages-access-control-and-visibility)
limit direct grants on private organization packages to organization members or
teams. Disabling inheritance therefore does not establish direct GHCR access
for outside collaborators. Keep source testers as outside collaborators; review
a separate private delivery repository with only approved recipients, or an
authenticated archive store. If package inheritance is used with a delivery
repository, every reader of that repository must already meet the vendor gate.
Verify the chosen channel before promising separately gated binary access. No
GHCR access is needed for the current release. This guide does not authorize
organization invitations or establish that a future delivery channel or vendor
process has been approved.

These vendor requirements apply only to the identified vendor components and
their documentation. They do not add restrictions to GPL, LGPL, MIT, Apache or
other separately licensed components, cancel their redistribution rights, or
condition a corresponding-source entitlement on signing vendor terms. Provide
an open-source-only source delivery when a combined archive would include
restricted binaries. See [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md).

## Review the actual vendor components

Oracle Instant Client is pulled in through Metasploit and `ruby-oci8`. Review
the installed package copyright against the
[Oracle Technology Network distribution agreement](https://www.oracle.com/downloads/licenses/distribution-license.html).
Prepare the end-user terms required by its Programs Redistribution section,
including its prescribed section coverage and exclusions. Preserve the
executed recipient agreement and required distribution records. Distributor
approval must explicitly address the agreement's indemnity, enforcement,
record inspection and breach-handling obligations; a notice file alone cannot
complete that approval.

The `pyxdia` package includes Microsoft's `msdia140.dll` for optional PDB
analysis through `xdialdr`. Its MIT wrapper license does not license that DLL.
The [Visual Studio 2022 redistribution list](https://learn.microsoft.com/en-us/visualstudio/releases/2022/redistribution#dia-sdk)
names the DIA DLL subject to the applicable Visual Studio terms. Establish the
valid license/acquisition and onward-distribution chain for the exact bundled
bytes. Review section 4 of the
[Visual Studio Community 2022 terms linked by the package](https://visualstudio.microsoft.com/license-terms/vs2022-ga-community/),
or document a different applicable grant. A file appearing on the list does
not establish entitlement. General ELF/PE metadata analysis is distinct from
the optional PDB capability; retaining both does not resolve this gate.

## Required private approval record

Keep the draft, vendor license captures, identities and signatures in a private
approval store outside the source tree. Link each record to the exact qualified
delivery, using its source commit, platform digest, workflow/run/attempt,
artifact identities and archive SHA-256 values. Record:

1. The distributor's legal identity, address, authorized signatory and explicit
   approval of the applicable vendor obligations and delivery scope.
2. The exact vendor package versions, binary hashes, original notices, license
   text hashes and evidence supporting the distributor's grant. Leave any
   missing entitlement evidence unresolved.
3. The approved recipient agreement and its attached, fixed vendor terms.
   Confirm that its restrictions address only the scheduled vendor components
   and preserve separately licensed component rights.
4. The recipient's legal name and address, GitHub identity, authorized signer,
   completed execution date and immutable agreement copy/hash. Complete these
   fields from the actual recipient; do not use placeholders as approval.
5. The approved binaries and archives, selected delivery channel, date of
   delivery, operator, effective package/archive access verification and the
   agreement covering that delivery. Record enforcement and record-retention
   responsibility.

For a qualified delivery, the sequence is **draft → authorized distributor
review → executed recipient agreement → release-gate verification →
recipient-specific access → delivery receipt**. An unsigned draft, repository
Read, a successful build or a clean
scanner report does not establish vendor approval. The current preview's
repository permission grants binary access without proving this sequence
complete. Use an appropriate qualified reviewer for legal questions; this guide records the
process and makes no legal-clearance finding.

## Verify a future recipient-specific delivery

After every required approval and release gate passes and a supported delivery
channel is verified, the maintainer can grant that recipient access to the
scheduled image and archives. Read back the effective permissions and verify
that an approved account can retrieve the exact bytes, an unapproved
source-repository-only account cannot, and anonymous access is denied. The
source-only distinction is unavailable for the current same-repository release.
For GHCR, verify pulls by exact digest; check archive access separately. Keep publication,
private binary delivery and production acceptance separate.

Remove package/archive access when the approval no longer covers the recipient
or delivery. Preserve required records and handle any vendor-component breach
through the approved process. Removing server access cannot erase downloaded
copies or revoke independently granted open-source rights.
