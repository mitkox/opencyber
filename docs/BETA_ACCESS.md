# Manage private beta access

The complete reviewed OpenCyber source and the published
[v0.5.0-private-beta.1 full-toolkit amd64 preview](https://github.com/mitkox/opencyber/releases/tag/v0.5.0-private-beta.1)
are in the same private [`mitkox/opencyber`](https://github.com/mitkox/opencyber)
repository. A repository **Read** invitation exposes both the source and all
private release assets, including the image and source/compliance bundles.
GitHub Releases cannot restrict those assets separately from repository Read.
Invite only the small group selected by the maintainer; a source-only invitation
is not possible in this repository while those assets are present.

The maintainer chose to retain the full toolkit in this unqualified private
preview. Oracle/PDB vendor reviews and license metadata remain unresolved; no
accepted vendor agreement or redistribution entitlement is asserted. Private
access does not waive component terms. See [BETA_VENDOR_TERMS.md](BETA_VENDOR_TERMS.md).
Keep private development history in `mitkox/opencyber-development`.

GitHub Free supports this setup without paid collaborator seats. If the
organization later adopts a paid plan, outside collaborators on private
repositories consume paid licenses. Outside collaborators cannot join teams.
See [GitHub's outside-collaborator guide](https://docs.github.com/en/organizations/managing-user-access-to-your-organizations-repositories/managing-outside-collaborators/adding-outside-collaborators-to-repositories-in-your-organization).

## Invite a tester

Review the selected tester's access knowing that it grants the published binary
preview as well as source. The current release has no independent
recipient-specific asset gate. The unresolved vendor process below must not be
described as completed by issuing an invitation.

In the repository, open **Settings → Collaborators and teams → Add people**,
select the tester's GitHub account, and grant **Read**. Invite them directly to
this repository rather than making them an organization member. Repeat for the
selected accounts (up to the planned 30 testers). If two-factor authentication
is required by the organization, testers must enable it before accepting.

The equivalent authenticated maintainer command is:

```sh
gh api --method PUT repos/mitkox/opencyber/collaborators/GITHUB_USERNAME \
  -f permission=pull
```

`pull` is GitHub's API permission for the Read role. Confirm pending invitations:

```sh
gh api repos/mitkox/opencyber/invitations \
  --jq '.[] | {login: .invitee.login, permissions}'
```

After acceptance, verify the effective role:

```sh
gh api repos/mitkox/opencyber/collaborators/GITHUB_USERNAME/permission \
  --jq '{login: .user.login, permission, role_name}'
```

Expect `permission: "read"` and `role_name: "read"`. Review any account already
granted a higher role before treating it as a read-only tester; organization
membership and other grants can affect effective access. Existing contributors
are separate from beta invitations.

## What Read access provides

Testers can browse, clone and download all tracked source and documentation,
download the private release's full image and source/compliance assets, and use
repository issues for redacted feedback. They cannot push commits,
edit repository settings or run write-authorized workflows. Keep private
forking disabled in repository settings. Read access permits a local copy;
removing GitHub access does not erase copies already downloaded.

Send accepted testers to [BETA_TESTING.md](BETA_TESTING.md) and the published
release's `README.md`. Download all 38 assets, about 13.3 GB, using their own
authenticated GitHub account:

```sh
gh auth login
gh release download v0.5.0-private-beta.1 \
  --repo mitkox/opencyber --dir opencyber-beta
```

No GHCR permission or Docker registry login is needed. Carry the complete
directory for offline import and follow [AIRGAP.md](AIRGAP.md); use the supplied
`beta-import.sh` to verify and assemble this release's split image. The frozen
source is `c1201976caf49c45068bb507032aee75e4509e20`; the local image tag is
`opencyber:0.5.0-private-beta.1-amd64`.

The beta guide covers MCP setup and a synthetic first exercise.
Hardware integrations are supported for beta use; [HARDWARE.md](HARDWARE.md)
covers device access, and [HARDWARE_QUALIFICATION.md](HARDWARE_QUALIFICATION.md)
records the device combinations and operations actually qualified.

## Future qualified candidates and separate delivery

The published amd64 preview is not a qualified candidate. Normal candidate
gates still require completed license/source review and matching native
amd64 software acceptance under [RELEASE.md](RELEASE.md). A source install
does not include the container toolchain, browser or offline assets.

For a future qualified delivery, complete the distributor approval,
exact-component entitlement evidence and executed recipient agreement described in
[BETA_VENDOR_TERMS.md](BETA_VENDOR_TERMS.md). The retained Oracle and Microsoft
DIA components require this review; selecting those features or supplying an
unsigned draft does not approve redistribution. These requirements remain
unresolved for the current preview; they are not enforced by its same-repository
release access.

The candidate workflow's private organization package is
`ghcr.io/mitkox/opencyber-beta-candidates`. Keep inheritance from the source
repository disabled. [GitHub limits direct access grants for private organization packages](https://docs.github.com/en/packages/learn-github-packages/configuring-a-packages-access-control-and-visibility)
to organization members or teams, so direct package Read for an outside
collaborator is not an established delivery path. The current preview uses
private release assets instead. If future delivery needs recipient-specific
binary approval independent of source Read, select and verify a separately gated
channel: for example, a distinct private delivery repository containing only
approved recipients, or an authenticated artifact store. If its package
inherits access from a delivery repository, every reader must have completed
the vendor process. Do not add testers to the organization to bypass this
unresolved delivery design.

After all gates pass for that future delivery, grant only approved recipients
access through that channel. Check its linked repository and Actions access; a repository transfer
does not transfer personal-account GHCR packages into the organization. Apply
the same approval boundary to downloaded image bundles and source/compliance
archives containing vendor binaries or binary package inputs. Open-source
corresponding-source rights remain governed by their own licenses; do not
require vendor terms to obtain an open-source-only source delivery.

Supply the frozen source commit, selected candidate run, exact platform digest
and checksummed compliance/source evidence as described in [RELEASE.md](RELEASE.md).
Verify the approved account can clone and retrieve the selected image, while a
source-repository-only account without vendor approval and anonymous users
cannot retrieve that separately gated binary delivery. This distinction cannot
be verified for the current same-repository preview: every repository reader
can retrieve its assets. For GHCR, pull the exact digest. Verify
artifact/archive access separately. Keep the repository and candidate packages
private until an explicit public release decision. Production acceptance
remains separate.

## Remove access

Remove a tester through the repository's access settings, then remove any
separate package and archive grants. Verify their repository, package and
artifact access is gone. Keep the invitation roster and required executed
vendor/distribution records privately; do not commit identities or tokens.
Access removal does not erase downloaded copies or cancel open-source rights.
