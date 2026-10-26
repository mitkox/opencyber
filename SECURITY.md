# Security policy

OpenCyber Harness is a capability container for authorized security work. It
runs untrusted-by-design tooling and ships offensive-security utilities, so the
container and the host around it need to be treated as a security boundary.

## Supported versions

| Version | Supported |
| --- | --- |
| `0.5.x` prereleases | Yes, best effort |
| Other versions | No |

0.5.0 has a published Linux amd64 private preview, `v0.5.0-private-beta.1`.
Follow [the beta guide](docs/BETA_TESTING.md) for verified archive import.
Security fixes land on the supported `0.5.x` line; use a new maintainer-provided
release when a fix is available. Published preview bytes are never replaced.
Public release and full qualification remain pending.
Hardware integrations are supported for beta use. Support does not establish
real-device or production qualification; device claims require recorded evidence.

When reporting, include the exact image digest where possible. A tag can move;
a digest identifies the build you tested.

## Reporting a vulnerability

During the private beta, email suspected vulnerabilities to
[tech@mitkox.com](mailto:tech@mitkox.com). Start with a redacted summary and ask
for a secure transfer method before sending sensitive evidence.

GitHub's private vulnerability reporting is available for public repositories,
so the advisory form is not the beta reporting route. Once public reporting is
enabled, this policy will link the active advisory form. See
[GitHub's reporting documentation](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/report-privately).

Do not open a public issue, discussion, or pull request for a suspected
vulnerability. Do not include exploit details in a public channel. If the
email route is unavailable, contact the maintainer directly on GitHub
([@mitkox](https://github.com/mitkox)) before disclosing anything publicly.

A useful report includes:

- The affected version and image digest, or the commit for a source checkout.
- The install path: published image, local build, `install.sh`, or source.
- Host architecture, Docker/Engine version, and the `docker run` flags or
  launcher profile used.
- The relevant `OPENCYBER_*` environment variables, with secrets redacted.
- Reproduction steps and the smallest tool call or command that demonstrates
  the issue.
- The impact you believe is reachable, and whether any exploit is public.
- `opencyber-doctor --json` output, if the issue may be environment-specific.
- Whether you want credit, and the name or handle to use.

## What to expect

These are best-effort targets, not a contractual service level:

- Acknowledgement within 3 business days.
- Initial triage within 7 business days.
- Coordinated disclosure around 90 days after the report, or earlier once a fix
  is available and users have had a reasonable upgrade window.
- Credit in the advisory or release notes unless you ask to remain anonymous.

The project does not currently operate a paid bounty program. Do not interpret
a response, a fix, or a credit as a promise of compensation.

Please give the maintainer a reasonable chance to ship a fix before publishing
details. If a 90-day window is not enough because a fix needs a base-image or
third-party change, the maintainer will say so and agree on a new date with you.

## Scope

In scope:

- Python source under `src/opencyber/`, including MCP tool contracts, argument
  validation, path handling, process execution, cancellation, audit logging,
  scope enforcement, HTTP handling, browser handling, serial sessions, and
  firmware triage.
- The container build: `Dockerfile`, build-time verification, downloaded asset
  pinning, embedded licenses, and the resulting image.
- `install.sh`, `scripts/opencyber-run.sh`, and
  `scripts/opencyber-airgap.sh`.
- Release and supply-chain infrastructure: workflows, attestations, SBOM and
  license evidence, version consistency, and published digests.
- Documentation that makes a false security claim or omits a limitation in a
  way that could lead an operator into an unsafe deployment.

Out of scope:

- Use of the harness against systems without authorization. The software
  provides capability, not permission.
- Host misconfiguration, including an exposed Docker socket, an unauthenticated
  Docker API, overly broad device passthrough, missing host firewall or egress
  controls, or running the container with `--privileged`.
- The container running as root as designed. `tcpdump`, `hashcat`, and
  `aircrack-ng` need privileged access inside the container. Harden from the
  host with dropped capabilities, `no-new-privileges`, a read-only root
  filesystem, and the tmpfs mounts described in the README.
- Documented limitations of the current design, including Chromium running with
  `--no-sandbox`, scope enforcement being opt-in and not covering browser tools or arbitrary
  Bash/Python execution, best-effort audit
  coverage, and evidence artifacts that are not redacted. See
  [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) for the current statement of
  these limits.
- Attacks that require the operator to run deliberately untrusted code or
  connect an untrusted MCP client. The container is the trust boundary; the
  operator is trusted.
- Vulnerabilities in a bundled third-party tool that have no harness-specific
  impact. Report those upstream. The project can still update packaging or pin a
  fixed version.
- Findings that depend on a modified image, a locally patched checkout, or a
  version outside the supported line.

## Safe harbor

The project supports good-faith security research and will not pursue or
support legal action against researchers who:

- Test only systems they own or are explicitly authorized to test.
- Act in good faith and avoid privacy violations, data destruction, and
  disruption of services or data that are not theirs.
- Access only the data needed to demonstrate the issue, and do not retain or
  disclose third-party data.
- Report the issue privately and give the maintainer a reasonable time to
  remediate before public disclosure.
- Comply with applicable law.

This statement covers the OpenCyber Harness project itself. It does not bind
third parties, does not authorize testing of any other system, and does not
waive anyone else's rights. If your research involves a third-party service or
data, ask the maintainer before proceeding.

## Secure deployment baseline

- During beta, authenticate and use the exact platform digest supplied by the
  maintainer, following [BETA_TESTING.md](docs/BETA_TESTING.md). Repository access
  and package access are separate. Do not treat a local development image or an
  incomplete candidate run as qualified. Public signatures and attestations
  become acceptance requirements when a public release is promoted.

- Use `install.sh` or `scripts/opencyber-run.sh` rather than an ad hoc
  privileged container. Both default to dropped capabilities and
  `no-new-privileges`; the installer also defaults to a read-only root
  filesystem.
- The MCP server speaks stdio only and publishes no network ports. Expose it to
  a client you trust, not to a network listener.
- Treat device passthrough as a host-security decision. A hardware profile grants
  access to real radios, buses, or debug ports.
- Keep the workspace volume out of shared or untrusted storage. Engagements and
  evidence are only as isolated as the host and volume around them.
- For a hard authorization boundary, combine `OPENCYBER_ENFORCE_SCOPE=1` with an
  internal Docker network and a host-level egress policy. Scope enforcement is a
  guardrail, not a firewall.

## Security updates

During beta, fixes are supplied as a new frozen source commit and, after all
candidate gates pass, a new immutable image digest with a `CHANGELOG.md` entry.
Watch the private repository and maintainer's beta instructions for updates.
Future public releases and security advisories will describe the
affected versions, the impact, the fixed version, and any required operator
action.
