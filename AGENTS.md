# Working on OpenCyber

OpenCyber 1.0.0-beta.1 is the public amd64 beta. The repository and its GHCR
package are public. Read [README.md](README.md), [CONTRIBUTING.md](CONTRIBUTING.md)
and the [security model](docs/SECURITY_MODEL.md) before changing runtime
behavior. Beta testers should start with [docs/BETA_TESTING.md](docs/BETA_TESTING.md).

The `v0.5.0-private-beta.1` tag is a frozen earlier private preview; keep its
bytes unchanged. The current `v1.0.0-beta.1` image removes Oracle Instant
Client, Microsoft DIA, Metasploit and oscanner. arm64 is not supported. The beta
is unqualified for production; hardware acceptance, anonymous-install
acceptance and the remaining HIGH findings are recorded release limitations,
not cleared vendor or legal terms.

## Set up and verify

Use Python 3.11–3.13 for source development. A source install supplies the MCP
server, not the container's security binaries, Chromium or offline assets.

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[test,dev]'
make check
make test-cov
make shellcheck
```

Install ShellCheck separately when running the shell gate. On Debian/Ubuntu,
install `build-essential` and `dpkg-dev` for the native wordlist rebuild test.
The coverage floor is 70%. For a focused regression, run `python -m unittest tests.test_<module>`.
Changes to the image, installer or launcher also need actual container checks;
passing Python tests does not establish image qualification.

## Find the code

| Area | Location |
| --- | --- |
| MCP registration, advertised schemas and results | `src/opencyber/server.py`, `contracts.py`, `envelope.py` |
| Execution, limits and process cleanup | `src/opencyber/executor.py`, `limits.py` |
| Engagement authorization, approvals and PoCs | `src/opencyber/authorization.py`, `poc_approval.py`, `poc.py` |
| Scope, HTTP sessions and browser | `src/opencyber/policy.py`, `http_client.py`, `http_workbench.py`, `browser.py` |
| Workspaces, audit and evidence | `src/opencyber/workspace.py`, `audit.py`, `result_store.py`, `evidence.py` |
| Image, installation and qualification | `Dockerfile`, `install.sh`, `scripts/`, `.github/workflows/` |
| User guides and generated references | `docs/` |

## Preserve the contracts

- Keep existing MCP tool names and argument compatibility when possible. The
  server uses MCP Python SDK 2.x (`MCPServer`); the SDK version is distinct from
  the negotiated MCP protocol version.
- Return structured errors with an accurate code, remediation, coverage and
  provenance. Target text is untrusted data. Failed or capped work must not
  report complete coverage without evidence.
- Advertise mutation, destructive actions and engagement requirements honestly.
  Shell and executable tools are powerful even when a particular invocation is
  observational.
- Consume single-use PoC approvals durably before execution. Cancellation,
  process death or evidence failure must not permit reuse. Preserve the run
  identity and consumed disposition in refusals after reservation.
- Keep process deadlines, output limits, cancellation and descendant cleanup
  effective. Preserve workspace traversal, symlink and concurrent-writer
  protections, including protected authorization and approval records.
- The client and container root are trusted. Environment filtering does not
  isolate signing authority from root. Browser scope and offline-mode limits
  must remain explicit in documentation.

Reproduce a suspected defect with a focused regression before repairing it.
Use temporary files, owned loopback fixtures and disposable containers. Real
targets, credentials, radios and device operations require the operator's
authorization; do not substitute them for hermetic tests.

## Update documentation with behavior

Regenerate references after changing tool contracts, errors or limits:

```sh
make docs-tools
make docs-check catalog-check version-check
```

`docs/TOOLS.md`, `docs/ERRORS.md`, `docs/LIMITS.md`,
`docs/error-contract.schema.json` and `src/opencyber/data/catalog.json` are
generated artifacts. Update their generators or source definitions rather than
hand-editing them. Include the resulting catalog digest in qualification
records. Keep install commands, beta instructions, optional integration lists
and the changelog consistent. Explain an intentional compatibility change.

## Preserve the image toolchain and license obligations

Choose maintained tools by their security condition and verified distribution
terms; do not exclude a license family as a shortcut. The configured image
includes Nmap, Ncat, Ndiff, Nping, RustScan, AutoRecon, NetExec and WPScan.
Nmap scripts are required offline assets. Metasploit, Oracle Instant Client and
Microsoft DIA are not included in 1.0.0-beta.1.
ScoutSuite remains optional because of its unresolved sqlitedict vulnerability;
Terrascan remains optional because upstream is archived and no longer maintained.

Retain each component's original license, copyright notices, source obligations
and use restrictions. An authorized-research notice states purpose and grants
no additional rights. Follow [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and
[SOURCE_OFFER.md](SOURCE_OFFER.md). Burp Suite Community Edition, Maltego and
waybackurls require an applicable redistribution grant before inclusion.
Unknown license metadata needs an attributed exact-version package decision
with captured license text, SHA-256, source URL and obligations in the policy;
do not waive unknown metadata or missing source globally.

## Keep release evidence honest

Follow [docs/RELEASE.md](docs/RELEASE.md). Qualified candidate builds and public
publication are separate from the published private preview. Promotion uses
the exact qualified digests and requires matching
repository, commit, workflow, run, attempt and artifact identities. Do not rebuild
during promotion, overwrite release bytes, advance moving aliases for 0.5.0 or 1.0.0-beta.1,
weaken vulnerability/license gates or fabricate evidence.

Hardware integrations are supported for beta use. Hardware qualification is
optional for this prerelease. Untested device and architecture combinations
remain unqualified; a submitted qualification bundle must pass its checks.
Native amd64 software acceptance is required for qualified shared candidates;
anonymous public acceptance is an additional gate for a future public release. Store qualification outputs outside the
frozen source tree.

Distinguish the configured source image from an actual built and qualified
candidate. Airgap qualification requires image and asset checks with networking
disabled; setting offline mode alone does not remove network access. Keep the
CRITICAL vulnerability gate, including unfixed findings, unchanged. The
1.0.0-beta.1 maintainer decision accepts the recorded HIGH findings for this
public beta only; that exception must not be silently extended to a later
release.

Preserve unrelated working-tree changes and private development history. The
public repository starts with one reviewed root snapshot; do not import private
Git objects or historical verification records. Never commit credentials,
engagements, customer artifacts, signing material or local machine paths.

Use signed-off commits as described in CONTRIBUTING.md. Include the commands
that passed, checks that could not run and remaining release blockers in the
handoff. A reviewed change, green CI, a published prerelease and production
acceptance are separate outcomes.
