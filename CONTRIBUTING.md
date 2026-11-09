# Contributing to OpenCyber Harness

Thanks for helping improve OpenCyber Harness. The project is a container-native
MCP toolkit for authorized security work, and it has two front doors: security
practitioners running engagements, and MCP/AI developers integrating the tool
surface. Contributions of code, tests, documentation, catalog entries, and
reproducible bug reports are welcome.

By participating, you agree to the [Code of Conduct](CODE_OF_CONDUCT.md).
Security vulnerabilities must never be reported in a public issue; follow
[SECURITY.md](SECURITY.md).

## Before you start

To test the beta without changing code, follow [the beta guide](docs/BETA_TESTING.md).
The published `v0.5.0-private-beta.1` archive preview is unqualified and frozen
at source commit `c120197`; current `main` documentation can advance separately.
Repository Read access includes the private release assets.
Coding agents and their operators should also read [AGENTS.md](AGENTS.md).

- Open an issue before starting anything larger than a focused fix. For a bug,
  use the bug report form. For a new capability, use the feature request form.
- Keep one concern per pull request. Large mixed changes are hard to review and
  hard to revert.
- Match the existing code style and keep the diff reviewable. The project starts
  with a conservative lint set on purpose; do not reformat unrelated files.
- The harness provides capability, not permission. Changes that make
  authorization, scope, or evidence easier to verify are welcome. Changes whose
  only purpose is to evade controls are not.

## Development setup

Python 3.11 through 3.13 are supported. The project uses a local virtual
environment and an editable install:

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
pip install -e '.[test,dev]'
```

On Debian/Ubuntu, install `build-essential` and `dpkg-dev` for the native
wordlist rebuild regression, and ShellCheck for `make shellcheck`.

The canonical test runner is the standard library's `unittest`:

```sh
python -m unittest discover -s tests -v
```

`pytest` is available in the `dev` extra for local exploration, but CI and pull
request checks run `unittest`. Unit tests use owned loopback fixtures and must
not require internet access, Docker, or a hardware device. Separate image
acceptance harnesses require Docker. Use the existing tests as the pattern: standard library
only unless a dependency is already declared in `pyproject.toml`.

`make check` runs the local release gate: unit tests, version consistency,
generated documentation, lint, and type checks. If the target is unavailable in
your checkout, run the equivalent commands directly:

```sh
python -m unittest discover -s tests -v
PYTHONPATH=src python3 scripts/check-version-consistency.py
PYTHONPATH=src python3 scripts/generate-tool-docs.py --check
python -m ruff check src tests scripts
python -m mypy src/opencyber
```

Shell entrypoints must also parse cleanly:

```sh
bash -n install.sh
for script in scripts/*.sh; do bash -n "$script"; done
```

## Repository layout

| Path | Contents |
| --- | --- |
| `src/opencyber/server.py` | MCP stdio server, native tools, and the shared executable-tool schema |
| `src/opencyber/catalog.py` | Declarative catalog of executable-backed tools and categories |
| `src/opencyber/executor.py` | Argv-only process execution, process groups, cancellation, and output capture |
| `src/opencyber/diagnostics.py` | Doctor model, fixed native tool inventory, and tool counts |
| `src/opencyber/hardware.py` | Hardware inventory, per-domain readiness, and playbooks |
| `src/opencyber/assets.py` | Offline asset reporting, verification, and build manifest |
| `src/opencyber/audit.py` | Hash-chained audit trail and verification |
| `src/opencyber/policy.py` | Offline policy and optional scope enforcement |
| `src/opencyber/http_client.py` | Shared HTTP timeout handling |
| `src/opencyber/http_workbench.py` | Persistent HTTP repeater and intruder |
| `src/opencyber/browser.py` | Headless Chromium sessions |
| `src/opencyber/api_audit.py` | OpenAPI, GraphQL, JWT, and API fuzzing support |
| `src/opencyber/workspace.py` | Engagement-workspace paths and file operations |
| `src/opencyber/workflows.py` | Tool recommendation and attack-chain helpers |
| `docs/` | User, operator, integration, and reference documentation |
| `scripts/` | Launchers, airgap tooling, release evidence, and repository checks |
| `tests/` | Stdlib `unittest` suite |
| `compliance/` | License policy enforced by the build and tests |
| `packaging/` | Host-side udev rules and packaging assets |

## Tests and checks

- Add or update a test for every behavior change. A bug fix should include a
  regression test that fails without the fix.
- Keep unit tests hermetic. Use local fixtures, do not contact external targets or depend on a real device,
  and do not assume Kali tooling is installed on the test host.
- Some tests pin documentation and distribution facts. In particular,
  `tests/test_distribution.py` checks README tool counts, Dockerfile pinning and
  excluded packages, while `tests/test_catalog.py` checks the catalog and
  executable requirements. Update the test and the document together when the
  underlying fact really changes.
- CI runs the suite on Python 3.11, 3.12, and 3.13, checks shell syntax, and
  verifies that `opencyber-doctor` fails closed on a bare host.

## Adding or changing an MCP tool

Tool names, argument contracts, result fields, error codes, and declared
authority are the public API. Treat a rename or a semantic change as a breaking
change and record it in [CHANGELOG.md](CHANGELOG.md). The contract rules are in
[docs/CONTRACTS.md](docs/CONTRACTS.md).

Every tool needs a declared contract, a result that tells the truth about
coverage, and a registered error code for each user-facing refusal.

### Declare the contract

Add a `ToolContract` for the tool in `src/opencyber/contracts.py` (native tools)
or rely on `ToolContract.for_executable()` (catalog tools). Declare:

- `shape` - the analyst task: `inspect`, `search`, `trace`, `compare`,
  `workflow`, `observe`, `execute`, or `manage`.
- `effects` - the side effects a caller must assume: `process`, `filesystem`,
  `network`, `device`, `secret`, `mutation`.
- `scope` - `none`, `argv`, `url`, `device`, or `engagement`.
- `engagement`, `destructive`, `open_world`, `idempotent`, and
  `returns_target_content` truthfully.

Registration fails at import when an advertised tool has no contract. MCP
annotations (`readOnlyHint`, `destructiveHint`, `idempotentHint`,
`openWorldHint`) and the `_meta.opencyber` block are derived from it, so do not
hand-write them.

### Executable-backed tools

1. Add the entry to `TOOL_GROUPS` in `src/opencyber/catalog.py`. The name must
   start with `oc_`; the executable is the binary invoked. The contract is
   derived from the category, so pick the right group.
2. Ensure the executable is installed by the image build. New binaries must be
   license-reviewed and pinned; see the licensing section below.
3. Add or extend tests in `tests/test_catalog.py` and any behavior-specific
   test module.
4. Route process execution through `executor.py` so deadlines, output caps,
   cancellation, process-group cleanup, and audit behavior stay consistent. Do
   not add `shell=True`.

### Native tools

1. Implement the tool in `src/opencyber/server.py`, or in the module it
   delegates to, and keep the `oc_` naming.
2. Add the contract entry in `src/opencyber/contracts.py`. The native inventory
   and every count derive from the registry; there is no second list to edit.
3. Raise `OcError(code, message, ...)` for user-facing refusals, not bare
   `ValueError`. Use an existing code from `opencyber.errors.ERROR_CODES`; a new
   code requires a new `ErrorSpec` and a regenerated reference.
4. Report honesty fields in the returned dict when they apply: `coverage`
   (`opencyber.envelope.coverage`), `limitations`, `truncated`,
   `continuation`, and `limit` facts
   (`opencyber.limits.facts`/`raise_exceeded`) when a named ceiling cut the
   result short.
5. Use `http_client.py` for outbound HTTP so the configured timeout applies, and
   check scope before each request and redirect hop for engagement-aware HTTP
   calls. Browser tools have a separately documented scope limitation.
6. Append an audit event for actions that touch the network, workspace,
   hardware, or evidence. Audit coverage is best-effort by design; do not
   describe a new call site as tamper-proof.

### Before you push

```sh
make docs-tools        # regenerate TOOLS.md, ERRORS.md, LIMITS.md and the schema
make catalog-record    # re-record the advertised catalog digest
make check             # lint, typecheck, generated-file checks, version aliases, tests
```

A contract change that is not accompanied by a regenerated
`src/opencyber/data/catalog.json` fails `make catalog-check`. That is deliberate:
the digest change is the review signal that a client-visible contract moved.

If the tool count changes, update the totals in `README.md`,
`docs/README.md`, and the pinned expectations in the tests in the same pull
request. If the tool belongs to the physical layer, update the hardware domain
mapping and readiness documentation as well.

## Documentation rules

- Every claim must match the code and tests. If behavior changes, update the
  affected document in the same pull request.
- Document every `OPENCYBER_*` environment variable in
  `docs/CONFIGURATION.md`, including its default and security effect.
- Do not document a tool as present unless it appears in `catalog.py` or
  the native contract registry.
- Do not hand-edit `docs/TOOLS.md` or any other generated page. Regenerate it.
- Use relative links and make sure the target exists. `make check` verifies
  generated docs and configuration coverage.
- When documenting a limitation, state it plainly. The project treats an
  accurate limitation as better than an aspirational guarantee.

## Licensing and third-party components

The harness source is Apache-2.0. Contributions are accepted under the same
license; there is no Contributor License Agreement.

New third-party packages, binaries, images, or downloaded assets require a
license check before they can be merged:

1. Confirm the license permits redistribution in the container.
2. Update `compliance/license-policy.json` when a component is blocked,
   requires review, or requires a notice.
3. Update [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) and, when required,
   [SOURCE_OFFER.md](SOURCE_OFFER.md).
4. Pin downloads by version and checksum. Do not use mutable selectors such as
   `/releases/latest/` or `go install ...@latest`.

Select maintained tools by their security condition and applicable distribution
terms. Custom, reciprocal and commercial license families are not automatic
exclusions. When SBOM metadata is incomplete, record an attributed decision for
the exact versioned package URL in `compliance/license-policy.json`, with the
captured license file, its SHA-256 and source URL, the redistribution basis and
notice/source obligations. Unknown metadata without that evidence and missing
required source remain blockers for qualified or public releases. The existing
private preview records unresolved license metadata and Oracle/PDB vendor
reviews in its `KNOWN_ISSUES.md`; these are pending obligations, not an approved
redistribution basis. See [vendor terms](docs/BETA_VENDOR_TERMS.md).

The configured image includes Nmap, Ncat, Ndiff, Nping, RustScan, AutoRecon,
Metasploit, NetExec and WPScan. Nmap scripts and Metasploit modules are required
offline assets. Preserve Nmap's applicable terms and source and WPScan's custom
license and commercialization restrictions as explained in
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

`burpsuite`, `maltego` and `waybackurls` remain excluded because no applicable
redistribution grant has been established for the intended binaries and
recipients. Reintroducing one requires that evidence and corresponding policy,
notice and test changes. ScoutSuite is excluded because its sqlitedict dependency
has an unresolved critical advisory; Terrascan is excluded because upstream is
archived and no longer maintained. Their optional adapters are documented
separately from the required image toolchain.

Describe OpenCyber's research and authorized-testing purpose without implying
that it grants rights to third-party software or target systems. All original
licenses, copyright notices, source obligations and use restrictions remain in
effect. Keep a configured Dockerfile, a built image, passing checks and completed
qualification distinct in documentation and handoffs.

## Commits and Developer Certificate of Origin

Every commit must be signed off under the
[Developer Certificate of Origin](https://developercertificate.org/). This
certifies that you wrote the change or otherwise have the right to submit it
under the project's license.

```sh
git commit -s -m "Describe the change in the imperative mood"
```

The sign-off appears as a trailer:

```text
Signed-off-by: Your Name <you@example.com>
```

Use an identity and address you can be contacted at. If you contribute on
behalf of an employer, make sure you are authorized to do so. Pull requests
without a matching sign-off will be asked to amend the commits.

Write an imperative subject line, keep it near 72 characters, and explain the
reason for the change in the body. Reference the issue with `Closes #123` when
the pull request resolves it.

## Pull request process

1. During private beta, accept the maintainer's repository invitation and
   authenticate with `gh auth login`. Clone with `gh repo clone mitkox/opencyber`.
   External beta testers receive **Read** access and can report issues without
   pushing changes. Ask the maintainer for contributor access before submitting
   code. Private forking is disabled for the beta; never copy private source into
   a public repository. Authorized contributors branch from `main` and submit a
   pull request. See [beta access](docs/BETA_ACCESS.md) for invitation management.
2. Make the change, add tests, and run `make check`.
3. Fill in the pull request template, including the security-impact section.
4. Open the pull request and wait for CI. The suite must pass on all supported
   Python versions, and shell syntax checks must pass.
5. Respond to review. Push follow-up commits rather than rewriting reviewed
   history, unless a maintainer asks for a clean history.
6. A maintainer merges the change. Do not merge your own pull request unless
   you have been explicitly asked to.

The organization currently uses GitHub Free. GitHub rejected enforcement for
this private repository, so branch protection is deferred by the maintainer.
The review and current-head CI requirements above remain the manual merge
policy; do not describe them as enforced branch rules.

Small documentation fixes may be merged with a lighter review, but they still
need a sign-off and must not introduce claims that the code does not support.

## Release process for maintainers

`src/opencyber/__init__.py` is the source of truth for the version. Shell
scripts, the Dockerfile, and the publish workflow carry aliases that must agree.

1. Record the current beta or release state in [CHANGELOG.md](CHANGELOG.md).
   Keep the repository and candidate packages private during beta; the
   maintainer manages tester invitations. The first public
   history starts at 0.5.0; retain previous private development history only in
   the private development repository.
2. Bump `__version__`, then update every alias checked by the version script:
   `Dockerfile`, `install.sh`, `scripts/opencyber-run.sh`,
   `scripts/opencyber-airgap.sh`, `scripts/publish-image.sh`, and
   `.github/workflows/publish-container.yml`.
3. Run the release gate:

   ```sh
   PYTHONPATH=src python3 scripts/check-version-consistency.py
   make check
   ```

4. Build the image and verify it before tagging:

   ```sh
   docker build -t opencyber:X.Y.Z .
   docker run --rm --entrypoint opencyber-doctor opencyber:X.Y.Z --json
   docker run --rm --entrypoint opencyber-mcp opencyber:X.Y.Z --self-test
   docker run --rm --entrypoint opencyber-assets opencyber:X.Y.Z --verify --json
   scripts/check-image-compliance.sh opencyber:X.Y.Z
   ```

5. Follow [the release procedure](docs/RELEASE.md). Native candidate builds run
   separately from future public publication. Freeze the artifact selection,
   record hardware as unqualified unless complete optional device evidence is
   supplied, and promote qualified beta images only after software, license and
   source gates pass. The separately published private preview is explicitly
   unqualified, with its pending reviews recorded in the release bundle.
   Public publication requires a later maintainer decision. The eventual
   0.5.0 GitHub release remains a prerelease; no moving image alias advances.
   Never rebuild during promotion or overwrite existing release bytes.

Do not describe an image as qualified when its doctor report is degraded or
its qualification evidence is incomplete. The existing preview is not evidence
of completed release qualification and does not authorize public publication.

## Getting help

Usage questions and troubleshooting belong in [SUPPORT.md](SUPPORT.md). Security
reports belong in [SECURITY.md](SECURITY.md). Conduct concerns belong in
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
