# Support

OpenCyber Harness is maintained on a best-effort basis. There is no service
level agreement, no guaranteed response time, and no promise that every report
will be fixed. Clear, reproducible reports with the details below are the
fastest way to get help.

The repository is currently private, with access granted by the maintainer.
Report ordinary defects in its issue forms. For a suspected vulnerability or
conduct concern, email [tech@mitkox.com](mailto:tech@mitkox.com) privately;
follow [SECURITY.md](SECURITY.md) for security report details.

## Documentation index

Start with the documentation index at [docs/README.md](docs/README.md). The most
useful pages by task:

| If you want to... | Read |
| --- | --- |
| Join the invited beta and try a first exercise | [docs/BETA_TESTING.md](docs/BETA_TESTING.md) |
| Install an assigned candidate or build from source | [docs/INSTALL.md](docs/INSTALL.md) |
| Learn the engagement and tool workflow | [docs/USER_GUIDE.md](docs/USER_GUIDE.md) |
| Connect an MCP client | [docs/MCP_INTEGRATION.md](docs/MCP_INTEGRATION.md) |
| Set environment variables and modes | [docs/CONFIGURATION.md](docs/CONFIGURATION.md) |
| Look up a tool or its contract | [docs/TOOLS.md](docs/TOOLS.md) |
| Use radios, buses, or debug ports | [docs/HARDWARE.md](docs/HARDWARE.md) |
| Run without internet access | [docs/AIRGAP.md](docs/AIRGAP.md) |
| Understand the trust boundary | [docs/SECURITY_MODEL.md](docs/SECURITY_MODEL.md) |
| Operate and monitor a deployment | [docs/OPERATIONS.md](docs/OPERATIONS.md) |
| Understand the architecture | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) |
| Run a release | [docs/RELEASE.md](docs/RELEASE.md) |

## Troubleshooting first

Run the self-checks before opening a request. The doctor is the same gate the
image build and container healthcheck use:

```sh
docker exec opencyber opencyber-doctor --json
docker exec opencyber opencyber-assets --verify --json
docker exec -e OPENCYBER_STRICT_CATALOG=1 opencyber opencyber-mcp --self-test
docker exec opencyber opencyber-hardware --json
```

Record the image reference and local image identity without dumping the full
container configuration:

```sh
docker inspect --format '{{.Config.Image}} {{.Image}}' opencyber
```

Compare the reference with the platform digest assigned by the maintainer.
If cloning works but the image pull is denied, check Docker login and package
read permission separately. Images are not yet cleared for private distribution;
a repository invitation alone does not make an image available. Public release
tags and promotion attestations are not present yet.

`opencyber-doctor` exits non-zero when the harness is degraded. On a host
without Kali tooling or with no devices passed through, a degraded or
tooling-only hardware report can be expected; it is not automatically a bug.
The doctor JSON lists the specific missing items.

The MCP server started with `docker exec` writes stderr to the MCP client's
server log. `docker logs opencyber` shows the container's main process and does
not collect that separate session. Share only a reviewed, redacted excerpt.

## What to include in a support request

- OpenCyber Harness version (`opencyber-doctor --json`, the image tag, or the
  commit for a source checkout).
- Image digest if you use a shared image. A tag can move; a digest identifies
  the build.
- Install path: private candidate image, local image build, `install.sh`, or
  source checkout with `pip install -e`.
- Architecture (`uname -m`) and host details: OS, Docker/Engine version, and
  whether the host is rootless.
- The launcher profile or the exact `docker run` flags, including capabilities,
  mounts, and device passthrough.
- Relevant `OPENCYBER_*` environment variables, with secrets and target data
  redacted.
- Reviewed and redacted `opencyber-doctor --json` output.
- The exact MCP tool call or shell command, the expected result, and the actual
  result.
- Reproduction steps from a clean container where possible.
- Relevant logs. Redact credentials, bearer tokens, customer names, target
  addresses, and engagement artifacts before posting.

Do not paste a full engagement workspace or a production credential into an
issue. Reduce the report to the smallest input that reproduces the problem.

## Where to ask

- Bug reports: use the bug report issue form.
- Feature requests: use the feature request issue form and state whether the
  request is for a practitioner, an MCP developer, or both.
- Documentation errors: use the documentation issue form, quoting the page and
  the incorrect claim.
- Security reports: email [tech@mitkox.com](mailto:tech@mitkox.com) and follow
  [SECURITY.md](SECURITY.md); keep details out of issues.
- Conduct reports: follow [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) and use the
  private route described there.

## Supported versions

The `0.5.x` pre-production line is supported on a best-effort basis. 0.5.0 is
currently a private beta preparation; it is intended to become the first
public open source prerelease. Report the exact source commit and image digest.
Support does not establish production suitability or qualification of a real
device or an untested platform.

## Scope of support

Community support covers the harness source, assigned candidate images, the
installer, the launcher and airgap scripts, and the documented MCP integration.
It does not include:

- Authoring or approving an engagement's authorization.
- Debugging a host's Docker, firewall, udev, or device-passthrough
  configuration beyond the documented flags and readiness output.
- Supporting modified images or local patches.
- Vulnerabilities in bundled third-party tools with no harness-specific impact;
  report those upstream.
- Guaranteed turnaround, paid support, or a commercial SLA.

If you need a hard operational guarantee, deploy the harness inside your own
support arrangement and pin a verified digest.
