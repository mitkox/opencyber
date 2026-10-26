# OpenCyber Harness user guide

Use the assigned 0.5.0 private beta candidate for authorized lab assessments
and evidence analysis once it is cleared for distribution.
Start with [Beta testing](BETA_TESTING.md) for installation, a client connection
and a synthetic first result. Repository access is by invitation; image access
also needs package permission and a maintainer-provided platform digest. A
source install or local image build remains an unqualified development build.
The examples here are MCP tool calls, not shell
commands, unless the block is marked `sh`. Replace `eng_...` and session IDs
with values returned by your running server.

> Use OpenCyber Harness only against systems you own or are explicitly authorized to test. Write the authorization down before you create the engagement; the engagement target list is metadata unless you turn on scope enforcement.

## The mental model

OpenCyber Harness is not an agent. It has no planner and no model. Your MCP client decides what to do; the harness supplies tools, a workspace, and an evidence trail.

Three things shape every workflow:

1. **The container is the trust boundary.** Tools run as root inside the container and can reach its filesystem and network. Isolation between operators or trust domains requires separate containers and volumes, not separate engagements.
2. **An engagement is a storage namespace.** It groups artifacts, evidence, findings, HTTP sessions, browser data, serial transcripts, and an audit log. It does not sandbox a hostile executable.
3. **Calls are explicit.** Executable-backed tools take an argv list. The harness never invokes a shell for them. `oc_bash` and `oc_python` are the deliberate arbitrary-code paths.

## Create an engagement

```text
oc_engagement_create(
  name="Owned lab assessment",
  targets=["10.0.0.5", "app.lab.test"],
  objective="Validate the agreed lab attack surface"
)
```

The server returns an identifier such as:

```text
eng_20261024_9f8d4c1a6b2743f4a2c11bb8d02a91a7
```

Pass that `engagement_id` to every executable-backed or workspace-backed tool. The identifier format is `eng_YYYYMMDD_` plus 32 lowercase hex characters. Names and target strings are metadata inside `engagement.json`; they never become directory names.

To resume after a client restart:

```text
oc_engagement_list()
oc_engagement_get(engagement_id="eng_...")
```

For a first exercise without target traffic, follow
[Beta testing](BETA_TESTING.md#3-produce-a-first-result). For supplied artifacts,
use the [blue-team guide](BLUE_TEAM.md). Check a tool's `available` field in
`oc_catalog` before selecting an executable integration; a registered name does
not mean its binary is included.

## Run an owned lab request

After confirming the endpoint is yours and reachable from the container:

```text
oc_curl(
  engagement_id="eng_...",
  arguments=["--silent", "--show-error", "--max-time", "15", "--output", "artifacts/lab-response.txt", "http://10.0.0.5:8080/"]
)
```

The result includes the resolved executable, argv, working directory, exit code, stdout, and stderr, plus `ok`, `coverage`, `limitations`, and an evidence digest. Every call runs under a named deadline (`OPENCYBER_TOOL_TIMEOUT_S`, default 1800 seconds) and output cap (`OPENCYBER_TOOL_MAX_OUTPUT_BYTES`, default 4 MiB per stream). A call that hits either ceiling says so: `timed_out` with `limit` facts, or `truncated: true` with partial coverage. Neither is reported as an empty result. Set either variable to `0` to remove that ceiling and let the client own it.

Inspect what the call produced:

```text
oc_workspace_list(engagement_id="eng_...", recursive=true)
oc_workspace_read(engagement_id="eng_...", path="artifacts/lab-response.txt")
```

Use relative paths for engagement artifacts. Absolute paths are accepted only when they resolve inside the engagement.

### Arbitrary code paths

```text
oc_bash(engagement_id="eng_...", script="printf 'Synthetic lab note\\n' | tee artifacts/lab-note.txt")
oc_python(engagement_id="eng_...", source="print('hello')")
oc_python(engagement_id="eng_...", path="artifacts/parse.py", script_arguments=["--input", "raw.json"])
```

Both default to the engagement directory. Both run in a new session so that client cancellation terminates the whole process group: SIGTERM first, then SIGKILL after 2 seconds. Prefer an executable-backed tool when one matches the task; it gives you a tighter contract and cleaner evidence.

## Discover tools

Full mode advertises every tool schema. Discovery is still useful when you know the task but not the name:

```text
oc_catalog(query="graphql")
oc_catalog(category="network")
oc_catalog(name="oc_python", include_contracts=true)
oc_catalog(missing_only=true)
```

An unfiltered `oc_catalog()` returns counts, the categories, and the platform state instead of dumping every schema into the context window. `include_all=true` returns every entry.

In compact mode, only the 82 native tools are advertised. Discover an executable-backed tool, then dispatch it:

```text
oc_catalog(query="curl", include_contracts=true)
oc_execute(
  tool="oc_curl",
  engagement_id="eng_...",
  arguments=["--silent", "--show-error", "--max-time", "15", "http://10.0.0.5:8080/"]
)
```

Prefer the direct named tool in full mode. Use `oc_execute` only with an exact `oc_*` name returned by a filtered catalog query. See [MCP_INTEGRATION.md](MCP_INTEGRATION.md) for modes and token costs.

## Workspace and findings

Every engagement starts with three directories:

```text
/workspace/engagements/<engagement_id>/
  artifacts/
  evidence/
  findings/
  engagement.json
```

Write findings as structured Markdown:

```text
oc_finding_report(
  engagement_id="eng_...",
  path="findings/SQLI-001.md",
  title="SQL injection in search endpoint",
  target="https://app.example.com/search",
  severity="high",
  summary="The q parameter is concatenated into a SQL query.",
  evidence=["evidence/request.txt", "evidence/response.txt"],
  remediation="Use parameterized queries."
)
```

`engagement.json` is server-managed. `oc_workspace_write` and `oc_workspace_delete` refuse to modify or remove it. Delete only files you intend to lose; deletion is audited but not reversible.

## HTTP workbench

The workbench is a persistent, engagement-scoped repeater and intruder. It enforces its own host scope on every request, including every redirect hop.

```text
oc_http_session_create(
  engagement_id="eng_...",
  name="app",
  base_url="https://app.example.com",
  scope_hosts=["app.example.com"],
  include_subdomains=false,
  default_headers={"Authorization": "Bearer ..."},
  verify_tls=true,
  follow_redirects=true,
  timeout_seconds=30
)
```

Replay a request:

```text
oc_http_repeater(
  engagement_id="eng_...",
  session_id="http_...",
  method="GET",
  url="/api/users?id=1",
  headers={"X-Test": "1"}
)
```

Run a bounded, caller-selected payload matrix:

```text
oc_http_intruder(
  engagement_id="eng_...",
  session_id="http_...",
  method="GET",
  url="/api/users?id=1",
  location="query",
  parameter="id",
  payloads=["1", "1'", "1 OR 1=1"],
  max_requests=10
)
```

Read the complete history:

```text
oc_http_history(engagement_id="eng_...", session_id="http_...")
```

Sessions persist scope, default headers, cookies, match/replace rules, TLS verification, redirect behavior, and timeout in `.opencyber/http-sessions/`. Update them with `oc_http_session_update`. A redirect that leaves scope aborts the request. The workbench also aborts at 30 in-scope redirects.

Timeouts resolve from the call, then the session, then `OPENCYBER_HTTP_TIMEOUT` (default 30 seconds, maximum 300). Values that are non-numeric, zero, negative, or above the cap are rejected rather than clamped.

## API audits

```text
oc_openapi_inspect(engagement_id="eng_...", source="https://app.example.com/openapi.json")
oc_openapi_audit(engagement_id="eng_...", source="https://app.example.com/openapi.json")
oc_graphql_audit(engagement_id="eng_...", url="https://app.example.com/graphql")
oc_jwt_audit(engagement_id="eng_...", token="eyJ...")
oc_api_fuzz(
  engagement_id="eng_...",
  base_url="https://app.example.com",
  path="/api/users",
  method="GET",
  location="query",
  parameter="id",
  payloads=["1", "1'"],
  max_requests=2
)
```

`source` may be a URL or an engagement-relative file. `oc_openapi_inspect` is an operation-inventory helper. The audit tools persist their results as JSON evidence under `evidence/api/` and report evidence-backed review items, not proof of a vulnerability. `oc_api_fuzz` accepts `query`, `header`, `body`, `path`, or `json` as the location. JWT signature verification is never implied.

**Scope:** native HTTP/API tools check the engagement target before each request and redirect hop when `OPENCYBER_ENFORCE_SCOPE=1`, and require `engagement_id`. Browser tools remain outside this control. A hard egress boundary still requires network policy.

Native HTTP calls honor `OPENCYBER_HTTP_TIMEOUT` and the per-call `timeout` argument where the tool exposes one.

## Browser automation

```text
oc_browser_create(
  engagement_id="eng_...",
  name="app",
  ignore_https_errors=true
)
  -> session_id "browser_..."

oc_browser_navigate(engagement_id="eng_...", session_id="browser_...", url="https://app.example.com")
oc_browser_snapshot(engagement_id="eng_...", session_id="browser_...")
oc_browser_action(engagement_id="eng_...", session_id="browser_...", action="fill", selector="#user", value="admin")
oc_browser_action(engagement_id="eng_...", session_id="browser_...", action="click", selector="#submit")
oc_browser_screenshot(engagement_id="eng_...", session_id="browser_...", path="evidence/login.png")
oc_browser_evaluate(engagement_id="eng_...", session_id="browser_...", expression="document.title")
oc_browser_state(engagement_id="eng_...", session_id="browser_...")
oc_browser_network_log(engagement_id="eng_...", session_id="browser_...")
oc_browser_close(engagement_id="eng_...", session_id="browser_...")
```

`ignore_https_errors` defaults to `true`, preserving the current behavior for self-signed and expired certificates. Pass `false` when certificate validation matters. Screenshots land under `.opencyber/browser/<session_id>/` unless you pass a different engagement-relative path.

Browser sessions are process-scoped: they belong to the MCP server process that created them. Close them with `oc_browser_close`. If the client restarts, the old sessions are gone.

Chromium runs with `--no-sandbox` inside the container. A malicious page is inside the container boundary, not outside it.

## Hardware and the physical layer

Hardware integrations are supported for beta use in 0.5.0. Device-specific
qualification is recorded separately. A successful inventory, a PTY test or an installed tool does not
qualify a physical device. Test only your own fixtures and report the actual
device, firmware, architecture and image digest used.

A tool being installed does not mean the host passed the matching device through. Ask two separate questions:

```text
oc_hardware_inventory()
oc_hardware_readiness()
oc_hardware_plan(domain="sdr", target="", objective="")
```

`oc_hardware_readiness` reports per-domain status and the exact host `docker run`
flags needed for missing devices. Import the archive using the
[beta guide](BETA_TESTING.md), then run the launcher from the extracted
`source-c120197/opencyber` directory with explicit fresh container and volume
names. Device access requires the operator's authorization.

```sh
BETA_IMAGE=opencyber:0.5.0-private-beta.1-amd64
bash scripts/opencyber-run.sh --image "$BETA_IMAGE" --profile sdr --dry-run \
  --name opencyber-sdr --volume opencyber-sdr
bash scripts/opencyber-run.sh --image "$BETA_IMAGE" --profile serial \
  --device /dev/ttyUSB1 --name opencyber-serial --volume opencyber-serial
```

Use `--dry-run` to inspect a profile before running it, then choose the one
matching your owned fixture. Do not use `install.sh --uninstall` for a
launcher-created container; see [Install](INSTALL.md#path-b-manual-container).

Profiles: `software`, `blue-team`, `usb`, `sdr`, `wifi`, `bluetooth`, `nfc`, `jtag`, `serial`, `can`, `logic`, `gps`, `ir`, `full`. None uses `--privileged`. The `blue-team` profile has no network or hardware passthrough.

### Serial sessions

Use persistent sessions instead of an interactive terminal so boot output survives between agent turns:

```text
oc_serial_open(engagement_id="eng_...", device="/dev/ttyUSB0", baudrate=115200)
oc_serial_read(engagement_id="eng_...", session_id="ser_...", timeout=2)
oc_serial_write(engagement_id="eng_...", session_id="ser_...", data="help\r\n")
oc_serial_close(engagement_id="eng_...", session_id="ser_...")
```

The device must be a character device under an allowed prefix such as `/dev/ttyUSB*`, `/dev/ttyACM*`, `/dev/ttyAMA*`, `/dev/ttyS*`, `/dev/serial/`, `/dev/rfcomm*`, or `/dev/lirc*`. A PTY under `/dev/pts/` is also accepted when `OPENCYBER_ALLOW_PTY=1`. Block and memory devices are always rejected. Transcripts are written to `hardware/serial/<session_id>.jsonl`.

### Firmware triage

```text
oc_firmware_analyze(engagement_id="eng_...", path="artifacts/firmware.bin")
```

This hashes the image, identifies magic and architecture, maps entropy, extracts interesting strings, runs binwalk signatures, and writes a JSON report. It never executes the firmware.

See [HARDWARE.md](HARDWARE.md) for per-domain flags, udev rules, transmit safety, and troubleshooting.

## Working offline

Set `OPENCYBER_OFFLINE=1` on the container. Internet-only features then fail fast with an actionable message instead of hanging.

The harness refuses the executables `shodan`, `censys`, `subfinder`, `theHarvester`, and `sherlock`. It also refuses `oc_hibp_password_check` and `oc_cve_lookup` when no local CVE database is available. `OPENCYBER_OFFLINE_ALLOW_NETWORK_TOOLS=1` overrides the executable refusals when an internal network provides those services.

Offline mode is **not** an egress firewall. It is a small refusal list plus local assets. For a hard boundary, combine it with an internal Docker network and a host-level egress policy.

Check posture:

```text
oc_assets_status(deep=false, verify=true)
oc_offline_status()
```

From a shell:

```sh
docker exec opencyber-beta opencyber-assets
docker exec opencyber-beta opencyber-assets --json
docker exec opencyber-beta opencyber-assets --verify
docker exec opencyber-beta opencyber-assets --offline
```

Move the image itself across a gap with `scripts/opencyber-airgap.sh export|verify|import`. See [AIRGAP.md](AIRGAP.md).

## Scope enforcement

Scope enforcement is optional and off by default:

```sh
-e OPENCYBER_ENFORCE_SCOPE=1
```

When enabled, URL, IP, CIDR, and hostname tokens in executable arguments are matched against the engagement targets before the process starts. Native HTTP tools (`oc_http_request`, `oc_graphql_request`, `oc_openapi_inspect`, `oc_openapi_audit`, `oc_graphql_audit`, `oc_api_fuzz`, and the HTTP workbench) check the requested host before opening a socket, and require `engagement_id`. Out-of-scope calls are refused before they reach the target and recorded when audit is enabled. `oc_bash` and `oc_python` are refused under enforcement unless `OPENCYBER_ALLOW_UNSCOPED_EXECUTION=1`, because arbitrary code cannot be scope-checked.

What it does not cover:

- Browser tools, DNS resolution changes, proxy destinations, and redirects performed by external executables.
- Network traffic that does not appear as a URL, IP, CIDR, or dotted hostname in argv.
- A hostile executable that ignores its arguments.

Treat it as a guardrail against accidental out-of-scope commands, not as a firewall.

## Evidence handling

The harness records audit events for executable calls, HTTP workbench requests, browser actions, workspace writes, serial operations, and firmware analysis in a SHA-256 hash chain at:

```text
/workspace/engagements/<engagement_id>/.opencyber/audit/events.jsonl
```

Read and verify it:

```text
oc_audit_log(engagement_id="eng_...", limit=100)
oc_audit_verify(engagement_id="eng_...")
```

`oc_audit_verify` recomputes the chain and reports detected continuity or hash
failures. An externally retained last hash is needed to detect a consistently
rewritten chain or deletion of an intact suffix.

Limits you must plan around:

- **Tamper-evident, not tamper-proof.** Root inside the container can rewrite the whole file. Verification detects broken links or hashes, not a fully recomputed history or every suffix deletion. Copy the trail out with the evidence and retain its head separately.
- **Best-effort at many call sites.** Some native operations use `safe_record`, which does not fail the operation when the audit write fails. Executor audit can be disabled entirely with `OPENCYBER_AUDIT=0`. Set `OPENCYBER_AUDIT_REQUIRED=1` if you want executor audit write failures to be fatal.
- **Redaction is partial.** Credentials and bearer tokens are redacted before they reach the audit log, but workspace artifacts, HTTP history, browser state, and screenshots are not redacted. They can contain live credentials, session cookies, and personal data.
- **Deletion is not secure erasure.** Deleting an engagement file or the Docker volume does not guarantee that the underlying blocks are gone.

Copy evidence out before you purge a workspace:

```sh
docker cp opencyber:/workspace/engagements/eng_... ./evidence-eng_...
```

For separate operators or trust domains, use separate containers and volumes. An engagement is an artifact boundary, not a security boundary against code you chose to run.

## CVE chain proof-of-concept

When an assessment surfaces CVEs that might combine into a chain, the PoC tools
turn "these findings look related" into a validated capability chain and a
bounded, reproducible proof. This path is deliberately gated; read
[POC_CHAINS.md](POC_CHAINS.md) before the first use.

1. **Authorize.** The operator signs the engagement authorization with
   `opencyber-poc authorize` inside the container. It lists targets, validity,
   and the technique classes allowed. The agent can only read it with
   `oc_authorization_get`.
2. **Plan.** Annotate each observed CVE with `requires`/`provides` capability
   tokens and call `oc_chain_plan`. The verdict is `complete`, `incomplete`
   (with the exact missing tokens), or `cyclic`.
3. **Build.** `oc_poc_spec_create` for one chain step, then `oc_poc_render` and
   `oc_poc_lint`. Lint must have zero blocking findings; every host must be in
   scope.
4. **Approve.** The operator mints a single-use approval bound to the spec and
   code hashes with `opencyber-poc approve`. The MCP surface does not provide a signing tool. This is a trusted-client workflow, not isolation from container root.
5. **Run and record.** `oc_poc_run` executes under hard request/time/output caps
   and writes evidence under `poc/runs/`; `oc_poc_evidence` reads it and
   `oc_finding_report` turns a verified result into a finding.

Run approval is consumed durably before launch. Cancellation, a process crash
or an evidence-write failure can leave an interrupted or unverified run, but
does not make that approval reusable. Inspect the recorded run and ask the
operator for a new approval before retrying. A consumed approval alone does
not prove that target execution started or that the result was verified.

```text
oc_authorization_get(engagement_id="eng_...")
oc_chain_plan(engagement_id="eng_...", steps=[...], entry_capabilities=[...])
oc_poc_spec_create(engagement_id="eng_...", chain_id="chain_...", step_order=1, technique="http_sequence", target="http://app.lab.test:8080", requests=[...], assertions=[...])
oc_poc_render(engagement_id="eng_...", spec_id="spec_...")
oc_poc_lint(engagement_id="eng_...", spec_id="spec_...")
oc_poc_run(engagement_id="eng_...", chain_id="chain_...", spec_id="spec_...", approval_id="apr_...")
oc_poc_evidence(engagement_id="eng_...", run_id="run_...")
```

Destructive techniques are out of scope even with authorization; record them as
unverified hypotheses. The agent adapters for OpenCode V2 Code Mode and
DeepSeek Harness are in [INTEGRATIONS.md](INTEGRATIONS.md).

## Next steps

- [TOOLS.md](TOOLS.md): the complete tool reference.
- [CONFIGURATION.md](CONFIGURATION.md): environment variables.
- [SECURITY_MODEL.md](SECURITY_MODEL.md): the full trust model and its limits.
