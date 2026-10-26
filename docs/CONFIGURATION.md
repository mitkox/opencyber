# Configuration for 0.5.0

Every `OPENCYBER_*` setting: its default, where it is read, what it changes, and the security consequence.

For a first run, use [BETA_TESTING.md](BETA_TESTING.md) and keep the defaults.
Change settings only after verifying the container with doctor and the MCP
self-test.

OpenCyber Harness has no configuration file. Runtime behavior is controlled by environment variables on the container or on the `docker exec` process, by variables consumed by the shell installers, and by Docker build arguments. Set container variables with `docker run -e` or `docker exec -e`; set build arguments with `docker build --build-arg`.

> Most settings are guardrails, not security boundaries. `OPENCYBER_ENFORCE_SCOPE` and `OPENCYBER_OFFLINE` do not filter packets. See [SECURITY_MODEL.md](SECURITY_MODEL.md).

## Runtime variables

These are read by the Python server, doctor, and CLI processes inside the container.

| Variable | Default | Read by | Effect |
| --- | --- | --- | --- |
| `OPENCYBER_WORKSPACE` | `/workspace` | `engagements.py` at import | Root of the engagement store: `<root>/engagements/<engagement_id>`. |
| `OPENCYBER_MCP_MODE` | `full` | `server.py` at import | `compact` advertises only the 82 native tools; any other value uses the full or category-selected catalog. |
| `OPENCYBER_TOOL_CATEGORIES` | empty (all) | `server.py` at import | Comma-separated executable categories to advertise individually. Ignored in compact mode. |
| `OPENCYBER_ENFORCE_SCOPE` | off | `policy.py` per call | Enables argv scope checks for executable-backed tools and host checks for native HTTP tools. Native HTTP calls then require `engagement_id`. |
| `OPENCYBER_ALLOW_UNSCOPED_EXECUTION` | off | `policy.py` per call | Under scope enforcement, allows `oc_bash` and `oc_python` to run without a target check. |
| `OPENCYBER_OFFLINE` | off | `assets.py`, `policy.py` per call | Refuses a fixed list of internet-only executables and the HIBP and NVD lookups. |
| `OPENCYBER_OFFLINE_ALLOW_NETWORK_TOOLS` | off | `policy.py` per call | Unblocks only the five offline-refused executable names. |
| `OPENCYBER_CVE_DB` | `/usr/share/opencyber/cve/cve.sqlite` | `assets.py` per call | Local SQLite CVE index consulted by `oc_cve_lookup` before any network fallback. |
| `OPENCYBER_ASSET_MANIFEST` | `/usr/share/opencyber/asset-manifest.json` | `assets.py` at import | Build-time manifest used by `opencyber-assets --verify` and the doctor. |
| `OPENCYBER_AUDIT` | on | `executor.py` per call | Disables executor audit events only. Native, workspace, HTTP, browser, API, and hardware audit writes ignore it. |
| `OPENCYBER_AUDIT_REQUIRED` | off | `executor.py` per call | Makes a failed executor audit write raise instead of being ignored. Executor-scoped. |
| `OPENCYBER_RESULT_RETENTION` | `digest` | `result_store.py` per call | How tool results are retained: `off` keeps nothing, `digest` keeps an index entry (id, tool, digest, size, time), `full` stores the redacted payload under `<engagement>/.opencyber/results/` capped at 1 MiB per record and pruned at 500 records / 32 MiB. |
| `OPENCYBER_STRICT_CATALOG` | off | `server.py` in `--self-test` | Makes a catalog digest mismatch a non-zero exit instead of a reported `strict_mismatch`. Use it in image smoke and deployment gates; a compact-mode deployment is a truthful subset and does not fail. |
| `OPENCYBER_TOOL_TIMEOUT_S` | `1800` | `executor.py` per call | Deadline for one executable-backed tool call. The process group is stopped at the deadline and the result carries `timed_out` plus `limit` facts. Valid range is 0 to 86400; `0` disables the server deadline. |
| `OPENCYBER_TOOL_MAX_OUTPUT_BYTES` | `4194304` | `executor.py` per call | Bytes retained per stream from one executable-backed call. The excess is still read and discarded, so a full pipe cannot block the child; the result is marked `truncated` with partial coverage. Valid range is 0 to 268435456; `0` disables the cap. |
| `OPENCYBER_SYSFS` | `/sys` | `hardware.py` per call | sysfs root for hardware inventory and readiness. |
| `OPENCYBER_DEV` | `/dev` | `hardware.py` per call | Device root for hardware inventory and serial device checks. |
| `OPENCYBER_ALLOW_PTY` | unset | `hardware.py` on `oc_serial_open` | When exactly `1`, permits `/dev/pts/*` devices for serial sessions. |
| `OPENCYBER_HTTP_TIMEOUT` | `30` | `http_client.py` per call | Default connect/read timeout in seconds for native HTTP calls. Must be finite, greater than 0 and at most 300. |
| `OPENCYBER_APPROVAL_KEY` | unset | `poc_schema.py`, `poc_approval.py` per call | HMAC key of at least 32 bytes that signs engagement authorizations and PoC run approvals. Without it, `oc_poc_run` and the `opencyber-poc` CLI refuse. Scrubbed from every tool child process. |
| `OPENCYBER_APPROVAL_KEY_FILE` | unset | `poc_schema.py`, `poc_approval.py` per call | Path to a file holding the approval key; used when `OPENCYBER_APPROVAL_KEY` is empty. |
| `OPENCYBER_POC_MAX_REQUESTS` | `20` | `poc_schema.py` per call | Lowers the per-run request cap. Valid range is 1 to 20; the environment cannot raise the hard ceiling. |
| `OPENCYBER_POC_TIMEOUT` | `60` | `poc_schema.py` per call | Lowers the per-run deadline in seconds. Valid range is 1 to 60; the environment cannot raise the hard ceiling. |

### PoC chain execution

These settings govern the CVE-chain PoC tools documented in
[POC_CHAINS.md](POC_CHAINS.md). They are read per call and are not captured at
import.

`OPENCYBER_APPROVAL_KEY`

- Default: unset.
- At least 32 bytes. The key signs two records with HMAC-SHA256: the engagement
  authorization (`poc/authorization.json`) and each single-use PoC run approval
  (`poc/approvals/<approval_id>.json`).
- Read by `poc_schema.resolve_approval_key()`. The server verifies signatures;
  the operator CLI (`opencyber-poc`) is the supported creator. There is no MCP
  signing tool; root code is still trusted.
- When unset or too short, `oc_poc_run` and every `opencyber-poc` subcommand
  refuse with `approval_key_unavailable`. Chain planning, spec creation,
  rendering, and linting still work.
- Security: the key is removed from every tool child environment by
  `executor.build_environment()`, to reduce accidental inheritance. This does not isolate signing authority
  from container-root code, which shares the filesystem and process namespace.
  Trust the client and its code; keep signing material out of engagement files.

`OPENCYBER_APPROVAL_KEY_FILE`

- Default: unset.
- Alternative to the variable: a file whose trimmed contents are the key. Used
  only when `OPENCYBER_APPROVAL_KEY` is empty. It avoids placing the key value
  in environment/command arguments. The file and its host mount must be protected;
  it remains readable to container root.

`OPENCYBER_POC_MAX_REQUESTS`

- Default: `20`.
- Bounds the number of HTTP requests a rendered verifier may issue in one run.
  Valid range is 1 to 20; `poc_schema.resolved_limits()` rejects larger values
  with `invalid_limit`. A spec may ask for less than this; it may never ask for
  more than the hard ceiling.

`OPENCYBER_POC_TIMEOUT`

- Default: `60`.
- Bounds the wall-clock duration of one run in seconds. Valid range is 1 to 60.
  On expiry the process group is terminated, the run records `timeout`, and the
  partial output is retained as evidence.

### Workspace and tool exposure

`OPENCYBER_WORKSPACE`

- Default: `/workspace`, also set as an image `ENV`.
- Captured once when `opencyber.engagements` is imported: `Path(os.environ["OPENCYBER_WORKSPACE"]).resolve()`.
- Changing the variable after the server process has started has no effect. A new `docker exec` starts a new process and re-reads it.
- If you mount the workspace volume somewhere other than `/workspace`, set this variable to the mount target as well. `scripts/opencyber-run.sh` only changes the mount target (see `OPENCYBER_WORKSPACE_PATH`).
- Security: the workspace contains engagements, evidence, HTTP history, browser logs, serial transcripts, and audit chains. Treat the volume as sensitive. It does not isolate one engagement from another against hostile code, because every process runs as root in the same container.

`OPENCYBER_MCP_MODE`

- Default: `full`.
- `compact` suppresses individual registration of the 174 executable-backed tools. The 82 native tools remain, and `oc_catalog` / `oc_execute` still reach the executable catalog.
- Any value other than `compact` (after trimming and lowercasing) takes the full/category path. There is no validation error for an unknown mode.
- Ignored interaction: compact mode is evaluated before categories, so `OPENCYBER_TOOL_CATEGORIES` has no effect in compact mode.
- See [MCP_INTEGRATION.md](MCP_INTEGRATION.md) for client-facing token trade-offs.

`OPENCYBER_TOOL_CATEGORIES`

- Default: empty, which registers every executable tool.
- A comma-separated allowlist of catalog categories. Whitespace around entries is stripped.
- Applies only to executable-backed tools. All 82 native tools are always registered.
- An unknown category raises `ValueError: unknown OPENCYBER_TOOL_CATEGORIES: [...]` while `server.py` is importing, so the MCP server fails to start instead of silently advertising a smaller set. `opencyber-doctor` does not import `server.py` and is unaffected.
- Valid categories:

```text
network
enumeration
web
credentials
exploitation
binary
forensics
cloud_container_iac
wireless
rf
wireless_attack
nfc_rfid
usb
embedded
automotive
gps
ir
mobile
utilities
```

Examples:

```sh
docker exec -i -e OPENCYBER_TOOL_CATEGORIES=network,web,enumeration \
  opencyber opencyber-mcp

docker exec -i -e OPENCYBER_TOOL_CATEGORIES=rf,wireless_attack,nfc_rfid,embedded,automotive,gps,ir,usb \
  opencyber opencyber-mcp
```

### Scope enforcement

`OPENCYBER_ENFORCE_SCOPE`

- Default: off.
- Enables `policy.enforce_scope()` for every executable-backed call, including calls dispatched through `oc_execute` and the `oc_bash` / `oc_python` wrappers.
- Before the process starts, URL, IPv4/CIDR, and dotted-hostname tokens are extracted from the argv and matched against the engagement's `targets`. A bare domain target also covers its subdomains. A target of `*` matches any host. An out-of-scope token refuses the call and records a `tool.denied` event.
- Native HTTP tools use the same targets through `policy.enforce_url_scope()`: `oc_http_request`, `oc_graphql_request`, `oc_openapi_inspect`, `oc_openapi_audit`, `oc_graphql_audit`, `oc_api_fuzz`, and every HTTP workbench request and redirect hop. They require `engagement_id` under enforcement and refuse with `engagement_required` without it.
- Extraction is deliberately narrow. It is a guardrail against accidental out-of-scope commands, not a firewall. It does not cover browser tools, HIBP, or CVE lookups. See the matrix in [SECURITY_MODEL.md](SECURITY_MODEL.md).
- Engine arguments that do not look like network targets are not checked. A tool that reads a target from a file or configuration can still leave scope.

`OPENCYBER_ALLOW_UNSCOPED_EXECUTION`

- Default: off.
- Only meaningful when `OPENCYBER_ENFORCE_SCOPE` is on.
- Without it, `oc_bash` and `oc_python` are refused under enforcement because arbitrary code cannot be target-checked.
- With it, they run without a target check. They are still audited. This deliberately reopens the gap that scope enforcement otherwise narrows.

### Offline mode

`OPENCYBER_OFFLINE`

- Default: off. On values: `1`, `true`, `yes`, `on` (case-insensitive).
- Refuses these five exact executable names before they start: `shodan`, `censys`, `subfinder`, `theHarvester`, `sherlock`.
- `oc_hibp_password_check` raises immediately. `oc_cve_lookup` raises immediately only when no local database is present; when `OPENCYBER_CVE_DB` exists it reads locally and never falls back to NVD, even for a miss.
- Does not block `amass`, `recon-ng`, `spiderfoot`, or `wafw00f`, which have useful local modes.
- Does not block native HTTP, GraphQL, OpenAPI, API fuzz, or browser traffic. Those tools still open sockets. Offline mode is a fail-fast switch for known internet-dependent features, not an egress firewall. For a hard airgap use `--network none`, an internal Docker network, or host firewall rules; see [AIRGAP.md](AIRGAP.md).
- `oc_offline_status()` reports the mode, asset readiness, local CVE database presence, the exact blocked executable list, and the features that still need internet access.

`OPENCYBER_OFFLINE_ALLOW_NETWORK_TOOLS`

- Default: off.
- On values: `1`, `true`, `yes`, `on`.
- Overrides only the five executable refusals. It does not re-enable `oc_hibp_password_check` or the NVD fallback in `oc_cve_lookup`.
- Use it only when the internal network supplies the services those tools expect.

### Audit

`OPENCYBER_AUDIT`

- Default: on (unset is treated as `1`).
- On values: `1`, `true`, `yes`, `on`. Any other value, including `0`, `false`, `no`, and `off`, disables executor audit.
- Scoped narrowly: it is consulted only by `executor._record()`. It suppresses `tool.exec`, `tool.denied`, `tool.scope_checked`, and `tool.cancelled` events.
- It does **not** suppress audit writes made through `safe_record()` by workspace, HTTP workbench, API audit, browser, serial, or firmware code. Those events continue to be appended.
- Disabling executor audit means an engagement can contain evidence artifacts with no corresponding tool-execution event. It does not make an existing chain invalid.

`OPENCYBER_AUDIT_REQUIRED`

- Default: off.
- On values: `1`, `true`, `yes`, `on`.
- Only consulted when `OPENCYBER_AUDIT` is enabled. It makes executor audit writes use `record_event()` and propagate an `OSError` or `ValueError` instead of the best-effort `safe_record()`.
- Executor-scoped. It does not make workspace, HTTP, browser, API, or hardware audit writes fatal.
- A failed write can fail the tool call after the underlying process has already run. Use it when losing an executor event is worse than losing the call result.

### Assets and CVE data

`OPENCYBER_CVE_DB`

- Default: `/usr/share/opencyber/cve/cve.sqlite`.
- Read per call by `assets.local_cve_db()`.
- Must be a regular file; symlinks are rejected by both the lookup and the asset measurement. Mount it read-only.
- If present, `oc_cve_lookup` reads it first and returns `found: false` for a miss instead of querying NVD.
- If absent, online mode falls back to NVD; offline mode raises an actionable error.
- An unreadable or corrupt SQLite file raises `ValueError: local CVE database is unreadable: ...`.

`OPENCYBER_ASSET_MANIFEST`

- Default: `/usr/share/opencyber/asset-manifest.json`.
- Captured when `opencyber.assets` is imported. Set it before starting the process; a later environment change is not observed.
- Used by `opencyber-assets --verify`, the doctor, and `oc_assets_status(verify=true)`.
- The file must be a regular file; symlinks are ignored. A missing manifest makes `opencyber-assets --verify` exit 1 with `valid: null`, but the doctor does not treat a missing manifest as a problem. A present but mismatched manifest makes the doctor degraded.
- Security: the manifest is an unsigned local file. It detects accidental truncation, not tampering. Use image digests and attestations for provenance.

### Hardware paths

`OPENCYBER_SYSFS`

- Default: `/sys`.
- Read per call by `hardware.py`. Used for USB, network, Bluetooth, serial, video, input, GPIO/I2C/SPI, and device-node inventory.
- Primarily useful for tests and unusual bind-mount layouts. Pointing it at an incomplete tree yields an incomplete inventory, not an error.

`OPENCYBER_DEV`

- Default: `/dev`.
- Read per call by `hardware.py`. Used for the same inventory and for serial device path checks.
- Changing it does not grant device access; host `--device` flags do.

`OPENCYBER_ALLOW_PTY`

- Default: unset (PTY devices refused).
- Exact comparison: only the value `1` enables it. `true`, `yes`, and `on` do not.
- When enabled, `oc_serial_open` accepts a resolved path under `/dev/pts/` in addition to the normal serial, RFCOMM, and LIRC prefixes.
- Intended for lab and test setups. A PTY is not a passed-through UART and does not provide hardware access.

### HTTP timeouts

`OPENCYBER_HTTP_TIMEOUT`

- Default: `30` seconds.
- Read by `http_client.resolve_timeout()` for every native `requests` call and for the HTTP workbench's default session timeout.
- Must parse as a finite number greater than 0 and at most 300. NaN, infinity, invalid, zero, negative, and above-cap values raise rather than clamp, so a typo cannot silently remove the deadline.
- A caller-supplied `timeout` argument wins over the environment. Values above 300 are rejected.
- Applies to native Python HTTP only. Executable-backed tools use `OPENCYBER_TOOL_TIMEOUT_S` instead (default 1800 seconds, `0` disables). Cancelling a call terminates the process group.

### On/off value handling

| Family | Truthy values | Default when unset |
| --- | --- | --- |
| Scope, offline, audit-required | `1`, `true`, `yes`, `on` | off |
| Audit | `1`, `true`, `yes`, `on` | **on** |
| `OPENCYBER_ALLOW_PTY` | exactly `1` | off |
| `OPENCYBER_HTTP_TIMEOUT` | numeric seconds | `30` |

Setting an audit or scope variable to an unrecognized string such as `enabled` is treated as off. There is no warning.

## Import-time versus per-call settings

Two variables are captured when a Python module is imported, not each time a tool runs:

| Variable | Captured by | Consequence |
| --- | --- | --- |
| `OPENCYBER_WORKSPACE` | `engagements.py` | The engagement root is fixed for the life of the server process. |
| `OPENCYBER_ASSET_MANIFEST` | `assets.py` | The manifest path is fixed for the life of the process. |

Because every `docker exec ... opencyber-mcp` starts a fresh process, `docker exec -e` can still set these for that session. They are only unreachable if you try to change the environment of an already-running server. `OPENCYBER_CVE_DB`, scope, offline, audit, sysfs/dev, PTY, and HTTP timeout settings are read at call time within that process.

## Script variables

These are consumed by `install.sh` and `scripts/opencyber-run.sh`; they are not read by the Python server.

| Variable | Used by | Default | Effect |
| --- | --- | --- | --- |
| `OPENCYBER_VERSION` | `install.sh` | `0.5.0` | Release to install. Must match `X.Y.Z` and the image's `com.opencyber.harness.version` label. |
| `OPENCYBER_DIGEST` | `install.sh` | empty | Pin the image by digest (`sha256:` plus 64 lowercase hex characters). Equivalent to `--digest`; the command-line option wins when both are supplied. |
| `OPENCYBER_IMAGE` | `install.sh`, `scripts/opencyber-run.sh` | `ghcr.io/mitkox-dev/opencyber` (installer); `opencyber:0.5.0` (launcher) | Image repository or reference. |
| `OPENCYBER_CONTAINER_NAME` | `install.sh`, `scripts/opencyber-run.sh` | `opencyber` | Container name. |
| `OPENCYBER_VOLUME_NAME` | `install.sh`, `scripts/opencyber-run.sh` | `opencyber-workspace` | Docker volume mounted as the workspace. |
| `OPENCYBER_WORKSPACE_PATH` | `scripts/opencyber-run.sh` only | `/workspace` | Container-side mount target for the workspace volume. It does not set `OPENCYBER_WORKSPACE` inside the container. |

`OPENCYBER_WORKSPACE_PATH` deserves care: changing it to `/data` mounts the volume at `/data`, but the server still writes to `/workspace` because the image sets `OPENCYBER_WORKSPACE=/workspace`. Either leave it at `/workspace` or use a manual `docker run` that also passes `-e OPENCYBER_WORKSPACE=/data`.

For the current private preview, follow [BETA_TESTING.md](BETA_TESTING.md)
to import `opencyber:0.5.0-private-beta.1-amd64` and launch it with explicit
`--image`, `--name opencyber-beta` and `--volume opencyber-beta` arguments.
`install.sh` does not import the published split archives and does not manage
that launcher-created container. Its defaults above describe the installer,
not a currently published public image.

## Build arguments

| Argument | Default | Effect |
| --- | --- | --- |
| `OPENCYBER_VERSION` | `0.5.0` | Sets the OCI version label and the `com.opencyber.harness.version` label. `scripts/check-version-consistency.py` keeps it equal to `src/opencyber/__init__.py`. |
| `OPENCYBER_CVE_YEARS` | empty | Space- or comma-separated NVD years. When non-empty, the build downloads those NVD 2.0 feeds, verifies their `.meta` SHA-256, and bakes `/usr/share/opencyber/cve/cve.sqlite` into the image. Empty keeps the image smaller and leaves `oc_cve_lookup` online-only. |

```sh
docker build \
  --build-arg OPENCYBER_VERSION=0.5.0 \
  --build-arg OPENCYBER_CVE_YEARS="2024 2025 2026" \
  -t opencyber:0.5.0-cve .
```

The candidate-build workflow does not pass `OPENCYBER_CVE_YEARS`, so release images do not include the optional CVE database. Mount one at `OPENCYBER_CVE_DB` or build a local variant if you need offline CVE lookups.

## Examples

Hardened, scope-enforced, with fatal executor audit and named internet features
disabled. This retains outbound routing; add `--network none` for a
software-only exercise that needs no target connections. The image below
is the imported private preview. This manual example uses a separate
container named `opencyber`; the beta guide uses `opencyber-beta`:

```sh
BETA_IMAGE=opencyber:0.5.0-private-beta.1-amd64
docker run -d --name opencyber \
  --cap-drop=ALL \
  --cap-add=NET_RAW --cap-add=NET_ADMIN --cap-add=NET_BIND_SERVICE \
  --security-opt no-new-privileges \
  --read-only --tmpfs /tmp --tmpfs /run \
  --tmpfs /root/.config --tmpfs /root/.cache \
  --tmpfs /root/.local/share --tmpfs /root/.nxc --tmpfs /root/.msf4 \
  -v opencyber-workspace:/workspace \
  -e OPENCYBER_OFFLINE=1 \
  -e OPENCYBER_ENFORCE_SCOPE=1 \
  -e OPENCYBER_AUDIT_REQUIRED=1 \
  -e OPENCYBER_HTTP_TIMEOUT=60 \
  "$BETA_IMAGE"
```

Compact discovery for a small-context model:

```sh
docker exec -i -e OPENCYBER_MCP_MODE=compact opencyber opencyber-mcp
```

Per-session override without recreating the container:

```sh
docker exec -i -e OPENCYBER_MCP_MODE=compact opencyber opencyber-mcp
docker exec -i -e OPENCYBER_TOOL_CATEGORIES=web opencyber opencyber-mcp
```

## Test-only names

The test suite uses two additional `OPENCYBER_*` names. Neither is a product setting:

| Name | Where | Purpose |
| --- | --- | --- |
| `OPENCYBER_SMOKE_COMPACT` | `tests/mcp_smoke.py` | When exactly `1`, the stdio smoke test runs against compact mode. |
| `OPENCYBER_TEST` | `tests/test_executor.py` | A fixture value passed through the executor's environment-override path to prove that overrides reach the child process. |

## Related documents

- [SECURITY_MODEL.md](SECURITY_MODEL.md): what these controls do and do not protect.
- [OPERATIONS.md](OPERATIONS.md): hardened deployment, backup, retention, and incident response.
- [CLI_REFERENCE.md](CLI_REFERENCE.md): command flags and exit codes.
- [AIRGAP.md](AIRGAP.md): offline assets, CVE index construction, and hard isolation.
