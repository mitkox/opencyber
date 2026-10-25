# Security model

The 0.5.0 private pre-production beta uses a trusted-client, container-root model. This page states its limits and the controls an operator applies from the host. Start with [BETA_TESTING.md](BETA_TESTING.md) for an owned software-only exercise; hardware interfaces remain experimental and unqualified.

> OpenCyber Harness provides offensive-security capability, not permission. Use it only against systems you own or are explicitly authorized to test.

## Assumptions

- The operator has authorization for every target and for any radio transmission.
- The host running Docker and the operator's MCP client are trusted.
- The container is treated as a single trust domain. There is no multi-tenant isolation inside it.
- The control point for authorization is outside the harness. The engagement target list is metadata unless scope enforcement is enabled, and scope enforcement is a guardrail, not an authorization system.

## Trust boundary

The container is the security boundary. That is deliberate: Nmap, tcpdump, hashcat, Aircrack-ng, SDR tooling, and raw-device work need filesystem, network, and device access that a per-tool sandbox would block.

| Property | Consequence |
| --- | --- |
| The runtime user is `root` inside the container on purpose. | Any code execution is container-root execution. Host hardening, not an in-container user model, is the control. |
| There is no application-level sandbox between tools. | One tool can read another engagement, another tool's artifacts, and the container filesystem. |
| All tools share a network namespace, filesystem, process table, and environment. | A compromised executable or injected command sees everything the container sees. |
| The server publishes no TCP port and speaks MCP over stdio. | There is no network listener to authenticate, but any local process that can run `docker exec` can act as the operator. |
| The workspace is a Docker volume. | Evidence survives container replacement. It also means a shared volume is shared data. |
| Host devices and `--network host` are opt-in. | The launcher's hardware profiles widen the boundary; use only the profile the task needs. |

### What leaves the boundary

Executable output, native tool results, workspace contents, HTTP responses, browser snapshots, screenshots, and audit events are returned to the MCP client. That client may be a model provider or a remote orchestration layer. Treat any data read from a target as potentially sensitive and potentially hostile. A target can return text that looks like instructions; the client must treat tool output as data, not as authority.

## Deployment baseline

The image runs as root. Complete the authenticated setup in
[BETA_TESTING.md](BETA_TESTING.md) and obtain the maintainer-selected qualified
platform digest before using a private candidate. No 0.5.0 release or image tag
is published yet. Harden from the host:

```sh
BETA_IMAGE=ghcr.io/mitkox/opencyber-beta-candidates@BETA_PLATFORM_DIGEST
docker run -d --name opencyber \
  --cap-drop=ALL \
  --cap-add=NET_RAW --cap-add=NET_ADMIN --cap-add=NET_BIND_SERVICE \
  --security-opt no-new-privileges \
  --read-only \
  --tmpfs /tmp --tmpfs /run \
  --tmpfs /root/.config --tmpfs /root/.cache \
  -v opencyber-workspace:/workspace \
  "$BETA_IMAGE"
```

| Control | Why it matters | Limitation |
| --- | --- | --- |
| `--cap-drop=ALL` plus three adds | Limits raw sockets, interface changes, and low-port binding to what the toolchain needs. | `NET_RAW` and `NET_ADMIN` are still powerful. Remove them for workloads that do not need packet capture or interface changes. |
| `--security-opt no-new-privileges` | Prevents a child process from gaining privileges through setuid or file capabilities. | Root already has most in-container privileges. |
| `--read-only` | Prevents persistent modification of the image filesystem. | `/workspace` and the listed tmpfs mounts remain writable. |
| tmpfs `/tmp`, `/run`, `/root/.config`, `/root/.cache` | Provides scratch space and lets Chromium's crashpad handler start under a read-only rootfs. | tmpfs is memory-backed; large tool caches can consume RAM. |
| No `--privileged` | The included tooling does not require it. | `--privileged` would effectively remove the container boundary. Do not add it for convenience. |
| Device flags per profile | Passes only the needed device nodes. | `/dev/bus/usb` exposes the whole USB bus; prefer specific nodes and host udev rules. |
| `--network host` for Wi-Fi, Bluetooth, and CAN | Gives access to host network interfaces and stacks. | It also removes Docker network isolation. Pair it with host firewall rules or a dedicated lab network. |

`install.sh` and `scripts/opencyber-run.sh` apply the same baseline by default. `--no-read-only` exists for diagnosis; it weakens the deployment.

## Code execution and environment inheritance

- `oc_bash` runs an arbitrary Bash script. `oc_python` runs inline Python or an engagement-relative file. Both are intentional arbitrary-code tools, executed as root, in a new process group so that client cancellation can terminate descendants.
- Executable-backed catalog tools receive an explicit argv array and are executed without a shell. That prevents shell metacharacter injection through arguments; it does not make the executable safe. The executable still has the container's filesystem, network, and device access.
- The executor inherits the full server environment. `executor.build_environment()` copies `os.environ` and applies caller-supplied overrides. Every child process therefore sees all environment variables present in the MCP server process, including target credentials, API tokens, proxy settings, and anything else passed with `docker run -e` or `docker exec -e`.
- There is exactly one scrubbed-prefix exception: names beginning with `OPENCYBER_APPROVAL_KEY` are removed from every child environment to reduce accidental signing-key disclosure (see **PoC execution gate** below). There is no other environment allowlist or per-tool secret scoping. If a secret must not reach a child process, do not put it in the server environment.
- Arbitrary code is not confined to an engagement. Engagement path resolution prevents path traversal through the workspace tools, not through `oc_bash`, `oc_python`, or a compromised binary.
- `oc_process_snapshot` exposes the container process table and network connections. That is useful for incident review and also confirms that anything running in the container is visible to the operator.

## PoC execution gate (CVE chains)

The `oc_chain_*` and `oc_poc_*` tools add a two-signature gate on top of the normal trust boundary. It exists because planning and writing a proof-of-concept is research, while *executing one against a live target* is an action that needs a human decision.

- **Authorization is signed, not declared.** The operator runs `opencyber-poc authorize` inside the container. It writes `<engagement>/poc/authorization.json`, HMAC-SHA256 signed with `OPENCYBER_APPROVAL_KEY`. The record names the authorized targets (a subset of the engagement targets), validity window, allowed technique classes, and whether agent-authored `custom` code is allowed. There is no MCP tool that creates or edits it; `oc_authorization_get` only reads and verifies.
- **Every run needs a signed, single-use approval.** `opencyber-poc approve` mints `poc/approvals/<approval_id>.json` bound to engagement, chain, spec id, spec hash, code hash, technique, targets, custom-code flag, issuer, expiry (at most 24 hours), and a nonce. `oc_poc_run` verifies the HMAC, hashes, expiry, scope, and authorization, then revalidates and durably consumes the approval under a cross-process lock before launching the executor. Cancellation, a crashed server, or evidence-write failure cannot make it reusable. A failed launch after reservation also consumes it; preflight refusals leave it unused. A spec or code change after approval fails with `artifact_hash_mismatch`.
- **Scope is mandatory for this path.** `oc_poc_spec_create` and `oc_poc_lint` check the declared target with `policy.scope_check`; `oc_poc_run` re-checks every target at execution time and requires each to appear in the signed authorization. This applies regardless of `OPENCYBER_ENFORCE_SCOPE`.
- **Signing is an operator workflow, not isolation from root.** `executor.build_environment()` strips `OPENCYBER_APPROVAL_KEY*` from child environments. There is no signing MCP tool, but arbitrary root code shares the filesystem and process namespace and may access signing material. Trust the client and its code. The operator CLI is the supported writer; environment scrubbing does not stop a hostile root process from forging records.
- **Runs are bounded.** At most 20 requests and 60 seconds per run, with at most 1 MiB per captured response body (the environment may only lower the request/deadline caps), one concurrent run per engagement, and a scrubbed environment. On timeout the process group is terminated and the partial evidence is retained.
- **Techniques are non-destructive by construction.** The rendered templates cover version/banner assertions, bounded HTTP sequences, auth-difference checks, OOB callbacks to an operator-supplied in-scope listener, canary file reads, and TCP probes. Reverse shells, persistence, credential dumping, privilege-escalation payloads, C2, evasion, DoS, and exfiltration are refused; they are out of scope even with authorization.
- **Limits.** Lint is static and best-effort, not a sandbox. A `custom` PoC runs as container root inside the trust boundary, so approve only code you have read. The container is still not an egress firewall.
- **Audit.** `poc.authorization.created`, `poc.chain.created`, `poc.approval.created`, `poc.approval.revoked`, and `poc.run.started/completed/refused` are appended to the engagement audit chain.

See [POC_CHAINS.md](POC_CHAINS.md) for the operator workflow and [INTEGRATIONS.md](INTEGRATIONS.md) for the agent adapters.

## Scope enforcement

`OPENCYBER_ENFORCE_SCOPE=1` turns on target inspection for two call paths. Before an executable starts, `policy.enforce_scope()` extracts URL, IPv4/CIDR, and dotted-hostname tokens from the argv and compares them with the engagement's `targets`. Native HTTP paths call `policy.enforce_url_scope()`, which compares the parsed host of the requested URL with the same targets and refuses before any socket is opened.

- A bare domain target also matches its subdomains. A CIDR target matches IP hosts inside it. A target of `*` matches anything. Matching is case-insensitive and strips ports, wildcard prefixes, userinfo, and trailing punctuation.
- Out-of-scope tokens refuse the call. The refusal is returned to the client and recorded as `tool.denied`; allowed checked calls record `tool.scope_checked`.
- `oc_bash` and `oc_python` cannot be meaningfully checked because their arguments are code. Under enforcement they are refused unless `OPENCYBER_ALLOW_UNSCOPED_EXECUTION=1`. With that override they run without a target check.
- Native HTTP tools require `engagement_id` when enforcement is on. Without it the call is refused with `engagement_required` rather than silently sent. When enforcement is off these tools run without a target check and the result says `scope_enforced: false`.
- A redirect can change the destination host. Native HTTP/API tools and the HTTP workbench re-check the URL host before every redirect request when engagement enforcement is enabled. Requests redirect limits still apply. DNS aliases, resolution changes, proxies and subprocess-managed redirects remain outside this host-token control.
- Extraction is heuristic and intentionally narrow. IPv6 literals outside URLs, targets assembled at runtime, config-file targets, DNS aliases, redirects performed by a tool, and IPs reached through a proxy are not reliably intercepted. The control raises the cost of an accidental out-of-scope command; it does not stop a determined operator or a compromised tool.

### Scope enforcement matrix

| Call path | Checked by `OPENCYBER_ENFORCE_SCOPE` | Actual control |
| --- | --- | --- |
| Executable-backed tools (`oc_nmap`, `oc_nuclei`, `oc_curl`, and the rest) | Yes, when enabled | argv token extraction before spawn; out-of-scope calls refused |
| `oc_execute` | Yes, when enabled | Same executor path as a direct tool |
| `oc_bash` | Refused when enabled, unless `OPENCYBER_ALLOW_UNSCOPED_EXECUTION=1` | No target-level check; arbitrary code |
| `oc_python` | Refused when enabled, unless `OPENCYBER_ALLOW_UNSCOPED_EXECUTION=1` | No target-level check; arbitrary code |
| HTTP workbench (`oc_http_repeater`, `oc_http_intruder`) | Yes, when enabled | Engagement target host check on every request and every redirect hop, plus the session's own `scope_hosts`; the redirect chain is capped at 30 |
| `oc_http_request` | Yes, when enabled | Host check before the request and each redirect hop; `engagement_id` is required under enforcement |
| `oc_graphql_request` | Yes, when enabled | Host check before the request and each redirect hop; `engagement_id` is required under enforcement |
| `oc_openapi_inspect`, `oc_openapi_audit`, `oc_graphql_audit` | Yes, when enabled | Host check before the fetch and each redirect hop; engagement-relative files are read locally |
| `oc_api_fuzz` | Yes, when enabled | Host check on every generated URL and redirect hop before sending |
| `oc_browser_*` | No | None; Chromium can navigate anywhere the container can reach |
| `oc_hibp_password_check` | No | Offline-mode refusal only |
| `oc_cve_lookup` | No | Local database first; NVD when online and no local DB |
| Workspace tools (`oc_workspace_*`, `oc_finding_report`) | Not applicable | Path containment inside one engagement |
| Serial and firmware tools | Not applicable | Serial device prefix allowlist; firmware is analyzed, not executed |
| `oc_scope_check` | Not applicable | Reports a decision without executing anything |
| `oc_poc_spec_create`, `oc_poc_lint` | Always, independent of the environment variable | Declared target must match an engagement target; lint checks the supported technique vocabulary, while signed technique authorization is enforced at run time |
| `oc_poc_run` | Always, independent of the environment variable | Signed authorization + signed single-use approval + target scope preflight + bounded process-group execution |
| `oc_chain_plan`, `oc_chain_get`, `oc_authorization_get`, `oc_poc_evidence` | Not applicable | Local planning/readback only; chain planning persists a record but sends no target traffic |

The HTTP workbench keeps a second, per-session host boundary (`scope_hosts`, optional subdomains) that applies even when engagement enforcement is off. `oc_http_session_update` can widen or narrow that session scope, but it cannot widen the engagement scope: under enforcement every request must also match an engagement target.

### What scope enforcement is not

It is not an egress firewall, a DNS policy, an authorization service, or a sandbox. It does not inspect packets, resolve DNS, or police native Python tools. A hard boundary requires network policy outside the container: `--network none`, an internal Docker network with no default route, a host firewall, or a dedicated VLAN. Combine that with the HTTP workbench when the task permits it, and use separate containers and volumes for separate trust domains.

## Offline mode is limited blocking

`OPENCYBER_OFFLINE=1` is a fail-fast switch, not an airgap enforcement mechanism.

| Blocked | Not blocked |
| --- | --- |
| `shodan`, `censys`, `subfinder`, `theHarvester`, `sherlock` (exact executable names) | All other catalog executables, including `amass`, `recon-ng`, `spiderfoot`, and `wafw00f` |
| `oc_hibp_password_check` | `oc_http_request`, `oc_graphql_request`, OpenAPI/GraphQL audits, API fuzz, browser tools |
| `oc_cve_lookup` NVD fallback when no local database exists | Local CVE lookup, shell, Python, file, workspace, and hardware tools |

`OPENCYBER_OFFLINE_ALLOW_NETWORK_TOOLS=1` overrides only the five executable refusals; it does not re-enable HIBP or NVD. Native network tools still open sockets in offline mode. A real airgap must remove routing; see [AIRGAP.md](AIRGAP.md).

## Evidence, audit, and redaction

Every engagement has an append-only audit log at `<engagement>/.opencyber/audit/events.jsonl`. Each record contains `seq`, `prev_hash`, and a SHA-256 `hash` over its canonical contents. `oc_audit_verify` recomputes the chain and reports the first removed, reordered, or edited record.

| Property | Guarantee |
| --- | --- |
| Hash chain | Detects internal removal, reordering, and edits within the file. Detecting removal from the end requires an externally retained final hash. |
| File lock and `fsync` | Serializes appends and flushes them before returning. |
| Coverage | Executor calls, denials, scope checks, cancellation, workspace writes and deletes, HTTP workbench requests, API fetches and audit artifacts, browser actions, serial sessions, firmware reports, and PoC authorization/chain/approval/run events. |
| Redaction | Pattern-based, applied to audit records only. Known credential-like keys and scalar patterns are replaced with `***`. |
| Tamper resistance | Tamper-evident, not tamper-proof. Root inside the container can rewrite the entire file and chain. There is no remote anchor or external witness. |
| Best-effort writes | Most native call sites use `safe_record()`, which silently ignores an audit failure. `OPENCYBER_AUDIT_REQUIRED=1` makes executor writes fatal, but does not change the other call sites. |

`OPENCYBER_AUDIT=0` disables only executor audit events. Workspace, HTTP, API, browser, serial, and firmware audit writes still occur. Conversely, `OPENCYBER_AUDIT_REQUIRED=1` is executor-scoped and does not make the other writes reliable.

### Evidence is unredacted by default

Audit redaction is not evidence redaction. These artifacts can contain live credentials, bearer tokens, cookies, session identifiers, personal data, and target content, and are stored unredacted:

- HTTP workbench session state and complete request/response history, including headers, cookies, and bodies.
- Browser cookies, local storage, session storage, screenshots, DOM snapshots, and the browser network log.
- API audit and fuzz evidence under `evidence/api/`.
- Workspace files, findings, and firmware reports.
- Serial transcripts, which may include boot secrets or console credentials.
- PoC run evidence under `poc/runs/`: transcripts redact `Authorization`, `Cookie`, `Set-Cookie`, and API-key headers, but response bodies and target content are kept, and `poc/code/` holds the rendered or custom verifier source.
- Executable stdout and stderr returned to the client, and any files the executable writes.

The audit redactor is a heuristic. It matches credential-like field names and patterns such as `token=...` and `Bearer ...`; it does not find secrets in arbitrary prose, positional password arguments, binary output, or every URL form. Do not treat the audit log as a sanitized copy of the engagement.

Evidence files are not hash-chained or signed as a set. Only audit events carry the chain. A `workspace.write` event records a SHA-256 of the content at write time, but that digest is not re-verified against the file later, and editing or deleting an artifact does not necessarily break the audit chain.

For an integrity record that survives beyond the container, copy the whole engagement directory and record the final chain hash (`oc_audit_verify` returns `last_hash`) in an external system you control.

### Tool results, retention, and untrusted content

Every tool result carries an `evidence` block: an `oc_ev_` identifier, a full SHA-256 of the canonical payload, its size, and whether content was retained. The digest identifies what one call returned; it is not a signature and does not establish the target's state.

`OPENCYBER_RESULT_RETENTION` decides what is stored under `<engagement>/.opencyber/results/`:

| Mode | Stored | Consequence |
| --- | --- | --- |
| `off` | Nothing | Only the digest returned in the response exists. |
| `digest` (default) | Index entry: id, tool, digest, size, time | A digest can be resolved to tool and size, never to content. |
| `full` | Redacted payload, 1 MiB per record, pruned at 500 records / 32 MiB | Content is readable with `oc_result_get`, subject to the audit redactor's known limits. |

Retention content is redacted with the same heuristic described above. It is not a sanitized copy: a secret in prose, a positional password argument, or binary output is not reliably removed. Treat retained results as sensitive engagement data.

Results larger than the evidence digest ceiling (4 MiB) carry `evidence.id: null` with an explicit reason instead of an unbounded hash. A result whose output exceeded the executor cap is reported as `partial` with a `limit` block, never as an empty result.

Tool output is untrusted input to the agent. Every result states `provenance.untrusted_content`, true whenever the payload contains bytes or text from the scanned system: banners, HTTP bodies, page snapshots, file contents, serial output. A prompt-injection attempt in a scanned response is data to report, not an instruction to follow.

## Browser, TLS, and web tooling

- Chromium runs headless with `--no-sandbox` and `--disable-dev-shm-usage`. Chromium's own sandbox is disabled because the container is already the boundary. A browser exploit therefore lands with container-root privileges.
- `oc_browser_create` defaults `ignore_https_errors=True`, so the browser accepts self-signed, expired, and mismatched certificates. Pass `ignore_https_errors=False` when certificate validation matters for the test.
- The HTTP workbench defaults `verify_tls=True`. It can be changed per session with `oc_http_session_create` or `oc_http_session_update`; disabling it removes certificate validation for that session.
- Native `oc_http_request`, `oc_graphql_request`, OpenAPI fetches, GraphQL audit, and API fuzz use Python `requests` with its default certificate verification. They do not expose a per-call `verify` switch.
- Browser tools are not engagement-scope-enforced. Native HTTP/API tools check each request and redirect host when enforcement is enabled. A browser session can reach any host the container can route to, and can exfiltrate data through page loads or JavaScript evaluation.

## Credentials and secret handling

- There is no secret store, vault integration, or per-engagement credential vault. Credentials are whatever you pass in the environment, arguments, workspace files, or HTTP/browser state.
- The executor's environment inheritance means any secret in the server environment is available to every child process. Use short-lived, least-privilege credentials and recreate the container to change its environment; `docker restart` does not change `docker run -e` values.
- Credentials supplied as tool arguments can appear in audit events. Redaction reduces but does not eliminate this.
- Cookies and tokens captured in HTTP history, browser state, and API evidence persist in the workspace volume. Rotate target credentials and invalidate sessions after an engagement, especially if the evidence is copied or shared.
- Host Docker access is equivalent to host root. Protect the Docker socket and any account that can run containers.

## Multi-tenancy and isolation

There is no authentication, authorization, RBAC, tenant separation, or per-client identity. Every process that can launch the MCP server can list and use every engagement in the mounted workspace, and root code can read the entire filesystem.

Engagements isolate artifacts and reduce accidental mixing. They are not a security boundary against a deliberately hostile executable or operator. For separate operators, clients, or trust domains, use separate containers with separate volumes, and give each container only the devices and network access it needs.

A workspace volume shared by multiple containers is shared data. File locks serialize audit appends, retained-result transactions and PoC approval consumption for processes sharing those files. They do not provide tenant identity, access control, distributed scheduling or workspace quotas.

## Network exposure and availability

- The server has no listening socket. It speaks MCP over the stdin/stdout of a `docker exec` process. There is no TLS endpoint, API key, or remote authentication.
- Containers keep outbound connectivity by default. Egress policy is a host concern.
- There is no general rate limit, request quota or global concurrency limit. Executor calls have a default 1800-second deadline and 4 MiB retained-output cap per stream; PoC runs have stricter limits. Time spent supplying stdin counts toward the executor deadline. Cancellation and timeout clean up the process group even when the original leader has exited. These controls do not replace host cgroup limits.
- There is no telemetry, license check, model download, or background updater.

## Supply chain

- Publication requires native `linux/amd64` and `linux/arm64` candidate receipts, corresponding source, license evidence, Syft SBOMs and a Trivy gate covering `HIGH` and `CRITICAL`, including unfixed vulnerabilities. Promotion copies the qualified digests without rebuilding, signs platform and manifest digests with keyless cosign, and attaches provenance. A local build or this document is not evidence that those release gates passed.
- Base images, Go/Rust tool versions, yq, and nuclei templates are pinned in the Dockerfile. The image records license bundles under `/usr/share/opencyber/licenses/`.
- The current repository and candidate package are private. Repository read access and package access are separate, and neither establishes qualification. Binary distribution remains blocked by unresolved license metadata and incomplete matching-commit software acceptance. Private beta sharing must satisfy those gates too.
- There is no PyPI publication. Use authenticated source access for development; a source install does not bundle the container toolchain. Once the maintainer supplies a qualified candidate, install its exact platform digest as described in the beta guide.
- A future public 0.5.0 prerelease will use the explicit version reference or an immutable digest and will not advance `latest`, major or minor aliases. Publication and anonymous access remain future gates; see [RELEASE.md](RELEASE.md). Verify supplied attestations rather than assuming private access proves provenance.
- The image build itself requires network access and executes upstream package repositories and projects. Treat a locally built image as trusted only as far as that build environment is.

## Residual risks

| Risk | Why it remains | Mitigation |
| --- | --- | --- |
| Out-of-scope traffic through native tools | Browser tools do not consult engagement scope; HTTP/API scope checks do not implement DNS or proxy egress policy | Network egress policy; prefer the HTTP workbench; separate containers per trust domain |
| Out-of-scope traffic through executable arguments | Token extraction is heuristic and can miss dynamically assembled targets | Keep target lists honest; review argv; use network policy |
| Arbitrary code as container root | `oc_bash`, `oc_python`, and compromised executables | Do not expose the container to untrusted clients; drop capabilities; no host mounts; rebuild after suspected compromise |
| Secrets exposed to child processes | The executor inherits the full server environment | Short-lived credentials; do not put long-lived secrets in the server environment; rotate |
| Secrets in evidence | HTTP history, browser state, API artifacts, serial transcripts, and workspace files are unredacted | Treat the volume as sensitive; encrypt backups; rotate and purge per policy |
| Audit rewritten wholesale | Root inside the container can recompute the chain | Copy evidence out and record the final hash externally; restrict host and container access |
| Missing audit events | Best-effort `safe_record()` call sites; `OPENCYBER_AUDIT=0` disables executor events | `OPENCYBER_AUDIT_REQUIRED=1` for executor calls; correlate with artifacts; avoid disabling audit |
| Browser exploit | Chromium runs with `--no-sandbox` and container-root privileges | Do not browse untrusted targets with valuable host credentials; isolate the container |
| TLS verification disabled | Browser defaults `ignore_https_errors=True`; workbench TLS can be disabled | Opt in to verification for tests that need it |
| Host exposure through devices or host networking | USB passthrough, `--network host`, `SYS_RAWIO`, `NET_ADMIN`, `NET_RAW` | Use the narrowest hardware profile; host firewall; dedicated lab host |
| Shared workspace | No authentication or per-tenant separation | Separate containers and volumes per operator or trust domain |

## Reporting a vulnerability

Follow [SECURITY.md](../SECURITY.md). Do not open a public issue for a suspected vulnerability in the harness or in a shipped component.
