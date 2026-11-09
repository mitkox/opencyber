# CVE chain proof-of-concept

How to plan a CVE exploit chain from OpenCyber findings, produce a bounded
proof-of-concept, and run it with signed operator approval and reproducible
evidence in the 0.5.0 private pre-production beta. For a first exercise use the
[disposable lab](POC_LAB.md); it needs no real target or hardware.

> Authorized testing only. The tooling provides capability, not permission.
> Every PoC run requires two human acts: a signed engagement authorization and a
> signed, single-use approval for that exact spec. Neither can be created
> through MCP.

## Design in one paragraph

OpenCyber is the execution substrate; it is not a planner and it does not write
exploits. The agent annotates each observed CVE with the capability tokens it
**requires** and **provides**; `oc_chain_plan` does deterministic graph math and
reports whether the chain closes. For each step the agent creates a declarative
PoC spec, renders a stdlib-only verifier from a fixed template library, and lints
it against engagement scope. Execution is gated: `oc_poc_run` refuses unless the
engagement has a valid signed authorization covering the target and technique,
and the operator has minted a signed, single-use approval bound to the spec and
code hashes. Runs are bounded, audited, and captured as evidence.

## Prerequisites

1. **An engagement** with the authorized target list:
   `oc_engagement_create(name, targets, objective)`.
2. **An approval key** inside the container, at least 32 bytes:
   `OPENCYBER_APPROVAL_KEY` or `OPENCYBER_APPROVAL_KEY_FILE`. Without it,
   planning and linting still work but `oc_poc_run` is disabled.
3. **A signed authorization record** for the engagement, created by the operator
   (see below). The record lists the targets, validity window, allowed
   techniques, and whether agent-authored `custom` code may run.

The agent reads the authorization with `oc_authorization_get`. MCP has no
signing tool; the operator CLI is the supported creator. This is a workflow
boundary, not isolation from arbitrary code running as container root. The `poc/` workspace subtree is server-managed: workspace
write/delete tools refuse it. Owning modules validate record identities,
signatures and content hashes where specified. This does not prevent trusted
container-root code from rewriting files.

## Operator CLI: `opencyber-poc`

Run it inside the running container so it reads the same workspace and key:

```sh
docker exec -i opencyber opencyber-poc --help
```

### authorize

Set `AUTHORIZATION_VALID_UNTIL` to the UTC expiry allowed by your written
authorization. Set `APPROVAL_EXPIRES` to a future UTC timestamp at most 24 hours
away. Replace the example engagement, chain and spec IDs with returned IDs;
these commands are templates, not an authorization for the example targets.

```sh
docker exec -i opencyber opencyber-poc authorize \
  --engagement eng_20261025_9f8d4c1a6b2743f4a2c11bb8d02a91a7 \
  --authorized-by "Jane Doe <jane@example.test>" \
  --reference "ROE-2026-014" \
  --scope 10.10.0.0/24 \
  --scope app.lab.test \
  --valid-until "$AUTHORIZATION_VALID_UNTIL" \
  --techniques version_assert,http_sequence,http_auth_diff,oob_callback,file_read_canary,tcp_probe \
  --acknowledgement "I confirm written authorization for these targets and techniques"
```

- Every `--scope` value must fall inside the engagement's target list.
- `--custom-code` additionally allows agent-authored Python (`technique: custom`).
  It is off by default and needs its own approval flag per run.
- Targets that look public (anything outside RFC1918, loopback, `.local`, or
  `.test`) require `--i-have-written-authorization`; the CLI warns loudly.
- A new authorization supersedes the previous one; the old record is archived
  under `poc/authorization-history/`.

### approve

```sh
docker exec -i opencyber opencyber-poc approve \
  --engagement eng_… \
  --chain chain_20261025_… \
  --spec spec_20261025_… \
  --issued-by "Jane Doe <jane@example.test>" \
  --expires "$APPROVAL_EXPIRES"
```

The CLI loads and lints the spec first and refuses if there are blocking
findings, then prints the signed approval record as JSON (`approval_id` is a
top-level field). The approval binds: engagement, chain, spec id, spec hash,
code hash, technique, targets, custom-code flag, issuer, issue time, expiry, and
a signed anti-replay nonce.
It is single-use: `oc_poc_run` revalidates and durably consumes it atomically
before executor launch. A reserved approval cannot be retried after interruption.

### revoke / status

```sh
docker exec -i opencyber opencyber-poc revoke --engagement eng_… --approval apr_… --reason "scope narrowed"
docker exec -i opencyber opencyber-poc status --engagement eng_…
```

`status` prints JSON with authorization validity, chain verdicts, approval state,
and run history.

## Capability tokens

Chain math uses a closed vocabulary. Tokens are claims recorded with provenance;
the tool never invents them.

| Token | Meaning |
| --- | --- |
| `net:tcp:<port>`, `net:udp:<port>`, `net:http:<port>` | service reachable from the attacker position |
| `net:internal:<port>` | service reachable only from inside the target network |
| `auth:none`, `auth:user`, `auth:admin` | authentication level already held |
| `exec:container`, `exec:host` | code execution position gained |
| `file:read:<glob>`, `file:write:<glob>` | filesystem capability |
| `creds:<type>` | credential material obtained |
| `secret:read:<name>` | one named secret readable |
| `info:<kind>` | information disclosure (version, config, path) |
| `position:internet`, `position:adjacent`, `position:local` | attacker position |

## Planning a chain

The CVE labels and capability claims below are illustrative, not statements
about a real advisory. Replace them with CVEs observed in your own artifacts.

`oc_chain_plan` input:

```json
{
  "engagement_id": "eng_…",
  "chain_name": "edge-to-internal",
  "entry_capabilities": ["position:internet", "net:http:8080", "auth:none"],
  "artifacts": ["artifacts/nuclei.jsonl", "artifacts/trivy.json"],
  "steps": [
    {
      "cve_id": "CVE-2026-1111",
      "asset": "app.lab.test",
      "requires": ["net:http:8080", "auth:none"],
      "provides": ["net:internal:6379", "info:version"],
      "basis": "advisory: the download endpoint proxies an attacker-controlled URL",
      "source": "nuclei"
    },
    {
      "cve_id": "CVE-2026-2222",
      "asset": "cache.lab.test",
      "requires": ["net:internal:6379", "auth:none"],
      "provides": ["exec:container"],
      "basis": "advisory: unauthenticated Redis protocol allows command execution",
      "source": "trivy"
    }
  ]
}
```

The result carries `verdict`:

| Verdict | Meaning |
| --- | --- |
| `complete` | every step's `requires` is satisfied by entry capabilities plus earlier steps' `provides` |
| `incomplete` | `missing` lists the exact tokens nothing supplies; the chain is not closed |
| `cyclic` | remaining steps depend on each other; reject the ordering |
| `invalid` | schema, id, or capability token error; fix it, do not re-spell it |

`artifacts` are parsed deterministically (nuclei JSONL, trivy JSON, generic JSON
lists). Steps whose CVE does not appear in any parsed artifact are marked
`observed: false` with an `unobserved_cve` warning. If a local NVD index is
present the CVE ids are also cross-checked; otherwise they carry an
`unverified_cve` warning. Planning never leaves the box.

## PoC specs and techniques

`oc_poc_spec_create` builds one spec per chain step.

| Technique | Rendered verifier behaviour |
| --- | --- |
| `version_assert` | one HTTP request; assert status plus a server/header/body marker |
| `http_sequence` | ordered requests; per-response assertions |
| `http_auth_diff` | the same resource requested with and without credentials; assert the access difference |
| `oob_callback` | request embeds a token aimed at an operator-supplied in-scope listener; poll for the callback |
| `file_read_canary` | traversal-style request; assert a fixed canary marker string was returned |
| `tcp_probe` | bounded connect + banner read; regex assertion |
| `custom` | agent-authored Python, stored verbatim, run only with the custom-code authorization and approval |

Every generated verifier is stdlib-only, bounded by the spec's `limits`, prints
one `POC_RESULT <json>` line, and writes a JSONL transcript with
`Authorization`, `Proxy-Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key`,
`X-Auth-Token`, and `X-Csrf-Token` headers redacted.

### Requests

`requests` is a closed schema: `{method, path, headers, body}`. `method` is one
of GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS; `path` must start with `/` and
contain no whitespace; `headers` is a string map; `body` is a string and
defaults to empty. Per technique: `version_assert` needs exactly one request,
`http_auth_diff` exactly two (unauthenticated first, then the credential-carrying
request), `tcp_probe` and `custom` accept none, and the rest need at least one
and never more than `limits.max_requests`.

`limits` is closed: `{max_requests, timeout_s, max_bytes}`; omitted keys default
to the current caps. `target` is an `http(s)` URL (no userinfo, query, or
fragment) for the HTTP techniques, a `host:port` for `tcp_probe`, and either for
`custom`. `step_order` is the chain record's satisfaction `order` and must name
a satisfied step.

HTTPS probes verify certificates and hostnames by default. A lab target with a
self-signed or otherwise invalid certificate needs the explicit
`allow_insecure_tls: true` field on the spec; the value is part of the persisted
spec digest and the run evidence, and there is no environment variable or bare
run flag that can disable verification.

### Assertions

Assertions are a closed expression language. The server evaluates every one
again after the run and never trusts the child's exit code.

| Type | Fields | Notes |
| --- | --- | --- |
| `status_in` | `statuses` (1-20 HTTP codes), optional `request` | response status is in the set |
| `body_regex` | `pattern`, optional `request` | regex over the response body |
| `header_regex` | `header`, `pattern`, optional `request` | regex over one response header |
| `latency_lt_ms` | `ms` (1-60000), optional `request` | response latency bound |
| `callback_received` | `url` (in-scope http(s) listener), optional `token`, `polls` 1-20, `interval_ms` 50-5000 | poll the listener for the token |

`request` is a 0-based index into `requests` and defaults to the last observed
request, which is what `http_sequence` usually wants. For `oob_callback` the
token is generated when omitted and injected as the `X-PoC-Callback` request
header plus `{{POC_TOKEN}}` replacement in paths, headers, and bodies; the
`callback_received` assertion needs the listener URL. For `file_read_canary`
the canary marker is the required `body_regex` pattern (the default assertion
looks for `root:x:0:0:` in a default traversal request); supply your own request
and pattern when the target differs.

Spec example:

```json
{
  "chain_id": "chain_…",
  "step_order": 1,
  "technique": "http_sequence",
  "target": "http://app.lab.test:8080",
  "requests": [
    {"method": "GET", "path": "/download?file=../../../../etc/opencyber-canary", "headers": {}}
  ],
  "assertions": [
    {"type": "status_in", "statuses": [200]},
    {"type": "body_regex", "pattern": "OPENCYBER-CANARY-[0-9a-f]{16}"}
  ],
  "limits": {"max_requests": 3, "timeout_s": 15, "max_bytes": 262144},
  "allow_insecure_tls": false
}
```

Caps are hard: at most 20 requests and 60 seconds per run, one concurrent run per
engagement, and `limits.max_bytes` bounds each captured response body (hard cap
1 MiB). Saved stdout/stderr evidence is capped at 8 MiB each and the transcript
summary at 512 KiB. `OPENCYBER_POC_MAX_REQUESTS` and `OPENCYBER_POC_TIMEOUT` can
only lower the caps.

## Linting

`oc_poc_lint` returns `blocking` findings (`{code, message, evidence?}`),
`warnings`, `hosts` (`{host, allowed, matched_target}`), and `passed`. Blocking
findings include: a host that is not in engagement scope (`out_of_scope_host`),
a technique outside the supported set (`technique_not_allowed`), limits or
request counts above the caps, forbidden patterns in custom code (reverse
shells, persistence, credential files, `subprocess`/`os.system`/`ctypes`/`pty`,
destructive commands, unbounded loops), and for the custom tier a missing or
unavailable authorization allowance. Warnings include
`custom_code_requires_separate_approval`, `custom_spec_has_no_assertions`, and
`callback_polling_exceeds_timeout`.

Lint does **not** decide whether the signed authorization allows a technique —
that is enforced at run time (`technique_not_authorized`). Lint is best-effort
defence in depth; the container remains the trust boundary.

## Running

Sequence inside `oc_poc_run`:

1. Load and verify the chain (`complete` required).
2. Verify the signed authorization covers the target, technique, and custom-code
   flag.
3. Verify the approval HMAC, expiry, single-use state, and that the spec/code
   hashes still match.
4. Re-lint and preflight `scope_check` for every target.
5. Take the per-engagement run lock, revalidate authorization and approval,
   durably consume the approval, and persist a `running` record.
6. Launch the verifier with signing-key variables removed from its environment
   and a bounded timeout under `poc/runs/<run_id>/`.
7. Evaluate assertions server-side, write evidence and audit events, and return
   a structured result. The child's exit code is not trusted.

| Status | Meaning |
| --- | --- |
| `verified` | all assertions held |
| `not_verified` | the effect did not reproduce; report the negative result |
| `timeout` | the bounded run expired; evidence is retained |
| `refused` | a gate rejected it; read `reason` |

Refusal reasons include: `approval_key_unavailable`, `authorization_required`,
`authorization_expired`, `authorization_not_yet_valid`, `authorization_invalid`,
`scope_violation`, `technique_not_authorized`, `approval_invalid`,
`approval_consumed`, `artifact_hash_mismatch`, `chain_incomplete`,
`chain_mismatch`, `lint_failed`, `run_in_progress`, `invalid_id`,
`unknown_spec`, `spec_invalid`, `invalid_source`, `execution_error`,
`execution_unavailable`, and `run_failed`.

A completed run returns `{status, run_id, chain_id, spec_id, approval_id,
technique, target, assertions: [{type, passed, detail}], evidence_path,
output_sha256, duration_ms, request_count, truncated, started_at, completed_at,
approval_consumed}`, plus `reason`/`message` on a refusal. When a read deadline
interrupts an HTTP response or a TCP banner after bytes arrived, the received
bytes are retained rather than discarded: the request record carries the partial
`body_text`, `body_complete: false`, and `error: "timed_out_after_partial_body"`
(or `timed_out_before_data` when nothing arrived), which the server reports as a
failed probe assertion. `timeout` counts as a
completed run. The approval is revalidated and durably consumed immediately
before executor launch; cancellation, process death, failed launch, or an evidence
write failure does not make it reusable. Preflight refusals leave it unused.
Reusing a reserved approval returns `approval_consumed`. A persisted `running`
record denotes an incomplete attempt, not proof that a process remains alive.
A cancelled request may leave a `cancelled` checkpoint without returning a tool
result. Inspect `opencyber-poc status` and `oc_poc_evidence` before deciding
whether another run is needed. If `run_failed` reports
`approval_consumed: true` and `execution_started: false`, fix the storage
failure and request a new approval; do not reuse the old one.

The signing CLI is an operator workflow within the trusted container. Removing
signing-key variables from child environments does not isolate them from arbitrary
root code. Do not expose this workflow to an untrusted client.

## Evidence and audit

```
<engagement>/poc/
  authorization.json
  authorization-history/<sha256>.json
  chains/<chain_id>.json
  specs/<spec_id>.json
  code/<spec_id>.py
  approvals/<approval_id>.json
  runs/<run_id>/result.json
  runs/<run_id>/stdout.txt
  runs/<run_id>/stderr.txt
  runs/<run_id>/transcript.jsonl
  runs/<run_id>/evidence.json
  .lock                                per-engagement PoC run mutex (runtime)
```

`oc_poc_evidence` lists runs or reads one run. Audit events:
`poc.authorization.created`, `poc.chain.created`, `poc.spec.created`,
`poc.spec.rendered`, `poc.approval.created`, `poc.approval.revoked`,
`poc.run.started`, `poc.run.completed`, `poc.run.refused`. `oc_audit_verify`
recomputes the engagement hash chain.

Evidence can contain live credentials in response bodies; treat the workspace
volume as sensitive.

## MCP tools

| Tool | Purpose |
| --- | --- |
| `oc_authorization_get` | Read and verify the signed authorization; never creates it. |
| `oc_chain_plan` | Deterministic capability-graph validation and persistence. |
| `oc_chain_get` | Read one chain or list summaries. |
| `oc_poc_spec_create` | Validate and persist one declarative PoC spec. |
| `oc_poc_render` | Render the spec to a bounded stdlib verifier. |
| `oc_poc_lint` | Scope/technique/limit/forbidden-pattern findings. |
| `oc_poc_run` | Gated execution with evidence and audit. |
| `oc_poc_evidence` | List runs or read one run's result and artifacts. |

## Agent integrations

The same tools are available from any MCP client. Ready-made adapters for
OpenCode V2 Code Mode and DeepSeek Harness are in
[../integrations/README.md](../integrations/README.md); the runtime-neutral
workflow is the `cve-chain-poc` skill.

To exercise the whole workflow against a synthetic target without an engagement
of record, use the disposable [PoC lab](POC_LAB.md).

## Limitations

- This is not a general exploit framework. It produces bounded,
  non-destructive verification of a claimed capability chain.
- Lint is static and best-effort. A `custom` PoC runs as root inside the trust
  boundary; only approve code you have read.
- CVE capability annotations are claims by the researcher, not ground truth.
  The tool records them with provenance and refuses to invent them.
- Destructive techniques (persistence, credential dumping, privilege-escalation
  payloads, C2, evasion, DoS, exfiltration) are out of scope even with
  authorization. Plan them as hypotheses only.
- Scope enforcement for PoC runs is mandatory, but the container is not a
  network firewall. Enforce egress at the host or network layer.
