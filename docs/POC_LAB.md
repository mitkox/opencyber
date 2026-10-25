# PoC lab: test the approval workflow without a real target

The 0.5.0 private pre-production beta includes a synthetic loopback target and a
26-check driver for [POC_CHAINS.md](POC_CHAINS.md). It exercises planning,
authorization, single-use approval, refusal and evidence paths. It does not
prove a real CVE, assess a production target or qualify hardware.

Start with [BETA_TESTING.md](BETA_TESTING.md) for the basic installation and
MCP exercise. This lab needs a Linux Docker host, Python 3, the source checkout
and a selected 0.5.0 image. Use the maintainer-provided source commit and
qualified private candidate digest after the distribution gates pass; no
0.5.0 release or image tag is published yet. A local build is development
evidence only.

## One-command check

From the selected source checkout, use a local build or a qualified candidate
supplied by the maintainer:

```sh
# Local build; omit this when testing an already selected immutable image.
docker build --provenance=false -t opencyber:0.5.0 .

mkdir -p ../opencyber-beta-evidence
bash scripts/poc-lab-image.sh opencyber:0.5.0 \
  ../opencyber-beta-evidence/poc-lab.json
```

Replace the image argument with the maintainer-selected
`ghcr.io/mitkox/opencyber-beta-candidates@sha256:…` reference when testing a
qualified private candidate. Authenticate as described in the beta guide;
repository and package access are separate. Keep evidence outside the source
checkout so collecting it does not change the commit being tested.

The helper creates its own disposable container with no external network,
dropped capabilities, a read-only root filesystem and temporary workspace.
It mounts the fixture read-only, creates a fresh lab key, starts the target on
loopback and runs the installed MCP server and operator CLI. It removes the
container on exit. No workspace volume or signing key is left behind.

Expected result: `26/26 checks passed`, process exit zero and JSON with
`passed: true` and an empty `failed_checks` list. The checks include:

- A complete two-step chain whose CVE labels appear in the synthetic artifact.
- `version_assert` and `file_read_canary` runs verified by server-side assertions.
- Replay, absent-approval, altered-spec, out-of-scope and unauthorized-technique
  refusals.
- Evidence readback and operator status showing the expected authorization.

The driver acts as the operator only for this disposable lab. Its CVE labels
are annotations over fixture behavior, not confirmation of those advisories.
A failing check is useful beta feedback: retain the JSON and terminal output,
then report the exact source commit and image identity. Do not edit the JSON to
make it pass or use these records to authorize an actual assessment.

## Interactive MCP exercise

Use this longer path to test an agent client with human approval. The container
stays alive until you remove it, while all lab state is temporary. The command
below uses the local development build; substitute the selected immutable
candidate reference when reporting candidate acceptance.

```sh
docker run -d --name opencyber-poc-lab --no-healthcheck --network none \
  --cap-drop=ALL --security-opt no-new-privileges --read-only \
  --tmpfs /tmp --tmpfs /run --tmpfs /workspace \
  --tmpfs /root/.config --tmpfs /root/.cache \
  -e OPENCYBER_STRICT_CATALOG=1 \
  -e OPENCYBER_APPROVAL_KEY_FILE=/run/secrets/opencyber-poc.key \
  opencyber:0.5.0

docker cp scripts/poc-lab-target.py opencyber-poc-lab:/tmp/target.py
docker exec opencyber-poc-lab sh -c \
  'mkdir -p /run/secrets; head -c 48 /dev/urandom | base64 > /run/secrets/opencyber-poc.key; chmod 0600 /run/secrets/opencyber-poc.key'
docker exec -d opencyber-poc-lab python3 /tmp/target.py --port 8099

docker exec opencyber-poc-lab curl --max-time 5 -fsS http://127.0.0.1:8099/version
docker exec opencyber-poc-lab opencyber-mcp --self-test
```

The fixture response is `FixtureApp 1.4.2`. The self-test must report version
`0.5.0`, 255 tools in full mode and a matching catalog. If the fixture is still
starting, repeat its bounded `curl` check before connecting the client.

Configure the client to launch:

```sh
docker exec -i opencyber-poc-lab opencyber-mcp
```

For OpenCode V2, copy
[`opencode.poc-lab.json.example`](../integrations/opencode/opencode.poc-lab.json.example)
to a separate lab project's `opencode.json`, install the skill and agent files
as described in [INTEGRATIONS.md](INTEGRATIONS.md), then reload the client's MCP
servers. Client configuration is version-specific; keep this entry separate
from your normal `opencyber` container.

1. Ask the client to create an engagement for `127.0.0.1` and return its ID.
2. In a terminal outside the agent, set `ENGAGEMENT_ID` to that returned ID and
   authorize only the fixture techniques. This one-hour window is for the
   disposable local lab:

   ```sh
   LAB_EXPIRES=$(python3 -c 'from datetime import datetime, timedelta, timezone; print((datetime.now(timezone.utc) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"))')
   docker exec opencyber-poc-lab opencyber-poc authorize \
     --engagement "$ENGAGEMENT_ID" --authorized-by "Lab operator" \
     --reference "Owned disposable loopback fixture" --scope 127.0.0.1 \
     --valid-until "$LAB_EXPIRES" \
     --techniques version_assert,file_read_canary \
     --acknowledgement "I confirm written authorization for these targets and techniques"
   ```

3. Ask the agent to read the authorization, write a synthetic scanner artifact
   with explicitly labeled fixture CVEs, plan one fixture step, and create/render
   a `version_assert` spec targeting `http://127.0.0.1:8099`. Use one GET request
   to `/version`, `status_in` with `statuses: [200]`, and `body_regex` for
   `FixtureApp 1\.4\.2`. Ask it to lint the spec and stop. Record the returned
   chain and spec IDs. This checks fixture behavior only.
4. Inspect the rendered source, then mint a single-use approval outside the
   agent. Replace `CHAIN_ID` and `SPEC_ID` with the returned values and refresh
   `LAB_EXPIRES` if necessary:

   ```sh
   docker exec opencyber-poc-lab opencyber-poc approve \
     --engagement "$ENGAGEMENT_ID" --chain "$CHAIN_ID" --spec "$SPEC_ID" \
     --issued-by "Lab operator" --expires "$LAB_EXPIRES"
   ```

5. Supply the returned approval ID to the agent. Ask it to call `oc_poc_run`,
   inspect `oc_poc_evidence`, and verify the audit chain. A matching fixture
   assertion returns `status: verified` and `approval_consumed: true`.
6. If the request is cancelled, inspect evidence and operator status first.
   Consumption occurs before launch; interruption does not permit replay.

The lab key is intentionally readable by the trusted container-root operator.
The MCP surface provides no signing tool. Do not mount valuable credentials or
reuse the key for any real engagement.

## Source-overlay development check

When changing Python source, the same manual container can run a copied source
snapshot. It must already contain `mcp>=2.3,<3`, requests and Playwright; copying
source does not install dependencies.

```sh
docker exec opencyber-poc-lab mkdir -p /tmp/opencyber-src
docker cp src/opencyber opencyber-poc-lab:/tmp/opencyber-src/opencyber
python3 scripts/poc-lab-run.py --container opencyber-poc-lab \
  --mode source --source-path /tmp/opencyber-src \
  --json-out ../opencyber-beta-evidence/poc-source.json
```

A source-overlay result qualifies that development check, not the image's
installed package. Always repeat image-mode acceptance against the frozen
release commit and exact candidate digest. The driver defaults to a path under
`docs/verification` if `--json-out` is omitted; pass the external path explicitly.

## Cleanup and troubleshooting

Copy any evidence you want to retain before removing the manual container:

```sh
docker cp "opencyber-poc-lab:/workspace/engagements/$ENGAGEMENT_ID" \
  ../opencyber-beta-evidence/
docker rm -f opencyber-poc-lab
```

Removal destroys the temporary workspace, key, authorization and approvals.
Retain only sanitized copies intended for a bug report.

| Symptom | Check |
| --- | --- |
| MCP process exits immediately | Keep `docker exec -i`; do not allocate a TTY |
| Client cannot find the server | Use `opencyber-poc-lab` in the lab config, then reload it |
| Driver cannot import the source | Copy to the same path passed as `--source-path`, or use image mode |
| `approval_key_unavailable` | Recreate the key after container restart; confirm the key-file environment variable |
| `approval_consumed` | Inspect the earlier attempt; a new run needs a new operator approval |
| `approval_invalid` or `artifact_hash_mismatch` | Check workspace, key, chain/spec IDs and rendered source before approving again |
| `technique_not_authorized` | Use only the authorized fixture techniques; any scope change belongs to the operator |
| Deterministic driver succeeds but an agent fails | Record client/model version and tool response separately; the driver does not certify a model provider |

Release acceptance additionally requires the native platform, source,
redistribution, vulnerability and public-digest gates in [RELEASE.md](RELEASE.md).
