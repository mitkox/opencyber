# Offline blue-team investigations

Use this workflow with the published Linux amd64 `v0.5.0-private-beta.1`
preview. Complete [beta setup](BETA_TESTING.md) to download the private release,
verify/import its split image and extract the frozen `c120197` source snapshot.
The preview remains unqualified and retains the vendor/license follow-ups in
its `KNOWN_ISSUES.md`. Hardware is unnecessary for these supplied-artifact cases.

OpenCyber analyzes supplied artifacts inside an engagement. It does not acquire
host memory, monitor a host, or act as an EDR or SIEM. `oc_process_snapshot`
reports the running container's own processes and connections.

## Start an isolated case

```sh
# From the extracted source-c120197/opencyber directory, after archive import.
BETA_IMAGE=opencyber:0.5.0-private-beta.1-amd64
scripts/opencyber-run.sh --profile blue-team --offline \
  --name opencyber-blue-team --volume opencyber-blue-team-workspace \
  --image "$BETA_IMAGE"
docker exec opencyber-blue-team opencyber-doctor --json
docker exec -e OPENCYBER_STRICT_CATALOG=1 opencyber-blue-team opencyber-mcp --self-test
```

Configure the MCP client to launch
`docker exec -i opencyber-blue-team opencyber-mcp`; use the client-specific
format in [MCP integration](MCP_INTEGRATION.md). The separate container and
volume names keep this case apart from an installer-managed beta session.
Choose unused container and volume names for a new case. The preview uses
repository release assets and local image loading, so this workflow needs no
registry credentials. The separate `opencyber-blue-team` names keep this case
apart from the initial `opencyber-beta` session.

The blue-team profile forces `--network none`, `--cap-drop=ALL`, a read-only
root filesystem, and offline mode. Device passthrough and `--no-read-only` are
rejected. The engagement volume remains writable. Existing assessment and
hardware profiles retain their capabilities.

Create a case through the MCP client:

```text
oc_engagement_create(name="Owned lab investigation", targets=["192.0.2.0/24"], objective="Investigate supplied synthetic artifacts")
```

Use the returned engagement identifier. Copy selected files into that case
from the host; substitute its actual identifier in the destination:

```sh
docker cp ./capture.pcap opencyber-blue-team:/workspace/engagements/ENGAGEMENT_ID/artifacts/capture.pcap
docker cp ./events.jsonl opencyber-blue-team:/workspace/engagements/ENGAGEMENT_ID/artifacts/events.jsonl
```

Host originals remain unmounted. Analyze the engagement copies using relative
paths. With a custom workspace, use its mount destination in these commands.
`oc_workspace_write` accepts UTF-8 text, so use `docker cp` for binary evidence.

## Analyze and preserve results

```text
oc_file_triage(engagement_id="eng_...", path="artifacts/events.jsonl")
oc_log_timeline(engagement_id="eng_...", path="artifacts/events.jsonl", format="jsonl", timestamp_field="timestamp")
oc_pcap_triage(engagement_id="eng_...", path="artifacts/capture.pcap")
```

Logs support JSONL/NDJSON and plain text with an ISO-8601 timestamp prefix.
For example, a synthetic JSONL record is:

```json
{"timestamp":"2026-10-25T12:00:00Z","message":"Lab connection from 192.0.2.1"}
```

UTC normalization retains raw timestamps, fractional precision, and source line
or packet locations. Naive timestamps require an explicit timezone such as
`timezone="UTC"`. Missing, invalid, ambiguous, or nonexistent times are reported
without inventing dates. Malformed records remain visible in report errors.

Each call hashes the complete file. Content analysis defaults to 16 MiB;
timelines and captures default to 10,000 encountered records or packets. Override
`max_bytes`, `max_records`, or `max_packets` explicitly when needed. Printable
string and subprocess-output limits are also recorded when reached. Check
`complete`, `incomplete_reasons`, and the persisted report; a complete hash does
not prove complete analysis. No input is executed, replayed, or modified.

Results return concise summaries and JSON report paths under `evidence/triage/`.
Reports include source SHA-256, size, tool version, parameters and source
locations. A successful call records its report in the audit trail; an audit
write failure fails the call and removes its output.

The concise result returns `report_path`; read that exact path with
`oc_workspace_read` to inspect individual indicators, events or packets.
For the synthetic record above, a timeline should contain one event at
`2026-10-25T12:00:00Z`. A result that reports incomplete analysis needs review
before drawing conclusions.

## Export and independently verify

Select the original copies and specific report paths returned above:

```text
oc_evidence_export(engagement_id="eng_...", paths=["artifacts/capture.pcap", "artifacts/events.jsonl", "evidence/triage/RETURNED_REPORT.json"])
oc_evidence_verify(engagement_id="eng_...", path="evidence/RETURNED_BUNDLE.tar.gz", expected_sha256="INDEPENDENTLY_RETAINED_SHA256")
```

Bundles contain only selected files, engagement metadata, an immutable audit
snapshot, and a versioned manifest with member sizes and SHA-256 hashes.
Reports and session credentials are not discovered automatically. Retain the
returned archive hash separately before transferring the bundle.

Verification streams the archive without extracting files and rejects unsafe
paths, links, duplicate, missing or extra members, mismatched hashes, and invalid
audit heads. Export fails when its audit snapshot is missing or invalid. Later
live audit entries do not change the exported snapshot.

The chain and manifest establish internal consistency. They cannot prove the
authenticity or completeness of evidence against an operator who can rewrite
the entire container workspace. Preserve an external hash or trusted audit head
for that comparison. Bundles and reports remain unredacted sensitive artifacts;
the release pipeline never uploads an engagement workspace.

## Stop and retain the case

The launcher does not create an installer-managed container. Stop it or remove
only the container when finished:

```sh
docker stop opencyber-blue-team
docker rm opencyber-blue-team
```

The `opencyber-blue-team-workspace` volume remains, including the evidence and
audit trail. Reuse that volume explicitly when restarting the case. Copy any
evidence you need before intentionally deleting a volume. For a software defect,
follow the [beta report format](BETA_TESTING.md#4-send-a-useful-report) with a
synthetic reproduction instead of uploading the case.
