# Operations

Operate the 0.5.0 private pre-production beta in an authorized lab: hardened
startup, hardware exposure, egress control, storage, health, replacement and
recovery.
Use [Beta testing](BETA_TESTING.md) for first setup and a synthetic exercise.
The published private preview is `v0.5.0-private-beta.1` for Linux amd64. Import
it with the supplied helper before using the local image reference below.
The preview is unqualified; public/candidate gates and vendor/license follow-ups
remain separate. Hardware integrations are supported for beta use; device
qualification and production acceptance remain separate.

> Operations decisions here assume you are authorized to test the targets the container can reach. The harness does not enforce authorization by itself.

## Deployment shapes

| Shape | Use it when | Start with |
| --- | --- | --- |
| Managed installer | You want a verified, hardened, restartable container and a persistent volume | `install.sh` (see [INSTALL.md](INSTALL.md)) |
| Hardware-aware launcher | You need a device profile or host networking | `scripts/opencyber-run.sh` |
| Plain Docker | You need full control of flags, secrets, or orchestration | The hardened command below |
| Compose, Kubernetes, or another orchestrator | You already have scheduling, secrets, and network policy | The same flags, translated to your platform |

The image command is `sleep infinity`. The container is a host for `docker exec`, not a listening service. There is nothing to port-forward.

## Hardened runtime baseline

Complete the archive setup in the beta guide. Its file-only default uses the
`opencyber-beta` container with no network. The manual example below uses the
name `opencyber` for a networked software-lab container; use unused names and
the operator's authorized lab network:

```sh
BETA_IMAGE=opencyber:0.5.0-private-beta.1-amd64
docker run -d --name opencyber \
  --restart unless-stopped \
  --cap-drop=ALL \
  --cap-add=NET_RAW --cap-add=NET_ADMIN --cap-add=NET_BIND_SERVICE \
  --security-opt no-new-privileges \
  --read-only \
  --tmpfs /tmp --tmpfs /run \
  --tmpfs /root/.config --tmpfs /root/.cache \
  --tmpfs /root/.local/share --tmpfs /root/.nxc --tmpfs /root/.msf4 \
  -v opencyber-workspace:/workspace \
  "$BETA_IMAGE"
```

| Flag | Purpose |
| --- | --- |
| `--restart unless-stopped` | Keeps the container available across host restarts. It does not restart an unhealthy container; Docker has no health-based restart policy. |
| `--cap-drop=ALL` plus adds | `NET_RAW` for raw sockets and packet capture, `NET_ADMIN` for interface and routing changes, `NET_BIND_SERVICE` for low ports. Drop any you do not need. |
| `--security-opt no-new-privileges` | Blocks privilege gain through setuid or file capabilities. |
| `--read-only` | Protects the image filesystem from persistent change. |
| tmpfs `/tmp`, `/run` | Writable scratch space for tools that assume it exists. |
| tmpfs `/root/.local/share`, `/root/.nxc`, `/root/.msf4` | Disposable AutoRecon, NetExec and Metasploit state under the read-only root filesystem. |
| tmpfs `/root/.config`, `/root/.cache` | Required for Chromium's crashpad handler under a read-only rootfs. Without them browser tools fail with `chrome_crashpad_handler: --database is required`. |
| `-v ...:/workspace` | Persistent engagement and evidence storage. |

Do not add `--privileged`. The launcher profiles use explicit capabilities and
device flags, and privileged mode removes much of that boundary. Do not
override the user, `HOME` or `PATH`: the image expects root, `/root` and its
virtual-environment paths for Chromium, nuclei templates, analysis runtimes and
entry points.

Optional resource controls:

```sh
--memory 8g --memory-swap 8g --cpus 4 --pids-limit 4096 --ulimit nofile=65536:65536
```

The harness has no internal quotas. Without cgroup limits, a scan, hashcat, or a large browser session can consume the host.

## Hardware profiles

The launcher starts from the hardened baseline and adds only the selected
profile's exposure. Except for `blue-team`, the base capabilities include
`NET_RAW` and `NET_ADMIN`. `blue-team` refuses hardware passthrough and a
writable root filesystem.

| Profile | Added flags |
| --- | --- |
| `software` | None (default) |
| `blue-team` | `--network none`, offline mode, no added capabilities or devices |
| `usb` | `--device /dev/bus/usb` |
| `sdr` | `--device /dev/bus/usb` |
| `wifi` | `--network host`, `--cap-add SYS_RAWIO` |
| `bluetooth` | `--network host`, `--device /dev/bus/usb` |
| `nfc` | `--device /dev/bus/usb` |
| `jtag` | `--device /dev/bus/usb` |
| `serial` | `--device` for each detected `/dev/ttyUSB*`, `/dev/ttyACM*`, `/dev/ttyAMA*` |
| `can` | `--network host`, `--device /dev/bus/usb` |
| `logic` | `--device /dev/bus/usb` |
| `gps` | `--device /dev/bus/usb`, plus detected serial adapters |
| `ir` | `--device /dev/lirc0` |
| `full` | All of the above, still without `--privileged` |

```sh
./scripts/opencyber-run.sh --profile software --image "$BETA_IMAGE"
./scripts/opencyber-run.sh --profile sdr --image "$BETA_IMAGE"
./scripts/opencyber-run.sh --profile serial --device /dev/ttyUSB1 --image "$BETA_IMAGE"
./scripts/opencyber-run.sh --profile full --dry-run --image "$BETA_IMAGE"
```

An explicit `--device` that does not exist is an error. Auto-detected devices that are absent produce a warning and the launcher continues. `--network host` removes Docker network isolation; use it only for the radios and buses that need it, and apply host firewall rules. Device-specific prerequisites and udev rules are in [HARDWARE.md](HARDWARE.md).

## Egress control

By default the container has outbound connectivity through Docker's bridge. `OPENCYBER_OFFLINE=1` does not change that; it only refuses a small set of named features. See [SECURITY_MODEL.md](SECURITY_MODEL.md).

| Goal | Control |
| --- | --- |
| No outbound traffic at all | `--network none`. The container keeps loopback only; target access must come through a passed-through interface or proxy. |
| Isolated lab network | `docker network create --internal opencyber-lab` and run with `--network opencyber-lab`. An internal network has no default route. |
| Host radios and buses | `--network host` for Wi-Fi, Bluetooth, and CAN. Compensate with host firewall rules or a dedicated lab VLAN. |
| Per-destination policy | Host firewall, egress proxy, or a network policy in your orchestrator. There is no built-in allowlist. |
| Name resolution | Use the orchestrator's DNS policy. `OPENCYBER_OFFLINE=1` is not a DNS sinkhole. |

Verify from inside rather than assuming:

```sh
docker exec opencyber sh -c 'ip route; getent hosts example.com || true'
```

Some tools honor `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY`; Python `requests` does by default. That is convenience, not an enforcement mechanism, and not every catalog executable honors it.

## Workspace layout

The workspace volume is mounted at `/workspace` (or `OPENCYBER_WORKSPACE`). Engagements are server-generated directories:

```text
/workspace/
  engagements/
    eng_YYYYMMDD_<32 hex>/
      engagement.json
      artifacts/                  # tool output and firmware reports
      evidence/                   # API audit evidence
      findings/                   # structured finding reports
      .opencyber/
        audit/events.jsonl        # hash-chained audit trail
        http-sessions/*.json      # workbench session state
        http-sessions/*.history.jsonl
        browser/<session_id>/network.jsonl
      hardware/serial/<session_id>.jsonl
```

| Path | Contents | Sensitive |
| --- | --- | --- |
| `engagement.json` | Name, targets, objective, creation time | Yes, target metadata |
| `artifacts/` | Tool-generated files, firmware reports | Usually |
| `evidence/` | API audit and fuzz evidence | Yes, often credentials |
| `findings/` | Markdown finding reports | Yes |
| `.opencyber/audit/events.jsonl` | Audit chain | Yes, redacted heuristically |
| `.opencyber/http-sessions/` | Headers, cookies, bodies, match/replace rules | Yes, often live credentials |
| `.opencyber/browser/` | Network metadata | Yes |
| `hardware/serial/` | Raw UART transcripts | Yes, may contain boot secrets |

Executable stdout and stderr are returned to the MCP client. Result retention
defaults to a digest index; full payload retention is opt-in and capped.
Byte counts are also recorded in executor audit events. Save important output
as engagement files and include those files explicitly in evidence exports.

## Backup

Stop the container first so the audit chain and JSONL files are not changing during the copy.

```sh
docker stop opencyber

docker run --rm \
  --entrypoint tar \
  -v opencyber-workspace:/src:ro \
  -v "$PWD":/backup \
  "$BETA_IMAGE" \
  -czf "/backup/opencyber-workspace-$(date -u +%Y%m%dT%H%M%SZ).tar.gz" -C /src .

docker start opencyber
```

The backup contains unredacted evidence and may contain live credentials. Encrypt it at rest, restrict who can read it, and apply the same retention policy as the original.

## Restore

Restore into a new volume, inspect it, then point the container at that volume.

```sh
docker volume create opencyber-workspace-restored

docker run --rm \
  --entrypoint tar \
  -v opencyber-workspace-restored:/dst \
  -v "$PWD":/backup \
  "$BETA_IMAGE" \
  -xzf /backup/opencyber-workspace-20261025T120000Z.tar.gz -C /dst
```

Run a container against the restored volume and verify the audit chains before using it:

```sh
docker run -d --name opencyber-restore \
  --cap-drop=ALL --cap-add=NET_RAW --cap-add=NET_ADMIN --cap-add=NET_BIND_SERVICE \
  --security-opt no-new-privileges \
  --read-only --tmpfs /tmp --tmpfs /run \
  --tmpfs /root/.config --tmpfs /root/.cache \
  --tmpfs /root/.local/share --tmpfs /root/.nxc --tmpfs /root/.msf4 \
  -v opencyber-workspace-restored:/workspace \
  "$BETA_IMAGE"

docker exec opencyber-restore opencyber-mcp --self-test
```

Then call `oc_engagement_list` and `oc_audit_verify` for each engagement through your MCP client. A restored volume created outside `install.sh` does not carry the installer's management label, so the installer will use it but `--uninstall --purge-workspace` will refuse to delete it. Set `OPENCYBER_VOLUME_NAME=opencyber-workspace-restored` when running the installer if that is the volume you want.

## Retention and deletion

- There is no automatic engagement retention or expiry. The audit log grows with every call; HTTP history and browser network logs grow with every request and event.
- Tool result content is not stored by default. `OPENCYBER_RESULT_RETENTION=digest` keeps an index entry per result (id, tool, digest, size, time); `full` stores the redacted payload under `<engagement>/.opencyber/results/`, capped at 1 MiB per record and pruned at 500 records / 32 MiB. Treat retained results as sensitive engagement data.
- Define retention per engagement, not per container. Archive the entire engagement directory so the audit chain stays with the artifacts it describes.
- `oc_audit_log` returns at most 1000 events per call (`limit` must be between 1 and 1000), with `offset` for paging, and examines at most 5000 matching events. That is a read API bound, not a retention mechanism.
- There is no engagement delete tool. Remove engagement directories through the workspace volume or `oc_workspace_delete` for files that are safe to delete. Do not delete `.opencyber/audit/events.jsonl` if you still claim the engagement's evidence is intact.
- `install.sh --uninstall --purge-workspace` removes the managed volume and therefore every engagement, artifact, and audit log in it.
- `docker volume rm` does not guarantee secure erasure of the underlying storage. If destruction must be provable, use encrypted storage and destroy the key.

## Credential rotation

- Target passwords, API tokens, cookies, and session identifiers can appear in HTTP history, browser state, API evidence, serial transcripts, and audit arguments. Rotate them after the engagement, and immediately if evidence is copied outside the trusted boundary.
- The server has no secret store. Credentials arrive through the environment, tool arguments, files, or captured web state.
- Executor children inherit the server environment except for the documented
  signing-related prefixes; explicit environment overrides can still expose
  credentials. This scrubbing limits accidental disclosure and does not
  isolate keys from trusted container-root code. Recreate the container to
  change its configured environment; `docker restart` reuses that environment.
- Do not bake long-lived credentials into the image or commit them to the workspace. Prefer short-lived, per-engagement credentials.
- Host Docker access is equivalent to host root. Rotate any credential that was reachable from a host you believe was compromised.

## Health checks and monitoring

The image defines a Docker healthcheck:

```text
opencyber-doctor --quiet
interval 30s, timeout 15s, start period 20s, retries 3
```

`opencyber-doctor` exits 0 only when the catalog executables, nuclei templates, wordlists, required offline assets, asset manifest, agent tools, and analysis runtimes are all healthy. `--quiet` prints only problems, to stderr.

```sh
docker inspect --format '{{json .State.Health}}' opencyber
docker exec opencyber opencyber-doctor
docker exec opencyber opencyber-doctor --json
docker exec opencyber opencyber-mcp --self-test
docker exec opencyber opencyber-assets --verify --json
```

| Signal | Covers | Does not cover |
| --- | --- | --- |
| Docker healthcheck | Image self-consistency and readiness | Hardware visibility, target reachability, network policy, audit validity |
| `opencyber-doctor --json` | Full readiness report with `problems[]` | Whether a passed-through device is usable |
| `opencyber-mcp --self-test` | Required executables resolve; optional omissions and tool counts; recorded catalog identity | Actual stdio exchange, offline assets, browser operation, hardware |
| `opencyber-assets --verify` | Required assets match the build manifest | Optional asset content, CVE database completeness |
| `oc_hardware_readiness` | Tooling plus visible devices per domain | Whether the host permits transmission or the device works |
| `oc_audit_verify` | Audit chain integrity per engagement | Whether an event was never written at all |

Logs: the MCP client owns the stdout/stderr streams of the server it starts
with `docker exec -i`. Read the client's MCP server log for server stderr.
`docker logs opencyber` captures the container's main process, normally the
idle host process, rather than separate exec sessions. Do not add a TTY to an
MCP session. Use `--self-test` for a one-shot diagnostic, and
`OPENCYBER_STRICT_CATALOG=1` when catalog mismatch must fail the command.

There is no metrics endpoint, structured log pipeline, telemetry, or remote management API. Collect and ship logs with your container platform.

Audit timestamps are generated in UTC from the container clock. Keep the host clock synchronized; timestamps are not signed or externally witnessed.

## Replace or upgrade a beta container

The preview image and `c120197` source are frozen. A replacement uses a new
release/tag and its own checksums; never rebuild or overwrite the published
preview. Back up evidence and stop the old container before intentionally
reusing a workspace with a replacement. The preview launcher is separate from
`install.sh`; follow [beta setup](BETA_TESTING.md) for its startup and cleanup.

The following installer procedure is for a future qualified registry candidate.
Keep that candidate's source, platform digest and evidence together. There is
no earlier public version to recommend as a rollback target.

1. Back up the workspace and export any evidence you need.
2. Pull or import the new image and run its gates before replacing anything:

   ```sh
   docker run --rm --entrypoint opencyber-doctor "$BETA_IMAGE"
   docker run --rm --entrypoint opencyber-mcp "$BETA_IMAGE" --self-test
   ```

3. Re-run the installer with the new version or digest:

   ```sh
   OPENCYBER_IMAGE=ghcr.io/mitkox-dev/opencyber-beta-candidates \
   bash install.sh --version 0.5.0 --digest BETA_PLATFORM_DIGEST
   ```

The installer preserves the current managed container as
`<name>-rollback-<epoch>` while it starts and self-tests the replacement. If
installation fails, the trap attempts to restore the previous container. If it
succeeds, the backup container is removed. The workspace volume is preserved
and is not migrated by the installer.

Set the private image repository explicitly on every installer invocation.
Replace `BETA_PLATFORM_DIGEST` with the complete `sha256:` value from the
maintainer's candidate record. Record that value with your test report.
Repository access alone does not grant private package access; authenticate to
GHCR before an online install.

For airgapped hosts, use the export/verify/import flow in [AIRGAP.md](AIRGAP.md) and keep the previous image until the new doctor passes.

Engagement directories carry `schema_version: 1` in `engagement.json`. A downgrade across a future schema change may not understand newer data; copy evidence out before downgrading.

## Rollback

There is no separate rollback command.

- A failed installer replacement attempts to restore the previous managed
  container automatically. Inspect its state if the run was interrupted.
- After a successful replacement, reinstall a previously retained version and
  matching digest only if its data compatibility is known. During private beta,
  consult the maintainer before selecting a previous candidate. There is no
  earlier public release to recommend as a downgrade target.

- The workspace volume is untouched. Process-scoped browser and serial sessions are gone on any restart; persisted network logs and serial transcripts remain.
- Keep the image digest and its SBOM/attestation record for every beta run;
  retain the preceding accepted image when testing an upgrade.

## Incident response

1. **Contain.** Stop the container. For `--network host` profiles, also revert the host-side changes the tools made: monitor-mode interfaces, CAN link state, firewall rules, and any host services started for the engagement. If the container had `--privileged` or broad device access, treat the host as potentially compromised.
2. **Preserve before repairing.** Do not restart, rebuild, or "clean up" first. Snapshot the workspace volume, `docker inspect` the container, save `docker logs`, and record the image digest and configuration.
3. **Verify the audit chain.** Run `oc_audit_verify` against each affected engagement from a copy of the evidence. Record `events`, `first_invalid_seq`, `error`, and `last_hash`. A valid chain does not prove completeness; a broken chain means the trail cannot be treated as intact.
4. **Determine exposure.** Review the audit log, HTTP history, browser network log, API evidence, serial transcripts, workspace files, and the container's process and connection snapshots. Identify credentials, targets, and data that were reachable.
5. **Rotate.** Invalidate and replace target credentials, API tokens, cookies, and any host secrets present in the container environment. Assume secrets in the environment reached every child process.
6. **Rebuild.** Start from a known-good image digest and a fresh container. Restore only the evidence you intentionally preserved. Do not reuse a container in which root-level compromise is suspected.
7. **Report.** Follow [SECURITY.md](../SECURITY.md) for a vulnerability in the harness. Notify affected target owners and your own security team according to your engagement agreement and legal requirements.
8. **Review.** Decide whether the triggering condition was a harness limit, a configuration gap, or an authorization failure, and change the deployment controls accordingly.

There is no remote kill switch, callback, telemetry channel, or vendor-side disable. Response is entirely operator-driven.

## Routine operations checklist

| Cadence | Check |
| --- | --- |
| Every start | Container health is `healthy`; `opencyber-doctor` exits 0; workspace volume mounted at the expected path |
| Every engagement | Targets recorded honestly at creation; scope enforcement on where appropriate; audit verification before evidence export |
| Daily or per shift | Disk usage of the workspace volume; container logs for repeated tool failures; hardware readiness if devices are in use |
| Weekly | Backup or archive completed engagements; review retention and credential age; confirm host egress policy |
| Per release | Read [RELEASE.md](RELEASE.md), pin the digest, verify the attestation, and run the doctor before replacing a working container |
| On incident | Preserve, verify, rotate, rebuild, report; do not repair the evidence in place |

## Related documents

- [CONFIGURATION.md](CONFIGURATION.md): every environment variable and its scope.
- [SECURITY_MODEL.md](SECURITY_MODEL.md): trust boundary, scope matrix, audit guarantees, residual risks.
- [AIRGAP.md](AIRGAP.md): offline assets, transfer, and hard isolation.
- [HARDWARE.md](HARDWARE.md): device passthrough, udev, serial sessions.
- [TROUBLESHOOTING.md](TROUBLESHOOTING.md): symptom-driven diagnosis.
