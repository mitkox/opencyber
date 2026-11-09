# Troubleshooting

Diagnosis for the 0.5.0 private pre-production beta: startup, doctor, assets,
browser, hardware, audit, scope, stdio, timeout and installer failures. Start with
[Beta testing](BETA_TESTING.md) for the minimal workflow and report format.

## First response

Collect these before changing anything:

```sh
docker ps -a --filter name=opencyber
docker inspect --format '{{json .State.Health}}' opencyber-beta
docker exec opencyber-beta opencyber-doctor --json
docker exec -e OPENCYBER_STRICT_CATALOG=1 opencyber-beta opencyber-mcp --self-test
docker exec opencyber-beta opencyber-assets --verify --json
docker exec opencyber-beta opencyber-hardware --inventory --json
docker logs --tail 200 opencyber-beta
```

Redact credentials, cookies, and target data before sharing this output.
Doctor and hardware inventory can contain device serial numbers and paths.
Hardware inventory is useful only for a device-related report. MCP server
stderr belongs to the client's server log; `docker logs` does not capture a
separate `docker exec` session's stderr.

The current delivery is the private [v0.5.0-private-beta.1 release](https://github.com/mitkox/opencyber/releases/tag/v0.5.0-private-beta.1).
Repository **Read** access includes its assets; this delivery needs no GHCR
permission. Follow [Beta testing](BETA_TESTING.md) to download all 38 assets,
transfer the complete directory and run `bash beta-import.sh`. The helper
verifies the checksums and image identity before loading
`opencyber:0.5.0-private-beta.1-amd64`. The examples here use the beta guide's
container name, `opencyber-beta`; substitute your own name if different.

The preview is unqualified. Vendor and license reviews remain open; private
access does not resolve those obligations. Keep the supplied `KNOWN_ISSUES.md`
with the bundle.

## Download and import failures

| Symptom | Action |
| --- | --- |
| Release returns 404 | Accept the private repository invitation and authenticate `gh` with the invited GitHub account. Ask the maintainer to check repository Read access. Never send your token. |
| Missing asset or checksum mismatch | Download the complete release into a fresh directory and transfer every file. Run `bash beta-import.sh --verify-only` before retrying the import. Do not edit checksums or combine files from different releases. |
| Insufficient disk space | Check free space on both the transfer filesystem and Docker's storage filesystem; the bundle, assembled archives and loaded layers coexist during import. |
| Existing assembled archive or image tag | Follow the helper's refusal. Use a fresh bundle directory and inspect the existing image before removing anything. Do not overwrite an image used by another engagement. |
| Existing container or workspace name | Choose fresh container and volume names in the beta launch command. Preserve existing workspace volumes and evidence. |
| Helper passes but no container appears | The helper imports and tests the image; it does not create the persistent beta container. Continue with the launch step in the beta guide. |

## Doctor reports degraded

`opencyber-doctor` exits 1 whenever `status` is `degraded`. Read `problems[]` in the JSON report rather than guessing.

| Problem text | Meaning | Action |
| --- | --- | --- |
| `N catalog executables missing` | A required executable integration is not on `PATH`. | Confirm you are running the image, not a source install. Check the release and image identity and `missing_required_tools`; unavailable optional adapters are listed separately. |
| `no nuclei templates installed` | The template store is absent or empty. | See [Nuclei template store](#nuclei-template-store). |
| `baseline dictionary missing` | `/usr/share/wordlists/opencyber-keyboard-patterns.txt` is absent or empty. | Restore the supplied image and verify its asset manifest. RockYou is an optional operator-supplied corpus. |
| `seclists missing` | `/usr/share/seclists` is absent. | Restore the image. A bind mount over the path can hide it. |
| `required offline assets missing: ...` | An asset is below its minimum count or size. | Run `opencyber-assets --json` and inspect `missing_required`. Restore or rebuild the image. |
| `offline asset manifest does not match the image` | Counts, sizes, or hashes differ from the build manifest. | See [Asset manifest mismatch](#asset-manifest-mismatch). |
| `rg missing`, `yq missing`, `jq missing` | Agent shell tooling is absent. | Restore the image; these are build-gated. A source install will not have them. |
| `angr import unavailable`, `volatility3 import unavailable` | The analysis virtual environment is not visible to the main venv. | Restore the image. A source install must install these separately or omit binary analysis. |
| Usage error or traceback instead of a report | The CLI could not start. | Check that the installed package version matches the image and that `PATH` was not overridden. |

A bare source checkout is expected to be degraded. CI asserts that the doctor fails closed on a bare host. Do not disable the check or rewrite the report to make a broken image pass.

Hardware `tooling_ready` domains are not doctor problems. A software-only container without radios is healthy.

## Missing executables or tools

1. Confirm the command runs inside the container, not on the host:

   ```sh
   docker exec opencyber-beta sh -c 'command -v curl; command -v nuclei; command -v chromium'
   ```

2. Confirm `PATH` includes the image's virtual environments. Do not override `PATH` with `docker run -e` or a shell wrapper; the image sets `/opt/opencyber-venv/bin`, the analysis venv, and the tool venvs.
3. Run `opencyber-mcp --self-test` and read `missing_required_tools` and `missing_optional_tools` separately.
4. From MCP, run `oc_catalog(missing_only=true)` to see which tools the catalog considers unavailable.
5. A source install (`pip install -e .`) provides the Python package and five console scripts. It does not install the external toolchain, Chromium or offline assets. Use the published container preview for beta runtime tests.
6. A registered optional adapter can be intentionally omitted from the distributed image. Read its availability reason and remediation in `oc_catalog`. If a qualified candidate is missing a **required** executable, record the image digest and report it; do not patch the container and call it verified.

`--no-read-only` does not install software. It only makes the rootfs writable, which is a diagnostic escape hatch.

## Architecture mismatch

The published preview contains **Linux amd64 only**. Use native amd64 for
beta testing; arm64 and emulated operation are unqualified. A future qualified
release requires separate native amd64 and arm64 acceptance.

```sh
docker info --format '{{.Architecture}}'
docker image inspect opencyber:0.5.0-private-beta.1-amd64 \
  --format '{{.Os}}/{{.Architecture}}'
```

An `exec format error` usually means an image/host architecture mismatch. Do
not relabel the archive as arm64 or describe QEMU execution as native
qualification. `install.sh` is a separate future qualified-image path; the
current archive preview uses `beta-import.sh` and the launcher.

## Read-only rootfs and Chromium crashpad

Symptom: every browser tool fails, and the container log or tool error contains:

```text
chrome_crashpad_handler: --database is required
```

Cause: Chromium's crashpad handler needs writable `/root/.config` and `/root/.cache`, and the rootfs is read-only.

Fix: add both tmpfs mounts.

```sh
--read-only --tmpfs /tmp --tmpfs /run \
--tmpfs /root/.config --tmpfs /root/.cache
```

`install.sh` and `scripts/opencyber-run.sh` do this by default. If you wrote your own `docker run`, copy the pair exactly.

Related failures:

| Symptom | Cause | Action |
| --- | --- | --- |
| Browser fails only when `HOME` or `--user` is changed | Chromium and nuclei expect `/root`; a different home changes cache and template paths. | Run as the image's default root user and do not override `HOME`. |
| `Read-only file system` when a tool writes to `/root` or `/usr` | The rootfs is read-only and the path is not a tmpfs or volume. | Write to `/workspace` or `/tmp`. Use `--no-read-only` only for diagnosis. |
| Container runs out of memory during browser work | tmpfs is memory-backed and Chromium is large. | Set a container memory limit with headroom or reduce concurrent browser sessions. |

## Nuclei template store

The image installs templates at `/root/.local/nuclei-templates` and symlinks `/usr/share/nuclei-templates` to it. Nuclei expects the store to be a real directory; a symlink at the store path makes it list zero templates and turns scans into no-ops.

Checks:

```sh
docker exec opencyber-beta sh -c 'ls -ld /root/.local/nuclei-templates /usr/share/nuclei-templates'
docker exec opencyber-beta sh -c 'nuclei -tl -silent 2>/dev/null | wc -l'
docker exec opencyber-beta opencyber-doctor --json | jq '.nuclei_templates'
```

| Symptom | Cause | Action |
| --- | --- | --- |
| Doctor reports `no nuclei templates installed` | Store missing, empty, or `HOME` changed. | Confirm `/root/.local/nuclei-templates` exists and contains `.yaml` files. Restore the image if it is empty. |
| `nuclei -tl` lists zero templates | The path is a symlink or was replaced by an empty mount. | Remove the bind mount or rebuild the image; do not replace the store directory with a symlink. |
| `nuclei -update-templates` fails | The rootfs is read-only. | Keep the beta image immutable. Rebuild or extend the image, then regenerate the asset manifest intentionally; the result is a different development artifact. |
| Scans run but find nothing | Empty store, wrong template filters, or target unreachable. | Count templates first, then review the argv and target. |
| Doctor reports a manifest mismatch after an update | The store changed relative to the build manifest. | Rebuild the image, or run `opencyber-assets --write` only if you own the change and understand that verification is now based on the new state. |

The build runs `nuclei -tl` once before recording the manifest so the first-run cache files are included. Re-running `nuclei -tl` in a writable container can create additional cache files; on a read-only rootfs it should use the primed state.

## Asset manifest mismatch

`opencyber-assets --verify` compares measured required assets with the manifest at `OPENCYBER_ASSET_MANIFEST` (default `/usr/share/opencyber/asset-manifest.json`).

```sh
docker exec opencyber-beta opencyber-assets --verify --json
docker exec opencyber-beta opencyber-assets --verify --deep --json   # content hashes, slow
```

| Result | Meaning | Action |
| --- | --- | --- |
| `available: false` | No manifest at the configured path. | Verify you did not override `OPENCYBER_ASSET_MANIFEST`; restore the image. `--verify` exits 1, but the doctor does not flag a missing manifest. |
| `valid: false` with `count` or `bytes` mismatches | A required asset was truncated, replaced, or hidden by a mount. | Remove the mount or restore the image. Do not write a new manifest to silence it. |
| `valid: false` with a `sha256` mismatch only under `--deep` | Content changed while count and size happened to match. | Restore the image or investigate what modified the store. |
| Optional asset missing | Optional entries are ignored by verification. | No action unless the feature is needed. |
| `OPENCYBER_ASSET_MANIFEST` change has no effect | The path is captured at import. | Set it before starting a new server process, not inside a running one. |

`opencyber-assets --write PATH` exits 0 on a successful write and records what it measures, including missing required assets. Using it to make verification pass hides supply-chain and storage failures. Only regenerate a manifest as part of an intentional image or asset-store build.

## Airgap transfer failures

| Symptom | Cause | Action |
| --- | --- | --- |
| `image is not present locally` | The export host has no image under that exact reference. | Build or pull the image, and pass the exact tag or digest to `--image`. |
| `archive already exists ... (use --force to replace)` | A previous export is in the output directory. | Choose a new directory or pass `--force` after confirming the old archive is expendable. |
| `checksum file is missing` or `archive is missing` | The bundle was copied incompletely. | Copy the entire export directory, including `release.json` and `.sha256`. |
| `sha256sum -c` mismatch | Corruption in transit or a modified archive. | Re-copy from the source. Do not import a failed checksum. |
| `doctor failed after import; do not deploy this image` | The imported image is incomplete or degraded. | Treat the bundle or image as bad, re-export, and re-verify. Do not override the check. |
| `offline install requires the image to be imported first` | `install.sh --offline` cannot pull. | Run `scripts/opencyber-airgap.sh import` first, then install with the same version. |
| Image label mismatch during offline install | The imported tag does not match the requested version. | Import the correct version or pass the matching `--version`. |
| `--verify-attestation requires network access and cannot be combined with --offline` | Attestation verification needs GitHub. | Verify on the connected side before transfer, then use `--offline` on the far side. |
| `oc_cve_lookup` fails offline despite a mounted database | The path is a symlink, unreadable, or not at `OPENCYBER_CVE_DB`. | Mount a regular file read-only at the configured path; symlinks are rejected. |
| Native HTTP tools still reach the network offline | `OPENCYBER_OFFLINE=1` is not an egress firewall. | Use `--network none`, an internal network, or host firewall rules. |

`verify` proves that the archive matches the checksum recorded beside it. It does not prove provenance: anyone who can replace both can produce a consistent bundle. Compare the recorded digest with the independently retained candidate record and verify any supplied attestation or cosign signature on a connected host. See [AIRGAP.md](AIRGAP.md).

## Source install reports missing tools

This is expected. A source install provides the Python package, five console
scripts and test code. It does not provide the Kali toolchain, Chromium,
offline assets or hardware binaries. Doctor reports the gaps and exits 1; CI
uses that behavior as a test.

Use the container image for assessments. Use a source install to:

- run `python -m unittest discover -s tests -v`;
- change the MCP contract and run `opencyber-mcp --self-test` against the Python package;
- run `python -m opencyber.cve_index` on a connected host;
- develop documentation and scripts.

If a Python-native tool fails on a source install, check that `playwright`, `requests`, and `mcp>=2.3,<3` are installed. `oc_browser_*` also needs a Chromium binary that the Python package does not install.

## Devices, serial, and monitor mode

Hardware integrations are supported for beta use in 0.5.0. Readiness and visibility do not
qualify a physical device. Include the device model/firmware, architecture,
image digest, launcher flags and observed operation in a hardware report.

Start with the two readiness views:

```sh
docker exec opencyber-beta opencyber-hardware
docker exec opencyber-beta opencyber-hardware --inventory --json
```

`accessible` is the field that matters for USB devices. sysfs can list a device that the container cannot open.

| Symptom | Check | Fix |
| --- | --- | --- |
| Readiness says `tooling_ready` for a domain | The tools are installed but no matching device is visible. | Pass the device or host network the domain needs. See [HARDWARE.md](HARDWARE.md). |
| SDR tools report no device | `/dev/bus/usb` not passed, permissions, or another process holds the device. | Add `--device /dev/bus/usb`; stop the competing process; check host udev rules. |
| RTL-SDR tunes but produces no samples | A DVB-T kernel driver is bound on the host. | Blacklist the DVB driver on the host and replug the device. |
| Wi-Fi interface missing | The host PHY is not in the container's network namespace. | Use `--network host` plus the `wifi` profile's `SYS_RAWIO`; keep the base `NET_ADMIN` and `NET_RAW`. |
| Monitor mode or injection fails | The adapter or firmware does not support it, or NetworkManager owns the interface. | Check `iw phy` capabilities; unmanage the interface on the host; try another adapter. |
| Bluetooth scan finds nothing | Host Bluetooth stack or D-Bus is not reachable. | Use `--network host`; test `btmgmt` or `hcitool`; use an Ubertooth for passive BLE capture. |
| CAN interface missing | Host network namespace, `NET_ADMIN`, or adapter driver. | Use `--network host` and `--device /dev/bus/usb`; bring the link up inside the container with `oc_ip`. |
| GPS device missing | USB or serial device not passed. | Use the `gps` profile or pass `/dev/ttyUSB0` explicitly. |
| IR device missing | `/dev/lirc0` not passed. | Use the `ir` profile or add `--device /dev/lirc0`. |
| `oc_serial_open` rejects the path | The resolved path is outside the serial allowlist, is not a character device, or does not exist in the container. | Pass the real device; check the resolved path. `/dev/pts/*` requires `OPENCYBER_ALLOW_PTY=1` exactly. |
| Serial read times out | Wrong baud rate, parity, flow control, or TX/RX wiring. | Use a supported baud rate (default 115200); verify with a known-good console. |
| Serial device is busy | Another process, host service, or container owns it. | Stop the competing process; do not open the same UART from two sessions. |
| Launcher error: `device does not exist on this host` | An explicit `--device` path is absent. | Fix the path or omit the flag and rely on auto-detection. |
| No hardware after adding `--privileged` | Privileged mode does not pass a missing device node. | Remove `--privileged`; pass the specific device or USB bus. |

## Audit verification failure

`oc_audit_verify` returns a result such as:

```json
{
  "valid": false,
  "events": 42,
  "first_invalid_seq": 17,
  "error": "line 18: prev_hash does not match the previous record"
}
```

| Error | Meaning |
| --- | --- |
| `expected seq N, found M` | A record was removed, inserted, or reordered. |
| `prev_hash does not match the previous record` | The chain is broken at that point. |
| `record hash does not match its contents` | A record was edited after it was written. |
| `invalid JSON` or `record is not an object` | The file was truncated, corrupted, or hand-edited. |
| `audit trail is empty` with `valid: true` | No events have been written yet. Absence of events is not proof that no work occurred. |

Actions:

1. Stop writing to the engagement.
2. Copy the entire engagement directory, including `.opencyber/audit/events.jsonl` and all evidence, before attempting repair.
3. Treat the trail as compromised from `first_invalid_seq` onward. Do not rewrite the file to "fix" the hash chain; that destroys the only record of the inconsistency.
4. Correlate the surviving range with HTTP history, browser logs, serial transcripts, and workspace files. Missing audit events do not mean the actions did not happen.
5. Record `last_hash` from a valid verification in an external system if you need a witness outside the container.

Context:

- The chain is tamper-evident, not tamper-proof. Root inside the container can rewrite the whole file and recompute the chain. A valid chain is not proof of completeness.
- Many native call sites use `safe_record()`, which silently ignores write failures. An operation can succeed without an audit event.
- `OPENCYBER_AUDIT=0` suppresses executor events only. Setting it does not corrupt the chain, but it creates gaps in tool-execution coverage.
- `OPENCYBER_AUDIT_REQUIRED=1` makes executor audit failures fatal. It does not make workspace, HTTP, browser, API, or hardware writes reliable.
- `oc_audit_log` reads at most 1000 events per call; use `offset` to page. A truncated read is not a truncated log.

## Scope refusal

Typical error:

```text
scope enforcement refused nmap: out-of-scope network target(s): 10.0.0.9
```

or, for arbitrary code:

```text
scope enforcement refused bash: bash executes arbitrary code and cannot be scope-checked;
set OPENCYBER_ALLOW_UNSCOPED_EXECUTION=1 to allow it under enforcement
```

| Cause | Fix |
| --- | --- |
| The engagement `targets` do not include the host. | Create a new engagement with the correct target list. Engagements have no target-update tool. |
| The target is a subdomain of a listed domain. | A bare domain target already covers subdomains; verify spelling and trailing dots. |
| The target is an IP inside a CIDR. | List the CIDR, not only individual addresses. |
| The target is dynamic or assembled at runtime. | Scope enforcement cannot see it. Use network policy or an HTTP workbench session with the right `scope_hosts`. |
| An executable needs an out-of-scope resolver, update server, or API. | Do not widen scope casually; use an internal mirror or accept that the tool cannot run under enforcement. |
| `oc_bash` or `oc_python` is refused. | Set `OPENCYBER_ALLOW_UNSCOPED_EXECUTION=1` only if you accept unrestricted execution, or move the work to catalog tools. |
| The HTTP workbench refuses a URL. | Update the session with `oc_http_session_update(scope_hosts=...)`; redirects are checked against the same scope. |

Remember the boundary: `OPENCYBER_ENFORCE_SCOPE` covers executable-backed calls and native HTTP/API request and redirect hosts. The workbench also applies its own session scope. Browser tools remain outside engagement enforcement. A scope refusal here does not prove the harness cannot reach the target through another path. See [SECURITY_MODEL.md](SECURITY_MODEL.md).

## CVE-chain PoC refusals

`oc_poc_run` returns `{"status": "refused", "reason": …}` instead of executing. Map the reason to the fix:

| Reason | Cause | Fix |
| --- | --- | --- |
| `approval_key_unavailable` | `OPENCYBER_APPROVAL_KEY` is unset, shorter than 32 bytes, or the file path is unreadable. | Start the container with the key: `docker run -e OPENCYBER_APPROVAL_KEY=…` or mount a file and set `OPENCYBER_APPROVAL_KEY_FILE`. Restart the MCP client so a new server process reads it. |
| `authorization_required` | No signed authorization record exists for the engagement. | Run `opencyber-poc authorize` inside the container. There is no MCP tool that creates it. |
| `authorization_expired` / `authorization_invalid` | The validity window ended or the record was edited. | Re-run `authorize` with a current window; a new record archives the old one. Never edit `poc/authorization.json` by hand. |
| `scope_violation` | The spec target is not an engagement target, or the target is not listed in the signed authorization. | Fix the target or the engagement; do not re-spell the host. |
| `technique_not_authorized` | The technique is not in the authorization's `allowed_techniques`. | Re-authorize with the technique listed, or choose another technique. |
| `approval_invalid` / `approval_consumed` | The approval id is unknown, expired, already reserved or used, or does not match this spec/chain. | Inspect the recorded run before asking the operator for a fresh approval. Reservation occurs before launch and remains consumed after cancellation, crashes or persistence failures. |
| `artifact_hash_mismatch` | The spec or code changed after approval. | Re-render, re-lint, and get a new approval. |
| `chain_incomplete` | The chain verdict is not `complete`. | Add the missing capability annotation or the step that supplies it. |
| `lint_failed` | Blocking lint findings. | Read `blocking` and fix the host, technique, limits, or forbidden pattern. |
| `run_in_progress` | Another PoC run holds the engagement lock. | Wait for it or stop the other client. |

A refusal or failed run may include `approval_consumed`, `run_id` and
`execution_started` facts. A consumed approval does not prove execution began.
Repair the reported storage or execution problem, review existing evidence,
then obtain a new approval for an intentional retry. Never edit the approval
record to clear consumption.

Workspace writes under `poc/` are refused by design: authorization, approvals, chains, specs, code, and evidence are written by their owning tools. Use `oc_authorization_get`, `oc_chain_plan`, `oc_poc_*`, and the `opencyber-poc` CLI. See [POC_CHAINS.md](POC_CHAINS.md).

## MCP stdio wiring

The server speaks MCP over stdio and publishes no port. A client launches it with `docker exec -i`.

```sh
docker exec -i opencyber-beta opencyber-mcp
```

| Symptom | Cause | Fix |
| --- | --- | --- |
| Client connects then immediately disconnects | Server process exited at startup. | Run the command manually and read the traceback. A common cause is an unknown `OPENCYBER_TOOL_CATEGORIES` value, which raises at import. |
| Garbled protocol or hangs | A TTY or shell banner is attached to stdout. | Use `docker exec -i` without `-t`; do not wrap the command in a login shell that prints output. |
| `command not found` | The client is not running the command inside the container, or `PATH` was overridden. | Use the full `docker exec -i <container> opencyber-mcp` form. |
| Client sees fewer tools than expected | Compact mode or a category filter is set, or the client is using Code Mode. | Check `OPENCYBER_MCP_MODE` and `OPENCYBER_TOOL_CATEGORIES`; compact mode advertises 82 native tools, including `oc_catalog` and `oc_execute`. Default full mode advertises 256. |
| Tools fail with `unknown engagement_id` | The client is passing an ID from another workspace or a malformed ID. | Call `oc_engagement_list`; IDs must match `eng_YYYYMMDD_<32 hex>`. |
| Browser or serial session ID stops working | Sessions are process-scoped. A new `docker exec` starts a new server process. | Reopen the browser or serial session; persisted logs remain under the engagement. |
| Multiple clients interfere | Each `docker exec` is a separate server process sharing the workspace volume. Process-scoped state is not shared. | Use one server process per client session; do not expect browser/serial IDs to cross processes. |
| Permission denied running `docker exec` | The host user cannot access the Docker socket. | Fix host Docker permissions; do not add the container to a broader trust domain to work around it. |

For client configuration examples, see [MCP_INTEGRATION.md](MCP_INTEGRATION.md). The server's `--self-test` does not exercise stdio framing; use the smoke test or a real client for that.

## HTTP timeout errors

Native HTTP tools resolve a deadline from the per-call `timeout`, then `OPENCYBER_HTTP_TIMEOUT`, then 30 seconds. The HTTP workbench uses the per-call `timeout`, then the session's stored value, which was resolved from the environment at session creation. All values must be greater than 0 and at most 300.

| Error or symptom | Cause | Fix |
| --- | --- | --- |
| `OPENCYBER_HTTP_TIMEOUT must be a number of seconds, got '...'` | The environment value is not numeric. | Set a number such as `60`, or unset it for the default. |
| `timeout must be greater than 0 and at most 300 seconds` | A per-call or environment value is zero, negative, or above the cap. | Use a value in range. Values are rejected, not clamped. |
| `requests.exceptions.ConnectTimeout` | Connection establishment exceeded the deadline. | Check routing and the target; raise the timeout within the cap. |
| `requests.exceptions.ReadTimeout` | The target accepted the connection but did not respond in time. | Raise the timeout, or use a longer-running executable tool with client-side cancellation. |
| A tool appears to hang | The scan is running under the 1800-second server deadline, or OPENCYBER_TOOL_TIMEOUT_S was set to 0. | Cancel from the MCP client, which terminates the process group; for long scans raise OPENCYBER_TOOL_TIMEOUT_S (up to 86400) instead of disabling it. |
| Redirect loop or scope error in the workbench | More than 30 in-scope redirects, or a redirect left the session scope. | Fix the target or session scope; redirects are bounded and checked hop by hop. |
| Timeouts offline | Offline mode is not the cause; it only blocks named features. | Diagnose network reachability, not the offline switch. |

Executable tools default to a 1800-second server deadline and 4 MiB retained
output per stream. `0` disables the corresponding limit. Client cancellation
also terminates the process group: SIGTERM followed by SIGKILL after two
seconds. A cap or timeout means the result can be partial; inspect `coverage`,
`limitations` and the limit facts rather than treating it as an empty result.

## Installer and upgrade failures

| Error | Cause | Fix |
| --- | --- | --- |
| `container '<name>' exists but is not managed by this installer.` | The name belongs to a container without the management label. | Rename or remove that container, or choose a different `OPENCYBER_CONTAINER_NAME`. |
| `volume '<name>' exists but is not managed by this installer.` | `--purge-workspace` found an unlabeled volume. | Remove it yourself only after confirming it is not needed, or leave it in place. |
| `image version label is '<x>', but <v> was requested.` | The tag points to a different version, or a digest/tag pair is mismatched. | Use the matching `--version` and `--digest`. |
| `Docker is installed but its daemon is not available.` | The daemon is stopped or the socket is inaccessible. | Start Docker and fix socket permissions. |
| `unsupported Docker architecture ...` | The daemon architecture is neither amd64 nor arm64. | Use a supported host. |
| `--verify-attestation requires network access and cannot be combined with --offline.` | Two incompatible modes. | Verify before transfer; install offline without attestation. |
| Upgrade left a `<name>-rollback-<epoch>` container | The new install failed and the trap could not complete, or a previous run was interrupted. | Inspect both containers, start the rollback one if needed, then remove the failed container. |
| Container is running but unhealthy | Doctor found a degraded image or a required asset changed. | Run `opencyber-doctor --json`; do not treat a running process as a healthy harness. |
| Uninstall removed the container but not the volume | Default behavior. | Use `--purge-workspace` only when you intend to destroy all engagements and evidence. |

Run the installer with `bash install.sh` as a user who already has Docker
access. It refuses to replace objects it does not own. Do not delete labels
or volumes to force an upgrade; that removes the check that distinguishes
managed state from someone else's data.

## Still failing

Collect, redact, and retain:

```sh
docker version
docker info --format '{{.Architecture}} {{.ServerVersion}}'
docker inspect --format '{{.Config.Image}} {{.Image}} {{json .State.Health}}' opencyber-beta
docker logs --tail 500 opencyber
docker exec opencyber-beta opencyber-doctor --json
docker exec opencyber-beta opencyber-mcp --self-test
docker exec opencyber-beta opencyber-assets --verify --deep --json
docker exec opencyber-beta opencyber-hardware --inventory --json
```

Also record the image reference and digest:

```sh
docker inspect --format '{{.Config.Image}} {{.Image}}' opencyber-beta
docker image inspect "$BETA_IMAGE" --format '{{json .RepoDigests}}'
```

Remove or replace credentials, cookies, bearer tokens, target hostnames, and device serial numbers before sending the bundle outside your organization. For a suspected vulnerability in the harness, follow [SECURITY.md](../SECURITY.md) rather than a public issue.

## Related documents

- [CONFIGURATION.md](CONFIGURATION.md): variable defaults and import-time behavior.
- [OPERATIONS.md](OPERATIONS.md): hardening, health checks, backups, incident response.
- [CLI_REFERENCE.md](CLI_REFERENCE.md): flags and exit codes.
- [HARDWARE.md](HARDWARE.md): device profiles and per-domain host flags.
- [AIRGAP.md](AIRGAP.md): transfer, offline assets, and hard isolation.
