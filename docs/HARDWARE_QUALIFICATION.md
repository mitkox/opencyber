# Optional real-device qualification

Real-device evidence is optional for the 0.5.0 private pre-production beta and
the planned first public prerelease. Hardware integrations are supported for
beta use; qualification identifies the device, firmware, host architecture and
operations actually tested against a candidate. The following checklist applies when adding
optional qualification; software publication does not require this bundle.
Beta testers can begin with [BETA_TESTING.md](BETA_TESTING.md) without owning any of these devices.

An optional submitted qualification bundle must cover every hardware domain
and firmware triage against a board-derived sample. Installed tools, device
enumeration, fake sysfs trees, PTYs, loopback fixtures and unit tests do not
satisfy device qualification. An incomplete submitted bundle is refused;
omitting the bundle retains an explicit `not_qualified` evidence status. That
status describes the absence of device qualification, not integration support.

An operator supplies the equipped lab and runs the procedures below against
the exact private candidate images selected through [RELEASE.md](RELEASE.md).
Each domain needs at least one tested host; it does not need both CPU
architectures. Software and container acceptance still require native amd64 and
arm64 candidates. Record the actual device, firmware and architecture matrix
with the qualification bundle. A successful test does not establish support
for untested models, operations or architectures. Public sharing remains a
future release step.

## Prepare the observations

Freeze the source commit and select a completed candidate build run before
testing. Obtain its validated candidate receipt list, including both platforms,
their immutable registry digests, full commit SHA and `catalog_sha256`.
Use immutable image references for every lab run and retain the exact launcher
arguments. A rebuild creates a different candidate and requires new evidence.

Keep the lab work outside the source checkout. For example, use a private
directory containing `observations.json` and `evidence/`:

```sh
python scripts/hardware-qualification.py template \
  --commit "$COMMIT" --candidate-run-id "$CANDIDATE_RUN_ID" \
  --records candidate-records.json --output /private/lab/observations.json
```

The template contains all 11 domain records and a firmware record. Every
status is `pending`, observations are blank and operator attestation is false.
It deliberately cannot pass validation. The CLI never operates a device,
executes a playbook, invents an observation, or changes a status to `passed`.

Set up an owned reference target and choose an expected result before each
operation. Set the process deadline and output limit before starting it.
Record actual commands, runtime flags, observations and cleanup in the report.
Run only bounded operations; a readiness report alone is a prerequisite check.

| Record domain | Required operation and observation | Cleanup to record |
| --- | --- | --- |
| `usb` | Enumerate and open an owned test device; retain its descriptor/control-read response | Close handles and restore device access |
| `sdr` | Receive a known lab signal for a fixed duration; retain capture metadata and the observed signal | Stop the capture and release the receiver |
| `wifi` | Monitor an owned lab AP and capture a bounded packet set that identifies that AP | Restore the interface mode and host network management |
| `bluetooth` | Discover and inspect an owned BLE fixture; match its expected identity/service data | Stop discovery and close device handles |
| `nfc` | Read an owned test tag and compare the expected identifier or test data | Close the reader session; do not modify the tag |
| `jtag` | Identify an owned JTAG/SWD/SPI reference board and read a known identifier or region | Detach without erase/program operations and restore board state |
| `serial` | Capture known UART output and a bounded permitted command/response; verify the persisted transcript | Close the session and confirm the device is released |
| `automotive` | Exchange known test frames and capture them on an isolated CAN bench bus | Stop senders/capture and restore the test interface |
| `logic` | Capture a fixed-duration known waveform and verify expected decoded values | Stop acquisition and release the analyzer |
| `gps` | Read and decode a real GNSS receiver's output, including its reported fix state | Stop readers and release the receiver |
| `ir` | Capture and decode a fixed set of signals from an owned test remote | Stop capture and release the receiver |
| `firmware` | Run non-executing firmware triage on an owned or redistributable board-derived sample; verify its known hash and expected identity | Close the analysis session and preserve the source sample identity |

The CAN record uses the canonical `automotive` domain name. The firmware
record is separate from the 11 hardware domains. Neither a synthetic firmware
fixture nor device visibility establishes the required board-derived sample.

For each operation, exercise absent-device refusal, insufficient-permission
refusal and disconnect handling where applicable. Also demonstrate that the
deadline bounds the run and that cleanup completes. Record the expected and
observed behavior and retain supporting output. These are lab operations, not
tests against unrelated networks or production devices.

## Record format

`qualification.json` is a UTF-8 JSON object with these fields:

| Field | Required value |
| --- | --- |
| `schema_version` | Integer `1` |
| `commit` | Full 40-character lowercase source commit SHA |
| `candidate_run_id` | Positive integer selecting the completed candidate workflow run |
| `catalog_sha256` | Lowercase 64-character catalog digest matching both candidate receipts |
| `domains` | Exactly one record for each domain in the table except `firmware` |
| `firmware` | A separate record whose `domain` is `firmware` |

Each completed domain or firmware record has the following fields. The
template emits this structure with pending values to fill in after testing.

| Field | Meaning |
| --- | --- |
| `domain`, `status` | Canonical domain name and `passed`; missing, failed and skipped records refuse the submitted qualification bundle |
| `kind` | `real_device` for hardware, `board_sample` for firmware; synthetic/fixture records are refused |
| `platform`, `image_digest` | `linux/amd64` or `linux/arm64` and that candidate's exact `sha256:` registry digest |
| `device` | Object containing nonempty `model` and `firmware` identity; explain versions the hardware cannot report |
| `host` | Object containing `architecture` (`amd64` or `arm64`, matching the platform), `os` and `kernel` |
| `launcher_flags` | Nonempty list of the exact runtime flags, including device, network, capability and mount flags |
| `limits` | `timeout_s` greater than zero and at most 3600; integer `max_output_bytes` greater than zero and at most 268435456 |
| `operation`, `expected`, `observed` | Nonempty descriptions of the bounded action, predetermined result and actual observation |
| `cleanup` | Nonempty account of released resources and restored host/device state |
| `operator`, `operator_attested` | Named operator and Boolean `true`, attesting that these observations came from the stated real equipment/sample |
| `completed_at` | ISO 8601 UTC timestamp with `Z` or explicit `+00:00`; future timestamps are refused (five minutes clock tolerance) |
| `negative_checks` | Object containing all five dispositions described below |
| `evidence` | Nonempty list of objects containing a relative `path` and its lowercase 64-character `sha256` |

`negative_checks` requires the keys `missing_device`,
`insufficient_permissions`, `disconnect`, `timeout` and `cleanup`. Each value
is an object with `status` and nonempty `detail` describing the observation.
`timeout` and `cleanup` must be `passed`. The other three may be `passed`, or
`not_applicable` with a concrete reason, such as an integrated device that
cannot be detached safely. Pending, skipped and failed dispositions refuse the
bundle. For firmware file analysis, explain the inapplicability of device-only
checks while retaining timeout and cleanup evidence.

Evidence paths use normalized forward slashes beneath `evidence/`, such as
`evidence/serial/transcript.jsonl`. Absolute paths, traversal, duplicate entries
within a record, symlinked files/directories and non-regular files are refused.
Every referenced file must be present and match its SHA-256. One combined
report may support multiple records, provided it documents the relevant tests.

The validator proves record completeness and artifact identity. It cannot
prove that an operator physically connected equipment or that an observation
is true. The maintainer must assess the named operator's attestation and
supporting reports before accepting the hardware matrix.

## Collect and verify

Keep original reports privately. Prepare reviewed, sanitized copies under the
chosen evidence root before collection; remove credentials, personal data,
internal host identifiers and unrelated engagement content. The collector
copies exact bytes and does **not** redact them. Include only sample material
intended for the release evidence bundle.

Edit the template with completed observations and the evidence paths. Hashes
may be omitted during collection; the collector computes them. If a supplied
hash is already present, changed bytes are refused rather than silently
receiving a new identity.

```sh
python scripts/hardware-qualification.py collect /private/lab/observations.json \
  --evidence-root /private/lab --output /private/qualification-bundle \
  --records candidate-records.json

python scripts/hardware-qualification.py verify \
  /private/qualification-bundle/qualification.json \
  --commit "$COMMIT" --records candidate-records.json
```

Collection requires a new output directory with an existing parent and will
not overwrite an earlier bundle. It copies evidence, calculates checksums and
validates all records before exposing the completed directory. The directory
contains `qualification.json` and its `evidence/` tree. Verification returns
the validated JSON and exits zero; refusals exit nonzero.

Submit that complete directory as the release workflow's checksummed
qualification archive. The release gate must additionally bind
`candidate_run_id` to the trusted selected run, repository identity, workflow,
attempt and frozen source commit, and verify the archive checksum before
calling the hardware validator. Do not upload raw private lab data as a
release asset. Hashes and these records are release evidence, not hardware
isolation or production-deployment qualification.
