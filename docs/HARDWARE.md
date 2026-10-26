# Hardware and physical-layer testing

OpenCyber 0.5.0 supports hardware and physical-layer integrations in the private
pre-production beta: USB, SDR, Wi-Fi, Bluetooth/BLE, NFC/RFID, JTAG/SWD/SPI, UART,
CAN, logic analyzers, GNSS and IR. This guide covers host setup and device access.
Begin with [beta testing](BETA_TESTING.md) for software-only checks. OpenCyber
runs in a container. A tool being installed says nothing about
whether the host has passed the matching device through, so treat these as two
separate readiness questions:

```text
opencyber-doctor          -> are the tools installed and are offline assets intact?
oc_hardware_readiness     -> is a matching device visible inside this container?
```

The hardware toolchain is baked into the image, so an airgapped host never
needs a package repository. A container that has the tools but no devices is
reported as `tooling_ready`, never as a working radio.

From the host, without an MCP client:

```sh
docker exec opencyber opencyber-hardware            # per-domain readiness
docker exec opencyber opencyber-hardware --inventory --json
docker exec opencyber opencyber-hardware --plan sdr
```

`oc_hardware_inventory` is the evidence view: USB devices with SDR/NFC/JTAG/
serial classification, serial ports, wireless and CAN interfaces, Bluetooth
adapters, video/input nodes, GPIO/I2C/SPI nodes, and effective capabilities.
USB entries include `accessible`, which is true only when the matching
`/dev/bus/usb/<bus>/<device>` node exists. sysfs can show a device that the
container cannot open. `accessible` means the node exists; it does not test
opening the device, permissions, firmware compatibility or a successful
operation. The inventory's `access` block summarizes node visibility.

Hardware support covers the documented integrations, tooling and passthrough
profiles. Compatibility depends on the device, firmware, host drivers and
architecture. Readiness enumeration does not prove a device works.
[The optional operator checklist](HARDWARE_QUALIFICATION.md) records tested
operations against exact image digests; an untested combination remains
unqualified. Production acceptance is separate.

## Host prerequisites

Run the container as root (the image already does), but grant only the
capabilities the selected domain needs. `scripts/opencyber-run.sh` builds the
`docker run` line and, unless you pass `--dry-run`, starts the container in
detached mode. First complete [beta archive import](BETA_TESTING.md) on Linux
amd64 and run the launcher from the extracted frozen source. The preview's
hardware integrations are available for beta use; device qualification remains
separate. These examples require the operator's authorization for the devices:

```sh
BETA_IMAGE=opencyber:0.5.0-private-beta.1-amd64
./scripts/opencyber-run.sh --profile sdr --image "$BETA_IMAGE"
./scripts/opencyber-run.sh --profile wifi --image "$BETA_IMAGE"
./scripts/opencyber-run.sh --profile serial --device /dev/ttyUSB0 --image "$BETA_IMAGE"
./scripts/opencyber-run.sh --profile can --image "$BETA_IMAGE"
./scripts/opencyber-run.sh --profile full --dry-run --image "$BETA_IMAGE"
```

`--dry-run` prints the command and exits without calling Docker. Useful
options are `--offline` (sets `OPENCYBER_OFFLINE=1`), `--no-read-only` (writes
to the container rootfs), `--device PATH` (repeatable, and the path must already
exist on the host), and `--command ...` (replaces the default `sleep infinity`).

Every profile starts from the same hardened base:

```sh
--cap-drop=ALL
--cap-add=NET_RAW
--cap-add=NET_ADMIN
--cap-add=NET_BIND_SERVICE
--security-opt no-new-privileges
--read-only --tmpfs /tmp --tmpfs /run --tmpfs /root/.config --tmpfs /root/.cache
-v opencyber-workspace:/workspace
```

With `--no-read-only`, the read-only flag and the seven tmpfs mounts are
omitted; the capability drop and `no-new-privileges` remain.

Profiles then add only the exposure they need:

| Profile | Added flags |
| --- | --- |
| `software` | None (default) |
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
| `full` | `--network host`, `--cap-add SYS_RAWIO`, `/dev/bus/usb`, serial adapters, `/dev/lirc0` |

If an auto-detected device is absent, the launcher warns and continues; an
explicit `--device` that does not exist is an error. No profile uses
`--privileged`.

### USB devices (SDR, NFC, JTAG, logic analyzers)

```sh
--device /dev/bus/usb
```

This exposes the whole USB bus, which is convenient but broad. For lab
testing, prefer specific device nodes and host udev rules. Install
the provided rules on the host:

```sh
sudo install -m 0644 packaging/99-opencyber-hw.rules /etc/udev/rules.d/
sudo udevadm control --reload-rules
sudo udevadm trigger
```

The rules make common SDR, NFC, JTAG, logic-analyzer, serial, GPS, and IR
devices readable by the user that runs Docker. They do not grant capabilities
and do not replace `--device` or `--device /dev/bus/usb`; the container still
needs the node passed through.

### Serial / UART

```sh
--device /dev/ttyUSB0
# or
--device /dev/ttyACM0
```

The container user is root, so no `dialout` group is needed inside the
container. On the host, the user running `docker` must be able to open the
device. Do not pass block devices or `/dev/mem`; `oc_serial_open` refuses them.

`oc_serial_open` accepts only character devices whose resolved path starts with
one of these prefixes:

```text
/dev/ttyUSB
/dev/ttyACM
/dev/ttyAMA
/dev/ttyS
/dev/ttyO
/dev/ttyPS
/dev/ttyGS
/dev/ttyHS
/dev/ttySC
/dev/ttyTHS
/dev/ttyRPMSG
/dev/serial/
/dev/rfcomm
/dev/lirc
```

`/dev/pts/*` is additionally allowed only when `OPENCYBER_ALLOW_PTY=1` is set,
which is intended for lab and test setups. There is no general `/dev/tty*`
allowlist. The path is resolved with `realpath` before the prefix check, so a
symlink under `/dev/serial/by-id/` is accepted when its target is in the list.

### Wi-Fi monitor mode and injection

The `wifi` profile adds:

```sh
--network host
--cap-add SYS_RAWIO
```

The base capabilities already include `NET_ADMIN` and `NET_RAW`. The wireless
PHY must be visible in the host network namespace. `oc_hardware_readiness`
reports the domain's minimum flags (`--network host`, `NET_ADMIN`, `NET_RAW`);
the launcher adds `SYS_RAWIO` for the `wifi` and `full` profiles. Put the
interface in monitor mode *inside the container* with `oc_airmon` or `oc_iw`.
If the host's NetworkManager owns the interface, unmanage it first. Not every
adapter supports monitor mode or injection; check with:

```text
oc_iw(engagement_id, ["dev"])
oc_iw(engagement_id, ["phy"])
```

### Bluetooth / BLE

```sh
--network host
--device /dev/bus/usb      # for Ubertooth
```

Base capabilities `NET_ADMIN` and `NET_RAW` are already present.
`bluetoothctl` and `btmon` need access to the host Bluetooth stack. If D-Bus is
not available in the container, use `btmgmt`/`hcitool` for raw HCI work or run
an Ubertooth for passive BLE capture.

### CAN / automotive

```sh
--network host
--device /dev/bus/usb      # for a USB-CAN adapter
```

Base capability `NET_ADMIN` is already present. Bring the interface up inside
the container (this is why `oc_ip` exists and is not treated as an arbitrary
shell):

```text
oc_ip(engagement_id, ["link", "set", "can0", "up", "type", "can", "bitrate", "500000"])
oc_candump(engagement_id, ["-n", "1000", "can0"])
```

### GPS / GNSS

```sh
--device /dev/bus/usb
--device /dev/ttyUSB0      # for a USB-serial GNSS receiver
```

The `gps` profile adds USB and auto-detects serial adapters. `oc_gpsmon`,
`oc_gpspipe`, and `oc_gpsfake` cover live inspection, persistence, and replay.

### Logic analyzers

```sh
--device /dev/bus/usb
```

`sigrok-firmware-fx2lafw` is bundled. If a device needs a vendor firmware
upload, use `sigrok-cli --list-supported` and the firmware paths under
`/usr/share/sigrok-firmware`.

### IR

```sh
--device /dev/lirc0
```

The `ir` profile adds this device when `/dev/lirc0` exists; otherwise it warns.

## Hardware playbooks

`oc_hardware_plan(domain)` and `opencyber-hardware --plan DOMAIN` return a
deterministic plan for `usb`, `sdr`, `wifi`, `bluetooth`, `nfc`, `jtag`,
`serial`, `automotive`, `logic`, `gps`, `ir`, and `firmware`. Each step names
the catalog tool that performs it. These plans are data and functions in
`src/opencyber/hardware.py`; they are not separate files on disk. This guide
is the host-side document; it is not the playbook source. A plan
does not execute anything: every step still requires an explicit MCP call, and
transmit or power operations still require authorization.

## UART capture: use serial sessions, not minicom

Interactive tools lose output when an agent's turn ends. The serial session API
captures every byte into
`<engagement>/hardware/serial/<session_id>.jsonl`:

```text
oc_serial_open(engagement_id, "/dev/ttyUSB0", 115200)
oc_serial_read(engagement_id, session_id, timeout=2)
oc_serial_write(engagement_id, session_id, data="help\r\n")
oc_serial_read(engagement_id, session_id, timeout=1)
oc_serial_close(engagement_id, session_id)
```

Closing a session restores the saved terminal settings and releases the
device. Record any disconnect or cleanup failure in the beta report.

Reads are non-blocking with a bounded timeout (0 to 30 seconds, at most 65536
bytes per read) and retain a 4 MB in-memory buffer in addition to the
transcript. A single write is limited to 65536 bytes. The default baud rate is
115200; unsupported rates are rejected rather than silently approximated.

Live sessions are process-scoped. If the MCP server restarts, open serial and
browser handles are gone even though their transcripts and browser network logs
remain under the engagement directory. Reopen the device or browser rather than
assuming the old session id still works.

## Firmware triage

`oc_firmware_analyze` never executes the image. It computes SHA-256/SHA-1/MD5,
identifies ELF/PE/Mach-O/filesystem/compression magic, maps entropy in 4 KiB
blocks, extracts interesting strings, runs `binwalk -B` when available, and
persists a JSON report under `artifacts/firmware/<stem>.report.json`.

The work is bounded:

- Entropy analysis covers the first 64 MiB by default (`max_entropy_bytes`,
  clamped to 4096 bytes through 512 MiB). The report sets `truncated` when the
  image is larger than the analyzed window.
- Printable strings of six or more characters are counted within the analyzed
  window; up to 200 keyword-matching strings are retained.
- The automatic `binwalk -B -q` pass has a 120-second timeout. A non-zero exit
  is recorded for review rather than treated as a crash.

Follow-up tools in the same engagement:

```text
oc_binwalk          signature scan and extraction
oc_unblob           recursive extraction of nested containers
oc_strings          credential and path mining
oc_qemu_arm         emulate an extracted ARM user-space binary
oc_qemu_system_arm  emulate a full ARM system
oc_gdb_multiarch    debug extracted ARM/MIPS code
```

## What is intentionally not supported

- **Kernel modules and device drivers.** The container cannot load a host
  module. Use the host for driver-bound work.
- **GPIO/PWM/I2C/SPI on the host SoC.** Only devices passed through appear.
  Raspberry Pi-style `/dev/gpiochip*` requires explicit device flags; the
  inventory can list GPIO, I2C, and SPI nodes once they are exposed.
- **PCIe cards.** Pass the resulting `/dev` node; PCIe hotplug is a host task.
- **Transmit without authorization.** `hackrf_transfer`, `aireplay-ng`,
  `mdk4`, and NFC writes are capability, not permission. Confirm frequency,
  power, and written authorization first.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| `oc_hardware_readiness` says tooling only | Device not passed; inspect `docker run` flags and udev |
| SDR tools report no device | `--device /dev/bus/usb`, permissions, another process holding the device |
| RTL-SDR tunes but no samples | DVB-T kernel driver is bound on the host; blacklist it |
| Wi-Fi interface missing | `--network host`; host PHY not moved into the container namespace |
| Monitor mode fails | Adapter/firmware does not support it; check `iw phy` |
| Bluetooth scan finds nothing | Host Bluetooth stack not reachable; use `--network host` and test `btmgmt` |
| CAN interface missing | `--network host`, `--cap-add NET_ADMIN`, adapter driver on host |
| Serial read times out | Wrong baud/parity, flow control, or TX/RX swapped |
| `oc_serial_open` rejects the path | Not in the allowlist; check the resolved path and `OPENCYBER_ALLOW_PTY` for a pty |
| Proxmark3 client cannot connect | USB passthrough plus matching firmware; run `oc_proxmark3` with `-h` |
| Logic analyzer not found | udev rule, FX2 firmware, or unsupported clone |
| IR device missing | Pass `/dev/lirc0`; the `ir` profile warns when it is absent |
