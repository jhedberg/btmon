# hcimon

A cross-platform Bluetooth HCI monitor written in Rust — a work-alike of
BlueZ's `btmon` that does not need the Linux kernel, with an interactive
terminal UI on top.

It was written to debug [Zephyr](https://zephyrproject.org) Bluetooth devices
from macOS (and anywhere else): Zephyr can stream every HCI packet, plus its
log messages, in BlueZ's *monitor* format over a UART
(`CONFIG_BT_DEBUG_MONITOR_UART`) or a SEGGER RTT channel
(`CONFIG_BT_DEBUG_MONITOR_RTT`).  `hcimon` reads those streams directly, and
also btsnoop / Apple PacketLogger capture files and, on Linux, the kernel's
HCI monitor socket.

```
$ hcimon --tty /dev/serial/by-id/usb-SEGGER_J-Link_000682451005-if00 -p
= New Index: 00:00:00:00:00:00 (Primary,Virtual,efr32)                 #1 [hci0] 0.000000
< HCI Command: LE Set Advertising Data (0x08|0x0008) plen 32           #45 [hci0] 0.226300
        Length: 24
        Flags: 0x06
          LE General Discoverable Mode
          BR/EDR Not Supported
        16-bit Service UUIDs (complete): 2 entries
          Heart Rate (0x180d)
          Battery (0x180f)
        Name (complete): Zephyr Heartrate Sensor
> HCI Event: Command Complete (0x0e) plen 4                            #46 [hci0] 0.227600
      LE Set Advertising Data (0x08|0x0008) ncmd 1
        Status: Success (0x00)
```

## Features

* **Sources** — serial port (DTR/RTS asserted, automatic reconnect when a
  board is re-plugged or re-flashed), RTT via any [probe-rs] supported debug
  probe (survives target resets), capture files (btsnoop with the monitor,
  HCI and H4 datalink types, Apple PacketLogger, raw monitor streams) and the
  Linux kernel monitor socket.  Several sources can be open at once.
* **Interactive UI** (default on a terminal): scrolling packet list with
  btmon's colours, a details pane with a collapsible field tree and raw bytes,
  free-text search, filters by packet type / protocol layer / controller /
  source / log priority, pause, time display modes, adding and removing
  sources at runtime (new serial ports are detected while running), and
  writing everything captured so far to a btsnoop file.
* **Plain mode** (`-p`, or automatically when stdout is not a terminal):
  btmon-style streaming text output.
* **Decoders** for HCI commands, events and LE subevents through Core
  Specification 6.3 (including Channel Sounding, PAwR, ISO, decision-based
  advertising filtering, monitored advertisers, UTP), ACL/SCO/ISO data, L2CAP
  (signaling, dynamic channels, ERTM/streaming framing, credit-based
  channels), ATT/GATT (with request/response matching and learned attribute
  types), SMP, SDP, RFCOMM, advertising/EIR data, and BlueZ management
  records.  The output format follows btmon so it reads the same.

## Building

```
cargo build --release
./target/release/hcimon --help
```

RTT support pulls in `probe-rs`; build with `--no-default-features` to leave
it out.  Reading the Linux kernel monitor socket needs `CAP_NET_RAW`
(`sudo setcap cap_net_raw+ep target/release/hcimon`, or run as root).

## Usage

```
hcimon --tty /dev/ttyACM0                     # Zephyr monitor over UART, interactive UI
hcimon --tty /dev/ttyACM0 -p                  # ...as btmon-style text
hcimon --rtt nRF52832_xxAA --probe 682451005  # Zephyr monitor over RTT
hcimon -r capture.snoop                       # browse a capture file
hcimon --tty /dev/ttyACM0 -w capture.snoop    # capture to a btsnoop file while watching
hcimon --list                                 # show serial ports and debug probes
sudo hcimon -K                                # Linux kernel monitor socket (like BlueZ btmon)
```

The option names follow BlueZ's `btmon` where the meaning is the same
(`-r`, `-w`, `-d`/`--tty`, `-B`, `-i`, `-t`, `-T`, `-N`, `-c`, `-S`, `-I`,
`-C`, `-V`, `-P`).  Press `?` in the UI for the key bindings.

### Zephyr configuration

```
CONFIG_BT_DEBUG_MONITOR_UART=y   # monitor stream on the console UART (logs go through it too)
# or
CONFIG_BT_DEBUG_MONITOR_RTT=y    # monitor stream on an RTT up-channel named "btmonitor"
```

## Design

The project is a Cargo workspace with three crates:

| Crate | Contents |
|---|---|
| `hcimon-capture` | The BlueZ monitor protocol: `Packet`, opcodes, the framed byte-stream format used over UART/RTT (`tty::Framer`, with resynchronisation on noisy lines), btsnoop and PacketLogger readers/writers. No I/O beyond `std::io` traits. |
| `hcimon-decode` | Stateful decoders producing a tree of fields (`Decoded` = headline + `Vec<Node>`) that both the text renderer and the UI consume. A `Context` tracks controllers, connections, L2CAP channels and outstanding ATT requests. Identifier tables (`hci/ids.rs`, `assigned/`) are generated from the Core Specification and the SIG Assigned Numbers by the scripts in `tools/`. See `crates/hcimon-decode/DECODERS.md` for how to add decoders. |
| `hcimon` | The application: CLI, sources (each on its own thread, feeding a channel), the btmon-style text printer, and the [ratatui] UI. |

Design choices worth knowing about:

* **Decoders build a tree, they do not print.** That is what makes one set
  of decoders serve a streaming text mode, a collapsible detail view and
  filtering by field contents.  Decoders never panic on bad input: reads go
  through a bounds-checked cursor (`Reader`) and truncation is reported in the
  output.
* **No parser-combinator framework.** HCI is fixed-layout little-endian
  records; a small cursor type keeps decoders readable and makes partial
  results on truncated packets natural.  `nom`/`winnow` were considered and
  would mostly add ceremony here.
* **Generated identifier tables.** Opcode and event names come from the
  specification text (`tools/gen_hci_ids.py`), UUIDs/company IDs/AD types
  from the SIG YAML files (`tools/gen_assigned_numbers.py`), so keeping up
  with new specification versions is a script run, not a typing exercise.
* **Sources are threads behind a channel.** The UI never blocks on I/O, and
  adding a new transport means implementing one `spawn` function.
* **Timestamps.** btsnoop files and the kernel socket carry wall-clock times;
  the UART/RTT stream carries a free-running 100 µs tick.  Both are kept as
  they are (`Timestamp::Wall` / `Timestamp::Monotonic`) and rendered as
  offsets from the first packet by default, like btmon.

## Testing with Zephyr hardware

`testdata/` contains two raw monitor-stream captures from Silicon Labs xG24
and SiWx917 boards running `samples/bluetooth/peripheral_hr`; the crate
tests and `cargo run -p hcimon-decode --example dump -- testdata/xg24_peripheral_hr.tty`
use them.

[probe-rs]: https://probe.rs
[ratatui]: https://ratatui.rs
