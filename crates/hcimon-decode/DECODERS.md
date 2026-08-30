# Writing decoders

This document describes how the decoders in `hcimon-decode` are structured and
the conventions they follow, so that new commands, events and protocols can be
added consistently.

## Architecture

```
hcimon-capture   Packet {opcode, index, ts, data}   (framing, btsnoop files)
      │
      ▼
hcimon-decode    decode(&mut Context, &Packet) -> Decoded
      │           Decoded { prefix, label, summary, extra, fields: Vec<Node>, layers, .. }
      ▼
btmon (app)     text renderer (btmon look-alike) / interactive TUI
```

* `src/monitor.rs` dispatches on the monitor opcode (HCI command/event/ACL/...,
  new index, user logging, ...).
* `src/hci/` decodes HCI. `command.rs` and `event.rs` are the dispatchers;
  the actual decoders are split by area:
  * `cmd_classic.rs` – OGF 1..6 (Link Control, Link Policy, Baseband, Info, Status, Testing)
  * `cmd_le_a.rs` – OGF 8, OCF 0x0001..0x0060
  * `cmd_le_b.rs` – OGF 8, OCF 0x0061..
  * `vendor.rs` – OGF 0x3f
  * `event.rs` – events other than LE Meta
  * `le_event.rs` – LE Meta subevents
  * `acl.rs`, `sco.rs`, `iso.rs` – data packets; ACL hands off to L2CAP
  * `common.rs` – shared field helpers (status, handles, addresses, features, ...)
  * `ids.rs` – **generated** opcode/event tables (`tools/gen_hci_ids.py`); do not edit
* `src/l2cap/` – L2CAP framing, signaling, dynamic channel tracking
* `src/att.rs`, `src/smp.rs` – fixed-channel protocols
* `src/ad.rs` – advertising / EIR data structures
* `src/assigned/` – **generated** SIG assigned numbers (UUIDs, company IDs, AD types, ...)
* `src/context.rs` – state kept across packets (controllers, connections, L2CAP
  channels, ATT requests)

## Decoder signature

Every decoder reads its fields from a `Reader` and appends lines to an `Out`:

```rust
fn le_set_scan_enable(st: &mut IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    enable("Scanning", r, out)?;
    enable("Filter duplicates", r, out)?;
    Ok(())
}
```

* `Reader` (`src/reader.rs`) is a bounds-checked cursor, little-endian like
  HCI and most Bluetooth protocols:
  `u8() u16() u24() u32() u64() i8() bytes(n) array::<N>() bdaddr() rest() sub(n) cstr() fixed_str(n)`,
  plus `u16_be() u32_be()` for the big-endian exceptions (SDP today; OBEX and
  parts of Mesh would be, if they are ever added).
  Every read returns `Result<T, Truncated>`; just use `?`.  The caller reports
  the truncation and hex dumps what is left, so decoders never need to handle
  short packets themselves.
* `Out` (`src/tree.rs`) builds the field tree.  Use `field!(out, "Label: {}", v)`
  for formatted lines, `out.line(..)`, `out.unknown(..)` for values the decoder
  does not recognise (rendered like btmon's white-background warnings),
  `out.error(..)` for malformed data, `out.hex(bytes)` for raw dumps, and
  `out.nest(|o| ..)` / `out.group("Text", |o| ..)` to add children under the
  most recent line.
* The dispatchers (`command_params`, `return_params`, `event_params`,
  `le_event_params`) return `Ok(false)` for opcodes they do not handle; the
  caller then dumps the payload as hex.  Return `Ok(true)` once the decoder ran.
  After a decoder returns, any unconsumed bytes are reported as
  "Unexpected trailing data" – so consume everything, including variable-length
  tails (`r.rest()`), and never read past what the packet actually contains.

## Output conventions (btmon style)

Match btmon's text so users can read output they already know:

```
        Status: Success (0x00)
        Handle: 3585 Address: 5C:F3:70:9C:2C:D7 (OUI 5C-F3-70)
        Address type: Random (0x01)
        Address: 4B:65:27:2E:1D:6E (Resolvable)
        Interval: 24.000 msec (0x0018)
        Latency: 0 (0x0000)
        Supervision timeout: 420 msec (0x002a)
        Scanning: Enabled (0x01)
        Own address type: Public (0x00)
        Filter policy: Accept all advertisement (0x00)
        RSSI: -45 dBm (0xd3)
        Features: 0xff 0xff 0x8f 0xfe 0xdb 0xff 0x5b 0x87
          3 slot packets
          5 slot packets
        Mask: 0xff 0x9f 0xfb 0xff 0x07 0xf8 0xbf 0x3d
          Inquiry Complete
```

* Enumerations: `Label: Meaning (0xNN)`; unknown values via `out.unknown(..)`
  (or `enum8()`/`enum16()` in `common.rs` which do this for you).
* Intervals in 1.25 ms units: `interval("Interval", r, out, 1250)`; slots
  (0.625 ms): `slots(..)`; timeouts in 10 ms units: `timeout_ms(.., 10)`.
* Bit masks: print the raw bytes, then one child line per set bit (`bits()`).
* Lists (e.g. `Num_Reports` entries): print a line per entry, nesting the
  entry's fields, e.g. `out.group(format!("Entry {i}"), |o| ..)` — or follow
  btmon's flat style where it is established (advertising reports print each
  report's fields at the same level).
* Version-specific variants (`v2` commands) are separate opcodes with their own
  decoder; reuse helpers between them.
* Keys and random values: `key128("Long term key", r, out)` prints them as one
  hex string; other blobs use `hex_bytes("Label", r, out, n)`.
* Strings: `name("Name", r, out, 248)`.

## State

`IndexState` (per controller) tracks connections (`conns`), each with L2CAP
and ATT state.  Decoders that establish or tear down links must keep it
current:

* connection complete events → `event::register_connection(st, handle, LinkType::.., addr_type, addr, role)`
* disconnection → `st.remove_conn(handle)`
* `handle(st, r, out)` prints the peer address next to the handle when known.

L2CAP connection requests/responses register `L2capChannel`s so that later
traffic on dynamic CIDs can be attributed to a PSM.  ATT keeps pending
requests so responses can be interpreted, and learns attribute types from
discovery responses.

## Reference material

* `tools/hci_ref_v6.3.txt` — every HCI command/event of Core Spec v6.3 with
  its opcode and the ordered list of parameters with sizes.  Search it for the
  section (e.g. `## 7.8.53 LE Set Extended Advertising Parameters command`).
* The full text of the specification is needed for the meaning of values
  (allowed ranges, enumerations).  It is not part of the repository.
* BlueZ's `monitor/packet.c` defines the de-facto output format; do not copy
  code from it (GPL), but matching its wording for labels is intended.

## Testing

Unit tests live next to the decoders and feed byte arrays through the
dispatcher:

```rust
#[test]
fn le_set_scan_enable_params() {
    let mut st = IndexState::default();
    let mut out = Out::new();
    let mut r = Reader::new(&[0x01, 0x00]);
    assert!(command_params(&mut st, cmd::LE_SET_SCAN_ENABLE, &mut r, &mut out).unwrap());
    let lines: Vec<_> = out.roots().iter().map(|n| n.text.clone()).collect();
    assert_eq!(lines, ["Scanning: Enabled (0x01)", "Filter duplicates: Disabled (0x00)"]);
}
```

`cargo run -p hcimon-decode --example dump -- testdata/xg24_peripheral_hr.tty`
prints a whole capture in btmon's text format and is the quickest way to eyeball
a decoder against real traffic.  Any capture in btsnoop/monitor format
(`btmon -w file.snoop`) works too.
