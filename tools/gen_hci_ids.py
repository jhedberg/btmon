#!/usr/bin/env python3
"""Generate crates/hcimon-decode/src/hci/ids.rs from the spec-derived reference.

The reference file (tools/hci_ref_v7.0.txt) is made from the text of the
Bluetooth Core Specification (Vol 4, Part E) by tools/gen_hci_ref.py and lists
every command and event section together with the opcode, event code or event
and subevent code of each version.  Commands and events that were removed from
the specification (AMP, park state, ...) are listed in the EXTRA_* tables below
so old captures still decode with a name.

Usage:  tools/gen_hci_ids.py > crates/hcimon-decode/src/hci/ids.rs
"""
import re
import sys
from pathlib import Path

REF = Path(__file__).with_name("hci_ref_v7.0.txt")

OGF_BY_SECTION = {"7.1": 1, "7.2": 2, "7.3": 3, "7.4": 4, "7.5": 5, "7.6": 6, "7.8": 8}

# (ogf, ocf, name) for opcodes no longer present in the current specification.
EXTRA_COMMANDS = [
    (1, 0x0007, "Add SCO Connection"),
    (1, 0x0035, "Create Physical Link"),
    (1, 0x0036, "Accept Physical Link"),
    (1, 0x0037, "Disconnect Physical Link"),
    (1, 0x0038, "Create Logical Link"),
    (1, 0x0039, "Accept Logical Link"),
    (1, 0x003A, "Disconnect Logical Link"),
    (1, 0x003B, "Logical Link Cancel"),
    (1, 0x003C, "Flow Spec Modify"),
    (2, 0x0005, "Park State"),
    (2, 0x0006, "Exit Park State"),
    (3, 0x000B, "Create New Unit Key"),
    (3, 0x0021, "Read Encryption Mode"),
    (3, 0x0022, "Write Encryption Mode"),
    (3, 0x003B, "Read Page Scan Period Mode"),
    (3, 0x003C, "Write Page Scan Period Mode"),
    (3, 0x003D, "Read Page Scan Mode"),
    (3, 0x003E, "Write Page Scan Mode"),
    (3, 0x0061, "Read Logical Link Accept Timeout"),
    (3, 0x0062, "Write Logical Link Accept Timeout"),
    (3, 0x0064, "Read Location Data"),
    (3, 0x0065, "Write Location Data"),
    (3, 0x0069, "Read Best Effort Flush Timeout"),
    (3, 0x006A, "Write Best Effort Flush Timeout"),
    (3, 0x006B, "Short Range Mode"),
    (5, 0x0009, "Read Local AMP Info"),
    (5, 0x000A, "Read Local AMP ASSOC"),
    (5, 0x000B, "Write Remote AMP ASSOC"),
    (6, 0x0003, "Enable Device Under Test Mode"),
    (6, 0x0007, "Enable AMP Receiver Reports"),
    (6, 0x0008, "AMP Test End"),
    (6, 0x0009, "AMP Test"),
    (6, 0x000B, "Read Secure Connections Test Mode"),
    (8, 0x0025, "LE Read Local P-256 Public Key"),
]

# (code, name) for events no longer present in the current specification.
EXTRA_EVENTS = [
    (0x1F, "Page Scan Mode Change"),
    (0x37, "Simple Pairing Options"),  # never allocated in practice; kept for completeness
    (0x3A, "Reserved"),
    (0x40, "Physical Link Complete"),
    (0x41, "Channel Selected"),
    (0x42, "Disconnection Physical Link Complete"),
    (0x43, "Physical Link Loss Early Warning"),
    (0x44, "Physical Link Recovery"),
    (0x45, "Logical Link Complete"),
    (0x46, "Disconnection Logical Link Complete"),
    (0x47, "Flow Spec Modify Complete"),
    (0x49, "AMP Start Test"),
    (0x4A, "AMP Test End"),
    (0x4B, "AMP Receiver Report"),
    (0x4C, "Short Range Mode Change Complete"),
    (0x4D, "AMP Status Change"),
    (0x50, "Connectionless Peripheral Broadcast Channel Map Change"),
    (0x55, "Slot Availability Mask Change"),  # never allocated; placeholder retained for older tooling
]

# Names that should not be taken from the section title.
EVENT_TITLE_OVERRIDES = {
    "7.7.5": "Disconnection Complete",
}


def const_name(name: str) -> str:
    s = re.sub(r"[^A-Za-z0-9]+", "_", name).strip("_").upper()
    return s


def versioned_names(title: str, found: dict) -> dict:
    """Names by code for the versions of one command or event.

    `found` maps each code to its version number, or None when the reference
    gives none; those are numbered in code order.  Version 1 keeps the plain
    title so that the names of commands and events stay the same when the
    specification adds a version.
    """
    codes = sorted(found)
    names = {}
    for i, c in enumerate(codes):
        ver = found[c] if found[c] is not None else i + 1
        names[c] = title if (len(codes) == 1 or ver == 1) else f"{title} v{ver}"
    return names


def main() -> None:
    sec_re = re.compile(r"^## (7\.\d+(?:\.\d+)+) (.+?) (command|event)  \[(.*?)\]$")
    pair_re = re.compile(r"(HCI_[A-Za-z0-9_\-]+?)(?:\[v(\d+)\])?=(0x[0-9A-Fa-f]{2,4})(?:/(0x[0-9A-Fa-f]{2}))?")

    commands = {}  # opcode -> name
    events = {}
    le_events = {}

    for line in REF.read_text().splitlines():
        m = sec_re.match(line)
        if not m:
            continue
        num, title, kind, pairs = m.groups()
        title = title.strip()
        top = ".".join(num.split(".")[:2])
        if kind == "command":
            ogf = OGF_BY_SECTION.get(top)
            if ogf is None:
                continue
            found = {}
            for _, ver, code, _ in pair_re.findall(pairs):
                if len(code) == 6:
                    found[int(code, 16)] = int(ver) if ver else None
            if not found:
                print(f"warning: no opcode for {num} {title}", file=sys.stderr)
                continue
            for ocf, name in versioned_names(title, found).items():
                commands[(ogf << 10) | ocf] = name
        else:
            if num.startswith("7.7.65."):
                found = {}
                for _, ver, _, sub in pair_re.findall(pairs):
                    if sub:
                        found[int(sub, 16)] = int(ver) if ver else None
                if not found:
                    print(f"warning: no subevent code for {num} {title}", file=sys.stderr)
                le_events.update(versioned_names(title, found))
                continue
            if num.count(".") != 2:
                continue
            found = {}
            for _, ver, code, _ in pair_re.findall(pairs):
                if len(code) == 4 and code.upper() != "0X3E":
                    found[int(code, 16)] = int(ver) if ver else None
            title = EVENT_TITLE_OVERRIDES.get(num, title)
            events.update(versioned_names(title, found))

    for ogf, ocf, name in EXTRA_COMMANDS:
        commands.setdefault((ogf << 10) | ocf, name)
    for code, name in EXTRA_EVENTS:
        events.setdefault(code, name)
    events.setdefault(0x3E, "LE Meta")

    out = []
    w = out.append
    w("//! HCI command opcodes, event codes and LE subevent codes.")
    w("//!")
    w("//! Generated by `tools/gen_hci_ids.py` from the Bluetooth Core Specification")
    w("//! v7.0 (Vol 4, Part E). Do not edit by hand.")
    w("")
    w("/// HCI command opcodes (`OGF << 10 | OCF`).")
    w("pub mod cmd {")
    for op in sorted(commands):
        w(f"    pub const {const_name(commands[op])}: u16 = 0x{op:04x};")
    w("}")
    w("")
    w("/// All known HCI commands as `(opcode, name)`, sorted by opcode.")
    w("pub static COMMANDS: &[(u16, &str)] = &[")
    for op in sorted(commands):
        w(f'    (0x{op:04x}, "{commands[op]}"),')
    w("];")
    w("")
    w("/// HCI event codes.")
    w("pub mod evt {")
    for code in sorted(events):
        w(f"    pub const {const_name(events[code])}: u8 = 0x{code:02x};")
    w("}")
    w("")
    w("/// All known HCI events as `(event code, name)`, sorted by code.")
    w("pub static EVENTS: &[(u8, &str)] = &[")
    for code in sorted(events):
        w(f'    (0x{code:02x}, "{events[code]}"),')
    w("];")
    w("")
    w("/// LE Meta event subevent codes.")
    w("pub mod le_evt {")
    for code in sorted(le_events):
        name = le_events[code]
        if name.startswith("LE "):
            name = name[3:]
        w(f"    pub const {const_name(name)}: u8 = 0x{code:02x};")
    w("}")
    w("")
    w("/// All known LE subevents as `(subevent code, name)`, sorted by code.")
    w("pub static LE_EVENTS: &[(u8, &str)] = &[")
    for code in sorted(le_events):
        w(f'    (0x{code:02x}, "{le_events[code]}"),')
    w("];")
    w("")
    print("\n".join(out))


if __name__ == "__main__":
    main()
