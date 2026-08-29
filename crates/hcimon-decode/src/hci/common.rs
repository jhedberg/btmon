//! Field formatting helpers shared by the HCI decoders.
//!
//! The formats follow btmon so that output is familiar: values are printed as
//! `Label: Meaning (0xNN)`, intervals are converted to milliseconds, and
//! bit masks are expanded into one line per set bit.

use crate::assigned::{appearance_name, company_name, COD_MAJOR, COD_MINOR, COD_MINOR_BITS, COD_SERVICES, COD_SUBMINOR};
use crate::context::IndexState;
use crate::reader::{BdAddr, Reader, Result};
use crate::tree::{Out, Style};
use crate::field;

/// Controller error codes (Core Specification Vol 1, Part F).
pub static ERRORS: &[(u8, &str)] = &[
    (0x00, "Success"),
    (0x01, "Unknown HCI Command"),
    (0x02, "Unknown Connection Identifier"),
    (0x03, "Hardware Failure"),
    (0x04, "Page Timeout"),
    (0x05, "Authentication Failure"),
    (0x06, "PIN or Key Missing"),
    (0x07, "Memory Capacity Exceeded"),
    (0x08, "Connection Timeout"),
    (0x09, "Connection Limit Exceeded"),
    (0x0a, "Synchronous Connection Limit to a Device Exceeded"),
    (0x0b, "Connection Already Exists"),
    (0x0c, "Command Disallowed"),
    (0x0d, "Connection Rejected due to Limited Resources"),
    (0x0e, "Connection Rejected due to Security Reasons"),
    (0x0f, "Connection Rejected due to Unacceptable BD_ADDR"),
    (0x10, "Connection Accept Timeout Exceeded"),
    (0x11, "Unsupported Feature or Parameter Value"),
    (0x12, "Invalid HCI Command Parameters"),
    (0x13, "Remote User Terminated Connection"),
    (0x14, "Remote Device Terminated Connection due to Low Resources"),
    (0x15, "Remote Device Terminated Connection due to Power Off"),
    (0x16, "Connection Terminated by Local Host"),
    (0x17, "Repeated Attempts"),
    (0x18, "Pairing Not Allowed"),
    (0x19, "Unknown LMP PDU"),
    (0x1a, "Unsupported Remote Feature"),
    (0x1b, "SCO Offset Rejected"),
    (0x1c, "SCO Interval Rejected"),
    (0x1d, "SCO Air Mode Rejected"),
    (0x1e, "Invalid LMP Parameters / Invalid LL Parameters"),
    (0x1f, "Unspecified Error"),
    (0x20, "Unsupported LMP Parameter Value / Unsupported LL Parameter Value"),
    (0x21, "Role Change Not Allowed"),
    (0x22, "LMP Response Timeout / LL Response Timeout"),
    (0x23, "LMP Error Transaction Collision / LL Procedure Collision"),
    (0x24, "LMP PDU Not Allowed"),
    (0x25, "Encryption Mode Not Acceptable"),
    (0x26, "Link Key cannot be Changed"),
    (0x27, "Requested QoS Not Supported"),
    (0x28, "Instant Passed"),
    (0x29, "Pairing With Unit Key Not Supported"),
    (0x2a, "Different Transaction Collision"),
    (0x2b, "Reserved for future use"),
    (0x2c, "QoS Unacceptable Parameter"),
    (0x2d, "QoS Rejected"),
    (0x2e, "Channel Assessment Not Supported"),
    (0x2f, "Insufficient Security"),
    (0x30, "Parameter Out of Mandatory Range"),
    (0x31, "Reserved for future use"),
    (0x32, "Role Switch Pending"),
    (0x33, "Reserved for future use"),
    (0x34, "Reserved Slot Violation"),
    (0x35, "Role Switch Failed"),
    (0x36, "Extended Inquiry Response Too Large"),
    (0x37, "Secure Simple Pairing Not Supported by Host"),
    (0x38, "Host Busy - Pairing"),
    (0x39, "Connection Rejected due to No Suitable Channel Found"),
    (0x3a, "Controller Busy"),
    (0x3b, "Unacceptable Connection Parameters"),
    (0x3c, "Advertising Timeout"),
    (0x3d, "Connection Terminated due to MIC Failure"),
    (0x3e, "Connection Failed to be Established / Synchronization Timeout"),
    (0x3f, "Previously used"),
    (0x40, "Coarse Clock Adjustment Rejected but Will Try to Adjust Using Clock Dragging"),
    (0x41, "Type0 Submap Not Defined"),
    (0x42, "Unknown Advertising Identifier"),
    (0x43, "Limit Reached"),
    (0x44, "Operation Cancelled by Host"),
    (0x45, "Packet Too Long"),
    (0x46, "Too Late"),
    (0x47, "Too Early"),
    (0x48, "Insufficient Channels"),
];

pub fn error_str(code: u8) -> &'static str {
    crate::assigned::lookup(ERRORS, code).unwrap_or("Unknown")
}

/// Append `Status: <text> (0xNN)` and return the status.
pub fn status(r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    let s = r.u8()?;
    status_value(out, s);
    Ok(s)
}

pub fn status_value(out: &mut Out, s: u8) {
    let name = crate::assigned::lookup(ERRORS, s);
    match name {
        Some(n) => field!(out, "Status: {} (0x{:02x})", n, s),
        None => out.unknown(format!("Status: Unknown (0x{s:02x})")),
    };
}

/// Append `Reason: <text> (0xNN)`.
pub fn reason(r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    let s = r.u8()?;
    field!(out, "Reason: {} (0x{:02x})", error_str(s), s);
    Ok(s)
}

/// Read a connection handle (12 significant bits).
pub fn read_handle(r: &mut Reader<'_>) -> Result<u16> {
    Ok(r.u16()? & 0x0fff)
}

/// Append `Handle: N` (with the peer address if the connection is known) and return the handle.
pub fn handle(st: &IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<u16> {
    let h = read_handle(r)?;
    handle_value(st, out, h);
    Ok(h)
}

pub fn handle_value(st: &IndexState, out: &mut Out, h: u16) {
    handle_labelled_value("Handle", st, out, h);
}

/// A connection handle with a custom label (`CIS Handle: 3`), with the peer address when known.
pub fn handle_labelled(label: &str, st: &IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<u16> {
    let h = read_handle(r)?;
    handle_labelled_value(label, st, out, h);
    Ok(h)
}

pub fn handle_labelled_value(label: &str, st: &IndexState, out: &mut Out, h: u16) {
    match st.conn(h) {
        Some(c) if !c.addr.is_zero() => {
            field!(out, "{}: {} Address: {} ({})", label, h, c.addr, addr_type_short(c.addr_type, &c.addr))
        }
        _ => field!(out, "{}: {}", label, h),
    };
}

/// `Status` followed by a connection handle.
pub fn status_handle(st: &IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    status(r, out)?;
    handle(st, r, out)?;
    Ok(())
}

/// Print the status and report whether nothing follows it (a failed command
/// may return only the status byte).
pub fn status_only(r: &mut Reader<'_>, out: &mut Out) -> Result<bool> {
    status(r, out)?;
    Ok(r.is_empty())
}

/// `Sync handle: 0xNNNN` (periodic advertising train identifier, 12 significant bits).
pub fn sync_handle(r: &mut Reader<'_>, out: &mut Out) -> Result<u16> {
    let h = read_handle(r)?;
    field!(out, "Sync handle: 0x{:04x}", h);
    Ok(h)
}

/// Short description of an address type for inline use.
pub fn addr_type_short(addr_type: u8, addr: &BdAddr) -> &'static str {
    match addr_type {
        0x00 => "Public",
        0x01 => match addr.msb2() {
            0b00 => "Non-Resolvable",
            0b01 => "Resolvable",
            0b11 => "Static",
            _ => "Reserved",
        },
        0x02 => "Public Identity",
        0x03 => "Random Identity",
        0xff => "Unresolved",
        _ => "Unknown",
    }
}

pub fn addr_type_str(t: u8) -> &'static str {
    match t {
        0x00 => "Public",
        0x01 => "Random",
        0x02 => "Public Identity",
        0x03 => "Random (Static) Identity",
        0xff => "Unresolved",
        _ => "Reserved",
    }
}

/// Append `Address type: <text> (0xNN)` and return it.
pub fn addr_type(r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    addr_type_labelled("Address type", r, out)
}

pub fn addr_type_labelled(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    let t = r.u8()?;
    match t {
        0x00..=0x03 | 0xff => field!(out, "{}: {} (0x{:02x})", label, addr_type_str(t), t),
        _ => out.unknown(format!("{label}: Reserved (0x{t:02x})")),
    };
    Ok(t)
}

/// Append `Address: XX:XX:XX:XX:XX:XX (<kind>)` for an address of the given HCI type.
pub fn bdaddr_typed(label: &str, addr_type: u8, r: &mut Reader<'_>, out: &mut Out) -> Result<BdAddr> {
    let a = r.bdaddr()?;
    bdaddr_value(label, addr_type, out, &a);
    Ok(a)
}

pub fn bdaddr_value(label: &str, addr_type: u8, out: &mut Out, a: &BdAddr) {
    match addr_type {
        0x00 | 0x02 => field!(out, "{}: {} ({})", label, a, oui_str(a)),
        0x01 | 0x03 => match a.msb2() {
            0b00 => field!(out, "{}: {} (Non-Resolvable)", label, a),
            0b01 => field!(out, "{}: {} (Resolvable)", label, a),
            0b11 => field!(out, "{}: {} (Static)", label, a),
            _ => field!(out, "{}: {} (Reserved)", label, a),
        },
        _ => field!(out, "{}: {}", label, a),
    };
}

/// Append a BR/EDR (public) address.
pub fn bdaddr(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<BdAddr> {
    bdaddr_typed(label, 0x00, r, out)
}

/// Read address type and address, printing both (`Address type` first as in btmon).
pub fn peer_addr(r: &mut Reader<'_>, out: &mut Out) -> Result<(u8, BdAddr)> {
    let t = addr_type(r, out)?;
    let a = bdaddr_typed("Address", t, r, out)?;
    Ok((t, a))
}

/// Same as [`peer_addr`] with custom labels, e.g. `Peer address type` / `Peer address`.
pub fn peer_addr_labelled(type_label: &str, addr_label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<(u8, BdAddr)> {
    let t = addr_type_labelled(type_label, r, out)?;
    let a = bdaddr_typed(addr_label, t, r, out)?;
    Ok((t, a))
}

/// Organisation name derived from the OUI (upper three bytes) of a public address.
///
/// No OUI database is bundled; the text is a placeholder that keeps the btmon
/// layout (`Address: ... (OUI 00-1A-7D)`).
pub fn oui_str(a: &BdAddr) -> String {
    format!("OUI {:02X}-{:02X}-{:02X}", a.0[5], a.0[4], a.0[3])
}

/// `Enabled` / `Disabled`.
pub fn enable(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    let v = r.u8()?;
    match v {
        0x00 => field!(out, "{}: Disabled (0x00)", label),
        0x01 => field!(out, "{}: Enabled (0x01)", label),
        _ => out.unknown(format!("{label}: Reserved (0x{v:02x})")),
    };
    Ok(v)
}

/// Print a one-byte enumeration using a lookup table; unknown values are flagged.
pub fn enum8(label: &str, r: &mut Reader<'_>, out: &mut Out, names: &[(u8, &str)]) -> Result<u8> {
    let v = r.u8()?;
    enum8_value(label, out, v, names);
    Ok(v)
}

pub fn enum8_value(label: &str, out: &mut Out, v: u8, names: &[(u8, &str)]) {
    match names.iter().find(|(k, _)| *k == v) {
        Some((_, n)) => field!(out, "{}: {} (0x{:02x})", label, n, v),
        None => out.unknown(format!("{label}: Reserved (0x{v:02x})")),
    };
}

/// Print a two-byte enumeration using a lookup table.
pub fn enum16(label: &str, r: &mut Reader<'_>, out: &mut Out, names: &[(u16, &str)]) -> Result<u16> {
    let v = r.u16()?;
    match names.iter().find(|(k, _)| *k == v) {
        Some((_, n)) => field!(out, "{}: {} (0x{:04x})", label, n, v),
        None => out.unknown(format!("{label}: Reserved (0x{v:04x})")),
    };
    Ok(v)
}

/// Print a plain decimal 8-bit value.
pub fn u8_field(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    let v = r.u8()?;
    field!(out, "{}: {}", label, v);
    Ok(v)
}

/// Print a plain decimal 16-bit value.
pub fn u16_field(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<u16> {
    let v = r.u16()?;
    field!(out, "{}: {}", label, v);
    Ok(v)
}

/// Print a plain decimal 32-bit value.
pub fn u32_field(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<u32> {
    let v = r.u32()?;
    field!(out, "{}: {}", label, v);
    Ok(v)
}

/// Print an 8-bit value as `0xNN`.
pub fn u8_hex(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    let v = r.u8()?;
    field!(out, "{}: 0x{:02x}", label, v);
    Ok(v)
}

/// Print a 16-bit value as `N (0xNNNN)`.
pub fn u16_hex(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<u16> {
    let v = r.u16()?;
    field!(out, "{}: {} (0x{:04x})", label, v, v);
    Ok(v)
}

/// Print a 32-bit value as `0xNNNNNNNN`.
pub fn u32_hex(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<u32> {
    let v = r.u32()?;
    field!(out, "{}: 0x{:08x}", label, v);
    Ok(v)
}

/// Print a value in units of `unit_us` microseconds as milliseconds: `Interval: 24.000 msec (0x0018)`.
pub fn interval(label: &str, r: &mut Reader<'_>, out: &mut Out, unit_us: u32) -> Result<u16> {
    let v = r.u16()?;
    interval_value(label, out, v as u32, unit_us, 4);
    Ok(v)
}

/// Print a 24-bit interval (used by ISO parameters, unit is 1 µs).
pub fn interval24(label: &str, r: &mut Reader<'_>, out: &mut Out, unit_us: u32) -> Result<u32> {
    let v = r.u24()?;
    interval_value(label, out, v, unit_us, 6);
    Ok(v)
}

pub fn interval_value(label: &str, out: &mut Out, v: u32, unit_us: u32, hex_width: usize) {
    let us = v as u64 * unit_us as u64;
    field!(out, "{}: {}.{:03} msec (0x{:0w$x})", label, us / 1000, us % 1000, v, w = hex_width);
}

/// Print a timeout in units of `unit_ms` milliseconds: `Timeout: 420 msec (0x002a)`.
pub fn timeout_ms(label: &str, r: &mut Reader<'_>, out: &mut Out, unit_ms: u32) -> Result<u16> {
    let v = r.u16()?;
    field!(out, "{}: {} msec (0x{:04x})", label, v as u32 * unit_ms, v);
    Ok(v)
}

/// Print a slot count in 0.625 ms units: `Interval: 1280.000 msec (0x0800)`.
pub fn slots(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<u16> {
    interval(label, r, out, 625)
}

/// Print a 3-byte slot count in 0.625 ms units (extended advertising intervals).
pub fn slots24(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<u32> {
    interval24(label, r, out, 625)
}

/// `Label: N us (0xNNNN)` for 16-bit microsecond values.
pub fn usec16(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<u16> {
    let v = r.u16()?;
    field!(out, "{}: {} us (0x{:04x})", label, v, v);
    Ok(v)
}

/// `Label: N us (0xNNNNNN)` for 24-bit microsecond values.
pub fn usec24(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<u32> {
    let v = r.u24()?;
    field!(out, "{}: {} us (0x{:06x})", label, v, v);
    Ok(v)
}

/// `Label: N ms (0xNNNN)` for 16-bit millisecond values.
pub fn ms16(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<u16> {
    let v = r.u16()?;
    field!(out, "{}: {} ms (0x{:04x})", label, v, v);
    Ok(v)
}

/// `Label: N seconds (0xNNNN)`.
pub fn seconds16(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<u16> {
    let v = r.u16()?;
    field!(out, "{}: {} seconds (0x{:04x})", label, v, v);
    Ok(v)
}

/// Print an RSSI value.
pub fn rssi(r: &mut Reader<'_>, out: &mut Out) -> Result<i8> {
    let v = r.i8()?;
    rssi_value("RSSI", out, v);
    Ok(v)
}

pub fn rssi_value(label: &str, out: &mut Out, v: i8) {
    match v {
        127 => field!(out, "{}: not available (0x7f)", label),
        _ => field!(out, "{}: {} dBm (0x{:02x})", label, v, v as u8),
    };
}

/// RSSI with a custom label.
pub fn rssi_labelled(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<i8> {
    let v = r.i8()?;
    rssi_value(label, out, v);
    Ok(v)
}

/// `Label: N dbm (0xNN)` without any special values (see [`tx_power`] for those).
pub fn power_dbm(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<i8> {
    let v = r.i8()?;
    field!(out, "{}: {} dbm (0x{:02x})", label, v, v as u8);
    Ok(v)
}

/// Print a TX power level.
pub fn tx_power(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<i8> {
    let v = r.i8()?;
    match v {
        127 => field!(out, "{}: Host has no preference (0x7f)", label),
        126 => field!(out, "{}: Not available (0x7e)", label),
        _ => field!(out, "{}: {} dbm (0x{:02x})", label, v, v as u8),
    };
    Ok(v)
}

/// Print a fixed-length key/random value as hex.
pub fn hex_bytes(label: &str, r: &mut Reader<'_>, out: &mut Out, len: usize) -> Result<()> {
    let b = r.bytes(len)?;
    out.hex_field(label, b);
    Ok(())
}

/// Compact lowercase hex without separators (`4c683841...`).
pub fn hexstr(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Print a 16-byte key in the compact btmon style (`Long term key: 4c68384139f574d836bcf34e9dfb01bf`).
pub fn key128(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let b = r.bytes(16)?;
    field!(out, "{}: {}", label, hexstr(b));
    Ok(())
}

/// `Random number: 0x0102030405060708` (64-bit).
pub fn random_number(r: &mut Reader<'_>, out: &mut Out) -> Result<u64> {
    let v = r.u64()?;
    field!(out, "Random number: 0x{:016x}", v);
    Ok(v)
}

/// Print a name/string field of `len` bytes (NUL padded).
pub fn name(label: &str, r: &mut Reader<'_>, out: &mut Out, len: usize) -> Result<String> {
    let s = r.fixed_str(len)?;
    field!(out, "{}: {}", label, s);
    Ok(s)
}

/// Company identifier: `Manufacturer: Nordic Semiconductor ASA (89)`.
pub fn manufacturer(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<u16> {
    let v = r.u16()?;
    manufacturer_value(label, out, v);
    Ok(v)
}

pub fn manufacturer_value(label: &str, out: &mut Out, v: u16) {
    match company_name(v) {
        Some(n) => field!(out, "{}: {} ({})", label, n, v),
        None => out.unknown(format!("{label}: Unknown ({v})")),
    };
}

/// HCI / LMP / LL version numbers to Bluetooth versions.
pub fn version_str(v: u8) -> &'static str {
    match v {
        0 => "Bluetooth 1.0b",
        1 => "Bluetooth 1.1",
        2 => "Bluetooth 1.2",
        3 => "Bluetooth 2.0",
        4 => "Bluetooth 2.1",
        5 => "Bluetooth 3.0",
        6 => "Bluetooth 4.0",
        7 => "Bluetooth 4.1",
        8 => "Bluetooth 4.2",
        9 => "Bluetooth 5.0",
        10 => "Bluetooth 5.1",
        11 => "Bluetooth 5.2",
        12 => "Bluetooth 5.3",
        13 => "Bluetooth 5.4",
        14 => "Bluetooth 6.0",
        15 => "Bluetooth 6.1",
        16 => "Bluetooth 6.2",
        17 => "Bluetooth 6.3",
        _ => "Reserved",
    }
}

pub fn version(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    let v = r.u8()?;
    match version_str(v) {
        "Reserved" => out.unknown(format!("{label}: Reserved (0x{v:02x})")),
        s => field!(out, "{}: {} (0x{:02x})", label, s, v),
    };
    Ok(v)
}

/// LE PHY names for the 1-based values used in most commands.
pub fn phy_str(phy: u8) -> &'static str {
    match phy {
        0x01 => "LE 1M",
        0x02 => "LE 2M",
        0x03 => "LE Coded",
        0x04 => "LE Coded with S=2",
        _ => "Reserved",
    }
}

pub fn phy(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    let v = r.u8()?;
    match phy_str(v) {
        "Reserved" => out.unknown(format!("{label}: Reserved (0x{v:02x})")),
        s => field!(out, "{}: {} (0x{:02x})", label, s, v),
    };
    Ok(v)
}

/// Expand a PHY bit mask (`LE 1M`, `LE 2M`, `LE Coded`).
pub fn phy_mask(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    let v = r.u8()?;
    field!(out, "{}: 0x{:02x}", label, v);
    out.nest(|o| {
        bits(o, v as u64, &[(0, "LE 1M"), (1, "LE 2M"), (2, "LE Coded")], 3);
    });
    Ok(v)
}

/// Append one child line per set bit in `mask`; bits at or above `known` without a name are flagged.
pub fn bits(out: &mut Out, mask: u64, names: &[(u8, &str)], known: u8) {
    for bit in 0..64u8 {
        if mask & (1u64 << bit) == 0 {
            continue;
        }
        match names.iter().find(|(b, _)| *b == bit) {
            Some((_, n)) => out.line(*n),
            None if bit < known => out.unknown(format!("Reserved (0x{:x})", 1u64 << bit)),
            None => out.unknown(format!("Unknown bit {bit}")),
        };
    }
}

/// One-byte bit mask: `Label: 0xNN` followed by one child per set bit (see [`bits`] for `known`).
pub fn mask8(label: &str, r: &mut Reader<'_>, out: &mut Out, names: &[(u8, &str)], known: u8) -> Result<u8> {
    let v = r.u8()?;
    field!(out, "{}: 0x{:02x}", label, v);
    out.nest(|o| bits(o, v as u64, names, known));
    Ok(v)
}

/// Two-byte bit mask: `Label: 0xNNNN` followed by one child per set bit.
pub fn mask16(label: &str, r: &mut Reader<'_>, out: &mut Out, names: &[(u8, &str)], known: u8) -> Result<u16> {
    let v = r.u16()?;
    field!(out, "{}: 0x{:04x}", label, v);
    out.nest(|o| bits(o, v as u64, names, known));
    Ok(v)
}

/// `Role: Central (0x00)` / `Peripheral (0x01)`.
pub fn role(r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    enum8("Role", r, out, &[(0x00, "Central"), (0x01, "Peripheral")])
}

/// Link type used by connection events.
pub fn link_type(r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    enum8("Link type", r, out, &[(0x00, "SCO"), (0x01, "ACL"), (0x02, "eSCO")])
}

/// Print a Class of Device with its decoded service and device classes.
pub fn class_of_device(r: &mut Reader<'_>, out: &mut Out) -> Result<u32> {
    let cod = r.u24()?;
    class_of_device_value(out, cod);
    Ok(cod)
}

pub fn class_of_device_value(out: &mut Out, cod: u32) {
    field!(out, "Class: 0x{:06x}", cod);
    out.nest(|o| {
        let major = ((cod >> 8) & 0x1f) as u8;
        let minor = ((cod >> 2) & 0x3f) as u8;
        let major_name = crate::assigned::lookup(COD_MAJOR, major);
        match major_name {
            Some(n) => o.line(format!("Major class: {n}")),
            None => o.unknown(format!("Major class: Reserved (0x{major:02x})")),
        };
        let minor_text = match major {
            // LAN/Network access point: upper 3 bits are load factor, lower 3 reserved.
            0x03 => COD_MINOR.iter().find(|(m, v, _)| *m == major && *v == minor >> 3).map(|(_, _, n)| n.to_string()),
            // Peripheral: bits 7-6 keyboard/pointing device, bits 5-2 the device type.
            0x05 => {
                let kind = COD_MINOR.iter().find(|(m, v, _)| *m == major && *v == minor >> 4).map(|(_, _, n)| *n);
                let sub = COD_SUBMINOR.iter().find(|(m, v, _)| *m == major && *v == minor & 0x0f).map(|(_, _, n)| *n);
                match (kind, sub) {
                    (Some(k), Some(s)) => Some(format!("{k} ({s})")),
                    (Some(k), None) => Some(k.to_string()),
                    (None, Some(s)) => Some(s.to_string()),
                    (None, None) => None,
                }
            }
            // Imaging: bits 7-4 are capability flags.
            0x06 => {
                let flags: Vec<&str> = COD_MINOR_BITS
                    .iter()
                    .filter(|(m, b, _)| *m == major && minor & (1 << (*b as u8 - 2)) != 0)
                    .map(|(_, _, n)| *n)
                    .collect();
                if flags.is_empty() {
                    None
                } else {
                    Some(flags.join(", "))
                }
            }
            _ => COD_MINOR.iter().find(|(m, v, _)| *m == major && *v == minor).map(|(_, _, n)| n.to_string()),
        };
        match minor_text {
            Some(t) => o.line(format!("Minor class: {t}")),
            None => o.unknown(format!("Minor class: Reserved (0x{minor:02x})")),
        };
        for bit in 13..24u8 {
            if cod & (1 << bit) != 0 {
                match crate::assigned::lookup(COD_SERVICES, bit) {
                    Some(n) => o.line(n),
                    None => o.unknown(format!("Reserved service bit {bit}")),
                };
            }
        }
    });
}

/// Bluetooth clock value in 312.5 µs units (28 bits).
pub fn clock(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<u32> {
    let v = r.u32()?;
    field!(out, "{}: 0x{:08x}", label, v);
    Ok(v)
}

/// LE feature bit names (Core Specification Vol 6, Part B, Section 4.6).
pub static LE_FEATURES: &[(u8, &str)] = &[
    (0, "LE Encryption"),
    (1, "Connection Parameter Request Procedure"),
    (2, "Extended Reject Indication"),
    (3, "Peripheral-initiated Features Exchange"),
    (4, "LE Ping"),
    (5, "LE Data Packet Length Extension"),
    (6, "LL Privacy"),
    (7, "Extended Scanner Filter Policies"),
    (8, "LE 2M PHY"),
    (9, "Stable Modulation Index - Transmitter"),
    (10, "Stable Modulation Index - Receiver"),
    (11, "LE Coded PHY"),
    (12, "LE Extended Advertising"),
    (13, "LE Periodic Advertising"),
    (14, "Channel Selection Algorithm #2"),
    (15, "LE Power Class 1"),
    (16, "Minimum Number of Used Channels Procedure"),
    (17, "Connection CTE Request"),
    (18, "Connection CTE Response"),
    (19, "Connectionless CTE Transmitter"),
    (20, "Connectionless CTE Receiver"),
    (21, "Antenna Switching During CTE Transmission (AoD)"),
    (22, "Antenna Switching During CTE Reception (AoA)"),
    (23, "Receiving Constant Tone Extensions"),
    (24, "Periodic Advertising Sync Transfer - Sender"),
    (25, "Periodic Advertising Sync Transfer - Recipient"),
    (26, "Sleep Clock Accuracy Updates"),
    (27, "Remote Public Key Validation"),
    (28, "Connected Isochronous Stream - Central"),
    (29, "Connected Isochronous Stream - Peripheral"),
    (30, "Isochronous Broadcaster"),
    (31, "Synchronized Receiver"),
    (32, "Connected Isochronous Stream (Host Support)"),
    (33, "LE Power Control Request"),
    (34, "LE Power Control Request"),
    (35, "LE Path Loss Monitoring"),
    (36, "Periodic Advertising ADI support"),
    (37, "Connection Subrating"),
    (38, "Connection Subrating (Host Support)"),
    (39, "Channel Classification"),
    (40, "Advertising Coding Selection"),
    (41, "Advertising Coding Selection (Host Support)"),
    (42, "Decision-Based Advertising Filtering"),
    (43, "Periodic Advertising with Responses - Advertiser"),
    (44, "Periodic Advertising with Responses - Scanner"),
    (45, "Unsegmented Framed Mode"),
    (46, "Channel Sounding"),
    (47, "Channel Sounding (Host Support)"),
    (48, "Channel Sounding Tone Quality Indication"),
    (63, "LL Extended Feature Set"),
];

/// LE feature bits of page 1 (bits 64..127 of the extended feature set), numbered from 0.
pub static LE_FEATURES_PAGE1: &[(u8, &str)] = &[
    (0, "Monitoring Advertisers"),
    (1, "Frame Space Update"),
    (2, "UTP OTA mode"),
    (3, "UTP HCI mode"),
    (8, "Shorter Connection Intervals"),
    (9, "Shorter Connection Intervals (Host Support)"),
    (10, "LE Flushable ACL Data"),
    (11, "Channel Sounding Enhancement #1"),
];

/// Print an 8-byte LE feature mask with its bits expanded.
pub fn le_features(label: &str, r: &mut Reader<'_>, out: &mut Out, page: u8) -> Result<u64> {
    let b = r.array::<8>()?;
    let mask = u64::from_le_bytes(b);
    let hex: Vec<String> = b.iter().map(|x| format!("0x{x:02x}")).collect();
    field!(out, "{}: {}", label, hex.join(" "));
    out.nest(|o| match page {
        0 => bits(o, mask, LE_FEATURES, 64),
        1 => bits(o, mask, LE_FEATURES_PAGE1, 64),
        _ => bits(o, mask, &[], 64),
    });
    Ok(mask)
}

/// LMP feature bit names, page 0 (Core Specification Vol 2, Part C, Section 3.3).
pub static LMP_FEATURES_PAGE0: &[(u8, &str)] = &[
    (0, "3 slot packets"),
    (1, "5 slot packets"),
    (2, "Encryption"),
    (3, "Slot offset"),
    (4, "Timing accuracy"),
    (5, "Role switch"),
    (6, "Hold mode"),
    (7, "Sniff mode"),
    (8, "Park state"),
    (9, "Power control requests"),
    (10, "Channel quality driven data rate (CQDDR)"),
    (11, "SCO link"),
    (12, "HV2 packets"),
    (13, "HV3 packets"),
    (14, "u-law log synchronous data"),
    (15, "A-law log synchronous data"),
    (16, "CVSD synchronous data"),
    (17, "Paging parameter negotiation"),
    (18, "Power control"),
    (19, "Transparent synchronous data"),
    (20, "Flow control lag (least significant bit)"),
    (21, "Flow control lag (middle bit)"),
    (22, "Flow control lag (most significant bit)"),
    (23, "Broadcast Encryption"),
    (25, "Enhanced Data Rate ACL 2 Mb/s mode"),
    (26, "Enhanced Data Rate ACL 3 Mb/s mode"),
    (27, "Enhanced inquiry scan"),
    (28, "Interlaced inquiry scan"),
    (29, "Interlaced page scan"),
    (30, "RSSI with inquiry results"),
    (31, "Extended SCO link (EV3 packets)"),
    (32, "EV4 packets"),
    (33, "EV5 packets"),
    (35, "AFH capable peripheral"),
    (36, "AFH classification peripheral"),
    (37, "BR/EDR Not Supported"),
    (38, "LE Supported (Controller)"),
    (39, "3-slot Enhanced Data Rate ACL packets"),
    (40, "5-slot Enhanced Data Rate ACL packets"),
    (41, "Sniff subrating"),
    (42, "Pause encryption"),
    (43, "AFH capable central"),
    (44, "AFH classification central"),
    (45, "Enhanced Data Rate eSCO 2 Mb/s mode"),
    (46, "Enhanced Data Rate eSCO 3 Mb/s mode"),
    (47, "3-slot Enhanced Data Rate eSCO packets"),
    (48, "Extended Inquiry Response"),
    (49, "Simultaneous LE and BR/EDR (Controller)"),
    (51, "Secure Simple Pairing (Controller Support)"),
    (52, "Encapsulated PDU"),
    (53, "Erroneous Data Reporting"),
    (54, "Non-flushable Packet Boundary Flag"),
    (56, "HCI Link Supervision Timeout Changed event"),
    (57, "Variable Inquiry TX Power Level"),
    (58, "Enhanced Power Control"),
    (63, "Extended features"),
];

pub static LMP_FEATURES_PAGE1: &[(u8, &str)] = &[
    (0, "Secure Simple Pairing (Host Support)"),
    (1, "LE Supported (Host)"),
    (2, "Simultaneous LE and BR/EDR (Host)"),
    (3, "Secure Connections (Host Support)"),
];

pub static LMP_FEATURES_PAGE2: &[(u8, &str)] = &[
    (0, "Connectionless Peripheral Broadcast - Transmitter Operation"),
    (1, "Connectionless Peripheral Broadcast - Receiver Operation"),
    (2, "Synchronization Train"),
    (3, "Synchronization Scan"),
    (4, "HCI Inquiry Response Notification event"),
    (5, "Generalized interlaced scan"),
    (6, "Coarse Clock Adjustment"),
    (8, "Secure Connections (Controller Support)"),
    (9, "Ping"),
    (10, "Slot Availability Mask"),
    (11, "Train nudging"),
];

/// Print an 8-byte LMP feature mask for the given page.
pub fn lmp_features(label: &str, r: &mut Reader<'_>, out: &mut Out, page: u8) -> Result<u64> {
    let b = r.array::<8>()?;
    let mask = u64::from_le_bytes(b);
    let hex: Vec<String> = b.iter().map(|x| format!("0x{x:02x}")).collect();
    field!(out, "{}: {}", label, hex.join(" "));
    out.nest(|o| match page {
        0 => bits(o, mask, LMP_FEATURES_PAGE0, 64),
        1 => bits(o, mask, LMP_FEATURES_PAGE1, 64),
        2 => bits(o, mask, LMP_FEATURES_PAGE2, 64),
        _ => bits(o, mask, &[], 64),
    });
    Ok(mask)
}

/// Append a `Style::Unknown` line for a reserved/unrecognised numeric value.
pub fn reserved(out: &mut Out, label: &str, v: u32, width: usize) {
    out.styled(Style::Unknown, format!("{label}: Reserved (0x{v:0width$x})"));
}

// ---------------------------------------------------------------------------
// BR/EDR fields shared by commands and events
// ---------------------------------------------------------------------------

/// ACL packet type bit mask (Create Connection, Connection Packet Type Changed, ...).
/// The EDR bits are inverted: set means the packet type may *not* be used.
pub static PKT_TYPE_ACL: &[(u8, &str)] = &[
    (1, "2-DH1 may not be used"),
    (2, "3-DH1 may not be used"),
    (3, "DM1 may be used"),
    (4, "DH1 may be used"),
    (8, "2-DH3 may not be used"),
    (9, "3-DH3 may not be used"),
    (10, "DM3 may be used"),
    (11, "DH3 may be used"),
    (12, "2-DH5 may not be used"),
    (13, "3-DH5 may not be used"),
    (14, "DM5 may be used"),
    (15, "DH5 may be used"),
];

/// Synchronous packet type bit mask (Setup Synchronous Connection, ...).
pub static PKT_TYPE_SCO: &[(u8, &str)] = &[
    (0, "HV1 may be used"),
    (1, "HV2 may be used"),
    (2, "HV3 may be used"),
    (3, "EV3 may be used"),
    (4, "EV4 may be used"),
    (5, "EV5 may be used"),
    (6, "2-EV3 may not be used"),
    (7, "3-EV3 may not be used"),
    (8, "2-EV5 may not be used"),
    (9, "3-EV5 may not be used"),
];

/// `Packet type: 0xNNNN` expanded one line per bit of `table`; unknown bits are flagged.
pub fn pkt_type(r: &mut Reader<'_>, out: &mut Out, table: &[(u8, &str)]) -> Result<u16> {
    let mask = r.u16()?;
    field!(out, "Packet type: 0x{:04x}", mask);
    out.nest(|o| {
        let mut unknown = mask;
        for (bit, name) in table {
            if mask & (1 << bit) != 0 {
                o.line(*name);
                unknown &= !(1 << bit);
            }
        }
        if unknown != 0 {
            o.unknown(format!("Unknown packet types (0x{unknown:04x})"));
        }
    });
    Ok(mask)
}

pub fn pkt_type_acl(r: &mut Reader<'_>, out: &mut Out) -> Result<u16> {
    pkt_type(r, out, PKT_TYPE_ACL)
}

pub fn pkt_type_sco(r: &mut Reader<'_>, out: &mut Out) -> Result<u16> {
    pkt_type(r, out, PKT_TYPE_SCO)
}

pub fn pscan_rep_mode(r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    enum8("Page scan repetition mode", r, out, &[(0x00, "R0"), (0x01, "R1"), (0x02, "R2")])
}

/// Page scan mode (reserved in current specifications, formerly Page_Scan_Mode).
pub fn pscan_mode(r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    enum8(
        "Page scan mode",
        r,
        out,
        &[(0x00, "Mandatory"), (0x01, "Optional I"), (0x02, "Optional II"), (0x03, "Optional III")],
    )
}

pub fn pscan_period_mode(r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    enum8("Page period mode", r, out, &[(0x00, "P0"), (0x01, "P1"), (0x02, "P2")])
}

pub fn clock_offset(r: &mut Reader<'_>, out: &mut Out) -> Result<u16> {
    let v = r.u16()?;
    field!(out, "Clock offset: 0x{:04x}", v);
    Ok(v)
}

pub fn lt_addr(r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    u8_field("LT address", r, out)
}

/// QoS service type (HCI QoS Setup / Flow Specification and the L2CAP QoS option).
pub fn service_type(r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    enum8("Service type", r, out, &[(0x00, "No Traffic"), (0x01, "Best Effort"), (0x02, "Guaranteed")])
}

/// Secure Simple Pairing IO capability.
pub fn io_capability(r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    enum8(
        "IO capability",
        r,
        out,
        &[(0x00, "DisplayOnly"), (0x01, "DisplayYesNo"), (0x02, "KeyboardOnly"), (0x03, "NoInputNoOutput")],
    )
}

/// Secure Simple Pairing authentication requirements.
pub fn authentication(r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    enum8(
        "Authentication",
        r,
        out,
        &[
            (0x00, "No Bonding - MITM not required"),
            (0x01, "No Bonding - MITM required"),
            (0x02, "Dedicated Bonding - MITM not required"),
            (0x03, "Dedicated Bonding - MITM required"),
            (0x04, "General Bonding - MITM not required"),
            (0x05, "General Bonding - MITM required"),
        ],
    )
}

/// Coding format identifiers (Assigned Numbers, "Coding Format").
pub static CODING_FORMATS: &[(u8, &str)] = &[
    (0x00, "u-law log"),
    (0x01, "A-law log"),
    (0x02, "CVSD"),
    (0x03, "Transparent"),
    (0x04, "Linear PCM"),
    (0x05, "mSBC"),
    (0x06, "LC3"),
    (0x07, "G.729A"),
    (0xff, "Vendor specific"),
];

/// Split channels 0..=78 of a 79-channel AFH map into runs of equal bit value: `(first, last, set)`.
pub fn afh_channel_ranges(map: &[u8; 10]) -> Vec<(u8, u8, bool)> {
    let mut ranges = Vec::new();
    let mut start = 0u8;
    let mut current = map[0] & 1 != 0;
    for ch in 1..79u8 {
        let set = map[(ch / 8) as usize] & (1 << (ch % 8)) != 0;
        if set != current {
            ranges.push((start, ch - 1, current));
            start = ch;
            current = set;
        }
    }
    ranges.push((start, 78, current));
    ranges
}

/// 79-channel AFH channel map (10 bytes): `Channel map: 0x...` with the ranges of set channels nested.
pub fn afh_channel_map(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let map = r.array::<10>()?;
    field!(out, "Channel map: 0x{}", hexstr(&map));
    out.nest(|o| {
        for (start, end, set) in afh_channel_ranges(&map) {
            if !set {
                continue;
            }
            if start == end {
                o.line(format!("Channel {start}"));
            } else {
                o.line(format!("Channel {start}-{end}"));
            }
        }
        if map[9] & 0x80 != 0 {
            o.unknown("Reserved bit 79 set");
        }
    });
    Ok(())
}

// ---------------------------------------------------------------------------
// LE fields shared by commands and events
// ---------------------------------------------------------------------------

/// `Own address type: Public (0x00)`.
pub fn own_addr_type(r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    enum8(
        "Own address type",
        r,
        out,
        &[(0x00, "Public"), (0x01, "Random"), (0x02, "Resolvable or Public"), (0x03, "Resolvable or Random")],
    )
}

/// Primary advertising channel map: `Channel map: 37, 38, 39 (0x07)`.
pub fn adv_channel_map(r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    enum8(
        "Channel map",
        r,
        out,
        &[(0x01, "37"), (0x02, "38"), (0x03, "37, 38"), (0x04, "39"), (0x05, "37, 39"), (0x06, "38, 39"), (0x07, "37, 38, 39")],
    )
}

/// Advertising filter policy of the legacy and extended advertising parameter commands.
pub fn adv_filter_policy(r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    enum8(
        "Filter policy",
        r,
        out,
        &[
            (0x00, "Allow Scan Request from Any, Allow Connect Request from Any"),
            (0x01, "Allow Scan Request from Accept List Only, Allow Connect Request from Any"),
            (0x02, "Allow Scan Request from Any, Allow Connect Request from Accept List Only"),
            (0x03, "Allow Scan Request from Accept List Only, Allow Connect Request from Accept List Only"),
        ],
    )
}

/// Advertising_Event_Properties bits (LE Set Extended Advertising Parameters v1 and v2).
pub static EXT_ADV_PROPERTIES: &[(u8, &str)] = &[
    (0, "Connectable"),
    (1, "Scannable"),
    (2, "Directed"),
    (3, "High Duty Cycle Directed Connectable"),
    (4, "Use legacy advertising PDUs"),
    (5, "Anonymous advertising"),
    (6, "Include TxPower"),
    (7, "Use decision PDUs"),
    (8, "Include AdvA in decision PDUs"),
    (9, "Include ADI in decision PDUs"),
];

/// Name of the legacy PDU selected by the low bits of Advertising_Event_Properties.
fn legacy_pdu_name(props: u16) -> &'static str {
    match props & 0x7f {
        0x10 => "ADV_NONCONN_IND",
        0x12 => "ADV_SCAN_IND",
        0x13 => "ADV_IND",
        0x15 => "ADV_DIRECT_IND (low duty cycle)",
        0x1d => "ADV_DIRECT_IND (high duty cycle)",
        _ => "Reserved",
    }
}

/// `Properties: 0xNNNN` with one line per set [`EXT_ADV_PROPERTIES`] bit; the legacy PDU bit names the PDU type.
pub fn ext_adv_properties(r: &mut Reader<'_>, out: &mut Out) -> Result<u16> {
    let v = r.u16()?;
    field!(out, "Properties: 0x{:04x}", v);
    out.nest(|o| {
        for (bit, name) in EXT_ADV_PROPERTIES {
            if v & (1 << bit) == 0 {
                continue;
            }
            if *bit == 4 {
                o.line(format!("{name}: {}", legacy_pdu_name(v)));
            } else {
                o.line(*name);
            }
        }
        let unknown = v & !0x03ff;
        if unknown != 0 {
            o.unknown(format!("Unknown advertising properties (0x{unknown:04x})"));
        }
    });
    Ok(v)
}

/// Connection interval/latency/timeout/CE length block shared by the connection commands.
pub fn conn_params(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    interval("Min connection interval", r, out, 1250)?;
    interval("Max connection interval", r, out, 1250)?;
    u16_hex("Connection latency", r, out)?;
    timeout_ms("Supervision timeout", r, out, 10)?;
    slots("Min connection length", r, out)?;
    slots("Max connection length", r, out)?;
    Ok(())
}

/// `Data length: N` followed by the decoded AD structures.
pub fn adv_data(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let len = r.u8()? as usize;
    field!(out, "Data length: {}", len);
    let data = r.bytes(len)?;
    crate::ad::decode(data, out);
    Ok(())
}

/// PHY including both LE Coded variants (power control, test and PHY update reports).
pub fn phy_coded(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    enum8(label, r, out, &[(0x01, "LE 1M"), (0x02, "LE 2M"), (0x03, "LE Coded with S=8"), (0x04, "LE Coded with S=2")])
}

/// ISO stream encryption: `Encryption: Unencrypted (0x00)`.
pub fn encryption(r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    enum8("Encryption", r, out, &[(0x00, "Unencrypted"), (0x01, "Encrypted")])
}

/// Constant Tone Extension types (CTE_Type parameters and IQ reports).
pub static CTE_TYPES: &[(u8, &str)] = &[
    (0x00, "AoA Constant Tone Extension"),
    (0x01, "AoD Constant Tone Extension with 1 us slots"),
    (0x02, "AoD Constant Tone Extension with 2 us slots"),
];

pub fn cte_type(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    enum8(label, r, out, CTE_TYPES)
}

pub fn slot_durations(r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    enum8("Slot durations", r, out, &[(0x01, "1 us"), (0x02, "2 us")])
}

/// GAP appearance: `Appearance: Heart Rate Sensor (0x0340)`.
pub fn appearance(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let v = r.u16()?;
    match appearance_name(v) {
        Some(n) => field!(out, "Appearance: {} (0x{:04x})", n, v),
        None => out.unknown(format!("Appearance: Unknown (0x{v:04x})")),
    };
    Ok(())
}

/// Connection interval in 1.25 ms units where 0xffff means no preference (AD / GAP characteristics).
pub fn conn_interval_value(label: &str, out: &mut Out, v: u16) {
    if v == 0xffff {
        field!(out, "{}: No specific value (0xffff)", label);
    } else {
        interval_value(label, out, v as u32, 1250, 4);
    }
}

// ---------------------------------------------------------------------------
// Channel Sounding tables shared by commands and events
// ---------------------------------------------------------------------------

pub static CS_ROLES: &[(u8, &str)] = &[(0, "Initiator"), (1, "Reflector")];

pub static CS_T_IP_TIMES: &[(u8, &str)] =
    &[(0, "10 us"), (1, "20 us"), (2, "30 us"), (3, "40 us"), (4, "50 us"), (5, "60 us"), (6, "80 us")];

pub static CS_T_FCS_TIMES: &[(u8, &str)] = &[
    (0, "15 us"),
    (1, "20 us"),
    (2, "30 us"),
    (3, "40 us"),
    (4, "50 us"),
    (5, "60 us"),
    (6, "80 us"),
    (7, "100 us"),
    (8, "120 us"),
];

pub static CS_T_PM_TIMES: &[(u8, &str)] = &[(0, "10 us"), (1, "20 us")];

pub static CS_TX_SNR: &[(u8, &str)] = &[(0, "18 dB"), (1, "21 dB"), (2, "24 dB"), (3, "27 dB"), (4, "30 dB")];

/// `T_SW` antenna switch time in microseconds (only 0, 1, 2, 4 and 10 are defined).
pub fn cs_t_sw_time(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    let v = r.u8()?;
    match v {
        0x00 | 0x01 | 0x02 | 0x04 | 0x0a => field!(out, "{}: {} us (0x{:02x})", label, v, v),
        _ => out.unknown(format!("{label}: Reserved (0x{v:02x})")),
    };
    Ok(v)
}
