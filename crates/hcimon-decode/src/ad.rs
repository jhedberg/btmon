//! Advertising data (AD) and Extended Inquiry Response (EIR) structures.
//!
//! Both formats are a sequence of `length, type, data...` elements, described
//! in the Core Specification Supplement.  Every structure is printed as one
//! line (its meaning, not just its type name) with decoded fields nested
//! underneath; structures the decoder does not know are flagged and dumped.

use crate::assigned::{ad_type_name, company_name};
use crate::field;
use crate::hci::common::{appearance, bdaddr_value, bits, class_of_device_value, conn_interval_value, hexstr, interval_value, LE_FEATURES};
use crate::reader::{BdAddr, Reader, Result};
use crate::tree::{Out, Style};
use crate::uuid::Uuid;

/// Decode a sequence of AD/EIR structures.
pub fn decode(data: &[u8], out: &mut Out) {
    let mut r = Reader::new(data);
    while let Ok(len) = r.u8() {
        let len = len as usize;
        if len == 0 {
            // Zero-length structures pad the end of fixed-size buffers (EIR, legacy advertising).
            if r.peek().iter().all(|&b| b == 0) {
                break;
            }
            continue;
        }
        let Ok(body) = r.bytes(len) else {
            out.styled(Style::Error, format!("AD structure truncated (len {len}, {} available)", r.remaining()));
            out.hex(r.rest());
            return;
        };
        structure(body[0], &body[1..], out);
    }
}

/// Decode one structure of type `t` with payload `value`.
fn structure(t: u8, value: &[u8], out: &mut Out) {
    let mut r = Reader::new(value);
    let res = match t {
        0x01 => flags(&mut r, out),
        0x02 => uuid_list("16-bit Service UUIDs (partial)", 2, &mut r, out),
        0x03 => uuid_list("16-bit Service UUIDs (complete)", 2, &mut r, out),
        0x04 => uuid_list("32-bit Service UUIDs (partial)", 4, &mut r, out),
        0x05 => uuid_list("32-bit Service UUIDs (complete)", 4, &mut r, out),
        0x06 => uuid_list("128-bit Service UUIDs (partial)", 16, &mut r, out),
        0x07 => uuid_list("128-bit Service UUIDs (complete)", 16, &mut r, out),
        0x08 => text("Name (short)", &mut r, out),
        0x09 => text("Name (complete)", &mut r, out),
        0x0a => tx_power(&mut r, out),
        0x0d => class(&mut r, out),
        0x0e => key("Hash C from P-192", &mut r, out),
        0x0f => key("Randomizer R with P-192", &mut r, out),
        // The same type carries the Device ID in EIR and the TK value in LE OOB data.
        0x10 if r.remaining() == 8 => device_id(&mut r, out),
        0x10 => key("Security Manager TK Value", &mut r, out),
        0x11 => oob_flags(&mut r, out),
        0x12 => conn_interval_range(&mut r, out),
        0x14 => uuid_list("16-bit Service Solicitation UUIDs", 2, &mut r, out),
        0x15 => uuid_list("128-bit Service Solicitation UUIDs", 16, &mut r, out),
        0x16 => service_data("Service Data", 2, &mut r, out),
        0x17 => target_addresses("Public Target Address", 0x00, &mut r, out),
        0x18 => target_addresses("Random Target Address", 0x01, &mut r, out),
        0x19 => appearance(&mut r, out),
        0x1a => adv_interval(&mut r, out),
        0x1b => le_device_address(&mut r, out),
        0x1c => le_role(&mut r, out),
        0x1d => key("Hash C from P-256", &mut r, out),
        0x1e => key("Randomizer R with P-256", &mut r, out),
        0x1f => uuid_list("32-bit Service Solicitation UUIDs", 4, &mut r, out),
        0x20 => service_data("Service Data (32-bit)", 4, &mut r, out),
        0x21 => service_data("Service Data (128-bit)", 16, &mut r, out),
        0x22 => key("LE Secure Connections Confirmation Value", &mut r, out),
        0x23 => key("LE Secure Connections Random Value", &mut r, out),
        0x24 => uri(&mut r, out),
        0x25 => indoor_positioning(&mut r, out),
        0x26 => transport_discovery(&mut r, out),
        0x27 => le_features(&mut r, out),
        0x28 => channel_map_update(&mut r, out),
        0x29 => pb_adv(&mut r, out),
        0x2a => mesh_message(&mut r, out),
        0x2b => mesh_beacon(&mut r, out),
        0x2c => hex_struct("BIGInfo", &mut r, out),
        0x2d => key("Broadcast Code", &mut r, out),
        0x2e => rsi(&mut r, out),
        0x2f => adv_interval_long(&mut r, out),
        0x30 => text("Broadcast Name", &mut r, out),
        0x31 => encrypted_data(&mut r, out),
        0x32 => pawr_timing(&mut r, out),
        0x34 => hex_struct("Electronic Shelf Label", &mut r, out),
        0x3d => info_3d(&mut r, out),
        0xff => manufacturer(&mut r, out),
        _ => {
            match ad_type_name(t) {
                Some(n) => out.unknown(format!("{n}: len {}", value.len())),
                None => out.unknown(format!("Unknown (0x{t:02x}): len {}", value.len())),
            };
            out.nest(|o| {
                o.hex(value);
            });
            return;
        }
    };
    match res {
        Ok(()) if r.is_empty() => {}
        Ok(()) => out.nest(|o| {
            o.hex(r.rest());
        }),
        Err(_) => {
            // The structure is intact but not what the specification describes:
            // the remote device's problem, so a warning rather than a decode error.
            let name = ad_type_name(t).unwrap_or("Unknown");
            out.unknown(format!("{name}: malformed (len {})", value.len()));
            out.nest(|o| {
                o.hex(value);
            });
        }
    }
}

fn entries(n: usize) -> String {
    format!("{n} entr{}", if n == 1 { "y" } else { "ies" })
}

fn hex_list(data: &[u8]) -> String {
    data.iter().map(|b| format!("0x{b:02x}")).collect::<Vec<_>>().join(" ")
}

/// A headline with the raw payload underneath, for structures that are not decoded further.
fn hex_struct(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    field!(out, "{}: len {}", label, r.remaining());
    out.nest(|o| {
        o.hex(r.rest());
    });
    Ok(())
}

fn text(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    field!(out, "{}: {}", label, String::from_utf8_lossy(r.rest()));
    Ok(())
}

fn key(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    field!(out, "{}: {}", label, hexstr(r.bytes(16)?));
    Ok(())
}

fn tx_power(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    field!(out, "TX power: {} dBm", r.i8()?);
    Ok(())
}

fn class(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    class_of_device_value(out, r.u24()?);
    Ok(())
}

static FLAGS: &[(u8, &str)] = &[
    (0, "LE Limited Discoverable Mode"),
    (1, "LE General Discoverable Mode"),
    (2, "BR/EDR Not Supported"),
    (3, "Simultaneous LE and BR/EDR (Controller)"),
    (4, "Simultaneous LE and BR/EDR (Host)"),
];

fn flags(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let f = r.u8()?;
    field!(out, "Flags: 0x{:02x}", f);
    out.nest(|o| {
        for (bit, name) in FLAGS {
            if f & (1 << bit) != 0 {
                o.line(*name);
            }
        }
        if f & 0xe0 != 0 {
            o.unknown(format!("Unknown flags (0x{:02x})", f & 0xe0));
        }
    });
    Ok(())
}

fn read_uuid(size: usize, r: &mut Reader<'_>) -> Result<Uuid> {
    Ok(match size {
        2 => Uuid::U16(r.u16()?),
        4 => Uuid::U32(r.u32()?),
        _ => Uuid::U128(r.array::<16>()?),
    })
}

fn uuid_list(label: &str, size: usize, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let n = r.remaining() / size;
    field!(out, "{}: {}", label, entries(n));
    out.nest(|o| -> Result<()> {
        for _ in 0..n {
            o.line(read_uuid(size, r)?.describe());
        }
        Ok(())
    })
}

fn device_id(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let source = r.u16()?;
    let vendor = r.u16()?;
    let product = r.u16()?;
    let version = r.u16()?;
    match source {
        0x0001 => field!(out, "Device ID: Bluetooth SIG assigned (0x0001)"),
        0x0002 => field!(out, "Device ID: USB Implementer's Forum assigned (0x0002)"),
        _ => out.unknown(format!("Device ID: Reserved (0x{source:04x})")),
    };
    out.nest(|o| {
        match (source, company_name(vendor)) {
            (0x0001, Some(n)) => field!(o, "Vendor: {} (0x{:04x})", n, vendor),
            _ => field!(o, "Vendor: 0x{:04x}", vendor),
        };
        field!(o, "Product: 0x{:04x}", product);
        field!(o, "Version: {}.{}.{} (0x{:04x})", version >> 8, (version >> 4) & 0x0f, version & 0x0f, version);
    });
    Ok(())
}

fn oob_flags(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let f = r.u8()?;
    field!(out, "Security Manager OOB Flags: 0x{:02x}", f);
    out.nest(|o| {
        if f & 0x01 != 0 {
            o.line("OOB data present");
        }
        if f & 0x02 != 0 {
            o.line("LE supported (Host)");
        }
        if f & 0x04 != 0 {
            o.line("Simultaneous LE and BR/EDR (Host)");
        }
        o.line(if f & 0x08 != 0 { "Address type: Random" } else { "Address type: Public" });
        if f & 0xf0 != 0 {
            o.unknown(format!("Unknown flags (0x{:02x})", f & 0xf0));
        }
    });
    Ok(())
}

fn conn_interval_range(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let min = r.u16()?;
    let max = r.u16()?;
    field!(out, "Peripheral Connection Interval Range: 0x{:04x} - 0x{:04x}", min, max);
    out.nest(|o| {
        conn_interval_value("Minimum", o, min);
        conn_interval_value("Maximum", o, max);
    });
    Ok(())
}

fn service_data(label: &str, size: usize, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let u = read_uuid(size, r)?;
    field!(out, "{}: {}", label, u.describe());
    let data = r.rest();
    if !data.is_empty() {
        out.nest(|o| {
            o.hex_field("Data", data);
        });
    }
    Ok(())
}

fn target_addresses(label: &str, addr_type: u8, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let mut first = true;
    while first || r.remaining() >= 6 {
        first = false;
        let a = r.bdaddr()?;
        bdaddr_value(label, addr_type, out, &a);
    }
    Ok(())
}

fn adv_interval(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let v = r.u16()?;
    interval_value("Advertising Interval", out, v as u32, 625, 4);
    Ok(())
}

fn adv_interval_long(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let (v, width) = match r.remaining() {
        3 => (r.u24()?, 6),
        _ => (r.u32()?, 8),
    };
    interval_value("Advertising Interval - long", out, v, 625, width);
    Ok(())
}

fn le_device_address(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let a = r.bdaddr()?;
    // The address type octet is mandatory, but devices in the field omit it.
    let Ok(t) = r.u8() else {
        bdaddr_value("LE Bluetooth Device Address", 0x00, out, &a);
        out.nest(|o| {
            o.line("Address type octet missing (non-conforming)");
        });
        return Ok(());
    };
    bdaddr_value("LE Bluetooth Device Address", t & 0x01, out, &a);
    if t & 0xfe != 0 {
        out.nest(|o| {
            o.unknown(format!("Unknown address flags (0x{:02x})", t & 0xfe));
        });
    }
    Ok(())
}

fn le_role(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let v = r.u8()?;
    let name = match v {
        0x00 => "Only Peripheral",
        0x01 => "Only Central",
        0x02 => "Peripheral and Central (Peripheral preferred)",
        0x03 => "Peripheral and Central (Central preferred)",
        _ => {
            out.unknown(format!("LE Role: Reserved (0x{v:02x})"));
            return Ok(());
        }
    };
    field!(out, "LE Role: {} (0x{:02x})", name, v);
    Ok(())
}

/// URI scheme name prefixes from the Assigned Numbers document (the first
/// character of a URI structure is a code point from this table).
static URI_SCHEMES: &[(u32, &str)] = &[
    (0x01, ""),
    (0x02, "aaa:"),
    (0x03, "aaas:"),
    (0x04, "about:"),
    (0x05, "acap:"),
    (0x06, "acct:"),
    (0x07, "cap:"),
    (0x08, "cid:"),
    (0x09, "coap:"),
    (0x0a, "coaps:"),
    (0x0b, "crid:"),
    (0x0c, "data:"),
    (0x0d, "dav:"),
    (0x0e, "dict:"),
    (0x0f, "dns:"),
    (0x10, "file:"),
    (0x11, "ftp:"),
    (0x12, "geo:"),
    (0x13, "go:"),
    (0x14, "gopher:"),
    (0x15, "h323:"),
    (0x16, "http:"),
    (0x17, "https:"),
    (0x18, "iax:"),
    (0x19, "icap:"),
    (0x1a, "im:"),
    (0x1b, "imap:"),
    (0x1c, "info:"),
    (0x1d, "ipp:"),
    (0x1e, "ipps:"),
    (0x1f, "iris:"),
    (0x20, "iris.beep:"),
    (0x21, "iris.xpc:"),
    (0x22, "iris.xpcs:"),
    (0x23, "iris.lwz:"),
    (0x24, "jabber:"),
    (0x25, "ldap:"),
    (0x26, "mailto:"),
    (0x27, "mid:"),
    (0x28, "msrp:"),
    (0x29, "msrps:"),
    (0x2a, "mtqp:"),
    (0x2b, "mupdate:"),
    (0x2c, "news:"),
    (0x2d, "nfs:"),
    (0x2e, "ni:"),
    (0x2f, "nih:"),
    (0x30, "nntp:"),
    (0x31, "opaquelocktoken:"),
    (0x32, "pop:"),
    (0x33, "pres:"),
    (0x34, "reload:"),
    (0x35, "rtsp:"),
    (0x36, "rtsps:"),
    (0x37, "rtspu:"),
    (0x38, "service:"),
    (0x39, "session:"),
    (0x3a, "shttp:"),
    (0x3b, "sieve:"),
    (0x3c, "sip:"),
    (0x3d, "sips:"),
    (0x3e, "sms:"),
    (0x3f, "snmp:"),
    (0x40, "soap.beep:"),
    (0x41, "soap.beeps:"),
    (0x42, "stun:"),
    (0x43, "stuns:"),
    (0x44, "tag:"),
    (0x45, "tel:"),
    (0x46, "telnet:"),
    (0x47, "tftp:"),
    (0x48, "thismessage:"),
    (0x49, "tn3270:"),
    (0x4a, "tip:"),
    (0x4b, "turn:"),
    (0x4c, "turns:"),
    (0x4d, "tv:"),
    (0x4e, "urn:"),
    (0x4f, "vemmi:"),
    (0x50, "ws:"),
    (0x51, "wss:"),
    (0x52, "xcon:"),
    (0x53, "xcon-userid:"),
    (0x54, "xmlrpc.beep:"),
    (0x55, "xmlrpc.beeps:"),
    (0x56, "xmpp:"),
    (0x57, "z39.50r:"),
    (0x58, "z39.50s:"),
];

fn uri(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let s = String::from_utf8_lossy(r.rest());
    let mut chars = s.chars();
    let Some(code) = chars.next() else {
        field!(out, "URI: (empty)");
        return Ok(());
    };
    let rest = chars.as_str();
    match crate::assigned::lookup(URI_SCHEMES, code as u32) {
        Some(scheme) => field!(out, "URI: {}{}", scheme, rest),
        None => out.unknown(format!("URI: (scheme 0x{:04x}) {}", code as u32, rest)),
    };
    Ok(())
}

fn indoor_positioning(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let f = r.u8()?;
    field!(out, "Indoor Positioning: 0x{:02x}", f);
    out.nest(|o| -> Result<()> {
        let local = f & 0x02 != 0;
        if f & 0x01 != 0 {
            o.line(if local { "Coordinates: Local (North and East)" } else { "Coordinates: WGS84" });
        }
        if f & 0x04 != 0 {
            o.line("TX Power present");
        }
        if f & 0x08 != 0 {
            o.line("Altitude present");
        }
        if f & 0x10 != 0 {
            o.line("Floor Number present");
        }
        if f & 0x20 != 0 {
            o.line("Uncertainty present");
        }
        if f & 0x40 != 0 {
            o.line("Location Name available");
        }
        if f & 0x80 != 0 {
            o.unknown("Reserved flag (0x80)");
        }
        if f & 0x01 != 0 {
            if local {
                field!(o, "Local North Coordinate: {}", r.i16()?);
                field!(o, "Local East Coordinate: {}", r.i16()?);
            } else {
                // sint32 in units of 10^-7 degrees.
                let lat = r.u32()? as i32;
                let lon = r.u32()? as i32;
                field!(o, "Latitude: {} (0x{:08x})", degrees(lat), lat as u32);
                field!(o, "Longitude: {} (0x{:08x})", degrees(lon), lon as u32);
            }
        }
        if f & 0x04 != 0 {
            field!(o, "TX Power: {} dBm", r.i8()?);
        }
        if f & 0x08 != 0 {
            field!(o, "Altitude: 0x{:04x}", r.u16()?);
        }
        if f & 0x10 != 0 {
            field!(o, "Floor Number: {}", r.u8()?);
        }
        if f & 0x20 != 0 {
            field!(o, "Uncertainty: 0x{:02x}", r.u8()?);
        }
        Ok(())
    })
}

/// Format a coordinate stored in units of 10^-7 degrees.
fn degrees(v: i32) -> String {
    let sign = if v < 0 { "-" } else { "" };
    let a = v.unsigned_abs();
    format!("{sign}{}.{:07}", a / 10_000_000, a % 10_000_000)
}

fn transport_discovery(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    field!(out, "Transport Discovery Data: len {}", r.remaining());
    out.nest(|o| -> Result<()> {
        let mut first = true;
        while first || r.remaining() >= 3 {
            first = false;
            let org = r.u8()?;
            let f = r.u8()?;
            let len = r.u8()?;
            match org {
                0x01 => field!(o, "Organization: Bluetooth SIG (0x01)"),
                _ => o.unknown(format!("Organization: RFU (0x{org:02x})")),
            };
            field!(o, "Flags: 0x{:02x}", f);
            o.nest(|o| {
                let role = match f & 0x03 {
                    0x00 => "Not Specified",
                    0x01 => "Seeker Only",
                    0x02 => "Provider Only",
                    _ => "Both Seeker and Provider",
                };
                field!(o, "Role: {} (0x{:02x})", role, f & 0x03);
                field!(o, "Transport Data Incomplete: {}", if f & 0x04 != 0 { "True" } else { "False" });
                let state = match (f >> 3) & 0x03 {
                    0x00 => "Off",
                    0x01 => "On",
                    0x02 => "Temporarily Unavailable",
                    _ => "RFU",
                };
                field!(o, "Transport State: {} (0x{:02x})", state, (f >> 3) & 0x03);
                if f & 0xe0 != 0 {
                    o.unknown(format!("Reserved flags (0x{:02x})", f & 0xe0));
                }
            });
            field!(o, "Length: {}", len);
            let data = r.bytes(len as usize)?;
            if !data.is_empty() {
                o.hex_field("Data", data);
            }
        }
        Ok(())
    })
}

fn le_features(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let data = r.rest();
    field!(out, "LE Supported Features: {}", hex_list(data));
    let mut mask = 0u64;
    for (i, b) in data.iter().take(8).enumerate() {
        mask |= (*b as u64) << (8 * i);
    }
    out.nest(|o| bits(o, mask, LE_FEATURES, 64));
    Ok(())
}

/// Ranges of set channels in a 37-channel map, e.g. `0-10, 12-36`.
fn channel_ranges(map: &[u8; 5]) -> String {
    let set = |ch: usize| map[ch / 8] & (1 << (ch % 8)) != 0;
    let mut parts = Vec::new();
    let mut ch = 0;
    while ch < 37 {
        if set(ch) {
            let start = ch;
            while ch + 1 < 37 && set(ch + 1) {
                ch += 1;
            }
            parts.push(if start == ch { start.to_string() } else { format!("{start}-{ch}") });
        }
        ch += 1;
    }
    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join(", ")
    }
}

fn channel_map_update(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let map = r.array::<5>()?;
    let instant = r.u16()?;
    field!(out, "Channel Map Update Indication");
    out.nest(|o| {
        field!(o, "Channel Map: {}", hex_list(&map));
        o.nest(|o| {
            field!(o, "Channels: {}", channel_ranges(&map));
            if map[4] & 0xe0 != 0 {
                o.unknown(format!("Reserved bits (0x{:02x})", map[4] & 0xe0));
            }
        });
        field!(o, "Instant: {} (0x{:04x})", instant, instant);
    });
    Ok(())
}

fn pb_adv(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    field!(out, "PB-ADV: len {}", r.remaining());
    out.nest(|o| -> Result<()> {
        field!(o, "Link ID: 0x{:08x}", r.u32_be()?);
        field!(o, "Transaction Number: {}", r.u8()?);
        let ctl = r.u8()?;
        match ctl & 0x03 {
            0x00 => {
                field!(o, "Transaction Start (0x00)");
                field!(o, "Segment Number: {}", ctl >> 2);
                field!(o, "Total Length: {}", r.u16_be()?);
                field!(o, "FCS: 0x{:02x}", r.u8()?);
            }
            0x01 => {
                field!(o, "Transaction Acknowledgment (0x01)");
            }
            0x02 => {
                field!(o, "Transaction Continuation (0x02)");
                field!(o, "Segment Index: {}", ctl >> 2);
            }
            _ => {
                field!(o, "Provisioning Bearer Control (0x03)");
                match ctl >> 2 {
                    0x00 => {
                        field!(o, "Link Open (0x00)");
                        field!(o, "Device UUID: {}", hexstr(r.bytes(16)?));
                    }
                    0x01 => {
                        field!(o, "Link Ack (0x01)");
                    }
                    0x02 => {
                        field!(o, "Link Close (0x02)");
                        let reason = r.u8()?;
                        match reason {
                            0x00 => field!(o, "Reason: Success (0x00)"),
                            0x01 => field!(o, "Reason: Timeout (0x01)"),
                            0x02 => field!(o, "Reason: Fail (0x02)"),
                            _ => o.unknown(format!("Reason: Unrecognized (0x{reason:02x})")),
                        };
                    }
                    op => {
                        o.unknown(format!("Unknown bearer opcode (0x{op:02x})"));
                    }
                }
            }
        }
        if !r.is_empty() {
            o.hex_field("Data", r.rest());
        }
        Ok(())
    })
}

fn mesh_message(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    field!(out, "Mesh Message: len {}", r.remaining());
    out.nest(|o| -> Result<()> {
        let b = r.u8()?;
        field!(o, "IVI: {}", b >> 7);
        field!(o, "NID: 0x{:02x}", b & 0x7f);
        if !r.is_empty() {
            o.hex_field("Data", r.rest());
        }
        Ok(())
    })
}

static MESH_OOB: &[(u8, &str)] = &[
    (0, "Other"),
    (1, "Electronic / URI"),
    (2, "2D machine-readable code"),
    (3, "Bar code"),
    (4, "Near Field Communication (NFC)"),
    (5, "Number"),
    (6, "String"),
    (7, "Support for certificate-based provisioning"),
    (8, "Support for provisioning records"),
    (11, "On box"),
    (12, "Inside box"),
    (13, "On piece of paper"),
    (14, "Inside manual"),
    (15, "On device"),
];

fn mesh_beacon(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    field!(out, "Mesh Beacon: len {}", r.remaining());
    out.nest(|o| -> Result<()> {
        let t = r.u8()?;
        match t {
            0x00 => {
                field!(o, "Unprovisioned Device Beacon (0x00)");
                field!(o, "Device UUID: {}", hexstr(r.bytes(16)?));
                let oob = r.u16_be()?;
                field!(o, "OOB Information: 0x{:04x}", oob);
                o.nest(|o| bits(o, oob as u64, MESH_OOB, 16));
                if r.remaining() >= 4 {
                    field!(o, "URI Hash: 0x{:08x}", r.u32_be()?);
                }
            }
            0x01 => {
                field!(o, "Secure Network Beacon (0x01)");
                let f = r.u8()?;
                field!(o, "Flags: 0x{:02x}", f);
                o.nest(|o| {
                    if f & 0x01 != 0 {
                        o.line("Key Refresh");
                    }
                    if f & 0x02 != 0 {
                        o.line("IV Update");
                    }
                });
                field!(o, "Network ID: {}", hexstr(r.bytes(8)?));
                field!(o, "IV Index: 0x{:08x}", r.u32_be()?);
                field!(o, "Authentication Value: {}", hexstr(r.bytes(8)?));
            }
            0x02 => {
                field!(o, "Mesh Private Beacon (0x02)");
                field!(o, "Random: {}", hexstr(r.bytes(13)?));
                field!(o, "Obfuscated Private Beacon Data: {}", hexstr(r.bytes(5)?));
                field!(o, "Authentication Tag: {}", hexstr(r.bytes(8)?));
            }
            _ => {
                o.unknown(format!("Unknown beacon type (0x{t:02x})"));
            }
        }
        if !r.is_empty() {
            o.hex(r.rest());
        }
        Ok(())
    })
}

fn rsi(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let b = r.array::<6>()?;
    field!(out, "Resolvable Set Identifier: {}", BdAddr(b));
    out.nest(|o| {
        field!(o, "Hash: 0x{:06x}", u32::from_le_bytes([b[0], b[1], b[2], 0]));
        field!(o, "Random: 0x{:06x}", u32::from_le_bytes([b[3], b[4], b[5], 0]));
    });
    Ok(())
}

fn encrypted_data(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    field!(out, "Encrypted Advertising Data: len {}", r.remaining());
    out.nest(|o| -> Result<()> {
        field!(o, "Randomizer: {}", hexstr(r.bytes(5)?));
        let rest = r.rest();
        let (payload, mic) = rest.split_at(rest.len().saturating_sub(4));
        if !payload.is_empty() {
            o.hex_field("Payload", payload);
        }
        field!(o, "MIC: {}", hexstr(mic));
        Ok(())
    })
}

fn pawr_timing(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    field!(out, "Periodic Advertising Response Timing Information");
    out.nest(|o| -> Result<()> {
        field!(o, "Response Access Address: 0x{:08x}", r.u32()?);
        field!(o, "Number of Subevents: {}", r.u8()?);
        interval_value("Subevent Interval", o, r.u8()? as u32, 1250, 2);
        interval_value("Response Slot Delay", o, r.u8()? as u32, 1250, 2);
        interval_value("Response Slot Spacing", o, r.u8()? as u32, 125, 2);
        Ok(())
    })
}

static FEATURES_3D: &[(u8, &str)] = &[
    (0, "Association Notification"),
    (1, "Battery Level Reporting"),
    (2, "Send Battery Level Report on Start-up Synchronization"),
    (7, "Factory Test Mode"),
];

fn info_3d(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let f = r.u8()?;
    let path_loss = r.u8()?;
    field!(out, "3D Information Data");
    out.nest(|o| {
        field!(o, "Features: 0x{:02x}", f);
        o.nest(|o| bits(o, f as u64, FEATURES_3D, 8));
        field!(o, "Path Loss Threshold: {}", path_loss);
    });
    Ok(())
}

// ---------------------------------------------------------------------------
// Manufacturer specific data

const COMPANY_MICROSOFT: u16 = 0x0006;
const COMPANY_APPLE: u16 = 0x004c;

fn manufacturer(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let company = r.u16()?;
    match company_name(company) {
        Some(n) => field!(out, "Manufacturer Specific Data: {} ({})", n, company),
        // 0xFFFF is reserved for tests and internal use, not an unknown vendor.
        None if company == 0xffff => field!(out, "Manufacturer Specific Data: Reserved for testing (65535)"),
        None => out.unknown(format!("Manufacturer Specific Data: Unknown ({company})")),
    };
    let data = r.rest();
    out.nest(|o| {
        if !data.is_empty() {
            o.hex_field("Data", data);
        }
        match company {
            COMPANY_APPLE => apple(data, o),
            COMPANY_MICROSOFT => microsoft(data, o),
            _ => {}
        }
    });
    Ok(())
}

fn apple_type_name(t: u8) -> &'static str {
    match t {
        0x02 => "iBeacon",
        0x05 => "AirDrop",
        0x07 => "Proximity Pairing",
        0x09 => "AirPlay Target",
        0x0a => "AirPlay Source",
        0x0c => "Handoff",
        0x0f => "Nearby Action",
        0x10 => "Nearby Info",
        0x12 => "Find My",
        _ => "Unknown",
    }
}

/// Apple's payload is a sequence of `type, length, value` records; iBeacon is decoded fully.
fn apple(data: &[u8], o: &mut Out) {
    let mut r = Reader::new(data);
    while r.remaining() >= 2 {
        let t = r.u8().unwrap_or(0);
        let len = r.u8().unwrap_or(0) as usize;
        let Ok(payload) = r.bytes(len) else {
            // Not a well-formed record list; the raw data was already printed.
            return;
        };
        field!(o, "Type: {} (0x{:02x})", apple_type_name(t), t);
        o.nest(|o| {
            if t == 0x02 && len == 21 {
                ibeacon(payload, o);
            } else if !payload.is_empty() {
                o.hex_field("Data", payload);
            }
        });
    }
}

fn ibeacon(p: &[u8], o: &mut Out) {
    let u = &p[..16];
    field!(
        o,
        "UUID: {:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        u[0], u[1], u[2], u[3], u[4], u[5], u[6], u[7], u[8], u[9], u[10], u[11], u[12], u[13], u[14], u[15]
    );
    field!(o, "Major: {} (0x{:04x})", u16::from_be_bytes([p[16], p[17]]), u16::from_be_bytes([p[16], p[17]]));
    field!(o, "Minor: {} (0x{:04x})", u16::from_be_bytes([p[18], p[19]]), u16::from_be_bytes([p[18], p[19]]));
    field!(o, "TX power: {} dBm", p[20] as i8);
}

fn microsoft(data: &[u8], o: &mut Out) {
    let mut r = Reader::new(data);
    let Ok(scenario) = r.u8() else { return };
    match scenario {
        0x01 => {
            field!(o, "Scenario: Beacon (0x01)");
            if let Ok(b) = r.u8() {
                let device = match b & 0x1f {
                    1 => "Xbox One",
                    6 => "Apple iPhone",
                    7 => "Apple iPad",
                    8 => "Android device",
                    9 => "Windows 10 Desktop",
                    11 => "Windows 10 Phone",
                    12 => "Linux device",
                    13 => "Windows IoT",
                    14 => "Surface Hub",
                    15 => "Windows laptop",
                    16 => "Windows tablet",
                    _ => "Unknown",
                };
                field!(o, "Version: {}", b >> 5);
                field!(o, "Device Type: {} ({})", device, b & 0x1f);
            }
        }
        0x03 => {
            field!(o, "Scenario: Swift Pair (0x03)");
            let Ok(sub) = r.u8() else { return };
            match sub {
                0x00 => field!(o, "Pairing over LE (0x00)"),
                0x01 => field!(o, "Pairing over BR/EDR (0x01)"),
                0x02 => field!(o, "Pairing over LE and BR/EDR with Secure Connections (0x02)"),
                _ => o.unknown(format!("Unknown sub-scenario (0x{sub:02x})")),
            };
            let Ok(reserved) = r.u8() else { return };
            field!(o, "Reserved: 0x{:02x}", reserved);
            if matches!(sub, 0x01 | 0x02) {
                if let Ok(cod) = r.u24() {
                    class_of_device_value(o, cod);
                }
            }
            if sub == 0x01 {
                if let Ok(a) = r.bdaddr() {
                    bdaddr_value("Address", 0x00, o, &a);
                }
            }
            if !r.is_empty() {
                field!(o, "Display Name: {}", String::from_utf8_lossy(r.rest()));
            }
        }
        _ => {
            o.unknown(format!("Scenario: Unknown (0x{scenario:02x})"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::render_lines;

    fn run(data: &[u8]) -> Vec<String> {
        let mut out = Out::new();
        decode(data, &mut out);
        let mut v = Vec::new();
        render_lines(out.roots(), 0, |indent, n| v.push(format!("{}{}", " ".repeat(indent), n.text)));
        v
    }

    #[test]
    fn flags_and_uuid16_list_with_padding() {
        // LE Set Advertising Data payload from the sample capture (31 bytes, zero padded).
        let mut data = vec![0x02, 0x01, 0x06, 0x07, 0x03, 0x0d, 0x18, 0x0f, 0x18, 0x0a, 0x18];
        data.resize(31, 0);
        assert_eq!(
            run(&data),
            [
                "Flags: 0x06",
                "  LE General Discoverable Mode",
                "  BR/EDR Not Supported",
                "16-bit Service UUIDs (complete): 3 entries",
                "  Heart Rate (0x180d)",
                "  Battery (0x180f)",
                "  Device Information (0x180a)",
            ]
        );
    }

    #[test]
    fn names_and_tx_power() {
        let mut data = vec![0x18, 0x09];
        data.extend_from_slice(b"Zephyr Heartrate Sensor");
        data.extend_from_slice(&[0x03, 0x08, b'Z', b'e', 0x02, 0x0a, 0xf6]);
        assert_eq!(run(&data), ["Name (complete): Zephyr Heartrate Sensor", "Name (short): Ze", "TX power: -10 dBm"]);
    }

    #[test]
    fn class_of_device_and_appearance() {
        let l = run(&[0x04, 0x0d, 0x0c, 0x02, 0x5a, 0x03, 0x19, 0x41, 0x03]);
        assert_eq!(l[0], "Class: 0x5a020c");
        assert!(l[1].starts_with("  Major class: Phone"), "{l:?}");
        assert!(l.contains(&"Appearance: Heart Rate Sensor: Heart Rate Belt (0x0341)".to_string()), "{l:?}");
    }

    #[test]
    fn service_data_and_uuid128_list() {
        let uuid: [u8; 16] = [
            0x9e, 0xca, 0xdc, 0x24, 0x0e, 0xe5, 0xa9, 0xe0, 0x93, 0xf3, 0xa3, 0xb5, 0x01, 0x00, 0x40, 0x6e,
        ];
        let mut data = vec![0x05, 0x16, 0x0d, 0x18, 0x06, 0x68, 0x11, 0x07];
        data.extend_from_slice(&uuid);
        data.extend_from_slice(&[0x06, 0x20, 0x00, 0x18, 0x00, 0x00, 0xaa]);
        assert_eq!(
            run(&data),
            [
                "Service Data: Heart Rate (0x180d)",
                "  Data: 06 68",
                "128-bit Service UUIDs (complete): 1 entry",
                "  Vendor specific (6e400001-b5a3-f393-e0a9-e50e24dcca9e)",
                "Service Data (32-bit): GAP (0x00001800)",
                "  Data: aa",
            ]
        );
    }

    #[test]
    fn apple_ibeacon() {
        let mut data = vec![0x1a, 0xff, 0x4c, 0x00, 0x02, 0x15];
        data.extend_from_slice(&[
            0xe2, 0xc5, 0x6d, 0xb5, 0xdf, 0xfb, 0x48, 0xd2, 0xb0, 0x60, 0xd0, 0xf5, 0xa7, 0x10, 0x96, 0xe0,
        ]);
        data.extend_from_slice(&[0x00, 0x01, 0x00, 0x02, 0xc5]);
        let l = run(&data);
        assert_eq!(l[0], "Manufacturer Specific Data: Apple, Inc. (76)");
        assert_eq!(
            l[2..],
            [
                "  Type: iBeacon (0x02)",
                "    UUID: e2c56db5-dffb-48d2-b060-d0f5a71096e0",
                "    Major: 1 (0x0001)",
                "    Minor: 2 (0x0002)",
                "    TX power: -59 dBm",
            ]
        );
    }

    #[test]
    fn microsoft_swift_pair() {
        let mut data = vec![0x0b, 0xff, 0x06, 0x00, 0x03, 0x00, 0x80];
        data.extend_from_slice(b"Mouse");
        let l = run(&data);
        assert_eq!(l[0], "Manufacturer Specific Data: Microsoft (6)");
        assert_eq!(l[2..], ["  Scenario: Swift Pair (0x03)", "  Pairing over LE (0x00)", "  Reserved: 0x80", "  Display Name: Mouse"]);
    }

    #[test]
    fn uri_scheme_prefix() {
        let mut data = vec![0x0d, 0x24, 0x17];
        data.extend_from_slice(b"//example.c");
        assert_eq!(run(&data), ["URI: https://example.c"]);
        assert_eq!(run(&[0x03, 0x24, 0xc2, 0xa0]), ["URI: (scheme 0x00a0) "]);
    }

    #[test]
    fn peripheral_connection_interval_range() {
        assert_eq!(
            run(&[0x05, 0x12, 0x06, 0x00, 0xff, 0xff]),
            [
                "Peripheral Connection Interval Range: 0x0006 - 0xffff",
                "  Minimum: 7.500 msec (0x0006)",
                "  Maximum: No specific value (0xffff)",
            ]
        );
    }

    #[test]
    fn le_address_role_and_interval() {
        let l = run(&[0x08, 0x1b, 0x13, 0x71, 0xda, 0x7d, 0x1a, 0x00, 0x00, 0x02, 0x1c, 0x00, 0x03, 0x1a, 0xa0, 0x00]);
        assert_eq!(
            l,
            [
                "LE Bluetooth Device Address: 00:1A:7D:DA:71:13 (cyber-blue(HK)Ltd)",
                "LE Role: Only Peripheral (0x00)",
                "Advertising Interval: 100.000 msec (0x00a0)",
            ]
        );
    }

    #[test]
    fn le_supported_features() {
        assert_eq!(
            run(&[0x03, 0x27, 0x21, 0x00]),
            ["LE Supported Features: 0x21 0x00", "  LE Encryption", "  LE Data Packet Length Extension"]
        );
    }

    #[test]
    fn channel_map_update_indication() {
        let l = run(&[0x08, 0x28, 0xff, 0xf7, 0xff, 0xff, 0x1f, 0x10, 0x00]);
        assert_eq!(
            l,
            [
                "Channel Map Update Indication",
                "  Channel Map: 0xff 0xf7 0xff 0xff 0x1f",
                "    Channels: 0-10, 12-36",
                "  Instant: 16 (0x0010)",
            ]
        );
    }

    #[test]
    fn rsi_and_broadcast_name() {
        let mut data = vec![0x07, 0x2e, 0x01, 0x02, 0x03, 0x04, 0x05, 0x46, 0x04, 0x30];
        data.extend_from_slice(b"Bar");
        assert_eq!(
            run(&data),
            [
                "Resolvable Set Identifier: 46:05:04:03:02:01",
                "  Hash: 0x030201",
                "  Random: 0x460504",
                "Broadcast Name: Bar",
            ]
        );
    }

    #[test]
    fn device_id_versus_tk_value() {
        let l = run(&[0x09, 0x10, 0x01, 0x00, 0x59, 0x00, 0x34, 0x12, 0x00, 0x01]);
        assert_eq!(
            l,
            [
                "Device ID: Bluetooth SIG assigned (0x0001)",
                "  Vendor: Nordic Semiconductor ASA (0x0059)",
                "  Product: 0x1234",
                "  Version: 1.0.0 (0x0100)",
            ]
        );
        let mut data = vec![0x11, 0x10];
        data.extend_from_slice(&[0xab; 16]);
        assert_eq!(run(&data), ["Security Manager TK Value: abababababababababababababababab"]);
    }

    #[test]
    fn truncated_malformed_and_unknown() {
        let l = run(&[0x05, 0x09, b'a']);
        assert!(l[0].starts_with("AD structure truncated (len 5, 2 available)"), "{l:?}");
        // Flags with no payload.
        let l = run(&[0x01, 0x01, 0x02, 0x0a, 0x00]);
        assert_eq!(l, ["Flags: malformed (len 0)", "TX power: 0 dBm"]);
        let l = run(&[0x03, 0xee, 0x01, 0x02]);
        assert_eq!(l[0], "Unknown (0xee): len 2");
        assert!(l[1].starts_with("  01 02"));
        // Trailing bytes of a fixed-size structure are dumped underneath.
        let l = run(&[0x03, 0x0a, 0x00, 0x77]);
        assert_eq!(l[0], "TX power: 0 dBm");
        assert!(l[1].starts_with("  77"));
    }

    #[test]
    fn transport_discovery_and_pawr_timing() {
        let l = run(&[0x06, 0x26, 0x01, 0x0a, 0x02, 0xbe, 0xef]);
        assert_eq!(
            l,
            [
                "Transport Discovery Data: len 5",
                "  Organization: Bluetooth SIG (0x01)",
                "  Flags: 0x0a",
                "    Role: Provider Only (0x02)",
                "    Transport Data Incomplete: False",
                "    Transport State: On (0x01)",
                "  Length: 2",
                "  Data: be ef",
            ]
        );
        let l = run(&[0x09, 0x32, 0x78, 0x56, 0x34, 0x12, 0x04, 0x06, 0x02, 0x02]);
        assert_eq!(
            l[1..],
            [
                "  Response Access Address: 0x12345678",
                "  Number of Subevents: 4",
                "  Subevent Interval: 7.500 msec (0x06)",
                "  Response Slot Delay: 2.500 msec (0x02)",
                "  Response Slot Spacing: 0.250 msec (0x02)",
            ]
        );
    }
}
