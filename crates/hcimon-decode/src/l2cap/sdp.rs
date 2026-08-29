//! Service Discovery Protocol (PSM 0x0001).
//!
//! PDUs are decoded down to their data elements, which are printed as a tree
//! in btmon's style (`Sequence (6) with 3 bytes [8 extra bits] len 5`).
//! Responses split over several transactions are not reassembled: attribute
//! lists that do not parse as a complete data element are dumped as hex
//! together with the continuation state.

use crate::field;
use crate::reader::{Reader, Truncated};
use crate::tree::Out;
use crate::uuid::Uuid;

pub fn pdu_name(id: u8) -> Option<&'static str> {
    Some(match id {
        0x01 => "Error Response",
        0x02 => "Service Search Request",
        0x03 => "Service Search Response",
        0x04 => "Service Attribute Request",
        0x05 => "Service Attribute Response",
        0x06 => "Service Search Attribute Request",
        0x07 => "Service Search Attribute Response",
        _ => return None,
    })
}

pub fn error_name(code: u16) -> &'static str {
    match code {
        0x0001 => "Invalid/unsupported SDP version",
        0x0002 => "Invalid Service Record Handle",
        0x0003 => "Invalid request syntax",
        0x0004 => "Invalid PDU size",
        0x0005 => "Invalid Continuation State",
        0x0006 => "Insufficient Resources to satisfy Request",
        _ => "Unknown",
    }
}

/// Universal attribute IDs (Vol 3, Part B, Section 5.1) plus the default
/// language base offsets for the name/description/provider strings.
pub fn attribute_name(id: u16) -> &'static str {
    match id {
        0x0000 => "Service Record Handle",
        0x0001 => "Service Class ID List",
        0x0002 => "Service Record State",
        0x0003 => "Service ID",
        0x0004 => "Protocol Descriptor List",
        0x0005 => "Browse Group List",
        0x0006 => "Language Base Attribute ID List",
        0x0007 => "Service Info Time To Live",
        0x0008 => "Service Availability",
        0x0009 => "Bluetooth Profile Descriptor List",
        0x000a => "Documentation URL",
        0x000b => "Client Executable URL",
        0x000c => "Icon URL",
        0x000d => "Additional Protocol Descriptor Lists",
        0x0100 => "Service Name",
        0x0101 => "Service Description",
        0x0102 => "Provider Name",
        _ => "Unknown",
    }
}

/// Why decoding stopped: short parameters, or data that does not follow the spec.
enum Fail {
    Truncated(Truncated),
    Malformed(String),
}

impl From<Truncated> for Fail {
    fn from(t: Truncated) -> Self {
        Fail::Truncated(t)
    }
}

type R<T> = std::result::Result<T, Fail>;

/// Decode one SDP PDU.
pub fn decode(payload: &[u8], out: &mut Out) {
    let mut r = Reader::new(payload);
    let (Ok(id), Ok(tid), Ok(plen)) = (r.u8(), r.u16_be(), r.u16_be()) else {
        out.error("SDP: header truncated");
        out.hex(payload);
        return;
    };
    match pdu_name(id) {
        Some(n) => field!(out, "SDP: {} (0x{:02x}) tid {} len {}", n, id, tid, plen),
        None => out.unknown(format!("SDP: Unknown (0x{id:02x}) tid {tid} len {plen}")),
    };
    out.nest(|o| {
        if plen as usize != r.remaining() {
            o.error(format!("Parameter length mismatch: header says {plen}, {} present", r.remaining()));
        }
        match params(id, &mut r, o) {
            Ok(true) => {
                if !r.is_empty() {
                    o.error("Unexpected trailing data");
                    o.hex(r.rest());
                }
            }
            Ok(false) => {
                o.hex(r.rest());
            }
            Err(Fail::Truncated(e)) => {
                o.error(format!("Parameters {e}"));
                o.hex(r.rest());
            }
            Err(Fail::Malformed(m)) => {
                o.error(m);
                o.hex(r.rest());
            }
        }
    });
}

fn params(id: u8, r: &mut Reader<'_>, out: &mut Out) -> R<bool> {
    match id {
        0x01 => {
            let e = r.u16_be()?;
            field!(out, "Error code: {} (0x{:04x})", error_name(e), e);
        }
        0x02 => {
            search_pattern(r, out)?;
            let n = r.u16_be()?;
            field!(out, "Max record count: {}", n);
            continuation(r, out)?;
        }
        0x03 => {
            let total = r.u16_be()?;
            let current = r.u16_be()?;
            field!(out, "Total record count: {}", total);
            field!(out, "Current record count: {}", current);
            for _ in 0..current {
                let h = r.u32_be()?;
                field!(out, "Record handle: 0x{:08x}", h);
            }
            continuation(r, out)?;
        }
        0x04 => {
            let h = r.u32_be()?;
            field!(out, "Record handle: 0x{:08x}", h);
            let n = r.u16_be()?;
            field!(out, "Max attribute bytes: {}", n);
            attribute_id_list(r, out)?;
            continuation(r, out)?;
        }
        0x05 => {
            attribute_lists(r, out, false)?;
            continuation(r, out)?;
        }
        0x06 => {
            search_pattern(r, out)?;
            let n = r.u16_be()?;
            field!(out, "Max attribute bytes: {}", n);
            attribute_id_list(r, out)?;
            continuation(r, out)?;
        }
        0x07 => {
            attribute_lists(r, out, true)?;
            continuation(r, out)?;
        }
        _ => return Ok(false),
    }
    Ok(true)
}

fn search_pattern(r: &mut Reader<'_>, out: &mut Out) -> R<()> {
    let e = parse_element(r)?;
    field!(out, "Search pattern: [len {}]", e.total);
    out.nest(|o| print_element(&e, o, Ctx::Plain));
    Ok(())
}

fn attribute_id_list(r: &mut Reader<'_>, out: &mut Out) -> R<()> {
    let e = parse_element(r)?;
    field!(out, "Attribute list: [len {}]", e.total);
    out.nest(|o| print_element(&e, o, Ctx::AttrIds));
    Ok(())
}

/// `AttributeListByteCount` followed by an attribute list (`nested`: a list
/// of attribute lists, as in a Service Search Attribute Response).
fn attribute_lists(r: &mut Reader<'_>, out: &mut Out, nested: bool) -> R<()> {
    let count = r.u16_be()? as usize;
    field!(out, "Attribute bytes: {}", count);
    let data = r.bytes(count)?;
    let mut sub = Reader::new(data);
    let parsed = parse_element(&mut sub).ok().filter(|e| e.typ == TYPE_SEQ && sub.is_empty());
    match parsed {
        Some(e) if nested => {
            for (i, list) in e.children.iter().enumerate() {
                field!(out, "Attribute list: [len {}] {{position {}}}", list.data.len(), i);
                out.nest(|o| print_attribute_list(list, o));
            }
        }
        Some(e) => {
            field!(out, "Attribute list: [len {}]", e.data.len());
            out.nest(|o| print_attribute_list(&e, o));
        }
        None => {
            if !data.is_empty() {
                out.line("Attribute list: partial (not decoded)");
                out.nest(|o| {
                    o.hex(data);
                });
            }
        }
    }
    Ok(())
}

fn continuation(r: &mut Reader<'_>, out: &mut Out) -> R<()> {
    let n = r.u8()? as usize;
    if n > r.remaining() {
        return Err(Fail::Malformed(format!(
            "Invalid continuation state: {n} bytes announced, {} present",
            r.remaining()
        )));
    }
    field!(out, "Continuation state: {}", n);
    if n > 0 {
        let b = r.bytes(n)?;
        out.nest(|o| {
            o.hex(b);
        });
    }
    Ok(())
}

// ---- data elements ---------------------------------------------------------

const TYPE_NIL: u8 = 0;
const TYPE_UINT: u8 = 1;
const TYPE_SINT: u8 = 2;
const TYPE_UUID: u8 = 3;
const TYPE_STRING: u8 = 4;
const TYPE_BOOL: u8 = 5;
const TYPE_SEQ: u8 = 6;
const TYPE_ALT: u8 = 7;
const TYPE_URL: u8 = 8;

fn type_name(t: u8) -> &'static str {
    match t {
        TYPE_NIL => "Nil",
        TYPE_UINT => "Unsigned Integer",
        TYPE_SINT => "Signed Integer",
        TYPE_UUID => "UUID",
        TYPE_STRING => "String",
        TYPE_BOOL => "Boolean",
        TYPE_SEQ => "Sequence",
        TYPE_ALT => "Alternative",
        TYPE_URL => "URL",
        _ => "Unknown",
    }
}

/// Bits of the additional length field selected by the size index.
fn extra_bits(size_index: u8) -> u8 {
    match size_index {
        5 => 8,
        6 => 16,
        7 => 32,
        _ => 0,
    }
}

/// A parsed data element; sequences and alternatives carry their members.
struct Element<'a> {
    typ: u8,
    size_index: u8,
    data: &'a [u8],
    /// Bytes on the wire including the descriptor and length.
    total: usize,
    children: Vec<Element<'a>>,
}

fn parse_element<'a>(r: &mut Reader<'a>) -> R<Element<'a>> {
    let start = r.pos();
    let hdr = r.u8().map_err(|_| Fail::Malformed("Data element descriptor missing".into()))?;
    let typ = hdr >> 3;
    let size_index = hdr & 0x07;
    let len = match size_index {
        0 => usize::from(typ != TYPE_NIL),
        1 => 2,
        2 => 4,
        3 => 8,
        4 => 16,
        5 => r.u8()? as usize,
        6 => r.u16_be()? as usize,
        _ => r.u32_be()? as usize,
    };
    let valid = match typ {
        TYPE_NIL | TYPE_BOOL => size_index == 0,
        TYPE_UINT | TYPE_SINT => size_index <= 4,
        TYPE_UUID => matches!(size_index, 1 | 2 | 4),
        TYPE_STRING | TYPE_SEQ | TYPE_ALT | TYPE_URL => size_index >= 5,
        _ => true,
    };
    if !valid {
        return Err(Fail::Malformed(format!("Invalid size index {size_index} for {} data element", type_name(typ))));
    }
    let available = r.remaining();
    let data = r
        .bytes(len)
        .map_err(|_| Fail::Malformed(format!("Data element size {len} exceeds the {available} bytes available")))?;
    let children = if typ == TYPE_SEQ || typ == TYPE_ALT { parse_sequence(data)? } else { Vec::new() };
    Ok(Element { typ, size_index, data, total: r.pos() - start, children })
}

fn parse_sequence(data: &[u8]) -> R<Vec<Element<'_>>> {
    let mut r = Reader::new(data);
    let mut v = Vec::new();
    while !r.is_empty() {
        v.push(parse_element(&mut r)?);
    }
    Ok(v)
}

/// What the integers in a list mean.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Ctx {
    Plain,
    /// An attribute ID list: 16-bit IDs and 32-bit ranges.
    AttrIds,
}

fn print_element(e: &Element<'_>, out: &mut Out, ctx: Ctx) {
    let n = e.data.len();
    field!(
        out,
        "{} ({}) with {} byte{} [{} extra bits] len {}",
        type_name(e.typ),
        e.typ,
        n,
        if n == 1 { "" } else { "s" },
        extra_bits(e.size_index),
        e.total
    );
    out.nest(|o| print_value(e, o, ctx));
}

fn print_value(e: &Element<'_>, out: &mut Out, ctx: Ctx) {
    match e.typ {
        TYPE_NIL => {}
        TYPE_UINT => print_uint(e.data, out, ctx),
        TYPE_SINT => print_sint(e.data, out),
        TYPE_UUID => print_uuid(e.data, out),
        TYPE_STRING | TYPE_URL => {
            let s: String = String::from_utf8_lossy(e.data)
                .trim_end_matches('\0')
                .chars()
                .map(|c| if c.is_control() { '.' } else { c })
                .collect();
            field!(out, "{} [len {}]", s, e.data.len());
        }
        TYPE_BOOL => {
            let v = e.data.first().copied().unwrap_or(0);
            field!(out, "{} (0x{:02x})", if v != 0 { "true" } else { "false" }, v);
        }
        TYPE_SEQ | TYPE_ALT => {
            for c in &e.children {
                print_element(c, out, ctx);
            }
        }
        _ => {
            out.hex(e.data);
        }
    }
}

fn be16(d: &[u8]) -> u16 {
    u16::from_be_bytes([d[0], d[1]])
}

fn print_uint(data: &[u8], out: &mut Out, ctx: Ctx) {
    match (ctx, data.len()) {
        (Ctx::AttrIds, 2) => {
            let id = be16(data);
            field!(out, "Attribute: {} (0x{:04x})", attribute_name(id), id)
        }
        (Ctx::AttrIds, 4) => field!(out, "Attribute range: 0x{:04x} - 0x{:04x}", be16(&data[..2]), be16(&data[2..])),
        (_, 1) => field!(out, "0x{:02x}", data[0]),
        (_, 2) => field!(out, "0x{:04x}", be16(data)),
        (_, 4) => field!(out, "0x{:08x}", u32::from_be_bytes([data[0], data[1], data[2], data[3]])),
        (_, 8) => field!(out, "0x{:016x}", u64::from_be_bytes(data.try_into().unwrap_or([0; 8]))),
        _ => out.hex(data),
    };
}

fn print_sint(data: &[u8], out: &mut Out) {
    match data.len() {
        1 => field!(out, "{} (0x{:02x})", data[0] as i8, data[0]),
        2 => field!(out, "{} (0x{:04x})", be16(data) as i16, be16(data)),
        4 => {
            let v = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
            field!(out, "{} (0x{:08x})", v as i32, v)
        }
        8 => {
            let v = u64::from_be_bytes(data.try_into().unwrap_or([0; 8]));
            field!(out, "{} (0x{:016x})", v as i64, v)
        }
        _ => out.hex(data),
    };
}

fn print_uuid(data: &[u8], out: &mut Out) {
    let u = match data.len() {
        2 => Uuid::U16(be16(data)),
        4 => Uuid::U32(u32::from_be_bytes([data[0], data[1], data[2], data[3]])),
        16 => {
            // SDP carries UUIDs big-endian; `Uuid::U128` is little-endian wire order.
            let mut b = [0u8; 16];
            for (i, x) in b.iter_mut().enumerate() {
                *x = data[15 - i];
            }
            Uuid::U128(b)
        }
        _ => {
            out.hex(data);
            return;
        }
    };
    field!(out, "{}", u.describe());
}

/// A sequence of (attribute ID, attribute value) pairs.
fn print_attribute_list(list: &Element<'_>, out: &mut Out) {
    if list.typ != TYPE_SEQ {
        out.error("Attribute list is not a sequence");
        print_element(list, out, Ctx::Plain);
        return;
    }
    let mut it = list.children.iter();
    while let Some(id) = it.next() {
        if id.typ == TYPE_UINT && id.data.len() == 2 {
            let n = be16(id.data);
            field!(out, "Attribute: {} (0x{:04x}) [len {}]", attribute_name(n), n, id.data.len());
        } else {
            out.error("Invalid attribute ID");
            print_element(id, out, Ctx::Plain);
        }
        match it.next() {
            Some(v) => out.nest(|o| match v.typ {
                TYPE_SEQ | TYPE_ALT => {
                    for c in &v.children {
                        print_element(c, o, Ctx::Plain);
                    }
                }
                _ => print_value(v, o, Ctx::Plain),
            }),
            None => out.nest(|o| {
                o.error("Missing attribute value");
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assigned::uuid16_name;
    use crate::l2cap::test_lines;

    fn run(payload: &[u8]) -> Vec<String> {
        let mut out = Out::new();
        decode(payload, &mut out);
        test_lines(&out)
    }

    #[test]
    fn service_search_attribute_request() {
        let l = run(&[0x06, 0x00, 0x01, 0x00, 0x0f, 0x35, 0x03, 0x19, 0x11, 0x01, 0xff, 0xff, 0x35, 0x05, 0x0a, 0x00, 0x00, 0xff, 0xff, 0x00]);
        assert_eq!(
            l,
            [
                "SDP: Service Search Attribute Request (0x06) tid 1 len 15".to_string(),
                "  Search pattern: [len 5]".into(),
                "    Sequence (6) with 3 bytes [8 extra bits] len 5".into(),
                "      UUID (3) with 2 bytes [0 extra bits] len 3".into(),
                format!("        {} (0x1101)", uuid16_name(0x1101).unwrap()),
                "  Max attribute bytes: 65535".into(),
                "  Attribute list: [len 7]".into(),
                "    Sequence (6) with 5 bytes [8 extra bits] len 7".into(),
                "      Unsigned Integer (1) with 4 bytes [0 extra bits] len 5".into(),
                "        Attribute range: 0x0000 - 0xffff".into(),
                "  Continuation state: 0".into(),
            ]
        );
    }

    #[test]
    fn service_search_attribute_response() {
        let l = run(&[
            0x07, 0x00, 0x01, 0x00, 0x17, 0x00, 0x14, 0x35, 0x12, 0x35, 0x10, 0x09, 0x00, 0x00, 0x0a, 0x00, 0x01, 0x00, 0x01, 0x09, 0x00, 0x01,
            0x35, 0x03, 0x19, 0x11, 0x01, 0x00,
        ]);
        assert_eq!(
            l,
            [
                "SDP: Service Search Attribute Response (0x07) tid 1 len 23".to_string(),
                "  Attribute bytes: 20".into(),
                "  Attribute list: [len 16] {position 0}".into(),
                "    Attribute: Service Record Handle (0x0000) [len 2]".into(),
                "      0x00010001".into(),
                "    Attribute: Service Class ID List (0x0001) [len 2]".into(),
                "      UUID (3) with 2 bytes [0 extra bits] len 3".into(),
                format!("        {} (0x1101)", uuid16_name(0x1101).unwrap()),
                "  Continuation state: 0".into(),
            ]
        );
    }

    #[test]
    fn service_search_request_and_response() {
        let l = run(&[0x02, 0x12, 0x34, 0x00, 0x08, 0x35, 0x03, 0x19, 0x01, 0x00, 0x00, 0x10, 0x00]);
        assert_eq!(l[0], "SDP: Service Search Request (0x02) tid 4660 len 8");
        assert_eq!(l[4], format!("        {} (0x0100)", uuid16_name(0x0100).unwrap()));
        assert_eq!(l[5], "  Max record count: 16");
        let l = run(&[0x03, 0x12, 0x34, 0x00, 0x0d, 0x00, 0x02, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00]);
        assert_eq!(
            l[1..],
            [
                "  Total record count: 2",
                "  Current record count: 2",
                "  Record handle: 0x00010000",
                "  Record handle: 0x00010001",
                "  Continuation state: 0",
            ]
        );
    }

    #[test]
    fn error_response() {
        let l = run(&[0x01, 0x00, 0x05, 0x00, 0x02, 0x00, 0x02]);
        assert_eq!(l, ["SDP: Error Response (0x01) tid 5 len 2", "  Error code: Invalid Service Record Handle (0x0002)"]);
    }

    #[test]
    fn attribute_response_with_strings_and_continuation() {
        // Service Name "SPP", Service Availability 0xff (uint8), a boolean and a 128-bit UUID on the base.
        let list = [
            0x09, 0x01, 0x00, 0x25, 0x03, b'S', b'P', b'P', // 0x0100 = "SPP"
            0x09, 0x00, 0x08, 0x08, 0xff, // 0x0008 = 0xff
            0x09, 0x02, 0x00, 0x28, 0x01, // 0x0200 = true
            0x09, 0x00, 0x03, 0x1c, 0x00, 0x00, 0x11, 0x01, 0x00, 0x00, 0x10, 0x00, 0x80, 0x00, 0x00, 0x80, 0x5f, 0x9b, 0x34, 0xfb,
        ];
        let mut pdu = vec![0x05, 0x00, 0x02, 0x00, 0x00, 0x00, (list.len() + 2) as u8, 0x35, list.len() as u8];
        pdu.extend_from_slice(&list);
        pdu.extend_from_slice(&[0x02, 0xaa, 0xbb]);
        pdu[4] = (pdu.len() - 5) as u8;
        let l = run(&pdu);
        assert_eq!(l[1], "  Attribute bytes: 40");
        assert_eq!(l[2], "  Attribute list: [len 38]");
        assert_eq!(l[3], "    Attribute: Service Name (0x0100) [len 2]");
        assert_eq!(l[4], "      SPP [len 3]");
        assert_eq!(l[5], "    Attribute: Service Availability (0x0008) [len 2]");
        assert_eq!(l[6], "      0xff");
        assert_eq!(l[7], "    Attribute: Unknown (0x0200) [len 2]");
        assert_eq!(l[8], "      true (0x01)");
        assert_eq!(l[9], "    Attribute: Service ID (0x0003) [len 2]");
        assert_eq!(l[10], format!("      {} (0x1101)", uuid16_name(0x1101).unwrap()));
        assert_eq!(l[11], "  Continuation state: 2");
        assert!(l[12].starts_with("    aa bb"));
    }

    #[test]
    fn partial_attribute_list_is_dumped() {
        // Attribute bytes announce a sequence that is longer than the data present.
        let l = run(&[0x05, 0x00, 0x03, 0x00, 0x07, 0x00, 0x04, 0x35, 0x10, 0x09, 0x00, 0x00]);
        assert_eq!(l[1], "  Attribute bytes: 4");
        assert_eq!(l[2], "  Attribute list: partial (not decoded)");
        assert!(l[3].starts_with("    35 10 09 00"));
    }

    #[test]
    fn malformed_data_element() {
        // A UUID with size index 0 (1 byte) is not allowed.
        let l = run(&[0x02, 0x00, 0x01, 0x00, 0x07, 0x35, 0x02, 0x18, 0x01, 0x00, 0x10, 0x00]);
        assert_eq!(l[1], "  Invalid size index 0 for UUID data element");
    }

    #[test]
    fn truncated_parameters() {
        let l = run(&[0x04, 0x00, 0x01, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00]);
        assert_eq!(l[1], "  Record handle: 0x00010000");
        assert!(l[2].starts_with("  Parameters truncated"), "{}", l[2]);
    }

    #[test]
    fn header_truncated_and_unknown_pdu() {
        assert_eq!(run(&[0x02, 0x00])[0], "SDP: header truncated");
        let l = run(&[0x09, 0x00, 0x01, 0x00, 0x01, 0xaa]);
        assert_eq!(l[0], "SDP: Unknown (0x09) tid 1 len 1");
        assert!(l[1].starts_with("  aa"));
    }
}
