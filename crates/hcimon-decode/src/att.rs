//! Attribute protocol (ATT) PDUs.
//!
//! Requests are remembered per connection so that responses can be interpreted
//! (a Read By Type Response only makes sense given the requested UUID), and the
//! attribute types learned from discovery are used to label handles and decode
//! values in later reads, writes and notifications.

use crate::assigned::uuid16_name;
use crate::context::{AttRequest, AttState, IndexState, LinkType};
use crate::field;
use crate::hci::common::{appearance, bits, conn_interval_value, hexstr};
use crate::reader::{Reader, Result};
use crate::tree::Out;
use crate::uuid::Uuid;

pub fn opcode_name(op: u8) -> Option<&'static str> {
    Some(match op {
        0x01 => "Error Response",
        0x02 => "Exchange MTU Request",
        0x03 => "Exchange MTU Response",
        0x04 => "Find Information Request",
        0x05 => "Find Information Response",
        0x06 => "Find By Type Value Request",
        0x07 => "Find By Type Value Response",
        0x08 => "Read By Type Request",
        0x09 => "Read By Type Response",
        0x0a => "Read Request",
        0x0b => "Read Response",
        0x0c => "Read Blob Request",
        0x0d => "Read Blob Response",
        0x0e => "Read Multiple Request",
        0x0f => "Read Multiple Response",
        0x10 => "Read By Group Type Request",
        0x11 => "Read By Group Type Response",
        0x12 => "Write Request",
        0x13 => "Write Response",
        0x16 => "Prepare Write Request",
        0x17 => "Prepare Write Response",
        0x18 => "Execute Write Request",
        0x19 => "Execute Write Response",
        0x1b => "Handle Value Notification",
        0x1d => "Handle Value Indication",
        0x1e => "Handle Value Confirmation",
        0x20 => "Read Multiple Variable Request",
        0x21 => "Read Multiple Variable Response",
        0x23 => "Multiple Handle Value Notification",
        0x52 => "Write Command",
        0xd2 => "Signed Write Command",
        _ => return None,
    })
}

/// Name of an ATT error code (Core Specification Vol 3, Part F, Section 3.4.1.1).
pub fn error_name(code: u8) -> Option<&'static str> {
    Some(match code {
        0x01 => "Invalid Handle",
        0x02 => "Read Not Permitted",
        0x03 => "Write Not Permitted",
        0x04 => "Invalid PDU",
        0x05 => "Insufficient Authentication",
        0x06 => "Request Not Supported",
        0x07 => "Invalid Offset",
        0x08 => "Insufficient Authorization",
        0x09 => "Prepare Queue Full",
        0x0a => "Attribute Not Found",
        0x0b => "Attribute Not Long",
        0x0c => "Insufficient Encryption Key Size",
        0x0d => "Invalid Attribute Value Length",
        0x0e => "Unlikely Error",
        0x0f => "Insufficient Encryption",
        0x10 => "Unsupported Group Type",
        0x11 => "Insufficient Resources",
        0x12 => "Database Out Of Sync",
        0x13 => "Value Not Allowed",
        0x80..=0x9f => "Application Error",
        0xfc => "Write Request Rejected",
        0xfd => "Client Characteristic Configuration Descriptor Improperly Configured",
        0xfe => "Procedure Already in Progress",
        0xff => "Out of Range",
        _ => return None,
    })
}

/// Whether `op` is a request (or indication) that the peer answers with opcode `op + 1`.
fn is_request(op: u8) -> bool {
    matches!(op, 0x02 | 0x04 | 0x06 | 0x08 | 0x0a | 0x0c | 0x0e | 0x10 | 0x12 | 0x16 | 0x18 | 0x1d | 0x20)
}

/// Outstanding requests kept per connection; older ones are dropped when a peer never answers.
const MAX_PENDING: usize = 32;

/// Decode an ATT PDU carried on `handle`.
pub fn decode(st: &mut IndexState, handle: u16, rx: bool, payload: &[u8], out: &mut Out, frame: u64) {
    let mut r = Reader::new(payload);
    let Ok(op) = r.u8() else {
        out.error("ATT: empty PDU");
        return;
    };
    let Some(name) = opcode_name(op) else {
        out.unknown(format!("ATT: Unknown (0x{op:02x}) len {}", r.remaining()));
        out.nest(|o| {
            o.hex(r.rest());
        });
        return;
    };
    field!(out, "ATT: {} (0x{:02x}) len {}", name, op, r.remaining());
    let att = &mut st.conn_or_insert(handle, LinkType::Unknown).att;
    out.nest(|o| match pdu(att, op, rx, &mut r, o, frame) {
        Ok(()) if r.is_empty() => {}
        Ok(()) => {
            o.error("Unexpected trailing data");
            o.hex(r.rest());
        }
        Err(e) => {
            o.error(format!("Malformed PDU: {e}"));
            o.hex(r.rest());
        }
    });
}

fn pdu(att: &mut AttState, op: u8, rx: bool, r: &mut Reader<'_>, o: &mut Out, frame: u64) -> Result<()> {
    if is_request(op) {
        push_pending(att, op, rx, r.peek(), frame);
    }
    match op {
        0x01 => error_response(att, rx, r, o),
        0x02 => {
            field!(o, "Client RX MTU: {}", r.u16()?);
            Ok(())
        }
        0x03 => exchange_mtu_rsp(att, rx, r, o),
        0x04 => handle_range(r, o),
        0x05 => find_info_rsp(att, rx, r, o),
        0x06 => find_by_type_value_req(att, r, o),
        0x07 => find_by_type_value_rsp(att, rx, r, o),
        0x08 => {
            handle_range(r, o)?;
            uuid_line("Attribute type", o, r)
        }
        0x09 => read_by_type_rsp(att, rx, r, o),
        0x0a => {
            let h = r.u16()?;
            handle_line(att, o, h);
            Ok(())
        }
        0x0b => read_rsp(att, rx, r, o),
        0x0c => read_blob_req(att, r, o),
        0x0d => read_blob_rsp(att, rx, r, o),
        0x0e | 0x20 => read_multiple_req(att, r, o),
        0x0f => read_multiple_rsp(att, rx, r, o),
        0x10 => {
            handle_range(r, o)?;
            uuid_line("Attribute group type", o, r)
        }
        0x11 => read_by_group_type_rsp(att, rx, r, o),
        0x12 | 0x52 => write(att, r, o),
        0x13 => {
            take_pending(att, 0x12, rx);
            Ok(())
        }
        0x16 => prepare_write(att, r, o),
        0x17 => {
            take_pending(att, 0x16, rx);
            prepare_write(att, r, o)
        }
        0x18 => execute_write_req(r, o),
        0x19 => {
            take_pending(att, 0x18, rx);
            Ok(())
        }
        0x1b | 0x1d => notify(att, r, o),
        0x1e => {
            take_pending(att, 0x1d, rx);
            Ok(())
        }
        0x21 => read_multiple_variable_rsp(att, rx, r, o),
        0x23 => multiple_notify(att, r, o),
        0xd2 => signed_write(att, r, o),
        _ => {
            o.hex(r.rest());
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Request tracking

fn push_pending(att: &mut AttState, op: u8, rx: bool, params: &[u8], frame: u64) {
    while att.pending.len() >= MAX_PENDING {
        att.pending.pop_front();
    }
    att.pending.push_back(AttRequest { opcode: op, tx: !rx, params: params.to_vec(), frame });
}

/// Remove and return the oldest outstanding request with opcode `op` that a PDU
/// travelling in this direction answers: a received response answers a request
/// that was transmitted, and vice versa.
fn take_pending(att: &mut AttState, op: u8, rx: bool) -> Option<AttRequest> {
    let i = att.pending.iter().position(|p| p.opcode == op && p.tx == rx)?;
    att.pending.remove(i)
}

/// First 16-bit parameter of a request (the attribute handle of most requests).
fn params_u16(req: &AttRequest) -> Option<u16> {
    Reader::new(&req.params).u16().ok()
}

/// The UUID following the handle range in Read By Type / Read By Group Type / Find By Type Value requests.
fn params_uuid(req: &AttRequest) -> Option<Uuid> {
    let mut r = Reader::new(&req.params);
    r.skip(4).ok()?;
    let n = r.remaining();
    Uuid::read(&mut r, n).ok().flatten()
}

/// The set of handles of a Read Multiple (Variable) request.
fn params_handles(req: &AttRequest) -> Vec<u16> {
    req.params.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect()
}

// ---------------------------------------------------------------------------
// Common fields

fn handle_range(r: &mut Reader<'_>, o: &mut Out) -> Result<()> {
    let start = r.u16()?;
    let end = r.u16()?;
    field!(o, "Handle range: 0x{:04x}-0x{:04x}", start, end);
    Ok(())
}

/// `Handle: 0x001d Type: Client Characteristic Configuration (0x2902)` when the type was learned.
fn handle_line(att: &AttState, o: &mut Out, h: u16) {
    match att.attr_types.get(&h) {
        Some(u) => field!(o, "Handle: 0x{:04x} Type: {}", h, u.describe()),
        None => field!(o, "Handle: 0x{:04x}", h),
    };
}

/// Print the rest of the reader as a UUID (16, 32 or 128 bits).
fn uuid_line(label: &str, o: &mut Out, r: &mut Reader<'_>) -> Result<()> {
    let n = r.remaining();
    match Uuid::read(r, n)? {
        Some(u) => {
            field!(o, "{}: {}", label, u.describe());
        }
        None => {
            o.error(format!("{label}: invalid UUID length {}", r.remaining()));
            o.hex(r.rest());
        }
    }
    Ok(())
}

fn offset_line(o: &mut Out, offset: u16) {
    field!(o, "Offset: {} (0x{:04x})", offset, offset);
}

/// Print an attribute value as hex and, when its type is known, decoded underneath.
fn data_field(att: &mut AttState, o: &mut Out, label: &str, uuid: Option<Uuid>, data: &[u8]) {
    if data.is_empty() {
        field!(o, "{}: (empty)", label);
        return;
    }
    if data.len() <= 32 {
        o.hex_field(label, data);
    } else {
        field!(o, "{}: {} bytes", label, data.len());
        o.nest(|o| {
            o.hex(data);
        });
    }
    if let Some(u) = uuid {
        o.nest(|o| decode_value(att, o, u, data));
    }
}

// ---------------------------------------------------------------------------
// PDUs

fn error_response(att: &mut AttState, rx: bool, r: &mut Reader<'_>, o: &mut Out) -> Result<()> {
    let req = r.u8()?;
    let h = r.u16()?;
    let code = r.u8()?;
    match opcode_name(req) {
        Some(n) => field!(o, "{} (0x{:02x})", n, req),
        None => o.unknown(format!("Unknown request (0x{req:02x})")),
    };
    handle_line(att, o, h);
    match error_name(code) {
        Some(n) => field!(o, "Error: {} (0x{:02x})", n, code),
        None => o.unknown(format!("Error: Reserved (0x{code:02x})")),
    };
    take_pending(att, req, rx);
    Ok(())
}

fn exchange_mtu_rsp(att: &mut AttState, rx: bool, r: &mut Reader<'_>, o: &mut Out) -> Result<()> {
    let server = r.u16()?;
    field!(o, "Server RX MTU: {}", server);
    let client = take_pending(att, 0x02, rx).and_then(|q| params_u16(&q));
    att.mtu = match client {
        Some(c) => c.min(server),
        None => server,
    };
    Ok(())
}

fn find_info_rsp(att: &mut AttState, rx: bool, r: &mut Reader<'_>, o: &mut Out) -> Result<()> {
    take_pending(att, 0x04, rx);
    let format = r.u8()?;
    let size = match format {
        0x01 => {
            field!(o, "Format: UUID-16 (0x01)");
            2
        }
        0x02 => {
            field!(o, "Format: UUID-128 (0x02)");
            16
        }
        _ => {
            o.unknown(format!("Format: Reserved (0x{format:02x})"));
            o.hex(r.rest());
            return Ok(());
        }
    };
    while r.remaining() >= 2 + size {
        let h = r.u16()?;
        let u = if size == 2 { Uuid::U16(r.u16()?) } else { Uuid::U128(r.array::<16>()?) };
        field!(o, "Handle: 0x{:04x} Type: {}", h, u.describe());
        att.attr_types.insert(h, u);
    }
    Ok(())
}

fn find_by_type_value_req(att: &mut AttState, r: &mut Reader<'_>, o: &mut Out) -> Result<()> {
    handle_range(r, o)?;
    let t = r.u16()?;
    field!(o, "Attribute type: {}", Uuid::U16(t).describe());
    data_field(att, o, "Value", Some(Uuid::U16(t)), r.rest());
    Ok(())
}

fn find_by_type_value_rsp(att: &mut AttState, rx: bool, r: &mut Reader<'_>, o: &mut Out) -> Result<()> {
    let t = take_pending(att, 0x06, rx).and_then(|q| {
        let mut p = Reader::new(&q.params);
        p.skip(4).ok()?;
        p.u16().ok()
    });
    while r.remaining() >= 4 {
        let found = r.u16()?;
        let end = r.u16()?;
        field!(o, "Handle range: 0x{:04x}-0x{:04x}", found, end);
        if let Some(t) = t {
            att.attr_types.insert(found, Uuid::U16(t));
        }
    }
    Ok(())
}

fn entries(n: usize) -> String {
    format!("{n} entr{}", if n == 1 { "y" } else { "ies" })
}

fn read_by_type_rsp(att: &mut AttState, rx: bool, r: &mut Reader<'_>, o: &mut Out) -> Result<()> {
    let uuid = take_pending(att, 0x08, rx).and_then(|q| params_uuid(&q));
    let len = r.u8()? as usize;
    field!(o, "Attribute data length: {}", len);
    if len < 2 {
        o.error("Invalid attribute data length");
        o.hex(r.rest());
        return Ok(());
    }
    let count = r.remaining() / len;
    field!(o, "Attribute data list: {}", entries(count));
    for _ in 0..count {
        let h = r.u16()?;
        let data = r.bytes(len - 2)?;
        if let Some(u) = uuid {
            att.attr_types.insert(h, u);
        }
        field!(o, "Handle: 0x{:04x}", h);
        data_field(att, o, "Value", uuid, data);
    }
    Ok(())
}

fn read_by_group_type_rsp(att: &mut AttState, rx: bool, r: &mut Reader<'_>, o: &mut Out) -> Result<()> {
    let group = take_pending(att, 0x10, rx).and_then(|q| params_uuid(&q));
    let len = r.u8()? as usize;
    field!(o, "Attribute data length: {}", len);
    if len < 4 {
        o.error("Invalid attribute data length");
        o.hex(r.rest());
        return Ok(());
    }
    let count = r.remaining() / len;
    field!(o, "Attribute group list: {}", entries(count));
    for _ in 0..count {
        let start = r.u16()?;
        let end = r.u16()?;
        let data = r.bytes(len - 4)?;
        field!(o, "Handle range: 0x{:04x}-0x{:04x}", start, end);
        match data.len() {
            2 | 16 => uuid_line("UUID", o, &mut Reader::new(data))?,
            _ => {
                o.hex_field("Value", data);
            }
        }
        if let Some(g) = group {
            att.attr_types.insert(start, g);
        }
    }
    Ok(())
}

fn read_rsp(att: &mut AttState, rx: bool, r: &mut Reader<'_>, o: &mut Out) -> Result<()> {
    let h = take_pending(att, 0x0a, rx).and_then(|q| params_u16(&q));
    let uuid = h.and_then(|h| att.attr_types.get(&h).copied());
    if let Some(h) = h {
        handle_line(att, o, h);
    }
    data_field(att, o, "Value", uuid, r.rest());
    Ok(())
}

fn read_blob_req(att: &mut AttState, r: &mut Reader<'_>, o: &mut Out) -> Result<()> {
    let h = r.u16()?;
    handle_line(att, o, h);
    offset_line(o, r.u16()?);
    Ok(())
}

fn read_blob_rsp(att: &mut AttState, rx: bool, r: &mut Reader<'_>, o: &mut Out) -> Result<()> {
    let req = take_pending(att, 0x0c, rx).and_then(|q| {
        let mut p = Reader::new(&q.params);
        Some((p.u16().ok()?, p.u16().ok()?))
    });
    let mut uuid = None;
    if let Some((h, offset)) = req {
        handle_line(att, o, h);
        offset_line(o, offset);
        // Only a value read from the start can be interpreted as a whole.
        if offset == 0 {
            uuid = att.attr_types.get(&h).copied();
        }
    }
    data_field(att, o, "Value", uuid, r.rest());
    Ok(())
}

fn read_multiple_req(att: &mut AttState, r: &mut Reader<'_>, o: &mut Out) -> Result<()> {
    while r.remaining() >= 2 {
        let h = r.u16()?;
        handle_line(att, o, h);
    }
    Ok(())
}

fn read_multiple_rsp(att: &mut AttState, rx: bool, r: &mut Reader<'_>, o: &mut Out) -> Result<()> {
    if let Some(q) = take_pending(att, 0x0e, rx) {
        for h in params_handles(&q) {
            handle_line(att, o, h);
        }
    }
    // The values are concatenated without delimiters, so they cannot be split.
    data_field(att, o, "Value", None, r.rest());
    Ok(())
}

fn read_multiple_variable_rsp(att: &mut AttState, rx: bool, r: &mut Reader<'_>, o: &mut Out) -> Result<()> {
    let handles = take_pending(att, 0x20, rx).map(|q| params_handles(&q)).unwrap_or_default();
    let mut i = 0;
    while !r.is_empty() {
        let len = r.u16()?;
        let data = r.bytes(len as usize)?;
        let h = handles.get(i).copied();
        let uuid = h.and_then(|h| att.attr_types.get(&h).copied());
        if let Some(h) = h {
            handle_line(att, o, h);
        }
        field!(o, "Length: {}", len);
        data_field(att, o, "Value", uuid, data);
        i += 1;
    }
    Ok(())
}

fn write(att: &mut AttState, r: &mut Reader<'_>, o: &mut Out) -> Result<()> {
    let h = r.u16()?;
    handle_line(att, o, h);
    let uuid = att.attr_types.get(&h).copied();
    data_field(att, o, "Data", uuid, r.rest());
    Ok(())
}

fn prepare_write(att: &mut AttState, r: &mut Reader<'_>, o: &mut Out) -> Result<()> {
    let h = r.u16()?;
    handle_line(att, o, h);
    offset_line(o, r.u16()?);
    // A prepared write carries part of a value; it is not decoded.
    data_field(att, o, "Data", None, r.rest());
    Ok(())
}

fn execute_write_req(r: &mut Reader<'_>, o: &mut Out) -> Result<()> {
    let flags = r.u8()?;
    match flags {
        0x00 => field!(o, "Flags: Cancel all prepared writes (0x00)"),
        0x01 => field!(o, "Flags: Immediately write all pending values (0x01)"),
        _ => o.unknown(format!("Flags: Reserved (0x{flags:02x})")),
    };
    Ok(())
}

fn notify(att: &mut AttState, r: &mut Reader<'_>, o: &mut Out) -> Result<()> {
    let h = r.u16()?;
    handle_line(att, o, h);
    let uuid = att.attr_types.get(&h).copied();
    data_field(att, o, "Data", uuid, r.rest());
    Ok(())
}

fn multiple_notify(att: &mut AttState, r: &mut Reader<'_>, o: &mut Out) -> Result<()> {
    while !r.is_empty() {
        let h = r.u16()?;
        let len = r.u16()?;
        let data = r.bytes(len as usize)?;
        handle_line(att, o, h);
        field!(o, "Length: {}", len);
        let uuid = att.attr_types.get(&h).copied();
        data_field(att, o, "Data", uuid, data);
    }
    Ok(())
}

fn signed_write(att: &mut AttState, r: &mut Reader<'_>, o: &mut Out) -> Result<()> {
    let h = r.u16()?;
    handle_line(att, o, h);
    if r.remaining() < 12 {
        o.error("Missing authentication signature");
        o.hex(r.rest());
        return Ok(());
    }
    let data = r.bytes(r.remaining() - 12)?;
    let uuid = att.attr_types.get(&h).copied();
    data_field(att, o, "Data", uuid, data);
    field!(o, "Signature: {}", hexstr(r.bytes(12)?));
    Ok(())
}

// ---------------------------------------------------------------------------
// Attribute values

static CHRC_PROPS: &[(u8, &str)] = &[
    (0, "Broadcast (0x01)"),
    (1, "Read (0x02)"),
    (2, "Write Without Response (0x04)"),
    (3, "Write (0x08)"),
    (4, "Notify (0x10)"),
    (5, "Indicate (0x20)"),
    (6, "Authenticated Signed Writes (0x40)"),
    (7, "Extended Properties (0x80)"),
];

static CLIENT_FEATURES: &[(u8, &str)] = &[
    (0, "Robust Caching"),
    (1, "Enhanced ATT bearer"),
    (2, "Multiple Handle Value Notifications"),
];

static SERVER_FEATURES: &[(u8, &str)] = &[(0, "EATT Supported")];

/// Decode a value whose attribute type is `uuid`, appending lines at the current level.
fn decode_value(att: &mut AttState, o: &mut Out, uuid: Uuid, data: &[u8]) {
    let Uuid::U16(t) = uuid.normalized() else { return };
    let mut r = Reader::new(data);
    let res = match t {
        0x2800 | 0x2801 => uuid_line("UUID", o, &mut r),
        0x2802 => include(o, &mut r),
        0x2803 => characteristic(att, o, &mut r),
        0x2900 => bitmask16(o, &mut r, &[(0, "Reliable Write (0x01)"), (1, "Writable Auxiliaries (0x02)")]),
        0x2901 | 0x2a00 | 0x2a24..=0x2a29 => string(t, o, &mut r),
        0x2902 => bitmask16(o, &mut r, &[(0, "Notification (0x01)"), (1, "Indication (0x02)")]),
        0x2903 => bitmask16(o, &mut r, &[(0, "Broadcast (0x01)")]),
        0x2904 => presentation_format(o, &mut r),
        0x2908 => report_reference(o, &mut r),
        0x2a01 => appearance(&mut r, o),
        0x2a04 => preferred_conn_params(o, &mut r),
        0x2a05 => handle_range(&mut r, o),
        0x2a19 => battery_level(o, &mut r),
        0x2a23 => system_id(o, &mut r),
        0x2a37 => heart_rate_measurement(o, &mut r),
        0x2a38 => body_sensor_location(o, &mut r),
        0x2a50 => pnp_id(o, &mut r),
        0x2b29 => feature_bits(o, &mut r, CLIENT_FEATURES),
        0x2b2a => {
            field!(o, "Database Hash: {}", hexstr(r.rest()));
            Ok(())
        }
        0x2b3a => feature_bits(o, &mut r, SERVER_FEATURES),
        _ => return,
    };
    match res {
        Ok(()) if r.is_empty() => {}
        Ok(()) => {
            o.error("Unexpected trailing data");
            o.hex(r.rest());
        }
        Err(_) => {
            o.error("Value too short");
        }
    }
}

fn include(o: &mut Out, r: &mut Reader<'_>) -> Result<()> {
    handle_range(r, o)?;
    match r.remaining() {
        0 => Ok(()),
        2 => uuid_line("UUID", o, r),
        _ => {
            o.hex_field("Value", r.rest());
            Ok(())
        }
    }
}

/// Characteristic declaration: properties, value handle and value UUID.  The
/// value handle's type is recorded so later reads and notifications can be decoded.
fn characteristic(att: &mut AttState, o: &mut Out, r: &mut Reader<'_>) -> Result<()> {
    let props = r.u8()?;
    field!(o, "Properties: 0x{:02x}", props);
    o.nest(|o| bits(o, props as u64, CHRC_PROPS, 8));
    let vh = r.u16()?;
    field!(o, "Value Handle: 0x{:04x}", vh);
    let n = r.remaining();
    match Uuid::read(r, n)? {
        Some(u) => {
            field!(o, "Value UUID: {}", u.describe());
            att.attr_types.insert(vh, u);
            att.char_values.insert(vh, u);
        }
        None => {
            o.error(format!("Value UUID: invalid UUID length {}", r.remaining()));
            o.hex(r.rest());
        }
    }
    Ok(())
}

fn bitmask16(o: &mut Out, r: &mut Reader<'_>, names: &[(u8, &str)]) -> Result<()> {
    let v = r.u16()?;
    bits(o, v as u64, names, 16);
    Ok(())
}

fn string(t: u16, o: &mut Out, r: &mut Reader<'_>) -> Result<()> {
    let label = uuid16_name(t).unwrap_or("String");
    field!(o, "{}: {}", label, String::from_utf8_lossy(r.rest()));
    Ok(())
}

fn format_name(f: u8) -> Option<&'static str> {
    Some(match f {
        0x01 => "boolean",
        0x02 => "2bit",
        0x03 => "nibble",
        0x04 => "uint8",
        0x05 => "uint12",
        0x06 => "uint16",
        0x07 => "uint24",
        0x08 => "uint32",
        0x09 => "uint48",
        0x0a => "uint64",
        0x0b => "uint128",
        0x0c => "sint8",
        0x0d => "sint12",
        0x0e => "sint16",
        0x0f => "sint24",
        0x10 => "sint32",
        0x11 => "sint48",
        0x12 => "sint64",
        0x13 => "sint128",
        0x14 => "float32",
        0x15 => "float64",
        0x16 => "SFLOAT",
        0x17 => "FLOAT",
        0x18 => "duint16",
        0x19 => "utf8s",
        0x1a => "utf16s",
        0x1b => "struct",
        0x1c => "medfloat16",
        0x1d => "medfloat32",
        _ => return None,
    })
}

fn presentation_format(o: &mut Out, r: &mut Reader<'_>) -> Result<()> {
    let f = r.u8()?;
    match format_name(f) {
        Some(n) => field!(o, "Format: {} (0x{:02x})", n, f),
        None => o.unknown(format!("Format: Reserved (0x{f:02x})")),
    };
    field!(o, "Exponent: {}", r.i8()?);
    field!(o, "Unit: {}", Uuid::U16(r.u16()?).describe());
    let ns = r.u8()?;
    match ns {
        0x00 => field!(o, "Name Space: None (0x00)"),
        0x01 => field!(o, "Name Space: Bluetooth SIG (0x01)"),
        _ => o.unknown(format!("Name Space: Reserved (0x{ns:02x})")),
    };
    field!(o, "Description: 0x{:04x}", r.u16()?);
    Ok(())
}

fn report_reference(o: &mut Out, r: &mut Reader<'_>) -> Result<()> {
    field!(o, "Report ID: {}", r.u8()?);
    let t = r.u8()?;
    match t {
        0x01 => field!(o, "Report Type: Input Report (0x01)"),
        0x02 => field!(o, "Report Type: Output Report (0x02)"),
        0x03 => field!(o, "Report Type: Feature Report (0x03)"),
        _ => o.unknown(format!("Report Type: Reserved (0x{t:02x})")),
    };
    Ok(())
}

fn preferred_conn_params(o: &mut Out, r: &mut Reader<'_>) -> Result<()> {
    conn_interval_value("Minimum Connection Interval", o, r.u16()?);
    conn_interval_value("Maximum Connection Interval", o, r.u16()?);
    field!(o, "Peripheral Latency: {}", r.u16()?);
    let t = r.u16()?;
    if t == 0xffff {
        field!(o, "Connection Supervision Timeout: No specific value (0xffff)");
    } else {
        field!(o, "Connection Supervision Timeout: {} msec (0x{:04x})", t as u32 * 10, t);
    }
    Ok(())
}

fn battery_level(o: &mut Out, r: &mut Reader<'_>) -> Result<()> {
    field!(o, "Battery Level: {}%", r.u8()?);
    Ok(())
}

fn system_id(o: &mut Out, r: &mut Reader<'_>) -> Result<()> {
    let v = r.u64()?;
    field!(o, "Manufacturer Identifier: 0x{:010x}", v & 0xff_ffff_ffff);
    field!(o, "Organizationally Unique Identifier: 0x{:06x}", v >> 40);
    Ok(())
}

fn heart_rate_measurement(o: &mut Out, r: &mut Reader<'_>) -> Result<()> {
    let flags = r.u8()?;
    field!(o, "Flags: 0x{:02x}", flags);
    o.nest(|o| {
        o.line(if flags & 0x01 != 0 { "Heart Rate Value Format: UINT16" } else { "Heart Rate Value Format: UINT8" });
        o.line(match (flags >> 1) & 0x03 {
            0 | 1 => "Sensor Contact: Not supported",
            2 => "Sensor Contact: Supported, contact not detected",
            _ => "Sensor Contact: Supported, contact detected",
        });
        if flags & 0x08 != 0 {
            o.line("Energy Expended present");
        }
        if flags & 0x10 != 0 {
            o.line("RR-Interval present");
        }
        if flags & 0xe0 != 0 {
            o.unknown(format!("Reserved bits (0x{:02x})", flags & 0xe0));
        }
    });
    let hr = if flags & 0x01 != 0 { r.u16()? } else { r.u8()? as u16 };
    field!(o, "Heart Rate: {} bpm", hr);
    if flags & 0x08 != 0 {
        field!(o, "Energy Expended: {} kJ", r.u16()?);
    }
    if flags & 0x10 != 0 {
        while r.remaining() >= 2 {
            let rr = r.u16()?;
            // Units of 1/1024 second.
            let us = rr as u64 * 1_000_000 / 1024;
            field!(o, "RR-Interval: {}.{:03} msec (0x{:04x})", us / 1000, us % 1000, rr);
        }
    }
    Ok(())
}

fn body_sensor_location(o: &mut Out, r: &mut Reader<'_>) -> Result<()> {
    let v = r.u8()?;
    let name = match v {
        0x00 => "Other",
        0x01 => "Chest",
        0x02 => "Wrist",
        0x03 => "Finger",
        0x04 => "Hand",
        0x05 => "Ear Lobe",
        0x06 => "Foot",
        _ => {
            o.unknown(format!("Body Sensor Location: Reserved (0x{v:02x})"));
            return Ok(());
        }
    };
    field!(o, "Body Sensor Location: {} (0x{:02x})", name, v);
    Ok(())
}

fn pnp_id(o: &mut Out, r: &mut Reader<'_>) -> Result<()> {
    let src = r.u8()?;
    match src {
        0x01 => field!(o, "Vendor ID Source: Bluetooth SIG (0x01)"),
        0x02 => field!(o, "Vendor ID Source: USB Implementer's Forum (0x02)"),
        _ => o.unknown(format!("Vendor ID Source: Reserved (0x{src:02x})")),
    };
    field!(o, "Vendor ID: 0x{:04x}", r.u16()?);
    field!(o, "Product ID: 0x{:04x}", r.u16()?);
    field!(o, "Product Version: 0x{:04x}", r.u16()?);
    Ok(())
}

/// Feature bit array (Client/Server Supported Features): one line per set bit of the first 8 octets.
fn feature_bits(o: &mut Out, r: &mut Reader<'_>, names: &[(u8, &str)]) -> Result<()> {
    let data = r.rest();
    let mut mask = 0u64;
    for (i, b) in data.iter().take(8).enumerate() {
        mask |= (*b as u64) << (8 * i);
    }
    bits(o, mask, names, 64);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::render_lines;

    /// Render the tree as indented text (two spaces per level) for assertions.
    fn lines(out: &Out) -> Vec<String> {
        let mut v = Vec::new();
        render_lines(out.roots(), 0, |indent, n| v.push(format!("{}{}", " ".repeat(indent), n.text)));
        v
    }

    fn run(st: &mut IndexState, rx: bool, pdu: &[u8]) -> Vec<String> {
        let mut out = Out::new();
        st.frames += 1;
        let frame = st.frames;
        decode(st, 0x0040, rx, pdu, &mut out, frame);
        lines(&out)
    }

    #[test]
    fn exchange_mtu_sets_negotiated_value() {
        let mut st = IndexState::default();
        assert_eq!(run(&mut st, true, &[0x02, 0x0f, 0x02]), ["ATT: Exchange MTU Request (0x02) len 2", "  Client RX MTU: 527"]);
        assert_eq!(st.conn(0x40).unwrap().att.pending.len(), 1);
        assert_eq!(run(&mut st, false, &[0x03, 0x41, 0x00]), ["ATT: Exchange MTU Response (0x03) len 2", "  Server RX MTU: 65"]);
        let att = &st.conn(0x40).unwrap().att;
        assert_eq!(att.mtu, 65);
        assert!(att.pending.is_empty());
    }

    #[test]
    fn error_response() {
        let mut st = IndexState::default();
        run(&mut st, true, &[0x10, 0x22, 0x00, 0xff, 0xff, 0x00, 0x28]);
        let l = run(&mut st, false, &[0x01, 0x10, 0x22, 0x00, 0x0a]);
        assert_eq!(
            l,
            [
                "ATT: Error Response (0x01) len 4",
                "  Read By Group Type Request (0x10)",
                "  Handle: 0x0022",
                "  Error: Attribute Not Found (0x0a)",
            ]
        );
        assert!(st.conn(0x40).unwrap().att.pending.is_empty());
        let l = run(&mut st, false, &[0x01, 0x12, 0x01, 0x00, 0x85]);
        assert_eq!(l[3], "  Error: Application Error (0x85)");
    }

    #[test]
    fn discovery_teaches_handle_types_used_by_notification() {
        let mut st = IndexState::default();
        // Primary service discovery (from the sample capture).
        let l = run(&mut st, true, &[0x10, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28]);
        assert_eq!(l[1..], ["  Handle range: 0x0001-0xffff", "  Attribute group type: Primary Service (0x2800)"]);
        let l = run(
            &mut st,
            false,
            &[
                0x11, 0x06, 0x01, 0x00, 0x08, 0x00, 0x01, 0x18, 0x09, 0x00, 0x0f, 0x00, 0x00, 0x18, 0x10, 0x00, 0x14, 0x00,
                0x0f, 0x18, 0x15, 0x00, 0x19, 0x00, 0x0a, 0x18, 0x1a, 0x00, 0x21, 0x00, 0x0d, 0x18,
            ],
        );
        assert_eq!(
            l[..6],
            [
                "ATT: Read By Group Type Response (0x11) len 31",
                "  Attribute data length: 6",
                "  Attribute group list: 5 entries",
                "  Handle range: 0x0001-0x0008",
                "  UUID: GATT (0x1801)",
                "  Handle range: 0x0009-0x000f",
            ]
        );
        assert_eq!(l[11], "  Handle range: 0x001a-0x0021");
        assert_eq!(l[12], "  UUID: Heart Rate (0x180d)");
        assert_eq!(st.conn(0x40).unwrap().att.attr_types[&0x001a], Uuid::U16(0x2800));

        // Characteristic discovery inside the Heart Rate service.
        run(&mut st, true, &[0x08, 0x1a, 0x00, 0x21, 0x00, 0x03, 0x28]);
        let l = run(
            &mut st,
            false,
            &[
                0x09, 0x07, 0x1b, 0x00, 0x10, 0x1c, 0x00, 0x37, 0x2a, 0x1e, 0x00, 0x02, 0x1f, 0x00, 0x38, 0x2a, 0x20, 0x00,
                0x08, 0x21, 0x00, 0x39, 0x2a,
            ],
        );
        assert_eq!(
            l[..10],
            [
                "ATT: Read By Type Response (0x09) len 22",
                "  Attribute data length: 7",
                "  Attribute data list: 3 entries",
                "  Handle: 0x001b",
                "  Value: 10 1c 00 37 2a",
                "    Properties: 0x10",
                "      Notify (0x10)",
                "    Value Handle: 0x001c",
                "    Value UUID: Heart Rate Measurement (0x2a37)",
                "  Handle: 0x001e",
            ]
        );
        let att = &st.conn(0x40).unwrap().att;
        assert_eq!(att.attr_types[&0x001b], Uuid::U16(0x2803));
        assert_eq!(att.char_values[&0x001c], Uuid::U16(0x2a37));
        assert_eq!(att.char_values[&0x0021], Uuid::U16(0x2a39));
        assert!(att.pending.is_empty());

        // The notification is now labelled and its value decoded.
        let l = run(&mut st, false, &[0x1b, 0x1c, 0x00, 0x06, 0x68]);
        assert_eq!(
            l,
            [
                "ATT: Handle Value Notification (0x1b) len 4",
                "  Handle: 0x001c Type: Heart Rate Measurement (0x2a37)",
                "  Data: 06 68",
                "    Flags: 0x06",
                "      Heart Rate Value Format: UINT8",
                "      Sensor Contact: Supported, contact detected",
                "    Heart Rate: 104 bpm",
            ]
        );
    }

    #[test]
    fn find_information_then_ccc_write_and_read() {
        let mut st = IndexState::default();
        run(&mut st, true, &[0x04, 0x1d, 0x00, 0x1d, 0x00]);
        let l = run(&mut st, false, &[0x05, 0x01, 0x1d, 0x00, 0x02, 0x29]);
        assert_eq!(
            l,
            [
                "ATT: Find Information Response (0x05) len 5",
                "  Format: UUID-16 (0x01)",
                "  Handle: 0x001d Type: Client Characteristic Configuration (0x2902)",
            ]
        );
        let l = run(&mut st, true, &[0x12, 0x1d, 0x00, 0x01, 0x00]);
        assert_eq!(
            l,
            [
                "ATT: Write Request (0x12) len 4",
                "  Handle: 0x001d Type: Client Characteristic Configuration (0x2902)",
                "  Data: 01 00",
                "    Notification (0x01)",
            ]
        );
        assert_eq!(run(&mut st, false, &[0x13]), ["ATT: Write Response (0x13) len 0"]);
        assert!(st.conn(0x40).unwrap().att.pending.is_empty());

        run(&mut st, true, &[0x0a, 0x1d, 0x00]);
        let l = run(&mut st, false, &[0x0b, 0x02, 0x00]);
        assert_eq!(
            l,
            [
                "ATT: Read Response (0x0b) len 2",
                "  Handle: 0x001d Type: Client Characteristic Configuration (0x2902)",
                "  Value: 02 00",
                "    Indication (0x02)",
            ]
        );
    }

    #[test]
    fn read_by_type_device_name() {
        let mut st = IndexState::default();
        run(&mut st, true, &[0x08, 0x09, 0x00, 0x0f, 0x00, 0x00, 0x2a]);
        let mut pdu = vec![0x09, 0x19, 0x0b, 0x00];
        pdu.extend_from_slice(b"Zephyr Heartrate Sensor");
        let l = run(&mut st, false, &pdu);
        assert_eq!(l[3], "  Handle: 0x000b");
        assert_eq!(l[5], "    Device Name: Zephyr Heartrate Sensor");
        assert_eq!(st.conn(0x40).unwrap().att.attr_types[&0x000b], Uuid::U16(0x2a00));
    }

    #[test]
    fn responses_match_requests_by_direction() {
        // A request received from the peer must not be answered by a response that is also received.
        let mut st = IndexState::default();
        run(&mut st, true, &[0x0a, 0x05, 0x00]);
        run(&mut st, true, &[0x0b, 0x01]);
        assert_eq!(st.conn(0x40).unwrap().att.pending.len(), 1);
        let l = run(&mut st, false, &[0x0b, 0x01]);
        assert_eq!(l, ["ATT: Read Response (0x0b) len 1", "  Handle: 0x0005", "  Value: 01"]);
        assert!(st.conn(0x40).unwrap().att.pending.is_empty());
    }

    #[test]
    fn read_blob() {
        let mut st = IndexState::default();
        let l = run(&mut st, true, &[0x0c, 0x03, 0x00, 0x16, 0x00]);
        assert_eq!(l, ["ATT: Read Blob Request (0x0c) len 4", "  Handle: 0x0003", "  Offset: 22 (0x0016)"]);
        let l = run(&mut st, false, &[0x0d, 0x41, 0x42]);
        assert_eq!(l, ["ATT: Read Blob Response (0x0d) len 2", "  Handle: 0x0003", "  Offset: 22 (0x0016)", "  Value: 41 42"]);
    }

    #[test]
    fn find_by_type_value() {
        let mut st = IndexState::default();
        let l = run(&mut st, true, &[0x06, 0x01, 0x00, 0xff, 0xff, 0x00, 0x28, 0x0d, 0x18]);
        assert_eq!(
            l,
            [
                "ATT: Find By Type Value Request (0x06) len 8",
                "  Handle range: 0x0001-0xffff",
                "  Attribute type: Primary Service (0x2800)",
                "  Value: 0d 18",
                "    UUID: Heart Rate (0x180d)",
            ]
        );
        let l = run(&mut st, false, &[0x07, 0x1a, 0x00, 0x21, 0x00]);
        assert_eq!(l, ["ATT: Find By Type Value Response (0x07) len 4", "  Handle range: 0x001a-0x0021"]);
        assert_eq!(st.conn(0x40).unwrap().att.attr_types[&0x001a], Uuid::U16(0x2800));
    }

    #[test]
    fn prepare_and_execute_write() {
        let mut st = IndexState::default();
        let l = run(&mut st, true, &[0x16, 0x10, 0x00, 0x12, 0x00, 0xaa, 0xbb]);
        assert_eq!(l[1..], ["  Handle: 0x0010", "  Offset: 18 (0x0012)", "  Data: aa bb"]);
        let l = run(&mut st, false, &[0x17, 0x10, 0x00, 0x12, 0x00, 0xaa, 0xbb]);
        assert_eq!(l[0], "ATT: Prepare Write Response (0x17) len 6");
        let l = run(&mut st, true, &[0x18, 0x01]);
        assert_eq!(l, ["ATT: Execute Write Request (0x18) len 1", "  Flags: Immediately write all pending values (0x01)"]);
        assert_eq!(run(&mut st, false, &[0x19]), ["ATT: Execute Write Response (0x19) len 0"]);
        assert!(st.conn(0x40).unwrap().att.pending.is_empty());
    }

    #[test]
    fn multiple_handle_value_notification() {
        let mut st = IndexState::default();
        st.conn_or_insert(0x40, LinkType::Le).att.attr_types.insert(0x0010, Uuid::U16(0x2a19));
        let l = run(&mut st, true, &[0x23, 0x10, 0x00, 0x01, 0x00, 0x64, 0x11, 0x00, 0x02, 0x00, 0x01, 0x02]);
        assert_eq!(
            l,
            [
                "ATT: Multiple Handle Value Notification (0x23) len 11",
                "  Handle: 0x0010 Type: Battery Level (0x2a19)",
                "  Length: 1",
                "  Data: 64",
                "    Battery Level: 100%",
                "  Handle: 0x0011",
                "  Length: 2",
                "  Data: 01 02",
            ]
        );
    }

    #[test]
    fn read_multiple_variable() {
        let mut st = IndexState::default();
        st.conn_or_insert(0x40, LinkType::Le).att.attr_types.insert(0x0002, Uuid::U16(0x2a38));
        let l = run(&mut st, true, &[0x20, 0x02, 0x00, 0x03, 0x00]);
        assert_eq!(l[1..], ["  Handle: 0x0002 Type: Body Sensor Location (0x2a38)", "  Handle: 0x0003"]);
        let l = run(&mut st, false, &[0x21, 0x01, 0x00, 0x01, 0x00, 0x00]);
        assert_eq!(
            l,
            [
                "ATT: Read Multiple Variable Response (0x21) len 5",
                "  Handle: 0x0002 Type: Body Sensor Location (0x2a38)",
                "  Length: 1",
                "  Value: 01",
                "    Body Sensor Location: Chest (0x01)",
                "  Handle: 0x0003",
                "  Length: 0",
                "  Value: (empty)",
            ]
        );
    }

    #[test]
    fn signed_write_command() {
        let mut st = IndexState::default();
        let mut pdu = vec![0xd2, 0x20, 0x00, 0x01];
        pdu.extend_from_slice(&[0x11; 12]);
        let l = run(&mut st, true, &pdu);
        assert_eq!(
            l,
            [
                "ATT: Signed Write Command (0xd2) len 15",
                "  Handle: 0x0020",
                "  Data: 01",
                "  Signature: 111111111111111111111111",
            ]
        );
        assert!(st.conn(0x40).unwrap().att.pending.is_empty());
    }

    #[test]
    fn value_decoders() {
        let mut st = IndexState::default();
        let att = &mut st.conn_or_insert(0x40, LinkType::Le).att;
        att.attr_types.insert(0x0001, Uuid::U16(0x2a01));
        att.attr_types.insert(0x0002, Uuid::U16(0x2a04));
        att.attr_types.insert(0x0003, Uuid::U16(0x2904));
        att.attr_types.insert(0x0004, Uuid::U16(0x2b29));
        att.attr_types.insert(0x0005, Uuid::U16(0x2a37));
        let l = run(&mut st, false, &[0x1b, 0x01, 0x00, 0x41, 0x03]);
        assert_eq!(l[3], "    Appearance: Heart Rate Sensor: Heart Rate Belt (0x0341)");
        let l = run(&mut st, false, &[0x1b, 0x02, 0x00, 0x06, 0x00, 0xff, 0xff, 0x00, 0x00, 0x90, 0x01]);
        assert_eq!(
            l[3..],
            [
                "    Minimum Connection Interval: 7.500 msec (0x0006)",
                "    Maximum Connection Interval: No specific value (0xffff)",
                "    Peripheral Latency: 0",
                "    Connection Supervision Timeout: 4000 msec (0x0190)",
            ]
        );
        let l = run(&mut st, false, &[0x1b, 0x03, 0x00, 0x04, 0x00, 0xad, 0x27, 0x01, 0x00, 0x00]);
        assert_eq!(
            l[3..],
            [
                "    Format: uint8 (0x04)",
                "    Exponent: 0",
                "    Unit: percentage (0x27ad)",
                "    Name Space: Bluetooth SIG (0x01)",
                "    Description: 0x0000",
            ]
        );
        let l = run(&mut st, true, &[0x52, 0x04, 0x00, 0x03]);
        assert_eq!(l[3..], ["    Robust Caching", "    Enhanced ATT bearer"]);
        // Heart rate with 16-bit value, energy expended and two RR intervals.
        let l = run(&mut st, false, &[0x1b, 0x05, 0x00, 0x19, 0x48, 0x00, 0x10, 0x00, 0x00, 0x04, 0x00, 0x02]);
        assert_eq!(
            l[3..],
            [
                "    Flags: 0x19",
                "      Heart Rate Value Format: UINT16",
                "      Sensor Contact: Not supported",
                "      Energy Expended present",
                "      RR-Interval present",
                "    Heart Rate: 72 bpm",
                "    Energy Expended: 16 kJ",
                "    RR-Interval: 1000.000 msec (0x0400)",
                "    RR-Interval: 500.000 msec (0x0200)",
            ]
        );
        // Too short for the type.
        let l = run(&mut st, false, &[0x1b, 0x02, 0x00, 0x06]);
        assert_eq!(l[3], "    Value too short");
    }

    #[test]
    fn malformed_and_unknown_pdus() {
        let mut st = IndexState::default();
        let l = run(&mut st, true, &[0x0c, 0x03, 0x00, 0x16]);
        assert_eq!(l[0], "ATT: Read Blob Request (0x0c) len 3");
        assert_eq!(l[1], "  Handle: 0x0003");
        assert!(l[2].starts_with("  Malformed PDU: truncated"), "{l:?}");
        assert!(l[3].starts_with("  16"), "{l:?}");
        let l = run(&mut st, true, &[0x08, 0x01, 0x00, 0xff, 0xff, 0x28]);
        assert_eq!(l[1], "  Handle range: 0x0001-0xffff");
        assert_eq!(l[2], "  Attribute type: invalid UUID length 1");
        let l = run(&mut st, true, &[0x42, 0x01]);
        assert_eq!(l[0], "ATT: Unknown (0x42) len 1");
        assert!(l[1].starts_with("  01"));
        // Requests without a response never accumulate beyond the limit.
        for _ in 0..100 {
            run(&mut st, true, &[0x0a, 0x01, 0x00]);
        }
        assert_eq!(st.conn(0x40).unwrap().att.pending.len(), MAX_PENDING);
        let mut out = Out::new();
        decode(&mut st, 0x40, true, &[], &mut out, 1);
        assert_eq!(lines(&out), ["ATT: empty PDU"]);
    }
}
