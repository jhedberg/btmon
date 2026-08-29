//! L2CAP signaling commands (BR/EDR CID 0x0001 and LE CID 0x0005).
//!
//! Besides printing the commands, this module keeps the per-connection
//! channel table current: connection requests are remembered by identifier
//! so that the matching response can register an [`L2capChannel`] under both
//! CIDs, configure requests/responses record the negotiated mode, FCS and
//! window options, and disconnection responses remove the channel again.

use super::{mode_from_option, mode_name, signaling_code_name};
use crate::assigned::psm_name;
use crate::context::{IndexState, L2capChannel, L2capMode, LinkType};
use crate::field;
use crate::hci::common::{bits, enum16, interval, service_type, timeout_ms, u16_field, u32_hex, u8_field};
use crate::reader::{Reader, Result};
use crate::tree::Out;

static REJECT_REASONS: &[(u16, &str)] = &[
    (0x0000, "Command not understood"),
    (0x0001, "Signaling MTU exceeded"),
    (0x0002, "Invalid CID in request"),
];

static CONN_RESULTS: &[(u16, &str)] = &[
    (0x0000, "Connection successful"),
    (0x0001, "Connection pending"),
    (0x0002, "Connection refused - PSM not supported"),
    (0x0003, "Connection refused - security block"),
    (0x0004, "Connection refused - no resources available"),
    (0x0006, "Connection refused - invalid Source CID"),
    (0x0007, "Connection refused - Source CID already allocated"),
];

static CREATE_RESULTS: &[(u16, &str)] = &[
    (0x0000, "Connection successful"),
    (0x0001, "Connection pending"),
    (0x0002, "Connection refused - PSM not supported"),
    (0x0003, "Connection refused - security block"),
    (0x0004, "Connection refused - no resources available"),
    (0x0005, "Connection refused - Controller ID not supported"),
    (0x0006, "Connection refused - invalid Source CID"),
    (0x0007, "Connection refused - Source CID already allocated"),
];

static CONN_STATUS: &[(u16, &str)] = &[
    (0x0000, "No further information available"),
    (0x0001, "Authentication pending"),
    (0x0002, "Authorization pending"),
];

static CONFIG_RESULTS: &[(u16, &str)] = &[
    (0x0000, "Success"),
    (0x0001, "Failure - unacceptable parameters"),
    (0x0002, "Failure - rejected"),
    (0x0003, "Failure - unknown options"),
    (0x0004, "Pending"),
    (0x0005, "Failure - flow spec rejected"),
];

static INFO_TYPES: &[(u16, &str)] = &[
    (0x0001, "Connectionless MTU"),
    (0x0002, "Extended features supported"),
    (0x0003, "Fixed channels supported"),
];

static INFO_RESULTS: &[(u16, &str)] = &[(0x0000, "Success"), (0x0001, "Not supported")];

/// Extended feature mask (Vol 3, Part A, Table 4.12).
static FEATURES: &[(u8, &str)] = &[
    (0, "Flow control mode"),
    (1, "Retransmission mode"),
    (2, "Bi-directional QoS"),
    (3, "Enhanced Retransmission Mode"),
    (4, "Streaming Mode"),
    (5, "FCS Option"),
    (6, "Extended Flow Specification for BR/EDR"),
    (7, "Fixed Channels"),
    (8, "Extended Window Size"),
    (9, "Unicast Connectionless Data Reception"),
    (10, "Enhanced Credit Based Flow Control Mode"),
    (31, "Reserved for feature mask extension"),
];

/// Fixed channels supported mask (Vol 3, Part A, Table 4.13).
static FIXED_CHANNELS: &[(u8, &str)] = &[
    (0, "Null identifier"),
    (1, "L2CAP Signaling (BR/EDR)"),
    (2, "Connectionless reception"),
    (3, "AMP Manager Protocol"),
    (4, "Attribute Protocol"),
    (5, "L2CAP Signaling (LE)"),
    (6, "Security Manager (LE)"),
    (7, "Security Manager (BR/EDR)"),
    (63, "AMP Test Manager"),
];

static MOVE_RESULTS: &[(u16, &str)] = &[
    (0x0000, "Move success"),
    (0x0001, "Move pending"),
    (0x0002, "Move refused - Controller ID not supported"),
    (0x0003, "Move refused - new Controller ID is same"),
    (0x0004, "Move refused - Configuration not supported"),
    (0x0005, "Move refused - Move Channel collision"),
    (0x0006, "Move refused - Channel not allowed to be moved"),
];

static MOVE_CFM_RESULTS: &[(u16, &str)] =
    &[(0x0000, "Move success - both sides succeed"), (0x0001, "Move failure - one or both sides refuse")];

static CONN_PARAM_RESULTS: &[(u16, &str)] =
    &[(0x0000, "Connection Parameters accepted"), (0x0001, "Connection Parameters rejected")];

static LE_CONN_RESULTS: &[(u16, &str)] = &[
    (0x0000, "Connection successful"),
    (0x0002, "Connection refused - LE PSM not supported"),
    (0x0004, "Connection refused - no resources available"),
    (0x0005, "Connection refused - insufficient authentication"),
    (0x0006, "Connection refused - insufficient authorization"),
    (0x0007, "Connection refused - encryption key size too short"),
    (0x0008, "Connection refused - insufficient encryption"),
    (0x0009, "Connection refused - invalid Source CID"),
    (0x000a, "Connection refused - Source CID already allocated"),
    (0x000b, "Connection refused - unacceptable parameters"),
];

/// Vol 3, Part A, Table 4.17.
static ECRED_CONN_RESULTS: &[(u16, &str)] = &[
    (0x0000, "All connections successful"),
    (0x0002, "All connections refused - SPSM not supported"),
    (0x0004, "Some connections refused - insufficient resources available"),
    (0x0005, "All connections refused - insufficient authentication"),
    (0x0006, "All connections refused - insufficient authorization"),
    (0x0007, "All connections refused - encryption key size too short"),
    (0x0008, "All connections refused - insufficient encryption"),
    (0x0009, "Some connections refused - invalid Source CID"),
    (0x000a, "Some connections refused - Source CID already allocated"),
    (0x000b, "All connections refused - unacceptable parameters"),
    (0x000c, "All connections refused - invalid parameters"),
];

/// Vol 3, Part A, Table 4.18.
static ECRED_RECONF_RESULTS: &[(u16, &str)] = &[
    (0x0000, "Reconfiguration successful"),
    (0x0001, "Reconfiguration failed - reduction in size of MTU not allowed"),
    (0x0002, "Reconfiguration failed - reduction in size of MPS not allowed for more than one channel at a time"),
    (0x0003, "Reconfiguration failed - one or more Destination CIDs invalid"),
    (0x0004, "Reconfiguration failed - other unacceptable parameters"),
];

/// Decode every signaling command in `payload` (BR/EDR may concatenate several).
pub fn decode(st: &mut IndexState, handle: u16, rx: bool, le: bool, payload: &[u8], out: &mut Out) {
    let label = if le { "LE" } else { "L2CAP" };
    let mut r = Reader::new(payload);
    if r.is_empty() {
        out.error(format!("{label}: empty signaling PDU"));
        return;
    }
    while !r.is_empty() {
        let (Ok(code), Ok(ident), Ok(len)) = (r.u8(), r.u8(), r.u16()) else {
            out.error(format!("{label}: signaling header truncated"));
            out.hex(r.rest());
            return;
        };
        let data = match r.bytes(len as usize) {
            Ok(d) => d,
            Err(_) => {
                out.error(format!(
                    "{label}: signaling command truncated (code 0x{code:02x} len {len}, {} available)",
                    r.remaining()
                ));
                out.hex(r.rest());
                return;
            }
        };
        match signaling_code_name(code) {
            Some(n) => field!(out, "{}: {} (0x{:02x}) ident {} len {}", label, n, code, ident, len),
            None => out.unknown(format!("{label}: Unknown (0x{code:02x}) ident {ident} len {len}")),
        };
        out.nest(|o| {
            let mut p = Reader::new(data);
            match command(st, handle, rx, le, ident, code, &mut p, o) {
                Ok(true) => {
                    if !p.is_empty() {
                        o.error("Unexpected trailing data");
                        o.hex(p.rest());
                    }
                }
                Ok(false) => {
                    o.hex(data);
                }
                Err(e) => {
                    o.error(format!("Parameters {e}"));
                    o.hex(p.rest());
                }
            }
        });
    }
}

#[allow(clippy::too_many_arguments)]
fn command(st: &mut IndexState, handle: u16, rx: bool, le: bool, ident: u8, code: u8, r: &mut Reader<'_>, out: &mut Out) -> Result<bool> {
    match code {
        0x01 => command_reject(r, out)?,
        0x02 => connection_request(st, handle, ident, r, out)?,
        0x03 => connection_response(st, handle, rx, ident, r, out)?,
        0x04 => configure_request(st, handle, rx, r, out)?,
        0x05 => configure_response(st, handle, rx, r, out)?,
        0x06 => disconnection_request(r, out)?,
        0x07 => disconnection_response(st, handle, r, out)?,
        0x08 | 0x09 => {
            let data = r.rest();
            if !data.is_empty() {
                out.hex(data);
            }
        }
        0x0a => information_request(r, out)?,
        0x0b => information_response(r, out)?,
        0x0c => create_channel_request(st, handle, ident, r, out)?,
        0x0d => create_channel_response(st, handle, rx, ident, r, out)?,
        0x0e => move_channel_request(r, out)?,
        0x0f => move_channel_response(r, out)?,
        0x10 => move_channel_confirmation(r, out)?,
        0x11 => move_channel_confirmation_response(r, out)?,
        0x12 => connection_parameter_update_request(r, out)?,
        0x13 => connection_parameter_update_response(r, out)?,
        0x14 => le_credit_based_connection_request(st, handle, ident, r, out)?,
        0x15 => le_credit_based_connection_response(st, handle, rx, le, ident, r, out)?,
        0x16 => flow_control_credit(r, out)?,
        0x17 => credit_based_connection_request(st, handle, ident, r, out)?,
        0x18 => credit_based_connection_response(st, handle, rx, le, ident, r, out)?,
        0x19 => credit_based_reconfigure_request(r, out)?,
        0x1a => credit_based_reconfigure_response(r, out)?,
        _ => return Ok(false),
    }
    Ok(true)
}

// ---- field helpers ---------------------------------------------------------

fn psm(r: &mut Reader<'_>, out: &mut Out) -> Result<u16> {
    let v = r.u16()?;
    match psm_name(v) {
        Some(n) => field!(out, "PSM: {} (0x{:04x})", n, v),
        None => field!(out, "PSM: {} (0x{:04x})", v, v),
    };
    Ok(v)
}

fn cid(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<u16> {
    let v = r.u16()?;
    field!(out, "{} CID: {}", label, v);
    Ok(v)
}

// ---- channel bookkeeping ---------------------------------------------------

fn remember_request(st: &mut IndexState, handle: u16, ident: u8, psm: u16, scid: u16) {
    st.conn_or_insert(handle, LinkType::Unknown).l2cap.pending.insert(ident, (psm, scid));
}

fn take_request(st: &mut IndexState, handle: u16, ident: u8) -> Option<(u16, u16)> {
    st.conn_mut(handle)?.l2cap.pending.remove(&ident)
}

/// Register a channel under both of its CIDs.  `rx` is the direction of the
/// response that completed the connection: the source CID belongs to the
/// requester, so it is the local CID when the response was received.
#[allow(clippy::too_many_arguments)]
fn register(st: &mut IndexState, handle: u16, rx: bool, psm: u16, scid: u16, dcid: u16, mode: L2capMode, le: bool, mtu: u16) {
    let (local_cid, remote_cid) = if rx { (scid, dcid) } else { (dcid, scid) };
    let ch = L2capChannel { local_cid, remote_cid, psm, mode, mtu, le, ..Default::default() };
    let conn = st.conn_or_insert(handle, LinkType::Unknown);
    for k in [local_cid, remote_cid] {
        if k != 0 {
            conn.l2cap.channels.insert(k, ch.clone());
        }
    }
}

/// Apply `f` to both entries of the channel known by `cid`.
fn update(st: &mut IndexState, handle: u16, cid: u16, mut f: impl FnMut(&mut L2capChannel)) {
    let Some(conn) = st.conn_mut(handle) else { return };
    let Some(ch) = conn.l2cap.channels.get(&cid) else { return };
    let keys = [ch.local_cid, ch.remote_cid];
    for k in keys {
        if let Some(c) = conn.l2cap.channels.get_mut(&k) {
            f(c);
        }
    }
}

fn remove(st: &mut IndexState, handle: u16, cid: u16) {
    let Some(conn) = st.conn_mut(handle) else { return };
    let Some(ch) = conn.l2cap.channels.get(&cid) else { return };
    let keys = [ch.local_cid, ch.remote_cid];
    for k in keys {
        conn.l2cap.channels.remove(&k);
    }
}

/// Complete a (Create Channel / Connection) request according to the response result.
#[allow(clippy::too_many_arguments)]
fn finish_connection(st: &mut IndexState, handle: u16, rx: bool, ident: u8, result: u16, scid: u16, dcid: u16, mode: L2capMode, le: bool, mtu: u16) {
    match result {
        0x0000 => {
            let (psm, req_scid) = take_request(st, handle, ident).unwrap_or((0, 0));
            let scid = if scid != 0 { scid } else { req_scid };
            register(st, handle, rx, psm, scid, dcid, mode, le, mtu);
        }
        // Pending: the final response will carry the same identifier.
        0x0001 if mode == L2capMode::Basic => {}
        _ => {
            take_request(st, handle, ident);
        }
    }
}

// ---- commands --------------------------------------------------------------

fn command_reject(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let reason = enum16("Reason", r, out, REJECT_REASONS)?;
    match reason {
        0x0001 => {
            u16_field("MTU", r, out)?;
        }
        0x0002 => {
            cid("Local", r, out)?;
            cid("Remote", r, out)?;
        }
        _ => {}
    }
    Ok(())
}

fn connection_request(st: &mut IndexState, handle: u16, ident: u8, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let p = psm(r, out)?;
    let scid = cid("Source", r, out)?;
    remember_request(st, handle, ident, p, scid);
    Ok(())
}

fn connection_response(st: &mut IndexState, handle: u16, rx: bool, ident: u8, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let dcid = cid("Destination", r, out)?;
    let scid = cid("Source", r, out)?;
    let result = enum16("Result", r, out, CONN_RESULTS)?;
    enum16("Status", r, out, CONN_STATUS)?;
    finish_connection(st, handle, rx, ident, result, scid, dcid, L2capMode::Basic, false, 0);
    Ok(())
}

fn config_flags(r: &mut Reader<'_>, out: &mut Out) -> Result<u16> {
    let f = r.u16()?;
    if f & 0x0001 != 0 {
        field!(out, "Flags: 0x{:04x} (continuation)", f);
    } else {
        field!(out, "Flags: 0x{:04x}", f);
    }
    Ok(f)
}

fn configure_request(st: &mut IndexState, handle: u16, rx: bool, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let dcid = cid("Destination", r, out)?;
    config_flags(r, out)?;
    config_options(st, handle, rx, dcid, false, r, out)
}

fn configure_response(st: &mut IndexState, handle: u16, rx: bool, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let scid = cid("Source", r, out)?;
    config_flags(r, out)?;
    let result = enum16("Result", r, out, CONFIG_RESULTS)?;
    if result == 0x0003 {
        // Unknown options are reported as a list of option types.
        while !r.is_empty() {
            let t = r.u8()? & 0x7f;
            match option_name(t) {
                Some(n) => field!(out, "Option: {} (0x{:02x})", n, t),
                None => out.unknown(format!("Option: Unknown (0x{t:02x})")),
            };
        }
        return Ok(());
    }
    config_options(st, handle, rx, scid, true, r, out)
}

fn option_name(t: u8) -> Option<&'static str> {
    Some(match t {
        0x01 => "Maximum Transmission Unit",
        0x02 => "Flush Timeout",
        0x03 => "Quality of Service",
        0x04 => "Retransmission and Flow Control",
        0x05 => "Frame Check Sequence",
        0x06 => "Extended Flow Specification",
        0x07 => "Extended Window Size",
        _ => return None,
    })
}

/// Configuration options (Vol 3, Part A, Section 5): type/length/value.
#[allow(clippy::too_many_arguments)]
fn config_options(st: &mut IndexState, handle: u16, rx: bool, cid: u16, response: bool, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    while !r.is_empty() {
        let t = r.u8()?;
        let len = r.u8()? as usize;
        let typ = t & 0x7f;
        let kind = if t & 0x80 != 0 { "hint" } else { "mandatory" };
        match option_name(typ) {
            Some(n) => field!(out, "Option: {} (0x{:02x}) [{}]", n, typ, kind),
            None => out.unknown(format!("Option: Unknown (0x{typ:02x}) [{kind}]")),
        };
        let mut o = r.sub(len)?;
        let res = out.nest(|n| option_value(st, handle, rx, cid, response, typ, &mut o, n));
        out.nest(|n| match res {
            Err(e) => {
                n.error(format!("Option {e}"));
                n.hex(o.rest());
            }
            Ok(()) if !o.is_empty() => {
                n.error("Unexpected option data");
                n.hex(o.rest());
            }
            Ok(()) => {}
        });
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn option_value(st: &mut IndexState, handle: u16, rx: bool, cid: u16, response: bool, typ: u8, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    match typ {
        0x01 => {
            let mtu = u16_field("MTU", r, out)?;
            update(st, handle, cid, |c| c.mtu = mtu);
        }
        0x02 => {
            u16_field("Flush timeout", r, out)?;
        }
        0x03 => {
            let flags = r.u8()?;
            field!(out, "Flags: 0x{:02x}", flags);
            service_type(r, out)?;
            u32_hex("Token rate", r, out)?;
            u32_hex("Token bucket size", r, out)?;
            u32_hex("Peak bandwidth", r, out)?;
            u32_hex("Latency", r, out)?;
            u32_hex("Delay variation", r, out)?;
        }
        0x04 => {
            let m = r.u8()?;
            match mode_from_option(m) {
                Some(mode) => {
                    field!(out, "Mode: {} (0x{:02x})", mode_name(mode), m);
                    update(st, handle, cid, |c| c.mode = mode);
                }
                None => {
                    out.unknown(format!("Mode: Reserved (0x{m:02x})"));
                }
            }
            u8_field("TX window size", r, out)?;
            u8_field("Max transmit", r, out)?;
            u16_field("Retransmission timeout", r, out)?;
            u16_field("Monitor timeout", r, out)?;
            u16_field("Maximum PDU size", r, out)?;
        }
        0x05 => {
            let f = r.u8()?;
            match f {
                0x00 => field!(out, "FCS: No FCS (0x00)"),
                0x01 => field!(out, "FCS: 16-bit FCS (0x01)"),
                _ => out.unknown(format!("FCS: Reserved (0x{f:02x})")),
            };
            if f == 0x00 && !response {
                update(st, handle, cid, |c| c.no_fcs[rx as usize] = true);
            }
        }
        0x06 => {
            let id = r.u8()?;
            field!(out, "Identifier: 0x{:02x}", id);
            service_type(r, out)?;
            let sdu = r.u16()?;
            field!(out, "Maximum SDU size: 0x{:04x}", sdu);
            u32_hex("SDU inter-arrival time", r, out)?;
            u32_hex("Access latency", r, out)?;
            u32_hex("Flush timeout", r, out)?;
        }
        0x07 => {
            u16_field("Extended window size", r, out)?;
            update(st, handle, cid, |c| c.ext_ctrl = true);
        }
        _ => {
            let d = r.rest();
            if !d.is_empty() {
                out.hex(d);
            }
        }
    }
    Ok(())
}

fn disconnection_request(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    cid("Destination", r, out)?;
    cid("Source", r, out)?;
    Ok(())
}

fn disconnection_response(st: &mut IndexState, handle: u16, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let dcid = cid("Destination", r, out)?;
    let scid = cid("Source", r, out)?;
    remove(st, handle, dcid);
    remove(st, handle, scid);
    Ok(())
}

fn information_request(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    enum16("Type", r, out, INFO_TYPES)?;
    Ok(())
}

fn information_response(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let t = enum16("Type", r, out, INFO_TYPES)?;
    let result = enum16("Result", r, out, INFO_RESULTS)?;
    if result != 0x0000 {
        return Ok(());
    }
    match t {
        0x0001 => {
            u16_field("MTU", r, out)?;
        }
        0x0002 => {
            let f = r.u32()?;
            field!(out, "Features: 0x{:08x}", f);
            out.nest(|o| bits(o, f as u64, FEATURES, 32));
        }
        0x0003 => {
            let c = r.u64()?;
            field!(out, "Channels: 0x{:016x}", c);
            out.nest(|o| bits(o, c, FIXED_CHANNELS, 64));
        }
        _ => {
            out.hex(r.rest());
        }
    }
    Ok(())
}

fn create_channel_request(st: &mut IndexState, handle: u16, ident: u8, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let p = psm(r, out)?;
    let scid = cid("Source", r, out)?;
    u8_field("Controller ID", r, out)?;
    remember_request(st, handle, ident, p, scid);
    Ok(())
}

fn create_channel_response(st: &mut IndexState, handle: u16, rx: bool, ident: u8, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let dcid = cid("Destination", r, out)?;
    let scid = cid("Source", r, out)?;
    let result = enum16("Result", r, out, CREATE_RESULTS)?;
    enum16("Status", r, out, CONN_STATUS)?;
    finish_connection(st, handle, rx, ident, result, scid, dcid, L2capMode::Basic, false, 0);
    Ok(())
}

fn move_channel_request(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    cid("Initiator", r, out)?;
    u8_field("Controller ID", r, out)?;
    Ok(())
}

fn move_channel_response(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    cid("Initiator", r, out)?;
    enum16("Result", r, out, MOVE_RESULTS)?;
    Ok(())
}

fn move_channel_confirmation(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    cid("Initiator", r, out)?;
    enum16("Result", r, out, MOVE_CFM_RESULTS)?;
    Ok(())
}

fn move_channel_confirmation_response(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    cid("Initiator", r, out)?;
    Ok(())
}

fn connection_parameter_update_request(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    interval("Min interval", r, out, 1250)?;
    interval("Max interval", r, out, 1250)?;
    let latency = r.u16()?;
    field!(out, "Peripheral latency: {} (0x{:04x})", latency, latency);
    timeout_ms("Supervision timeout", r, out, 10)?;
    Ok(())
}

fn connection_parameter_update_response(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    enum16("Result", r, out, CONN_PARAM_RESULTS)?;
    Ok(())
}

fn le_credit_based_connection_request(st: &mut IndexState, handle: u16, ident: u8, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let p = psm(r, out)?;
    let scid = cid("Source", r, out)?;
    u16_field("MTU", r, out)?;
    u16_field("MPS", r, out)?;
    u16_field("Credits", r, out)?;
    remember_request(st, handle, ident, p, scid);
    Ok(())
}

fn le_credit_based_connection_response(st: &mut IndexState, handle: u16, rx: bool, le: bool, ident: u8, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let dcid = cid("Destination", r, out)?;
    let mtu = u16_field("MTU", r, out)?;
    u16_field("MPS", r, out)?;
    u16_field("Credits", r, out)?;
    let result = enum16("Result", r, out, LE_CONN_RESULTS)?;
    finish_connection(st, handle, rx, ident, result, 0, dcid, L2capMode::LeCreditBased, le, mtu);
    Ok(())
}

fn flow_control_credit(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    cid("Source", r, out)?;
    u16_field("Credits", r, out)?;
    Ok(())
}

fn credit_based_connection_request(st: &mut IndexState, handle: u16, ident: u8, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let p = psm(r, out)?;
    u16_field("MTU", r, out)?;
    u16_field("MPS", r, out)?;
    u16_field("Credits", r, out)?;
    let mut scids = Vec::new();
    while !r.is_empty() {
        scids.push(cid("Source", r, out)?);
    }
    st.conn_or_insert(handle, LinkType::Unknown).l2cap.pending_ecred.insert(ident, (p, scids));
    Ok(())
}

fn credit_based_connection_response(st: &mut IndexState, handle: u16, rx: bool, le: bool, ident: u8, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let mtu = u16_field("MTU", r, out)?;
    u16_field("MPS", r, out)?;
    u16_field("Credits", r, out)?;
    enum16("Result", r, out, ECRED_CONN_RESULTS)?;
    let mut dcids = Vec::new();
    while !r.is_empty() {
        dcids.push(cid("Destination", r, out)?);
    }
    let pending = st.conn_mut(handle).and_then(|c| c.l2cap.pending_ecred.remove(&ident));
    if let Some((psm, scids)) = pending {
        // A destination CID of 0 means that channel was refused.
        for (scid, dcid) in scids.iter().zip(dcids.iter()) {
            if *dcid != 0 {
                register(st, handle, rx, psm, *scid, *dcid, L2capMode::EnhancedCreditBased, le, mtu);
            }
        }
    }
    Ok(())
}

fn credit_based_reconfigure_request(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    u16_field("MTU", r, out)?;
    u16_field("MPS", r, out)?;
    while !r.is_empty() {
        cid("Destination", r, out)?;
    }
    Ok(())
}

fn credit_based_reconfigure_response(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    enum16("Result", r, out, ECRED_RECONF_RESULTS)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l2cap::test_lines;

    const HANDLE: u16 = 0x0040;

    fn run(st: &mut IndexState, rx: bool, le: bool, payload: &[u8]) -> Vec<String> {
        let mut out = Out::new();
        decode(st, HANDLE, rx, le, payload, &mut out);
        test_lines(&out)
    }

    #[test]
    fn empty_pdu() {
        let mut st = IndexState::default();
        assert_eq!(run(&mut st, true, true, &[]), ["LE: empty signaling PDU"]);
    }

    #[test]
    fn unknown_code_is_dumped() {
        let mut st = IndexState::default();
        let l = run(&mut st, true, false, &[0x30, 0x01, 0x01, 0x00, 0xaa]);
        assert_eq!(l[0], "L2CAP: Unknown (0x30) ident 1 len 1");
        assert!(l[1].starts_with("  aa"));
    }

    #[test]
    fn connection_refused_drops_pending_request() {
        let mut st = IndexState::default();
        run(&mut st, false, false, &[0x02, 0x07, 0x04, 0x00, 0x01, 0x00, 0x40, 0x00]);
        let l = run(&mut st, true, false, &[0x03, 0x07, 0x08, 0x00, 0x00, 0x00, 0x40, 0x00, 0x02, 0x00, 0x00, 0x00]);
        assert_eq!(l[3], "  Result: Connection refused - PSM not supported (0x0002)");
        let conn = st.conn(HANDLE).unwrap();
        assert!(conn.l2cap.pending.is_empty());
        assert!(conn.l2cap.channels.is_empty());
    }

    #[test]
    fn connection_pending_keeps_request_until_final_response() {
        let mut st = IndexState::default();
        run(&mut st, false, false, &[0x02, 0x07, 0x04, 0x00, 0x01, 0x00, 0x40, 0x00]);
        let l = run(&mut st, true, false, &[0x03, 0x07, 0x08, 0x00, 0x41, 0x00, 0x40, 0x00, 0x01, 0x00, 0x01, 0x00]);
        assert_eq!(l[3], "  Result: Connection pending (0x0001)");
        assert_eq!(l[4], "  Status: Authentication pending (0x0001)");
        assert!(st.conn(HANDLE).unwrap().l2cap.channels.is_empty());
        run(&mut st, true, false, &[0x03, 0x07, 0x08, 0x00, 0x41, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(st.conn(HANDLE).unwrap().l2cap.channel(0x41).unwrap().psm, 1);
    }

    #[test]
    fn configure_options() {
        let mut st = IndexState::default();
        let l = run(
            &mut st,
            false,
            false,
            &[
                0x04, 0x01, 0x2e, 0x00, 0x41, 0x00, 0x01, 0x00, // dcid, flags (continuation)
                0x02, 0x02, 0xff, 0xff, // flush timeout
                0x03, 0x16, 0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // QoS
                0x05, 0x01, 0x00, // FCS
                0x07, 0x02, 0x00, 0x10, // extended window size
                0x85, 0x02, 0x00, 0x00, // FCS with hint bit
                0x09, 0x01, 0x42, // unknown option
            ],
        );
        assert_eq!(
            l[..20],
            [
                "L2CAP: Configure Request (0x04) ident 1 len 46",
                "  Destination CID: 65",
                "  Flags: 0x0001 (continuation)",
                "  Option: Flush Timeout (0x02) [mandatory]",
                "    Flush timeout: 65535",
                "  Option: Quality of Service (0x03) [mandatory]",
                "    Flags: 0x00",
                "    Service type: Best Effort (0x01)",
                "    Token rate: 0x00000000",
                "    Token bucket size: 0x00000000",
                "    Peak bandwidth: 0xffffffff",
                "    Latency: 0xffffffff",
                "    Delay variation: 0xffffffff",
                "  Option: Frame Check Sequence (0x05) [mandatory]",
                "    FCS: No FCS (0x00)",
                "  Option: Extended Window Size (0x07) [mandatory]",
                "    Extended window size: 4096",
                "  Option: Frame Check Sequence (0x05) [hint]",
                "    FCS: No FCS (0x00)",
                "    Unexpected option data",
            ]
        );
        assert!(l[20].starts_with("    00 "), "{}", l[20]);
        assert_eq!(l[21], "  Option: Unknown (0x09) [mandatory]");
        assert!(l[22].starts_with("    42 "), "{}", l[22]);
        assert_eq!(l.len(), 23);
    }

    #[test]
    fn configure_response_with_unknown_options() {
        let mut st = IndexState::default();
        let l = run(&mut st, true, false, &[0x05, 0x01, 0x08, 0x00, 0x40, 0x00, 0x00, 0x00, 0x03, 0x00, 0x09, 0x0a]);
        assert_eq!(l[3], "  Result: Failure - unknown options (0x0003)");
        assert_eq!(l[4], "  Option: Unknown (0x09)");
        assert_eq!(l[5], "  Option: Unknown (0x0a)");
    }

    #[test]
    fn amp_channel_commands() {
        let mut st = IndexState::default();
        let l = run(&mut st, false, false, &[0x0c, 0x01, 0x05, 0x00, 0x01, 0x00, 0x40, 0x00, 0x01]);
        assert_eq!(l[1..], ["  PSM: SDP (0x0001)", "  Source CID: 64", "  Controller ID: 1"]);
        let l = run(&mut st, true, false, &[0x0d, 0x01, 0x08, 0x00, 0x41, 0x00, 0x40, 0x00, 0x05, 0x00, 0x00, 0x00]);
        assert_eq!(l[3], "  Result: Connection refused - Controller ID not supported (0x0005)");
        let l = run(&mut st, false, false, &[0x0e, 0x02, 0x03, 0x00, 0x40, 0x00, 0x01]);
        assert_eq!(l[1..], ["  Initiator CID: 64", "  Controller ID: 1"]);
        let l = run(&mut st, true, false, &[0x0f, 0x02, 0x04, 0x00, 0x40, 0x00, 0x01, 0x00]);
        assert_eq!(l[2], "  Result: Move pending (0x0001)");
        let l = run(&mut st, false, false, &[0x10, 0x03, 0x04, 0x00, 0x40, 0x00, 0x00, 0x00]);
        assert_eq!(l[2], "  Result: Move success - both sides succeed (0x0000)");
        let l = run(&mut st, true, false, &[0x11, 0x03, 0x02, 0x00, 0x40, 0x00]);
        assert_eq!(l, ["L2CAP: Move Channel Confirmation Response (0x11) ident 3 len 2", "  Initiator CID: 64"]);
    }

    #[test]
    fn credit_based_reconfigure() {
        let mut st = IndexState::default();
        let l = run(&mut st, false, true, &[0x19, 0x01, 0x08, 0x00, 0x00, 0x01, 0x40, 0x00, 0x40, 0x00, 0x41, 0x00]);
        assert_eq!(l[1..], ["  MTU: 256", "  MPS: 64", "  Destination CID: 64", "  Destination CID: 65"]);
        let l = run(&mut st, true, true, &[0x1a, 0x01, 0x02, 0x00, 0x01, 0x00]);
        assert_eq!(l[1], "  Result: Reconfiguration failed - reduction in size of MTU not allowed (0x0001)");
    }

    #[test]
    fn le_connection_response_without_request_still_registers_destination() {
        let mut st = IndexState::default();
        run(&mut st, true, true, &[0x15, 0x09, 0x0a, 0x00, 0x41, 0x00, 0x64, 0x00, 0x17, 0x00, 0x05, 0x00, 0x00, 0x00]);
        let conn = st.conn(HANDLE).unwrap();
        assert_eq!(conn.l2cap.channels.len(), 1);
        assert_eq!(conn.l2cap.channel(0x41).unwrap().mode, L2capMode::LeCreditBased);
    }
}
