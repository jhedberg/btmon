//! HCI event parameter decoders.
//!
//! [`event_params`] returns `Ok(false)` when no decoder exists for the event
//! code so that the caller can hex dump the parameters.  LE Meta subevents
//! are dispatched to [`le_event`]; everything else is decoded here.

use super::command::{command_params, return_params};
use super::common::*;
use super::{evt, le_event, opcode_text, opcode_text_for, vendor};
use crate::context::{IndexState, LinkType};
use crate::field;
use crate::reader::{Reader, Result};
use crate::tree::Out;

/// Decode the parameters of the event with the given code.
pub fn event_params(st: &mut IndexState, code: u8, r: &mut Reader<'_>, out: &mut Out) -> Result<bool> {
    match code {
        evt::INQUIRY_COMPLETE => {
            status(r, out)?;
        }
        evt::INQUIRY_RESULT => inquiry_result(r, out, false)?,
        evt::CONNECTION_COMPLETE => connection_complete(st, r, out)?,
        evt::CONNECTION_REQUEST => connection_request(r, out)?,
        evt::DISCONNECTION_COMPLETE => disconnection_complete(st, r, out)?,
        evt::AUTHENTICATION_COMPLETE
        | evt::CHANGE_CONNECTION_LINK_KEY_COMPLETE
        | evt::ENCRYPTION_KEY_REFRESH_COMPLETE => status_handle(st, r, out)?,
        evt::REMOTE_NAME_REQUEST_COMPLETE => remote_name_request_complete(r, out)?,
        evt::ENCRYPTION_CHANGE => encryption_change(st, r, out, false)?,
        evt::ENCRYPTION_CHANGE_V2 => encryption_change(st, r, out, true)?,
        evt::LINK_KEY_TYPE_CHANGED => link_key_type_changed(st, r, out)?,
        evt::READ_REMOTE_SUPPORTED_FEATURES_COMPLETE => read_remote_supported_features_complete(st, r, out)?,
        evt::READ_REMOTE_VERSION_INFORMATION_COMPLETE => read_remote_version_information_complete(st, r, out)?,
        evt::QOS_SETUP_COMPLETE => qos_setup_complete(st, r, out)?,
        evt::COMMAND_COMPLETE => command_complete(st, r, out)?,
        evt::COMMAND_STATUS => command_status(st, r, out)?,
        evt::HARDWARE_ERROR => hardware_error(r, out)?,
        evt::FLUSH_OCCURRED | evt::QOS_VIOLATION | evt::ENHANCED_FLUSH_COMPLETE | evt::AUTHENTICATED_PAYLOAD_TIMEOUT_EXPIRED => {
            handle(st, r, out)?;
        }
        evt::ROLE_CHANGE => role_change(st, r, out)?,
        evt::NUMBER_OF_COMPLETED_PACKETS => number_of_completed_packets(st, r, out)?,
        evt::MODE_CHANGE => mode_change(st, r, out)?,
        evt::RETURN_LINK_KEYS => return_link_keys(r, out)?,
        evt::PIN_CODE_REQUEST
        | evt::LINK_KEY_REQUEST
        | evt::IO_CAPABILITY_REQUEST
        | evt::USER_PASSKEY_REQUEST
        | evt::REMOTE_OOB_DATA_REQUEST => {
            bdaddr("Address", r, out)?;
        }
        evt::LINK_KEY_NOTIFICATION => link_key_notification(r, out)?,
        evt::LOOPBACK_COMMAND => loopback_command(st, r, out)?,
        evt::DATA_BUFFER_OVERFLOW => {
            link_type(r, out)?;
        }
        evt::MAX_SLOTS_CHANGE => max_slots_change(st, r, out)?,
        evt::READ_CLOCK_OFFSET_COMPLETE => read_clock_offset_complete(st, r, out)?,
        evt::CONNECTION_PACKET_TYPE_CHANGED => connection_packet_type_changed(st, r, out)?,
        evt::PAGE_SCAN_MODE_CHANGE => page_scan_mode_change(r, out)?,
        evt::PAGE_SCAN_REPETITION_MODE_CHANGE => page_scan_repetition_mode_change(r, out)?,
        evt::FLOW_SPECIFICATION_COMPLETE => flow_specification_complete(st, r, out)?,
        evt::INQUIRY_RESULT_WITH_RSSI => inquiry_result(r, out, true)?,
        evt::READ_REMOTE_EXTENDED_FEATURES_COMPLETE => read_remote_extended_features_complete(st, r, out)?,
        evt::SYNCHRONOUS_CONNECTION_COMPLETE => synchronous_connection_complete(st, r, out)?,
        evt::SYNCHRONOUS_CONNECTION_CHANGED => synchronous_connection_changed(st, r, out)?,
        evt::SNIFF_SUBRATING => sniff_subrating(st, r, out)?,
        evt::EXTENDED_INQUIRY_RESULT => extended_inquiry_result(r, out)?,
        evt::IO_CAPABILITY_RESPONSE => io_capability_response(r, out)?,
        evt::USER_CONFIRMATION_REQUEST | evt::USER_PASSKEY_NOTIFICATION => {
            bdaddr("Address", r, out)?;
            passkey(r, out)?;
        }
        evt::SIMPLE_PAIRING_COMPLETE | evt::TRUNCATED_PAGE_COMPLETE => {
            status(r, out)?;
            bdaddr("Address", r, out)?;
        }
        evt::LINK_SUPERVISION_TIMEOUT_CHANGED => link_supervision_timeout_changed(st, r, out)?,
        evt::KEYPRESS_NOTIFICATION => keypress_notification(r, out)?,
        evt::REMOTE_HOST_SUPPORTED_FEATURES_NOTIFICATION => remote_host_supported_features_notification(r, out)?,
        evt::LE_META => le_meta(st, r, out)?,
        evt::NUMBER_OF_COMPLETED_DATA_BLOCKS => number_of_completed_data_blocks(st, r, out)?,
        evt::TRIGGERED_CLOCK_CAPTURE => triggered_clock_capture(st, r, out)?,
        evt::SYNCHRONIZATION_TRAIN_COMPLETE => {
            status(r, out)?;
        }
        evt::SYNCHRONIZATION_TRAIN_RECEIVED => synchronization_train_received(r, out)?,
        evt::CONNECTIONLESS_PERIPHERAL_BROADCAST_RECEIVE => connectionless_peripheral_broadcast_receive(r, out)?,
        evt::CONNECTIONLESS_PERIPHERAL_BROADCAST_TIMEOUT => {
            bdaddr("Address", r, out)?;
            lt_addr(r, out)?;
        }
        // No parameters.
        evt::PERIPHERAL_PAGE_RESPONSE_TIMEOUT => {}
        evt::CONNECTIONLESS_PERIPHERAL_BROADCAST_CHANNEL_MAP_CHANGE => afh_channel_map(r, out)?,
        evt::INQUIRY_RESPONSE_NOTIFICATION => inquiry_response_notification(r, out)?,
        evt::SAM_STATUS_CHANGE => sam_status_change(st, r, out)?,
        vendor::EVT_VENDOR => return vendor::event_params(st, r, out),
        // Deprecated AMP events (0x40..0x4d except 0x48) and anything unknown
        // are left to the caller to hex dump.
        _ => return Ok(false),
    }
    Ok(true)
}

fn command_complete(st: &mut IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let ncmd = r.u8()?;
    let opcode = r.u16()?;
    st.answer_command(opcode);
    let (text, unknown) = opcode_text_for(st, opcode);
    if unknown {
        out.unknown(format!("{text} ncmd {ncmd}"));
    } else {
        field!(out, "{} ncmd {}", text, ncmd);
    }
    out.nest(|o| {
        let mut params = Reader::new(r.rest());
        let res = return_params(st, opcode, &mut params, o);
        super::finish(res, &mut params, o);
    });
    Ok(())
}

fn command_status(st: &mut IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let s = r.u8()?;
    let ncmd = r.u8()?;
    let opcode = r.u16()?;
    st.answer_command(opcode);
    let (text, unknown) = opcode_text_for(st, opcode);
    if unknown {
        out.unknown(format!("{text} ncmd {ncmd}"));
    } else {
        field!(out, "{} ncmd {}", text, ncmd);
    }
    out.nest(|o| status_value(o, s));
    Ok(())
}

fn le_meta(st: &mut IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let sub = r.u8()?;
    match super::le_event_name(sub) {
        Some(n) => field!(out, "{} (0x{:02x})", n, sub),
        None => out.unknown(format!("Unknown subevent (0x{sub:02x})")),
    };
    out.nest(|o| {
        let mut params = Reader::new(r.rest());
        let res = le_event::le_event_params(st, sub, &mut params, o);
        super::finish(res, &mut params, o);
    });
    Ok(())
}

/// Record a newly established connection in the index state.
pub fn register_connection(st: &mut IndexState, handle: u16, link: LinkType, addr_type: u8, addr: crate::BdAddr, role: u8) {
    let frame = st.frames;
    let c = st.conn_or_insert(handle, link);
    c.addr = addr;
    c.addr_type = addr_type;
    c.role = role;
    c.since_frame = frame;
}

// ---------------------------------------------------------------------------
// Link control events
// ---------------------------------------------------------------------------

/// Inquiry Result (7.7.2) and Inquiry Result with RSSI (7.7.33).
///
/// Responses are printed flat, one block of fields per response, as btmon does.
/// The reserved bytes are printed with their pre-1.2 meaning (page scan period
/// mode / page scan mode) to match btmon.
fn inquiry_result(r: &mut Reader<'_>, out: &mut Out, with_rssi: bool) -> Result<()> {
    let n = u8_field("Num responses", r, out)?;
    for _ in 0..n {
        bdaddr("Address", r, out)?;
        pscan_rep_mode(r, out)?;
        pscan_period_mode(r, out)?;
        if !with_rssi {
            pscan_mode(r, out)?;
        }
        class_of_device(r, out)?;
        clock_offset(r, out)?;
        if with_rssi {
            rssi(r, out)?;
        }
    }
    Ok(())
}

/// Extended Inquiry Result (7.7.38): a single response followed by 240 bytes of EIR.
fn extended_inquiry_result(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    u8_field("Num responses", r, out)?;
    bdaddr("Address", r, out)?;
    pscan_rep_mode(r, out)?;
    pscan_period_mode(r, out)?;
    class_of_device(r, out)?;
    clock_offset(r, out)?;
    rssi(r, out)?;
    crate::ad::decode(r.rest(), out);
    Ok(())
}

fn connection_complete(st: &mut IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let s = status(r, out)?;
    // The connection is not known yet, so print the handle without a peer address.
    let h = read_handle(r)?;
    field!(out, "Handle: {}", h);
    let a = bdaddr("Address", r, out)?;
    let lt = link_type(r, out)?;
    enable("Encryption", r, out)?;
    if s == 0 {
        let link = match lt {
            0x00 => LinkType::Sco,
            0x02 => LinkType::Esco,
            _ => LinkType::Acl,
        };
        register_connection(st, h, link, 0, a, 0);
    }
    Ok(())
}

fn connection_request(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    bdaddr("Address", r, out)?;
    class_of_device(r, out)?;
    link_type(r, out)?;
    Ok(())
}

fn disconnection_complete(st: &mut IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let s = status(r, out)?;
    let h = handle(st, r, out)?;
    reason(r, out)?;
    if s == 0 {
        st.remove_conn(h);
    }
    Ok(())
}

fn remote_name_request_complete(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    status(r, out)?;
    bdaddr("Address", r, out)?;
    name("Name", r, out, 248)?;
    Ok(())
}

/// Encryption Change v1 (0x08) and v2 (0x59, adds the key size).
fn encryption_change(st: &IndexState, r: &mut Reader<'_>, out: &mut Out, v2: bool) -> Result<()> {
    status(r, out)?;
    let h = handle(st, r, out)?;
    encryption_mode(st, h, r, out)?;
    if v2 {
        u8_field("Key size", r, out)?;
    }
    Ok(())
}

fn link_key_type_changed(st: &IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    status(r, out)?;
    handle(st, r, out)?;
    enum8("Key flag", r, out, &[(0x00, "Semi-permanent"), (0x01, "Temporary")])?;
    Ok(())
}

fn read_remote_supported_features_complete(st: &IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    status(r, out)?;
    handle(st, r, out)?;
    lmp_features("Features", r, out, 0)?;
    Ok(())
}

fn read_remote_extended_features_complete(st: &IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    status(r, out)?;
    handle(st, r, out)?;
    let page = r.u8()?;
    let max_page = r.u8()?;
    field!(out, "Page: {}/{}", page, max_page);
    lmp_features("Features", r, out, page)?;
    Ok(())
}

fn read_remote_version_information_complete(st: &IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    status(r, out)?;
    handle(st, r, out)?;
    let ver = r.u8()?;
    let manuf = r.u16()?;
    let subver = r.u16()?;
    match version_str(ver) {
        "Reserved" => out.unknown(format!("LMP version: Reserved (0x{ver:02x}) - Subversion {subver} (0x{subver:04x})")),
        s => field!(out, "LMP version: {} (0x{:02x}) - Subversion {} (0x{:04x})", s, ver, subver, subver),
    };
    manufacturer_value("Manufacturer", out, manuf);
    Ok(())
}

fn qos_setup_complete(st: &IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    status(r, out)?;
    handle(st, r, out)?;
    let flags = r.u8()?;
    field!(out, "Flags: 0x{:02x}", flags);
    service_type(r, out)?;
    u32_field("Token rate", r, out)?;
    u32_field("Peak bandwidth", r, out)?;
    u32_field("Latency", r, out)?;
    u32_field("Delay variation", r, out)?;
    Ok(())
}

fn flow_specification_complete(st: &IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    status(r, out)?;
    handle(st, r, out)?;
    let flags = r.u8()?;
    field!(out, "Flags: 0x{:02x}", flags);
    enum8("Flow direction", r, out, &[(0x00, "Outgoing"), (0x01, "Incoming")])?;
    service_type(r, out)?;
    u32_field("Token rate", r, out)?;
    u32_field("Token bucket size", r, out)?;
    u32_field("Peak bandwidth", r, out)?;
    u32_field("Access latency", r, out)?;
    Ok(())
}

fn hardware_error(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let c = r.u8()?;
    field!(out, "Code: 0x{:02x}", c);
    Ok(())
}

fn role_change(st: &mut IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let s = status(r, out)?;
    let a = bdaddr("Address", r, out)?;
    let new_role = role(r, out)?;
    if s == 0 {
        for c in st.conns.values_mut().filter(|c| c.link == LinkType::Acl && c.addr == a) {
            c.role = new_role;
        }
    }
    Ok(())
}

fn number_of_completed_packets(st: &IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let n = u8_field("Num handles", r, out)?;
    for _ in 0..n {
        handle(st, r, out)?;
        u16_field("Count", r, out)?;
    }
    Ok(())
}

fn number_of_completed_data_blocks(st: &IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    u16_field("Total num data blocks", r, out)?;
    let n = u8_field("Num handles", r, out)?;
    for _ in 0..n {
        handle(st, r, out)?;
        u16_field("Num packets", r, out)?;
        u16_field("Num blocks", r, out)?;
    }
    Ok(())
}

fn mode_change(st: &IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    status(r, out)?;
    handle(st, r, out)?;
    enum8("Mode", r, out, &[(0x00, "Active"), (0x01, "Hold"), (0x02, "Sniff"), (0x03, "Park")])?;
    slots("Interval", r, out)?;
    Ok(())
}

fn return_link_keys(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let n = u8_field("Num keys", r, out)?;
    for _ in 0..n {
        bdaddr("Address", r, out)?;
        key128("Link key", r, out)?;
    }
    Ok(())
}

fn link_key_notification(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    bdaddr("Address", r, out)?;
    key128("Link key", r, out)?;
    enum8("Key type", r, out, KEY_TYPES)?;
    Ok(())
}

/// Loopback Command (7.7.25): the parameters are a complete HCI command packet.
fn loopback_command(st: &mut IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let opcode = r.u16()?;
    let plen = r.u8()?;
    let (text, unknown) = opcode_text(opcode);
    if unknown {
        out.unknown(format!("{text} plen {plen}"));
    } else {
        field!(out, "{} plen {}", text, plen);
    }
    if plen as usize != r.remaining() {
        out.error(format!("Parameter length mismatch: header says {plen}, {} present", r.remaining()));
    }
    out.nest(|o| {
        let mut params = Reader::new(r.rest());
        let res = command_params(st, opcode, &mut params, o);
        super::finish(res, &mut params, o);
    });
    Ok(())
}

fn max_slots_change(st: &IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    handle(st, r, out)?;
    u8_field("Max slots", r, out)?;
    Ok(())
}

fn read_clock_offset_complete(st: &IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    status(r, out)?;
    handle(st, r, out)?;
    clock_offset(r, out)?;
    Ok(())
}

fn connection_packet_type_changed(st: &IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    status(r, out)?;
    handle(st, r, out)?;
    pkt_type_acl(r, out)?;
    Ok(())
}

fn page_scan_mode_change(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    bdaddr("Address", r, out)?;
    pscan_mode(r, out)?;
    Ok(())
}

fn page_scan_repetition_mode_change(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    bdaddr("Address", r, out)?;
    pscan_rep_mode(r, out)?;
    Ok(())
}

fn synchronous_connection_complete(st: &mut IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let s = status(r, out)?;
    let h = read_handle(r)?;
    field!(out, "Handle: {}", h);
    let a = bdaddr("Address", r, out)?;
    let lt = link_type(r, out)?;
    sync_link_params(r, out)?;
    enum8("Air mode", r, out, &[(0x00, "u-law log"), (0x01, "A-law log"), (0x02, "CVSD"), (0x03, "Transparent")])?;
    if s == 0 {
        let link = if lt == 0x00 { LinkType::Sco } else { LinkType::Esco };
        register_connection(st, h, link, 0, a, 0);
    }
    Ok(())
}

fn synchronous_connection_changed(st: &IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    status(r, out)?;
    handle(st, r, out)?;
    sync_link_params(r, out)
}

/// Transmission interval, retransmission window and packet lengths of a synchronous link.
fn sync_link_params(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let tx_interval = r.u8()?;
    field!(out, "Transmission interval: 0x{:02x}", tx_interval);
    let retrans = r.u8()?;
    field!(out, "Retransmission window: 0x{:02x}", retrans);
    u16_field("RX packet length", r, out)?;
    u16_field("TX packet length", r, out)?;
    Ok(())
}

fn sniff_subrating(st: &IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    status(r, out)?;
    handle(st, r, out)?;
    slots("Max transmit latency", r, out)?;
    slots("Max receive latency", r, out)?;
    slots("Min remote timeout", r, out)?;
    slots("Min local timeout", r, out)?;
    Ok(())
}

fn io_capability_response(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    bdaddr("Address", r, out)?;
    io_capability(r, out)?;
    enum8("OOB data", r, out, &[(0x00, "Authentication data not present"), (0x01, "Authentication data present")])?;
    authentication(r, out)?;
    Ok(())
}

fn link_supervision_timeout_changed(st: &IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    handle(st, r, out)?;
    slots("Timeout", r, out)?;
    Ok(())
}

fn keypress_notification(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    bdaddr("Address", r, out)?;
    enum8(
        "Notification type",
        r,
        out,
        &[
            (0x00, "Passkey entry started"),
            (0x01, "Passkey digit entered"),
            (0x02, "Passkey digit erased"),
            (0x03, "Passkey cleared"),
            (0x04, "Passkey entry completed"),
        ],
    )?;
    Ok(())
}

fn remote_host_supported_features_notification(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    bdaddr("Address", r, out)?;
    lmp_features("Features", r, out, 1)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Connectionless peripheral broadcast / synchronization train / misc events
// ---------------------------------------------------------------------------

fn triggered_clock_capture(st: &IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    handle(st, r, out)?;
    enum8("Type", r, out, &[(0x00, "Local clock"), (0x01, "Piconet clock")])?;
    clock("Clock", r, out)?;
    // btmon labels the Slot_Offset parameter "Clock offset".
    clock_offset(r, out)?;
    Ok(())
}

fn synchronization_train_received(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    status(r, out)?;
    bdaddr("Address", r, out)?;
    u32_hex("Offset", r, out)?;
    afh_channel_map(r, out)?;
    lt_addr(r, out)?;
    u32_hex("Next broadcast instant", r, out)?;
    slots("Interval", r, out)?;
    let sd = r.u8()?;
    field!(out, "Service Data: 0x{:02x}", sd);
    Ok(())
}

fn connectionless_peripheral_broadcast_receive(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    bdaddr("Address", r, out)?;
    lt_addr(r, out)?;
    clock("Clock", r, out)?;
    u32_hex("Offset", r, out)?;
    enum8("Receive status", r, out, &[(0x00, "Packet received successfully"), (0x01, "Packet not received successfully")])?;
    enum8(
        "Fragment",
        r,
        out,
        &[(0x00, "Continuation fragment"), (0x01, "Starting fragment"), (0x02, "Ending fragment"), (0x03, "No fragmentation")],
    )?;
    let len = u8_field("Length", r, out)?;
    if len as usize != r.remaining() {
        out.error(format!("invalid data size ({} != {})", r.remaining(), len));
    }
    let data = r.rest();
    if !data.is_empty() {
        out.hex(data);
    }
    Ok(())
}

fn inquiry_response_notification(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let lap = r.array::<3>()?;
    let kind = match (lap[2], lap[1], lap[0]) {
        (0x9e, 0x8b, 0x33) => " (General Inquiry)",
        (0x9e, 0x8b, 0x00) => " (Limited Inquiry)",
        _ => "",
    };
    field!(out, "Access code: 0x{:02x}{:02x}{:02x}{}", lap[2], lap[1], lap[0], kind);
    rssi(r, out)?;
    Ok(())
}

fn sam_status_change(st: &IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    handle(st, r, out)?;
    sam_index("Local SAM index", r, out)?;
    sam_availability("Local SAM TX availability", r, out)?;
    sam_availability("Local SAM RX availability", r, out)?;
    sam_index("Remote SAM index", r, out)?;
    sam_availability("Remote SAM TX availability", r, out)?;
    sam_availability("Remote SAM RX availability", r, out)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Field helpers specific to BR/EDR events
// ---------------------------------------------------------------------------

/// Link key types reported by Link Key Notification.
static KEY_TYPES: &[(u8, &str)] = &[
    (0x00, "Combination key"),
    (0x01, "Local Unit key"),
    (0x02, "Remote Unit key"),
    (0x03, "Debug Combination key"),
    (0x04, "Unauthenticated Combination key from P-192"),
    (0x05, "Authenticated Combination key from P-192"),
    (0x06, "Changed Combination key"),
    (0x07, "Unauthenticated Combination key from P-256"),
    (0x08, "Authenticated Combination key from P-256"),
];

/// Six-digit passkey / numeric comparison value.
fn passkey(r: &mut Reader<'_>, out: &mut Out) -> Result<u32> {
    let v = r.u32()?;
    field!(out, "Passkey: {:06}", v);
    Ok(v)
}

/// `Encryption_Enabled` of the Encryption Change event.  Value 0x01 means E0
/// on BR/EDR links and AES-CCM on LE links, so the meaning depends on the
/// link the handle refers to.
fn encryption_mode(st: &IndexState, h: u16, r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    let v = r.u8()?;
    let text = match v {
        0x00 => "Disabled",
        0x01 => match st.conn(h).map(|c| c.link) {
            Some(LinkType::Acl | LinkType::Sco | LinkType::Esco) => "Enabled with E0",
            Some(LinkType::Le) => "Enabled with AES-CCM",
            _ => "Enabled",
        },
        0x02 => "Enabled with AES-CCM",
        _ => {
            out.unknown(format!("Encryption: Reserved (0x{v:02x})"));
            return Ok(v);
        }
    };
    field!(out, "Encryption: {} (0x{:02x})", text, v);
    Ok(v)
}

fn sam_index(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    let v = r.u8()?;
    if v == 0xff {
        field!(out, "{}: Disabled (0xff)", label);
    } else {
        field!(out, "{}: {}", label, v);
    }
    Ok(v)
}

/// Proportion of available slots, 0 = less than 1/255 and 255 = all.
fn sam_availability(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    let v = r.u8()?;
    field!(out, "{}: {}/255 (0x{:02x})", label, v, v);
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reader::BdAddr;
    use crate::tree::render_lines;

    const ADDR: [u8; 6] = [0x03, 0x32, 0x07, 0xdc, 0x1b, 0x00];
    const ADDR_TEXT: &str = "Address: 00:1B:DC:07:32:03 (OUI 00-1B-DC)";

    fn decode(st: &mut IndexState, code: u8, data: &[u8]) -> Out {
        let mut out = Out::new();
        let mut r = Reader::new(data);
        assert!(event_params(st, code, &mut r, &mut out).unwrap(), "event 0x{code:02x} not decoded");
        assert!(r.is_empty(), "event 0x{code:02x} left {} byte(s)", r.remaining());
        out
    }

    /// Root line texts only.
    fn roots(out: &Out) -> Vec<String> {
        out.roots().iter().map(|n| n.text.clone()).collect()
    }

    /// Every line, indented two spaces per nesting level.
    fn lines(out: &Out) -> Vec<String> {
        let mut v = Vec::new();
        render_lines(out.roots(), 0, |indent, n| v.push(format!("{}{}", " ".repeat(indent), n.text)));
        v
    }

    fn with(parts: &[&[u8]]) -> Vec<u8> {
        parts.concat()
    }

    #[test]
    fn inquiry_result_params() {
        let mut st = IndexState::default();
        let data = with(&[&[0x01], &ADDR, &[0x01, 0x00, 0x00, 0x0c, 0x02, 0x5a, 0x34, 0x12]]);
        let out = decode(&mut st, evt::INQUIRY_RESULT, &data);
        assert_eq!(
            roots(&out),
            [
                "Num responses: 1",
                ADDR_TEXT,
                "Page scan repetition mode: R1 (0x01)",
                "Page period mode: P0 (0x00)",
                "Page scan mode: Mandatory (0x00)",
                "Class: 0x5a020c",
                "Clock offset: 0x1234",
            ]
        );
    }

    #[test]
    fn inquiry_result_with_rssi_two_responses() {
        let mut st = IndexState::default();
        let one = with(&[&ADDR, &[0x01, 0x00, 0x0c, 0x02, 0x5a, 0x00, 0x00, 0xc4]]);
        let data = with(&[&[0x02], &one, &one]);
        let out = decode(&mut st, evt::INQUIRY_RESULT_WITH_RSSI, &data);
        let r = roots(&out);
        assert_eq!(r.len(), 1 + 2 * 6);
        assert_eq!(r[6], "RSSI: -60 dBm (0xc4)");
        assert_eq!(r[7], ADDR_TEXT);
    }

    #[test]
    fn connection_complete_registers_acl() {
        let mut st = IndexState::default();
        let data = with(&[&[0x00, 0x0b, 0x00], &ADDR, &[0x01, 0x00]]);
        let out = decode(&mut st, evt::CONNECTION_COMPLETE, &data);
        assert_eq!(
            roots(&out),
            ["Status: Success (0x00)", "Handle: 11", ADDR_TEXT, "Link type: ACL (0x01)", "Encryption: Disabled (0x00)"]
        );
        let c = st.conn(11).expect("connection registered");
        assert_eq!(c.link, LinkType::Acl);
        assert_eq!(c.addr, BdAddr(ADDR));
        assert_eq!(c.addr_type, 0);
    }

    #[test]
    fn connection_complete_failure_is_not_registered() {
        let mut st = IndexState::default();
        let data = with(&[&[0x04, 0x0b, 0x00], &ADDR, &[0x01, 0x00]]);
        let out = decode(&mut st, evt::CONNECTION_COMPLETE, &data);
        assert_eq!(roots(&out)[0], "Status: Page Timeout (0x04)");
        assert!(st.conn(11).is_none());
    }

    #[test]
    fn connection_request_params() {
        let mut st = IndexState::default();
        let data = with(&[&ADDR, &[0x0c, 0x02, 0x5a, 0x01]]);
        let out = decode(&mut st, evt::CONNECTION_REQUEST, &data);
        assert_eq!(roots(&out), [ADDR_TEXT, "Class: 0x5a020c", "Link type: ACL (0x01)"]);
    }

    #[test]
    fn synchronous_connection_complete_registers_esco() {
        let mut st = IndexState::default();
        let data = with(&[&[0x00, 0x0c, 0x00], &ADDR, &[0x02, 0x0c, 0x04, 0x3c, 0x00, 0x3c, 0x00, 0x02]]);
        let out = decode(&mut st, evt::SYNCHRONOUS_CONNECTION_COMPLETE, &data);
        assert_eq!(
            roots(&out),
            [
                "Status: Success (0x00)",
                "Handle: 12",
                ADDR_TEXT,
                "Link type: eSCO (0x02)",
                "Transmission interval: 0x0c",
                "Retransmission window: 0x04",
                "RX packet length: 60",
                "TX packet length: 60",
                "Air mode: CVSD (0x02)",
            ]
        );
        assert_eq!(st.conn(12).unwrap().link, LinkType::Esco);
    }

    #[test]
    fn encryption_change_depends_on_link_type() {
        let mut st = IndexState::default();
        register_connection(&mut st, 1, LinkType::Acl, 0, BdAddr::ZERO, 0);
        register_connection(&mut st, 2, LinkType::Le, 1, BdAddr::ZERO, 0);

        let out = decode(&mut st, evt::ENCRYPTION_CHANGE, &[0x00, 0x01, 0x00, 0x01]);
        assert_eq!(roots(&out), ["Status: Success (0x00)", "Handle: 1", "Encryption: Enabled with E0 (0x01)"]);

        let out = decode(&mut st, evt::ENCRYPTION_CHANGE_V2, &[0x00, 0x02, 0x00, 0x01, 0x10]);
        assert_eq!(
            roots(&out),
            ["Status: Success (0x00)", "Handle: 2", "Encryption: Enabled with AES-CCM (0x01)", "Key size: 16"]
        );

        let out = decode(&mut st, evt::ENCRYPTION_CHANGE, &[0x00, 0x01, 0x00, 0x02]);
        assert_eq!(roots(&out)[2], "Encryption: Enabled with AES-CCM (0x02)");
    }

    #[test]
    fn disconnection_complete_removes_connection() {
        let mut st = IndexState::default();
        register_connection(&mut st, 1, LinkType::Acl, 0, BdAddr(ADDR), 0);
        let out = decode(&mut st, evt::DISCONNECTION_COMPLETE, &[0x00, 0x01, 0x00, 0x13]);
        assert_eq!(
            roots(&out),
            [
                "Status: Success (0x00)",
                "Handle: 1 Address: 00:1B:DC:07:32:03 (Public)",
                "Reason: Remote User Terminated Connection (0x13)",
            ]
        );
        assert!(st.conn(1).is_none());
    }

    #[test]
    fn role_change_updates_connection_role() {
        let mut st = IndexState::default();
        register_connection(&mut st, 1, LinkType::Acl, 0, BdAddr(ADDR), 0);
        let data = with(&[&[0x00], &ADDR, &[0x01]]);
        let out = decode(&mut st, evt::ROLE_CHANGE, &data);
        assert_eq!(roots(&out), ["Status: Success (0x00)", ADDR_TEXT, "Role: Peripheral (0x01)"]);
        assert_eq!(st.conn(1).unwrap().role, 1);
    }

    #[test]
    fn remote_name_request_complete_params() {
        let mut st = IndexState::default();
        let mut name = [0u8; 248];
        name[..4].copy_from_slice(b"Test");
        let data = with(&[&[0x00], &ADDR, &name]);
        let out = decode(&mut st, evt::REMOTE_NAME_REQUEST_COMPLETE, &data);
        assert_eq!(roots(&out), ["Status: Success (0x00)", ADDR_TEXT, "Name: Test"]);
    }

    #[test]
    fn read_remote_version_information_complete_params() {
        let mut st = IndexState::default();
        let out = decode(&mut st, evt::READ_REMOTE_VERSION_INFORMATION_COMPLETE, &[0x00, 0x01, 0x00, 0x08, 0x0f, 0x00, 0x11, 0x23]);
        let expected_manuf = format!("Manufacturer: {} (15)", crate::assigned::company_name(15).unwrap());
        assert_eq!(
            roots(&out),
            [
                "Status: Success (0x00)",
                "Handle: 1",
                "LMP version: Bluetooth 4.2 (0x08) - Subversion 8977 (0x2311)",
                expected_manuf.as_str(),
            ]
        );
    }

    #[test]
    fn read_remote_extended_features_complete_params() {
        let mut st = IndexState::default();
        let out = decode(
            &mut st,
            evt::READ_REMOTE_EXTENDED_FEATURES_COMPLETE,
            &[0x00, 0x01, 0x00, 0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        );
        assert_eq!(
            lines(&out),
            [
                "Status: Success (0x00)",
                "Handle: 1",
                "Page: 1/2",
                "Features: 0x03 0x00 0x00 0x00 0x00 0x00 0x00 0x00",
                "  Secure Simple Pairing (Host Support)",
                "  LE Supported (Host)",
            ]
        );
    }

    #[test]
    fn mode_change_params() {
        let mut st = IndexState::default();
        let out = decode(&mut st, evt::MODE_CHANGE, &[0x00, 0x01, 0x00, 0x02, 0x00, 0x08]);
        assert_eq!(roots(&out), ["Status: Success (0x00)", "Handle: 1", "Mode: Sniff (0x02)", "Interval: 1280.000 msec (0x0800)"]);
    }

    #[test]
    fn return_link_keys_params() {
        let mut st = IndexState::default();
        let key: Vec<u8> = (0..16).collect();
        let data = with(&[&[0x02], &ADDR, &key, &ADDR, &key]);
        let out = decode(&mut st, evt::RETURN_LINK_KEYS, &data);
        assert_eq!(
            roots(&out),
            [
                "Num keys: 2",
                ADDR_TEXT,
                "Link key: 000102030405060708090a0b0c0d0e0f",
                ADDR_TEXT,
                "Link key: 000102030405060708090a0b0c0d0e0f",
            ]
        );
    }

    #[test]
    fn link_key_notification_params() {
        let mut st = IndexState::default();
        let key: Vec<u8> = (0..16).collect();
        let data = with(&[&ADDR, &key, &[0x05]]);
        let out = decode(&mut st, evt::LINK_KEY_NOTIFICATION, &data);
        assert_eq!(
            roots(&out),
            [ADDR_TEXT, "Link key: 000102030405060708090a0b0c0d0e0f", "Key type: Authenticated Combination key from P-192 (0x05)"]
        );
    }

    #[test]
    fn link_key_type_changed_params() {
        let mut st = IndexState::default();
        let out = decode(&mut st, evt::LINK_KEY_TYPE_CHANGED, &[0x00, 0x01, 0x00, 0x01]);
        assert_eq!(roots(&out), ["Status: Success (0x00)", "Handle: 1", "Key flag: Temporary (0x01)"]);
    }

    #[test]
    fn address_only_events() {
        let mut st = IndexState::default();
        for code in [
            evt::PIN_CODE_REQUEST,
            evt::LINK_KEY_REQUEST,
            evt::IO_CAPABILITY_REQUEST,
            evt::USER_PASSKEY_REQUEST,
            evt::REMOTE_OOB_DATA_REQUEST,
        ] {
            let out = decode(&mut st, code, &ADDR);
            assert_eq!(roots(&out), [ADDR_TEXT]);
        }
    }

    #[test]
    fn loopback_command_decodes_looped_command() {
        let mut st = IndexState::default();
        let out = decode(&mut st, evt::LOOPBACK_COMMAND, &[0x0c, 0x20, 0x02, 0x01, 0x00]);
        assert_eq!(roots(&out), ["LE Set Scan Enable (0x08|0x000c) plen 2"]);
        assert!(!out.roots()[0].children.is_empty());
    }

    #[test]
    fn connection_packet_type_changed_bits() {
        let mut st = IndexState::default();
        let out = decode(&mut st, evt::CONNECTION_PACKET_TYPE_CHANGED, &[0x00, 0x01, 0x00, 0x19, 0xcc]);
        assert_eq!(
            lines(&out),
            [
                "Status: Success (0x00)",
                "Handle: 1",
                "Packet type: 0xcc19",
                "  DM1 may be used",
                "  DH1 may be used",
                "  DM3 may be used",
                "  DH3 may be used",
                "  DM5 may be used",
                "  DH5 may be used",
                "  Unknown packet types (0x0001)",
            ]
        );
    }

    #[test]
    fn qos_setup_complete_params() {
        let mut st = IndexState::default();
        let out = decode(
            &mut st,
            evt::QOS_SETUP_COMPLETE,
            &[0x00, 0x01, 0x00, 0x00, 0x01, 0x10, 0x27, 0x00, 0x00, 0x20, 0x4e, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        );
        assert_eq!(
            roots(&out),
            [
                "Status: Success (0x00)",
                "Handle: 1",
                "Flags: 0x00",
                "Service type: Best Effort (0x01)",
                "Token rate: 10000",
                "Peak bandwidth: 20000",
                "Latency: 4294967295",
                "Delay variation: 4294967295",
            ]
        );
    }

    #[test]
    fn flow_specification_complete_params() {
        let mut st = IndexState::default();
        let out = decode(
            &mut st,
            evt::FLOW_SPECIFICATION_COMPLETE,
            &[0x00, 0x01, 0x00, 0x00, 0x01, 0x02, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00],
        );
        assert_eq!(
            roots(&out),
            [
                "Status: Success (0x00)",
                "Handle: 1",
                "Flags: 0x00",
                "Flow direction: Incoming (0x01)",
                "Service type: Guaranteed (0x02)",
                "Token rate: 1",
                "Token bucket size: 2",
                "Peak bandwidth: 3",
                "Access latency: 4",
            ]
        );
    }

    #[test]
    fn sniff_subrating_params() {
        let mut st = IndexState::default();
        let out = decode(&mut st, evt::SNIFF_SUBRATING, &[0x00, 0x01, 0x00, 0x02, 0x00, 0x04, 0x00, 0x06, 0x00, 0x08, 0x00]);
        assert_eq!(
            roots(&out),
            [
                "Status: Success (0x00)",
                "Handle: 1",
                "Max transmit latency: 1.250 msec (0x0002)",
                "Max receive latency: 2.500 msec (0x0004)",
                "Min remote timeout: 3.750 msec (0x0006)",
                "Min local timeout: 5.000 msec (0x0008)",
            ]
        );
    }

    #[test]
    fn extended_inquiry_result_decodes_eir() {
        let mut st = IndexState::default();
        let mut eir = [0u8; 240];
        eir[..6].copy_from_slice(&[0x05, 0x09, b'T', b'e', b's', b't']);
        let data = with(&[&[0x01], &ADDR, &[0x01, 0x00, 0x0c, 0x02, 0x5a, 0x00, 0x00, 0xc4], &eir]);
        let out = decode(&mut st, evt::EXTENDED_INQUIRY_RESULT, &data);
        let r = roots(&out);
        assert_eq!(r[0], "Num responses: 1");
        assert_eq!(r[6], "RSSI: -60 dBm (0xc4)");
        assert_eq!(r.len(), 8, "{r:?}");
        assert_eq!(r[7], "Name (complete): Test");
    }

    #[test]
    fn io_capability_response_params() {
        let mut st = IndexState::default();
        let data = with(&[&ADDR, &[0x01, 0x00, 0x03]]);
        let out = decode(&mut st, evt::IO_CAPABILITY_RESPONSE, &data);
        assert_eq!(
            roots(&out),
            [
                ADDR_TEXT,
                "IO capability: DisplayYesNo (0x01)",
                "OOB data: Authentication data not present (0x00)",
                "Authentication: Dedicated Bonding - MITM required (0x03)",
            ]
        );
    }

    #[test]
    fn user_confirmation_request_prints_six_digit_passkey() {
        let mut st = IndexState::default();
        let data = with(&[&ADDR, &[0x39, 0x30, 0x00, 0x00]]);
        let out = decode(&mut st, evt::USER_CONFIRMATION_REQUEST, &data);
        assert_eq!(roots(&out), [ADDR_TEXT, "Passkey: 012345"]);
        let out = decode(&mut st, evt::USER_PASSKEY_NOTIFICATION, &data);
        assert_eq!(roots(&out)[1], "Passkey: 012345");
    }

    #[test]
    fn keypress_notification_params() {
        let mut st = IndexState::default();
        let data = with(&[&ADDR, &[0x04]]);
        let out = decode(&mut st, evt::KEYPRESS_NOTIFICATION, &data);
        assert_eq!(roots(&out), [ADDR_TEXT, "Notification type: Passkey entry completed (0x04)"]);
    }

    #[test]
    fn link_supervision_timeout_changed_params() {
        let mut st = IndexState::default();
        let out = decode(&mut st, evt::LINK_SUPERVISION_TIMEOUT_CHANGED, &[0x01, 0x00, 0x20, 0x00]);
        assert_eq!(roots(&out), ["Handle: 1", "Timeout: 20.000 msec (0x0020)"]);
    }

    #[test]
    fn number_of_completed_data_blocks_params() {
        let mut st = IndexState::default();
        let out = decode(&mut st, evt::NUMBER_OF_COMPLETED_DATA_BLOCKS, &[0x10, 0x00, 0x01, 0x01, 0x00, 0x02, 0x00, 0x03, 0x00]);
        assert_eq!(roots(&out), ["Total num data blocks: 16", "Num handles: 1", "Handle: 1", "Num packets: 2", "Num blocks: 3"]);
    }

    #[test]
    fn triggered_clock_capture_params() {
        let mut st = IndexState::default();
        let out = decode(&mut st, evt::TRIGGERED_CLOCK_CAPTURE, &[0x01, 0x00, 0x01, 0x78, 0x56, 0x34, 0x02, 0x10, 0x00]);
        assert_eq!(roots(&out), ["Handle: 1", "Type: Piconet clock (0x01)", "Clock: 0x02345678", "Clock offset: 0x0010"]);
    }

    #[test]
    fn synchronization_train_received_channel_map() {
        let mut st = IndexState::default();
        let map = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f];
        let data = with(&[&[0x00], &ADDR, &[0x10, 0x00, 0x00, 0x00], &map, &[0x01, 0x20, 0x00, 0x00, 0x00, 0x40, 0x00, 0x05]]);
        let out = decode(&mut st, evt::SYNCHRONIZATION_TRAIN_RECEIVED, &data);
        assert_eq!(
            lines(&out),
            [
                "Status: Success (0x00)",
                ADDR_TEXT,
                "Offset: 0x00000010",
                "Channel map: 0xffffffffffffffffff7f",
                "  Channel 0-78",
                "LT address: 1",
                "Next broadcast instant: 0x00000020",
                "Interval: 40.000 msec (0x0040)",
                "Service Data: 0x05",
            ]
        );
    }

    #[test]
    fn channel_map_change_ranges() {
        let mut st = IndexState::default();
        // Channels 0, 2-4 and 78 set.
        let map = [0x1d, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40];
        let out = decode(&mut st, evt::CONNECTIONLESS_PERIPHERAL_BROADCAST_CHANNEL_MAP_CHANGE, &map);
        assert_eq!(lines(&out), ["Channel map: 0x1d000000000000000040", "  Channel 0", "  Channel 2-4", "  Channel 78"]);
    }

    #[test]
    fn connectionless_peripheral_broadcast_receive_params() {
        let mut st = IndexState::default();
        let data = with(&[&ADDR, &[0x01, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x03, 0x02, 0xaa, 0xbb]]);
        let out = decode(&mut st, evt::CONNECTIONLESS_PERIPHERAL_BROADCAST_RECEIVE, &data);
        let l = lines(&out);
        assert_eq!(
            &l[..7],
            [
                ADDR_TEXT,
                "LT address: 1",
                "Clock: 0x00000001",
                "Offset: 0x00000002",
                "Receive status: Packet received successfully (0x00)",
                "Fragment: No fragmentation (0x03)",
                "Length: 2",
            ]
        );
        assert_eq!(l.len(), 8);
        assert!(l[7].starts_with("aa bb ") && l[7].ends_with("  .."), "{}", l[7]);
    }

    #[test]
    fn inquiry_response_notification_params() {
        let mut st = IndexState::default();
        let out = decode(&mut st, evt::INQUIRY_RESPONSE_NOTIFICATION, &[0x33, 0x8b, 0x9e, 0xc4]);
        assert_eq!(roots(&out), ["Access code: 0x9e8b33 (General Inquiry)", "RSSI: -60 dBm (0xc4)"]);
    }

    #[test]
    fn sam_status_change_params() {
        let mut st = IndexState::default();
        let out = decode(&mut st, evt::SAM_STATUS_CHANGE, &[0x01, 0x00, 0x00, 0xff, 0x80, 0xff, 0xff, 0xff]);
        assert_eq!(
            roots(&out),
            [
                "Handle: 1",
                "Local SAM index: 0",
                "Local SAM TX availability: 255/255 (0xff)",
                "Local SAM RX availability: 128/255 (0x80)",
                "Remote SAM index: Disabled (0xff)",
                "Remote SAM TX availability: 255/255 (0xff)",
                "Remote SAM RX availability: 255/255 (0xff)",
            ]
        );
    }

    #[test]
    fn handle_only_and_empty_events() {
        let mut st = IndexState::default();
        for code in [evt::FLUSH_OCCURRED, evt::QOS_VIOLATION, evt::ENHANCED_FLUSH_COMPLETE, evt::AUTHENTICATED_PAYLOAD_TIMEOUT_EXPIRED] {
            let out = decode(&mut st, code, &[0x05, 0x00]);
            assert_eq!(roots(&out), ["Handle: 5"]);
        }
        let out = decode(&mut st, evt::PERIPHERAL_PAGE_RESPONSE_TIMEOUT, &[]);
        assert!(out.is_empty());
        let out = decode(&mut st, evt::DATA_BUFFER_OVERFLOW, &[0x01]);
        assert_eq!(roots(&out), ["Link type: ACL (0x01)"]);
        let out = decode(&mut st, evt::MAX_SLOTS_CHANGE, &[0x01, 0x00, 0x05]);
        assert_eq!(roots(&out), ["Handle: 1", "Max slots: 5"]);
    }

    #[test]
    fn undecoded_events_return_false() {
        let mut st = IndexState::default();
        let mut out = Out::new();
        for code in [0xff, evt::PHYSICAL_LINK_COMPLETE, evt::AMP_STATUS_CHANGE] {
            let mut r = Reader::new(&[0x01, 0x02]);
            assert!(!event_params(&mut st, code, &mut r, &mut out).unwrap());
        }
        assert!(out.is_empty());
    }

    #[test]
    fn truncated_event_reports_error() {
        let mut st = IndexState::default();
        let mut out = Out::new();
        let mut r = Reader::new(&[0x00, 0x01]);
        assert!(event_params(&mut st, evt::MODE_CHANGE, &mut r, &mut out).is_err());
        assert_eq!(roots(&out), ["Status: Success (0x00)"]);
    }
}
