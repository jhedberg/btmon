//! LE Controller command decoders, OCF 0x0061 and above (ISO, power control, subrating, PAwR, Channel Sounding, ...).

use super::cmd;
use super::common::*;
use crate::context::IndexState;
use crate::field;
use crate::reader::{Reader, Result};
use crate::tree::Out;

/// Decode command parameters; `Ok(false)` if the opcode is not handled here.
pub fn command_params(st: &mut IndexState, opcode: u16, r: &mut Reader<'_>, out: &mut Out) -> Result<bool> {
    match opcode {
        cmd::LE_READ_ISO_TX_SYNC
        | cmd::LE_REQUEST_PEER_SCA
        | cmd::LE_ISO_READ_TEST_COUNTERS
        | cmd::LE_ISO_TEST_END
        | cmd::LE_READ_ISO_LINK_QUALITY
        | cmd::LE_CS_READ_REMOTE_SUPPORTED_CAPABILITIES
        | cmd::LE_CS_SECURITY_ENABLE
        | cmd::LE_CS_READ_REMOTE_FAE_TABLE => {
            handle(st, r, out)?;
        }
        cmd::LE_SET_CIG_PARAMETERS => set_cig_parameters(r, out)?,
        cmd::LE_SET_CIG_PARAMETERS_TEST => set_cig_parameters_test(r, out)?,
        cmd::LE_CREATE_CIS => create_cis(st, r, out)?,
        cmd::LE_REMOVE_CIG => {
            cig_id(r, out)?;
        }
        cmd::LE_ACCEPT_CIS_REQUEST => {
            handle_labelled("CIS Handle", st, r, out)?;
        }
        cmd::LE_REJECT_CIS_REQUEST => {
            handle_labelled("CIS Handle", st, r, out)?;
            reason(r, out)?;
        }
        cmd::LE_CREATE_BIG => create_big(r, out)?,
        cmd::LE_CREATE_BIG_TEST => create_big_test(r, out)?,
        cmd::LE_TERMINATE_BIG => {
            big_handle(r, out)?;
            reason(r, out)?;
        }
        cmd::LE_BIG_CREATE_SYNC => big_create_sync(r, out)?,
        cmd::LE_BIG_TERMINATE_SYNC => {
            big_handle(r, out)?;
        }
        cmd::LE_SETUP_ISO_DATA_PATH => setup_iso_data_path(st, r, out)?,
        cmd::LE_REMOVE_ISO_DATA_PATH => {
            handle(st, r, out)?;
            mask8("Data Path Direction", r, out, &[(0, "Remove input data path"), (1, "Remove output data path")], 8)?;
        }
        cmd::LE_ISO_TRANSMIT_TEST | cmd::LE_ISO_RECEIVE_TEST => {
            handle(st, r, out)?;
            enum8(
                "Payload Type",
                r,
                out,
                &[(0x00, "Zero length payload"), (0x01, "Variable length payload"), (0x02, "Maximum length payload")],
            )?;
        }
        cmd::LE_SET_HOST_FEATURE => set_host_feature(r, out, false)?,
        cmd::LE_SET_HOST_FEATURE_V2 => set_host_feature(r, out, true)?,
        cmd::LE_ENHANCED_READ_TRANSMIT_POWER_LEVEL | cmd::LE_READ_REMOTE_TRANSMIT_POWER_LEVEL => {
            handle(st, r, out)?;
            phy_coded("PHY", r, out)?;
        }
        cmd::LE_SET_PATH_LOSS_REPORTING_PARAMETERS => set_path_loss_reporting_parameters(st, r, out)?,
        cmd::LE_SET_PATH_LOSS_REPORTING_ENABLE => {
            handle(st, r, out)?;
            enable("Reporting", r, out)?;
        }
        cmd::LE_SET_TRANSMIT_POWER_REPORTING_ENABLE => {
            handle(st, r, out)?;
            enable("Local reporting", r, out)?;
            enable("Remote reporting", r, out)?;
        }
        cmd::LE_TRANSMITTER_TEST_V4 => transmitter_test_v4(r, out)?,
        cmd::LE_SET_DATA_RELATED_ADDRESS_CHANGES => {
            u8_hex("Handle", r, out)?;
            mask8(
                "Change reasons",
                r,
                out,
                &[(0, "Change address when advertising data changes"), (1, "Change address when scan response data changes")],
                8,
            )?;
        }
        cmd::LE_SET_DEFAULT_SUBRATE => subrate_params(r, out)?,
        cmd::LE_SUBRATE_REQUEST => {
            handle(st, r, out)?;
            subrate_params(r, out)?;
        }
        cmd::LE_SET_EXTENDED_ADVERTISING_PARAMETERS_V2 => set_ext_adv_params_v2(r, out)?,
        cmd::LE_SET_DECISION_DATA => set_decision_data(r, out)?,
        cmd::LE_SET_DECISION_INSTRUCTIONS => set_decision_instructions(r, out)?,
        cmd::LE_SET_PERIODIC_ADVERTISING_SUBEVENT_DATA => set_pa_subevent_data(r, out)?,
        cmd::LE_SET_PERIODIC_ADVERTISING_RESPONSE_DATA => set_pa_response_data(r, out)?,
        cmd::LE_SET_PERIODIC_SYNC_SUBEVENT => set_periodic_sync_subevent(r, out)?,
        cmd::LE_EXTENDED_CREATE_CONNECTION_V2 => ext_create_connection_v2(r, out)?,
        cmd::LE_SET_PERIODIC_ADVERTISING_PARAMETERS_V2 => set_pa_params_v2(r, out)?,
        cmd::LE_READ_ALL_REMOTE_FEATURES => {
            handle(st, r, out)?;
            u8_field("Pages requested", r, out)?;
        }
        cmd::LE_CS_WRITE_CACHED_REMOTE_SUPPORTED_CAPABILITIES | cmd::LE_CS_WRITE_CACHED_REMOTE_SUPPORTED_CAPABILITIES_V2 => {
            handle(st, r, out)?;
            cs_capabilities(r, out)?;
        }
        cmd::LE_CS_SET_DEFAULT_SETTINGS => cs_set_default_settings(st, r, out)?,
        cmd::LE_CS_WRITE_CACHED_REMOTE_FAE_TABLE => {
            handle(st, r, out)?;
            hex_bytes("Remote FAE table", r, out, 72)?;
        }
        cmd::LE_CS_CREATE_CONFIG => cs_create_config(st, r, out)?,
        cmd::LE_CS_REMOVE_CONFIG => {
            handle(st, r, out)?;
            u8_field("Config ID", r, out)?;
        }
        cmd::LE_CS_SET_CHANNEL_CLASSIFICATION => {
            hex_bytes("Channel classification", r, out, 10)?;
        }
        cmd::LE_CS_SET_PROCEDURE_PARAMETERS => cs_set_procedure_parameters(st, r, out)?,
        cmd::LE_CS_PROCEDURE_ENABLE => {
            handle(st, r, out)?;
            u8_field("Config ID", r, out)?;
            enable("CS procedures", r, out)?;
        }
        cmd::LE_CS_TEST => cs_test(r, out)?,
        cmd::LE_ADD_DEVICE_TO_MONITORED_ADVERTISERS_LIST => {
            peer_addr(r, out)?;
            rssi_labelled("RSSI low threshold", r, out)?;
            rssi_labelled("RSSI high threshold", r, out)?;
            let t = r.u8()?;
            field!(out, "Timeout: {} seconds (0x{:02x})", t, t);
        }
        cmd::LE_REMOVE_DEVICE_FROM_MONITORED_ADVERTISERS_LIST => {
            peer_addr(r, out)?;
        }
        cmd::LE_ENABLE_MONITORING_ADVERTISERS => {
            enable("Monitoring", r, out)?;
        }
        cmd::LE_FRAME_SPACE_UPDATE => frame_space_update(st, r, out)?,
        cmd::LE_SET_RESOLVABLE_PRIVATE_ADDRESS_TIMEOUT_V2 => {
            seconds16("Timeout", r, out)?;
            seconds16("Min timeout", r, out)?;
            seconds16("Max timeout", r, out)?;
        }
        cmd::LE_ENABLE_UTP_OTA_MODE => {
            enable("UTP OTA mode", r, out)?;
        }
        cmd::LE_UTP_SEND => {
            let len = u8_field("Data length", r, out)? as usize;
            out.hex_field("Data", r.bytes(len)?);
        }
        cmd::LE_CONNECTION_RATE_REQUEST => {
            handle(st, r, out)?;
            rate_params(r, out)?;
        }
        cmd::LE_SET_DEFAULT_RATE_PARAMETERS => rate_params(r, out)?,
        cmd::LE_SET_EVENT_MASK_V2 => le_event_mask_v2(r, out)?,
        _ => return Ok(false),
    }
    Ok(true)
}

/// Decode Command Complete return parameters; `Ok(false)` if the opcode is not handled here.
pub fn return_params(st: &mut IndexState, opcode: u16, r: &mut Reader<'_>, out: &mut Out) -> Result<bool> {
    match opcode {
        cmd::LE_READ_ISO_TX_SYNC => {
            if status_only(r, out)? {
                return Ok(true);
            }
            handle(st, r, out)?;
            u16_field("Packet sequence number", r, out)?;
            let ts = r.u32()?;
            field!(out, "TX timestamp: {} us (0x{:08x})", ts, ts);
            usec24("Time offset", r, out)?;
        }
        cmd::LE_SET_CIG_PARAMETERS | cmd::LE_SET_CIG_PARAMETERS_TEST => {
            if status_only(r, out)? {
                return Ok(true);
            }
            cig_id(r, out)?;
            let n = u8_field("Number of Handles", r, out)?;
            for i in 0..n {
                let h = read_handle(r)?;
                field!(out, "Connection Handle #{}: {}", i, h);
                if !st.pending_iso.contains(&h) {
                    st.pending_iso.push(h);
                }
            }
        }
        cmd::LE_REMOVE_CIG => {
            if status_only(r, out)? {
                return Ok(true);
            }
            cig_id(r, out)?;
        }
        cmd::LE_BIG_TERMINATE_SYNC => {
            if status_only(r, out)? {
                return Ok(true);
            }
            big_handle(r, out)?;
        }
        cmd::LE_REJECT_CIS_REQUEST
        | cmd::LE_SETUP_ISO_DATA_PATH
        | cmd::LE_REMOVE_ISO_DATA_PATH
        | cmd::LE_ISO_TRANSMIT_TEST
        | cmd::LE_ISO_RECEIVE_TEST
        | cmd::LE_SET_PATH_LOSS_REPORTING_PARAMETERS
        | cmd::LE_SET_PATH_LOSS_REPORTING_ENABLE
        | cmd::LE_SET_TRANSMIT_POWER_REPORTING_ENABLE
        | cmd::LE_CS_WRITE_CACHED_REMOTE_SUPPORTED_CAPABILITIES
        | cmd::LE_CS_WRITE_CACHED_REMOTE_SUPPORTED_CAPABILITIES_V2
        | cmd::LE_CS_SET_DEFAULT_SETTINGS
        | cmd::LE_CS_WRITE_CACHED_REMOTE_FAE_TABLE
        | cmd::LE_CS_SET_PROCEDURE_PARAMETERS => {
            if status_only(r, out)? {
                return Ok(true);
            }
            handle(st, r, out)?;
        }
        cmd::LE_SET_PERIODIC_ADVERTISING_RESPONSE_DATA | cmd::LE_SET_PERIODIC_SYNC_SUBEVENT => {
            if status_only(r, out)? {
                return Ok(true);
            }
            sync_handle(r, out)?;
        }
        cmd::LE_ISO_READ_TEST_COUNTERS | cmd::LE_ISO_TEST_END => {
            if status_only(r, out)? {
                return Ok(true);
            }
            handle(st, r, out)?;
            u32_field("Received SDU count", r, out)?;
            u32_field("Missed SDU count", r, out)?;
            u32_field("Failed SDU count", r, out)?;
        }
        cmd::LE_READ_ISO_LINK_QUALITY => {
            if status_only(r, out)? {
                return Ok(true);
            }
            handle(st, r, out)?;
            u32_field("TX unacked packets", r, out)?;
            u32_field("TX flushed packets", r, out)?;
            u32_field("TX last subevent packets", r, out)?;
            u32_field("Retransmitted packets", r, out)?;
            u32_field("CRC error packets", r, out)?;
            u32_field("RX unreceived packets", r, out)?;
            u32_field("Duplicate packets", r, out)?;
        }
        cmd::LE_ENHANCED_READ_TRANSMIT_POWER_LEVEL => {
            if status_only(r, out)? {
                return Ok(true);
            }
            handle(st, r, out)?;
            phy_coded("PHY", r, out)?;
            let cur = r.i8()?;
            match cur {
                127 => field!(out, "Current TX power: Not available (0x7f)"),
                _ => field!(out, "Current TX power: {} dbm (0x{:02x})", cur, cur as u8),
            };
            power_dbm("Max TX power", r, out)?;
        }
        cmd::LE_SET_EXTENDED_ADVERTISING_PARAMETERS_V2 => {
            if status_only(r, out)? {
                return Ok(true);
            }
            power_dbm("TX power (selected)", r, out)?;
        }
        cmd::LE_SET_PERIODIC_ADVERTISING_SUBEVENT_DATA | cmd::LE_SET_PERIODIC_ADVERTISING_PARAMETERS_V2 => {
            if status_only(r, out)? {
                return Ok(true);
            }
            u8_hex("Handle", r, out)?;
        }
        cmd::LE_READ_ALL_LOCAL_SUPPORTED_FEATURES => read_all_local_supported_features_rsp(r, out)?,
        cmd::LE_CS_READ_LOCAL_SUPPORTED_CAPABILITIES | cmd::LE_CS_READ_LOCAL_SUPPORTED_CAPABILITIES_V2 => {
            if status_only(r, out)? {
                return Ok(true);
            }
            cs_capabilities(r, out)?;
        }
        cmd::LE_READ_MONITORED_ADVERTISERS_LIST_SIZE => {
            if status_only(r, out)? {
                return Ok(true);
            }
            u8_field("List size", r, out)?;
        }
        cmd::LE_READ_MINIMUM_SUPPORTED_CONNECTION_INTERVAL => read_min_supported_conn_interval_rsp(r, out)?,
        _ => return Ok(false),
    }
    Ok(true)
}

// ---------------------------------------------------------------------------
// Small formatting helpers used by several decoders in this file.
// ---------------------------------------------------------------------------

fn cig_id(r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    u8_hex("CIG ID", r, out)
}

fn big_handle(r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    u8_hex("BIG Handle", r, out)
}

/// Worst case sleep clock accuracy.
fn sca(r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    enum8(
        "Worst Case SCA",
        r,
        out,
        &[
            (0x00, "251 ppm to 500 ppm"),
            (0x01, "151 ppm to 250 ppm"),
            (0x02, "101 ppm to 150 ppm"),
            (0x03, "76 ppm to 100 ppm"),
            (0x04, "51 ppm to 75 ppm"),
            (0x05, "31 ppm to 50 ppm"),
            (0x06, "21 ppm to 30 ppm"),
            (0x07, "0 ppm to 20 ppm"),
        ],
    )
}

fn packing(r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    enum8("Packing", r, out, &[(0x00, "Sequential"), (0x01, "Interleaved")])
}

fn framing(r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    enum8("Framing", r, out, &[(0x00, "Unframed"), (0x01, "Framed, Segmentable"), (0x02, "Framed, Unsegmented")])
}

fn broadcast_code(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    hex_bytes("Broadcast Code", r, out, 16)
}

fn iso_interval(r: &mut Reader<'_>, out: &mut Out) -> Result<u16> {
    interval("ISO Interval", r, out, 1250)
}

/// Five-byte Codec_ID: coding format, company ID and vendor codec ID.
fn codec_id(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    enum8("Coding Format", r, out, CODING_FORMATS)?;
    manufacturer("Company Codec ID", r, out)?;
    u16_field("Vendor Codec ID", r, out)?;
    Ok(())
}

/// Subrate factor, latency, continuation number and supervision timeout shared by the
/// subrating and connection rate commands.
fn subrate_params(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    u16_hex("Subrate min", r, out)?;
    u16_hex("Subrate max", r, out)?;
    u16_hex("Max latency", r, out)?;
    u16_hex("Continuation number", r, out)?;
    timeout_ms("Supervision timeout", r, out, 10)?;
    Ok(())
}

/// Connection rate parameters (intervals and CE lengths in 125 µs units around the subrate parameters).
fn rate_params(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    interval("Min connection interval", r, out, 125)?;
    interval("Max connection interval", r, out, 125)?;
    subrate_params(r, out)?;
    interval("Min connection length", r, out, 125)?;
    interval("Max connection length", r, out, 125)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Isochronous channels
// ---------------------------------------------------------------------------

fn set_cig_parameters(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    cig_id(r, out)?;
    usec24("Central to Peripheral SDU Interval", r, out)?;
    usec24("Peripheral to Central SDU Interval", r, out)?;
    sca(r, out)?;
    packing(r, out)?;
    framing(r, out)?;
    ms16("Central to Peripheral Maximum Latency", r, out)?;
    ms16("Peripheral to Central Maximum Latency", r, out)?;
    let n = u8_field("Number of CIS", r, out)?;
    for _ in 0..n {
        u8_hex("CIS ID", r, out)?;
        out.nest(|o| -> Result<()> {
            u16_field("Central to Peripheral Maximum SDU Size", r, o)?;
            u16_field("Peripheral to Central Maximum SDU Size", r, o)?;
            phy_mask("Central to Peripheral PHY", r, o)?;
            phy_mask("Peripheral to Central PHY", r, o)?;
            u8_hex("Central to Peripheral Retransmission attempts", r, o)?;
            u8_hex("Peripheral to Central Retransmission attempts", r, o)?;
            Ok(())
        })?;
    }
    Ok(())
}

fn set_cig_parameters_test(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    cig_id(r, out)?;
    usec24("Central to Peripheral SDU Interval", r, out)?;
    usec24("Peripheral to Central SDU Interval", r, out)?;
    u8_hex("Central to Peripheral Flush Timeout", r, out)?;
    u8_hex("Peripheral to Central Flush Timeout", r, out)?;
    iso_interval(r, out)?;
    sca(r, out)?;
    packing(r, out)?;
    framing(r, out)?;
    let n = u8_field("Number of CIS", r, out)?;
    for _ in 0..n {
        u8_hex("CIS ID", r, out)?;
        out.nest(|o| -> Result<()> {
            u8_field("Number of Subevents", r, o)?;
            u16_field("Central to Peripheral Maximum SDU", r, o)?;
            u16_field("Peripheral to Central Maximum SDU", r, o)?;
            u16_field("Central to Peripheral Maximum PDU", r, o)?;
            u16_field("Peripheral to Central Maximum PDU", r, o)?;
            phy_mask("Central to Peripheral PHY", r, o)?;
            phy_mask("Peripheral to Central PHY", r, o)?;
            u8_field("Central to Peripheral Burst Number", r, o)?;
            u8_field("Peripheral to Central Burst Number", r, o)?;
            Ok(())
        })?;
    }
    Ok(())
}

fn create_cis(st: &IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let n = u8_field("Number of CIS", r, out)?;
    for _ in 0..n {
        handle_labelled("CIS Handle", st, r, out)?;
        handle_labelled("ACL Handle", st, r, out)?;
    }
    Ok(())
}

fn create_big(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    big_handle(r, out)?;
    u8_hex("Advertising Handle", r, out)?;
    u8_field("Number of BIS", r, out)?;
    usec24("SDU Interval", r, out)?;
    u16_field("Maximum SDU size", r, out)?;
    ms16("Maximum Latency", r, out)?;
    u8_hex("RTN", r, out)?;
    phy_mask("PHY", r, out)?;
    packing(r, out)?;
    framing(r, out)?;
    encryption(r, out)?;
    broadcast_code(r, out)?;
    Ok(())
}

fn create_big_test(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    big_handle(r, out)?;
    u8_hex("Advertising Handle", r, out)?;
    u8_field("Number of BIS", r, out)?;
    usec24("SDU Interval", r, out)?;
    iso_interval(r, out)?;
    u8_field("Number of Subevents", r, out)?;
    u16_field("Maximum SDU", r, out)?;
    u16_field("Maximum PDU", r, out)?;
    phy_mask("PHY", r, out)?;
    packing(r, out)?;
    framing(r, out)?;
    u8_field("Burst Number", r, out)?;
    u8_field("Immediate Repetition Count", r, out)?;
    u8_hex("Pre Transmission Offset", r, out)?;
    encryption(r, out)?;
    broadcast_code(r, out)?;
    Ok(())
}

fn big_create_sync(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    big_handle(r, out)?;
    let h = read_handle(r)?;
    field!(out, "BIG Sync Handle: 0x{:04x}", h);
    encryption(r, out)?;
    broadcast_code(r, out)?;
    let mse = r.u8()?;
    match mse {
        0 => field!(out, "Maximum Number Subevents: No limit (0x00)"),
        _ => field!(out, "Maximum Number Subevents: {} (0x{:02x})", mse, mse),
    };
    timeout_ms("Timeout", r, out, 10)?;
    let n = u8_field("Number of BIS", r, out)?;
    for _ in 0..n {
        u8_hex("BIS ID", r, out)?;
    }
    Ok(())
}

fn setup_iso_data_path(st: &IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    handle(st, r, out)?;
    enum8("Data Path Direction", r, out, &[(0x00, "Input (Host to Controller)"), (0x01, "Output (Controller to Host)")])?;
    let id = r.u8()?;
    match id {
        0x00 => field!(out, "Data Path ID: HCI (0x00)"),
        0xff => out.unknown("Data Path ID: Reserved (0xff)"),
        _ => field!(out, "Data Path ID: Logical Channel Number {} (0x{:02x})", id, id),
    };
    codec_id(r, out)?;
    usec24("Controller Delay", r, out)?;
    let len = u8_field("Codec Configuration Length", r, out)? as usize;
    out.hex_field("Codec Configuration", r.bytes(len)?);
    Ok(())
}

// ---------------------------------------------------------------------------
// Host features
// ---------------------------------------------------------------------------

/// Print the name of an LE feature bit (page 0 bits 0..63, page 1 bits 64..255, ...).
fn feature_bit_name(out: &mut Out, bit: u16) {
    let found = if bit < 64 {
        LE_FEATURES.iter().find(|(b, _)| *b as u16 == bit).map(|(_, n)| *n)
    } else if bit < 128 {
        LE_FEATURES_PAGE1.iter().find(|(b, _)| *b as u16 == bit - 64).map(|(_, n)| *n)
    } else {
        None
    };
    match found {
        Some(n) => out.line(n),
        None if bit < 64 => out.unknown(format!("Unknown feature bit {bit}")),
        None => {
            let page = (bit - 64) / 192 + 1;
            out.unknown(format!("Unknown feature bit {} (page {} bit {})", bit, page, (bit - 64) % 192))
        }
    };
}

fn set_host_feature(r: &mut Reader<'_>, out: &mut Out, v2: bool) -> Result<()> {
    let bit = if v2 { r.u16()? } else { r.u8()? as u16 };
    field!(out, "Bit Number: {}", bit);
    out.nest(|o| feature_bit_name(o, bit));
    enable("Bit Value", r, out)?;
    Ok(())
}

/// A 24-octet LE feature page (pages 1 and above of the extended feature set).
fn le_features_page(label: &str, out: &mut Out, page: u8, b: &[u8]) {
    let hex: Vec<String> = b.iter().map(|x| format!("0x{x:02x}")).collect();
    field!(out, "{}: {}", label, hex.join(" "));
    out.nest(|o| {
        for (i, byte) in b.iter().enumerate() {
            for bit in 0..8u16 {
                if byte & (1 << bit) == 0 {
                    continue;
                }
                let n = i as u16 * 8 + bit;
                if page == 1 {
                    feature_bit_name(o, n + 64);
                } else {
                    o.unknown(format!("Unknown feature bit (page {page} bit {n})"));
                }
            }
        }
    });
}

fn read_all_local_supported_features_rsp(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    if status_only(r, out)? {
        return Ok(());
    }
    let max_page = u8_field("Max page", r, out)?;
    le_features("Features", r, out, 0)?;
    // Pages 1..=10 are 24 octets each; show the ones the controller reports as
    // used, plus any later page that unexpectedly has bits set.
    let mut page = 1u8;
    while page <= 10 && r.remaining() >= 24 {
        let b = r.bytes(24)?;
        if page <= max_page || b.iter().any(|&x| x != 0) {
            le_features_page(&format!("Features (page {page})"), out, page, b);
        }
        page += 1;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Power control, test and address commands
// ---------------------------------------------------------------------------

fn set_path_loss_reporting_parameters(st: &IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    handle(st, r, out)?;
    let high = r.u8()?;
    match high {
        0xff => field!(out, "High threshold: Unused (0xff)"),
        _ => field!(out, "High threshold: {} dB (0x{:02x})", high, high),
    };
    let v = r.u8()?;
    field!(out, "High hysteresis: {} dB (0x{:02x})", v, v);
    let v = r.u8()?;
    field!(out, "Low threshold: {} dB (0x{:02x})", v, v);
    let v = r.u8()?;
    field!(out, "Low hysteresis: {} dB (0x{:02x})", v, v);
    let t = r.u16()?;
    field!(out, "Min time spent: {} connection events (0x{:04x})", t, t);
    Ok(())
}

static TEST_PAYLOADS: &[(u8, &str)] = &[
    (0x00, "PRBS9"),
    (0x01, "Repeated 11110000"),
    (0x02, "Repeated 10101010"),
    (0x03, "PRBS15"),
    (0x04, "Repeated 11111111"),
    (0x05, "Repeated 00000000"),
    (0x06, "Repeated 00001111"),
    (0x07, "Repeated 01010101"),
    (0x80, "User payload"),
];

fn transmitter_test_v4(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let ch = r.u8()?;
    field!(out, "TX channel: {} MHz (0x{:02x})", ch as u32 * 2 + 2402, ch);
    u8_field("Length of test data", r, out)?;
    enum8("Packet payload", r, out, &TEST_PAYLOADS[..8])?;
    phy_coded("PHY", r, out)?;
    let cte = r.u8()?;
    match cte {
        0 => field!(out, "CTE length: No CTE (0x00)"),
        _ => field!(out, "CTE length: {} us (0x{:02x})", cte as u32 * 8, cte),
    };
    enum8("CTE type", r, out, &[(0x00, "AoA"), (0x01, "AoD with 1 us slots"), (0x02, "AoD with 2 us slots")])?;
    let n = u8_field("Switching pattern length", r, out)?;
    for _ in 0..n {
        u8_field("Antenna ID", r, out)?;
    }
    let p = r.i8()?;
    match p {
        126 => field!(out, "TX power: Minimum (0x7e)"),
        127 => field!(out, "TX power: Maximum (0x7f)"),
        _ => field!(out, "TX power: {} dbm (0x{:02x})", p, p as u8),
    };
    Ok(())
}

// ---------------------------------------------------------------------------
// Extended advertising, connections and periodic advertising with responses
// ---------------------------------------------------------------------------

fn phy_options(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    enum8(
        label,
        r,
        out,
        &[
            (0x00, "No preference"),
            (0x01, "Prefer S=2 coding"),
            (0x02, "Prefer S=8 coding"),
            (0x03, "Require S=2 coding"),
            (0x04, "Require S=8 coding"),
        ],
    )
}

fn set_ext_adv_params_v2(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    u8_hex("Handle", r, out)?;
    ext_adv_properties(r, out)?;
    slots24("Min advertising interval", r, out)?;
    slots24("Max advertising interval", r, out)?;
    adv_channel_map(r, out)?;
    own_addr_type(r, out)?;
    peer_addr_labelled("Peer address type", "Peer address", r, out)?;
    adv_filter_policy(r, out)?;
    tx_power("TX power", r, out)?;
    enum8("Primary PHY", r, out, &[(0x01, "LE 1M"), (0x03, "LE Coded")])?;
    u8_hex("Secondary max skip", r, out)?;
    phy("Secondary PHY", r, out)?;
    u8_hex("SID", r, out)?;
    enable("Scan request notifications", r, out)?;
    phy_options("Primary PHY options", r, out)?;
    phy_options("Secondary PHY options", r, out)?;
    Ok(())
}

fn ext_create_connection_v2(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let h = r.u8()?;
    match h {
        0xff => field!(out, "Advertising handle: Not used (0xff)"),
        _ => field!(out, "Advertising handle: 0x{:02x}", h),
    };
    let s = r.u8()?;
    match s {
        0xff => field!(out, "Subevent: Not used (0xff)"),
        _ => field!(out, "Subevent: 0x{:02x}", s),
    };
    enum8(
        "Filter policy",
        r,
        out,
        &[
            (0x00, "Accept list is not used"),
            (0x01, "Accept list is used"),
            (0x02, "Accept list is not used, decision PDUs only"),
            (0x03, "Accept list is used, all PDUs processed"),
            (0x04, "All decision PDUs, accept list for other PDUs"),
        ],
    )?;
    own_addr_type(r, out)?;
    peer_addr_labelled("Peer address type", "Peer address", r, out)?;
    let phys = r.u8()?;
    field!(out, "Initiating PHYs: 0x{:02x}", phys);
    let mut n = 0;
    for (bit, name) in [(0u8, "LE 1M"), (1, "LE 2M"), (2, "LE Coded")] {
        if phys & (1 << bit) == 0 {
            continue;
        }
        out.group(format!("Entry {n}: {name}"), |o| -> Result<()> {
            slots("Scan interval", r, o)?;
            slots("Scan window", r, o)?;
            conn_params(r, o)
        })?;
        n += 1;
    }
    if phys & !0x07 != 0 {
        out.unknown(format!("Unknown initiating PHYs (0x{:02x})", phys & !0x07));
    }
    Ok(())
}

fn pa_properties(r: &mut Reader<'_>, out: &mut Out) -> Result<u16> {
    mask16("Properties", r, out, &[(6, "Include TxPower")], 16)
}

fn set_pa_params_v2(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    u8_hex("Handle", r, out)?;
    interval("Min interval", r, out, 1250)?;
    interval("Max interval", r, out, 1250)?;
    pa_properties(r, out)?;
    let n = r.u8()?;
    match n {
        0 => field!(out, "Number of subevents: Periodic Advertising without responses (0x00)"),
        _ => field!(out, "Number of subevents: {}", n),
    };
    let v = r.u8()?;
    interval_value("Subevent interval", out, v as u32, 1250, 2);
    let v = r.u8()?;
    interval_value("Response slot delay", out, v as u32, 1250, 2);
    let v = r.u8()?;
    interval_value("Response slot spacing", out, v as u32, 125, 2);
    u8_field("Number of response slots", r, out)?;
    Ok(())
}

fn set_pa_subevent_data(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    u8_hex("Handle", r, out)?;
    let n = u8_field("Number of subevents", r, out)?;
    for i in 0..n {
        out.group(format!("Entry {i}"), |o| -> Result<()> {
            u8_hex("Subevent", r, o)?;
            u8_field("Response slot start", r, o)?;
            u8_field("Response slot count", r, o)?;
            let len = u8_field("Data length", r, o)? as usize;
            o.hex_field("Data", r.bytes(len)?);
            Ok(())
        })?;
    }
    Ok(())
}

fn set_pa_response_data(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    sync_handle(r, out)?;
    u16_hex("Request event", r, out)?;
    u8_hex("Request subevent", r, out)?;
    u8_hex("Response subevent", r, out)?;
    u8_hex("Response slot", r, out)?;
    let len = u8_field("Data length", r, out)? as usize;
    out.hex_field("Data", r.bytes(len)?);
    Ok(())
}

fn set_periodic_sync_subevent(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    sync_handle(r, out)?;
    pa_properties(r, out)?;
    let n = u8_field("Number of subevents", r, out)?;
    out.nest(|o| -> Result<()> {
        for _ in 0..n {
            u8_hex("Subevent", r, o)?;
        }
        Ok(())
    })?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Decision-based advertising filtering
// ---------------------------------------------------------------------------

fn set_decision_data(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    u8_hex("Handle", r, out)?;
    mask8("Decision type flags", r, out, &[(0, "Resolvable Tag present")], 8)?;
    let len = u8_field("Data length", r, out)? as usize;
    out.hex_field("Data", r.bytes(len)?);
    Ok(())
}

fn decision_test_field(out: &mut Out, f: u8) {
    let text = match f {
        0 => "Resolvable Tag".to_string(),
        6 => "AdvMode".to_string(),
        7 => "RSSI".to_string(),
        8 => "Path loss".to_string(),
        9 => "AdvA".to_string(),
        17..=24 => format!("Arbitrary Data of exactly {} octets", f - 16),
        33..=40 => format!("Arbitrary Data of at least {} octets", f - 32),
        49..=56 => format!("Arbitrary Data of 1 to {} octets", f - 48),
        240..=255 => "Vendor-specific".to_string(),
        _ => {
            out.unknown(format!("Field: Reserved (0x{f:02x})"));
            return;
        }
    };
    field!(out, "Field: {} (0x{:02x})", text, f);
}

fn set_decision_instructions(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let n = u8_field("Number of tests", r, out)?;
    for i in 0..n {
        out.group(format!("Test {i}"), |o| -> Result<()> {
            mask8(
                "Flags",
                r,
                o,
                &[
                    (0, "Start of new test group"),
                    (1, "Pass if field present and check passes"),
                    (2, "Pass if field present and check fails"),
                    (3, "Pass if field not present"),
                ],
                8,
            )?;
            let f = r.u8()?;
            decision_test_field(o, f);
            hex_bytes("Parameters", r, o, 16)?;
            Ok(())
        })?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Channel Sounding
// ---------------------------------------------------------------------------

static CS_NADM: &[(u8, &str)] = &[(0, "Phase-based NADM"), (1, "Amplitude-based NADM")];

fn cs_rtt_n(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    let v = r.u8()?;
    match v {
        0 => field!(out, "{}: Not supported (0x00)", label),
        _ => field!(out, "{}: {}", label, v),
    };
    Ok(v)
}

/// Capability fields shared by LE CS Read Local Supported Capabilities (return) and
/// LE CS Write Cached Remote Supported Capabilities (command); the [v2] variants add
/// five trailing fields which are decoded when present.
fn cs_capabilities(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    u8_field("Num config supported", r, out)?;
    let n = r.u16()?;
    match n {
        0 => field!(out, "Max consecutive procedures supported: Fixed or indefinite (0x0000)"),
        _ => field!(out, "Max consecutive procedures supported: {} (0x{:04x})", n, n),
    };
    u8_field("Num antennas supported", r, out)?;
    u8_field("Max antenna paths supported", r, out)?;
    mask8("Roles supported", r, out, CS_ROLES, 8)?;
    mask8("Modes supported", r, out, &[(0, "Mode-3")], 8)?;
    mask8(
        "RTT capability",
        r,
        out,
        &[
            (0, "RTT AA-only: 10 ns accuracy"),
            (1, "RTT sounding: 10 ns accuracy"),
            (2, "RTT random sequence: 10 ns accuracy"),
            (3, "RTT 2M AA-only: 10 ns accuracy"),
            (4, "RTT 2M sounding: 10 ns accuracy"),
            (5, "RTT 2M random sequence: 10 ns accuracy"),
        ],
        8,
    )?;
    cs_rtt_n("RTT AA only N", r, out)?;
    cs_rtt_n("RTT sounding N", r, out)?;
    cs_rtt_n("RTT random sequence N", r, out)?;
    mask16("NADM sounding capability", r, out, CS_NADM, 16)?;
    mask16("NADM random capability", r, out, CS_NADM, 16)?;
    mask8("CS_SYNC PHYs supported", r, out, &[(1, "LE 2M"), (2, "LE 2M 2BT")], 8)?;
    mask16(
        "Subfeatures supported",
        r,
        out,
        &[
            (1, "CS with no transmitter Frequency Actuation Error"),
            (2, "CS Channel Selection Algorithm #3c"),
            (3, "CS phase-based ranging from RTT sounding sequence"),
            (4, "IPT in the CS reflector"),
            (5, "CS RTT accuracy specified per PHY"),
        ],
        16,
    )?;
    mask16("T_IP1 times supported", r, out, CS_T_IP_TIMES, 16)?;
    mask16("T_IP2 times supported", r, out, CS_T_IP_TIMES, 16)?;
    mask16("T_FCS times supported", r, out, CS_T_FCS_TIMES, 16)?;
    mask16("T_PM times supported", r, out, CS_T_PM_TIMES, 16)?;
    cs_t_sw_time("T_SW time supported", r, out)?;
    mask8("TX_SNR capability", r, out, CS_TX_SNR, 8)?;
    if r.is_empty() {
        return Ok(());
    }
    mask16("T_IP2 IPT times supported", r, out, CS_T_IP_TIMES, 16)?;
    cs_t_sw_time("T_SW IPT time supported", r, out)?;
    cs_rtt_n("RTT 2M AA only N", r, out)?;
    cs_rtt_n("RTT 2M sounding N", r, out)?;
    cs_rtt_n("RTT 2M random sequence N", r, out)?;
    Ok(())
}

fn cs_set_default_settings(st: &IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    handle(st, r, out)?;
    mask8("Role enable", r, out, CS_ROLES, 8)?;
    let a = r.u8()?;
    match a {
        0x01..=0x04 => field!(out, "CS_SYNC antenna selection: Antenna {} (0x{:02x})", a, a),
        0xfd => field!(out, "CS_SYNC antenna selection: Repetitive, each antenna twice (0xfd)"),
        0xfe => field!(out, "CS_SYNC antenna selection: Repetitive (0xfe)"),
        0xff => field!(out, "CS_SYNC antenna selection: No recommendation (0xff)"),
        _ => out.unknown(format!("CS_SYNC antenna selection: Reserved (0x{a:02x})")),
    };
    power_dbm("Max TX power", r, out)?;
    Ok(())
}

fn cs_mode(label: &str, r: &mut Reader<'_>, out: &mut Out, allow_unused: bool) -> Result<u8> {
    let v = r.u8()?;
    match v {
        0x01..=0x03 => field!(out, "{}: Mode-{} (0x{:02x})", label, v, v),
        0xff if allow_unused => field!(out, "{}: Unused (0xff)", label),
        _ => out.unknown(format!("{label}: Reserved (0x{v:02x})")),
    };
    Ok(v)
}

fn cs_role(r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    enum8("Role", r, out, &[(0x00, "Initiator"), (0x01, "Reflector")])
}

fn cs_rtt_type(r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    enum8(
        "RTT type",
        r,
        out,
        &[
            (0x00, "RTT AA-only"),
            (0x01, "RTT with 32-bit sounding sequence"),
            (0x02, "RTT with 96-bit sounding sequence"),
            (0x03, "RTT with 32-bit random sequence"),
            (0x04, "RTT with 64-bit random sequence"),
            (0x05, "RTT with 96-bit random sequence"),
            (0x06, "RTT with 128-bit random sequence"),
        ],
    )
}

fn cs_sync_phy(r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    enum8("CS_SYNC PHY", r, out, &[(0x01, "LE 1M"), (0x02, "LE 2M"), (0x03, "LE 2M 2BT")])
}

fn cs_channel_selection_type(r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    enum8(
        "Channel selection type",
        r,
        out,
        &[(0x00, "Channel Selection Algorithm #3b"), (0x01, "Channel Selection Algorithm #3c")],
    )
}

fn cs_ch3c_shape(r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    enum8("Ch3c shape", r, out, &[(0x00, "Hat shape"), (0x01, "X shape")])
}

fn cs_snr_control(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    enum8(
        label,
        r,
        out,
        &[(0x00, "18 dB"), (0x01, "21 dB"), (0x02, "24 dB"), (0x03, "27 dB"), (0x04, "30 dB"), (0xff, "Not applied")],
    )
}

fn cs_enhancements(r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    mask8("CS enhancements", r, out, &[(0, "IPT enabled in the CS reflector")], 8)
}

fn cs_create_config(st: &IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    handle(st, r, out)?;
    u8_field("Config ID", r, out)?;
    enum8("Create context", r, out, &[(0x00, "Local Controller only"), (0x01, "Local and remote Controller")])?;
    cs_mode("Main mode type", r, out, false)?;
    cs_mode("Sub mode type", r, out, true)?;
    u8_field("Min main mode steps", r, out)?;
    u8_field("Max main mode steps", r, out)?;
    u8_field("Main mode repetition", r, out)?;
    u8_field("Mode 0 steps", r, out)?;
    cs_role(r, out)?;
    cs_rtt_type(r, out)?;
    cs_sync_phy(r, out)?;
    hex_bytes("Channel map", r, out, 10)?;
    u8_field("Channel map repetition", r, out)?;
    cs_channel_selection_type(r, out)?;
    cs_ch3c_shape(r, out)?;
    u8_field("Ch3c jump", r, out)?;
    cs_enhancements(r, out)?;
    Ok(())
}

fn cs_set_procedure_parameters(st: &IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    handle(st, r, out)?;
    u8_field("Config ID", r, out)?;
    slots("Max procedure length", r, out)?;
    let v = r.u16()?;
    field!(out, "Min procedure interval: {} connection events (0x{:04x})", v, v);
    let v = r.u16()?;
    field!(out, "Max procedure interval: {} connection events (0x{:04x})", v, v);
    let v = r.u16()?;
    match v {
        0 => field!(out, "Max procedure count: Until disabled (0x0000)"),
        _ => field!(out, "Max procedure count: {} (0x{:04x})", v, v),
    };
    usec24("Min subevent length", r, out)?;
    usec24("Max subevent length", r, out)?;
    u8_field("Tone antenna config selection", r, out)?;
    phy_coded("PHY", r, out)?;
    let d = r.i8()?;
    match d as u8 {
        0x80 => field!(out, "TX power delta: No recommendation (0x80)"),
        _ => field!(out, "TX power delta: {} dB (0x{:02x})", d, d as u8),
    };
    mask8(
        "Preferred peer antenna",
        r,
        out,
        &[
            (0, "First ordered antenna element"),
            (1, "Second ordered antenna element"),
            (2, "Third ordered antenna element"),
            (3, "Fourth ordered antenna element"),
        ],
        8,
    )?;
    cs_snr_control("SNR control initiator", r, out)?;
    cs_snr_control("SNR control reflector", r, out)?;
    Ok(())
}

fn cs_time_us(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    let v = r.u8()?;
    field!(out, "{}: {} us (0x{:02x})", label, v, v);
    Ok(v)
}

static CS_OVERRIDE_CONFIG: &[(u8, &str)] = &[
    (0, "Channel list overrides channel map"),
    (2, "Main mode steps override"),
    (3, "T_PM tone extension override"),
    (4, "Antenna path permutation index override"),
    (5, "CS_SYNC access address override"),
    (6, "Sounding sequence marker position override"),
    (7, "Sounding sequence marker value override"),
    (8, "CS_SYNC payload override"),
    (10, "Stable Phase test"),
];

/// The variable Override_Parameters_Data of LE CS Test, whose contents depend on Override_Config.
fn cs_override_parameters(r: &mut Reader<'_>, out: &mut Out, config: u16) -> Result<()> {
    if config & (1 << 0) != 0 {
        let n = u8_field("Channel length", r, out)?;
        out.hex_field("Channels", r.bytes(n as usize)?);
    } else {
        hex_bytes("Channel map", r, out, 10)?;
        cs_channel_selection_type(r, out)?;
        cs_ch3c_shape(r, out)?;
        u8_field("Ch3c jump", r, out)?;
    }
    if config & (1 << 2) != 0 {
        u8_field("Main mode steps", r, out)?;
    }
    if config & (1 << 3) != 0 {
        enum8(
            "T_PM tone extension",
            r,
            out,
            &[
                (0x00, "Neither"),
                (0x01, "Initiator only"),
                (0x02, "Reflector only"),
                (0x03, "Both"),
                (0x04, "Loop through all"),
            ],
        )?;
    }
    if config & (1 << 4) != 0 {
        let v = r.u8()?;
        match v {
            0xff => field!(out, "Antenna path permutation index: Loop through all (0xff)"),
            _ => field!(out, "Antenna path permutation index: {} (0x{:02x})", v, v),
        };
    }
    if config & (1 << 5) != 0 {
        u32_hex("CS_SYNC access address initiator", r, out)?;
        u32_hex("CS_SYNC access address reflector", r, out)?;
    }
    if config & (1 << 6) != 0 {
        u8_field("SS marker 1 position", r, out)?;
        let v = r.u8()?;
        match v {
            0xff => field!(out, "SS marker 2 position: Not present (0xff)"),
            _ => field!(out, "SS marker 2 position: {}", v),
        };
    }
    if config & (1 << 7) != 0 {
        enum8("SS marker value", r, out, &[(0x00, "0011"), (0x01, "1100"), (0x02, "Loop through 0011 and 1100")])?;
    }
    if config & (1 << 8) != 0 {
        enum8("CS_SYNC payload pattern", r, out, TEST_PAYLOADS)?;
        hex_bytes("CS_SYNC user payload", r, out, 16)?;
    }
    Ok(())
}

fn cs_test(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    cs_mode("Main mode type", r, out, false)?;
    cs_mode("Sub mode type", r, out, true)?;
    u8_field("Main mode repetition", r, out)?;
    u8_field("Mode 0 steps", r, out)?;
    cs_role(r, out)?;
    cs_rtt_type(r, out)?;
    cs_sync_phy(r, out)?;
    u8_field("CS_SYNC antenna selection", r, out)?;
    usec24("Subevent length", r, out)?;
    let v = r.u16()?;
    if v == 0 {
        field!(out, "Subevent interval: Single CS subevent (0x0000)");
    } else {
        interval_value("Subevent interval", out, v as u32, 625, 4);
    }
    let v = r.u8()?;
    match v {
        0 => field!(out, "Max number of subevents: No restriction (0x00)"),
        _ => field!(out, "Max number of subevents: {}", v),
    };
    let p = r.i8()?;
    match p {
        126 => field!(out, "TX power: Minimum (0x7e)"),
        127 => field!(out, "TX power: Maximum (0x7f)"),
        _ => field!(out, "TX power: {} dbm (0x{:02x})", p, p as u8),
    };
    cs_time_us("T_IP1 time", r, out)?;
    cs_time_us("T_IP2 time", r, out)?;
    cs_time_us("T_FCS time", r, out)?;
    cs_time_us("T_PM time", r, out)?;
    cs_t_sw_time("T_SW time", r, out)?;
    u8_field("Tone antenna config selection", r, out)?;
    cs_enhancements(r, out)?;
    cs_snr_control("SNR control initiator", r, out)?;
    cs_snr_control("SNR control reflector", r, out)?;
    let v = r.u16()?;
    field!(out, "DRBG nonce: 0x{:04x}", v);
    u8_field("Channel map repetition", r, out)?;
    let config = mask16("Override config", r, out, CS_OVERRIDE_CONFIG, 16)?;
    let len = u8_field("Override parameters length", r, out)? as usize;
    let mut sub = r.sub(len)?;
    out.line("Override parameters");
    out.nest(|o| {
        if cs_override_parameters(&mut sub, o, config).is_err() {
            o.error("Override parameters truncated");
        } else if !sub.is_empty() {
            o.error(format!("Unexpected trailing override data ({} bytes)", sub.remaining()));
        }
        if !sub.is_empty() {
            o.hex(sub.rest());
        }
    });
    Ok(())
}

// ---------------------------------------------------------------------------
// Frame space, connection rate and event mask
// ---------------------------------------------------------------------------

fn frame_space_update(st: &IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    handle(st, r, out)?;
    usec16("Frame space min", r, out)?;
    usec16("Frame space max", r, out)?;
    phy_mask("PHYs", r, out)?;
    mask16(
        "Spacing types",
        r,
        out,
        &[(0, "T_IFS_ACL_CP"), (1, "T_IFS_ACL_PC"), (2, "T_MCES"), (3, "T_IFS_CIS"), (4, "T_MSS_CIS")],
        16,
    )?;
    Ok(())
}

fn read_min_supported_conn_interval_rsp(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    if status_only(r, out)? {
        return Ok(());
    }
    let v = r.u8()?;
    interval_value("Minimum supported connection interval", out, v as u32, 125, 2);
    let n = u8_field("Number of groups", r, out)?;
    for i in 0..n {
        out.group(format!("Group {i}"), |o| -> Result<()> {
            interval("Min interval", r, o, 125)?;
            interval("Max interval", r, o, 125)?;
            interval("Stride", r, o, 125)?;
            Ok(())
        })?;
    }
    Ok(())
}

/// LE event mask bit names (LE Set Event Mask, Core Specification Vol 4, Part E, Section 7.8.1).
static LE_EVENT_MASK_BITS: &[(u8, &str)] = &[
    (0, "LE Connection Complete"),
    (1, "LE Advertising Report"),
    (2, "LE Connection Update Complete"),
    (3, "LE Read Remote Features Page 0 Complete"),
    (4, "LE Long Term Key Request"),
    (5, "LE Remote Connection Parameter Request"),
    (6, "LE Data Length Change"),
    (7, "LE Read Local P-256 Public Key Complete"),
    (8, "LE Generate DHKey Complete"),
    (9, "LE Enhanced Connection Complete"),
    (10, "LE Directed Advertising Report"),
    (11, "LE PHY Update Complete"),
    (12, "LE Extended Advertising Report"),
    (13, "LE Periodic Advertising Sync Established"),
    (14, "LE Periodic Advertising Report"),
    (15, "LE Periodic Advertising Sync Lost"),
    (16, "LE Scan Timeout"),
    (17, "LE Advertising Set Terminated"),
    (18, "LE Scan Request Received"),
    (19, "LE Channel Selection Algorithm"),
    (20, "LE Connectionless IQ Report"),
    (21, "LE Connection IQ Report"),
    (22, "LE CTE Request Failed"),
    (23, "LE Periodic Advertising Sync Transfer Received"),
    (24, "LE CIS Established"),
    (25, "LE CIS Request"),
    (26, "LE Create BIG Complete"),
    (27, "LE Terminate BIG Complete"),
    (28, "LE BIG Sync Established"),
    (29, "LE BIG Sync Lost"),
    (30, "LE Request Peer SCA Complete"),
    (31, "LE Path Loss Threshold"),
    (32, "LE Transmit Power Reporting"),
    (33, "LE BIGInfo Advertising Report"),
    (34, "LE Subrate Change"),
    (35, "LE Periodic Advertising Sync Established v2"),
    (36, "LE Periodic Advertising Report v2"),
    (37, "LE Periodic Advertising Sync Transfer Received v2"),
    (38, "LE Periodic Advertising Subevent Data Request"),
    (39, "LE Periodic Advertising Response Report"),
    (40, "LE Enhanced Connection Complete v2"),
    (41, "LE CIS Established v2"),
    (42, "LE Read All Remote Features Complete"),
    (43, "LE CS Read Remote Supported Capabilities Complete"),
    (44, "LE CS Read Remote FAE Table Complete"),
    (45, "LE CS Security Enable Complete"),
    (46, "LE CS Config Complete"),
    (47, "LE CS Procedure Enable Complete"),
    (48, "LE CS Subevent Result"),
    (49, "LE CS Subevent Result Continue"),
    (50, "LE CS Test End Complete"),
    (51, "LE Monitored Advertisers Report"),
    (52, "LE Frame Space Update Complete"),
    (53, "LE UTP Receive"),
    (54, "LE Connection Rate Change"),
    (55, "LE CS Read Remote Supported Capabilities Complete v2"),
];

/// LE Set Event Mask [v2]: the first eight octets carry the bits defined so far, the
/// remaining octets (up to 255 in total) are reserved.
fn le_event_mask_v2(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let b = r.array::<8>()?;
    let mask = u64::from_le_bytes(b);
    let hex: Vec<String> = b.iter().map(|x| format!("0x{x:02x}")).collect();
    field!(out, "Mask: {}", hex.join(" "));
    out.nest(|o| bits(o, mask, LE_EVENT_MASK_BITS, 64));
    let rest = r.rest();
    if rest.is_empty() {
        return Ok(());
    }
    if rest.iter().all(|&x| x == 0) {
        field!(out, "Mask (bits 64 and above): {} octets, none set", rest.len());
        return Ok(());
    }
    out.hex_field("Mask (bits 64 and above)", rest);
    out.nest(|o| {
        for (i, byte) in rest.iter().enumerate() {
            for bit in 0..8 {
                if byte & (1 << bit) != 0 {
                    o.unknown(format!("Unknown bit {}", 64 + i * 8 + bit));
                }
            }
        }
    });
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{Connection, LinkType};
    use crate::reader::BdAddr;
    use crate::tree::render_lines;

    /// Run a command parameter decoder and return the rendered tree (two spaces per level).
    fn cmd_lines(st: &mut IndexState, opcode: u16, data: &[u8]) -> Vec<String> {
        let mut out = Out::new();
        let mut r = Reader::new(data);
        assert!(command_params(st, opcode, &mut r, &mut out).unwrap(), "opcode 0x{opcode:04x} not handled");
        assert!(r.is_empty(), "{} trailing bytes for 0x{opcode:04x}", r.remaining());
        render(&out)
    }

    fn rsp_lines(st: &mut IndexState, opcode: u16, data: &[u8]) -> Vec<String> {
        let mut out = Out::new();
        let mut r = Reader::new(data);
        assert!(return_params(st, opcode, &mut r, &mut out).unwrap(), "opcode 0x{opcode:04x} not handled");
        assert!(r.is_empty(), "{} trailing bytes for 0x{opcode:04x}", r.remaining());
        render(&out)
    }

    fn render(out: &Out) -> Vec<String> {
        let mut lines = Vec::new();
        render_lines(out.roots(), 0, |indent, n| lines.push(format!("{}{}", " ".repeat(indent), n.text)));
        lines
    }

    #[test]
    fn unhandled_opcode() {
        let mut st = IndexState::default();
        let mut out = Out::new();
        let mut r = Reader::new(&[0x01]);
        assert!(!command_params(&mut st, cmd::LE_SET_SCAN_ENABLE, &mut r, &mut out).unwrap());
        assert!(!return_params(&mut st, cmd::LE_SET_SCAN_ENABLE, &mut r, &mut out).unwrap());
        assert!(out.is_empty());
    }

    #[test]
    fn set_cig_parameters_params() {
        let mut st = IndexState::default();
        let data = [
            0x00, // CIG ID
            0x10, 0x27, 0x00, // C->P SDU interval 10000 us
            0x10, 0x27, 0x00, // P->C SDU interval
            0x00, // SCA
            0x00, // packing
            0x00, // framing
            0x0a, 0x00, // C->P max latency 10 ms
            0x0a, 0x00, // P->C max latency
            0x01, // CIS count
            0x00, // CIS ID
            0x28, 0x00, // C->P max SDU 40
            0x00, 0x00, // P->C max SDU 0
            0x02, // C->P PHY
            0x02, // P->C PHY
            0x02, // C->P RTN
            0x02, // P->C RTN
        ];
        let lines = cmd_lines(&mut st, cmd::LE_SET_CIG_PARAMETERS, &data);
        assert_eq!(
            lines,
            [
                "CIG ID: 0x00",
                "Central to Peripheral SDU Interval: 10000 us (0x002710)",
                "Peripheral to Central SDU Interval: 10000 us (0x002710)",
                "Worst Case SCA: 251 ppm to 500 ppm (0x00)",
                "Packing: Sequential (0x00)",
                "Framing: Unframed (0x00)",
                "Central to Peripheral Maximum Latency: 10 ms (0x000a)",
                "Peripheral to Central Maximum Latency: 10 ms (0x000a)",
                "Number of CIS: 1",
                "CIS ID: 0x00",
                "  Central to Peripheral Maximum SDU Size: 40",
                "  Peripheral to Central Maximum SDU Size: 0",
                "  Central to Peripheral PHY: 0x02",
                "    LE 2M",
                "  Peripheral to Central PHY: 0x02",
                "    LE 2M",
                "  Central to Peripheral Retransmission attempts: 0x02",
                "  Peripheral to Central Retransmission attempts: 0x02",
            ]
        );
    }

    #[test]
    fn set_cig_parameters_rsp() {
        let mut st = IndexState::default();
        let lines = rsp_lines(&mut st, cmd::LE_SET_CIG_PARAMETERS, &[0x00, 0x00, 0x02, 0x01, 0x00, 0x02, 0x00]);
        assert_eq!(
            lines,
            [
                "Status: Success (0x00)",
                "CIG ID: 0x00",
                "Number of Handles: 2",
                "Connection Handle #0: 1",
                "Connection Handle #1: 2",
            ]
        );
        assert_eq!(st.pending_iso, [1, 2]);
        // A failed command carries only the status.
        let lines = rsp_lines(&mut st, cmd::LE_SET_CIG_PARAMETERS, &[0x12]);
        assert_eq!(lines, ["Status: Invalid HCI Command Parameters (0x12)"]);
    }

    #[test]
    fn create_cis_params() {
        let mut st = IndexState::default();
        let mut c = Connection::new(0x0010, LinkType::Le);
        c.addr = BdAddr([0xd7, 0x2c, 0x9c, 0x70, 0xf3, 0x5c]);
        st.conns.insert(0x0010, c);
        let lines = cmd_lines(&mut st, cmd::LE_CREATE_CIS, &[0x01, 0x01, 0x00, 0x10, 0x00]);
        assert_eq!(
            lines,
            ["Number of CIS: 1", "CIS Handle: 1", "ACL Handle: 16 Address: 5C:F3:70:9C:2C:D7 (Public)"]
        );
    }

    #[test]
    fn create_big_params() {
        let mut st = IndexState::default();
        let mut data = vec![
            0x00, 0x01, 0x02, // BIG handle, adv handle, num BIS
            0x10, 0x27, 0x00, // SDU interval
            0x28, 0x00, // max SDU
            0x0a, 0x00, // max transport latency
            0x02, // RTN
            0x02, // PHY
            0x00, 0x00, // packing, framing
            0x01, // encryption
        ];
        data.extend_from_slice(&[0xaa; 16]);
        let lines = cmd_lines(&mut st, cmd::LE_CREATE_BIG, &data);
        assert_eq!(
            lines,
            [
                "BIG Handle: 0x00",
                "Advertising Handle: 0x01",
                "Number of BIS: 2",
                "SDU Interval: 10000 us (0x002710)",
                "Maximum SDU size: 40",
                "Maximum Latency: 10 ms (0x000a)",
                "RTN: 0x02",
                "PHY: 0x02",
                "  LE 2M",
                "Packing: Sequential (0x00)",
                "Framing: Unframed (0x00)",
                "Encryption: Encrypted (0x01)",
                "Broadcast Code: aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa aa",
            ]
        );
    }

    #[test]
    fn big_create_sync_params() {
        let mut st = IndexState::default();
        let mut data = vec![0x00, 0x02, 0x00, 0x00];
        data.extend_from_slice(&[0x00; 16]);
        data.extend_from_slice(&[0x00, 0x64, 0x00, 0x02, 0x01, 0x02]);
        let lines = cmd_lines(&mut st, cmd::LE_BIG_CREATE_SYNC, &data);
        assert_eq!(
            lines,
            [
                "BIG Handle: 0x00",
                "BIG Sync Handle: 0x0002",
                "Encryption: Unencrypted (0x00)",
                "Broadcast Code: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
                "Maximum Number Subevents: No limit (0x00)",
                "Timeout: 1000 msec (0x0064)",
                "Number of BIS: 2",
                "BIS ID: 0x01",
                "BIS ID: 0x02",
            ]
        );
    }

    #[test]
    fn setup_iso_data_path_params() {
        let mut st = IndexState::default();
        let data = [0x01, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x01, 0x02];
        let lines = cmd_lines(&mut st, cmd::LE_SETUP_ISO_DATA_PATH, &data);
        assert_eq!(
            lines,
            [
                "Handle: 1",
                "Data Path Direction: Input (Host to Controller) (0x00)",
                "Data Path ID: HCI (0x00)",
                "Coding Format: LC3 (0x06)",
                "Company Codec ID: Ericsson AB (0)",
                "Vendor Codec ID: 0",
                "Controller Delay: 0 us (0x000000)",
                "Codec Configuration Length: 2",
                "Codec Configuration: 01 02",
            ]
        );
        let lines = rsp_lines(&mut st, cmd::LE_SETUP_ISO_DATA_PATH, &[0x00, 0x01, 0x00]);
        assert_eq!(lines, ["Status: Success (0x00)", "Handle: 1"]);
    }

    #[test]
    fn remove_iso_data_path_params() {
        let mut st = IndexState::default();
        let lines = cmd_lines(&mut st, cmd::LE_REMOVE_ISO_DATA_PATH, &[0x01, 0x00, 0x03]);
        assert_eq!(
            lines,
            ["Handle: 1", "Data Path Direction: 0x03", "  Remove input data path", "  Remove output data path"]
        );
    }

    #[test]
    fn set_host_feature_params() {
        let mut st = IndexState::default();
        let lines = cmd_lines(&mut st, cmd::LE_SET_HOST_FEATURE, &[0x20, 0x01]);
        assert_eq!(
            lines,
            ["Bit Number: 32", "  Connected Isochronous Stream (Host Support)", "Bit Value: Enabled (0x01)"]
        );
        let lines = cmd_lines(&mut st, cmd::LE_SET_HOST_FEATURE_V2, &[0x40, 0x00, 0x00]);
        assert_eq!(lines, ["Bit Number: 64", "  Monitoring Advertisers", "Bit Value: Disabled (0x00)"]);
        let lines = cmd_lines(&mut st, cmd::LE_SET_HOST_FEATURE_V2, &[0x00, 0x01, 0x01]);
        assert_eq!(
            lines,
            ["Bit Number: 256", "  Unknown feature bit 256 (page 2 bit 0)", "Bit Value: Enabled (0x01)"]
        );
    }

    #[test]
    fn read_iso_tx_sync_rsp() {
        let mut st = IndexState::default();
        let data = [0x00, 0x01, 0x00, 0x34, 0x12, 0x78, 0x56, 0x34, 0x12, 0x10, 0x27, 0x00];
        let lines = rsp_lines(&mut st, cmd::LE_READ_ISO_TX_SYNC, &data);
        assert_eq!(
            lines,
            [
                "Status: Success (0x00)",
                "Handle: 1",
                "Packet sequence number: 4660",
                "TX timestamp: 305419896 us (0x12345678)",
                "Time offset: 10000 us (0x002710)",
            ]
        );
    }

    #[test]
    fn iso_test_counters_rsp() {
        let mut st = IndexState::default();
        let data = [0x00, 0x01, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let lines = rsp_lines(&mut st, cmd::LE_ISO_TEST_END, &data);
        assert_eq!(
            lines,
            ["Status: Success (0x00)", "Handle: 1", "Received SDU count: 10", "Missed SDU count: 1", "Failed SDU count: 0"]
        );
    }

    #[test]
    fn enhanced_read_transmit_power_level() {
        let mut st = IndexState::default();
        let lines = cmd_lines(&mut st, cmd::LE_ENHANCED_READ_TRANSMIT_POWER_LEVEL, &[0x00, 0x00, 0x03]);
        assert_eq!(lines, ["Handle: 0", "PHY: LE Coded with S=8 (0x03)"]);
        let lines = rsp_lines(&mut st, cmd::LE_ENHANCED_READ_TRANSMIT_POWER_LEVEL, &[0x00, 0x00, 0x00, 0x01, 0xfc, 0x08]);
        assert_eq!(
            lines,
            [
                "Status: Success (0x00)",
                "Handle: 0",
                "PHY: LE 1M (0x01)",
                "Current TX power: -4 dbm (0xfc)",
                "Max TX power: 8 dbm (0x08)",
            ]
        );
    }

    #[test]
    fn path_loss_and_power_reporting() {
        let mut st = IndexState::default();
        let data = [0x00, 0x00, 0x50, 0x02, 0x30, 0x02, 0x05, 0x00];
        let lines = cmd_lines(&mut st, cmd::LE_SET_PATH_LOSS_REPORTING_PARAMETERS, &data);
        assert_eq!(
            lines,
            [
                "Handle: 0",
                "High threshold: 80 dB (0x50)",
                "High hysteresis: 2 dB (0x02)",
                "Low threshold: 48 dB (0x30)",
                "Low hysteresis: 2 dB (0x02)",
                "Min time spent: 5 connection events (0x0005)",
            ]
        );
        let lines = cmd_lines(&mut st, cmd::LE_SET_TRANSMIT_POWER_REPORTING_ENABLE, &[0x00, 0x00, 0x01, 0x00]);
        assert_eq!(lines, ["Handle: 0", "Local reporting: Enabled (0x01)", "Remote reporting: Disabled (0x00)"]);
    }

    #[test]
    fn transmitter_test_v4_params() {
        let mut st = IndexState::default();
        let data = [0x13, 0x25, 0x00, 0x02, 0x00, 0x00, 0x02, 0x01, 0x02, 0x7f];
        let lines = cmd_lines(&mut st, cmd::LE_TRANSMITTER_TEST_V4, &data);
        assert_eq!(
            lines,
            [
                "TX channel: 2440 MHz (0x13)",
                "Length of test data: 37",
                "Packet payload: PRBS9 (0x00)",
                "PHY: LE 2M (0x02)",
                "CTE length: No CTE (0x00)",
                "CTE type: AoA (0x00)",
                "Switching pattern length: 2",
                "Antenna ID: 1",
                "Antenna ID: 2",
                "TX power: Maximum (0x7f)",
            ]
        );
    }

    #[test]
    fn subrate_request_params() {
        let mut st = IndexState::default();
        let data = [0x00, 0x00, 0x01, 0x00, 0x05, 0x00, 0x02, 0x00, 0x01, 0x00, 0x2a, 0x00];
        let lines = cmd_lines(&mut st, cmd::LE_SUBRATE_REQUEST, &data);
        assert_eq!(
            lines,
            [
                "Handle: 0",
                "Subrate min: 1 (0x0001)",
                "Subrate max: 5 (0x0005)",
                "Max latency: 2 (0x0002)",
                "Continuation number: 1 (0x0001)",
                "Supervision timeout: 420 msec (0x002a)",
            ]
        );
    }

    #[test]
    fn set_ext_adv_params_v2_params() {
        let mut st = IndexState::default();
        let data = [
            0x00, // handle
            0x13, 0x00, // properties: legacy ADV_IND
            0x20, 0x00, 0x00, // min interval 20 ms
            0x40, 0x00, 0x00, // max interval 40 ms
            0x07, // channel map
            0x01, // own address type
            0x00, // peer address type
            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, // peer address
            0x00, // filter policy
            0x7f, // tx power
            0x01, // primary PHY
            0x00, // secondary max skip
            0x01, // secondary PHY
            0x00, // SID
            0x00, // scan request notifications
            0x00, // primary PHY options
            0x02, // secondary PHY options
        ];
        let lines = cmd_lines(&mut st, cmd::LE_SET_EXTENDED_ADVERTISING_PARAMETERS_V2, &data);
        assert_eq!(
            lines,
            [
                "Handle: 0x00",
                "Properties: 0x0013",
                "  Connectable",
                "  Scannable",
                "  Use legacy advertising PDUs: ADV_IND",
                "Min advertising interval: 20.000 msec (0x000020)",
                "Max advertising interval: 40.000 msec (0x000040)",
                "Channel map: 37, 38, 39 (0x07)",
                "Own address type: Random (0x01)",
                "Peer address type: Public (0x00)",
                "Peer address: 66:55:44:33:22:11 (OUI 66-55-44)",
                "Filter policy: Allow Scan Request from Any, Allow Connect Request from Any (0x00)",
                "TX power: Host has no preference (0x7f)",
                "Primary PHY: LE 1M (0x01)",
                "Secondary max skip: 0x00",
                "Secondary PHY: LE 1M (0x01)",
                "SID: 0x00",
                "Scan request notifications: Disabled (0x00)",
                "Primary PHY options: No preference (0x00)",
                "Secondary PHY options: Prefer S=8 coding (0x02)",
            ]
        );
        let lines = rsp_lines(&mut st, cmd::LE_SET_EXTENDED_ADVERTISING_PARAMETERS_V2, &[0x00, 0xfb]);
        assert_eq!(lines, ["Status: Success (0x00)", "TX power (selected): -5 dbm (0xfb)"]);
    }

    #[test]
    fn ext_create_connection_v2_params() {
        let mut st = IndexState::default();
        let data = [
            0xff, 0xff, // adv handle, subevent
            0x00, // filter policy
            0x00, // own address type
            0x01, // peer address type
            0x01, 0x02, 0x03, 0x04, 0x05, 0xc6, // peer address (static)
            0x05, // initiating PHYs: 1M + Coded
            0x60, 0x00, 0x30, 0x00, 0x18, 0x00, 0x28, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x60, 0x00, 0x30, 0x00, 0x18, 0x00, 0x28, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00, 0x00, 0x00, 0x00,
        ];
        let lines = cmd_lines(&mut st, cmd::LE_EXTENDED_CREATE_CONNECTION_V2, &data);
        assert_eq!(
            &lines[..7],
            &[
                "Advertising handle: Not used (0xff)",
                "Subevent: Not used (0xff)",
                "Filter policy: Accept list is not used (0x00)",
                "Own address type: Public (0x00)",
                "Peer address type: Random (0x01)",
                "Peer address: C6:05:04:03:02:01 (Static)",
                "Initiating PHYs: 0x05",
            ]
        );
        assert_eq!(
            &lines[7..16],
            &[
                "Entry 0: LE 1M",
                "  Scan interval: 60.000 msec (0x0060)",
                "  Scan window: 30.000 msec (0x0030)",
                "  Min connection interval: 30.000 msec (0x0018)",
                "  Max connection interval: 50.000 msec (0x0028)",
                "  Connection latency: 0 (0x0000)",
                "  Supervision timeout: 420 msec (0x002a)",
                "  Min connection length: 0.000 msec (0x0000)",
                "  Max connection length: 0.000 msec (0x0000)",
            ]
        );
        assert_eq!(lines[16], "Entry 1: LE Coded");
        assert_eq!(lines.len(), 25);
    }

    #[test]
    fn set_pa_params_v2_params() {
        let mut st = IndexState::default();
        let data = [0x01, 0x50, 0x00, 0x50, 0x00, 0x40, 0x00, 0x03, 0x08, 0x02, 0x04, 0x05];
        let lines = cmd_lines(&mut st, cmd::LE_SET_PERIODIC_ADVERTISING_PARAMETERS_V2, &data);
        assert_eq!(
            lines,
            [
                "Handle: 0x01",
                "Min interval: 100.000 msec (0x0050)",
                "Max interval: 100.000 msec (0x0050)",
                "Properties: 0x0040",
                "  Include TxPower",
                "Number of subevents: 3",
                "Subevent interval: 10.000 msec (0x08)",
                "Response slot delay: 2.500 msec (0x02)",
                "Response slot spacing: 0.500 msec (0x04)",
                "Number of response slots: 5",
            ]
        );
        let lines = rsp_lines(&mut st, cmd::LE_SET_PERIODIC_ADVERTISING_PARAMETERS_V2, &[0x00, 0x01]);
        assert_eq!(lines, ["Status: Success (0x00)", "Handle: 0x01"]);
    }

    #[test]
    fn set_pa_subevent_data_params() {
        let mut st = IndexState::default();
        let data = [0x01, 0x02, 0x00, 0x00, 0x04, 0x02, 0xaa, 0xbb, 0x01, 0x04, 0x04, 0x00];
        let lines = cmd_lines(&mut st, cmd::LE_SET_PERIODIC_ADVERTISING_SUBEVENT_DATA, &data);
        assert_eq!(
            lines,
            [
                "Handle: 0x01",
                "Number of subevents: 2",
                "Entry 0",
                "  Subevent: 0x00",
                "  Response slot start: 0",
                "  Response slot count: 4",
                "  Data length: 2",
                "  Data: aa bb",
                "Entry 1",
                "  Subevent: 0x01",
                "  Response slot start: 4",
                "  Response slot count: 4",
                "  Data length: 0",
                "  Data:",
            ]
        );
    }

    #[test]
    fn read_all_local_supported_features_rsp() {
        let mut st = IndexState::default();
        let mut data = vec![0x00, 0x01];
        let mut features = [0u8; 248];
        features[0] = 0x01; // LE Encryption
        features[8] = 0x03; // page 1: Monitoring Advertisers, Frame Space Update
        data.extend_from_slice(&features);
        let lines = rsp_lines(&mut st, cmd::LE_READ_ALL_LOCAL_SUPPORTED_FEATURES, &data);
        assert_eq!(
            lines,
            [
                "Status: Success (0x00)",
                "Max page: 1",
                "Features: 0x01 0x00 0x00 0x00 0x00 0x00 0x00 0x00",
                "  LE Encryption",
                "Features (page 1): 0x03 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 \
                 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00 0x00",
                "  Monitoring Advertisers",
                "  Frame Space Update",
            ]
        );
    }

    #[test]
    fn cs_read_local_supported_capabilities_rsp() {
        let mut st = IndexState::default();
        let v1 = [
            0x00, // status
            0x04, // num config
            0x00, 0x00, // max consecutive procedures
            0x02, 0x02, // antennas, antenna paths
            0x03, // roles
            0x01, // modes
            0x00, // RTT capability
            0x01, 0x00, 0x00, // RTT N values
            0x01, 0x00, 0x00, 0x00, // NADM sounding, random
            0x02, // CS_SYNC PHYs
            0x04, 0x00, // subfeatures
            0x41, 0x00, // T_IP1
            0x01, 0x00, // T_IP2
            0x01, 0x01, // T_FCS
            0x02, 0x00, // T_PM
            0x02, // T_SW
            0x11, // TX SNR
        ];
        let lines = rsp_lines(&mut st, cmd::LE_CS_READ_LOCAL_SUPPORTED_CAPABILITIES, &v1);
        assert_eq!(
            lines,
            [
                "Status: Success (0x00)",
                "Num config supported: 4",
                "Max consecutive procedures supported: Fixed or indefinite (0x0000)",
                "Num antennas supported: 2",
                "Max antenna paths supported: 2",
                "Roles supported: 0x03",
                "  Initiator",
                "  Reflector",
                "Modes supported: 0x01",
                "  Mode-3",
                "RTT capability: 0x00",
                "RTT AA only N: 1",
                "RTT sounding N: Not supported (0x00)",
                "RTT random sequence N: Not supported (0x00)",
                "NADM sounding capability: 0x0001",
                "  Phase-based NADM",
                "NADM random capability: 0x0000",
                "CS_SYNC PHYs supported: 0x02",
                "  LE 2M",
                "Subfeatures supported: 0x0004",
                "  CS Channel Selection Algorithm #3c",
                "T_IP1 times supported: 0x0041",
                "  10 us",
                "  80 us",
                "T_IP2 times supported: 0x0001",
                "  10 us",
                "T_FCS times supported: 0x0101",
                "  15 us",
                "  120 us",
                "T_PM times supported: 0x0002",
                "  20 us",
                "T_SW time supported: 2 us (0x02)",
                "TX_SNR capability: 0x11",
                "  18 dB",
                "  30 dB",
            ]
        );
        let mut v2 = v1.to_vec();
        v2.extend_from_slice(&[0x02, 0x00, 0x04, 0x01, 0x02, 0x00]);
        let lines = rsp_lines(&mut st, cmd::LE_CS_READ_LOCAL_SUPPORTED_CAPABILITIES_V2, &v2);
        assert_eq!(
            &lines[35..],
            &[
                "T_IP2 IPT times supported: 0x0002",
                "  20 us",
                "T_SW IPT time supported: 4 us (0x04)",
                "RTT 2M AA only N: 1",
                "RTT 2M sounding N: 2",
                "RTT 2M random sequence N: Not supported (0x00)",
            ]
        );
    }

    #[test]
    fn cs_create_config_params() {
        let mut st = IndexState::default();
        let mut data = vec![0x00, 0x00, 0x00, 0x01, 0x02, 0xff, 0x02, 0x05, 0x01, 0x03, 0x00, 0x00, 0x02];
        data.extend_from_slice(&[0xfc, 0xff, 0x7f, 0xfc, 0xff, 0xff, 0xff, 0xff, 0x1f, 0x00]);
        data.extend_from_slice(&[0x03, 0x01, 0x00, 0x02, 0x01]);
        let lines = cmd_lines(&mut st, cmd::LE_CS_CREATE_CONFIG, &data);
        assert_eq!(
            lines,
            [
                "Handle: 0",
                "Config ID: 0",
                "Create context: Local and remote Controller (0x01)",
                "Main mode type: Mode-2 (0x02)",
                "Sub mode type: Unused (0xff)",
                "Min main mode steps: 2",
                "Max main mode steps: 5",
                "Main mode repetition: 1",
                "Mode 0 steps: 3",
                "Role: Initiator (0x00)",
                "RTT type: RTT AA-only (0x00)",
                "CS_SYNC PHY: LE 2M (0x02)",
                "Channel map: fc ff 7f fc ff ff ff ff 1f 00",
                "Channel map repetition: 3",
                "Channel selection type: Channel Selection Algorithm #3c (0x01)",
                "Ch3c shape: Hat shape (0x00)",
                "Ch3c jump: 2",
                "CS enhancements: 0x01",
                "  IPT enabled in the CS reflector",
            ]
        );
    }

    #[test]
    fn cs_set_procedure_parameters_params() {
        let mut st = IndexState::default();
        let data = [
            0x00, 0x00, 0x01, 0xff, 0xff, 0x10, 0x00, 0x20, 0x00, 0x00, 0x00, 0xe2, 0x04, 0x00, 0x40, 0x9c, 0x00, 0x07,
            0x02, 0x80, 0x01, 0xff, 0x00,
        ];
        let lines = cmd_lines(&mut st, cmd::LE_CS_SET_PROCEDURE_PARAMETERS, &data);
        assert_eq!(
            lines,
            [
                "Handle: 0",
                "Config ID: 1",
                "Max procedure length: 40959.375 msec (0xffff)",
                "Min procedure interval: 16 connection events (0x0010)",
                "Max procedure interval: 32 connection events (0x0020)",
                "Max procedure count: Until disabled (0x0000)",
                "Min subevent length: 1250 us (0x0004e2)",
                "Max subevent length: 40000 us (0x009c40)",
                "Tone antenna config selection: 7",
                "PHY: LE 2M (0x02)",
                "TX power delta: No recommendation (0x80)",
                "Preferred peer antenna: 0x01",
                "  First ordered antenna element",
                "SNR control initiator: Not applied (0xff)",
                "SNR control reflector: 18 dB (0x00)",
            ]
        );
    }

    #[test]
    fn cs_test_params() {
        let mut st = IndexState::default();
        let mut data = vec![
            0x02, 0xff, 0x00, 0x01, 0x00, 0x00, 0x01, 0x01, // modes, repetition, mode0, role, rtt, phy, antenna
            0xe2, 0x04, 0x00, // subevent len
            0x00, 0x00, // subevent interval
            0x00, // max subevents
            0x7e, // tx power
            0x50, 0x50, 0x0f, 0x28, 0x0a, // T_IP1, T_IP2, T_FCS, T_PM, T_SW
            0x00, 0x00, 0xff, 0xff, // antenna config, enhancements, SNR ctrl x2
            0x34, 0x12, // nonce
            0x01, // channel map repetition
            0x05, 0x00, // override config: bits 0, 2
            0x04, // override length
            0x02, 0x0a, 0x0b, // channel length + channels
            0x03, // main mode steps
        ];
        let lines = cmd_lines(&mut st, cmd::LE_CS_TEST, &data);
        assert_eq!(
            lines,
            [
                "Main mode type: Mode-2 (0x02)",
                "Sub mode type: Unused (0xff)",
                "Main mode repetition: 0",
                "Mode 0 steps: 1",
                "Role: Initiator (0x00)",
                "RTT type: RTT AA-only (0x00)",
                "CS_SYNC PHY: LE 1M (0x01)",
                "CS_SYNC antenna selection: 1",
                "Subevent length: 1250 us (0x0004e2)",
                "Subevent interval: Single CS subevent (0x0000)",
                "Max number of subevents: No restriction (0x00)",
                "TX power: Minimum (0x7e)",
                "T_IP1 time: 80 us (0x50)",
                "T_IP2 time: 80 us (0x50)",
                "T_FCS time: 15 us (0x0f)",
                "T_PM time: 40 us (0x28)",
                "T_SW time: 10 us (0x0a)",
                "Tone antenna config selection: 0",
                "CS enhancements: 0x00",
                "SNR control initiator: Not applied (0xff)",
                "SNR control reflector: Not applied (0xff)",
                "DRBG nonce: 0x1234",
                "Channel map repetition: 1",
                "Override config: 0x0005",
                "  Channel list overrides channel map",
                "  Main mode steps override",
                "Override parameters length: 4",
                "Override parameters",
                "  Channel length: 2",
                "  Channels: 0a 0b",
                "  Main mode steps: 3",
            ]
        );
        // A short override blob is flagged without failing the whole command.
        data[29] = 0x02;
        data.truncate(32);
        let lines = cmd_lines(&mut st, cmd::LE_CS_TEST, &data);
        assert_eq!(lines[lines.len() - 2], "  Override parameters truncated");
        assert!(lines[lines.len() - 1].starts_with("  0a "), "{}", lines[lines.len() - 1]);
    }

    #[test]
    fn set_decision_instructions_params() {
        let mut st = IndexState::default();
        let mut data = vec![0x01, 0x03, 0x07];
        data.extend_from_slice(&[0x00; 16]);
        let lines = cmd_lines(&mut st, cmd::LE_SET_DECISION_INSTRUCTIONS, &data);
        assert_eq!(
            lines,
            [
                "Number of tests: 1",
                "Test 0",
                "  Flags: 0x03",
                "    Start of new test group",
                "    Pass if field present and check passes",
                "  Field: RSSI (0x07)",
                "  Parameters: 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00",
            ]
        );
    }

    #[test]
    fn monitored_advertisers_params() {
        let mut st = IndexState::default();
        let data = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0xba, 0xce, 0x05];
        let lines = cmd_lines(&mut st, cmd::LE_ADD_DEVICE_TO_MONITORED_ADVERTISERS_LIST, &data);
        assert_eq!(
            lines,
            [
                "Address type: Public (0x00)",
                "Address: 66:55:44:33:22:11 (OUI 66-55-44)",
                "RSSI low threshold: -70 dBm (0xba)",
                "RSSI high threshold: -50 dBm (0xce)",
                "Timeout: 5 seconds (0x05)",
            ]
        );
        let lines = rsp_lines(&mut st, cmd::LE_READ_MONITORED_ADVERTISERS_LIST_SIZE, &[0x00, 0x08]);
        assert_eq!(lines, ["Status: Success (0x00)", "List size: 8"]);
    }

    #[test]
    fn frame_space_update_params() {
        let mut st = IndexState::default();
        let data = [0x00, 0x00, 0x96, 0x00, 0xf4, 0x01, 0x03, 0x03, 0x00];
        let lines = cmd_lines(&mut st, cmd::LE_FRAME_SPACE_UPDATE, &data);
        assert_eq!(
            lines,
            [
                "Handle: 0",
                "Frame space min: 150 us (0x0096)",
                "Frame space max: 500 us (0x01f4)",
                "PHYs: 0x03",
                "  LE 1M",
                "  LE 2M",
                "Spacing types: 0x0003",
                "  T_IFS_ACL_CP",
                "  T_IFS_ACL_PC",
            ]
        );
    }

    #[test]
    fn connection_rate_and_min_interval() {
        let mut st = IndexState::default();
        let data = [
            0x00, 0x00, 0x03, 0x00, 0x06, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x01, 0x00,
            0x02, 0x00,
        ];
        let lines = cmd_lines(&mut st, cmd::LE_CONNECTION_RATE_REQUEST, &data);
        assert_eq!(
            lines,
            [
                "Handle: 0",
                "Min connection interval: 0.375 msec (0x0003)",
                "Max connection interval: 0.750 msec (0x0006)",
                "Subrate min: 1 (0x0001)",
                "Subrate max: 1 (0x0001)",
                "Max latency: 0 (0x0000)",
                "Continuation number: 0 (0x0000)",
                "Supervision timeout: 420 msec (0x002a)",
                "Min connection length: 0.125 msec (0x0001)",
                "Max connection length: 0.250 msec (0x0002)",
            ]
        );
        let data = [0x00, 0x03, 0x01, 0x03, 0x00, 0x3c, 0x00, 0x01, 0x00];
        let lines = rsp_lines(&mut st, cmd::LE_READ_MINIMUM_SUPPORTED_CONNECTION_INTERVAL, &data);
        assert_eq!(
            lines,
            [
                "Status: Success (0x00)",
                "Minimum supported connection interval: 0.375 msec (0x03)",
                "Number of groups: 1",
                "Group 0",
                "  Min interval: 0.375 msec (0x0003)",
                "  Max interval: 7.500 msec (0x003c)",
                "  Stride: 0.125 msec (0x0001)",
            ]
        );
    }

    #[test]
    fn set_event_mask_v2_params() {
        let mut st = IndexState::default();
        let mut data = vec![0x1f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x00];
        data.extend_from_slice(&[0x00; 16]);
        let lines = cmd_lines(&mut st, cmd::LE_SET_EVENT_MASK_V2, &data);
        assert_eq!(
            lines,
            [
                "Mask: 0x1f 0x00 0x00 0x00 0x00 0x00 0x80 0x00",
                "  LE Connection Complete",
                "  LE Advertising Report",
                "  LE Connection Update Complete",
                "  LE Read Remote Features Page 0 Complete",
                "  LE Long Term Key Request",
                "  LE CS Read Remote Supported Capabilities Complete v2",
                "Mask (bits 64 and above): 16 octets, none set",
            ]
        );
        data[9] = 0x02;
        let lines = cmd_lines(&mut st, cmd::LE_SET_EVENT_MASK_V2, &data);
        assert_eq!(lines[7], "Mask (bits 64 and above): 00 02 00 00 00 00 00 00 00 00 00 00 00 00 00 00");
        assert_eq!(lines[8], "  Unknown bit 73");
    }

    #[test]
    fn rpa_timeout_and_utp() {
        let mut st = IndexState::default();
        let lines = cmd_lines(&mut st, cmd::LE_SET_RESOLVABLE_PRIVATE_ADDRESS_TIMEOUT_V2, &[0x84, 0x03, 0x3c, 0x00, 0x10, 0x0e]);
        assert_eq!(
            lines,
            ["Timeout: 900 seconds (0x0384)", "Min timeout: 60 seconds (0x003c)", "Max timeout: 3600 seconds (0x0e10)"]
        );
        let lines = cmd_lines(&mut st, cmd::LE_UTP_SEND, &[0x03, 0x01, 0x02, 0x03]);
        assert_eq!(lines, ["Data length: 3", "Data: 01 02 03"]);
        let lines = cmd_lines(&mut st, cmd::LE_ENABLE_UTP_OTA_MODE, &[0x01]);
        assert_eq!(lines, ["UTP OTA mode: Enabled (0x01)"]);
    }
}
