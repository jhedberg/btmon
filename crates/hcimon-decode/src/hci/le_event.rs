//! LE Meta subevent decoders (Core Specification Vol 4, Part E, Section 7.7.65).
//!
//! One function per subevent; [`le_event_params`] dispatches on the subevent
//! code.  Labels follow btmon.  Arrayed parameters (`Foo[i]`) are laid out on
//! the wire interleaved per element (Vol 4, Part E, Section 5.2), so report
//! lists are walked one complete report at a time.

use super::common::*;
use super::event::register_connection;
use super::le_evt;
use crate::context::{IndexState, LinkType};
use crate::field;
use crate::reader::{BdAddr, Reader, Result};
use crate::tree::Out;

// Subevent codes the generated `le_evt` table has no constants for.
const PERIODIC_ADVERTISING_SYNC_ESTABLISHED_V2: u8 = 0x24;
const PERIODIC_ADVERTISING_REPORT_V2: u8 = 0x25;
const PERIODIC_ADVERTISING_SYNC_TRANSFER_RECEIVED_V2: u8 = 0x26;
const ENHANCED_CONNECTION_COMPLETE_V2: u8 = 0x29;

/// Decode the parameters of the LE subevent with the given code.
pub fn le_event_params(st: &mut IndexState, sub: u8, r: &mut Reader<'_>, out: &mut Out) -> Result<bool> {
    match sub {
        le_evt::CONNECTION_COMPLETE => connection_complete(st, r, out, ConnComplete::Legacy)?,
        le_evt::ADVERTISING_REPORT => advertising_report(r, out)?,
        le_evt::CONNECTION_UPDATE_COMPLETE => connection_update_complete(st, r, out)?,
        le_evt::READ_REMOTE_FEATURES_PAGE_0_COMPLETE => read_remote_features_page0_complete(st, r, out)?,
        le_evt::LONG_TERM_KEY_REQUEST => long_term_key_request(st, r, out)?,
        le_evt::REMOTE_CONNECTION_PARAMETER_REQUEST => remote_connection_parameter_request(st, r, out)?,
        le_evt::DATA_LENGTH_CHANGE => data_length_change(st, r, out)?,
        le_evt::READ_LOCAL_P_256_PUBLIC_KEY_COMPLETE => read_local_p256_public_key_complete(r, out)?,
        le_evt::GENERATE_DHKEY_COMPLETE => generate_dhkey_complete(r, out)?,
        le_evt::ENHANCED_CONNECTION_COMPLETE => connection_complete(st, r, out, ConnComplete::EnhancedV1)?,
        le_evt::DIRECTED_ADVERTISING_REPORT => directed_advertising_report(r, out)?,
        le_evt::PHY_UPDATE_COMPLETE => phy_update_complete(st, r, out)?,
        le_evt::EXTENDED_ADVERTISING_REPORT => extended_advertising_report(r, out)?,
        le_evt::PERIODIC_ADVERTISING_SYNC_ESTABLISHED => periodic_advertising_sync_established(r, out, false)?,
        le_evt::PERIODIC_ADVERTISING_REPORT => periodic_advertising_report(r, out, false)?,
        le_evt::PERIODIC_ADVERTISING_SYNC_LOST => {
            sync_handle(r, out)?;
        }
        // No parameters.
        le_evt::SCAN_TIMEOUT => {}
        le_evt::ADVERTISING_SET_TERMINATED => advertising_set_terminated(st, r, out)?,
        le_evt::SCAN_REQUEST_RECEIVED => scan_request_received(r, out)?,
        le_evt::CHANNEL_SELECTION_ALGORITHM => channel_selection_algorithm(st, r, out)?,
        le_evt::CONNECTIONLESS_IQ_REPORT => connectionless_iq_report(r, out)?,
        le_evt::CONNECTION_IQ_REPORT => connection_iq_report(st, r, out)?,
        le_evt::CTE_REQUEST_FAILED => status_handle(st, r, out)?,
        le_evt::PERIODIC_ADVERTISING_SYNC_TRANSFER_RECEIVED => {
            periodic_advertising_sync_transfer_received(st, r, out, false)?
        }
        le_evt::CIS_ESTABLISHED => cis_established(st, r, out, false)?,
        le_evt::CIS_REQUEST => cis_request(st, r, out)?,
        le_evt::CREATE_BIG_COMPLETE => create_big_complete(st, r, out)?,
        le_evt::TERMINATE_BIG_COMPLETE | le_evt::BIG_SYNC_LOST => big_handle_reason(r, out)?,
        le_evt::BIG_SYNC_ESTABLISHED => big_sync_established(st, r, out)?,
        le_evt::REQUEST_PEER_SCA_COMPLETE => request_peer_sca_complete(st, r, out)?,
        le_evt::PATH_LOSS_THRESHOLD => path_loss_threshold(st, r, out)?,
        le_evt::TRANSMIT_POWER_REPORTING => transmit_power_reporting(st, r, out)?,
        le_evt::BIGINFO_ADVERTISING_REPORT => biginfo_advertising_report(r, out)?,
        le_evt::SUBRATE_CHANGE => subrate_change(st, r, out)?,
        PERIODIC_ADVERTISING_SYNC_ESTABLISHED_V2 => periodic_advertising_sync_established(r, out, true)?,
        PERIODIC_ADVERTISING_REPORT_V2 => periodic_advertising_report(r, out, true)?,
        PERIODIC_ADVERTISING_SYNC_TRANSFER_RECEIVED_V2 => {
            periodic_advertising_sync_transfer_received(st, r, out, true)?
        }
        le_evt::PERIODIC_ADVERTISING_SUBEVENT_DATA_REQUEST => periodic_advertising_subevent_data_request(r, out)?,
        le_evt::PERIODIC_ADVERTISING_RESPONSE_REPORT => periodic_advertising_response_report(r, out)?,
        ENHANCED_CONNECTION_COMPLETE_V2 => connection_complete(st, r, out, ConnComplete::EnhancedV2)?,
        le_evt::CIS_ESTABLISHED_V2 => cis_established(st, r, out, true)?,
        le_evt::READ_ALL_REMOTE_FEATURES_COMPLETE => read_all_remote_features_complete(st, r, out)?,
        le_evt::CS_READ_REMOTE_SUPPORTED_CAPABILITIES_COMPLETE => {
            cs_read_remote_supported_capabilities_complete(st, r, out, false)?
        }
        le_evt::CS_READ_REMOTE_FAE_TABLE_COMPLETE => cs_read_remote_fae_table_complete(st, r, out)?,
        le_evt::CS_SECURITY_ENABLE_COMPLETE => status_handle(st, r, out)?,
        le_evt::CS_CONFIG_COMPLETE => cs_config_complete(st, r, out)?,
        le_evt::CS_PROCEDURE_ENABLE_COMPLETE => cs_procedure_enable_complete(st, r, out)?,
        le_evt::CS_SUBEVENT_RESULT => cs_subevent_result(st, r, out, false)?,
        le_evt::CS_SUBEVENT_RESULT_CONTINUE => cs_subevent_result(st, r, out, true)?,
        le_evt::CS_TEST_END_COMPLETE => {
            status(r, out)?;
        }
        le_evt::MONITORED_ADVERTISERS_REPORT => monitored_advertisers_report(r, out)?,
        le_evt::FRAME_SPACE_UPDATE_COMPLETE => frame_space_update_complete(st, r, out)?,
        le_evt::UTP_RECEIVE => utp_receive(r, out)?,
        le_evt::CONNECTION_RATE_CHANGE => connection_rate_change(st, r, out)?,
        le_evt::CS_READ_REMOTE_SUPPORTED_CAPABILITIES_COMPLETE_V2 => {
            cs_read_remote_supported_capabilities_complete(st, r, out, true)?
        }
        _ => return Ok(false),
    }
    Ok(true)
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------

/// Clock accuracy values used by connection and periodic sync events.
static CLOCK_ACCURACY_PPM: &[(u8, &str)] = &[
    (0x00, "500 ppm"),
    (0x01, "250 ppm"),
    (0x02, "150 ppm"),
    (0x03, "100 ppm"),
    (0x04, "75 ppm"),
    (0x05, "50 ppm"),
    (0x06, "30 ppm"),
    (0x07, "20 ppm"),
];

/// Legacy advertising report event types (7.7.65.2 / 7.7.65.11).
static ADV_EVENT_TYPES: &[(u8, &str)] = &[
    (0x00, "Connectable undirected - ADV_IND"),
    (0x01, "Connectable directed - ADV_DIRECT_IND"),
    (0x02, "Scannable undirected - ADV_SCAN_IND"),
    (0x03, "Non connectable undirected - ADV_NONCONN_IND"),
    (0x04, "Scan response - SCAN_RSP"),
];

/// Constant Tone Extension types as reported in advertising/response reports
/// ([`CTE_TYPES`] plus the "none" value).
static REPORT_CTE_TYPES: &[(u8, &str)] = &[
    (0x00, "AoA Constant Tone Extension"),
    (0x01, "AoD Constant Tone Extension with 1 us slots"),
    (0x02, "AoD Constant Tone Extension with 2 us slots"),
    (0xff, "No Constant Tone Extension"),
];

/// `Sync handle: N` (12 significant bits).  Events print the handle in decimal
/// as btmon does; commands use the hex form in [`common::sync_handle`](super::common::sync_handle).
fn sync_handle(r: &mut Reader<'_>, out: &mut Out) -> Result<u16> {
    let h = read_handle(r)?;
    field!(out, "Sync handle: {}", h);
    Ok(h)
}

/// TX power as carried in advertising reports: 0x7f means not available.
fn report_tx_power(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<i8> {
    let v = r.i8()?;
    match v {
        127 => field!(out, "{}: not available (0x7f)", label),
        _ => field!(out, "{}: {} dBm (0x{:02x})", label, v, v as u8),
    };
    Ok(v)
}

/// Address type of advertising reports, which may also be anonymous (0xff)
/// or an unresolved random address (0xfe).
fn report_addr_type(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    let t = r.u8()?;
    match t {
        0x00..=0x03 => field!(out, "{}: {} (0x{:02x})", label, addr_type_str(t), t),
        0xfe => field!(out, "{}: Random (Controller unable to resolve) (0xfe)", label),
        0xff => field!(out, "{}: Anonymous (0xff)", label),
        _ => out.unknown(format!("{label}: Reserved (0x{t:02x})")),
    };
    Ok(t)
}

/// Address type + address pair for advertising reports.
fn report_addr(type_label: &str, addr_label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<(u8, BdAddr)> {
    let t = report_addr_type(type_label, r, out)?;
    let kind = if t == 0xfe { 0x01 } else { t };
    let a = bdaddr_typed(addr_label, kind, r, out)?;
    Ok((t, a))
}

/// Advertising SID: `0x00..0x0f`, optionally `0xff` for "no ADI field".
fn adv_sid(label: &str, r: &mut Reader<'_>, out: &mut Out, allow_none: bool) -> Result<u8> {
    let v = r.u8()?;
    match v {
        0x00..=0x0f => field!(out, "{}: 0x{:02x}", label, v),
        0xff if allow_none => field!(out, "{}: no ADI field (0xff)", label),
        _ => out.unknown(format!("{label}: Reserved (0x{v:02x})")),
    };
    Ok(v)
}

fn data_status_str(v: u8) -> Option<&'static str> {
    match v {
        0x00 => Some("Complete"),
        0x01 => Some("Incomplete, more data to come"),
        0x02 => Some("Incomplete, data truncated, no more to come"),
        _ => None,
    }
}

/// `Data status` byte of periodic advertising / response reports.
fn data_status(r: &mut Reader<'_>, out: &mut Out, failed: &str) -> Result<u8> {
    let v = r.u8()?;
    match (data_status_str(v), v) {
        (Some(s), _) => field!(out, "Data status: {} (0x{:02x})", s, v),
        (None, 0xff) => field!(out, "Data status: {} (0xff)", failed),
        _ => out.unknown(format!("Data status: Reserved (0x{v:02x})")),
    };
    Ok(v)
}

/// PHY of a periodic advertiser / ISO stream (`LE 1M`, `LE 2M`, `LE Coded`).
fn le_phy(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    enum8(label, r, out, &[(0x01, "LE 1M"), (0x02, "LE 2M"), (0x03, "LE Coded")])
}

/// ISO framing (CIS Established v2, BIGInfo).
fn framing(r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    enum8(
        "Framing",
        r,
        out,
        &[(0x00, "Unframed"), (0x01, "Framed, Segmentable mode"), (0x02, "Framed, Unsegmented mode")],
    )
}

/// `BIG handle: 0xNN` (btmon spells the label `BIG Handle` in commands, `BIG handle` in events).
fn big_handle(r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    let v = u8_hex("BIG handle", r, out)?;
    Ok(v)
}

/// Read `n` BIS connection handles, print them and register them as ISO links when `register`.
fn bis_handles(st: &mut IndexState, r: &mut Reader<'_>, out: &mut Out, register: bool) -> Result<()> {
    let n = u8_field("Number of BIS", r, out)?;
    for i in 0..n {
        let h = read_handle(r)?;
        field!(out, "Connection handle #{}: {}", i, h);
        if register {
            register_connection(st, h, LinkType::Iso, 0, BdAddr::ZERO, 0);
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Connections
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum ConnComplete {
    Legacy,
    EnhancedV1,
    EnhancedV2,
}

/// LE Connection Complete (7.7.65.1) and LE Enhanced Connection Complete v1/v2 (7.7.65.10).
fn connection_complete(st: &mut IndexState, r: &mut Reader<'_>, out: &mut Out, variant: ConnComplete) -> Result<()> {
    let s = status(r, out)?;
    let h = read_handle(r)?;
    field!(out, "Handle: {}", h);
    let role = role(r, out)?;
    let (t, a) = peer_addr_labelled("Peer address type", "Peer address", r, out)?;
    if variant != ConnComplete::Legacy {
        bdaddr_typed("Local resolvable private address", 0x01, r, out)?;
        bdaddr_typed("Peer resolvable private address", 0x01, r, out)?;
    }
    interval("Connection interval", r, out, 1250)?;
    u16_hex("Connection latency", r, out)?;
    timeout_ms("Supervision timeout", r, out, 10)?;
    enum8("Central clock accuracy", r, out, CLOCK_ACCURACY_PPM)?;
    if variant == ConnComplete::EnhancedV2 {
        let adv = r.u8()?;
        match adv {
            0xff => field!(out, "Advertising handle: None (0xff)"),
            _ => field!(out, "Advertising handle: {}", adv),
        };
        let sync = r.u16()?;
        match sync {
            0xffff => field!(out, "Sync handle: None (0xffff)"),
            _ => field!(out, "Sync handle: {}", sync & 0x0fff),
        };
    }
    if s == 0 {
        register_connection(st, h, LinkType::Le, t, a, role);
    }
    Ok(())
}

/// LE Connection Update Complete (7.7.65.3).
fn connection_update_complete(st: &IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    status(r, out)?;
    handle(st, r, out)?;
    interval("Connection interval", r, out, 1250)?;
    u16_hex("Connection latency", r, out)?;
    timeout_ms("Supervision timeout", r, out, 10)?;
    Ok(())
}

/// LE Read Remote Features Page 0 Complete (7.7.65.4).
fn read_remote_features_page0_complete(st: &IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    status(r, out)?;
    handle(st, r, out)?;
    le_features("Features", r, out, 0)?;
    Ok(())
}

/// LE Long Term Key Request (7.7.65.5).
fn long_term_key_request(st: &IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    handle(st, r, out)?;
    random_number(r, out)?;
    let ediv = r.u16()?;
    field!(out, "Encrypted diversifier: 0x{:04x}", ediv);
    Ok(())
}

/// LE Remote Connection Parameter Request (7.7.65.6).
fn remote_connection_parameter_request(st: &IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    handle(st, r, out)?;
    interval("Min connection interval", r, out, 1250)?;
    interval("Max connection interval", r, out, 1250)?;
    u16_hex("Connection latency", r, out)?;
    timeout_ms("Supervision timeout", r, out, 10)?;
    Ok(())
}

/// LE Data Length Change (7.7.65.7).
fn data_length_change(st: &IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    handle(st, r, out)?;
    u16_field("Max TX octets", r, out)?;
    u16_field("Max TX time", r, out)?;
    u16_field("Max RX octets", r, out)?;
    u16_field("Max RX time", r, out)?;
    Ok(())
}

/// LE Read Local P-256 Public Key Complete (7.7.65.8).
fn read_local_p256_public_key_complete(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    status(r, out)?;
    let key = r.bytes(64)?;
    out.group("Local P-256 public key:", |o| {
        o.hex_field("X", &key[..32]);
        o.hex_field("Y", &key[32..]);
    });
    Ok(())
}

/// LE Generate DHKey Complete (7.7.65.9).
fn generate_dhkey_complete(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    status(r, out)?;
    hex_bytes("Diffie-Hellman key", r, out, 32)?;
    Ok(())
}

/// LE PHY Update Complete (7.7.65.12).
fn phy_update_complete(st: &IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    status(r, out)?;
    handle(st, r, out)?;
    phy("TX PHY", r, out)?;
    phy("RX PHY", r, out)?;
    Ok(())
}

/// LE Channel Selection Algorithm (7.7.65.20).
fn channel_selection_algorithm(st: &IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    handle(st, r, out)?;
    enum8("Algorithm", r, out, &[(0x00, "#1"), (0x01, "#2")])?;
    Ok(())
}

/// LE Request Peer SCA Complete (7.7.65.31).
fn request_peer_sca_complete(st: &IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    status(r, out)?;
    handle(st, r, out)?;
    enum8(
        "SCA",
        r,
        out,
        &[
            (0x00, "251 - 500 ppm"),
            (0x01, "151 - 250 ppm"),
            (0x02, "101 - 150 ppm"),
            (0x03, "76 - 100 ppm"),
            (0x04, "51 - 75 ppm"),
            (0x05, "31 - 50 ppm"),
            (0x06, "21 - 30 ppm"),
            (0x07, "0 - 20 ppm"),
        ],
    )?;
    Ok(())
}

/// LE Path Loss Threshold (7.7.65.32).
fn path_loss_threshold(st: &IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    handle(st, r, out)?;
    let loss = r.u8()?;
    match loss {
        0xff => field!(out, "Current path loss: Unavailable (0xff)"),
        _ => field!(out, "Current path loss: {} dB (0x{:02x})", loss, loss),
    };
    enum8("Zone entered", r, out, &[(0x00, "Low"), (0x01, "Middle"), (0x02, "High")])?;
    Ok(())
}

/// LE Transmit Power Reporting (7.7.65.33).
fn transmit_power_reporting(st: &IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    status(r, out)?;
    handle(st, r, out)?;
    enum8(
        "Reason",
        r,
        out,
        &[
            (0x00, "Local transmit power changed"),
            (0x01, "Remote transmit power changed"),
            (0x02, "HCI_LE_Read_Remote_Transmit_Power_Level command completed"),
        ],
    )?;
    phy_coded("PHY", r, out)?;
    let level = r.i8()?;
    match level {
        126 => field!(out, "TX power level: Remote device is not managing power levels (0x7e)"),
        127 => field!(out, "TX power level: Not available (0x7f)"),
        _ => field!(out, "TX power level: {} dBm (0x{:02x})", level, level as u8),
    };
    mask8(
        "TX power level flag",
        r,
        out,
        &[(0, "Transmit power level is at minimum level"), (1, "Transmit power level is at maximum level")],
        2,
    )?;
    let delta = r.i8()?;
    match delta {
        127 => field!(out, "Delta: Not available (0x7f)"),
        _ => field!(out, "Delta: {} dB (0x{:02x})", delta, delta as u8),
    };
    Ok(())
}

/// LE Subrate Change (7.7.65.35).
fn subrate_change(st: &IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    status(r, out)?;
    handle(st, r, out)?;
    subrate_params(r, out)
}

fn subrate_params(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    u16_hex("Subrate factor", r, out)?;
    u16_hex("Peripheral latency", r, out)?;
    u16_hex("Continuation number", r, out)?;
    timeout_ms("Supervision timeout", r, out, 10)?;
    Ok(())
}

/// LE Connection Rate Change (7.7.65.50).  The interval is in 125 µs units.
fn connection_rate_change(st: &IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    status(r, out)?;
    handle(st, r, out)?;
    interval("Connection interval", r, out, 125)?;
    subrate_params(r, out)
}

/// LE Frame Space Update Complete (7.7.65.48).
fn frame_space_update_complete(st: &IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    status(r, out)?;
    handle(st, r, out)?;
    enum8(
        "Initiator",
        r,
        out,
        &[(0x00, "Local Host initiated"), (0x01, "Local Controller initiated"), (0x02, "Peer initiated")],
    )?;
    usec16("Frame space", r, out)?;
    phy_mask("PHYs", r, out)?;
    mask16(
        "Spacing types",
        r,
        out,
        &[(0, "T_IFS_ACL_CP"), (1, "T_IFS_ACL_PC"), (2, "T_MCES"), (3, "T_IFS_CIS"), (4, "T_MSS_CIS")],
        5,
    )?;
    Ok(())
}

/// LE Read All Remote Features Complete (7.7.65.38).
///
/// The 248-octet feature mask is page 0 (8 octets) followed by ten pages of
/// 24 octets (Vol 6, Part B, Section 4.6).  Pages above `Max_Valid_Page` are
/// only printed when they are not all zero.
fn read_all_remote_features_complete(st: &IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    status(r, out)?;
    handle(st, r, out)?;
    u8_field("Max remote page", r, out)?;
    let valid = u8_field("Max valid page", r, out)?;
    let feats = r.bytes(248)?;
    let mut page0 = Reader::new(&feats[..8]);
    le_features("Features page 0", &mut page0, out, 0)?;
    for page in 1..=10u8 {
        let start = 8 + (page as usize - 1) * 24;
        let bytes = &feats[start..start + 24];
        if page > valid && bytes.iter().all(|&b| b == 0) {
            continue;
        }
        feature_page(out, page, bytes);
    }
    Ok(())
}

/// Print one 24-octet feature page with its bits expanded.
fn feature_page(out: &mut Out, page: u8, bytes: &[u8]) {
    let hex: Vec<String> = bytes.iter().map(|b| format!("0x{b:02x}")).collect();
    field!(out, "Features page {}: {}", page, hex.join(" "));
    out.nest(|o| {
        let mut low = [0u8; 8];
        low.copy_from_slice(&bytes[..8]);
        let mask = u64::from_le_bytes(low);
        match page {
            1 => bits(o, mask, LE_FEATURES_PAGE1, 64),
            _ => bits(o, mask, &[], 64),
        }
        for (i, b) in bytes[8..].iter().enumerate() {
            for bit in 0..8 {
                if b & (1 << bit) != 0 {
                    o.unknown(format!("Unknown bit {}", 64 + i * 8 + bit));
                }
            }
        }
    });
}

// ---------------------------------------------------------------------------
// Advertising and scanning
// ---------------------------------------------------------------------------

/// LE Advertising Report (7.7.65.2): reports are printed flat, one block each.
fn advertising_report(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let n = u8_field("Num reports", r, out)?;
    for _ in 0..n {
        enum8("Event type", r, out, ADV_EVENT_TYPES)?;
        report_addr("Address type", "Address", r, out)?;
        adv_data(r, out)?;
        rssi(r, out)?;
    }
    Ok(())
}

/// LE Directed Advertising Report (7.7.65.11).
fn directed_advertising_report(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let n = u8_field("Num reports", r, out)?;
    for _ in 0..n {
        enum8("Event type", r, out, ADV_EVENT_TYPES)?;
        report_addr("Address type", "Address", r, out)?;
        report_addr("Direct address type", "Direct address", r, out)?;
        rssi(r, out)?;
    }
    Ok(())
}

/// Event type of an extended advertising report: property bits plus data status.
fn ext_adv_event_type(out: &mut Out, flags: u16) {
    field!(out, "Event type: 0x{:04x}", flags);
    out.nest(|o| {
        let props = flags & 0x1f;
        field!(o, "Props: 0x{:04x}", props);
        o.nest(|o| {
            bits(
                o,
                props as u64,
                &[(0, "Connectable"), (1, "Scannable"), (2, "Directed"), (3, "Scan response"), (4, "Use legacy advertising PDUs")],
                5,
            )
        });
        match data_status_str(((flags >> 5) & 0x03) as u8) {
            Some(s) => o.line(format!("Data status: {s}")),
            None => o.unknown("Data status: Reserved"),
        };
        let reserved = flags & !0x7f;
        if reserved != 0 {
            o.unknown(format!("Reserved (0x{reserved:04x})"));
        }
    });
    if flags & 0x10 != 0 {
        let pdu = match flags & 0x1f {
            0x10 => "ADV_NONCONN_IND",
            0x12 => "ADV_SCAN_IND",
            0x13 => "ADV_IND",
            0x15 => "ADV_DIRECT_IND",
            0x1a => "SCAN_RSP to an ADV_SCAN_IND",
            0x1b => "SCAN_RSP to an ADV_IND",
            _ => "Reserved",
        };
        match pdu {
            "Reserved" => out.unknown(format!("Legacy PDU Type: Reserved (0x{flags:04x})")),
            _ => field!(out, "Legacy PDU Type: {} (0x{:04x})", pdu, flags),
        };
    }
}

/// LE Extended Advertising Report (7.7.65.13).
fn extended_advertising_report(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let n = u8_field("Num reports", r, out)?;
    for _ in 0..n {
        let flags = r.u16()?;
        ext_adv_event_type(out, flags);
        report_addr("Address type", "Address", r, out)?;
        let primary = r.u8()?;
        match primary {
            0x01 => out.line("Primary PHY: LE 1M"),
            0x03 => out.line("Primary PHY: LE Coded"),
            0x04 => out.line("Primary PHY: LE Coded with S=2"),
            _ => out.unknown(format!("Primary PHY: Reserved (0x{primary:02x})")),
        };
        let secondary = r.u8()?;
        match secondary {
            0x00 => out.line("Secondary PHY: No packets"),
            0x01 => out.line("Secondary PHY: LE 1M"),
            0x02 => out.line("Secondary PHY: LE 2M"),
            0x03 => out.line("Secondary PHY: LE Coded"),
            0x04 => out.line("Secondary PHY: LE Coded with S=2"),
            _ => out.unknown(format!("Secondary PHY: Reserved (0x{secondary:02x})")),
        };
        adv_sid("SID", r, out, true)?;
        report_tx_power("TX power", r, out)?;
        rssi(r, out)?;
        interval("Periodic advertising interval", r, out, 1250)?;
        report_addr("Direct address type", "Direct address", r, out)?;
        adv_data(r, out)?;
    }
    Ok(())
}

/// LE Advertising Set Terminated (7.7.65.18).
fn advertising_set_terminated(st: &IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    status(r, out)?;
    u8_field("Handle", r, out)?;
    let h = read_handle(r)?;
    match st.conn(h) {
        Some(c) if !c.addr.is_zero() => {
            field!(out, "Connection handle: {} Address: {} ({})", h, c.addr, addr_type_short(c.addr_type, &c.addr))
        }
        _ => field!(out, "Connection handle: {}", h),
    };
    u8_field("Number of completed extended advertising events", r, out)?;
    Ok(())
}

/// LE Scan Request Received (7.7.65.19).
fn scan_request_received(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    u8_field("Handle", r, out)?;
    peer_addr_labelled("Scanner address type", "Scanner address", r, out)?;
    Ok(())
}

/// LE Monitored Advertisers Report (7.7.65.47).
fn monitored_advertisers_report(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    peer_addr(r, out)?;
    enum8(
        "Condition",
        r,
        out,
        &[(0x00, "Left range (RSSI below low threshold or lost)"), (0x01, "Entered range (RSSI above high threshold)")],
    )?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Periodic advertising
// ---------------------------------------------------------------------------

/// Advertiser description shared by Sync Established and Sync Transfer Received.
fn periodic_advertiser(r: &mut Reader<'_>, out: &mut Out, v2: bool) -> Result<()> {
    adv_sid("Advertising SID", r, out, false)?;
    peer_addr_labelled("Advertiser address type", "Advertiser address", r, out)?;
    le_phy("Advertiser PHY", r, out)?;
    interval("Periodic advertising interval", r, out, 1250)?;
    enum8("Advertiser clock accuracy", r, out, CLOCK_ACCURACY_PPM)?;
    if v2 {
        u8_field("Number of subevents", r, out)?;
        let v = r.u8()?;
        interval_value("Subevent interval", out, v as u32, 1250, 2);
        let v = r.u8()?;
        interval_value("Response slot delay", out, v as u32, 1250, 2);
        let v = r.u8()?;
        interval_value("Response slot spacing", out, v as u32, 125, 2);
    }
    Ok(())
}

/// LE Periodic Advertising Sync Established v1 (0x0e) / v2 (0x24) (7.7.65.14).
fn periodic_advertising_sync_established(r: &mut Reader<'_>, out: &mut Out, v2: bool) -> Result<()> {
    status(r, out)?;
    sync_handle(r, out)?;
    periodic_advertiser(r, out, v2)
}

/// LE Periodic Advertising Sync Transfer Received v1 (0x18) / v2 (0x26) (7.7.65.24).
fn periodic_advertising_sync_transfer_received(st: &IndexState, r: &mut Reader<'_>, out: &mut Out, v2: bool) -> Result<()> {
    status(r, out)?;
    handle(st, r, out)?;
    let sd = r.u16()?;
    field!(out, "Service data: 0x{:04x}", sd);
    sync_handle(r, out)?;
    periodic_advertiser(r, out, v2)
}

/// LE Periodic Advertising Report v1 (0x0f) / v2 (0x25) (7.7.65.15).
fn periodic_advertising_report(r: &mut Reader<'_>, out: &mut Out, v2: bool) -> Result<()> {
    sync_handle(r, out)?;
    report_tx_power("TX power", r, out)?;
    rssi(r, out)?;
    enum8("CTE Type", r, out, REPORT_CTE_TYPES)?;
    if v2 {
        u16_hex("Periodic event counter", r, out)?;
        let sub = r.u8()?;
        match sub {
            0xff => field!(out, "Subevent: No subevents (0xff)"),
            _ => field!(out, "Subevent: {}", sub),
        };
    }
    data_status(r, out, "Failed to receive an AUX_SYNC_SUBEVENT_IND PDU")?;
    adv_data(r, out)
}

/// LE Periodic Advertising Subevent Data Request (7.7.65.36).
fn periodic_advertising_subevent_data_request(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    u8_field("Advertising handle", r, out)?;
    u8_field("Subevent start", r, out)?;
    u8_field("Subevent data count", r, out)?;
    Ok(())
}

/// LE Periodic Advertising Response Report (7.7.65.37): responses are printed flat.
fn periodic_advertising_response_report(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    u8_field("Advertising handle", r, out)?;
    u8_field("Subevent", r, out)?;
    enum8(
        "TX status",
        r,
        out,
        &[(0x00, "AUX_SYNC_SUBEVENT_IND packet was transmitted"), (0x01, "AUX_SYNC_SUBEVENT_IND packet was not transmitted")],
    )?;
    let n = u8_field("Num responses", r, out)?;
    for _ in 0..n {
        report_tx_power("TX power", r, out)?;
        rssi(r, out)?;
        enum8("CTE Type", r, out, REPORT_CTE_TYPES)?;
        u8_field("Response slot", r, out)?;
        data_status(r, out, "Failed to receive or listen for an AUX_SYNC_SUBEVENT_RSP PDU")?;
        adv_data(r, out)?;
    }
    Ok(())
}

/// LE BIGInfo Advertising Report (7.7.65.34).
fn biginfo_advertising_report(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    sync_handle(r, out)?;
    u8_field("Number of BIS", r, out)?;
    u8_field("NSE", r, out)?;
    interval("ISO interval", r, out, 1250)?;
    u8_field("BN", r, out)?;
    u8_field("PTO", r, out)?;
    u8_field("IRC", r, out)?;
    u16_field("Maximum PDU", r, out)?;
    usec24("SDU interval", r, out)?;
    u16_field("Maximum SDU", r, out)?;
    le_phy("PHY", r, out)?;
    framing(r, out)?;
    encryption(r, out)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Constant Tone Extension / IQ reports
// ---------------------------------------------------------------------------

/// The fields shared by the connectionless and connection IQ reports, from
/// `RSSI` through the I/Q samples.
fn iq_report_tail(r: &mut Reader<'_>, out: &mut Out, counter_label: &str) -> Result<()> {
    let v = r.i16()?;
    let a = v.unsigned_abs();
    field!(out, "RSSI: {}{}.{} dBm (0x{:04x})", if v < 0 { "-" } else { "" }, a / 10, a % 10, v as u16);
    u8_field("RSSI antenna ID", r, out)?;
    cte_type("CTE type", r, out)?;
    slot_durations(r, out)?;
    enum8(
        "Packet status",
        r,
        out,
        &[
            (0x00, "CRC was correct"),
            (0x01, "CRC was incorrect, Length and CTETime fields used"),
            (0x02, "CRC was incorrect, CTE position determined in some other way"),
            (0xff, "Insufficient resources to sample"),
        ],
    )?;
    u16_hex(counter_label, r, out)?;
    let n = r.u8()? as usize;
    field!(out, "Sample count: {}", n);
    if n == 0 {
        return Ok(());
    }
    let i = r.bytes(n)?;
    let q = r.bytes(n)?;
    let sample = |v: u8| if v == 0x80 { "n/a".to_string() } else { (v as i8).to_string() };
    out.group("IQ samples (I/Q)", |o| {
        for (row, (ci, cq)) in i.chunks(8).zip(q.chunks(8)).enumerate() {
            let mut s = format!("{:2}:", row * 8);
            for (a, b) in ci.iter().zip(cq) {
                s.push_str(&format!(" {}/{}", sample(*a), sample(*b)));
            }
            o.line(s);
        }
    });
    Ok(())
}

/// LE Connectionless IQ Report (7.7.65.21).
fn connectionless_iq_report(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let h = read_handle(r)?;
    match h {
        0x0fff => field!(out, "Sync handle: Receiver test (0x0fff)"),
        _ => field!(out, "Sync handle: {}", h),
    };
    u8_field("Channel index", r, out)?;
    iq_report_tail(r, out, "Periodic event counter")
}

/// LE Connection IQ Report (7.7.65.22).
fn connection_iq_report(st: &IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    handle(st, r, out)?;
    enum8("RX PHY", r, out, &[(0x01, "LE 1M"), (0x02, "LE 2M")])?;
    u8_field("Data channel index", r, out)?;
    iq_report_tail(r, out, "Connection event counter")
}

// ---------------------------------------------------------------------------
// Isochronous streams
// ---------------------------------------------------------------------------

/// LE CIS Established v1 (0x19) / v2 (0x2a) (7.7.65.25).
fn cis_established(st: &mut IndexState, r: &mut Reader<'_>, out: &mut Out, v2: bool) -> Result<()> {
    let s = status(r, out)?;
    let h = read_handle(r)?;
    field!(out, "Connection handle: {}", h);
    usec24("CIG synchronization delay", r, out)?;
    usec24("CIS synchronization delay", r, out)?;
    usec24("Central to Peripheral latency", r, out)?;
    usec24("Peripheral to Central latency", r, out)?;
    le_phy("Central to Peripheral PHY", r, out)?;
    le_phy("Peripheral to Central PHY", r, out)?;
    u8_field("Number of subevents", r, out)?;
    u8_field("Central to Peripheral burst number", r, out)?;
    u8_field("Peripheral to Central burst number", r, out)?;
    u8_field("Central to Peripheral flush timeout", r, out)?;
    u8_field("Peripheral to Central flush timeout", r, out)?;
    u16_field("Central to Peripheral MTU", r, out)?;
    u16_field("Peripheral to Central MTU", r, out)?;
    interval("ISO interval", r, out, 1250)?;
    if v2 {
        usec24("Sub interval", r, out)?;
        u16_field("Central to Peripheral maximum SDU", r, out)?;
        u16_field("Peripheral to Central maximum SDU", r, out)?;
        usec24("Central to Peripheral SDU interval", r, out)?;
        usec24("Peripheral to Central SDU interval", r, out)?;
        framing(r, out)?;
    }
    st.pending_iso.retain(|&p| p != h);
    if s == 0 {
        register_connection(st, h, LinkType::Iso, 0, BdAddr::ZERO, 0);
    }
    Ok(())
}

/// LE CIS Request (7.7.65.26).
fn cis_request(st: &mut IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let acl = read_handle(r)?;
    match st.conn(acl) {
        Some(c) if !c.addr.is_zero() => {
            field!(out, "ACL handle: {} Address: {} ({})", acl, c.addr, addr_type_short(c.addr_type, &c.addr))
        }
        _ => field!(out, "ACL handle: {}", acl),
    };
    let cis = read_handle(r)?;
    field!(out, "CIS handle: {}", cis);
    let cig_id = r.u8()?;
    field!(out, "CIG ID: 0x{:02x}", cig_id);
    let cis_id = r.u8()?;
    field!(out, "CIS ID: 0x{:02x}", cis_id);
    if !st.pending_iso.contains(&cis) {
        st.pending_iso.push(cis);
    }
    Ok(())
}

/// LE Create BIG Complete (7.7.65.27).
fn create_big_complete(st: &mut IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let s = status(r, out)?;
    big_handle(r, out)?;
    usec24("BIG synchronization delay", r, out)?;
    usec24("Transport latency", r, out)?;
    le_phy("PHY", r, out)?;
    big_params(r, out)?;
    bis_handles(st, r, out, s == 0)
}

/// `NSE`, `BN`, `PTO`, `IRC`, `Maximum PDU` and `ISO interval` of BIG events.
fn big_params(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    u8_field("NSE", r, out)?;
    u8_field("BN", r, out)?;
    u8_field("PTO", r, out)?;
    u8_field("IRC", r, out)?;
    u16_field("Maximum PDU", r, out)?;
    interval("ISO interval", r, out, 1250)?;
    Ok(())
}

/// LE Terminate BIG Complete (7.7.65.28) and LE BIG Sync Lost (7.7.65.30).
fn big_handle_reason(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    big_handle(r, out)?;
    reason(r, out)?;
    Ok(())
}

/// LE BIG Sync Established (7.7.65.29).
fn big_sync_established(st: &mut IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let s = status(r, out)?;
    big_handle(r, out)?;
    usec24("Transport latency", r, out)?;
    big_params(r, out)?;
    bis_handles(st, r, out, s == 0)
}

// ---------------------------------------------------------------------------
// Channel Sounding
// ---------------------------------------------------------------------------

static CS_NADM_CAPABILITY: &[(u8, &str)] =
    &[(0, "Phase-based Normalized Attack Detector Metric"), (1, "Amplitude-based Normalized Attack Detector Metric")];

/// LE CS Read Remote Supported Capabilities Complete v1 (0x2c) / v2 (0x38) (7.7.65.39).
fn cs_read_remote_supported_capabilities_complete(st: &IndexState, r: &mut Reader<'_>, out: &mut Out, v2: bool) -> Result<()> {
    status(r, out)?;
    handle(st, r, out)?;
    u8_field("Num config supported", r, out)?;
    u16_field("Max consecutive procedures supported", r, out)?;
    u8_field("Num antennas supported", r, out)?;
    u8_field("Max antenna paths supported", r, out)?;
    mask8("Roles supported", r, out, CS_ROLES, 2)?;
    mask8("Modes supported", r, out, &[(0, "Mode-3")], 1)?;
    mask8(
        "RTT capability",
        r,
        out,
        &[
            (0, "RTT AA Only: 10 ns time-of-flight accuracy"),
            (1, "RTT Sounding: 10 ns time-of-flight accuracy"),
            (2, "RTT Random Sequence: 10 ns time-of-flight accuracy"),
            (3, "RTT 2M AA Only: 10 ns time-of-flight accuracy"),
            (4, "RTT 2M Sounding: 10 ns time-of-flight accuracy"),
            (5, "RTT 2M Random Sequence: 10 ns time-of-flight accuracy"),
        ],
        6,
    )?;
    u8_field("RTT AA Only N", r, out)?;
    u8_field("RTT Sounding N", r, out)?;
    u8_field("RTT Random Sequence N", r, out)?;
    mask16("NADM sounding capability", r, out, CS_NADM_CAPABILITY, 2)?;
    mask16("NADM random capability", r, out, CS_NADM_CAPABILITY, 2)?;
    mask8("CS_SYNC PHYs supported", r, out, &[(1, "LE 2M"), (2, "LE 2M 2BT")], 3)?;
    mask16(
        "Subfeatures supported",
        r,
        out,
        &[
            (1, "CS with no transmitter Frequency Actuation Error"),
            (2, "CS Channel Selection Algorithm #3c"),
            (3, "CS phase-based ranging from RTT sounding sequence"),
            (4, "IPT in the CS reflector"),
            (5, "CS RTT accuracy specified on a per PHY basis"),
        ],
        6,
    )?;
    mask16("T_IP1 times supported", r, out, CS_T_IP_TIMES, 7)?;
    mask16("T_IP2 times supported", r, out, CS_T_IP_TIMES, 7)?;
    mask16("T_FCS times supported", r, out, CS_T_FCS_TIMES, 9)?;
    mask16("T_PM times supported", r, out, CS_T_PM_TIMES, 2)?;
    cs_t_sw_time("T_SW time supported", r, out)?;
    mask8("TX_SNR capability", r, out, CS_TX_SNR, 5)?;
    if v2 {
        mask16("T_IP2_IPT times supported", r, out, CS_T_IP_TIMES, 7)?;
        cs_t_sw_time("T_SW_IPT time supported", r, out)?;
        u8_field("RTT 2M AA Only N", r, out)?;
        u8_field("RTT 2M Sounding N", r, out)?;
        u8_field("RTT 2M Random Sequence N", r, out)?;
    }
    Ok(())
}

/// LE CS Read Remote FAE Table Complete (7.7.65.40).
fn cs_read_remote_fae_table_complete(st: &IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    status(r, out)?;
    handle(st, r, out)?;
    let table = r.bytes(72)?;
    out.group("Remote FAE table:", |o| {
        o.hex(table);
    });
    Ok(())
}

/// LE CS Config Complete (7.7.65.42).
fn cs_config_complete(st: &IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    status(r, out)?;
    handle(st, r, out)?;
    u8_field("Config ID", r, out)?;
    enum8("Action", r, out, &[(0x00, "Removed"), (0x01, "Created")])?;
    enum8("Main mode type", r, out, &[(0x01, "Mode-1"), (0x02, "Mode-2"), (0x03, "Mode-3")])?;
    enum8("Sub mode type", r, out, &[(0x01, "Mode-1"), (0x02, "Mode-2"), (0x03, "Mode-3"), (0xff, "Unused")])?;
    u8_field("Min main mode steps", r, out)?;
    u8_field("Max main mode steps", r, out)?;
    u8_field("Main mode repetition", r, out)?;
    u8_field("Mode 0 steps", r, out)?;
    enum8("Role", r, out, &[(0x00, "Initiator"), (0x01, "Reflector")])?;
    enum8(
        "RTT type",
        r,
        out,
        &[
            (0x00, "RTT AA Only"),
            (0x01, "RTT with 32-bit sounding sequence"),
            (0x02, "RTT with 96-bit sounding sequence"),
            (0x03, "RTT with 32-bit random sequence"),
            (0x04, "RTT with 64-bit random sequence"),
            (0x05, "RTT with 96-bit random sequence"),
            (0x06, "RTT with 128-bit random sequence"),
        ],
    )?;
    enum8("CS_SYNC PHY", r, out, &[(0x01, "LE 1M"), (0x02, "LE 2M"), (0x03, "LE 2M 2BT")])?;
    hex_bytes("Channel map", r, out, 10)?;
    u8_field("Channel map repetition", r, out)?;
    enum8(
        "Channel selection type",
        r,
        out,
        &[(0x00, "Channel Selection Algorithm #3b"), (0x01, "Channel Selection Algorithm #3c")],
    )?;
    enum8("Ch3c shape", r, out, &[(0x00, "Hat shape"), (0x01, "X shape")])?;
    u8_field("Ch3c jump", r, out)?;
    mask8("CS enhancements", r, out, &[(0, "IPT is enabled in the CS reflector")], 1)?;
    for label in ["T_IP1 time", "T_IP2 time", "T_FCS time", "T_PM time"] {
        let v = r.u8()?;
        field!(out, "{}: {} us (0x{:02x})", label, v, v);
    }
    Ok(())
}

/// LE CS Procedure Enable Complete (7.7.65.43).
fn cs_procedure_enable_complete(st: &IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    status(r, out)?;
    handle(st, r, out)?;
    u8_field("Config ID", r, out)?;
    enum8("State", r, out, &[(0x00, "Disabled"), (0x01, "Enabled")])?;
    u8_field("Tone antenna config selection", r, out)?;
    let power = r.i8()?;
    match power {
        127 => field!(out, "Selected TX power: Unavailable (0x7f)"),
        _ => field!(out, "Selected TX power: {} dBm (0x{:02x})", power, power as u8),
    };
    usec24("Subevent length", r, out)?;
    u8_field("Subevents per event", r, out)?;
    interval("Subevent interval", r, out, 625)?;
    u16_field("Event interval", r, out)?;
    u16_field("Procedure interval", r, out)?;
    let count = r.u16()?;
    match count {
        0 => field!(out, "Procedure count: Until disabled (0x0000)"),
        _ => field!(out, "Procedure count: {}", count),
    };
    interval("Max procedure length", r, out, 625)?;
    Ok(())
}

/// A 15-bit signed value in 0.01 ppm units (frequency compensation / offset).
fn cs_ppm(label: &str, out: &mut Out, v: u16) {
    if v == 0xc000 {
        field!(out, "{}: Not available (0xc000)", label);
        return;
    }
    let raw = (v & 0x7fff) as i32;
    let signed = if raw & 0x4000 != 0 { raw - 0x8000 } else { raw };
    let a = signed.abs();
    field!(out, "{}: {}{}.{:02} ppm (0x{:04x})", label, if signed < 0 { "-" } else { "" }, a / 100, a % 100, v);
}

fn cs_done_status(label: &str, r: &mut Reader<'_>, out: &mut Out, kind: &str, aborted: &str) -> Result<u8> {
    let v = r.u8()?;
    match v & 0x0f {
        0x0 => field!(out, "{}: All results complete for the CS {} (0x{:02x})", label, kind, v),
        0x1 => field!(out, "{}: Partial results with more to follow for the CS {} (0x{:02x})", label, kind, v),
        0xf => field!(out, "{}: {} (0x{:02x})", label, aborted, v),
        _ => out.unknown(format!("{label}: Reserved (0x{v:02x})")),
    };
    Ok(v)
}

fn cs_abort_reason(r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    let v = r.u8()?;
    field!(out, "Abort reason: 0x{:02x}", v);
    out.nest(|o| {
        let procedure = match v & 0x0f {
            0x0 => "Report with no abort",
            0x1 => "Abort because of local Host or remote request",
            0x2 => "Abort because filtered channel map has less than 15 channels",
            0x3 => "Abort because the channel map update instant has passed",
            0xf => "Abort because of unspecified reasons",
            _ => "Reserved",
        };
        field!(o, "Procedure: {} (0x{:x})", procedure, v & 0x0f);
        let subevent = match v >> 4 {
            0x0 => "Report with no abort",
            0x1 => "Abort because of local Host or remote request",
            0x2 => "Abort because no CS_SYNC (mode-0) received",
            0x3 => "Abort because of scheduling conflicts or limited resources",
            0xf => "Abort because of unspecified reasons",
            _ => "Reserved",
        };
        field!(o, "Subevent: {} (0x{:x})", subevent, v >> 4);
    });
    Ok(v)
}

/// LE CS Subevent Result (0x31) and LE CS Subevent Result Continue (0x32) (7.7.65.44/45).
fn cs_subevent_result(st: &IndexState, r: &mut Reader<'_>, out: &mut Out, cont: bool) -> Result<()> {
    let h = read_handle(r)?;
    if h == 0x0fff {
        field!(out, "Handle: CS test (0x0fff)");
    } else {
        handle_value(st, out, h);
    }
    u8_field("Config ID", r, out)?;
    if !cont {
        u16_hex("Start ACL connection event counter", r, out)?;
        u16_hex("Procedure counter", r, out)?;
        let v = r.u16()?;
        cs_ppm("Frequency compensation", out, v);
        let p = r.i8()?;
        match p {
            127 => field!(out, "Reference power level: Not applicable (0x7f)"),
            _ => field!(out, "Reference power level: {} dBm (0x{:02x})", p, p as u8),
        };
    }
    cs_done_status("Procedure done status", r, out, "procedure", "All subsequent CS procedures aborted")?;
    cs_done_status("Subevent done status", r, out, "subevent", "Current CS subevent aborted")?;
    cs_abort_reason(r, out)?;
    let paths = u8_field("Num antenna paths", r, out)?;
    let steps = u8_field("Num steps reported", r, out)?;
    for i in 0..steps {
        let mode = r.u8()?;
        let channel = r.u8()?;
        let len = r.u8()? as usize;
        let data = r.bytes(len)?;
        out.group(format!("Step {i}"), |o| {
            field!(o, "Mode: {}", mode);
            field!(o, "Channel: {}", channel);
            field!(o, "Data length: {}", len);
            if !data.is_empty() && !cs_step_data(o, mode, data, paths) {
                o.hex(data);
            }
        });
    }
    Ok(())
}

/// Decode mode/role-specific step data when its length identifies the layout.
/// Returns `false` (having printed nothing) when it does not.
fn cs_step_data(out: &mut Out, mode: u8, data: &[u8], paths: u8) -> bool {
    let tones = 4 * (paths as usize + 1);
    let mut r = Reader::new(data);
    let res = match (mode, data.len()) {
        (0, 3) => cs_mode0(&mut r, out, false),
        (0, 5) => cs_mode0(&mut r, out, true),
        (1, 6) => cs_mode1(&mut r, out, false),
        (1, 14) => cs_mode1(&mut r, out, true),
        (2, n) if n == 1 + tones => cs_mode2(&mut r, out, paths),
        (3, n) if n == 7 + tones => cs_mode1(&mut r, out, false).and_then(|_| cs_mode2(&mut r, out, paths)),
        (3, n) if n == 15 + tones => cs_mode1(&mut r, out, true).and_then(|_| cs_mode2(&mut r, out, paths)),
        _ => return false,
    };
    res.is_ok() && r.is_empty()
}

fn cs_packet_quality(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let v = r.u8()?;
    field!(out, "Packet quality: 0x{:02x}", v);
    out.nest(|o| {
        match v & 0x0f {
            0x0 => o.line("CS Access Address check is successful, and all bits match the expected sequence"),
            0x1 => o.line("CS Access Address check contains one or more bit errors"),
            0x2 => o.line("CS Access Address not found"),
            x => o.unknown(format!("Reserved (0x{x:x})")),
        };
        field!(o, "Bit errors: {}", v >> 4);
    });
    Ok(())
}

fn cs_packet_nadm(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    enum8(
        "Packet NADM",
        r,
        out,
        &[
            (0x00, "Attack is extremely unlikely"),
            (0x01, "Attack is very unlikely"),
            (0x02, "Attack is unlikely"),
            (0x03, "Attack is possible"),
            (0x04, "Attack is likely"),
            (0x05, "Attack is very likely"),
            (0x06, "Attack is extremely likely"),
            (0xff, "Unknown NADM"),
        ],
    )?;
    Ok(())
}

fn cs_packet_rssi(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let v = r.i8()?;
    match v {
        127 => field!(out, "Packet RSSI: Not available (0x7f)"),
        _ => field!(out, "Packet RSSI: {} dBm (0x{:02x})", v, v as u8),
    };
    Ok(())
}

/// Sign-extend a 12-bit I or Q sample.
fn sint12(v: u32) -> i32 {
    let v = (v & 0xfff) as i32;
    if v & 0x800 != 0 {
        v - 0x1000
    } else {
        v
    }
}

fn cs_pct_iq(out: &mut Out, pct: u32) {
    field!(out, "I: {} (0x{:03x})", sint12(pct), pct & 0xfff);
    field!(out, "Q: {} (0x{:03x})", sint12(pct >> 12), (pct >> 12) & 0xfff);
}

/// Mode-0 step data: reflector (3 octets) or initiator (5 octets).
fn cs_mode0(r: &mut Reader<'_>, out: &mut Out, initiator: bool) -> Result<()> {
    cs_packet_quality(r, out)?;
    cs_packet_rssi(r, out)?;
    u8_field("Packet antenna", r, out)?;
    if initiator {
        let v = r.u16()?;
        cs_ppm("Measured frequency offset", out, v);
    }
    Ok(())
}

/// Mode-1 step data (also the first part of mode-3): with or without the sounding PCTs.
fn cs_mode1(r: &mut Reader<'_>, out: &mut Out, pct: bool) -> Result<()> {
    cs_packet_quality(r, out)?;
    cs_packet_nadm(r, out)?;
    cs_packet_rssi(r, out)?;
    let t = r.u16()?;
    match t {
        0x8000 => field!(out, "ToA_ToD: Time difference is not available (0x8000)"),
        _ => field!(out, "ToA_ToD: {} (0x{:04x})", t as i16, t),
    };
    u8_field("Packet antenna", r, out)?;
    if pct {
        for n in 1..=2 {
            let v = r.u32()?;
            if v == 0xffff_ffff {
                field!(out, "Packet PCT{}: Not available (0xffffffff)", n);
            } else {
                field!(out, "Packet PCT{}: 0x{:08x}", n, v);
                out.nest(|o| cs_pct_iq(o, v));
            }
        }
    }
    Ok(())
}

/// Mode-2 step data (also the tail of mode-3): permutation index and one PCT per antenna path.
fn cs_mode2(r: &mut Reader<'_>, out: &mut Out, paths: u8) -> Result<()> {
    u8_field("Antenna path permutation index", r, out)?;
    for k in 0..=paths {
        let pct = r.u24()?;
        let tqi = r.u8()?;
        out.group(format!("Path {k}"), |o| {
            field!(o, "PCT: 0x{:06x}", pct);
            o.nest(|o| cs_pct_iq(o, pct));
            field!(o, "Tone quality indicator: 0x{:02x}", tqi);
            o.nest(|o| {
                match tqi & 0x0f {
                    0x0 => o.line("Tone quality is high (0x0)"),
                    0x1 => o.line("Tone quality is medium (0x1)"),
                    0x2 => o.line("Tone quality is low (0x2)"),
                    0x3 => o.line("Tone quality indication is not available (0x3)"),
                    x => o.unknown(format!("Reserved (0x{x:x})")),
                };
                match tqi >> 4 {
                    0x0 => o.line("Not tone extension slot (0x0)"),
                    0x1 => o.line("Tone extension slot; tone not expected to be present (0x1)"),
                    0x2 => o.line("Tone extension slot; tone expected to be present (0x2)"),
                    x => o.unknown(format!("Reserved (0x{x:x})")),
                };
            });
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Test protocol
// ---------------------------------------------------------------------------

/// LE UTP Receive (7.7.65.49).
fn utp_receive(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let len = r.u8()? as usize;
    field!(out, "Data length: {}", len);
    let data = r.bytes(len)?;
    out.hex(data);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::Node;

    fn run(sub: u8, data: &[u8]) -> (IndexState, Vec<Node>) {
        let mut st = IndexState::default();
        let mut out = Out::new();
        let mut r = Reader::new(data);
        assert!(le_event_params(&mut st, sub, &mut r, &mut out).unwrap(), "subevent 0x{sub:02x} not decoded");
        assert!(r.is_empty(), "{} trailing byte(s) after subevent 0x{sub:02x}", r.remaining());
        (st, out.finish())
    }

    fn texts(nodes: &[Node]) -> Vec<String> {
        nodes.iter().map(|n| n.text.clone()).collect()
    }

    fn child_texts(node: &Node) -> Vec<String> {
        texts(&node.children)
    }

    #[test]
    fn advertising_report_params() {
        let (_, nodes) = run(
            le_evt::ADVERTISING_REPORT,
            &[0x01, 0x00, 0x01, 0x5a, 0x65, 0x27, 0x2e, 0x1d, 0x5e, 0x03, 0x02, 0x01, 0x06, 0xd3],
        );
        let lines = texts(&nodes);
        assert_eq!(
            &lines[..5],
            [
                "Num reports: 1",
                "Event type: Connectable undirected - ADV_IND (0x00)",
                "Address type: Random (0x01)",
                "Address: 5E:1D:2E:27:65:5A (Resolvable)",
                "Data length: 3",
            ]
        );
        assert_eq!(lines.last().unwrap(), "RSSI: -45 dBm (0xd3)");
        assert!(lines.len() > 6, "AD data was not decoded");
    }

    #[test]
    fn extended_advertising_report_legacy_pdu() {
        let mut data = vec![0x01, 0x13, 0x00, 0x01, 0x5a, 0x65, 0x27, 0x2e, 0x1d, 0x5e, 0x01, 0x00, 0xff, 0x7f, 0xd3];
        data.extend_from_slice(&[0x00, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0x00]);
        let (_, nodes) = run(le_evt::EXTENDED_ADVERTISING_REPORT, &data);
        let lines = texts(&nodes);
        assert_eq!(
            lines,
            [
                "Num reports: 1",
                "Event type: 0x0013",
                "Legacy PDU Type: ADV_IND (0x0013)",
                "Address type: Random (0x01)",
                "Address: 5E:1D:2E:27:65:5A (Resolvable)",
                "Primary PHY: LE 1M",
                "Secondary PHY: No packets",
                "SID: no ADI field (0xff)",
                "TX power: not available (0x7f)",
                "RSSI: -45 dBm (0xd3)",
                "Periodic advertising interval: 0.000 msec (0x0000)",
                "Direct address type: Public (0x00)",
                "Direct address: 00:00:00:00:00:00 (OUI 00-00-00)",
                "Data length: 0",
            ]
        );
        let evt = &nodes[1];
        assert_eq!(child_texts(evt), ["Props: 0x0013", "Data status: Complete"]);
        assert_eq!(child_texts(&evt.children[0]), ["Connectable", "Scannable", "Use legacy advertising PDUs"]);
    }

    #[test]
    fn extended_advertising_report_data_status() {
        // Non-legacy, scannable, incomplete (more data to come) with two bytes of data.
        let data = [
            0x01, 0x22, 0x00, 0x00, 1, 2, 3, 4, 5, 6, 0x03, 0x02, 0x02, 0x05, 0xc4, 0x50, 0x00, 0x00, 0, 0, 0, 0, 0, 0,
            0x02, 0x01, 0xff,
        ];
        let (_, nodes) = run(le_evt::EXTENDED_ADVERTISING_REPORT, &data);
        let lines = texts(&nodes);
        assert_eq!(lines[1], "Event type: 0x0022");
        assert_eq!(child_texts(&nodes[1]), ["Props: 0x0002", "Data status: Incomplete, more data to come"]);
        assert!(!lines.iter().any(|l| l.starts_with("Legacy PDU Type")));
        assert_eq!(lines[4], "Primary PHY: LE Coded");
        assert_eq!(lines[5], "Secondary PHY: LE 2M");
        assert_eq!(lines[6], "SID: 0x02");
        assert_eq!(lines[7], "TX power: 5 dBm (0x05)");
        assert_eq!(lines[8], "RSSI: -60 dBm (0xc4)");
        assert_eq!(lines[9], "Periodic advertising interval: 100.000 msec (0x0050)");
    }

    #[test]
    fn connection_update_complete_params() {
        let (_, nodes) = run(le_evt::CONNECTION_UPDATE_COMPLETE, &[0x00, 0x40, 0x00, 0x18, 0x00, 0x00, 0x00, 0x2a, 0x00]);
        assert_eq!(
            texts(&nodes),
            [
                "Status: Success (0x00)",
                "Handle: 64",
                "Connection interval: 30.000 msec (0x0018)",
                "Connection latency: 0 (0x0000)",
                "Supervision timeout: 420 msec (0x002a)",
            ]
        );
    }

    #[test]
    fn long_term_key_request_params() {
        let (_, nodes) = run(le_evt::LONG_TERM_KEY_REQUEST, &[0x40, 0x00, 1, 2, 3, 4, 5, 6, 7, 8, 0x34, 0x12]);
        assert_eq!(texts(&nodes), ["Handle: 64", "Random number: 0x0807060504030201", "Encrypted diversifier: 0x1234"]);
    }

    #[test]
    fn data_length_change_params() {
        let (_, nodes) = run(le_evt::DATA_LENGTH_CHANGE, &[0x40, 0x00, 0xfb, 0x00, 0x48, 0x08, 0xfb, 0x00, 0x48, 0x08]);
        assert_eq!(
            texts(&nodes),
            ["Handle: 64", "Max TX octets: 251", "Max TX time: 2120", "Max RX octets: 251", "Max RX time: 2120"]
        );
    }

    #[test]
    fn phy_update_complete_params() {
        let (_, nodes) = run(le_evt::PHY_UPDATE_COMPLETE, &[0x00, 0x40, 0x00, 0x02, 0x02]);
        assert_eq!(texts(&nodes), ["Status: Success (0x00)", "Handle: 64", "TX PHY: LE 2M (0x02)", "RX PHY: LE 2M (0x02)"]);
    }

    #[test]
    fn read_local_p256_public_key_complete_params() {
        let mut data = vec![0x00];
        data.extend((0u8..64).collect::<Vec<_>>());
        let (_, nodes) = run(le_evt::READ_LOCAL_P_256_PUBLIC_KEY_COMPLETE, &data);
        assert_eq!(texts(&nodes), ["Status: Success (0x00)", "Local P-256 public key:"]);
        let key = child_texts(&nodes[1]);
        assert!(key[0].starts_with("X: 00 01 02"));
        assert!(key[1].starts_with("Y: 20 21 22"));
        assert!(key[1].ends_with(" 3f"));
    }

    #[test]
    fn enhanced_connection_complete_v2_registers_connection() {
        let mut data = vec![0x00, 0x40, 0x00, 0x01, 0x01, 0x5a, 0x65, 0x27, 0x2e, 0x1d, 0x5e];
        data.extend_from_slice(&[0; 12]);
        data.extend_from_slice(&[0x18, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x01, 0xff, 0xff, 0xff]);
        let (st, nodes) = run(ENHANCED_CONNECTION_COMPLETE_V2, &data);
        let lines = texts(&nodes);
        assert_eq!(lines[2], "Role: Peripheral (0x01)");
        assert_eq!(lines[3], "Peer address type: Random (0x01)");
        assert_eq!(lines[5], "Local resolvable private address: 00:00:00:00:00:00 (Non-Resolvable)");
        assert_eq!(lines[10], "Central clock accuracy: 250 ppm (0x01)");
        assert_eq!(lines[11], "Advertising handle: None (0xff)");
        assert_eq!(lines[12], "Sync handle: None (0xffff)");
        let c = st.conn(0x40).expect("connection registered");
        assert_eq!(c.link, LinkType::Le);
        assert_eq!(c.addr_type, 0x01);
        assert_eq!(c.role, 1);
    }

    #[test]
    fn cis_established_v1_registers_iso_link() {
        let data = [
            0x00, 0x03, 0x00, 0x10, 0x27, 0x00, 0x10, 0x27, 0x00, 0x20, 0x4e, 0x00, 0x20, 0x4e, 0x00, 0x02, 0x02, 0x02,
            0x01, 0x01, 0x02, 0x02, 0x64, 0x00, 0x64, 0x00, 0x08, 0x00,
        ];
        let (st, nodes) = run(le_evt::CIS_ESTABLISHED, &data);
        let lines = texts(&nodes);
        assert_eq!(lines[1], "Connection handle: 3");
        assert_eq!(lines[2], "CIG synchronization delay: 10000 us (0x002710)");
        assert_eq!(lines[6], "Central to Peripheral PHY: LE 2M (0x02)");
        assert_eq!(lines[15], "ISO interval: 10.000 msec (0x0008)");
        assert_eq!(st.conn(3).unwrap().link, LinkType::Iso);
    }

    #[test]
    fn create_big_complete_registers_bis_handles() {
        let data = [
            0x00, 0x01, 0x30, 0x00, 0x00, 0x30, 0x00, 0x00, 0x02, 0x03, 0x01, 0x00, 0x01, 0x64, 0x00, 0x08, 0x00, 0x02,
            0x10, 0x00, 0x11, 0x00,
        ];
        let (st, nodes) = run(le_evt::CREATE_BIG_COMPLETE, &data);
        let lines = texts(&nodes);
        assert_eq!(lines[1], "BIG handle: 0x01");
        assert_eq!(lines[4], "PHY: LE 2M (0x02)");
        assert_eq!(lines[11], "Number of BIS: 2");
        assert_eq!(lines[12], "Connection handle #0: 16");
        assert_eq!(lines[13], "Connection handle #1: 17");
        assert_eq!(st.conn(0x10).unwrap().link, LinkType::Iso);
        assert_eq!(st.conn(0x11).unwrap().link, LinkType::Iso);
    }

    #[test]
    fn transmit_power_reporting_params() {
        let (_, nodes) = run(le_evt::TRANSMIT_POWER_REPORTING, &[0x00, 0x40, 0x00, 0x01, 0x03, 0xfc, 0x02, 0x7f]);
        let lines = texts(&nodes);
        assert_eq!(lines[2], "Reason: Remote transmit power changed (0x01)");
        assert_eq!(lines[3], "PHY: LE Coded with S=8 (0x03)");
        assert_eq!(lines[4], "TX power level: -4 dBm (0xfc)");
        assert_eq!(lines[5], "TX power level flag: 0x02");
        assert_eq!(child_texts(&nodes[5]), ["Transmit power level is at maximum level"]);
        assert_eq!(lines[6], "Delta: Not available (0x7f)");
    }

    #[test]
    fn connectionless_iq_report_samples() {
        let mut data = vec![0x05, 0x00, 0x11, 0x3e, 0xfe, 0x01, 0x00, 0x01, 0x00, 0x2a, 0x00, 0x03];
        data.extend_from_slice(&[0x01, 0xff, 0x80]);
        data.extend_from_slice(&[0x02, 0xfe, 0x80]);
        let (_, nodes) = run(le_evt::CONNECTIONLESS_IQ_REPORT, &data);
        let lines = texts(&nodes);
        assert_eq!(lines[0], "Sync handle: 5");
        assert_eq!(lines[1], "Channel index: 17");
        assert_eq!(lines[2], "RSSI: -45.0 dBm (0xfe3e)");
        assert_eq!(lines[4], "CTE type: AoA Constant Tone Extension (0x00)");
        assert_eq!(lines[5], "Slot durations: 1 us (0x01)");
        assert_eq!(lines[6], "Packet status: CRC was correct (0x00)");
        assert_eq!(lines[7], "Periodic event counter: 42 (0x002a)");
        assert_eq!(lines[8], "Sample count: 3");
        assert_eq!(child_texts(&nodes[9]), [" 0: 1/2 -1/-2 n/a/n/a"]);
    }

    #[test]
    fn periodic_advertising_report_v2_params() {
        let data = [0x02, 0x00, 0x7f, 0xd3, 0xff, 0x10, 0x00, 0x03, 0x00, 0x03, 0x02, 0x01, 0x06];
        let (_, nodes) = run(PERIODIC_ADVERTISING_REPORT_V2, &data);
        let lines = texts(&nodes);
        assert_eq!(
            &lines[..8],
            [
                "Sync handle: 2",
                "TX power: not available (0x7f)",
                "RSSI: -45 dBm (0xd3)",
                "CTE Type: No Constant Tone Extension (0xff)",
                "Periodic event counter: 16 (0x0010)",
                "Subevent: 3",
                "Data status: Complete (0x00)",
                "Data length: 3",
            ]
        );
    }

    #[test]
    fn periodic_advertising_sync_established_v2_params() {
        let data = [0x00, 0x02, 0x00, 0x05, 0x00, 1, 2, 3, 4, 5, 6, 0x01, 0x50, 0x00, 0x07, 0x04, 0x06, 0x02, 0x04];
        let (_, nodes) = run(PERIODIC_ADVERTISING_SYNC_ESTABLISHED_V2, &data);
        let lines = texts(&nodes);
        assert_eq!(lines[2], "Advertising SID: 0x05");
        assert_eq!(lines[5], "Advertiser PHY: LE 1M (0x01)");
        assert_eq!(lines[6], "Periodic advertising interval: 100.000 msec (0x0050)");
        assert_eq!(lines[7], "Advertiser clock accuracy: 20 ppm (0x07)");
        assert_eq!(lines[8], "Number of subevents: 4");
        assert_eq!(lines[9], "Subevent interval: 7.500 msec (0x06)");
        assert_eq!(lines[10], "Response slot delay: 2.500 msec (0x02)");
        assert_eq!(lines[11], "Response slot spacing: 0.500 msec (0x04)");
    }

    #[test]
    fn read_all_remote_features_complete_pages() {
        let mut data = vec![0x00, 0x40, 0x00, 0x01, 0x01];
        let mut feats = [0u8; 248];
        feats[0] = 0x01;
        feats[8] = 0x03;
        data.extend_from_slice(&feats);
        let (_, nodes) = run(le_evt::READ_ALL_REMOTE_FEATURES_COMPLETE, &data);
        let lines = texts(&nodes);
        assert_eq!(lines[2], "Max remote page: 1");
        assert_eq!(lines[3], "Max valid page: 1");
        assert!(lines[4].starts_with("Features page 0: 0x01 0x00"));
        assert_eq!(child_texts(&nodes[4]), ["LE Encryption"]);
        assert!(lines[5].starts_with("Features page 1: 0x03 0x00"));
        assert_eq!(child_texts(&nodes[5]), ["Monitoring Advertisers", "Frame Space Update"]);
        assert_eq!(lines.len(), 6, "all-zero pages above Max_Valid_Page must be skipped");
    }

    #[test]
    fn cs_subevent_result_mode0_step() {
        let data = [
            0x40, 0x00, 0x00, 0x05, 0x00, 0x01, 0x00, 0x10, 0x27, 0xf6, 0x00, 0x00, 0x00, 0x01, 0x01, 0x00, 0x20, 0x05,
            0x01, 0xc4, 0x02, 0xc4, 0x09,
        ];
        let (_, nodes) = run(le_evt::CS_SUBEVENT_RESULT, &data);
        let lines = texts(&nodes);
        assert_eq!(lines[4], "Frequency compensation: 100.00 ppm (0x2710)");
        assert_eq!(lines[5], "Reference power level: -10 dBm (0xf6)");
        assert_eq!(lines[6], "Procedure done status: All results complete for the CS procedure (0x00)");
        assert_eq!(lines[10], "Num steps reported: 1");
        let step = &nodes[11];
        assert_eq!(step.text, "Step 0");
        let fields = child_texts(step);
        assert_eq!(fields[0], "Mode: 0");
        assert_eq!(fields[1], "Channel: 32");
        assert_eq!(fields[2], "Data length: 5");
        assert_eq!(fields[3], "Packet quality: 0x01");
        assert_eq!(fields[4], "Packet RSSI: -60 dBm (0xc4)");
        assert_eq!(fields[5], "Packet antenna: 2");
        assert_eq!(fields[6], "Measured frequency offset: 25.00 ppm (0x09c4)");
    }

    #[test]
    fn request_peer_sca_complete_params() {
        let (_, nodes) = run(le_evt::REQUEST_PEER_SCA_COMPLETE, &[0x00, 0x40, 0x00, 0x07]);
        assert_eq!(texts(&nodes), ["Status: Success (0x00)", "Handle: 64", "SCA: 0 - 20 ppm (0x07)"]);
    }

    #[test]
    fn connection_rate_change_uses_125us_units() {
        let data = [0x00, 0x40, 0x00, 0x18, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03, 0x00, 0x2a, 0x00];
        let (_, nodes) = run(le_evt::CONNECTION_RATE_CHANGE, &data);
        let lines = texts(&nodes);
        assert_eq!(lines[2], "Connection interval: 3.000 msec (0x0018)");
        assert_eq!(lines[3], "Subrate factor: 2 (0x0002)");
        assert_eq!(lines[6], "Supervision timeout: 420 msec (0x002a)");
    }

    #[test]
    fn scan_timeout_has_no_params() {
        let (_, nodes) = run(le_evt::SCAN_TIMEOUT, &[]);
        assert!(nodes.is_empty());
    }

    #[test]
    fn unknown_subevent_is_not_decoded() {
        let mut st = IndexState::default();
        let mut out = Out::new();
        let mut r = Reader::new(&[1, 2, 3]);
        assert!(!le_event_params(&mut st, 0xf0, &mut r, &mut out).unwrap());
        assert_eq!(r.remaining(), 3);
    }

    #[test]
    fn truncated_report_is_an_error() {
        let mut st = IndexState::default();
        let mut out = Out::new();
        let mut r = Reader::new(&[0x01, 0x00, 0x01, 0x5a, 0x65]);
        assert!(le_event_params(&mut st, le_evt::ADVERTISING_REPORT, &mut r, &mut out).is_err());
    }
}
