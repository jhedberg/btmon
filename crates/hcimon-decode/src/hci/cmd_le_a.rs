//! LE Controller command decoders, OCF 0x0001 - 0x0060.
//!
//! Covers legacy advertising/scanning/connection setup, encryption, the
//! resolving list, PHY selection, extended and periodic advertising, the
//! periodic advertiser list, direction finding (CTE) and periodic advertising
//! sync transfer.  Return parameters that carry more than a bare status are
//! decoded in [`return_params`].

use super::cmd;
use super::common::*;
use crate::context::IndexState;
use crate::field;
use crate::reader::{Reader, Result};
use crate::tree::Out;

/// Commands in this range that carry no parameters.
static PARAMETERLESS: &[u16] = &[
    cmd::LE_READ_BUFFER_SIZE,
    cmd::LE_READ_LOCAL_SUPPORTED_FEATURES_PAGE_0,
    cmd::LE_READ_ADVERTISING_PHYSICAL_CHANNEL_TX_POWER,
    cmd::LE_CREATE_CONNECTION_CANCEL,
    cmd::LE_READ_FILTER_ACCEPT_LIST_SIZE,
    cmd::LE_CLEAR_FILTER_ACCEPT_LIST,
    cmd::LE_RAND,
    cmd::LE_READ_SUPPORTED_STATES,
    cmd::LE_TEST_END,
    cmd::LE_READ_SUGGESTED_DEFAULT_DATA_LENGTH,
    cmd::LE_READ_LOCAL_P_256_PUBLIC_KEY,
    cmd::LE_CLEAR_RESOLVING_LIST,
    cmd::LE_READ_RESOLVING_LIST_SIZE,
    cmd::LE_READ_MAXIMUM_DATA_LENGTH,
    cmd::LE_READ_MAXIMUM_ADVERTISING_DATA_LENGTH,
    cmd::LE_READ_NUMBER_OF_SUPPORTED_ADVERTISING_SETS,
    cmd::LE_CLEAR_ADVERTISING_SETS,
    cmd::LE_PERIODIC_ADVERTISING_CREATE_SYNC_CANCEL,
    cmd::LE_CLEAR_PERIODIC_ADVERTISER_LIST,
    cmd::LE_READ_PERIODIC_ADVERTISER_LIST_SIZE,
    cmd::LE_READ_TRANSMIT_POWER,
    cmd::LE_READ_RF_PATH_COMPENSATION,
    cmd::LE_READ_ANTENNA_INFORMATION,
    cmd::LE_READ_BUFFER_SIZE_V2,
];

/// Decode command parameters; `Ok(false)` if the opcode is not handled here.
pub fn command_params(st: &mut IndexState, opcode: u16, r: &mut Reader<'_>, out: &mut Out) -> Result<bool> {
    match opcode {
        cmd::LE_SET_EVENT_MASK => le_event_mask(r, out)?,
        cmd::LE_SET_RANDOM_ADDRESS => {
            bdaddr_typed("Address", 0x01, r, out)?;
        }
        cmd::LE_SET_ADVERTISING_PARAMETERS => adv_parameters(r, out)?,
        cmd::LE_SET_ADVERTISING_DATA | cmd::LE_SET_SCAN_RESPONSE_DATA => legacy_adv_data(r, out)?,
        cmd::LE_SET_ADVERTISING_ENABLE => {
            enable("Advertising", r, out)?;
        }
        cmd::LE_SET_SCAN_PARAMETERS => scan_parameters(r, out)?,
        cmd::LE_SET_SCAN_ENABLE => {
            enable("Scanning", r, out)?;
            enable("Filter duplicates", r, out)?;
        }
        cmd::LE_CREATE_CONNECTION => create_connection(r, out)?,
        cmd::LE_ADD_DEVICE_TO_FILTER_ACCEPT_LIST | cmd::LE_REMOVE_DEVICE_FROM_FILTER_ACCEPT_LIST => {
            peer_addr(r, out)?;
        }
        cmd::LE_CONNECTION_UPDATE => {
            handle(st, r, out)?;
            conn_params(r, out)?;
        }
        cmd::LE_SET_HOST_CHANNEL_CLASSIFICATION => le_channel_map(r, out)?,
        cmd::LE_READ_CHANNEL_MAP
        | cmd::LE_READ_REMOTE_FEATURES_PAGE_0
        | cmd::LE_LONG_TERM_KEY_REQUEST_NEGATIVE_REPLY
        | cmd::LE_READ_PHY => {
            handle(st, r, out)?;
        }
        cmd::LE_ENCRYPT => {
            key128("Key", r, out)?;
            key128("Plaintext data", r, out)?;
        }
        cmd::LE_ENABLE_ENCRYPTION => {
            handle(st, r, out)?;
            random_number(r, out)?;
            let ediv = r.u16()?;
            field!(out, "Encrypted diversifier: 0x{:04x}", ediv);
            key128("Long term key", r, out)?;
        }
        cmd::LE_LONG_TERM_KEY_REQUEST_REPLY => {
            handle(st, r, out)?;
            key128("Long term key", r, out)?;
        }
        cmd::LE_RECEIVER_TEST => receiver_test(r, out, 1)?,
        cmd::LE_RECEIVER_TEST_V2 => receiver_test(r, out, 2)?,
        cmd::LE_RECEIVER_TEST_V3 => receiver_test(r, out, 3)?,
        cmd::LE_TRANSMITTER_TEST => transmitter_test(r, out, 1)?,
        cmd::LE_TRANSMITTER_TEST_V2 => transmitter_test(r, out, 2)?,
        cmd::LE_TRANSMITTER_TEST_V3 => transmitter_test(r, out, 3)?,
        cmd::LE_REMOTE_CONNECTION_PARAMETER_REQUEST_REPLY => {
            handle(st, r, out)?;
            conn_params(r, out)?;
        }
        cmd::LE_REMOTE_CONNECTION_PARAMETER_REQUEST_NEGATIVE_REPLY => {
            handle(st, r, out)?;
            reason(r, out)?;
        }
        cmd::LE_SET_DATA_LENGTH => {
            handle(st, r, out)?;
            data_length(r, out)?;
        }
        cmd::LE_WRITE_SUGGESTED_DEFAULT_DATA_LENGTH => data_length(r, out)?,
        cmd::LE_GENERATE_DHKEY => generate_dhkey(r, out, false)?,
        cmd::LE_GENERATE_DHKEY_V2 => generate_dhkey(r, out, true)?,
        cmd::LE_ADD_DEVICE_TO_RESOLVING_LIST => {
            peer_addr(r, out)?;
            key128("Peer identity resolving key", r, out)?;
            key128("Local identity resolving key", r, out)?;
        }
        cmd::LE_REMOVE_DEVICE_FROM_RESOLVING_LIST
        | cmd::LE_READ_PEER_RESOLVABLE_ADDRESS
        | cmd::LE_READ_LOCAL_RESOLVABLE_ADDRESS => {
            peer_addr(r, out)?;
        }
        cmd::LE_SET_ADDRESS_RESOLUTION_ENABLE => {
            enable("Address resolution", r, out)?;
        }
        cmd::LE_SET_RESOLVABLE_PRIVATE_ADDRESS_TIMEOUT => {
            let t = r.u16()?;
            field!(out, "Timeout: {} seconds", t);
        }
        cmd::LE_SET_DEFAULT_PHY => phy_preference(r, out)?,
        cmd::LE_SET_PHY => {
            handle(st, r, out)?;
            phy_preference(r, out)?;
            phy_options(r, out)?;
        }
        cmd::LE_SET_ADVERTISING_SET_RANDOM_ADDRESS => {
            u8_hex("Advertising handle", r, out)?;
            bdaddr_typed("Advertising random address", 0x01, r, out)?;
        }
        cmd::LE_SET_EXTENDED_ADVERTISING_PARAMETERS => ext_adv_parameters(r, out)?,
        cmd::LE_SET_EXTENDED_ADVERTISING_DATA => ext_adv_data(r, out, false)?,
        cmd::LE_SET_EXTENDED_SCAN_RESPONSE_DATA => ext_adv_data(r, out, true)?,
        cmd::LE_SET_EXTENDED_ADVERTISING_ENABLE => ext_adv_enable(r, out)?,
        cmd::LE_REMOVE_ADVERTISING_SET => {
            u8_hex("Handle", r, out)?;
        }
        cmd::LE_SET_PERIODIC_ADVERTISING_PARAMETERS => periodic_adv_parameters(r, out)?,
        cmd::LE_SET_PERIODIC_ADVERTISING_DATA => periodic_adv_data(r, out)?,
        cmd::LE_SET_PERIODIC_ADVERTISING_ENABLE => periodic_adv_enable(r, out)?,
        cmd::LE_SET_EXTENDED_SCAN_PARAMETERS => ext_scan_parameters(r, out)?,
        cmd::LE_SET_EXTENDED_SCAN_ENABLE => ext_scan_enable(r, out)?,
        cmd::LE_EXTENDED_CREATE_CONNECTION => ext_create_connection(r, out)?,
        cmd::LE_PERIODIC_ADVERTISING_CREATE_SYNC => periodic_adv_create_sync(r, out)?,
        cmd::LE_PERIODIC_ADVERTISING_TERMINATE_SYNC => {
            sync_handle(r, out)?;
        }
        cmd::LE_ADD_DEVICE_TO_PERIODIC_ADVERTISER_LIST | cmd::LE_REMOVE_DEVICE_FROM_PERIODIC_ADVERTISER_LIST => {
            peer_addr_labelled("Advertiser address type", "Advertiser address", r, out)?;
            sid(r, out)?;
        }
        cmd::LE_WRITE_RF_PATH_COMPENSATION => {
            rf_path_compensation("RF TX path compensation", r, out)?;
            rf_path_compensation("RF RX path compensation", r, out)?;
        }
        cmd::LE_SET_PRIVACY_MODE => {
            peer_addr_labelled("Peer identity address type", "Peer identity address", r, out)?;
            enum8("Privacy mode", r, out, &[(0x00, "Use Network Privacy"), (0x01, "Use Device Privacy")])?;
        }
        cmd::LE_SET_CONNECTIONLESS_CTE_TRANSMIT_PARAMETERS => {
            u8_hex("Handle", r, out)?;
            cte_length("CTE length", r, out)?;
            cte_type("CTE type", r, out)?;
            u8_field("CTE count", r, out)?;
            switching_pattern(r, out)?;
        }
        cmd::LE_SET_CONNECTIONLESS_CTE_TRANSMIT_ENABLE => {
            u8_hex("Handle", r, out)?;
            enable("CTE transmit", r, out)?;
        }
        cmd::LE_SET_CONNECTIONLESS_IQ_SAMPLING_ENABLE => {
            sync_handle(r, out)?;
            enable("IQ sampling", r, out)?;
            slot_durations(r, out)?;
            let n = r.u8()?;
            match n {
                0 => field!(out, "Max sampled CTEs: All (0x00)"),
                _ => field!(out, "Max sampled CTEs: {} (0x{:02x})", n, n),
            };
            switching_pattern(r, out)?;
        }
        cmd::LE_SET_CONNECTION_CTE_RECEIVE_PARAMETERS => {
            handle(st, r, out)?;
            enable("IQ sampling", r, out)?;
            slot_durations(r, out)?;
            switching_pattern(r, out)?;
        }
        cmd::LE_SET_CONNECTION_CTE_TRANSMIT_PARAMETERS => {
            handle(st, r, out)?;
            let t = r.u8()?;
            field!(out, "CTE types: 0x{:02x}", t);
            out.nest(|o| bits(o, t as u64, CTE_TYPE_BITS, 8));
            switching_pattern(r, out)?;
        }
        cmd::LE_CONNECTION_CTE_REQUEST_ENABLE => {
            handle(st, r, out)?;
            enable("CTE request", r, out)?;
            let i = r.u16()?;
            match i {
                0 => field!(out, "CTE request interval: Once (0x0000)"),
                _ => field!(out, "CTE request interval: {} connection events (0x{:04x})", i, i),
            };
            cte_length("Requested CTE length", r, out)?;
            cte_type("Requested CTE type", r, out)?;
        }
        cmd::LE_CONNECTION_CTE_RESPONSE_ENABLE => {
            handle(st, r, out)?;
            enable("CTE response", r, out)?;
        }
        cmd::LE_SET_PERIODIC_ADVERTISING_RECEIVE_ENABLE => {
            sync_handle(r, out)?;
            let v = r.u8()?;
            match v & 0x01 {
                0 => field!(out, "Reporting: Disabled (0x{:02x})", v),
                _ => field!(out, "Reporting: Enabled (0x{:02x})", v),
            };
            out.nest(|o| {
                if v & 0x02 != 0 {
                    o.line("Duplicate filtering enabled");
                }
                if v & !0x03 != 0 {
                    o.unknown(format!("Reserved bits (0x{:02x})", v & !0x03));
                }
            });
        }
        cmd::LE_PERIODIC_ADVERTISING_SYNC_TRANSFER => {
            handle(st, r, out)?;
            service_data(r, out)?;
            sync_handle(r, out)?;
        }
        cmd::LE_PERIODIC_ADVERTISING_SET_INFO_TRANSFER => {
            handle(st, r, out)?;
            service_data(r, out)?;
            u8_hex("Advertising handle", r, out)?;
        }
        cmd::LE_SET_PERIODIC_ADVERTISING_SYNC_TRANSFER_PARAMETERS => {
            handle(st, r, out)?;
            past_parameters(r, out)?;
        }
        cmd::LE_SET_DEFAULT_PERIODIC_ADVERTISING_SYNC_TRANSFER_PARAMETERS => past_parameters(r, out)?,
        cmd::LE_MODIFY_SLEEP_CLOCK_ACCURACY => {
            enum8(
                "Action",
                r,
                out,
                &[(0x00, "Switch to a more accurate clock"), (0x01, "Switch to a less accurate clock")],
            )?;
        }
        _ if PARAMETERLESS.contains(&opcode) => return Ok(r.is_empty()),
        _ => return Ok(false),
    }
    Ok(true)
}

/// Decode Command Complete return parameters; `Ok(false)` if the opcode is not handled here.
pub fn return_params(st: &mut IndexState, opcode: u16, r: &mut Reader<'_>, out: &mut Out) -> Result<bool> {
    match opcode {
        cmd::LE_READ_BUFFER_SIZE => {
            if status_only(r, out)? {
                return Ok(true);
            }
            u16_field("Data packet length", r, out)?;
            u8_field("Num data packets", r, out)?;
        }
        cmd::LE_READ_BUFFER_SIZE_V2 => {
            if status_only(r, out)? {
                return Ok(true);
            }
            u16_field("ACL MTU", r, out)?;
            u8_field("ACL max packet", r, out)?;
            u16_field("ISO MTU", r, out)?;
            u8_field("ISO max packet", r, out)?;
        }
        cmd::LE_READ_LOCAL_SUPPORTED_FEATURES_PAGE_0 => {
            if status_only(r, out)? {
                return Ok(true);
            }
            le_features("Features", r, out, 0)?;
        }
        cmd::LE_READ_ADVERTISING_PHYSICAL_CHANNEL_TX_POWER => {
            if status_only(r, out)? {
                return Ok(true);
            }
            tx_power("TX power", r, out)?;
        }
        cmd::LE_READ_FILTER_ACCEPT_LIST_SIZE | cmd::LE_READ_RESOLVING_LIST_SIZE => {
            if status_only(r, out)? {
                return Ok(true);
            }
            u8_field("Size", r, out)?;
        }
        cmd::LE_READ_CHANNEL_MAP => {
            if status_only(r, out)? {
                return Ok(true);
            }
            handle(st, r, out)?;
            le_channel_map(r, out)?;
        }
        cmd::LE_ENCRYPT => {
            if status_only(r, out)? {
                return Ok(true);
            }
            key128("Encrypted data", r, out)?;
        }
        cmd::LE_RAND => {
            if status_only(r, out)? {
                return Ok(true);
            }
            random_number(r, out)?;
        }
        cmd::LE_LONG_TERM_KEY_REQUEST_REPLY
        | cmd::LE_LONG_TERM_KEY_REQUEST_NEGATIVE_REPLY
        | cmd::LE_REMOTE_CONNECTION_PARAMETER_REQUEST_REPLY
        | cmd::LE_REMOTE_CONNECTION_PARAMETER_REQUEST_NEGATIVE_REPLY
        | cmd::LE_SET_DATA_LENGTH
        | cmd::LE_SET_CONNECTION_CTE_RECEIVE_PARAMETERS
        | cmd::LE_SET_CONNECTION_CTE_TRANSMIT_PARAMETERS
        | cmd::LE_CONNECTION_CTE_REQUEST_ENABLE
        | cmd::LE_CONNECTION_CTE_RESPONSE_ENABLE
        | cmd::LE_PERIODIC_ADVERTISING_SYNC_TRANSFER
        | cmd::LE_PERIODIC_ADVERTISING_SET_INFO_TRANSFER
        | cmd::LE_SET_PERIODIC_ADVERTISING_SYNC_TRANSFER_PARAMETERS => {
            if status_only(r, out)? {
                return Ok(true);
            }
            handle(st, r, out)?;
        }
        cmd::LE_READ_SUPPORTED_STATES => {
            if status_only(r, out)? {
                return Ok(true);
            }
            le_states(r, out)?;
        }
        cmd::LE_TEST_END => {
            if status_only(r, out)? {
                return Ok(true);
            }
            u16_field("Number of packets", r, out)?;
        }
        cmd::LE_READ_SUGGESTED_DEFAULT_DATA_LENGTH => {
            if status_only(r, out)? {
                return Ok(true);
            }
            data_length(r, out)?;
        }
        cmd::LE_READ_PEER_RESOLVABLE_ADDRESS | cmd::LE_READ_LOCAL_RESOLVABLE_ADDRESS => {
            if status_only(r, out)? {
                return Ok(true);
            }
            bdaddr_typed("Address", 0x01, r, out)?;
        }
        cmd::LE_READ_MAXIMUM_DATA_LENGTH => {
            if status_only(r, out)? {
                return Ok(true);
            }
            u16_field("Max TX octets", r, out)?;
            u16_field("Max TX time", r, out)?;
            u16_field("Max RX octets", r, out)?;
            u16_field("Max RX time", r, out)?;
        }
        cmd::LE_READ_PHY => {
            if status_only(r, out)? {
                return Ok(true);
            }
            handle(st, r, out)?;
            phy("TX PHY", r, out)?;
            phy("RX PHY", r, out)?;
        }
        cmd::LE_SET_EXTENDED_ADVERTISING_PARAMETERS => {
            if status_only(r, out)? {
                return Ok(true);
            }
            tx_power("Selected TX power", r, out)?;
        }
        cmd::LE_READ_MAXIMUM_ADVERTISING_DATA_LENGTH => {
            if status_only(r, out)? {
                return Ok(true);
            }
            u16_field("Max length", r, out)?;
        }
        cmd::LE_READ_NUMBER_OF_SUPPORTED_ADVERTISING_SETS => {
            if status_only(r, out)? {
                return Ok(true);
            }
            u8_field("Num supported adv sets", r, out)?;
        }
        cmd::LE_READ_PERIODIC_ADVERTISER_LIST_SIZE => {
            if status_only(r, out)? {
                return Ok(true);
            }
            u8_field("List size", r, out)?;
        }
        cmd::LE_READ_TRANSMIT_POWER => {
            if status_only(r, out)? {
                return Ok(true);
            }
            tx_power("Min TX power", r, out)?;
            tx_power("Max TX power", r, out)?;
        }
        cmd::LE_READ_RF_PATH_COMPENSATION => {
            if status_only(r, out)? {
                return Ok(true);
            }
            rf_path_compensation("RF TX path compensation", r, out)?;
            rf_path_compensation("RF RX path compensation", r, out)?;
        }
        cmd::LE_SET_CONNECTIONLESS_IQ_SAMPLING_ENABLE => {
            if status_only(r, out)? {
                return Ok(true);
            }
            sync_handle(r, out)?;
        }
        cmd::LE_READ_ANTENNA_INFORMATION => {
            if status_only(r, out)? {
                return Ok(true);
            }
            let rates = r.u8()?;
            field!(out, "Supported switching sampling rates: 0x{:02x}", rates);
            out.nest(|o| {
                bits(
                    o,
                    rates as u64,
                    &[
                        (0, "1 us switching for AoD transmission"),
                        (1, "1 us sampling for AoD reception"),
                        (2, "1 us switching and sampling for AoA reception"),
                    ],
                    8,
                )
            });
            u8_field("Number of antennae", r, out)?;
            u8_field("Max switching pattern length", r, out)?;
            cte_length("Max CTE length", r, out)?;
        }
        _ => return Ok(false),
    }
    Ok(true)
}

// ---------------------------------------------------------------------------
// Tables

/// LE event mask bit names (LE Set Event Mask, Core Specification v6.3 Section 7.8.1).
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

const ST_NONCONN: &str = "Non-connectable Advertising State";
const ST_SCAN: &str = "Scannable Advertising State";
const ST_CONN: &str = "Connectable Advertising State";
const ST_HIGH: &str = "High Duty Cycle Directed Advertising State";
const ST_LOW: &str = "Low Duty Cycle Directed Advertising State";
const ST_PASSIVE: &str = "Passive Scanning State";
const ST_ACTIVE: &str = "Active Scanning State";
const ST_INIT: &str = "Initiating State";
const ST_CENTRAL: &str = "Connection State (Central Role)";
const ST_PERIPH: &str = "Connection State (Peripheral Role)";
const ST_CC: &str = "Central Role & Central Role";
const ST_PP: &str = "Peripheral Role & Peripheral Role";
const ST_CP: &str = "Central Role & Peripheral Role";

/// State combinations of the LE_States bit field (Core Specification v6.3
/// Section 7.8.27 and Vol 6, Part B, Section 1.1.1), one entry per bit.
static LE_STATES: &[&[&str]] = &[
    &[ST_NONCONN],                    // 0
    &[ST_SCAN],                       // 1
    &[ST_CONN],                       // 2
    &[ST_HIGH],                       // 3
    &[ST_PASSIVE],                    // 4
    &[ST_ACTIVE],                     // 5
    &[ST_INIT, ST_CENTRAL],           // 6
    &[ST_PERIPH],                     // 7
    &[ST_NONCONN, ST_PASSIVE],        // 8
    &[ST_SCAN, ST_PASSIVE],           // 9
    &[ST_CONN, ST_PASSIVE],           // 10
    &[ST_HIGH, ST_PASSIVE],           // 11
    &[ST_NONCONN, ST_ACTIVE],         // 12
    &[ST_SCAN, ST_ACTIVE],            // 13
    &[ST_CONN, ST_ACTIVE],            // 14
    &[ST_HIGH, ST_ACTIVE],            // 15
    &[ST_NONCONN, ST_INIT],           // 16
    &[ST_SCAN, ST_INIT],              // 17
    &[ST_NONCONN, ST_CENTRAL],        // 18
    &[ST_SCAN, ST_CENTRAL],           // 19
    &[ST_NONCONN, ST_PERIPH],         // 20
    &[ST_SCAN, ST_PERIPH],            // 21
    &[ST_PASSIVE, ST_INIT],           // 22
    &[ST_ACTIVE, ST_INIT],            // 23
    &[ST_PASSIVE, ST_CENTRAL],        // 24
    &[ST_ACTIVE, ST_CENTRAL],         // 25
    &[ST_PASSIVE, ST_PERIPH],         // 26
    &[ST_ACTIVE, ST_PERIPH],          // 27
    &[ST_INIT, ST_CENTRAL, ST_CC],    // 28
    &[ST_LOW],                        // 29
    &[ST_LOW, ST_PASSIVE],            // 30
    &[ST_LOW, ST_ACTIVE],             // 31
    &[ST_CONN, ST_INIT, ST_CP],       // 32
    &[ST_HIGH, ST_INIT, ST_CP],       // 33
    &[ST_LOW, ST_INIT, ST_CP],        // 34
    &[ST_CONN, ST_CENTRAL, ST_CP],    // 35
    &[ST_HIGH, ST_CENTRAL, ST_CP],    // 36
    &[ST_LOW, ST_CENTRAL, ST_CP],     // 37
    &[ST_CONN, ST_PERIPH, ST_CP],     // 38
    &[ST_HIGH, ST_PERIPH, ST_PP],     // 39
    &[ST_LOW, ST_PERIPH, ST_PP],      // 40
    &[ST_INIT, ST_PERIPH, ST_CP],     // 41
];

static ADV_TYPES: &[(u8, &str)] = &[
    (0x00, "Connectable undirected - ADV_IND"),
    (0x01, "Connectable directed - ADV_DIRECT_IND (high duty cycle)"),
    (0x02, "Scannable undirected - ADV_SCAN_IND"),
    (0x03, "Non connectable undirected - ADV_NONCONN_IND"),
    (0x04, "Connectable directed - ADV_DIRECT_IND (low duty cycle)"),
];

static SCAN_FILTER_POLICIES: &[(u8, &str)] = &[
    (0x00, "Accept all advertisement"),
    (0x01, "Ignore not in accept list"),
    (0x02, "Accept all advertisement, inc. directed unresolved RPA"),
    (0x03, "Ignore not in accept list, exc. directed unresolved RPA"),
];

/// Bit-mask form of [`CTE_TYPES`] (CTE_Types of LE Set Connection CTE Transmit Parameters).
static CTE_TYPE_BITS: &[(u8, &str)] = &[
    (0, "AoA Constant Tone Extension"),
    (1, "AoD Constant Tone Extension with 1 us slots"),
    (2, "AoD Constant Tone Extension with 2 us slots"),
];

/// Sync_CTE_Type / CTE_Type bits of the periodic advertising sync commands.
static SYNC_CTE_TYPE_BITS: &[(u8, &str)] = &[
    (0, "Do not sync to packets with AoA CTE"),
    (1, "Do not sync to packets with AoD CTE 1 us slots"),
    (2, "Do not sync to packets with AoD CTE 2 us slots"),
    (3, "Do not sync to packets with type 3 CTE"),
    (4, "Do not sync to packets without CTE"),
];

static TX_TEST_PAYLOADS: &[(u8, &str)] = &[
    (0x00, "PRBS9 sequence 11111111100000111101..."),
    (0x01, "Repeated 11110000"),
    (0x02, "Repeated 10101010"),
    (0x03, "PRBS15"),
    (0x04, "Repeated 11111111"),
    (0x05, "Repeated 00000000"),
    (0x06, "Repeated 00001111"),
    (0x07, "Repeated 01010101"),
];

static PAST_MODES: &[(u8, &str)] = &[
    (0x00, "Disabled"),
    (0x01, "Enabled with report events disabled"),
    (0x02, "Enabled with report events enabled"),
    (0x03, "Enabled with report events enabled with duplicate filtering"),
];

// ---------------------------------------------------------------------------
// Field helpers private to this module

fn le_event_mask(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let b = r.array::<8>()?;
    let mask = u64::from_le_bytes(b);
    let hex: Vec<String> = b.iter().map(|x| format!("0x{x:02x}")).collect();
    field!(out, "Mask: {}", hex.join(" "));
    out.nest(|o| bits(o, mask, LE_EVENT_MASK_BITS, 64));
    Ok(())
}

fn le_states(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let states = r.u64()?;
    field!(out, "States: 0x{:016x}", states);
    out.nest(|o| {
        let mut unknown = states;
        for (bit, combo) in LE_STATES.iter().enumerate() {
            if states & (1u64 << bit) == 0 {
                continue;
            }
            unknown &= !(1u64 << bit);
            o.group(combo[0], |o| {
                for s in &combo[1..] {
                    o.line(format!("and {s}"));
                }
            });
        }
        if unknown != 0 {
            o.unknown(format!("Unknown states (0x{unknown:016x})"));
        }
    });
    Ok(())
}

fn scan_type(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    enum8(label, r, out, &[(0x00, "Passive"), (0x01, "Active")])
}

/// Scanning filter policy; the extended form also carries the decision PDU mode in bits 2-3.
fn scan_filter_policy(r: &mut Reader<'_>, out: &mut Out, extended: bool) -> Result<u8> {
    let v = r.u8()?;
    let base = crate::assigned::lookup(SCAN_FILTER_POLICIES, v & 0x03).unwrap_or("Reserved");
    let decision = match (extended, (v >> 2) & 0x03) {
        (_, 0b00) => Some(""),
        (true, 0b01) => Some(", All-PDUs decision mode"),
        (true, 0b11) => Some(", Decisions-only mode"),
        _ => None,
    };
    match decision {
        Some(d) if v & !0x0f == 0 => field!(out, "Filter policy: {}{} (0x{:02x})", base, d, v),
        _ => out.unknown(format!("Filter policy: Reserved (0x{v:02x})")),
    };
    Ok(v)
}

fn initiator_filter_policy(r: &mut Reader<'_>, out: &mut Out, extended: bool) -> Result<u8> {
    let names: &[(u8, &str)] = if extended {
        &[
            (0x00, "Accept list is not used"),
            (0x01, "Accept list is used"),
            (0x02, "Accept list is not used, decision PDUs only"),
            (0x03, "Accept list is used, all PDUs"),
            (0x04, "All decision PDUs, accept list for other PDUs"),
        ]
    } else {
        &[(0x00, "Accept list is not used"), (0x01, "Accept list is used")]
    };
    enum8("Filter policy", r, out, names)
}

/// 37-bit LE channel map: `Channel map: 0xffffffff1f` with the enabled channel ranges nested.
fn le_channel_map(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let b = r.array::<5>()?;
    field!(out, "Channel map: 0x{}", hexstr(&b));
    let mask = u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], 0, 0, 0]);
    out.nest(|o| {
        let mut ch = 0u8;
        while ch < 37 {
            if mask & (1u64 << ch) == 0 {
                ch += 1;
                continue;
            }
            let start = ch;
            while ch < 37 && mask & (1u64 << ch) != 0 {
                ch += 1;
            }
            if ch - 1 > start {
                o.line(format!("Channel {}-{}", start, ch - 1));
            } else {
                o.line(format!("Channel {start}"));
            }
        }
        if mask >> 37 != 0 {
            o.unknown(format!("Reserved bits (0x{:02x})", (mask >> 37) << 5));
        }
    });
    Ok(())
}

fn sid(r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    let v = r.u8()?;
    match v {
        0x00..=0x0f => field!(out, "SID: 0x{:02x}", v),
        _ => out.unknown(format!("SID: Reserved (0x{v:02x})")),
    };
    Ok(v)
}

fn service_data(r: &mut Reader<'_>, out: &mut Out) -> Result<u16> {
    let v = r.u16()?;
    field!(out, "Service data: 0x{:04x}", v);
    Ok(v)
}

/// TX octets / TX time pair used by the data length commands.
fn data_length(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    u16_field("TX octets", r, out)?;
    u16_field("TX time", r, out)?;
    Ok(())
}

/// RF path compensation in 0.1 dB units: `RF TX path compensation: -1.5 dB (0xfff1)`.
fn rf_path_compensation(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<i16> {
    let v = r.i16()?;
    let abs = v.unsigned_abs();
    field!(out, "{}: {}{}.{} dB (0x{:04x})", label, if v < 0 { "-" } else { "" }, abs / 10, abs % 10, v as u16);
    Ok(v)
}

fn phy_preference(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let all = r.u8()?;
    field!(out, "All PHYs preference: 0x{:02x}", all);
    out.nest(|o| bits(o, all as u64, &[(0, "No TX PHY preference"), (1, "No RX PHY preference")], 8));
    phy_mask("TX PHYs preference", r, out)?;
    phy_mask("RX PHYs preference", r, out)?;
    Ok(())
}

fn phy_options(r: &mut Reader<'_>, out: &mut Out) -> Result<u16> {
    let v = r.u16()?;
    let name = match v {
        0x0000 => "No preferred coding",
        0x0001 => "S=2 coding",
        0x0002 => "S=8 coding",
        _ => "Reserved",
    };
    match name {
        "Reserved" => out.unknown(format!("PHY options preference: Reserved (0x{v:04x})")),
        _ => field!(out, "PHY options preference: {} (0x{:04x})", name, v),
    };
    Ok(v)
}

fn adv_parameters(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    slots("Min advertising interval", r, out)?;
    slots("Max advertising interval", r, out)?;
    enum8("Type", r, out, ADV_TYPES)?;
    own_addr_type(r, out)?;
    peer_addr_labelled("Direct address type", "Direct address", r, out)?;
    adv_channel_map(r, out)?;
    adv_filter_policy(r, out)?;
    Ok(())
}

/// Legacy advertising / scan response data: a length byte followed by a 31-byte buffer.
fn legacy_adv_data(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let len = r.u8()? as usize;
    field!(out, "Length: {}", len);
    let data = r.rest();
    if data.len() != 31 {
        out.error(format!("Data buffer is {} bytes, expected 31", data.len()));
    }
    if len > data.len() {
        out.error(format!("Length {len} exceeds the {} byte buffer", data.len()));
    }
    crate::ad::decode(&data[..len.min(data.len())], out);
    Ok(())
}

fn scan_parameters(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    scan_type("Type", r, out)?;
    slots("Interval", r, out)?;
    slots("Window", r, out)?;
    own_addr_type(r, out)?;
    scan_filter_policy(r, out, false)?;
    Ok(())
}

fn create_connection(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    slots("Scan interval", r, out)?;
    slots("Scan window", r, out)?;
    initiator_filter_policy(r, out, false)?;
    peer_addr_labelled("Peer address type", "Peer address", r, out)?;
    own_addr_type(r, out)?;
    conn_params(r, out)?;
    Ok(())
}

fn channel_frequency(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    let c = r.u8()?;
    match c {
        0x00..=0x27 => field!(out, "{}: {} MHz (0x{:02x})", label, 2402 + c as u32 * 2, c),
        _ => out.unknown(format!("{label}: Reserved (0x{c:02x})")),
    };
    Ok(c)
}

/// CTE length in 8 µs units; zero means no CTE.
fn cte_length(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    let v = r.u8()?;
    match v {
        0x00 => field!(out, "{}: None (0x00)", label),
        0x02..=0x14 => field!(out, "{}: {} us (0x{:02x})", label, v as u32 * 8, v),
        _ => out.unknown(format!("{label}: Reserved (0x{v:02x})")),
    };
    Ok(v)
}

/// Switching pattern length followed by that many antenna IDs.
fn switching_pattern(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let n = r.u8()?;
    field!(out, "Switching pattern length: {}", n);
    out.nest(|o| -> Result<()> {
        for _ in 0..n {
            let id = r.u8()?;
            o.line(format!("Antenna ID: {id}"));
        }
        Ok(())
    })
}

fn sync_cte_type(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    let v = r.u8()?;
    field!(out, "{}: 0x{:02x}", label, v);
    out.nest(|o| bits(o, v as u64, SYNC_CTE_TYPE_BITS, 8));
    Ok(v)
}

fn receiver_test(r: &mut Reader<'_>, out: &mut Out, version: u8) -> Result<()> {
    channel_frequency("RX channel", r, out)?;
    if version >= 2 {
        phy("PHY", r, out)?;
        enum8("Modulation index", r, out, &[(0x00, "Standard"), (0x01, "Stable")])?;
    }
    if version >= 3 {
        cte_length("Expected CTE length", r, out)?;
        cte_type("Expected CTE type", r, out)?;
        slot_durations(r, out)?;
        switching_pattern(r, out)?;
    }
    Ok(())
}

fn transmitter_test(r: &mut Reader<'_>, out: &mut Out, version: u8) -> Result<()> {
    channel_frequency("TX channel", r, out)?;
    let len = r.u8()?;
    field!(out, "Test data length: {} bytes", len);
    enum8("Packet payload", r, out, TX_TEST_PAYLOADS)?;
    if version >= 2 {
        phy_coded("PHY", r, out)?;
    }
    if version >= 3 {
        cte_length("CTE length", r, out)?;
        cte_type("CTE type", r, out)?;
        switching_pattern(r, out)?;
    }
    Ok(())
}

fn generate_dhkey(r: &mut Reader<'_>, out: &mut Out, v2: bool) -> Result<()> {
    let x = r.bytes(32)?;
    let y = r.bytes(32)?;
    out.group("Remote P-256 public key", |o| {
        o.line(format!("X: {}", hexstr(x)));
        o.line(format!("Y: {}", hexstr(y)));
    });
    if v2 {
        enum8("Key type", r, out, &[(0x00, "Use the generated private key"), (0x01, "Use the debug private key")])?;
    }
    Ok(())
}

fn ext_adv_parameters(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
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
    let skip = r.u8()?;
    field!(out, "Secondary max skip: 0x{:02x}", skip);
    phy("Secondary PHY", r, out)?;
    sid(r, out)?;
    enable("Scan request notifications", r, out)?;
    Ok(())
}

fn ext_adv_data(r: &mut Reader<'_>, out: &mut Out, scan_rsp: bool) -> Result<()> {
    u8_hex("Handle", r, out)?;
    let complete = if scan_rsp { "Complete scan response data" } else { "Complete extended advertising data" };
    enum8(
        "Operation",
        r,
        out,
        &[
            (0x00, "Intermediate fragment"),
            (0x01, "First fragment"),
            (0x02, "Last fragment"),
            (0x03, complete),
            (0x04, "Unchanged data"),
        ],
    )?;
    enum8("Fragment preference", r, out, &[(0x00, "Fragment all"), (0x01, "Minimize fragmentation")])?;
    adv_data(r, out)
}

fn ext_adv_enable(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    enable("Extended advertising", r, out)?;
    let n = r.u8()?;
    match n {
        0x00 => field!(out, "Number of sets: Disable all sets (0x00)"),
        0x01..=0x3f => field!(out, "Number of sets: {} (0x{:02x})", n, n),
        _ => out.unknown(format!("Number of sets: Reserved (0x{n:02x})")),
    };
    for i in 0..n {
        out.group(format!("Entry {i}"), |o| -> Result<()> {
            u8_hex("Handle", r, o)?;
            let d = r.u16()?;
            match d {
                0 => field!(o, "Duration: No limit (0x0000)"),
                _ => field!(o, "Duration: {} msec (0x{:04x})", d as u32 * 10, d),
            };
            let m = r.u8()?;
            match m {
                0 => field!(o, "Max ext adv events: No limit (0x00)"),
                _ => field!(o, "Max ext adv events: {} (0x{:02x})", m, m),
            };
            Ok(())
        })?;
    }
    Ok(())
}

fn periodic_adv_parameters(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    u8_hex("Handle", r, out)?;
    interval("Min interval", r, out, 1250)?;
    interval("Max interval", r, out, 1250)?;
    let p = r.u16()?;
    field!(out, "Properties: 0x{:04x}", p);
    out.nest(|o| bits(o, p as u64, &[(6, "Include TxPower")], 16));
    Ok(())
}

fn periodic_adv_data(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    u8_hex("Handle", r, out)?;
    enum8(
        "Operation",
        r,
        out,
        &[
            (0x00, "Intermediate fragment"),
            (0x01, "First fragment"),
            (0x02, "Last fragment"),
            (0x03, "Complete periodic advertising data"),
            (0x04, "Unchanged data"),
        ],
    )?;
    adv_data(r, out)
}

fn periodic_adv_enable(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let v = r.u8()?;
    match v & 0x01 {
        0 => field!(out, "Periodic advertising: Disabled (0x{:02x})", v),
        _ => field!(out, "Periodic advertising: Enabled (0x{:02x})", v),
    };
    out.nest(|o| {
        if v & 0x02 != 0 {
            o.line("Include ADI");
        }
        if v & !0x03 != 0 {
            o.unknown(format!("Reserved bits (0x{:02x})", v & !0x03));
        }
    });
    u8_hex("Handle", r, out)?;
    Ok(())
}

fn ext_scan_parameters(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    own_addr_type(r, out)?;
    scan_filter_policy(r, out, true)?;
    let phys = r.u8()?;
    field!(out, "PHYs: 0x{:02x}", phys);
    let mut idx = 0;
    for (bit, name) in [(0u8, "LE 1M"), (2, "LE Coded")] {
        if phys & (1 << bit) == 0 {
            continue;
        }
        out.group(format!("Entry {idx}: {name}"), |o| -> Result<()> {
            scan_type("Type", r, o)?;
            slots("Interval", r, o)?;
            slots("Window", r, o)?;
            Ok(())
        })?;
        idx += 1;
    }
    if phys & !0x05 != 0 {
        out.unknown(format!("Unknown scanning PHYs (0x{:02x})", phys & !0x05));
    }
    Ok(())
}

fn ext_scan_enable(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    enable("Extended scan", r, out)?;
    enum8(
        "Filter duplicates",
        r,
        out,
        &[(0x00, "Disabled"), (0x01, "Enabled"), (0x02, "Enabled, reset for each period")],
    )?;
    timeout_ms("Duration", r, out, 10)?;
    let p = r.u16()? as u32;
    field!(out, "Period: {}.{:02} sec (0x{:04x})", p * 128 / 100, p * 128 % 100, p);
    Ok(())
}

fn ext_create_connection(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    initiator_filter_policy(r, out, true)?;
    own_addr_type(r, out)?;
    peer_addr_labelled("Peer address type", "Peer address", r, out)?;
    let phys = r.u8()?;
    field!(out, "Initiating PHYs: 0x{:02x}", phys);
    let mut idx = 0;
    for (bit, name) in [(0u8, "LE 1M"), (1, "LE 2M"), (2, "LE Coded")] {
        if phys & (1 << bit) == 0 {
            continue;
        }
        out.group(format!("Entry {idx}: {name}"), |o| -> Result<()> {
            slots("Scan interval", r, o)?;
            slots("Scan window", r, o)?;
            conn_params(r, o)
        })?;
        idx += 1;
    }
    if phys & !0x07 != 0 {
        out.unknown(format!("Unknown initiating PHYs (0x{:02x})", phys & !0x07));
    }
    Ok(())
}

fn periodic_adv_create_sync(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let opts = r.u8()?;
    field!(out, "Options: 0x{:02x}", opts);
    out.nest(|o| {
        o.line(if opts & 0x01 != 0 {
            "Use Periodic Advertiser List"
        } else {
            "Use advertising SID, advertiser address type and address"
        });
        o.line(if opts & 0x02 != 0 { "Reporting initially disabled" } else { "Reporting initially enabled" });
        o.line(if opts & 0x04 != 0 {
            "Duplicate filtering initially enabled"
        } else {
            "Duplicate filtering initially disabled"
        });
        if opts & !0x07 != 0 {
            o.unknown(format!("Unknown options (0x{:02x})", opts & !0x07));
        }
    });
    sid(r, out)?;
    peer_addr_labelled("Advertiser address type", "Advertiser address", r, out)?;
    u16_hex("Skip", r, out)?;
    timeout_ms("Sync timeout", r, out, 10)?;
    sync_cte_type("Sync CTE type", r, out)?;
    Ok(())
}

/// Mode/skip/timeout/CTE type block of the PAST parameter commands.
fn past_parameters(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    enum8("Mode", r, out, PAST_MODES)?;
    u16_hex("Skip", r, out)?;
    timeout_ms("Sync timeout", r, out, 10)?;
    sync_cte_type("CTE type", r, out)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tree::{Node, Style};

    fn cmd_lines(opcode: u16, data: &[u8]) -> Vec<String> {
        let mut st = IndexState::default();
        let mut out = Out::new();
        let mut r = Reader::new(data);
        assert!(command_params(&mut st, opcode, &mut r, &mut out).unwrap(), "opcode 0x{opcode:04x} not handled");
        assert!(r.is_empty(), "opcode 0x{opcode:04x} left {} bytes", r.remaining());
        flatten(out.roots())
    }

    fn rsp_lines(opcode: u16, data: &[u8]) -> Vec<String> {
        let mut st = IndexState::default();
        let mut out = Out::new();
        let mut r = Reader::new(data);
        assert!(return_params(&mut st, opcode, &mut r, &mut out).unwrap(), "opcode 0x{opcode:04x} not handled");
        assert!(r.is_empty(), "opcode 0x{opcode:04x} left {} bytes", r.remaining());
        flatten(out.roots())
    }

    /// Render the tree as indented lines (two spaces per level).
    fn flatten(nodes: &[Node]) -> Vec<String> {
        let mut lines = Vec::new();
        for n in nodes {
            n.walk(0, &mut |depth, node| lines.push(format!("{}{}", "  ".repeat(depth), node.text)));
        }
        lines
    }

    #[test]
    fn le_set_event_mask_params() {
        let lines = cmd_lines(cmd::LE_SET_EVENT_MASK, &[0x1f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(
            lines,
            [
                "Mask: 0x1f 0x00 0x00 0x00 0x00 0x00 0x00 0x00",
                "  LE Connection Complete",
                "  LE Advertising Report",
                "  LE Connection Update Complete",
                "  LE Read Remote Features Page 0 Complete",
                "  LE Long Term Key Request",
            ]
        );
    }

    #[test]
    fn le_set_advertising_parameters_params() {
        let lines = cmd_lines(
            cmd::LE_SET_ADVERTISING_PARAMETERS,
            &[0x21, 0x00, 0x33, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x07, 0x00],
        );
        assert_eq!(
            lines,
            [
                "Min advertising interval: 20.625 msec (0x0021)",
                "Max advertising interval: 31.875 msec (0x0033)",
                "Type: Connectable undirected - ADV_IND (0x00)",
                "Own address type: Public (0x00)",
                "Direct address type: Public (0x00)",
                "Direct address: 00:00:00:00:00:00",
                "Channel map: 37, 38, 39 (0x07)",
                "Filter policy: Allow Scan Request from Any, Allow Connect Request from Any (0x00)",
            ]
        );
    }

    #[test]
    fn le_set_advertising_data_params() {
        let mut data = vec![0x03, 0x02, 0x01, 0x06];
        data.resize(32, 0);
        let mut st = IndexState::default();
        let mut out = Out::new();
        let mut r = Reader::new(&data);
        assert!(command_params(&mut st, cmd::LE_SET_ADVERTISING_DATA, &mut r, &mut out).unwrap());
        assert!(r.is_empty());
        let roots = out.roots();
        assert_eq!(roots[0].text, "Length: 3");
        // The 3 significant bytes are decoded as AD data without complaint; the padding is ignored.
        assert!(roots.len() >= 2, "AD data was not decoded");
        assert!(roots[1..].iter().all(|n| n.style != Style::Error), "{roots:?}");
    }

    #[test]
    fn le_set_scan_enable_params() {
        assert_eq!(
            cmd_lines(cmd::LE_SET_SCAN_ENABLE, &[0x01, 0x00]),
            ["Scanning: Enabled (0x01)", "Filter duplicates: Disabled (0x00)"]
        );
    }

    #[test]
    fn le_set_scan_parameters_params() {
        assert_eq!(
            cmd_lines(cmd::LE_SET_SCAN_PARAMETERS, &[0x01, 0x11, 0x00, 0x11, 0x00, 0x01, 0x00]),
            [
                "Type: Active (0x01)",
                "Interval: 10.625 msec (0x0011)",
                "Window: 10.625 msec (0x0011)",
                "Own address type: Random (0x01)",
                "Filter policy: Accept all advertisement (0x00)",
            ]
        );
    }

    #[test]
    fn le_create_connection_params() {
        let lines = cmd_lines(
            cmd::LE_CREATE_CONNECTION,
            &[
                0x11, 0x00, 0x11, 0x00, 0x00, 0x01, 0x6e, 0x1d, 0x2e, 0x27, 0x65, 0x4b, 0x00, 0x19, 0x00, 0x19, 0x00,
                0x00, 0x00, 0x90, 0x01, 0x00, 0x00, 0x00, 0x00,
            ],
        );
        assert_eq!(
            lines,
            [
                "Scan interval: 10.625 msec (0x0011)",
                "Scan window: 10.625 msec (0x0011)",
                "Filter policy: Accept list is not used (0x00)",
                "Peer address type: Random (0x01)",
                "Peer address: 4B:65:27:2E:1D:6E (Resolvable)",
                "Own address type: Public (0x00)",
                "Min connection interval: 31.250 msec (0x0019)",
                "Max connection interval: 31.250 msec (0x0019)",
                "Connection latency: 0 (0x0000)",
                "Supervision timeout: 4000 msec (0x0190)",
                "Min connection length: 0.000 msec (0x0000)",
                "Max connection length: 0.000 msec (0x0000)",
            ]
        );
    }

    #[test]
    fn le_read_channel_map_rsp() {
        assert_eq!(
            rsp_lines(cmd::LE_READ_CHANNEL_MAP, &[0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0x1f]),
            ["Status: Success (0x00)", "Handle: 0", "Channel map: 0xffffffff1f", "  Channel 0-36"]
        );
        assert_eq!(
            rsp_lines(cmd::LE_READ_CHANNEL_MAP, &[0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x18]),
            ["Status: Success (0x00)", "Handle: 0", "Channel map: 0x0100000018", "  Channel 0", "  Channel 35-36"]
        );
    }

    #[test]
    fn le_enable_encryption_params() {
        let lines = cmd_lines(
            cmd::LE_ENABLE_ENCRYPTION,
            &[
                0x00, 0x00, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x34, 0x12, 0x4c, 0x68, 0x38, 0x41, 0x39,
                0xf5, 0x74, 0xd8, 0x36, 0xbc, 0xf3, 0x4e, 0x9d, 0xfb, 0x01, 0xbf,
            ],
        );
        assert_eq!(
            lines,
            [
                "Handle: 0",
                "Random number: 0x0102030405060708",
                "Encrypted diversifier: 0x1234",
                "Long term key: 4c68384139f574d836bcf34e9dfb01bf",
            ]
        );
    }

    #[test]
    fn le_long_term_key_request_reply_rsp() {
        assert_eq!(
            rsp_lines(cmd::LE_LONG_TERM_KEY_REQUEST_REPLY, &[0x00, 0x01, 0x00]),
            ["Status: Success (0x00)", "Handle: 1"]
        );
        // A failed command may carry only the status.
        assert_eq!(rsp_lines(cmd::LE_LONG_TERM_KEY_REQUEST_REPLY, &[0x0c]), ["Status: Command Disallowed (0x0c)"]);
    }

    #[test]
    fn le_read_supported_states_rsp() {
        let lines = rsp_lines(cmd::LE_READ_SUPPORTED_STATES, &[0x00, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(
            lines,
            [
                "Status: Success (0x00)",
                "States: 0x0000000000000041",
                "  Non-connectable Advertising State",
                "  Initiating State",
                "    and Connection State (Central Role)",
            ]
        );
        let all = rsp_lines(cmd::LE_READ_SUPPORTED_STATES, &[0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0x03, 0x00, 0x00]);
        assert_eq!(all[1], "States: 0x000003ffffffffff");
        assert!(!all.iter().any(|l| l.contains("Unknown")));
        let bad = rsp_lines(cmd::LE_READ_SUPPORTED_STATES, &[0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00]);
        assert_eq!(bad[2], "  Unknown states (0x0000040000000000)");
    }

    #[test]
    fn le_set_default_phy_params() {
        assert_eq!(
            cmd_lines(cmd::LE_SET_DEFAULT_PHY, &[0x00, 0x03, 0x01]),
            [
                "All PHYs preference: 0x00",
                "TX PHYs preference: 0x03",
                "  LE 1M",
                "  LE 2M",
                "RX PHYs preference: 0x01",
                "  LE 1M",
            ]
        );
    }

    #[test]
    fn le_set_phy_params() {
        assert_eq!(
            cmd_lines(cmd::LE_SET_PHY, &[0x00, 0x00, 0x00, 0x04, 0x04, 0x02, 0x00]),
            [
                "Handle: 0",
                "All PHYs preference: 0x00",
                "TX PHYs preference: 0x04",
                "  LE Coded",
                "RX PHYs preference: 0x04",
                "  LE Coded",
                "PHY options preference: S=8 coding (0x0002)",
            ]
        );
    }

    #[test]
    fn le_set_extended_advertising_parameters_params_and_rsp() {
        let lines = cmd_lines(
            cmd::LE_SET_EXTENDED_ADVERTISING_PARAMETERS,
            &[
                0x00, 0x13, 0x00, 0xa1, 0x00, 0x00, 0xa1, 0x00, 0x00, 0x07, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x7f, 0x01, 0x00, 0x01, 0x00, 0x00,
            ],
        );
        assert_eq!(
            lines,
            [
                "Handle: 0x00",
                "Properties: 0x0013",
                "  Connectable",
                "  Scannable",
                "  Use legacy advertising PDUs: ADV_IND",
                "Min advertising interval: 100.625 msec (0x0000a1)",
                "Max advertising interval: 100.625 msec (0x0000a1)",
                "Channel map: 37, 38, 39 (0x07)",
                "Own address type: Random (0x01)",
                "Peer address type: Public (0x00)",
                "Peer address: 00:00:00:00:00:00",
                "Filter policy: Allow Scan Request from Any, Allow Connect Request from Any (0x00)",
                "TX power: Host has no preference (0x7f)",
                "Primary PHY: LE 1M (0x01)",
                "Secondary max skip: 0x00",
                "Secondary PHY: LE 1M (0x01)",
                "SID: 0x00",
                "Scan request notifications: Disabled (0x00)",
            ]
        );
        assert_eq!(
            rsp_lines(cmd::LE_SET_EXTENDED_ADVERTISING_PARAMETERS, &[0x00, 0x09]),
            ["Status: Success (0x00)", "Selected TX power: 9 dbm (0x09)"]
        );
    }

    #[test]
    fn le_set_extended_advertising_data_params() {
        let lines = cmd_lines(cmd::LE_SET_EXTENDED_ADVERTISING_DATA, &[0x00, 0x03, 0x01, 0x03, 0x02, 0x01, 0x06]);
        assert_eq!(lines[..4].to_vec(), [
            "Handle: 0x00",
            "Operation: Complete extended advertising data (0x03)",
            "Fragment preference: Minimize fragmentation (0x01)",
            "Data length: 3",
        ]);
        assert!(lines.len() >= 5, "AD data was not decoded");
    }

    #[test]
    fn le_set_extended_advertising_enable_params() {
        assert_eq!(
            cmd_lines(cmd::LE_SET_EXTENDED_ADVERTISING_ENABLE, &[0x01, 0x01, 0x00, 0x00, 0x00, 0x00]),
            [
                "Extended advertising: Enabled (0x01)",
                "Number of sets: 1 (0x01)",
                "Entry 0",
                "  Handle: 0x00",
                "  Duration: No limit (0x0000)",
                "  Max ext adv events: No limit (0x00)",
            ]
        );
        assert_eq!(
            cmd_lines(cmd::LE_SET_EXTENDED_ADVERTISING_ENABLE, &[0x00, 0x00]),
            ["Extended advertising: Disabled (0x00)", "Number of sets: Disable all sets (0x00)"]
        );
    }

    #[test]
    fn le_set_extended_scan_parameters_params() {
        assert_eq!(
            cmd_lines(
                cmd::LE_SET_EXTENDED_SCAN_PARAMETERS,
                &[0x00, 0x00, 0x05, 0x01, 0x11, 0x00, 0x11, 0x00, 0x00, 0x21, 0x00, 0x21, 0x00]
            ),
            [
                "Own address type: Public (0x00)",
                "Filter policy: Accept all advertisement (0x00)",
                "PHYs: 0x05",
                "Entry 0: LE 1M",
                "  Type: Active (0x01)",
                "  Interval: 10.625 msec (0x0011)",
                "  Window: 10.625 msec (0x0011)",
                "Entry 1: LE Coded",
                "  Type: Passive (0x00)",
                "  Interval: 20.625 msec (0x0021)",
                "  Window: 20.625 msec (0x0021)",
            ]
        );
    }

    #[test]
    fn le_extended_create_connection_params() {
        let lines = cmd_lines(
            cmd::LE_EXTENDED_CREATE_CONNECTION,
            &[
                0x00, 0x00, 0x00, 0x13, 0x71, 0xda, 0x7d, 0x1a, 0x00, 0x01, 0x11, 0x00, 0x11, 0x00, 0x19, 0x00, 0x19,
                0x00, 0x00, 0x00, 0x90, 0x01, 0x00, 0x00, 0x00, 0x00,
            ],
        );
        assert_eq!(
            lines,
            [
                "Filter policy: Accept list is not used (0x00)",
                "Own address type: Public (0x00)",
                "Peer address type: Public (0x00)",
                "Peer address: 00:1A:7D:DA:71:13 (cyber-blue(HK)Ltd)",
                "Initiating PHYs: 0x01",
                "Entry 0: LE 1M",
                "  Scan interval: 10.625 msec (0x0011)",
                "  Scan window: 10.625 msec (0x0011)",
                "  Min connection interval: 31.250 msec (0x0019)",
                "  Max connection interval: 31.250 msec (0x0019)",
                "  Connection latency: 0 (0x0000)",
                "  Supervision timeout: 4000 msec (0x0190)",
                "  Min connection length: 0.000 msec (0x0000)",
                "  Max connection length: 0.000 msec (0x0000)",
            ]
        );
    }

    #[test]
    fn le_periodic_advertising_create_sync_params() {
        let lines = cmd_lines(
            cmd::LE_PERIODIC_ADVERTISING_CREATE_SYNC,
            &[0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc8, 0x00, 0x10],
        );
        assert_eq!(
            lines,
            [
                "Options: 0x01",
                "  Use Periodic Advertiser List",
                "  Reporting initially enabled",
                "  Duplicate filtering initially disabled",
                "SID: 0x02",
                "Advertiser address type: Public (0x00)",
                "Advertiser address: 00:00:00:00:00:00",
                "Skip: 0 (0x0000)",
                "Sync timeout: 2000 msec (0x00c8)",
                "Sync CTE type: 0x10",
                "  Do not sync to packets without CTE",
            ]
        );
    }

    #[test]
    fn le_receiver_test_v3_params() {
        assert_eq!(
            cmd_lines(cmd::LE_RECEIVER_TEST_V3, &[0x00, 0x01, 0x00, 0x02, 0x00, 0x01, 0x02, 0x01, 0x02]),
            [
                "RX channel: 2402 MHz (0x00)",
                "PHY: LE 1M (0x01)",
                "Modulation index: Standard (0x00)",
                "Expected CTE length: 16 us (0x02)",
                "Expected CTE type: AoA Constant Tone Extension (0x00)",
                "Slot durations: 1 us (0x01)",
                "Switching pattern length: 2",
                "  Antenna ID: 1",
                "  Antenna ID: 2",
            ]
        );
        assert_eq!(cmd_lines(cmd::LE_RECEIVER_TEST, &[0x27]), ["RX channel: 2480 MHz (0x27)"]);
    }

    #[test]
    fn le_transmitter_test_v2_params() {
        assert_eq!(
            cmd_lines(cmd::LE_TRANSMITTER_TEST_V2, &[0x13, 0x25, 0x00, 0x03]),
            [
                "TX channel: 2440 MHz (0x13)",
                "Test data length: 37 bytes",
                "Packet payload: PRBS9 sequence 11111111100000111101... (0x00)",
                "PHY: LE Coded with S=8 (0x03)",
            ]
        );
    }

    #[test]
    fn le_read_buffer_size_rsp() {
        assert_eq!(
            rsp_lines(cmd::LE_READ_BUFFER_SIZE, &[0x00, 0xfb, 0x00, 0x03]),
            ["Status: Success (0x00)", "Data packet length: 251", "Num data packets: 3"]
        );
        assert_eq!(
            rsp_lines(cmd::LE_READ_BUFFER_SIZE_V2, &[0x00, 0xfb, 0x00, 0x03, 0x00, 0x01, 0x02]),
            [
                "Status: Success (0x00)",
                "ACL MTU: 251",
                "ACL max packet: 3",
                "ISO MTU: 256",
                "ISO max packet: 2",
            ]
        );
    }

    #[test]
    fn le_rf_path_compensation() {
        assert_eq!(
            cmd_lines(cmd::LE_WRITE_RF_PATH_COMPENSATION, &[0xf1, 0xff, 0x0a, 0x00]),
            ["RF TX path compensation: -1.5 dB (0xfff1)", "RF RX path compensation: 1.0 dB (0x000a)"]
        );
        assert_eq!(
            rsp_lines(cmd::LE_READ_RF_PATH_COMPENSATION, &[0x00, 0x00, 0x00, 0x00, 0x00]),
            [
                "Status: Success (0x00)",
                "RF TX path compensation: 0.0 dB (0x0000)",
                "RF RX path compensation: 0.0 dB (0x0000)",
            ]
        );
    }

    #[test]
    fn le_read_antenna_information_rsp() {
        assert_eq!(
            rsp_lines(cmd::LE_READ_ANTENNA_INFORMATION, &[0x00, 0x07, 0x04, 0x10, 0x14]),
            [
                "Status: Success (0x00)",
                "Supported switching sampling rates: 0x07",
                "  1 us switching for AoD transmission",
                "  1 us sampling for AoD reception",
                "  1 us switching and sampling for AoA reception",
                "Number of antennae: 4",
                "Max switching pattern length: 16",
                "Max CTE length: 160 us (0x14)",
            ]
        );
    }

    #[test]
    fn le_periodic_advertising_sync_transfer_parameters() {
        assert_eq!(
            cmd_lines(
                cmd::LE_SET_PERIODIC_ADVERTISING_SYNC_TRANSFER_PARAMETERS,
                &[0x01, 0x00, 0x02, 0x05, 0x00, 0xc8, 0x00, 0x00]
            ),
            [
                "Handle: 1",
                "Mode: Enabled with report events enabled (0x02)",
                "Skip: 5 (0x0005)",
                "Sync timeout: 2000 msec (0x00c8)",
                "CTE type: 0x00",
            ]
        );
        assert_eq!(
            rsp_lines(cmd::LE_SET_PERIODIC_ADVERTISING_SYNC_TRANSFER_PARAMETERS, &[0x00, 0x01, 0x00]),
            ["Status: Success (0x00)", "Handle: 1"]
        );
    }

    #[test]
    fn unhandled_and_parameterless() {
        let mut st = IndexState::default();
        let mut out = Out::new();
        // An opcode outside this file's range is not claimed.
        let mut r = Reader::new(&[0x00]);
        assert!(!command_params(&mut st, cmd::LE_SET_CIG_PARAMETERS, &mut r, &mut out).unwrap());
        // A parameterless command is claimed only when it really has no parameters.
        let mut r = Reader::new(&[]);
        assert!(command_params(&mut st, cmd::LE_READ_ANTENNA_INFORMATION, &mut r, &mut out).unwrap());
        let mut r = Reader::new(&[0x01]);
        assert!(!command_params(&mut st, cmd::LE_READ_ANTENNA_INFORMATION, &mut r, &mut out).unwrap());
        assert!(out.is_empty());
    }
}
