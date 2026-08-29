//! BR/EDR command decoders: Link Control (OGF 1), Link Policy (OGF 2), Controller & Baseband (OGF 3), Informational (OGF 4), Status (OGF 5) and Testing (OGF 6).
//!
//! Parameter layouts follow Core Specification v6.3, Vol 4, Part E, Sections
//! 7.1 to 7.6; the labels follow btmon so that output reads the same.

use super::cmd;
use super::common::*;
use crate::context::IndexState;
use crate::field;
use crate::reader::{Reader, Result};
use crate::tree::Out;

/// Decode command parameters; `Ok(false)` if the opcode is not handled here.
pub fn command_params(st: &mut IndexState, opcode: u16, r: &mut Reader<'_>, out: &mut Out) -> Result<bool> {
    match opcode {
        // --- Link Control (OGF 1) ---------------------------------------------------------
        cmd::INQUIRY => {
            iac(r, out)?;
            inquiry_length("Length", r, out)?;
            num_responses(r, out)?;
        }
        cmd::PERIODIC_INQUIRY_MODE => {
            inquiry_period("Max period", r, out)?;
            inquiry_period("Min period", r, out)?;
            iac(r, out)?;
            inquiry_length("Length", r, out)?;
            num_responses(r, out)?;
        }
        cmd::CREATE_CONNECTION => {
            bdaddr("Address", r, out)?;
            pkt_type_acl(r, out)?;
            pscan_rep_mode(r, out)?;
            pscan_mode(r, out)?;
            clock_offset(r, out)?;
            enum8("Role switch", r, out, &[(0x00, "Stay central"), (0x01, "Allow peripheral")])?;
        }
        cmd::DISCONNECT => {
            handle(st, r, out)?;
            reason(r, out)?;
        }
        cmd::ADD_SCO_CONNECTION => {
            handle(st, r, out)?;
            pkt_type_sco(r, out)?;
        }
        cmd::CREATE_CONNECTION_CANCEL
        | cmd::LINK_KEY_REQUEST_NEGATIVE_REPLY
        | cmd::PIN_CODE_REQUEST_NEGATIVE_REPLY
        | cmd::REMOTE_NAME_REQUEST_CANCEL
        | cmd::USER_CONFIRMATION_REQUEST_REPLY
        | cmd::USER_CONFIRMATION_REQUEST_NEGATIVE_REPLY
        | cmd::USER_PASSKEY_REQUEST_NEGATIVE_REPLY
        | cmd::REMOTE_OOB_DATA_REQUEST_NEGATIVE_REPLY
        | cmd::TRUNCATED_PAGE_CANCEL => {
            bdaddr("Address", r, out)?;
        }
        cmd::ACCEPT_CONNECTION_REQUEST => {
            bdaddr("Address", r, out)?;
            role(r, out)?;
        }
        cmd::REJECT_CONNECTION_REQUEST | cmd::REJECT_SYNCHRONOUS_CONNECTION_REQUEST | cmd::IO_CAPABILITY_REQUEST_NEGATIVE_REPLY => {
            bdaddr("Address", r, out)?;
            reason(r, out)?;
        }
        cmd::LINK_KEY_REQUEST_REPLY => {
            bdaddr("Address", r, out)?;
            key128("Link key", r, out)?;
        }
        cmd::PIN_CODE_REQUEST_REPLY => {
            bdaddr("Address", r, out)?;
            let len = r.u8()?;
            field!(out, "PIN length: {}", len);
            pin_code(r, out, len)?;
        }
        cmd::CHANGE_CONNECTION_PACKET_TYPE => {
            handle(st, r, out)?;
            pkt_type_acl(r, out)?;
        }
        cmd::AUTHENTICATION_REQUESTED
        | cmd::CHANGE_CONNECTION_LINK_KEY
        | cmd::READ_REMOTE_SUPPORTED_FEATURES
        | cmd::READ_REMOTE_VERSION_INFORMATION
        | cmd::READ_CLOCK_OFFSET
        | cmd::READ_LMP_HANDLE
        | cmd::EXIT_SNIFF_MODE
        | cmd::EXIT_PARK_STATE
        | cmd::ROLE_DISCOVERY
        | cmd::READ_LINK_POLICY_SETTINGS
        | cmd::FLUSH
        | cmd::READ_AUTOMATIC_FLUSH_TIMEOUT
        | cmd::READ_LINK_SUPERVISION_TIMEOUT
        | cmd::REFRESH_ENCRYPTION_KEY
        | cmd::READ_AUTHENTICATED_PAYLOAD_TIMEOUT
        | cmd::READ_FAILED_CONTACT_COUNTER
        | cmd::RESET_FAILED_CONTACT_COUNTER
        | cmd::READ_LINK_QUALITY
        | cmd::READ_RSSI
        | cmd::READ_AFH_CHANNEL_MAP
        | cmd::READ_ENCRYPTION_KEY_SIZE => {
            handle(st, r, out)?;
        }
        cmd::SET_CONNECTION_ENCRYPTION => {
            handle(st, r, out)?;
            enum8("Encryption", r, out, &[(0x00, "Disabled"), (0x01, "Enabled")])?;
        }
        cmd::LINK_KEY_SELECTION => {
            enum8("Key flag", r, out, &[(0x00, "Semi-permanent"), (0x01, "Temporary")])?;
        }
        cmd::REMOTE_NAME_REQUEST => {
            bdaddr("Address", r, out)?;
            pscan_rep_mode(r, out)?;
            pscan_mode(r, out)?;
            clock_offset(r, out)?;
        }
        cmd::READ_REMOTE_EXTENDED_FEATURES => {
            handle(st, r, out)?;
            u8_field("Page", r, out)?;
        }
        cmd::SETUP_SYNCHRONOUS_CONNECTION => {
            handle(st, r, out)?;
            sync_conn_params(r, out)?;
        }
        cmd::ACCEPT_SYNCHRONOUS_CONNECTION_REQUEST => {
            bdaddr("Address", r, out)?;
            sync_conn_params(r, out)?;
        }
        cmd::IO_CAPABILITY_REQUEST_REPLY => {
            bdaddr("Address", r, out)?;
            io_capability(r, out)?;
            enum8(
                "OOB data",
                r,
                out,
                &[
                    (0x00, "Authentication data not present"),
                    (0x01, "P-192 authentication data present"),
                    (0x02, "P-256 authentication data present"),
                    (0x03, "P-192 and P-256 authentication data present"),
                ],
            )?;
            authentication(r, out)?;
        }
        cmd::USER_PASSKEY_REQUEST_REPLY => {
            bdaddr("Address", r, out)?;
            let passkey = r.u32()?;
            field!(out, "Passkey: {:06}", passkey);
        }
        cmd::REMOTE_OOB_DATA_REQUEST_REPLY => {
            bdaddr("Address", r, out)?;
            key128("Hash C from P-192", r, out)?;
            key128("Randomizer R with P-192", r, out)?;
        }
        cmd::ENHANCED_SETUP_SYNCHRONOUS_CONNECTION => {
            handle(st, r, out)?;
            enhanced_sync_conn_params(r, out)?;
        }
        cmd::ENHANCED_ACCEPT_SYNCHRONOUS_CONNECTION_REQUEST => {
            bdaddr("Address", r, out)?;
            enhanced_sync_conn_params(r, out)?;
        }
        cmd::TRUNCATED_PAGE => {
            bdaddr("Address", r, out)?;
            pscan_rep_mode(r, out)?;
            clock_offset(r, out)?;
        }
        cmd::SET_CONNECTIONLESS_PERIPHERAL_BROADCAST => {
            enable("Enable", r, out)?;
            lt_addr(r, out)?;
            lpo_allowed(r, out)?;
            pkt_type_acl(r, out)?;
            slots("Min interval", r, out)?;
            slots("Max interval", r, out)?;
            slots("Supervision timeout", r, out)?;
        }
        cmd::SET_CONNECTIONLESS_PERIPHERAL_BROADCAST_RECEIVE => {
            enable("Enable", r, out)?;
            bdaddr("Address", r, out)?;
            lt_addr(r, out)?;
            slots("Interval", r, out)?;
            let offset = r.u32()?;
            field!(out, "Clock offset: 0x{:08x}", offset);
            let instant = r.u32()?;
            field!(out, "Next broadcast instant: 0x{:08x}", instant);
            slots("Supervision timeout", r, out)?;
            let acc = r.u8()?;
            field!(out, "Remote timing accuracy: {} ppm", acc);
            let skip = r.u8()?;
            field!(out, "Skip: 0x{:02x}", skip);
            pkt_type_acl(r, out)?;
            afh_channel_map(r, out)?;
        }
        cmd::RECEIVE_SYNCHRONIZATION_TRAIN => {
            bdaddr("Address", r, out)?;
            slots("Timeout", r, out)?;
            slots("Window", r, out)?;
            slots("Interval", r, out)?;
        }
        cmd::REMOTE_OOB_EXTENDED_DATA_REQUEST_REPLY => {
            bdaddr("Address", r, out)?;
            key128("Hash C from P-192", r, out)?;
            key128("Randomizer R with P-192", r, out)?;
            key128("Hash C from P-256", r, out)?;
            key128("Randomizer R with P-256", r, out)?;
        }

        // --- Link Policy (OGF 2) ----------------------------------------------------------
        cmd::HOLD_MODE => {
            handle(st, r, out)?;
            slots("Max interval", r, out)?;
            slots("Min interval", r, out)?;
        }
        cmd::SNIFF_MODE => {
            handle(st, r, out)?;
            slots("Max interval", r, out)?;
            slots("Min interval", r, out)?;
            interval("Attempt", r, out, 1250)?;
            interval("Timeout", r, out, 1250)?;
        }
        cmd::PARK_STATE => {
            handle(st, r, out)?;
            slots("Max interval", r, out)?;
            slots("Min interval", r, out)?;
        }
        cmd::QOS_SETUP => {
            handle(st, r, out)?;
            let flags = r.u8()?;
            field!(out, "Flags: 0x{:02x}", flags);
            service_type(r, out)?;
            u32_field("Token rate", r, out)?;
            u32_field("Peak bandwidth", r, out)?;
            u32_field("Latency", r, out)?;
            u32_field("Delay variation", r, out)?;
        }
        cmd::SWITCH_ROLE => {
            bdaddr("Address", r, out)?;
            role(r, out)?;
        }
        cmd::WRITE_LINK_POLICY_SETTINGS => {
            handle(st, r, out)?;
            link_policy(r, out)?;
        }
        cmd::WRITE_DEFAULT_LINK_POLICY_SETTINGS => {
            link_policy(r, out)?;
        }
        cmd::FLOW_SPECIFICATION => {
            handle(st, r, out)?;
            let flags = r.u8()?;
            field!(out, "Flags: 0x{:02x}", flags);
            enum8("Flow direction", r, out, &[(0x00, "Outgoing"), (0x01, "Incoming")])?;
            service_type(r, out)?;
            u32_field("Token rate", r, out)?;
            u32_field("Token bucket size", r, out)?;
            u32_field("Peak bandwidth", r, out)?;
            u32_field("Access latency", r, out)?;
        }
        cmd::SNIFF_SUBRATING => {
            handle(st, r, out)?;
            slots("Max latency", r, out)?;
            slots("Min remote timeout", r, out)?;
            slots("Min local timeout", r, out)?;
        }

        // --- Controller & Baseband (OGF 3) ------------------------------------------------
        cmd::SET_EVENT_MASK => {
            event_mask(r, out, EVENT_MASK_BITS)?;
        }
        cmd::SET_EVENT_FILTER => {
            set_event_filter(r, out)?;
        }
        cmd::WRITE_PIN_TYPE => {
            pin_type(r, out)?;
        }
        cmd::READ_STORED_LINK_KEY => {
            bdaddr("Address", r, out)?;
            enum8("Read all", r, out, &[(0x00, "Only specified address"), (0x01, "All stored keys")])?;
        }
        cmd::WRITE_STORED_LINK_KEY => {
            let n = r.u8()?;
            field!(out, "Num keys: {}", n);
            for _ in 0..n {
                bdaddr("Address", r, out)?;
                key128("Link key", r, out)?;
            }
        }
        cmd::DELETE_STORED_LINK_KEY => {
            bdaddr("Address", r, out)?;
            enum8("Delete all", r, out, &[(0x00, "Only specified address"), (0x01, "All stored keys")])?;
        }
        cmd::WRITE_LOCAL_NAME => {
            name("Name", r, out, 248)?;
        }
        cmd::WRITE_CONNECTION_ACCEPT_TIMEOUT | cmd::WRITE_PAGE_TIMEOUT | cmd::WRITE_EXTENDED_PAGE_TIMEOUT => {
            slots("Timeout", r, out)?;
        }
        cmd::WRITE_SCAN_ENABLE => {
            scan_enable(r, out)?;
        }
        cmd::WRITE_PAGE_SCAN_ACTIVITY | cmd::WRITE_INQUIRY_SCAN_ACTIVITY => {
            slots("Interval", r, out)?;
            slots("Window", r, out)?;
        }
        cmd::WRITE_AUTHENTICATION_ENABLE => {
            auth_enable(r, out)?;
        }
        cmd::WRITE_ENCRYPTION_MODE => {
            encrypt_mode(r, out)?;
        }
        cmd::WRITE_CLASS_OF_DEVICE => {
            class_of_device(r, out)?;
        }
        cmd::WRITE_VOICE_SETTING => {
            voice_setting(r, out)?;
        }
        cmd::WRITE_AUTOMATIC_FLUSH_TIMEOUT => {
            handle(st, r, out)?;
            flush_timeout(r, out)?;
        }
        cmd::WRITE_NUM_BROADCAST_RETRANSMISSIONS => {
            u8_field("Number of broadcast retransmissions", r, out)?;
        }
        cmd::WRITE_HOLD_MODE_ACTIVITY => {
            hold_mode_activity(r, out)?;
        }
        cmd::READ_TRANSMIT_POWER_LEVEL | cmd::READ_ENHANCED_TRANSMIT_POWER_LEVEL => {
            handle(st, r, out)?;
            enum8("Type", r, out, &[(0x00, "Current Transmit Power Level"), (0x01, "Maximum Transmit Power Level")])?;
        }
        cmd::WRITE_SYNCHRONOUS_FLOW_CONTROL_ENABLE => {
            enable("Flow control", r, out)?;
        }
        cmd::SET_CONTROLLER_TO_HOST_FLOW_CONTROL => {
            host_flow_control(r, out)?;
        }
        cmd::HOST_BUFFER_SIZE => {
            u16_field("ACL MTU", r, out)?;
            u8_field("SCO MTU", r, out)?;
            u16_field("ACL max packet", r, out)?;
            u16_field("SCO max packet", r, out)?;
        }
        cmd::HOST_NUMBER_OF_COMPLETED_PACKETS => {
            let n = r.u8()?;
            field!(out, "Num handles: {}", n);
            for _ in 0..n {
                handle(st, r, out)?;
                u16_field("Count", r, out)?;
            }
        }
        cmd::WRITE_LINK_SUPERVISION_TIMEOUT => {
            handle(st, r, out)?;
            slots("Timeout", r, out)?;
        }
        cmd::WRITE_CURRENT_IAC_LAP => {
            iac_list(r, out)?;
        }
        cmd::WRITE_PAGE_SCAN_PERIOD_MODE => {
            pscan_period_mode(r, out)?;
        }
        cmd::WRITE_PAGE_SCAN_MODE => {
            pscan_mode(r, out)?;
        }
        cmd::SET_AFH_HOST_CHANNEL_CLASSIFICATION => {
            channel_classification(r, out)?;
        }
        cmd::WRITE_INQUIRY_SCAN_TYPE | cmd::WRITE_PAGE_SCAN_TYPE => {
            scan_type(r, out)?;
        }
        cmd::WRITE_INQUIRY_MODE => {
            inquiry_mode(r, out)?;
        }
        cmd::WRITE_AFH_CHANNEL_ASSESSMENT_MODE => {
            afh_assessment_mode(r, out)?;
        }
        cmd::WRITE_EXTENDED_INQUIRY_RESPONSE => {
            eir(r, out)?;
        }
        cmd::WRITE_SIMPLE_PAIRING_MODE => {
            enable("Mode", r, out)?;
        }
        cmd::WRITE_INQUIRY_TRANSMIT_POWER_LEVEL => {
            power_dbm("TX power", r, out)?;
        }
        cmd::WRITE_DEFAULT_ERRONEOUS_DATA_REPORTING => {
            enable("Mode", r, out)?;
        }
        cmd::ENHANCED_FLUSH => {
            handle(st, r, out)?;
            enum8("Type", r, out, &[(0x00, "Automatic flushable only")])?;
        }
        cmd::SEND_KEYPRESS_NOTIFICATION => {
            bdaddr("Address", r, out)?;
            enum8(
                "Type",
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
        }
        cmd::SET_EVENT_MASK_PAGE_2 => {
            event_mask(r, out, EVENT_MASK_PAGE2_BITS)?;
        }
        cmd::WRITE_FLOW_CONTROL_MODE => {
            flow_control_mode(r, out)?;
        }
        cmd::WRITE_LE_HOST_SUPPORT => {
            enable("Supported", r, out)?;
            enable("Simultaneous", r, out)?;
        }
        cmd::SET_MWS_CHANNEL_PARAMETERS => {
            enable("Channel", r, out)?;
            let v = r.u16()?;
            field!(out, "RX center frequency: {} MHz", v);
            let v = r.u16()?;
            field!(out, "TX center frequency: {} MHz", v);
            let v = r.u16()?;
            field!(out, "RX channel bandwidth: {} kHz", v);
            let v = r.u16()?;
            field!(out, "TX channel bandwidth: {} kHz", v);
            enum8("Channel type", r, out, &[(0x00, "TDD"), (0x01, "FDD")])?;
        }
        cmd::SET_EXTERNAL_FRAME_CONFIGURATION => {
            usec_u16("Frame duration", r, out)?;
            usec_i16("Frame sync assert offset", r, out)?;
            usec_u16("Frame sync assert jitter", r, out)?;
            let n = r.u8()?;
            field!(out, "Number of periods: {}", n);
            let mut durations = Vec::with_capacity(n as usize);
            for _ in 0..n {
                durations.push(r.u16()?);
            }
            for (i, d) in durations.iter().enumerate() {
                let t = r.u8()?;
                out.group(format!("Period {}", i + 1), |o| {
                    field!(o, "Duration: {} usec", d);
                    enum8_value(
                        "Type",
                        o,
                        t,
                        &[(0x00, "Downlink"), (0x01, "Uplink"), (0x02, "Bi-Directional"), (0x03, "Guard Period")],
                    );
                });
            }
        }
        cmd::SET_MWS_SIGNALING => {
            for label in [
                "RX assert offset",
                "RX assert jitter",
                "RX deassert offset",
                "RX deassert jitter",
                "TX assert offset",
                "TX assert jitter",
                "TX deassert offset",
                "TX deassert jitter",
                "Pattern assert offset",
                "Pattern assert jitter",
                "Inactivity duration assert offset",
                "Inactivity duration assert jitter",
                "Scan frequency assert offset",
                "Scan frequency assert jitter",
                "Priority assert offset request",
            ] {
                if label.ends_with("jitter") {
                    usec_u16(label, r, out)?;
                } else {
                    usec_i16(label, r, out)?;
                }
            }
        }
        cmd::SET_MWS_TRANSPORT_LAYER => {
            mws_transport_layer(r, out)?;
            u32_field("To MWS baud rate", r, out)?;
            u32_field("From MWS baud rate", r, out)?;
        }
        cmd::SET_MWS_SCAN_FREQUENCY_TABLE => {
            let n = r.u8()?;
            field!(out, "Number of scan frequencies: {}", n);
            let mut lows = Vec::with_capacity(n as usize);
            for _ in 0..n {
                lows.push(r.u16()?);
            }
            for (i, low) in lows.iter().enumerate() {
                let high = r.u16()?;
                field!(out, "Scan frequency {}: {} MHz to {} MHz", i + 1, low, high);
            }
        }
        cmd::SET_MWS_PATTERN_CONFIGURATION => {
            u8_field("Pattern index", r, out)?;
            let n = r.u8()?;
            field!(out, "Number of intervals: {}", n);
            let mut durations = Vec::with_capacity(n as usize);
            for _ in 0..n {
                durations.push(r.u16()?);
            }
            for (i, d) in durations.iter().enumerate() {
                let t = r.u8()?;
                out.group(format!("Interval {}", i + 1), |o| {
                    field!(o, "Duration: {} usec", d);
                    enum8_value(
                        "Type",
                        o,
                        t,
                        &[
                            (0x00, "Neither transmission nor reception allowed"),
                            (0x01, "Transmission allowed"),
                            (0x02, "Reception allowed"),
                            (0x03, "Transmission and reception allowed"),
                            (0x04, "MWS frame interval"),
                        ],
                    );
                });
            }
        }
        cmd::SET_RESERVED_LT_ADDR | cmd::DELETE_RESERVED_LT_ADDR => {
            lt_addr(r, out)?;
        }
        cmd::SET_CONNECTIONLESS_PERIPHERAL_BROADCAST_DATA => {
            lt_addr(r, out)?;
            enum8(
                "Fragment",
                r,
                out,
                &[
                    (0x00, "Continuation fragment"),
                    (0x01, "Starting fragment"),
                    (0x02, "Ending fragment"),
                    (0x03, "No fragmentation"),
                ],
            )?;
            let len = r.u8()?;
            field!(out, "Data length: {}", len);
            let data = r.bytes(len as usize)?;
            out.hex_field("Data", data);
        }
        cmd::WRITE_SYNCHRONIZATION_TRAIN_PARAMETERS => {
            slots("Min interval", r, out)?;
            slots("Max interval", r, out)?;
            sync_train_timeout(r, out)?;
            let sd = r.u8()?;
            field!(out, "Service data: 0x{:02x}", sd);
        }
        cmd::WRITE_SECURE_CONNECTIONS_HOST_SUPPORT => {
            enable("Support", r, out)?;
        }
        cmd::WRITE_AUTHENTICATED_PAYLOAD_TIMEOUT => {
            handle(st, r, out)?;
            timeout_ms("Timeout", r, out, 10)?;
        }
        cmd::WRITE_EXTENDED_INQUIRY_LENGTH => {
            slots("Interval", r, out)?;
        }
        cmd::SET_ECOSYSTEM_BASE_INTERVAL => {
            interval("Interval", r, out, 1250)?;
        }
        cmd::CONFIGURE_DATA_PATH => {
            path_direction("Direction", r, out)?;
            u8_field("ID", r, out)?;
            let len = r.u8()?;
            field!(out, "Vendor specific config length: {}", len);
            let cfg = r.bytes(len as usize)?;
            out.hex_field("Vendor specific config", cfg);
        }
        cmd::SET_MIN_ENCRYPTION_KEY_SIZE => {
            let v = r.u8()?;
            field!(out, "Key size: {}", v);
        }

        // --- Informational (OGF 4) --------------------------------------------------------
        cmd::READ_LOCAL_EXTENDED_FEATURES => {
            u8_field("Page", r, out)?;
        }
        cmd::READ_LOCAL_SUPPORTED_CODEC_CAPABILITIES => {
            codec_id("Codec", r, out)?;
            logical_transport_type(r, out)?;
            path_direction("Direction", r, out)?;
        }
        cmd::READ_LOCAL_SUPPORTED_CONTROLLER_DELAY => {
            codec_id("Codec", r, out)?;
            logical_transport_type(r, out)?;
            path_direction("Direction", r, out)?;
            let len = r.u8()?;
            field!(out, "Codec configuration length: {}", len);
            let cfg = r.bytes(len as usize)?;
            out.hex_field("Codec configuration", cfg);
        }

        // --- Status (OGF 5) ---------------------------------------------------------------
        cmd::READ_CLOCK => {
            handle(st, r, out)?;
            clock_type(r, out)?;
        }
        cmd::SET_TRIGGERED_CLOCK_CAPTURE => {
            handle(st, r, out)?;
            enable("Capture", r, out)?;
            clock_type(r, out)?;
            lpo_allowed(r, out)?;
            u8_field("Clock captures to filter", r, out)?;
        }

        // --- Testing (OGF 6) --------------------------------------------------------------
        cmd::WRITE_LOOPBACK_MODE => {
            loopback_mode(r, out)?;
        }
        cmd::WRITE_SIMPLE_PAIRING_DEBUG_MODE => {
            enable("Debug mode", r, out)?;
        }
        cmd::WRITE_SECURE_CONNECTIONS_TEST_MODE => {
            handle(st, r, out)?;
            enable("DM1 ACL-U mode", r, out)?;
            enable("eSCO loopback mode", r, out)?;
        }

        _ => return Ok(false),
    }
    Ok(true)
}

/// Decode Command Complete return parameters; `Ok(false)` if the opcode is not handled here.
pub fn return_params(st: &mut IndexState, opcode: u16, r: &mut Reader<'_>, out: &mut Out) -> Result<bool> {
    match opcode {
        // --- Link Control (OGF 1) ---------------------------------------------------------
        cmd::CREATE_CONNECTION_CANCEL
        | cmd::LINK_KEY_REQUEST_REPLY
        | cmd::LINK_KEY_REQUEST_NEGATIVE_REPLY
        | cmd::PIN_CODE_REQUEST_REPLY
        | cmd::PIN_CODE_REQUEST_NEGATIVE_REPLY
        | cmd::REMOTE_NAME_REQUEST_CANCEL
        | cmd::IO_CAPABILITY_REQUEST_REPLY
        | cmd::USER_CONFIRMATION_REQUEST_REPLY
        | cmd::USER_CONFIRMATION_REQUEST_NEGATIVE_REPLY
        | cmd::USER_PASSKEY_REQUEST_REPLY
        | cmd::USER_PASSKEY_REQUEST_NEGATIVE_REPLY
        | cmd::REMOTE_OOB_DATA_REQUEST_REPLY
        | cmd::REMOTE_OOB_DATA_REQUEST_NEGATIVE_REPLY
        | cmd::IO_CAPABILITY_REQUEST_NEGATIVE_REPLY
        | cmd::TRUNCATED_PAGE_CANCEL
        | cmd::REMOTE_OOB_EXTENDED_DATA_REQUEST_REPLY
        | cmd::SEND_KEYPRESS_NOTIFICATION => {
            status(r, out)?;
            bdaddr("Address", r, out)?;
        }
        cmd::READ_LMP_HANDLE => {
            status(r, out)?;
            handle(st, r, out)?;
            u8_field("LMP handle", r, out)?;
            let reserved = r.u32()?;
            field!(out, "Reserved: 0x{:08x}", reserved);
        }
        cmd::SET_CONNECTIONLESS_PERIPHERAL_BROADCAST => {
            status(r, out)?;
            lt_addr(r, out)?;
            slots("Interval", r, out)?;
        }
        cmd::SET_CONNECTIONLESS_PERIPHERAL_BROADCAST_RECEIVE => {
            status(r, out)?;
            bdaddr("Address", r, out)?;
            lt_addr(r, out)?;
        }

        // --- Link Policy (OGF 2) ----------------------------------------------------------
        cmd::ROLE_DISCOVERY => {
            status(r, out)?;
            handle(st, r, out)?;
            role(r, out)?;
        }
        cmd::READ_LINK_POLICY_SETTINGS => {
            status(r, out)?;
            handle(st, r, out)?;
            link_policy(r, out)?;
        }
        cmd::WRITE_LINK_POLICY_SETTINGS
        | cmd::SNIFF_SUBRATING
        | cmd::FLUSH
        | cmd::WRITE_AUTOMATIC_FLUSH_TIMEOUT
        | cmd::WRITE_LINK_SUPERVISION_TIMEOUT
        | cmd::WRITE_AUTHENTICATED_PAYLOAD_TIMEOUT
        | cmd::RESET_FAILED_CONTACT_COUNTER
        | cmd::WRITE_SECURE_CONNECTIONS_TEST_MODE => {
            status(r, out)?;
            handle(st, r, out)?;
        }
        cmd::READ_DEFAULT_LINK_POLICY_SETTINGS => {
            status(r, out)?;
            link_policy(r, out)?;
        }

        // --- Controller & Baseband (OGF 3) ------------------------------------------------
        cmd::READ_PIN_TYPE => {
            status(r, out)?;
            pin_type(r, out)?;
        }
        cmd::READ_STORED_LINK_KEY => {
            status(r, out)?;
            u16_field("Max num keys", r, out)?;
            u16_field("Num keys", r, out)?;
        }
        cmd::WRITE_STORED_LINK_KEY => {
            status(r, out)?;
            u8_field("Num keys", r, out)?;
        }
        cmd::DELETE_STORED_LINK_KEY => {
            status(r, out)?;
            u16_field("Num keys", r, out)?;
        }
        cmd::READ_LOCAL_NAME => {
            status(r, out)?;
            let n = name("Name", r, out, 248)?;
            if st.name.is_empty() {
                st.name = n;
            }
        }
        cmd::READ_CONNECTION_ACCEPT_TIMEOUT | cmd::READ_PAGE_TIMEOUT | cmd::READ_EXTENDED_PAGE_TIMEOUT => {
            status(r, out)?;
            slots("Timeout", r, out)?;
        }
        cmd::READ_SCAN_ENABLE => {
            status(r, out)?;
            scan_enable(r, out)?;
        }
        cmd::READ_PAGE_SCAN_ACTIVITY | cmd::READ_INQUIRY_SCAN_ACTIVITY => {
            status(r, out)?;
            slots("Interval", r, out)?;
            slots("Window", r, out)?;
        }
        cmd::READ_AUTHENTICATION_ENABLE => {
            status(r, out)?;
            auth_enable(r, out)?;
        }
        cmd::READ_ENCRYPTION_MODE => {
            status(r, out)?;
            encrypt_mode(r, out)?;
        }
        cmd::READ_CLASS_OF_DEVICE => {
            status(r, out)?;
            class_of_device(r, out)?;
        }
        cmd::READ_VOICE_SETTING => {
            status(r, out)?;
            voice_setting(r, out)?;
        }
        cmd::READ_AUTOMATIC_FLUSH_TIMEOUT => {
            status(r, out)?;
            handle(st, r, out)?;
            flush_timeout(r, out)?;
        }
        cmd::READ_NUM_BROADCAST_RETRANSMISSIONS => {
            status(r, out)?;
            u8_field("Number of broadcast retransmissions", r, out)?;
        }
        cmd::READ_HOLD_MODE_ACTIVITY => {
            status(r, out)?;
            hold_mode_activity(r, out)?;
        }
        cmd::READ_TRANSMIT_POWER_LEVEL => {
            status(r, out)?;
            handle(st, r, out)?;
            power_dbm("TX power", r, out)?;
        }
        cmd::READ_SYNCHRONOUS_FLOW_CONTROL_ENABLE => {
            status(r, out)?;
            enable("Flow control", r, out)?;
        }
        cmd::READ_LINK_SUPERVISION_TIMEOUT => {
            status(r, out)?;
            handle(st, r, out)?;
            slots("Timeout", r, out)?;
        }
        cmd::READ_NUMBER_OF_SUPPORTED_IAC => {
            status(r, out)?;
            u8_field("Number of IAC", r, out)?;
        }
        cmd::READ_CURRENT_IAC_LAP => {
            status(r, out)?;
            iac_list(r, out)?;
        }
        cmd::READ_PAGE_SCAN_PERIOD_MODE => {
            status(r, out)?;
            pscan_period_mode(r, out)?;
        }
        cmd::READ_PAGE_SCAN_MODE => {
            status(r, out)?;
            pscan_mode(r, out)?;
        }
        cmd::READ_INQUIRY_SCAN_TYPE | cmd::READ_PAGE_SCAN_TYPE => {
            status(r, out)?;
            scan_type(r, out)?;
        }
        cmd::READ_INQUIRY_MODE => {
            status(r, out)?;
            inquiry_mode(r, out)?;
        }
        cmd::READ_AFH_CHANNEL_ASSESSMENT_MODE => {
            status(r, out)?;
            afh_assessment_mode(r, out)?;
        }
        cmd::READ_EXTENDED_INQUIRY_RESPONSE => {
            status(r, out)?;
            eir(r, out)?;
        }
        cmd::READ_SIMPLE_PAIRING_MODE => {
            status(r, out)?;
            enable("Mode", r, out)?;
        }
        cmd::READ_LOCAL_OOB_DATA => {
            status(r, out)?;
            key128("Hash C from P-192", r, out)?;
            key128("Randomizer R with P-192", r, out)?;
        }
        cmd::READ_INQUIRY_RESPONSE_TRANSMIT_POWER_LEVEL => {
            status(r, out)?;
            power_dbm("TX power", r, out)?;
        }
        cmd::READ_DEFAULT_ERRONEOUS_DATA_REPORTING => {
            status(r, out)?;
            enable("Mode", r, out)?;
        }
        cmd::READ_FLOW_CONTROL_MODE => {
            status(r, out)?;
            flow_control_mode(r, out)?;
        }
        cmd::READ_ENHANCED_TRANSMIT_POWER_LEVEL => {
            status(r, out)?;
            handle(st, r, out)?;
            power_dbm("TX power (GFSK)", r, out)?;
            power_dbm("TX power (DQPSK)", r, out)?;
            power_dbm("TX power (8DPSK)", r, out)?;
        }
        cmd::READ_LE_HOST_SUPPORT => {
            status(r, out)?;
            enable("Supported", r, out)?;
            enable("Simultaneous", r, out)?;
        }
        cmd::SET_MWS_SIGNALING => {
            status(r, out)?;
            for label in [
                "Bluetooth RX priority assert offset",
                "Bluetooth RX priority assert jitter",
                "Bluetooth RX priority deassert offset",
                "Bluetooth RX priority deassert jitter",
                "802 RX priority assert offset",
                "802 RX priority assert jitter",
                "802 RX priority deassert offset",
                "802 RX priority deassert jitter",
                "Bluetooth TX on assert offset",
                "Bluetooth TX on assert jitter",
                "Bluetooth TX on deassert offset",
                "Bluetooth TX on deassert jitter",
                "802 TX on assert offset",
                "802 TX on assert jitter",
                "802 TX on deassert offset",
                "802 TX on deassert jitter",
            ] {
                if label.ends_with("jitter") {
                    usec_u16(label, r, out)?;
                } else {
                    usec_i16(label, r, out)?;
                }
            }
        }
        cmd::SET_RESERVED_LT_ADDR | cmd::DELETE_RESERVED_LT_ADDR | cmd::SET_CONNECTIONLESS_PERIPHERAL_BROADCAST_DATA => {
            status(r, out)?;
            lt_addr(r, out)?;
        }
        cmd::READ_SYNCHRONIZATION_TRAIN_PARAMETERS => {
            status(r, out)?;
            slots("Interval", r, out)?;
            sync_train_timeout(r, out)?;
            let sd = r.u8()?;
            field!(out, "Service data: 0x{:02x}", sd);
        }
        cmd::WRITE_SYNCHRONIZATION_TRAIN_PARAMETERS => {
            status(r, out)?;
            slots("Interval", r, out)?;
        }
        cmd::READ_SECURE_CONNECTIONS_HOST_SUPPORT => {
            status(r, out)?;
            enable("Support", r, out)?;
        }
        cmd::READ_AUTHENTICATED_PAYLOAD_TIMEOUT => {
            status(r, out)?;
            handle(st, r, out)?;
            timeout_ms("Timeout", r, out, 10)?;
        }
        cmd::READ_LOCAL_OOB_EXTENDED_DATA => {
            status(r, out)?;
            key128("Hash C from P-192", r, out)?;
            key128("Randomizer R with P-192", r, out)?;
            key128("Hash C from P-256", r, out)?;
            key128("Randomizer R with P-256", r, out)?;
        }
        cmd::READ_EXTENDED_INQUIRY_LENGTH => {
            status(r, out)?;
            slots("Interval", r, out)?;
        }

        // --- Informational (OGF 4) --------------------------------------------------------
        cmd::READ_LOCAL_VERSION_INFORMATION => {
            status(r, out)?;
            let hci = r.u8()?;
            let rev = r.u16()?;
            field!(out, "HCI version: {} (0x{:02x}) - Revision {} (0x{:04x})", version_str(hci), hci, rev, rev);
            let lmp = r.u8()?;
            let m = r.u16()?;
            let sub = r.u16()?;
            field!(out, "LMP version: {} (0x{:02x}) - Subversion {} (0x{:04x})", version_str(lmp), lmp, sub, sub);
            manufacturer_value("Manufacturer", out, m);
            if st.manufacturer.is_none() {
                st.manufacturer = Some(m);
            }
        }
        cmd::READ_LOCAL_SUPPORTED_COMMANDS | cmd::READ_LOCAL_SUPPORTED_COMMANDS_V2 => {
            status(r, out)?;
            supported_commands(r.rest(), out);
        }
        cmd::READ_LOCAL_SUPPORTED_FEATURES => {
            status(r, out)?;
            lmp_features("Features", r, out, 0)?;
        }
        cmd::READ_LOCAL_EXTENDED_FEATURES => {
            status(r, out)?;
            let page = r.u8()?;
            let max = r.u8()?;
            field!(out, "Page: {}/{}", page, max);
            lmp_features("Features", r, out, page)?;
        }
        cmd::READ_BUFFER_SIZE => {
            status(r, out)?;
            u16_field("ACL MTU", r, out)?;
            u8_field("SCO MTU", r, out)?;
            u16_field("ACL max packet", r, out)?;
            u16_field("SCO max packet", r, out)?;
        }
        cmd::READ_BD_ADDR => {
            status(r, out)?;
            let a = bdaddr("Address", r, out)?;
            if st.addr.is_zero() {
                st.addr = a;
            }
        }
        cmd::READ_DATA_BLOCK_SIZE => {
            status(r, out)?;
            u16_field("Max ACL length", r, out)?;
            u16_field("Block length", r, out)?;
            u16_field("Num blocks", r, out)?;
        }
        cmd::READ_LOCAL_SUPPORTED_CODECS => {
            status(r, out)?;
            let n = r.u8()?;
            field!(out, "Number of supported codecs: {}", n);
            for _ in 0..n {
                let id = r.u8()?;
                out.nest(|o| codec_id_value("Codec", o, id));
            }
            let n = r.u8()?;
            field!(out, "Number of vendor codecs: {}", n);
            for _ in 0..n {
                let company = r.u16()?;
                let vid = r.u16()?;
                out.nest(|o| {
                    manufacturer_value("Company", o, company);
                    field!(o, "Vendor codec ID: 0x{:04x}", vid);
                });
            }
        }
        cmd::READ_LOCAL_SIMPLE_PAIRING_OPTIONS => {
            status(r, out)?;
            let opts = r.u8()?;
            field!(out, "Pairing options: 0x{:02x}", opts);
            out.nest(|o| bits(o, opts as u64, &[(0, "Remote public key validation is always performed")], 8));
            let size = r.u8()?;
            field!(out, "Max encryption key size: {} octets", size);
        }
        cmd::READ_LOCAL_SUPPORTED_CODECS_V2 => {
            status(r, out)?;
            let n = r.u8()?;
            field!(out, "Number of supported codecs: {}", n);
            for _ in 0..n {
                let id = r.u8()?;
                let transport = r.u8()?;
                out.nest(|o| {
                    codec_id_value("Codec", o, id);
                    o.nest(|o| codec_transport_value(o, transport));
                });
            }
            let n = r.u8()?;
            field!(out, "Number of vendor codecs: {}", n);
            for _ in 0..n {
                let company = r.u16()?;
                let vid = r.u16()?;
                let transport = r.u8()?;
                out.nest(|o| {
                    manufacturer_value("Company", o, company);
                    field!(o, "Vendor codec ID: 0x{:04x}", vid);
                    codec_transport_value(o, transport);
                });
            }
        }
        cmd::READ_LOCAL_SUPPORTED_CODEC_CAPABILITIES => {
            status(r, out)?;
            let n = r.u8()?;
            field!(out, "Number of codec capabilities: {}", n);
            for i in 0..n {
                let len = r.u8()?;
                let data = r.bytes(len as usize)?;
                out.group(format!("Capabilities #{}: len {}", i, len), |o| {
                    o.hex(data);
                });
            }
        }
        cmd::READ_LOCAL_SUPPORTED_CONTROLLER_DELAY => {
            status(r, out)?;
            let v = r.u24()?;
            field!(out, "Minimum Controller delay: {} usec (0x{:06x})", v, v);
            let v = r.u24()?;
            field!(out, "Maximum Controller delay: {} usec (0x{:06x})", v, v);
        }

        // --- Status (OGF 5) ---------------------------------------------------------------
        cmd::READ_FAILED_CONTACT_COUNTER => {
            status(r, out)?;
            handle(st, r, out)?;
            u16_field("Counter", r, out)?;
        }
        cmd::READ_LINK_QUALITY => {
            status(r, out)?;
            handle(st, r, out)?;
            let q = r.u8()?;
            field!(out, "Link quality: 0x{:02x}", q);
        }
        cmd::READ_RSSI => {
            status(r, out)?;
            handle(st, r, out)?;
            rssi(r, out)?;
        }
        cmd::READ_AFH_CHANNEL_MAP => {
            status(r, out)?;
            handle(st, r, out)?;
            enum8("Mode", r, out, &[(0x00, "AFH disabled"), (0x01, "AFH enabled")])?;
            afh_channel_map(r, out)?;
        }
        cmd::READ_CLOCK => {
            status(r, out)?;
            handle(st, r, out)?;
            clock("Clock", r, out)?;
            let acc = r.u16()?;
            if acc == 0xffff {
                field!(out, "Accuracy: Unknown (0x{:04x})", acc);
            } else {
                // One Bluetooth clock tick is 312.5 µs; work in tenths of a microsecond.
                let tenth_us = acc as u64 * 3125;
                field!(out, "Accuracy: {}.{:04} msec (0x{:04x})", tenth_us / 10000, tenth_us % 10000, acc);
            }
        }
        cmd::READ_ENCRYPTION_KEY_SIZE => {
            status(r, out)?;
            handle(st, r, out)?;
            u8_field("Key size", r, out)?;
        }
        cmd::GET_MWS_TRANSPORT_LAYER_CONFIGURATION => {
            status(r, out)?;
            let n = r.u8()?;
            field!(out, "Number of transports: {}", n);
            let mut layers = Vec::with_capacity(n as usize);
            for _ in 0..n {
                layers.push(r.u8()?);
            }
            let mut total = 0usize;
            let mut counts = Vec::with_capacity(n as usize);
            for _ in 0..n {
                let c = r.u8()?;
                total += c as usize;
                counts.push(c);
            }
            for (layer, count) in layers.iter().zip(counts.iter()) {
                out.nest(|o| {
                    mws_transport_layer_value(o, *layer);
                    field!(o, "Number of baud rates: {}", count);
                });
            }
            field!(out, "Baud rate list: {} entr{}", total, if total == 1 { "y" } else { "ies" });
            let mut to = Vec::with_capacity(total);
            for _ in 0..total {
                to.push(r.u32()?);
            }
            for t in to {
                let from = r.u32()?;
                out.nest(|o| {
                    field!(o, "Bluetooth to MWS: {}", t);
                    field!(o, "MWS to Bluetooth: {}", from);
                });
            }
        }

        // --- Testing (OGF 6) --------------------------------------------------------------
        cmd::READ_LOOPBACK_MODE => {
            status(r, out)?;
            loopback_mode(r, out)?;
        }

        _ => return Ok(false),
    }
    Ok(true)
}

// ------------------------------------------------------------------------------------------
// Link Control helpers
// ------------------------------------------------------------------------------------------

/// Inquiry access code (LAP): `Access code: 0x9e8b33 (General Inquiry)`.
fn iac(r: &mut Reader<'_>, out: &mut Out) -> Result<u32> {
    let lap = r.u24()?;
    iac_value(out, lap);
    Ok(lap)
}

fn iac_value(out: &mut Out, lap: u32) {
    match lap {
        0x9e8b33 => field!(out, "Access code: 0x{:06x} (General Inquiry)", lap),
        0x9e8b00 => field!(out, "Access code: 0x{:06x} (Limited Inquiry)", lap),
        _ => field!(out, "Access code: 0x{:06x}", lap),
    };
}

fn iac_list(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let n = r.u8()?;
    field!(out, "Number of IAC: {}", n);
    for _ in 0..n {
        iac(r, out)?;
    }
    Ok(())
}

/// A one-octet duration in 1.28 s units: `Length: 10.24s (0x08)`.
fn inquiry_length(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let v = r.u8()?;
    secs_1_28(label, out, v as u32, 2);
    Ok(())
}

/// A two-octet duration in 1.28 s units (periodic inquiry period lengths).
fn inquiry_period(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let v = r.u16()?;
    secs_1_28(label, out, v as u32, 4);
    Ok(())
}

fn secs_1_28(label: &str, out: &mut Out, v: u32, hex_width: usize) {
    let cs = v as u64 * 128; // centiseconds
    field!(out, "{}: {}.{:02}s (0x{:0w$x})", label, cs / 100, cs % 100, v, w = hex_width);
}

fn num_responses(r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    let n = r.u8()?;
    match n {
        0 => field!(out, "Num responses: Unlimited (0x00)"),
        _ => field!(out, "Num responses: {} (0x{:02x})", n, n),
    };
    Ok(n)
}

fn pin_code(r: &mut Reader<'_>, out: &mut Out, len: u8) -> Result<()> {
    let b = r.bytes(16)?;
    let n = (len as usize).min(16);
    let pin = &b[..n];
    if !pin.is_empty() && pin.iter().all(|c| (0x20..0x7f).contains(c)) {
        field!(out, "PIN code: {}", String::from_utf8_lossy(pin));
    } else {
        out.hex_field("PIN code", pin);
    }
    Ok(())
}

/// Voice setting bit field (Section 6.12).
fn voice_setting(r: &mut Reader<'_>, out: &mut Out) -> Result<u16> {
    let v = r.u16()?;
    field!(out, "Setting: 0x{:04x}", v);
    out.nest(|o| {
        let input_coding = (v >> 8) & 0x03;
        let input_format = (v >> 6) & 0x03;
        let air_coding = v & 0x03;
        match input_coding {
            0 => o.line("Input Coding: Linear"),
            1 => o.line("Input Coding: u-law"),
            2 => o.line("Input Coding: A-law"),
            _ => o.unknown("Input Coding: Reserved"),
        };
        match input_format {
            0 => o.line("Input Data Format: 1's complement"),
            1 => o.line("Input Data Format: 2's complement"),
            2 => o.line("Input Data Format: Sign-Magnitude"),
            _ => o.line("Input Data Format: Unsigned"),
        };
        if input_coding == 0 {
            o.line(format!("Input Sample Size: {}", if v & 0x20 != 0 { "16-bit" } else { "8-bit" }));
            o.line(format!("# of bits padding at MSB: {}", (v >> 2) & 0x07));
        }
        match air_coding {
            0 => o.line("Air Coding Format: CVSD"),
            1 => o.line("Air Coding Format: u-law"),
            2 => o.line("Air Coding Format: A-law"),
            _ => o.line("Air Coding Format: Transparent Data"),
        };
        if v & 0xfc00 != 0 {
            o.unknown(format!("Reserved bits (0x{:04x})", v & 0xfc00));
        }
    });
    Ok(v)
}

fn retransmission_effort(r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    enum8(
        "Retransmission effort",
        r,
        out,
        &[
            (0x00, "No retransmissions"),
            (0x01, "Optimize for power consumption"),
            (0x02, "Optimize for link quality"),
            (0xff, "Don't care"),
        ],
    )
}

/// Parameters shared by Setup Synchronous Connection and Accept Synchronous Connection Request.
fn sync_conn_params(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    u32_field("Transmit bandwidth", r, out)?;
    u32_field("Receive bandwidth", r, out)?;
    u16_field("Max latency", r, out)?;
    voice_setting(r, out)?;
    retransmission_effort(r, out)?;
    pkt_type_sco(r, out)?;
    Ok(())
}

fn codec_id_value(label: &str, out: &mut Out, id: u8) {
    enum8_value(label, out, id, CODING_FORMATS);
}

/// A five-octet coding format / codec ID: coding format, company ID and vendor codec ID.
fn codec_id(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    let id = r.u8()?;
    let company = r.u16()?;
    let vid = r.u16()?;
    codec_id_value(label, out, id);
    if id == 0xff {
        out.nest(|o| {
            manufacturer_value("Company", o, company);
            field!(o, "Vendor codec ID: 0x{:04x}", vid);
        });
    }
    Ok(id)
}

fn coding_format(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    out.line(format!("{label}:"));
    out.nest(|o| codec_id("Codec", r, o))?;
    Ok(())
}

fn codec_transport_value(out: &mut Out, transport: u8) {
    field!(out, "Logical transport type: 0x{:02x}", transport);
    out.nest(|o| {
        bits(
            o,
            transport as u64,
            &[
                (0, "Codec supported over BR/EDR ACL"),
                (1, "Codec supported over BR/EDR SCO and eSCO"),
                (2, "Codec supported over LE CIS"),
                (3, "Codec supported over LE BIS"),
            ],
            8,
        )
    });
}

fn logical_transport_type(r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    enum8(
        "Logical transport type",
        r,
        out,
        &[(0x00, "BR/EDR ACL"), (0x01, "BR/EDR SCO or eSCO"), (0x02, "LE CIS"), (0x03, "LE BIS")],
    )
}

fn path_direction(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    enum8(label, r, out, &[(0x00, "Input (Host to Controller)"), (0x01, "Output (Controller to Host)")])
}

fn pcm_data_format(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    enum8(
        label,
        r,
        out,
        &[(0x00, "NA"), (0x01, "1's complement"), (0x02, "2's complement"), (0x03, "Sign-magnitude"), (0x04, "Unsigned")],
    )
}

fn data_path(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    let v = r.u8()?;
    match v {
        0x00 => field!(out, "{}: HCI (0x00)", label),
        0xff => field!(out, "{}: Audio test mode (0xff)", label),
        _ => field!(out, "{}: Vendor specific (0x{:02x})", label, v),
    };
    Ok(v)
}

/// Parameters shared by Enhanced Setup Synchronous Connection and its Accept variant.
fn enhanced_sync_conn_params(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    u32_field("Transmit bandwidth", r, out)?;
    u32_field("Receive bandwidth", r, out)?;
    coding_format("Transmit coding format", r, out)?;
    coding_format("Receive coding format", r, out)?;
    u16_field("Transmit codec frame size", r, out)?;
    u16_field("Receive codec frame size", r, out)?;
    u32_field("Input bandwidth", r, out)?;
    u32_field("Output bandwidth", r, out)?;
    coding_format("Input coding format", r, out)?;
    coding_format("Output coding format", r, out)?;
    u16_field("Input coded data size", r, out)?;
    u16_field("Output coded data size", r, out)?;
    pcm_data_format("Input PCM data format", r, out)?;
    pcm_data_format("Output PCM data format", r, out)?;
    u8_field("Input PCM sample payload MSB position", r, out)?;
    u8_field("Output PCM sample payload MSB position", r, out)?;
    data_path("Input data path", r, out)?;
    data_path("Output data path", r, out)?;
    u8_field("Input transport unit size", r, out)?;
    u8_field("Output transport unit size", r, out)?;
    u16_field("Max latency", r, out)?;
    pkt_type_sco(r, out)?;
    retransmission_effort(r, out)?;
    Ok(())
}

fn lpo_allowed(r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    enum8("LPO allowed", r, out, &[(0x00, "Controller shall not sleep"), (0x01, "Controller may sleep")])
}

/// Host channel classification: bits set are `Unknown`, cleared bits are `Bad`.
fn channel_classification(r: &mut Reader<'_>, out: &mut Out) -> Result<[u8; 10]> {
    let map = r.array::<10>()?;
    field!(out, "Channel map: 0x{}", hexstr(&map));
    out.nest(|o| {
        for (start, end, set) in afh_channel_ranges(&map) {
            let state = if set { "Unknown" } else { "Bad" };
            if start == end {
                o.line(format!("Channel {start}: {state}"));
            } else {
                o.line(format!("Channel {start}-{end}: {state}"));
            }
        }
        if map[9] & 0x80 != 0 {
            o.unknown("Reserved bit 79 set");
        }
    });
    Ok(map)
}

// ------------------------------------------------------------------------------------------
// Link Policy helpers
// ------------------------------------------------------------------------------------------

fn link_policy(r: &mut Reader<'_>, out: &mut Out) -> Result<u16> {
    let v = r.u16()?;
    field!(out, "Link policy: 0x{:04x}", v);
    out.nest(|o| {
        if v == 0 {
            o.line("Disable All Modes");
        } else {
            bits(
                o,
                v as u64,
                &[(0, "Enable Role Switch"), (1, "Enable Hold Mode"), (2, "Enable Sniff Mode"), (3, "Enable Park State")],
                16,
            );
        }
    });
    Ok(v)
}

// ------------------------------------------------------------------------------------------
// Controller & Baseband helpers
// ------------------------------------------------------------------------------------------

/// Event mask bit names (Set Event Mask).
pub static EVENT_MASK_BITS: &[(u8, &str)] = &[
    (0, "Inquiry Complete"),
    (1, "Inquiry Result"),
    (2, "Connection Complete"),
    (3, "Connection Request"),
    (4, "Disconnection Complete"),
    (5, "Authentication Complete"),
    (6, "Remote Name Request Complete"),
    (7, "Encryption Change"),
    (8, "Change Connection Link Key Complete"),
    (9, "Link Key Type Changed"),
    (10, "Read Remote Supported Features Complete"),
    (11, "Read Remote Version Information Complete"),
    (12, "QoS Setup Complete"),
    (15, "Hardware Error"),
    (16, "Flush Occurred"),
    (17, "Role Change"),
    (19, "Mode Change"),
    (20, "Return Link Keys"),
    (21, "PIN Code Request"),
    (22, "Link Key Request"),
    (23, "Link Key Notification"),
    (24, "Loopback Command"),
    (25, "Data Buffer Overflow"),
    (26, "Max Slots Change"),
    (27, "Read Clock Offset Complete"),
    (28, "Connection Packet Type Changed"),
    (29, "QoS Violation"),
    (30, "Page Scan Mode Change"),
    (31, "Page Scan Repetition Mode Change"),
    (32, "Flow Specification Complete"),
    (33, "Inquiry Result with RSSI"),
    (34, "Read Remote Extended Features Complete"),
    (43, "Synchronous Connection Complete"),
    (44, "Synchronous Connection Changed"),
    (45, "Sniff Subrating"),
    (46, "Extended Inquiry Result"),
    (47, "Encryption Key Refresh Complete"),
    (48, "IO Capability Request"),
    (49, "IO Capability Response"),
    (50, "User Confirmation Request"),
    (51, "User Passkey Request"),
    (52, "Remote OOB Data Request"),
    (53, "Simple Pairing Complete"),
    (55, "Link Supervision Timeout Changed"),
    (56, "Enhanced Flush Complete"),
    (58, "User Passkey Notification"),
    (59, "Keypress Notification"),
    (60, "Remote Host Supported Features Notification"),
    (61, "LE Meta"),
];

/// Event mask page 2 bit names (Set Event Mask Page 2).  Bits 0-7 and 9-13 are the
/// withdrawn AMP events, kept so that masks from older hosts still decode.
pub static EVENT_MASK_PAGE2_BITS: &[(u8, &str)] = &[
    (0, "Physical Link Complete"),
    (1, "Channel Selected"),
    (2, "Disconnection Physical Link Complete"),
    (3, "Physical Link Loss Early Warning"),
    (4, "Physical Link Recovery"),
    (5, "Logical Link Complete"),
    (6, "Disconnection Logical Link Complete"),
    (7, "Flow Specification Modify Complete"),
    (8, "Number of Completed Data Blocks"),
    (9, "AMP Start Test"),
    (10, "AMP Test End"),
    (11, "AMP Receiver Report"),
    (12, "Short Range Mode Change Complete"),
    (13, "AMP Status Change"),
    (14, "Triggered Clock Capture"),
    (15, "Synchronization Train Complete"),
    (16, "Synchronization Train Received"),
    (17, "Connectionless Peripheral Broadcast Receive"),
    (18, "Connectionless Peripheral Broadcast Timeout"),
    (19, "Truncated Page Complete"),
    (20, "Peripheral Page Response Timeout"),
    (21, "Connectionless Peripheral Broadcast Channel Map Change"),
    (22, "Inquiry Response Notification"),
    (23, "Authenticated Payload Timeout Expired"),
    (24, "SAM Status Change"),
    (25, "Encryption Change v2"),
];

fn event_mask(r: &mut Reader<'_>, out: &mut Out, table: &[(u8, &str)]) -> Result<u64> {
    let b = r.array::<8>()?;
    let mask = u64::from_le_bytes(b);
    let hex: Vec<String> = b.iter().map(|x| format!("0x{x:02x}")).collect();
    field!(out, "Mask: {}", hex.join(" "));
    out.nest(|o| bits(o, mask, table, 64));
    Ok(mask)
}

fn set_event_filter(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let t = enum8("Type", r, out, &[(0x00, "Clear All Filters"), (0x01, "Inquiry Result"), (0x02, "Connection Setup")])?;
    match t {
        0x00 => {}
        0x01 => {
            let cond = enum8(
                "Filter",
                r,
                out,
                &[
                    (0x00, "Return responses from all devices"),
                    (0x01, "Device with specific Class of Device"),
                    (0x02, "Device with specific BD_ADDR"),
                ],
            )?;
            match cond {
                0x01 => {
                    class_of_device(r, out)?;
                    class_mask(r, out)?;
                }
                0x02 => {
                    bdaddr("Address", r, out)?;
                }
                _ => {}
            }
        }
        0x02 => {
            let cond = enum8(
                "Filter",
                r,
                out,
                &[
                    (0x00, "Allow connections all devices"),
                    (0x01, "Allow connections with specific Class of Device"),
                    (0x02, "Allow connections with specific BD_ADDR"),
                ],
            )?;
            match cond {
                0x00 => auto_accept(r, out)?,
                0x01 => {
                    class_of_device(r, out)?;
                    class_mask(r, out)?;
                    auto_accept(r, out)?;
                }
                0x02 => {
                    bdaddr("Address", r, out)?;
                    auto_accept(r, out)?;
                }
                _ => {}
            }
        }
        _ => {}
    }
    if !r.is_empty() {
        // Reserved filter types (or reserved conditions) carry data we cannot interpret.
        out.hex(r.rest());
    }
    Ok(())
}

fn class_mask(r: &mut Reader<'_>, out: &mut Out) -> Result<u32> {
    let v = r.u24()?;
    field!(out, "Class mask: 0x{:06x}", v);
    Ok(v)
}

fn auto_accept(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    enum8(
        "Auto accept",
        r,
        out,
        &[(0x01, "Off"), (0x02, "On with role switch disabled"), (0x03, "On with role switch enabled")],
    )?;
    Ok(())
}

fn pin_type(r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    enum8("PIN type", r, out, &[(0x00, "Variable"), (0x01, "Fixed")])
}

fn scan_enable(r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    enum8(
        "Scan enable",
        r,
        out,
        &[(0x00, "No Scans"), (0x01, "Inquiry Scan"), (0x02, "Page Scan"), (0x03, "Inquiry Scan + Page Scan")],
    )
}

fn auth_enable(r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    enum8(
        "Enable",
        r,
        out,
        &[(0x00, "Authentication not required"), (0x01, "Authentication required for all connections")],
    )
}

fn encrypt_mode(r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    enum8("Mode", r, out, &[(0x00, "Encryption not required"), (0x01, "Encryption required for all connections")])
}

fn flush_timeout(r: &mut Reader<'_>, out: &mut Out) -> Result<u16> {
    let v = r.u16()?;
    if v == 0 {
        field!(out, "Timeout: No Automatic Flush (0x0000)");
    } else {
        interval_value("Timeout", out, v as u32, 625, 4);
    }
    Ok(v)
}

fn hold_mode_activity(r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    let v = r.u8()?;
    field!(out, "Activity: 0x{:02x}", v);
    out.nest(|o| {
        if v == 0 {
            o.line("Maintain current Power State");
        } else {
            bits(o, v as u64, &[(0, "Suspend Page Scan"), (1, "Suspend Inquiry Scan"), (2, "Suspend Periodic Inquiries")], 8);
        }
    });
    Ok(v)
}

fn host_flow_control(r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    enum8(
        "Flow control",
        r,
        out,
        &[
            (0x00, "Off"),
            (0x01, "ACL Data Packets"),
            (0x02, "Synchronous Data Packets"),
            (0x03, "ACL and Synchronous Data Packets"),
        ],
    )
}

fn scan_type(r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    enum8("Type", r, out, &[(0x00, "Standard Scan"), (0x01, "Interlaced Scan")])
}

fn inquiry_mode(r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    enum8(
        "Mode",
        r,
        out,
        &[
            (0x00, "Standard Inquiry Result"),
            (0x01, "Inquiry Result with RSSI"),
            (0x02, "Inquiry Result with RSSI or Extended Inquiry Result"),
        ],
    )
}

fn afh_assessment_mode(r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    enum8("Mode", r, out, &[(0x00, "Disabled"), (0x01, "Enabled")])
}

/// FEC flag followed by the 240-byte extended inquiry response.
fn eir(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    enum8("FEC", r, out, &[(0x00, "Not required"), (0x01, "Required")])?;
    let data = r.bytes(240)?;
    crate::ad::decode(data, out);
    Ok(())
}

fn flow_control_mode(r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    enum8("Flow control mode", r, out, &[(0x00, "Packet based"), (0x01, "Data block based")])
}

fn usec_u16(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<u16> {
    let v = r.u16()?;
    field!(out, "{}: {} usec", label, v);
    Ok(v)
}

fn usec_i16(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<i16> {
    let v = r.i16()?;
    field!(out, "{}: {} usec", label, v);
    Ok(v)
}

fn mws_transport_layer_value(out: &mut Out, v: u8) {
    enum8_value("Transport layer", out, v, &[(0x00, "Disabled"), (0x01, "WCI-1"), (0x02, "WCI-2")]);
}

fn mws_transport_layer(r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    let v = r.u8()?;
    mws_transport_layer_value(out, v);
    Ok(v)
}

/// Synchronization train timeout: 32-bit value in 0.625 ms slots.
fn sync_train_timeout(r: &mut Reader<'_>, out: &mut Out) -> Result<u32> {
    let v = r.u32()?;
    let us = v as u64 * 625;
    if us % 1000 == 0 {
        field!(out, "Timeout: {} msec (0x{:08x})", us / 1000, v);
    } else {
        field!(out, "Timeout: {}.{:03} msec (0x{:08x})", us / 1000, us % 1000, v);
    }
    Ok(v)
}

// ------------------------------------------------------------------------------------------
// Status & Testing helpers
// ------------------------------------------------------------------------------------------

fn clock_type(r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    enum8("Type", r, out, &[(0x00, "Local clock"), (0x01, "Piconet clock")])
}

fn loopback_mode(r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    enum8("Mode", r, out, &[(0x00, "No Loopback"), (0x01, "Local Loopback"), (0x02, "Remote Loopback")])
}

// ------------------------------------------------------------------------------------------
// Supported commands
// ------------------------------------------------------------------------------------------

/// Supported_Commands bit assignments (Section 6.27): `(octet, bit, name)`.
///
/// Bits marked "Previously used" in the current specification keep the name of the
/// withdrawn command so that masks from older controllers still decode.
pub static SUPPORTED_COMMANDS: &[(u8, u8, &str)] = &[
    (0, 0, "Inquiry"),
    (0, 1, "Inquiry Cancel"),
    (0, 2, "Periodic Inquiry Mode"),
    (0, 3, "Exit Periodic Inquiry Mode"),
    (0, 4, "Create Connection"),
    (0, 5, "Disconnect"),
    (0, 6, "Add SCO Connection"),
    (0, 7, "Create Connection Cancel"),
    (1, 0, "Accept Connection Request"),
    (1, 1, "Reject Connection Request"),
    (1, 2, "Link Key Request Reply"),
    (1, 3, "Link Key Request Negative Reply"),
    (1, 4, "PIN Code Request Reply"),
    (1, 5, "PIN Code Request Negative Reply"),
    (1, 6, "Change Connection Packet Type"),
    (1, 7, "Authentication Requested"),
    (2, 0, "Set Connection Encryption"),
    (2, 1, "Change Connection Link Key"),
    (2, 2, "Link Key Selection"),
    (2, 3, "Remote Name Request"),
    (2, 4, "Remote Name Request Cancel"),
    (2, 5, "Read Remote Supported Features"),
    (2, 6, "Read Remote Extended Features"),
    (2, 7, "Read Remote Version Information"),
    (3, 0, "Read Clock Offset"),
    (3, 1, "Read LMP Handle"),
    (4, 1, "Hold Mode"),
    (4, 2, "Sniff Mode"),
    (4, 3, "Exit Sniff Mode"),
    (4, 4, "Park State"),
    (4, 5, "Exit Park State"),
    (4, 6, "QoS Setup"),
    (4, 7, "Role Discovery"),
    (5, 0, "Switch Role"),
    (5, 1, "Read Link Policy Settings"),
    (5, 2, "Write Link Policy Settings"),
    (5, 3, "Read Default Link Policy Settings"),
    (5, 4, "Write Default Link Policy Settings"),
    (5, 5, "Flow Specification"),
    (5, 6, "Set Event Mask"),
    (5, 7, "Reset"),
    (6, 0, "Set Event Filter"),
    (6, 1, "Flush"),
    (6, 2, "Read PIN Type"),
    (6, 3, "Write PIN Type"),
    (6, 4, "Create New Unit Key"),
    (6, 5, "Read Stored Link Key"),
    (6, 6, "Write Stored Link Key"),
    (6, 7, "Delete Stored Link Key"),
    (7, 0, "Write Local Name"),
    (7, 1, "Read Local Name"),
    (7, 2, "Read Connection Accept Timeout"),
    (7, 3, "Write Connection Accept Timeout"),
    (7, 4, "Read Page Timeout"),
    (7, 5, "Write Page Timeout"),
    (7, 6, "Read Scan Enable"),
    (7, 7, "Write Scan Enable"),
    (8, 0, "Read Page Scan Activity"),
    (8, 1, "Write Page Scan Activity"),
    (8, 2, "Read Inquiry Scan Activity"),
    (8, 3, "Write Inquiry Scan Activity"),
    (8, 4, "Read Authentication Enable"),
    (8, 5, "Write Authentication Enable"),
    (8, 6, "Read Encryption Mode"),
    (8, 7, "Write Encryption Mode"),
    (9, 0, "Read Class Of Device"),
    (9, 1, "Write Class Of Device"),
    (9, 2, "Read Voice Setting"),
    (9, 3, "Write Voice Setting"),
    (9, 4, "Read Automatic Flush Timeout"),
    (9, 5, "Write Automatic Flush Timeout"),
    (9, 6, "Read Num Broadcast Retransmissions"),
    (9, 7, "Write Num Broadcast Retransmissions"),
    (10, 0, "Read Hold Mode Activity"),
    (10, 1, "Write Hold Mode Activity"),
    (10, 2, "Read Transmit Power Level"),
    (10, 3, "Read Synchronous Flow Control Enable"),
    (10, 4, "Write Synchronous Flow Control Enable"),
    (10, 5, "Set Controller To Host Flow Control"),
    (10, 6, "Host Buffer Size"),
    (10, 7, "Host Number Of Completed Packets"),
    (11, 0, "Read Link Supervision Timeout"),
    (11, 1, "Write Link Supervision Timeout"),
    (11, 2, "Read Number Of Supported IAC"),
    (11, 3, "Read Current IAC LAP"),
    (11, 4, "Write Current IAC LAP"),
    (11, 5, "Read Page Scan Period Mode"),
    (11, 6, "Write Page Scan Period Mode"),
    (11, 7, "Read Page Scan Mode"),
    (12, 0, "Write Page Scan Mode"),
    (12, 1, "Set AFH Host Channel Classification"),
    (12, 2, "LE CS Read Remote FAE Table"),
    (12, 3, "LE CS Write Cached Remote FAE Table"),
    (12, 4, "Read Inquiry Scan Type"),
    (12, 5, "Write Inquiry Scan Type"),
    (12, 6, "Read Inquiry Mode"),
    (12, 7, "Write Inquiry Mode"),
    (13, 0, "Read Page Scan Type"),
    (13, 1, "Write Page Scan Type"),
    (13, 2, "Read AFH Channel Assessment Mode"),
    (13, 3, "Write AFH Channel Assessment Mode"),
    (14, 3, "Read Local Version Information"),
    (14, 5, "Read Local Supported Features"),
    (14, 6, "Read Local Extended Features"),
    (14, 7, "Read Buffer Size"),
    (15, 0, "Read Country Code"),
    (15, 1, "Read BD ADDR"),
    (15, 2, "Read Failed Contact Counter"),
    (15, 3, "Reset Failed Contact Counter"),
    (15, 4, "Read Link Quality"),
    (15, 5, "Read RSSI"),
    (15, 6, "Read AFH Channel Map"),
    (15, 7, "Read Clock"),
    (16, 0, "Read Loopback Mode"),
    (16, 1, "Write Loopback Mode"),
    (16, 2, "Enable Implementation Under Test Mode"),
    (16, 3, "Setup Synchronous Connection"),
    (16, 4, "Accept Synchronous Connection Request"),
    (16, 5, "Reject Synchronous Connection Request"),
    (16, 6, "LE CS Create Config"),
    (16, 7, "LE CS Remove Config"),
    (17, 0, "Read Extended Inquiry Response"),
    (17, 1, "Write Extended Inquiry Response"),
    (17, 2, "Refresh Encryption Key"),
    (17, 4, "Sniff Subrating"),
    (17, 5, "Read Simple Pairing Mode"),
    (17, 6, "Write Simple Pairing Mode"),
    (17, 7, "Read Local OOB Data"),
    (18, 0, "Read Inquiry Response Transmit Power Level"),
    (18, 1, "Write Inquiry Transmit Power Level"),
    (18, 2, "Read Default Erroneous Data Reporting"),
    (18, 3, "Write Default Erroneous Data Reporting"),
    (18, 7, "IO Capability Request Reply"),
    (19, 0, "User Confirmation Request Reply"),
    (19, 1, "User Confirmation Request Negative Reply"),
    (19, 2, "User Passkey Request Reply"),
    (19, 3, "User Passkey Request Negative Reply"),
    (19, 4, "Remote OOB Data Request Reply"),
    (19, 5, "Write Simple Pairing Debug Mode"),
    (19, 6, "Enhanced Flush"),
    (19, 7, "Remote OOB Data Request Negative Reply"),
    (20, 2, "Send Keypress Notification"),
    (20, 3, "IO Capability Request Negative Reply"),
    (20, 4, "Read Encryption Key Size"),
    (20, 5, "LE CS Read Local Supported Capabilities"),
    (20, 6, "LE CS Read Remote Supported Capabilities"),
    (20, 7, "LE CS Write Cached Remote Supported Capabilities"),
    (21, 0, "Create Physical Link"),
    (21, 1, "Accept Physical Link"),
    (21, 2, "Disconnect Physical Link"),
    (21, 3, "Create Logical Link"),
    (21, 4, "Accept Logical Link"),
    (21, 5, "Disconnect Logical Link"),
    (21, 6, "Logical Link Cancel"),
    (21, 7, "Flow Spec Modify"),
    (22, 0, "Read Logical Link Accept Timeout"),
    (22, 1, "Write Logical Link Accept Timeout"),
    (22, 2, "Set Event Mask Page 2"),
    (22, 3, "Read Location Data"),
    (22, 4, "Write Location Data"),
    (22, 5, "Read Local AMP Info"),
    (22, 6, "Read Local AMP ASSOC"),
    (22, 7, "Write Remote AMP ASSOC"),
    (23, 0, "Read Flow Control Mode"),
    (23, 1, "Write Flow Control Mode"),
    (23, 2, "Read Data Block Size"),
    (23, 3, "LE CS Test"),
    (23, 4, "LE CS Test End"),
    (23, 5, "Enable AMP Receiver Reports"),
    (23, 6, "AMP Test End"),
    (23, 7, "AMP Test"),
    (24, 0, "Read Enhanced Transmit Power Level"),
    (24, 1, "LE CS Security Enable"),
    (24, 2, "Read Best Effort Flush Timeout"),
    (24, 3, "Write Best Effort Flush Timeout"),
    (24, 4, "Short Range Mode"),
    (24, 5, "Read LE Host Support"),
    (24, 6, "Write LE Host Support"),
    (24, 7, "LE CS Set Default Settings"),
    (25, 0, "LE Set Event Mask"),
    (25, 1, "LE Read Buffer Size"),
    (25, 2, "LE Read Local Supported Features Page 0"),
    (25, 4, "LE Set Random Address"),
    (25, 5, "LE Set Advertising Parameters"),
    (25, 6, "LE Read Advertising Physical Channel Tx Power"),
    (25, 7, "LE Set Advertising Data"),
    (26, 0, "LE Set Scan Response Data"),
    (26, 1, "LE Set Advertising Enable"),
    (26, 2, "LE Set Scan Parameters"),
    (26, 3, "LE Set Scan Enable"),
    (26, 4, "LE Create Connection"),
    (26, 5, "LE Create Connection Cancel"),
    (26, 6, "LE Read Filter Accept List Size"),
    (26, 7, "LE Clear Filter Accept List"),
    (27, 0, "LE Add Device To Filter Accept List"),
    (27, 1, "LE Remove Device From Filter Accept List"),
    (27, 2, "LE Connection Update"),
    (27, 3, "LE Set Host Channel Classification"),
    (27, 4, "LE Read Channel Map"),
    (27, 5, "LE Read Remote Features Page 0"),
    (27, 6, "LE Encrypt"),
    (27, 7, "LE Rand"),
    (28, 0, "LE Enable Encryption"),
    (28, 1, "LE Long Term Key Request Reply"),
    (28, 2, "LE Long Term Key Request Negative Reply"),
    (28, 3, "LE Read Supported States"),
    (28, 4, "LE Receiver Test"),
    (28, 5, "LE Transmitter Test"),
    (28, 6, "LE Test End"),
    (28, 7, "LE Enable Monitoring Advertisers"),
    (29, 0, "LE CS Set Channel Classification"),
    (29, 1, "LE CS Set Procedure Parameters"),
    (29, 2, "LE CS Procedure Enable"),
    (29, 3, "Enhanced Setup Synchronous Connection"),
    (29, 4, "Enhanced Accept Synchronous Connection Request"),
    (29, 5, "Read Local Supported Codecs"),
    (29, 6, "Set MWS Channel Parameters"),
    (29, 7, "Set External Frame Configuration"),
    (30, 0, "Set MWS Signaling"),
    (30, 1, "Set MWS Transport Layer"),
    (30, 2, "Set MWS Scan Frequency Table"),
    (30, 3, "Get MWS Transport Layer Configuration"),
    (30, 4, "Set MWS PATTERN Configuration"),
    (30, 5, "Set Triggered Clock Capture"),
    (30, 6, "Truncated Page"),
    (30, 7, "Truncated Page Cancel"),
    (31, 0, "Set Connectionless Peripheral Broadcast"),
    (31, 1, "Set Connectionless Peripheral Broadcast Receive"),
    (31, 2, "Start Synchronization Train"),
    (31, 3, "Receive Synchronization Train"),
    (31, 4, "Set Reserved LT ADDR"),
    (31, 5, "Delete Reserved LT ADDR"),
    (31, 6, "Set Connectionless Peripheral Broadcast Data"),
    (31, 7, "Read Synchronization Train Parameters"),
    (32, 0, "Write Synchronization Train Parameters"),
    (32, 1, "Remote OOB Extended Data Request Reply"),
    (32, 2, "Read Secure Connections Host Support"),
    (32, 3, "Write Secure Connections Host Support"),
    (32, 4, "Read Authenticated Payload Timeout"),
    (32, 5, "Write Authenticated Payload Timeout"),
    (32, 6, "Read Local OOB Extended Data"),
    (32, 7, "Write Secure Connections Test Mode"),
    (33, 0, "Read Extended Page Timeout"),
    (33, 1, "Write Extended Page Timeout"),
    (33, 2, "Read Extended Inquiry Length"),
    (33, 3, "Write Extended Inquiry Length"),
    (33, 4, "LE Remote Connection Parameter Request Reply"),
    (33, 5, "LE Remote Connection Parameter Request Negative Reply"),
    (33, 6, "LE Set Data Length"),
    (33, 7, "LE Read Suggested Default Data Length"),
    (34, 0, "LE Write Suggested Default Data Length"),
    (34, 1, "LE Read Local P-256 Public Key"),
    (34, 2, "LE Generate DHKey"),
    (34, 3, "LE Add Device To Resolving List"),
    (34, 4, "LE Remove Device From Resolving List"),
    (34, 5, "LE Clear Resolving List"),
    (34, 6, "LE Read Resolving List Size"),
    (34, 7, "LE Read Peer Resolvable Address"),
    (35, 0, "LE Read Local Resolvable Address"),
    (35, 1, "LE Set Address Resolution Enable"),
    (35, 2, "LE Set Resolvable Private Address Timeout"),
    (35, 3, "LE Read Maximum Data Length"),
    (35, 4, "LE Read PHY"),
    (35, 5, "LE Set Default PHY"),
    (35, 6, "LE Set PHY"),
    (35, 7, "LE Receiver Test v2"),
    (36, 0, "LE Transmitter Test v2"),
    (36, 1, "LE Set Advertising Set Random Address"),
    (36, 2, "LE Set Extended Advertising Parameters"),
    (36, 3, "LE Set Extended Advertising Data"),
    (36, 4, "LE Set Extended Scan Response Data"),
    (36, 5, "LE Set Extended Advertising Enable"),
    (36, 6, "LE Read Maximum Advertising Data Length"),
    (36, 7, "LE Read Number of Supported Advertising Sets"),
    (37, 0, "LE Remove Advertising Set"),
    (37, 1, "LE Clear Advertising Sets"),
    (37, 2, "LE Set Periodic Advertising Parameters"),
    (37, 3, "LE Set Periodic Advertising Data"),
    (37, 4, "LE Set Periodic Advertising Enable"),
    (37, 5, "LE Set Extended Scan Parameters"),
    (37, 6, "LE Set Extended Scan Enable"),
    (37, 7, "LE Extended Create Connection"),
    (38, 0, "LE Periodic Advertising Create Sync"),
    (38, 1, "LE Periodic Advertising Create Sync Cancel"),
    (38, 2, "LE Periodic Advertising Terminate Sync"),
    (38, 3, "LE Add Device To Periodic Advertiser List"),
    (38, 4, "LE Remove Device From Periodic Advertiser List"),
    (38, 5, "LE Clear Periodic Advertiser List"),
    (38, 6, "LE Read Periodic Advertiser List Size"),
    (38, 7, "LE Read Transmit Power"),
    (39, 0, "LE Read RF Path Compensation"),
    (39, 1, "LE Write RF Path Compensation"),
    (39, 2, "LE Set Privacy Mode"),
    (39, 3, "LE Receiver Test v3"),
    (39, 4, "LE Transmitter Test v3"),
    (39, 5, "LE Set Connectionless CTE Transmit Parameters"),
    (39, 6, "LE Set Connectionless CTE Transmit Enable"),
    (39, 7, "LE Set Connectionless IQ Sampling Enable"),
    (40, 0, "LE Set Connection CTE Receive Parameters"),
    (40, 1, "LE Set Connection CTE Transmit Parameters"),
    (40, 2, "LE Connection CTE Request Enable"),
    (40, 3, "LE Connection CTE Response Enable"),
    (40, 4, "LE Read Antenna Information"),
    (40, 5, "LE Set Periodic Advertising Receive Enable"),
    (40, 6, "LE Periodic Advertising Sync Transfer"),
    (40, 7, "LE Periodic Advertising Set Info Transfer"),
    (41, 0, "LE Set Periodic Advertising Sync Transfer Parameters"),
    (41, 1, "LE Set Default Periodic Advertising Sync Transfer Parameters"),
    (41, 2, "LE Generate DHKey v2"),
    (41, 3, "Read Local Simple Pairing Options"),
    (41, 4, "LE Modify Sleep Clock Accuracy"),
    (41, 5, "LE Read Buffer Size v2"),
    (41, 6, "LE Read ISO TX Sync"),
    (41, 7, "LE Set CIG Parameters"),
    (42, 0, "LE Set CIG Parameters Test"),
    (42, 1, "LE Create CIS"),
    (42, 2, "LE Remove CIG"),
    (42, 3, "LE Accept CIS Request"),
    (42, 4, "LE Reject CIS Request"),
    (42, 5, "LE Create BIG"),
    (42, 6, "LE Create BIG Test"),
    (42, 7, "LE Terminate BIG"),
    (43, 0, "LE BIG Create Sync"),
    (43, 1, "LE BIG Terminate Sync"),
    (43, 2, "LE Request Peer SCA"),
    (43, 3, "LE Setup ISO Data Path"),
    (43, 4, "LE Remove ISO Data Path"),
    (43, 5, "LE ISO Transmit Test"),
    (43, 6, "LE ISO Receive Test"),
    (43, 7, "LE ISO Read Test Counters"),
    (44, 0, "LE ISO Test End"),
    (44, 1, "LE Set Host Feature"),
    (44, 2, "LE Read ISO Link Quality"),
    (44, 3, "LE Enhanced Read Transmit Power Level"),
    (44, 4, "LE Read Remote Transmit Power Level"),
    (44, 5, "LE Set Path Loss Reporting Parameters"),
    (44, 6, "LE Set Path Loss Reporting Enable"),
    (44, 7, "LE Set Transmit Power Reporting Enable"),
    (45, 0, "LE Transmitter Test v4"),
    (45, 1, "Set Ecosystem Base Interval"),
    (45, 2, "Read Local Supported Codecs v2"),
    (45, 3, "Read Local Supported Codec Capabilities"),
    (45, 4, "Read Local Supported Controller Delay"),
    (45, 5, "Configure Data Path"),
    (45, 6, "LE Set Data Related Address Changes"),
    (45, 7, "Set Min Encryption Key Size"),
    (46, 0, "LE Set Default Subrate"),
    (46, 1, "LE Subrate Request"),
    (46, 2, "LE Set Extended Advertising Parameters v2"),
    (46, 3, "LE Set Decision Data"),
    (46, 4, "LE Set Decision Instructions"),
    (46, 5, "LE Set Periodic Advertising Subevent Data"),
    (46, 6, "LE Set Periodic Advertising Response Data"),
    (46, 7, "LE Set Periodic Sync Subevent"),
    (47, 0, "LE Extended Create Connection v2"),
    (47, 1, "LE Set Periodic Advertising Parameters v2"),
    (47, 2, "LE Read All Local Supported Features"),
    (47, 3, "LE Read All Remote Features"),
    (47, 4, "LE Set Host Feature v2"),
    (47, 5, "LE Add Device To Monitored Advertisers List"),
    (47, 6, "LE Remove Device From Monitored Advertisers List"),
    (47, 7, "LE Clear Monitored Advertisers List"),
    (48, 0, "LE Read Monitored Advertisers List Size"),
    (48, 1, "LE Frame Space Update"),
    (48, 2, "LE Set Resolvable Private Address Timeout v2"),
    (48, 3, "LE Enable OTA UTP Mode"),
    (48, 4, "LE UTP Send"),
    (48, 5, "LE Connection Rate Request"),
    (48, 6, "LE Set Default Rate Parameters"),
    (48, 7, "LE Read Minimum Supported Connection Interval"),
    (49, 0, "Read Local Supported Commands v2"),
    (49, 1, "LE Set Event Mask v2"),
    (49, 2, "LE CS Read Local Supported Capabilities v2"),
    (49, 3, "LE CS Write Cached Remote Supported Capabilities v2"),
    (49, 4, "LE CS Set Security Requirements"),
    (49, 5, "LE CS Set Default Security Requirements"),
];

/// Name of the command at the given octet/bit of Supported_Commands.
pub fn supported_command_name(octet: u8, bit: u8) -> Option<&'static str> {
    SUPPORTED_COMMANDS.iter().find(|(o, b, _)| *o == octet && *b == bit).map(|(_, _, n)| *n)
}

/// Print a Supported_Commands bitmap (64 octets for v1, 251 for v2).
fn supported_commands(data: &[u8], out: &mut Out) {
    let count: usize = data.iter().map(|b| b.count_ones() as usize).sum();
    field!(out, "Commands: {} entr{}", count, if count == 1 { "y" } else { "ies" });
    out.nest(|o| {
        for (i, byte) in data.iter().enumerate() {
            for bit in 0..8u8 {
                if byte & (1 << bit) == 0 {
                    continue;
                }
                let name = u8::try_from(i).ok().and_then(|octet| supported_command_name(octet, bit));
                match name {
                    Some(n) => o.line(format!("{n} (Octet {i} - Bit {bit})")),
                    None => o.unknown(format!("Octet {i} - Bit {bit}")),
                };
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reader::BdAddr;

    fn cmd_lines(opcode: u16, data: &[u8]) -> Vec<String> {
        let mut st = IndexState::default();
        let mut out = Out::new();
        let mut r = Reader::new(data);
        assert!(command_params(&mut st, opcode, &mut r, &mut out).unwrap());
        assert!(r.is_empty(), "unconsumed bytes: {:02x?}", r.rest());
        flatten(out.roots())
    }

    fn rsp_lines(opcode: u16, data: &[u8]) -> Vec<String> {
        let mut st = IndexState::default();
        let mut out = Out::new();
        let mut r = Reader::new(data);
        assert!(return_params(&mut st, opcode, &mut r, &mut out).unwrap());
        assert!(r.is_empty(), "unconsumed bytes: {:02x?}", r.rest());
        flatten(out.roots())
    }

    /// Render the tree as indented lines (two spaces per level) for easy comparison.
    fn flatten(nodes: &[crate::tree::Node]) -> Vec<String> {
        let mut lines = Vec::new();
        crate::tree::render_lines(nodes, 0, |indent, n| lines.push(format!("{}{}", " ".repeat(indent), n.text)));
        lines
    }

    #[test]
    fn inquiry_params() {
        let lines = cmd_lines(cmd::INQUIRY, &[0x33, 0x8b, 0x9e, 0x08, 0x00]);
        assert_eq!(lines, ["Access code: 0x9e8b33 (General Inquiry)", "Length: 10.24s (0x08)", "Num responses: Unlimited (0x00)"]);
    }

    #[test]
    fn create_connection_params() {
        let mut data = vec![0x13, 0x71, 0xda, 0x7d, 0x1a, 0x00];
        data.extend_from_slice(&[0x18, 0xcc, 0x02, 0x00, 0x00, 0x00, 0x01]);
        let lines = cmd_lines(cmd::CREATE_CONNECTION, &data);
        assert_eq!(
            lines,
            [
                "Address: 00:1A:7D:DA:71:13 (OUI 00-1A-7D)",
                "Packet type: 0xcc18",
                "  DM1 may be used",
                "  DH1 may be used",
                "  DM3 may be used",
                "  DH3 may be used",
                "  DM5 may be used",
                "  DH5 may be used",
                "Page scan repetition mode: R2 (0x02)",
                "Page scan mode: Mandatory (0x00)",
                "Clock offset: 0x0000",
                "Role switch: Allow peripheral (0x01)",
            ]
        );
    }

    #[test]
    fn packet_type_flags_unknown_bits() {
        let lines = cmd_lines(cmd::CHANGE_CONNECTION_PACKET_TYPE, &[0x0b, 0x00, 0x19, 0x00]);
        assert_eq!(lines, ["Handle: 11", "Packet type: 0x0019", "  DM1 may be used", "  DH1 may be used", "  Unknown packet types (0x0001)"]);
    }

    #[test]
    fn remote_name_request_params() {
        let lines = cmd_lines(cmd::REMOTE_NAME_REQUEST, &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x01, 0x00, 0x34, 0x12]);
        assert_eq!(
            lines,
            [
                "Address: 06:05:04:03:02:01 (OUI 06-05-04)",
                "Page scan repetition mode: R1 (0x01)",
                "Page scan mode: Mandatory (0x00)",
                "Clock offset: 0x1234",
            ]
        );
    }

    #[test]
    fn io_capability_request_reply_params() {
        let lines = cmd_lines(cmd::IO_CAPABILITY_REQUEST_REPLY, &[0, 0, 0, 0, 0, 0, 0x01, 0x00, 0x03]);
        assert_eq!(lines[1..], ["IO capability: DisplayYesNo (0x01)", "OOB data: Authentication data not present (0x00)", "Authentication: Dedicated Bonding - MITM required (0x03)"]);
    }

    #[test]
    fn setup_synchronous_connection_params() {
        let mut data = vec![0x01, 0x00];
        data.extend_from_slice(&8000u32.to_le_bytes());
        data.extend_from_slice(&8000u32.to_le_bytes());
        data.extend_from_slice(&0x000cu16.to_le_bytes());
        data.extend_from_slice(&0x0060u16.to_le_bytes());
        data.push(0x02);
        data.extend_from_slice(&0x0380u16.to_le_bytes());
        let lines = cmd_lines(cmd::SETUP_SYNCHRONOUS_CONNECTION, &data);
        assert_eq!(
            lines,
            [
                "Handle: 1",
                "Transmit bandwidth: 8000",
                "Receive bandwidth: 8000",
                "Max latency: 12",
                "Setting: 0x0060",
                "  Input Coding: Linear",
                "  Input Data Format: 2's complement",
                "  Input Sample Size: 16-bit",
                "  # of bits padding at MSB: 0",
                "  Air Coding Format: CVSD",
                "Retransmission effort: Optimize for link quality (0x02)",
                "Packet type: 0x0380",
                "  3-EV3 may not be used",
                "  2-EV5 may not be used",
                "  3-EV5 may not be used",
            ]
        );
    }

    #[test]
    fn write_scan_enable_and_timeouts() {
        assert_eq!(cmd_lines(cmd::WRITE_SCAN_ENABLE, &[0x03]), ["Scan enable: Inquiry Scan + Page Scan (0x03)"]);
        assert_eq!(cmd_lines(cmd::WRITE_CONNECTION_ACCEPT_TIMEOUT, &[0x00, 0x20]), ["Timeout: 5120.000 msec (0x2000)"]);
        assert_eq!(cmd_lines(cmd::WRITE_AUTHENTICATED_PAYLOAD_TIMEOUT, &[0x01, 0x00, 0xb8, 0x0b]), ["Handle: 1", "Timeout: 30000 msec (0x0bb8)"]);
        assert_eq!(cmd_lines(cmd::WRITE_PAGE_SCAN_ACTIVITY, &[0x00, 0x08, 0x12, 0x00]), ["Interval: 1280.000 msec (0x0800)", "Window: 11.250 msec (0x0012)"]);
    }

    #[test]
    fn link_policy_settings() {
        assert_eq!(cmd_lines(cmd::WRITE_DEFAULT_LINK_POLICY_SETTINGS, &[0x05, 0x00]), ["Link policy: 0x0005", "  Enable Role Switch", "  Enable Sniff Mode"]);
        assert_eq!(rsp_lines(cmd::READ_DEFAULT_LINK_POLICY_SETTINGS, &[0x00, 0x00, 0x00]), ["Status: Success (0x00)", "Link policy: 0x0000", "  Disable All Modes"]);
    }

    #[test]
    fn set_event_filter_connection_setup() {
        let lines = cmd_lines(cmd::SET_EVENT_FILTER, &[0x02, 0x02, 1, 2, 3, 4, 5, 6, 0x02]);
        assert_eq!(
            lines,
            [
                "Type: Connection Setup (0x02)",
                "Filter: Allow connections with specific BD_ADDR (0x02)",
                "Address: 06:05:04:03:02:01 (OUI 06-05-04)",
                "Auto accept: On with role switch disabled (0x02)",
            ]
        );
        assert_eq!(cmd_lines(cmd::SET_EVENT_FILTER, &[0x00]), ["Type: Clear All Filters (0x00)"]);
    }

    #[test]
    fn set_event_mask_page2() {
        let lines = cmd_lines(cmd::SET_EVENT_MASK_PAGE_2, &[0x00, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(lines, ["Mask: 0x00 0x80 0x00 0x00 0x00 0x00 0x00 0x00", "  Synchronization Train Complete"]);
    }

    #[test]
    fn afh_host_channel_classification() {
        let mut map = [0xffu8; 10];
        map[0] = 0xfc; // channels 0 and 1 bad
        map[9] = 0x7f;
        let lines = cmd_lines(cmd::SET_AFH_HOST_CHANNEL_CLASSIFICATION, &map);
        assert_eq!(lines, ["Channel map: 0xfcffffffffffffffff7f", "  Channel 0-1: Bad", "  Channel 2-78: Unknown"]);
    }

    #[test]
    fn read_local_supported_commands_rsp() {
        let mut data = vec![0x00];
        let mut bitmap = [0u8; 64];
        bitmap[0] = 0x01; // Inquiry
        bitmap[14] = 0x08; // Read Local Version Information
        bitmap[3] = 0x80; // reserved bit
        data.extend_from_slice(&bitmap);
        let lines = rsp_lines(cmd::READ_LOCAL_SUPPORTED_COMMANDS, &data);
        assert_eq!(
            lines,
            [
                "Status: Success (0x00)",
                "Commands: 3 entries",
                "  Inquiry (Octet 0 - Bit 0)",
                "  Octet 3 - Bit 7",
                "  Read Local Version Information (Octet 14 - Bit 3)",
            ]
        );
    }

    #[test]
    fn read_local_extended_features_rsp() {
        let lines = rsp_lines(cmd::READ_LOCAL_EXTENDED_FEATURES, &[0x00, 0x01, 0x02, 0x0b, 0, 0, 0, 0, 0, 0, 0]);
        assert_eq!(
            lines,
            [
                "Status: Success (0x00)",
                "Page: 1/2",
                "Features: 0x0b 0x00 0x00 0x00 0x00 0x00 0x00 0x00",
                "  Secure Simple Pairing (Host Support)",
                "  LE Supported (Host)",
                "  Secure Connections (Host Support)",
            ]
        );
    }

    #[test]
    fn read_bd_addr_updates_state() {
        let mut st = IndexState::default();
        let mut out = Out::new();
        let mut r = Reader::new(&[0x00, 0x13, 0x71, 0xda, 0x7d, 0x1a, 0x00]);
        assert!(return_params(&mut st, cmd::READ_BD_ADDR, &mut r, &mut out).unwrap());
        assert_eq!(st.addr, BdAddr([0x13, 0x71, 0xda, 0x7d, 0x1a, 0x00]));
        assert_eq!(flatten(out.roots())[1], "Address: 00:1A:7D:DA:71:13 (OUI 00-1A-7D)");
    }

    #[test]
    fn role_discovery_and_clock_rsp() {
        assert_eq!(rsp_lines(cmd::ROLE_DISCOVERY, &[0x00, 0x05, 0x00, 0x01]), ["Status: Success (0x00)", "Handle: 5", "Role: Peripheral (0x01)"]);
        let lines = rsp_lines(cmd::READ_CLOCK, &[0x00, 0x05, 0x00, 0x78, 0x56, 0x34, 0x02, 0x10, 0x00]);
        assert_eq!(lines, ["Status: Success (0x00)", "Handle: 5", "Clock: 0x02345678", "Accuracy: 5.0000 msec (0x0010)"]);
        let lines = rsp_lines(cmd::READ_CLOCK, &[0x00, 0x00, 0x00, 0, 0, 0, 0, 0xff, 0xff]);
        assert_eq!(lines[3], "Accuracy: Unknown (0xffff)");
    }

    #[test]
    fn read_local_supported_codecs_v2_rsp() {
        let data = [0x00, 0x02, 0x02, 0x02, 0x05, 0x02, 0x01, 0x0f, 0x00, 0x01, 0x00, 0x03];
        let lines = rsp_lines(cmd::READ_LOCAL_SUPPORTED_CODECS_V2, &data);
        assert_eq!(
            lines,
            [
                "Status: Success (0x00)",
                "Number of supported codecs: 2",
                "  Codec: CVSD (0x02)",
                "    Logical transport type: 0x02",
                "      Codec supported over BR/EDR SCO and eSCO",
                "  Codec: mSBC (0x05)",
                "    Logical transport type: 0x02",
                "      Codec supported over BR/EDR SCO and eSCO",
                "Number of vendor codecs: 1",
                "  Company: Broadcom Corporation (15)",
                "  Vendor codec ID: 0x0001",
                "  Logical transport type: 0x03",
                "    Codec supported over BR/EDR ACL",
                "    Codec supported over BR/EDR SCO and eSCO",
            ]
        );
    }

    #[test]
    fn host_number_of_completed_packets_params() {
        let lines = cmd_lines(cmd::HOST_NUMBER_OF_COMPLETED_PACKETS, &[0x02, 0x01, 0x00, 0x03, 0x00, 0x02, 0x00, 0x01, 0x00]);
        assert_eq!(lines, ["Num handles: 2", "Handle: 1", "Count: 3", "Handle: 2", "Count: 1"]);
    }

    #[test]
    fn read_afh_channel_map_rsp() {
        let mut data = vec![0x00, 0x01, 0x00, 0x01];
        data.extend_from_slice(&[0xff, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x60]);
        let lines = rsp_lines(cmd::READ_AFH_CHANNEL_MAP, &data);
        assert_eq!(lines, ["Status: Success (0x00)", "Handle: 1", "Mode: AFH enabled (0x01)", "Channel map: 0xff000000000000000060", "  Channel 0-7", "  Channel 77-78"]);
    }

    #[test]
    fn write_extended_inquiry_response_params() {
        let mut data = vec![0x00, 0x05, 0x09, b'b', b't', b'm', b'n'];
        data.resize(241, 0);
        let lines = cmd_lines(cmd::WRITE_EXTENDED_INQUIRY_RESPONSE, &data);
        assert_eq!(lines[0], "FEC: Not required (0x00)");
        assert_eq!(lines[1], "Name (complete): btmn");
    }

    #[test]
    fn pin_code_request_reply_params() {
        let mut data = vec![1, 2, 3, 4, 5, 6, 0x04];
        data.extend_from_slice(b"1234");
        data.resize(7 + 16, 0);
        let lines = cmd_lines(cmd::PIN_CODE_REQUEST_REPLY, &data);
        assert_eq!(lines[1..], ["PIN length: 4", "PIN code: 1234"]);
    }

    #[test]
    fn unhandled_opcode_is_not_claimed() {
        let mut st = IndexState::default();
        let mut out = Out::new();
        let mut r = Reader::new(&[0x01]);
        assert!(!command_params(&mut st, cmd::READ_LOCAL_AMP_INFO, &mut r, &mut out).unwrap());
        assert!(!return_params(&mut st, cmd::READ_LOCAL_AMP_INFO, &mut r, &mut out).unwrap());
    }
}
