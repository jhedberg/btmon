//! Vendor-specific (OGF 0x3f) commands and the vendor event (0xff).
//!
//! Which vendor extension applies is decided from the manufacturer the
//! controller reported (`IndexState::manufacturer`).  The Zephyr Bluetooth
//! controller's extension (`include/zephyr/bluetooth/hci_vs.h`) is used for
//! The Linux Foundation (0x05f1, Zephyr's own controller), Nordic
//! Semiconductor (0x0059, whose SoftDevice Controller implements the same
//! set) and when no manufacturer is known, because every Zephyr host probes
//! its controller with these commands at boot.  Other manufacturers are left
//! as hex until a decoder exists for them: add a further `mod` next to
//! [`zephyr`] and extend [`Vendor::of`].

use super::common::*;
use super::{ocf, ogf, OGF_VENDOR};
use crate::context::IndexState;
use crate::field;
use crate::reader::{Reader, Result};
use crate::tree::Out;

/// Event code of the vendor-specific event.
pub const EVT_VENDOR: u8 = 0xff;

/// The vendor extension set a controller speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Vendor {
    Zephyr,
    /// No decoder; everything is hex dumped.
    Other,
}

impl Vendor {
    fn of(st: &IndexState) -> Vendor {
        match st.manufacturer {
            None | Some(zephyr::COMPANY_LINUX_FOUNDATION) | Some(zephyr::COMPANY_NORDIC) => Vendor::Zephyr,
            _ => Vendor::Other,
        }
    }
}

/// Name of a vendor command, including the vendor prefix (`Zephyr Read Version Info`).
pub fn command_name(st: &IndexState, opcode: u16) -> Option<&'static str> {
    if ogf(opcode) != OGF_VENDOR {
        return None;
    }
    match Vendor::of(st) {
        Vendor::Zephyr => zephyr::command_name(ocf(opcode)),
        Vendor::Other => None,
    }
}

/// Decode command parameters; `Ok(false)` if the opcode is not handled here.
pub fn command_params(st: &mut IndexState, opcode: u16, r: &mut Reader<'_>, out: &mut Out) -> Result<bool> {
    if ogf(opcode) != OGF_VENDOR {
        return Ok(false);
    }
    match Vendor::of(st) {
        Vendor::Zephyr => zephyr::command_params(st, ocf(opcode), r, out),
        Vendor::Other => Ok(false),
    }
}

/// Decode Command Complete return parameters; `Ok(false)` if the opcode is not handled here.
pub fn return_params(st: &mut IndexState, opcode: u16, r: &mut Reader<'_>, out: &mut Out) -> Result<bool> {
    if ogf(opcode) != OGF_VENDOR {
        return Ok(false);
    }
    match Vendor::of(st) {
        Vendor::Zephyr => zephyr::return_params(st, ocf(opcode), r, out),
        Vendor::Other => Ok(false),
    }
}

/// Decode the parameters of the vendor event (0xff); `Ok(false)` if they are not understood.
///
/// The first line names the subevent (`Zephyr Scan Request Received (0x04)`) and
/// its fields are nested below it, like LE Meta subevents.
pub fn event_params(st: &mut IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<bool> {
    match Vendor::of(st) {
        Vendor::Zephyr => zephyr::event_params(st, r, out),
        Vendor::Other => Ok(false),
    }
}

// ---------------------------------------------------------------------------
// Helpers private to this module
// ---------------------------------------------------------------------------

/// Print an 8-byte mask as `Label: 0x.. 0x..` with one child per set bit.
fn mask64(label: &str, r: &mut Reader<'_>, out: &mut Out, names: &[(u8, &str)]) -> Result<u64> {
    let b = r.array::<8>()?;
    let mask = u64::from_le_bytes(b);
    let hex: Vec<String> = b.iter().map(|x| format!("0x{x:02x}")).collect();
    field!(out, "{}: {}", label, hex.join(" "));
    out.nest(|o| bits(o, mask, names, 64));
    Ok(mask)
}

/// Print a one-byte value with a name from `names`, or `Unknown` (not flagged) when absent.
fn named8(label: &str, r: &mut Reader<'_>, out: &mut Out, names: &[(u8, &str)]) -> Result<u8> {
    let v = r.u8()?;
    let n = names.iter().find(|(k, _)| *k == v).map(|(_, n)| *n).unwrap_or("Unknown");
    field!(out, "{}: {} (0x{:02x})", label, n, v);
    Ok(v)
}

/// Print a two-byte value with a name from `names`, or `Unknown` (not flagged) when absent.
fn named16(label: &str, r: &mut Reader<'_>, out: &mut Out, names: &[(u16, &str)]) -> Result<u16> {
    let v = r.u16()?;
    let n = names.iter().find(|(k, _)| *k == v).map(|(_, n)| *n).unwrap_or("Unknown");
    field!(out, "{}: {} (0x{:04x})", label, n, v);
    Ok(v)
}

/// Print a signed 8-bit value as `Label: N (0xNN)`.
fn i8_hex(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<i8> {
    let v = r.i8()?;
    field!(out, "{}: {} (0x{:02x})", label, v, v as u8);
    Ok(v)
}

/// Print a 32-bit value in decimal.
fn u32_field(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<u32> {
    let v = r.u32()?;
    field!(out, "{}: {}", label, v);
    Ok(v)
}

/// Advertising channel map (bits 0..2 = channels 37..39): `Channel map: 37, 38, 39 (0x07)`.
fn adv_channel_map(r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    let v = r.u8()?;
    let chans: Vec<&str> =
        [(0x01, "37"), (0x02, "38"), (0x04, "39")].iter().filter(|(bit, _)| v & bit != 0).map(|(_, n)| *n).collect();
    if v == 0 || v & !0x07 != 0 {
        out.unknown(format!("Channel map: Reserved (0x{v:02x})"));
    } else {
        field!(out, "Channel map: {} (0x{:02x})", chans.join(", "), v);
    }
    Ok(v)
}

// ---------------------------------------------------------------------------
// Zephyr Bluetooth controller vendor extension
// ---------------------------------------------------------------------------

mod zephyr {
    use super::*;

    pub const COMPANY_LINUX_FOUNDATION: u16 = 0x05f1;
    pub const COMPANY_NORDIC: u16 = 0x0059;

    // Command OCFs.
    pub const READ_VERSION_INFO: u16 = 0x0001;
    pub const READ_SUPPORTED_COMMANDS: u16 = 0x0002;
    pub const READ_SUPPORTED_FEATURES: u16 = 0x0003;
    pub const SET_EVENT_MASK: u16 = 0x0004;
    pub const RESET: u16 = 0x0005;
    pub const WRITE_BD_ADDR: u16 = 0x0006;
    pub const SET_TRACE_ENABLE: u16 = 0x0007;
    pub const READ_BUILD_INFO: u16 = 0x0008;
    pub const READ_STATIC_ADDRS: u16 = 0x0009;
    pub const READ_KEY_HIERARCHY_ROOTS: u16 = 0x000a;
    pub const READ_CHIP_TEMP: u16 = 0x000b;
    pub const READ_HOST_STACK_CMDS: u16 = 0x000c;
    pub const SET_SCAN_REQ_REPORTS: u16 = 0x000d;
    pub const WRITE_TX_POWER_LEVEL: u16 = 0x000e;
    pub const READ_TX_POWER_LEVEL: u16 = 0x000f;
    pub const READ_USB_TRANSPORT_MODE: u16 = 0x0010;
    pub const SET_USB_TRANSPORT_MODE: u16 = 0x0011;
    pub const SET_MIN_NUM_USED_CHANS: u16 = 0x0012;
    pub const MESH: u16 = 0x0042;

    // Vendor event subevent codes.
    pub const EVT_FATAL_ERROR: u8 = 0x02;
    pub const EVT_TRACE_INFO: u8 = 0x03;
    pub const EVT_SCAN_REQ_RX: u8 = 0x04;
    pub const EVT_LE_CONNECTIONLESS_IQ_REPORT: u8 = 0x05;
    pub const EVT_LE_CONNECTION_IQ_REPORT: u8 = 0x06;
    /// First byte of the mesh events (`bt_hci_evt_mesh.prefix`), followed by the mesh subevent.
    pub const MESH_EVT_PREFIX: u8 = 0xf0;

    /// Command names by OCF.  OCFs 0x0001..=0x000f are also, in order, bits
    /// 0..=14 of the Read Supported Commands bitmap.
    static COMMANDS: &[(u16, &str)] = &[
        (READ_VERSION_INFO, "Zephyr Read Version Info"),
        (READ_SUPPORTED_COMMANDS, "Zephyr Read Supported Commands"),
        (READ_SUPPORTED_FEATURES, "Zephyr Read Supported Features"),
        (SET_EVENT_MASK, "Zephyr Set Event Mask"),
        (RESET, "Zephyr Reset"),
        (WRITE_BD_ADDR, "Zephyr Write BD_ADDR"),
        (SET_TRACE_ENABLE, "Zephyr Set Trace Enable"),
        (READ_BUILD_INFO, "Zephyr Read Build Info"),
        (READ_STATIC_ADDRS, "Zephyr Read Static Addresses"),
        (READ_KEY_HIERARCHY_ROOTS, "Zephyr Read Key Hierarchy Roots"),
        (READ_CHIP_TEMP, "Zephyr Read Chip Temperature"),
        (READ_HOST_STACK_CMDS, "Zephyr Read Host Stack Commands"),
        (SET_SCAN_REQ_REPORTS, "Zephyr Set Scan Request Reports"),
        (WRITE_TX_POWER_LEVEL, "Zephyr Write TX Power Level"),
        (READ_TX_POWER_LEVEL, "Zephyr Read TX Power Level"),
        (READ_USB_TRANSPORT_MODE, "Zephyr Read USB Transport Mode"),
        (SET_USB_TRANSPORT_MODE, "Zephyr Set USB Transport Mode"),
        (SET_MIN_NUM_USED_CHANS, "Zephyr Set Minimum Number of Used Channels"),
        (MESH, "Zephyr Mesh"),
    ];

    /// Highest bit of the Read Supported Commands bitmap that has a defined meaning.
    const SUPPORTED_COMMAND_BITS: u8 = 15;

    pub fn command_name(ocf: u16) -> Option<&'static str> {
        COMMANDS.iter().find(|(o, _)| *o == ocf).map(|(_, n)| *n)
    }

    /// Name of the command at `bit` of the Read Supported Commands bitmap, without the vendor prefix.
    fn supported_command_name(bit: u8) -> Option<&'static str> {
        if bit >= SUPPORTED_COMMAND_BITS {
            return None;
        }
        command_name(bit as u16 + 1).map(|n| n.strip_prefix("Zephyr ").unwrap_or(n))
    }

    static HW_PLATFORMS: &[(u16, &str)] =
        &[(0x0001, "Intel Corporation"), (0x0002, "Nordic Semiconductor"), (0x0003, "NXP"), (0x0004, "Espressif")];

    static HW_VARIANTS_NORDIC: &[(u16, &str)] =
        &[(0x0001, "nRF51x"), (0x0002, "nRF52x"), (0x0003, "nRF53x"), (0x0004, "nRF54Hx"), (0x0005, "nRF54Lx")];

    static HW_VARIANTS_ESPRESSIF: &[(u16, &str)] = &[
        (0x0001, "ESP32"),
        (0x0002, "ESP32-S3"),
        (0x0003, "ESP32-C2"),
        (0x0004, "ESP32-C3"),
        (0x0005, "ESP32-C6"),
        (0x0006, "ESP32-H2"),
        (0x0007, "ESP32-C5"),
    ];

    static FW_VARIANTS: &[(u8, &str)] = &[
        (0x00, "Standard Bluetooth controller"),
        (0x01, "Vendor specific controller"),
        (0x02, "Firmware loader"),
        (0x03, "Rescue image"),
    ];

    /// Bits of the vendor event mask (Set Event Mask).
    static EVENT_MASK_BITS: &[(u8, &str)] = &[
        (1, "Fatal Error"),
        (2, "Trace Info"),
        (3, "Scan Request Received"),
        (4, "LE Connectionless IQ Report"),
        (5, "LE Connection IQ Report"),
    ];

    static HANDLE_TYPES: &[(u8, &str)] = &[(0x00, "Advertiser"), (0x01, "Scanner"), (0x02, "Connection")];

    static USB_MODES: &[(u8, &str)] = &[(0x00, "H2"), (0x01, "H4")];

    static HOST_STACK_VENDORS: &[(u16, &str)] = &[(0x0001, "Android"), (0x0002, "Microsoft")];

    static MESH_OPCODES: &[(u8, &str)] = &[
        (0x00, "Get Options"),
        (0x01, "Set Scan Filter"),
        (0x02, "Advertise"),
        (0x03, "Advertise Timed"),
        (0x04, "Advertise Cancel"),
        (0x05, "Set Scanning"),
    ];

    const MESH_GET_OPTS: u8 = 0x00;
    const MESH_SET_SCAN_FILTER: u8 = 0x01;
    const MESH_ADVERTISE: u8 = 0x02;
    const MESH_ADVERTISE_TIMED: u8 = 0x03;
    const MESH_ADVERTISE_CANCEL: u8 = 0x04;
    const MESH_SET_SCANNING: u8 = 0x05;

    const MESH_EVT_ADV_COMPLETE: u8 = 0x00;
    const MESH_EVT_SCANNING_REPORT: u8 = 0x01;

    pub fn command_params(st: &mut IndexState, ocf: u16, r: &mut Reader<'_>, out: &mut Out) -> Result<bool> {
        match ocf {
            READ_VERSION_INFO | READ_SUPPORTED_COMMANDS | READ_SUPPORTED_FEATURES | READ_BUILD_INFO
            | READ_STATIC_ADDRS | READ_KEY_HIERARCHY_ROOTS | READ_CHIP_TEMP | READ_HOST_STACK_CMDS
            | READ_USB_TRANSPORT_MODE => {
                // No parameters.
                if !r.is_empty() {
                    return Ok(false);
                }
            }
            SET_EVENT_MASK => {
                mask64("Mask", r, out, EVENT_MASK_BITS)?;
            }
            RESET => {
                enum8("Type", r, out, &[(0x00, "Soft reset"), (0x01, "Hard reset")])?;
            }
            WRITE_BD_ADDR => {
                bdaddr("Address", r, out)?;
            }
            SET_TRACE_ENABLE => {
                enable("Trace", r, out)?;
                enum8("Type", r, out, &[(0x00, "HCI events"), (0x01, "Vendor data channel")])?;
            }
            SET_SCAN_REQ_REPORTS => {
                enable("Scan request reports", r, out)?;
            }
            WRITE_TX_POWER_LEVEL => {
                let t = enum8("Handle type", r, out, HANDLE_TYPES)?;
                ll_handle(st, t, r, out)?;
                tx_power("TX power level", r, out)?;
            }
            READ_TX_POWER_LEVEL => {
                let t = enum8("Handle type", r, out, HANDLE_TYPES)?;
                ll_handle(st, t, r, out)?;
            }
            SET_USB_TRANSPORT_MODE => {
                enum8("Mode", r, out, USB_MODES)?;
            }
            SET_MIN_NUM_USED_CHANS => {
                handle(st, r, out)?;
                phy_mask("PHYs", r, out)?;
                u8_field("Minimum used channels", r, out)?;
            }
            MESH => mesh_command(r, out)?,
            _ => return Ok(false),
        }
        Ok(true)
    }

    pub fn return_params(st: &mut IndexState, ocf: u16, r: &mut Reader<'_>, out: &mut Out) -> Result<bool> {
        match ocf {
            READ_VERSION_INFO => rsp_read_version_info(r, out)?,
            READ_SUPPORTED_COMMANDS => {
                status(r, out)?;
                supported_commands(r.bytes(64)?, out);
            }
            READ_SUPPORTED_FEATURES => {
                status(r, out)?;
                // No feature bits are defined yet; every set bit is flagged.
                mask64("Features", r, out, &[])?;
            }
            SET_EVENT_MASK | RESET | WRITE_BD_ADDR | SET_TRACE_ENABLE | SET_SCAN_REQ_REPORTS | SET_USB_TRANSPORT_MODE
            | SET_MIN_NUM_USED_CHANS => {
                status(r, out)?;
            }
            READ_BUILD_INFO => {
                status(r, out)?;
                let info = r.cstr();
                field!(out, "Build info: {}", info);
            }
            READ_STATIC_ADDRS => rsp_read_static_addrs(r, out)?,
            READ_KEY_HIERARCHY_ROOTS => {
                status(r, out)?;
                key128("Identity root", r, out)?;
                key128("Encryption root", r, out)?;
            }
            READ_CHIP_TEMP => {
                status(r, out)?;
                let t = r.i8()?;
                field!(out, "Temperature: {} C (0x{:02x})", t, t as u8);
            }
            READ_HOST_STACK_CMDS => rsp_read_host_stack_cmds(r, out)?,
            WRITE_TX_POWER_LEVEL => {
                status(r, out)?;
                let t = enum8("Handle type", r, out, HANDLE_TYPES)?;
                ll_handle(st, t, r, out)?;
                tx_power("Selected TX power", r, out)?;
            }
            READ_TX_POWER_LEVEL => {
                status(r, out)?;
                let t = enum8("Handle type", r, out, HANDLE_TYPES)?;
                ll_handle(st, t, r, out)?;
                tx_power("TX power level", r, out)?;
            }
            READ_USB_TRANSPORT_MODE => {
                status(r, out)?;
                let n = r.u8()?;
                field!(out, "Num supported modes: {}", n);
                for _ in 0..n {
                    enum8("Supported mode", r, out, USB_MODES)?;
                }
            }
            MESH => mesh_return(r, out)?,
            _ => return Ok(false),
        }
        Ok(true)
    }

    /// Handle of a Write/Read TX Power Level command: a connection handle (with the
    /// peer address when known), or an advertising set / scanner handle.
    fn ll_handle(st: &IndexState, handle_type: u8, r: &mut Reader<'_>, out: &mut Out) -> Result<u16> {
        if handle_type == 0x02 {
            handle(st, r, out)
        } else {
            u16_field("Handle", r, out)
        }
    }

    fn rsp_read_version_info(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
        status(r, out)?;
        let platform = named16("Hardware platform", r, out, HW_PLATFORMS)?;
        let variants: &[(u16, &str)] = match platform {
            0x0002 => HW_VARIANTS_NORDIC,
            0x0004 => HW_VARIANTS_ESPRESSIF,
            _ => &[],
        };
        named16("Hardware variant", r, out, variants)?;
        named8("Firmware variant", r, out, FW_VARIANTS)?;
        u8_field("Firmware version", r, out)?;
        u16_field("Firmware revision", r, out)?;
        u32_field("Firmware build", r, out)?;
        Ok(())
    }

    /// Print the 64-byte Read Supported Commands bitmap like Read Local Supported Commands.
    fn supported_commands(data: &[u8], out: &mut Out) {
        let count: usize = data.iter().map(|b| b.count_ones() as usize).sum();
        field!(out, "Commands: {} entr{}", count, if count == 1 { "y" } else { "ies" });
        out.nest(|o| {
            for (i, byte) in data.iter().enumerate() {
                for bit in 0..8u8 {
                    if byte & (1 << bit) == 0 {
                        continue;
                    }
                    let name = u8::try_from(i * 8 + bit as usize).ok().and_then(supported_command_name);
                    match name {
                        Some(n) => o.line(format!("{n} (Octet {i} - Bit {bit})")),
                        None => o.unknown(format!("Octet {i} - Bit {bit}")),
                    };
                }
            }
        });
    }

    fn rsp_read_static_addrs(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
        status(r, out)?;
        let n = r.u8()?;
        field!(out, "Num addresses: {}", n);
        for _ in 0..n {
            // Static addresses are random addresses; print the kind like btmon does.
            bdaddr_typed("Address", 0x01, r, out)?;
            key128("Identity root", r, out)?;
        }
        Ok(())
    }

    fn rsp_read_host_stack_cmds(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
        status(r, out)?;
        let n = r.u8()?;
        field!(out, "Num commands: {}", n);
        for _ in 0..n {
            named16("Vendor", r, out, HOST_STACK_VENDORS)?;
            let base = r.u16()?;
            field!(out, "Opcode base: 0x{:04x} (0x{:02x}|0x{:04x})", base, ogf(base), ocf(base));
        }
        Ok(())
    }

    // --- Mesh (OCF 0x0042) -------------------------------------------------

    fn mesh_opcode(r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
        enum8("Opcode", r, out, MESH_OPCODES)
    }

    fn mesh_command(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
        let op = mesh_opcode(r, out)?;
        match op {
            MESH_GET_OPTS => {}
            MESH_SET_SCAN_FILTER => {
                u8_field("Scan filter", r, out)?;
                enable("Filter duplicates", r, out)?;
                let n = r.u8()?;
                field!(out, "Num patterns: {}", n);
                for _ in 0..n {
                    let len = r.u8()? as usize;
                    hex_bytes("Pattern", r, out, len)?;
                }
            }
            MESH_ADVERTISE => {
                u8_field("Advertising slot", r, out)?;
                mesh_own_addr(r, out)?;
                adv_channel_map(r, out)?;
                tx_power("TX power", r, out)?;
                u8_field("Min TX delay", r, out)?;
                u8_field("Max TX delay", r, out)?;
                u8_field("Retransmit count", r, out)?;
                u8_field("Retransmit interval", r, out)?;
                u8_field("Scan delay", r, out)?;
                u16_field("Scan duration", r, out)?;
                u8_field("Scan filter", r, out)?;
                mesh_adv_data(r, out)?;
            }
            MESH_ADVERTISE_TIMED => {
                u8_field("Advertising slot", r, out)?;
                mesh_own_addr(r, out)?;
                adv_channel_map(r, out)?;
                tx_power("TX power", r, out)?;
                u8_field("Retransmit count", r, out)?;
                u8_field("Retransmit interval", r, out)?;
                u32_field("Instant", r, out)?;
                u16_field("TX delay", r, out)?;
                u16_field("TX window", r, out)?;
                mesh_adv_data(r, out)?;
            }
            MESH_ADVERTISE_CANCEL => {
                u8_field("Advertising slot", r, out)?;
            }
            MESH_SET_SCANNING => {
                enable("Scanning", r, out)?;
                adv_channel_map(r, out)?;
                u8_field("Scan filter", r, out)?;
            }
            _ => {
                if !r.is_empty() {
                    out.hex(r.rest());
                }
            }
        }
        Ok(())
    }

    fn mesh_return(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
        status(r, out)?;
        let op = mesh_opcode(r, out)?;
        match op {
            MESH_GET_OPTS => {
                u8_field("Revision", r, out)?;
                adv_channel_map(r, out)?;
                i8_hex("Min TX power", r, out)?;
                i8_hex("Max TX power", r, out)?;
                u8_field("Max scan filters", r, out)?;
                u8_field("Max filter patterns", r, out)?;
                u8_field("Max advertising slots", r, out)?;
                u8_field("Max TX window", r, out)?;
                u8_field("Event prefix length", r, out)?;
                let p = r.u8()?;
                field!(out, "Event prefix: 0x{:02x}", p);
            }
            MESH_SET_SCAN_FILTER => {
                u8_field("Scan filter", r, out)?;
            }
            MESH_ADVERTISE | MESH_ADVERTISE_TIMED | MESH_ADVERTISE_CANCEL => {
                u8_field("Advertising slot", r, out)?;
            }
            MESH_SET_SCANNING => {}
            _ => {
                if !r.is_empty() {
                    out.hex(r.rest());
                }
            }
        }
        Ok(())
    }

    fn mesh_own_addr(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
        let t = addr_type_labelled("Own address type", r, out)?;
        bdaddr_typed("Random address", if t == 0x00 { 0x00 } else { 0x01 }, r, out)?;
        Ok(())
    }

    /// `Data length: N` followed by the advertising data, which sits in a fixed 31-byte field.
    fn mesh_adv_data(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
        let len = r.u8()? as usize;
        field!(out, "Data length: {}", len);
        let data = r.bytes(r.remaining().min(31))?;
        if len > data.len() {
            out.error(format!("Data length exceeds the {} bytes present", data.len()));
            crate::ad::decode(data, out);
        } else {
            crate::ad::decode(&data[..len], out);
        }
        Ok(())
    }

    // --- Events ------------------------------------------------------------

    pub fn event_params(st: &mut IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<bool> {
        let sub = match r.peek().first() {
            Some(&b) => b,
            None => return Ok(false),
        };
        let name = match sub {
            EVT_FATAL_ERROR => "Zephyr Fatal Error",
            EVT_TRACE_INFO => "Zephyr Trace Info",
            EVT_SCAN_REQ_RX => "Zephyr Scan Request Received",
            EVT_LE_CONNECTIONLESS_IQ_REPORT => "Zephyr LE Connectionless IQ Report",
            EVT_LE_CONNECTION_IQ_REPORT => "Zephyr LE Connection IQ Report",
            MESH_EVT_PREFIX => return mesh_event(r, out),
            // Nothing consumed: the caller hex dumps the whole payload.
            _ => return Ok(false),
        };
        r.skip(1)?;
        field!(out, "{} (0x{:02x})", name, sub);
        out.nest(|o| match sub {
            EVT_FATAL_ERROR => fatal_error(r, o),
            EVT_TRACE_INFO => trace_info(r, o),
            EVT_SCAN_REQ_RX => {
                peer_addr(r, o)?;
                rssi(r, o)?;
                Ok(())
            }
            EVT_LE_CONNECTIONLESS_IQ_REPORT => connectionless_iq_report(r, o),
            EVT_LE_CONNECTION_IQ_REPORT => connection_iq_report(st, r, o),
            _ => Ok(()),
        })?;
        Ok(true)
    }

    /// Zephyr kernel fatal error reasons (`k_fatal_error_reason`).
    fn fatal_reason_str(reason: u32) -> Option<&'static str> {
        Some(match reason {
            0 => "CPU exception",
            1 => "Spurious interrupt",
            2 => "Stack check failure",
            3 => "Kernel oops",
            4 => "Kernel panic",
            16.. => "Architecture specific",
            _ => return None,
        })
    }

    fn fatal_error(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
        let t = enum8("Type", r, out, &[(0x01, "Stack frame"), (0x02, "Controller assert"), (0x03, "Trace")])?;
        match t {
            0x01 => {
                let reason = r.u32()?;
                match fatal_reason_str(reason) {
                    Some(n) => field!(out, "Reason: {} (0x{:08x})", n, reason),
                    None => out.unknown(format!("Reason: Unknown (0x{reason:08x})")),
                };
                let cpu = enum8("CPU type", r, out, &[(0x01, "Cortex-M")])?;
                if cpu == 0x01 {
                    for reg in ["a1", "a2", "a3", "a4", "ip", "lr", "pc", "xpsr"] {
                        u32_hex(reg, r, out)?;
                    }
                } else if !r.is_empty() {
                    out.hex(r.rest());
                }
            }
            0x02 => file_line(r, out)?,
            0x03 => {
                let pc = r.u64()?;
                field!(out, "PC: 0x{:08x}", pc);
                file_line(r, out)?;
            }
            _ => {
                if !r.is_empty() {
                    out.hex(r.rest());
                }
            }
        }
        Ok(())
    }

    /// NUL-terminated source file name followed by a 32-bit line number.
    fn file_line(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
        let file = r.cstr();
        field!(out, "File: {}", file);
        u32_field("Line", r, out)?;
        Ok(())
    }

    fn trace_info(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
        enum8(
            "Type",
            r,
            out,
            &[(0x01, "LMP TX"), (0x02, "LMP RX"), (0x03, "LLCP TX"), (0x04, "LLCP RX"), (0x05, "LE connection indication")],
        )?;
        if !r.is_empty() {
            out.hex(r.rest());
        }
        Ok(())
    }

    /// Fields shared by both IQ reports, from the RSSI onwards.  Samples are
    /// 16-bit I/Q pairs; 0x8000 marks an invalid sample.
    fn iq_report_tail(r: &mut Reader<'_>, out: &mut Out, counter_label: &str) -> Result<()> {
        let v = r.i16()?;
        let a = v.unsigned_abs();
        field!(out, "RSSI: {}{}.{} dBm (0x{:04x})", if v < 0 { "-" } else { "" }, a / 10, a % 10, v as u16);
        u8_field("RSSI antenna ID", r, out)?;
        enum8(
            "CTE type",
            r,
            out,
            &[
                (0x00, "AoA Constant Tone Extension"),
                (0x01, "AoD Constant Tone Extension with 1 us slots"),
                (0x02, "AoD Constant Tone Extension with 2 us slots"),
            ],
        )?;
        enum8("Slot durations", r, out, &[(0x01, "1 us"), (0x02, "2 us")])?;
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
        let mut samples = Vec::with_capacity(n);
        for _ in 0..n {
            let i = r.i16()?;
            let q = r.i16()?;
            samples.push((i, q));
        }
        let sample = |v: i16| if v as u16 == 0x8000 { "n/a".to_string() } else { v.to_string() };
        out.group("IQ samples (I/Q)", |o| {
            for (row, chunk) in samples.chunks(8).enumerate() {
                let mut s = format!("{:2}:", row * 8);
                for (i, q) in chunk {
                    s.push_str(&format!(" {}/{}", sample(*i), sample(*q)));
                }
                o.line(s);
            }
        });
        Ok(())
    }

    fn connectionless_iq_report(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
        let h = read_handle(r)?;
        match h {
            0x0fff => field!(out, "Sync handle: Receiver test (0x0fff)"),
            _ => field!(out, "Sync handle: {}", h),
        };
        u8_field("Channel index", r, out)?;
        iq_report_tail(r, out, "Periodic event counter")
    }

    fn connection_iq_report(st: &IndexState, r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
        handle(st, r, out)?;
        enum8("RX PHY", r, out, &[(0x01, "LE 1M"), (0x02, "LE 2M")])?;
        u8_field("Data channel index", r, out)?;
        iq_report_tail(r, out, "Connection event counter")
    }

    /// Mesh events: prefix byte (0xf0) then the mesh subevent code.
    fn mesh_event(r: &mut Reader<'_>, out: &mut Out) -> Result<bool> {
        let sub = match r.peek().get(1) {
            Some(&b) => b,
            None => return Ok(false),
        };
        let name = match sub {
            MESH_EVT_ADV_COMPLETE => "Zephyr Mesh Advertising Complete",
            MESH_EVT_SCANNING_REPORT => "Zephyr Mesh Scanning Report",
            _ => return Ok(false),
        };
        r.skip(2)?;
        field!(out, "{} (0x{:02x}|0x{:02x})", name, MESH_EVT_PREFIX, sub);
        out.nest(|o| -> Result<()> {
            match sub {
                MESH_EVT_ADV_COMPLETE => {
                    u8_field("Advertising slot", r, o)?;
                }
                _ => {
                    let n = r.u8()?;
                    field!(o, "Num reports: {}", n);
                    for _ in 0..n {
                        peer_addr(r, o)?;
                        u8_field("Channel", r, o)?;
                        rssi(r, o)?;
                        u32_field("Instant", r, o)?;
                        let len = r.u8()? as usize;
                        field!(o, "Data length: {}", len);
                        let data = r.bytes(len)?;
                        crate::ad::decode(data, o);
                    }
                }
            }
            Ok(())
        })?;
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{Connection, LinkType};
    use crate::reader::BdAddr;

    const OP: u16 = 0xfc00;

    fn state(manufacturer: Option<u16>) -> IndexState {
        IndexState { manufacturer, ..Default::default() }
    }

    /// Render the tree as indented lines (two spaces per level) for easy comparison.
    fn flatten(nodes: &[crate::tree::Node]) -> Vec<String> {
        let mut lines = Vec::new();
        crate::tree::render_lines(nodes, 0, |indent, n| lines.push(format!("{}{}", " ".repeat(indent), n.text)));
        lines
    }

    fn cmd_lines(st: &mut IndexState, opcode: u16, data: &[u8]) -> Vec<String> {
        let mut out = Out::new();
        let mut r = Reader::new(data);
        assert!(command_params(st, opcode, &mut r, &mut out).unwrap());
        assert!(r.is_empty(), "unconsumed bytes: {:02x?}", r.rest());
        flatten(out.roots())
    }

    fn rsp_lines(st: &mut IndexState, opcode: u16, data: &[u8]) -> Vec<String> {
        let mut out = Out::new();
        let mut r = Reader::new(data);
        assert!(return_params(st, opcode, &mut r, &mut out).unwrap());
        assert!(r.is_empty(), "unconsumed bytes: {:02x?}", r.rest());
        flatten(out.roots())
    }

    fn evt_lines(st: &mut IndexState, data: &[u8]) -> Vec<String> {
        let mut out = Out::new();
        let mut r = Reader::new(data);
        assert!(event_params(st, &mut r, &mut out).unwrap());
        assert!(r.is_empty(), "unconsumed bytes: {:02x?}", r.rest());
        flatten(out.roots())
    }

    #[test]
    fn names_depend_on_manufacturer() {
        for m in [None, Some(0x05f1), Some(0x0059)] {
            assert_eq!(command_name(&state(m), OP | 0x0001), Some("Zephyr Read Version Info"));
            assert_eq!(command_name(&state(m), OP | 0x0042), Some("Zephyr Mesh"));
        }
        assert_eq!(command_name(&state(None), OP | 0x0100), None);
        // Not a vendor opcode.
        assert_eq!(command_name(&state(None), 0x0c01), None);
        // Intel: no decoder, so no names and nothing decoded.
        let mut st = state(Some(0x0002));
        assert_eq!(command_name(&st, OP | 0x0001), None);
        let mut out = Out::new();
        assert!(!command_params(&mut st, OP | 0x0005, &mut Reader::new(&[0x00]), &mut out).unwrap());
        assert!(!return_params(&mut st, OP | 0x0001, &mut Reader::new(&[0x00; 13]), &mut out).unwrap());
        assert!(!event_params(&mut st, &mut Reader::new(&[0x04, 0, 1, 2, 3, 4, 5, 6, 0xd3]), &mut out).unwrap());
        assert!(out.is_empty());
    }

    #[test]
    fn read_version_info() {
        let mut st = state(Some(0x05f1));
        assert_eq!(cmd_lines(&mut st, OP | 0x0001, &[]), Vec::<String>::new());
        // From an nRF52 boot capture.
        let lines = rsp_lines(&mut st, OP | 0x0001, &[0x00, 0x02, 0x00, 0x02, 0x00, 0x00, 0x04, 0x04, 0x00, 0x63, 0x00, 0x00, 0x00]);
        assert_eq!(
            lines,
            [
                "Status: Success (0x00)",
                "Hardware platform: Nordic Semiconductor (0x0002)",
                "Hardware variant: nRF52x (0x0002)",
                "Firmware variant: Standard Bluetooth controller (0x00)",
                "Firmware version: 4",
                "Firmware revision: 4",
                "Firmware build: 99",
            ]
        );
        let lines = rsp_lines(&mut st, OP | 0x0001, &[0x00, 0x04, 0x00, 0x05, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(lines[1], "Hardware platform: Espressif (0x0004)");
        assert_eq!(lines[2], "Hardware variant: ESP32-C6 (0x0005)");
        assert_eq!(lines[3], "Firmware variant: Vendor specific controller (0x01)");
        let lines = rsp_lines(&mut st, OP | 0x0001, &[0x00; 13]);
        assert_eq!(lines[1], "Hardware platform: Unknown (0x0000)");
        assert_eq!(lines[2], "Hardware variant: Unknown (0x0000)");
    }

    #[test]
    fn read_supported_commands() {
        let mut data = vec![0x00, 0xa7, 0x03];
        data.resize(65, 0);
        data[64] = 0x80;
        let lines = rsp_lines(&mut state(None), OP | 0x0002, &data);
        assert_eq!(
            lines,
            [
                "Status: Success (0x00)",
                "Commands: 8 entries",
                "  Read Version Info (Octet 0 - Bit 0)",
                "  Read Supported Commands (Octet 0 - Bit 1)",
                "  Read Supported Features (Octet 0 - Bit 2)",
                "  Write BD_ADDR (Octet 0 - Bit 5)",
                "  Read Build Info (Octet 0 - Bit 7)",
                "  Read Static Addresses (Octet 1 - Bit 0)",
                "  Read Key Hierarchy Roots (Octet 1 - Bit 1)",
                "  Octet 63 - Bit 7",
            ]
        );
        // Parameters that are not expected are left to the caller.
        let mut out = Out::new();
        assert!(!command_params(&mut state(None), OP | 0x0002, &mut Reader::new(&[0x01]), &mut out).unwrap());
    }

    #[test]
    fn supported_features_and_event_mask() {
        let mut st = state(None);
        let mut data = vec![0x00, 0x01];
        data.resize(9, 0);
        let lines = rsp_lines(&mut st, OP | 0x0003, &data);
        assert_eq!(lines, ["Status: Success (0x00)", "Features: 0x01 0x00 0x00 0x00 0x00 0x00 0x00 0x00", "  Reserved (0x1)"]);

        let lines = cmd_lines(&mut st, OP | 0x0004, &[0x3e, 0, 0, 0, 0, 0, 0, 0x80]);
        assert_eq!(
            lines,
            [
                "Mask: 0x3e 0x00 0x00 0x00 0x00 0x00 0x00 0x80",
                "  Fatal Error",
                "  Trace Info",
                "  Scan Request Received",
                "  LE Connectionless IQ Report",
                "  LE Connection IQ Report",
                "  Reserved (0x8000000000000000)",
            ]
        );
        assert_eq!(rsp_lines(&mut st, OP | 0x0004, &[0x00]), ["Status: Success (0x00)"]);
    }

    #[test]
    fn simple_commands() {
        let mut st = state(None);
        assert_eq!(cmd_lines(&mut st, OP | 0x0005, &[0x01]), ["Type: Hard reset (0x01)"]);
        assert_eq!(rsp_lines(&mut st, OP | 0x0005, &[0x0c]), ["Status: Command Disallowed (0x0c)"]);
        assert_eq!(
            cmd_lines(&mut st, OP | 0x0006, &[0x13, 0x71, 0xda, 0x7d, 0x1a, 0x00]),
            ["Address: 00:1A:7D:DA:71:13 (cyber-blue(HK)Ltd)"]
        );
        assert_eq!(cmd_lines(&mut st, OP | 0x0007, &[0x01, 0x00]), ["Trace: Enabled (0x01)", "Type: HCI events (0x00)"]);
        assert_eq!(cmd_lines(&mut st, OP | 0x000d, &[0x01]), ["Scan request reports: Enabled (0x01)"]);
        assert_eq!(cmd_lines(&mut st, OP | 0x0011, &[0x01]), ["Mode: H4 (0x01)"]);
        assert_eq!(
            rsp_lines(&mut st, OP | 0x0010, &[0x00, 0x02, 0x00, 0x01]),
            ["Status: Success (0x00)", "Num supported modes: 2", "Supported mode: H2 (0x00)", "Supported mode: H4 (0x01)"]
        );
        assert_eq!(rsp_lines(&mut st, OP | 0x000b, &[0x00, 0xe7]), ["Status: Success (0x00)", "Temperature: -25 C (0xe7)"]);
        assert_eq!(
            rsp_lines(&mut st, OP | 0x0008, b"\x00Zephyr OS v4.2.0\0"),
            ["Status: Success (0x00)", "Build info: Zephyr OS v4.2.0"]
        );
    }

    #[test]
    fn read_static_addrs_and_key_roots() {
        let mut st = state(None);
        // From an nRF52 boot capture.
        let lines = rsp_lines(
            &mut st,
            OP | 0x0009,
            &[
                0x00, 0x01, 0x1d, 0x02, 0xd7, 0x98, 0xa0, 0xf8, 0x89, 0x0a, 0xf0, 0x38, 0xc7, 0xb2, 0xf6, 0xd3, 0x5a, 0x30, 0x33,
                0xf2, 0xd6, 0x07, 0x43, 0x9a,
            ],
        );
        assert_eq!(
            lines,
            [
                "Status: Success (0x00)",
                "Num addresses: 1",
                "Address: F8:A0:98:D7:02:1D (Static)",
                "Identity root: 890af038c7b2f6d35a3033f2d607439a",
            ]
        );
        let mut data = vec![0x00];
        data.extend_from_slice(&[0x11; 16]);
        data.extend_from_slice(&[0x22; 16]);
        let lines = rsp_lines(&mut st, OP | 0x000a, &data);
        assert_eq!(
            lines,
            [
                "Status: Success (0x00)",
                "Identity root: 11111111111111111111111111111111",
                "Encryption root: 22222222222222222222222222222222",
            ]
        );
    }

    #[test]
    fn host_stack_commands() {
        let lines = rsp_lines(&mut state(None), OP | 0x000c, &[0x00, 0x02, 0x01, 0x00, 0x53, 0xfd, 0x02, 0x00, 0x1e, 0xfc]);
        assert_eq!(
            lines,
            [
                "Status: Success (0x00)",
                "Num commands: 2",
                "Vendor: Android (0x0001)",
                "Opcode base: 0xfd53 (0x3f|0x0153)",
                "Vendor: Microsoft (0x0002)",
                "Opcode base: 0xfc1e (0x3f|0x001e)",
            ]
        );
    }

    #[test]
    fn tx_power_level() {
        let mut st = state(None);
        let mut c = Connection::new(3, LinkType::Le);
        c.addr = BdAddr([0x6e, 0x1d, 0x2e, 0x27, 0x65, 0x4b]);
        c.addr_type = 1;
        st.conns.insert(3, c);
        assert_eq!(
            cmd_lines(&mut st, OP | 0x000e, &[0x02, 0x03, 0x00, 0x7f]),
            [
                "Handle type: Connection (0x02)",
                "Handle: 3 Address: 4B:65:27:2E:1D:6E (Resolvable)",
                "TX power level: Host has no preference (0x7f)",
            ]
        );
        assert_eq!(
            rsp_lines(&mut st, OP | 0x000e, &[0x00, 0x00, 0x01, 0x00, 0xfc]),
            ["Status: Success (0x00)", "Handle type: Advertiser (0x00)", "Handle: 1", "Selected TX power: -4 dbm (0xfc)"]
        );
        assert_eq!(cmd_lines(&mut st, OP | 0x000f, &[0x01, 0x00, 0x00]), ["Handle type: Scanner (0x01)", "Handle: 0"]);
        assert_eq!(
            rsp_lines(&mut st, OP | 0x000f, &[0x00, 0x01, 0x00, 0x00, 0x08]),
            ["Status: Success (0x00)", "Handle type: Scanner (0x01)", "Handle: 0", "TX power level: 8 dbm (0x08)"]
        );
        assert_eq!(
            cmd_lines(&mut st, OP | 0x0012, &[0x03, 0x00, 0x03, 0x14]),
            ["Handle: 3 Address: 4B:65:27:2E:1D:6E (Resolvable)", "PHYs: 0x03", "  LE 1M", "  LE 2M", "Minimum used channels: 20"]
        );
    }

    #[test]
    fn mesh_commands() {
        let mut st = state(None);
        assert_eq!(cmd_lines(&mut st, OP | 0x0042, &[0x00]), ["Opcode: Get Options (0x00)"]);
        let lines = rsp_lines(&mut st, OP | 0x0042, &[0x00, 0x00, 0x01, 0x07, 0xe2, 0x04, 0x02, 0x03, 0x01, 0x05, 0x01, 0xf0]);
        assert_eq!(
            lines,
            [
                "Status: Success (0x00)",
                "Opcode: Get Options (0x00)",
                "Revision: 1",
                "Channel map: 37, 38, 39 (0x07)",
                "Min TX power: -30 (0xe2)",
                "Max TX power: 4 (0x04)",
                "Max scan filters: 2",
                "Max filter patterns: 3",
                "Max advertising slots: 1",
                "Max TX window: 5",
                "Event prefix length: 1",
                "Event prefix: 0xf0",
            ]
        );
        assert_eq!(
            cmd_lines(&mut st, OP | 0x0042, &[0x01, 0x01, 0x01, 0x01, 0x02, 0x2a, 0x2b]),
            [
                "Opcode: Set Scan Filter (0x01)",
                "Scan filter: 1",
                "Filter duplicates: Enabled (0x01)",
                "Num patterns: 1",
                "Pattern: 2a 2b",
            ]
        );
        assert_eq!(cmd_lines(&mut st, OP | 0x0042, &[0x04, 0x01]), ["Opcode: Advertise Cancel (0x04)", "Advertising slot: 1"]);
        assert_eq!(
            rsp_lines(&mut st, OP | 0x0042, &[0x00, 0x04, 0x01]),
            ["Status: Success (0x00)", "Opcode: Advertise Cancel (0x04)", "Advertising slot: 1"]
        );
        assert_eq!(
            cmd_lines(&mut st, OP | 0x0042, &[0x05, 0x01, 0x07, 0x00]),
            ["Opcode: Set Scanning (0x05)", "Scanning: Enabled (0x01)", "Channel map: 37, 38, 39 (0x07)", "Scan filter: 0"]
        );
    }

    #[test]
    fn mesh_advertise() {
        let mut data = vec![0x02, 0x01, 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0xc6, 0x07, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x10, 0x00, 0x00];
        data.push(3);
        data.extend_from_slice(&[0x02, 0x01, 0x06]);
        data.resize(data.len() + 28, 0);
        let lines = cmd_lines(&mut state(None), OP | 0x0042, &data);
        assert_eq!(&lines[..4], ["Opcode: Advertise (0x02)", "Advertising slot: 1", "Own address type: Random (0x01)", "Random address: C6:55:44:33:22:11 (Static)"]);
        assert_eq!(&lines[4..13], [
            "Channel map: 37, 38, 39 (0x07)",
            "TX power: 0 dbm (0x00)",
            "Min TX delay: 1",
            "Max TX delay: 2",
            "Retransmit count: 3",
            "Retransmit interval: 4",
            "Scan delay: 5",
            "Scan duration: 16",
            "Scan filter: 0",
        ]);
        assert_eq!(lines[13], "Data length: 3");
        assert!(lines[14].starts_with("Flags:"), "{:?}", lines);
    }

    #[test]
    fn scan_request_received_event() {
        let lines = evt_lines(&mut state(None), &[0x04, 0x01, 0x6e, 0x1d, 0x2e, 0x27, 0x65, 0x4b, 0xd3]);
        assert_eq!(
            lines,
            [
                "Zephyr Scan Request Received (0x04)",
                "  Address type: Random (0x01)",
                "  Address: 4B:65:27:2E:1D:6E (Resolvable)",
                "  RSSI: -45 dBm (0xd3)",
            ]
        );
    }

    #[test]
    fn fatal_error_events() {
        let mut st = state(None);
        let lines = evt_lines(&mut st, b"\x02\x02ull.c\0\x39\x05\x00\x00");
        assert_eq!(lines, ["Zephyr Fatal Error (0x02)", "  Type: Controller assert (0x02)", "  File: ull.c", "  Line: 1337"]);

        let lines = evt_lines(&mut st, b"\x02\x03\x00\x10\x00\x20\x00\x00\x00\x00lll.c\0\x07\x00\x00\x00");
        assert_eq!(
            lines,
            ["Zephyr Fatal Error (0x02)", "  Type: Trace (0x03)", "  PC: 0x20001000", "  File: lll.c", "  Line: 7"]
        );

        let mut data = vec![0x02, 0x01, 0x04, 0x00, 0x00, 0x00, 0x01];
        for reg in 1..=8u32 {
            data.extend_from_slice(&reg.to_le_bytes());
        }
        let lines = evt_lines(&mut st, &data);
        assert_eq!(
            lines,
            [
                "Zephyr Fatal Error (0x02)",
                "  Type: Stack frame (0x01)",
                "  Reason: Kernel panic (0x00000004)",
                "  CPU type: Cortex-M (0x01)",
                "  a1: 0x00000001",
                "  a2: 0x00000002",
                "  a3: 0x00000003",
                "  a4: 0x00000004",
                "  ip: 0x00000005",
                "  lr: 0x00000006",
                "  pc: 0x00000007",
                "  xpsr: 0x00000008",
            ]
        );

        let lines = evt_lines(&mut st, &[0x03, 0x03, 0x01, 0x02]);
        assert_eq!(lines[..2], ["Zephyr Trace Info (0x03)", "  Type: LLCP TX (0x03)"]);
        assert!(lines[2].starts_with("  01 02"));
    }

    #[test]
    fn iq_report_events() {
        let mut st = state(None);
        let lines = evt_lines(
            &mut st,
            &[0x06, 0x03, 0x00, 0x02, 0x11, 0xe6, 0xfd, 0x01, 0x00, 0x02, 0x00, 0x34, 0x12, 0x02, 0x10, 0x00, 0xf0, 0xff, 0x00, 0x80, 0x00, 0x80],
        );
        assert_eq!(
            lines,
            [
                "Zephyr LE Connection IQ Report (0x06)",
                "  Handle: 3",
                "  RX PHY: LE 2M (0x02)",
                "  Data channel index: 17",
                "  RSSI: -53.8 dBm (0xfde6)",
                "  RSSI antenna ID: 1",
                "  CTE type: AoA Constant Tone Extension (0x00)",
                "  Slot durations: 2 us (0x02)",
                "  Packet status: CRC was correct (0x00)",
                "  Connection event counter: 4660 (0x1234)",
                "  Sample count: 2",
                "  IQ samples (I/Q)",
                "     0: 16/-16 n/a/n/a",
            ]
        );
        let lines = evt_lines(&mut st, &[0x05, 0xff, 0x0f, 0x05, 0x00, 0x00, 0x00, 0x01, 0x01, 0xff, 0x01, 0x00, 0x00]);
        assert_eq!(lines[1], "  Sync handle: Receiver test (0x0fff)");
        assert_eq!(lines[2], "  Channel index: 5");
        assert_eq!(lines[3], "  RSSI: 0.0 dBm (0x0000)");
        assert_eq!(lines[8], "  Periodic event counter: 1 (0x0001)");
        assert_eq!(lines[9], "  Sample count: 0");
    }

    #[test]
    fn mesh_events() {
        let mut st = state(None);
        assert_eq!(evt_lines(&mut st, &[0xf0, 0x00, 0x01]), ["Zephyr Mesh Advertising Complete (0xf0|0x00)", "  Advertising slot: 1"]);
        let lines = evt_lines(
            &mut st,
            &[0xf0, 0x01, 0x01, 0x00, 0x13, 0x71, 0xda, 0x7d, 0x1a, 0x00, 0x25, 0xd3, 0x10, 0x00, 0x00, 0x00, 0x03, 0x02, 0x01, 0x06],
        );
        assert_eq!(
            &lines[..8],
            [
                "Zephyr Mesh Scanning Report (0xf0|0x01)",
                "  Num reports: 1",
                "  Address type: Public (0x00)",
                "  Address: 00:1A:7D:DA:71:13 (cyber-blue(HK)Ltd)",
                "  Channel: 37",
                "  RSSI: -45 dBm (0xd3)",
                "  Instant: 16",
                "  Data length: 3",
            ]
        );
        assert!(lines[8].starts_with("  Flags:"), "{:?}", lines);
    }

    #[test]
    fn unknown_subevents_are_left_alone() {
        let mut st = state(None);
        let mut out = Out::new();
        for data in [&[0x01u8, 0x02][..], &[0xf0, 0x07, 0x00][..], &[][..]] {
            let mut r = Reader::new(data);
            assert!(!event_params(&mut st, &mut r, &mut out).unwrap());
            assert_eq!(r.remaining(), data.len());
        }
        assert!(out.is_empty());
    }

    #[test]
    fn truncated_data_is_an_error() {
        let mut st = state(None);
        let mut out = Out::new();
        assert!(return_params(&mut st, OP | 0x0001, &mut Reader::new(&[0x00, 0x02]), &mut out).is_err());
        assert!(return_params(&mut st, OP | 0x0009, &mut Reader::new(&[0x00, 0x02, 0x01]), &mut out).is_err());
        assert!(event_params(&mut st, &mut Reader::new(&[0x02, 0x02, b'a']), &mut out).is_err());
    }
}
