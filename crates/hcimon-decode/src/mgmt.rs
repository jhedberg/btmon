//! BlueZ management interface (`HCI_CHANNEL_CONTROL`) records.
//!
//! These only appear when capturing from the Linux kernel's monitor socket.
//! The full management protocol is large; this module names the opcodes and
//! events and decodes the framing, leaving parameters as hex dumps.

use hcimon_capture::Packet;

use crate::context::Context;
use crate::reader::Reader;
use crate::tree::Out;
use crate::{field, Decoded, Layer};

/// Management command opcodes (`doc/mgmt-api.txt`).
pub static COMMANDS: &[(u16, &str)] = &[
    (0x0001, "Read Management Version Information"),
    (0x0002, "Read Management Supported Commands"),
    (0x0003, "Read Controller Index List"),
    (0x0004, "Read Controller Information"),
    (0x0005, "Set Powered"),
    (0x0006, "Set Discoverable"),
    (0x0007, "Set Connectable"),
    (0x0008, "Set Fast Connectable"),
    (0x0009, "Set Bondable"),
    (0x000a, "Set Link Security"),
    (0x000b, "Set Secure Simple Pairing"),
    (0x000c, "Set High Speed"),
    (0x000d, "Set Low Energy"),
    (0x000e, "Set Device Class"),
    (0x000f, "Set Local Name"),
    (0x0010, "Add UUID"),
    (0x0011, "Remove UUID"),
    (0x0012, "Load Link Keys"),
    (0x0013, "Load Long Term Keys"),
    (0x0014, "Disconnect"),
    (0x0015, "Get Connections"),
    (0x0016, "PIN Code Reply"),
    (0x0017, "PIN Code Negative Reply"),
    (0x0018, "Set IO Capability"),
    (0x0019, "Pair Device"),
    (0x001a, "Cancel Pair Device"),
    (0x001b, "Unpair Device"),
    (0x001c, "User Confirmation Reply"),
    (0x001d, "User Confirmation Negative Reply"),
    (0x001e, "User Passkey Reply"),
    (0x001f, "User Passkey Negative Reply"),
    (0x0020, "Read Local Out Of Band Data"),
    (0x0021, "Add Remote Out Of Band Data"),
    (0x0022, "Remove Remote Out Of Band Data"),
    (0x0023, "Start Discovery"),
    (0x0024, "Stop Discovery"),
    (0x0025, "Confirm Name"),
    (0x0026, "Block Device"),
    (0x0027, "Unblock Device"),
    (0x0028, "Set Device ID"),
    (0x0029, "Set Advertising"),
    (0x002a, "Set BR/EDR"),
    (0x002b, "Set Static Address"),
    (0x002c, "Set Scan Parameters"),
    (0x002d, "Set Secure Connections"),
    (0x002e, "Set Debug Keys"),
    (0x002f, "Set Privacy"),
    (0x0030, "Load Identity Resolving Keys"),
    (0x0031, "Get Connection Information"),
    (0x0032, "Get Clock Information"),
    (0x0033, "Add Device"),
    (0x0034, "Remove Device"),
    (0x0035, "Load Connection Parameters"),
    (0x0036, "Read Unconfigured Controller Index List"),
    (0x0037, "Read Controller Configuration Information"),
    (0x0038, "Set External Configuration"),
    (0x0039, "Set Public Address"),
    (0x003a, "Start Service Discovery"),
    (0x003b, "Read Local Out Of Band Extended Data"),
    (0x003c, "Read Extended Controller Index List"),
    (0x003d, "Read Advertising Features"),
    (0x003e, "Add Advertising"),
    (0x003f, "Remove Advertising"),
    (0x0040, "Get Advertising Size Information"),
    (0x0041, "Start Limited Discovery"),
    (0x0042, "Read Extended Controller Information"),
    (0x0043, "Set Appearance"),
    (0x0044, "Get PHY Configuration"),
    (0x0045, "Set PHY Configuration"),
    (0x0046, "Set Blocked Keys"),
    (0x0047, "Set Wideband Speech"),
    (0x0048, "Read Controller Capabilities"),
    (0x0049, "Read Experimental Features Information"),
    (0x004a, "Set Experimental Feature"),
    (0x004b, "Read Default System Configuration"),
    (0x004c, "Set Default System Configuration"),
    (0x004d, "Read Default Runtime Configuration"),
    (0x004e, "Set Default Runtime Configuration"),
    (0x004f, "Get Device Flags"),
    (0x0050, "Set Device Flags"),
    (0x0051, "Read Advertisement Monitor Features"),
    (0x0052, "Add Advertisement Patterns Monitor"),
    (0x0053, "Remove Advertisement Monitor"),
    (0x0054, "Add Extended Advertising Parameters"),
    (0x0055, "Add Extended Advertising Data"),
    (0x0056, "Add Advertisement Patterns Monitor With RSSI Threshold"),
    (0x0057, "Set Mesh Receiver"),
    (0x0058, "Read Mesh Features"),
    (0x0059, "Mesh Send"),
    (0x005a, "Mesh Send Cancel"),
    (0x005b, "HCI Command"),
];

/// Management event codes.
pub static EVENTS: &[(u16, &str)] = &[
    (0x0001, "Command Complete"),
    (0x0002, "Command Status"),
    (0x0003, "Controller Error"),
    (0x0004, "Index Added"),
    (0x0005, "Index Removed"),
    (0x0006, "New Settings"),
    (0x0007, "Class Of Device Changed"),
    (0x0008, "Local Name Changed"),
    (0x0009, "New Link Key"),
    (0x000a, "New Long Term Key"),
    (0x000b, "Device Connected"),
    (0x000c, "Device Disconnected"),
    (0x000d, "Connect Failed"),
    (0x000e, "PIN Code Request"),
    (0x000f, "User Confirmation Request"),
    (0x0010, "User Passkey Request"),
    (0x0011, "Authentication Failed"),
    (0x0012, "Device Found"),
    (0x0013, "Discovering"),
    (0x0014, "Device Blocked"),
    (0x0015, "Device Unblocked"),
    (0x0016, "Device Unpaired"),
    (0x0017, "Passkey Notify"),
    (0x0018, "New Identity Resolving Key"),
    (0x0019, "New Signature Resolving Key"),
    (0x001a, "Device Added"),
    (0x001b, "Device Removed"),
    (0x001c, "New Connection Parameter"),
    (0x001d, "Unconfigured Index Added"),
    (0x001e, "Unconfigured Index Removed"),
    (0x001f, "New Configuration Options"),
    (0x0020, "Extended Index Added"),
    (0x0021, "Extended Index Removed"),
    (0x0022, "Local Out Of Band Extended Data Updated"),
    (0x0023, "Advertising Added"),
    (0x0024, "Advertising Removed"),
    (0x0025, "Extended Controller Information Changed"),
    (0x0026, "PHY Configuration Changed"),
    (0x0027, "Experimental Feature Changed"),
    (0x0028, "Default System Configuration Changed"),
    (0x0029, "Default Runtime Configuration Changed"),
    (0x002a, "Device Flags Changed"),
    (0x002b, "Advertisement Monitor Added"),
    (0x002c, "Advertisement Monitor Removed"),
    (0x002d, "Controller Suspended"),
    (0x002e, "Controller Resumed"),
    (0x002f, "Advertisement Monitor Device Found"),
    (0x0030, "Advertisement Monitor Device Lost"),
    (0x0031, "Mesh Device Found"),
    (0x0032, "Mesh Packet Transmit Complete"),
];

pub static STATUS: &[(u8, &str)] = &[
    (0x00, "Success"),
    (0x01, "Unknown Command"),
    (0x02, "Not Connected"),
    (0x03, "Failed"),
    (0x04, "Connect Failed"),
    (0x05, "Authentication Failed"),
    (0x06, "Not Paired"),
    (0x07, "No Resources"),
    (0x08, "Timeout"),
    (0x09, "Already Connected"),
    (0x0a, "Busy"),
    (0x0b, "Rejected"),
    (0x0c, "Not Supported"),
    (0x0d, "Invalid Parameters"),
    (0x0e, "Disconnected"),
    (0x0f, "Not Powered"),
    (0x10, "Cancelled"),
    (0x11, "Invalid Index"),
    (0x12, "RFKilled"),
    (0x13, "Already Paired"),
    (0x14, "Permission Denied"),
];

pub fn command_name(op: u16) -> Option<&'static str> {
    crate::assigned::lookup(COMMANDS, op)
}

pub fn event_name(ev: u16) -> Option<&'static str> {
    crate::assigned::lookup(EVENTS, ev)
}

pub fn status_name(s: u8) -> &'static str {
    crate::assigned::lookup(STATUS, s).unwrap_or("Unknown")
}

fn ctrl_open_close(pkt: &Packet, open: bool) -> Decoded {
    let mut d = Decoded::new(pkt.opcode, '@', if open { "Control Open" } else { "Control Close" });
    d.layers.push(Layer::Mgmt);
    let mut out = Out::new();
    let mut r = Reader::new(&pkt.data);
    if open {
        // struct: u32 cookie, u16 format, u8 version, u16 revision, u32 flags, u16 ident_len, ident
        if let (Ok(cookie), Ok(format)) = (r.u32(), r.u16()) {
            let name = match format {
                0x0001 => "Raw",
                0x0002 => "User Channel",
                0x0003 => "Control",
                _ => "Unknown",
            };
            d.summary = format!("{name} (0x{format:04x})");
            field!(out, "Cookie: 0x{:08x}", cookie);
            if let (Ok(ver), Ok(rev), Ok(flags), Ok(ident_len)) = (r.u8(), r.u16(), r.u32(), r.u16()) {
                field!(out, "Version: {}.{}", ver, rev);
                field!(out, "Flags: 0x{:08x}", flags);
                if let Ok(ident) = r.fixed_str(ident_len as usize) {
                    field!(out, "Ident: {}", ident);
                }
            }
        }
    } else if let Ok(cookie) = r.u32() {
        field!(out, "Cookie: 0x{:08x}", cookie);
    }
    if !r.is_empty() {
        out.hex(r.rest());
    }
    d.fields = out.finish();
    d
}

pub fn decode_ctrl_open(_ctx: &mut Context, pkt: &Packet) -> Decoded {
    ctrl_open_close(pkt, true)
}

pub fn decode_ctrl_close(_ctx: &mut Context, pkt: &Packet) -> Decoded {
    ctrl_open_close(pkt, false)
}

pub fn decode_ctrl_command(_ctx: &mut Context, pkt: &Packet) -> Decoded {
    let mut d = Decoded::new(pkt.opcode, '@', "MGMT Command");
    d.layers.push(Layer::Mgmt);
    let mut r = Reader::new(&pkt.data);
    // struct: u32 cookie, u16 opcode, params...
    let mut out = Out::new();
    match (r.u32(), r.u16()) {
        (Ok(cookie), Ok(op)) => {
            let name = command_name(op);
            d.unknown = name.is_none();
            d.summary = format!("{} (0x{op:04x})", name.unwrap_or("Unknown"));
            d.extra = format!("plen {}", r.remaining());
            field!(out, "Cookie: 0x{:08x}", cookie);
            out.hex(r.rest());
        }
        _ => {
            d.summary = "malformed".into();
            d.unknown = true;
            out.hex(&pkt.data);
        }
    }
    d.fields = out.finish();
    d
}

pub fn decode_ctrl_event(_ctx: &mut Context, pkt: &Packet) -> Decoded {
    let mut d = Decoded::new(pkt.opcode, '@', "MGMT Event");
    d.layers.push(Layer::Mgmt);
    let mut r = Reader::new(&pkt.data);
    let mut out = Out::new();
    match (r.u32(), r.u16()) {
        (Ok(cookie), Ok(ev)) => {
            let name = event_name(ev);
            d.unknown = name.is_none();
            d.summary = format!("{} (0x{ev:04x})", name.unwrap_or("Unknown"));
            d.extra = format!("plen {}", r.remaining());
            field!(out, "Cookie: 0x{:08x}", cookie);
            if ev == 0x0001 || ev == 0x0002 {
                if let (Ok(op), Ok(status)) = (r.u16(), r.u8()) {
                    field!(out, "{} (0x{:04x})", command_name(op).unwrap_or("Unknown"), op);
                    field!(out, "Status: {} (0x{:02x})", status_name(status), status);
                }
            }
            out.hex(r.rest());
        }
        _ => {
            d.summary = "malformed".into();
            d.unknown = true;
            out.hex(&pkt.data);
        }
    }
    d.fields = out.finish();
    d
}
