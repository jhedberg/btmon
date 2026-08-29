//! HCI packet decoders: commands, events, ACL/SCO/ISO data.
//!
//! The dispatch tables live in [`command`], [`event`] and [`le_event`]; each
//! decoder is a small function with the signature
//! `fn(st: &mut IndexState, r: &mut Reader, out: &mut Out) -> Result<()>`.
//! Shared field formatting lives in [`common`].

pub mod acl;
pub mod cmd_classic;
pub mod cmd_le_a;
pub mod cmd_le_b;
pub mod command;
pub mod common;
pub mod event;
pub mod ids;
pub mod iso;
pub mod le_event;
pub mod sco;
pub mod vendor;

use hcimon_capture::Packet;

use crate::context::{Context, IndexState};
use crate::reader::{Reader, Truncated};
use crate::tree::{Out, Style};
use crate::{Decoded, Layer};

pub use ids::{cmd, evt, le_evt};

/// Name of an HCI command opcode.
pub fn command_name(opcode: u16) -> Option<&'static str> {
    crate::assigned::lookup(ids::COMMANDS, opcode)
}

/// Name of an HCI event code.
pub fn event_name(code: u8) -> Option<&'static str> {
    crate::assigned::lookup(ids::EVENTS, code)
}

/// Name of an LE Meta subevent code.
pub fn le_event_name(sub: u8) -> Option<&'static str> {
    crate::assigned::lookup(ids::LE_EVENTS, sub)
}

pub const fn ogf(opcode: u16) -> u8 {
    (opcode >> 10) as u8
}

pub const fn ocf(opcode: u16) -> u16 {
    opcode & 0x03ff
}

/// `OGF` value of vendor-specific commands.
pub const OGF_VENDOR: u8 = 0x3f;

/// Text for a command opcode: `LE Set Advertising Data (0x08|0x0008)`.
pub fn opcode_text(opcode: u16) -> (String, bool) {
    match command_name(opcode) {
        Some(n) => (format!("{n} (0x{:02x}|0x{:04x})", ogf(opcode), ocf(opcode)), false),
        None if ogf(opcode) == OGF_VENDOR => (format!("Vendor (0x{:02x}|0x{:04x})", ogf(opcode), ocf(opcode)), false),
        None => (format!("Unknown (0x{:02x}|0x{:04x})", ogf(opcode), ocf(opcode)), true),
    }
}

/// Like [`opcode_text`], but names vendor commands (`Zephyr Read Version Info (0x3f|0x0001)`)
/// when the controller's manufacturer has a vendor decoder.
pub fn opcode_text_for(st: &IndexState, opcode: u16) -> (String, bool) {
    match vendor::command_name(st, opcode) {
        Some(n) => (format!("{n} (0x{:02x}|0x{:04x})", ogf(opcode), ocf(opcode)), false),
        None => opcode_text(opcode),
    }
}

/// Finish a decoder call: report truncation and dump whatever was not consumed.
pub(crate) fn finish(result: Result<bool, Truncated>, r: &mut Reader<'_>, out: &mut Out) {
    match result {
        Ok(true) => {
            if !r.is_empty() {
                out.styled(Style::Error, format!("Unexpected trailing data ({} bytes)", r.remaining()));
                out.hex(r.rest());
            }
        }
        Ok(false) => {
            if !r.is_empty() {
                out.hex(r.rest());
            }
        }
        Err(e) => {
            out.styled(Style::Error, format!("Truncated packet: {e}"));
            if !r.is_empty() {
                out.hex(r.rest());
            }
        }
    }
}

pub fn decode_command(ctx: &mut Context, pkt: &Packet) -> Decoded {
    let mut d = Decoded::new(pkt.opcode, '<', "HCI Command");
    d.layers.push(Layer::Hci);
    d.indent = 8;
    let mut r = Reader::new(&pkt.data);
    let mut out = Out::new();
    match (r.u16(), r.u8()) {
        (Ok(opcode), Ok(plen)) => {
            let st = ctx.index_mut(pkt.index);
            let (text, unknown) = opcode_text_for(st, opcode);
            d.summary = text;
            d.extra = format!("plen {plen}");
            d.unknown = unknown;
            if plen as usize != r.remaining() {
                out.error(format!("Parameter length mismatch: header says {plen}, {} present", r.remaining()));
            }
            let mut params = Reader::new(r.rest());
            let res = command::command_params(st, opcode, &mut params, &mut out);
            finish(res, &mut params, &mut out);
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

pub fn decode_event(ctx: &mut Context, pkt: &Packet) -> Decoded {
    let mut d = Decoded::new(pkt.opcode, '>', "HCI Event");
    d.layers.push(Layer::Hci);
    let mut r = Reader::new(&pkt.data);
    let mut out = Out::new();
    match (r.u8(), r.u8()) {
        (Ok(code), Ok(plen)) => {
            let name = event_name(code).or((code == vendor::EVT_VENDOR).then_some("Vendor"));
            d.unknown = name.is_none();
            let name = name.unwrap_or("Unknown");
            d.summary = if code == evt::LE_META { format!("LE Meta Event (0x{code:02x})") } else { format!("{name} (0x{code:02x})") };
            d.extra = format!("plen {plen}");
            if plen as usize != r.remaining() {
                out.error(format!("Parameter length mismatch: header says {plen}, {} present", r.remaining()));
            }
            let st = ctx.index_mut(pkt.index);
            let mut params = Reader::new(r.rest());
            let res = event::event_params(st, code, &mut params, &mut out);
            if code != evt::COMMAND_COMPLETE && code != evt::COMMAND_STATUS && code != evt::LE_META && code != vendor::EVT_VENDOR {
                // Plain events print their parameters directly under the headline.
                d.indent = 8;
            }
            finish(res, &mut params, &mut out);
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

pub fn decode_acl(ctx: &mut Context, pkt: &Packet, rx: bool) -> Decoded {
    acl::decode(ctx, pkt, rx)
}

pub fn decode_sco(ctx: &mut Context, pkt: &Packet, rx: bool) -> Decoded {
    sco::decode(ctx, pkt, rx)
}

pub fn decode_iso(ctx: &mut Context, pkt: &Packet, rx: bool) -> Decoded {
    iso::decode(ctx, pkt, rx)
}
