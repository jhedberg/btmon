//! Isochronous (CIS/BIS) data packets.

use hcimon_capture::Packet;

use crate::context::Context;
use crate::field;
use crate::reader::Reader;
use crate::tree::Out;
use crate::{Decoded, Layer};

pub fn decode(ctx: &mut Context, pkt: &Packet, rx: bool) -> Decoded {
    let mut d = Decoded::new(pkt.opcode, if rx { '>' } else { '<' }, if rx { "ISO Data RX" } else { "ISO Data TX" });
    d.layers.push(Layer::Hci);
    let mut r = Reader::new(&pkt.data);
    let mut out = Out::new();
    let (Ok(hf), Ok(lf)) = (r.u16(), r.u16()) else {
        d.summary = "malformed".into();
        d.unknown = true;
        out.hex(&pkt.data);
        d.fields = out.finish();
        return d;
    };
    let handle = hf & 0x0fff;
    let flags = (hf >> 12) as u8;
    let pb = flags & 0x03;
    let ts_present = flags & 0x04 != 0;
    let dlen = lf & 0x3fff;
    d.summary = format!("Handle {handle} flags 0x{flags:02x}");
    d.extra = format!("dlen {dlen}");
    if dlen as usize != r.remaining() {
        out.error(format!("Data length mismatch: header says {dlen}, {} present", r.remaining()));
    }
    let pb_text = match pb {
        0b00 => "First fragment",
        0b01 => "Continuation fragment",
        0b10 => "Complete",
        _ => "Last fragment",
    };
    field!(out, "Packet boundary: {} (0x{:02x})", pb_text, pb);
    if pb == 0b00 || pb == 0b10 {
        if ts_present {
            if let Ok(ts) = r.u32() {
                field!(out, "Timestamp: {} us", ts);
            }
        }
        if let (Ok(seq), Ok(sl)) = (r.u16(), r.u16()) {
            field!(out, "Sequence number: {}", seq);
            let sdu_len = sl & 0x0fff;
            let status = (sl >> 14) & 0x03;
            let status_text = match status {
                0 => "Valid",
                1 => "Possibly invalid",
                2 => "Lost data",
                _ => "Reserved",
            };
            field!(out, "SDU length: {}", sdu_len);
            field!(out, "Packet status: {} (0x{:02x})", status_text, status);
        }
    }
    if ctx.options.iso && !r.is_empty() {
        out.hex(r.rest());
    }
    d.fields = out.finish();
    d
}
