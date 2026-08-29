//! SCO/eSCO data packets.

use hcimon_capture::Packet;

use crate::context::Context;
use crate::reader::Reader;
use crate::tree::Out;
use crate::{Decoded, Layer};

pub fn decode(ctx: &mut Context, pkt: &Packet, rx: bool) -> Decoded {
    let mut d = Decoded::new(pkt.opcode, if rx { '>' } else { '<' }, if rx { "SCO Data RX" } else { "SCO Data TX" });
    d.layers.push(Layer::Hci);
    let mut r = Reader::new(&pkt.data);
    let mut out = Out::new();
    let (Ok(hf), Ok(dlen)) = (r.u16(), r.u8()) else {
        d.summary = "malformed".into();
        d.unknown = true;
        out.hex(&pkt.data);
        d.fields = out.finish();
        return d;
    };
    let handle = hf & 0x0fff;
    let flags = (hf >> 12) as u8;
    d.summary = format!("Handle {handle} flags 0x{flags:02x}");
    d.extra = format!("dlen {dlen}");
    if dlen as usize != r.remaining() {
        out.error(format!("Data length mismatch: header says {dlen}, {} present", r.remaining()));
    }
    match flags & 0x03 {
        0 => {}
        1 => {
            out.line("Packet status: Possibly invalid data");
        }
        2 => {
            out.line("Packet status: No data received");
        }
        _ => {
            out.line("Packet status: Data partially lost");
        }
    }
    if ctx.options.sco {
        out.hex(r.rest());
    }
    d.fields = out.finish();
    d
}
