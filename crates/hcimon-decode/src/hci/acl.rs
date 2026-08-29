//! ACL data packets: the 4-byte HCI header, fragment reassembly and hand-off to L2CAP.

use hcimon_capture::Packet;

use crate::context::{Context, LinkType, Reassembly};
use crate::l2cap;
use crate::reader::Reader;
use crate::tree::{Out, Style};
use crate::{Decoded, Layer};

/// Packet boundary flag names.
pub fn pb_str(pb: u8) -> &'static str {
    match pb {
        0b00 => "start of non-automatically-flushable",
        0b01 => "continuing fragment",
        0b10 => "start of automatically-flushable",
        _ => "complete automatically-flushable",
    }
}

pub fn decode(ctx: &mut Context, pkt: &Packet, rx: bool) -> Decoded {
    let mut d = Decoded::new(pkt.opcode, if rx { '>' } else { '<' }, if rx { "ACL Data RX" } else { "ACL Data TX" });
    d.layers.push(Layer::Hci);
    let mut r = Reader::new(&pkt.data);
    let mut out = Out::new();
    let (Ok(hf), Ok(dlen)) = (r.u16(), r.u16()) else {
        d.summary = "malformed".into();
        d.unknown = true;
        out.hex(&pkt.data);
        d.fields = out.finish();
        return d;
    };
    let handle = hf & 0x0fff;
    let flags = (hf >> 12) as u8;
    let pb = flags & 0x03;
    let bc = (flags >> 2) & 0x03;
    d.summary = format!("Handle {handle} flags 0x{flags:02x}");
    d.extra = format!("dlen {dlen}");
    if dlen as usize != r.remaining() {
        out.error(format!("Data length mismatch: header says {dlen}, {} present", r.remaining()));
    }
    let data = r.rest();
    let st = ctx.index_mut(pkt.index);
    let frame = st.frames;

    // Broadcast (BC != 0) packets never carry L2CAP for a specific link.
    if bc != 0 {
        out.line(format!("Broadcast flag: 0x{bc:02x}"));
        out.hex(data);
        d.fields = out.finish();
        return d;
    }

    if !rx {
        st.push_acl_tx(handle);
    }
    let conn = st.conn_or_insert(handle, LinkType::Unknown);
    if conn.since_frame == 0 {
        conn.since_frame = frame;
    }
    let dir = rx as usize;

    let pdu: Option<Vec<u8>> = match pb {
        0b01 => {
            // Continuing fragment.
            match conn.l2cap.reassembly[dir].take() {
                Some(mut re) => {
                    re.data.extend_from_slice(data);
                    if re.data.len() >= re.expected + 4 {
                        Some(re.data)
                    } else {
                        conn.l2cap.reassembly[dir] = Some(re);
                        None
                    }
                }
                None => {
                    out.styled(Style::Error, "Continuing fragment without a start fragment");
                    out.hex(data);
                    d.fields = out.finish();
                    return d;
                }
            }
        }
        _ => {
            if conn.l2cap.reassembly[dir].take().is_some() {
                out.styled(Style::Error, "Previous L2CAP PDU was incomplete");
            }
            if data.len() >= 4 {
                let expected = u16::from_le_bytes([data[0], data[1]]) as usize;
                if data.len() >= expected + 4 {
                    Some(data.to_vec())
                } else {
                    conn.l2cap.reassembly[dir] = Some(Reassembly { expected, data: data.to_vec() });
                    None
                }
            } else {
                Some(data.to_vec())
            }
        }
    };

    match pdu {
        Some(pdu) => {
            let mut layers = Vec::new();
            l2cap::decode_pdu(st, handle, rx, &pdu, &mut out, &mut layers);
            d.layers.extend(layers);
        }
        None => {
            out.line(format!("Fragment ({})", pb_str(pb)));
            out.nest(|o| {
                o.hex(data);
            });
        }
    }
    d.fields = out.finish();
    d
}
