//! Top-level dispatch on the monitor opcode.

use hcimon_capture::{IndexInfo, NewIndex, Opcode, Packet, UserLogging, INDEX_NONE};

use crate::assigned::company_name;
use crate::context::Context;
use crate::hci;
use crate::mgmt;
use crate::reader::BdAddr;
use crate::tree::Out;
use crate::{Decoded, Layer};

impl Decoded {
    pub(crate) fn new(opcode: Opcode, prefix: char, label: impl Into<String>) -> Self {
        Decoded {
            opcode,
            prefix,
            label: label.into(),
            summary: String::new(),
            extra: String::new(),
            unknown: false,
            priority: None,
            layers: Vec::new(),
            fields: Vec::new(),
            indent: 6,
            frame: 0,
            links: Vec::new(),
        }
    }
}

/// Decode one monitor packet, updating `ctx`.
pub fn decode(ctx: &mut Context, pkt: &Packet) -> Decoded {
    ctx.packets += 1;
    let frame = if pkt.index != INDEX_NONE {
        let st = ctx.index_mut(pkt.index);
        st.frames += 1;
        st.last_ts = pkt.ts;
        st.cur_ts = pkt.ts;
        st.links.clear();
        st.frames
    } else {
        0
    };

    let mut d = match pkt.opcode {
        Opcode::NewIndex => new_index(ctx, pkt),
        Opcode::DelIndex => index_record(ctx, pkt, "Delete Index"),
        Opcode::OpenIndex => index_record(ctx, pkt, "Open Index"),
        Opcode::CloseIndex => index_record(ctx, pkt, "Close Index"),
        Opcode::IndexInfo => index_info(ctx, pkt),
        Opcode::Command => hci::decode_command(ctx, pkt),
        Opcode::Event => hci::decode_event(ctx, pkt),
        Opcode::AclTx => hci::decode_acl(ctx, pkt, false),
        Opcode::AclRx => hci::decode_acl(ctx, pkt, true),
        Opcode::ScoTx => hci::decode_sco(ctx, pkt, false),
        Opcode::ScoRx => hci::decode_sco(ctx, pkt, true),
        Opcode::IsoTx => hci::decode_iso(ctx, pkt, false),
        Opcode::IsoRx => hci::decode_iso(ctx, pkt, true),
        Opcode::VendorDiag => vendor_diag(pkt),
        Opcode::SystemNote => system_note(pkt),
        Opcode::UserLogging => user_logging(pkt),
        Opcode::CtrlOpen => mgmt::decode_ctrl_open(ctx, pkt),
        Opcode::CtrlClose => mgmt::decode_ctrl_close(ctx, pkt),
        Opcode::CtrlCommand => mgmt::decode_ctrl_command(ctx, pkt),
        Opcode::CtrlEvent => mgmt::decode_ctrl_event(ctx, pkt),
        Opcode::Unknown(op) => {
            let mut d = Decoded::new(pkt.opcode, '=', "Unknown packet");
            d.summary = format!("code 0x{op:04x}");
            d.extra = format!("len {}", pkt.data.len());
            d.unknown = true;
            let mut out = Out::new();
            out.hex(&pkt.data);
            d.fields = out.finish();
            d
        }
    };
    d.frame = frame;
    if pkt.index != INDEX_NONE {
        let st = ctx.index_mut(pkt.index);
        d.links = std::mem::take(&mut st.links);
        names::learn_and_annotate(st, &mut d);
    }
    if pkt.opcode == Opcode::DelIndex {
        ctx.remove_index(pkt.index);
    }
    d
}

/// Device name resolution: learn names from the decoded tree and show them next to addresses.
mod names {
    use super::*;
    use crate::context::IndexState;
    use crate::tree::Node;

    /// Parse `XX:XX:XX:XX:XX:XX` from the first 17 bytes; works on bytes so
    /// that non-ASCII text around the address cannot cause a slicing panic.
    fn parse_addr(b: &[u8]) -> Option<BdAddr> {
        if b.len() < 17 {
            return None;
        }
        let hex = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
        let mut out = [0u8; 6];
        for i in 0..6 {
            let hi = hex(b[i * 3])?;
            let lo = hex(b[i * 3 + 1])?;
            out[5 - i] = (hi << 4) | lo;
            if i < 5 && b[i * 3 + 2] != b':' {
                return None;
            }
        }
        Some(BdAddr(out))
    }

    /// Address found in a `... : XX:XX:XX:XX:XX:XX ...` line, with the byte offset
    /// just past it (always a char boundary, since the address is ASCII).
    fn find_addr(text: &str) -> Option<(BdAddr, usize)> {
        let b = text.as_bytes();
        let mut i = 0;
        while i + 17 <= b.len() {
            if b[i].is_ascii_hexdigit() && (i == 0 || !b[i - 1].is_ascii_hexdigit()) {
                if let Some(a) = parse_addr(&b[i..i + 17]) {
                    if i + 17 == b.len() || !b[i + 17].is_ascii_hexdigit() {
                        return Some((a, i + 17));
                    }
                }
            }
            i += 1;
        }
        None
    }

    fn name_of(text: &str) -> Option<&str> {
        for prefix in ["Name (complete): ", "Name (short): ", "Name: ", "Remote name: ", "Broadcast Name: "] {
            if let Some(n) = text.strip_prefix(prefix) {
                let n = n.trim();
                if !n.is_empty() {
                    return Some(n);
                }
            }
        }
        None
    }

    pub fn learn_and_annotate(st: &mut IndexState, d: &mut Decoded) {
        // Learn: a name line refers to the most recent address seen above it.
        let mut last_addr: Option<BdAddr> = None;
        let mut learned: Vec<(BdAddr, String)> = Vec::new();
        for n in &d.fields {
            n.walk(0, &mut |_, node| {
                if let Some((a, _)) = find_addr(&node.text) {
                    if !a.is_zero() {
                        last_addr = Some(a);
                    }
                }
                if let (Some(name), Some(a)) = (name_of(&node.text), last_addr) {
                    learned.push((a, name.to_string()));
                }
            });
        }
        for (a, name) in learned {
            st.names.insert(a, name);
        }
        if st.names.is_empty() {
            return;
        }
        // Annotate: append the known name after every address.
        fn annotate(node: &mut Node, names: &std::collections::HashMap<BdAddr, String>) {
            if let Some((a, end)) = find_addr(&node.text) {
                if let Some(name) = names.get(&a) {
                    let quoted = format!(" \"{name}\"");
                    if !node.text.contains(&quoted) {
                        // Insert after the address and any `(qualifier)` that follows it;
                        // vendor names may themselves contain parentheses.
                        let rest = &node.text[end..];
                        let mut insert_at = end;
                        if rest.starts_with(" (") {
                            let mut depth = 0usize;
                            for (i, c) in rest.char_indices() {
                                match c {
                                    '(' => depth += 1,
                                    ')' => {
                                        depth -= 1;
                                        if depth == 0 {
                                            insert_at = end + i + 1;
                                            break;
                                        }
                                    }
                                    _ => {}
                                }
                            }
                        }
                        node.text.insert_str(insert_at, &quoted);
                    }
                }
            }
            for c in &mut node.children {
                annotate(c, names);
            }
        }
        for n in &mut d.fields {
            annotate(n, &st.names);
        }
    }
}

fn new_index(ctx: &mut Context, pkt: &Packet) -> Decoded {
    let mut d = Decoded::new(pkt.opcode, '=', "New Index");
    match NewIndex::parse(&pkt.data) {
        Some(ni) => {
            let addr = BdAddr(ni.bdaddr);
            d.summary = format!("{addr} ({},{},{})", ni.controller_type, ni.bus, ni.name);
            let st = ctx.index_mut(pkt.index);
            st.name = ni.name;
            st.addr = addr;
        }
        None => {
            d.summary = "malformed".into();
            d.unknown = true;
            let mut out = Out::new();
            out.hex(&pkt.data);
            d.fields = out.finish();
        }
    }
    d
}

fn index_record(ctx: &mut Context, pkt: &Packet, label: &str) -> Decoded {
    let mut d = Decoded::new(pkt.opcode, '=', label);
    if let Some(st) = ctx.index(pkt.index) {
        d.summary = st.addr.to_string();
    }
    if !pkt.data.is_empty() {
        let mut out = Out::new();
        out.hex(&pkt.data);
        d.fields = out.finish();
    }
    d
}

fn index_info(ctx: &mut Context, pkt: &Packet) -> Decoded {
    let mut d = Decoded::new(pkt.opcode, '=', "Index Info");
    match IndexInfo::parse(&pkt.data) {
        Some(ii) => {
            let addr = BdAddr(ii.bdaddr);
            let manufacturer = company_name(ii.manufacturer).unwrap_or("Unknown");
            d.summary = format!("{addr} ({manufacturer})");
            let st = ctx.index_mut(pkt.index);
            st.addr = addr;
            st.manufacturer = Some(ii.manufacturer);
        }
        None => {
            d.summary = "malformed".into();
            d.unknown = true;
        }
    }
    d
}

fn vendor_diag(pkt: &Packet) -> Decoded {
    let mut d = Decoded::new(pkt.opcode, '*', "Vendor Diagnostic");
    d.extra = format!("len {}", pkt.data.len());
    let mut out = Out::new();
    out.hex(&pkt.data);
    d.fields = out.finish();
    d
}

fn system_note(pkt: &Packet) -> Decoded {
    let mut d = Decoded::new(pkt.opcode, '=', "Note");
    let end = pkt.data.iter().position(|&b| b == 0).unwrap_or(pkt.data.len());
    d.summary = String::from_utf8_lossy(&pkt.data[..end]).into_owned();
    d
}

fn user_logging(pkt: &Packet) -> Decoded {
    let mut d = Decoded::new(pkt.opcode, '=', "User Logging");
    d.layers.push(Layer::UserLogging);
    match UserLogging::parse(&pkt.data) {
        Some(ul) => {
            d.label = ul.ident;
            d.summary = ul.message;
            d.priority = Some(ul.priority);
        }
        None => {
            d.summary = "malformed".into();
            d.unknown = true;
            let mut out = Out::new();
            out.hex(&pkt.data);
            d.fields = out.finish();
        }
    }
    d
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::LinkKind;
    use hcimon_capture::Timestamp;

    fn pkt(opcode: Opcode, ts_us: i64, data: &[u8]) -> Packet {
        Packet { ts: Some(Timestamp::Wall(ts_us)), index: 0, opcode, drops: 0, data: data.to_vec() }
    }

    #[test]
    fn command_complete_links_to_command() {
        let mut ctx = Context::new();
        let cmd = decode(&mut ctx, &pkt(Opcode::Command, 1_000, &[0x03, 0x0c, 0x00]));
        assert!(cmd.links.is_empty());
        // An unrelated command in between.
        decode(&mut ctx, &pkt(Opcode::Command, 1_500, &[0x01, 0x10, 0x00]));
        let evt = decode(&mut ctx, &pkt(Opcode::Event, 3_500, &[0x0e, 0x04, 0x01, 0x03, 0x0c, 0x00]));
        assert_eq!(evt.links.len(), 1);
        assert_eq!(evt.links[0].kind, LinkKind::ResponseTo);
        assert_eq!(evt.links[0].frame, cmd.frame);
        assert_eq!(evt.links[0].elapsed_us, Some(2_500));
        // The second command is still pending; a Command Status answers it.
        let st = decode(&mut ctx, &pkt(Opcode::Event, 4_000, &[0x0f, 0x04, 0x00, 0x01, 0x01, 0x10]));
        assert_eq!(st.links[0].frame, 2);
    }

    #[test]
    fn number_of_completed_packets_links_acl_tx() {
        let mut ctx = Context::new();
        // LE Read Buffer Size reply: 3 buffers of 27 bytes.
        decode(&mut ctx, &pkt(Opcode::Event, 0, &[0x0e, 0x07, 0x01, 0x02, 0x20, 0x00, 0x1b, 0x00, 0x03]));
        let tx = decode(&mut ctx, &pkt(Opcode::AclTx, 1_000, &[0x00, 0x00, 0x07, 0x00, 0x03, 0x00, 0x04, 0x00, 0x02, 0x17, 0x00]));
        let ncp = decode(&mut ctx, &pkt(Opcode::Event, 99_000, &[0x13, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00]));
        assert_eq!(ncp.links, vec![crate::Link { kind: LinkKind::Completes, frame: tx.frame, elapsed_us: Some(98_000) }]);
        let lines = ncp.lines().join("\n");
        assert!(lines.contains("Latency: 98 msec (98-98 msec ~98 msec)"), "{lines}");
        assert!(lines.contains("Buffers: 0/3"), "{lines}");
    }

    #[test]
    fn att_response_links_to_request() {
        let mut ctx = Context::new();
        // Exchange MTU Request (TX) on handle 0, then the Response (RX).
        let req = decode(&mut ctx, &pkt(Opcode::AclTx, 10, &[0x00, 0x00, 0x07, 0x00, 0x03, 0x00, 0x04, 0x00, 0x02, 0x17, 0x00]));
        let rsp = decode(&mut ctx, &pkt(Opcode::AclRx, 2_010, &[0x00, 0x20, 0x07, 0x00, 0x03, 0x00, 0x04, 0x00, 0x03, 0x40, 0x00]));
        assert_eq!(rsp.links, vec![crate::Link { kind: LinkKind::ResponseTo, frame: req.frame, elapsed_us: Some(2_000) }]);
    }

    #[test]
    fn names_are_learned_from_advertising_reports() {
        let mut ctx = Context::new();
        // LE Advertising Report: 1 report, ADV_IND, public 00:1A:7D:DA:71:13, AD = Complete Local Name "Zephyr".
        let mut data = vec![0x3e, 0x00, 0x02, 0x01, 0x00, 0x00, 0x13, 0x71, 0xda, 0x7d, 0x1a, 0x00];
        let ad = [0x07u8, 0x09, b'Z', b'e', b'p', b'h', b'y', b'r'];
        data.push(ad.len() as u8);
        data.extend_from_slice(&ad);
        data.push(0xd3);
        data[1] = (data.len() - 2) as u8;
        let rep = decode(&mut ctx, &pkt(Opcode::Event, 0, &data));
        let lines = rep.lines().join("\n");
        assert!(lines.contains("Address: 00:1A:7D:DA:71:13 (cyber-blue(HK)Ltd) \"Zephyr\""), "{lines}");
        // A later LE Connection Complete to the same address is annotated with the name.
        let cc = decode(&mut ctx, &pkt(Opcode::Event, 1, &[0x3e, 0x13, 0x01, 0x00, 0x40, 0x00, 0x00, 0x00, 0x13, 0x71, 0xda, 0x7d, 0x1a, 0x00, 0x18, 0x00, 0x00, 0x00, 0x2a, 0x00, 0x00]));
        let lines = cc.lines().join("\n");
        assert!(lines.contains("Peer address: 00:1A:7D:DA:71:13 (cyber-blue(HK)Ltd) \"Zephyr\""), "{lines}");
    }

    #[test]
    fn l2cap_signaling_links_by_identifier() {
        let mut ctx = Context::new();
        // LE Connection Parameter Update Request ident 7 (RX), Response ident 7 (TX).
        let req = decode(&mut ctx, &pkt(Opcode::AclRx, 0, &[0x00, 0x20, 0x0c, 0x00, 0x08, 0x00, 0x05, 0x00, 0x12, 0x07, 0x08, 0x00, 0x18, 0x00, 0x28, 0x00, 0x00, 0x00, 0x2a, 0x00]));
        let rsp = decode(&mut ctx, &pkt(Opcode::AclTx, 500, &[0x00, 0x00, 0x06, 0x00, 0x02, 0x00, 0x05, 0x00, 0x13, 0x07, 0x02, 0x00, 0x00, 0x00]));
        assert_eq!(rsp.links.len(), 1);
        assert_eq!(rsp.links[0].frame, req.frame);
        assert_eq!(rsp.links[0].elapsed_us, Some(500));
    }
}

#[cfg(test)]
mod fuzz {
    //! Mutation fuzzing of the whole decode pipeline over the sample capture:
    //! every packet truncated at every length and with every byte flipped,
    //! decoded through a shared context (so state-dependent paths run too),
    //! then indexed and assessed.  Nothing may panic.
    use super::*;
    use crate::expert;
    use crate::query::{FieldIndex, PacketMeta};
    use hcimon_capture::tty::Framer;

    fn sample() -> Vec<Packet> {
        let mut f = Framer::new();
        f.push(include_bytes!("../../../testdata/xg24_peripheral_hr.tty"));
        let mut v = Vec::new();
        while let Some(fr) = f.next_frame() {
            v.push(fr.packet);
        }
        v
    }

    fn run(ctx: &mut Context, pkt: &Packet) {
        let d = decode(ctx, pkt);
        let ix = FieldIndex::build(&d, pkt, PacketMeta { seq: 1, source: "fuzz" });
        let _ = expert::assess(&d, pkt, &ix);
        let _ = d.lines();
    }

    #[test]
    fn mutated_packets_never_panic() {
        let packets = sample();
        assert!(packets.len() > 100);
        let mut ctx = Context::new();
        let mut decodes = 0usize;
        for p in &packets {
            // Truncations.
            for len in 0..p.data.len() {
                let mut m = p.clone();
                m.data.truncate(len);
                run(&mut ctx, &m);
                decodes += 1;
            }
            // Byte flips: zero, all-ones, and a bit flip at every position.
            for i in 0..p.data.len() {
                for v in [0x00u8, 0xff, p.data[i] ^ 0x01, p.data[i] ^ 0x80] {
                    let mut m = p.clone();
                    m.data[i] = v;
                    run(&mut ctx, &m);
                    decodes += 1;
                }
            }
            // Extra trailing bytes.
            let mut m = p.clone();
            m.data.extend_from_slice(&[0xaa, 0x55, 0x00, 0xff]);
            run(&mut ctx, &m);
            run(&mut ctx, p);
            decodes += 2;
        }
        assert!(decodes > 10_000, "{decodes}");
    }

    #[test]
    fn random_payloads_never_panic() {
        // A simple LCG so the test is deterministic and dependency-free.
        let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
        let mut next = move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let mut ctx = Context::new();
        for i in 0..20_000u32 {
            let opcode = Opcode::from_u16((next() % 22) as u16);
            let len = (next() % 64) as usize;
            let data: Vec<u8> = (0..len).map(|_| next() as u8).collect();
            let mut pkt = Packet::new(opcode, (i % 3) as u16, data);
            pkt.ts = Some(hcimon_capture::Timestamp::Wall(i as i64 * 1000));
            run(&mut ctx, &pkt);
        }
    }
}
