//! Connections seen in the session, derived from the decoded fields.

use std::collections::HashMap;

use hcimon_capture::Opcode;

use crate::session::Entry;
use crate::source::SourceId;

/// One connection: a handle on one controller from the packet that
/// established it (or the first that mentioned it) to its Disconnection
/// Complete.  A handle reused for a later connection gets a new row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Conversation {
    pub source: SourceId,
    pub index: u16,
    pub handle: u16,
    /// Peer address as printed by the decoder (with its type), if seen.
    pub peer: String,
    /// Packets sent by the host / received from the controller.
    pub tx: u64,
    pub rx: u64,
    /// ACL/SCO/ISO payload bytes in both directions.
    pub bytes: u64,
    pub first: u64,
    pub last: u64,
    /// Decoder frame numbers of the first and last packet (for filters).
    pub first_frame: u64,
    pub last_frame: u64,
    /// `false` once a Disconnection Complete for the handle was seen.
    pub open: bool,
}

/// Whether the packet reports a connection successfully established.
fn establishes_connection(e: &Entry) -> bool {
    let s = &e.decoded.summary;
    (s.starts_with("Connection Complete") || s.starts_with("LE Connection Complete") || s.starts_with("LE Enhanced Connection Complete") || s.starts_with("Synchronous Connection Complete"))
        && e.index.get("status").next().is_some_and(|f| f.raw() == Some(0))
}

/// Connection handles referenced by a packet: `Handle:` fields (the decoders
/// print connection handles in decimal and attribute handles as `0x....`, which
/// tells them apart) or the ACL/SCO/ISO header.
pub fn handles_of(e: &Entry) -> Vec<u16> {
    let mut v: Vec<u16> = e
        .index
        .get("handle")
        .filter(|f| !f.text().starts_with("0x"))
        .filter_map(|f| f.num().map(|n| n as u64))
        .filter(|&h| h <= 0x0eff)
        .map(|h| h as u16)
        .collect();
    v.sort_unstable();
    v.dedup();
    v
}

/// Build the conversation table from the packet store.
pub fn collect(entries: &[Entry]) -> Vec<Conversation> {
    let mut rows: Vec<Conversation> = Vec::new();
    // The row currently collecting a (source, controller, handle).
    let mut current: HashMap<(SourceId, u16, u16), usize> = HashMap::new();
    for e in entries {
        let handles = handles_of(e);
        if handles.is_empty() {
            continue;
        }
        let single = handles.len() == 1;
        let is_data = matches!(e.packet.opcode, Opcode::AclTx | Opcode::AclRx | Opcode::ScoTx | Opcode::ScoRx | Opcode::IsoTx | Opcode::IsoRx);
        let disconnected = e.decoded.summary.starts_with("Disconnection Complete");
        let established = establishes_connection(e);
        for h in handles {
            let key = (e.source, e.packet.index, h);
            let i = match current.get(&key).copied() {
                Some(i) if !established => i,
                prior => {
                    // A new connection on this handle: the previous one is over.
                    if let Some(i) = prior {
                        rows[i].open = false;
                    }
                    rows.push(Conversation {
                        source: e.source,
                        index: e.packet.index,
                        handle: h,
                        peer: String::new(),
                        tx: 0,
                        rx: 0,
                        bytes: 0,
                        first: e.seq,
                        last: e.seq,
                        first_frame: e.decoded.frame,
                        last_frame: e.decoded.frame,
                        open: true,
                    });
                    current.insert(key, rows.len() - 1);
                    rows.len() - 1
                }
            };
            let c = &mut rows[i];
            c.last = e.seq;
            c.last_frame = e.decoded.frame;
            match e.decoded.prefix {
                '<' => c.tx += 1,
                '>' => c.rx += 1,
                _ => {}
            }
            if is_data {
                c.bytes += e.packet.data.len().saturating_sub(4) as u64;
            }
            if disconnected {
                c.open = false;
            }
            if single && c.peer.is_empty() {
                if let Some(a) = e.index.get("peer_address").chain(e.index.get("address")).next() {
                    c.peer = a.text().to_string();
                }
            }
        }
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;
    use hcimon_capture::{Packet, Timestamp};
    use hcimon_decode::{decode, Context, FieldIndex, PacketMeta};

    fn entries(packets: &[(Opcode, Vec<u8>)]) -> Vec<Entry> {
        let mut ctx = Context::new();
        packets
            .iter()
            .enumerate()
            .map(|(i, (op, data))| {
                let packet = Packet { ts: Some(Timestamp::Wall(i as i64 * 1000)), index: 0, opcode: *op, drops: 0, data: data.clone() };
                let decoded = decode(&mut ctx, &packet);
                let index = FieldIndex::build(&decoded, &packet, PacketMeta { seq: i as u64 + 1, source: "t" });
                Entry { seq: i as u64 + 1, source: SourceId(1), packet, decoded, index, refs: Vec::new(), findings: Vec::new() }
            })
            .collect()
    }

    #[test]
    fn a_reused_handle_is_a_new_conversation() {
        let mut connect_a = vec![0x03, 0x0b, 0x00, 0x40, 0x00];
        connect_a.extend([1, 2, 3, 4, 5, 6, 0x01, 0x00]);
        let mut connect_b = vec![0x03, 0x0b, 0x00, 0x40, 0x00];
        connect_b.extend([9, 9, 9, 9, 9, 9, 0x01, 0x00]);
        let acl = vec![0x40, 0x00, 0x07, 0x00, 0x03, 0x00, 0x04, 0x00, 0x02, 0x17, 0x00];
        let rows = collect(&entries(&[
            (Opcode::Event, connect_a),
            (Opcode::AclTx, acl.clone()),
            (Opcode::Event, vec![0x05, 0x04, 0x00, 0x40, 0x00, 0x13]),
            // A late completion for the old connection must not reopen it.
            (Opcode::Event, vec![0x13, 0x05, 0x01, 0x40, 0x00, 0x01, 0x00]),
            (Opcode::Event, connect_b),
            (Opcode::AclTx, acl),
        ]));
        assert_eq!(rows.len(), 2, "{rows:?}");
        assert!(rows[0].peer.starts_with("06:05:04:03:02:01") && !rows[0].open, "{:?}", rows[0]);
        assert_eq!((rows[0].first, rows[0].last), (1, 4));
        assert!(rows[1].peer.starts_with("09:09:09:09:09:09") && rows[1].open, "{:?}", rows[1]);
        assert_eq!((rows[1].first, rows[1].last, rows[1].tx), (5, 6, 1));
        // A failed connection attempt does not start a row of its own.
        let mut failed = vec![0x03, 0x0b, 0x04, 0x40, 0x00];
        failed.extend([1, 2, 3, 4, 5, 6, 0x01, 0x00]);
        assert_eq!(collect(&entries(&[(Opcode::Event, failed)])).len(), 1);
    }
}
