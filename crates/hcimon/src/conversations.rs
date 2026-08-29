//! Connections seen in the session, derived from the decoded fields.

use std::collections::HashMap;

use hcimon_capture::Opcode;

use crate::session::Entry;
use crate::source::SourceId;

/// One connection handle on one controller.
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
    /// `false` once a Disconnection Complete for the handle was seen.
    pub open: bool,
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
    let mut map: HashMap<(SourceId, u16, u16), Conversation> = HashMap::new();
    for e in entries {
        let handles = handles_of(e);
        if handles.is_empty() {
            continue;
        }
        let single = handles.len() == 1;
        let is_data = matches!(e.packet.opcode, Opcode::AclTx | Opcode::AclRx | Opcode::ScoTx | Opcode::ScoRx | Opcode::IsoTx | Opcode::IsoRx);
        let disconnected = e.decoded.summary.starts_with("Disconnection Complete");
        for h in handles {
            let c = map.entry((e.source, e.packet.index, h)).or_insert_with(|| Conversation {
                source: e.source,
                index: e.packet.index,
                handle: h,
                peer: String::new(),
                tx: 0,
                rx: 0,
                bytes: 0,
                first: e.seq,
                last: e.seq,
                open: true,
            });
            c.last = e.seq;
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
            } else if !is_data {
                c.open = true;
            }
            if single && c.peer.is_empty() {
                if let Some(a) = e.index.get("peer_address").chain(e.index.get("address")).next() {
                    c.peer = a.text().to_string();
                }
            }
        }
    }
    let mut v: Vec<Conversation> = map.into_values().collect();
    v.sort_by_key(|c| c.first);
    v
}
