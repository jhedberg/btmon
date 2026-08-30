//! Display filters for the packet list.

use hcimon_decode::{Layer, Lifecycle, Opcode, Query};

use crate::conversations::{connection_handles_of, controller_boundary};
use crate::session::Entry;
use crate::source::SourceId;

/// One connection being followed: a handle on a controller from a session
/// number on, until the packet that ended it (once that has been seen).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Follow {
    pub source: SourceId,
    pub index: u16,
    pub handle: u16,
    pub first: u64,
    pub last: Option<u64>,
}

impl Follow {
    pub fn matches(&self, e: &Entry) -> bool {
        e.source == self.source
            && e.packet.index == self.index
            && e.seq >= self.first
            && self.last.is_none_or(|l| e.seq <= l)
            && connection_handles_of(e).contains(&self.handle)
    }

    /// Whether `e` ends the followed connection, and where: its
    /// disconnection stays in view; a new connection on the handle, or the
    /// controller starting over or going away, do not.
    pub fn end_at(&self, e: &Entry) -> Option<u64> {
        if e.source != self.source || e.packet.index != self.index {
            return None;
        }
        if controller_boundary(e) {
            return Some(e.seq.saturating_sub(1));
        }
        e.decoded.lifecycle.iter().find_map(|l| match l {
            Lifecycle::Closed(h) if *h == self.handle => Some(e.seq),
            Lifecycle::Established(h) if *h == self.handle => Some(e.seq.saturating_sub(1)),
            _ => None,
        })
    }
}

/// Coarse packet categories that can be toggled in the filter dialog.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Category {
    Command,
    Event,
    Acl,
    Sco,
    Iso,
    Index,
    Log,
    Control,
    Vendor,
}

impl Category {
    pub const ALL: [Category; 9] = [
        Category::Command,
        Category::Event,
        Category::Acl,
        Category::Sco,
        Category::Iso,
        Category::Index,
        Category::Log,
        Category::Control,
        Category::Vendor,
    ];

    pub fn name(self) -> &'static str {
        match self {
            Category::Command => "HCI commands",
            Category::Event => "HCI events",
            Category::Acl => "ACL data",
            Category::Sco => "SCO data",
            Category::Iso => "ISO data",
            Category::Index => "Index / notes",
            Category::Log => "User logging",
            Category::Control => "Control / MGMT",
            Category::Vendor => "Vendor diagnostics",
        }
    }

    pub fn key(self) -> char {
        match self {
            Category::Command => 'c',
            Category::Event => 'e',
            Category::Acl => 'a',
            Category::Sco => 's',
            Category::Iso => 'i',
            Category::Index => 'n',
            Category::Log => 'l',
            Category::Control => 'm',
            Category::Vendor => 'v',
        }
    }

    pub fn of(opcode: Opcode) -> Category {
        match opcode {
            Opcode::Command => Category::Command,
            Opcode::Event => Category::Event,
            Opcode::AclTx | Opcode::AclRx => Category::Acl,
            Opcode::ScoTx | Opcode::ScoRx => Category::Sco,
            Opcode::IsoTx | Opcode::IsoRx => Category::Iso,
            Opcode::UserLogging => Category::Log,
            Opcode::CtrlOpen | Opcode::CtrlClose | Opcode::CtrlCommand | Opcode::CtrlEvent => Category::Control,
            Opcode::VendorDiag => Category::Vendor,
            _ => Category::Index,
        }
    }
}

/// Protocol layers that can be required.
pub const LAYERS: [Layer; 7] = [Layer::L2cap, Layer::Att, Layer::Smp, Layer::Sdp, Layer::Rfcomm, Layer::Avdtp, Layer::Avctp];

#[derive(Debug, Clone)]
pub struct Filter {
    /// Categories that are shown (all by default).
    pub categories: Vec<Category>,
    /// If non-empty, only packets containing one of these layers are shown.
    pub layers: Vec<Layer>,
    /// Only this controller index.
    pub index: Option<u16>,
    /// Only this source.
    pub source: Option<SourceId>,
    /// Case-insensitive substring that the headline or any field must contain.
    pub text: String,
    /// Maximum user-logging priority (0..7) to show.
    pub max_priority: Option<u8>,
    /// Display filter expression.
    pub expr: Option<Query>,
    /// The connection being followed (`F`).
    pub follow: Option<Follow>,
}

impl Default for Filter {
    fn default() -> Self {
        Filter {
            categories: Category::ALL.to_vec(),
            layers: Vec::new(),
            index: None,
            source: None,
            text: String::new(),
            max_priority: None,
            expr: None,
            follow: None,
        }
    }
}

impl Filter {
    pub fn is_active(&self) -> bool {
        self.categories.len() != Category::ALL.len()
            || !self.layers.is_empty()
            || self.index.is_some()
            || self.source.is_some()
            || !self.text.is_empty()
            || self.max_priority.is_some()
            || self.expr.is_some()
            || self.follow.is_some()
    }

    pub fn has_category(&self, c: Category) -> bool {
        self.categories.contains(&c)
    }

    pub fn toggle_category(&mut self, c: Category) {
        if let Some(pos) = self.categories.iter().position(|x| *x == c) {
            self.categories.remove(pos);
        } else {
            self.categories.push(c);
        }
    }

    pub fn toggle_layer(&mut self, l: Layer) {
        if let Some(pos) = self.layers.iter().position(|x| *x == l) {
            self.layers.remove(pos);
        } else {
            self.layers.push(l);
        }
    }

    pub fn matches(&self, e: &Entry) -> bool {
        if !self.has_category(Category::of(e.packet.opcode)) {
            return false;
        }
        if !self.layers.is_empty() && !self.layers.iter().any(|l| e.decoded.has_layer(*l)) {
            return false;
        }
        if let Some(idx) = self.index {
            if e.packet.index != idx && e.packet.index != hcimon_capture::INDEX_NONE {
                return false;
            }
        }
        if let Some(src) = self.source {
            if e.source != src {
                return false;
            }
        }
        if let (Some(max), Some(p)) = (self.max_priority, e.decoded.priority) {
            if p > max {
                return false;
            }
        }
        if !self.text.is_empty() && !text_matches(e, &self.text) {
            return false;
        }
        if let Some(q) = &self.expr {
            if !q.matches(&e.index) {
                return false;
            }
        }
        if let Some(f) = &self.follow {
            if !f.matches(e) {
                return false;
            }
        }
        true
    }

    /// One-line description for the status bar.
    pub fn describe(&self) -> String {
        let mut parts = Vec::new();
        if self.categories.len() != Category::ALL.len() {
            let hidden: Vec<&str> = Category::ALL.iter().filter(|c| !self.has_category(**c)).map(|c| c.name()).collect();
            parts.push(format!("hide {}", hidden.join(",")));
        }
        if !self.layers.is_empty() {
            let l: Vec<&str> = self.layers.iter().map(|l| l.name()).collect();
            parts.push(format!("layers {}", l.join("|")));
        }
        if let Some(i) = self.index {
            parts.push(format!("hci{i}"));
        }
        if let Some(s) = self.source {
            parts.push(format!("source {s}"));
        }
        if let Some(p) = self.max_priority {
            parts.push(format!("prio<={p}"));
        }
        if !self.text.is_empty() {
            parts.push(format!("\"{}\"", self.text));
        }
        if let Some(q) = &self.expr {
            parts.push(q.source().to_string());
        }
        if let Some(f) = &self.follow {
            parts.push(format!("follow handle {}", f.handle));
        }
        parts.join(" ")
    }
}

/// Case-insensitive substring match over the headline and all field lines.
pub fn text_matches(e: &Entry, needle: &str) -> bool {
    e.index.text().to_lowercase().contains(&needle.to_lowercase())
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

    fn le_connect(addr: u8) -> Vec<u8> {
        let mut v = vec![0x3e, 0x13, 0x01, 0x00, 0x40, 0x00, 0x00, 0x00];
        v.extend([addr; 6]);
        v.extend([0x18, 0, 0, 0, 0x48, 0, 0]);
        v
    }

    #[test]
    fn follow_ends_with_its_connection() {
        let acl = vec![0x40, 0x00, 0x07, 0x00, 0x03, 0x00, 0x04, 0x00, 0x02, 0x17, 0x00];
        let es = entries(&[
            (Opcode::Event, le_connect(1)),
            (Opcode::AclTx, acl.clone()),
            (Opcode::Event, vec![0x05, 0x04, 0x00, 0x40, 0x00, 0x13]),
            (Opcode::Event, le_connect(2)),
            (Opcode::AclTx, acl.clone()),
        ]);
        // Started while the first connection is open (after its first packet).
        let mut f = Follow { source: SourceId(1), index: 0, handle: 64, first: 1, last: None };
        assert_eq!(f.end_at(&es[1]), None);
        assert_eq!(f.end_at(&es[2]), Some(3), "the disconnection stays in view");
        f.last = Some(3);
        let shown: Vec<u64> = es.iter().filter(|e| f.matches(e)).map(|e| e.seq).collect();
        assert_eq!(shown, vec![1, 2, 3]);
        // Disconnection never captured: the handle's next connection ends the follow before itself.
        let es = entries(&[(Opcode::Event, le_connect(1)), (Opcode::AclTx, acl.clone()), (Opcode::Event, le_connect(2)), (Opcode::AclTx, acl)]);
        let f = Follow { source: SourceId(1), index: 0, handle: 64, first: 1, last: None };
        assert_eq!(f.end_at(&es[2]), Some(2));
        // Another source or controller is none of this follow's business.
        let mut other = es[2].clone();
        other.source = SourceId(2);
        assert_eq!(f.end_at(&other), None);
        // Controller boundaries end it before themselves: New Index, a successful HCI Reset, Delete Index.
        let mut ni = vec![0u8; 16];
        ni[8..12].copy_from_slice(b"hci0");
        let es = entries(&[(Opcode::Event, le_connect(1)), (Opcode::NewIndex, ni), (Opcode::Event, le_connect(1)), (Opcode::Event, vec![0x0e, 0x04, 0x01, 0x03, 0x0c, 0x00]), (Opcode::DelIndex, vec![])]);
        assert_eq!(f.end_at(&es[1]), Some(1));
        assert_eq!(f.end_at(&es[3]), Some(3));
        assert_eq!(f.end_at(&es[4]), Some(4));
        assert_eq!(f.end_at(&entries(&[(Opcode::Event, vec![0x0e, 0x04, 0x01, 0x03, 0x0c, 0x0c])])[0]), None);
        // Following a CIS includes the packet that established it.
        let mut cis = vec![0x3e, 0x1d, 0x19, 0x00, 0x03, 0x00];
        cis.extend([0u8; 26]);
        let es = entries(&[(Opcode::Event, cis)]);
        let f = Follow { source: SourceId(1), index: 0, handle: 3, first: 1, last: None };
        assert!(f.matches(&es[0]));
    }
}
