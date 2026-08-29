//! Display filters for the packet list.

use hcimon_decode::{Layer, Opcode, Query};

use crate::session::Entry;
use crate::source::SourceId;

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
        parts.join(" ")
    }
}

/// Case-insensitive substring match over the headline and all field lines.
pub fn text_matches(e: &Entry, needle: &str) -> bool {
    e.index.text().to_lowercase().contains(&needle.to_lowercase())
}
