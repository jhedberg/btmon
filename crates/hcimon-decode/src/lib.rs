//! Decoders for the Bluetooth host/controller traffic carried in the BlueZ
//! monitor protocol.
//!
//! The entry point is [`decode`], which turns a [`hcimon_capture::Packet`] into
//! a [`Decoded`] record: a one-line summary in the style of BlueZ's `btmon`
//! plus a tree of [`Node`]s describing every field the decoders understood.
//! Decoding is stateful — a [`Context`] tracks controllers, connections,
//! L2CAP channels and outstanding ATT requests so that later packets can be
//! interpreted in light of earlier ones.
//!
//! The crate does no I/O and never panics on malformed input; unknown or
//! truncated data is reported through [`Style::Unknown`] / [`Style::Error`]
//! nodes and hex dumps.

pub mod ad;
pub mod assigned;
pub mod att;
pub mod context;
pub mod expert;
pub mod hci;
pub mod l2cap;
pub mod mgmt;
mod monitor;
pub mod query;
pub mod reader;
pub mod smp;
pub mod tree;
pub mod uuid;

pub use hcimon_capture::{Opcode, Packet, Timestamp};
pub use context::{Connection, Context, IndexState, LinkType, Options};
pub use expert::{Finding, Severity};
pub use monitor::decode;
pub use query::{FieldIndex, PacketMeta, Query};
pub use reader::{BdAddr, Reader, Result, Truncated};
pub use tree::{render_lines, Node, Out, Style};
pub use uuid::Uuid;

/// Protocol layers found in a packet; used for filtering in user interfaces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Layer {
    Hci,
    L2cap,
    Att,
    Smp,
    Sdp,
    Rfcomm,
    Avdtp,
    Avctp,
    Mgmt,
    UserLogging,
}

impl Layer {
    pub fn name(self) -> &'static str {
        match self {
            Layer::Hci => "HCI",
            Layer::L2cap => "L2CAP",
            Layer::Att => "ATT",
            Layer::Smp => "SMP",
            Layer::Sdp => "SDP",
            Layer::Rfcomm => "RFCOMM",
            Layer::Avdtp => "AVDTP",
            Layer::Avctp => "AVCTP",
            Layer::Mgmt => "MGMT",
            Layer::UserLogging => "Log",
        }
    }
}

/// How one packet relates to another (request/response pairing).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkKind {
    /// This packet answers the referenced frame.
    ResponseTo,
    /// This packet was answered by the referenced frame (filled in by the consumer).
    AnsweredBy,
}

/// A reference from one packet to another, in per-controller frame numbers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Link {
    pub kind: LinkKind,
    pub frame: u64,
    /// Time between the two packets in microseconds, when both are timestamped.
    pub elapsed_us: Option<i64>,
}

/// A decoded monitor packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decoded {
    pub opcode: Opcode,
    /// Direction marker used by btmon: `<` host to controller, `>` controller to host,
    /// `=` bookkeeping/notes, `@` management interface, `*` vendor diagnostics.
    pub prefix: char,
    /// Category label, e.g. `HCI Command`, `ACL Data RX`, `New Index` or the ident of a log message.
    pub label: String,
    /// The headline, e.g. `LE Set Advertising Data (0x08|0x0008)`.
    pub summary: String,
    /// Trailing text after the summary, e.g. `plen 32`.
    pub extra: String,
    /// The packet type or opcode was not recognised.
    pub unknown: bool,
    /// Syslog priority for user logging records.
    pub priority: Option<u8>,
    /// Protocol layers present in the packet.
    pub layers: Vec<Layer>,
    /// Decoded fields.
    pub fields: Vec<Node>,
    /// Base indentation for the text renderer (btmon uses 8 for command parameters, 6 otherwise).
    pub indent: usize,
    /// Per-controller frame number (1-based) or 0 for records without a controller.
    pub frame: u64,
    /// Requests this packet answers.
    pub links: Vec<Link>,
}

impl Decoded {
    /// The summary line as btmon prints it, without timestamp or index.
    pub fn headline(&self) -> String {
        let mut s = String::with_capacity(64);
        s.push(self.prefix);
        s.push(' ');
        s.push_str(&self.label);
        if !self.summary.is_empty() {
            s.push_str(": ");
            s.push_str(&self.summary);
        }
        if !self.extra.is_empty() {
            s.push(' ');
            s.push_str(&self.extra);
        }
        s
    }

    /// Render the field tree as indented text lines.
    pub fn lines(&self) -> Vec<String> {
        let mut v = Vec::new();
        render_lines(&self.fields, self.indent, |indent, n| {
            v.push(format!("{}{}", " ".repeat(indent), n.text));
        });
        v
    }

    pub fn has_layer(&self, layer: Layer) -> bool {
        self.layers.contains(&layer)
    }
}
