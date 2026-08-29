//! Output back-ends.

pub mod machine;
pub mod plain;

/// What plain mode writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// btmon-style text.
    Text,
    /// One line per packet.
    Digest,
    /// One JSON object per packet.
    Jsonl,
    /// A whole-capture overview.
    Summary,
}
