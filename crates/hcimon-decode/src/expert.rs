//! Expert information: things in a packet worth a second look.
//!
//! Wireshark's "expert info" flags anomalies so that they can be reviewed
//! without reading every packet.  [`assess`] derives the same kind of
//! findings from a decoded packet: decoding problems, non-success status
//! codes, rejected requests, disconnections, dropped packets, and vendor
//! fatal-error events.

use hcimon_capture::Packet;

use crate::query::FieldIndex;
use crate::tree::Style;
use crate::Decoded;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    Note,
    Warning,
    Error,
}

impl Severity {
    pub fn name(self) -> &'static str {
        match self {
            Severity::Note => "note",
            Severity::Warning => "warning",
            Severity::Error => "error",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub severity: Severity,
    pub text: String,
}

/// Findings for one packet, most severe first.
pub fn assess(d: &Decoded, pkt: &Packet, ix: &FieldIndex) -> Vec<Finding> {
    let mut out = Vec::new();
    let mut add = |severity: Severity, text: String| {
        if !out.iter().any(|f: &Finding| f.text == text) {
            out.push(Finding { severity, text });
        }
    };

    if pkt.drops > 0 {
        add(Severity::Warning, format!("{} packet(s) dropped by the capture before this one", pkt.drops));
    }
    if d.unknown {
        add(Severity::Warning, format!("Unrecognised packet: {}", d.summary));
    }
    let mut flagged = 0;
    for n in &d.fields {
        n.walk(0, &mut |_, node| {
            if flagged >= 3 {
                return;
            }
            match node.style {
                Style::Error => {
                    flagged += 1;
                    add(Severity::Error, node.text.clone());
                }
                Style::Unknown => {
                    flagged += 1;
                    add(Severity::Warning, node.text.clone());
                }
                _ => {}
            }
        });
    }

    // Non-success HCI status codes.
    for s in ix.get("status") {
        if s.raw.is_some_and(|r| r != 0) {
            add(Severity::Warning, format!("{}: Status {}", d.summary, s.text));
        }
    }
    if d.summary.starts_with("Hardware Error") {
        add(Severity::Error, "Hardware Error event".into());
    }
    if d.summary.starts_with("Disconnection Complete") {
        let reason = ix.get("reason").next().map(|r| r.text.clone()).unwrap_or_default();
        let handle = ix.get("handle").next().map(|h| h.text.clone()).unwrap_or_default();
        add(Severity::Note, format!("Disconnected: handle {handle}, reason {reason}"));
    }
    // ATT Error Response and SMP Pairing Failed print `Error:` / `Reason:` fields.
    if let Some(e) = ix.get("error").next() {
        add(Severity::Warning, format!("ATT error: {}", e.text));
    }
    if ix.text().contains("SMP: Pairing Failed") {
        let reason = ix.get("reason").next().map(|r| r.text.clone()).unwrap_or_default();
        add(Severity::Error, format!("Pairing failed: {reason}"));
    }
    // L2CAP results other than success/pending, and command rejects.
    for r in ix.get("result") {
        let name = r.name().to_ascii_lowercase();
        if !(name.contains("success") || name.contains("pending") || name.contains("accept") || name.starts_with("all connections")) {
            add(Severity::Warning, format!("L2CAP: {}", r.text));
        }
    }
    if ix.text().contains("Command Reject") {
        add(Severity::Warning, "L2CAP: Command Reject".into());
    }
    if ix.text().contains("Fatal Error") && d.summary.starts_with("Vendor") {
        add(Severity::Error, "Controller reported a fatal error".into());
    }
    // User logging: err and above.  Priority 0 is not treated as "emergency":
    // Zephyr's monitor uses it for plain printk output.
    if let Some(p) = d.priority {
        if (1..=3).contains(&p) {
            add(if p <= 2 { Severity::Error } else { Severity::Warning }, format!("{}: {}", d.label, d.summary));
        }
    }
    out.sort_by(|a, b| b.severity.cmp(&a.severity));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::Context;
    use crate::query::PacketMeta;
    use hcimon_capture::Opcode;

    fn assess_pkt(pkt: &Packet) -> Vec<Finding> {
        let mut ctx = Context::new();
        let d = crate::decode(&mut ctx, pkt);
        let ix = FieldIndex::build(&d, pkt, PacketMeta { seq: 1, source: "t" });
        assess(&d, pkt, &ix)
    }

    #[test]
    fn status_and_disconnect() {
        // Command Status with "Command Disallowed" for LE Set Scan Enable.
        let f = assess_pkt(&Packet::new(Opcode::Event, 0, vec![0x0f, 0x04, 0x0c, 0x01, 0x0c, 0x20]));
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].severity, Severity::Warning);
        assert!(f[0].text.contains("Command Disallowed"), "{}", f[0].text);

        let f = assess_pkt(&Packet::new(Opcode::Event, 0, vec![0x05, 0x04, 0x00, 0x40, 0x00, 0x13]));
        assert_eq!(f[0].severity, Severity::Note);
        assert!(f[0].text.contains("Remote User Terminated Connection"));
    }

    #[test]
    fn clean_packet_has_no_findings() {
        let f = assess_pkt(&Packet::new(Opcode::Command, 0, vec![0x0a, 0x20, 0x01, 0x01]));
        assert!(f.is_empty());
    }

    #[test]
    fn truncated_packet_is_an_error() {
        let f = assess_pkt(&Packet::new(Opcode::Event, 0, vec![0x05, 0x04, 0x00, 0x40]));
        assert!(f.iter().any(|x| x.severity == Severity::Error), "{f:?}");
        let mut p = Packet::new(Opcode::Command, 0, vec![0x0a, 0x20, 0x01, 0x01]);
        p.drops = 2;
        let f = assess_pkt(&p);
        assert!(f[0].text.contains("dropped"));
    }
}
