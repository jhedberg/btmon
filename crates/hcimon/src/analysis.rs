//! Capture analysis over a loaded file: the primitives behind the machine
//! output formats and the MCP server.
//!
//! A [`Loaded`] capture holds every packet decoded once, with the typed field
//! index, request/response references and expert findings resolved, so that
//! summaries, digests, single-packet dumps and the field dictionary can be
//! produced repeatedly without re-decoding.

use std::collections::{BTreeMap, HashMap};
use std::fmt::Write as _;

use anyhow::{bail, Result};
use hcimon_capture::INDEX_NONE;
use hcimon_decode::{decode, expert, Context, FieldIndex, LinkKind, PacketMeta, Query, Timestamp};

use crate::conversations;
use crate::output::machine;
use crate::output::plain::Printer;
use crate::session::{Entry, Ref};
use crate::source::{file, SourceId};
use crate::time::TimeMode;

/// A capture file decoded into memory.
pub struct Loaded {
    pub path: String,
    pub entries: Vec<Entry>,
    pub first_ts: Option<Timestamp>,
}

impl Loaded {
    pub fn from_file(path: &str) -> Result<Loaded> {
        let packets = file::read_all(path)?;
        let mut ctx = Context::new();
        let source = SourceId(1);
        let label = crate::source::short_path(path).to_string();
        let mut entries: Vec<Entry> = Vec::with_capacity(packets.len());
        let mut frame_map: HashMap<(u16, u64), u64> = HashMap::new();
        let mut first_ts = None;
        for (i, packet) in packets.into_iter().enumerate() {
            let seq = i as u64 + 1;
            if first_ts.is_none() {
                first_ts = packet.ts;
            }
            let decoded = decode(&mut ctx, &packet);
            let index = FieldIndex::build(&decoded, &packet, PacketMeta { seq, source: &label });
            let findings = expert::assess(&decoded, &packet, &index);
            let mut refs = Vec::new();
            for link in &decoded.links {
                if link.kind != LinkKind::ResponseTo {
                    continue;
                }
                if let Some(&req) = frame_map.get(&(packet.index, link.frame)) {
                    refs.push(Ref { kind: LinkKind::ResponseTo, seq: req, elapsed_us: link.elapsed_us });
                    if let Some(e) = entries.get_mut((req - 1) as usize) {
                        e.refs.push(Ref { kind: LinkKind::AnsweredBy, seq, elapsed_us: link.elapsed_us });
                    }
                }
            }
            if decoded.frame > 0 {
                frame_map.insert((packet.index, decoded.frame), seq);
            }
            entries.push(Entry { seq, source, packet, decoded, index, refs, findings });
        }
        Ok(Loaded { path: path.to_string(), entries, first_ts })
    }

    pub fn entry(&self, seq: u64) -> Option<&Entry> {
        self.entries.get(seq.checked_sub(1)? as usize)
    }

    /// Whole-capture overview.
    pub fn summary(&self) -> String {
        let mut buf = Vec::new();
        let _ = machine::write_summary(&mut buf, &self.entries);
        String::from_utf8_lossy(&buf).into_owned()
    }

    /// Sequence numbers of the packets matching `filter` (all when `None`) within `[first, last]`.
    pub fn matching(&self, filter: Option<&Query>, first: Option<u64>, last: Option<u64>) -> Vec<u64> {
        self.entries
            .iter()
            .filter(|e| first.is_none_or(|f| e.seq >= f) && last.is_none_or(|l| e.seq <= l))
            .filter(|e| filter.is_none_or(|q| q.matches(&e.index)))
            .map(|e| e.seq)
            .collect()
    }

    /// Digest lines for the matching packets plus `context` packets around each
    /// match, at most `limit` lines.  Returns the text and whether it was truncated.
    pub fn digest(&self, filter: Option<&Query>, first: Option<u64>, last: Option<u64>, context: usize, limit: usize) -> (String, bool) {
        let matches = self.matching(filter, first, last);
        let selected = with_context(&matches, context, self.entries.len() as u64);
        let mut out = Vec::new();
        let mut prev: Option<u64> = None;
        let mut lines = 0usize;
        let mut truncated = false;
        let match_set: std::collections::HashSet<u64> = matches.iter().copied().collect();
        for seq in selected {
            if lines >= limit {
                truncated = true;
                break;
            }
            if let Some(p) = prev {
                if seq != p + 1 && context > 0 {
                    out.extend_from_slice(b"--\n");
                }
            }
            if let Some(e) = self.entry(seq) {
                if context > 0 && !match_set.contains(&seq) {
                    out.extend_from_slice(b"  ");
                }
                let _ = machine::write_digest(&mut out, e, self.first_ts);
                lines += 1;
            }
            prev = Some(seq);
        }
        (String::from_utf8_lossy(&out).into_owned(), truncated)
    }

    /// Full decode of one packet as btmon-style text.
    pub fn packet_text(&self, seq: u64) -> Result<String> {
        let Some(e) = self.entry(seq) else { bail!("no packet {seq} (capture has {} packets)", self.entries.len()) };
        let mut buf = Vec::new();
        {
            let mut p = Printer::new(&mut buf, false, 100, TimeMode::Offset);
            p.set_origin(self.first_ts);
            p.print(&e.packet, &e.decoded, None)?;
        }
        let mut s = String::from_utf8_lossy(&buf).into_owned();
        // The printer already shows what this packet answers; add what answered it.
        for r in e.refs.iter().filter(|r| r.kind == LinkKind::AnsweredBy) {
            let rtt = r.elapsed_text();
            let _ = writeln!(s, "      [Answered by packet #{}{}]", r.seq, if rtt.is_empty() { String::new() } else { format!(", {rtt}") });
        }
        for f in &e.findings {
            let _ = writeln!(s, "      [{}: {}]", f.severity.name(), f.text);
        }
        let hex: Vec<String> = e.packet.data.iter().map(|b| format!("{b:02x}")).collect();
        let _ = writeln!(s, "      [raw: {}]", hex.join(" "));
        Ok(s)
    }

    /// Full decode of one packet as JSON.
    pub fn packet_json(&self, seq: u64) -> Result<String> {
        let Some(e) = self.entry(seq) else { bail!("no packet {seq} (capture has {} packets)", self.entries.len()) };
        let mut buf = Vec::new();
        machine::write_jsonl(&mut buf, e, self.first_ts, crate::source::short_path(&self.path))?;
        Ok(String::from_utf8_lossy(&buf).into_owned())
    }

    pub fn conversations(&self) -> String {
        let rows = conversations::collect(&self.entries);
        if rows.is_empty() {
            return "No connections in this capture.\n".into();
        }
        let mut s = String::new();
        for c in rows {
            let _ = writeln!(
                s,
                "handle {} peer {} | tx {} rx {} bytes {} | packets #{}..#{} | {}",
                c.handle,
                if c.peer.is_empty() { "?" } else { &c.peer },
                c.tx,
                c.rx,
                c.bytes,
                c.first,
                c.last,
                if c.open { "open" } else { "closed" }
            );
        }
        s
    }

    /// Expert findings, optionally at or above a severity.
    pub fn findings(&self, min: Option<hcimon_decode::Severity>) -> String {
        let mut s = String::new();
        let mut n = 0;
        for e in &self.entries {
            for f in &e.findings {
                if min.is_some_and(|m| f.severity < m) {
                    continue;
                }
                n += 1;
                let _ = writeln!(s, "#{} {}: {}", e.seq, f.severity.name(), f.text);
            }
        }
        if n == 0 {
            s.push_str("No findings.\n");
        }
        s
    }

    /// The field keys present in this capture with counts and example values.
    pub fn fields_seen(&self) -> BTreeMap<String, (usize, Vec<String>)> {
        let mut map: BTreeMap<String, (usize, Vec<String>)> = BTreeMap::new();
        for e in &self.entries {
            for (k, v) in e.index.fields() {
                let ent = map.entry(k.clone()).or_default();
                ent.0 += 1;
                if ent.1.len() < 3 && !ent.1.contains(&v.text) {
                    ent.1.push(v.text.clone());
                }
            }
        }
        map
    }
}

/// Add `context` neighbours on each side of every match, deduplicated and sorted.
pub fn with_context(matches: &[u64], context: usize, total: u64) -> Vec<u64> {
    if context == 0 {
        return matches.to_vec();
    }
    let mut out: Vec<u64> = Vec::new();
    for &m in matches {
        let lo = m.saturating_sub(context as u64).max(1);
        let hi = (m + context as u64).min(total);
        for s in lo..=hi {
            if out.last().is_none_or(|&l| l < s) {
                out.push(s);
            } else if !out.contains(&s) {
                out.push(s);
            }
        }
    }
    out.sort_unstable();
    out.dedup();
    out
}

/// Built-in filter fields with a one-line description each.
pub const BUILTIN_FIELDS: &[(&str, &str)] = &[
    ("frame", "session packet number (1-based)"),
    ("kind", "command, event, acl, sco, iso, index, log, control, vendor, note"),
    ("dir", "tx (host to controller) or rx"),
    ("index", "controller index (hci0 = 0)"),
    ("source", "capture source label"),
    ("opcode", "HCI command name or opcode (also set on Command Complete / Status)"),
    ("event", "HCI event name or code"),
    ("subevent", "LE Meta subevent name or code"),
    ("len", "payload length in bytes"),
    ("drops", "packets dropped by the capture before this one"),
    ("ident", "user-logging identifier (e.g. bt)"),
    ("prio", "user-logging priority 0..7"),
    ("message", "user-logging text"),
    ("response_to", "frame of the request this packet answers"),
    ("rtt", "milliseconds between the request and this response"),
    ("headline", "the one-line packet summary"),
    ("text", "headline plus every decoded line (use with contains)"),
    ("error", "true when the packet has a decoding problem"),
    ("hci / l2cap / att / smp / sdp / rfcomm / avdtp / avctp / mgmt / log", "protocol layer present"),
    ("handle", "connection handle (data packets and any event naming one)"),
    ("address / peer_address", "device address, e.g. address == 4B:65:27:2E:1D:6E"),
    ("status", "HCI status, e.g. status != Success"),
    ("reason", "disconnection reason"),
    ("att", "ATT PDU headline, e.g. att contains Notification"),
];

/// Render the field dictionary, with per-capture keys when a capture is given.
pub fn field_dictionary(loaded: Option<&Loaded>) -> String {
    let mut s = String::new();
    s.push_str("Filter expressions combine comparisons with && || ! and parentheses.\n");
    s.push_str("Operators: == != < <= > >= contains. Values: numbers (0x.. hex), \"strings\", addresses.\n");
    s.push_str("Field names are the decoded labels lower-cased with spaces as _ (\"Peer address\" -> peer_address).\n");
    s.push_str("A bare field name tests for presence (e.g. att, error, rtt).\n\n");
    s.push_str("Built-in fields:\n");
    for (k, d) in BUILTIN_FIELDS {
        let _ = writeln!(s, "  {k:<24} {d}");
    }
    if let Some(l) = loaded {
        let seen = l.fields_seen();
        let _ = writeln!(s, "\nFields in {} ({} keys):", crate::source::short_path(&l.path), seen.len());
        for (k, (n, examples)) in seen {
            let _ = writeln!(s, "  {k:<36} {n:>6}  e.g. {}", examples.join(" | "));
        }
    }
    s
}

/// True when a packet's controller index is a real controller.
#[allow(dead_code)]
pub fn has_index(e: &Entry) -> bool {
    e.packet.index != INDEX_NONE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_windows() {
        assert_eq!(with_context(&[5], 0, 10), vec![5]);
        assert_eq!(with_context(&[5], 2, 10), vec![3, 4, 5, 6, 7]);
        assert_eq!(with_context(&[1, 9], 1, 9), vec![1, 2, 8, 9]);
        assert_eq!(with_context(&[4, 5], 1, 10), vec![3, 4, 5, 6]);
    }

    #[test]
    fn load_and_query_sample() {
        let l = Loaded::from_file("../../testdata/xg24_peripheral_hr.tty").unwrap();
        assert_eq!(l.entries.len(), 143);
        let q = Query::parse("att && handle == 0").unwrap();
        let m = l.matching(Some(&q), None, None);
        assert!(m.len() > 10, "{m:?}");
        let (d, truncated) = l.digest(Some(&q), None, None, 0, 5);
        assert!(truncated);
        assert_eq!(d.lines().count(), 5);
        assert!(l.packet_text(66).unwrap().contains("Read By Group Type Response"));
        assert!(l.packet_text(66).unwrap().contains("[Response to frame #64"));
        assert!(l.packet_text(64).unwrap().contains("[Answered by packet #66"));
        assert!(l.packet_json(1).unwrap().starts_with("{\"seq\":1"));
        assert!(l.packet_text(9999).is_err());
        assert!(l.summary().contains("Packets: 143"));
        assert!(l.conversations().contains("handle 0"));
        assert!(field_dictionary(Some(&l)).contains("handle"));
    }
}
