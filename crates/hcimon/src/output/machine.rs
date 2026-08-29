//! Machine-oriented output formats: a compact per-packet digest, JSON Lines
//! with the full decode, and a whole-capture summary.  These are meant for
//! scripts and for feeding captures to LLM-based analysis, where the text
//! renderer's verbosity costs tokens and its layout costs parsing effort.

use std::fmt::Write as _;
use std::io::{self, Write};

use hcimon_capture::{Opcode, INDEX_NONE};
use hcimon_decode::{LinkKind, Node, Timestamp};

use crate::conversations;
use crate::session::Entry;
use crate::stats;
use crate::time::{format_time, TimeMode};

/// Escape a string for JSON.
pub fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

fn kind_name(op: Opcode) -> &'static str {
    match op {
        Opcode::Command => "command",
        Opcode::Event => "event",
        Opcode::AclTx | Opcode::AclRx => "acl",
        Opcode::ScoTx | Opcode::ScoRx => "sco",
        Opcode::IsoTx | Opcode::IsoRx => "iso",
        Opcode::UserLogging => "log",
        Opcode::CtrlOpen | Opcode::CtrlClose | Opcode::CtrlCommand | Opcode::CtrlEvent => "control",
        Opcode::VendorDiag => "vendor",
        Opcode::SystemNote => "note",
        _ => "index",
    }
}

/// The protocol headline inside a data packet or nested event, if any
/// (`ATT: Read By Type Request (0x08) len 6`, `LE Connection Complete (0x01)`).
fn inner_headline(e: &Entry) -> Option<&str> {
    if e.decoded.indent == 6 {
        e.decoded.fields.first().map(|n| n.text.as_str())
    } else {
        None
    }
}

/// One line per packet: number, offset, direction, headline, inner protocol
/// headline, round-trip time and findings.
pub fn write_digest(w: &mut impl Write, e: &Entry, first_ts: Option<Timestamp>) -> io::Result<()> {
    let off = e.packet.ts.and_then(|t| format_time(t, first_ts, TimeMode::Offset)).unwrap_or_default();
    let mut line = format!("#{} {:>11} {}", e.seq, off, e.decoded.headline());
    if let Some(inner) = inner_headline(e) {
        line.push_str(" | ");
        line.push_str(inner);
    }
    for l in &e.decoded.links {
        match (l.kind, l.elapsed_us) {
            (LinkKind::ResponseTo, Some(us)) => {
                let _ = write!(line, " | rtt {:.3} ms to #{}", us as f64 / 1000.0, l.frame);
            }
            (LinkKind::ResponseTo, None) => {
                let _ = write!(line, " | answers #{}", l.frame);
            }
            (LinkKind::Completes, Some(us)) => {
                let _ = write!(line, " | completes #{} after {:.3} ms", l.frame, us as f64 / 1000.0);
            }
            (LinkKind::Completes, None) => {
                let _ = write!(line, " | completes #{}", l.frame);
            }
            _ => {}
        }
    }
    for f in &e.findings {
        let _ = write!(line, " | {}: {}", f.severity.name(), f.text);
    }
    writeln!(w, "{line}")
}

fn tree_json(nodes: &[Node], out: &mut String) {
    out.push('[');
    for (i, n) in nodes.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"t\":");
        out.push_str(&json_str(&n.text));
        if n.style != hcimon_decode::Style::Normal {
            let _ = write!(out, ",\"s\":\"{:?}\"", n.style);
        }
        if !n.children.is_empty() {
            out.push_str(",\"c\":");
            tree_json(&n.children, out);
        }
        out.push('}');
    }
    out.push(']');
}

/// One JSON object per packet.
pub fn write_jsonl(w: &mut impl Write, e: &Entry, first_ts: Option<Timestamp>, source: &str) -> io::Result<()> {
    let d = &e.decoded;
    let mut o = String::with_capacity(512);
    let _ = write!(o, "{{\"seq\":{},\"frame\":{}", e.seq, d.frame);
    if e.packet.index != INDEX_NONE {
        let _ = write!(o, ",\"index\":{}", e.packet.index);
    }
    let _ = write!(o, ",\"source\":{}", json_str(source));
    if let Some(ts) = e.packet.ts {
        let _ = write!(o, ",\"ts_us\":{}", ts.micros());
        if let Some(f) = first_ts {
            let _ = write!(o, ",\"offset_us\":{}", ts.micros_since(f));
        }
    }
    let dir = match d.prefix {
        '<' => "\"tx\"",
        '>' => "\"rx\"",
        _ => "null",
    };
    let _ = write!(
        o,
        ",\"dir\":{dir},\"kind\":\"{}\",\"label\":{},\"summary\":{},\"extra\":{},\"headline\":{}",
        kind_name(e.packet.opcode),
        json_str(&d.label),
        json_str(&d.summary),
        json_str(&d.extra),
        json_str(&d.headline())
    );
    if d.unknown {
        o.push_str(",\"unknown\":true");
    }
    if let Some(p) = d.priority {
        let _ = write!(o, ",\"prio\":{p}");
    }
    let layers: Vec<String> = d.layers.iter().map(|l| json_str(l.name())).collect();
    let _ = write!(o, ",\"layers\":[{}]", layers.join(","));
    let links: Vec<String> = d
        .links
        .iter()
        .filter(|l| l.kind.is_back_reference())
        .map(|l| {
            let key = if l.kind == LinkKind::Completes { "completes" } else { "response_to" };
            let ms = if l.kind == LinkKind::Completes { "tx_latency_ms" } else { "rtt_ms" };
            match l.elapsed_us {
                Some(us) => format!("{{\"{key}\":{},\"{ms}\":{:.3}}}", l.frame, us as f64 / 1000.0),
                None => format!("{{\"{key}\":{}}}", l.frame),
            }
        })
        .collect();
    let _ = write!(o, ",\"links\":[{}]", links.join(","));
    let findings: Vec<String> = e.findings.iter().map(|f| format!("{{\"severity\":\"{}\",\"text\":{}}}", f.severity.name(), json_str(&f.text))).collect();
    let _ = write!(o, ",\"findings\":[{}]", findings.join(","));
    // Typed fields: key → list of value texts (packet-level built-ins included).
    o.push_str(",\"fields\":{");
    let mut keys: Vec<&str> = e.index.fields().iter().map(|(k, _)| *k).collect();
    keys.sort_unstable();
    keys.dedup();
    for (i, k) in keys.iter().enumerate() {
        if i > 0 {
            o.push(',');
        }
        let vals: Vec<String> = e.index.get(k).map(|v| json_str(&v.text)).collect();
        let _ = write!(o, "{}:[{}]", json_str(k), vals.join(","));
    }
    o.push('}');
    o.push_str(",\"tree\":");
    tree_json(&d.fields, &mut o);
    o.push('}');
    writeln!(w, "{o}")
}

/// A capture overview: what is in it, who talked to whom, what went wrong.
pub fn write_summary(w: &mut impl Write, entries: &[Entry]) -> io::Result<()> {
    let s = stats::collect(entries, 40);
    writeln!(w, "Packets: {} over {}", s.total, stats::span_text(s.span_us))?;
    for (name, n, bytes) in &s.kinds {
        writeln!(w, "  {name:<16} {n:>7}  {bytes:>9} B")?;
    }
    if !s.layers.is_empty() {
        let l: Vec<String> = s.layers.iter().map(|(n, c)| format!("{n} {c}")).collect();
        writeln!(w, "Protocols: {}", l.join(", "))?;
    }
    if s.answered > 0 {
        writeln!(w, "Request/response: {} answered, avg {:.3} ms, max {:.3} ms", s.answered, s.avg_rtt_ms, s.max_rtt_ms)?;
    }
    for (title, list) in [("Top commands", &s.top_commands), ("Top events", &s.top_events), ("Top ATT PDUs", &s.top_att)] {
        if !list.is_empty() {
            let l: Vec<String> = list.iter().map(|(n, c)| format!("{n} ({c})")).collect();
            writeln!(w, "{title}: {}", l.join(", "))?;
        }
    }
    let convs = conversations::collect(entries);
    if !convs.is_empty() {
        writeln!(w, "Connections:")?;
        for c in &convs {
            writeln!(
                w,
                "  handle {} peer {} tx {} rx {} bytes {} packets #{}..#{} {}",
                c.handle,
                if c.peer.is_empty() { "?" } else { &c.peer },
                c.tx,
                c.rx,
                c.bytes,
                c.first,
                c.last,
                if c.open { "open" } else { "closed" }
            )?;
        }
    }
    if !s.rate.is_empty() {
        let max = s.rate.iter().copied().max().unwrap_or(0).max(1);
        let bars: String = s.rate.iter().map(|&n| " ▁▂▃▄▅▆▇█".chars().nth((n * 8 / max) as usize).unwrap_or('█')).collect();
        writeln!(w, "Activity ({} per column): {bars}", stats::span_text(s.bucket_us))?;
    }
    let findings: Vec<&Entry> = entries.iter().filter(|e| !e.findings.is_empty()).collect();
    writeln!(w, "Findings: {} errors, {} warnings, {} notes", s.findings.0, s.findings.1, s.findings.2)?;
    for e in findings.iter().take(60) {
        let f = &e.findings[0];
        writeln!(w, "  #{} {}: {}", e.seq, f.severity.name(), f.text)?;
    }
    if findings.len() > 60 {
        writeln!(w, "  ... {} more (use --format digest with -Y 'error || status != Success')", findings.len() - 60)?;
    }
    Ok(())
}
