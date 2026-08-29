//! Capture statistics, computed on demand from the packet store.

use std::collections::HashMap;

use hcimon_capture::Opcode;
use hcimon_decode::Timestamp;

use crate::session::Entry;

#[derive(Debug, Clone, Default)]
pub struct Stats {
    pub total: usize,
    /// Packets and payload bytes per kind, in display order.
    pub kinds: Vec<(&'static str, u64, u64)>,
    pub top_commands: Vec<(String, u64)>,
    pub top_events: Vec<(String, u64)>,
    pub top_att: Vec<(String, u64)>,
    /// Packets per protocol layer.
    pub layers: Vec<(&'static str, u64)>,
    pub findings: (u64, u64, u64),
    /// Capture span in microseconds (first to last timestamp).
    pub span_us: i64,
    /// Packets per bucket over the capture span, oldest first.
    pub rate: Vec<u64>,
    pub bucket_us: i64,
    pub max_rtt_ms: f64,
    pub avg_rtt_ms: f64,
    pub answered: u64,
}

fn top(map: HashMap<String, u64>, n: usize) -> Vec<(String, u64)> {
    let mut v: Vec<(String, u64)> = map.into_iter().collect();
    v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    v.truncate(n);
    v
}

/// Compute statistics; `buckets` is the number of rate samples wanted.
pub fn collect(entries: &[Entry], buckets: usize) -> Stats {
    let mut s = Stats { total: entries.len(), ..Default::default() };
    let mut kinds: Vec<(&'static str, u64, u64)> = vec![
        ("HCI commands", 0, 0),
        ("HCI events", 0, 0),
        ("ACL TX", 0, 0),
        ("ACL RX", 0, 0),
        ("SCO", 0, 0),
        ("ISO", 0, 0),
        ("User logging", 0, 0),
        ("Index / notes", 0, 0),
        ("Control / MGMT", 0, 0),
        ("Vendor diag", 0, 0),
    ];
    let mut cmds = HashMap::new();
    let mut evts = HashMap::new();
    let mut atts = HashMap::new();
    let mut layers: HashMap<&'static str, u64> = HashMap::new();
    let mut rtt_sum = 0.0;
    let mut first: Option<Timestamp> = None;
    let mut last: Option<Timestamp> = None;
    for e in entries {
        let k = match e.packet.opcode {
            Opcode::Command => 0,
            Opcode::Event => 1,
            Opcode::AclTx => 2,
            Opcode::AclRx => 3,
            Opcode::ScoTx | Opcode::ScoRx => 4,
            Opcode::IsoTx | Opcode::IsoRx => 5,
            Opcode::UserLogging => 6,
            Opcode::CtrlOpen | Opcode::CtrlClose | Opcode::CtrlCommand | Opcode::CtrlEvent => 8,
            Opcode::VendorDiag => 9,
            _ => 7,
        };
        kinds[k].1 += 1;
        kinds[k].2 += e.packet.data.len() as u64;
        match e.packet.opcode {
            Opcode::Command => {
                if let Some(v) = e.index.get("opcode").next() {
                    *cmds.entry(v.name.clone()).or_insert(0) += 1;
                }
            }
            Opcode::Event => {
                let name = e.index.get("subevent").next().or_else(|| e.index.get("event").next()).map(|v| v.name.clone());
                if let Some(n) = name {
                    *evts.entry(n).or_insert(0) += 1;
                }
            }
            _ => {}
        }
        if let Some(v) = e.index.get("att").next() {
            // `Read By Type Request (0x08) len 6` → the PDU name.
            let name = v.text.split(" (").next().unwrap_or(&v.text).to_string();
            *atts.entry(name).or_insert(0) += 1;
        }
        for l in &e.decoded.layers {
            *layers.entry(l.name()).or_insert(0) += 1;
        }
        if let Some(f) = e.findings.first() {
            match f.severity {
                hcimon_decode::Severity::Error => s.findings.0 += 1,
                hcimon_decode::Severity::Warning => s.findings.1 += 1,
                hcimon_decode::Severity::Note => s.findings.2 += 1,
            }
        }
        for r in &e.refs {
            if r.kind == hcimon_decode::LinkKind::ResponseTo {
                if let Some(us) = r.elapsed_us {
                    let ms = us as f64 / 1000.0;
                    s.answered += 1;
                    rtt_sum += ms;
                    if ms > s.max_rtt_ms {
                        s.max_rtt_ms = ms;
                    }
                }
            }
        }
        if let Some(ts) = e.packet.ts {
            if first.is_none() {
                first = Some(ts);
            }
            last = Some(ts);
        }
    }
    s.kinds = kinds.into_iter().filter(|k| k.1 > 0).collect();
    s.top_commands = top(cmds, 8);
    s.top_events = top(evts, 8);
    s.top_att = top(atts, 8);
    let mut lv: Vec<(&'static str, u64)> = layers.into_iter().collect();
    lv.sort_by(|a, b| b.1.cmp(&a.1));
    s.layers = lv;
    if s.answered > 0 {
        s.avg_rtt_ms = rtt_sum / s.answered as f64;
    }
    if let (Some(f), Some(l)) = (first, last) {
        s.span_us = l.micros_since(f).max(0);
        let buckets = buckets.max(1);
        s.bucket_us = (s.span_us / buckets as i64).max(1);
        s.rate = vec![0; buckets];
        for e in entries {
            if let Some(ts) = e.packet.ts {
                let i = ((ts.micros_since(f).max(0) / s.bucket_us) as usize).min(buckets - 1);
                s.rate[i] += 1;
            }
        }
    }
    s
}

/// Human readable duration.
pub fn span_text(us: i64) -> String {
    let secs = us as f64 / 1_000_000.0;
    if secs >= 3600.0 {
        format!("{:.1} h", secs / 3600.0)
    } else if secs >= 60.0 {
        format!("{:.1} min", secs / 60.0)
    } else {
        format!("{secs:.1} s")
    }
}
