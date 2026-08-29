//! btmon-style streaming text output.
//!
//! Layout of a headline (fixed column for the trailer, like btmon):
//!
//! ```text
//! < HCI Command: LE Set Advertising Data (0x08|0x0008) plen 32     #1 [hci0] 0.000004
//!         Length: 3
//! ```

use std::io::{self, Write};

use hcimon_decode::{Decoded, Opcode, Style, Timestamp};
use hcimon_capture::{Packet, INDEX_NONE};

use crate::time::{format_time, TimeMode};

/// ANSI SGR sequences used by the renderer (btmon's palette).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Palette {
    pub enabled: bool,
}

impl Palette {
    const OFF: &'static str = "\x1b[0m";
    const RED: &'static str = "\x1b[0;31m";
    const GREEN: &'static str = "\x1b[0;32m";
    const YELLOW: &'static str = "\x1b[0;33m";
    const BLUE: &'static str = "\x1b[0;34m";
    const MAGENTA: &'static str = "\x1b[0;35m";
    const CYAN: &'static str = "\x1b[0;36m";
    const WHITE_BG: &'static str = "\x1b[0;47;30m";
    const RED_BOLD: &'static str = "\x1b[1;31m";
    const GREEN_BOLD: &'static str = "\x1b[1;32m";
    const BLUE_BOLD: &'static str = "\x1b[1;34m";
    const MAGENTA_BOLD: &'static str = "\x1b[1;35m";

    fn for_packet(&self, d: &Decoded) -> &'static str {
        if !self.enabled {
            return "";
        }
        if d.unknown {
            return Self::WHITE_BG;
        }
        match d.opcode {
            Opcode::NewIndex | Opcode::OpenIndex | Opcode::IndexInfo => Self::GREEN,
            Opcode::DelIndex | Opcode::CloseIndex => Self::RED,
            Opcode::Command => Self::BLUE,
            Opcode::Event => Self::MAGENTA,
            Opcode::AclTx | Opcode::AclRx => Self::CYAN,
            Opcode::ScoTx | Opcode::ScoRx | Opcode::IsoTx | Opcode::IsoRx | Opcode::VendorDiag => Self::YELLOW,
            Opcode::CtrlOpen => Self::GREEN_BOLD,
            Opcode::CtrlClose => Self::RED_BOLD,
            Opcode::CtrlCommand => Self::BLUE_BOLD,
            Opcode::CtrlEvent => Self::MAGENTA_BOLD,
            Opcode::SystemNote | Opcode::UserLogging | Opcode::Unknown(_) => "",
        }
    }

    fn for_style(&self, style: Style) -> &'static str {
        if !self.enabled {
            return "";
        }
        match style {
            Style::Normal | Style::Hex | Style::Heading => "",
            Style::Unknown => Self::WHITE_BG,
            Style::Error => Self::RED_BOLD,
        }
    }

    fn off(&self) -> &'static str {
        if self.enabled {
            Self::OFF
        } else {
            ""
        }
    }

    fn timestamp(&self) -> &'static str {
        if self.enabled {
            Self::YELLOW
        } else {
            ""
        }
    }
}

/// Streaming text printer.
pub struct Printer<W: Write> {
    out: W,
    palette: Palette,
    columns: usize,
    time_mode: TimeMode,
    show_index: bool,
    first_ts: Option<Timestamp>,
}

impl<W: Write> Printer<W> {
    pub fn new(out: W, color: bool, columns: usize, time_mode: TimeMode) -> Self {
        Printer { out, palette: Palette { enabled: color }, columns: columns.max(40), time_mode, show_index: true, first_ts: None }
    }

    /// Set the timestamp that offsets are relative to (the first captured packet).
    pub fn set_origin(&mut self, ts: Option<Timestamp>) {
        if self.first_ts.is_none() {
            self.first_ts = ts;
        }
    }

    /// Print a decoded packet.
    pub fn print(&mut self, pkt: &Packet, d: &Decoded, source_label: Option<&str>) -> io::Result<()> {
        if self.first_ts.is_none() {
            self.first_ts = pkt.ts;
        }
        let mut trailer = String::new();
        if let Some(label) = source_label {
            trailer.push_str(&format!(" {{{label}}}"));
        }
        if d.frame > 0 {
            trailer.push_str(&format!(" #{}", d.frame));
        }
        if self.show_index && pkt.index != INDEX_NONE {
            trailer.push_str(&format!(" [hci{}]", pkt.index));
        }
        if let Some(ts) = pkt.ts {
            if let Some(s) = format_time(ts, self.first_ts, self.time_mode) {
                trailer.push(' ');
                trailer.push_str(&s);
            }
        }

        let head = d.headline();
        let color = self.palette.for_packet(d);
        let off = self.palette.off();
        if trailer.is_empty() {
            writeln!(self.out, "{color}{head}{off}")?;
        } else {
            let head_len = head.chars().count();
            let max_head = self.columns.saturating_sub(trailer.chars().count() + 1);
            let (head, head_len) = if head_len > max_head && max_head > 3 {
                let mut h: String = head.chars().take(max_head - 2).collect();
                h.push_str("..");
                (h, max_head)
            } else {
                (head, head_len)
            };
            let pad = max_head.saturating_sub(head_len);
            writeln!(
                self.out,
                "{color}{head}{off}{:pad$}{ts}{trailer}{off}",
                "",
                ts = self.palette.timestamp(),
                pad = pad
            )?;
        }

        // Generated fields, in Wireshark's bracket style.
        for l in &d.links {
            if l.kind == hcimon_decode::LinkKind::ResponseTo {
                let rtt = l.elapsed_us.map(|us| format!(", {:.3} ms", us as f64 / 1000.0)).unwrap_or_default();
                writeln!(self.out, "      [Response to frame #{}{rtt}]", l.frame)?;
            }
        }
        let palette = self.palette;
        let mut res = Ok(());
        hcimon_decode::render_lines(&d.fields, d.indent, |indent, node| {
            if res.is_err() {
                return;
            }
            let c = palette.for_style(node.style);
            let o = if c.is_empty() { "" } else { palette.off() };
            res = writeln!(self.out, "{:indent$}{c}{}{o}", "", node.text, indent = indent);
        });
        res
    }

    /// Print a status/informational line (source connected, errors, ...).
    pub fn note(&mut self, text: &str) -> io::Result<()> {
        writeln!(self.out, "{}= Note: {}{}", self.palette.for_style(Style::Normal), text, self.palette.off())
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.out.flush()
    }
}
