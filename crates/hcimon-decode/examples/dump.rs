//! Decode a capture file and print it in btmon's text format.
//!
//! Accepts btsnoop / PacketLogger files and raw monitor-over-TTY captures
//! (the format Zephyr writes to a UART or RTT channel).
//!
//! Usage: `cargo run -p hcimon-decode --example dump -- <file>`

use std::env;
use std::fs;
use std::io::{self, Write};

use hcimon_decode::{decode, Context, Decoded, Packet, Timestamp};
use hcimon_capture::{btsnoop, tty};

fn main() {
    let path = match env::args().nth(1) {
        Some(p) => p,
        None => {
            eprintln!("usage: dump <capture file>");
            std::process::exit(2);
        }
    };
    let packets = match read_packets(&path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("{path}: {e}");
            std::process::exit(1);
        }
    };

    let mut ctx = Context::new();
    let mut stdout = io::BufWriter::new(io::stdout().lock());
    let first_ts = packets.iter().find_map(|p| p.ts);
    for pkt in &packets {
        let d = decode(&mut ctx, pkt);
        let _ = print_packet(&mut stdout, pkt, &d, first_ts);
    }
    let _ = stdout.flush();
}

fn read_packets(path: &str) -> io::Result<Vec<Packet>> {
    let data = fs::read(path)?;
    let mut packets = Vec::new();
    if !data.starts_with(b"btsnoop\0") {
        // Try the raw monitor stream framing first; it has no header.
        let mut framer = tty::Framer::new();
        framer.push(&data);
        while let Some(f) = framer.next_frame() {
            packets.push(f.packet);
        }
        if !packets.is_empty() && framer.skipped == 0 {
            return Ok(packets);
        }
        packets.clear();
    }
    let mut reader = btsnoop::Reader::new(io::Cursor::new(data))?;
    while let Some(p) = reader.read_packet()? {
        packets.push(p);
    }
    Ok(packets)
}

fn print_packet(w: &mut impl Write, pkt: &Packet, d: &Decoded, first_ts: Option<Timestamp>) -> io::Result<()> {
    let mut head = d.headline();
    let mut tail = String::new();
    if d.frame > 0 {
        tail.push_str(&format!(" #{}", d.frame));
    }
    if pkt.index != hcimon_capture::INDEX_NONE {
        tail.push_str(&format!(" [hci{}]", pkt.index));
    }
    if let (Some(ts), Some(first)) = (pkt.ts, first_ts) {
        let us = ts.micros_since(first);
        tail.push_str(&format!(" {}.{:06}", us / 1_000_000, us % 1_000_000));
    }
    let width = 80usize;
    if head.len() + tail.len() + 1 < width {
        head.push_str(&" ".repeat(width - head.len() - tail.len() - 1));
    }
    writeln!(w, "{head}{tail}")?;
    for line in d.lines() {
        writeln!(w, "{line}")?;
    }
    Ok(())
}
