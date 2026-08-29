//! Capture file source: btsnoop, Apple PacketLogger, or a raw monitor byte stream.

use std::fs;
use std::io;
use std::thread::JoinHandle;

use anyhow::{Context, Result};
use hcimon_capture::{btsnoop, tty::Framer, Packet};

use super::SourceCtx;

pub fn spawn(ctx: SourceCtx, path: String) -> Result<JoinHandle<()>> {
    let packets = read_all(&path)?;
    let thread = std::thread::Builder::new()
        .name(format!("file {}", super::short_path(&path)))
        .spawn(move || {
            ctx.status(format!("{}: {} packets", super::short_path(&path), packets.len()));
            for p in packets {
                if ctx.stopped() || !ctx.packet(p) {
                    break;
                }
            }
            ctx.eof();
        })?;
    Ok(thread)
}

/// Read every packet of a capture file.
pub fn read_all(path: &str) -> Result<Vec<Packet>> {
    let data = fs::read(path).with_context(|| format!("failed to read {path}"))?;
    if data.starts_with(b"btsnoop\0") {
        return read_btsnoop(path, data);
    }
    // A raw monitor stream (what Zephyr writes to a UART/RTT) has no header;
    // accept it when the whole file frames cleanly.
    let mut framer = Framer::new();
    framer.push(&data);
    let mut packets = Vec::new();
    while let Some(f) = framer.next_frame() {
        packets.push(f.packet);
    }
    if !packets.is_empty() && framer.skipped == 0 && framer.buffered() < 6 {
        return Ok(packets);
    }
    if looks_like_packetlogger(&data) {
        return read_btsnoop(path, data);
    }
    if !packets.is_empty() {
        // Framed with some noise: still usable.
        return Ok(packets);
    }
    anyhow::bail!("{path}: not a btsnoop, PacketLogger or monitor stream file")
}

fn read_btsnoop(path: &str, data: Vec<u8>) -> Result<Vec<Packet>> {
    let mut reader = btsnoop::Reader::new(io::Cursor::new(data)).with_context(|| format!("{path}: unsupported file"))?;
    let mut packets = Vec::new();
    loop {
        match reader.read_packet() {
            Ok(Some(p)) => packets.push(p),
            Ok(None) => break,
            // A truncated tail: keep what was read.
            Err(_) if !packets.is_empty() => break,
            Err(e) => return Err(e).with_context(|| format!("{path}: read error")),
        }
    }
    Ok(packets)
}

fn looks_like_packetlogger(data: &[u8]) -> bool {
    data.len() >= 4 && ((data[0] == 0 && data[1] <= 1) || (data[3] == 0 && data[2] <= 1))
}
