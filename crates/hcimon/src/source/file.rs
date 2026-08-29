//! Capture file source: btsnoop, Apple PacketLogger, or a raw monitor byte stream.

use std::fs;
use std::io;
use std::thread::JoinHandle;

use anyhow::{Context, Result};
use hcimon_capture::{btsnoop, tty::Framer, Opcode, Packet, Timestamp};

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
    rebase_across_reboots(&mut packets);
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

/// A raw stream carries device ticks only, and those start over when the
/// device reboots.  Keep the timestamps non-decreasing by continuing each boot
/// from where the previous one left off; the length of the reset gap itself is
/// not recorded anywhere, so it is not shown.
fn rebase_across_reboots(packets: &mut [Packet]) {
    let jump_us = super::REBOOT_JUMP * 100;
    let mut base: i64 = 0;
    let mut high_raw: u64 = 0;
    let mut high: i64 = 0;
    for p in packets {
        let Some(Timestamp::Monotonic(raw)) = p.ts else { continue };
        let announced = matches!(p.opcode, Opcode::NewIndex | Opcode::OpenIndex) && raw < high_raw;
        if announced || raw + jump_us < high_raw {
            base = high - raw as i64;
            high_raw = 0;
        }
        let ts = raw as i64 + base;
        high = high.max(ts);
        high_raw = high_raw.max(raw);
        p.ts = Some(Timestamp::Monotonic(ts.max(0) as u64));
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn pkt(opcode: Opcode, ts_us: u64) -> Packet {
        let mut p = Packet::new(opcode, 0, vec![]);
        p.ts = Some(Timestamp::Monotonic(ts_us));
        p
    }

    fn ts(p: &Packet) -> u64 {
        match p.ts {
            Some(Timestamp::Monotonic(t)) => t,
            _ => unreachable!(),
        }
    }

    #[test]
    fn raw_stream_ticks_continue_across_a_reboot() {
        let mut packets = vec![
            pkt(Opcode::Event, 10_000_000),
            pkt(Opcode::Event, 10_500_000),
            // Reboot: the device announces itself with a fresh, small tick.
            pkt(Opcode::NewIndex, 270_000),
            pkt(Opcode::OpenIndex, 270_300),
            pkt(Opcode::Command, 271_000),
            // A log record stamped before the packet that preceded it (deferred logging).
            pkt(Opcode::UserLogging, 270_900),
        ];
        rebase_across_reboots(&mut packets);
        let got: Vec<u64> = packets.iter().map(ts).collect();
        assert_eq!(got, vec![10_000_000, 10_500_000, 10_500_000, 10_500_300, 10_501_000, 10_500_900]);
    }

    #[test]
    fn raw_stream_without_reboot_is_untouched() {
        let mut packets = vec![pkt(Opcode::Command, 5_000), pkt(Opcode::NewIndex, 6_000), pkt(Opcode::Event, 4_000)];
        rebase_across_reboots(&mut packets);
        let got: Vec<u64> = packets.iter().map(ts).collect();
        assert_eq!(got, vec![5_000, 6_000, 4_000]);
    }
}
