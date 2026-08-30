//! Capture file source: btsnoop, Apple PacketLogger, or a raw monitor byte stream.

use std::fs;
use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;

use anyhow::{Context, Result};
use hcimon_capture::{btsnoop, tty::Framer, Opcode, Packet, Timestamp};

use super::SourceCtx;

pub fn spawn(ctx: SourceCtx, path: String) -> Result<JoinHandle<()>> {
    let capture = read_capture(&path)?;
    let thread = std::thread::Builder::new()
        .name(format!("file {}", super::short_path(&path)))
        .spawn(move || {
            ctx.status(format!("{}: {} packets", super::short_path(&path), capture.packets.len()));
            for w in &capture.warnings {
                ctx.warning(w.clone());
            }
            for p in capture.packets {
                if ctx.stopped() || !ctx.packet(p) {
                    break;
                }
            }
            ctx.eof();
        })?;
    Ok(thread)
}

/// A capture file's packets, plus anything that went wrong reading it.
pub struct Capture {
    pub packets: Vec<Packet>,
    /// A truncated final record, corrupt data or bytes that could not be
    /// framed: the packets are usable, but the file was not clean.
    pub warnings: Vec<String>,
}

/// Read every packet of a capture file.
pub fn read_capture(path: &str) -> Result<Capture> {
    let data = fs::read(path).with_context(|| format!("failed to read {path}"))?;
    if data.starts_with(b"btsnoop\0") {
        return read_btsnoop(path, data);
    }
    // A raw monitor stream (what Zephyr writes to a UART/RTT) has no header;
    // accept it when the whole file frames cleanly.
    let mut framer = Framer::new();
    framer.push(&data);
    let mut packets = Vec::new();
    while let Some(f) = framer.next_frame().or_else(|| framer.flush()).or_else(|| framer.abandon()) {
        packets.push(f.packet);
    }
    rebase_across_reboots(&mut packets);
    if !packets.is_empty() && framer.skipped == 0 {
        return Ok(Capture { packets, warnings: Vec::new() });
    }
    if looks_like_packetlogger(&data) {
        return read_btsnoop(path, data);
    }
    if !packets.is_empty() {
        // Framed with some noise: still usable, but say so.
        let warning = format!("{} bytes in {} gaps of the raw stream could not be framed", framer.skipped, framer.resyncs);
        return Ok(Capture { packets, warnings: vec![warning] });
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

/// Byte position of the reader, for saying where a file went bad.
struct Counting {
    data: io::Cursor<Vec<u8>>,
    pos: Arc<AtomicU64>,
}

impl io::Read for Counting {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = io::Read::read(&mut self.data, buf)?;
        self.pos.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
}

fn read_btsnoop(path: &str, data: Vec<u8>) -> Result<Capture> {
    let pos = Arc::new(AtomicU64::new(0));
    let mut reader =
        btsnoop::Reader::new(Counting { data: io::Cursor::new(data), pos: pos.clone() }).with_context(|| format!("{path}: unsupported file"))?;
    let mut packets = Vec::new();
    let mut warnings = Vec::new();
    loop {
        match reader.read_packet() {
            Ok(Some(p)) => packets.push(p),
            Ok(None) => break,
            // Keep what was read, but not quietly: a short final record is a
            // writer that was interrupted, anything else is corruption.
            Err(e) if !packets.is_empty() => {
                let truncated = e.kind() == io::ErrorKind::UnexpectedEof || e.to_string().contains("truncated");
                let what = if truncated { "truncated" } else { "corrupt" };
                warnings.push(format!("{what} after {} packets, at byte {}: {e}", packets.len(), pos.load(Ordering::Relaxed)));
                break;
            }
            Err(e) => return Err(e).with_context(|| format!("{path}: read error")),
        }
    }
    Ok(Capture { packets, warnings })
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

    fn temp(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("hcimon-test-{}-{name}", std::process::id()))
    }

    fn write_btsnoop(path: &std::path::Path, packets: usize) -> Vec<u8> {
        let mut w = btsnoop::Writer::create(path, btsnoop::Format::Monitor).unwrap();
        for _ in 0..packets {
            w.write_packet(&Packet::new(Opcode::Command, 0, vec![0x03, 0x0c, 0x00])).unwrap();
        }
        w.flush().unwrap();
        fs::read(path).unwrap()
    }

    #[test]
    fn truncated_btsnoop_keeps_packets_and_warns() {
        let path = temp("truncated.snoop");
        let bytes = write_btsnoop(&path, 3);
        fs::write(&path, &bytes[..bytes.len() - 5]).unwrap();
        let cap = read_capture(path.to_str().unwrap()).unwrap();
        assert_eq!(cap.packets.len(), 2);
        assert_eq!(cap.warnings.len(), 1);
        assert!(cap.warnings[0].starts_with("truncated after 2 packets, at byte "), "{}", cap.warnings[0]);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn corrupt_btsnoop_record_warns() {
        let path = temp("corrupt.snoop");
        let mut bytes = write_btsnoop(&path, 2);
        // Second record's included length: 16-byte file header, 24 + 3 byte first record.
        bytes[16 + 27 + 4..16 + 27 + 8].copy_from_slice(&0x7fff_ffffu32.to_be_bytes());
        fs::write(&path, &bytes).unwrap();
        let cap = read_capture(path.to_str().unwrap()).unwrap();
        assert_eq!(cap.packets.len(), 1);
        assert!(cap.warnings[0].starts_with("corrupt after 1 packets, at byte 67:"), "{}", cap.warnings[0]);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn clean_and_noisy_raw_streams() {
        let cap = read_capture("../../testdata/xg24_peripheral_hr.tty").unwrap();
        assert!(cap.warnings.is_empty(), "{:?}", cap.warnings);
        let cap = read_capture("../../testdata/nrf52dk_observer_reboot.tty").unwrap();
        assert_eq!(cap.warnings, vec!["119 bytes in 4 gaps of the raw stream could not be framed".to_string()]);
    }
}
