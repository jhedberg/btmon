//! Framing of the monitor protocol over a byte stream (UART, RTT, pipes).
//!
//! Each packet is a little-endian header followed by extended header fields
//! and the payload:
//!
//! ```text
//! struct tty_hdr {
//!     uint16_t data_len;   // everything after this field
//!     uint16_t opcode;
//!     uint8_t  flags;
//!     uint8_t  hdr_len;    // length of ext_hdr
//!     uint8_t  ext_hdr[hdr_len];
//!     uint8_t  payload[data_len - 4 - hdr_len];
//! };
//! ```
//!
//! Extended header fields are `type` + fixed-size value, sorted by type.

use crate::{Opcode, Packet, Timestamp, MAX_PACKET_SIZE};

pub const EXTHDR_COMMAND_DROPS: u8 = 1;
pub const EXTHDR_EVENT_DROPS: u8 = 2;
pub const EXTHDR_ACL_TX_DROPS: u8 = 3;
pub const EXTHDR_ACL_RX_DROPS: u8 = 4;
pub const EXTHDR_SCO_TX_DROPS: u8 = 5;
pub const EXTHDR_SCO_RX_DROPS: u8 = 6;
pub const EXTHDR_OTHER_DROPS: u8 = 7;
pub const EXTHDR_TS32: u8 = 8;

const HDR_LEN: usize = 6;

/// Per-category drop counters carried in the extended header.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Drops {
    pub command: u8,
    pub event: u8,
    pub acl_tx: u8,
    pub acl_rx: u8,
    pub sco_tx: u8,
    pub sco_rx: u8,
    pub other: u8,
}

impl Drops {
    pub fn total(&self) -> u32 {
        [self.command, self.event, self.acl_tx, self.acl_rx, self.sco_tx, self.sco_rx, self.other]
            .iter()
            .map(|&d| d as u32)
            .sum()
    }
}

/// A packet decoded from the stream together with its framing metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub packet: Packet,
    pub flags: u8,
    pub drops: Drops,
    /// Raw 32-bit timestamp (units of 100 µs), if present.
    pub ts32: Option<u32>,
}

/// Incremental parser for the framed monitor stream.
///
/// Feed bytes with [`Framer::push`] and drain complete packets with
/// [`Framer::next_frame`].  Garbage between packets (common when a UART is
/// opened mid-stream or picks up noise) is skipped one byte at a time until a
/// plausible header is found.
#[derive(Debug, Default)]
pub struct Framer {
    buf: Vec<u8>,
    /// Bytes discarded while resynchronising.
    pub skipped: u64,
    /// Number of times a resynchronisation happened.
    pub resyncs: u64,
    in_gap: bool,
}

impl Framer {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// Bytes currently buffered and not yet consumed.
    pub fn buffered(&self) -> usize {
        self.buf.len()
    }

    /// Returns the next complete frame, or `None` if more bytes are needed.
    ///
    /// A frame is only returned once the header following it has arrived and
    /// looks valid, which is what catches a frame cut short by a device reboot
    /// (its own header is intact, but its tail is the start of the new boot's
    /// stream).  Call [`Framer::flush`] when the line has gone quiet to get the
    /// last frame without that confirmation.
    pub fn next_frame(&mut self) -> Option<Frame> {
        self.frame(false)
    }

    /// Returns a complete frame even if the bytes that would confirm it (the
    /// next header) have not arrived yet.  Sources call this on read timeouts
    /// and at end of input so that the last frame is not held back.
    pub fn flush(&mut self) -> Option<Frame> {
        self.frame(true)
    }

    /// Give up on an incomplete frame at the head of the buffer.
    ///
    /// For use when the line has been silent for longer than any frame takes
    /// to transmit: the header at the head is then either from a frame cut by
    /// a device reset or not a header at all (a chance match while
    /// resynchronising).  Bytes are skipped one at a time until a frame is
    /// found, which is returned, or too few bytes remain.
    pub fn abandon(&mut self) -> Option<Frame> {
        while self.buf.len() >= HDR_LEN {
            self.resync();
            if let Some(frame) = self.frame(true) {
                return Some(frame);
            }
        }
        None
    }

    fn frame(&mut self, flush: bool) -> Option<Frame> {
        loop {
            if self.buf.len() < HDR_LEN {
                return None;
            }
            let data_len = u16::from_le_bytes([self.buf[0], self.buf[1]]) as usize;
            let opcode = u16::from_le_bytes([self.buf[2], self.buf[3]]);
            let flags = self.buf[4];
            let hdr_len = self.buf[5] as usize;

            if !plausible(data_len, opcode, hdr_len) {
                self.resync();
                continue;
            }
            let total = 2 + data_len;
            if self.buf.len() < total {
                return None;
            }
            let ext = &self.buf[HDR_LEN..HDR_LEN + hdr_len];
            let Some((drops, ts32)) = parse_ext(ext) else {
                self.resync();
                continue;
            };
            if !payload_consistent(opcode, &self.buf[HDR_LEN + hdr_len..total]) {
                // A header that fits the length rules but frames garbage, typically
                // the remains of a frame cut by a reboot.  Skip a byte and try again.
                self.resync();
                continue;
            }
            // Confirm the frame by the header that follows it before releasing it.
            match self.lookahead(total) {
                Lookahead::Valid => {}
                Lookahead::Invalid => {
                    self.resync();
                    continue;
                }
                Lookahead::Incomplete if flush => {}
                Lookahead::Incomplete => return None,
            }
            let payload = self.buf[HDR_LEN + hdr_len..total].to_vec();
            self.buf.drain(..total);
            self.in_gap = false;

            let ts = ts32.map(|t| Timestamp::Monotonic(t as u64 * 100));
            let packet = Packet {
                ts,
                index: 0,
                opcode: Opcode::from_u16(opcode),
                drops: drops.total(),
                data: payload,
            };
            return Some(Frame { packet, flags, drops, ts32 });
        }
    }

    /// Check the header (and extended header) of the frame starting at `at`.
    fn lookahead(&self, at: usize) -> Lookahead {
        let Some(h) = self.buf.get(at..at + HDR_LEN) else {
            return Lookahead::Incomplete;
        };
        let data_len = u16::from_le_bytes([h[0], h[1]]) as usize;
        let opcode = u16::from_le_bytes([h[2], h[3]]);
        let hdr_len = h[5] as usize;
        if !plausible(data_len, opcode, hdr_len) {
            return Lookahead::Invalid;
        }
        let Some(ext) = self.buf.get(at + HDR_LEN..at + HDR_LEN + hdr_len) else {
            return Lookahead::Incomplete;
        };
        if parse_ext(ext).is_none() {
            return Lookahead::Invalid;
        }
        Lookahead::Valid
    }

    fn resync(&mut self) {
        // Drop one byte; leading NUL bytes are silently discarded since UARTs
        // commonly emit them at power-up.
        let first = self.buf.remove(0);
        if first != 0 {
            self.skipped += 1;
            if !self.in_gap {
                self.resyncs += 1;
                self.in_gap = true;
            }
        }
    }
}

enum Lookahead {
    Valid,
    Invalid,
    Incomplete,
}

fn plausible(data_len: usize, opcode: u16, hdr_len: usize) -> bool {
    if data_len < 4 + hdr_len {
        return false;
    }
    if data_len - 4 - hdr_len > MAX_PACKET_SIZE {
        return false;
    }
    // The extended header consists of 2-byte drop fields and one 5-byte timestamp.
    if hdr_len > 7 * 2 + 5 {
        return false;
    }
    opcode <= 19
}

/// Whether a payload is internally consistent with its opcode.
///
/// The length rules of the framing alone let a random header claim hundreds
/// of bytes of a following stream as one frame (seen after device reboots,
/// where the old frame is cut and the new boot sequence was swallowed by a
/// bogus "System Note").  HCI packets carry their own length fields, index
/// records have fixed sizes and notes are text, which makes misalignment
/// detectable without waiting for the next header.
fn payload_consistent(opcode: u16, p: &[u8]) -> bool {
    match opcode {
        // New Index: type, bus, bdaddr[6], name[8]
        0 => p.len() == 16,
        // Delete / Open / Close Index carry nothing.
        1 | 8 | 9 => p.is_empty(),
        // HCI command: opcode(2), plen(1), params
        2 => p.len() >= 3 && p[2] as usize + 3 == p.len(),
        // HCI event: code(1), plen(1), params
        3 => p.len() >= 2 && p[1] as usize + 2 == p.len(),
        // ACL data: handle/flags(2), dlen(2), data
        4 | 5 => p.len() >= 4 && u16::from_le_bytes([p[2], p[3]]) as usize + 4 == p.len(),
        // SCO data: handle/flags(2), dlen(1), data
        6 | 7 => p.len() >= 3 && p[2] as usize + 3 == p.len(),
        // Index Info: bdaddr[6], manufacturer(2)
        10 => p.len() == 8,
        // System Note: text.
        12 => p.iter().all(|&b| b == 0 || (b >= 0x20 && b < 0x7f) || b == b'\n' || b == b'\t' || b >= 0x80),
        // User Logging: priority, ident_len, ident, message
        13 => p.len() >= 2 && p[1] as usize + 2 <= p.len(),
        // ISO data: handle/flags(2), dlen(2, 14 bits), data
        18 | 19 => p.len() >= 4 && (u16::from_le_bytes([p[2], p[3]]) & 0x3fff) as usize + 4 == p.len(),
        // Vendor diagnostics and control records have no checkable structure.
        _ => true,
    }
}

/// Parse the extended header. Returns `None` on malformed contents.
fn parse_ext(mut ext: &[u8]) -> Option<(Drops, Option<u32>)> {
    let mut drops = Drops::default();
    let mut ts32 = None;
    let mut last_type = 0u8;
    while !ext.is_empty() {
        let t = ext[0];
        if t <= last_type {
            return None;
        }
        last_type = t;
        match t {
            EXTHDR_COMMAND_DROPS..=EXTHDR_OTHER_DROPS => {
                let v = *ext.get(1)?;
                match t {
                    EXTHDR_COMMAND_DROPS => drops.command = v,
                    EXTHDR_EVENT_DROPS => drops.event = v,
                    EXTHDR_ACL_TX_DROPS => drops.acl_tx = v,
                    EXTHDR_ACL_RX_DROPS => drops.acl_rx = v,
                    EXTHDR_SCO_TX_DROPS => drops.sco_tx = v,
                    EXTHDR_SCO_RX_DROPS => drops.sco_rx = v,
                    _ => drops.other = v,
                }
                ext = &ext[2..];
            }
            EXTHDR_TS32 => {
                let v = ext.get(1..5)?;
                ts32 = Some(u32::from_le_bytes([v[0], v[1], v[2], v[3]]));
                ext = &ext[5..];
            }
            _ => return None,
        }
    }
    Some((drops, ts32))
}

/// Encode a packet in the stream format (the inverse of [`Framer`]).
pub fn encode(packet: &Packet, ts32: Option<u32>) -> Vec<u8> {
    let mut ext = Vec::new();
    if let Some(ts) = ts32 {
        ext.push(EXTHDR_TS32);
        ext.extend_from_slice(&ts.to_le_bytes());
    }
    let data_len = 4 + ext.len() + packet.data.len();
    let mut out = Vec::with_capacity(2 + data_len);
    out.extend_from_slice(&(data_len as u16).to_le_bytes());
    out.extend_from_slice(&packet.opcode.to_u16().to_le_bytes());
    out.push(0);
    out.push(ext.len() as u8);
    out.extend_from_slice(&ext);
    out.extend_from_slice(&packet.data);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Drain a framer the way the file reader does: confirmed frames, then the
    /// unconfirmed last one, then whatever hides behind an incomplete header.
    fn drain(f: &mut Framer) -> Vec<Frame> {
        let mut out = Vec::new();
        while let Some(frame) = f.next_frame().or_else(|| f.flush()).or_else(|| f.abandon()) {
            out.push(frame);
        }
        out
    }

    #[test]
    fn roundtrip() {
        let pkt = Packet::new(Opcode::Command, 0, vec![0x03, 0x0c, 0x00]);
        let bytes = encode(&pkt, Some(12345));
        let mut f = Framer::new();
        f.push(&bytes[..3]);
        assert!(f.next_frame().is_none());
        f.push(&bytes[3..]);
        // Without the next header the frame is only released by flush().
        assert!(f.next_frame().is_none());
        let frame = f.flush().unwrap();
        assert_eq!(frame.packet.data, pkt.data);
        assert_eq!(frame.packet.opcode, Opcode::Command);
        assert_eq!(frame.ts32, Some(12345));
        assert_eq!(frame.packet.ts, Some(Timestamp::Monotonic(1_234_500)));
        assert!(f.next_frame().is_none());
    }

    #[test]
    fn resync_after_garbage() {
        let pkt = Packet::new(Opcode::Event, 0, vec![0x0e, 0x04, 0x01, 0x03, 0x0c, 0x00]);
        let mut bytes = vec![0x00, 0x00, 0xff, 0x13, 0x37];
        bytes.extend(encode(&pkt, None));
        let mut f = Framer::new();
        f.push(&bytes);
        let frame = f.next_frame().or_else(|| f.flush()).unwrap();
        assert_eq!(frame.packet, pkt);
        assert!(f.skipped > 0);
    }

    #[test]
    fn reboot_cut_stream_recovers_boot_sequence() {
        // Real stream from an nRF52 DK reset while streaming: the old frame is cut
        // and the new boot's New Index / Open Index / Reset must come out intact.
        let data = include_bytes!("../../../testdata/nrf52dk_observer_reboot.tty");
        let mut f = Framer::new();
        f.push(data);
        let ops: Vec<Opcode> = drain(&mut f).iter().map(|f| f.packet.opcode).collect();
        let boot = ops.windows(3).position(|w| w == [Opcode::NewIndex, Opcode::OpenIndex, Opcode::Command]);
        assert!(boot.is_some(), "boot sequence not recovered: {:?}", &ops[100..160.min(ops.len())]);
        assert!(!ops.contains(&Opcode::SystemNote), "garbage accepted as a System Note");
    }

    #[test]
    fn synthetic_cut_frame_does_not_swallow_the_next_boot() {
        // A frame announced as 40 bytes but cut after 10, followed by a fresh boot.
        let old = encode(&Packet::new(Opcode::Event, 0, vec![0x0e, 0x24, 0x01, 0x03, 0x0c, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]), Some(500));
        let mut stream = old[..16].to_vec();
        let mut ni = Packet::new(Opcode::NewIndex, 0, vec![0; 16]);
        ni.data[8..13].copy_from_slice(b"hci00");
        stream.extend(encode(&ni, Some(1)));
        stream.extend(encode(&Packet::new(Opcode::OpenIndex, 0, vec![]), Some(2)));
        stream.extend(encode(&Packet::new(Opcode::Command, 0, vec![0x03, 0x0c, 0x00]), Some(3)));
        stream.extend(encode(&Packet::new(Opcode::Event, 0, vec![0x0e, 0x04, 0x01, 0x03, 0x0c, 0x00]), Some(4)));
        let mut f = Framer::new();
        f.push(&stream);
        let ops: Vec<Opcode> = drain(&mut f).iter().map(|f| f.packet.opcode).collect();
        assert_eq!(ops, vec![Opcode::NewIndex, Opcode::OpenIndex, Opcode::Command, Opcode::Event], "{ops:?}");
    }

    #[test]
    fn sample_capture_parses_completely() {
        let data = include_bytes!("../../../testdata/xg24_peripheral_hr.tty");
        let mut f = Framer::new();
        f.push(data);
        let mut n = 0;
        while let Some(frame) = f.next_frame().or_else(|| f.flush()) {
            assert!(frame.ts32.is_some());
            n += 1;
        }
        assert!(n > 20, "only {n} frames");
        assert_eq!(f.skipped, 0);
        // The capture was cut mid-stream; at most a partial header may remain.
        assert!(f.buffered() < HDR_LEN);
    }
}
