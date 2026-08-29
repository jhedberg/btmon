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
    pub fn next_frame(&mut self) -> Option<Frame> {
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

    #[test]
    fn roundtrip() {
        let pkt = Packet::new(Opcode::Command, 0, vec![0x03, 0x0c, 0x00]);
        let bytes = encode(&pkt, Some(12345));
        let mut f = Framer::new();
        f.push(&bytes[..3]);
        assert!(f.next_frame().is_none());
        f.push(&bytes[3..]);
        let frame = f.next_frame().unwrap();
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
        let frame = f.next_frame().unwrap();
        assert_eq!(frame.packet, pkt);
        assert!(f.skipped > 0);
    }

    #[test]
    fn sample_capture_parses_completely() {
        let data = include_bytes!("../../../testdata/xg24_peripheral_hr.tty");
        let mut f = Framer::new();
        f.push(data);
        let mut n = 0;
        while let Some(frame) = f.next_frame() {
            assert!(frame.ts32.is_some());
            n += 1;
        }
        assert!(n > 20, "only {n} frames");
        assert_eq!(f.skipped, 0);
        // The capture was cut mid-stream; at most a partial header may remain.
        assert!(f.buffered() < HDR_LEN);
    }
}
