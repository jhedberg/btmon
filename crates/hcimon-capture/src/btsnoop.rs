//! btsnoop (RFC 1761 style) capture files, plus Apple PacketLogger files.
//!
//! btsnoop files start with a 16-byte header (`"btsnoop\0"`, version 1 and a
//! datalink type) followed by records with a 24-byte big-endian header.  The
//! datalink type decides how the monitor opcode and controller index are
//! stored in the record flags.  `btmon -w` writes [`Format::Monitor`].

use std::fs::File;
use std::io::{self, BufReader, BufWriter, ErrorKind, Read, Write};
use std::path::Path;

use crate::{Opcode, Packet, Timestamp, INDEX_NONE, MAX_PACKET_SIZE};

const MAGIC: &[u8; 8] = b"btsnoop\0";
const VERSION: u32 = 1;
/// Offset of the Unix epoch relative to the btsnoop epoch (0000-01-01), in microseconds.
const EPOCH_OFFSET: i64 = 0x00E0_3AB4_4A67_6000 - 946_684_800 * 1_000_000;

/// btsnoop datalink types.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    /// Raw HCI packets, direction and command/event flags in the record.
    Hci,
    /// H4: packets prefixed by the UART packet type indicator.
    Uart,
    Bcsp,
    ThreeWire,
    /// BlueZ monitor: `(index << 16) | opcode` in the flags field.
    Monitor,
    Simulator,
}

impl Format {
    pub fn from_u32(v: u32) -> Option<Self> {
        Some(match v {
            1001 => Format::Hci,
            1002 => Format::Uart,
            1003 => Format::Bcsp,
            1004 => Format::ThreeWire,
            2001 => Format::Monitor,
            2002 => Format::Simulator,
            _ => return None,
        })
    }

    pub fn to_u32(self) -> u32 {
        match self {
            Format::Hci => 1001,
            Format::Uart => 1002,
            Format::Bcsp => 1003,
            Format::ThreeWire => 1004,
            Format::Monitor => 2001,
            Format::Simulator => 2002,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Btsnoop(Format),
    /// Apple PacketLogger; `true` when little-endian ("v2").
    Pklg(bool),
}

/// Reads monitor packets from a btsnoop or PacketLogger file.
pub struct Reader {
    inner: Box<dyn Read + Send>,
    kind: Kind,
}

impl Reader {
    pub fn open(path: impl AsRef<Path>) -> io::Result<Self> {
        Reader::new(BufReader::new(File::open(path)?))
    }

    pub fn new<R: Read + Send + 'static>(mut reader: R) -> io::Result<Self> {
        let mut hdr = [0u8; 16];
        reader.read_exact(&mut hdr)?;
        if &hdr[..8] == MAGIC {
            let version = u32::from_be_bytes(hdr[8..12].try_into().unwrap());
            if version != VERSION {
                return Err(invalid(format!("unsupported btsnoop version {version}")));
            }
            let datalink = u32::from_be_bytes(hdr[12..16].try_into().unwrap());
            let format = Format::from_u32(datalink)
                .ok_or_else(|| invalid(format!("unsupported btsnoop datalink type {datalink}")))?;
            return Ok(Reader { inner: Box::new(reader), kind: Kind::Btsnoop(format) });
        }
        // Apple PacketLogger has no file header; sniff the first record length.
        let kind = if hdr[0] == 0 && (hdr[1] == 0 || hdr[1] == 1) {
            Kind::Pklg(false)
        } else if hdr[3] == 0 && (hdr[2] == 0 || hdr[2] == 1) {
            Kind::Pklg(true)
        } else {
            return Err(invalid("not a btsnoop or PacketLogger file"));
        };
        // Push the sniffed bytes back in front of the stream.
        let inner = Box::new(io::Cursor::new(hdr.to_vec()).chain(reader));
        Ok(Reader { inner, kind })
    }

    /// The datalink format of the file (PacketLogger files report [`Format::Monitor`]).
    pub fn format(&self) -> Format {
        match self.kind {
            Kind::Btsnoop(f) => f,
            Kind::Pklg(_) => Format::Monitor,
        }
    }

    pub fn is_packetlogger(&self) -> bool {
        matches!(self.kind, Kind::Pklg(_))
    }

    /// Read the next packet; `Ok(None)` at a clean end of file.
    pub fn read_packet(&mut self) -> io::Result<Option<Packet>> {
        match self.kind {
            Kind::Btsnoop(format) => self.read_btsnoop(format),
            Kind::Pklg(le) => self.read_pklg(le),
        }
    }

    fn read_btsnoop(&mut self, format: Format) -> io::Result<Option<Packet>> {
        let mut hdr = [0u8; 24];
        match read_full(&mut self.inner, &mut hdr)? {
            0 => return Ok(None),
            24 => {}
            _ => return Err(invalid("truncated btsnoop record header")),
        }
        let incl_len = u32::from_be_bytes(hdr[4..8].try_into().unwrap()) as usize;
        let flags = u32::from_be_bytes(hdr[8..12].try_into().unwrap());
        let drops = u32::from_be_bytes(hdr[12..16].try_into().unwrap());
        let ts = i64::from_be_bytes(hdr[16..24].try_into().unwrap());
        if incl_len > MAX_PACKET_SIZE + 1 {
            return Err(invalid(format!("btsnoop record too large ({incl_len} bytes)")));
        }
        let mut data = vec![0u8; incl_len];
        self.inner.read_exact(&mut data)?;

        let (index, opcode) = match format {
            Format::Monitor => ((flags >> 16) as u16, Opcode::from_u16((flags & 0xffff) as u16)),
            Format::Hci => (0, opcode_from_hci_flags(flags)),
            Format::Uart => {
                if data.is_empty() {
                    return Err(invalid("empty H4 record"));
                }
                let t = data.remove(0);
                (0, opcode_from_h4(t, flags))
            }
            other => return Err(invalid(format!("reading {other:?} files is not supported"))),
        };
        Ok(Some(Packet {
            ts: Some(Timestamp::Wall(ts.wrapping_sub(EPOCH_OFFSET))),
            index,
            opcode,
            drops,
            data,
        }))
    }

    fn read_pklg(&mut self, le: bool) -> io::Result<Option<Packet>> {
        let mut hdr = [0u8; 13];
        match read_full(&mut self.inner, &mut hdr)? {
            0 => return Ok(None),
            13 => {}
            _ => return Err(invalid("truncated PacketLogger record header")),
        }
        let len_bytes: [u8; 4] = hdr[0..4].try_into().unwrap();
        let ts_bytes: [u8; 8] = hdr[4..12].try_into().unwrap();
        let (len, secs, usec) = if le {
            let ts = u64::from_le_bytes(ts_bytes);
            (u32::from_le_bytes(len_bytes), (ts & 0xffff_ffff) as i64, (ts >> 32) as i64)
        } else {
            let ts = u64::from_be_bytes(ts_bytes);
            (u32::from_be_bytes(len_bytes), (ts >> 32) as i64, (ts & 0xffff_ffff) as i64)
        };
        let len = (len as usize).checked_sub(9).ok_or_else(|| invalid("bad PacketLogger record length"))?;
        if len > MAX_PACKET_SIZE {
            return Err(invalid(format!("PacketLogger record too large ({len} bytes)")));
        }
        let mut data = vec![0u8; len];
        self.inner.read_exact(&mut data)?;
        let (index, opcode) = match hdr[12] {
            0x00 => (0, Opcode::Command),
            0x01 => (0, Opcode::Event),
            0x02 => (0, Opcode::AclTx),
            0x03 => (0, Opcode::AclRx),
            0x08 => (0, Opcode::ScoTx),
            0x09 => (0, Opcode::ScoRx),
            0x12 => (0, Opcode::IsoTx),
            0x13 => (0, Opcode::IsoRx),
            0x0b => (0, Opcode::VendorDiag),
            0xfc => (INDEX_NONE, Opcode::SystemNote),
            other => (INDEX_NONE, Opcode::Unknown(0xff00 | other as u16)),
        };
        Ok(Some(Packet {
            ts: Some(Timestamp::from_timeval(secs, usec)),
            index,
            opcode,
            drops: 0,
            data,
        }))
    }

}

fn opcode_from_hci_flags(flags: u32) -> Opcode {
    match (flags & 0x02 != 0, flags & 0x01 != 0) {
        (true, true) => Opcode::Event,
        (true, false) => Opcode::Command,
        (false, true) => Opcode::AclRx,
        (false, false) => Opcode::AclTx,
    }
}

fn opcode_from_h4(t: u8, flags: u32) -> Opcode {
    let rx = flags & 0x01 != 0;
    match t {
        0x01 => Opcode::Command,
        0x02 if rx => Opcode::AclRx,
        0x02 => Opcode::AclTx,
        0x03 if rx => Opcode::ScoRx,
        0x03 => Opcode::ScoTx,
        0x04 => Opcode::Event,
        0x05 if rx => Opcode::IsoRx,
        0x05 => Opcode::IsoTx,
        other => Opcode::Unknown(0xff00 | other as u16),
    }
}

fn hci_flags_from_opcode(op: Opcode) -> Option<u32> {
    Some(match op {
        Opcode::Command => 0x02,
        Opcode::Event => 0x03,
        Opcode::AclTx => 0x00,
        Opcode::AclRx => 0x01,
        _ => return None,
    })
}

fn read_full<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut n = 0;
    while n < buf.len() {
        match r.read(&mut buf[n..]) {
            Ok(0) => break,
            Ok(k) => n += k,
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(n)
}

fn invalid(msg: impl Into<String>) -> io::Error {
    io::Error::new(ErrorKind::InvalidData, msg.into())
}

/// Writes monitor packets to a btsnoop file.
pub struct Writer<W: Write> {
    inner: BufWriter<W>,
    format: Format,
    /// For single-controller formats: the index that is being recorded.
    index: Option<u16>,
    written: u64,
}

impl Writer<File> {
    pub fn create(path: impl AsRef<Path>, format: Format) -> io::Result<Self> {
        Writer::new(File::create(path)?, format)
    }
}

impl<W: Write> Writer<W> {
    pub fn new(writer: W, format: Format) -> io::Result<Self> {
        let mut inner = BufWriter::new(writer);
        inner.write_all(MAGIC)?;
        inner.write_all(&VERSION.to_be_bytes())?;
        inner.write_all(&format.to_u32().to_be_bytes())?;
        Ok(Writer { inner, format, index: None, written: 0 })
    }

    pub fn format(&self) -> Format {
        self.format
    }

    /// Packets written so far.
    pub fn written(&self) -> u64 {
        self.written
    }

    /// Write a packet.  Returns `Ok(false)` if the packet cannot be represented
    /// in the file's format (e.g. a "New Index" record in an H4 file) and was skipped.
    pub fn write_packet(&mut self, pkt: &Packet) -> io::Result<bool> {
        let mut prefix: Option<u8> = None;
        let flags = match self.format {
            Format::Monitor => ((pkt.index as u32) << 16) | pkt.opcode.to_u16() as u32,
            Format::Hci => {
                if !self.accept_index(pkt.index) {
                    return Ok(false);
                }
                match hci_flags_from_opcode(pkt.opcode) {
                    Some(f) => f,
                    None => return Ok(false),
                }
            }
            Format::Uart => {
                if !self.accept_index(pkt.index) {
                    return Ok(false);
                }
                let Some(t) = pkt.opcode.h4_type() else { return Ok(false) };
                prefix = Some(t);
                match pkt.opcode {
                    Opcode::Event | Opcode::AclRx | Opcode::ScoRx | Opcode::IsoRx => 0x01,
                    _ => 0x00,
                }
            }
            other => return Err(invalid(format!("writing {other:?} files is not supported"))),
        };
        let ts = match pkt.ts.unwrap_or_else(Timestamp::now) {
            Timestamp::Wall(us) => us,
            // Monotonic timestamps are stored as-is; readers see them as times in year 1970.
            Timestamp::Monotonic(us) => us as i64,
        };
        let len = pkt.data.len() + prefix.is_some() as usize;
        self.inner.write_all(&(len as u32).to_be_bytes())?;
        self.inner.write_all(&(len as u32).to_be_bytes())?;
        self.inner.write_all(&flags.to_be_bytes())?;
        self.inner.write_all(&pkt.drops.to_be_bytes())?;
        self.inner.write_all(&ts.wrapping_add(EPOCH_OFFSET).to_be_bytes())?;
        if let Some(t) = prefix {
            self.inner.write_all(&[t])?;
        }
        self.inner.write_all(&pkt.data)?;
        self.written += 1;
        Ok(true)
    }

    fn accept_index(&mut self, index: u16) -> bool {
        if index == INDEX_NONE {
            return false;
        }
        match self.index {
            None => {
                self.index = Some(index);
                true
            }
            Some(i) => i == index,
        }
    }

    pub fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monitor_roundtrip() {
        let pkts = vec![
            Packet { ts: Some(Timestamp::Wall(1_700_000_000_123_456)), index: 0, opcode: Opcode::NewIndex, drops: 0, data: vec![0; 16] },
            Packet { ts: Some(Timestamp::Wall(1_700_000_000_223_456)), index: 1, opcode: Opcode::Command, drops: 2, data: vec![3, 0x0c, 0] },
            Packet { ts: Some(Timestamp::Wall(1_700_000_000_323_456)), index: 1, opcode: Opcode::Event, drops: 0, data: vec![0x0e, 4, 1, 3, 0x0c, 0] },
        ];
        let mut buf = Vec::new();
        {
            let mut w = Writer::new(&mut buf, Format::Monitor).unwrap();
            for p in &pkts {
                assert!(w.write_packet(p).unwrap());
            }
            w.flush().unwrap();
        }
        let mut r = Reader::new(io::Cursor::new(buf)).unwrap();
        assert_eq!(r.format(), Format::Monitor);
        for p in &pkts {
            assert_eq!(r.read_packet().unwrap().as_ref(), Some(p));
        }
        assert_eq!(r.read_packet().unwrap(), None);
    }

    #[test]
    fn uart_roundtrip() {
        let pkts = vec![
            Packet { ts: Some(Timestamp::Wall(1)), index: 0, opcode: Opcode::Command, drops: 0, data: vec![3, 0x0c, 0] },
            Packet { ts: Some(Timestamp::Wall(2)), index: 0, opcode: Opcode::AclRx, drops: 0, data: vec![0, 0x20, 0, 0] },
        ];
        let mut buf = Vec::new();
        {
            let mut w = Writer::new(&mut buf, Format::Uart).unwrap();
            for p in &pkts {
                assert!(w.write_packet(p).unwrap());
            }
            assert!(!w.write_packet(&Packet::new(Opcode::NewIndex, 0, vec![])).unwrap());
            w.flush().unwrap();
        }
        let mut r = Reader::new(io::Cursor::new(buf)).unwrap();
        assert_eq!(r.format(), Format::Uart);
        for p in &pkts {
            assert_eq!(r.read_packet().unwrap().as_ref(), Some(p));
        }
    }

    #[test]
    fn epoch_offset_matches_bluez() {
        // 2000-01-01T00:00:00Z in btsnoop time is 0x00E03AB44A676000.
        let unix_2000 = 946_684_800i64 * 1_000_000;
        assert_eq!(unix_2000 + EPOCH_OFFSET, 0x00E0_3AB4_4A67_6000);
    }

    #[test]
    fn packetlogger_big_endian() {
        // One record: len (BE) = 9 + 3, ts = 10s / 5us, type 0x00 (command), payload 03 0c 00
        let mut buf = Vec::new();
        buf.extend_from_slice(&12u32.to_be_bytes());
        buf.extend_from_slice(&((10u64 << 32) | 5).to_be_bytes());
        buf.push(0x00);
        buf.extend_from_slice(&[3, 0x0c, 0]);
        let mut r = Reader::new(io::Cursor::new(buf)).unwrap();
        assert!(r.is_packetlogger());
        let p = r.read_packet().unwrap().unwrap();
        assert_eq!(p.opcode, Opcode::Command);
        assert_eq!(p.ts, Some(Timestamp::Wall(10_000_005)));
        assert_eq!(p.data, vec![3, 0x0c, 0]);
        assert_eq!(r.read_packet().unwrap(), None);
    }
}
