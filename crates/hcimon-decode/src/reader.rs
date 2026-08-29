//! A bounds-checked little-endian cursor over a byte slice.
//!
//! Every decoder in this crate reads its fields through [`Reader`].  Reads
//! past the end return [`Truncated`] instead of panicking, which lets the
//! caller render what was decoded so far and flag the rest.

use std::fmt;

/// Error returned when a decoder needs more bytes than are available.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Truncated {
    /// Bytes the decoder wanted to read.
    pub needed: usize,
    /// Bytes that were available.
    pub available: usize,
}

impl fmt::Display for Truncated {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "truncated: needed {} more byte(s), {} available", self.needed, self.available)
    }
}

impl std::error::Error for Truncated {}

pub type Result<T> = std::result::Result<T, Truncated>;

/// Bluetooth device address (BD_ADDR) in wire (little-endian) byte order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct BdAddr(pub [u8; 6]);

impl BdAddr {
    pub const ZERO: BdAddr = BdAddr([0; 6]);

    /// Whether the address is all zeros.
    pub fn is_zero(&self) -> bool {
        self.0 == [0; 6]
    }

    /// The two most significant bits, which classify random addresses.
    pub fn msb2(&self) -> u8 {
        self.0[5] >> 6
    }
}

impl fmt::Display for BdAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let a = &self.0;
        write!(f, "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", a[5], a[4], a[3], a[2], a[1], a[0])
    }
}

#[derive(Clone, Copy)]
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl fmt::Debug for Reader<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Reader(pos {}, {:02x?})", self.pos, &self.data[self.pos..])
    }
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    /// Bytes not yet consumed.
    pub fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// Current offset from the start of the underlying slice.
    pub fn pos(&self) -> usize {
        self.pos
    }

    /// The bytes not yet consumed, without consuming them.
    pub fn peek(&self) -> &'a [u8] {
        &self.data[self.pos..]
    }

    /// The whole underlying slice.
    pub fn all(&self) -> &'a [u8] {
        self.data
    }

    fn need(&self, n: usize) -> Result<()> {
        if self.remaining() < n {
            Err(Truncated { needed: n - self.remaining(), available: self.remaining() })
        } else {
            Ok(())
        }
    }

    /// Consume `n` bytes.
    pub fn bytes(&mut self, n: usize) -> Result<&'a [u8]> {
        self.need(n)?;
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    /// Consume exactly `N` bytes into an array.
    pub fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let s = self.bytes(N)?;
        let mut a = [0u8; N];
        a.copy_from_slice(s);
        Ok(a)
    }

    /// Consume everything that is left.
    pub fn rest(&mut self) -> &'a [u8] {
        let s = &self.data[self.pos..];
        self.pos = self.data.len();
        s
    }

    /// Consume `n` bytes and return a reader limited to them.
    pub fn sub(&mut self, n: usize) -> Result<Reader<'a>> {
        Ok(Reader::new(self.bytes(n)?))
    }

    pub fn skip(&mut self, n: usize) -> Result<()> {
        self.bytes(n).map(|_| ())
    }

    pub fn u8(&mut self) -> Result<u8> {
        self.need(1)?;
        let v = self.data[self.pos];
        self.pos += 1;
        Ok(v)
    }

    pub fn i8(&mut self) -> Result<i8> {
        self.u8().map(|v| v as i8)
    }

    pub fn u16(&mut self) -> Result<u16> {
        self.array::<2>().map(u16::from_le_bytes)
    }

    pub fn i16(&mut self) -> Result<i16> {
        self.array::<2>().map(i16::from_le_bytes)
    }

    pub fn u24(&mut self) -> Result<u32> {
        let b = self.array::<3>()?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], 0]))
    }

    pub fn u32(&mut self) -> Result<u32> {
        self.array::<4>().map(u32::from_le_bytes)
    }

    pub fn u64(&mut self) -> Result<u64> {
        self.array::<8>().map(u64::from_le_bytes)
    }

    pub fn u128(&mut self) -> Result<u128> {
        self.array::<16>().map(u128::from_le_bytes)
    }

    pub fn u16_be(&mut self) -> Result<u16> {
        self.array::<2>().map(u16::from_be_bytes)
    }

    pub fn u32_be(&mut self) -> Result<u32> {
        self.array::<4>().map(u32::from_be_bytes)
    }

    pub fn bdaddr(&mut self) -> Result<BdAddr> {
        self.array::<6>().map(BdAddr)
    }

    /// Consume a NUL-terminated string (or the rest of the buffer), lossily decoded.
    pub fn cstr(&mut self) -> String {
        let rest = self.peek();
        let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        let s = String::from_utf8_lossy(&rest[..end]).into_owned();
        self.pos += if end < rest.len() { end + 1 } else { end };
        s
    }

    /// Consume `n` bytes holding a fixed-size, NUL-padded string.
    pub fn fixed_str(&mut self, n: usize) -> Result<String> {
        let b = self.bytes(n)?;
        let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
        Ok(String::from_utf8_lossy(&b[..end]).into_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads() {
        let mut r = Reader::new(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(r.u8().unwrap(), 1);
        assert_eq!(r.u16().unwrap(), 0x0302);
        assert_eq!(r.u24().unwrap(), 0x060504);
        assert_eq!(r.remaining(), 2);
        assert_eq!(r.u32(), Err(Truncated { needed: 2, available: 2 }));
        assert_eq!(r.rest(), &[7, 8]);
        assert!(r.is_empty());
    }

    #[test]
    fn bdaddr_display() {
        let a = BdAddr([0x13, 0x71, 0xda, 0x7d, 0x1a, 0x00]);
        assert_eq!(a.to_string(), "00:1A:7D:DA:71:13");
    }

    #[test]
    fn cstr() {
        let mut r = Reader::new(b"abc\0def");
        assert_eq!(r.cstr(), "abc");
        assert_eq!(r.cstr(), "def");
        assert!(r.is_empty());
    }
}
