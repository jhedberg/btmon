//! Bluetooth UUIDs in their 16-, 32- and 128-bit forms.

use std::fmt;

use crate::assigned::uuid16_name;
use crate::reader::{Reader, Result};

/// The Bluetooth base UUID: `00000000-0000-1000-8000-00805F9B34FB`.
pub const BASE_UUID: [u8; 16] = [
    0xfb, 0x34, 0x9b, 0x5f, 0x80, 0x00, 0x00, 0x80, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Uuid {
    U16(u16),
    U32(u32),
    /// Little-endian wire order, as found in ATT/GATT PDUs and advertising data.
    U128([u8; 16]),
}

impl Uuid {
    /// Read a UUID of the given byte length (2, 4 or 16).
    pub fn read(r: &mut Reader<'_>, len: usize) -> Result<Option<Uuid>> {
        Ok(match len {
            2 => Some(Uuid::U16(r.u16()?)),
            4 => Some(Uuid::U32(r.u32()?)),
            16 => Some(Uuid::U128(r.array::<16>()?)),
            _ => None,
        })
    }

    /// Collapse a 128-bit UUID built on the Bluetooth base UUID to its short form.
    pub fn normalized(self) -> Uuid {
        if let Uuid::U128(b) = self {
            if b[..12] == BASE_UUID[..12] {
                let v = u32::from_le_bytes([b[12], b[13], b[14], b[15]]);
                return if v <= 0xffff { Uuid::U16(v as u16) } else { Uuid::U32(v) };
            }
        }
        self
    }

    /// Well-known name of the UUID, if any.
    pub fn name(self) -> Option<&'static str> {
        match self.normalized() {
            Uuid::U16(v) => uuid16_name(v),
            Uuid::U32(v) if v <= 0xffff => uuid16_name(v as u16),
            _ => None,
        }
    }

    /// Size in bytes on the wire.
    pub fn len(self) -> usize {
        match self {
            Uuid::U16(_) => 2,
            Uuid::U32(_) => 4,
            Uuid::U128(_) => 16,
        }
    }

    /// `Name (0x2a00)` style text used in field output.
    pub fn describe(self) -> String {
        match self.name() {
            Some(n) => format!("{n} ({self})"),
            None => match self.normalized() {
                Uuid::U16(_) | Uuid::U32(_) => format!("Unknown ({self})"),
                Uuid::U128(_) => format!("Vendor specific ({self})"),
            },
        }
    }
}

impl fmt::Display for Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.normalized() {
            Uuid::U16(v) => write!(f, "0x{v:04x}"),
            Uuid::U32(v) => write!(f, "0x{v:08x}"),
            Uuid::U128(b) => write!(
                f,
                "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                b[15], b[14], b[13], b[12], b[11], b[10], b[9], b[8], b[7], b[6], b[5], b[4], b[3], b[2], b[1], b[0]
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_uuid_collapses() {
        let mut b = BASE_UUID;
        b[12] = 0x00;
        b[13] = 0x18;
        let u = Uuid::U128(b);
        assert_eq!(u.normalized(), Uuid::U16(0x1800));
        assert_eq!(u.name(), Some("GAP"));
        assert_eq!(u.to_string(), "0x1800");
    }

    #[test]
    fn vendor_uuid_display() {
        let b: [u8; 16] = [
            0x9e, 0xca, 0xdc, 0x24, 0x0e, 0xe5, 0xa9, 0xe0, 0x93, 0xf3, 0xa3, 0xb5, 0x01, 0x00, 0x40, 0x6e,
        ];
        assert_eq!(Uuid::U128(b).to_string(), "6e400001-b5a3-f393-e0a9-e50e24dcca9e");
    }
}
