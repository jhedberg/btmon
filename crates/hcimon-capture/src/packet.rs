use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Monitor packet opcode (BlueZ `BTSNOOP_OPCODE_*`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Opcode {
    NewIndex,
    DelIndex,
    Command,
    Event,
    AclTx,
    AclRx,
    ScoTx,
    ScoRx,
    OpenIndex,
    CloseIndex,
    IndexInfo,
    VendorDiag,
    SystemNote,
    UserLogging,
    CtrlOpen,
    CtrlClose,
    CtrlCommand,
    CtrlEvent,
    IsoTx,
    IsoRx,
    Unknown(u16),
}

impl Opcode {
    pub const fn from_u16(v: u16) -> Self {
        use Opcode::*;
        match v {
            0 => NewIndex,
            1 => DelIndex,
            2 => Command,
            3 => Event,
            4 => AclTx,
            5 => AclRx,
            6 => ScoTx,
            7 => ScoRx,
            8 => OpenIndex,
            9 => CloseIndex,
            10 => IndexInfo,
            11 => VendorDiag,
            12 => SystemNote,
            13 => UserLogging,
            14 => CtrlOpen,
            15 => CtrlClose,
            16 => CtrlCommand,
            17 => CtrlEvent,
            18 => IsoTx,
            19 => IsoRx,
            other => Unknown(other),
        }
    }

    pub const fn to_u16(self) -> u16 {
        use Opcode::*;
        match self {
            NewIndex => 0,
            DelIndex => 1,
            Command => 2,
            Event => 3,
            AclTx => 4,
            AclRx => 5,
            ScoTx => 6,
            ScoRx => 7,
            OpenIndex => 8,
            CloseIndex => 9,
            IndexInfo => 10,
            VendorDiag => 11,
            SystemNote => 12,
            UserLogging => 13,
            CtrlOpen => 14,
            CtrlClose => 15,
            CtrlCommand => 16,
            CtrlEvent => 17,
            IsoTx => 18,
            IsoRx => 19,
            Unknown(v) => v,
        }
    }

    /// Whether the packet carries HCI traffic (as opposed to bookkeeping).
    pub const fn is_hci(self) -> bool {
        use Opcode::*;
        matches!(self, Command | Event | AclTx | AclRx | ScoTx | ScoRx | IsoTx | IsoRx)
    }

    /// The H4 packet type indicator used by UART transports, if any.
    pub const fn h4_type(self) -> Option<u8> {
        use Opcode::*;
        match self {
            Command => Some(0x01),
            AclTx | AclRx => Some(0x02),
            ScoTx | ScoRx => Some(0x03),
            Event => Some(0x04),
            IsoTx | IsoRx => Some(0x05),
            _ => None,
        }
    }
}

impl From<u16> for Opcode {
    fn from(v: u16) -> Self {
        Self::from_u16(v)
    }
}

impl From<Opcode> for u16 {
    fn from(op: Opcode) -> Self {
        op.to_u16()
    }
}

/// A point in time attached to a packet.
///
/// Timestamps read from btsnoop files and the Linux monitor socket are wall
/// clock times.  The 32-bit timestamps in the TTY/RTT stream are ticks of an
/// unknown epoch (typically "since boot"), which is what [`Timestamp::Monotonic`]
/// represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Timestamp {
    /// Microseconds since the Unix epoch.
    Wall(i64),
    /// Microseconds since an arbitrary origin.
    Monotonic(u64),
}

impl Timestamp {
    pub fn now() -> Self {
        let d = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
        Timestamp::Wall(d.as_micros() as i64)
    }

    /// Timestamp from a `tv_sec`/`tv_usec` pair.
    pub fn from_timeval(secs: i64, usec: i64) -> Self {
        Timestamp::Wall(secs * 1_000_000 + usec)
    }

    /// Microseconds relative to the origin (Unix epoch or the monotonic origin).
    pub fn micros(self) -> i64 {
        match self {
            Timestamp::Wall(us) => us,
            Timestamp::Monotonic(us) => us as i64,
        }
    }

    /// Signed difference `self - other` in microseconds.
    pub fn micros_since(self, other: Timestamp) -> i64 {
        self.micros() - other.micros()
    }

    pub fn is_wall(self) -> bool {
        matches!(self, Timestamp::Wall(_))
    }
}

/// One record of the monitor protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Packet {
    pub ts: Option<Timestamp>,
    /// Controller index, or [`crate::INDEX_NONE`].
    pub index: u16,
    pub opcode: Opcode,
    /// Packets the producer dropped before this one (TTY extended headers, btsnoop `drops`).
    pub drops: u32,
    pub data: Vec<u8>,
}

impl Packet {
    pub fn new(opcode: Opcode, index: u16, data: Vec<u8>) -> Self {
        Packet { ts: None, index, opcode, drops: 0, data }
    }
}

/// Controller type from a New Index record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ControllerType {
    Primary,
    Amp,
    Unknown(u8),
}

impl ControllerType {
    pub fn from_u8(v: u8) -> Self {
        match v {
            0 => ControllerType::Primary,
            1 => ControllerType::Amp,
            other => ControllerType::Unknown(other),
        }
    }
}

impl fmt::Display for ControllerType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ControllerType::Primary => f.write_str("Primary"),
            ControllerType::Amp => f.write_str("AMP"),
            ControllerType::Unknown(v) => write!(f, "Unknown ({v})"),
        }
    }
}

/// Transport bus from a New Index record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Bus {
    Virtual,
    Usb,
    PcCard,
    Uart,
    Rs232,
    Pci,
    Sdio,
    Spi,
    I2c,
    Smd,
    Virtio,
    Ipc,
    Unknown(u8),
}

impl Bus {
    pub fn from_u8(v: u8) -> Self {
        use Bus::*;
        match v {
            0 => Virtual,
            1 => Usb,
            2 => PcCard,
            3 => Uart,
            4 => Rs232,
            5 => Pci,
            6 => Sdio,
            7 => Spi,
            8 => I2c,
            9 => Smd,
            10 => Virtio,
            11 => Ipc,
            other => Unknown(other),
        }
    }
}

impl fmt::Display for Bus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Bus::*;
        match self {
            Virtual => f.write_str("Virtual"),
            Usb => f.write_str("USB"),
            PcCard => f.write_str("PCCARD"),
            Uart => f.write_str("UART"),
            Rs232 => f.write_str("RS232"),
            Pci => f.write_str("PCI"),
            Sdio => f.write_str("SDIO"),
            Spi => f.write_str("SPI"),
            I2c => f.write_str("I2C"),
            Smd => f.write_str("SMD"),
            Virtio => f.write_str("VIRTIO"),
            Ipc => f.write_str("IPC"),
            Unknown(v) => write!(f, "Unknown ({v})"),
        }
    }
}

/// Payload of a [`Opcode::NewIndex`] record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewIndex {
    pub controller_type: ControllerType,
    pub bus: Bus,
    /// Address in little-endian wire order.
    pub bdaddr: [u8; 6],
    pub name: String,
}

impl NewIndex {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 16 {
            return None;
        }
        let mut bdaddr = [0u8; 6];
        bdaddr.copy_from_slice(&data[2..8]);
        let name = &data[8..16];
        let end = name.iter().position(|&b| b == 0).unwrap_or(name.len());
        Some(NewIndex {
            controller_type: ControllerType::from_u8(data[0]),
            bus: Bus::from_u8(data[1]),
            bdaddr,
            name: String::from_utf8_lossy(&name[..end]).into_owned(),
        })
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(16);
        v.push(match self.controller_type {
            ControllerType::Primary => 0,
            ControllerType::Amp => 1,
            ControllerType::Unknown(x) => x,
        });
        v.push(match self.bus {
            Bus::Unknown(x) => x,
            b => (0..=11u8).find(|&i| Bus::from_u8(i) == b).unwrap_or(0),
        });
        v.extend_from_slice(&self.bdaddr);
        let mut name = [0u8; 8];
        for (dst, src) in name.iter_mut().zip(self.name.bytes().take(7)) {
            *dst = src;
        }
        v.extend_from_slice(&name);
        v
    }
}

/// Payload of a [`Opcode::IndexInfo`] record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexInfo {
    pub bdaddr: [u8; 6],
    pub manufacturer: u16,
}

impl IndexInfo {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 8 {
            return None;
        }
        let mut bdaddr = [0u8; 6];
        bdaddr.copy_from_slice(&data[..6]);
        Some(IndexInfo { bdaddr, manufacturer: u16::from_le_bytes([data[6], data[7]]) })
    }
}

/// Syslog-style priority of a [`Opcode::UserLogging`] record.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Priority {
    Emerg = 0,
    Alert = 1,
    Crit = 2,
    Err = 3,
    Warning = 4,
    Notice = 5,
    Info = 6,
    Debug = 7,
}

impl Priority {
    pub fn from_u8(v: u8) -> Option<Self> {
        use Priority::*;
        Some(match v {
            0 => Emerg,
            1 => Alert,
            2 => Crit,
            3 => Err,
            4 => Warning,
            5 => Notice,
            6 => Info,
            7 => Debug,
            _ => return None,
        })
    }

    pub fn name(self) -> &'static str {
        use Priority::*;
        match self {
            Emerg => "emerg",
            Alert => "alert",
            Crit => "crit",
            Err => "err",
            Warning => "warning",
            Notice => "notice",
            Info => "info",
            Debug => "debug",
        }
    }
}

/// Payload of a [`Opcode::UserLogging`] record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserLogging {
    pub priority: u8,
    pub ident: String,
    pub message: String,
}

impl UserLogging {
    pub fn parse(data: &[u8]) -> Option<Self> {
        if data.len() < 2 {
            return None;
        }
        let priority = data[0];
        let ident_len = data[1] as usize;
        let rest = data.get(2..)?;
        let ident_raw = rest.get(..ident_len)?;
        let msg_raw = &rest[ident_len..];
        Some(UserLogging {
            priority,
            ident: cstr(ident_raw),
            message: cstr(msg_raw),
        })
    }
}

/// Decode a NUL-terminated (or unterminated) byte string leniently.
pub(crate) fn cstr(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opcode_roundtrip() {
        for v in 0..25u16 {
            assert_eq!(Opcode::from_u16(v).to_u16(), v);
        }
    }

    #[test]
    fn new_index_roundtrip() {
        let ni = NewIndex {
            controller_type: ControllerType::Primary,
            bus: Bus::Uart,
            bdaddr: [1, 2, 3, 4, 5, 6],
            name: "hci0".into(),
        };
        let bytes = ni.encode();
        assert_eq!(bytes.len(), 16);
        assert_eq!(NewIndex::parse(&bytes).unwrap(), ni);
    }

    #[test]
    fn user_logging() {
        let mut data = vec![6u8, 4];
        data.extend_from_slice(b"bt\0\0");
        data.extend_from_slice(b"hello\0");
        let ul = UserLogging::parse(&data).unwrap();
        assert_eq!(ul.priority, 6);
        assert_eq!(ul.ident, "bt");
        assert_eq!(ul.message, "hello");
    }
}
