use std::{fmt, str};
use nom::{IResult, bytes, number, multi};
use time::Time;
use crate::hci;

#[derive(Debug, Eq, PartialEq)]
pub enum IndexType {
    Primary,
    Amp,
    Unknown(u8),
}

impl From<u8> for IndexType {
    fn from(raw: u8) -> IndexType {
        match raw {
            0 => IndexType::Primary,
            1 => IndexType::Amp,
            _ => IndexType::Unknown(raw),
        }
    }
}

impl fmt::Display for IndexType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            IndexType::Primary => write!(f, "Primary"),
            IndexType::Amp => write!(f, "AMP"),
            IndexType::Unknown(t) => write!(f, "Unknown (0x{:02x?})", t),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum IndexBus {
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
    Ipm,
    Unknown(u8),
}

impl From<u8> for IndexBus {
    fn from(raw: u8) -> IndexBus {
        use IndexBus::*;
        match raw {
            0  => Virtual,
            1  => Usb,
            2  => PcCard,
            3  => Uart,
            4  => Rs232,
            5  => Pci,
            6  => Sdio,
            7  => Spi,
            8  => I2c,
            9  => Smd,
            10 => Virtio,
            11 => Ipm,
            _  => Unknown(raw),
        }
    }
}

impl fmt::Display for IndexBus {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use IndexBus::*;
        match self {
            Virtual => write!(f, "Virtual"),
            Usb     => write!(f, "USB"),
            PcCard  => write!(f, "PC Card"),
            Uart    => write!(f, "UART"),
            Rs232   => write!(f, "RS232"),
            Pci     => write!(f, "PCI"),
            Sdio    => write!(f, "SDIO"),
            Spi     => write!(f, "SPI"),
            I2c     => write!(f, "I2C"),
            Smd     => write!(f, "SMD"),
            Virtio  => write!(f, "VirtIO"),
            Ipm     => write!(f, "IPM"),
            Unknown(v) => write!(f, "Unknown (0x{:02x})", v),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct BdAddr <'a> {
    val: &'a[u8],
}

impl fmt::Display for BdAddr<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.val[5], self.val[4], self.val[3], self.val[2], self.val[1], self.val[0])
    }
}

fn get_utf8(data: &[u8]) -> IResult<&[u8], &str> {
    let (data, str_raw) = bytes::complete::take_until(&[b'\0'][..])(data)?;
    match str::from_utf8(str_raw) {
        Ok(str) => Ok((data, str)),
        Err(_) => todo!(),
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct NewIndex <'a> {
    ctrl_type: IndexType,
    bus: IndexBus,
    addr: BdAddr<'a>,
    name: &'a str,
}

impl NewIndex <'_> {
    fn parse(data: &'_[u8]) -> IResult<&[u8], Op> {
        let (data, type_raw) = number::complete::le_u8(data)?;
        let (data, bus_raw) = number::complete::le_u8(data)?;
        let (data, bdaddr) = bytes::complete::take(6usize)(data)?;
        let (data, name) = get_utf8(data)?;

        Ok((data, Op::NewIndex(NewIndex {
            ctrl_type: IndexType::from(type_raw),
            bus: IndexBus::from(bus_raw),
            addr: BdAddr { val: bdaddr },
            name,
        })))
    }
}

impl fmt::Display for NewIndex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "type {} bus {} addr {} name {}", self.ctrl_type, self.bus, self.addr, self.name)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum LogPriority {
    Err,
    Warn,
    Info,
    Dbg,
    None,
}

impl fmt::Display for LogPriority {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use LogPriority::*;
        match self {
            Err => write!(f, "err"),
            Warn => write!(f, "warn"),
            Info => write!(f, "info"),
            Dbg => write!(f, "dbg"),
            None => write!(f, "none"),
        }
    }
}

impl From<u8> for LogPriority {
    fn from(val: u8) -> LogPriority {
        use LogPriority::*;

        match val {
            3 => Err,
            4 => Warn,
            6 => Info,
            7 => Dbg,
            _ => None,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct UserLogging <'a> {
    prio: LogPriority,
    id: &'a str,
    msg: &'a str,
}

impl fmt::Display for UserLogging<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "[{}] {}: {}", self.prio, self.id, self.msg)
    }
}

impl UserLogging <'_> {
    fn parse(data: &'_ [u8]) -> IResult<&[u8], Op> {
        let (data, prio) = number::complete::le_u8(data)?;
        let (data, raw_id) = multi::length_data(number::complete::le_u8)(data)?;
        let (_, id) = get_utf8(raw_id)?;
        let (data, msg) = get_utf8(data)?;

        Ok((data, Op::UserLogging(UserLogging { prio: LogPriority::from(prio), id, msg })))
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum Op <'a> {
    NewIndex(NewIndex<'a>),
    DelIndex,
    CommandPkt(hci::Command<'a>),
    EventPkt(hci::Event<'a>),
    AclTxPkt(&'a[u8]),
    AclRxPkt(&'a[u8]),
    ScoTxPkt(&'a[u8]),
    ScoRxPkt(&'a[u8]),
    OpenIndex,
    CloseIndex,
    IndexInfo(&'a[u8]),
    VendorDiag(&'a[u8]),
    SystemNote(&'a[u8]),
    UserLogging(UserLogging<'a>),
    CtrlOpen(&'a[u8]),
    CtrlClose(&'a[u8]),
    CtrlCommand(&'a[u8]),
    CtrlEvent(&'a[u8]),
    IsoTxPkt(&'a[u8]),
    IsoRxPkt(&'a[u8]),
    Unknown(u16, &'a[u8]),
}

impl fmt::Display for Op<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Op::NewIndex(m) => {
                write!(f, "New Index: {}", m)
            },
            Op::OpenIndex => {
                write!(f, "Open Index")
            },
            Op::UserLogging(m) => {
                write!(f, "User Logging: {}", m)
            },
            Op::CommandPkt(c) => {
                write!(f, "HCI Command: {}", c)
            },
            Op::EventPkt(e) => {
                write!(f, "HCI Event: {}", e)
            },
            _ => write!(f, "{:02x?}", self),
        }
    }
}

#[derive(Debug)]
pub struct Packet <'a> {
    pub ts: Time,
    pub index: u16,
    pub op: Op<'a>,
}

fn parse_packet(op: u16, data: &[u8]) -> IResult<&[u8], Op> {
    match op {
        0  => NewIndex::parse(data),
        1  => Ok((data, Op::DelIndex)),
        2  => match hci::Command::parse(data) {
            Ok((data, cmd)) => Ok((data, Op::CommandPkt(cmd))),
            Err(e) => Err(e),
        },
        3  => match hci::Event::parse(data) {
            Ok((data, ev)) => Ok((data, Op::EventPkt(ev))),
            Err(e) => Err(e),
        },
        4  => Ok((data, Op::AclTxPkt(data))),
        5  => Ok((data, Op::AclRxPkt(data))),
        6  => Ok((data, Op::ScoTxPkt(data))),
        7  => Ok((data, Op::ScoTxPkt(data))),
        8  => Ok((data, Op::OpenIndex)),
        9  => Ok((data, Op::CloseIndex)),
        10 => Ok((data, Op::IndexInfo(data))),
        11 => Ok((data, Op::VendorDiag(data))),
        12 => Ok((data, Op::SystemNote(data))),
        13 => UserLogging::parse(data),
        14 => Ok((data, Op::CtrlOpen(data))),
        15 => Ok((data, Op::CtrlClose(data))),
        16 => Ok((data, Op::CtrlCommand(data))),
        17 => Ok((data, Op::CtrlEvent(data))),
        18 => Ok((data, Op::IsoTxPkt(data))),
        19 => Ok((data, Op::IsoRxPkt(data))),
        unknown => Ok((&data[1..], Op::Unknown(unknown, data))),
    }
}

pub fn monitor_packet(ts: Time, index: u16, op: u16, data: &[u8]) -> IResult<&[u8], Packet> {
    let (data, op) = parse_packet(op, data)?;
    Ok((data, Packet { ts, index, op }))
}

#[cfg(test)]
mod tests {
    use super::{parse_packet, Op};

    #[test]
    fn close_index() {
        let data = b"";
        let result = &data[..];
        assert_eq!(parse_packet(0x0009, data), Ok((result, Op::CloseIndex)));
    }
}
