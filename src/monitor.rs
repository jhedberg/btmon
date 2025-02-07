use std::{fmt, str};
use nom::{IResult, sequence::tuple, bytes, number::complete::{le_u8, le_u16}, multi::length_data};
use time::Time;
use num_enum::FromPrimitive;
use crate::hci;
use crate::l2cap;

#[repr(u8)]
#[derive(Debug, Eq, PartialEq, FromPrimitive)]
pub enum IndexType {
    Primary,
    Amp,

    #[num_enum(catch_all)]
    Unknown(u8),
}

#[repr(u8)]
#[derive(Debug, Eq, PartialEq, FromPrimitive)]
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

    #[num_enum(catch_all)]
    Unknown(u8),
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
        let (data, type_raw) = le_u8(data)?;
        let (data, bus_raw) = le_u8(data)?;
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
        write!(f, "type {:?} bus {:?} addr {} name {}", self.ctrl_type, self.bus, self.addr, self.name)
    }
}

#[repr(u8)]
#[derive(Debug, Eq, PartialEq, FromPrimitive)]
pub enum LogPriority {
    Emerg  = 0,
    Alert  = 1,
    Crit   = 2,
    Err    = 3,
    Warn   = 4,
    Notice = 5,
    Info   = 6,
    Dbg    = 7,

    #[num_enum(catch_all)]
    Unknown(u8),
}

#[derive(Debug, Eq, PartialEq)]
pub struct UserLogging <'a> {
    prio: LogPriority,
    id: &'a str,
    msg: &'a str,
}

impl fmt::Display for UserLogging<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.msg)
    }
}

impl UserLogging <'_> {
    fn parse(data: &'_ [u8]) -> IResult<&[u8], Op> {
        let (data, prio) = le_u8(data)?;
        let (data, raw_id) = length_data(le_u8)(data)?;
        let (_, id) = get_utf8(raw_id)?;
        let (data, msg) = get_utf8(data)?;

        Ok((data, Op::UserLogging(UserLogging { prio: LogPriority::from(prio), id, msg })))
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct AclPkt <'a> {
    handle: u16,
    pb: u8,
    bc: u8,
    data: &'a[u8],
}

impl fmt::Display for AclPkt<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match l2cap::Frame::parse(self.data) {
            Ok((_, frame)) => {
                write!(f, "handle 0x{:04x} pb {:02b} bc {:02b}: {}", self.handle, self.pb, self.bc, frame)
            },
            Err(_) => {
                write!(f, "handle 0x{:04x} pb {:02b} bc {:02b}: {:02x?}", self.handle, self.pb, self.bc, self.data)
            }
        }

    }
}

impl AclPkt <'_> {
    fn parse(frame: &'_ [u8]) -> IResult<&[u8], AclPkt> {
        let (rem, (mut handle, data)) = tuple((le_u16, length_data(le_u16)))(frame)?;
        let pb: u8 = (handle >> 12) as u8 & 0b11;
        let bc: u8 = (handle >> 14) as u8 & 0b11;
        handle &= 0b111111111111;
        Ok((rem, AclPkt { handle, pb, bc, data} ))
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum Op <'a> {
    NewIndex(NewIndex<'a>),
    DelIndex,
    CommandPkt(hci::Command<'a>),
    EventPkt(hci::Event<'a>),
    AclTxPkt(AclPkt<'a>),
    AclRxPkt(AclPkt<'a>),
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
                write!(f, "New Index:    {}", m)
            },
            Op::OpenIndex => {
                write!(f, "Open Index")
            },
            Op::UserLogging(m) => {
                write!(f, "User Logging: {}", m)
            },
            Op::CommandPkt(c) => {
                write!(f, "HCI Command:  {}", c)
            },
            Op::EventPkt(e) => {
                write!(f, "HCI Event:    {}", e)
            },
            Op::AclTxPkt(p) => {
                write!(f, "ACL TX:       {}", p)
            },
            Op::AclRxPkt(p) => {
                write!(f, "ACL RX:       {}", p)
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
        4  => match AclPkt::parse(data) {
            Ok((data, pkt)) => Ok((data, Op::AclTxPkt(pkt))),
            Err(e) => Err(e),
        }
        5  => match AclPkt::parse(data) {
            Ok((data, pkt)) => Ok((data, Op::AclRxPkt(pkt))),
            Err(e) => Err(e),
        }
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
