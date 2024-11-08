use nom::{IResult, multi, number::complete};
use std::fmt;

#[derive(Debug, Eq, PartialEq)]
pub struct DisconnectComplete {
    status: u8,
    handle: u16,
    reason: u8,
}

impl DisconnectComplete {
    fn parse(data: &'_[u8]) -> IResult<&[u8], Event> {
        let (data, status) = complete::le_u8(data)?;
        let (data, handle) = complete::le_u16(data)?;
        let (data, reason) = complete::le_u8(data)?;

        Ok((data, Event::DisconnectComplete(DisconnectComplete {
            status,
            handle,
            reason,
        })))
    }
}
#[derive(Debug, Eq, PartialEq)]
pub struct CommandComplete <'a> {
    ncmd: u8,
    op: u16,
    param: &'a[u8],
}

impl CommandComplete <'_> {
    fn parse(data: &'_[u8]) -> IResult<&[u8], Event> {
        let (data, ncmd) = complete::le_u8(data)?;
        let (data, op) = complete::le_u16(data)?;

        Ok((data, Event::CommandComplete(CommandComplete {
            ncmd,
            op,
            param: data,
        })))
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct CommandStatus {
    status: u8,
    ncmd: u8,
    op: u16,
}

impl CommandStatus {
    fn parse(data: &'_[u8]) -> IResult<&[u8], Event> {
        let (data, status) = complete::le_u8(data)?;
        let (data, ncmd) = complete::le_u8(data)?;
        let (data, op) = complete::le_u16(data)?;

        Ok((data, Event::CommandStatus(CommandStatus {
            status,
            ncmd,
            op,
        })))
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct NumCompletedPkts {
    handle: u16,
    pkts: u16,
}

impl NumCompletedPkts {
    fn parse(data: &'_[u8]) -> IResult<&[u8], Event> {
        let (data, _n_handles) = complete::le_u8(data)?;
        let (data, handle) = complete::le_u16(data)?;
        let (data, pkts) = complete::le_u16(data)?;

        Ok((data, Event::NumCompletedPkts(NumCompletedPkts {
            handle,
            pkts,
        })))
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct LeMeta <'a> {
    sub: u8,
    param: &'a[u8],
}

impl LeMeta <'_> {
    fn parse(data: &'_[u8]) -> IResult<&[u8], Event> {
        let (data, sub) = complete::le_u8(data)?;

        Ok((data, Event::LeMeta(LeMeta {
            sub,
            param: data,
        })))
    }
}

#[derive(Debug, Eq, PartialEq)]
pub enum Event <'a> {
    DisconnectComplete(DisconnectComplete),
    CommandComplete(CommandComplete<'a>),
    CommandStatus(CommandStatus),
    NumCompletedPkts(NumCompletedPkts),
    LeMeta(LeMeta<'a>),
    Unknown(u8, &'a[u8]),
}

impl fmt::Display for Event<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Event::DisconnectComplete(dc) => {
                write!(f, "Disconnect Complete: status 0x{:02x} handle 0x{:04x} reason {:02x}", dc.status, dc.handle, dc.reason)
            },
            Event::CommandComplete(cc) => {
                write!(f, "Command Complete: ncmd {} op 0x{:02x} param {:02x?}", cc.ncmd, cc.op, cc.param)
            },
            Event::CommandStatus(cs) => {
                write!(f, "Command Status: status 0x{:02x} ncmd {} op 0x{:04x}", cs.status, cs.ncmd, cs.op)
            },
            Event::NumCompletedPkts(nc) => {
                write!(f, "Number Of Completed Packets: handle 0x{:04x} pkts {}", nc.handle, nc.pkts)
            },
            Event::LeMeta(cc) => {
                write!(f, "LE Meta: sub 0x{:02x} param {:02x?}", cc.sub, cc.param)
            },
            Event::Unknown(e, d) => {
                write!(f, "0x{:02x} (Unknown): {:02x?}", e, d)
            },
        }
    }
}

impl Event <'_> {
    pub fn parse(data: &'_[u8]) -> IResult<&[u8], Event> {
        let (data, code) = complete::le_u8(data)?;
        let (data, param) = multi::length_data(complete::le_u8)(data)?;

        match code {
            0x05 => DisconnectComplete::parse(param),
            0x0e => CommandComplete::parse(param),
            0x0f => CommandStatus::parse(param),
            0x13 => NumCompletedPkts::parse(param),
            0x3e => LeMeta::parse(param),
            _    => Ok((data, Event::Unknown(code, param))),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct Command <'a> {
    op: u16,
    param: &'a[u8],
}

impl Command <'_> {
    pub fn parse(data: &'_[u8]) -> IResult<&[u8], Command> {
        let (data, op) = complete::le_u16(data)?;
        let (data, param) = multi::length_data(complete::le_u8)(data)?;

        Ok((data, Command { op, param }))
    }
}

impl fmt::Display for Command<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "op 0x{:02x} param {:02x?}", self.op, self.param)
    }
}

//pub struct AclData <'a> {
//    handle: u16,
//    data: &'a[u8],
//}
