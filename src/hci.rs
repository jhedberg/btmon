use nom::{IResult, multi, number::complete};
use std::fmt;

#[derive(Debug, Eq, PartialEq)]
pub struct Event <'a> {
    evt: u8,
    param: &'a[u8],
}

#[derive(Debug, Eq, PartialEq)]
pub struct Command <'a> {
    op: u16,
    param: &'a[u8],
}

//pub struct AclData <'a> {
//    handle: u16,
//    data: &'a[u8],
//}

impl Event <'_> {
    pub fn parse(data: &'_[u8]) -> IResult<&[u8], Event> {
        let (data, evt) = complete::le_u8(data)?;
        let (data, param) = multi::length_data(complete::le_u8)(data)?;

        Ok((data, Event { evt, param }))
    }
}

impl fmt::Display for Event<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "evt 0x{:02x} param {:02?}", self.evt, self.param)
    }
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
