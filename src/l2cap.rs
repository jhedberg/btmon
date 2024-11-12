use nom::{IResult, bytes::complete::take, sequence::tuple, number::complete::{le_u16, le_u8}};
use num_enum::FromPrimitive;
use std::fmt;
use crate::att;

#[repr(u16)]
#[derive(Debug, PartialEq, Eq, FromPrimitive)]
enum Cid {
    Null      = 0x0000,
    Sig       = 0x0001,
    Connless  = 0x0002,
    Att       = 0x0004,
    LeSig     = 0x0005,
    Smp       = 0x0006,
    BrSmp     = 0x0007,

    #[num_enum(catch_all)]
    Other(u16),
}

impl fmt::Display for Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Cid::*;
        match self {
            Null     => write!(f, "Null (Not allowed))"),
            Sig      => write!(f, "L2CAP Signaling"),
            Connless => write!(f, "Connectionless"),
            Att      => write!(f, "ATT"),
            LeSig    => write!(f, "LE Signaling"),
            Smp      => write!(f, "SMP"),
            BrSmp    => write!(f, "BR/EDR SMP"),
            Other(c) => write!(f, "CID 0x{:04}", c),
        }
    }
}

pub struct Frame <'a> {
    cid: Cid,
    data: &'a[u8],
}

impl Frame <'_> {
    pub fn parse(input: &'_[u8]) -> IResult<&[u8], Frame> {
        let (rem, (len, cid)) = tuple((le_u16, le_u16))(input)?;
        let (rem, data) = take(len)(rem)?;

        Ok((rem, Frame { cid: Cid::from(cid), data }))
    }
}

impl fmt::Display for Frame<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use Cid::*;

        match self.cid {
            Att => {
                match att::Pdu::parse(self.data) {
                    Ok((_, pdu)) => write!(f, "ATT: {}", pdu),
                    Err(_) => write!(f, "{}: {:02x?}", self.cid, self.data),
                }
            },
            _ => write!(f, "{}: {:02x?}", self.cid, self.data),
        }
    }
}
