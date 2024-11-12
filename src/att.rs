use nom::{IResult, bytes::complete::take, number::complete::le_u8};
use num_enum::FromPrimitive;
use std::fmt;

#[repr(u8)]
#[derive(Debug, PartialEq, Eq, FromPrimitive)]
enum OpCode {
    ErrorRsp                = 0x01,
    ExchangeMtuReq          = 0x02,
    ExchangeMtuRsp          = 0x03,
    FindInformationReq      = 0x04,
    FindInformationRsp      = 0x05,
    FindByTypeValueReq      = 0x06,
    FindByTypeValueRsp      = 0x07,
    ReadByTypeReq           = 0x08,
    ReadByTypeRsp           = 0x09,
    ReadReq                 = 0x0a,
    ReadRsp                 = 0x0b,
    ReadBlobReq             = 0x0c,
    ReadBlobRsp             = 0x0d,
    ReadMultipleReq         = 0x0e,
    ReadMultipleRsp         = 0x0f,
    ReadByGroupTypeReq      = 0x10,
    ReadByGroupTypeRsp      = 0x11,
    WriteReq                = 0x12,
    WriteRsp                = 0x13,
    WriteCmd                = 0x52,
    PrepareWriteReq         = 0x16,
    PrepareWriteRsp         = 0x17,
    ExecuteWriteReq         = 0x18,
    ExecuteWriteRsp         = 0x19,
    ReadMultipleVariableReq = 0x20,
    ReadMultipleVariableRsp = 0x21,
    ReadMultipleVariableNtf = 0x23,
    HandleValueNtf          = 0x1b,
    HandleValueInd          = 0x1d,
    HandleValueCfm          = 0x1e,
    SignedWriteCmd          = 0xd2,

    #[num_enum(catch_all)]
    Other(u8),
}

pub struct Pdu <'a> {
    opcode: OpCode,
    param: &'a[u8],
}

impl Pdu <'_> {
    pub fn parse(input: &'_[u8]) -> IResult<&[u8], Pdu> {
        let (param, opcode) = le_u8(input)?;
        let (rem, param) = take(param.len())(param)?;

        Ok((rem, Pdu { opcode: OpCode::from(opcode), param }))
    }
}

impl fmt::Display for Pdu<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:?} {:02x?}", self.opcode, self.param)
    }
}
