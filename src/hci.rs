use nom::{IResult, multi, number::complete::{le_u16, le_u8}, sequence::tuple};
use std::fmt;

#[derive(Debug, Eq, PartialEq)]
pub struct Event<'a> {
    code: u8,
    param: &'a [u8],
}

#[derive(Debug, Eq, PartialEq)]
pub struct LeMeta <'a> {
    sub: u8,
    param: &'a[u8],
}

fn le_sub_str(sub: u8) -> &'static str {
    match sub {
        0x01 => "LE Connection Complete",
        0x02 => "LE Advertising Report",
        0x03 => "LE Connection Update Complete",
        0x04 => "LE Read Remote Features Page 0 Complete",
        0x05 => "LE Long Term Key Request",
        0x06 => "LE Remote Connection Parameter Request",
        0x07 => "LE Data Length Change",
        0x08 => "LE Read Local P-256 Public Key Complete",
        0x09 => "LE Generate DHKey Complete",
        0x0a => "LE Enhanced Connection Complete [v1]",
        0x29 => "LE Enhanced Connection Complete [v2]",
        0x0b => "LE Directed Advertising Report",
        0x0c => "LE PHY Update Complete",
        0x0d => "LE Extended Advertising Report",
        0x0e => "LE Periodic Advertising Sync Established [v1]",
        0x24 => "LE Periodic Advertising Sync Established [v2]",
        0x0f => "LE Periodic Advertising Report [v1]",
        0x25 => "LE Periodic Advertising Report [v2]",
        0x10 => "LE Periodic Advertising Sync Lost",
        0x11 => "LE Scan Timeout",
        0x12 => "LE Advertising Set Terminated",
        0x13 => "LE Scan Request Received",
        0x14 => "LE Channel Selection Algorithm",
        0x15 => "LE Connectionless IQ Repor",
        0x16 => "LE Connection IQ Report",
        0x17 => "LE CTE Request Failed",
        0x18 => "LE Periodic Advertising Sync Transfer Receive [v1]",
        0x26 => "LE Periodic Advertising Sync Transfer Receive [v2]",
        0x19 => "LE CIS Established [v1]",
        0x2a => "LE CIS Established [v2]",
        0x1a => "LE CIS Request",
        0x1b => "LE Create BIG Complete",
        0x1c => "LE Terminate BIG Complete",
        0x1d => "LE BIG Sync Established",
        0x1e => "LE BIG Sync Lost",
        0x1f => "LE Request Peer SCA Complete",
        0x20 => "LE Path Loss Threshold",
        0x21 => "LE Transmit Power Reporting",
        0x22 => "LE BIGInfo Advertising Report",
        0x23 => "LE Subrate Change",
        0x27 => "LE Periodic Advertising Subevent Data Request",
        0x28 => "LE Periodic Advertising Response Report",
        0x2b => "LE Read All Remote Features Complete",
        0x2c => "LE CS Read Remote Supported Capabilities Complete",
        0x2d => "LE CS Read Remote FAE Table Complete",
        0x2e => "LE CS Security Enable Complete",
        0x2f => "LE CS Config Complete",
        0x30 => "LE CS Procedure Enable Complet",
        0x31 => "LE CS Subevent Result",
        0x32 => "LE CS Subevent Result Continue",
        0x33 => "LE CS Test End Complete",
        0x34 => "LE Monitored Advertisers Report",
        0x35 => "LE Frame Space Update Complete",
        _    => "LE <Unknown>",
    }
}

fn disconnect_complete(param: &[u8]) -> IResult<&[u8], (u8, u16, u8)> {
    tuple((le_u8, le_u16, le_u8))(param)
}

fn command_complete(param: &[u8]) -> IResult<&[u8], (u8, u16)> {
    tuple((le_u8, le_u16))(param)
}

fn command_status(param: &[u8]) -> IResult<&[u8], (u8, u8, u16)> {
    tuple((le_u8, le_u8, le_u16))(param)
}

fn num_completed_pkts(param: &[u8]) -> IResult<&[u8], (u8, u16, u16)> {
    tuple((le_u8, le_u16, le_u16))(param)
}

fn le_meta(param: &[u8]) -> IResult<&[u8], u8> {
    le_u8(param)
}

impl fmt::Display for Event<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.code {
            0x05 => {
                match disconnect_complete(self.param) {
                    Ok((_, (status, handle, reason))) => {
                        write!(f, "Disconnect Complete: status 0x{:02x} handle 0x{:04x} reason 0x{:02x}",
                            status, handle, reason)
                    },
                    Err(e) => write!(f, "Disconnect Complete failed to parse: {:?}", e),
                }
            },
            0x0e => {
                match command_complete(self.param) {
                    Ok((rem, (ncmd, op))) => {
                        write!(f, "Command Complete: ncmd {} {} param {:02x?}", ncmd, Op::from(op), rem)
                    },
                    Err(e) => write!(f, "Command Complete failed to parse: {:?}", e),
                }
            },
            0x0f => {
                match command_status(self.param) {
                    Ok((_, (status, ncmd, op))) => {
                        write!(f, "Command Status: status 0x{:02x} ncmd {} {}", status, ncmd, Op::from(op))
                    },
                    Err(e) => write!(f, "Command Status failed to parse: {:?}", e),
                }
            },
            0x13 => {
                match num_completed_pkts(self.param) {
                    Ok((_, (_n_handles, handle, pkts))) => {
                        write!(f, "Number Of Completed Packets: handle 0x{:04x} pkts {}", handle, pkts)
                    },
                    Err(e) => write!(f, "Number Of Completed Packets failed to parse: {:?}", e),
                }
            },
            0x3e => {
                match le_meta(self.param) {
                    Ok((rem, sub)) => {
                        write!(f, "{} (0x{:02x}) param {:02x?}", le_sub_str(sub), sub, rem)
                    },
                    Err(e) => write!(f, "LE Meta failed to parse: {:?}", e),
                }
            },
            _ => {
                write!(f, "0x{:02x} (Unknown): {:02x?}", self.code, self.param)
            },
        }
    }
}

impl Event <'_> {
    pub fn parse(data: &'_[u8]) -> IResult<&[u8], Event> {
        let (data, code) = le_u8(data)?;
        let (data, param) = multi::length_data(le_u8)(data)?;

        Ok((data, Event { code, param }))
    }
}

#[repr(u8)]
enum Ogf {
    LinkControl = 0x01,
    LinkPolicy  = 0x02,
    Baseband    = 0x03,
    Info        = 0x04,
    Status      = 0x05,
    Testing     = 0x06,
    Le          = 0x08,
    // Vs = 0x3f,
}

// OpCode from OGF + OCF
macro_rules! op {
    ($ogf:expr, $ocf:expr) => (
        (($ocf) | (($ogf as u16) << 10))
    );
}

// OGF from OpCode
macro_rules! ogf {
    ($op:expr) => (
        (($op >> 10) & 0b111111)
    );
}

// OCF from OpCode
macro_rules! ocf {
    ($op:expr) => (
        ($op & 0b111111)
    );
}

use Ogf::*;

#[repr(u16)]
#[derive(Debug, PartialEq, Eq, num_enum::FromPrimitive)]
pub enum Op {
    // Link Control commands
    Inquiry                      = op!(LinkControl, 0x0001),
    InquiryCancel                = op!(LinkControl, 0x0002),
    PeriodicInquiryMode          = op!(LinkControl, 0x0003),
    ExitPeriodicInquiryMode      = op!(LinkControl, 0x0004),
    CreateConn                   = op!(LinkControl, 0x0005),
    Disconnect                   = op!(LinkControl, 0x0006),


    // Link Policy commands
    HoldMode                     = op!(LinkPolicy,  0x0001),

    // Controller & Baseband commands
    SetEvtMask                   = op!(Baseband,    0x0001),

    // Informational parameters
    ReadLocalVerInfo             = op!(Info,        0x0001),
    ReadLocalSupportedCommands   = op!(Info,        0x0002),
    ReadLocalSupportedFeatures   = op!(Info,        0x0003),
    ReadLocalExtendedFeatures    = op!(Info,        0x0004),
    ReadBufSize                  = op!(Info,        0x0005),
    ReadBdAddr                   = op!(Info,        0x0009),

    // Status parameters
    ReadFailedContactCounter     = op!(Status,      0x0001),

    // Testing commands
    ReadLoopbackMode             = op!(Testing,     0x0001),

    // LE Controller commands
    LeSetEvtMask                 = op!(Le,          0x0001),
    LeReadBufSizeV1              = op!(Le,          0x0002),
    LeReadBufSizeV2              = op!(Le,          0x0060),
    LeReadLocalFeaturesPage0     = op!(Le,          0x0003),
    LeSetRandomAddress           = op!(Le,          0x0005),
    LeSetAdvPAram                = op!(Le,          0x0006),
    LeReadAdvPhyChanTxPower      = op!(Le,          0x0007),
    LeSetAdvData                 = op!(Le,          0x0008),
    LeSetScanResponseData        = op!(Le,          0x0009),
    LeSetAdvEnable               = op!(Le,          0x000a),
    LeSetScanParam               = op!(Le,          0x000b),
    LeSetScanEnable              = op!(Le,          0x000c),
    LeCreateConn                 = op!(Le,          0x000d),
    LeCreateConnCancel           = op!(Le,          0x000e),
    LeReadFilterAcceptListSize   = op!(Le,          0x000f),
    LeClearFilterAcceptList      = op!(Le,          0x0010),
    LeAddDevToFilterAcceptList   = op!(Le,          0x0011),
    LeRemDevFromFilterAcceptList = op!(Le,          0x0012),
    LeConnUpdate                 = op!(Le,          0x0013),
    LeSetHostChanClass           = op!(Le,          0x0014),
    LeReadChanMAp                = op!(Le,          0x0015),
    LeReadRemFeatPage0           = op!(Le,          0x0016),
    LeEncrypt                    = op!(Le,          0x0017),
    LeRand                       = op!(Le,          0x0018),
    LeEnableEncrypt              = op!(Le,          0x0019),
    LeLtkReqReply                = op!(Le,          0x001a),
    LeLtkReqNegReply             = op!(Le,          0x001b),
    LeReadSupportedStates        = op!(Le,          0x001c),
    LeReceiverTestV1             = op!(Le,          0x001d),
    LeReceiverTestV2             = op!(Le,          0x0033),
    LeReceiverTestV3             = op!(Le,          0x004f),
    LeTransmitterTestV1          = op!(Le,          0x001e),
    LeTransmitterTestV2          = op!(Le,          0x0034),
    LeTransmitterTestV3          = op!(Le,          0x0050),
    LeTransmitterTestV4          = op!(Le,          0x007b),
    LeTestEnd                    = op!(Le,          0x001f),
    LeRemoteConnParamReqReply    = op!(Le,          0x0020),
    LeRemoteConnParamReqNegReply = op!(Le,          0x0021),
    LeSetDataLength              = op!(Le,          0x0022),
    LeReadSuggDefDataLength      = op!(Le,          0x0023),
    LeWriteSuggDefDataLength     = op!(Le,          0x0024),
    LeReadLocalP256PubKey        = op!(Le,          0x0025),
    LeGenerateDHKeyV1            = op!(Le,          0x0026),
    LeGenerateDHKeyV2            = op!(Le,          0x005e),
    LeAddDevToResolvList         = op!(Le,          0x0027),
    LeRemDevFromResolvList       = op!(Le,          0x0028),
    LeClearResolvList            = op!(Le,          0x0029),
    LeReadResolvListSize         = op!(Le,          0x002a),
    LeReadPeerResolvAddress      = op!(Le,          0x002b),
    LeReadLocalResolvAddress     = op!(Le,          0x002c),
    LeSetAddressResolutionEnable = op!(Le,          0x002d),
    LeSetResolvPrivAddrTimeout   = op!(Le,          0x002e),
    LeReadMaxDataLength          = op!(Le,          0x002f),

    #[num_enum(catch_all)]
    Unknown(u16),
}

impl fmt::Display for Op {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Op::*;

        match self {
            // Link Control commands
            Inquiry                      => write!(f, "Inquiry"),
            InquiryCancel                => write!(f, "Inquiry Cancel"),
            PeriodicInquiryMode          => write!(f, "Periodic Inquiry Mode"),
            ExitPeriodicInquiryMode      => write!(f, "Exit Periodic Inquiry Mode"),
            CreateConn                   => write!(f, "Create Connection"),
            Disconnect                   => write!(f, "Disconnect"),

            // Link Policy Commands
            HoldMode                     => write!(f, "Hold Mode"),

            // Controller & Baseband commands
            SetEvtMask                   => write!(f, "Set Event Mask"),

            // Informational parameters
            ReadLocalVerInfo             => write!(f, "Read Local Version Information"),
            ReadLocalSupportedCommands   => write!(f, "Read Local Supported Commands"),
            ReadLocalSupportedFeatures   => write!(f, "Read Local Supported Features"),
            ReadLocalExtendedFeatures    => write!(f, "Read Local Extended Features"),
            ReadBufSize                  => write!(f, "Read Buffer Size"),
            ReadBdAddr                   => write!(f, "Read BD_ADDR"),

            // Status parameters
            ReadFailedContactCounter     => write!(f, "Read Failed Contact Counter"),

            // Testing commands
            ReadLoopbackMode             => write!(f, "Read Loopback Mode"),

            // LE Controller commands
            LeSetEvtMask                 => write!(f, "LE Set Event Mask"),
            LeReadBufSizeV1              => write!(f, "LE Read Buffer Size [v1]"),
            LeReadBufSizeV2              => write!(f, "LE Read Buffer Size [v2]"),
            LeReadLocalFeaturesPage0     => write!(f, "LE Read Local Supported Features Page 0"),
            LeSetRandomAddress           => write!(f, "LE Set Random Address"),
            LeSetAdvPAram                => write!(f, "LE Set Advertising Parameters"),
            LeReadAdvPhyChanTxPower      => write!(f, "LE Read Advertising Physical Channel Tx Power"),
            LeSetAdvData                 => write!(f, "LE Set Advertising Data"),
            LeSetScanResponseData        => write!(f, "LE Set Scan Response Data"),
            LeSetAdvEnable               => write!(f, "LE Set Advertising Enable"),
            LeSetScanParam               => write!(f, "LE Set Scan Parameters"),
            LeSetScanEnable              => write!(f, "LE Set Scan Enable"),
            LeCreateConn                 => write!(f, "LE Create Connection"),
            LeCreateConnCancel           => write!(f, "LE Create Connection Cancel"),
            LeReadFilterAcceptListSize   => write!(f, "LE Read Filter Accept List Size"),
            LeClearFilterAcceptList      => write!(f, "LE Clear Filter Accept List"),
            LeAddDevToFilterAcceptList   => write!(f, "LE Add Device To Filter Accept List"),
            LeRemDevFromFilterAcceptList => write!(f, "LE Remove Device From Filter Accept List"),
            LeConnUpdate                 => write!(f, "LE Connection Update"),
            LeSetHostChanClass           => write!(f, "LE Set Host Channel Classification"),
            LeReadChanMAp                => write!(f, "LE Read Channel Map"),
            LeReadRemFeatPage0           => write!(f, "LE Read Remote Features Page 0"),
            LeEncrypt                    => write!(f, "LE Encrypt"),
            LeRand                       => write!(f, "LE Rand"),
            LeEnableEncrypt              => write!(f, "LE Enable Encryption"),
            LeLtkReqReply                => write!(f, "LE LTK Request Reply"),
            LeLtkReqNegReply             => write!(f, "LE LTK Request Negative Reply"),
            LeReadSupportedStates        => write!(f, "LE Read Supported States"),
            LeReceiverTestV1             => write!(f, "LE Receiver Test [v1]"),
            LeReceiverTestV2             => write!(f, "LE Receiver Test [v1]"),
            LeReceiverTestV3             => write!(f, "LE Receiver Test [v1]"),
            LeTransmitterTestV1          => write!(f, "LE Transmitter Test [v1]"),
            LeTransmitterTestV2          => write!(f, "LE Transmitter Test [v2]"),
            LeTransmitterTestV3          => write!(f, "LE Transmitter Test [v3]"),
            LeTransmitterTestV4          => write!(f, "LE Transmitter Test [v4]"),
            LeTestEnd                    => write!(f, "LE Test End"),
            LeRemoteConnParamReqReply    => write!(f, "LE Remote Connection Parameter Request Reply"),
            LeRemoteConnParamReqNegReply => write!(f, "LE Remote Connection Parameter Request Negative Reply"),
            LeSetDataLength              => write!(f, "LE Set Data Length"),
            LeReadSuggDefDataLength      => write!(f, "LE Read Suggested Default Data Length"),
            LeWriteSuggDefDataLength     => write!(f, "LE Write Suggested Default Data Length"),
            LeReadLocalP256PubKey        => write!(f, "LE Read Local P-256 Public Key"),
            LeGenerateDHKeyV1            => write!(f, "LE Generate DHKey [v1]"),
            LeGenerateDHKeyV2            => write!(f, "LE Generate DHKey [v2]"),
            LeAddDevToResolvList         => write!(f, "LE Add Device To Resolving List"),
            LeRemDevFromResolvList       => write!(f, "LE Remove Device From Resolving List"),
            LeClearResolvList            => write!(f, "LE Clear Resolving List"),
            LeReadResolvListSize         => write!(f, "LE Read Resolving List Size"),
            LeReadPeerResolvAddress      => write!(f, "LE Read Peer Resolvable Address"),
            LeReadLocalResolvAddress     => write!(f, "LE Read Local Resolvable Address"),
            LeSetAddressResolutionEnable => write!(f, "LE Set Address Resolution Enable"),
            LeSetResolvPrivAddrTimeout   => write!(f, "LE Set Resolvable Private Address Timeout"),
            LeReadMaxDataLength          => write!(f, "LE Read Maximum Data Length"),

            Unknown(op) => {
                write!(f, "Unknown OGF 0x{:02x} OCF 0x{:04x} (0x{:02x})", ogf!(op), ocf!(op), op)
            },
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct Command <'a> {
    op: Op,
    param: &'a[u8],
}

impl Command <'_> {
    pub fn parse(data: &'_[u8]) -> IResult<&[u8], Command> {
        let (data, (op_raw, param)) = tuple((le_u16, multi::length_data(le_u8)))(data)?;
        Ok((data, Command { op: Op::from(op_raw), param }))
    }
}

impl fmt::Display for Command<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {:02x?}", self.op, self.param)
    }
}

//pub struct AclData <'a> {
//    handle: u16,
//    data: &'a[u8],
//}
