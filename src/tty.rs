use nom::{IResult, multi::length_data, sequence::tuple, number::{streaming, complete::{le_u8, le_u16, le_u32}}};
use crate::monitor;
use time::{Time, Duration};

#[derive(Debug)]
pub enum ExtHeader {
    CommandDrops(u8),
    EventDrops(u8),
    AclTxDrops(u8),
    AclRxDrops(u8),
    ScoTxDrops(u8),
    ScoRxDrops(u8),
    OtherDrops(u8),
    TimeStamp(u32),
    Unknown(u8),
}

fn parse_ext(data: &[u8]) -> IResult<&[u8], ExtHeader> {
    use ExtHeader::*;

    let (data, hdr) = le_u8(data)?;

    match hdr {
        1 => {
            let (data, drops) = le_u8(data)?;
            Ok((data, CommandDrops(drops)))
        },
        2 => {
            let (data, drops) = le_u8(data)?;
            Ok((data, EventDrops(drops)))
        },
        3 => {
            let (data, drops) = le_u8(data)?;
            Ok((data, AclTxDrops(drops)))
        },
        4 => {
            let (data, drops) = le_u8(data)?;
            Ok((data, AclRxDrops(drops)))
        },
        5 => {
            let (data, drops) = le_u8(data)?;
            Ok((data, ScoTxDrops(drops)))
        },
        6 => {
            let (data, drops) = le_u8(data)?;
            Ok((data, ScoRxDrops(drops)))
        },
        7 => {
            let (data, drops) = le_u8(data)?;
            Ok((data, OtherDrops(drops)))
        },
        8 => {
            let (data, ts) = le_u32(data)?;
            Ok((data, TimeStamp(ts)))
        },
        _ => Ok((data, Unknown(hdr))),
    }
}

pub fn parse_data(input: &[u8]) -> IResult<&[u8], monitor::Packet> {
    let (input, frame) = length_data(streaming::le_u16)(input)?;
    let (frame, (opcode, _flags, mut ext)) = tuple((le_u16, le_u8, length_data(le_u8)))(frame)?;
    let mut ts = Time::MIDNIGHT;

    while let Ok((rem, hdr)) = parse_ext(ext) {
        use ExtHeader::*;

        ext = rem;
        match hdr {
            CommandDrops(d) => println!("Commands dropped: {}", d),
            EventDrops(d) => println!("Commands dropps: {}", d),
            AclTxDrops(d) => println!("ACL TX dropps: {}", d),
            AclRxDrops(d) => println!("ACL RX dropps: {}", d),
            ScoTxDrops(d) => println!("SCO TX dropps: {}", d),
            ScoRxDrops(d) => println!("SCO RX dropps: {}", d),
            OtherDrops(d) => println!("Other dropps: {}", d),
            Unknown(h) => println!("Unknown ext header: {}", h),
            TimeStamp(t) => ts += Duration::microseconds(t as i64 * 100),
        }
    }

    let (_, pkt) = monitor::monitor_packet(ts, 0, opcode, frame)?;

    Ok((input, pkt))
}

#[cfg(test)]
mod tests {
    fn analyze_data(mut data: &[u8]) {
        use super::parse_data;

        loop {
            match parse_data(data) {
                Ok((remaining, pkt)) => {
                    data = remaining;
                    println!("{} {}", pkt.ts, pkt.op);
                },
                Err(e) => {
                    println!("{:?}", e);
                    break;
                },
            }
        }
    }

    #[test]
    fn peripheral_hr_xg24() {
        let data = include_bytes!("xg24_peripheral_hr.btsnoop");

        analyze_data(data);
    }

    #[test]
    fn peripheral_hr_siwx917() {
        let data = include_bytes!("siw917_peripheral_hr.btsnoop");

        analyze_data(data);
    }
}
