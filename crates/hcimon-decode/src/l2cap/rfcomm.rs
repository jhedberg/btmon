//! RFCOMM frames (PSM 0x0003): TS 07.10 framing with the Bluetooth adaptations.
//!
//! A frame is address, control, length (one or two octets), an optional
//! credits octet (UIH frames with the P/F bit set on a data DLCI), payload
//! and a one-octet FCS.  Frames on DLCI 0 carry multiplexer control
//! commands, which are decoded; the payload of data DLCIs is dumped as hex.

use crate::field;
use crate::reader::{Reader, Result};
use crate::tree::Out;

const UIH: u8 = 0xef;

pub fn frame_name(ctype: u8) -> Option<&'static str> {
    Some(match ctype {
        0x2f => "Set Async Balance Mode (SABM)",
        0x63 => "Unnumbered Ack (UA)",
        0x0f => "Disconnect Mode (DM)",
        0x43 => "Disconnect (DISC)",
        UIH => "Unnumbered Info with Header Check (UIH)",
        _ => return None,
    })
}

const MCC_TEST: u8 = 0x08;
const MCC_FCON: u8 = 0x28;
const MCC_FCOFF: u8 = 0x18;
const MCC_MSC: u8 = 0x38;
const MCC_RPN: u8 = 0x24;
const MCC_RLS: u8 = 0x14;
const MCC_PN: u8 = 0x20;
const MCC_NSC: u8 = 0x04;

pub fn mcc_name(t: u8) -> Option<&'static str> {
    Some(match t {
        MCC_TEST => "Test Command",
        MCC_FCON => "Flow Control On Command",
        MCC_FCOFF => "Flow Control Off Command",
        MCC_MSC => "Modem Status Command",
        MCC_RPN => "Remote Port Negotiation Command",
        MCC_RLS => "Remote Line Status",
        MCC_PN => "DLC Parameter Negotiation",
        MCC_NSC => "Non Supported Command",
        _ => return None,
    })
}

/// A length field: 7 bits with the EA bit set, otherwise 15 bits over two octets.
fn ea_length(r: &mut Reader<'_>) -> Result<u16> {
    let l1 = r.u8()?;
    if l1 & 0x01 != 0 {
        Ok((l1 >> 1) as u16)
    } else {
        let l2 = r.u8()?;
        Ok(((l1 >> 1) as u16) | ((l2 as u16) << 7))
    }
}

/// Decode one RFCOMM frame.
pub fn decode(payload: &[u8], out: &mut Out) {
    let mut r = Reader::new(payload);
    let (Ok(addr), Ok(ctrl), Ok(len)) = (r.u8(), r.u8(), ea_length(&mut r)) else {
        out.error("RFCOMM: frame too short");
        out.hex(payload);
        return;
    };
    let Some((&fcs, body)) = r.rest().split_last() else {
        out.error("RFCOMM: missing FCS");
        out.hex(payload);
        return;
    };
    let ctype = ctrl & 0xef;
    let pf = (ctrl >> 4) & 0x01;
    let dlci = addr >> 2;
    let cr = (addr >> 1) & 0x01;
    match frame_name(ctype) {
        Some(n) => field!(out, "RFCOMM: {} (0x{:02x})", n, ctype),
        None => out.unknown(format!("RFCOMM: Unknown (0x{ctype:02x})")),
    };
    out.nest(|o| {
        field!(o, "Address: 0x{:02x} cr {} dlci 0x{:02x}", addr, cr, dlci);
        field!(o, "Control: 0x{:02x} poll/final {}", ctrl, pf);
        field!(o, "Length: {}", len);
        field!(o, "FCS: 0x{:02x}", fcs);
        let mut b = Reader::new(body);
        let mut expected = len as usize;
        if ctype == UIH && dlci != 0 && pf == 1 {
            // Credit based flow control: the credits octet precedes the payload.
            if let Ok(c) = b.u8() {
                field!(o, "Credits: {}", c);
                expected += 1;
            }
        }
        if body.len() != expected {
            o.error(format!("Length mismatch: header says {len}, {} present", b.remaining()));
        }
        if ctype == UIH && dlci == 0 {
            let res = mcc(&mut b, o);
            if let Err(e) = res {
                o.error(format!("Multiplexer command {e}"));
            }
        }
        let rest = b.rest();
        if !rest.is_empty() {
            o.hex(rest);
        }
    });
}

/// Multiplexer control command on DLCI 0: type, length, parameters.
fn mcc(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let t = r.u8()?;
    let len = ea_length(r)?;
    let typ = t >> 2;
    let cr = if (t >> 1) & 0x01 != 0 { "CMD" } else { "RSP" };
    match mcc_name(typ) {
        Some(n) => field!(out, "MCC Message type: {} {} (0x{:02x})", n, cr, typ),
        None => out.unknown(format!("MCC Message type: Unknown {cr} (0x{typ:02x})")),
    };
    let data = r.bytes(len as usize)?;
    out.nest(|o| {
        field!(o, "Length: {}", len);
        let mut d = Reader::new(data);
        let res = match typ {
            MCC_PN => pn(&mut d, o),
            MCC_MSC => msc(&mut d, o),
            MCC_RPN => rpn(&mut d, o),
            MCC_RLS => rls(&mut d, o),
            MCC_NSC => nsc(&mut d, o),
            MCC_TEST => {
                o.hex_field("Test data", d.rest());
                Ok(())
            }
            MCC_FCON | MCC_FCOFF => Ok(()),
            _ => {
                if !d.is_empty() {
                    o.hex(d.rest());
                }
                Ok(())
            }
        };
        match res {
            Err(e) => {
                o.error(format!("Parameters {e}"));
                o.hex(d.rest());
            }
            Ok(()) if !d.is_empty() => {
                o.error("Unexpected trailing data");
                o.hex(d.rest());
            }
            Ok(()) => {}
        }
    });
    Ok(())
}

fn dlci_field(r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    let v = r.u8()? >> 2;
    field!(out, "DLCI: {}", v);
    Ok(v)
}

/// DLC parameter negotiation.
fn pn(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let d = r.u8()? & 0x3f;
    field!(out, "DLCI: {}", d);
    let b = r.u8()?;
    let ft = b & 0x0f;
    match ft {
        0x00 => field!(out, "Frame type: UIH (0x00)"),
        0x01 => field!(out, "Frame type: UI (0x01)"),
        0x02 => field!(out, "Frame type: I (0x02)"),
        _ => out.unknown(format!("Frame type: Reserved (0x{ft:02x})")),
    };
    let cl = b >> 4;
    match cl {
        0x00 => field!(out, "Convergence layer: Type 1 (0x00)"),
        0x0f => field!(out, "Convergence layer: Credit based flow control (0x0f)"),
        0x0e => field!(out, "Convergence layer: Credit based flow control accepted (0x0e)"),
        _ => out.unknown(format!("Convergence layer: Reserved (0x{cl:02x})")),
    };
    field!(out, "Priority: {}", r.u8()? & 0x3f);
    field!(out, "ACK timer: {}", r.u8()?);
    field!(out, "Max frame size: {}", r.u16()?);
    field!(out, "Max retransmissions: {}", r.u8()?);
    field!(out, "Credits: {}", r.u8()? & 0x07);
    Ok(())
}

/// Modem status: V.24 signals and an optional break signal.
fn msc(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    dlci_field(r, out)?;
    let s = r.u8()?;
    field!(
        out,
        "V.24 signals: fc {} rtc {} rtr {} ic {} dv {} (0x{:02x})",
        (s >> 1) & 1,
        (s >> 2) & 1,
        (s >> 3) & 1,
        (s >> 6) & 1,
        (s >> 7) & 1,
        s
    );
    if !r.is_empty() {
        let b = r.u8()?;
        field!(out, "Break signal: {} length {} (0x{:02x})", (b >> 1) & 1, b >> 4, b);
    }
    Ok(())
}

/// Remote port negotiation: DLCI plus optional port settings.
fn rpn(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    dlci_field(r, out)?;
    if r.is_empty() {
        return Ok(());
    }
    let baud = r.u8()?;
    let rate = match baud {
        0x00 => Some(2400),
        0x01 => Some(4800),
        0x02 => Some(7200),
        0x03 => Some(9600),
        0x04 => Some(19200),
        0x05 => Some(38400),
        0x06 => Some(57600),
        0x07 => Some(115200),
        0x08 => Some(230400),
        _ => None,
    };
    match rate {
        Some(bps) => field!(out, "Baud rate: {} bps (0x{:02x})", bps, baud),
        None => out.unknown(format!("Baud rate: Reserved (0x{baud:02x})")),
    };
    let f = r.u8()?;
    field!(out, "Data bits: {} (0x{:02x})", 5 + (f & 0x03), f & 0x03);
    field!(out, "Stop bits: {}", if f & 0x04 != 0 { "1.5" } else { "1" });
    let parity_type = match (f >> 4) & 0x03 {
        0 => "odd",
        1 => "even",
        2 => "mark",
        _ => "space",
    };
    if f & 0x08 != 0 {
        field!(out, "Parity: {} (0x{:02x})", parity_type, (f >> 4) & 0x03);
    } else {
        field!(out, "Parity: none");
    }
    let fc = r.u8()?;
    field!(out, "Flow control: 0x{:02x}", fc);
    out.nest(|o| {
        for (bit, name) in [
            (0, "XON/XOFF on input"),
            (1, "XON/XOFF on output"),
            (2, "RTR on input"),
            (3, "RTR on output"),
            (4, "RTC on input"),
            (5, "RTC on output"),
        ] {
            if fc & (1 << bit) != 0 {
                o.line(name);
            }
        }
    });
    field!(out, "XON character: 0x{:02x}", r.u8()?);
    field!(out, "XOFF character: 0x{:02x}", r.u8()?);
    field!(out, "Parameter mask: 0x{:04x}", r.u16()?);
    Ok(())
}

/// Remote line status.
fn rls(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    dlci_field(r, out)?;
    let e = r.u8()?;
    if e & 0x01 == 0 {
        field!(out, "Line status: No error (0x{:02x})", e);
    } else {
        let what = match (e >> 1) & 0x07 {
            0x01 => "Overrun error",
            0x02 => "Parity error",
            0x04 => "Framing error",
            _ => "Unknown error",
        };
        field!(out, "Line status: {} (0x{:02x})", what, e);
    }
    Ok(())
}

/// Non supported command response: the command type that was not understood.
fn nsc(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    let t = r.u8()?;
    let typ = t >> 2;
    let cr = if (t >> 1) & 0x01 != 0 { "CMD" } else { "RSP" };
    match mcc_name(typ) {
        Some(n) => field!(out, "Command type: {} {} (0x{:02x})", n, cr, typ),
        None => out.unknown(format!("Command type: Unknown {cr} (0x{typ:02x})")),
    };
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l2cap::test_lines;

    fn run(payload: &[u8]) -> Vec<String> {
        let mut out = Out::new();
        decode(payload, &mut out);
        test_lines(&out)
    }

    #[test]
    fn sabm_on_dlci_0() {
        assert_eq!(
            run(&[0x03, 0x3f, 0x01, 0x1c]),
            [
                "RFCOMM: Set Async Balance Mode (SABM) (0x2f)",
                "  Address: 0x03 cr 1 dlci 0x00",
                "  Control: 0x3f poll/final 1",
                "  Length: 0",
                "  FCS: 0x1c",
            ]
        );
    }

    #[test]
    fn parameter_negotiation() {
        assert_eq!(
            run(&[0x03, 0xef, 0x15, 0x83, 0x11, 0x02, 0xf0, 0x07, 0x00, 0x9b, 0x02, 0x00, 0x07, 0x70]),
            [
                "RFCOMM: Unnumbered Info with Header Check (UIH) (0xef)",
                "  Address: 0x03 cr 1 dlci 0x00",
                "  Control: 0xef poll/final 0",
                "  Length: 10",
                "  FCS: 0x70",
                "  MCC Message type: DLC Parameter Negotiation CMD (0x20)",
                "    Length: 8",
                "    DLCI: 2",
                "    Frame type: UIH (0x00)",
                "    Convergence layer: Credit based flow control (0x0f)",
                "    Priority: 7",
                "    ACK timer: 0",
                "    Max frame size: 667",
                "    Max retransmissions: 0",
                "    Credits: 7",
            ]
        );
    }

    #[test]
    fn modem_status_with_break() {
        let l = run(&[0x03, 0xef, 0x0b, 0xe1, 0x07, 0x0b, 0x8d, 0x13, 0x00]);
        assert_eq!(l[5], "  MCC Message type: Modem Status Command RSP (0x38)");
        assert_eq!(l[6], "    Length: 3");
        assert_eq!(l[7], "    DLCI: 2");
        assert_eq!(l[8], "    V.24 signals: fc 0 rtc 1 rtr 1 ic 0 dv 1 (0x8d)");
        assert_eq!(l[9], "    Break signal: 1 length 1 (0x13)");
    }

    #[test]
    fn data_frame_with_credits() {
        let l = run(&[0x0b, 0xff, 0x07, 0x05, 0x61, 0x62, 0x63, 0x9a]);
        assert_eq!(l[1], "  Address: 0x0b cr 1 dlci 0x02");
        assert_eq!(l[2], "  Control: 0xff poll/final 1");
        assert_eq!(l[3], "  Length: 3");
        assert_eq!(l[5], "  Credits: 5");
        assert!(l[6].starts_with("  61 62 63"));
        assert_eq!(l.len(), 7);
    }

    #[test]
    fn two_octet_length() {
        // Length 200 (EA clear): 0x90 0x03 → (0x90 >> 1) | (3 << 7) = 72 + 384... use 200 = 0b11001000:
        // low 7 bits 0x48 → 0x90, high bits 1 → 0x01.
        let mut f = vec![0x0b, 0xef, 0x90, 0x01];
        f.extend(std::iter::repeat_n(0x00, 200));
        f.push(0x00);
        let l = run(&f);
        assert_eq!(l[3], "  Length: 200");
        assert!(!l.iter().any(|s| s.contains("mismatch")));
    }

    #[test]
    fn remote_port_negotiation_and_line_status() {
        let l = run(&[0x03, 0xef, 0x15, 0x93, 0x11, 0x0b, 0x07, 0x03, 0x00, 0x11, 0x13, 0x00, 0x00, 0xaa]);
        assert_eq!(l[5], "  MCC Message type: Remote Port Negotiation Command CMD (0x24)");
        assert_eq!(l[7..], [
            "    DLCI: 2",
            "    Baud rate: 115200 bps (0x07)",
            "    Data bits: 8 (0x03)",
            "    Stop bits: 1",
            "    Parity: none",
            "    Flow control: 0x00",
            "    XON character: 0x11",
            "    XOFF character: 0x13",
            "    Parameter mask: 0x0000",
        ]);
        let l = run(&[0x03, 0xef, 0x09, 0x53, 0x05, 0x0b, 0x03, 0xaa]);
        assert_eq!(l[5], "  MCC Message type: Remote Line Status CMD (0x14)");
        assert_eq!(l[8], "    Line status: Overrun error (0x03)");
    }

    #[test]
    fn non_supported_command() {
        let l = run(&[0x03, 0xef, 0x07, 0x11, 0x03, 0x93, 0xaa]);
        assert_eq!(l[5], "  MCC Message type: Non Supported Command RSP (0x04)");
        assert_eq!(l[7], "    Command type: Remote Port Negotiation Command CMD (0x24)");
    }

    #[test]
    fn short_frames() {
        assert_eq!(run(&[0x03, 0x3f])[0], "RFCOMM: frame too short");
        assert_eq!(run(&[0x03, 0x3f, 0x01])[0], "RFCOMM: missing FCS");
        let l = run(&[0x03, 0xef, 0x05, 0x83, 0x11, 0x02, 0x70]);
        assert!(l.iter().any(|s| s.contains("Length mismatch")), "{l:?}");
        assert!(l.iter().any(|s| s.starts_with("  Multiplexer command truncated")), "{l:?}");
    }
}
