//! L2CAP: basic frames, fixed channels, dynamic channel framing and dispatch by PSM.
//!
//! * [`signaling`] decodes the signaling channels (CID 0x0001 / 0x0005) and
//!   keeps the per-connection channel table in [`crate::context::L2capState`]
//!   current.
//! * Dynamic channels are framed according to the mode recorded for them:
//!   control field, SAR reassembly and FCS for the retransmission / streaming
//!   modes, SDU length and reassembly for the credit based modes.
//! * The payload is then handed to the protocol identified by the channel's
//!   PSM: [`sdp`], [`rfcomm`], ATT (also for EATT), or dumped as hex.

pub mod rfcomm;
pub mod sdp;
pub mod signaling;

use crate::assigned::psm_name;
use crate::att;
use crate::context::{IndexState, L2capChannel, L2capMode, Reassembly};
use crate::field;
use crate::reader::Reader;
use crate::smp;
use crate::tree::{Out, Style};
use crate::Layer;

pub const CID_SIGNALING: u16 = 0x0001;
pub const CID_CONNECTIONLESS: u16 = 0x0002;
pub const CID_AMP_MANAGER: u16 = 0x0003;
pub const CID_ATT: u16 = 0x0004;
pub const CID_LE_SIGNALING: u16 = 0x0005;
pub const CID_SMP: u16 = 0x0006;
pub const CID_BREDR_SMP: u16 = 0x0007;
pub const CID_AMP_TEST: u16 = 0x003f;

/// PSMs whose payload is decoded further.
pub const PSM_SDP: u16 = 0x0001;
pub const PSM_RFCOMM: u16 = 0x0003;
pub const PSM_AVCTP: u16 = 0x0017;
pub const PSM_AVDTP: u16 = 0x0019;
pub const PSM_AVCTP_BROWSING: u16 = 0x001b;
pub const PSM_ATT: u16 = 0x001f;
pub const PSM_EATT: u16 = 0x0027;

pub fn fixed_cid_name(cid: u16) -> Option<&'static str> {
    Some(match cid {
        0x0000 => "Null",
        CID_SIGNALING => "L2CAP Signaling",
        CID_CONNECTIONLESS => "Connectionless",
        CID_AMP_MANAGER => "AMP Manager",
        CID_ATT => "ATT",
        CID_LE_SIGNALING => "LE Signaling",
        CID_SMP => "SMP",
        CID_BREDR_SMP => "BR/EDR SMP",
        CID_AMP_TEST => "AMP Test Manager",
        _ => return None,
    })
}

/// Name of a channel mode as btmon prints it.
pub fn mode_name(mode: L2capMode) -> &'static str {
    match mode {
        L2capMode::Basic => "Basic",
        L2capMode::Retransmission => "Retransmission",
        L2capMode::FlowControl => "Flow Control",
        L2capMode::EnhancedRetransmission => "Enhanced Retransmission",
        L2capMode::Streaming => "Streaming",
        L2capMode::LeCreditBased => "LE Flow Control",
        L2capMode::EnhancedCreditBased => "Enhanced Credit",
    }
}

/// Numeric mode as printed in channel headlines: the values of the
/// Retransmission and Flow Control option, plus 0x80 / 0x81 for the credit
/// based modes (which have no option value; btmon uses the same numbers).
pub fn mode_code(mode: L2capMode) -> u8 {
    match mode {
        L2capMode::Basic => 0x00,
        L2capMode::Retransmission => 0x01,
        L2capMode::FlowControl => 0x02,
        L2capMode::EnhancedRetransmission => 0x03,
        L2capMode::Streaming => 0x04,
        L2capMode::LeCreditBased => 0x80,
        L2capMode::EnhancedCreditBased => 0x81,
    }
}

/// Mode from the value of the Retransmission and Flow Control configuration option.
pub fn mode_from_option(v: u8) -> Option<L2capMode> {
    Some(match v {
        0x00 => L2capMode::Basic,
        0x01 => L2capMode::Retransmission,
        0x02 => L2capMode::FlowControl,
        0x03 => L2capMode::EnhancedRetransmission,
        0x04 => L2capMode::Streaming,
        _ => return None,
    })
}

/// The 16-bit FCS of the retransmission / flow control / streaming modes
/// (Vol 3, Part A, Section 3.3.5): generator D^16 + D^15 + D^2 + 1, initial
/// value 0, LSB first.  It covers the basic header, control field and payload.
pub fn fcs16(data: &[u8]) -> u16 {
    let mut crc: u16 = 0;
    for &b in data {
        crc ^= b as u16;
        for _ in 0..8 {
            crc = if crc & 1 != 0 { (crc >> 1) ^ 0xa001 } else { crc >> 1 };
        }
    }
    crc
}

/// Whether frames on the channel end with an FCS.  It is mandatory in
/// Retransmission and Flow Control modes and, for Enhanced Retransmission and
/// Streaming modes, omitted only if both sides asked for "No FCS".
pub fn has_fcs(ch: &L2capChannel) -> bool {
    match ch.mode {
        L2capMode::Retransmission | L2capMode::FlowControl => true,
        L2capMode::EnhancedRetransmission | L2capMode::Streaming => !(ch.no_fcs[0] && ch.no_fcs[1]),
        _ => false,
    }
}

/// Decode a complete L2CAP PDU (basic header + payload) received on `handle`.
///
/// `layers` receives the protocol layers found in the payload.
pub fn decode_pdu(st: &mut IndexState, handle: u16, rx: bool, pdu: &[u8], out: &mut Out, layers: &mut Vec<Layer>) {
    layers.push(Layer::L2cap);
    let mut r = Reader::new(pdu);
    let (Ok(len), Ok(cid)) = (r.u16(), r.u16()) else {
        out.styled(Style::Error, "L2CAP header truncated");
        out.hex(pdu);
        return;
    };
    if len as usize != r.remaining() {
        out.error(format!("L2CAP length mismatch: header says {len}, {} present", r.remaining()));
    }
    let payload = r.rest();
    match cid {
        CID_SIGNALING | CID_LE_SIGNALING => {
            signaling::decode(st, handle, rx, cid == CID_LE_SIGNALING, payload, out);
        }
        CID_CONNECTIONLESS => connectionless(st, handle, rx, payload, out, layers),
        CID_ATT => {
            layers.push(Layer::Att);
            let frame = st.frames;
            att::decode(st, handle, rx, payload, out, frame);
        }
        CID_SMP | CID_BREDR_SMP => {
            layers.push(Layer::Smp);
            smp::decode(st, handle, cid == CID_BREDR_SMP, payload, out);
        }
        0x0000 | CID_AMP_MANAGER | CID_AMP_TEST => {
            field!(out, "Channel: {} len {} [{}]", cid, payload.len(), fixed_cid_name(cid).unwrap_or("Unknown"));
            out.nest(|o| {
                o.hex(payload);
            });
        }
        _ => dynamic(st, handle, rx, cid, pdu, payload, out, layers),
    }
}

/// Connectionless data (CID 0x0002): a PSM followed by the payload.
fn connectionless(st: &mut IndexState, handle: u16, rx: bool, payload: &[u8], out: &mut Out, layers: &mut Vec<Layer>) {
    let mut r = Reader::new(payload);
    let Ok(psm) = r.u16() else {
        out.error("L2CAP: Connectionless PSM truncated");
        out.hex(payload);
        return;
    };
    let data = r.rest();
    field!(out, "L2CAP: Connectionless len {} [PSM {}]", data.len(), psm);
    dispatch_psm(st, handle, rx, psm, data, out, layers);
}

/// What the framing code needs to know about a channel, copied out of the
/// state so that the state can be borrowed again for reassembly.
struct Chan {
    cid: u16,
    psm: u16,
    mode: L2capMode,
    ext_ctrl: bool,
    fcs: bool,
    /// `[PSM 3 mode Basic (0x00)]`
    tag: String,
}

/// Data on a dynamically allocated (or unknown) CID.
#[allow(clippy::too_many_arguments)]
fn dynamic(st: &mut IndexState, handle: u16, rx: bool, cid: u16, pdu: &[u8], payload: &[u8], out: &mut Out, layers: &mut Vec<Layer>) {
    let len = payload.len();
    let Some(ch) = st.conn(handle).and_then(|c| c.l2cap.channel(cid)) else {
        out.unknown(format!("Channel: {cid} len {len} [Unknown]"));
        out.nest(|o| {
            o.hex(payload);
        });
        return;
    };
    let ch = Chan {
        cid,
        psm: ch.psm,
        mode: ch.mode,
        ext_ctrl: ch.ext_ctrl,
        fcs: has_fcs(ch),
        tag: format!("[PSM {} mode {} (0x{:02x})]", ch.psm, mode_name(ch.mode), mode_code(ch.mode)),
    };
    match ch.mode {
        L2capMode::Basic => {
            field!(out, "Channel: {} len {} {}", cid, len, ch.tag);
            dispatch_psm(st, handle, rx, ch.psm, payload, out, layers);
        }
        L2capMode::LeCreditBased | L2capMode::EnhancedCreditBased => credit_based(st, handle, rx, &ch, payload, out, layers),
        _ => framed(st, handle, rx, &ch, pdu, payload, out, layers),
    }
}

fn take_sdu(st: &mut IndexState, handle: u16, cid: u16, dir: usize) -> Option<Reassembly> {
    st.conn_mut(handle)?.l2cap.channels.get_mut(&cid)?.sdu[dir].take()
}

fn store_sdu(st: &mut IndexState, handle: u16, cid: u16, dir: usize, re: Reassembly) {
    if let Some(ch) = st.conn_mut(handle).and_then(|c| c.l2cap.channels.get_mut(&cid)) {
        ch.sdu[dir] = Some(re);
    }
}

fn incomplete_sdu(out: &mut Out, have: usize, expected: usize, data: &[u8]) {
    out.nest(|o| {
        o.line(format!("Incomplete SDU: {have} of {expected} bytes"));
        o.hex(data);
    });
}

/// LE Credit Based / Enhanced Credit Based channels: the first PDU of an SDU
/// starts with the SDU length; further PDUs continue it.
fn credit_based(st: &mut IndexState, handle: u16, rx: bool, ch: &Chan, payload: &[u8], out: &mut Out, layers: &mut Vec<Layer>) {
    let dir = rx as usize;
    let len = payload.len();
    match take_sdu(st, handle, ch.cid, dir) {
        None => {
            let mut r = Reader::new(payload);
            let Ok(sdu_len) = r.u16() else {
                field!(out, "Channel: {} len {} {}", ch.cid, len, ch.tag);
                out.nest(|o| {
                    o.error("SDU length truncated");
                    o.hex(payload);
                });
                return;
            };
            field!(out, "Channel: {} len {} sdu {} {}", ch.cid, len, sdu_len, ch.tag);
            let data = r.rest();
            let expected = sdu_len as usize;
            if data.len() >= expected {
                if data.len() > expected {
                    out.nest(|o| {
                        o.error(format!("SDU length mismatch: {} announced, {} present", expected, data.len()));
                    });
                }
                dispatch_psm(st, handle, rx, ch.psm, data, out, layers);
            } else {
                store_sdu(st, handle, ch.cid, dir, Reassembly { expected, data: data.to_vec() });
                incomplete_sdu(out, data.len(), expected, data);
            }
        }
        Some(mut re) => {
            let remaining = re.expected.saturating_sub(re.data.len());
            field!(out, "Channel: {} len {} sdu {} {}", ch.cid, len, remaining, ch.tag);
            re.data.extend_from_slice(payload);
            if re.data.len() >= re.expected {
                if re.data.len() > re.expected {
                    out.nest(|o| {
                        o.error(format!("SDU length mismatch: {} announced, {} present", re.expected, re.data.len()));
                    });
                }
                dispatch_psm(st, handle, rx, ch.psm, &re.data, out, layers);
            } else {
                let (have, expected) = (re.data.len(), re.expected);
                store_sdu(st, handle, ch.cid, dir, re);
                incomplete_sdu(out, have, expected, payload);
            }
        }
    }
}

const SAR_UNSEGMENTED: u8 = 0b00;
const SAR_START: u8 = 0b01;
const SAR_END: u8 = 0b10;

fn sar_name(sar: u8) -> &'static str {
    match sar {
        SAR_UNSEGMENTED => "Unsegmented",
        SAR_START => "Start",
        SAR_END => "End",
        _ => "Continuation",
    }
}

fn supervisory_name(s: u8) -> &'static str {
    match s {
        0b00 => "Receiver Ready (RR)",
        0b01 => "Reject (REJ)",
        0b10 => "Receiver Not Ready (RNR)",
        _ => "Select Reject (SREJ)",
    }
}

/// Decoded control field (standard, enhanced or extended format).
struct Control {
    sframe: bool,
    sar: u8,
    txseq: u16,
    reqseq: u16,
    supervisory: u8,
    poll: bool,
    /// F-bit (enhanced / extended) or R-bit (standard).
    fin: bool,
    /// Standard control field (Retransmission / Flow Control modes).
    standard: bool,
}

impl Control {
    fn parse(ctrl: u32, ext: bool, standard: bool) -> Control {
        let sframe = ctrl & 0x01 != 0;
        if ext {
            Control {
                sframe,
                fin: ctrl & 0x02 != 0,
                reqseq: ((ctrl >> 2) & 0x3fff) as u16,
                sar: ((ctrl >> 16) & 0x03) as u8,
                supervisory: ((ctrl >> 16) & 0x03) as u8,
                poll: ctrl & (1 << 18) != 0,
                txseq: ((ctrl >> 18) & 0x3fff) as u16,
                standard,
            }
        } else {
            Control {
                sframe,
                txseq: ((ctrl >> 1) & 0x3f) as u16,
                supervisory: ((ctrl >> 2) & 0x03) as u8,
                poll: ctrl & 0x10 != 0,
                fin: ctrl & 0x80 != 0,
                reqseq: ((ctrl >> 8) & 0x3f) as u16,
                sar: ((ctrl >> 14) & 0x03) as u8,
                standard,
            }
        }
    }

    fn describe(&self, sdu_len: Option<u16>) -> String {
        let mut s = String::new();
        if self.sframe {
            s.push_str("S-frame: ");
            s.push_str(supervisory_name(self.supervisory));
            if self.poll && !self.standard {
                s.push_str(" P-bit");
            }
        } else {
            s.push_str("I-frame: ");
            s.push_str(sar_name(self.sar));
            if let Some(n) = sdu_len {
                s.push_str(&format!(" (len {n})"));
            }
            s.push_str(&format!(" TxSeq {}", self.txseq));
        }
        s.push_str(&format!(" ReqSeq {}", self.reqseq));
        if self.fin {
            s.push_str(if self.standard { " R-bit" } else { " F-bit" });
        }
        s
    }
}

/// Retransmission / Flow Control / Enhanced Retransmission / Streaming modes:
/// control field, optional SDU length, payload and FCS.
#[allow(clippy::too_many_arguments)]
fn framed(st: &mut IndexState, handle: u16, rx: bool, ch: &Chan, pdu: &[u8], payload: &[u8], out: &mut Out, layers: &mut Vec<Layer>) {
    let len = payload.len();
    let (body, fcs) = if ch.fcs && len >= 2 {
        (&payload[..len - 2], Some(u16::from_le_bytes([payload[len - 2], payload[len - 1]])))
    } else {
        (payload, None)
    };
    let mut r = Reader::new(body);
    let ctrl = if ch.ext_ctrl { r.u32() } else { r.u16().map(u32::from) };
    let Ok(ctrl) = ctrl else {
        field!(out, "Channel: {} len {} {}", ch.cid, len, ch.tag);
        out.nest(|o| {
            o.error("Control field truncated");
            o.hex(payload);
        });
        return;
    };
    if ch.ext_ctrl {
        field!(out, "Channel: {} len {} ext_ctrl 0x{:08x} {}", ch.cid, len, ctrl, ch.tag);
    } else {
        field!(out, "Channel: {} len {} ctrl 0x{:04x} {}", ch.cid, len, ctrl, ch.tag);
    }
    let standard = matches!(ch.mode, L2capMode::Retransmission | L2capMode::FlowControl);
    let c = Control::parse(ctrl, ch.ext_ctrl, standard);
    let sdu_len = if !c.sframe && c.sar == SAR_START { r.u16().ok() } else { None };
    out.nest(|o| {
        o.line(c.describe(sdu_len));
        if let Some(f) = fcs {
            let calc = fcs16(&pdu[..pdu.len() - 2]);
            if calc == f {
                field!(o, "FCS: 0x{:04x}", f);
            } else {
                o.error(format!("FCS: 0x{f:04x} (calculated 0x{calc:04x})"));
            }
        }
        if !c.sframe && c.sar == SAR_START && sdu_len.is_none() {
            o.error("SDU length truncated");
        }
    });
    let data = r.rest();
    if c.sframe {
        if !data.is_empty() {
            out.nest(|o| {
                o.error("Unexpected data in S-frame");
                o.hex(data);
            });
        }
        return;
    }
    let dir = rx as usize;
    match c.sar {
        SAR_UNSEGMENTED => {
            take_sdu(st, handle, ch.cid, dir);
            dispatch_psm(st, handle, rx, ch.psm, data, out, layers);
        }
        SAR_START => {
            take_sdu(st, handle, ch.cid, dir);
            if let Some(expected) = sdu_len {
                let expected = expected as usize;
                store_sdu(st, handle, ch.cid, dir, Reassembly { expected, data: data.to_vec() });
                incomplete_sdu(out, data.len(), expected, data);
            } else {
                out.nest(|o| {
                    o.hex(data);
                });
            }
        }
        _ => match take_sdu(st, handle, ch.cid, dir) {
            Some(mut re) => {
                re.data.extend_from_slice(data);
                if c.sar == SAR_END {
                    if re.data.len() != re.expected {
                        out.nest(|o| {
                            o.error(format!("SDU length mismatch: {} announced, {} reassembled", re.expected, re.data.len()));
                        });
                    }
                    dispatch_psm(st, handle, rx, ch.psm, &re.data, out, layers);
                } else {
                    let (have, expected) = (re.data.len(), re.expected);
                    store_sdu(st, handle, ch.cid, dir, re);
                    incomplete_sdu(out, have, expected, data);
                }
            }
            None => {
                out.nest(|o| {
                    o.error(format!("{} segment without start of SDU", sar_name(c.sar)));
                    o.hex(data);
                });
            }
        },
    }
}

/// Hand a complete SDU to the protocol identified by the PSM.
fn dispatch_psm(st: &mut IndexState, handle: u16, rx: bool, psm: u16, payload: &[u8], out: &mut Out, layers: &mut Vec<Layer>) {
    match psm {
        PSM_SDP => {
            layers.push(Layer::Sdp);
            sdp::decode(payload, out);
        }
        PSM_RFCOMM => {
            layers.push(Layer::Rfcomm);
            rfcomm::decode(payload, out);
        }
        PSM_ATT | PSM_EATT => {
            layers.push(Layer::Att);
            let frame = st.frames;
            att::decode(st, handle, rx, payload, out, frame);
        }
        PSM_AVCTP | PSM_AVCTP_BROWSING => {
            layers.push(Layer::Avctp);
            protocol_hex("AVCTP", payload, out);
        }
        PSM_AVDTP => {
            layers.push(Layer::Avdtp);
            protocol_hex("AVDTP", payload, out);
        }
        _ => match psm_name(psm) {
            Some(name) => protocol_hex(name, payload, out),
            None => {
                out.nest(|o| {
                    o.hex(payload);
                });
            }
        },
    }
}

/// Headline plus hex dump for a protocol that is not decoded further.
fn protocol_hex(name: &str, payload: &[u8], out: &mut Out) {
    field!(out, "{}: len {}", name, payload.len());
    out.nest(|o| {
        o.hex(payload);
    });
}

pub fn signaling_code_name(code: u8) -> Option<&'static str> {
    Some(match code {
        0x01 => "Command Reject",
        0x02 => "Connection Request",
        0x03 => "Connection Response",
        0x04 => "Configure Request",
        0x05 => "Configure Response",
        0x06 => "Disconnection Request",
        0x07 => "Disconnection Response",
        0x08 => "Echo Request",
        0x09 => "Echo Response",
        0x0a => "Information Request",
        0x0b => "Information Response",
        0x0c => "Create Channel Request",
        0x0d => "Create Channel Response",
        0x0e => "Move Channel Request",
        0x0f => "Move Channel Response",
        0x10 => "Move Channel Confirmation Request",
        0x11 => "Move Channel Confirmation Response",
        0x12 => "Connection Parameter Update Request",
        0x13 => "Connection Parameter Update Response",
        0x14 => "LE Credit Based Connection Request",
        0x15 => "LE Credit Based Connection Response",
        0x16 => "Flow Control Credit Indication",
        0x17 => "Credit Based Connection Request",
        0x18 => "Credit Based Connection Response",
        0x19 => "Credit Based Reconfigure Request",
        0x1a => "Credit Based Reconfigure Response",
        _ => return None,
    })
}

/// Flatten an `Out` into indented text lines (two spaces per level), for tests.
#[cfg(test)]
pub(crate) fn test_lines(out: &Out) -> Vec<String> {
    let mut v = Vec::new();
    crate::tree::render_lines(out.roots(), 0, |indent, n| v.push(format!("{}{}", " ".repeat(indent), n.text)));
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    const HANDLE: u16 = 0x0040;

    fn pdu(cid: u16, payload: &[u8]) -> Vec<u8> {
        let mut v = (payload.len() as u16).to_le_bytes().to_vec();
        v.extend_from_slice(&cid.to_le_bytes());
        v.extend_from_slice(payload);
        v
    }

    fn run(st: &mut IndexState, rx: bool, cid: u16, payload: &[u8]) -> (Vec<String>, Vec<Layer>) {
        let mut out = Out::new();
        let mut layers = Vec::new();
        decode_pdu(st, HANDLE, rx, &pdu(cid, payload), &mut out, &mut layers);
        (test_lines(&out), layers)
    }

    /// TX Connection Request (ident 1) + RX Connection Response: local CID 0x40, remote CID 0x41.
    fn open_bredr_channel(st: &mut IndexState, psm: u16) {
        let mut req = vec![0x02, 0x01, 0x04, 0x00];
        req.extend_from_slice(&psm.to_le_bytes());
        req.extend_from_slice(&[0x40, 0x00]);
        run(st, false, CID_SIGNALING, &req);
        run(st, true, CID_SIGNALING, &[0x03, 0x01, 0x08, 0x00, 0x41, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00]);
    }

    #[test]
    fn fcs_matches_spec_examples() {
        assert_eq!(fcs16(&[0x0e, 0x00, 0x40, 0x00, 0x02, 0x00, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9]), 0x6138);
        assert_eq!(fcs16(&[0x04, 0x00, 0x40, 0x00, 0x01, 0x01]), 0x14d4);
    }

    #[test]
    fn header_truncated() {
        let mut st = IndexState::default();
        let mut out = Out::new();
        let mut layers = Vec::new();
        decode_pdu(&mut st, HANDLE, true, &[0x01, 0x00, 0x04], &mut out, &mut layers);
        let l = test_lines(&out);
        assert_eq!(l[0], "L2CAP header truncated");
        assert_eq!(layers, [Layer::L2cap]);
    }

    #[test]
    fn unknown_cid_is_dumped() {
        let mut st = IndexState::default();
        let (l, _) = run(&mut st, true, 0x0050, &[0xaa, 0xbb]);
        assert_eq!(l[0], "Channel: 80 len 2 [Unknown]");
        assert!(l[1].starts_with("  aa bb"));
    }

    #[test]
    fn connection_request_and_response_register_channel() {
        let mut st = IndexState::default();
        let (l, _) = run(&mut st, false, CID_SIGNALING, &[0x02, 0x01, 0x04, 0x00, 0x03, 0x00, 0x40, 0x00]);
        assert_eq!(l, ["L2CAP: Connection Request (0x02) ident 1 len 4", "  PSM: RFCOMM (0x0003)", "  Source CID: 64"]);
        assert_eq!(st.conn(HANDLE).unwrap().l2cap.pending.get(&1), Some(&(3, 0x40)));

        let (l, _) = run(&mut st, true, CID_SIGNALING, &[0x03, 0x01, 0x08, 0x00, 0x41, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00]);
        assert_eq!(
            l,
            [
                "L2CAP: Connection Response (0x03) ident 1 len 8",
                "  Destination CID: 65",
                "  Source CID: 64",
                "  Result: Connection successful (0x0000)",
                "  Status: No further information available (0x0000)",
            ]
        );
        let conn = st.conn(HANDLE).unwrap();
        assert!(conn.l2cap.pending.is_empty());
        let ch = conn.l2cap.channel(0x41).unwrap();
        assert_eq!((ch.local_cid, ch.remote_cid, ch.psm, ch.mode), (0x40, 0x41, 3, L2capMode::Basic));
        assert_eq!(conn.l2cap.channel(0x40), Some(ch));

        // Data in either direction is attributed to the channel and decoded as RFCOMM.
        let (l, layers) = run(&mut st, false, 0x41, &[0x03, 0x3f, 0x01, 0x1c]);
        assert_eq!(l[0], "Channel: 65 len 4 [PSM 3 mode Basic (0x00)]");
        assert_eq!(l[1], "RFCOMM: Set Async Balance Mode (SABM) (0x2f)");
        assert_eq!(layers, [Layer::L2cap, Layer::Rfcomm]);
        let (l, _) = run(&mut st, true, 0x40, &[0x03, 0x73, 0x01, 0xd7]);
        assert_eq!(l[0], "Channel: 64 len 4 [PSM 3 mode Basic (0x00)]");
        assert_eq!(l[1], "RFCOMM: Unnumbered Ack (UA) (0x63)");
    }

    #[test]
    fn configure_records_ertm_mode_and_frames_are_decoded() {
        let mut st = IndexState::default();
        open_bredr_channel(&mut st, PSM_SDP);
        // Configure Request: dcid 0x41, flags 0, MTU 672, RFC option (ERTM, tx window 8, max transmit 3,
        // retransmission timeout 1000, monitor timeout 3000, MPS 1010).
        let (l, _) = run(
            &mut st,
            false,
            CID_SIGNALING,
            &[
                0x04, 0x02, 0x13, 0x00, 0x41, 0x00, 0x00, 0x00, 0x01, 0x02, 0xa0, 0x02, 0x04, 0x09, 0x03, 0x08, 0x03, 0xe8, 0x03, 0xb8, 0x0b,
                0xf2, 0x03,
            ],
        );
        assert_eq!(
            l,
            [
                "L2CAP: Configure Request (0x04) ident 2 len 19",
                "  Destination CID: 65",
                "  Flags: 0x0000",
                "  Option: Maximum Transmission Unit (0x01) [mandatory]",
                "    MTU: 672",
                "  Option: Retransmission and Flow Control (0x04) [mandatory]",
                "    Mode: Enhanced Retransmission (0x03)",
                "    TX window size: 8",
                "    Max transmit: 3",
                "    Retransmission timeout: 1000",
                "    Monitor timeout: 3000",
                "    Maximum PDU size: 1010",
            ]
        );
        let ch = st.conn(HANDLE).unwrap().l2cap.channel(0x40).unwrap();
        assert_eq!(ch.mode, L2capMode::EnhancedRetransmission);
        assert_eq!(ch.mtu, 672);

        // I-frame (TxSeq 1) carrying an SDP Service Search Request, with FCS.
        let mut payload = vec![0x02, 0x00];
        payload.extend_from_slice(&[0x02, 0x00, 0x01, 0x00, 0x08, 0x35, 0x03, 0x19, 0x11, 0x01, 0x00, 0x20, 0x00]);
        let mut p = pdu(0x41, &payload);
        p[0] += 2;
        let fcs = fcs16(&p);
        p.extend_from_slice(&fcs.to_le_bytes());
        let mut out = Out::new();
        let mut layers = Vec::new();
        decode_pdu(&mut st, HANDLE, false, &p, &mut out, &mut layers);
        let l = test_lines(&out);
        assert_eq!(l[0], "Channel: 65 len 17 ctrl 0x0002 [PSM 1 mode Enhanced Retransmission (0x03)]");
        assert_eq!(l[1], "  I-frame: Unsegmented TxSeq 1 ReqSeq 0");
        assert_eq!(l[2], format!("  FCS: 0x{fcs:04x}"));
        assert_eq!(l[3], "SDP: Service Search Request (0x02) tid 1 len 8");
        assert_eq!(layers, [Layer::L2cap, Layer::Sdp]);

        // S-frame RR with ReqSeq 1 (spec example, including its FCS).
        let (l, _) = run(&mut st, true, 0x40, &[0x01, 0x01, 0xd4, 0x14]);
        assert_eq!(l[0], "Channel: 64 len 4 ctrl 0x0101 [PSM 1 mode Enhanced Retransmission (0x03)]");
        assert_eq!(l[1], "  S-frame: Receiver Ready (RR) ReqSeq 1");
        assert_eq!(l[2], "  FCS: 0x14d4");
    }

    #[test]
    fn ertm_segments_are_reassembled() {
        let mut st = IndexState::default();
        open_bredr_channel(&mut st, PSM_RFCOMM);
        // Both sides ask for No FCS so frames carry none.
        run(&mut st, false, CID_SIGNALING, &[0x04, 0x02, 0x07, 0x00, 0x41, 0x00, 0x00, 0x00, 0x05, 0x01, 0x00]);
        run(&mut st, true, CID_SIGNALING, &[0x04, 0x02, 0x07, 0x00, 0x40, 0x00, 0x00, 0x00, 0x05, 0x01, 0x00]);
        // Configure Response with RFC option (ERTM).
        run(
            &mut st,
            true,
            CID_SIGNALING,
            &[0x05, 0x02, 0x11, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x09, 0x03, 0x08, 0x03, 0xe8, 0x03, 0xb8, 0x0b, 0xf2, 0x03],
        );
        assert!(!has_fcs(st.conn(HANDLE).unwrap().l2cap.channel(0x41).unwrap()));

        // Start (SAR 01, TxSeq 0): SDU length 4, first 2 bytes of an RFCOMM SABM frame.
        let (l, _) = run(&mut st, false, 0x41, &[0x00, 0x40, 0x04, 0x00, 0x03, 0x3f]);
        assert_eq!(l[0], "Channel: 65 len 6 ctrl 0x4000 [PSM 3 mode Enhanced Retransmission (0x03)]");
        assert_eq!(l[1], "  I-frame: Start (len 4) TxSeq 0 ReqSeq 0");
        assert_eq!(l[2], "  Incomplete SDU: 2 of 4 bytes");
        // End (SAR 10, TxSeq 1).
        let (l, layers) = run(&mut st, false, 0x41, &[0x02, 0x80, 0x01, 0x1c]);
        assert_eq!(l[1], "  I-frame: End TxSeq 1 ReqSeq 0");
        assert_eq!(l[2], "RFCOMM: Set Async Balance Mode (SABM) (0x2f)");
        assert_eq!(layers, [Layer::L2cap, Layer::Rfcomm]);
    }

    #[test]
    fn le_credit_based_channel_reassembles_sdus() {
        let mut st = IndexState::default();
        let (l, _) = run(
            &mut st,
            false,
            CID_LE_SIGNALING,
            &[0x14, 0x03, 0x0a, 0x00, 0x80, 0x00, 0x40, 0x00, 0x64, 0x00, 0x17, 0x00, 0x05, 0x00],
        );
        assert_eq!(
            l,
            [
                "LE: LE Credit Based Connection Request (0x14) ident 3 len 10",
                "  PSM: 128 (0x0080)",
                "  Source CID: 64",
                "  MTU: 100",
                "  MPS: 23",
                "  Credits: 5",
            ]
        );
        let (l, _) = run(&mut st, true, CID_LE_SIGNALING, &[0x15, 0x03, 0x0a, 0x00, 0x41, 0x00, 0x64, 0x00, 0x17, 0x00, 0x05, 0x00, 0x00, 0x00]);
        assert_eq!(l[1], "  Destination CID: 65");
        assert_eq!(l[5], "  Result: Connection successful (0x0000)");
        let ch = st.conn(HANDLE).unwrap().l2cap.channel(0x41).unwrap();
        assert_eq!((ch.psm, ch.mode, ch.le, ch.mtu), (0x80, L2capMode::LeCreditBased, true, 100));

        let (l, _) = run(&mut st, false, 0x41, &[0x05, 0x00, 0x01, 0x02, 0x03]);
        assert_eq!(l[0], "Channel: 65 len 5 sdu 5 [PSM 128 mode LE Flow Control (0x80)]");
        assert_eq!(l[1], "  Incomplete SDU: 3 of 5 bytes");
        let (l, _) = run(&mut st, false, 0x41, &[0x04, 0x05]);
        assert_eq!(l[0], "Channel: 65 len 2 sdu 2 [PSM 128 mode LE Flow Control (0x80)]");
        assert!(l[1].starts_with("  01 02 03 04 05"));
        // The next PDU starts a new SDU.
        let (l, _) = run(&mut st, false, 0x41, &[0x01, 0x00, 0xff]);
        assert_eq!(l[0], "Channel: 65 len 3 sdu 1 [PSM 128 mode LE Flow Control (0x80)]");
        assert!(l[1].starts_with("  ff"));
        // Credits on the way back.
        let (l, _) = run(&mut st, true, CID_LE_SIGNALING, &[0x16, 0x04, 0x04, 0x00, 0x41, 0x00, 0x02, 0x00]);
        assert_eq!(l, ["LE: Flow Control Credit Indication (0x16) ident 4 len 4", "  Source CID: 65", "  Credits: 2"]);
    }

    #[test]
    fn enhanced_credit_based_connection_registers_every_channel() {
        let mut st = IndexState::default();
        let (l, _) = run(
            &mut st,
            true,
            CID_LE_SIGNALING,
            &[0x17, 0x05, 0x0c, 0x00, 0x27, 0x00, 0x40, 0x00, 0x40, 0x00, 0x0a, 0x00, 0x40, 0x00, 0x41, 0x00],
        );
        assert_eq!(l[1], "  PSM: EATT (0x0027)");
        assert_eq!(l[5], "  Source CID: 64");
        assert_eq!(l[6], "  Source CID: 65");
        let (l, _) = run(
            &mut st,
            false,
            CID_LE_SIGNALING,
            &[0x18, 0x05, 0x0c, 0x00, 0x40, 0x00, 0x40, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x50, 0x00, 0x51, 0x00],
        );
        assert_eq!(l[4], "  Result: All connections successful (0x0000)");
        assert_eq!(l[5], "  Destination CID: 80");
        let conn = st.conn(HANDLE).unwrap();
        for (a, b) in [(0x40, 0x50), (0x41, 0x51)] {
            let ch = conn.l2cap.channel(a).unwrap();
            assert_eq!((ch.local_cid, ch.remote_cid, ch.psm, ch.mode), (b, a, PSM_EATT, L2capMode::EnhancedCreditBased));
            assert_eq!(conn.l2cap.channel(b), Some(ch));
        }
        // An EATT SDU on one of them is handed to ATT (after the SDU length).
        let (l, layers) = run(&mut st, true, 0x50, &[0x03, 0x00, 0x02, 0x40, 0x00]);
        assert_eq!(l[0], "Channel: 80 len 5 sdu 3 [PSM 39 mode Enhanced Credit (0x81)]");
        assert!(l[1].starts_with("ATT: "), "{}", l[1]);
        assert_eq!(layers, [Layer::L2cap, Layer::Att]);
    }

    #[test]
    fn disconnection_response_removes_channel() {
        let mut st = IndexState::default();
        open_bredr_channel(&mut st, PSM_SDP);
        let (l, _) = run(&mut st, false, CID_SIGNALING, &[0x06, 0x03, 0x04, 0x00, 0x41, 0x00, 0x40, 0x00]);
        assert_eq!(l, ["L2CAP: Disconnection Request (0x06) ident 3 len 4", "  Destination CID: 65", "  Source CID: 64"]);
        assert!(st.conn(HANDLE).unwrap().l2cap.channel(0x41).is_some());
        let (l, _) = run(&mut st, true, CID_SIGNALING, &[0x07, 0x03, 0x04, 0x00, 0x41, 0x00, 0x40, 0x00]);
        assert_eq!(l[0], "L2CAP: Disconnection Response (0x07) ident 3 len 4");
        let conn = st.conn(HANDLE).unwrap();
        assert!(conn.l2cap.channel(0x41).is_none());
        assert!(conn.l2cap.channel(0x40).is_none());
        let (l, _) = run(&mut st, true, 0x40, &[0x00]);
        assert_eq!(l[0], "Channel: 64 len 1 [Unknown]");
    }

    #[test]
    fn several_signaling_commands_in_one_pdu() {
        let mut st = IndexState::default();
        let (l, _) = run(
            &mut st,
            false,
            CID_SIGNALING,
            &[0x0a, 0x01, 0x02, 0x00, 0x02, 0x00, 0x0a, 0x02, 0x02, 0x00, 0x03, 0x00, 0x08, 0x03, 0x02, 0x00, 0xaa, 0xbb],
        );
        assert_eq!(
            l[..5],
            [
                "L2CAP: Information Request (0x0a) ident 1 len 2",
                "  Type: Extended features supported (0x0002)",
                "L2CAP: Information Request (0x0a) ident 2 len 2",
                "  Type: Fixed channels supported (0x0003)",
                "L2CAP: Echo Request (0x08) ident 3 len 2",
            ]
        );
        assert!(l[5].starts_with("  aa bb"), "{}", l[5]);
    }

    #[test]
    fn information_response_masks() {
        let mut st = IndexState::default();
        let (l, _) = run(&mut st, true, CID_SIGNALING, &[0x0b, 0x01, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00, 0xb8, 0x02, 0x00, 0x00]);
        assert_eq!(
            l,
            [
                "L2CAP: Information Response (0x0b) ident 1 len 8",
                "  Type: Extended features supported (0x0002)",
                "  Result: Success (0x0000)",
                "  Features: 0x000002b8",
                "    Enhanced Retransmission Mode",
                "    Streaming Mode",
                "    FCS Option",
                "    Fixed Channels",
                "    Unicast Connectionless Data Reception",
            ]
        );
        let (l, _) = run(
            &mut st,
            true,
            CID_SIGNALING,
            &[0x0b, 0x02, 0x0c, 0x00, 0x03, 0x00, 0x00, 0x00, 0x86, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
        );
        assert_eq!(l[3], "  Channels: 0x0000000000000086");
        assert_eq!(l[4..], ["    L2CAP Signaling (BR/EDR)", "    Connectionless reception", "    Security Manager (BR/EDR)"]);
        let (l, _) = run(&mut st, true, CID_SIGNALING, &[0x0b, 0x03, 0x06, 0x00, 0x01, 0x00, 0x00, 0x00, 0xa0, 0x02]);
        assert_eq!(l[3], "  MTU: 672");
        let (l, _) = run(&mut st, true, CID_SIGNALING, &[0x0b, 0x04, 0x04, 0x00, 0x01, 0x00, 0x01, 0x00]);
        assert_eq!(l[2], "  Result: Not supported (0x0001)");
    }

    #[test]
    fn command_reject_reasons() {
        let mut st = IndexState::default();
        let (l, _) = run(&mut st, true, CID_SIGNALING, &[0x01, 0x01, 0x02, 0x00, 0x00, 0x00]);
        assert_eq!(l, ["L2CAP: Command Reject (0x01) ident 1 len 2", "  Reason: Command not understood (0x0000)"]);
        let (l, _) = run(&mut st, true, CID_SIGNALING, &[0x01, 0x02, 0x04, 0x00, 0x01, 0x00, 0x30, 0x00]);
        assert_eq!(l[1..], ["  Reason: Signaling MTU exceeded (0x0001)", "  MTU: 48"]);
        let (l, _) = run(&mut st, true, CID_SIGNALING, &[0x01, 0x03, 0x06, 0x00, 0x02, 0x00, 0x40, 0x00, 0x41, 0x00]);
        assert_eq!(l[1..], ["  Reason: Invalid CID in request (0x0002)", "  Local CID: 64", "  Remote CID: 65"]);
    }

    #[test]
    fn connection_parameter_update() {
        let mut st = IndexState::default();
        let (l, _) = run(&mut st, false, CID_LE_SIGNALING, &[0x12, 0x01, 0x08, 0x00, 0x18, 0x00, 0x28, 0x00, 0x00, 0x00, 0x2a, 0x00]);
        assert_eq!(
            l,
            [
                "LE: Connection Parameter Update Request (0x12) ident 1 len 8",
                "  Min interval: 30.000 msec (0x0018)",
                "  Max interval: 50.000 msec (0x0028)",
                "  Peripheral latency: 0 (0x0000)",
                "  Supervision timeout: 420 msec (0x002a)",
            ]
        );
        let (l, _) = run(&mut st, true, CID_LE_SIGNALING, &[0x13, 0x01, 0x02, 0x00, 0x00, 0x00]);
        assert_eq!(l[1], "  Result: Connection Parameters accepted (0x0000)");
    }

    #[test]
    fn truncated_signaling_parameters_are_flagged() {
        let mut st = IndexState::default();
        let (l, _) = run(&mut st, false, CID_SIGNALING, &[0x02, 0x01, 0x03, 0x00, 0x03, 0x00, 0x40]);
        assert_eq!(l[0], "L2CAP: Connection Request (0x02) ident 1 len 3");
        assert_eq!(l[1], "  PSM: RFCOMM (0x0003)");
        assert!(l[2].starts_with("  Parameters truncated"), "{}", l[2]);
        let (l, _) = run(&mut st, false, CID_SIGNALING, &[0x02, 0x01, 0x04, 0x00, 0x03]);
        assert!(l[0].contains("truncated"), "{}", l[0]);
    }

    #[test]
    fn connectionless_data() {
        let mut st = IndexState::default();
        let (l, _) = run(&mut st, true, CID_CONNECTIONLESS, &[0x0f, 0x00, 0x01, 0x02]);
        assert_eq!(l[0], "L2CAP: Connectionless len 2 [PSM 15]");
        assert_eq!(l[1], "BNEP: len 2");
    }

    #[test]
    fn fixed_channel_names() {
        let mut st = IndexState::default();
        let (l, _) = run(&mut st, true, CID_AMP_MANAGER, &[0x01]);
        assert_eq!(l[0], "Channel: 3 len 1 [AMP Manager]");
        let (l, _) = run(&mut st, true, CID_AMP_TEST, &[0x01]);
        assert_eq!(l[0], "Channel: 63 len 1 [AMP Test Manager]");
    }
}
