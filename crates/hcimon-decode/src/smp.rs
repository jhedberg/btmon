//! Security Manager Protocol (SMP) PDUs (Vol 3, Part H, Section 3).

use crate::context::IndexState;
use crate::field;
use crate::hci::common::{bits, enum8, peer_addr};
use crate::reader::{Reader, Result};
use crate::tree::Out;

pub fn code_name(code: u8) -> Option<&'static str> {
    Some(match code {
        0x01 => "Pairing Request",
        0x02 => "Pairing Response",
        0x03 => "Pairing Confirm",
        0x04 => "Pairing Random",
        0x05 => "Pairing Failed",
        0x06 => "Encryption Information",
        0x07 => "Central Identification",
        0x08 => "Identity Information",
        0x09 => "Identity Address Information",
        0x0a => "Signing Information",
        0x0b => "Security Request",
        0x0c => "Pairing Public Key",
        0x0d => "Pairing DHKey Check",
        0x0e => "Pairing Keypress Notification",
        _ => return None,
    })
}

static IO_CAPABILITIES: &[(u8, &str)] = &[
    (0x00, "DisplayOnly"),
    (0x01, "DisplayYesNo"),
    (0x02, "KeyboardOnly"),
    (0x03, "NoInputNoOutput"),
    (0x04, "KeyboardDisplay"),
];

static OOB_DATA: &[(u8, &str)] =
    &[(0x00, "Authentication data not present"), (0x01, "Authentication data from remote device present")];

static KEY_DISTRIBUTION: &[(u8, &str)] =
    &[(0, "Encryption Key (LTK)"), (1, "Identity Key (IRK)"), (2, "Signature Key (CSRK)"), (3, "Link Key")];

pub fn failed_reason(reason: u8) -> Option<&'static str> {
    Some(match reason {
        0x01 => "Passkey Entry Failed",
        0x02 => "OOB Not Available",
        0x03 => "Authentication Requirements",
        0x04 => "Confirm Value Failed",
        0x05 => "Pairing Not Supported",
        0x06 => "Encryption Key Size",
        0x07 => "Command Not Supported",
        0x08 => "Unspecified Reason",
        0x09 => "Repeated Attempts",
        0x0a => "Invalid Parameters",
        0x0b => "DHKey Check Failed",
        0x0c => "Numeric Comparison Failed",
        0x0d => "BR/EDR pairing in progress",
        0x0e => "Cross-transport Key Derivation/Generation not allowed",
        0x0f => "Key Rejected",
        0x10 => "Busy",
        _ => return None,
    })
}

static KEYPRESS_TYPES: &[(u8, &str)] = &[
    (0x00, "Passkey entry started"),
    (0x01, "Passkey digit entered"),
    (0x02, "Passkey digit erased"),
    (0x03, "Passkey cleared"),
    (0x04, "Passkey entry completed"),
];

/// Decode an SMP PDU carried on `handle` (`bredr` for CID 0x0007).
pub fn decode(st: &mut IndexState, handle: u16, bredr: bool, payload: &[u8], out: &mut Out) {
    let _ = (st, handle);
    let mut r = Reader::new(payload);
    let Ok(code) = r.u8() else {
        out.error("SMP: empty PDU");
        return;
    };
    let label = if bredr { "BR/EDR SMP" } else { "SMP" };
    match code_name(code) {
        Some(n) => field!(out, "{}: {} (0x{:02x}) len {}", label, n, code, r.remaining()),
        None => out.unknown(format!("{label}: Unknown (0x{code:02x}) len {}", r.remaining())),
    };
    out.nest(|o| match params(code, &mut r, o) {
        Ok(true) => {
            if !r.is_empty() {
                o.error("Unexpected trailing data");
                o.hex(r.rest());
            }
        }
        Ok(false) => {
            o.hex(r.rest());
        }
        Err(e) => {
            o.error(format!("Parameters {e}"));
            o.hex(r.rest());
        }
    });
}

fn params(code: u8, r: &mut Reader<'_>, out: &mut Out) -> Result<bool> {
    match code {
        0x01 | 0x02 => pairing(r, out)?,
        0x03 => hex_value("Confirm value", r, out, 16)?,
        0x04 => hex_value("Random value", r, out, 16)?,
        0x05 => {
            let reason = r.u8()?;
            match failed_reason(reason) {
                Some(n) => field!(out, "Reason: {} (0x{:02x})", n, reason),
                None => out.unknown(format!("Reason: Reserved (0x{reason:02x})")),
            };
        }
        0x06 => hex_value("Long term key", r, out, 16)?,
        0x07 => {
            let ediv = r.u16()?;
            field!(out, "EDIV: 0x{:04x}", ediv);
            let rand = r.u64()?;
            field!(out, "Rand: 0x{:016x}", rand);
        }
        0x08 => hex_value("Identity resolving key", r, out, 16)?,
        0x09 => {
            peer_addr(r, out)?;
        }
        0x0a => hex_value("Signature key", r, out, 16)?,
        0x0b => {
            auth_req(r, out)?;
        }
        0x0c => {
            hex_value("X", r, out, 32)?;
            hex_value("Y", r, out, 32)?;
        }
        0x0d => hex_value("DHKey check", r, out, 16)?,
        0x0e => {
            enum8("Type", r, out, KEYPRESS_TYPES)?;
        }
        _ => return Ok(false),
    }
    Ok(true)
}

fn pairing(r: &mut Reader<'_>, out: &mut Out) -> Result<()> {
    enum8("IO capability", r, out, IO_CAPABILITIES)?;
    enum8("OOB data", r, out, OOB_DATA)?;
    auth_req(r, out)?;
    let size = r.u8()?;
    field!(out, "Max encryption key size: {}", size);
    key_dist("Initiator key distribution", r, out)?;
    key_dist("Responder key distribution", r, out)?;
    Ok(())
}

/// `Authentication requirement: Bonding, MITM, SC, No Keypresses (0x0d)`
fn auth_req(r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    let v = r.u8()?;
    let bonding = match v & 0x03 {
        0x00 => "No Bonding",
        0x01 => "Bonding",
        _ => "Reserved",
    };
    let mitm = if v & 0x04 != 0 { "MITM" } else { "No MITM" };
    let sc = if v & 0x08 != 0 { "SC" } else { "Legacy" };
    let keypress = if v & 0x10 != 0 { "Keypresses" } else { "No Keypresses" };
    let ct2 = if v & 0x20 != 0 { ", CT2" } else { "" };
    field!(out, "Authentication requirement: {}, {}, {}, {}{} (0x{:02x})", bonding, mitm, sc, keypress, ct2, v);
    Ok(v)
}

fn key_dist(label: &str, r: &mut Reader<'_>, out: &mut Out) -> Result<u8> {
    let v = r.u8()?;
    field!(out, "{}: 0x{:02x}", label, v);
    out.nest(|o| bits(o, v as u64, KEY_DISTRIBUTION, 8));
    Ok(v)
}

/// A fixed-size value printed as one hex string, like `key128`.
fn hex_value(label: &str, r: &mut Reader<'_>, out: &mut Out, len: usize) -> Result<()> {
    let b = r.bytes(len)?;
    let s: String = b.iter().map(|x| format!("{x:02x}")).collect();
    field!(out, "{}: {}", label, s);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::l2cap::test_lines;

    fn run(bredr: bool, payload: &[u8]) -> Vec<String> {
        let mut st = IndexState::default();
        let mut out = Out::new();
        decode(&mut st, 0x0040, bredr, payload, &mut out);
        test_lines(&out)
    }

    #[test]
    fn pairing_request() {
        assert_eq!(
            run(false, &[0x01, 0x03, 0x00, 0x2d, 0x10, 0x0f, 0x07]),
            [
                "SMP: Pairing Request (0x01) len 6",
                "  IO capability: NoInputNoOutput (0x03)",
                "  OOB data: Authentication data not present (0x00)",
                "  Authentication requirement: Bonding, MITM, SC, No Keypresses, CT2 (0x2d)",
                "  Max encryption key size: 16",
                "  Initiator key distribution: 0x0f",
                "    Encryption Key (LTK)",
                "    Identity Key (IRK)",
                "    Signature Key (CSRK)",
                "    Link Key",
                "  Responder key distribution: 0x07",
                "    Encryption Key (LTK)",
                "    Identity Key (IRK)",
                "    Signature Key (CSRK)",
            ]
        );
    }

    #[test]
    fn pairing_response_on_bredr() {
        let l = run(true, &[0x02, 0x04, 0x01, 0x00, 0x07, 0x00, 0x00]);
        assert_eq!(l[0], "BR/EDR SMP: Pairing Response (0x02) len 6");
        assert_eq!(l[1], "  IO capability: KeyboardDisplay (0x04)");
        assert_eq!(l[2], "  OOB data: Authentication data from remote device present (0x01)");
        assert_eq!(l[3], "  Authentication requirement: No Bonding, No MITM, Legacy, No Keypresses (0x00)");
        assert_eq!(l[5], "  Initiator key distribution: 0x00");
        assert_eq!(l[6], "  Responder key distribution: 0x00");
    }

    #[test]
    fn confirm_and_random() {
        let mut p = vec![0x03];
        p.extend((0u8..16).map(|i| 0xa0 + i));
        let l = run(false, &p);
        assert_eq!(l, ["SMP: Pairing Confirm (0x03) len 16", "  Confirm value: a0a1a2a3a4a5a6a7a8a9aaabacadaeaf"]);
        p[0] = 0x04;
        assert_eq!(run(false, &p)[1], "  Random value: a0a1a2a3a4a5a6a7a8a9aaabacadaeaf");
    }

    #[test]
    fn pairing_failed() {
        assert_eq!(run(false, &[0x05, 0x0c])[1], "  Reason: Numeric Comparison Failed (0x0c)");
        assert_eq!(run(false, &[0x05, 0x10])[1], "  Reason: Busy (0x10)");
        assert_eq!(run(false, &[0x05, 0x11])[1], "  Reason: Reserved (0x11)");
    }

    #[test]
    fn key_distribution_pdus() {
        let mut p = vec![0x06];
        p.extend([0x11u8; 16]);
        assert_eq!(run(false, &p)[1], "  Long term key: 11111111111111111111111111111111");
        let l = run(false, &[0x07, 0x34, 0x12, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
        assert_eq!(l[1..], ["  EDIV: 0x1234", "  Rand: 0x0807060504030201"]);
        p[0] = 0x08;
        assert_eq!(run(false, &p)[1], "  Identity resolving key: 11111111111111111111111111111111");
        p[0] = 0x0a;
        assert_eq!(run(false, &p)[1], "  Signature key: 11111111111111111111111111111111");
    }

    #[test]
    fn identity_address_information() {
        let l = run(false, &[0x09, 0x01, 0x13, 0x71, 0xda, 0x7d, 0x1a, 0xc0]);
        assert_eq!(l[1], "  Address type: Random (0x01)");
        assert_eq!(l[2], "  Address: C0:1A:7D:DA:71:13 (Static)");
        let l = run(false, &[0x09, 0x00, 0x13, 0x71, 0xda, 0x7d, 0x1a, 0x00]);
        assert_eq!(l[1], "  Address type: Public (0x00)");
        assert!(l[2].starts_with("  Address: 00:1A:7D:DA:71:13"));
    }

    #[test]
    fn security_request_and_keypress() {
        assert_eq!(run(false, &[0x0b, 0x01])[1], "  Authentication requirement: Bonding, No MITM, Legacy, No Keypresses (0x01)");
        assert_eq!(run(false, &[0x0e, 0x04])[1], "  Type: Passkey entry completed (0x04)");
    }

    #[test]
    fn public_key_and_dhkey_check() {
        let mut p = vec![0x0c];
        p.extend([0x01u8; 32]);
        p.extend([0x02u8; 32]);
        let l = run(false, &p);
        assert_eq!(l[0], "SMP: Pairing Public Key (0x0c) len 64");
        assert_eq!(l[1], format!("  X: {}", "01".repeat(32)));
        assert_eq!(l[2], format!("  Y: {}", "02".repeat(32)));
        let mut p = vec![0x0d];
        p.extend([0x03u8; 16]);
        assert_eq!(run(false, &p)[1], format!("  DHKey check: {}", "03".repeat(16)));
    }

    #[test]
    fn truncated_and_unknown() {
        let l = run(false, &[0x01, 0x03, 0x00]);
        assert_eq!(l[2], "  OOB data: Authentication data not present (0x00)");
        assert!(l[3].starts_with("  Parameters truncated"), "{}", l[3]);
        assert_eq!(run(false, &[])[0], "SMP: empty PDU");
        let l = run(false, &[0x20, 0xaa]);
        assert_eq!(l[0], "SMP: Unknown (0x20) len 1");
        assert!(l[1].starts_with("  aa"));
        let l = run(false, &[0x0e, 0x04, 0xff]);
        assert_eq!(l[2], "  Unexpected trailing data");
    }
}
