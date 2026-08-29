//! HCI command parameter and return parameter dispatch.
//!
//! The decoders live in the per-area modules (`cmd_classic`, `cmd_le_a`,
//! `cmd_le_b`, `vendor`); this module only routes an opcode to them and
//! provides the generic fall-backs: a command without parameters needs no
//! decoder, and a Command Complete that carries nothing but a status is
//! printed here.

use super::command_name;
use super::common::status;
use crate::context::IndexState;
use crate::reader::{Reader, Result};
use crate::tree::Out;

/// Decode the parameters of the command with the given opcode.
///
/// Returns `Ok(false)` when no decoder exists so the caller can hex dump the payload.
pub fn command_params(st: &mut IndexState, opcode: u16, r: &mut Reader<'_>, out: &mut Out) -> Result<bool> {
    let handled = match super::ogf(opcode) {
        1..=6 => super::cmd_classic::command_params(st, opcode, r, out)?,
        8 if super::ocf(opcode) <= 0x0060 => super::cmd_le_a::command_params(st, opcode, r, out)?,
        8 => super::cmd_le_b::command_params(st, opcode, r, out)?,
        super::OGF_VENDOR => super::vendor::command_params(st, opcode, r, out)?,
        _ => false,
    };
    // Known commands without parameters have nothing to decode.
    Ok(handled || (r.is_empty() && command_name(opcode).is_some()))
}

/// Decode the return parameters (Command Complete) of the command with the given opcode.
pub fn return_params(st: &mut IndexState, opcode: u16, r: &mut Reader<'_>, out: &mut Out) -> Result<bool> {
    let handled = match super::ogf(opcode) {
        1..=6 => super::cmd_classic::return_params(st, opcode, r, out)?,
        8 if super::ocf(opcode) <= 0x0060 => super::cmd_le_a::return_params(st, opcode, r, out)?,
        8 => super::cmd_le_b::return_params(st, opcode, r, out)?,
        super::OGF_VENDOR => super::vendor::return_params(st, opcode, r, out)?,
        _ => false,
    };
    if handled {
        return Ok(true);
    }
    // Most commands return nothing but a status.
    if r.remaining() == 1 {
        status(r, out)?;
        return Ok(true);
    }
    Ok(false)
}
