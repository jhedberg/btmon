//! The BlueZ *monitor* protocol and the container formats it travels in.
//!
//! Every piece of HCI traffic (and a handful of housekeeping records such as
//! "new controller index" or "user logging") is represented as a
//! [`Packet`]: an opcode, a controller index, an optional timestamp and a
//! payload.  This crate knows how to read and write packets in the formats
//! that carry them:
//!
//! * the framed byte stream that Zephyr's `bt_monitor` produces over a UART
//!   or an RTT channel ([`tty::Framer`]),
//! * btsnoop files as written by `btmon -w` ([`btsnoop::Reader`] /
//!   [`btsnoop::Writer`]), including the plain HCI / H4 datalink variants,
//! * Apple PacketLogger (`.pklg`) files ([`btsnoop::Reader`] detects them).
//!
//! The protocol is documented in BlueZ's `doc/btsnoop-protocol.rst`.

pub mod btsnoop;
mod packet;
pub mod tty;

pub use packet::{Bus, ControllerType, IndexInfo, NewIndex, Opcode, Packet, Priority, Timestamp, UserLogging};

/// Largest payload a monitor packet may carry (BlueZ `BTSNOOP_MAX_PACKET_SIZE`).
pub const MAX_PACKET_SIZE: usize = 1486 + 4;

/// Controller index used for records that are not tied to a controller.
pub const INDEX_NONE: u16 = 0xffff;
