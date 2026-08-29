//! Command line interface.

use std::path::PathBuf;

use clap::{ArgAction, Parser, ValueEnum};

/// Bluetooth HCI monitor.
///
/// Captures and decodes HCI traffic from Zephyr devices (monitor protocol over
/// a serial port or RTT), btsnoop / PacketLogger files and, on Linux, the
/// kernel's HCI monitor socket.  Runs an interactive terminal UI when stdout
/// is a terminal, otherwise prints btmon-style text.
#[derive(Debug, Parser)]
#[command(name = "hcimon", version, about, long_about = None, after_help = AFTER_HELP, disable_version_flag = true)]
pub struct Cli {
    /// Read packets from a capture file (btsnoop, Apple PacketLogger, or a raw monitor stream)
    #[arg(short = 'r', long = "read", value_name = "FILE")]
    pub read: Vec<PathBuf>,

    /// Write all captured packets to a btsnoop file
    #[arg(short = 'w', long = "write", value_name = "FILE")]
    pub write: Option<PathBuf>,

    /// Read the monitor protocol from a serial port (repeatable)
    #[arg(short = 'd', long = "tty", value_name = "DEVICE")]
    pub tty: Vec<String>,

    /// Serial port speed
    #[arg(short = 'B', long = "tty-speed", value_name = "BAUD", default_value_t = 115_200)]
    pub tty_speed: u32,

    /// Read the monitor protocol from an RTT up-channel via a debug probe
    ///
    /// The value is the probe-rs chip name, e.g. `nRF52832_xxAA` or `EFR32MG24B010F1536IM48`.
    #[cfg(feature = "rtt")]
    #[arg(short = 'R', long = "rtt", value_name = "CHIP")]
    pub rtt: Vec<String>,

    /// Debug probe to use for RTT, as `VID:PID`, `VID:PID:SERIAL` or a serial number
    #[cfg(feature = "rtt")]
    #[arg(long = "probe", value_name = "SELECTOR")]
    pub probe: Option<String>,

    /// RTT up-channel to read (index or name); defaults to the channel named "btmonitor", else 0
    #[cfg(feature = "rtt")]
    #[arg(long = "rtt-channel", value_name = "CHANNEL")]
    pub rtt_channel: Option<String>,

    /// Reset the target after attaching for RTT, so that the capture starts at boot
    #[cfg(feature = "rtt")]
    #[arg(long = "rtt-reset")]
    pub rtt_reset: bool,

    /// Read from the Linux kernel's HCI monitor socket (default when no other source is given)
    #[cfg(target_os = "linux")]
    #[arg(short = 'K', long = "kernel")]
    pub kernel: bool,

    /// Only show packets for the given controller index
    #[arg(short = 'i', long = "index", value_name = "N")]
    pub index: Option<u16>,

    /// Show wall-clock time instead of the offset from the first packet
    #[arg(short = 't', long = "time")]
    pub time: bool,

    /// Show date and wall-clock time
    #[arg(short = 'T', long = "date")]
    pub date: bool,

    /// Do not show timestamps
    #[arg(short = 'N', long = "no-time")]
    pub no_time: bool,

    /// Colored output
    #[arg(short = 'c', long = "color", value_enum, default_value_t = Color::Auto)]
    pub color: Color,

    /// Print btmon-style text instead of the interactive UI
    #[arg(short = 'p', long = "plain", conflicts_with = "tui")]
    pub plain: bool,

    /// Run the interactive UI even if stdout is not a terminal
    #[arg(long = "tui")]
    pub tui: bool,

    /// Minimum priority of user logging records to show (0 = emerg .. 7 = debug, or a name)
    #[arg(short = 'P', long = "priority", value_name = "LEVEL")]
    pub priority: Option<String>,

    /// Decode SCO data payload (default: shown as hex)
    #[arg(short = 'S', long = "sco", action = ArgAction::SetTrue)]
    pub sco: bool,

    /// Decode ISO data payload (default: shown as hex)
    #[arg(short = 'I', long = "iso", action = ArgAction::SetTrue)]
    pub iso: bool,

    /// Output width for plain mode (default: terminal width or 80)
    #[arg(short = 'C', long = "columns", value_name = "N")]
    pub columns: Option<usize>,

    /// Company identifier to assume for vendor-specific commands and events
    #[arg(short = 'V', long = "vendor", value_name = "ID")]
    pub vendor: Option<u16>,

    /// Display filter expression, e.g. 'att && handle == 0x1c' or 'status != Success'
    #[arg(short = 'Y', long = "filter", value_name = "EXPR")]
    pub filter: Option<String>,

    /// Output format for non-interactive use (implies --plain):
    /// text (btmon style), digest (one line per packet), jsonl (one JSON object per packet),
    /// summary (overview of the whole capture: statistics, connections, findings)
    #[arg(short = 'f', long = "format", value_enum, default_value_t = OutputFormat::Text)]
    pub format: OutputFormat,

    /// Also show N packets before and after every packet that matches --filter
    #[arg(short = 'X', long = "context", value_name = "N", default_value_t = 0)]
    pub context: usize,

    /// Print the filter expression language and field names, then exit
    /// (with -r FILE, also every field present in that capture)
    #[arg(long = "fields")]
    pub fields: bool,

    /// Run as a Model Context Protocol server on stdin/stdout, exposing capture analysis tools
    #[arg(long = "mcp")]
    pub mcp: bool,

    /// Keep at most this many packets in memory in the interactive UI
    #[arg(long = "max-packets", value_name = "N", default_value_t = 100_000)]
    pub max_packets: usize,

    /// List serial ports and debug probes that can be used as sources, then exit
    #[arg(long = "list")]
    pub list: bool,

    /// Print version information
    #[arg(short = 'v', long = "version", action = ArgAction::Version)]
    pub version: (),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Text,
    Digest,
    Jsonl,
    Summary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum Color {
    Auto,
    Always,
    Never,
}

const AFTER_HELP: &str = "\
Examples:
  hcimon --tty /dev/serial/by-id/usb-SEGGER_J-Link_000682451005-if00
  hcimon --rtt nRF52832_xxAA --probe 682451005
  hcimon -r capture.snoop -p
  hcimon -r capture.snoop -p -Y 'att && handle == 0x1c'
  hcimon -r capture.snoop -f summary                  # overview for scripts and LLM analysis
  hcimon -r capture.snoop -f digest -Y 'rtt > 5'      # one line per packet
  hcimon -r capture.snoop -f jsonl -Y 'frame == 66'   # full decode as JSON
  hcimon -r capture.snoop -Y 'error' -X 3 -f digest   # matches with 3 packets of context
  hcimon --fields -r capture.snoop                    # filter field dictionary
  hcimon --mcp                                        # MCP server for LLM clients
  hcimon --tty /dev/ttyACM0 -w capture.snoop

Sources can also be added interactively in the UI (press 'a').";

/// Parse a priority name or number.
pub fn parse_priority(s: &str) -> Option<u8> {
    if let Ok(n) = s.parse::<u8>() {
        return (n <= 7).then_some(n);
    }
    Some(match s.to_ascii_lowercase().as_str() {
        "emerg" | "emergency" => 0,
        "alert" => 1,
        "crit" | "critical" => 2,
        "err" | "error" => 3,
        "warn" | "warning" => 4,
        "notice" => 5,
        "info" => 6,
        "debug" | "dbg" => 7,
        _ => return None,
    })
}
