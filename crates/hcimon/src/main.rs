//! btmon — cross-platform Bluetooth HCI monitor.

mod analysis;
mod cli;
mod conversations;
mod mcp;
mod output;
mod session;
mod source;
mod stats;
mod terminal;
mod time;
mod tui;

use std::io::{self, IsTerminal, Write};
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::Parser;

use cli::{Cli, Color, OutputFormat};
use output::Format;
use session::{Session, SessionConfig};
use source::{discovery, SourceKind};
use time::TimeMode;

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            // A closed pipe (`hcimon ... | head`) is not an error worth reporting.
            if e.downcast_ref::<io::Error>().map(|e| e.kind() == io::ErrorKind::BrokenPipe).unwrap_or(false) {
                return ExitCode::SUCCESS;
            }
            let _ = writeln!(io::stderr(), "hcimon: {e:#}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    if cli.list {
        list_devices()?;
        return Ok(ExitCode::SUCCESS);
    }
    if cli.mcp {
        mcp::serve()?;
        return Ok(ExitCode::SUCCESS);
    }
    if cli.fields {
        let loaded = match cli.read.first() {
            Some(p) => Some(analysis::Loaded::from_file(&p.to_string_lossy())?),
            None => None,
        };
        print!("{}", analysis::field_dictionary(loaded.as_ref()));
        return Ok(ExitCode::SUCCESS);
    }

    let stdout_tty = io::stdout().is_terminal();
    let format = match cli.format {
        OutputFormat::Text => Format::Text,
        OutputFormat::Digest => Format::Digest,
        OutputFormat::Jsonl => Format::Jsonl,
        OutputFormat::Summary => Format::Summary,
    };
    let interactive = cli.tui || (!cli.plain && stdout_tty && format == Format::Text);
    #[allow(unused_mut, unused_assignments)]
    let mut rtt_terminal = false;
    #[cfg(feature = "rtt")]
    {
        rtt_terminal = cli.rtt_terminal;
    }

    let mut kinds: Vec<SourceKind> = Vec::new();
    for path in &cli.read {
        kinds.push(SourceKind::File { path: path.to_string_lossy().into_owned() });
    }
    for path in &cli.tty {
        kinds.push(SourceKind::Tty { path: path.clone(), baud: cli.tty_speed });
    }
    #[cfg(feature = "rtt")]
    for chip in &cli.rtt {
        kinds.push(SourceKind::Rtt {
            chip: chip.clone(),
            probe: cli.probe.clone(),
            channel: cli.rtt_channel.clone(),
            reset: cli.rtt_reset,
            // The UI offers the shell pane; plain mode prints the channel on request.
            terminal: interactive || rtt_terminal,
        });
    }
    #[cfg(target_os = "linux")]
    if cli.kernel {
        kinds.push(SourceKind::Kernel);
    }

    #[cfg(target_os = "linux")]
    if kinds.is_empty() && !interactive {
        // Same default as BlueZ's btmon: the local kernel.
        kinds.push(SourceKind::Kernel);
    }

    let time_mode = if cli.no_time {
        TimeMode::None
    } else if cli.date {
        TimeMode::DateTime
    } else if cli.time {
        TimeMode::Time
    } else {
        TimeMode::Offset
    };
    let priority = match &cli.priority {
        Some(p) => Some(cli::parse_priority(p).with_context(|| format!("invalid priority {p:?}"))?),
        None => None,
    };
    let color = match cli.color {
        Color::Always => true,
        Color::Never => false,
        Color::Auto => stdout_tty && std::env::var_os("NO_COLOR").is_none(),
    };
    let columns = cli.columns.or_else(|| ratatui::crossterm::terminal::size().ok().map(|(w, _)| w as usize)).unwrap_or(80);
    let filter = match &cli.filter {
        Some(f) => Some(hcimon_decode::Query::parse(f).map_err(|e| anyhow::anyhow!("invalid filter expression: {e}"))?),
        None => None,
    };

    let config = SessionConfig {
        write: cli.write.clone(),
        index: cli.index,
        priority,
        time_mode,
        sco: cli.sco,
        iso: cli.iso,
        vendor: cli.vendor,
        max_packets: cli.max_packets,
        color,
        columns,
        filter,
        context: cli.context,
        rtt_terminal,
    };

    let mut session = Session::new(config)?;
    let mut errors = Vec::new();
    for kind in kinds {
        if let Err(e) = session.add_source(kind.clone()) {
            errors.push(format!("{}: {e:#}", kind.label()));
        }
    }
    if !errors.is_empty() && session.sources().is_empty() && !interactive {
        anyhow::bail!("{}", errors.join("\n"));
    }
    for e in &errors {
        eprintln!("hcimon: {e}");
    }

    if interactive {
        tui::run(session, errors)?;
        Ok(ExitCode::SUCCESS)
    } else if session.run_plain(format)? {
        // A source failed and said so; scripts should notice.
        Ok(ExitCode::FAILURE)
    } else {
        Ok(ExitCode::SUCCESS)
    }
}

fn list_devices() -> Result<()> {
    let ports = discovery::serial_ports();
    println!("Serial ports:");
    if ports.is_empty() {
        println!("  (none)");
    }
    for p in ports {
        println!("  {}  {}  {}", p.path, p.device, p.description);
    }
    let probes = discovery::probes();
    println!("Debug probes:");
    if probes.is_empty() {
        println!("  (none)");
    }
    for p in probes {
        println!("  {}  {}", p.selector, p.name);
    }
    Ok(())
}
