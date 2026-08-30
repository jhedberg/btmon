//! A capture session: sources, the decoder state, an optional capture file and
//! the packet store shared by the outputs.

use std::collections::HashMap;
use std::io::{self, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use hcimon_decode::{decode, expert, Context as DecodeContext, Decoded, FieldIndex, Finding, LinkKind, Options, Packet, PacketMeta, Query, Timestamp};
use hcimon_capture::btsnoop;
use crossbeam_channel::{unbounded, Receiver, RecvTimeoutError};

use crate::output::{machine, plain::Printer, Format};
use crate::source::{Event, SourceId, SourceKind, SourceManager};
use crate::time::TimeMode;

#[derive(Debug, Clone)]
pub struct SessionConfig {
    pub write: Option<PathBuf>,
    pub index: Option<u16>,
    pub priority: Option<u8>,
    pub time_mode: TimeMode,
    pub sco: bool,
    pub iso: bool,
    pub vendor: Option<u16>,
    pub max_packets: usize,
    pub color: bool,
    pub columns: usize,
    /// Display filter applied in plain mode (the UI keeps its own).
    pub filter: Option<Query>,
    /// Packets of context to print around each match in plain mode.
    pub context: usize,
    /// Print the RTT terminal channel (shell / console) in plain mode.
    pub rtt_terminal: bool,
}

/// A reference to another packet of the session (request/response pairing).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ref {
    pub kind: LinkKind,
    pub seq: u64,
    pub elapsed_us: Option<i64>,
}

impl Ref {
    /// Wording for the link, e.g. `Response to` / `Completed by`.
    pub fn what(&self) -> &'static str {
        match self.kind {
            LinkKind::ResponseTo => "Response to",
            LinkKind::AnsweredBy => "Answered by",
            LinkKind::Completes => "Completes",
            LinkKind::CompletedBy => "Completed by",
        }
    }

    /// `1.234 ms` style text for the round-trip time.
    pub fn elapsed_text(&self) -> String {
        match self.elapsed_us {
            Some(us) => format!("{:.3} ms", us as f64 / 1000.0),
            None => String::new(),
        }
    }
}

/// A captured packet together with its decoding.
#[derive(Debug, Clone)]
pub struct Entry {
    /// Sequence number within the session (1-based, never reused).
    pub seq: u64,
    pub source: SourceId,
    pub packet: Packet,
    pub decoded: Decoded,
    /// Typed fields for filter expressions.
    pub index: FieldIndex,
    /// Requests this packet answers and responses that answered it, in session numbers.
    pub refs: Vec<Ref>,
    /// Expert findings (problems worth a look), most severe first.
    pub findings: Vec<Finding>,
}

pub struct Session {
    pub config: SessionConfig,
    pub sources: SourceManager,
    rx: Receiver<Event>,
    /// Decoder state per source (controller indexes are only unique within a source).
    contexts: HashMap<SourceId, DecodeContext>,
    writer: Option<btsnoop::Writer<std::fs::File>>,
    /// Why recording stopped, until someone asks.
    recording_error: Option<String>,
    next_seq: u64,
    pub first_ts: Option<Timestamp>,
    pub packets_total: u64,
}

impl Session {
    pub fn new(config: SessionConfig) -> Result<Self> {
        let (tx, rx) = unbounded();
        let writer = match &config.write {
            Some(path) => Some(
                btsnoop::Writer::create(path, btsnoop::Format::Monitor)
                    .with_context(|| format!("failed to create {}", path.display()))?,
            ),
            None => None,
        };
        Ok(Session {
            sources: SourceManager::new(tx),
            rx,
            contexts: HashMap::new(),
            writer,
            recording_error: None,
            next_seq: 1,
            first_ts: None,
            packets_total: 0,
            config,
        })
    }

    pub fn sources(&self) -> &[crate::source::SourceHandle] {
        self.sources.sources()
    }

    pub fn add_source(&mut self, kind: SourceKind) -> Result<SourceId> {
        self.sources.add(kind)
    }

    /// Send keystrokes to a source's terminal channel (the shell over RTT).
    pub fn send_terminal(&self, id: SourceId, bytes: &[u8]) -> bool {
        self.sources.send_terminal(id, bytes)
    }

    pub fn remove_source(&mut self, id: SourceId) -> bool {
        self.contexts.remove(&id);
        self.sources.remove(id)
    }

    /// Label used to distinguish sources in the outputs when more than one is active.
    pub fn source_label(&self, id: SourceId) -> Option<String> {
        if self.sources.sources().len() <= 1 {
            return None;
        }
        self.sources.get(id).map(|s| s.kind.label())
    }

    fn decode_options(&self) -> Options {
        Options { sco: self.config.sco, iso: self.config.iso, fallback_manufacturer: self.config.vendor }
    }

    /// Wait for the next event from any source.
    pub fn next_event(&self, timeout: Duration) -> Option<Event> {
        match self.rx.recv_timeout(timeout) {
            Ok(e) => Some(e),
            Err(RecvTimeoutError::Timeout) | Err(RecvTimeoutError::Disconnected) => None,
        }
    }

    /// The channel that sources deliver events on.
    pub fn receiver(&self) -> &Receiver<Event> {
        &self.rx
    }

    /// Start (or switch) recording to a btsnoop file, first writing every packet in `existing`.
    ///
    /// Returns the number of packets written from the backlog.
    pub fn start_writing(&mut self, path: &str, existing: &[Entry]) -> Result<usize> {
        let mut w = btsnoop::Writer::create(path, btsnoop::Format::Monitor).with_context(|| format!("failed to create {path}"))?;
        let mut n = 0;
        for e in existing {
            if w.write_packet(&e.packet)? {
                n += 1;
            }
        }
        w.flush()?;
        self.writer = Some(w);
        self.config.write = Some(PathBuf::from(path));
        Ok(n)
    }

    /// Decode a packet, record it in the capture file and apply the index/priority filters.
    ///
    /// Returns `None` when the packet is filtered out.
    pub fn ingest(&mut self, source: SourceId, packet: Packet) -> Option<Entry> {
        self.packets_total += 1;
        if let Some(w) = self.writer.as_mut() {
            // Flush per packet so that a capture survives an abrupt exit.
            if let Err(e) = w.write_packet(&packet).and_then(|_| w.flush()) {
                self.fail_recording(e);
            }
        }
        if let Some(idx) = self.config.index {
            if packet.index != idx && packet.index != hcimon_capture::INDEX_NONE {
                return None;
            }
        }
        if self.first_ts.is_none() {
            self.first_ts = packet.ts;
        }
        let options = self.decode_options();
        let ctx = self.contexts.entry(source).or_insert_with(|| DecodeContext::with_options(options));
        let decoded = decode(ctx, &packet);
        if let (Some(min), Some(p)) = (self.config.priority, decoded.priority) {
            if p > min {
                return None;
            }
        }
        let seq = self.next_seq;
        self.next_seq += 1;
        let label = self.sources.get(source).map(|s| s.kind.label()).unwrap_or_default();
        let index = FieldIndex::build(&decoded, &packet, PacketMeta { seq, source: &label });
        let findings = expert::assess(&decoded, &packet, &index);
        Some(Entry { seq, source, packet, decoded, index, refs: Vec::new(), findings })
    }

    pub fn flush_writer(&mut self) {
        if let Some(w) = self.writer.as_mut() {
            if let Err(e) = w.flush() {
                self.fail_recording(e);
            }
        }
    }

    /// Recording stopped: drop the writer rather than fail on every packet,
    /// and keep the reason for whoever reports it.
    fn fail_recording(&mut self, e: io::Error) {
        let path = self.config.write.as_ref().map(|p| p.display().to_string()).unwrap_or_default();
        self.writer = None;
        self.recording_error = Some(format!("recording to {path} stopped: {e}"));
    }

    /// The reason recording stopped, if it did since the last call.
    pub fn take_recording_error(&mut self) -> Option<String> {
        self.recording_error.take()
    }


    /// Plain streaming mode: print until every source has finished, or until
    /// SIGINT/SIGTERM, which stop the sources and close the capture file cleanly.
    /// Stream everything to stdout until the sources are done or Ctrl-C.
    /// Returns whether a source failed (its error has been printed), so the
    /// caller can exit with a failure status.
    pub fn run_plain(mut self, format: Format) -> Result<bool> {
        let stop = Arc::new(AtomicBool::new(false));
        {
            let stop = stop.clone();
            let _ = ctrlc::set_handler(move || stop.store(true, Ordering::Relaxed));
        }
        let stdout = io::stdout();
        let mut out = io::BufWriter::new(stdout.lock());
        let mut printer = Printer::new(io::BufWriter::new(io::stdout()), self.config.color, self.config.columns, self.config.time_mode);
        // The summary needs the whole capture.
        let mut kept: Vec<Entry> = Vec::new();
        // Context windows: recent non-matching packets, and how many more to print after a match.
        let context = if self.config.filter.is_some() { self.config.context } else { 0 };
        let mut before: std::collections::VecDeque<Entry> = std::collections::VecDeque::new();
        let mut after_left = 0usize;
        let mut last_printed: Option<u64> = None;
        let mut failed = false;
        // One terminal emulator per source with a shell / console channel.
        let mut terminals: std::collections::HashMap<SourceId, crate::terminal::Terminal> = std::collections::HashMap::new();
        loop {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            match self.next_event(Duration::from_millis(200)) {
                Some(Event::Packet { source, packet }) => {
                    let entry = self.ingest(source, packet);
                    if let Some(err) = self.take_recording_error() {
                        failed = true;
                        printer.flush()?;
                        eprintln!("hcimon: {err}");
                    }
                    if let Some(entry) = entry {
                        printer.set_origin(self.first_ts);
                        let matches = self.config.filter.as_ref().is_none_or(|q| q.matches(&entry.index));
                        let mut to_print: Vec<(Entry, bool)> = Vec::new();
                        if matches {
                            for e in before.drain(..) {
                                to_print.push((e, true));
                            }
                            to_print.push((entry, false));
                            after_left = context;
                        } else if after_left > 0 {
                            after_left -= 1;
                            to_print.push((entry, true));
                        } else if context > 0 {
                            if before.len() >= context {
                                before.pop_front();
                            }
                            before.push_back(entry);
                            continue;
                        } else {
                            continue;
                        }
                        for (entry, is_context) in to_print {
                            if context > 0 && last_printed.is_some_and(|l| entry.seq != l + 1) && format != Format::Summary {
                                writeln!(out, "--")?;
                            }
                            last_printed = Some(entry.seq);
                            // Context packets may come from another source than the match.
                            let label = self.source_label(entry.source);
                            match format {
                                Format::Text => {
                                    printer.flush()?;
                                    printer.print(&entry.packet, &entry.decoded, label.as_deref())?;
                                    printer.flush()?;
                                }
                                Format::Digest => {
                                    if is_context {
                                        write!(out, "  ")?;
                                    }
                                    machine::write_digest(&mut out, &entry, self.first_ts)?;
                                }
                                Format::Jsonl => {
                                    let src = self.sources.get(entry.source).map(|s| s.kind.label()).unwrap_or_default();
                                    machine::write_jsonl(&mut out, &entry, self.first_ts, &src)?
                                }
                                Format::Summary => kept.push(entry),
                            }
                        }
                    }
                }
                Some(Event::Status { source, message }) => {
                    if format == Format::Text {
                        let label = self.source_label(source);
                        match label {
                            Some(l) => printer.note(&format!("{l}: {message}"))?,
                            None => printer.note(&message)?,
                        }
                    }
                }
                Some(Event::Terminal { source, data }) => {
                    if self.config.rtt_terminal && format == Format::Text {
                        let term = terminals.entry(source).or_insert_with(|| crate::terminal::Terminal::new(2).with_size(usize::MAX / 4, 2).recording_completed());
                        term.feed(&data);
                        let label = self.source_label(source);
                        for line in term.take_completed() {
                            match &label {
                                Some(l) => printer.shell(&format!("{l}: {line}"))?,
                                None => printer.shell(&line)?,
                            }
                        }
                    }
                }
                Some(Event::Error { source, message }) => {
                    failed = true;
                    let label = self.source_label(source).unwrap_or_default();
                    printer.flush()?;
                    eprintln!("hcimon: {label}{}{message}", if label.is_empty() { "" } else { ": " });
                }
                Some(Event::Eof { .. }) => {}
                None => {}
            }
            printer.flush()?;
            out.flush()?;
            if !self.sources.any_running() && self.rx.is_empty() {
                break;
            }
        }
        if format == Format::Summary {
            machine::write_summary(&mut out, &kept)?;
            out.flush()?;
        }
        self.flush_writer();
        if let Some(err) = self.take_recording_error() {
            failed = true;
            eprintln!("hcimon: {err}");
        }
        Ok(failed)
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        self.sources.stop_all();
        self.flush_writer();
    }
}
