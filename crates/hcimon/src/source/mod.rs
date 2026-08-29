//! Packet sources.
//!
//! Every source runs on its own thread and delivers [`Event`]s through a
//! channel.  The [`SourceManager`] owns the threads and offers a uniform way
//! to add and remove sources at runtime, which the interactive UI uses to
//! attach to boards as they appear.

pub mod discovery;
pub mod file;
#[cfg(target_os = "linux")]
pub mod kernel;
#[cfg(feature = "rtt")]
pub mod rtt;
pub mod tty;

use std::fmt;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::Result;
use hcimon_capture::Packet;
use crossbeam_channel::Sender;

/// Identifies a source within a session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SourceId(pub u32);

impl fmt::Display for SourceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "S{}", self.0)
    }
}

/// What a source reads from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceKind {
    Tty { path: String, baud: u32 },
    Rtt { chip: String, probe: Option<String>, channel: Option<String>, reset: bool },
    File { path: String },
    Kernel,
}

impl SourceKind {
    /// Short label used in the UI.
    pub fn label(&self) -> String {
        match self {
            SourceKind::Tty { path, baud } => format!("{} @{}", short_path(path), baud),
            SourceKind::Rtt { chip, probe, .. } => match probe {
                Some(p) => format!("RTT {chip} ({p})"),
                None => format!("RTT {chip}"),
            },
            SourceKind::File { path } => short_path(path).to_string(),
            SourceKind::Kernel => "kernel".to_string(),
        }
    }
}

/// Strip `/dev/serial/by-id/` style prefixes for display.
pub fn short_path(path: &str) -> &str {
    path.strip_prefix("/dev/serial/by-id/").unwrap_or(path)
}

/// Something a source has to say.
#[derive(Debug)]
pub enum Event {
    Packet { source: SourceId, packet: Packet },
    /// Human readable status change (connected, reconnecting, ...).
    Status { source: SourceId, message: String },
    /// The source has finished (end of file, or stopped).
    Eof { source: SourceId },
    /// The source failed; it will not deliver more packets.
    Error { source: SourceId, message: String },
}

/// Handle to a running source thread.
pub struct SourceHandle {
    pub id: SourceId,
    pub kind: SourceKind,
    stop: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl SourceHandle {
    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(t) = self.thread.take() {
            let _ = t.join();
        }
    }

    pub fn is_finished(&self) -> bool {
        self.thread.as_ref().map(|t| t.is_finished()).unwrap_or(true)
    }
}

impl Drop for SourceHandle {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Shared context handed to every source thread.
#[derive(Clone)]
pub struct SourceCtx {
    pub id: SourceId,
    pub tx: Sender<Event>,
    pub stop: Arc<AtomicBool>,
}

impl SourceCtx {
    pub fn stopped(&self) -> bool {
        self.stop.load(Ordering::Relaxed)
    }

    pub fn packet(&self, packet: Packet) -> bool {
        self.tx.send(Event::Packet { source: self.id, packet }).is_ok()
    }

    pub fn status(&self, message: impl Into<String>) {
        let _ = self.tx.send(Event::Status { source: self.id, message: message.into() });
    }

    pub fn error(&self, message: impl Into<String>) {
        let _ = self.tx.send(Event::Error { source: self.id, message: message.into() });
    }

    pub fn eof(&self) {
        let _ = self.tx.send(Event::Eof { source: self.id });
    }

    /// Sleep in small steps so that a stop request is noticed promptly.
    pub fn sleep(&self, d: Duration) {
        let step = Duration::from_millis(50);
        let mut left = d;
        while !self.stopped() && !left.is_zero() {
            let s = left.min(step);
            std::thread::sleep(s);
            left -= s;
        }
    }
}

/// Owns all sources of a session.
pub struct SourceManager {
    tx: Sender<Event>,
    next_id: u32,
    sources: Vec<SourceHandle>,
}

impl SourceManager {
    pub fn new(tx: Sender<Event>) -> Self {
        SourceManager { tx, next_id: 1, sources: Vec::new() }
    }

    pub fn sources(&self) -> &[SourceHandle] {
        &self.sources
    }

    pub fn get(&self, id: SourceId) -> Option<&SourceHandle> {
        self.sources.iter().find(|s| s.id == id)
    }

    /// Start a source of the given kind.
    pub fn add(&mut self, kind: SourceKind) -> Result<SourceId> {
        let id = SourceId(self.next_id);
        self.next_id += 1;
        let stop = Arc::new(AtomicBool::new(false));
        let ctx = SourceCtx { id, tx: self.tx.clone(), stop: stop.clone() };
        let thread = match &kind {
            SourceKind::Tty { path, baud } => tty::spawn(ctx, path.clone(), *baud)?,
            SourceKind::File { path } => file::spawn(ctx, path.clone())?,
            #[cfg(feature = "rtt")]
            SourceKind::Rtt { chip, probe, channel, reset } => rtt::spawn(ctx, chip.clone(), probe.clone(), channel.clone(), *reset)?,
            #[cfg(not(feature = "rtt"))]
            SourceKind::Rtt { .. } => anyhow::bail!("this build has no RTT support (enable the `rtt` feature)"),
            #[cfg(target_os = "linux")]
            SourceKind::Kernel => kernel::spawn(ctx)?,
            #[cfg(not(target_os = "linux"))]
            SourceKind::Kernel => anyhow::bail!("the kernel monitor socket is only available on Linux"),
        };
        self.sources.push(SourceHandle { id, kind, stop, thread: Some(thread) });
        Ok(id)
    }

    /// Stop and forget a source.
    pub fn remove(&mut self, id: SourceId) -> bool {
        if let Some(pos) = self.sources.iter().position(|s| s.id == id) {
            let mut s = self.sources.remove(pos);
            s.stop();
            true
        } else {
            false
        }
    }

    /// Stop everything.
    pub fn stop_all(&mut self) {
        for s in &mut self.sources {
            s.stop.store(true, Ordering::Relaxed);
        }
        for s in &mut self.sources {
            s.stop();
        }
        self.sources.clear();
    }

    pub fn any_running(&self) -> bool {
        self.sources.iter().any(|s| !s.is_finished())
    }
}
