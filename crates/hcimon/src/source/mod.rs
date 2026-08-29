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
use hcimon_capture::tty::Frame;
use hcimon_capture::{Opcode, Packet, Timestamp};
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

/// Turns the free-running 100 µs tick of the monitor stream into wall-clock
/// timestamps: the first packet is anchored at the host's clock and later
/// ones follow the device's own tick, which is finer and steadier than the
/// host's arrival time.
///
/// Ticks are not monotonic in the stream: Zephyr stamps log records when
/// they are created and sends them later, so a record may carry a tick up to
/// a second or so older than its predecessor.  Those keep the anchor.  The
/// clock re-anchors when the tick jumps back by more than [`REBOOT_JUMP`],
/// or by any amount on a record that announces a boot (New Index / Open
/// Index, which sources flag with [`TickClock::reboot_announced`]; the very
/// first frame after a reboot is often cut, so either record counts).  A
/// wrap of the 32-bit counter near its maximum is carried into the next
/// epoch.  Re-anchoring happens only when the tick really did go backwards:
/// every anchor takes the host-side delay of that one frame into the
/// timeline, so an Open Index following New Index must not anchor again.
#[derive(Debug, Default)]
pub struct TickClock {
    anchor_wall_us: i64,
    anchor_tick: u64,
    epoch: u64,
    high_water: u64,
    anchored: bool,
    reboot_hint: bool,
}

/// Backwards jump (in 100 µs ticks) taken as a device reboot: 5 s, well above
/// the lag of deferred log records (about a second) and below most uptimes.
const REBOOT_JUMP: u64 = 50_000;

impl TickClock {
    pub fn new() -> Self {
        Self::default()
    }

    /// The next tick belongs to a record announcing a boot: if it is smaller
    /// than what was seen before, the device's clock started over.
    pub fn reboot_announced(&mut self) {
        self.reboot_hint = true;
    }

    fn restart(&mut self) {
        self.anchored = false;
        self.epoch = 0;
        self.high_water = 0;
    }

    pub fn wall(&mut self, tick100us: u32) -> Timestamp {
        let now = Timestamp::now().micros();
        let raw = tick100us as u64;
        let announced = std::mem::take(&mut self.reboot_hint);
        if self.anchored {
            if raw + REBOOT_JUMP < self.high_water && self.high_water > u32::MAX as u64 - REBOOT_JUMP {
                // Counter wrapped (the previous ticks were near the maximum).
                self.epoch += 1u64 << 32;
                self.high_water = raw;
            } else if raw + REBOOT_JUMP < self.high_water || (announced && raw < self.high_water) {
                self.restart();
            }
        }
        let tick = raw + self.epoch;
        if !self.anchored {
            self.anchor_wall_us = now;
            self.anchor_tick = tick;
            self.anchored = true;
            self.high_water = raw;
        }
        self.high_water = self.high_water.max(raw);
        Timestamp::Wall(self.anchor_wall_us + tick as i64 * 100 - self.anchor_tick as i64 * 100)
    }
}

/// Strip `/dev/serial/by-id/` style prefixes for display.
/// Silence after which an incomplete frame at the head of a device stream is
/// given up on (see [`hcimon_capture::tty::Framer::abandon`]).  A frame in
/// transmission never pauses this long; a device reset mid-frame does.
pub const QUIET_RESYNC: Duration = Duration::from_millis(300);

/// Turn a frame from a device stream into a packet with a wall-clock timestamp.
pub fn stamp(frame: Frame, clock: &mut TickClock) -> Packet {
    let mut pkt = frame.packet;
    if matches!(pkt.opcode, Opcode::NewIndex | Opcode::OpenIndex) {
        // Sent first after a (re)boot; the clock re-anchors if the tick restarted.
        clock.reboot_announced();
    }
    pkt.ts = Some(match frame.ts32 {
        Some(t) => clock.wall(t),
        None => Timestamp::now(),
    });
    pkt
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tick_clock_follows_device_ticks_and_reanchors() {
        let mut c = TickClock::new();
        let t0 = c.wall(1000).micros();
        let t1 = c.wall(1010).micros();
        assert_eq!(t1 - t0, 1000, "10 ticks of 100 µs");
        // A late log record (tick slightly in the past) keeps the anchor and gets an earlier time.
        let t2 = c.wall(990).micros();
        assert_eq!(t0 - t2, 1000);
        let t3 = c.wall(1020).micros();
        assert_eq!(t3 - t0, 2000);
        // Wrap of the 32-bit counter keeps counting forward.
        let mut c = TickClock::new();
        let a = c.wall(u32::MAX - 5).micros();
        let b = c.wall(4).micros();
        assert_eq!(b - a, 10 * 100);
        // A jump backwards of more than a few seconds is a reboot: time restarts near "now".
        let mut c = TickClock::new();
        let a = c.wall(150_000).micros();
        let b = c.wall(10).micros();
        assert!(b >= a - 1_000_000, "re-anchored near the host clock, not 500 s in the past");
        // A boot announcement (New Index) does the same for small ticks ...
        let mut c = TickClock::new();
        let a = c.wall(200_000).micros();
        c.reboot_announced();
        let b = c.wall(5).micros();
        assert!(b >= a - 1_000_000);
        // ... but the Open Index that follows keeps the fresh anchor: the device's
        // 300 µs stay 300 µs instead of the host's delay between the two frames.
        c.reboot_announced();
        let d = c.wall(8).micros();
        assert_eq!(d - b, 300);
        // Nor does an announcement with ticks still running forward re-anchor.
        let mut c = TickClock::new();
        let a = c.wall(1_000).micros();
        c.reboot_announced();
        assert_eq!(c.wall(1_010).micros() - a, 1_000);
    }
}
