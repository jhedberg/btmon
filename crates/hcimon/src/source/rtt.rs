//! RTT source: Zephyr's monitor protocol over a SEGGER RTT up-channel, read
//! through a debug probe with probe-rs.
//!
//! Zephyr names the channel `btmonitor` (`CONFIG_BT_DEBUG_MONITOR_RTT`).  The
//! source survives target resets: when the control block disappears it
//! re-attaches and continues.  It can also read the terminal channel (up-buffer
//! 0, Zephyr's shell and console) and write keystrokes to the matching
//! down-buffer, so a shell over RTT works through the same probe session.

use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use crossbeam_channel::{unbounded, Receiver, Sender};
use hcimon_capture::tty::Framer;
use probe_rs::probe::list::Lister;
use probe_rs::probe::DebugProbeSelector;
use probe_rs::rtt::{DownChannel, Rtt, ScanRegion};
use probe_rs::{Core, MemoryInterface, Permissions, Session};

use super::discovery::ProbeCandidate;
use super::{SourceCtx, TickClock};

const DEFAULT_CHANNEL_NAME: &str = "btmonitor";
const IDLE_POLL: Duration = Duration::from_millis(5);
const RETRY_DELAY: Duration = Duration::from_millis(500);
/// How long to keep trying to push shell input into a full down-buffer.
const INPUT_TIMEOUT: Duration = Duration::from_millis(500);

/// Probes currently attached to the host.
pub fn list_probes() -> Vec<ProbeCandidate> {
    Lister::new()
        .list_all()
        .into_iter()
        .map(|p| ProbeCandidate {
            name: p.identifier.clone(),
            selector: match &p.serial_number {
                Some(s) => format!("{:04x}:{:04x}:{}", p.vendor_id, p.product_id, s),
                None => format!("{:04x}:{:04x}", p.vendor_id, p.product_id),
            },
            serial: p.serial_number.clone(),
        })
        .collect()
}

pub fn spawn(
    ctx: SourceCtx,
    chip: String,
    probe: Option<String>,
    channel: Option<String>,
    reset: bool,
    terminal: bool,
) -> Result<(JoinHandle<()>, Option<Sender<Vec<u8>>>)> {
    // Validate the probe selector up front so that typos fail fast.
    let selector = resolve_probe(probe.as_deref())?;
    let (input_tx, input_rx) = if terminal {
        let (tx, rx) = unbounded();
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };
    let thread = std::thread::Builder::new()
        .name(format!("rtt {chip}"))
        .spawn(move || run(ctx, chip, selector, channel, reset, input_rx))?;
    Ok((thread, input_tx))
}

/// Turn a user supplied probe description into a selector.
///
/// Accepts `VID:PID`, `VID:PID:SERIAL`, or just a serial number (matched
/// against the attached probes).  With no selector, the only attached probe
/// is used; several attached probes require an explicit choice.
fn resolve_probe(spec: Option<&str>) -> Result<DebugProbeSelector> {
    let probes = Lister::new().list_all();
    match spec {
        Some(s) if s.contains(':') => s.parse::<DebugProbeSelector>().map_err(|e| anyhow!("invalid probe selector {s:?}: {e}")),
        Some(s) => {
            let matches: Vec<_> = probes
                .iter()
                .filter(|p| p.serial_number.as_deref().map(|sn| sn == s || sn.trim_start_matches('0') == s.trim_start_matches('0')).unwrap_or(false))
                .collect();
            match matches.as_slice() {
                [p] => Ok(DebugProbeSelector::from(*p)),
                [] => bail!("no attached debug probe has serial number {s}"),
                _ => bail!("several probes match serial number {s}"),
            }
        }
        None => match probes.as_slice() {
            [p] => Ok(DebugProbeSelector::from(p)),
            [] => bail!("no debug probe attached"),
            many => {
                let list: Vec<String> = many
                    .iter()
                    .map(|p| format!("{} [{}]", p.identifier, p.serial_number.as_deref().unwrap_or("?")))
                    .collect();
                bail!("several debug probes attached, pick one with --probe: {}", list.join(", "))
            }
        },
    }
}

fn attach(chip: &str, selector: &DebugProbeSelector) -> Result<Session> {
    let probe = Lister::new().open(selector.clone()).with_context(|| format!("failed to open probe {selector}"))?;
    let session = probe.attach(chip, Permissions::default()).with_context(|| format!("failed to attach to {chip}"))?;
    Ok(session)
}

fn find_channel(rtt: &mut Rtt, wanted: Option<&str>) -> Result<usize> {
    let channels = rtt.up_channels();
    if channels.is_empty() {
        bail!("the RTT control block has no up-channels");
    }
    match wanted {
        Some(w) => {
            if let Ok(n) = w.parse::<usize>() {
                if n < channels.len() {
                    return Ok(n);
                }
                bail!("RTT up-channel {n} does not exist ({} channels)", channels.len());
            }
            channels
                .iter()
                .position(|c| c.name() == Some(w))
                .ok_or_else(|| anyhow!("no RTT up-channel named {w:?}"))
        }
        None => Ok(channels.iter().position(|c| c.name() == Some(DEFAULT_CHANNEL_NAME)).unwrap_or(0)),
    }
}

/// Whether every channel name reads as text: a control block that is still
/// being initialised, or stale from a previous image, fails this.
fn channels_sane(rtt: &mut Rtt) -> bool {
    let ok = |name: Option<&str>| name.is_none_or(|n| n.chars().all(|c| c.is_ascii_graphic() || c == ' '));
    rtt.up_channels().iter().all(|c| ok(c.name())) && rtt.down_channels().iter().all(|c| ok(c.name()))
}

/// The terminal up-channel: buffer 0 unless that is the monitor, else the one
/// named "Terminal".
fn find_terminal(rtt: &mut Rtt, monitor: usize) -> Option<usize> {
    let channels = rtt.up_channels();
    if monitor != 0 && !channels.is_empty() {
        return Some(0);
    }
    channels.iter().position(|c| c.number() != monitor && c.name() == Some("Terminal"))
}

/// Write everything, waiting a little for the target to drain its buffer
/// (Zephyr's shell down-buffer is 16 bytes by default).  `Ok(false)` when
/// the target did not take the bytes in time.
fn write_all(core: &mut Core<'_>, chan: &mut DownChannel, mut bytes: &[u8], ctx: &SourceCtx) -> Result<bool, probe_rs::rtt::Error> {
    let deadline = Instant::now() + INPUT_TIMEOUT;
    while !bytes.is_empty() {
        let n = chan.write(core, bytes)?;
        bytes = &bytes[n..];
        if !bytes.is_empty() {
            if Instant::now() > deadline || ctx.stopped() {
                return Ok(false);
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }
    Ok(true)
}

fn run(ctx: SourceCtx, chip: String, selector: DebugProbeSelector, channel: Option<String>, reset: bool, input: Option<Receiver<Vec<u8>>>) {
    let mut buf = [0u8; 4096];
    let mut tbuf = [0u8; 4096];
    let mut first_attach = true;
    let mut reset_pending = reset;
    'attach: while !ctx.stopped() {
        let mut session = match attach(&chip, &selector) {
            Ok(s) => s,
            Err(e) => {
                if first_attach {
                    ctx.error(format!("{e:#}"));
                    return;
                }
                ctx.sleep(RETRY_DELAY);
                continue;
            }
        };
        let mut core = match session.core(0) {
            Ok(c) => c,
            Err(e) => {
                ctx.error(format!("failed to access core 0: {e}"));
                return;
            }
        };
        if reset_pending {
            reset_pending = false;
            // RAM keeps the control block of whatever ran before, and it looks
            // valid until the new firmware initialises its own (SEGGER writes
            // the ID last for that reason).  Blank the ID so that only the
            // fresh block is found after the reset.
            if let Ok(stale) = Rtt::attach_region(&mut core, &ScanRegion::Ram) {
                let _ = core.write_8(stale.ptr(), &[0u8; 16]);
            }
            match core.reset() {
                Ok(()) => ctx.status(format!("{chip}: target reset")),
                Err(e) => ctx.status(format!("{chip}: reset failed ({e})")),
            }
        }
        // The control block may not exist until the firmware has booted.
        let mut rtt = loop {
            if ctx.stopped() {
                return;
            }
            match Rtt::attach_region(&mut core, &ScanRegion::Ram) {
                // A block whose channel names are not text is one still being
                // set up (or left over from another image): try again shortly.
                Ok(mut r) => {
                    if channels_sane(&mut r) {
                        break r;
                    }
                    ctx.sleep(RETRY_DELAY);
                }
                Err(_) => {
                    if first_attach {
                        ctx.status(format!("{chip}: waiting for the RTT control block"));
                        first_attach = false;
                    }
                    ctx.sleep(RETRY_DELAY);
                }
            }
        };
        let idx = match find_channel(&mut rtt, channel.as_deref()) {
            Ok(i) => i,
            Err(e) => {
                ctx.error(format!("{e:#}"));
                return;
            }
        };
        let terminal = if input.is_some() { find_terminal(&mut rtt, idx) } else { None };
        let down = terminal.filter(|_| !rtt.down_channels().is_empty()).map(|_| 0);
        let ptr = rtt.ptr();
        let (number, name) = {
            let c = rtt.up_channel(idx).expect("channel index validated above");
            (c.number(), c.name().unwrap_or("unnamed").to_string())
        };
        let mut status = format!("{chip}: reading RTT channel {number} ({name}) at {ptr:#010x}");
        if let Some(t) = terminal {
            status.push_str(&format!(", terminal on channel {t}{}", if down.is_some() { " with input" } else { "" }));
        }
        ctx.status(status);
        first_attach = false;

        let mut framer = Framer::new();
        let mut clock = TickClock::new();
        let mut last_data = Instant::now();
        let mut input_dropped = false;
        while !ctx.stopped() {
            let mut busy = false;
            match rtt.up_channel(idx).expect("channel index validated above").read(&mut core, &mut buf) {
                Ok(0) => {
                    // The target went quiet: release a frame waiting for its successor
                    // and, after a longer silence, give up on an incomplete one.
                    let mut frame = framer.flush();
                    if frame.is_none() && last_data.elapsed() >= super::QUIET_RESYNC {
                        frame = framer.abandon();
                    }
                    while let Some(f) = frame {
                        if !ctx.packet(super::stamp(f, &mut clock)) {
                            return;
                        }
                        frame = framer.next_frame().or_else(|| framer.flush());
                    }
                }
                Ok(n) => {
                    busy = true;
                    last_data = Instant::now();
                    framer.push(&buf[..n]);
                    while let Some(frame) = framer.next_frame() {
                        if !ctx.packet(super::stamp(frame, &mut clock)) {
                            return;
                        }
                    }
                    if n == buf.len() {
                        // More is waiting: come straight back for it.
                        continue;
                    }
                }
                Err(e) => {
                    ctx.status(format!("{chip}: RTT read failed ({e}), re-attaching"));
                    ctx.sleep(RETRY_DELAY);
                    continue 'attach;
                }
            }
            // Drain the terminal channel: the target drops what does not fit
            // its buffer, and a burst of shell output can be several reads.
            for _ in 0..16 {
                let Some(t) = terminal else { break };
                match rtt.up_channel(t).expect("terminal channel validated above").read(&mut core, &mut tbuf) {
                    Ok(0) => break,
                    Ok(n) => {
                        busy = true;
                        last_data = Instant::now();
                        if !ctx.terminal(tbuf[..n].to_vec()) {
                            return;
                        }
                        if n < tbuf.len() {
                            break;
                        }
                    }
                    Err(e) => {
                        ctx.status(format!("{chip}: RTT read failed ({e}), re-attaching"));
                        ctx.sleep(RETRY_DELAY);
                        continue 'attach;
                    }
                }
            }
            // Keystrokes for the shell: whatever is queued, and while idle wait
            // for the next one instead of sleeping so that typing feels immediate.
            let mut pending: Vec<Vec<u8>> = Vec::new();
            if let Some(rx) = &input {
                while let Ok(bytes) = rx.try_recv() {
                    pending.push(bytes);
                }
                if pending.is_empty() && !busy {
                    let idle = last_data.elapsed();
                    let wait = if idle > Duration::from_secs(2) { IDLE_POLL * 4 } else { IDLE_POLL };
                    if let Ok(bytes) = rx.recv_timeout(wait) {
                        pending.push(bytes);
                    }
                }
            } else if !busy {
                let idle = last_data.elapsed();
                std::thread::sleep(if idle > Duration::from_secs(2) { IDLE_POLL * 4 } else { IDLE_POLL });
            }
            for bytes in pending {
                let Some(d) = down else {
                    if !input_dropped {
                        ctx.status(format!("{chip}: the target has no RTT down-channel, shell input is discarded"));
                        input_dropped = true;
                    }
                    break;
                };
                let chan = rtt.down_channel(d).expect("down-channel validated above");
                match write_all(&mut core, chan, &bytes, &ctx) {
                    Ok(true) => {}
                    Ok(false) => {
                        if !input_dropped {
                            ctx.status(format!("{chip}: shell input dropped, the target is not reading its RTT down-channel"));
                            input_dropped = true;
                        }
                    }
                    Err(e) => {
                        ctx.status(format!("{chip}: RTT write failed ({e}), re-attaching"));
                        ctx.sleep(RETRY_DELAY);
                        continue 'attach;
                    }
                }
            }
        }
    }
    ctx.eof();
}
