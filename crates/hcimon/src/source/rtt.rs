//! RTT source: Zephyr's monitor protocol over a SEGGER RTT up-channel, read
//! through a debug probe with probe-rs.
//!
//! Zephyr names the channel `btmonitor` (`CONFIG_BT_DEBUG_MONITOR_RTT`).  The
//! source survives target resets: when the control block disappears it
//! re-attaches and continues.

use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use anyhow::{anyhow, bail, Context, Result};
use hcimon_capture::{tty::Framer, Timestamp};
use probe_rs::probe::list::Lister;
use probe_rs::probe::DebugProbeSelector;
use probe_rs::rtt::{Rtt, ScanRegion};
use probe_rs::{Permissions, Session};

use super::discovery::ProbeCandidate;
use super::{SourceCtx, TickClock};

const DEFAULT_CHANNEL_NAME: &str = "btmonitor";
const IDLE_POLL: Duration = Duration::from_millis(5);
const RETRY_DELAY: Duration = Duration::from_millis(500);

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

pub fn spawn(ctx: SourceCtx, chip: String, probe: Option<String>, channel: Option<String>, reset: bool) -> Result<JoinHandle<()>> {
    // Validate the probe selector up front so that typos fail fast.
    let selector = resolve_probe(probe.as_deref())?;
    let thread = std::thread::Builder::new()
        .name(format!("rtt {chip}"))
        .spawn(move || run(ctx, chip, selector, channel, reset))?;
    Ok(thread)
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

fn run(ctx: SourceCtx, chip: String, selector: DebugProbeSelector, channel: Option<String>, reset: bool) {
    let mut buf = [0u8; 4096];
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
                Ok(r) => break r,
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
        let ptr = rtt.ptr();
        let chan = rtt.up_channel(idx).expect("channel index validated above");
        ctx.status(format!(
            "{chip}: reading RTT channel {} ({}) at {:#010x}",
            chan.number(),
            chan.name().unwrap_or("unnamed"),
            ptr
        ));
        first_attach = false;

        let mut framer = Framer::new();
        let mut clock = TickClock::new();
        let mut last_data = Instant::now();
        while !ctx.stopped() {
            match chan.read(&mut core, &mut buf) {
                Ok(0) => {
                    // Back off a little when idle; RTT polling is host driven.
                    let idle = last_data.elapsed();
                    std::thread::sleep(if idle > Duration::from_secs(2) { IDLE_POLL * 4 } else { IDLE_POLL });
                }
                Ok(n) => {
                    last_data = Instant::now();
                    framer.push(&buf[..n]);
                    while let Some(frame) = framer.next_frame() {
                        let mut pkt = frame.packet;
                        pkt.ts = Some(match frame.ts32 {
                            Some(t) => clock.wall(t),
                            None => Timestamp::now(),
                        });
                        if !ctx.packet(pkt) {
                            return;
                        }
                    }
                }
                Err(e) => {
                    ctx.status(format!("{chip}: RTT read failed ({e}), re-attaching"));
                    ctx.sleep(RETRY_DELAY);
                    continue 'attach;
                }
            }
        }
    }
    ctx.eof();
}
