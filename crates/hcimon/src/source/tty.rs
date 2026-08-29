//! Serial port source: Zephyr's monitor protocol over a UART.
//!
//! The port is opened with DTR and RTS asserted because many on-board debug
//! adapters (SEGGER J-Link OB, Silicon Labs WPK) only forward target output
//! while a terminal signals that it is present.  When the port disappears
//! (board unplugged or re-flashed) the source keeps retrying so the session
//! resumes by itself.

use std::io::{ErrorKind, Read};
use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::{Context, Result};
use hcimon_capture::{tty::Framer, Timestamp};

use super::SourceCtx;

const READ_TIMEOUT: Duration = Duration::from_millis(100);
const RETRY_DELAY: Duration = Duration::from_millis(500);

pub fn spawn(ctx: SourceCtx, path: String, baud: u32) -> Result<JoinHandle<()>> {
    // Open once synchronously so that an unusable path fails fast.
    let port = open(&path, baud)?;
    let thread = std::thread::Builder::new()
        .name(format!("tty {}", super::short_path(&path)))
        .spawn(move || run(ctx, path, baud, Some(port)))?;
    Ok(thread)
}

fn open(path: &str, baud: u32) -> Result<Box<dyn serialport::SerialPort>> {
    let mut port = serialport::new(path, baud)
        .timeout(READ_TIMEOUT)
        .open()
        .with_context(|| format!("failed to open {path}"))?;
    // Best effort: not every driver supports modem control lines.
    let _ = port.write_data_terminal_ready(true);
    let _ = port.write_request_to_send(true);
    Ok(port)
}

fn run(ctx: SourceCtx, path: String, baud: u32, mut port: Option<Box<dyn serialport::SerialPort>>) {
    let mut framer = Framer::new();
    let mut buf = [0u8; 4096];
    let mut announced = false;

    while !ctx.stopped() {
        let Some(p) = port.as_mut() else {
            match open(&path, baud) {
                Ok(p) => {
                    port = Some(p);
                    framer = Framer::new();
                    ctx.status(format!("reconnected to {}", super::short_path(&path)));
                    announced = true;
                }
                Err(_) => ctx.sleep(RETRY_DELAY),
            }
            continue;
        };
        if !announced {
            ctx.status(format!("listening on {} at {} baud", super::short_path(&path), baud));
            announced = true;
        }
        match p.read(&mut buf) {
            Ok(0) => {
                // EOF: the device went away.
                ctx.status(format!("{} closed, waiting for it to return", super::short_path(&path)));
                port = None;
                ctx.sleep(RETRY_DELAY);
            }
            Ok(n) => {
                framer.push(&buf[..n]);
                let now = Timestamp::now();
                while let Some(frame) = framer.next_frame() {
                    let mut pkt = frame.packet;
                    if pkt.ts.is_none() {
                        pkt.ts = Some(now);
                    }
                    if !ctx.packet(pkt) {
                        return;
                    }
                }
            }
            Err(e) if e.kind() == ErrorKind::TimedOut || e.kind() == ErrorKind::Interrupted => {}
            Err(e) => {
                ctx.status(format!("{}: {} — waiting for it to return", super::short_path(&path), e));
                port = None;
                ctx.sleep(RETRY_DELAY);
            }
        }
    }
    ctx.eof();
}
