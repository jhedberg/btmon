use clap::Parser;
use std::time::Duration;
use std::io::Read;
use std::{fmt, str};
use probe_rs::{Core, rtt::UpChannel};
use btmon::tty;

const BUF_SIZE: usize = 2048;    // Size of buffer to read data into
const PKT_MAX: usize = 1486 + 4; // Maximum BTSnoop packet size
const MIN_LEN: usize = 6;        // Minumum length for a valid header

fn process_data(mut source: impl Read + std::fmt::Debug) {
    let mut buf = vec![0u8; BUF_SIZE];
    let mut len = 0usize;
    let mut offset = 0usize;

    println!("{:?}", source);

    loop {
        if offset > (BUF_SIZE - PKT_MAX) {
            buf.rotate_left(offset);
            offset = 0;
        }

        len += source.read(&mut buf[(offset + len)..])
            .expect("Unable to read from serial port");

        // Discard garbage zero bytes which may show up on the UART
        if len > 0 && buf[offset] == b'\0' {
            offset +=1;
            len -= 1;
        }

        let mut data = &buf[offset..(offset + len)];

        loop {
            let pkt: btmon::monitor::Packet;

            if len < MIN_LEN {
                break;
            }

            (data, pkt) = match tty::parse_data(data) {
                Ok(v) => v,
                Err(_) => {
                    offset += len - data.len();
                    len = data.len();
                    break;
                },
            };

            println!("{} {}", pkt.ts, pkt.op);
        }
    }
}

fn open_tty(tty: std::path::PathBuf, tty_speed: u32) -> impl Read + std::fmt::Debug {
    let timeout = Duration::from_secs(60);
    let port = serialport::new(tty.to_string_lossy(), tty_speed)
        .timeout(timeout)
        .open()
        .expect("Failed to open TTY");

    println!("Successfully opened {} with speed {}", tty.to_string_lossy(), tty_speed);

    port
}

struct UpChannelReader <'a> {
    core: Core<'a>,
    chan: & 'a mut UpChannel,
}

impl fmt::Debug for UpChannelReader<'_> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Up Channel")
    }
}

impl Read for UpChannelReader <'_> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.chan.read(&mut self.core, buf) {
            Ok(len) => Ok(len),
            Err(_) => Err(std::io::Error::last_os_error()),
        }
    }
}

#[derive(Parser)]
struct Opts {
    #[arg(long)]
    tty: Option<std::path::PathBuf>,

    #[arg(long, default_value_t = 115_200)]
    tty_speed: u32,

    #[arg(long)]
    rtt: Option<String>,

    #[arg(long, default_value_t = 0)]
    rtt_chan: usize,
}

pub fn main() {
    let opts = Opts::parse();

    if let Some(tty) = opts.tty {
        process_data(open_tty(tty, opts.tty_speed));
    } else if let Some(target) = opts.rtt {
        use probe_rs::{
            Permissions,
            rtt::{Rtt, ScanRegion},
            config::TargetSelector,
            probe::list::Lister,
        };

        let lister = Lister::new();
        let probes = lister.list_all();
        let probe = probes[0].open().unwrap();

        let target_selector = TargetSelector::from(target);
        let mut session = probe.attach(target_selector, Permissions::default()).unwrap();

        let mut core = session.core(0).expect("Error attaching to core # 0");

        println!("Attaching to RTT...");

        let mut rtt =
            Rtt::attach_region(&mut core, &ScanRegion::Ram).expect("Error attaching to RTT");

        println!("Found control block at {:#010x}", rtt.ptr());

        let chan = rtt.up_channel(opts.rtt_chan).unwrap();

        let reader = UpChannelReader {
            core,
            chan,
        };

        process_data(reader);
    }
}
