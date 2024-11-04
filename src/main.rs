use clap::Parser;
use std::time::Duration;
use btmon::tty;

#[derive(Parser)]
struct Opts {
    tty: std::path::PathBuf,

    #[arg(default_value_t = 115_200)]
    tty_speed: u32,
}

const BUF_SIZE: usize = 2048;    // Size of buffer to read data into
const PKT_MAX: usize = 1486 + 4; // Maximum BTSnoop packet size
const MIN_LEN: usize = 6;        // Minumum length for a valid header

pub fn main() {
    let opts = Opts::parse();

    let timeout = Duration::from_secs(60);
    let mut port = serialport::new(opts.tty.to_string_lossy(), opts.tty_speed)
        .timeout(timeout)
        .open()
        .expect("Failed to open TTY");

    println!("Successfully opened {} with speed {}", opts.tty.to_string_lossy(), opts.tty_speed);

    let mut buf = vec![0u8; BUF_SIZE];
    let mut len = 0usize;
    let mut offset = 0usize;

    println!("{:?}", port);

    loop {
        if offset > (BUF_SIZE - PKT_MAX) {
            buf.rotate_left(offset);
            offset = 0;
        }

        len += port.read(&mut buf[(offset + len)..])
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
