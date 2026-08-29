//! Enumeration of devices that could serve as sources: serial ports and debug probes.

use std::fs;

/// A serial port that may carry the monitor protocol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SerialCandidate {
    /// Stable path to open (prefers `/dev/serial/by-id/...` on Linux).
    pub path: String,
    /// Underlying device node, e.g. `/dev/ttyACM0`.
    pub device: String,
    pub description: String,
}

/// List serial ports, most useful first.
pub fn serial_ports() -> Vec<SerialCandidate> {
    let mut out = Vec::new();
    let ports = serialport::available_ports().unwrap_or_default();
    for p in ports {
        let (description, usb) = match &p.port_type {
            serialport::SerialPortType::UsbPort(u) => {
                let mut d = String::new();
                if let Some(m) = &u.manufacturer {
                    d.push_str(m);
                }
                if let Some(pr) = &u.product {
                    if !d.is_empty() {
                        d.push(' ');
                    }
                    d.push_str(pr);
                }
                if let Some(s) = &u.serial_number {
                    d.push_str(&format!(" [{s}]"));
                }
                (d, true)
            }
            serialport::SerialPortType::BluetoothPort => ("Bluetooth".to_string(), false),
            serialport::SerialPortType::PciPort => ("PCI".to_string(), false),
            serialport::SerialPortType::Unknown => (String::new(), false),
        };
        // Only USB serial devices are plausible debug UARTs; skip legacy ttyS* noise.
        if !usb && !p.port_name.contains("ACM") && !p.port_name.contains("usb") {
            continue;
        }
        let path = stable_path(&p.port_name).unwrap_or_else(|| p.port_name.clone());
        out.push(SerialCandidate { path, device: p.port_name, description });
    }
    out.sort_by(|a, b| a.device.cmp(&b.device));
    out.dedup_by(|a, b| a.device == b.device);
    out
}

/// Map `/dev/ttyACMn` to its `/dev/serial/by-id/` symlink when one exists.
fn stable_path(device: &str) -> Option<String> {
    let dir = fs::read_dir("/dev/serial/by-id").ok()?;
    for entry in dir.flatten() {
        let link = entry.path();
        if let Ok(target) = fs::canonicalize(&link) {
            if target.to_string_lossy() == device {
                return Some(link.to_string_lossy().into_owned());
            }
        }
    }
    None
}

/// A debug probe usable for RTT.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeCandidate {
    pub name: String,
    /// `VID:PID:SERIAL` selector.
    pub selector: String,
    pub serial: Option<String>,
}

#[cfg(feature = "rtt")]
pub fn probes() -> Vec<ProbeCandidate> {
    super::rtt::list_probes()
}

#[cfg(not(feature = "rtt"))]
pub fn probes() -> Vec<ProbeCandidate> {
    Vec::new()
}
