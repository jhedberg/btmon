//! Timestamp formatting shared by the text and interactive outputs.

use hcimon_decode::Timestamp;
use jiff::Timestamp as JiffTimestamp;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimeMode {
    /// Seconds since the first packet (btmon default): `12.345678`.
    Offset,
    /// Wall clock `HH:MM:SS.uuuuuu`.
    Time,
    /// `YYYY-MM-DD HH:MM:SS.uuuuuu`.
    DateTime,
    None,
}

impl TimeMode {
    pub fn next(self) -> TimeMode {
        match self {
            TimeMode::Offset => TimeMode::Time,
            TimeMode::Time => TimeMode::DateTime,
            TimeMode::DateTime => TimeMode::None,
            TimeMode::None => TimeMode::Offset,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            TimeMode::Offset => "offset",
            TimeMode::Time => "time",
            TimeMode::DateTime => "date",
            TimeMode::None => "none",
        }
    }
}

/// Format `ts` according to `mode`; `first` is the timestamp of the first packet.
///
/// Monotonic timestamps (from TTY/RTT streams) have no wall-clock meaning and
/// are always shown as offsets.
pub fn format_time(ts: Timestamp, first: Option<Timestamp>, mode: TimeMode) -> Option<String> {
    match (mode, ts) {
        (TimeMode::None, _) => None,
        (TimeMode::Offset, _) | (_, Timestamp::Monotonic(_)) => {
            let base = first.unwrap_or(ts);
            let us = ts.micros_since(base);
            let sign = if us < 0 { "-" } else { "" };
            let us = us.unsigned_abs();
            Some(format!("{sign}{}.{:06}", us / 1_000_000, us % 1_000_000))
        }
        (TimeMode::Time, Timestamp::Wall(us)) => {
            let t = JiffTimestamp::from_microsecond(us).ok()?.to_zoned(jiff::tz::TimeZone::system());
            Some(format!("{:02}:{:02}:{:02}.{:06}", t.hour(), t.minute(), t.second(), t.subsec_nanosecond() / 1000))
        }
        (TimeMode::DateTime, Timestamp::Wall(us)) => {
            let t = JiffTimestamp::from_microsecond(us).ok()?.to_zoned(jiff::tz::TimeZone::system());
            Some(format!(
                "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:06}",
                t.year(),
                t.month(),
                t.day(),
                t.hour(),
                t.minute(),
                t.second(),
                t.subsec_nanosecond() / 1000
            ))
        }
    }
}

/// Short offset text for the interactive UI, e.g. `+0.001234` relative to the previous packet.
pub fn format_delta(ts: Timestamp, prev: Option<Timestamp>) -> String {
    match prev {
        Some(p) => {
            let us = ts.micros_since(p);
            let sign = if us < 0 { "-" } else { "+" };
            let us = us.unsigned_abs();
            if us >= 10_000_000 {
                format!("{sign}{}s", us / 1_000_000)
            } else {
                format!("{sign}{}.{:06}", us / 1_000_000, us % 1_000_000)
            }
        }
        None => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offsets() {
        let first = Timestamp::Monotonic(1_000_000);
        assert_eq!(format_time(Timestamp::Monotonic(2_500_000), Some(first), TimeMode::Offset).unwrap(), "1.500000");
        // Monotonic timestamps never render as wall-clock time.
        assert_eq!(format_time(Timestamp::Monotonic(2_500_000), Some(first), TimeMode::Time).unwrap(), "1.500000");
        assert_eq!(format_time(Timestamp::Wall(5), None, TimeMode::None), None);
        assert_eq!(format_time(Timestamp::Wall(1_000), Some(Timestamp::Wall(2_000)), TimeMode::Offset).unwrap(), "-0.001000");
    }

    #[test]
    fn wall_clock_has_microseconds() {
        let s = format_time(Timestamp::Wall(1_700_000_000_123_456), None, TimeMode::Time).unwrap();
        assert!(s.ends_with(".123456"), "{s}");
        let d = format_time(Timestamp::Wall(1_700_000_000_123_456), None, TimeMode::DateTime).unwrap();
        assert!(d.starts_with("2023-11-1"), "{d}");
    }

    #[test]
    fn deltas() {
        assert_eq!(format_delta(Timestamp::Wall(2_000), Some(Timestamp::Wall(500))), "+0.001500");
        assert_eq!(format_delta(Timestamp::Wall(20_000_000), Some(Timestamp::Wall(0))), "+20s");
        assert_eq!(format_delta(Timestamp::Wall(0), None), "");
    }
}
