//! Per-instance traffic accounting from the host end of the veth pair.
//!
//! The veth (and its counters) is recreated on every instance boot, so the
//! agent accumulates deltas and persists them; a new interface index means
//! the counters started again from zero.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct Traffic {
    /// Bytes received by the instance (host end transmitted them).
    pub total_in: u64,
    /// Bytes sent by the instance (host end received them).
    pub total_out: u64,
    pub month_in: u64,
    pub month_out: u64,
    /// Billing period the month counters belong to, `YYYY-MM`.
    pub period: String,
    last_ifindex: u32,
    last_rx: u64,
    last_tx: u64,
}

impl Traffic {
    /// Fold in a counter sample of the host-side interface.
    pub fn update(&mut self, ifindex: u32, rx: u64, tx: u64, period: &str) {
        if self.period != period {
            self.period = period.to_owned();
            self.month_in = 0;
            self.month_out = 0;
        }
        let fresh = ifindex != self.last_ifindex;
        let delta = |cur: u64, last: u64| if fresh || cur < last { cur } else { cur - last };
        let d_out = delta(rx, self.last_rx);
        let d_in = delta(tx, self.last_tx);
        self.total_out += d_out;
        self.total_in += d_in;
        self.month_out += d_out;
        self.month_in += d_in;
        self.last_ifindex = ifindex;
        self.last_rx = rx;
        self.last_tx = tx;
    }

    /// Month counters as seen now (zero once a new period has started).
    pub fn month(&self, period: &str) -> (u64, u64) {
        if self.period == period {
            (self.month_in, self.month_out)
        } else {
            (0, 0)
        }
    }
}

/// Billing period containing `unix_secs` when periods start on `reset_day`.
pub fn period_key(unix_secs: u64, reset_day: u32) -> String {
    let (mut y, mut m, d) = civil_from_days((unix_secs / 86_400) as i64);
    if d < reset_day {
        if m == 1 {
            m = 12;
            y -= 1;
        } else {
            m -= 1;
        }
    }
    format!("{y:04}-{m:02}")
}

/// Days since 1970-01-01 to (year, month, day), proleptic Gregorian.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    let y = yoe + era * 400 + i64::from(m <= 2);
    (y, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn periods() {
        // 2026-10-25 12:00 UTC
        let t = 1_792_929_600;
        assert_eq!(period_key(t, 1), "2026-10");
        assert_eq!(period_key(t, 25), "2026-10");
        assert_eq!(period_key(t, 26), "2026-09");
        // 2026-01-03 -> previous year's December when resetting on the 5th
        assert_eq!(period_key(1_767_398_400, 5), "2025-12");
    }

    #[test]
    fn accumulates_across_interface_recreation() {
        let mut t = Traffic::default();
        t.update(7, 100, 1000, "2026-10");
        t.update(7, 150, 1300, "2026-10");
        assert_eq!((t.total_out, t.total_in), (150, 1300));
        // Instance rebooted: new veth whose counters already exceed the old.
        t.update(9, 500, 2000, "2026-10");
        assert_eq!((t.total_out, t.total_in), (650, 3300));
        t.update(9, 600, 2100, "2026-11");
        assert_eq!((t.month_out, t.month_in), (100, 100));
        assert_eq!(t.month("2026-12"), (0, 0));
    }
}
