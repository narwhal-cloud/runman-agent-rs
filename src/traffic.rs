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

/// When monthly counters restart: 00:00 of `reset_day` at a fixed UTC
/// offset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Schedule {
    pub reset_day: u32,
    /// Minutes east of UTC.
    pub utc_offset_min: i32,
}

impl Schedule {
    /// (year, month) of the period that started on or before `unix_secs`.
    fn period_start(&self, unix_secs: u64) -> (i64, u32) {
        let local = unix_secs as i64 + i64::from(self.utc_offset_min) * 60;
        let (y, m, d) = civil_from_days(local.div_euclid(86_400));
        if d >= self.reset_day {
            (y, m)
        } else if m == 1 {
            (y - 1, 12)
        } else {
            (y, m - 1)
        }
    }

    /// Billing period containing `unix_secs`, `YYYY-MM` of its first day.
    pub fn period(&self, unix_secs: u64) -> String {
        let (y, m) = self.period_start(unix_secs);
        format!("{y:04}-{m:02}")
    }

    /// Unix time at which the period containing `unix_secs` ends.
    pub fn next_reset(&self, unix_secs: u64) -> u64 {
        let (y, m) = self.period_start(unix_secs);
        let (y, m) = if m == 12 { (y + 1, 1) } else { (y, m + 1) };
        let local = days_from_civil(y, m, self.reset_day) * 86_400;
        (local - i64::from(self.utc_offset_min) * 60).max(0) as u64
    }
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

/// (year, month, day) to days since 1970-01-01, proleptic Gregorian.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y.rem_euclid(400);
    let mp = i64::from(if m > 2 { m - 3 } else { m + 9 });
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn periods() {
        let utc = |day| Schedule {
            reset_day: day,
            utc_offset_min: 0,
        };
        // 2026-10-25 12:00 UTC
        let t = 1_792_929_600;
        assert_eq!(utc(1).period(t), "2026-10");
        assert_eq!(utc(25).period(t), "2026-10");
        assert_eq!(utc(26).period(t), "2026-09");
        // 2026-01-03 -> previous year's December when resetting on the 5th
        assert_eq!(utc(5).period(1_767_398_400), "2025-12");

        // Next reset: 2026-11-01 00:00 UTC, and 2026-10-26 00:00 UTC.
        assert_eq!(utc(1).next_reset(t), 1_793_491_200);
        assert_eq!(utc(26).next_reset(t), 1_792_972_800);
        // December rolls into January.
        assert_eq!(utc(5).next_reset(1_767_398_400), 1_767_571_200);

        // UTC+8: 2026-10-31 20:00 UTC is already 1 November in Beijing.
        let cn = Schedule {
            reset_day: 1,
            utc_offset_min: 480,
        };
        let t = 1_793_476_800;
        assert_eq!(utc(1).period(t), "2026-10");
        assert_eq!(cn.period(t), "2026-11");
        // Beijing's 2026-11-01 00:00 is 2026-10-31 16:00 UTC.
        assert_eq!(cn.next_reset(t - 4 * 3600 - 1), 1_793_462_400);
        assert_eq!(cn.next_reset(1_793_462_400), 1_796_054_400);
        // Negative offset: 2026-11-01 02:00 UTC is still October in New York.
        let ny = Schedule {
            reset_day: 1,
            utc_offset_min: -300,
        };
        assert_eq!(ny.period(1_793_498_400), "2026-10");

        for day in [1, 15, 28] {
            for t in (1_760_000_000..1_830_000_000).step_by(86_400 * 7 + 3_607) {
                let s = Schedule {
                    reset_day: day,
                    utc_offset_min: 330,
                };
                let next = s.next_reset(t);
                assert!(next > t && next - t <= 31 * 86_400);
                assert_eq!(s.period(next - 1), s.period(t));
                assert_ne!(s.period(next), s.period(t));
            }
        }
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
