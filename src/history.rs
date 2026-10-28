//! Per-instance resource history in SQLite (`<data>/metrics.db`).
//!
//! The runtime samples every running instance once a minute. Raw samples
//! are kept for [`RAW_KEEP`]; every [`ROLLUP_SECS`] they are folded into
//! rollups (averages, plus peaks of the bursty series) kept for
//! [`ROLLUP_KEEP`]. Charts read raw samples for short ranges and rollups
//! for long ones, bucketed to at most [`MAX_POINTS`] points.

use std::path::Path;
use std::sync::Mutex;

use anyhow::{Context, Result, bail};
use rusqlite::{Connection, params};
use serde::{Deserialize, Serialize};

pub const RAW_KEEP: u64 = 48 * 3600;
pub const ROLLUP_SECS: u64 = 600;
pub const ROLLUP_KEEP: u64 = 30 * 86_400;
pub const MAX_POINTS: u64 = 360;

/// One instance at one moment. Rates are averages over the sampling
/// interval, from the instance's point of view (`rx` = received by it).
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize, Deserialize)]
pub struct Sample {
    /// Unix time.
    pub ts: u64,
    /// Percent of the instance's allocated cores.
    pub cpu: f64,
    /// Bytes, excluding reclaimable page cache.
    pub mem: u64,
    /// Bytes used on the instance's disk.
    pub disk: u64,
    /// Disk read / write, bytes per second.
    pub rd: f64,
    pub wr: f64,
    /// Disk read / write operations per second.
    pub rio: f64,
    pub wio: f64,
    /// Network, bits per second.
    pub rx: f64,
    pub tx: f64,
    /// Network, packets per second.
    pub rxp: f64,
    pub txp: f64,
}

/// A chart point: averages over its bucket, plus peaks.
#[derive(Debug, Clone, Copy, Default, PartialEq, Serialize)]
pub struct Point {
    #[serde(flatten)]
    pub avg: Sample,
    pub cpu_max: f64,
    pub rx_max: f64,
    pub tx_max: f64,
    pub wr_max: f64,
}

/// Averages of one instance over a window, for the ranking.
#[derive(Debug, Clone, Default, PartialEq, Serialize)]
pub struct Usage {
    pub vm_id: String,
    #[serde(flatten)]
    pub avg: Sample,
    pub cpu_max: f64,
    /// Samples in the window.
    pub samples: u64,
}

pub struct History {
    db: Mutex<Connection>,
}

impl History {
    pub fn open(path: &Path) -> Result<Self> {
        let db = Connection::open(path).with_context(|| format!("open {}", path.display()))?;
        Self::init(db)
    }

    pub fn in_memory() -> Result<Self> {
        Self::init(Connection::open_in_memory()?)
    }

    fn init(db: Connection) -> Result<Self> {
        // Small cache: the agent runs next to 128 MB instances.
        db.execute_batch(
            "PRAGMA journal_mode = WAL;
             PRAGMA synchronous = NORMAL;
             PRAGMA cache_size = -1024;
             CREATE TABLE IF NOT EXISTS samples (
                 vm TEXT NOT NULL, ts INTEGER NOT NULL,
                 cpu REAL, mem INTEGER, disk INTEGER, rd REAL, wr REAL, rio REAL, wio REAL,
                 rx REAL, tx REAL, rxp REAL, txp REAL,
                 PRIMARY KEY (vm, ts)) WITHOUT ROWID;
             CREATE TABLE IF NOT EXISTS rollups (
                 vm TEXT NOT NULL, ts INTEGER NOT NULL,
                 cpu REAL, mem INTEGER, disk INTEGER, rd REAL, wr REAL, rio REAL, wio REAL,
                 rx REAL, tx REAL, rxp REAL, txp REAL,
                 cpu_max REAL, rx_max REAL, tx_max REAL, wr_max REAL,
                 PRIMARY KEY (vm, ts)) WITHOUT ROWID;
             CREATE INDEX IF NOT EXISTS samples_ts ON samples (ts);",
        )?;
        Ok(Self { db: Mutex::new(db) })
    }

    pub fn record(&self, samples: &[(String, Sample)]) -> Result<()> {
        let mut db = self.db.lock().unwrap();
        let tx = db.transaction()?;
        {
            let mut stmt = tx.prepare_cached(
                "INSERT OR REPLACE INTO samples (vm, ts, cpu, mem, disk, rd, wr, rio, wio, rx, tx, rxp, txp)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)",
            )?;
            for (vm, s) in samples {
                stmt.execute(params![
                    vm,
                    s.ts as i64,
                    s.cpu,
                    s.mem as i64,
                    s.disk as i64,
                    s.rd,
                    s.wr,
                    s.rio,
                    s.wio,
                    s.rx,
                    s.tx,
                    s.rxp,
                    s.txp
                ])?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Fold completed buckets into rollups and drop expired rows.
    pub fn maintain(&self, now: u64) -> Result<()> {
        let db = self.db.lock().unwrap();
        let done = (now / ROLLUP_SECS * ROLLUP_SECS) as i64;
        let last: i64 = db.query_row(
            "SELECT COALESCE(MAX(ts) + ?1, 0) FROM rollups",
            [ROLLUP_SECS as i64],
            |r| r.get(0),
        )?;
        db.execute(
            "INSERT OR REPLACE INTO rollups
             SELECT vm, ts / ?1 * ?1 AS b,
                    AVG(cpu), CAST(AVG(mem) AS INTEGER), MAX(disk), AVG(rd), AVG(wr), AVG(rio), AVG(wio),
                    AVG(rx), AVG(tx), AVG(rxp), AVG(txp), MAX(cpu), MAX(rx), MAX(tx), MAX(wr)
             FROM samples WHERE ts >= ?2 AND ts < ?3 GROUP BY vm, b",
            params![ROLLUP_SECS as i64, last, done],
        )?;
        db.execute(
            "DELETE FROM samples WHERE ts < ?1",
            [now.saturating_sub(RAW_KEEP) as i64],
        )?;
        db.execute(
            "DELETE FROM rollups WHERE ts < ?1",
            [now.saturating_sub(ROLLUP_KEEP) as i64],
        )?;
        Ok(())
    }

    pub fn forget(&self, vm: &str) -> Result<()> {
        let db = self.db.lock().unwrap();
        db.execute("DELETE FROM samples WHERE vm = ?1", [vm])?;
        db.execute("DELETE FROM rollups WHERE vm = ?1", [vm])?;
        Ok(())
    }

    /// Chart points of `vm` over the last `range` seconds.
    pub fn series(&self, vm: &str, range: u64, now: u64) -> Result<Vec<Point>> {
        if range == 0 || range > ROLLUP_KEEP {
            bail!("range must be 1 s to 30 days");
        }
        let from = now.saturating_sub(range) as i64;
        // Raw samples while they cover the range, rollups beyond.
        let (table, step, peaks) = if range <= RAW_KEEP {
            ("samples", 60, "MAX(cpu), MAX(rx), MAX(tx), MAX(wr)")
        } else {
            (
                "rollups",
                ROLLUP_SECS,
                "MAX(cpu_max), MAX(rx_max), MAX(tx_max), MAX(wr_max)",
            )
        };
        let bucket = (range / MAX_POINTS).max(step) as i64;
        let sql = format!(
            "SELECT ts / ?1 * ?1 AS b, AVG(cpu), AVG(mem), MAX(disk), AVG(rd), AVG(wr), AVG(rio), AVG(wio),
                    AVG(rx), AVG(tx), AVG(rxp), AVG(txp), {peaks}
             FROM {table} WHERE vm = ?2 AND ts >= ?3 GROUP BY b ORDER BY b"
        );
        let db = self.db.lock().unwrap();
        let mut stmt = db.prepare_cached(&sql)?;
        let rows = stmt.query_map(params![bucket, vm, from], |r| {
            Ok(Point {
                avg: Sample {
                    ts: r.get::<_, i64>(0)? as u64,
                    cpu: r.get(1)?,
                    mem: r.get::<_, f64>(2)? as u64,
                    disk: r.get::<_, i64>(3)? as u64,
                    rd: r.get(4)?,
                    wr: r.get(5)?,
                    rio: r.get(6)?,
                    wio: r.get(7)?,
                    rx: r.get(8)?,
                    tx: r.get(9)?,
                    rxp: r.get(10)?,
                    txp: r.get(11)?,
                },
                cpu_max: r.get(12)?,
                rx_max: r.get(13)?,
                tx_max: r.get(14)?,
                wr_max: r.get(15)?,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }

    /// Every instance's averages over the last `window` seconds (raw
    /// samples, so at most [`RAW_KEEP`]).
    pub fn usage(&self, window: u64, now: u64) -> Result<Vec<Usage>> {
        let from = now.saturating_sub(window.min(RAW_KEEP)) as i64;
        let db = self.db.lock().unwrap();
        let mut stmt = db.prepare_cached(
            "SELECT vm, MAX(ts), AVG(cpu), AVG(mem), MAX(disk), AVG(rd), AVG(wr), AVG(rio), AVG(wio),
                    AVG(rx), AVG(tx), AVG(rxp), AVG(txp), MAX(cpu), COUNT(*)
             FROM samples WHERE ts >= ?1 GROUP BY vm",
        )?;
        let rows = stmt.query_map([from], |r| {
            Ok(Usage {
                vm_id: r.get(0)?,
                avg: Sample {
                    ts: r.get::<_, i64>(1)? as u64,
                    cpu: r.get(2)?,
                    mem: r.get::<_, f64>(3)? as u64,
                    disk: r.get::<_, i64>(4)? as u64,
                    rd: r.get(5)?,
                    wr: r.get(6)?,
                    rio: r.get(7)?,
                    wio: r.get(8)?,
                    rx: r.get(9)?,
                    tx: r.get(10)?,
                    rxp: r.get(11)?,
                    txp: r.get(12)?,
                },
                cpu_max: r.get(13)?,
                samples: r.get::<_, i64>(14)? as u64,
            })
        })?;
        Ok(rows.collect::<Result<_, _>>()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample(ts: u64, cpu: f64, rx: f64) -> Sample {
        Sample {
            ts,
            cpu,
            mem: 64 << 20,
            disk: 1 << 30,
            rx,
            ..Default::default()
        }
    }

    #[test]
    fn record_rank_roll_up_and_expire() {
        let h = History::in_memory().unwrap();
        let t0 = 1_800_000_000 / ROLLUP_SECS * ROLLUP_SECS;
        // Two instances, 20 minutes of one-minute samples.
        for i in 0..20 {
            let ts = t0 + i * 60;
            h.record(&[
                ("a".into(), sample(ts, 90.0, 1e6)),
                (
                    "b".into(),
                    sample(ts, if i == 19 { 50.0 } else { 10.0 }, 1e3),
                ),
            ])
            .unwrap();
        }
        let now = t0 + 20 * 60;
        // Longer than the raw samples cover, at one point per rollup.
        const LONG: u64 = RAW_KEEP + 3600;

        // Ranking over the last 5 minutes.
        let mut usage = h.usage(300, now).unwrap();
        usage.sort_by(|x, y| y.avg.cpu.total_cmp(&x.avg.cpu));
        assert_eq!(usage[0].vm_id, "a");
        assert_eq!(usage[0].samples, 5);
        assert_eq!(usage[1].cpu_max, 50.0);

        // Short ranges come from raw samples.
        let pts = h.series("a", 3600, now).unwrap();
        assert_eq!(pts.len(), 20);
        assert_eq!(pts[0].avg.cpu, 90.0);
        assert_eq!(pts[0].avg.mem, 64 << 20);

        // Two completed 10-minute buckets roll up; peaks survive averaging.
        h.maintain(now).unwrap();
        h.maintain(now).unwrap(); // idempotent
        let long = h.series("b", LONG, now).unwrap();
        assert_eq!(long.len(), 2);
        assert_eq!(long[1].cpu_max, 50.0);
        assert!((long[1].avg.cpu - 14.0).abs() < 1e-9);

        // Raw samples expire after RAW_KEEP, rollups later.
        h.maintain(now + RAW_KEEP + 3600).unwrap();
        assert!(h.series("a", 3600, now).unwrap().is_empty());
        assert_eq!(h.series("a", LONG, now + RAW_KEEP).unwrap().len(), 2);

        h.forget("a").unwrap();
        assert!(h.series("a", LONG, now + RAW_KEEP).unwrap().is_empty());
        assert!(h.series("a", 0, now).is_err());
    }
}
