//! Host metrics from /proc and statvfs.

use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Instant;

use anyhow::{Context, Result};
use async_trait::async_trait;

use crate::backend::HostMetrics;
use crate::model::HostSnapshot;

pub struct ProcMetrics {
    disk_path: PathBuf,
    prev: Mutex<Option<Sample>>,
}

#[derive(Clone, Copy)]
struct Sample {
    at: Instant,
    cpu_busy: u64,
    cpu_total: u64,
    rx: u64,
    tx: u64,
}

impl ProcMetrics {
    pub fn new(disk_path: PathBuf) -> Self {
        Self {
            disk_path,
            prev: Mutex::new(None),
        }
    }
}

#[async_trait]
impl HostMetrics for ProcMetrics {
    async fn snapshot(&self) -> Result<HostSnapshot> {
        let stat = std::fs::read_to_string("/proc/stat")?;
        let (busy, total) = cpu_times(&stat).context("parse /proc/stat")?;
        let (rx, tx) = net_bytes(&std::fs::read_to_string("/proc/net/dev")?);
        let now = Sample {
            at: Instant::now(),
            cpu_busy: busy,
            cpu_total: total,
            rx,
            tx,
        };

        let mut snap = HostSnapshot::default();
        if let Some(prev) = self.prev.lock().unwrap().replace(now) {
            let dt = now.cpu_total.saturating_sub(prev.cpu_total);
            if dt > 0 {
                snap.cpu_pct =
                    (now.cpu_busy.saturating_sub(prev.cpu_busy) as f64 / dt as f64 * 100.0) as f32;
            }
            let secs = now.at.duration_since(prev.at).as_secs_f64();
            if secs > 0.0 {
                snap.net_in_bps = (now.rx.saturating_sub(prev.rx) as f64 / secs) as i64;
                snap.net_out_bps = (now.tx.saturating_sub(prev.tx) as f64 / secs) as i64;
            }
        }

        let mem = std::fs::read_to_string("/proc/meminfo")?;
        let total_kb = meminfo(&mem, "MemTotal").unwrap_or(0);
        let avail_kb = meminfo(&mem, "MemAvailable").unwrap_or(0);
        snap.ram_total_mb = (total_kb / 1024) as i64;
        snap.ram_used_mb = (total_kb.saturating_sub(avail_kb) / 1024) as i64;

        // statvfs field types differ between libcs and architectures.
        #[allow(clippy::unnecessary_cast)]
        if let Ok(vfs) = nix::sys::statvfs::statvfs(&self.disk_path) {
            let frag = vfs.fragment_size() as u64;
            let total = vfs.blocks() as u64 * frag;
            let free = vfs.blocks_available() as u64 * frag;
            snap.disk_total_gb = (total >> 30) as i64;
            snap.disk_used_gb = (total.saturating_sub(free) >> 30) as i64;
        }

        let load = std::fs::read_to_string("/proc/loadavg")?;
        for (i, v) in load.split_whitespace().take(3).enumerate() {
            snap.load[i] = v.parse().unwrap_or(0.0);
        }
        snap.uptime_secs = std::fs::read_to_string("/proc/uptime")?
            .split_whitespace()
            .next()
            .and_then(|v| v.parse::<f64>().ok())
            .unwrap_or(0.0) as i64;
        snap.cpus = std::thread::available_parallelism().map_or(1, |n| n.get() as i32);
        Ok(snap)
    }
}

fn cpu_times(stat: &str) -> Option<(u64, u64)> {
    let line = stat.lines().find(|l| l.starts_with("cpu "))?;
    let v: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .filter_map(|x| x.parse().ok())
        .collect();
    // user nice system idle iowait irq softirq steal
    let total: u64 = v.iter().take(8).sum();
    let idle = v.get(3)? + v.get(4).unwrap_or(&0);
    Some((total - idle, total))
}

/// Sum of physical-ish interfaces (skips loopback and container plumbing).
fn net_bytes(dev: &str) -> (u64, u64) {
    let mut rx = 0;
    let mut tx = 0;
    for line in dev.lines().skip(2) {
        let Some((name, rest)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim();
        if name == "lo"
            || name.starts_with("veth")
            || name.starts_with("rm")
            || name.starts_with("wg")
        {
            continue;
        }
        let f: Vec<u64> = rest
            .split_whitespace()
            .filter_map(|x| x.parse().ok())
            .collect();
        rx += f.first().copied().unwrap_or(0);
        tx += f.get(8).copied().unwrap_or(0);
    }
    (rx, tx)
}

fn meminfo(mem: &str, key: &str) -> Option<u64> {
    mem.lines().find_map(|l| {
        let rest = l.strip_prefix(key)?.strip_prefix(':')?;
        rest.split_whitespace().next()?.parse().ok()
    })
}
