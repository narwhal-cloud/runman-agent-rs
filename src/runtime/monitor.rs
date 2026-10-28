//! Once-a-minute resource samples of running instances (see `history`).

use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::Result;
use async_trait::async_trait;
use tracing::warn;

use super::spec::unit_cgroup;
use super::{Runtime, cpu_usage_usec, memory_used, unix_now};
use crate::backend::Monitor;
use crate::history::{Point, Sample, Usage};

/// Cumulative counters of one instance at one moment.
#[derive(Debug, Clone, Copy)]
pub struct Counters {
    at: Instant,
    cpu_usec: u64,
    io: Io,
    rx_bytes: u64,
    tx_bytes: u64,
    rx_packets: u64,
    tx_packets: u64,
    /// The veth these network counters belong to (recreated on boot).
    ifindex: u64,
}

/// Disk I/O from the unit's `io.stat`. Writes all land on the instance's
/// loop device. Reads of its own disk are charged twice (loop device and the
/// host disk behind it), reads of the shared image only to the host disk,
/// so the larger of the two read counts is the instance's reads.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
struct Io {
    loop_rbytes: u64,
    loop_rios: u64,
    wbytes: u64,
    wios: u64,
    host_rbytes: u64,
    host_rios: u64,
}

const LOOP_MAJOR: &str = "7";

fn parse_io_stat(text: &str, own_loop: Option<&str>) -> Io {
    let mut io = Io::default();
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let Some(dev) = parts.next() else { continue };
        let field = |name: &str| -> u64 {
            line.split_whitespace()
                .find_map(|kv| kv.strip_prefix(name)?.strip_prefix('=')?.parse().ok())
                .unwrap_or(0)
        };
        if Some(dev) == own_loop {
            io.loop_rbytes += field("rbytes");
            io.loop_rios += field("rios");
            io.wbytes += field("wbytes");
            io.wios += field("wios");
        } else if dev.split(':').next() != Some(LOOP_MAJOR) {
            io.host_rbytes += field("rbytes");
            io.host_rios += field("rios");
        }
    }
    io
}

/// `major:minor` of the loop device backed by `image`.
fn loop_device(image: &Path) -> Option<String> {
    std::fs::read_dir("/sys/block")
        .ok()?
        .flatten()
        .find_map(|e| {
            let dir = e.path();
            let backing = std::fs::read_to_string(dir.join("loop/backing_file")).ok()?;
            (Path::new(backing.trim()) == image)
                .then(|| std::fs::read_to_string(dir.join("dev")).ok())
                .flatten()
                .map(|d| d.trim().to_owned())
        })
}

fn read_u64(path: PathBuf) -> Option<u64> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// Bytes used on the instance's disk: its root is an overlay whose statfs
/// reports the upper (the instance's own) filesystem.
fn disk_used(init_pid: i32) -> Option<u64> {
    let st = nix::sys::statfs::statfs(format!("/proc/{init_pid}/root").as_str()).ok()?;
    let block = st.block_size() as u64;
    Some((st.blocks() as u64).saturating_sub(st.blocks_free() as u64) * block)
}

/// Rate between two counter readings; 0 across a counter reset.
fn rate(cur: u64, prev: u64, secs: f64) -> f64 {
    cur.checked_sub(prev).map_or(0.0, |d| d as f64 / secs)
}

impl Runtime {
    /// Sample every running instance and store the samples.
    pub async fn sample_history(&self) {
        let Ok(records) = self.records() else { return };
        let ts = unix_now();
        let mut out = Vec::new();
        let mut live = Vec::new();
        for rec in records.iter().filter(|r| !r.builder) {
            let Some(pid) = std::fs::read_to_string(self.run_spec(rec).init_pid_file())
                .ok()
                .and_then(|p| p.trim().parse::<i32>().ok())
            else {
                continue;
            };
            let cg = unit_cgroup(&rec.id);
            let net = Path::new("/sys/class/net").join(self.net.host_if(rec.idx));
            let (Some(cpu_usec), Some(ifindex)) =
                (cpu_usage_usec(&cg), read_u64(net.join("ifindex")))
            else {
                continue;
            };
            let disk_img = self.dir(&rec.id).join("disk.img");
            let own_loop = loop_device(&disk_img);
            let stat = |n: &str| read_u64(net.join("statistics").join(n)).unwrap_or(0);
            // The host end's rx is what the instance sent.
            let now = Counters {
                at: Instant::now(),
                cpu_usec,
                io: parse_io_stat(
                    &std::fs::read_to_string(cg.join("io.stat")).unwrap_or_default(),
                    own_loop.as_deref(),
                ),
                rx_bytes: stat("tx_bytes"),
                tx_bytes: stat("rx_bytes"),
                rx_packets: stat("tx_packets"),
                tx_packets: stat("rx_packets"),
                ifindex,
            };
            live.push(rec.id.clone());
            let prev = self
                .monitor_prev
                .lock()
                .unwrap()
                .insert(rec.id.clone(), now);
            let Some(prev) = prev else { continue };
            let secs = now.at.duration_since(prev.at).as_secs_f64();
            if secs < 1.0 {
                continue;
            }
            let same_veth = prev.ifindex == now.ifindex;
            let net = |cur: u64, old: u64| if same_veth { rate(cur, old, secs) } else { 0.0 };
            let cpu = rate(now.cpu_usec, prev.cpu_usec, secs) / 1e6 / f64::from(rec.cpu.max(1));
            out.push((
                rec.id.clone(),
                Sample {
                    ts,
                    cpu: (cpu * 100.0).clamp(0.0, 100.0),
                    mem: memory_used(&cg).unwrap_or(0),
                    disk: disk_used(pid).unwrap_or(0),
                    rd: rate(now.io.loop_rbytes, prev.io.loop_rbytes, secs).max(rate(
                        now.io.host_rbytes,
                        prev.io.host_rbytes,
                        secs,
                    )),
                    wr: rate(now.io.wbytes, prev.io.wbytes, secs),
                    rio: rate(now.io.loop_rios, prev.io.loop_rios, secs).max(rate(
                        now.io.host_rios,
                        prev.io.host_rios,
                        secs,
                    )),
                    wio: rate(now.io.wios, prev.io.wios, secs),
                    rx: net(now.rx_bytes, prev.rx_bytes) * 8.0,
                    tx: net(now.tx_bytes, prev.tx_bytes) * 8.0,
                    rxp: net(now.rx_packets, prev.rx_packets),
                    txp: net(now.tx_packets, prev.tx_packets),
                },
            ));
        }
        self.monitor_prev
            .lock()
            .unwrap()
            .retain(|id, _| live.contains(id));
        let history = self.history.clone();
        let result = tokio::task::spawn_blocking(move || {
            history.record(&out)?;
            history.maintain(ts)
        })
        .await;
        match result {
            Ok(Ok(())) => {}
            Ok(Err(e)) => warn!("record metrics: {e:#}"),
            Err(e) => warn!("record metrics: {e}"),
        }
    }
}

/// The panel's view of the history.
pub struct MonitorHandle(pub std::sync::Arc<Runtime>);

#[async_trait]
impl Monitor for MonitorHandle {
    async fn usage(&self, window: u64) -> Result<Vec<Usage>> {
        let h = self.0.history.clone();
        tokio::task::spawn_blocking(move || h.usage(window, unix_now())).await?
    }

    async fn series(&self, vm: &str, range: u64) -> Result<Vec<Point>> {
        let (h, vm) = (self.0.history.clone(), vm.to_owned());
        tokio::task::spawn_blocking(move || h.series(&vm, range, unix_now())).await?
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn io_stat_counts_reads_once() {
        let text = "7:2 rbytes=0 wbytes=0 rios=0 wios=1 dbytes=0 dios=0\n\
                    8:0 rbytes=138833920 wbytes=3645440 rios=1282 wios=555 dbytes=0 dios=0\n\
                    7:1 rbytes=68658176 wbytes=76673024 rios=633 wios=1558 dbytes=0 dios=0\n";
        let io = parse_io_stat(text, Some("7:1"));
        assert_eq!(
            io,
            Io {
                loop_rbytes: 68_658_176,
                loop_rios: 633,
                wbytes: 76_673_024,
                wios: 1558,
                host_rbytes: 138_833_920,
                host_rios: 1282,
            }
        );
        assert_eq!(rate(10, 4, 2.0), 3.0);
        assert_eq!(rate(4, 10, 2.0), 0.0);
    }
}
