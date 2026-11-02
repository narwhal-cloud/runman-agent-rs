//! Once-a-minute resource samples of running instances (see `history`).

use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::net::IpAddr;
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
    let dir = super::sys::loop_device(image)?;
    Some(
        std::fs::read_to_string(dir.join("dev"))
            .ok()?
            .trim()
            .to_owned(),
    )
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

/// Connections of one instance at one moment.
#[derive(Debug, Default, PartialEq)]
struct Conns {
    tcp: u64,
    udp: u64,
    remotes: HashSet<IpAddr>,
}

/// An instance to count connections of.
struct ConnTarget {
    id: String,
    init_pid: i32,
    /// Its own addresses, as they appear on the host.
    addrs: Vec<IpAddr>,
}

/// Address of `/proc/net/tcp*`: 32-bit words in host byte order.
fn parse_proc_addr(hex: &str) -> Option<IpAddr> {
    let word = |i: usize| {
        u32::from_str_radix(hex.get(i * 8..(i + 1) * 8)?, 16)
            .ok()
            .map(u32::to_ne_bytes)
    };
    match hex.len() {
        8 => Some(IpAddr::from(word(0)?)),
        32 => {
            let mut bytes = [0u8; 16];
            for (i, chunk) in bytes.chunks_mut(4).enumerate() {
                chunk.copy_from_slice(&word(i)?);
            }
            // Dual-stack sockets show IPv4 peers as ::ffff:a.b.c.d.
            Some(IpAddr::from(bytes).to_canonical())
        }
        _ => None,
    }
}

/// Add the established connections of a `/proc/<pid>/net/tcp*` table. The
/// instance's own sockets, not conntrack: conntrack keeps entries of vanished
/// peers and of the instance's previous boot for days.
fn count_tcp(table: impl BufRead, conns: &mut Conns) {
    for line in table.lines().map_while(Result::ok).skip(1) {
        let mut fields = line.split_whitespace();
        let (Some(remote), Some("01")) = (fields.nth(2), fields.next()) else {
            continue;
        };
        let Some(ip) = remote.split(':').next().and_then(parse_proc_addr) else {
            continue;
        };
        if !ip.is_loopback() {
            conns.tcp += 1;
            conns.remotes.insert(ip);
        }
    }
}

/// Add UDP flows from `/proc/net/nf_conntrack` to the instance owning either
/// end: `owners` maps its addresses to its index in `conns`. UDP sockets have
/// no peers to read, and these entries expire within minutes.
fn count_udp(table: impl BufRead, owners: &HashMap<IpAddr, usize>, conns: &mut [Conns]) {
    for line in table.lines().map_while(Result::ok) {
        let mut fields = line.split_whitespace();
        if fields.nth(2) != Some("udp") {
            continue;
        }
        let mut addrs = fields
            .filter_map(|f| f.strip_prefix("src=").or_else(|| f.strip_prefix("dst=")))
            .filter_map(|a| a.parse::<IpAddr>().ok());
        // Original direction, then the source of the reply: the instance
        // for flows forwarded to it.
        let (Some(src), Some(dst), Some(reply)) = (addrs.next(), addrs.next(), addrs.next()) else {
            continue;
        };
        let (from, to) = (owners.get(&src), owners.get(&reply));
        if let Some(&i) = from {
            conns[i].udp += 1;
            conns[i].remotes.insert(dst);
        }
        if let Some(&i) = to.filter(|_| to != from) {
            conns[i].udp += 1;
            conns[i].remotes.insert(src);
        }
    }
}

/// Connections per target, and whether UDP flows could be read.
fn measure_conns(targets: &[ConnTarget]) -> (Vec<Conns>, bool) {
    let mut conns: Vec<Conns> = targets.iter().map(|_| Conns::default()).collect();
    for (target, c) in targets.iter().zip(&mut conns) {
        for table in ["tcp", "tcp6"] {
            let path = format!("/proc/{}/net/{table}", target.init_pid);
            if let Ok(f) = File::open(path) {
                count_tcp(BufReader::new(f), c);
            }
        }
    }
    let owners = targets
        .iter()
        .enumerate()
        .flat_map(|(i, t)| t.addrs.iter().map(move |a| (*a, i)))
        .collect();
    let conntrack = File::open("/proc/net/nf_conntrack");
    let udp_known = conntrack.is_ok();
    if let Ok(f) = conntrack {
        count_udp(BufReader::new(f), &owners, &mut conns);
    }
    (conns, udp_known)
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
        let mut targets = Vec::new();
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
            let mut addrs = self.dedicated_for(&rec.id);
            addrs.push(rec.addrs.ipv4.into());
            addrs.extend(rec.addrs.ipv6.map(IpAddr::from));
            targets.push(ConnTarget {
                id: rec.id.clone(),
                init_pid: pid,
                addrs,
            });
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
                    ..Default::default()
                },
            ));
        }
        self.monitor_prev
            .lock()
            .unwrap()
            .retain(|id, _| live.contains(id));
        let history = self.history.clone();
        let result = tokio::task::spawn_blocking(move || {
            let (conns, udp_known) = measure_conns(&targets);
            for (target, c) in targets.iter().zip(&conns) {
                if let Some((_, s)) = out.iter_mut().find(|(id, _)| *id == target.id) {
                    s.tcp = Some(c.tcp as f64);
                    s.udp = udp_known.then_some(c.udp as f64);
                    s.ips = Some(c.remotes.len() as f64);
                }
            }
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

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn tcp_counts_established_remote_peers() {
        let v4 = "  sl  local_address rem_address   st tx_queue rx_queue
                  0: 00000000:0016 00000000:0000 0A 00000000:00000000
                  1: 02005B0A:0016 0A02A8C0:C350 01 00000000:00000000
                  2: 0100007F:1F90 0100007F:D4A6 01 00000000:00000000
                  3: 02005B0A:0016 0A02A8C0:C351 01 00000000:00000000
                  4: 02005B0A:0016 0B02A8C0:C351 06 00000000:00000000
";
        // An IPv4 peer on a dual-stack socket, an IPv6 peer, IPv6 loopback.
        let v6 = "  sl  local_address remote_address st
                  0: 00000000000000000000000000000000:0016 0000000000000000FFFF00000C02A8C0:C350 01
                  1: 00000000000000000000000000000000:0016 B80D012000000000000000000100FFFF:C350 01
                  2: 00000000000000000000000001000000:0016 00000000000000000000000001000000:C350 01
";
        let mut c = Conns::default();
        count_tcp(v4.as_bytes(), &mut c);
        count_tcp(v6.as_bytes(), &mut c);
        assert_eq!(c.tcp, 4);
        assert_eq!(
            c.remotes,
            HashSet::from([
                ip("192.168.2.10"),
                ip("192.168.2.12"),
                ip("2001:db8::ffff:1"),
            ])
        );
    }

    #[test]
    fn udp_flows_belong_to_the_instance_at_either_end() {
        let table = "ipv4     2 udp      17 29 src=10.91.0.2 dst=1.1.1.1 sport=5000 dport=53 packets=1 bytes=60 src=1.1.1.1 dst=203.0.113.1 sport=53 dport=5000 packets=1 bytes=90 mark=0 use=2
ipv4     2 udp      17 170 src=198.51.100.7 dst=203.0.113.1 sport=4000 dport=27015 src=10.91.0.3 dst=198.51.100.7 sport=27015 dport=4000 [ASSURED] mark=0 use=2
ipv6     10 udp      17 25 src=2001:0db8:0000:0000:0000:0000:0000:0001 dst=2001:0db8:0001:0000:0000:0000:0000:0002 sport=1 dport=2 src=2001:0db8:0001:0000:0000:0000:0000:0002 dst=2001:0db8:0000:0000:0000:0000:0000:0001 sport=2 dport=1 mark=0 use=2
ipv4     2 tcp      6 300 ESTABLISHED src=10.91.0.2 dst=1.1.1.1 sport=1 dport=2 src=1.1.1.1 dst=10.91.0.2 sport=2 dport=1 [ASSURED] mark=0 use=2
ipv4     2 udp      17 29 src=192.168.2.1 dst=192.168.2.2 sport=1 dport=2 src=192.168.2.2 dst=192.168.2.1 sport=2 dport=1 mark=0 use=2
";
        let owners = HashMap::from([
            (ip("10.91.0.2"), 0),
            (ip("10.91.0.3"), 1),
            (ip("2001:db8:1::2"), 1),
        ]);
        let mut conns = [Conns::default(), Conns::default()];
        count_udp(table.as_bytes(), &owners, &mut conns);
        assert_eq!(conns[0].udp, 1);
        assert_eq!(conns[0].remotes, HashSet::from([ip("1.1.1.1")]));
        assert_eq!(
            conns[1].udp, 2,
            "forwarded in, and over IPv6 to its address"
        );
        assert!(conns[1].remotes.contains(&ip("198.51.100.7")));
    }
}
