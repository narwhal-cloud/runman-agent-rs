//! System-container runtime: implements [`Instances`] and [`PortForwards`] on
//! top of transient systemd units running [`supervisor`].
//!
//! Per instance (`<data>/instances/<id>/`):
//! - `instance.json` — the record (resources, image, addresses, desired state);
//! - `runtime.json`  — the [`RunSpec`] handed to the supervisor;
//! - `disk.img`      — sparse ext4 holding the overlay upper/work dirs, sized
//!   to the plan's disk so the limit is a real filesystem size;
//! - `traffic.json`  — accumulated traffic counters;
//! - `console.log`   — the instance console.
//!
//! Port forwards live in `<data>/portforwards.json`.

pub mod attach;
pub mod build;
pub mod customize;
pub mod exec;
pub mod fsutil;
pub mod image;
pub mod net;
pub mod seccomp;
pub mod spec;
pub mod supervisor;
pub mod sys;
pub mod wg;

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use rand::Rng;
use serde::{Deserialize, Serialize};
use tokio::process::Command;
use tracing::{info, warn};

use crate::backend::{ConsoleIo, Instances, PortForwards, WgBindings};
use crate::config::{self, Config, NetworkConfig};
use crate::model::{ConsoleSize, InstanceDetails, InstanceSpec, L4Proto, PortForward, VmId};
use crate::proto;
use crate::traffic::{Schedule, Traffic};
use exec::ExecTarget;
use fsutil::{RootFs, mkdir_private};
use image::{ImageStore, run};
use net::{Addrs, Forward, Net, Port};
use spec::{ID_BASE, ID_RANGE, NetSpec, RunSpec, unit_cgroup, unit_name};

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

const RUN_ROOT: &str = "/run/runman-agent";
const START_TIMEOUT: Duration = Duration::from_secs(15);
/// Highest instance index so the UID ranges stay below 2^32.
const MAX_IDX: u32 = (u32::MAX - ID_BASE) / ID_RANGE - 1;
/// Range for automatically chosen host ports.
const AUTO_PORTS: std::ops::Range<u16> = 20000..60000;

pub struct Options {
    pub data_dir: PathBuf,
    pub image_base_url: String,
    pub tun: bool,
    pub network: NetworkConfig,
    pub traffic: Schedule,
}

impl Options {
    pub fn from_config(c: &Config) -> Self {
        Self {
            data_dir: c.data_dir.clone(),
            image_base_url: c.image_base_url.clone(),
            tun: c.tun,
            network: c.network.clone(),
            traffic: c.traffic_schedule(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum Desired {
    Running,
    Stopped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Record {
    id: String,
    idx: u32,
    cpu: u32,
    ram_mb: u64,
    disk_gb: u64,
    bandwidth_mbps: u32,
    os_image: String,
    /// Image template this instance's overlay was built on.
    lower: PathBuf,
    stop_signal: String,
    hostname: String,
    addrs: Addrs,
    desired: Desired,
    /// Temporary instance building a custom image: hidden from listings and
    /// heartbeats (the platform would delete it as an orphan).
    #[serde(default)]
    builder: bool,
    /// Unix time of the first create (kept across reinstalls); aligns
    /// traffic periods in `creation` reset mode. 0 in records of older
    /// agents until `init` fills it in.
    #[serde(default)]
    created: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StoredForward {
    vm_id: String,
    proto: String,
    host_port: u16,
    guest_port: u16,
    #[serde(default)]
    description: String,
}

pub struct Runtime {
    data: PathBuf,
    exe: PathBuf,
    images: ImageStore,
    tun: bool,
    net: Net,
    /// Traffic schedule in effect; its lock also serializes `traffic.json`
    /// writes against relabelling (see `traffic_schedule`).
    schedule: Mutex<Schedule>,
    /// Live configuration, for schedule changes made in the panel.
    config: Option<Arc<config::Store>>,
    /// Port forwards; the lock also serializes ruleset updates.
    forwards: tokio::sync::Mutex<Vec<PortForward>>,
    cpu_samples: Mutex<HashMap<String, (Instant, u64)>>,
    tunnels: tokio::sync::Mutex<wg::Tunnels>,
    /// Dedicated addresses per instance id (snapshot of `tunnels`, readable
    /// without its async lock).
    dedicated: Mutex<BTreeMap<String, Vec<IpAddr>>>,
    /// Instances whose in-instance network config still has to be updated.
    net_pending: Mutex<BTreeSet<String>>,
    /// Serializes operations on one instance (platform commands and WG sync
    /// both touch an instance's rootfs and unit).
    vm_locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    /// Serializes instance index allocation (see `create_locked`).
    alloc: Mutex<()>,
    builds: build::Builds,
}

impl Runtime {
    pub fn new(opts: Options) -> Result<Self> {
        let data_dir = &opts.data_dir;
        // Paths are embedded in overlayfs mount options.
        if data_dir
            .to_string_lossy()
            .contains([',', ':', '\\', ' ', '\n'])
            || !data_dir.is_absolute()
        {
            bail!("data_dir must be an absolute path without ',', ':', '\\' or whitespace");
        }
        mkdir_private(data_dir)?;
        mkdir_private(&data_dir.join("instances"))?;
        let forwards = load_forwards(&data_dir.join("portforwards.json"))?;
        let net = Net::from_config(&opts.network)?;
        let tunnels = wg::Tunnels::load(
            data_dir,
            &net.bridge,
            &opts.network.wg_prefix,
            opts.network.wg_table_base,
        )?;
        let dedicated = tunnels.addresses_by_vm();
        Ok(Self {
            data: data_dir.clone(),
            exe: std::env::current_exe()?,
            images: ImageStore::new(data_dir, &opts.image_base_url)?,
            tun: opts.tun,
            net,
            schedule: Mutex::new(opts.traffic),
            config: None,
            forwards: tokio::sync::Mutex::new(forwards),
            cpu_samples: Mutex::default(),
            tunnels: tokio::sync::Mutex::new(tunnels),
            dedicated: Mutex::new(dedicated),
            net_pending: Mutex::default(),
            vm_locks: Mutex::default(),
            alloc: Mutex::default(),
            builds: build::Builds::new(&data_dir.join("image-builds"))?,
        })
    }

    async fn lock_vm(&self, id: &str) -> tokio::sync::OwnedMutexGuard<()> {
        let lock = self
            .vm_locks
            .lock()
            .unwrap()
            .entry(id.to_owned())
            .or_default()
            .clone();
        lock.lock_owned().await
    }

    fn dedicated_for(&self, id: &str) -> Vec<IpAddr> {
        self.dedicated
            .lock()
            .unwrap()
            .get(id)
            .cloned()
            .unwrap_or_default()
    }

    fn net_files(&self, rec: &Record) -> customize::NetFiles {
        customize::NetFiles {
            ipv4: rec.addrs.ipv4,
            prefix4: self.net.v4_prefix_len(),
            gateway4: self.net.gateway4(),
            ipv6: rec.addrs.ipv6,
            gateway6: self.net.gateway6(),
            dns: self.net.dns.clone(),
            extra: self.dedicated_for(&rec.id),
        }
    }

    /// Rewrite the instance's own network config (dedicated IPs changed) and
    /// apply it: live through its network manager, or on disk when stopped.
    async fn update_instance_network(&self, rec: &Record) -> Result<()> {
        let files = self.net_files(rec);
        if self.is_active(&rec.id).await {
            let script = customize::network_update_script(&files);
            self.exec_target(&rec.id)
                .run(&["sh", "-s"], script.as_bytes())
                .await
        } else {
            self.with_offline_rootfs(rec, false, move |root| {
                customize::write_network(root, &files)
            })
            .await
        }
    }

    /// Follow the traffic schedule of a live configuration.
    pub fn with_config(mut self, store: Arc<config::Store>) -> Self {
        self.config = Some(store);
        self
    }

    /// Binary that provides `__supervise`/`__exec` (default: this executable).
    pub fn with_helper(mut self, exe: PathBuf) -> Self {
        self.exe = exe;
        self
    }

    pub fn images(&self) -> &ImageStore {
        &self.images
    }

    /// Download new official image versions, then drop versions no instance
    /// is built on.
    pub async fn refresh_images(&self) {
        if let Err(e) = self.images.sync().await {
            warn!("image sync: {e:#}");
        }
        self.gc_images();
    }

    /// Drop image versions no instance is built on.
    pub fn gc_images(&self) {
        let _alloc = self.alloc.lock().unwrap();
        let in_use: Vec<PathBuf> = self
            .records()
            .map(|r| r.into_iter().map(|r| r.lower).collect())
            .unwrap_or_default();
        self.images.gc(&in_use);
    }

    /// Prepare host networking and start every instance that should be
    /// running (after boot or an agent upgrade).
    pub async fn init(&self) -> Result<()> {
        self.net.setup_host().await.context("host network setup")?;
        let inotify = std::fs::read_to_string("/proc/sys/fs/inotify/max_user_instances")
            .ok()
            .and_then(|v| v.trim().parse::<u64>().ok())
            .unwrap_or(0);
        if inotify < 8192 {
            // Every instance runs a full init; their inotify instances all
            // count against one host user, so the default (128) runs out
            // after a handful of instances.
            warn!(
                "fs.inotify.max_user_instances is {inotify}; instances will fail to start services. \
                 Re-run install.sh or set it to 65536 (/etc/sysctl.d/90-runman.conf)"
            );
        }
        if self
            .dedicated
            .lock()
            .unwrap()
            .values()
            .flatten()
            .any(IpAddr::is_ipv6)
        {
            self.net.enable_v6().await?;
        }
        self.reconcile_network().await?;
        // Records of older agents have no creation time: take the instance
        // directory's (its birth time where the filesystem records one).
        for mut rec in self.records()?.into_iter().filter(|r| r.created == 0) {
            let meta = std::fs::metadata(self.dir(&rec.id))?;
            let born = meta.created().or_else(|_| meta.modified())?;
            rec.created = born
                .duration_since(SystemTime::UNIX_EPOCH)
                .map_or_else(|_| unix_now(), |d| d.as_secs());
            self.save(&rec)?;
        }
        // Builds do not survive a restart; drop their temporary instances.
        for rec in self.records()?.into_iter().filter(|r| r.builder) {
            let id = VmId::parse(&rec.id).expect("record ids are validated");
            warn!(
                "removing builder {} left by an interrupted image build",
                rec.id
            );
            if let Err(e) = self.delete(&id).await {
                warn!("remove builder {}: {e:#}", rec.id);
            }
        }
        for rec in self
            .records()?
            .into_iter()
            .filter(|r| r.desired == Desired::Running)
        {
            let id = VmId::parse(&rec.id).expect("record ids are validated");
            if let Err(e) = self.start(&id).await {
                warn!("autostart {}: {e:#}", rec.id);
            }
        }
        Ok(())
    }

    fn dir(&self, id: &str) -> PathBuf {
        self.data.join("instances").join(id)
    }

    fn run_spec(&self, rec: &Record) -> RunSpec {
        RunSpec {
            id: rec.id.clone(),
            dir: self.dir(&rec.id),
            lower: rec.lower.clone(),
            uid_base: ID_BASE + rec.idx * ID_RANGE,
            hostname: rec.hostname.clone(),
            stop_signal: rec.stop_signal.clone(),
            tun: self.tun,
            run_dir: Path::new(RUN_ROOT).join(&rec.id),
            cpus: rec.cpu,
            net: Some(NetSpec {
                host_if: self.net.host_if(rec.idx),
                bridge: self.net.bridge.clone(),
                mac: net::mac(rec.idx),
                bandwidth_mbps: rec.bandwidth_mbps,
            }),
        }
    }

    fn exec_target(&self, id: &str) -> ExecTarget {
        ExecTarget {
            exe: self.exe.clone(),
            pid_file: Path::new(RUN_ROOT).join(id).join("init.pid"),
            unit_cgroup: unit_cgroup(id),
        }
    }

    fn load(&self, id: &str) -> Result<Option<Record>> {
        match std::fs::read(self.dir(id).join("instance.json")) {
            Ok(raw) => Ok(Some(serde_json::from_slice(&raw)?)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    fn require(&self, id: &VmId) -> Result<Record> {
        self.load(id.as_str())?
            .with_context(|| format!("instance {id} not found"))
    }

    fn save(&self, rec: &Record) -> Result<()> {
        let dir = self.dir(&rec.id);
        fsutil::write_atomic(&dir.join("instance.json"), &serde_json::to_vec_pretty(rec)?)?;
        fsutil::write_atomic(
            &dir.join("runtime.json"),
            &serde_json::to_vec_pretty(&self.run_spec(rec))?,
        )
    }

    fn records(&self) -> Result<Vec<Record>> {
        let mut out = Vec::new();
        for entry in std::fs::read_dir(self.data.join("instances"))? {
            let name = entry?.file_name();
            let Some(name) = name.to_str() else { continue };
            if VmId::parse(name).is_err() {
                continue;
            }
            match self.load(name) {
                Ok(Some(rec)) => out.push(rec),
                Ok(None) => {}
                Err(e) => warn!("instance {name}: unreadable record: {e:#}"),
            }
        }
        Ok(out)
    }

    fn allocate_idx(&self) -> Result<u32> {
        let used: BTreeSet<u32> = self.records()?.iter().map(|r| r.idx).collect();
        (0..=MAX_IDX.min(self.net.max_idx()))
            .find(|i| !used.contains(i))
            .context("no free instance slot")
    }

    /// Rebuild nftables/NDP state from the records and port forwards.
    async fn reconcile_network(&self) -> Result<()> {
        let forwards = self.forwards.lock().await;
        self.apply_network(&forwards).await
    }

    async fn apply_network(&self, forwards: &[PortForward]) -> Result<()> {
        let records = self.records()?;
        let by_id: HashMap<&str, &Record> = records.iter().map(|r| (r.id.as_str(), r)).collect();
        let dedicated = self.dedicated.lock().unwrap().clone();
        let instances: Vec<Port> = records
            .iter()
            .map(|r| Port {
                idx: r.idx,
                addrs: r.addrs.clone(),
                extra: dedicated.get(&r.id).cloned().unwrap_or_default(),
            })
            .collect();
        let resolved: Vec<Forward> = forwards
            .iter()
            .filter_map(|f| {
                by_id.get(f.vm_id.as_str()).map(|r| Forward {
                    proto: f.proto,
                    host_port: f.host_port,
                    target: r.addrs.ipv4,
                    guest_port: f.guest_port,
                })
            })
            .collect();
        self.net.apply(&instances, &resolved).await
    }

    fn save_forwards(&self, forwards: &[PortForward]) -> Result<()> {
        let stored: Vec<StoredForward> = forwards
            .iter()
            .map(|f| StoredForward {
                vm_id: f.vm_id.to_string(),
                proto: f.proto.as_str().into(),
                host_port: f.host_port,
                guest_port: f.guest_port,
                description: f.description.clone(),
            })
            .collect();
        fsutil::write_atomic(
            &self.data.join("portforwards.json"),
            &serde_json::to_vec_pretty(&stored)?,
        )
    }

    async fn is_active(&self, id: &str) -> bool {
        Command::new("systemctl")
            .args(["is-active", "--quiet", &unit_name(id)])
            .status()
            .await
            .is_ok_and(|s| s.success())
    }

    /// Build the disk image and prepare the rootfs for first boot.
    async fn provision(&self, rec: &Record, password: &str) -> Result<()> {
        let rs = self.run_spec(rec);
        for d in [
            rs.dir.clone(),
            rs.dir.join("mnt"),
            rs.mnt_disk(),
            rs.mnt_lower(),
            rs.mnt_upper(),
            rs.mnt_rootfs(),
        ] {
            mkdir_private(&d)?;
        }
        let disk = rs.disk_image();
        let _ = std::fs::remove_file(&disk);
        std::fs::File::create(&disk)?.set_len(rec.disk_gb << 30)?;
        run(Command::new("mkfs.ext4")
            .args([
                "-q",
                "-F",
                "-m",
                "0",
                "-E",
                "lazy_itable_init=1,lazy_journal_init=1",
            ])
            .arg(&disk))
        .await
        .context("mkfs.ext4")?;

        let hostname = rec.hostname.clone();
        let password = password.to_owned();
        let net = self.net_files(rec);
        self.with_offline_rootfs(rec, true, move |root| {
            customize::prepare(
                root,
                &customize::FirstBoot {
                    hostname: &hostname,
                    root_password: &password,
                    net: Some(net),
                },
            )
        })
        .await
    }

    /// Mount the (stopped) instance's overlay on the host and run `f` on it.
    async fn with_offline_rootfs<T: Send + 'static>(
        &self,
        rec: &Record,
        fresh: bool,
        f: impl FnOnce(&RootFs) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        self.with_offline_path(rec, fresh, move |path| f(&RootFs::open(path)?))
            .await
    }

    /// Like `with_offline_rootfs`, handing `f` the mounted path (for bulk
    /// copies; prefer `RootFs` for edits).
    async fn with_offline_path<T: Send + 'static>(
        &self,
        rec: &Record,
        fresh: bool,
        f: impl FnOnce(&Path) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let rs = self.run_spec(rec);
        let (disk, rootfs) = (rs.mnt_disk(), rs.mnt_rootfs());
        run(Command::new("mount")
            .args(["-t", "ext4", "-o", "loop,noatime,nodev"])
            .arg(rs.disk_image())
            .arg(&disk))
        .await
        .context("mount disk")?;
        let result = async {
            if fresh {
                for sub in ["up", "wk"] {
                    std::fs::create_dir_all(disk.join(sub))?;
                }
            }
            // Same `userxattr` as the in-container mount, so both read the
            // overlay metadata (whiteouts, opaque dirs) the same way.
            let opts = format!(
                "lowerdir={},upperdir={},workdir={},userxattr",
                rec.lower.display(),
                disk.join("up").display(),
                disk.join("wk").display()
            );
            run(Command::new("mount")
                .args(["-t", "overlay", "overlay", "-o", &opts])
                .arg(&rootfs))
            .await
            .context("mount overlay")?;
            let path = rootfs.clone();
            tokio::task::spawn_blocking(move || f(&path)).await?
        }
        .await;
        let _ = sys::umount_if_mounted(&rootfs);
        let _ = sys::umount_if_mounted(&disk);
        result
    }

    async fn launch(&self, rec: &Record) -> Result<()> {
        let unit = unit_name(&rec.id);
        let rs = self.run_spec(rec);
        let _ = std::fs::remove_file(rs.init_pid_file());
        let _ = Command::new("systemctl")
            .args(["reset-failed", &unit])
            .stderr(std::process::Stdio::null())
            .status()
            .await;
        let spec_path = rs.dir.join("runtime.json");
        run(Command::new("systemd-run")
            .arg(format!("--unit={unit}"))
            .arg(format!("--description=runman instance {}", rec.id))
            .args(["--collect", "--service-type=exec", "--quiet"])
            .args([
                "-p",
                "Delegate=yes",
                "-p",
                "PrivateMounts=yes",
                "-p",
                "KillMode=mixed",
            ])
            .args(["-p", "TimeoutStopSec=60", "-p", "OOMPolicy=continue"])
            .args(["-p", &format!("MemoryMax={}M", rec.ram_mb)])
            .args(["-p", &format!("MemorySwapMax={}M", rec.ram_mb)])
            .args(["-p", &format!("CPUQuota={}%", rec.cpu * 100)])
            .args(["-p", &format!("TasksMax={}", 1024 * rec.cpu.max(4))])
            .arg(&self.exe)
            .arg("__supervise")
            .arg(&spec_path))
        .await
        .context("systemd-run")?;

        let deadline = Instant::now() + START_TIMEOUT;
        while Instant::now() < deadline {
            if rs.init_pid_file().exists() {
                return Ok(());
            }
            if !self.is_active(&rec.id).await {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let log = Command::new("journalctl")
            .args(["-u", &unit, "-n", "5", "--no-pager", "-o", "cat"])
            .output()
            .await
            .map(|o| {
                String::from_utf8_lossy(&o.stdout)
                    .trim()
                    .replace('\n', "; ")
            })
            .unwrap_or_default();
        bail!("instance did not start: {log}")
    }

    async fn halt(&self, id: &str, force: bool) -> Result<()> {
        if !self.is_active(id).await {
            return Ok(());
        }
        let unit = unit_name(id);
        if force {
            // Kill only the instance; the supervisor sees init die and cleans
            // up (killing it too would leak its network devices and mounts).
            let _ = std::fs::write(unit_cgroup(id).join("ct/cgroup.kill"), "1");
            let deadline = Instant::now() + Duration::from_secs(10);
            while self.is_active(id).await && Instant::now() < deadline {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
        // The unit may finish and be garbage-collected (`--collect`) while we
        // ask, which systemctl reports as "not loaded": that is success too.
        match run(Command::new("systemctl").args(["stop", &unit])).await {
            Err(e) if self.is_active(id).await => Err(e),
            _ => Ok(()),
        }
    }

    fn set_desired(&self, id: &VmId, desired: Desired) -> Result<Record> {
        let mut rec = self.require(id)?;
        if rec.desired != desired {
            rec.desired = desired;
            self.save(&rec)?;
        }
        Ok(rec)
    }

    /// Repair host state that something else removed: re-apply the nftables
    /// ruleset (atomic, so harmless when nothing changed) and re-plug running
    /// instances whose veth vanished (`ip link del`, network restarts).
    pub async fn heal(&self) {
        if let Err(e) = self.reconcile_network().await {
            warn!("re-apply network rules: {e:#}");
        }
        let Ok(records) = self.records() else { return };
        for rec in &records {
            let rs = self.run_spec(rec);
            if let Some(pid) = std::fs::read_to_string(rs.init_pid_file())
                .ok()
                .and_then(|p| p.trim().parse::<i32>().ok())
            {
                let moved = exec::adopt_strays(&unit_cgroup(&rec.id), pid);
                if moved > 0 {
                    info!(
                        "instance {}: moved {moved} process(es) into its cgroup",
                        rec.id
                    );
                }
            }
        }
        for rec in records {
            let host_if = self.net.host_if(rec.idx);
            let master =
                std::fs::read_link(Path::new("/sys/class/net").join(&host_if).join("master"));
            if master
                .ok()
                .and_then(|m| m.file_name().map(|n| n == self.net.bridge.as_str()))
                == Some(true)
            {
                continue;
            }
            let _g = self.lock_vm(&rec.id).await;
            if !self.is_active(&rec.id).await {
                continue;
            }
            // No init.pid while the supervisor is (re)booting the instance;
            // it attaches the network itself then.
            let rs = self.run_spec(&rec);
            let Some(pid) = std::fs::read_to_string(rs.init_pid_file())
                .ok()
                .and_then(|p| p.trim().parse::<i32>().ok())
            else {
                continue;
            };
            let Some(spec) = rs.net.clone() else { continue };
            warn!(
                "instance {}: {host_if} is missing from {}, re-attaching",
                rec.id, self.net.bridge
            );
            match tokio::task::spawn_blocking(move || attach::attach(&spec, pid)).await {
                Ok(Ok(())) => {
                    if let Err(e) = self.update_instance_network(&rec).await {
                        warn!("instance {}: reconfigure eth0: {e:#}", rec.id);
                    }
                }
                Ok(Err(e)) => warn!("instance {}: re-attach network: {e:#}", rec.id),
                Err(e) => warn!("instance {}: re-attach network: {e}", rec.id),
            }
        }
    }

    /// The schedule in effect, switching to the configured one if it
    /// changed. A change keeps the usage counted so far: counters of the
    /// current period are relabelled to the new schedule's period, so they
    /// restart at its next reset, not right away.
    fn traffic_schedule(&self) -> std::sync::MutexGuard<'_, Schedule> {
        let mut seen = self.schedule.lock().unwrap();
        let Some(wanted) = self.config.as_ref().map(|c| c.get().traffic_schedule()) else {
            return seen;
        };
        if wanted != *seen {
            let now = unix_now();
            info!(
                "traffic schedule: {:?}, day {}, UTC{:+}min",
                wanted.mode, wanted.reset_day, wanted.utc_offset_min
            );
            for rec in self.records().unwrap_or_default() {
                let old = seen.period(rec.created, now);
                let new = wanted.period(rec.created, now);
                let mut t = self.load_traffic(&rec.id);
                if old != new && t.period == old {
                    t.period = new;
                    self.save_traffic(&rec.id, &t);
                }
            }
            *seen = wanted;
        }
        seen
    }

    fn save_traffic(&self, id: &str, t: &Traffic) {
        let result = serde_json::to_vec(t)
            .map_err(anyhow::Error::from)
            .and_then(|raw| fsutil::write_atomic(&self.dir(id).join("traffic.json"), &raw));
        if let Err(e) = result {
            warn!("traffic {id}: {e:#}");
        }
    }

    fn load_traffic(&self, id: &str) -> Traffic {
        std::fs::read(self.dir(id).join("traffic.json"))
            .ok()
            .and_then(|raw| serde_json::from_slice(&raw).ok())
            .unwrap_or_default()
    }

    /// Fold the current veth counters of running instances into their
    /// persisted totals. Call periodically (and before deleting nothing:
    /// totals of deleted instances are discarded with them).
    pub async fn sample_traffic(&self) {
        let schedule = self.traffic_schedule();
        let now = unix_now();
        let Ok(records) = self.records() else { return };
        for rec in records {
            let period = schedule.period(rec.created, now);
            let base = Path::new("/sys/class/net").join(self.net.host_if(rec.idx));
            let read = |name: &str| -> Option<u64> {
                std::fs::read_to_string(base.join(name))
                    .ok()?
                    .trim()
                    .parse()
                    .ok()
            };
            let (Some(ifindex), Some(rx), Some(tx)) = (
                read("ifindex"),
                read("statistics/rx_bytes"),
                read("statistics/tx_bytes"),
            ) else {
                continue; // not running
            };
            let mut t = self.load_traffic(&rec.id);
            t.update(ifindex as u32, rx, tx, &period);
            self.save_traffic(&rec.id, &t);
        }
        drop(schedule);
    }

    fn summary(&self, rec: &Record, active: bool, period: &str) -> proto::VmSummary {
        let traffic = self.load_traffic(&rec.id);
        let (month_in, month_out) = traffic.month(period);
        let mut ips = vec![rec.addrs.ipv4.to_string()];
        ips.extend(rec.addrs.ipv6.map(|a| a.to_string()));
        let mut s = proto::VmSummary {
            vm_id: rec.id.clone(),
            status: if active {
                proto::VmStatus::Running
            } else {
                proto::VmStatus::Stopped
            } as i32,
            ips,
            traffic_in_bytes: traffic.total_in as i64,
            traffic_out_bytes: traffic.total_out as i64,
            monthly_traffic_in: month_in as i64,
            monthly_traffic_out: month_out as i64,
            ..Default::default()
        };
        if active {
            let cg = unit_cgroup(&rec.id);
            s.ram_used_mb = memory_used(&cg).map_or(0, |b| (b >> 20) as i64);
            if let Some(usage) = cpu_usage_usec(&cg) {
                let mut samples = self.cpu_samples.lock().unwrap();
                let now = Instant::now();
                if let Some((at, prev)) = samples.insert(rec.id.clone(), (now, usage)) {
                    let elapsed = now.duration_since(at).as_micros() as f64;
                    if elapsed > 0.0 {
                        let pct =
                            (usage.saturating_sub(prev)) as f64 / elapsed / f64::from(rec.cpu)
                                * 100.0;
                        s.cpu_pct = pct.clamp(0.0, 100.0) as f32;
                    }
                }
            }
        }
        s
    }
}

fn load_forwards(path: &Path) -> Result<Vec<PortForward>> {
    let raw = match std::fs::read(path) {
        Ok(raw) => raw,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e.into()),
    };
    let stored: Vec<StoredForward> =
        serde_json::from_slice(&raw).context("parse portforwards.json")?;
    stored
        .into_iter()
        .map(|s| {
            Ok(PortForward {
                vm_id: VmId::parse(&s.vm_id)?,
                proto: if s.proto == "udp" {
                    L4Proto::Udp
                } else {
                    L4Proto::Tcp
                },
                host_port: s.host_port,
                guest_port: s.guest_port,
                description: s.description,
            })
        })
        .collect()
}

/// Status check for reports (no process spawn per instance): the unit's
/// cgroup exists and holds processes. Lifecycle operations still ask systemd.
fn unit_running(id: &str) -> bool {
    std::fs::read_to_string(unit_cgroup(id).join("cgroup.events"))
        .is_ok_and(|e| e.contains("populated 1"))
}

fn read_kv(path: &Path, key: &str) -> Option<u64> {
    std::fs::read_to_string(path).ok()?.lines().find_map(|l| {
        let (k, v) = l.split_once(' ')?;
        (k == key).then(|| v.trim().parse().ok()).flatten()
    })
}

fn cpu_usage_usec(cg: &Path) -> Option<u64> {
    read_kv(&cg.join("cpu.stat"), "usage_usec")
}

/// Like `free`: total charge minus reclaimable page cache.
fn memory_used(cg: &Path) -> Option<u64> {
    let current: u64 = std::fs::read_to_string(cg.join("memory.current"))
        .ok()?
        .trim()
        .parse()
        .ok()?;
    let inactive = read_kv(&cg.join("memory.stat"), "inactive_file").unwrap_or(0);
    Some(current.saturating_sub(inactive))
}

fn hostname_for(id: &str) -> String {
    format!("vps-{}", &id[..8])
}

impl Runtime {
    /// `create` with the instance lock held.
    async fn create_locked(&self, spec: &InstanceSpec, builder: bool) -> Result<()> {
        let id = spec.vm_id.as_str();
        // Replacing an instance (reinstall, or a repeated create) keeps its
        // creation time and traffic counters: a reinstall must not hand out
        // a fresh monthly quota.
        let mut carried = None;
        if let Some(old) = self.load(id)? {
            carried = Some((old.created, self.load_traffic(id)));
        }
        if carried.is_some() || self.dir(id).exists() {
            info!("create {id}: replacing existing instance");
            self.delete_locked(&spec.vm_id).await?;
        }
        let (created, traffic) = match carried {
            Some((c, t)) if c > 0 => (c, Some(t)),
            Some((_, t)) => (unix_now(), Some(t)),
            None => (unix_now(), None),
        };
        // Choosing an index and writing the record that claims it must be one
        // step: creates of different instances run concurrently, and two of
        // them picking the same free index would share a veth name and
        // addresses. The slow part (disk, boot) runs outside the lock.
        let alloc = self.alloc.lock().unwrap();
        // Under the same lock as image GC: the serial chosen here is claimed
        // by the record below before GC can consider it unused.
        let image = self.images.get(&spec.os_image)?;
        let idx = self.allocate_idx()?;
        let rec = Record {
            id: id.to_owned(),
            idx,
            cpu: spec.cpu,
            ram_mb: spec.ram_mb,
            disk_gb: spec.disk_gb,
            bandwidth_mbps: spec.bandwidth_mbps,
            os_image: spec.os_image.clone(),
            lower: image.rootfs.clone(),
            stop_signal: image.stop_signal.clone(),
            hostname: hostname_for(id),
            addrs: self.net.addrs_for(idx)?,
            desired: Desired::Running,
            builder,
            created,
        };
        mkdir_private(&self.dir(id))?;
        self.save(&rec)?;
        if let Some(t) = &traffic {
            self.save_traffic(id, t);
        }
        drop(alloc);
        let started = Instant::now();
        if let Err(e) = self.provision(&rec, &spec.root_password).await {
            let _ = std::fs::remove_dir_all(self.dir(id));
            return Err(e.context("provision instance"));
        }
        self.reconcile_network().await?;
        self.launch(&rec).await?;
        info!(
            "instance {id} created from {} in {:?}",
            image.name,
            started.elapsed()
        );
        Ok(())
    }

    /// `delete` with the instance lock held.
    async fn delete_locked(&self, id: &VmId) -> Result<()> {
        self.halt(id.as_str(), true).await?;
        let dir = self.dir(id.as_str());
        if let Some(rec) = self.load(id.as_str())? {
            // Safety net if the supervisor died without cleaning up.
            let ifb = format!("{}i", self.net.host_if(rec.idx));
            if Path::new("/sys/class/net").join(&ifb).exists() {
                let _ = run(Command::new("ip").args(["link", "del", &ifb])).await;
            }
        }
        if dir.exists() {
            for sub in ["mnt/rootfs", "mnt/disk"] {
                sys::umount_if_mounted(&dir.join(sub))?;
            }
            tokio::fs::remove_dir_all(&dir)
                .await
                .with_context(|| format!("remove {}", dir.display()))?;
        }
        let _ = std::fs::remove_dir_all(Path::new(RUN_ROOT).join(id.as_str()));
        self.cpu_samples.lock().unwrap().remove(id.as_str());
        self.reconcile_network().await
    }
}

#[async_trait]
impl Instances for Runtime {
    async fn create(&self, spec: &InstanceSpec) -> Result<()> {
        let _g = self.lock_vm(spec.vm_id.as_str()).await;
        self.create_locked(spec, false).await
    }

    async fn reinstall(&self, spec: &InstanceSpec) -> Result<()> {
        // Delete + create gives a clean disk; port forwards are keyed by the
        // instance id and follow it to its (possibly new) address.
        let _g = self.lock_vm(spec.vm_id.as_str()).await;
        self.create_locked(spec, false).await
    }

    async fn start(&self, id: &VmId) -> Result<()> {
        let _g = self.lock_vm(id.as_str()).await;
        let rec = self.set_desired(id, Desired::Running)?;
        if self.is_active(id.as_str()).await {
            return Ok(());
        }
        self.save(&rec)?; // refresh runtime.json for the current binary/layout
        self.launch(&rec).await
    }

    async fn stop(&self, id: &VmId, force: bool) -> Result<()> {
        let _g = self.lock_vm(id.as_str()).await;
        self.set_desired(id, Desired::Stopped)?;
        self.halt(id.as_str(), force).await
    }

    async fn restart(&self, id: &VmId) -> Result<()> {
        let _g = self.lock_vm(id.as_str()).await;
        let rec = self.set_desired(id, Desired::Running)?;
        self.halt(id.as_str(), false).await?;
        self.launch(&rec).await
    }

    async fn delete(&self, id: &VmId) -> Result<()> {
        let _g = self.lock_vm(id.as_str()).await;
        self.delete_locked(id).await
    }

    async fn reset_password(&self, id: &VmId, password: &str) -> Result<()> {
        let _g = self.lock_vm(id.as_str()).await;
        let rec = self.require(id)?;
        let hash = customize::hash_password(password)?;
        if self.is_active(id.as_str()).await {
            let line = format!("root:{hash}\n");
            self.exec_target(id.as_str())
                .run(&["chpasswd", "-e"], line.as_bytes())
                .await
        } else {
            self.with_offline_rootfs(&rec, false, move |root| {
                customize::set_root_password(root, &hash)
            })
            .await
        }
    }

    async fn list(&self) -> Result<Vec<proto::VmSummary>> {
        let schedule = *self.traffic_schedule();
        let now = unix_now();
        let mut out = Vec::new();
        for rec in self.records()?.into_iter().filter(|r| !r.builder) {
            let active = unit_running(&rec.id);
            out.push(self.summary(&rec, active, &schedule.period(rec.created, now)));
        }
        Ok(out)
    }

    async fn images(&self) -> Result<Vec<proto::OsImageInfo>> {
        Ok(self
            .images
            .ready()
            .into_iter()
            .map(|i| proto::OsImageInfo {
                id: i.id,
                name: i.name,
            })
            .collect())
    }

    async fn details(&self) -> Result<Vec<InstanceDetails>> {
        let schedule = *self.traffic_schedule();
        let now = unix_now();
        let mut out = Vec::new();
        for rec in self.records()?.into_iter().filter(|r| !r.builder) {
            let active = unit_running(&rec.id);
            let period = schedule.period(rec.created, now);
            let mut d = InstanceDetails::from_summary(&self.summary(&rec, active, &period));
            d.created = rec.created;
            d.traffic_next_reset = schedule.next_reset(rec.created, now);
            d.hostname = rec.hostname.clone();
            d.cpu = rec.cpu;
            d.ram_mb = rec.ram_mb;
            d.disk_gb = rec.disk_gb;
            d.bandwidth_mbps = rec.bandwidth_mbps;
            d.os_image = rec.os_image.clone();
            d.dedicated = self
                .dedicated_for(&rec.id)
                .iter()
                .map(ToString::to_string)
                .collect();
            out.push(d);
        }
        Ok(out)
    }

    async fn console_log(&self, id: &VmId, max_bytes: usize) -> Result<String> {
        use std::io::{Read, Seek, SeekFrom};
        self.require(id)?;
        let path = self.dir(id.as_str()).join("console.log");
        let Ok(mut f) = std::fs::File::open(&path) else {
            return Ok(String::new());
        };
        let len = f.metadata()?.len();
        f.seek(SeekFrom::Start(len.saturating_sub(max_bytes as u64)))?;
        let mut buf = Vec::new();
        f.read_to_end(&mut buf)?;
        Ok(String::from_utf8_lossy(&buf).into_owned())
    }

    async fn open_console(&self, id: &VmId, size: Option<ConsoleSize>) -> Result<ConsoleIo> {
        self.require(id)?;
        if !self.is_active(id.as_str()).await {
            bail!("instance {id} is not running");
        }
        self.exec_target(id.as_str()).console(size)
    }
}

#[async_trait]
impl PortForwards for Runtime {
    async fn add(&self, rule: PortForward) -> Result<()> {
        self.require(&rule.vm_id)?;
        let mut forwards = self.forwards.lock().await;
        if let Some(existing) = forwards
            .iter()
            .find(|f| f.proto == rule.proto && f.host_port == rule.host_port)
        {
            if existing.vm_id == rule.vm_id && existing.guest_port == rule.guest_port {
                return Ok(());
            }
            bail!(
                "host port {}/{} is already forwarded",
                rule.host_port,
                rule.proto.as_str()
            );
        }
        if net::host_listening(rule.proto, rule.host_port) {
            bail!(
                "host port {}/{} is used by a host service",
                rule.host_port,
                rule.proto.as_str()
            );
        }
        let mut next = forwards.clone();
        next.push(rule);
        self.apply_network(&next).await?;
        self.save_forwards(&next)?;
        *forwards = next;
        Ok(())
    }

    async fn remove(&self, id: &VmId, proto: L4Proto, host_port: u16) -> Result<()> {
        let mut forwards = self.forwards.lock().await;
        let mut next = forwards.clone();
        next.retain(|f| !(&f.vm_id == id && f.proto == proto && f.host_port == host_port));
        if next.len() == forwards.len() {
            return Ok(());
        }
        self.apply_network(&next).await?;
        self.save_forwards(&next)?;
        *forwards = next;
        Ok(())
    }

    async fn list(&self, id: Option<&VmId>) -> Result<Vec<PortForward>> {
        let forwards = self.forwards.lock().await;
        Ok(forwards
            .iter()
            .filter(|f| id.is_none_or(|id| &f.vm_id == id))
            .cloned()
            .collect())
    }

    async fn remove_all(&self, id: &VmId) -> Result<()> {
        let mut forwards = self.forwards.lock().await;
        let mut next = forwards.clone();
        next.retain(|f| &f.vm_id != id);
        if next.len() == forwards.len() {
            return Ok(());
        }
        self.apply_network(&next).await?;
        self.save_forwards(&next)?;
        *forwards = next;
        Ok(())
    }

    async fn free_port(&self) -> Result<u16> {
        let forwards = self.forwards.lock().await;
        let mut rng = rand::rng();
        for _ in 0..200 {
            let port = rng.random_range(AUTO_PORTS);
            let taken = forwards.iter().any(|f| f.host_port == port)
                || net::host_listening(L4Proto::Tcp, port)
                || net::host_listening(L4Proto::Udp, port);
            if !taken {
                return Ok(port);
            }
        }
        bail!("no free host port in {AUTO_PORTS:?}")
    }
}

#[async_trait]
impl WgBindings for Runtime {
    async fn reconcile(&self, desired: Vec<proto::WgBindDesired>) -> Result<()> {
        let bindings: Vec<wg::Binding> = desired
            .iter()
            .filter_map(|d| match wg::Binding::from_proto(d) {
                Ok(b) => Some(b),
                Err(e) => {
                    warn!("wg {}: ignoring invalid binding: {e:#}", d.resource_id);
                    None
                }
            })
            .collect();
        let mut tunnels = self.tunnels.lock().await;
        if bindings.iter().any(|b| b.address.is_ipv6()) {
            self.net.enable_v6().await?;
        }
        tunnels.reconcile(&bindings).await?;
        let after = tunnels.addresses_by_vm();
        let before = std::mem::replace(&mut *self.dedicated.lock().unwrap(), after.clone());

        let mut todo = std::mem::take(&mut *self.net_pending.lock().unwrap());
        for vm in before.keys().chain(after.keys()) {
            if before.get(vm) != after.get(vm) {
                todo.insert(vm.clone());
            }
        }
        if todo.is_empty() {
            return Ok(());
        }
        // Anti-spoofing sets must allow the new source addresses first.
        self.reconcile_network().await?;
        for vm in todo {
            let Ok(id) = VmId::parse(&vm) else { continue };
            let _g = self.lock_vm(id.as_str()).await;
            let Some(rec) = self.load(id.as_str())? else {
                continue; // bound to an instance that is not on this host
            };
            match self.update_instance_network(&rec).await {
                Ok(()) => info!(
                    "instance {vm}: dedicated addresses now {:?}",
                    self.dedicated_for(&vm)
                ),
                Err(e) => {
                    warn!("instance {vm}: apply dedicated addresses: {e:#}");
                    self.net_pending.lock().unwrap().insert(vm);
                }
            }
        }
        Ok(())
    }
}
