//! Per-instance launch description shared by the agent and the supervisor.

use std::path::PathBuf;

use anyhow::{Result, bail};
use serde::{Deserialize, Serialize};

/// Size of every instance's UID/GID range.
pub const ID_RANGE: u32 = 65536;
/// First host UID used for instance ranges (instance `idx` gets
/// `ID_BASE + idx * ID_RANGE`).
pub const ID_BASE: u32 = 1_000_000;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct RunSpec {
    pub id: String,
    /// `<data_dir>/instances/<id>`
    pub dir: PathBuf,
    /// Read-only image template (unshifted ownership).
    pub lower: PathBuf,
    pub uid_base: u32,
    pub hostname: String,
    /// Signal that makes the image's init power off (`SIGRTMIN+4` for systemd,
    /// `SIGUSR2` for busybox init).
    pub stop_signal: String,
    /// Expose `/dev/net/tun`.
    pub tun: bool,
    /// `/run/runman-agent/<id>`
    pub run_dir: PathBuf,
    /// None: loopback only.
    pub net: Option<NetSpec>,
    /// CPU quota in cores, mirrored onto the instance's cgroup root so lxcfs
    /// can show it (the effective limit is the unit's `CPUQuota`).
    #[serde(default)]
    pub cpus: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NetSpec {
    /// Host side of the veth pair (the instance side is always `eth0`).
    pub host_if: String,
    pub bridge: String,
    pub mac: String,
    /// 0 = unlimited.
    pub bandwidth_mbps: u32,
}

impl RunSpec {
    pub fn disk_image(&self) -> PathBuf {
        self.dir.join("disk.img")
    }
    pub fn mnt_disk(&self) -> PathBuf {
        self.dir.join("mnt/disk")
    }
    pub fn mnt_lower(&self) -> PathBuf {
        self.dir.join("mnt/lower")
    }
    pub fn mnt_upper(&self) -> PathBuf {
        self.dir.join("mnt/upper")
    }
    pub fn mnt_rootfs(&self) -> PathBuf {
        self.dir.join("mnt/rootfs")
    }
    pub fn console_log(&self) -> PathBuf {
        self.dir.join("console.log")
    }
    pub fn init_pid_file(&self) -> PathBuf {
        self.run_dir.join("init.pid")
    }
}

const GLIBC_SIGRTMIN: i32 = 34;

pub fn parse_signal(name: &str) -> Result<i32> {
    if let Some(off) = name.strip_prefix("SIGRTMIN+") {
        let off: i32 = off.parse()?;
        // The container's init is a glibc program, whose SIGRTMIN is 34.
        // musl (this binary) reserves one more signal, so libc::SIGRTMIN()
        // would be 35 and SIGRTMIN+4 (poweroff) would arrive as reboot.
        return Ok(GLIBC_SIGRTMIN + off);
    }
    Ok(match name {
        "SIGTERM" => libc::SIGTERM,
        "SIGINT" => libc::SIGINT,
        "SIGUSR1" => libc::SIGUSR1,
        "SIGUSR2" => libc::SIGUSR2,
        "SIGPWR" => libc::SIGPWR,
        _ => bail!("unsupported stop signal {name}"),
    })
}

pub fn unit_name(id: &str) -> String {
    format!("runman-{id}.service")
}

/// cgroup v2 directory of an instance's systemd unit.
pub fn unit_cgroup(id: &str) -> PathBuf {
    PathBuf::from("/sys/fs/cgroup/system.slice").join(unit_name(id))
}
