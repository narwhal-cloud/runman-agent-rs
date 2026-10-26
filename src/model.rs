//! Domain types passed from the protocol layer to the backends.
//!
//! Commands are validated and converted here once, so backends never see raw
//! protocol values (for example an unchecked `vm_id` that later becomes part of
//! a filesystem path).

use std::fmt;

use anyhow::{Result, bail};
use uuid::Uuid;

use crate::proto;

/// Platform-assigned instance identifier (always a canonical UUID).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize)]
#[serde(transparent)]
pub struct VmId(String);

impl VmId {
    pub fn parse(raw: &str) -> Result<Self> {
        match Uuid::parse_str(raw) {
            Ok(id) => Ok(Self(id.hyphenated().to_string())),
            Err(_) => bail!("invalid vm_id {raw:?}: expected a UUID"),
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for VmId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceSpec {
    pub vm_id: VmId,
    pub cpu: u32,
    pub ram_mb: u64,
    pub disk_gb: u64,
    /// 0 = unlimited.
    pub bandwidth_mbps: u32,
    pub os_image: String,
    pub root_password: String,
}

impl InstanceSpec {
    pub fn from_create(c: &proto::CmdCreateVm) -> Result<Self> {
        Self::build(
            &c.vm_id,
            c.cpu,
            c.ram_mb,
            c.disk_gb,
            c.bandwidth_mbps,
            &c.os_image,
            &c.root_password,
        )
    }

    pub fn from_reinstall(c: &proto::CmdReinstallVm) -> Result<Self> {
        Self::build(
            &c.vm_id,
            c.cpu,
            c.ram_mb,
            c.disk_gb,
            c.bandwidth_mbps,
            &c.os_image,
            &c.root_password,
        )
    }

    fn build(
        vm_id: &str,
        cpu: i32,
        ram_mb: i64,
        disk_gb: i64,
        bandwidth_mbps: i32,
        os_image: &str,
        root_password: &str,
    ) -> Result<Self> {
        if os_image.is_empty() {
            bail!("os_image is required");
        }
        validate_password(root_password)?;
        Ok(Self {
            vm_id: VmId::parse(vm_id)?,
            // Same floor as the Go agent: 1 vCPU, 128 MiB, 1 GiB.
            cpu: cpu.max(1) as u32,
            ram_mb: ram_mb.max(128) as u64,
            disk_gb: disk_gb.max(1) as u64,
            bandwidth_mbps: bandwidth_mbps.max(0) as u32,
            os_image: os_image.to_owned(),
            root_password: root_password.to_owned(),
        })
    }
}

pub fn validate_password(password: &str) -> Result<()> {
    if password.is_empty() {
        bail!("password is required");
    }
    // The password ends up in chpasswd input; reject anything that could split lines.
    if password.chars().any(|c| c.is_control()) {
        bail!("password must not contain control characters");
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum L4Proto {
    Tcp,
    Udp,
}

impl L4Proto {
    pub fn from_proto(p: i32) -> Result<Self> {
        match proto::Protocol::try_from(p) {
            Ok(proto::Protocol::Tcp) => Ok(Self::Tcp),
            Ok(proto::Protocol::Udp) => Ok(Self::Udp),
            _ => bail!("unsupported protocol {p}"),
        }
    }

    pub fn to_proto(self) -> proto::Protocol {
        match self {
            Self::Tcp => proto::Protocol::Tcp,
            Self::Udp => proto::Protocol::Udp,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub struct PortForward {
    pub vm_id: VmId,
    pub proto: L4Proto,
    pub host_port: u16,
    pub guest_port: u16,
    pub description: String,
}

impl PortForward {
    pub fn to_proto(&self) -> proto::PortForwardEntry {
        proto::PortForwardEntry {
            vm_id: self.vm_id.to_string(),
            protocol: self.proto.to_proto() as i32,
            host_port: i32::from(self.host_port),
            guest_port: i32::from(self.guest_port),
            description: self.description.clone(),
        }
    }
}

pub fn port(raw: i32, what: &str) -> Result<u16> {
    match u16::try_from(raw) {
        Ok(p) if p != 0 => Ok(p),
        _ => bail!("{what} {raw} out of range 1-65535"),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsoleSize {
    pub cols: u16,
    pub rows: u16,
}

impl ConsoleSize {
    pub fn new(cols: u32, rows: u32) -> Option<Self> {
        let cols = u16::try_from(cols).ok().filter(|v| *v > 0)?;
        let rows = u16::try_from(rows).ok().filter(|v| *v > 0)?;
        Some(Self { cols, rows })
    }
}

/// Host-level metrics reported in every heartbeat.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize)]
pub struct HostSnapshot {
    pub cpu_pct: f32,
    pub ram_used_mb: i64,
    pub ram_total_mb: i64,
    pub disk_used_gb: i64,
    pub disk_total_gb: i64,
    pub net_in_bps: i64,
    pub net_out_bps: i64,
    pub load: [f32; 3],
    pub uptime_secs: i64,
    pub cpus: i32,
    pub bandwidth_mbps: i32,
}

/// Instance as shown in the management panel.
#[derive(Debug, Clone, Default, serde::Serialize, PartialEq)]
pub struct InstanceDetails {
    pub id: String,
    pub hostname: String,
    /// "running", "stopped", "creating" or "error".
    pub status: String,
    pub cpu: u32,
    pub ram_mb: u64,
    pub disk_gb: u64,
    pub bandwidth_mbps: u32,
    pub os_image: String,
    pub ips: Vec<String>,
    /// Dedicated (WireGuard) addresses.
    pub dedicated: Vec<String>,
    pub cpu_pct: f32,
    pub ram_used_mb: i64,
    pub traffic_in: i64,
    pub traffic_out: i64,
    pub month_in: i64,
    pub month_out: i64,
}

impl InstanceDetails {
    pub fn from_summary(s: &proto::VmSummary) -> Self {
        Self {
            id: s.vm_id.clone(),
            status: status_name(s.status).into(),
            ips: s.ips.clone(),
            cpu_pct: s.cpu_pct,
            ram_used_mb: s.ram_used_mb,
            traffic_in: s.traffic_in_bytes,
            traffic_out: s.traffic_out_bytes,
            month_in: s.monthly_traffic_in,
            month_out: s.monthly_traffic_out,
            ..Default::default()
        }
    }
}

pub fn status_name(status: i32) -> &'static str {
    match proto::VmStatus::try_from(status) {
        Ok(proto::VmStatus::Running) => "running",
        Ok(proto::VmStatus::Stopped) => "stopped",
        Ok(proto::VmStatus::Creating) => "creating",
        Ok(proto::VmStatus::Error) => "error",
        _ => "unknown",
    }
}

/// An image offered for new instances.
#[derive(Debug, Clone, serde::Serialize, PartialEq)]
pub struct ImageInfo {
    pub id: String,
    pub name: String,
    pub serial: String,
    pub custom: bool,
    /// Custom images: what they were built from and how.
    pub base: String,
    pub script: String,
    /// Instances currently built on any version of this image.
    pub in_use: usize,
}

/// Request to build a custom image on the node.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct BuildRequest {
    /// New image id (`[a-z0-9-]`), also what instances are created with.
    pub image_id: String,
    pub name: String,
    /// Image to start from (official or custom).
    pub base: String,
    /// Shell script run as root inside a temporary instance.
    pub script: String,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq)]
pub struct BuildInfo {
    pub id: String,
    pub image_id: String,
    pub name: String,
    pub base: String,
    /// "running", "succeeded" or "failed".
    pub state: String,
    pub error: String,
    pub started: u64,
    pub finished: Option<u64>,
}
