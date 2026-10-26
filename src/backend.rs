//! Service interfaces the protocol layer drives.
//!
//! Each trait is implemented once by the real container runtime and once by
//! [`crate::fake`] for tests. Implementations must be idempotent where the
//! platform may replay a command (create/delete/port-forward add/remove).

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::model::{
    BuildInfo, BuildRequest, ConsoleSize, HostSnapshot, ImageInfo, InstanceDetails, InstanceSpec,
    L4Proto, PortForward, VmId,
};
use crate::proto;

#[async_trait]
pub trait Instances: Send + Sync {
    async fn create(&self, spec: &InstanceSpec) -> Result<()>;
    /// Replace the root filesystem; must also work when the instance is unknown
    /// locally (state lost), in which case it behaves like `create`.
    async fn reinstall(&self, spec: &InstanceSpec) -> Result<()>;
    async fn start(&self, id: &VmId) -> Result<()>;
    async fn stop(&self, id: &VmId, force: bool) -> Result<()>;
    async fn restart(&self, id: &VmId) -> Result<()>;
    /// Deleting an unknown instance succeeds.
    async fn delete(&self, id: &VmId) -> Result<()>;
    async fn reset_password(&self, id: &VmId, password: &str) -> Result<()>;
    /// Runtime summaries (status, usage, IPs, traffic counters) for heartbeats.
    async fn list(&self) -> Result<Vec<proto::VmSummary>>;
    async fn images(&self) -> Result<Vec<proto::OsImageInfo>>;
    async fn open_console(&self, id: &VmId, size: Option<ConsoleSize>) -> Result<ConsoleIo>;

    /// Richer view for the management panel.
    async fn details(&self) -> Result<Vec<InstanceDetails>> {
        Ok(self
            .list()
            .await?
            .iter()
            .map(InstanceDetails::from_summary)
            .collect())
    }

    /// Tail of the instance's console output.
    async fn console_log(&self, _id: &VmId, _max_bytes: usize) -> Result<String> {
        anyhow::bail!("console log not available")
    }
}

/// An attached interactive TTY.
///
/// The session ends when `output` yields `None` (the TTY exited) or when the
/// caller drops `input` (the platform closed the session).
pub struct ConsoleIo {
    pub output: mpsc::Receiver<Vec<u8>>,
    pub input: mpsc::Sender<Vec<u8>>,
    pub resize: mpsc::Sender<ConsoleSize>,
}

#[async_trait]
pub trait PortForwards: Send + Sync {
    /// Adding an identical existing rule succeeds; a host port owned by
    /// another rule is an error.
    async fn add(&self, rule: PortForward) -> Result<()>;
    async fn remove(&self, id: &VmId, proto: L4Proto, host_port: u16) -> Result<()>;
    async fn list(&self, id: Option<&VmId>) -> Result<Vec<PortForward>>;
    async fn remove_all(&self, id: &VmId) -> Result<()>;
    /// Choose an unused host port for the automatic SSH rule.
    async fn free_port(&self) -> Result<u16>;
}

#[async_trait]
pub trait WgBindings: Send + Sync {
    /// Converge local bindings to exactly `desired` (full desired-state snapshot).
    async fn reconcile(&self, desired: Vec<proto::WgBindDesired>) -> Result<()>;
}

#[async_trait]
pub trait HostMetrics: Send + Sync {
    async fn snapshot(&self) -> Result<HostSnapshot>;
}

/// Image management for the local panel: listing, custom builds, removal.
#[async_trait]
pub trait ImageAdmin: Send + Sync {
    async fn list_images(&self) -> Result<Vec<ImageInfo>>;
    /// Start a build in the background; returns the build id.
    fn start_build(&self, req: BuildRequest) -> Result<String>;
    fn builds(&self) -> Vec<BuildInfo>;
    fn build_log(&self, build_id: &str) -> Result<String>;
    /// Stop offering a custom image (files go once no instance uses them).
    async fn delete_image(&self, id: &str) -> Result<()>;
}

/// Bundle of services handed to the protocol layer.
#[derive(Clone)]
pub struct Services {
    pub instances: Arc<dyn Instances>,
    pub port_forwards: Arc<dyn PortForwards>,
    pub wg: Arc<dyn WgBindings>,
    pub host: Arc<dyn HostMetrics>,
    /// None for backends without image management (the in-memory fake).
    pub images: Option<Arc<dyn ImageAdmin>>,
}

/// Every instance gets a random host port forwarded to SSH (22/tcp), as the
/// Go agent did. Failure is logged, not fatal: the instance itself exists.
/// Returns the host port of the SSH forward, if there is one.
pub async fn ensure_ssh_forward(pf: &dyn PortForwards, id: &VmId) -> Option<u16> {
    match pf.list(Some(id)).await {
        Ok(rules) => {
            if let Some(r) = rules
                .iter()
                .find(|r| r.proto == L4Proto::Tcp && r.guest_port == 22)
            {
                return Some(r.host_port);
            }
        }
        Err(e) => {
            tracing::warn!("ssh forward for {id}: list rules: {e:#}");
            return None;
        }
    }
    for _ in 0..5 {
        let host_port = match pf.free_port().await {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!("ssh forward for {id}: {e:#}");
                return None;
            }
        };
        let rule = PortForward {
            vm_id: id.clone(),
            proto: L4Proto::Tcp,
            host_port,
            guest_port: 22,
            description: "ssh".into(),
        };
        match pf.add(rule).await {
            Ok(()) => {
                tracing::info!("ssh forward for {id}: {host_port} -> 22");
                return Some(host_port);
            }
            Err(e) => tracing::warn!("ssh forward for {id} on {host_port}: {e:#}"),
        }
    }
    None
}
