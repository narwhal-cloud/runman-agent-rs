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
    ConsoleSize, HostSnapshot, InstanceDetails, InstanceSpec, L4Proto, PortForward, VmId,
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

/// Bundle of services handed to the protocol layer.
#[derive(Clone)]
pub struct Services {
    pub instances: Arc<dyn Instances>,
    pub port_forwards: Arc<dyn PortForwards>,
    pub wg: Arc<dyn WgBindings>,
    pub host: Arc<dyn HostMetrics>,
}
