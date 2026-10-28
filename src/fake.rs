//! In-memory backend used by protocol tests and `backend = "fake"` dev mode.
//! It records what it was asked to do and touches nothing on the host.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use anyhow::{Result, bail};
use async_trait::async_trait;
use tokio::sync::mpsc;

use crate::backend::{ConsoleIo, HostMetrics, Instances, PortForwards, Services, WgBindings};
use crate::model::{ConsoleSize, HostSnapshot, InstanceSpec, L4Proto, PortForward, VmId};
use crate::proto;

#[derive(Debug, Clone, PartialEq)]
pub struct FakeInstance {
    pub spec: InstanceSpec,
    pub running: bool,
}

#[derive(Default)]
pub struct Fake {
    pub instances: Mutex<BTreeMap<VmId, FakeInstance>>,
    pub rules: Mutex<Vec<PortForward>>,
    pub wg: Mutex<Vec<proto::WgBindDesired>>,
    pub create_calls: AtomicUsize,
    pub wg_reconciles: AtomicUsize,
    /// Artificial latency for create/reinstall (exercises in-flight replay).
    pub create_delay: Mutex<Duration>,
    next_port: Mutex<u16>,
}

impl Fake {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            next_port: Mutex::new(20000),
            ..Default::default()
        })
    }

    pub fn services(self: &Arc<Self>) -> Services {
        Services {
            instances: self.clone(),
            port_forwards: self.clone(),
            wg: self.clone(),
            host: self.clone(),
            images: None,
            monitor: None,
        }
    }

    fn with_instance<T>(&self, id: &VmId, f: impl FnOnce(&mut FakeInstance) -> T) -> Result<T> {
        let mut map = self.instances.lock().unwrap();
        match map.get_mut(id) {
            Some(inst) => Ok(f(inst)),
            None => bail!("instance {id} not found"),
        }
    }

    async fn delay(&self) {
        let d = *self.create_delay.lock().unwrap();
        if !d.is_zero() {
            tokio::time::sleep(d).await;
        }
    }
}

#[async_trait]
impl Instances for Fake {
    async fn create(&self, spec: &InstanceSpec) -> Result<()> {
        self.create_calls.fetch_add(1, Ordering::SeqCst);
        self.delay().await;
        self.instances.lock().unwrap().insert(
            spec.vm_id.clone(),
            FakeInstance {
                spec: spec.clone(),
                running: true,
            },
        );
        Ok(())
    }

    async fn reinstall(&self, spec: &InstanceSpec) -> Result<()> {
        self.create(spec).await
    }

    async fn start(&self, id: &VmId) -> Result<()> {
        self.with_instance(id, |i| i.running = true)
    }

    async fn stop(&self, id: &VmId, _force: bool) -> Result<()> {
        self.with_instance(id, |i| i.running = false)
    }

    async fn restart(&self, id: &VmId) -> Result<()> {
        self.with_instance(id, |i| i.running = true)
    }

    async fn delete(&self, id: &VmId) -> Result<()> {
        self.instances.lock().unwrap().remove(id);
        Ok(())
    }

    async fn reset_password(&self, id: &VmId, password: &str) -> Result<()> {
        self.with_instance(id, |i| i.spec.root_password = password.to_owned())
    }

    async fn list(&self) -> Result<Vec<proto::VmSummary>> {
        let map = self.instances.lock().unwrap();
        Ok(map
            .values()
            .enumerate()
            .map(|(n, i)| proto::VmSummary {
                vm_id: i.spec.vm_id.to_string(),
                status: if i.running {
                    proto::VmStatus::Running
                } else {
                    proto::VmStatus::Stopped
                } as i32,
                ips: vec![format!("10.91.0.{}", n + 2)],
                ..Default::default()
            })
            .collect())
    }

    async fn images(&self) -> Result<Vec<proto::OsImageInfo>> {
        Ok(vec![
            proto::OsImageInfo {
                id: "debian".into(),
                name: "Debian 13".into(),
            },
            proto::OsImageInfo {
                id: "alpine".into(),
                name: "Alpine 3.22".into(),
            },
        ])
    }

    async fn details(&self) -> Result<Vec<crate::model::InstanceDetails>> {
        let summaries = Instances::list(self).await?;
        let map = self.instances.lock().unwrap();
        Ok(summaries
            .iter()
            .map(|s| {
                let mut d = crate::model::InstanceDetails::from_summary(s);
                if let Some(i) = map.values().find(|i| i.spec.vm_id.as_str() == s.vm_id) {
                    d.cpu = i.spec.cpu;
                    d.ram_mb = i.spec.ram_mb;
                    d.disk_gb = i.spec.disk_gb;
                    d.bandwidth_mbps = i.spec.bandwidth_mbps;
                    d.os_image = i.spec.os_image.clone();
                }
                d
            })
            .collect())
    }

    /// Echo console: every input chunk is written back as output.
    async fn open_console(&self, id: &VmId, _size: Option<ConsoleSize>) -> Result<ConsoleIo> {
        self.with_instance(id, |_| ())?;
        let (in_tx, mut in_rx) = mpsc::channel::<Vec<u8>>(16);
        let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>(16);
        let (resize_tx, _resize_rx) = mpsc::channel(4);
        tokio::spawn(async move {
            while let Some(chunk) = in_rx.recv().await {
                if out_tx.send(chunk).await.is_err() {
                    break;
                }
            }
        });
        Ok(ConsoleIo {
            output: out_rx,
            input: in_tx,
            resize: resize_tx,
        })
    }
}

#[async_trait]
impl PortForwards for Fake {
    async fn add(&self, rule: PortForward) -> Result<()> {
        let mut rules = self.rules.lock().unwrap();
        if let Some(existing) = rules
            .iter()
            .find(|r| r.proto == rule.proto && r.host_port == rule.host_port)
        {
            if existing.vm_id == rule.vm_id && existing.guest_port == rule.guest_port {
                return Ok(());
            }
            bail!(
                "host port {}/{} already in use",
                rule.host_port,
                rule.proto.as_str()
            );
        }
        rules.push(rule);
        Ok(())
    }

    async fn remove(&self, id: &VmId, proto: L4Proto, host_port: u16) -> Result<()> {
        self.rules
            .lock()
            .unwrap()
            .retain(|r| !(&r.vm_id == id && r.proto == proto && r.host_port == host_port));
        Ok(())
    }

    async fn list(&self, id: Option<&VmId>) -> Result<Vec<PortForward>> {
        let rules = self.rules.lock().unwrap();
        Ok(rules
            .iter()
            .filter(|r| id.is_none_or(|id| &r.vm_id == id))
            .cloned()
            .collect())
    }

    async fn remove_all(&self, id: &VmId) -> Result<()> {
        self.rules.lock().unwrap().retain(|r| &r.vm_id != id);
        Ok(())
    }

    async fn free_port(&self) -> Result<u16> {
        let mut next = self.next_port.lock().unwrap();
        *next += 1;
        Ok(*next)
    }
}

#[async_trait]
impl WgBindings for Fake {
    async fn reconcile(&self, desired: Vec<proto::WgBindDesired>) -> Result<()> {
        *self.wg.lock().unwrap() = desired;
        self.wg_reconciles.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

#[async_trait]
impl HostMetrics for Fake {
    async fn snapshot(&self) -> Result<HostSnapshot> {
        Ok(HostSnapshot {
            cpu_pct: 1.5,
            ram_used_mb: 512,
            ram_total_mb: 2048,
            disk_used_gb: 5,
            disk_total_gb: 40,
            cpus: 2,
            ..Default::default()
        })
    }
}
