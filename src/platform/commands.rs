//! Execution of platform commands.
//!
//! - Commands for the same instance run strictly one after another.
//! - The platform persists commands and may replay a `command_id` after a
//!   reconnect. A replay of a running command is ignored (its result is sent
//!   when it finishes); a replay of a finished command re-sends the cached
//!   result instead of executing it twice.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use tracing::{info, warn};

use super::Link;
use crate::backend::Services;
use crate::model::{InstanceSpec, L4Proto, PortForward, VmId, port, validate_password};
use crate::proto::agent_envelope::Payload as Up;
use crate::proto::platform_envelope::Payload as Down;
use crate::proto::{self, CommandResult};

const RESULT_TTL: Duration = Duration::from_secs(3600);
const CACHE_SOFT_LIMIT: usize = 1024;

enum Entry {
    Running,
    Done(Box<Up>, Instant),
}

pub struct CommandRunner {
    services: Services,
    link: Link,
    cache: Mutex<HashMap<String, Entry>>,
    vm_locks: Mutex<HashMap<VmId, Arc<tokio::sync::Mutex<()>>>>,
}

impl CommandRunner {
    pub fn new(services: Services, link: Link) -> Arc<Self> {
        Arc::new(Self {
            services,
            link,
            cache: Mutex::default(),
            vm_locks: Mutex::default(),
        })
    }

    /// Accept a command from the stream; execution happens in the background.
    pub async fn submit(self: &Arc<Self>, command_id: String, payload: Option<Down>) {
        if !command_id.is_empty() {
            let cached = {
                let mut cache = self.cache.lock().unwrap();
                match cache.get(&command_id) {
                    Some(Entry::Running) => return,
                    Some(Entry::Done(reply, _)) => Some((**reply).clone()),
                    None => {
                        prune(&mut cache);
                        cache.insert(command_id.clone(), Entry::Running);
                        None
                    }
                }
            };
            if let Some(reply) = cached {
                info!("command {command_id} replayed; re-sending cached result");
                self.link.send(reply).await;
                return;
            }
        }

        let this = self.clone();
        tokio::spawn(async move {
            let reply = this.execute(&command_id, payload).await;
            if !command_id.is_empty() {
                this.cache.lock().unwrap().insert(
                    command_id.clone(),
                    Entry::Done(Box::new(reply.clone()), Instant::now()),
                );
            }
            if !this.link.send(reply).await {
                warn!("command {command_id}: no platform connection; result kept for replay");
            }
        });
    }

    async fn execute(&self, command_id: &str, payload: Option<Down>) -> Up {
        let kind = payload.as_ref().map_or("empty", kind_name);
        // Handled outside the lifecycle path: it answers with its own message.
        if let Some(Down::GetPortFwds(q)) = &payload {
            match self.list_port_forwards(&q.vm_id).await {
                Ok(entries) => {
                    return Up::PortFwdList(proto::PortForwardList {
                        command_id: command_id.to_owned(),
                        entries,
                    });
                }
                Err(e) => return result(command_id, Err(e)),
            }
        }

        let started = Instant::now();
        let res = self.run(payload).await;
        match &res {
            Ok(()) => info!(
                "command {command_id} ({kind}) ok in {:?}",
                started.elapsed()
            ),
            Err(e) => warn!("command {command_id} ({kind}) failed: {e:#}"),
        }
        result(command_id, res)
    }

    async fn run(&self, payload: Option<Down>) -> Result<()> {
        let s = &self.services;
        match payload {
            Some(Down::CreateVm(c)) => {
                let spec = InstanceSpec::from_create(&c)?;
                let _g = self.lock_vm(&spec.vm_id).await;
                s.instances.create(&spec).await?;
                self.ensure_ssh_forward(&spec.vm_id).await;
                Ok(())
            }
            Some(Down::ReinstallVm(c)) => {
                let spec = InstanceSpec::from_reinstall(&c)?;
                let _g = self.lock_vm(&spec.vm_id).await;
                s.instances.reinstall(&spec).await?;
                self.ensure_ssh_forward(&spec.vm_id).await;
                Ok(())
            }
            Some(Down::StartVm(c)) => {
                let id = VmId::parse(&c.vm_id)?;
                let _g = self.lock_vm(&id).await;
                s.instances.start(&id).await
            }
            Some(Down::StopVm(c)) => {
                let id = VmId::parse(&c.vm_id)?;
                let _g = self.lock_vm(&id).await;
                s.instances.stop(&id, c.force).await
            }
            Some(Down::RestartVm(c)) => {
                let id = VmId::parse(&c.vm_id)?;
                let _g = self.lock_vm(&id).await;
                s.instances.restart(&id).await
            }
            Some(Down::DeleteVm(c)) => {
                let id = VmId::parse(&c.vm_id)?;
                let _g = self.lock_vm(&id).await;
                s.instances.delete(&id).await?;
                s.port_forwards.remove_all(&id).await
            }
            Some(Down::ResetPassword(c)) => {
                let id = VmId::parse(&c.vm_id)?;
                validate_password(&c.new_password)?;
                let _g = self.lock_vm(&id).await;
                s.instances.reset_password(&id, &c.new_password).await
            }
            Some(Down::SetPortFwd(c)) => {
                s.port_forwards
                    .add(PortForward {
                        vm_id: VmId::parse(&c.vm_id)?,
                        proto: L4Proto::from_proto(c.protocol)?,
                        host_port: port(c.host_port, "host_port")?,
                        guest_port: port(c.guest_port, "guest_port")?,
                        description: c.description,
                    })
                    .await
            }
            Some(Down::DelPortFwd(c)) => {
                let id = VmId::parse(&c.vm_id)?;
                let proto = L4Proto::from_proto(c.protocol)?;
                s.port_forwards
                    .remove(&id, proto, port(c.host_port, "host_port")?)
                    .await
            }
            Some(other) => bail!("unsupported command {}", kind_name(&other)),
            None => bail!("empty or unknown command payload"),
        }
    }

    async fn list_port_forwards(&self, vm_id: &str) -> Result<Vec<proto::PortForwardEntry>> {
        let id = VmId::parse(vm_id)?;
        let rules = self.services.port_forwards.list(Some(&id)).await?;
        Ok(rules.iter().map(PortForward::to_proto).collect())
    }

    /// Every instance gets a random host port forwarded to SSH (22/tcp), like
    /// the Go agent. Failure is logged, not fatal: the instance itself exists.
    async fn ensure_ssh_forward(&self, id: &VmId) {
        let pf = &self.services.port_forwards;
        match pf.list(Some(id)).await {
            Ok(rules)
                if rules
                    .iter()
                    .any(|r| r.proto == L4Proto::Tcp && r.guest_port == 22) =>
            {
                return;
            }
            Ok(_) => {}
            Err(e) => {
                warn!("ssh forward for {id}: list rules: {e:#}");
                return;
            }
        }
        for _ in 0..5 {
            let host_port = match pf.free_port().await {
                Ok(p) => p,
                Err(e) => {
                    warn!("ssh forward for {id}: {e:#}");
                    return;
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
                    info!("ssh forward for {id}: {host_port} -> 22");
                    return;
                }
                Err(e) => warn!("ssh forward for {id} on {host_port}: {e:#}"),
            }
        }
    }

    async fn lock_vm(&self, id: &VmId) -> tokio::sync::OwnedMutexGuard<()> {
        let lock = {
            let mut locks = self.vm_locks.lock().unwrap();
            if locks.len() > CACHE_SOFT_LIMIT {
                locks.retain(|_, l| Arc::strong_count(l) > 1);
            }
            locks.entry(id.clone()).or_default().clone()
        };
        lock.lock_owned().await
    }
}

fn prune(cache: &mut HashMap<String, Entry>) {
    if cache.len() >= CACHE_SOFT_LIMIT {
        cache.retain(|_, e| match e {
            Entry::Running => true,
            Entry::Done(_, at) => at.elapsed() < RESULT_TTL,
        });
    }
}

fn result(command_id: &str, res: Result<()>) -> Up {
    Up::CmdResult(CommandResult {
        command_id: command_id.to_owned(),
        success: res.is_ok(),
        error: res.err().map(|e| format!("{e:#}")).unwrap_or_default(),
        data: Vec::new(),
    })
}

fn kind_name(p: &Down) -> &'static str {
    match p {
        Down::CreateVm(_) => "create_vm",
        Down::StartVm(_) => "start_vm",
        Down::StopVm(_) => "stop_vm",
        Down::RestartVm(_) => "restart_vm",
        Down::DeleteVm(_) => "delete_vm",
        Down::ReinstallVm(_) => "reinstall_vm",
        Down::ResetPassword(_) => "reset_password",
        Down::SetPortFwd(_) => "set_port_fwd",
        Down::DelPortFwd(_) => "del_port_fwd",
        Down::GetPortFwds(_) => "get_port_fwds",
        Down::Ping(_) => "ping",
        Down::ConsoleOpen(_) => "console_open",
        Down::ConsoleInput(_) => "console_input",
        Down::ConsoleResize(_) => "console_resize",
        Down::ConsoleClose(_) => "console_close",
        Down::WgSyncResponse(_) => "wg_sync_response",
    }
}
