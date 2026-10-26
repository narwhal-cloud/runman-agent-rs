//! Host side of dedicated IPs over kernel WireGuard.
//!
//! One interface per binding (`rw<n>`), living in the host network namespace
//! so the private key never enters the instance. The binding's public address
//! is assigned inside the instance (see `customize::write_network`); here we
//! only make the host route it:
//!
//! - inbound:  `<addr> dev <bridge>` (main table) — arrives on `rw<n>`, goes
//!   to the instance;
//! - outbound: `ip rule from <addr> lookup <20000+n>` whose table holds
//!   `default dev rw<n>` — anything the instance sends from that address
//!   leaves through the tunnel, unNATed.

use std::collections::BTreeMap;
use std::hash::{Hash, Hasher};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tracing::{info, warn};

use super::image::run;
use crate::model::VmId;
use crate::proto::WgBindDesired;

const RULE_PRIORITY: &str = "1000";
const MTU: &str = "1420";

/// A validated binding. `Debug` is implemented by hand to keep keys out of logs.
#[derive(Clone)]
pub struct Binding {
    pub resource_id: String,
    pub vm_id: VmId,
    pub address: IpAddr,
    private_key: String,
    peer_public_key: String,
    preshared_key: String,
    endpoint: String,
    allowed_ips: Vec<String>,
    keepalive: u16,
}

impl std::fmt::Debug for Binding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Binding")
            .field("resource_id", &self.resource_id)
            .field("vm_id", &self.vm_id)
            .field("address", &self.address)
            .field("endpoint", &self.endpoint)
            .finish_non_exhaustive()
    }
}

impl Binding {
    pub fn from_proto(d: &WgBindDesired) -> Result<Self> {
        if d.resource_id.is_empty() || d.resource_id.len() > 128 {
            bail!("invalid resource_id");
        }
        let vm_id = VmId::parse(&d.vm_id)?;
        let address: IpAddr = d
            .address
            .split('/')
            .next()
            .unwrap_or_default()
            .trim()
            .parse()
            .with_context(|| format!("invalid address {:?}", d.address))?;
        for (what, key, required) in [
            ("private_key", &d.private_key, true),
            ("peer_public_key", &d.peer_public_key, true),
            ("preshared_key", &d.preshared_key, false),
        ] {
            if key.is_empty() && !required {
                continue;
            }
            if !is_wg_key(key) {
                bail!("{what} is not a base64 WireGuard key");
            }
        }
        let endpoint = d.endpoint.trim().to_owned();
        let (host, port) = endpoint
            .rsplit_once(':')
            .context("endpoint must be host:port")?;
        if host.trim_matches(['[', ']']).is_empty() || port.parse::<u16>().is_err() {
            bail!("invalid endpoint {endpoint:?}");
        }
        let mut allowed_ips = Vec::new();
        for raw in &d.allowed_ips {
            for item in raw.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                let (ip, len) = item.split_once('/').unwrap_or((item, ""));
                let ip: IpAddr = ip
                    .parse()
                    .with_context(|| format!("invalid allowed IP {item:?}"))?;
                let max = if ip.is_ipv4() { 32 } else { 128 };
                let len = if len.is_empty() {
                    max
                } else {
                    len.parse::<u8>()
                        .ok()
                        .filter(|l| *l <= max)
                        .context("bad allowed IP prefix")?
                };
                allowed_ips.push(format!("{ip}/{len}"));
            }
        }
        if allowed_ips.is_empty() {
            // Same default as the platform's own configs: anything may come
            // from and go to the gateway.
            allowed_ips = vec!["0.0.0.0/0".into(), "::/0".into()];
        }
        Ok(Self {
            resource_id: d.resource_id.clone(),
            vm_id,
            address,
            private_key: d.private_key.clone(),
            peer_public_key: d.peer_public_key.clone(),
            preshared_key: d.preshared_key.clone(),
            endpoint,
            allowed_ips,
            keepalive: u16::try_from(d.keepalive_sec.max(0)).unwrap_or(25),
        })
    }

    /// In-memory change detection (never persisted: it covers the keys).
    fn fingerprint(&self) -> u64 {
        let mut h = std::collections::hash_map::DefaultHasher::new();
        (
            &self.vm_id,
            self.address,
            &self.private_key,
            &self.peer_public_key,
            &self.preshared_key,
            &self.endpoint,
            &self.allowed_ips,
            self.keepalive,
        )
            .hash(&mut h);
        h.finish()
    }
}

fn is_wg_key(s: &str) -> bool {
    s.len() == 44
        && s.ends_with('=')
        && s[..43]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
}

/// What is persisted per binding: enough to tear it down after a restart.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Slot {
    pub n: u32,
    pub vm_id: String,
    pub address: IpAddr,
}

pub struct Tunnels {
    state_path: PathBuf,
    bridge: String,
    prefix: String,
    table_base: u32,
    pub slots: BTreeMap<String, Slot>,
    applied: BTreeMap<String, (u64, SocketAddr)>,
}

impl Tunnels {
    pub fn load(data_dir: &Path, bridge: &str, prefix: &str, table_base: u32) -> Result<Self> {
        let state_path = data_dir.join("wg.json");
        let slots = match std::fs::read(&state_path) {
            Ok(raw) => serde_json::from_slice(&raw).context("parse wg.json")?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(e) => return Err(e.into()),
        };
        Ok(Self {
            state_path,
            bridge: bridge.to_owned(),
            prefix: prefix.to_owned(),
            table_base,
            slots,
            applied: BTreeMap::new(),
        })
    }

    fn save(&self) -> Result<()> {
        super::fsutil::write_atomic(&self.state_path, &serde_json::to_vec_pretty(&self.slots)?)
    }

    /// Dedicated addresses per instance id, from the current state.
    pub fn addresses_by_vm(&self) -> BTreeMap<String, Vec<IpAddr>> {
        let mut m: BTreeMap<String, Vec<IpAddr>> = BTreeMap::new();
        for s in self.slots.values() {
            m.entry(s.vm_id.clone()).or_default().push(s.address);
        }
        m
    }

    /// Converge host tunnels to `desired`. Errors of single bindings are
    /// logged and retried on the next round; the others still converge.
    pub async fn reconcile(&mut self, desired: &[Binding]) -> Result<()> {
        let wanted: BTreeMap<&str, &Binding> = desired
            .iter()
            .map(|b| (b.resource_id.as_str(), b))
            .collect();
        let stale: Vec<String> = self
            .slots
            .keys()
            .filter(|r| !wanted.contains_key(r.as_str()))
            .cloned()
            .collect();
        for resource in stale {
            let slot = self.slots[&resource].clone();
            if let Err(e) = self.teardown(&slot).await {
                warn!("wg {resource}: teardown: {e:#}");
                continue;
            }
            info!(
                "wg {resource}: removed {} from {}",
                slot.address, slot.vm_id
            );
            self.slots.remove(&resource);
            self.applied.remove(&resource);
            self.save()?;
        }

        for b in desired {
            let endpoint = match resolve_endpoint(&b.endpoint).await {
                Ok(ep) => ep,
                Err(e) => {
                    warn!("wg {}: {e:#}", b.resource_id);
                    continue;
                }
            };
            let fp = b.fingerprint();
            let same_slot = self
                .slots
                .get(&b.resource_id)
                .is_some_and(|s| s.vm_id == b.vm_id.as_str() && s.address == b.address);
            // Re-create a tunnel whose interface vanished (deleted by hand,
            // network restart) even though its configuration is unchanged.
            let iface_present = self
                .slots
                .get(&b.resource_id)
                .is_some_and(|s| Path::new("/sys/class/net").join(self.iface(s)).exists());
            match self.applied.get(&b.resource_id) {
                Some((applied_fp, applied_ep))
                    if *applied_fp == fp && same_slot && iface_present =>
                {
                    if *applied_ep != endpoint {
                        // The gateway's name now resolves elsewhere.
                        let slot = &self.slots[&b.resource_id];
                        let ep = endpoint.to_string();
                        if let Err(e) = run(Command::new("wg").args([
                            "set",
                            &self.iface(slot),
                            "peer",
                            &b.peer_public_key,
                            "endpoint",
                            &ep,
                        ]))
                        .await
                        {
                            warn!("wg {}: update endpoint: {e:#}", b.resource_id);
                            continue;
                        }
                        self.applied.insert(b.resource_id.clone(), (fp, endpoint));
                    }
                    continue;
                }
                _ => {}
            }
            let slot = match self.slots.get(&b.resource_id) {
                Some(s) if same_slot => s.clone(),
                Some(old) => {
                    // Address or instance changed: start from a clean slate.
                    let old = old.clone();
                    if let Err(e) = self.teardown(&old).await {
                        warn!("wg {}: teardown: {e:#}", b.resource_id);
                        continue;
                    }
                    Slot {
                        n: old.n,
                        vm_id: b.vm_id.to_string(),
                        address: b.address,
                    }
                }
                None => Slot {
                    n: self.free_n(),
                    vm_id: b.vm_id.to_string(),
                    address: b.address,
                },
            };
            self.slots.insert(b.resource_id.clone(), slot.clone());
            self.save()?;
            match self.setup(&slot, b, endpoint).await {
                Ok(()) => {
                    info!(
                        "wg {}: {} via {} for {}",
                        b.resource_id, b.address, endpoint, b.vm_id
                    );
                    self.applied.insert(b.resource_id.clone(), (fp, endpoint));
                }
                Err(e) => {
                    warn!("wg {}: setup: {e:#}", b.resource_id);
                    self.applied.remove(&b.resource_id);
                }
            }
        }
        Ok(())
    }

    fn iface(&self, slot: &Slot) -> String {
        format!("{}{}", self.prefix, slot.n)
    }

    fn table(&self, slot: &Slot) -> String {
        (self.table_base + slot.n).to_string()
    }

    fn free_n(&self) -> u32 {
        let used: std::collections::BTreeSet<u32> = self.slots.values().map(|s| s.n).collect();
        (0..).find(|n| !used.contains(n)).expect("u32 space")
    }

    async fn setup(&self, slot: &Slot, b: &Binding, endpoint: SocketAddr) -> Result<()> {
        let ifc = self.iface(slot);
        let table = self.table(slot);
        if Path::new("/sys/class/net").join(&ifc).exists() {
            run(Command::new("ip").args(["link", "del", &ifc])).await?;
        }
        run(Command::new("ip").args(["link", "add", &ifc, "type", "wireguard"])).await?;
        wg_with_secret(&["set", &ifc, "private-key", "/dev/stdin"], &b.private_key).await?;
        let ep = endpoint.to_string();
        let allowed = b.allowed_ips.join(",");
        let keepalive = b.keepalive.to_string();
        let mut args = vec![
            "set",
            &ifc,
            "peer",
            &b.peer_public_key,
            "endpoint",
            &ep,
            "allowed-ips",
            &allowed,
            "persistent-keepalive",
            &keepalive,
        ];
        if b.preshared_key.is_empty() {
            run(Command::new("wg").args(&args)).await?;
        } else {
            args.extend(["preshared-key", "/dev/stdin"]);
            wg_with_secret(&args, &b.preshared_key).await?;
        }
        run(Command::new("ip").args(["link", "set", &ifc, "mtu", MTU, "up"])).await?;
        if b.address.is_ipv4() {
            let _ = tokio::fs::write(format!("/proc/sys/net/ipv4/conf/{ifc}/rp_filter"), "0").await;
        }

        let fam = if b.address.is_ipv4() { "-4" } else { "-6" };
        let host = host_prefix(b.address);
        run(Command::new("ip").args([
            fam, "route", "replace", "default", "dev", &ifc, "table", &table,
        ]))
        .await?;
        run(Command::new("ip").args([fam, "route", "replace", &host, "dev", &self.bridge])).await?;
        // `ip rule add` is not idempotent: drop an existing copy first.
        let _ = Command::new("ip")
            .args([fam, "rule", "del", "from", &host, "lookup", &table])
            .stderr(std::process::Stdio::null())
            .status()
            .await;
        run(Command::new("ip").args([
            fam,
            "rule",
            "add",
            "from",
            &host,
            "lookup",
            &table,
            "priority",
            RULE_PRIORITY,
        ]))
        .await?;
        Ok(())
    }

    async fn teardown(&self, slot: &Slot) -> Result<()> {
        let fam = if slot.address.is_ipv4() { "-4" } else { "-6" };
        let host = host_prefix(slot.address);
        let table = self.table(slot);
        while Command::new("ip")
            .args([fam, "rule", "del", "from", &host, "lookup", &table])
            .stderr(std::process::Stdio::null())
            .status()
            .await
            .is_ok_and(|s| s.success())
        {}
        let _ = Command::new("ip")
            .args([fam, "route", "flush", "table", &table])
            .stderr(std::process::Stdio::null())
            .status()
            .await;
        let _ = Command::new("ip")
            .args([fam, "route", "del", &host, "dev", &self.bridge])
            .stderr(std::process::Stdio::null())
            .status()
            .await;
        let ifc = self.iface(slot);
        if Path::new("/sys/class/net").join(&ifc).exists() {
            run(Command::new("ip").args(["link", "del", &ifc])).await?;
        }
        Ok(())
    }
}

fn host_prefix(a: IpAddr) -> String {
    match a {
        IpAddr::V4(v4) => format!("{v4}/32"),
        IpAddr::V6(v6) => format!("{v6}/128"),
    }
}

async fn wg_with_secret(args: &[&str], secret: &str) -> Result<()> {
    let mut child = Command::new("wg")
        .args(args)
        .stdin(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .context("run wg (is wireguard-tools installed?)")?;
    child
        .stdin
        .take()
        .expect("piped")
        .write_all(secret.as_bytes())
        .await?;
    let out = child.wait_with_output().await?;
    if !out.status.success() {
        bail!(
            "wg {} failed: {}",
            args[..2].join(" "),
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

/// Resolve the gateway, preferring the address family the host can reach.
async fn resolve_endpoint(endpoint: &str) -> Result<SocketAddr> {
    let addrs: Vec<SocketAddr> = tokio::net::lookup_host(endpoint)
        .await
        .with_context(|| format!("resolve endpoint {endpoint}"))?
        .collect();
    let has_default = |fam: &str| {
        std::process::Command::new("ip")
            .args([fam, "route", "show", "default"])
            .output()
            .is_ok_and(|o| !o.stdout.is_empty())
    };
    let v4 = has_default("-4");
    let v6 = has_default("-6");
    addrs
        .iter()
        .find(|a| (a.is_ipv4() && v4) || (a.is_ipv6() && v6))
        .or(addrs.first())
        .copied()
        .with_context(|| format!("endpoint {endpoint} has no addresses"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn desired() -> WgBindDesired {
        WgBindDesired {
            vm_id: "4f1c9a3e-8a5b-4c1d-9e2f-0a1b2c3d4e5f".into(),
            resource_id: "res-1".into(),
            private_key: format!("{}=", "A".repeat(43)),
            address: "2001:db8:1::1/64".into(),
            peer_public_key: format!("{}=", "B".repeat(43)),
            preshared_key: String::new(),
            endpoint: "gw.example.com:51820".into(),
            allowed_ips: vec![],
            keepalive_sec: 25,
        }
    }

    #[test]
    fn validates_and_defaults() {
        let b = Binding::from_proto(&desired()).unwrap();
        assert_eq!(b.address, "2001:db8:1::1".parse::<IpAddr>().unwrap());
        assert_eq!(b.allowed_ips, ["0.0.0.0/0", "::/0"]);
        assert!(
            !format!("{b:?}").contains(&b.private_key),
            "keys must not appear in Debug"
        );

        let mut bad = desired();
        bad.private_key = "short".into();
        assert!(Binding::from_proto(&bad).is_err());
        let mut bad = desired();
        bad.endpoint = "no-port".into();
        assert!(Binding::from_proto(&bad).is_err());
        let mut ok = desired();
        ok.allowed_ips = vec!["203.0.113.7".into(), "0.0.0.0/0, ::/0".into()];
        assert_eq!(
            Binding::from_proto(&ok).unwrap().allowed_ips,
            ["203.0.113.7/32", "0.0.0.0/0", "::/0"]
        );
    }
}
