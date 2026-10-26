//! WireGuard dedicated IPs managed from the local panel in standalone mode
//! (no platform token). The platform otherwise owns bindings and hands out
//! keys on every sync; without it the bindings, keys included, live in
//! `<data_dir>/wg-local.json` (mode 0600) and are applied through the same
//! `WgBindings::reconcile` path.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

use crate::backend::WgBindings;
use crate::model::VmId;
use crate::proto::WgBindDesired;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct LocalBinding {
    pub resource_id: String,
    pub vm_id: String,
    pub address: String,
    pub endpoint: String,
    private_key: String,
    peer_public_key: String,
    #[serde(default)]
    preshared_key: String,
    allowed_ips: Vec<String>,
    keepalive_sec: i32,
}

impl LocalBinding {
    fn desired(&self) -> WgBindDesired {
        WgBindDesired {
            vm_id: self.vm_id.clone(),
            resource_id: self.resource_id.clone(),
            private_key: self.private_key.clone(),
            address: self.address.clone(),
            peer_public_key: self.peer_public_key.clone(),
            preshared_key: self.preshared_key.clone(),
            endpoint: self.endpoint.clone(),
            allowed_ips: self.allowed_ips.clone(),
            keepalive_sec: self.keepalive_sec,
        }
    }
}

/// Parse a wg-quick style config (`[Interface]` + one `[Peer]`).
pub fn parse_wg_quick(text: &str, vm_id: &VmId) -> Result<LocalBinding> {
    let mut section = "";
    let mut get = std::collections::HashMap::new();
    for line in text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
    {
        if line.starts_with('[') {
            section = if line.eq_ignore_ascii_case("[interface]") {
                "i"
            } else if line.eq_ignore_ascii_case("[peer]") {
                if get.contains_key("p:PublicKey") {
                    bail!("only one [Peer] is supported");
                }
                "p"
            } else {
                bail!("unknown section {line}");
            };
            continue;
        }
        let (k, v) = line
            .split_once('=')
            .with_context(|| format!("not a key = value line: {line}"))?;
        get.insert(format!("{section}:{}", k.trim()), v.trim().to_owned());
    }
    let field = |k: &str| get.get(k).cloned().unwrap_or_default();
    let address = field("i:Address");
    let address = address
        .split(',')
        .next()
        .unwrap_or_default()
        .trim()
        .to_owned();
    let addr = address.split('/').next().unwrap_or_default();
    addr.parse::<std::net::IpAddr>()
        .with_context(|| format!("[Interface] Address {address:?} is not an IP address"))?;
    for (what, key, required) in [
        ("[Interface] PrivateKey", field("i:PrivateKey"), true),
        ("[Peer] PublicKey", field("p:PublicKey"), true),
        ("[Peer] PresharedKey", field("p:PresharedKey"), false),
    ] {
        if (required || !key.is_empty()) && !is_wg_key(&key) {
            bail!("{what} is missing or not a WireGuard key");
        }
    }
    let endpoint = field("p:Endpoint");
    match endpoint.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() && port.parse::<u16>().is_ok() => {}
        _ => bail!("[Peer] Endpoint must be host:port"),
    }
    let allowed_ips: Vec<String> = field("p:AllowedIPs")
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
    Ok(LocalBinding {
        resource_id: format!("local-{}", uuid::Uuid::new_v4()),
        vm_id: vm_id.to_string(),
        address,
        endpoint,
        private_key: field("i:PrivateKey"),
        peer_public_key: field("p:PublicKey"),
        preshared_key: field("p:PresharedKey"),
        allowed_ips,
        keepalive_sec: field("p:PersistentKeepalive").parse().unwrap_or(25),
    })
}

fn is_wg_key(s: &str) -> bool {
    s.len() == 44
        && s.ends_with('=')
        && s[..43]
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/')
}

pub struct LocalWg {
    path: PathBuf,
    list: Mutex<Vec<LocalBinding>>,
}

impl LocalWg {
    pub fn load(data_dir: &Path) -> Result<Self> {
        let path = data_dir.join("wg-local.json");
        let list = match std::fs::read(&path) {
            Ok(raw) => serde_json::from_slice(&raw).context("parse wg-local.json")?,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
            Err(e) => return Err(e.into()),
        };
        Ok(Self {
            path,
            list: Mutex::new(list),
        })
    }

    pub fn list(&self) -> Vec<LocalBinding> {
        self.list.lock().unwrap().clone()
    }

    fn save(&self, list: &[LocalBinding]) -> Result<()> {
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        crate::config::write_atomic(&self.path, &serde_json::to_vec_pretty(list)?)
    }

    pub fn add(&self, b: LocalBinding) -> Result<()> {
        let mut list = self.list.lock().unwrap();
        if list
            .iter()
            .any(|x| x.address.split('/').next() == b.address.split('/').next())
        {
            bail!("address {} is already bound", b.address);
        }
        let mut next = list.clone();
        next.push(b);
        self.save(&next)?;
        *list = next;
        Ok(())
    }

    /// Remove by resource id, or every binding of `vm_id`.
    pub fn remove(&self, resource_id: Option<&str>, vm_id: Option<&str>) -> Result<bool> {
        let mut list = self.list.lock().unwrap();
        let next: Vec<_> = list
            .iter()
            .filter(|b| {
                !(resource_id == Some(b.resource_id.as_str()) || vm_id == Some(b.vm_id.as_str()))
            })
            .cloned()
            .collect();
        if next.len() == list.len() {
            return Ok(false);
        }
        self.save(&next)?;
        *list = next;
        Ok(true)
    }

    /// Converge the host to exactly the locally stored bindings.
    pub async fn apply(&self, wg: &dyn WgBindings) -> Result<()> {
        let desired = self.list().iter().map(LocalBinding::desired).collect();
        wg.reconcile(desired).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(c: char) -> String {
        format!("{}=", c.to_string().repeat(43))
    }

    #[test]
    fn parses_wg_quick() {
        let vm = VmId::parse("4f1c9a3e-8a5b-4c1d-9e2f-0a1b2c3d4e5f").unwrap();
        let conf = format!(
            "[Interface]\nPrivateKey = {}\nAddress = 2001:db8::1/64\n\n[Peer]\nPublicKey = {}\nEndpoint = gw.example.com:51820\nAllowedIPs = ::/0\nPersistentKeepalive = 25\n",
            key('A'),
            key('B')
        );
        let b = parse_wg_quick(&conf, &vm).unwrap();
        assert_eq!(b.address, "2001:db8::1/64");
        assert_eq!(b.endpoint, "gw.example.com:51820");
        assert_eq!(b.allowed_ips, ["::/0"]);
        assert!(b.resource_id.starts_with("local-"));
        assert!(parse_wg_quick("[Interface]\nAddress = 1.2.3.4/32\n", &vm).is_err());
        assert!(parse_wg_quick(&conf.replace("gw.example.com:51820", "nohost"), &vm).is_err());
    }

    #[test]
    fn store_roundtrip() {
        let dir = std::env::temp_dir().join(format!("runman-wg-test-{}", uuid::Uuid::new_v4()));
        let vm = VmId::parse("4f1c9a3e-8a5b-4c1d-9e2f-0a1b2c3d4e5f").unwrap();
        let conf = format!(
            "[Interface]\nPrivateKey = {}\nAddress = 203.0.113.7/32\n[Peer]\nPublicKey = {}\nEndpoint = 192.0.2.1:51820\n",
            key('C'),
            key('D')
        );
        let store = LocalWg::load(&dir).unwrap();
        let b = parse_wg_quick(&conf, &vm).unwrap();
        store.add(b.clone()).unwrap();
        assert!(
            store.add(parse_wg_quick(&conf, &vm).unwrap()).is_err(),
            "same address twice"
        );
        let reloaded = LocalWg::load(&dir).unwrap();
        assert_eq!(reloaded.list(), vec![b.clone()]);
        assert!(reloaded.remove(None, Some(vm.as_str())).unwrap());
        assert!(LocalWg::load(&dir).unwrap().list().is_empty());
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(dir.join("wg-local.json"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600, "keys must not be world-readable");
        let _ = std::fs::remove_dir_all(dir);
    }
}
