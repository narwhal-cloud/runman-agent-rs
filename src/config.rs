//! Agent configuration (TOML), shared by the platform session and the web panel.

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

pub const DEFAULT_PATH: &str = "/etc/runman-agent/config.toml";
pub const DEFAULT_PLATFORM_URL: &str = "https://hosting.fuckip.me:443";
pub const DEFAULT_UPDATE_URL: &str =
    "https://github.com/narwhal-cloud/runman-agent-rs/releases/download/continuous";
pub const DEFAULT_IMAGE_BASE_URL: &str =
    "https://github.com/narwhal-cloud/runman-agent-rs/releases/download/images";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    /// Platform gRPC endpoint. `https://` uses TLS with WebPKI roots;
    /// `http://` is plaintext and intended for local testing only.
    pub platform_url: String,
    /// Integration token, sent as `authorization: Bearer <token>`.
    pub token: String,
    /// Public entry address reported in heartbeats. Empty: auto-detected IPv4.
    pub host: String,
    /// Label reported as `Heartbeat.virt_type`; the platform only displays it.
    pub virt_label: String,
    /// Persistent state (database, images, instances).
    pub data_dir: PathBuf,
    pub backend: BackendKind,
    /// Where prebuilt image tarballs are downloaded from.
    pub image_base_url: String,
    /// Expose /dev/net/tun to instances.
    pub tun: bool,
    /// Day of month (1-28) on which monthly traffic counters restart.
    pub traffic_reset_day: u32,
    /// UTC offset (`+08:00`) whose midnight starts the reset day.
    pub traffic_timezone: String,
    /// Correction of the measured uplink bandwidth reported to the platform
    /// (Mbit/s; 0 = report the speed test, see `speedtest`).
    pub bandwidth_mbps: u32,
    /// Management panel; empty `web_listen` disables it.
    pub web_listen: String,
    pub web_user: String,
    /// bcrypt hash (`runman-agent set-password`).
    pub web_password_hash: String,
    /// Local API of the rfw firewall, proxied under /rfw/api/.
    pub rfw_addr: String,
    /// Release location holding `SHA256SUMS` and the
    /// `runman-agent-linux-<arch>` binaries.
    pub update_url: String,
    pub auto_update: bool,
    pub network: NetworkConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default, deny_unknown_fields)]
pub struct NetworkConfig {
    pub bridge: String,
    pub ipv4_subnet: String,
    /// "none", "snat" (ULA + masquerade) or "subnet" (public addresses).
    pub ipv6_mode: String,
    /// Subnet mode: prefix to allocate instance addresses from.
    pub ipv6_prefix: String,
    /// Subnet mode: uplink on which the prefix is on-link (answer NDP for
    /// instance addresses). Empty when the prefix is routed to the host.
    pub ipv6_ndp_uplink: String,
    pub dns: Vec<String>,
    /// Host-side names: veth `<veth_prefix><idx>` (+ `i` for its IFB),
    /// WireGuard `<wg_prefix><n>` with policy table `wg_table_base + n`,
    /// and the nftables tables. Only change them to run several agents
    /// (e.g. tests) side by side on one host.
    pub veth_prefix: String,
    pub wg_prefix: String,
    pub wg_table_base: u32,
    pub nft_table: String,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            bridge: "rmbr0".into(),
            ipv4_subnet: "10.91.0.0/20".into(),
            ipv6_mode: "none".into(),
            ipv6_prefix: String::new(),
            ipv6_ndp_uplink: String::new(),
            dns: vec!["1.1.1.1".into(), "8.8.8.8".into()],
            veth_prefix: "rv".into(),
            wg_prefix: "rw".into(),
            wg_table_base: 20000,
            nft_table: "runman".into(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BackendKind {
    /// In-memory backend for development and protocol tests; manages nothing.
    Fake,
    /// System containers managed by this agent.
    Container,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            platform_url: DEFAULT_PLATFORM_URL.into(),
            token: String::new(),
            host: String::new(),
            virt_label: "container".into(),
            data_dir: PathBuf::from("/var/lib/runman-agent"),
            backend: BackendKind::Container,
            image_base_url: DEFAULT_IMAGE_BASE_URL.into(),
            tun: true,
            traffic_reset_day: 1,
            traffic_timezone: "+00:00".into(),
            bandwidth_mbps: 0,
            web_listen: "0.0.0.0:8792".into(),
            web_user: "admin".into(),
            web_password_hash: String::new(),
            rfw_addr: "127.0.0.1:7734".into(),
            update_url: DEFAULT_UPDATE_URL.into(),
            auto_update: true,
            network: NetworkConfig::default(),
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        if !(self.platform_url.starts_with("https://") || self.platform_url.starts_with("http://"))
        {
            bail!("platform_url must start with https:// or http://");
        }
        if !self.token.is_empty() && !(16..=512).contains(&self.token.len()) {
            bail!("token must contain 16-512 characters");
        }
        if !self.web_listen.is_empty() && self.web_listen.parse::<std::net::SocketAddr>().is_err() {
            bail!("web_listen must be ip:port");
        }
        if self.rfw_addr.parse::<std::net::SocketAddr>().is_err() {
            bail!("rfw_addr must be ip:port");
        }
        if !(self.update_url.starts_with("https://") || self.update_url.starts_with("http://")) {
            bail!("update_url must be an http(s) URL");
        }
        if !(1..=28).contains(&self.traffic_reset_day) {
            bail!("traffic_reset_day must be 1-28");
        }
        parse_utc_offset(&self.traffic_timezone)?;
        if self.token.chars().any(char::is_control) {
            bail!("token must not contain control characters");
        }
        Ok(())
    }
}

impl Config {
    /// When monthly traffic restarts.
    pub fn traffic_schedule(&self) -> crate::traffic::Schedule {
        crate::traffic::Schedule {
            reset_day: self.traffic_reset_day,
            utc_offset_min: parse_utc_offset(&self.traffic_timezone).unwrap_or(0),
        }
    }
}

/// `+08:00` / `-05:30` / `+00:00` to minutes east of UTC.
pub fn parse_utc_offset(s: &str) -> Result<i32> {
    let parsed = (|| {
        let (sign, rest) = match s.as_bytes().first()? {
            b'+' => (1, &s[1..]),
            b'-' => (-1, &s[1..]),
            _ => return None,
        };
        let (h, m) = rest.split_once(':')?;
        if h.len() != 2 || m.len() != 2 {
            return None;
        }
        let (h, m): (i32, i32) = (h.parse().ok()?, m.parse().ok()?);
        let total = sign * (h * 60 + m);
        (m < 60 && (-12 * 60..=14 * 60).contains(&total)).then_some(total)
    })();
    parsed.with_context(|| {
        format!("traffic_timezone {s:?} must be a UTC offset like +08:00 (-12:00 to +14:00)")
    })
}

/// Thread-safe configuration holder that persists updates atomically.
pub struct Store {
    path: PathBuf,
    cfg: RwLock<Config>,
}

impl Store {
    pub fn load(path: impl Into<PathBuf>) -> Result<Arc<Self>> {
        let path = path.into();
        let raw = std::fs::read_to_string(&path)
            .with_context(|| format!("read config {}", path.display()))?;
        let cfg: Config =
            toml::from_str(&raw).with_context(|| format!("parse config {}", path.display()))?;
        cfg.validate()?;
        Ok(Arc::new(Self {
            path,
            cfg: RwLock::new(cfg),
        }))
    }

    /// In-memory store (tests); `update` writes to `path` if it is non-empty.
    pub fn in_memory(cfg: Config) -> Arc<Self> {
        Arc::new(Self {
            path: PathBuf::new(),
            cfg: RwLock::new(cfg),
        })
    }

    pub fn get(&self) -> Config {
        self.cfg.read().expect("config lock poisoned").clone()
    }

    pub fn update(&self, f: impl FnOnce(&mut Config)) -> Result<()> {
        let mut guard = self.cfg.write().expect("config lock poisoned");
        let mut next = guard.clone();
        f(&mut next);
        next.validate()?;
        if !self.path.as_os_str().is_empty() {
            write_atomic(&self.path, toml::to_string_pretty(&next)?.as_bytes())?;
        }
        *guard = next;
        Ok(())
    }
}

/// Write via a temp file + rename so a crash never leaves a truncated config.
pub fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let tmp = path.with_extension("tmp");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .with_context(|| format!("write {}", tmp.display()))?;
    f.write_all(data)?;
    f.sync_all()?;
    std::fs::rename(&tmp, path).with_context(|| format!("rename to {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_config_matches_defaults() {
        let example: Config =
            toml::from_str(include_str!("../config.example.toml")).expect("parse example");
        assert_eq!(example, Config::default());
        example.validate().unwrap();
    }

    #[test]
    fn utc_offsets() {
        assert_eq!(parse_utc_offset("+00:00").unwrap(), 0);
        assert_eq!(parse_utc_offset("+08:00").unwrap(), 480);
        assert_eq!(parse_utc_offset("+05:30").unwrap(), 330);
        assert_eq!(parse_utc_offset("-03:30").unwrap(), -210);
        assert_eq!(parse_utc_offset("+14:00").unwrap(), 840);
        for bad in [
            "", "08:00", "+8:00", "+08", "+08:60", "-13:00", "+15:00", "UTC", "+0a:00",
        ] {
            assert!(parse_utc_offset(bad).is_err(), "{bad:?}");
        }
    }
}
