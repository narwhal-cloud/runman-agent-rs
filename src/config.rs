//! Agent configuration (TOML), shared by the platform session and the web panel.

use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

pub const DEFAULT_PATH: &str = "/etc/runman-agent/config.toml";
pub const DEFAULT_PLATFORM_URL: &str = "https://hosting.fuckip.me:443";
pub const DEFAULT_UPDATE_URL: &str =
    "https://github.com/narwhal-cloud/runman-agent-rs/releases/latest/download";
/// Former default (pre-release builds of `main`). Configs still carrying it,
/// e.g. written back by the panel, are moved to the stable channel on load.
const LEGACY_UPDATE_URL: &str =
    "https://github.com/narwhal-cloud/runman-agent-rs/releases/download/continuous";
pub const DEFAULT_VIRT_LABEL: &str = "Runman";
/// Former default `virt_label`, moved to [`DEFAULT_VIRT_LABEL`] on load.
const LEGACY_VIRT_LABEL: &str = "container";
pub const DEFAULT_MAX_FORWARDS: u32 = 20;
/// Highest `max_forwards`: more than a host has ports to give.
pub const MAX_FORWARDS_LIMIT: u32 = 65535;
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
    /// `fixed`: monthly traffic restarts for every instance on
    /// `traffic_reset_day`; `creation`: monthly on each instance's creation
    /// day and time.
    pub traffic_reset_mode: crate::traffic::ResetMode,
    /// Day of month (1-28) on which monthly traffic counters restart.
    pub traffic_reset_day: u32,
    /// UTC offset (`+08:00`) whose midnight starts the reset day.
    pub traffic_timezone: String,
    /// Port forwards per instance, TCP and UDP together (0 = no limit).
    /// Existing rules stay when it is lowered; only new ones are refused.
    pub max_forwards: u32,
    /// Correction of the measured uplink bandwidth reported to the platform
    /// (Mbit/s; 0 = report the speed test, see `speedtest`).
    pub bandwidth_mbps: u32,
    /// Management panel; empty `web_listen` disables it. `0.0.0.0` and
    /// `[::]` both listen on every address, IPv4 and IPv6.
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
            virt_label: DEFAULT_VIRT_LABEL.into(),
            data_dir: PathBuf::from("/var/lib/runman-agent"),
            backend: BackendKind::Container,
            image_base_url: DEFAULT_IMAGE_BASE_URL.into(),
            tun: true,
            traffic_reset_mode: crate::traffic::ResetMode::Fixed,
            traffic_reset_day: 1,
            traffic_timezone: "+00:00".into(),
            max_forwards: DEFAULT_MAX_FORWARDS,
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
    /// Rewrite values that older versions stored as defaults.
    fn migrate(&mut self) {
        if self.update_url.trim_end_matches('/') == LEGACY_UPDATE_URL {
            self.update_url = DEFAULT_UPDATE_URL.into();
        }
        if self.virt_label == LEGACY_VIRT_LABEL {
            self.virt_label = DEFAULT_VIRT_LABEL.into();
        }
    }

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
        if self.max_forwards > MAX_FORWARDS_LIMIT {
            bail!("max_forwards must be 0-{MAX_FORWARDS_LIMIT}");
        }
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
            mode: self.traffic_reset_mode,
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
///
/// The file is also changed by other processes (`runman-agent set-password`,
/// `set-token`, manual edits), so every read checks whether it changed on
/// disk and reloads it. Without this the running agent would keep serving
/// the old values and write them back on its next `update`.
pub struct Store {
    path: PathBuf,
    cfg: RwLock<Loaded>,
}

struct Loaded {
    cfg: Config,
    /// Identity of the file `cfg` was read from or written to.
    stamp: Option<Stamp>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Stamp {
    modified: std::time::SystemTime,
    len: u64,
    ino: u64,
}

fn stamp(path: &Path) -> Option<Stamp> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(path).ok()?;
    Some(Stamp {
        modified: m.modified().ok()?,
        len: m.len(),
        ino: m.ino(),
    })
}

fn read_config(path: &Path) -> Result<Config> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("read config {}", path.display()))?;
    let mut cfg: Config =
        toml::from_str(&raw).with_context(|| format!("parse config {}", path.display()))?;
    cfg.migrate();
    cfg.validate()?;
    Ok(cfg)
}

impl Store {
    pub fn load(path: impl Into<PathBuf>) -> Result<Arc<Self>> {
        let path = path.into();
        let stamp = stamp(&path);
        let cfg = read_config(&path)?;
        Ok(Arc::new(Self {
            path,
            cfg: RwLock::new(Loaded { cfg, stamp }),
        }))
    }

    /// In-memory store (tests); `update` writes to `path` if it is non-empty.
    pub fn in_memory(cfg: Config) -> Arc<Self> {
        Arc::new(Self {
            path: PathBuf::new(),
            cfg: RwLock::new(Loaded { cfg, stamp: None }),
        })
    }

    /// Reload the file if another process changed it. A file that fails to
    /// parse is ignored (the last good config stays in effect).
    fn refresh(&self, loaded: &mut Loaded) {
        if self.path.as_os_str().is_empty() {
            return;
        }
        let now = stamp(&self.path);
        if now.is_none() || now == loaded.stamp {
            return;
        }
        match read_config(&self.path) {
            Ok(cfg) => {
                tracing::info!("config {} changed on disk, reloaded", self.path.display());
                loaded.cfg = cfg;
            }
            Err(e) => tracing::warn!("config changed on disk but was not reloaded: {e:#}"),
        }
        loaded.stamp = now;
    }

    pub fn get(&self) -> Config {
        {
            let guard = self.cfg.read().expect("config lock poisoned");
            if self.path.as_os_str().is_empty() || stamp(&self.path) == guard.stamp {
                return guard.cfg.clone();
            }
        }
        let mut guard = self.cfg.write().expect("config lock poisoned");
        self.refresh(&mut guard);
        guard.cfg.clone()
    }

    pub fn update(&self, f: impl FnOnce(&mut Config)) -> Result<()> {
        let mut guard = self.cfg.write().expect("config lock poisoned");
        self.refresh(&mut guard);
        let mut next = guard.cfg.clone();
        f(&mut next);
        next.validate()?;
        if !self.path.as_os_str().is_empty() {
            write_atomic(&self.path, toml::to_string_pretty(&next)?.as_bytes())?;
            guard.stamp = stamp(&self.path);
        }
        guard.cfg = next;
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
    fn store_picks_up_changes_from_other_processes() {
        let dir = std::env::temp_dir().join(format!("runman-cfg-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.toml");
        let base = toml::to_string_pretty(&Config::default()).unwrap();
        std::fs::write(&path, &base).unwrap();

        let agent = Store::load(&path).unwrap();
        assert!(agent.get().web_password_hash.is_empty());

        // `runman-agent set-password` runs as a separate process.
        Store::load(&path)
            .unwrap()
            .update(|c| c.web_password_hash = "new-hash".into())
            .unwrap();
        assert_eq!(agent.get().web_password_hash, "new-hash");

        // A later update by the agent keeps the new hash.
        agent.update(|c| c.token = "tok-0123456789abcdef".into()).unwrap();
        let on_disk = Store::load(&path).unwrap().get();
        assert_eq!(on_disk.web_password_hash, "new-hash");
        assert_eq!(on_disk.token, "tok-0123456789abcdef");

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn example_config_matches_defaults() {
        let example: Config =
            toml::from_str(include_str!("../config.example.toml")).expect("parse example");
        assert_eq!(example, Config::default());
        example.validate().unwrap();
    }

    #[test]
    fn legacy_update_url_moves_to_stable() {
        let mut cfg = Config {
            update_url: format!("{LEGACY_UPDATE_URL}/"),
            ..Config::default()
        };
        cfg.migrate();
        assert_eq!(cfg.update_url, DEFAULT_UPDATE_URL);

        let custom = "https://mirror.example/runman";
        cfg.update_url = custom.into();
        cfg.migrate();
        assert_eq!(cfg.update_url, custom);
    }

    #[test]
    fn legacy_virt_label_is_renamed() {
        let mut cfg = Config {
            virt_label: LEGACY_VIRT_LABEL.into(),
            ..Config::default()
        };
        cfg.migrate();
        assert_eq!(cfg.virt_label, DEFAULT_VIRT_LABEL);

        cfg.virt_label = "LXC".into();
        cfg.migrate();
        assert_eq!(cfg.virt_label, "LXC");
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
