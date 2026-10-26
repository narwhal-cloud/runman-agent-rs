//! Self-update from the release location (`update_url`).
//!
//! A release publishes `runman-agent-linux-<arch>` and `SHA256SUMS` on the
//! official GitHub repository. An update is applied only when the download
//! matches its checksum, is an ELF for this architecture and runs
//! `--version`. The new binary then atomically replaces the running one and
//! the agent exits so systemd starts the new version; instances keep
//! running. Only CI release builds (`RUNMAN_BUILD_ID` set) self-update, so a
//! locally built binary is never replaced behind its developer's back.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, bail};
use rand::Rng;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::process::Command;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::config;

/// Set by CI for release builds.
const BUILD_ID: Option<&str> = option_env!("RUNMAN_BUILD_ID");

const FIRST_CHECK: Duration = Duration::from_secs(600);
const CHECK_EVERY: Duration = Duration::from_secs(6 * 3600);
/// Upper bound of the random delay before applying a found update, so a
/// release does not restart every node at once.
const MAX_JITTER: Duration = Duration::from_secs(6 * 3600);

/// Version string: crate version plus the CI build id when present.
pub fn version() -> &'static str {
    match BUILD_ID {
        Some(id) => Box::leak(format!("{}+{id}", env!("CARGO_PKG_VERSION")).into_boxed_str()),
        None => env!("CARGO_PKG_VERSION"),
    }
}

pub fn asset_name() -> Result<&'static str> {
    Ok(match std::env::consts::ARCH {
        "x86_64" => "runman-agent-linux-amd64",
        "aarch64" => "runman-agent-linux-arm64",
        other => bail!("unsupported architecture {other}"),
    })
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Status {
    /// A CI release build, which can update itself.
    pub release_build: bool,
    pub auto_update: bool,
    pub last_check: Option<u64>,
    pub last_error: String,
    /// SHA-256 of the newer binary waiting to be applied.
    pub pending: Option<String>,
}

pub struct Updater {
    cfg: Arc<config::Store>,
    exe: PathBuf,
    status: Mutex<Status>,
    /// Cancelled to make the process exit after an update was installed.
    restart: CancellationToken,
}

#[derive(Debug, PartialEq)]
pub enum Outcome {
    UpToDate,
    /// A newer binary was installed; the process should exit now.
    Installed(String),
}

impl Updater {
    pub fn new(cfg: Arc<config::Store>, restart: CancellationToken) -> Result<Arc<Self>> {
        let exe = std::env::current_exe()?;
        Ok(Arc::new(Self {
            cfg,
            exe,
            status: Mutex::default(),
            restart,
        }))
    }

    pub fn status(&self) -> Status {
        let mut s = self.status.lock().unwrap().clone();
        s.release_build = BUILD_ID.is_some();
        s.auto_update = self.cfg.get().auto_update;
        s
    }

    /// Periodic checks; a found update is applied after a random delay.
    pub async fn run(self: Arc<Self>, shutdown: CancellationToken) {
        if BUILD_ID.is_none() {
            info!("self-update disabled: not a release build");
            return;
        }
        let mut wait = FIRST_CHECK;
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = tokio::time::sleep(wait) => {}
            }
            wait = CHECK_EVERY;
            if !self.cfg.get().auto_update {
                continue;
            }
            match self.newer_release().await {
                Ok(Some(sha)) => {
                    let jitter =
                        Duration::from_secs(rand::rng().random_range(0..MAX_JITTER.as_secs()));
                    info!("update {} available; applying in {jitter:?}", &sha[..12]);
                    self.status.lock().unwrap().pending = Some(sha);
                    tokio::select! {
                        _ = shutdown.cancelled() => return,
                        _ = tokio::time::sleep(jitter) => {}
                    }
                    if let Err(e) = self.update_now().await {
                        warn!("self-update failed: {e:#}");
                    }
                }
                Ok(None) => {}
                Err(e) => warn!("update check failed: {e:#}"),
            }
        }
    }

    /// Check and, if there is a newer release, install it and request
    /// a restart.
    pub async fn update_now(&self) -> Result<Outcome> {
        let result = self.update_inner().await;
        let mut st = self.status.lock().unwrap();
        st.last_check = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .ok()
            .map(|d| d.as_secs());
        st.last_error = result
            .as_ref()
            .err()
            .map(|e| format!("{e:#}"))
            .unwrap_or_default();
        if let Ok(Outcome::UpToDate) = &result {
            st.pending = None;
        }
        drop(st);
        if let Ok(Outcome::Installed(sha)) = &result {
            info!("installed update {}; restarting", &sha[..12]);
            self.restart.cancel();
        }
        result
    }

    async fn update_inner(&self) -> Result<Outcome> {
        let Some(sha) = self.newer_release().await? else {
            return Ok(Outcome::UpToDate);
        };
        let staged = self.exe.with_extension("new");
        let url = format!("{}/{}", self.base(), asset_name()?);
        fetch(&url, &staged).await?;
        let result = async {
            let data = tokio::fs::read(&staged).await?;
            if hex_sha256(&data) != sha {
                bail!("downloaded binary does not match SHA256SUMS");
            }
            check_elf(&data)?;
            set_mode(&staged, 0o755)?;
            let out = tokio::time::timeout(
                Duration::from_secs(10),
                Command::new(&staged).arg("--version").output(),
            )
            .await
            .context("new binary hangs on --version")??;
            if !out.status.success() {
                bail!(
                    "new binary fails to run: {}",
                    String::from_utf8_lossy(&out.stderr).trim()
                );
            }
            tokio::fs::rename(&staged, &self.exe)
                .await
                .context("replace binary")?;
            Ok(Outcome::Installed(sha.clone()))
        }
        .await;
        if result.is_err() {
            let _ = tokio::fs::remove_file(&staged).await;
        }
        result
    }

    fn base(&self) -> String {
        self.cfg.get().update_url.trim_end_matches('/').to_owned()
    }

    /// SHA-256 of the release binary for this architecture if it differs
    /// from the running one.
    async fn newer_release(&self) -> Result<Option<String>> {
        if BUILD_ID.is_none() {
            bail!("not a release build; install a release to update");
        }
        let dir = tempdir()?;
        let sums_path = dir.join("SHA256SUMS");
        let fetched = async {
            fetch(&format!("{}/SHA256SUMS", self.base()), &sums_path).await?;
            Ok::<_, anyhow::Error>(tokio::fs::read(&sums_path).await?)
        }
        .await;
        let _ = tokio::fs::remove_dir_all(&dir).await;
        let sums = fetched?;
        let want = expected_sha(&String::from_utf8_lossy(&sums), asset_name()?)?;
        let current = hex_sha256(&tokio::fs::read(&self.exe).await?);
        Ok((current != want).then_some(want))
    }
}

/// The checksum listed for `asset` (`sha256sum` format).
pub fn expected_sha(sums: &str, asset: &str) -> Result<String> {
    sums.lines()
        .find_map(|l| {
            let (sha, name) = l.split_once(char::is_whitespace)?;
            (name.trim().trim_start_matches('*') == asset
                && sha.len() == 64
                && sha.bytes().all(|b| b.is_ascii_hexdigit()))
            .then(|| sha.to_ascii_lowercase())
        })
        .with_context(|| format!("{asset} is not listed in SHA256SUMS"))
}

pub fn hex_sha256(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

fn check_elf(data: &[u8]) -> Result<()> {
    let machine = match std::env::consts::ARCH {
        "x86_64" => 62u16,
        "aarch64" => 183,
        other => bail!("unsupported architecture {other}"),
    };
    if data.len() < 20
        || &data[..6] != b"\x7fELF\x02\x01"
        || u16::from_le_bytes([data[18], data[19]]) != machine
    {
        bail!("downloaded file is not a 64-bit ELF for this architecture");
    }
    Ok(())
}

fn set_mode(path: &Path, mode: u32) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))?;
    Ok(())
}

fn tempdir() -> Result<PathBuf> {
    let dir = std::env::temp_dir().join(format!("runman-update-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&dir)?;
    Ok(dir)
}

async fn fetch(url: &str, dest: &Path) -> Result<()> {
    let out = Command::new("curl")
        .args([
            "-fsSL",
            "--retry",
            "2",
            "--connect-timeout",
            "20",
            "--max-time",
            "600",
            "-o",
        ])
        .arg(dest)
        .arg(url)
        .output()
        .await
        .context("run curl")?;
    if !out.status.success() {
        bail!(
            "download {url}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checksums() {
        let sums = format!(
            "{}  runman-agent-linux-amd64\n{}  runman-agent-linux-arm64\n",
            "a".repeat(64),
            "B".repeat(64)
        );
        assert_eq!(
            expected_sha(&sums, "runman-agent-linux-arm64").unwrap(),
            "b".repeat(64)
        );
        assert!(expected_sha(&sums, "runman-agent-linux-riscv").is_err());
        assert_eq!(
            hex_sha256(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn elf_check() {
        let mut elf = b"\x7fELF\x02\x01".to_vec();
        elf.resize(20, 0);
        let machine: u16 = if cfg!(target_arch = "x86_64") {
            62
        } else {
            183
        };
        elf[18..20].copy_from_slice(&machine.to_le_bytes());
        check_elf(&elf).unwrap();
        assert!(check_elf(b"#!/bin/sh\necho pwned\n").is_err());
    }
}
