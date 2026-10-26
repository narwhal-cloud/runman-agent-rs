//! Self-update from the release location (`update_url`).
//!
//! A release publishes `runman-agent-linux-<arch>`, `SHA256SUMS` and
//! `SHA256SUMS.sig` (ed25519 over `SHA256SUMS`). An update is applied only
//! when the signature verifies against the public key compiled into this
//! binary (`RUNMAN_UPDATE_PUBKEY`, base64 of the raw 32-byte key, set by CI),
//! the download matches its checksum, is an ELF for this architecture and
//! runs `--version`. The new binary then atomically replaces the running one
//! and the agent exits so systemd starts the new version; instances keep
//! running. Builds without a key never self-update.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, bail};
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use rand::Rng;
use serde::Serialize;
use sha2::{Digest, Sha256};
use tokio::process::Command;
use tokio_util::sync::CancellationToken;
use tracing::{info, warn};

use crate::config;

const PUBKEY: Option<&str> = option_env!("RUNMAN_UPDATE_PUBKEY");

/// The release signing key compiled into this build, if any (also verifies
/// the image manifest).
pub fn signing_key() -> Option<&'static str> {
    PUBKEY
}
const FIRST_CHECK: Duration = Duration::from_secs(600);
const CHECK_EVERY: Duration = Duration::from_secs(6 * 3600);
/// Upper bound of the random delay before applying a found update, so a
/// release does not restart every node at once.
const MAX_JITTER: Duration = Duration::from_secs(6 * 3600);

/// Version string: crate version plus the CI build id when present.
pub fn version() -> &'static str {
    match option_env!("RUNMAN_BUILD_ID") {
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
    pub signing_key: bool,
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
        s.signing_key = PUBKEY.is_some();
        s.auto_update = self.cfg.get().auto_update;
        s
    }

    /// Periodic checks; a found update is applied after a random delay.
    pub async fn run(self: Arc<Self>, shutdown: CancellationToken) {
        if PUBKEY.is_none() {
            warn!("self-update disabled: this build has no update signing key");
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

    /// Check and, if there is a newer signed release, install it and request
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

    /// SHA-256 of the release binary for this architecture if it is signed
    /// and differs from the running one.
    async fn newer_release(&self) -> Result<Option<String>> {
        let key = PUBKEY.context("this build has no update signing key")?;
        let dir = tempdir()?;
        let sums_path = dir.join("SHA256SUMS");
        let sig_path = dir.join("SHA256SUMS.sig");
        let base = self.base();
        let fetched = async {
            fetch(&format!("{base}/SHA256SUMS"), &sums_path).await?;
            fetch(&format!("{base}/SHA256SUMS.sig"), &sig_path).await?;
            Ok::<_, anyhow::Error>((
                tokio::fs::read(&sums_path).await?,
                tokio::fs::read(&sig_path).await?,
            ))
        }
        .await;
        let _ = tokio::fs::remove_dir_all(&dir).await;
        let (sums, sig) = fetched?;
        verify_signature(key, &sums, &sig)?;
        let want = expected_sha(&String::from_utf8_lossy(&sums), asset_name()?)?;
        let current = hex_sha256(&tokio::fs::read(&self.exe).await?);
        Ok((current != want).then_some(want))
    }
}

pub fn verify_signature(pubkey_b64: &str, message: &[u8], signature: &[u8]) -> Result<()> {
    let engine = base64::engine::general_purpose::STANDARD;
    let key: [u8; 32] = engine
        .decode(pubkey_b64.trim())
        .ok()
        .and_then(|k| k.try_into().ok())
        .context("invalid compiled-in update key")?;
    let key = VerifyingKey::from_bytes(&key).context("invalid compiled-in update key")?;
    let sig: [u8; 64] = signature
        .try_into()
        .map_err(|_| anyhow::anyhow!("SHA256SUMS.sig must be 64 raw bytes"))?;
    key.verify(message, &Signature::from_bytes(&sig))
        .context("SHA256SUMS signature does not verify")
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
    use ed25519_dalek::{Signer, SigningKey};

    #[test]
    fn signature_and_checksums() {
        let sk = SigningKey::from_bytes(&[7u8; 32]);
        let pk = base64::engine::general_purpose::STANDARD.encode(sk.verifying_key().to_bytes());
        let sums = format!(
            "{}  runman-agent-linux-amd64\n{}  runman-agent-linux-arm64\n",
            "a".repeat(64),
            "B".repeat(64)
        );
        let sig = sk.sign(sums.as_bytes()).to_bytes();
        verify_signature(&pk, sums.as_bytes(), &sig).unwrap();
        let mut tampered = sums.clone().into_bytes();
        tampered[0] = b'c';
        assert!(verify_signature(&pk, &tampered, &sig).is_err());
        assert!(verify_signature(&pk, sums.as_bytes(), &sig[..63]).is_err());

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
