//! Uplink speed test, for the bandwidth reported to the platform (which caps
//! the plan bandwidth an owner can sell on this node).
//!
//! Downloads from and uploads to Cloudflare's speed test endpoints over
//! several parallel connections with `curl` (one TCP stream underestimates
//! fast links), best of two rounds, and reports the slower direction: instance bandwidth limits
//! apply both ways. The result is kept in `<data>/speedtest.json` and
//! refreshed weekly, so agent restarts and updates do not re-test.
//!
//! A test is approximate (distance to Cloudflare, congestion), so the owner
//! may correct it with `bandwidth_mbps`: anything below the measurement, or
//! up to [`MAX_CORRECTION`] times it.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tokio::process::Command;
use tracing::{info, warn};

const DOWN_URL: &str = "https://speed.cloudflare.com/__down?bytes=";
const UP_URL: &str = "https://speed.cloudflare.com/__up";
const STREAMS: usize = 8;
/// Per stream, round and direction; caps a test at 800 MB each way. (Cloudflare
/// refuses downloads of 100 MB and more.)
const STREAM_BYTES: u64 = 50_000_000;
const STREAM_TIMEOUT: Duration = Duration::from_secs(15);
const ROUNDS: usize = 2;
/// Re-test after this long.
pub const MAX_AGE: Duration = Duration::from_secs(7 * 86_400);
/// An owner may report at most this many times the measured bandwidth.
pub const MAX_CORRECTION: u32 = 2;

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq)]
pub struct Measurement {
    pub down_mbps: u32,
    pub up_mbps: u32,
    /// Unix time of the test.
    pub at: u64,
}

impl Measurement {
    /// What the link sustains both ways.
    pub fn mbps(&self) -> u32 {
        self.down_mbps.min(self.up_mbps)
    }
}

/// Bandwidth to report: the measurement, or the owner's correction within
/// range. `configured` is `bandwidth_mbps` (0 = use the measurement).
pub fn effective(measured: u32, configured: u32) -> u32 {
    match (measured, configured) {
        (m, 0) => m,
        (0, c) => c,
        (m, c) => c.min(m.saturating_mul(MAX_CORRECTION)),
    }
}

/// Reject a correction outside the allowed range.
pub fn check_correction(measured: u32, configured: u32) -> Result<()> {
    let max = measured.saturating_mul(MAX_CORRECTION);
    if measured > 0 && configured > max {
        bail!(
            "bandwidth may be at most {MAX_CORRECTION}x the measured {measured} Mbps ({max} Mbps)"
        );
    }
    Ok(())
}

pub struct SpeedTest {
    path: PathBuf,
    last: Mutex<Option<Measurement>>,
    last_error: Mutex<String>,
    running: AtomicBool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Status {
    pub measured: Option<Measurement>,
    pub running: bool,
    pub last_error: String,
}

impl SpeedTest {
    pub fn load(data_dir: &Path) -> Self {
        let path = data_dir.join("speedtest.json");
        let last = std::fs::read(&path)
            .ok()
            .and_then(|raw| serde_json::from_slice(&raw).ok());
        Self {
            path,
            last: Mutex::new(last),
            last_error: Mutex::default(),
            running: AtomicBool::new(false),
        }
    }

    /// Measured bandwidth, 0 before the first successful test.
    pub fn measured_mbps(&self) -> u32 {
        self.last.lock().unwrap().map_or(0, |m| m.mbps())
    }

    pub fn status(&self) -> Status {
        Status {
            measured: *self.last.lock().unwrap(),
            running: self.running.load(Ordering::SeqCst),
            last_error: self.last_error.lock().unwrap().clone(),
        }
    }

    fn stale(&self) -> bool {
        let age = self
            .last
            .lock()
            .unwrap()
            .map(|m| unix_now().saturating_sub(m.at));
        age.is_none_or(|a| a >= MAX_AGE.as_secs())
    }

    /// Run a test unless one is already running.
    pub async fn run(&self) -> Result<Measurement> {
        if self.running.swap(true, Ordering::SeqCst) {
            bail!("a speed test is already running");
        }
        let result = measure().await;
        self.running.store(false, Ordering::SeqCst);
        match &result {
            Ok(m) => {
                info!(
                    "speed test: down {} Mbps, up {} Mbps",
                    m.down_mbps, m.up_mbps
                );
                *self.last.lock().unwrap() = Some(*m);
                self.last_error.lock().unwrap().clear();
                if let Err(e) = serde_json::to_vec(m)
                    .map_err(anyhow::Error::from)
                    .and_then(|raw| crate::config::write_atomic(&self.path, &raw))
                {
                    warn!("save speed test: {e:#}");
                }
            }
            Err(e) => {
                warn!("speed test failed: {e:#}");
                *self.last_error.lock().unwrap() = format!("{e:#}");
            }
        }
        result
    }

    /// Test shortly after start when the last result is old, then weekly.
    pub async fn schedule(&self, shutdown: tokio_util::sync::CancellationToken) {
        let mut wait = Duration::from_secs(60);
        loop {
            tokio::select! {
                _ = shutdown.cancelled() => return,
                _ = tokio::time::sleep(wait) => {}
            }
            wait = Duration::from_secs(6 * 3600);
            if self.stale() {
                let _ = self.run().await;
            }
        }
    }
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

async fn measure() -> Result<Measurement> {
    let down = best_of(false).await.context("download")?;
    let up = best_of(true).await.context("upload")?;
    Ok(Measurement {
        down_mbps: down,
        up_mbps: up,
        at: unix_now(),
    })
}

/// A round ends when its slowest transfer does, so one straggler drags it
/// down; keep the better of `ROUNDS`.
async fn best_of(upload: bool) -> Result<u32> {
    let mut best = Err(anyhow::anyhow!("no rounds"));
    for _ in 0..ROUNDS {
        match parallel(upload).await {
            Ok(r) => best = Ok(r.max(*best.as_ref().unwrap_or(&0))),
            Err(e) if best.is_err() => best = Err(e),
            Err(_) => {}
        }
    }
    best
}

/// Mbit/s over `STREAMS` concurrent transfers in one direction.
async fn parallel(upload: bool) -> Result<u32> {
    // Uploads read a sparse file of zeros: a known size, streamed from disk
    // without memory or disk use.
    let body = std::env::temp_dir().join(format!("runman-speedtest-{}", std::process::id()));
    if upload {
        std::fs::File::create(&body)?.set_len(STREAM_BYTES)?;
    }
    let start = Instant::now();
    let mut transfers = Vec::with_capacity(STREAMS);
    for _ in 0..STREAMS {
        let mut cmd = Command::new("curl");
        cmd.args(["-sS", "-o", "/dev/null", "--max-time"])
            .arg(STREAM_TIMEOUT.as_secs().to_string())
            .stdin(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if upload {
            cmd.args([
                "-X",
                "POST",
                "-H",
                "Content-Type: application/octet-stream",
                "-H",
                "Expect:",
                "-w",
                "%{http_code} %{size_upload}",
                "-T",
            ])
            .arg(&body)
            .arg(UP_URL);
        } else {
            cmd.args(["-w", "%{http_code} %{size_download}"])
                .arg(format!("{DOWN_URL}{STREAM_BYTES}"));
        }
        cmd.stdout(Stdio::piped());
        transfers.push(cmd.spawn().context("run curl")?);
    }
    // All transfers run concurrently; collect them in turn.
    let mut outputs = Vec::with_capacity(STREAMS);
    for t in transfers {
        outputs.push(t.wait_with_output().await);
    }
    let elapsed = start.elapsed().as_secs_f64();
    if upload {
        let _ = std::fs::remove_file(&body);
    }
    let mut bytes = 0u64;
    let mut errors = Vec::new();
    for out in outputs {
        let out = out.context("run curl")?;
        // A transfer cut off by --max-time (exit 28) still counts, even an
        // upload the server has not answered yet; an error response does not.
        let stdout = String::from_utf8_lossy(&out.stdout);
        let (code, n) = stdout.trim().split_once(' ').unwrap_or_default();
        let timed_out = out.status.code() == Some(28) && !code.starts_with(['4', '5']);
        match n.parse::<f64>() {
            Ok(n) if (code == "200" || timed_out) && n > 0.0 => bytes += n as u64,
            _ => {
                let stderr = String::from_utf8_lossy(&out.stderr);
                errors.push(format!("HTTP {code} {}", stderr.trim()));
            }
        }
    }
    if bytes == 0 {
        bail!(
            "no data transferred: {}",
            errors.first().map_or("", String::as_str)
        );
    }
    Ok(mbps(bytes, elapsed))
}

fn mbps(bytes: u64, secs: f64) -> u32 {
    (bytes as f64 * 8.0 / secs.max(0.001) / 1e6).round() as u32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn correction_range() {
        // No correction: the measurement.
        assert_eq!(effective(940, 0), 940);
        // Lower is always allowed, higher up to 2x.
        assert_eq!(effective(940, 500), 500);
        assert_eq!(effective(940, 1000), 1000);
        assert_eq!(effective(940, 5000), 1880);
        // Nothing measured yet: the owner's value.
        assert_eq!(effective(0, 1000), 1000);
        assert_eq!(effective(0, 0), 0);

        assert!(check_correction(940, 1880).is_ok());
        assert!(check_correction(940, 1881).is_err());
        assert!(check_correction(0, 100_000).is_ok());
    }

    #[test]
    fn rates() {
        assert_eq!(mbps(125_000_000, 1.0), 1000);
        assert_eq!(mbps(800_000_000, 6.4), 1000);
        let m = Measurement {
            down_mbps: 940,
            up_mbps: 310,
            at: 0,
        };
        assert_eq!(m.mbps(), 310);
    }
}
