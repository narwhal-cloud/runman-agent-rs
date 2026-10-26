//! Custom images built on the node.
//!
//! A build boots a temporary instance from the base image (marked `builder`,
//! hidden from listings and heartbeats), runs the user's script in it as
//! root with network access, cleans caches, powers it off and copies its
//! merged root filesystem into a new image version. The temporary instance
//! is always deleted; the build log is kept. One build runs at a time.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use tracing::{info, warn};

use super::Runtime;
use super::image::{Image, valid_id};
use crate::backend::{ImageAdmin, Instances};
use crate::model::{BuildInfo, BuildRequest, ImageInfo, InstanceSpec, VmId};

const SCRIPT_TIMEOUT: Duration = Duration::from_secs(3600);
const MAX_SCRIPT: usize = 64 * 1024;
const KEEP_BUILDS: usize = 50;
// Resources of the temporary instance a build runs in.
const BUILDER_CPU: u32 = 2;
const BUILDER_RAM_MB: u64 = 2048;
const BUILDER_DISK_GB: u64 = 20;

pub struct Builds {
    dir: PathBuf,
    list: Mutex<Vec<BuildInfo>>,
    /// Held by the running build.
    running: Arc<tokio::sync::Mutex<()>>,
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

impl Builds {
    pub fn new(dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(dir)?;
        let mut list: Vec<BuildInfo> = std::fs::read(dir.join("builds.json"))
            .ok()
            .and_then(|raw| serde_json::from_slice(&raw).ok())
            .unwrap_or_default();
        // A build cannot outlive the agent process.
        for b in list.iter_mut().filter(|b| b.state == "running") {
            b.state = "failed".into();
            b.error = "interrupted by an agent restart".into();
        }
        Ok(Self {
            dir: dir.to_owned(),
            list: Mutex::new(list),
            running: Arc::default(),
        })
    }

    fn log_path(&self, id: &str) -> PathBuf {
        self.dir.join(format!("{id}.log"))
    }

    fn update(&self, id: &str, f: impl FnOnce(&mut BuildInfo)) {
        let mut list = self.list.lock().unwrap();
        if let Some(b) = list.iter_mut().find(|b| b.id == id) {
            f(b);
        }
        let _ = std::fs::write(
            self.dir.join("builds.json"),
            serde_json::to_vec_pretty(&*list).unwrap_or_default(),
        );
    }

    fn push(&self, info: BuildInfo) {
        let mut list = self.list.lock().unwrap();
        list.insert(0, info);
        let keep = KEEP_BUILDS.min(list.len());
        for old in list.split_off(keep) {
            let _ = std::fs::remove_file(self.log_path(&old.id));
        }
        let _ = std::fs::write(
            self.dir.join("builds.json"),
            serde_json::to_vec_pretty(&*list).unwrap_or_default(),
        );
    }
}

fn log_line(path: &Path, line: &str) {
    use std::io::Write;
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(f, "==> {line}");
    }
}

impl Runtime {
    fn validate_build(&self, req: &BuildRequest) -> Result<()> {
        if !valid_id(&req.image_id) {
            bail!("image id must be 1-40 lowercase letters, digits or '-'");
        }
        if let Ok(existing) = self.images.get(&req.image_id)
            && !existing.custom
        {
            bail!("{} is an official image id", req.image_id);
        }
        let name = req.name.trim();
        if name.is_empty() || name.len() > 64 || name.chars().any(char::is_control) {
            bail!("name must be 1-64 printable characters");
        }
        self.images
            .get(&req.base)
            .with_context(|| format!("base image {:?}", req.base))?;
        if req.script.trim().is_empty() || req.script.len() > MAX_SCRIPT {
            bail!("script must be 1 byte to 64 KB");
        }
        Ok(())
    }

    async fn run_build(self: &Arc<Self>, build_id: &str, req: &BuildRequest) -> Result<()> {
        let log = self.builds.log_path(build_id);
        let base = self.images.get(&req.base)?;
        log_line(
            &log,
            &format!(
                "building {} ({}) from {} {}",
                req.image_id, req.name, base.id, base.serial
            ),
        );
        let vm = VmId::parse(&uuid::Uuid::new_v4().to_string())?;
        let spec = InstanceSpec {
            vm_id: vm.clone(),
            cpu: BUILDER_CPU,
            ram_mb: BUILDER_RAM_MB,
            disk_gb: BUILDER_DISK_GB,
            bandwidth_mbps: 0,
            os_image: req.base.clone(),
            root_password: crate::web::random_token(24),
        };
        {
            let _g = self.lock_vm(vm.as_str()).await;
            self.create_locked(&spec, true)
                .await
                .context("start build instance")?;
        }
        let result = self.build_in(&vm, build_id, req, &base, &log).await;
        if let Err(e) = Instances::delete(self.as_ref(), &vm).await {
            warn!("build {build_id}: remove build instance: {e:#}");
        }
        result
    }

    async fn build_in(
        &self,
        vm: &VmId,
        build_id: &str,
        req: &BuildRequest,
        base: &Image,
        log: &Path,
    ) -> Result<()> {
        let target = self.exec_target(vm.as_str());
        // Wait for the instance's network (its default route).
        let mut ready = false;
        for _ in 0..90 {
            if target
                .run(
                    &["sh", "-c", "ip route 2>/dev/null | grep -q '^default'"],
                    b"",
                )
                .await
                .is_ok()
            {
                ready = true;
                break;
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
        if !ready {
            bail!("build instance did not come up with a network");
        }
        log_line(log, "running script");
        let script = format!(
            "set -e\nexport DEBIAN_FRONTEND=noninteractive\n{}\n",
            req.script
        );
        let code = target
            .run_logged(&["/bin/sh", "-s"], script.as_bytes(), log, SCRIPT_TIMEOUT)
            .await?;
        if code != 0 {
            bail!("script exited with status {code}");
        }
        log_line(log, "script finished; cleaning caches");
        let clean = "rm -rf /tmp/* /var/tmp/* /var/cache/apk/* 2>/dev/null; \
                     if command -v apt-get >/dev/null; then apt-get clean; rm -rf /var/lib/apt/lists/*; fi; :";
        target
            .run_logged(
                &["/bin/sh", "-c", clean],
                b"",
                log,
                Duration::from_secs(300),
            )
            .await?;
        Instances::stop(self, vm, false)
            .await
            .context("power off build instance")?;

        log_line(log, "saving image");
        let rec = self.require(vm)?;
        let tree = self.images.dir().join(format!(".build-{build_id}"));
        let rootfs = tree.join("rootfs");
        std::fs::create_dir_all(&rootfs)?;
        let copied = {
            let rootfs = rootfs.clone();
            self.with_offline_path(&rec, false, move |src| copy_tree(src, &rootfs))
                .await
        };
        if let Err(e) = copied {
            let _ = std::fs::remove_dir_all(&tree);
            return Err(e.context("copy root filesystem"));
        }
        let meta = Image {
            id: req.image_id.clone(),
            name: req.name.trim().to_owned(),
            serial: now().to_string(),
            stop_signal: base.stop_signal.clone(),
            custom: true,
            base: req.base.clone(),
            script: req.script.clone(),
            rootfs: PathBuf::new(),
        };
        let installed = self.images.install_custom(&tree, &meta);
        if installed.is_err() {
            let _ = std::fs::remove_dir_all(&tree);
        }
        let img = installed?;
        log_line(
            log,
            &format!("image {} version {} is ready", img.id, img.serial),
        );
        Ok(())
    }
}

/// Copy the merged root filesystem, then drop what must differ per instance
/// (the agent recreates it at each instance's first boot).
fn copy_tree(src: &Path, dst: &Path) -> Result<()> {
    let status = std::process::Command::new("cp")
        .args(["-a", "--one-file-system"])
        .arg(format!("{}/.", src.display()))
        .arg(dst)
        .status()?;
    if !status.success() {
        bail!("cp failed ({status})");
    }
    for rel in [
        "root/.bash_history",
        "root/.ash_history",
        "var/lib/dbus/machine-id",
    ] {
        let _ = std::fs::remove_file(dst.join(rel));
    }
    if let Ok(keys) = std::fs::read_dir(dst.join("etc/ssh")) {
        for k in keys.flatten() {
            if k.file_name().to_string_lossy().starts_with("ssh_host_") {
                let _ = std::fs::remove_file(k.path());
            }
        }
    }
    if dst.join("etc/machine-id").exists() {
        std::fs::write(dst.join("etc/machine-id"), b"")?;
    }
    let _ = std::fs::remove_dir_all(dst.join("var/log/journal"));
    Ok(())
}

/// The panel's view of a runtime's images.
pub struct ImageAdminHandle(pub Arc<Runtime>);

#[async_trait]
impl ImageAdmin for ImageAdminHandle {
    async fn list_images(&self) -> Result<Vec<ImageInfo>> {
        let records = self.0.records()?;
        Ok(self
            .0
            .images
            .ready()
            .into_iter()
            .map(|img| {
                let id_dir = self.0.images.dir().join(&img.id);
                let in_use = records
                    .iter()
                    .filter(|r| !r.builder && r.lower.starts_with(&id_dir))
                    .count();
                ImageInfo {
                    id: img.id,
                    name: img.name,
                    serial: img.serial,
                    custom: img.custom,
                    base: img.base,
                    script: img.script,
                    in_use,
                }
            })
            .collect())
    }

    fn start_build(&self, req: BuildRequest) -> Result<String> {
        self.0.validate_build(&req)?;
        let Ok(guard) = self.0.builds.running.clone().try_lock_owned() else {
            bail!("another image build is running");
        };
        let build_id = uuid::Uuid::new_v4().to_string();
        self.0.builds.push(BuildInfo {
            id: build_id.clone(),
            image_id: req.image_id.clone(),
            name: req.name.trim().to_owned(),
            base: req.base.clone(),
            state: "running".into(),
            error: String::new(),
            started: now(),
            finished: None,
        });
        let rt = self.0.clone();
        let bid = build_id.clone();
        tokio::spawn(async move {
            let _running = guard;
            info!("image build {bid}: {} from {}", req.image_id, req.base);
            let result = rt.run_build(&bid, &req).await;
            if let Err(e) = &result {
                log_line(&rt.builds.log_path(&bid), &format!("FAILED: {e:#}"));
                warn!("image build {bid} failed: {e:#}");
            }
            rt.builds.update(&bid, |b| {
                b.state = if result.is_ok() {
                    "succeeded"
                } else {
                    "failed"
                }
                .into();
                b.error = result.err().map(|e| format!("{e:#}")).unwrap_or_default();
                b.finished = Some(now());
            });
        });
        Ok(build_id)
    }

    fn builds(&self) -> Vec<BuildInfo> {
        self.0.builds.list.lock().unwrap().clone()
    }

    fn build_log(&self, build_id: &str) -> Result<String> {
        let id = uuid::Uuid::parse_str(build_id).context("invalid build id")?;
        let raw =
            std::fs::read(self.0.builds.log_path(&id.to_string())).context("no such build")?;
        // The tail is what matters for long logs.
        let start = raw.len().saturating_sub(256 * 1024);
        Ok(String::from_utf8_lossy(&raw[start..]).into_owned())
    }

    async fn delete_image(&self, id: &str) -> Result<()> {
        self.0.images.remove_custom(id)?;
        self.0.gc_images();
        Ok(())
    }
}
