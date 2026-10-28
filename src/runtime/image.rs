//! Image templates: root filesystems unpacked once and shared read-only as the
//! overlay lower layer of every instance.
//!
//! Layout: `<data>/images/<id>/<serial>/{rootfs,meta.json}` plus a `current`
//! symlink to the serial new instances use. Instances keep the serial they
//! were created from; [`ImageStore::gc`] removes serials nobody uses.
//!
//! Official images come from `image_base_url`: `images.json`, listing per-arch
//! `rootfs-<id>-<arch>.tar.zst` with SHA-256 and size. They are built by
//! `images/build.sh` in this repository. Custom images are built on the node
//! (see `Runtime::build_image`) and stored the same way.
//!
//! `<data>/images/settings.json` holds the owner's display order and the
//! images not offered for new instances; both apply to what is reported to
//! the platform.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tokio::process::Command;
use tracing::{info, warn};

use super::fsutil::{mkdir_private, replace_symlink};
use crate::model::ImageSettings;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Image {
    pub id: String,
    pub name: String,
    pub serial: String,
    pub stop_signal: String,
    /// Built on this node from `base` with `script`.
    #[serde(default)]
    pub custom: bool,
    #[serde(default)]
    pub base: String,
    #[serde(default)]
    pub script: String,
    #[serde(skip)]
    pub rootfs: PathBuf,
}

#[derive(Debug, Clone, Deserialize)]
struct Manifest {
    images: Vec<ManifestEntry>,
}

#[derive(Debug, Clone, Deserialize)]
struct ManifestEntry {
    id: String,
    name: String,
    serial: String,
    stop_signal: String,
    arch: String,
    file: String,
    sha256: String,
    size: u64,
}

/// Image ids end up in paths and in the platform's `os_image`.
pub fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 40
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !id.starts_with('-')
}

/// Serial as a directory name: overlayfs option syntax reserves ':' and ','.
fn dir_name(serial: &str) -> String {
    serial
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

pub struct ImageStore {
    dir: PathBuf,
    base_url: String,
    arch: &'static str,
}

impl ImageStore {
    pub fn new(data_dir: &Path, base_url: &str) -> Result<Self> {
        let arch = match std::env::consts::ARCH {
            "x86_64" => "amd64",
            "aarch64" => "arm64",
            other => bail!("unsupported architecture {other}"),
        };
        let dir = data_dir.join("images");
        mkdir_private(&dir)?;
        Ok(Self {
            dir,
            base_url: base_url.trim_end_matches('/').to_owned(),
            arch,
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    /// Every image with a current version, official and custom, in the
    /// owner's order, disabled ones included.
    pub fn ready(&self) -> Vec<Image> {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return Vec::new();
        };
        let mut out: Vec<Image> = entries
            .filter_map(|e| e.ok()?.file_name().into_string().ok())
            .filter(|id| valid_id(id))
            .filter_map(|id| self.get(&id).ok())
            .collect();
        let order = self.settings().order;
        let rank = |id: &str| order.iter().position(|o| o == id).unwrap_or(usize::MAX);
        // Unlisted images: official first, then custom ones by name.
        out.sort_by(|a, b| (rank(&a.id), a.custom, &a.name).cmp(&(rank(&b.id), b.custom, &b.name)));
        out
    }

    /// Images offered for new instances (and to the platform), in order.
    pub fn enabled(&self) -> Vec<Image> {
        let disabled = self.settings().disabled;
        self.ready()
            .into_iter()
            .filter(|i| !disabled.contains(&i.id))
            .collect()
    }

    pub fn is_enabled(&self, id: &str) -> bool {
        !self.settings().disabled.iter().any(|d| d == id)
    }

    fn settings_path(&self) -> PathBuf {
        self.dir.join("settings.json")
    }

    pub fn settings(&self) -> ImageSettings {
        std::fs::read(self.settings_path())
            .ok()
            .and_then(|raw| serde_json::from_slice(&raw).ok())
            .unwrap_or_default()
    }

    /// Replace the order and disabled set. At least one available image must
    /// stay enabled: an empty list in a heartbeat means "unchanged" to the
    /// platform, so it would keep offering the old ones.
    pub fn set_settings(&self, mut s: ImageSettings) -> Result<()> {
        if let Some(bad) = s.order.iter().chain(&s.disabled).find(|id| !valid_id(id)) {
            bail!("invalid image id {bad:?}");
        }
        let mut seen = std::collections::HashSet::new();
        s.order.retain(|id| seen.insert(id.clone()));
        s.disabled.sort();
        s.disabled.dedup();
        let ready = self.ready();
        if !ready.is_empty() && ready.iter().all(|i| s.disabled.contains(&i.id)) {
            bail!("at least one image must stay enabled");
        }
        crate::config::write_atomic(&self.settings_path(), &serde_json::to_vec_pretty(&s)?)
    }

    pub fn get(&self, id: &str) -> Result<Image> {
        if !valid_id(id) {
            bail!("invalid image id {id:?}");
        }
        let current = self.dir.join(id).join("current");
        let serial_dir = std::fs::canonicalize(&current)
            .with_context(|| format!("image {id:?} is not available"))?;
        let mut img: Image = serde_json::from_slice(&std::fs::read(serial_dir.join("meta.json"))?)?;
        img.rootfs = serial_dir.join("rootfs");
        Ok(img)
    }

    /// Fetch the manifest and download images whose serial is new.
    pub async fn sync(&self) -> Result<()> {
        let staging = self.dir.join(format!(".staging-{}", uuid::Uuid::new_v4()));
        mkdir_private(&staging)?;
        let result = self.sync_into(&staging).await;
        let _ = tokio::fs::remove_dir_all(&staging).await;
        result
    }

    async fn sync_into(&self, staging: &Path) -> Result<()> {
        let manifest_path = staging.join("images.json");
        fetch(&format!("{}/images.json", self.base_url), &manifest_path).await?;
        let raw = std::fs::read(&manifest_path)?;
        let manifest: Manifest = serde_json::from_slice(&raw).context("parse images.json")?;
        for entry in manifest.images.iter().filter(|e| e.arch == self.arch) {
            if !valid_id(&entry.id)
                || !entry.file.starts_with("rootfs-")
                || entry.file.contains('/')
            {
                warn!("skipping invalid manifest entry {:?}", entry.id);
                continue;
            }
            let image_dir = self.dir.join(&entry.id);
            let serial_dir = image_dir.join(dir_name(&entry.serial));
            if !serial_dir.join("meta.json").exists() {
                if let Err(e) = self.fetch_entry(entry, staging, &serial_dir).await {
                    warn!("image {} {}: {e:#}", entry.id, entry.serial);
                    continue;
                }
                info!(
                    "image {} ready ({}, {})",
                    entry.id, entry.name, entry.serial
                );
            }
            replace_symlink(&dir_name(&entry.serial), &image_dir.join("current"))?;
        }
        Ok(())
    }

    async fn fetch_entry(
        &self,
        e: &ManifestEntry,
        staging: &Path,
        serial_dir: &Path,
    ) -> Result<()> {
        let archive = staging.join(&e.file);
        info!(
            "downloading image {} {} ({} MB)",
            e.id,
            e.serial,
            e.size >> 20
        );
        fetch(&format!("{}/{}", self.base_url, e.file), &archive).await?;
        let len = std::fs::metadata(&archive)?.len();
        if len != e.size {
            bail!("size {len} does not match manifest ({})", e.size);
        }
        let data = tokio::fs::read(&archive).await?;
        if crate::updater::hex_sha256(&data) != e.sha256.to_ascii_lowercase() {
            bail!("checksum does not match manifest");
        }
        drop(data);
        let tree = staging.join(format!("tree-{}", e.id));
        let rootfs = tree.join("rootfs");
        mkdir_private(&tree)?;
        std::fs::create_dir(&rootfs)?;
        run(Command::new("tar")
            .arg("--zstd")
            .arg("-xf")
            .arg(&archive)
            .arg("-C")
            .arg(&rootfs)
            .args(["--numeric-owner", "--xattrs", "--xattrs-include=*"]))
        .await
        .context("unpack")?;
        let meta = Image {
            id: e.id.clone(),
            name: e.name.clone(),
            serial: e.serial.clone(),
            stop_signal: e.stop_signal.clone(),
            custom: false,
            base: String::new(),
            script: String::new(),
            rootfs: PathBuf::new(),
        };
        std::fs::write(tree.join("meta.json"), serde_json::to_vec_pretty(&meta)?)?;
        mkdir_private(serial_dir.parent().expect("serial dir has a parent"))?;
        std::fs::rename(&tree, serial_dir)?;
        let _ = tokio::fs::remove_file(&archive).await;
        Ok(())
    }

    /// Install a finished custom image tree (`tree/rootfs`) as the current
    /// version of `meta.id`.
    pub fn install_custom(&self, tree: &Path, meta: &Image) -> Result<Image> {
        let image_dir = self.dir.join(&meta.id);
        mkdir_private(&image_dir)?;
        std::fs::write(tree.join("meta.json"), serde_json::to_vec_pretty(meta)?)?;
        let name = dir_name(&meta.serial);
        std::fs::rename(tree, image_dir.join(&name))?;
        replace_symlink(&name, &image_dir.join("current"))?;
        self.get(&meta.id)
    }

    /// Stop offering a custom image; its files go once no instance uses them.
    pub fn remove_custom(&self, id: &str) -> Result<()> {
        let img = self.get(id)?;
        if !img.custom {
            bail!("{id} is an official image");
        }
        std::fs::remove_file(self.dir.join(id).join("current"))?;
        // A later image with the same id starts out enabled, at the end.
        let mut s = self.settings();
        if s.order.iter().chain(&s.disabled).any(|x| x == id) {
            s.order.retain(|x| x != id);
            s.disabled.retain(|x| x != id);
            crate::config::write_atomic(&self.settings_path(), &serde_json::to_vec_pretty(&s)?)?;
        }
        Ok(())
    }

    /// Delete serials that are neither current nor the lower layer of any
    /// instance (`in_use` holds their rootfs paths).
    pub fn gc(&self, in_use: &[PathBuf]) {
        let Ok(ids) = std::fs::read_dir(&self.dir) else {
            return;
        };
        for id_entry in ids.flatten() {
            let id_dir = id_entry.path();
            let name = id_entry.file_name().to_string_lossy().into_owned();
            if name.starts_with(".staging-") {
                // Leftover of an interrupted download.
                let _ = std::fs::remove_dir_all(&id_dir);
                continue;
            }
            if !id_dir.is_dir() || !valid_id(&name) {
                continue;
            }
            let current = std::fs::canonicalize(id_dir.join("current")).ok();
            let Ok(serials) = std::fs::read_dir(&id_dir) else {
                continue;
            };
            let mut kept = 0;
            for s in serials.flatten() {
                let path = s.path();
                if s.file_name() == "current" || !path.is_dir() {
                    continue;
                }
                let canonical = std::fs::canonicalize(&path).unwrap_or(path.clone());
                let used = in_use
                    .iter()
                    .any(|p| p.starts_with(&canonical) || p.starts_with(&path));
                if Some(&canonical) == current.as_ref() || used {
                    kept += 1;
                    continue;
                }
                info!(
                    "removing unused image {name} {}",
                    s.file_name().to_string_lossy()
                );
                if let Err(e) = std::fs::remove_dir_all(&path) {
                    warn!("remove {}: {e}", path.display());
                }
            }
            if kept == 0 && current.is_none() {
                let _ = std::fs::remove_dir_all(&id_dir);
            }
        }
    }
}

async fn fetch(url: &str, dest: &Path) -> Result<()> {
    run(Command::new("curl")
        .args(["-fsSL", "--retry", "3", "--connect-timeout", "20", "-o"])
        .arg(dest)
        .arg(url))
    .await
    .with_context(|| format!("download {url}"))
}

pub(super) async fn run(cmd: &mut Command) -> Result<()> {
    let out = cmd.output().await?;
    if !out.status.success() {
        bail!(
            "{:?} failed ({}): {}",
            cmd.as_std().get_program(),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ids_and_dir_names() {
        assert!(valid_id("debian"));
        assert!(valid_id("custom-web-1"));
        assert!(!valid_id("../etc"));
        assert!(!valid_id("Debian"));
        assert!(!valid_id("-x"));
        assert_eq!(dir_name("20261012_05:24"), "20261012_05_24");
    }

    #[test]
    fn gc_keeps_current_and_used() {
        let root = std::env::temp_dir().join(format!("runman-img-gc-{}", uuid::Uuid::new_v4()));
        let store = ImageStore::new(&root, "http://example.invalid").unwrap();
        let mk = |id: &str, serial: &str| {
            let d = store.dir.join(id).join(serial);
            std::fs::create_dir_all(d.join("rootfs")).unwrap();
            d
        };
        let old = mk("debian", "1");
        let used = mk("debian", "2");
        let cur = mk("debian", "3");
        replace_symlink("3", &store.dir.join("debian").join("current")).unwrap();
        let gone = mk("custom-x", "1");
        store.gc(&[used.join("rootfs")]);
        assert!(!old.exists(), "unused old serial is removed");
        assert!(used.exists() && cur.exists());
        assert!(
            !gone.exists() && !store.dir.join("custom-x").exists(),
            "removed custom image without current"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn settings_order_and_disable() {
        let root = std::env::temp_dir().join(format!("runman-img-set-{}", uuid::Uuid::new_v4()));
        let store = ImageStore::new(&root, "http://example.invalid").unwrap();
        for (id, name, custom) in [
            ("debian", "Debian", false),
            ("alpine", "Alpine", false),
            ("web", "Web", true),
        ] {
            let d = store.dir.join(id).join("1");
            std::fs::create_dir_all(d.join("rootfs")).unwrap();
            let meta = Image {
                id: id.into(),
                name: name.into(),
                serial: "1".into(),
                stop_signal: String::new(),
                custom,
                base: String::new(),
                script: String::new(),
                rootfs: PathBuf::new(),
            };
            std::fs::write(d.join("meta.json"), serde_json::to_vec(&meta).unwrap()).unwrap();
            replace_symlink("1", &store.dir.join(id).join("current")).unwrap();
        }
        let ids = |v: Vec<Image>| v.into_iter().map(|i| i.id).collect::<Vec<_>>();
        assert_eq!(
            ids(store.ready()),
            ["alpine", "debian", "web"],
            "default order"
        );

        store
            .set_settings(ImageSettings {
                order: vec!["web".into(), "debian".into(), "web".into()],
                disabled: vec!["debian".into()],
            })
            .unwrap();
        assert_eq!(
            ids(store.ready()),
            ["web", "debian", "alpine"],
            "listed first, rest after"
        );
        assert_eq!(ids(store.enabled()), ["web", "alpine"]);
        assert!(!store.is_enabled("debian") && store.is_enabled("alpine"));
        assert_eq!(
            store.settings().order,
            ["web", "debian"],
            "duplicates dropped"
        );

        let all_off = ImageSettings {
            order: vec![],
            disabled: vec!["debian".into(), "alpine".into(), "web".into()],
        };
        assert!(
            store.set_settings(all_off).is_err(),
            "last enabled image stays"
        );
        assert!(
            store
                .set_settings(ImageSettings {
                    order: vec!["../x".into()],
                    disabled: vec![]
                })
                .is_err()
        );

        store
            .set_settings(ImageSettings {
                order: vec!["web".into()],
                disabled: vec!["web".into()],
            })
            .unwrap();
        store.remove_custom("web").unwrap();
        assert_eq!(
            store.settings(),
            ImageSettings::default(),
            "removed image forgotten"
        );
        let _ = std::fs::remove_dir_all(root);
    }
}
