//! Image templates: prebuilt rootfs trees, unpacked once and shared read-only
//! as the overlay lower layer of every instance.
//!
//! Layout: `<data>/images/<id>/<serial>/rootfs`, `<serial>/meta.json`, and a
//! `current` symlink pointing at the serial new instances should use. Older
//! serials stay until no instance references them.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tokio::process::Command;
use tracing::{info, warn};

use super::fsutil::{mkdir_private, replace_symlink};

pub struct ImageDef {
    pub id: &'static str,
    /// Prebuilt asset name; `{arch}` is `amd64` or `arm64`.
    asset: &'static str,
    pub stop_signal: &'static str,
}

pub const IMAGES: &[ImageDef] = &[
    ImageDef {
        id: "debian",
        asset: "incus-debian-{arch}.tar.gz",
        stop_signal: "SIGRTMIN+4",
    },
    ImageDef {
        id: "alpine",
        asset: "incus-alpine-{arch}.tar.gz",
        stop_signal: "SIGUSR2",
    },
];

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Image {
    pub id: String,
    pub name: String,
    pub serial: String,
    pub stop_signal: String,
    #[serde(skip)]
    pub rootfs: PathBuf,
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

    /// Images that are unpacked and usable now.
    pub fn ready(&self) -> Vec<Image> {
        IMAGES.iter().filter_map(|d| self.get(d.id).ok()).collect()
    }

    pub fn get(&self, id: &str) -> Result<Image> {
        let def = def(id)?;
        let current = self.dir.join(def.id).join("current");
        let serial_dir = std::fs::canonicalize(&current)
            .with_context(|| format!("image {id} is not downloaded yet"))?;
        let mut img: Image = serde_json::from_slice(&std::fs::read(serial_dir.join("meta.json"))?)?;
        img.rootfs = serial_dir.join("rootfs");
        Ok(img)
    }

    /// Download and unpack every image that is not present yet.
    pub async fn sync(&self) {
        for d in IMAGES {
            if self.get(d.id).is_ok() {
                continue;
            }
            match self.fetch(d).await {
                Ok(img) => info!("image {} ready ({})", img.id, img.name),
                Err(e) => warn!("image {}: {e:#}", d.id),
            }
        }
    }

    async fn fetch(&self, def: &ImageDef) -> Result<Image> {
        let image_dir = self.dir.join(def.id);
        mkdir_private(&image_dir)?;
        let staging = image_dir.join(format!(".staging-{}", uuid::Uuid::new_v4()));
        mkdir_private(&staging)?;
        let result = self.fetch_into(def, &image_dir, &staging).await;
        let _ = tokio::fs::remove_dir_all(&staging).await;
        result
    }

    async fn fetch_into(&self, def: &ImageDef, image_dir: &Path, staging: &Path) -> Result<Image> {
        let url = format!(
            "{}/{}",
            self.base_url,
            def.asset.replace("{arch}", self.arch)
        );
        let archive = staging.join("image.tar.gz");
        info!("downloading image {} from {url}", def.id);
        run(Command::new("curl")
            .args(["-fsSL", "--retry", "3", "--connect-timeout", "20", "-o"])
            .arg(&archive)
            .arg(&url))
        .await
        .context("download")?;
        let tree = staging.join("tree");
        mkdir_private(&tree)?;
        run(Command::new("tar")
            .args(["-xzf"])
            .arg(&archive)
            .arg("-C")
            .arg(&tree)
            .args(["--numeric-owner", "--xattrs", "--xattrs-include=*"]))
        .await
        .context("unpack")?;

        let meta = std::fs::read_to_string(tree.join("metadata.yaml")).context("metadata.yaml")?;
        let serial = yaml_value(&meta, "serial").context("image serial missing")?;
        if serial.is_empty() || serial.contains(['/', '\0']) || serial.starts_with('.') {
            bail!("invalid image serial {serial:?}");
        }
        let name = yaml_value(&meta, "description").unwrap_or_else(|| def.id.to_owned());
        let img = Image {
            id: def.id.to_owned(),
            name,
            serial: serial.clone(),
            stop_signal: def.stop_signal.to_owned(),
            rootfs: PathBuf::new(),
        };

        // The directory name ends up in overlayfs mount options, where ':'
        // and ',' are separators, so keep it to a safe alphabet.
        let dir_name: String = serial
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let serial_dir = image_dir.join(&dir_name);
        if !serial_dir.exists() {
            mkdir_private(&serial_dir)?;
            std::fs::rename(tree.join("rootfs"), serial_dir.join("rootfs"))?;
            std::fs::write(
                serial_dir.join("meta.json"),
                serde_json::to_vec_pretty(&img)?,
            )?;
        }
        replace_symlink(&dir_name, &image_dir.join("current"))?;
        self.get(def.id)
    }
}

fn def(id: &str) -> Result<&'static ImageDef> {
    IMAGES
        .iter()
        .find(|d| d.id == id)
        .with_context(|| format!("unknown image {id:?}"))
}

/// First `key: value` occurrence in a simple YAML document (quotes stripped).
fn yaml_value(doc: &str, key: &str) -> Option<String> {
    doc.lines().find_map(|line| {
        let rest = line.trim_start().strip_prefix(key)?.strip_prefix(':')?;
        Some(rest.trim().trim_matches('"').to_owned())
    })
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
    fn parses_incus_metadata() {
        let doc = "architecture: amd64\nproperties:\n  description: Debian trixie amd64 (cloud) (20261012_05:24)\n  serial: \"20261012_05:24\"\n";
        assert_eq!(yaml_value(doc, "serial").unwrap(), "20261012_05:24");
        assert_eq!(
            yaml_value(doc, "description").unwrap(),
            "Debian trixie amd64 (cloud) (20261012_05:24)"
        );
    }
}
