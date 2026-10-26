//! Filesystem helpers, including writes confined to a container rootfs.

use std::ffi::CString;
use std::io::{self, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Component, Path};

use anyhow::{Context, Result, bail};

use super::sys::open_in_root;

/// Create `dir` (and parents) with mode 0711: traversable by container users
/// (needed to reach idmapped layers), not listable.
pub fn mkdir_private(dir: &Path) -> Result<()> {
    std::fs::DirBuilder::new()
        .recursive(true)
        .mode(0o711)
        .create(dir)?;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o711))?;
    Ok(())
}

pub fn replace_symlink(target: &str, link: &Path) -> Result<()> {
    let tmp = link.with_extension(format!("tmp-{}", std::process::id()));
    let _ = std::fs::remove_file(&tmp);
    std::os::unix::fs::symlink(target, &tmp)?;
    std::fs::rename(&tmp, link)?;
    Ok(())
}

pub fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    crate::config::write_atomic(path, data)
}

fn cstr(s: &[u8]) -> io::Result<CString> {
    CString::new(s).map_err(|_| io::Error::other("NUL in path"))
}

/// A container root filesystem opened as a directory fd. Every path is
/// resolved with `RESOLVE_IN_ROOT`, so symlinks inside the rootfs are followed
/// relative to it and can never reach the host.
pub struct RootFs {
    root: OwnedFd,
}

impl RootFs {
    pub fn open(path: &Path) -> Result<Self> {
        let root = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
        Ok(Self { root: root.into() })
    }

    fn dir(&self, rel: &Path) -> io::Result<OwnedFd> {
        open_in_root(&self.root, rel, libc::O_DIRECTORY | libc::O_RDONLY, 0)
    }

    pub fn exists(&self, rel: &str) -> bool {
        open_in_root(&self.root, Path::new(rel), libc::O_PATH, 0).is_ok()
    }

    pub fn read(&self, rel: &str) -> Result<Option<String>> {
        match open_in_root(&self.root, Path::new(rel), libc::O_RDONLY, 0) {
            Ok(fd) => {
                let mut s = String::new();
                io::Read::read_to_string(&mut std::fs::File::from(fd), &mut s)?;
                Ok(Some(s))
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e).with_context(|| format!("read {rel}")),
        }
    }

    /// Atomically replace `rel` (temp file + rename in the same directory).
    pub fn write(&self, rel: &str, data: &[u8], mode: u32) -> Result<()> {
        let (parent, name) = split(rel)?;
        let dir = self
            .dir(parent)
            .with_context(|| format!("open dir of {rel}"))?;
        let tmp = format!(".runman-{}-{}", std::process::id(), name.to_string_lossy());
        let tmp_c = cstr(tmp.as_bytes())?;
        let name_c = cstr(name.as_bytes())?;
        unsafe {
            libc::unlinkat(dir.as_raw_fd(), tmp_c.as_ptr(), 0);
            let fd = libc::openat(
                dir.as_raw_fd(),
                tmp_c.as_ptr(),
                libc::O_WRONLY | libc::O_CREAT | libc::O_EXCL | libc::O_NOFOLLOW | libc::O_CLOEXEC,
                mode,
            );
            if fd < 0 {
                return Err(io::Error::last_os_error()).with_context(|| format!("create {rel}"));
            }
            let mut f = std::fs::File::from_raw_fd(fd);
            f.write_all(data)?;
            libc::fchmod(fd, mode);
            f.sync_all()?;
            if libc::renameat(
                dir.as_raw_fd(),
                tmp_c.as_ptr(),
                dir.as_raw_fd(),
                name_c.as_ptr(),
            ) != 0
            {
                let e = io::Error::last_os_error();
                libc::unlinkat(dir.as_raw_fd(), tmp_c.as_ptr(), 0);
                return Err(e).with_context(|| format!("rename {rel}"));
            }
        }
        Ok(())
    }

    pub fn mkdir_all(&self, rel: &str) -> Result<()> {
        let mut cur = std::path::PathBuf::from("/");
        for comp in Path::new(rel).components() {
            let Component::Normal(name) = comp else {
                continue;
            };
            let dir = self.dir(&cur)?;
            let c = cstr(name.as_bytes())?;
            if unsafe { libc::mkdirat(dir.as_raw_fd(), c.as_ptr(), 0o755) } != 0 {
                let e = io::Error::last_os_error();
                if e.kind() != io::ErrorKind::AlreadyExists {
                    return Err(e).with_context(|| format!("mkdir {rel}"));
                }
            }
            cur.push(name);
        }
        Ok(())
    }

    /// Create or replace a symlink at `rel` pointing to `target`.
    pub fn symlink(&self, rel: &str, target: &str) -> Result<()> {
        let (parent, name) = split(rel)?;
        let dir = self.dir(parent)?;
        let name_c = cstr(name.as_bytes())?;
        let target_c = cstr(target.as_bytes())?;
        unsafe {
            libc::unlinkat(dir.as_raw_fd(), name_c.as_ptr(), 0);
            if libc::symlinkat(target_c.as_ptr(), dir.as_raw_fd(), name_c.as_ptr()) != 0 {
                return Err(io::Error::last_os_error()).with_context(|| format!("symlink {rel}"));
            }
        }
        Ok(())
    }

    pub fn remove(&self, rel: &str) -> Result<()> {
        let (parent, name) = split(rel)?;
        let Ok(dir) = self.dir(parent) else {
            return Ok(());
        };
        let name_c = cstr(name.as_bytes())?;
        if unsafe { libc::unlinkat(dir.as_raw_fd(), name_c.as_ptr(), 0) } != 0 {
            let e = io::Error::last_os_error();
            if e.kind() != io::ErrorKind::NotFound {
                return Err(e).with_context(|| format!("remove {rel}"));
            }
        }
        Ok(())
    }
}

fn split(rel: &str) -> Result<(&Path, &std::ffi::OsStr)> {
    let p = Path::new(rel);
    match (p.parent(), p.file_name()) {
        (Some(parent), Some(name)) => Ok((parent, name)),
        _ => bail!("invalid rootfs path {rel:?}"),
    }
}
