//! Thin wrappers for Linux syscalls that `nix` does not cover.

use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

// Syscall numbers shared by x86_64 and aarch64 (the post-4.20 unified table).
const SYS_OPEN_TREE: libc::c_long = 428;
const SYS_MOVE_MOUNT: libc::c_long = 429;
const SYS_OPENAT2: libc::c_long = 437;
const SYS_MOUNT_SETATTR: libc::c_long = 442;

const OPEN_TREE_CLONE: libc::c_uint = 1;
const AT_RECURSIVE: libc::c_uint = 0x8000;
const MOVE_MOUNT_F_EMPTY_PATH: libc::c_uint = 0x4;
const MOUNT_ATTR_IDMAP: u64 = 0x0010_0000;

const RESOLVE_NO_MAGICLINKS: u64 = 0x02;
const RESOLVE_IN_ROOT: u64 = 0x10;

#[repr(C)]
struct MountAttr {
    attr_set: u64,
    attr_clr: u64,
    propagation: u64,
    userns_fd: u64,
}

#[repr(C)]
struct OpenHow {
    flags: u64,
    mode: u64,
    resolve: u64,
}

fn cstr(p: &Path) -> io::Result<CString> {
    CString::new(p.as_os_str().as_bytes()).map_err(|_| io::Error::other("path contains NUL"))
}

fn check(ret: libc::c_long) -> io::Result<libc::c_long> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

/// Bind-mount `src` onto `dst` with every UID/GID shifted through the mapping
/// of the user namespace `userns`: files owned by 0 on disk appear owned by
/// the namespace's root, and writes from that root are stored as 0.
pub fn idmapped_bind(src: &Path, dst: &Path, userns: &impl AsRawFd) -> io::Result<()> {
    let src_c = cstr(src)?;
    let dst_c = cstr(dst)?;
    let empty = c"";
    unsafe {
        let tree = check(libc::syscall(
            SYS_OPEN_TREE,
            libc::AT_FDCWD,
            src_c.as_ptr(),
            OPEN_TREE_CLONE | libc::O_CLOEXEC as libc::c_uint | AT_RECURSIVE,
        ))? as RawFd;
        let tree = OwnedFd::from_raw_fd(tree);
        let attr = MountAttr {
            attr_set: MOUNT_ATTR_IDMAP,
            attr_clr: 0,
            propagation: 0,
            userns_fd: userns.as_raw_fd() as u64,
        };
        check(libc::syscall(
            SYS_MOUNT_SETATTR,
            tree.as_raw_fd(),
            empty.as_ptr(),
            libc::AT_EMPTY_PATH as libc::c_uint,
            &attr as *const MountAttr,
            std::mem::size_of::<MountAttr>(),
        ))?;
        check(libc::syscall(
            SYS_MOVE_MOUNT,
            tree.as_raw_fd(),
            empty.as_ptr(),
            libc::AT_FDCWD,
            dst_c.as_ptr(),
            MOVE_MOUNT_F_EMPTY_PATH,
        ))?;
    }
    Ok(())
}

/// `openat2(root, rel, RESOLVE_IN_ROOT)`: resolve `rel` as if `root` were `/`,
/// so symlinks planted inside a container rootfs cannot escape it.
pub fn open_in_root(root: &impl AsRawFd, rel: &Path, flags: i32, mode: u32) -> io::Result<OwnedFd> {
    let rel_c = cstr(rel)?;
    let how = OpenHow {
        flags: (flags | libc::O_CLOEXEC) as u64,
        mode: u64::from(mode),
        resolve: RESOLVE_IN_ROOT | RESOLVE_NO_MAGICLINKS,
    };
    unsafe {
        let fd = check(libc::syscall(
            SYS_OPENAT2,
            root.as_raw_fd(),
            rel_c.as_ptr(),
            &how as *const OpenHow,
            std::mem::size_of::<OpenHow>(),
        ))?;
        Ok(OwnedFd::from_raw_fd(fd as RawFd))
    }
}

pub fn pivot_root_here() -> io::Result<()> {
    let dot = c".";
    unsafe {
        check(libc::syscall(
            libc::SYS_pivot_root,
            dot.as_ptr(),
            dot.as_ptr(),
        ))?;
        if libc::umount2(dot.as_ptr(), libc::MNT_DETACH) != 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Is `path` a mount point (different device or mount id than its parent)?
pub fn is_mountpoint(path: &Path) -> bool {
    let target = match std::fs::canonicalize(path) {
        Ok(p) => p,
        Err(_) => return false,
    };
    let Ok(mounts) = std::fs::read_to_string("/proc/self/mountinfo") else {
        return false;
    };
    let want = target.as_os_str().as_bytes();
    mounts.lines().any(|line| {
        line.split(' ')
            .nth(4)
            .is_some_and(|mp| unescape_mountinfo(mp).as_slice() == want)
    })
}

fn unescape_mountinfo(s: &str) -> Vec<u8> {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'\\'
            && i + 3 < b.len()
            && let Ok(v) = u8::from_str_radix(&s[i + 1..i + 4], 8)
        {
            out.push(v);
            i += 4;
            continue;
        }
        out.push(b[i]);
        i += 1;
    }
    out
}

/// Lazily detach `path` if it is mounted (ignores "not mounted").
pub fn umount_if_mounted(path: &Path) -> io::Result<()> {
    while is_mountpoint(path) {
        nix::mount::umount2(path, nix::mount::MntFlags::MNT_DETACH).map_err(io::Error::from)?;
    }
    Ok(())
}
