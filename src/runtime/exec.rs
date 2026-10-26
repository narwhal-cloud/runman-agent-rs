//! Running commands inside a live instance.
//!
//! `runman-agent __exec <init.pid> <unit cgroup> -- <cmd>...` joins the
//! instance's cgroup (the one its init is in) and namespaces, then forks so the command becomes a
//! member of the instance's pid namespace, running as container root. It is a
//! separate single-threaded process because `setns(CLONE_NEWUSER)` is refused
//! to multi-threaded callers such as the agent.

use std::ffi::{CString, OsString};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsFd, AsRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::{Context, Result, anyhow, bail};
use nix::sched::{CloneFlags, setns};
use nix::sys::wait::{WaitStatus, waitpid};
use nix::unistd::{ForkResult, Gid, Uid, fork};
use tokio::sync::mpsc;

use crate::backend::ConsoleIo;
use crate::model::ConsoleSize;

const PATH: &str = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin";
const NAMESPACES: &[(&str, CloneFlags)] = &[
    // The user namespace must come first: the others are owned by it.
    ("user", CloneFlags::CLONE_NEWUSER),
    ("mnt", CloneFlags::CLONE_NEWNS),
    ("net", CloneFlags::CLONE_NEWNET),
    ("uts", CloneFlags::CLONE_NEWUTS),
    ("ipc", CloneFlags::CLONE_NEWIPC),
    ("cgroup", CloneFlags::CLONE_NEWCGROUP),
    ("pid", CloneFlags::CLONE_NEWPID),
];

/// Entry point of the `__exec` helper.
pub fn main(args: &[OsString]) -> ! {
    let code = match helper(args) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("runman exec: {e:#}");
            126
        }
    };
    std::process::exit(code)
}

fn helper(args: &[OsString]) -> Result<i32> {
    let [pid_file, unit, sep, cmd @ ..] = args else {
        bail!("usage: __exec <init.pid> <unit cgroup> -- <cmd>...");
    };
    if sep != "--" || cmd.is_empty() {
        bail!("missing command");
    }
    let pid: i32 = std::fs::read_to_string(Path::new(pid_file))
        .context("instance is not running")?
        .trim()
        .parse()?;
    let fds: Vec<(File, CloneFlags)> = NAMESPACES
        .iter()
        .map(|(name, flag)| Ok((File::open(format!("/proc/{pid}/ns/{name}"))?, *flag)))
        .collect::<Result<_>>()
        .context("open instance namespaces")?;
    // Join the instance's cgroup before its cgroup namespace (migrations
    // must stay inside the namespace root afterwards), so the session and
    // everything started from it is accounted and limited with the
    // instance: lxcfs reports the memory of init's cgroup, and the CPU limit
    // is on `ct`.
    let me = std::process::id().to_string();
    if !session_cgroups(Path::new(unit), pid)
        .iter()
        .any(|dir| std::fs::write(dir.join("cgroup.procs"), &me).is_ok())
    {
        bail!("cannot join the instance's cgroup");
    }
    for (fd, flag) in &fds {
        setns(fd.as_fd(), *flag).with_context(|| format!("setns {flag:?}"))?;
    }
    drop(fds);

    let argv: Vec<CString> = cmd
        .iter()
        .map(|a| CString::new(a.as_bytes()))
        .collect::<Result<_, _>>()?;
    // SAFETY: single-threaded helper process.
    match unsafe { fork()? } {
        ForkResult::Child => {
            let err = exec_child(&argv);
            eprintln!("runman exec: {err:#}");
            unsafe { libc::_exit(127) }
        }
        ForkResult::Parent { child } => loop {
            match waitpid(child, None) {
                Ok(WaitStatus::Exited(_, c)) => return Ok(c),
                Ok(WaitStatus::Signaled(_, s, _)) => return Ok(128 + s as i32),
                Ok(_) | Err(nix::errno::Errno::EINTR) => continue,
                Err(e) => return Err(e.into()),
            }
        },
    }
}

fn exec_child(argv: &[CString]) -> anyhow::Error {
    let res = (|| -> Result<()> {
        nix::unistd::setsid()?;
        if nix::unistd::isatty(std::io::stdin())? {
            unsafe { libc::ioctl(0, libc::TIOCSCTTY, 0) };
        }
        nix::unistd::setgroups(&[])?;
        nix::unistd::setresgid(Gid::from_raw(0), Gid::from_raw(0), Gid::from_raw(0))?;
        nix::unistd::setresuid(Uid::from_raw(0), Uid::from_raw(0), Uid::from_raw(0))?;
        if nix::unistd::chdir("/root").is_err() {
            nix::unistd::chdir("/")?;
        }
        // Console sessions get the same seccomp filter as the instance's init.
        super::seccomp::install()?;
        // execvp searches the PATH of the current environment.
        unsafe { std::env::set_var("PATH", PATH) };
        nix::unistd::execvp(&argv[0], argv)?;
        Ok(())
    })();
    match res {
        Ok(()) => anyhow!("exec returned"),
        Err(e) => e,
    }
}

/// Where to put processes entering the instance, best first: the cgroup of
/// its init (a populated leaf, so joining it is always allowed: `ct` itself,
/// or `ct/init.scope` under systemd), then `ct`.
fn session_cgroups(unit: &Path, init_pid: i32) -> Vec<PathBuf> {
    let ct = unit.join("ct");
    let init = std::fs::read_to_string(format!("/proc/{init_pid}/cgroup"))
        .ok()
        .and_then(|s| {
            let rel = s.lines().find_map(|l| l.strip_prefix("0::"))?.trim();
            Some(Path::new("/sys/fs/cgroup").join(rel.trim_start_matches('/')))
        })
        .filter(|p| p.starts_with(&ct) && !p.components().any(|c| c.as_os_str() == ".."));
    init.into_iter().chain([ct]).collect()
}

/// Move instance processes that ended up in the unit's `supervisor` cgroup
/// (sessions of older agents put them there) into the instance's cgroup.
/// They are recognised by living in the instance's pid namespace; the
/// supervisor and `__exec` helpers stay in the host's. Returns how many moved.
pub fn adopt_strays(unit: &Path, init_pid: i32) -> usize {
    let Ok(host_ns) = std::fs::read_link("/proc/self/ns/pid") else {
        return 0;
    };
    let Ok(ct_ns) = std::fs::read_link(format!("/proc/{init_pid}/ns/pid")) else {
        return 0;
    };
    if ct_ns == host_ns {
        return 0;
    }
    let Ok(procs) = std::fs::read_to_string(unit.join("supervisor/cgroup.procs")) else {
        return 0;
    };
    let targets = session_cgroups(unit, init_pid);
    let mut moved = 0;
    for pid in procs.lines().filter_map(|l| l.trim().parse::<u32>().ok()) {
        if std::fs::read_link(format!("/proc/{pid}/ns/pid"))
            .ok()
            .as_ref()
            != Some(&ct_ns)
        {
            continue;
        }
        if targets
            .iter()
            .any(|dir| std::fs::write(dir.join("cgroup.procs"), pid.to_string()).is_ok())
        {
            moved += 1;
        }
    }
    moved
}

/// How the agent reaches an instance's exec helper.
#[derive(Clone)]
pub struct ExecTarget {
    pub exe: PathBuf,
    pub pid_file: PathBuf,
    /// The instance's systemd unit cgroup.
    pub unit_cgroup: PathBuf,
}

impl ExecTarget {
    fn command(&self, argv: &[&str]) -> std::process::Command {
        let mut cmd = std::process::Command::new(&self.exe);
        cmd.arg("__exec")
            .arg(&self.pid_file)
            .arg(&self.unit_cgroup)
            .arg("--")
            .args(argv);
        cmd.env_clear()
            .env("PATH", PATH)
            .env("HOME", "/root")
            .env("USER", "root")
            .env("LOGNAME", "root")
            .env("LANG", "C.UTF-8")
            .env("TERM", "xterm-256color");
        cmd
    }

    /// Run a command to completion, feeding `stdin`.
    pub async fn run(&self, argv: &[&str], stdin: &[u8]) -> Result<()> {
        let mut child = tokio::process::Command::from(self.command(argv))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        if let Some(mut input) = child.stdin.take() {
            tokio::io::AsyncWriteExt::write_all(&mut input, stdin).await?;
        }
        let out = child.wait_with_output().await?;
        if !out.status.success() {
            bail!(
                "{} failed ({}): {}",
                argv[0],
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(())
    }

    /// Run a command feeding `stdin`, appending its stdout and stderr to
    /// `log` as they come; killed after `timeout`. Returns the exit code.
    pub async fn run_logged(
        &self,
        argv: &[&str],
        stdin: &[u8],
        log: &Path,
        timeout: std::time::Duration,
    ) -> Result<i32> {
        let out = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(log)?;
        let mut child = tokio::process::Command::from(self.command(argv))
            .stdin(Stdio::piped())
            .stdout(Stdio::from(out.try_clone()?))
            .stderr(Stdio::from(out))
            .kill_on_drop(true)
            .spawn()?;
        if let Some(mut input) = child.stdin.take() {
            tokio::io::AsyncWriteExt::write_all(&mut input, stdin).await?;
        }
        match tokio::time::timeout(timeout, child.wait()).await {
            Ok(status) => Ok(status?.code().unwrap_or(-1)),
            Err(_) => {
                let _ = child.kill().await;
                bail!("timed out after {timeout:?}")
            }
        }
    }

    /// Start an interactive login shell on a fresh pty.
    pub fn console(&self, size: Option<ConsoleSize>) -> Result<ConsoleIo> {
        let ws = size.map(winsize);
        let pty = nix::pty::openpty(ws.as_ref(), None)?;
        let shell = "if [ -x /bin/bash ]; then exec /bin/bash -l; else exec /bin/sh -l; fi";
        let mut cmd = self.command(&["/bin/sh", "-c", shell]);
        cmd.stdin(Stdio::from(pty.slave.try_clone()?))
            .stdout(Stdio::from(pty.slave.try_clone()?))
            .stderr(Stdio::from(pty.slave));
        let mut child = cmd.spawn().context("spawn console helper")?;

        let master = Arc::new(pty.master);
        let closed = Arc::new(AtomicBool::new(false));
        let (out_tx, out_rx) = mpsc::channel::<Vec<u8>>(64);
        let (in_tx, mut in_rx) = mpsc::channel::<Vec<u8>>(64);
        let (resize_tx, mut resize_rx) = mpsc::channel::<ConsoleSize>(8);

        // Reader: polls so it can drop its fd promptly once the session is
        // closed; the shell gets SIGHUP when the last master fd goes away.
        {
            let master = master.clone();
            let closed = closed.clone();
            std::thread::spawn(move || {
                let mut file = File::from(master.as_fd().try_clone_to_owned().expect("dup pty"));
                drop(master);
                let mut buf = [0u8; 8192];
                while !closed.load(Ordering::Relaxed) {
                    let mut pfd = libc::pollfd {
                        fd: file.as_raw_fd(),
                        events: libc::POLLIN,
                        revents: 0,
                    };
                    if unsafe { libc::poll(&mut pfd, 1, 200) } <= 0 {
                        continue;
                    }
                    match file.read(&mut buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if out_tx.blocking_send(buf[..n].to_vec()).is_err() {
                                break;
                            }
                        }
                    }
                }
                closed.store(true, Ordering::Relaxed);
                drop(file);
                let _ = child.wait();
            });
        }
        // Writer: ends when the platform side drops the input sender.
        {
            let master = master.clone();
            let closed = closed.clone();
            std::thread::spawn(move || {
                let mut file = File::from(master.as_fd().try_clone_to_owned().expect("dup pty"));
                drop(master);
                while let Some(data) = in_rx.blocking_recv() {
                    if file.write_all(&data).is_err() {
                        break;
                    }
                }
                closed.store(true, Ordering::Relaxed);
            });
        }
        let resize_fd: OwnedFd = master.as_fd().try_clone_to_owned()?;
        drop(master);
        tokio::spawn(async move {
            while let Some(size) = resize_rx.recv().await {
                let ws = winsize(size);
                unsafe { libc::ioctl(resize_fd.as_raw_fd(), libc::TIOCSWINSZ, &ws) };
            }
        });
        Ok(ConsoleIo {
            output: out_rx,
            input: in_tx,
            resize: resize_tx,
        })
    }
}

fn winsize(s: ConsoleSize) -> libc::winsize {
    libc::winsize {
        ws_row: s.rows,
        ws_col: s.cols,
        ws_xpixel: 0,
        ws_ypixel: 0,
    }
}
