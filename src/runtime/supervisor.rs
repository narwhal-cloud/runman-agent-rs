//! `runman-agent __supervise <spec.json>`: runs as the main process of the
//! instance's transient systemd unit (`Delegate=yes`, `PrivateMounts=yes`).
//!
//! Strictly single-threaded and tokio-free: it forks between namespace steps.
//!
//! Process tree:
//! ```text
//! supervisor (host ns, cgroup <unit>/supervisor)
//!  └─ intermediate (container userns; owns new mnt/net/ipc/uts/cgroup ns)
//!      └─ init, PID 1 of the new pid ns (cgroup <unit>/ct = cgroupns root)
//! ```
//! Launch handshake over two pipes (tags written by the child side):
//! `U` userns created → parent writes id maps, idmapped layer mounts, moves
//! child into `ct` → `1`; `N` namespaces created → parent sets up networking →
//! `2`; `P<pid>` init forked → parent moves the intermediate out of `ct` → `3`
//! releases init to exec. `E<message>` reports a failure at any step.

use std::ffi::CString;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::{DirBuilderExt, symlink};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use nix::mount::{MsFlags, mount};
use nix::sched::{CloneFlags, unshare};
use nix::sys::signal::{SigSet, SigmaskHow, Signal, sigprocmask};
use nix::sys::signalfd::{SfdFlags, SignalFd};
use nix::sys::wait::{WaitPidFlag, WaitStatus, waitpid};
use nix::unistd::{ForkResult, Gid, Pid, Uid, fork, pipe2};

use super::spec::{ID_RANGE, RunSpec, parse_signal};
use super::sys;

const STOP_TIMEOUT: Duration = Duration::from_secs(45);
const CONSOLE_LOG_MAX: u64 = 1 << 20;
const TTY_GID: u32 = 5;

pub fn main(spec_path: &Path) -> ! {
    let code = match run(spec_path) {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("supervisor: {e:#}");
            1
        }
    };
    std::process::exit(code)
}

#[derive(Debug, PartialEq)]
enum Outcome {
    Reboot,
    Halted,
    Other(String),
}

fn run(spec_path: &Path) -> Result<()> {
    let spec: RunSpec = serde_json::from_slice(&fs::read(spec_path)?)
        .with_context(|| format!("parse {}", spec_path.display()))?;
    let stop_signal = parse_signal(&spec.stop_signal)?;

    let mut mask = SigSet::empty();
    for s in [Signal::SIGTERM, Signal::SIGINT, Signal::SIGCHLD] {
        mask.add(s);
    }
    sigprocmask(SigmaskHow::SIG_BLOCK, Some(&mask), None)?;
    let sfd = SignalFd::with_flags(&mask, SfdFlags::SFD_CLOEXEC | SfdFlags::SFD_NONBLOCK)?;

    fs::create_dir_all(&spec.run_dir)?;
    let cg = Cgroups::setup()?;
    mount_disk(&spec)?;

    let mut stop_requested = false;
    loop {
        let outcome = boot_once(&spec, &cg, &sfd, stop_signal, &mut stop_requested);
        let _ = fs::remove_file(spec.init_pid_file());
        cg.destroy_ct()?;
        if let Some(net) = &spec.net {
            super::attach::detach(net);
        }
        for p in [spec.mnt_lower(), spec.mnt_upper()] {
            sys::umount_if_mounted(&p)?;
        }
        match outcome? {
            Outcome::Reboot if !stop_requested => {
                eprintln!("supervisor: instance rebooted, starting again");
                continue;
            }
            Outcome::Other(why) if !stop_requested => eprintln!("supervisor: init ended: {why}"),
            _ => {}
        }
        break;
    }
    sys::umount_if_mounted(&spec.mnt_disk())?;
    Ok(())
}

fn mount_disk(spec: &RunSpec) -> Result<()> {
    let target = spec.mnt_disk();
    if sys::is_mountpoint(&target) {
        return Ok(());
    }
    let status = Command::new("mount")
        .args(["-t", "ext4", "-o", "loop,noatime,nodev"])
        .arg(spec.disk_image())
        .arg(&target)
        .status()?;
    if !status.success() {
        bail!("mount {} failed", spec.disk_image().display());
    }
    Ok(())
}

fn boot_once(
    spec: &RunSpec,
    cg: &Cgroups,
    sfd: &SignalFd,
    stop_signal: i32,
    stop_requested: &mut bool,
) -> Result<Outcome> {
    for p in [spec.mnt_lower(), spec.mnt_upper()] {
        sys::umount_if_mounted(&p)?;
    }
    let pty = nix::pty::openpty(None, None)?;
    for fd in [&pty.master, &pty.slave] {
        nix::fcntl::fcntl(
            fd,
            nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::FD_CLOEXEC),
        )?;
    }
    std::os::unix::fs::fchown(
        &pty.slave,
        Some(spec.uid_base),
        Some(spec.uid_base + TTY_GID),
    )?;
    let slave_path = nix::unistd::ttyname(&pty.slave)?;
    cg.create_ct(spec.uid_base)?;

    let (to_child_r, to_child_w) = pipe2(nix::fcntl::OFlag::O_CLOEXEC)?;
    let (from_child_r, from_child_w) = pipe2(nix::fcntl::OFlag::O_CLOEXEC)?;

    // SAFETY: the supervisor never starts threads, so the child may allocate.
    let child = match unsafe { fork()? } {
        ForkResult::Child => {
            drop((to_child_w, from_child_r, pty.master));
            intermediate(spec, to_child_r, from_child_w, &pty.slave, &slave_path)
        }
        ForkResult::Parent { child } => child,
    };
    drop((to_child_r, from_child_w, pty.slave));
    let mut tx = File::from(to_child_w);
    let mut rx = File::from(from_child_r);

    let launched = (|| -> Result<Pid> {
        expect_tag(&mut rx, b'U')?;
        let base = spec.uid_base;
        let map = format!("0 {base} {ID_RANGE}\n");
        fs::write(format!("/proc/{child}/uid_map"), &map).context("write uid_map")?;
        fs::write(format!("/proc/{child}/gid_map"), &map).context("write gid_map")?;
        let userns = File::open(format!("/proc/{child}/ns/user"))?;
        sys::idmapped_bind(&spec.lower, &spec.mnt_lower(), &userns).context("idmap image")?;
        sys::idmapped_bind(&spec.mnt_disk(), &spec.mnt_upper(), &userns).context("idmap disk")?;
        cg.move_to_ct(child)?;
        tx.write_all(b"1")?;

        expect_tag(&mut rx, b'N')?;
        if let Some(net) = &spec.net {
            super::attach::attach(net, child.as_raw()).context("attach network")?;
        }
        tx.write_all(b"2")?;

        expect_tag(&mut rx, b'P')?;
        let mut buf = [0u8; 4];
        rx.read_exact(&mut buf)?;
        let init = Pid::from_raw(i32::from_le_bytes(buf));
        cg.move_to_supervisor(child)?;
        tx.write_all(b"3")?;
        Ok(init)
    })();
    let init = match launched {
        Ok(pid) => pid,
        Err(e) => {
            let _ = nix::sys::signal::kill(child, Signal::SIGKILL);
            let _ = waitpid(child, None);
            return Err(e.context("launch container"));
        }
    };
    fs::write(spec.init_pid_file(), init.to_string())?;

    let mut log = ConsoleLog::open(spec.console_log())?;
    let mut master = Some(File::from(pty.master));
    let mut deadline: Option<Instant> = None;
    loop {
        let timeout_ms = deadline.map_or(-1, |d| {
            d.saturating_duration_since(Instant::now())
                .as_millis()
                .min(i32::MAX as u128) as i32
        });
        let mut fds = [
            libc::pollfd {
                fd: sfd.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            },
            libc::pollfd {
                fd: master.as_ref().map_or(-1, |m| m.as_raw_fd()),
                events: libc::POLLIN,
                revents: 0,
            },
        ];
        let n = unsafe { libc::poll(fds.as_mut_ptr(), 2, timeout_ms) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(err.into());
        }
        if fds[1].revents != 0
            && let Some(m) = master.as_mut()
        {
            let mut buf = [0u8; 4096];
            match m.read(&mut buf) {
                Ok(0) | Err(_) => master = None, // EIO once every slave fd closed
                Ok(n) => log.write(&buf[..n]),
            }
        }
        while let Some(info) = sfd.read_signal()? {
            match info.ssi_signo as i32 {
                libc::SIGTERM | libc::SIGINT if deadline.is_none() => {
                    *stop_requested = true;
                    unsafe { libc::kill(init.as_raw(), stop_signal) };
                    deadline = Some(Instant::now() + STOP_TIMEOUT);
                }
                libc::SIGCHLD => match waitpid(child, Some(WaitPidFlag::WNOHANG))? {
                    WaitStatus::Exited(_, code) => return Ok(outcome(code)),
                    WaitStatus::Signaled(_, sig, _) => {
                        return Ok(Outcome::Other(format!("intermediate killed by {sig}")));
                    }
                    _ => {}
                },
                _ => {}
            }
        }
        if deadline.is_some_and(|d| Instant::now() >= d) {
            eprintln!("supervisor: graceful stop timed out, killing instance");
            cg.kill_ct();
            deadline = None;
        }
    }
}

/// The intermediate exits with init's status: 128+signal when init was killed.
fn outcome(code: i32) -> Outcome {
    match code - 128 {
        libc::SIGHUP => Outcome::Reboot,
        libc::SIGINT => Outcome::Halted,
        _ if code == 0 => Outcome::Halted,
        sig if sig > 0 => Outcome::Other(format!("init killed by signal {sig}")),
        _ => Outcome::Other(format!("init exited with {code}")),
    }
}

fn expect_tag(rx: &mut File, want: u8) -> Result<()> {
    let mut tag = [0u8; 1];
    if rx.read(&mut tag)? == 0 {
        bail!("container setup process exited unexpectedly");
    }
    if tag[0] == b'E' {
        let mut msg = String::new();
        let _ = rx.read_to_string(&mut msg);
        bail!("container setup failed: {msg}");
    }
    if tag[0] != want {
        bail!(
            "protocol error: expected {:?}, got {:?}",
            want as char,
            tag[0] as char
        );
    }
    Ok(())
}

// ── child side ──────────────────────────────────────────────────────────────

fn intermediate(spec: &RunSpec, rx: OwnedFd, tx: OwnedFd, slave: &OwnedFd, slave_path: &Path) -> ! {
    let mut rx = File::from(rx);
    let mut tx = File::from(tx);
    let res = (|| -> Result<()> {
        unshare(CloneFlags::CLONE_NEWUSER).context("unshare user ns")?;
        tx.write_all(b"U")?;
        expect_go(&mut rx, b'1')?;

        nix::unistd::setresgid(Gid::from_raw(0), Gid::from_raw(0), Gid::from_raw(0))?;
        nix::unistd::setresuid(Uid::from_raw(0), Uid::from_raw(0), Uid::from_raw(0))?;
        nix::unistd::setgroups(&[])?;
        unshare(
            CloneFlags::CLONE_NEWNS
                | CloneFlags::CLONE_NEWNET
                | CloneFlags::CLONE_NEWIPC
                | CloneFlags::CLONE_NEWUTS
                | CloneFlags::CLONE_NEWCGROUP
                | CloneFlags::CLONE_NEWPID,
        )
        .context("unshare namespaces")?;
        tx.write_all(b"N")?;
        expect_go(&mut rx, b'2')?;

        mount(
            None::<&str>,
            "/",
            None::<&str>,
            MsFlags::MS_REC | MsFlags::MS_PRIVATE,
            None::<&str>,
        )?;
        let rootfs = spec.mnt_rootfs();
        let upper = spec.mnt_upper();
        let opts = format!(
            "lowerdir={},upperdir={},workdir={},userxattr",
            spec.mnt_lower().display(),
            upper.join("up").display(),
            upper.join("wk").display()
        );
        mount(
            Some("overlay"),
            &rootfs,
            Some("overlay"),
            MsFlags::empty(),
            Some(opts.as_str()),
        )
        .context("mount rootfs overlay")?;
        setup_dev(&rootfs, slave_path, spec.tun).context("populate /dev")?;
        nix::unistd::sethostname(&spec.hostname)?;

        // SAFETY: still single-threaded.
        match unsafe { fork()? } {
            ForkResult::Child => pid1(&rootfs, &mut rx, slave),
            ForkResult::Parent { child } => {
                tx.write_all(b"P")?;
                tx.write_all(&child.as_raw().to_le_bytes())?;
                let code = loop {
                    match waitpid(child, None) {
                        Ok(WaitStatus::Exited(_, c)) => break c,
                        Ok(WaitStatus::Signaled(_, s, _)) => break 128 + s as i32,
                        Ok(_) | Err(nix::errno::Errno::EINTR) => continue,
                        Err(_) => break 1,
                    }
                };
                unsafe { libc::_exit(code) }
            }
        }
    })();
    if let Err(e) = res {
        let _ = tx.write_all(format!("E{e:#}").as_bytes());
    }
    unsafe { libc::_exit(1) }
}

fn expect_go(rx: &mut File, want: u8) -> Result<()> {
    let mut b = [0u8; 1];
    rx.read_exact(&mut b).context("supervisor went away")?;
    if b[0] != want {
        bail!("unexpected go byte {:?}", b[0] as char);
    }
    Ok(())
}

fn setup_dev(rootfs: &Path, console: &Path, tun: bool) -> Result<()> {
    let dev = rootfs.join("dev");
    let nosuid_noexec = MsFlags::MS_NOSUID | MsFlags::MS_NOEXEC;
    mount(
        Some("tmpfs"),
        &dev,
        Some("tmpfs"),
        nosuid_noexec,
        Some("mode=755,size=65536k"),
    )?;
    let bind = |src: &Path, name: &str| -> Result<()> {
        let dst = dev.join(name);
        File::create(&dst)?;
        mount(
            Some(src),
            &dst,
            None::<&str>,
            MsFlags::MS_BIND,
            None::<&str>,
        )
        .with_context(|| format!("bind {}", src.display()))
    };
    for name in ["null", "zero", "full", "random", "urandom", "tty"] {
        bind(&Path::new("/dev").join(name), name)?;
    }
    if tun && Path::new("/dev/net/tun").exists() {
        fs::DirBuilder::new().mode(0o755).create(dev.join("net"))?;
        bind(Path::new("/dev/net/tun"), "net/tun")?;
    }
    bind(console, "console")?;

    let pts = dev.join("pts");
    fs::DirBuilder::new().mode(0o755).create(&pts)?;
    mount(
        Some("devpts"),
        &pts,
        Some("devpts"),
        nosuid_noexec,
        Some("newinstance,ptmxmode=0666,mode=0620,gid=5"),
    )?;
    symlink("pts/ptmx", dev.join("ptmx"))?;

    let shm = dev.join("shm");
    fs::DirBuilder::new().mode(0o1777).create(&shm)?;
    mount(
        Some("tmpfs"),
        &shm,
        Some("tmpfs"),
        nosuid_noexec | MsFlags::MS_NODEV,
        Some("mode=1777"),
    )?;
    let mq = dev.join("mqueue");
    fs::DirBuilder::new().mode(0o755).create(&mq)?;
    mount(
        Some("mqueue"),
        &mq,
        Some("mqueue"),
        nosuid_noexec | MsFlags::MS_NODEV,
        None::<&str>,
    )?;

    for (name, target) in [
        ("fd", "/proc/self/fd"),
        ("stdin", "/proc/self/fd/0"),
        ("stdout", "/proc/self/fd/1"),
        ("stderr", "/proc/self/fd/2"),
    ] {
        symlink(target, dev.join(name))?;
    }
    Ok(())
}

fn pid1(rootfs: &Path, rx: &mut File, console: &OwnedFd) -> ! {
    let res = (|| -> Result<()> {
        let hard = MsFlags::MS_NOSUID | MsFlags::MS_NODEV | MsFlags::MS_NOEXEC;
        mount(
            Some("proc"),
            &rootfs.join("proc"),
            Some("proc"),
            hard,
            None::<&str>,
        )
        .context("mount /proc")?;
        mount(
            Some("sysfs"),
            &rootfs.join("sys"),
            Some("sysfs"),
            hard | MsFlags::MS_RDONLY,
            None::<&str>,
        )
        .context("mount /sys")?;
        mount(
            Some("cgroup2"),
            &rootfs.join("sys/fs/cgroup"),
            Some("cgroup2"),
            hard,
            None::<&str>,
        )
        .context("mount cgroup2")?;
        nix::unistd::chdir(rootfs)?;
        sys::pivot_root_here().context("pivot_root")?;
        nix::unistd::chdir("/")?;

        // Wait until the supervisor moved the intermediate out of our cgroup,
        // so init owns an empty cgroup namespace root it can delegate.
        expect_go(rx, b'3')?;

        nix::unistd::setsid()?;
        for fd in 0..=2 {
            if unsafe { libc::dup2(console.as_raw_fd(), fd) } < 0 {
                return Err(std::io::Error::last_os_error().into());
            }
        }
        unsafe { libc::ioctl(0, libc::TIOCSCTTY, 0) };
        sigprocmask(SigmaskHow::SIG_SETMASK, Some(&SigSet::empty()), None)?;

        let init = CString::new("/sbin/init")?;
        let env = [
            CString::new("container=lxc")?,
            CString::new("TERM=linux")?,
            CString::new("PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")?,
        ];
        nix::unistd::execve(&init, std::slice::from_ref(&init), &env).context("exec /sbin/init")?;
        Ok(())
    })();
    if let Err(e) = res {
        eprintln!("container init setup failed: {e:#}");
    }
    unsafe { libc::_exit(1) }
}

// ── cgroups ─────────────────────────────────────────────────────────────────

struct Cgroups {
    unit: PathBuf,
}

impl Cgroups {
    /// Move ourselves into `<unit>/supervisor` and enable controllers so the
    /// sibling `ct` cgroup can carry the instance.
    fn setup() -> Result<Self> {
        let own = fs::read_to_string("/proc/self/cgroup")?;
        let rel = own
            .lines()
            .find_map(|l| l.strip_prefix("0::"))
            .ok_or_else(|| anyhow!("cgroup v2 required"))?;
        let rel = rel.trim().trim_end_matches("/supervisor");
        let unit = Path::new("/sys/fs/cgroup").join(rel.trim_start_matches('/'));
        let sup = unit.join("supervisor");
        if !sup.exists() {
            fs::create_dir(&sup)?;
        }
        fs::write(sup.join("cgroup.procs"), std::process::id().to_string())?;
        for ctl in ["+cpu", "+memory", "+pids", "+io"] {
            if let Err(e) = fs::write(unit.join("cgroup.subtree_control"), ctl) {
                eprintln!("supervisor: enable {ctl}: {e}");
            }
        }
        Ok(Self { unit })
    }

    fn ct(&self) -> PathBuf {
        self.unit.join("ct")
    }

    fn create_ct(&self, uid: u32) -> Result<()> {
        self.destroy_ct()?;
        let ct = self.ct();
        fs::create_dir(&ct)?;
        // Delegate the subtree to the container's root user.
        for f in [
            "",
            "cgroup.procs",
            "cgroup.threads",
            "cgroup.subtree_control",
        ] {
            std::os::unix::fs::chown(ct.join(f), Some(uid), Some(uid))?;
        }
        Ok(())
    }

    fn move_to_ct(&self, pid: Pid) -> Result<()> {
        fs::write(self.ct().join("cgroup.procs"), pid.to_string()).context("move into ct cgroup")
    }

    fn move_to_supervisor(&self, pid: Pid) -> Result<()> {
        fs::write(self.unit.join("supervisor/cgroup.procs"), pid.to_string())
            .context("move intermediate out of ct")
    }

    fn kill_ct(&self) {
        let _ = fs::write(self.ct().join("cgroup.kill"), "1");
    }

    fn destroy_ct(&self) -> Result<()> {
        let ct = self.ct();
        if !ct.exists() {
            return Ok(());
        }
        self.kill_ct();
        let deadline = Instant::now() + Duration::from_secs(10);
        while fs::read_to_string(ct.join("cgroup.events")).is_ok_and(|e| e.contains("populated 1"))
        {
            if Instant::now() > deadline {
                bail!("instance cgroup did not empty");
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        remove_cgroup_tree(&ct)
    }
}

fn remove_cgroup_tree(dir: &Path) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_dir() {
            remove_cgroup_tree(&entry.path())?;
        }
    }
    fs::remove_dir(dir).with_context(|| format!("rmdir {}", dir.display()))
}

// ── console log ─────────────────────────────────────────────────────────────

struct ConsoleLog {
    path: PathBuf,
    file: File,
}

impl ConsoleLog {
    fn open(path: PathBuf) -> Result<Self> {
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self { path, file })
    }

    fn write(&mut self, data: &[u8]) {
        if self
            .file
            .metadata()
            .is_ok_and(|m| m.len() > CONSOLE_LOG_MAX)
        {
            let _ = fs::rename(&self.path, self.path.with_extension("log.1"));
            if let Ok(f) = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&self.path)
            {
                self.file = f;
            }
        }
        let _ = self.file.write_all(data);
    }
}
