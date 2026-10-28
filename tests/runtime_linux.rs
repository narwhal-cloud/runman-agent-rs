//! End-to-end runtime test on a real host. Needs root, systemd, network for
//! the first image download, and is therefore ignored by default:
//!
//! ```sh
//! sudo cargo test --release --test runtime_linux -- --ignored --nocapture --test-threads=1
//! ```
#![cfg(target_os = "linux")]

use std::path::Path;
use std::time::{Duration, Instant};

use runman_agent::backend::{Instances, PortForwards};
use runman_agent::config::{DEFAULT_IMAGE_BASE_URL, NetworkConfig};
use runman_agent::model::{ConsoleSize, InstanceSpec, L4Proto, PortForward, VmId};
use runman_agent::proto::VmStatus;
use runman_agent::runtime::{Options, Runtime};

const DATA: &str = "/var/lib/runman-agent-test";

fn spec(id: &VmId, image: &str, password: &str) -> InstanceSpec {
    InstanceSpec {
        vm_id: id.clone(),
        cpu: 1,
        ram_mb: 512,
        disk_gb: 3,
        bandwidth_mbps: 10,
        os_image: image.into(),
        root_password: password.into(),
    }
}

async fn status(rt: &Runtime, id: &VmId) -> Option<VmStatus> {
    vms(rt)
        .await
        .into_iter()
        .find(|s| s.vm_id == id.as_str())
        .map(|s| VmStatus::try_from(s.status).unwrap())
}

/// Run `cmd` in the instance's console and return the text printed between markers.
async fn console_run(rt: &Runtime, id: &VmId, cmd: &str) -> String {
    let mut io = rt
        .open_console(id, ConsoleSize::new(200, 50))
        .await
        .expect("open console");
    let line = format!("echo __B__; {cmd}; echo; echo __E__\n");
    io.input.send(line.into_bytes()).await.unwrap();
    let mut out = String::new();
    let deadline = Instant::now() + Duration::from_secs(20);
    while Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(1), io.output.recv()).await {
            Ok(Some(chunk)) => out.push_str(&String::from_utf8_lossy(&chunk)),
            Ok(None) => break,
            Err(_) => {}
        }
        // The echoed command line also contains the markers; take the lines
        // between a line that is exactly "__B__" and one that is "__E__".
        let clean = strip_ansi(&out).replace('\r', "\n");
        let lines: Vec<&str> = clean.lines().collect();
        if let Some(b) = lines.iter().rposition(|l| *l == "__B__")
            && let Some(e) = lines[b..].iter().position(|l| *l == "__E__")
        {
            return lines[b + 1..b + e]
                .iter()
                .filter(|l| !l.is_empty())
                .copied()
                .collect::<Vec<_>>()
                .join("\n");
        }
    }
    panic!("console command {cmd:?} produced no result; got {out:?}");
}

fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            if chars.peek() == Some(&'[') {
                chars.next();
                for c in chars.by_ref() {
                    if c.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}

async fn wait_for(rt: &Runtime, id: &VmId, cmd: &str, want: impl Fn(&str) -> bool) -> String {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let got = console_run(rt, id, cmd).await;
        if want(&got) || Instant::now() > deadline {
            return got;
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

fn mounts_mentioning(id: &VmId) -> usize {
    std::fs::read_to_string("/proc/self/mountinfo")
        .unwrap()
        .lines()
        .filter(|l| l.contains(id.as_str()))
        .count()
}

#[tokio::test]
#[ignore = "needs root, systemd and network"]
async fn instance_lifecycle() {
    let rt = Runtime::new(Options {
        data_dir: DATA.into(),
        image_base_url: image_url(),
        tun: true,
        network: NetworkConfig {
            bridge: "rmtest0".into(),
            ipv4_subnet: "10.93.0.0/20".into(),
            veth_prefix: "tv".into(),
            wg_prefix: "tw".into(),
            nft_table: "runman_t".into(),
            wg_table_base: 21000,
            ..Default::default()
        },
        traffic: runman_agent::traffic::Schedule {
            mode: runman_agent::traffic::ResetMode::Fixed,
            reset_day: 1,
            utc_offset_min: 0,
        },
    })
    .unwrap()
    .with_helper(env!("CARGO_BIN_EXE_runman-agent").into());
    rt.init().await.expect("init");
    rt.refresh_images().await;
    let images: Vec<String> = rt.images().ready().into_iter().map(|i| i.id).collect();
    assert!(images.contains(&"debian".to_string()), "{images:?}");
    assert!(images.contains(&"alpine".to_string()), "{images:?}");

    // Remove leftovers of earlier failed runs.
    for s in vms(&rt).await {
        rt.delete(&VmId::parse(&s.vm_id).unwrap()).await.unwrap();
    }

    let id = VmId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();

    // Create must fit in the platform's 30 s command timeout.
    let t = Instant::now();
    rt.create(&spec(&id, "debian", "First-pass1"))
        .await
        .expect("create");
    let took = t.elapsed();
    println!("create took {took:?}");
    assert!(took < Duration::from_secs(10), "create took {took:?}");
    assert_eq!(status(&rt, &id).await, Some(VmStatus::Running));

    let hostname = console_run(&rt, &id, "hostname").await;
    assert_eq!(hostname, format!("vps-{}", &id.as_str()[..8]));
    assert_eq!(console_run(&rt, &id, "id -u").await, "0");
    let ssh = wait_for(&rt, &id, "systemctl is-active ssh", |s| s == "active").await;
    assert_eq!(ssh, "active", "sshd should run with per-instance host keys");
    let failed = console_run(&rt, &id, "systemctl --failed --no-legend --plain | wc -l").await;
    println!("failed units: {failed}");
    let df = console_run(&rt, &id, "df -BG --output=size / | tail -1").await;
    assert_eq!(df.trim(), "3G");

    // lxcfs: the instance sees its own memory, CPUs and uptime.
    let mem: u64 = console_run(&rt, &id, "free -m | awk '/^Mem:/ {print $2}'")
        .await
        .parse()
        .unwrap();
    assert!(
        (400..=600).contains(&mem),
        "free shows {mem} MB, plan has 512"
    );
    // /proc/cpuinfo follows the CPU quota (`nproc` reports the scheduler
    // affinity instead, which only CPU pinning would change).
    assert_eq!(
        console_run(&rt, &id, "grep -c ^processor /proc/cpuinfo").await,
        "1"
    );
    let up: u64 = console_run(&rt, &id, "cut -d. -f1 /proc/uptime")
        .await
        .parse()
        .unwrap();
    assert!(up < 600, "uptime {up}s is the host's, not the instance's");
    // Host details are masked; init and console sessions are filtered.
    assert_eq!(console_run(&rt, &id, "wc -c < /proc/timer_list").await, "0");
    assert_eq!(
        console_run(&rt, &id, "awk '/^Seccomp:/ {print $2}' /proc/1/status").await,
        "2"
    );
    assert_eq!(
        console_run(&rt, &id, "awk '/^Seccomp:/ {print $2}' /proc/self/status").await,
        "2"
    );

    network_checks(&rt, &id).await;

    // Online password reset: verify the hash changed.
    let before = console_run(&rt, &id, "grep ^root: /etc/shadow | cut -d: -f2").await;
    rt.reset_password(&id, "Second-pass2")
        .await
        .expect("online reset");
    let after = console_run(&rt, &id, "grep ^root: /etc/shadow | cut -d: -f2").await;
    assert_ne!(before, after);
    assert!(
        sha_crypt::sha512_check("Second-pass2", &after).is_ok(),
        "{after}"
    );

    rt.restart(&id).await.expect("restart");
    assert_eq!(status(&rt, &id).await, Some(VmStatus::Running));

    let t = Instant::now();
    rt.stop(&id, false).await.expect("stop");
    println!("graceful stop took {:?}", t.elapsed());
    assert_eq!(status(&rt, &id).await, Some(VmStatus::Stopped));
    assert_eq!(mounts_mentioning(&id), 0, "mounts left after stop");
    let log = std::fs::read_to_string(
        Path::new(DATA)
            .join("instances")
            .join(id.as_str())
            .join("console.log"),
    )
    .unwrap();
    let tail: String = log.lines().rev().take(3).collect::<Vec<_>>().join(" | ");
    assert!(
        tail.contains("Powering off"),
        "stop must power off cleanly, console ends with: {tail}"
    );

    // Offline password reset, then boot and check it.
    rt.reset_password(&id, "Third-pass3")
        .await
        .expect("offline reset");
    rt.start(&id).await.expect("start");
    let hash = console_run(&rt, &id, "grep ^root: /etc/shadow | cut -d: -f2").await;
    assert!(
        sha_crypt::sha512_check("Third-pass3", &hash).is_ok(),
        "{hash}"
    );

    // Reinstall onto another distribution.
    rt.reinstall(&spec(&id, "alpine", "Alpine-pass4"))
        .await
        .expect("reinstall");
    let os = console_run(&rt, &id, "grep ^ID= /etc/os-release").await;
    assert_eq!(os, "ID=alpine");
    let sshd = wait_for(&rt, &id, "rc-service sshd status", |s| {
        s.contains("started")
    })
    .await;
    assert!(sshd.contains("started"), "{sshd}");

    let t = Instant::now();
    rt.stop(&id, false).await.expect("stop alpine");
    println!("alpine graceful stop took {:?}", t.elapsed());

    rt.delete(&id).await.expect("delete");
    assert_eq!(status(&rt, &id).await, None);
    assert!(!Path::new(DATA).join("instances").join(id.as_str()).exists());
    assert_eq!(mounts_mentioning(&id), 0);
    // Deleting again is a no-op.
    rt.delete(&id).await.expect("idempotent delete");
}

fn host_ip() -> String {
    let out = std::process::Command::new("ip")
        .args(["-4", "route", "get", "1.1.1.1"])
        .output()
        .unwrap();
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let mut words = text.split_whitespace();
    while let Some(w) = words.next() {
        if w == "src" {
            return words.next().unwrap().to_owned();
        }
    }
    panic!("no source address in {text}");
}

fn ssh_banner(addr: &str) -> String {
    use std::io::Read;
    let mut s =
        std::net::TcpStream::connect_timeout(&addr.parse().unwrap(), Duration::from_secs(3))
            .expect("connect forward");
    s.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
    let mut buf = [0u8; 7];
    s.read_exact(&mut buf).expect("read banner");
    String::from_utf8_lossy(&buf).into_owned()
}

async fn network_checks(rt: &Runtime, id: &VmId) {
    let ip = console_run(rt, id, "ip -4 -o addr show dev eth0 | awk '{print $4}'").await;
    assert!(ip.starts_with("10.93.0.") && ip.ends_with("/20"), "{ip}");
    let ip = ip.trim_end_matches("/20").to_owned();
    let summary = vms(rt)
        .await
        .into_iter()
        .find(|s| s.vm_id == id.as_str())
        .unwrap();
    assert_eq!(summary.ips, vec![ip.clone()]);
    let web = wait_for(
        rt,
        id,
        "curl -sS -o /dev/null -w '%{http_code}' https://www.cloudflare.com/",
        |s| s == "200",
    )
    .await;
    assert_eq!(web, "200", "outbound HTTPS with DNS");

    // Port forward from the host's address to the instance's sshd.
    let port = rt.free_port().await.unwrap();
    rt.add(PortForward {
        vm_id: id.clone(),
        proto: L4Proto::Tcp,
        host_port: port,
        guest_port: 22,
        description: "ssh".into(),
    })
    .await
    .expect("add forward");
    let host = host_ip();
    assert_eq!(ssh_banner(&format!("{host}:{port}")), "SSH-2.0");
    // An agent restart re-applies the ruleset without disturbing anything.
    rt.init().await.expect("re-init");
    assert_eq!(ssh_banner(&format!("{host}:{port}")), "SSH-2.0");

    // A host with Docker (or ufw) drops forwarded traffic by policy.
    let has_iptables = std::process::Command::new("iptables")
        .arg("-V")
        .output()
        .is_ok_and(|o| o.status.success());
    if has_iptables {
        let ipt = |args: &[&str]| {
            std::process::Command::new("iptables")
                .args(args)
                .status()
                .unwrap()
                .success()
        };
        assert!(ipt(&["-P", "FORWARD", "DROP"]));
        rt.heal().await;
        let web = wait_for(
            rt,
            id,
            "curl -sS -o /dev/null -w '%{http_code}' https://www.cloudflare.com/",
            |s| s == "200",
        )
        .await;
        assert!(ipt(&["-P", "FORWARD", "ACCEPT"]));
        assert_eq!(
            web, "200",
            "outbound must survive an iptables FORWARD DROP policy"
        );
    }

    // Self-healing: another tool deletes the instance's veth and our tables.
    let sh = |cmd: &str| {
        assert!(
            std::process::Command::new("sh")
                .args(["-c", cmd])
                .status()
                .unwrap()
                .success(),
            "{cmd}"
        );
    };
    sh("ip link del tv0");
    sh("nft delete table inet runman_t && nft delete table bridge runman_t");
    assert!(
        std::net::TcpStream::connect_timeout(
            &format!("{host}:{port}").parse().unwrap(),
            Duration::from_secs(2)
        )
        .is_err()
    );
    rt.heal().await;
    assert_eq!(
        ssh_banner(&format!("{host}:{port}")),
        "SSH-2.0",
        "forward restored"
    );
    let web = wait_for(
        rt,
        id,
        "curl -sS -o /dev/null -w '%{http_code}' https://www.cloudflare.com/",
        |s| s == "200",
    )
    .await;
    assert_eq!(web, "200", "outbound restored after heal");
    assert!(
        rt.add(PortForward {
            vm_id: id.clone(),
            proto: L4Proto::Tcp,
            host_port: 22,
            guest_port: 22,
            description: String::new()
        })
        .await
        .is_err(),
        "must refuse to hijack the host's sshd"
    );

    // Host services on the bridge are closed; spoofed sources are dropped.
    let host_ssh = console_run(
        rt,
        id,
        "timeout 3 bash -c 'echo > /dev/tcp/10.93.0.1/22' && echo open || echo closed",
    )
    .await;
    assert_eq!(host_ssh, "closed");
    let spoof = console_run(
        rt,
        id,
        "ip addr add 10.93.0.200/20 dev eth0; ping -c1 -W2 -I 10.93.0.200 1.1.1.1 >/dev/null && echo leak || echo dropped; ip addr del 10.93.0.200/20 dev eth0",
    )
    .await;
    assert_eq!(spoof, "dropped");

    // A second instance cannot reach the first directly, only via a forward.
    let other = VmId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    rt.create(&spec(&other, "alpine", "Other-pass1"))
        .await
        .expect("create second");
    let direct = wait_for(
        rt,
        &other,
        &format!("ping -c1 -W2 {ip} >/dev/null && echo reach || echo blocked"),
        |s| s == "blocked" || s == "reach",
    )
    .await;
    assert_eq!(direct, "blocked");
    let hairpin = console_run(
        rt,
        &other,
        &format!("nc -w 3 {host} {port} </dev/null | head -c 7"),
    )
    .await;
    assert_eq!(hairpin, "SSH-2.0");
    rt.delete(&other).await.unwrap();

    // 20 Mbit/s limit and traffic accounting.
    let speed = console_run(rt, id, "curl -sS -o /dev/null -w '%{speed_download}' 'https://speed.cloudflare.com/__down?bytes=10000000'").await;
    let bps: f64 = speed.parse().unwrap_or(0.0);
    println!(
        "download with 10 Mbit/s limit: {:.1} Mbit/s",
        bps * 8.0 / 1e6
    );
    // The lower bound only catches a collapse (as with policing); the real
    // throughput depends on this host's internet link.
    assert!(bps * 8.0 > 4e6 && bps * 8.0 < 12e6, "{speed}");
    let up = console_run(rt, id, "head -c 8000000 /dev/urandom > /tmp/up.bin; curl -sS -o /dev/null -w '%{speed_upload}' --data-binary @/tmp/up.bin https://speed.cloudflare.com/__up").await;
    let up_bps: f64 = up.parse().unwrap_or(0.0);
    println!(
        "upload with 10 Mbit/s limit: {:.1} Mbit/s",
        up_bps * 8.0 / 1e6
    );
    // The lower bound only catches a collapse (as with policing); the real
    // throughput depends on this host's internet link.
    assert!(up_bps * 8.0 > 4e6 && up_bps * 8.0 < 12e6, "{up}");
    rt.sample_traffic().await;
    let s = vms(rt)
        .await
        .into_iter()
        .find(|s| s.vm_id == id.as_str())
        .unwrap();
    println!(
        "traffic in={} out={}",
        s.traffic_in_bytes, s.traffic_out_bytes
    );
    assert!(
        s.traffic_in_bytes > 10_000_000 && s.monthly_traffic_in == s.traffic_in_bytes,
        "{s:?}"
    );

    // TUN inside the instance.
    let tun = console_run(
        rt,
        id,
        "ip tuntap add mode tun dev tun9 && ip link show tun9 >/dev/null && echo ok",
    )
    .await;
    assert_eq!(tun, "ok");

    rt.remove_all(id).await.unwrap();
    assert!(rt.list_forwards(id).await.is_empty());
}

trait ListForwards {
    async fn list_forwards(&self, id: &VmId) -> Vec<PortForward>;
}

impl ListForwards for Runtime {
    async fn list_forwards(&self, id: &VmId) -> Vec<PortForward> {
        PortForwards::list(self, Some(id)).await.unwrap()
    }
}

async fn vms(rt: &Runtime) -> Vec<runman_agent::proto::VmSummary> {
    Instances::list(rt).await.unwrap_or_default()
}

/// A runtime with its own data dir and bridge, sharing the image cache.
async fn side_runtime(name: &str, network: NetworkConfig) -> Runtime {
    let data = format!("/var/lib/runman-agent-{name}");
    std::fs::create_dir_all(&data).unwrap();
    std::fs::create_dir_all(Path::new(DATA).join("images")).unwrap();
    let images = Path::new(&data).join("images");
    if !images.exists() {
        std::os::unix::fs::symlink(Path::new(DATA).join("images"), &images).unwrap();
    }
    let rt = Runtime::new(Options {
        data_dir: data.into(),
        image_base_url: image_url(),
        tun: true,
        network,
        traffic: runman_agent::traffic::Schedule {
            mode: runman_agent::traffic::ResetMode::Fixed,
            reset_day: 1,
            utc_offset_min: 0,
        },
    })
    .unwrap()
    .with_helper(env!("CARGO_BIN_EXE_runman-agent").into());
    rt.init().await.expect("init");
    for s in vms(&rt).await {
        rt.delete(&VmId::parse(&s.vm_id).unwrap()).await.unwrap();
    }
    rt.refresh_images().await;
    rt
}

/// Public IPv6 from an on-link /64 (NDP proxied). Set
/// `RUNMAN_TEST_V6_PREFIX=2001:db8:1:2::/64` and `RUNMAN_TEST_V6_UPLINK=eth0`.
#[tokio::test]
#[ignore = "needs root, systemd and a public IPv6 /64"]
async fn ipv6_subnet_mode() {
    let (Ok(prefix), Ok(uplink)) = (
        std::env::var("RUNMAN_TEST_V6_PREFIX"),
        std::env::var("RUNMAN_TEST_V6_UPLINK"),
    ) else {
        println!("RUNMAN_TEST_V6_PREFIX / RUNMAN_TEST_V6_UPLINK not set; skipping");
        return;
    };
    let rt = side_runtime(
        "test6s",
        NetworkConfig {
            bridge: "rmtest6s".into(),
            ipv4_subnet: "10.95.0.0/20".into(),
            veth_prefix: "uv".into(),
            wg_prefix: "uw".into(),
            nft_table: "runman_u".into(),
            wg_table_base: 23000,
            ipv6_mode: "subnet".into(),
            ipv6_prefix: prefix,
            ipv6_ndp_uplink: uplink,
            ..Default::default()
        },
    )
    .await;
    let id = VmId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    rt.create(&spec(&id, "debian", "Pub6-pass1"))
        .await
        .expect("create");
    let summary = vms(&rt)
        .await
        .into_iter()
        .find(|s| s.vm_id == id.as_str())
        .unwrap();
    let addr = summary.ips[1].clone();
    println!("instance IPv6: {addr}");
    // The instance's own public address must be its source: no NAT, and the
    // upstream router reached it through the host's NDP proxy.
    let seen = wait_for(
        &rt,
        &id,
        "curl -6 -sS --max-time 8 https://api64.ipify.org",
        |s| s.parse::<std::net::Ipv6Addr>().is_ok(),
    )
    .await;
    assert_eq!(seen, addr, "outbound IPv6 must use the instance address");
    let v4 = console_run(&rt, &id, "curl -4 -sS --max-time 8 https://api.ipify.org").await;
    println!("instance IPv4 (NAT): {v4}");
    assert!(v4.split('.').count() == 4, "{v4}");
    // Keep the instance up for external (inbound) checks.
    if let Some(secs) = std::env::var("RUNMAN_TEST_HOLD_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
    {
        println!("holding instance for {secs}s");
        tokio::time::sleep(Duration::from_secs(secs)).await;
    }
    rt.delete(&id).await.unwrap();
    // The instance's host route and NDP proxy entry go away with it.
    let out = |args: &[&str]| {
        String::from_utf8(
            std::process::Command::new("ip")
                .args(args)
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
    };
    assert!(
        !out(&["-6", "route", "show", "dev", "rmtest6s"]).contains(addr.as_str()),
        "stale host route"
    );
    assert!(
        !out(&["-6", "neigh", "show", "proxy"]).contains(addr.as_str()),
        "stale NDP proxy entry"
    );
}

#[tokio::test]
#[ignore = "needs root, systemd and network"]
async fn ipv6_snat_mode() {
    let rt = side_runtime(
        "test6",
        NetworkConfig {
            bridge: "rmtest6".into(),
            ipv4_subnet: "10.94.0.0/20".into(),
            veth_prefix: "sv".into(),
            wg_prefix: "sw".into(),
            nft_table: "runman_s".into(),
            wg_table_base: 22000,
            ipv6_mode: "snat".into(),
            ..Default::default()
        },
    )
    .await;

    let id = VmId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    rt.create(&spec(&id, "debian", "Six-pass1"))
        .await
        .expect("create");
    let summary = vms(&rt)
        .await
        .into_iter()
        .find(|s| s.vm_id == id.as_str())
        .unwrap();
    assert_eq!(summary.ips.len(), 2, "{:?}", summary.ips);
    assert!(
        summary.ips[1].starts_with("fd91:cafe:cafe:10::"),
        "{:?}",
        summary.ips
    );
    let v6 = wait_for(
        &rt,
        &id,
        "ip -6 -o addr show dev eth0 scope global | awk '{print $4}'",
        |s| s.contains("fd91"),
    )
    .await;
    assert_eq!(v6, format!("{}/128", summary.ips[1]));
    let gw = wait_for(
        &rt,
        &id,
        "ping -6 -c1 -W2 fe80::1%eth0 >/dev/null && echo ok || echo no",
        |s| s == "ok",
    )
    .await;
    assert_eq!(gw, "ok");
    let route = console_run(&rt, &id, "ip -6 route show default").await;
    assert!(route.contains("via fe80::1"), "{route}");
    rt.delete(&id).await.unwrap();
}

/// Parse a wg-quick style config into the platform's binding message.
fn binding_from_conf(path: &str, vm: &VmId, resource: &str) -> runman_agent::proto::WgBindDesired {
    let text = std::fs::read_to_string(path).unwrap();
    let get = |key: &str| {
        text.lines()
            .find_map(|l| {
                let (k, v) = l.split_once('=')?;
                (k.trim() == key).then(|| v.trim().to_owned())
            })
            .unwrap_or_default()
    };
    runman_agent::proto::WgBindDesired {
        vm_id: vm.to_string(),
        resource_id: resource.into(),
        private_key: get("PrivateKey"),
        address: get("Address"),
        peer_public_key: get("PublicKey"),
        preshared_key: get("PresharedKey"),
        endpoint: get("Endpoint"),
        allowed_ips: vec![get("AllowedIPs")],
        keepalive_sec: get("PersistentKeepalive").parse().unwrap_or(25),
    }
}

/// Dedicated IPs over kernel WireGuard. Set `RUNMAN_TEST_WG_CONFS` to a
/// comma-separated list of wg-quick configs (one dedicated address each).
#[tokio::test]
#[ignore = "needs root, systemd, wireguard-tools and real tunnel configs"]
async fn wireguard_dedicated_ips() {
    use runman_agent::backend::WgBindings;
    let Ok(confs) = std::env::var("RUNMAN_TEST_WG_CONFS") else {
        println!("RUNMAN_TEST_WG_CONFS not set; skipping");
        return;
    };
    let rt = side_runtime(
        "testwg",
        NetworkConfig {
            bridge: "rmtestwg".into(),
            ipv4_subnet: "10.96.0.0/20".into(),
            veth_prefix: "wv".into(),
            wg_prefix: "ww".into(),
            nft_table: "runman_w".into(),
            wg_table_base: 24000,
            ..Default::default()
        },
    )
    .await;
    WgBindings::reconcile(&rt, vec![]).await.unwrap();
    let id = VmId::parse(&uuid::Uuid::new_v4().to_string()).unwrap();
    rt.create(&spec(&id, "debian", "Wg-pass1"))
        .await
        .expect("create");
    let host_v4 = wait_for(
        &rt,
        &id,
        "curl -4 -sS --max-time 8 https://api.ipify.org",
        |s| s.parse::<std::net::Ipv4Addr>().is_ok(),
    )
    .await;
    println!("before binding, instance leaves as {host_v4}");

    let desired: Vec<_> = confs
        .split(',')
        .enumerate()
        .map(|(i, p)| binding_from_conf(p, &id, &format!("test-res-{i}")))
        .collect();
    let addrs: Vec<String> = desired
        .iter()
        .map(|d| d.address.split('/').next().unwrap().to_owned())
        .collect();
    WgBindings::reconcile(&rt, desired.clone())
        .await
        .expect("bind");
    // Second round with the same input must be a no-op (no tunnel reset).
    WgBindings::reconcile(&rt, desired.clone())
        .await
        .expect("rebind");

    let shown = console_run(&rt, &id, "ip -o addr show dev eth0 | awk '{print $4}'").await;
    for a in &addrs {
        assert!(shown.contains(a.as_str()), "{a} not on eth0: {shown}");
    }
    for a in &addrs {
        let (flag, url) = if a.contains(':') {
            ("-6", "https://api64.ipify.org")
        } else {
            ("-4", "https://api.ipify.org")
        };
        let seen = wait_for(
            &rt,
            &id,
            &format!("curl {flag} -sS --max-time 8 {url}"),
            |s| s == a,
        )
        .await;
        println!("outbound {flag}: {seen}");
        assert_eq!(&seen, a, "outbound must leave from the dedicated address");
    }
    // Services can bind the dedicated address itself.
    let v4 = addrs
        .iter()
        .find(|a| !a.contains(':'))
        .cloned()
        .unwrap_or_else(|| "0.0.0.0".into());
    let listen = console_run(&rt, &id, &format!("sh -c 'nc -l -s {v4} -p 8080 >/dev/null 2>&1 & p=$!; sleep 1; kill $p 2>/dev/null && echo bound || echo failed'")).await;
    assert_eq!(listen, "bound");

    if let Some(secs) = std::env::var("RUNMAN_TEST_HOLD_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
    {
        println!("holding instance for {secs}s");
        tokio::time::sleep(Duration::from_secs(secs)).await;
    }

    // A reinstalled system comes up with its dedicated addresses.
    rt.reinstall(&spec(&id, "alpine", "Wg-pass2"))
        .await
        .expect("reinstall");
    check_dedicated(&rt, &id, &addrs, "after reinstall").await;

    // Agent restart: keys are not persisted, so tunnels come back with the
    // next sync; the instance's own configuration stays as it is.
    drop(rt);
    for l in ["ww0", "ww1"] {
        let _ = std::process::Command::new("ip")
            .args(["link", "del", l])
            .status();
    }
    let rt = Runtime::new(Options {
        data_dir: "/var/lib/runman-agent-testwg".into(),
        image_base_url: image_url(),
        tun: true,
        network: NetworkConfig {
            bridge: "rmtestwg".into(),
            ipv4_subnet: "10.96.0.0/20".into(),
            veth_prefix: "wv".into(),
            wg_prefix: "ww".into(),
            nft_table: "runman_w".into(),
            wg_table_base: 24000,
            ..Default::default()
        },
        traffic: runman_agent::traffic::Schedule {
            mode: runman_agent::traffic::ResetMode::Fixed,
            reset_day: 1,
            utc_offset_min: 0,
        },
    })
    .unwrap()
    .with_helper(env!("CARGO_BIN_EXE_runman-agent").into());
    rt.init().await.expect("re-init");
    WgBindings::reconcile(&rt, desired.clone())
        .await
        .expect("bind after restart");
    check_dedicated(&rt, &id, &addrs, "after agent restart").await;

    // Unbinding returns the instance to the host's address.
    WgBindings::reconcile(&rt, vec![]).await.expect("unbind");
    let after = wait_for(
        &rt,
        &id,
        "curl -4 -sS --max-time 8 https://api.ipify.org",
        |s| s == host_v4,
    )
    .await;
    assert_eq!(after, host_v4);
    let shown = console_run(&rt, &id, "ip -o addr show dev eth0 | awk '{print $4}'").await;
    for a in &addrs {
        assert!(!shown.contains(a.as_str()), "{a} still on eth0: {shown}");
    }
    rt.delete(&id).await.unwrap();

    let links = String::from_utf8(
        std::process::Command::new("ip")
            .args(["-br", "link"])
            .output()
            .unwrap()
            .stdout,
    )
    .unwrap();
    assert!(!links.lines().any(|l| l.starts_with("ww")), "{links}");
    for fam in ["-4", "-6"] {
        let rules = String::from_utf8(
            std::process::Command::new("ip")
                .args([fam, "rule"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap();
        assert!(!rules.contains("lookup 24"), "{rules}");
    }
}

async fn check_dedicated(rt: &Runtime, id: &VmId, addrs: &[String], when: &str) {
    for a in addrs {
        let (flag, url) = if a.contains(':') {
            ("-6", "https://api64.ipify.org")
        } else {
            ("-4", "https://api.ipify.org")
        };
        let seen = wait_for(
            rt,
            id,
            &format!("curl {flag} -sS --max-time 8 {url}"),
            |s| s == a,
        )
        .await;
        println!("{when}: outbound {flag} {seen}");
        assert_eq!(&seen, a, "{when} ({flag})");
    }
}

/// The platform often provisions several instances at once.
#[tokio::test]
#[ignore = "needs root, systemd and network"]
async fn concurrent_creates_get_distinct_slots() {
    let rt = std::sync::Arc::new(
        side_runtime(
            "testcc",
            NetworkConfig {
                bridge: "rmtestcc".into(),
                ipv4_subnet: "10.97.0.0/20".into(),
                veth_prefix: "cv".into(),
                wg_prefix: "cw".into(),
                nft_table: "runman_c".into(),
                wg_table_base: 25000,
                ..Default::default()
            },
        )
        .await,
    );
    let ids: Vec<VmId> = (0..4)
        .map(|_| VmId::parse(&uuid::Uuid::new_v4().to_string()).unwrap())
        .collect();
    let tasks: Vec<_> = ids
        .iter()
        .enumerate()
        .map(|(n, id)| {
            let rt = rt.clone();
            let spec = spec(
                id,
                if n % 2 == 0 { "debian" } else { "alpine" },
                "Conc-pass-1",
            );
            tokio::spawn(async move { rt.create(&spec).await })
        })
        .collect();
    for t in tasks {
        t.await.unwrap().expect("concurrent create");
    }
    let list = vms(&rt).await;
    let mut ips: Vec<String> = list.iter().map(|s| s.ips[0].clone()).collect();
    ips.sort();
    ips.dedup();
    assert_eq!(
        ips.len(),
        4,
        "every instance needs its own address: {ips:?}"
    );
    for id in &ids {
        let out = wait_for(&rt, id, "ip -4 -o addr show dev eth0 | wc -l", |s| s == "1").await;
        assert_eq!(out, "1", "{id} lost its network");
        let web = wait_for(
            &rt,
            id,
            "wget -q -O /dev/null https://www.cloudflare.com/ && echo ok || echo fail",
            |s| s == "ok",
        )
        .await;
        assert_eq!(web, "ok", "{id} has no outbound access");
    }
    for id in &ids {
        rt.delete(id).await.unwrap();
    }
}

/// Image source for tests: `RUNMAN_TEST_IMAGE_URL` (e.g. a local build) or the
/// published images.
fn image_url() -> String {
    std::env::var("RUNMAN_TEST_IMAGE_URL").unwrap_or_else(|_| DEFAULT_IMAGE_BASE_URL.into())
}
