//! Host networking for instances.
//!
//! ```text
//! uplink ── (routing, nft NAT) ── rmbr0 10.91.0.1/20, fe80::1 ── rv<idx> ⇄ eth0 (instance)
//! ```
//! - Every instance gets a fixed IPv4 (and optionally IPv6) derived from its
//!   index; the address is written into the instance's own network config.
//! - Bridge ports are `isolated`: instances cannot reach each other at L2;
//!   the `bridge runman` table drops spoofed IP/ARP/IPv6 sources and router
//!   advertisements coming from instances.
//! - The `inet runman` table does NAT, port forwarding (maps rebuilt
//!   atomically from the agent's state) and blocks instances from host
//!   services on the bridge.
//! - The whole ruleset is regenerated and swapped in one `nft -f` transaction
//!   on every change; it never touches other tables.

use std::fmt::Write as _;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

use super::image::run;
use crate::config::NetworkConfig;
use crate::model::L4Proto;

const GATEWAY6_LL: Ipv6Addr = Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1);
const SNAT6_PREFIX: Ipv6Addr = Ipv6Addr::new(0xfd91, 0xcafe, 0xcafe, 0x10, 0, 0, 0, 0);
/// Instance IPv6 addresses start this far into the prefix, clear of the
/// host's own addresses (commonly ::1, ::2 or EUI-64 ones).
const V6_HOST_OFFSET: u128 = 0x1_0000;

#[derive(Debug, Clone, PartialEq)]
pub enum V6Mode {
    None,
    /// ULA addresses masqueraded behind the host's IPv6.
    Snat,
    /// Public addresses from `prefix`. With `ndp_uplink`, the prefix is
    /// on-link at the uplink and the host answers NDP for instance addresses;
    /// without it, the prefix is routed to the host.
    Subnet {
        prefix: Ipv6Addr,
        len: u8,
        ndp_uplink: Option<String>,
    },
}

#[derive(Debug, Clone)]
pub struct Net {
    pub bridge: String,
    veth_prefix: String,
    wg_prefix: String,
    table: String,
    v4_base: u32,
    v4_len: u8,
    pub v6: V6Mode,
    pub dns: Vec<String>,
}

/// Addresses assigned to one instance.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Addrs {
    pub ipv4: Ipv4Addr,
    pub ipv6: Option<Ipv6Addr>,
}

/// An instance's bridge port and the source addresses it may use.
pub struct Port {
    pub idx: u32,
    pub addrs: Addrs,
    /// Dedicated (WireGuard) addresses.
    pub extra: Vec<IpAddr>,
}

/// Port-forward rule resolved to its target address.
pub struct Forward {
    pub proto: L4Proto,
    pub host_port: u16,
    pub target: Ipv4Addr,
    pub guest_port: u16,
}

impl Net {
    pub fn from_config(c: &NetworkConfig) -> Result<Self> {
        let (v4, v4_len) = parse_cidr4(&c.ipv4_subnet)?;
        if !(8..=24).contains(&v4_len) {
            bail!("ipv4_subnet must be between /8 and /24");
        }
        if !valid_ifname(&c.bridge) {
            bail!("invalid bridge name {:?}", c.bridge);
        }
        let v6 = match c.ipv6_mode.as_str() {
            "none" | "" => V6Mode::None,
            "snat" => V6Mode::Snat,
            "subnet" => {
                let (prefix, len) = parse_cidr6(&c.ipv6_prefix).context("ipv6_prefix")?;
                if len > 96 {
                    bail!("ipv6_prefix must be /96 or larger");
                }
                let ndp_uplink = (!c.ipv6_ndp_uplink.is_empty()).then(|| c.ipv6_ndp_uplink.clone());
                if ndp_uplink.as_deref().is_some_and(|i| !valid_ifname(i)) {
                    bail!("invalid ipv6_ndp_uplink");
                }
                V6Mode::Subnet {
                    prefix,
                    len,
                    ndp_uplink,
                }
            }
            other => bail!("unknown ipv6_mode {other:?}"),
        };
        for d in &c.dns {
            d.parse::<std::net::IpAddr>()
                .with_context(|| format!("invalid dns server {d:?}"))?;
        }
        let short =
            |p: &str| (1..=4).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_lowercase());
        if !short(&c.veth_prefix) || !short(&c.wg_prefix) || c.veth_prefix == c.wg_prefix {
            bail!("veth_prefix/wg_prefix must be distinct 1-4 lowercase letters");
        }
        if c.nft_table.is_empty()
            || !c
                .nft_table
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
        {
            bail!("invalid nft_table");
        }
        Ok(Self {
            bridge: c.bridge.clone(),
            veth_prefix: c.veth_prefix.clone(),
            wg_prefix: c.wg_prefix.clone(),
            table: c.nft_table.clone(),
            v4_base: u32::from(v4) & mask4(v4_len),
            v4_len,
            v6,
            dns: c.dns.clone(),
        })
    }

    pub fn subnet4(&self) -> String {
        format!("{}/{}", Ipv4Addr::from(self.v4_base), self.v4_len)
    }

    pub fn v4_prefix_len(&self) -> u8 {
        self.v4_len
    }

    pub fn gateway4(&self) -> Ipv4Addr {
        Ipv4Addr::from(self.v4_base + 1)
    }

    pub fn gateway6(&self) -> Ipv6Addr {
        GATEWAY6_LL
    }

    /// Largest index that still has an IPv4 address (.0 network, .1 gateway,
    /// last = broadcast).
    pub fn max_idx(&self) -> u32 {
        (1u32 << (32 - self.v4_len)) - 4
    }

    pub fn addrs_for(&self, idx: u32) -> Result<Addrs> {
        if idx > self.max_idx() {
            bail!("no free address in {}", self.subnet4());
        }
        let ipv6 = match &self.v6 {
            V6Mode::None => None,
            V6Mode::Snat => Some(Ipv6Addr::from(
                u128::from(SNAT6_PREFIX) + 2 + u128::from(idx),
            )),
            V6Mode::Subnet { prefix, len, .. } => {
                let host = V6_HOST_OFFSET + u128::from(idx);
                if *len < 128 && host >> (128 - u32::from(*len)) != 0 {
                    bail!("IPv6 prefix too small");
                }
                Some(Ipv6Addr::from(u128::from(*prefix) | host))
            }
        };
        Ok(Addrs {
            ipv4: Ipv4Addr::from(self.v4_base + 2 + idx),
            ipv6,
        })
    }

    /// Bridge, addresses and sysctls. Idempotent.
    pub async fn setup_host(&self) -> Result<()> {
        let br = self.bridge.as_str();
        if !link_exists(br).await {
            run(Command::new("ip").args(["link", "add", br, "type", "bridge"])).await?;
        }
        let gw = format!("{}/{}", self.gateway4(), self.v4_len);
        run(Command::new("ip").args(["addr", "replace", &gw, "dev", br])).await?;
        if self.v6 == V6Mode::Snat {
            let ula = format!("{}/64", Ipv6Addr::from(u128::from(SNAT6_PREFIX) + 1));
            run(Command::new("ip").args(["-6", "addr", "replace", &ula, "dev", br])).await?;
        }
        run(Command::new("ip").args(["link", "set", br, "up"])).await?;

        sysctl("net.ipv4.ip_forward", "1").await?;
        if self.v6 != V6Mode::None {
            self.enable_v6().await?;
        }
        Ok(())
    }

    /// IPv6 routing on the bridge: gateway `fe80::1` and host forwarding.
    /// Also needed in `none` mode once an instance gets a dedicated IPv6.
    pub async fn enable_v6(&self) -> Result<()> {
        let br = self.bridge.as_str();
        sysctl(&format!("net.ipv6.conf.{br}.disable_ipv6"), "0").await?;
        run(Command::new("ip").args(["-6", "addr", "replace", "fe80::1/64", "dev", br])).await?;
        // Forwarding makes the kernel ignore RAs on every interface whose
        // accept_ra is 1; the host would lose its RA-learned default route
        // when it expires. Switch them to 2 *before* enabling forwarding.
        sysctl("net.ipv6.conf.default.accept_ra", "2").await?;
        sysctl("net.ipv6.conf.all.accept_ra", "2").await?;
        for iface in ra_interfaces() {
            sysctl(&format!("net.ipv6.conf.{iface}.accept_ra"), "2").await?;
        }
        if let V6Mode::Subnet {
            ndp_uplink: Some(up),
            ..
        } = &self.v6
        {
            sysctl(&format!("net.ipv6.conf.{up}.proxy_ndp"), "1").await?;
        }
        sysctl("net.ipv6.conf.all.forwarding", "1").await
    }

    /// Converge nftables, NDP proxy entries and IPv6 host routes.
    pub async fn apply(&self, instances: &[Port], forwards: &[Forward]) -> Result<()> {
        let rules = self.ruleset(instances, forwards);
        let mut child = Command::new("nft")
            .args(["-f", "-"])
            .stdin(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .context("run nft")?;
        child
            .stdin
            .take()
            .expect("piped")
            .write_all(rules.as_bytes())
            .await?;
        let out = child.wait_with_output().await?;
        if !out.status.success() {
            bail!(
                "nft rejected ruleset: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        self.allow_in_iptables_forward().await;
        if let V6Mode::Subnet {
            prefix,
            len,
            ndp_uplink,
        } = &self.v6
        {
            self.sync_v6_routes(instances, *prefix, *len, ndp_uplink.as_deref())
                .await?;
        }
        Ok(())
    }

    /// Docker (and ufw's default) set the iptables FORWARD policy to DROP.
    /// iptables-nft chains hook into forwarding next to our table, and a drop
    /// in any of them wins, which cuts every instance off. Accept the bridge's
    /// traffic at the top of FORWARD; isolation and anti-spoofing stay in our
    /// own tables. Re-checked on every apply (Docker re-inserts its jumps).
    async fn allow_in_iptables_forward(&self) {
        for tool in ["iptables", "ip6tables"] {
            for dir in ["-i", "-o"] {
                let rule = [
                    dir,
                    self.bridge.as_str(),
                    "-m",
                    "comment",
                    "--comment",
                    "runman",
                    "-j",
                    "ACCEPT",
                ];
                let present = Command::new(tool)
                    .args(["-w", "-C", "FORWARD"])
                    .args(rule)
                    .stderr(std::process::Stdio::null())
                    .status()
                    .await;
                match present {
                    Ok(s) if s.success() => {}
                    // 1 = rule missing; anything else (no iptables, no
                    // FORWARD chain) means there is nothing to work around.
                    Ok(s) if s.code() == Some(1) => {
                        if let Err(e) = run(Command::new(tool)
                            .args(["-w", "-I", "FORWARD", "1"])
                            .args(rule))
                        .await
                        {
                            tracing::warn!("{tool}: allow {} in FORWARD: {e:#}", self.bridge);
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    async fn sync_v6_routes(
        &self,
        instances: &[Port],
        prefix: Ipv6Addr,
        len: u8,
        uplink: Option<&str>,
    ) -> Result<()> {
        let want: Vec<Ipv6Addr> = instances.iter().filter_map(|p| p.addrs.ipv6).collect();
        let in_prefix = |a: &Ipv6Addr| {
            len == 0 || (u128::from(*a) ^ u128::from(prefix)) >> (128 - u32::from(len)) == 0
        };
        for a in &want {
            let dst = format!("{a}/128");
            run(Command::new("ip").args(["-6", "route", "replace", &dst, "dev", &self.bridge]))
                .await?;
            if let Some(up) = uplink {
                run(Command::new("ip").args([
                    "-6",
                    "neigh",
                    "replace",
                    "proxy",
                    &a.to_string(),
                    "dev",
                    up,
                ]))
                .await?;
            }
        }
        // Remove entries of deleted instances.
        let routes =
            output(Command::new("ip").args(["-6", "route", "show", "dev", &self.bridge])).await?;
        for line in routes.lines() {
            let Some(dst) = line.split_whitespace().next() else {
                continue;
            };
            if let Some(addr) = host_route(dst)
                && in_prefix(&addr)
                && !want.contains(&addr)
            {
                let dst = format!("{addr}/128");
                let _ =
                    run(Command::new("ip").args(["-6", "route", "del", &dst, "dev", &self.bridge]))
                        .await;
            }
        }
        if let Some(up) = uplink {
            let proxies =
                output(Command::new("ip").args(["-6", "neigh", "show", "proxy", "dev", up]))
                    .await?;
            for line in proxies.lines() {
                if let Some(addr) = line
                    .split_whitespace()
                    .next()
                    .and_then(|a| a.parse::<Ipv6Addr>().ok())
                    && in_prefix(&addr)
                    && !want.contains(&addr)
                {
                    let _ = run(Command::new("ip").args([
                        "-6",
                        "neigh",
                        "del",
                        "proxy",
                        &addr.to_string(),
                        "dev",
                        up,
                    ]))
                    .await;
                }
            }
        }
        Ok(())
    }

    pub fn ruleset(&self, instances: &[Port], forwards: &[Forward]) -> String {
        let br = &self.bridge;
        let sub4 = self.subnet4();
        let mut r = String::new();
        // `add` + `delete` + definition in one transaction: atomic replace,
        // and it works whether or not the table exists yet.
        for family in ["bridge", "inet"] {
            let _ = writeln!(
                r,
                "add table {family} {t}\ndelete table {family} {t}",
                t = self.table
            );
        }

        // ── L2: anti-spoofing and RA guard on instance ports ──
        let _ = writeln!(r, "table bridge {} {{", self.table);
        let _ = writeln!(
            r,
            "  set src4 {{ type ifname . ipv4_addr;{} }}",
            elements(instances.iter().flat_map(|p| {
                let ifc = self.host_if(p.idx);
                std::iter::once(p.addrs.ipv4)
                    .chain(p.extra.iter().filter_map(|a| match a {
                        IpAddr::V4(v4) => Some(*v4),
                        IpAddr::V6(_) => None,
                    }))
                    .map(move |a| format!("\"{ifc}\" . {a}"))
            }))
        );
        let _ = writeln!(
            r,
            "  set src6 {{ type ifname . ipv6_addr;{} }}",
            elements(instances.iter().flat_map(|p| {
                let ifc = self.host_if(p.idx);
                p.addrs
                    .ipv6
                    .into_iter()
                    .chain(p.extra.iter().filter_map(|a| match a {
                        IpAddr::V6(v6) => Some(*v6),
                        IpAddr::V4(_) => None,
                    }))
                    .map(move |a| format!("\"{ifc}\" . {a}"))
            }))
        );
        let _ = writeln!(
            r,
            "  chain guard {{\n    type filter hook prerouting priority -200; policy accept;"
        );
        let _ = writeln!(r, "    iifname != \"{}*\" accept", self.veth_prefix);
        let _ = writeln!(r, "    ether type ip iifname . ip saddr != @src4 drop");
        let _ = writeln!(r, "    ether type arp iifname . arp saddr ip != @src4 drop");
        let _ = writeln!(
            r,
            "    ether type ip6 icmpv6 type {{ nd-router-advert, nd-redirect }} drop"
        );
        let _ = writeln!(r, "    ether type ip6 ip6 saddr fe80::/10 accept");
        let _ = writeln!(r, "    ether type ip6 ip6 saddr :: accept");
        let _ = writeln!(r, "    ether type ip6 iifname . ip6 saddr != @src6 drop");
        let _ = writeln!(r, "  }}\n}}");

        // ── L3: NAT, port forwards, host protection ──
        let _ = writeln!(r, "table inet {} {{", self.table);
        for proto in [L4Proto::Tcp, L4Proto::Udp] {
            let elems = elements(
                forwards
                    .iter()
                    .filter(|f| f.proto == proto)
                    .map(|f| format!("{} : {} . {}", f.host_port, f.target, f.guest_port)),
            );
            let _ = writeln!(
                r,
                "  map fwd_{} {{ type inet_service : ipv4_addr . inet_service;{elems} }}",
                proto.as_str()
            );
        }
        let _ = writeln!(
            r,
            "  chain dstnat {{\n    type nat hook prerouting priority dstnat; policy accept;"
        );
        let _ = writeln!(
            r,
            "    fib daddr type local dnat ip to tcp dport map @fwd_tcp"
        );
        let _ = writeln!(
            r,
            "    fib daddr type local dnat ip to udp dport map @fwd_udp"
        );
        let _ = writeln!(r, "  }}");
        // Connections made by the host itself to its own public address.
        let _ = writeln!(
            r,
            "  chain outnat {{\n    type nat hook output priority -100; policy accept;"
        );
        let _ = writeln!(
            r,
            "    fib daddr type local dnat ip to tcp dport map @fwd_tcp"
        );
        let _ = writeln!(
            r,
            "    fib daddr type local dnat ip to udp dport map @fwd_udp"
        );
        let _ = writeln!(r, "  }}");
        let _ = writeln!(
            r,
            "  chain srcnat {{\n    type nat hook postrouting priority srcnat; policy accept;"
        );
        let _ = writeln!(r, "    ip saddr {sub4} ip daddr != {sub4} masquerade");
        // Hairpin: an instance reaching a forward via the host's public IP.
        let _ = writeln!(
            r,
            "    ip saddr {sub4} ip daddr {sub4} ct status dnat masquerade"
        );
        if self.v6 == V6Mode::Snat {
            let _ = writeln!(
                r,
                "    ip6 saddr {SNAT6_PREFIX}/64 ip6 daddr != {SNAT6_PREFIX}/64 masquerade"
            );
        }
        let _ = writeln!(r, "  }}");
        let _ = writeln!(
            r,
            "  chain input {{\n    type filter hook input priority filter; policy accept;"
        );
        let _ = writeln!(
            r,
            "    iifname \"{br}\" ct state established,related accept"
        );
        let _ = writeln!(
            r,
            "    iifname \"{br}\" meta l4proto {{ icmp, ipv6-icmp }} accept"
        );
        let _ = writeln!(r, "    iifname \"{br}\" drop");
        let _ = writeln!(r, "  }}");
        let _ = writeln!(
            r,
            "  chain forward {{\n    type filter hook forward priority filter; policy accept;"
        );
        // Instances talk to each other only through published forwards.
        let _ = writeln!(
            r,
            "    iifname \"{}*\" tcp flags syn tcp option maxseg size set rt mtu",
            self.wg_prefix
        );
        let _ = writeln!(
            r,
            "    oifname \"{}*\" tcp flags syn tcp option maxseg size set rt mtu",
            self.wg_prefix
        );
        let _ = writeln!(
            r,
            "    iifname \"{br}\" oifname \"{br}\" ct status dnat accept"
        );
        let _ = writeln!(r, "    iifname \"{br}\" oifname \"{br}\" drop");
        let _ = writeln!(r, "  }}\n}}");
        r
    }
}

impl Net {
    /// Host end of an instance's veth pair.
    pub fn host_if(&self, idx: u32) -> String {
        format!("{}{idx}", self.veth_prefix)
    }

    pub fn wg_prefix(&self) -> &str {
        &self.wg_prefix
    }

    pub fn table(&self) -> &str {
        &self.table
    }
}

/// Locally administered, stable per index.
pub fn mac(idx: u32) -> String {
    let b = idx.to_be_bytes();
    format!("02:72:6d:{:02x}:{:02x}:{:02x}", b[1], b[2], b[3])
}

fn elements(items: impl Iterator<Item = String>) -> String {
    let v: Vec<String> = items.collect();
    if v.is_empty() {
        String::new()
    } else {
        format!(" elements = {{ {} }};", v.join(", "))
    }
}

fn mask4(len: u8) -> u32 {
    if len == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(len))
    }
}

fn parse_cidr4(s: &str) -> Result<(Ipv4Addr, u8)> {
    let (a, l) = s
        .split_once('/')
        .with_context(|| format!("{s:?} is not a CIDR"))?;
    Ok((
        a.parse()?,
        l.parse::<u8>()
            .ok()
            .filter(|l| *l <= 32)
            .context("bad prefix length")?,
    ))
}

fn parse_cidr6(s: &str) -> Result<(Ipv6Addr, u8)> {
    let (a, l) = s
        .split_once('/')
        .with_context(|| format!("{s:?} is not a CIDR"))?;
    let len = l
        .parse::<u8>()
        .ok()
        .filter(|l| *l <= 128)
        .context("bad prefix length")?;
    let addr: Ipv6Addr = a.parse()?;
    let mask = if len == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(len))
    };
    Ok((Ipv6Addr::from(u128::from(addr) & mask), len))
}

fn valid_ifname(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 15
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// Destination of an `ip -6 route` line if it is a single-address route.
/// `ip` prints those without the `/128` suffix.
fn host_route(dst: &str) -> Option<Ipv6Addr> {
    match dst.split_once('/') {
        Some((addr, "128")) => addr.parse().ok(),
        Some(_) => None,
        None => dst.parse().ok(),
    }
}

/// Interfaces that accept RAs only while not forwarding (`accept_ra = 1`).
fn ra_interfaces() -> Vec<String> {
    let Ok(dir) = std::fs::read_dir("/proc/sys/net/ipv6/conf") else {
        return Vec::new();
    };
    dir.filter_map(|e| e.ok()?.file_name().into_string().ok())
        .filter(|name| name != "all" && name != "default" && valid_ifname(name))
        .filter(|name| {
            std::fs::read_to_string(format!("/proc/sys/net/ipv6/conf/{name}/accept_ra"))
                .is_ok_and(|v| v.trim() == "1")
        })
        .collect()
}

async fn link_exists(name: &str) -> bool {
    std::path::Path::new("/sys/class/net").join(name).exists()
}

async fn sysctl(key: &str, value: &str) -> Result<()> {
    let path = std::path::Path::new("/proc/sys").join(key.replace('.', "/"));
    tokio::fs::write(&path, value)
        .await
        .with_context(|| format!("sysctl {key}={value}"))
}

async fn output(cmd: &mut Command) -> Result<String> {
    let out = cmd.output().await?;
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

/// Host ports with a local listener (so a forward would hijack a host service).
pub fn host_listening(proto: L4Proto, port: u16) -> bool {
    let (files, listen_state) = match proto {
        L4Proto::Tcp => (["/proc/net/tcp", "/proc/net/tcp6"], "0A"),
        L4Proto::Udp => (["/proc/net/udp", "/proc/net/udp6"], "07"),
    };
    files.iter().any(|f| {
        std::fs::read_to_string(f).is_ok_and(|s| {
            s.lines().skip(1).any(|l| {
                let cols: Vec<&str> = l.split_whitespace().collect();
                cols.get(3) == Some(&listen_state)
                    && cols
                        .get(1)
                        .and_then(|a| a.rsplit_once(':'))
                        .and_then(|(_, p)| u16::from_str_radix(p, 16).ok())
                        == Some(port)
            })
        })
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg(mode: &str, prefix: &str) -> NetworkConfig {
        NetworkConfig {
            ipv6_mode: mode.into(),
            ipv6_prefix: prefix.into(),
            ..NetworkConfig::default()
        }
    }

    #[test]
    fn addresses_are_stable_and_in_range() {
        let n = Net::from_config(&cfg("none", "")).unwrap();
        assert_eq!(n.gateway4(), Ipv4Addr::new(10, 91, 0, 1));
        assert_eq!(n.addrs_for(0).unwrap().ipv4, Ipv4Addr::new(10, 91, 0, 2));
        assert_eq!(n.addrs_for(300).unwrap().ipv4, Ipv4Addr::new(10, 91, 1, 46));
        assert_eq!(n.max_idx(), 4092);
        assert_eq!(
            n.addrs_for(4092).unwrap().ipv4,
            Ipv4Addr::new(10, 91, 15, 254)
        );
        assert!(n.addrs_for(4093).is_err());
        assert_eq!(n.addrs_for(0).unwrap().ipv6, None);
    }

    #[test]
    fn ipv6_modes() {
        let s = Net::from_config(&cfg("snat", "")).unwrap();
        assert_eq!(
            s.addrs_for(3).unwrap().ipv6.unwrap(),
            "fd91:cafe:cafe:10::5".parse::<Ipv6Addr>().unwrap()
        );
        let p = Net::from_config(&cfg("subnet", "2001:db8:1:2::77/64")).unwrap();
        assert_eq!(
            p.addrs_for(5).unwrap().ipv6.unwrap(),
            "2001:db8:1:2::1:5".parse::<Ipv6Addr>().unwrap()
        );
        assert!(Net::from_config(&cfg("subnet", "2001:db8::/120")).is_err());
    }

    #[test]
    fn ruleset_contains_forwards_and_guards() {
        let n = Net::from_config(&cfg("snat", "")).unwrap();
        let inst = vec![Port {
            idx: 0,
            addrs: n.addrs_for(0).unwrap(),
            extra: vec!["203.0.113.9".parse().unwrap()],
        }];
        let fw = vec![Forward {
            proto: L4Proto::Tcp,
            host_port: 22022,
            target: inst[0].addrs.ipv4,
            guest_port: 22,
        }];
        let r = n.ruleset(&inst, &fw);
        assert!(r.contains("elements = { 22022 : 10.91.0.2 . 22 }"), "{r}");
        assert!(r.contains("\"rv0\" . 10.91.0.2"));
        assert!(r.contains("\"rv0\" . fd91:cafe:cafe:10::2"));
        assert!(r.contains("\"rv0\" . 203.0.113.9"), "{r}");
        assert!(r.contains("map fwd_udp { type inet_service : ipv4_addr . inet_service; }"));
    }

    #[test]
    fn host_routes_as_printed_by_ip() {
        let a: Ipv6Addr = "2001:db8::1:5".parse().unwrap();
        assert_eq!(host_route("2001:db8::1:5"), Some(a));
        assert_eq!(host_route("2001:db8::1:5/128"), Some(a));
        assert_eq!(host_route("fe80::/64"), None);
        assert_eq!(host_route("default"), None);
    }

    #[test]
    fn mac_is_locally_administered() {
        assert_eq!(mac(258), "02:72:6d:00:01:02");
    }
}
