//! `runman-agent detect-ipv6`: suggest the `[network]` IPv6 settings.
//!
//! - The uplink (interface of the IPv6 default route) holds a global /64 (or
//!   larger) and the provider really delivers the whole prefix there: verified
//!   by temporarily adding an unused address from it and checking that the
//!   internet sees that address as our source → `subnet` with NDP proxying.
//! - Otherwise, with any IPv6 default route → `snat`.
//! - No IPv6 default route → `none`.

use std::net::Ipv6Addr;
use std::time::Duration;

use anyhow::Result;
use tokio::process::Command;

#[derive(Debug, PartialEq)]
pub enum Ipv6Plan {
    None,
    Snat { uplink: String },
    Subnet { prefix: String, uplink: String },
}

impl Ipv6Plan {
    /// Lines for the `[network]` table of config.toml.
    pub fn toml(&self) -> String {
        match self {
            Self::None => "ipv6_mode = \"none\"\n".into(),
            Self::Snat { .. } => "ipv6_mode = \"snat\"\n".into(),
            Self::Subnet { prefix, uplink } => {
                format!(
                    "ipv6_mode = \"subnet\"\nipv6_prefix = \"{prefix}\"\nipv6_ndp_uplink = \"{uplink}\"\n"
                )
            }
        }
    }
}

pub async fn detect_ipv6() -> Result<Ipv6Plan> {
    let routes = output(&["-6", "route", "show", "default"]).await;
    let Some(uplink) = routes.lines().find_map(|l| word_after(l, "dev")) else {
        return Ok(Ipv6Plan::None);
    };
    let addrs = output(&[
        "-6", "-o", "addr", "show", "dev", &uplink, "scope", "global",
    ])
    .await;
    for line in addrs
        .lines()
        .filter(|l| !l.contains("temporary") && !l.contains("deprecated"))
    {
        let Some(cidr) = word_after(line, "inet6") else {
            continue;
        };
        let Some((addr, len)) = cidr.split_once('/') else {
            continue;
        };
        let (Ok(addr), Ok(len)) = (addr.parse::<Ipv6Addr>(), len.parse::<u32>()) else {
            continue;
        };
        if len > 64 {
            continue;
        }
        let net = u128::from(addr) & (u128::MAX << 64);
        let probe = Ipv6Addr::from(net | 0xffff_ffff);
        if probe_source(&uplink, probe).await {
            return Ok(Ipv6Plan::Subnet {
                prefix: format!("{}/64", Ipv6Addr::from(net)),
                uplink,
            });
        }
    }
    Ok(Ipv6Plan::Snat { uplink })
}

/// Does traffic sourced from `addr` (inside our prefix) get out and back?
async fn probe_source(uplink: &str, addr: Ipv6Addr) -> bool {
    let a = format!("{addr}/128");
    if !run(&["ip", "-6", "addr", "add", &a, "dev", uplink, "nodad"]).await {
        return false;
    }
    tokio::time::sleep(Duration::from_secs(1)).await;
    let mut seen = String::new();
    for url in ["https://api64.ipify.org", "https://api-ipv6.ip.sb/ip"] {
        let out = Command::new("curl")
            .args([
                "-6",
                "-fsS",
                "--max-time",
                "8",
                "--interface",
                &addr.to_string(),
                url,
            ])
            .output()
            .await;
        if let Ok(o) = out
            && o.status.success()
        {
            seen = String::from_utf8_lossy(&o.stdout).trim().to_owned();
            break;
        }
    }
    run(&["ip", "-6", "addr", "del", &a, "dev", uplink]).await;
    seen.parse::<Ipv6Addr>().ok() == Some(addr)
}

fn word_after(line: &str, key: &str) -> Option<String> {
    let mut words = line.split_whitespace();
    while let Some(w) = words.next() {
        if w == key {
            return words.next().map(str::to_owned);
        }
    }
    None
}

async fn output(args: &[&str]) -> String {
    Command::new("ip")
        .args(args)
        .output()
        .await
        .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
        .unwrap_or_default()
}

async fn run(argv: &[&str]) -> bool {
    Command::new(argv[0])
        .args(&argv[1..])
        .status()
        .await
        .is_ok_and(|s| s.success())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn toml_output() {
        let p = Ipv6Plan::Subnet {
            prefix: "2001:db8:1:2::/64".into(),
            uplink: "enp1s0".into(),
        };
        assert_eq!(
            p.toml(),
            "ipv6_mode = \"subnet\"\nipv6_prefix = \"2001:db8:1:2::/64\"\nipv6_ndp_uplink = \"enp1s0\"\n"
        );
        assert_eq!(
            word_after("default via fe80::1 dev eth0 proto ra", "dev").as_deref(),
            Some("eth0")
        );
    }
}
