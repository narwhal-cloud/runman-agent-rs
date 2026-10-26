//! First-boot preparation of an instance rootfs, done by the agent while the
//! instance is stopped (no cloud-init, no network needed at create time).

use anyhow::{Context, Result, bail};
use sha_crypt::{Sha512Params, sha512_simple};

use super::fsutil::RootFs;

/// Units that cannot work in an unprivileged container and only produce
/// failed-unit noise.
const MASKED_UNITS: &[&str] = &[
    "sys-kernel-config.mount",
    "sys-kernel-debug.mount",
    "sys-kernel-tracing.mount",
    "sys-fs-fuse-connections.mount",
    "systemd-journald-audit.socket",
];

const SSH_HOST_KEYS: &[&str] = &["rsa", "ecdsa", "ed25519", "dsa"];

pub struct FirstBoot<'a> {
    pub hostname: &'a str,
    pub root_password: &'a str,
    pub net: Option<NetFiles>,
}

/// Static network configuration written into the instance.
pub struct NetFiles {
    pub ipv4: std::net::Ipv4Addr,
    pub prefix4: u8,
    pub gateway4: std::net::Ipv4Addr,
    pub ipv6: Option<std::net::Ipv6Addr>,
    pub gateway6: std::net::Ipv6Addr,
    pub dns: Vec<String>,
    /// Dedicated public addresses (WireGuard bindings); the first of each
    /// family becomes the default source address.
    pub extra: Vec<std::net::IpAddr>,
}

pub fn prepare(root: &RootFs, cfg: &FirstBoot<'_>) -> Result<()> {
    root.write(
        "/etc/hostname",
        format!("{}\n", cfg.hostname).as_bytes(),
        0o644,
    )?;
    root.write("/etc/hosts", hosts(cfg.hostname).as_bytes(), 0o644)?;
    set_root_password(root, &hash_password(cfg.root_password)?)?;

    // Every instance must get its own identity: the template ships the
    // builder's machine-id and SSH host keys.
    if root.exists("/etc/machine-id") {
        root.write("/etc/machine-id", b"", 0o444)?;
    }
    for kind in SSH_HOST_KEYS {
        root.remove(&format!("/etc/ssh/ssh_host_{kind}_key"))?;
        root.remove(&format!("/etc/ssh/ssh_host_{kind}_key.pub"))?;
    }

    if root.exists("/etc/systemd/system") {
        // sshd refuses to start without host keys; generate them before the
        // unit's own config check (OpenRC's sshd script already does this).
        // Drop-ins append to ExecStartPre, so reset the list and re-add the
        // check after key generation.
        let dropin = "[Service]\nExecStartPre=\nExecStartPre=-/usr/bin/ssh-keygen -A\nExecStartPre=/usr/sbin/sshd -t\n";
        if let Some(unit) = ["ssh.service", "sshd.service"].into_iter().find(|u| {
            root.exists(&format!("/usr/lib/systemd/system/{u}"))
                || root.exists(&format!("/lib/systemd/system/{u}"))
        }) {
            let dir = format!("/etc/systemd/system/{unit}.d");
            root.mkdir_all(&dir)?;
            root.write(
                &format!("{dir}/10-runman-hostkeys.conf"),
                dropin.as_bytes(),
                0o644,
            )?;
        }
        for unit in MASKED_UNITS {
            root.symlink(&format!("/etc/systemd/system/{unit}"), "/dev/null")?;
        }
    }
    if root.exists("/etc/cloud") {
        root.write("/etc/cloud/cloud-init.disabled", b"", 0o644)?;
    }
    if let Some(net) = &cfg.net {
        write_network(root, net)?;
    }
    Ok(())
}

const NETWORKD_FILE: &str = "/etc/systemd/network/05-runman-eth0.network";

/// systemd-networkd when the image uses it, ifupdown otherwise (Alpine).
pub fn write_network(root: &RootFs, n: &NetFiles) -> Result<()> {
    if root.exists("/usr/lib/systemd/systemd-networkd")
        || root.exists("/lib/systemd/systemd-networkd")
    {
        root.mkdir_all("/etc/systemd/network")?;
        // Sorts before the image's DHCP config; networkd uses the first match.
        root.write(NETWORKD_FILE, networkd_file(n).as_bytes(), 0o644)?;
        root.remove("/etc/systemd/network/10-cloud-init-eth0.network")?;
    } else {
        root.mkdir_all("/etc/network")?;
        root.write(
            "/etc/network/interfaces",
            interfaces_file(n).as_bytes(),
            0o644,
        )?;
        root.write("/etc/resolv.conf", resolv_conf(n).as_bytes(), 0o644)?;
    }
    Ok(())
}

/// Shell script (for `sh -s` inside a running instance) that installs the
/// same configuration and makes the network manager apply it now.
pub fn network_update_script(n: &NetFiles) -> String {
    format!(
        "set -e\n\
         if [ -x /usr/lib/systemd/systemd-networkd ] || [ -x /lib/systemd/systemd-networkd ]; then\n\
         mkdir -p /etc/systemd/network\n\
         cat > {NETWORKD_FILE}.tmp <<'RUNMAN_EOF'\n{}RUNMAN_EOF\n\
         mv {NETWORKD_FILE}.tmp {NETWORKD_FILE}\n\
         networkctl reload\n\
         networkctl reconfigure eth0\n\
         else\n\
         cat > /etc/network/interfaces.tmp <<'RUNMAN_EOF'\n{}RUNMAN_EOF\n\
         mv /etc/network/interfaces.tmp /etc/network/interfaces\n\
         ifdown -f eth0 >/dev/null 2>&1 || true\n\
         ifup eth0\n\
         fi\n",
        networkd_file(n),
        interfaces_file(n)
    )
}

fn split_extra(n: &NetFiles) -> (Vec<std::net::Ipv4Addr>, Vec<std::net::Ipv6Addr>) {
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    for a in &n.extra {
        match a {
            std::net::IpAddr::V4(a) => v4.push(*a),
            std::net::IpAddr::V6(a) => v6.push(*a),
        }
    }
    (v4, v6)
}

fn networkd_file(n: &NetFiles) -> String {
    let (x4, x6) = split_extra(n);
    let has_v6 = n.ipv6.is_some() || !x6.is_empty();
    let mut f = format!(
        "[Match]\nName=eth0\n\n[Network]\nAddress={}/{}\nIPv6AcceptRA=no\nLinkLocalAddressing={}\n",
        n.ipv4,
        n.prefix4,
        if has_v6 { "ipv6" } else { "no" }
    );
    for a in &x4 {
        f.push_str(&format!("Address={a}/32\n"));
    }
    for d in &n.dns {
        f.push_str(&format!("DNS={d}\n"));
    }
    // A dedicated address becomes the default source, so outbound traffic
    // uses it (the host routes that source through its tunnel).
    f.push_str(&format!("\n[Route]\nGateway={}\n", n.gateway4));
    if let Some(src) = x4.first() {
        f.push_str(&format!("PreferredSource={src}\n"));
    }
    for a in n.ipv6.iter().chain(&x6) {
        f.push_str(&format!("\n[Address]\nAddress={a}/128\n"));
    }
    if has_v6 {
        f.push_str(&format!(
            "\n[Route]\nGateway={}\nGatewayOnLink=yes\n",
            n.gateway6
        ));
        if let Some(src) = x6.first() {
            f.push_str(&format!("PreferredSource={src}\n"));
        }
    }
    f
}

fn interfaces_file(n: &NetFiles) -> String {
    let (x4, x6) = split_extra(n);
    let mut f = format!(
        "auto lo\niface lo inet loopback\n\nauto eth0\niface eth0 inet static\n\taddress {}/{}\n",
        n.ipv4, n.prefix4
    );
    for a in &x4 {
        f.push_str(&format!("\taddress {a}/32\n"));
    }
    match x4.first() {
        Some(src) => f.push_str(&format!(
            "\tpost-up ip route replace default via {} dev eth0 src {src}\n",
            n.gateway4
        )),
        None => f.push_str(&format!("\tgateway {}\n", n.gateway4)),
    }
    let v6: Vec<_> = n.ipv6.iter().chain(&x6).collect();
    if let Some((first, rest)) = v6.split_first() {
        f.push_str(&format!(
            "\niface eth0 inet6 static\n\taddress {first}/128\n"
        ));
        for a in rest {
            f.push_str(&format!("\taddress {a}/128\n"));
        }
        let src = x6.first().map(|s| format!(" src {s}")).unwrap_or_default();
        f.push_str(&format!(
            "\tpost-up ip -6 route replace default via {} dev eth0{src}\n",
            n.gateway6
        ));
    }
    f
}

fn resolv_conf(n: &NetFiles) -> String {
    n.dns.iter().map(|d| format!("nameserver {d}\n")).collect()
}

fn hosts(hostname: &str) -> String {
    format!(
        "127.0.0.1\tlocalhost\n127.0.1.1\t{hostname}\n::1\tlocalhost ip6-localhost ip6-loopback\nff02::1\tip6-allnodes\nff02::2\tip6-allrouters\n"
    )
}

pub fn hash_password(password: &str) -> Result<String> {
    let params = Sha512Params::new(5000).map_err(|e| anyhow::anyhow!("{e:?}"))?;
    sha512_simple(password, &params).map_err(|e| anyhow::anyhow!("hash password: {e:?}"))
}

/// Replace root's hash in /etc/shadow, keeping every other field and line.
pub fn set_root_password(root: &RootFs, hash: &str) -> Result<()> {
    let shadow = root.read("/etc/shadow")?.context("/etc/shadow missing")?;
    let updated = replace_root_hash(&shadow, hash)?;
    root.write("/etc/shadow", updated.as_bytes(), 0o640)
}

fn replace_root_hash(shadow: &str, hash: &str) -> Result<String> {
    let mut found = false;
    let mut out = String::with_capacity(shadow.len() + hash.len());
    for line in shadow.lines() {
        let mut fields: Vec<&str> = line.split(':').collect();
        if fields.first() == Some(&"root") && fields.len() >= 3 {
            fields[1] = hash;
            // Day of last change: today, so no forced expiry prompt.
            let days = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| (d.as_secs() / 86400).to_string())
                .unwrap_or_default();
            let joined: Vec<String> = fields
                .iter()
                .enumerate()
                .map(|(i, f)| {
                    if i == 2 {
                        days.clone()
                    } else {
                        (*f).to_owned()
                    }
                })
                .collect();
            out.push_str(&joined.join(":"));
            found = true;
        } else {
            out.push_str(line);
        }
        out.push('\n');
    }
    if !found {
        bail!("no root entry in /etc/shadow");
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn replaces_only_root_hash() {
        let shadow = "root:*:20000:0:99999:7:::\ndaemon:*:20000:0:99999:7:::\n";
        let out = replace_root_hash(shadow, "$6$x$y").unwrap();
        let root: Vec<&str> = out.lines().next().unwrap().split(':').collect();
        assert_eq!(root[1], "$6$x$y");
        assert_eq!(root.len(), 9);
        assert_eq!(out.lines().nth(1).unwrap(), "daemon:*:20000:0:99999:7:::");
    }

    #[test]
    fn hash_verifies() {
        let h = hash_password("Secret-pass1").unwrap();
        assert!(h.starts_with("$6$"));
        assert!(sha_crypt::sha512_check("Secret-pass1", &h).is_ok());
    }
}
