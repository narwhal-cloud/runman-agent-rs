#!/usr/bin/env bash
# Runman agent installer / upgrader / uninstaller.
#
#   bash install.sh [--token TOKEN] [options]      install, or upgrade in place
#   bash install.sh --uninstall [--purge]          remove (--purge also deletes instances)
#
# Re-running it is safe: an existing configuration is kept and only the
# binaries and service units are refreshed. It never prompts.
set -euo pipefail

RELEASE_URL="${RUNMAN_RELEASE_URL:-https://github.com/narwhal-cloud/runman-agent-rs/releases/download/continuous}"
RFW_URL="${RUNMAN_RFW_URL:-https://github.com/narwhal-cloud/runman-agent/releases/download/continuous}"
PLATFORM_URL="https://hosting.fuckip.me:443"
CONFIG_DIR=/etc/runman-agent
CONFIG="$CONFIG_DIR/config.toml"
DATA_DIR=/var/lib/runman-agent
BIN=/usr/local/bin/runman-agent
RFW_BIN=/usr/local/bin/rfw
RFW_DIR=/var/lib/rfw
RFW_API=127.0.0.1:7734
MIN_KERNEL=5.19

TOKEN=""
WEB_LISTEN="0.0.0.0:8792"
IPV6="auto"
IPV6_PREFIX=""
IPV6_UPLINK=""
BANDWIDTH=0
WITH_RFW=1
RFW_IFACE=""
FROM_DIR=""
UNINSTALL=0
PURGE=0

log() { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33mwarning:\033[0m %s\n' "$*" >&2; }
die() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<'EOF'
Usage: install.sh [options]

  --token TOKEN           Token issued by the platform. Without one the node runs
                          standalone: it never contacts the platform and is
                          managed entirely from its own panel
  --platform-url URL      Platform gRPC endpoint (default: https://hosting.fuckip.me:443)
  --web-listen ADDR       Management panel address (default 0.0.0.0:8792;
                          use 127.0.0.1:8792 to reach it only through an SSH tunnel)
  --no-web                Disable the management panel
  --ipv6 MODE             auto (default), none, snat or subnet
  --ipv6-prefix CIDR      Prefix for --ipv6 subnet, e.g. 2001:db8:1:2::/64
  --ipv6-uplink IFACE     Interface where that prefix is on-link (NDP proxy);
                          omit when the prefix is routed to this host
  --bandwidth MBPS        Uplink bandwidth reported to the platform
  --no-rfw                Do not install the rfw firewall
  --rfw-iface IFACE       Interface rfw protects (default: IPv4 default route)
  --from-dir DIR          Use binaries from DIR (runman-agent-linux-<arch>, SHA256SUMS,
                          optionally rfw-<arch>) instead of downloading them
  --uninstall             Remove the agent; refuses while instances exist
  --purge                 With --uninstall: also delete every instance and all data
  -h, --help              Show this help
EOF
}

while [ $# -gt 0 ]; do
    case "$1" in
        --token) TOKEN="${2:?--token needs a value}"; shift 2 ;;
        --platform-url) PLATFORM_URL="${2:?--platform-url needs a value}"; shift 2 ;;
        --web-listen) WEB_LISTEN="${2:?--web-listen needs a value}"; shift 2 ;;
        --no-web) WEB_LISTEN=""; shift ;;
        --ipv6) IPV6="${2:?--ipv6 needs a value}"; shift 2 ;;
        --ipv6-prefix) IPV6_PREFIX="${2:?--ipv6-prefix needs a value}"; shift 2 ;;
        --ipv6-uplink) IPV6_UPLINK="${2:?--ipv6-uplink needs a value}"; shift 2 ;;
        --bandwidth) BANDWIDTH="${2:?--bandwidth needs a value}"; shift 2 ;;
        --no-rfw) WITH_RFW=0; shift ;;
        --rfw-iface) RFW_IFACE="${2:?--rfw-iface needs a value}"; shift 2 ;;
        --from-dir) FROM_DIR="${2:?--from-dir needs a value}"; shift 2 ;;
        --uninstall) UNINSTALL=1; shift ;;
        --purge) PURGE=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; die "unknown option: $1" ;;
    esac
done

[ "$(id -u)" = 0 ] || die "run as root"

# ── validation ──────────────────────────────────────────────────────────────

[[ "$PLATFORM_URL" =~ ^https?://[A-Za-z0-9.-]+(:[0-9]{1,5})?/?$ ]] || die "invalid --platform-url"
[ -z "$WEB_LISTEN" ] || [[ "$WEB_LISTEN" =~ ^[0-9.]+:[0-9]{1,5}$|^\[[0-9a-fA-F:]+\]:[0-9]{1,5}$ ]] \
    || die "invalid --web-listen (expected ip:port)"
[[ "$BANDWIDTH" =~ ^[0-9]{1,7}$ ]] || die "invalid --bandwidth"
[ -z "$TOKEN" ] || [[ "$TOKEN" =~ ^[[:graph:]]{16,512}$ ]] || die "--token must be 16-512 printable characters"
case "$IPV6" in
    auto|none|snat) ;;
    subnet)
        [[ "$IPV6_PREFIX" =~ ^[0-9a-fA-F:]+/[0-9]{1,3}$ ]] || die "--ipv6 subnet needs --ipv6-prefix CIDR"
        [ -z "$IPV6_UPLINK" ] || [[ "$IPV6_UPLINK" =~ ^[A-Za-z0-9_.-]{1,15}$ ]] || die "invalid --ipv6-uplink"
        ;;
    *) die "--ipv6 must be auto, none, snat or subnet" ;;
esac
[ -z "$RFW_IFACE" ] || [[ "$RFW_IFACE" =~ ^[A-Za-z0-9_.-]{1,15}$ ]] || die "invalid --rfw-iface"

case "$(uname -m)" in
    x86_64) ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) die "unsupported architecture $(uname -m)" ;;
esac

# ── uninstall ───────────────────────────────────────────────────────────────

uninstall() {
    local count=0
    if [ -d "$DATA_DIR/instances" ]; then
        count=$(find "$DATA_DIR/instances" -mindepth 1 -maxdepth 1 -type d | wc -l)
    fi
    if [ "$count" -gt 0 ] && [ "$PURGE" != 1 ]; then
        die "$count instance(s) exist on this node; delete them on the platform first, or use --uninstall --purge to destroy them"
    fi
    log "stopping the agent"
    systemctl disable --now runman-agent.service 2>/dev/null || true
    if [ "$PURGE" = 1 ]; then
        log "stopping and deleting all instances"
        systemctl stop 'runman-*.service' 2>/dev/null || true
    fi
    log "removing host networking"
    nft delete table inet runman 2>/dev/null || true
    nft delete table bridge runman 2>/dev/null || true
    local link
    for link in $(ip -o link show | awk -F': ' '{print $2}' | cut -d@ -f1 | grep -E '^(rv[0-9]+i?|rw[0-9]+)$' || true); do
        ip link del "$link" 2>/dev/null || true
    done
    # Instance IPv6 addresses are the /128 routes on the bridge; drop the NDP
    # proxy entries the agent kept for them on the uplink.
    local addr uplink
    uplink=$(sed -n 's/^ipv6_ndp_uplink = "\(.*\)"$/\1/p' "$CONFIG" 2>/dev/null || true)
    if [ -n "$uplink" ]; then
        # `ip` prints single-address routes without the /128 suffix.
        for addr in $(ip -6 route show dev rmbr0 2>/dev/null | awk '$1 ~ /:/ && $1 !~ /\// && $1 !~ /^fe80/ {print $1}'); do
            ip -6 neigh del proxy "$addr" dev "$uplink" 2>/dev/null || true
        done
    fi
    ip link del rmbr0 2>/dev/null || true
    local tool dir
    for tool in iptables ip6tables; do
        command -v "$tool" >/dev/null || continue
        for dir in -i -o; do
            while "$tool" -w -D FORWARD "$dir" rmbr0 -m comment --comment runman -j ACCEPT 2>/dev/null; do :; done
        done
    done
    local fam rule
    for fam in -4 -6; do
        { ip "$fam" rule show | grep -E 'lookup 20[0-9]{3}' || true; } | while read -r rule; do
            # shellcheck disable=SC2086 # the rule text is split into ip arguments on purpose
            ip "$fam" rule del ${rule#*:} 2>/dev/null || true
        done
    done
    if [ -f /etc/systemd/system/rfw.service ]; then
        log "removing rfw"
        systemctl disable --now rfw.service 2>/dev/null || true
        rm -f /etc/systemd/system/rfw.service "$RFW_BIN"
    fi
    rm -f /etc/systemd/system/runman-agent.service /etc/modules-load.d/runman.conf "$BIN" \
        /etc/sysctl.d/90-runman.conf /etc/systemd/system/lxcfs.service.d/runman.conf
    rm -rf "$CONFIG_DIR" /run/runman-agent
    if [ "$PURGE" = 1 ]; then
        local dir
        for dir in "$DATA_DIR"/instances/*/mnt/*; do
            if [ -d "$dir" ]; then umount -l "$dir" 2>/dev/null || true; fi
        done
        rm -rf "$DATA_DIR" "$RFW_DIR"
    fi
    systemctl daemon-reload
    log "uninstalled$([ "$PURGE" = 1 ] && echo ' (instances and data deleted)')"
}

if [ "$UNINSTALL" = 1 ]; then
    uninstall
    exit 0
fi

# ── host checks ─────────────────────────────────────────────────────────────

# shellcheck disable=SC1091
. /etc/os-release
case "${ID:-}:${ID_LIKE:-}" in
    debian:*|ubuntu:*|*:*debian*) ;;
    *) die "unsupported OS ${PRETTY_NAME:-unknown}; Debian 12+/Ubuntu 22.04+ are supported (Debian 13 recommended)" ;;
esac
if command -v systemd-detect-virt >/dev/null && systemd-detect-virt --container --quiet; then
    die "this host is itself a container ($(systemd-detect-virt --container)); a KVM VM or bare metal is required"
fi
[ "$(cat /proc/1/comm 2>/dev/null)" = systemd ] || die "systemd is required"
[ -f /sys/fs/cgroup/cgroup.controllers ] || die "cgroup v2 (unified hierarchy) is required"
kernel=$(uname -r | cut -d- -f1)
[ "$(printf '%s\n%s\n' "$MIN_KERNEL" "$kernel" | sort -V | head -n1)" = "$MIN_KERNEL" ] \
    || die "kernel $kernel is too old; $MIN_KERNEL or newer is required (idmapped mounts)"

# ── packages ────────────────────────────────────────────────────────────────

log "installing packages"
# Wait for other apt/dpkg runs (e.g. unattended-upgrades) instead of killing them.
apt_get() { LC_ALL=C DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=600 -y -q "$@"; }
apt_get update >/dev/null
apt_get install --no-install-recommends \
    ca-certificates curl iproute2 nftables wireguard-tools e2fsprogs tar gzip zstd util-linux kmod lxcfs >/dev/null

for mod in wireguard ifb sch_cake tcp_bbr; do
    modprobe "$mod" 2>/dev/null || warn "kernel module $mod is unavailable; related features will fail"
done
printf '%s\n' wireguard ifb sch_cake tcp_bbr > /etc/modules-load.d/runman.conf

log "tuning kernel limits"
# Each instance runs a full init. Their inotify instances, keys and neighbour
# entries add up on the host (inotify instances of all instances count against
# one host user: the default of 128 runs out after a handful of instances).
cat > /etc/sysctl.d/90-runman.conf <<'SYSCTL'
# Written by the runman installer.
fs.inotify.max_user_instances = 65536
fs.inotify.max_user_watches = 4194304
fs.inotify.max_queued_events = 65536
kernel.keys.maxkeys = 2000
kernel.keys.maxbytes = 2000000
kernel.pid_max = 4194304
vm.max_map_count = 262144
net.ipv4.neigh.default.gc_thresh3 = 8192
net.ipv6.neigh.default.gc_thresh3 = 8192
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
SYSCTL
sysctl -q -p /etc/sysctl.d/90-runman.conf || warn "some kernel settings could not be applied"

# lxcfs gives instances their own /proc/meminfo, cpuinfo, uptime and load
# (CPU count from the CPU quota, load average per instance).
lxcfs_dropin=/etc/systemd/system/lxcfs.service.d/runman.conf
lxcfs_conf=$(printf '[Service]\nExecStart=\nExecStart=/usr/bin/lxcfs --enable-cfs -l /var/lib/lxcfs')
if [ "$(cat "$lxcfs_dropin" 2>/dev/null)" != "$lxcfs_conf" ]; then
    install -d /etc/systemd/system/lxcfs.service.d
    printf '%s\n' "$lxcfs_conf" > "$lxcfs_dropin"
    systemctl daemon-reload
    # Restarting lxcfs detaches the views of running instances until they
    # restart, so only do it when its options actually change.
    systemctl restart lxcfs.service
fi
systemctl enable --now lxcfs.service >/dev/null 2>&1 || warn "lxcfs is not running; instances will see host-wide /proc values"

# ── binaries ────────────────────────────────────────────────────────────────

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

fetch() { # fetch <name> <dest> <base-url>; --from-dir wins when it has the file
    if [ -n "$FROM_DIR" ] && [ -f "$FROM_DIR/$1" ]; then
        cp "$FROM_DIR/$1" "$2"
    else
        curl -fsSL --retry 3 --connect-timeout 20 -o "$2" "$3/$1"
    fi
}

is_elf_for_arch() { # the file must be a 64-bit ELF for this machine
    local want
    want=$([ "$ARCH" = amd64 ] && echo 3e00 || echo b700)
    [ "$(head -c 6 "$1" | od -An -tx1 | tr -d ' \n')" = 7f454c460201 ] \
        && [ "$(dd if="$1" bs=1 skip=18 count=2 2>/dev/null | od -An -tx1 | tr -d ' \n')" = "$want" ]
}

asset="runman-agent-linux-$ARCH"
log "fetching $asset"
fetch SHA256SUMS "$WORK/SHA256SUMS" "$RELEASE_URL" || die "cannot fetch SHA256SUMS"
fetch "$asset" "$WORK/$asset" "$RELEASE_URL" || die "cannot fetch $asset"
(cd "$WORK" && grep -E "  \*?$asset\$" SHA256SUMS | sha256sum -c --quiet -) || die "checksum mismatch for $asset"
is_elf_for_arch "$WORK/$asset" || die "$asset is not a binary for $ARCH"
chmod 755 "$WORK/$asset"
"$WORK/$asset" --version >/dev/null || die "$asset does not run on this host"
install -m 755 "$WORK/$asset" "$BIN.new"
mv -f "$BIN.new" "$BIN"
log "installed $("$BIN" --version)"

# ── configuration ───────────────────────────────────────────────────────────

FRESH=0
PASSWORD=""
if [ ! -f "$CONFIG" ]; then
    FRESH=1
    log "writing $CONFIG"
    if [ "$IPV6" = auto ]; then
        log "detecting IPv6 (this briefly tests one address of the prefix)"
        ipv6_conf=$("$BIN" detect-ipv6) || { warn "IPv6 detection failed; using none"; ipv6_conf='ipv6_mode = "none"'; }
    elif [ "$IPV6" = subnet ]; then
        ipv6_conf=$(printf 'ipv6_mode = "subnet"\nipv6_prefix = "%s"\nipv6_ndp_uplink = "%s"' "$IPV6_PREFIX" "$IPV6_UPLINK")
    else
        ipv6_conf="ipv6_mode = \"$IPV6\""
    fi
    install -d -m 700 "$CONFIG_DIR"
    umask 077
    cat > "$CONFIG" <<EOF
# Runman agent configuration. Most settings take effect after
# \`systemctl restart runman-agent\`; instances keep running across restarts.
platform_url = "$PLATFORM_URL"
data_dir = "$DATA_DIR"
backend = "container"
web_listen = "$WEB_LISTEN"
bandwidth_mbps = $BANDWIDTH
rfw_addr = "$RFW_API"

[network]
$ipv6_conf
EOF
    umask 022
    PASSWORD=$(tr -dc 'A-Za-z0-9' </dev/urandom | head -c 16 || true)
    printf '%s\n' "$PASSWORD" | "$BIN" --config "$CONFIG" set-password >/dev/null
else
    log "keeping existing $CONFIG"
fi
# Tokens are only ever issued by the platform; none means standalone mode.
if [ -n "$TOKEN" ]; then
    "$BIN" --config "$CONFIG" set-token "$TOKEN" >/dev/null
fi

# ── rfw ─────────────────────────────────────────────────────────────────────

rfw_ready() {
    local _
    for _ in $(seq 1 "$1"); do
        curl -fsS "http://$RFW_API/api/status" >/dev/null 2>&1 && return 0
        sleep 1
    done
    return 1
}

install_rfw() {
    local iface=$RFW_IFACE fresh_rfw=0
    [ -n "$iface" ] || iface=$(ip -4 route show default | awk '{for (i = 1; i < NF; i++) if ($i == "dev") { print $(i + 1); exit }}')
    [ -n "$iface" ] || { warn "no IPv4 default route; skipping rfw (use --rfw-iface)"; return 0; }
    log "installing rfw on $iface"
    if ! fetch "rfw-$ARCH" "$WORK/rfw" "$RFW_URL"; then
        warn "cannot download rfw; continuing without it"
        return 0
    fi
    is_elf_for_arch "$WORK/rfw" || { warn "rfw download is not a binary for $ARCH; skipping"; return 0; }
    install -m 755 "$WORK/rfw" "$RFW_BIN.new"
    mv -f "$RFW_BIN.new" "$RFW_BIN"
    install -d -m 700 "$RFW_DIR"
    [ -f /etc/systemd/system/rfw.service ] || fresh_rfw=1
    write_rfw_unit "$iface" ""
    systemctl daemon-reload
    systemctl enable rfw.service >/dev/null 2>&1
    systemctl restart rfw.service
    if ! rfw_ready 10; then
        # Some virtual NICs reject native XDP; the generic SKB mode works everywhere.
        warn "rfw did not start in native XDP mode; retrying in SKB mode"
        write_rfw_unit "$iface" "--xdp-mode skb"
        systemctl daemon-reload
        systemctl restart rfw.service
        rfw_ready 15 || { warn "rfw is not responding; see journalctl -u rfw"; return 0; }
    fi
    if [ "$fresh_rfw" = 1 ] && [ "$(curl -fsS "http://$RFW_API/api/rules")" = "[]" ]; then
        log "adding default rfw rules"
        local proto port
        for proto in http socks5 fet; do
            rfw_rule "{\"priority\":100,\"direction\":\"in\",\"protocol\":\"$proto\",\"action\":\"block\",\"port_start\":0,\"enabled\":true,\"ip_type\":\"geoip\",\"countries\":[\"CN\"]}"
        done
        for port in 25 465 587; do
            rfw_rule "{\"priority\":100,\"direction\":\"out\",\"protocol\":\"tcp\",\"action\":\"block\",\"port_start\":$port,\"enabled\":true,\"ip_type\":\"any\"}"
        done
    fi
}

write_rfw_unit() { # write_rfw_unit <iface> <extra args>
    cat > /etc/systemd/system/rfw.service <<EOF
[Unit]
Description=rfw eBPF firewall
After=network-online.target
Wants=network-online.target

[Service]
WorkingDirectory=$RFW_DIR
ExecStart=$RFW_BIN --iface $1 --api-addr $RFW_API $2
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
}

rfw_rule() {
    curl -fsS -X POST -H 'Content-Type: application/json' -d "$1" "http://$RFW_API/api/rules" >/dev/null \
        || warn "failed to add rfw rule $1"
}

if [ "$WITH_RFW" = 1 ]; then
    install_rfw
fi

# ── service ─────────────────────────────────────────────────────────────────

log "starting runman-agent"
cat > /etc/systemd/system/runman-agent.service <<EOF
[Unit]
Description=Runman node agent
After=network-online.target nftables.service lxcfs.service
Wants=network-online.target lxcfs.service

[Service]
ExecStart=$BIN --config $CONFIG
Restart=always
RestartSec=5
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable runman-agent.service >/dev/null 2>&1
systemctl restart runman-agent.service

if [ -n "$WEB_LISTEN" ]; then
    port=${WEB_LISTEN##*:}
    for _ in $(seq 1 20); do
        curl -fsS -o /dev/null "http://127.0.0.1:$port/" 2>/dev/null && break
        sleep 1
    done
fi
systemctl is-active --quiet runman-agent.service || die "runman-agent failed to start; see journalctl -u runman-agent"

public_ip=$(curl -4 -fsS --max-time 8 https://api-ipv4.ip.sb/ip 2>/dev/null || echo '<this-host>')
echo
log "done"
echo "  agent:   $("$BIN" --version), $(grep -E '^ipv6_mode' "$CONFIG" | head -n1 || echo 'ipv6_mode = none')"
if [ -n "$WEB_LISTEN" ]; then
    case "$WEB_LISTEN" in
        127.*|\[::1\]*) echo "  panel:   http://$WEB_LISTEN (local only; use: ssh -L ${WEB_LISTEN##*:}:$WEB_LISTEN root@$public_ip)" ;;
        *) echo "  panel:   http://$public_ip:${WEB_LISTEN##*:}" ;;
    esac
fi
if [ "$FRESH" = 1 ]; then
    echo "  login:   admin / $PASSWORD"
fi
if grep -qE '^token = ".+"' "$CONFIG"; then
    echo "  mode:    platform (connects to $(sed -n 's/^platform_url = "\(.*\)"$/\1/p' "$CONFIG"))"
else
    echo "  mode:    standalone (no platform token; manage instances in the panel)"
    echo "           connect later: runman-agent set-token '<token from the platform>' && systemctl restart runman-agent"
fi
echo "  OS images are downloaded in the background on first start (journalctl -fu runman-agent)."
