#!/usr/bin/env bash
# Build an instance image (root filesystem template) from the distribution's
# own package sources.
#
#   sudo bash images/build.sh <debian|alpine> <amd64|arm64> <outdir> [serial]
#
# Produces <outdir>/rootfs-<distro>-<arch>.tar.zst and a matching .json with
# the metadata images.json is assembled from. Must run on the target
# architecture (package maintainer scripts execute in a chroot).
#
# Images are deliberately small. The agent finishes every instance at first
# boot (hostname, root password, SSH host keys, machine-id, network, masked
# services), so nothing instance-specific is baked in here.
set -euo pipefail

DISTRO="${1:?usage: build.sh <debian|alpine> <amd64|arm64> <outdir> [serial]}"
ARCH="${2:?arch required}"
OUT="${3:?output directory required}"
SERIAL="${4:-$(date -u +%Y%m%d)}"

DEBIAN_SUITE=trixie
DEBIAN_MIRROR=http://deb.debian.org/debian
ALPINE_MIRROR=https://dl-cdn.alpinelinux.org/alpine

[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
case "$ARCH" in amd64|arm64) ;; *) echo "unsupported arch $ARCH" >&2; exit 1 ;; esac

WORK=$(mktemp -d)
ROOT="$WORK/rootfs"
cleanup() {
    for m in dev/pts dev proc sys; do umount -l "$ROOT/$m" 2>/dev/null || true; done
    rm -rf "$WORK"
}
trap cleanup EXIT
mkdir -p "$OUT" "$ROOT"

log() { printf '==> %s\n' "$*"; }

sshd_config() {
    mkdir -p "$ROOT/etc/ssh/sshd_config.d"
    printf 'PermitRootLogin yes\nPasswordAuthentication yes\n' > "$ROOT/etc/ssh/sshd_config.d/10-runman.conf"
    rm -f "$ROOT"/etc/ssh/ssh_host_*
}

build_debian() {
    log "debootstrapping Debian $DEBIAN_SUITE ($ARCH)"
    # Minimal base without recommends, docs, man pages or translations.
    local nodocs=(
        --dpkgopt='path-exclude=/usr/share/doc/*'
        --dpkgopt='path-include=/usr/share/doc/*/copyright'
        --dpkgopt='path-exclude=/usr/share/man/*'
        --dpkgopt='path-exclude=/usr/share/info/*'
        --dpkgopt='path-exclude=/usr/share/locale/*'
        --dpkgopt='path-include=/usr/share/locale/locale.alias'
        --dpkgopt='path-exclude=/usr/share/lintian/*'
    )
    mmdebstrap --variant=minbase --arch="$ARCH" --aptopt='APT::Install-Recommends "false"' "${nodocs[@]}" \
        --include=systemd,systemd-sysv,openssh-server,ca-certificates,curl,wget,iproute2,iputils-ping,netcat-openbsd,procps,cron,less,nano,sudo,netbase,apt-utils \
        "$DEBIAN_SUITE" "$ROOT" "$DEBIAN_MIRROR"

    # Keep the same footprint rules for packages users install later.
    printf '%s\n' 'path-exclude=/usr/share/doc/*' 'path-include=/usr/share/doc/*/copyright' \
        'path-exclude=/usr/share/man/*' 'path-exclude=/usr/share/info/*' \
        'path-exclude=/usr/share/locale/*' 'path-include=/usr/share/locale/locale.alias' \
        > "$ROOT/etc/dpkg/dpkg.cfg.d/01-runman-nodoc"
    printf 'APT::Install-Recommends "false";\n' > "$ROOT/etc/apt/apt.conf.d/01-runman-norecommends"
    rm -f "$ROOT/etc/apt/sources.list"
    cat > "$ROOT/etc/apt/sources.list.d/debian.sources" <<EOF
Types: deb
URIs: $DEBIAN_MIRROR
Suites: $DEBIAN_SUITE $DEBIAN_SUITE-updates
Components: main contrib non-free non-free-firmware
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg

Types: deb
URIs: http://security.debian.org/debian-security
Suites: $DEBIAN_SUITE-security
Components: main contrib non-free non-free-firmware
Signed-By: /usr/share/keyrings/debian-archive-keyring.gpg
EOF
    sshd_config
    chroot "$ROOT" systemctl enable ssh.service cron.service >/dev/null
    chroot "$ROOT" systemctl set-default multi-user.target >/dev/null
    # Root login is configured per instance; keep the account locked here.
    chroot "$ROOT" usermod -p '*' root
    : > "$ROOT/etc/machine-id"
    rm -f "$ROOT/var/lib/dbus/machine-id"
    echo localhost > "$ROOT/etc/hostname"
    rm -rf "$ROOT"/var/lib/apt/lists/* "$ROOT"/var/cache/apt/*.bin "$ROOT"/var/cache/apt/archives/*.deb \
        "$ROOT"/var/log/*.log "$ROOT"/var/log/apt/* "$ROOT"/tmp/* "$ROOT"/var/tmp/*
    NAME="Debian 13 (trixie)"
    STOP_SIGNAL="SIGRTMIN+4"
}

build_alpine() {
    local aarch version file sha
    aarch=$([ "$ARCH" = amd64 ] && echo x86_64 || echo aarch64)
    local rel="$ALPINE_MIRROR/latest-stable/releases/$aarch"
    curl -fsSL "$rel/latest-releases.yaml" -o "$WORK/releases.yaml"
    # The minirootfs entry of latest-releases.yaml (entries start with "-").
    read -r version file sha < <(awk '
        /^-/ { v = f = fl = "" }
        $1 == "version:" { v = $2 }
        $1 == "flavor:" { fl = $2 }
        $1 == "file:" { f = $2 }
        $1 == "sha256:" && fl == "alpine-minirootfs" { print v, f, $2; exit }' "$WORK/releases.yaml")
    [ -n "$file" ] || { echo "minirootfs not found in latest-releases.yaml" >&2; exit 1; }
    log "Alpine $version minirootfs ($aarch)"
    curl -fsSL "$rel/$file" -o "$WORK/mini.tar.gz"
    echo "$sha  $WORK/mini.tar.gz" | sha256sum -c --quiet -
    tar -xzf "$WORK/mini.tar.gz" -C "$ROOT" --numeric-owner

    local branch="v${version%.*}"
    printf '%s\n' "$ALPINE_MIRROR/$branch/main" "$ALPINE_MIRROR/$branch/community" > "$ROOT/etc/apk/repositories"
    cp /etc/resolv.conf "$ROOT/etc/resolv.conf"
    chroot "$ROOT" apk add --no-cache openrc openssh busybox-openrc ifupdown-ng curl ca-certificates bash nano >/dev/null
    # Container mode: OpenRC skips kernel/hardware services; no gettys (the
    # console is reached through the agent).
    sed -i 's/^#\?rc_sys=.*/rc_sys="lxc"/' "$ROOT/etc/rc.conf"
    grep -q '^rc_sys=' "$ROOT/etc/rc.conf" || echo 'rc_sys="lxc"' >> "$ROOT/etc/rc.conf"
    sed -i '/getty/d' "$ROOT/etc/inittab"
    for svc in bootmisc hostname networking syslog; do chroot "$ROOT" rc-update add "$svc" boot >/dev/null; done
    for svc in sshd crond; do chroot "$ROOT" rc-update add "$svc" default >/dev/null; done
    chroot "$ROOT" rc-update add killprocs shutdown >/dev/null
    sshd_config
    chroot "$ROOT" passwd -l root >/dev/null 2>&1 || true
    echo localhost > "$ROOT/etc/hostname"
    : > "$ROOT/etc/resolv.conf"
    rm -rf "$ROOT"/var/cache/apk/* "$ROOT"/tmp/*
    NAME="Alpine Linux $version"
    STOP_SIGNAL="SIGUSR2"
}

case "$DISTRO" in
    debian) build_debian ;;
    alpine) build_alpine ;;
    *) echo "unknown distro $DISTRO" >&2; exit 1 ;;
esac

ASSET="rootfs-$DISTRO-$ARCH.tar.zst"
log "packing $ASSET"
tar --numeric-owner --xattrs --xattrs-include='*' -C "$ROOT" -cf - . | zstd -q -19 -T0 -o "$OUT/$ASSET" -f
SIZE=$(stat -c %s "$OUT/$ASSET")
UNPACKED=$(du -sb "$ROOT" | cut -f1)
SHA=$(sha256sum "$OUT/$ASSET" | cut -d' ' -f1)
cat > "$OUT/rootfs-$DISTRO-$ARCH.json" <<EOF
{"id": "$DISTRO", "name": "$NAME", "serial": "$SERIAL", "stop_signal": "$STOP_SIGNAL", "arch": "$ARCH", "file": "$ASSET", "sha256": "$SHA", "size": $SIZE, "unpacked_size": $UNPACKED}
EOF
log "done: $ASSET $((SIZE / 1048576)) MB packed, $((UNPACKED / 1048576)) MB unpacked"
