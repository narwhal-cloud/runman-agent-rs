# runman-agent

Runman 节点 agent（Rust 重写版）。它在宿主机上直接运行系统容器（完整的 Debian / Alpine，带 systemd 或 OpenRC 与 sshd），通过 `proto/agent.proto` 的 gRPC 长连接接受 Narwhal Cloud 平台的管理。协议与原 Go 版 agent 完全兼容，平台无需任何改动。

两种运行模式：

- **独立模式**（没有平台 Token，默认）：不连接平台，作为独立的切鸡服务使用。实例的开通、删除、重装、端口转发、WireGuard 独立 IP 都在节点自带的面板里管理。
- **平台模式**（设置了平台下发的 Token）：由 Narwhal Cloud 平台管理，面板只做查看和日常运维。

Token 只由平台生成，agent 和安装器从不自行生成。

只面向**全新安装**的节点，不接管旧版 agent 的 Podman / Incus / cloud-hypervisor 实例。设计与实测结论见 [DESIGN.md](DESIGN.md)。

## 功能

- **系统容器运行时**：每个实例独立的 user namespace（UID 段互不重叠）、cgroup v2 资源限制、按套餐大小的 ext4 磁盘、共享只读镜像模板；创建约 0.3 s，实例内 reboot 自动重启，`/dev/net/tun` 可用。
- **网络**：NAT4、端口转发（含新建实例自动分配的 SSH 端口）、实例间隔离与防地址伪造、上下行限速、流量统计；IPv6 支持 `none` / `snat` / `subnet`（同链路 /64 经 NDP 代理或路由前缀）。
- **WireGuard 独立 IP**：宿主机内核 WireGuard，独立 IPv4/IPv6 直接配在实例 `eth0` 上，出站、入站、监听都用它；私钥不进实例。
- **管理面板**（`:8792`）：节点概览、实例操作、浏览器终端、rfw 防火墙规则、Token 轮换。
- **自愈**：被其他工具清掉的 nftables 规则、被删除的实例网卡会自动恢复。
- **自更新**：只接受签名与校验和都正确的发布。

## 安装

要求：Debian 12+ / Ubuntu 22.04+（推荐 Debian 13），内核 ≥ 5.19，systemd 与 cgroup v2，KVM 虚拟机或物理机（不能在 LXC / OpenVZ 容器里运行）。

```bash
curl -fsSL https://github.com/narwhal-cloud/runman-agent-rs/releases/download/continuous/install.sh -o install.sh
bash install.sh                                  # 独立模式
bash install.sh --token '<平台下发的 Token>'      # 接入平台
```

安装完成后会打印面板地址和登录密码（只在首次安装时打印）。常用参数：

| 参数 | 说明 |
|---|---|
| `--token TOKEN` | 平台下发的 Token；省略则以独立模式运行 |
| `--web-listen 127.0.0.1:8792` | 面板只监听本机，通过 `ssh -L` 访问（推荐公网节点使用） |
| `--ipv6 auto\|none\|snat\|subnet` | 默认 `auto`：实测整段 /64 能否作为源地址后选择 `subnet`，否则 `snat` 或 `none` |
| `--ipv6-prefix CIDR --ipv6-uplink IFACE` | 手工指定 `subnet` 前缀 |
| `--bandwidth MBPS` | 上报给平台的上行带宽 |
| `--no-rfw` / `--rfw-iface IFACE` | 不安装 rfw / 指定 rfw 保护的网卡 |

- **升级**：重新运行 `install.sh` 即可，配置保持不变；默认也会自动更新。
- **卸载**：`bash install.sh --uninstall`（节点上还有实例时拒绝执行）；`--uninstall --purge` 会连同全部实例和数据一起删除。
- **忘记面板密码**：`echo '新密码' | runman-agent set-password`。
- **接入或断开平台**：`runman-agent set-token '<Token>'` / `runman-agent set-token --clear`，然后执行 `systemctl restart runman-agent`；也可以在面板「设置」里操作（立即生效）。节点上已有本地实例时接入平台要谨慎：平台会删除它数据库里没有的实例。

配置文件为 `/etc/runman-agent/config.toml`，全部配置项见 [config.example.toml](config.example.toml)。

## 发布与自更新

推送到 `main` 会发布 `continuous` 预发布版本，推送 `v*` tag 会发布正式版本（`.github/workflows/release.yml`）。每次发布包含：

- `runman-agent-linux-amd64`、`runman-agent-linux-arm64`（静态 musl 二进制）
- `install.sh`
- `SHA256SUMS` 与 `SHA256SUMS.sig`（对 `SHA256SUMS` 的 ed25519 签名）

节点只安装能用**编译进二进制的公钥**验证签名、且校验和匹配的版本，发现新版后随机延迟 0–6 小时再应用，以免整批节点同时重启（面板里可立即更新）。没有内置公钥的构建（例如本地编译版本）不会自动更新。

首次使用前生成签名密钥（私钥妥善保管，只放进仓库 secret）：

```bash
openssl genpkey -algorithm ed25519 -out update-signing-key.pem
# 仓库 Settings → Secrets and variables → Actions：
#   Secret   UPDATE_SIGNING_KEY = update-signing-key.pem 的完整内容
#   Variable UPDATE_PUBKEY      = 下面这条命令的输出
openssl pkey -in update-signing-key.pem -pubout -outform DER | tail -c 32 | base64
```

更换密钥后，已部署的节点仍只信任旧公钥，需要用新版 `install.sh` 重新安装一次才能继续自动更新。

## 实例镜像

官方镜像由本仓库自己构建，不依赖其他仓库或第三方现成镜像：`images/build.sh` 直接从 Debian 官方源（mmdebstrap，最小安装、不带推荐包和文档）和 Alpine 官方 minirootfs 构建根文件系统。`.github/workflows/images.yml` 每周一（以及 `images/` 有改动时）构建 amd64 和 arm64，生成 `images.json` 清单并用与自更新相同的密钥签名，发布到滚动更新的 `images` Release。

节点启动时以及每 6 小时同步一次：验证清单签名和每个文件的 SHA-256，有新版本就下载并作为新实例的默认版本；已有实例继续使用它们创建时的版本，没有实例使用的旧版本会被自动删除。

| 镜像 | 压缩包 | 解压后 | 128 MB 实例开机后的内存 |
|---|---|---|---|
| Debian 13 | 31 MB | 136 MB | 9 MB |
| Alpine 3.24 | 7 MB | 25 MB | 2 MB |

本地构建：`sudo bash images/build.sh debian amd64 dist`（需要 mmdebstrap 和 zstd，且必须在目标架构上运行）。

## 开发

```bash
cargo test                      # 单元、协议一致性（模拟平台）、面板测试；macOS 上也可运行
cargo zigbuild --release --target x86_64-unknown-linux-musl   # 静态二进制
```

运行时相关代码只在 Linux 上编译。需要 root 的集成测试会创建真实实例（首次运行要下载约 300 MB 镜像）：

```bash
sudo cargo test --release --test runtime_linux -- --ignored --test-threads=1
# 可选：RUNMAN_TEST_IMAGE_URL=http://127.0.0.1:8998  使用本地构建的镜像（images.json 所在目录）
# 可选：真实 /64 与 WireGuard 绑定
#   RUNMAN_TEST_V6_PREFIX=2001:db8:1:2::/64 RUNMAN_TEST_V6_UPLINK=eth0
#   RUNMAN_TEST_WG_CONFS=/root/wg4.conf,/root/wg6.conf   （wg-quick 格式）
```

测试使用独立的网桥、网卡前缀和 nftables 表，可以和正在运行的 agent 共存。

本地联调可以用模拟平台：`cargo run --example mock_platform -- 127.0.0.1:50051`，把 agent 的 `platform_url` 指向 `http://127.0.0.1:50051`，然后在标准输入里输入 `create <uuid> debian <密码>` 等命令（见 `examples/mock_platform.rs` 文件头）。

## 目录

```
proto/agent.proto     与平台共用的协议（不要修改）
src/platform/         gRPC 会话、命令执行、控制台路由
src/runtime/          容器运行时：supervisor、镜像、网络、WireGuard、流量统计
src/web/              管理面板（ui.html 内嵌进二进制）
src/updater.rs        自更新
src/detect.rs         IPv6 模式探测（install.sh 使用）
install.sh            安装 / 升级 / 卸载
```
