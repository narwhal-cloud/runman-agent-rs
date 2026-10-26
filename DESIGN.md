# runman-agent (Rust) 设计

只面向**全新安装**的节点：不读取旧 Go agent 的 `config.json` / `agent.db`，也不接管 Podman/Incus/cloud-hypervisor 实例。

## 1. 与平台的契约（不可变）

`proto/agent.proto` 与 runman-v2 后端逐字一致。proto 之外的约定由 `src/platform/` 实现，并由 `tests/protocol.rs` 覆盖：

| 约定 | 说明 |
|---|---|
| 认证 | gRPC metadata `authorization: Bearer <token>`；`https://` 走 TLS（WebPKI 根证书） |
| 心跳 | 连上后立即一次，之后每 15 s |
| 保活 | 平台每 15 s 下发 `Ping`；60 s 没收到即判定连接已死，主动重连 |
| 命令回执 | 除 `Ping`、控制台帧、`WgSyncResponse` 外，每条命令**恰好一条** `CommandResult`；`CmdGetPortForwards` 改用 `PortForwardList` 回复 |
| WG 绑定 | Agent 每 20 s 发 `WgSyncRequest` 拉取全量期望状态，本地按 `resource_id` 收敛 |
| 重连 | 指数退避 5 s → 5 min；只有收到过平台消息的会话才重置退避 |
| 超时 | 平台对命令只等 **30 s**（`server.go: defaultWaitTimeout`），创建实例必须秒级完成 |

相对 Go 版的改进：

- 同一实例的命令严格串行（per-VM 锁），创建和删除不会互相踩。
- `command_id` 去重：平台重放正在执行的命令时不再执行第二次；已完成的命令直接回放缓存结果（保留 1 h）。
- 结果走「当前连接」：命令跨越断线重连完成时，结果也能送达新连接。
- 所有 `vm_id` 在协议边界校验为 UUID，后端永远拿不到可拼进路径的原始字符串；端口校验在 1–65535 范围内，密码不得含控制字符。
- 平台地址可配置（Go 版写死为 `hosting.fuckip.me:443`）。

## 2. 进程结构

```
runman-agent (单个静态 musl 二进制, systemd 单元)
├── platform/   gRPC 会话、命令执行、控制台路由        ← 已完成
├── runtime/    系统容器运行时                         ← 阶段 1
├── net/        网桥、nftables、端口转发、限速、IPv6/NDP、WG 独立 IP
├── store/      SQLite（实例、端口转发、流量计数）
├── metrics/    宿主机与实例指标（/proc、cgroup、nft 计数器）
└── web/        管理面板（axum）+ /rfw/ 反向代理
rfw (独立进程, 127.0.0.1:7734)   eBPF/XDP 防火墙，由 agent 安装与反代
```

`backend.rs` 中的 trait（`Instances` / `PortForwards` / `WgBindings` / `HostMetrics`）是协议层与实现之间唯一的边界；`fake.rs` 是测试用实现。

## 3. 系统容器运行时

卖的是「完整的 Linux」（systemd/openrc 作为 PID 1、sshd、root 密码），不是 OCI 应用容器，因此只实现所需子集，不做通用 OCI 运行时。

**隔离（已实现）**
- 每个实例有独立的 user namespace，UID 段互不重叠，容器里的 root 不等于宿主机 root。mount、pid、net、ipc、uts、cgroup namespace 全部启用，通过 `pivot_root` 进入 rootfs。
- **seccomp**（`src/runtime/seccomp.rs`）：拦截加载内核模块、kexec、`open_by_handle_at`，返回 EPERM，范围和 LXD 默认一致。过滤器按架构分别处理：x86_64 加 i386、aarch64 加 arm。32 位程序（例如 SteamCMD）照常可用，x32 ABI 整体拒绝。init 进程和控制台会话都会加载这个过滤器。这些调用在 user namespace 里本来就会因为权限不足而失败，seccomp 只是多加一道防线，以防这些路径上出现内核漏洞。
- **屏蔽宿主机信息**：和 Docker 的屏蔽范围一致。`/proc/{kcore,keys,latency_stats,timer_list,timer_stats,sched_debug,sysrq-trigger}` 覆盖为 `/dev/null`；`/proc/{acpi,scsi,asound}` 和 `/sys/firmware` 覆盖为空的只读 tmpfs；`/sys` 整体只读。
- **lxcfs**：把 `/proc/{meminfo,cpuinfo,stat,uptime,loadavg,diskstats,swaps,slabinfo}` 和 `/sys/devices/system/cpu` 绑定挂载为实例自己的视图。安装器给 lxcfs 加了 `--enable-cfs -l` 参数。lxcfs 只读取容器 cgroup 根自身的 `cpu.max` 来算 CPU 数，所以 supervisor 会把配额也写到 `ct` 上。
  - 实测：`free` 显示的是套餐内存，`/proc/cpuinfo` 显示的是套餐核数，`uptime` 是实例自己的运行时间。
  - `nproc` 仍显示宿主机核数：它读的是调度亲和性，只有把实例绑定到具体 CPU 核（cpuset）才能改变，目前没做。
  - 重启 lxcfs 会让运行中的实例失去这些视图，直到实例重启。安装器只在 lxcfs 参数变化时才重启它。

**宿主机内核参数**（由安装器写入 `/etc/sysctl.d/90-runman.conf`）：inotify、keys、pid_max、max_map_count、邻居表上限，以及 BBR。实测证实，inotify 实例上限是所有实例共用宿主机同一个用户的份额：宿主机总用量 86 时把上限设为 60，任何实例都无法再新建 inotify（EMFILE）。默认的 128 大约在开到第 14 个 Debian 实例时就会耗尽，届时所有实例里的服务都会开始启动失败。agent 启动时如果发现上限低于 8192，会记录警告。

**宿主机重启**（已在测试机上实测）：agent、rfw、lxcfs 开机自启；agent 按实例记录的期望状态重新拉起实例，并重建网桥、nftables 规则和端口转发。实例磁盘上的数据保留，IP 不变，lxcfs 视图和 seccomp 生效，流量计数在原累计值上继续增加（veth 接口编号变了，不会被当成计数器归零）。

**TUN 支持**：默认对每个实例开放 `/dev/net/tun`（cgroup 放行 `c 10:200 rwm`，并 bind mount 设备节点）。容器 root 在自己的 user namespace / network namespace 内拥有 CAP_NET_ADMIN，可以直接运行 WireGuard-go、OpenVPN、tailscale、sing-box TUN 模式，影响不到宿主机。按实例可关闭。

**资源**：cgroup v2 `cpu.max`（核数 × 100000/100000）、`memory.max` + `memory.swap.max`、`pids.max`、`io.max`。

**磁盘与 30 s 约束**（已实现，创建实测约 0.25 s）
- 镜像使用 narwhal-cloud/images 的预构建包，解压到 `images/<id>/<serial>/rootfs`，**保持原始属主**，所有实例共用、只读。
- 每个实例一个稀疏 ext4 文件 `disk.img`（`mkfs.ext4 -E lazy_itable_init` 不到 0.1 s），放 overlay 的 upper/work，容量就是套餐磁盘大小，容器里 `df` 显示正确，不依赖宿主机是 XFS。
- overlayfs 本身不支持 idmapped mount（实测返回 EINVAL），因此 supervisor 对**镜像层和磁盘层分别**做 idmapped bind，再由容器在自己的 user namespace 里挂 overlay（`userxattr`）。磁盘上的文件始终是未偏移的属主，宿主机离线编辑无需换算。
- 首次启动前由 agent 离线挂载 rootfs，写入主机名、root 密码哈希，清空 machine-id，删除镜像自带的 SSH host key（首启时重新生成），屏蔽容器里无法工作的 `sys-kernel-*.mount` 等单元，并禁用 cloud-init。所有写入都经 `openat2(RESOLVE_IN_ROOT)`，容器内的符号链接无法把宿主机 root 的写操作引到外面。
- 重装 = 删除实例后按新命令重新创建。

**进程模型**（已实现）
- 每个实例是一个 systemd 临时单元 `runman-<id>.service`（`Delegate=yes`、`PrivateMounts=yes`、`KillMode=mixed`），资源限制用 `MemoryMax`/`MemorySwapMax`/`CPUQuota`/`TasksMax`。agent 重启不影响实例。
- 单元主进程是 `runman-agent __supervise`（单线程，可 fork）：建 user namespace（每个实例独立的 65536 个 ID，从 1000000 起）、cgroup 委派（`<unit>/ct` 作为容器 cgroup namespace 的根）、idmapped 层、/dev（含 TUN）、devpts、pivot_root，然后执行 `/sbin/init`。
- 容器内 reboot（init 以 SIGHUP 结束）自动重新拉起；poweroff 或 `systemctl stop` 结束单元。停止信号按镜像设定（systemd 用 SIGRTMIN+4，busybox init 用 SIGUSR2），45 s 后仍未停止就 `cgroup.kill`。注意 SIGRTMIN 要按 glibc 的 34 计算（本程序是 musl，`libc::SIGRTMIN()` 为 35，会把关机变成重启）。

**控制台**（已实现）：agent 在宿主机分配 pty，启动 `runman-agent __exec`（单线程，依次 setns 进入容器的各个 namespace，再 fork 成为容器 pid namespace 内的进程）运行登录 shell，通过 `ConsoleIo` 通道与平台互通，resize 用 `TIOCSWINSZ`。

**重置密码**（已实现）：运行中通过 `__exec` 执行 `chpasswd -e`；停止时离线修改 `/etc/shadow`。哈希为 SHA-512 crypt。

## 4. 网络（已实现，`src/runtime/net.rs`）

- 网桥 `rmbr0`：IPv4 默认 `10.91.0.0/20`（网关 .1，可配置）。实例按序号分配固定地址，宿主机侧 veth 名为 `rv<序号>`，MAC 也按序号固定。地址在创建时写入实例自己的网络配置（Debian 用 networkd，Alpine 用 ifupdown），宿主机只负责建 veth、把 `eth0` 放进容器；不从外面直接配地址，因为 networkd 会删掉外来的路由。
- **隔离**：网桥端口开启 `isolated`，实例之间二层不通（网桥上转发的二层流量不经过 `inet` 表的 forward 链，必须在网桥层面处理）。`bridge runman` 表按「端口 . 源地址」白名单丢弃伪造的 IPv4、ARP、IPv6 源地址，并丢弃实例发出的 RA 和重定向。实例只能经端口转发互访（hairpin NAT 已支持）。
- **nftables**：独立的 `bridge runman` 和 `inet runman` 两张表，每次变更都整体重新生成，在同一个 `nft -f` 事务里原子替换，不碰其他表。`inet runman` 里有：
  - 出站 masquerade；
  - 端口转发 map，对外部入站和宿主机本机访问都生效；
  - 拦截实例从网桥访问宿主机上的服务。
- **端口转发**：存放在 `portforwards.json`，按实例 ID 记录，所以重装后地址变了也会自动跟随；拒绝宿主机已在监听的端口（例如宿主机的 22）。新建实例时自动在 20000–60000 范围内选一个端口映射到 22。
- **限速**：下行在宿主机 veth 出方向挂 cake；上行先把流量重定向到 IFB 设备 `rv<序号>i`，再挂 cake。最初用 police 做上行限速，实测把 TCP 压到了限速的四分之一，所以放弃。限速都在宿主机这一侧，容器 root 改不了。实测设 10 Mbit/s，上下行都在 9 Mbit/s 左右。
- **流量统计**：每 30 秒读一次宿主机 veth 的计数器，按增量累加写入 `traffic.json`；接口索引变化时把计数器视为从零重新开始。按月统计的起始日可配置（`traffic_reset_day`）。
- **IPv6**：
  - none：不配置 IPv6；
  - snat：ULA `fd91:cafe:cafe:10::/64`，经宿主机 masquerade 出站；
  - subnet：从公网前缀分配，实例地址从 `前缀 + 0x10000` 起，每个地址加一条 /128 路由到网桥。前缀和上行网卡在同一链路上时（配置了 `ipv6_ndp_uplink`），用内核 proxy_ndp 为每个地址做 NDP 应答，不再自己实现应答器。

  实例里地址都是 /128，网关统一是网桥的 `fe80::1`。subnet 模式已在带同链路 /64 的 Vultr VPS 上实测：实例出站源地址就是它自己的公网地址（无 NAT），外部探针 ping 该地址 0 丢包；删除实例后 NDP 代理条目和路由一并清除。
- **自愈**：agent 每 30 秒执行一次 `heal()`，修复被其他东西改掉的宿主机状态：
  - 重新应用 nftables 规则集。它是原子替换的，没变化时无副作用；比如 Debian 的 `nftables.service` 重载会执行 `flush ruleset`，这一步能恢复规则。
  - 检查每个运行中实例的宿主机侧 veth 是否还挂在网桥上。缺了就重建到实例现有的 network namespace 里，再让实例自己的网络服务重新配置 `eth0`。实例启动过程中还没有 `init.pid`，此时跳过，不和 supervisor 抢。
  - WG 同步时，发现隧道接口消失也会重建。

  这一机制是在测试机上发现问题后加的：在同一台机器上跑集成测试时，测试实例与正式实例的 veth 和 nftables 表重名，正式实例的 `eth0` 因此丢失。新版 agent 启动后自动修复了它。
- **命名**：veth 前缀 `rv`、WG 前缀 `rw`、WG 策略路由表起始号 20000、nftables 表名 `runman` 都可以配置（`[network]` 段）。只有在一台机器上跑多个 agent 时才需要修改，集成测试就是这样做的。
- **开启 IPv6 转发前**，所有 `accept_ra=1` 的网卡都先改成 2，否则宿主机通过 RA 学到的默认路由会在过期后消失（适用于所有 IPv6 模式）。

### WireGuard 独立 IP（已实现，`src/runtime/wg.rs`）

```
平台网关 ⇄ (UDP，走宿主机网络) ⇄ rw<n>（宿主机 netns）⇄ 路由 ⇄ rmbr0 ⇄ 实例 eth0（含独立 IP）
```

- **隧道**：每个绑定一个内核 WireGuard 接口 `rw<n>`，建在宿主机上，MTU 1420，私钥不进容器。私钥经 stdin 交给 `wg set`，不出现在命令行、文件和日志里。`wg.json` 只记录 resource → 序号、实例和地址，用于 agent 重启后清理，不含任何密钥。
- **出站**：`ip rule from <独立IP> lookup 20000+n`，该路由表只有一条 `default dev rw<n>`，不做 NAT。实例里默认路由的 `PreferredSource` 设为独立 IP，所以主动出站默认就用它；IPv4 和 IPv6 分别处理。
- **入站与监听**：独立 IP 以 /32 或 /128 加在实例的 `eth0` 上，服务可以直接 bind；宿主机在主路由表加 `<独立IP> dev rmbr0`。宿主机本身没有 IPv6 也能给实例 IPv6 独立 IP，此时会按需开启网桥上的 IPv6 转发。
- **防伪造白名单**加入独立 IP；进出 `rw*` 的 TCP 连接做 MSS 钳制。
- **同步**：
  - 每轮 `WgSyncResponse` 做全量收敛：没变化的绑定不碰，不会重置握手。
  - 每轮都重新解析 Endpoint 域名，按宿主机实际有 IPv4 还是 IPv6 来选结果，网关换 IP 时只更新 endpoint。
  - 地址或所属实例变了，就拆掉重建。
  - 某个绑定失败只记日志，下一轮重试，不影响其他绑定。
- **实例侧配置**：绑定变化时重新生成实例的网络配置。运行中的实例通过 exec 让它自己的 networkd 执行 reload 和 reconfigure（Alpine 是 ifdown 再 ifup），停止中的实例离线改文件。新建和重装时也会带上已有绑定。失败的实例会在下一轮重试。实例操作和 WG 同步通过运行时内部的按实例锁串行执行。
- **实测**（`tests/runtime_linux.rs::wireguard_dedicated_ips`，用平台下发的真实 IPv4 和 IPv6 配置，测试机本身没有 IPv6）：
  - 实例出站的 IPv4 和 IPv6 分别是对应的独立地址；服务可以 bind 独立 IP。
  - 从外部连独立 IP 的 IPv4 和 IPv6 的 22 端口都能拿到实例 sshd 的 banner。
  - 重装为 Alpine、agent 重启后由下一轮同步重建隧道，两种情况下独立 IP 都保持可用。
  - 解绑后恢复为宿主机出口；删除实例后没有残留的接口、规则和路由表。

依赖：宿主机需要 `wireguard-tools`（`wg`）和内核 WireGuard 模块，由安装器负责安装。

## 5. 管理面板与 rfw（已实现，`src/web/`）

- **面板**：axum 实现，默认监听 `0.0.0.0:8792`（`web_listen` 留空即关闭）。页面是一个嵌入二进制的单文件 HTML，终端用 xterm.js，从 jsdelivr 加载，加载不到时只有终端不可用。
- **认证**：
  - 用户名加 bcrypt 密码登录，会话 cookie 设为 HttpOnly、SameSite=Strict，12 小时滑动过期；agent 重启后所有会话失效。
  - 同一来源地址 10 分钟内失败 5 次就锁定登录。
  - 修改类请求还必须带 `X-Runman: 1`；WebSocket 只接受同源请求。
  - 修改面板密码后，其他会话全部失效。
- **功能**：
  - 概览：平台连接状态、入口 IP、宿主机指标、镜像、rfw 状态。
  - 实例列表：规格、IP、独立 IP、端口转发、本月流量。
  - 实例操作：开机、关机、强制关机、重启、重置 root 密码、浏览器终端、控制台日志。
  - 设置：入口地址、上行带宽、轮换对接 Token（轮换后立即重连平台）、修改面板密码。
- **两种模式**：Token 只由平台生成，agent 和安装器从不自行生成。
  - **独立模式**（Token 为空）：完全不连接平台。面板可以开通实例（不填密码时自动生成，自动分配 SSH 端口转发）、删除、重装，增删端口转发，以及粘贴 wg-quick 配置来绑定和解绑 WireGuard 独立 IP。独立 IP 的绑定连同密钥保存在 `<data_dir>/wg-local.json`（权限 0600），启动时、清除 Token 时和每次修改后都会经同一个 `WgBindings::reconcile` 生效。
  - **平台模式**（已设置 Token）：开通、删除、重装、端口转发、WG 绑定都返回 409，必须在平台上操作。平台数据库才是事实来源，本地新建的实例会被平台的孤儿清理删掉。
  - 从独立模式接入平台时，如果节点上已有实例，必须明确确认；清除 Token 会立即回到独立模式，并重新应用本地保存的独立 IP 绑定。
- **命令行**：`runman-agent set-password` 从 stdin 读密码；`runman-agent set-token <TOKEN>` 和 `runman-agent set-token --clear` 用于接入和断开平台，供安装器和运维使用。
- **rfw**：独立的 systemd 服务，API 只监听 `127.0.0.1:7734`。面板把 `/rfw/api/*` 反向代理过去，同样受会话和 CSRF 保护，规则页由面板自己实现。rfw 自带的页面把 API 路径写死为 `/api/...`，不适合挂在子路径下，所以不代理它的页面。
  - 实测：通过面板添加「入站 tcp 某端口 拦截」后，对应的端口转发立即不可达，删除规则后恢复。
  - 匹配顺序（rfw 实现）：启用的规则按优先级数字从大到小逐条比对，第一条命中的规则生效；优先级相同时先创建的先比对；都没命中则放行；最多 64 条启用中的规则生效。面板防火墙页写明了这些规则。
  - rfw 只处理 IPv4，IPv6 流量不经过它。WireGuard 独立 IP 的流量在隧道里是加密的，rfw 也看不到。
- **公网入口 IP** 每 5 分钟通过 ip.sb 探测一次，写进心跳。带宽改为在配置里填写 `bandwidth_mbps`，不再每次启动都测速。
- **开发工具** `examples/mock_platform.rs`：模拟平台，从 stdin 下发命令，打印心跳和回执。


## 6. 安装器原则

吸取旧 `install.sh` 的教训，新安装器只做：检查 root 与系统、等待 dpkg 锁（不 kill、不删锁文件）、装少量依赖、下载并校验二进制、写配置（只用 serde/jq 生成，不拼接字符串）、写入 systemd 单元。宿主机网络等复杂配置交给 agent 以幂等方式完成，可重复执行，失败可安全重跑。

## 7. 阶段

| 阶段 | 内容 | 状态 |
|---|---|---|
| 0 | 协议层、模拟平台、一致性测试、静态构建 | ✅ |
| 1 | 运行时核心：镜像模板、loop+overlay、namespaces/userns、cgroup、启停删重装、控制台、密码 | ✅ |
| 2 | 网络：网桥、nftables、端口转发、流量计数、限速、IPv6 | ✅ |
| 3 | WG 独立 IP、TUN | ✅ |
| 4 | Web 面板、rfw 集成、宿主机指标 | ✅（自更新挪到阶段 5） |
| 5 | 安装器、自更新（签名校验）、CI | ✅（工作流尚未在 GitHub 上运行） |
