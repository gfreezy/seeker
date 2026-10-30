# Hy2 用户态 Mimic

Linux 和 macOS 的 Seeker 客户端可以直接生成与 [Mimic](https://github.com/hack3ric/mimic) 兼容的 FakeTCP 报文。客户端不加载 eBPF、内核模块，也不建立内核 TCP socket。

```text
Hy2 / QUIC 数据报
  → Salamander（可选）
  → 用户态 Mimic 状态机、padding、IPv4/TCP 校验和
  → 独立 TUN / utun
  → 系统 IP 转发、NAT
  → 服务端 Mimic
  → 原有 Hy2 服务端
```

这是用户态 FakeTCP 协议实现，不启用普通 TCP 的流重组、数据重传或拥塞控制。每个 TCP 数据段保持一个 UDP 数据报的边界，丢包与乱序交给 QUIC 处理。smoltcp 用于报文编解码及校验和；握手、序列号、窗口探测、保活由 Mimic 状态机处理。IP 转发和 NAT 仍使用操作系统。

## 配置

在 Hy2 节点下增加 `mimic`，Seeker 原生格式和 Clash 格式均支持：

```yaml
servers:
  - name: hy2-mimic
    protocol: hy2
    addr: 203.0.113.10:443
    password: your-auth-password
    sni: server.example.com
    # obfs_password: your-salamander-password
    mimic:
      enabled: true
      padding: 0
      mtu: 1500
      # interface: en0        # Linux 通常为 eth0；默认按服务端路由推导
      # tun_name: utun8       # Linux 可用 mimic0；建议省略，由系统分配
```

- `enabled` 默认 `false`；未配置时仍走原有 UDP 传输。
- `xdpMode` 是官方 eBPF 客户端的挂载选项，Seeker 用户态实现无需配置此项。
- `padding` 默认 `0`，接受整数 `0..16` 或字符串 `random`，须与服务端 Mimic 设置一致。
- `mtu` 是外层 IP MTU，默认 `1500`，接受 `1280..9000`。客户端会扣除 IPv4/TCP、padding 和 Salamander 开销，并限制 QUIC 路径 MTU 探测上限。
- 每个连接使用独立的虚拟 `/30` 子网，取自 `198.19.0.0/16`。请为 Mimic 保留此地址段，避免与现有 VPN、路由或 Fake-IP 地址池重叠。

目前外层只支持 IPv4 服务器地址，代理目标仍可使用域名或 IPv6。此实现是客户端；服务端需要单独部署并配置兼容的 Mimic。服务端可继续使用官方的 eBPF 实现。

## 系统要求与清理

以 root 身份运行 Seeker。Linux 需要可用的 `/dev/net/tun`、`ip`、`iptables`、`sysctl`；容器还需要对应的 TUN 设备与网络管理权限。macOS 使用 `utun`、`route`、`pfctl`、`sysctl`，要求现有 PF 主规则中保留标准的 `com.apple/*` filter anchor 和 NAT anchor。

Seeker 为虚拟地址到指定服务器 TCP 端口添加 NAT 和转发规则。macOS 使用独立的 `com.apple/seeker-mimic-*` PF anchor 和 PF enable 引用，不重载主规则集。正常退出、握手失败及重连时，移除自己的规则、关闭接口并释放转发设置引用。最后一个 Mimic 连接关闭时恢复原有的 IP 转发开关。`SIGKILL`、进程崩溃或断电无法执行清理；可能需要管理员删除遗留的 iptables 规则／PF anchor，并恢复转发设置。

macOS PF 会保留已经清空的 anchor 名称；Seeker 按 utun 名复用这些空 anchor，避免重启时按进程号不断累积名称。

外层路径必须保持 TCP 数据段边界，不能经过会重组 TCP 字节流的代理。若服务端使用未加载 checksum hack 模块的原版 Mimic，须正确处理网卡 offload；本次验证环境关闭了测试网卡的 checksum/segmentation offload，并以 `QUIC_GO_DISABLE_GSO=true` 启动 Hy2 服务端。未关闭服务端 GSO 时，大流量会出现报文合并和错误校验和，认证或小包成功并不代表大流量可用。

## 验证方法

无需权限的报文、状态机和配置测试：

```sh
cargo test -p config -p hysteria2_client --lib
cargo check -p seeker
```

仓库提供一个需要 root 的实际互通探针，使用生产 `Hy2Client` 和 Quinn 传输实现：

```sh
cargo build -p hysteria2_client --example mimic_probe
sudo target/debug/examples/mimic_probe echo SERVER_IPV4:4443
sudo env MIMIC_BULK_MIB=64 target/debug/examples/mimic_probe hy2 SERVER_IPV4:4444
sudo env MIMIC_PADDING=random target/debug/examples/mimic_probe hy2 SERVER_IPV4:4444 SALAMANDER_PASSWORD
```

`echo` 检查 0、1、2、11、12、13、100、1200 字节及 MTU 边界的数据报。`hy2` 检查并发调用复用同一个 QUIC 连接、Hy2 认证、TCP 和 UDP 回显；设置 `MIMIC_BULK_MIB` 后还检查大流量逐字节一致性、4 路并发流和重连。`hy2` 模式使用测试认证密码 `mimic-test` 和自签名 TLS 证书，关闭证书校验，仅限隔离测试环境。

公网服务器可使用 `remote` 模式，认证字符串从权限为 `600` 的文件读取，避免放进命令行参数：

```sh
sudo target/debug/examples/mimic_probe remote SERVER_IPV4:8443 server.example.com /path/to/auth-file
```

此模式启用服务器 TLS 证书校验，通过代理访问 `https://example.com`（同样校验证书），再通过代理查询公共 DNS。探针不将认证字符串写入日志。

HTTP/3 关键流生命周期的回归测试无需 root 或 Docker：

```sh
cargo test -p hysteria2_client --features integration-tests --test h3_lifecycle
```

服务端测试前提：

1. 运行 `python3 hysteria2_client/tests/mimic_services.py`，提供 UDP `4443` 回显及 Hy2 的 TCP `18080`、UDP `18081` 目标。
2. 启动官方 Hy2，监听 UDP `4444`，密码 `mimic-test`，使用测试证书；测试 Salamander 时配置同一 obfs 密码。
3. 在实际出口网卡上启动原版 Mimic，例如 `mimic run eth0 -f local=0.0.0.0:4443 -f local=0.0.0.0:4444 --xdp-mode skb`。测试 padding 时追加 `-p 16` 或 `-p random` 并同步设置客户端 `MIMIC_PADDING`。
4. 服务端保留默认的握手重试参数。所验证版本的 `handshake=0:3` 会令服务端半开连接超时变为 0，延迟／丢包时会错误重置连接。
5. 客户端与服务端必须处于不同网络命名空间或不同机器，避免本机回环绕开 Mimic。

测试前后对比接口列表、转发开关、iptables／PF 规则；错误端口的握手测试也应恢复到测试前的状态。探针直接调用生产客户端，不会启动 Seeker 的 DNS、全局代理路由或修改系统 DNS。

## 本次验证记录（2026-10-30）

参考服务端：Mimic `c8d46732c84808beba2cd85d1161da0f78ac9e0b`、官方 Hy2 `v2.10.0`。macOS ARM64 为本机实测，Linux ARM64 为独立容器／网络命名空间实测；Linux 客户端没有挂载 eBPF 程序，外层没有内核 TCP 连接。

| 验证项 | macOS | Linux |
| --- | --- | --- |
| 原版 Mimic 数据报互通，含 0/1 字节和 MTU 边界 | 通过 | 通过 |
| Hy2 认证、TCP／UDP 回显 | 通过 | 通过 |
| padding 0、16、random，random + Salamander | 通过 | 通过 |
| 64 MiB 回显逐字节校验，窗口更新 | 通过 | 通过 |
| 4 路并发流、关闭后重连 | 通过 | 通过 |
| 5 ms 延迟、2% 丢包、乱序，各连续 5 轮 | 通过（服务端出口模拟） | 通过（双向模拟） |
| 正常退出、拒绝连接、握手超时后清理 | 通过 | 通过（含转发开关 0→1→0） |
| 完整 Seeker：Fake DNS → 主 TUN → Hy2/Mimic → TCP／UDP 回显 | 未运行全局代理 | 通过 |

配置与 Hy2 库的 83 项单元测试、原有 6 项 Hy2 集成测试及新增的 HTTP/3 生命周期回归测试通过，两平台 Seeker 编译通过。联调中同时修复了原有 UDP 固定长度头编码，以及认证后过早终止 H3 驱动导致服务器以 `H3_CLOSED_CRITICAL_STREAM`（`0x104`）关闭连接的问题。回归测试可重现修复前的关闭码，并确认修复后连接保持有效。Linux 网络监听忽略虚拟 TUN 的链路／地址事件，避免创建 Mimic 接口触发全连接重置。

另以 macOS 用户态客户端连接公网 Mimic/Hy2 服务器，通过服务器 TLS 校验、Hy2 认证、代理 HTTPS（HTTP 200）及 UDP DNS 查询。修复 H3 生命周期后，两组重复测试共 8 次，7 次完整成功（最后连续 5 次均通过），1 次在 Mimic 握手阶段收到 RST，发生在 QUIC/TLS/认证之前。该偶发重置的原因尚未确认，不能据此认定公网连接已稳定。

### 公网 RST 复查

随后在实际出口 `en14` 上抓包并重新连接 10 次：7 次完整通过服务器 TLS、Hy2 认证、HTTPS 200 和 UDP DNS，3 次收到远端地址发来的 RST。测试前后本机 IP 转发均为 `0`，Mimic 的 PF filter/NAT 规则均已清空。

失败报文均为 `RST, seq=0, ack=0, window=0`，校验和正确。其中两次先收到正常的 SYN-ACK，客户端在不到 0.5 ms 内发出正确的 ACK，但分别在收到 SYN-ACK 后约 48 ms 和 117 ms 收到 RST；这两次的 SYN/SYN-ACK 往返耗时分别约 206 ms 和 156 ms。另一次没有捕获到 SYN-ACK，在 SYN 后约 730 ms 收到 RST。

上游代码存在一个与此现象吻合的参数冲突：

- [Hysteria 的 `filtersFor`](https://github.com/HyNetworks/hysteria/blob/ca8fbd874fd6ca82413948de6dc5924405e103e1/app/internal/mimic/mimic_linux.go) 会自动给服务端 filter 加 `handshake=0:3`，用于禁止服务端主动发起 FakeTCP 连接；用户配置中没有写 `extraArgs` 也可能带上此参数。
- [Mimic 的 `do_routine`](https://github.com/hack3ric/mimic/blob/v0.7.1/src/run.c) 对 `CONN_SYN_RECV` 使用 `(retry + 1) * interval` 判断超时，`0:3` 的阈值为 `0`，下一轮定时检查即可重置半开连接。
- [Mimic 的 `conn_reset`](https://github.com/hack3ric/mimic/blob/v0.7.1/common/defs.h) 将序列号清为 `0`，随后发出的 RST 与抓包格式一致。

### SSH 只读确认

在用户授权的 SSH 只读检查中，已确认公网服务器运行 Hysteria `v2.13.0`（commit `ca8fbd874fd6ca82413948de6dc5924405e103e1`）和 Mimic `0.7.1`。服务为 `hysteria-mimic.service`，监听 `:8443`，Mimic 挂载于 `ens3`、XDP 模式为 `skb`。配置中的 `mimic` 只有 `enabled`、`interface` 和 `xdpMode`；`handshake=0:3` 是 Hysteria 自动生成的 filter 参数。

`mimic show ens3` 显示全局默认值为 `handshake 2:3`，但 8443 的四条 filter 均显式覆盖了 interval，显示 `handshake=0:`（retry 沿用默认值 `3`）。因此不能只看全局 Settings 来判断实际握手参数。

服务端 journal 与上一轮 10 次测试中的三次失败逐一对应：

| 客户端出口端口 | 接受连接时间（UTC） | 服务端记录超时（UTC） | 接受后多久超时 |
| --- | --- | --- | --- |
| 33879 | 06:30:38.867031 | 06:30:38.916061 | 49.030 ms |
| 42342 | 06:30:46.798589 | 06:30:46.916163 | 117.574 ms |
| 41043 | 06:30:52.400120 | 06:30:52.916417 | 516.297 ms |

三次均先记录 `accepting connection`，随后记录 `connection destroyed (timed out)`；超时发生在同一秒内，并集中在周期性检查的相同相位。这与客户端捕获的远端 RST 一致，确认该组失败由服务端过早清理半开连接引起。

本次只读取版本、进程参数、实际 filter、配置的 `mimic` 区块和相关日志，没有修改线上文件、filter 或系统设置，也没有重启服务。检查结束时服务主进程仍为 PID `98587`，状态 `active`，`NRestarts=0`。修复方向是给被动握手保留非零等待时间，或修复 Mimic 在被动模式下的半开连接超时逻辑；本次未在生产环境实施调整。全局 `-h 2:3` 不一定能覆盖 filter 中显式写出的 `handshake=0:3`，不能直接据此判断已修复。
