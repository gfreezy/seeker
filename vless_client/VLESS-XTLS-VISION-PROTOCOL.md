# VLESS + XTLS-rprx-Vision 协议交互详解

基于 Xray-core 源码分析，完整描述 VLESS 协议 + XTLS-rprx-vision flow 的交互过程。

---

## 1. 整体架构

```
应用程序 (Browser)
    |
    |  明文 HTTP / TLS (内层 TLS)
    v
+-----------------------------+
|  VLESS Client (seeker)      |
|  1. 建立外层 TLS 连接        |
|  2. 发送 VLESS 请求头        |
|  3. Vision 填充 (pad)        |
|  4. 检测内层 TLS 握手        |
|  5. 切换到 direct copy       |
+-----------------------------+
    |
    |  外层 TLS 1.3 (必须)
    v
+-----------------------------+
|  VLESS Server (Xray-core)   |
|  1. 解析 VLESS 请求头        |
|  2. Vision 去填充 (unpad)    |
|  3. 检测内层 TLS 握手        |
|  4. 切换到 direct copy       |
|  5. 连接目标服务器           |
+-----------------------------+
    |
    |  明文 HTTP / TLS (内层 TLS)
    v
目标服务器 (example.com)
```

**关键约束**: Vision flow **必须**运行在外层 TLS 1.3 之上。Xray-core 在连接建立后会检查 `ConnectionState().Version != tls.VersionTLS13`，如果不是 TLS 1.3 会直接返回错误。

---

## 2. 连接建立阶段

### 2.1 外层 TLS 握手

客户端先建立到 VLESS 服务器的 TCP 连接，然后进行 TLS 1.3 握手：

```
Client                          Server
  |--- TCP SYN ------------------>|
  |<-- TCP SYN+ACK ---------------|
  |--- TCP ACK ------------------>|
  |                                |
  |--- TLS ClientHello ---------->|   (外层 TLS)
  |<-- TLS ServerHello -----------|
  |<-- TLS EncryptedExtensions ---|
  |<-- TLS Certificate -----------|
  |<-- TLS CertificateVerify -----|
  |<-- TLS Finished --------------|
  |--- TLS Finished ------------->|
  |                                |
  |   外层 TLS 1.3 通道已建立      |
```

之后所有数据都在这个外层 TLS 通道内传输。

### 2.2 VLESS 请求头

TLS 握手完成后，客户端立即通过加密通道发送 VLESS 请求头：

```
+-------+------+----------+--------+-----+---------+---------+
| Ver   | UUID | Addons   | Addons | CMD | Port    | Address |
| 1byte | 16B  | Len 1B   | varlen | 1B  | 2B BE   | varlen  |
+-------+------+----------+--------+-----+---------+---------+
```

#### 各字段详解：

**Version** (1 byte): 固定 `0x00`

**UUID** (16 bytes): 用户认证 ID，以二进制原始字节写入（不是字符串形式）

**Addons Length** (1 byte): 后续 Addons protobuf 数据的长度

**Addons** (变长): Protobuf 编码的扩展数据。对于 Vision flow:

```protobuf
message Addons {
  string Flow = 1;   // "xtls-rprx-vision"
  bytes Seed = 2;    // 未使用
}
```

当 `Flow = "xtls-rprx-vision"` 时，protobuf 编码为：

```
0x0a                          // field 1, wire type 2 (length-delimited)
0x10                          // varint: 16 (字符串长度)
"xtls-rprx-vision"            // 16 bytes 字符串内容
```

总共 18 bytes。所以 Addons Length = 18。

当没有 flow 时，Addons Length = 0，没有 Addons 数据。

**Command** (1 byte):
- `0x01` = TCP
- `0x02` = UDP
- `0x03` = Mux

**Port** (2 bytes, Big Endian): 目标端口

**Address Type** (1 byte):
- `0x01` = IPv4，后跟 4 bytes IP
- `0x02` = Domain，后跟 1 byte 长度 + 域名字符串
- `0x03` = IPv6，后跟 16 bytes IP

**地址顺序**: Port 在 Address 前面（Xray-core 使用 `PortThenAddress()` 选项）。

#### 完整示例（连接 example.com:443）：

```
00                                     # Version = 0
b8 31 38 1d 63 24 4d 53               # UUID (前8字节)
ad 4f 8c da 48 b3 08 11               # UUID (后8字节)
12                                     # Addons Length = 18
0a 10 78 74 6c 73 2d 72 70 72         # Protobuf: tag + len + "xtls-rpr"
78 2d 76 69 73 69 6f 6e               # "x-vision"
01                                     # Command = TCP
01 bb                                  # Port = 443 (Big Endian)
02                                     # Address Type = Domain
0b                                     # Domain Length = 11
65 78 61 6d 70 6c 65 2e 63 6f 6d      # "example.com"
```

---

## 3. VLESS 响应头

服务器收到请求后，返回一个极简的响应头：

```
+-------+----------+--------+
| Ver   | Addons   | Addons |
| 1byte | Len 1B   | varlen |
+-------+----------+--------+
```

- **Version** (1 byte): 与请求相同，`0x00`
- **Addons Length** (1 byte): 通常为 `0x00`（服务器不发送 addons）
- **Addons** (变长): 通常为空

**响应头总共 2 bytes**: `0x00 0x00`

客户端在**第一次读取数据时**延迟消费这个响应头。

---

## 4. Vision 填充协议（核心）

Vision 的目标是消除 VLESS 数据流中的长度特征，使流量在外层 TLS 中看起来更像正常的 TLS 流量。

### 4.1 共享状态 (TrafficState)

一个连接的 Vision 处理共享以下状态（客户端和服务端各自维护一份）：

```
TrafficState {
    UserUUID: [16]byte               // 用于标识 Vision padded frame

    // TLS 检测状态（读/写共享）
    NumberOfPacketToFilter: 8        // 剩余需要检测的包数
    IsTLS: false                     // 是否检测到内层 TLS
    IsTLS12orAbove: false            // 是否 TLS 1.2+
    EnableXtls: false                // 是否启用 XTLS (TLS 1.3 + 支持的密码套件)
    RemainingServerHello: -1         // ServerHello 剩余长度
    Cipher: 0                        // 检测到的密码套件

    // 读方向的 padding 状态
    Read.WithinPaddingBuffers: true
    Read.RemainingCommand: -1
    Read.RemainingContent: -1
    Read.RemainingPadding: -1
    Read.CurrentCommand: 0
    Read.DirectCopy: false

    // 写方向的 padding 状态
    Write.IsPadding: true
    Write.DirectCopy: false
}
```

### 4.2 Vision Padded Frame 格式

每个 Vision padded frame 的结构：

```
+------+--------+-----------+-----------+---------+---------+
| UUID | CMD    | ContentLen| PaddingLen| Content | Padding |
| 16B  | 1byte  | 2B BE     | 2B BE     | varlen  | varlen  |
+------+--------+-----------+-----------+---------+---------+
  ^
  |
  仅第一个 frame 有 UUID 前缀
```

**UUID 前缀** (16 bytes): **仅第一个 padded frame** 带有 UUID。后续 frame 不再带 UUID。
- 读取端通过检测前 16 bytes 是否等于 UUID 来判断这是否是 Vision padded frame
- 如果不匹配，则认为是普通数据，直接透传

**Command** (1 byte):
- `0x00` = `PADDING_CONTINUE` — 后续还有 padded frame
- `0x01` = `PADDING_END` — 这是最后一个 padded frame，之后数据直接透传（无去填充开销）
- `0x02` = `PADDING_DIRECT` — 这是最后一个 padded frame，之后切换到 direct copy 模式（绕过外层 TLS，直接操作底层 TCP）

**Content Length** (2 bytes, Big Endian): 实际应用数据的长度

**Padding Length** (2 bytes, Big Endian): 随机填充的长度

**Content** (变长): 实际应用数据

**Padding** (变长): 随机填充字节（接收端直接丢弃）

### 4.3 Padding 长度计算

```go
// testseed 默认值: [900, 500, 900, 256]

if contentLen < testseed[0] && longPadding {
    // 长填充模式（TLS 握手阶段）
    paddingLen = rand(0, testseed[1]) + testseed[2] - contentLen
    // 即: rand(0,500) + 900 - contentLen
    // 效果: 把 frame 总长度拉到约 900-1400 bytes
} else {
    // 短填充模式
    paddingLen = rand(0, testseed[3])
    // 即: rand(0, 256)
}

// 不超过 buffer 上限
if paddingLen > bufSize - 21 - contentLen {
    paddingLen = bufSize - 21 - contentLen
}
```

**`longPadding`** 的值等于 `trafficState.IsTLS`。意思是只有检测到内层流量是 TLS 时才使用长填充。

---

## 5. 完整数据流交互（以 HTTPS 请求为例）

以浏览器通过 VLESS+Vision 代理访问 `https://example.com` 为例：

### 阶段 1: VLESS 连接建立

```
Client (seeker)                    VLESS Server (Xray-core)
   |                                    |
   |  [外层 TLS 1.3 已建立]             |
   |                                    |
   |--- VLESS Request Header --------->|
   |    Version=0, UUID, Flow=XRV      |
   |    CMD=TCP, Port=443              |
   |    Addr=example.com               |
   |                                    |
   |    状态: Write.IsPadding=true      |    状态: Read.WithinPadding=true
   |           NumberOfPackets=8        |           NumberOfPackets=8
```

### 阶段 2: 第一个写入 — 内层 TLS ClientHello

浏览器向代理发送 TLS ClientHello。这是第一个通过 Vision 发送的数据。

**写路径处理 (VisionWriter)**:

```
1. filter_tls(ClientHello 数据)
   → 检测到 data[0:2] == [0x16, 0x03] && data[5] == 0x01
   → 设置 IsTLS = true
   → NumberOfPacketToFilter = 7

2. 因为 IsTLS == true 但还不是 Application Data
   → command = PADDING_CONTINUE

3. 因为 IsTLS == true 且 contentLen < 900
   → 使用长填充: paddingLen = rand(0,500) + 900 - contentLen

4. 构建 frame:
   [UUID(16)] [0x00] [contentLen(2)] [paddingLen(2)] [ClientHello] [random padding]
    ^第一帧带UUID  ^CONTINUE
```

发送出去的数据:

```
Client                              Server
  |                                    |
  |--- Vision Padded Frame #1 ------->|
  |    UUID(16B)                       |
  |    CMD=0x00 (CONTINUE)             |
  |    ContentLen=ClientHello长度       |
  |    PaddingLen=长填充                |
  |    Content=TLS ClientHello         |
  |    Padding=random bytes            |
  |                                    |
```

### 阶段 3: 服务器响应 — VLESS 响应头 + 内层 TLS ServerHello

服务器连接 example.com:443，收到 ServerHello，通过 Vision 发回。

```
Server                              Client
  |                                    |
  |--- VLESS Response Header -------->|
  |    [0x00, 0x00] (2 bytes)          |
  |                                    |
  |--- Vision Padded Frame #1 ------->|   (服务端的第一帧，带 UUID)
  |    UUID(16B)                       |
  |    CMD=0x00 (CONTINUE)             |
  |    Content=TLS ServerHello         |
  |    Padding=长填充                   |
  |                                    |
```

**读路径处理 (VisionReader, 客户端侧)**:

```
1. 延迟解析 VLESS Response Header (2 bytes)

2. 读取后续数据，进入 XtlsUnpadding:
   - 检查前 16 bytes == UUID → 匹配
   - 跳过 UUID (16B)
   - 读取 5-byte frame header: command, contentLen, paddingLen
   - 提取 content（TLS ServerHello），跳过 padding

3. filter_tls(ServerHello 数据)
   - 检测到 data[0:3] == [0x16, 0x03, 0x03] && data[5] == 0x02
   → IsTLS = true, IsTLS12orAbove = true
   → RemainingServerHello = (data[3]<<8 | data[4]) + 5
   - 在 ServerHello 中查找 TLS13_SUPPORTED_VERSIONS 扩展 [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]
   → 如果找到 → EnableXtls = true, NumberOfPacketToFilter = 0
   → 如果没找到但 ServerHello 已结束 → TLS 1.2, NumberOfPacketToFilter = 0
```

### 阶段 4: 继续 TLS 握手（Certificate, Finished 等）

```
Server → Client: Vision Padded Frame (CONTINUE)
                  Content = TLS Certificate, CertificateVerify, Finished
                  注：后续 frame 不再带 UUID 前缀

Client → Server: Vision Padded Frame (CONTINUE)
                  Content = TLS Finished
```

这些 frame 的 command 都是 `0x00 (CONTINUE)`，因为还没有检测到 Application Data。

### 阶段 5: TLS Application Data — 结束填充

内层 TLS 握手完成后，浏览器发送加密的 HTTP 请求（作为 TLS Application Data record）。

**写路径（客户端发送 HTTP 请求）**:

```
1. filter_tls(数据)
   → NumberOfPacketToFilter 可能已经是 0，跳过

2. 检查: IsTLS == true && data[0:3] == [0x17, 0x03, 0x03]
   → 是 TLS Application Data!

3. 如果 EnableXtls == true:
   → command = PADDING_DIRECT (0x02)
   → Write.DirectCopy = true
   否则:
   → command = PADDING_END (0x01)

4. Write.IsPadding = false（填充阶段结束）

5. 构建最后一个 padded frame:
   [0x02] [contentLen(2)] [paddingLen(2)] [Application Data] [random padding]
    ^DIRECT (不带 UUID，因为不是第一帧)
```

```
Client                              Server
  |                                    |
  |--- Vision Padded Frame (最后) --->|
  |    CMD=0x02 (DIRECT)               |
  |    Content=TLS Application Data    |
  |    Padding=短填充                   |
  |                                    |
  |    此后所有数据直接透传             |
  |                                    |
  |--- Raw TLS Data ----------------->|   (不再有 Vision padding)
  |<-- Raw TLS Data ------------------|   (不再有 Vision padding)
```

### 阶段 6: Direct Copy 模式

一旦发送/接收了 `COMMAND_PADDING_DIRECT`：

- **写路径**: `Write.DirectCopy = true`，后续 `pad()` 直接返回原始数据
- **读路径**: `Read.DirectCopy = true`，后续 `unpad()` 直接返回原始数据

在 Xray-core 中，direct copy 甚至会绕过外层 TLS 的加解密，直接操作底层 TCP socket（利用 Go 的 `reflect` + `unsafe` 访问 TLS conn 的内部 `input`/`rawInput` buffer），实现零拷贝。这是 XTLS 性能优势的核心。

在 seeker 的 Rust 实现中，由于 `tokio-rustls` 不暴露这些内部 buffer，所以 direct copy 只是跳过 Vision 的 pad/unpad 逻辑，数据仍然经过外层 TLS。功能上等价于 `PADDING_END`。

---

## 6. 非 TLS 内层流量的处理

如果代理的目标不是 HTTPS（比如 HTTP 明文），内层流量不包含 TLS 记录：

```
1. filter_tls 在前 8 个包内没有检测到 TLS 特征
   → IsTLS = false, NumberOfPacketToFilter 递减到 0

2. 在 pad() 中:
   → IsTLS == false，不会触发 Application Data 检测
   → 但 !IsTLS12orAbove && NumberOfPacketToFilter <= 1 条件会触发
   → command = PADDING_END
   → Write.IsPadding = false

3. 后续数据直接透传（不填充）
```

这个兼容性分支确保非 TLS 流量不会永远卡在填充模式。

---

## 7. TLS 检测逻辑 (XtlsFilterTls)

### 检测的 TLS 记录类型

| 字节特征 | 含义 |
|---------|------|
| `[0x16, 0x03]` + `data[5] == 0x01` | TLS ClientHello |
| `[0x16, 0x03, 0x03]` + `data[5] == 0x02` | TLS ServerHello |
| `[0x17, 0x03, 0x03]` | TLS Application Data |

### TLS 1.3 检测

在 ServerHello 中搜索 `supported_versions` 扩展：

```
字节序列: [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04]
含义:
  0x00, 0x2b  → Extension Type = supported_versions (43)
  0x00, 0x02  → Extension Length = 2
  0x03, 0x04  → TLS 1.3 (0x0304)
```

如果找到，且密码套件不是 `TLS_AES_128_CCM_8_SHA256` (0x1305)，则 `EnableXtls = true`。

### 检测在哪里执行

| 方向 | 数据内容 | 谁执行检测 |
|------|---------|-----------|
| Client → Server (uplink write) | ClientHello, Finished, App Data | VisionWriter (pad 之前) |
| Server → Client (downlink read) | ServerHello, Certificate, App Data | VisionReader (unpad 之后) |

**关键**: 读和写**共享** `TrafficState`，所以写路径检测到的 `IsTLS` 也会影响读路径的 padding 行为，反之亦然。

---

## 8. Unpadding 状态机

读路径的去填充是一个状态机，处理跨包切割的情况：

```
                    ┌──────────────┐
                    │ 初始状态      │
                    │ Cmd=-1       │
                    │ Content=-1   │
                    │ Padding=-1   │
                    └──────┬───────┘
                           │
                    检查前 16 字节 == UUID?
                   ╱                     ╲
                  是                       否
                  │                        │
          跳过 UUID (16B)            直接透传数据
          Cmd=5                     (不是 padded frame)
                  │
                  v
          ┌───────────────┐
          │ 读 Frame Header│  (5 bytes)
          │ Cmd倒计数 5→0  │
          │ 5:command      │
          │ 4:contentH     │
          │ 3:contentL     │
          │ 2:paddingH     │
          │ 1:paddingL     │
          └───────┬───────┘
                  │ Cmd=0
                  v
          ┌───────────────┐
          │ 读 Content     │
          │ 提取实际数据    │
          │ Content倒计数   │
          └───────┬───────┘
                  │ Content=0
                  v
          ┌───────────────┐
          │ 跳过 Padding   │
          │ Padding倒计数   │
          └───────┬───────┘
                  │ Padding=0
                  v
          ┌───────────────┐
          │ 当前 block 完成 │
          └───────┬───────┘
                  │
          command == ?
         ╱        |        ╲
        0         1          2
   CONTINUE     END       DIRECT
        │         │          │
    Cmd=5      重置为       重置为初始
    继续下     初始状态     DirectCopy=true
    一个block  透传剩余     透传剩余
```

**跨包处理**: 一个 padded frame 可能被 TCP 分段切割，状态机通过保持 `RemainingCommand`/`RemainingContent`/`RemainingPadding` 的计数来正确处理跨包情况。seeker 的实现使用 `read_staging` 缓冲区来积累数据。

---

## 9. 完整时序图

```
Browser        Seeker (Client)              Xray Server              Target (example.com)
   |                |                           |                          |
   |                |--- TCP Connect ---------->|                          |
   |                |<-- TCP Connected ---------|                          |
   |                |                           |                          |
   |                |=== 外层 TLS 1.3 握手 ====>|                          |
   |                |<=== 外层 TLS 1.3 完成 ====|                          |
   |                |                           |                          |
   |                |--- VLESS Req Header ----->|                          |
   |                |    (Ver+UUID+Addons+CMD   |                          |
   |                |     +Port+Addr)           |                          |
   |                |                           |--- TCP Connect --------->|
   |                |                           |<-- TCP Connected --------|
   |                |                           |                          |
   |  TLS           |                           |                          |
   |  ClientHello   |                           |                          |
   |--------------->|                           |                          |
   |                | pad(ClientHello)           |                          |
   |                | → filter_tls → IsTLS=true |                          |
   |                | → CONTINUE + 长填充        |                          |
   |                |--- Vision Frame #1 ------>|                          |
   |                |   [UUID][0x00][clen]       | unpad → ClientHello      |
   |                |   [plen][data][padding]    |--- TLS ClientHello ----->|
   |                |                           |                          |
   |                |                           |<-- TLS ServerHello ------|
   |                |<-- VLESS Resp [0x00,0x00] -|                          |
   |                |<-- Vision Frame #1 -------|  pad(ServerHello)         |
   |                |   [UUID][0x00][clen]       |  → CONTINUE + 长填充     |
   |                |   [plen][data][padding]    |                          |
   |                | unpad → ServerHello        |                          |
   |                | filter_tls                 |                          |
   |                | → IsTLS12orAbove=true      |                          |
   |                | → 检查 TLS 1.3 扩展        |                          |
   |                | → EnableXtls=true          |                          |
   |  TLS           |                           |                          |
   |  ServerHello   |                           |                          |
   |<---------------|                           |                          |
   |                |                           |                          |
   |  ... TLS 握手继续 (Certificate, Finished) ... |                      |
   |                |--- Vision CONTINUE ------>|--- TLS Finished -------->|
   |                |<-- Vision CONTINUE -------|<-- TLS Finished ----------|
   |                |                           |                          |
   |  内层 TLS 握手完成                          |  内层 TLS 握手完成         |
   |                |                           |                          |
   |  HTTP Request  |                           |                          |
   |  (App Data)    |                           |                          |
   |--------------->|                           |                          |
   |                | pad(AppData)               |                          |
   |                | → data[0:3]==[0x17,0x03,0x03]                        |
   |                | → EnableXtls → DIRECT      |                          |
   |                | → IsPadding=false          |                          |
   |                | → DirectCopy=true          |                          |
   |                |--- Vision Frame (最后) --->|                          |
   |                |   [0x02][clen][plen]        | unpad → AppData          |
   |                |   [data][padding]           | → CurrentCommand=2       |
   |                |                           | → DirectCopy=true        |
   |                |                           |--- TLS App Data -------->|
   |                |                           |                          |
   |                |      此后所有数据直接透传，不再有 Vision padding         |
   |                |                           |                          |
   |  HTTP Resp     |                           |                          |
   |  (App Data)    |                           |                          |
   |<---------------|<-- Raw Data --------------|<-- TLS App Data ----------|
   |                |--- Raw Data ------------->|--- TLS App Data --------->|
   |                |                           |                          |
```

---

## 10. 关键实现要点

### 10.1 首包合并

Xray-core 客户端会尝试将 VLESS 请求头和第一个 payload 数据合并发送：

```go
// outbound.go: postRequest()
bufferWriter := buf.NewBufferedWriter(buf.NewWriter(conn))
encoding.EncodeRequestHeader(bufferWriter, request, requestAddons)
serverWriter := encoding.EncodeBodyAddons(bufferWriter, ...)

// 尝试在 500ms 内读取第一个 payload
multiBuffer, err := timeoutReader.ReadMultiBufferTimeout(500ms)
if err == nil {
    serverWriter.WriteMultiBuffer(multiBuffer)  // header + 第一个padded payload
} else if flow == XRV {
    // 超时也要发一个空内容的 padding frame 来伪装 header
    serverWriter.WriteMultiBuffer(make(MultiBuffer, 1))  // header + 空padding
}

bufferWriter.SetBuffered(false)  // flush 所有缓冲数据
```

这确保 VLESS 请求头不会单独作为一个 TLS record 发出去，减少特征。

### 10.2 UUID 只发一次

写路径第一个 padded frame 前缀 UUID (16 bytes)，之后 UUID 被 `take()` / 设为 nil，不再发送。

读路径只在初始状态（所有计数器 == -1）才检查 UUID 前缀。一旦进入填充解析循环，不再检查 UUID。

### 10.3 IsCompleteRecord 检查

Xray-core 在发送 Application Data 之前，会检查整个 multi-buffer 是否构成完整的 TLS records：

```go
isComplete := IsCompleteRecord(mb)
// 只有当数据是完整 TLS record 时才发 PADDING_END/DIRECT
if IsTLS && AppData && isComplete {
    command = PADDING_END/DIRECT
}
```

这避免在 TLS record 被切割时错误地结束填充。seeker 当前没有这个检查。

### 10.4 ReshapeMultiBuffer

Xray-core 在 padding 前会重新整形 buffer，确保每个 buffer 留有至少 21 bytes 空间给 Vision header（UUID 16B + command 1B + contentLen 2B + paddingLen 2B = 21B）。如果 buffer 太满，会在 `TlsApplicationDataStart` 位置切割。
