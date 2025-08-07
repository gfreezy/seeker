## 使用 tun-rs 的网络配置方法

`TunDevice` 现在支持使用 `tun-rs` 库的方法来配置 IP 地址、netmask 等网络参数，而不需要依赖外部的系统命令。

### 基础用法

```rust
use std::net::Ipv4Addr;
use tun_nat::tun_device::TunDevice;

// 方法 1: 创建设备后配置
let tun = TunDevice::new("my_tun")?;
tun.set_ipv4_address(Ipv4Addr::new(10, 0, 0, 1), 24, None)?;

// 方法 2: 创建时直接配置 IPv4
let tun = TunDevice::new_with_ipv4(
    "my_tun",
    Ipv4Addr::new(10, 0, 0, 1),
    24,
    None
)?;
```

### 支持的配置方法

#### 创建方法
- `new(name)` - 创建基础 TUN 设备
- `new_with_ipv4(name, address, netmask, destination)` - 创建并配置 IPv4
- `new_with_ipv6(name, address, prefix)` - 创建并配置 IPv6
- `new_with_mtu(name, mtu)` - 创建并设置 MTU

#### IPv4/IPv6 配置
- `set_ipv4_address(address, netmask, destination)` - 设置 IPv4 地址
- `add_ipv6_address(address, prefix)` - 添加 IPv6 地址
- `remove_address(address)` - 移除 IP 地址
- `addresses()` - 获取所有 IP 地址

#### 设备属性
- `set_mtu(mtu)` - 设置 MTU
- `mtu()` - 获取当前 MTU
- `set_enabled(enabled)` - 启用/禁用设备
- `if_index()` - 获取接口索引

#### MAC 地址 (TAP 设备)
- `set_mac_address(mac)` - 设置 MAC 地址
- `mac_address()` - 获取 MAC 地址

### 优势

1. **跨平台兼容** - `tun-rs` 处理平台差异
2. **类型安全** - 使用 Rust 类型而非字符串命令
3. **错误处理** - 统一的 `Result<T>` 返回类型
4. **性能更好** - 直接系统调用，无需启动外部进程
5. **功能丰富** - 支持更多高级网络配置

### 迁移指南

**之前使用 sysconfig::setup_ip:**
```rust
use sysconfig::setup_ip;
setup_ip("tun0", "10.0.0.1", "10.0.0.0/24", vec![]);
```

**现在使用 TunDevice:**
```rust
use tun_nat::tun_device::TunDevice;
let tun = TunDevice::new_with_ipv4("tun0", Ipv4Addr::new(10, 0, 0, 1), 24, None)?;
```
