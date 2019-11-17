# Dump-cat [![Build Status](https://travis-ci.com/gfreezy/seeker.svg?branch=master)](https://travis-ci.com/gfreezy/seeker)[![Gitter](https://badges.gitter.im/AllSundays/seeker.svg)](https://gitter.im/AllSundays/seeker?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)
使用 Tun 实现 ss 透明代理（支持 Mac & Linux 系统），支持 TCP、UDP。

## Download
访问 https://github.com/gfreezy/seeker/releases 下载最新 release

```bash
chmod +x seeker-osx  # or  chmod+x seeker-linux
```
## Usage

1. 启动 `seeker`

    ```bash
    Seeker 1.0.0
    gfreezy <gfreezy@gmail.com>
    Tun to Shadowsockets proxy. https://github.com/gfreezy/seeker
    
    USAGE:
        seeker [OPTIONS] --config <FILE>
    
    FLAGS:
        -h, --help       Prints help information
        -V, --version    Prints version information
    
    OPTIONS:
        -c, --config <FILE>    Sets config file. Sample config at
                               https://github.com/gfreezy/seeker/blob/master/sample_config.yml
        -u, --uid <UID>        User id to proxy.
    ```
   
   ```bash
   sudo seeker --config path/to/config.yml
   ```
      
2. `seeker` 启动的时候会自动将本机 DNS 修改为 `127.0.0.1`，退出的时候将 DNS 设置为默认值

## Config

* `seeker` 直接使用的 clash 的规则。目前支持 `DOMAIN` `DOMAIN-KEYWORD` `DOMAIN-SUFFIX` `MATCH` 规则，
不支持 `IP` 相关的规则。
* 确保系统没有重复的 `tun_name` 
* 确保 TUN 的网络 `tun_ip` 和 `tun_cidr` 与当前所处网络环境不在一个网段
   
```yaml
server_config:
  addr: domain-or-ip-to-ss-server:port
  method: chacha20-ietf
  password: password
  connect_timeout: 5
  read_timeout: 30
  write_timeout: 30
  idle_connections: 10
dns_start_ip: 10.0.0.10
dns_server: 223.5.5.5:53
tun_name: utun4
tun_ip: 10.0.0.1
tun_cidr: 10.0.0.0/16

rules:
  - 'DOMAIN,audio-ssl.itunes.apple.com,DIRECT'
  - 'DOMAIN,gspe1-ssl.ls.apple.com,DIRECT'
  - 'DOMAIN-KEYWORD,itunes.apple.com,PROXY'
  - 'DOMAIN-KEYWORD,itunes.apple.com,PROXY'
  - 'DOMAIN-SUFFIX,apple.co,REJECT'
  - 'DOMAIN-SUFFIX,apple.com,REJECT'
  - 'MATCH,DIRECT'
```

## 重置 DNS 分配

```bash
rm -rf dns.db
``` 

## Build (rust >= 1.39)
```bash
git clone https://github.com/gfreezy/seeker.git
cd seeker
OPENSSL_STATIC=yes SODIUM_STATIC=yes SODIUM_BUILD_STATIC=yes cargo build --release
```

编译完成后，程序在 `target/release/seeker`。

## 实现原理
`seeker` 参考了 `Surge for Mac` 的实现原理，基本如下：

1. `seeker` 会在本地启动一个 DNS server，并自动将本机 DNS 修改为 `seeker` 的 DNS 服务器地址
2. `seeker` 会创建一个 TUN 设备，并将 IP 设置为 `10.0.0.1`，系统路由表设置 `10.0.0.0/16` 网段都路由到 TUN 设备
2. 有应用请求 DNS 的时候， `seeker` 会为这个域名返回 `10.0.0.0/16` 网段内一个唯一的 IP 
3. `seeker` 从 TUN 接受到 IP 包后，会在内部组装成 TCP/UDP 数据
4. `seeker` 会根据规则和网络连接的 uid 判断走代理还是直连
5. 如果需要走代理，将 TCP/UDP 数据转发到 SS 服务器，从 SS 接受到数据后，在返回给应用；如果直连，则本地建立直接将数据发送到目标地址

## 使用限制

只有通过域名访问网络的应用可以被代理。如果某个应用直接使用 IP 访问网络，则 `seeker` 对这类应用无效。

## License

Licensed under either of

 * Apache License, Version 2.0
   ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license
   ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
