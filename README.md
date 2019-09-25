# Dump-cat [![Build Status](https://travis-ci.com/gfreezy/seeker.svg?branch=master)](https://travis-ci.com/gfreezy/seeker)[![Gitter](https://badges.gitter.im/AllSundays/seeker.svg)](https://gitter.im/AllSundays/seeker?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge)
使用 Tun 实现 ss 透明代理（支持 Mac & Linux 系统）

## Download
访问 https://github.com/gfreezy/seeker/releases 下载最新 release

```bash
chmod +x seeker-osx  # or  chmod+x seeker-linux
```
## Usage

1. 启动 `seeker`

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

## Build
```bash
git clone https://github.com/gfreezy/seeker.git
cd seeker
OPENSSL_STATIC=yes SODIUM_STATIC=yes SODIUM_BUILD_STATIC=yes cargo build --release
```

编译完成后，程序在 `target/release/seeker`。

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
