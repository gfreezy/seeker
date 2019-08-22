# Dump-cat [![Build Status](https://travis-ci.com/gfreezy/seeker.svg?branch=master)](https://travis-ci.com/gfreezy/seeker)
使用 Tun 实现 ss 透明代理（目前只支持 Mac 系统）

## Build
```bash
brew install libsodium
git clone https://github.com/gfreezy/seeker.git
cd seeker
cargo build --release
```

编译完成后，程序在 `target/release/seeker`。

## Usage

1. 启动 `seeker`

    ```bash
    sudo seeker --config path/to/config.yml
    ```
   
2. 修改本机 DNS 到 `127.0.0.1`

    ```bash
    networksetup -setdnsservers Wi-Fi 127.0.0.1
    ```

## Config

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
