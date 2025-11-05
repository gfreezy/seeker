# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Seeker is a transparent proxy implementation for Mac & Linux that uses TUN devices to route TCP and UDP traffic. It supports multiple proxy protocols (Shadowsocks, SOCKS5, HTTP/HTTPS) and implements rule-based routing similar to Surge for Mac.

## Build & Development Commands

### Building
```bash
# Standard build with static OpenSSL linking
OPENSSL_STATIC=yes cargo build --release

# Build output location
# target/release/seeker

# musl build (Linux static binary via Docker)
docker run -v $PWD:/volume -e OPENSSL_STATIC=yes --rm -t clux/muslrust cargo build --release
# Output: target/x86_64-unknown-linux-musl/release/seeker
```

### Testing
```bash
# Run all tests across workspace
cargo test --all

# Set DNS for tests (optional)
DNS=8.8.8.8 cargo test --all
```

### Code Quality
```bash
# Format check
cargo fmt --all -- --check

# Lint
cargo clippy --all
```

### Running Locally
```bash
# With local config file
sudo ./target/release/seeker --config config.yml

# With remote encrypted config
sudo ./target/release/seeker --config-url https://example.com/config --key encryption-key

# With logging
sudo ./target/release/seeker --config config.yml --log seeker.log

# Encrypt a config file for remote hosting
sudo ./target/release/seeker --config config.yml --encrypt --key your-key
```

### Release Process
```bash
# Install cargo-release if not already installed
cargo install cargo-release

# Create a new release tag (triggers GitHub Actions to build and publish)
./add-tag.sh
```

## Architecture Overview

### High-Level Design

Seeker implements transparent proxying by intercepting network traffic at the IP layer:

1. **DNS Interception**: Seeker runs a local DNS server that assigns fake IPs (from `dns_start_ip` range, e.g., 11.0.0.10+) to domain names, mapping them internally
2. **TUN Device**: Creates a virtual network interface (default: `utun4` on Mac, configurable `tun_name` on Linux) with IP `tun_ip` (e.g., 11.0.0.1)
3. **Traffic Routing**: System routes packets for the configured CIDR (e.g., 11.0.0.0/16) to the TUN device
4. **Packet Processing**: Seeker reads IP packets from TUN, reconstructs TCP/UDP streams, and applies routing rules
5. **NAT & Relay**: Uses session tracking to NAT connections and relay them through proxy servers or direct connections based on rules

### Workspace Structure

The project uses a Cargo workspace with these crates:

- **seeker/**: Main binary and application logic
  - `proxy_client.rs`: Core proxy orchestration, manages DNS, TUN, and relay servers
  - `server_chooser.rs`: Proxy server selection and health monitoring
  - `relay_tcp_stream.rs`, `relay_udp_socket.rs`: Traffic forwarding logic
  - `probe_connectivity.rs`: PROBE action implementation (race between direct/proxy)
  - `config_watcher.rs`: Hot-reload configuration file changes

- **tun_nat/**: TUN device management and NAT session tracking
  - Handles low-level packet routing and port mapping
  - Multi-queue support on Linux for performance

- **dnsserver/**: DNS server implementation
  - `resolver.rs`: Rule-based DNS resolution with fake IP assignment
  - Maps fake IPs back to domain names for rule evaluation

- **config/**: Configuration parsing and rule engine
  - `rule.rs`: Implements DOMAIN, DOMAIN-SUFFIX, DOMAIN-KEYWORD, IP-CIDR, GEOIP, MATCH rules
  - `server_config.rs`: Proxy server configuration (SS/SOCKS5/HTTP)

- **ssclient/**: Shadowsocks client implementation
- **socks5_client/**: SOCKS5 client implementation
- **http_proxy_client/**: HTTP/HTTPS CONNECT proxy client
- **crypto/**: Encryption implementations for Shadowsocks (multiple ciphers)
- **tcp_connection/**: TCP connection with obfuscation support (HTTP/TLS obfs)
- **sysconfig/**: System configuration management (DNS setup, IP forwarding, iptables)
- **store/**: SQLite-based persistent storage for DNS mappings and statistics
- **hermesdns/**: DNS protocol implementation

### Rule Actions

- **DIRECT**: Bypass proxy, connect directly
- **REJECT**: Block the connection
- **PROXY(group-name)**: Route through specified proxy group (auto-selects fastest server)
- **PROBE(group-name)**: Race direct connection vs proxy, cache results per domain

### Operational Modes

- **TUN mode** (default): Uses TUN device for all TCP/UDP traffic
  - Set `tun_bypass_direct: true` to bypass TUN for DIRECT action (better performance)
- **REDIR mode** (`redir_mode: true`): Uses iptables REDIRECT for TCP only (no UDP support)

### Key Configuration

- `dns_start_ip`: First IP in the fake IP range for DNS responses
- `tun_cidr`: CIDR range routed to TUN device (must not conflict with local networks)
- `gateway_mode`: Enable to proxy other devices on LAN (sets DNS to 0.0.0.0:53)
- `queue_number` & `threads_per_queue`: Linux-only performance tuning (macOS always uses 1 queue)
- `probe_timeout`: Timeout for PROBE action connection attempts
- `max_connect_errors`: Retries before switching to next proxy server

## Development Notes

- The project uses async-std for async runtime
- DNS mappings are persisted in SQLite (`seeker.sqlite`) - delete to reset
- Config file changes are auto-reloaded for rules (servers require restart)
- Use `tracing` for logging (spans are used extensively for debugging)
- Platform-specific code: macOS uses `nix` APIs, Linux uses `iptables` and multi-queue TUN
- Proxy groups support custom `ping_urls` and `ping_timeout` for health checks
- Remote config URLs support encryption with ChaCha20-IETF cipher