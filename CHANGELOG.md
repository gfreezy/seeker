# Changelog

## Unreleased

### Improved

- Improve server performance `success_rate` calculation: use per-URL success ratio instead of binary per-round success. Previously, if any single ping URL succeeded, the entire round was marked as 100% success. Now `success_rate` accurately reflects the proportion of successful URL pings (e.g., 2/3 URLs success = 66.67%). The `success`/`failure` counters now track individual URL results.

### Refactor

- Replace `vmess_security` and `flow` fields from `Option<String>` to enum types (`VMessSecurity`, `VlessFlow`) for type-safe configuration parsing.
- Remove OpenSSL dependency. All symmetric crypto (AES-CFB/CTR, Camellia-CFB, AES-128-GCM, ChaCha20-Poly1305, AES-128-ECB) is now provided by pure-Rust RustCrypto crates. `OPENSSL_STATIC=yes` is no longer needed when building.
- Replace `native-tls` / `tokio-native-tls` with `rustls` / `tokio-rustls` across `http_proxy_client`, `trojan_client`, `vmess_client`, `vless_client`, `hysteria2_client`, and the seeker probe paths. A shared `tcp_connection::tls` helper (`get_tls_connector(insecure)`) builds a webpki-roots-backed `ClientConfig` with ALPN h2/http1.1.
- Upgrade `base64` from 0.20 to 0.22 (new `Engine` trait API; `FastPortable` → `GeneralPurpose`).
- Upgrade `ureq` from 2.5 to 3 (new `Agent` timeout configuration; `.set()` → `.header()`; response body accessed via `.into_body().into_reader()`).
- Prune unused workspace dependencies: drop `webpki-roots` from `vless_client`, `hickory-resolver` + `tempfile` from `hysteria2_client`, `tokio-rustls` from the top-level `seeker` crate.

### Removed

- CFB-1 (1-bit feedback) cipher variants (`Aes*Cfb1`, `Camellia*Cfb1`) no longer function — RustCrypto has no pure-Rust CFB-1 implementation, and these modes are deprecated legacy Shadowsocks stream ciphers. Existing configs using them will panic at connection time; switch to CFB-128 or, preferably, an AEAD cipher (`aes-128-gcm`, `chacha20-ietf-poly1305`).
