# Changelog

## Unreleased

### Improved

- Improve server performance `success_rate` calculation: use per-URL success ratio instead of binary per-round success. Previously, if any single ping URL succeeded, the entire round was marked as 100% success. Now `success_rate` accurately reflects the proportion of successful URL pings (e.g., 2/3 URLs success = 66.67%). The `success`/`failure` counters now track individual URL results.

### Refactor

- Replace `vmess_security` and `flow` fields from `Option<String>` to enum types (`VMessSecurity`, `VlessFlow`) for type-safe configuration parsing.
