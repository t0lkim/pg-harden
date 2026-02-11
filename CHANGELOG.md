# Changelog

All notable changes to pg-harden are documented in this file.

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-02-11

### Added

- **CIDR target support:** `-H` accepts IPv4 and IPv6 CIDR notation (e.g., `192.168.1.0/24`, `fd00::/120`). Blocks are expanded to individual host addresses and scanned sequentially.
- **Hostname DNS resolution:** `-H` accepts hostnames (e.g., `db.example.com`). Addresses are resolved via DNS before scanning. Dual-stack hosts (A + AAAA records) scan all resolved IPs.
- **Multi-target scanning:** `-H` is now repeatable. Multiple hosts, CIDRs, and hostnames can be combined in a single invocation (e.g., `-H 10.0.0.1 -H 10.0.0.2 -H db.local`).
- **Per-host report grouping:** Multi-target scans display results grouped by host with individual summaries and an aggregate "Overall" line. JSON output includes a `hosts[]` array with per-host results.
- **Top-level help examples:** `pg-harden --help` now includes usage examples and a hint to use `<COMMAND> --help` for subcommand details.
- **New module: `target.rs`** — target resolution pipeline handling IP parsing, CIDR expansion, and DNS resolution.
- **New dependency: `ipnet 2`** — for CIDR block parsing and host enumeration.

### Changed

- `-H`/`--host` changed from single `Option<String>` to `Vec<String>` (repeatable, multi-value).
- `connection.rs` refactored to use `ConnectParams` struct instead of taking full `ScanArgs`, decoupling connection logic from CLI.
- `ScanReport` restructured with `HostReport` sub-type for per-host result grouping. Single-host output format unchanged for backwards compatibility.
- Removed unused `get_data_directory` and `use_socket` functions.

## [0.1.0] - 2026-02-10

### Added

- Initial release.
- PostgreSQL security hardening scanner with 3 checks: SCRAM authentication, SSL/TLS enabled, pg_hba.conf audit.
- Connection via TCP host or Unix socket.
- Output formats: text (coloured) and JSON.
- Check filtering via `-c` (include) and `-x` (exclude).
- Offline mode (`--offline`) for file-based checks without a database connection.
- Custom pg_hba.conf and postgresql.conf paths via `--hba-file` and `--config-file`.
- Environment variable support for connection parameters (`PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD`, `PGDATABASE`).
