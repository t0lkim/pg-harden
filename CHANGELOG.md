# Changelog — pg-harden

## v0.4.0 (2026-08-10)

### Added
- `hba-reject-all` check (HIGH, enabled by default) — verifies pg_hba.conf ends with `reject` rules for `0.0.0.0/0` and `::/0`; flags unreachable entries after the reject-all
- `--ssl-mode` flag (env `PGSSLMODE`) — psql-style TLS for the scanner's own connection: `disable`, `prefer` (default), `require`, `verify-full` (rustls + Mozilla CA roots)
- pg_hba.conf `include` / `include_if_exists` / `include_dir` directive expansion (depth-limited, cycle-safe, `include_dir` files processed alphabetically)
- `--allow-large` flag required for CIDR blocks over 256 hosts
- Concurrent scanning — targets scanned 16 at a time (previously sequential)

### Fixed
- `PGHOST` env var no longer shadows explicit `-H` targets (was bound to `--socket`); it now acts as the target fallback when no `-H`/`-s` is given
- `-s`/`--socket` and `-H`/`--host` now error when combined instead of silently ignoring one
- pg_hba.conf parser handles the separate-netmask address form (`host db user 10.0.0.0 255.0.0.0 md5`), folding it to CIDR
- `ident` authentication is now flagged as dangerous alongside `trust`/`password`/`md5`
- Connection parameters built with `tokio_postgres::Config` instead of string formatting (passwords/hosts with spaces no longer break)
- The scanner can now audit servers that enforce SSL (`hostssl`-only pg_hba) — previously it connected plaintext-only
- File-based checks (`auth-pghba`, `hba-reject-all`) now error instead of silently passing when pg_hba.conf itself is unreadable — a remote scan previously `pass`ed a configuration it never read (the server's hba path doesn't exist locally)

### Changed
- `auth-scram` and `auth-pghba` severities raised from HIGH to CRITICAL, matching specs/ARCHITECTURE.md
- Binary now uses the library crate instead of compiling every module twice

### Removed
- Unused dependencies: `anyhow`, `toml`, tokio-postgres `with-serde_json-1` feature
- Dead code: `ConfigFile`/`ConnectionConfig`/`ChecksConfig` structs, never-constructed error variants

## v0.3.0 (2026-03-20)

### Added
- ARCH-001 architecture diagram
- specs/DENY-ALL-HARDENING.md — deny-all PostgreSQL security lockdown spec
  - Connection controls, authentication, privilege minimisation
  - Audit/logging, network, runtime security
  - BCP: backup/restore, HA/load balancing considerations
  - Internet-facing security checklist

### Changed
- Rebuilt release binary (broken symlink from prior migration)
- Tested against PostgreSQL 18.3 on hardened Debian 13 LXC: 2/2 checks pass

## v0.2.1 (2026-02-11)

### Changed
- Aligned help text example descriptions to a consistent column in `pg-harden --help` output

## v0.2.0 (2026-02-11)

### Added
- CIDR target support — `-H` accepts IPv4 and IPv6 CIDR notation (e.g. `192.168.1.0/24`, `fd00::/120`)
- Hostname DNS resolution — `-H` accepts hostnames (e.g. `db.example.com`), dual-stack supported
- Multi-target scanning — `-H` is repeatable, CIDR blocks, hostnames, and bare IPs combine freely
- Per-host report grouping — per-host headers with individual summaries plus aggregate "Overall" line
- 9 usage examples in `pg-harden --help`

### Architecture
- `src/target.rs` — target resolution pipeline (CIDR expansion, DNS resolution)
- `src/connection.rs` — `ConnectParams` struct, decoupled from `ScanArgs`
- `src/output.rs` — `HostReport` sub-type, `ScanSummary::aggregate()`, per-host text/JSON

## v0.1.0 (2026-02-10)

### Added
- PostgreSQL security hardening scanner with 3 checks:
  - `auth-scram` — SCRAM-SHA-256 authentication verification
  - `ssl-enabled` — SSL/TLS connection enforcement
  - `auth-pghba` — pg_hba.conf audit for weak authentication methods
- Connection via TCP host (`-H`) or Unix socket (`-s`)
- Output formats: coloured text and JSON (`-f text|json`)
- Check filtering: include (`-c`) and exclude (`-x`)
- Offline mode (`--offline`) for file-based checks without a database connection
- Environment variable support: `PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD`, `PGDATABASE`
