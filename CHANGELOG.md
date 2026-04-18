# Changelog — pg-harden

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
