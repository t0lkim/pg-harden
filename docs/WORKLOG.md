# pg-harden Work Log

**Project:** pg-harden — PostgreSQL security hardening scanner
**Repository:** `USER/CODE/pg-harden/` (nested git repo, branch: `main`)
**Language:** Rust (edition 2024)

---

## v0.2.1 (2026-02-11)

**Session:** Help text alignment patch

### Changes
- Aligned help text example descriptions to a consistent column in `pg-harden --help` output
- Version bumped to 0.2.1

### Commit
- `79f86f8` — "v0.2.1: Align help text example descriptions"
- 3 files changed, 16 insertions, 11 deletions

---

## v0.2.0 (2026-02-11)

**Session:** SPEC-001 review completion + pg-harden feature work

### Changes

#### CIDR Target Support
- `-H` now accepts IPv4 and IPv6 CIDR notation (e.g., `192.168.1.0/24`, `fd00::/120`)
- Blocks are expanded to individual host addresses via `ipnet` crate
- Network and broadcast addresses excluded automatically

#### Hostname DNS Resolution
- `-H` accepts hostnames (e.g., `db.example.com`)
- Resolved via `std::net::ToSocketAddrs` before scanning
- Dual-stack hosts (A + AAAA records) scan all resolved IPs
- Deduplication prevents scanning the same IP twice

#### Multi-Target Scanning
- `-H` is repeatable: `-H 10.0.0.1 -H 10.0.0.2 -H db.local`
- CIDR blocks, hostnames, and bare IPs can be combined freely
- Sequential scanning with per-host connection handling

#### Per-Host Report Grouping
- Multi-target text output: per-host headers with individual summaries + aggregate "Overall" line
- Single-target output: unchanged "Summary:" format (backwards compatible)
- JSON output: `hosts[]` array with per-host results and summary

#### Help Text
- `pg-harden --help` now includes 9 usage examples
- Subcommand hint: "Use \<COMMAND\> --help for more information"

### Architecture Changes

| File | Change |
|------|--------|
| `Cargo.toml` | Added `ipnet = "2"`, bumped version to `0.2.0` |
| `src/target.rs` | **NEW** — target resolution pipeline (CIDR expansion, DNS resolution) |
| `src/cli.rs` | `-H` from `Option<String>` to `Vec<String>`, `after_help` examples |
| `src/connection.rs` | New `ConnectParams` struct, decoupled from `ScanArgs` |
| `src/main.rs` | Multi-target scan loop with `scan_single_target()` |
| `src/output.rs` | `HostReport` sub-type, `ScanSummary::aggregate()`, per-host text/JSON |
| `src/lib.rs` | Added `pub mod target` |
| `CHANGELOG.md` | **NEW** — Keep a Changelog format with v0.1.0 and v0.2.0 entries |

### Commit
- `21624fc` — "v0.2.0: Add CIDR, hostname, and multi-target scanning"
- 9 files changed, 428 insertions, 82 deletions

---

## v0.1.0 (2026-02-10)

**Session:** Initial pg-harden implementation

### Features
- PostgreSQL security hardening scanner with 3 checks:
  - `auth-scram` — SCRAM-SHA-256 authentication verification
  - `ssl-enabled` — SSL/TLS connection enforcement
  - `auth-pghba` — pg_hba.conf audit for weak authentication methods
- Connection via TCP host (`-H`) or Unix socket (`-s`)
- Output formats: coloured text and JSON (`-f text|json`)
- Check filtering: include (`-c`) and exclude (`-x`)
- Offline mode (`--offline`) for file-based checks without a database connection
- Environment variable support: `PGHOST`, `PGPORT`, `PGUSER`, `PGPASSWORD`, `PGDATABASE`

### Commit
- `8f0b28e` — "Initial commit: pg-harden Phase 1 CLI skeleton"

---

## Integration with DevSecOps Skill Ecosystem

pg-harden is referenced in SPEC-001 as the first non-TypeScript tool in the ecosystem. It's integrated into the **InfraSecOps** skill as the `DatabaseAudit` workflow (added during SPEC-001 review, Issue #8 / pg-harden integration).

**SPEC-001 references:**
- InfraSecOps skill → DatabaseAudit workflow
- Tool: `pg-harden` (existing Rust binary, v0.2.1 with CIDR/DNS/multi-target)
- Named Agent: Niko Varga (Database Engineer) — assigned to DatabaseAudit workflow
- Named Agent: Sable Kai (Security QA) — finding validation and remediation verification across all workflows
- Workflow count: 42 → 43
