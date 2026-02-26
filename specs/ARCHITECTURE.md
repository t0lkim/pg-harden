# pg-harden - PostgreSQL Security Hardening Tool

**Status:** Design Complete
**Last Updated:** 2026-01-28
**Author:** Mike + Maia

---

## Overview

A focused Rust CLI tool for PostgreSQL security hardening. Runs locally on the database server or remotely via OpenSSH. Scans, reports, and applies security configurations with toggleable features and rollback capability.

### Design Principles

1. **Single binary** - No runtime dependencies beyond OpenSSH for remote mode
2. **Focused scope** - PostgreSQL hardening, optional OS hardening
3. **Non-destructive by default** - Scan and report without changes
4. **Reversible** - All changes can be rolled back
5. **Practical** - Real-world hardening, not checkbox compliance

---

## Execution Modes

### Local Mode

Run directly on the PostgreSQL server (LXC container or VM):

```bash
# Scan PostgreSQL security
pg-harden scan

# Include OS-level checks
pg-harden scan --os

# Apply hardening
pg-harden harden --profile standard
```

### Remote Mode (via OpenSSH)

Piggyback on existing SSH configuration and keys:

```bash
# Remote scan via SSH
pg-harden scan --ssh root@db-server.example.com

# With specific PostgreSQL user
pg-harden scan --ssh root@db-server.example.com --pguser postgres

# Through jump host
pg-harden scan --ssh root@db-server -J bastion@gateway
```

**Remote execution flow:**

```
┌────────────────────────────────────────────────────────────────────────────┐
│                            REMOTE EXECUTION FLOW                           │
├────────────────────────────────────────────────────────────────────────────┤
│                                                                            │
│   Local Machine                          Remote Host (LXC/VM)             │
│   ─────────────                          ───────────────────               │
│                                                                            │
│   ┌──────────────┐     SSH + SCP        ┌──────────────────┐              │
│   │  pg-harden   │ ─────────────────────▶│ pg-harden-agent  │              │
│   │    (CLI)     │                       │   (stateless)    │              │
│   └──────────────┘                       └────────┬─────────┘              │
│         ▲                                         │                        │
│         │                                         ▼                        │
│         │         JSON response          ┌──────────────────┐              │
│         │◀───────────────────────────────│   PostgreSQL     │              │
│         │                                │   + OS checks    │              │
│                                          └──────────────────┘              │
│                                                                            │
└────────────────────────────────────────────────────────────────────────────┘
```

**Agent lifecycle:**
1. CLI checks for cached agent on remote host (`~/.cache/pg-harden/agent`)
2. If missing/outdated, SCP copies agent binary
3. SSH executes agent with arguments
4. Agent outputs JSON to stdout
5. CLI parses and formats results
6. Agent remains cached for future runs (or `--no-cache` to remove)

---

## Commands

| Command | Purpose | Example |
|---------|---------|---------|
| `scan` | Assess security posture | `pg-harden scan` |
| `report` | Generate detailed report | `pg-harden report --format markdown` |
| `harden` | Apply security configurations | `pg-harden harden --profile standard` |
| `status` | Show current hardening state | `pg-harden status` |
| `diff` | Compare current vs recommended | `pg-harden diff` |
| `rollback` | Revert changes | `pg-harden rollback --last` |
| `baseline` | Save/compare baseline | `pg-harden baseline save` |

---

## PostgreSQL Hardening Checks

### Authentication

| Check | Description | Severity |
|-------|-------------|----------|
| `auth-scram` | SCRAM-SHA-256 enforced, MD5 disabled | Critical |
| `auth-pghba` | pg_hba.conf review (trust, password, reject rules) | Critical |
| `auth-password-policy` | Password complexity (if passwordcheck extension) | Medium |
| `auth-superuser-count` | Number of superuser roles | High |
| `auth-default-roles` | Dangerous default role memberships | Medium |

### SSL/TLS

| Check | Description | Severity |
|-------|-------------|----------|
| `ssl-enabled` | SSL is enabled | Critical |
| `ssl-version` | TLS 1.2+ only (no SSLv3, TLS 1.0/1.1) | High |
| `ssl-cert-valid` | Certificate not expired, chain valid | High |
| `ssl-require` | hostssl vs host in pg_hba.conf | High |

### Connection Security

| Check | Description | Severity |
|-------|-------------|----------|
| `conn-listen` | listen_addresses not '*' | High |
| `conn-max` | max_connections reasonable | Low |
| `conn-timeout` | idle_in_transaction_session_timeout set | Medium |
| `conn-superuser-reserved` | superuser_reserved_connections set | Low |

### Logging & Audit

| Check | Description | Severity |
|-------|-------------|----------|
| `log-connections` | log_connections enabled | Medium |
| `log-disconnections` | log_disconnections enabled | Low |
| `log-statement` | log_statement setting | Medium |
| `log-pgaudit` | pgaudit extension enabled and configured | High |
| `log-destination` | Log destination configured | Low |

### Privileges & Permissions

| Check | Description | Severity |
|-------|-------------|----------|
| `priv-public-schema` | Revoke CREATE on public schema | High |
| `priv-public-functions` | Function SECURITY DEFINER audit | Medium |
| `priv-role-inheritance` | Role inheritance review | Medium |
| `priv-default-privs` | Default privileges review | Medium |

### Extensions & Configuration

| Check | Description | Severity |
|-------|-------------|----------|
| `ext-risky` | Risky extensions (dblink, postgres_fdw, plpythonu) | High |
| `ext-required` | Required security extensions (pgaudit, pg_stat_statements) | Medium |
| `conf-preload` | shared_preload_libraries review | Medium |
| `conf-data-checksums` | Data checksums enabled | Medium |

### Network Exposure

| Check | Description | Severity |
|-------|-------------|----------|
| `net-port` | Non-standard port consideration | Low |
| `net-allowed-hosts` | pg_hba.conf allowed CIDR review | High |

---

## OS Hardening Checks (Optional)

Enabled with `--os` flag.

### File System

| Check | Description | Severity |
|-------|-------------|----------|
| `os-pgdata-perms` | PGDATA directory permissions (700) | Critical |
| `os-config-perms` | postgresql.conf, pg_hba.conf permissions | High |
| `os-socket-perms` | Unix socket permissions | Medium |
| `os-log-perms` | Log file permissions | Medium |

### Kernel & System

| Check | Description | Severity |
|-------|-------------|----------|
| `os-sysctl-shm` | Shared memory settings (shmmax, shmall) | Medium |
| `os-sysctl-hugepages` | Huge pages configuration | Low |
| `os-limits` | ulimit settings for postgres user | Medium |

### Service Configuration

| Check | Description | Severity |
|-------|-------------|----------|
| `os-systemd` | Systemd service hardening options | Medium |
| `os-postgres-user` | postgres user shell, home, groups | Medium |

### Firewall

| Check | Description | Severity |
|-------|-------------|----------|
| `os-firewall-5432` | Port 5432 exposure rules | High |
| `os-firewall-allowed` | Allowed source networks | High |

---

## Hardening Profiles

| Profile | Description | Changes |
|---------|-------------|---------|
| `minimal` | Essential security only | SSL, SCRAM-SHA-256 |
| `standard` | Recommended for most deployments | + logging, pgaudit, connection limits |
| `strict` | Maximum hardening | + role lockdown, extension restrictions |
| `custom` | Pick individual features | Via `--enable` / `--disable` flags |

### Feature Toggles

```bash
# Apply specific features only
pg-harden harden --enable ssl-enforce --enable scram-only --enable pgaudit

# Disable a feature
pg-harden harden --disable connection-limit

# See all available features
pg-harden features list
```

---

## Report Formats

```bash
# Markdown (default)
pg-harden report > security-report.md

# JSON (for automation)
pg-harden report --format json > report.json

# HTML (for sharing)
pg-harden report --format html > report.html

# With CIS Benchmark mapping
pg-harden report --format markdown --cis > cis-report.md
```

### Report Contents

1. **Executive Summary** - Pass/fail counts, severity breakdown
2. **Findings** - Each check with status, description, remediation
3. **Configuration Snapshot** - Current settings
4. **Recommendations** - Prioritized action items
5. **CIS Mapping** (optional) - Alignment with CIS PostgreSQL Benchmark

---

## Baseline & Drift Detection

```bash
# Save current state as baseline
pg-harden baseline save

# Save with name
pg-harden baseline save --name pre-upgrade

# Compare current to baseline
pg-harden baseline diff

# Compare to named baseline
pg-harden baseline diff --name pre-upgrade

# List baselines
pg-harden baseline list
```

---

## Rollback

All changes are tracked and reversible:

```bash
# Show change history
pg-harden rollback --list

# Rollback last change
pg-harden rollback --last

# Rollback specific change
pg-harden rollback --id 20260128-143022

# Rollback all changes
pg-harden rollback --all
```

**Rollback mechanism:**
- Before any change, backup affected files
- Store in `~/.pg-harden/backups/` (local) or `/var/lib/pg-harden/backups/` (system)
- Track change manifest with timestamps

---

## Configuration

### Config File

`~/.config/pg-harden/config.toml` or `/etc/pg-harden/config.toml`

```toml
[defaults]
profile = "standard"
format = "markdown"

[postgresql]
# Default connection (local mode)
host = "/var/run/postgresql"
port = 5432
user = "postgres"
database = "postgres"

[ssh]
# Default SSH options for remote mode
agent_path = "/tmp/pg-harden-agent"
cache_agent = true

[checks]
# Disable specific checks globally
disabled = ["os-sysctl-hugepages"]

[severity]
# Customize severity levels
auth-superuser-count = "critical"  # Override default "high"
```

---

## Exit Codes

For CI/CD integration:

| Code | Meaning |
|------|---------|
| 0 | All checks passed |
| 1 | Warnings present (medium severity) |
| 2 | Critical/high severity findings |
| 3 | Error (connection failed, etc.) |

```bash
# CI/CD usage
pg-harden scan --quiet
if [ $? -eq 2 ]; then
  echo "Security scan failed - critical issues found"
  exit 1
fi
```

---

## Implementation

### Tech Stack

| Component | Choice | Purpose |
|-----------|--------|---------|
| **Language** | Rust | Single binary, performance, safety |
| **CLI** | clap | Argument parsing, subcommands |
| **PostgreSQL** | tokio-postgres | Async database client |
| **SSH exec** | std::process::Command | Shell out to system OpenSSH |
| **Config** | toml + serde | Configuration parsing |
| **JSON** | serde_json | Report output, agent communication |
| **Markdown** | pulldown-cmark | Markdown report generation |

### Project Structure

```
pg-harden/
├── Cargo.toml
├── src/
│   ├── main.rs              # CLI entry point
│   ├── cli.rs               # Clap command definitions
│   ├── agent.rs             # Agent mode (for remote)
│   ├── checks/
│   │   ├── mod.rs
│   │   ├── auth.rs          # Authentication checks
│   │   ├── ssl.rs           # SSL/TLS checks
│   │   ├── connection.rs    # Connection checks
│   │   ├── logging.rs       # Logging/audit checks
│   │   ├── privileges.rs    # Privilege checks
│   │   ├── extensions.rs    # Extension checks
│   │   └── os.rs            # OS-level checks
│   ├── harden/
│   │   ├── mod.rs
│   │   ├── profiles.rs      # Hardening profiles
│   │   └── apply.rs         # Apply changes
│   ├── report/
│   │   ├── mod.rs
│   │   ├── markdown.rs
│   │   ├── json.rs
│   │   └── html.rs
│   ├── baseline.rs          # Baseline management
│   ├── rollback.rs          # Rollback functionality
│   ├── config.rs            # Configuration handling
│   └── ssh.rs               # SSH remote execution
├── tests/
│   └── integration/
└── README.md
```

### Implementation Phases

| Phase | Focus | Deliverables |
|-------|-------|--------------|
| **1** | CLI + PostgreSQL connection | Clap skeleton, local DB connection, 3 basic checks |
| **2** | All PostgreSQL checks | Complete check suite, severity levels |
| **3** | Reporting | Markdown, JSON, HTML output |
| **4** | Hardening | Apply changes, profiles, dry-run |
| **5** | Remote mode | SSH execution, agent |
| **6** | OS checks | File perms, sysctl, firewall |
| **7** | Baseline + Rollback | State management, undo |

---

## Example Session

```bash
# Initial scan
$ pg-harden scan
pg-harden v0.1.0 - PostgreSQL Security Hardening

Scanning PostgreSQL 16.2 at /var/run/postgresql:5432...

CRITICAL (2)
  [auth-scram]     MD5 authentication still enabled
  [ssl-enabled]    SSL is disabled

HIGH (3)
  [auth-pghba]     'trust' authentication found for local connections
  [priv-public]    CREATE privilege on public schema not revoked
  [ext-risky]      Extension 'dblink' is installed

MEDIUM (4)
  [log-pgaudit]    pgaudit extension not installed
  [conn-timeout]   No idle transaction timeout set
  ...

Summary: 2 critical, 3 high, 4 medium, 2 low
Exit code: 2

# Apply standard hardening
$ pg-harden harden --profile standard --dry-run
Would apply the following changes:

1. [ssl-enabled] Enable SSL
   - Set ssl = on in postgresql.conf
   - Requires: SSL certificate at /var/lib/postgresql/16/main/server.crt

2. [auth-scram] Enforce SCRAM-SHA-256
   - Set password_encryption = scram-sha-256
   - Update pg_hba.conf to use scram-sha-256

3. [log-pgaudit] Install and configure pgaudit
   - Add pgaudit to shared_preload_libraries
   - Requires: PostgreSQL restart

Run without --dry-run to apply changes.

# Apply for real
$ pg-harden harden --profile standard
Applying standard hardening profile...
[1/6] Enabling SSL... done
[2/6] Enforcing SCRAM-SHA-256... done
...

Hardening complete. 6 changes applied.
PostgreSQL reload required. Run: sudo systemctl reload postgresql

Changes saved to ~/.pg-harden/changes/20260128-143022.json
To rollback: pg-harden rollback --id 20260128-143022
```

---

## References

- [CIS PostgreSQL Benchmark](https://www.cisecurity.org/benchmark/postgresql)
- [PostgreSQL Security Documentation](https://www.postgresql.org/docs/current/security.html)
- [PGDSAT - PostgreSQL Database Security Assessment Tool](https://github.com/HexaCluster/pgdsat)

---

## Revision History

| Date | Author | Changes |
|------|--------|---------|
| 2026-01-23 | Mike + Maia | Initial 7-phase architecture (overengineered) |
| 2026-01-28 | Mike + Maia | Scaled back to focused hardening tool |
