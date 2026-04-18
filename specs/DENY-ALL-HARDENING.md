# pg-harden — Deny-All PostgreSQL Hardening Specification

**Date:** 2026-03-20
**Status:** Draft
**Philosophy:** Locked down by default. Explicitly open what's needed. Like nftables drop-all inbound.

---

## Current Checks (v0.2.1)

- [x] SCRAM-SHA-256 authentication
- [x] SSL enabled

## Planned Checks — Deny-All Posture

### Connection Controls
- [ ] pg_hba.conf: reject-all default as final rule
- [ ] pg_hba.conf: no `trust` method anywhere
- [ ] pg_hba.conf: no `ident` method anywhere
- [ ] pg_hba.conf: no `md5` method (SCRAM-SHA-256 only)
- [ ] SSL mode: `require` (reject non-SSL connections)
- [ ] listen_addresses: not `*` unless explicitly justified
- [ ] max_connections: set to expected workload (not default 100)
- [ ] Connection limit per user (`ALTER ROLE ... CONNECTION LIMIT`)
- [ ] Connection limit per database (`ALTER DATABASE ... CONNECTION LIMIT`)
- [ ] Idle session timeout (`idle_session_timeout` — PG 17+)

### Authentication
- [ ] password_encryption = scram-sha-256 (no md5)
- [ ] No empty passwords (pg_authid check)
- [ ] No default postgres superuser password (not blank, not 'postgres')
- [ ] Password complexity: minimum length check via credcheck extension

### Privilege Minimisation
- [ ] No superuser connections from network (superuser local peer only)
- [ ] No CREATE privilege on public schema for PUBLIC
- [ ] REVOKE CONNECT ON DATABASE from PUBLIC (explicit grant per service)
- [ ] No GRANT ALL on schemas to non-owner roles
- [ ] pg_read_server_files role: no members
- [ ] pg_write_server_files role: no members
- [ ] pg_execute_server_program role: no members
- [ ] COPY TO/FROM PROGRAM: disabled or restricted

### Audit & Logging
- [ ] log_connections = on
- [ ] log_disconnections = on
- [ ] log_statement = 'ddl' (at minimum)
- [ ] log_line_prefix includes %h (host), %u (user), %d (database), %t (timestamp)
- [ ] log_destination includes 'syslog' or 'csvlog'
- [ ] pgaudit extension installed and configured
- [ ] Failed auth attempts logged (always on by default)

### Network
- [ ] SSL certificate valid and not self-signed (for internet-facing)
- [ ] SSL minimum protocol version: TLSv1.2+
- [ ] No trust-based access from 0.0.0.0/0 or ::/0

### Runtime Security
- [ ] shared_preload_libraries: no unnecessary extensions
- [ ] Data checksums enabled (initdb --data-checksums)
- [ ] Row-level security policies where applicable

### Backup & Recovery (BCP)
- [ ] WAL archiving enabled (for PITR)
- [ ] pg_basebackup accessible from backup host
- [ ] Backup retention policy configured
- [ ] Restore tested (documented last successful restore date)

### PostgreSQL HA / Replication / Load Balancing

Core database for all internal services — must survive single node failure.

**Architecture:** Primary + standby on separate PVE nodes, automatic failover, connection pooling.

- [ ] Streaming replication: primary (node-a) → standby (node-b), async by default
- [ ] Synchronous commit for critical databases (NetBox, future services)
- [ ] pgBouncer for connection pooling (reduces PG connection overhead)
- [ ] Automatic failover via Patroni (etcd-based) or repmgr
- [ ] Read replicas for read-heavy workloads (NetBox API queries)
- [ ] VIP for client connections (keepalived or Patroni-managed)
- [ ] pg_basebackup for standby initialisation
- [ ] WAL archiving to NFS for PITR (point-in-time recovery)
- [ ] Monitoring: replication lag, connection count, WAL size
- [ ] pg-harden checks for replication security (SSL between nodes, replication user permissions)

**Deployment plan:**
| Instance | Node | IP | Role |
|----------|------|----|------|
| pg-primary | node-a | 10.0.1.10 | Primary (read-write) |
| pg-standby | node-b | 10.0.1.11 | Standby (read-only, hot standby) |
| pg-vip | — | 10.0.1.12 | Client VIP (Patroni/keepalived) |
| pgbouncer | both | :6432 | Connection pooler |

**Services connecting to PostgreSQL:**
- NetBox (IPAM, DCIM)
- Future: OpenBao audit backend, Forgejo, monitoring

---

## Internet-Facing Considerations

When any application backed by this PostgreSQL instance is exposed to the internet:

1. **SSL required with valid cert** (not self-signed — Let's Encrypt or internal CA)
2. **pg_hba.conf: explicit IP allowlist** (no CIDR wider than /24)
3. **Connection rate limiting** at firewall level
4. **pgaudit on all DML** for forensic capability
5. **WAL archiving** for point-in-time recovery after compromise
6. **Separate database per application** with isolated users (no cross-database access)
7. **Network segmentation** — PostgreSQL on a dedicated data VLAN, not management

---

## Implementation Priority

1. **Immediate (next pg-harden release):** pg_hba analysis, trust/md5 detection, superuser network check, log_connections
2. **Short-term:** Privilege audit (public schema, dangerous roles), SSL enforcement, connection limits
3. **Medium-term:** pgaudit integration, backup verification, WAL archiving check
4. **Long-term:** HA/replication checks, connection pooling verification, automatic failover health
