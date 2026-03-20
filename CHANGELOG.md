# Changelog — pg-harden

All notable changes to this project will be documented in this file.

## [Unreleased]

### 2026-03-20

#### Added
- ARCH-001 architecture diagram
- specs/DENY-ALL-HARDENING.md — deny-all PostgreSQL security lockdown spec
  - Connection controls, authentication, privilege minimisation
  - Audit/logging, network, runtime security
  - BCP: backup/restore, HA/load balancing considerations
  - Internet-facing security checklist


#### Changed
- Rebuilt release binary (broken symlink from prior migration)
- Tested against PostgreSQL 18.3 on hardened Debian 13 LXC: 2/2 checks pass
  - SCRAM-SHA-256 authentication: PASS
  - SSL enabled: PASS

## [Prior History]

See git log for changes before 2026-03-20.
