# Changelog — pg-harden

All notable changes to this project will be documented in this file.

## [Unreleased]

### 2026-03-20

#### Changed
- Rebuilt release binary (broken symlink from prior migration)
- Tested against PostgreSQL 18.3 on hardened Debian 13 LXC: 2/2 checks pass
  - SCRAM-SHA-256 authentication: PASS
  - SSL enabled: PASS

## [Prior History]

See git log for changes before 2026-03-20.
