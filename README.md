# pg-harden

PostgreSQL security hardening scanner. Checks SCRAM authentication, SSL enforcement, pg_hba configuration, and reject-all default rules against security best practices.

Scan, report, and enforce a deny-all security posture across your database fleet.

## Usage

```bash
# Get help
pg-harden --help
pg-harden scan --help

# Scan a single host
pg-harden scan -H 192.168.1.100

# Scan by hostname
pg-harden scan -H db.example.com

# Scan a subnet via CIDR (up to 256 hosts)
pg-harden scan -H 10.0.0.0/24

# Scan a larger CIDR block
pg-harden scan -H 10.0.0.0/16 --allow-large

# Scan an IPv6 CIDR block
pg-harden scan -H fd00::/120

# Scan multiple targets
pg-harden scan -H 10.0.0.1 -H 10.0.0.2

# Custom port and user
pg-harden scan -H db.local -p 5433 -U admin

# Require TLS for the scan connection itself
pg-harden scan -H db.local --ssl-mode require

# Verify the server certificate chain and hostname
pg-harden scan -H db.example.com --ssl-mode verify-full

# Output as JSON
pg-harden scan -H db.local -f json

# Run a specific check only
pg-harden scan -H db.local -c auth-scram

# Exclude specific checks
pg-harden scan -H db.local -x hba-reject-all

# Offline mode — file-based checks without a database connection
pg-harden scan --offline --hba-file /etc/postgresql/pg_hba.conf

# Use environment variables
PGHOST=db.local PGUSER=admin PGPASSWORD=secret pg-harden scan

# List all available checks
pg-harden list

# Verbose output
pg-harden scan -H db.local -v
```

## What it checks

- `auth-scram` — SCRAM-SHA-256 password encryption (rejects MD5)
- `ssl-enabled` — SSL/TLS enabled on the server
- `auth-pghba` — pg_hba.conf audit: flags `trust`, `password`, `md5`, and `ident` authentication, follows `include`/`include_dir` directives
- `hba-reject-all` — deny-all posture: `reject` rules for `0.0.0.0/0` and `::/0` must be the final pg_hba.conf entries

Further checks (public schema, privileges, logging, pgaudit) are planned — see `specs/DENY-ALL-HARDENING.md`.

## Connection notes

- Targets: `-H` (IP, hostname, or CIDR), `-s` (Unix socket directory), or the `PGHOST` environment variable when `-H` is omitted. `-s` cannot be combined with `-H`.
- `--ssl-mode` controls TLS for the scanner's own connection, with psql-style semantics: `disable`, `prefer` (default), `require` (encrypt, no CA verification), `verify-full` (verify chain and hostname against Mozilla CA roots). Honours `PGSSLMODE`. TLS is not attempted over Unix sockets.
- CIDR blocks larger than 256 hosts are rejected unless `--allow-large` is given. Targets are scanned 16 at a time.
- Exit codes: `0` all passed, `1` warnings only, `2` critical/high findings, `3` error.

## Language

Rust

## License

MIT
