# pg-harden

PostgreSQL security hardening scanner. Checks SCRAM authentication, SSL enforcement, pg_hba configuration, and public schema access against security best practices.

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

# Scan a subnet via CIDR
pg-harden scan -H 10.0.0.0/24

# Scan an IPv6 CIDR block
pg-harden scan -H fd00::/120

# Scan multiple targets
pg-harden scan -H 10.0.0.1 -H 10.0.0.2

# Custom port and user
pg-harden scan -H db.local -p 5433 -U admin

# Output as JSON
pg-harden scan -H db.local -f json

# Run a specific check only
pg-harden scan -H db.local -c auth-scram

# Exclude specific checks
pg-harden scan -H db.local -x ssl-enabled

# Offline mode — file-based checks without a database connection
pg-harden scan --offline --hba-file /etc/postgresql/pg_hba.conf

# Use environment variables
PGHOST=db.local PGUSER=admin PGPASSWORD=secret pg-harden scan -H db.local

# List all available checks
pg-harden list

# Verbose output
pg-harden scan -H db.local -v
```

## What it checks

- `auth-scram` — SCRAM-SHA-256 authentication (rejects MD5)
- `ssl-enabled` — SSL/TLS enforcement
- `auth-pghba` — pg_hba rules audit
- Public schema access restrictions
- Password policy compliance

## Language

Rust

## License

MIT
