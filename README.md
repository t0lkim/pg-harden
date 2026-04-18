# pg-harden

PostgreSQL security hardening scanner. Checks SCRAM authentication, SSL enforcement, pg_hba configuration, and public schema access against security best practices.

Scan, report, and enforce a deny-all security posture across your database fleet.

## Usage

```bash
pg-harden --host localhost --port 5432 --user admin
```

## What it checks

- SCRAM-SHA-256 authentication (rejects MD5)
- SSL/TLS enforcement
- pg_hba rules audit
- Public schema access restrictions
- Password policy compliance

## Language

Rust

## License

MIT
