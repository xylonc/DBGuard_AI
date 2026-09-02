# DBGuardAI SQL Collector — Three-CIS-Control Variant

Read-only PostgreSQL security posture snapshot tool.

## What it does

Runs against a PostgreSQL 12+ instance and collects exactly three CIS benchmarks:

1. **CIS 5.1** — `log_connections` setting (pg_settings row)
2. **CIS 5.2** — `CREATE` on schema `public` not granted to `PUBLIC` (per-database ACL)
3. **CIS 5.3** — No role uses `md5` password storage (per-role login flag + derived type)

## Setup

Run as superuser on the target database:

```bash
psql -f collector/grant_collector_role.sql
```

This creates the `dbguard_collector` role and the `dbguard_password_types()` SECURITY DEFINER function.

## Usage

```bash
# Connect as the collector role
PGUSER=dbguard_collector PGDATABASE=yourdb \
  collector/dbguard-collect.sh --target=myserver --output=./bundles

# Or connect as any user with read access
collector/dbguard-collect.sh --target=myserver --output=./bundles
```

Authentication uses standard libpq (PGPASSFILE, .pgpass, service files).

## Output

The bundle directory contains:

- `envelope.json` — metadata, status, gap/redaction records
- `sections/log_connections.json` — CIS 5.1 data
- `sections/public_schema_acl.json` — CIS 5.2 data
- `sections/password_storage.json` — CIS 5.3 data
- `SHA256SUMS` — integrity checksums
- `collector.log` — collection transcript

## Validation

```bash
cd /workspace/DBGuardAI
python3 collector/test/validate_schema.py <bundle-dir>
```
