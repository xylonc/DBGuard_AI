# DBGuardAI SQL Collector

A read-only PostgreSQL security posture snapshot tool. Designed to be run by a DBA on their own production host.

## What it does

1. Connects to a PostgreSQL 12–17 instance.
2. Runs read-only `SELECT` queries against system catalogs to collect security-relevant configuration.
3. Outputs a JSON bundle conforming to the `manifest.py` v0.2 schema.
4. The DBGuardAI application later loads this bundle, assesses it against CIS controls, and proposes remediations.

## What it **never** does

- **Never writes** to the target database (no `INSERT`, `UPDATE`, `DELETE`, `CREATE`, `ALTER`, `DROP`, `TRUNCATE`, `GRANT`, `REVOKE`, or `COPY FROM`).
- **Never handles credentials** — no password arguments, no prompts, no credential storage.
- **Never collects secrets** — password hashes, private keys, connection strings, archive commands, and service file passwords are all classified as S0 (never collected) or S1/S2 (masked/derived only).
- **Never reads log file content** — logs can contain `ALTER ROLE ... PASSWORD` statements in plaintext.

## Prerequisites

- **PostgreSQL 12–17** (client and server)
- **`psql`** in PATH (version ≥ 12)
- **POSIX sh/bash** (no GNU-specific flags)
- Standard libpq authentication: `PGHOST`, `PGPORT`, `PGUSER`, `PGDATABASE`, `PGPASSFILE`, or `.pgpass`/service files

### Required grants (minimum)

Run `grant_collector_role.sql` as a superuser, or run the collector with a role that has:

```sql
GRANT pg_monitor TO dbguard_collector;
```

### Optional grants (improved coverage)

| Grant | What it adds |
|-------|-------------|
| `GRANT pg_read_all_settings TO ...` | Full `pg_settings` coverage |
| `GRANT pg_read_server_files TO ...` | Config file content (postgresql.conf, pg_hba.conf, pg_ident.conf) |

Without optional grants, the collector gracefully records gaps with specific remediation hints.

## Usage

```bash
# Set authentication (standard libpq mechanism)
export PGHOST=prod-db.example.com
export PGUSER=dbguard_collector
export PGDATABASE=postgres

# Run the collector
./dbguard-collect.sh --target=my-server-id
```

Environment variables:

| Variable | Default | Description |
|----------|---------|-------------|
| `TARGET_ID` | `unknown` | Opaque identifier for the target (not a hostname) |
| `OUTPUT_DIR` | temp dir | Where to write the bundle. Omitted = temp dir with cleanup |
| `PGDATABASE` | `postgres` | Database to connect to |
| `PGUSER` | current OS user | PostgreSQL user |

## Output

The collector writes a directory, then tars it:

```
dbguard-<target_id>-<timestamp>/
  envelope.json               # Envelope model with gaps and redactions
  sections/                   # One JSON file per section
    instance.json
    configuration.json
    authentication.json
    privileges.json
    structure.json
    logging.json
    replication.json
    operational.json
  raw/                        # Verbatim config files (if readable)
    postgresql.conf
    postgresql.auto.conf
    pg_hba.conf
    pg_ident.conf
  SHA256SUMS
  collector.log
```

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Complete — no gaps |
| 10 | Partial — bundle written, gaps recorded |
| 20 | Refused: managed platform |
| 21 | Refused: unsupported version |
| 30 | Refused: cannot connect / psql missing |

## Sanitisation classes

| Class | Meaning |
|-------|---------|
| S0 | Never collected |
| S1 | Derived — only non-reversible projection |
| S2 | Sanitised — structure preserved, credentials replaced with `<redacted>` |
| S3 | Presence — boolean + location, never the matched content |
| S4 | Verbatim, confidential — full value, treated as confidential metadata |

See `COLLECTION_SPEC.md` for the authoritative field-by-field specification.

## Review before running

1. Read `dbguard-collect.sh` — verify it only runs `SELECT` and `SHOW` statements.
2. Read each `.sql` file in `queries/` — verify no data is extracted from user tables.
3. Run `grant_collector_role.sql` — verify it only creates a role and grants minimal privileges.
4. Check that your connecting user has the expected grants (at minimum `pg_monitor`).

## Running on a managed platform (RDS, Aurora, etc.)

The collector detects managed platforms and **refuses with exit code 20**. It does not collect a partial bundle. Managed platforms require a different collector because host-level controls cannot be assessed.
