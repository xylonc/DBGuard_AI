# DBGuardAI Collector

Reference documentation for `collector/`.

This directory contains the **evidence collector** — the first of four stages in
DBGuardAI (collect → assess → propose → validate). It reads the security-relevant
configuration of a PostgreSQL instance and writes it to a single JSON file.

Nothing downstream ever connects to the target database. The assessor, the
proposal engine and the sandbox all read the bundle and nothing else. That is the
core security property of the design: a DBA can read one static SQL file,
understand exactly what it selects, and approve it once.

---

## Contents

| File | Purpose |
|---|---|
| `collect.sql` | The collector. One SQL statement; PostgreSQL builds the entire bundle via `jsonb_build_object`. |
| `dbguard-collect.sh` | Thin wrapper. Preflight checks, invokes psql, atomic write on success. |
| `../run_tests.sh` | Nine-section Docker acceptance harness (20 checks). Lives at repo root. |

---

## What the wrapper does

The wrapper does **not** collect anything. It is the launcher and the safety rail.

1. Check `psql` is on `PATH` — exit `30` if not.
2. Check the connection works.
3. Invoke psql with `ON_ERROR_STOP=1`, passing `:'target_id'`.
4. Write psql's stdout to a **temporary file**.
5. `mv` the temp file into place **only if psql exited 0**.

Step 4–5 is the reason a failed run leaves nothing behind. A naive
`psql -f collect.sql > bundle.json` truncates the output file before psql starts,
so a mid-query failure leaves a corrupt bundle *and* destroys the previous good
one. `mv` within a single filesystem is atomic, so no reader can ever observe a
partially written bundle.

---

## Running it

Connection parameters come from standard libpq environment variables:

```sh
export PGHOST=db.example.internal
export PGPORT=5432
export PGUSER=dbguard_collector
export PGDATABASE=postgres

./dbguard-collect.sh
```

> Confirm the argument and output-path handling against the current script before
> relying on this block — the wrapper is the authority, this is a summary.

### Exit codes

| Code | Meaning | Bundle written? |
|---|---|---|
| `0` | Ran successfully. May contain recorded gaps. | Yes |
| `20` | Managed platform detected (RDS / Cloud SQL / Azure). Refused. | **No** |
| `30` | `psql` not found on `PATH`. | **No** |
| other non-zero | SQL or connection failure. | **No** |

Exit `20` is a deliberate scope decision, not a bug. On managed platforms
`pg_hba.conf` is unreadable, server files are inaccessible, and restarts are not
under your control — roughly a quarter of the CIS benchmark becomes unanswerable.
Producing a report that *looks* complete while silently omitting the
authentication rules is worse than refusing outright.

---

## The bundle

A single JSON object. Top-level keys are sections; there is also a `gaps` array.

### Absent vs. empty — the load-bearing distinction

This is the most important rule in the whole project.

| Value | Means |
|---|---|
| `[]` | Collected. There were none. |
| `null` + entry in `gaps` | **Could not collect.** Insufficient privilege, or the object does not exist on this version. |

"No roles use md5 passwords" and "I could not check password types" are entirely
different statements. Any system that conflates them will eventually tell someone
their database is fine when it is not.

Every `jsonb_agg` in `collect.sql` is therefore wrapped in
`coalesce(jsonb_agg(...), '[]')`.

### Responsibility split

- **The collector is permissive.** It gathers what it can and honestly records
  what it could not. It never fails the whole run over one inaccessible section.
- **The assessor is strict.** Any control depending on a gapped field routes to
  human review rather than being scored.

---

## What is collected, and why

The collector photographs the *lock hardware*, not the contents of the rooms.

| Section | Why it is there |
|---|---|
| Version / instance identity | CIS benchmarks are published per major version; control IDs are meaningless without it. |
| `pg_settings` | Most CIS controls are literally "is setting X equal to Y". Also captures `source` (file / command line / default) and `context` (restart / reload / instant) — remediation planning depends on both. |
| `pg_file_settings` | What is written on disk, including overridden and syntactically invalid lines. Not the same as the running value. |
| Roles and attributes | Login, superuser, createrole, createdb, connection limits, password expiry. The least-privilege control family. |
| Password **types** | `md5` vs `scram-sha-256`, derived from the stored value's prefix. The value itself never leaves the host. |
| Role memberships | Superuser inherited via a group is still superuser; attributes alone miss it. |
| Schema ACLs (`nspacl`) | The `public` schema `CREATE`-to-`PUBLIC` control. |
| Object ACLs, default ACLs | Names and owners only. Never columns, never rows. |
| RLS policies | Row-level security posture. |
| `pg_hba.conf` rules | Arguably the highest-value table in the bundle. Decides who may connect from where and how they must authenticate. A `trust` line means no password at all. |
| ident maps | Companion to hba. |
| TLS / SSL state | Whether ssl is on, ciphers, certificate file *paths* — never contents. |
| Extensions, tablespaces, foreign servers, event triggers | Attack surface, plus sandbox rebuild recipe. |
| Replication slots / publications | Replication connections are a lateral-movement path. |
| Host-side leak checks (6) | `.pgpass`, `PGPASSWORD` in environment, password on command line, `psql_history`, `pg_service.conf`, etc. Not in the database at all. |
| Connection summary | Grouped by application / user / database / client address. Not individual sessions. |

### Why non-security fields are present

The bundle has a second job: it is the recipe for reconstructing a lookalike of
the target inside Docker so proposed remediations can be tested before anyone
runs them on production.

The insight that made this tractable is that you do not replicate the *database*
— you replicate **the surface the benchmark inspects**. Configuration, identity,
access control. Stub tables with correct names, owners and kinds; no columns, no
rows, ever. That is why the field list is a few dozen items rather than an
impossible full-fidelity clone.

Running the collector against both target and sandbox and diffing the two bundles
turns sandbox fidelity from a caveat into a machine-checkable number.

### The sandbox carve-out

The six host-side leak checks go **false-green** in a fresh container — a new
container has no `.pgpass` and no shell history. They are scored from target
evidence only and are excluded from the target/sandbox diff.

---

## What is deliberately never collected

- Table data. Not one row.
- Column definitions.
- Password hashes. Only the *type* is derived.
- `primary_conninfo` and any connection string containing a password.
- TLS private keys.
- `ldapbindpasswd` and `radiussecret` — masked in hba options.

CIS controls check *properties* of secrets, never the secret values, which is
what makes this possible.

---

## Privileges

Least-privilege target role: `pg_monitor` + `pg_read_all_settings`.

Password type detection requires `pg_authid`, which is superuser-only. This is
the sole reason the `SECURITY DEFINER` wrapper function exists.

Under a reduced role the collector degrades rather than failing: privilege-
sensitive sections return `null` with a recorded gap and the run still exits `0`.
A CONNECT-only role produces a valid bundle full of gaps.

---

## Design invariants

Each of these was learned from a bug that shipped. Do not relax them.

**1. `ON_ERROR_STOP=1`, always.**
Without it psql returns exit 0 after a SQL error, and a broken query reaches the
assessor as a benign finding.

**2. Read `pg_authid`, never `pg_roles.rolpassword`.**
`pg_roles.rolpassword` is always the literal string `********`. Reading it reports
every login role in the cluster as storing a plaintext password.

**3. Every `jsonb_agg` wrapped in `coalesce(..., '[]')`.**
See absent-vs-empty above.

**4. `try_jsonb` catches only `insufficient_privilege` and
`undefined_table` / `undefined_function` / `undefined_column` / `undefined_object`.**
An earlier version caught `WHEN OTHERS`, which turned our own nested-aggregate bug
into "this data is absent." Never catch broadly here.

**5. Never rebuild JSON in bash.**
A role name containing a quote breaks hand-rolled string concatenation.
PostgreSQL knows how to escape its own data. The bash layer must remain unaware
of the bundle's structure.

---

## Testing

`run_tests.sh` at the repo root. Requires Docker on the host; psql is used inside
the container only.

```sh
./run_tests.sh ./collector
```

Nine sections, 20 checks, all passing against live PostgreSQL 16. Coverage
includes:

- Superuser run exits 0 and produces valid JSON
- CONNECT-only role exits 0 with gaps recorded (does not crash, does not produce
  an empty file)
- Deliberately broken SQL exits non-zero and writes nothing
- Managed platform (`CREATE ROLE rdsadmin NOLOGIN`) exits 20 and writes nothing
- No password hashes or plaintext passwords appear anywhere in the output
- `md5` and `scram-sha-256` roles are differentiated correctly

The md5 canary role requires `SET password_encryption = 'md5'` before creation,
since PostgreSQL 16 defaults to scram. That is test-fixture setup, not a
collector concern.

### Windows / Git Bash

- MSYS rewrites container paths — set `MSYS_NO_PATHCONV=1` and
  `MSYS2_ARG_CONV_EXCL='*'`.
- Windows Anaconda Python cannot open `/c/Users` MSYS paths; pass relative paths.
- CRLF line endings kill the wrapper at the shebang. Fix with a `.gitattributes`
  entry: `*.sh text eol=lf`.
- Pull files out of containers with `docker exec cat`, not `docker cp`.

---

## Known limitations

**Single database per run.** `schemas`, `object_acls`, `default_acls`,
`rls_policies` and `extensions` are scoped to the connected database. The CIS
public-schema `CREATE` control is per-database. On a multi-database cluster the
current collector assesses one database and silently misses the rest. Accepted
for now; a multi-database loop in the wrapper is the planned fix.

**Runtime gotcha — `context = superuser-backend`.** Settings with this context are
fixed at backend start time. A long-lived session can honestly report a value that
no longer matches the cluster's configured state. Cross-check against
`pg_file_settings` where it matters.

**Bundle validation is not yet enforced.** Structural validation of the bundle
moves to the FastAPI upload endpoint. There is currently no schema check between
the collector and whatever consumes the JSON.

**Managed platforms are out of scope**, by decision. See exit code 20 above.
