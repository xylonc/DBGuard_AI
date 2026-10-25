# DBGuardAI roadmap to 16 Nov 2026

Source plan: "DBGuardAI End-to-End PostgreSQL Plan" (shared doc). This file is the working copy
for Claude Code; keep its status column current.

## Goal

1. **Task 1 — full PostgreSQL control set.** All 72 CIS PostgreSQL 17 v1.1.0 recommendations report a
   status with evidence; as many as safely possible get sandbox-proven fixes.
2. **Task 2 — screenshot evidence.** Before/after/rollback screenshots for every tested control.
   Rendered capture exists; add a VHS real-terminal mode (preferred by the supervisor). Sandbox evidence is enough.
3. **Task 3 — other operating systems.** Design done; build a runtime interface and one RHEL-family image if time allows.

## Control families (all 72 recommendations)

| Family | Count | CIS recommendations | Check | Fix |
| --- | --- | --- | --- | --- |
| F1 Fixed-value settings | 14 | 3.1.7, 3.1.11, 3.1.12, 3.1.16–3.1.23, 3.1.25, 6.9, 7.2 | `SHOW` + equals/in | `ALTER SYSTEM` + reload |
| F2 Richer comparison | 5 | 3.1.6, 3.1.14, 3.1.15, 3.1.24, 6.10 | new operators: severity order, contains tokens, mode limit, cipher subset | `ALTER SYSTEM` + reload |
| F3 Organisation policy | 8 | 3.1.2, 3.1.4, 3.1.5, 3.1.8, 3.1.9, 3.1.10, 3.1.13, 3.1.26 | compare with an approved policy profile | `ALTER SYSTEM` + reload |
| F4 Restart required | 3 | 3.1.3, 5.2, 7.4 | `SHOW` + operators | `ALTER SYSTEM` + restart (supported) |
| F5 Extensions | 4 | 3.2, 4.8, 5.6, 6.11 | preload libraries, `pg_extension` | package + preload + restart + `CREATE EXTENSION` |
| F6 Roles and privileges | 9 | 4.3, 4.4, 4.5, 4.6, 4.7, 4.9, 4.10, 5.5, 7.1 | named catalog queries vs allowlists | per-object proposals chosen by the DBA |
| F7 Authentication and TLS | 3 | 5.3, 5.4, 6.8 | `pg_hba_file_rules`, `ssl`, real connection attempts | structured `pg_hba.conf` edits; certificates |
| F8 Host and OS | 17 | 1.1–1.4, 1.6, 1.7, 2.1–2.4, 4.1, 4.2, 5.1, 6.7, 8.1–8.3 | read-only host collector | guided manual steps with evidence |
| F9 Review and procedure | 9 | 1.5, 6.1–6.6, 7.3, 7.5 | drift vs approved baseline; attestation | manual with sign-off |

Notes: CIS wording such as "at least `warning`" (3.1.14) needs a named human ruling. Syslog controls
(3.1.10–3.1.13) apply only when `log_destination` includes syslog. Never blanket-fix F6.

## Status

| Item | Status |
| --- | --- |
| Generalised loop, batch tests, restart settings, rendered screenshots | Done (live-demo-package) |
| One rulebook; selected control respected; combined fixes in DBA review | Done (PR #30, merged to main) |
| Spec schema v2 operators (F2) and coverage report of all 72 | Wave 0 remainder |
| F1 + F3 specs, policy profile, policy entries, live tests (27 controls) | Wave 1 |
| VHS real-terminal screenshots next to rendered capture | Task 2 |
| F4, F5, F7 (extension image, hba, TLS) | Wave 2 |
| F6, F8, F9 assessed and reported (no auto-fix) | Wave 3–4 (assessment only by 16 Nov) |
| Runtime interface + one RHEL-family image | Task 3 (if time) |

## Schedule

| Dates | Work |
| --- | --- |
| 26 Oct – 1 Nov | Wave 0 remainder; Task 2 VHS mode on sandbox stages |
| 2 – 8 Nov | Wave 1 (27 controls with screenshots); start Wave 2 |
| 9 – 13 Nov | Finish Wave 2 (37 fixed); F6/F8/F9 assessed; Task 3 runtime interface |
| 14 – 16 Nov | Freeze, live tests, demo rehearsal, handover notes |
