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
| Spec schema v2 operators (F2), applies_when / NOT_APPLICABLE, policy profiles, interpretation notes | Done on `melvin/wave1b-f2-f3-f4`, awaiting Gate 2 approval. Proof: `tests/test_spec_engine_wave1b.py`, `tests/test_wave1b_fixability.py` |
| Coverage report of all 72 | Not started (Wave 0 remainder) |
| F1 fixed-value settings (15 specs, 12 fixable, 2 manual checklist, 1 F7-deferred) | Done, merged (PR #32) |
| F2 + F3 + F4 (14 new specs; 3.1.14 now automated; 3.1.11/3.1.13 syslog applies_when; 6.10 moved to F7; Policy Profile screen; plain-language reasons) | Built on `melvin/wave1b-f2-f3-f4`, awaiting Melvin's spec + profile approval (Gate 2). Unit 1679 passed; live 32 passed / 1 skipped; combined 3.1.24 + 3.1.3 + 3.1.7 VERIFIED in the demo |
| F6 + 7.4 (10 report-only catalog checks with evidence; catalog checks out of the sandbox) | Built on `melvin/wave1b-f6-catalog`, awaiting Gate 2. Unit 1124 passed; live 35 passed / 1 skipped |
| Collector hardening (search_path/standard_conforming_strings pins; never ship secret-bearing setting text) | Done, merged (PR #33). Proof: `tests/test_collector_hardening.py`, `tests/test_collector_hardening_live.py` |
| Session overrides never PASS; redaction marker never evaluated | Built on `melvin/wave1b-f2-f3-f4`. Proof: `tests/test_session_override*.py`, `tests/test_redacted_secret_setting.py` |
| Production follow-ups | Real sign-in for approvals (approvals are DEMO-labelled); bind API port to localhost; persistent profile storage volume; retire legacy `/api/v1/sandbox/validate` + twin runner; MCP `snapshot_id` quoting; check `pg_hba_file_rules.error` for RADIUS secret echo; null sections without `gaps` entries |
| F6 fix proposals (password-free skeleton copy; per-role connection limits from the profile) | Next week |
| VHS real-terminal screenshots next to rendered capture | Task 2 |
| F5, F7 incl. 6.10 (extension image, hba, TLS) | Next week (Wave 2) |
| F8, F9 assessed and reported with guided manual steps (no auto-fix) | 9–13 Nov |
| Runtime interface + one RHEL-family image | Task 3 (if time) |

## Schedule

| Dates | Work |
| --- | --- |
| 26 Oct – 1 Nov | Wave 0 remainder; Task 2 VHS mode on sandbox stages |
| 2 – 8 Nov | Wave 1 (27 controls with screenshots); start Wave 2 |
| 9 – 13 Nov | Finish Wave 2 (37 fixed); F6/F8/F9 assessed; Task 3 runtime interface |
| 14 – 16 Nov | Freeze, live tests, demo rehearsal, handover notes |
