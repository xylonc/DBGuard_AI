# F6 + CIS 7.4 — Gate 2 (implementation, tests, reviews)

Branch `melvin/wave1b-f6-catalog` (worktree `wonderful-wilbur-8162a2`), base `main` @ d9639bd. **Approved by Melvin on
29 Oct 2026** ("ok please proceed with the gate 2 updates and commit"); committed, not pushed. Gate 1 and its rulings: `docs/gates/F6-gate1.md` (§6 records Melvin's round-1 rulings).

## 1. What now works

Ten CIS PG17 v1.1.0 recommendations report a status with evidence and are never fixed:

| Rec | Tier | Result on the re-recorded live fixture | How |
| --- | --- | --- | --- |
| 4.3, 4.4, 4.6, 4.7, 4.9, 7.1 | manual_checklist | MANUAL with an evidence list | `manual_review` (4.6/4.7: `databases_not_covered`) |
| 4.5 | manual_checklist | MANUAL `databases_not_covered` (the `postgres` DB is connectable) | PASS `empty_review_set` only when no function matches and every connectable DB is covered |
| 4.10 | manual_checklist | PASS `empty_review_set` | Never PASS from hba; GAPPED if `password_types` is unknown |
| 5.5 | **automated** | FAIL `unlimited_connections` (dbguard_poc at -1) | Flagged only; per-role fix proposals next week |
| 7.4 | **automated** | FAIL `archive_mode_off` | Melvin's PASS/FAIL ruling; always carries the restore-test reminder |

- **Catalog check kind.** A spec names an evaluator from a fixed, read-only registry
  (`backend/app/services/spec_engine/catalog_checks.py`); specs contain no SQL. Each registry entry is bound to
  one recommendation and its tiers, lists the sections it reads, the CIS constants it hard-codes
  (`quote_tokens`, checked as whole tokens in the verbatim quote) and the settings that can change its inputs
  (`setting_inputs`). Catalog checks never carry `proof`, never appear in the collector manifest, and
  `planning.fix_scope` rejects them. Their Findings are always `MANUAL_PROCEDURE`, non-automatable.
- **Unknown is never PASS.** A null section, a section with a `gaps` record, a missing or mistyped field, an
  unparseable timestamp, the wrong PG major, a roles list without the bootstrap superuser or a databases
  list without the connected database all give GAPPED. `[]` means collected and empty.
- **7.4 (Melvin's ruling).** Config FAILs first (mode off, no destination, both destinations), then standby →
  MANUAL, latest copy failed → FAIL, then the 24 h age proxy (`WAL_ARCHIVE_MAX_AGE_HOURS = 24`, measured from
  `envelope.collected_at`; no profile override is wired). PASS `archive_recent` needs a success within 24 h
  and no later failure; unclear cases are MANUAL.
- **Restore-test reminder (Melvin, round 2).** One reviewed constant, `RESTORE_TEST_REMINDER`, is attached to
  every 7.4 result whatever the status: assessment rows (`notices`), the offline Finding rationale, the
  review bundle `report.html` (escaped) and the UI row (amber).
- **Unknown label (Melvin, round 2).** GAPPED / NOT_COLLECTED badges read "Unknown: needs human review"
  (amber); the GAPPED reason sentences end "A person must review it by hand; unknown evidence never counts as
  a pass."
- **UI.** Every catalog row shows a plain-language reason (`frontend/src/adapters/explain.ts`), the fixed
  notices and a collapsible evidence list (`frontend/src/live/Evidence.tsx`). The fix step lists catalog
  controls under "Not fixable automatically" with the reason "DBGuard only reports this from catalog
  evidence and never changes roles, privileges or archiving; a person must act on it."

### Explanation codes (facts only; the UI maps each to one sentence)

| Code | Result | Facts |
| --- | --- | --- |
| `section_not_collected` | GAPPED | `section`, `gap_reason?` (string only) |
| `field_missing` | GAPPED | `section`, `field` |
| `wrong_pg_major` | GAPPED | `spec_pg_major`, `snapshot_pg_major` |
| `manual_review` | MANUAL | `evidence_count` |
| `databases_not_covered` | MANUAL | `evidence_count`, `databases` |
| `empty_review_set` | PASS (4.5, 4.10) | `evidence_count: 0` |
| `unlimited_connections` | FAIL (5.5) | `role_count` |
| `connection_limits_set` | PASS (5.5) | `evidence_count` |
| `archive_mode_off` | FAIL | `archive_mode` |
| `archive_destination_missing`, `archive_destination_conflict` | FAIL | — |
| `archive_latest_failed` | FAIL | `last_failed_time`, `last_archived_time` |
| `archive_standby` | MANUAL | — |
| `archive_never_run` | MANUAL | `archived_count`, `failed_count` |
| `archive_stats_reset_recent` | MANUAL | `stats_reset`, `max_age_hours` |
| `archive_timestamp_missing` | MANUAL | `field` |
| `archive_timestamp_after_collection` | MANUAL | `field`, `collected_at` (tolerance 300 s) |
| `archive_older_than_max_age` | MANUAL | `last_archived_time`, `collected_at`, `max_age_hours` |
| `archive_recent` | PASS | `last_archived_time`, `collected_at`, `max_age_hours` |

Any result may add `sections_not_collected` (optional sections that were missing). Fixed notices:
`restore_test_reminder` (7.4 only). Catalog checks add no NOT_APPLICABLE case. In the assessment report a
catalog GAPPED is `result: NOT_COLLECTED` with `reason_code` equal to the explanation code.

## 2. Collector and fixture

- **Collector (B10, approved round 2).** `collector/collect.sql` equals HEAD plus the reviewed
  `docs/gates/F6-gate1-collector.diff` byte for byte (+84 lines): `functions` (never `prosrc`; setting names
  plus the `search_path` value; default ACL expanded) and `archiving` (`archive_command_is_set` boolean only),
  each with a `gaps` entry and redaction records. The main branch's `SET search_path = pg_catalog, pg_temp`
  pin is not on this branch; reconcile it at rebase (new collector hash).
- **Fixture re-recorded** from a disposable PG17 (`postgres:17-bookworm`, 17.11, `--network none`) with the
  real collector via `DisposablePostgres` + `SpecEngine.collect`; container removed and verified.
  `tests/fixtures/phase1/snapshot-pg17-live.json` and `frontend/examples/disposable-pg17-snapshot.json`
  (identical). Target `dbguard-poc-51560a32d5b84bd6a1a4bccd40b73833`, collected 2026-10-27T10:34:04Z,
  collector sha256 `27484d77…203e85`, `gaps: []`. Diff vs the old capture: the two new sections, three
  redaction records, run identifiers and timestamps. No hashes, passwords or function bodies.

## 3. Sandbox scope (Melvin, round 3: "Skip now, skeleton next week")

This week the sandbox ignores catalog checks entirely; they stay fully shown in `/assessment`, the upstream
report and the UI. Next week, with the F6 fix proposals, a password-free skeleton of accounts, permissions and
function stubs will let those fixes be proven.

- **Switch.** `services/sandbox_poc/shared.py` `SANDBOX_COMPARES_CATALOG = False` (a module constant; nothing
  reads it from a request, env, MCP or HERMES). The sandbox findings map holds the 15 non-catalog specs, so the
  no-GAPPED guards, regressions and reproduction/rollback equality (`review_bundle.py:69`, `batch.py:67/151`,
  `workflow.py`, `history.compare`) ignore catalog checks. `upstream_report` keeps all 25 rows. The bundle
  table shows 15 rows, so it no longer shows 7.4 or its reminder. `True` restores comparison for the skeleton;
  both positions are tested.
- **Guards.** `SpecEngine.gapped_settings(findings)` returns GAPPED findings outside the catalog specs (any
  non-catalog GAPPED still blocks). It is used by `service.py`, `workflow.py` (before fix and the after-fix
  regression clause), `review_bundle.py` and `history.compare`. The PASS → non-PASS regression clause covers
  every finding in the map.
- **Gap records.** `CATALOG_ONLY_SECTIONS = {functions, archiving}` (the two sections F6 added, read only by
  4.5 and 7.4) and `blocking_gaps(snapshot)`. With the switch off, a `baseline.gaps` record for those two
  sections no longer blocks the six whole-collection checks (`provenance.py:41` "ungapped source",
  `workflow.py` post-apply and rollback, `review_bundle.py:75`, `batch.py:105`, `history.compare`). Without
  this, F6 would make the sandbox stricter: a collector that cannot read `pg_proc` or the archiver stats would
  newly block every fix. Gap records for every other section (including `password_types`, `hba_rules`,
  `rls_policies`, `settings`, `file_settings`) still block exactly as before F6.
- **Fix plan.** `router.py` `fix_plan` lists non-PASS catalog rows from the upstream report under "Not fixable
  automatically" (`kind: "catalog"`); the UI reason reads "DBGuard only reports this from catalog evidence and
  never changes roles, privileges or archiving; a person must act on it."
- **Safeguards.** `setting_inputs` per evaluator (4.10 `hba_file`; 7.1 `hba_file`, `primary_conninfo`; 7.4
  `archive_mode`, `archive_library`, `archive_command`, `wal_level`). Tests fail if any `planning.POLICIES`
  setting is a catalog input, an `archiving` key or named in `catalog_checks.py`, and they tie the 7.4 inputs
  to the `current_setting(...)` names in the collector's `sql_archiving()`. Further tests prove setting
  reconstruction, setting findings and the manifest are identical whether `functions`/`archiving` are present,
  null or malformed.
- **Confirmed:** catalog findings still appear in `/assessment` (spec_controls Findings), the upstream report
  (all 25 rows) and the UI assessment step. Real-target-style bundles no longer fail "reproduction findings
  differ": the live test `test_review_bundle_live.py::test_source_only_catalog_objects_do_not_block_a_setting_fix`
  gives the source an extra login role and a SECURITY DEFINER function the sandbox lacks; the setting fix is
  VERIFIED, the bundle is READY with 15 rows, and the source report shows both objects in the 4.x evidence.

## 4. Tests

| Suite | Result |
| --- | --- |
| `pytest -q` (unit) | **1124 passed, 0 failed, 0 errors** (39 skipped, 56 deselected, 4 xfailed); was 589 passed before F6 |
| `tests/test_catalog_checks.py` (new) | 369 passed |
| `tests/test_sandbox_guard_scope.py` (new) | 53 passed |
| `tests/test_sandbox_blocking_gaps.py` (new) | 76 passed |
| `tests/test_fix_plan_catalog.py` (new) | 3 passed |
| Frontend `npm test` / `npm run typecheck` | 18 passed / clean. UI checked in the live demo (step 4 rows, 7.4 reminder, fix step); the final fix-step wording change is typecheck-verified only |
| `scripts/validate_specs.py catalog/specs/cis-pg17-v1.1.0` | 25 OK |
| Live (`DBGUARD_POC_LIVE=1`): product_improvements, sandbox_poc, sandbox_poc_api, review_bundle, adaptive_sandbox, collector_demo | Final run 2026-10-27 17:12:21–17:17:36Z, after the round-3 code: **33 passed, 1 skipped** (needs a configured live model), incl. the new `test_source_only_catalog_objects_do_not_block_a_setting_fix`; 2 failed in `test_sandbox_poc_live.py` only on its global "labelled-container set unchanged" assertion while another session was creating and removing `dbguard.sandbox-poc.run` containers (observed every few seconds). That file re-run alone after a full quiet minute (no labelled containers), 2026-10-27 17:24:19–17:24:53Z: **3 passed**. So every live test passes on the final code: 35 passed, 1 skipped |

Existing assertions changed (none loosened; each follows a ruling, the re-recorded fixture or a design
change): spec count 15 → 25 and control count 17 → 27; the handoff summary counts and an exact per-spec catalog
map; break/fix and live PASS/FAIL loops restricted to setting checks, with a test proving only 5.5 and 7.4 are
dropped; setting-list helpers filter `kind == "setting"`; `test_review_bundle.py` no longer empties `roles` in
its fixture (now asserts the bootstrap role is present); "collected empty is not GAPPED" no longer applies to
`roles`/`databases` (an empty list there is a contract violation → `field_missing`); 7.1 now asserts no
`primary_conninfo` value appears; the fixture-pinned catalog outcomes follow the re-recorded capture
(7.4 NOT_COLLECTED → FAIL `archive_mode_off`; 4.5 NOT_COLLECTED → MANUAL `databases_not_covered`); frontend
wording `/never treated as a pass/` → `/unknown evidence never counts as a pass/`.

## 5. Reviews

| Review | Verdict | Outcome |
| --- | --- | --- |
| benchmark-fidelity-reviewer, 7.4 and 5.5 after the ruling | 7.4 CHANGES NEEDED (wording) → applied; 5.5 PASS | 7.4 keeps the config quote; interpretation entries labelled stricter/wider; disclosure that a no-op command still PASSes |
| db-security-reviewer, collector proposal | PASS WITH NOTES | All four notes applied before approval |
| db-security-reviewer, full F6 diff | PASS WITH NOTES | Applied: completeness guards (bootstrap role, connected DB), 7.1 no longer reads `primary_conninfo_parsed`, type guards, schema description, ruling recorded in Gate 1 §6 |
| db-security-reviewer, round-2 delta | PASS WITH NOTES | Applied: N1 (Gate 1 §3/§6 updated), N3 (`wal_level` added to 7.4 inputs). N2 (search_path pin) is the main branch's change; keep it at rebase |
| db-security-reviewer, round-3 (catalog out of the sandbox, `blocking_gaps`) | PASS WITH NOTES | No setting path reads `functions`/`archiving`; the switch and section list are code constants; a request cannot relabel a setting check as catalog (evaluators are bound to F6 recommendations). Applied: stale test docstring. Noted: `blocking_gaps` trusts the gap record's section label, which a handoff requester could set, but they control the whole snapshot anyway |

## 6. Melvin's decisions (29 Oct 2026, "ok please proceed with the gate 2 updates and commit")

1. **Approved: the 10 specs** (all `authored_by: agent`): 4.3, 4.4, 4.5, 4.6, 4.7, 4.9, 4.10, 5.5, 7.1, 7.4.
2. **Approved: the gap-record exemption** (§3). Gap records for `functions`/`archiving` no longer block the
   sandbox while catalog checks are out of it. This loosens the pre-existing "ungapped snapshot" rule for
   those two new sections only, so F6 does not make the sandbox stricter. Gaps elsewhere (e.g. a collector
   without `pg_authid`, which gaps `password_types`) still block every fix, as before F6.
3. **Next week (skeleton):** switching `SANDBOX_COMPARES_CATALOG` back to `True` restores catalog comparison,
   the 7.4 bundle row and its reminder, and the gap-record blocking for the two sections.

## 7. Not done, not verified, follow-ups

- Not verified on PostgreSQL below 15 (`archive_library` read with `missing_ok`; no local image).
- 4.4 shows `password_type: null` without a gap note when `password_types` is `[]` while login roles exist
  (MANUAL anyway; 4.10 GAPs in the same case).
- **Collector bug to file (pre-existing):** `parse_conninfo` is not quote- or URI-aware; a URI-form
  `primary_conninfo` leaves the password inside a key name of `primary_conninfo_parsed` in every snapshot.
  Needs its own collector proposal and approval; main's PR #33 (allowlisted `parse_conninfo`) may already
  cover it, so check at rebase.
- `docs/gates/F6-gate1-collector.diff` is git-ignored (`*.diff`) and is not committed; the reviewed change
  is in `collector/collect.sql` itself.
- `docs/ROADMAP.md` gains an F6 status row.
- Merge order: the main session's PR first, then rebase this branch and re-pin counts, the collector hash and
  the fixture (re-record after the `search_path` pin lands).
