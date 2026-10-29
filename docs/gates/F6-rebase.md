# F6 + CIS 7.4: rebase onto Wave 1b and main

Branch `melvin/wave1b-f6-catalog`, rebased first onto `origin/melvin/wave1b-f2-f3-f4` (PR #34), then onto
`origin/main` @ 8f375e6 after Melvin merged PR #34 (tree identical, so the second rebase was trivial).
Gate 2 approval: `docs/gates/F6-gate2.md` §6 (Melvin, 29 Oct 2026). The seven reviewed commits are kept.

## 1. What was reconciled

| Area | Decision |
| --- | --- |
| `spec_engine/validate.py` | Wave 1b's operators, `applies_when`, policy, redaction and session-override rules kept. A `catalog` check returns early through the F6 block (exact keys `kind, evaluator, pass_condition_quote`; no `proof`, no `applies_when`; tier `automated` or `manual_checklist`). F6's own `interpretation` validator dropped: Wave 1b's stricter one (no `;`, no SQL keywords, ≤ 600 characters) now applies to catalog specs too. |
| `spec_engine/manifest.py` | `collects_evidence` also requires `check.kind == "setting"`: catalog checks read baseline sections, never a manifest query. The golden manifest is unchanged (29 checks). |
| `spec_engine/assess.py` | The catalog evaluator decides catalog rows before `_decide`; Wave 1b's `_explain` runs only for setting rows. Unknown evidence is NOT_COLLECTED for both kinds, never PASS. |
| `schema.json`, `assessment-report-v1.json`, `docs/CONTRACTS.md` | Both feature sets merged: `check` is setting or catalog; the report's reason and explanation enums carry both code sets; catalog rows add `evidence`, `evidence_paths`, `notices`. |
| `collector/collect.sql` | The reviewed `functions`/`archiving` sections, gap entries and redaction notes re-applied on the hardened file (search_path/scs pins, `is_secret_setting`, `sanitise_setting`, never-ship). The changed lines are identical to the Gate 1 diff. `tests/test_collector_hardening.py` now lists the two new `pg_temp` helpers. |
| Sandbox | `gapped_settings` combined with Wave 1b's `session_override_reason` (service) and `is_regression` (workflow, review bundle). The findings projection no longer copies `cis`/`explanation` for catalog rows (their role counts and archiver times differ between source and sandbox). Setting-name lists now exclude only catalog checks, so Wave 1b's behaviour for every other check is kept. |
| UI | One explanation module: F6's sentences moved into `frontend/src/live/explanations.ts` (fixed templates, facts quoted and clipped); `src/adapters/explain.ts` deleted. Every catalog row gets a reason, PASS and FAIL included. `src/live/Evidence.tsx` (`CatalogEvidence`) shows the notices and evidence under it. F6's `Badge` change dropped: Wave 1b's `FindingBadge` already labels unknown statuses. |
| 7.4 spec | Wave 1b's interpretation rules rejected four entries. Changes: one `;` became `.` and one `; until` became `. Until`; two long entries were split at an existing sentence boundary. No word was added, removed or changed (checked with `git diff --word-diff` against the approved version). `pass_condition_quote` is byte-identical. |
| Counts | 39 specs (29 + 10 F6), 41 controls with the two supplementary checks, findings map 29, report rows 39, golden manifest 29. |

## 2. Fixtures

Both fixtures were re-recorded with the real collector from a disposable PG17 (target `dbguard-poc-18e130515602430f911530d62e25ae9a`, collected 2026-10-29T10:02:41Z, collector sha256 `7b6a4d31…0fbb1797`). They have 29 checks, `functions: []`, `archiving.archive_mode: off` and `gaps: []`. No passwords, hashes or secrets; `archive_command` appears only as the sanitised `pg_settings` row.

## 3. Tests on the final code (HEAD of this branch, rebased on main)

| Suite | Result |
| --- | --- |
| Unit (`.venv-demo/bin/python -m pytest -q`) | 2623 passed, 0 failed, 82 skipped, 61 deselected, 4 xfailed |
| `scripts/validate_specs.py catalog/specs/cis-pg17-v1.1.0` | 39 OK; reference profile valid (UNAPPROVED) |
| Frontend | `npm run typecheck` clean; `npm test` 36 passed, 0 failed |
| Live (`DBGUARD_POC_LIVE=1 SANDBOX_LLM_ENABLED=false`) | 77 passed, 0 failed, 1 skipped, 19 deselected (837 s, on 7f76a9d) |

The live run covers `test_collector_hardening_live`, `test_collector_demo_live`, `test_product_improvements_live`, `test_sandbox_poc_live`, `test_review_bundle_live` (including F6's `test_source_only_catalog_objects_do_not_block_a_setting_fix`), `test_sandbox_poc_api_live`, `test_session_override_live` and `test_listen_addresses_live`. The one skip needs a configured live model. `tests/live/test_e2e_break_fix.py` (19 tests, `live` marker, needs the full pg-target stack) is deselected by `pytest.ini`, as before F6.

## 4. Reviews

| Reviewer | Verdict | Notes |
| --- | --- | --- |
| db-security-reviewer, collector reconciliation | PASS | The new helpers run under the pinned search_path and are `pg_temp`-qualified. No `prosrc`. Of `proconfig`, only names plus the `search_path` value, so no secret value. `archive_command` shipped only as a boolean. Every null section has a gap. Fixtures are clean. |
| db-security-reviewer, full diff vs the new base | PASS WITH NOTES | (1) duplicate `return errors` in `validate.py`: fixed. (2) `batch.py`'s combined-fix regression check uses only `is_regression`, not `gapped_settings`: this was already on main and F6 does not change it, so it is a follow-up. (3) The 7.4 reminder is not in the sandbox DBA report while `SANDBOX_COMPARES_CATALOG` is `False`: a deliberate Gate 2 choice. |
| benchmark-fidelity-reviewer, 7.4 rewording | Not concluded | It had no git access. I checked mechanically instead (see §1, 7.4 spec). The reviewer's point that "Requiring this for PASS" lost its subject was fixed by moving the split, so that sentence stays with the proxy it refers to. |

## 5. Known gaps and follow-ups

- `batch.py` combined-fix regression check: align it with `gapped_settings` like workflow, review bundle and history (already on main).
- `schema.json`'s interpretation pattern lets a `;` through (its `\S` matches `;`). `validate.py` still rejects it, so `validate_specs.py` is the gate. This is a Wave 1b schema fix.
- F6's earlier `parse_conninfo` follow-up is superseded by PR #33's allowlisted parser. 7.1 no longer reads `primary_conninfo_parsed` anyway.
- Next week: the password-free skeleton and `SANDBOX_COMPARES_CATALOG = True`. That brings back catalog comparison, the 7.4 row and reminder in the bundle, and gap-record blocking for `functions`/`archiving`.
- Not verified on PostgreSQL below 15.
