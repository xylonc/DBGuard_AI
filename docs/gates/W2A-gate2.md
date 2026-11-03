# ★ Gate 2: Wave 2a, per-object fixes (F6) and the 72-rule coverage report

Branch `melvin/wave2a-f6-fixes`, base `main` @ 12eaefe. Nothing is committed yet; this file asks for your approval to commit and open the PR. Gate 1 and your rulings ("Accept all", 30 Oct): `docs/gates/W2A-gate1.md`.

## In plain words (read this first)
The 10 account and permission checks used to **only report** problems. Now the DBA can **pick a specific fix for one object** from the report, for example "Remove SUPERUSER from `app_admin`" or "Stop `old_report` logging in". DBGuard rehearses each picked fix on a throwaway stand-in copy of that one object. It proves the fix works and that the undo puts everything back, then adds it to the instruction pack. As before, DBGuard never touches the real database.

What changed since Gate 1, in one line each:
- **Six fix types are built**, exactly as ruled in Gate 1 table A, with the same risk levels.
- **The fix-picking screen is built**: step 5 has "Proposed fixes for accounts and permissions" with tick-boxes, plain explanations, risk labels and notes. Connection limits show **COMPANY POLICY MISSING** until you approve a policy.
- **The DBA's runner checks the object first.** It refuses if the object has changed since the evidence was collected, and applies and undoes inside one transaction, so nothing is left half-done.
- **The DBA's runner refuses to change a protected account.** This is the main admin account, the built-in `pg_` accounts, or the account the DBA is logged in as. The security review asked for this; without it a DBA could lock themselves out.
- **Checking the real database afterwards:** once the DBA applies the pack, DBGuard can confirm each fix took effect. It only says "confirmed" when the object matches what was rehearsed.
- **The collector now records which add-on owns each table** (your "Yes, add it", security-reviewed first). Ordinary tables next to add-on tables can now get fixes; add-on tables never do.
- **Coverage report:** `docs/COVERAGE.md` lists all 72 rules with a status each, and a check keeps it in sync.

## Your decisions
1. **Approve Wave 2a for commit and PR.** **Rec:** yes.
2. **Two small collector follow-ups from the security review.** Both are collector changes, so they need your OK. **Rec:** yes, as a separate small PR after this one.
   - Record the **login account** as well as the current account, and protect both. Today, if the collector switches account with `SET ROLE`, only the switched-to account is protected from lock-out fixes.
   - Add the same `LIMIT 1` safety step to the functions lookup that the tables lookup now has. A damaged catalogue would then not blank out the functions section.
3. **Sample accounts in the demo database.** The demo source is a brand-new database whose only account is the main admin account, which is never offered a fix. So the demo shows the section and its "never touched" note, but nothing to tick. Adding a few planted sample accounts and tables to the throwaway demo source would let a viewer pick and test a fix end to end. Examples: `app_admin` with CREATEDB, an unused `old_report` login, and a table anyone can write to. **Rec:** yes, as a small follow-up; it changes demo results, so the demo live tests get updated with it.
4. **Coverage wording after merge:** change the seven rules (4.3, 4.4, 4.5, 4.6, 4.9, 4.10, 5.5) from "fix proposals in progress" to "per-object fixes the DBA picks". **Rec:** yes, in this PR once you approve.

The six templates stay **demo-approved only** (`DEMO_FIXTURE_ONLY`, your "Yes, demo only"). Real use still needs a named human approval of each template, as for `set_config_parameter`.

---

## 1. What was built

| Area | Files | What it does |
| --- | --- | --- |
| Proposals | `services/sandbox_poc/object_fixes.py` | Builds per-object proposals from the evidence and applies the Gate 1 safety list server-side. Each fix has an id (`fix-<rec>-<type>-<hash>`); the server re-derives it from the evidence at every step, so a forged or edited id is refused |
| Templates | `backend/app/templates/{role_connection_limit,role_drop_attribute,role_nologin,function_security_invoker,function_revoke_public_execute,table_revoke_dml}.sql.j2`, `template_service.py`, `models.py` | Names go through `ident`, numbers through `pg_int`, attributes and privileges come from fixed lists. **Every template now has a parameter schema**; a template without one is refused |
| Stand-in copy | `services/sandbox_poc/catalog_skeleton.py` | Recreates only the target role, table stub or function stub, plus what it needs. A throwaway password is set only if the original had one; it is never logged or kept |
| Rehearsal | `workflow.py` (`ObjectRemediationLoop`), `batch.py` | Confirm problem → apply (one transaction) → prove → check nothing else changed → undo → confirm original → destroy |
| Pack | `review_bundle.py`, `bundle_assets/runner.py` | Object fingerprint before and inside the transaction; refuses protected roles; pinned `search_path`; README says what was and wasn't rehearsed |
| Target check | `history.py` | Reassessment uses the object's own proof for object fixes |
| Plumbing | `handoff.py`, `upstream.py`, `router.py`, `service.py`, `templates.py`, `planning.py`, `readiness.py`, contracts `fix-unit-v2.json`, `sandbox-handoff-v1.json` | Only `object_fix_id` and a template version travel in a request; the fix plan reports the approved version of each template |
| HERMES/MCP | (no change) | `validate-and-render` refuses the six object templates; the MCP tool has no `object_fix_id`. HERMES can read proposals, not act on them |
| Collector | `collector/collect.sql`, `collector/docs/COLLECTOR.md` | `object_acls` rows carry `extension` (owning extension or null) |
| UI | `frontend/src/live/{ObjectProposals.tsx,objectFixes.ts,ReviewPanel.tsx,LiveUI.tsx}`, `frontend/src/store/liveStore.tsx` | Fix-picking section, notes for every backend note code, single and combined tests, step 6 rows |
| Coverage | `scripts/coverage_report.py`, `docs/COVERAGE.md`, `docs/coverage.json` | 72 rows; `--check` fails if it drifts from the specs |
| Demo | `services/sandbox_poc/demo.py` | Seeds the six templates as `DEMO_FIXTURE_ONLY` |

Not offered, as ruled: 4.7 (enable RLS), 7.1 (replication user), the 4.9 predefined-role grant, 7.4.

## 2. Problems found and fixed during the build
- **Timezone mismatch:** account expiry dates were compared as text, so a server not on UTC looked "changed". They are now converted to UTC first.
- **"Can rehearse" was sometimes wrong:** a few fixes (functions with extra pinned settings, grants made by a non-owner, partitioned tables) were offered as testable, then refused at run time. Rehearsability is now decided by the stand-in builder itself.
- **Target check could never confirm an object fix:** it looked for a check status the sandbox doesn't produce for these checks. It now uses the object's own proof.
- **Security review (PASS WITH NOTES):** the runner now refuses protected roles on the target (Medium), pins `search_path` on every connection (Low), and the combined pack's front page carries the DEMO label (Info). The two collector notes are decision 2 above.

## 3. Tests
All on the final code, 3 Nov 2026:
- **Unit:** `pytest -q`: 2974 passed, 93 skipped, 61 deselected (live/tier_b), 4 xfailed.
- **Specs:** `validate_specs.py`: all 39 OK. **Coverage:** `coverage_report.py --check` exit 0.
- **Frontend:** `npm run typecheck` clean; `npm test` 51/51 (15 new: note sentences for every backend code, unknown codes fall back safely, requests carry no params, per-template versions).
- **Live, full set** (`DBGUARD_POC_LIVE=1`, disposable Docker only): 89 passed, 1 skipped, 0 containers left. This includes `test_sandbox_poc_live` (flaky before when other runs were active; passed in a quiet window) and `test_collector_hardening_live` (collector hash changed).
- **Live, after the security-review fixes:** `test_object_sandbox_live`, `test_review_bundle_live`, `test_product_improvements_live`: 39 passed, 1 skipped, 0 left.
- **Live per-object proof:** each of the six fix types reproduces → applies → proves → undoes exactly → cleans up. Also covered: a hostile role name, a combined batch of three, the runner refusing a changed object, and the collector recording the owning extension (`pg_trgm` member table vs ordinary table).
- **New unit coverage:** runner refuses the bootstrap superuser, `pg_` roles and the connected account for apply and rollback with no SQL run; `search_path` pinned before catalogue reads; combined pack front page carries the DEMO label.

`SANDBOX_LLM_ENABLED=false` was set for live runs: with the local sandbox LLM switched on, adaptive retries need a configured reviewer, which is a local setting unrelated to this change.

**Demo check (3 Nov):** `scripts/demo.py up` → Load live demo → step 5 → Show recommended fixes. The section renders. CIS 4.3, 4.4, 4.9 and 5.5 each show the bootstrap-superuser note for `dbguard_poc` and offer no fix, which is correct for a fresh cluster. No console errors. The tick-box, single and combined flows were checked in the browser against fixture-derived proposals (the server's own `grouped()` output) and live through the API tests above.

## 4. Reviews
- **db-security-reviewer, collector field:** PASS WITH NOTES; applied as specified, with `LIMIT 1`.
- **db-security-reviewer, full Wave 2a change:** PASS WITH NOTES. No Critical or High findings. The Medium, Low (search_path) and Info findings are fixed and tested; the two collector notes await decision 2.

## 5. Known limits (unchanged from Gate 1)
- Function stubs with non-built-in argument types can't be rehearsed; they show "can't rehearse".
- The rehearsal proves the change and its undo, not how your applications use the object; every pack says so.
- Approvals are still DEMO-labelled; real sign-in is a production follow-up.

---

## Rulings (Melvin, 3 Nov 2026)
"Approve all recs": all four recommendations are approved.
1. Wave 2a is approved for commit and PR to `main`.
2. The two collector follow-ups (protect the login account as well as the current account; `LIMIT 1` on the functions extension lookup) go in a separate small PR after this one, security-reviewed first.
3. Planted sample accounts and tables in the throwaway demo source, as a small follow-up, with the demo live tests updated.
4. The coverage wording for 4.3, 4.4, 4.5, 4.6, 4.9, 4.10 and 5.5 is now "per-object fixes the DBA picks" (done in this PR).

The six object templates remain `DEMO_FIXTURE_ONLY`; real use needs a named human approval of each template.
