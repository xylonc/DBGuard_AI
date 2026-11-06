# ★ Gate 2: Wave 2b, add-ons (F5) and login and encryption (F7)

Branch `melvin/wave2b-f5-f7`, cut from the open roadmap PR branch. Nothing is committed yet; this file asks for your approval to commit and open the PR. Gate 1 and all three rounds of your rulings: `docs/gates/W2B-gate1.md`.

## In plain words (read this first)
This wave adds the 8 rules about **add-on software** (an audit logger, a password checker, an encryption toolkit) and **how people log in** (login routes and encryption).

- **All 8 now give a result with evidence.** Live coverage goes from **39 to 46** of 72 rules.
- **Three get a fix rehearsed on a throwaway copy**, so rehearsed fixes go from **33 to 36**:
  - turning on the **audit logger (pgaudit)**, with the classes from your company policy;
  - turning on the **password checker**;
  - removing **weak encryption ciphers**.
- **Two more are checked, with guided steps** for the DBA: TLS encryption (needs a certificate) and set_user (needs a software install). **Three are checklists** for a person, with evidence: pgcrypto, local logins and network logins.
- **Safety:**
  - Adding an add-on to the start-up list only ever **adds**; it never removes what's there.
  - The DBA's runner **refuses** unless the add-on can really be loaded on the server, because a missing add-on would stop PostgreSQL from starting.
  - The cipher rehearsal uses a **one-time certificate** that never leaves the throwaway copy.

## Your decisions
1. **Approve Wave 2b for commit and PR.** **Rec:** yes.
2. **Acknowledge one deliberate test change.** A safety test said "a setting DBGuard can fix must never feed a check". The pgaudit, password-checker and cipher checks read exactly the settings their fixes change. So the rule now allows this **only through an explicitly listed link**, and every such fix re-checks the affected rules on the throwaway copy. The test is still strict: the list is pinned both ways. The security reviewer accepted it but asked you to acknowledge it. **Rec:** acknowledge.
3. **Collector follow-up: also read `ssl_max_protocol_version`** (one more read-only setting name). The cipher check depends on it, but today it's only collected when set. **Rec:** yes, as a small follow-up PR, security-reviewed first.
4. **Make the pgaudit image the default sandbox, and use it in the demo** (ruling 5: after every live suite passes on it). Every live suite passes on it: 117 passed, 1 skipped, the same as on the stock image. The demo currently pins an **older** PostgreSQL image. On that image the cipher rehearsal is very slow (31 minutes, still VERIFIED), so the demo screen gave up at its 10-minute limit. On the pgaudit image the same rehearsal takes under a minute, and the demo can also show the pgaudit fix once you approve the policy. **Rec:** yes, switch both the default and the demo to the pinned pgaudit image in this PR, then re-run the demo walkthrough.

The new `set_config_list` template and `pgaudit_log_classes` policy value are **demo-approved / unapproved only**. Real use still needs your named approval.

---

## 1. What was built
| Area | Files | What it does |
| --- | --- | --- |
| Collector | `collector/collect.sql` | `available_extensions`; per-connection TLS details and a server-read `visible` flag; replication (walsender) rows; a `connections.tls` gap when the collector can't see other sessions; client certificate identity never selected |
| Specs | `catalog/specs/cis-pg17-v1.1.0/{3.2,4.8,5.3,5.4,5.6,6.8,6.10,6.11}.yaml`, `schema.json` | 8 specs, `authored_by: agent`; 3.2 is `parameterised` (policy); verbatim CIS quotes |
| Checks | `backend/app/services/spec_engine/catalog_checks.py` (+ validate, policy, assess) | 8 evaluators; unknown or hidden evidence is GAPPED, never PASS; preload and `pgaudit.log` parsers mirror PostgreSQL and pgaudit; login-rule options show values only for map/clientcert/clientname |
| Policy | `reference.yaml`, `policy.py`, `policy_profile_store.py`, router draft | `pgaudit_log_classes` (default ddl, role, write), strictly validated, read only from an approved profile |
| Fixes | `services/sandbox_poc/catalog_fixes.py` (new), `planning.py`, `workflow.py`, `batch.py`, `review_bundle.py`, `history.py`, `router.py`, `upstream.py`, `readiness.py`, `provenance.py`, `shared.py` | 3.2 / 5.6 / 6.10. Values are re-derived on the server; proof is "the check passes on the copy"; other affected checks must not regress; 3.2 + 5.6 chain correctly |
| List template | `backend/app/templates/set_config_list.sql.j2`, `models.py`, `template_service.py`, `main.py`, `handoff.py`, `templates.py`, `demo.py` | Writes the preload list properly; server-only (the AI assistant can't render it); demo-approved |
| Runner | `bundle_assets/runner.py` | Fixed-literal `LOAD` test before adding a library; only known statement shapes accepted (any case) |
| Sandbox | `runtime.py`, `images/pg17-pgaudit/Dockerfile`, `scripts/build_sandbox_image.py`, `catalog/images/sandbox/pg17-pgaudit.json` | Pinned pgaudit image; restart on preload change; clean failed-start report; one-time in-copy TLS and cipher probes |
| UI | `frontend/src/live/{explanations.ts,Evidence.tsx,profileForm.ts,PolicyProfile.tsx,fixPlan.ts,objectFixes.ts,ReviewPanel.tsx}`, `liveStore.tsx` | Sentences for 21 new result codes; amber login-rule highlights; pgaudit classes on the Policy screen; fix cards with restart and "install first" notes; the server's own reason text |
| Coverage | `scripts/coverage_report.py`, `docs/COVERAGE.md` | 46 of 72 live; new category "checked, guided fix" |

## 2. Problems found and fixed during the build
- **Hidden sessions dropped (collector, security review BLOCK).** Sessions the collector couldn't see were filtered out, so a low-privilege collection could look fully encrypted. They are now kept as "not visible", with a "not collected" record. Confirmed live for three account set-ups.
- **The old collector mislabelled hidden sessions** as local, unencrypted connections (an existing problem). Now marked "not visible".
- **CIS review (4 specs needed changes):** pgaudit's default `none` is now a FAIL, not "person decides"; replication connections are included; GSS login rules mean "person decides"; set_user passes when no login account is a superuser (your round-2 rulings).
- **The approved template couldn't write a list.** Writing two add-ons gave one bogus name, and the server would not start. Fixed with the new list template (round 3).
- **A failed restart caused confusing errors** (rollback SQL sent to a stopped server). Now reported cleanly, with no rollback SQL.
- **Security review of the whole wave (BLOCK, fixed):** the AI assistant's review-only path could still draft SQL replacing the whole start-up list. Removed, with tests that pin it. The runner now accepts only known statement shapes in any letter case, and the cipher fix isn't offered when only old sessions use weak ciphers.

## 3. Tests
All on the final code, 6 Nov 2026:
- **Unit:** `pytest -q`: 3735 passed, 108 skipped, 61 deselected, 4 xfailed. Includes about 680 new Wave 2b tests: checks, fixes, runner guard, list template, sandbox runtime and policy draft.
- **Specs:** `validate_specs.py`: all 46 OK; the profile is valid and UNAPPROVED. **Coverage:** `coverage_report.py --check` exit 0.
- **Frontend:** typecheck clean; `npm test` 70/70.
- **Live, every suite** (`DBGUARD_POC_LIVE=1`, disposable Docker only, `SANDBOX_LLM_ENABLED=false` because the local `.env` turns the AI reviewer on):
  - stock image: **117 passed, 1 skipped**, 0 containers left;
  - pgaudit image: **117 passed, 1 skipped**, 0 left.
- **Live fix proofs:**
  - each of 3.2, 5.6 and 6.10 fails before, passes after and fails again after rollback;
  - 3.2 keeps an existing `pg_stat_statements` and restores it exactly;
  - 3.2 + 5.6 together VERIFIED, as is 6.10 + 3.1.20 + 3.2;
  - the runner refuses pgaudit on a server without it, before any change;
  - the TLS key never appears in any output.
- **Collector checks on PostgreSQL 17**, with three account set-ups: no monitoring rights, monitoring rights without inheritance, and normal monitoring rights. Hidden sessions are "not visible" with a "not collected" record; visible sessions show their real encryption state.

**Demo check (6 Nov):**
- **Working:** all 8 new rules appear in the assessment with plain sentences. The fix plan offers 5.6 (high risk, restart, "install the package first") and 6.10 (medium), and shows **COMPANY POLICY MISSING** for 3.2.
- **A screen bug, found and fixed:** the combined test sent the demo's "adaptive retries" setting, which these fixes refuse. Fixed in `objectFixes.ts`/`ReviewPanel.tsx`, with a test.
- **Older image too slow:** the combined test of 5.6 + 6.10 then ran longer than the screen's 10-minute limit, because the demo's older pinned image makes the cipher probe very slow (see decision 4). Run directly on that image: 6.10 VERIFIED in 31 minutes, 5.6 VERIFIED in 3.5 minutes.
- **Demo download fix:** the demo no longer re-downloads its digest-pinned images when they are already present. That download had stalled twice.

**Demo re-check on the pgaudit image (after ruling 4):**
- 6.10 + 5.6 combined test **VERIFIED** in under two minutes.
- **A screen bug, found and fixed:** the step 6 "Combined fixes for DBA review" table showed a blank change and "NOT RUN" for the new fixes, though the test had passed. It only knew the older single-setting fixes. It now lists each setting change (for example `shared_preload_libraries: (empty) → passwordcheck`) and reads "After combined test" from each fix's own CIS check result. Fixed in `objectFixes.ts`/`ReviewPanel.tsx`, with tests (frontend 72/72). Confirmed in the demo: both rows show VERIFIED alone and PASS after the combined test.

## 4. Reviews
- **benchmark-fidelity-reviewer:** 4 OK, 4 changes, all applied after your round-2 rulings.
- **db-security-reviewer, collector:** BLOCK, then fixed; replication delta PASS WITH NOTES (race refinement applied).
- **db-security-reviewer, whole wave:** BLOCK on one item (B1), now fixed; N1 and N2 fixed; N3 is decision 2; N4 (image pinning covers the recorded tag; arm64 only, fails closed) is noted for the roadmap.

## 5. Known limits
- pgaudit and set_user packages, certificates and `pg_hba.conf` edits are guided steps; DBGuard never does them.
- 3.2's fix needs your approved company policy (pgaudit classes) and the pgaudit image.
- The pinned image is recorded for arm64 (this Mac). Other hosts are refused until the image is recorded for them.

---

## Rulings (Melvin, 6 Nov 2026)
"Approve all recs": all four recommendations are approved.
1. Wave 2b is approved for commit and PR to `main`.
2. The safeguard change is acknowledged: a fixable setting may be a catalog input only through a reviewed link or affects pair, and every such fix re-checks the dependent catalog checks in the sandbox.
3. Collector follow-up: also read `ssl_max_protocol_version`, as a small separate PR, security-reviewed first.
4. The pinned pgaudit image becomes the default sandbox image and the demo image in this PR, followed by a fresh demo walkthrough.
