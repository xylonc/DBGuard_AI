# ★ Gate 2 (combined): Wave 1b F2/F3/F4 + F6/7.4

## In plain words (read this first)

**Where we are.** This week's work is finished and tested but not yet released. It's waiting for your approval. The urgent security fix to the evidence collector was released on 29 October (PR #33).

**What this week adds to the app**
- **24 more security rules checked**, bringing the total from 15 to 39 of the 72 CIS rules:
  - **14 logging and network rules:** for example how much detail the logs record, where log files go, and whether the database listens on every network address. Most of them can be fixed with a button.
  - **10 rules about accounts, permissions and backups:** for example who has administrator powers, accounts without passwords, connection limits, and whether backups of the change log are running. These are *reported with evidence* for a person to decide on. Their fixes come next week.
- **A Company Policy screen.** Some rules say "follow your company's policy". You enter those values once, each with an explanation and a recommended default, and approve them by name. Until then, those rules show **COMPANY POLICY MISSING** and never count as passed.
- **Plain-language explanations.**
  - When a rule doesn't apply, the app says **NOT APPLICABLE** and why. For example: "only applies when logs go to syslog; this server uses stderr".
  - When the app can't tell, it says **Unknown: needs human review** and why. It never guesses "pass".
- **Results can't be faked.** If a database changes a setting only for DBGuard's own login, or a value is hidden for safety, the result becomes Unknown rather than a false pass.
- **More fixes rehearsed safely.** This includes fixes that need a database restart, and several fixes tested together in the right order.

**How we know it works**
- About 2,800 automated tests pass across the two pieces of work, including real tests on throwaway databases.
- Independent security reviews passed. Every issue they raised was fixed.
- Live demo on 29 October:
  - the new screens appear correctly;
  - a combined test of three new fixes (one needing a restart) **passed**;
  - the download pack contains no secrets.

**What I need from you**
1. **Approve the rules:**
   - 15 on this week's main branch: 14 new, plus 2 earlier ones that changed and need re-approval;
   - 10 on the accounts and permissions branch.
2. **Accept two deliberately cautious choices:**
   - hostnames made only of hex-like characters (e.g. `cafe`) aren't accepted as the 5.2 network fix;
   - one harmless file-path setting is hidden in the evidence.
3. **Say "go"**, and I'll save (commit) the work in tidy pieces, bring in the released security fix, re-run every test, and open the pull requests for you to merge.

You don't need to approve the company policy now. The app works without it; those rules just stay flagged until you approve one on the screen.

---

**Status:** both branches are built, tested and security-reviewed. **Nothing is committed.** The collector hotfix (PR #33) is merged to `main`.

## What each branch delivers

### `melvin/wave1b-f2-f3-f4` (main checkout)
- **Specs:** 14 new (3.1.2, 3.1.3, 3.1.4, 3.1.5, 3.1.6, 3.1.8, 3.1.9, 3.1.10, 3.1.13, 3.1.15, 3.1.24, 3.1.26, 5.2, 6.10), plus 3.1.14 rewritten (now automated) and 3.1.11 re-specced (syslog condition). All are `authored_by: agent`, and there are 29 specs in total.
- **Engine:**
  - new comparisons: `severity`, `contains_items`, `contains_escapes`, `not_in`, `no_item_in`;
  - `applies_when`, which gives **NOT APPLICABLE**;
  - `interpretation` notes;
  - policy profiles: unapproved profiles never PASS;
  - session overrides give **Unknown: needs human review**;
  - redacted values are never evaluated.
- **Sandbox:**
  - per-setting value rules and allowed values;
  - the restart allowlist (`logging_collector`, `listen_addresses`), plus a restart when needed during reconstruction;
  - fix ordering (3.1.3 before collector-dependent log fixes);
  - the 5.2 address-aware check;
  - a 5.2 fix only from an approved profile, which must include `localhost`.
- **UI:**
  - the Policy Profile screen: explanations, recommended values, live validation, draft → named approval labelled **DEMO approval: no sign-in**, and connection limits;
  - a **COMPANY POLICY MISSING** banner and flags;
  - plain-language reasons for every NOT APPLICABLE and Unknown row;
  - clearer fix-plan wording.

### `melvin/wave1b-f6-catalog` (worktree `wonderful-wilbur-8162a2`)
- 10 report-only specs (4.3, 4.4, 4.5, 4.6, 4.7, 4.9, 4.10, 5.5, 7.1, 7.4) using a reviewed `catalog` check kind.
- **Evidence:** each finding comes with an evidence list.
- **7.4:** automatic PASS/FAIL, plus the restore-test reminder.
- **Collector:** `functions` and `archiving` sections, approved by Melvin.
- **Sandbox:** catalog checks are kept out of the sandbox (Melvin: "Skip now, skeleton next week").
- Full report: `.claude/worktrees/wonderful-wilbur-8162a2/docs/gates/F6-gate2.md`.

## Evidence

| Check | Main branch | F6 branch |
| --- | --- | --- |
| Unit suite | **1679 passed**, 0 failed | **1124 passed**, 0 failed |
| Live sandbox suites | **32 passed**, 1 skipped (needs a live LLM) | **35 passed**, 1 skipped |
| Specs validate | 29/29 OK; profile valid (UNAPPROVED) | 25/25 OK |
| Frontend | typecheck clean, 29/29 tests | typecheck clean, 18/18 |
| Security review | PASS: 2 WARNs fixed; marker-guard follow-up PASS WITH NOTES (fixed) | PASS WITH NOTES (three rounds) |
| Demo walkthrough (29 Oct) | Assessment shows NOT APPLICABLE (3.1.11), COMPANY POLICY MISSING (9 controls) and plain reasons. Policy Profile screen works. Combined test **3.1.24 + 3.1.3 (restart) + 3.1.7: VERIFIED**, ordered correctly; bundle has 39 files, no secrets, restart warning present | UI evidence lists checked in its own demo run |

## Decisions for Melvin
1. **Approve the main-branch specs:** the 14 new ones, plus re-approval of 3.1.14 and 3.1.11. All rulings from Gate 1 are applied.
2. **Approve the F6 specs:** the 10 listed above.
3. **Policy profile:**
   - The committed `reference.yaml` stays a draft template; a test pins `approved_by: null`.
   - To use it, approve it by name on the Policy Profile screen. That is a demo approval until real sign-in exists.
   - Add your server's real address for 5.2 (`localhost, <IP>`) when you have it.
4. **Accept two strictness choices:**
   - all-hex host names (e.g. `cafe`) are refused as 5.2 fix values and read Unknown on a target;
   - the non-secret `krb_server_keyfile` path is redacted.
5. **Go-ahead to commit and open PRs:**
   1. Main branch: commit in reviewable pieces (engine; specs + profile; sandbox fixability; UI; tests and fixtures; docs). Then merge `main` (keeping this branch's fixtures, same collector hash `79f5422c…`), re-run the suites and open the PR.
   2. F6 branch: after the main PR merges, rebase and reconcile the shared files:
      - `validate.py`, `assess.py` and `schema.json`;
      - the two UI explanation modules (`explanations.ts` vs `explain.ts`);
      - the `interpretation` key;
      - the collector, which gains F6's two sections on top of the hardened file.

      Then re-pin counts and fixtures, re-run, and open its PR.

## Follow-ups recorded (not blocking)
- **Production items:**
  - real sign-in for approvals;
  - bind the API to localhost;
  - a persistent volume for approved profiles;
  - retire the legacy `/api/v1/sandbox/validate` route and twin runner;
  - quote `snapshot_id` in the MCP bridge.
- **Collector:**
  - check whether `pg_hba_file_rules.error` can echo a RADIUS secret;
  - add `gaps` entries for sections that can be `null`;
  - refresh the redaction-note wording and the old v0.2.0 section in `docs/CONTRACTS.md`.
- **Next week:** F6 fix proposals (password-free skeleton copy, per-role connection limits from the profile), F5 and F7 (including 6.10).

## Approval (Melvin, 29 Oct 2026)
"ok please proceed with the gate 2 updates and commit". This was given after reading this report, the plain-language summary and the F6 Gate 2 report. It approves:
- the 15 main-branch specs (14 new, plus re-approval of 3.1.14 and 3.1.11);
- the 10 F6 specs;
- the two strictness choices (all-hex host names refused for 5.2; `krb_server_keyfile` redacted);
- committing and opening PRs.

The reference policy profile stays unapproved (`approved_by: null`), to be approved on the Policy Profile screen when wanted.
