# ★ Gate 1 (combined): Wave 1b F2/F3/F4 + F6/7.4

**Status:** drafts only. Nothing is committed, approved or applied. The policy profile's `approved_by` is still blank.

- **Main branch** `melvin/wave1b-f2-f3-f4`: the engine contract is built and 15 specs are drafted. 29/29 specs validate.
  - Unit tests: 766 pass on the engine work alone. With the new specs, old test tables still need updating in step 5.
- **F6 branch** `melvin/wave1b-f6-catalog`: 10 specs drafted and reviewed. The full report is at `.claude/worktrees/wonderful-wilbur-8162a2/docs/gates/F6-gate1.md`.

Each decision below has a recommendation (**Rec**). Reply "accept all recommendations", or list the numbers you want changed.

---

## Part A: main branch (F2, F3, F4)

### A1. The 15 controls
| CIS | What it checks (plain words) | How | Reviewer |
| --- | --- | --- | --- |
| 3.1.14 | Server log records warnings | severity: `warning` or more detailed passes | approve |
| 3.1.15 | Errors record the SQL that caused them | severity: `error` or more detailed passes | approve |
| 3.1.24 | Each log line shows time, process, line no., db, user, app, client | must contain all 7 `%` codes | approve (known false FAIL, see A3) |
| 3.1.6 | Log file permissions | your policy (`0600`) | approve |
| 6.10 | Weak TLS ciphers | moved to F7 next week | reason text needs a fix (A9) |
| 3.1.2 | Where logs go | your policy (`stderr`) | approve |
| 3.1.4 | Log folder | your policy | approve; value needs a ruling (A8) |
| 3.1.5 | Log filename pattern | your policy (`postgresql-%a.log`) | approve |
| 3.1.8 | Rotate logs at least daily | your policy (`1h` or `1d`) | approve; limitation noted |
| 3.1.9 | Rotate logs by size | your policy | approve; value needs a ruling (A8) |
| 3.1.10 | Syslog facility (CIS Manual) | your policy, **only when logging to syslog** | approve |
| 3.1.13 | Syslog program name | your policy | approve; consistency question (A6) |
| 3.1.26 | Log timezone | your policy (GMT/UTC) | approve; values need a ruling (A5) |
| 3.1.3 | Logging collector on | must be `on` (restart needed) | approve |
| 5.2 | Don't listen on all network addresses | must not be `*` / `0.0.0.0` | **changes required (A4)** |

Until you approve the profile, every "your policy" control shows **COMPANY POLICY MISSING** and can never PASS.

### A2. Severity direction (3.1.14, 3.1.15)
CIS says "at least `warning`". Its own description reads "the lower the level, the fewer messages are logged", and it calls PANIC "practically mute". So "at least warning" means *logs at least as much as warning*.
- **Rec:** `warning` or any more detailed level passes; `error`, `fatal` and `panic` fail. Both reviewers agree.
- The trade-off: very chatty levels like `debug5` also pass.

### A3. 3.1.24 log line prefix
The check requires all 7 codes (`%m %p %l %d %u %a %h`) in any order, not CIS's exact text.
- On a server that logs **only** to syslog, CIS asks for just 4 codes, so this check can give a false FAIL. It can never give a false PASS.
- **Rec:** accept this, and record the limitation in the spec's `interpretation` note (see A10).

### A4. 5.2 listen_addresses (must change before approval)
- **Bug:** the check compares the whole value, so `'*, 10.0.0.1'` would wrongly PASS. **Rec:** in step 4, add an address-aware check that FAILs if any listed address is `*` or `0.0.0.0`.
- **Unsafe fix:** the draft fix is `localhost`, which in production cuts off every remote client. **Rec:** the fix value comes only from **your policy profile**, as a DBA-supplied address. If none is supplied, DBGuard shows FAIL with a manual fix and offers no fix button. Restart required; high risk.
- **Rec:** automated checking is acceptable even though CIS marks 5.2 "Manual". CIS gives a clear fail sentence, and "Manual" refers to choosing your IP.
- `::` (IPv6 "all addresses") isn't in the CIS text. **Rec:** make it a separate DBGuard check later, not part of 5.2.

### A5. 3.1.26 timezone
**Rec:**
- policy-based (CIS allows "or as defined by your organization");
- the profile must always include both `GMT` and `UTC`;
- also accept `Etc/UTC` (what PostgreSQL containers report);
- use `America/New_York` as the test "break" value, because `US/Eastern` may not exist on newer images.

### A6. "Only applies when…" conditions
- **3.1.11** (syslog sequence numbers): **Rec adopt.** It becomes NOT APPLICABLE when you don't log to syslog. Because the file changes, you re-approve it.
- **3.1.7** (log truncation): **Rec drop.** CIS has no real condition there, and 3.1.3 already makes sure the collector is on.
- **3.1.12:** stays human-checked. Manual specs can't carry a condition yet (follow-up).
- **3.1.13** (syslog name): **Rec** add the same syslog condition, for consistency with 3.1.10 and 3.1.11.
- **3.1.4, 3.1.6, 3.1.8:** **Rec no condition.** The CIS sentences describe effects, not when the rule applies.

### A7. 3.1.10 syslog facility
CIS marks it Manual. **Rec:** keep it policy-based, because your approved profile *is* the "organization's logging policy" CIS refers to.

### A8. Draft policy profile values (you approve these, then type your name into `approved_by` yourself)
| CIS | Expected (pass) | Fix value | Rec / note |
| --- | --- | --- | --- |
| 3.1.2 log_destination | `stderr` | stderr | keep (CIS's alternative `csvlog, stderr` depends on 3.1.3) |
| 3.1.4 log_directory | draft `log` (inside PGDATA) | — | **change:** CIS says logs belong outside PGDATA. **Rec** `/var/log/postgresql`, if step 4 confirms the sandbox image has it |
| 3.1.5 log_filename | `postgresql-%a.log` | same | keep |
| 3.1.6 log_file_mode | `0600` | 0600 | **Rec** also allow `0640` (CIS: "commonly useful") |
| 3.1.8 log_rotation_age | `1h`, `1d` | 1d | keep (e.g. `12h` would FAIL until listed) |
| 3.1.9 log_rotation_size | draft `1GB` only | 1GB | **Rec** also allow `0`, since age rotation is on (CIS allows it) |
| 3.1.10 syslog_facility | `local0` | local0 | keep |
| 3.1.13 syslog_ident | `postgres` | postgres | keep |
| 3.1.26 log_timezone | `GMT`, `UTC`, `Etc/UTC` | GMT | see A5 |
| 5.2 listen_addresses | (new) **your server's real IP** | — | you supply it; leave blank for the demo |

### A9. 6.10 reason text
**Rec:** correct it to "needs a cipher-list check and a read-only check of live TLS connections", and record CIS's warning that without the right privileges the connection query returns nothing. Nothing returned must count as UNKNOWN, never PASS.

### A10. A shared `interpretation` note on specs (both branches)
This is an optional list of plain sentences recording where DBGuard reads CIS more strictly or more narrowly. **Rec:**
- add it once on the main branch, and let F6 reuse it;
- use it for 3.1.24, 5.2, 3.1.14/15, and F6's 4.5, 5.5 and 7.4;
- no SQL inside.

### A11. Smaller notes (no ruling needed unless you disagree)
- **3.1.3 impact text** will say: turning the collector on in a container moves logs into files, so `docker logs` goes quiet.
- **3.1.8 follow-up:** a future "at least daily" duration comparison would let `12h` pass without listing it.
- **3.1.7 risk wording:** the reviewer says the current "loses log data every hour" impact text overstates the risk. **Rec:** keep your "high" ruling, but tighten the sentence in step 4.

---

## Part B: F6 branch (roles/privileges + 7.4), report-only
| CIS | What it shows | Result rule |
| --- | --- | --- |
| 4.3 | Roles with admin powers (superuser, createrole, createdb, replication, bypassrls) | always human review |
| 4.4 | All login roles (CIS: inactive ones shouldn't exist) | always human review |
| 4.5 | SECURITY DEFINER / SET functions (no function bodies) | PASS only if none and all DBs covered, otherwise human review |
| 4.6 | Who can INSERT/UPDATE/DELETE each table | always human review |
| 4.7 | Tables with row-level security, and roles that bypass it | always human review |
| 4.9 | Superuser roles | always human review |
| 4.10 | Login roles with no password, plus the hba rules that apply | PASS if none, otherwise human review |
| 5.5 | Login roles with unlimited connections (-1) | **FAIL** if any; a default cluster fails (`postgres` is -1) |
| 7.1 | Roles that can replicate, plus whether replication is in use | always human review |
| 7.4 | WAL archiving configured (never shows the command) | **FAIL** if off, unset or both set; configured gives human review of the counters |

**B decisions** (all **Rec yes / as drafted**):
1. Add the new "catalog" check type. Human-checked specs may name the evidence-building check.
2. 4.5 and 4.10 may PASS when there is nothing to review.
3. 4.5 stays human-checked this week; an approved-functions list goes in the policy profile later.
4. 5.5 scope as drafted. Every default cluster FAILs.
5. 7.4 never auto-PASSes: a correct configuration still gets human review of the archiver counters.
6. Only the connected database is checked for 4.5/4.6/4.7. Other databases are listed as "not covered"; a multi-database run is a follow-up.
7. 7.1 doesn't collect `pg_stat_replication` yet.
8. Use the shared `interpretation` note (A10). F6 rewords the 5.5 entry so it contains no SQL.
9. 4.6 group-inherited grants are labelled "upper bound".
10. **Collector change.** Two new read-only evidence sections: `functions` (names and settings, never bodies or secret values) and `archiving` (a yes/no for "command set", never the command). It was dry-run on a throwaway PG17 with planted secrets, and none leaked. **Rec:** approve now, conditional on the db-security-reviewer's PASS before it is applied.
11. **Follow-up:** the existing `settings` section still ships the masked `archive_command` text. Decide later whether to drop it.

---

## Part C: what happens after you rule
1. **Main:**
   - apply the rulings (specs, profile, re-specs);
   - **you fill `approved_by` in the profile yourself**, and the test that pins it to blank is updated to match;
   - step 4: fixes, safe value checks, restart support for 5.2/3.1.3, the address-aware 5.2 check;
   - then tests, the security review, and the UI: plain-language reasons, the COMPANY POLICY MISSING flag, the profile panel.
2. **F6:** build the catalog engine and evidence lists, apply the collector change after the security review, then tests and its Gate 2.
3. **Combined Gate 2:** the demo walkthrough, then your go-ahead to commit. Main merges first; F6 then rebases.

---

## Rulings (Melvin, 28 Oct 2026)

- **A2, 3.1.14/3.1.15:** "lets log warning, error, log, fatal and panic." Confirmed: *warning or chattier* passes (`severity`, `at_or_more_verbose`).
- **A3, 3.1.24:** encode as CIS recommends (escape-set reading; record the syslog-only limitation in `interpretation`).
- **A4, 5.2:** "yes agreed" to an address-aware check (FAIL if any entry is `*` or `0.0.0.0`). "ok agreed" to taking the fix value only from the policy profile; with no IP there is no fix button.
- **A5, 3.1.26:** recommended values accepted (`GMT`, `UTC`, `Etc/UTC`; GMT and UTC always required; break value `America/New_York`).
- **A6:** 3.1.11 adopts the syslog condition ("ok") and is re-approved. 3.1.13 gets the same condition. The 3.1.7 condition is dropped (keep as today). No condition for 3.1.4, 3.1.6 or 3.1.8.
- **A7–A11:** encode as CIS recommends; recommended values accepted.
- **A8, profile:** "i can agree to your recommended value." Melvin fills `approved_by` himself.
- **New, Policy Profile screen:** build it **this week** (form, explanations, recommended defaults, validation, draft → named-human approval).
- **B1–B4, B6–B9, B11:** encode as drafted / as CIS recommends.
- **B5, 7.4:** auto PASS/FAIL. PASS if configured and the latest archive succeeded within a limit (profile value, default 24h, recorded as an interpretation) with no later failure. FAIL if off, unset, conflicting, or the latest copy failed after the latest success. Human review only when unclear (never archived, stats just reset, standby).
- **B10, collector change:** still needs Melvin's **explicit** approval after db-security-reviewer passes it; not yet applied.
- **5.5:** flagged this week; per-role fix proposals (the DBA chooses the limit) come next week with the F6 fixes.

## Rulings, round 2 (Melvin, 28 Oct 2026)
- **F6 collector change:** "Approve". Apply it on the F6 branch, then re-record fixtures from a throwaway PG17. Not yet applied: the F6 session stopped on the usage limit.
- **Sandbox guard:** "Settings only + safeguard". The no-UNKNOWN-before-fix guard covers setting checks only. Catalog checks still show UNKNOWN. A test must fail if any fixable setting ever feeds a catalog check.
- **5.2 sandbox:** "Require localhost in the value". The profile fix value must include `localhost` (e.g. `localhost, <IP>`), so the sandbox can start.
- **Profile approvals:** "Accept, label as demo". Show "DEMO approval: no sign-in" wherever an approval appears. Real sign-in stays a roadmap item.
- **UNKNOWN results:** "ok for these cases, can we state it as unknown and then require human review?" Every UNKNOWN row shows "Unknown: needs human review" with its plain-language reason. It never counts as PASS.
- **Collector search_path hardening:** applied in the working tree. Live-proven against a shadowing function. db-security-reviewer: PASS WITH NOTES.
- **Open, found by the reviewer:** `standard_conforming_strings=off` at database level may break `mask_secrets`/`parse_conninfo` and leak secrets. The live repro was INCONCLUSIVE because my test setup failed (ALTER SYSTEM ran inside a transaction). Re-run the repro properly; if confirmed, add `SET standard_conforming_strings = on;` next to the search_path line, with Melvin's approval and a review.
- **Sandbox scope for catalog checks (Melvin, 28 Oct):** "Skip now, skeleton next week". This week the sandbox ignores catalog checks: they are left out of the guards and the reproduction comparisons, but stay fully visible in the assessment, the report and the UI. Next week, together with the F6 fix proposals, a password-free skeleton copy of accounts, permissions and function stubs will be built. 7.4 stays report-only for good.
- **Collector string-escape leak (confirmed live; Melvin chose "Hotfix PR to main today"):** branch `melvin/hotfix-collector-hardening` adds `SET standard_conforming_strings = on;` next to the search_path line. This branch carries an identical header.
