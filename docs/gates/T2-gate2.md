# ★ Gate 2: Task 2, terminal (VHS) screenshots of sandbox tests

Branch `melvin/task2-vhs-screenshots`, cut from the PR #43 branch. **Approved by Melvin on 7 Nov 2026** (see Rulings at the end). Gate 1 and your ruling: `docs/gates/T2-gate1.md`.

## In plain words (read this first)
Every sandbox test now takes **three real terminal screenshots** on the throwaway copy:
- **Before the fix:** the problem.
- **After the fix:** the fix in place.
- **After the undo:** back exactly as before.

This covers every kind of fix: settings, add-ons and logins, single accounts or objects, and combined tests. The screen shows them as an **"Evidence screenshots"** strip, and you can click any picture to see it full size. Each picture is also in the DBA bundle, with its fingerprint.

**Safety, as you asked.** VHS types into a real terminal on this Mac, so we made sure nothing from the database ever reaches that terminal:
- **One fixed command:** DBGuard writes the checks *inside* the sandbox first. VHS then types one fixed command, whose only variable is the sandbox's own name, checked three ways.
- **Strict filter:** a second filter allows only letters, digits and `/ . _ = -` in anything typed.
- **Read-only checks:** each picture runs only read-only checks that never touch passwords, keys or connection details. Anything that would need masking gets a rendered picture instead.
- **Nothing left running:** if a recording hangs, DBGuard stops it and everything it started (terminal, browser, shell), and a live test proves nothing is left running.
- **No downloads during a test:** DBGuard never lets VHS download a browser during a test, and never puts your user name in a picture.
- **Images never reach the AI assistant:** the pictures and their query text are removed before anything is sent to HERMES.
- **Graceful fallback:** if VHS is missing or fails, the stage gets today's rendered picture, with the reason, and **a screenshot problem never changes a fix's PASS or FAIL.**

## Your decisions
1. **Approve Task 2 for commit and PR** (stacked on #43). **Rec:** yes.
2. **Acknowledge one change to what the AI assistant receives.** The two HERMES tools that return sandbox results now replace screenshot images, raw query output, the checks' SQL and the typed command with a short "omitted" note. This only removes data. The tool list, inputs and permissions are unchanged, and a test pins the eleven tools exactly. **Rec:** acknowledge.
3. **Combined bundles get a top-level manifest only when they contain screenshots.** This leaves today's combined bundles byte-for-byte unchanged when screenshots are off. **Rec:** keep it conditional for now.
4. **Defaults.**
   - The real product default stays **rendered** (today's behaviour).
   - The demo uses **terminal** and prints a warning: terminal mode briefly opens a local-only terminal, so use it only on a single-user machine. You can override it with `DBGUARD_SCREENSHOT_MODE=rendered`.

   **Rec:** yes.

## 1. What was built
| Area | Files | What it does |
| --- | --- | --- |
| Capture | `services/sandbox_poc/terminal_capture.py` (new) | Fixed SQL templates per fix kind; strict typed-line and tape checks; VHS runner with a private folder, minimal environment, timeout and full process clean-up; rendered fallback; never raises |
| Sandbox | `runtime.py` | `write_evidence_sql`: a constant `tee` into the sandbox's own temporary folder, with no shell, a read-only first line and a 64 KiB cap |
| Loops | `workflow.py`, `catalog_fixes.py`, `batch.py` | Before, after and undo pictures for setting, add-on/login, per-object and combined tests, taken after each check is decided |
| Bundles | `review_bundle.py`, `bundle_assets/runner.py`, `batch.py` | `screenshots/<stage>.png` with sha256 in the manifest; JSON keeps file name and fingerprint, not the image; DBA `verify.sh` unchanged |
| AI assistant | `services/dbguard_mcp/server.py`, `upstream.py` | Images and query text omitted for HERMES (decision 2) |
| Screen | `frontend/src/live/EvidenceShots.tsx`, `shotViews.ts`, `LiveUI.tsx`, `ReviewPanel.tsx` | "Evidence screenshots" strip; full-size view with the typed command, the checks and the fingerprint |
| Demo | `scripts/demo.py`, `services/sandbox_poc/DEMO.md` | Terminal mode with the shared-machine warning; one-time browser set-up note |

## 2. Problems found and fixed during the build
- **Two security review rounds, PASS WITH NOTES, all applied:**
  - **Docker path:** it could have shown your Mac user name; now only standard paths are allowed.
  - **Clean-up:** after a timeout it is now proven live.
  - **Browser downloads:** a capture can no longer trigger one.
  - **Backup SQL check:** tightened. It allows only read-only statements and blocks dollar quoting, Unicode-escaped names and SQL-as-text functions.
  - **Masking:** also checks the printed queries.
  - **The AI assistant:** receives no images or query text.
  - **Combined manifest:** carries the demo label.
  - **Bundle JSON:** no longer repeats the images.
- **Test-writer finding:** the backup SQL check could be fooled by PostgreSQL's `$$` quoting. It is fixed, and the test now runs normally.
- **Your user name could appear in pictures** on Docker installs inside your home folder. Fixed (above).
- **A screen bug you found in the demo (7 Nov): "4 got worse" when nothing got worse.** It came from PR #43's results view in two parts:
  - **Unlabelled restored result:** the demo restored an earlier test with no label saying so. A background refresh also kept re-marking results.
  - **Mismatched comparison:** that earlier test was run *before* the company policy was chosen, but it was compared with an assessment made *with* the policy, so policy rules showed "PASS → Manual review".

  Now:
  - **Labelled:** a result restored from the recorded history says so.
  - **Compared only when it matches:** "What changed" appears only when the test was run on the same evidence, rule set and company policy as the assessment on screen. Otherwise the screen says why it can't compare and asks you to run the test again.
  - **Backend:** the run summary now carries those three fingerprints (hashes only, no new data). The policy fingerprint record also includes the approver's name.
  - **Tests and demo check:** 4 new tests. In the demo, an old run under a different policy now shows "comparison not shown"; a fresh run shows 1 improved, 0 got worse, with no "restored" label.

## 3. Tests
All on the final code, 7 Nov 2026:
- **Unit:** `pytest -q`: 4160 passed, 114 skipped, 61 deselected, 4 xfailed. That includes about 370 new Task 2 tests:
  - hostile container, docker-path, stage and object names;
  - SQL check bypasses, including dollar quoting, Unicode-escaped names and SQL-as-text functions;
  - masking;
  - the VHS runner's folder, environment, timeout and clean-up;
  - PASS or FAIL unchanged across 17 injected faults;
  - bundles, manifests and the DBA runner's allowlist;
  - the AI assistant filter and its unchanged tool list;
  - the demo setting.
- **Frontend:** typecheck clean; `npm test` 114/114, including the screenshot strip's checks that refuse malformed image data.
- **Live, on disposable Docker sandboxes** (`DBGUARD_POC_LIVE=1`): the Task 2 suites passed 6/6, with no containers or recording processes left:
  - setting fix (log_connections): 29.5 s;
  - add-on fix 3.2 (pgaudit): 29.3 s;
  - account fix on a deliberately hostile role name: 22.3 s;
  - combined test: 71.5 s;
  - VHS missing, so the rendered picture is used with the reason: 13.8 s;
  - forced timeout, after which nothing is left running: 13.7 s.
  
  Earlier in this round, `test_product_improvements_live.py` also passed (26 passed, 1 skipped).
- **Demo (7 Nov):** a single-fix test VERIFIED. The result shows before, after-fix and after-undo terminal pictures, and each opens full size with the typed command, the checks and the fingerprint. The start-up output shows the shared-machine warning.

## 4. Known limits
- **Tested on this Mac only.** Clean-up uses `ps` and `lsof`; on a system without `lsof` it still stops the recording's process group and its children.
- **One-time browser set-up:** VHS needs its browser downloaded once while online. DBGuard never downloads it during a test.
- **Short local terminal window:** while a picture is taken, a local-only terminal is open for a few seconds. Use terminal mode only on single-user machines.
- **Test time:** each test takes about 25 seconds longer (three pictures).
- **Pictures are evidence, not proof of authenticity:** the recorded query output and its fingerprint are the source of truth.

---

## Rulings (Melvin, 7 Nov 2026)
"Approve all recs": all four recommendations are approved.
1. **Task 2 is approved for commit and PR,** stacked on #43. The comparison fix goes in its own commit.
2. **The HERMES response filter is acknowledged.** It only removes screenshot images, raw query output, the checks' SQL and the typed command; the tools, inputs and permissions are unchanged.
3. **The combined-bundle top-level manifest stays conditional:** it is written only when the bundle contains screenshots.
4. **Defaults:** the product stays **rendered**; the demo uses **terminal** with the shared-machine warning.
