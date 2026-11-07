# ★ Gate 1: Task 2, terminal (VHS) screenshots of sandbox tests

Branch `melvin/task2-vhs-screenshots` (cut from the PR #43 branch). Rulings below; build in progress.

## In plain words (read this first)
Today DBGuard takes **one** screenshot per tested fix, **after** the fix. It's a browser page that shows the query results. Account and permission fixes get none.

Task 2 asks for **before, after and undo** screenshots for every tested fix. Your supervisor prefers screenshots of a **real terminal** over a rendered page. We'll use **VHS**, a terminal recorder, installed on this Mac (your decision of 7 Nov). It opens a real terminal, types fixed commands into the throwaway sandbox database, and takes a picture of the result.

**One safety point to know before ruling.** VHS types into a **real shell on the computer running DBGuard**, not inside the sandbox. Anything it types would run on that computer. So the rule is the same as for SQL today: **every typed line comes from a fixed, reviewed template**. Names (accounts, settings, the sandbox container) are checked against a strict pattern first. Anything unexpected means **no terminal recording** for that stage. It never means typing something unchecked.

We are **not** running VHS in a Docker container. That would need access to the sandbox (which has no network by design) or to Docker itself, which is a major security risk. That option stays off the table unless a separate security design is reviewed.

## Your decisions

1. **What each picture shows.** There are three pictures per single-fix test, each from a fresh terminal on the throwaway copy:
   - **Before:** the problem reproduced.
   - **After fix:** the fix in place.
   - **After undo:** back exactly as before.

   Each picture shows only fixed, read-only checks:
   - **for a setting fix:** the setting's value and where it comes from (`SHOW`, and `pg_settings` name, setting and source);
   - **for an add-on/login fix (3.2, 5.6, 6.10):** each changed setting;
   - **for an account or permission fix:** that one object's attributes (for example `rolcanlogin` for one role, or one table's grants);
   - **always:** the database identity (database name, version, sandbox run ID).

   It never shows passwords, password hashes, `pg_authid`, keys, certificates or connection strings.
   **Rec:** yes.
2. **Combined tests.** Three pictures for the whole combined test: before (once), after all fixes, and after the undo. Not one per step.
   **Rec:** yes. Per-step pictures would multiply recording time (about 10 seconds each) for little extra evidence.
3. **Picture format.** PNG stills only. Each is fingerprinted (sha256) and listed in the bundle's manifest. No GIF or video for now.
   **Rec:** yes. Stills are small, easy to review and easy to verify.
4. **How the terminal reaches the sandbox (tightened after your "yes", 7 Nov).** No name from the database ever passes through the shell on this computer.
   - **First,** DBGuard writes the stage's SQL **inside the sandbox**, as `/var/run/postgresql/dbguard-<stage>.sql`. It uses the same method as its config writes: a constant command with the content sent as data, never through a shell.
   - **Then** VHS types exactly **one fixed command:** `docker exec -i <container> psql -X -e … -f /var/run/postgresql/dbguard-<stage>.sql`. The SQL file starts by making the session read-only. `-e` makes psql print each query above its result, so the picture shows what was asked.
   - **The only variable in the typed line is the container name.** It must match `dbguard-poc-<32 hex>`, equal this run's own name, and the container must carry this run's label. `<stage>` is one of `before`, `after`, `rollback`. The path to `docker` is resolved once and must be an absolute path without spaces.
   - **Second layer:** the tape builder refuses any typed line containing a quote other than the fixed ones, a backslash, backtick, `$`, `;`, `|`, `&`, `<`, `>`, a newline or a control character. Names inside the SQL are still quoted with the reviewed `ident` helper.
   - **The shell:** starts with no user profile (`env -i … bash --norc --noprofile`), a fixed prompt (`sandbox$`) and a minimal environment (`PATH`, `TERM`), so no host user name, machine name or environment values appear in the picture.

   **Rec:** yes.
5. **When VHS is missing or fails.** DBGuard falls back to today's rendered picture for that stage. The run records `terminal: UNAVAILABLE` with the reason, and the screen and bundle say so. A screenshot problem **never** changes a fix's PASS or FAIL.
   **Rec:** yes.
6. **Where it runs.** Only in sandbox tests: Task 2 says sandbox evidence is enough. The DBA bundle's own `verify.sh --screenshots` keeps the rendered capture on the real target. A terminal recording on the DBA's machine would risk showing their connection details.
   **Rec:** yes.
7. **Switching it on.** A new setting, `DBGUARD_SCREENSHOT_MODE`:
   - `rendered` (today's behaviour) is the default;
   - `terminal` adds VHS pictures, with the rendered picture as fallback;
   - the demo uses `terminal`.

   **Rec:** yes.
8. **Recorded tool versions.** Each picture's evidence record includes the VHS, ttyd and ffmpeg versions and the exact typed text, so a reviewer can see what produced it. DBGuard doesn't refuse other versions, but records them.
   **Rec:** yes.
9. **On screen.** Each result shows an **"Evidence screenshots"** strip with three thumbnails (Before, After fix, After undo), each labelled terminal or rendered. Clicking a thumbnail opens it full size.
   **Rec:** yes.

## Known limits (no ruling needed; for your awareness)
- **ttyd listens briefly on this computer.** While a picture is taken, VHS starts ttyd on `127.0.0.1` on a random port for a few seconds. Another program on the same computer could in principle connect during that window. That's acceptable for a single-user Mac; on a shared server, the terminal mode should stay off.
- **A picture is evidence, not proof of authenticity.** As today, the JSON next to each picture is the source of truth, and the picture's fingerprint only detects accidental changes.
- **Recording time.** Each picture takes roughly 5–10 seconds, so a single-fix test grows by about 30 seconds.

## Build plan after your rulings
1. **evidence-capture-engineer:** a tape builder from fixed templates, a VHS runner with timeout and fallback, the three stages wired into single, catalog, per-object and combined tests, and bundle and manifest entries.
2. **Frontend:** the screenshot strip.
3. **test-writer:**
   - unit tests for the tape builder, including names designed to break the shell or the tape, which must be refused;
   - fallback when VHS is missing;
   - live sandbox tests that produce three real terminal pictures per fix type.
4. **db-security-reviewer:** focused on what the tapes type into the host shell.
5. **Demo check, then Gate 2.**

---

## Rulings (Melvin, 7 Nov 2026)
"yes please make sure of the safety and security": all recommendations are approved, with safety and security as the priority. In response, decision 4 is tightened (above): evidence-derived names never reach the host shell, because the SQL is written inside the sandbox and VHS types only one fixed command.

VHS 0.12.1, ttyd 1.7.7 and ffmpeg 9.0.2 are installed with Homebrew. On its first run VHS downloaded its own Chromium into `~/.cache/rod/browser`. The build should prefer the Playwright Chromium DBGuard already uses, if VHS allows that.
