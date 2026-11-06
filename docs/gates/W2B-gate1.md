# ★ Gate 1: Wave 2b, add-ons (F5) and login and encryption (F7)

Branch `melvin/wave2b-f5-f7`. Scope chosen by Melvin on 4 Nov: **"Also rehearse pgaudit"**. That means checks for all 8 rules; rehearsed fixes for 3.2 (pgaudit), 5.6 (password complexity) and 6.10 (weak ciphers); guided DBA steps for the rest.

## In plain words (read this first)
These 8 rules are about **add-on software** the database loads (an audit logger, a password checker, an encryption toolkit) and **how people log in** (which login routes exist and whether traffic is encrypted).

- **All 8 get a result with evidence**, so live coverage goes from **39 to 46** of 72 rules.
- **Three get a fix rehearsed on a throwaway copy**, so rehearsed fixes go from **33 to 36**:
  - turning on the **audit logger (pgaudit)**;
  - turning on the **password checker**;
  - removing **weak encryption ciphers**.
- **The other five get step-by-step guidance** for the DBA, because the fix needs something DBGuard must never handle: installing software on the server, a TLS certificate and its private key, or edits to the login rules file.

Two things are new for DBGuard:
1. **A throwaway copy with the audit logger installed.** The standard PostgreSQL image doesn't include pgaudit, so we build our own pinned image with it. The copy still has no network, as before.
2. **A throwaway certificate inside the copy.** To rehearse the cipher fix, encryption must be switched on in the copy. The copy makes its own one-time certificate, which never leaves it and is destroyed with it.

**Your rulings are needed on 9 points** (end of this file). Recommendations are marked **Rec**.

---

## A. The 8 rules

| CIS | Rule | Result DBGuard gives | Fix |
| --- | --- | --- | --- |
| 3.2 | pgaudit enabled | FAIL if `pgaudit` is not in `shared_preload_libraries`. FAIL if `pgaudit.log` is missing or lacks the classes in your **company policy**. Otherwise PASS | **Rehearsed**: add `pgaudit` to the preload list (keeping existing entries), set `pgaudit.log` from the policy, restart. The DBA must install the pgaudit package first |
| 5.6 | Password complexity | FAIL unless `passwordcheck` (or `$libdir/passwordcheck`) is preloaded and `dynamic_library_path` is `$libdir`. Otherwise PASS | **Rehearsed**: add `passwordcheck` to the preload list (keeping existing entries), restart. Ships with PostgreSQL; no install needed |
| 6.10 | Weak ciphers disabled | FAIL if `ssl_ciphers` lists anything outside the 4 CIS ciphers. FAIL if an established TLS 1.2 connection uses another cipher. **Unknown** if the connection list can't be read (needs `pg_read_all_stats`). Otherwise PASS | **Rehearsed**: set `ssl_ciphers` to the 4 CIS ciphers, reload |
| 6.8 | TLS enabled and enforced | FAIL if `ssl` is off, if any `host` / `hostnossl` login rule exists, or if any established TCP connection is unencrypted. **Unknown** if a part can't be read. Otherwise PASS | **Guided**: the DBA installs a CA-signed certificate and changes `host` rules to `hostssl`. DBGuard never handles keys |
| 4.8 | set_user installed | FAIL if `set_user` is not available on the server. Otherwise **person decides**, with the list of login accounts that hold superuser powers directly or inherited | **Guided**: install the package, preload, then the DBA reviews the superuser list |
| 6.11 | pgcrypto | **Human checklist** (CIS marks it Manual: "if data requires encryption"). Evidence: whether pgcrypto is available and installed | Guided: `CREATE EXTENSION pgcrypto` if the organisation needs it |
| 5.3 | Local (socket) logins | **Human checklist**. Evidence: the `local` login rules and their methods, with `trust` highlighted | Guided |
| 5.4 | Host (TCP) logins | **Human checklist**. Evidence: the `host*` login rules, their address ranges and methods, with `trust`, `password` and `0.0.0.0/0` highlighted | Guided |

**Unknown never counts as PASS**, as for every rule today.

## B. How the three rehearsed fixes work

### B1. Adding to the preload list (3.2, 5.6)
- **The fix appends, never replaces.** The new value is the current list plus the library, in the same order, with no duplicates. It is rendered by the existing approved `set_config_parameter` template, so no new SQL template is needed.
- **It needs a restart.** `shared_preload_libraries` joins the reviewed restart list. The sandbox already handles restarts (5.2 and 3.1.3 use it).
- **The danger, and the guard:** if the preload list names a library that isn't installed, **PostgreSQL will not start**. So:
  - the sandbox proves the server restarts cleanly with the new list;
  - the DBA's runner refuses to apply unless the library is installed on the target. It checks `pg_available_extensions` for pgaudit, and for passwordcheck, which ships with PostgreSQL, a `LOAD` test in a throwaway session.
- **3.2 also sets `pgaudit.log`** to the classes in your approved company policy (decision 2). Until the policy is approved, 3.2's fix shows **COMPANY POLICY MISSING**, like the other policy rules.

### B2. Cipher list (6.10)
- `ALTER SYSTEM SET ssl_ciphers = '<4 CIS ciphers>'`, then reload. The approved template is reused.
- **Rehearsal:** the copy switches `ssl` on using a self-signed certificate it makes itself (OpenSSL is already in the image). It then:
  - opens a TLS 1.2 connection inside the copy;
  - checks that only the 4 CIS ciphers are negotiated;
  - undoes the change.

  The certificate and key exist only in the copy's temporary memory storage and are destroyed with it. They are never logged, collected or bundled.
- **The bundle does not switch `ssl` on.** That is 6.8's guided step, with the DBA's own certificate.

### B3. The pgaudit sandbox image
- **Build:** the stock `postgres:17-bookworm` image plus the `postgresql-17-pgaudit` package at a **pinned version**. The image digest is pinned in the repo, and a script rebuilds it.
- **Isolation unchanged:** at run time the sandbox still has no network, no host mounts and no raw SQL.
- **Rec:** use this one image for **all** sandboxes. It has nothing preloaded, so existing tests behave the same. Every live suite is re-run on it before switching.

## C. Collector additions (read-only, security-reviewed before they're applied)
1. **`available_extensions`**: name, default version and installed version from `pg_available_extensions`. Needed for 4.8 and 6.11, and for the runner's install check.
2. **TLS details in `connections`**: for each existing group, also whether it is encrypted, the TLS version and the cipher, from `pg_stat_ssl`. Needed for 6.8 and 6.10.

   Without `pg_read_all_stats`, other users' sessions are hidden. Their encryption state is then reported as not collected, and the result is Unknown, never PASS.

## D. Not offered (with reasons)
- **Installing software** (pgaudit, set_user packages): an operating-system change outside the database. Guided steps only.
- **Certificates and keys for 6.8:** DBGuard never handles private keys.
- **Editing `pg_hba.conf` (5.3, 5.4, 6.8):** a file edit on the server, and a mistake locks people out. Guided steps list the exact rules to change. A rehearsed `pg_hba` edit stays on the roadmap as a later item.
- **4.8's "authorised superusers" judgement:** a person decides, from the evidence list.

## E. Risk levels (DRAFT)
| Fix | Risk | Why |
| --- | --- | --- |
| 3.2 pgaudit | **High** | Restart. A missing package stops the server starting (the runner guards against this). Can produce an *enormous volume of logging* (CIS's words) |
| 5.6 passwordcheck | **Medium** | Restart. New passwords that are too weak are refused, so account-creation scripts may fail. Existing and pre-hashed passwords are not checked (CIS's own caveat) |
| 6.10 ciphers | **Medium** | Old clients that only support other ciphers lose TLS connections. TLS 1.3 is unaffected |

---

## Rulings needed
1. **Scope and results (table A):** approve the result rules for all 8, including Unknown when connection or TLS data can't be read. **Rec:** yes.
2. **pgaudit classes (3.2):** CIS leaves "desired components" to the organisation. Add `pgaudit_log_classes` to the company policy. **Rec:** default `ddl,role,write`. The CIS example `ddl,write` plus ROLE, so grants and account changes are audited. READ is excluded because it multiplies log volume. The PASS rule is "contains at least the policy classes".
3. **Preload fixes (B1):** appending to `shared_preload_libraries`, the restart, and the runner's "library installed" guard. **Rec:** yes.
4. **Cipher rehearsal (B2):** the throwaway in-sandbox certificate, never leaving the copy. **Rec:** yes.
5. **pgaudit image (B3):** build a pinned image with pgaudit and use it for all sandboxes. **Rec:** yes, after every live suite passes on it.
6. **Collector additions (C):** `available_extensions`, and TLS details in `connections`. **Rec:** yes, applied only after a security review.
7. **4.8 result:** FAIL if set_user is not available, else "person decides" with the superuser list. **Rec:** yes.
8. **Guided-only list (D):** packages, certificates, `pg_hba` edits and 4.8's judgement. **Rec:** yes.
9. **Risk levels (E):** approve the draft levels. The AI review may only raise them.

---

## Rulings (Melvin, 5 Nov 2026)
"Accept all": all nine recommendations are approved.
1. The result rules in table A for all 8, with Unknown (never PASS) when connection or TLS data can't be read.
2. `pgaudit_log_classes` joins the company policy, default `ddl,role,write`; 3.2 passes when `pgaudit.log` contains at least the policy classes.
3. Preload fixes append to `shared_preload_libraries`, restart, and the runner refuses unless the library is installed on the target.
4. 6.10 is rehearsed with a throwaway in-sandbox certificate that never leaves the copy.
5. A pinned sandbox image with pgaudit, used for all sandboxes once every live suite passes on it.
6. Collector additions `available_extensions` and TLS details in `connections`, applied only after a security review.
7. 4.8: FAIL if set_user is not available, otherwise "person decides" with the superuser list.
8. Guided only: packages, certificates, `pg_hba` edits, 4.8's judgement.
9. Risk levels: 3.2 high, 5.6 medium, 6.10 medium; the AI review may only raise them.

## Rulings round 2 (Melvin, 5 Nov 2026, after the CIS fidelity review)
1. **Replication connections:** the collector keeps them (with their type), so 6.8 and 6.10 check them as CIS does. Security-reviewed before it is applied.
2. **6.8 GSS rule types:** a `hostnogssenc` or `hostgssenc` login rule makes 6.8 "person decides" (never PASS). Amends table A.
3. **4.8 empty superuser list:** PASS when set_user is available and no login account holds superuser powers, directly or inherited; otherwise "person decides". Amends ruling 7 for this case.
4. **Refinements:**
   - 3.2: `$libdir/pgaudit` and `pgaudit.so` count as pgaudit, since CIS says "contains pgaudit".
   - 5.6: `$libdir/passwordcheck` with a non-`$libdir` library path gives "person decides" instead of FAIL.
   - 3.2 is marked as a company-policy rule (the engine allows `parameterised` for catalog checks).
   - 5.4 also highlights `ident` and `md5` and shows each rule's address. 5.3 highlights local methods other than peer and reject, and shows user-mapping options. Highlights only; both stay checklists.

## Rulings round 3 (Melvin, 5 Nov 2026, during the build)
1. **List template:** add one new reviewed template that writes `shared_preload_libraries` as a proper quoted list (keeping existing entries), demo-approved (`DEMO_FIXTURE_ONLY`) like the others and security-reviewed. Then 3.2 and 5.6 work on servers that already preload libraries, and can be done together.
2. **5.6 risk:** shows **high**, because the existing rule raises every restart fix to high. The reviewed "medium" stays alongside for reference.
