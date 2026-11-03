# ★ Gate 1: Wave 2a, per-object fixes for account and permission checks (F6)

## In plain words (read this first)
Today the 10 account, permission and backup checks only **report** problems: which accounts have admin powers, which tables anyone can change, and so on. This wave lets a database administrator **pick specific fixes from that list**. Examples: "remove SUPERUSER from `app_admin`", "lock the unused account `old_report`", "stop PUBLIC from running function `x`". DBGuard first rehearses each picked fix on a throwaway copy, proves it works and can be undone, then puts it in the instruction pack.

Nothing is applied to a real database by DBGuard, as before. Nothing is fixed in bulk: every fix is one object, chosen by a person.

**Your rulings are needed on 6 points** (end of this file). Recommendations are marked **Rec**.

---

## A. The six fix types

**Rendering.** Every statement comes from a new approved, hash-pinned template. Names are taken from the collected evidence and always quoted safely (the `ident` filter). Nothing is typed by an AI or a user.

**Proof.** After the fix, DBGuard re-reads the copy and checks one precise fact about that one object. It also checks that every other object it recreated is unchanged, and that the undo restores the object exactly.

| # | Fix (template) | For CIS | Statement | Undo | How we prove it worked | Risk (DRAFT) |
| --- | --- | --- | --- | --- | --- | --- |
| 1 | `role_connection_limit` | 5.5 | `ALTER ROLE "r" CONNECTION LIMIT n;` (n from your **approved company policy**: per-account value, else the default) | previous limit | the role's limit equals n | **Medium.** Too low a limit refuses new connections; superusers ignore limits |
| 2 | `role_drop_attribute` | 4.3, 4.9 | `ALTER ROLE "r" NO<ATTR>;` where ATTR ∈ SUPERUSER, CREATEROLE, CREATEDB, REPLICATION, BYPASSRLS, and only an attribute the role really has | `ALTER ROLE "r" <ATTR>;` | that attribute is now false | **High.** Tools or apps using that power fail. REPLICATION removal stops streaming replication that uses the role. BYPASSRLS removal can hide rows from reports |
| 3 | `role_nologin` | 4.4, 4.10 | `ALTER ROLE "r" NOLOGIN;` (never sets a password) | `ALTER ROLE "r" LOGIN;` | the role can no longer log in | **High.** Anything still using that account stops working |
| 4 | `function_security_invoker` | 4.5 | `ALTER FUNCTION "s"."f"(args) SECURITY INVOKER;` | `… SECURITY DEFINER;` | the function no longer runs as its owner | **High.** Callers without the owner's privileges get permission errors |
| 5 | `function_revoke_public_execute` | 4.5 | `REVOKE EXECUTE ON FUNCTION "s"."f"(args) FROM PUBLIC;` (only if PUBLIC really has EXECUTE) | `GRANT EXECUTE … TO PUBLIC;` | PUBLIC no longer has EXECUTE | **Medium–high.** Callers relying on PUBLIC access lose it; the DBA grants specific roles separately |
| 6 | `table_revoke_dml` | 4.6 | `REVOKE INSERT, UPDATE, DELETE … ON TABLE "s"."t" FROM "grantee"/PUBLIC;` (only privileges the evidence shows) | `GRANT` exactly those, `WITH GRANT OPTION` if the original had it | the grantee no longer holds those privileges | **High.** Application writes fail |

## B. Not offered (with reasons)
- **4.7, enable row-level security.** On a table with no policies it hides every row from non-owners, and writing policies is business logic. Stays report-only.
- **7.1, create a replication-only user.** That needs a password, which DBGuard never handles. Stays report-only.
- **4.9, grant a predefined role instead of superuser.** Which role suffices is a judgement call. Only the "remove SUPERUSER" part is offered, through fix #2.
- **7.4, backups.** Never; it would mean writing a backup command containing credentials.

## C. Objects never offered a fix (safety list)
- **The bootstrap superuser** (the cluster's first role, usually `postgres`): removing its powers or login could lock everyone out.
- **Built-in roles** starting with `pg_`.
- **Objects owned by an extension** (e.g. pgaudit functions). They are managed by the extension.
- **Functions whose argument types aren't standard built-in types.** The throwaway copy can't recreate them, so they show "can't rehearse".
- **Rec:** the account DBGuard itself collected with also gets no NOLOGIN or attribute-removal offer, so the next collection still works. It is shown with a note instead.

## D. How the rehearsal works (the "stand-in copy")
For each picked fix, the throwaway database recreates **only the object being fixed and what it needs**:
- a role gets its exact powers and limit, plus a random throwaway password only if the original had one;
- a table becomes an empty stand-in with the same owner and permissions;
- a function becomes a stub with the same arguments, owner, run-as setting and permissions.

No real data and no real passwords are ever copied. The rehearsal then runs:
1. **Confirm the problem exists** on the copy.
2. **Apply the fix.**
3. **Prove it**, and check nothing else changed.
4. **Undo it**, and confirm the copy matches the original.
5. **Destroy the copy.**

**In the instruction pack:** the DBA's runner checks that the object is still exactly as it was in the evidence before applying anything. It applies and undoes **inside one database transaction**, so a failure leaves nothing half-done.

## E. Where it shows in the app
In step 5 (fix plan), a new section **"Proposed fixes for accounts and permissions"** lists each affected object with tick-boxes. For example:
- "Remove SUPERUSER from `app_admin`: high risk".
- "Set connection limit 50 on `web` (from your company policy)".

The ticked fixes go into the existing single or combined test. Connection-limit fixes need an approved company policy; until then they show **COMPANY POLICY MISSING**.

## F. The coverage report (running in parallel)
`docs/COVERAGE.md` lists all 72 rules, each with one status:
- Live: fixable;
- Live: fixable once company policy is approved;
- Live: report-only, person decides (with "fix proposals in progress" for the F6 rules above);
- Live: human checklist;
- Needs capability (planned);
- Not started (with the planned week).

It is regenerated by a script, and a check keeps it in sync with the rules.

---

## Rulings needed
1. **Fix types:** approve the six fix types in table A, including their undo statements. **Rec:** yes.
2. **Exclusions:** approve the "not offered" list in B. **Rec:** yes.
3. **Safety list (C):** in particular, never offer NOLOGIN or power removal for **the account DBGuard collects with**. **Rec:** yes, show it with a note instead.
4. **Connection limits on superusers (5.5):** PostgreSQL doesn't enforce limits on superusers, and CIS still flags them. **Rec:** offer the fix for non-superusers only; superusers get the note "limit not enforced; remove SUPERUSER first (fix #2)".
5. **Risk levels:** approve the draft risk levels in table A. They're shown to the DBA and can only be raised, never lowered, by the AI review.
6. **Coverage report statuses (F):** approve the six categories.

---

## Rulings (Melvin, 30 Oct 2026)
"Accept all": all six recommendations are approved.
1. The six fix types and undo statements in table A.
2. The "not offered" list in B (4.7, 7.1, the 4.9 predefined-role grant, 7.4).
3. The safety list in C, including no NOLOGIN or power removal for the account DBGuard collects with; it is shown with a note instead.
4. Connection-limit fixes (5.5) for non-superusers only; superusers get the note "limit not enforced; remove SUPERUSER first (fix #2)".
5. The draft risk levels in table A. The AI review may only raise them.
6. The coverage report's status categories in F.
