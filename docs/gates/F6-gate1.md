# F6 + CIS 7.4 — Gate 1 (specs and collector proposal)

Branch `melvin/wave1b-f6-catalog` (worktree `wonderful-wilbur-8162a2`), base `main` @ d9639bd. Approved at Gate 2 on 29 Oct 2026 (see `F6-gate2.md` §6).
Melvin's standing rulings: 7.4 is report-only (DBGuard never writes `archive_command`); F6 fix proposals
are next week. Every spec below is `authored_by: agent` and needs Melvin's approval.

**Where things are**

| What | Path |
| --- | --- |
| 10 draft specs | `docs/gates/F6-specs/*.yaml`, parked outside `catalog/specs/`. Today `spec_controls.load_spec_controls()` raises on the first spec it cannot validate, so with these files in `catalog/specs/` every `import app` breaks, `validate_specs.py` included. They move into `catalog/specs/cis-pg17-v1.1.0/` together with the engine change |
| Collector proposal (exact SQL, unified diff against `collector/collect.sql`) | `docs/gates/F6-gate1-collector.diff` |
| This report | `docs/gates/F6-gate1.md` |

## 1. Controls

Evidence is names and attributes only: no password hashes, no function bodies, no `archive_command` text.
"Connected DB" means the snapshot only covers the database the collector connected to. Catalog objects
(tables, functions, policies) live in a single database; roles are cluster-wide.

| Rec | Title | CIS status | Tier | Evaluator | Evidence shown | Pass/fail rule | Reviewer verdict | Open questions |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 4.3 | Ensure excessive administrative privileges are revoked | Manual | manual_checklist | `roles_with_admin_attributes` | Non-predefined roles with any of superuser, createrole, createdb, replication, bypassrls; each role's attribute flags and login flag | Always MANUAL (or GAPPED). CIS has only an example fail; "excessive" is a human call | APPROVE FOR HUMAN REVIEW | Q2 (PASS when the list is empty?) |
| 4.4 | Lock Out Accounts if Not Currently in Use | Manual | manual_checklist | `login_roles` | Login roles matching `rolname !~ '^pg_'`, with rolvaliduntil, password type and superuser flag | Always MANUAL. "Inactive accounts should not be shown in the output." The catalog does not record whether an account is in use | APPROVE FOR HUMAN REVIEW | — |
| 4.5 | Ensure excessive function privileges are revoked | **Automated** | manual_checklist | `elevated_functions` | Functions with `prosecdef` or a `proconfig`, excluding `proname LIKE 'pgaudit%'` (as in CIS): schema, name(args), owner, SECURITY DEFINER flag, `search_path`, other config names, EXECUTE ACL. Connected DB | PASS only if the set is empty **and** no other connectable non-template database exists. Otherwise MANUAL, because the fail depends on "not required or ... expressly forbidden by organizational guidance" | APPROVE FOR HUMAN REVIEW (after its evaluator changes: DB scope, NULL ACL, pgaudit by extension) | Q2, Q3 (tier), Q6 (per DB) |
| 4.6 | Ensure excessive DML privileges are revoked | Manual | manual_checklist | `table_dml_grants` | For each table that has an ACL: grantees other than the owner (including PUBLIC) holding INSERT, UPDATE or DELETE, parsed from `relacl`; members of `pg_write_all_data`; superusers. Connected DB | Always MANUAL. The decision is made "with application developers" | CHANGES NEEDED (evaluator), adopted: DB scope, group expansion, owner | Q6 |
| 4.7 | Ensure Row Level Security (RLS) is configured correctly | Manual | manual_checklist | `rls_tables_and_bypass_roles` | RLS-enabled tables with the forced flag, and policy name, command and roles for each (no `qual` text); roles with BYPASSRLS and their superuser flag. Connected DB | Always MANUAL. Which tables need RLS "is unique to each organization" | CHANGES NEEDED (evaluator), adopted: superusers/owners bypass, zero-policy flag, DB scope | Q6 |
| 4.9 | Make use of predefined roles | Manual | manual_checklist | `superuser_roles` | Roles with `rolsuper`, with login flag | Always MANUAL. CIS has no fail sentence | APPROVE FOR HUMAN REVIEW | — |
| 4.10 | Ensure all accounts that can log in have passwords | Manual | manual_checklist | `login_roles_without_password` | Login roles whose derived `password_type` is `none`, plus the `pg_hba` rules that could match each one (line, type, database, user, method) | PASS if no login role lacks a password. Otherwise MANUAL: a human verifies a non-password hba method. GAPPED if `password_types` is gapped (needs pg_authid). If only `hba_rules` is gapped, the result is MANUAL with that gap shown | CHANGES NEEDED (evaluator, minor), adopted: hba over-include, `trust` highlight | Q2 |
| 5.5 | Ensure per-account connection limits are used | Automated | **automated** | `role_connection_limits` | Login roles not starting with the literal prefix `pg_`, with rolconnlimit and the superuser flag, failing roles first. Superusers carry a note that PostgreSQL does not enforce the limit for them. NOLOGIN roles at -1 are listed as information | FAIL if any role in scope has `rolconnlimit = -1`, else PASS. "Any user with a connection limit of `-1` should be considered a failure." | CHANGES NEEDED (spec + evaluator), adopted: scope rulings, `interpretation` | Q4 (scope) |
| 7.1 | Ensure a replication-only user is created and used for streaming replication | Manual | manual_checklist | `replication_roles` | Roles with `rolreplication OR rolsuper` (superusers can replicate without the attribute), each flagged. Replication-in-use evidence: hba rules whose database is `replication`, replication slots, `in_recovery`, and the user in primary_conninfo | Always MANUAL. CIS has no fail sentence ("In a default PostgreSQL cluster, only the `postgres` user will have this permission" describes the default) | CHANGES NEEDED (evaluator), adopted: `rolreplication OR rolsuper`, replication-in-use evidence | Q7 |
| 7.4 | Ensure WAL archiving is configured and functional | Automated | **automated** (configuration) | `wal_archiving` | archive_mode, archive_library, `archive_command_is_set` (boolean), pg_stat_archiver counts and timestamps | FAIL if archive_mode is not `on`/`always`, if neither command nor library is set, or if both are set. Configured: MANUAL with the counters, highlighting a last failure later than the last success (Q5). GAPPED if `archiving` is null or gapped | CHANGES NEEDED (spec), adopted: `always`, both-set FAIL, `interpretation` | Q5 |

The CIS quotes (each one checked as a whitespace-collapsed verbatim substring of its audit procedure):

| Rec | `pass_condition_quote` |
| --- | --- |
| 4.3 | "While this example demonstrated excessive administrative privileges granted to a single user, a comprehensive audit should be conducted to inspect all database users for excessive administrative privileges." |
| 4.4 | "Inactive accounts should not be shown in the output." |
| 4.5 | "In the query results, a `prosecdef` value of '`t`' on a row indicates that that function uses privilege elevation. If elevation privileges are utilized which are not required or are expressly forbidden by organizational guidance, this is a fail." |
| 4.6 | "Therefore, the commands below should be executed for each defined database in the cluster. With this information, inspect database table grants and determine if any are excessive for defined database users." |
| 4.7 | "The first step for an organization is to determine which, if any, database tables require RLS. … If any table(s) should have RLS policies applied, but do not appear in this query's results, then this is a fail." (four sentences, one contiguous passage) |
| 4.9 | "Review the list of all database roles that have `superuser` access and determine if one or more of the predefined roles would suffice for the needs of that role:" |
| 4.10 | "For each role returned, verify that it authenticates exclusively through a non-password method configured in `pg_hba.conf` (such as certificate, GSSAPI, or LDAP authentication). Any returned role that is not verified to use such a method is a fail." |
| 5.5 | "Any user with a connection limit of `-1` should be considered a failure." |
| 7.1 | "Check which users currently have the replication permission:" |
| 7.4 | "If no rows are returned, as shown, this is a failure. If rows are returned, note that `archive_mode` must be 'on' and either `archive_command` or `archive_library` must be set for WAL archiving to be fully enabled." |

### 1b. Review results and what changed

**benchmark-fidelity-reviewer, first pass.** APPROVE FOR HUMAN REVIEW: 4.3, 4.4, 4.9. CHANGES NEEDED: the
other seven, mostly on how the evaluators would behave rather than on the spec text. Every quote checked as
verbatim, and every tier was judged honest, including 4.5 as manual_checklist despite CIS's "Automated".
All of its evaluator points are adopted in the table above, with one exception:

- **Declined: deriving `archive_command_is_set` from the raw value.** `pg_settings.setting`, `SHOW` and
  `current_setting` all report `(disabled)` when archive_mode is off, and that is what the CIS query tests.
  The two readings differ only when archive_mode is off, and then the result is FAIL either way.

**Spec text changes (spec-author).** 4.5, 5.5 and 7.4 now carry an `interpretation` list, a proposed
schema key (Q8) that records where DBGuard deviates from a literal reading of CIS:

| Rec | Interpretation entries |
| --- | --- |
| 4.5 | Exclude only functions **both** named `pgaudit%` **and** owned by the pgaudit extension (**stricter**). PASS only when nothing matches and no other connectable non-template DB exists; otherwise MANUAL with the uncovered DBs listed (**stricter**) |
| 5.5 | Literal `pg_` prefix, so `pgbouncer` and `pgadmin` stay in scope (**stricter**). NOLOGIN roles are excluded ("Any user", `ALTER USER` remediation) and listed for information (**narrower**). Superusers stay in scope, with a note that the limit is not enforced for them (**same as CIS**) |
| 7.4 | `always` is accepted alongside `on` (**wider**). Both command and library set is a FAIL (**stricter**; verified live). A correct configuration gives MANUAL, not PASS, because "changing" counters need observation over time |

**Checked live** on PostgreSQL 17.11 (`postgres:17-bookworm`, `--network none`, removed afterwards):
- A SUPERUSER role with `CONNECTION LIMIT 0` still connects; a normal role is refused with "too many connections for role".
- With archive_mode=on and both settings set, the archiver exits `FATAL: both "archive_command" and
  "archive_library" set` while `pg_stat_archiver.failed_count` stays **0**. The counters alone would hide
  this, which is why both-set is a FAIL.

**benchmark-fidelity-reviewer, delta pass** (interpretation entries plus the adopted evaluator plan):

| Spec | Verdict | Notes |
| --- | --- | --- |
| 4.5 | APPROVE FOR HUMAN REVIEW | Both entries are accurate and stricter than CIS. Optional note for Melvin: template1 accepts connections and new databases copy its functions. Excluding templates is no weaker than CIS |
| 5.5 | CHANGES NEEDED → applied | Entry 2 (NOLOGIN) **narrows** the literal query and now says so. Entries now state their direction, and entry 1 no longer quotes CIS SQL. Consider showing a normal role at limit 0 (locked out, yet PASS) in the evidence |
| 7.4 | CHANGES NEEDED → applied | Entry 1 (`always`) **widens** CIS's literal 'on' and now says so. Entry 2 now records the live result that `failed_count` stays 0. Optional: show `in_recovery` in the MANUAL evidence (on a standby with `on`, nothing is archived) |
| Others | unchanged | 4.3, 4.4, 4.9 approved for human review. The adopted plan covers 4.6, 4.7, 4.10 and 7.1 |

- **Decline on `archive_command_is_set`: agreed.** The decision never changes. The evaluator must treat both `''` and `(disabled)` as not set, as the collector does.
- **7.1 `primary_conninfo` may contain `password=`.** Already handled. The collector exposes only
  `replication.primary_conninfo_parsed`, which `parse_conninfo` builds with `password`/`passfile` dropped
  (collect.sql:100). The evaluator reads only its `user` key.
- **Q2, its view:** yes. PASS only when the review set is empty **and complete** (no gapped section; for 4.5 every connectable DB covered), labelled as an empty-review-set PASS. A non-empty set never PASSes.
- **The `extension` field** changes `collect.sql`, so it falls under the collector approval rule (Q10).

**Validation status.** A scratch checker confirms all 10 specs: verbatim quotes, ref fields matching
records.json, the check shape, evaluator names, hard-coded constants as whole tokens, and well-formed
`interpretation` entries (`all ok`). `scripts/validate_specs.py` still passes the 15 existing specs. It
rejects the 10 new ones only for the not-yet-supported kind and shape. They will pass once the engine change lands.

## 2. Design of the `catalog` check kind (for approval)

Spec shape. There is no SQL in a spec and no `proof`, because catalog checks never get a fix:

```yaml
tier: automated            # or manual_checklist (reason required)
check:
  kind: catalog
  evaluator: role_connection_limits
  pass_condition_quote: "Any user with a connection limit of `-1` should be considered a failure."
```

- **Fixed registry** in `backend/app/services/spec_engine/catalog_checks.py`. Each entry gives the
  evaluator function, the one recommendation it may serve, the tiers it supports, the baseline sections it
  reads, and the constants it hard-codes (`quote_tokens`, e.g. `-1` for 5.5). The validator rejects
  four things: an unknown evaluator, an evaluator wired to a different recommendation or tier, a
  `quote_tokens` entry that is not a whole token in the spec's quote, and any `proof`. This ties the
  code's constants to the CIS text, the way `expected` is tied today.
- **Schema exception.** Today non-automated tiers must not have `check`. The one exception is
  `manual_checklist` with `kind: catalog`, because it names the evaluator that builds the human's evidence
  list. `parameterised` and `needs_capability` keep the old rule.
- **Results.** PASS, FAIL, MANUAL or GAPPED, plus `evidence: [{...}]` (names and attributes) and
  `evidence_paths`. A null section, a section with a matching `gaps` entry, a missing field on a row, or a
  PostgreSQL major other than 17 gives GAPPED, never PASS. `[]` means collected and empty.
- **Wiring** (after approval): `validate.py`, `schema.json`, `assess.py` (`_decide` calls the evaluator on
  `snapshot.baseline`; MANUAL rows carry evidence), `spec_controls.py`, the sandbox `SpecEngine`,
  `provenance.py:32` and `review_bundle.py:59` skip non-setting checks, `planning.fix_scope` rejects catalog
  checks, and the UI assessment step lists evidence. Each change goes in its own block, apart from the main
  session's operator and `applies_when` edits. `manifest.py` stays settings-only: catalog evaluators read the
  baseline and need no manifest entry.

## 3. Collector proposal (exact SQL)

The full diff is in `docs/gates/F6-gate1-collector.diff` (+84 lines, nothing removed).

**Update (round 2):** Melvin approved this proposal (B10, 28 Oct) after db-security-reviewer's
PASS WITH NOTES, and it is now applied. The notes changed the SQL: `config_names` is coalesced to `[]`,
a NULL `proacl` is expanded with `acldefault`, `archive_library` uses `current_setting(..., true)`, and the
functions gap remediation names all five catalogs. The SQL below is the earlier draft; the authoritative text
is `docs/gates/F6-gate1-collector.diff` (`collect.sql` equals HEAD plus that diff, byte for byte).

```sql
-- section 2 helper. Same predicate as the CIS 4.5 audit query.
CREATE FUNCTION pg_temp.sql_functions() RETURNS text AS $$
    SELECT $q$
        SELECT coalesce(jsonb_agg(jsonb_build_object(
            'schema',        n.nspname,
            'name',          p.proname,
            'identity_args', pg_get_function_identity_arguments(p.oid),
            'kind',          p.prokind,
            'language',      l.lanname,
            'prosecdef',     p.prosecdef,
            'config_names',  (SELECT jsonb_agg(split_part(c, '=', 1) ORDER BY ord)
                              FROM unnest(p.proconfig) WITH ORDINALITY AS u(c, ord)),
            'search_path',   (SELECT substring(c from position('=' in c) + 1)
                              FROM unnest(p.proconfig) c
                              WHERE split_part(c, '=', 1) = 'search_path' LIMIT 1),
            'owner',         pg_get_userbyid(p.proowner),
            -- NULL acl = the default: PUBLIC may EXECUTE
            'acl',           p.proacl::text[],
            'extension',     (SELECT e.extname FROM pg_depend d
                              JOIN pg_extension e ON e.oid = d.refobjid
                              WHERE d.classid = 'pg_proc'::regclass AND d.objid = p.oid
                                AND d.refclassid = 'pg_extension'::regclass AND d.deptype = 'e')
        ) ORDER BY n.nspname, p.proname, pg_get_function_identity_arguments(p.oid)), '[]'::jsonb)
        FROM pg_proc p
        JOIN pg_namespace n ON n.oid = p.pronamespace
        JOIN pg_language  l ON l.oid = p.prolang
        WHERE p.prosecdef OR p.proconfig IS NOT NULL
    $q$;
$$ LANGUAGE sql IMMUTABLE;

-- section 2 helper. archive_command is never returned, masked or not.
CREATE FUNCTION pg_temp.sql_archiving() RETURNS text AS $$
    SELECT $q$
        SELECT jsonb_build_object(
            'archive_mode',           current_setting('archive_mode'),
            'archive_library',        current_setting('archive_library'),
            'archive_command_is_set', current_setting('archive_command') NOT IN ('', '(disabled)'),
            'stat_archiver', (SELECT jsonb_build_object(
                'archived_count',     archived_count,
                'last_archived_wal',  last_archived_wal,
                'last_archived_time', last_archived_time,
                'failed_count',       failed_count,
                'last_failed_wal',    last_failed_wal,
                'last_failed_time',   last_failed_time,
                'stats_reset',        stats_reset)
              FROM pg_stat_archiver)
        )
    $q$;
$$ LANGUAGE sql IMMUTABLE;

-- baseline sections
'functions',        pg_temp.try_jsonb(pg_temp.sql_functions()),
'archiving',        pg_temp.try_jsonb(pg_temp.sql_archiving()),

-- gaps (UNION ALL branches, same pattern as hba_rules)
SELECT jsonb_build_object('section','functions',
       'reason', pg_temp.try_reason(pg_temp.sql_functions()),
       'remediation','pg_proc is readable by every role by default; restore SELECT on pg_proc, pg_namespace and pg_language.')
WHERE pg_temp.try_reason(pg_temp.sql_functions()) IS NOT NULL
UNION ALL
SELECT jsonb_build_object('section','archiving',
       'reason', pg_temp.try_reason(pg_temp.sql_archiving()),
       'remediation','archive_mode, archive_library, archive_command or pg_stat_archiver could not be read. Null here does NOT mean archiving is off.')
WHERE pg_temp.try_reason(pg_temp.sql_archiving()) IS NOT NULL

-- redactions (three new entries)
pg_proc.prosrc              S0  Function bodies are never selected.
pg_proc.proconfig           S2  Setting names only; the search_path value is the one value returned.
archiving.archive_command   S0  Never returned in the archiving section; only archive_command_is_set (boolean).
```

Design choices to approve:

- `functions` keeps the CIS predicate (`prosecdef OR proconfig IS NOT NULL`), so the section stays small
  (`[]` on a fresh PG17). The `pgaudit%` exclusion is applied in the evaluator, not in the collector.
- Of `proconfig`, only the setting **names** are returned, plus the `search_path` value. A SET clause can
  carry a custom GUC value (e.g. `SET myapp.password = '…'`). `search_path` is the value that decides whether
  a SECURITY DEFINER function can be hijacked.
- `archive_command_is_set` follows CIS: SHOW gives `(disabled)` while archive_mode is off, so it is false then.
- The snapshot contract `snapshot-v0.3.0.json` has `baseline.additionalProperties: true`, so there is no
  contract or schema-version bump. `tests/fixtures/phase1/snapshot-pg17-live.json` is re-recorded from a
  disposable PG17 after the change is applied.

**Dry run.** I ran the proposed collector against a throwaway `postgres:17-bookworm` container
(`--network none`, removed afterwards) as a superuser and as a plain LOGIN role:

| Case | Result |
| --- | --- |
| SECURITY DEFINER fn with `SET search_path = pg_catalog, public SET myapp.password = 'SUPERSECRET1'`, plus a SET-only fn whose body contains `SUPERSECRET2` | Both listed. `config_names` `["search_path","myapp.password"]`, `search_path` value only. Neither secret appears anywhere in the output (whole-bundle string search) |
| `archive_command = 'cp %p rclone://tok:SUPERSECRET3@bucket/%f'`, mode off | `archive_command_is_set: false` (CIS semantics) |
| Same, after `archive_mode = on` and a restart | `archive_command_is_set: true`, `failed_count: 3`, `archived_count: 0`. The command text is not in `archiving` |
| `REVOKE SELECT ON pg_proc FROM PUBLIC`, low-privilege run | `functions: null` plus gap `functions: insufficient_privilege`. The run still completes |
| Plain LOGIN role on PG17 | `archiving` is readable (archive_* are not superuser-only on 17), so no gap |
| Fresh cluster | `functions: []` |
| `REVOKE EXECUTE … FROM PUBLIC; GRANT EXECUTE … TO lowpriv` on a SECURITY DEFINER fn; `CREATE EXTENSION pageinspect` | `acl: ["postgres=X/postgres","lowpriv=X/postgres"]`, `extension: null` (user function). The `extension` subquery resolves `page_header → pageinspect`. It runs as a low-privilege role |

## 4. Open questions for Melvin

Each question has a recommendation. **Bold** marks the ones that change the specs or the collector.

1. **Catalog check design (§2).** May `manual_checklist` carry a `kind: catalog` check, as the one exception
   to "non-automated tiers have no check"? And should the registry bind each evaluator to one
   recommendation and its constants (`quote_tokens`)? *Recommend yes to both.*
2. **PASS from a manual_checklist when the CIS review set is empty (4.5, 4.10).** CIS says "For each role
   returned, verify…" (4.10) and "a `prosecdef` value of '`t`' on a row indicates…" (4.5). With no rows
   there is nothing to review. spec-author flags that this conflicts with the tier's name. *Recommend yes:
   the evaluator returns PASS only for an empty set (and for 4.5 only when every connectable DB is covered).
   The tier stays manual_checklist because any non-empty result needs a human.* The alternative is
   always MANUAL with an empty list.
3. **4.5 tier.** manual_checklist now. Later it could become `parameterised` with an org allowlist of approved
   SECURITY DEFINER functions in the main session's policy profile. *Recommend manual_checklist this week;
   the allowlist goes on the F3 follow-up list.*
4. **5.5 scope.** Login roles only, escaped `pg\_` prefix, superusers kept in (see 1b). One consequence:
   **every default cluster FAILs 5.5**, because `postgres` is at -1. *Recommend as drafted.*
5. **7.4 rulings.** `always` is accepted, both-set is a FAIL, and a correct configuration gives MANUAL, so 7.4
   can never PASS automatically. *Recommend as drafted, with the tier kept `automated`, because the FAIL
   branch is mechanical and `interpretation` records the MANUAL branch.* The alternative is PASS on
   configuration with a "functional not verified" note.
6. **Per-database scope (4.5, 4.6, 4.7).** The collector reads one database. Other connectable
   non-template databases (from `databases`) are listed as "not covered", which blocks 4.5's PASS. *Recommend
   accepting this for now; a multi-database collector run is a separate item.*
7. **7.1 replication-in-use.** `pg_stat_replication` is not collected. *Recommend not adding it now;
   the hba `replication` rules, slots and primary_conninfo are enough for a MANUAL check.*
8. **`interpretation` schema key**: an optional top-level list of plain sentences, with no SQL, allowed on any
   tier. The main session may want the same key for its F2/F3 rulings (e.g. 3.1.14 "at least `warning`"),
   so it should be added once, in one place. *Recommend the main session owns the schema line and this
   branch reuses it.* spec-author notes that 5.5's entry quotes CIS's `NOT LIKE 'pg_%'` fragment for
   comparison. If "no SQL" is meant strictly, that entry needs rewording.
9. **4.6 group expansion.** `role_memberships` has no PG16+ `inherit_option`, so grants inherited through
   groups are shown as an upper bound. *Recommend the upper-bound label.* Adding the column would need a
   `try_jsonb` wrapper to keep older majors working.
10. **Collector proposal (§3)** for review by db-security-reviewer and approval by Melvin: two sections,
    `functions` and `archiving`; `proconfig` reduced to names plus `search_path`; `extension` taken from
    `pg_depend`. *Recommend approving as written.*
11. **Follow-up, out of scope here.** The existing `settings` section already ships `archive_command`
    **text** (masked, e.g. `cp %p rclone://tok:***REDACTED***@bucket/%f`). The new `archiving` section never
    does. *Recommend a separate follow-up deciding whether `settings` should stop shipping it.*

## 4b. Accepted requirement: plain-language reason on every row

Melvin, relayed by the main session: "while the assessment table displays the NOT APPLICABLE BADGE or
UNKNOWN badge, could it also state the reason? i.e. list the CIS rule and explain why is it not applicable
or unknown. so that even, the most amateur DBA can understand what is going on."

Accepted. The catalog findings use the contract the main session sent from step 1 on
`melvin/wave1b-f2-f3-f4`. That work is uncommitted, so this branch matches its field names and does not
merge it:

- The engine results (`assess.py`) and the offline ASSESS `Finding` (`models.py`) carry
  `cis: {recommendation, title}` and `explanation: {code, ...facts}`. These hold facts from the spec and the
  evidence only, never prose. `result`/`status` and `reason_code` are unchanged. The sandbox SpecEngine
  copies both fields unchanged into `assessment.findings[spec_id]`.
- `cis` comes from the spec's `ref`.

Catalog-check `explanation` codes, for the UI step to map to one sentence each:

| Code | Status | Facts | When |
| --- | --- | --- | --- |
| `section_not_collected` | GAPPED | `section`, `gap_reason?` | A section the evaluator reads is null, or has a matching `gaps` entry. Without one, `gap_reason` is absent and the collector contract was violated |
| `field_missing` | GAPPED | `section`, `field` | A row lacks a field the evaluator needs (e.g. `roles[].rolconnlimit`) |
| `wrong_pg_major` | GAPPED | `spec_pg_major`, `snapshot_pg_major` | Same code and keys as the main branch |
| `manual_review` | MANUAL | `evidence_count` | A human must decide; the evidence list is on the row |
| `databases_not_covered` | MANUAL | `evidence_count`, `databases` | 4.5/4.6/4.7: other connectable non-template databases are not in this snapshot |
| `empty_review_set` | PASS | `evidence_count: 0` | Only if Q2 is approved: 4.5/4.10 PASS because CIS leaves nothing to review |

FAIL rows (5.5, 7.4) keep their failing roles or settings in the evidence list and need no explanation
code, which matches how setting checks report FAIL. Catalog checks introduce no NOT_APPLICABLE case of
their own; `applies_when` belongs to the main branch.

## 5. Not done yet (after Gate 1)

Engine and wiring, evaluators, unit and live tests, applying the collector change and re-recording the
fixture, count pins, the UI evidence list, db-security-reviewer on the diff, and the Gate 2 report.

## 6. Gate 1 rulings (Melvin, relayed verbatim by the main session)

Recorded here because the 7.4 spec and `catalog_checks.py` point at this section.

- **B1–B4, B6–B9, B11** (catalog kind design, empty-review-set PASS for 4.5/4.10, 4.5 manual_checklist,
  5.5 scope, per-DB scope, 7.1, `interpretation` key, 4.6 upper-bound label, archive_command follow-up):
  approved as drafted: "yes encode as CIS recommends".
- **B5, 7.4: changed.** "Yes, auto PASS/FAIL (Recommended): PASS if configured and a copy succeeded recently
  (limit from the policy profile, default 24h) with no later failure; FAIL if off/unset/conflicting/latest copy
  failed; review only if unclear." And: "ideally, this app should help minimise human review but not to the
  extent of human negligence". The 24h default was approved; a profile override applies only once the
  profile is approved. This replaces the §1 table and Q5 rule (MANUAL when configured).
- **B10, collector proposal:** db-security-reviewer PASS WITH NOTES, then approved by Melvin in round 2
  (28 Oct: "Approve (Recommended)") and applied.
- **5.5:** flagged only this week; per-role fix proposals next week.
- **`interpretation`:** the main branch adds the schema line with the same name and shape; reconcile at rebase.
