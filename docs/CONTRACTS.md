# DBGuardAI Contract Documentation

This document describes the contracts enforced by the DBGuardAI codebase as of commit b32fd83.

## snapshot v0.3.0

### Enforced by: `collector/collect.sql:pg_temp.run_checks()` and `catalog/specs/contracts/snapshot-v0.3.0.json` (JSON Schema)

### Structure:

The snapshot contract is defined in `catalog/specs/contracts/snapshot-v0.3.0.json`.

- **Envelope (v0.3.0)**: Contains collector metadata:
  - `schema_version`: Must be `'0.3.0'`
  - `database`: Non-empty string
  - `target_id`: Non-empty string
  - Optional fields: `collected_at`, `collected_by`, `is_superuser`, `has_pg_monitor`, `deployment_type`, `collector_version`, `can_read_pg_authid`, `has_read_all_settings`

- **Baseline**: Contains all collector sections (roles, settings, hba_rules, etc.) as a free-form object.

- **Checks**: Assessment results keyed by `spec_id`. Each entry has:
  - `spec_hash`: SHA-256 hash of the spec (pattern: `^[0-9a-f]{64}$`)
  - `query`: Non-empty string
  - `status`: One of `"ok"`, `"error"`, `"not_collected"`
  - When `status == "ok"`: `result` field is required
  - When `status == "error"`: `error` field is required
  - When `status == "not_collected"`: `result` must not be present

### Safety rules:

1. **No EXECUTE of manifest text**: The `pg_temp.run_checks()` function never uses `EXECUTE` on any text derived from the manifest. It only reads known fields (`spec_id`, `kind`, `setting_name`, `query`) and uses them directly in controlled operations.

2. **Secret redaction**: The `pg_temp.sanitise_setting()` function never returns the text of a setting that can carry a secret. `pg_temp.is_secret_setting()` marks as secret: the seven built-in settings (`archive_command`, `restore_command`, `archive_cleanup_command`, `recovery_end_command`, `primary_conninfo`, `ssl_passphrase_command`, `krb_server_keyfile`); every dotted custom or extension setting except an exact list of 28 reviewed pgaudit, set_user, pg_stat_statements and plpgsql names; and any plain name the server does not recognise (e.g. a config-file typo). Names compare lower-cased under the C collation, and a missing name fails closed. For those settings `setting`, `reset_val`, `boot_val`, `file_settings`, `role_settings` entries and manifest check results read `***REDACTED*** (set, N characters)`; NULL, '' and `(disabled)` pass through. Connection strings are additionally parsed to an allowlist of safe keys (`*_conninfo_parsed`), and `rls_policies` expressions are redacted the same way.

3. **Catalog sections for F6 and 7.4**: `functions` lists functions with SECURITY DEFINER or a SET clause (schema, name, identity arguments, kind, language, `prosecdef`, owner, ACL with the default expanded, extension, the setting NAMES from `proconfig` and the `search_path` value only). `prosrc` is never selected. `archiving` holds `archive_mode`, `archive_library`, `archive_command_is_set` (a boolean: the command text is never shipped) and the `pg_stat_archiver` counters and times. Either section is `null` with a `gaps` entry when it could not be read; `[]` means collected and empty.
#
## check manifest v1

### Enforced by: `app/services/spec_engine/manifest.py:build_manifest()` and `catalog/specs/contracts/check-manifest-v1.json` (JSON Schema)

### Structure:

The check manifest is a plain JSON list of checks the collector must look up, derived from CIS control specs.

- **Envelope**: Contains metadata:
  - `manifest_version`: Must be `1`
  - `benchmark_id`: The benchmark identifier (e.g., `'cis-pg17-v1.1.0'`)

- **Checks**: Array of check entries, sorted by `spec_id`:
  - `spec_id`: The spec identifier that this check corresponds to, or `<spec_id>#applies_when` for the condition setting of a spec with `applies_when` (same `spec_hash` as the spec, `query` is `SHOW <condition setting>`)
  - `spec_hash`: SHA-256 hash of the spec file (pattern: `^[0-9a-f]{64}$`)
  - `kind`: One of `"setting"` (current only)
  - `setting_name`: PostgreSQL GUC parameter name (pattern: `^[a-z_][a-z0-9_.]*$`)
  - `query`: SQL query to execute (currently always `"SHOW <setting_name>"`)

### Constraints:
- Specs with a check are included: `tier: automated`, and `tier: parameterised` with `check.expected_from: policy`
- A spec with `applies_when` adds a second entry `<spec_id>#applies_when`, so the condition is collected and hash-pinned like any check (`#` never occurs in a spec_id)
- `kind` must be `"setting"` (the only supported kind)
- `setting_name` uses the same pattern as the spec schema
- No SQL is generated from spec text - only the query field from the spec is used
- Output is deterministic: same specs always produce byte-identical output (sorted by spec_id)

### Generation:
Run: `python scripts/build_check_manifest.py --specs <dir> --out <file>`
## Structure

The snapshot contract is defined in `catalog/specs/contracts/snapshot-v0.3.0.json`.

- **Envelope (v0.2.0)**: Contains collector metadata:
  - `schema_version`: Must be `'0.2.0'`
  - `database`: Non-empty string
  - `target_id`: Non-empty string
  - Optional fields: `collected_at`, `collected_by`, `is_superuser`, `has_pg_monitor`, `deployment_type`, `collector_version`, `can_read_pg_authid`, `has_read_all_settings`

- **Baseline**: Contains all collector sections (roles, settings, hba_rules, etc.) as a free-form object.

- **Checks**: Assessment results keyed by `spec_id`. Each entry has:
  - `spec_hash`: SHA-256 hash of the spec (pattern: `^[0-9a-f]{64}$`)
  - `query`: Non-empty string
  - `status`: One of `"ok"`, `"error"`, `"not_collected"`
  - When `status == "ok"`: `result` field is required
  - When `status == "error"`: `error` field is required
  - When `status == "not_collected"`: `result` must not be present

## spec schema

### Enforced by: `app/services/spec_engine/validate.py:validate_spec()`

### Rules:

1. **Top-level fields**: Required fields are `spec_id`, `schema_version`, `authored_by`, `ref`, `tier`, `reason`. Optional: `check`, `proof`, `applies_when` (tier rules below) and `interpretation` (any tier). No other keys are allowed.

1a. **interpretation** (optional, any tier, any schema_version): a non-empty list of unique plain sentences recording where DBGuard reads the CIS text more strictly, more narrowly or more widely (for example the 3.1.24 syslog-only limitation). Never SQL: each sentence is at most 600 characters, has no `;`, line break or code fence, and no upper-case SQL keyword (`SELECT INSERT UPDATE DELETE ALTER CREATE DROP GRANT REVOKE TRUNCATE COPY EXECUTE FROM WHERE LIKE UNION`). It is part of the spec hash, so changing it changes `spec_sha256`. It does not affect assessment.

2. **Schema version**: Integer `2` exactly when the spec uses `applies_when` or `check.expected_from`; otherwise `1`. Existing v1 specs are unchanged.

3. **Authored by**: Must be `"human"` or `"agent"`.

4. **Tier**: Must be one of `"automated"`, `"parameterised"`, `"manual_checklist"`, `"needs_capability"`.

5. **Ref object**: Required keys are `benchmark`, `benchmark_version`, `pg_major`, `recommendation`, `title`, `source_sha256`. All must be strings except `pg_major` which must be integer.

6. **Traceability to records.json**:
   - `spec_id` prefix must match `RecordsIndex.benchmark_id` (from records.json directory)
   - `ref.benchmark` must match `records.benchmark`
   - `ref.benchmark_version` must match `records.benchmark_version`
   - `ref.recommendation` must exist in records

7. **Reason and tier-dependent keys**:
   - `tier == "automated"`: `reason` must be `null`, `check` (with a literal `expected`) and `proof` are required
   - `tier == "parameterised"`: `reason` must be a non-empty string; `check` is optional and, if present, uses `expected_from: policy` (no `expected`); `proof` is forbidden (break/fix come from the policy profile)
   - `manual_checklist`, `needs_capability`: `reason` must be a non-empty string; `check`, `proof` and `applies_when` are forbidden, except that `manual_checklist` may carry a catalog check (7a)

7a. **Catalog check** (`check.kind: catalog`, F6 and 7.4): exactly `{kind, evaluator, pass_condition_quote}`. `evaluator` names a fixed entry in `backend/app/services/spec_engine/catalog_checks.py` `REGISTRY`, bound to one recommendation and the tiers it allows (`automated` or `manual_checklist`); `pass_condition_quote` is verbatim audit text and the evaluator's `quote_tokens` must be whole tokens in it. A catalog spec never has `proof`, `applies_when`, `setting_name`, `query` or `expected_from`, is never in the check manifest, and is never fixed.

8. **Check object** (automated tier, or parameterised with a policy value):
   - Required keys: `kind`, `setting_name`, `query`, `operator`, `pass_condition_quote`, and exactly one of `expected` (automated) or `expected_from: policy` (parameterised)
   - `kind` must be `"setting"` (or `"catalog"`, rule 7a)
   - `setting_name` must match pattern `^[a-z_][a-z0-9_.]*$`
   - `query` must be `"SHOW " + setting_name`
   - `operator` must be a key of `OPERATORS` in `backend/app/services/spec_engine/operators.py` (table below); `direction` is required with `severity` and forbidden otherwise
   - `expected` shape depends on the operator (table below)
   - `pass_condition_quote` must be a whitespace-normalised substring of the record's audit_procedure, and every literal expected value must be a whole token in it (waived for `expected_from: policy`, whose values are in the profile)

   | operator | expected | PASS when | cannot interpret (ERROR, never PASS) |
   |---|---|---|---|
   | `equals` | string | SHOW value is exactly expected | non-string value |
   | `not_equals` | string | SHOW value is not exactly expected | non-string value |
   | `in` | list of strings | SHOW value is exactly one of them | non-string value |
   | `not_in` | list of strings | SHOW value is exactly none of them (no list splitting) | non-string value |
   | `contains_items` | list of `^[a-z0-9_]+$` | every item is among the comma-separated SHOW items, compared trimmed, unquoted and lower-cased (PostgreSQL's own reading of `log_destination`) | an item that is not a bare or double-quoted name, an empty item |
   | `contains_escapes` | list of PG17 `log_line_prefix` escapes (`%a %u %d %r %h %L %b %p %P %t %m %n %i %e %c %l %s %v %x %Q`) | every escape is used before any `%q`; `%%` is a literal, `%-10u` counts as `%u` (scanner mirrors PG17 `elog.c`) | non-string value |
   | `severity` | one level of the setting's scale; needs `direction: at_or_more_verbose \| at_or_less_verbose` | level is the expected one or earlier (more verbose) / later (less verbose) on the fixed scale | a level outside the scale, a setting without a reviewed scale |
   | `no_item_in` | list of elements (`*` or `^[A-Za-z0-9.:%_-]+$`); only on a setting with a reviewed list grammar (`listen_addresses`) | NO element of the SHOW list is one of expected. Split like PG17 `SplitGUCList`: comma separated, whitespace around elements trimmed, double quotes removed (`""` is a literal quote), no case folding; `''` is the empty list (PASS for 5.2) | unclosed quote, empty element (`a,,b`, trailing comma), two names without a comma, an element that is not `*`/host/address; for `listen_addresses`, an element made only of `[0-9a-fA-FxX.]` that is not a strict IPv4/IPv6 literal (`0`, `0x0`, `0.0x0`, `0.0.0.00`: glibc reads these as 0.0.0.0), unless an expected element already makes it FAIL |

   Severity scale for `log_min_messages` and `log_min_error_statement` (PG17 docs, runtime-config-logging, "When to Log"; checked against `pg_settings.enumvals` on PostgreSQL 17.11): `debug5 < debug4 < debug3 < debug2 < debug1 < info < notice < warning < error < log < fatal < panic` (most to least verbose). Which direction a CIS "at least" means is a human ruling recorded in each spec.

8a. **applies_when** (schema_version 2): `{setting_name, operator, expected, condition_quote}` plus `direction` for `severity`.
   - `setting_name` follows the setting pattern, differs from `check.setting_name`, and is not a collector-masked setting (`archive_command`, `restore_command`, `archive_cleanup_command`, `recovery_end_command`, `primary_conninfo`, `ssl_passphrase_command`, `krb_server_keyfile`)
   - `operator` and `expected` follow the same rules as the check
   - `condition_quote` must be a whitespace-normalised substring of the record's audit_procedure, description or rationale (no whole-token rule: CIS states conditions in prose, e.g. "When logging to Syslog")
   - only allowed on a spec with a check

9. **Proof object**:
   - Contains `break` and `fix` phases
   - Each phase's `setting_name` must match `check.setting_name`
   - `value` must be a string
   - For `break` phase: value must NOT satisfy the check (control must be breakable)
   - For `fix` phase: value MUST satisfy the check (control must be fixable)

### Unsupported controls downgrade:

Controls marked as `needs_capability` or `manual_checklist`, and `parameterised` controls without a policy check, do NOT have a `check` block. They are assessed through manual review, not automated checks.

## policy profile

### Enforced by: `backend/app/services/spec_engine/policy.py`

`catalog/policies/<benchmark_id>/reference.yaml` holds organisation-chosen values for parameterised specs:

```yaml
profile_id: cis-pg17-v1.1.0-reference
benchmark: cis-pg17-v1.1.0        # must equal the records directory name
approved_by: null                 # null, or a named human; only a human sets it
approved_at: null                 # set together with approved_by
values:
  cis-pg17-v1.1.0:3.1.2: {expected: [stderr, csvlog], fix: "stderr,csvlog", break: "stderr"}
```

- Loaded with duplicate-key rejection; unknown keys refused; pinned by the SHA-256 of the file bytes.
- `approved_by` must be `null` or a human name under the same rule as a UI approval (1-120 characters, letters, no control characters, no automated identity words); this applies to every profile read, the repository seed included. `approved_at` is null exactly when `approved_by` is null.
- Approvals are a typed name without sign-in. Every output that carries `approved_by` also carries `approval_auth: "DEMO_NO_SIGN_IN"` (the profile pin, profile summaries and displayed profile documents), and the human-readable files (bundle `report.html` and `README.txt`, batch `README.txt` and `report.html`) print `DEMO approval: no sign-in` next to the profile pin.
- Every value must belong to a spec with `expected_from: policy`, have the operator's expected shape, and its `fix` must pass and `break` must fail the operator (like a proof). `validate_specs.py` checks the installed profile against the whole catalog directory.
- Optional `fixes: {spec_id: value}`: a site-specific sandbox fix value for an **automated** spec whose expected value comes from CIS (5.2 listen_addresses: the DBA's real address). The value must satisfy the spec operator; a policy spec may not appear here (its fix is `values[spec].fix`). Without an approved profile carrying the value there is no fix: `planning.fix_scope` raises `site-specific fix value not supplied in an approved policy profile` and the fix plan lists the FAIL under `manual_review` with `manual_fix` (CIS recommendation, title and remediation procedure).
- Optional `connection_limits: {default_login_limit: int >= 0 | null, roles: {rolename: int >= 0}}`. Role names: letters, digits and `_`, at most 63, not starting with `pg_`. Stored and loaded only (used by F6 fix proposals later).
- Every `fix`/`break` value and every `fixes` value must also pass the reviewed per-setting value rule (`backend/app/services/setting_values.py`) because it may be rendered into SQL.
- Assessment: no profile, `approved_by: null`, or no value for the spec gives `MANUAL` / `policy_missing`, never PASS.

### Active profile per assessment

The user chooses the profile for each assessment by its hash: `policy_profile=<sha256>` on `GET /api/v1/snapshots/{id}/spec-assessment` and `/fix-plan`, and `policy_profile` in `POST /api/v1/sandbox/handoffs`. Default: none (every policy control is `policy_missing`, no site-specific fix). The handoff carries only `policy_profile_sha256`; `SandboxService.validate_handoff` resolves it server-side from the profile store. The report pins `inputs.policy_profile` (`{profile_id, sha256, approved_by, approved_at, approval_auth}`) when a spec uses policy or when an approved profile supplies a site-specific fix (`fixes`) for a spec in the set; sandbox runs, batches, bundles (`fix.json`), spec-assessment and fix-plan responses, and `fix_value_source.profile` in risk reviews record `policy_profile` (the same pin or null). A batch must use one profile, and a target reassessment uses the run's recorded profile. HERMES/MCP tools never pass a profile.

### Profile store (`backend/app/services/policy_profile_store.py`)

Content-addressed files under `settings.policy_profile_storage_dir/<benchmark_id>/` (`<sha256>.yaml` plus an append-only `log.jsonl`); the repository `reference.yaml` is a read-only seed that is listed and loadable but never written.

| Call | Effect |
|---|---|
| `list()` | summaries `{profile_ref, profile_id, benchmark, source: seed\|store, status: draft\|approved, approved_by, approved_at, approval_auth, value_count, fix_count, has_connection_limits}` |
| `get(profile_ref)` | the profile with that exact hash; a store object's bytes must hash to its name, and an approved store object needs its matching approval log entry (a dropped-in "approved" file is refused) |
| `create_draft(profile_id, values, fixes=None, connection_limits=None, based_on=None)` | validates against the catalog (strict) and stores a draft with `approved_by: null`; there is no approver argument |
| `approve(profile_ref, approver_name)` | named human only (1-120 characters, letters, no control characters, no automated identity words such as hermes/agent/model/llm/bot); writes the approved copy as a NEW object (new hash) and logs `{draft_sha256, sha256, approved_by, approved_at}`. Approving an approved profile is refused; an edit is a new draft |

HTTP (UI only, not on the MCP surface): `GET /api/v1/benchmarks/{benchmark_id}/policy-profiles`, `GET .../policy-profiles/{profile_ref}`, `POST .../policy-profiles` (draft), `POST .../policy-profiles/validate` (read-only check), `POST .../policy-profiles/{profile_ref}/approve` (`{approver_name}`). The POST routes refuse a body over 64 KB with 413 before parsing it, and more than 100 `values` or `fixes` entries or 500 `connection_limits.roles` entries with 422.

## fix-unit v1

### Enforced by: `catalog/specs/contracts/fix-unit-v1.json` (JSON Schema) and `app/services/fix_unit_validator.py:validate_fix_unit()`

### Typed actions:

The `apply` and `rollback` fields use typed actions:

- `{"action": "set_config", "param": <string>, "value": <string>}` - Set a configuration parameter
- `{"action": "reset_config", "param": <string>}` - Reset a configuration parameter

### derive_rollback table

Defined in `app/services/fix_unit_render.py:derive_rollback()`:

| apply action | prior from postgresql.auto.conf | prior from other/sourcefile=null | result |
|--------------|---------------------------------|----------------------------------|--------|
| set_config   | set_config(param, prior.value)  | reset_config(param)              | Correct rollback |
| reset_config | set_config(param, prior.value)  | **raises ValueError**            | No valid rollback |

### validator cross-field rules

**File:** `app/services/fix_unit_validator.py:validate_fix_unit()`

1. **precheck.expected_value must equal prior_state.value** (compare-and-swap safety)

2. **rollback must match derive_rollback(prior_state, apply)**:
   - `rollback.action` must match the computed rollback action
   - `rollback.param` must match `apply.param`
   - For `set_config` rollback: `rollback.value` must equal `prior_state.value`

3. **No-op rules**:
   - `set_config` with `apply.value == prior_state.value` is rejected (no-op)
   - `reset_config` on non-auto.conf is rejected (no-op)

### render_action

**File:** `app/services/fix_unit_render.py:render_action()`

- Returns `list[str]` with exactly 2 elements
- For `set_config`: `["ALTER SYSTEM SET <param> = '<value>'", "SELECT pg_reload_conf()"]`
- For `reset_config`: `["ALTER SYSTEM RESET <param>", "SELECT pg_reload_conf()"]`
- Each statement has NO trailing semicolon
- Statements must be executed separately (see Known gaps)

### render_action_script

**File:** `app/services/fix_unit_render.py:render_action_script()`

- Joins statements from `render_action()` with `";\n"`
- Adds final `";"`
- Used for file/report output

## template registry

### Enforced by: `app/services/vector_service.py`

### Immutable versions:

**File:** `app/services/vector_service.py:ingest_template()`

- Templates are stored in PostgreSQL with `sql_template` and `template_hash`
- **No UPDATEs are allowed** - content cannot be changed after storage
- If `template_hash` matches an existing template, no new row is created (no-op)
- If content differs, a new version is INSERTed with `version = max + 1` and `status = 'draft'`

### One active version per name:

**File:** `app/services/vector_service.py:approve_template()`

- Approval sets `status = 'active'` and archives previous versions
- Only one version can be active (`status = 'active'`) per `template_name`
- Previously approved versions are archived (`status = 'archived'`)

### literal/ident escaping:

**File:** `app/services/template_service.py`

- `ident` filter (via `quote_identifier`): Quotes identifier with double quotes, doubles any internal double quotes
- `literal` filter: Doubles single quotes for SQL string literals
- Both filters reject NUL characters

### SET_CONFIG fix values (`app/services/setting_values.py`)

One reviewed table checks every fix value before it is rendered (`SetConfigTemplateParams`), when the rendered statement is parsed back (`workflow.template_action`), and in policy profiles. Every value is non-empty and must not contain `'`, `"`, `\`, `;`, CR/LF, NUL, `--`, `/*` or `$`. Then, per setting (whole-value match):

| setting | allowed |
|---|---|
| `log_line_prefix` | letters, digits, `%`, space, `[]:=,-@.` |
| `log_filename` | letters, digits, `%`, `-`, `_`, `.` |
| `log_directory` | absolute or relative path of `[A-Za-z0-9_.-]` segments separated by `/`; no `..` segment |
| `listen_addresses` | strict IPv4 (four decimal parts, no leading zeros) / IPv6 addresses and host names whose labels start with a letter (incl. `localhost`, which must be listed) separated by `,` and spaces; never `*`, `0.0.0.0` or `::`, and never a non-standard numeric form such as `0`, `0x0`, `0.0x0` or `0.0.0.00` |
| `log_timezone` | tz names: letters, digits, `/`, `_`, `+`, `-` (e.g. `Etc/UTC`, `America/New_York`) |
| `log_destination` | lower-case names separated by `,` and spaces |
| `log_file_mode` | `0` plus three octal digits |
| `log_rotation_age` | digits plus optional `us ms s min h d` |
| `log_rotation_size` | digits plus optional `B kB MB GB TB` |
| `syslog_ident` | 1-63 of letters, digits, `_`, `.`, `-` |

Settings without an entry keep their previous rule: `[a-zA-Z0-9_.]+` in the sandbox loop, the historical boolean/number/no-`';--/*` rule (plus the global list) in `SetConfigTemplateParams`. The template quotes with `'...'` and the `literal` filter; PostgreSQL 17 runs with `standard_conforming_strings = on`, so `%`, `[`, `/` and spaces need no escaping.

## Known gaps

### 1. requires field unused

The `requires` field exists in the fix-unit schema (`catalog/specs/contracts/fix-unit-v1.json`) and all test fixtures specify `"requires": "reload"`.

**No code reads this field.** A grep search found no reader in `backend/app/services/`.

### 2. params vs apply duplication

The fix-unit contract has both `params` (with `param_name`, `param_value`) and `apply` (with `action`, `param`, `value`) fields. Both appear to define the same target parameter and value. It is unclear which is the source of truth.

### 3. Single query with semicolons fails

The rendered SQL `"ALTER SYSTEM ...; SELECT pg_reload_conf();"` sent as ONE query fails with `SQLSTATE 25001` (implicit transaction block). PostgreSQL requires these statements be executed separately.

**This is why `render_action` returns a list** - each element must be executed as a separate statement via `conn.cursor().execute(stmt)`.

### 4. tests/live/* not independently verified

The live tests in `tests/live/` (commit b32fd83) passed in the agent environment but have not been:
- Reviewed by Xylon
- Independently run on a separate environment
- Verified for `derive_rollback` mutation checks

### 5. Two quote_identifier implementations

Both Python and Jinja template define `quote_identifier`:

- `app/services/template_service.py:quote_identifier()` (line 27)
- `app/services/fix_unit_render.py:_quote_identifier()` (line 20)

They are kept in agreement only by the template parity test `tests/test_contract_schemas.py:test_render_action_matches_template`. There is no automated check ensuring they remain identical.

## assessment report v1

### Enforced by: `backend/app/services/spec_engine/assess.py:assess()`

### Structure:

The assessment report is the output of the `assess()` function. It contains:

- **report_version**: Integer 1 (current schema version)
- **target**: Target database metadata (`target_id`, `database`, `server_version`, `server_major`)
- **inputs**: Collector and manifest provenance (`collector_sha256`, `manifest_sha256`, `benchmark_id`, `specs`)
- **flags**: Assessment metadata (`version_mismatch`, `check_count`, `orphan_checks`, `integrity_ok`)
- **summary**: Counts for each result type (PASS, FAIL, MANUAL, NEEDS_CAPABILITY, NOT_APPLICABLE, NOT_COLLECTED, STALE, ERROR)
- **inputs.policy_profile**: when a spec uses `expected_from: policy`, or an approved profile supplies a site-specific fix for a spec in the set: `{profile_id, sha256, approved_by, approved_at, approval_auth: "DEMO_NO_SIGN_IN"}`, or `null` when no profile was supplied
- **results**: Array of result rows for each spec

### Decision order:

A catalog check (`check.kind: catalog`) is decided by its evaluator (`catalog_checks.evaluate`) instead of the order below: PASS, FAIL or MANUAL on complete evidence, otherwise NOT_COLLECTED. A `null` section, a matching `gaps` entry, a roles list without the bootstrap superuser or a databases list without the connected database is never PASS. `reason_code` is the explanation code (table below).

For every other spec, the result is determined in this order (returns at first match; `assess._decide`):

1. **MANUAL** `tier_manual`: tier `manual_checklist`, or `parameterised` without a policy check
2. **NEEDS_CAPABILITY** `tier_needs_capability`: tier `needs_capability`
3. **MANUAL** `policy_missing`: policy check without an approved profile value
4. Main entry: **NOT_COLLECTED** `no_entry`; **STALE** `hash_mismatch`; **NOT_COLLECTED** `status_not_collected`; **ERROR** `status_error`; **ERROR** `non_string_result`; **NOT_COLLECTED** `redacted_secret_setting` when the result is the collector's redaction marker (starts with `***REDACTED***`; `spec_engine/redaction.py`). No operator is ever evaluated on the marker.
   - **NOT_COLLECTED** `session_override`: the checked setting's `baseline.settings` row has a source that is not server-wide (anything but `default`, `environment variable`, `configuration file`, `command line`, `override`; e.g. `user`, `database`, `database user`, `global`, `client`, `session`). The collector's session value may not be the server's (`spec_engine/sources.py`). A missing settings section, row or `source` key keeps the other rules.
5. `applies_when` only, condition entry: the same six checks with codes `condition_no_entry`, `condition_hash_mismatch`, `condition_status_not_collected`, `condition_status_error`, `condition_non_string_result`, `condition_redacted_secret_setting`, then **NOT_COLLECTED** `condition_session_override` for an overridden condition setting
6. `applies_when` only: **ERROR** `condition_operator_error` if the condition value cannot be interpreted; **NOT_APPLICABLE** `condition_false` if the condition is false
7. **ERROR** `operator_error`: the operator cannot interpret the value (e.g. an unknown severity level)
8. **PASS** `operator_true` / **FAIL** `operator_false`

All evidence problems are decided before the condition, so NOT_APPLICABLE is only given on clean, current evidence for both settings. The sandbox projection (`services/sandbox_poc/shared.py`) maps PASS, FAIL, MANUAL/NEEDS_CAPABILITY (MANUAL_REVIEW) and NOT_APPLICABLE explicitly; everything else is GAPPED. The fix plan lists NOT_APPLICABLE controls under `not_applicable`, neither as fixes nor as manual review.

### Result codes:

| Result | Reason code | Description |
|--------|-------------|-------------|
| PASS | `operator_true` | Operator evaluated to true |
| FAIL | `operator_false` | Operator evaluated to false |
| MANUAL | `tier_manual` | Tier is `manual_checklist`, or `parameterised` without a policy check |
| MANUAL | `policy_missing` | Policy check without an approved profile value |
| NEEDS_CAPABILITY | `tier_needs_capability` | Tier is `needs_capability` |
| NOT_APPLICABLE | `condition_false` | `applies_when` is false on clean evidence |
| NOT_COLLECTED | `no_entry` / `condition_no_entry` | No entry in snapshot for the spec / its condition |
| NOT_COLLECTED | `status_not_collected` / `condition_status_not_collected` | Entry status is `not_collected` |
| NOT_COLLECTED | `session_override` / `condition_session_override` | The setting's value is set per role, database or session, not server-wide |
| NOT_COLLECTED | `redacted_secret_setting` / `condition_redacted_secret_setting` | The collector redacted the value because it can carry a secret |
| STALE | `hash_mismatch` / `condition_hash_mismatch` | Spec hash doesn't match collected hash |
| ERROR | `status_error` / `condition_status_error` | Entry status is `error` |
| ERROR | `non_string_result` / `condition_non_string_result` | Entry status is `ok` but result is not a string |
| ERROR | `operator_error` / `condition_operator_error` | The operator cannot interpret the value |
| PASS / FAIL / MANUAL / NOT_COLLECTED | catalog codes (`empty_review_set`, `connection_limits_set`, `unlimited_connections`, `manual_review`, `databases_not_covered`, `archive_*`, `section_not_collected`, `field_missing`, `wrong_pg_major`) | Catalog checks: the evaluator's explanation code |

### Output shape:

Each result row contains:

| Field | Type | Description |
|-------|------|-------------|
| spec_id | string | Spec identifier |
| title | string | Spec title |
| tier | string | Spec tier |
| result | string | Assessment result |
| reason_code | string | Short code explaining result |
| setting_name | string | PostgreSQL setting (specs with a check, entry collected) |
| operator | string | Check operator |
| direction | string | `severity` only |
| expected | string/array | Expected value(s); for policy specs only when an approved value exists |
| expected_from | string | `policy` for policy specs |
| spec_hash | string | Computed spec hash |
| collected_spec_hash | string/null | Hash from snapshot |
| observed | string | Observed result when status is ok |
| condition | object | `applies_when` specs: `{setting_name, operator, expected, direction?, observed?}` |
| cis | object | With `explanation`: `{recommendation, title}` from the spec ref |
| explanation | object | NOT_APPLICABLE, NOT_COLLECTED, STALE, ERROR and MANUAL `policy_missing` rows, and every catalog row: structured facts, never prose |
| evidence | array | Catalog rows: the rows the evaluator read, as names and attributes (never hashes, function bodies, policy expressions or archive_command text) |
| evidence_paths | array | Catalog rows: baseline paths the evaluator read |
| notices | array | Catalog rows: fixed, reviewed notices shown whatever the result; 7.4 always carries `restore_test_reminder` |

### Explanations (`explanation`)

Facts only, from the spec, the policy profile and the collected evidence; the UI writes the sentence. `evidence` is `check` (the control's own setting) or `condition` (the `applies_when` setting).

| code | when | facts |
|---|---|---|
| `condition_false` | NOT_APPLICABLE | `setting_name, operator, expected, direction?, condition_quote` (verbatim CIS), `actual` |
| `condition_unknown` | condition evidence problem | `cause` (one of the evidence codes below), `evidence: condition`, the condition facts above, plus the cause's facts |
| `not_collected` | no entry / `not_collected` | `evidence, setting_name, entry_status: missing \| not_collected` |
| `stale_spec_hash` | STALE | `evidence, setting_name, spec_hash, collected_spec_hash` |
| `collector_error` | entry status `error` | `evidence, setting_name, error` (collector text) |
| `unit_or_non_text_value` | result is not a string | `evidence, setting_name` |
| `uninterpretable_value` | operator cannot read the value | `evidence, setting_name, operator, direction?, actual` |
| `session_override` | value set per role, database or session | `evidence, setting_name, source` (`pg_settings.source`) |
| `redacted_secret_setting` | the collector redacted the value (it can carry a secret) | `evidence, setting_name` |
| `policy_missing` | MANUAL `policy_missing` | `case: no_profile \| profile_unapproved \| no_value_for_spec`, `profile_id` when a profile exists |
| catalog codes | every catalog row | the code plus facts such as `section`, `gap_reason`, `field`, `evidence_count`, `databases`, `role_count`, `archive_mode`, archiver counters and times, `collected_at`, `max_age_hours` (`assessment-report-v1.json` lists them all) |

The sandbox projection copies `cis` and `explanation` unchanged into `findings[spec_id]`, except for catalog rows: while `SANDBOX_COMPARES_CATALOG` is `False` (`services/sandbox_poc/shared.py`, Melvin's Gate 2 ruling) catalog specs are left out of `findings` entirely, and gap records for the `functions` and `archiving` sections do not block a sandbox run. Their facts never enter `findings`, because role counts and archiver times differ between source and sandbox. The offline ASSESS controls (`catalog/controls/assess/spec_controls.py`) put the same shapes on `Finding.cis` / `Finding.explanation` and add three codes that only arise from `pg_settings` rows: `sanitised` (`setting_name`), `wrong_pg_major` (`spec_pg_major, snapshot_pg_major`), and `unit_or_non_text_value` with `unit, vartype`; a missing settings section is `not_collected` with `entry_status: section_unavailable` and the collector `gap_reason`. Both read `session_override` from the same rule (`spec_engine/sources.py`) and give GAPPED, never PASS or FAIL. No spec may check, or use as `applies_when`, a setting the collector sets in its own session (`search_path`, `standard_conforming_strings`; `validate_spec`), or a setting the collector redacts: the seven secret-bearing built-ins and every dotted name not on the reviewed list (`spec_engine/redaction.py`, pinned to `pg_temp.is_secret_setting` by a test). A redacted value that still reaches either path is `redacted_secret_setting`, GAPPED.

### Determinism:

The same inputs always produce byte-identical output (sorted keys, no timestamps).
