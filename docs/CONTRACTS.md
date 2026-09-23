# DBGuardAI Contract Documentation

This document describes the contracts enforced by the DBGuardAI codebase as of commit b32fd83.

## snapshot v0.3.0

### Structure

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

1. **Top-level fields**: Required fields are `spec_id`, `schema_version`, `authored_by`, `ref`, `tier`, `reason`. Only these keys are allowed.

2. **Schema version**: Must be integer `1`.

3. **Authored by**: Must be `"human"` or `"agent"`.

4. **Tier**: Must be one of `"automated"`, `"parameterised"`, `"manual_checklist"`, `"needs_capability"`.

5. **Ref object**: Required keys are `benchmark`, `benchmark_version`, `pg_major`, `recommendation`, `title`, `source_sha256`. All must be strings except `pg_major` which must be integer.

6. **Traceability to records.json**:
   - `spec_id` prefix must match `RecordsIndex.benchmark_id` (from records.json directory)
   - `ref.benchmark` must match `records.benchmark`
   - `ref.benchmark_version` must match `records.benchmark_version`
   - `ref.recommendation` must exist in records

7. **Reason and tier-dependent keys**:
   - `tier == "automated"`: `reason` must be `null`, `check` and `proof` are required
   - `tier != "automated"`: `reason` must be non-empty string, `check` and `proof` are forbidden

8. **Check object** (for automated tier):
   - Required keys: `kind`, `setting_name`, `query`, `operator`, `expected`, `pass_condition_quote`
   - `kind` must be `"setting"` (current only)
   - `setting_name` must match pattern `^[a-z_][a-z0-9_.]*$`
   - `query` must be `"SHOW " + setting_name`
   - `operator` must be one of `equals`, `not_equals`, `in`
   - `expected` format depends on operator
   - `pass_condition_quote` must contain the expected value as a whole token in the audit_procedure

9. **Proof object**:
   - Contains `break` and `fix` phases
   - Each phase's `setting_name` must match `check.setting_name`
   - `value` must be a string
   - For `break` phase: value must NOT satisfy the check (control must be breakable)
   - For `fix` phase: value MUST satisfy the check (control must be fixable)

### Unsupported controls downgrade:

Controls marked as `needs_capability`, `manual_checklist`, or `parameterised` tier do NOT have a `check` block. They are assessed through manual review, not automated checks.

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

- Approval sets `status = 'approved'` and archives previous versions
- Only one version can be active (`status = 'approved'`) per `template_name`
- Previously approved versions are archived (`status = 'archived'`)

### literal/ident escaping:

**File:** `app/services/template_service.py`

- `ident` filter (via `quote_identifier`): Quotes identifier with double quotes, doubles any internal double quotes
- `literal` filter: Doubles single quotes for SQL string literals
- Both filters reject NUL characters

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
