# Assessment foundation

This package defines the deterministic assessment contract for DBGuard's two
current SQL templates:

- `create_read_only_rule`
- `revoke_public_access`

`catalog/controls/hardening-controls.yaml` is the declarative source of truth.
`catalog_loader.py` validates the complete file before the registry becomes
available. Unknown fields, parameter models, verifier IDs, duplicate IDs,
missing template versions, and unapproved control sources fail closed.

It intentionally does not start Docker, connect to PostgreSQL, or expose a new
API endpoint. Those operations belong to the future restricted twin adapter.

## Trust boundary

HERMES may select an approved template and supply its permitted parameters.
It cannot supply verifier IDs, assessment SQL, expected results, or pass/fail
statuses. Those values are selected from the validated YAML catalogue and
cross-checked against closed allowlists in application code.
Assessment definitions are bound to an exact template name and version so a
new template version cannot silently reuse checks that were reviewed for older
SQL.

A future twin executor implements `AssessmentExecutor.run_check`. It maps each
registered verifier ID to fixed SQL or a fixed behavioural test and returns an
observation plus immutable evidence references.

An observed result without evidence is reported as `UNKNOWN`, never `PASS`.
Executor exceptions are reported as `ERROR`, not as compliance failures.
Baseline and DBA-requirement results are aggregated independently.

The global CIS/industry baseline is currently `NOT_READY` because there are no
approved entries in `baseline_profiles` and `baseline_controls`. Passing the
template-specific checks cannot produce an overall `PASS` until that complete
baseline is reviewed and activated. RAG document approval alone does not
authorize a source for executable control authoring.

## Deliberately exposed template gaps

The read-only template grants `SELECT` on tables that already exist. It does not
currently add an `ALTER DEFAULT PRIVILEGES` rule for future tables, so the
`role_can_select_future_probe_table` criterion is expected to expose that gap.
There is no approved remediation template for this gap yet; reconciliation must
stop for human review instead of inventing SQL.

If a role can create objects because of `PUBLIC` schema privileges, the
criterion points to the existing `revoke_public_access` template. Existing
direct or inherited write grants have no approved revocation template and also
require human review.

## Next implementation

Add a restricted PostgreSQL assessment executor for the verifier IDs in these
two definitions. It should create synthetic probe objects, execute positive and
negative operations as the target role, capture query/command output, hash the
evidence, and clean up the twin regardless of the result.
