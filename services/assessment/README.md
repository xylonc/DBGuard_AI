# Assessment foundation

This package defines the deterministic assessment contract for DBGuard's two
current SQL templates:

- `create_read_only_rule`
- `revoke_public_access`

`catalog/controls/hardening-controls.yaml` is the declarative source of truth.
`catalog_loader.py` validates the complete file before the registry becomes
available. Unknown fields, parameter models, verifier IDs, duplicate IDs,
missing template versions, and unapproved control sources fail closed.

It intentionally does not start Docker or expose a new API endpoint. The
restricted PostgreSQL executor connects only to the isolated twin connection
provided by a future twin controller.

## Trust boundary

HERMES may select an approved template and supply its permitted parameters.
It cannot supply verifier IDs, assessment SQL, expected results, or pass/fail
statuses. Those values are selected from the validated YAML catalogue and
cross-checked against closed allowlists in application code.
Assessment definitions are bound to an exact template name and version so a
new template version cannot silently reuse checks that were reviewed for older
SQL.

`PostgresAssessmentExecutor` implements `AssessmentExecutor.run_check`. It maps
each registered verifier ID to fixed SQL or a fixed behavioural test and
returns an observation plus immutable evidence references. It has no generic
SQL-execution method.

The `AssessmentExecutor` protocol in `service.py` is the common boundary, not a
second executor implementation. Production code supplies
`PostgresAssessmentExecutor`. The `FakeExecutor` declared inside
`tests/test_assessment_foundations.py` is a test-only substitute: it returns
pre-programmed results so report logic can be tested without Docker or a live
database. It is never part of the application runtime and should remain for
fast, deterministic unit tests.

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

## PostgreSQL executor and fixtures

`PostgresAssessmentFixtureManager` creates synthetic tables before and after a
trusted hardening plan is applied. For the read-only test it also assigns a
random password to the test role inside the disposable twin only. The password
is removed during cleanup and never appears in evidence.

`PostgresAssessmentExecutor` implements all 16 current verifier IDs:

- fixed catalogue queries for role flags, schema privileges and PUBLIC ACLs;
- a real authenticated connection as the requested role;
- positive SELECT tests against existing and future probe tables;
- rolled-back INSERT, UPDATE, DELETE, TRUNCATE and CREATE attempts;
- hashed query/command evidence stored through an `EvidenceSink` boundary.

An unknown verifier ID or parameter/context mismatch is rejected before any
database operation. Application code must never pass the RAG PostgreSQL DSN;
the executor is only for a dedicated disposable twin.

Integration tests are opt-in. Set `DBGUARD_TEST_POSTGRES_DSN` to a dedicated
test database and run:

```powershell
.\.venv\Scripts\python.exe -m unittest tests.test_postgres_assessment_executor -v
```

## Next implementation

Add a one-iteration twin controller that creates an isolated PostgreSQL
container, replays supported snapshot configuration, applies a trusted compiled
plan, invokes `PostgresAssessmentExecutor`, persists its evidence, and always
destroys the twin. The existing test-only executor must not be selectable in
this production flow.
