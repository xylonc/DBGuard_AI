# Existing collector → sandbox → DBA review bundle

## Repository review (22 September 2026)

Checked GitHub branches and PR status, not only README claims:

- `origin/main` remains `c70a465`; snapshot intake is `CollectorBundleV020`.
- Xylon's `feature/phase0-contracts` now reaches `5b43910`, adding fix-unit
  cross-field validation and rollback tests. Integrated locally. The merged
  schema retains Melvin's PostgreSQL context enum corrections.
- `feature/recon-loop-implementation` ends at `3221b5a` (8 September) and uses
  an older assessment catalog. `feature/assess-contract-vertical-slice` ends
  at `31bbd78` (15 September). Neither is a newer spec-handoff implementation.
- `collector/dbguard-collect.sh` runs `collector/collect.sql` and writes v0.2 JSON.
  There is no file literally named `collect.sh` on current main.
- `scripts/capture_assess_fixtures.sh` populates disposable PostgreSQL 16 targets
  and collects insecure/hardened/low-privilege examples. Existing examples are
  incompatible with this PostgreSQL 17 milestone.
- `scripts/ingest_templates.py` populates pgvector's template registry;
  `db/init.sql` creates its tables. They do not create genuine human approvals.
- `SnapshotStore` stores uploaded snapshots as local JSON files, not registry rows.
- Legacy `services/reporting/reporting.py` uses a different report model. This
  milestone adds a small renderer tied directly to verified sandbox evidence.

## Reuse Xylon's existing collection script

### Export an existing approved reference

The latest remote branches were fetched again on 22 September: main remains
`c70a465`, and Xylon's phase-zero branch remains `5b43910`, already merged into
the local edit branch. There is no newer upstream handoff on those branches.
The PG16 seeded snapshots are useful collection examples, not valid PG17
sandbox input. Do not relabel their server version to make them pass.

Given a team-reviewed template version and evidence document ID, export their
exact existing registry hashes through a SELECT-only connection:

```sh
python scripts/export_sandbox_template_ref.py \
  --template-version 1 --evidence-id YOUR_REVIEWED_DOCUMENT_ID \
  --environment dev --registry-env DATABASE_URL \
  --output approved-template-ref.json
```

Use the actual reviewed version/ID; repeat `--evidence-id` for multiple sources.
This command never creates approvals, never selects an implicit latest version,
and rejects missing, inactive, expired, incompatible, blank or demo/test approvals.
It checks the rendered SQL against the supported connection-logging fix. Content
is re-read by exact pins before export and again at sandbox execution. The
reference contains identities only, without database credentials.

Run the existing collector near the PostgreSQL 17 target with normal libpq
connection settings. Collection is read-only; no fix is executed on that target.

```sh
bash collector/dbguard-collect.sh -t reviewed-target -o source.json
python scripts/build_sandbox_handoff.py \
  --collector-bundle source.json \
  --spec-dir catalog/specs/cis-pg17-v1.1.0 \
  --records catalog/benchmarks/cis-pg17-v1.1.0/records.json \
  --template-ref approved-template-ref.json \
  --output handoff.json
```

The bridge projects unitless boolean/enum settings from the collector's
`pg_settings` evidence into exact spec checks. It records the input hash and
this evidence origin; it does **not** claim to have executed extra SHOW queries.
It rejects missing/duplicate/redacted settings, units, gaps, unsupported sources,
pending restart, and a PostgreSQL major other than 17. Other check kinds must use
spec-driven collection instead. All exact specs and benchmark evidence remain
validated by the shared spec engine. No collector code is replaced.

`--snapshot` continues to accept a native v0.3 spec snapshot. The output handoff
file must not already exist. The approved-reference structure is documented in
API.md; it must identify the exact registry template and document versions/hashes.
Do not invent approval records or label test fixtures as team approval.

## Validate and review

```sh
python scripts/review_handoff.py --handoff handoff.json --check-only
```

Check-only does not access a registry or Docker and is not execution/approval
proof. For an actual run, configure DATABASE_URL for the approved registry
(prefer a SELECT-only account), install `requirements-sandbox.txt`, and enable
the local runner:

```sh
export SANDBOX_POC_ENABLED=true
python scripts/review_handoff.py --handoff handoff.json --port 8011
```

Open http://127.0.0.1:8011. The UI reads the supplied handoff and uses the same
`POST /api/v1/sandbox/runs` endpoint. It never connects to the source database.
There is no automatic approval, source mutation or production apply action.
The real-target recollection button stays disabled in this mode.

For a one-shot local run and ZIP export:

```sh
python scripts/review_handoff.py --handoff handoff.json --output review.zip
```

The source must still fail connection logging. The loop reconstructs the source
in new disposable containers; regression, health, rollback and cleanup gates
must all pass. Approved registry content is checked at execution time.

### Check a team handoff before allocating a sandbox

The builder optionally accepts `--assessment upstream-assessment.json`. When
provided, this must match the shared assessment of the exact normalized snapshot
and spec set; stale results or a legacy assessment shape are rejected, not silently
replaced. When omitted, the shared spec engine computes the assessment as before.
For collector v0.2 input, the matching assessment must refer to the bridge's v0.3
snapshot, including its source-bundle hash. This bridge is not a claim that
Xylon's legacy assessment API already emits the new handoff format.

```sh
python scripts/review_handoff.py --handoff handoff.json \
  --check-registry --readiness-output readiness.json
```

Both check modes print structured JSON and optionally save a new report file:

- `--check-only`: `INPUT_VALID` means contract/provenance checks passed; registry
  approval remains `NOT_CHECKED`.
- `--check-registry`: `READY_FOR_SANDBOX` means the exact currently applicable
  registry pins were verified and rendered SQL fits the supported fix.
- `BLOCKED` exits with code 2 and an issue explanation. Demo/test approver markers
  return `FIXTURE_ONLY`; connectivity errors omit credentials.

Neither check starts Docker, applies SQL, or creates a review bundle.
`sandbox_execution` is always `NOT_RUN`. The check cannot establish that a named
human actually reviewed the content: it relies on the registry's approval records.
Marker detection prevents known fixture records being mistaken for team records;
it is not proof of approval authenticity. Actual execution repeats the checks.
The existing demo runner is still available for explicitly labelled fixture tests.

## Bundle contents and download contract

Verified API responses now include `review_bundle.status` (`READY` or
`UNAVAILABLE`). An unavailable export does not rewrite the sandbox outcome;
its reason is included. When ready, GET the returned URL under
`/api/v1/sandbox/runs/{run_id}/bundle` to download the ZIP. Only the last eight
server-created bundles are retained in process memory; restarting expires them.
No endpoint accepts caller-supplied test results as proof of execution.

The ZIP contains `harden.sh`, `runner.py`, `fix.json`, `report.html`,
`evidence.json`, `manifest.json`, and `README.txt`. The script requires Python 3
and psycopg2; requirements-sandbox.txt provides the latter. It supports explicit
per-fix status/apply/rollback commands, checks the manifest, checks PostgreSQL
version/database and full scoped configuration provenance, and refuses drift.
It holds an advisory lock while applying, reloading and verifying via new
sessions. Rollback restores the exact prior value and source, not file formatting.
A manifest detects changed files but is not a cryptographic signature.

The DBA must verify server identity: matching database names/configuration do
not uniquely identify a cluster. Advisory locking coordinates these runners,
not unrelated administrator changes. If execution partially succeeds or
verification fails, inspect the target before retrying. The bundle contains
snapshot evidence; store it according to the team's data-handling rules.

Demo/test approvers are detected and labelled throughout the report/config.
Their runner requires `--allow-demo`; genuine team approval remains a separate
prerequisite for a team demonstration. UI download does not run the script.
After DBA application, recollect and reassess with the same specs.

## Remaining integration work

- The repo already provides the collector, six sample specs and benchmark records.
  `scripts/demo_collector_handoff.py` generates a real collector snapshot on an
  owned PG17 target and exports the complete development review evidence. We do
  not need Xylon to supply another collector or manually generate that snapshot.
- A genuine approved registry reference (and a team-selected target if required
  for the demonstration) is still needed to claim a non-fixture end-to-end run.
- HERMES tools now connect existing uploaded snapshots through an exact-spec
  assessment/preparation bridge to adaptive sandbox testing and bundle downloads.
  See [HERMES_INTEGRATION.md](HERMES_INTEGRATION.md). A live chat/model run still
  needs local HERMES and model configuration.
- Automatic spec generation/collector compilation, native snapshot API v0.3
  migration, restart settings and real-target recollection remain separate.
- Xylon's validator is reused as one check; its regex-based SQL validation is
  not a general SQL safety boundary. The bundle also enforces the exact supported
  apply shape and source-derived rollback. It conservatively refuses a rollback
  alias whose literal differs from the recorded effective prior value.
