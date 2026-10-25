# Phase 1 snapshot + assessment → sandbox → DBA bundle

## Integration reviewed on 25 September 2026

This branch integrates Xylon's main at `499ec01` (Phase 1 collector, assessment,
typed fix units and immutable template versions) with Melvin's sandbox work.

The handoff now uses:

- The native `snapshot-v0.3.0` output from `collector/dbguard-collect.sh -m checks.json`.
- The exact specs and benchmark `records.json` used to build that manifest.
- The `assessment-report-v1` output from `scripts/assess.py`, if supplied. It must
  equal a fresh assessment of those inputs; it is never trusted solely by ID.
- Exact active template/evidence references from the approved registry.

Every sandbox recollection runs that same collector and manifest. Every
reassessment calls `app.services.spec_engine.assess.assess`. The full upstream
report is retained under `assessment.upstream_report`; `findings` is a UI
compatibility projection (MANUAL/NEEDS_CAPABILITY → MANUAL_REVIEW, unavailable
checks → GAPPED). It is not another assessment engine. Snapshot, spec, collector
and canonical manifest hashes are checked before registry access or allocation.

Legacy v0.2 uploads remain supported for legacy assessment, but require
recollection with a manifest before sandbox use. No check results are synthesized
from old settings rows. Manual/needs-capability specs are assessed even though
they do not appear in the automated collection manifest.

## Xylon: continue from your existing assessment

If your `source.json`, `assessment.json` and `checks.json` were produced with
this revision and these exact specs, skip collection and assessment below.
Otherwise, with libpq connection variables configured for a disposable/dev PG17
target (never DBGuard's pgvector registry):

```sh
python scripts/build_check_manifest.py \
  --specs catalog/specs/cis-pg17-v1.1.0 --out checks.json
bash collector/dbguard-collect.sh -m checks.json -t dev-pg17 -o source.json
python scripts/assess.py \
  --specs catalog/specs/cis-pg17-v1.1.0 \
  --records catalog/benchmarks/cis-pg17-v1.1.0/records.json \
  --snapshot source.json --out assessment.json
```

Export existing reviewed registry identities (DATABASE_URL is the registry,
preferably using a SELECT-only account):

```sh
python scripts/export_sandbox_template_ref.py \
  --template-version 1 --evidence-id YOUR_REVIEWED_DOCUMENT_ID \
  --environment dev --registry-env DATABASE_URL \
  --output approved-template-ref.json
python scripts/build_sandbox_handoff.py \
  --snapshot source.json --assessment assessment.json \
  --spec-dir catalog/specs/cis-pg17-v1.1.0 \
  --records catalog/benchmarks/cis-pg17-v1.1.0/records.json \
  --template-ref approved-template-ref.json --output handoff.json
python scripts/review_handoff.py --handoff handoff.json --check-registry
```

Use the actual approved version and document ID. Seeding/embedding content does
not grant human approval. `--check-only` checks inputs without registry/Docker;
`--check-registry` checks approvals without running a sandbox. Fixture approvals
are identified as `FIXTURE_ONLY`, not team approval.

With Docker running and `requirements-sandbox.txt` installed:

```sh
export SANDBOX_POC_ENABLED=true
python scripts/review_handoff.py --handoff handoff.json --output review.zip
```

Or use `--port 8011` instead of `--output` to review the supplied handoff in the
UI. Output files must be new. The ZIP contains `harden.sh`, `runner.py`,
`fix.json`, `report.html`, `evidence.json`, `manifest.json` and `README.txt`.
Nothing is applied to the source. The DBA reviews and applies separately, then
collects and assesses the target again.

## Existing API and HERMES path

1. `POST /api/v1/snapshots` on the main backend accepts native v0.3 JSON as well
   as legacy bundles. It preserves native JSON evidence exactly.
2. `GET /api/v1/snapshots/{id}/spec-assessment?benchmark_id=cis-pg17-v1.1.0`
   returns the shared assessment and exact installed specs.
3. `POST /api/v1/sandbox/handoffs` takes `snapshot_id`, `benchmark_id`,
   `template_version`, `evidence_ids`, `environment` and `retry_mode`. It also
   accepts an optional `assessment` containing Xylon's native report. Omit it to
   calculate the report using the shared assessor. Set `retry_mode: "repeat"`
   if no LLM reviewer is configured; the existing default is `adaptive`.
4. `POST /api/v1/sandbox/handoffs/{handoff_id}/run` executes the bounded loop.
5. Download the returned `review_bundle.url` only when its status is `READY`.

Alternatively `POST /api/v1/sandbox/runs` accepts the full `handoff.json` directly;
its `assessment` may be a native Phase 1 report or the bound wrapper. HTTP 200
means execution completed, not necessarily acceptance: require `VERIFIED` and
`review_bundle.status == READY`. The last eight bundles are kept in memory;
server restarts expire their links.

HERMES continues to call these same preparation/run/status endpoints. This
integration does not require a second chat workflow. See
[HERMES_INTEGRATION.md](HERMES_INTEGRATION.md) for local model/MCP setup.

## Acceptance and current boundaries

The supported fix is still PG17 `log_connections=on`, requiring reload. The
loop must reproduce the source failure and all scoped findings; make the target
PASS; preserve other passing controls; verify database health; restore prior
values and configuration sources; and clean up every run-owned container.
Each retry starts from a fresh reconstruction; maximum three attempts per fix.

Fix units now contain upstream typed `apply`/`rollback` actions. Approved
rendered SQL is kept separately as evidence, and the bundle checks it matches
the typed action and final tested attempt. Rollback SQL comes from the upstream
renderer. Noncanonical textual aliases in auto.conf are rejected before testing
because the typed contract stores the effective prior value. Default and
standard postgresql.conf/postgresql.auto.conf sources are supported; custom
paths, command-line overrides and pending restart states are rejected.

The current catalog has six sample controls, not full benchmark coverage.
Workbook-to-spec completion, more fixes, restart support and a connected
real-target reassessment UI remain separate work. Snapshots generated with a
different collector/spec manifest must be recollected with this checkout.

Xylon's registry allows one active version per template name. Changing content
creates a draft version without revoking the prior version; activating the new
version archives the old one. The sandbox respects this rule. Adaptive retries
can only execute separately eligible approved candidates; this registry does
not currently provide simultaneous active versions of `set_config_parameter`.
Without an eligible alternative, the LLM can diagnose and request review but
cannot execute invented SQL or reactivate archived content.

For a labelled development proof without team approval or a model:

```sh
python scripts/demo_collector_handoff.py --output-dir data/phase1-demo
```

This creates a separate fixture registry and disposable source, collects native
Phase 1 evidence, tests the fix, exports the report/bundle, verifies source and
registry unchanged, and cleans up its resources. Approval remains
`DEMO_FIXTURE_ONLY`; it is not proof of genuine team approval or live LLM use.
