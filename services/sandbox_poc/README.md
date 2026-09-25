# Local sandbox milestone

Implements one real fix: PostgreSQL 17 `log_connections`, using the exact
`cis-pg17-v1.1.0:3.1.20` spec. This module is independent of the legacy HTTP
sandbox service; no production target is contacted by the execution layer.

## Run locally

From the repository root, with Docker Desktop running:

```sh
python3 -m venv .venv
.venv/bin/pip install -r requirements-sandbox.txt
docker pull postgres:17-bookworm
.venv/bin/python scripts/sandbox_poc.py demo --prior-source conf --output data/demo-conf.json
.venv/bin/python scripts/sandbox_poc.py demo --prior-source auto --output data/demo-auto.json
```

Each demo creates a disposable source database, collects/assesses it, and creates
a separate disposable sandbox. The `auto` case has an underlying `on` value in
`postgresql.conf` and an overriding `off` in `postgresql.auto.conf`, so resetting
the override would be an incorrect rollback. Both cases enable
`log_disconnections` to provide an initially passing regression control.

The demo uses the repository's Jinja template with a **synthetic test approval**;
`demo_only: true` and `TEST FIXTURE ONLY` identify its output. It does not insert
templates/documents, grant approval, use RAG credentials or access pgvector.
Its results are development evidence, not a production-approved bundle.

The image tag is resolved to a local immutable image ID before each container is
created; that ID is recorded in evidence. Containers have no network, published
ports, host mounts or persistent volumes. PostgreSQL runs as the image's postgres
user with a read-only root and tmpfs data. An official PG17 Bookworm image is the
tested runtime. The downloaded image is retained as a reusable dependency.

## Connected API

See [API.md](API.md) for the versioned handoff, exact template/evidence references,
local server setup and end-to-end registry integration tests. The new endpoint
is `/api/v1/sandbox/runs`; legacy `/api/v1/sandbox/validate` is unchanged.

## Shared boundary with Xylon

`SpecEngine.collect(runtime)` runs Xylon's native manifest collector inside a
run-owned disposable container. `SpecEngine.assess(snapshot)` calls his Phase 1
assessor and retains its original report. Main API intake accepts v0.3 snapshots.
The sandbox also binds a supplied `assessment-report-v1` to the exact inputs.
See [INTEGRATION.md](INTEGRATION.md) for the current commands and API contract.

Spec loading validates traceability against `records.json` and uses canonical
spec hashes. The current six catalog specs include five automated settings and
one manual/needs-capability finding. Regression claims cover the supplied set
only, not every control in the benchmark. Existing proof descriptors are
validated but no general break/fix proof-generation system is added.

To validate an upstream snapshot using real approved registry content:

1. Supply the exact spec directory and matching benchmark records.
2. Save an input JSON object with `snapshot`, `assessment`, and `template_ref`:

   ```json
   {
     "version": 1,
     "sha256": "<exact approved template content hash>",
     "evidence_refs": ["<exact approved document ID>"],
     "environment": "dev"
   }
   ```

   The object above is the value of `template_ref`, not the whole input.
3. Set `DATABASE_URL` for **read-only registry retrieval**, then run:

   ```sh
   .venv/bin/python scripts/sandbox_poc.py validate --input input.json \
     --spec-dir catalog/specs/cis-pg17-v1.1.0 \
     --records catalog/benchmarks/cis-pg17-v1.1.0/records.json \
     --output data/validation.json
   ```

The lookup requires the exact active `set_config_parameter` version/hash and
approved, effective, applicable RAG documents by ID. It uses a read-only database
transaction. No similarity-search substitution or latest-template fallback is
allowed. `SET_CONFIG_log_connections` is the fix-unit contract ID; the result's
`template.registry_name` records its explicit mapping to `set_config_parameter`.
The template is rendered internally using the existing parameter validator.
There is no CLI option for raw remediation SQL or an existing container/target.

## Loop and acceptance

A LangGraph conditional cycle runs one full attempt at a time. Each attempt:

1. Creates a fresh container and reconstructs the scoped settings.
2. Recollects and proves matching values, sources, configuration entries and
   findings, including the target FAIL.
3. Renders/applies the fixed approved candidate `log_connections=on`, reloads and
   checks through fresh PostgreSQL sessions.
4. Recollects all supplied specs. The target must PASS, initially passing
   controls must remain PASS, no new gaps may appear, and `SELECT 1` must work.
5. Tests rollback even after a partially failed apply. Restored values, sources,
   file entries and assessment findings must match the reconstructed baseline.
6. Removes and verifies absence of run-labelled resources in `finally`.

At most three attempts execute. Compatibility mode retries the same approved
candidate. Adaptive mode inserts an LLM revision node after an eligible failure:
it selects a different pinned approved candidate or stops with `NEEDS_REVIEW`.
The model's own SQL is never executed. See [HERMES_INTEGRATION.md](HERMES_INTEGRATION.md)
for model setup, the connected upstream endpoints, and remaining inputs from Xylon.
Invalid contracts/provenance terminate, as does cleanup failure. Input failures
raise before creating a sandbox. SIGINT/SIGTERM unwind cleanup; an uncatchable
process kill or an unavailable Docker daemon cannot guarantee immediate removal.
Container ownership is labelled `dbguard.sandbox-poc.run=<run_id>` for recovery.
There is no global Docker prune or cleanup of unrelated resources.

The result is a `sandbox-run-v1` envelope containing the schema-validated
`fix_unit`, hashes, template/evidence identities, regression scope and every
attempt's snapshots, assessments, health, rollback and cleanup results.
Downstream consumers must require `status == VERIFIED`, successful rollback
and cleanup, and reject demo-only output for production bundle generation.
Failed results deliberately retain the attempted fix and evidence for diagnosis;
the presence of `fix_unit` alone does not mean the fix is accepted.

## Deliberate limits

- Reconstruction supports defaults and standard paths under
  `/var/lib/postgresql/data`: `postgresql.conf` and `postgresql.auto.conf`.
  Custom includes, command-line/session/role/database overrides, duplicate
  entries, sanitised values, gaps and pending-restart states are rejected.
- Exact rollback means effective value, source path, context and the relevant
  configuration entries/precedence are restored. `ALTER SYSTEM` can rewrite
  comments and line numbers in auto.conf; byte-for-byte file restoration is not
  claimed. Source lines are not used as stable identities.
- Only settings referenced by supplied automated specs are reconstructed.
  This is not a full clone of data, roles, extensions or the operating system.
- Restart/internal settings are explicitly unsupported in this milestone.
  Restart handling, new fix candidates, full spec coverage, legacy endpoint migration,
  and production hardening remain future work. The local review bundle now
  provides `harden.sh` and HTML reporting for the supported fix; see
  [INTEGRATION.md](INTEGRATION.md) for the collector handoff and approval checks.
- The fix-unit context enum now uses actual PostgreSQL contexts, replacing the
  invalid `suicide` entry and adding `postmaster`/`internal`. This does not enable
  automatic remediation for those contexts.

## Verify

```sh
.venv/bin/python -m pytest tests/test_sandbox_poc.py tests/test_spec_validate.py -q
DBGUARD_POC_LIVE=1 .venv/bin/python -m pytest tests/test_sandbox_poc_live.py -q
```

Live tests are opt-in and create only disposable PG17 databases. They cover both
configuration sources and a real partially executed fix that must roll back and
clean up on all three attempts. Unit tests inject missing evidence, regressions,
health/rollback/cleanup failures, interruption, and identity/approval mismatches.
Legacy sandbox expected-failure tests are left unchanged.
