# Live workflow demo

This is a real local UI for the existing `POST /api/v1/sandbox/runs` endpoint.
It runs actual PostgreSQL collection, assessment, approved-template lookup,
LangGraph remediation, rollback verification and cleanup. It does not require
an LLM, external network API, or access to the team's DBGuard database.

The initial source snapshot now comes from the repository's actual
`collector/dbguard-collect.sh` and `collect.sql`, projected through the collector
bridge. The shared spec collector is used for sandbox reassessment and source
invariance checks. This keeps the existing upstream collector in the demo path.

## One-command collector demonstration

With the same dependencies and Docker images described below:

```sh
python scripts/demo_collector_handoff.py --output-dir data/collector-demo-run-1
```

Choose a new output directory for each run. This creates a disposable PG17 source
and a separate fixture registry, runs Xylon's collector, stores its output through
the existing SnapshotStore, assesses the exact installed specs, tests the fix and
exports the review bundle. No files, approvals or database connections need to
come from Xylon to reproduce this development demonstration.

Outputs: `collector-snapshot.json`, `snapshot-receipt.json`, `uploaded-snapshots/`,
`handoff.json`, `sandbox-result.json`, `summary.json`, `review-bundle.zip`, and
`report.html`. The summary records collector file hashes and whether source,
registry and cleanup checks passed. It exports the bundle only after fixture
cleanup succeeds. A failed run exits with code 2 and preserves available evidence.

This uses genuine collector output from synthetic target state and deliberately
labelled `DEMO_FIXTURE_ONLY` approval records. It does not establish team approval
or test a live LLM/HERMES chat session. It uses deterministic compatibility mode;
adaptive mode and live model setup are covered in HERMES_INTEGRATION.md.

## Start

From the repository root, use the environment with `requirements-sandbox.txt`
installed. Docker Desktop must be running and these images available:

```sh
docker pull postgres:17-bookworm
docker pull pgvector/pgvector:pg17
python scripts/demo_ui.py --port 8010
```

Open <http://127.0.0.1:8010> after startup completes. API documentation is at
<http://127.0.0.1:8010/docs>. Keep the server terminal open. Press Ctrl+C once
and wait for shutdown to complete; this removes the demo source and registry.
Each sandbox attempt removes its own resources before returning.

The launcher creates a new disposable source and a separate temporary pgvector
registry. It never uses `DATABASE_URL` to connect to an existing database.
The registry has only demo template/evidence records, explicitly marked
`DEMO_FIXTURE_ONLY`. They demonstrate the approval gate, not genuine human
approval. The sandbox API accesses the registry using a SELECT-only account;
fixes execute only in new disposable PostgreSQL sandbox containers.

## Presentation walkthrough

1. **Benchmark:** inspect the six installed specs and their exact hash.
2. **Assessment:** show the real source findings; connection logging fails.
3. **Proposed fix:** inspect the pinned template/evidence reference.
4. **Sandbox test:** run the live API. The UI waits for its real response;
   it does not simulate stages. The API is synchronous and can take minutes.
5. **DBA handoff:** inspect before/after findings, SQL, rollback and per-attempt
   evidence. Download the actual request/result as JSON or the DBA review ZIP (script, HTML report and evidence).
6. **Reassessment:** recollect the demo source to prove it remains unchanged.
   The source should still fail the connection-logging control.
7. Optionally run **Test evidence mismatch rejection**: the UI sends a wrong
   evidence hash and displays the real API rejection. It clears the old result.

Only `VERIFIED` accepts a fix. An HTTP 200 alone does not mean success. Failed
attempts and cleanup failures remain visible. A disconnected browser does not
cancel a run; wait for the backend to finish. Concurrent demo operations return
409. Do not restart a run merely because the browser connection was lost.

## Scope and endpoints

- `GET /` serves the local UI.
- `GET /demo/context` supplies the exact handoff built from the live demo source.
- `POST /api/v1/sandbox/runs` is the existing real sandbox route, using a demo-only
  service/registry and allowing only this session's source snapshot.
- `GET /demo/source` recollects the owned source with the shared spec engine and
  checks source/registry invariance.

XLSX upload, end-to-end upstream orchestration, HERMES chat wiring, additional fix types and production recollection are not connected by this demo.
It does not call legacy v0.2 snapshot APIs with a v0.3 handoff. No production
apply button is provided. No fake retry outcomes or progress are generated.

The server binds only to loopback, blocks unexpected Host/cross-origin writes,
and has no authentication. Do not expose it remotely. Demo source and registry
containers stay alive only while the demo server is running. Abrupt termination
(SIGKILL, host crash) cannot run shutdown hooks; inspect only containers labelled
`dbguard.live-demo.run=<session_id>` and the source's specific
`dbguard.sandbox-poc.run=<run_id>` before manual removal. Never remove all project
containers indiscriminately.

For a real collector handoff instead of demo fixtures, see [INTEGRATION.md](INTEGRATION.md).
