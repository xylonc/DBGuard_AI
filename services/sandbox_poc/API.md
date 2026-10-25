# Sandbox API handoff — local integration milestone

`POST /api/v1/sandbox/runs` connects a v0.3 snapshot and spec-driven assessment
to exact approved registry content and the existing disposable sandbox loop.
The same router is included in the main DBGuard API and a standalone local app.
Legacy `/api/v1/sandbox/validate` remains separate. Main snapshot intake also accepts
native Phase 1 v0.3 snapshots; sandbox testing requires this new evidence.

## Start the local API

Run on the host with Docker Desktop running and the PostgreSQL image available:

```sh
.venv/bin/pip install -r requirements-sandbox.txt
docker pull postgres:17-bookworm
export PYTHONPATH=backend:.
export SANDBOX_POC_ENABLED=true
# Configure DATABASE_URL in the environment or repository .env to point to
# your registry. Prefer a dedicated account with SELECT on templates and
# knowledge_documents; no write privileges are required.
.venv/bin/python -m uvicorn services.sandbox_poc.api:app --host 127.0.0.1 --port 8010
```

Interactive request documentation is at `http://127.0.0.1:8010/docs`.
The endpoint is synchronous: keep the client connected for the full run and
allow up to 15 minutes for failure/retry paths. Closing the connection is not a
cancellation API; the worker completes its attempt and cleanup.

The existing Compose API does not have Docker access. Leave its sandbox flag
disabled and use this host process for the local POC. The backend image now
includes `collector/collect.sql`, but this does not grant Docker access.
Production authentication, queuing and remote runner deployment are deferred.

## Handoff format for Xylon

The JSON Schema is `catalog/specs/contracts/sandbox-handoff-v1.json`; the matching
Python models and `build_handoff()` helper are in `handoff.py`.

| Field | Meaning |
|---|---|
| `schema_version` | Exactly `sandbox-handoff-v1` |
| `benchmark_id` | Installed benchmark record set, initially `cis-pg17-v1.1.0` |
| `specs` | Complete exact spec objects used to collect and assess this snapshot |
| `spec_set_hash` | Canonical hash of the mapping from spec ID to spec hash |
| `snapshot` | v0.3 object containing `envelope`, `baseline`, `checks` |
| `assessment` | Shared assessment result bound to snapshot and spec-set hashes |
| `template_ref` | Exact approved template and evidence identities, below |

The server validates each spec against the installed benchmark records, verifies
collection query/spec hashes, recalculates assessment, and validates supported
configuration provenance before accessing the registry or creating a container.
Clients cannot supply a registry DSN, image, container ID, raw remediation SQL
or filesystem path. Extra handoff/reference fields are rejected.

Template reference example (replace placeholders with actual approved metadata):

```json
{
  "registry_name": "set_config_parameter",
  "version": 1,
  "sha256": "<64-character approved template SHA-256>",
  "environment": "dev",
  "evidence": [
    {
      "document_id": "<approved RAG document ID>",
      "version": "<exact document version>",
      "sha256": "<64-character approved document SHA-256>"
    }
  ]
}
```

Templates must be active and approved for PostgreSQL 17. Evidence must be active,
approved, currently effective, unexpired and applicable to the PG version and
requested environment. Version/hash mismatches stop the request; there is no
latest-version or similarity-search fallback. Lookup uses a read-only,
repeatable-read transaction and never approves or modifies registry content.
Re-ingesting changed template content creates a new draft version and preserves
the previous version. Activation archives the previous active version. Sandbox
lookup continues to require exact active pins.

Upstream callers can pass their native snapshot and `assessment-report-v1`:

```python
handoff = build_handoff(engine, snapshot, approved_template_reference,
                        assessment=upstream_report)
payload = handoff.model_dump()
```

The sandbox uses the shared Phase 1 manifest builder, native collector and
assessor. See [INTEGRATION.md](INTEGRATION.md) for the full file/API flow.

For an already collected v0.3 snapshot, create the handoff from files:

```sh
.venv/bin/python scripts/build_sandbox_handoff.py \
  --snapshot snapshot-v03.json --template-ref approved-template-ref.json \
  --spec-dir catalog/specs/cis-pg17-v1.1.0 \
  --records catalog/benchmarks/cis-pg17-v1.1.0/records.json \
  --output sandbox-request.json

curl --fail-with-body --max-time 900 \
  -H 'Content-Type: application/json' \
  --data-binary @sandbox-request.json \
  http://127.0.0.1:8010/api/v1/sandbox/runs > sandbox-result.json
```

Do not pass a v0.2 upload response or silently wrap it as v0.3: exact per-spec
collection results and provenance are required. The installed records.json is
the server's benchmark evidence source; installing other benchmarks is separate
from accepting a request. The handoff integrates the Phase 1 snapshot and report. Full workbook-to-spec
generation remains outside this milestone.

## Response and errors

- **HTTP 200**: execution completed. Inspect `status`: only `VERIFIED` is an
  accepted fix. `FAILED` and `CLEANUP_FAILED` retain diagnostic attempt evidence.
- **HTTP 422**: malformed/stale handoff, unsupported provenance, missing approval,
  or template/evidence identity/applicability mismatch. No sandbox is created.
- **HTTP 503**: the local endpoint is disabled or the registry is unavailable.
  Raw registry connection errors are not returned to the client.

Successful responses include a server-generated `run_id`, `approval_source:
registry`, `requires_dba_review: true`, the fix unit, all identity hashes and the
before/after/rollback/health/cleanup evidence from each attempt. Save this JSON
for downstream bundle/report generation. This endpoint does not persist results
or apply anything to the real target.

The existing milestone limits remain: PG17, `log_connections`, at most three
fresh attempts, reload-only fixes, and default/standard configuration sources.
Regression coverage is the exact supplied spec set, not the entire benchmark.

## Tests and approval boundaries

```sh
.venv/bin/python -m pytest tests/test_sandbox_poc_api.py tests/test_sandbox_poc.py tests/test_spec_validate.py -q
docker pull pgvector/pgvector:pg17
DBGUARD_POC_LIVE=1 .venv/bin/python -m pytest tests/test_sandbox_poc_api_live.py -q
```

The live tests create a separate disposable pgvector registry using the actual
`db/init.sql`, a SELECT-only registry account, and disposable source/sandbox
databases. They exercise the real API route and real registry queries without
mocking collection, assessment, template lookup or sandbox execution. They
verify exact rollback for both configuration files, no source/registry changes,
approval rejection and cleanup. Only the registry test container publishes an
ephemeral localhost port; remediation containers remain network-isolated.

Approval records in those tests are explicitly marked `INTEGRATION_TEST_ONLY`.
They prove integration mechanics, not genuine human review. This code never
creates approvals in an existing DBGuard registry. A run using the team's real
approved template and RAG evidence remains necessary before claiming the full
approved-content milestone is accepted. Approval status is checked at lookup
time; downstream DBA review must revalidate freshness before eventual use.

## DBA review export

Verified runs may include a `review_bundle` link to a server-generated ZIP. See
[INTEGRATION.md](INTEGRATION.md) for acceptance gates, download lifetime, the
existing collector bridge and the per-fix DBA runner. No script is applied by the API.
# HERMES and adaptive handoffs

`SandboxHandoff` now optionally includes `retry_mode` (`repeat`, the compatibility
default, or `adaptive`) and up to two `retry_template_refs`, each with the same
exact approval pins as `template_ref`. Adaptive mode requires a configured LLM
reviewer and may return `NEEDS_REVIEW`. Responses include `revisions` and per-attempt
candidate identities/hashes. A verified result can select an alternative pinned
template; downstream bundle checks bind to that selected identity.

The existing snapshot upload API connects through the new spec-assessment and
handoff-handle endpoints. See [HERMES_INTEGRATION.md](HERMES_INTEGRATION.md) for
routes, MCP tools, setup and the distinction between legacy and exact-spec assessments.
