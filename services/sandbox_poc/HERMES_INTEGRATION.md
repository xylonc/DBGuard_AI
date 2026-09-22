# HERMES, upstream intake and adaptive sandbox retries

## Connected path

The existing `POST /api/v1/snapshots` stores Xylon's collector v0.2 JSON.
HERMES can now use these MCP tools, backed by the shared API:

| Tool | API | Purpose |
|---|---|---|
| `get_snapshot_spec_assessment` | `GET /api/v1/snapshots/{id}/spec-assessment` | Bridge the collector evidence and assess the exact installed specs |
| `prepare_sandbox_handoff` | `POST /api/v1/sandbox/handoffs` | Resolve exact approved hashes and bind snapshot, specs and assessment |
| `run_sandbox_handoff` | `POST /api/v1/sandbox/handoffs/{id}/run` | Run the existing sandbox/bundle service with adaptive retries |
| `get_sandbox_handoff_status` | `GET /api/v1/sandbox/handoffs/{id}` | Retrieve status and the resulting bundle URL |

The existing `/api/v1/sandbox/runs` still accepts a complete handoff directly.
The bundle uses the existing `GET /api/v1/sandbox/runs/{run_id}/bundle` route.
Legacy `/assessment`, `/proposals/validate-and-render`, and `/sandbox/validate`
are unchanged. A rendered legacy proposal is not evidence of a sandbox test.

Prepared handles live in a bounded process-local store (eight entries). A repeated
run request returns the previous result instead of starting another three tries.
A concurrent request returns 409. On a timeout, inspect the same handle. Restart
or eviction expires handles; this POC needs a single API worker. Durable jobs and
cross-process duplicate protection are not implemented.

## What adaptive means

The actual LangGraph cycle is `test_fix -> revise_fix -> test_fix` after an eligible
failure. Each test still starts from a fresh disposable baseline and performs
rollback/cleanup before the model sees the failure. Maximum three tests and two
revision calls per run. Contract or cleanup failures terminate immediately.

The LLM receives the tested template SQL, scoped setting values/context, findings,
failed phase, rollback/health results and a list of approved alternatives. Missing
post-apply measurements remain unknown. Model explanations are advisory; only the
measured acceptance gates establish success. It does not receive the raw snapshot, registry DSN,
roles or credentials. It returns a diagnosis, proposed improvement, and either an
approved candidate ID or `manual_review`. The latter is reported as `NEEDS_REVIEW`.
The suggestion is untested text, not executable SQL. The model has no tools.

Only a different pre-approved candidate may execute. Its exact approval pins are
rechecked immediately before retesting. Invented IDs, malformed responses and
comment/whitespace-only changes stop the loop. Final bundle generation independently
checks the selected template against the handoff and its supported SQL shape.

For the current `log_connections=on` fix, there may be no meaningful alternative
approved template. The correct result is a diagnosis/review request, not three
cosmetically different commands. General arbitrary-SQL repair, new controls and
restart remediation are not enabled by this feature.

HERMES coordinates the workflow through MCP. The LangGraph reviewer makes a
separate, tool-free call to an OpenAI-compatible model endpoint; it may use the
same provider/model as HERMES. It does not recursively call the HERMES agent.

## Local setup

Install `requirements.txt` on the host, with Docker available. Configure the
registry connection and model locally; do not place secrets in chat or git:

```text
DATABASE_URL=<approved-registry connection using a SELECT-only role>
SANDBOX_POC_ENABLED=true
SANDBOX_LLM_ENABLED=true
SANDBOX_LLM_BASE_URL=https://ollama.com/v1
SANDBOX_LLM_MODEL=gpt-oss:20b
SANDBOX_LLM_API_KEY=<model provider key>
SNAPSHOT_STORAGE_DIR=<local snapshot directory>
```

Start the existing API with its new routes on the Docker host:

```sh
python scripts/local_sandbox_api.py --env-file /path/to/local-settings.env --port 8011
```

The default host binding is localhost. The optional Compose overlay routes the
container MCP bridge to `host.docker.internal:8011`; verify that the Docker host
can reach that binding in your environment. If a different binding is necessary,
choose it explicitly; this local API does not add authentication.

```sh
docker compose --env-file .env -f deploy/compose.yaml -f deploy/compose.local-sandbox.yaml up -d --build api mcp hermes
```

For a host-run MCP bridge, use:

```sh
DBGUARD_MCP_HOST=127.0.0.1 DBGUARD_API_URL=http://127.0.0.1:8011 python -m services.dbguard_mcp.server
```

A HERMES container using that host bridge needs `mcp:host-gateway` in its extra
hosts. The bridge permits `mcp:8001` as well as localhost while retaining DNS
rebinding protection. The Compose network already resolves the `mcp` service.

HERMES needs its model/dashboard configuration from `.env.example`.
The registry used by the host API must contain the same approved records used
by its search endpoints. HERMES and MCP receive no Docker socket.

Upload the collector JSON to the host API (not the separate default API container),
then give its returned `snapshot_id` to HERMES. Ask it to assess and test the
connection-logging fix. It should show the returned outcome and downloadable
review bundle, or explain missing input/approval/model configuration.

File-based callers may use `build_sandbox_handoff.py --retry-mode adaptive`
and repeat `--retry-template-ref approved-alternative.json` at most twice. Existing
handoffs default to `repeat` for compatibility; the new HERMES path uses `adaptive`.

## Exactly what we need from Xylon

Implementation can continue with fixtures. To prove a genuine upstream handoff,
request these concrete items:

1. **A PostgreSQL 17 collector snapshot**, produced by `collector/dbguard-collect.sh`
   from a disposable/dev target with `log_connections=off`. It needs ungapped,
   unredacted evidence for the scoped settings and `file_settings`, including prior
   values, sources, contexts and pending-restart state. Current reconstruction
   supports defaults and the standard `postgresql.conf`/`postgresql.auto.conf`
   paths under `/var/lib/postgresql/data`; custom paths/overrides remain unsupported.
   Do not collect DBGuard's own pgvector registry as the test target.
2. **The exact spec set and matching benchmark records** used for that snapshot:
   benchmark ID/version, YAML/JSON specs, and `records.json` with source hashes.
   The six installed sample specs work today; they are not the whole benchmark.
3. **The upstream assessment, if available**, bound to the same normalized snapshot
   and spec hashes. The legacy finding-list response differs from this contract.
   Our new spec-assessment bridge can compute it until upstream emits this format.
4. **Existing human-approved registry identities**: `set_config_parameter` version,
   applicable evidence document IDs/versions, and environment. Configure a read-only
   registry connection locally. The exporter resolves exact hashes. Seeding or
   embedding records alone does not approve them. Approval can come from the team's
   reviewer; it need not be Xylon personally.
5. **For meaningful adaptive alternatives**, any separately reviewed template
   versions that could correct a failed candidate, with their supporting evidence.
   If none exists, the LLM can diagnose the failure but execution pauses for review.

For full workbook-to-sandbox integration, Xylon must also expose the completed
workbook-to-spec generation and spec-driven collector compilation outputs.
The current XLSX knowledge ingestion endpoint is not a complete spec generator.
Real-target recollection after DBA application remains a separate integration.

## Verification boundaries

Automated tests exercise actual MCP tool functions against the existing API,
and real disposable PostgreSQL tests exercise failed candidate -> revised candidate
-> reassessment -> exact rollback -> cleanup. Model responses in those tests are
scripted. These tests do not prove a live HERMES conversation or model quality.
Live verification on 2026-09-22 used Ollama Cloud `gpt-oss:20b` with the pinned
HERMES image, a host API on port 8011, and a host MCP bridge on port 8001:

- HERMES chat called the real spec-assessment endpoint for an uploaded collector
  snapshot and correctly reported failing controls 3.1.20 / 3.1.25 and manual
  control 3.1.14. All nine MCP tools were discoverable. This exercised chat over
  the HERMES API; dashboard health/login routing was checked, not a browser chat.
- A deliberately faulty synthetic candidate kept `log_connections` off. The live
  reviewer selected a different fixture candidate, and the second PostgreSQL
  attempt became VERIFIED: target PASS, no supplied-spec regressions, healthy
  database, exact scoped rollback and cleanup. Source and registry were unchanged.
- The first review's restart explanation was incorrect. Adding the actual tested
  SQL and scoped setting context produced the correct diagnosis on a fresh live
  run. This is one observed scenario, not proof of general model reliability.
- Fixture approval records were labelled DEMO_FIXTURE_ONLY. This does not prove
  team-approved RAG retrieval or a complete HERMES-driven prepare/run/bundle chat.
  Those still need a reviewed registry and embedding configuration.

Private provider/dashboard settings stay in the ignored local `.env`. Live
responses and database evidence are local artifacts, not committed credentials.
The dashboard is at `http://127.0.0.1:9119`; use the local dashboard credentials.
The local host API/MCP processes must remain running for chat tools to work.
