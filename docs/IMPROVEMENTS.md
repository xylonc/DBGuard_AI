# Product improvements delivered for the local POC

This is a local PostgreSQL 17 package. “Implemented” means a working code path, not human approval of team content or proof of production readiness. Verification evidence is listed in PRODUCT_VERIFICATION.md.

| Review item | Implementation and boundary |
| --- | --- |
| Task-based navigation | Library has SQL templates and Knowledge & evidence tabs; raw API tools are under Settings. Workflow stages remain separate. |
| Library catalogue | Paged drafts/active/archived versions, name filtering, SQL/content preview, ingestion forms, XLSX knowledge upload. Empty lists and failures are distinct. |
| Exact content approval | Named reviewer and deliberate approval of the selected stored version. Existing active-version constraints remain. No team approvals are seeded. |
| LLM operational risk | Conservative setting policies plus optional live model review. Model advice cannot lower the risk floor or replace baseline checks. Unknown application context and security severity are explicit. Common reload/restart and logging contradictions are rejected. Advice remains subject to DBA review. |
| Fix ordering | Dependency-aware, lower-operational-risk recommendation. DBA may select another order; the batch must test that exact order and enforce dependencies. Security urgency remains a human decision. |
| Per-fix review | Current/proposed values, configuration source, activation requirement, prerequisites, policy rationale, LLM advice and functional checks. Exact template/evidence pins remain in the handoff and bundle. |
| DBA test scripts | `verify.sh`, plus per-fix apply/rollback/status/verify commands. Fresh connection, simple query, catalogue read, transaction rollback and all scoped configuration values/sources. Model-suggested application checks are plain-English review items, not arbitrary executable SQL. |
| Recovery | Stop on failed gates or drift. Restart fixes stage configuration and require the DBA to restart PostgreSQL, then verify. Combined rollback is reverse order. No automatic production rollback or blind retry. |
| Visual database evidence | Headless browser screenshots of an evidence viewer populated with actual fresh database query results. Raw query output retained; database identity, time, control and sandbox/target scope shown. Not a simulated terminal or model-generated result. Capture failure is explicit. |
| Real-target reassessment | Server checks cluster identity, target/database, version, strictly newer collection, exact specs, target PASS, collection gaps and regressions. Inputs are operator-supplied snapshots; this is not remote attestation or full application health proof. |
| Durable local history | Runs, original bundles, DBA statements, manual screenshot attachments and review events stored in private local SQLite. Complete evidence download retains original bundle plus events/attachments. Approval of an image does not change automated assessment. |
| Reconciliation | Existing LangGraph loop extended to supported settings. Up to three fresh-baseline attempts; explicit model diagnosis/candidate decision retained. Named alternate templates allow separately approved candidates to coexist without reactivating archived versions. No eligible improved candidate means manual review. |
| Additional controls | Policies for log_connections, log_disconnections, debug_print_parse, log_statement, ssl_min_protocol_version and logging_collector. First five use installed specs; restart example for logging_collector reuses benchmark evidence and is included in matching imported releases after reviewer approval. Runtime claims apply only to controls actually tested. |
| Combined tests | Individual tests followed by sequential apply and reverse rollback in one disposable sandbox. Per-fix scripts use the combined configuration baseline; partial/failing combinations do not produce an accepted bundle. |
| Workbook → collector → assessment | Uses Xylon’s Combined Profiles parser. Creates a traceable spec for every row, reuses exact matching supported specs and explicitly marks other controls manual/needs-capability. Review ZIP includes records, specs, manifest and collector. Reviewer approves an exact spec hash before the local release can be assessed. Does not pretend to infer every control automatically. |
| HERMES and UI | Packaged MCP routes both demo and Main API by explicit backend. Chat can assess, obtain risk advice, prepare/run approved fixes and retrieve their results; UI discovers matching server runs. Chat has no content-approval or real-target apply tool. |
| Launch package | One command installs locked dependencies and Chromium, builds UI and starts services. Library uses a dedicated persistent local volume; imported releases, snapshots and history persist privately. Runtime secrets and evidence are excluded from Git/source ZIPs. |

## Human inputs still required

- Xylon/team review of genuine templates, RAG evidence and any imported benchmark release.
- DBA confirmation of application dependencies, maintenance windows and representative application checks.
- Explicit target connection credentials and DBA-run apply/restart/recollect steps.
- Model credentials configured locally by each teammate.

Production access control, multi-user audit authentication, deployment hardening, arbitrary benchmark formats and exhaustive break/fix proof of every generated spec remain outside this POC.
