# Verification — 25 September 2026

## Actually run

- TypeScript check (`npm run typecheck`) and production build (`npm run build`).
- Six automated contract/gateway tests: native assessment normalization; target identity and collection freshness checks; locally resolved bundle URLs; API error propagation; and server-side authentication, origin rejection, binary download forwarding and chat-job completion against a controlled HTTP fixture.
- Browser test: loaded the current disposable demo and observed 3 PASS, 2 FAIL, 1 NEEDS_CAPABILITY.
- Browser test: sent the live HERMES sandbox action. The first transport attempt failed because HERMES rejected a forwarded Origin header. Corrected the gateway, added a regression assertion, and retried successfully.
- The corrected live HERMES request produced run `75c04192-7b25-4ec8-a4c6-fde59770ad94`. The response and UI backend record agreed on this identifier and VERIFIED result.
- Browser DBA review displayed connection logging FAIL → PASS, other automated results unchanged, and NEEDS_CAPABILITY retained for the unsupported comparison.
- Actual evidence confirmed rollback_verified=true, health checks after apply and rollback=true, cleanup.verified=true, source_unchanged=true, registry_unchanged=true.
- Downloaded the real ZIP through the UI gateway. ZIP integrity check passed; contents: fix.json, evidence.json, report.html, runner.py, harden.sh, manifest.json, README.txt.
- Recollected the disposable source. Source and registry remained unchanged.
- Main API upload of the freshly collected snapshot succeeded (201); exact-spec assessment returned 3 PASS, 2 FAIL, 1 NEEDS_CAPABILITY. Snapshot: `snap-68f7acb61545393a61d1`.
- The repository's older recorded snapshot uploaded successfully but assessment correctly rejected collector/manifest provenance mismatch (422). This is not counted as a successful assessment.
- Real local nomic-embed-text embeddings: knowledge ingestion returned 200 with one chunk; document lookup returned its draft metadata; template ingestion returned draft status; both search endpoints returned 200 with empty eligible results. Draft-only test records were not approved.

## Not claimed

- The successful live sandbox run needed one attempt. It did not invoke the failure reviewer, demonstrate adaptive revision, or prove model reliability.
- The disposable approvals do not establish team-reviewed RAG provenance. No human approval was invented for Library test records.
- Every API route is wired into the advanced form, but destructive/bulk/approval and all legacy operations were not executed merely to claim coverage.
- A real production target was not modified, and post-production remediation was not proved.
- Main-target HERMES routing was not tested: the running agent's MCP bridge is deliberately connected to the demo backend.
- No workbook-to-spec generation endpoint was added.
- This is a local integration, not an authenticated multi-user deployment or durable run-history service.

Local evidence files are in `verification/` in the working folder and excluded from the source ZIP. Runtime IDs and in-memory bundle handles may expire when their backend process restarts.
