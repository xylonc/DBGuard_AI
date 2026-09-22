---
name: dbguard-hardening
description: Create an evidence-backed PostgreSQL hardening proposal from a DBGuard collector snapshot and approved RAG sources.
version: 1.1.0
author: DBGuardAI
metadata:
  hermes:
    tags: [postgresql, security, hardening, dbguard]
---

# DBGuardAI hardening proposal

Use this workflow whenever a user asks about PostgreSQL hardening, security
configuration, access control, authentication, encryption, logging, auditing,
or related database security requirements.

## Required workflow

1. Obtain the collector `snapshot_id` and deployment environment.
2. Use `get_snapshot_context` to establish the database version and available
   evidence. Report every item in `unavailable_sections`.
3. Use `get_snapshot_assessment` before proposing anything. Its `findings`
   are the source of truth:
   - propose remediation only for findings whose `status` is `FAIL`;
   - never propose changes for `PASS` findings;
   - report every `GAPPED` or `MANUAL_REVIEW` finding as requiring DBA review,
     and never describe it as passing;
   - use each finding's `control_id` exactly; never invent one.
4. Use `search_approved_knowledge` with the request, PostgreSQL version, and
   environment. Only returned active documents may be cited.
5. Use `search_approved_templates`. Never invent a template name. If a FAIL
   finding has `control_metadata.template_id`, use that template only if it
   appears in the search results.
6. For each FAIL finding, choose the smallest relevant returned template and
   prepare its required parameters.
7. Use `validate_and_render_proposal` with a `proposal` object containing:
   - `control_id`: the finding's `control_id`
   - `template_id`: approved template ID from search_approved_templates
   - `parameters`: template parameters matching the template schema
   - `reasoning`: why this template fixes this finding
   - `evidence_refs`: list of approved RAG document IDs
8. If no approved template fits a FAIL finding, report `MANUAL_REVIEW_REQUIRED`
   for that finding and continue with the others.
9. Explain the result in plain language and preserve the returned citations.

## Local sandbox testing

When the user asks to test a fix, use the newer isolated sandbox workflow:

1. Obtain the uploaded `snapshot_id`. Upload remains through DBGuard's existing
   `POST /api/v1/snapshots` endpoint; never fabricate a snapshot or its ID.
2. Call `get_snapshot_spec_assessment`. Its exact spec IDs, findings and scope
   govern sandbox testing. Do not substitute the legacy assessment's control IDs.
3. Use approved knowledge/template searches to obtain actual document IDs and
   template versions. The current sandbox supports PG17 `log_connections=on`
   only. Explain unsupported controls and collection gaps.
4. Call `prepare_sandbox_handoff` with those identities, environment and benchmark.
   Only supply alternative versions that appeared in approved results and could
   address a failure. The service resolves hashes and checks approvals itself.
5. Call `run_sandbox_handoff` once for the returned handle. The LangGraph loop
   gives a failed attempt's scoped feedback to the configured LLM reviewer.
   It can select a different approved candidate or return a correction requiring
   human review. It cannot execute arbitrary generated SQL. Maximum three tests.
6. If the tool times out, use `get_sandbox_handoff_status` for the same handle.
   Do not create a fresh handoff to bypass the attempt limit or restart a run.
7. Report returned status, attempt count, regression/health checks, rollback and
   cleanup. `NEEDS_REVIEW` is not success; describe the LLM suggestion as untested.
   If a review bundle is READY, show its URL using the user's DBGuard API address
   (local setup: http://127.0.0.1:8011), not the internal container hostname.

No sandbox tool modifies the source target. DBA application is separate. Do not
claim complete benchmark coverage, human approval from model reasoning, or a
live HERMES connection merely because these tools are configured.

## Output expectations

Always include:

- interpreted requirement;
- relevant snapshot facts and collector gaps;
- proposed SQL returned by DBGuardAI;
- evidence title, version, section, and source URL when available;
- operational risks and compatibility questions;
- DBA verification and rollback considerations;
- an explicit statement that DBA approval is required before use.

If an approved source or suitable template cannot be retrieved, return
`MANUAL_REVIEW_REQUIRED`. Never bypass the knowledge or template lifecycle.
