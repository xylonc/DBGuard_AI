---
name: dbguard-hardening
description: Create an evidence-backed PostgreSQL hardening proposal from a DBGuard collector snapshot and approved RAG sources.
version: 1.0.0
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
3. Use `search_approved_knowledge` with the request, PostgreSQL version, and
   environment. Only returned active documents may be cited.
4. Use `search_approved_templates`. Never invent a template name.
5. Choose the smallest relevant set of returned templates and prepare their
   required identifier parameters.
6. Use `compile_hardening_proposal`. The backend must validate and render the
   template; do not construct SQL in free text.
7. Explain the result in plain language and preserve the returned citations.

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
