# Product upgrade verification — 25 September 2026

Verified locally on macOS, Python 3.14, Node 24, Docker and disposable PostgreSQL 17. These are observed checks, not a claim that the entire repository or a production deployment has been certified.

## Automated compatibility checks

Final targeted suite: **137 passed**. Files:

```text
tests/test_product_improvements.py
tests/test_sandbox_poc.py
tests/test_adaptive_sandbox.py
tests/test_review_bundle.py
tests/test_sandbox_upstream.py
tests/test_demo_ui.py
tests/test_phase1_sandbox_handoff.py
tests/test_hermes_workflow_config.py
tests/test_demo_package.py
tests/test_mcp_tool_surface.py
tests/test_contract_schemas.py
tests/test_models.py
tests/test_api_routes.py
```

Frontend TypeScript check and production build passed. All **6 frontend tests passed**, including gateway error handling and bundle forwarding. `git diff --check` passed. Local server tests require permission to bind sockets; the initially restricted run was repeated successfully with that permission.

## Real disposable database checks

The live tests exercised all six supported setting policies: log_connections, log_disconnections, debug_print_parse, log_statement, ssl_min_protocol_version and logging_collector. Observed checks included:

- Failure reproduction, apply, reassessment, no regressions in supplied specs, fresh database queries, exact prior value/configuration-source rollback and owned-resource cleanup.
- Two fixes tested together, reverse rollback and an actual database query screenshot. Final targeted rerun passed.
- Exported target script applied a fix to a disposable target, captured real query evidence, recollection confirmed the target, and rollback restored its prior configuration. Final targeted rerun passed.
- Restart-setting sandbox test passed. Exported restart script correctly required a DBA restart before verification and a second restart for rollback verification; the dedicated test passed.
- Existing exported-bundle live test passed after its fixture was updated to assert the new cluster-identity guard.

The normal live-test file initially completed with **6 passed, 1 skipped** (model test separately gated). The subsequently added exported restart test passed separately. These are separate runs, not one combined test count.

## Live model and application checks

- A deliberately failed first candidate was diagnosed by the configured live LLM. It selected a separately approved, different fixture candidate; the second attempt passed. Rollback and cleanup passed. The dedicated live model test passed.
- Live risk review returned REVIEWED for connection logging. An earlier incorrect reload/outage explanation led to grounding and contradiction validation; malformed or rejected advice now remains explicit UNAVAILABLE with conservative policy retained.
- `scripts/verify_demo.py` passed through live HERMES, including the recorded sandbox run, bundle, rollback, health, regression, cleanup and unchanged source checks. Recorded run: `60fbc901-639c-4dce-a288-a33d49f0e4eb`.
- Main API chat routing was verified against an actual uploaded snapshot and a new Main API assessment request in the server log. It did not substitute demo assessment results.
- Browser checks exercised the real assessment, risk cards, sandbox evidence image and Library draft form. An explicitly labelled draft was saved without approval.
- Normal shutdown/restart retained that Library draft. The new launcher reached READY on the reserved test ports while the older demo was left undisturbed.
- Combined history requires every selected control to PASS; its durable bundle and negative/positive target reassessment paths are covered by the final unit suite.

Runtime logs, query screenshots and model transcripts remain in the private `.demo/` directory and are excluded from the source package. No production database was used.

## Boundaries

No claim is made of Linux/WSL2 verification, native Windows support, full benchmark automation, authenticated multi-user approvals or representative application workload testing. Approved team templates/evidence and imported spec releases must be reviewed by the team. Model advice is fallible and cannot replace that review. Exact rollback refers to supported values and configuration sources, not byte-for-byte restoration of file formatting. Regression coverage is limited to the supplied specs.

## Publication checks — 27 September 2026

Before publishing, the same targeted backend suite was rerun: **137 passed**. The frontend typecheck, production build and all **6 frontend tests** passed again. Docker was not reachable through its configured socket, so no new live Docker/HERMES run is claimed for this date. Earlier live results above remain historical evidence. Additional recording-polish improvements from the 26 September review remain pending; see REMAINING_IMPROVEMENTS.md.
