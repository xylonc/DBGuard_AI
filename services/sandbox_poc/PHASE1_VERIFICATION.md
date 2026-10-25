# Phase 1 integration verification — 25 September 2026

Integrated upstream `499ec01` with sandbox/HERMES branch `d604ea8` in an isolated
checkout. The original checkout was left at `d604ea8` with a clean working tree.

## Executed checks

- Default pytest selection: **351 passed, 23 skipped, 49 deselected, 2 expected
  failures**. Three existing datetime deprecation warnings remain. This does not
  claim the excluded upstream live/tier-B suites passed.
- Disposable PostgreSQL tests: **17 passed** across `test_sandbox_poc_live.py`,
  `test_sandbox_poc_api_live.py`, `test_review_bundle_live.py`,
  `test_adaptive_sandbox_live.py`, and `test_collector_demo_live.py`.
- `git diff --check`: no whitespace errors in the integration changes.

The first live invocation could not connect because Docker Desktop was stopped.
After starting Docker, all 17 selected live tests passed. Tests ran in a new
Python environment; no existing application database was used as a fix target.

## Observed handoff

The live review-bundle test ran the repository collector with its exact manifest,
passed the resulting native v0.3 snapshot through Xylon's `scripts/assess.py`,
and submitted the resulting native assessment-report-v1 to the sandbox API.

- Initial report: 3 PASS, 2 FAIL, 1 NEEDS_CAPABILITY.
- After connection-logging fix: 4 PASS, 1 FAIL, 1 NEEDS_CAPABILITY.
- `log_connections`: FAIL → PASS → FAIL after verified rollback.
- No regression of another passing control; database health verified.
- Prior value and configuration source restored; attempt cleanup verified.
- Disposable source and fixture registry unchanged.
- API review bundle downloaded and its exported DBA runner tested on another
  disposable database for status, apply, drift refusal and rollback.
- Native snapshot upload → handoff preparation → run → bundle and HERMES MCP
  function routing were also checked through API tests with controlled runtimes.

The live registry used explicit test/demo approval records. No genuine human
approval, cloud model, or live HERMES conversation was claimed. The adaptive live
test used a controlled reviewer response to prove changed-candidate retry and
cleanup; it does not demonstrate multiple active candidates in Phase 1's registry.

## Deliberate remaining limits

Only PG17 connection logging and reload are supported for fixes. Regression scope
is the supplied six-spec catalog. Production target execution, restart settings,
custom configuration paths, full benchmark coverage, genuine team registry
approval and additional approved adaptive candidates remain outside this proof.
See [INTEGRATION.md](INTEGRATION.md) for Xylon's commands and the registry's
one-active-version constraint.
