# DBGuardAI — working notes for Claude Code

DBGuardAI turns a PostgreSQL hardening requirement into a reviewable fix: collect read-only
evidence, assess it against CIS specs, test an approved fix in a disposable sandbox, and hand
the DBA a bundle. It never changes a real target. Read `ARCHITECTURE.md` for trust boundaries
and `docs/ROADMAP.md` for the current plan (internship ends 16 Nov 2026).

## Where things live

| Path | What |
| --- | --- |
| `catalog/benchmarks/cis-pg17-v1.1.0/records.json` | All 72 CIS PostgreSQL 17 v1.1.0 recommendations (parsed workbook) |
| `catalog/specs/cis-pg17-v1.1.0/*.yaml` | Control specs: the single source of truth for CIS rules |
| `catalog/specs/schema.json`, `catalog/specs/contracts/` | Spec schema and JSON contracts (snapshot, fix-unit, handoff) |
| `backend/app/services/spec_engine/` | Spec validation, operators, Phase 1 assessment engine |
| `catalog/controls/assess/` | ASSESS registry: CIS controls generated from specs (`spec_controls.py`) + two `DBGUARD-*` checks |
| `services/sandbox_poc/` | Sandbox loop (`workflow.py`), policy allowlist (`planning.py`), batch tests (`batch.py`), evidence capture, review bundle |
| `collector/` | Read-only evidence collector (`collect.sql`). Subagents only propose changes; the main session applies them after db-security-reviewer and Melvin's approval |
| `frontend/` | React UI (Vite). `src/live/` holds the connected workflow |
| `hermes/`, `services/dbguard_mcp/` | HERMES agent config and its restricted MCP tool surface |

## Commands (macOS, from the repo root)

```sh
python3 scripts/demo.py up            # full stack + UI on http://127.0.0.1:8443 (needs Docker, .env.demo)
python3 scripts/demo.py down
.venv-demo/bin/python -m pytest -q    # unit tests; live and tier_b are deselected by pytest.ini
DBGUARD_POC_LIVE=1 .venv-demo/bin/python -m pytest tests/test_product_improvements_live.py   # Docker sandboxes
python scripts/validate_specs.py catalog/specs/cis-pg17-v1.1.0   # every spec must pass
cd frontend && npm run typecheck && npm test && npx oxfmt <changed files>
```

`tests/test_assess.py::TestAssessCLI` uses `uv run`; install `uv` or expect those two to fail.
Run the live tests before calling sandbox work done: unit tests use fake runtimes.

## Security invariants (never break these)

- `[]` means collected and empty; `null` + a `gaps` entry means not collected. Unknown evidence is GAPPED, never PASS.
- Specs are traceable: `pass_condition_quote` must be verbatim CIS audit text; `validate_specs.py` enforces it.
- An agent may draft a spec (`authored_by: agent`) but never approve one. Approval is a named human.
- SQL is only ever rendered from approved, hash-pinned templates. Identifiers go through the `ident` filter.
- HERMES/the model never supplies executable SQL, template IDs outside the approved set, DSNs or approvals.
- The sandbox accepts no DSN, host mount, network, existing container ID or raw SQL. Containers are run-labelled and removed.
- The HERMES product container keeps shell, file, code-execution and delegation toolsets disabled.
- No passwords, hashes or secrets in snapshots, bundles, logs or screenshots.
- Never apply anything to a real target. The DBA runs the exported bundle.

## Adding a fixable setting control (the Wave 1 recipe)

1. `spec-author` writes `catalog/specs/cis-pg17-v1.1.0/<rec>.yaml` from `records.json`; `validate_specs.py` passes.
2. `benchmark-fidelity-reviewer` checks it against the CIS text (operator direction, expected value, whether the control is conditional).
3. Add the setting to `POLICIES` in `services/sandbox_poc/planning.py` (fix value, risk, impact, checks) and to
   `SetConfigTemplateParams` in `backend/app/models.py`. The fix value must satisfy the spec's operator.
4. `test-writer` adds unit tests and a live break → FAIL, fix → PASS, rollback → original test.
5. `db-security-reviewer` reviews the diff. Then a human approves the spec.

## Working rules

- One reviewed change per commit; branch from `main` (or the open PR branch) and open PRs to `main`. Melvin is the sole engineer and reviews.
- Never weaken an existing assertion to make a test pass; fix the code or ask.
- Keep `docs/ROADMAP.md` honest: update status when a wave item lands, with the test that proves it.
- `docs/REMAINING_IMPROVEMENTS.md` lists known UI/product gaps; tick items off there when fixed.

## The subagent council (`.claude/agents/`)

The main session plans each wave and hands work out. No agent both writes something and approves it.

| Agent | Writes | Never |
| --- | --- | --- |
| `spec-author` | spec YAML | approves, invents pass conditions |
| `benchmark-fidelity-reviewer` | nothing (read-only) | edits specs |
| `engine-implementer` | spec engine, operators, fix units, loop (proposes collector changes) | touches approvals, HERMES allowlists or `collect.sql` |
| `sandbox-runtime-engineer` | sandbox runtime, images, restart/hba/TLS, later VM backends | adds network/mounts/raw SQL |
| `evidence-capture-engineer` | screenshot evidence (rendered + VHS), bundle/report wiring | renders from model output |
| `test-writer` | tests | weakens assertions |
| `db-security-reviewer` | nothing (read-only) | edits code |
