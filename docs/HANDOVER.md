# DBGuardAI handover

_Written 12 Nov 2026 by Melvin Loo (sole engineer, internship ends 16 Nov 2026). Update the
"State at handover" section on the last day._

This document is for the next intern or engineer. Read these three, in this order:

| # | Document | What it gives you |
| --- | --- | --- |
| 1 | **Architecture Plan** (claude.ai page, shared by Melvin) | Why each feature was designed the way it was, how fix risk levels are decided, why work is done in batches, and the recommended next steps. Plain language. |
| 2 | **This handover** | How to run, test and change the app, where everything lives, the exact state of the work, and where to continue. |
| 3 | [`ARCHITECTURE.md`](../ARCHITECTURE.md) | The technical reference: components, API, trust boundaries and diagrams. |

Then skim [`CLAUDE.md`](../CLAUDE.md) (working rules and security invariants),
[`docs/ROADMAP.md`](ROADMAP.md) (status per item, with the test that proves it) and
[`docs/COVERAGE.md`](COVERAGE.md) (status of all 72 CIS rules, generated).

---

## 1. The app in five sentences

DBGuardAI checks a PostgreSQL 17 database against the CIS PostgreSQL 17 Benchmark v1.1.0 (72 rules).
A read-only collector produces an evidence snapshot, and a spec engine assesses it against one YAML spec
per CIS rule. For a failed rule, DBGuard picks a fix from a reviewed allowlist and proves it in a
disposable, network-less PostgreSQL container: reproduce FAIL → apply → PASS → roll back → original
state. The DBA downloads a fingerprinted bundle and runs it on the real database. **DBGuard never changes
a real target.** An AI agent (HERMES) explains and drives the workflow through 11 restricted tools, but
never writes SQL or approves anything.

## 2. State at handover (12 Nov 2026)

| Area | State |
| --- | --- |
| CIS coverage | **46 of 72** rules live (checked with evidence). **36** have a rehearsed fix: 29 setting fixes (18 immediately, 11 once the company policy is approved) and 7 per-object account/permission fixes. 26 not started, mostly F8 (host/OS) and F9 (procedure). Source: `docs/COVERAGE.md`. |
| Families done | F1, F2, F3, F4, F5, F6, F7 (see the ROADMAP status table) |
| Task 2 screenshots | Done (PR #44): rendered and VHS real-terminal pictures of sandbox runs |
| Architecture doc | Rewritten 11 Nov (PR #46) |
| **E2E "fix everything"** | **In progress, NOT on `main`.** Branch `melvin/e2e-fix-all` (see §8) |
| F8, F9 | Not started. Planned as guided manual steps with evidence |
| Task 3 (other OSes) | Not started. Design idea only: one runtime interface for the sandbox |
| Production readiness | Not production-ready. Approvals are DEMO-labelled (no real sign-in), the services are not locked to loopback, and policy storage is not persistent |

## 3. First day: set up, run, test

Everything below is macOS, run from the repo root.

### Prerequisites
- Python 3.12+, Node 24+, and Docker with Compose (running).
- `uv`. Two tests in `tests/test_assess.py::TestAssessCLI` and the `tests/live` harness use it.
- VHS, for terminal screenshots: `brew install vhs` (it also needs `ttyd` and `ffmpeg`). It must run on
  the host, never in a container. The reason is in `docs/gates/T2-gate1.md`.

### Configure the AI model (`.env.demo`)
Copy `.env.demo.example` to `.env.demo`. **Never commit it or paste the key anywhere.** As of 12 Nov the
demo uses the NUS School of Computing LLM service:

```
HERMES_MODEL=qwen3.6:35b
HERMES_MODEL_BASE_URL=https://soclaas-api.comp.nus.edu.sg/v1
OLLAMA_API_KEY=<your SoC LLM key>
```

- **The key variable is still called `OLLAMA_API_KEY`.** That is historical: the demo used Ollama Cloud
  until its credits ran out on 10 Nov. Any OpenAI-compatible `/v1` endpoint works.
- **`.env.demo.example` still shows the old Ollama Cloud values** (`gpt-oss:20b`, `https://ollama.com/v1`).
  Use the values above instead.
- **The same model and URL serve three things:**
  - the HERMES agent;
  - the advisory risk reviewer (`LLMRiskReviewer` in `planning.py`);
  - the adaptive retry (`adaptive.py`).
- **Embeddings run locally:** an Ollama container with `nomic-embed-text`. No external call.

### Run the demo
```sh
python3 scripts/demo.py up      # prints READY and the URL; first run takes several minutes
python3 scripts/demo.py down
```

Ports start at `DEMO_BASE_PORT` (default 8443):

| Port | Service |
| --- | --- |
| base | UI |
| +1 | Demo API |
| +2 | Main API |
| +3 | HERMES API |
| +4 | HERMES dashboard |
| +5 | MCP bridge |
| +6 | Embeddings |

Then open the URL, choose **Home → Load live demo**, and walk the seven stages: Benchmark, Collect,
Snapshot, Assessment, Sandbox test, DBA review and Verify target. The Architecture Plan's "What each step
looks like in the app" section has a screenshot of every stage, with what the user does and why.

Logs and state live in `.demo/`. Note that `docs/LOCAL_DEMO.md` is **out of date**: it refers to branch
`melvin/live-demo-package` and "six sample controls". Trust `scripts/demo.py` and this section.

### Tests
```sh
.venv-demo/bin/python -m pytest -q                                   # unit tests; live + tier_b deselected by pytest.ini
python scripts/validate_specs.py catalog/specs/cis-pg17-v1.1.0       # every spec must pass
python scripts/coverage_report.py --check                            # docs/COVERAGE.md must match the specs
cd frontend && npm run typecheck && npm test                         # UI
DBGUARD_POC_LIVE=1 .venv-demo/bin/python -m pytest tests/<name>_live.py   # live: real Docker sandboxes
```

- **CI:** GitHub Actions (`.github/workflows/ci.yml`) runs spec validation, the unit tests and the
  frontend checks on every PR. CI does **not** run the live tests.
- **Run the live tests yourself** before calling any sandbox work done. The unit tests use fake runtimes.
  The main live suites are:
  - `test_product_improvements_live.py`;
  - `test_object_sandbox_live.py`;
  - `test_catalog_fixes_w2b_live.py`;
  - `test_sandbox_pgaudit_tls_live.py`;
  - `test_terminal_capture_live.py`.
- **`tests/live/` is an older harness** (`scripts/run_live_tests.sh`). It needs a `pg-target` database
  defined outside this repo, and it refuses any other host because it runs `ALTER SYSTEM`. The newer
  `*_live.py` tests above do not need it.

## 4. End-to-end: what happens to one rule

Example: CIS 3.1.20, "log_connections must be on".

| Step | What happens | Where (code) | API |
| --- | --- | --- | --- |
| 1. Collect | The DBA runs the read-only collector, which prints JSON (schema 0.3.0). Secret-bearing settings are recorded only as "set, N characters". | `collector/collect.sql`, `collector/dbguard-collect.sh` | – |
| 2. Upload | The snapshot is validated against the contract, hashed and stored immutably | `backend/app/services/snapshot_service.py`, `catalog/specs/contracts/snapshot-v0.3.0.json` | `POST /api/v1/snapshots` |
| 3. Assess | The spec `3.1.20.yaml` is loaded and its operator compares `log_connections` with `on`. The result is FAIL, with evidence. Missing evidence gives NOT_COLLECTED, never PASS. | `catalog/specs/cis-pg17-v1.1.0/3.1.20.yaml`, `backend/app/services/spec_engine/assess.py`, `operators.py` | `GET /api/v1/snapshots/{id}/spec-assessment` |
| 4. Plan | The fix comes from the allowlist: value `on`, risk medium, impact text, prerequisites. The risk is raised (never lowered) by the template, restart and AI advice. | `services/sandbox_poc/planning.py` (`POLICIES`, `risk_review`, `review_floor_and_llm`) | `GET /api/v1/snapshots/{id}/fix-plan` |
| 5. Handoff | The caller (UI or HERMES) pins the snapshot, template version and evidence IDs. No SQL, DSN or approval is accepted. | `services/sandbox_poc/handoff.py` | `POST /api/v1/sandbox/handoffs` |
| 6. Rehearse | A container starts from the pinned PG17+pgaudit image, with no network and a read-only root. It rebuilds the setting from the snapshot, then: assess = FAIL, render and apply the approved template, assess = PASS with no regressions and the server healthy, roll back, assess = original. The container is then removed. | `services/sandbox_poc/workflow.py` (`RemediationLoop`), `runtime.py` (`DisposablePostgres`), `provenance.py`, `templates.py` | `POST /api/v1/sandbox/handoffs/{id}/run` |
| 7. Record | The result (VERIFIED / NEEDS_REVIEW / FAILED) and its evidence go into local SQLite history | `services/sandbox_poc/history.py` | `GET /api/v1/history/{run_id}` |
| 8. Bundle | A zip is built: `fix.json`, `evidence.json`, `report.html`, `runner.py`, `harden.sh`, `verify.sh`, `visual_evidence.py` and `manifest.json` (sha256 of every file) | `services/sandbox_poc/review_bundle.py`, `bundle_assets/` | `GET /api/v1/sandbox/runs/{id}/bundle` |
| 9. DBA applies | `harden.sh` checks the fingerprints, the database identity and that the setting is still as tested, then applies. `verify.sh` re-checks. | `bundle_assets/runner.py` | – |

Variants of step 4:
- **Per-object fixes (F6):** `object_fixes.py` and `ObjectRemediationLoop` use a "stand-in copy" of
  only the object being fixed.
- **Add-on and TLS fixes:** `catalog_fixes.py` covers 3.2 pgaudit, 5.6 passwordcheck and 6.10 ciphers.
- **Several fixes together:** `batch.py` (`POST /api/v1/sandbox/batches`).
- **Report-only account checks:** `spec_engine/catalog_checks.py`.

## 5. Repository map

| Path | What |
| --- | --- |
| `collector/` | Read-only collector. Only the main session changes `collect.sql`, after db-security-reviewer and Melvin approve |
| `catalog/benchmarks/cis-pg17-v1.1.0/records.json` | All 72 CIS recommendations, parsed from the workbook |
| `catalog/specs/cis-pg17-v1.1.0/*.yaml` | 46 specs, the single source of truth for rules. `schema.json` and `contracts/` sit beside them |
| `catalog/policies/cis-pg17-v1.1.0/reference.yaml` | Reference company policy profile (still awaiting real approval) |
| `catalog/controls/assess/` | Registry: CIS controls generated from the specs plus two `DBGUARD-*` checks |
| `catalog/images/sandbox/pg17-pgaudit.json` | Pinned sandbox image record. Rebuild with `scripts/build_sandbox_image.py` |
| `backend/app/main.py` | FastAPI app: snapshots, older proposal path, knowledge and templates, health. Includes the sandbox router |
| `backend/app/services/spec_engine/` | Spec loading, validation, operators, assessment, catalog checks, policy, redaction |
| `backend/app/templates/*.sql.j2` | The only source of executable SQL (approved and hash-pinned) |
| `services/sandbox_poc/` | Planning, handoff, sandbox loop, runtime, batches, history, bundles, screenshots, API router |
| `services/dbguard_mcp/server.py` | MCP bridge: the 11 tools HERMES can call |
| `hermes/` | HERMES image, config (`config/config.yaml`: toolset allowlist), context and the `dbguard-hardening` skill |
| `frontend/` | React + Vite UI. `src/views/` holds the screens, `src/live/` the connected workflow, `server.mjs` the gateway |
| `scripts/` | `demo.py`, `validate_specs.py`, `coverage_report.py`, `build_sandbox_image.py`, `parse_cis_workbook.py`, … |
| `docs/gates/` | Every Gate 1 and Gate 2 record: the design reasoning and Melvin's rulings. Read the one for the area you touch |
| `docs/design/` | Designs not yet built (company custom rules arrives with the E2E branch) |
| `services/twin_runner/`, `services/rag/` | Older parts, still wired in. Candidates for retirement |
| `.claude/agents/` | The subagent council (see §7) |

## 6. The AI parts

| Part | Model and endpoint | What it can do | What it can never do |
| --- | --- | --- | --- |
| HERMES agent (chat in the UI and the HERMES dashboard) | `HERMES_MODEL` at `HERMES_MODEL_BASE_URL` (12 Nov: `qwen3.6:35b` on NUS SoC LLM) | Call the 11 MCP tools below | Shell, files, web, code, memory, delegation, cron: all disabled in `hermes/config/config.yaml`. No Docker socket. Never sees screenshots or raw query output (stripped in the MCP bridge) |
| Risk reviewer | Same model, called by `LLMRiskReviewer` | Return risk advice in a strict schema. It can only **raise** a level | Lower a level, write SQL. Advice that contradicts known facts is discarded |
| Adaptive retry | Same model, called by `adaptive.py` | After a failed rehearsal: pick another **already approved** candidate, or ask for human review | Supply SQL, a DSN or a new template. It never sees the raw snapshot |
| Embeddings | Local Ollama `nomic-embed-text` | Semantic search for the older knowledge and template path | – |

**The 11 MCP tools** (`services/dbguard_mcp/server.py`, allowlisted in `hermes/config/config.yaml`):

| Tool | Plain meaning | Calls |
| --- | --- | --- |
| `get_snapshot_context` | Show the database's version, settings, roles and what could not be collected | `GET /api/v1/snapshots/{id}` |
| `get_snapshot_spec_assessment` | Show the CIS rule results for a snapshot | `GET …/{id}/spec-assessment` |
| `get_snapshot_assessment` | Same, plus DBGuard's own `DBGUARD-*` checks | `GET …/{id}/assessment` |
| `get_fix_risk_plan` | Show the proposed fixes with risk, impact and order | `GET …/{id}/fix-plan` |
| `get_demo_workflow_context` | Show which demo snapshot and workflow are loaded | `GET /api/v1/demo/workflow` |
| `search_approved_knowledge` | Search only approved guidance documents | `GET /api/v1/knowledge/search` |
| `search_approved_templates` | Search only approved SQL templates (names and versions, not to run) | `GET /api/v1/templates/search` |
| `validate_and_render_proposal` | Older path: the server checks the AI's choice of approved template and fills it in for review | `POST /api/v1/proposals/validate-and-render` |
| `prepare_sandbox_handoff` | Pin approved IDs to a snapshot, ready for a rehearsal. No SQL or approvals accepted | `POST /api/v1/sandbox/handoffs` |
| `run_sandbox_handoff` | Start that rehearsal on a throwaway copy | `POST …/handoffs/{id}/run` |
| `get_sandbox_handoff_status` | Read the rehearsal result (images stripped) | `GET …/handoffs/{id}` |

Most tools take `backend` = `default`, `demo` or `main`, which chooses which API they reach.

**Adding or changing a tool:** change both `server.py` and the `include` list in
`hermes/config/config.yaml`, keep `prompts: false` and `resources: false`, and have db-security-reviewer
review it. A tool must never accept SQL, a DSN, a file path or an approval.

## 7. How work is done here

- **Batches ("waves") with two gates.**
  - *Gate 1* is the plan, with numbered decisions and a recommendation for each. Melvin rules on them.
  - *Gate 2* is what was built, the tests, the reviews and the known limits. Melvin approves.

  Both are written to `docs/gates/<wave>-gate{1,2}.md`. The reasons for batching are in the Architecture
  Plan.
- **The subagent council** (`.claude/agents/`): spec-author, benchmark-fidelity-reviewer,
  engine-implementer, sandbox-runtime-engineer, evidence-capture-engineer, test-writer and
  db-security-reviewer. **No agent both writes something and approves it.** Reviewers are read-only.
- **Recipe for a new fixable setting** (from `CLAUDE.md`):
  1. `spec-author` writes the spec and `validate_specs.py` passes.
  2. `benchmark-fidelity-reviewer` checks it against the CIS text.
  3. Add the setting to `POLICIES` in `planning.py` and to `SetConfigTemplateParams` in
     `backend/app/models.py`. The fix value must satisfy the spec.
  4. `test-writer` adds unit tests and a live break → fix → rollback test.
  5. `db-security-reviewer` reviews.
  6. A human approves the spec.
- **Git:** one reviewed change per commit. Branch from `main`, open a PR to `main`, and the reviewer
  merges. Never weaken a test assertion to make it pass.
- **Keep these current:**
  - `docs/ROADMAP.md` status, with the proving test;
  - `docs/COVERAGE.md` (run `coverage_report.py`; CI's `--check` fails otherwise);
  - `docs/REMAINING_IMPROVEMENTS.md`;
  - `ARCHITECTURE.md`;
  - the supervisor progress report on claude.ai.
- **The security invariants** in `CLAUDE.md` are non-negotiable. In short:
  - unknown is never PASS;
  - specs quote CIS verbatim;
  - agents draft and humans approve;
  - SQL only comes from approved, hash-pinned templates;
  - the model never supplies SQL, DSNs or approvals;
  - the sandbox has no network, mounts or raw SQL;
  - no secrets in any output;
  - nothing is ever applied to a real target.

## 8. Where to continue

### 8.1 Finish the E2E "fix everything" work (branch `melvin/e2e-fix-all`)

**First, protect the work.** As of 12 Nov this branch exists only on Melvin's machine. It has 2 local
commits, more uncommitted edits, and is behind `main`. It must be committed, rebased on `main` and pushed
before handover, or it is lost.

The rulings are in `docs/gates/E2E-gate1.md` (approved 10 Nov). Status as of 12 Nov:

| Item | State |
| --- | --- |
| One-click run: phase 1 (no restart) then phase 2 (restart, one joint restart), lowest risk first, failed fixes left out (PARTIAL), no 6-fix limit | Backend in progress (`batch.py`, `planning.py` `fix_phase`/`order_key`/`recommend_order`) |
| Progress bar with plain step descriptions | UI in progress (`frontend/src/live/batchProgress.ts`) |
| Dependencies mean "verify after the restart", not "apply after" | Built in `recommend_order` |
| Decision 1: separate "Needs restart (brief downtime)" label; 3.1.3, 5.6, 3.2 → medium; 5.2 stays high | **Not built.** Remove the restart floor in `review_floor_and_llm` (`if result["requires"] == "restart": … "high"`), add the label, and set the reviewed levels |
| Decision 2: one combined pack with `harden.sh status / apply-all / verify-all / rollback-all`; terminal screenshots on the real database; evidence upload | In progress (`package_assets.py`, `bundle_assets/package_runner.py`, `bundle_assets/terminal_evidence.py`) |
| Decision 3: client-impact warnings, live counts, required checkbox, `CLIENT-ACTIONS.txt`, `--ack-client-impact` | Not started |
| Company custom rules | Design only: `docs/design/COMPANY_RULES.md` |
| Live tests: a one-click run of 10 or more fixes including restart fixes and one deliberate failure; the package's apply-all → restart → verify-all → rollback-all on the **disposable demo source** only | Not done |
| db-security-reviewer pass (terminal capture on the DBA's machine, the evidence upload, the new commands), demo check, Gate 2 | Not done |

### 8.2 After E2E (recommended order, with the reasons in the Architecture Plan)
1. Real sign-in for approvals (replace the DEMO labels).
2. Lock services to loopback or a private network. The demo MCP bridge binds `0.0.0.0`
   (`DEMO_MCP_BIND`).
3. Persistent storage for approved policy profiles.
4. Move the risk levels (`POLICIES`, `CATALOG_FIX_LINKS`, `FIX_TYPES`) into one reviewed data file. Keep
   the "only goes up" rule.
5. Retire the older paths: the twin runner and `POST /api/v1/sandbox/validate`; the free-text proposal
   path, or fence it off.
6. Build company custom rules, following the design doc: new ≥/≤ operators, rules traced to a named
   company owner.
7. F8 and F9 as guided steps with evidence. F8 needs a read-only host collector.
8. Task 3: one runtime interface so a RHEL-family image or VM backend keeps the same sandbox walls.

## 9. Known gaps and gotchas

- **`/api/v1/health` reports stale flags:** `assessment_enabled: false` and `twin_runner_enabled: false`.
- **Screenshot defaults differ by branch.** On `main` the demo turns sandbox screenshots on in terminal
  mode. On the E2E branch they are off by default (10 Nov ruling) and move to the DBA package.
- **Risk-level inconsistency:** 3.1.15 (`log_min_error_statement`) is *low*, while 3.1.25
  (`log_statement`) is *medium*, although both notes warn about sensitive statement text. This awaits a
  decision.
- **Some risk and impact texts are still marked DRAFT** in `planning.py`.
- **The sandbox image is recorded for this Mac's platform.** Intel/amd64 hosts need it rebuilt and
  re-recorded.
- **Wave 2b follow-ups:**
  - collect `ssl_max_protocol_version`;
  - rehearsed `pg_hba` edits;
  - check `pg_hba_file_rules.error` for RADIUS secret echo;
  - null sections that lack a `gaps` entry.
- **Out-of-date docs:** `docs/LOCAL_DEMO.md` and `.env.demo.example` (see §3).
- **`docs/REMAINING_IMPROVEMENTS.md`** lists 16 UI and product refinements. Some are partly done.

## 10. Decisions waiting for a human

1. Approve the reference company policy profile, which unlocks 11 policy-dependent fixes.
2. Approve moving risk levels into one reviewed file.
3. 3.1.15 vs 3.1.25: which way to make them consistent.
4. Which older paths to retire first.
5. Priority after the internship: company custom rules, or F8/F9.

## 11. Glossary

| Term | Meaning |
| --- | --- |
| Spec | One YAML file per CIS rule: what evidence to read, how to compare it, and the verbatim CIS quote |
| Snapshot | The collector's JSON evidence for one database at one time. Immutable and hashed |
| Gap / NOT_COLLECTED | Evidence the collector could not read. Never treated as PASS |
| Policy profile | Company-specific values for CIS rules that say "per your organisation's policy". Approved by a named person |
| Fix unit / handoff | The pinned description of a fix to rehearse: IDs and hashes only, no SQL |
| Sandbox / throwaway copy | A disposable PostgreSQL container with no network, deleted after each run |
| Stand-in copy | A sandbox holding only the one account, table or function being fixed. No real data or passwords |
| Bundle / instruction pack | The zip the DBA runs on the real database |
| Gate 1 / Gate 2 | Plan approval / build approval for a wave, recorded in `docs/gates/` |
| HERMES | The AI agent. MCP is the protocol for its 11 tools |
| Restart floor | Today's rule that any restart-required fix is shown as high risk (to be replaced by Decision 1) |
