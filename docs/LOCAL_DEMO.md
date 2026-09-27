# Launch DBGuardAI locally

Install Python 3.12+, Node.js 24+ (including npm), and Docker with Docker Compose. Start Docker. This package was verified on macOS with Python 3.14 and Node 24; Linux/WSL2 require Chromium system libraries and have not been verified here. Native Windows is not supported by the launcher.

## First launch

Use branch **`melvin/live-demo-package`**, not `main`, for this package. For a clean first launch without disturbing an existing checkout:

```sh
git clone --branch melvin/live-demo-package https://github.com/xylonc/DBGuard_AI.git DBGuardAI-demo
cd DBGuardAI-demo
```

If you already cloned this branch, use `git status` first and preserve any local changes before `git pull --ff-only`. For the initial configuration only (do not overwrite an existing key file):

```sh
cp .env.demo.example .env.demo
```

Open `.env.demo` in a text editor and replace the placeholder with **your own Ollama Cloud API key**. Never commit this file or paste a key into chat.

```sh
python3 scripts/demo.py up
```

Keep the terminal open. First launch downloads dependencies, Docker images, the embedding model and a Chromium browser for visual evidence. It also builds the UI. When it prints **READY**, open the displayed address. The default is **http://127.0.0.1:8443**. The packaged UI does not need a separate HERMES dashboard login.

If those ports are occupied, change `DEMO_BASE_PORT` in `.env.demo`. The package uses that port plus the following six ports. It does not stop other applications to take their ports. Docker should have enough memory for HERMES, embeddings and several PostgreSQL instances; 8 GB is a reasonable starting allocation.

On Linux/WSL2, if Chromium reports missing system libraries, install its platform dependencies using your normal administrator process (`.venv-demo/bin/python -m playwright install-deps chromium`) and restart.

## Demonstration

For a timed five-minute presentation, follow [FIVE_MINUTE_DEMO.md](FIVE_MINUTE_DEMO.md). The complete feature tour below takes longer, particularly with live model calls.

1. **Home → Load live demo**. This loads the real disposable PostgreSQL 17 source collected when the package started, using Xylon's collector and assessor.
2. **Assessment** shows the six installed sample controls, including two failures.
3. **Sandbox test → Show recommended fixes**. Review current/proposed values, operational risk, prerequisites and rollback. **Ask LLM to review risk** adds model advice; it remains subject to DBA review.
4. Select an individual fix and **Run sandbox test**. Or select connection logging and statement logging and **Test selected fixes together**. The latter runs individual tests plus a combined test and reverse rollback.
5. **DBA review** shows actual results, exact rollback/health/cleanup gates and a screenshot of fresh database query results. Download the review bundle. Combined bundles are downloaded from the combined-test panel.
6. Open **HERMES**. Ask: “Assess the current demo snapshot using the actual API. Explain the failed controls and their risk. Do not apply target changes.” To test: “Run a new disposable sandbox test for connection logging using the discovered demo references. Return the real run ID and bundle link.” The agent and UI use the same backend records.
7. **Verify target → Recollect unchanged demo source** shows that sandbox tests did not change the source. A sandbox PASS does not imply the source is fixed.

Demo approvals are always **DEMO_FIXTURE_ONLY**, not human approval. The live demo does not edit the Library registry.

## Real upstream workflow

1. **Benchmark → Import benchmark workbook** accepts the CIS PostgreSQL 17 v1.1.0 Combined Profiles format. Download its review package. Each control receives a traceable spec; only exact matching supported specs are automated. Others explicitly remain manual or need capability.
2. Have the reviewer examine the specs and coverage, then approve the exact release hash with their name. Approval does not magically automate unsupported controls.
3. Run the downloaded collector against your **disposable/dev target**, with standard PostgreSQL connection variables configured locally. Never point it at DBGuard's pgvector registry.
4. In **Settings**, choose **Main API**. Enter the imported benchmark ID, upload its snapshot, and assess.
5. In **Library**, ingest the SQL template and supporting evidence as drafts. Review their exact content and versions, then approve. Do not label demo material as team-approved content.
6. Select a supported failed control. Enter the exact active template version and applicable evidence document IDs, then test. HERMES routes to Main API when that backend is selected; do not ask it to substitute demo references.
7. Download and review the resulting bundle. The DBA controls target apply/restart/rollback outside the web UI.

The package has policies for connection/disconnection logging, parse debugging, statement logging, minimum TLS version and the logging collector. `logging_collector` uses the supplied restart example spec when an imported workbook contains its matching benchmark record. Client TLS/application behaviour still needs representative application testing. Reconstruction supports the configuration sources and paths validated by the sandbox; unsupported overrides or incomplete source evidence are rejected rather than guessed.

## Use the DBA bundle

Use the Python environment created by the launcher so `psycopg2` and Playwright are available:

```sh
source .venv-demo/bin/activate
```

Extract the bundle into its own folder and enter that folder. Set `DBGUARD_DSN` locally using your normal credential handling. The bundle contains no target credentials. Review `report.html`, `risk-review.json`, SQL and evidence first.

For connection logging:

```sh
sh harden.sh status fix-log_connections
sh harden.sh apply fix-log_connections --ack-prerequisites --screenshots
sh verify.sh fix-log_connections --screenshots
sh harden.sh rollback fix-log_connections --screenshots
```

Use the fix ID printed in the bundle for other settings. Demo bundles additionally require `--allow-demo` and must only be used with disposable databases. The runner checks the original cluster identity when available, database/version and scoped configuration drift. A failed check stops progression; inspect the state before retrying.

For restart settings, apply/rollback stages the configuration and returns **RESTART_REQUIRED**. The DBA restarts PostgreSQL through their normal operational process, then runs `verify` or `verify-rollback`. The web application never restarts a real target.

Evidence is saved under `target-evidence/verification-.../`: actual query results, optional browser screenshot and an action event. Screenshots capture a viewer populated with real query output; they are not screenshots of pgAdmin or an external terminal. Keep the query JSON alongside the image.

A combined bundle contains one folder per fix. Apply in the tested order, verify each, and roll back in **reverse order**. To use another order, select it in the UI and run a new combined test first.

## Recollect and confirm the target

After DBA application, rerun the same collector with the same target identifier. Upload the new snapshot to Main API. In **Verify target** or **Settings → Run history**, open the original run and enter the new snapshot ID. The server checks cluster identity, newer collection time, matching specs and regressions before recording **TARGET_REASSESSMENT_CONFIRMED**.

A **DBA_REPORTS_APPLIED** statement remains an operator statement. It does not mark the target verified. Supporting screenshots may be attached and accepted/rejected by a named reviewer; this never changes the automatic assessment. Download the complete evidence/history bundle to include those attachments and review events. Application-specific checks remain separate DBA responsibilities.

## Adaptive retry candidates

The failure reviewer runs only after a failed attempt, with at most three attempts per fix. Separately approved alternatives can use names such as `set_config_parameter__alternative`, each with its own active version. Ingest and review them through Library, then enter `name:version` in the optional alternatives field. The SQL must still fit the supported setting action. Archived or unapproved versions are not executable. The model may choose a genuinely different approved candidate or request manual review; it cannot execute arbitrary newly invented SQL.

## Stop, restart and retained data

```sh
python3 scripts/demo.py status
python3 scripts/demo.py down
```

Ctrl+C in the launch terminal also stops the package. Normal shutdown removes this package's owned disposable source/sandbox containers and stops its services. The dedicated **Library volume** persists drafts and approvals. `.demo/` retains local history, imported releases, Main API snapshots, logs and private runtime configuration. HERMES and embedding-model volumes also persist. None of these are included in Git or source ZIPs.

On restart, load the new disposable demo snapshot. Old demo handoff IDs expire; saved run bundles/history remain accessible. Main API snapshots and Library content survive normal shutdown. Avoid deleting `.demo/library-password` while retaining its Library volume, because that file holds its local database password.

## Verification commands

With the package running:

```sh
python3 scripts/verify_demo.py
```

This invokes the configured live model and creates a new disposable sandbox run. For developers:

```sh
.venv-demo/bin/python -m pytest tests/test_product_improvements.py
DBGUARD_POC_LIVE=1 .venv-demo/bin/python -m pytest tests/test_product_improvements_live.py
```

The deliberately failing-then-improved live model test additionally needs `DBGUARD_LLM_LIVE=1` and `.env.demo`. It uses explicit fixture approvals, never a production target.

## Troubleshooting before recording

- **Docker unavailable:** start Docker Desktop and wait until its engine is running. `docker info` must succeed before starting this package.
- **Port occupied:** set an unused `DEMO_BASE_PORT` in `.env.demo`. Seven consecutive ports are needed. The app URL follows that value; the default is 8443.
- **HERMES unavailable or Library 503:** check Docker first. With Docker ready, stop this package using `python3 scripts/demo.py down`, then start it again. Do not delete persistent volumes or private state to fix a connection error.
- **A CONNECTED badge or API READY status:** these do not prove all dependencies work. In Settings, click **Check live connections**, confirm Library loads, and rehearse an actual sandbox run and HERMES request.
- **Model key:** edit `.env.demo` locally, then restart the package. Never commit the key. First-time installation and model/image downloads can take several minutes.
- **Repeat launch:** from the same folder run `python3 scripts/demo.py up`; do not recopy `.env.demo.example` over your existing key file.

See [REMAINING_IMPROVEMENTS.md](REMAINING_IMPROVEMENTS.md) for known recording/UI gaps. Publishing this package does not mean those follow-up changes have been implemented.

## Limits

This is a local POC, not a public or multi-user deployment. API approval names are operator declarations, not authenticated organisational identities. Snapshot verification is based on supplied evidence, not remote attestation. An application can still fail despite simple database health checks. Unknown benchmark controls remain visible and unautomated. Production hardening and exhaustive proof of every generated spec are deferred.

See [IMPROVEMENTS.md](IMPROVEMENTS.md) and [PRODUCT_VERIFICATION.md](PRODUCT_VERIFICATION.md) for the implementation checklist and checks actually run.
