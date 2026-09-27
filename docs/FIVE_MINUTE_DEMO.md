# DBGuardAI — five-minute recording

Use Connected mode and the disposable demo backend. Before recording, start Docker and the package, check HERMES and Library, and rehearse one new sandbox run. Save a successful bundle as an explicitly labelled backup. Keep credentials off screen.

A five-minute presentation is achievable; live model/network latency has no hard deadline. Do not cram workbook import, two sandbox runs, combined testing and target application into the same take. If a run exceeds the time budget, shorten the wait with a visible “waiting shortened” caption or identify a previous recorded run honestly. Do not present old evidence as new execution.

| Time | Screen and exact click | Spoken script |
|---|---|---|
| 0:00–0:25 | Home → **Load live demo** | “DBGuardAI checks PostgreSQL settings against a benchmark, tests fixes safely and prepares a DBA review package. Today we are using a real disposable database with clearly labelled demo approvals.” |
| 0:25–0:55 | **4. Assessment** | “This snapshot has three passing controls, two failures and one requiring additional capability. We will fix connection logging. These are API results, not a mock table. The source was collected when the demo started.” |
| 0:55–1:25 | **Review available fixes → Show recommended fixes** | “The proposal changes connection logging from off to on. It shows operational risk, prerequisites and how to roll back. More logging can affect storage, so the DBA checks rotation and capacity. Both available example fixes are medium risk.” |
| 1:25–1:40 | Confirm connection logging **Selected for individual test**; scroll to **Run sandbox test** and click once | “Now we test the approved fix in an isolated PostgreSQL sandbox.” |
| 1:40–2:25 | Remain on test screen while it runs | “The runner reproduces the failure, applies the fix, reassesses the supplied controls, checks database health, restores the prior value and configuration source, and cleans up. LangGraph allows up to three attempts. After failure, the LLM can select a different approved candidate; a first-attempt success does not invoke that reviewer.” |
| 2:25–3:15 | **Recorded sandbox result** | “The selected control now passes in the sandbox. The other failure remains because we tested one fix. Here are rollback, health and cleanup results. This screenshot contains actual database query output, with raw evidence retained. It does not prove that the original target has been changed.” |
| 3:15–3:55 | **6. DBA review → Download DBA review bundle**; open extracted report.html | “The DBA receives the report, evidence, apply and rollback instructions, and verification script. Downloading does not apply anything. The DBA reviews each fix and decides when to execute it.” |
| 3:55–4:25 | Open **HERMES** panel; show an actual rehearsal response, explicitly labelled if reused | “HERMES can request assessment and sandbox testing through these same backend tools. This is the response from our rehearsal [or say ‘this live response’ only if newly returned]. Its run ID and bundle identify recorded execution. It cannot approve content or apply target changes.” |
| 4:25–4:50 | **7. Verify target → Recollect unchanged demo source** | “The source remains unchanged, which is expected. Only the sandbox was modified. After the DBA applies a reviewed fix, a fresh collection and reassessment confirm the actual target.” |
| 4:50–5:00 | Remain on result | “That is our workflow: assess, review, test, verify rollback and hand control to the DBA.” |

If a strict unedited live five-minute take is required, omit a new model request and explain HERMES briefly; use a rehearsed normal single-fix run. Model risk review, chat-triggered execution, deliberate retries, combined fixes, Library approval and genuine target application belong in separate clips.

Do not claim success if the result is FAILED/NEEDS_REVIEW. Do not call an empty retry history a demonstrated retry. Keep the actual run ID visible and state that regression coverage is limited to the supplied specs/basic checks.

Known current UI limitations and workarounds are in REMAINING_IMPROVEMENTS.md. Full launch instructions are in LOCAL_DEMO.md.
