import { useEffect, useState, type ReactNode } from "react"
import { useLive } from "@/store/liveStore"
import { useWorkflow } from "@/store/workflowStore"
import {
  api,
  request,
  findings,
  jsonText,
  bundlePath,
  sameTarget,
  isFreshSnapshot,
} from "@/adapters/live"
const button =
  "rounded-lg bg-teal-700 text-white px-4 py-2 text-sm disabled:opacity-40 disabled:cursor-not-allowed"
const input =
  "border border-slate-300 rounded-lg px-3 py-2 w-full text-sm bg-white"
export function Card({
  children,
  title,
}: {
  children: ReactNode
  title?: string
}) {
  return (
    <section className="bg-white rounded-xl border border-slate-200 p-5 space-y-3">
      {title && <h2 className="font-semibold text-slate-800">{title}</h2>}
      {children}
    </section>
  )
}
export function Raw({
  value,
  label = "Inspect API evidence",
}: {
  value: any
  label?: string
}) {
  return (
    <details className="text-xs">
      <summary className="cursor-pointer text-teal-700">{label}</summary>
      <pre className="mt-2 bg-slate-50 p-3 overflow-auto max-h-96 whitespace-pre-wrap break-all">
        {JSON.stringify(value, null, 2)}
      </pre>
    </details>
  )
}
export function Badge({ value }: { value: any }) {
  const text = jsonText(value)
  const color = ["PASS", "VERIFIED", "true", "READY"].includes(text)
    ? "bg-green-50 text-green-700"
    : ["FAIL", "FAILED", "false", "CLEANUP_FAILED"].includes(text)
      ? "bg-red-50 text-red-700"
      : "bg-slate-100 text-slate-700"
  return (
    <span className={`inline-block px-2 py-1 rounded text-xs ${color}`}>
      {text}
    </span>
  )
}
export function Feedback() {
  const { state } = useLive()
  return (
    <>
      {state.busy && (
        <p role="status" className="p-3 bg-teal-50 text-teal-800 rounded">
          {state.busy}…
        </p>
      )}
      {state.error && (
        <p
          role="alert"
          className="p-3 bg-red-50 text-red-800 rounded whitespace-pre-wrap break-words"
        >
          {state.error}
        </p>
      )}
    </>
  )
}
export function Results({
  assessment,
  after,
  label = "Original assessment",
  afterLabel = "After sandbox fix",
}: {
  assessment: any
  after?: any
  label?: string
  afterLabel?: string
}) {
  const rows = findings(assessment)
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-left text-sm">
        <thead>
          <tr>
            <th className="p-2">Control</th>
            <th className="p-2">{label}</th>
            {after && <th className="p-2">{afterLabel}</th>}
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r.id} className="border-t border-slate-100">
              <td className="p-2">
                {r.title || r.id}
                <small className="block text-slate-500">{r.id}</small>
              </td>
              <td className="p-2">
                <Badge value={r.status} />
              </td>
              {after && (
                <td className="p-2">
                  <Badge value={after[r.id]} />
                </td>
              )}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
export function LiveHome() {
  const live = useLive()
  const { dispatch, setWorkflowStep } = useWorkflow()
  return (
    <div className="p-6 max-w-4xl mx-auto space-y-5">
      <h1 className="text-2xl font-semibold">
        Your database hardening workspace
      </h1>
      <p className="text-slate-500">
        Collect evidence, test a fix safely, and give the DBA a reviewable
        result.
      </p>
      <Feedback />
      <Card title="Start with a real disposable demo">
        <p>
          This uses a fresh PostgreSQL source, the repository's collector and
          assessor, and disposable sandbox containers. Approval records are
          DEMO_FIXTURE_ONLY.
        </p>
        <button
          className={button}
          disabled={!!live.state.busy || !!live.state.chatJob}
          onClick={async () => {
            await live.loadDemo()
            dispatch({ type: "SET_VIEW", view: "workflows" })
            setWorkflowStep(4)
          }}
        >
          Load live demo
        </button>
      </Card>
      {live.state.snapshot && (
        <Card title="Current workflow">
          <p>{live.state.snapshot.snapshot_id}</p>
          <button
            className={button}
            onClick={() => dispatch({ type: "SET_VIEW", view: "workflows" })}
          >
            Resume workflow
          </button>
        </Card>
      )}
      <Card title="Use your own collector snapshot">
        <p>
          Switch to the Main API in Settings, then import a snapshot. Sandbox
          preparation requires reviewed template and evidence versions.
        </p>
        <button
          className={button}
          onClick={() => dispatch({ type: "SET_VIEW", view: "settings" })}
        >
          Open connections
        </button>
      </Card>
    </div>
  )
}
export function LiveWorkflow() {
  const live = useLive()
  const { state: s, patch } = live
  const { state: ui, setWorkflowStep } = useWorkflow()
  const step = ui.activeWorkflowStep
  const [id, setId] = useState("")
  const steps = [
    "Benchmark",
    "Collect",
    "Snapshot",
    "Assessment",
    "Sandbox test",
    "DBA review",
    "Verify target",
  ]
  const busy = !!s.busy || !!s.chatJob
  const done = [
    !!s.assessment,
    false,
    !!s.snapshot,
    !!s.assessment,
    !!s.result,
    !!s.result?.review_bundle,
    s.verification?.matched === true,
  ]
  return (
    <div>
      <nav
        aria-label="Workflow stages"
        className="flex flex-wrap gap-2 p-4 border-b bg-white"
      >
        {steps.map((label, i) => (
          <button
            key={label}
            className={`px-3 py-2 text-xs rounded-lg ${
              step === i + 1 ? "bg-teal-700 text-white" : "bg-slate-50"
            }`}
            onClick={() => setWorkflowStep(i + 1)}
          >
            {i + 1}. {label}
            {done[i] ? " •" : ""}
          </button>
        ))}
      </nav>
      <div className="p-6 max-w-5xl mx-auto space-y-5">
        <div className="flex justify-between gap-4">
          <div>
            <p className="text-xs text-teal-700 uppercase tracking-widest">
              Live · {s.service === "demo" ? "Disposable demo" : "Main API"}
            </p>
            <h1 className="text-2xl font-semibold mt-1">
              {step}. {steps[step - 1]}
            </h1>
            <p className="text-sm text-slate-500 break-all">
              {s.snapshot
                ? `${s.snapshot.target_id} · ${s.snapshot.snapshot_id}`
                : "No snapshot selected"}
            </p>
          </div>
          <button
            className="text-teal-700 text-xs"
            disabled={busy}
            onClick={() => {
              live.reset()
              setWorkflowStep(1)
            }}
          >
            New workflow
          </button>
        </div>
        {s.service === "demo" && (
          <p className="p-3 bg-amber-50 text-amber-800 text-xs rounded-lg">
            Real database execution · disposable source only · DEMO_FIXTURE_ONLY
            approvals · source changes require separate DBA action.
          </p>
        )}
        <Feedback />
        {step === 1 && (
          <Card title="Installed benchmark">
            <label className="block text-sm">
              Benchmark ID
              <input
                className={input}
                value={s.benchmark}
                disabled={busy || s.service === "demo"}
                onChange={(e) => live.configure({ benchmark: e.target.value })}
              />
            </label>
            <p>
              The six installed sample specs are resolved by the backend during
              assessment. Workbook knowledge ingestion is available in Library;
              automatic workbook-to-spec generation has no endpoint in this
              backend.
            </p>
            {s.assessment?.specs && (
              <Raw value={s.assessment.specs} label="Exact returned specs" />
            )}
            <button className={button} onClick={() => setWorkflowStep(2)}>
              Continue to collection
            </button>
          </Card>
        )}
        {step === 2 && (
          <Card title="Collect from the target">
            <p>
              Run the repository collector locally with your target connection
              configured. Do not use DBGuard's pgvector database as the target.
            </p>
            <pre className="overflow-auto p-3 bg-slate-900 text-slate-100 text-xs rounded">
              {
                "python scripts/build_check_manifest.py --specs catalog/specs/cis-pg17-v1.1.0 --out checks.json\nbash collector/dbguard-collect.sh -m checks.json -t dev-pg17 -o snapshot.json"
              }
            </pre>
            <p className="text-sm">
              The live demo collects its own disposable source when it starts.
            </p>
            <button className={button} disabled={busy} onClick={live.loadDemo}>
              Load collected demo
            </button>
            <button
              className="ml-3 text-teal-700"
              onClick={() => setWorkflowStep(3)}
            >
              I have a snapshot →
            </button>
          </Card>
        )}
        {step === 3 && (
          <Card title="Import snapshot">
            {s.service === "demo" ? (
              <>
                <p>
                  The demo accepts only its own source. Load it here, or choose
                  Main API in Settings to upload another target.
                </p>
                <button
                  className={button}
                  disabled={busy}
                  onClick={live.loadDemo}
                >
                  Load demo snapshot
                </button>
              </>
            ) : (
              <>
                <label className="block">
                  Snapshot JSON
                  <input
                    aria-label="Import snapshot JSON"
                    type="file"
                    accept=".json"
                    disabled={busy}
                    className="block mt-2"
                    onChange={(e) => {
                      if (e.target.files?.[0])
                        void live.upload(e.target.files[0])
                    }}
                  />
                </label>
              </>
            )}
            <div className="flex gap-2">
              <input
                className={input}
                aria-label="Existing snapshot ID"
                placeholder="Existing snapshot ID"
                value={id}
                onChange={(e) => setId(e.target.value)}
              />
              <button
                className={button}
                disabled={busy || !id}
                onClick={() => live.loadSnapshot(id)}
              >
                Load
              </button>
            </div>
            {s.snapshot && (
              <>
                <Raw value={s.snapshot} />
                <button className={button} onClick={() => setWorkflowStep(4)}>
                  Continue to assessment
                </button>
              </>
            )}
          </Card>
        )}
        {step === 4 && (
          <Card title="Assessment from the actual API">
            <button
              className={button}
              disabled={busy || !s.snapshot}
              onClick={live.assess}
            >
              Assess snapshot
            </button>
            {!s.snapshot && <p>Load a snapshot in step 3 first.</p>}
            {s.assessment && (
              <>
                <Results assessment={s.assessment} />
                <Raw value={s.assessment} />
                <p className="text-sm text-slate-500">
                  This milestone supports the connection-logging fix (3.1.20).
                  Other findings remain visible.
                </p>
                <button
                  className={button}
                  disabled={
                    !findings(s.assessment).some(
                      (r) =>
                        (String(r.id).endsWith(":3.1.20") ||
                          r.id === "3.1.20") &&
                        r.status === "FAIL",
                    )
                  }
                  onClick={() => setWorkflowStep(5)}
                >
                  Test connection-logging fix
                </button>
              </>
            )}
          </Card>
        )}
        {step === 5 && (
          <>
            <Card title="Reviewed fix references">
              <label className="block text-sm">
                Environment
                <input
                  className={input}
                  value={s.environment}
                  disabled={busy || s.service === "demo"}
                  onChange={(e) =>
                    live.configure({ environment: e.target.value })
                  }
                />
              </label>
              <label className="block text-sm">
                set_config_parameter template version
                <input
                  type="number"
                  min="1"
                  className={input}
                  value={s.templateVersion}
                  disabled={busy || s.service === "demo"}
                  onChange={(e) =>
                    live.configure({ templateVersion: Number(e.target.value) })
                  }
                />
              </label>
              <label className="block text-sm">
                Evidence document IDs (comma separated)
                <input
                  className={input}
                  value={s.evidenceIds}
                  disabled={busy || s.service === "demo"}
                  onChange={(e) =>
                    live.configure({ evidenceIds: e.target.value })
                  }
                />
              </label>
              <label className="block text-sm">
                Retry policy
                <select
                  className={input}
                  disabled={busy || !!s.handoffId}
                  value={s.retryMode}
                  onChange={(e) => patch({ retryMode: e.target.value })}
                >
                  <option value="adaptive">LLM review after failure</option>
                  <option value="repeat">Repeat approved candidate</option>
                </select>
              </label>
              <p className="text-xs text-slate-500">
                Maximum three attempts. Each test uses a fresh baseline.
                Adaptive execution is limited to approved candidates; a
                first-attempt success does not invoke the reviewer.
              </p>
              <button
                className={button}
                disabled={busy || !s.assessment || !s.evidenceIds.trim()}
                onClick={live.run}
              >
                {s.handoffId
                  ? "Retrieve / resume same handoff"
                  : "Run sandbox test"}
              </button>
              <button
                className="ml-3 text-teal-700"
                disabled={!!s.busy}
                onClick={() =>
                  live.action("Refreshing recorded result", live.sync)
                }
              >
                Refresh result
              </button>
              {s.handoffId && (
                <p className="text-xs break-all">Handoff: {s.handoffId}</p>
              )}
            </Card>
            {s.result && <RunResult />}
          </>
        )}
        {step === 6 &&
          (s.result ? (
            <>
              <RunResult />
              <Card title="DBA handoff">
                <p>
                  The DBA reviews and runs harden.sh separately. Downloading the
                  bundle does not apply anything.
                </p>
                {bundlePath(s.service, s.result) ? (
                  <a
                    className={`${button} inline-block`}
                    href={bundlePath(s.service, s.result)}
                    download
                  >
                    Download DBA review bundle
                  </a>
                ) : (
                  <p>No bundle is available for this result.</p>
                )}
                <button
                  className="ml-3 text-teal-700"
                  onClick={() => setWorkflowStep(7)}
                >
                  Continue to target verification →
                </button>
              </Card>
            </>
          ) : (
            <Card title="No recorded result">
              <p>Run a sandbox test in step 5 first.</p>
            </Card>
          ))}
        {step === 7 && <Verification />}
      </div>
    </div>
  )
}
export function RunResult() {
  const { state: s } = useLive()
  const r = s.result
  return (
    <Card title="Recorded sandbox result">
      <div className="flex gap-3 items-center">
        <Badge value={r.status} />
        <span className="text-xs break-all">Run: {r.run_id}</span>
      </div>
      {s.assessment && (
        <Results
          assessment={s.assessment}
          after={
            r.sandbox_after_findings ??
            Object.fromEntries(
              findings(r.attempts?.at(-1)?.after_assessment).map((f) => [
                f.id,
                f.status,
              ]),
            )
          }
        />
      )}
      <p className="text-xs">
        A verified fix does not mean every control passes. Rollback checks the
        prior value and configuration source inside the disposable sandbox.
      </p>
      {(r.attempts ?? []).map((a: any) => (
        <div className="rounded border p-3 space-y-2" key={a.attempt}>
          <p>
            Attempt {a.attempt} · <Badge value={a.status} />
          </p>
          <div className="flex gap-3 text-xs flex-wrap">
            <span>
              Rollback: <Badge value={a.rollback_verified} />
            </span>
            <span>
              Health after fix: <Badge value={a.health_after_apply} />
            </span>
            <span>
              Health after rollback: <Badge value={a.health_after_rollback} />
            </span>
            <span>
              Cleanup:{" "}
              <Badge
                value={a.cleanup?.verified ?? a.cleanup?.status ?? a.cleanup}
              />
            </span>
          </div>
          <Raw value={a} />
        </div>
      ))}
      {r.demo_evidence && (
        <p className="text-sm">
          Source unchanged: <Badge value={r.demo_evidence.source_unchanged} />{" "}
          Registry unchanged:{" "}
          <Badge value={r.demo_evidence.registry_unchanged} />
        </p>
      )}
      <p className="text-xs text-slate-500">
        LLM review records: {(r.revisions ?? []).length}. The reviewer is
        invoked after a failed attempt; first-attempt success needs no revision.
      </p>
      <Raw value={r} label="Complete returned run evidence" />
    </Card>
  )
}
function Verification() {
  const live = useLive()
  const s = live.state
  const [snapshot, setSnapshot] = useState<any>(null)
  const [assessment, setAssessment] = useState<any>(null)
  const [source, setSource] = useState<any>(null)
  const matching =
    sameTarget(s.snapshot, snapshot) &&
    isFreshSnapshot(s.snapshot, snapshot) &&
    !!s.assessment?.assessment?.spec_set_hash &&
    s.assessment.assessment.spec_set_hash ===
      assessment?.assessment?.spec_set_hash
  return (
    <Card title="Verify the actual target">
      <p>
        After the DBA applies the reviewed fix, collect a fresh snapshot and
        assess it. The application never applies changes to the source.
      </p>
      {s.service === "demo" ? (
        <>
          <button
            className={button}
            disabled={!!s.busy}
            onClick={() =>
              live.action("Recollecting disposable source", async () =>
                setSource(await api("demo", "/demo/source")),
              )
            }
          >
            Recollect unchanged demo source
          </button>
          {source && (
            <>
              <p>
                Source unchanged: <Badge value={source.source_unchanged} />
              </p>
              <Raw value={source} label="Fresh source assessment" />
            </>
          )}
          <p className="text-xs text-slate-500">
            The source is expected to still fail connection logging because the
            fix was tested only in the sandbox. Use Main API for a separate
            post-DBA snapshot.
          </p>
        </>
      ) : (
        <>
          <input
            type="file"
            aria-label="Fresh target snapshot"
            accept=".json"
            disabled={!!s.busy}
            onChange={(e) => {
              const f = e.target.files?.[0]
              if (f)
                void live.action("Importing fresh target", async () => {
                  setSnapshot(null)
                  setAssessment(null)
                  live.patch({ verification: null })
                  const receipt = await api(
                    "main",
                    "/api/v1/snapshots",
                    JSON.parse(await f.text()),
                  )
                  setSnapshot(
                    await api(
                      "main",
                      `/api/v1/snapshots/${receipt.snapshot_id}`,
                    ),
                  )
                })
            }}
          />
          <button
            className={button}
            disabled={!snapshot || !!s.busy}
            onClick={() =>
              live.action("Reassessing fresh target", async () => {
                const a = await api(
                  "main",
                  `/api/v1/snapshots/${snapshot.snapshot_id}/spec-assessment?benchmark_id=${encodeURIComponent(s.benchmark)}`,
                )
                setAssessment(a)
                live.patch({
                  verification: {
                    snapshot,
                    assessment: a,
                    matched:
                      sameTarget(s.snapshot, snapshot) &&
    isFreshSnapshot(s.snapshot, snapshot) &&
                      !!s.assessment?.assessment?.spec_set_hash &&
                      s.assessment.assessment.spec_set_hash ===
                        a.assessment?.spec_set_hash,
                  },
                })
              })
            }
          >
            Assess fresh target
          </button>
          {assessment && (
            <>
              <p>
                {matching
                  ? "Newer collection from the same target and exact spec set confirmed."
                  : "Comparison not verified: target/spec identity must match and collection must be newer."}
              </p>
              {matching ? <Results assessment={s.assessment} after={Object.fromEntries(findings(assessment).map(f=>[f.id,f.status]))} afterLabel="Fresh target assessment"/> : <Results assessment={assessment} label="Uploaded target assessment (unmatched)"/>}
              <Raw value={{ snapshot, assessment }} />
            </>
          )}
        </>
      )}
    </Card>
  )
}
export function LiveChat({ onClose }: { onClose?: () => void }) {
  const live = useLive()
  const { state: s } = live
  const [text, setText] = useState("")
  return (
    <aside className="h-full flex flex-col bg-white border-l">
      <div className="p-4 border-b flex justify-between">
        <strong>HERMES · Live</strong>
        <button onClick={onClose} aria-label="Close chat">
          ×
        </button>
      </div>
      <div className="p-3 text-xs border-b text-slate-500 break-all">
        {s.snapshot?.snapshot_id || "Load a workflow snapshot first"}
        <br />
        {s.benchmark}
        <br />
        {s.result?.run_id && `Recorded run: ${s.result.run_id}`}
      </div>
      <div className="flex-1 overflow-auto p-3 space-y-3">
        {!s.messages.length && (
          <p className="text-sm text-slate-500">
            Ask HERMES to explain the assessment or explicitly request a
            disposable sandbox test. Results appear in the same workflow.
          </p>
        )}
        {s.messages.map((m, i) => (
          <div
            key={i}
            className={`p-3 rounded-lg text-sm whitespace-pre-wrap break-words ${
              m.role === "user" ? "bg-teal-50" : "bg-slate-50"
            }`}
          >
            <p className="font-semibold text-xs mb-1">
              {m.role === "user" ? "You" : "HERMES"}
            </p>
            {m.content}
          </div>
        ))}
        {s.chatJob && (
          <p role="status" className="text-teal-700">
            HERMES is using the live agent. This can take a few minutes…
          </p>
        )}
        {s.error && (
          <p role="alert" className="text-red-700 text-xs break-words">
            {s.error}
          </p>
        )}
        {s.result && (
          <p className="text-xs text-teal-800">
            Backend record: {s.result.status} · {s.result.run_id}
          </p>
        )}
        {bundlePath(s.service, s.result) && (
          <a
            className="text-teal-700 underline"
            href={bundlePath(s.service, s.result)}
          >
            Download recorded bundle
          </a>
        )}
      </div>
      <div className="p-3 space-y-2 border-t">
        <button
          className="text-xs text-teal-700"
          disabled={!!s.chatJob || !!s.busy || !s.snapshot}
          onClick={() =>
            live.send(
              `Assess snapshot ${s.snapshot.snapshot_id} for ${s.benchmark} using get_snapshot_spec_assessment. Use actual API results. Do not apply changes.`,
            )
          }
        >
          Assess current snapshot
        </button>
        <button
          className="block text-xs text-teal-700"
          disabled={!!s.chatJob || !!s.busy || !s.snapshot}
          onClick={() =>
            live.send(
              `Run a new disposable sandbox test for log_connections on snapshot ${s.snapshot.snapshot_id}, benchmark ${s.benchmark}, environment ${s.environment}. Discover the connected demo references if applicable, prepare the handoff and call run_sandbox_handoff. Show the real run ID and bundle. Do not modify the source.`,
            )
          }
        >
          Run disposable sandbox through HERMES
        </button>
        <form
          onSubmit={(e) => {
            e.preventDefault()
            if (text.trim()) {
              void live.send(text)
              setText("")
            }
          }}
        >
          <textarea
            className={input}
            aria-label="Message HERMES"
            value={text}
            onChange={(e) => setText(e.target.value)}
            placeholder="Ask HERMES…"
          />
          <button
            className={`${button} mt-2`}
            disabled={!text.trim() || !!s.chatJob || !!s.busy}
          >
            Send
          </button>
        </form>
      </div>
    </aside>
  )
}
export function LiveSettings() {
  const live = useLive()
  const [status, setStatus] = useState<any>(null)
  return (
    <div className="p-6 max-w-4xl mx-auto space-y-4">
      <h1 className="text-xl font-semibold">Connections</h1>
      <Feedback />
      <Card title="Workflow backend">
        <select
          aria-label="Workflow backend"
          className={input}
          disabled={!!live.state.busy || !!live.state.chatJob}
          value={live.state.service}
          onChange={(e) => live.reset(e.target.value as "demo" | "main")}
        >
          <option value="demo">
            Live disposable demo — shared with HERMES
          </option>
          <option value="main">
            Main API — uploaded snapshots and reviewed registry
          </option>
        </select>
        <p>
          Changing backend starts an empty workflow. HERMES must point to the
          same backend through MCP.
        </p>
        <button
          className={button}
          onClick={() =>
            live.action("Checking connections", async () =>
              setStatus(await request("/bridge/status")),
            )
          }
        >
          Check live connections
        </button>
        {status && (
          <>
            {Object.entries(status.services).map(
              ([name, info]: [string, any]) => (
                <p key={name}>
                  {name}:{" "}
                  <Badge value={info.available ? "READY" : "UNAVAILABLE"} />
                </p>
              ),
            )}
            <Raw value={status} />
          </>
        )}
      </Card>
      <Card title="Local gateway">
        <p>
          Provider keys stay on the local server. Configure DBGUARD_API_URL,
          DBGUARD_DEMO_URL and HERMES_API_URL in the gateway environment.
          HERMES_WORKFLOW_BACKEND must match the MCP target.
        </p>
        <p className="text-xs">
          Library tools use Main API. The demo registry is intentionally
          separate and is never edited from Library.
        </p>
      </Card>
    </div>
  )
}
