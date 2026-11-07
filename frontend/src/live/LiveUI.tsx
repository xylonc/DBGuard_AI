import { FileButton } from "./FileButton"
import { EvidenceShots } from "./EvidenceShots"
import { BenchmarkImport } from "./BenchmarkImport"
import {
  CombinedResult,
  CombinedReview,
  FixPlan,
  RunHistory,
  currentBatch,
} from "./ReviewPanel"
import { EndpointPanel } from "./EndpointPanel"
import {
  PolicyMissingBanner,
  PolicyProfileScreen,
  PolicyProfileSelector,
} from "./PolicyProfile"
import {
  POLICY_MISSING_LABEL,
  explainRow,
  isPolicyMissing,
  policyMissingRows,
  settingEvidence,
  statusKind,
  statusLabel,
} from "./explanations"
import { CatalogEvidence } from "./Evidence"
import { snapshotSummary } from "./snapshotSummary"
import {
  anyBundleReady,
  bundleState,
  combinedResultTitle,
  singleFixName,
  singleResultTitle,
  titlesBySpec,
} from "./resultLabels"
import {
  changeDirection,
  runAfter,
  runRegressions,
  statusChanges,
  type Direction,
} from "./sandboxChanges"
import { useEffect, useState, type ReactNode } from "react"
import { activeObjectFix, assessmentPath, useLive } from "@/store/liveStore"
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
  subtitle,
  // One line saying what this card is for.
}: {
  children: ReactNode
  title?: string
  subtitle?: string
}) {
  return (
    <section className="bg-white rounded-xl border border-slate-200 p-5 space-y-3">
      {title && (
        <div className="space-y-1">
          <h2 className="font-semibold text-slate-800">{title}</h2>
          {subtitle && <p className="text-sm text-slate-500">{subtitle}</p>}
        </div>
      )}
      {children}
    </section>
  )
}

function DemoTag() {
  return (
    <span className="rounded bg-amber-50 border border-amber-200 px-2 py-0.5 text-xs text-amber-900">
      Demo approval only (DEMO_FIXTURE_ONLY)
    </span>
  )
}

// A collapsible group with a clear title, an optional count and a one-line hint.
export function Fold({
  title,
  count,
  hint,
  open = false,
  tone = "slate",
  children,
}: {
  title: string
  count?: number
  hint?: string
  open?: boolean
  tone?: "slate" | "amber" | "sky" | "teal"
  children: ReactNode
}) {
  const border = {
    slate: "border-slate-200",
    amber: "border-amber-300",
    sky: "border-sky-200",
    teal: "border-teal-200",
  }[tone]
  return (
    <details className={`rounded-lg border ${border}`} open={open}>
      <summary className="cursor-pointer list-none px-4 py-3 flex items-start gap-2 [&::-webkit-details-marker]:hidden">
        {/* Rotates only when its own <details> is open, not a parent's. */}
        <span
          aria-hidden="true"
          className="mt-0.5 text-slate-400 transition-transform [[open]>summary>&]:rotate-90"
        >
          ▶
        </span>
        <span className="flex-1">
          <span className="font-medium">
            {title}
            {typeof count === "number" && (
              <span className="ml-2 rounded-full bg-slate-100 px-2 text-xs text-slate-600">
                {count}
              </span>
            )}
          </span>
          {hint && <span className="block text-xs text-slate-500">{hint}</span>}
        </span>
      </summary>
      <div className="px-4 pb-4 space-y-3">{children}</div>
    </details>
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
// Assessment status. NOT_APPLICABLE has its own badge; every status DBGuard could not
// decide (GAPPED, NOT_COLLECTED, STALE, ERROR, or anything unrecognised) is shown as
// "Unknown: needs human review", never as passing.
export function FindingBadge({ value }: { value: any }) {
  const status =
    value && typeof value === "object" ? value.status : (value ?? undefined)
  if (status === undefined || status === null) return <Badge value={status} />
  const kind = statusKind(status)
  const color =
    kind === "pass"
      ? "bg-green-50 text-green-700"
      : kind === "fail"
        ? "bg-red-50 text-red-700"
        : kind === "not_applicable"
          ? "bg-sky-50 text-sky-800 border border-sky-200"
          : kind === "unknown"
            ? "bg-amber-100 text-amber-900 border border-amber-300"
            : "bg-slate-100 text-slate-700"
  return (
    <span className={`inline-block px-2 py-1 rounded text-xs ${color}`}>
      {statusLabel(status)}
      {kind === "unknown" && (
        <small className="block opacity-75">{jsonText(status)}</small>
      )}
    </span>
  )
}
export function PolicyMissingFlag() {
  return (
    <span className="inline-block mt-1 px-2 py-1 rounded text-xs font-bold tracking-wide bg-red-600 text-white">
      {POLICY_MISSING_LABEL}
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
// "Found / CIS expects" for a setting rule, from the authoritative report row.
function SettingEvidenceLine({
  row,
  original,
}: {
  row: any
  original?: boolean
}) {
  const ev = settingEvidence(row)
  if (!ev) return null
  return (
    <dl className="mt-1 text-xs text-slate-600 bg-slate-50 rounded px-2 py-1 space-y-0.5 break-words">
      <div>
        <dt className="inline font-semibold">
          {original ? "Found (original snapshot): " : "Found: "}
        </dt>
        <dd className="inline">{ev.found}</dd>
      </div>
      {ev.expects && (
        <div>
          <dt className="inline font-semibold">{ev.source} expects: </dt>
          <dd className="inline">{ev.expects}</dd>
        </div>
      )}
    </dl>
  )
}

// Step 3: what the loaded snapshot contains, before the raw data.
function SnapshotSummaryCard({ snapshot }: { snapshot: any }) {
  const summary = snapshotSummary(snapshot)
  if (!summary) return null
  return (
    <div className="rounded-lg border border-slate-200 p-3 space-y-2">
      <p className="text-sm font-semibold">What this snapshot contains</p>
      <dl className="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
        {summary.lines.map((l) => (
          <div key={l.label} className="contents">
            <dt className="text-slate-500">{l.label}</dt>
            <dd className="break-all">{l.value}</dd>
          </div>
        ))}
      </dl>
      {(summary.gaps.length > 0 ||
        summary.unavailable.length > 0 ||
        summary.malformedGaps > 0) && (
        <div className="rounded bg-amber-50 p-2 text-xs text-amber-900 space-y-1">
          <p className="font-semibold">
            Not collected: rules that need this evidence can't say PASS.
          </p>
          <ul className="list-disc pl-4">
            {summary.unavailable.map((s) => (
              <li key={`u-${s}`}>{s}</li>
            ))}
            {summary.gaps.map((g, i) => (
              <li key={`g-${i}`}>
                {g.section}: {g.reason}
              </li>
            ))}
            {summary.malformedGaps > 0 && (
              <li>
                {summary.malformedGaps} gap record(s) could not be read; treat
                that evidence as not collected.
              </li>
            )}
          </ul>
        </div>
      )}
      <p className="text-xs text-slate-500">
        The assessment in step 4 reads this evidence rule by rule.
      </p>
    </div>
  )
}

const CHANGE_ROW: Record<Direction, string> = {
  better: "bg-green-50/60",
  worse: "bg-red-50/70",
  changed: "bg-amber-50/60",
}
const CHANGE_TAG: Record<Direction, [string, string]> = {
  better: ["▲ Improved", "text-green-800"],
  worse: ["▼ Got worse", "text-red-800"],
  changed: ["● Changed", "text-amber-900"],
}
function ChangeTag({ direction }: { direction: Direction }) {
  const [label, color] = CHANGE_TAG[direction]
  return (
    <span className={`block mt-1 text-xs font-semibold ${color}`}>{label}</span>
  )
}

// After a sandbox run: the checks whose status changed, then every check in a
// collapsed list. `after` maps spec id to the sandbox status after the fix.
// `regressions`: ids the sandbox recorded as regressions (always shown as worse).
// `notice`: shown first in red, e.g. when the test did not verify.
export function SandboxChanges({
  assessment,
  after,
  regressions = [],
  notice,
  afterLabel = "After sandbox fix",
}: {
  assessment: any
  after: Record<string, any>
  regressions?: string[]
  notice?: string
  afterLabel?: string
}) {
  const rows = findings(assessment)
  const { changes, unchanged, notRechecked } = statusChanges(
    rows,
    after,
    regressions,
  )
  const better = changes.filter((c) => c.direction === "better").length
  const worse = changes.filter((c) => c.direction === "worse").length
  return (
    <div className="space-y-3">
      <div className="rounded-lg border border-slate-200 p-3 space-y-2">
        <p className="font-semibold text-sm">What changed in the sandbox</p>
        {notice && (
          <p className="rounded bg-red-50 border border-red-200 px-2 py-1 text-sm text-red-900">
            {notice}
          </p>
        )}
        <p className="text-sm">
          {changes.length === 0
            ? "No check changed status."
            : `${changes.length} check${
                changes.length === 1 ? "" : "s"
              } changed: ${better} improved, ${worse} got worse.`}{" "}
          {unchanged} unchanged.
          {notRechecked > 0 &&
            ` ${notRechecked} not re-checked in the sandbox: the throwaway copy doesn't hold your real accounts, permissions and connections, so those rules are only judged on the real database.`}
        </p>
        {changes.length > 0 && (
          <ul className="space-y-1">
            {changes.map((c) => (
              <li
                key={c.id}
                className={`flex flex-wrap items-center gap-2 rounded px-2 py-1 text-sm border-l-4 ${
                  c.direction === "better"
                    ? "border-green-500 bg-green-50"
                    : c.direction === "worse"
                      ? "border-red-500 bg-red-50"
                      : "border-amber-500 bg-amber-50"
                }`}
              >
                <span className="flex-1 min-w-[12rem]">
                  {c.title}
                  <small className="block text-slate-500">{c.id}</small>
                </span>
                <FindingBadge value={c.before} />
                <span aria-hidden="true">→</span>
                <span className="sr-only">changed to</span>
                {c.after === null ? (
                  <span className="text-xs font-semibold text-red-800">
                    Got worse (recorded by the sandbox)
                  </span>
                ) : (
                  <FindingBadge value={c.after} />
                )}
              </li>
            ))}
          </ul>
        )}
      </div>
      <details className="rounded-lg border border-slate-200">
        <summary className="cursor-pointer px-3 py-2 text-sm text-teal-700">
          Show all {rows.length} checks, before and after (changes highlighted)
        </summary>
        <div className="px-1 pb-2">
          <Results
            assessment={assessment}
            after={after}
            regressions={regressions}
            afterLabel={afterLabel}
          />
        </div>
      </details>
    </div>
  )
}

export function Results({
  assessment,
  after,
  regressions = [],
  label = "Original assessment",
  afterLabel = "After sandbox fix",
}: {
  assessment: any
  after?: any
  regressions?: string[]
  label?: string
  afterLabel?: string
}) {
  const rows = findings(assessment)
  const has = (id: string) =>
    !!after && Object.prototype.hasOwnProperty.call(after, id)
  const directionOf = (r: any): Direction | null => {
    if (regressions.includes(r.id)) return "worse"
    if (!has(r.id)) return null
    const now = after[r.id]
    const nowStatus = now && typeof now === "object" ? now.status : now
    return statusKind(r.status) === statusKind(nowStatus)
      ? null
      : changeDirection(r.status, nowStatus)
  }
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
          {rows.map((r) => {
            const why = explainRow(r)
            const moved = directionOf(r)
            return (
              <tr
                key={r.id}
                className={`border-t border-slate-100 align-top ${
                  moved ? CHANGE_ROW[moved] : ""
                }`}
              >
                <td className="p-2">
                  {r.title || r.id}
                  <small className="block text-slate-500">{r.id}</small>
                  {why && (
                    <div
                      className={`mt-2 rounded-lg p-2 text-xs space-y-1 ${
                        why.policyMissing
                          ? "bg-red-50 text-red-900"
                          : why.unknown
                            ? "bg-amber-50 text-amber-900"
                            : "bg-sky-50 text-sky-900"
                      }`}
                    >
                      <p className="font-semibold">{why.cis}</p>
                      <p>{why.sentence}</p>
                      {why.quote && (
                        <p className="italic opacity-80">CIS: “{why.quote}”</p>
                      )}
                    </div>
                  )}
                  <SettingEvidenceLine row={r} original={!!after} />
                  <CatalogEvidence row={r} />
                </td>
                <td className="p-2">
                  <FindingBadge value={r.status} />
                  {isPolicyMissing(r) && <PolicyMissingFlag />}
                </td>
                {after && (
                  <td className="p-2">
                    {has(r.id) ? (
                      <>
                        <FindingBadge value={after[r.id]} />
                        {moved && <ChangeTag direction={moved} />}
                      </>
                    ) : regressions.includes(r.id) ? (
                      <span className="text-xs font-semibold text-red-800">
                        ▼ Got worse (recorded by the sandbox)
                      </span>
                    ) : (
                      <span className="text-xs text-slate-500">
                        Not re-checked here
                      </span>
                    )}
                  </td>
                )}
              </tr>
            )
          })}
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
  // The Policy Profile screen opens inside step 4 (Assessment).
  const [policyOpen, setPolicyOpen] = useState(false)
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
  const objectFix = activeObjectFix(s)
  const specTitles = titlesBySpec(findings(s.assessment))
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
        {step === 1 && <BenchmarkImport />}
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
              Use the six installed sample specs, or an approved imported
              release. Workbook import creates a spec for every control and
              explicitly marks unsupported checks.
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
              {s.benchmark.includes("-import-")
                ? "# In the extracted benchmark review package\nbash dbguard-collect.sh -m checks.json -t dev-pg17 -o snapshot.json"
                : "python scripts/build_check_manifest.py --specs catalog/specs/cis-pg17-v1.1.0 --out checks.json\nbash collector/dbguard-collect.sh -m checks.json -t dev-pg17 -o snapshot.json"}
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
                <div className="space-y-1">
                  <p className="text-sm">Snapshot JSON from the collector</p>
                  <FileButton
                    label="Choose snapshot file (.json)"
                    aria-label="Import snapshot JSON"
                    accept=".json"
                    disabled={busy}
                    onChange={(e) => {
                      if (e.target.files?.[0])
                        void live.upload(e.target.files[0])
                    }}
                  />
                </div>
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
                <SnapshotSummaryCard snapshot={s.snapshot} />
                <Raw value={s.snapshot} />
                <button className={button} onClick={() => setWorkflowStep(4)}>
                  Continue to assessment
                </button>
              </>
            )}
          </Card>
        )}
        {step === 4 && policyOpen && (
          <PolicyProfileScreen onBack={() => setPolicyOpen(false)} />
        )}
        {step === 4 && !policyOpen && (
          <PolicyProfileSelector onOpen={() => setPolicyOpen(true)} />
        )}
        {step === 4 && !policyOpen && s.assessment && (
          <PolicyMissingBanner
            rows={policyMissingRows(findings(s.assessment))}
            onOpen={() => setPolicyOpen(true)}
          />
        )}
        {step === 4 && !policyOpen && (
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
                  Supported setting fixes appear in the next step. Controls
                  needing manual review remain visible.
                </p>
                <button
                  className={button}
                  disabled={
                    !findings(s.assessment).some((r) => r.status === "FAIL")
                  }
                  onClick={() => setWorkflowStep(5)}
                >
                  Review available fixes
                </button>
              </>
            )}
          </Card>
        )}
        {step === 5 && (
          <>
            <FixPlan
              onOpenPolicy={() => {
                setPolicyOpen(true)
                setWorkflowStep(4)
              }}
              singleTest={
                <>
                  <p className="text-sm">
                    Chosen fix:{" "}
                    <strong>
                      {objectFix
                        ? objectFix.title
                        : (specTitles.get(s.controlId) ?? s.controlId)}
                    </strong>
                  </p>
                  <p className="text-xs text-slate-500">
                    To pick another, use “Test this fix on its own” in section
                    1.
                    {objectFix &&
                      " Account and permission fixes run once with their approved template, with no retries."}
                  </p>
                  <div className="flex flex-wrap gap-3 items-center">
                    <button
                      className={button}
                      disabled={busy || !s.assessment || !s.evidenceIds.trim()}
                      onClick={live.run}
                    >
                      {s.handoffId ? "Get this test's result" : "Run the test"}
                    </button>
                    <button
                      className="text-sm text-teal-700"
                      disabled={!!s.busy}
                      onClick={() =>
                        live.action("Refreshing recorded result", live.sync)
                      }
                    >
                      Refresh result
                    </button>
                  </div>
                  {!s.evidenceIds.trim() && (
                    <p className="text-xs text-amber-800">
                      Add the evidence document IDs under Advanced test settings
                      before running the test.
                    </p>
                  )}
                  <Fold
                    open={!s.evidenceIds.trim()}
                    title="Advanced test settings"
                    hint="Template versions, evidence references and retry rules. The defaults suit most tests."
                  >
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
                          live.configure({
                            templateVersion: Number(e.target.value),
                          })
                        }
                      />
                    </label>
                    <label className="block text-sm">
                      Per-object fix template version (used only when the server
                      reports no approved version)
                      <input
                        type="number"
                        min="1"
                        className={input}
                        value={s.objectTemplateVersion}
                        disabled={busy || s.service === "demo"}
                        onChange={(e) =>
                          live.configure({
                            objectTemplateVersion: Number(e.target.value),
                          })
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
                        disabled={busy || !!s.handoffId || !!objectFix}
                        value={s.retryMode}
                        onChange={(e) => patch({ retryMode: e.target.value })}
                      >
                        <option value="adaptive">
                          LLM review after failure
                        </option>
                        <option value="repeat">
                          Repeat approved candidate
                        </option>
                      </select>
                    </label>
                    <label className="block text-sm">
                      Approved alternative templates (optional: name:version,
                      comma separated)
                      <input
                        className={input}
                        value={s.alternativeTemplates}
                        disabled={
                          busy ||
                          !!s.handoffId ||
                          s.retryMode !== "adaptive" ||
                          !!objectFix
                        }
                        placeholder="set_config_parameter__alternative:1"
                        onChange={(e) =>
                          live.configure({
                            alternativeTemplates: e.target.value,
                          })
                        }
                      />
                    </label>
                    <p className="text-xs text-slate-500">
                      Up to three attempts, each on a fresh copy. Retries only
                      use approved alternatives; a fix that works first time is
                      not sent to the AI reviewer.
                    </p>
                    {s.handoffId && (
                      <p className="text-xs break-all">
                        Test reference: {s.handoffId}
                      </p>
                    )}
                  </Fold>
                </>
              }
            />
            <Card
              title="3. Results"
              subtitle="What each test changed on the throwaway copy. Changes are listed first; open the full list to see every rule before and after."
            >
              {!s.result && !currentBatch(s) && (
                <p className="text-sm text-slate-500">No test has run yet.</p>
              )}
              <CombinedResult />
              {s.result && <RunResult framed={false} />}
            </Card>
            {(s.result || currentBatch(s)) && (
              <Card title="4. Next: DBA review">
                <p className="text-sm">
                  {anyBundleReady(s.result, currentBatch(s))
                    ? "A test passed and its bundle is ready. Next, review the change, its risk and its undo, and download the bundle for the DBA."
                    : s.result?.status === "VERIFIED" ||
                        currentBatch(s)?.status === "VERIFIED"
                      ? "A test passed, but no bundle could be made for it yet; step 6 shows why. You can still review what happened."
                      : "No test has passed yet, so there is nothing to hand over. You can still review what happened."}
                </p>
                <button className={button} onClick={() => setWorkflowStep(6)}>
                  Continue to DBA review →
                </button>
              </Card>
            )}
          </>
        )}
        {step === 6 &&
          (s.result || currentBatch(s) ? (
            <>
              <CombinedReview />
              {s.result && <RunResult />}
              <Card
                title="Hand over to the DBA"
                subtitle="Download what the DBA needs. Downloading changes nothing: the DBA reviews the bundle and runs it separately."
              >
                <ul className="space-y-3">
                  {currentBatch(s) && (
                    <li className="flex flex-wrap items-center gap-3">
                      {currentBatch(s).review_bundle?.status === "READY" ? (
                        <a
                          className={`${button} inline-block`}
                          href={`/bridge/${s.service}/api/v1/sandbox/runs/${encodeURIComponent(currentBatch(s).run_id)}/bundle`}
                          download
                        >
                          Download combined bundle
                        </a>
                      ) : (
                        <span className="text-sm text-amber-800">
                          {bundleState(currentBatch(s), true).message}
                        </span>
                      )}
                      {bundleState(currentBatch(s), true).demo && <DemoTag />}
                      <span className="text-sm text-slate-600">
                        {combinedResultTitle(currentBatch(s), specTitles)}
                      </span>
                    </li>
                  )}
                  {s.result && (
                    <li className="flex flex-wrap items-center gap-3">
                      {bundlePath(s.service, s.result) ? (
                        <a
                          className={`${
                            currentBatch(s)
                              ? "rounded border border-teal-700 text-teal-700 px-4 py-2 text-sm"
                              : button
                          } inline-block`}
                          href={bundlePath(s.service, s.result)}
                          download
                        >
                          Download single-fix bundle
                        </a>
                      ) : (
                        <span className="text-sm text-amber-800">
                          {bundleState(s.result).message}
                        </span>
                      )}
                      {bundleState(s.result).demo && <DemoTag />}
                      <span className="text-sm text-slate-600">
                        {singleFixName(s.result, specTitles)}
                      </span>
                    </li>
                  )}
                </ul>
                <button
                  className="mt-2 block rounded border border-teal-700 text-teal-700 px-4 py-2 text-sm"
                  onClick={() => setWorkflowStep(7)}
                >
                  Continue to step 7: check the real database →
                </button>
              </Card>
            </>
          ) : (
            <Card title="Nothing to review yet">
              <p>Run a sandbox test in step 5 first.</p>
            </Card>
          ))}
        {step === 7 && (
          <>
            <Verification />
            <RunHistory />
          </>
        )}
      </div>
    </div>
  )
}
// One recorded single-fix test. `framed`: its own card (step 6) or a panel
// inside the step 5 results card.
export function RunResult({ framed = true }: { framed?: boolean }) {
  const { state: s } = useLive()
  const r = s.result
  const titles = titlesBySpec(findings(s.assessment))
  const title = singleResultTitle(r, titles)
  const body = (
    <>
      <div className="flex flex-wrap gap-3 items-center">
        <Badge value={r.status} />
        <span className="text-xs text-slate-500 break-all">Run {r.run_id}</span>
      </div>
      {r.kind === "object" && (
        <p className="text-sm">
          Checked on the object itself: {r.fix_unit?.verify?.predicate}
        </p>
      )}
      {s.assessment && (
        <SandboxChanges
          assessment={s.assessment}
          after={runAfter(r)}
          regressions={runRegressions(r)}
          notice={
            r.status === "VERIFIED"
              ? undefined
              : `This test did not verify (${jsonText(r.status)}). The statuses below are from its last attempt; see the test details.`
          }
        />
      )}
      <EvidenceShots evidence={r.attempts?.at(-1)?.terminal_evidence} />
      <Fold
        title="Test details"
        hint="Each attempt, its undo and clean-up, the screenshot, and the raw evidence."
      >
        <p className="text-xs text-slate-500">
          A verified fix does not mean every rule passes. The undo is checked
          too: the setting and where it came from must be back exactly as
          before.
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
            {a.functional_checks?.screenshot?.status === "CAPTURED" && (
              <img
                alt="Actual sandbox database query results after fix"
                className="w-full border rounded"
                src={
                  "data:image/png;base64," +
                  a.functional_checks.screenshot.png_base64
                }
              />
            )}
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
          invoked after a failed attempt; first-attempt success needs no
          revision.
        </p>
        {r.risk_review && (
          <Raw
            value={r.risk_review}
            label="Risk, prerequisites and functional test plan"
          />
        )}
        <Raw
          value={r.revisions ?? []}
          label="LLM retry decisions (empty means no retry review)"
        />
        <Raw value={r} label="Complete returned run evidence" />
      </Fold>
    </>
  )
  return framed ? (
    <Card
      title={title}
      subtitle="This fix was tried on its own, on a throwaway copy of your database."
    >
      {body}
    </Card>
  ) : (
    <section className="rounded-lg border border-slate-200 p-4 space-y-3">
      <h3 className="font-semibold">{title}</h3>
      <p className="text-sm text-slate-500">
        This fix was tried on its own, on a throwaway copy of your database.
      </p>
      {body}
    </section>
  )
}

function Verification() {
  const live = useLive()
  const s = live.state
  const [snapshot, setSnapshot] = useState<any>(null)
  const [assessment, setAssessment] = useState<any>(null)
  const [source, setSource] = useState<any>(null)
  // Name the controls actually tested, not a fixed example.
  const tested: string[] = [
    ...new Set<string>(
      [
        s.result?.fix_unit?.spec_id,
        ...(currentBatch(s)?.fix_units ?? []).map((u: any) => u.spec_id),
      ].filter(Boolean),
    ),
  ]
  const testedTitles = titlesBySpec(findings(s.assessment))
  const matching =
    sameTarget(s.snapshot, snapshot) &&
    isFreshSnapshot(s.snapshot, snapshot) &&
    !!s.assessment?.assessment?.spec_set_hash &&
    s.assessment.assessment.spec_set_hash ===
      assessment?.assessment?.spec_set_hash
  return (
    <Card
      title="Check the real database after the DBA's change"
      subtitle="DBGuard never changes your database itself. Once the DBA has run the bundle, collect fresh evidence and check it here: the fixed rules should now pass."
    >
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
            Check the demo database again
          </button>
          {source && (
            <>
              <p>
                Demo database unchanged by DBGuard:{" "}
                <Badge value={source.source_unchanged} />
              </p>
              <Raw value={source} label="Fresh check of the demo database" />
            </>
          )}
          <p className="text-sm text-slate-600">
            This is a demo, so no DBA has applied anything.{" "}
            {tested.length
              ? `The demo database will still fail ${tested
                  .map((id) => testedTitles.get(id) ?? id)
                  .join(
                    "; ",
                  )}. That's expected: the fixes were only tried on a throwaway copy.`
              : "It stays exactly as it was, because fixes are only tried on a throwaway copy."}
          </p>
          <p className="text-xs text-slate-500">
            To check a real database after the DBA's change, switch to Main API
            in Settings and upload the new snapshot there.
          </p>
        </>
      ) : (
        <>
          <p className="text-sm">
            1. Upload the snapshot collected after the DBA applied the fix.
          </p>
          <FileButton
            label="Choose new snapshot (.json)"
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
                // Same policy profile as the original assessment, so results compare.
                const a = await api(
                  "main",
                  assessmentPath(
                    snapshot.snapshot_id,
                    s.benchmark,
                    s.policyProfile,
                  ),
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
            2. Check it against the CIS rules
          </button>
          {assessment && (
            <>
              <p>
                {matching
                  ? "Same database, newer evidence and the same rule set: the comparison below is valid."
                  : "These results can't be compared with the original: the snapshot must come from the same database, be newer, and use the same rule set."}
              </p>
              {matching ? (
                <Results
                  assessment={s.assessment}
                  after={Object.fromEntries(
                    findings(assessment).map((f) => [f.id, f.status]),
                  )}
                  afterLabel="After the DBA's change"
                />
              ) : (
                <Results
                  assessment={assessment}
                  label="Uploaded snapshot (not comparable)"
                />
              )}
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
          Changing backend starts an empty workflow. The packaged HERMES
          connection routes its tools to the selected backend.
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
      <RunHistory />
      <details className="border rounded">
        <summary className="p-3 cursor-pointer">Advanced API tools</summary>
        <EndpointPanel />
      </details>
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
