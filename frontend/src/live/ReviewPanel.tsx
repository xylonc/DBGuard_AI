import { FileButton } from "./FileButton"
import { useEffect, useState } from "react"
import { api, request, findings } from "@/adapters/live"
import { activeObjectFix, useLive } from "@/store/liveStore"
import type { ReactNode } from "react"
import { Badge, Card, Fold, Raw, SandboxChanges } from "./LiveUI"
import { combinedResultTitle, titlesBySpec } from "./resultLabels"
import { batchAfter } from "./sandboxChanges"
import { ObjectProposals } from "./ObjectProposals"
import { EvidenceShots } from "./EvidenceShots"
import {
  MAX_BATCH,
  batchFixes,
  chooseListTemplate,
  isCatalogLinkedFix,
  listTemplateVersionFor,
  needsListTemplate,
  objectTemplateVersionFor,
  isObjectFixId,
  catalogAfterCombined,
  catalogChangeLines,
  isCatalogUnit,
  isObjectUnit,
  objectAfterCombined,
} from "./objectFixes"
import { cisRule, explanationSentence } from "./explanations"
import { profileRefQuery } from "./profileForm"
import {
  catalogChanges,
  isCatalogSettingFix,
  manualReason,
  preloadNote,
  restartNote,
} from "./fixPlan"
export { manualReason }
const button = "rounded bg-teal-700 text-white px-4 py-2 disabled:opacity-40"
type FixPlanProps = {
  // Opens the Policy Profile screen (for COMPANY POLICY MISSING notes).
  onOpenPolicy?: () => void
  // The single-fix test panel (its settings live in the workflow screen).
  singleTest?: ReactNode
}
const RISK_CHIP: Record<string, string> = {
  low: "bg-slate-100 text-slate-700",
  medium: "bg-amber-50 text-amber-800",
  high: "bg-red-50 text-red-800",
}
const outline =
  "rounded border border-teal-700 text-teal-700 px-4 py-2 disabled:opacity-40"
export function FixPlan({ onOpenPolicy, singleTest }: FixPlanProps) {
  const live = useLive(),
    s = live.state
  const [customOrder, setCustomOrder] = useState(false)
  // Selection keys: a setting fix's control id, or an object fix's fix_id.
  const [plan, setPlan] = useState<any>(null),
    [selected, setSelected] = useState<string[]>([])
  const chosenObject = activeObjectFix(s)
  const groups: any[] = Array.isArray(plan?.object_proposals)
    ? plan.object_proposals
    : []
  const proposalsById = new Map<string, any>(
    groups.flatMap((g) =>
      (g.proposals ?? []).map((p: any) => [p.fix_id, p] as [string, any]),
    ),
  )
  const toggle = (key: string, on: boolean) =>
    setSelected(on ? [...selected, key] : selected.filter((x) => x !== key))
  function selectionLabel(key: string) {
    if (isObjectFixId(key)) return proposalsById.get(key)?.title ?? key
    return (
      plan?.recommended_order.find((f: any) => f.spec_id === key)?.title ?? key
    )
  }
  // The combined result lives in the shared store so DBA review (step 6) shows it too.
  const batch = currentBatch(s)
  useEffect(() => {
    setPlan(null)
    setSelected([])
  }, [s.snapshot?.snapshot_id, s.benchmark, s.policyProfile?.profile_ref])
  // Assessment rows by spec, for the structured reasons shown below.
  const rows = new Map(findings(s.assessment).map((r: any) => [r.id, r]))
  async function load(llm = false) {
    await live.action("Reviewing proposed fixes", async () => {
      const p = await api(
        s.service,
        `/api/v1/snapshots/${s.snapshot.snapshot_id}/fix-plan?benchmark_id=${encodeURIComponent(s.benchmark)}&review_with_llm=${llm}${profileRefQuery(s.policyProfile?.profile_ref)}`,
      )
      setPlan(p)
    })
  }
  const proposalCount = groups.reduce(
    (n, g) => n + (g.proposals ?? []).length,
    0,
  )
  return (
    <>
      <Card
        title="1. Choose the fixes to test"
        subtitle="DBGuard lists the fixes it can safely try, safest first. Pick one to test on its own, or tick several to test together. The DBA still decides what is applied."
      >
        <div className="flex flex-wrap gap-2">
          <button
            className={button}
            disabled={!!s.busy || !s.assessment}
            onClick={() => void load()}
          >
            Show recommended fixes
          </button>
          <button
            className={outline}
            disabled={!!s.busy || !s.assessment}
            onClick={() => void load(true)}
          >
            Ask the AI to review the risks
          </button>
        </div>
        {!plan && (
          <p className="text-sm text-slate-500">
            Press “Show recommended fixes” to see what can be fixed.
          </p>
        )}
        {plan && (
          <>
            <p className="text-xs text-slate-500">{plan.ordering_basis}</p>
            <Fold
              title="Setting fixes"
              count={plan.recommended_order.length}
              hint="Each changes one server setting. Listed safest first."
              open
              tone="teal"
            >
              {plan.recommended_order.map((f: any, i: number) => (
                <section
                  className="rounded-lg border border-slate-200 p-3 space-y-2"
                  key={f.fix_id}
                >
                  <div className="flex flex-wrap gap-2 items-center">
                    <h3 className="font-semibold flex-1">
                      {i + 1}. {f.title}
                    </h3>
                    <span
                      className={`rounded px-2 py-0.5 text-xs ${
                        RISK_CHIP[String(f.operational_risk).toLowerCase()] ??
                        RISK_CHIP.low
                      }`}
                    >
                      {f.operational_risk} risk
                    </span>
                  </div>
                  {isCatalogSettingFix(f) ? (
                    <CatalogSettingChanges
                      fix={f}
                      listTemplateVersion={plan.list_template_version}
                    />
                  ) : (
                    <p>
                      {f.setting}:{" "}
                      <strong>
                        {f.current_value} → {f.proposed_value}
                      </strong>{" "}
                      · {f.requires}
                    </p>
                  )}
                  <p className="text-sm">{f.reasoning}</p>
                  {f.prerequisites.length > 0 && (
                    <div className="text-sm">
                      <p className="font-medium">Check before applying</p>
                      <ul className="list-disc pl-5">
                        {f.prerequisites.map((p: string) => (
                          <li key={p}>{p}</li>
                        ))}
                      </ul>
                    </div>
                  )}
                  <Fold
                    title="Undo and AI review"
                    hint="How the change is undone, where the current value comes from, and any AI comments."
                  >
                    <p className="text-sm">
                      <strong>Undo:</strong> {f.rollback_explanation}
                    </p>
                    <p className="text-sm">{f.activation_fact}</p>
                    <p className="text-sm">
                      Current value comes from: {f.prior_source}. Security
                      severity: {f.security_severity}.
                    </p>
                    <p className="text-sm">
                      AI risk review: {f.llm.status}. AI comments are advice
                      only and need DBA review; the test itself runs only
                      checked steps.
                    </p>
                    {f.llm.advice && (
                      <p className="text-sm">{f.llm.advice.reasoning}</p>
                    )}
                    <Raw
                      value={{
                        checks: f.checks,
                        unknowns: f.unknowns,
                        application_checks: f.manual_application_checks,
                        llm: f.llm,
                      }}
                      label="Functional checks, unknowns and application tests"
                    />
                  </Fold>
                  <div className="flex flex-wrap gap-4 items-center border-t pt-3">
                    {!chosenObject &&
                    (s.controlId || "cis-pg17-v1.1.0:3.1.20") === f.spec_id ? (
                      <span className="rounded bg-teal-700 text-white px-4 py-2 text-sm">
                        ✓ Chosen for the single-fix test
                      </span>
                    ) : (
                      <button
                        className={`${outline} text-sm`}
                        disabled={!!s.busy || !!s.handoffId}
                        onClick={() =>
                          live.configure({
                            controlId: f.spec_id,
                            objectFix: null,
                            // Preload fixes (3.2, 5.6) also send the approved
                            // set_config_list version; null for every other fix.
                            listTemplate: chooseListTemplate(
                              plan,
                              f.spec_id,
                              s.snapshot.snapshot_id,
                              s.policyProfile?.profile_ref ?? null,
                            ),
                            // Catalog-linked fixes run once with the approved
                            // template: no adaptive retries or alternatives.
                            ...(f.kind === "catalog_setting"
                              ? {
                                  retryMode: "repeat",
                                  alternativeTemplates: "",
                                }
                              : {}),
                          })
                        }
                      >
                        Test this fix on its own
                      </button>
                    )}
                    <label className="flex gap-2 items-center text-sm">
                      <input
                        aria-label={
                          "Include " + f.setting + " in combined test"
                        }
                        type="checkbox"
                        checked={selected.includes(f.spec_id)}
                        onChange={(e) => toggle(f.spec_id, e.target.checked)}
                      />
                      Add to the combined test
                    </label>
                  </div>
                </section>
              ))}
            </Fold>
            {groups.length > 0 && (
              <Fold
                title="Account and permission fixes"
                count={proposalCount}
                hint="Each changes one account, function or table. You choose which ones; nothing is ticked for you."
                open
                tone="teal"
              >
                <ObjectProposals
                  embedded
                  groups={groups}
                  templateVersions={plan.object_template_versions}
                  selected={selected}
                  onToggle={toggle}
                  onOpenPolicy={onOpenPolicy}
                />
              </Fold>
            )}
            {plan.manual_review.length > 0 && (
              <Fold
                title="Not fixable automatically"
                count={plan.manual_review.length}
                hint="These rules did not pass, but need a person. Each has the reason and, where CIS gives them, the manual steps."
                tone="amber"
              >
                <ul className="list-disc pl-5 space-y-2">
                  {plan.manual_review.map((f: any) => {
                    const row = rows.get(f.spec_id)
                    return (
                      <li key={f.spec_id}>
                        <strong>{f.title || f.spec_id}</strong>{" "}
                        <span className="text-sm">({f.spec_id})</span>:{" "}
                        {manualReason(
                          f,
                          row,
                          groups.some(
                            (g) =>
                              g.spec_id === f.spec_id &&
                              (g.proposals ?? []).length > 0,
                          ),
                        )}
                        {f.manual_fix && (
                          <ManualFix fix={f.manual_fix} item={f} />
                        )}
                      </li>
                    )
                  })}
                </ul>
              </Fold>
            )}
            {(plan.not_applicable ?? []).length > 0 && (
              <Fold
                title="Not applicable on this server"
                count={plan.not_applicable.length}
                hint="These rules only apply in a set-up this server doesn't use, so there is nothing to do."
                tone="sky"
              >
                <ul className="list-disc pl-5 space-y-2">
                  {plan.not_applicable.map((f: any) => {
                    const row = rows.get(f.spec_id)
                    return (
                      <li key={f.spec_id}>
                        <strong>
                          {cisRule(row ?? { ...f, id: f.spec_id })}
                        </strong>
                        <p className="text-sm">
                          {row?.explanation
                            ? explanationSentence(row.explanation)
                            : "Its CIS condition is not met on this server, so it doesn't apply."}
                        </p>
                        {f.condition && (
                          <p className="text-xs italic text-slate-600">
                            CIS: “{f.condition}”
                          </p>
                        )}
                      </li>
                    )
                  })}
                </ul>
              </Fold>
            )}
          </>
        )}
      </Card>
      <Card
        title="2. Test on a throwaway copy"
        subtitle="Your database is never touched. Each test builds a fresh copy, applies the fix, checks it, undoes it, then deletes the copy."
      >
        <div className="grid gap-4 lg:grid-cols-2">
          <section className="rounded-lg border border-slate-200 p-4 space-y-3">
            <h3 className="font-semibold">Test one fix on its own</h3>
            {singleTest}
          </section>
          <section className="rounded-lg border border-slate-200 p-4 space-y-3">
            <h3 className="font-semibold">Test the ticked fixes together</h3>
            <p className="text-sm text-slate-500">
              Checks that the fixes still work when applied one after another on
              the same copy. Tick 2 to {MAX_BATCH} fixes in section 1.
            </p>
            {!plan ? (
              <p className="text-sm">Show the recommended fixes first.</p>
            ) : selected.length === 0 ? (
              <p className="text-sm">Nothing ticked yet.</p>
            ) : (
              <ol className="list-decimal pl-5 text-sm">
                {selected.map((sid) => (
                  <li key={sid}>{selectionLabel(sid)}</li>
                ))}
              </ol>
            )}
            {plan && selected.length > 1 && (
              <div className="rounded border border-slate-200 p-3 space-y-2 text-sm">
                <label className="flex gap-2">
                  <input
                    type="checkbox"
                    checked={customOrder}
                    onChange={(e) => setCustomOrder(e.target.checked)}
                  />
                  Test them in a different order
                </label>
                {customOrder &&
                  selected.map((sid, index) => (
                    <p key={sid}>
                      {index + 1}. {selectionLabel(sid)}{" "}
                      <button
                        className="text-teal-700 underline"
                        disabled={index === 0 || !!s.busy}
                        onClick={() => {
                          const next = [...selected]
                          ;[next[index - 1], next[index]] = [
                            next[index],
                            next[index - 1],
                          ]
                          setSelected(next)
                        }}
                      >
                        Move earlier
                      </button>
                    </p>
                  ))}
              </div>
            )}
            {plan && (
              <button
                className={button}
                disabled={
                  !!s.busy || selected.length < 2 || selected.length > MAX_BATCH
                }
                onClick={() =>
                  void live.action(
                    "Testing fixes individually and together",
                    async () => {
                      live.patch({ batch: null })
                      const b = await api(
                        s.service,
                        "/api/v1/sandbox/batches",
                        {
                          // Object fixes are ordered by their own fix_id.
                          requested_order: customOrder
                            ? selected.map((sid) =>
                                isObjectFixId(sid)
                                  ? sid
                                  : plan.recommended_order.find(
                                      (f: any) => f.spec_id === sid,
                                    ).fix_id,
                              )
                            : null,
                          // Object fixes send only object_fix_id; never params.
                          fixes: batchFixes(
                            selected,
                            {
                              snapshot_id: s.snapshot.snapshot_id,
                              benchmark_id: s.benchmark,
                              environment: s.environment,
                              evidence_ids: s.evidenceIds
                                .split(",")
                                .map((v: string) => v.trim())
                                .filter(Boolean),
                              policy_profile:
                                s.policyProfile?.profile_ref ?? null,
                            },
                            {
                              templateVersion: s.templateVersion,
                              retryMode: s.retryMode,
                            },
                            (fixId: string) =>
                              objectTemplateVersionFor(
                                plan,
                                fixId,
                                s.objectTemplateVersion,
                              ),
                            // Only preload fixes (3.2, 5.6) get list_template_version.
                            (controlId: string) =>
                              listTemplateVersionFor(plan, controlId),
                            // Catalog-linked fixes (3.2, 5.6, 6.10) run once: no retries.
                            (controlId: string) =>
                              isCatalogLinkedFix(plan, controlId),
                          ),
                        },
                      )
                      live.patch({
                        batch: {
                          snapshot_id: s.snapshot.snapshot_id,
                          benchmark: s.benchmark,
                          data: b,
                        },
                      })
                    },
                  )
                }
              >
                {selected.length < 2
                  ? "Tick at least two fixes to test together"
                  : selected.length > MAX_BATCH
                    ? `Tick at most ${MAX_BATCH} fixes`
                    : `Test ${selected.length} selected fixes together`}
              </button>
            )}
          </section>
        </div>
      </Card>
    </>
  )
}

// Step 5 result panel for the latest combined test (step 6 shows CombinedReview).
export function CombinedResult() {
  const s = useLive().state
  const batch = currentBatch(s)
  if (!batch) return null
  const titles = titlesBySpec(findings(s.assessment))
  return (
    <section className="rounded-lg border border-slate-200 p-4 space-y-3">
      <h3 className="font-semibold">{combinedResultTitle(batch, titles)}</h3>
      <p className="text-sm text-slate-500">
        These fixes were applied one after another on the same throwaway copy,
        to check they work together.
      </p>
      <div className="flex flex-wrap gap-3 items-center">
        <Badge value={batch.status} />
        {batch.run_id && (
          <span className="text-xs text-slate-500 break-all">
            Run {batch.run_id}
          </span>
        )}
      </div>
      {s.assessment && (
        <SandboxChanges
          assessment={s.assessment}
          after={batchAfter(batch)}
          notice={
            batch.status === "VERIFIED"
              ? undefined
              : `The combined test did not verify (${String(batch.status ?? "Not returned")}). The statuses below may not include every selected fix or what the failure broke; check the test details.`
          }
          afterLabel={
            batch.status === "VERIFIED"
              ? "After combined test"
              : "Before the failure"
          }
        />
      )}
      <EvidenceShots evidence={batch.combined_test?.terminal_evidence} />
      <Fold
        title="Test details"
        hint="Each fix tested alone, the combined run, the undo and clean-up, as raw evidence."
      >
        <Raw value={batch} label="Combined test, undo and clean-up evidence" />
      </Fold>
    </section>
  )
}

export function currentBatch(s: any) {
  return s.batch &&
    s.batch.snapshot_id === s.snapshot?.snapshot_id &&
    s.batch.benchmark === s.benchmark
    ? s.batch.data
    : null
}

// CIS remediation text for a FAIL that DBGuard will not fix (from records.json).
type ManualFixProps = {
  fix: any
  item: any
}

function ManualFix({ fix, item }: ManualFixProps) {
  return (
    <div className="mt-2 rounded border border-amber-200 bg-amber-50 p-3 space-y-1 text-sm">
      <p className="font-medium">
        Manual fix
        {fix.cis_recommendation
          ? ` · CIS ${fix.cis_recommendation}${
              fix.cis_title ? `: ${fix.cis_title}` : ""
            }`
          : ""}
      </p>
      <p>
        No automatic fix is offered for this control
        {item.reason ? ` (DBGuard: ${item.reason})` : ""}. The DBA makes this
        change by hand.
      </p>
      {fix.instructions && <p>{fix.instructions}</p>}
      {fix.remediation_procedure ? (
        <pre className="whitespace-pre-wrap break-words bg-white border rounded p-2 text-xs">
          {fix.remediation_procedure}
        </pre>
      ) : (
        <p className="text-xs text-slate-600">
          The CIS remediation text is not available in this release.
        </p>
      )}
    </div>
  )
}

function fixIdOf(run: any) {
  return run?.fix_id ?? run?.fix_unit?.fix_id
}

// One row per selected fix, so the DBA sees every fix from a combined test in step 6.
export function CombinedReview() {
  const s = useLive().state
  const batch = currentBatch(s)
  if (!batch) return null
  const runs: any[] = batch.individual_runs ?? []
  const units: any[] =
    batch.fix_units ?? runs.map((r) => r.fix_unit).filter(Boolean)
  const order: string[] = batch.recommended_order ?? units.map((u) => u.fix_id)
  const combinedOk = batch.combined_test?.status === "VERIFIED"
  const after = batch.sandbox_after_findings ?? {}
  // Object fixes: the title from their risk review (server-derived text).
  const reviews: any[] = Array.isArray(batch.risk_reviews)
    ? batch.risk_reviews
    : []
  const rows = order
    .map((fid) => units.find((u) => u.fix_id === fid))
    .filter(Boolean)
  const untested = runs
    .map(fixIdOf)
    .filter((fid) => fid && !rows.some((u: any) => u.fix_id === fid))
  const titles = titlesBySpec(findings(s.assessment))
  return (
    <Card
      title={`For the DBA: ${combinedResultTitle(batch, titles)}`}
      subtitle="Each fix was tested alone, then all together. Only fixes that passed both go into the combined bundle."
    >
      <p className="flex flex-wrap items-center gap-2">
        <Badge value={batch.status} />
        {batch.order_source && (
          <span className="text-sm text-slate-500">
            {batch.order_source === "DBA_SELECTED"
              ? "Tested in the order you chose"
              : "Tested in the recommended order"}
          </span>
        )}
      </p>
      {batch.reason && <p className="text-amber-800">{batch.reason}</p>}
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="text-left">
              <th className="py-2 pr-3">#</th>
              <th className="py-2 pr-3">CIS rule</th>
              <th className="py-2 pr-3">What changes</th>
              <th className="py-2 pr-3">Tested alone</th>
              <th className="py-2 pr-3">Tested together</th>
              <th className="py-2">What the DBA does</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((u: any, i: number) => {
              const alone =
                runs.find((r) => fixIdOf(r) === u.fix_id)?.status ?? "NOT RUN"
              const ok = alone === "VERIFIED" && combinedOk
              const object = isObjectUnit(u)
              const catalog = !object && isCatalogUnit(u)
              const review = reviews.find((r) => r?.fix_id === u.fix_id)
              return (
                <tr
                  key={u.fix_id}
                  className="border-t border-slate-200 align-top"
                >
                  <td className="py-2 pr-3">{i + 1}</td>
                  <td className="py-2 pr-3">
                    {titles.get(u.spec_id) ?? u.spec_id}
                    <small className="block text-slate-500">{u.spec_id}</small>
                  </td>
                  <td className="py-2 pr-3">
                    {object ? (
                      <>
                        {review?.title ??
                          runs.find((r) => fixIdOf(r) === u.fix_id)?.proposal
                            ?.title ??
                          u.fix_id}
                        <span className="block text-xs text-slate-600">
                          Object fix · {u.verify?.predicate}
                        </span>
                      </>
                    ) : catalog ? (
                      <>
                        {catalogChangeLines(u).map((line) => (
                          <span key={line} className="block">
                            {line}
                          </span>
                        ))}
                        <span className="block text-xs text-slate-600">
                          Proven by its CIS check · {u.requires}
                        </span>
                      </>
                    ) : (
                      <>
                        {u.params?.param_name}: {u.prior_state?.value} →{" "}
                        {u.params?.param_value} · {u.requires}
                      </>
                    )}
                  </td>
                  <td className="py-2 pr-3">{alone}</td>
                  <td className="py-2 pr-3">
                    {object
                      ? objectAfterCombined(batch, u.fix_id)
                      : catalog
                        ? catalogAfterCombined(batch, u.fix_id)
                        : (after[u.spec_id] ?? "NOT RUN")}
                  </td>
                  <td className="py-2">
                    {ok
                      ? "Review it, then apply it with the combined bundle"
                      : "Not in a bundle: needs the DBA's own review"}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
      {untested.length > 0 && (
        <p className="text-amber-800">
          Stopped before the combined test: {untested.join(", ")}
        </p>
      )}
      <p className="text-xs text-slate-500">
        The download is in “Hand over to the DBA” below.
      </p>
      <EvidenceShots evidence={batch.combined_test?.terminal_evidence} />
      <Fold
        title="Test details"
        hint="Each fix tested alone, the combined run, the undo and clean-up, as raw evidence."
      >
        <Raw value={batch} label="Combined test, undo and clean-up evidence" />
      </Fold>
    </Card>
  )
}

export function RunHistory() {
  const live = useLive(),
    s = live.state
  const [runs, setRuns] = useState<any[]>([]),
    [detail, setDetail] = useState<any>(null)
  const [operator, setOperator] = useState(""),
    [note, setNote] = useState(""),
    [kind, setKind] = useState("REVIEW_NOTE")
  const [fresh, setFresh] = useState(""),
    [control, setControl] = useState("")
  const runId = detail?.result?.run_id
  async function refresh() {
    setRuns((await api(s.service, "/api/v1/history")).runs)
  }
  async function open(id: string) {
    const d = await api(s.service, `/api/v1/history/${id}`)
    setDetail(d)
    setControl(
      d.result.fix_unit?.spec_id ?? d.result.fix_units?.[0]?.spec_id ?? "",
    )
  }
  return (
    <Card title="Run history and target verification">
      <button
        className={button}
        disabled={!!s.busy}
        onClick={() => void live.action("Loading run history", refresh)}
      >
        Load saved runs
      </button>
      <p className="text-sm">
        Sandbox results, DBA statements and target reassessment are separate
        records. Local history survives a package restart.
      </p>
      <div className="max-h-44 overflow-auto">
        {runs.map((r) => (
          <button
            key={r.run_id}
            className="block text-left text-teal-700 underline p-1"
            onClick={() =>
              void live.action("Opening run", () => open(r.run_id))
            }
          >
            {r.created_at} · {r.status} · {r.run_id}
          </button>
        ))}
      </div>
      {detail && (
        <>
          <p className="font-medium">
            Run {runId} · Sandbox {detail.result.status}
          </p>
          <a
            className="text-teal-700 underline"
            href={`/bridge/${s.service}/api/v1/sandbox/runs/${runId}/bundle`}
            download
          >
            Download saved review bundle
          </a>
          <a
            className="text-teal-700 underline block"
            href={`/bridge/${s.service}/api/v1/history/${runId}/evidence-bundle`}
            download
          >
            Download complete evidence and review history
          </a>
          <div className="space-y-2 border rounded p-3">
            <h3>Record DBA action or review note</h3>
            <input
              aria-label="Operator or reviewer"
              className="border rounded p-2 w-full"
              placeholder="Your name"
              value={operator}
              onChange={(e) => setOperator(e.target.value)}
            />
            <select
              aria-label="DBA action type"
              className="border rounded p-2"
              value={kind}
              onChange={(e) => setKind(e.target.value)}
            >
              {[
                "REVIEW_NOTE",
                "DBA_REPORTS_APPLIED",
                "DBA_REPORTS_ROLLED_BACK",
              ].map((k) => (
                <option key={k}>{k}</option>
              ))}
            </select>
            <textarea
              aria-label="DBA action note"
              className="border rounded p-2 w-full"
              placeholder="Fix, change ticket and what you checked"
              value={note}
              onChange={(e) => setNote(e.target.value)}
            />
            <button
              className={button}
              disabled={!!s.busy || !operator.trim() || !note.trim()}
              onClick={() =>
                void live.action("Recording operator statement", async () => {
                  await api(s.service, `/api/v1/history/${runId}/events`, {
                    kind,
                    operator,
                    note,
                  })
                  setNote("")
                  await open(runId)
                })
              }
            >
              Save statement
            </button>
            <p className="text-xs">
              This records your statement; it does not mark the target verified.
            </p>
          </div>
          <div className="border rounded p-3 space-y-2">
            <h3>Reassess the actual target</h3>
            <p className="text-sm">
              Use Main API to upload a fresh collected snapshot, then enter its
              ID. The server checks target cluster identity, collection time,
              exact specs and regressions.
            </p>
            <input
              aria-label="Fresh reassessment snapshot ID"
              className="border rounded p-2 w-full"
              placeholder="snap-…"
              value={fresh}
              onChange={(e) => setFresh(e.target.value)}
            />
            <button
              className={button}
              disabled={!!s.busy || !fresh}
              onClick={() =>
                void live.action(
                  "Verifying fresh target evidence",
                  async () => {
                    await api(s.service, `/api/v1/history/${runId}/reassess`, {
                      snapshot_id: fresh,
                      benchmark_id: detail.handoff.benchmark_id,
                    })
                    await open(runId)
                  },
                )
              }
            >
              Verify fresh target assessment
            </button>
          </div>
          <div className="border rounded p-3 space-y-2">
            <h3>Attach supporting database screenshot</h3>
            <p className="text-sm">
              Manual evidence stays pending review. Enter your name above first.
            </p>
            <select
              aria-label="Screenshot control"
              className="border rounded p-2"
              value={control}
              onChange={(e) => setControl(e.target.value)}
            >
              {Object.keys(detail.result.spec_hashes).map((id) => (
                <option key={id}>{id}</option>
              ))}
            </select>
            <FileButton
              label="Choose screenshot (PNG or JPEG)"
              accept="image/png,image/jpeg"
              aria-label="Database evidence screenshot"
              disabled={!!s.busy || !operator.trim()}
              onChange={(e) => {
                const file = e.target.files?.[0]
                if (file)
                  void live.action("Attaching evidence", async () => {
                    const data = new FormData()
                    data.append("file", file)
                    data.append("control_id", control)
                    data.append("operator", operator)
                    await request(
                      `/bridge/${s.service}/api/v1/history/${runId}/evidence`,
                      { method: "POST", body: data },
                    )
                    await open(runId)
                  })
              }}
            />
          </div>
          {detail.events.map((ev: any) => (
            <div className="border-l-4 border-teal-600 pl-3" key={ev.id}>
              <p>
                {ev.kind} · {ev.timestamp}
              </p>
              {ev.data.image_base64 ? (
                <>
                  <img
                    className="max-w-full max-h-72 object-contain"
                    alt={"Uploaded evidence for " + ev.data.control_id}
                    src={`data:image/${ev.data.format};base64,${ev.data.image_base64}`}
                  />
                  <p>
                    Evidence review:{" "}
                    {detail.events
                      .filter(
                        (e: any) =>
                          e.data.evidence_sha256 === ev.data.sha256 &&
                          e.kind.startsWith("MANUAL_EVIDENCE_"),
                      )
                      .at(-1)?.kind ?? "PENDING_REVIEW"}{" "}
                    · {ev.data.sha256}
                  </p>
                  <div className="flex gap-2">
                    {["ACCEPTED", "REJECTED"].map((decision) => (
                      <button
                        key={decision}
                        className={button}
                        disabled={!!s.busy || !operator.trim() || !note.trim()}
                        onClick={() =>
                          void live.action(
                            "Recording evidence review",
                            async () => {
                              await api(
                                s.service,
                                `/api/v1/history/${runId}/events`,
                                {
                                  kind: "MANUAL_EVIDENCE_" + decision,
                                  operator,
                                  note,
                                  evidence_sha256: ev.data.sha256,
                                },
                              )
                              await open(runId)
                            },
                          )
                        }
                      >
                        {decision === "ACCEPTED" ? "Accept" : "Reject"} evidence
                      </button>
                    ))}
                  </div>
                  <p className="text-xs">
                    Enter reviewer name and review note above; acceptance does
                    not change automatic assessment.
                  </p>
                </>
              ) : (
                <Raw value={ev.data} />
              )}
            </div>
          ))}
          <Raw
            value={detail.result.risk_review ?? detail.result.risk_reviews}
            label="Recorded risk review"
          />
        </>
      )}
    </Card>
  )
}

// W2B catalog-linked setting fix (3.2, 5.6, 6.10): every setting it changes, the
// restart and preload notes, and how the sandbox proves it. Text only.
function CatalogSettingChanges({
  fix: f,
  listTemplateVersion,
}: {
  fix: any
  listTemplateVersion: any
}) {
  const preload = preloadNote(f)
  const restart = restartNote(f)
  const versionMissing =
    needsListTemplate(f) &&
    !(Number.isInteger(listTemplateVersion) && listTemplateVersion > 0)
  return (
    <div className="space-y-1">
      <p className="font-medium">What changes</p>
      <ul className="list-disc pl-5">
        {catalogChanges(f).map((c) => (
          <li key={c.setting}>
            {c.setting}:{" "}
            <strong>
              {c.current} → {c.proposed}
            </strong>
          </li>
        ))}
      </ul>
      {restart && (
        <p className="rounded bg-amber-50 px-2 py-1 text-sm text-amber-900">
          {restart}
        </p>
      )}
      {preload && (
        <p className="rounded bg-amber-50 px-2 py-1 text-sm text-amber-900">
          {preload}
        </p>
      )}
      {versionMissing && (
        <p className="text-sm text-red-700">
          DBGuard could not read the approved list template version, so a test
          of this fix will be refused until the template registry is reachable.
        </p>
      )}
      {typeof f.proof === "string" && f.proof && (
        <p className="text-sm">Proof: {f.proof}</p>
      )}
    </div>
  )
}
