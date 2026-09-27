import { useEffect, useState } from "react"
import { api, request } from "@/adapters/live"
import { useLive } from "@/store/liveStore"
import { Card, Raw } from "./LiveUI"
const button = "rounded bg-teal-700 text-white px-4 py-2 disabled:opacity-40"
export function FixPlan() {
  const live = useLive(),
    s = live.state
  const [customOrder, setCustomOrder] = useState(false)
  const [plan, setPlan] = useState<any>(null),
    [selected, setSelected] = useState<string[]>([]),
    [batch, setBatch] = useState<any>(null)
  useEffect(() => {
    setPlan(null)
    setSelected([])
    setBatch(null)
  }, [s.snapshot?.snapshot_id, s.benchmark])
  async function load(llm = false) {
    await live.action("Reviewing proposed fixes", async () => {
      const p = await api(
        s.service,
        `/api/v1/snapshots/${s.snapshot.snapshot_id}/fix-plan?benchmark_id=${encodeURIComponent(s.benchmark)}&review_with_llm=${llm}`,
      )
      setPlan(p)
    })
  }
  return (
    <Card title="Fix risk, prerequisites and test plan">
      <p>
        Compare operational risk before choosing a fix. Security urgency and
        application dependencies still need DBA judgement.
      </p>
      <div className="flex gap-2">
        <button
          className={button}
          disabled={!!s.busy || !s.assessment}
          onClick={() => void load()}
        >
          Show recommended fixes
        </button>
        <button
          className={button}
          disabled={!!s.busy || !s.assessment}
          onClick={() => void load(true)}
        >
          Ask LLM to review risk
        </button>
      </div>
      {plan && (
        <>
          <p className="text-sm">{plan.ordering_basis}</p>
          {plan.recommended_order.map((f: any, i: number) => (
            <section className="border rounded p-4 space-y-2" key={f.fix_id}>
              <div className="flex gap-2 items-center">
                <input
                  aria-label={"Include " + f.setting + " in combined test"}
                  type="checkbox"
                  checked={selected.includes(f.spec_id)}
                  onChange={(e) =>
                    setSelected(
                      e.target.checked
                        ? [...selected, f.spec_id]
                        : selected.filter((x) => x !== f.spec_id),
                    )
                  }
                />
                <h3 className="font-semibold">
                  {i + 1}. {f.title}
                </h3>
                <span className="rounded bg-amber-50 px-2 text-sm">
                  {f.operational_risk} operational risk
                </span>
              </div>
              <p>
                {f.setting}:{" "}
                <strong>
                  {f.current_value} → {f.proposed_value}
                </strong>{" "}
                · {f.requires}
              </p>
              <p>{f.reasoning}</p>
              <p className="text-sm">Rollback: {f.rollback_explanation}</p>
              <p className="text-sm">{f.activation_fact}</p>
              <p className="text-sm">
                Prior source: {f.prior_source}. Security severity:{" "}
                {f.security_severity}.
              </p>
              <p className="font-medium">Check before applying</p>
              <ul className="list-disc pl-5">
                {f.prerequisites.map((p: string) => (
                  <li key={p}>{p}</li>
                ))}
              </ul>
              <p className="text-sm">
                LLM risk review: {f.llm.status}. Model commentary is advisory
                and requires DBA review. The test runner only executes validated
                checks.
              </p>
              {f.llm.advice && <p>{f.llm.advice.reasoning}</p>}
              <details>
                <summary>
                  Functional checks, unknowns and application tests
                </summary>
                <Raw
                  value={{
                    checks: f.checks,
                    unknowns: f.unknowns,
                    application_checks: f.manual_application_checks,
                    llm: f.llm,
                  }}
                />
              </details>
              <button
                className={button}
                disabled={!!s.busy || !!s.handoffId}
                onClick={() => live.configure({ controlId: f.spec_id })}
              >
                {(s.controlId || "cis-pg17-v1.1.0:3.1.20") === f.spec_id
                  ? "Selected for individual test"
                  : "Select individual fix"}
              </button>
            </section>
          ))}
          {plan.manual_review.map((f: any) => (
            <p className="text-amber-800" key={f.spec_id}>
              {f.spec_id}: {f.reason}
            </p>
          ))}
          {selected.length > 1 && (
            <div className="border rounded p-3 space-y-2">
              <label className="flex gap-2">
                <input
                  type="checkbox"
                  checked={customOrder}
                  onChange={(e) => setCustomOrder(e.target.checked)}
                />
                Choose a different order and test it
              </label>
              {customOrder &&
                selected.map((sid, index) => (
                  <p key={sid}>
                    {index + 1}. {sid}{" "}
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
          <button
            className={button}
            disabled={!!s.busy || selected.length < 2}
            onClick={() =>
              void live.action(
                "Testing fixes individually and together",
                async () => {
                  setBatch(null)
                  const b = await api(s.service, "/api/v1/sandbox/batches", {
                    requested_order: customOrder
                      ? selected.map(
                          (sid) =>
                            plan.recommended_order.find(
                              (f: any) => f.spec_id === sid,
                            ).fix_id,
                        )
                      : null,
                    fixes: selected.map((control_id) => ({
                      snapshot_id: s.snapshot.snapshot_id,
                      benchmark_id: s.benchmark,
                      template_version: s.templateVersion,
                      evidence_ids: s.evidenceIds
                        .split(",")
                        .map((v: string) => v.trim())
                        .filter(Boolean),
                      environment: s.environment,
                      retry_mode: s.retryMode,
                      retry_template_versions: [],
                      control_id,
                    })),
                  })
                  setBatch(b)
                },
              )
            }
          >
            Test selected fixes together ({selected.length})
          </button>
        </>
      )}
      {batch && (
        <>
          <p>
            Combined test: <strong>{batch.status}</strong>
          </p>
          {batch.review_bundle?.status === "READY" && (
            <a
              className="text-teal-700 underline"
              href={`/bridge/${s.service}/api/v1/sandbox/runs/${encodeURIComponent(batch.run_id)}/bundle`}
              download
            >
              Download combined DBA bundle
            </a>
          )}
          <Raw
            value={batch}
            label="Combined test, rollback and cleanup evidence"
          />
        </>
      )}
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
            <input
              type="file"
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
