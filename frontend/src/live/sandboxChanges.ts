// After a sandbox run: which checks changed status between the original
// assessment and the sandbox after the fix. Statuses are compared by kind
// (statusKind), so the report's MANUAL and the sandbox's MANUAL_REVIEW, or
// NOT_COLLECTED and GAPPED, are the same and never count as a change.
// A check with no sandbox result (account and permission rules, which are
// proven per object) is "not re-checked", never a change.
// This file must stay free of React and "@/" imports so node --test can load it.
import { statusKind } from "./explanations.ts"

export type Direction = "better" | "worse" | "changed"

export type StatusChange = {
  id: string
  title: string
  before: string
  // null: the sandbox recorded a regression for a check outside its compared
  // findings (a catalog check that reads the changed setting); status not returned.
  after: string | null
  direction: Direction
  recordedRegression: boolean
}

export type ChangeSummary = {
  changes: StatusChange[]
  unchanged: number
  notRechecked: number
}

function status(value: unknown): string | null {
  if (typeof value === "string" && value) return value
  if (value && typeof value === "object") {
    const s = (value as any).status
    if (typeof s === "string" && s) return s
  }
  return null
}

export function changeDirection(before: unknown, after: unknown): Direction {
  const b = statusKind(before)
  const a = statusKind(after)
  // Not applicable is neither better nor worse than PASS.
  if (a === "not_applicable" || b === "not_applicable") return "changed"
  if (a === "pass" && b !== "pass") return "better"
  if (b === "pass" && a !== "pass") return "worse"
  if (a === "fail" && b !== "fail") return "worse"
  return "changed"
}

// `regressions`: check ids the sandbox itself recorded as regressions (the last
// attempt's `regressions`). They are always listed as worse, never "unchanged" or
// "not re-checked", even when their after status is not in `after`.
export function statusChanges(
  rows: any[],
  after: any,
  regressions: string[] = [],
): ChangeSummary {
  const map = after && typeof after === "object" ? after : {}
  const recorded = new Set(
    (Array.isArray(regressions) ? regressions : []).filter(
      (r) => typeof r === "string" && !!r,
    ),
  )
  const changes: StatusChange[] = []
  let unchanged = 0
  let notRechecked = 0
  const seen = new Set<string>()
  for (const row of Array.isArray(rows) ? rows : []) {
    const id = typeof row?.id === "string" ? row.id : null
    if (!id) continue
    seen.add(id)
    const title = typeof row?.title === "string" && row.title ? row.title : id
    const before = status(row?.status)
    const now = Object.prototype.hasOwnProperty.call(map, id)
      ? status(map[id])
      : null
    if (recorded.has(id)) {
      changes.push({
        id,
        title,
        before: before ?? "Not returned",
        after: now,
        direction: "worse",
        recordedRegression: true,
      })
      continue
    }
    if (now === null || before === null) {
      notRechecked++
      continue
    }
    if (statusKind(before) === statusKind(now)) {
      unchanged++
      continue
    }
    changes.push({
      id,
      title,
      before,
      after: now,
      direction: changeDirection(before, now),
      recordedRegression: false,
    })
  }
  for (const id of recorded)
    if (!seen.has(id))
      changes.push({
        id,
        title: id,
        before: "Not returned",
        after: null,
        direction: "worse",
        recordedRegression: true,
      })
  // Worse first, so a regression is never below the fold.
  const order: Record<Direction, number> = { worse: 0, changed: 1, better: 2 }
  changes.sort((x, y) => order[x.direction] - order[y.direction])
  return { changes, unchanged, notRechecked }
}

// Sandbox statuses for one recorded run, from the sandbox's compared findings
// only: sandbox_after_findings, else the last attempt's after_assessment.findings.
// Never its upstream_report: that also holds account and permission checks run
// against the sandbox's stand-in accounts, which must not be compared with the
// source. Catalog-linked fixes (3.2, 5.6, 6.10) are outside the findings map;
// their own CIS check result is in sandbox_control, or catalog_proof.after.
export function runAfter(result: any): Record<string, string> {
  const out: Record<string, string> = {}
  const attempts: any[] = Array.isArray(result?.attempts) ? result.attempts : []
  const findings =
    result?.sandbox_after_findings ??
    attempts[attempts.length - 1]?.after_assessment?.findings
  if (findings && typeof findings === "object")
    for (const [id, v] of Object.entries(findings)) {
      const s = status(v)
      if (s) out[id] = s
    }
  const control = result?.sandbox_control ?? {
    spec_id: result?.fix_unit?.spec_id,
    after_status: result?.catalog_proof?.after?.result,
  }
  const sid = control?.spec_id
  const after = control?.after_status
  if (
    typeof sid === "string" &&
    sid &&
    !(sid in out) &&
    typeof after === "string" &&
    after &&
    after !== "UNKNOWN"
  )
    out[sid] = after
  return out
}

// Check ids the sandbox recorded as regressions in a run's last attempt.
export function runRegressions(result: any): string[] {
  const attempts: any[] = Array.isArray(result?.attempts) ? result.attempts : []
  const last = attempts[attempts.length - 1]?.regressions
  return Array.isArray(last)
    ? last.filter((r: unknown): r is string => typeof r === "string" && !!r)
    : []
}

// Sandbox statuses after a combined test. A catalog-linked fix's CIS check result
// is added only when the whole combined test VERIFIED.
export function batchAfter(batch: any): Record<string, string> {
  const out: Record<string, string> = {}
  const findings = batch?.sandbox_after_findings
  if (findings && typeof findings === "object")
    for (const [id, v] of Object.entries(findings)) {
      const s = status(v)
      if (s) out[id] = s
    }
  const combined = batch?.combined_test
  if (combined?.status !== "VERIFIED") return out
  const units: any[] = Array.isArray(batch?.fix_units) ? batch.fix_units : []
  const steps: any[] = Array.isArray(combined?.steps) ? combined.steps : []
  for (const step of steps) {
    const result = step?.catalog_proof?.result
    if (typeof result !== "string" || !result) continue
    const sid =
      step?.fix_unit?.spec_id ??
      units.find((u) => u?.fix_id === step?.fix_id)?.spec_id
    if (typeof sid === "string" && sid && !(sid in out)) out[sid] = result
  }
  return out
}

// Whether a recorded test (a run or a combined test) was made against the same
// assessment that is on screen: same evidence (snapshot hash), same rule set
// (spec-set hash) and same company policy (profile sha256, or none on both).
// A comparison across different assessments would show changes the fix did not
// cause (e.g. policy rules "PASS -> Manual review" when the profile differs), so
// the UI compares only when this says same. Unknown identity is never "same".
export type AssessmentMatch = {
  same: boolean
  reason: string | null
}

function policySha(pin: unknown): string | null | undefined {
  if (pin === null) return null
  if (pin === undefined) return undefined
  const sha = (pin as any)?.sha256
  return typeof sha === "string" && sha ? sha : undefined
}

export function sameAssessment(item: any, envelope: any): AssessmentMatch {
  const current = envelope?.assessment ?? envelope
  const itemSnap = item?.snapshot_hash
  const itemSpecs = item?.spec_set_hash
  if (typeof itemSnap !== "string" || typeof itemSpecs !== "string")
    return {
      same: false,
      reason:
        "this recorded test doesn't say which assessment it was run against",
    }
  if (itemSnap !== current?.snapshot_hash)
    return { same: false, reason: "it was run on different evidence" }
  if (itemSpecs !== current?.spec_set_hash)
    return { same: false, reason: "it was run with a different rule set" }
  const itemPolicy = policySha(item?.policy_profile)
  const currentPolicy = policySha(
    envelope?.policy_profile !== undefined
      ? envelope.policy_profile
      : (current?.upstream_report?.inputs?.policy_profile ?? null),
  )
  if (itemPolicy === undefined || currentPolicy === undefined)
    return {
      same: false,
      reason: "its company policy can't be matched to the current one",
    }
  if (itemPolicy !== currentPolicy)
    return {
      same: false,
      reason:
        itemPolicy === null
          ? "it was run before a company policy was chosen"
          : currentPolicy === null
            ? "it was run with a company policy that isn't selected now"
            : "it was run with a different company policy",
    }
  return { same: true, reason: null }
}
