// Plain names for recorded sandbox results, so a single-fix test and a combined
// test are never mistaken for two versions of the same thing. Names come only
// from server-derived fields (proposal/risk-review titles, assessment titles,
// spec ids); nothing here comes from model output.
// This file must stay free of React and "@/" imports so node --test can load it.
import { isObjectUnit } from "./objectFixes.ts"

const MAX_NAMES = 3
const MAX_NAME = 80

function clip(text: string): string {
  return text.length > MAX_NAME ? text.slice(0, MAX_NAME - 1) + "…" : text
}

function str(value: unknown): string | null {
  return typeof value === "string" && value ? value : null
}

// Assessment title by spec id, from the rows shown in step 4.
export function titlesBySpec(rows: any[]): Map<string, string> {
  const out = new Map<string, string>()
  for (const r of Array.isArray(rows) ? rows : []) {
    const id = str(r?.id) ?? str(r?.spec_id)
    const title = str(r?.title)
    if (id && title) out.set(id, title)
  }
  return out
}

function unitName(
  unit: any,
  titles: Map<string, string>,
  objectTitle: (fixId: string) => string | null,
): string {
  const spec = str(unit?.spec_id)
  const fixId = str(unit?.fix_id)
  const object = fixId ? objectTitle(fixId) : null
  return clip(
    object ??
      (spec && titles.get(spec)) ??
      str(unit?.params?.param_name) ??
      spec ??
      fixId ??
      "unnamed fix",
  )
}

export function singleFixName(
  result: any,
  titles: Map<string, string>,
): string {
  const object =
    str(result?.proposal?.title) ?? str(result?.risk_review?.title) ?? null
  return unitName(
    result?.fix_unit ?? { spec_id: result?.sandbox_control?.spec_id },
    titles,
    () => (result?.kind === "object" ? object : null),
  )
}

export function singleResultTitle(
  result: any,
  titles: Map<string, string>,
): string {
  return `Single-fix test: ${singleFixName(result, titles)}`
}

export function combinedFixNames(
  batch: any,
  titles: Map<string, string>,
): string[] {
  const reviews: any[] = Array.isArray(batch?.risk_reviews)
    ? batch.risk_reviews
    : []
  const runs: any[] = Array.isArray(batch?.individual_runs)
    ? batch.individual_runs
    : []
  const units: any[] = Array.isArray(batch?.fix_units)
    ? batch.fix_units
    : runs.map((r) => r?.fix_unit).filter(Boolean)
  const objectTitle = (fixId: string) =>
    str(reviews.find((r) => r?.fix_id === fixId)?.title) ??
    str(runs.find((r) => r?.fix_unit?.fix_id === fixId)?.proposal?.title)
  return units.map((u) =>
    unitName(u, titles, (fid) => (isObjectUnit(u) ? objectTitle(fid) : null)),
  )
}

export function combinedResultTitle(
  batch: any,
  titles: Map<string, string>,
): string {
  const names = combinedFixNames(batch, titles)
  const n = names.length
  if (!n) return "Combined test"
  const shown = names.slice(0, MAX_NAMES).join(" + ")
  const more = n > MAX_NAMES ? ` + ${n - MAX_NAMES} more` : ""
  return `Combined test of ${n} fix${n === 1 ? "" : "es"}: ${shown}${more}`
}

// Why a recorded test has (or has no) DBA bundle, in words that never claim the
// wrong reason: a VERIFIED run can still have no bundle (export is a separate
// gate, router.py), and then the server's own reason is shown.
export type BundleState = {
  ready: boolean
  // Shown when not ready.
  message: string
  // Demo approval records (DEMO_FIXTURE_ONLY), never a named human.
  demo: boolean
}

export function bundleState(item: any, combined = false): BundleState {
  const bundle = item?.review_bundle
  const ready = bundle?.status === "READY"
  const demo = !!(bundle?.demo_fixture_approval || item?.demo_fixture_approval)
  let message = "No bundle is available for this result."
  if (!ready) {
    if (item?.status !== "VERIFIED")
      message = combined
        ? "No combined bundle: every fix must pass alone and together first."
        : "No bundle: this test did not pass."
    else if (str(bundle?.reason)) message = `No bundle: ${clip(bundle.reason)}`
  }
  return { ready, message, demo }
}

export function anyBundleReady(...items: any[]): boolean {
  return items.some((i) => i?.review_bundle?.status === "READY")
}
