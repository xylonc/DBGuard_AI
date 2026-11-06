// Pure helpers for the fix plan (ReviewPanel.tsx FixPlan). No React and no "@/"
// imports, so node --test can load this file directly. Everything shown is either a
// fixed sentence here or a plain value from the fix plan, rendered as React text.

import {
  POLICY_MISSING_LABEL,
  UNKNOWN_LABEL,
  explanationSentence,
  isPolicyMissing,
  statusKind,
} from "./explanations.ts"

// Backend reason (planning.SITE_FIX_MISSING) when a fix needs a site-specific value.
const SITE_FIX_MISSING = "site-specific fix value not supplied"

export const CATALOG_OBJECT_FIXES_SENTENCE =
  'DBGuard does not fix this check as a whole. Fixes for single accounts or objects are offered above under "Proposed fixes for accounts and permissions"; anything not listed there needs a person.'
export const CATALOG_GENERIC_SENTENCE =
  "DBGuard only reports this from catalog evidence and does not change it as a whole; a person must act on anything not offered as a per-object fix."

function isCatalogItem(f: any): boolean {
  return f?.kind === "catalog" || Array.isArray(f?.evidence)
}

// Plain-language reason a non-passing control gets no automatic fix. `row` is the
// matching assessment row; its structured explanation is preferred when present.
export function manualReason(f: any, row?: any, objectFixes = false): string {
  if (isCatalogItem(f)) {
    // W2B: a catalog-linked fix (3.2, 5.6, 6.10) that could not be offered carries a
    // reason_code and the server's fixed plain-language reason
    // (catalog_fixes.REASONS). Shown as text; the generic sentence only without one.
    if (
      typeof f?.reason_code === "string" &&
      f.reason_code &&
      typeof f?.reason === "string" &&
      f.reason.trim()
    )
      return f.reason
    // Catalog checks (F6): per-object fixes, when offered, are listed separately.
    return objectFixes
      ? CATALOG_OBJECT_FIXES_SENTENCE
      : CATALOG_GENERIC_SENTENCE
  }
  if (row && isPolicyMissing(row))
    return `${POLICY_MISSING_LABEL}. ${explanationSentence(row.explanation)}`
  if (statusKind(f?.status) === "unknown")
    return row?.explanation
      ? explanationSentence(row.explanation)
      : `${UNKNOWN_LABEL}. The evidence is missing or out of date; collect a new snapshot before fixing.`
  if (f?.tier === "manual_checklist" || f?.tier === "parameterised")
    return "a person must check this; the CIS text gives no value DBGuard can test automatically."
  if (f?.tier === "needs_capability")
    return "DBGuard cannot check this automatically yet."
  if (typeof f?.reason === "string" && f.reason.includes(SITE_FIX_MISSING))
    return "no automatic fix is offered because the fix needs a value specific to your server (for 5.2, the addresses it should listen on), and no approved policy profile with that value is selected. Add it under Site-specific fixes on the Policy Profile screen, approve the profile and select it, or fix it by hand as described below."
  if (f?.status === "FAIL")
    return "no reviewed fix exists for this setting yet."
  return "the evidence is missing or out of date; collect a new snapshot before fixing."
}

// ---- catalog-linked setting fixes (W2B: 3.2, 5.6, 6.10) ---------------------------

export function isCatalogSettingFix(f: any): boolean {
  return f?.kind === "catalog_setting"
}

export type ChangeRow = {
  setting: string
  current: string
  proposed: string
}

function shown(value: unknown): string {
  if (value == null) return "not set"
  if (typeof value === "string") return value === "" ? "'' (empty)" : value
  return String(value)
}

// One row per setting the fix changes (3.2 changes shared_preload_libraries and
// pgaudit.log). Falls back to the single setting/current/proposed fields.
export function catalogChanges(f: any): ChangeRow[] {
  const changes = Array.isArray(f?.changes) ? f.changes : []
  const rows = changes
    .filter((c: any) => c && typeof c.setting === "string" && c.setting)
    .map((c: any) => ({
      setting: c.setting,
      current: shown(c.current_value),
      proposed: shown(c.proposed_value),
    }))
  if (rows.length) return rows
  return typeof f?.setting === "string" && f.setting
    ? [
        {
          setting: f.setting,
          current: shown(f.current_value),
          proposed: shown(f.proposed_value),
        },
      ]
    : []
}

// The libraries the fix adds to shared_preload_libraries (strings only).
export function preloadAdded(f: any): string[] {
  return Array.isArray(f?.preload_added)
    ? f.preload_added.filter((x: unknown) => typeof x === "string" && x)
    : []
}

// Fixed note for a fix that adds to shared_preload_libraries.
export function preloadNote(f: any): string | null {
  const libs = preloadAdded(f)
  if (!libs.length) return null
  return `Adds ${libs.join(", ")} to shared_preload_libraries and keeps the existing entries in order. PostgreSQL will not start if a preloaded library is missing, so the package must be installed on the server first; the exported runner refuses to apply otherwise.`
}

export function restartNote(f: any): string | null {
  return f?.requires === "restart"
    ? "Needs a PostgreSQL restart to take effect. Plan a maintenance window."
    : null
}
