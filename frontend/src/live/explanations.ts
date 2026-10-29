// Plain-language sentences for assessment results, built ONLY from the structured
// `explanation` facts the backend returns (assess.py `_explain`, ASSESS spec_controls).
// Every sentence is a fixed template per code with the facts filled in; nothing here
// ever comes from model output. An unknown code, a missing fact or a malformed
// explanation falls back to a safe generic "Unknown: needs human review" sentence and
// is never presented as passing.
//
// Adding a code (the F6 branch will add section_not_collected, field_missing,
// manual_review, databases_not_covered, empty_review_set, restore_test_reminder):
// add one entry to TEMPLATES below and one case to tests/explanations.test.mjs.
// This file must stay free of React and "@/" imports so node --test can load it.

export const UNKNOWN_LABEL = "Unknown: needs human review"
export const POLICY_MISSING_LABEL = "COMPANY POLICY MISSING"
export const GENERIC_UNKNOWN_SENTENCE =
  "Unknown: needs human review. DBGuard has no plain-language explanation for this result, so it can't say PASS and a person must check this control."

// Statuses that mean DBGuard could not decide. The sandbox projection reports all
// of them as GAPPED; the authoritative report keeps the detail.
export const UNKNOWN_STATUSES = ["GAPPED", "NOT_COLLECTED", "STALE", "ERROR"]
const MANUAL_STATUSES = ["MANUAL", "MANUAL_REVIEW", "NEEDS_CAPABILITY"]

export type StatusKind = "pass" | "fail" | "not_applicable" | "manual" | "unknown"

// Anything not recognised is unknown: an unexpected status is never shown as PASS.
export function statusKind(status: unknown): StatusKind {
  const text = typeof status === "string" ? status : ""
  if (text === "PASS") return "pass"
  if (text === "FAIL") return "fail"
  if (text === "NOT_APPLICABLE") return "not_applicable"
  if (MANUAL_STATUSES.includes(text)) return "manual"
  return "unknown"
}

export function statusLabel(status: unknown): string {
  const kind = statusKind(status)
  if (kind === "pass") return "PASS"
  if (kind === "fail") return "FAIL"
  if (kind === "not_applicable") return "NOT APPLICABLE"
  if (kind === "manual") return "Manual review"
  return UNKNOWN_LABEL
}

// ---- fact formatting --------------------------------------------------------------

const MAX_VALUE = 160

function clip(text: string): string {
  return text.length > MAX_VALUE ? text.slice(0, MAX_VALUE - 1) + "…" : text
}

// A collected value or expected value, shown in quotes. Never trusted as markup:
// React escapes it, and it is clipped so a huge collector string cannot flood the row.
export function quoteValue(value: unknown): string {
  if (typeof value === "string")
    return value === "" ? "'' (empty)" : `'${clip(value)}'`
  if (Array.isArray(value)) {
    if (!value.length) return "an empty list"
    return value.map(quoteValue).join(", ")
  }
  if (typeof value === "number" || typeof value === "boolean")
    return `'${String(value)}'`
  if (value == null) return "unknown"
  try {
    return `'${clip(JSON.stringify(value))}'`
  } catch {
    return "unknown"
  }
}

function name(value: unknown, fallback = "this setting"): string {
  return typeof value === "string" && value ? clip(value) : fallback
}

function version(value: unknown): string {
  return (typeof value === "number" && Number.isFinite(value)) ||
    (typeof value === "string" && /^[0-9]{1,3}$/.test(value))
    ? String(value)
    : "(unknown version)"
}

function joinAnd(items: string[]): string {
  if (items.length <= 1) return items.join("")
  return items.slice(0, -1).join(", ") + " and " + items[items.length - 1]
}

function list(value: unknown): string[] {
  return Array.isArray(value)
    ? value.map((v) => (typeof v === "string" ? v : String(v)))
    : typeof value === "string"
      ? [value]
      : []
}

// "logs are sent to syslog" / "log_destination is 'csvlog'": the condition a control
// depends on, written from the applies_when facts (setting_name, operator, expected).
export function conditionPhrase(facts: any): string {
  const setting = name(facts?.setting_name)
  const expected = facts?.expected
  switch (facts?.operator) {
    case "contains_items": {
      const items = list(expected)
      if (setting === "log_destination" && items.length)
        return `logs are sent to ${joinAnd(items.map((i) => clip(i)))}`
      return `${setting} includes ${joinAnd(items.map(quoteValue))}`
    }
    case "equals":
      return `${setting} is ${quoteValue(expected)}`
    case "not_equals":
      return `${setting} is not ${quoteValue(expected)}`
    case "in":
      return `${setting} is one of ${quoteValue(expected)}`
    case "not_in":
      return `${setting} is none of ${quoteValue(expected)}`
    case "no_item_in":
      return `${setting} lists none of ${quoteValue(expected)}`
    case "contains_escapes":
      return `${setting} uses ${joinAnd(list(expected).map(quoteValue))}`
    case "severity":
      return facts?.direction === "at_or_less_verbose"
        ? `${setting} is ${quoteValue(expected)} or less verbose`
        : `${setting} is ${quoteValue(expected)} or more verbose`
    default:
      return `a condition on ${setting} holds`
  }
}

// ---- evidence causes (shared by the check itself and by its condition) ------------

function evidenceSentence(code: string, facts: any): string | null {
  const setting = name(facts?.setting_name)
  switch (code) {
    case "not_collected": {
      if (facts?.entry_status === "section_unavailable") {
        const why =
          typeof facts?.gap_reason === "string" && facts.gap_reason
            ? ` (collector said: ${quoteValue(facts.gap_reason)})`
            : ""
        return `The collector could not read the server's settings at all${why}, so DBGuard has no value for ${setting} and can't say PASS. Fix the collector access and collect a new snapshot.`
      }
      if (facts?.entry_status === "not_collected")
        return `The collector marked ${setting} as not collected, so DBGuard has no value to check and can't say PASS. Check the collector ran with enough access, then collect a new snapshot.`
      return `This snapshot has no reading of ${setting}, so DBGuard can't say PASS. Collect a new snapshot with the current collector and check list.`
    }
    case "stale_spec_hash":
      return `This snapshot was collected for an older version of this control's rule, so its reading of ${setting} can't be trusted against the current rule and DBGuard can't say PASS. Collect a new snapshot with the current check list.`
    case "collector_error": {
      const detail =
        typeof facts?.error === "string" && facts.error
          ? `: ${quoteValue(facts.error)}`
          : ""
      return `The collector hit an error while reading ${setting}${detail}. DBGuard can't say PASS until it is read without errors.`
    }
    case "unit_or_non_text_value": {
      const unit =
        typeof facts?.unit === "string" && facts.unit
          ? ` It has the unit ${quoteValue(facts.unit)}`
          : ""
      const type =
        typeof facts?.vartype === "string" && facts.vartype
          ? `${unit ? " and" : " It has"} the type ${quoteValue(facts.vartype)}`
          : ""
      return `DBGuard got ${setting} in a form it can't compare as plain text, so it can't say PASS.${unit}${type}${
        unit || type ? "." : ""
      }`
    }
    case "uninterpretable_value":
      return `DBGuard read ${setting} as ${quoteValue(facts?.actual)} but couldn't interpret that value for this rule, so it can't say PASS. A person should check the value.`
    case "sanitised":
      return `DBGuard couldn't read ${setting} (it was hidden for safety), so it can't say PASS.`
    case "redacted_secret_setting":
      return "DBGuard deliberately never reads this setting's value because it can contain a secret, so it can't say PASS or FAIL; check it by hand."
    case "session_override": {
      const source =
        typeof facts?.source === "string" && facts.source
          ? ` (source ${quoteValue(facts.source)})`
          : ""
      return `The value of ${setting} DBGuard read is set for a role, a database or the session${source}, not for the whole server, so it may not be what the server and other sessions use. DBGuard can't say PASS or FAIL, and no sandbox fix can be tested on this snapshot while it is unknown. Check the server-wide value and pg_db_role_setting, remove the override if it is not wanted, then collect a new snapshot.`
    }
    default:
      return null
  }
}

// ---- one template per explanation code -------------------------------------------

type Template = (facts: any) => string | null

const TEMPLATES: Record<string, Template> = {
  condition_false: (f) =>
    `Only applies when ${conditionPhrase(f)}. This server's ${name(f?.setting_name)} is ${quoteValue(f?.actual)}, so it doesn't apply.`,
  condition_unknown: (f) => {
    const cause =
      typeof f?.cause === "string" ? evidenceSentence(f.cause, f) : null
    if (!cause) return null
    return `Only applies when ${conditionPhrase(f)}, and DBGuard couldn't confirm that. ${cause} So it can't tell whether this control applies.`
  },
  not_collected: (f) => evidenceSentence("not_collected", f),
  stale_spec_hash: (f) => evidenceSentence("stale_spec_hash", f),
  collector_error: (f) => evidenceSentence("collector_error", f),
  unit_or_non_text_value: (f) => evidenceSentence("unit_or_non_text_value", f),
  uninterpretable_value: (f) => evidenceSentence("uninterpretable_value", f),
  sanitised: (f) => evidenceSentence("sanitised", f),
  redacted_secret_setting: (f) =>
    evidenceSentence("redacted_secret_setting", f),
  session_override: (f) => evidenceSentence("session_override", f),
  wrong_pg_major: (f) =>
    `This rule is written for PostgreSQL ${version(f?.spec_pg_major)}, but the snapshot is from PostgreSQL ${version(f?.snapshot_pg_major)}, so DBGuard does not apply it and can't say PASS.`,
  policy_missing: (f) => {
    const profile =
      typeof f?.profile_id === "string" && f.profile_id
        ? quoteValue(f.profile_id)
        : "the selected profile"
    if (f?.case === "no_profile")
      return "This control checks a value your company must choose, and no approved policy profile is selected for this assessment, so DBGuard can't check it. Approve a profile on the Policy Profile screen and select it."
    if (f?.case === "profile_unapproved")
      return `The selected policy profile ${profile} has not been approved by a named person, so its values are not used and DBGuard can't check this control.`
    if (f?.case === "no_value_for_spec")
      return `The selected policy profile ${profile} has no value for this control, so DBGuard can't check it. Add a value in a new profile version and approve it.`
    return null
  },
  // F6 codes go here: section_not_collected, field_missing, manual_review,
  // databases_not_covered, empty_review_set, restore_test_reminder.
}

export const KNOWN_CODES = Object.keys(TEMPLATES)

// The sentence for one `explanation` object. Never throws, never returns empty.
export function explanationSentence(explanation: unknown): string {
  if (!explanation || typeof explanation !== "object")
    return GENERIC_UNKNOWN_SENTENCE
  const code = (explanation as any).code
  const template =
    typeof code === "string" &&
    Object.prototype.hasOwnProperty.call(TEMPLATES, code)
      ? TEMPLATES[code]
      : undefined
  if (!template) return GENERIC_UNKNOWN_SENTENCE
  try {
    return template(explanation) || GENERIC_UNKNOWN_SENTENCE
  } catch {
    return GENERIC_UNKNOWN_SENTENCE
  }
}

// ---- rows ----------------------------------------------------------------------

function recommendationOf(row: any): string {
  const rec = row?.cis?.recommendation
  if (typeof rec === "string" && rec) return rec
  const id = typeof row?.id === "string" ? row.id : row?.spec_id
  return typeof id === "string" && id.includes(":")
    ? id.slice(id.lastIndexOf(":") + 1)
    : ""
}

// "CIS 3.1.11: Ensure Syslog messages are not suppressed"
export function cisRule(row: any): string {
  const rec = recommendationOf(row)
  const title =
    (typeof row?.cis?.title === "string" && row.cis.title) ||
    (typeof row?.title === "string" && row.title) ||
    ""
  if (rec && title) return `CIS ${rec}: ${title}`
  if (rec) return `CIS ${rec}`
  return title || name(row?.id ?? row?.spec_id, "Unidentified control")
}

export function isPolicyMissing(row: any): boolean {
  return (
    row?.reason_code === "policy_missing" ||
    row?.explanation?.code === "policy_missing"
  )
}

// NOT_APPLICABLE, every unknown row, and every policy_missing row get a reason.
export function needsExplanation(row: any): boolean {
  const kind = statusKind(row?.status)
  return kind === "not_applicable" || kind === "unknown" || isPolicyMissing(row)
}

export type RowExplanation = {
  cis: string
  sentence: string
  quote: string | null
  unknown: boolean
  policyMissing: boolean
}

export function explainRow(row: any): RowExplanation | null {
  if (!needsExplanation(row)) return null
  const unknown = statusKind(row?.status) === "unknown"
  let sentence = explanationSentence(row?.explanation)
  // An unknown row always carries the label, even when the code is recognised.
  if (unknown && !sentence.startsWith(UNKNOWN_LABEL))
    sentence = `${UNKNOWN_LABEL}. ${sentence}`
  const quote = row?.explanation?.condition_quote
  return {
    cis: cisRule(row),
    sentence,
    quote: typeof quote === "string" && quote ? quote : null,
    unknown,
    policyMissing: isPolicyMissing(row),
  }
}

// "3.1.2" before "3.1.10": CIS numbering, not string order.
export function compareRecommendation(a: any, b: any): number {
  const pa = recommendationOf(a).split(".").map(Number)
  const pb = recommendationOf(b).split(".").map(Number)
  for (let i = 0; i < Math.max(pa.length, pb.length); i++) {
    const d = (pa[i] || 0) - (pb[i] || 0)
    if (d) return d
  }
  return 0
}

export function policyMissingRows(rows: any[]): any[] {
  return (rows ?? []).filter(isPolicyMissing).sort(compareRecommendation)
}
