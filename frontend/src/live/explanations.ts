// Plain-language sentences for assessment results, built ONLY from the structured
// `explanation` facts the backend returns (assess.py `_explain`, ASSESS spec_controls).
// Every sentence is a fixed template per code with the facts filled in; nothing here
// ever comes from model output. An unknown code, a missing fact or a malformed
// explanation falls back to a safe generic "Unknown: needs human review" sentence and
// is never presented as passing.
//
// Adding a code: add one entry to TEMPLATES below and one case to
// tests/explanations.test.mjs. Catalog checks (F6, 7.4) explain every result,
// PASS and FAIL included; their fixed notices (7.4's restore-test reminder) are
// rendered by Evidence.tsx, not here.
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

function count(value: unknown, one: string, many: string): string {
  const n = typeof value === "number" && Number.isFinite(value) ? value : 0
  return n === 1 ? `1 ${one}` : `${n} ${many}`
}

function hours(value: unknown): string {
  return typeof value === "number" && Number.isInteger(value) && value > 0
    ? String(value)
    : "the configured number of"
}

function time(value: unknown): string {
  return typeof value === "string" && value ? clip(value) : "an unknown time"
}

function list(value: unknown): string[] {
  return Array.isArray(value)
    ? value.map((v) => (typeof v === "string" ? v : String(v)))
    : typeof value === "string"
      ? [value]
      : []
}

// "'ddl', 'role' and 'write'", or the fallback when the list is empty or absent.
function quotedList(value: unknown, empty: string): string {
  const items = list(value).map(quoteValue)
  return items.length ? joinAnd(items) : empty
}

// The standard closing sentence of every GAPPED (unknown) reason.
export const UNKNOWN_NEVER_PASS = "Unknown never counts as a pass."

// CIS 6.8: the parts of "TLS enabled and enforced" that failed or could not be read.
const TLS_FAILING_PARTS: Record<string, string> = {
  ssl_off: "ssl is off, so the server accepts no encrypted connections",
  non_tls_hba_rules:
    "some login rules (type host or hostnossl) let clients log in over TCP without encryption",
  unencrypted_tcp_connections: "some current TCP connections are not encrypted",
}
const TLS_UNKNOWN_PARTS: Record<string, string> = {
  ssl: "the ssl setting",
  hba_rules: "the login rules (pg_hba.conf)",
  connections: "the encryption state of every current connection",
}

function partPhrases(
  value: unknown,
  phrases: Record<string, string>,
): string[] {
  return list(value).map((p) =>
    Object.prototype.hasOwnProperty.call(phrases, p)
      ? phrases[p]
      : `an unrecognised part ${quoteValue(p)}`,
  )
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
  // ---- catalog checks (F6 roles and privileges, 7.4 WAL archiving) ----
  section_not_collected: (f) => {
    if (typeof f?.section !== "string" || !f.section) return null
    const why =
      typeof f?.gap_reason === "string" && f.gap_reason
        ? ` (collector said: ${quoteValue(f.gap_reason)})`
        : ""
    return `The collector could not read ${quoteValue(f?.section)} from this database${why}, so DBGuard cannot judge this control and can't say PASS.`
  },
  field_missing: (f) =>
    typeof f?.section !== "string" ||
    !f.section ||
    typeof f?.field !== "string" ||
    !f.field
      ? null
      : `The snapshot has no ${quoteValue(f?.field)} in ${quoteValue(f?.section)}, so DBGuard cannot judge this control and can't say PASS.`,
  manual_review: (f) => {
    const base =
      typeof f?.evidence_count === "number" && f.evidence_count > 0
        ? `CIS leaves this decision to a person. Review the ${count(f.evidence_count, "item", "items")} listed below.`
        : "CIS leaves this decision to a person. Nothing matched, but CIS still asks someone to confirm."
    // 5.3 / 5.4 login-rule checklists: rules with a highlight tag.
    const highlighted =
      typeof f?.highlight_count === "number" && f.highlight_count > 0
        ? ` ${count(f.highlight_count, "of them is", "of them are")} highlighted for a closer look.`
        : ""
    return base + highlighted
  },
  databases_not_covered: (f) =>
    `The snapshot only covers the database DBGuard connected to. Check these databases too: ${
      joinAnd(list(f?.databases).map((d) => clip(d))) || "none listed"
    }. ${count(f?.evidence_count, "item", "items")} from the connected database ${
      f?.evidence_count === 1 ? "is" : "are"
    } listed below.`,
  empty_review_set: () =>
    "CIS asks a person to review each matching item, and nothing matched, so there is nothing to review.",
  unlimited_connections: (f) =>
    `${count(f?.role_count, "login role has", "login roles have")} no connection limit (-1). CIS counts any such account as a failure.`,
  connection_limits_set: () =>
    "Every login role in scope has a connection limit.",
  archive_mode_off: (f) =>
    `WAL archiving is off (archive_mode is ${quoteValue(f?.archive_mode)}). CIS requires it to be on.`,
  archive_destination_missing: () =>
    "archive_mode is on, but neither archive_command nor archive_library is set, so nothing is archived.",
  archive_destination_conflict: () =>
    "Both archive_command and archive_library are set. PostgreSQL refuses to archive in that case.",
  archive_latest_failed: (f) =>
    `The most recent archive attempt failed (last failure ${time(f?.last_failed_time)}, last success ${
      typeof f?.last_archived_time === "string" && f.last_archived_time
        ? clip(f.last_archived_time)
        : "never"
    }).`,
  archive_standby: () =>
    "This server is a standby. Check archiving on the primary, or confirm how this standby is meant to archive.",
  archive_never_run: () =>
    "Archiving is configured, but no WAL file has been archived yet and none has failed. Check again once the server has written some WAL.",
  archive_stats_reset_recent: (f) =>
    `The archiver statistics were reset at ${time(f?.stats_reset)}, within the last ${hours(f?.max_age_hours)} hours, and nothing has been archived since, so DBGuard cannot tell whether archiving works.`,
  archive_timestamp_missing: (f) =>
    `The archiver reports archived files but no time for the last one (${quoteValue(f?.field)}).`,
  archive_timestamp_after_collection: (f) =>
    `The last archive time is later than the snapshot time (${time(f?.collected_at)}). Check the server clock and collect again.`,
  archive_older_than_max_age: (f) =>
    `The last successful archive was at ${time(f?.last_archived_time)}, more than ${hours(f?.max_age_hours)} hours before this snapshot (${time(f?.collected_at)}). On a quiet database this can be normal; otherwise check the archiver.`,
  archive_recent: (f) =>
    `The last successful archive was at ${time(f?.last_archived_time)}, within ${hours(f?.max_age_hours)} hours of the snapshot, with no later failure.`,
  // ---- Wave 2b: add-ons (3.2 pgaudit, 5.6 passwordcheck, 4.8 set_user) ----
  preload_list_unparseable: () =>
    "DBGuard could not read the list in shared_preload_libraries for certain (it uses quoting, path parts or characters DBGuard does not interpret), so it can't tell whether the add-on this rule needs is loaded. A person must check the list.",
  pgaudit_not_preloaded: () =>
    "The pgaudit audit logger is not in shared_preload_libraries, so it is not loaded and database activity is not audited. CIS requires pgaudit to be loaded.",
  pgaudit_log_missing: () =>
    "pgaudit is in shared_preload_libraries, but the server has no pgaudit.log setting, so nothing is being audited. pgaudit may not be installed, or the server has not been restarted since the list changed. CIS requires pgaudit.log to name the activity to audit.",
  pgaudit_log_unparseable: () =>
    "DBGuard could not read pgaudit.log for certain (it has a word or list syntax DBGuard does not interpret), so it can't tell which activity is audited. A person must check the value.",
  pgaudit_log_classes_missing: (f) =>
    `pgaudit.log audits ${quotedList(f?.effective_classes, "nothing")}, but your company policy requires ${quotedList(f?.policy_classes, "certain classes")}. Missing: ${quotedList(f?.missing_classes, "unknown")}. CIS requires pgaudit.log to cover the activity your company chose to audit.`,
  pgaudit_log_classes_present: (f) =>
    `pgaudit is loaded and pgaudit.log audits ${quotedList(f?.effective_classes, "the configured classes")}, which covers every class your company policy requires (${quotedList(f?.policy_classes, "as approved")}).`,
  passwordcheck_not_preloaded: () =>
    "The passwordcheck module is not in shared_preload_libraries, so PostgreSQL does not check new passwords for complexity. CIS requires passwordcheck to be loaded.",
  dynamic_library_path_not_libdir: (f) =>
    `passwordcheck is loaded by its bare name, but dynamic_library_path is ${quoteValue(f?.dynamic_library_path)} instead of '$libdir', so PostgreSQL may load a different library called passwordcheck from another folder. CIS requires dynamic_library_path to be '$libdir'.`,
  libdir_form_with_custom_library_path: (f) =>
    `passwordcheck is loaded as '$libdir/passwordcheck', so the standard module is used, but dynamic_library_path is ${quoteValue(f?.dynamic_library_path)} instead of '$libdir'. CIS expects '$libdir'; a person should confirm the custom path is intended.`,
  passwordcheck_preloaded: () =>
    "passwordcheck is loaded and dynamic_library_path is '$libdir', so new passwords are checked for complexity as CIS requires.",
  set_user_not_available: () =>
    "The set_user extension is not available on this server, so superuser access cannot be routed through it and logged. CIS requires set_user to be installed; installing the package is a server change the DBA makes.",
  superuser_login_review: (f) => {
    const n =
      typeof f?.evidence_count === "number" && f.evidence_count > 1
        ? f.evidence_count - 1
        : 0
    const installed =
      typeof f?.installed_version === "string" && f.installed_version
        ? `installed (version ${clip(f.installed_version)})`
        : "available but not installed"
    const where =
      typeof f?.database === "string" && f.database
        ? ` in the database ${quoteValue(f.database)}`
        : ""
    return `The set_user extension is ${installed}${where}. CIS leaves it to a person to decide which login accounts may hold superuser powers. Review the ${count(n, "login account", "login accounts")} listed below, which hold them directly or through a role they belong to.`
  },
  // ---- Wave 2b: login and encryption (6.10 ciphers, 6.8 TLS) ----
  unapproved_ciphers_configured: (f) =>
    `ssl_ciphers allows ciphers outside the four CIS approves for TLS 1.2: ${quotedList(f?.other_items, "unknown")}. Older, weaker ciphers make encrypted traffic easier to break. CIS requires ssl_ciphers to list only the four approved ciphers.`,
  unapproved_cipher_in_use: (f) =>
    `${count(f?.connection_count, "current connection uses", "current connections use")} TLS 1.2 with a cipher CIS does not approve: ${quotedList(f?.ciphers, "unknown")}. CIS requires every TLS 1.2 connection to use one of the four approved ciphers.`,
  connections_not_visible: (f) => {
    const hidden =
      typeof f?.hidden_connection_count === "number" &&
      f.hidden_connection_count > 0
        ? `${count(f.hidden_connection_count, "session belongs", "sessions belong")} to other accounts and ${
            f.hidden_connection_count === 1 ? "was" : "were"
          } hidden from the collecting account`
        : ""
    const tls =
      f?.tls_details_gap === true
        ? "the collector could not read the encryption details of other sessions"
        : ""
    const why = [hidden, tls].filter(Boolean).join("; ")
    return `DBGuard could not see whether every connection is encrypted${
      why ? `: ${why}` : ""
    }. The collecting account needs the pg_read_all_stats role (or pg_monitor, which includes it) to see other sessions. Grant it and collect a new snapshot. ${UNKNOWN_NEVER_PASS}`
  },
  ssl_ciphers_empty: () =>
    "ssl_ciphers is empty, so DBGuard can't tell which ciphers the server allows. A person must check the server's TLS cipher settings.",
  approved_ciphers_only: () =>
    "ssl_ciphers lists only the four ciphers CIS approves for TLS 1.2, and no visible TLS 1.2 connection uses another cipher.",
  tls_not_enabled_or_enforced: (f) => {
    const failing = partPhrases(f?.failing_parts, TLS_FAILING_PARTS)
    const unknown = partPhrases(f?.unknown_parts, TLS_UNKNOWN_PARTS)
    // Parts are joined with "; " because each phrase may contain a comma.
    const what = failing.length ? `: ${failing.join("; ")}` : ""
    const alsoUnknown = unknown.length
      ? ` DBGuard also could not read ${joinAnd(unknown)}.`
      : ""
    return `Encryption (TLS) is not fully switched on and required${what}. CIS requires ssl to be on, only hostssl login rules for TCP, and every TCP connection to be encrypted.${alsoUnknown}`
  },
  gss_hba_rules: (f) =>
    `${count(f?.rule_count, "login rule uses", "login rules use")} a GSSAPI encryption type (hostgssenc or hostnogssenc). CIS's check does not cover these, so a person must decide whether these logins are encrypted as required.`,
  hba_rule_error: (f) =>
    `${count(f?.rule_count, "line", "lines")} in the login rules file (pg_hba.conf) ${
      f?.rule_count === 1 ? "has" : "have"
    } an error, so DBGuard can't tell what ${
      f?.rule_count === 1 ? "it allows" : "they allow"
    }. A person must check or fix ${f?.rule_count === 1 ? "it" : "them"}.`,
  tls_enabled_and_enforced: () =>
    "ssl is on, every TCP login rule requires encryption (hostssl), and every visible TCP connection is encrypted.",
}

// ---- 5.3 / 5.4 evidence highlights ---------------------------------------------

// Fixed sentences for the `highlights` codes on 5.3 / 5.4 login-rule evidence rows.
// Highlights are emphasis only: the result stays a person's decision.
export const HIGHLIGHT_SENTENCES: Record<string, string> = {
  auth_method_not_peer_or_reject:
    "Not peer or reject: CIS calls peer the most secure method for local logins.",
  auth_method_not_for_remote:
    "trust, password or ident: CIS says these are not to be used for remote logins.",
  auth_method_md5: "md5: CIS recommends scram-sha-256 instead.",
  any_address: "Open to every address (0.0.0.0/0, ::/0 or all).",
  line_error:
    "This line has an error, so its type and method can't be trusted.",
}
export const UNKNOWN_HIGHLIGHT_SENTENCE = "Highlighted for a closer look."

// The fixed sentences for one evidence item's highlights (empty when it has none).
export function highlightSentences(item: unknown): string[] {
  const codes = (item as any)?.highlights
  if (!Array.isArray(codes)) return []
  return codes.map((code) =>
    typeof code === "string" &&
    Object.prototype.hasOwnProperty.call(HIGHLIGHT_SENTENCES, code)
      ? HIGHLIGHT_SENTENCES[code]
      : UNKNOWN_HIGHLIGHT_SENTENCE,
  )
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

// Catalog rows carry an explanation on every result (PASS and FAIL included).
export function isCatalogRow(row: any): boolean {
  return Array.isArray(row?.evidence_paths) || row?.kind === "catalog"
}

// NOT_APPLICABLE, every unknown row, every policy_missing row and every catalog
// row get a reason.
export function needsExplanation(row: any): boolean {
  const kind = statusKind(row?.status)
  return (
    kind === "not_applicable" ||
    kind === "unknown" ||
    isPolicyMissing(row) ||
    isCatalogRow(row)
  )
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
