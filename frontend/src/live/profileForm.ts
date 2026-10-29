// Pure helpers for the Policy Profile screen. No React and no "@/" imports, so
// node --test can load this file directly.
//
// The backend is the only validator: these helpers only reshape what the user typed
// into the draft body (create_draft / validate) and sort the backend's error strings
// next to the field they mention. Hints shown here are hints, never rules.

export const DEMO_APPROVAL_LABEL = "DEMO approval: no sign-in"

// Operators whose expected value is a list (typed as comma-separated text).
const LIST_OPERATORS = [
  "in",
  "not_in",
  "contains_items",
  "contains_escapes",
  "no_item_in",
]

export function isListOperator(operator: unknown): boolean {
  return typeof operator === "string" && LIST_OPERATORS.includes(operator)
}

// Plain-language description of what each setting does (UI copy, reviewed text).
export const SETTING_HELP: Record<string, string> = {
  log_destination:
    "Where PostgreSQL writes its log messages: stderr (standard error, usually captured to files), csvlog (CSV files), jsonlog (JSON files) or syslog (the operating system's log service). Several can be listed, separated by commas.",
  log_directory:
    "The folder log files are written to when the logging collector is on. Keeping logs outside the database data directory (PGDATA) protects them if the data directory is restored or replaced.",
  log_filename:
    "The name pattern for log files. % codes are replaced by the date and time; for example %a is the weekday, so postgresql-%a.log keeps one file per weekday.",
  log_file_mode:
    "The file permissions of new log files, as an octal number. 0600 means only the PostgreSQL server account can read them; 0640 also lets its group read them.",
  log_rotation_age:
    "How long one log file is used before PostgreSQL starts a new one, for example 1d (daily) or 1h (hourly). 0 turns time-based rotation off.",
  log_rotation_size:
    "How large one log file can grow before PostgreSQL starts a new one, for example 1GB. 0 turns size-based rotation off.",
  syslog_facility:
    "Which syslog facility (LOCAL0 to LOCAL7) PostgreSQL's messages are tagged with when logs go to syslog. Your syslog server uses it to route the messages.",
  syslog_ident:
    "The program name shown on PostgreSQL's syslog messages, so they can be told apart from other programs and other PostgreSQL servers.",
  log_timezone:
    "The time zone used for timestamps in the server log. Using one zone, such as UTC, on every server makes logs easy to line up.",
  listen_addresses:
    "The network addresses PostgreSQL accepts connections on. '*' or 0.0.0.0 means every network interface, which CIS treats as a failure.",
}

export function settingHelp(control: any): string {
  const help = SETTING_HELP[control?.setting_name]
  if (help) return help
  return typeof control?.reason === "string" && control.reason
    ? control.reason
    : "No plain-language description is available for this setting yet."
}

// Character hints per setting, mirroring docs/CONTRACTS.md (setting_values.py). The
// server enforces the real rule; this is only shown under the field.
const VALUE_HINTS: Record<string, string> = {
  log_destination: "lower-case names separated by commas, e.g. stderr, csvlog",
  log_directory:
    "an absolute or relative path of letters, digits, _ . - separated by /; no .. segment",
  log_filename: "letters, digits, %, -, _ and .",
  log_file_mode: "0 followed by three octal digits, e.g. 0600",
  log_rotation_age: "digits with an optional unit: us ms s min h d",
  log_rotation_size: "digits with an optional unit: B kB MB GB TB",
  log_timezone: "time zone names such as UTC, Etc/UTC or America/New_York",
  listen_addresses:
    "localhost plus IP addresses (IPv4 as four decimal numbers, e.g. 10.0.0.5) and host names starting with a letter, separated by commas; no 0.0.0.0, and never * or ::",
  syslog_facility: "local0 to local7",
  syslog_ident: "1 to 63 letters, digits, _, . and -",
}

export function shapeHint(control: any): string {
  const hint = VALUE_HINTS[control?.setting_name]
  if (control?.kind === "site_fix") {
    const forbidden = Array.isArray(control?.expected)
      ? control.expected.map((v: unknown) => `'${String(v)}'`).join(" or ")
      : ""
    const rule = forbidden
      ? `The fix value must pass the CIS check, so it must not contain ${forbidden}.`
      : "The fix value must pass the CIS check."
    return hint ? `${rule} Characters: ${hint}.` : rule
  }
  const op = control?.operator
  const shape =
    op === "contains_items"
      ? "A list of required items, separated by commas. PASS when every item is among the server's values (others may also be present)."
      : op === "equals"
        ? "One exact value. PASS only when the server's value is exactly this."
        : op === "in"
          ? "A list of acceptable values, separated by commas. PASS when the server's value is exactly one of them."
          : op === "not_in"
            ? "A list of forbidden values, separated by commas. PASS when the server's value is none of them."
            : op === "not_equals"
              ? "One value the setting must not have."
              : op === "no_item_in"
                ? "A list of forbidden entries. PASS when none of the server's entries is one of them."
                : op === "severity"
                  ? "One log level on PostgreSQL's fixed scale."
                  : "The shape the server accepts for this check."
  return hint ? `${shape} Characters: ${hint}.` : shape
}

export function expectedToText(expected: unknown): string {
  if (Array.isArray(expected)) return expected.map(String).join(", ")
  return expected == null ? "" : String(expected)
}

export function textToExpected(operator: unknown, text: string): any {
  if (!isListOperator(operator)) return text.trim()
  return text
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean)
}

// ---- form state ----------------------------------------------------------------

export type ValueForm = {
  expected: string
  fix: string
  brk: string
}

export type RoleLimitForm = {
  name: string
  limit: string
  superuser: boolean
  current: string
}

export type ProfileForm = {
  profileId: string
  basedOn: string | null
  values: Record<string, ValueForm>
  fixes: Record<string, string>
  defaultLimit: string
  roles: RoleLimitForm[]
}

// Login roles from the current snapshot (collector `roles` section), for the
// connection-limit overrides. Predefined pg_ roles cannot log in and are skipped.
export function loginRoles(snapshot: any): RoleLimitForm[] {
  const roles = Array.isArray(snapshot?.roles) ? snapshot.roles : []
  return roles
    .filter(
      (r: any) =>
        r &&
        r.rolcanlogin === true &&
        typeof r.rolname === "string" &&
        r.rolname &&
        r.is_predefined !== true &&
        !r.rolname.toLowerCase().startsWith("pg_"),
    )
    .map((r: any) => ({
      name: r.rolname,
      limit: "",
      superuser: r.rolsuper === true,
      current:
        typeof r.rolconnlimit === "number"
          ? r.rolconnlimit < 0
            ? "no limit"
            : String(r.rolconnlimit)
          : "unknown",
    }))
}

export function formFromProfile(
  controls: any[],
  doc: any,
  basedOn: string | null,
  snapshot: any,
): ProfileForm {
  const values: Record<string, ValueForm> = {}
  const fixes: Record<string, string> = {}
  for (const c of controls ?? []) {
    if (c?.kind === "policy_value") {
      const v = doc?.values?.[c.spec_id]
      values[c.spec_id] = {
        expected: expectedToText(v?.expected),
        fix: v?.fix == null ? "" : String(v.fix),
        brk: v?.break == null ? "" : String(v.break),
      }
    } else if (c?.kind === "site_fix") {
      const v = doc?.fixes?.[c.spec_id]
      fixes[c.spec_id] = v == null ? "" : String(v)
    }
  }
  const limits = doc?.connection_limits
  const saved: Record<string, unknown> =
    limits?.roles && typeof limits.roles === "object" ? limits.roles : {}
  const roles = loginRoles(snapshot)
  for (const role of roles)
    if (saved[role.name] != null) role.limit = String(saved[role.name])
  for (const [roleName, limit] of Object.entries(saved))
    if (!roles.some((r) => r.name === roleName))
      roles.push({
        name: roleName,
        limit: String(limit),
        superuser: false,
        current: "not in this snapshot",
      })
  return {
    profileId: typeof doc?.profile_id === "string" ? doc.profile_id : "",
    basedOn,
    values,
    fixes,
    defaultLimit:
      limits?.default_login_limit == null
        ? ""
        : String(limits.default_login_limit),
    roles,
  }
}

// A whole number is sent as a number; anything else is sent as typed so the
// backend's own error message explains it.
function limitValue(text: string): any {
  const t = text.trim()
  return /^-?[0-9]+$/.test(t) ? Number(t) : t
}

export function draftBody(form: ProfileForm, controls: any[]): any {
  const values: Record<string, any> = {}
  const fixes: Record<string, string> = {}
  for (const c of controls ?? []) {
    if (c?.kind === "policy_value") {
      const v = form.values[c.spec_id]
      if (!v || (!v.expected.trim() && !v.fix.trim() && !v.brk.trim())) continue // left blank: no value, so the control stays policy_missing
      values[c.spec_id] = {
        expected: textToExpected(c.operator, v.expected),
        fix: v.fix.trim(),
        break: v.brk.trim(),
      }
    } else if (c?.kind === "site_fix") {
      const v = (form.fixes[c.spec_id] ?? "").trim()
      if (v) fixes[c.spec_id] = v
    }
  }
  const roles: Record<string, any> = {}
  for (const r of form.roles)
    if (r.name.trim() && r.limit.trim())
      roles[r.name.trim()] = limitValue(r.limit)
  const hasLimits = !!form.defaultLimit.trim() || Object.keys(roles).length > 0
  return {
    profile_id: form.profileId.trim(),
    values,
    fixes: Object.keys(fixes).length ? fixes : null,
    connection_limits: hasLimits
      ? {
          default_login_limit: form.defaultLimit.trim()
            ? limitValue(form.defaultLimit)
            : null,
          roles,
        }
      : null,
    based_on: form.basedOn,
  }
}

// ---- backend errors --------------------------------------------------------------

// FastAPI 422 detail: a string (ProfileStoreError) or a pydantic error list.
export function errorsFromDetail(detail: unknown): string[] {
  if (typeof detail === "string") return detail ? [detail] : []
  if (Array.isArray(detail))
    return detail.map((d: any) => {
      const where = Array.isArray(d?.loc)
        ? d.loc.filter((p: any) => p !== "body").join(".")
        : ""
      const msg = typeof d?.msg === "string" ? d.msg : JSON.stringify(d)
      return where ? `${where}: ${msg}` : msg
    })
  if (detail && typeof detail === "object") return [JSON.stringify(detail)]
  return []
}

export type GroupedErrors = {
  bySpec: Record<string, string[]>
  profileId: string[]
  connection: string[]
  general: string[]
}

// Puts each backend message next to the control or section it names.
export function groupErrors(
  errors: string[],
  specIds: string[],
): GroupedErrors {
  const grouped: GroupedErrors = {
    bySpec: {},
    profileId: [],
    connection: [],
    general: [],
  }
  for (const e of errors ?? []) {
    const text = String(e)
    const spec = specIds.find((id) => text.includes(`'${id}'`))
    if (spec) (grouped.bySpec[spec] ??= []).push(text)
    else if (text.includes("connection_limits")) grouped.connection.push(text)
    else if (text.includes("profile_id")) grouped.profileId.push(text)
    else grouped.general.push(text)
  }
  return grouped
}

// ---- display ---------------------------------------------------------------------

export function shortSha(sha: unknown): string {
  return typeof sha === "string" && sha ? sha.slice(0, 12) : "none"
}

export function isApproved(summary: any): boolean {
  return (
    summary?.status === "approved" &&
    typeof summary?.approved_by === "string" &&
    !!summary.approved_by.trim()
  )
}

// The pin the backend recorded for this assessment (`policy_profile` on the
// spec-assessment response, or upstream_report.inputs.policy_profile).
export function assessmentProfilePin(assessment: any): any {
  if (!assessment) return undefined
  if (assessment.policy_profile !== undefined) return assessment.policy_profile
  return assessment?.assessment?.upstream_report?.inputs?.policy_profile
}

export function profileRefQuery(ref: unknown): string {
  return typeof ref === "string" && /^[0-9a-f]{64}$/.test(ref)
    ? `&policy_profile=${ref}`
    : ""
}
