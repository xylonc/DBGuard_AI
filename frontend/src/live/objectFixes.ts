// Per-object fixes for the account and permission checks (Wave 2a, Gate 1 E).
//
// The fix plan's `object_proposals` come from services/sandbox_poc/object_fixes.py,
// derived only from collected evidence and the approved policy profile. This module
// turns them into plain sentences and request bodies:
//
// - every note is shown through a FIXED sentence keyed by its `code` (never the
//   backend's free text and never model output); an unknown code gets a safe
//   generic sentence that asks a person to review it;
// - a request carries only the proposal's `fix_id`. Params, targets and values are
//   never sent: the server re-derives them (object_fixes.resolve).
//
// Adding a note code: add it to NOTE_SENTENCES and to OBJECT_NOTE_CODES in
// tests/objectFixes.test.mjs (that list mirrors object_fixes.NOTE_TEXTS).
// This file must stay free of React and "@/" imports so node --test can load it.

export const OBJECT_FIX_ID_RE =
  /^fix-[0-9]+(?:\.[0-9]+)*-(?:role_connection_limit|role_drop_attribute|role_nologin|function_security_invoker|function_revoke_public_execute|table_revoke_dml)-[0-9a-f]{10}$/

export function isObjectFixId(value: unknown): boolean {
  return typeof value === "string" && OBJECT_FIX_ID_RE.test(value)
}

// One fixed sentence per note code in object_fixes.NOTE_TEXTS.
export const NOTE_SENTENCES: Record<string, string> = {
  bootstrap_superuser:
    "This is the cluster's first superuser (usually postgres). DBGuard never offers a fix for it, because removing its powers or login could lock everyone out.",
  collecting_role:
    "DBGuard collects evidence with this account, so it does not offer to stop it logging in or remove its powers: the next collection must still work.",
  collecting_role_unknown:
    "The snapshot does not say which account collected it, so DBGuard offers no fixes that stop an account logging in or remove its powers for this check.",
  superuser_limit_not_enforced:
    "Superuser: limit not enforced; remove SUPERUSER first (fix #2). PostgreSQL ignores connection limits for superusers, so no limit is offered for this account until SUPERUSER is removed (see CIS 4.3 or 4.9).",
  policy_missing:
    "COMPANY POLICY MISSING: set connection limits on the Policy Profile screen and approve the profile. Until then DBGuard does not know which limit to propose.",
  evidence_not_collected:
    "The evidence this check needs was not collected, so no fix is offered. Collect a new snapshot first.",
  extension_owned:
    "Owned by an extension, which manages it. DBGuard never offers a fix for it.",
  extension_evidence_missing:
    "The snapshot cannot show whether these tables belong to an extension (extensions were not collected), so no table fix is offered.",
  possibly_extension_owned:
    "An extension is installed in this table's schema and the snapshot cannot show whether the table belongs to it, so no fix is offered.",
  system_schema:
    "A function in a system schema. DBGuard never offers a fix for it.",
  not_a_function:
    "Not a plain function (a procedure, aggregate or window function), so no fix is offered.",
  grantor_not_owner:
    "Granted by a role other than the owner. A REVOKE by the DBA would not remove it, so no fix is offered; review it by hand.",
  dependent_grants:
    "This grantee passed the privilege on to others. Revoking it would need CASCADE, which DBGuard does not offer; review it by hand.",
  predefined_role: "A built-in pg_ role. DBGuard never offers a fix for it.",
  ambiguous_grantee:
    "A role literally named PUBLIC cannot be told apart from PUBLIC safely; review it by hand.",
}

export const UNKNOWN_NOTE_SENTENCE =
  "Unknown: needs human review. DBGuard has a note for this check that this screen cannot explain, so a person must review it."

export const POLICY_MISSING_CODE = "policy_missing"

export function noteSentence(code: unknown): string {
  return typeof code === "string" &&
    Object.prototype.hasOwnProperty.call(NOTE_SENTENCES, code)
    ? NOTE_SENTENCES[code]
    : UNKNOWN_NOTE_SENTENCE
}

// ---- labels -----------------------------------------------------------------------

const MAX_NAME = 120

function text(value: unknown): string | null {
  if (typeof value !== "string" || !value) return null
  return value.length > MAX_NAME ? value.slice(0, MAX_NAME - 1) + "…" : value
}

// "role app_admin", "function public.f(integer)", "table public.t (grantee web)".
export function targetLabel(target: unknown): string | null {
  if (!target || typeof target !== "object") return null
  const t = target as Record<string, unknown>
  const role = text(t.role)
  if (role) return `account ${role}`
  const schema = text(t.schema)
  const fn = text(t.name)
  if (schema && fn)
    return `function ${schema}.${fn}(${text(t.identity_args) ?? ""})`
  const table = text(t.table)
  if (schema && table) {
    const grantee = text(t.grantee)
    return `table ${schema}.${table}${
      grantee ? ` (granted to ${grantee})` : ""
    }`
  }
  return null
}

// Facts a note may carry, as one short plain line (or null).
export function noteDetail(note: any): string | null {
  if (!note || typeof note !== "object") return null
  if (note.code === POLICY_MISSING_CODE && Array.isArray(note.roles)) {
    const roles = note.roles.map(text).filter(Boolean)
    if (roles.length) return `Accounts waiting for a limit: ${roles.join(", ")}`
  }
  if (note.code === "extension_owned" && text(note.extension))
    return `Extension: ${text(note.extension)}`
  return null
}

export type RiskLevel = "low" | "medium" | "high" | "not_assessed"

export function riskLevel(risk: unknown): RiskLevel {
  return risk === "low" || risk === "medium" || risk === "high"
    ? risk
    : "not_assessed"
}

export function riskLabel(risk: unknown): string {
  const level = riskLevel(risk)
  return level === "not_assessed" ? "Risk not assessed" : `${level} risk`
}

// Where a 5.5 connection limit comes from.
export function limitSourceLabel(limitSource: any): string | null {
  if (!limitSource || typeof limitSource !== "object") return null
  const profile = text(limitSource.profile?.profile_id)
  const from = profile
    ? `your approved company policy "${profile}"`
    : "your approved company policy"
  if (limitSource.source === "role")
    return `From ${from}: a limit set for this account.`
  if (limitSource.source === "default_login_limit")
    return `From ${from}: the default limit for login accounts.`
  return "Unknown: needs human review. The source of this limit is not recognised."
}

function rolconnlimit(value: unknown): string {
  if (value === -1) return "unlimited"
  if (typeof value === "number" && Number.isInteger(value)) return String(value)
  return "unknown"
}

// What one proposal changes, from its type and the server-derived target/params/prior.
// Display only; none of these values is ever sent back.
export function changeSummary(proposal: any): string {
  const p = proposal ?? {}
  const t = p.target ?? {}
  switch (p.fix_type) {
    case "role_connection_limit": {
      const limit = p.params?.connection_limit
      return `Connection limit of ${text(t.role) ?? "the account"}: ${rolconnlimit(p.prior?.rolconnlimit)} → ${
        typeof limit === "number" ? limit : "unknown"
      }`
    }
    case "role_drop_attribute":
      return `${text(t.attribute) ?? "Attribute"} on ${text(t.role) ?? "the account"}: yes → no`
    case "role_nologin":
      return `Login for ${text(t.role) ?? "the account"}: allowed → not allowed`
    case "function_security_invoker":
      return "Runs as: the function's owner (SECURITY DEFINER) → the caller (SECURITY INVOKER)"
    case "function_revoke_public_execute":
      return "EXECUTE for PUBLIC (every account): granted → revoked"
    case "table_revoke_dml": {
      const privileges = Array.isArray(t.privileges)
        ? t.privileges.map(text).filter(Boolean).join(", ")
        : "write privileges"
      return `${privileges} for ${text(t.grantee) ?? "the grantee"}${
        t.grant_option ? " (with grant option)" : ""
      }: granted → revoked`
    }
    default:
      return "Unknown change: needs human review"
  }
}

// Two proposals for the same change (e.g. "Remove SUPERUSER" under 4.3 and 4.9)
// cannot run together; the server refuses them, so the UI warns first.
export function changeKey(proposal: any): string {
  const t = proposal?.target ?? {}
  const sorted = Object.keys(t)
    .sort()
    .map((k) => [k, t[k]])
  return JSON.stringify([proposal?.fix_type ?? null, sorted])
}

// ---- requests ---------------------------------------------------------------------

// The shared, non-fix fields of a PrepareRequest.
export type PrepareBase = {
  snapshot_id: string
  benchmark_id: string
  environment: string
  evidence_ids: string[]
  policy_profile: string | null
}

// PrepareRequest for one object fix. Only the id: no params, target, control_id or
// retry settings (object fixes run once with their approved template).
export function objectFixRequest(
  base: PrepareBase,
  templateVersion: number,
  fixId: string,
) {
  if (!isObjectFixId(fixId)) throw new Error("Not a per-object fix id")
  return {
    snapshot_id: base.snapshot_id,
    benchmark_id: base.benchmark_id,
    environment: base.environment,
    evidence_ids: base.evidence_ids,
    policy_profile: base.policy_profile,
    template_version: templateVersion,
    object_fix_id: fixId,
  }
}

export type SettingOptions = {
  templateVersion: number
  retryMode: string
}

// ---- W2B: catalog fixes that change shared_preload_libraries (3.2, 5.6) -----------

const PRELOAD_SETTING = "shared_preload_libraries"

// True for a fix-plan entry whose changes include shared_preload_libraries; only
// these are rendered with the server-only set_config_list template.
export function needsListTemplate(fix: any): boolean {
  return (
    fix?.kind === "catalog_setting" &&
    Array.isArray(fix?.settings) &&
    fix.settings.includes(PRELOAD_SETTING)
  )
}

// The plan's approved set_config_list version for this control, or null: null when
// the control's fix does not change shared_preload_libraries (prepare refuses the
// field for anything else) or the server could not read the registry.
export function listTemplateVersionFor(
  plan: any,
  controlId: string,
): number | null {
  const fix = (
    Array.isArray(plan?.recommended_order) ? plan.recommended_order : []
  ).find((f: any) => f?.spec_id === controlId)
  if (!needsListTemplate(fix)) return null
  const version = plan?.list_template_version
  return Number.isInteger(version) && version > 0 ? version : null
}

// The set_config_list version chosen with a preload fix for the single-fix test. It
// belongs to the control, snapshot and profile it was planned for.
export type ChosenListTemplate = {
  control_id: string
  snapshot_id: string
  profile_ref: string | null
  version: number
}

export function chooseListTemplate(
  plan: any,
  controlId: string,
  snapshotId: string,
  profileRef: string | null,
): ChosenListTemplate | null {
  const version = listTemplateVersionFor(plan, controlId)
  return version == null
    ? null
    : {
        control_id: controlId,
        snapshot_id: snapshotId,
        profile_ref: profileRef,
        version,
      }
}

// The version to send with the single-fix prepare request, or null when the chosen
// one belongs to another control, snapshot or profile (or none was chosen).
export function activeListTemplateVersion(s: any): number | null {
  const chosen = s?.listTemplate
  return chosen &&
    chosen.control_id === s?.controlId &&
    chosen.snapshot_id === s?.snapshot?.snapshot_id &&
    chosen.profile_ref === (s?.policyProfile?.profile_ref ?? null) &&
    Number.isInteger(chosen.version) &&
    chosen.version > 0
    ? chosen.version
    : null
}

// True when the plan links this control to a catalog setting fix (3.2, 5.6, 6.10).
// The server runs those once with the approved template: no adaptive retries or
// alternative templates, so their requests always say retry_mode "repeat".
export function isCatalogLinkedFix(plan: any, controlId: string): boolean {
  return (
    Array.isArray(plan?.recommended_order) ? plan.recommended_order : []
  ).some((f: any) => f?.spec_id === controlId && f?.kind === "catalog_setting")
}

// The list_template_version field, present only for a positive integer.
export function listTemplateField(version: unknown): any {
  return Number.isInteger(version) && version as number > 0
    ? { list_template_version: version }
    : {}
}

// PrepareRequest for one setting fix in a combined test. A catalog fix that changes
// shared_preload_libraries also carries list_template_version; nothing else does.
export function settingFixRequest(
  base: PrepareBase,
  options: SettingOptions,
  controlId: string,
  listTemplateVersion: number | null = null,
  catalogLinked = false,
) {
  return {
    snapshot_id: base.snapshot_id,
    benchmark_id: base.benchmark_id,
    environment: base.environment,
    evidence_ids: base.evidence_ids,
    policy_profile: base.policy_profile,
    template_version: options.templateVersion,
    retry_mode: catalogLinked ? "repeat" : options.retryMode,
    retry_template_versions: [],
    control_id: controlId,
    ...listTemplateField(listTemplateVersion),
  }
}

export const MAX_BATCH = 6

// The approved version of a fix type's template, from the fix plan's
// `object_template_versions` ({fix_type: version|null}); null when the server could
// not read the registry or the fix type is unknown.
export function approvedTemplateVersion(
  versions: any,
  fixType: any,
): number | null {
  const version =
    versions &&
    typeof versions === "object" &&
    typeof fixType === "string" &&
    Object.prototype.hasOwnProperty.call(versions, fixType)
      ? versions[fixType]
      : null
  return Number.isInteger(version) && version > 0 ? version : null
}

// The version to send for one object fix in the plan; the manual field is the
// fallback.
export function objectTemplateVersionFor(
  plan: any,
  fixId: string,
  fallback: number,
): number {
  const proposal = (
    Array.isArray(plan?.object_proposals) ? plan.object_proposals : []
  )
    .flatMap((g: any) => g?.proposals ?? [])
    .find((p: any) => p?.fix_id === fixId)
  return (
    approvedTemplateVersion(
      plan?.object_template_versions,
      proposal?.fix_type,
    ) ?? fallback
  )
}

// BatchRequest.fixes for a mixed selection: each key is a setting control id or an
// object fix id. listTemplateVersion gives the set_config_list version for a control
// (null for every fix that does not change shared_preload_libraries).
export function batchFixes(
  selected: string[],
  base: PrepareBase,
  options: SettingOptions,
  objectTemplateVersion: (fixId: string) => number,
  listTemplateVersion: (controlId: string) => number | null = () => null,
  catalogLinked: (controlId: string) => boolean = () => false,
) {
  return selected.map((key) =>
    isObjectFixId(key)
      ? objectFixRequest(base, objectTemplateVersion(key), key)
      : settingFixRequest(
          base,
          options,
          key,
          listTemplateVersion(key),
          catalogLinked(key),
        ),
  )
}

// ---- results ----------------------------------------------------------------------

export function isObjectUnit(unit: any): boolean {
  return (
    !!unit &&
    (unit.schema_version === "fix-unit-v2" || isObjectFixId(unit.fix_id))
  )
}

// "After combined test" for an object fix. An object step is recorded only after
// its own check (and every earlier object's) held; any failure stops the run.
export function objectAfterCombined(batch: any, fixId: string): string {
  const combined = batch?.combined_test
  const steps: any[] = Array.isArray(combined?.steps) ? combined.steps : []
  const step = steps.some((s) => s?.fix_id === fixId)
  if (step && combined?.status === "VERIFIED") return "Change holds"
  if (step) return "Held at its step; combined test did not finish"
  return "NOT RUN"
}

// ---- catalog-linked fix results (3.2, 5.6, 6.10) -------------------------------------

// A catalog-linked fix unit lists its setting changes and is proven by its catalog check.
export function isCatalogUnit(unit: any): boolean {
  return (
    !!unit &&
    Array.isArray(unit.changes) &&
    typeof unit.verify?.catalog_evaluator === "string"
  )
}

function shownValue(value: unknown): string {
  if (value === null || value === undefined) return "(not set)"
  return value === "" ? "(empty)" : String(value)
}

// "setting: before → after" for each change, from the server's fix unit.
export function catalogChangeLines(unit: any): string[] {
  const changes: any[] = Array.isArray(unit?.changes) ? unit.changes : []
  return changes.map(
    (c) =>
      `${c?.param}: ${shownValue(c?.prior_state?.value)} → ${shownValue(c?.expected_value)}`,
  )
}

// "After combined test" for a catalog-linked fix. Catalog checks are not in the setting
// findings; each combined step records its own catalog proof, and every later step
// re-checks the earlier ones, so a VERIFIED run means each proof still holds.
export function catalogAfterCombined(batch: any, fixId: string): string {
  const combined = batch?.combined_test
  const steps: any[] = Array.isArray(combined?.steps) ? combined.steps : []
  const step = steps.find((s) => s?.fix_id === fixId)
  const result = step?.catalog_proof?.result
  if (typeof result !== "string") return "NOT RUN"
  if (combined?.status === "VERIFIED") return result
  return `${result} at its step; combined test did not finish`
}
