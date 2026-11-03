import { test } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import {
  NOTE_SENTENCES,
  UNKNOWN_NOTE_SENTENCE,
  approvedTemplateVersion,
  batchFixes,
  changeKey,
  changeSummary,
  isObjectFixId,
  isObjectUnit,
  limitSourceLabel,
  noteDetail,
  noteSentence,
  objectAfterCombined,
  objectFixRequest,
  objectTemplateVersionFor,
  riskLabel,
  targetLabel,
} from "../src/live/objectFixes.ts"

// Every note code services/sandbox_poc/object_fixes.py can emit (NOTE_TEXTS).
const OBJECT_NOTE_CODES = [
  "bootstrap_superuser",
  "collecting_role",
  "collecting_role_unknown",
  "superuser_limit_not_enforced",
  "policy_missing",
  "evidence_not_collected",
  "extension_owned",
  "extension_evidence_missing",
  "possibly_extension_owned",
  "system_schema",
  "not_a_function",
  "grantor_not_owner",
  "dependent_grants",
  "predefined_role",
  "ambiguous_grantee",
]

// The backend's NOTE_TEXTS keys, read from the source so a new code fails here.
function backendNoteCodes() {
  const source = readFileSync(
    new URL("../../services/sandbox_poc/object_fixes.py", import.meta.url),
    "utf8",
  )
  const block = source.match(
    /NOTE_TEXTS = MappingProxyType\(\{([\s\S]*?)\n\}\)/,
  )
  assert.ok(block, "NOTE_TEXTS not found in object_fixes.py")
  return [...block[1].matchAll(/^\s{4}"([a-z_]+)":/gm)].map((m) => m[1])
}

const base = {
  snapshot_id: "snap-abc",
  benchmark_id: "cis-pg17-v1.1.0",
  environment: "test",
  evidence_ids: ["demo-evidence"],
  policy_profile: null,
}
const FIX = "fix-4.3-role_drop_attribute-0123456789"
const FIX2 = "fix-4.4-role_nologin-abcdef0123"

test("the code list matches the backend's NOTE_TEXTS", () => {
  assert.deepEqual(
    [...backendNoteCodes()].sort(),
    [...OBJECT_NOTE_CODES].sort(),
  )
})

test("every backend note code has a fixed sentence", () => {
  for (const code of OBJECT_NOTE_CODES) {
    assert.ok(NOTE_SENTENCES[code], code)
    assert.equal(noteSentence(code), NOTE_SENTENCES[code])
    assert.notEqual(noteSentence(code), UNKNOWN_NOTE_SENTENCE)
  }
  assert.deepEqual(
    Object.keys(NOTE_SENTENCES).sort(),
    [...OBJECT_NOTE_CODES].sort(),
  )
})

test("ruled sentences: policy missing and superuser limits", () => {
  assert.match(
    noteSentence("policy_missing"),
    /^COMPANY POLICY MISSING: set connection limits on the Policy Profile screen/,
  )
  // Gate 1 ruling 4, verbatim.
  assert.match(
    noteSentence("superuser_limit_not_enforced"),
    /limit not enforced; remove SUPERUSER first \(fix #2\)/,
  )
})

test("unknown or malformed codes fall back to a safe review sentence", () => {
  for (const code of [
    "brand_new_code",
    "",
    null,
    undefined,
    7,
    {},
    "__proto__",
    "toString",
  ]) {
    assert.equal(noteSentence(code), UNKNOWN_NOTE_SENTENCE)
  }
  assert.match(UNKNOWN_NOTE_SENTENCE, /^Unknown: needs human review/)
  assert.doesNotMatch(UNKNOWN_NOTE_SENTENCE, /PASS/)
})

test("note details show the roles waiting for a policy and the extension", () => {
  assert.equal(
    noteDetail({ code: "policy_missing", roles: ["web", "report"] }),
    "Accounts waiting for a limit: web, report",
  )
  assert.equal(
    noteDetail({ code: "extension_owned", extension: "pgaudit" }),
    "Extension: pgaudit",
  )
  assert.equal(noteDetail({ code: "bootstrap_superuser" }), null)
  assert.equal(noteDetail(null), null)
})

test("targets are labelled for roles, functions and tables", () => {
  assert.equal(targetLabel({ role: "app_admin" }), "account app_admin")
  assert.equal(
    targetLabel({ schema: "public", name: "f", identity_args: "integer" }),
    "function public.f(integer)",
  )
  assert.equal(
    targetLabel({ schema: "public", table: "t", grantee: "web" }),
    "table public.t (granted to web)",
  )
  assert.equal(targetLabel(null), null)
  assert.equal(targetLabel({}), null)
})

test("risk badges and limit sources", () => {
  assert.equal(riskLabel("high"), "high risk")
  assert.equal(riskLabel("medium"), "medium risk")
  assert.equal(riskLabel("extreme"), "Risk not assessed")
  assert.match(
    limitSourceLabel({ source: "role", profile: { profile_id: "acme" } }),
    /company policy "acme": a limit set for this account/,
  )
  assert.match(
    limitSourceLabel({ source: "default_login_limit", profile: null }),
    /default limit for login accounts/,
  )
  assert.match(
    limitSourceLabel({ source: "guess" }),
    /^Unknown: needs human review/,
  )
})

test("change summaries say what each fix type changes", () => {
  assert.equal(
    changeSummary({
      fix_type: "role_connection_limit",
      target: { role: "web" },
      params: { connection_limit: 50 },
      prior: { rolconnlimit: -1 },
    }),
    "Connection limit of web: unlimited → 50",
  )
  assert.equal(
    changeSummary({
      fix_type: "role_drop_attribute",
      target: { role: "a", attribute: "SUPERUSER" },
    }),
    "SUPERUSER on a: yes → no",
  )
  assert.match(
    changeSummary({ fix_type: "role_nologin", target: { role: "old" } }),
    /allowed → not allowed/,
  )
  assert.match(
    changeSummary({
      fix_type: "table_revoke_dml",
      target: {
        grantee: "PUBLIC",
        privileges: ["INSERT", "UPDATE"],
        grant_option: true,
      },
    }),
    /^INSERT, UPDATE for PUBLIC \(with grant option\): granted → revoked$/,
  )
  assert.match(changeSummary({ fix_type: "mystery" }), /^Unknown change/)
})

test("the same change under two CIS rules has one change key", () => {
  const a = {
    fix_type: "role_drop_attribute",
    target: { role: "x", attribute: "SUPERUSER" },
  }
  const b = {
    fix_type: "role_drop_attribute",
    target: { attribute: "SUPERUSER", role: "x" },
  }
  const c = {
    fix_type: "role_drop_attribute",
    target: { role: "x", attribute: "CREATEDB" },
  }
  assert.equal(changeKey(a), changeKey(b))
  assert.notEqual(changeKey(a), changeKey(c))
})

test("an object fix request carries only the fix id, never params", () => {
  const body = objectFixRequest(base, 1, FIX)
  assert.equal(body.object_fix_id, FIX)
  for (const key of [
    "params",
    "target",
    "control_id",
    "retry_mode",
    "alternative_templates",
    "prior",
  ]) {
    assert.ok(!(key in body), key)
  }
  assert.deepEqual(Object.keys(body).sort(), [
    "benchmark_id",
    "environment",
    "evidence_ids",
    "object_fix_id",
    "policy_profile",
    "snapshot_id",
    "template_version",
  ])
  assert.throws(() => objectFixRequest(base, 1, "cis-pg17-v1.1.0:3.1.20"))
  assert.throws(() => objectFixRequest(base, 1, "fix-4.3-rm -rf-0123456789"))
})

test("a combined test can mix setting and object fixes", () => {
  const fixes = batchFixes(
    ["cis-pg17-v1.1.0:3.1.20", FIX, FIX2],
    base,
    { templateVersion: 3, retryMode: "adaptive" },
    () => 1,
  )
  assert.equal(fixes.length, 3)
  assert.equal(fixes[0].control_id, "cis-pg17-v1.1.0:3.1.20")
  assert.equal(fixes[0].template_version, 3)
  assert.ok(!("object_fix_id" in fixes[0]))
  for (const f of fixes.slice(1)) {
    assert.ok(isObjectFixId(f.object_fix_id))
    assert.equal(f.template_version, 1)
    assert.ok(!("params" in f) && !("control_id" in f) && !("retry_mode" in f))
  }
})

test("fix id recognition follows the backend pattern", () => {
  assert.ok(isObjectFixId(FIX))
  assert.ok(isObjectFixId("fix-5.5-role_connection_limit-ffffffffff"))
  assert.ok(!isObjectFixId("fix-log_connections"))
  assert.ok(!isObjectFixId("fix-4.3-drop_table-0123456789"))
  assert.ok(!isObjectFixId(null))
})

test("step 6: object units and their after-combined status", () => {
  assert.ok(isObjectUnit({ schema_version: "fix-unit-v2", fix_id: FIX }))
  assert.ok(
    !isObjectUnit({
      fix_id: "fix-log_connections",
      params: { param_name: "x" },
    }),
  )
  const ok = { combined_test: { status: "VERIFIED", steps: [{ fix_id: FIX }] } }
  assert.equal(objectAfterCombined(ok, FIX), "Change holds")
  assert.equal(objectAfterCombined(ok, FIX2), "NOT RUN")
  const failed = {
    combined_test: { status: "FAILED", steps: [{ fix_id: FIX }] },
  }
  assert.match(objectAfterCombined(failed, FIX), /did not finish/)
  assert.equal(objectAfterCombined({}, FIX), "NOT RUN")
})

test("object fix screens render text only and never send params", () => {
  for (const file of ["ObjectProposals.tsx", "ReviewPanel.tsx"]) {
    const source = readFileSync(
      new URL(`../src/live/${file}`, import.meta.url),
      "utf8",
    )
    assert.doesNotMatch(source, /dangerouslySetInnerHTML/, file)
  }
  const panel = readFileSync(
    new URL("../src/live/ObjectProposals.tsx", import.meta.url),
    "utf8",
  )
  assert.match(panel, /Proposed fixes for accounts and permissions/)
  assert.match(panel, /Test this fix on its own/)
  assert.match(panel, /Add to combined test/)
  assert.match(panel, /noteSentence\(note\?\.code\)/)
  // Never renders the backend's free note text in place of the fixed sentence.
  assert.doesNotMatch(panel, /note\??\.text/)
  // The single-fix choice stores the id and labels, never params or target.
  const choice = panel.match(/objectFix: \{([\s\S]*?)\}/)
  assert.ok(choice)
  assert.doesNotMatch(choice[1], /params|target/)
  const store = readFileSync(
    new URL("../src/store/liveStore.tsx", import.meta.url),
    "utf8",
  )
  assert.match(store, /objectFixRequest\(/)
  const review = readFileSync(
    new URL("../src/live/ReviewPanel.tsx", import.meta.url),
    "utf8",
  )
  assert.match(review, /fixes: batchFixes\(/)
})

test("each object fix sends its template's approved version", () => {
  const plan = {
    object_proposals: [
      { proposals: [{ fix_id: FIX, fix_type: "role_drop_attribute" }] },
      { proposals: [{ fix_id: FIX2, fix_type: "role_nologin" }] },
    ],
    object_template_versions: { role_drop_attribute: 3, role_nologin: null },
  }
  assert.equal(objectTemplateVersionFor(plan, FIX, 1), 3)
  // Registry could not say: fall back to the manual field.
  assert.equal(objectTemplateVersionFor(plan, FIX2, 7), 7)
  assert.equal(objectTemplateVersionFor({}, FIX, 2), 2)
  const fixes = batchFixes(
    [FIX, FIX2],
    base,
    { templateVersion: 9, retryMode: "adaptive" },
    (id) => objectTemplateVersionFor(plan, id, 1),
  )
  assert.deepEqual(
    fixes.map((f) => f.template_version),
    [3, 1],
  )
  for (const bad of [0, -1, 1.5, "2", true])
    assert.equal(approvedTemplateVersion({ t: bad }, "t"), null)
  assert.equal(approvedTemplateVersion({}, "__proto__"), null)
  assert.equal(approvedTemplateVersion(null, "t"), null)
})
