import { test } from "node:test"
import assert from "node:assert/strict"
import { readFileSync } from "node:fs"
import {
  CATALOG_GENERIC_SENTENCE,
  CATALOG_OBJECT_FIXES_SENTENCE,
  catalogChanges,
  isCatalogSettingFix,
  manualReason,
  preloadAdded,
  preloadNote,
  restartNote,
} from "../src/live/fixPlan.ts"

// A catalog_fixes.REASONS text, as the fix plan sends it with reason_code.
const PRELOAD_UNSUPPORTED =
  "shared_preload_libraries lists an entry the reviewed list template cannot write back exactly. Add the library by hand following the CIS remediation, keeping the existing entries and their order."

test("a catalog item with reason_code shows the server's plain-language reason", () => {
  const item = {
    spec_id: "cis-pg17-v1.1.0:3.2",
    kind: "catalog",
    status: "FAIL",
    reason: PRELOAD_UNSUPPORTED,
    reason_code: "preload_list_unsupported",
  }
  assert.equal(manualReason(item), PRELOAD_UNSUPPORTED)
  // The reason wins over the generic per-object sentence too.
  assert.equal(manualReason(item, undefined, true), PRELOAD_UNSUPPORTED)
  const policy = {
    ...item,
    reason_code: "policy_missing",
    reason:
      "COMPANY POLICY MISSING: approve pgaudit_log_classes in the company policy profile before DBGuard can offer the pgaudit fix (policy_missing).",
  }
  assert.match(
    manualReason(policy),
    /^COMPANY POLICY MISSING: approve pgaudit_log_classes/,
  )
})

test("without a reason_code the generic catalog sentence stays", () => {
  const item = {
    spec_id: "cis-pg17-v1.1.0:4.3",
    kind: "catalog",
    status: "FAIL",
    reason: "Assessment-only catalog check",
  }
  assert.equal(manualReason(item), CATALOG_GENERIC_SENTENCE)
  assert.equal(
    manualReason(item, undefined, true),
    CATALOG_OBJECT_FIXES_SENTENCE,
  )
  // reason_code null (an error without a code), empty, or a missing/blank reason.
  for (const extra of [
    { reason_code: null, reason: "boom" },
    { reason_code: "", reason: "boom" },
    { reason_code: "not_linked", reason: undefined },
    { reason_code: "not_linked", reason: "   " },
    { reason_code: "not_linked", reason: 42 },
  ])
    assert.equal(
      manualReason({ ...item, ...extra }),
      CATALOG_GENERIC_SENTENCE,
      JSON.stringify(extra),
    )
})

test("setting items keep their existing reasons", () => {
  assert.equal(
    manualReason({ status: "FAIL", tier: "automated" }),
    "no reviewed fix exists for this setting yet.",
  )
  assert.match(
    manualReason({
      status: "FAIL",
      reason: "site-specific fix value not supplied",
    }),
    /Site-specific fixes on the Policy Profile screen/,
  )
  assert.match(
    manualReason({ status: "GAPPED" }),
    /^Unknown: needs human review\./,
  )
})

const PGAUDIT_FIX = {
  spec_id: "cis-pg17-v1.1.0:3.2",
  fix_id: "fix-3.2",
  kind: "catalog_setting",
  setting: "shared_preload_libraries",
  settings: ["shared_preload_libraries", "pgaudit.log"],
  changes: [
    {
      setting: "shared_preload_libraries",
      current_value: "",
      current_source: "default",
      proposed_value: "pgaudit",
    },
    {
      setting: "pgaudit.log",
      current_value: null,
      current_source: "not defined",
      proposed_value: "ddl,role,write",
    },
  ],
  requires: "restart",
  preload_added: ["pgaudit"],
  reviewed_risk: "high",
  proof:
    "CIS 3.2 check (pgaudit_enabled) must give PASS on the sandbox collection after the fix, and the original FAIL after rollback.",
}

test("catalog_setting cards list every change, the restart and the preload note", () => {
  assert.equal(isCatalogSettingFix(PGAUDIT_FIX), true)
  assert.equal(isCatalogSettingFix({ kind: "setting" }), false)
  assert.deepEqual(catalogChanges(PGAUDIT_FIX), [
    {
      setting: "shared_preload_libraries",
      current: "'' (empty)",
      proposed: "pgaudit",
    },
    { setting: "pgaudit.log", current: "not set", proposed: "ddl,role,write" },
  ])
  // Falls back to the single setting fields; malformed changes are skipped.
  assert.deepEqual(
    catalogChanges({
      setting: "ssl_ciphers",
      current_value: "HIGH",
      proposed_value: "X",
      changes: [{}],
    }),
    [{ setting: "ssl_ciphers", current: "HIGH", proposed: "X" }],
  )
  assert.deepEqual(catalogChanges({}), [])
  assert.match(restartNote(PGAUDIT_FIX), /restart/)
  assert.equal(restartNote({ requires: "reload" }), null)
  assert.deepEqual(preloadAdded(PGAUDIT_FIX), ["pgaudit"])
  assert.deepEqual(preloadAdded({ preload_added: ["x", 1, "", null] }), ["x"])
  const note = preloadNote(PGAUDIT_FIX)
  assert.match(note, /^Adds pgaudit to shared_preload_libraries/)
  assert.match(note, /installed on the server first/)
  assert.equal(preloadNote({ preload_added: [] }), null)
})

test("ReviewPanel uses the pure helpers and renders text only", () => {
  const source = readFileSync(
    new URL("../src/live/ReviewPanel.tsx", import.meta.url),
    "utf8",
  )
  assert.match(source, /from "\.\/fixPlan"/)
  assert.doesNotMatch(source, /function manualReason/)
  assert.match(source, /<CatalogSettingChanges/)
  assert.match(source, /listTemplateVersionFor\(plan, controlId\)/)
  assert.match(source, /listTemplate: chooseListTemplate\(/)
  assert.doesNotMatch(source, /dangerouslySetInnerHTML/)
  const store = readFileSync(
    new URL("../src/store/liveStore.tsx", import.meta.url),
    "utf8",
  )
  assert.match(
    store,
    /\.\.\.listTemplateField\(activeListTemplateVersion\(s\)\)/,
  )
})
