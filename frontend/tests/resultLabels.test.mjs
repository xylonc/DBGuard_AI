import { test } from "node:test"
import assert from "node:assert/strict"
import {
  combinedResultTitle,
  singleFixName,
  singleResultTitle,
  titlesBySpec,
} from "../src/live/resultLabels.ts"

const titles = titlesBySpec([
  { id: "cis:3.1.20", title: "Ensure 'log_connections' is enabled" },
  { id: "cis:3.1.22", title: "Ensure 'log_error_verbosity' is set correctly" },
  { id: "cis:4.4", title: "Ensure excessive function privileges are revoked" },
  { id: "bad" },
  null,
])

test("single-fix title: setting fix uses the CIS rule title", () => {
  assert.equal(
    singleResultTitle({ fix_unit: { spec_id: "cis:3.1.20" } }, titles),
    "Single-fix test: Ensure 'log_connections' is enabled",
  )
})

test("single-fix title: object fix uses its proposal title", () => {
  assert.equal(
    singleFixName(
      {
        kind: "object",
        proposal: { title: "Stop old_report from logging in" },
        fix_unit: { spec_id: "cis:4.4", fix_id: "fix-4.4-role-old_report" },
      },
      titles,
    ),
    "Stop old_report from logging in",
  )
})

test("single-fix title: falls back safely, and clips long names", () => {
  assert.equal(
    singleFixName({ sandbox_control: { spec_id: "cis:9.9" } }, titles),
    "cis:9.9",
  )
  assert.equal(singleFixName({}, titles), "unnamed fix")
  const long = singleFixName({ fix_unit: { spec_id: "x".repeat(500) } }, titles)
  assert.ok(long.length <= 80)
})

test("combined title: counts and names the fixes", () => {
  const batch = {
    fix_units: [
      { fix_id: "fix-3.1.20", spec_id: "cis:3.1.20" },
      { fix_id: "fix-3.1.22", spec_id: "cis:3.1.22" },
    ],
  }
  assert.equal(
    combinedResultTitle(batch, titles),
    "Combined test of 2 fixes: Ensure 'log_connections' is enabled + Ensure 'log_error_verbosity' is set correctly",
  )
})

test("combined title: object fixes use their review titles; long lists say how many more", () => {
  const batch = {
    fix_units: [
      {
        fix_id: "fix-4.4-role-old_report",
        spec_id: "cis:4.4",
        schema_version: "fix-unit-v2",
      },
      { fix_id: "a", spec_id: "cis:a" },
      { fix_id: "b", spec_id: "cis:b" },
      { fix_id: "c", spec_id: "cis:c" },
    ],
    risk_reviews: [
      {
        fix_id: "fix-4.4-role-old_report",
        title: "Stop old_report from logging in",
      },
    ],
  }
  assert.equal(
    combinedResultTitle(batch, titles),
    "Combined test of 4 fixes: Stop old_report from logging in + cis:a + cis:b + 1 more",
  )
  assert.equal(combinedResultTitle({}, titles), "Combined test")
})

import { anyBundleReady, bundleState } from "../src/live/resultLabels.ts"

test("bundle state: a VERIFIED run without a bundle shows the server's reason, never 'did not pass'", () => {
  const st = bundleState({
    status: "VERIFIED",
    review_bundle: {
      status: "UNAVAILABLE",
      reason: "Export gate: template not approved",
    },
  })
  assert.equal(st.ready, false)
  assert.equal(st.message, "No bundle: Export gate: template not approved")
  assert.equal(
    bundleState({
      status: "VERIFIED",
      review_bundle: { status: "UNAVAILABLE" },
    }).message,
    "No bundle is available for this result.",
  )
})

test("bundle state: a run that did not verify says so; combined wording differs", () => {
  assert.equal(
    bundleState({ status: "FAILED" }).message,
    "No bundle: this test did not pass.",
  )
  assert.equal(
    bundleState({ status: "FAILED" }, true).message,
    "No combined bundle: every fix must pass alone and together first.",
  )
})

test("bundle state: READY and the demo approval flag", () => {
  const st = bundleState({
    status: "VERIFIED",
    review_bundle: { status: "READY", demo_fixture_approval: true },
  })
  assert.equal(st.ready, true)
  assert.equal(st.demo, true)
  assert.equal(bundleState({ demo_fixture_approval: true }).demo, true)
  assert.equal(bundleState(null).demo, false)
  assert.equal(
    anyBundleReady(null, { review_bundle: { status: "READY" } }),
    true,
  )
  assert.equal(anyBundleReady({ status: "VERIFIED" }, null), false)
})
