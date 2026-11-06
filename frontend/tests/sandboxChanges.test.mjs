import { test } from "node:test"
import assert from "node:assert/strict"
import {
  batchAfter,
  changeDirection,
  runAfter,
  runRegressions,
  statusChanges,
} from "../src/live/sandboxChanges.ts"

const rows = [
  { id: "cis:3.1.20", title: "log_connections", status: "FAIL" },
  { id: "cis:3.1.21", title: "log_disconnections", status: "PASS" },
  { id: "cis:3.1.2", title: "log_destination", status: "MANUAL" },
  { id: "cis:3.1.9", title: "rotation", status: "NOT_COLLECTED" },
  { id: "cis:4.3", title: "admin privileges", status: "MANUAL" },
  { id: "cis:3.1.22", title: "verbosity", status: "PASS" },
]

test("changes: only real status changes are listed, worse first", () => {
  const out = statusChanges(rows, {
    "cis:3.1.20": "PASS",
    "cis:3.1.21": "PASS",
    "cis:3.1.2": "MANUAL_REVIEW", // same kind as MANUAL: not a change
    "cis:3.1.9": "GAPPED", // same kind as NOT_COLLECTED: not a change
    "cis:3.1.22": "FAIL",
  })
  assert.deepEqual(
    out.changes.map((c) => [c.id, c.before, c.after, c.direction]),
    [
      ["cis:3.1.22", "PASS", "FAIL", "worse"],
      ["cis:3.1.20", "FAIL", "PASS", "better"],
    ],
  )
  assert.equal(out.unchanged, 3)
  // 4.3 has no sandbox result: not re-checked, never a change.
  assert.equal(out.notRechecked, 1)
})

test("changes: direction rules", () => {
  assert.equal(changeDirection("FAIL", "PASS"), "better")
  assert.equal(changeDirection("GAPPED", "PASS"), "better")
  assert.equal(changeDirection("PASS", "GAPPED"), "worse")
  assert.equal(changeDirection("MANUAL", "FAIL"), "worse")
  assert.equal(changeDirection("FAIL", "GAPPED"), "changed")
  // An unrecognised status is unknown, never PASS.
  assert.equal(changeDirection("FAIL", "WEIRD"), "changed")
})

test("changes: object-shaped after values and bad input are handled", () => {
  const out = statusChanges(rows.slice(0, 1), {
    "cis:3.1.20": { status: "PASS" },
  })
  assert.equal(out.changes[0].after, "PASS")
  assert.deepEqual(statusChanges(null, null), {
    changes: [],
    unchanged: 0,
    notRechecked: 0,
  })
  const missing = statusChanges(rows.slice(0, 1), { "cis:3.1.20": null })
  assert.equal(missing.notRechecked, 1)
})

test("runAfter: setting findings plus a catalog fix's own CIS result", () => {
  assert.deepEqual(
    runAfter({
      sandbox_after_findings: { "cis:3.1.20": "PASS" },
      sandbox_control: {
        spec_id: "cis:6.10",
        before_status: "FAIL",
        after_status: "PASS",
      },
    }),
    { "cis:3.1.20": "PASS", "cis:6.10": "PASS" },
  )
  // The findings map wins; UNKNOWN is never added.
  assert.deepEqual(
    runAfter({
      sandbox_after_findings: { "cis:3.1.20": "FAIL" },
      sandbox_control: { spec_id: "cis:3.1.20", after_status: "PASS" },
    }),
    { "cis:3.1.20": "FAIL" },
  )
  assert.deepEqual(
    runAfter({ sandbox_control: { spec_id: "x", after_status: "UNKNOWN" } }),
    {},
  )
})

test("batchAfter: catalog proofs only when the combined test VERIFIED", () => {
  const batch = {
    sandbox_after_findings: { "cis:3.1.20": "PASS" },
    fix_units: [{ fix_id: "fix-6.10", spec_id: "cis:6.10" }],
    combined_test: {
      status: "VERIFIED",
      steps: [{ fix_id: "fix-6.10", catalog_proof: { result: "PASS" } }],
    },
  }
  assert.deepEqual(batchAfter(batch), {
    "cis:3.1.20": "PASS",
    "cis:6.10": "PASS",
  })
  assert.deepEqual(
    batchAfter({
      ...batch,
      combined_test: { ...batch.combined_test, status: "FAILED" },
    }),
    { "cis:3.1.20": "PASS" },
  )
  assert.deepEqual(batchAfter(null), {})
})

test("runAfter: falls back to the compared findings, never the sandbox's full report", () => {
  // The sandbox report also judges account rules against its stand-in accounts
  // (4.10 PASS there); those must not appear as a change caused by the fix.
  const result = {
    attempts: [
      {
        after_assessment: {
          findings: { "cis:3.1.20": { status: "PASS" } },
          upstream_report: {
            results: [
              { spec_id: "cis:3.1.20", result: "PASS" },
              { spec_id: "cis:4.10", result: "PASS" },
            ],
          },
        },
      },
    ],
  }
  assert.deepEqual(runAfter(result), { "cis:3.1.20": "PASS" })
})

test("runAfter: a raw catalog-linked run uses its own CIS check result", () => {
  assert.deepEqual(
    runAfter({
      kind: "catalog_setting",
      fix_unit: { spec_id: "cis:6.10" },
      catalog_proof: {
        before: { result: "FAIL" },
        after: { result: "PASS" },
      },
      attempts: [{ after_assessment: { findings: {} } }],
    }),
    { "cis:6.10": "PASS" },
  )
})

test("recorded regressions are always listed as worse, never not re-checked", () => {
  // A setting fix broke a catalog check that reads it (outside the findings map).
  const out = statusChanges(
    [
      { id: "cis:3.1.20", title: "log_connections", status: "FAIL" },
      { id: "cis:6.10", title: "ciphers", status: "PASS" },
      { id: "cis:4.3", title: "admin", status: "MANUAL" },
    ],
    { "cis:3.1.20": "PASS" },
    ["cis:6.10"],
  )
  assert.deepEqual(
    out.changes.map((c) => [c.id, c.after, c.direction, c.recordedRegression]),
    [
      ["cis:6.10", null, "worse", true],
      ["cis:3.1.20", "PASS", "better", false],
    ],
  )
  assert.equal(out.notRechecked, 1) // only 4.3
  assert.equal(out.unchanged, 0)
})

test("recorded regressions win even when the status kind looks unchanged", () => {
  const out = statusChanges(
    [{ id: "a", title: "A", status: "FAIL" }],
    { a: "FAIL" },
    ["a", "b-not-in-rows", 3, ""],
  )
  assert.deepEqual(
    out.changes.map((c) => [c.id, c.direction, c.after]),
    [
      ["a", "worse", "FAIL"],
      ["b-not-in-rows", "worse", null],
    ],
  )
  assert.equal(out.unchanged, 0)
})

test("runRegressions reads the last attempt only", () => {
  assert.deepEqual(
    runRegressions({
      attempts: [{ regressions: ["x"] }, { regressions: ["y", 5, ""] }],
    }),
    ["y"],
  )
  assert.deepEqual(runRegressions({}), [])
})

test("not applicable is a neutral change, neither improved nor worse", () => {
  assert.equal(changeDirection("NOT_APPLICABLE", "PASS"), "changed")
  assert.equal(changeDirection("PASS", "NOT_APPLICABLE"), "changed")
})
