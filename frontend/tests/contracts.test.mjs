import { test } from "node:test"
import assert from "node:assert/strict"
import {
  findings,
  sameTarget, isFreshSnapshot,
  bundlePath,
  request,
} from "../src/adapters/live.ts"
test("assessment uses native authoritative results, not bridge convenience statuses", () => {
  const input = {
    assessment: {
      findings: { "cis:3.1.14": "MANUAL_REVIEW" },
      upstream_report: {
        results: [
          {
            spec_id: "cis:3.1.14",
            title: "Log level",
            result: "NEEDS_CAPABILITY",
          },
        ],
      },
    },
  }
  assert.deepEqual(
    findings(input).map((r) => [r.id, r.status]),
    [["cis:3.1.14", "NEEDS_CAPABILITY"]],
  )
})
test("uncollected target cannot be declared matching", () => {
  assert.equal(sameTarget(null, null), false)
  assert.equal(
    sameTarget({ target_id: "a", database: "db", postgresql_version: "17" }, {
      target_id: "b",
      database: "db",
      postgresql_version: "17",
    }),
    false,
  )
  assert.equal(
    sameTarget({ target_id: "a", database: "db", postgresql_version: "17" }, {
      target_id: "a",
      database: "db",
      postgresql_version: "17",
    }),
    true,
  )
})
test("bundle links are built from recorded run, never model-supplied external URL", () => {
  assert.equal(
    bundlePath("demo", {
      run_id: "real-id",
      review_bundle: { status: "READY", url: "https://attacker.invalid" },
    }),
    "/bridge/demo/api/v1/sandbox/runs/real-id/bundle",
  )
  assert.equal(
    bundlePath("demo", {
      run_id: "x",
      review_bundle: { status: "UNAVAILABLE" },
    }),
    undefined,
  )
  assert.equal(bundlePath("demo", null), undefined)
})
test("API errors remain errors, not empty successful results", async () => {
  const original = global.fetch
  global.fetch = async () =>
    new Response(JSON.stringify({ detail: "Snapshot not found" }), {
      status: 404,
    })
  try {
    await assert.rejects(() => request("/x"), /Snapshot not found/)
  } finally {
    global.fetch = original
  }
})

test('reuploading the original snapshot is not fresh target verification', () => {
 const before={snapshot_id:'a',collected_at:'2026-09-25T00:00:00Z'};
 assert.equal(isFreshSnapshot(before,before),false);
 assert.equal(isFreshSnapshot(before,{snapshot_id:'b',collected_at:'2026-09-24T00:00:00Z'}),false);
 assert.equal(isFreshSnapshot(before,{snapshot_id:'b',collected_at:'2026-09-25T01:00:00Z'}),true);
});
