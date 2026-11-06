import { test } from "node:test"
import assert from "node:assert/strict"
import { snapshotSummary } from "../src/live/snapshotSummary.ts"

const value = (summary, label) =>
  summary.lines.find((l) => l.label === label)?.value

test("snapshot summary: identity, counts and no gaps", () => {
  const s = snapshotSummary({
    snapshot_id: "snap-1",
    target_id: "dev-pg17",
    database: "app",
    postgresql_version: "17",
    collected_at: "2026-11-06T07:26:49Z",
    settings: { log_connections: "off", ssl: "on" },
    roles: [{ rolname: "a" }, { rolname: "b" }, { rolname: "c" }],
    gaps: [],
    available_sections: ["settings", "roles"],
    unavailable_sections: [],
  })
  assert.equal(value(s, "Target"), "dev-pg17")
  assert.equal(value(s, "Database"), "app")
  assert.equal(value(s, "PostgreSQL"), "version 17")
  assert.equal(value(s, "Collected"), "2026-11-06 07:26 UTC")
  assert.equal(value(s, "Server settings read"), "2")
  assert.equal(value(s, "Accounts (roles) read"), "3")
  assert.equal(value(s, "Evidence sections"), "2 collected, 0 not collected")
  assert.equal(value(s, "Collection gaps"), "None")
  assert.deepEqual(s.gaps, [])
})

test("snapshot summary: only counts, never setting values or role names", () => {
  const s = snapshotSummary({
    settings: { password_encryption: "scram-sha-256" },
    roles: [{ rolname: "secret_admin" }],
  })
  const all = JSON.stringify(s)
  assert.ok(!all.includes("scram-sha-256"))
  assert.ok(!all.includes("secret_admin"))
})

test("snapshot summary: not-collected evidence and gaps are shown, never hidden", () => {
  const s = snapshotSummary({
    settings: {},
    roles: null,
    gaps: [{ section: "roles", reason: "permission denied" }],
    available_sections: ["settings"],
    unavailable_sections: ["roles"],
  })
  assert.equal(value(s, "Accounts (roles) read"), "Not collected")
  assert.equal(value(s, "Collection gaps"), "1 gap")
  assert.equal(value(s, "Evidence sections"), "1 collected, 1 not collected")
  assert.deepEqual(s.gaps, [{ section: "roles", reason: "permission denied" }])
  // Named by its gap already, so not listed a second time.
  assert.deepEqual(s.unavailable, [])
})

test("snapshot summary: a gapped settings section reads Not collected, not 0", () => {
  const s = snapshotSummary({
    settings: {},
    roles: [],
    gaps: [{ section: "settings", reason: "permission denied" }],
    unavailable_sections: ["settings", "extensions"],
    available_sections: ["roles"],
  })
  assert.equal(value(s, "Server settings read"), "Not collected")
  assert.equal(value(s, "Accounts (roles) read"), "0")
  assert.equal(value(s, "Evidence sections"), "1 collected, 2 not collected")
  assert.deepEqual(s.unavailable, ["extensions"])
})

test("snapshot summary: long collector text is clipped", () => {
  const s = snapshotSummary({
    gaps: [{ section: "roles", reason: "x".repeat(5000) }],
  })
  assert.ok(s.gaps[0].reason.length <= 160)
})

test("snapshot summary: missing or malformed fields fall back safely", () => {
  assert.equal(snapshotSummary(null), null)
  const s = snapshotSummary({ collected_at: "not a date", gaps: [null, 3] })
  assert.equal(value(s, "Collected"), "Not returned")
  assert.equal(value(s, "Database"), "Not returned")
  assert.equal(value(s, "Server settings read"), "Not collected")
  // Unreadable gap records are counted, never hidden behind "None".
  assert.equal(value(s, "Collection gaps"), "2 gaps (2 unreadable)")
  assert.equal(s.malformedGaps, 2)
  // No gaps field at all is "Not returned", never "None".
  assert.equal(value(snapshotSummary({}), "Collection gaps"), "Not returned")
})
