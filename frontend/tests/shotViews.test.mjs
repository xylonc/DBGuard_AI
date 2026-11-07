import { test } from "node:test"
import assert from "node:assert/strict"
import { shotsOf } from "../src/live/shotViews.ts"

const PNG = "iVBORw0KGgo=" // well-formed base64
const SHA = "a".repeat(64)

test("shots: three stages in order, terminal and rendered labelled", () => {
  const shots = shotsOf({
    mode: "terminal",
    stages: {
      before: {
        status: "CAPTURED",
        mode: "terminal",
        format: "png",
        png_base64: PNG,
        sha256: SHA,
        typed_command: "docker exec …",
        sql: "SHOW x;",
      },
      after: {
        status: "CAPTURED",
        mode: "rendered",
        format: "png",
        png_base64: PNG,
        sha256: SHA,
        reason: "VHS timed out; rendered picture used",
      },
      rollback: { status: "UNAVAILABLE", reason: "VHS is not installed" },
    },
  })
  assert.deepEqual(
    shots.map((s) => [s.stage, s.captured, s.kind]),
    [
      ["before", true, "Terminal"],
      ["after", true, "Rendered"],
      ["rollback", false, null],
    ],
  )
  assert.equal(shots[0].src, `data:image/png;base64,${PNG}`)
  assert.equal(shots[1].reason, "VHS timed out; rendered picture used")
  assert.equal(shots[2].src, null)
  assert.equal(shots[2].reason, "VHS is not installed")
})

test("shots: malformed picture data is never shown as an image", () => {
  for (const bad of ["not base64!", "abc", "", 5, '"><script>']) {
    const [s] = shotsOf({
      stages: {
        before: { status: "CAPTURED", format: "png", png_base64: bad },
      },
    })
    assert.equal(s.captured, false, String(bad))
    assert.equal(s.src, null)
  }
  const [svg] = shotsOf({
    stages: { before: { status: "CAPTURED", format: "svg", png_base64: PNG } },
  })
  assert.equal(svg.src, null)
})

test("shots: a missing stage stays visible with a reason", () => {
  const shots = shotsOf({ stages: {} })
  assert.equal(shots.length, 3)
  assert.ok(shots.every((s) => !s.captured && s.reason))
})

test("shots: no evidence means no strip; bad fingerprints are dropped", () => {
  assert.equal(shotsOf(null), null)
  assert.equal(shotsOf({ mode: "rendered" }), null)
  const [s] = shotsOf({
    stages: {
      before: {
        status: "CAPTURED",
        format: "png",
        png_base64: PNG,
        sha256: "xyz",
      },
    },
  })
  assert.equal(s.sha256, null)
})
