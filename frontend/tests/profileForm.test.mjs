import { test } from "node:test"
import assert from "node:assert/strict"
import {
  assessmentProfilePin,
  draftBody,
  errorsFromDetail,
  formFromProfile,
  groupErrors,
  isApproved,
  loginRoles,
  profileRefQuery,
  shapeHint,
  shortSha,
  textToExpected,
} from "../src/live/profileForm.ts"
import { findings, ApiError, request } from "../src/adapters/live.ts"

const B = "cis-pg17-v1.1.0"
const controls = [
  {
    spec_id: `${B}:3.1.2`,
    kind: "policy_value",
    operator: "contains_items",
    setting_name: "log_destination",
  },
  {
    spec_id: `${B}:3.1.4`,
    kind: "policy_value",
    operator: "equals",
    setting_name: "log_directory",
  },
  {
    spec_id: `${B}:5.2`,
    kind: "site_fix",
    operator: "no_item_in",
    setting_name: "listen_addresses",
  },
]
const seed = {
  profile_id: `${B}-reference`,
  values: {
    [`${B}:3.1.2`]: { expected: ["stderr"], fix: "stderr", break: "csvlog" },
    [`${B}:3.1.4`]: {
      expected: "/var/log/postgresql",
      fix: "/var/log/postgresql",
      break: "log",
    },
  },
}
const snapshot = {
  roles: [
    { rolname: "app", rolcanlogin: true, rolsuper: false, rolconnlimit: -1 },
    { rolname: "postgres", rolcanlogin: true, rolsuper: true, rolconnlimit: 3 },
    { rolname: "readers", rolcanlogin: false },
    { rolname: "pg_monitor", rolcanlogin: true, is_predefined: true },
  ],
}

test("seed profile pre-fills the form and round-trips to the same draft values", () => {
  const form = formFromProfile(controls, seed, "a".repeat(64), snapshot)
  assert.equal(form.values[`${B}:3.1.2`].expected, "stderr")
  assert.equal(form.values[`${B}:3.1.4`].brk, "log")
  assert.equal(form.fixes[`${B}:5.2`], "")
  const body = draftBody(form, controls)
  assert.deepEqual(body.values, seed.values)
  assert.equal(body.fixes, null)
  assert.equal(body.connection_limits, null)
  assert.equal(body.based_on, "a".repeat(64))
  assert.equal(body.profile_id, `${B}-reference`)
  // No approver can be put in a draft body.
  assert.equal("approved_by" in body, false)
})

test("blank controls are left out, site fixes and connection limits are sent as typed", () => {
  const form = formFromProfile(controls, seed, null, snapshot)
  form.values[`${B}:3.1.4`] = { expected: "", fix: "", brk: "" }
  form.fixes[`${B}:5.2`] = "  localhost, 10.0.0.5 "
  form.defaultLimit = "20"
  form.roles[0].limit = "5"
  form.roles[1].limit = "lots"
  const body = draftBody(form, controls)
  assert.deepEqual(Object.keys(body.values), [`${B}:3.1.2`])
  assert.deepEqual(body.fixes, { [`${B}:5.2`]: "localhost, 10.0.0.5" })
  assert.deepEqual(body.connection_limits, {
    default_login_limit: 20,
    roles: { app: 5, postgres: "lots" },
  })
})

test("login roles come from the snapshot; superusers are marked", () => {
  assert.deepEqual(
    loginRoles(snapshot).map((r) => [r.name, r.superuser, r.current]),
    [
      ["app", false, "no limit"],
      ["postgres", true, "3"],
    ],
  )
  assert.deepEqual(loginRoles(null), [])
  const form = formFromProfile(
    controls,
    {
      ...seed,
      connection_limits: {
        default_login_limit: null,
        roles: { app: 7, batch: 2 },
      },
    },
    null,
    snapshot,
  )
  assert.deepEqual(
    form.roles.map((r) => [r.name, r.limit]),
    [
      ["app", "7"],
      ["postgres", ""],
      ["batch", "2"],
    ],
  )
})

test("list operators split comma text; single-value operators keep the text", () => {
  assert.deepEqual(textToExpected("in", " 0600, 0640 ,"), ["0600", "0640"])
  assert.equal(textToExpected("equals", " postgres "), "postgres")
  assert.match(shapeHint(controls[0]), /every item/)
  assert.match(shapeHint(controls[2]), /never \* or ::/)
  assert.match(
    shapeHint({ ...controls[2], expected: ["*", "0.0.0.0"] }),
    /^The fix value must pass the CIS check, so it must not contain '\*' or '0\.0\.0\.0'\./,
  )
})

test("backend errors are placed next to the control or section they name", () => {
  const grouped = groupErrors(
    [
      `policy values['${B}:3.1.4'].fix: log_directory must not contain a '..' segment`,
      `policy fixes['${B}:5.2']: listen_addresses value must not contain '*'`,
      "connection_limits.roles['pg_x'] must be an integer >= 0, got -1",
      "profile_id: String should match pattern",
      "Base policy profile not found",
    ],
    controls.map((c) => c.spec_id),
  )
  assert.equal(grouped.bySpec[`${B}:3.1.4`].length, 1)
  assert.equal(grouped.bySpec[`${B}:5.2`].length, 1)
  assert.equal(grouped.connection.length, 1)
  assert.equal(grouped.profileId.length, 1)
  assert.deepEqual(grouped.general, ["Base policy profile not found"])
  assert.equal(grouped.bySpec[`${B}:3.1.2`], undefined)
})

test("422 details: plain strings and pydantic lists", () => {
  assert.deepEqual(
    errorsFromDetail("Approval must be recorded under a named human reviewer"),
    ["Approval must be recorded under a named human reviewer"],
  )
  assert.deepEqual(
    errorsFromDetail([
      { loc: ["body", "profile_id"], msg: "String should match pattern" },
    ]),
    ["profile_id: String should match pattern"],
  )
  assert.deepEqual(errorsFromDetail(undefined), [])
})

test("only a named approval counts as approved; profile query only accepts a sha256", () => {
  assert.equal(isApproved({ status: "approved", approved_by: "Melvin" }), true)
  assert.equal(isApproved({ status: "approved", approved_by: " " }), false)
  assert.equal(isApproved({ status: "draft", approved_by: null }), false)
  const sha = "c".repeat(64)
  assert.equal(profileRefQuery(sha), `&policy_profile=${sha}`)
  assert.equal(profileRefQuery("abc&x=1"), "")
  assert.equal(profileRefQuery(null), "")
  assert.equal(shortSha(sha), "cccccccccccc")
  assert.equal(shortSha(null), "none")
})

test("the profile in use is read from the backend pin, null meaning none", () => {
  assert.equal(assessmentProfilePin(null), undefined)
  assert.equal(assessmentProfilePin({ policy_profile: null }), null)
  const pin = {
    profile_id: "acme",
    sha256: "d".repeat(64),
    approved_by: "Melvin",
    approved_at: "2026-10-27",
  }
  assert.deepEqual(assessmentProfilePin({ policy_profile: pin }), pin)
  assert.deepEqual(
    assessmentProfilePin({
      assessment: { upstream_report: { inputs: { policy_profile: pin } } },
    }),
    pin,
  )
})

test("projection findings keep cis and explanation for unknown rows", () => {
  const rows = findings({
    assessment: {
      findings: {
        "x:5.2": {
          status: "GAPPED",
          cis: { recommendation: "5.2", title: "Bind" },
          explanation: { code: "not_collected" },
        },
      },
    },
  })
  assert.equal(rows[0].status, "GAPPED")
  assert.equal(rows[0].cis.recommendation, "5.2")
  assert.equal(rows[0].explanation.code, "not_collected")
})

test("API errors keep the structured detail for inline display", async () => {
  const original = global.fetch
  global.fetch = async () =>
    new Response(
      JSON.stringify({ detail: [{ loc: ["body", "profile_id"], msg: "bad" }] }),
      { status: 422 },
    )
  try {
    await assert.rejects(
      () => request("/x"),
      (e) =>
        e instanceof ApiError && e.status === 422 && Array.isArray(e.detail),
    )
  } finally {
    global.fetch = original
  }
})
