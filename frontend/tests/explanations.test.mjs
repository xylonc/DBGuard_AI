import { test } from "node:test"
import assert from "node:assert/strict"
import {
  GENERIC_UNKNOWN_SENTENCE,
  KNOWN_CODES,
  UNKNOWN_LABEL,
  cisRule,
  conditionPhrase,
  explainRow,
  explanationSentence,
  isPolicyMissing,
  needsExplanation,
  policyMissingRows,
  quoteValue,
  statusKind,
  statusLabel,
} from "../src/live/explanations.ts"

const syslogCondition = {
  setting_name: "log_destination",
  operator: "contains_items",
  expected: ["syslog"],
  condition_quote: "When logging to Syslog and `syslog_sequence_numbers` is on",
}

// One case per code the backend can send today (assess.py _explain and
// ASSESS spec_controls). F6 codes get a case here when they are added.
const CASES = {
  condition_false: [
    { code: "condition_false", ...syslogCondition, actual: "stderr" },
    "Only applies when logs are sent to syslog. This server's log_destination is 'stderr', so it doesn't apply.",
  ],
  condition_unknown: [
    {
      code: "condition_unknown",
      cause: "not_collected",
      evidence: "condition",
      entry_status: "missing",
      ...syslogCondition,
    },
    "Only applies when logs are sent to syslog, and DBGuard couldn't confirm that. This snapshot has no reading of log_destination, so DBGuard can't say PASS. Collect a new snapshot with the current collector and check list. So it can't tell whether this control applies.",
  ],
  not_collected: [
    {
      code: "not_collected",
      evidence: "check",
      setting_name: "log_connections",
      entry_status: "not_collected",
    },
    "The collector marked log_connections as not collected, so DBGuard has no value to check and can't say PASS. Check the collector ran with enough access, then collect a new snapshot.",
  ],
  stale_spec_hash: [
    {
      code: "stale_spec_hash",
      evidence: "check",
      setting_name: "log_connections",
      spec_hash: "a".repeat(64),
      collected_spec_hash: "b".repeat(64),
    },
    "This snapshot was collected for an older version of this control's rule, so its reading of log_connections can't be trusted against the current rule and DBGuard can't say PASS. Collect a new snapshot with the current check list.",
  ],
  collector_error: [
    {
      code: "collector_error",
      evidence: "check",
      setting_name: "ssl",
      error: "permission denied",
    },
    "The collector hit an error while reading ssl: 'permission denied'. DBGuard can't say PASS until it is read without errors.",
  ],
  unit_or_non_text_value: [
    {
      code: "unit_or_non_text_value",
      evidence: "check",
      setting_name: "log_rotation_age",
      unit: "min",
      vartype: "integer",
    },
    "DBGuard got log_rotation_age in a form it can't compare as plain text, so it can't say PASS. It has the unit 'min' and the type 'integer'.",
  ],
  uninterpretable_value: [
    {
      code: "uninterpretable_value",
      evidence: "check",
      setting_name: "log_min_messages",
      operator: "severity",
      direction: "at_or_more_verbose",
      actual: "loud",
    },
    "DBGuard read log_min_messages as 'loud' but couldn't interpret that value for this rule, so it can't say PASS. A person should check the value.",
  ],
  sanitised: [
    { code: "sanitised", setting_name: "archive_command" },
    "DBGuard couldn't read archive_command (it was hidden for safety), so it can't say PASS.",
  ],
  redacted_secret_setting: [
    {
      code: "redacted_secret_setting",
      evidence: "check",
      setting_name: "pgrst.jwt_secret",
    },
    "DBGuard deliberately never reads this setting's value because it can contain a secret, so it can't say PASS or FAIL; check it by hand.",
  ],
  session_override: [
    {
      code: "session_override",
      evidence: "check",
      setting_name: "log_statement",
      source: "user",
    },
    "The value of log_statement DBGuard read is set for a role, a database or the session (source 'user'), not for the whole server, so it may not be what the server and other sessions use. DBGuard can't say PASS or FAIL, and no sandbox fix can be tested on this snapshot while it is unknown. Check the server-wide value and pg_db_role_setting, remove the override if it is not wanted, then collect a new snapshot.",
  ],
  wrong_pg_major: [
    { code: "wrong_pg_major", spec_pg_major: 17, snapshot_pg_major: 16 },
    "This rule is written for PostgreSQL 17, but the snapshot is from PostgreSQL 16, so DBGuard does not apply it and can't say PASS.",
  ],
  policy_missing: [
    { code: "policy_missing", case: "no_profile" },
    "This control checks a value your company must choose, and no approved policy profile is selected for this assessment, so DBGuard can't check it. Approve a profile on the Policy Profile screen and select it.",
  ],
  // ---- catalog checks (F6, 7.4): backend/app/services/spec_engine/catalog_checks.py
  section_not_collected: [
    {
      code: "section_not_collected",
      section: "functions",
      gap_reason: "insufficient_privilege",
    },
    "The collector could not read 'functions' from this database (collector said: 'insufficient_privilege'), so DBGuard cannot judge this control and can't say PASS.",
  ],
  field_missing: [
    { code: "field_missing", section: "roles", field: "rolconnlimit" },
    "The snapshot has no 'rolconnlimit' in 'roles', so DBGuard cannot judge this control and can't say PASS.",
  ],
  manual_review: [
    { code: "manual_review", evidence_count: 2 },
    "CIS leaves this decision to a person. Review the 2 items listed below.",
  ],
  databases_not_covered: [
    {
      code: "databases_not_covered",
      evidence_count: 1,
      databases: ["postgres", "sales"],
    },
    "The snapshot only covers the database DBGuard connected to. Check these databases too: postgres and sales. 1 item from the connected database is listed below.",
  ],
  empty_review_set: [
    { code: "empty_review_set", evidence_count: 0 },
    "CIS asks a person to review each matching item, and nothing matched, so there is nothing to review.",
  ],
  unlimited_connections: [
    { code: "unlimited_connections", role_count: 2 },
    "2 login roles have no connection limit (-1). CIS counts any such account as a failure.",
  ],
  connection_limits_set: [
    { code: "connection_limits_set", evidence_count: 3 },
    "Every login role in scope has a connection limit.",
  ],
  archive_mode_off: [
    { code: "archive_mode_off", archive_mode: "off" },
    "WAL archiving is off (archive_mode is 'off'). CIS requires it to be on.",
  ],
  archive_destination_missing: [
    { code: "archive_destination_missing" },
    "archive_mode is on, but neither archive_command nor archive_library is set, so nothing is archived.",
  ],
  archive_destination_conflict: [
    { code: "archive_destination_conflict" },
    "Both archive_command and archive_library are set. PostgreSQL refuses to archive in that case.",
  ],
  archive_latest_failed: [
    {
      code: "archive_latest_failed",
      last_failed_time: "2026-10-26T05:40:54+00:00",
      last_archived_time: null,
    },
    "The most recent archive attempt failed (last failure 2026-10-26T05:40:54+00:00, last success never).",
  ],
  archive_standby: [
    { code: "archive_standby" },
    "This server is a standby. Check archiving on the primary, or confirm how this standby is meant to archive.",
  ],
  archive_never_run: [
    { code: "archive_never_run", archived_count: 0, failed_count: 0 },
    "Archiving is configured, but no WAL file has been archived yet and none has failed. Check again once the server has written some WAL.",
  ],
  archive_stats_reset_recent: [
    {
      code: "archive_stats_reset_recent",
      stats_reset: "2026-10-26T05:40:54+00:00",
      max_age_hours: 24,
    },
    "The archiver statistics were reset at 2026-10-26T05:40:54+00:00, within the last 24 hours, and nothing has been archived since, so DBGuard cannot tell whether archiving works.",
  ],
  archive_timestamp_missing: [
    { code: "archive_timestamp_missing", field: "last_archived_time" },
    "The archiver reports archived files but no time for the last one ('last_archived_time').",
  ],
  archive_timestamp_after_collection: [
    {
      code: "archive_timestamp_after_collection",
      field: "last_archived_time",
      collected_at: "2026-10-26T06:40:54Z",
    },
    "The last archive time is later than the snapshot time (2026-10-26T06:40:54Z). Check the server clock and collect again.",
  ],
  archive_older_than_max_age: [
    {
      code: "archive_older_than_max_age",
      last_archived_time: "2026-10-24T06:40:54+00:00",
      collected_at: "2026-10-26T06:40:54Z",
      max_age_hours: 24,
    },
    "The last successful archive was at 2026-10-24T06:40:54+00:00, more than 24 hours before this snapshot (2026-10-26T06:40:54Z). On a quiet database this can be normal; otherwise check the archiver.",
  ],
  archive_recent: [
    {
      code: "archive_recent",
      last_archived_time: "2026-10-26T06:35:54+00:00",
      collected_at: "2026-10-26T06:40:54Z",
      max_age_hours: 24,
    },
    "The last successful archive was at 2026-10-26T06:35:54+00:00, within 24 hours of the snapshot, with no later failure.",
  ],
}

test("every known explanation code has a fixed sentence", () => {
  assert.deepEqual(Object.keys(CASES).sort(), [...KNOWN_CODES].sort())
  for (const [code, [facts, sentence]] of Object.entries(CASES))
    assert.equal(explanationSentence(facts), sentence, code)
})

test("session_override: unknown row label, condition cause, missing source", () => {
  const row = {
    status: "GAPPED",
    explanation: {
      code: "session_override",
      evidence: "check",
      setting_name: "log_statement",
      source: "database",
    },
  }
  const explained = explainRow(row)
  assert.equal(explained.unknown, true)
  assert.ok(
    explained.sentence.startsWith(
      `${UNKNOWN_LABEL}. The value of log_statement`,
    ),
  )
  assert.match(explained.sentence, /\(source 'database'\)/)
  assert.doesNotMatch(explained.sentence, /\bPASS\b(?! or FAIL)/)
  assert.match(
    explanationSentence({
      code: "condition_unknown",
      cause: "session_override",
      evidence: "condition",
      source: "database user",
      ...syslogCondition,
    }),
    /^Only applies when logs are sent to syslog, and DBGuard couldn't confirm that\. The value of log_destination DBGuard read is set for a role, a database or the session \(source 'database user'\)/,
  )
  assert.match(
    explanationSentence({
      code: "session_override",
      setting_name: "log_statement",
      source: null,
    }),
    /set for a role, a database or the session, not for the whole server/,
  )
})

test("redacted_secret_setting: unknown row label and condition cause, never PASS", () => {
  const explained = explainRow({
    status: "GAPPED",
    explanation: {
      code: "redacted_secret_setting",
      evidence: "check",
      setting_name: "archive_command",
    },
  })
  assert.equal(explained.unknown, true)
  assert.equal(
    explained.sentence,
    `${UNKNOWN_LABEL}. DBGuard deliberately never reads this setting's value because it can contain a secret, so it can't say PASS or FAIL; check it by hand.`,
  )
  assert.equal(
    explanationSentence({
      code: "condition_unknown",
      cause: "redacted_secret_setting",
      evidence: "condition",
      ...syslogCondition,
    }),
    "Only applies when logs are sent to syslog, and DBGuard couldn't confirm that. DBGuard deliberately never reads this setting's value because it can contain a secret, so it can't say PASS or FAIL; check it by hand. So it can't tell whether this control applies.",
  )
})

test("policy_missing covers every case and names the profile", () => {
  assert.match(
    explanationSentence({
      code: "policy_missing",
      case: "profile_unapproved",
      profile_id: "acme",
    }),
    /profile 'acme' has not been approved by a named person/,
  )
  assert.match(
    explanationSentence({
      code: "policy_missing",
      case: "no_value_for_spec",
      profile_id: "acme",
    }),
    /profile 'acme' has no value for this control/,
  )
  assert.equal(
    explanationSentence({ code: "policy_missing", case: "surprise" }),
    GENERIC_UNKNOWN_SENTENCE,
  )
})

test("not_collected variants: missing entry and unavailable settings section", () => {
  assert.match(
    explanationSentence({
      code: "not_collected",
      setting_name: "ssl",
      entry_status: "missing",
    }),
    /This snapshot has no reading of ssl/,
  )
  assert.match(
    explanationSentence({
      code: "not_collected",
      setting_name: "ssl",
      entry_status: "section_unavailable",
      gap_reason: "insufficient_privilege",
    }),
    /could not read the server's settings at all \(collector said: 'insufficient_privilege'\)/,
  )
})

test("condition_unknown explains each cause and refuses an unknown cause", () => {
  for (const cause of [
    "stale_spec_hash",
    "collector_error",
    "unit_or_non_text_value",
  ])
    assert.match(
      explanationSentence({
        code: "condition_unknown",
        cause,
        ...syslogCondition,
      }),
      /^Only applies when logs are sent to syslog, and DBGuard couldn't confirm that\. .+ So it can't tell whether this control applies\.$/,
    )
  assert.equal(
    explanationSentence({
      code: "condition_unknown",
      cause: "mystery",
      ...syslogCondition,
    }),
    GENERIC_UNKNOWN_SENTENCE,
  )
})

test("unknown codes and malformed explanations fall back to the generic unknown sentence", () => {
  assert.ok(GENERIC_UNKNOWN_SENTENCE.startsWith(UNKNOWN_LABEL))
  // A fixed notice (Evidence.tsx renders it), never an explanation code.
  for (const bad of [
    undefined,
    null,
    "condition_false",
    42,
    [],
    {},
    { code: 7 },
    { code: "brand_new_code" },
    { code: "restore_test_reminder" },
    { code: "__proto__" },
    { code: "toString" },
  ])
    assert.equal(explanationSentence(bad), GENERIC_UNKNOWN_SENTENCE)
})

test("missing facts never throw and never claim PASS", () => {
  for (const code of KNOWN_CODES) {
    const sentence = explanationSentence({ code })
    assert.equal(typeof sentence, "string")
    assert.ok(sentence.length > 0, code)
    assert.doesNotMatch(sentence, /\bpasses\b|\bpassed\b/i, code)
  }
})

test("condition phrases are built from the operator, not free text", () => {
  assert.equal(
    conditionPhrase({ setting_name: "x", operator: "equals", expected: "on" }),
    "x is 'on'",
  )
  assert.equal(
    conditionPhrase({
      setting_name: "x",
      operator: "in",
      expected: ["a", "b"],
    }),
    "x is one of 'a', 'b'",
  )
  assert.equal(
    conditionPhrase({
      setting_name: "log_min_messages",
      operator: "severity",
      expected: "warning",
      direction: "at_or_less_verbose",
    }),
    "log_min_messages is 'warning' or less verbose",
  )
  assert.equal(
    conditionPhrase({ setting_name: "x", operator: "unheard_of" }),
    "a condition on x holds",
  )
})

test("collected values are quoted and clipped", () => {
  assert.equal(quoteValue(""), "'' (empty)")
  assert.equal(quoteValue(["a", "b"]), "'a', 'b'")
  assert.equal(quoteValue(null), "unknown")
  const long = quoteValue("x".repeat(500))
  assert.ok(long.length < 200)
  assert.ok(long.endsWith("…'"))
})

test("status labels: NOT_APPLICABLE badge, unknowns need human review, unrecognised is never PASS", () => {
  assert.equal(statusLabel("NOT_APPLICABLE"), "NOT APPLICABLE")
  for (const s of [
    "GAPPED",
    "NOT_COLLECTED",
    "STALE",
    "ERROR",
    "WEIRD",
    undefined,
    1,
  ]) {
    assert.equal(statusKind(s), "unknown")
    assert.equal(statusLabel(s), UNKNOWN_LABEL)
  }
  assert.equal(statusKind("PASS"), "pass")
  assert.equal(statusKind("pass"), "unknown")
  assert.equal(statusKind("MANUAL_REVIEW"), "manual")
})

test("rows: N/A and unknown rows explain with the CIS rule; unknown rows carry the label", () => {
  const na = explainRow({
    id: "cis-pg17-v1.1.0:3.1.11",
    status: "NOT_APPLICABLE",
    cis: {
      recommendation: "3.1.11",
      title: "Ensure Syslog messages are not suppressed",
    },
    explanation: {
      code: "condition_false",
      ...syslogCondition,
      actual: "stderr",
    },
  })
  assert.equal(na.cis, "CIS 3.1.11: Ensure Syslog messages are not suppressed")
  assert.equal(na.unknown, false)
  assert.equal(na.quote, syslogCondition.condition_quote)
  assert.match(na.sentence, /^Only applies when logs are sent to syslog\./)

  const stale = explainRow({
    id: "cis-pg17-v1.1.0:3.1.20",
    status: "STALE",
    title: "Ensure log_connections is enabled",
    explanation: { code: "stale_spec_hash", setting_name: "log_connections" },
  })
  assert.equal(stale.cis, "CIS 3.1.20: Ensure log_connections is enabled")
  assert.ok(stale.sentence.startsWith(`${UNKNOWN_LABEL}. This snapshot`))
  assert.equal(stale.unknown, true)

  // A GAPPED projection row with no explanation still gets the CIS rule and label.
  const gapped = explainRow({ id: "cis-pg17-v1.1.0:5.2", status: "GAPPED" })
  assert.equal(gapped.cis, "CIS 5.2")
  assert.equal(gapped.sentence, GENERIC_UNKNOWN_SENTENCE)

  assert.equal(explainRow({ id: "x:1", status: "PASS" }), null)
  assert.equal(explainRow({ id: "x:1", status: "FAIL" }), null)
})

test("policy_missing rows are flagged and collected for the banner", () => {
  const rows = [
    {
      id: "cis-pg17-v1.1.0:3.1.2",
      status: "MANUAL",
      reason_code: "policy_missing",
      cis: {
        recommendation: "3.1.2",
        title: "Ensure the log destinations are set correctly",
      },
      explanation: { code: "policy_missing", case: "no_profile" },
    },
    {
      id: "cis-pg17-v1.1.0:3.1.3",
      status: "MANUAL",
      reason_code: "tier_manual",
    },
    {
      id: "cis-pg17-v1.1.0:3.1.4",
      status: "MANUAL_REVIEW",
      explanation: { code: "policy_missing", case: "no_profile" },
    },
  ]
  assert.deepEqual(
    policyMissingRows(rows).map((r) => r.id),
    ["cis-pg17-v1.1.0:3.1.2", "cis-pg17-v1.1.0:3.1.4"],
  )
  // Banner order follows CIS numbering: 3.1.2 before 3.1.10.
  assert.deepEqual(
    policyMissingRows([
      { id: "b:3.1.10", reason_code: "policy_missing" },
      { id: "b:3.1.2", reason_code: "policy_missing" },
    ]).map((r) => r.id),
    ["b:3.1.2", "b:3.1.10"],
  )
  assert.equal(needsExplanation(rows[1]), false)
  const why = explainRow(rows[0])
  assert.equal(why.policyMissing, true)
  assert.equal(why.unknown, false)
  assert.equal(isPolicyMissing(rows[0]), true)
  assert.equal(cisRule({ id: "plain" }), "plain")
})

// ---- catalog rows (F6, 7.4) ------------------------------------------------------
// Catalog rows carry an explanation on every result, so every catalog row gets a
// reason (Melvin: a plain-language reason on every row). Unknown ones carry the label.

const catalogRow = (status, explanation) => ({
  spec_id: "cis-pg17-v1.1.0:5.5",
  status,
  cis: {
    recommendation: "5.5",
    title: "Ensure per-account connection limits are used",
  },
  evidence_paths: ["baseline.roles"],
  explanation,
})

test("every catalog row gets a reason, PASS and FAIL included", () => {
  for (const [status, code] of [
    ["PASS", "connection_limits_set"],
    ["FAIL", "unlimited_connections"],
    ["MANUAL", "manual_review"],
  ]) {
    const row = catalogRow(status, { ...CASES[code][0] })
    assert.ok(needsExplanation(row), status)
    const why = explainRow(row)
    assert.equal(why.sentence, CASES[code][1], status)
    assert.equal(why.unknown, false, status)
    assert.equal(
      why.cis,
      "CIS 5.5: Ensure per-account connection limits are used",
    )
  }
  // A setting row that passes still gets none (no catalog evidence paths).
  assert.equal(
    explainRow({ spec_id: "cis-pg17-v1.1.0:3.1.20", status: "PASS" }),
    null,
  )
})

test("unknown catalog rows carry the human-review label and never read as PASS", () => {
  for (const status of ["GAPPED", "NOT_COLLECTED"]) {
    for (const code of [
      "section_not_collected",
      "field_missing",
      "wrong_pg_major",
    ]) {
      const why = explainRow(catalogRow(status, { ...CASES[code][0] }))
      assert.equal(statusLabel(status), UNKNOWN_LABEL)
      assert.equal(why.unknown, true, code)
      assert.ok(why.sentence.startsWith(`${UNKNOWN_LABEL}. `), why.sentence)
      assert.match(why.sentence, /can't say PASS/, code)
    }
  }
})

test("a catalog gap without a recorded reason does not invent one", () => {
  const sentence = explanationSentence({
    code: "section_not_collected",
    section: "archiving",
  })
  assert.match(sentence, /'archiving'/)
  assert.doesNotMatch(sentence, /collector said/)
  // Without the section the sentence would name nothing: generic unknown instead.
  assert.equal(
    explanationSentence({ code: "section_not_collected" }),
    GENERIC_UNKNOWN_SENTENCE,
  )
  assert.equal(
    explanationSentence({ code: "field_missing", section: "roles" }),
    GENERIC_UNKNOWN_SENTENCE,
  )
})

test("catalog facts are quoted and clipped, never trusted as text", () => {
  const sentence = explanationSentence({
    code: "archive_mode_off",
    archive_mode: "x".repeat(500),
  })
  assert.ok(sentence.length < 300, sentence)
  assert.match(sentence, /…'/)
})
