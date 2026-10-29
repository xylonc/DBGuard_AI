"""Wave 1b per-control tests: the 14 new CIS PG17 v1.1.0 setting controls.

Fixed-value automated controls (F2/F4): 3.1.3, 3.1.14, 3.1.15, 3.1.24, 5.2.
Policy controls (F3/F2, parameterised, expected value from an APPROVED profile):
3.1.2, 3.1.4, 3.1.5, 3.1.6, 3.1.8, 3.1.9, 3.1.10, 3.1.13, 3.1.26.

For each: PASS / FAIL / GAPPED / NOT_APPLICABLE (where the spec has applies_when) /
policy_missing (no profile, unapproved profile, approved profile without a value).

Every expected value below is written out from the CIS text and Melvin's Gate 1
rulings (docs/gates/GATE1-combined.md: A2 severity direction, A3 prefix escapes,
A4 address-aware 5.2, A5 timezones, A6 syslog conditions, A8 profile values),
never read back from the spec or the profile, so a spec or profile that drifts is
caught. Approved profiles here are in-memory test objects; the repository profile
is never written. No Docker, network or model.
"""
import copy

import pytest
import yaml
from pydantic import ValidationError

from app.models import FindingStatus, SetConfigTemplateParams
from app.services.assessment_service import AssessmentService
from app.services.spec_engine import assess, spec_sha256
from app.services.spec_engine.manifest import condition_check_id
from app.services.spec_engine.policy import default_profile_path, load_default_profile, parse_profile
from catalog.controls.assess.registry import CONTROL_REGISTRY
from catalog.controls.assess.spec_controls import _setting_rule
from scripts.sandbox_poc import demo_template
from services.sandbox_poc.planning import FROM_PROFILE, POLICIES, SITE_FIX_MISSING, fix_scope, risk_review
from services.sandbox_poc.provenance import setting_rows
from services.sandbox_poc.shared import ContractError, SpecEngine
from services.sandbox_poc.workflow import template_action
from test_sandbox_poc import engine, snapshot  # noqa: F401  shared fixtures

B = "cis-pg17-v1.1.0"
CIS_PREFIX = "%m [%p]: [%l-1] db=%d,user=%u,app=%a,client=%h"
SYSLOG = "stderr,syslog"

# ---------------------------------------------------------------------------
# Written-out expectations
# ---------------------------------------------------------------------------

# rec: (setting, pg_settings vartype, PG17 context, compliant, non-compliant, fix value)
# fix value None = no reviewed fixed value (5.2: site-specific, from an approved profile only).
FIXED = {
    # CIS 3.1.3: "confirm that the logging_collector is enabled (on)"
    "3.1.3": ("logging_collector", "bool", "postmaster", ["on"], ["off"], "on"),
    # CIS 3.1.14 "at least warning" read as "logs at least as much as warning" (ruling A2):
    # PG17 order debug5..debug1, info, notice, warning, error, log, fatal, panic.
    "3.1.14": ("log_min_messages", "enum", "superuser",
               ["warning", "notice", "info", "debug1", "debug2", "debug3", "debug4", "debug5"],
               ["error", "log", "fatal", "panic"], "warning"),
    # CIS 3.1.15 "at least error", same reading (ruling A2).
    "3.1.15": ("log_min_error_statement", "enum", "superuser",
               ["error", "warning", "notice", "info", "debug1", "debug5"],
               ["log", "fatal", "panic"], "error"),
    # CIS 3.1.24: the seven escapes %m %p %l %d %u %a %h, in any order (ruling A3).
    "3.1.24": ("log_line_prefix", "string", "sighup",
               [CIS_PREFIX, "%h %a %u %d %l %p %m", CIS_PREFIX + " xid=%x", "%t %m %p %l %d %u %a %h"],
               ["%m [%p] ", "%m [%p]: [%l-1] db=%d,user=%u,app=%a",  # PG17 default; no %h
                "%%m %%p %%l %%d %%u %%a %%h",                       # literal percents only
                "user=%u,db=%d,app=%a,client=%h"],                   # syslog-only set: still FAIL
               CIS_PREFIX),
    # CIS 5.2: "If * or 0.0.0.0 is returned, this is a failure", any list entry (ruling A4).
    # '' (unix sockets only, no TCP) returns neither * nor 0.0.0.0, so it passes; '::' is not
    # in the CIS text (5.2 interpretation note) and passes here too.
    "5.2": ("listen_addresses", "string", "postmaster",
            ["localhost", "10.0.0.5", "localhost, 10.0.0.5", "127.0.0.1,::1", "::", ""],
            ["*", "0.0.0.0", "*, 10.0.0.1", "localhost,0.0.0.0", "10.0.0.5 , *"], None),
}

# rec: (setting, pg_settings vartype/unit, expected (ruling A5/A8), fix, compliant, non-compliant,
#       applies only when logging to syslog)
POLICY = {
    "3.1.2": ("log_destination", ("string", None), ["stderr"], "stderr",
              ["stderr", "stderr,csvlog", "csvlog, stderr"], ["csvlog", "syslog", "csvlog,jsonlog"], False),
    "3.1.4": ("log_directory", ("string", None), "/var/log/postgresql", "/var/log/postgresql",
              ["/var/log/postgresql"], ["log", "/var/log/postgresql/sub", "/tmp"], False),
    "3.1.5": ("log_filename", ("string", None), "postgresql-%a.log", "postgresql-%a.log",
              ["postgresql-%a.log"], ["postgresql-%Y-%m-%d_%H%M%S.log", "postgresql.log"], False),
    "3.1.6": ("log_file_mode", ("integer", None), ["0600", "0640"], "0600",
              ["0600", "0640"], ["0644", "0666", "0700"], False),
    "3.1.8": ("log_rotation_age", ("integer", "min"), ["1h", "1d"], "1d",
              ["1h", "1d"], ["0", "12h", "2d"], False),
    "3.1.9": ("log_rotation_size", ("integer", "kB"), ["0", "1GB"], "1GB",
              ["0", "1GB"], ["10MB", "2GB"], False),
    "3.1.10": ("syslog_facility", ("enum", None), "local0", "local0",
               ["local0"], ["local1", "local7"], True),
    "3.1.13": ("syslog_ident", ("string", None), "postgres", "postgres",
               ["postgres"], ["proddb", "postgres17"], True),
    "3.1.26": ("log_timezone", ("string", None), ["GMT", "UTC", "Etc/UTC"], "GMT",
               ["GMT", "UTC", "Etc/UTC"], ["America/New_York", "Europe/London", "EST"], False),
}
# pg_settings rows of integer vartype (with or without unit) are never SHOW-equivalent
# offline, so ASSESS keeps 3.1.6, 3.1.8 and 3.1.9 GAPPED; the Phase 1 SHOW check decides them.
OFFLINE_UNREADABLE = {"3.1.6", "3.1.8", "3.1.9"}

FIXED_IDS = sorted(FIXED)
POLICY_IDS = sorted(POLICY)


def sid(rec):
    return f"{B}:{rec}"


def spec_of(engine, rec):
    return copy.deepcopy(next(s for s in engine.specs if s["spec_id"] == sid(rec)))


def profile_doc(approved=True, values=None, **extra):
    doc = {"profile_id": "wave1b-unit", "benchmark": B,
           "approved_by": "Unit Test Reviewer" if approved else None,
           "approved_at": "2026-10-28" if approved else None,
           "values": values if values is not None else {
               sid(rec): {"expected": exp, "fix": fix, "break": bad[0]}
               for rec, (_, _, exp, fix, _, bad, _) in POLICY.items()}}
    doc.update(extra)
    return doc


def make_profile(engine, approved=True, values=None, **extra):
    return parse_profile(yaml.safe_dump(profile_doc(approved, values, **extra)).encode(), engine.records)


# ---------------------------------------------------------------------------
# The committed specs say what the CIS text and rulings say
# ---------------------------------------------------------------------------

def test_new_controls_are_exactly_these(engine):
    tiers = {s["spec_id"]: s["tier"] for s in engine.specs}
    for rec in FIXED:
        assert tiers[sid(rec)] == "automated", rec
    for rec in POLICY:
        assert tiers[sid(rec)] == "parameterised", rec
    assert tiers[sid("6.10")] == "needs_capability"


@pytest.mark.parametrize("rec", FIXED_IDS)
def test_fixed_spec_check(engine, rec):
    name, _, _, good, bad, _ = FIXED[rec]
    spec = spec_of(engine, rec)
    assert spec["authored_by"] == "agent"
    check = spec["check"]
    assert (check["kind"], check["setting_name"], check["query"]) == ("setting", name, f"SHOW {name}")
    assert "expected_from" not in check
    assert "applies_when" not in spec
    if rec in ("3.1.14", "3.1.15"):
        assert (check["operator"], check["direction"]) == ("severity", "at_or_more_verbose")
        assert check["expected"] == {"3.1.14": "warning", "3.1.15": "error"}[rec]
    if rec == "3.1.24":
        assert check["operator"] == "contains_escapes"
        assert sorted(check["expected"]) == sorted(["%m", "%p", "%l", "%d", "%u", "%a", "%h"])
    if rec == "5.2":
        assert check["operator"] == "no_item_in"
        assert sorted(check["expected"]) == ["*", "0.0.0.0"]
    if rec == "3.1.3":
        assert (check["operator"], check["expected"]) == ("equals", "on")
    assert spec["proof"]["break"]["value"] in bad
    if rec != "5.2":
        assert spec["proof"]["fix"]["value"] in good


@pytest.mark.parametrize("rec", POLICY_IDS)
def test_policy_spec_check(engine, rec):
    name, _, _, _, _, _, syslog_only = POLICY[rec]
    spec = spec_of(engine, rec)
    check = spec["check"]
    assert (check["kind"], check["setting_name"], check["query"]) == ("setting", name, f"SHOW {name}")
    assert check["expected_from"] == "policy" and "expected" not in check
    assert "proof" not in spec
    if syslog_only:
        assert spec["applies_when"]["setting_name"] == "log_destination"
        assert spec["applies_when"]["operator"] == "contains_items"
        assert spec["applies_when"]["expected"] == ["syslog"]
    else:
        assert "applies_when" not in spec


def test_reference_profile_holds_the_ruled_values_and_stays_unapproved(engine):
    seed = load_default_profile(engine.records)
    assert seed.approved is False and seed.approved_by is None and seed.approved_at is None
    assert set(seed.values) == {sid(rec) for rec in POLICY}
    for rec, (_, _, expected, fix, good, bad, _) in POLICY.items():
        entry = seed.values[sid(rec)]
        assert entry["expected"] == expected, rec
        assert entry["fix"] == fix, rec
        assert entry["break"] in bad, rec
    # Gate 1 ruling A5: GMT and UTC are always accepted
    assert {"GMT", "UTC"} <= set(seed.values[sid("3.1.26")]["expected"])
    # Gate 1 ruling A8: 3.1.4 points outside PGDATA
    assert seed.values[sid("3.1.4")]["expected"].startswith("/")


# ---------------------------------------------------------------------------
# Phase 1 assessor (collector check entries)
# ---------------------------------------------------------------------------

def phase1(engine, rec, entry, condition=SYSLOG, policy=None):
    spec = spec_of(engine, rec)
    checks = {}
    if entry is not None:
        checks[spec["spec_id"]] = {"spec_hash": spec_sha256(spec), "query": spec["check"]["query"], **entry}
    if "applies_when" in spec and condition is not None:
        checks[condition_check_id(spec["spec_id"])] = {
            "spec_hash": spec_sha256(spec), "query": "SHOW log_destination", "status": "ok",
            "result": condition}
    snap = {"envelope": {"schema_version": "0.3.0", "target_id": "t", "database": "d",
                         "collector_sha256": "a" * 64,
                         "manifest": {"sha256": "b" * 64, "manifest_version": 1, "benchmark_id": B,
                                      "check_count": len(checks)}},
            "baseline": {"identity": {"server_version_num": 170000}},
            "checks": checks}
    row = assess([spec], snap, engine.records, policy)["results"][0]
    return row["result"], row["reason_code"]


def ok(value):
    return {"status": "ok", "result": value}


@pytest.mark.parametrize("rec", FIXED_IDS)
def test_fixed_phase1_pass_fail(engine, rec):
    _, _, _, good, bad, _ = FIXED[rec]
    for value in good:
        assert phase1(engine, rec, ok(value)) == ("PASS", "operator_true"), value
    for value in bad:
        assert phase1(engine, rec, ok(value)) == ("FAIL", "operator_false"), value


@pytest.mark.parametrize("rec", FIXED_IDS)
def test_fixed_phase1_unknown_is_never_pass(engine, rec):
    good = FIXED[rec][3][0]
    assert phase1(engine, rec, None) == ("NOT_COLLECTED", "no_entry")
    assert phase1(engine, rec, {"status": "not_collected"}) == ("NOT_COLLECTED", "status_not_collected")
    assert phase1(engine, rec, {"status": "error", "error": "permission denied"}) == ("ERROR", "status_error")
    assert phase1(engine, rec, {"status": "ok", "result": None}) == ("ERROR", "non_string_result")
    assert phase1(engine, rec, {**ok(good), "spec_hash": "0" * 64}) == ("STALE", "hash_mismatch")


@pytest.mark.parametrize("rec,value", [
    ("3.1.14", "WARNING"), ("3.1.14", "loud"), ("3.1.14", "warning "), ("3.1.15", "Error"),
    ("3.1.15", "notice,error"), ("3.1.3", "true"), ("5.2", "localhost,,10.0.0.5"),
    ("5.2", "localhost,"),
])
def test_fixed_phase1_uninterpretable_value_is_error_not_pass(engine, rec, value):
    """Values PostgreSQL SHOW would never print are uninterpretable, never PASS."""
    result = phase1(engine, rec, ok(value))
    assert result[0] in ("ERROR", "FAIL"), (value, result)
    if rec in ("3.1.14", "3.1.15", "5.2"):
        assert result == ("ERROR", "operator_error"), (value, result)


@pytest.mark.parametrize("rec", POLICY_IDS)
def test_policy_phase1_pass_fail_with_approved_profile(engine, rec):
    _, _, _, _, good, bad, _ = POLICY[rec]
    policy = make_profile(engine)
    for value in good:
        assert phase1(engine, rec, ok(value), policy=policy) == ("PASS", "operator_true"), value
    for value in bad:
        assert phase1(engine, rec, ok(value), policy=policy) == ("FAIL", "operator_false"), value


@pytest.mark.parametrize("rec", POLICY_IDS)
def test_committed_reference_profile_agrees_with_rulings_once_approved(engine, rec):
    """Approve a COPY of reference.yaml in memory; its verdicts match the written-out values."""
    doc = yaml.safe_load(default_profile_path(B).read_bytes())
    doc.update(approved_by="Unit Test Reviewer", approved_at="2026-10-28")
    policy = parse_profile(yaml.safe_dump(doc).encode(), engine.records)
    _, _, _, _, good, bad, _ = POLICY[rec]
    for value in good:
        assert phase1(engine, rec, ok(value), policy=policy)[0] == "PASS", value
    for value in bad:
        assert phase1(engine, rec, ok(value), policy=policy)[0] == "FAIL", value


@pytest.mark.parametrize("rec", POLICY_IDS)
@pytest.mark.parametrize("case", ["no_profile", "unapproved", "approved_without_value"])
def test_policy_missing_is_manual_and_never_pass(engine, rec, case):
    _, _, _, _, good, bad, _ = POLICY[rec]
    policy = {"no_profile": None,
              "unapproved": make_profile(engine, approved=False),
              "approved_without_value": make_profile(
                  engine, values={k: v for k, v in profile_doc()["values"].items() if k != sid(rec)})}[case]
    for value in good + bad:
        for condition in (SYSLOG, "stderr", None):
            assert phase1(engine, rec, ok(value), condition=condition, policy=policy) == (
                "MANUAL", "policy_missing"), (value, condition)
    # the committed (unapproved) reference profile behaves exactly like case "unapproved"
    assert phase1(engine, rec, ok(good[0]), policy=load_default_profile(engine.records)) == (
        "MANUAL", "policy_missing")


@pytest.mark.parametrize("rec", POLICY_IDS)
def test_policy_phase1_unknown_is_never_pass(engine, rec):
    good = POLICY[rec][4][0]
    policy = make_profile(engine)
    assert phase1(engine, rec, None, policy=policy) == ("NOT_COLLECTED", "no_entry")
    assert phase1(engine, rec, {"status": "not_collected"}, policy=policy) == (
        "NOT_COLLECTED", "status_not_collected")
    assert phase1(engine, rec, {"status": "error", "error": "permission denied"}, policy=policy) == (
        "ERROR", "status_error")
    assert phase1(engine, rec, {**ok(good), "spec_hash": "0" * 64}, policy=policy) == (
        "STALE", "hash_mismatch")


SYSLOG_CONTROLS = ["3.1.10", "3.1.11", "3.1.13"]


def _good_bad(rec):
    if rec == "3.1.11":
        return ["on"], ["off"]  # CIS 3.1.11: syslog_sequence_numbers enabled (on)
    return POLICY[rec][4], POLICY[rec][5]


@pytest.mark.parametrize("rec", SYSLOG_CONTROLS)
def test_syslog_controls_not_applicable_without_syslog(engine, rec):
    """Ruling A6: 3.1.10, 3.1.11 and 3.1.13 apply only when logging to syslog."""
    policy = make_profile(engine)
    good, bad = _good_bad(rec)
    for value in good + bad:
        for destination in ("stderr", "csvlog", "stderr,csvlog,jsonlog"):
            assert phase1(engine, rec, ok(value), condition=destination, policy=policy) == (
                "NOT_APPLICABLE", "condition_false"), (value, destination)
        for destination in ("syslog", "stderr,syslog", "csvlog, SYSLOG"):
            result = phase1(engine, rec, ok(value), condition=destination, policy=policy)
            assert result[0] == ("PASS" if value in good else "FAIL"), (value, destination)


@pytest.mark.parametrize("rec", SYSLOG_CONTROLS)
@pytest.mark.parametrize("condition_entry,expected", [
    (None, ("NOT_COLLECTED", "condition_no_entry")),
    ("std err;syslog", ("ERROR", "condition_operator_error")),
])
def test_syslog_controls_unknown_condition_is_never_pass_or_na(engine, rec, condition_entry, expected):
    policy = make_profile(engine)
    good = _good_bad(rec)[0][0]
    assert phase1(engine, rec, ok(good), condition=condition_entry, policy=policy) == expected


# ---------------------------------------------------------------------------
# ASSESS (offline pg_settings rows)
# ---------------------------------------------------------------------------

def row(name, value, vartype, unit=None, **extra):
    return {"name": name, "setting": value, "vartype": vartype, "unit": unit, "sanitised": False, **extra}


def offline(spec, rows, policy=None, version=170000):
    snap = {"snapshot_id": "wave1b", "identity": {"server_version_num": version}, "settings": rows,
            "schemas": [], "password_types": [], "gaps": []}
    if rows is None:
        snap["gaps"] = [{"section": "settings", "reason": "insufficient_privilege"}]
    return _setting_rule(spec, policy)(snap)


SYSLOG_ROW = row("log_destination", SYSLOG, "string")


@pytest.mark.parametrize("rec", FIXED_IDS)
def test_fixed_assess_pass_fail(engine, rec):
    name, vartype, _, good, bad, _ = FIXED[rec]
    spec = spec_of(engine, rec)
    for value in good:
        assert offline(spec, [row(name, value, vartype)]).status == FindingStatus.PASS, value
    for value in bad:
        finding = offline(spec, [row(name, value, vartype)])
        assert finding.status == FindingStatus.FAIL, value
        assert finding.control_metadata.template_id == "SET_CONFIG_PARAMETER"


@pytest.mark.parametrize("rec", FIXED_IDS)
@pytest.mark.parametrize("unreadable", [
    None, {"setting": None}, {"sanitised": True}, {"unit": "s"}, {"vartype": "integer"},
    {"vartype": "real"}, {"setting": 1}, "missing", "wrong_major_16", "wrong_major_18",
], ids=["section_gap", "null", "sanitised", "unit", "integer", "real", "non_string", "missing",
        "pg16", "pg18"])
def test_fixed_assess_unreadable_evidence_is_gapped(engine, rec, unreadable):
    name, vartype, _, good, _, _ = FIXED[rec]
    spec = spec_of(engine, rec)
    version = 170000
    if unreadable is None:
        rows = None
    elif unreadable == "missing":
        rows = [row("log_connections", "on", "bool")]
    elif unreadable.__class__ is str:
        rows, version = [row(name, good[0], vartype)], int(unreadable[-2:]) * 10000
    else:
        rows = [{**row(name, good[0], vartype), **unreadable}]
    finding = offline(spec, rows, version=version)
    assert finding.status == FindingStatus.GAPPED and finding.is_gapped is True


@pytest.mark.parametrize("rec", POLICY_IDS)
def test_policy_assess_with_approved_profile(engine, rec):
    name, (vartype, unit), _, _, good, bad, syslog_only = POLICY[rec]
    spec = spec_of(engine, rec)
    policy = make_profile(engine)
    extra = [SYSLOG_ROW] if syslog_only else []
    for value in good + bad:
        finding = offline(spec, [row(name, value, vartype, unit), *extra], policy)
        if rec in OFFLINE_UNREADABLE:
            assert finding.status == FindingStatus.GAPPED, value
        else:
            assert finding.status == (FindingStatus.PASS if value in good else FindingStatus.FAIL), value


@pytest.mark.parametrize("rec", POLICY_IDS)
@pytest.mark.parametrize("unreadable", [None, {"sanitised": True}, {"setting": None}, "missing", "pg16"],
                         ids=["section_gap", "sanitised", "null", "missing", "pg16"])
def test_policy_assess_unreadable_evidence_is_gapped(engine, rec, unreadable):
    name, (vartype, unit), _, _, good, _, syslog_only = POLICY[rec]
    spec = spec_of(engine, rec)
    extra = [SYSLOG_ROW] if syslog_only else []
    version = 170000
    if unreadable is None:
        rows = None
    elif unreadable == "missing":
        rows = [row("log_connections", "on", "bool"), *extra]
    elif unreadable == "pg16":
        rows, version = [row(name, good[0], vartype, unit), *extra], 160004
    else:
        rows = [{**row(name, good[0], vartype, unit), **unreadable}, *extra]
    finding = offline(spec, rows, make_profile(engine), version=version)
    assert finding.status == FindingStatus.GAPPED


@pytest.mark.parametrize("rec", POLICY_IDS)
def test_policy_assess_policy_missing_is_manual_review(engine, rec):
    name, (vartype, unit), _, _, good, _, syslog_only = POLICY[rec]
    spec = spec_of(engine, rec)
    extra = [SYSLOG_ROW] if syslog_only else []
    for policy in (None, make_profile(engine, approved=False), make_profile(engine, values={})):
        finding = offline(spec, [row(name, good[0], vartype, unit), *extra], policy)
        assert finding.status == FindingStatus.MANUAL_REVIEW
        assert finding.explanation["code"] == "policy_missing"


@pytest.mark.parametrize("rec", POLICY_IDS)
def test_registry_uses_the_unapproved_reference_profile(rec):
    """The installed ASSESS registry never PASSes a policy control until a human approves."""
    name, (vartype, unit), _, _, good, _, syslog_only = POLICY[rec]
    rows = [row(name, good[0], vartype, unit), *([SYSLOG_ROW] if syslog_only else [])]
    report = AssessmentService(CONTROL_REGISTRY).evaluate(
        {"snapshot_id": "wave1b", "settings": rows, "schemas": [], "password_types": [], "gaps": []})
    finding = {f.control_id: f for f in report.findings}[sid(rec)]
    assert finding.status == FindingStatus.MANUAL_REVIEW
    assert finding.explanation == {"code": "policy_missing", "case": "profile_unapproved",
                                   "profile_id": "cis-pg17-v1.1.0-reference"}


@pytest.mark.parametrize("rec", ["3.1.10", "3.1.13"])
def test_policy_syslog_controls_assess_not_applicable_and_condition_gap(engine, rec):
    name, (vartype, unit), _, _, good, bad, _ = POLICY[rec]
    spec = spec_of(engine, rec)
    policy = make_profile(engine)
    for value in good + bad:
        finding = offline(spec, [row(name, value, vartype, unit), row("log_destination", "stderr", "string")],
                          policy)
        assert finding.status == FindingStatus.NOT_APPLICABLE, value
        assert finding.explanation["code"] == "condition_false"
    finding = offline(spec, [row(name, good[0], vartype, unit)], policy)
    assert finding.status == FindingStatus.GAPPED
    assert finding.explanation["code"] == "condition_unknown"


# ---------------------------------------------------------------------------
# Fix scope: reviewed values, profile values, no fix without approval
# ---------------------------------------------------------------------------

class _Engine:
    def __init__(self, specs, policy=None, records=None):
        self.specs, self.policy, self.records = specs, policy, records
        self.policy_pin = policy.pin() if policy is not None else None


@pytest.mark.parametrize("rec", [r for r in FIXED_IDS if FIXED[r][5] is not None])
def test_fixed_fix_value(engine, rec):
    name, _, _, good, bad, fix = FIXED[rec]
    spec, setting, value = fix_scope(engine, sid(rec))
    assert (setting, value) == (name, fix)
    assert value in good
    assert POLICIES[name][0] == fix  # a reviewed fixed value, not FROM_PROFILE


def test_5_2_offers_no_fix_without_an_approved_site_value(engine):
    with pytest.raises(ContractError, match=SITE_FIX_MISSING):
        fix_scope(engine, sid("5.2"))
    spec = spec_of(engine, "5.2")
    with pytest.raises(ContractError, match=SITE_FIX_MISSING):
        fix_scope(_Engine([spec], make_profile(engine, approved=False, fixes={sid("5.2"): "localhost, 10.0.0.5"})),
                  sid("5.2"))
    _, name, value = fix_scope(_Engine([spec], make_profile(engine, fixes={sid("5.2"): "localhost, 10.0.0.5"})),
                               sid("5.2"))
    assert (name, value) == ("listen_addresses", "localhost, 10.0.0.5")


@pytest.mark.parametrize("fix", ["*", "0.0.0.0", "10.0.0.5", "localhost, *", "localhost, 0.0.0.0", "::"])
def test_5_2_site_value_must_list_localhost_and_never_a_wildcard(engine, fix):
    """Round 2 ruling: the 5.2 fix must include localhost; a wildcard can never be a fix."""
    from app.services.spec_engine.policy import PolicyProfileError
    spec = spec_of(engine, "5.2")
    try:
        policy = make_profile(engine, fixes={sid("5.2"): fix})
    except PolicyProfileError:
        return
    with pytest.raises(ContractError):
        fix_scope(_Engine([spec], policy), sid("5.2"))


@pytest.mark.parametrize("rec", POLICY_IDS)
def test_policy_fix_value_only_from_an_approved_profile(engine, rec):
    name, _, _, fix, good, _, _ = POLICY[rec]
    assert POLICIES[name][0] == FROM_PROFILE
    with pytest.raises(ContractError, match="policy_missing"):
        fix_scope(engine, sid(rec))  # the default engine has no profile
    spec = spec_of(engine, rec)
    with pytest.raises(ContractError, match="policy_missing"):
        fix_scope(_Engine([spec], make_profile(engine, approved=False)), sid(rec))
    with pytest.raises(ContractError, match="policy_missing"):
        fix_scope(_Engine([spec], load_default_profile(engine.records)), sid(rec))
    _, setting, value = fix_scope(_Engine([spec], make_profile(engine)), sid(rec))
    assert (setting, value) == (name, fix)
    assert value in good


@pytest.mark.parametrize("rec,mutation", [
    ("3.1.3", {"expected": "off"}),
    ("3.1.14", {"expected": "debug1"}),                        # warning is less verbose than debug1
    ("3.1.14", {"direction": "at_or_less_verbose", "expected": "error"}),
    ("3.1.15", {"expected": "notice"}),
    ("3.1.24", {"expected": ["%m", "%p", "%l", "%d", "%u", "%a", "%h", "%x"]}),
])
def test_fix_refused_when_spec_direction_or_value_is_wrong(engine, rec, mutation):
    spec = spec_of(engine, rec)
    spec["check"].update(mutation)
    with pytest.raises(ContractError, match="does not satisfy"):
        fix_scope(_Engine([spec]), sid(rec))


@pytest.mark.parametrize("rec", FIXED_IDS + POLICY_IDS)
def test_forged_query_is_refused(engine, rec):
    spec = spec_of(engine, rec)
    spec["check"]["query"] = f"SHOW {spec['check']['setting_name']}; SELECT 1"
    with pytest.raises(ContractError):
        fix_scope(_Engine([spec], make_profile(engine)), sid(rec))


@pytest.mark.parametrize("rec", POLICY_IDS)
def test_policy_fix_value_must_satisfy_its_own_profile_entry(engine, rec):
    """A profile whose fix fails its own expected value is refused at parse/use time."""
    from app.services.spec_engine.policy import PolicyProfileError, profile_value_errors
    _, _, expected, _, _, bad, _ = POLICY[rec]
    values = {sid(rec): {"expected": expected, "fix": bad[0], "break": bad[0]}}
    try:
        policy = make_profile(engine, values=values)
    except PolicyProfileError:
        return
    assert profile_value_errors(policy, [spec_of(engine, rec)])
    with pytest.raises(ContractError):
        fix_scope(_Engine([spec_of(engine, rec)], policy), sid(rec))


# ---------------------------------------------------------------------------
# Template allowlist and rendering
# ---------------------------------------------------------------------------

def _fix_values():
    out = [(rec, FIXED[rec][0], FIXED[rec][5]) for rec in FIXED_IDS if FIXED[rec][5] is not None]
    out.append(("5.2", "listen_addresses", "localhost, 10.0.0.5"))
    out += [(rec, POLICY[rec][0], POLICY[rec][3]) for rec in POLICY_IDS]
    return out


@pytest.mark.parametrize("rec,name,value", _fix_values(), ids=[v[0] for v in _fix_values()])
def test_fix_value_renders_through_the_approved_template(rec, name, value):
    assert SetConfigTemplateParams(param_name=name, param_value=value).param_value == value
    sql = demo_template().render(name, value)
    assert template_action(sql, name) == {"action": "set_config", "param": name, "value": value}
    with pytest.raises(ContractError):
        template_action(sql, "log_connections")


@pytest.mark.parametrize("rec,name,value", _fix_values(), ids=[v[0] for v in _fix_values()])
@pytest.mark.parametrize("param_name,param_value", [
    ("{name}; DROP TABLE x", "{value}"),
    ('"{name}"', "{value}"),
    ("{name}_x", "{value}"),
    ("{upper}", "{value}"),
    ("{name}", "{value}'; SELECT pg_reload_conf(); --"),
    ("{name}", "{value}/*"),
    ("{name}", "{value}\nALTER SYSTEM RESET ALL"),
    ("{name}", "{value}$$"),
    ("{name}", ""),
])
def test_malicious_identifier_or_value_is_refused(rec, name, value, param_name, param_value):
    fill = dict(name=name, value=value, upper=name.upper())
    with pytest.raises(ValidationError):
        SetConfigTemplateParams(param_name=param_name.format(**fill), param_value=param_value.format(**fill))


# Formerly a known gap (strict xfails): bool/enum settings had no value rule, so
# SetConfigTemplateParams accepted any value free of quotes, ';' and comments. Now
# enforced by setting_values.SETTING_ALLOWED_VALUES on every path.
@pytest.mark.parametrize("name,value", [
    ("logging_collector", "maybe"), ("log_min_messages", "warning error"), ("syslog_facility", "local9"),
    ("log_min_messages", "loud"), ("logging_collector", "t"), ("log_min_messages", "WARNING"),
    ("log_min_messages", "debug"),
    ("log_line_prefix", "%m\t"), ("listen_addresses", "*"), ("log_directory", "/var/log/../../etc"),
    ("log_timezone", "UTC 1"), ("log_file_mode", "0800"), ("log_rotation_age", "1w"),
    ("log_rotation_size", "1PB"), ("log_destination", "Stderr"), ("log_filename", "../x.log"),
])
def test_value_outside_the_allowlist_is_refused(name, value):
    with pytest.raises(ValidationError):
        SetConfigTemplateParams(param_name=name, param_value=value)


# ---------------------------------------------------------------------------
# Risk review: restart for postmaster settings, reload for the rest
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("rec", [r for r in FIXED_IDS if FIXED[r][5] is not None])
def test_fixed_risk_review_requires_restart_only_for_postmaster(engine, snapshot, rec):
    name, _, context, _, bad, fix = FIXED[rec]
    snap = copy.deepcopy(snapshot)
    setting_rows(snap)[name].update(context=context, setting=bad[0])
    review = risk_review(engine, snap, sid(rec))
    assert (review["current_value"], review["proposed_value"]) == (bad[0], fix)
    assert review["requires"] == ("restart" if context == "postmaster" else "reload")
    if context == "postmaster":
        assert review["operational_risk"] == "high"
    assert review["dba_review_required"] is True
    assert review["fix_value_source"] == {"source": "reviewed_policy"}


@pytest.mark.parametrize("rec", POLICY_IDS)
def test_policy_risk_review_names_the_profile(engine, snapshot, rec):
    name, _, _, fix, _, bad, _ = POLICY[rec]
    policy = make_profile(engine)
    eng = SpecEngine(engine.specs, engine.records, policy)
    snap = copy.deepcopy(snapshot)
    setting_rows(snap)[name].update(context="sighup", setting=bad[0])
    review = risk_review(eng, snap, sid(rec))
    assert (review["proposed_value"], review["requires"]) == (fix, "reload")
    assert review["fix_value_source"] == {"source": "policy_profile", "profile": policy.pin()}
    assert review["fix_value_source"]["profile"]["approved_by"] == "Unit Test Reviewer"
