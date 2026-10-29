"""Wave 1b engine contract: new operators, applies_when and the policy profile.

Every path here must end in a status that is never PASS unless the evidence is
exact and complete: unknown values are ERROR/GAPPED, a false condition is
NOT_APPLICABLE only on clean evidence, and an unapproved or incomplete policy
profile is MANUAL (policy_missing).
"""

import copy
import json
import re
import sys
from pathlib import Path
from types import SimpleNamespace

import jsonschema
import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
for extra in (str(REPO_ROOT), str(REPO_ROOT / "backend")):
    if extra not in sys.path:
        sys.path.insert(0, extra)

from app.models import FindingStatus  # noqa: E402
from app.services.spec_engine import RecordsIndex, assess, spec_sha256, validate_spec  # noqa: E402
from app.services.spec_engine.manifest import condition_check_id, manifest_from_specs  # noqa: E402
from app.services.spec_engine.operators import (  # noqa: E402
    EXPECTED_SHAPE,
    LOG_LINE_PREFIX_ESCAPES,
    OPERATOR_PARAMS,
    OPERATORS,
    SERVER_MESSAGE_LEVELS,
    SEVERITY_SCALES,
    contains_escapes,
    contains_items,
    equals,
    evaluate,
    in_,
    not_equals,
    not_in,
    severity,
)
from app.services.spec_engine.policy import (  # noqa: E402
    PolicyProfileError,
    default_profile_path,
    load_default_profile,
    parse_profile,
    profile_value_errors,
)
from app.services.spec_engine.validate import SANITISED_SETTINGS  # noqa: E402

RECORDS = RecordsIndex.load(REPO_ROOT / "catalog/benchmarks/cis-pg17-v1.1.0/records.json")
REPORT_SCHEMA = json.loads((REPO_ROOT / "catalog/specs/contracts/assessment-report-v1.json").read_text())
SPEC_SCHEMA = json.loads((REPO_ROOT / "catalog/specs/schema.json").read_text())
B = "cis-pg17-v1.1.0"


def ref(rec):
    record = RECORDS[rec]
    return {"benchmark": RECORDS.benchmark, "benchmark_version": RECORDS.benchmark_version,
            "pg_major": 17, "recommendation": rec, "title": record["title"],
            "source_sha256": record["source_sha256"]}


def severity_spec(direction="at_or_less_verbose"):
    return {
        "spec_id": f"{B}:3.1.14", "schema_version": 1, "authored_by": "agent", "ref": ref("3.1.14"),
        "tier": "automated", "reason": None,
        "check": {"kind": "setting", "setting_name": "log_min_messages", "query": "SHOW log_min_messages",
                  "operator": "severity", "direction": direction, "expected": "warning",
                  "pass_condition_quote": "If logging is not configured to at least `warning`, this is a fail."},
        "proof": {"break": {"setting_name": "log_min_messages", "value": "debug1" if direction == "at_or_less_verbose" else "error"},
                  "fix": {"setting_name": "log_min_messages", "value": "warning"}},
    }


def prefix_spec():
    return {
        "spec_id": f"{B}:3.1.24", "schema_version": 1, "authored_by": "agent", "ref": ref("3.1.24"),
        "tier": "automated", "reason": None,
        "check": {"kind": "setting", "setting_name": "log_line_prefix", "query": "SHOW log_line_prefix",
                  "operator": "contains_escapes", "expected": ["%m", "%p", "%d", "%u"],
                  "pass_condition_quote": "If the prefix does not at a minimum include "
                  "`%m [%p]: [%l-1] db=%d,user=%u,app=%a,client=%h` (for non-Syslog logging), this is a fail."},
        "proof": {"break": {"setting_name": "log_line_prefix", "value": "%m [%p] "},
                  "fix": {"setting_name": "log_line_prefix", "value": "%m [%p]: [%l-1] db=%d,user=%u "}},
    }


def listen_spec():
    return {
        "spec_id": f"{B}:5.2", "schema_version": 1, "authored_by": "agent", "ref": ref("5.2"),
        "tier": "automated", "reason": None,
        "check": {"kind": "setting", "setting_name": "listen_addresses", "query": "SHOW listen_addresses",
                  "operator": "not_in", "expected": ["*", "0.0.0.0"],
                  "pass_condition_quote": "If `*` or `0.0.0.0` is returned, this is a failure."},
        "proof": {"break": {"setting_name": "listen_addresses", "value": "*"},
                  "fix": {"setting_name": "listen_addresses", "value": "localhost"}},
    }


def syslog_spec():
    """3.1.11 re-specced with applies_when (schema_version 2)."""
    return {
        "spec_id": f"{B}:3.1.11", "schema_version": 2, "authored_by": "agent", "ref": ref("3.1.11"),
        "tier": "automated", "reason": None,
        "check": {"kind": "setting", "setting_name": "syslog_sequence_numbers",
                  "query": "SHOW syslog_sequence_numbers", "operator": "equals", "expected": "on",
                  "pass_condition_quote": "Execute the following SQL statement and confirm that the "
                  "`syslog_sequence_numbers` is enabled (on):"},
        "proof": {"break": {"setting_name": "syslog_sequence_numbers", "value": "off"},
                  "fix": {"setting_name": "syslog_sequence_numbers", "value": "on"}},
        "applies_when": {"setting_name": "log_destination", "operator": "contains_items",
                         "expected": ["syslog"],
                         "condition_quote": "When logging to Syslog and `syslog_sequence_numbers` is on"},
    }


def policy_spec():
    """3.1.2 as a parameterised policy spec (schema_version 2)."""
    return {
        "spec_id": f"{B}:3.1.2", "schema_version": 2, "authored_by": "agent", "ref": ref("3.1.2"),
        "tier": "parameterised", "reason": "Log destinations are set by organisational logging policy.",
        "check": {"kind": "setting", "setting_name": "log_destination", "query": "SHOW log_destination",
                  "operator": "contains_items", "expected_from": "policy",
                  "pass_condition_quote": "If all the expected log destinations are not set, this is a fail."},
    }


def profile_bytes(approved_by=None, approved_at=None, values=None, **extra):
    doc = {"profile_id": "test-profile", "benchmark": B, "approved_by": approved_by,
           "approved_at": approved_at,
           "values": values if values is not None else
           {f"{B}:3.1.2": {"expected": ["stderr", "csvlog"], "fix": "stderr,csvlog", "break": "stderr"}}}
    doc.update(extra)
    return yaml.safe_dump(doc, sort_keys=False).encode()


def approved(**kw):
    return parse_profile(profile_bytes("Melvin Loo", "2026-10-30", **kw), RECORDS)


def entry(spec, status="ok", result=None, spec_hash=None):
    e = {"spec_hash": spec_hash or spec_sha256(spec), "query": "SHOW x", "status": status}
    if status == "ok":
        e["result"] = result
    elif status == "error":
        e["error"] = "boom"
    return e


def snapshot(checks):
    return {"envelope": {"schema_version": "0.3.0", "target_id": "t", "database": "d",
                         "collector_sha256": "a" * 64,
                         "manifest": {"sha256": "b" * 64, "manifest_version": 1, "benchmark_id": B,
                                      "check_count": len(checks)}},
            "baseline": {"identity": {"version_full": "PostgreSQL 17", "server_version_num": 170000}},
            "checks": checks}


def run(specs, checks, policy=None):
    report = assess(specs, snapshot(checks), RECORDS, policy)
    jsonschema.validate(report, REPORT_SCHEMA)
    return report


# ---------------------------------------------------------------------------
# Operators
# ---------------------------------------------------------------------------

class TestNotIn:
    def test_pass_and_fail(self):
        assert not_in("localhost", ["*", "0.0.0.0"]) is True
        assert not_in("*", ["*", "0.0.0.0"]) is False
        assert not_in("0.0.0.0", ["*", "0.0.0.0"]) is False

    def test_exact_comparison_only(self):
        # A list value is not split: only exact membership counts.
        assert not_in("*, 10.0.0.1", ["*"]) is True

    @pytest.mark.parametrize("actual", [None, 1, True, ["*"]])
    def test_wrong_actual_type(self, actual):
        with pytest.raises(TypeError):
            not_in(actual, ["*"])

    @pytest.mark.parametrize("expected", ["*", None, [1], {"*": 1}])
    def test_wrong_expected_type(self, expected):
        with pytest.raises(TypeError):
            not_in("*", expected)


class TestContainsItems:
    @pytest.mark.parametrize("actual", ["stderr,syslog", " Stderr , SYSLOG", '"syslog"', "csvlog, syslog ,stderr"])
    def test_pass(self, actual):
        assert contains_items(actual, ["syslog"]) is True

    @pytest.mark.parametrize("actual", ["stderr", "stderr,csvlog", "", "syslogx", "jsonlog"])
    def test_fail(self, actual):
        assert contains_items(actual, ["syslog"]) is False

    def test_all_items_required(self):
        assert contains_items("stderr,csvlog", ["stderr", "csvlog"]) is True
        assert contains_items("stderr", ["stderr", "csvlog"]) is False

    @pytest.mark.parametrize("actual", ["stderr,", ",syslog", "std err,syslog", "syslog;stderr", '"sys log"', "a,,b"])
    def test_unparseable_value_raises(self, actual):
        with pytest.raises(ValueError):
            contains_items(actual, ["syslog"])

    @pytest.mark.parametrize("actual", [None, 3, ["syslog"]])
    def test_wrong_actual_type(self, actual):
        with pytest.raises(TypeError):
            contains_items(actual, ["syslog"])

    def test_wrong_expected_type(self):
        with pytest.raises(TypeError):
            contains_items("syslog", "syslog")


class TestContainsEscapes:
    CIS = "%m [%p]: [%l-1] db=%d,user=%u,app=%a,client=%h "

    def test_pass(self):
        assert contains_escapes(self.CIS, ["%m", "%p", "%l", "%d", "%u", "%a", "%h"]) is True

    def test_fail_when_missing(self):
        assert contains_escapes("%m [%p] ", ["%m", "%p", "%u"]) is False

    def test_literal_percent_is_not_an_escape(self):
        assert contains_escapes("%%m [%p]", ["%m"]) is False
        assert contains_escapes("%%%m", ["%m"]) is True

    def test_padding_is_the_same_escape(self):
        assert contains_escapes("%-10u %5d", ["%u", "%d"]) is True

    def test_escapes_after_q_are_not_counted(self):
        assert contains_escapes("%m [%p] %q%u@%d ", ["%m", "%p"]) is True
        assert contains_escapes("%m [%p] %q%u@%d ", ["%u"]) is False

    def test_trailing_and_unknown_escapes_ignored(self):
        assert contains_escapes("%m %", ["%m"]) is True
        assert contains_escapes("%z %-", ["%m"]) is False
        assert contains_escapes("% p", ["%p"]) is False

    @pytest.mark.parametrize("actual", [None, 7])
    def test_wrong_actual_type(self, actual):
        with pytest.raises(TypeError):
            contains_escapes(actual, ["%m"])

    def test_wrong_expected_type(self):
        with pytest.raises(TypeError):
            contains_escapes("%m", "%m")


class TestSeverity:
    def test_scale_is_the_reviewed_pg17_list(self):
        # https://www.postgresql.org/docs/17/runtime-config-logging.html ; LOG sits between ERROR and FATAL.
        assert SERVER_MESSAGE_LEVELS == ("debug5", "debug4", "debug3", "debug2", "debug1", "info",
                                         "notice", "warning", "error", "log", "fatal", "panic")
        assert SEVERITY_SCALES == {"log_min_messages": SERVER_MESSAGE_LEVELS,
                                   "log_min_error_statement": SERVER_MESSAGE_LEVELS}

    @pytest.mark.parametrize("actual,more,less", [
        ("warning", True, True), ("debug1", True, False), ("notice", True, False),
        ("error", False, True), ("log", False, True), ("panic", False, True), ("debug5", True, False),
    ])
    def test_both_directions(self, actual, more, less):
        kw = {"setting_name": "log_min_messages"}
        assert severity(actual, "warning", direction="at_or_more_verbose", **kw) is more
        assert severity(actual, "warning", direction="at_or_less_verbose", **kw) is less

    @pytest.mark.parametrize("actual", ["WARNING", "debug", "warn", "", "fatal "])
    def test_unknown_actual_raises(self, actual):
        with pytest.raises(ValueError):
            severity(actual, "warning", setting_name="log_min_messages", direction="at_or_more_verbose")

    def test_unknown_expected_setting_or_direction_raises(self):
        with pytest.raises(ValueError):
            severity("error", "loud", setting_name="log_min_error_statement", direction="at_or_more_verbose")
        with pytest.raises(ValueError):
            severity("error", "error", setting_name="client_min_messages", direction="at_or_more_verbose")
        with pytest.raises(ValueError):
            severity("error", "error", setting_name="log_min_error_statement", direction="at_least")

    def test_wrong_types_raise(self):
        with pytest.raises(TypeError):
            severity(None, "warning", setting_name="log_min_messages", direction="at_or_more_verbose")
        with pytest.raises(TypeError):
            severity("warning", ["warning"], setting_name="log_min_messages", direction="at_or_more_verbose")

    def test_registry_call_without_parameters_fails_closed(self):
        with pytest.raises(TypeError):
            OPERATORS["severity"]("warning", "warning")


class TestExistingOperatorsRejectWrongExpectedType:
    def test_not_equals_with_non_string_expected_raises_instead_of_passing(self):
        with pytest.raises(TypeError):
            not_equals("on", True)
        with pytest.raises(TypeError):
            equals("on", ["on"])

    def test_in_with_string_expected_raises_instead_of_substring_match(self):
        with pytest.raises(TypeError):
            in_("o", "on")


class TestOneRulebook:
    def test_every_operator_has_a_shape(self):
        assert set(EXPECTED_SHAPE) == set(OPERATORS)
        assert set(OPERATOR_PARAMS) <= set(OPERATORS)

    def test_report_contract_lists_exactly_the_registry(self):
        row = REPORT_SCHEMA["properties"]["results"]["items"]["properties"]
        assert set(row["operator"]["enum"]) == set(OPERATORS)
        assert set(row["condition"]["properties"]["operator"]["enum"]) == set(OPERATORS)

    def test_spec_schema_lists_exactly_the_registry_and_tables(self):
        defs = SPEC_SCHEMA["$defs"]
        assert set(defs["operator"]["enum"]) == set(OPERATORS)
        rules = defs["operator_rules"]["allOf"]
        lists = [r for r in rules if r["if"]["properties"]["operator"].get("enum")][0]
        assert set(lists["if"]["properties"]["operator"]["enum"]) == {
            op for op, shape in EXPECTED_SHAPE.items() if shape == "list"}
        by_op = {r["if"]["properties"]["operator"].get("const"): r for r in rules}
        escapes = by_op["contains_escapes"]["then"]["properties"]["expected"]["items"]["enum"]
        assert set(escapes) == LOG_LINE_PREFIX_ESCAPES
        sev = by_op["severity"]["then"]["properties"]
        assert set(sev["setting_name"]["enum"]) == set(SEVERITY_SCALES)
        assert tuple(sev["expected"]["enum"]) == SERVER_MESSAGE_LEVELS

    def test_sanitised_settings_match_the_collector(self):
        sql = (REPO_ROOT / "collector/collect.sql").read_text()
        # The secret-bearing built-ins: the first IN list of pg_temp.is_secret_setting
        # (tests/test_redacted_secret_setting.py pins the reviewed dotted names too).
        block = re.search(r'is_secret_setting\(p_name text\) RETURNS boolean AS \$\$\s*'
                          r'SELECT lower\(\$1 COLLATE "C"\) IN \(([^)]*)\)', sql).group(1)
        assert set(re.findall(r"'([a-z_]+)'", block)) == SANITISED_SETTINGS


# ---------------------------------------------------------------------------
# Spec validation (validate.py and schema.json agree)
# ---------------------------------------------------------------------------

def schema_ok(spec):
    return not list(jsonschema.Draft202012Validator(SPEC_SCHEMA).iter_errors(spec))


class TestValidateNewSpecs:
    @pytest.mark.parametrize("make", [severity_spec, prefix_spec, listen_spec, syslog_spec, policy_spec],
                             ids=["severity", "escapes", "not_in", "applies_when", "policy"])
    def test_valid(self, make):
        spec = make()
        assert validate_spec(spec, RECORDS) == []
        assert schema_ok(spec)

    def test_both_severity_directions_are_expressible(self):
        assert validate_spec(severity_spec("at_or_more_verbose"), RECORDS) == []

    def test_severity_requires_direction(self):
        spec = severity_spec()
        del spec["check"]["direction"]
        errors = validate_spec(spec, RECORDS)
        assert any("direction" in e for e in errors), errors
        assert not schema_ok(spec)

    def test_direction_only_with_severity(self):
        spec = listen_spec()
        spec["check"]["direction"] = "at_or_more_verbose"
        assert any("direction is only allowed" in e for e in validate_spec(spec, RECORDS))
        assert not schema_ok(spec)

    def test_severity_on_unreviewed_setting_rejected(self):
        spec = listen_spec()
        spec["check"].update(operator="severity", direction="at_or_more_verbose", expected="error")
        assert any("no reviewed scale" in e for e in validate_spec(spec, RECORDS))

    def test_severity_expected_outside_scale_rejected(self):
        spec = severity_spec()
        spec["check"]["expected"] = "loud"
        assert any("is not a log_min_messages level" in e for e in validate_spec(spec, RECORDS))
        assert not schema_ok(spec)

    def test_escape_must_be_a_pg17_escape(self):
        spec = prefix_spec()
        spec["check"]["expected"] = ["%m", "[%p]"]
        assert any("log_line_prefix escape" in e for e in validate_spec(spec, RECORDS))
        assert not schema_ok(spec)

    def test_list_item_must_be_lower_case_name(self):
        cond = syslog_spec()
        cond["applies_when"]["expected"] = ["Syslog"]
        assert any("lower-case" in e for e in validate_spec(cond, RECORDS))
        assert not schema_ok(cond)

    def test_proof_still_checked_with_new_operators(self):
        spec = listen_spec()
        spec["proof"]["fix"]["value"] = "0.0.0.0"
        assert any("does not satisfy check" in e for e in validate_spec(spec, RECORDS))
        spec = severity_spec()
        spec["proof"]["break"]["value"] = "not-a-level"
        assert any("cannot be evaluated" in e for e in validate_spec(spec, RECORDS))

    def test_whole_token_rule_applies_to_new_operators(self):
        spec = listen_spec()
        spec["check"]["expected"] = ["*", "::"]
        assert any("whole token" in e for e in validate_spec(spec, RECORDS))


class TestValidateAppliesWhen:
    def test_requires_schema_version_2(self):
        spec = syslog_spec()
        spec["schema_version"] = 1
        assert any("schema_version must be 2" in e for e in validate_spec(spec, RECORDS))
        assert not schema_ok(spec)

    def test_v2_without_v2_feature_rejected(self):
        spec = syslog_spec()
        del spec["applies_when"]
        assert any("schema_version must be 1" in e for e in validate_spec(spec, RECORDS))
        assert not schema_ok(spec)

    def test_condition_quote_must_be_verbatim(self):
        spec = syslog_spec()
        spec["applies_when"]["condition_quote"] = "Only when syslog is used"
        assert any("condition_quote not found" in e for e in validate_spec(spec, RECORDS))

    def test_condition_quote_may_come_from_rationale(self):
        spec = syslog_spec()
        spec["applies_when"]["condition_quote"] = "Many modern Syslog implementations perform a log optimization"
        assert validate_spec(spec, RECORDS) == []

    def test_condition_on_same_setting_rejected(self):
        spec = syslog_spec()
        spec["applies_when"].update(setting_name="syslog_sequence_numbers", operator="equals", expected="on")
        assert any("must differ" in e for e in validate_spec(spec, RECORDS))

    def test_condition_on_masked_setting_rejected(self):
        spec = syslog_spec()
        spec["applies_when"].update(setting_name="archive_command", operator="not_equals", expected="x")
        assert any("masked by the collector" in e for e in validate_spec(spec, RECORDS))
        assert not schema_ok(spec)

    def test_missing_condition_key_and_unknown_key(self):
        spec = syslog_spec()
        del spec["applies_when"]["condition_quote"]
        spec["applies_when"]["note"] = "x"
        errors = validate_spec(spec, RECORDS)
        assert any("condition_quote" in e for e in errors) and any("note" in e for e in errors)

    def test_not_allowed_on_manual_tiers(self):
        spec = syslog_spec()
        spec.update(tier="manual_checklist", reason="manual")
        del spec["check"], spec["proof"]
        assert any("must not have applies_when" in e for e in validate_spec(spec, RECORDS))
        assert not schema_ok(spec)


class TestValidatePolicySpec:
    def test_policy_spec_has_no_proof(self):
        spec = policy_spec()
        spec["proof"] = {"break": {"setting_name": "log_destination", "value": "stderr"},
                         "fix": {"setting_name": "log_destination", "value": "syslog"}}
        assert any("must not have proof" in e for e in validate_spec(spec, RECORDS))
        assert not schema_ok(spec)

    def test_policy_spec_cannot_carry_literal_expected(self):
        spec = policy_spec()
        spec["check"]["expected"] = ["stderr"]
        assert any("Unknown check key: expected" in e for e in validate_spec(spec, RECORDS))
        assert not schema_ok(spec)

    def test_expected_from_only_policy(self):
        spec = policy_spec()
        spec["check"]["expected_from"] = "spec_author"
        assert any("expected_from must be one of" in e for e in validate_spec(spec, RECORDS))

    def test_automated_spec_cannot_use_expected_from(self):
        spec = listen_spec()
        spec["schema_version"] = 2
        del spec["check"]["expected"]
        spec["check"]["expected_from"] = "policy"
        assert validate_spec(spec, RECORDS) != []
        assert not schema_ok(spec)

    def test_quote_still_verbatim(self):
        spec = policy_spec()
        spec["check"]["pass_condition_quote"] = "Log destinations must be stderr."
        assert any("not found in audit_procedure" in e for e in validate_spec(spec, RECORDS))

    def test_parameterised_without_check_stays_v1(self):
        spec = policy_spec()
        del spec["check"]
        spec["schema_version"] = 1
        assert validate_spec(spec, RECORDS) == []


# ---------------------------------------------------------------------------
# Manifest: condition evidence is collected under its own key
# ---------------------------------------------------------------------------

class TestManifest:
    def test_condition_entry_and_policy_spec_are_collected(self):
        specs = [syslog_spec(), policy_spec()]
        manifest = manifest_from_specs(specs, RECORDS)
        by_id = {c["spec_id"]: c for c in manifest["checks"]}
        cond = by_id[condition_check_id(f"{B}:3.1.11")]
        assert cond == {"spec_id": f"{B}:3.1.11#applies_when", "spec_hash": spec_sha256(specs[0]),
                        "kind": "setting", "setting_name": "log_destination", "query": "SHOW log_destination"}
        assert by_id[f"{B}:3.1.11"]["setting_name"] == "syslog_sequence_numbers"
        assert by_id[f"{B}:3.1.2"]["setting_name"] == "log_destination"
        assert [c["spec_id"] for c in manifest["checks"]] == sorted(by_id)

    def test_spec_engine_requires_the_condition_entry(self):
        from services.sandbox_poc.shared import ContractError, SpecEngine
        engine = SpecEngine([syslog_spec()], RECORDS, policy=None)
        assert set(c["spec_id"] for c in engine.manifest["checks"]) == {
            f"{B}:3.1.11", f"{B}:3.1.11#applies_when"}
        snap = snapshot({})
        snap["envelope"].update(collector_sha256=engine.collector_hash)
        snap["envelope"]["manifest"].update(sha256=engine.manifest_hash, check_count=1)
        spec = syslog_spec()
        snap["checks"] = {f"{B}:3.1.11": entry(spec, result="on") | {"query": "SHOW syslog_sequence_numbers"}}
        with pytest.raises(ContractError, match="exactly the pinned"):
            engine.assess(snap)
        snap["checks"][f"{B}:3.1.11#applies_when"] = entry(spec, result="stderr") | {"query": "SHOW log_destination"}
        snap["envelope"]["manifest"]["check_count"] = 2
        result = engine.assess(snap)
        assert result["findings"][f"{B}:3.1.11"]["status"] == "NOT_APPLICABLE"
        snap["checks"][f"{B}:3.1.11#applies_when"]["status"] = "not_collected"
        del snap["checks"][f"{B}:3.1.11#applies_when"]["result"]
        assert engine.assess(snap)["findings"][f"{B}:3.1.11"]["status"] == "GAPPED"


# ---------------------------------------------------------------------------
# assess(): applies_when
# ---------------------------------------------------------------------------

S = f"{B}:3.1.11"
C = f"{B}:3.1.11#applies_when"


class TestAssessAppliesWhen:
    def decide(self, main=None, cond=None):
        spec = syslog_spec()
        checks = {}
        if main is not None:
            checks[S] = main(spec)
        if cond is not None:
            checks[C] = cond(spec)
        return run([spec], checks)["results"][0]

    def test_condition_true_pass(self):
        row = self.decide(lambda s: entry(s, result="on"), lambda s: entry(s, result="stderr,syslog"))
        assert (row["result"], row["reason_code"]) == ("PASS", "operator_true")
        assert row["condition"] == {"setting_name": "log_destination", "operator": "contains_items",
                                    "expected": ["syslog"], "observed": "stderr,syslog"}

    def test_condition_true_fail(self):
        row = self.decide(lambda s: entry(s, result="off"), lambda s: entry(s, result="syslog"))
        assert (row["result"], row["reason_code"]) == ("FAIL", "operator_false")

    def test_condition_false_not_applicable(self):
        row = self.decide(lambda s: entry(s, result="off"), lambda s: entry(s, result="stderr"))
        assert (row["result"], row["reason_code"]) == ("NOT_APPLICABLE", "condition_false")

    @pytest.mark.parametrize("cond,expected", [
        (None, ("NOT_COLLECTED", "condition_no_entry")),
        (lambda s: entry(s, result="syslog", spec_hash="d" * 64), ("STALE", "condition_hash_mismatch")),
        (lambda s: entry(s, status="not_collected"), ("NOT_COLLECTED", "condition_status_not_collected")),
        (lambda s: entry(s, status="error"), ("ERROR", "condition_status_error")),
        (lambda s: entry(s, result=5), ("ERROR", "condition_non_string_result")),
        (lambda s: entry(s, result="std err;syslog"), ("ERROR", "condition_operator_error")),
    ])
    def test_unknown_condition_is_never_pass(self, cond, expected):
        row = self.decide(lambda s: entry(s, result="on"), cond)
        assert (row["result"], row["reason_code"]) == expected

    def test_main_evidence_problems_come_before_the_condition(self):
        row = self.decide(None, lambda s: entry(s, result="stderr"))
        assert (row["result"], row["reason_code"]) == ("NOT_COLLECTED", "no_entry")
        row = self.decide(lambda s: entry(s, status="error"), lambda s: entry(s, result="stderr"))
        assert (row["result"], row["reason_code"]) == ("ERROR", "status_error")

    def test_pass_only_when_condition_true_and_value_compliant(self):
        mains = [None, lambda s: entry(s, result="on"), lambda s: entry(s, result="off"),
                 lambda s: entry(s, status="not_collected"), lambda s: entry(s, result="on", spec_hash="e" * 64)]
        conds = [None, lambda s: entry(s, result="syslog"), lambda s: entry(s, result="stderr"),
                 lambda s: entry(s, status="error"), lambda s: entry(s, result="syslog", spec_hash="e" * 64),
                 lambda s: entry(s, result="SYSLOG"), lambda s: entry(s, result="bad value!")]
        passes = []
        for i, main in enumerate(mains):
            for j, cond in enumerate(conds):
                if self.decide(main, cond)["result"] == "PASS":
                    passes.append((i, j))
        assert passes == [(1, 1), (1, 5)]

    def test_summary_and_orphans(self):
        spec = syslog_spec()
        report = run([spec], {S: entry(spec, result="off"), C: entry(spec, result="stderr"),
                              f"{B}:9.9#applies_when": entry(spec, result="x")})
        assert report["summary"]["NOT_APPLICABLE"] == 1
        assert report["flags"]["orphan_checks"] == [f"{B}:9.9#applies_when"]

    def test_condition_on_spec_without_applies_when_is_orphan(self):
        spec = listen_spec()
        report = run([spec], {spec["spec_id"]: entry(spec, result="*"),
                              condition_check_id(spec["spec_id"]): entry(spec, result="x")})
        assert report["flags"]["orphan_checks"] == [condition_check_id(spec["spec_id"])]


class TestAssessNewOperators:
    def test_severity_unknown_observed_is_error(self):
        spec = severity_spec()
        row = run([spec], {spec["spec_id"]: entry(spec, result="WARNING")})["results"][0]
        assert (row["result"], row["reason_code"]) == ("ERROR", "operator_error")
        assert row["direction"] == "at_or_less_verbose"

    @pytest.mark.parametrize("make,good,bad", [
        (severity_spec, "error", "info"),
        (prefix_spec, "%m [%p]: [%l-1] db=%d,user=%u,app=%a,client=%h ", "%m [%p] "),
        (listen_spec, "10.0.0.5", "0.0.0.0"),
    ])
    def test_pass_and_fail(self, make, good, bad):
        spec = make()
        assert run([spec], {spec["spec_id"]: entry(spec, result=good)})["results"][0]["result"] == "PASS"
        assert run([spec], {spec["spec_id"]: entry(spec, result=bad)})["results"][0]["result"] == "FAIL"


# ---------------------------------------------------------------------------
# Policy profile
# ---------------------------------------------------------------------------

P = f"{B}:3.1.2"


class TestPolicyProfileLoading:
    def test_committed_profile_is_unapproved_until_a_human_approves_it(self):
        # Agents never set approved_by. While this file is agent-maintained it must stay null;
        # only Melvin's own edit may change it (and then this assertion is updated by him).
        raw = yaml.safe_load(default_profile_path(B).read_text())
        assert raw["approved_by"] is None and raw["approved_at"] is None
        profile = load_default_profile(RECORDS)
        assert profile is not None and profile.approved is False

    def test_committed_profile_values_are_consistent_with_catalog_specs(self):
        from app.services.spec_engine import load_spec
        specs = [load_spec(p) for p in sorted((REPO_ROOT / "catalog/specs" / B).glob("*.yaml"))]
        assert profile_value_errors(load_default_profile(RECORDS), specs, strict=True) == []

    @pytest.mark.parametrize("approved_by", ["", "   ", True, 1, ["Melvin"], {"name": "Melvin"}])
    def test_approved_by_must_be_null_or_a_name(self, approved_by):
        with pytest.raises(PolicyProfileError, match="approved_by"):
            parse_profile(profile_bytes(approved_by, "2026-10-30"), RECORDS)

    def test_approval_needs_both_fields(self):
        with pytest.raises(PolicyProfileError, match="approved_at"):
            parse_profile(profile_bytes("Melvin Loo", None), RECORDS)
        with pytest.raises(PolicyProfileError, match="approved_at"):
            parse_profile(profile_bytes(None, "2026-10-30"), RECORDS)

    def test_unquoted_yaml_date_is_normalised(self):
        data = profile_bytes("Melvin Loo", "2026-10-30").replace(b"'2026-10-30'", b"2026-10-30")
        assert parse_profile(data, RECORDS).approved_at == "2026-10-30"

    @pytest.mark.parametrize("change,match", [
        ({"benchmark": "cis-pg16-v1.0.0"}, "benchmark"),
        ({"profile_id": ""}, "profile_id"),
        ({"extra": 1}, "unknown key"),
        ({"values": {f"{B}:3.1.2": {"expected": ["stderr"], "fix": "stderr"}}}, "missing key: break"),
        ({"values": {f"{B}:3.1.2": {"expected": ["stderr"], "fix": "", "break": "csvlog"}}}, "fix"),
        ({"values": {"other:3.1.2": {"expected": ["stderr"], "fix": "stderr", "break": "csvlog"}}}, "spec_id"),
        ({"values": ["x"]}, "values"),
    ])
    def test_malformed_profile_refused(self, change, match):
        with pytest.raises(PolicyProfileError, match=match):
            parse_profile(profile_bytes(None, None, **change), RECORDS)

    def test_duplicate_keys_refused(self):
        data = profile_bytes() + b"approved_by: Someone\n"
        with pytest.raises(PolicyProfileError):
            parse_profile(data, RECORDS)

    def test_pin_is_sha256_of_file_bytes(self):
        import hashlib
        data = profile_bytes("Melvin Loo", "2026-10-30")
        assert parse_profile(data, RECORDS).sha256 == hashlib.sha256(data).hexdigest()


class TestPolicyValuesConsistency:
    def test_fix_must_pass_and_break_must_fail(self):
        bad = approved(values={P: {"expected": ["stderr", "csvlog"], "fix": "stderr", "break": "stderr"}})
        errors = profile_value_errors(bad, [policy_spec()])
        assert any("fix.value" in e and "does not satisfy" in e for e in errors), errors
        bad = approved(values={P: {"expected": ["stderr"], "fix": "stderr", "break": "stderr,csvlog"}})
        assert any("already satisfies" in e for e in profile_value_errors(bad, [policy_spec()]))

    def test_value_must_match_operator_shape(self):
        bad = approved(values={P: {"expected": "stderr", "fix": "stderr", "break": "csvlog"}})
        assert any("non-empty list" in e for e in profile_value_errors(bad, [policy_spec()]))

    def test_unparseable_fix_is_an_error(self):
        bad = approved(values={P: {"expected": ["stderr"], "fix": "stderr,", "break": "csvlog"}})
        assert any("cannot be evaluated" in e for e in profile_value_errors(bad, [policy_spec()]))

    def test_value_for_non_policy_spec_rejected(self):
        bad = approved(values={f"{B}:5.2": {"expected": ["*"], "fix": "localhost", "break": "*"}})
        assert any("does not take its expected value from policy" in e
                   for e in profile_value_errors(bad, [listen_spec()]))

    def test_strict_mode_reports_unknown_spec(self):
        assert profile_value_errors(approved(), [], strict=True)
        assert profile_value_errors(approved(), []) == []

    def test_assess_refuses_inconsistent_profile(self):
        bad = approved(values={P: {"expected": ["stderr"], "fix": "csvlog", "break": "csvlog"}})
        spec = policy_spec()
        with pytest.raises(ValueError, match="Policy profile validation failed"):
            assess([spec], snapshot({P: entry(spec, result="stderr")}), RECORDS, bad)


class TestAssessPolicy:
    def row(self, observed, policy):
        spec = policy_spec()
        report = run([spec], {P: entry(spec, result=observed)}, policy)
        return report, report["results"][0]

    def test_no_profile_is_policy_missing(self):
        report, row = self.row("stderr,csvlog", None)
        assert (row["result"], row["reason_code"]) == ("MANUAL", "policy_missing")
        assert report["inputs"]["policy_profile"] is None
        assert row["expected_from"] == "policy" and "expected" not in row

    def test_unapproved_profile_is_policy_missing(self):
        profile = parse_profile(profile_bytes(), RECORDS)
        report, row = self.row("stderr,csvlog", profile)
        assert (row["result"], row["reason_code"]) == ("MANUAL", "policy_missing")
        assert report["inputs"]["policy_profile"]["approved_by"] is None

    def test_approved_profile_without_value_is_policy_missing(self):
        _, row = self.row("stderr,csvlog", approved(values={}))
        assert (row["result"], row["reason_code"]) == ("MANUAL", "policy_missing")

    def test_approved_profile_pass_and_fail(self):
        profile = approved()
        report, row = self.row("stderr, CSVLOG", profile)
        assert (row["result"], row["reason_code"]) == ("PASS", "operator_true")
        assert row["expected"] == ["stderr", "csvlog"]
        assert report["inputs"]["policy_profile"] == {"profile_id": "test-profile", "sha256": profile.sha256,
                                                      "approved_by": "Melvin Loo", "approved_at": "2026-10-30",
                                                      "approval_auth": "DEMO_NO_SIGN_IN"}
        _, row = self.row("stderr", profile)
        assert (row["result"], row["reason_code"]) == ("FAIL", "operator_false")

    def test_approved_value_still_needs_clean_evidence(self):
        spec = policy_spec()
        row = run([spec], {}, approved())["results"][0]
        assert (row["result"], row["reason_code"]) == ("NOT_COLLECTED", "no_entry")

    def test_unapproved_profile_never_passes(self):
        states = [None, parse_profile(profile_bytes(), RECORDS), approved(values={})]
        for policy in states:
            for observed in ("stderr,csvlog", "stderr", "csvlog,stderr,syslog"):
                assert self.row(observed, policy)[1]["result"] == "MANUAL"

    def test_profile_not_pinned_when_no_spec_uses_it(self):
        spec = listen_spec()
        report = run([spec], {spec["spec_id"]: entry(spec, result="*")}, approved())
        assert "policy_profile" not in report["inputs"]


# ---------------------------------------------------------------------------
# Projections: offline ASSESS controls, sandbox status map, fix scope, fix plan
# ---------------------------------------------------------------------------

def rows(**values):
    return {"identity": {"server_version_num": 170000},
            "settings": [{"name": k, "setting": v, "vartype": vt, "unit": None, "sanitised": False}
                         for k, (v, vt) in values.items()]}


class TestSpecControls:
    def test_applies_when_not_applicable_and_gapped(self):
        from catalog.controls.assess.spec_controls import _setting_rule
        rule = _setting_rule(syslog_spec())
        finding = rule(rows(syslog_sequence_numbers=("off", "bool"), log_destination=("stderr", "string")))
        assert finding.status == FindingStatus.NOT_APPLICABLE
        finding = rule(rows(syslog_sequence_numbers=("off", "bool"), log_destination=("syslog", "string")))
        assert finding.status == FindingStatus.FAIL
        finding = rule(rows(syslog_sequence_numbers=("on", "bool")))
        assert finding.status == FindingStatus.GAPPED and "Applicability unknown" in finding.rationale
        finding = rule(rows(syslog_sequence_numbers=("on", "bool"), log_destination=("syslog", "integer")))
        assert finding.status == FindingStatus.GAPPED

    def test_policy_missing_is_manual_review_and_approved_value_evaluates(self):
        from catalog.controls.assess.spec_controls import _setting_rule
        evidence = rows(log_destination=("stderr,csvlog", "string"))
        assert _setting_rule(policy_spec(), None)(evidence).status == FindingStatus.MANUAL_REVIEW
        unapproved = parse_profile(profile_bytes(), RECORDS)
        assert _setting_rule(policy_spec(), unapproved)(evidence).status == FindingStatus.MANUAL_REVIEW
        assert _setting_rule(policy_spec(), approved())(evidence).status == FindingStatus.PASS

    def test_unit_and_integer_rows_are_gapped(self):
        from catalog.controls.assess.spec_controls import _setting_rule
        spec = listen_spec()
        assert _setting_rule(spec)(rows(listen_addresses=("localhost", "string"))).status == FindingStatus.PASS
        evidence = rows(listen_addresses=("localhost", "string"))
        evidence["settings"][0]["unit"] = "min"
        assert _setting_rule(spec)(evidence).status == FindingStatus.GAPPED
        assert _setting_rule(spec)(rows(listen_addresses=("localhost", "integer"))).status == FindingStatus.GAPPED

    def test_unknown_severity_is_gapped(self):
        from catalog.controls.assess.spec_controls import _setting_rule
        finding = _setting_rule(severity_spec())(rows(log_min_messages=("LOUD", "enum")))
        assert finding.status == FindingStatus.GAPPED


class TestFixScopeUsesTheRulebook:
    def engine(self, spec, policy=None):
        return SimpleNamespace(specs=[spec], policy=policy)

    def test_list_operator_with_reviewed_policy_value(self):
        from services.sandbox_poc.planning import ContractError, fix_scope
        spec = copy.deepcopy(listen_spec())
        spec["check"].update(setting_name="log_statement", query="SHOW log_statement",
                             operator="not_in", expected=["none"])
        assert fix_scope(self.engine(spec), spec["spec_id"])[2] == "ddl"
        spec["check"]["expected"] = ["ddl", "none"]
        with pytest.raises(ContractError, match="does not satisfy"):
            fix_scope(self.engine(spec), spec["spec_id"])

    def test_unknown_value_is_refused_not_accepted(self):
        from services.sandbox_poc.planning import ContractError, fix_scope
        spec = copy.deepcopy(listen_spec())
        spec["check"].update(setting_name="log_statement", query="SHOW log_statement",
                             operator="contains_items", expected=["ddl"])
        assert fix_scope(self.engine(spec), spec["spec_id"])[2] == "ddl"
        spec["check"].update(operator="severity", direction="at_or_more_verbose", expected="warning")
        with pytest.raises(ContractError):
            fix_scope(self.engine(spec), spec["spec_id"])


class TestFixPlanListsNotApplicableSeparately:
    def test_not_applicable_is_neither_fix_nor_manual(self, monkeypatch):
        from services.sandbox_poc import router
        spec = syslog_spec()
        engine = SimpleNamespace(specs=[spec], spec_set_hash="f" * 64)
        assessment = {"findings": {S: {"status": "NOT_APPLICABLE", "spec_hash": "0" * 64}}}
        monkeypatch.setattr(router, "assess_uploaded", lambda *a: (engine, {}, assessment))
        plan = router.fix_plan("snap-x", B, False, store=None, service=SimpleNamespace(risk_reviewer=None))
        assert plan["recommended_order"] == [] and plan["manual_review"] == []
        assert plan["not_applicable"] == [{"spec_id": S, "title": spec["ref"]["title"], "tier": "automated",
                                           "status": "NOT_APPLICABLE",
                                           "condition": spec["applies_when"]["condition_quote"]}]


# ---------------------------------------------------------------------------
# Structured explanations (cis + explanation) for the UI
# ---------------------------------------------------------------------------

CIS_3111 = {"recommendation": "3.1.11", "title": RECORDS["3.1.11"]["title"]}
COND = {"setting_name": "log_destination", "operator": "contains_items", "expected": ["syslog"],
        "condition_quote": "When logging to Syslog and `syslog_sequence_numbers` is on"}


class TestAssessExplanations:
    def row(self, main=None, cond=None, spec=None, policy=None):
        spec = spec or syslog_spec()
        checks = {}
        if main is not None:
            checks[spec["spec_id"]] = main(spec)
        if cond is not None:
            checks[condition_check_id(spec["spec_id"])] = cond(spec)
        return run([spec], checks, policy)["results"][0]

    def test_not_applicable(self):
        row = self.row(lambda s: entry(s, result="off"), lambda s: entry(s, result="stderr"))
        assert row["result"] == "NOT_APPLICABLE" and row["cis"] == CIS_3111
        assert row["explanation"] == {"code": "condition_false", **COND, "actual": "stderr"}

    @pytest.mark.parametrize("cond,facts", [
        (None, {"cause": "not_collected", "entry_status": "missing"}),
        (lambda s: entry(s, status="not_collected"), {"cause": "not_collected", "entry_status": "not_collected"}),
        (lambda s: entry(s, result="syslog", spec_hash="d" * 64),
         {"cause": "stale_spec_hash", "collected_spec_hash": "d" * 64}),
        (lambda s: entry(s, status="error"), {"cause": "collector_error", "error": "boom"}),
        (lambda s: entry(s, result=5), {"cause": "unit_or_non_text_value"}),
        (lambda s: entry(s, result="std err;syslog"), {"cause": "uninterpretable_value", "actual": "std err;syslog"}),
    ])
    def test_condition_unknown(self, cond, facts):
        row = self.row(lambda s: entry(s, result="on"), cond)
        exp = row["explanation"]
        assert row["cis"] == CIS_3111
        assert exp["code"] == "condition_unknown" and exp["evidence"] == "condition"
        assert {k: exp[k] for k in COND} == COND
        assert {k: exp[k] for k in facts} == facts

    @pytest.mark.parametrize("main,facts", [
        (None, {"code": "not_collected", "entry_status": "missing"}),
        (lambda s: entry(s, status="not_collected"), {"code": "not_collected", "entry_status": "not_collected"}),
        (lambda s: entry(s, result="on", spec_hash="d" * 64),
         {"code": "stale_spec_hash", "collected_spec_hash": "d" * 64}),
        (lambda s: entry(s, status="error"), {"code": "collector_error", "error": "boom"}),
        (lambda s: entry(s, result=["on"]), {"code": "unit_or_non_text_value"}),
    ])
    def test_main_evidence_problems(self, main, facts):
        row = self.row(main, lambda s: entry(s, result="syslog"))
        exp = row["explanation"]
        assert exp["evidence"] == "check" and exp["setting_name"] == "syslog_sequence_numbers"
        assert {k: exp[k] for k in facts} == facts
        if facts["code"] == "stale_spec_hash":
            assert exp["spec_hash"] == spec_sha256(syslog_spec())

    def test_uninterpretable_main_value(self):
        spec = severity_spec()
        row = self.row(lambda s: entry(s, result="LOUD"), spec=spec)
        assert row["cis"] == {"recommendation": "3.1.14", "title": RECORDS["3.1.14"]["title"]}
        assert row["explanation"] == {"code": "uninterpretable_value", "evidence": "check",
                                      "setting_name": "log_min_messages", "operator": "severity",
                                      "direction": "at_or_less_verbose", "actual": "LOUD"}

    @pytest.mark.parametrize("policy,facts", [
        (lambda: None, {"code": "policy_missing", "case": "no_profile"}),
        (lambda: parse_profile(profile_bytes(), RECORDS),
         {"code": "policy_missing", "case": "profile_unapproved", "profile_id": "test-profile"}),
        (lambda: approved(values={}),
         {"code": "policy_missing", "case": "no_value_for_spec", "profile_id": "test-profile"}),
    ])
    def test_policy_missing(self, policy, facts):
        row = self.row(lambda s: entry(s, result="stderr"), spec=policy_spec(), policy=policy())
        assert row["reason_code"] == "policy_missing"
        assert row["cis"] == {"recommendation": "3.1.2", "title": RECORDS["3.1.2"]["title"]}
        assert row["explanation"] == facts

    @pytest.mark.parametrize("main,cond", [
        (lambda s: entry(s, result="on"), lambda s: entry(s, result="syslog")),
        (lambda s: entry(s, result="off"), lambda s: entry(s, result="syslog")),
    ])
    def test_pass_and_fail_carry_no_explanation(self, main, cond):
        row = self.row(main, cond)
        assert "explanation" not in row and "cis" not in row

    def test_tier_manual_and_capability_carry_no_explanation(self):
        spec = policy_spec()
        del spec["check"]
        spec["schema_version"] = 1
        row = run([spec], {})["results"][0]
        assert row["reason_code"] == "tier_manual" and "explanation" not in row

    def test_sandbox_findings_pass_explanations_through(self):
        from services.sandbox_poc.shared import SpecEngine
        engine = SpecEngine([syslog_spec()], RECORDS, policy=None)
        spec = syslog_spec()
        snap = snapshot({S: entry(spec, result="off") | {"query": "SHOW syslog_sequence_numbers"},
                         C: entry(spec, result="stderr") | {"query": "SHOW log_destination"}})
        snap["envelope"].update(collector_sha256=engine.collector_hash)
        snap["envelope"]["manifest"].update(sha256=engine.manifest_hash)
        finding = engine.assess(snap)["findings"][S]
        assert finding["status"] == "NOT_APPLICABLE"
        assert finding["cis"] == CIS_3111
        assert finding["explanation"] == {"code": "condition_false", **COND, "actual": "stderr"}
        del snap["checks"][C]["result"]
        snap["checks"][C]["status"] = "not_collected"
        finding = engine.assess(snap)["findings"][S]
        assert finding["status"] == "GAPPED"
        assert finding["explanation"]["code"] == "condition_unknown"
        assert finding["explanation"]["cause"] == "not_collected"


class TestSpecControlsExplanations:
    def rule(self, spec=None, policy=None):
        from catalog.controls.assess.spec_controls import _setting_rule
        return _setting_rule(spec or syslog_spec(), policy)

    def test_not_applicable(self):
        f = self.rule()(rows(syslog_sequence_numbers=("off", "bool"), log_destination=("stderr", "string")))
        assert f.status == FindingStatus.NOT_APPLICABLE and f.cis == CIS_3111
        assert f.explanation == {"code": "condition_false", **COND, "actual": "stderr"}

    def test_wrong_pg_major(self):
        evidence = rows(syslog_sequence_numbers=("on", "bool"), log_destination=("syslog", "string"))
        evidence["identity"]["server_version_num"] = 160004
        f = self.rule()(evidence)
        assert f.status == FindingStatus.GAPPED and f.cis == CIS_3111
        assert f.explanation == {"code": "wrong_pg_major", "spec_pg_major": 17, "snapshot_pg_major": 16}

    def test_settings_section_gap_reason(self):
        f = self.rule()({"identity": {"server_version_num": 170000}, "settings": None,
                         "gaps": [{"section": "settings", "reason": "insufficient_privilege"}]})
        assert f.explanation == {"code": "not_collected", "setting_name": "syslog_sequence_numbers",
                                 "entry_status": "section_unavailable",
                                 "gap_reason": "insufficient_privilege", "evidence": "check"}

    def test_missing_row_sanitised_and_unit(self):
        f = self.rule()(rows(log_destination=("syslog", "string")))
        assert (f.explanation["code"], f.explanation["entry_status"]) == ("not_collected", "missing")
        evidence = rows(syslog_sequence_numbers=("on", "bool"), log_destination=("syslog", "string"))
        evidence["settings"][0]["sanitised"] = True
        assert self.rule()(evidence).explanation == {"code": "sanitised", "evidence": "check",
                                                     "setting_name": "syslog_sequence_numbers"}
        evidence = rows(syslog_sequence_numbers=("on", "bool"), log_destination=("syslog", "string"))
        evidence["settings"][0]["unit"] = "s"
        assert self.rule()(evidence).explanation == {"code": "unit_or_non_text_value", "evidence": "check",
                                                     "setting_name": "syslog_sequence_numbers",
                                                     "unit": "s", "vartype": "bool"}

    def test_condition_unknown(self):
        f = self.rule()(rows(syslog_sequence_numbers=("on", "bool")))
        assert f.status == FindingStatus.GAPPED
        assert f.explanation == {"code": "condition_unknown", "cause": "not_collected", "evidence": "condition",
                                 **COND, "entry_status": "missing"}
        f = self.rule()(rows(syslog_sequence_numbers=("on", "bool"), log_destination=("a;b", "string")))
        assert f.explanation == {"code": "condition_unknown", "cause": "uninterpretable_value",
                                 "evidence": "condition", **COND, "actual": "a;b"}

    def test_uninterpretable_value(self):
        f = self.rule(severity_spec())(rows(log_min_messages=("LOUD", "enum")))
        assert f.explanation == {"code": "uninterpretable_value", "evidence": "check",
                                 "setting_name": "log_min_messages", "operator": "severity",
                                 "actual": "LOUD", "direction": "at_or_less_verbose"}

    @pytest.mark.parametrize("policy,facts", [
        (lambda: None, {"code": "policy_missing", "case": "no_profile"}),
        (lambda: parse_profile(profile_bytes(), RECORDS),
         {"code": "policy_missing", "case": "profile_unapproved", "profile_id": "test-profile"}),
        (lambda: approved(values={}),
         {"code": "policy_missing", "case": "no_value_for_spec", "profile_id": "test-profile"}),
    ])
    def test_policy_missing(self, policy, facts):
        f = self.rule(policy_spec(), policy())(rows(log_destination=("stderr", "string")))
        assert f.status == FindingStatus.MANUAL_REVIEW
        assert f.cis == {"recommendation": "3.1.2", "title": RECORDS["3.1.2"]["title"]}
        assert f.explanation == facts

    def test_pass_and_fail_carry_no_explanation(self):
        for value in ("on", "off"):
            f = self.rule()(rows(syslog_sequence_numbers=(value, "bool"), log_destination=("syslog", "string")))
            assert f.explanation is None and f.cis is None
