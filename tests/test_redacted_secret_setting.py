"""The collector's redaction marker is never evaluated (db-security-reviewer follow-up N3).

collector/collect.sql ships ``***REDACTED*** (set, N characters)`` instead of the
value of a secret-bearing setting. A ``not_equals``/``not_in``/``no_item_in`` rule
would PASS on that text, so every assessment path (assess.py, the offline ASSESS
spec controls and the sandbox SpecEngine) must give NOT_COLLECTED/GAPPED with the
explanation code ``redacted_secret_setting`` and never call the operator. The
validator rejects a spec on a setting the collector redacts, and the Python list
of such settings is pinned to the collector source.
"""

import importlib
import json
import re
import sys
from pathlib import Path

import jsonschema
import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
for extra in (str(REPO_ROOT), str(REPO_ROOT / "backend")):
    if extra not in sys.path:
        sys.path.insert(0, extra)

from app.models import FindingStatus  # noqa: E402
from app.services.spec_engine import RecordsIndex, assess, load_spec, spec_sha256, validate_spec  # noqa: E402
# The package re-exports the assess() function under the module's name.
assess_module = importlib.import_module("app.services.spec_engine.assess")
from app.services.spec_engine.manifest import condition_check_id  # noqa: E402
from app.services.spec_engine.operators import evaluate  # noqa: E402
from app.services.spec_engine.policy import parse_profile  # noqa: E402
from app.services.spec_engine.redaction import (  # noqa: E402
    COLLECTOR_REVIEWED_CUSTOM_SETTINGS,
    COLLECTOR_SECRET_SETTINGS,
    REDACTED_PREFIX,
    collector_redacts,
    is_redacted,
)
from app.services.spec_engine.validate import SANITISED_SETTINGS  # noqa: E402

B = "cis-pg17-v1.1.0"
SPECS_DIR = REPO_ROOT / "catalog/specs" / B
RECORDS = RecordsIndex.load(REPO_ROOT / "catalog/benchmarks" / B / "records.json")
REPORT_SCHEMA = json.loads((REPO_ROOT / "catalog/specs/contracts/assessment-report-v1.json").read_text())
SPEC_SCHEMA = json.loads((REPO_ROOT / "catalog/specs/schema.json").read_text())
COLLECTOR_SQL = (REPO_ROOT / "collector/collect.sql").read_text()

# Exactly what pg_temp.sanitise_setting emits for a 42-character secret.
MARKER = "***REDACTED*** (set, 42 characters)"


def spec(rec):
    return load_spec(SPECS_DIR / f"{rec}.yaml")


def not_in_spec():
    """5.2 written with not_in (the operator family the catalog does not use today)."""
    s = spec("5.2")
    s["check"].update(operator="not_in", expected=["*", "0.0.0.0"],
                      pass_condition_quote="If `*` or `0.0.0.0` is returned, this is a failure.")
    s["proof"] = {"break": {"setting_name": "listen_addresses", "value": "*"},
                  "fix": {"setting_name": "listen_addresses", "value": "localhost"}}
    s.pop("interpretation", None)
    assert validate_spec(s, RECORDS) == []
    return s


def reviewed_test_profile():
    """In-memory test profile (not an approval record) so the policy spec reaches its operator."""
    doc = {"profile_id": "redaction-test", "benchmark": B, "approved_by": "Test Reviewer",
           "approved_at": "2026-10-28",
           "values": {f"{B}:3.1.2": {"expected": ["stderr"], "fix": "stderr", "break": "csvlog"}}}
    return parse_profile(yaml.safe_dump(doc).encode(), RECORDS)


# One spec per operator family, with the check that matters for the marker.
OPERATOR_CASES = {
    "equals": lambda: (spec("3.1.20"), None),
    "not_equals": lambda: (spec("3.1.25"), None),
    "in": lambda: (spec("6.9"), None),
    "not_in": lambda: (not_in_spec(), None),
    "no_item_in": lambda: (spec("5.2"), None),
    "contains_items": lambda: (spec("3.1.2"), reviewed_test_profile()),
    "contains_escapes": lambda: (spec("3.1.24"), None),
    "severity": lambda: (spec("3.1.14"), None),
}


def entry(s, result, query=None):
    return {"spec_hash": spec_sha256(s), "query": query or s["check"]["query"], "status": "ok",
            "result": result}


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


@pytest.fixture
def operator_never_sees_marker(monkeypatch):
    """Fail the test if assess.py ever hands the marker to an operator."""
    real = assess_module.evaluate

    def guarded(check, actual, expected=None):
        assert not is_redacted(actual), "operator evaluated on the redaction marker"
        return real(check, actual, expected)

    monkeypatch.setattr(assess_module, "evaluate", guarded)


# ---------------------------------------------------------------------------
# The marker
# ---------------------------------------------------------------------------

class TestMarker:
    def test_marker_is_the_collector_literal(self):
        assert f"'{REDACTED_PREFIX} (set, ' || length($2) || ' characters)'" in COLLECTOR_SQL

    @pytest.mark.parametrize("value,redacted", [
        (MARKER, True), (REDACTED_PREFIX, True), ("***REDACTED*** anything", True),
        ("", False), ("(disabled)", False), ("on", False), (" ***REDACTED***", False),
        ("x***REDACTED***", False), (None, False), (["***REDACTED***"], False),
    ])
    def test_is_redacted(self, value, redacted):
        assert is_redacted(value) is redacted

    @pytest.mark.parametrize("case", ["not_equals", "not_in"])
    def test_without_the_guard_these_operators_would_pass_on_the_marker(self, case):
        s, _ = OPERATOR_CASES[case]()
        assert evaluate(s["check"], MARKER) is True


# ---------------------------------------------------------------------------
# assess.py (and through it the sandbox SpecEngine)
# ---------------------------------------------------------------------------

@pytest.mark.usefixtures("operator_never_sees_marker")
class TestAssessNeverEvaluatesTheMarker:
    @pytest.mark.parametrize("case", sorted(OPERATOR_CASES))
    def test_marker_check_result_is_not_collected(self, case):
        s, policy = OPERATOR_CASES[case]()
        assert s["check"]["operator"] == case
        row = run([s], {s["spec_id"]: entry(s, MARKER)}, policy)["results"][0]
        assert (row["result"], row["reason_code"]) == ("NOT_COLLECTED", "redacted_secret_setting")
        assert row["explanation"] == {"code": "redacted_secret_setting", "evidence": "check",
                                      "setting_name": s["check"]["setting_name"]}
        assert row["cis"]["recommendation"] == s["ref"]["recommendation"]

    def test_bare_prefix_is_enough(self):
        s = spec("3.1.25")
        row = run([s], {s["spec_id"]: entry(s, REDACTED_PREFIX)})["results"][0]
        assert row["result"] == "NOT_COLLECTED"

    def test_summary_counts_it_as_not_collected(self):
        s = spec("3.1.25")
        report = run([s], {s["spec_id"]: entry(s, MARKER)})
        assert report["summary"]["NOT_COLLECTED"] == 1 and report["summary"]["PASS"] == 0

    @pytest.mark.parametrize("main", ["on", "off", MARKER])
    def test_marker_condition_is_never_decided(self, main):
        s = spec("3.1.11")
        cid = condition_check_id(s["spec_id"])
        row = run([s], {s["spec_id"]: entry(s, main),
                        cid: entry(s, MARKER, query="SHOW log_destination")})["results"][0]
        if main == MARKER:  # main evidence problems come first
            assert (row["result"], row["reason_code"]) == ("NOT_COLLECTED", "redacted_secret_setting")
            return
        assert (row["result"], row["reason_code"]) == ("NOT_COLLECTED", "condition_redacted_secret_setting")
        exp = row["explanation"]
        assert exp["code"] == "condition_unknown" and exp["cause"] == "redacted_secret_setting"
        assert exp["evidence"] == "condition" and exp["setting_name"] == "log_destination"
        assert exp["condition_quote"] == s["applies_when"]["condition_quote"]

    def test_sandbox_spec_engine_gaps_it(self):
        from services.sandbox_poc.shared import SpecEngine
        s = spec("3.1.25")
        engine = SpecEngine([s], RECORDS, policy=None)
        snap = snapshot({s["spec_id"]: entry(s, MARKER)})
        snap["envelope"].update(collector_sha256=engine.collector_hash)
        snap["envelope"]["manifest"].update(sha256=engine.manifest_hash)
        finding = engine.assess(snap)["findings"][s["spec_id"]]
        assert finding["status"] == "GAPPED"
        assert finding["explanation"] == {"code": "redacted_secret_setting", "evidence": "check",
                                          "setting_name": "log_statement"}


# ---------------------------------------------------------------------------
# Offline ASSESS spec controls (pg_settings rows)
# ---------------------------------------------------------------------------

VARTYPES = {"log_connections": "bool", "log_statement": "enum", "ssl_min_protocol_version": "enum",
            "listen_addresses": "string", "log_destination": "string", "log_line_prefix": "string",
            "log_min_messages": "enum", "syslog_sequence_numbers": "bool"}


def rows(**values):
    return {"identity": {"server_version_num": 170000},
            "settings": [{"name": k, "setting": v, "vartype": VARTYPES[k], "unit": None, "sanitised": False}
                         for k, v in values.items()]}


class TestSpecControlsNeverEvaluateTheMarker:
    @pytest.fixture(autouse=True)
    def guard(self, monkeypatch):
        from catalog.controls.assess import spec_controls
        real = spec_controls.evaluate

        def guarded(check, actual, expected=None):
            assert not is_redacted(actual), "operator evaluated on the redaction marker"
            return real(check, actual, expected)

        monkeypatch.setattr(spec_controls, "evaluate", guarded)

    @pytest.mark.parametrize("case", sorted(OPERATOR_CASES))
    def test_marker_value_is_gapped(self, case):
        from catalog.controls.assess.spec_controls import _setting_rule
        s, policy = OPERATOR_CASES[case]()
        name = s["check"]["setting_name"]
        finding = _setting_rule(s, policy)(rows(**{name: MARKER}))
        assert finding.status == FindingStatus.GAPPED and finding.is_gapped
        assert finding.explanation == {"code": "redacted_secret_setting", "evidence": "check",
                                       "setting_name": name}

    def test_marker_wins_over_the_sanitised_flag(self):
        from catalog.controls.assess.spec_controls import _setting_rule
        evidence = rows(log_statement=MARKER)
        evidence["settings"][0]["sanitised"] = True
        assert _setting_rule(spec("3.1.25"))(evidence).explanation["code"] == "redacted_secret_setting"

    def test_marker_condition_is_gapped(self):
        from catalog.controls.assess.spec_controls import _setting_rule
        s = spec("3.1.11")
        finding = _setting_rule(s)(rows(syslog_sequence_numbers="on", log_destination=MARKER))
        assert finding.status == FindingStatus.GAPPED
        exp = finding.explanation
        assert (exp["code"], exp["cause"], exp["evidence"]) == (
            "condition_unknown", "redacted_secret_setting", "condition")
        assert exp["setting_name"] == "log_destination"


# ---------------------------------------------------------------------------
# validate.py and schema.json: no spec on a setting the collector redacts
# ---------------------------------------------------------------------------

def schema_ok(s):
    return not list(jsonschema.Draft202012Validator(SPEC_SCHEMA).iter_errors(s))


def check_on(name):
    s = spec("3.1.25")
    s["check"].update(setting_name=name, query=f"SHOW {name}")
    for phase in ("break", "fix"):
        s["proof"][phase]["setting_name"] = name
    return s


def condition_on(name):
    s = spec("3.1.11")
    s["applies_when"].update(setting_name=name, operator="not_equals", expected="x")
    return s


REDACTED_NAMES = sorted(COLLECTOR_SECRET_SETTINGS) + [
    "pgrst.jwt_secret", "app.jwt_key", "pgaudit.jwt_secret", "set_user.password",
    "pg_stat_statements.secret", "plpgsql.extra_errors_x",
]


class TestValidatorRejectsRedactedSettings:
    @pytest.mark.parametrize("name", REDACTED_NAMES)
    def test_check_rejected(self, name):
        s = check_on(name)
        errors = validate_spec(s, RECORDS)
        assert any(f"check.setting_name {name!r} is masked by the collector" in e for e in errors), errors
        assert not schema_ok(s)

    @pytest.mark.parametrize("name", REDACTED_NAMES)
    def test_condition_rejected(self, name):
        s = condition_on(name)
        errors = validate_spec(s, RECORDS)
        assert any(f"applies_when.setting_name {name!r} is masked by the collector" in e for e in errors), errors
        assert not schema_ok(s)

    @pytest.mark.parametrize("name", sorted(COLLECTOR_REVIEWED_CUSTOM_SETTINGS) + ["log_statement"])
    def test_reviewed_and_plain_names_are_not_masked(self, name):
        assert not collector_redacts(name)
        assert not any("masked by the collector" in e for e in validate_spec(check_on(name), RECORDS))
        assert not any("masked by the collector" in e for e in validate_spec(condition_on(name), RECORDS))

    def test_look_alike_characters_do_not_reach_a_reviewed_name(self):
        # U+212A KELVIN SIGN folds to 'k' in str.lower() but not under COLLATE "C".
        assert collector_redacts("plpgsql.checK_asserts")
        assert collector_redacts("PGRST.JWT_SECRET") and collector_redacts("ARCHIVE_COMMAND")
        assert not collector_redacts("PGAUDIT.LOG")

    def test_every_installed_spec_still_validates(self):
        paths = sorted(SPECS_DIR.glob("*.yaml"))
        assert len(paths) == 29
        for path in paths:
            assert validate_spec(load_spec(path), RECORDS) == [], path.name


# ---------------------------------------------------------------------------
# One list: collector, Python and schema.json agree exactly
# ---------------------------------------------------------------------------

def is_secret_setting_body():
    match = re.search(r"CREATE FUNCTION pg_temp\.is_secret_setting\(p_name text\) RETURNS boolean AS \$\$"
                      r"(.*?)\$\$ LANGUAGE sql STABLE;", COLLECTOR_SQL, re.S)
    assert match, "pg_temp.is_secret_setting not found in collector/collect.sql"
    return match.group(1)


def quoted(block):
    return re.findall(r"'([^']*)'", block)


class TestListParity:
    def test_python_lists_match_is_secret_setting_exactly(self):
        body = is_secret_setting_body()
        builtins = re.search(r'lower\(\$1 COLLATE "C"\) IN \(([^)]*)\)', body)
        reviewed = re.search(r'lower\(\$1 COLLATE "C"\) NOT IN \(([^)]*)\)', body)
        assert builtins and reviewed
        builtin_names, reviewed_names = quoted(builtins.group(1)), quoted(reviewed.group(1))
        assert len(builtin_names) == len(set(builtin_names)) == 7
        assert len(reviewed_names) == len(set(reviewed_names)) == 28
        assert set(builtin_names) == COLLECTOR_SECRET_SETTINGS == SANITISED_SETTINGS
        assert set(reviewed_names) == COLLECTOR_REVIEWED_CUSTOM_SETTINGS

    def test_is_secret_setting_has_exactly_the_three_reviewed_clauses(self):
        # If the collector gains or changes a clause, redaction.py must be reviewed too.
        body = is_secret_setting_body()
        literals = re.sub(r"'[^']*'", "''", body)
        assert literals.count(" IN (") == 2 and literals.count("NOT IN (") == 1
        clauses = re.findall(r"position\(''\s+in \$1\) ([=>]) 0", literals)
        assert clauses == [">", "="]
        assert "NOT EXISTS (SELECT 1 FROM pg_catalog.pg_settings p" in body
        assert re.sub(r"\s+", " ", body).count(" OR ") == 2

    def test_schema_lists_match(self):
        rule = SPEC_SCHEMA["$defs"]["readable_setting_name"]["not"]["anyOf"]
        assert set(rule[0]["enum"]) == COLLECTOR_SECRET_SETTINGS
        assert rule[1]["pattern"] == "\\."
        assert set(rule[1]["not"]["enum"]) == COLLECTOR_REVIEWED_CUSTOM_SETTINGS
        props = SPEC_SCHEMA["$defs"]
        assert props["check"]["properties"]["setting_name"] == {"$ref": "#/$defs/readable_setting_name"}
        assert props["applies_when"]["properties"]["setting_name"] == {"$ref": "#/$defs/readable_setting_name"}

    def test_report_contract_lists_the_new_codes(self):
        row = REPORT_SCHEMA["properties"]["results"]["items"]["properties"]
        assert {"redacted_secret_setting", "condition_redacted_secret_setting"} <= set(row["reason_code"]["enum"])
        exp = row["explanation"]["properties"]
        assert "redacted_secret_setting" in exp["code"]["enum"]
        assert "redacted_secret_setting" in exp["cause"]["enum"]


class TestFixPlanReason:
    """The fix plan explains a redacted-value finding instead of a generic reason."""

    def test_redacted_check_gets_plain_reason(self):
        from services.sandbox_poc.planning import session_override_reason
        reason = session_override_reason(
            {"explanation": {"code": "redacted_secret_setting", "setting_name": "primary_conninfo"}})
        assert reason.startswith("Unknown: DBGuard deliberately never reads primary_conninfo")
        assert "no sandbox fix can run" in reason

    def test_redacted_condition_gets_plain_reason(self):
        from services.sandbox_poc.planning import session_override_reason
        reason = session_override_reason({"explanation": {
            "code": "condition_unknown", "cause": "redacted_secret_setting", "setting_name": "app.key"}})
        assert "never reads app.key" in reason

    def test_other_codes_are_unchanged(self):
        from services.sandbox_poc.planning import session_override_reason
        assert session_override_reason({"explanation": {"code": "not_collected"}}) is None
        assert "per role, database or session" in session_override_reason(
            {"explanation": {"code": "session_override", "setting_name": "log_statement", "source": "user"}})
