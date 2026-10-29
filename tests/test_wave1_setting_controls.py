"""Wave 1 setting controls: assessment, policy and allowlist for the seven new automated
CIS PG17 v1.1.0 specs, plus the two manual_checklist specs that must get no policy.

The compliant values below are written out from the CIS audit text, not read back from
the spec or POLICIES, so a spec or policy that drifts in the same direction is caught.
No Docker, network or model.
"""
import copy

import pytest
from pydantic import ValidationError

from app.models import FindingStatus, SetConfigTemplateParams
from app.services.assessment_service import AssessmentService
from app.services.spec_engine import assess, spec_sha256
from app.services.spec_engine.manifest import condition_check_id
from app.services.spec_engine.validate import OPERATORS
from catalog.controls.assess.registry import CONTROL_REGISTRY
from scripts.sandbox_poc import demo_template
from services.sandbox_poc.planning import POLICIES, fix_scope, risk_review
from services.sandbox_poc.provenance import setting_rows
from services.sandbox_poc.shared import ContractError
from services.sandbox_poc.workflow import template_action
from test_sandbox_poc import engine, snapshot  # noqa: F401  shared fixtures

# (spec_id, setting, compliant value, non-compliant values, pg_settings vartype,
#  pg_settings context observed on postgres:17-bookworm 17.11)
CONTROLS = [
    ("cis-pg17-v1.1.0:3.1.7", "log_truncate_on_rotation", "on", ["off"], "bool", "sighup"),
    ("cis-pg17-v1.1.0:3.1.11", "syslog_sequence_numbers", "on", ["off"], "bool", "sighup"),
    ("cis-pg17-v1.1.0:3.1.17", "debug_print_rewritten", "off", ["on"], "bool", "user"),
    ("cis-pg17-v1.1.0:3.1.18", "debug_print_plan", "off", ["on"], "bool", "user"),
    ("cis-pg17-v1.1.0:3.1.19", "debug_pretty_print", "on", ["off"], "bool", "user"),
    ("cis-pg17-v1.1.0:3.1.22", "log_error_verbosity", "verbose", ["terse", "default"], "enum",
     "superuser"),
    ("cis-pg17-v1.1.0:3.1.23", "log_hostname", "off", ["on"], "bool", "sighup"),
]
IDS = [c[0].split(":")[1] for c in CONTROLS]
# Reviewed operational risk per setting, written out so a POLICIES change must update it here.
EXPECTED_RISK = {
    "log_truncate_on_rotation": "high",
    "syslog_sequence_numbers": "low",
    "debug_print_rewritten": "low",
    "debug_print_plan": "low",
    "debug_pretty_print": "low",
    "log_error_verbosity": "medium",
    "log_hostname": "low",
}
# 3.1.11 applies only when logging to syslog (Gate 1 ruling A6, re-approved). Tests of its
# main check supply that condition as a log_destination row / '#applies_when' entry.
SYSLOG_ROW = {"name": "log_destination", "setting": "stderr,syslog", "vartype": "string",
              "unit": None, "sanitised": False}
CONDITIONAL = {"cis-pg17-v1.1.0:3.1.11"}


def with_condition(spec_id, rows):
    return [*rows, dict(SYSLOG_ROW)] if spec_id in CONDITIONAL else rows


MANUAL = [
    ("cis-pg17-v1.1.0:3.1.12", "syslog_split_messages"),
    ("cis-pg17-v1.1.0:7.2", "log_replication_commands"),
]


@pytest.fixture
def service():
    return AssessmentService(CONTROL_REGISTRY)


def evaluate(service, settings, **extra):
    snapshot = {"snapshot_id": "wave1", "settings": settings, "schemas": [],
                "password_types": [], "gaps": [], **extra}
    return {f.control_id: f for f in service.evaluate(snapshot).findings}


def spec_of(engine, spec_id):
    return next(s for s in engine.specs if s["spec_id"] == spec_id)


# ---------------------------------------------------------------------------
# The spec says what the CIS text says
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("spec_id,name,good,bad,vartype,context", CONTROLS, ids=IDS)
def test_spec_check_and_proof_match_cis_value(engine, spec_id, name, good, bad, vartype, context):
    spec = spec_of(engine, spec_id)
    assert spec["tier"] == "automated"
    assert spec["authored_by"] == "agent"  # drafted, not approved
    check = spec["check"]
    assert (check["kind"], check["setting_name"], check["query"]) == ("setting", name, f"SHOW {name}")
    assert (check["operator"], check["expected"]) == ("equals", good)
    assert spec["proof"]["fix"] == {"setting_name": name, "value": good}
    assert spec["proof"]["break"]["setting_name"] == name
    assert spec["proof"]["break"]["value"] in bad


# ---------------------------------------------------------------------------
# ASSESS (offline registry generated from the specs)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("spec_id,name,good,bad,vartype,context", CONTROLS, ids=IDS)
def test_compliant_value_passes(service, spec_id, name, good, bad, vartype, context):
    finding = evaluate(service, with_condition(spec_id, [{"name": name, "setting": good,
                                                          "vartype": vartype, "unit": None,
                                                          "sanitised": False}]))[spec_id]
    assert finding.status == FindingStatus.PASS
    assert finding.evidence_found == {name: good}
    assert finding.is_gapped is False


@pytest.mark.parametrize("spec_id,name,good,bad,vartype,context", CONTROLS, ids=IDS)
def test_non_compliant_values_fail(service, spec_id, name, good, bad, vartype, context):
    for value in bad:
        finding = evaluate(service, with_condition(
            spec_id, [{"name": name, "setting": value, "vartype": vartype}]))[spec_id]
        assert finding.status == FindingStatus.FAIL, value
        assert finding.evidence_found == {name: value}
        assert f"'{good}'" in finding.rationale
        assert finding.control_metadata.template_id == "SET_CONFIG_PARAMETER"


@pytest.mark.parametrize("spec_id,name,good,bad,vartype,context", CONTROLS, ids=IDS)
def test_settings_section_not_collected_is_gapped(service, spec_id, name, good, bad, vartype,
                                                  context):
    finding = evaluate(service, None, gaps=[{"section": "settings",
                                             "reason": "insufficient_privilege"}])[spec_id]
    assert finding.status == FindingStatus.GAPPED
    assert finding.is_gapped is True
    assert "insufficient_privilege" in finding.rationale


@pytest.mark.parametrize("spec_id,name,good,bad,vartype,context", CONTROLS, ids=IDS)
def test_setting_row_missing_is_gapped(service, spec_id, name, good, bad, vartype, context):
    # Collected settings list without this row: never read as default/PASS.
    finding = evaluate(service, with_condition(
        spec_id, [{"name": "log_connections", "setting": "on"}]))[spec_id]
    assert finding.status == FindingStatus.GAPPED
    assert finding.evidence_found[name] is None


@pytest.mark.parametrize("spec_id,name,good,bad,vartype,context", CONTROLS, ids=IDS)
@pytest.mark.parametrize("unreadable", [
    {"setting": None},
    {"sanitised": True},
    {"unit": "s"},
    {"vartype": "integer"},
    {"vartype": "string"},
    {"setting": 1},
], ids=["null", "sanitised", "unit", "integer", "string", "non-string"])
def test_unreadable_evidence_is_gapped_even_with_compliant_value(
        service, spec_id, name, good, bad, vartype, context, unreadable):
    row = {"name": name, "setting": good, "vartype": vartype, "unit": None, "sanitised": False}
    row.update(unreadable)
    finding = evaluate(service, with_condition(spec_id, [row]))[spec_id]
    assert finding.status == FindingStatus.GAPPED
    assert finding.is_gapped is True


@pytest.mark.parametrize("spec_id,name,good,bad,vartype,context", CONTROLS, ids=IDS)
@pytest.mark.parametrize("version", [160004, 180000])
def test_wrong_postgres_major_is_gapped(service, spec_id, name, good, bad, vartype, context,
                                        version):
    finding = evaluate(service, with_condition(spec_id, [{"name": name, "setting": good,
                                                          "vartype": vartype}]),
                       identity={"server_version_num": version})[spec_id]
    assert finding.status == FindingStatus.GAPPED
    assert "PostgreSQL 17" in finding.rationale


# ---------------------------------------------------------------------------
# Phase 1 assessor (collector check entries)
# ---------------------------------------------------------------------------

def phase1(engine, spec_id, entry, condition="stderr,syslog"):
    spec = spec_of(engine, spec_id)
    entry = {"spec_hash": spec_sha256(spec), "query": spec["check"]["query"], **entry}
    checks = {spec_id: entry}
    if "applies_when" in spec:
        checks[condition_check_id(spec_id)] = {"spec_hash": spec_sha256(spec),
                                                "query": "SHOW log_destination",
                                                "status": "ok", "result": condition}
    snapshot = {
        "envelope": {"schema_version": "0.3.0", "target_id": "t", "database": "d",
                     "collector_sha256": "a" * 64,
                     "manifest": {"sha256": "b" * 64, "manifest_version": 1,
                                  "benchmark_id": "cis-pg17-v1.1.0", "check_count": len(checks)}},
        "baseline": {"identity": {"server_version_num": 170000}},
        "checks": checks,
    }
    return assess([spec], snapshot, engine.records)["results"][0]["result"]


@pytest.mark.parametrize("spec_id,name,good,bad,vartype,context", CONTROLS, ids=IDS)
def test_phase1_pass_fail_and_never_pass_without_a_result(engine, spec_id, name, good, bad,
                                                         vartype, context):
    assert phase1(engine, spec_id, {"status": "ok", "result": good}) == "PASS"
    for value in bad:
        assert phase1(engine, spec_id, {"status": "ok", "result": value}) == "FAIL"
    assert phase1(engine, spec_id, {"status": "not_collected"}) == "NOT_COLLECTED"
    assert phase1(engine, spec_id, {"status": "error", "error": "permission denied"}) == "ERROR"
    assert phase1(engine, spec_id, {"status": "ok", "result": good,
                                    "spec_hash": "0" * 64}) == "STALE"


def test_3_1_11_applies_only_when_logging_to_syslog(engine, service):
    """stderr only: 3.1.11 is NOT_APPLICABLE whatever syslog_sequence_numbers says; with no
    log_destination evidence it is unknown (GAPPED / NOT_COLLECTED), never PASS."""
    spec_id = "cis-pg17-v1.1.0:3.1.11"
    assert spec_of(engine, spec_id)["applies_when"]["setting_name"] == "log_destination"
    for value in ("on", "off"):
        assert phase1(engine, spec_id, {"status": "ok", "result": value},
                      condition="stderr") == "NOT_APPLICABLE"
        assert phase1(engine, spec_id, {"status": "ok", "result": value},
                      condition="csvlog,stderr") == "NOT_APPLICABLE"
        assert phase1(engine, spec_id, {"status": "ok", "result": value},
                      condition="syslog") == ("PASS" if value == "on" else "FAIL")
        row = {"name": "syslog_sequence_numbers", "setting": value, "vartype": "bool"}
        stderr = {"name": "log_destination", "setting": "stderr", "vartype": "string"}
        assert evaluate(service, [row, stderr])[spec_id].status == FindingStatus.NOT_APPLICABLE
        assert evaluate(service, [row])[spec_id].status == FindingStatus.GAPPED


# ---------------------------------------------------------------------------
# Reviewed fix policy and template allowlist
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("spec_id,name,good,bad,vartype,context", CONTROLS, ids=IDS)
def test_policy_value_satisfies_spec_operator(engine, spec_id, name, good, bad, vartype, context):
    spec, setting, value = fix_scope(engine, spec_id)
    assert (spec["spec_id"], setting, value) == (spec_id, name, good)
    assert OPERATORS[spec["check"]["operator"]](value, spec["check"]["expected"])
    assert not any(OPERATORS[spec["check"]["operator"]](v, spec["check"]["expected"]) for v in bad)


class _Specs:
    def __init__(self, specs):
        self.specs = specs


@pytest.mark.parametrize("spec_id,name,good,bad,vartype,context", CONTROLS, ids=IDS)
def test_policy_is_refused_when_spec_direction_is_flipped(engine, spec_id, name, good, bad,
                                                          vartype, context):
    flipped = copy.deepcopy(spec_of(engine, spec_id))
    flipped["check"]["expected"] = bad[0]
    with pytest.raises(ContractError, match="does not satisfy"):
        fix_scope(_Specs([flipped]), spec_id)
    forged = copy.deepcopy(spec_of(engine, spec_id))
    forged["check"]["query"] = f"SHOW {name}; SELECT 1"
    with pytest.raises(ContractError):
        fix_scope(_Specs([forged]), spec_id)


@pytest.mark.parametrize("spec_id,name,good,bad,vartype,context", CONTROLS, ids=IDS)
def test_set_config_params_accept_the_policy_value(spec_id, name, good, bad, vartype, context):
    params = SetConfigTemplateParams(param_name=name, param_value=good)
    assert (params.param_name, params.param_value) == (name, good)


@pytest.mark.parametrize("spec_id,name,good,bad,vartype,context", CONTROLS, ids=IDS)
@pytest.mark.parametrize("param_name,param_value", [
    ("{name}; DROP TABLE x", "{good}"),
    ('"{name}"', "{good}"),
    ("{name}_x", "{good}"),
    ("{upper}", "{good}"),
    ("{name}", "{good}'; SELECT pg_reload_conf(); --"),
    ("{name}", "{good}/*"),
])
def test_set_config_params_reject_malicious_identifier_and_value(
        spec_id, name, good, bad, vartype, context, param_name, param_value):
    fill = dict(name=name, good=good, upper=name.upper())
    with pytest.raises(ValidationError):
        SetConfigTemplateParams(param_name=param_name.format(**fill),
                                param_value=param_value.format(**fill))


@pytest.mark.parametrize("spec_id,name,good,bad,vartype,context", CONTROLS, ids=IDS)
def test_approved_template_renders_the_supported_action(spec_id, name, good, bad, vartype,
                                                        context):
    sql = demo_template().render(name, good)
    assert template_action(sql, name) == {"action": "set_config", "param": name, "value": good}
    with pytest.raises(ContractError):  # the rendered statement is bound to this setting only
        template_action(sql, "log_connections")


# ---------------------------------------------------------------------------
# Risk review
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("spec_id,name,good,bad,vartype,context", CONTROLS, ids=IDS)
def test_risk_review_reports_reload_for_real_context(engine, snapshot, spec_id, name, good, bad,
                                                     vartype, context):
    snapshot = copy.deepcopy(snapshot)
    row = setting_rows(snapshot)[name]
    row.update(context=context, setting=bad[0])
    review = risk_review(engine, snapshot, spec_id)
    assert review["requires"] == "reload"
    assert "without restarting" in review["activation_fact"]
    assert (review["current_value"], review["proposed_value"]) == (bad[0], good)
    # A reload keeps exactly the reviewed policy risk (3.1.7 is high by policy, not by context).
    assert POLICIES[name][1] == EXPECTED_RISK[name]
    assert review["operational_risk"] == EXPECTED_RISK[name]
    assert review["dba_review_required"] is True
    # The same review flips to restart (and high risk) if evidence says postmaster.
    row.update(context="postmaster")
    restart = risk_review(engine, snapshot, spec_id)
    assert (restart["requires"], restart["operational_risk"]) == ("restart", "high")


def test_log_truncate_on_rotation_impact_warns_of_log_data_loss(engine, snapshot):
    reasoning = POLICIES["log_truncate_on_rotation"][2].lower()
    assert "los" in reasoning and "log data" in reasoning  # "loses log data"
    assert "logging_collector" in reasoning
    review = risk_review(engine, snapshot, "cis-pg17-v1.1.0:3.1.7")
    assert review["reasoning"] == POLICIES["log_truncate_on_rotation"][2]
    # Melvin ruled at Gate 2: silent audit-log loss is high operational risk.
    assert review["operational_risk"] == "high"


# ---------------------------------------------------------------------------
# Manual specs: no check, no proof, no policy
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("spec_id,name", MANUAL, ids=["3.1.12", "7.2"])
def test_manual_specs_have_no_check_proof_or_policy(engine, service, spec_id, name):
    spec = spec_of(engine, spec_id)
    assert spec["tier"] == "manual_checklist"
    assert "check" not in spec and "proof" not in spec
    assert spec["reason"]
    assert spec_id not in {c["spec_id"] for c in engine.manifest["checks"]}
    assert name not in POLICIES
    with pytest.raises(ContractError):
        fix_scope(engine, spec_id)
    with pytest.raises(ValidationError):
        SetConfigTemplateParams(param_name=name, param_value="on")
    finding = evaluate(service, [{"name": name, "setting": "on", "vartype": "bool"}])[spec_id]
    assert finding.status == FindingStatus.MANUAL_REVIEW
    assert finding.control_metadata.is_automatable is False
