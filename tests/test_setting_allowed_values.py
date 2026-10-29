"""Allowed values for every allowlisted boolean and enum setting.

The expected sets below are written out from the PostgreSQL 17 documentation
(runtime-config-logging, runtime-config-connection, runtime-config-developer) and
pg_settings.enumvals, never read back from setting_values, so a table that drifts
is caught. Every path a fix value can take is checked: check_setting_value,
SetConfigTemplateParams, workflow.template_action, policy-profile validation and
planning.fix_scope. No Docker, network or model.
"""
import copy
import json
from types import SimpleNamespace

import pytest
import yaml
from pydantic import ValidationError

from app.models import SetConfigTemplateParams
from app.services.setting_values import (
    SETTING_ALLOWED_VALUES,
    SETTING_VALUE_RULES,
    SettingValueError,
    check_setting_value,
)
from app.services.spec_engine import RecordsIndex, load_spec
from app.services.spec_engine.policy import parse_profile, profile_value_errors
from scripts.sandbox_poc import demo_template
from services.sandbox_poc.planning import FROM_PROFILE, POLICIES, fix_scope
from services.sandbox_poc.shared import ROOT, ContractError
from services.sandbox_poc.workflow import template_action

B = "cis-pg17-v1.1.0"
RECORDS = RecordsIndex.load(ROOT / f"catalog/benchmarks/{B}/records.json")
LIVE_SNAPSHOT = ROOT / "tests/fixtures/phase1/snapshot-pg17-live.json"
SPECS = [load_spec(p) for p in sorted((ROOT / f"catalog/specs/{B}").glob("*.yaml"))]

BOOLS = {"log_connections", "log_disconnections", "log_checkpoints", "log_lock_waits", "log_hostname",
         "log_truncate_on_rotation", "logging_collector", "syslog_sequence_numbers", "debug_print_parse",
         "debug_print_rewritten", "debug_print_plan", "debug_pretty_print"}
LEVELS = {"debug5", "debug4", "debug3", "debug2", "debug1", "info", "notice", "warning", "error",
          "log", "fatal", "panic"}
ENUMS = {
    "log_statement": {"none", "ddl", "mod", "all"},
    "log_error_verbosity": {"terse", "default", "verbose"},
    "log_min_messages": LEVELS,
    "log_min_error_statement": LEVELS,
    "syslog_facility": {f"local{n}" for n in range(8)},
    "ssl_min_protocol_version": {"TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"},
    "password_encryption": {"md5", "scram-sha-256"},
}
BOOL_SPELLINGS = {"on", "off", "true", "false", "yes", "no", "1", "0"}
EXPECTED = {**{name: BOOL_SPELLINGS for name in BOOLS}, **ENUMS}

# PostgreSQL also accepts these (case-insensitive, unique prefixes), but a reviewed
# value uses only the lowercase whole words. Hidden enum aliases are refused.
BOOL_REFUSED = ["ON", "Off", "TRUE", "True", "t", "tr", "y", "of", "2", "-1", "maybe", "on ", " off",
                "enabled"]
ENUM_REFUSED = {
    "log_statement": ["DDL", "none,ddl", "everything"],
    "log_error_verbosity": ["Verbose", "loud"],
    "log_min_messages": ["WARNING", "debug", "loud", "warning error", "debug6"],
    "log_min_error_statement": ["Error", "debug", "critical"],
    "syslog_facility": ["local8", "local9", "LOCAL0", "user", "daemon"],
    "ssl_min_protocol_version": ["tlsv1.2", "TLSv1.4", "SSLv3", "TLSv1.2 "],
    "password_encryption": ["SCRAM-SHA-256", "on", "plain", "scram"],
}


def allowlisted_settings():
    """The SetConfigTemplateParams allowlist, read from its own error message."""
    with pytest.raises(ValidationError) as info:
        SetConfigTemplateParams(param_name="not_a_setting", param_value="x")
    text = str(info.value)
    return {name for name in set(POLICIES) | set(EXPECTED) | set(SETTING_VALUE_RULES)
            if f"'{name}'" in text}


def test_table_is_exactly_the_reviewed_sets():
    assert {name: set(values) for name, values in SETTING_ALLOWED_VALUES.items()} == EXPECTED


def test_every_allowlisted_bool_and_enum_setting_has_allowed_values():
    allowlisted = allowlisted_settings()
    assert set(EXPECTED) <= allowlisted
    assert set(POLICIES) <= allowlisted
    assert not set(SETTING_ALLOWED_VALUES) & set(SETTING_VALUE_RULES)
    # Independent source: the vartype a real PostgreSQL 17 reported in the live fixture.
    rows = {r["name"]: r for r in json.loads(LIVE_SNAPSHOT.read_text())["baseline"]["settings"]}
    typed = {name: rows[name]["vartype"] for name in allowlisted if name in rows}
    assert set(EXPECTED) <= set(typed), set(EXPECTED) - set(typed)
    for name, vartype in typed.items():
        assert (vartype in ("bool", "enum")) == (name in SETTING_ALLOWED_VALUES), (name, vartype)


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_allowed_values_pass_every_path(name):
    for value in sorted(EXPECTED[name]):
        assert check_setting_value(name, value) == value
        assert SetConfigTemplateParams(param_name=name, param_value=value).param_value == value
        if name in POLICIES:
            sql = demo_template().render(name, value)
            assert template_action(sql, name) == {"action": "set_config", "param": name, "value": value}


@pytest.mark.parametrize("name", sorted(EXPECTED))
def test_other_values_are_refused_on_every_path(name):
    refused = BOOL_REFUSED if name in BOOLS else ENUM_REFUSED[name]
    for value in refused + [""]:
        with pytest.raises(SettingValueError):
            check_setting_value(name, value)
        with pytest.raises(ValidationError):
            SetConfigTemplateParams(param_name=name, param_value=value)
        if name in POLICIES and value.strip() == value and value:
            sql = f"ALTER SYSTEM SET \"{name}\" = '{value}';\nSELECT pg_reload_conf();"
            with pytest.raises(ContractError, match="outside the reviewed rule"):
                template_action(sql, name)


def test_reviewed_fixed_values_are_allowed():
    for name, (value, *_rest) in POLICIES.items():
        if name in EXPECTED:
            assert value != FROM_PROFILE or name == "syslog_facility", name
            if value != FROM_PROFILE:
                assert value in EXPECTED[name], name
            if name in BOOLS:  # the canonical SHOW spelling, so verify compares like with like
                assert value in ("on", "off"), name


def _profile(values):
    doc = {"profile_id": "allowed-values", "benchmark": B, "approved_by": "Test Reviewer",
           "approved_at": "2026-10-30", "values": values}
    return parse_profile(yaml.safe_dump(doc).encode(), RECORDS)


def test_profile_validation_refuses_values_outside_the_enum():
    sid = f"{B}:3.1.10"
    good = _profile({sid: {"expected": "local0", "fix": "local0", "break": "local1"}})
    assert profile_value_errors(good, SPECS) == []
    for phase in ("fix", "break"):
        entry = {"expected": "local0", "fix": "local0", "break": "local1"}
        entry[phase] = "local9"
        errors = profile_value_errors(_profile({sid: entry}), SPECS)
        assert any(f".{phase}: value 'local9' is not allowed for syslog_facility" in e for e in errors), errors


def test_fix_scope_refuses_a_non_canonical_enum_fix():
    spec = copy.deepcopy(next(s for s in SPECS if s["spec_id"] == f"{B}:3.1.10"))
    policy = _profile({spec["spec_id"]: {"expected": "local0", "fix": "LOCAL0", "break": "local1"}})
    engine = SimpleNamespace(specs=[spec], policy=policy, records=RECORDS, policy_pin=policy.pin())
    with pytest.raises(ContractError, match="outside the reviewed value rule"):
        fix_scope(engine, spec["spec_id"])
