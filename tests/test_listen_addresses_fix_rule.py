"""5.2 listen_addresses fix values (Gate 1 ruling, Melvin: "Require localhost in the value").

A site-specific fix value must parse like the 5.2 check reads it (SplitGUCList),
list localhost, list no '*' or 0.0.0.0, and list only IPv4/IPv6 addresses or host
names otherwise. The sandbox (--network none) can only start PostgreSQL on loopback
after the restart, so the risk text and every exported bundle carry that limit.

No Docker, network or model. Approved profiles are in-memory test objects.
"""
import io
import zipfile

import pytest
from pydantic import ValidationError

from app.models import SetConfigTemplateParams
from app.services.setting_values import SettingValueError, check_setting_value
from app.services.spec_engine.policy import profile_value_errors
from scripts.sandbox_poc import demo_template
from services.sandbox_poc import planning
from services.sandbox_poc.handoff import SandboxHandoff
from services.sandbox_poc.planning import (
    LISTEN_ADDRESSES_SANDBOX_LIMIT,
    POLICIES,
    SANDBOX_LIMITS,
    fix_scope,
)
from services.sandbox_poc.review_bundle import build_review_bundle
from services.sandbox_poc.shared import ContractError
from services.sandbox_poc.workflow import template_action
from test_review_bundle import recorded  # noqa: F401  shared fixture
from test_sandbox_poc import engine, snapshot  # noqa: F401  shared fixtures
from test_wave1b_fixability import B, _engine, listen_spec, profile

SPEC_ID = f"{B}:5.2"


@pytest.mark.parametrize("value", ["localhost, 10.0.0.5", "localhost"])
def test_accepted_everywhere(value):
    assert check_setting_value("listen_addresses", value) == value
    assert SetConfigTemplateParams(param_name="listen_addresses", param_value=value).param_value == value
    sql = demo_template().render("listen_addresses", value)
    assert template_action(sql, "listen_addresses")["value"] == value
    spec = listen_spec()
    approved = profile(fixes={SPEC_ID: value})
    assert profile_value_errors(approved, [spec]) == []
    assert fix_scope(_engine([spec], approved), SPEC_ID)[1:] == ("listen_addresses", value)


@pytest.mark.parametrize("value,message", [
    ("10.0.0.5", "must include localhost as one of its items"),
    ("*, localhost", "must not contain '*'"),
    ("localhost, 0.0.0.0", "must not contain '0.0.0.0'"),
    ("garbage!!", "is not a valid comma-separated address list"),
    ("localhost 10.0.0.5", "is not a valid comma-separated address list"),
    ("localhost, 10.0.0.256", "is not a valid IPv4 address, IPv6 address or host name"),
    ("localhost, db_1", "is not a valid IPv4 address, IPv6 address or host name"),
    ("localhost, ::", "is not allowed"),
    ("localhost'; ALTER SYSTEM SET listen_addresses = '*'; --", "forbidden fragment"),
    ('localhost, "*"', "forbidden fragment"),
])
def test_rejected_everywhere_with_a_clear_message(value, message):
    with pytest.raises(SettingValueError) as exc:
        check_setting_value("listen_addresses", value)
    assert message in str(exc.value)
    with pytest.raises(ValidationError):
        SetConfigTemplateParams(param_name="listen_addresses", param_value=value)
    spec = listen_spec()
    approved = profile(fixes={SPEC_ID: value})
    errors = profile_value_errors(approved, [spec])
    assert errors and message in errors[0], errors  # the clear value-rule message comes first
    with pytest.raises(ContractError, match="outside the reviewed value rule"):
        fix_scope(_engine([spec], approved), SPEC_ID)


def test_risk_text_states_the_sandbox_limit():
    text = POLICIES["listen_addresses"][2]
    assert LISTEN_ADDRESSES_SANDBOX_LIMIT in text
    for phrase in ("only verify the restart and the CIS 5.2 check with loopback",
                   "cannot bind the site IP address",
                   "listed IP address exists on the host",
                   "application clients can reach PostgreSQL"):
        assert phrase in LISTEN_ADDRESSES_SANDBOX_LIMIT
    prerequisites = POLICIES["listen_addresses"][3]
    assert "Confirm each listed IP address exists on the host" in prerequisites
    assert SANDBOX_LIMITS == {"listen_addresses": LISTEN_ADDRESSES_SANDBOX_LIMIT}


def _bundle_files(recorded, engine):  # noqa: F811
    data = build_review_bundle(SandboxHandoff(**recorded["handoff"]), recorded["result"], engine)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        return {name: archive.read(name).decode() for name in archive.namelist()}


def test_bundle_carries_the_sandbox_limit_for_its_setting(recorded, engine, monkeypatch):  # noqa: F811
    plain = _bundle_files(recorded, engine)  # log_connections has no sandbox limit
    assert "SANDBOX LIMIT" not in plain["README.txt"] and "Sandbox limit:" not in plain["report.html"]
    warning = "Test limit: the sandbox cannot prove <this>."
    monkeypatch.setattr(planning, "SANDBOX_LIMITS", {"log_connections": warning})
    files = _bundle_files(recorded, engine)
    assert f"SANDBOX LIMIT: {warning}" in files["README.txt"]
    assert "Test limit: the sandbox cannot prove &lt;this&gt;." in files["report.html"]
