"""db-security-reviewer findings on Wave 1b (PASS with two WARNs and NOTEs).

WARN 1: 5.2 all-interfaces addresses in non-standard numeric form. glibc reads
'0', '0x0', '0.0x0' and '0.0.0.00' as 0.0.0.0, so none of them may be a fix value,
and a target listing one is never assessed as PASS (ERROR / GAPPED).

WARN 2: profile approvals are a typed name without sign-in. Every output that
carries an approver name also carries approval_auth = DEMO_NO_SIGN_IN, and the
human-readable files print "DEMO approval: no sign-in" next to the profile pin.

NOTEs: restart allowlist in runtime.activate, syslog_ident value rule, seed
approver rule, policy-profile request limits, 5.2 host-name limit text, report pin
for site fixes.

No Docker, network or model. Profiles are in-memory test objects or tmp-path stores.
"""
import copy
import io
import json
import zipfile
from types import SimpleNamespace

import pytest
import yaml
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.models import SetConfigTemplateParams
from app.services.policy_profile_store import PolicyProfileStore, ProfileStoreError
from app.services.setting_values import SettingValueError, check_setting_value
from app.services.spec_engine.operators import evaluate, is_nonstandard_numeric_address, no_item_in
from app.services.spec_engine.policy import (
    APPROVAL_AUTH,
    DEMO_APPROVAL_LABEL,
    PolicyProfileError,
    approval_text,
    default_profile_path,
    parse_profile,
    profile_value_errors,
)
from catalog.controls.assess.registry import FindingStatus
from services.sandbox_poc import batch as batch_module
from services.sandbox_poc import planning, runtime as runtime_module
from services.sandbox_poc.handoff import SandboxHandoff, TemplateReference, build_handoff
from services.sandbox_poc.planning import FROM_PROFILE, LISTEN_ADDRESSES_SANDBOX_LIMIT, fix_scope, fix_value_source
from services.sandbox_poc.review_bundle import build_review_bundle
from services.sandbox_poc.runtime import RESTART_SETTINGS, DisposablePostgres
from services.sandbox_poc.shared import ContractError, SpecEngine
from test_sandbox_poc import engine, run_fake, snapshot  # noqa: F401  shared fixtures
from test_spec_engine_wave1b import entry, rows, run
from test_wave1b_fixability import B, RECORDS, SPECS, _engine, listen_spec, profile, spec_of

SPEC_ID = f"{B}:5.2"
LABEL = "DEMO_NO_SIGN_IN"


# ---------------------------------------------------------------------------
# WARN 1: non-standard numeric listen_addresses forms
# ---------------------------------------------------------------------------

NUMERIC_FIXES = ["0x0, localhost", "0.0x0, localhost", "0, localhost", "0.0.0.00, localhost"]


@pytest.mark.parametrize("value", NUMERIC_FIXES)
def test_numeric_all_interfaces_forms_are_refused_as_fix_values(value):
    item = value.split(",")[0]
    with pytest.raises(SettingValueError) as exc:
        check_setting_value("listen_addresses", value)
    message = str(exc.value)
    assert f"listen_addresses item {item!r}" in message
    assert "non-standard numeric form" in message and "0.0.0.0" in message
    with pytest.raises(ValidationError):
        SetConfigTemplateParams(param_name="listen_addresses", param_value=value)
    spec = listen_spec()
    errors = profile_value_errors(profile(fixes={SPEC_ID: value}), [spec])
    assert errors and "non-standard numeric form" in errors[0], errors
    with pytest.raises(ContractError, match="outside the reviewed value rule"):
        fix_scope(_engine([spec], profile(fixes={SPEC_ID: value})), SPEC_ID)


@pytest.mark.parametrize("value", ["localhost, 1db.example.com", "localhost, db.9host", "localhost, 127.1",
                                   "localhost, 010.0.0.5", "localhost, 0x7f.1", "localhost, cafe", "localhost, a1.b2"])
def test_host_labels_start_with_a_letter_and_hex_only_items_are_refused(value):
    with pytest.raises(SettingValueError):
        check_setting_value("listen_addresses", value)


@pytest.mark.parametrize("value", ["localhost, 10.0.0.5", "localhost, db-1.example.com", "localhost, ::1",
                                   "localhost, fe80::1", "localhost, db1.prod"])
def test_strict_addresses_and_letter_host_names_still_pass(value):
    assert check_setting_value("listen_addresses", value) == value


def test_numeric_form_helper():
    for item in ("0", "0x0", "0.0x0", "0.0.0.00", "127.1", "0177.0.0.1", "10.0.0.256", "0x7f000001"):
        assert is_nonstandard_numeric_address(item), item
    for item in ("0.0.0.0", "10.0.0.5", "localhost", "db.example.com", "::", "::1", "*"):
        assert not is_nonstandard_numeric_address(item), item


@pytest.mark.parametrize("actual", ["0", "0x0", "0.0.0.00", "localhost, 0x0", "0.0x0", "127.1"])
def test_numeric_target_values_are_never_pass(actual):
    spec = listen_spec()
    with pytest.raises(ValueError, match="non-standard numeric address form"):
        no_item_in(actual, ["*", "0.0.0.0"], setting_name="listen_addresses")
    with pytest.raises(ValueError):
        evaluate(spec["check"], actual)
    # Phase 1 assessment: ERROR (operator_error), never PASS
    row = run([spec], {SPEC_ID: entry(spec, result=actual)})["results"][0]
    assert (row["result"], row["reason_code"]) == ("ERROR", "operator_error"), actual
    # ASSESS registry: GAPPED, never PASS
    from catalog.controls.assess.spec_controls import _setting_rule
    finding = _setting_rule(spec)(rows(listen_addresses=(actual, "string")))
    assert finding.status == FindingStatus.GAPPED
    assert finding.explanation["code"] == "uninterpretable_value"


def test_a_definite_fail_stays_fail_and_ipv6_wildcard_is_out_of_scope():
    assert no_item_in("*, 0x0", ["*", "0.0.0.0"], setting_name="listen_addresses") is False
    assert no_item_in("0.0.0.0, 0", ["*", "0.0.0.0"], setting_name="listen_addresses") is False
    # Melvin's ruling: '::' is outside 5.2 (spec interpretation); unchanged
    assert no_item_in("::", ["*", "0.0.0.0"], setting_name="listen_addresses") is True


# ---------------------------------------------------------------------------
# WARN 2: approval_auth travels with every approver name
# ---------------------------------------------------------------------------

def _profile_dicts(obj):
    """Every dict that carries a policy-profile approver (approved_by next to profile_id)."""
    if isinstance(obj, dict):
        if "approved_by" in obj and "profile_id" in obj:
            yield obj
        for value in obj.values():
            yield from _profile_dicts(value)
    elif isinstance(obj, list):
        for value in obj:
            yield from _profile_dicts(value)


def assert_labelled(obj, at_least=1):
    found = list(_profile_dicts(obj))
    assert len(found) >= at_least, "no profile approval found: the check would be vacuous"
    for item in found:
        assert item.get("approval_auth") == LABEL, item
    return found


def _approved_site_profile():
    return profile(fixes={SPEC_ID: "localhost, 10.0.0.5"})


def test_pin_and_constants():
    assert APPROVAL_AUTH == LABEL and DEMO_APPROVAL_LABEL == "DEMO approval: no sign-in"
    pin = _approved_site_profile().pin()
    assert pin["approval_auth"] == LABEL and pin["approved_by"] == "Test Reviewer"
    text = approval_text(pin)
    assert "approved by Test Reviewer" in text and DEMO_APPROVAL_LABEL in text and pin["sha256"] in text
    assert approval_text(profile(approved=False).pin()).endswith("not approved")
    assert DEMO_APPROVAL_LABEL not in approval_text(profile(approved=False).pin())
    assert approval_text(None) == "Policy profile: none"


def test_assessment_report_pin_carries_the_label_and_matches_the_contract():
    spec = spec_of(f"{B}:3.1.2")
    approved = profile(values={f"{B}:3.1.2": {"expected": ["stderr"], "fix": "stderr", "break": "csvlog"}})
    report = run([spec], {spec["spec_id"]: entry(spec, result="stderr")}, approved)  # validates the contract
    assert_labelled(report)
    assert report["inputs"]["policy_profile"]["approval_auth"] == LABEL


def test_fix_value_source_carries_the_label():
    spec = listen_spec()
    source = fix_value_source(_engine([spec], _approved_site_profile()), spec)
    assert source["source"] == "policy_profile"
    assert_labelled(source)


def test_profile_store_summaries_and_route_views_carry_the_label(tmp_path, monkeypatch):
    from app.config import settings
    from services.sandbox_poc import router
    monkeypatch.setattr(settings, "policy_profile_storage_dir", str(tmp_path / "profiles"))
    values = {f"{B}:3.1.2": {"expected": ["stderr"], "fix": "stderr", "break": "csvlog"}}
    created = router.create_policy_profile_draft(B, router.PolicyProfileDraft(profile_id="site-a", values=values))
    assert_labelled(created, at_least=2)  # summary and displayed profile
    approved = router.approve_policy_profile(B, created["profile_ref"],
                                             router.PolicyProfileApproval(approver_name="Test Human"))
    assert approved["approved_by"] == "Test Human"
    assert_labelled(approved, at_least=2)
    assert_labelled(router.get_policy_profile(B, approved["profile_ref"]), at_least=2)
    assert_labelled(router.list_policy_profiles(B)["profiles"], at_least=3)  # seed + draft + approved
    # the label is display data only: stored profile bytes never contain it
    stored = (tmp_path / "profiles" / B / f"{approved['profile_ref']}.yaml").read_text()
    assert "approval_auth" not in stored and "Test Human" in stored


def test_spec_assessment_and_fix_plan_responses_carry_the_label(engine, snapshot, monkeypatch):  # noqa: F811
    from services.sandbox_poc import router
    labelled = SpecEngine(engine.specs, engine.records, _approved_site_profile())
    assessment = labelled.assess(snapshot)
    monkeypatch.setattr(router, "assess_uploaded", lambda *args: (labelled, snapshot, assessment))
    response = router.spec_assessment("snap-x", B, "a" * 64, store=None)
    assert_labelled(response)
    plan = router.fix_plan("snap-x", B, False, "a" * 64, store=None, service=SimpleNamespace(risk_reviewer=None))
    assert_labelled(plan)


@pytest.fixture
def labelled_recorded(engine, snapshot):  # noqa: F811
    """test_review_bundle.recorded, but run with an approved profile (5.2 site fix only)."""
    labelled = SpecEngine(engine.specs, engine.records, _approved_site_profile())
    snapshot["envelope"].update(collector_version="unit-fixture", collected_at="2026-09-22T00:00:00Z",
                                collected_by="unit-fixture", is_superuser=True, target_id="t-1")
    snapshot["baseline"]["roles"] = []
    for row in snapshot["baseline"]["settings"]:
        row.update(vartype="bool" if row["setting"] in ("on", "off") else "enum", unit=None, sanitised=False)
    result, _ = run_fake(labelled, snapshot, [None])
    result.update(approval_source="registry", run_id="labelled-run")
    result["template"]["approved_by"] = "INTEGRATION_TEST_ONLY"
    result["template"]["evidence"] = [dict(document_id="test-doc", version="1", sha256="a" * 64,
                                           approved_by="INTEGRATION_TEST_ONLY")]
    ref = TemplateReference(version=result["template"]["version"], sha256=result["template"]["sha256"],
                            evidence=[dict(document_id="test-doc", version="1", sha256="a" * 64)])
    return labelled, build_handoff(labelled, snapshot, ref), result


def test_run_result_carries_the_label(labelled_recorded):
    _, _, result = labelled_recorded
    assert result["status"] == "VERIFIED"
    assert_labelled(result["policy_profile"])


def test_bundle_files_carry_the_label(labelled_recorded):
    labelled, handoff, result = labelled_recorded
    data = build_review_bundle(SandboxHandoff(**handoff.model_dump()), result, labelled)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        files = {name: archive.read(name).decode() for name in archive.namelist()}
    for name in ("fix.json", "evidence.json"):
        assert_labelled(json.loads(files[name]))
    assert json.loads(files["fix.json"])["policy_profile"]["approval_auth"] == LABEL
    assert all(item.get("approval_auth") == LABEL for item in _profile_dicts(json.loads(files["risk-review.json"])))
    line = approval_text(labelled.policy_pin)
    assert DEMO_APPROVAL_LABEL in line
    assert line in files["README.txt"]
    assert line in files["report.html"]  # plain text: nothing in the line needs HTML escaping
    # the label sits next to the profile pin, not somewhere else in the file
    assert f"approved by Test Reviewer at 2026-10-30 [{DEMO_APPROVAL_LABEL}]" in files["README.txt"]


def test_bundle_without_profile_says_none(engine, snapshot):  # noqa: F811
    plain_snapshot = copy.deepcopy(snapshot)
    plain_snapshot["envelope"].update(collector_version="unit-fixture", collected_at="2026-09-22T00:00:00Z",
                                      collected_by="unit-fixture", is_superuser=True, target_id="t-2")
    plain_snapshot["baseline"]["roles"] = []
    for row in plain_snapshot["baseline"]["settings"]:
        row.update(vartype="bool" if row["setting"] in ("on", "off") else "enum", unit=None, sanitised=False)
    result, _ = run_fake(engine, plain_snapshot, [None])
    result.update(approval_source="registry", run_id="plain-run")
    result["template"]["evidence"] = [dict(document_id="test-doc", version="1", sha256="a" * 64,
                                           approved_by="INTEGRATION_TEST_ONLY")]
    ref = TemplateReference(version=result["template"]["version"], sha256=result["template"]["sha256"],
                            evidence=[dict(document_id="test-doc", version="1", sha256="a" * 64)])
    handoff = build_handoff(engine, plain_snapshot, ref)
    data = build_review_bundle(handoff, result, engine)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        assert "Policy profile: none" in archive.read("README.txt").decode()
        assert DEMO_APPROVAL_LABEL not in archive.read("README.txt").decode()


class _BatchRuntime:
    run_id = "batch-runtime"

    def start(self): pass
    def sql(self, script): return "t"
    def activate(self, expected): pass
    def health(self): return True
    def close(self): return {"verified": True}


def test_batch_output_readme_and_report_carry_the_label(monkeypatch):
    pin = _approved_site_profile().pin()
    findings = {"c1": {"status": "PASS"}, "c2": {"status": "PASS"}}
    fake_engine = SimpleNamespace(specs=[], spec_set_hash="h", hashes={}, policy_pin=pin,
                                  collect=lambda runtime: {"baseline": {"gaps": []}},
                                  assess=lambda snap: {"findings": findings})

    def result_for(request):
        fid = "fix-" + request.control_id
        return {"status": "VERIFIED", "run_id": "run-" + request.control_id,
                "fix_unit": {"fix_id": fid, "spec_id": request.control_id, "apply": {"param": "p", "value": "on"}},
                "risk_review": {"fix_id": fid, "setting": "log_" + request.control_id, "operational_risk": "low",
                                "dependencies": []},
                "rendered_apply_sql": "apply", "rendered_rollback_sql": "rollback"}

    def fake_bundle(handoff, result, engine):
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as archive:
            archive.writestr("fix.json", json.dumps({"policy_profile": engine.policy_pin}))
            archive.writestr("manifest.json", json.dumps({"files": {}}))
        return buffer.getvalue()

    service = SimpleNamespace(validate_handoff=lambda request: fake_engine, run=result_for,
                              runtime_factory=_BatchRuntime)
    monkeypatch.setattr(batch_module, "build_review_bundle", fake_bundle)
    monkeypatch.setattr(batch_module, "is_fixture", lambda result: False)
    monkeypatch.setattr(batch_module.history, "record", lambda *args: None)
    monkeypatch.setattr(batch_module, "reconstruction_plan", lambda snap, specs: {"names": [], "signature": {"settings": {}}})
    monkeypatch.setattr(batch_module, "reconstruct", lambda runtime, plan: None)
    monkeypatch.setattr(batch_module, "signature", lambda snap, names: {"settings": {}})
    monkeypatch.setattr("services.sandbox_poc.evidence_capture.verify_runtime", lambda *args: {"passed": True})
    requests = [SimpleNamespace(snapshot={"s": 1}, spec_set_hash="h", policy_profile_sha256=pin["sha256"],
                                control_id=control) for control in ("c1", "c2")]
    output, data = batch_module.run_batch(requests, service)
    assert output["status"] == "VERIFIED", output
    assert_labelled(output)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        readme = archive.read("README.txt").decode()
        report = archive.read("report.html").decode()
        assert_labelled(json.loads(archive.read("combined-evidence.json")))
        assert_labelled(json.loads(archive.read("fix-c1/fix.json")))
    line = approval_text(pin)
    assert line in readme and DEMO_APPROVAL_LABEL in readme
    assert line in report


# ---------------------------------------------------------------------------
# NOTE 1: runtime.activate restarts only for the reviewed restart settings
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("pending,restarts", [
    ("", False),
    ("listen_addresses", True),
    ("listen_addresses,logging_collector", True),
])
def test_activate_restarts_for_reviewed_settings(monkeypatch, pending, restarts):
    target, calls = _fake_target(monkeypatch, pending)
    target.activate({"listen_addresses": "localhost"})
    assert ("restart" in calls) is restarts


@pytest.mark.parametrize("pending", ["shared_buffers", "listen_addresses,shared_buffers", "port"])
def test_activate_refuses_restart_for_other_settings(monkeypatch, pending):
    target, calls = _fake_target(monkeypatch, pending)
    with pytest.raises(ContractError, match="outside the reviewed restart allowlist"):
        target.activate({"listen_addresses": "localhost"})
    assert "restart" not in calls


def test_restart_allowlist_is_shared_with_provenance():
    from services.sandbox_poc import provenance
    assert provenance.RESTART_SETTINGS is RESTART_SETTINGS
    assert RESTART_SETTINGS == frozenset({"logging_collector", "listen_addresses"})


def _fake_target(monkeypatch, pending):
    target = DisposablePostgres(image="unused")
    calls = []

    def sql(script):
        if "pg_reload_conf" in script:
            return "t"
        if "pending_restart" in script:
            return pending
        raise AssertionError(f"unexpected SQL: {script}")
    monkeypatch.setattr(target, "sql", sql)
    monkeypatch.setattr(target, "restart", lambda: calls.append("restart"))
    monkeypatch.setattr(target, "_effective", lambda name, value: True)
    monkeypatch.setattr(runtime_module.time, "sleep", lambda seconds: None)
    return target, calls


# ---------------------------------------------------------------------------
# NOTE 2: syslog_ident value rule on every path
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("value", [FROM_PROFILE, "post gres", "pg/prod", "a" * 64, "pg:1", "x'y"])
def test_syslog_ident_odd_values_refused_everywhere(value):
    with pytest.raises(SettingValueError):
        check_setting_value("syslog_ident", value)
    with pytest.raises(ValidationError):
        SetConfigTemplateParams(param_name="syslog_ident", param_value=value)
    spec = spec_of(f"{B}:3.1.13")
    values = {spec["spec_id"]: {"expected": value, "fix": value, "break": "other"}}
    assert profile_value_errors(profile(values=values), [spec])


def test_syslog_ident_reviewed_value_accepted():
    assert SetConfigTemplateParams(param_name="syslog_ident", param_value="postgres").param_value == "postgres"
    spec = spec_of(f"{B}:3.1.13")
    values = {spec["spec_id"]: {"expected": "pg-prod_1", "fix": "pg-prod_1", "break": "postgres"}}
    approved = profile(values=values)
    assert profile_value_errors(approved, [spec]) == []
    assert fix_scope(_engine([spec], approved), spec["spec_id"])[1:] == ("syslog_ident", "pg-prod_1")


# ---------------------------------------------------------------------------
# NOTE 4: the seed's approved_by goes through the human-name rule too
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", ["HERMES", "dbguard agent", "LLM reviewer", "12345", "a\x07b", "x" * 121])
def test_parse_profile_refuses_non_human_approvers(name):
    doc = {"profile_id": "p", "benchmark": B, "approved_by": name, "approved_at": "2026-10-30", "values": {}}
    with pytest.raises(PolicyProfileError, match="approved_by"):
        parse_profile(yaml.safe_dump(doc).encode(), RECORDS)


def test_seed_with_non_human_approver_is_refused(tmp_path):
    doc = yaml.safe_load(default_profile_path(B).read_bytes())
    doc.update(approved_by="Claude", approved_at="2026-10-30")
    seed = tmp_path / "seed.yaml"
    seed.write_bytes(yaml.safe_dump(doc).encode())
    store = PolicyProfileStore(tmp_path / "profiles", RECORDS, SPECS, seed_path=seed)
    with pytest.raises(ProfileStoreError, match="named human"):
        store.list()
    doc.update(approved_by="Melvin Loo")
    seed.write_bytes(yaml.safe_dump(doc).encode())
    assert store.list()[0]["approved_by"] == "Melvin Loo"


# ---------------------------------------------------------------------------
# NOTE 5: policy-profile request limits
# ---------------------------------------------------------------------------

@pytest.fixture
def client(tmp_path, monkeypatch):
    from app.config import settings
    from services.sandbox_poc import router
    monkeypatch.setattr(settings, "policy_profile_storage_dir", str(tmp_path / "profiles"))
    app = FastAPI()
    app.include_router(router.router)
    with TestClient(app) as test_client:
        yield test_client


PROFILE_ROUTES = [f"/api/v1/benchmarks/{B}/policy-profiles/validate", f"/api/v1/benchmarks/{B}/policy-profiles",
                  f"/api/v1/benchmarks/{B}/policy-profiles/{'a' * 64}/approve"]


@pytest.mark.parametrize("path", PROFILE_ROUTES)
def test_oversize_body_is_refused_with_413(client, path, tmp_path):
    from services.sandbox_poc.router import MAX_PROFILE_BODY_BYTES
    body = json.dumps({"profile_id": "big", "values": {"x": "y" * MAX_PROFILE_BODY_BYTES}})
    response = client.post(path, content=body, headers={"content-type": "application/json"})
    assert response.status_code == 413, response.text

    def chunks():  # no content-length: the streamed size is capped too
        for _ in range(MAX_PROFILE_BODY_BYTES // 1024 + 2):
            yield b" " * 1024
    response = client.post(path, content=chunks(), headers={"content-type": "application/json"})
    assert response.status_code == 413, response.text
    assert not (tmp_path / "profiles" / B).exists()  # nothing was stored


def test_too_many_entries_are_refused_with_422(client, tmp_path):
    from services.sandbox_poc.router import MAX_PROFILE_ENTRIES, MAX_PROFILE_ROLES
    path = PROFILE_ROUTES[0]
    many = {f"{B}:x.{i}": "v" for i in range(MAX_PROFILE_ENTRIES + 1)}
    assert client.post(path, json={"profile_id": "p", "values": many}).status_code == 422
    assert client.post(path, json={"profile_id": "p", "fixes": many}).status_code == 422
    roles = {f"r{i}": 1 for i in range(MAX_PROFILE_ROLES + 1)}
    response = client.post(path, json={"profile_id": "p",
                                       "connection_limits": {"default_login_limit": None, "roles": roles}})
    assert response.status_code == 422 and "at most" in response.text
    ok = client.post(path, json={"profile_id": "p", "values": {}})
    assert ok.status_code == 200 and ok.json() == {"valid": True, "errors": []}
    created = client.post(PROFILE_ROUTES[1], json={"profile_id": "p", "values": {}})
    assert created.status_code == 201 and created.json()["approval_auth"] == LABEL


# ---------------------------------------------------------------------------
# NOTE 7: the 5.2 limit text covers host names
# ---------------------------------------------------------------------------

def test_listen_addresses_limit_covers_host_name_resolution():
    assert "For each listed host name, the DBA must confirm what it resolves to on the target host" \
        in LISTEN_ADDRESSES_SANDBOX_LIMIT
    assert planning.SANDBOX_LIMITS["listen_addresses"] == LISTEN_ADDRESSES_SANDBOX_LIMIT


# ---------------------------------------------------------------------------
# NOTE 8: the report pins an approved profile used only for a site fix
# ---------------------------------------------------------------------------

def test_report_pins_profile_used_for_site_fix_only():
    spec = listen_spec()  # automated spec, no expected_from: policy
    checks = {SPEC_ID: entry(spec, result="*")}
    report = run([spec], checks, _approved_site_profile())
    assert report["inputs"]["policy_profile"]["sha256"] == _approved_site_profile().sha256
    assert_labelled(report)
    # nothing used: no pin (unchanged behaviour)
    assert "policy_profile" not in run([spec], checks)["inputs"]
    assert "policy_profile" not in run([spec], checks, profile(approved=False, fixes={SPEC_ID: "localhost"}))["inputs"]
    assert "policy_profile" not in run([spec], checks, profile())["inputs"]
