import copy
import io
import json
import zipfile
import pytest
from fastapi.testclient import TestClient
from test_sandbox_poc import engine, snapshot
from test_review_bundle import recorded
from services.sandbox_poc.planning import risk_review, recommend_order, fix_scope
from services.sandbox_poc.shared import ContractError
from services.sandbox_poc import history


def test_llm_cannot_lower_risk_or_replace_checks(engine, snapshot):
    def reviewer(_):
        return {
            "risk": "low",
            "reasoning": "Low impact",
            "affected_components": ["logs"],
            "prerequisites": ["Check disk space"],
            "unknowns": ["Workload unknown"],
            "check_ids": [],
            "manual_application_checks": ["Test application login"],
        }

    result = risk_review(engine, snapshot, "cis-pg17-v1.1.0:3.1.20", reviewer)
    assert result["operational_risk"] == "medium"
    assert len(result["checks"]) == 3
    assert result["llm"]["status"] == "REVIEWED"
    result = risk_review(
        engine, snapshot, "cis-pg17-v1.1.0:3.1.20", lambda _: {"sql": "DROP DATABASE"}
    )
    assert result["llm"]["status"] == "UNAVAILABLE"


def test_dependencies_override_risk_and_conflicts_fail():
    high = {
        "fix_id": "a",
        "setting": "a",
        "operational_risk": "high",
        "dependencies": [],
    }
    low = {
        "fix_id": "b",
        "setting": "b",
        "operational_risk": "low",
        "dependencies": ["a"],
    }
    assert [f["fix_id"] for f in recommend_order([low, high])] == ["a", "b"]
    with pytest.raises(ContractError):
        recommend_order([low])
    with pytest.raises(ContractError):
        recommend_order([high, {**low, "setting": "a"}])


def test_log_statement_uses_reviewed_policy_not_arbitrary_expected(engine):
    _, name, value = fix_scope(engine, "cis-pg17-v1.1.0:3.1.25")
    assert (name, value) == ("log_statement", "ddl")


def test_history_distinguishes_statement_and_verification(
    recorded, engine, tmp_path, monkeypatch
):
    from services.sandbox_poc.handoff import SandboxHandoff

    monkeypatch.setenv("DBGUARD_HISTORY_DIR", str(tmp_path))
    old = recorded["handoff"]["snapshot"]
    old["baseline"]["identity"]["system_identifier"] = "12345"
    history.record(SandboxHandoff(**recorded["handoff"]), recorded["result"], b"zip")
    history.event("test-run", "DBA_REPORTS_APPLIED", {"operator": "test"})
    assert history.get("test-run")["events"][0]["kind"] == "DBA_REPORTS_APPLIED"
    with pytest.raises(ContractError, match="newer"):
        history.compare("test-run", old, engine)
    fresh = copy.deepcopy(old)
    fresh["envelope"]["collected_at"] = "2026-09-25T00:00:00Z"
    verdict = history.compare("test-run", fresh, engine)
    assert verdict["status"] == "TARGET_VERIFICATION_FAILED"
    fresh["baseline"]["identity"]["system_identifier"] = "another"
    with pytest.raises(ContractError, match="cluster"):
        history.compare("test-run", fresh, engine)
    assert history.bundle("test-run") == b"zip"


def test_import_reuses_exact_specs_unknowns_remain_explicit(tmp_path, monkeypatch):
    from openpyxl import Workbook
    from services.sandbox_poc.benchmarks import import_workbook, package
    from services.sandbox_poc.shared import ROOT

    monkeypatch.setenv("DBGUARD_CATALOG_DIR", str(tmp_path))
    records = json.loads(
        (ROOT / "catalog/benchmarks/cis-pg17-v1.1.0/records.json").read_text()
    )["records"]
    fields = {
        "Recommendation #": "recommendation",
        "Section #": "section",
        "Profile": "profile",
        "Title": "title",
        "Assessment Status": "assessment_status",
        "Description": "description",
        "Rationale Statement": "rationale",
        "Impact Statement": "impact",
        "Audit Procedure": "audit_procedure",
        "Remediation Procedure": "remediation_procedure",
        "Additional Information": "additional_information",
        "References": "references",
        "Default Value": "pg_default_value",
    }
    wb = Workbook()
    ws = wb.active
    ws.title = "Combined Profiles"
    ws.append(list(fields))
    for r in records[:12] + [r for r in records if r["recommendation"] == "3.1.20"]:
        ws.append([r.get(k) for k in fields.values()])
    buf = io.BytesIO()
    wb.save(buf)
    receipt = import_workbook(buf.getvalue())
    assert (
        receipt["controls"] == 13
        and receipt["automated"] >= 1
        and receipt["manual_or_capability"] >= 1
    )
    with zipfile.ZipFile(io.BytesIO(package(receipt["benchmark_id"]))) as z:
        assert "checks.json" in z.namelist() and "dbguard-collect.sh" in z.namelist()


def test_library_route_reports_failure_not_empty(monkeypatch):
    from app.main import app
    from app.services import library_catalog
    import psycopg2

    monkeypatch.setattr(
        library_catalog,
        "catalogue",
        lambda *a, **k: (_ for _ in ()).throw(psycopg2.OperationalError()),
    )
    with TestClient(app) as c:
        assert c.get("/api/v1/library/templates").status_code == 503
        assert c.get("/api/v1/library/anything").status_code == 422


def test_model_reload_downtime_claim_is_rejected(engine, snapshot):
    result = risk_review(
        engine,
        snapshot,
        "cis-pg17-v1.1.0:3.1.20",
        lambda _: {
            "risk": "medium",
            "reasoning": "The reload causes a brief outage.",
            "affected_components": [],
            "prerequisites": [],
            "unknowns": [],
            "check_ids": [],
            "manual_application_checks": [],
        },
    )
    assert result["llm"]["status"] == "UNAVAILABLE"
    assert "without restarting" in result["activation_fact"]


def test_named_alternatives_do_not_reactivate_archived_versions():
    from services.sandbox_poc.handoff import TemplateReference
    from pydantic import ValidationError

    evidence = [{"document_id": "test", "version": "1", "sha256": "a" * 64}]
    ref = TemplateReference(
        registry_name="set_config_parameter__alternative",
        version=1,
        sha256="b" * 64,
        evidence=evidence,
    )
    assert ref.registry_name.endswith("__alternative")
    with pytest.raises(ValidationError):
        TemplateReference(
            registry_name="arbitrary_sql", version=1, sha256="b" * 64, evidence=evidence
        )


def test_approved_template_risk_is_not_lowered(engine, snapshot):
    review = risk_review(
        engine, snapshot, "cis-pg17-v1.1.0:3.1.20", template_risk="high"
    )
    assert review["operational_risk"] == "high"


def test_combined_history_requires_every_target_to_pass(
    recorded, engine, tmp_path, monkeypatch
):
    from services.sandbox_poc.handoff import SandboxHandoff

    monkeypatch.setenv("DBGUARD_HISTORY_DIR", str(tmp_path))
    old = recorded["handoff"]["snapshot"]
    old["baseline"]["identity"]["system_identifier"] = "12345"
    result = recorded["result"]
    result.pop("fix_unit")
    result["fix_units"] = [
        {"spec_id": "cis-pg17-v1.1.0:3.1.20"},
        {"spec_id": "cis-pg17-v1.1.0:3.1.25"},
    ]
    history.record(SandboxHandoff(**recorded["handoff"]), result, b"combined-zip")
    fresh = copy.deepcopy(old)
    fresh["envelope"]["collected_at"] = "2026-09-25T00:00:00Z"
    fresh["checks"]["cis-pg17-v1.1.0:3.1.20"]["result"] = "on"
    fresh["checks"]["cis-pg17-v1.1.0:3.1.25"]["result"] = "none"
    assert (
        history.compare("test-run", fresh, engine)["status"]
        == "TARGET_VERIFICATION_FAILED"
    )
    fresh["checks"]["cis-pg17-v1.1.0:3.1.25"]["result"] = "ddl"
    assert (
        history.compare("test-run", fresh, engine)["status"]
        == "TARGET_REASSESSMENT_CONFIRMED"
    )
    assert history.bundle("test-run") == b"combined-zip"
