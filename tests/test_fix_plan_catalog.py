"""Router fix-plan lists catalog (F6) checks as "Not fixable automatically".

With the default SANDBOX_COMPARES_CATALOG=False, catalog specs are outside the
sandbox findings map; fix_plan appends every non-PASS catalog row from
upstream_report as a manual_review entry with kind "catalog". Unit level: real
SnapshotStore upload + TestClient, no Docker.
"""
import copy

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services.snapshot_service import SnapshotStore
from services.sandbox_poc import router as routes, shared
from services.sandbox_poc.service import SandboxService
from test_review_bundle import recorded, collector  # shared fixtures
from test_sandbox_poc import engine, snapshot

CATALOG = {f"cis-pg17-v1.1.0:{r}" for r in ("4.3", "4.4", "4.5", "4.6", "4.7", "4.9", "4.10", "5.5", "7.1", "7.4")}
STATUS = {"PASS": "PASS", "FAIL": "FAIL", "MANUAL": "MANUAL_REVIEW", "NOT_COLLECTED": "GAPPED"}


@pytest.fixture
def client(tmp_path, monkeypatch):
    store = SnapshotStore(tmp_path)
    monkeypatch.setattr("app.main.snapshot_store", store)
    app.dependency_overrides[routes.get_snapshot_store] = lambda: store
    app.dependency_overrides[routes.get_service] = lambda: SandboxService("unused")
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


def plan_for(client, bundle):
    uploaded = client.post("/api/v1/snapshots", json=bundle)
    assert uploaded.status_code == 201, uploaded.text
    sid = uploaded.json()["snapshot_id"]
    response = client.get(f"/api/v1/snapshots/{sid}/fix-plan")
    assert response.status_code == 200, response.text
    assessment = client.get(f"/api/v1/snapshots/{sid}/spec-assessment")
    assert assessment.status_code == 200, assessment.text
    return response.json(), assessment.json()["assessment"]


def catalog_rows(assessment):
    return {r["spec_id"]: r for r in assessment["upstream_report"]["results"] if r["spec_id"] in CATALOG}


def test_non_pass_catalog_rows_listed_once_with_kind_and_status(client, recorded):
    assert shared.SANDBOX_COMPARES_CATALOG is False
    plan, assessment = plan_for(client, collector(recorded))
    rows = catalog_rows(assessment)
    assert len(rows) == 10 and not CATALOG & set(assessment["findings"])
    expected = {sid: STATUS[r["result"]] for sid, r in rows.items() if r["result"] != "PASS"}
    # The fixture: 4.10 PASS; 5.5 and 7.4 FAIL; the rest MANUAL.
    assert expected == {**{f"cis-pg17-v1.1.0:{r}": "MANUAL_REVIEW" for r in ("4.3", "4.4", "4.5", "4.6", "4.7", "4.9", "7.1")},
                        "cis-pg17-v1.1.0:5.5": "FAIL", "cis-pg17-v1.1.0:7.4": "FAIL"}
    listed = [m for m in plan["manual_review"] if m["spec_id"] in CATALOG]
    assert sorted(m["spec_id"] for m in listed) == sorted(expected)  # once each
    for m in listed:
        assert m["kind"] == "catalog"
        assert m["status"] == expected[m["spec_id"]]
        assert m["title"] == rows[m["spec_id"]]["title"]
        assert m["tier"] == rows[m["spec_id"]]["tier"]
        assert m["reason"]
    # PASS catalog rows are absent, and no catalog check is ever offered as a fix.
    assert "cis-pg17-v1.1.0:4.10" not in {m["spec_id"] for m in plan["manual_review"]}
    assert plan["recommended_order"]  # the setting fixes are still offered
    assert not CATALOG & {f["spec_id"] for f in plan["recommended_order"]}
    # Non-catalog manual entries carry no catalog kind.
    assert all(m.get("kind") != "catalog" for m in plan["manual_review"] if m["spec_id"] not in CATALOG)


def test_gapped_catalog_row_maps_to_gapped(client, recorded):
    bundle = collector(recorded)
    bundle["baseline"]["archiving"] = None
    plan, assessment = plan_for(client, bundle)
    assert catalog_rows(assessment)["cis-pg17-v1.1.0:7.4"]["result"] == "NOT_COLLECTED"
    [entry] = [m for m in plan["manual_review"] if m["spec_id"] == "cis-pg17-v1.1.0:7.4"]
    assert entry["status"] == "GAPPED" and entry["kind"] == "catalog"


def test_switch_true_lists_catalog_rows_once_without_duplicates(client, recorded, monkeypatch):
    monkeypatch.setattr(shared, "SANDBOX_COMPARES_CATALOG", True)
    plan, assessment = plan_for(client, collector(recorded))
    assert CATALOG <= set(assessment["findings"])
    ids = [m["spec_id"] for m in plan["manual_review"]]
    assert len(ids) == len(set(ids))
    non_pass = {sid for sid in CATALOG if assessment["findings"][sid]["status"] != "PASS"}
    assert non_pass <= set(ids) and "cis-pg17-v1.1.0:4.10" not in ids
    for m in plan["manual_review"]:
        if m["spec_id"] in CATALOG:
            assert m["status"] == assessment["findings"][m["spec_id"]]["status"]
