"""API boundary checks without Docker or a registry connection."""
import copy
import json
from unittest.mock import Mock

import psycopg2
import pytest
from fastapi.testclient import TestClient

from scripts.sandbox_poc import demo_template
from services.sandbox_poc.api import app
from services.sandbox_poc.handoff import SandboxHandoff, TemplateReference, build_handoff
from services.sandbox_poc.router import get_service, settings
from services.sandbox_poc.service import SandboxService
from services.sandbox_poc.shared import ContractError, ROOT, SpecEngine
from test_sandbox_poc import FakeRuntime, engine, snapshot  # shared fixtures

URL = "/api/v1/sandbox/runs"


@pytest.fixture
def handoff(engine, snapshot):
    template = demo_template()
    reference = TemplateReference(version=template.version, sha256=template.sha256,
        evidence=[{"document_id": "doc-1", "version": "1", "sha256": "a" * 64}])
    return build_handoff(engine, snapshot, reference).model_dump()


@pytest.fixture
def boundary(snapshot, monkeypatch):
    runtimes = []
    def factory():
        runtime = FakeRuntime(snapshot, len(runtimes) + 1)
        runtimes.append(runtime)
        return runtime
    loader = Mock(return_value=demo_template())
    service = SandboxService("unused-registry-url", registry_loader=loader, runtime_factory=factory)
    monkeypatch.setattr(SpecEngine, "collect", lambda self, runtime: copy.deepcopy(runtime.snapshot))
    app.dependency_overrides[get_service] = lambda: service
    try:
        with TestClient(app) as client:
            yield client, loader, runtimes
    finally:
        app.dependency_overrides.clear()


def test_api_runs_loop_and_returns_evidence(boundary, handoff):
    client, loader, runtimes = boundary
    response = client.post(URL, json=handoff)
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["status"] == "VERIFIED"
    assert result["approval_source"] == "registry"
    assert result["requires_dba_review"] is True
    assert result["attempts"][0]["rollback_verified"]
    assert runtimes[0].closed
    assert loader.call_args.kwargs["evidence_pins"] == handoff["template_ref"]["evidence"]


@pytest.mark.parametrize("fault", ["spec_hash", "assessment", "missing_check", "malformed_spec",
                                   "source", "benchmark", "unknown_field", "template_bool"])
def test_bad_handoff_stops_before_registry_or_container(boundary, handoff, fault):
    client, loader, runtimes = boundary
    if fault == "spec_hash":
        handoff["spec_set_hash"] = "0" * 64
    elif fault == "assessment":
        handoff["assessment"]["snapshot_hash"] = "0" * 64
    elif fault == "missing_check":
        handoff["snapshot"]["checks"].pop(next(iter(handoff["snapshot"]["checks"])))
    elif fault == "malformed_spec":
        handoff["specs"][0] = {"spec_id": 12}
    elif fault == "source":
        handoff["snapshot"]["baseline"]["settings"][0]["source"] = "command line"
    elif fault == "benchmark":
        handoff["benchmark_id"] = "../../private"
    elif fault == "unknown_field":
        handoff["rendered_sql"] = "SELECT 1"
    else:
        handoff["template_ref"]["version"] = True
    assert client.post(URL, json=handoff).status_code == 422
    loader.assert_not_called()
    assert not runtimes


def test_unapproved_template_never_starts_runtime(boundary, handoff):
    client, loader, runtimes = boundary
    loader.side_effect = ContractError("Exact approved template version/hash not found")
    assert client.post(URL, json=handoff).status_code == 422
    assert not runtimes


def test_registry_failure_is_reported_without_connection_details(boundary, handoff):
    client, loader, runtimes = boundary
    loader.side_effect = psycopg2.OperationalError("private-password-in-dsn")
    response = client.post(URL, json=handoff)
    assert response.status_code == 503
    assert "private-password" not in response.text
    assert not runtimes


def test_execution_failure_is_not_reported_as_verified(boundary, handoff):
    client, _, runtimes = boundary
    original = FakeRuntime.sql
    def fail_apply(self, sql):
        if "RESET" not in sql:
            raise RuntimeError("apply failed")
        return original(self, sql)
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(FakeRuntime, "sql", fail_apply)
        response = client.post(URL, json=handoff)
    assert response.status_code == 200
    assert response.json()["status"] == "FAILED"
    assert len(runtimes) == 3 and all(r.closed for r in runtimes)


def test_endpoint_is_disabled_until_local_operator_enables_it(handoff, monkeypatch):
    monkeypatch.setattr(settings, "sandbox_poc_enabled", False)
    with TestClient(app) as client:
        assert client.post(URL, json=handoff).status_code == 503


def test_existing_api_mounts_same_endpoint():
    from app.main import app as existing_app
    assert URL in existing_app.openapi()["paths"]


def test_openapi_describes_pinned_handoff():
    schema = app.openapi()["components"]["schemas"]
    assert "specs" in schema["SandboxHandoff"]["required"]
    assert "sha256" in schema["EvidenceReference"]["required"]


def test_exported_handoff_contract_matches_api():
    expected = SandboxHandoff.model_json_schema()
    expected["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    saved = json.loads((ROOT / "catalog/specs/contracts/sandbox-handoff-v1.json").read_text())
    assert saved == expected
