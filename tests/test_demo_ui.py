"""Shared chat/UI flow, fixture isolation and lifecycle; no Docker or model calls."""
import copy
import threading
from dataclasses import replace
from unittest.mock import Mock

from fastapi.testclient import TestClient
import pytest

from app.collector_models import parse_snapshot
from services.sandbox_poc import upstream, router as routes
from services.sandbox_poc.collector_intake import from_collector_bundle
from services.sandbox_poc.demo import create_app
from services.sandbox_poc.handoff import SandboxHandoff, build_handoff
from services.sandbox_poc.shared import SpecEngine
from scripts.sandbox_poc import demo_template
from test_review_bundle import recorded, collector
from test_sandbox_poc import engine, snapshot, FakeRuntime


class Resources:
    def __init__(self, recorded, engine):
        self.closed = False
        self.registry_url = "unused"
        self.run_id = "unit-demo"
        self.lock = threading.Lock()
        self.collector_bundle = parse_snapshot(collector(recorded)).model_dump(mode='json')
        self.snapshot = from_collector_bundle(self.collector_bundle, engine)
        self.handoff = build_handoff(engine, self.snapshot, SandboxHandoff(**recorded['handoff']).template_ref)
        self.engine = engine

    def start(self):
        pass

    def close(self):
        self.closed = True

    def source_evidence(self):
        return {"source_unchanged": True, "registry_unchanged": True,
                "assessment": self.engine.assess(self.snapshot)}


def test_demo_is_same_origin_and_owns_lifecycle(recorded, engine):
    resources = Resources(recorded, engine)
    app = create_app(lambda: resources)
    with TestClient(app) as client:
        assert client.get("/").status_code == 200
        assert client.get("/demo/context").json()["fixture_approval"] is True
        assert client.get("/demo/source").json()["source_unchanged"] is True
        assert client.post("/api/v1/sandbox/runs", json={}, headers={"Origin": "https://external.example"}).status_code == 403
        assert client.get("/demo/context", headers={"Host": "external.example"}).status_code == 400
        resources.lock.acquire()
        try:
            assert client.get("/demo/source").status_code == 409
        finally:
            resources.lock.release()
        assert "/api/v1/sandbox/runs" in client.get("/openapi.json").json()["paths"]
        directory = app.state.store.storage_dir
    assert resources.closed and not directory.exists()


def test_partial_startup_still_cleans_up(recorded, engine):
    resources = Resources(recorded, engine)
    def fail():
        raise RuntimeError("fixture startup failed")
    resources.start = fail
    with pytest.raises(RuntimeError, match="fixture startup failed"):
        with TestClient(create_app(lambda: resources)):
            pass
    assert resources.closed


def test_chat_runs_same_snapshot_and_ui_receives_bundle(recorded, engine, monkeypatch):
    from services.dbguard_mcp import server
    resources = Resources(recorded, engine)
    app = create_app(lambda: resources, reviser=Mock())
    runtimes = []
    def factory():
        runtime = FakeRuntime(resources.snapshot, len(runtimes)+1)
        runtimes.append(runtime)
        return runtime
    template = replace(demo_template(), approved_by='DEMO_FIXTURE_ONLY', evidence=tuple(
        {**e.model_dump(), 'approved_by':'DEMO_FIXTURE_ONLY'} for e in resources.handoff.template_ref.evidence))
    monkeypatch.setattr(upstream, 'export_reference', Mock(return_value=(resources.handoff.template_ref, template)))
    monkeypatch.setattr(routes, 'handoffs', upstream.HandoffStore())
    monkeypatch.setattr(SpecEngine, 'collect', lambda _, runtime: copy.deepcopy(runtime.snapshot))
    with TestClient(app) as client:
        service = app.state.service
        service.registry_loader = Mock(return_value=template)
        service.runtime_factory = factory
        def request(method, url, **kwargs):
            kwargs.pop('timeout', None)
            return client.request(method, url.removeprefix(server.DBGUARD_API_URL), **kwargs)
        monkeypatch.setattr(server.requests, 'request', request)
        context = server.get_demo_workflow_context()
        assert context['demo_fixture_approval'] is True
        assert 'snapshot' not in context and 'registry_url' not in context
        sid = context['snapshot_id']
        assert server.get_snapshot_context(sid)['snapshot_id'] == sid
        assert server.get_snapshot_spec_assessment(sid)['assessment'] == resources.handoff.assessment
        prepared = server.prepare_sandbox_handoff(sid, context['template_version'],
            context['evidence_ids'], context['environment'])
        assert prepared['readiness']['status'] == 'READY_FOR_DEMO'
        assert prepared['readiness']['registry'] == 'FIXTURE_ONLY'
        result = server.run_sandbox_handoff(prepared['handoff_id'])
        assert result['status'] == 'VERIFIED' and result['demo_fixture_approval'] is True
        assert result['demo_evidence']['source_unchanged']
        assert result['demo_evidence']['source_control_status'] == 'FAIL'
        assert 'assessment' not in result['demo_evidence']
        assert result['sandbox_control']['after_status'] == 'PASS'
        assert result['sandbox_control']['before_status'] == 'FAIL'
        assert 'DEMO_FIXTURE_ONLY' in result['verification_report']
        ui = client.get('/review/context').json()
        assert ui['last_result']['run_id'] == result['run_id']
        assert ui['last_result']['review_bundle'] == result['review_bundle']
        assert ui['last_handoff']['snapshot'] == resources.snapshot
        assert client.get(result['review_bundle']['url']).status_code == 200
        assert server.get_demo_workflow_context()['bundle_url'].endswith(result['review_bundle']['url'])
        assert server.run_sandbox_handoff(prepared['handoff_id']) == result
        assert len(runtimes) == 1 and runtimes[0].closed
        service.reviser.assert_not_called()  # First attempt passes.
        wrong = resources.handoff.model_dump()
        wrong['snapshot']['envelope']['target_id'] = 'foreign-target'
        assert client.post('/api/v1/sandbox/runs', json=wrong).status_code == 422
        assert len(runtimes) == 1
