from dataclasses import replace
from unittest.mock import Mock
import copy

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.services.snapshot_service import SnapshotStore
from scripts.sandbox_poc import demo_template
from services.sandbox_poc import router as routes, upstream
from services.sandbox_poc.handoff import SandboxHandoff
from services.sandbox_poc.service import SandboxService
from services.sandbox_poc.shared import SpecEngine
from test_review_bundle import recorded, collector
from test_sandbox_poc import engine, snapshot, FakeRuntime


@pytest.fixture
def integration(recorded, tmp_path, monkeypatch):
    store = SnapshotStore(tmp_path)
    request = SandboxHandoff(**recorded['handoff'])
    ref = request.template_ref
    approved = replace(demo_template(), approved_by='unit-reviewer', evidence=tuple(
        {**e.model_dump(), 'approved_by':'unit-reviewer'} for e in ref.evidence))
    runtimes = []
    def factory():
        r = FakeRuntime(request.snapshot, len(runtimes)+1); runtimes.append(r); return r
    monkeypatch.setattr(SpecEngine, 'collect', lambda _, r: copy.deepcopy(r.snapshot))
    monkeypatch.setattr(upstream, 'export_reference', Mock(return_value=(ref, approved)))
    monkeypatch.setattr(routes, 'handoffs', upstream.HandoffStore())
    service = SandboxService('unused', registry_loader=Mock(return_value=approved),
                             runtime_factory=factory, reviser=Mock())
    # Both existing upload and the new bridge use the same real SnapshotStore.
    monkeypatch.setattr('app.main.snapshot_store', store)
    app.dependency_overrides[routes.get_snapshot_store] = lambda: store
    app.dependency_overrides[routes.get_service] = lambda: service
    with TestClient(app) as client:
        yield client, runtimes, service
    app.dependency_overrides.clear()


def test_existing_upload_to_preparation_run_and_cached_result(integration, recorded):
    client, runtimes, _ = integration
    uploaded = client.post('/api/v1/snapshots', json=collector(recorded))
    assert uploaded.status_code == 201, uploaded.text
    sid = uploaded.json()['snapshot_id']
    assessment = client.get(f'/api/v1/snapshots/{sid}/spec-assessment')
    assert assessment.status_code == 200, assessment.text
    assert assessment.json()['assessment']['findings'] == recorded['handoff']['assessment']['findings']
    prepared = client.post('/api/v1/sandbox/handoffs', json={
        'snapshot_id':sid, 'template_version':1, 'evidence_ids':['test-doc']})
    assert prepared.status_code == 201, prepared.text
    hid = prepared.json()['handoff_id']
    tested = client.post(f'/api/v1/sandbox/handoffs/{hid}/run')
    assert tested.status_code == 200, tested.text
    assert tested.json()['status'] == 'VERIFIED'
    again = client.post(f'/api/v1/sandbox/handoffs/{hid}/run')
    assert again.json() == tested.json() and len(runtimes) == 1
    assert tested.json()['review_bundle']['status'] == 'READY'
    assert client.get(tested.json()['review_bundle']['url']).status_code == 200
    assert client.get(f'/api/v1/sandbox/handoffs/{hid}').json()['status'] == 'FINISHED'


def test_unknown_snapshot_and_unsupported_pg_version_rejected(integration, recorded):
    client, runtimes, _ = integration
    assert client.get('/api/v1/snapshots/snap-unknown/spec-assessment').status_code == 404
    bundle = collector(recorded); bundle['baseline']['identity']['server_version_num'] = 160000
    sid = client.post('/api/v1/snapshots', json=bundle).json()['snapshot_id']
    result = client.post('/api/v1/sandbox/handoffs', json={
        'snapshot_id':sid, 'template_version':1, 'evidence_ids':['test-doc']})
    assert result.status_code == 422 and not runtimes


def test_no_double_execution_or_eviction_of_running_handle(recorded):
    store = upstream.HandoffStore(limit=1)
    request = SandboxHandoff(**recorded['handoff'])
    hid = store.put(request, 'snap-unit')
    assert store.begin(hid) is not None
    assert store.begin(hid) is None
    with pytest.raises(ValueError, match='running'):
        store.put(request, 'snap-unit')
    store.fail(hid)
    assert store.get(hid)['status'] == 'REJECTED'


def test_hermes_mcp_tools_call_existing_api_flow(integration, recorded, monkeypatch):
    from services.dbguard_mcp import server
    client, runtimes, _ = integration
    # Exercise the real tool functions and HTTP paths; no external model involved.
    def request(method, url, **kwargs):
        kwargs.pop('timeout', None)
        return client.request(method, url.removeprefix(server.DBGUARD_API_URL), **kwargs)
    monkeypatch.setattr(server.requests, 'request', request)
    sid = client.post('/api/v1/snapshots', json=collector(recorded)).json()['snapshot_id']
    assert server.get_snapshot_spec_assessment(sid)['assessment']['findings']
    prepared = server.prepare_sandbox_handoff(sid, 1, ['test-doc'], 'dev')
    result = server.run_sandbox_handoff(prepared['handoff_id'])
    assert result['status'] == 'VERIFIED'
    assert server.get_sandbox_handoff_status(prepared['handoff_id'])['status'] == 'FINISHED'
    assert len(runtimes) == 1


def test_missing_after_measurement_is_unknown_not_success(recorded):
    result = copy.deepcopy(recorded['result'])
    result['status'] = 'FAILED'
    result['attempts'][-1].pop('after_assessment')
    summary = upstream.result_summary(result)
    assert summary['sandbox_control']['after_status'] == 'UNKNOWN'
    assert summary['sandbox_after_findings'] == {}
    assert 'Overall sandbox test status: FAILED' in summary['verification_report']
