"""Native Phase 1 evidence binding and CLI/API compatibility boundaries."""
import copy
import json
import subprocess
import sys

import pytest

from app.collector_models import SnapshotV030
from app.services.snapshot_service import SnapshotStore
from app.services.spec_engine.assess import assess
from app.services.spec_engine.manifest import build_manifest, manifest_text
from services.sandbox_poc.handoff import build_handoff, TemplateReference
from services.sandbox_poc.shared import ROOT, ContractError
from test_sandbox_poc import engine, snapshot
from test_sandbox_upstream import integration
from test_review_bundle import recorded, collector


def test_shared_engine_retains_authoritative_phase1_report(engine, snapshot):
    native = assess(engine.specs, snapshot, engine.records)
    calculated = engine.assess(snapshot)
    assert calculated['upstream_report'] == native
    assert native['summary'] == dict(PASS=3, FAIL=2, MANUAL=0, NEEDS_CAPABILITY=1,
                                     NOT_COLLECTED=0, STALE=0, ERROR=0)
    ref = TemplateReference(version=1, sha256='a'*64,
        evidence=[dict(document_id='test', version='1', sha256='b'*64)])
    request = build_handoff(engine, snapshot, ref, assessment=native)
    assert request.assessment == calculated
    assert engine.manifest_text == manifest_text(build_manifest(
        ROOT/'catalog/specs/cis-pg17-v1.1.0', engine.records))


@pytest.mark.parametrize('fault', ['collector', 'manifest', 'count', 'check_hash', 'query', 'result'])
def test_changed_evidence_cannot_reuse_report(engine, snapshot, fault):
    original = engine.assess(snapshot)['upstream_report']
    sid = next(iter(snapshot['checks']))
    if fault == 'collector': snapshot['envelope']['collector_sha256'] = '0'*64
    if fault == 'manifest': snapshot['envelope']['manifest']['sha256'] = '0'*64
    if fault == 'count': snapshot['envelope']['manifest']['check_count'] += 1
    if fault == 'check_hash': snapshot['checks'][sid]['spec_hash'] = '0'*64
    if fault == 'query': snapshot['checks'][sid]['query'] = 'SHOW ssl'
    if fault == 'result': snapshot['checks'][sid]['result'] = 'CHANGED'
    with pytest.raises(ContractError):
        engine.bind_assessment(snapshot, original)


def test_native_storage_preserves_wire_evidence_and_context(engine, snapshot, tmp_path):
    snapshot['envelope']['collected_at'] = '2026-09-25T03:10:00+00:00'
    store = SnapshotStore(tmp_path)
    receipt = store.save(SnapshotV030.model_validate(snapshot))
    assert store.load(receipt.snapshot_id).model_dump() == snapshot
    assert store.context(receipt.snapshot_id).settings['log_connections'] == 'off'


def test_native_report_api_is_bound_before_registry_or_container(integration, recorded):
    client, runtimes, service = integration
    sid = client.post('/api/v1/snapshots', json=collector(recorded)).json()['snapshot_id']
    legacy = client.get(f'/api/v1/snapshots/{sid}/assessment')
    assert legacy.status_code == 422 and 'spec-assessment' in legacy.text
    report = copy.deepcopy(recorded['handoff']['assessment']['upstream_report'])
    report['summary']['PASS'] = 999
    rejected = client.post('/api/v1/sandbox/handoffs', json={
        'snapshot_id': sid, 'template_version': 1, 'evidence_ids': ['test-doc'],
        'assessment': report})
    assert rejected.status_code == 422
    service.registry_loader.assert_not_called()
    assert not runtimes
    report = recorded['handoff']['assessment']['upstream_report']
    prepared = client.post('/api/v1/sandbox/handoffs', json={
        'snapshot_id': sid, 'template_version': 1, 'evidence_ids': ['test-doc'],
        'assessment': report})
    assert prepared.status_code == 201, prepared.text
    result = client.post('/api/v1/sandbox/handoffs/'+prepared.json()['handoff_id']+'/run')
    assert result.json()['status'] == 'VERIFIED'
    assert result.json()['review_bundle']['status'] == 'READY'


def test_assessment_cli_to_handoff_cli(engine, snapshot, tmp_path):
    snapshot_path, report_path = tmp_path/'snapshot.json', tmp_path/'assessment.json'
    ref_path, output = tmp_path/'reference.json', tmp_path/'handoff.json'
    snapshot_path.write_text(json.dumps(snapshot))
    ref_path.write_text(json.dumps(dict(version=1, sha256='a'*64,
        evidence=[dict(document_id='test', version='1', sha256='b'*64)])))
    common = ['--specs', str(ROOT/'catalog/specs/cis-pg17-v1.1.0'),
              '--records', str(ROOT/'catalog/benchmarks/cis-pg17-v1.1.0/records.json')]
    subprocess.run([sys.executable, str(ROOT/'scripts/assess.py'), *common,
                    '--snapshot', str(snapshot_path), '--out', str(report_path)], check=True)
    common[0] = '--spec-dir'
    subprocess.run([sys.executable, str(ROOT/'scripts/build_sandbox_handoff.py'), *common,
                    '--snapshot', str(snapshot_path), '--assessment', str(report_path),
                    '--template-ref', str(ref_path), '--output', str(output)], check=True)
    handoff = json.loads(output.read_text())
    assert handoff['assessment']['upstream_report'] == json.loads(report_path.read_text())


def test_native_report_readiness_and_review_ui(engine, snapshot):
    from fastapi.testclient import TestClient
    from services.sandbox_poc.readiness import check_readiness
    from services.sandbox_poc.review_api import create_app
    from services.sandbox_poc.service import SandboxService
    ref = TemplateReference(version=1, sha256='a'*64,
        evidence=[dict(document_id='test', version='1', sha256='b'*64)])
    request = build_handoff(engine, snapshot, ref)
    request.assessment = request.assessment['upstream_report']
    assert check_readiness(SandboxService('unused'), request)['status'] == 'INPUT_VALID'
    with TestClient(create_app(request)) as client:
        context = client.get('/review/context').json()
    assert context['handoff']['assessment']['upstream_report'] == request.assessment
    assert context['handoff']['assessment']['findings']


def test_auto_conf_alias_rejected_before_testing(engine, snapshot):
    from services.sandbox_poc.provenance import FILES, reconstruction_plan
    row = next(row for row in snapshot['baseline']['settings'] if row['name'] == 'log_connections')
    row['sourcefile'] = FILES[1]
    entry = next(row for row in snapshot['baseline']['file_settings'] if row['name'] == 'log_connections')
    entry.update(sourcefile=FILES[1], setting='false')
    with pytest.raises(ContractError, match='canonical'):
        reconstruction_plan(snapshot, engine.specs)
