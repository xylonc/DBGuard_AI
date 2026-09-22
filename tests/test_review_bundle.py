import copy
import io
import json
from pathlib import Path
import zipfile

import pytest

from services.sandbox_poc.collector_intake import from_collector_bundle
from services.sandbox_poc.handoff import SandboxHandoff, TemplateReference, build_handoff
from services.sandbox_poc.review_bundle import build_review_bundle, BundleStore
from services.sandbox_poc.shared import ContractError, digest
from test_sandbox_poc import engine, snapshot, run_fake


@pytest.fixture
def recorded(engine, snapshot):
    snapshot['envelope'].update(collector_version='unit-fixture', collected_at='2026-09-22T00:00:00Z',
        collected_by='unit-fixture', is_superuser=True, target_id='<script>alert(1)</script>')
    snapshot['baseline']['roles'] = []
    for row in snapshot['baseline']['settings']:
        row.update(vartype='bool' if row['setting'] in ('on','off') else 'enum', unit=None, sanitised=False)
    result, _ = run_fake(engine, snapshot, [None])
    result.update(approval_source='registry', run_id='test-run')
    result['template']['approved_by'] = 'INTEGRATION_TEST_ONLY'
    result['template']['evidence'] = [dict(document_id='test-doc', version='1', sha256='a'*64, approved_by='INTEGRATION_TEST_ONLY')]
    ref = TemplateReference(version=result['template']['version'], sha256=result['template']['sha256'],
        evidence=[dict(document_id='test-doc', version='1', sha256='a'*64)])
    handoff = build_handoff(engine, snapshot, ref)
    return {'handoff':handoff.model_dump(), 'result':result}


def test_bundle_is_bound_and_escapes_report(recorded, engine):
    request = SandboxHandoff(**recorded['handoff'])
    data = build_review_bundle(request, recorded['result'], engine)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        assert set(archive.namelist()) == {'harden.sh','runner.py','fix.json','manifest.json','evidence.json','report.html','README.txt'}
        manifest = json.loads(archive.read('manifest.json'))
        assert manifest['demo_fixture_approval'] is True
        assert b'NOT PERFORMED' in archive.read('report.html')
        assert b'<script>' not in archive.read('report.html')
        assert b'&lt;script&gt;' in archive.read('report.html')
        assert b'FAIL' in archive.read('report.html')
        assert json.loads(archive.read('fix.json'))['prior'] != json.loads(archive.read('fix.json'))['applied']


@pytest.mark.parametrize('fault', ['failed','cleanup','rollback','hash','apply','evidence','assessment','provenance'])
def test_rejects_unbound_or_unsafe_bundle(recorded, engine, fault):
    result = recorded['result']
    if fault == 'failed': result['status'] = 'FAILED'
    if fault == 'cleanup': result['attempts'][0]['cleanup']['verified'] = False
    if fault == 'rollback': result['attempts'][0]['rollback_verified'] = False
    if fault == 'hash': result['fix_unit_hash'] = '0'*64
    if fault == 'apply':
        result['fix_unit']['apply'] += '\nDROP TABLE unsafe;'
        result['fix_unit_hash'] = digest(result['fix_unit'])
    if fault == 'evidence': result['template']['evidence'][0]['sha256'] = '0'*64
    if fault == 'assessment': result['attempts'][0]['after_assessment']['findings'][next(iter(engine.hashes))]['status'] = 'PASS'
    if fault == 'provenance': result['attempts'][0]['rollback']['baseline']['file_settings'] = []
    with pytest.raises(ContractError):
        build_review_bundle(SandboxHandoff(**recorded['handoff']), result, engine)


def test_store_expires_old_downloads():
    store = BundleStore(1)
    store.put('first', b'one')
    store.put('second', b'two')
    assert store.get('first') is None
    assert store.get('second') == b'two'


def collector(recorded):
    snapshot = recorded['handoff']['snapshot']
    return dict(copy.deepcopy(snapshot['baseline']), envelope=snapshot['envelope'])


def test_existing_collector_bridge_preserves_findings(recorded, engine):
    bundle = collector(recorded)
    original = copy.deepcopy(bundle)
    snapshot = from_collector_bundle(bundle, engine)
    assert bundle == original
    assert engine.assess(snapshot)['findings'] == recorded['handoff']['assessment']['findings']
    assert snapshot['baseline']['dbguard_intake']['source_bundle_hash'] == digest(bundle)


@pytest.mark.parametrize('fault', ['unit','missing','sanitised','pg16','gap','duplicate'])
def test_collector_bridge_does_not_invent_evidence(recorded, engine, fault):
    bundle = collector(recorded)
    row = next(r for r in bundle['settings'] if r['name']=='log_connections')
    if fault == 'unit': row['unit'] = 'ms'
    if fault == 'missing': bundle['settings'].remove(row)
    if fault == 'sanitised': row['sanitised'] = True
    if fault == 'pg16': bundle['identity']['server_version_num'] = 160000
    if fault == 'gap': bundle['gaps'] = [{'section':'settings','reason':'missing'}]
    if fault == 'duplicate': bundle['settings'].append(copy.deepcopy(row))
    with pytest.raises(ContractError):
        from_collector_bundle(bundle, engine)
