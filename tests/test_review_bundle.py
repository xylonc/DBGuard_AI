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
    # roles come from the shared fixture (real collector rows, bootstrap superuser oid 10).
    # An empty roles list is a collector contract violation and GAPs every role-based
    # catalog control, which blocks the loop, so it is no longer emptied here.
    assert any(r['oid'] == '10' for r in snapshot['baseline']['roles'])
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
        assert set(archive.namelist()) == {'harden.sh','runner.py','fix.json','manifest.json','evidence.json','report.html','README.txt','risk-review.json','visual_evidence.py','verify.sh'}
        manifest = json.loads(archive.read('manifest.json'))
        assert manifest['demo_fixture_approval'] is True
        assert b'NOT PERFORMED' in archive.read('report.html')
        assert b'<script>' not in archive.read('report.html')
        assert b'&lt;script&gt;' in archive.read('report.html')
        assert b'FAIL' in archive.read('report.html')
        assert json.loads(archive.read('fix.json'))['prior'] != json.loads(archive.read('fix.json'))['applied']



def test_report_has_no_catalog_rows_or_7_4_notice_by_default(recorded, engine):
    from app.services.spec_engine.catalog_checks import RESTORE_TEST_REMINDER
    from html import escape
    from services.sandbox_poc import shared
    assert shared.SANDBOX_COMPARES_CATALOG is False
    assert 'cis-pg17-v1.1.0:7.4' in {s['spec_id'] for s in engine.specs}
    data = build_review_bundle(SandboxHandoff(**recorded['handoff']), recorded['result'], engine)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        report = archive.read('report.html').decode('utf-8')
    catalog = [s['spec_id'] for s in engine.specs if s.get('check', {}).get('kind') == 'catalog']
    assert len(catalog) == 10
    assert report.count('<tr><td>cis-') == 29  # the 29 non-catalog specs
    for sid in catalog:
        assert f'<td>{sid}</td>' not in report
    # 7.4 is not shown in the sandbox report, so neither is its reminder.
    assert '<p class="notice">cis-' not in report
    assert escape(RESTORE_TEST_REMINDER) not in report and RESTORE_TEST_REMINDER not in report


def test_report_shows_the_fixed_7_4_restore_test_reminder_once_when_catalog_compared(engine, snapshot, monkeypatch):
    from html import escape
    from app.services.spec_engine.catalog_checks import RESTORE_TEST_REMINDER
    from services.sandbox_poc import shared
    from test_sandbox_guard_scope import recorded_run
    monkeypatch.setattr(shared, 'SANDBOX_COMPARES_CATALOG', True)
    handoff, result = recorded_run(engine, snapshot)
    data = build_review_bundle(handoff, result, engine)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        report = archive.read('report.html').decode('utf-8')
    escaped = escape(RESTORE_TEST_REMINDER)
    assert escaped != RESTORE_TEST_REMINDER  # the apostrophe in "PostgreSQL's" must be escaped
    assert report.count(escaped) == 1
    assert RESTORE_TEST_REMINDER not in report
    assert report.count(f'<p class="notice">cis-pg17-v1.1.0:7.4: {escaped}</p>') == 1
    # No other spec carries a notice paragraph.
    assert report.count('<p class="notice">cis-') == 1
    # It follows the findings table.
    assert report.index('</table>') < report.index(escaped)
    assert report.count('<tr><td>cis-') == 39  # all 39 specs


@pytest.mark.parametrize('fault', ['failed','cleanup','rollback','hash','apply','evidence','assessment','not_applicable','provenance'])
def test_rejects_unbound_or_unsafe_bundle(recorded, engine, fault):
    result = recorded['result']
    if fault == 'failed': result['status'] = 'FAILED'
    if fault == 'cleanup': result['attempts'][0]['cleanup']['verified'] = False
    if fault == 'rollback': result['attempts'][0]['rollback_verified'] = False
    if fault == 'hash': result['fix_unit_hash'] = '0'*64
    if fault == 'apply':
        result['fix_unit']['apply']['param'] = 'unsafe'
        result['fix_unit_hash'] = digest(result['fix_unit'])
    if fault == 'evidence': result['template']['evidence'][0]['sha256'] = '0'*64
    if fault == 'assessment':
        # Pin a finding that is non-PASS after the fix so the tamper is never a no-op.
        # (3.1.14 was used while it was needs_capability; it is automated and PASSes now.)
        # The run fixes 3.1.20 only, so 3.1.25 (log_statement 'none') still FAILs.
        findings = result['attempts'][0]['after_assessment']['findings']
        assert findings['cis-pg17-v1.1.0:3.1.25']['status'] == 'FAIL'
        findings['cis-pg17-v1.1.0:3.1.25']['status'] = 'PASS'
    if fault == 'not_applicable':
        # A NOT_APPLICABLE finding forged to PASS must be refused as well.
        findings = result['attempts'][0]['after_assessment']['findings']
        assert findings['cis-pg17-v1.1.0:3.1.11']['status'] == 'NOT_APPLICABLE'
        findings['cis-pg17-v1.1.0:3.1.11']['status'] = 'PASS'
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
    return copy.deepcopy(snapshot)


def test_existing_collector_bridge_preserves_findings(recorded, engine):
    bundle = collector(recorded)
    original = copy.deepcopy(bundle)
    snapshot = from_collector_bundle(bundle, engine)
    assert bundle == original
    assert engine.assess(snapshot)['findings'] == recorded['handoff']['assessment']['findings']
    assert snapshot == bundle  # Native evidence is preserved byte-for-byte as JSON values.


@pytest.mark.parametrize('fault', ['missing','sanitised','pg16','gap','duplicate','legacy'])
def test_collector_bridge_does_not_invent_evidence(recorded, engine, fault):
    bundle = collector(recorded)
    row = next(r for r in bundle['baseline']['settings'] if r['name']=='log_connections')
    if fault == 'legacy': bundle['envelope']['schema_version'] = '0.2.0'
    if fault == 'missing': bundle['baseline']['settings'].remove(row)
    if fault == 'sanitised': row['sanitised'] = True
    if fault == 'pg16': bundle['baseline']['identity']['server_version_num'] = 160000
    if fault == 'gap': bundle['baseline']['gaps'] = [{'section':'settings','reason':'missing'}]
    if fault == 'duplicate': bundle['baseline']['settings'].append(copy.deepcopy(row))
    with pytest.raises(ContractError):
        from_collector_bundle(bundle, engine)
