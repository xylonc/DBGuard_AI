"""Exercise the actual one-command collector demo and verify its evidence."""
import json
import os
import zipfile

import pytest

from services.sandbox_poc.collector_demo import run_collector_demo
from services.sandbox_poc.runtime import docker, LABEL

pytestmark = pytest.mark.skipif(os.environ.get('DBGUARD_POC_LIVE') != '1', reason='Requires disposable Docker databases')


def test_collector_demo_exports_after_all_resources_are_removed(tmp_path):
    output = tmp_path/'collector-run'
    result = run_collector_demo(output)
    assert result['status'] == 'VERIFIED', result
    assert result['fixture_cleanup_verified']
    assert result['source_unchanged'] and result['registry_unchanged']
    assert result['approval'] == 'DEMO_FIXTURE_ONLY' and result['model'] == 'NOT_USED'
    snapshot = json.loads((output/'collector-snapshot.json').read_text())
    assert int(snapshot['baseline']['identity']['server_version_num']) // 10000 == 17
    assert snapshot['envelope']['schema_version'] == '0.3.0'
    with zipfile.ZipFile(output/'review-bundle.zip') as archive:
        assert json.loads(archive.read('manifest.json'))['demo_fixture_approval']
        assert archive.read('report.html') == (output/'report.html').read_bytes()
    evidence = json.loads((output/'sandbox-result.json').read_text())
    assert all(a['rollback_verified'] and a['cleanup']['verified'] for a in evidence['attempts'])
    for attempt in evidence['attempts']:
        assert not docker('ps','-aq','--filter', f"label={LABEL}={attempt['run_id']}")
    assert not docker('ps','-aq','--filter', f"label=dbguard.live-demo.run={result['session_id']}")
    source_name = snapshot['envelope']['target_id']
    assert not docker('ps','-aq','--filter', f'name=^/{source_name}$')
