#!/usr/bin/env python3
"""Exercise live HERMES -> sandbox -> bundle on the launcher's disposable demo."""
import io
import json
from pathlib import Path
import time
import urllib.request
import zipfile
from demo import get, read_state, STATE


def main():
    state=read_state()
    if state.get('status') != 'ready': raise RuntimeError('Start python3 scripts/demo.py up first')
    url=state['url']
    context=get(url+'/bridge/demo/api/v1/demo/workflow')
    if context.get('mode') != 'live-disposable-demo': raise RuntimeError('Refusing non-demo verification')
    previous=context.get('latest_run_id')
    message=(f"Run a NEW disposable DBGuard sandbox test for log_connections on snapshot {context['snapshot_id']}, "
        f"benchmark {context['benchmark_id']}, environment {context['environment']}. "
        'Discover current demo references, use the exact-spec assessment, prepare a new handoff and call run_sandbox_handoff. '
        'Return the actual run ID and bundle link. Do not change the source. Disclose fixture-only approval.')
    job=get(url+'/bridge/chat', {'service':'demo','context':context,'messages':[{'role':'user','content':message}]})
    print('Live HERMES test running; no production target is involved.',flush=True)
    deadline=time.monotonic()+600
    while time.monotonic()<deadline:
        result=get(url+'/bridge/chat/'+job['id'])
        if result['status'] != 'running': break
        time.sleep(1)
    else: raise RuntimeError('Chat timeout: inspect the existing backend run before retrying')
    if result['status'] != 'complete': raise RuntimeError(result.get('error','Chat failed'))
    recorded=get(url+'/bridge/demo/review/context')['last_result']
    assert recorded and recorded['run_id'] != previous, 'No new backend run was recorded'
    assert recorded['run_id'] in result['response']['choices'][0]['message']['content'], 'Chat omitted the recorded run ID'
    assert recorded['status']=='VERIFIED', recorded['status']
    final=recorded['attempts'][-1]
    assert final['rollback_verified'] and final['health_after_apply'] and final['health_after_rollback']
    assert final['cleanup']['verified'] and not final['regressions']
    source=get(url+'/bridge/demo/demo/source')
    assert source['source_unchanged'] and source['registry_unchanged']
    with urllib.request.urlopen(url+'/bridge/demo/api/v1/sandbox/runs/'+recorded['run_id']+'/bundle',timeout=30) as response:
        bundle=response.read()
    with zipfile.ZipFile(io.BytesIO(bundle)) as archive:
        assert archive.testzip() is None
        assert {'harden.sh','report.html','evidence.json'} <= set(archive.namelist())
    proof={'run':recorded,'source':source,'chat':result,'bundle_bytes':len(bundle)}
    path=STATE/'verification.json';path.write_text(json.dumps(proof,indent=2));path.chmod(0o600)
    print('PASS: live chat, new run '+recorded['run_id']+', rollback, health, regression, cleanup, unchanged source, and ZIP integrity.',flush=True)

if __name__ == '__main__':
    main()
