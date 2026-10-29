"""Real collector script -> API bundle -> DBA runner, all on owned disposable DBs."""
from contextlib import contextmanager
import importlib.util
import io
import json
import os
import sys
import subprocess
from pathlib import Path
from unittest.mock import patch
import zipfile

from fastapi.testclient import TestClient
import psycopg2
import pytest

from services.sandbox_poc import runtime as runtime_module
from services.sandbox_poc.collector_intake import from_collector_bundle
from services.sandbox_poc.demo import DemoResources, create_app
from services.sandbox_poc.handoff import build_handoff
from services.sandbox_poc.runtime import DisposablePostgres, docker, LABEL
from services.sandbox_poc.shared import ROOT
from services.sandbox_poc.service import SandboxService
from services.sandbox_poc.readiness import check_readiness
from services.sandbox_poc.templates import export_reference

pytestmark = pytest.mark.skipif(os.environ.get('DBGUARD_POC_LIVE') != '1', reason='Requires disposable Docker databases')


@contextmanager
def published_target():
    target = DisposablePostgres()
    password = None
    def start_docker(*args, **kwargs):
        nonlocal password
        args = list(args)
        if args[0] == 'run' and target.name in args:
            password = next(x.split('=',1)[1] for x in args if x.startswith('POSTGRES_PASSWORD='))
            i = args.index('--network')
            args[i:i+2] = ['-p', '127.0.0.1::5432']
        return docker(*args, **kwargs)
    try:
        with patch.object(runtime_module, 'docker', start_docker):
            target.start()
        port = int(docker('port', target.name, '5432/tcp').rsplit(':',1)[1])
        dsn = psycopg2.extensions.make_dsn(host='127.0.0.1',port=port,user='dbguard_poc',password=password,dbname='dbguard_sandbox')
        yield target, dsn
    finally:
        target.close()


def test_real_collector_to_review_bundle_and_exported_runner(tmp_path):
    resources = DemoResources()
    with TestClient(create_app(lambda:resources)) as client:
        ref = resources.handoff.template_ref
        exported, _ = export_reference(resources.registry_url, ref.version,
            [entry.document_id for entry in ref.evidence], ref.environment)
        assert exported == ref
        preflight = check_readiness(SandboxService(resources.registry_url),
                                    resources.handoff, check_registry=True)
        assert preflight['registry'] == 'FIXTURE_ONLY'
        assert preflight['sandbox_execution'] == 'NOT_RUN'
        assert preflight['ready_for_sandbox'] is False
        target = resources.target
        folder = '/var/run/postgresql/collector'
        docker('exec',target.name,'mkdir','-p',folder)
        for name in ('dbguard-collect.sh','collect.sql'):
            docker('exec','-i',target.name,'sh','-c',f'cat > {folder}/{name}', stdin=(ROOT/'collector'/name).read_text())
        docker('exec','-i',target.name,'sh','-c',f'cat > {folder}/checks.json', stdin=resources.engine.manifest_text)
        docker('exec','-e','PGUSER=dbguard_poc','-e','PGDATABASE=dbguard_sandbox',
               '-e','TMPDIR=/var/run/postgresql',target.name,'bash',f'{folder}/dbguard-collect.sh',
               '-t',target.name,'-m',f'{folder}/checks.json','-o',f'{folder}/source.json')
        old_bundle = json.loads(docker('exec',target.name,'cat',f'{folder}/source.json'))
        converted = from_collector_bundle(old_bundle, resources.engine)
        # Use the real script's source evidence rather than the spec-collector startup evidence.
        resources.snapshot = converted
        # Use Xylon's actual assessment CLI output, not a fabricated sandbox report.
        source_path, report_path = tmp_path/'source.json', tmp_path/'assessment.json'
        source_path.write_text(json.dumps(converted))
        subprocess.run([sys.executable, str(ROOT/'scripts/assess.py'),
                        '--specs', str(ROOT/'catalog/specs/cis-pg17-v1.1.0'),
                        '--records', str(ROOT/'catalog/benchmarks/cis-pg17-v1.1.0/records.json'),
                        '--snapshot', str(source_path), '--out', str(report_path)], check=True)
        phase1_report = json.loads(report_path.read_text())
        handoff = build_handoff(resources.engine, converted, resources.handoff.template_ref,
                                assessment=phase1_report)
        # Direct API callers can supply the original upstream report too.
        handoff.assessment = phase1_report
        response = client.post('/api/v1/sandbox/runs',json=handoff.model_dump())
        assert response.status_code == 200, response.text
        result = response.json()
        assert result['status'] == 'VERIFIED', result
        assert result['review_bundle']['status'] == 'READY', result.get('review_bundle')
        archive_response = client.get(result['review_bundle']['url'])
        assert archive_response.status_code == 200
        with zipfile.ZipFile(io.BytesIO(archive_response.content)) as archive:
            archive.extractall(tmp_path)
        config = json.loads((tmp_path/'fix.json').read_text())
        spec = importlib.util.spec_from_file_location('exported_runner',tmp_path/'runner.py')
        runner = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(runner)
        with published_target() as (execution_target, dsn):
            execution_target.write_config('postgresql.conf',"\nlog_connections='on'\nlog_disconnections='on'\n")
            execution_target.sql("ALTER SYSTEM SET log_connections='off';")
            execution_target.activate({'log_connections':'off','log_disconnections':'on'})
            with pytest.raises(RuntimeError, match='Demo fixture'):
                runner.execute(config,'apply',dsn)
            with pytest.raises(RuntimeError, match='cluster identity'):
                runner.execute(config,'status',dsn,True)
            # The runner fixture is explicitly rebound to this independent disposable target.
            config['system_identifier'] = execution_target.sql('SELECT system_identifier::text FROM pg_control_system();')
            assert runner.execute(config,'status',dsn,True)['matches_prior']
            assert runner.execute(config,'apply',dsn,True)['verified']
            assert execution_target.sql('SHOW log_connections;') == 'on'
            with pytest.raises(RuntimeError, match='drift'):
                runner.execute(config,'apply',dsn,True)
            assert runner.execute(config,'rollback',dsn,True)['verified']
            assert execution_target.sql('SHOW log_connections;') == 'off'
            # Check artifact integrity via the actual launcher, before any connection.
            (tmp_path/'fix.json').write_text('{}')
            checked = subprocess.run(['sh',str(tmp_path/'harden.sh'),'status','fix-log_connections','--allow-demo'],
                                     env={**os.environ,'DBGUARD_DSN':dsn},capture_output=True,text=True)
            assert checked.returncode != 0
            assert 'Bundle content changed' in checked.stderr
        assert resources.source_evidence()['source_unchanged']
        assert resources.source_evidence()['registry_unchanged']
        for attempt in result['attempts']:
            assert not docker('ps','-aq','--filter',f"label={LABEL}={attempt['run_id']}")
        evidence_dir = os.environ.get('DBGUARD_TEST_EVIDENCE_DIR')
        if evidence_dir:
            output = Path(evidence_dir)
            output.mkdir(parents=True,exist_ok=True)
            (output/'review-bundle.zip').write_bytes(archive_response.content)
            (output/'collector-handoff.json').write_text(handoff.model_dump_json(indent=2))
    assert not docker('ps','-aq','--filter',f'label=dbguard.live-demo.run={resources.run_id}')


# Fixed SQL for the disposable SOURCE only (never the sandbox, never a real target):
# catalog objects the setting-only sandbox reconstruction will not have.
SOURCE_ONLY_CATALOG_SQL = """
CREATE ROLE dbguard_extra_login LOGIN CONNECTION LIMIT 3;
CREATE FUNCTION public.dbguard_extra_definer() RETURNS integer
    LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp
    AS 'SELECT 1';
"""


def _collect_with_real_script(resources):
    target = resources.target
    folder = '/var/run/postgresql/collector'
    docker('exec', target.name, 'mkdir', '-p', folder)
    for name in ('dbguard-collect.sh', 'collect.sql'):
        docker('exec', '-i', target.name, 'sh', '-c', f'cat > {folder}/{name}', stdin=(ROOT/'collector'/name).read_text())
    docker('exec', '-i', target.name, 'sh', '-c', f'cat > {folder}/checks.json', stdin=resources.engine.manifest_text)
    docker('exec', '-e', 'PGUSER=dbguard_poc', '-e', 'PGDATABASE=dbguard_sandbox',
           '-e', 'TMPDIR=/var/run/postgresql', target.name, 'bash', f'{folder}/dbguard-collect.sh',
           '-t', target.name, '-m', f'{folder}/checks.json', '-o', f'{folder}/source.json')
    return from_collector_bundle(json.loads(docker('exec', target.name, 'cat', f'{folder}/source.json')),
                                 resources.engine)


def _rows(assessment):
    return {r['spec_id']: r for r in assessment['upstream_report']['results']}


def test_source_only_catalog_objects_do_not_block_a_setting_fix(tmp_path):
    from services.sandbox_poc import shared
    assert shared.SANDBOX_COMPARES_CATALOG is False
    resources = DemoResources()
    with TestClient(create_app(lambda: resources)) as client:
        resources.target.sql(SOURCE_ONLY_CATALOG_SQL)
        converted = _collect_with_real_script(resources)
        resources.snapshot = converted
        source = resources.engine.assess(converted)
        rows = _rows(source)
        # The source assessment shows the extra role and function in the 4.x/5.5 evidence.
        assert {'rolname': 'dbguard_extra_login', 'rolsuper': False, 'rolvaliduntil': None,
                'password_type': 'none'} in rows['cis-pg17-v1.1.0:4.4']['evidence']
        definer = [e for e in rows['cis-pg17-v1.1.0:4.5']['evidence'] if e['name'] == 'dbguard_extra_definer']
        assert definer == [{'schema': 'public', 'name': 'dbguard_extra_definer', 'identity_args': '',
                            'owner': 'dbguard_poc', 'prosecdef': True, 'search_path': 'pg_catalog, pg_temp',
                            'config_names': ['search_path'], 'acl': definer[0]['acl'], 'extension': None}]
        assert '=X/dbguard_poc' in definer[0]['acl']  # default ACL: PUBLIC may EXECUTE
        assert rows['cis-pg17-v1.1.0:4.10']['result'] == 'MANUAL'  # the extra role has no password
        assert [e['rolname'] for e in rows['cis-pg17-v1.1.0:4.10']['evidence']] == ['dbguard_extra_login']
        assert any(e.get('rolname') == 'dbguard_extra_login' and e['rolconnlimit'] == 3
                   for e in rows['cis-pg17-v1.1.0:5.5']['evidence'])
        assert source['findings']['cis-pg17-v1.1.0:3.1.20']['status'] == 'FAIL'

        handoff = build_handoff(resources.engine, converted, resources.handoff.template_ref)
        response = client.post('/api/v1/sandbox/runs', json=handoff.model_dump())
        assert response.status_code == 200, response.text
        result = response.json()
        assert result['status'] == 'VERIFIED', result
        assert 'reproduction or rollback findings differ' not in json.dumps(result)
        assert result['review_bundle']['status'] == 'READY', result.get('review_bundle')
        archive_response = client.get(result['review_bundle']['url'])
        assert archive_response.status_code == 200
        with zipfile.ZipFile(io.BytesIO(archive_response.content)) as archive:
            report = archive.read('report.html').decode('utf-8')
        assert 'reproduction or rollback findings differ' not in report
        assert 'Sandbox status: VERIFIED' in report
        assert report.count('<tr><td>cis-') == 29  # the 29 non-catalog specs
        assert 'dbguard_extra' not in report

        # The difference was real: the sandbox reproduction has neither object.
        attempt = result['attempts'][-1]
        sandbox_rows = _rows(attempt['before_assessment'])
        assert 'dbguard_extra_login' not in json.dumps(sandbox_rows['cis-pg17-v1.1.0:4.4']['evidence'])
        assert 'dbguard_extra_definer' not in json.dumps(sandbox_rows['cis-pg17-v1.1.0:4.5']['evidence'])
        assert sandbox_rows['cis-pg17-v1.1.0:4.10']['result'] == 'PASS'
        assert attempt['before_assessment']['findings'] == source['findings']
        assert attempt['after_assessment']['findings']['cis-pg17-v1.1.0:3.1.20']['status'] == 'PASS'
        assert attempt['rollback_verified'] and attempt['cleanup']['verified']
        for attempt in result['attempts']:
            assert not docker('ps', '-aq', '--filter', f"label={LABEL}={attempt['run_id']}")
    assert not docker('ps', '-aq', '--filter', f'label=dbguard.live-demo.run={resources.run_id}')
    # Every container this test created (source target and each attempt) is gone. Checked by
    # this run's own labels: other sessions may run labelled containers concurrently.
    owned = [resources.target.run_id] + [a['run_id'] for a in result['attempts']]
    assert len(owned) == len(set(owned)) >= 2
    assert [run_id for run_id in owned if docker('ps', '-aq', '--filter', f'label={LABEL}={run_id}')] == []
