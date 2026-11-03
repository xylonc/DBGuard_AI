"""Wave 2a live: per-object fixes rehearsed on real disposable PostgreSQL 17 sandboxes.

Objects are planted on the DemoResources SOURCE (never a sandbox, never a real
target) and collected with the real collector script. Each rehearsal then runs
the real ObjectRemediationLoop: fresh sandbox -> settings reconstruction ->
stand-in copy -> reproduce -> apply (one transaction) -> verify -> rollback (one
transaction) -> cleanup, checked by this test's own run IDs.

Templates are the bundled template files pinned by hash in memory with a
LIVE_TEST_FIXTURE approval (no registry row is written or approved); the 5.5
connection limit comes from an in-memory test profile (no profile store write).
"""
import copy
import hashlib
import importlib.util
import io
import json
import os
import re
import secrets
import zipfile

import pytest
import yaml
from fastapi.testclient import TestClient

from app.services.spec_engine import RecordsIndex
from app.services.spec_engine.policy import parse_profile
from services.sandbox_poc import object_fixes
from services.sandbox_poc.demo import DemoResources, create_app
from services.sandbox_poc.handoff import SandboxHandoff, TemplateReference, build_handoff
from services.sandbox_poc.runtime import LABEL, DisposablePostgres, docker
from services.sandbox_poc.shared import ROOT, SpecEngine
from services.sandbox_poc.templates import ApprovedTemplate
from services.sandbox_poc.workflow import ObjectRemediationLoop
from tests.test_review_bundle_live import _collect_with_real_script, published_target

pytestmark = pytest.mark.skipif(os.environ.get('DBGUARD_POC_LIVE') != '1',
                                reason='Requires disposable Docker databases')

B = 'cis-pg17-v1.1.0'
ODD = 'w2a "q";--rôle'  # a quote, a semicolon, a comment marker and non-ASCII


def odd_ident():
    return '"' + ODD.replace('"', '""') + '"'


# Fixed SQL for the disposable SOURCE only. The password is random per run and
# only exists so the source role has password_type scram-sha-256.
def source_sql(password):
    return f"""
CREATE ROLE w2a_admin LOGIN SUPERUSER CREATEDB PASSWORD '{password}';
CREATE ROLE w2a_web LOGIN CONNECTION LIMIT -1;
CREATE ROLE w2a_owner NOLOGIN;
CREATE ROLE w2a_app LOGIN;
CREATE ROLE {odd_ident()} LOGIN CREATEDB;
CREATE SCHEMA w2a_sales AUTHORIZATION w2a_owner;
CREATE TABLE w2a_sales.orders (id integer, note text);
ALTER TABLE w2a_sales.orders OWNER TO w2a_owner;
GRANT SELECT, INSERT, UPDATE, DELETE ON w2a_sales.orders TO w2a_app;
CREATE FUNCTION public.w2a_definer(a integer, b text) RETURNS integer
    LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp AS 'SELECT 1';
ALTER FUNCTION public.w2a_definer(integer, text) OWNER TO w2a_owner;
"""


def fixture_template(name):
    sql = (ROOT / f'backend/app/templates/{name}.sql.j2').read_text()
    return ApprovedTemplate(name, 1, sql, hashlib.sha256(sql.encode()).hexdigest(), 'LIVE_TEST_FIXTURE',
                            ({'document_id': 'live-doc', 'version': '1', 'sha256': 'b' * 64,
                              'approved_by': 'LIVE_TEST_FIXTURE'},), 'high')


def profile_engine():
    records = RecordsIndex.load(ROOT / f'catalog/benchmarks/{B}/records.json')
    doc = {'profile_id': 'live-object-fixes', 'benchmark': B, 'approved_by': 'Test Reviewer',
           'approved_at': '2026-10-30', 'values': {},
           'connection_limits': {'default_login_limit': None, 'roles': {'w2a_web': 15}}}
    return SpecEngine.load(ROOT / f'catalog/specs/{B}', ROOT / f'catalog/benchmarks/{B}/records.json',
                           parse_profile(yaml.safe_dump(doc).encode(), records))


@pytest.fixture(scope='module')
def source():
    """Planted source, real collector snapshot, the engine and offered proposals."""
    resources = DemoResources()
    with TestClient(create_app(lambda: resources)):
        resources.target.sql(source_sql(secrets.token_urlsafe(24)))
        snapshot = _collect_with_real_script(resources)
        engine = profile_engine()
        offered = object_fixes.proposals(engine, snapshot, engine.policy_pin)
        yield {'resources': resources, 'snapshot': snapshot, 'engine': engine, 'offered': offered}
    assert not docker('ps', '-aq', '--filter', f'label=dbguard.live-demo.run={resources.run_id}')
    assert not docker('ps', '-aq', '--filter', f'label={LABEL}={resources.target.run_id}')


def pick(source, fix_type, **target):
    found = [p for p in source['offered'] if p['fix_type'] == fix_type
             and all(p['target'].get(k) == v for k, v in target.items())]
    assert found, (fix_type, target, [p['fix_id'] for p in source['offered']])
    return found[0]


def find_row(snapshot, proposal):
    t = proposal['target']
    b = snapshot['baseline']
    if proposal['fix_type'].startswith('role_'):
        return next(r for r in b['roles'] if r['rolname'] == t['role'])
    if proposal['fix_type'].startswith('function_'):
        return next(r for r in b['functions'] if (r['schema'], r['name'], r['identity_args'])
                    == (t['schema'], t['name'], t['identity_args']))
    return next(r for r in b['object_acls'] if (r['schema'], r['name']) == (t['schema'], t['table']))


def no_oid(row):
    return {k: v for k, v in row.items() if k != 'oid'}


def rehearse(source, proposal):
    engine, snapshot = source['engine'], source['snapshot']
    assert proposal['rehearsable'], proposal.get('not_rehearsable_reason')
    result = ObjectRemediationLoop(engine, fixture_template(proposal['fix_type']), proposal).run(
        snapshot, engine.assess(snapshot))
    attempt = result['attempts'][-1]
    assert result['status'] == 'VERIFIED', attempt.get('error')
    # Reproduce: the stand-in equals the source object; the problem exists.
    assert object_fixes.object_signature(proposal, attempt['before']) == object_fixes.object_signature(proposal, snapshot)
    assert object_fixes.prior_holds(proposal, attempt['before'])
    assert not object_fixes.predicate(proposal, attempt['before'])
    # Verify: the predicate holds; nothing else recreated changed; settings unchanged.
    assert object_fixes.predicate(proposal, attempt['after'])
    assert attempt['other_objects_changed'] == [] and attempt['regressions'] == []
    assert attempt['functional_checks']['passed'] and attempt['health_after_apply']
    # Rollback: exact.
    assert attempt['rollback_verified'] and not object_fixes.predicate(proposal, attempt['rollback'])
    assert object_fixes.object_signature(proposal, attempt['rollback']) == object_fixes.object_signature(proposal, snapshot)
    # Cleanup by this run's own IDs.
    print('RUN_IDS', proposal['fix_id'], [each['run_id'] for each in result['attempts']])
    for each in result['attempts']:
        assert each['cleanup']['verified'] is True
        assert not docker('ps', '-aq', '--filter', f"label={LABEL}={each['run_id']}")
    return result, attempt


def test_role_connection_limit(source):
    proposal = pick(source, 'role_connection_limit', role='w2a_web')
    assert proposal['params']['connection_limit'] == 15
    result, attempt = rehearse(source, proposal)
    assert find_row(attempt['after'], proposal)['rolconnlimit'] == 15
    assert find_row(attempt['rollback'], proposal)['rolconnlimit'] == -1
    assert result['skeleton']['exact_roles'] == ['w2a_web']
    assert result['skeleton']['throwaway_password_roles'] == []  # the source role has no password


@pytest.mark.parametrize('attribute', ['SUPERUSER', 'CREATEDB'])
def test_role_drop_attribute(source, attribute):
    proposal = pick(source, 'role_drop_attribute', role='w2a_admin', attribute=attribute)
    result, attempt = rehearse(source, proposal)
    column = object_fixes.ATTRIBUTE_COLUMNS[attribute]
    assert find_row(attempt['after'], proposal)[column] is False
    assert no_oid(find_row(attempt['before'], proposal)) == no_oid(find_row(source['snapshot'], proposal))
    # The stand-in had a throwaway password (source type scram), never shown anywhere.
    assert result['skeleton']['throwaway_password_roles'] == ['w2a_admin']
    types = {r['rolname']: r['password_type'] for r in attempt['before']['baseline']['password_types']}
    assert types['w2a_admin'] == 'scram-sha-256'
    text = json.dumps(result)
    assert not re.search(r"PASSWORD\s+'", text, re.I)  # no password statement or secret literal anywhere
    assert not any('PASSWORD' in s for s in result['skeleton']['statements'])


def test_role_drop_attribute_on_a_hostile_name(source):
    proposal = pick(source, 'role_drop_attribute', role=ODD, attribute='CREATEDB')
    result, attempt = rehearse(source, proposal)
    assert find_row(attempt['after'], proposal)['rolcreatedb'] is False
    assert result['skeleton']['exact_roles'] == [ODD]


def test_role_nologin(source):
    proposal = pick(source, 'role_nologin', role='w2a_web')
    result, attempt = rehearse(source, proposal)
    assert find_row(attempt['after'], proposal)['rolcanlogin'] is False
    assert find_row(attempt['rollback'], proposal)['rolcanlogin'] is True


def test_function_security_invoker(source):
    proposal = pick(source, 'function_security_invoker', name='w2a_definer')
    result, attempt = rehearse(source, proposal)
    stub = find_row(attempt['before'], proposal)
    original = find_row(source['snapshot'], proposal)
    # The stub has the same identity, owner, SECURITY DEFINER, search_path and ACL.
    for key in ('identity_args', 'owner', 'prosecdef', 'search_path', 'config_names', 'kind'):
        assert stub[key] == original[key], key
    assert sorted(stub['acl']) == sorted(original['acl'])
    assert find_row(attempt['after'], proposal)['prosecdef'] is False
    assert result['skeleton']['dependency_roles'] == ['w2a_owner']


def test_function_revoke_public_execute(source):
    proposal = pick(source, 'function_revoke_public_execute', name='w2a_definer')
    _, attempt = rehearse(source, proposal)
    assert not any(a.startswith('=') for a in find_row(attempt['after'], proposal)['acl'])


def test_table_revoke_dml(source):
    proposal = pick(source, 'table_revoke_dml', table='orders', grantee='w2a_app')
    assert proposal['target']['privileges'] == ['INSERT', 'UPDATE', 'DELETE']
    result, attempt = rehearse(source, proposal)
    original = find_row(source['snapshot'], proposal)
    stub = find_row(attempt['before'], proposal)
    assert stub['owner'] == original['owner'] and stub['acl'] == original['acl']
    after = find_row(attempt['after'], proposal)
    assert 'w2a_app=r/w2a_owner' in after['acl']
    assert sorted(result['skeleton']['schemas']) == ['w2a_sales']


def test_combined_batch_of_three_object_fixes(source, monkeypatch, tmp_path):
    from services.sandbox_poc import batch, profiles
    from services.sandbox_poc.service import SandboxService
    engine, snapshot, resources = source['engine'], source['snapshot'], source['resources']
    chosen = [pick(source, 'role_connection_limit', role='w2a_web'),
              pick(source, 'role_drop_attribute', role='w2a_admin', attribute='CREATEDB'),
              pick(source, 'table_revoke_dml', table='orders', grantee='w2a_app')]
    templates = {p['fix_type']: fixture_template(p['fix_type']) for p in chosen}
    monkeypatch.setattr(profiles, 'resolve_profile', lambda records, specs, ref: engine.policy)
    created = []

    def factory():
        created.append(DisposablePostgres())
        return created[-1]
    service = SandboxService('unused', runtime_factory=factory,
                             registry_loader=lambda url, version, sha, docs, env, **kw: templates[kw['registry_name']])
    base = build_handoff(engine, snapshot, resources.handoff.template_ref).model_dump()
    requests = []
    for p in chosen:
        t = templates[p['fix_type']]
        ref = TemplateReference(registry_name=p['fix_type'], version=1, sha256=t.sha256,
                                evidence=[{'document_id': 'live-doc', 'version': '1', 'sha256': 'b' * 64}])
        requests.append(SandboxHandoff(**{**base, 'control_id': p['spec_id'], 'object_fix_id': p['fix_id'],
                                          'template_ref': ref.model_dump()}))
    output, data = batch.run_batch(requests, service)
    combined = output['combined_test']
    assert output['status'] == 'VERIFIED', combined.get('reason') or combined.get('rollback_error')
    assert [r['status'] for r in output['individual_runs']] == ['VERIFIED'] * 3
    assert [r['fix_id'] for r in combined['rollback']] == list(reversed(output['recommended_order']))
    assert all(r['verified'] for r in combined['rollback'])
    # One stand-in with all three targets and their dependencies.
    assert set(combined['skeleton']['exact_roles']) == {'w2a_web', 'w2a_admin'}
    last = combined['steps'][-1]['after']
    assert all(object_fixes.predicate(p, last) for p in chosen)
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        assert 'WHAT WAS NOT REHEARSED' in z.read('README.txt').decode()
        for fix_id in output['recommended_order']:
            config = json.loads(z.read(fix_id + '/fix.json'))
            assert config['kind'] == 'object' and config['prior'] != config['applied']
    # Every container this batch created (three individual runs, one combined), by its own run ID.
    owned = [runtime.run_id for runtime in created]
    assert len(owned) == len(set(owned)) == 4 and owned[-1] == combined['run_id']
    print('RUN_IDS batch containers (3 individual, then combined)', owned)
    assert [run_id for run_id in owned if docker('ps', '-aq', '--filter', f'label={LABEL}={run_id}')] == []


def test_exported_bundle_runner_guards_the_object(source, tmp_path):
    """Bundle from a VERIFIED rehearsal; the runner refuses a changed object and applies in one transaction."""
    from services.sandbox_poc.review_bundle import build_review_bundle
    engine, snapshot, resources = source['engine'], source['snapshot'], source['resources']
    proposal = pick(source, 'role_drop_attribute', role='w2a_admin', attribute='CREATEDB')
    template = fixture_template('role_drop_attribute')
    result = ObjectRemediationLoop(engine, template, proposal).run(snapshot, engine.assess(snapshot))
    assert result['status'] == 'VERIFIED'
    result.update(run_id='live-object-bundle', approval_source='registry', requires_dba_review=True)
    ref = TemplateReference(registry_name='role_drop_attribute', version=1, sha256=template.sha256,
                            evidence=[{'document_id': 'live-doc', 'version': '1', 'sha256': 'b' * 64}])
    base = build_handoff(engine, snapshot, resources.handoff.template_ref).model_dump()
    handoff = SandboxHandoff(**{**base, 'control_id': proposal['spec_id'], 'object_fix_id': proposal['fix_id'],
                                'template_ref': ref.model_dump()})
    data = build_review_bundle(handoff, result, engine)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        archive.extractall(tmp_path)
        readme = archive.read('README.txt').decode()
    assert 'stand-in copy' in readme and 'WHAT WAS NOT REHEARSED' in readme
    config = json.loads((tmp_path / 'fix.json').read_text())
    assert config['apply_statements'] == ['ALTER ROLE "w2a_admin" NOCREATEDB;']
    spec = importlib.util.spec_from_file_location('exported_object_runner', tmp_path / 'runner.py')
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    with published_target() as (target, dsn):
        target.sql(f"CREATE ROLE w2a_admin LOGIN SUPERUSER CREATEDB PASSWORD '{secrets.token_urlsafe(24)}';")
        with pytest.raises(RuntimeError, match='Demo fixture'):
            runner.execute(config, 'apply', dsn)
        with pytest.raises(RuntimeError, match='cluster identity'):
            runner.execute(config, 'status', dsn, True)
        # The runner fixture is explicitly rebound to this independent disposable target.
        config['system_identifier'] = target.sql('SELECT system_identifier::text FROM pg_control_system();')
        assert runner.execute(config, 'status', dsn, True) == {'matches_prior': True, 'matches_applied': False}
        # Someone changes the object: no SQL runs.
        target.sql('ALTER ROLE w2a_admin CREATEROLE;')
        with pytest.raises(RuntimeError, match='Object drift detected; no SQL executed'):
            runner.execute(config, 'apply', dsn, True)
        assert target.sql("SELECT rolcreatedb FROM pg_roles WHERE rolname = 'w2a_admin';") == 't'
        target.sql('ALTER ROLE w2a_admin NOCREATEROLE;')
        assert runner.execute(config, 'apply', dsn, True)['verified']
        assert target.sql("SELECT rolcreatedb FROM pg_roles WHERE rolname = 'w2a_admin';") == 'f'
        with pytest.raises(RuntimeError, match='drift'):
            runner.execute(config, 'apply', dsn, True)
        assert runner.execute(config, 'verify', dsn, True)['verified']
        assert runner.execute(config, 'rollback', dsn, True)['verified']
        assert target.sql("SELECT rolcreatedb FROM pg_roles WHERE rolname = 'w2a_admin';") == 't'
        evidence = runner.verification_queries(config, dsn, 'rollback')
        assert all(q['passed'] for q in evidence['queries'])
        target_run_id = target.run_id
    assert not docker('ps', '-aq', '--filter', f'label={LABEL}={target_run_id}')
    for each in result['attempts']:
        assert not docker('ps', '-aq', '--filter', f"label={LABEL}={each['run_id']}")


# The collector's object_acls.extension field, on a disposable SOURCE only.
# ALTER EXTENSION ... ADD TABLE makes the table a member of the extension
# (pg_depend deptype 'e'), exactly as an extension script's CREATE TABLE would.
EXTENSION_SQL = """
CREATE ROLE w2x_owner NOLOGIN;
CREATE ROLE w2x_app LOGIN;
CREATE SCHEMA w2x AUTHORIZATION w2x_owner;
CREATE EXTENSION pg_trgm SCHEMA w2x;
CREATE TABLE w2x.ext_cfg (id integer);
ALTER TABLE w2x.ext_cfg OWNER TO w2x_owner;
GRANT INSERT, UPDATE ON w2x.ext_cfg TO w2x_app;
ALTER EXTENSION pg_trgm ADD TABLE w2x.ext_cfg;
CREATE TABLE w2x.orders (id integer);
ALTER TABLE w2x.orders OWNER TO w2x_owner;
GRANT INSERT, UPDATE ON w2x.orders TO w2x_app;
"""


def test_collector_records_the_owning_extension_of_a_table():
    resources = DemoResources()
    with TestClient(create_app(lambda: resources)):
        resources.target.sql(EXTENSION_SQL)
        snapshot = _collect_with_real_script(resources)
    assert not docker('ps', '-aq', '--filter', f'label=dbguard.live-demo.run={resources.run_id}')
    assert not docker('ps', '-aq', '--filter', f'label={LABEL}={resources.target.run_id}')
    rows = {r['name']: r for r in snapshot['baseline']['object_acls'] if r['schema'] == 'w2x'}
    assert rows['ext_cfg']['extension'] == 'pg_trgm' and rows['ext_cfg']['acl']
    assert 'extension' in rows['orders'] and rows['orders']['extension'] is None and rows['orders']['acl']
    # Every collected row carries the key ([] vs null rule: null means "no owning extension").
    assert all('extension' in r for r in snapshot['baseline']['object_acls'])
    assert any(e['extname'] == 'pg_trgm' and e['schema'] == 'w2x' for e in snapshot['baseline']['extensions'])
    # With the field present, only the extension-owned table is excluded; the ordinary
    # table in the same schema now gets rehearsable proposals.
    engine = profile_engine()
    plan = object_fixes.plan(engine, snapshot, engine.policy_pin)
    tables = {p['target']['table'] for p in plan['proposals'] if p['fix_type'] == 'table_revoke_dml'
              and p['target']['schema'] == 'w2x'}
    assert tables == {'orders'}
    assert all(p['rehearsable'] for p in plan['proposals'] if p['fix_type'] == 'table_revoke_dml'
               and p['target']['schema'] == 'w2x')
    owned = [n for n in plan['notes'] if n['code'] == 'extension_owned' and (n['target'] or {}).get('schema') == 'w2x']
    assert [n['target']['table'] for n in owned] == ['ext_cfg'] and owned[0]['extension'] == 'pg_trgm'
    assert not [n for n in plan['notes'] if n['code'] == 'possibly_extension_owned'
                and (n['target'] or {}).get('schema') == 'w2x']
