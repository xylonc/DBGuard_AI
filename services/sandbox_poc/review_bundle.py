"""Build a review ZIP only from a bound, verified server-produced sandbox result."""
from collections import OrderedDict
import hashlib
from html import escape
import io
import json
from pathlib import Path
import re
import threading
import zipfile

from app.services.fix_unit_validator import validate_fix_unit
from .provenance import signature, rollback_sql, setting_rows
from .shared import ContractError, digest
from .workflow import CONTROL

ASSETS = Path(__file__).parent / 'bundle_assets'


def require(condition, message):
    if not condition:
        raise ContractError('Review bundle: ' + message)


def canonical_apply(sql):
    # Fixed one-setting milestone: reject extra statements, psql commands and comments
    # other than full-line template comments. This is stricter than the general validator.
    body = '\n'.join(line for line in sql.splitlines() if not line.lstrip().startswith('--'))
    require(re.fullmatch(r'''\s*ALTER\s+SYSTEM\s+SET\s+"?log_connections"?\s*=\s*'on'\s*;\s*SELECT\s+pg_reload_conf\s*\(\s*\)\s*;\s*''', body, re.I),
            'apply SQL is outside the supported template')
    return ['ALTER SYSTEM SET "log_connections" = \'on\';', 'SELECT pg_reload_conf();']


def is_fixture(result):
    approvers = [result['template'].get('approved_by', '')] + [e.get('approved_by', '') for e in result['template'].get('evidence', [])]
    return bool(result.get('demo_fixture_approval')) or any(any(word in a.upper() for word in ('FIXTURE', 'TEST_ONLY', 'DEMO')) for a in approvers)


def build_review_bundle(handoff, result, engine):
    require(result.get('status') == 'VERIFIED', 'only VERIFIED runs are exportable')
    require(result.get('approval_source') == 'registry', 'registry approval evidence is required')
    require(result.get('snapshot_hash') == digest(handoff.snapshot), 'snapshot identity mismatch')
    require(result.get('spec_set_hash') == engine.spec_set_hash == handoff.spec_set_hash, 'spec identity mismatch')
    require(result.get('spec_hashes') == engine.hashes and result.get('collector_hash') == engine.collector_hash, 'collector/spec evidence mismatch')
    fix = result['fix_unit']
    require(result.get('fix_unit_hash') == digest(fix), 'fix-unit identity mismatch')
    require(not validate_fix_unit(fix), 'upstream fix-unit validation failed')
    require(fix['spec_id'] == CONTROL and fix['fix_id'] == 'fix-log_connections' and fix['requires'] == 'reload', 'unsupported fix')
    template = result['template']
    ref = next((ref for ref in [handoff.template_ref, *handoff.retry_template_refs]
                if ref.version == template['version'] and ref.sha256 == template['sha256']), None)
    require(ref is not None, 'selected template was not pinned in the handoff')
    require(template['registry_name'] == ref.registry_name and template['version'] == ref.version and template['sha256'] == ref.sha256, 'template reference mismatch')
    pins = [{k: e.get(k) for k in ('document_id', 'version', 'sha256')} for e in template['evidence']]
    require(pins == [p.model_dump() for p in ref.evidence], 'evidence reference mismatch')
    names = [s['check']['setting_name'] for s in engine.specs if 'check' in s]
    attempts = result['attempts']
    require(1 <= len(attempts) <= 3 and all(a.get('cleanup', {}).get('verified') is True for a in attempts), 'attempt cleanup is incomplete')
    final = attempts[-1]
    require(final.get('status') == 'VERIFIED' and final.get('rollback_verified') is True and final.get('health_after_apply') is True and final.get('health_after_rollback') is True, 'acceptance evidence incomplete')
    before = engine.assess(final['before'])
    after = engine.assess(final['after'])
    restored = engine.assess(final['rollback'])
    require(before == final['before_assessment'] and after == final['after_assessment'] and restored == final['rollback_assessment'], 'assessments do not match snapshots')
    require(before['findings'] == handoff.assessment['findings'] == restored['findings'], 'reproduction or rollback findings differ')
    require(after['findings'][CONTROL]['status'] == 'PASS', 'target did not pass')
    regressions = [sid for sid, f in before['findings'].items() if sid != CONTROL and ((f['status'] == 'PASS' and after['findings'][sid]['status'] != 'PASS') or after['findings'][sid]['status'] == 'GAPPED')]
    require(not regressions and final.get('regressions') == [], 'regression evidence is invalid')
    prior = signature(handoff.snapshot, names)
    require(signature(final['before'], names) == prior == signature(final['rollback'], names), 'exact rollback provenance differs')
    require(not any(s['baseline'].get('gaps') for s in (final['before'], final['after'], final['rollback'])), 'collection has gaps')
    require(fix['rollback'] == rollback_sql(handoff.snapshot), 'rollback differs from source-aware plan')
    row = setting_rows(handoff.snapshot)['log_connections']
    require(fix['prior_state'] == {k: row.get(v) for k, v in {'value':'setting','source':'source','sourcefile':'sourcefile','context':'context'}.items()}, 'prior state differs from source')
    apply_statements = canonical_apply(fix['apply'])
    demo = is_fixture(result)
    config = {'fix_id': fix['fix_id'], 'database': handoff.snapshot['envelope']['database'],
              'demo_fixture_approval': demo, 'names': names, 'prior': prior,
              'applied': signature(final['after'], names), 'apply_statements': apply_statements,
              'rollback_statements': [s.strip()+';' for s in fix['rollback'].split(';') if s.strip()]}
    rows = ''.join('<tr>'+''.join(f'<td>{escape(str(x))}</td>' for x in
                 (s['spec_id'], s['ref']['title'], before['findings'][s['spec_id']]['status'], after['findings'][s['spec_id']]['status'], restored['findings'][s['spec_id']]['status']))+'</tr>' for s in engine.specs)
    scope = 'DEMO FIXTURE APPROVAL — not human approval' if demo else 'Registry-approved template and evidence — DBA review still required'
    report = f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>DBGuardAI review report</title><style>body{{font:15px/1.5 system-ui;margin:32px;color:#21343b;max-width:1100px}}table{{border-collapse:collapse;width:100%}}td,th{{padding:10px;border:1px solid #cbd5db;text-align:left;overflow-wrap:anywhere}}th{{background:#eaf4f1}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#f1f4f6;padding:16px}}.notice{{padding:16px;background:#fff3d9}}.table{{overflow:auto}}</style></head><body><h1>DBGuardAI · DBA review</h1><p class="notice">{escape(scope)}</p><p>Sandbox status: VERIFIED. Target application and real-target reassessment: NOT PERFORMED.</p><p>Run: {escape(result['run_id'])}<br>Source: {escape(handoff.snapshot['envelope']['target_id'])}<br>Spec set: {escape(engine.spec_set_hash)}</p><h2>Before / after / rollback in the sandbox</h2><div class="table"><table><tr><th>Control</th><th>Title</th><th>Before</th><th>After fix</th><th>After rollback</th></tr>{rows}</table></div><p>{len(attempts)} attempt(s). All attempt resources removed. Exact rollback and database health verified.</p><h2>Reviewed apply SQL</h2><pre>{escape(fix['apply'])}</pre><h2>Rollback SQL</h2><pre>{escape(fix['rollback'])}</pre><h2>Limits</h2><p>PostgreSQL 17; connection logging only; reload only. Regression coverage is limited to the supplied specs. Configuration provenance is restored semantically, not byte-for-byte file formatting.</p><p>The script requires an explicit target connection and refuses configuration drift. A database name and matching settings do not uniquely identify a server: the DBA must verify the target. Advisory locking coordinates DBGuard runs only; other administrators can still change configuration.</p><p>After applying, recollect and reassess the target using the same specs. Review README.txt and the bundled evidence before running harden.sh.</p></body></html>'''
    files = {'fix.json': json.dumps(config, indent=2).encode(),
             'evidence.json': json.dumps({'handoff': handoff.model_dump(), 'result': result}, indent=2).encode(),
             'report.html': report.encode(), 'runner.py': (ASSETS/'runner.py').read_bytes(),
             'harden.sh': b'#!/bin/sh\nset -eu\nBUNDLE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)\nexec python3 "$BUNDLE_DIR/runner.py" "$@"\n'}
    manifest = {'schema_version':'review-bundle-v1', 'run_id':result['run_id'], 'demo_fixture_approval':demo,
                'requires_dba_review':True, 'snapshot_hash':result['snapshot_hash'], 'spec_set_hash':engine.spec_set_hash,
                'files':{name:hashlib.sha256(data).hexdigest() for name,data in files.items()}}
    files['manifest.json'] = json.dumps(manifest, indent=2).encode()
    files['README.txt'] = (f'''{scope}\n\nReview report.html, evidence.json and both SQL commands before any execution.\nRequires Python 3 and psycopg2 (requirements-sandbox.txt includes psycopg2-binary).\nSet DBGUARD_DSN to the DBA-verified target using your normal credential handling.\nNo credentials are included. Verify server identity separately.\n\nsh harden.sh status fix-log_connections\nsh harden.sh apply fix-log_connections\nsh harden.sh rollback fix-log_connections\n\nDemo bundles require --allow-demo and must only be used with disposable databases.\nThe runner checks PostgreSQL version, database name and configuration provenance.\nIt checks all scoped settings for drift before apply or rollback, and uses fresh\nconnections to verify the resulting settings and source. It never applies automatically.\nIf SQL executes but verification fails, inspect the server before retrying.\nRollback refuses drift; it is not a disaster recovery tool. Recollect and reassess\nthe real target after applying. The manifest detects accidental changes, not forgery.\n''').encode()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return buffer.getvalue()


class BundleStore:
    """Bounded process-local downloads; only server-created ZIPs enter this store."""
    def __init__(self, capacity=8):
        self.capacity, self.entries, self.lock = capacity, OrderedDict(), threading.Lock()

    def put(self, run_id, data):
        with self.lock:
            self.entries[run_id] = data
            while len(self.entries) > self.capacity:
                self.entries.popitem(last=False)

    def get(self, run_id):
        with self.lock:
            return self.entries.get(run_id)
