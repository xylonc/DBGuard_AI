"""Build a review ZIP only from a bound, verified server-produced sandbox result."""
from collections import OrderedDict
import hashlib
import base64
from html import escape
import io
import json
from pathlib import Path
import re
import threading
import zipfile

from app.services.fix_unit_validator import validate_fix_unit
from .provenance import signature, setting_rows
from .shared import ContractError, digest
from .workflow import CONTROL, template_action
from app.services.fix_unit_render import derive_rollback, render_action, render_action_script

ASSETS = Path(__file__).parent / 'bundle_assets'


def require(condition, message):
    if not condition:
        raise ContractError('Review bundle: ' + message)


def canonical_apply(sql, name="log_connections"):
    from .planning import POLICIES
    action = template_action(sql, name)
    require(action['value'] == POLICIES[name][0], 'apply value differs from reviewed policy')
    return render_action(action)


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
    from .planning import fix_scope, risk_review
    control = handoff.control_id
    _, name, value = fix_scope(engine, control)
    require(fix['spec_id'] == control and fix['fix_id'] == 'fix-'+name and fix['requires'] in ('reload','restart'), 'unsupported fix')
    template = result['template']
    ref = next((ref for ref in [handoff.template_ref, *handoff.retry_template_refs]
                if ref.registry_name == template['registry_name'] and ref.version == template['version'] and ref.sha256 == template['sha256']), None)
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
    bound = engine.bind_assessment(handoff.snapshot, handoff.assessment)
    require(before['findings'] == bound['findings'] == restored['findings'], 'reproduction or rollback findings differ')
    require(after['findings'][control]['status'] == 'PASS', 'target did not pass')
    regressions = [sid for sid, f in before['findings'].items() if sid != control and ((f['status'] == 'PASS' and after['findings'][sid]['status'] != 'PASS') or after['findings'][sid]['status'] == 'GAPPED')]
    require(not regressions and final.get('regressions') == [], 'regression evidence is invalid')
    prior = signature(handoff.snapshot, names)
    require(signature(final['before'], names) == prior == signature(final['rollback'], names), 'exact rollback provenance differs')
    require(not any(s['baseline'].get('gaps') for s in (final['before'], final['after'], final['rollback'])), 'collection has gaps')
    require(fix['rollback'] == derive_rollback(fix['prior_state'], fix['apply']), 'rollback differs from source-aware plan')
    row = setting_rows(handoff.snapshot)[name]
    require(fix['prior_state'] == {k: row.get(v) for k, v in {'value':'setting','source':'source','sourcefile':'sourcefile','context':'context'}.items()}, 'prior state differs from source')
    require(fix['apply'] == template_action(result['rendered_apply_sql'], name), 'typed action differs from tested template')
    require(final.get('rendered_apply_sql') == result['rendered_apply_sql'] and final.get('fix_unit_hash') == digest(fix), 'final attempt differs from exported fix')
    require(result['rendered_rollback_sql'] == render_action_script(fix['rollback']), 'rendered rollback differs')
    apply_statements = canonical_apply(result['rendered_apply_sql'], name)
    demo = is_fixture(result)
    risk = result.get('risk_review') or risk_review(engine, handoff.snapshot, control)
    config = {'fix_id': fix['fix_id'], 'database': handoff.snapshot['envelope']['database'],
              'demo_fixture_approval': demo, 'names': names, 'prior': prior,
              'run_id':result['run_id'], 'control_id':control, 'setting':name, 'requires':fix['requires'],
              'target_id':handoff.snapshot['envelope']['target_id'], 'system_identifier':handoff.snapshot['baseline'].get('identity',{}).get('system_identifier'),
              'spec_set_hash':engine.spec_set_hash, 'snapshot_hash':result['snapshot_hash'],
              'applied': signature(final['after'], names), 'apply_statements': apply_statements,
              'rollback_statements': [s+';' for s in render_action(fix['rollback'])]}
    rows = ''.join('<tr>'+''.join(f'<td>{escape(str(x))}</td>' for x in
                 (s['spec_id'], s['ref']['title'], before['findings'][s['spec_id']]['status'], after['findings'][s['spec_id']]['status'], restored['findings'][s['spec_id']]['status']))+'</tr>' for s in engine.specs)
    scope = 'DEMO FIXTURE APPROVAL — not human approval' if demo else 'Registry-approved template and evidence — DBA review still required'
    risk_html = '<h2>Risk and prerequisites</h2><pre>'+escape(json.dumps(risk,indent=2))+'</pre>'
    report = f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>DBGuardAI review report</title><style>body{{font:15px/1.5 system-ui;margin:32px;color:#21343b;max-width:1100px}}table{{border-collapse:collapse;width:100%}}td,th{{padding:10px;border:1px solid #cbd5db;text-align:left;overflow-wrap:anywhere}}th{{background:#eaf4f1}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#f1f4f6;padding:16px}}.notice{{padding:16px;background:#fff3d9}}.table{{overflow:auto}}</style></head><body><h1>DBGuardAI · DBA review</h1><p class="notice">{escape(scope)}</p><p>Sandbox status: VERIFIED. Target application and real-target reassessment: NOT PERFORMED.</p><p>Run: {escape(result['run_id'])}<br>Source: {escape(handoff.snapshot['envelope']['target_id'])}<br>Spec set: {escape(engine.spec_set_hash)}</p><h2>Before / after / rollback in the sandbox</h2><div class="table"><table><tr><th>Control</th><th>Title</th><th>Before</th><th>After fix</th><th>After rollback</th></tr>{rows}</table></div><p>{len(attempts)} attempt(s). All attempt resources removed. Exact rollback and database health verified.</p>{risk_html}<h2>DBA verification</h2><p>Run verify.sh after each complete fix. It opens fresh connections, reads the catalogue, tests a transaction and checks all scoped settings. Run the listed application checks separately.</p><h2>Reviewed apply SQL</h2><pre>{escape(result['rendered_apply_sql'])}</pre><h2>Rollback SQL</h2><pre>{escape(result['rendered_rollback_sql'])}</pre><h2>Limits</h2><p>PostgreSQL 17; reviewed configuration policies. Restart settings require a DBA-controlled restart on the target. Regression coverage is limited to the supplied specs. Configuration provenance is restored semantically, not byte-for-byte file formatting.</p><p>The script requires an explicit target connection and refuses configuration drift. A database name and matching settings do not uniquely identify a server: the DBA must verify the target. Advisory locking coordinates DBGuard runs only; other administrators can still change configuration.</p><p>After applying, recollect and reassess the target using the same specs. Review README.txt and the bundled evidence before running harden.sh.</p></body></html>'''
    files = {'fix.json': json.dumps(config, indent=2).encode(),
             'evidence.json': json.dumps({'handoff': handoff.model_dump(), 'result': result}, indent=2).encode(),
             'report.html': report.encode(), 'runner.py': (ASSETS/'runner.py').read_bytes(),
             'harden.sh': b'#!/bin/sh\nset -eu\nBUNDLE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)\nexec python3 "$BUNDLE_DIR/runner.py" "$@"\n'}
    files['risk-review.json'] = json.dumps(risk,indent=2).encode()
    files['visual_evidence.py'] = (ASSETS/'visual_evidence.py').read_bytes()
    files['verify.sh'] = b'#!/bin/sh\nset -eu\nBUNDLE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)\nexec python3 "$BUNDLE_DIR/runner.py" verify "$@"\n'
    visual = final.get('functional_checks',{}).get('screenshot',{})
    if visual.get('status') != 'CAPTURED':
        files['report.html'] = report.replace('</body>', '<p>Screenshot capture: '+escape(visual.get('status','NOT_RECORDED'))+'. Query and assessment evidence remain in evidence.json.</p></body>').encode()
    if visual.get('status') == 'CAPTURED':
        png = base64.b64decode(visual['png_base64'],validate=True)
        require(hashlib.sha256(png).hexdigest() == visual['sha256'], 'screenshot hash mismatch')
        files['sandbox-after.png'] = png
        files['sandbox-queries.json'] = json.dumps(visual['query_evidence'],indent=2).encode()
        report = report.replace('</body>', '<h2>Actual sandbox database results</h2><p>Browser capture of the query evidence viewer, from fresh database queries after the fix.</p><img style="max-width:100%" src="sandbox-after.png" alt="Sandbox verification query results"></body>')
        files['report.html'] = report.encode()
    manifest = {'schema_version' :'review-bundle-v1', 'run_id':result['run_id'], 'demo_fixture_approval':demo,
                'requires_dba_review':True, 'snapshot_hash':result['snapshot_hash'], 'spec_set_hash':engine.spec_set_hash,
                'files':{name:hashlib.sha256(data).hexdigest() for name,data in files.items()}}
    files['manifest.json'] = json.dumps(manifest, indent=2).encode()
    files['README.txt'] = (f'''{scope}\n\nReview report.html, evidence.json and both SQL commands before any execution.\nRequires Python 3 and psycopg2 (requirements-sandbox.txt includes psycopg2-binary).\nSet DBGUARD_DSN to the DBA-verified target using your normal credential handling.\nNo credentials are included. Verify server identity separately.\n\nsh harden.sh status {fix["fix_id"]}\nsh harden.sh apply {fix["fix_id"]} --ack-prerequisites\nsh harden.sh rollback {fix["fix_id"]}\n\nsh verify.sh {fix["fix_id"]} --screenshots\n\nVerification captures actual database query output, not model-generated content.\nScreenshot dependencies: pip install playwright; python3 -m playwright install chromium.\nImages show a browser evidence viewer populated with actual query results.\nReview and perform application-specific checks in risk-review.json separately.\nFor restart settings, apply/rollback stages the configuration; the DBA restarts\nPostgreSQL outside this tool, then runs verify (or verify-rollback).\nRecollect the target with the original collector and reassess via the application.\n\nDemo bundles require --allow-demo and must only be used with disposable databases.\nThe runner checks PostgreSQL version, database name and configuration provenance.\nIt checks all scoped settings for drift before apply or rollback, and uses fresh\nconnections to verify the resulting settings and source. It never applies automatically.\nIf SQL executes but verification fails, inspect the server before retrying.\nRollback refuses drift; it is not a disaster recovery tool. Recollect and reassess\nthe real target after applying. The manifest detects accidental changes, not forgery.\n''').encode()
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
