"""Build a review ZIP only from a bound, verified server-produced sandbox result."""
from collections import OrderedDict
import binascii
import copy
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
from app.services.spec_engine.policy import approval_text
from .provenance import signature, setting_rows
from .shared import ContractError, blocking_gaps, digest, is_regression
from .workflow import CONTROL, template_action
from app.services.fix_unit_render import derive_rollback, render_action, render_action_script

ASSETS = Path(__file__).parent / 'bundle_assets'


def require(condition, message):
    if not condition:
        raise ContractError('Review bundle: ' + message)


def canonical_apply(sql, name="log_connections", value=None):
    """The tested statement, bound to the reviewed fix value (POLICIES or approved profile)."""
    if value is None:
        from .planning import POLICIES
        value = POLICIES[name][0]
    action = template_action(sql, name)
    require(action['value'] == value, 'apply value differs from reviewed policy')
    return render_action(action)


def is_fixture(result):
    # W2B: a catalog fix may also carry the set_config_list template's approval.
    templates = [result['template']] + ([result['list_template']] if result.get('list_template') else [])
    approvers = [a for t in templates for a in [t.get('approved_by', '')] + [e.get('approved_by', '') for e in t.get('evidence', [])]]
    return bool(result.get('demo_fixture_approval')) or any(any(word in a.upper() for word in ('FIXTURE', 'TEST_ONLY', 'DEMO')) for a in approvers)


# Task 2: sandbox stage screenshots (terminal_capture). Fixed member names; the DBA's
# runner.py lists exactly these in its manifest allowlist.
SCREENSHOT_STAGES = (('before', 'Before (problem reproduced on the sandbox copy)'),
                     ('after', 'After fix'), ('rollback', 'After rollback'))
SCREENSHOT_MEMBERS = tuple(f'screenshots/{s}.png' for s, _ in SCREENSHOT_STAGES)
COMBINED_SCREENSHOT_MEMBERS = tuple(f'screenshots/combined-{s}.png' for s, _ in SCREENSHOT_STAGES)
PNG_MAGIC = b'\x89PNG\r\n\x1a\n'


def stage_screenshots(evidence, prefix=''):
    """({member: png}, report html, README text) for the recorded stage screenshots.

    Only CAPTURED shots become files; each PNG must match its recorded sha256. The JSON
    raw output (evidence.json) stays the authority; the picture is evidence, not proof."""
    stages = evidence.get('stages') if isinstance(evidence, dict) else None
    if not isinstance(stages, dict):
        return {}, '', ''
    files, rows, text = {}, [], ['', 'Sandbox screenshots (before / after fix / after rollback):']
    for stage, label in SCREENSHOT_STAGES:
        shot = stages.get(stage)
        if not isinstance(shot, dict):
            continue
        kind = ('real terminal (VHS) running the typed command below' if shot.get('mode') == 'terminal'
                else 'rendered evidence viewer of the same query output')
        details = (f"Raw output sha256: {shot.get('raw_output_sha256', 'not recorded')}; "
                   f"captured {shot.get('captured_at', 'not recorded')} UTC; target {shot.get('target_id', 'not recorded')}")
        if shot.get('status') == 'CAPTURED':
            try:
                png = base64.b64decode(shot.get('png_base64') or '', validate=True)
            except (binascii.Error, ValueError, TypeError):
                raise ContractError('Review bundle: stage screenshot is not valid base64') from None
            require(png.startswith(PNG_MAGIC) and hashlib.sha256(png).hexdigest() == shot.get('sha256'),
                    'stage screenshot hash mismatch')
            name = f'screenshots/{prefix}{stage}.png'
            require(name in SCREENSHOT_MEMBERS + COMBINED_SCREENSHOT_MEMBERS, 'unexpected screenshot member')
            files[name] = png
            typed = f"<pre>{escape(shot['typed_command'])}</pre>" if shot.get('typed_command') else ''
            note = f"<p class=\"notice\">{escape(shot['reason'])}</p>" if shot.get('reason') else ''
            rows.append(f'<h3>{escape(label)}</h3><p>{escape(kind.capitalize())}. {escape(details)}. '
                        f'PNG sha256 {escape(shot["sha256"])}.</p>{typed}{note}'
                        f'<img style="max-width:100%" src="{escape(name)}" alt="{escape(label)}">')
            text.append(f"- {name}: {label}, {kind}; {details}; PNG sha256 {shot['sha256']}"
                        + (f"\n  typed: {shot['typed_command']}" if shot.get('typed_command') else '')
                        + (f"\n  note: {shot['reason']}" if shot.get('reason') else ''))
        else:
            reason = shot.get('reason') or 'not recorded'
            rows.append(f'<h3>{escape(label)}</h3><p class="notice">Screenshot UNAVAILABLE: {escape(reason)}</p>')
            text.append(f'- {label}: screenshot UNAVAILABLE ({reason})')
    if not rows:
        return {}, '', ''
    html = ('<h2>Sandbox screenshots</h2><p>Pictures of fresh read-only queries in the disposable sandbox at '
            'each stage. evidence.json holds the raw output and is the authority; the manifest detects '
            'accidental changes, not forgery. verify.sh --screenshots on the real target is separate '
            '(rendered capture, never a terminal recording).</p>' + ''.join(rows))
    return files, html, '\n'.join(text) + '\n'


def strip_screenshot_data(evidence, prefix):
    """Review N9: in a bundle the stage PNGs are members, so evidence JSON keeps each shot's
    member name and sha256 instead of repeating the image as base64. prefix None: the shots
    are not bundled (an earlier attempt), so only the sha256 is kept."""
    stages = evidence.get('stages') if isinstance(evidence, dict) else None
    if not isinstance(stages, dict):
        return
    for stage, shot in stages.items():
        if isinstance(shot, dict) and 'png_base64' in shot:
            del shot['png_base64']
            member = f'screenshots/{prefix}{stage}.png' if prefix is not None else None
            if shot.get('status') == 'CAPTURED' and member in SCREENSHOT_MEMBERS + COMBINED_SCREENSHOT_MEMBERS:
                shot['png_member'] = member
            else:
                shot['png_omitted'] = 'Not included in this bundle; its sha256 is kept.'


def bundled_result(result):
    """The run result as written to evidence.json (see strip_screenshot_data)."""
    out = copy.deepcopy(result)
    attempts = out.get('attempts') if isinstance(out.get('attempts'), list) else []
    for index, attempt in enumerate(attempts):
        if isinstance(attempt, dict):
            strip_screenshot_data(attempt.get('terminal_evidence'), '' if index == len(attempts) - 1 else None)
    return out


def build_review_bundle(handoff, result, engine):
    is_object = result.get('kind') == 'object'
    require(is_object == bool(getattr(handoff, 'object_fix_id', None)), 'fix kind differs from the handoff')
    if is_object:
        return build_object_review_bundle(handoff, result, engine)
    if result.get('kind') == 'catalog_setting':
        return build_catalog_review_bundle(handoff, result, engine)
    require(result.get('status') == 'VERIFIED', 'only VERIFIED runs are exportable')
    require(result.get('approval_source') == 'registry', 'registry approval evidence is required')
    require(result.get('snapshot_hash') == digest(handoff.snapshot), 'snapshot identity mismatch')
    require(result.get('spec_set_hash') == engine.spec_set_hash == handoff.spec_set_hash, 'spec identity mismatch')
    require(result.get('spec_hashes') == engine.hashes and result.get('collector_hash') == engine.collector_hash, 'collector/spec evidence mismatch')
    fix = result['fix_unit']
    require(result.get('fix_unit_hash') == digest(fix), 'fix-unit identity mismatch')
    require(not validate_fix_unit(fix), 'upstream fix-unit validation failed')
    from .planning import SANDBOX_LIMITS, fix_scope, risk_review
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
    names = [s['check']['setting_name'] for s in engine.specs if 'check' in s and s['check'].get('kind') != 'catalog']
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
    regressions = [sid for sid, f in before['findings'].items() if sid != control and (is_regression(f['status'], after['findings'][sid]['status']) or sid in engine.gapped_settings(after['findings']))]
    from .workflow import setting_catalog_regressions
    regressions += setting_catalog_regressions(engine, before, after, name, control)
    require(not regressions and final.get('regressions') == [], 'regression evidence is invalid')
    prior = signature(handoff.snapshot, names)
    require(signature(final['before'], names) == prior == signature(final['rollback'], names), 'exact rollback provenance differs')
    require(not any(blocking_gaps(s) for s in (final['before'], final['after'], final['rollback'])), 'collection has gaps')
    require(fix['rollback'] == derive_rollback(fix['prior_state'], fix['apply']), 'rollback differs from source-aware plan')
    row = setting_rows(handoff.snapshot)[name]
    require(fix['prior_state'] == {k: row.get(v) for k, v in {'value':'setting','source':'source','sourcefile':'sourcefile','context':'context'}.items()}, 'prior state differs from source')
    require(fix['apply'] == template_action(result['rendered_apply_sql'], name), 'typed action differs from tested template')
    require(final.get('rendered_apply_sql') == result['rendered_apply_sql'] and final.get('fix_unit_hash') == digest(fix), 'final attempt differs from exported fix')
    require(result['rendered_rollback_sql'] == render_action_script(fix['rollback']), 'rendered rollback differs')
    require(fix['apply']['value'] == value, 'apply value differs from the reviewed fix value')
    require(result.get('policy_profile') == engine.policy_pin, 'policy profile differs from the tested run')
    apply_statements = canonical_apply(result['rendered_apply_sql'], name, value)
    demo = is_fixture(result)
    risk = result.get('risk_review') or risk_review(engine, handoff.snapshot, control)
    config = {'fix_id': fix['fix_id'], 'database': handoff.snapshot['envelope']['database'],
              'demo_fixture_approval': demo, 'names': names, 'prior': prior,
              'run_id':result['run_id'], 'control_id':control, 'setting':name, 'requires':fix['requires'],
              'target_id':handoff.snapshot['envelope']['target_id'], 'system_identifier':handoff.snapshot['baseline'].get('identity',{}).get('system_identifier'),
              'spec_set_hash':engine.spec_set_hash, 'snapshot_hash':result['snapshot_hash'],
              'policy_profile':engine.policy_pin,
              'applied': signature(final['after'], names), 'apply_statements': apply_statements,
              'rollback_statements': [s+';' for s in render_action(fix['rollback'])]}
    rows = ''.join('<tr>'+''.join(f'<td>{escape(str(x))}</td>' for x in
                 (s['spec_id'], s['ref']['title'], before['findings'][s['spec_id']]['status'], after['findings'][s['spec_id']]['status'], restored['findings'][s['spec_id']]['status']))+'</tr>' for s in engine.specs if s['spec_id'] in before['findings'])
    from app.services.spec_engine.catalog_checks import notices_for
    # Fixed, reviewed notices (e.g. 7.4's restore-test reminder) for the DBA, never model output.
    notice_html = ''.join(f'<p class="notice">{escape(s["spec_id"])}: {escape(n["text"])}</p>'
                          for s in engine.specs if s['spec_id'] in before['findings'] for n in notices_for(s['ref']['recommendation']))
    scope = 'DEMO FIXTURE APPROVAL — not human approval' if demo else 'Registry-approved template and evidence — DBA review still required'
    # Reviewed server-side text only (planning.SANDBOX_LIMITS), e.g. 5.2 listen_addresses.
    sandbox_limit = SANDBOX_LIMITS.get(name)
    limit_html = f'<p class="notice"><strong>Sandbox limit:</strong> {escape(sandbox_limit)}</p>' if sandbox_limit else ''
    limit_text = f'SANDBOX LIMIT: {sandbox_limit}\n\n' if sandbox_limit else ''
    risk_html = '<h2>Risk and prerequisites</h2><pre>'+escape(json.dumps(risk,indent=2))+'</pre>'
    # The profile pin, with the DEMO approval label next to any approver name.
    profile_line = approval_text(engine.policy_pin)
    report = f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>DBGuardAI review report</title><style>body{{font:15px/1.5 system-ui;margin:32px;color:#21343b;max-width:1100px}}table{{border-collapse:collapse;width:100%}}td,th{{padding:10px;border:1px solid #cbd5db;text-align:left;overflow-wrap:anywhere}}th{{background:#eaf4f1}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#f1f4f6;padding:16px}}.notice{{padding:16px;background:#fff3d9}}.table{{overflow:auto}}</style></head><body><h1>DBGuardAI · DBA review</h1><p class="notice">{escape(scope)}</p>{limit_html}<p>Sandbox status: VERIFIED. Target application and real-target reassessment: NOT PERFORMED.</p><p>Run: {escape(result['run_id'])}<br>Source: {escape(handoff.snapshot['envelope']['target_id'])}<br>Spec set: {escape(engine.spec_set_hash)}<br>{escape(profile_line)}</p><h2>Before / after / rollback in the sandbox</h2><div class="table"><table><tr><th>Control</th><th>Title</th><th>Before</th><th>After fix</th><th>After rollback</th></tr>{rows}</table></div>{notice_html}<p>{len(attempts)} attempt(s). All attempt resources removed. Exact rollback and database health verified.</p>{risk_html}<h2>DBA verification</h2><p>Run verify.sh after each complete fix. It opens fresh connections, reads the catalogue, tests a transaction and checks all scoped settings. Run the listed application checks separately.</p><h2>Reviewed apply SQL</h2><pre>{escape(result['rendered_apply_sql'])}</pre><h2>Rollback SQL</h2><pre>{escape(result['rendered_rollback_sql'])}</pre><h2>Limits</h2><p>PostgreSQL 17; reviewed configuration policies. Restart settings require a DBA-controlled restart on the target. Regression coverage is limited to the supplied specs. Configuration provenance is restored semantically, not byte-for-byte file formatting.</p><p>The script requires an explicit target connection and refuses configuration drift. A database name and matching settings do not uniquely identify a server: the DBA must verify the target. Advisory locking coordinates DBGuard runs only; other administrators can still change configuration.</p><p>After applying, recollect and reassess the target using the same specs. Review README.txt and the bundled evidence before running harden.sh.</p></body></html>'''
    shots_files, shots_html, shots_text = stage_screenshots(final.get('terminal_evidence'))
    report = report.replace('</body>', shots_html + '</body>', 1)
    files = {'fix.json': json.dumps(config, indent=2).encode(),
             'evidence.json': json.dumps({'handoff': handoff.model_dump(), 'result': bundled_result(result)}, indent=2).encode(),
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
    files.update(shots_files)  # Task 2 stage screenshots, listed in the manifest
    manifest = {'schema_version' :'review-bundle-v1', 'run_id':result['run_id'], 'demo_fixture_approval':demo,
                'requires_dba_review':True, 'snapshot_hash':result['snapshot_hash'], 'spec_set_hash':engine.spec_set_hash,
                'files':{name:hashlib.sha256(data).hexdigest() for name,data in files.items()}}
    files['manifest.json'] = json.dumps(manifest, indent=2).encode()
    files['README.txt'] = (f'''{scope}\n{profile_line}\n\n{limit_text}Review report.html, evidence.json and both SQL commands before any execution.\nRequires Python 3 and psycopg2 (requirements-sandbox.txt includes psycopg2-binary).\nSet DBGUARD_DSN to the DBA-verified target using your normal credential handling.\nNo credentials are included. Verify server identity separately.\n\nsh harden.sh status {fix["fix_id"]}\nsh harden.sh apply {fix["fix_id"]} --ack-prerequisites\nsh harden.sh rollback {fix["fix_id"]}\n\nsh verify.sh {fix["fix_id"]} --screenshots\n\nVerification captures actual database query output, not model-generated content.\nScreenshot dependencies: pip install playwright; python3 -m playwright install chromium.\nImages show a browser evidence viewer populated with actual query results.\nReview and perform application-specific checks in risk-review.json separately.\nFor restart settings, apply/rollback stages the configuration; the DBA restarts\nPostgreSQL outside this tool, then runs verify (or verify-rollback).\nRecollect the target with the original collector and reassess via the application.\n\nDemo bundles require --allow-demo and must only be used with disposable databases.\nThe runner checks PostgreSQL version, database name and configuration provenance.\nIt checks all scoped settings for drift before apply or rollback, and uses fresh\nconnections to verify the resulting settings and source. It never applies automatically.\nIf SQL executes but verification fails, inspect the server before retrying.\nRollback refuses drift; it is not a disaster recovery tool. Recollect and reassess\nthe real target after applying. The manifest detects accidental changes, not forgery.\n''' + shots_text).encode()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return buffer.getvalue()


# ---------------------------------------------------------------------------
# Wave 2a: per-object fixes. Same member allowlist and manifest as setting fixes.
# ---------------------------------------------------------------------------

OBJECT_REHEARSAL_TEXT = (
    "\nWHAT WAS REHEARSED: each object fix ran on a stand-in copy in a disposable sandbox:\n"
    "the target object with the same name, owner, attributes and permissions, and the roles\n"
    "it needs. The copy holds no real data, no function bodies and no real passwords (a\n"
    "random throwaway password stood in where the original role had one).\n"
    "WHAT WAS NOT REHEARSED: how your applications use the object. Removing a privilege,\n"
    "an attribute or a login can break an application or a scheduled job that relies on it.\n"
)

ROLE_FIELDS = ('rolsuper', 'rolinherit', 'rolcreaterole', 'rolcreatedb', 'rolcanlogin',
               'rolreplication', 'rolbypassrls', 'rolconnlimit')


def _valid_until(value):
    """rolvaliduntil in one timezone-independent form (UTC, microseconds)."""
    from datetime import datetime, timezone
    if value is None or value in ('infinity', '-infinity'):
        return value
    require(isinstance(value, str), 'unreadable role expiry')
    parsed = datetime.fromisoformat(value[:-1] + '+00:00' if value.endswith('Z') else value)
    require(parsed.tzinfo is not None, 'role expiry has no timezone')
    return parsed.astimezone(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.%f')


def object_fingerprint(proposal, snapshot):
    """The target object's state as the bundle runner reads it from the target.

    Built from collected evidence in exactly the runner's shape (runner.object_fingerprint):
    the pg_roles row, the table's owner/relacl/RLS flags, or the function's owner,
    prosecdef, proacl and pinned search_path. ACLs are compared as sets: a GRANT
    re-appends an entry that a REVOKE removed, which changes order but not privileges.
    """
    from .catalog_skeleton import FUNCTION_FIX_TYPES, ROLE_FIX_TYPES, TABLE_FIX_TYPES
    baseline = snapshot['baseline']
    target, fix_type = proposal['target'], proposal['fix_type']
    if fix_type in ROLE_FIX_TYPES:
        rows = [r for r in baseline.get('roles') or [] if r.get('rolname') == target['role']]
        require(len(rows) == 1, 'target role is not in the evidence')
        return {'kind': 'role', 'rolname': target['role'], **{k: rows[0][k] for k in ROLE_FIELDS},
                'rolvaliduntil': _valid_until(rows[0]['rolvaliduntil'])}
    if fix_type in TABLE_FIX_TYPES:
        rows = [r for r in baseline.get('object_acls') or []
                if r.get('schema') == target['schema'] and r.get('name') == target['table']]
        require(len(rows) == 1, 'target table is not in the evidence')
        row = rows[0]
        return {'kind': 'table', 'schema': row['schema'], 'name': row['name'], 'relkind': row['kind'],
                'owner': row['owner'], 'acl': None if row['acl'] is None else sorted(row['acl']),
                'rls': row['rls'], 'rls_forced': row['rls_forced']}
    if fix_type in FUNCTION_FIX_TYPES:
        rows = [r for r in baseline.get('functions') or []
                if r.get('schema') == target['schema'] and r.get('name') == target['name']
                and r.get('identity_args') == target['identity_args']]
        require(len(rows) == 1, 'target function is not in the evidence')
        row = rows[0]
        return {'kind': 'function', 'schema': row['schema'], 'name': row['name'],
                'identity_args': row['identity_args'], 'prokind': row['kind'], 'owner': row['owner'],
                'prosecdef': row['prosecdef'], 'acl': sorted(row['acl']),
                'search_path': row['search_path'], 'config_names': list(row['config_names'])}
    raise ContractError('Review bundle: unsupported object fix type')


def build_object_review_bundle(handoff, result, engine):
    from . import object_fixes
    from .catalog_skeleton import target_key
    from .workflow import object_risk_review, object_statements
    require(result.get('status') == 'VERIFIED', 'only VERIFIED runs are exportable')
    require(result.get('approval_source') == 'registry', 'registry approval evidence is required')
    require(result.get('snapshot_hash') == digest(handoff.snapshot), 'snapshot identity mismatch')
    require(result.get('spec_set_hash') == engine.spec_set_hash == handoff.spec_set_hash, 'spec identity mismatch')
    require(result.get('spec_hashes') == engine.hashes and result.get('collector_hash') == engine.collector_hash, 'collector/spec evidence mismatch')
    require(result.get('policy_profile') == engine.policy_pin, 'policy profile differs from the tested run')
    fix, proposal = result['fix_unit'], result['proposal']
    require(result.get('fix_unit_hash') == digest(fix), 'fix-unit identity mismatch')
    require(fix['fix_id'] == proposal['fix_id'] == handoff.object_fix_id, 'fix differs from the selected object fix')
    require(fix['spec_id'] == proposal['spec_id'] == handoff.control_id and fix['requires'] == 'none', 'unsupported fix')
    from .shared import ROOT, validate_contract
    if (ROOT / 'catalog/specs/contracts/fix-unit-v2.json').is_file():
        validate_contract(fix, 'fix-unit-v2.json')
    # Re-derived from the bound evidence: a stored proposal cannot widen the fix.
    require(object_fixes.resolve(engine, handoff.snapshot, engine.policy_pin, fix['fix_id']) == proposal,
            'proposal differs from the evidence-derived proposal')
    template = result['template']
    ref = handoff.template_ref
    require(template['registry_name'] == ref.registry_name == proposal['fix_type'] and template['version'] == ref.version
            and template['sha256'] == ref.sha256, 'selected template was not pinned in the handoff')
    pins = [{k: e.get(k) for k in ('document_id', 'version', 'sha256')} for e in template['evidence']]
    require(pins == [p.model_dump() for p in ref.evidence], 'evidence reference mismatch')
    apply, rollback = object_statements({'apply': fix['apply']['statements'], 'rollback': fix['rollback']['statements']},
                                        proposal['fix_type'])
    require(result['rendered_apply_sql'] == '\n'.join(apply) and result['rendered_rollback_sql'] == '\n'.join(rollback),
            'rendered statements differ from the fix unit')
    # Each statement still has the reviewed shape of its template (object_fixes.STATEMENT_SHAPES).
    require(all(re.fullmatch(object_fixes.STATEMENT_SHAPES[(proposal['fix_type'], action)], sql)
                for action, statements in (('apply', apply), ('rollback', rollback)) for sql in statements),
            'a statement is outside the reviewed template shape')
    attempts = result['attempts']
    require(1 <= len(attempts) <= 3 and all(a.get('cleanup', {}).get('verified') is True for a in attempts), 'attempt cleanup is incomplete')
    final = attempts[-1]
    require(final.get('status') == 'VERIFIED' and final.get('rollback_verified') is True and final.get('health_after_apply') is True and final.get('health_after_rollback') is True, 'acceptance evidence incomplete')
    require(final.get('rendered_apply_sql') == result['rendered_apply_sql'] and final.get('fix_unit_hash') == digest(fix), 'final attempt differs from exported fix')
    before, after, restored = (engine.assess(final[k]) for k in ('before', 'after', 'rollback'))
    require(before == final['before_assessment'] and after == final['after_assessment'] and restored == final['rollback_assessment'], 'assessments do not match snapshots')
    bound = engine.bind_assessment(handoff.snapshot, handoff.assessment)
    require(before['findings'] == bound['findings'] == restored['findings'], 'reproduction or rollback findings differ')
    regressions = [sid for sid, f in before['findings'].items() if is_regression(f['status'], after['findings'][sid]['status']) or sid in engine.gapped_settings(after['findings'])]
    require(not regressions and final.get('regressions') == [] and final.get('other_objects_changed') == [], 'regression evidence is invalid')
    names = [s['check']['setting_name'] for s in engine.specs if 'check' in s and s['check'].get('kind') != 'catalog']
    prior_settings = signature(handoff.snapshot, names)
    require(all(signature(final[k], names) == prior_settings for k in ('before', 'after', 'rollback')), 'an object fix changed configuration settings')
    require(not any(blocking_gaps(s) for s in (final['before'], final['after'], final['rollback'])), 'collection has gaps')
    source_signature = object_fixes.object_signature(proposal, handoff.snapshot)
    require(result.get('source_object_signature') == source_signature, 'source object signature differs')
    require(object_fixes.object_signature(proposal, final['before']) == source_signature == object_fixes.object_signature(proposal, final['rollback']), 'stand-in or rollback object differs from the source')
    require(object_fixes.prior_holds(proposal, final['before']) and object_fixes.prior_holds(proposal, final['rollback']), 'prior state not reproduced')
    require(not object_fixes.predicate(proposal, final['before']) and object_fixes.predicate(proposal, final['after'])
            and not object_fixes.predicate(proposal, final['rollback']), 'object predicate evidence is invalid')
    prior = object_fingerprint(proposal, handoff.snapshot)
    applied = object_fingerprint(proposal, final['after'])
    require(object_fingerprint(proposal, final['before']) == prior == object_fingerprint(proposal, final['rollback']), 'target fingerprint not reproduced or restored')
    require(applied != prior, 'the fix did not change the target object')
    demo = is_fixture(result)
    risk = result.get('risk_review') or object_risk_review(proposal, template.get('risk_level'))
    predicate = fix['verify']['predicate']
    config = {'kind': 'object', 'fix_id': fix['fix_id'], 'fix_type': fix['fix_type'], 'object_key': target_key(proposal),
              'database': handoff.snapshot['envelope']['database'], 'demo_fixture_approval': demo,
              'run_id': result['run_id'], 'control_id': fix['spec_id'], 'requires': 'none', 'transactional': True,
              'target': proposal['target'], 'target_id': handoff.snapshot['envelope']['target_id'],
              'system_identifier': handoff.snapshot['baseline'].get('identity', {}).get('system_identifier'),
              'spec_set_hash': engine.spec_set_hash, 'snapshot_hash': result['snapshot_hash'],
              'policy_profile': engine.policy_pin, 'prior': prior, 'applied': applied,
              'proposal_prior': proposal['prior'], 'predicate': predicate,
              'apply_statements': apply, 'rollback_statements': rollback}
    scope = 'DEMO FIXTURE APPROVAL — not human approval' if demo else 'Registry-approved template and evidence — DBA review still required'
    profile_line = approval_text(engine.policy_pin)
    title = proposal.get('title') or fix['fix_id']
    states = ''.join(f'<tr><td>{escape(label)}</td><td><pre>{escape(json.dumps(object_fingerprint(proposal, final[k]), indent=2))}</pre></td></tr>'
                     for label, k in (('Before (stand-in, equals source evidence)', 'before'), ('After fix', 'after'), ('After rollback', 'rollback')))
    report = f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>DBGuardAI review report</title><style>body{{font:15px/1.5 system-ui;margin:32px;color:#21343b;max-width:1100px}}table{{border-collapse:collapse;width:100%}}td,th{{padding:10px;border:1px solid #cbd5db;text-align:left;overflow-wrap:anywhere}}th{{background:#eaf4f1}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#f1f4f6;padding:16px}}.notice{{padding:16px;background:#fff3d9}}</style></head><body><h1>DBGuardAI · DBA review</h1><p class="notice">{escape(scope)}</p><p>Sandbox status: VERIFIED. Target application and real-target reassessment: NOT PERFORMED.</p><p>Run: {escape(result['run_id'])}<br>Source: {escape(handoff.snapshot['envelope']['target_id'])}<br>Spec set: {escape(engine.spec_set_hash)}<br>{escape(profile_line)}</p><h2>{escape(title)}</h2><p>{escape(str(proposal.get('explanation') or ''))}</p><p><strong>Proof checked after the fix:</strong> {escape(predicate)}</p><p class="notice"><strong>What was rehearsed:</strong> the fix on a stand-in copy of this object (same name, owner, attributes and permissions) in a disposable sandbox. No real data, no function bodies and no real passwords were copied. <strong>What was not rehearsed:</strong> how your applications use this object.</p><h2>Object state in the sandbox</h2><table><tr><th>Phase</th><th>Object</th></tr>{states}</table><p>{len(attempts)} attempt(s). All attempt resources removed. Every other recreated object and every scoped setting was unchanged; exact rollback verified.</p><h2>Risk</h2><pre>{escape(json.dumps(risk, indent=2))}</pre><h2>Reviewed apply SQL (one transaction)</h2><pre>{escape(result['rendered_apply_sql'])}</pre><h2>Rollback SQL (one transaction)</h2><pre>{escape(result['rendered_rollback_sql'])}</pre><h2>Limits</h2><p>PostgreSQL 17. The runner checks the PostgreSQL version, database, cluster identity and this object's exact state before and inside the transaction, and refuses if anything differs. After applying, recollect and reassess the target using the same specs.</p></body></html>'''
    shots_files, shots_html, shots_text = stage_screenshots(final.get('terminal_evidence'))
    report = report.replace('</body>', shots_html + '</body>', 1)
    files = {'fix.json': json.dumps(config, indent=2).encode(),
             'evidence.json': json.dumps({'handoff': handoff.model_dump(), 'result': bundled_result(result)}, indent=2).encode(),
             'report.html': report.encode(), 'runner.py': (ASSETS/'runner.py').read_bytes(),
             'harden.sh': b'#!/bin/sh\nset -eu\nBUNDLE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)\nexec python3 "$BUNDLE_DIR/runner.py" "$@"\n'}
    files['risk-review.json'] = json.dumps(risk, indent=2).encode()
    files['visual_evidence.py'] = (ASSETS/'visual_evidence.py').read_bytes()
    files['verify.sh'] = b'#!/bin/sh\nset -eu\nBUNDLE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)\nexec python3 "$BUNDLE_DIR/runner.py" verify "$@"\n'
    files.update(shots_files)  # Task 2 stage screenshots, listed in the manifest
    manifest = {'schema_version': 'review-bundle-v1', 'run_id': result['run_id'], 'demo_fixture_approval': demo,
                'requires_dba_review': True, 'snapshot_hash': result['snapshot_hash'], 'spec_set_hash': engine.spec_set_hash,
                'files': {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}}
    files['manifest.json'] = json.dumps(manifest, indent=2).encode()
    files['README.txt'] = (f'''{scope}\n{profile_line}\n\nFix: {title}\nProof checked after the fix: {predicate}\n{OBJECT_REHEARSAL_TEXT}\nReview report.html, evidence.json and both SQL commands before any execution.\nRequires Python 3 and psycopg2 (requirements-sandbox.txt includes psycopg2-binary).\nSet DBGUARD_DSN to the DBA-verified target using your normal credential handling.\nNo credentials are included. Verify server identity separately.\n\nsh harden.sh status {fix["fix_id"]}\nsh harden.sh apply {fix["fix_id"]} --ack-prerequisites\nsh harden.sh rollback {fix["fix_id"]}\n\nsh verify.sh {fix["fix_id"]}\n\nThe runner checks PostgreSQL version, database name, cluster identity and that this one\nobject is still exactly as it was in the evidence. It applies (and rolls back) inside one\ntransaction, re-reads the object before COMMIT and rolls the transaction back if the\nresult is not exactly the tested state. It never applies automatically.\nRecollect the target with the original collector and reassess via the application.\nDemo bundles require --allow-demo and must only be used with disposable databases.\nThe manifest detects accidental changes, not forgery.\n''' + shots_text).encode()
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
        for name, data in files.items():
            archive.writestr(name, data)
    return buffer.getvalue()


# ---------------------------------------------------------------------------
# W2B gate 1: catalog-linked setting fixes (3.2 pgaudit, 5.6 passwordcheck, 6.10 ciphers).
# ---------------------------------------------------------------------------

PRELOAD_README = (
    "\nPACKAGE PREREQUISITE AND RESTART: this fix adds {libs} to shared_preload_libraries.\n"
    "Install the library on the server first (pgaudit: the postgresql-17-pgaudit package;\n"
    "passwordcheck ships with PostgreSQL). If a preloaded library is missing, PostgreSQL does\n"
    "NOT start. Before apply, the runner loads each added library in a throwaway session\n"
    "(LOAD) and refuses with 'install the package first; no SQL executed' if it cannot.\n"
    "apply and rollback only stage the change: the DBA restarts PostgreSQL in a maintenance\n"
    "window, then runs verify (or verify-rollback).\n")
TLS_README = (
    "\nTLS: the sandbox switched ssl on with a throwaway self-signed certificate that never left\n"
    "it. This bundle does NOT switch ssl on; that is CIS 6.8's guided step with your own\n"
    "certificate. Existing TLS 1.2 sessions keep their cipher until they reconnect.\n")


def build_catalog_review_bundle(handoff, result, engine):
    from . import catalog_fixes as cf
    from app.services.spec_engine.catalog_checks import notices_for
    require(result.get('status') == 'VERIFIED', 'only VERIFIED runs are exportable')
    require(result.get('approval_source') == 'registry', 'registry approval evidence is required')
    require(result.get('snapshot_hash') == digest(handoff.snapshot), 'snapshot identity mismatch')
    require(result.get('spec_set_hash') == engine.spec_set_hash == handoff.spec_set_hash, 'spec identity mismatch')
    require(result.get('spec_hashes') == engine.hashes and result.get('collector_hash') == engine.collector_hash, 'collector/spec evidence mismatch')
    require(result.get('policy_profile') == engine.policy_pin, 'policy profile differs from the tested run')
    fix = result['fix_unit']
    require(result.get('fix_unit_hash') == digest(fix), 'fix-unit identity mismatch')
    control = handoff.control_id
    require(not getattr(handoff, 'object_fix_id', None) and not handoff.retry_template_refs, 'unsupported handoff')
    # Re-derived from the bound evidence and the approved profile: a stored fix cannot widen it.
    scope = cf.catalog_fix_scope(engine, handoff.snapshot, control)
    require(fix == cf.build_fix(scope, fix['template_version'], fix.get('list_template_version')),
            'fix differs from the evidence-derived catalog fix')
    list_ref, list_template = handoff.list_template_ref, result.get('list_template')
    require((list_ref is None) == (list_template is None) == ('list_template_id' not in fix), 'list template pin mismatch')
    if list_ref is not None:
        require(list_ref.registry_name == list_template['registry_name'] == cf.LIST_TEMPLATE
                and list_template['version'] == list_ref.version == fix['list_template_version']
                and list_template['sha256'] == list_ref.sha256
                and [{k: e.get(k) for k in ('document_id', 'version', 'sha256')} for e in list_template['evidence']]
                == [p.model_dump() for p in list_ref.evidence], 'list template was not pinned in the handoff')
    template, ref = result['template'], handoff.template_ref
    require(ref.registry_name == cf.TEMPLATE_NAME and template['registry_name'] == ref.registry_name
            and template['version'] == ref.version == fix['template_version'] and template['sha256'] == ref.sha256,
            'selected template was not pinned in the handoff')
    pins = [{k: e.get(k) for k in ('document_id', 'version', 'sha256')} for e in template['evidence']]
    require(pins == [p.model_dump() for p in ref.evidence], 'evidence reference mismatch')
    statements = result['rendered_apply_statements']
    require(len(statements) == len(fix['changes']) and result['rendered_apply_sql'] == '\n'.join(statements),
            'rendered statements differ from the fix')
    apply_statements = []
    from .workflow import list_template_action
    for sql, change in zip(statements, fix['changes']):
        if change['template'] == cf.LIST_TEMPLATE:
            action = list_template_action(sql)
            require(action == change['apply'], 'typed action differs from tested list template')
            apply_statements += render_action(action)
        else:
            require(template_action(sql, change['param']) == change['apply'], 'typed action differs from tested template')
            apply_statements += canonical_apply(sql, change['param'], change['apply']['value'])
    require(result['rendered_rollback_sql'] == cf.rollback_sql(fix), 'rendered rollback differs')
    rollback_statements = [s + ';' for c in reversed(fix['changes']) for s in render_action(c['rollback'])]
    attempts = result['attempts']
    require(1 <= len(attempts) <= 3 and all(a.get('cleanup', {}).get('verified') is True for a in attempts), 'attempt cleanup is incomplete')
    final = attempts[-1]
    require(final.get('status') == 'VERIFIED' and final.get('rollback_verified') is True and final.get('health_after_apply') is True
            and final.get('health_after_rollback') is True and final.get('functional_checks', {}).get('passed') is True,
            'acceptance evidence incomplete')
    require(final.get('rendered_apply_sql') == result['rendered_apply_sql'] and final.get('fix_unit_hash') == digest(fix),
            'final attempt differs from exported fix')
    before, after, restored = (engine.assess(final[k]) for k in ('before', 'after', 'rollback'))
    require(before == final['before_assessment'] and after == final['after_assessment'] and restored == final['rollback_assessment'],
            'assessments do not match snapshots')
    bound = engine.bind_assessment(handoff.snapshot, handoff.assessment)
    require(before['findings'] == bound['findings'] == restored['findings'], 'reproduction or rollback findings differ')
    # The proof, recomputed server-side from the recorded collections with the approved profile.
    proof = {k: cf.proof(engine, scope['spec'], final[k]) for k in ('before', 'after', 'rollback')}
    require(proof == final.get('catalog_proof') and proof['before']['result'] == 'FAIL'
            and proof['after']['result'] == 'PASS' and proof['rollback'] == proof['before'], 'catalog check proof is invalid')
    regressions = [sid for sid, f in before['findings'].items()
                   if is_regression(f['status'], after['findings'][sid]['status']) or sid in engine.gapped_settings(after['findings'])]
    regressions += cf.catalog_regressions(engine, before, after, [c['param'] for c in fix['changes']], control)
    require(not regressions and final.get('regressions') == [], 'regression evidence is invalid')
    from .provenance import reconstruction_plan
    plan = reconstruction_plan(handoff.snapshot, engine.specs, cf.reconstruction_names(engine, handoff.snapshot, scope))
    names = cf.fix_names(engine, scope, plan)
    require(result.get('names') == names, 'scoped setting names differ')
    prior = cf.catalog_signature(handoff.snapshot, names)
    require(cf.catalog_signature(final['before'], names) == prior == cf.catalog_signature(final['rollback'], names),
            'exact rollback provenance differs')
    require(not any(blocking_gaps(s) for s in (final['before'], final['after'], final['rollback'])), 'collection has gaps')
    applied = cf.catalog_signature(final['after'], names)
    require(all(applied['settings'].get(c['param'], {}).get('setting') == c['expected_value'] for c in fix['changes']),
            'the fix values are not the applied values')
    if scope['tls']:
        require(all(k in final for k in ('tls_before', 'tls_after', 'tls_rollback')) and cf.tls_fixed(final['tls_after'])
                and cf._same_tls(final['tls_rollback'], final['tls_before']), 'TLS handshake evidence is invalid')
    demo = is_fixture(result)
    risk = result.get('risk_review') or cf.catalog_risk_review(engine, handoff.snapshot, control, scope=scope)
    link = scope['link']
    config = {'kind': 'catalog_setting', 'fix_id': fix['fix_id'], 'database': handoff.snapshot['envelope']['database'],
              'demo_fixture_approval': demo, 'names': names, 'prior': prior,
              'run_id': result['run_id'], 'control_id': control, 'setting': fix['changes'][0]['param'],
              'settings': [c['param'] for c in fix['changes']], 'requires': fix['requires'],
              'preload_added': list(fix['preload_added']),
              'target_id': handoff.snapshot['envelope']['target_id'],
              'system_identifier': handoff.snapshot['baseline'].get('identity', {}).get('system_identifier'),
              'spec_set_hash': engine.spec_set_hash, 'snapshot_hash': result['snapshot_hash'],
              'policy_profile': engine.policy_pin, 'applied': applied,
              'apply_statements': apply_statements, 'rollback_statements': rollback_statements}
    scope_line = 'DEMO FIXTURE APPROVAL — not human approval' if demo else 'Registry-approved template and evidence — DBA review still required'
    profile_line = approval_text(engine.policy_pin)
    title = scope['spec']['ref']['title']
    proof_rows = ''.join(f'<tr><td>{escape(label)}</td><td>{escape(proof[k]["result"])}</td><td>{escape(str(proof[k]["code"]))}</td></tr>'
                         for label, k in (('Before (reproduced source)', 'before'), ('After fix', 'after'), ('After rollback', 'rollback')))
    changes_html = ''.join(f'<tr><td>{escape(c["param"])}</td><td>{escape(str((c["prior_state"] or {}).get("value", "(not defined)")))}</td>'
                           f'<td>{escape(c["expected_value"])}</td></tr>' for c in fix['changes'])
    tls_html = ''
    if scope['tls']:
        tls_html = ('<h2>TLS 1.2 handshakes in the sandbox (loopback, throwaway certificate)</h2><pre>'
                    + escape(json.dumps({k: final[k] for k in ('tls_before', 'tls_after', 'tls_rollback')}, indent=2)) + '</pre>')
    notice_html = ''.join(f'<p class="notice">{escape(n["text"])}</p>' for n in notices_for(link['recommendation']))
    extra_readme = (PRELOAD_README.format(libs=', '.join(fix['preload_added'])) if fix['preload_added'] else '') + (TLS_README if scope['tls'] else '')
    report = f'''<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>DBGuardAI review report</title><style>body{{font:15px/1.5 system-ui;margin:32px;color:#21343b;max-width:1100px}}table{{border-collapse:collapse;width:100%}}td,th{{padding:10px;border:1px solid #cbd5db;text-align:left;overflow-wrap:anywhere}}th{{background:#eaf4f1}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#f1f4f6;padding:16px}}.notice{{padding:16px;background:#fff3d9}}</style></head><body><h1>DBGuardAI · DBA review</h1><p class="notice">{escape(scope_line)}</p><p>Sandbox status: VERIFIED. Target application and real-target reassessment: NOT PERFORMED.</p><p>Run: {escape(result['run_id'])}<br>Source: {escape(handoff.snapshot['envelope']['target_id'])}<br>Spec set: {escape(engine.spec_set_hash)}<br>{escape(profile_line)}</p><h2>CIS {escape(link['recommendation'])}: {escape(title)}</h2><table><tr><th>Setting</th><th>Before</th><th>Fix value</th></tr>{changes_html}</table><p class="notice">{escape(extra_readme.strip())}</p><h2>Proof: the CIS check in the sandbox</h2><table><tr><th>Phase</th><th>Result</th><th>Reason</th></tr>{proof_rows}</table>{notice_html}{tls_html}<p>{len(attempts)} attempt(s). All attempt resources removed. Exact rollback and database health verified.</p><h2>Risk and prerequisites</h2><pre>{escape(json.dumps(risk, indent=2))}</pre><h2>Reviewed apply SQL</h2><pre>{escape(result['rendered_apply_sql'])}</pre><h2>Rollback SQL</h2><pre>{escape(result['rendered_rollback_sql'])}</pre><h2>Limits</h2><p>PostgreSQL 17; reviewed catalog-linked configuration fix. The runner checks the PostgreSQL version, database, cluster identity and every scoped setting before apply or rollback, and refuses drift. After applying, recollect and reassess the target using the same specs.</p></body></html>'''
    shots_files, shots_html, shots_text = stage_screenshots(final.get('terminal_evidence'))
    report = report.replace('</body>', shots_html + '</body>', 1)
    files = {'fix.json': json.dumps(config, indent=2).encode(),
             'evidence.json': json.dumps({'handoff': handoff.model_dump(), 'result': bundled_result(result)}, indent=2).encode(),
             'report.html': report.encode(), 'runner.py': (ASSETS/'runner.py').read_bytes(),
             'harden.sh': b'#!/bin/sh\nset -eu\nBUNDLE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)\nexec python3 "$BUNDLE_DIR/runner.py" "$@"\n'}
    files['risk-review.json'] = json.dumps(risk, indent=2).encode()
    files['visual_evidence.py'] = (ASSETS/'visual_evidence.py').read_bytes()
    files['verify.sh'] = b'#!/bin/sh\nset -eu\nBUNDLE_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)\nexec python3 "$BUNDLE_DIR/runner.py" verify "$@"\n'
    files.update(shots_files)  # Task 2 stage screenshots, listed in the manifest
    manifest = {'schema_version': 'review-bundle-v1', 'run_id': result['run_id'], 'demo_fixture_approval': demo,
                'requires_dba_review': True, 'snapshot_hash': result['snapshot_hash'], 'spec_set_hash': engine.spec_set_hash,
                'files': {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}}
    files['manifest.json'] = json.dumps(manifest, indent=2).encode()
    files['README.txt'] = (f'''{scope_line}\n{profile_line}\n\nFix: CIS {link['recommendation']} {title}\nProof: the CIS check gave FAIL, then PASS after the fix and FAIL again after rollback, in a disposable sandbox.\n{extra_readme}\nReview report.html, evidence.json and the SQL before any execution.\nRequires Python 3 and psycopg2 (requirements-sandbox.txt includes psycopg2-binary).\nSet DBGUARD_DSN to the DBA-verified target using your normal credential handling.\nNo credentials are included. Verify server identity separately.\n\nsh harden.sh status {fix["fix_id"]}\nsh harden.sh apply {fix["fix_id"]} --ack-prerequisites\nsh harden.sh rollback {fix["fix_id"]}\n\nsh verify.sh {fix["fix_id"]}\n\nThe runner checks PostgreSQL version, database name, cluster identity and every scoped\nsetting and its configuration source for drift before apply or rollback. It never applies\nautomatically. Recollect the target with the original collector and reassess via the\napplication. Demo bundles require --allow-demo and must only be used with disposable\ndatabases. The manifest detects accidental changes, not forgery.\n''' + shots_text).encode()
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
