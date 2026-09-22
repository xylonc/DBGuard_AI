"""Narrow bridge from the existing dbguard-collect.sh v0.2 JSON to spec evidence.

Only unitless boolean/enum SHOW checks can use pg_settings.setting verbatim.
This is a documented projection of collected evidence, not a new live query.
"""
import copy

from app.collector_models import CollectorBundleV020
from .provenance import reconstruction_plan
from .shared import ContractError, digest, validate_contract


def from_collector_bundle(bundle, engine):
    CollectorBundleV020.model_validate(bundle)
    if bundle.get('gaps'):
        raise ContractError('Collector bundle has gaps; recollect with sufficient access')
    baseline = copy.deepcopy(bundle)
    envelope = baseline.pop('envelope')
    rows = baseline.get('settings')
    if not isinstance(rows, list) or len({r.get('name') for r in rows}) != len(rows):
        raise ContractError('Collector settings must be present and unique')
    settings = {r['name']: r for r in rows}
    checks = {}
    for spec in engine.specs:
        sid, check = spec['spec_id'], spec.get('check')
        entry = {'spec_hash':engine.hashes[sid], 'query':check['query'] if check else 'not applicable', 'status':'not_collected'}
        if check:
            row = settings.get(check['setting_name'])
            if not row or row.get('vartype') not in ('bool', 'enum') or row.get('unit') is not None or row.get('sanitised') is not False or not isinstance(row.get('setting'), str):
                raise ContractError(f'Cannot project exact SHOW evidence for {sid}; use spec-driven collection')
            entry.update(status='ok', result=row['setting'])
        checks[sid] = entry
    baseline['dbguard_intake'] = {'adapter':'collector-v020-settings-v1', 'source_bundle_hash':digest(bundle),
                                  'evidence_origin':'pg_settings projection; no additional SHOW queries executed'}
    snapshot = {'envelope':envelope, 'baseline':baseline, 'checks':checks}
    validate_contract(snapshot, 'snapshot-v0.3.0.json')
    engine.assess(snapshot)
    reconstruction_plan(snapshot, engine.specs)
    return snapshot
