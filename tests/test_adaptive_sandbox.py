import copy
from dataclasses import replace
import hashlib
from unittest.mock import Mock

import pytest

from scripts.sandbox_poc import demo_template
from services.sandbox_poc.adaptive import LLMReviser, RevisionDecision
from services.sandbox_poc.shared import ContractError, SpecEngine
from services.sandbox_poc.workflow import RemediationLoop
from test_sandbox_poc import engine, snapshot, FakeRuntime


def candidate(sql, version):
    return replace(demo_template(), sql=sql, version=version,
                   sha256=hashlib.sha256(sql.encode()).hexdigest(),
                   evidence=({'document_id':'unit-fixture', 'version':'1',
                              'sha256':'a'*64, 'approved_by':'TEST FIXTURE ONLY'},))


BAD = "ALTER SYSTEM SET log_connections = 'off'; SELECT pg_reload_conf();"
GOOD = "ALTER SYSTEM SET log_connections = 'on'; SELECT pg_reload_conf();"


def run_adaptive(engine, snapshot, monkeypatch, decision, alternatives=None, faults=('apply', None)):
    runtimes = []
    def factory():
        runtime = FakeRuntime(snapshot, len(runtimes)+1, faults[min(len(runtimes), len(faults)-1)])
        runtimes.append(runtime)
        return runtime
    monkeypatch.setattr(SpecEngine, 'collect', lambda _, runtime: copy.deepcopy(runtime.snapshot))
    reviewer = Mock(side_effect=decision) if isinstance(decision, Exception) else Mock(return_value=decision)
    result = RemediationLoop(engine, candidate(BAD, 1), factory, reviser=reviewer,
                            alternatives=alternatives or [candidate(GOOD, 2)]).run(snapshot, engine.assess(snapshot))
    return result, runtimes, reviewer


def retry(which='alternative-1'):
    return {'action':'retry', 'candidate_id':which, 'diagnosis':'The previous candidate failed.',
            'proposed_improvement':'Use the approved corrected value and rerun the checks.'}


def test_failed_attempt_routes_through_llm_to_changed_approved_fix(engine, snapshot, monkeypatch):
    result, runtimes, reviewer = run_adaptive(engine, snapshot, monkeypatch, retry())
    assert result['status'] == 'VERIFIED'
    assert len(result['attempts']) == 2 and all(r.closed for r in runtimes)
    assert result['template']['version'] == 2
    assert result['rendered_apply_sql'] == GOOD
    assert result['attempts'][0]['fix_unit_hash'] != result['attempts'][1]['fix_unit_hash']
    assert result['attempts'][1]['rollback_verified']
    assert reviewer.call_count == 1
    feedback = reviewer.call_args.args[0]
    assert feedback['failure_phase'] == 'apply'
    assert feedback['tested_sql'] == BAD
    assert feedback['setting_metadata']['before_apply'] == {
        'setting': 'off', 'context': 'superuser-backend', 'pending_restart': False}
    assert feedback['setting_metadata']['after_apply'] == {}  # Never fabricate a measurement.
    assert 'sourcefile' not in str(feedback) and 'source' not in feedback['setting_metadata']
    assert 'baseline' not in feedback and 'snapshot' not in feedback


@pytest.mark.parametrize('decision', [retry('invented-id'),
    {**retry(), 'sql':'DROP TABLE users'}, ContractError('model-secret-token'),
    {'action':'manual_review', 'candidate_id':None, 'diagnosis':'No approved correction.',
     'proposed_improvement':'Ask a reviewer to approve a suitable template.'}])
def test_invalid_or_manual_revision_stops_without_second_container(engine, snapshot, monkeypatch, decision):
    result, runtimes, _ = run_adaptive(engine, snapshot, monkeypatch, decision)
    assert result['status'] == 'NEEDS_REVIEW'
    assert len(runtimes) == 1 and runtimes[0].closed
    assert 'model-secret-token' not in str(result)


def test_cosmetic_candidate_is_not_a_revised_fix(engine, snapshot, monkeypatch):
    result, runtimes, reviewer = run_adaptive(engine, snapshot, monkeypatch, retry(),
        alternatives=[candidate('-- cosmetic\n'+BAD, 2)])
    assert result['status'] == 'NEEDS_REVIEW' and len(runtimes) == 1
    assert reviewer.call_args.args[0]['available_candidates'] == []


def test_adaptive_loop_keeps_three_attempt_cap(engine, snapshot, monkeypatch):
    runtimes = []
    def factory():
        r = FakeRuntime(snapshot, len(runtimes)+1, 'apply'); runtimes.append(r); return r
    monkeypatch.setattr(SpecEngine, 'collect', lambda _, r: copy.deepcopy(r.snapshot))
    reviewer = Mock(side_effect=[retry('alternative-1'), retry('alternative-2')])
    result = RemediationLoop(engine, candidate(BAD, 1), factory, reviser=reviewer,
        alternatives=[candidate(GOOD, 2), candidate(GOOD.replace("'on'", "'true'"), 3)]).run(snapshot, engine.assess(snapshot))
    assert result['status'] == 'FAILED'
    assert len(runtimes) == 3 and reviewer.call_count == 2
    assert all(r.closed for r in runtimes)


def test_cleanup_failure_does_not_call_model(engine, snapshot, monkeypatch):
    result, runtimes, reviewer = run_adaptive(engine, snapshot, monkeypatch, retry(), faults=('cleanup',))
    assert result['status'] == 'CLEANUP_FAILED'
    reviewer.assert_not_called()


def test_model_transport_validates_json_and_masks_errors(monkeypatch):
    import httpx
    response = Mock()
    response.json.return_value = {'choices':[{'message':{'content':RevisionDecision(**retry()).model_dump_json()}}]}
    post = Mock(return_value=response)
    monkeypatch.setattr(httpx, 'post', post)
    review = LLMReviser('https://model.invalid/v1', 'unit-model', 'secret-key')
    assert review({'failure_phase':'apply'}).candidate_id == 'alternative-1'
    assert post.call_args.kwargs['follow_redirects'] is False
    post.side_effect = RuntimeError('secret-key')
    with pytest.raises(ContractError, match='unavailable') as failure:
        review({})
    assert 'secret-key' not in str(failure.value)


def test_revoked_alternative_stops_before_next_attempt(engine, snapshot, monkeypatch):
    runtimes = []
    def factory():
        r = FakeRuntime(snapshot, len(runtimes)+1, 'apply'); runtimes.append(r); return r
    monkeypatch.setattr(SpecEngine, 'collect', lambda _, r: copy.deepcopy(r.snapshot))
    refresh = Mock(side_effect=ContractError('Approval revoked'))
    result = RemediationLoop(engine, candidate(BAD, 1), factory, reviser=Mock(return_value=retry()),
        alternatives=[candidate(GOOD, 2)], refresh_template=refresh).run(snapshot, engine.assess(snapshot))
    assert result['status'] == 'NEEDS_REVIEW' and len(runtimes) == 1
    refresh.assert_called_once()


def test_bundle_binds_to_selected_alternative(engine, snapshot, monkeypatch):
    from services.sandbox_poc.handoff import build_handoff, TemplateReference
    from services.sandbox_poc.review_bundle import build_review_bundle
    def ref(template):
        return TemplateReference(version=template.version, sha256=template.sha256,
            evidence=[{k:e[k] for k in ('document_id','version','sha256')} for e in template.evidence])
    result, _, _ = run_adaptive(engine, snapshot, monkeypatch, retry())
    result.update(approval_source='registry', run_id='unit-adaptive')
    handoff = build_handoff(engine, snapshot, ref(candidate(BAD, 1)))
    handoff.retry_mode = 'adaptive'
    handoff.retry_template_refs = [ref(candidate(GOOD, 2))]
    assert build_review_bundle(handoff, result, engine).startswith(b'PK')
    handoff.retry_template_refs = []
    with pytest.raises(ContractError, match='not pinned'):
        build_review_bundle(handoff, result, engine)


def test_candidates_cannot_change_environment_or_duplicate_identity(engine, snapshot):
    from services.sandbox_poc.handoff import SandboxHandoff, build_handoff, TemplateReference
    ref = TemplateReference(version=1, sha256='a'*64,
        evidence=[{'document_id':'unit','version':'1','sha256':'b'*64}])
    request = build_handoff(engine, snapshot, ref).model_dump()
    request.update(retry_mode='adaptive', retry_template_refs=[ref.model_dump()])
    with pytest.raises(ValueError, match='unique'):
        SandboxHandoff.model_validate(request)
    request['retry_template_refs'][0].update(version=2, environment='prod')
    with pytest.raises(ValueError, match='same environment'):
        SandboxHandoff.model_validate(request)
