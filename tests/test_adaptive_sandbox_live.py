"""Real PostgreSQL adaptive retest with a scripted LLM response, not a live model."""
from dataclasses import replace
import hashlib
import os
from unittest.mock import Mock

import pytest

from services.sandbox_poc.demo import DemoResources
from services.sandbox_poc.runtime import docker, LABEL
from services.sandbox_poc.templates import from_registry
from services.sandbox_poc.workflow import RemediationLoop

pytestmark = pytest.mark.skipif(os.environ.get('DBGUARD_POC_LIVE') != '1', reason='Requires disposable Docker databases')


def test_live_failed_candidate_is_revised_and_verified():
    resources = DemoResources()
    try:
        resources.start()
        ref = resources.handoff.template_ref
        good = from_registry(resources.registry_url, ref.version, ref.sha256,
                              [e.document_id for e in ref.evidence], ref.environment,
                              evidence_pins=[e.model_dump() for e in ref.evidence])
        # Deliberately faulty test fixture: keep logging off so acceptance fails.
        # Never added to or described as a team-approved registry record.
        sql = "ALTER SYSTEM SET log_connections = 'off'; SELECT pg_reload_conf();"
        bad = replace(good, sql=sql, sha256=hashlib.sha256(sql.encode()).hexdigest(), version=999)
        model = Mock(return_value={'action':'retry', 'candidate_id':'alternative-1',
            'diagnosis':'The candidate kept the setting off.',
            'proposed_improvement':'Use the approved on-setting candidate.'})
        result = RemediationLoop(resources.engine, bad, reviser=model, alternatives=[good]).run(
            resources.snapshot, resources.handoff.assessment)
        assert result['status'] == 'VERIFIED', result
        assert len(result['attempts']) == 2 and model.call_count == 1
        assert result['attempts'][0]['status'] == 'FAILED'
        assert all(a['rollback_verified'] and a['cleanup']['verified'] for a in result['attempts'])
        assert result['fix_unit']['apply'] == good.render()
        assert resources.source_evidence()['source_unchanged']
        assert resources.source_evidence()['registry_unchanged']
        for attempt in result['attempts']:
            assert not docker('ps', '-aq', '--filter', f"label={LABEL}={attempt['run_id']}")
    finally:
        resources.close()
