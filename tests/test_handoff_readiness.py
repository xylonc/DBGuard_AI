"""Upstream mismatch and approval readiness must fail before any sandbox starts."""
import copy
from dataclasses import replace
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import MagicMock, Mock, patch

import psycopg2
import pytest

from services.sandbox_poc.handoff import SandboxHandoff, build_handoff
from services.sandbox_poc.readiness import check_readiness
from services.sandbox_poc.service import SandboxService
from services.sandbox_poc.shared import ContractError, ROOT
from services.sandbox_poc.templates import ApprovedTemplate, export_reference
from test_sandbox_poc_api import handoff
from test_sandbox_poc import engine, snapshot


def approved(ref):
    # Synthetic unit-test values, never inserted into any real registry.
    from scripts.sandbox_poc import demo_template
    return replace(demo_template(), approved_by='unit-reviewer', evidence=tuple(
        {**entry.model_dump(), 'approved_by': 'unit-reviewer'} for entry in ref.evidence))


@pytest.mark.parametrize('fault', ['snapshot_hash', 'spec_set_hash', 'findings'])
def test_upstream_assessment_mismatch_is_rejected(engine, snapshot, handoff, fault):
    request = SandboxHandoff(**handoff)
    assessment = copy.deepcopy(request.assessment)
    assessment[fault] = {} if fault == 'findings' else '0' * 64
    with pytest.raises(ContractError, match='Upstream assessment'):
        build_handoff(engine, snapshot, request.template_ref, assessment=assessment)


def test_matching_upstream_assessment_is_preserved(engine, snapshot, handoff):
    request = SandboxHandoff(**handoff)
    actual = build_handoff(engine, snapshot, request.template_ref, assessment=request.assessment)
    assert actual == request


@pytest.mark.parametrize('mode', ['input_only', 'invalid', 'approved', 'fixture', 'stale', 'offline', 'unsafe'])
def test_readiness_never_starts_runtime(handoff, mode):
    request = SandboxHandoff(**handoff)
    template = approved(request.template_ref)
    loader, runtime = Mock(return_value=template), Mock(side_effect=AssertionError('Docker forbidden'))
    service = SandboxService('not-a-real-dsn', registry_loader=loader, runtime_factory=runtime)
    if mode == 'invalid':
        request.assessment['snapshot_hash'] = '0' * 64
    if mode == 'fixture':
        loader.return_value = replace(template, approved_by='DEMO_FIXTURE_ONLY')
    if mode == 'stale':
        loader.side_effect = ContractError('Approved evidence version/hash mismatch')
    if mode == 'offline':
        loader.side_effect = psycopg2.OperationalError('password=private-secret')
    if mode == 'unsafe':
        import hashlib
        sql = template.sql + '\nDROP TABLE sensitive;'
        loader.return_value = replace(template, sql=sql, sha256=hashlib.sha256(sql.encode()).hexdigest())
    report = check_readiness(service, request, check_registry=mode != 'input_only')
    runtime.assert_not_called()
    assert report['sandbox_execution'] == 'NOT_RUN'
    if mode in ('input_only', 'invalid'):
        loader.assert_not_called()
    if mode == 'approved':
        assert report['status'] == 'READY_FOR_SANDBOX'
        assert report['ready_for_sandbox'] is True
    elif mode == 'input_only':
        assert report['status'] == 'INPUT_VALID'
        assert report['registry'] == 'NOT_CHECKED'
    else:
        assert report['status'] == 'BLOCKED'
        assert report['ready_for_sandbox'] is False
    assert 'private-secret' not in json.dumps(report)


def test_export_reads_pins_and_rechecks_before_return(handoff):
    ref = SandboxHandoff(**handoff).template_ref
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.fetchone.side_effect = [(ref.sha256,), ('doc-1', '1', 'a' * 64)]
    with patch('psycopg2.connect', return_value=connection), patch(
            'services.sandbox_poc.templates.from_registry', return_value=approved(ref)) as verify:
        result, _ = export_reference('private-dsn', 1, ['doc-1'])
    assert result == ref
    connection.set_session.assert_called_once_with(readonly=True, isolation_level='REPEATABLE READ')
    connection.close.assert_called_once()
    assert verify.call_args.kwargs['evidence_pins'] == [e.model_dump() for e in ref.evidence]
    assert all(call.args[0].lstrip().startswith(('SELECT', 'SET LOCAL')) for call in cursor.execute.call_args_list)


def test_export_does_not_fall_back_to_unapproved_or_latest():
    connection = MagicMock()
    cursor = connection.cursor.return_value.__enter__.return_value
    cursor.fetchone.return_value = None
    with patch('psycopg2.connect', return_value=connection), pytest.raises(ContractError, match='unavailable'):
        export_reference('unused', 7, ['doc-1'])
    assert cursor.execute.call_args.args[1] == ('set_config_parameter', 7)
    connection.close.assert_called_once()


def test_export_rejects_change_between_reads(handoff):
    ref = SandboxHandoff(**handoff).template_ref
    connection = MagicMock()
    connection.cursor.return_value.__enter__.return_value.fetchone.side_effect = [
        (ref.sha256,), ('doc-1', '1', 'a' * 64)]
    with patch('psycopg2.connect', return_value=connection), patch(
            'services.sandbox_poc.templates.from_registry', side_effect=ContractError('hash mismatch')):
        with pytest.raises(ContractError, match='hash mismatch'):
            export_reference('unused', 1, ['doc-1'])


def test_check_only_cli_writes_report_without_registry_or_docker(handoff, tmp_path):
    source, output = tmp_path/'handoff.json', tmp_path/'readiness.json'
    source.write_text(json.dumps(handoff))
    env = {**os.environ, 'DATABASE_URL': 'postgresql://unused@127.0.0.1:1/unused', 'SANDBOX_POC_ENABLED': 'false'}
    command = [sys.executable, str(ROOT/'scripts/review_handoff.py'), '--handoff', str(source),
               '--check-only', '--readiness-output', str(output)]
    checked = subprocess.run(command, env=env, capture_output=True, text=True)
    assert checked.returncode == 0, checked.stderr
    report = json.loads(output.read_text())
    assert report['status'] == 'INPUT_VALID' and report['sandbox_execution'] == 'NOT_RUN'
    original = output.read_bytes()
    assert subprocess.run(command, env=env, capture_output=True).returncode != 0
    assert output.read_bytes() == original
