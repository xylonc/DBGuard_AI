from unittest.mock import Mock
import json

import pytest

from services.sandbox_poc.collector_demo import run_collector_demo
from services.sandbox_poc.collector_runner import collect_owned_target


def test_existing_output_rejected_before_resource_creation(tmp_path):
    factory = Mock()
    with pytest.raises(FileExistsError):
        run_collector_demo(tmp_path, factory)
    factory.assert_not_called()


@pytest.mark.parametrize('cleanup_failure', [False, True])
def test_failed_startup_always_cleans_and_never_exports(tmp_path, cleanup_failure):
    resources = Mock()
    resources.start.side_effect = RuntimeError('private-password')
    if cleanup_failure:
        resources.close.side_effect = RuntimeError('private-dsn')
    directory = tmp_path/'run'
    result = run_collector_demo(directory, lambda: resources)
    resources.close.assert_called_once()
    assert result['status'] == ('CLEANUP_FAILED' if cleanup_failure else 'FAILED')
    assert result['fixture_cleanup_verified'] is not cleanup_failure
    assert not (directory/'review-bundle.zip').exists()
    assert 'private-' not in (directory/'summary.json').read_text()


def test_collector_rejects_unowned_container_before_execution(monkeypatch):
    runtime = Mock()
    runtime._assert_owned.side_effect = RuntimeError('Not owned')
    runner = Mock()
    monkeypatch.setattr('services.sandbox_poc.collector_runner.docker', runner)
    with pytest.raises(RuntimeError, match='Not owned'):
        collect_owned_target(runtime)
    runner.assert_not_called()
