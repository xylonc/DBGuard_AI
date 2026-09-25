"""Launcher safety checks; no provider calls or Docker mutations."""
import importlib.util
from pathlib import Path
import socket
from types import SimpleNamespace
import pytest

spec = importlib.util.spec_from_file_location('demo_launcher', Path(__file__).parents[1]/'scripts/demo.py')
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)


def test_env_is_data_not_shell(tmp_path):
    env = tmp_path/'settings'
    env.write_text('KEY="literal$(do-not-run)#value"\nPORT=9000 # comment\n')
    assert launcher.read_env(env) == {'KEY':'literal$(do-not-run)#value', 'PORT':'9000'}


def test_ports_fail_without_stopping_existing_listener():
    with socket.socket() as existing:
        existing.bind(('0.0.0.0',0))
        port=existing.getsockname()[1]
        if port>65529: pytest.skip('Allocated outside usable seven-port range')
        with pytest.raises(RuntimeError,match='occupied'):
            launcher.require_ports(port)
        assert existing.getsockname()[1] == port


def test_cleanup_uses_only_exact_owner_label(monkeypatch):
    calls=[]
    def run(command,**kwargs):
        calls.append(command)
        return SimpleNamespace(stdout='owned-container\n',returncode=0)
    monkeypatch.setattr(launcher.subprocess,'run',run)
    owner='a'*32
    launcher.owned_cleanup(owner)
    assert calls == [['docker','ps','-aq','--filter','label=dbguard.demo.owner='+owner],['docker','rm','-f','-v','owned-container']]


def test_cleanup_refuses_wildcard_owner(monkeypatch):
    monkeypatch.setattr(launcher.subprocess,'run',lambda *a,**k:pytest.fail('must not invoke Docker'))
    with pytest.raises(RuntimeError,match='Invalid owner'):
        launcher.owned_cleanup('*')


def test_start_does_not_inherit_another_gateway_env_file(monkeypatch):
    monkeypatch.setenv('DBGUARD_ENV_FILE','/another/private.env')
    package=launcher.Demo({'OLLAMA_API_KEY':'fixture-only','DEMO_BASE_PORT':'19000'})
    assert 'DBGUARD_ENV_FILE' not in package.env
    assert package.env['DEMO_MCP_PORT']=='19005'
    assert package.env['HERMES_API_SERVER_KEY'] != package.env['HERMES_DASHBOARD_PASSWORD']
    assert 'OLLAMA_API_KEY' not in package.info


def test_runtime_labels_only_package_owned_runs(monkeypatch):
    from services.sandbox_poc import runtime
    seen=[]
    def run(command,**kwargs):
        seen.append(command)
        return SimpleNamespace(returncode=0,stdout='ok',stderr='')
    monkeypatch.setattr(runtime.subprocess,'run',run)
    monkeypatch.setenv('DBGUARD_DEMO_OWNER','b'*32)
    runtime.docker('run','--name','owned','postgres:17')
    runtime.docker('ps','-q')
    assert seen[0][:4] == ['docker','run','--label','dbguard.demo.owner='+'b'*32]
    assert seen[1] == ['docker','ps','-q']
