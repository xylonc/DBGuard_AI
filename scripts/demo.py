#!/usr/bin/env python3
"""One-command local demo. Python 3.12+, Node 24+, Docker with Compose required."""
from __future__ import annotations
import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import secrets
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import uuid

ROOT = Path(__file__).resolve().parents[1]
STATE = ROOT / '.demo'
PG = 'postgres@sha256:051f7b7b3abdd564d5d1bd1e8c4b9c1b6e77087d1dd22020ede611c096a272e0'
REGISTRY = 'pgvector/pgvector@sha256:cf134a767f474095eeba57e0117be8e568e011a63f33fbf252f14c9b760f8e6f'


def read_env(path):
    result = {}
    for number, raw in enumerate(path.read_text().splitlines(), 1):
        if not raw.strip() or raw.lstrip().startswith('#'): continue
        key, separator, value = raw.partition('=')
        if not separator or not key.strip().replace('_', '').isalnum():
            raise RuntimeError(f'Invalid environment line {number}')
        values = shlex.split(value, comments=True)
        if len(values) > 1: raise RuntimeError(f'Quote the value on environment line {number}')
        result[key.strip()] = values[0] if values else ''
    return result


def save(value):
    tmp = STATE / 'state.tmp'
    tmp.write_text(json.dumps(value, indent=2))
    tmp.chmod(0o600)
    tmp.replace(STATE / 'state.json')


def read_state():
    path = STATE / 'state.json'
    return json.loads(path.read_text()) if path.exists() else {}


def get(url, data=None, headers=None, timeout=5):
    payload = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=payload, headers={'Content-Type': 'application/json', **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return json.load(response)


def compose(project):
    return ['docker', 'compose', '--project-name', project, '--env-file', str(STATE / 'empty.env'), '-f', str(ROOT / 'deploy/compose.demo.yaml')]


def owned_cleanup(owner):
    if not owner or len(owner) != 32 or any(c not in '0123456789abcdef' for c in owner):
        raise RuntimeError('Invalid owner; refusing Docker cleanup')
    result = subprocess.run(['docker', 'ps', '-aq', '--filter', 'label=dbguard.demo.owner=' + owner], capture_output=True, text=True, check=True)
    ids = result.stdout.split()
    if ids:
        subprocess.run(['docker', 'rm', '-f', '-v', *ids], check=True, stdout=subprocess.DEVNULL)


def prerequisite_checks():
    if sys.version_info < (3, 12): raise RuntimeError('Python 3.12 or newer is required')
    for tool in ('node', 'npm', 'docker'):
        if not shutil.which(tool): raise RuntimeError(f'Install {tool} before starting the demo')
    version = subprocess.check_output(['node', '--version'], text=True).strip()
    if int(version.lstrip('v').split('.')[0]) < 24: raise RuntimeError('Node 24 or newer is required')
    subprocess.run(['docker', 'info'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(['docker', 'compose', 'version'], check=True, stdout=subprocess.DEVNULL)


def require_ports(base):
    if base < 1024 or base > 65529: raise RuntimeError('DEMO_BASE_PORT must be between 1024 and 65529')
    sockets = []
    try:
        for port in range(base, base+7):
            sock = socket.socket()
            sockets.append(sock)
            try: sock.bind(('0.0.0.0', port))
            except OSError: raise RuntimeError(f'Port {port} is occupied. Set another DEMO_BASE_PORT; existing services will not be stopped.') from None
    finally:
        for sock in sockets: sock.close()


class Demo:
    def __init__(self, config):
        self.config = config
        self.owner = uuid.uuid4().hex
        self.project = 'dbguard-demo-' + hashlib.sha256(str(ROOT).encode()).hexdigest()[:10]
        self.base = int(config.get('DEMO_BASE_PORT', '8443'))
        self.children = []
        self.logs = []
        self.stopping = False
        self.compose_started = False
        self.info = {'owner': self.owner, 'project': self.project, 'pid': os.getpid(), 'status': 'starting', 'base_port': self.base}
        self.env = {**os.environ, **config}
        self.env.pop('DBGUARD_ENV_FILE', None)
        # Disable external trace export for this self-contained local demo.
        self.env.update(LANGCHAIN_TRACING_V2='false', LANGSMITH_TRACING='false')
        self.env.update(DBGUARD_DEMO_OWNER=self.owner, DBGUARD_POSTGRES_IMAGE=PG, DBGUARD_REGISTRY_IMAGE=REGISTRY,
            DEMO_HERMES_PORT=str(self.base+3), DEMO_DASHBOARD_PORT=str(self.base+4), DEMO_MCP_PORT=str(self.base+5),
            DEMO_EMBEDDING_PORT=str(self.base+6), HERMES_API_SERVER_KEY=secrets.token_urlsafe(32),
            HERMES_DASHBOARD_PASSWORD=secrets.token_urlsafe(24), DBGUARD_EMBEDDING_URL=f'http://127.0.0.1:{self.base+6}')

    def check_stop(self):
        stop = STATE / 'stop-request'
        if self.stopping or (stop.exists() and stop.read_text().strip() == self.owner): raise KeyboardInterrupt
        for name, process in self.children:
            if process.poll() is not None: raise RuntimeError(f'{name} exited. See .demo/{name}.log')

    def run(self, command, name, cwd=ROOT, env=None):
        self.check_stop()
        with (STATE / f'{name}.log').open('ab') as log:
            process = subprocess.Popen(command, cwd=cwd, env=env or self.env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            try:
                while process.poll() is None:
                    self.check_stop()
                    time.sleep(.25)
                if process.returncode: raise RuntimeError(f'{name} failed; see .demo/{name}.log')
            finally:
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGTERM)
                    try: process.wait(timeout=15)
                    except subprocess.TimeoutExpired: os.killpg(process.pid, signal.SIGKILL); process.wait()

    def start(self, name, command, cwd=ROOT, env=None):
        log = (STATE / f'{name}.log').open('wb')
        self.logs.append(log)
        process = subprocess.Popen(command, cwd=cwd, env=env or self.env, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
        self.children.append((name, process))

    def ready(self, label, url, seconds=120):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            self.check_stop()
            try: return get(url)
            except (OSError, ValueError): time.sleep(.5)
        raise RuntimeError(f'{label} did not become ready; see .demo/ logs')

    def up(self):
        prerequisite_checks()
        require_ports(self.base)
        save(self.info)
        print('Preparing dependencies (first launch may take several minutes).', flush=True)
        python = ROOT / '.venv-demo/bin/python'
        if not python.exists(): self.run([sys.executable, '-m', 'venv', str(ROOT / '.venv-demo')], 'venv')
        fingerprint = hashlib.sha256((ROOT / 'requirements-demo.lock').read_bytes()).hexdigest()
        stamp = STATE / 'python-lock'
        if not stamp.exists() or stamp.read_text() != fingerprint:
            self.run([str(python), '-m', 'pip', 'install', '-r', 'requirements-demo.lock'], 'python-install')
            self.run([str(python), '-m', 'pip', 'check'], 'python-check')
            stamp.write_text(fingerprint)
        self.run(['npm', 'ci', '--ignore-scripts'], 'npm-install', ROOT / 'frontend')
        self.run(['npm', 'run', 'typecheck'], 'ui-typecheck', ROOT / 'frontend')
        self.run(['npm', 'run', 'build'], 'ui-build', ROOT / 'frontend')
        for name, image in [('postgres-image', PG), ('registry-image', REGISTRY)]: self.run(['docker', 'pull', image], name)
        self.env.update(SANDBOX_POC_ENABLED='true', SANDBOX_LLM_ENABLED='true', SANDBOX_LLM_API_KEY=self.config['OLLAMA_API_KEY'],
            SANDBOX_LLM_BASE_URL=self.config.get('HERMES_MODEL_BASE_URL', 'https://ollama.com/v1'), SANDBOX_LLM_MODEL=self.config.get('HERMES_MODEL', 'gpt-oss:20b'))
        self.start('demo-api', [str(python), 'scripts/demo_ui.py', '--port', str(self.base+1)])
        context = self.ready('Disposable demo', f'http://127.0.0.1:{self.base+1}/api/v1/demo/workflow')
        self.start('mcp', [str(python), '-m', 'services.dbguard_mcp.server'], env={**self.env,
            'DBGUARD_MCP_HOST': self.config.get('DEMO_MCP_BIND', '0.0.0.0'), 'DBGUARD_MCP_PORT': str(self.base+5),
            'DBGUARD_API_URL': f'http://127.0.0.1:{self.base+1}', 'DBGUARD_MCP_SANDBOX_TIMEOUT_SECONDS': '600'})
        self.ready('MCP', f'http://127.0.0.1:{self.base+5}/health')
        print('Starting HERMES and embedding services.', flush=True)
        self.compose_started = True
        self.run([*compose(self.project), 'up', '-d', '--build'], 'compose-up')
        self.ready('HERMES', f'http://127.0.0.1:{self.base+3}/health', 180)
        self.ready('Embeddings', f'http://127.0.0.1:{self.base+6}/api/tags')
        # Pull is streamed so Ctrl+C and down remain responsive during a large download.
        self.start('embedding-pull', ['docker', 'compose', '--project-name', self.project, '--env-file', str(STATE/'empty.env'),
            '-f', str(ROOT/'deploy/compose.demo.yaml'), 'exec', '-T', 'embeddings', 'ollama', 'pull', 'nomic-embed-text'])
        name, process = self.children.pop()
        while process.poll() is None:
            try: self.check_stop(); time.sleep(.5)
            except BaseException:
                os.killpg(process.pid, signal.SIGTERM); process.wait(); raise
        if process.returncode: raise RuntimeError('Embedding download failed; see .demo/embedding-pull.log')
        get(f'http://127.0.0.1:{self.base+6}/api/embed', {'model':'nomic-embed-text','input':'DBGuard readiness'}, timeout=60)
        self.start('main-api', [str(python), 'frontend/scripts/library_api.py', '--repo', str(ROOT), '--port', str(self.base+2)])
        self.ready('Main API', f'http://127.0.0.1:{self.base+2}/api/v1/health')
        self.start('ui', ['node', 'server.mjs'], ROOT / 'frontend', {**self.env,
            'UI_PORT':str(self.base), 'DBGUARD_API_URL':f'http://127.0.0.1:{self.base+2}',
            'DBGUARD_DEMO_URL':f'http://127.0.0.1:{self.base+1}', 'HERMES_API_URL':f'http://127.0.0.1:{self.base+3}', 'HERMES_WORKFLOW_BACKEND':'demo'})
        status = self.ready('UI gateway', f'http://127.0.0.1:{self.base}/bridge/status')
        if not all(v['available'] for v in status['services'].values()): raise RuntimeError('UI dependency readiness failed')
        self.info.update(status='ready', snapshot_id=context['snapshot_id'], url=f'http://127.0.0.1:{self.base}')
        save(self.info)
        print(f"READY: {self.info['url']}\nOpen Home → Load live demo. Ctrl+C or python3 scripts/demo.py down stops this package.", flush=True)
        while True: self.check_stop(); time.sleep(.5)

    def cleanup(self):
        print('Stopping package services and cleaning its disposable databases.', flush=True)
        errors = []
        for name, process in reversed(self.children):
            if process.poll() is None:
                try:
                    os.killpg(process.pid, signal.SIGINT)
                    process.wait(timeout=45)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL); process.wait()
                except OSError as exc: errors.append(str(exc))
        if self.compose_started:
            result = subprocess.run([*compose(self.project), 'down', '--remove-orphans'], env=self.env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, text=True)
            if result.returncode: errors.append('Compose cleanup failed')
        try: owned_cleanup(self.owner)
        except Exception: errors.append('Owned database cleanup failed; Docker may be unavailable')
        for log in self.logs: log.close()
        self.info.update(status='cleanup-failed' if errors else 'stopped', cleanup_errors=errors)
        save(self.info)
        if errors: print('; '.join(errors), file=sys.stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['up','down','status'])
    parser.add_argument('--env-file', type=Path, default=ROOT/'.env.demo')
    args = parser.parse_args()
    STATE.mkdir(mode=0o700, exist_ok=True)
    STATE.chmod(0o700)
    (STATE/'empty.env').touch(mode=0o600)
    if args.command == 'status':
        state=read_state()
        if state.get('status') == 'ready':
            try: state['services']=get(state['url']+'/bridge/status')['services']
            except OSError: state['status']='unreachable'
        print(json.dumps(state or {'status':'not started'}, indent=2)); return
    if args.command == 'down':
        state=read_state()
        if state.get('status') not in ('starting','ready'): print('Package is not running.'); return
        (STATE/'stop-request').write_text(state['owner'])
        deadline=time.monotonic()+180
        while time.monotonic()<deadline:
            result=read_state()
            if result.get('status') in ('stopped','cleanup-failed'):
                print(result['status']); return
            time.sleep(.5)
        raise RuntimeError('Supervisor did not stop. Inspect .demo/state.json and logs; no unrelated process was killed.')
    with (STATE/'launcher.lock').open('w') as lock:
        try: fcntl.flock(lock, fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError: raise RuntimeError('This checkout already has a running demo') from None
        config=read_env(args.env_file) if args.env_file.exists() else {}
        key=config.get('OLLAMA_API_KEY','')
        if not key or key.startswith('replace-'): raise RuntimeError('Copy .env.demo.example to .env.demo and set your own OLLAMA_API_KEY')
        demo=Demo(config)
        signal.signal(signal.SIGTERM, lambda *_: setattr(demo,'stopping',True))
        try: demo.up()
        except KeyboardInterrupt: pass
        finally: demo.cleanup()


if __name__ == '__main__':
    try: main()
    except Exception as exc: print(f'Demo: {exc}', file=sys.stderr); sys.exit(1)
