"""Run the repository collector inside an already-owned disposable target."""
import json

from .runtime import docker
from .shared import ROOT


def collect_owned_target(runtime, engine):
    # Reject arbitrary/stale containers before copying or running any script.
    runtime._assert_owned()
    folder = '/var/run/postgresql/dbguard-collector'
    docker('exec', runtime.name, 'mkdir', '-p', folder)
    for name in ('dbguard-collect.sh', 'collect.sql'):
        docker('exec', '-i', runtime.name, 'sh', '-c', f'cat > {folder}/{name}',
               stdin=(ROOT / 'collector' / name).read_text())
    docker('exec', '-i', runtime.name, 'sh', '-c', f'cat > {folder}/checks.json',
           stdin=engine.manifest_text)
    docker('exec', '-e', 'PGUSER=dbguard_poc', '-e', 'PGDATABASE=dbguard_sandbox',
           '-e', 'TMPDIR=/var/run/postgresql', runtime.name, 'bash',
           f'{folder}/dbguard-collect.sh', '-t', runtime.name, '-m', f'{folder}/checks.json', '-o', f'{folder}/snapshot.json')
    return json.loads(docker('exec', runtime.name, 'cat', f'{folder}/snapshot.json'))
