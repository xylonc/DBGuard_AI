"""DBA-invoked runner for one reviewed PG17 configuration fix; never invoked by UI."""
import argparse
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import sys
import time


def fingerprint(conn, names):
    with conn.cursor() as cur:
        cur.execute("""SELECT name,setting,source,sourcefile,context,pending_restart
                       FROM pg_settings WHERE name = ANY(%s)""", (names,))
        settings = {r[0]: dict(zip(('setting', 'source', 'sourcefile', 'context', 'pending_restart'), r[1:]))
                    for r in cur.fetchall()}
        cur.execute("""SELECT name,setting,sourcefile,applied,error FROM pg_file_settings
                       WHERE name = ANY(%s) ORDER BY name,sourcefile,setting""", (names,))
        files = [dict(zip(('name', 'setting', 'sourcefile', 'applied', 'error'), r)) for r in cur.fetchall()]
    return {'settings': settings, 'file_settings': files}


def execute(config, action, dsn, allow_demo=False):
    import psycopg2
    if config['demo_fixture_approval'] and not allow_demo:
        raise RuntimeError('Demo fixture approval: use --allow-demo only with a disposable database')
    with closing(psycopg2.connect(dsn, connect_timeout=10)) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute("SET statement_timeout='15s'")
            cur.execute("SELECT current_setting('server_version_num')::int / 10000, current_database()")
            major, database = cur.fetchone()
            if major != 17 or database != config['database']:
                raise RuntimeError('PostgreSQL version or database differs from the reviewed handoff')
            cur.execute("SELECT pg_try_advisory_lock(741093, 320)")
            if cur.fetchone()[0] is not True:
                raise RuntimeError('Another DBGuard fix is running on this database')
        current = fingerprint(conn, config['names'])
        if action == 'status':
            return {'matches_prior': current == config['prior'], 'matches_applied': current == config['applied']}
        expected = config['prior'] if action == 'apply' else config['applied']
        wanted = config['applied'] if action == 'apply' else config['prior']
        if current != expected:
            raise RuntimeError('Configuration drift detected; no SQL executed. Recollect and reassess.')
        # Each statement has its own autocommit command; ALTER SYSTEM cannot be in a transaction.
        with conn.cursor() as cur:
            for statement in config[action + '_statements']:
                cur.execute(statement)
        deadline = time.monotonic() + 10
        while True:
            # New sessions are required for superuser-backend settings such as log_connections.
            with closing(psycopg2.connect(dsn, connect_timeout=10)) as check:
                with check.cursor() as cur:
                    cur.execute("SET statement_timeout='10s'")
                    cur.execute('SELECT 1')
                    usable = cur.fetchone()[0] == 1
                observed = fingerprint(check, config['names'])
            if observed == wanted and usable:
                return {'action': action, 'verified': True, 'fix_id': config['fix_id']}
            if time.monotonic() >= deadline:
                raise RuntimeError('SQL executed but expected state was not verified. Inspect the database before any retry.')
            time.sleep(.25)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=['status', 'apply', 'rollback'])
    parser.add_argument('fix_id', choices=['fix-log_connections'])
    parser.add_argument('--allow-demo', action='store_true')
    args = parser.parse_args()
    base = Path(__file__).resolve().parent
    manifest = json.loads((base / 'manifest.json').read_text())
    for name, expected in manifest['files'].items():
        if name not in {'fix.json', 'evidence.json', 'report.html', 'harden.sh', 'runner.py'}:
            raise RuntimeError('Unexpected bundle member')
        if hashlib.sha256((base / name).read_bytes()).hexdigest() != expected:
            raise RuntimeError(f'Bundle content changed: {name}')
    config = json.loads((base / 'fix.json').read_text())
    dsn = os.environ.get('DBGUARD_DSN')
    if not dsn:
        raise RuntimeError('Set DBGUARD_DSN explicitly for the reviewed target; credentials are never bundled')
    print(json.dumps(execute(config, args.action, dsn, args.allow_demo)))


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        # Avoid echoing connection strings or server diagnostics that can include secrets.
        if isinstance(exc, RuntimeError):
            print(str(exc), file=sys.stderr)
        else:
            print('Database operation failed. Inspect PostgreSQL and connection configuration before retrying.', file=sys.stderr)
        sys.exit(1)
