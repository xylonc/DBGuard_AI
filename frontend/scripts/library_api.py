"""Serve the existing Main API with a separate disposable Library registry.
Nothing is approved automatically. Ctrl+C removes this process's registry only.
"""
import argparse, os, secrets, subprocess, sys, time, uuid
from pathlib import Path
from tempfile import TemporaryDirectory

def docker(*args):
    r = subprocess.run(['docker', *args], capture_output=True, text=True)
    if r.returncode: raise RuntimeError('Docker operation failed: ' + r.stderr)
    return r.stdout.strip()

if __name__ == '__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--repo', type=Path, required=True)
    p.add_argument('--env-file', type=Path)
    p.add_argument('--port', type=int, default=8011)
    args=p.parse_args()
    sys.path[:0]=[str(args.repo),str(args.repo/'backend')]
    if args.env_file:
        from dotenv import load_dotenv
        load_dotenv(args.env_file,override=False)
    name='dbguard-ui-library-'+uuid.uuid4().hex[:12]
    password=secrets.token_hex(24)
    try:
        docker('run','-d','--name',name,'--label','dbguard.ui.library=true','--label','dbguard.demo.owner='+os.environ.get('DBGUARD_DEMO_OWNER','standalone'),'-p','127.0.0.1::5432','-e','POSTGRES_USER=ui_library','-e','POSTGRES_DB=ui_library','-e','POSTGRES_PASSWORD='+password,'--mount',f'type=bind,source={args.repo}/db/init.sql,target=/docker-entrypoint-initdb.d/01-init.sql,readonly',os.environ.get('DBGUARD_REGISTRY_IMAGE','pgvector/pgvector:pg17'))
        port=docker('port',name,'5432/tcp').rsplit(':',1)[1]
        import psycopg2
        dsn=f'postgresql://ui_library:{password}@127.0.0.1:{port}/ui_library'
        deadline=time.monotonic()+50
        while True:
            try:
                with psycopg2.connect(dsn) as conn:
                    with conn.cursor() as cur: cur.execute('SELECT count(*) FROM knowledge_documents')
                break
            except psycopg2.Error:
                if time.monotonic()>deadline: raise RuntimeError('Library database startup timed out') from None
                time.sleep(.5)
        os.environ.update(DATABASE_URL=dsn,SANDBOX_POC_ENABLED='true',OLLAMA_API_BASE=os.environ.get('DBGUARD_EMBEDDING_URL','http://127.0.0.1:11434'),OLLAMA_API_URL=os.environ.get('DBGUARD_EMBEDDING_URL','http://127.0.0.1:11434'),OLLAMA_API_KEY='',OPENAI_API_KEY='')
        with TemporaryDirectory(prefix='dbguard-ui-snapshots-') as directory:
            os.environ['SNAPSHOT_STORAGE_DIR']=directory
            import uvicorn
            print(f'Main API on {args.port}; isolated Library registry ready. No team approvals seeded.',flush=True)
            uvicorn.run('app.main:app',host='127.0.0.1',port=args.port)
    finally:
        docker('rm','-f','-v',name)
