"""Local live demo: isolated fixtures, existing sandbox endpoint, no team DB access."""
from contextlib import asynccontextmanager, closing
import hashlib
import json
from pathlib import Path
import secrets
import threading
import time
import uuid

import psycopg2
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from starlette.concurrency import run_in_threadpool
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .handoff import TemplateReference, build_handoff
from .provenance import signature
from .router import get_service, router
from .runtime import DATA, DisposablePostgres, docker
from .service import SandboxService
from .shared import ROOT, SpecEngine, digest

DEMO_LABEL = "dbguard.live-demo.run"


class DemoResources:
    """Owns only a newly created registry and disposable source; closes both."""
    def __init__(self):
        self.run_id = uuid.uuid4().hex
        self.name = f"dbguard-demo-registry-{self.run_id}"
        self.target = DisposablePostgres()
        self.lock = threading.Lock()
        self.registry_created = False

    def start(self):
        password = secrets.token_hex(24)
        self.registry_created = True
        docker("run", "-d", "--name", self.name, "--label", f"{DEMO_LABEL}={self.run_id}",
               "--read-only", "--user", "postgres", "--cap-drop", "ALL",
               "--security-opt", "no-new-privileges:true", "--memory", "512m",
               "--tmpfs", f"{DATA}:rw,uid=999,gid=999,mode=0700,size=256m",
               "--tmpfs", "/var/run/postgresql:rw,uid=999,gid=999,mode=0775",
               "-p", "127.0.0.1::5432", "-e", "POSTGRES_USER=demo_fixture",
               "-e", "POSTGRES_DB=demo_fixture", "-e", f"POSTGRES_PASSWORD={password}",
               "pgvector/pgvector:pg17")
        port = int(docker("port", self.name, "5432/tcp").rsplit(":", 1)[1])
        self.admin = dict(host="127.0.0.1", port=port, user="demo_fixture",
                          password=password, dbname="demo_fixture", connect_timeout=2)
        deadline = time.monotonic() + 45
        while True:
            try:
                with closing(psycopg2.connect(**self.admin)) as conn:
                    with conn.cursor() as cur:
                        cur.execute("SELECT 1")
                break
            except psycopg2.OperationalError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(.25)
        sql = (ROOT / "backend/app/templates/set_config_parameter.sql.j2").read_text()
        template_hash = hashlib.sha256(sql.encode()).hexdigest()
        document_hash = hashlib.sha256(b"DEMO FIXTURE ONLY: enable connection logging").hexdigest()
        with closing(psycopg2.connect(**self.admin)) as conn:
            with conn, conn.cursor() as cur:
                cur.execute((ROOT / "db/init.sql").read_text())
                cur.execute("""INSERT INTO templates
                    (template_name,version,sql_template,template_hash,pg_version,status,approved_by,approved_at)
                    VALUES ('set_config_parameter',1,%s,%s,'17','active','DEMO_FIXTURE_ONLY',NOW())""",
                            (sql, template_hash))
                cur.execute("""INSERT INTO knowledge_documents
                    (document_id,title,version,status,effective_date,postgresql_versions,
                     environment_applicability,document_hash,approved_by,approved_at)
                    VALUES ('demo-evidence','Demo fixture, not human approval','1','active',
                    NOW()-INTERVAL '1 day',ARRAY['17'],ARRAY['test'],%s,'DEMO_FIXTURE_ONLY',NOW())""",
                            (document_hash,))
                cur.execute("CREATE ROLE demo_reader LOGIN PASSWORD %s", (password,))
                cur.execute("GRANT SELECT ON templates, knowledge_documents TO demo_reader")
                cur.execute("ALTER ROLE demo_reader SET default_transaction_read_only=on")
        self.registry_url = psycopg2.extensions.make_dsn(**dict(self.admin, user="demo_reader"))
        self.engine = SpecEngine.load(ROOT / "catalog/specs/cis-pg17-v1.1.0",
                                      ROOT / "catalog/benchmarks/cis-pg17-v1.1.0/records.json")
        self.target.start()
        self.target.write_config("postgresql.conf", "\nlog_connections='on'\nlog_disconnections='on'\n")
        self.target.sql("ALTER SYSTEM SET log_connections='off';")
        self.target.activate({"log_connections": "off", "log_disconnections": "on"})
        self.snapshot = self.engine.collect(self.target)
        self.handoff = build_handoff(self.engine, self.snapshot, TemplateReference(
            version=1, sha256=template_hash, environment="test",
            evidence=[dict(document_id="demo-evidence", version="1", sha256=document_hash)]))
        self.registry_before = self.registry_signature()

    def registry_signature(self):
        with closing(psycopg2.connect(**self.admin)) as conn:
            with conn.cursor() as cur:
                cur.execute("""SELECT json_build_object(
                    'templates',(SELECT json_agg(t) FROM templates t),
                    'documents',(SELECT json_agg(d) FROM knowledge_documents d),
                    'setting',current_setting('log_connections'))""")
                return digest(cur.fetchone()[0])

    def source_evidence(self):
        snapshot = self.engine.collect(self.target)
        names = [s["check"]["setting_name"] for s in self.engine.specs if "check" in s]
        return dict(assessment=self.engine.assess(snapshot),
                    source_unchanged=signature(snapshot, names) == signature(self.snapshot, names),
                    registry_unchanged=self.registry_signature() == self.registry_before,
                    scope="Disposable demo source; no production target is connected")

    def close(self):
        errors = []
        try:
            self.target.close()
        except Exception as exc:
            errors.append(str(exc))
        if self.registry_created:
            try:
                for cid in docker("ps", "-aq", "--filter", f"label={DEMO_LABEL}={self.run_id}").split():
                    docker("rm", "-f", "-v", cid)
                if docker("ps", "-aq", "--filter", f"label={DEMO_LABEL}={self.run_id}"):
                    raise RuntimeError("Demo registry remains after cleanup")
            except Exception as exc:
                errors.append(str(exc))
        if errors:
            raise RuntimeError("Demo cleanup failed: " + "; ".join(errors))


class DemoService(SandboxService):
    def __init__(self, resources):
        super().__init__(resources.registry_url)
        self.resources = resources

    def run(self, request):
        if not self.resources.lock.acquire(blocking=False):
            raise HTTPException(409, "A demo operation is already running. Wait for its result.")
        try:
            # The demo API only accepts the source snapshot created by this session.
            if request.snapshot != self.resources.snapshot:
                raise HTTPException(422, "This demo only tests its own disposable source snapshot")
            result = super().run(request)
            result["demo_evidence"] = self.resources.source_evidence()
            result["demo_fixture_approval"] = True
            return result
        finally:
            self.resources.lock.release()


def create_app(resource_factory=DemoResources):
    @asynccontextmanager
    async def lifespan(app):
        resources = resource_factory()
        try:
            await run_in_threadpool(resources.start)
            app.state.resources = resources
            app.state.service = DemoService(resources)
            yield
        finally:
            await run_in_threadpool(resources.close)

    app = FastAPI(title="DBGuardAI live local demo", lifespan=lifespan)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=["127.0.0.1", "localhost", "testserver"])

    @app.middleware("http")
    async def local_requests(request, call_next):
        # No remote exposure or browser cross-origin writes for this unauthenticated POC.
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            origin = request.headers.get("origin")
            if origin and origin != str(request.base_url).rstrip("/"):
                return JSONResponse({"detail": "Cross-origin requests are not allowed"}, status_code=403)
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    app.include_router(router)
    app.dependency_overrides[get_service] = lambda: app.state.service

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(Path(__file__).parent / "ui/index.html")

    @app.get("/demo/context")
    def context():
        return {"mode": "live-disposable-demo", "fixture_approval": True,
                "handoff": app.state.resources.handoff.model_dump(),
                "session_id": app.state.resources.run_id}

    @app.get("/demo/source")
    def source():
        resources = app.state.resources
        if not resources.lock.acquire(blocking=False):
            raise HTTPException(409, "A demo operation is already running. Wait for its result.")
        try:
            return resources.source_evidence()
        finally:
            resources.lock.release()

    return app
