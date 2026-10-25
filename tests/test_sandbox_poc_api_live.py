"""Real API -> read-only pgvector registry -> disposable PG17 fix/rollback.

Approval records below are explicitly integration-test fixtures, not human
approval. No existing DBGuard database is accessed or seeded by these tests.
"""
import hashlib
import json
import os
from pathlib import Path
import secrets
import time
import uuid
from contextlib import closing

import psycopg2
from psycopg2.extras import Json
import pytest
from fastapi.testclient import TestClient

from services.sandbox_poc.api import app
from services.sandbox_poc.handoff import TemplateReference, build_handoff
from services.sandbox_poc.provenance import signature
from services.sandbox_poc.router import settings
from services.sandbox_poc.runtime import DATA, LABEL, DisposablePostgres, docker
from services.sandbox_poc.shared import ROOT, SpecEngine

pytestmark = pytest.mark.skipif(os.environ.get("DBGUARD_POC_LIVE") != "1",
                                reason="Set DBGUARD_POC_LIVE=1 for disposable registry/API integration")
TEST_LABEL = "dbguard.sandbox-api-test.run"
URL = "/api/v1/sandbox/runs"


@pytest.fixture(scope="module")
def registry():
    run_id = uuid.uuid4().hex
    name = f"dbguard-registry-test-{run_id}"
    password = secrets.token_hex(24)
    try:
        docker("run", "-d", "--name", name, "--label", f"{TEST_LABEL}={run_id}",
               "--read-only", "--user", "postgres", "--cap-drop", "ALL",
               "--security-opt", "no-new-privileges:true", "--memory", "512m",
               "--tmpfs", f"{DATA}:rw,uid=999,gid=999,mode=0700,size=256m",
               "--tmpfs", "/var/run/postgresql:rw,uid=999,gid=999,mode=0775",
               "-p", "127.0.0.1::5432", "-e", "POSTGRES_USER=registry_fixture",
               "-e", "POSTGRES_DB=registry_fixture", "-e", f"POSTGRES_PASSWORD={password}",
               "pgvector/pgvector:pg17")
        port = int(docker("port", name, "5432/tcp").rsplit(":", 1)[1])
        config = dict(host="127.0.0.1", port=port, user="registry_fixture",
                      password=password, dbname="registry_fixture", connect_timeout=2)
        deadline = time.monotonic() + 45
        while True:
            try:
                with closing(psycopg2.connect(**config)) as conn:
                    with conn, conn.cursor() as cur:
                        cur.execute("SELECT 1")
                break
            except psycopg2.OperationalError:
                if time.monotonic() > deadline:
                    raise
                time.sleep(0.25)
        sql = (ROOT / "backend/app/templates/set_config_parameter.sql.j2").read_text()
        template_hash = hashlib.sha256(sql.encode()).hexdigest()
        document_hash = hashlib.sha256(b"INTEGRATION TEST ONLY: enable connection logging").hexdigest()
        with closing(psycopg2.connect(**config)) as conn:
            with conn, conn.cursor() as cur:
                cur.execute((ROOT / "db/init.sql").read_text())
                cur.execute("""INSERT INTO templates
                    (template_name,version,sql_template,template_hash,pg_version,status,approved_by,approved_at)
                    VALUES ('set_config_parameter',1,%s,%s,'17','active','INTEGRATION_TEST_ONLY',NOW())""",
                            (sql, template_hash))
                cur.execute("""INSERT INTO knowledge_documents
                    (document_id,title,version,status,effective_date,postgresql_versions,
                    environment_applicability,document_hash,approved_by,approved_at)
                    VALUES ('test-evidence','Integration fixture','1','active',NOW()-INTERVAL '1 day',
                    ARRAY['17'],ARRAY['test'],%s,'INTEGRATION_TEST_ONLY',NOW())""", (document_hash,))
                cur.execute("CREATE ROLE registry_reader LOGIN PASSWORD %s", (password,))
                cur.execute("GRANT SELECT ON templates, knowledge_documents TO registry_reader")
                cur.execute("ALTER ROLE registry_reader SET default_transaction_read_only=on")
        read_config = dict(config, user="registry_reader")
        yield {"admin": config, "url": psycopg2.extensions.make_dsn(**read_config),
               "reference": {"version": 1, "sha256": template_hash, "environment": "test",
                             "evidence": [{"document_id": "test-evidence", "version": "1", "sha256": document_hash}]}}
    finally:
        for cid in docker("ps", "-aq", "--filter", f"label={TEST_LABEL}={run_id}").split():
            docker("rm", "-f", "-v", cid)
        assert not docker("ps", "-aq", "--filter", f"label={TEST_LABEL}={run_id}")


@pytest.fixture
def live_client(registry, monkeypatch):
    monkeypatch.setattr(settings, "sandbox_poc_enabled", True)
    monkeypatch.setattr(settings, "database_url", registry["url"])
    with TestClient(app) as client:
        yield client


def engine():
    return SpecEngine.load(ROOT / "catalog/specs/cis-pg17-v1.1.0",
                           ROOT / "catalog/benchmarks/cis-pg17-v1.1.0/records.json")


def registry_state(registry):
    with closing(psycopg2.connect(**registry["admin"])) as conn:
        with conn.cursor() as cur:
            cur.execute("""SELECT json_build_object('templates',(SELECT json_agg(t) FROM templates t),
                'documents',(SELECT json_agg(d) FROM knowledge_documents d),
                'log_connections',current_setting('log_connections'))""")
            return cur.fetchone()[0]


@pytest.mark.parametrize("source", ["conf", "auto"])
def test_api_uses_real_registry_and_restores_exact_source(registry, live_client, source):
    spec_engine = engine()
    target = DisposablePostgres()
    before_registry = registry_state(registry)
    try:
        target.start()
        underlying = "on" if source == "auto" else "off"
        target.write_config("postgresql.conf", f"\nlog_connections='{underlying}'\nlog_disconnections='on'\n")
        if source == "auto":
            target.sql("ALTER SYSTEM SET log_connections='off';")
        target.activate({"log_connections": "off", "log_disconnections": "on"})
        snapshot = spec_engine.collect(target)
        handoff = build_handoff(spec_engine, snapshot, TemplateReference(**registry["reference"]))
        response = live_client.post(URL, json=handoff.model_dump())
        assert response.status_code == 200, response.text
        result = response.json()
        assert result["status"] == "VERIFIED", result
        assert result["approval_source"] == "registry"
        assert result["template"]["approved_by"] == "INTEGRATION_TEST_ONLY"
        assert all(a["rollback_verified"] and a["cleanup"]["verified"] for a in result["attempts"])
        assert target.sql("SHOW log_connections;") == "off"
        names = [s["check"]["setting_name"] for s in spec_engine.specs if "check" in s]
        assert signature(spec_engine.collect(target), names) == signature(snapshot, names)
        assert registry_state(registry) == before_registry
        with closing(psycopg2.connect(registry["url"])) as conn:
            with conn.cursor() as cur:
                cur.execute("SHOW transaction_read_only")
                assert cur.fetchone()[0] == "on"
        evidence_dir = os.environ.get("DBGUARD_TEST_EVIDENCE_DIR")
        if evidence_dir:
            output = Path(evidence_dir)
            output.mkdir(parents=True, exist_ok=True)
            (output / f"api-{source}.json").write_text(json.dumps({
                "test_fixture_approval": True, "handoff": handoff.model_dump(), "result": result,
                "source_unchanged": True, "registry_unchanged": True}, indent=2) + "\n")
    finally:
        target.close()
    for attempt in result["attempts"]:
        assert not docker("ps", "-aq", "--filter", f"label={LABEL}={attempt['run_id']}")


@pytest.mark.parametrize("fault", ["draft_template", "draft_document", "expired_document",
                                   "wrong_environment", "template_hash", "tampered_sql",
                                   "document_version", "document_hash"])
def test_live_registry_rejects_unapproved_or_changed_records(registry, live_client, fault):
    # The source fixture is only used to reach the real registry rejection gate.
    from test_sandbox_poc import snapshot as snapshot_fixture
    spec_engine = engine()
    snapshot = snapshot_fixture.__wrapped__(spec_engine)
    request = build_handoff(spec_engine, snapshot, TemplateReference(**registry["reference"])).model_dump()
    old_state = registry_state(registry)
    before = set(docker("ps", "-aq", "--filter", f"label={LABEL}").split())
    try:
        with closing(psycopg2.connect(**registry["admin"])) as conn:
            with conn, conn.cursor() as cur:
                if fault == "draft_template":
                    cur.execute("UPDATE templates SET status='draft'")
                elif fault == "draft_document":
                    cur.execute("UPDATE knowledge_documents SET status='draft'")
                elif fault == "expired_document":
                    cur.execute("UPDATE knowledge_documents SET expiry_date=NOW()-INTERVAL '1 day'")
                elif fault == "wrong_environment":
                    request["template_ref"]["environment"] = "prod"
                elif fault == "template_hash":
                    request["template_ref"]["sha256"] = "0" * 64
                elif fault == "tampered_sql":
                    cur.execute("UPDATE templates SET sql_template=sql_template || E'\\n-- changed after approval'")
                elif fault == "document_version":
                    request["template_ref"]["evidence"][0]["version"] = "wrong-version"
                else:
                    request["template_ref"]["evidence"][0]["sha256"] = "0" * 64
        assert live_client.post(URL, json=request).status_code == 422
        assert set(docker("ps", "-aq", "--filter", f"label={LABEL}").split()) == before
    finally:
        with closing(psycopg2.connect(**registry["admin"])) as conn:
            with conn, conn.cursor() as cur:
                cur.execute("UPDATE templates SET status='active', sql_template=%s",
                            (old_state["templates"][0]["sql_template"],))
                cur.execute("UPDATE knowledge_documents SET status='active', expiry_date=NULL")
        assert registry_state(registry) == old_state


def test_reingested_template_requires_fresh_approval(registry, live_client, monkeypatch):
    from app.services import vector_service
    from test_sandbox_poc import snapshot as snapshot_fixture
    spec_engine = engine()
    snapshot = snapshot_fixture.__wrapped__(spec_engine)
    old_state = registry_state(registry)
    before = set(docker("ps", "-aq", "--filter", f"label={LABEL}").split())
    try:
        # Only the fixture's admin performs test setup. The API still uses the
        # separate SELECT-only account for all real registry lookup requests.
        with monkeypatch.context() as patch:
            patch.setattr(settings, "database_url", psycopg2.extensions.make_dsn(**registry["admin"]))
            patch.setattr(vector_service, "get_embedding", lambda _: [0.0] * 768)
            revised_sql = old_state["templates"][0]["sql_template"] + "\n-- revised fixture"
            ingested = vector_service.ingest_template("set_config_parameter", "Revised fixture",
                                                      revised_sql, version=1, pg_version="17")
        assert ingested["status"] == "draft"
        rows = registry_state(registry)["templates"]
        assert ingested["version"] == 2
        assert next(row for row in rows if row["version"] == 1) == old_state["templates"][0]
        current = next(row for row in rows if row["version"] == 2)
        assert current["approved_by"] is None and current["approved_at"] is None
        reference = dict(registry["reference"], version=ingested["version"], sha256=hashlib.sha256(revised_sql.encode()).hexdigest())
        request = build_handoff(spec_engine, snapshot, TemplateReference(**reference)).model_dump()
        assert live_client.post(URL, json=request).status_code == 422
        assert set(docker("ps", "-aq", "--filter", f"label={LABEL}").split()) == before
    finally:
        with closing(psycopg2.connect(**registry["admin"])) as conn:
            with conn, conn.cursor() as cur:
                cur.execute("DELETE FROM templates")
                cur.execute("INSERT INTO templates SELECT * FROM json_populate_record(NULL::templates, %s)",
                            (Json(old_state["templates"][0]),))
        assert registry_state(registry) == old_state
