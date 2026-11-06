"""Live W2B gate 1 rehearsals (DBGUARD_POC_LIVE=1, Docker, the pinned pgaudit image).

    DBGUARD_POC_LIVE=1 .venv-demo/bin/python -m pytest tests/test_catalog_fixes_w2b_live.py

Disposable sandboxes only (--network none, run-labelled, removed). The approved policy
profile with pgaudit_log_classes is a TEST profile that exists only in this file; it is
never written to the profile store.
"""
import io
import json
import os
import re
import zipfile

import pytest

from app.services.spec_engine import RecordsIndex
from app.services.spec_engine.policy import parse_profile
from scripts.sandbox_poc import demo_template
from services.sandbox_poc import catalog_fixes as cf
from services.sandbox_poc import profiles
from services.sandbox_poc.batch import run_batch
from services.sandbox_poc.handoff import SandboxHandoff, TemplateReference, build_handoff
from services.sandbox_poc.review_bundle import build_review_bundle
from services.sandbox_poc.runtime import STOCK_IMAGE, LABEL, PINNED_IMAGES_DIR, DisposablePostgres, docker
from services.sandbox_poc.service import SandboxService
from services.sandbox_poc.shared import ROOT, SpecEngine
from services.sandbox_poc.workflow import ROLLBACK_SKIPPED
from tests.test_catalog_fixes_w2b import list_template

pytestmark = pytest.mark.skipif(os.environ.get("DBGUARD_POC_LIVE") != "1",
                                reason="Set DBGUARD_POC_LIVE=1 with Docker running")

PGAUDIT_IMAGE = json.loads((PINNED_IMAGES_DIR / "pg17-pgaudit.json").read_text())["tag"]
RECORDS_PATH = ROOT / "catalog/benchmarks/cis-pg17-v1.1.0/records.json"
SID = {rec: f"cis-pg17-v1.1.0:{rec}" for rec in ("3.2", "5.6", "6.10", "3.1.20")}
TEST_PROFILE = b"""profile_id: w2b-live-test-only
benchmark: cis-pg17-v1.1.0
approved_by: Test Reviewer
approved_at: '2026-11-05'
values: {}
pgaudit_log_classes: [ddl, role, write]
"""
KEY_MARKERS = ("PRIVATE KEY", "BEGIN CERTIFICATE", "server.key\n", "-----BEGIN")


def owned_containers():
    return docker("ps", "-aq", "--filter", f"label={LABEL}")


@pytest.fixture(scope="module")
def image():
    try:
        docker("image", "inspect", "--format", "{{.Id}}", PGAUDIT_IMAGE)
    except RuntimeError:
        pytest.skip(f"{PGAUDIT_IMAGE} is not built: python3 scripts/build_sandbox_image.py")
    return PGAUDIT_IMAGE


@pytest.fixture(scope="module")
def engine():
    records = RecordsIndex.load(RECORDS_PATH)
    return SpecEngine.load(ROOT / "catalog/specs/cis-pg17-v1.1.0", RECORDS_PATH,
                           parse_profile(TEST_PROFILE, records, "live-test-only"))


@pytest.fixture(scope="module")
def source(engine, image):
    """A disposable source database (break: nothing preloaded, default ciphers)."""
    db = DisposablePostgres(image)
    try:
        db.start()
        snapshot = engine.collect(db)
    finally:
        assert db.close()["verified"] is True
    return snapshot, engine.assess(snapshot)


def upstream(assessment, sid):
    return next(r for r in assessment["upstream_report"]["results"] if r["spec_id"] == sid)


def run(engine, source, rec, image):
    snapshot, assessment = source
    assert upstream(assessment, SID[rec])["result"] == "FAIL"  # break -> FAIL first
    before = owned_containers()
    result = cf.CatalogFixLoop(engine, demo_template(), lambda: DisposablePostgres(image),
                               control_id=SID[rec], list_template=list_template()).run(snapshot, assessment)
    assert owned_containers() == before
    return result


EVIDENCE = [dict(document_id="demo-fixture", version="1", sha256="a" * 64)]


def handoff_for(engine, snapshot, rec):
    template = demo_template()
    ref = TemplateReference(version=template.version, sha256=template.sha256, evidence=EVIDENCE)
    handoff = build_handoff(engine, snapshot, ref)
    handoff.control_id = SID[rec]
    if cf.is_catalog_fix(engine, SID[rec]) and cf.needs_list_template(engine, snapshot, SID[rec]):
        handoff.list_template_ref = TemplateReference(registry_name="set_config_list", version=1,
                                                      sha256=list_template().sha256, evidence=EVIDENCE)
    return SandboxHandoff.model_validate(handoff.model_dump())


def bundle(engine, source, rec, result):
    result = {**result, "approval_source": "registry", "run_id": "live-" + rec}
    pinned = [dict(document_id="demo-fixture", version="1", sha256="a" * 64, approved_by="TEST FIXTURE ONLY")]
    result["template"] = {**result["template"], "evidence": pinned}
    if "list_template" in result:
        result["list_template"] = {**result["list_template"], "evidence": pinned}
    data = build_review_bundle(handoff_for(engine, source[0], rec), result, engine)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        return {name: archive.read(name) for name in archive.namelist()}


def assert_proof(result):
    assert result["status"] == "VERIFIED", result["attempts"][-1].get("error")
    attempt = result["attempts"][-1]
    assert [attempt["catalog_proof"][k]["result"] for k in ("before", "after", "rollback")] == ["FAIL", "PASS", "FAIL"]
    assert attempt["rollback_verified"] is True and attempt["regressions"] == []
    assert attempt["cleanup"]["verified"] is True
    return attempt


def test_6_10_tls_rehearsal_only_cis_ciphers_then_exact_rollback(engine, source, image):
    result = run(engine, source, "6.10", image)
    attempt = assert_proof(result)
    weak = "ECDHE-RSA-AES256-SHA384"
    assert attempt["tls_before"]["weak_accepted"][weak] is True           # FAIL at the handshake too
    assert attempt["tls_after"]["weak_accepted"] == {c: False for c in cf.WEAK_TLS12_PROBES}
    assert attempt["tls_after"]["negotiated"]["protocol"] == "TLSv1.2"
    assert attempt["tls_after"]["negotiated"]["cipher"] in cf.CIS_TLS12_CIPHERS
    assert all(attempt["tls_after"]["cis_accepted"].values())
    assert attempt["tls_rollback"]["weak_accepted"] == attempt["tls_before"]["weak_accepted"]
    text = json.dumps(result)
    assert not any(marker in text for marker in KEY_MARKERS)              # cert and key never leave
    files = bundle(engine, source, "6.10", result)
    config = json.loads(files["fix.json"])
    assert config["kind"] == "catalog_setting" and config["requires"] == "reload" and config["preload_added"] == []
    assert config["apply_statements"][0] == f"ALTER SYSTEM SET \"ssl_ciphers\" = '{cf.CIS_SSL_CIPHERS}'"
    readme = files["README.txt"].decode()
    assert "does NOT switch ssl on" in readme
    assert not any(marker in b"".join(files.values()).decode("utf-8", "replace") for marker in KEY_MARKERS)


def test_5_6_passwordcheck_restart_and_rollback(engine, source, image):
    result = run(engine, source, "5.6", image)
    assert_proof(result)
    assert result["fix_unit"]["requires"] == "restart"
    files = bundle(engine, source, "5.6", result)
    config = json.loads(files["fix.json"])
    assert config["preload_added"] == ["passwordcheck"] and config["requires"] == "restart"
    readme = files["README.txt"].decode()
    assert "PACKAGE PREREQUISITE AND RESTART" in readme and "install the package first; no SQL executed" in readme


def test_3_2_pgaudit_with_approved_test_profile(engine, source, image):
    result = run(engine, source, "3.2", image)
    attempt = assert_proof(result)
    assert attempt["pgaudit_log_shown"] == "ddl,role,write"                 # SHOW pgaudit.log works
    restored = {r["name"] for r in attempt["rollback"]["baseline"]["settings"]}
    assert "pgaudit.log" not in restored                                    # unloaded again
    files = bundle(engine, source, "3.2", result)
    config = json.loads(files["fix.json"])
    assert config["settings"] == ["shared_preload_libraries", "pgaudit.log"]
    assert config["preload_added"] == ["pgaudit"]
    assert config["rollback_statements"][0] == 'ALTER SYSTEM RESET "pgaudit.log";'
    assert "postgresql-17-pgaudit" in files["README.txt"].decode()


def test_3_2_on_the_stock_image_is_a_clean_start_failure(engine, source):
    result = run(engine, source, "3.2", STOCK_IMAGE)
    assert result["status"] == "FAILED" and len(result["attempts"]) == 1
    attempt = result["attempts"][0]
    assert attempt["error"] == ("SandboxStartError: PostgreSQL failed to start after restart: "
                                "shared_preload_libraries names 'pgaudit', which is not installed in the sandbox image")
    assert attempt["phase"] == "start_failed" and attempt["rollback_skipped"] == ROLLBACK_SKIPPED
    # No confusing psql error from rollback SQL on a stopped server.
    assert "psql" not in attempt["error"] + attempt["apply_or_assessment_error"]
    assert attempt["cleanup"]["verified"] is True


class SandboxConnection:
    """Routes the runner guard's fixed statements through psql in a disposable sandbox,
    so the guard sees PostgreSQL's real answers (the sandbox has no network for a DSN)."""

    def __init__(self, db, log):
        self.db, self.log, self.autocommit = db, log, True

    def cursor(self):
        connection = self

        class Cursor:
            def __enter__(self): return self
            def __exit__(self, *a): return False

            def execute(self, sql, params=None):
                connection.log.append(sql)
                if sql.startswith("SET LOCAL"):
                    return
                try:
                    self.output = connection.db.sql(sql + ";")
                except RuntimeError as exc:
                    match = re.search(r"ERROR:\s+(.*)", str(exc))
                    raise LivePgError(match.group(1).strip() if match else str(exc)) from None

            def fetchone(self):
                return (self.output,)
        return Cursor()

    def rollback(self): pass
    def close(self): pass


class LivePgError(Exception):
    def __init__(self, message):
        super().__init__(message)
        from types import SimpleNamespace
        self.diag = SimpleNamespace(message_primary=message)


@pytest.mark.parametrize("which, library, allowed", [
    ("stock", "pgaudit", False), ("pgaudit", "pgaudit", True), ("stock", "passwordcheck", True)])
def test_runner_guard_against_real_postgresql(monkeypatch, image, which, library, allowed):
    import sys
    import types
    from tests.test_catalog_fixes_w2b import load_runner
    fake = types.ModuleType("psycopg2")
    fake.Error = LivePgError
    monkeypatch.setitem(sys.modules, "psycopg2", fake)
    runner = load_runner()
    db = DisposablePostgres(STOCK_IMAGE if which == "stock" else image)
    log = []
    try:
        db.start()
        connect = lambda dsn, connect_timeout=10: SandboxConnection(db, log)  # noqa: E731
        if allowed:
            runner.preload_guard("unused", [library], connect=connect)
        else:
            with pytest.raises(RuntimeError, match="install the package first; no SQL executed"):
                runner.preload_guard("unused", [library], connect=connect)
        assert f"LOAD '{library}'" in log
        assert db.sql("SHOW shared_preload_libraries;") == ""                 # nothing changed
    finally:
        assert db.close()["verified"] is True


def test_runner_guard_with_the_list_statement_on_a_server_without_pgaudit(monkeypatch):
    """Stock image already preloading pg_stat_statements: the list statement adds pgaudit,
    which is not installed, so the runner refuses before any ALTER SYSTEM."""
    import sys
    import types
    from tests.test_catalog_fixes_w2b import load_runner
    fake = types.ModuleType("psycopg2")
    fake.Error = LivePgError
    monkeypatch.setitem(sys.modules, "psycopg2", fake)
    runner = load_runner()
    db = DisposablePostgres(STOCK_IMAGE)
    log = []
    try:
        db.start()
        db.sql("ALTER SYSTEM SET shared_preload_libraries = 'pg_stat_statements';")
        db.activate({"shared_preload_libraries": "pg_stat_statements"})
        statement = "ALTER SYSTEM SET \"shared_preload_libraries\" = 'pg_stat_statements', 'pgaudit'"
        added = runner.preload_additions(SandboxConnection(db, log), {"apply_statements": [statement]})
        assert added == ["pgaudit"]
        with pytest.raises(RuntimeError, match="install the package first; no SQL executed"):
            runner.preload_guard("unused", added, connect=lambda dsn, connect_timeout=10: SandboxConnection(db, log))
        assert not any(sql.startswith("ALTER SYSTEM") for sql in log)
        assert db.sql("SHOW shared_preload_libraries;") == "pg_stat_statements"
    finally:
        assert db.close()["verified"] is True


class DemoService(SandboxService):
    """The real service with the demo template and the pinned pgaudit image (no registry)."""

    def __init__(self, image):
        super().__init__("unused", image)

    def resolve_template(self, request, ref=None):
        from services.sandbox_poc.templates import ApprovedTemplate
        t = list_template() if ref is not None and ref.registry_name == "set_config_list" else demo_template()
        # evidence pinned exactly as in handoff_for
        return ApprovedTemplate(t.registry_name, t.version, t.sql, t.sha256, t.approved_by,
                                (dict(document_id="demo-fixture", version="1", sha256="a" * 64,
                                      approved_by="TEST FIXTURE ONLY"),))


def test_combined_batch_with_catalog_and_setting_fixes(monkeypatch, tmp_path, engine, source, image):
    monkeypatch.setenv("DBGUARD_HISTORY_DIR", str(tmp_path))
    snapshot, assessment = source
    assert assessment["findings"][SID["3.1.20"]]["status"] == "FAIL"     # log_connections off
    monkeypatch.setattr(profiles, "resolve_profile",
                        lambda records, specs, ref: engine.policy if ref == engine.policy.sha256 else None)
    requests = [handoff_for(engine, snapshot, rec) for rec in ("6.10", "3.1.20", "3.2")]
    before = owned_containers()
    output, data = run_batch(requests, DemoService(image))
    assert owned_containers() == before
    assert output["status"] == "VERIFIED", output["combined_test"].get("reason")
    combined = output["combined_test"]
    assert all(r["verified"] for r in combined["rollback"]) and len(combined["rollback"]) == 3
    assert {s["fix_id"] for s in combined["steps"]} == {"fix-ssl_ciphers", "fix-log_connections", "fix-pgaudit"}
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        names = archive.namelist()
        readme = archive.read("README.txt").decode()
        pgaudit = json.loads(archive.read("fix-pgaudit/fix.json"))
    assert "fix-pgaudit/fix.json" in names and "fix-ssl_ciphers/runner.py" in names
    assert "PACKAGE PREREQUISITE AND RESTART" in readme and "does NOT switch ssl on" in readme
    assert pgaudit["prior"] != pgaudit["applied"]


def test_3_2_and_5_6_together_in_one_batch(monkeypatch, tmp_path, engine, source, image):
    """The second preload fix is re-derived from the first's result: both libraries stay."""
    monkeypatch.setenv("DBGUARD_HISTORY_DIR", str(tmp_path))
    snapshot, _ = source
    monkeypatch.setattr(profiles, "resolve_profile",
                        lambda records, specs, ref: engine.policy if ref == engine.policy.sha256 else None)
    requests = [handoff_for(engine, snapshot, rec) for rec in ("3.2", "5.6")]
    before = owned_containers()
    output, data = run_batch(requests, DemoService(image))
    assert owned_containers() == before
    assert output["status"] == "VERIFIED", output["combined_test"].get("reason")
    steps = output["combined_test"]["steps"]
    assert [s["fix_id"] for s in steps] == ["fix-passwordcheck", "fix-pgaudit"]
    last = {r["name"]: r["setting"] for r in steps[-1]["after"]["baseline"]["settings"]}
    assert last["shared_preload_libraries"] == "passwordcheck, pgaudit"
    assert steps[1]["chained"] is True and steps[0]["chained"] is False
    assert steps[1]["fix_unit"]["changes"][0]["rollback"] == {
        "action": "set_config_list", "param": "shared_preload_libraries", "values": ["passwordcheck"]}
    assert all(r["verified"] for r in output["combined_test"]["rollback"])
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        pgaudit = json.loads(archive.read("fix-pgaudit/fix.json"))
        report = archive.read("fix-pgaudit/report.html").decode()
    assert pgaudit["apply_statements"][0] == ("ALTER SYSTEM SET \"shared_preload_libraries\" = "
                                              "'passwordcheck', 'pgaudit'")
    assert pgaudit["prior"]["settings"]["shared_preload_libraries"]["setting"] == "passwordcheck"
    assert "Combined order" in report


@pytest.fixture(scope="module")
def preloaded_source(engine, image):
    """A source that already preloads pg_stat_statements (stock contrib), set with ALTER SYSTEM."""
    db = DisposablePostgres(image)
    try:
        db.start()
        db.sql("ALTER SYSTEM SET shared_preload_libraries = 'pg_stat_statements';")
        db.activate({"shared_preload_libraries": "pg_stat_statements"})
        snapshot = engine.collect(db)
    finally:
        assert db.close()["verified"] is True
    return snapshot, engine.assess(snapshot)


def test_3_2_keeps_an_existing_library_and_restores_it_exactly(engine, preloaded_source, image):
    snapshot, _ = preloaded_source
    row = next(r for r in snapshot["baseline"]["settings"] if r["name"] == "shared_preload_libraries")
    assert row["setting"] == "pg_stat_statements" and row["sourcefile"].endswith("postgresql.auto.conf")
    result = run(engine, preloaded_source, "3.2", image)
    attempt = assert_proof(result)
    rows = {r["name"]: r for r in attempt["after"]["baseline"]["settings"]}
    # Both loaded: the restarted server runs with both (a missing one stops the start, see
    # the stock-image test) and nothing is pending; pgaudit.log exists only once pgaudit loads.
    assert rows["shared_preload_libraries"]["setting"] == "pg_stat_statements, pgaudit"
    assert rows["shared_preload_libraries"]["pending_restart"] is False
    assert rows["pgaudit.log"]["setting"] == "ddl,role,write"
    assert result["rendered_rollback_sql"].splitlines()[2] == \
        "ALTER SYSTEM SET \"shared_preload_libraries\" = 'pg_stat_statements';"
    restored = next(r for r in attempt["rollback"]["baseline"]["settings"] if r["name"] == "shared_preload_libraries")
    assert {k: restored[k] for k in ("setting", "source", "sourcefile")} == \
        {k: row[k] for k in ("setting", "source", "sourcefile")}
    files = bundle(engine, preloaded_source, "3.2", result)
    config = json.loads(files["fix.json"])
    assert config["apply_statements"][0] == ("ALTER SYSTEM SET \"shared_preload_libraries\" = "
                                             "'pg_stat_statements', 'pgaudit'")
