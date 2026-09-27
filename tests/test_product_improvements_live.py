import copy
import io
import json
import os
import zipfile
from pathlib import Path
import pytest
import yaml
from services.sandbox_poc.demo import DemoResources
from services.sandbox_poc.service import SandboxService
from services.sandbox_poc.batch import run_batch
from services.sandbox_poc.shared import ROOT, SpecEngine
from services.sandbox_poc.workflow import RemediationLoop
from services.sandbox_poc.runtime import DisposablePostgres, docker, LABEL
from scripts.sandbox_poc import demo_template
from services.sandbox_poc.review_bundle import build_review_bundle

pytestmark = pytest.mark.skipif(
    os.environ.get("DBGUARD_POC_LIVE") != "1", reason="Disposable Docker integration"
)


def test_two_fixes_combined_and_actual_screenshot(tmp_path, monkeypatch):
    monkeypatch.setenv("DBGUARD_HISTORY_DIR", str(tmp_path / "history"))
    monkeypatch.setenv("DBGUARD_SCREENSHOTS", "true")
    r = DemoResources()
    try:
        r.start()
        service = SandboxService(r.registry_url)
        a = r.handoff.model_copy(deep=True)
        a.retry_mode = "repeat"
        b = a.model_copy(deep=True)
        b.control_id = "cis-pg17-v1.1.0:3.1.25"
        result, data = run_batch([a, b], service)
        assert result["status"] == "VERIFIED", result
        assert len(result["combined_test"]["steps"]) == 2
        assert all(
            s["functional_checks"]["screenshot"]["status"] == "CAPTURED"
            for s in result["combined_test"]["steps"]
        )
        assert all(s["verified"] for s in result["combined_test"]["rollback"])
        assert result["combined_test"]["cleanup"]["verified"]
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            assert z.testzip() is None
            assert "fix-log_statement/sandbox-after.png" in z.namelist()
        assert r.source_evidence()["source_unchanged"]
        out = Path(os.environ.get("DBGUARD_TEST_EVIDENCE_DIR", str(tmp_path)))
        out.mkdir(parents=True, exist_ok=True)
        (out / "combined-review.zip").write_bytes(data)
        (out / "combined-result.json").write_text(json.dumps(result, indent=2))
    finally:
        r.close()


def test_restart_control_reproduce_apply_and_exact_rollback(tmp_path, monkeypatch):
    spec = yaml.safe_load(
        (ROOT / "catalog/specs-examples/logging_collector.yaml").read_text()
    )
    from app.services.spec_engine import RecordsIndex

    engine = SpecEngine(
        [spec],
        RecordsIndex.load(ROOT / "catalog/benchmarks/cis-pg17-v1.1.0/records.json"),
    )
    target = DisposablePostgres()
    try:
        target.start()
        snapshot = engine.collect(target)
        assert snapshot["checks"][spec["spec_id"]]["result"] == "off"
        result = RemediationLoop(
            engine, demo_template(), control_id=spec["spec_id"]
        ).run(snapshot, engine.assess(snapshot))
        assert result["status"] == "VERIFIED", result
        assert result["fix_unit"]["requires"] == "restart"
        assert result["attempts"][-1]["rollback_verified"]
        assert result["attempts"][-1]["cleanup"]["verified"]
        assert target.sql("SHOW logging_collector;") == "off"
    finally:
        target.close()


def test_target_apply_query_screenshot_reassessment_and_rollback(tmp_path, monkeypatch):
    import subprocess, sys
    from test_review_bundle_live import published_target
    from services.sandbox_poc.handoff import build_handoff
    from services.sandbox_poc import history

    monkeypatch.setenv("DBGUARD_HISTORY_DIR", str(tmp_path / "history"))
    r = DemoResources()
    try:
        r.start()
        with published_target() as (target, dsn):
            target.sql("ALTER SYSTEM SET log_connections='off';")
            target.activate({"log_connections": "off"})
            before = r.engine.collect(target)
            handoff = build_handoff(r.engine, before, r.handoff.template_ref)
            service = SandboxService(r.registry_url)
            result = service.run(handoff)
            assert result["status"] == "VERIFIED", result
            bundle = build_review_bundle(handoff, result, r.engine)
            history.record(handoff, result, bundle)
            folder = tmp_path / "bundle"
            folder.mkdir()
            with zipfile.ZipFile(io.BytesIO(bundle)) as z:
                z.extractall(folder)
            env = {**os.environ, "DBGUARD_DSN": dsn}
            command = [sys.executable, str(folder / "runner.py")]
            evidence = tmp_path / "target-evidence"
            applied = subprocess.run(
                [
                    *command,
                    "apply",
                    "fix-log_connections",
                    "--allow-demo",
                    "--ack-prerequisites",
                    "--screenshots",
                    "--evidence-dir",
                    str(evidence),
                ],
                env=env,
                capture_output=True,
                text=True,
            )
            assert applied.returncode == 0, applied.stderr
            assert list(evidence.glob("*/database-results.png"))
            after = r.engine.collect(target)
            assert (
                history.compare(result["run_id"], after, r.engine)["status"]
                == "TARGET_REASSESSMENT_CONFIRMED"
            )
            rolled = subprocess.run(
                [
                    *command,
                    "rollback",
                    "fix-log_connections",
                    "--allow-demo",
                    "--evidence-dir",
                    str(evidence),
                ],
                env=env,
                capture_output=True,
                text=True,
            )
            assert rolled.returncode == 0, rolled.stderr
            from services.sandbox_poc.provenance import signature

            names = [s["check"]["setting_name"] for s in r.engine.specs if "check" in s]
            assert signature(r.engine.collect(target), names) == signature(
                before, names
            )
            out = Path(os.environ.get("DBGUARD_TEST_EVIDENCE_DIR", str(tmp_path)))
            import shutil

            if evidence.resolve() != (out / "target-evidence").resolve():
                shutil.copytree(evidence, out / "target-evidence", dirs_exist_ok=True)
    finally:
        r.close()


@pytest.mark.skipif(
    os.environ.get("DBGUARD_LLM_LIVE") != "1", reason="Requires configured live model"
)
def test_live_llm_revises_using_separately_approved_named_template(
    tmp_path, monkeypatch
):
    import hashlib, psycopg2
    from services.sandbox_poc.adaptive import LLMReviser
    from services.sandbox_poc.templates import export_reference
    from scripts.demo import read_env
    from services.sandbox_poc.handoff import build_handoff

    monkeypatch.setenv("DBGUARD_HISTORY_DIR", str(tmp_path / "history"))
    cfg = read_env(ROOT / ".env.demo")
    reviewer = LLMReviser(
        cfg.get("HERMES_MODEL_BASE_URL", "https://ollama.com/v1"),
        cfg.get("HERMES_MODEL", "gpt-oss:20b"),
        cfg["OLLAMA_API_KEY"],
    )
    r = DemoResources()
    try:
        r.start()
        good = (ROOT / "backend/app/templates/set_config_parameter.sql.j2").read_text()
        bad = "ALTER SYSTEM SET log_connections = 'off'; SELECT pg_reload_conf();"
        with psycopg2.connect(**r.admin) as conn:
            with conn.cursor() as cur:
                cur.execute(
                    "UPDATE templates SET status='archived' WHERE template_name='set_config_parameter'"
                )
                for name, version, sql in [
                    ("set_config_parameter", 2, bad),
                    ("set_config_parameter__improved", 1, good),
                ]:
                    cur.execute(
                        "INSERT INTO templates(template_name,version,description,sql_template,template_hash,pg_version,status,approved_by,approved_at) VALUES(%s,%s,'Explicit disposable adaptive test fixture',%s,%s,'17','active','INTEGRATION_TEST_ONLY',now())",
                        (name, version, sql, hashlib.sha256(sql.encode()).hexdigest()),
                    )
        reference, _ = export_reference(r.registry_url, 2, ["demo-evidence"], "test")
        alternate, _ = export_reference(
            r.registry_url,
            1,
            ["demo-evidence"],
            "test",
            registry_name="set_config_parameter__improved",
        )
        handoff = build_handoff(r.engine, r.snapshot, reference)
        handoff.retry_mode = "adaptive"
        handoff.retry_template_refs = [alternate]
        result = SandboxService(r.registry_url, reviser=reviewer).run(handoff)
        assert result["status"] == "VERIFIED", result
        assert (
            len(result["attempts"]) == 2 and result["revisions"][0]["action"] == "retry"
        )
        assert result["template"]["registry_name"] == "set_config_parameter__improved"
        assert all(
            a["cleanup"]["verified"] and a["rollback_verified"]
            for a in result["attempts"]
        )
        assert build_review_bundle(handoff, result, r.engine)
        out = Path(os.environ.get("DBGUARD_TEST_EVIDENCE_DIR", str(tmp_path)))
        out.mkdir(parents=True, exist_ok=True)
        (out / "live-adaptive-result.json").write_text(json.dumps(result, indent=2))
    finally:
        r.close()


@pytest.mark.parametrize(
    "control,name,broken",
    [
        ("cis-pg17-v1.1.0:3.1.16", "debug_print_parse", "on"),
        ("cis-pg17-v1.1.0:3.1.21", "log_disconnections", "off"),
        ("cis-pg17-v1.1.0:6.9", "ssl_min_protocol_version", "TLSv1.1"),
    ],
)
def test_additional_setting_policies(control, name, broken):
    r = DemoResources()
    try:
        r.start()
        r.target.sql(f"ALTER SYSTEM SET {name}='{broken}';")
        r.target.activate({name: broken})
        snapshot = r.engine.collect(r.target)
        result = RemediationLoop(r.engine, demo_template(), control_id=control).run(
            snapshot, r.engine.assess(snapshot)
        )
        assert result["status"] == "VERIFIED", result
        assert result["attempts"][-1]["rollback_verified"]
        assert result["attempts"][-1]["cleanup"]["verified"]
        assert r.target.sql("SHOW " + name + ";") == broken
    finally:
        r.close()


def test_exported_restart_fix_waits_for_dba_restart(tmp_path):
    import importlib.util
    from test_review_bundle_live import published_target
    from app.services.spec_engine import RecordsIndex
    from services.sandbox_poc.handoff import build_handoff

    spec = yaml.safe_load(
        (ROOT / "catalog/specs-examples/logging_collector.yaml").read_text()
    )
    engine = SpecEngine(
        [spec],
        RecordsIndex.load(ROOT / "catalog/benchmarks/cis-pg17-v1.1.0/records.json"),
    )
    resources = DemoResources()
    try:
        resources.start()
        with published_target() as (target, dsn):
            snapshot = engine.collect(target)
            handoff = build_handoff(engine, snapshot, resources.handoff.template_ref)
            handoff.control_id = spec["spec_id"]
            result = SandboxService(resources.registry_url).run(handoff)
            assert result["status"] == "VERIFIED", result
            with zipfile.ZipFile(
                io.BytesIO(build_review_bundle(handoff, result, engine))
            ) as archive:
                archive.extractall(tmp_path)
            module_spec = importlib.util.spec_from_file_location(
                "restart_runner", tmp_path / "runner.py"
            )
            runner = importlib.util.module_from_spec(module_spec)
            module_spec.loader.exec_module(runner)
            config = json.loads((tmp_path / "fix.json").read_text())
            applied = runner.execute(config, "apply", dsn, True)
            assert applied["status"] == "RESTART_REQUIRED" and not applied["verified"]
            assert target.sql("SHOW logging_collector;") == "off"
            target.activate(
                {"logging_collector": "on"}
            )  # owned target: simulates the separate DBA restart
            assert runner.execute(config, "verify", dsn, True)["verified"]
            rolled = runner.execute(config, "rollback", dsn, True)
            assert rolled["status"] == "RESTART_REQUIRED"
            target.activate({"logging_collector": "off"})
            assert runner.execute(config, "verify-rollback", dsn, True)["verified"]
    finally:
        resources.close()
