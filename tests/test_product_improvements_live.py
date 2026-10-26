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


def _labelled(label, value):
    return docker("ps", "-aq", "--filter", f"label={label}={value}")


def _assert_no_leftovers(resources, sandbox_run_ids):
    """Every container this test created (demo registry, source, sandboxes) is gone."""
    from services.sandbox_poc.demo import DEMO_LABEL

    assert not _labelled(DEMO_LABEL, resources.run_id)
    assert not _labelled(LABEL, resources.target.run_id)
    for run_id in sandbox_run_ids:
        assert run_id and not _labelled(LABEL, run_id), run_id


def _row(snapshot, name):
    from services.sandbox_poc.provenance import setting_rows

    return setting_rows(snapshot)[name]


@pytest.mark.parametrize(
    "control,name,broken,fixed",
    [
        ("cis-pg17-v1.1.0:3.1.16", "debug_print_parse", "on", "off"),
        ("cis-pg17-v1.1.0:3.1.21", "log_disconnections", "off", "on"),
        ("cis-pg17-v1.1.0:6.9", "ssl_min_protocol_version", "TLSv1.1", "TLSv1.2"),
        ("cis-pg17-v1.1.0:3.1.7", "log_truncate_on_rotation", "off", "on"),
        ("cis-pg17-v1.1.0:3.1.11", "syslog_sequence_numbers", "off", "on"),
        ("cis-pg17-v1.1.0:3.1.17", "debug_print_rewritten", "on", "off"),
        ("cis-pg17-v1.1.0:3.1.18", "debug_print_plan", "on", "off"),
        ("cis-pg17-v1.1.0:3.1.19", "debug_pretty_print", "off", "on"),
        ("cis-pg17-v1.1.0:3.1.22", "log_error_verbosity", "terse", "verbose"),
        ("cis-pg17-v1.1.0:3.1.23", "log_hostname", "on", "off"),
    ],
)
def test_additional_setting_policies(control, name, broken, fixed):
    r = DemoResources()
    sandbox_runs = []
    try:
        r.start()
        r.target.sql(f"ALTER SYSTEM SET {name}='{broken}';")
        r.target.activate({name: broken})
        snapshot = r.engine.collect(r.target)
        original = _row(snapshot, name)
        assert original["setting"] == broken
        assert original["source"] == "configuration file"
        assert original["sourcefile"].endswith("/postgresql.auto.conf")
        # break -> FAIL
        assert r.engine.assess(snapshot)["findings"][control]["status"] == "FAIL"
        result = RemediationLoop(r.engine, demo_template(), control_id=control).run(
            snapshot, r.engine.assess(snapshot)
        )
        sandbox_runs = [a["run_id"] for a in result["attempts"]]
        print(f"LIVE-RUN {control} demo={r.run_id} source={r.target.run_id} "
              f"sandbox={','.join(sandbox_runs)} status={result['status']}")
        assert result["status"] == "VERIFIED", result
        attempt = result["attempts"][-1]
        assert result["fix_unit"]["requires"] == "reload"
        assert result["fix_unit"]["apply"] == {"action": "set_config", "param": name, "value": fixed}
        assert result["fix_unit"]["prior_state"]["value"] == broken
        assert result["fix_unit"]["prior_state"]["source"] == original["source"]
        # the sandbox reproduced the FAIL with the same provenance
        assert attempt["before_assessment"]["findings"][control]["status"] == "FAIL"
        before = _row(attempt["before"], name)
        assert (before["setting"], before["source"], before["sourcefile"]) == (
            broken, original["source"], original["sourcefile"])
        # fix -> PASS
        assert attempt["after_assessment"]["findings"][control]["status"] == "PASS"
        assert _row(attempt["after"], name)["setting"] == fixed
        assert attempt["regressions"] == []
        # rollback -> original value and source
        assert attempt["rollback_verified"]
        restored = _row(attempt["rollback"], name)
        assert (restored["setting"], restored["source"], restored["sourcefile"]) == (
            broken, original["source"], original["sourcefile"])
        assert attempt["rollback_assessment"]["findings"] == attempt["before_assessment"]["findings"]
        assert attempt["cleanup"]["verified"]
        assert r.target.sql("SHOW " + name + ";") == broken
    finally:
        r.close()
    _assert_no_leftovers(r, sandbox_runs)


@pytest.mark.parametrize(
    "control,name,default,fixed",
    [
        ("cis-pg17-v1.1.0:3.1.7", "log_truncate_on_rotation", "off", "on"),
        ("cis-pg17-v1.1.0:3.1.22", "log_error_verbosity", "default", "verbose"),
    ],
)
def test_default_sourced_setting_rolls_back_to_default_source(control, name, default, fixed):
    """The PG17 default already fails: rollback must return to source=default, not a file entry."""
    r = DemoResources()
    sandbox_runs = []
    try:
        r.start()
        snapshot = r.engine.collect(r.target)
        original = _row(snapshot, name)
        assert (original["setting"], original["source"], original["sourcefile"]) == (
            default, "default", None)
        assert r.engine.assess(snapshot)["findings"][control]["status"] == "FAIL"
        result = RemediationLoop(r.engine, demo_template(), control_id=control).run(
            snapshot, r.engine.assess(snapshot)
        )
        sandbox_runs = [a["run_id"] for a in result["attempts"]]
        print(f"LIVE-RUN default-{control} demo={r.run_id} source={r.target.run_id} "
              f"sandbox={','.join(sandbox_runs)} status={result['status']}")
        assert result["status"] == "VERIFIED", result
        attempt = result["attempts"][-1]
        assert attempt["after_assessment"]["findings"][control]["status"] == "PASS"
        assert _row(attempt["after"], name)["setting"] == fixed
        assert attempt["rollback_verified"]
        restored = _row(attempt["rollback"], name)
        assert (restored["setting"], restored["source"], restored["sourcefile"]) == (
            default, "default", None)
        assert not [f for f in attempt["rollback"]["baseline"]["file_settings"] if f["name"] == name]
        assert attempt["cleanup"]["verified"]
        assert r.target.sql("SHOW " + name + ";") == default
    finally:
        r.close()
    _assert_no_leftovers(r, sandbox_runs)


def test_three_new_fixes_combined(tmp_path, monkeypatch):
    from services.sandbox_poc.handoff import build_handoff

    monkeypatch.setenv("DBGUARD_HISTORY_DIR", str(tmp_path / "history"))
    broken = {"debug_print_rewritten": "on", "log_error_verbosity": "terse", "log_hostname": "on"}
    fixed = {"debug_print_rewritten": "off", "log_error_verbosity": "verbose", "log_hostname": "off"}
    controls = {"debug_print_rewritten": "cis-pg17-v1.1.0:3.1.17",
                "log_error_verbosity": "cis-pg17-v1.1.0:3.1.22",
                "log_hostname": "cis-pg17-v1.1.0:3.1.23"}
    r = DemoResources()
    combined_run = None
    try:
        r.start()
        for name, value in broken.items():
            r.target.sql(f"ALTER SYSTEM SET {name}='{value}';")
        r.target.activate(broken)
        snapshot = r.engine.collect(r.target)
        findings = r.engine.assess(snapshot)["findings"]
        assert all(findings[c]["status"] == "FAIL" for c in controls.values())
        base = build_handoff(r.engine, snapshot, r.handoff.template_ref)
        base.retry_mode = "repeat"
        requests = []
        for control in controls.values():
            request = base.model_copy(deep=True)
            request.control_id = control
            requests.append(request)
        result, data = run_batch(requests, SandboxService(r.registry_url))
        combined = result["combined_test"]
        combined_run = combined["run_id"]
        print(f"LIVE-RUN batch demo={r.run_id} source={r.target.run_id} combined={combined_run} "
              f"batch={result['run_id']} individual="
              f"{','.join(i['run_id'] for i in result['individual_runs'])} status={result['status']}")
        assert result["status"] == "VERIFIED", result
        assert all(i["status"] == "VERIFIED" for i in result["individual_runs"])
        assert sorted(i["fix_id"] for i in result["individual_runs"]) == sorted(
            "fix-" + n for n in controls)
        assert len(combined["steps"]) == 3
        # each fix PASSes in the combined sandbox with the earlier ones still applied
        applied = {}
        for step in combined["steps"]:
            name = step["fix_id"][len("fix-"):]
            applied[name] = fixed[name]
            assert step["assessment"]["findings"][controls[name]]["status"] == "PASS"
            assert step["functional_checks"]["passed"]
            for done, value in applied.items():
                assert _row(step["after"], done)["setting"] == value
        assert all(result["sandbox_after_findings"][c] == "PASS" for c in controls.values())
        # per-fix rollback in reverse order, each exact
        assert [x["fix_id"] for x in combined["rollback"]] == [
            s["fix_id"] for s in reversed(combined["steps"])]
        assert all(x["verified"] for x in combined["rollback"])
        assert combined["cleanup"]["verified"]
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            assert z.testzip() is None
            names = z.namelist()
            assert all(f"fix-{n}/fix.json" in names for n in controls)
            assert "combined-evidence.json" in names
        # the source target was never changed
        assert all(r.target.sql(f"SHOW {n};") == v for n, v in broken.items())
        assert r.source_evidence()["registry_unchanged"]
    finally:
        r.close()
    _assert_no_leftovers(r, [combined_run])


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
