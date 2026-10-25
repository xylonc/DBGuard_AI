"""Fault injection for acceptance gates and fresh-baseline retry behavior."""
import copy
from unittest.mock import Mock, MagicMock

import pytest

from scripts.sandbox_poc import demo_template
from services.sandbox_poc.provenance import FILES, reconstruction_plan
from services.sandbox_poc.shared import ContractError, ROOT, SpecEngine
from services.sandbox_poc.templates import ApprovedTemplate
from services.sandbox_poc.workflow import CONTROL, RemediationLoop


@pytest.fixture
def engine():
    return SpecEngine.load(ROOT / "catalog/specs/cis-pg17-v1.1.0",
                           ROOT / "catalog/benchmarks/cis-pg17-v1.1.0/records.json")


@pytest.fixture
def snapshot(engine):
    settings, checks, files = [], {}, []
    values = {"log_connections": "off", "debug_print_parse": "off", "log_disconnections": "on",
              "log_statement": "none", "ssl_min_protocol_version": "TLSv1.2"}
    for spec in engine.specs:
        sid = spec["spec_id"]
        entry = {"spec_hash": engine.hashes[sid], "query": "not applicable", "status": "not_collected"}
        if "check" in spec:
            name = spec["check"]["setting_name"]
            value = values[name]
            entry.update(query=spec["check"]["query"], status="ok", result=value)
            settings.append({"name": name, "setting": value, "context": "superuser-backend",
                             "source": "configuration file", "sourcefile": FILES[0],
                             "pending_restart": False})
            files.append({"name": name, "setting": value, "sourcefile": FILES[0],
                          "applied": True, "error": None})
        if "check" in spec:
            checks[sid] = entry
    return {"envelope": {"schema_version": "0.3.0", "database": "test", "target_id": "test",
                         "collector_sha256": engine.collector_hash,
                         "manifest": {"sha256": engine.manifest_hash, "manifest_version": 1,
                                      "benchmark_id": engine.records.benchmark_id, "check_count": len(checks)}},
            "baseline": {"identity": {"server_version_num": 170000}, "settings": settings,
                         "file_settings": files, "gaps": []}, "checks": checks}


class FakeRuntime:
    def __init__(self, snapshot, number, fault=None):
        self.original = copy.deepcopy(snapshot)
        self.snapshot = copy.deepcopy(snapshot)
        self.run_id = str(number)
        self.image_id = "sha256:test"
        self.closed = False
        self.fault = fault
        self.executed = []

    def start(self):
        if self.fault == "interrupt":
            raise KeyboardInterrupt()
        if self.fault == "create":
            raise RuntimeError("partial creation failure")

    def write_config(self, *args):
        pass

    def activate(self, expected):
        pass

    def health(self):
        return self.fault != "health"

    def sql(self, sql):
        self.executed.append(sql)
        if "RESET" in sql:
            if self.fault != "rollback":
                self.snapshot = copy.deepcopy(self.original)
            return "t"
        if self.fault == "apply":
            raise RuntimeError("partial apply failure")
        self.snapshot["checks"][CONTROL]["result"] = "on"
        for row in self.snapshot["baseline"]["settings"]:
            if row["name"] == "log_connections":
                row["setting"] = "on"
        if self.fault == "regression":
            self.snapshot["checks"]["cis-pg17-v1.1.0:3.1.21"]["result"] = "off"
        if self.fault == "gap":
            self.snapshot["checks"]["cis-pg17-v1.1.0:3.1.21"].update(status="error", error="denied")
        if self.fault == "missing":
            self.snapshot["checks"].pop("cis-pg17-v1.1.0:3.1.21")
        return "t"

    def close(self):
        self.closed = True
        if self.fault == "cleanup":
            raise RuntimeError("cleanup failure")
        if self.fault == "cleanup_unverified":
            return {"verified": False}
        return {"verified": True}


def run_fake(engine, snapshot, faults):
    runtimes = []
    def factory():
        runtime = FakeRuntime(snapshot, len(runtimes) + 1, faults[min(len(runtimes), len(faults)-1)])
        runtimes.append(runtime)
        return runtime
    engine.collect = lambda runtime: copy.deepcopy(runtime.snapshot)
    result = RemediationLoop(engine, demo_template(), factory).run(snapshot, engine.assess(snapshot))
    return result, runtimes


def test_success_requires_rollback_health_and_cleanup(engine, snapshot):
    result, runtimes = run_fake(engine, snapshot, [None])
    assert result["status"] == "VERIFIED"
    assert len(result["attempts"]) == 1
    assert result["attempts"][0]["rollback_verified"]
    assert all(r.closed for r in runtimes)


@pytest.mark.parametrize("fault", ["create", "apply", "regression", "gap", "rollback", "health"])
def test_failures_cannot_pass_and_stop_after_three_fresh_attempts(engine, snapshot, fault):
    result, runtimes = run_fake(engine, snapshot, [fault])
    assert result["status"] == "FAILED"
    assert len(runtimes) == 3
    assert len({r.run_id for r in runtimes}) == 3
    assert all(r.closed for r in runtimes)
    assert all(r.original == snapshot for r in runtimes)


def test_retry_can_recover_without_reusing_database(engine, snapshot):
    result, runtimes = run_fake(engine, snapshot, ["apply", None])
    assert result["status"] == "VERIFIED"
    assert len(runtimes) == 2
    assert runtimes[0].closed and runtimes[1].closed
    assert any("RESET" in sql for sql in runtimes[0].executed)


@pytest.mark.parametrize("fault", ["cleanup", "cleanup_unverified"])
def test_cleanup_failure_is_terminal_and_not_verified(engine, snapshot, fault):
    result, runtimes = run_fake(engine, snapshot, [fault])
    assert result["status"] == "CLEANUP_FAILED"
    assert len(runtimes) == 1


def test_missing_post_check_is_not_silently_ignored(engine, snapshot):
    result, _ = run_fake(engine, snapshot, ["missing"])
    assert result["status"] == "FAILED"


@pytest.mark.parametrize("change", ["hash", "query", "version", "assessment"])
def test_mismatched_input_never_starts_a_container(engine, snapshot, change):
    assessment = engine.assess(snapshot)
    if change == "hash":
        snapshot["checks"][CONTROL]["spec_hash"] = "0" * 64
    elif change == "query":
        snapshot["checks"][CONTROL]["query"] = "SHOW ssl"
    elif change == "version":
        snapshot["baseline"]["identity"]["server_version_num"] = 160000
    else:
        assessment["findings"][CONTROL]["status"] = "PASS"
    factory = Mock()
    with pytest.raises(ContractError):
        RemediationLoop(engine, demo_template(), factory).run(snapshot, assessment)
    factory.assert_not_called()


@pytest.mark.parametrize("field,value", [("source", "command line"), ("pending_restart", True),
                                         ("context", "postmaster"), ("sourcefile", "/custom/conf")])
def test_unsupported_provenance_is_rejected(engine, snapshot, field, value):
    snapshot["baseline"]["settings"][0][field] = value
    with pytest.raises(ContractError):
        reconstruction_plan(snapshot, engine.specs)


def test_template_hash_is_verified(engine, snapshot):
    template = demo_template()
    bad = ApprovedTemplate(template.registry_name, template.version, template.sql + "-- changed",
                           template.sha256, template.approved_by, template.evidence)
    with pytest.raises(ContractError, match="hash"):
        RemediationLoop(engine, bad).run(snapshot, engine.assess(snapshot))


def test_attempt_limit_cannot_exceed_three(engine):
    with pytest.raises(ContractError):
        RemediationLoop(engine, demo_template(), max_attempts=4)


def test_interruption_still_cleans_partial_container(engine, snapshot):
    runtime = FakeRuntime(snapshot, 1, "interrupt")
    with pytest.raises(KeyboardInterrupt):
        RemediationLoop(engine, demo_template(), lambda: runtime).run(snapshot, engine.assess(snapshot))
    assert runtime.closed


def test_registry_lookup_pins_version_hash_and_is_readonly(monkeypatch):
    import sys
    from services.sandbox_poc.templates import from_registry
    template = demo_template()
    driver = MagicMock()
    conn = driver.connect.return_value
    cursor = conn.cursor.return_value.__enter__.return_value
    cursor.fetchone.side_effect = [(template.sql, template.sha256, "reviewer", "12+"),
                                  ("doc-1", "1", "a" * 64, "reviewer")]
    monkeypatch.setitem(sys.modules, "psycopg2", driver)
    loaded = from_registry("postgresql://registry", 2, template.sha256, ["doc-1"])
    assert loaded.version == 2
    assert loaded.evidence[0]["document_id"] == "doc-1"
    conn.set_session.assert_called_once_with(readonly=True, isolation_level="REPEATABLE READ")
    assert cursor.execute.call_args_list[1].args[1] == ("set_config_parameter", 2, template.sha256)
    conn.close.assert_called_once()


def test_missing_registry_approval_is_not_replaced_by_latest(monkeypatch):
    import sys
    from services.sandbox_poc.templates import from_registry
    driver = MagicMock()
    conn = driver.connect.return_value
    conn.cursor.return_value.__enter__.return_value.fetchone.return_value = None
    monkeypatch.setitem(sys.modules, "psycopg2", driver)
    with pytest.raises(ContractError, match="Exact approved"):
        from_registry("postgresql://registry", 2, "0" * 64, ["doc-1"])
    conn.close.assert_called_once()
