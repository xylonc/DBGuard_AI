"""Opt-in real PostgreSQL tests, separate from legacy expected failures."""
import os

import pytest

from scripts.sandbox_poc import run_demo
from services.sandbox_poc.runtime import LABEL, DisposablePostgres, docker
from services.sandbox_poc.shared import ROOT, SpecEngine, validate_contract
from services.sandbox_poc.workflow import CONTROL

pytestmark = pytest.mark.skipif(os.environ.get("DBGUARD_POC_LIVE") != "1",
                                reason="Set DBGUARD_POC_LIVE=1 with Docker and postgres:17-bookworm available")


@pytest.mark.parametrize("source", ["conf", "auto"])
def test_real_fail_pass_exact_rollback_and_cleanup(source):
    engine = SpecEngine.load(ROOT / "catalog/specs/cis-pg17-v1.1.0",
                             ROOT / "catalog/benchmarks/cis-pg17-v1.1.0/records.json")
    existing = set(docker("ps", "-aq", "--filter", f"label={LABEL}").split())
    result = run_demo(engine, "postgres:17-bookworm", source)
    assert result["status"] == "VERIFIED", result["attempts"]
    validate_contract(result["fix_unit"], "fix-unit-v1.json")
    assert result["demo_target_cleanup"]["verified"]
    assert len(result["attempts"]) == 1
    attempt = result["attempts"][0]
    assert attempt["before_assessment"]["findings"][CONTROL]["status"] == "FAIL"
    assert attempt["after_assessment"]["findings"][CONTROL]["status"] == "PASS"
    assert attempt["rollback_assessment"]["findings"][CONTROL]["status"] == "FAIL"
    assert attempt["rollback_verified"] and attempt["cleanup"]["verified"]
    assert not attempt["regressions"]
    assert attempt["health_after_apply"] and attempt["health_after_rollback"]
    assert set(docker("ps", "-aq", "--filter", f"label={LABEL}").split()) == existing


def test_real_partial_apply_rolls_back_and_cleans_all_three_attempts():
    engine = SpecEngine.load(ROOT / "catalog/specs/cis-pg17-v1.1.0",
                             ROOT / "catalog/benchmarks/cis-pg17-v1.1.0/records.json")
    existing = set(docker("ps", "-aq", "--filter", f"label={LABEL}").split())
    class FailAfterApply(DisposablePostgres):
        def sql(self, script):
            result = super().sql(script)
            if 'ALTER SYSTEM SET "log_connections"' in script:
                raise RuntimeError("Injected failure after real ALTER SYSTEM execution")
            return result
    result = run_demo(engine, "postgres:17-bookworm", "conf", FailAfterApply)
    assert result["status"] == "FAILED"
    assert len(result["attempts"]) == 3
    assert len({a["run_id"] for a in result["attempts"]}) == 3
    assert all(a["rollback_verified"] and a["cleanup"]["verified"] for a in result["attempts"])
    assert result["demo_target_cleanup"]["verified"]
    assert set(docker("ps", "-aq", "--filter", f"label={LABEL}").split()) == existing
