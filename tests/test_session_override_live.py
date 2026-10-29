"""Live: a per-role or per-database override on a disposable PostgreSQL 17 is GAPPED.

ALTER ROLE <collector role> SET log_statement = 'ddl' (postgresql.conf keeps the
default 'none') makes the collector's own session read 'ddl'. The real collector
reports source 'user' for that row, and 3.1.25 must be GAPPED (session_override),
never PASS, in the Phase 1 report, the sandbox projection and the offline ASSESS
controls. ALTER DATABASE gives source 'database', with the same result.

Needs DBGUARD_POC_LIVE=1 and Docker. Every container is labelled with this test's
own run ID and must be gone afterwards.
"""
import os

import pytest

from app.services.assessment_service import AssessmentService
from catalog.controls.assess.registry import CONTROL_REGISTRY
from services.sandbox_poc.planning import session_override_reason
from services.sandbox_poc.runtime import LABEL, DisposablePostgres, docker
from services.sandbox_poc.shared import ROOT, SpecEngine

pytestmark = pytest.mark.skipif(os.environ.get("DBGUARD_POC_LIVE") != "1",
                                reason="Disposable Docker integration")

S3125 = "cis-pg17-v1.1.0:3.1.25"


def _row(snapshot, name):
    return next(r for r in snapshot["baseline"]["settings"] if r["name"] == name)


@pytest.mark.parametrize("statement,source", [
    ("ALTER ROLE dbguard_poc SET log_statement = 'ddl';", "user"),
    ("ALTER DATABASE dbguard_sandbox SET log_statement = 'ddl';", "database"),
])
def test_override_on_real_collector_is_gapped(statement, source):
    engine = SpecEngine.load(ROOT / "catalog/specs/cis-pg17-v1.1.0",
                             ROOT / "catalog/benchmarks/cis-pg17-v1.1.0/records.json")
    target = DisposablePostgres()
    run_id = target.run_id
    try:
        target.start()
        before = engine.collect(target)
        assert _row(before, "log_statement")["source"] == "default"
        assert engine.assess(before)["findings"][S3125]["status"] == "FAIL"

        target.sql(statement)
        snapshot = engine.collect(target)
        row = _row(snapshot, "log_statement")
        assert (row["setting"], row["source"]) == ("ddl", source)
        assert snapshot["checks"][S3125]["result"] == "ddl"

        report = engine.assess(snapshot)
        finding = report["findings"][S3125]
        assert finding["status"] == "GAPPED", finding
        assert finding["explanation"] == {"code": "session_override", "evidence": "check",
                                          "setting_name": "log_statement", "source": source}
        upstream = next(r for r in report["upstream_report"]["results"] if r["spec_id"] == S3125)
        assert (upstream["result"], upstream["reason_code"]) == ("NOT_COLLECTED", "session_override")
        assert "no sandbox fix can run on this snapshot" in session_override_reason(finding)

        offline = AssessmentService(CONTROL_REGISTRY).evaluate_control(snapshot["baseline"], S3125)
        assert offline.status.value == "GAPPED"
        assert offline.explanation["code"] == "session_override"
        print(f"LIVE-RUN session-override source={source} target={run_id} status={finding['status']}")
    finally:
        cleanup = target.close()
    assert cleanup.get("verified") is True, cleanup
    assert not docker("ps", "-aq", "--filter", f"label={LABEL}={run_id}"), run_id
