"""Live 5.2 listen_addresses loop (Gate 1 ruling: the fix value must list localhost).

With an in-memory approved profile ``fixes: {5.2: "localhost, 10.0.0.5"}`` the
sandbox (--network none, loopback only) must restart PostgreSQL with the fix,
reach VERIFIED, roll back exactly and remove its containers. 10.0.0.5 cannot be
bound in the sandbox; PostgreSQL 17 logs a warning for it and keeps running
because localhost binds.

Run: DBGUARD_POC_LIVE=1 .venv-demo/bin/python -m pytest tests/test_listen_addresses_live.py
"""
import os

import pytest
import yaml

from app.services.spec_engine import RecordsIndex, load_spec
from app.services.spec_engine.policy import parse_profile
from scripts.sandbox_poc import demo_template
from services.sandbox_poc.planning import LISTEN_ADDRESSES_SANDBOX_LIMIT, risk_review
from services.sandbox_poc.provenance import setting_rows
from services.sandbox_poc.runtime import LABEL, DisposablePostgres, docker
from services.sandbox_poc.shared import ROOT, SpecEngine
from services.sandbox_poc.workflow import RemediationLoop

pytestmark = pytest.mark.skipif(
    os.environ.get("DBGUARD_POC_LIVE") != "1", reason="Disposable Docker integration"
)

B = "cis-pg17-v1.1.0"
SPEC_ID = f"{B}:5.2"
FIX = "localhost, 10.0.0.5"


def _engine():
    records = RecordsIndex.load(ROOT / f"catalog/benchmarks/{B}/records.json")
    spec = load_spec(ROOT / f"catalog/specs/{B}/5.2.yaml")
    # In-memory test profile only; the repository profile is never read or written here.
    doc = {"profile_id": "live-test-5.2", "benchmark": B, "approved_by": "Live Test Reviewer",
           "approved_at": "2026-10-27", "values": {}, "fixes": {SPEC_ID: FIX}}
    return SpecEngine([spec], records, parse_profile(yaml.safe_dump(doc).encode(), records))


# The auto.conf case is a regression test: the source's postgresql.conf line '*' is
# superseded by postgresql.auto.conf, and the sandbox image also writes
# listen_addresses = '*' into postgresql.conf, so the reconstructed sandbox has two
# identical unapplied postgresql.conf lines. provenance._shadowed_duplicate ignores
# only the earlier identical copy (see tests/test_provenance_superseded.py).
@pytest.mark.parametrize("source", ["postgresql.conf", "postgresql.auto.conf"])
def test_5_2_fix_with_localhost_verifies_and_rolls_back(source):
    engine = _engine()
    target = DisposablePostgres()
    sandbox_runs = []
    try:
        target.start()
        if source == "postgresql.auto.conf":
            target.sql("ALTER SYSTEM SET listen_addresses = '*';")
            target.activate({"listen_addresses": "*"})
        snapshot = engine.collect(target)
        original = setting_rows(snapshot)["listen_addresses"]
        assert original["setting"] == "*"
        assert original["sourcefile"].endswith("/" + source)
        # break -> FAIL (the postgres image listens on '*')
        assessment = engine.assess(snapshot)
        assert assessment["findings"][SPEC_ID]["status"] == "FAIL"
        review = risk_review(engine, snapshot, SPEC_ID)
        assert review["proposed_value"] == FIX and review["requires"] == "restart"
        assert LISTEN_ADDRESSES_SANDBOX_LIMIT in review["reasoning"]

        result = RemediationLoop(engine, demo_template(), control_id=SPEC_ID).run(snapshot, assessment)
        sandbox_runs = [a.get("run_id") for a in result["attempts"]]
        print(f"LIVE-RUN {SPEC_ID} source={source} target={target.run_id} "
              f"sandbox={','.join(map(str, sandbox_runs))} status={result['status']}")
        assert result["status"] == "VERIFIED", result
        assert result["fix_unit"]["requires"] == "restart"
        assert result["fix_unit"]["apply"] == {"action": "set_config", "param": "listen_addresses",
                                               "value": FIX}
        attempt = result["attempts"][-1]
        assert attempt["before_assessment"]["findings"][SPEC_ID]["status"] == "FAIL"
        # fix -> PASS, after a restart, with 10.0.0.5 unbindable in the sandbox
        assert attempt["after_assessment"]["findings"][SPEC_ID]["status"] == "PASS"
        assert setting_rows(attempt["after"])["listen_addresses"]["setting"] == FIX
        assert attempt["health_after_apply"] is True
        assert attempt["regressions"] == []
        # rollback -> original value and source
        assert attempt["rollback_verified"] is True and attempt["health_after_rollback"] is True
        restored = setting_rows(attempt["rollback"])["listen_addresses"]
        assert (restored["setting"], restored["source"], restored["sourcefile"]) == (
            "*", original["source"], original["sourcefile"])
        assert attempt["rollback_assessment"]["findings"] == attempt["before_assessment"]["findings"]
        assert all(a["cleanup"]["verified"] for a in result["attempts"])
        # the source container is untouched
        assert target.sql("SHOW listen_addresses;") == "*"
    finally:
        target.close()
    for run_id in sandbox_runs:
        assert run_id and not docker("ps", "-aq", "--filter", f"label={LABEL}={run_id}"), run_id
    assert not docker("ps", "-aq", "--filter", f"label={LABEL}={target.run_id}")


# db-security-reviewer WARN on 5.2: PostgreSQL resolves listen_addresses items with
# getaddrinfo, and glibc reads '0', '0x0' and '0.0.0.00' as 0.0.0.0. The live server
# really listens on all interfaces (0.0.0.0:5432 in /proc/net/tcp), and the 5.2
# check must never call that PASS: the operator raises, so the finding is an error.
# One run-labelled container; cleanup is asserted by its own run ID.
def test_numeric_all_interfaces_forms_bind_everywhere_and_never_pass():
    records = RecordsIndex.load(ROOT / f"catalog/benchmarks/{B}/records.json")
    engine = SpecEngine([load_spec(ROOT / f"catalog/specs/{B}/5.2.yaml")], records)
    target = DisposablePostgres()
    statuses = {}
    try:
        target.start()
        for value in ("0x0", "0", "0.0.0.00"):
            target.sql(f"ALTER SYSTEM SET listen_addresses = '{value}';")
            target.activate({"listen_addresses": value})  # reviewed restart setting
            assert target.sql("SHOW listen_addresses;") == value
            listening = [line.split() for line in
                         docker("exec", target.name, "cat", "/proc/net/tcp").splitlines()[1:]]
            # 0.0.0.0:5432 (hex 1538) in state LISTEN (0A): every IPv4 interface
            assert any(cols[1] == "00000000:1538" and cols[3] == "0A" for cols in listening), value
            snapshot = engine.collect(target)
            assert setting_rows(snapshot)["listen_addresses"]["setting"] == value
            statuses[value] = engine.assess(snapshot)["findings"][SPEC_ID]["status"]
        print(f"LIVE-RUN numeric-5.2 target={target.run_id} statuses={statuses}")
    finally:
        target.close()
    assert not docker("ps", "-aq", "--filter", f"label={LABEL}={target.run_id}")
    assert statuses and all(status in ("ERROR", "GAPPED") for status in statuses.values()), statuses
