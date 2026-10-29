"""A value set per role, database or session must never give PASS or FAIL.

Checks read SHOW / current_setting() in the collector's session. If the target sets
e.g. ALTER ROLE <collector> SET log_statement = 'ddl' while postgresql.conf has
'none', 3.1.25 must be GAPPED (NOT_COLLECTED session_override), not PASS. The
source of each value comes from the snapshot's settings rows (pg_settings.source).

Covers the Phase 1 assessor (and the sandbox SpecEngine projection built on it),
the offline ASSESS spec controls, the collector-pinned-setting spec rule, and the
sandbox guards and fix-plan reason. No Docker, network or model.
"""
import copy
import json
import re

import jsonschema
import pytest

from app.models import FindingStatus
from app.services.spec_engine import RecordsIndex, assess, validate_spec
from app.services.spec_engine.manifest import condition_check_id
from app.services.spec_engine.sources import COLLECTOR_PINNED_SETTINGS, SERVER_WIDE_SOURCES, session_override
from catalog.controls.assess.spec_controls import _setting_rule
from scripts.sandbox_poc import demo_template
from services.sandbox_poc.planning import session_override_reason
from services.sandbox_poc.provenance import setting_rows
from services.sandbox_poc.shared import ROOT, ContractError
from services.sandbox_poc.workflow import CONTROL, RemediationLoop
from test_sandbox_poc import engine, snapshot  # noqa: F401  shared fixtures

B = "cis-pg17-v1.1.0"
S3125 = f"{B}:3.1.25"   # log_statement, expected ddl
S3111 = f"{B}:3.1.11"   # syslog_sequence_numbers, applies when log_destination includes syslog
REPORT_SCHEMA = json.loads((ROOT / "catalog/specs/contracts/assessment-report-v1.json").read_text())

# Written out from PostgreSQL 17 guc.c GucSource_Names, not read from sources.py.
SERVER_WIDE = ["default", "environment variable", "configuration file", "command line", "override"]
PER_SESSION = ["user", "database", "database user", "global", "client", "session", "interactive", "test"]
UNKNOWN = ["", "ldap", "Configuration File", None, 7]


def with_source(snap, name, source, value=None, check_ids=()):
    snap = copy.deepcopy(snap)
    row = setting_rows(snap)[name]
    row["source"] = source
    if value is not None:
        row["setting"] = value
        for sid in check_ids:
            snap["checks"][sid]["result"] = value
    return snap


def report_row(engine, snap, sid):
    report = assess(engine.specs, snap, engine.records)
    jsonschema.validate(report, REPORT_SCHEMA)
    return next(r for r in report["results"] if r["spec_id"] == sid)


def test_source_lists_are_pg17():
    assert SERVER_WIDE_SOURCES == set(SERVER_WIDE)
    assert COLLECTOR_PINNED_SETTINGS == {"search_path", "standard_conforming_strings"}


# ---------------------------------------------------------------------------
# Phase 1 assessor and the sandbox projection
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("value", ["ddl", "none"])  # would be PASS / FAIL server-wide
@pytest.mark.parametrize("source", PER_SESSION + UNKNOWN)
def test_overridden_check_setting_is_gapped(engine, snapshot, source, value):
    snap = with_source(snapshot, "log_statement", source, value, [S3125])
    row = report_row(engine, snap, S3125)
    assert (row["result"], row["reason_code"]) == ("NOT_COLLECTED", "session_override")
    assert row["explanation"] == {"code": "session_override", "evidence": "check", "setting_name": "log_statement",
                                  "source": source if isinstance(source, str) else None}
    assert row["cis"]["recommendation"] == "3.1.25"
    finding = engine.assess(snap)["findings"][S3125]
    assert finding["status"] == "GAPPED"
    assert finding["explanation"]["code"] == "session_override"


@pytest.mark.parametrize("source", ["user", "database"])
def test_role_and_database_overrides_never_pass(engine, snapshot, source):
    """ALTER ROLE / ALTER DATABASE ... SET log_statement = 'ddl' (conf says none)."""
    snap = with_source(snapshot, "log_statement", source, "ddl", [S3125])
    assert engine.assess(snap)["findings"][S3125]["status"] == "GAPPED"
    # the same evidence with a server-wide source passes
    assert engine.assess(with_source(snap, "log_statement", "configuration file"))["findings"][S3125]["status"] == "PASS"


@pytest.mark.parametrize("source", SERVER_WIDE)
def test_server_wide_source_evaluates_normally(engine, snapshot, source):
    assert report_row(engine, with_source(snapshot, "log_statement", source), S3125)["result"] == "FAIL"
    row = report_row(engine, with_source(snapshot, "log_statement", source, "ddl", [S3125]), S3125)
    assert (row["result"], row["reason_code"]) == ("PASS", "operator_true")
    assert "explanation" not in row


@pytest.mark.parametrize("source", ["database", "database user", "session"])
def test_overridden_condition_setting_is_gapped_not_not_applicable(engine, snapshot, source):
    # log_destination 'stderr' would make 3.1.11 NOT_APPLICABLE server-wide.
    assert engine.assess(snapshot)["findings"][S3111]["status"] == "NOT_APPLICABLE"
    snap = with_source(snapshot, "log_destination", source)
    row = report_row(engine, snap, S3111)
    assert (row["result"], row["reason_code"]) == ("NOT_COLLECTED", "condition_session_override")
    explanation = row["explanation"]
    assert explanation["code"] == "condition_unknown"
    assert explanation["cause"] == "session_override"
    assert explanation["evidence"] == "condition"
    assert explanation["source"] == source
    assert explanation["setting_name"] == "log_destination"
    assert engine.assess(snap)["findings"][S3111]["status"] == "GAPPED"
    # and a condition that would be true is not decided either
    snap = with_source(snapshot, "log_destination", source, "stderr,syslog")
    snap["checks"][condition_check_id(S3111)]["result"] = "stderr,syslog"
    assert report_row(engine, snap, S3111)["reason_code"] == "condition_session_override"


def test_main_evidence_problem_is_reported_before_the_override(engine, snapshot):
    snap = with_source(snapshot, "log_statement", "user")
    snap["checks"][S3125]["status"] = "error"
    snap["checks"][S3125]["error"] = "permission denied"
    assert report_row(engine, snap, S3125)["reason_code"] == "status_error"


def test_missing_row_source_or_section_keeps_existing_behaviour(engine, snapshot):
    snap = copy.deepcopy(snapshot)
    snap["baseline"]["settings"] = [r for r in snap["baseline"]["settings"] if r["name"] != "log_statement"]
    assert report_row(engine, snap, S3125)["result"] == "FAIL"
    snap = copy.deepcopy(snapshot)
    del setting_rows(snap)["log_statement"]["source"]
    assert report_row(engine, snap, S3125)["result"] == "FAIL"
    snap = copy.deepcopy(snapshot)
    snap["baseline"]["settings"] = None
    assert assess(engine.specs, snap, engine.records)["results"]
    assert session_override(None, "log_statement") is None


# ---------------------------------------------------------------------------
# Offline ASSESS spec controls (collector bundle rows)
# ---------------------------------------------------------------------------

def bundle(rows):
    return {"identity": {"server_version_num": 170011},
            "settings": [{"vartype": "enum", "unit": None, **row} for row in rows]}


def spec(engine, sid):
    return next(s for s in engine.specs if s["spec_id"] == sid)


@pytest.mark.parametrize("source", ["user", "database", "database user", "client", "session", None])
def test_assess_control_gaps_an_overridden_setting(engine, source):
    rule = _setting_rule(spec(engine, S3125))
    finding = rule(bundle([{"name": "log_statement", "setting": "ddl", "source": source}]))
    assert finding.status == FindingStatus.GAPPED and finding.is_gapped
    assert finding.explanation == {"code": "session_override", "evidence": "check", "setting_name": "log_statement",
                                   "source": source}
    assert finding.cis == {"recommendation": "3.1.25", "title": spec(engine, S3125)["ref"]["title"]}


@pytest.mark.parametrize("source", SERVER_WIDE)
def test_assess_control_server_wide_source_evaluates(engine, source):
    rule = _setting_rule(spec(engine, S3125))
    assert rule(bundle([{"name": "log_statement", "setting": "ddl", "source": source}])).status == FindingStatus.PASS
    assert rule(bundle([{"name": "log_statement", "setting": "none", "source": source}])).status == FindingStatus.FAIL
    # a row without source keeps the existing reading
    assert rule(bundle([{"name": "log_statement", "setting": "ddl"}])).status == FindingStatus.PASS


def test_assess_control_overridden_condition(engine):
    rule = _setting_rule(spec(engine, S3111))
    rows = [{"name": "syslog_sequence_numbers", "setting": "on", "vartype": "bool", "source": "default"},
            {"name": "log_destination", "setting": "stderr", "vartype": "string", "source": "user"}]
    finding = rule(bundle(rows))
    assert finding.status == FindingStatus.GAPPED
    assert finding.explanation["code"] == "condition_unknown"
    assert finding.explanation["cause"] == "session_override"
    assert finding.explanation["source"] == "user"
    rows[1]["source"] = "configuration file"
    assert rule(bundle(rows)).status == FindingStatus.NOT_APPLICABLE


# ---------------------------------------------------------------------------
# No spec may use a collector-pinned setting
# ---------------------------------------------------------------------------

RECORDS = RecordsIndex.load(ROOT / f"catalog/benchmarks/{B}/records.json")


def test_pinned_settings_match_the_collector():
    """Every top-level SET in collect.sql is pinned here, and nothing else."""
    sql = (ROOT / "collector/collect.sql").read_text()
    pinned = set(re.findall(r"^SET\s+([a-z_]+)\s*(?:=|TO)", sql, re.I | re.M))
    assert {name.lower() for name in pinned} == COLLECTOR_PINNED_SETTINGS


@pytest.mark.parametrize("name", sorted(COLLECTOR_PINNED_SETTINGS))
def test_spec_checking_a_pinned_setting_is_rejected(engine, name):
    bad = copy.deepcopy(spec(engine, S3125))
    bad["check"].update(setting_name=name, query=f"SHOW {name}")
    assert any("set by the collector in its own session" in e for e in validate_spec(bad, RECORDS))


@pytest.mark.parametrize("name", sorted(COLLECTOR_PINNED_SETTINGS))
def test_applies_when_on_a_pinned_setting_is_rejected(engine, name):
    good = copy.deepcopy(spec(engine, S3111))
    assert validate_spec(good, RECORDS) == []
    good["applies_when"]["setting_name"] = name
    assert any("applies_when.setting_name" in e and "set by the collector" in e
               for e in validate_spec(good, RECORDS))


def test_no_installed_spec_uses_a_pinned_setting(engine):
    for s in engine.specs:
        assert (s.get("check") or {}).get("setting_name") not in COLLECTOR_PINNED_SETTINGS
        assert (s.get("applies_when") or {}).get("setting_name") not in COLLECTOR_PINNED_SETTINGS


# ---------------------------------------------------------------------------
# Sandbox: the no-GAPPED guard blocks, and the fix plan says why
# ---------------------------------------------------------------------------

def test_override_blocks_sandbox_fixes_and_is_explained(engine, snapshot):
    snap = with_source(snapshot, "log_statement", "user", "ddl", [S3125])
    assessment = engine.assess(snap)
    assert assessment["findings"][CONTROL]["status"] == "FAIL"   # 3.1.20 itself is fixable
    reason = session_override_reason(assessment["findings"][S3125])
    assert reason.startswith("Unknown: its value (log_statement) is set per role, database or session "
                             "(source 'user')")
    assert "no sandbox fix can run on this snapshot" in reason
    created = []
    with pytest.raises(ContractError, match="gapped controls"):
        RemediationLoop(engine, demo_template(), lambda: created.append(1)).run(snap, assessment)
    assert created == []   # refused before any container


def test_override_reason_for_condition_and_other_gaps(engine, snapshot):
    findings = engine.assess(with_source(snapshot, "log_destination", "database"))["findings"]
    assert session_override_reason(findings[S3111]).startswith(
        "Unknown: the setting it depends on (log_destination) is set per role, database or session "
        "(source 'database')")
    assert session_override_reason({"status": "GAPPED", "explanation": {"code": "not_collected"}}) is None
    assert session_override_reason({"status": "FAIL"}) is None


def test_handoff_guard_names_the_override(engine, snapshot):
    from services.sandbox_poc.handoff import TemplateReference, build_handoff
    from services.sandbox_poc.service import SandboxService
    template = demo_template()
    ref = TemplateReference(version=template.version, sha256=template.sha256,
                            evidence=[dict(document_id="test-doc", version="1", sha256="a" * 64)])
    snap = with_source(snapshot, "log_statement", "user", "ddl", [S3125])
    handoff = build_handoff(engine, snap, ref)
    with pytest.raises(ContractError, match=r"regression coverage\. Unknown: its value \(log_statement\)"):
        SandboxService("postgresql://unused").validate_handoff(handoff)


def test_fix_plan_explains_the_override(engine, snapshot, monkeypatch):
    from types import SimpleNamespace
    from services.sandbox_poc import router
    snap = with_source(snapshot, "log_statement", "user", "ddl", [S3125])
    monkeypatch.setattr(router, "assess_uploaded", lambda *a: (engine, snap, engine.assess(snap)))
    plan = router.fix_plan("snap-x", B, False, store=None, service=SimpleNamespace(risk_reviewer=None))
    item = next(m for m in plan["manual_review"] if m["spec_id"] == S3125)
    assert item["status"] == "GAPPED"
    assert item["reason"] == session_override_reason(engine.assess(snap)["findings"][S3125])
    assert S3125 not in [f["spec_id"] for f in plan["recommended_order"]]
