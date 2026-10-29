"""Sandbox scope for catalog checks (Melvin: "Skip now, skeleton next week").

Default, shared.SANDBOX_COMPARES_CATALOG = False: the sandbox findings map holds
the 29 non-catalog specs only, so the no-GAPPED guards, regressions and
reproduction/rollback equality in service, workflow, review_bundle, batch and
history ignore the 10 catalog specs. upstream_report keeps all 39 rows.

Switch True (monkeypatched in TestCatalogCompared): catalog findings stay in the
map; the no-GAPPED guards still skip them (gapped_settings), the PASS clause and
reproduction equality cover them.

Fake runtimes only: no Docker, network or model.
"""
import copy
import io
import re
import zipfile
from dataclasses import replace
from unittest.mock import Mock

import pytest

from scripts.sandbox_poc import demo_template
from services.sandbox_poc import batch, history, shared
from services.sandbox_poc.handoff import SandboxHandoff, TemplateReference, build_handoff
from services.sandbox_poc.review_bundle import build_review_bundle
from services.sandbox_poc.service import SandboxService
from services.sandbox_poc.shared import ContractError
from services.sandbox_poc.workflow import CONTROL, RemediationLoop
from services.sandbox_poc.shared import SpecEngine
from test_sandbox_poc import FakeRuntime, engine, snapshot  # shared fixtures

S74 = "cis-pg17-v1.1.0:7.4"
S410 = "cis-pg17-v1.1.0:4.10"
S49 = "cis-pg17-v1.1.0:4.9"
S3125 = "cis-pg17-v1.1.0:3.1.25"   # FAIL in the fixture (log_statement none)
S3121 = "cis-pg17-v1.1.0:3.1.21"   # PASS in the fixture
CATALOG_IDS = {f"cis-pg17-v1.1.0:{r}" for r in ("4.3", "4.4", "4.5", "4.6", "4.7", "4.9", "4.10", "5.5", "7.1", "7.4")}
# Specs without a check (manual_checklist / needs_capability): not catalog, so always kept.
NON_CHECK_IDS = {f"cis-pg17-v1.1.0:{r}" for r in ("3.1.12", "6.10", "7.2")}  # no check: manual_checklist, needs_capability


# ---------------------------------------------------------------------------
# Snapshot mutations
# ---------------------------------------------------------------------------

def catalog_gap_unrecorded(s):
    """7.4 GAPPED: archiving null with no gaps entry (section_not_collected)."""
    s["baseline"]["archiving"] = None


def catalog_gap_recorded(s):
    """7.4 GAPPED: archiving null with a gaps entry, as the collector writes it."""
    s["baseline"]["archiving"] = None
    s["baseline"]["gaps"] = [{"section": "archiving", "reason": "insufficient_privilege",
                              "remediation": "test"}]


def add_source_only_catalog(s):
    """Catalog-only differences a sandbox never has: an extra login role and a
    SECURITY DEFINER function with SET search_path (setting evidence unchanged)."""
    b = s["baseline"]
    b["roles"].append({**next(r for r in b["roles"] if r["oid"] == "10"), "oid": "16500",
                       "rolname": "dbguard_extra_login", "rolsuper": False, "rolcreaterole": False,
                       "rolcreatedb": False, "rolreplication": False, "rolbypassrls": False})
    b["password_types"].append({"rolname": "dbguard_extra_login", "password_type": "scram-sha-256",
                                "rolvaliduntil": None})
    b["functions"] = b["functions"] + [{
        "acl": ["=X/dbguard_poc", "dbguard_poc=X/dbguard_poc"], "kind": "f", "name": "dbguard_extra_definer",
        "owner": "dbguard_poc", "schema": "public", "language": "sql", "extension": None, "prosecdef": True,
        "search_path": "pg_catalog, pg_temp", "config_names": ["search_path"], "identity_args": ""}]


def setting_reproduction_difference(s):
    """The sandbox reproduces 3.1.21 (PASS in the source) as FAIL."""
    s["checks"][S3121]["result"] = "off"


def setting_gap(s, sid=S3125):
    s["checks"][sid].update(status="error", error="denied")
    s["checks"][sid].pop("result", None)


class MutatingRuntime(FakeRuntime):
    """FakeRuntime that also changes the sandbox snapshot when the fix is applied."""

    def __init__(self, snapshot, number, mutate):
        super().__init__(snapshot, number)
        self.mutate = mutate

    def sql(self, sql):
        out = super().sql(sql)
        if "RESET" not in sql:
            self.mutate(self.snapshot)
        return out


class SettingRuntime:
    """Fake runtime that applies/resets any ALTER SYSTEM setting, for service.run and batch."""

    def __init__(self, snapshot, number, by_setting):
        self.original = copy.deepcopy(snapshot)
        self.snapshot = copy.deepcopy(snapshot)
        self.run_id, self.name, self.image_id = f"run-{number}", f"fake-{number}", "sha256:test"
        self.by_setting = by_setting
        self.closed = False

    def start(self):
        pass

    def write_config(self, *args):
        pass

    def activate(self, expected):
        pass

    def health(self):
        return True

    def setting_sources(self, names):
        # Like test_sandbox_poc's fake: the sandbox reproduces the snapshot's provenance.
        rows = {r["name"]: r for r in self.snapshot["baseline"]["settings"]}
        return {n: {"source": rows[n]["source"], "sourcefile": rows[n]["sourcefile"]}
                for n in names if n in rows}

    def _set(self, name, value):
        for row in self.snapshot["baseline"]["settings"]:
            if row["name"] == name:
                row["setting"] = value
        if name in self.by_setting:
            self.snapshot["checks"][self.by_setting[name]]["result"] = value

    def sql(self, sql):
        shown = re.fullmatch(r"SHOW (\w+);", sql.strip())
        if shown:
            return next(r["setting"] for r in self.snapshot["baseline"]["settings"] if r["name"] == shown.group(1))
        if "json_build_object" in sql:
            return '{"database": "test"}'
        for name in re.findall(r'ALTER SYSTEM RESET "?([a-z_.]+)"?', sql):
            self._set(name, next(r["setting"] for r in self.original["baseline"]["settings"] if r["name"] == name))
        for name, value in re.findall(r'ALTER SYSTEM SET "?([a-z_.]+)"? = \'([^\']*)\'', sql):
            self._set(name, value)
        return "t"

    def close(self):
        self.closed = True
        return {"verified": True}


def run_batch(engine, source, tmp_path, monkeypatch, combined_start=None):
    """run_batch over 3.1.20 + 3.1.25. Individual runs start from the source; the
    combined runtime (the third) starts from ``combined_start`` when given."""
    monkeypatch.setenv("DBGUARD_HISTORY_DIR", str(tmp_path))
    monkeypatch.setattr(SpecEngine, "collect", lambda self, runtime: copy.deepcopy(runtime.snapshot))
    by_setting = {s["check"]["setting_name"]: s["spec_id"] for s in engine.specs
                  if s.get("check", {}).get("kind") == "setting"}
    runtimes = []

    def factory():
        start = combined_start if (combined_start is not None and len(runtimes) == 2) else source
        runtimes.append(SettingRuntime(start, len(runtimes) + 1, by_setting))
        return runtimes[-1]
    template = demo_template()
    ref = TemplateReference(version=template.version, sha256=template.sha256,
                            evidence=[{"document_id": "doc-1", "version": "1", "sha256": "a" * 64}])
    approved = replace(template, approved_by="unit-reviewer", evidence=tuple(
        {**e.model_dump(), "approved_by": "unit-reviewer"} for e in ref.evidence))
    service = SandboxService("unused", registry_loader=Mock(return_value=approved), runtime_factory=factory)
    base = build_handoff(engine, source, ref).model_dump()
    requests = [SandboxHandoff(**{**base, "control_id": c, "retry_mode": "repeat"})
                for c in (CONTROL, S3125)]
    output, _ = batch.run_batch(requests, service)
    return output, runtimes


def run_loop(engine, source, sandbox=None, mutate=None):
    """Run the loop on ``source``; runtimes start from ``sandbox`` (default: the source)."""
    runtimes = []

    def factory():
        start = sandbox if sandbox is not None else source
        rt = MutatingRuntime(start, len(runtimes) + 1, mutate) if mutate else FakeRuntime(start, len(runtimes) + 1)
        runtimes.append(rt)
        return rt
    engine.collect = lambda runtime: copy.deepcopy(runtime.snapshot)
    return RemediationLoop(engine, demo_template(), factory).run(source, engine.assess(source)), runtimes


def handoff_for(engine, snapshot):
    template = demo_template()
    ref = TemplateReference(version=template.version, sha256=template.sha256,
                            evidence=[{"document_id": "doc-1", "version": "1", "sha256": "a" * 64}])
    return build_handoff(engine, snapshot, ref)


def recorded_run(engine, snapshot):
    """Same steps as test_review_bundle.recorded, for a caller-built snapshot."""
    snapshot["envelope"].update(collector_version="unit-fixture", collected_at="2026-09-22T00:00:00Z",
                                collected_by="unit-fixture", is_superuser=True, target_id="target")
    for row in snapshot["baseline"]["settings"]:
        row.update(vartype="bool" if row["setting"] in ("on", "off") else "enum", unit=None, sanitised=False)
    result, _ = run_loop(engine, snapshot)
    assert result["status"] == "VERIFIED", result["attempts"][-1].get("error")
    result.update(approval_source="registry", run_id="test-run")
    result["template"]["approved_by"] = "INTEGRATION_TEST_ONLY"
    result["template"]["evidence"] = [dict(document_id="test-doc", version="1", sha256="a" * 64,
                                           approved_by="INTEGRATION_TEST_ONLY")]
    ref = TemplateReference(version=result["template"]["version"], sha256=result["template"]["sha256"],
                            evidence=[dict(document_id="test-doc", version="1", sha256="a" * 64)])
    return build_handoff(engine, snapshot, ref), result


def report_html(engine, handoff, result):
    with zipfile.ZipFile(io.BytesIO(build_review_bundle(handoff, result, engine))) as archive:
        return archive.read("report.html").decode("utf-8")


def tamper_after(engine, result, mutate):
    """Change the final after-fix snapshot and keep its assessment consistent with it."""
    final = result["attempts"][-1]
    mutate(final["after"])
    final["after_assessment"] = engine.assess(final["after"])




def tamper_before(engine, result, mutate):
    """Change the final reproduction snapshot and keep its assessment consistent with it."""
    final = result["attempts"][-1]
    mutate(final["before"])
    final["before_assessment"] = engine.assess(final["before"])


@pytest.fixture
def recorded_history(engine, snapshot, tmp_path, monkeypatch):
    monkeypatch.setenv("DBGUARD_HISTORY_DIR", str(tmp_path))
    snapshot["baseline"]["identity"]["system_identifier"] = "12345"
    handoff, result = recorded_run(engine, snapshot)
    history.record(handoff, result, b"zip")
    fresh = copy.deepcopy(handoff.snapshot)
    fresh["envelope"]["collected_at"] = "2026-09-25T00:00:00Z"
    fresh["checks"][CONTROL]["result"] = "on"
    return fresh


# ---------------------------------------------------------------------------
# The engine helpers and the default
# ---------------------------------------------------------------------------

class TestDefaultScope:
    def test_default_is_false_and_findings_are_the_29_non_catalog_specs(self, engine, snapshot):
        assert shared.SANDBOX_COMPARES_CATALOG is False
        assessment = engine.assess(snapshot)
        all_ids = {s["spec_id"] for s in engine.specs}
        assert set(assessment["findings"]) == all_ids - CATALOG_IDS
        assert len(assessment["findings"]) == 29
        for sid in NON_CHECK_IDS:
            assert assessment["findings"][sid]["status"] == "MANUAL_REVIEW"
        assert not CATALOG_IDS & set(assessment["findings"])

    def test_upstream_report_keeps_all_39_rows_with_catalog_evidence(self, engine, snapshot):
        report = engine.assess(snapshot)["upstream_report"]
        rows = {r["spec_id"]: r for r in report["results"]}
        assert len(rows) == 39 and CATALOG_IDS <= set(rows)
        assert rows["cis-pg17-v1.1.0:5.5"]["result"] == "FAIL"
        assert rows["cis-pg17-v1.1.0:5.5"]["evidence"][0]["rolname"] == "dbguard_poc"
        assert rows[S74]["result"] == "FAIL"
        assert sum(report["summary"].values()) == 39

    def test_catalog_ids_are_exactly_the_catalog_specs(self, engine):
        ids = {s["spec_id"] for s in engine.specs if s.get("check", {}).get("kind") == "catalog"}
        assert engine.catalog_ids == ids == CATALOG_IDS and len(ids) == 10
        assert not engine.catalog_ids & NON_CHECK_IDS
        assert not hasattr(engine, "setting_ids")

    def test_non_catalog_non_setting_gap_still_counts(self, engine):
        """Stricter than "settings only": any non-catalog GAPPED finding blocks."""
        assert engine.gapped_settings({"cis-pg17-v1.1.0:3.1.14": {"status": "GAPPED"}}) == [
            "cis-pg17-v1.1.0:3.1.14"]
        assert engine.gapped_settings({"cis-pg17-v1.1.0:unknown": {"status": "GAPPED"}}) == [
            "cis-pg17-v1.1.0:unknown"]

    def test_only_non_catalog_specs_count_and_result_is_sorted(self, engine):
        findings = {S74: {"status": "GAPPED"}, S3125: {"status": "GAPPED"}, S3121: {"status": "GAPPED"},
                    S410: {"status": "PASS"}, "cis-pg17-v1.1.0:3.1.20": {"status": "FAIL"}}
        assert engine.gapped_settings(findings) == [S3121, S3125]
        assert engine.gapped_settings({S74: {"status": "GAPPED"}}) == []

    def test_catalog_gap_is_only_in_upstream_report(self, engine, snapshot):
        catalog_gap_unrecorded(snapshot)
        assessment = engine.assess(snapshot)
        assert S74 not in assessment["findings"]
        row = next(r for r in assessment["upstream_report"]["results"] if r["spec_id"] == S74)
        assert row["result"] == "NOT_COLLECTED"
        assert engine.gapped_settings(assessment["findings"]) == []


# ---------------------------------------------------------------------------
# Default: catalog gaps and catalog differences never block
# ---------------------------------------------------------------------------

class TestDefaultCatalogNeverBlocks:
    def test_service(self, engine, snapshot):
        catalog_gap_unrecorded(snapshot)
        add_source_only_catalog(snapshot)
        validated = SandboxService("unused-registry-url").validate_handoff(handoff_for(engine, snapshot))
        assert validated.spec_set_hash == engine.spec_set_hash

    @pytest.mark.parametrize("mutate", [catalog_gap_unrecorded, add_source_only_catalog])
    def test_workflow_source_only_catalog_state(self, engine, snapshot, mutate):
        sandbox = copy.deepcopy(snapshot)
        mutate(snapshot)
        assert engine.assess(snapshot)["upstream_report"] != engine.assess(sandbox)["upstream_report"]
        result, runtimes = run_loop(engine, snapshot, sandbox=sandbox)
        assert result["status"] == "VERIFIED", result["attempts"][-1].get("error")
        assert len(runtimes) == 1 and runtimes[0].closed
        assert result["attempts"][0]["regressions"] == []

    def test_workflow_catalog_pass_to_gapped_after_fix(self, engine, snapshot):
        """4.10 PASS -> GAPPED in the sandbox is outside the compared findings."""
        result, _ = run_loop(engine, snapshot, mutate=lambda s: s["baseline"].update(password_types=None))
        assert result["status"] == "VERIFIED"
        assert result["attempts"][0]["regressions"] == []
        after = result["attempts"][0]["after_assessment"]
        assert next(r for r in after["upstream_report"]["results"] if r["spec_id"] == S410)["result"] == "NOT_COLLECTED"

    @pytest.mark.parametrize("mutate", [catalog_gap_unrecorded, add_source_only_catalog])
    def test_bundle(self, engine, snapshot, mutate):
        mutate(snapshot)
        handoff, result = recorded_run(engine, snapshot)
        report = report_html(engine, handoff, result)
        assert report.count("<tr><td>cis-") == 29
        assert "reproduction or rollback findings differ" not in report

    def test_bundle_catalog_difference_between_source_and_sandbox(self, engine, snapshot):
        handoff, result = recorded_run(engine, snapshot)
        tamper_before(engine, result, add_source_only_catalog)
        tamper_after(engine, result, add_source_only_catalog)
        assert report_html(engine, handoff, result).count("<tr><td>cis-") == 29

    @pytest.mark.parametrize("mutate", [catalog_gap_unrecorded, add_source_only_catalog])
    def test_batch_combined_reproduction(self, engine, snapshot, tmp_path, monkeypatch, mutate):
        sandbox = copy.deepcopy(snapshot)
        mutate(snapshot)
        output, runtimes = run_batch(engine, snapshot, tmp_path, monkeypatch, combined_start=sandbox)
        assert output["status"] == "VERIFIED", output.get("combined_test", {}).get("reason")
        assert len(runtimes) == 3 and all(r.closed for r in runtimes)

    def test_batch_without_differences(self, engine, snapshot, tmp_path, monkeypatch):
        output, runtimes = run_batch(engine, snapshot, tmp_path, monkeypatch)
        assert output["status"] == "VERIFIED"
        assert [r["status"] for r in output["individual_runs"]] == ["VERIFIED", "VERIFIED"]
        assert not CATALOG_IDS & set(output["sandbox_after_findings"])

    @pytest.mark.parametrize("mutate", [catalog_gap_unrecorded, add_source_only_catalog,
                                        lambda s: s["baseline"].update(password_types=None)])
    def test_history(self, engine, recorded_history, mutate):
        mutate(recorded_history)
        verdict = history.compare("test-run", recorded_history, engine)
        assert verdict["status"] == "TARGET_REASSESSMENT_CONFIRMED"
        assert verdict["regressions"] == [] and verdict["gaps"] == []


class TestDefaultRecordedCatalogGap:
    """A catalog gap WITH its baseline.gaps record, which is how the collector reports an
    unreadable section, does not block under the default: blocking_gaps() drops records
    for CATALOG_ONLY_SECTIONS in provenance.reconstruction_plan, the workflow post-apply
    and rollback checks and history.compare. Gaps in every other section still block
    (tests/test_sandbox_blocking_gaps.py)."""

    def test_service(self, engine, snapshot):
        catalog_gap_recorded(snapshot)
        SandboxService("unused-registry-url").validate_handoff(handoff_for(engine, snapshot))

    def test_workflow(self, engine, snapshot):
        catalog_gap_recorded(snapshot)
        result, _ = run_loop(engine, snapshot)
        assert result["status"] == "VERIFIED"

    def test_history(self, engine, recorded_history):
        catalog_gap_recorded(recorded_history)
        assert history.compare("test-run", recorded_history, engine)["status"] == "TARGET_REASSESSMENT_CONFIRMED"


# ---------------------------------------------------------------------------
# Default: a setting gap or a setting reproduction difference still blocks
# ---------------------------------------------------------------------------

class TestDefaultSettingsStillBlock:
    def test_service_setting_gap(self, engine, snapshot):
        setting_gap(snapshot)
        with pytest.raises(ContractError, match="Gapped controls"):
            SandboxService("unused-registry-url").validate_handoff(handoff_for(engine, snapshot))

    def test_workflow_setting_gap_in_source_blocks_before_any_container(self, engine, snapshot):
        setting_gap(snapshot)
        created = []
        engine.collect = lambda runtime: copy.deepcopy(runtime.snapshot)
        loop = RemediationLoop(engine, demo_template(), lambda: created.append(1))
        with pytest.raises(ContractError, match="gapped controls"):
            loop.run(snapshot, engine.assess(snapshot))
        assert created == []

    def test_workflow_setting_gap_after_fix(self, engine, snapshot):
        """3.1.25 FAILs before, so only the gapped_settings clause can catch it."""
        result, _ = run_loop(engine, snapshot, mutate=lambda s: setting_gap(s, S3125))
        assert result["status"] == "FAILED"
        assert all(a["regressions"] == [S3125] for a in result["attempts"])

    def test_workflow_setting_pass_to_fail_after_fix(self, engine, snapshot):
        result, _ = run_loop(engine, snapshot, mutate=setting_reproduction_difference)
        assert result["status"] == "FAILED"
        assert all(a["regressions"] == [S3121] for a in result["attempts"])

    def test_workflow_setting_reproduction_difference(self, engine, snapshot):
        sandbox = copy.deepcopy(snapshot)
        setting_reproduction_difference(sandbox)
        result, runtimes = run_loop(engine, snapshot, sandbox=sandbox)
        assert result["status"] == "FAILED"
        assert "did not reproduce all scoped findings" in result["attempts"][0]["error"]
        assert len(runtimes) == 1

    def test_bundle_setting_gap_after_fix(self, engine, snapshot):
        handoff, result = recorded_run(engine, snapshot)
        tamper_after(engine, result, lambda s: setting_gap(s, S3125))
        with pytest.raises(ContractError, match="regression evidence is invalid"):
            build_review_bundle(handoff, result, engine)

    def test_bundle_setting_reproduction_difference(self, engine, snapshot):
        handoff, result = recorded_run(engine, snapshot)
        tamper_before(engine, result, setting_reproduction_difference)
        with pytest.raises(ContractError, match="reproduction or rollback findings differ"):
            build_review_bundle(handoff, result, engine)

    def test_batch_setting_gap(self, engine, snapshot, tmp_path, monkeypatch):
        setting_gap(snapshot, S3121)
        with pytest.raises(ContractError, match="Gapped controls"):
            run_batch(engine, snapshot, tmp_path, monkeypatch)

    def test_batch_combined_setting_reproduction_difference(self, engine, snapshot, tmp_path, monkeypatch):
        sandbox = copy.deepcopy(snapshot)
        setting_reproduction_difference(sandbox)
        output, runtimes = run_batch(engine, snapshot, tmp_path, monkeypatch, combined_start=sandbox)
        assert output["status"] == "FAILED"
        assert output["combined_test"]["reason"] == "Combined baseline reproduction differs"
        assert all(r.closed for r in runtimes)

    def test_history_setting_gap(self, engine, recorded_history):
        setting_gap(recorded_history, S3125)
        verdict = history.compare("test-run", recorded_history, engine)
        assert verdict["status"] == "TARGET_VERIFICATION_FAILED"
        assert verdict["gaps"] == [S3125] and verdict["regressions"] == []

    def test_history_setting_regression(self, engine, recorded_history):
        setting_reproduction_difference(recorded_history)
        verdict = history.compare("test-run", recorded_history, engine)
        assert verdict["status"] == "TARGET_VERIFICATION_FAILED"
        assert verdict["regressions"] == [S3121]

    def test_history_fixed_target_is_confirmed(self, engine, recorded_history):
        verdict = history.compare("test-run", recorded_history, engine)
        assert verdict["status"] == "TARGET_REASSESSMENT_CONFIRMED"
        assert verdict["regressions"] == [] and verdict["gaps"] == []


# ---------------------------------------------------------------------------
# Switch True: catalog findings stay in the map (both positions stay covered)
# ---------------------------------------------------------------------------

class TestCatalogCompared:
    @pytest.fixture(autouse=True)
    def _catalog_compared(self, monkeypatch):
        monkeypatch.setattr(shared, "SANDBOX_COMPARES_CATALOG", True)

    def test_findings_keep_all_39(self, engine, snapshot):
        findings = engine.assess(snapshot)["findings"]
        assert set(findings) == {s["spec_id"] for s in engine.specs} and len(findings) == 39
        assert CATALOG_IDS <= set(findings)

    def test_catalog_gap_is_gapped_in_findings_but_not_a_guarded_gap(self, engine, snapshot):
        catalog_gap_unrecorded(snapshot)
        findings = engine.assess(snapshot)["findings"]
        assert findings[S74]["status"] == "GAPPED"
        assert engine.gapped_settings(findings) == []

    def test_service_catalog_gap_does_not_block(self, engine, snapshot):
        catalog_gap_unrecorded(snapshot)
        handoff = handoff_for(engine, snapshot)
        assert handoff.assessment["findings"][S74]["status"] == "GAPPED"
        validated = SandboxService("unused-registry-url").validate_handoff(handoff)
        assert validated.spec_set_hash == engine.spec_set_hash

    def test_service_setting_gap_blocks(self, engine, snapshot):
        setting_gap(snapshot)
        with pytest.raises(ContractError, match="Gapped controls"):
            SandboxService("unused-registry-url").validate_handoff(handoff_for(engine, snapshot))

    def test_workflow_catalog_gap_does_not_block_the_loop(self, engine, snapshot):
        catalog_gap_unrecorded(snapshot)
        result, runtimes = run_loop(engine, snapshot)
        assert result["status"] == "VERIFIED"
        attempt = result["attempts"][0]
        assert attempt["before_assessment"]["findings"][S74]["status"] == "GAPPED"
        assert attempt["after_assessment"]["findings"][S74]["status"] == "GAPPED"
        assert attempt["regressions"] == []
        assert all(r.closed for r in runtimes)

    def test_workflow_catalog_pass_to_gapped_after_fix_is_a_regression(self, engine, snapshot):
        """4.10 PASSes before; GAPPED after is caught by the PASS clause, not gapped_settings."""
        assert engine.assess(snapshot)["findings"][S410]["status"] == "PASS"
        result, _ = run_loop(engine, snapshot, mutate=lambda s: s["baseline"].update(password_types=None))
        assert result["status"] == "FAILED"
        for attempt in result["attempts"]:
            assert attempt["after_assessment"]["findings"][S410]["status"] == "GAPPED"
            assert engine.gapped_settings(attempt["after_assessment"]["findings"]) == []
            assert attempt["regressions"] == [S410]
            assert "acceptance" in attempt["error"]

    def test_workflow_catalog_non_pass_to_gapped_after_fix_is_not_a_regression(self, engine, snapshot):
        """4.9 (MANUAL before) turning GAPPED is not blocking; 4.10 (PASS before) is."""
        assert engine.assess(snapshot)["findings"][S49]["status"] == "MANUAL_REVIEW"

        def drop_bootstrap(s):
            s["baseline"]["roles"] = [r for r in s["baseline"]["roles"] if r["oid"] != "10"]
        result, _ = run_loop(engine, snapshot, mutate=drop_bootstrap)
        attempt = result["attempts"][0]
        assert attempt["after_assessment"]["findings"][S49]["status"] == "GAPPED"
        assert attempt["regressions"] == [S410]

    def test_workflow_source_only_catalog_status_fails_reproduction(self, engine, snapshot):
        sandbox = copy.deepcopy(snapshot)
        catalog_gap_unrecorded(snapshot)          # source 7.4 GAPPED, sandbox 7.4 FAIL
        result, runtimes = run_loop(engine, snapshot, sandbox=sandbox)
        assert result["status"] == "FAILED"
        assert "did not reproduce all scoped findings" in result["attempts"][0]["error"]
        assert len(runtimes) == 1  # a ContractError is terminal

    def test_workflow_evidence_only_catalog_difference_is_not_compared(self, engine, snapshot):
        """findings carry status + spec_hash only: an extra role/function that leaves every
        catalog status unchanged (4.4/4.5 MANUAL, 5.5 FAIL) reproduces even when compared."""
        sandbox = copy.deepcopy(snapshot)
        add_source_only_catalog(snapshot)
        assert engine.assess(snapshot)["findings"] == engine.assess(sandbox)["findings"]
        result, _ = run_loop(engine, snapshot, sandbox=sandbox)
        assert result["status"] == "VERIFIED"

    def test_workflow_setting_gap_after_fix(self, engine, snapshot):
        result, _ = run_loop(engine, snapshot, mutate=lambda s: setting_gap(s, S3125))
        assert result["status"] == "FAILED"
        assert all(a["regressions"] == [S3125] for a in result["attempts"])

    def test_bundle_catalog_gap_does_not_block(self, engine, snapshot):
        catalog_gap_unrecorded(snapshot)
        handoff, result = recorded_run(engine, snapshot)
        report = report_html(engine, handoff, result)
        row = report[report.index(f"<tr><td>{S74}</td>"):]
        row = row[:row.index("</tr>")]
        assert row.count("<td>GAPPED</td>") == 3  # before, after fix, after rollback

    def test_bundle_setting_gap_after_fix_is_refused(self, engine, snapshot):
        handoff, result = recorded_run(engine, snapshot)
        tamper_after(engine, result, lambda s: setting_gap(s, S3125))
        with pytest.raises(ContractError, match="regression evidence is invalid"):
            build_review_bundle(handoff, result, engine)

    def test_bundle_catalog_pass_to_gapped_after_fix_is_refused(self, engine, snapshot):
        handoff, result = recorded_run(engine, snapshot)
        tamper_after(engine, result, lambda s: s["baseline"].update(password_types=None))
        assert result["attempts"][-1]["after_assessment"]["findings"][S410]["status"] == "GAPPED"
        with pytest.raises(ContractError, match="regression evidence is invalid"):
            build_review_bundle(handoff, result, engine)

    def test_bundle_catalog_reproduction_difference_is_refused(self, engine, snapshot):
        handoff, result = recorded_run(engine, snapshot)
        tamper_before(engine, result, catalog_gap_unrecorded)
        with pytest.raises(ContractError, match="reproduction or rollback findings differ"):
            build_review_bundle(handoff, result, engine)

    def test_untampered_bundle_has_all_39_rows(self, engine, snapshot):
        handoff, result = recorded_run(engine, snapshot)
        assert report_html(engine, handoff, result).count("<tr><td>cis-") == 39

    def test_batch_combined_catalog_difference_is_refused(self, engine, snapshot, tmp_path, monkeypatch):
        sandbox = copy.deepcopy(snapshot)
        catalog_gap_unrecorded(snapshot)
        # Individual runs start from the source too, so only the combined step differs.
        output, _ = run_batch(engine, snapshot, tmp_path, monkeypatch, combined_start=sandbox)
        assert output["status"] == "FAILED"
        assert output["combined_test"]["reason"] == "Combined baseline reproduction differs"

    def test_history_catalog_gap_does_not_block(self, engine, recorded_history):
        catalog_gap_unrecorded(recorded_history)  # 7.4 was FAIL: FAIL -> GAPPED is no regression
        verdict = history.compare("test-run", recorded_history, engine)
        assert verdict["assessment"]["findings"][S74]["status"] == "GAPPED"
        assert verdict["status"] == "TARGET_REASSESSMENT_CONFIRMED"
        assert verdict["gaps"] == []

    def test_history_setting_gap_blocks(self, engine, recorded_history):
        setting_gap(recorded_history, S3125)
        verdict = history.compare("test-run", recorded_history, engine)
        assert verdict["status"] == "TARGET_VERIFICATION_FAILED"
        assert verdict["gaps"] == [S3125]
        assert verdict["regressions"] == []

    def test_history_catalog_pass_to_gapped_is_a_regression(self, engine, recorded_history):
        recorded_history["baseline"]["password_types"] = None
        verdict = history.compare("test-run", recorded_history, engine)
        assert verdict["status"] == "TARGET_VERIFICATION_FAILED"
        assert verdict["regressions"] == [S410]
        assert verdict["gaps"] == []
