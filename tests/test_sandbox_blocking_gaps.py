"""Whole-collection gap rules (shared.blocking_gaps).

Default (SANDBOX_COMPARES_CATALOG False): baseline.gaps records for the two F6-only
sections (functions, archiving) are exempt; every other record still blocks the
six whole-collection checks exactly as before F6: provenance (service and batch
source), workflow post-apply and rollback, review bundle, batch combined step and
history. With the switch True every record blocks.

Each gap record is added next to unchanged data, so only the gaps rule can fire.
Fake runtimes only: no Docker, network or model.
"""
import copy
import json
import re
from dataclasses import replace
from unittest.mock import Mock

import pytest

from app.services.spec_engine.catalog_checks import REGISTRY
from app.services.spec_engine.manifest import manifest_from_specs
from scripts.sandbox_poc import demo_template
from services.sandbox_poc import batch, history, provenance, shared
from services.sandbox_poc.handoff import SandboxHandoff, TemplateReference, build_handoff
from services.sandbox_poc.review_bundle import build_review_bundle
from services.sandbox_poc.service import SandboxService
from services.sandbox_poc.shared import ROOT, ContractError, SpecEngine, blocking_gaps
from services.sandbox_poc.workflow import CONTROL
from test_sandbox_guard_scope import (FakeRuntime, S3125, SettingRuntime, engine, handoff_for,  # noqa: F401
                                      recorded_history, recorded_run, run_loop, snapshot, tamper_after)

# Sections that blocked before F6 and must still block. rls_policies is read only by a
# catalog evaluator today (4.7) but existed before F6, so it is NOT exempt.
STILL_BLOCKING = ["password_types", "file_settings", "settings", "rls_policies"]
EXEMPT = ["archiving", "functions"]


def gap(section):
    return {"section": section, "reason": "insufficient_privilege", "remediation": "test"}


def add_gaps(*sections):
    def mutate(s):
        s["baseline"]["gaps"] = list(s["baseline"].get("gaps") or []) + [gap(x) for x in sections]
    return mutate


BLOCKING_CASES = [pytest.param((s,), id=s) for s in STILL_BLOCKING] + [
    pytest.param(("archiving", "password_types"), id="mixed-archiving+password_types")]


class RollbackMutatingRuntime(FakeRuntime):
    """FakeRuntime that changes the sandbox snapshot when the rollback runs."""

    def __init__(self, snapshot, number, mutate):
        super().__init__(snapshot, number)
        self.mutate = mutate

    def sql(self, sql):
        out = super().sql(sql)
        if "RESET" in sql:
            self.mutate(self.snapshot)
        return out


def run_loop_rollback_mutation(engine, source, mutate):
    from services.sandbox_poc.workflow import RemediationLoop
    runtimes = []

    def factory():
        runtimes.append(RollbackMutatingRuntime(source, len(runtimes) + 1, mutate))
        return runtimes[-1]
    engine.collect = lambda runtime: copy.deepcopy(runtime.snapshot)
    return RemediationLoop(engine, demo_template(), factory).run(source, engine.assess(source)), runtimes


class ApplyMutatingSettingRuntime(SettingRuntime):
    def __init__(self, snapshot, number, by_setting, mutate):
        super().__init__(snapshot, number, by_setting)
        self.mutate = mutate

    def sql(self, sql):
        out = super().sql(sql)
        if "ALTER SYSTEM SET" in sql:
            self.mutate(self.snapshot)
        return out


def run_batch(engine, source, tmp_path, monkeypatch, combined_mutate=None):
    """run_batch over 3.1.20 + 3.1.25; only the combined (third) runtime is mutated on apply."""
    monkeypatch.setenv("DBGUARD_HISTORY_DIR", str(tmp_path))
    monkeypatch.setattr(SpecEngine, "collect", lambda self, runtime: copy.deepcopy(runtime.snapshot))
    by_setting = {s["check"]["setting_name"]: s["spec_id"] for s in engine.specs
                  if s.get("check", {}).get("kind") == "setting"}
    runtimes = []

    def factory():
        n = len(runtimes) + 1
        rt = (ApplyMutatingSettingRuntime(source, n, by_setting, combined_mutate)
              if combined_mutate and n == 3 else SettingRuntime(source, n, by_setting))
        runtimes.append(rt)
        return rt
    template = demo_template()
    ref = TemplateReference(version=template.version, sha256=template.sha256,
                            evidence=[{"document_id": "doc-1", "version": "1", "sha256": "a" * 64}])
    approved = replace(template, approved_by="unit-reviewer", evidence=tuple(
        {**e.model_dump(), "approved_by": "unit-reviewer"} for e in ref.evidence))
    service = SandboxService("unused", registry_loader=Mock(return_value=approved), runtime_factory=factory)
    base = build_handoff(engine, source, ref).model_dump()
    requests = [SandboxHandoff(**{**base, "control_id": c, "retry_mode": "repeat"}) for c in (CONTROL, S3125)]
    output, _ = batch.run_batch(requests, service)
    return output, runtimes


def tamper_rollback(engine, result, mutate):
    final = result["attempts"][-1]
    mutate(final["rollback"])
    final["rollback_assessment"] = engine.assess(final["rollback"])


# ---------------------------------------------------------------------------
# The helper itself
# ---------------------------------------------------------------------------

class TestBlockingGapsHelper:
    def test_default_drops_only_the_two_f6_sections(self, snapshot):
        assert shared.SANDBOX_COMPARES_CATALOG is False
        assert shared.CATALOG_ONLY_SECTIONS == frozenset({"functions", "archiving"})
        add_gaps(*EXEMPT, *STILL_BLOCKING)(snapshot)
        assert [g["section"] for g in blocking_gaps(snapshot)] == STILL_BLOCKING

    def test_switch_true_keeps_every_record(self, snapshot, monkeypatch):
        monkeypatch.setattr(shared, "SANDBOX_COMPARES_CATALOG", True)
        add_gaps(*EXEMPT, *STILL_BLOCKING)(snapshot)
        assert [g["section"] for g in blocking_gaps(snapshot)] == EXEMPT + STILL_BLOCKING

    def test_malformed_records_still_block(self, snapshot):
        snapshot["baseline"]["gaps"] = ["archiving", {"reason": "x"}, {"section": None}]
        assert blocking_gaps(snapshot) == snapshot["baseline"]["gaps"]

    def test_no_gaps(self, snapshot):
        assert blocking_gaps(snapshot) == []
        snapshot["baseline"].pop("gaps")
        assert blocking_gaps(snapshot) == []

    def test_does_not_mutate_the_snapshot(self, snapshot):
        add_gaps("archiving", "settings")(snapshot)
        before = copy.deepcopy(snapshot)
        blocking_gaps(snapshot).clear()
        assert snapshot == before


# ---------------------------------------------------------------------------
# (1) + (3) Default: every pre-F6 section's gap record still blocks, mixed lists too
# ---------------------------------------------------------------------------

class TestDefaultStillBlocks:
    @pytest.mark.parametrize("sections", BLOCKING_CASES)
    def test_service_provenance(self, engine, snapshot, sections):
        add_gaps(*sections)(snapshot)
        handoff = handoff_for(engine, snapshot)
        assert engine.gapped_settings(handoff.assessment["findings"]) == []  # only the gaps rule
        with pytest.raises(ContractError, match="ungapped source snapshot"):
            SandboxService("unused-registry-url").validate_handoff(handoff)

    @pytest.mark.parametrize("sections", BLOCKING_CASES)
    def test_workflow_post_apply(self, engine, snapshot, sections):
        result, runtimes = run_loop(engine, snapshot, mutate=add_gaps(*sections))
        assert result["status"] == "FAILED"
        assert len(runtimes) == 3
        assert all("Post-apply collection has gaps" in a["error"] for a in result["attempts"])
        assert all(a["regressions"] == [] for a in result["attempts"])

    @pytest.mark.parametrize("sections", BLOCKING_CASES)
    def test_workflow_rollback(self, engine, snapshot, sections):
        result, _ = run_loop_rollback_mutation(engine, snapshot, add_gaps(*sections))
        assert result["status"] == "FAILED"
        for attempt in result["attempts"]:
            assert attempt["rollback_verified"] is False
            assert "Exact rollback verification failed" in attempt["error"]
            # Settings provenance and findings were restored; only the gaps rule failed.
            assert attempt["rollback_assessment"]["findings"] == attempt["before_assessment"]["findings"]

    @pytest.mark.parametrize("stage", ["after", "rollback"])
    @pytest.mark.parametrize("sections", BLOCKING_CASES)
    def test_bundle(self, engine, snapshot, sections, stage):
        handoff, result = recorded_run(engine, snapshot)
        (tamper_after if stage == "after" else tamper_rollback)(engine, result, add_gaps(*sections))
        with pytest.raises(ContractError, match="collection has gaps"):
            build_review_bundle(handoff, result, engine)

    @pytest.mark.parametrize("sections", BLOCKING_CASES)
    def test_batch_source(self, engine, snapshot, tmp_path, monkeypatch, sections):
        add_gaps(*sections)(snapshot)
        with pytest.raises(ContractError, match="ungapped source snapshot"):
            run_batch(engine, snapshot, tmp_path, monkeypatch)

    @pytest.mark.parametrize("sections", BLOCKING_CASES)
    def test_batch_combined(self, engine, snapshot, tmp_path, monkeypatch, sections):
        output, runtimes = run_batch(engine, snapshot, tmp_path, monkeypatch, combined_mutate=add_gaps(*sections))
        assert [r["status"] for r in output["individual_runs"]] == ["VERIFIED", "VERIFIED"]
        assert output["status"] == "FAILED"
        assert output["combined_test"]["reason"] == "Combined target, regression or functional gate failed"
        assert all(r.closed for r in runtimes)

    @pytest.mark.parametrize("sections", BLOCKING_CASES)
    def test_history(self, engine, recorded_history, sections):
        add_gaps(*sections)(recorded_history)
        verdict = history.compare("test-run", recorded_history, engine)
        assert verdict["status"] == "TARGET_VERIFICATION_FAILED"
        assert verdict["regressions"] == [] and verdict["gaps"] == []


# ---------------------------------------------------------------------------
# Default: the two F6 sections are exempt at every check (the contrast to the above)
# ---------------------------------------------------------------------------

class TestDefaultExempt:
    @pytest.mark.parametrize("section", EXEMPT)
    def test_service_provenance(self, engine, snapshot, section):
        add_gaps(section)(snapshot)
        SandboxService("unused-registry-url").validate_handoff(handoff_for(engine, snapshot))

    @pytest.mark.parametrize("section", EXEMPT)
    def test_workflow_post_apply_and_rollback(self, engine, snapshot, section):
        result, _ = run_loop(engine, snapshot, mutate=add_gaps(section))
        assert result["status"] == "VERIFIED"
        result, _ = run_loop_rollback_mutation(engine, snapshot, add_gaps(section))
        assert result["status"] == "VERIFIED"
        assert result["attempts"][0]["rollback_verified"] is True

    @pytest.mark.parametrize("stage", ["after", "rollback"])
    @pytest.mark.parametrize("section", EXEMPT)
    def test_bundle(self, engine, snapshot, section, stage):
        handoff, result = recorded_run(engine, snapshot)
        (tamper_after if stage == "after" else tamper_rollback)(engine, result, add_gaps(section))
        assert build_review_bundle(handoff, result, engine)

    @pytest.mark.parametrize("section", EXEMPT)
    def test_batch(self, engine, snapshot, tmp_path, monkeypatch, section):
        source = copy.deepcopy(snapshot)
        add_gaps(section)(source)
        output, _ = run_batch(engine, source, tmp_path, monkeypatch, combined_mutate=add_gaps(section))
        assert output["status"] == "VERIFIED", output.get("combined_test", {}).get("reason")

    @pytest.mark.parametrize("section", EXEMPT)
    def test_history(self, engine, recorded_history, section):
        add_gaps(section)(recorded_history)
        assert history.compare("test-run", recorded_history, engine)["status"] == "TARGET_REASSESSMENT_CONFIRMED"


# ---------------------------------------------------------------------------
# (2) Switch True: an archiving or functions gap record blocks all of them again
# ---------------------------------------------------------------------------

class TestSwitchTrueBlocksF6Sections:
    @pytest.fixture(autouse=True)
    def _catalog_compared(self, monkeypatch):
        monkeypatch.setattr(shared, "SANDBOX_COMPARES_CATALOG", True)

    @pytest.mark.parametrize("section", EXEMPT)
    def test_service_provenance(self, engine, snapshot, section):
        add_gaps(section)(snapshot)
        with pytest.raises(ContractError, match="ungapped source snapshot"):
            SandboxService("unused-registry-url").validate_handoff(handoff_for(engine, snapshot))

    @pytest.mark.parametrize("section", EXEMPT)
    def test_workflow_post_apply(self, engine, snapshot, section):
        result, _ = run_loop(engine, snapshot, mutate=add_gaps(section))
        assert result["status"] == "FAILED"
        assert all("Post-apply collection has gaps" in a["error"] for a in result["attempts"])

    @pytest.mark.parametrize("section", EXEMPT)
    def test_workflow_rollback(self, engine, snapshot, section):
        result, _ = run_loop_rollback_mutation(engine, snapshot, add_gaps(section))
        assert result["status"] == "FAILED"
        assert all(a["rollback_verified"] is False for a in result["attempts"])

    @pytest.mark.parametrize("stage", ["after", "rollback"])
    @pytest.mark.parametrize("section", EXEMPT)
    def test_bundle(self, engine, snapshot, section, stage):
        handoff, result = recorded_run(engine, snapshot)
        (tamper_after if stage == "after" else tamper_rollback)(engine, result, add_gaps(section))
        # The gap also turns the catalog finding GAPPED, so an earlier equality check may fire first.
        with pytest.raises(ContractError, match="collection has gaps|findings differ|regression evidence"):
            build_review_bundle(handoff, result, engine)

    @pytest.mark.parametrize("section", EXEMPT)
    def test_batch(self, engine, snapshot, tmp_path, monkeypatch, section):
        source = copy.deepcopy(snapshot)
        add_gaps(section)(source)
        with pytest.raises(ContractError, match="ungapped source snapshot"):
            run_batch(engine, source, tmp_path, monkeypatch)
        output, _ = run_batch(engine, snapshot, tmp_path, monkeypatch, combined_mutate=add_gaps(section))
        assert output["status"] == "FAILED"

    @pytest.mark.parametrize("section", EXEMPT)
    def test_history(self, engine, recorded_history, section):
        add_gaps(section)(recorded_history)
        verdict = history.compare("test-run", recorded_history, engine)
        assert verdict["status"] == "TARGET_VERIFICATION_FAILED"


# ---------------------------------------------------------------------------
# (4) Safeguard: the exempt sections are F6-only and no setting path reads them
# ---------------------------------------------------------------------------

class TestCatalogOnlySectionsSafeguard:
    def test_every_entry_is_read_by_a_catalog_evaluator(self):
        read = {s for e in REGISTRY.values() for s in (*e.required_sections, *e.optional_sections)}
        assert shared.CATALOG_ONLY_SECTIONS <= read
        assert {name for name, e in REGISTRY.items()
                if shared.CATALOG_ONLY_SECTIONS & {*e.required_sections, *e.optional_sections}} == {
            "elevated_functions", "wal_archiving"}

    def test_both_sections_are_produced_by_the_collector(self):
        sql = (ROOT / "collector" / "collect.sql").read_text(encoding="utf-8")
        keys = set(re.findall(r"^'([a-z_]+)',", sql, flags=re.MULTILINE))
        assert shared.CATALOG_ONLY_SECTIONS <= keys
        # Each has its own gap record branch, so an unreadable section is recorded.
        compact = re.sub(r"\s+", "", sql)
        for section in shared.CATALOG_ONLY_SECTIONS:
            assert f"jsonb_build_object('section','{section}'," in compact
            assert f"try_reason(pg_temp.sql_{section}())ISNOTNULL" in compact

    def test_provenance_never_reads_them(self, engine, snapshot):
        plan = provenance.reconstruction_plan(snapshot, engine.specs)
        rows = provenance.setting_rows(snapshot)
        names = plan["names"]
        sig = provenance.signature(snapshot, names)
        for poison in (None, "not-a-section", {"rolname": "x"}, [{"prosrc": "SECRET"}]):
            changed = copy.deepcopy(snapshot)
            for section in shared.CATALOG_ONLY_SECTIONS:
                changed["baseline"][section] = poison
            assert provenance.reconstruction_plan(changed, engine.specs) == plan
            assert provenance.setting_rows(changed) == rows
            assert provenance.signature(changed, names) == sig
        removed = copy.deepcopy(snapshot)
        for section in shared.CATALOG_ONLY_SECTIONS:
            removed["baseline"].pop(section)
        assert provenance.reconstruction_plan(removed, engine.specs) == plan
        source = (ROOT / "services/sandbox_poc/provenance.py").read_text(encoding="utf-8")
        assert not [s for s in shared.CATALOG_ONLY_SECTIONS if s in source]

    def test_setting_manifest_and_setting_findings_never_touch_them(self, engine, snapshot):
        setting_specs = [s for s in engine.specs if s.get("check", {}).get("kind") == "setting"]
        manifest = manifest_from_specs(setting_specs, engine.records)
        assert manifest == engine.manifest
        text = json.dumps(manifest)
        assert not [s for s in shared.CATALOG_ONLY_SECTIONS if s in text]
        assert all(s["check"]["query"] == f"SHOW {s['check']['setting_name']}" for s in setting_specs)
        changed = copy.deepcopy(snapshot)
        for section in shared.CATALOG_ONLY_SECTIONS:
            changed["baseline"][section] = None
        before, after = engine.assess(snapshot), engine.assess(changed)
        ids = {s["spec_id"] for s in setting_specs}
        assert {k: v for k, v in before["findings"].items() if k in ids} == \
               {k: v for k, v in after["findings"].items() if k in ids}
        setting_rows = lambda report: [r for r in report["upstream_report"]["results"] if r["spec_id"] in ids]
        assert setting_rows(before) == setting_rows(after)

    def test_no_setting_spec_names_them(self, engine):
        for spec in engine.specs:
            if spec.get("check", {}).get("kind") == "setting":
                assert not [s for s in shared.CATALOG_ONLY_SECTIONS if s in json.dumps(spec)]
