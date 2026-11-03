"""Step 7 for per-object fixes (Wave 2a): history.compare on a fresh target snapshot.

Catalog specs are not in the sandbox findings, so an object fix cannot be
confirmed by "spec PASS". history.compare instead re-derives each recorded
object fix from the recorded source evidence and requires, on the fresh target
collection: the object predicate holds, the object is exactly in the rehearsed
post-fix state (the sandbox's applied signature) and it is no longer in its
recorded prior state. Setting runs keep the spec PASS rule.

Fake runtimes only (tests/test_object_sandbox.py helpers); no Docker.
"""
import copy

import pytest

from services.sandbox_poc import history, object_fixes
from services.sandbox_poc.handoff import SandboxHandoff, TemplateReference, build_handoff
from services.sandbox_poc.shared import ContractError, SpecEngine
from tests.test_object_sandbox import (_find_role, batch_service, effect_for, engine, planted,  # noqa: F401
                                       proposals_for, run_object, snapshot)

EVIDENCE = [{"document_id": "doc-1", "version": "1", "sha256": "a" * 64}]


@pytest.fixture
def history_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("DBGUARD_HISTORY_DIR", str(tmp_path))
    return tmp_path


@pytest.fixture
def source(planted):
    planted["baseline"]["identity"]["system_identifier"] = "12345"
    planted["envelope"]["collected_at"] = "2026-10-30T00:00:00Z"
    return planted


def fresh_from(source, *proposals, applied=True):
    """A newer target collection; with ``applied`` the DBA ran these fixes."""
    fresh = copy.deepcopy(source)
    fresh["envelope"]["collected_at"] = "2026-11-02T00:00:00Z"
    for proposal in proposals:
        effect_for(proposal)[2](fresh, applied)
    return fresh


def record_single(engine, source, proposal):
    result, _ = run_object(engine, source, proposal, [None])
    assert result["status"] == "VERIFIED", result["attempts"][-1].get("error")
    result["run_id"] = "obj-run"
    from scripts.sandbox_poc import demo_template
    setting = demo_template()
    ref = TemplateReference(version=setting.version, sha256=setting.sha256, evidence=EVIDENCE)
    base = build_handoff(engine, source, ref).model_dump()
    handoff = SandboxHandoff(**{**base, "control_id": proposal["spec_id"], "object_fix_id": proposal["fix_id"],
                                "template_ref": {"registry_name": proposal["fix_type"], "version": 1,
                                                 "sha256": result["template"]["sha256"], "evidence": EVIDENCE}})
    history.record(handoff, result, None)
    return result


class TestSingleObjectRun:
    @pytest.mark.parametrize("index", range(5))
    def test_fix_visible_on_target_is_confirmed(self, engine, source, history_dir, index):
        proposal = proposals_for(engine, source)[index]
        record_single(engine, source, proposal)
        verdict = history.compare("obj-run", fresh_from(source, proposal), engine)
        assert verdict["status"] == "TARGET_REASSESSMENT_CONFIRMED", verdict.get("object_checks")
        [check] = verdict["object_checks"]
        assert check == {"fix_id": proposal["fix_id"], "spec_id": proposal["spec_id"], "predicate": True,
                         "matches_applied": True, "still_prior": False, "verified": True}
        # The catalog spec itself is not in the findings and is not what confirmed it.
        assert proposal["spec_id"] not in verdict["assessment"]["findings"]

    def test_target_still_in_prior_state_fails(self, engine, source, history_dir):
        proposal = proposals_for(engine, source)[2]  # role_nologin
        record_single(engine, source, proposal)
        verdict = history.compare("obj-run", fresh_from(source), engine)
        assert verdict["status"] == "TARGET_VERIFICATION_FAILED"
        [check] = verdict["object_checks"]
        assert check["predicate"] is False and check["still_prior"] is True and check["verified"] is False

    def test_predicate_true_but_object_otherwise_changed_fails(self, engine, source, history_dir):
        proposal = proposals_for(engine, source)[2]  # role_nologin
        record_single(engine, source, proposal)
        fresh = fresh_from(source, proposal)
        _find_role(fresh, proposal["target"]["role"])["rolcreaterole"] = True
        verdict = history.compare("obj-run", fresh, engine)
        assert verdict["status"] == "TARGET_VERIFICATION_FAILED"
        [check] = verdict["object_checks"]
        assert check["predicate"] is True and check["matches_applied"] is False

    def test_object_missing_on_target_fails(self, engine, source, history_dir):
        proposal = proposals_for(engine, source)[2]
        record_single(engine, source, proposal)
        fresh = fresh_from(source, proposal)
        fresh["baseline"]["roles"] = [r for r in fresh["baseline"]["roles"]
                                      if r["rolname"] != proposal["target"]["role"]]
        verdict = history.compare("obj-run", fresh, engine)
        assert verdict["status"] == "TARGET_VERIFICATION_FAILED"
        assert verdict["object_checks"][0]["predicate"] is False

    @pytest.mark.parametrize("index,section", [(2, "roles"), (3, "functions"), (4, "object_acls")])
    def test_uncollected_section_never_confirms(self, engine, source, history_dir, index, section):
        proposal = proposals_for(engine, source)[index]
        record_single(engine, source, proposal)
        fresh = fresh_from(source, proposal)
        fresh["baseline"][section] = None
        fresh["baseline"]["gaps"] = [{"section": section, "reason": "insufficient_privilege"}]
        verdict = history.compare("obj-run", fresh, engine)
        assert verdict["status"] == "TARGET_VERIFICATION_FAILED"
        [check] = verdict["object_checks"]
        assert check["verified"] is False and check["predicate"] is False and "reason" in check

    def test_expiry_in_another_timezone_still_confirms(self, engine, source, history_dir):
        """Source collected at +08:00, sandbox in UTC, fresh target at -05:00: one instant."""
        proposal = proposals_for(engine, source)[2]
        name = proposal["target"]["role"]
        _find_role(source, name)["rolvaliduntil"] = "2027-01-01T08:00:00+08:00"
        proposal = object_fixes.resolve(engine, source, engine.policy_pin, proposal["fix_id"])
        record_single(engine, source, proposal)
        fresh = fresh_from(source, proposal)
        _find_role(fresh, name)["rolvaliduntil"] = "2026-12-31T19:00:00-05:00"
        assert history.compare("obj-run", fresh, engine)["status"] == "TARGET_REASSESSMENT_CONFIRMED"
        _find_role(fresh, name)["rolvaliduntil"] = "2026-12-31T20:00:00-05:00"
        assert history.compare("obj-run", fresh, engine)["status"] == "TARGET_VERIFICATION_FAILED"

    def test_run_without_rehearsed_state_never_confirms(self, engine, source, history_dir):
        proposal = proposals_for(engine, source)[2]
        result = record_single(engine, source, proposal)
        result["status"] = "FAILED"
        with history.db() as c:
            import json
            c.execute("UPDATE runs SET result=? WHERE run_id=?", (json.dumps(result), "obj-run"))
        verdict = history.compare("obj-run", fresh_from(source, proposal), engine)
        assert verdict["status"] == "TARGET_VERIFICATION_FAILED"
        assert verdict["object_checks"][0]["reason"] == "The recorded run has no rehearsed post-fix state"

    def test_tampered_recorded_fix_unit_is_refused(self, engine, source, history_dir):
        proposal = proposals_for(engine, source)[2]
        result = record_single(engine, source, proposal)
        result["fix_unit"]["target"] = {"role": "dbguard_poc"}
        with history.db() as c:
            import json
            c.execute("UPDATE runs SET result=? WHERE run_id=?", (json.dumps(result), "obj-run"))
        with pytest.raises(ContractError, match="differs from the evidence-derived proposal"):
            history.compare("obj-run", fresh_from(source, proposal), engine)


class TestObjectBatchRun:
    def _record(self, engine, source, monkeypatch):
        from services.sandbox_poc import batch, profiles
        monkeypatch.setattr(profiles, "resolve_profile", lambda records, specs, ref: engine.policy)
        monkeypatch.setattr(SpecEngine, "collect", lambda self, runtime: copy.deepcopy(runtime.snapshot))
        service, requests, _, proposals = batch_service(engine, source)
        output, data = batch.run_batch(requests, service)
        assert output["status"] == "VERIFIED", output.get("combined_test", {}).get("reason")
        history.record(requests[0], output, data)
        return output, proposals

    def test_all_fixes_visible_confirms(self, engine, source, history_dir, monkeypatch):
        output, proposals = self._record(engine, source, monkeypatch)
        verdict = history.compare(output["run_id"], fresh_from(source, *proposals), engine)
        assert verdict["status"] == "TARGET_REASSESSMENT_CONFIRMED", verdict["object_checks"]
        assert sorted(c["fix_id"] for c in verdict["object_checks"]) == sorted(p["fix_id"] for p in proposals)

    def test_partly_applied_batch_fails(self, engine, source, history_dir, monkeypatch):
        output, proposals = self._record(engine, source, monkeypatch)
        verdict = history.compare(output["run_id"], fresh_from(source, *proposals[:-1]), engine)
        assert verdict["status"] == "TARGET_VERIFICATION_FAILED"
        verified = {c["fix_id"]: c["verified"] for c in verdict["object_checks"]}
        missing = proposals[-1]
        assert verified[missing["fix_id"]] is False
        for p in proposals[:-1]:
            # A fix on the same object fails too: that object is not in the combined tested state.
            assert verified[p["fix_id"]] is (p["target"]["role"] != missing["target"]["role"])
        assert any(verified.values())


class TestTargetVerificationFunction:
    def test_rehearsed_state_must_differ_from_prior(self, engine, source):
        proposal = proposals_for(engine, source)[2]
        check = object_fixes.target_verification(proposal, source, source, fresh_from(source, proposal))
        assert check["matches_applied"] is False and check["verified"] is False

