"""Bounded LangGraph remediation/testing loop with fail-closed evidence."""
from __future__ import annotations

import copy
import re
from typing import TypedDict

from langgraph.graph import END, START, StateGraph

from .provenance import reconstruct, reconstruction_plan, rollback_sql, setting_rows, signature
from .runtime import DisposablePostgres
from .shared import ContractError, SpecEngine, digest, validate_contract
from .templates import ApprovedTemplate
from .adaptive import RevisionDecision, feedback_for

CONTROL = "cis-pg17-v1.1.0:3.1.20"


class LoopState(TypedDict):
    attempts: list[dict]
    done: bool
    status: str
    revisions: list[dict]


class RemediationLoop:
    def __init__(self, engine: SpecEngine, template: ApprovedTemplate,
                 runtime_factory=DisposablePostgres, max_attempts: int = 3,
                 reviser=None, alternatives=(), refresh_template=None):
        if type(max_attempts) is not int or not 1 <= max_attempts <= 3:
            raise ContractError("Attempt limit must be 1, 2 or 3")
        self.engine = engine
        self.template = template
        self.runtime_factory = runtime_factory
        self.max_attempts = max_attempts
        self.reviser = reviser
        self.alternatives = tuple(alternatives)
        self.refresh_template = refresh_template

    def run(self, snapshot: dict, assessment: dict) -> dict:
        snapshot = copy.deepcopy(snapshot)
        # A supplied assessment is bound to exact evidence, not merely an ID.
        actual = self.engine.assess(snapshot)
        if assessment != actual:
            raise ContractError("Assessment is not bound to this snapshot and exact spec set")
        if actual["findings"].get(CONTROL, {}).get("status") != "FAIL":
            raise ContractError("log_connections must be a reproduced source FAIL")
        spec = next(s for s in self.engine.specs if s["spec_id"] == CONTROL)
        supported = {"kind": "setting", "setting_name": "log_connections",
                     "query": "SHOW log_connections", "operator": "equals", "expected": "on"}
        if any(spec["check"].get(key) != value for key, value in supported.items()):
            raise ContractError("This milestone only fixes log_connections equals on")
        if any(f["status"] == "GAPPED" for f in actual["findings"].values()):
            raise ContractError("Cannot establish regression coverage with gapped controls")
        plan = reconstruction_plan(snapshot, self.engine.specs)
        rendered = self.template.render()
        prior = setting_rows(snapshot)["log_connections"]
        fix = {
            "fix_id": "fix-log_connections", "spec_id": CONTROL,
            "template_id": "SET_CONFIG_log_connections", "template_version": self.template.version,
            "params": {"param_name": "log_connections", "param_value": "on"},
            "prior_state": {"value": prior["setting"], "source": prior["source"],
                            "sourcefile": prior["sourcefile"], "context": prior["context"]},
            "precheck": {"expected_value": prior["setting"], "query": "SHOW log_connections"},
            "apply": rendered,
            "verify": {"spec_check_ref": CONTROL, "expected_value": "on", "query": "SHOW log_connections"},
            "rollback": rollback_sql(snapshot), "requires": "reload",
        }
        validate_contract(fix, "fix-unit-v1.json")
        current_template = self.template
        current_id = 'initial'
        used_sql = set()

        def sql_identity(sql):
            # Whitespace/comment-only changes are not improved fixes.
            return re.sub(r'\s+', ' ', re.sub(r'--[^\n]*', '', sql)).strip()

        def revise(state: LoopState):
            nonlocal fix, current_template, current_id
            available = {}
            try:
                for index, candidate in enumerate(self.alternatives):
                    if sql_identity(candidate.render()) not in used_sql:
                        available[f'alternative-{index + 1}'] = candidate
                choices = [{'candidate_id': key, 'template': value.identity(),
                            'rendered_sql': value.render()} for key, value in available.items()]
                decision = RevisionDecision.model_validate(self.reviser(
                    feedback_for(state['attempts'], choices, current_id, fix['apply'])))
                revision = decision.model_dump()
                if decision.action == 'manual_review':
                    return {'done': True, 'status': 'NEEDS_REVIEW',
                            'revisions': state['revisions'] + [revision]}
                if decision.candidate_id not in available:
                    raise ContractError('LLM did not select a different approved candidate')
                candidate = available[decision.candidate_id]
                if self.refresh_template:
                    candidate = self.refresh_template(candidate)
                if sql_identity(candidate.render()) in used_sql:
                    raise ContractError('Revised candidate repeats previously tested SQL')
                current_template, current_id = candidate, decision.candidate_id
                fix = {**fix, 'apply': candidate.render(), 'template_version': candidate.version}
                validate_contract(fix, 'fix-unit-v1.json')
                return {'done': False, 'revisions': state['revisions'] + [revision]}
            except Exception:
                return {'done': True, 'status': 'NEEDS_REVIEW',
                        'revisions': state['revisions'] + [{
                            'action': 'manual_review',
                            'diagnosis': 'Revision failed model, approval or candidate validation',
                            'proposed_improvement': 'Review the failed gates and approved alternatives before another run'}]}

        def attempt(state: LoopState):
            runtime = self.runtime_factory()
            record = {"attempt": len(state["attempts"]) + 1, "run_id": runtime.run_id,
                      "status": "FAILED", "phase": "create", "rollback_verified": False,
                      "candidate_id": current_id, "template": current_template.identity(),
                      "fix_unit_hash": digest(fix)}
            used_sql.add(sql_identity(fix['apply']))
            terminal = False
            try:
                runtime.start()
                record["image_id"] = runtime.image_id
                record["phase"] = "reproduce"
                reconstruct(runtime, plan)
                before = self.engine.collect(runtime)
                before_report = self.engine.assess(before)
                record.update(before=before, before_assessment=before_report)
                if signature(before, plan["names"]) != plan["signature"]:
                    raise ContractError("Reconstruction did not preserve configuration provenance")
                if before_report["findings"] != actual["findings"]:
                    raise ContractError("Reconstruction did not reproduce all scoped findings")
                record["phase"] = "apply"
                try:
                    runtime.sql(fix["apply"])
                    runtime.activate({"log_connections": "on"})
                    record["phase"] = "reassess"
                    after = self.engine.collect(runtime)
                    after_report = self.engine.assess(after)
                    record.update(after=after, after_assessment=after_report)
                    record["health_after_apply"] = runtime.health()
                    regressions = [sid for sid, finding in before_report["findings"].items()
                                   if sid != CONTROL and (
                                       (finding["status"] == "PASS" and after_report["findings"][sid]["status"] != "PASS")
                                       or after_report["findings"][sid]["status"] == "GAPPED")]
                    record["regressions"] = regressions
                    if after["baseline"].get("gaps"):
                        raise RuntimeError("Post-apply collection has gaps")
                    if (after_report["findings"][CONTROL]["status"] != "PASS"
                            or regressions or not record["health_after_apply"]):
                        raise RuntimeError("Fix failed acceptance: target/regression/health")
                    # A reload request alone is not proof that the setting applied.
                    if setting_rows(after)["log_connections"].get("pending_restart") is not False:
                        raise RuntimeError("Fix left a pending restart")
                except Exception as exc:
                    record["apply_or_assessment_error"] = f"{type(exc).__name__}: {exc}"
                    raise
                finally:
                    # Also test rollback after a partially executed/failed apply.
                    record["phase_before_rollback"] = record["phase"]
                    record["phase"] = "rollback"
                    runtime.sql(fix["rollback"])
                    runtime.activate(plan["expected"])
                    restored = self.engine.collect(runtime)
                    restored_report = self.engine.assess(restored)
                    record.update(rollback=restored, rollback_assessment=restored_report,
                                  health_after_rollback=runtime.health())
                    record["rollback_verified"] = (
                        signature(restored, plan["names"]) == plan["signature"]
                        and restored_report["findings"] == before_report["findings"]
                        and not restored["baseline"].get("gaps")
                        and record["health_after_rollback"])
                    if not record["rollback_verified"]:
                        raise RuntimeError("Exact rollback verification failed")
                record.update(status="VERIFIED", phase="complete")
            except ContractError as exc:
                terminal = True
                record["error"] = str(exc)
            except Exception as exc:
                record["error"] = f"{type(exc).__name__}: {exc}"
            finally:
                try:
                    record["cleanup"] = runtime.close()
                    if record["cleanup"].get("verified") is not True:
                        raise RuntimeError("Cleanup did not confirm resource removal")
                except Exception as exc:
                    terminal = True
                    record["status"] = "CLEANUP_FAILED"
                    record["cleanup"] = {"verified": False, "error": str(exc)}
            attempts = state["attempts"] + [record]
            return {"attempts": attempts, "status": record["status"],
                    "done": terminal or record["status"] == "VERIFIED" or len(attempts) >= self.max_attempts}

        graph = StateGraph(LoopState)
        graph.add_node("test_fix", attempt)
        graph.add_edge(START, "test_fix")
        if self.reviser:
            graph.add_node('revise_fix', revise)
            graph.add_conditional_edges('test_fix', lambda state: 'end' if state['done'] else 'revise',
                                        {'end': END, 'revise': 'revise_fix'})
            graph.add_conditional_edges('revise_fix', lambda state: 'end' if state['done'] else 'retry',
                                        {'end': END, 'retry': 'test_fix'})
        else:
            graph.add_conditional_edges("test_fix", lambda state: "end" if state["done"] else "retry",
                                        {"end": END, "retry": "test_fix"})
        state = graph.compile().invoke({"attempts": [], "done": False, "status": "PENDING", 'revisions': []},
                                       config={"recursion_limit": 12})
        return {"schema_version": "sandbox-run-v1", "status": state["status"],
                "snapshot_hash": digest(snapshot), "spec_set_hash": self.engine.spec_set_hash,
                "spec_hashes": self.engine.hashes, "collector_hash": self.engine.collector_hash,
                "template": current_template.identity(), "fix_unit": fix,
                "retry_mode": 'adaptive' if self.reviser else 'repeat', 'revisions': state['revisions'],
                "fix_unit_hash": digest(fix), "attempts": state["attempts"],
                "regression_scope": list(self.engine.hashes),
                "limitations": ["PostgreSQL 17; log_connections only; reload only",
                                "Reconstructs settings in supplied specs, not the full database",
                                "No real-target execution by the sandbox"]}
