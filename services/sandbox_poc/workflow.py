"""Bounded LangGraph remediation/testing loop with fail-closed evidence."""
from __future__ import annotations

import copy
import re
from typing import TypedDict

from langgraph.graph import END, START, StateGraph

from .provenance import reconstruct, reconstruction_plan, setting_rows, signature
from app.services.fix_unit_render import derive_rollback, render_action_script
from app.services.setting_values import SettingValueError, check_setting_value
from .runtime import DisposablePostgres, SandboxStartError
from .shared import ContractError, SpecEngine, blocking_gaps, digest, is_regression, validate_contract
from .templates import ApprovedTemplate
from . import terminal_capture
from .adaptive import RevisionDecision, feedback_for

CONTROL = "cis-pg17-v1.1.0:3.1.20"


def template_action(sql: str, name="log_connections") -> dict:
    from .planning import COMPUTED, POLICIES
    # COMPUTED settings (shared_preload_libraries) are written only by the set_config_list
    # template (list_template_action), never by set_config_parameter (W2B security review B1).
    if name not in POLICIES or POLICIES[name][0] == COMPUTED:
        raise ContractError("Unsupported setting action")
    body = "\n".join(line for line in sql.splitlines() if not line.lstrip().startswith("--"))
    # The literal may hold any character except a quote or line break; the value is
    # then checked against the reviewed per-setting table (GLOBAL_FORBIDDEN rejects
    # quotes, so an escaped '' can never reach this point as a valid value).
    match = re.fullmatch(r"\s*ALTER\s+SYSTEM\s+SET\s+\"?"+re.escape(name)+r"\"?\s*=\s*'([^'\n\r]+)'\s*;\s*SELECT\s+pg_reload_conf\s*\(\s*\)\s*;\s*", body, re.I)
    if not match:
        raise ContractError("Approved template is outside the supported setting action")
    try:
        value = check_setting_value(name, match[1])
    except SettingValueError as exc:
        raise ContractError(f"Approved template value is outside the reviewed rule: {exc}") from None
    return {"action": "set_config", "param": name, "value": value}


ROLLBACK_SKIPPED = ("PostgreSQL did not start after the change, so no rollback SQL was run on a stopped "
                    "server; the disposable sandbox is removed instead.")


def _setting_rollback(engine, runtime, fix, plan, record, before_report) -> None:
    """Roll back one setting fix and verify the exact prior provenance and findings."""
    runtime.sql(render_action_script(fix["rollback"]))
    runtime.activate(plan["expected"])
    restored = engine.collect(runtime)
    restored_report = engine.assess(restored)
    record.update(rollback=restored, rollback_assessment=restored_report,
                  health_after_rollback=runtime.health())
    record["rollback_verified"] = (
        signature(restored, plan["names"]) == plan["signature"]
        and restored_report["findings"] == before_report["findings"]
        and not blocking_gaps(restored)
        and record["health_after_rollback"])
    if not record["rollback_verified"]:
        raise RuntimeError("Exact rollback verification failed")


def setting_catalog_regressions(engine, before_report, after_report, name, control) -> list[str]:
    """Catalog checks whose evaluator reads the changed setting and went from PASS to not PASS."""
    from .catalog_fixes import catalog_regressions
    if "upstream_report" not in before_report or "upstream_report" not in after_report:
        return []
    return catalog_regressions(engine, before_report, after_report, [name], control)


_LIST_ITEM = r"'(?:[^'\n\r]|'')*'"
_LIST_STATEMENT = re.compile(r"\s*ALTER\s+SYSTEM\s+SET\s+\"shared_preload_libraries\"\s*=\s*(" + _LIST_ITEM
                             + r"(?:\s*,\s*" + _LIST_ITEM + r")*)\s*;\s*SELECT\s+pg_reload_conf\s*\(\s*\)\s*;\s*",
                             re.I)


def list_template_action(sql: str) -> dict:
    """The typed action of a rendered set_config_list statement (W2B rulings round 3).

    Exactly one ALTER SYSTEM SET of shared_preload_libraries to one or more literals, then
    pg_reload_conf(); every item must pass the reviewed list schema."""
    from app.models import SetConfigListTemplateParams
    body = "\n".join(line for line in sql.splitlines() if not line.lstrip().startswith("--"))
    match = _LIST_STATEMENT.fullmatch(body)
    if not match:
        raise ContractError("Approved list template is outside the supported setting action")
    values = [item[1:-1].replace("''", "'") for item in re.findall(_LIST_ITEM, match[1])]
    try:
        SetConfigListTemplateParams(param_name="shared_preload_libraries", param_values=values)
    except ValueError as exc:
        raise ContractError(f"Approved list template value is outside the reviewed rule: {exc}") from None
    return {"action": "set_config_list", "param": "shared_preload_libraries", "values": values}


class LoopState(TypedDict):
    attempts: list[dict]
    done: bool
    status: str
    revisions: list[dict]


class RemediationLoop:
    def __init__(self, engine: SpecEngine, template: ApprovedTemplate,
                 runtime_factory=DisposablePostgres, max_attempts: int = 3,
                 reviser=None, alternatives=(), refresh_template=None, control_id=CONTROL):
        if type(max_attempts) is not int or not 1 <= max_attempts <= 3:
            raise ContractError("Attempt limit must be 1, 2 or 3")
        self.control_id = control_id
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
        actual = self.engine.bind_assessment(snapshot, assessment)
        control = self.control_id
        from .planning import fix_scope
        spec, name, value = fix_scope(self.engine, control)
        if actual["findings"].get(control, {}).get("status") != "FAIL":
            raise ContractError("Selected control must be a reproduced source FAIL")
        if self.engine.gapped_settings(actual["findings"]):
            raise ContractError("Cannot establish regression coverage with gapped controls")
        plan = reconstruction_plan(snapshot, self.engine.specs)
        rendered = self.template.render(name, value)
        prior = setting_rows(snapshot)[name]
        fix = {
            "fix_id": "fix-"+name, "spec_id": control,
            "template_id": "SET_CONFIG_"+name, "template_version": self.template.version,
            "params": {"param_name": name, "param_value": value},
            "prior_state": {"value": prior["setting"], "source": prior["source"],
                            "sourcefile": prior["sourcefile"], "context": prior["context"]},
            "precheck": {"expected_value": prior["setting"], "query": f"SHOW {name}"},
            "apply": template_action(rendered, name),
            "verify": {"spec_check_ref": control, "expected_value": value, "query": f"SHOW {name}"},
            "requires": "restart" if prior["context"] == "postmaster" else "reload",
        }
        fix["rollback"] = derive_rollback(fix["prior_state"], fix["apply"])
        fix["params"]["param_value"] = fix["apply"]["value"]
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
                    if sql_identity(candidate.render(name, value)) not in used_sql:
                        available[f'alternative-{index + 1}'] = candidate
                choices = [{'candidate_id': key, 'template': candidate_template.identity(),
                            'rendered_sql': candidate_template.render(name, value)} for key, candidate_template in available.items()]
                decision = RevisionDecision.model_validate(self.reviser(
                    feedback_for(state['attempts'], choices, current_id, current_template.render(name, value), name, value)))
                revision = decision.model_dump()
                if decision.action == 'manual_review':
                    return {'done': True, 'status': 'NEEDS_REVIEW',
                            'revisions': state['revisions'] + [revision]}
                if decision.candidate_id not in available:
                    raise ContractError('LLM did not select a different approved candidate')
                candidate = available[decision.candidate_id]
                if self.refresh_template:
                    candidate = self.refresh_template(candidate)
                if sql_identity(candidate.render(name, value)) in used_sql:
                    raise ContractError('Revised candidate repeats previously tested SQL')
                current_template, current_id = candidate, decision.candidate_id
                fix = {**fix, 'apply': template_action(candidate.render(name, value), name), 'template_version': candidate.version}
                fix['params'] = {**fix['params'], 'param_value': fix['apply']['value']}
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
            used_sql.add(sql_identity(current_template.render(name, value)))
            record['rendered_apply_sql'] = current_template.render(name, value)
            # Task 2: terminal screenshots (no-op unless DBGUARD_SCREENSHOT_MODE=terminal).
            terminal_capture.begin(record)
            shots = terminal_capture.setting_targets([name])
            terminal = False
            start_error = None
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
                terminal_capture.stage(record, runtime, "before", shots)
                record["phase"] = "apply"
                try:
                    runtime.sql(current_template.render(name, value))
                    runtime.activate({name: value})
                    record["phase"] = "reassess"
                    after = self.engine.collect(runtime)
                    after_report = self.engine.assess(after)
                    record.update(after=after, after_assessment=after_report)
                    record["health_after_apply"] = runtime.health()
                    if isinstance(runtime, DisposablePostgres):
                        from .evidence_capture import verify_runtime
                        record['functional_checks'] = verify_runtime(runtime, control, name, value, 'AFTER FIX')
                        if not record['functional_checks']['passed']:
                            raise RuntimeError('Functional verification failed')
                    regressions = [sid for sid, finding in before_report["findings"].items()
                                   if sid != control and (
                                       is_regression(finding["status"], after_report["findings"][sid]["status"])
                                       or sid in self.engine.gapped_settings(after_report["findings"]))]
                    # W2B: catalog checks that read this setting (planning.CATALOG_INPUT_AFFECTS).
                    regressions += setting_catalog_regressions(self.engine, before_report, after_report, name, control)
                    record["regressions"] = regressions
                    if blocking_gaps(after):
                        raise RuntimeError("Post-apply collection has gaps")
                    if (after_report["findings"][control]["status"] != "PASS"
                            or regressions or not record["health_after_apply"]):
                        raise RuntimeError("Fix failed acceptance: target/regression/health")
                    # A reload request alone is not proof that the setting applied.
                    if setting_rows(after)[name].get("pending_restart") is not False:
                        raise RuntimeError("Fix left a pending restart")
                    terminal_capture.stage(record, runtime, "after", shots)
                except SandboxStartError as exc:
                    start_error = exc
                    record["apply_or_assessment_error"] = f"SandboxStartError: {exc}"
                    raise
                except Exception as exc:
                    record["apply_or_assessment_error"] = f"{type(exc).__name__}: {exc}"
                    raise
                finally:
                    # Also test rollback after a partially executed/failed apply.
                    record["phase_before_rollback"] = record["phase"]
                    if start_error is not None:
                        # PostgreSQL is down after the restart: running rollback SQL would only
                        # add a confusing psql error. The sandbox is removed in cleanup instead.
                        record["phase"] = "start_failed"
                        record["rollback_skipped"] = ROLLBACK_SKIPPED
                    else:
                        record["phase"] = "rollback"
                        _setting_rollback(self.engine, runtime, fix, plan, record, before_report)
                        terminal_capture.stage(record, runtime, "rollback", shots)
                record.update(status="VERIFIED", phase="complete")
            except SandboxStartError as exc:
                # Deterministic (e.g. a preload library missing from the image): no retry.
                terminal = True
                record["error"] = f"SandboxStartError: {exc}"
            except ContractError as exc:
                terminal = True
                record["error"] = str(exc)
            except Exception as exc:
                record["error"] = f"{type(exc).__name__}: {exc}"
            finally:
                terminal_capture.finish(record)
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
                "policy_profile": self.engine.policy_pin,
                "template": current_template.identity(), "fix_unit": fix,
                "rendered_apply_sql": current_template.render(name, value),
                "rendered_rollback_sql": render_action_script(fix["rollback"]),
                "retry_mode": 'adaptive' if self.reviser else 'repeat', 'revisions': state['revisions'],
                "fix_unit_hash": digest(fix), "attempts": state["attempts"],
                "regression_scope": list(self.engine.hashes),
                "limitations": ["PostgreSQL 17; approved setting policies only",
                                "Reconstructs settings in supplied specs, not the full database",
                                "No real-target execution by the sandbox"]}


# ---------------------------------------------------------------------------
# Wave 2a: per-object fixes (roles, function security, table DML grants).
# ---------------------------------------------------------------------------

OBJECT_STATEMENT_PREFIXES = {
    "role_connection_limit": ("ALTER ROLE ",),
    "role_drop_attribute": ("ALTER ROLE ",),
    "role_nologin": ("ALTER ROLE ",),
    "function_security_invoker": ("ALTER FUNCTION ",),
    "function_revoke_public_execute": ("REVOKE EXECUTE ON FUNCTION ", "GRANT EXECUTE ON FUNCTION "),
    "table_revoke_dml": ("REVOKE ", "GRANT "),
}


def _one_statement(sql: str) -> bool:
    """True when sql is exactly one statement: one trailing ';', no psql meta-command.

    Quoted identifiers and literals are skipped, so a name holding ';', '--' or a
    backslash cannot split the statement or reach psql as a command.
    """
    pos, semicolons, end = 0, [], len(sql)
    while pos < end:
        char = sql[pos]
        if char in "\"'":
            close = pos + 1
            while True:
                close = sql.find(char, close)
                if close < 0:
                    return False
                if sql[close + 1:close + 2] == char:
                    close += 2
                    continue
                break
            pos = close + 1
            continue
        if char == "\\" or sql.startswith("--", pos) or sql.startswith("/*", pos) or char == "$":
            return False
        if char == ";":
            semicolons.append(pos)
        pos += 1
    return semicolons == [len(sql.rstrip()) - 1]


def object_statements(rendered: dict, fix_type: str) -> tuple[list[str], list[str]]:
    """Checked apply/rollback lists from object_fixes.render(); transactional DCL/ALTER only."""
    prefixes = OBJECT_STATEMENT_PREFIXES.get(fix_type)
    if prefixes is None or not isinstance(rendered, dict):
        raise ContractError("Unsupported object fix type")
    out = []
    for key in ("apply", "rollback"):
        statements = rendered.get(key)
        if not isinstance(statements, list) or not 1 <= len(statements) <= 8:
            raise ContractError("Rendered object fix has no statements")
        for sql in statements:
            if (not isinstance(sql, str) or not sql.strip().upper().startswith(prefixes)
                    or not _one_statement(sql.strip())):
                raise ContractError("Rendered object fix is outside the supported statements")
        out.append([s.strip() for s in statements])
    return out[0], out[1]


def in_transaction(statements: list[str]) -> str:
    """One BEGIN ... COMMIT script. psql ON_ERROR_STOP ends the session on any error,
    so a failed statement aborts the whole transaction: nothing is half-applied."""
    return "BEGIN;\n" + "\n".join(statements) + "\nCOMMIT;\n"


def health_queries(runtime, phase: str) -> dict:
    """Fixed reviewed health checks (planning.CHECKS) in fresh psql sessions."""
    from .planning import CHECKS
    queries = []
    for key, check in CHECKS.items():
        output = runtime.sql(check["query"] + ";")
        queries.append({"id": key, **check, "output": output,
                        "passed": output.strip() in ("1", "t", "true")})
    return {"passed": all(q["passed"] for q in queries), "screenshot": {"status": "DISABLED"},
            "query_evidence": {"scope": "DISPOSABLE SANDBOX · " + phase, "run_id": runtime.run_id,
                               "queries": queries}}


def _normalised(row):
    """A collected object row with its ACL as a set: GRANT re-appends, REVOKE removes,
    so an exact rollback can reorder aclitems without changing any privilege."""
    if not isinstance(row, dict):
        return row
    out = dict(row)
    if isinstance(out.get("acl"), list):
        out["acl"] = sorted(out["acl"])
    return out


def object_fix_unit(proposal: dict, template: ApprovedTemplate, apply: list[str],
                    rollback: list[str], predicate_text: str) -> dict:
    """fix-unit v2 for an object action; validated when the v2 contract is installed."""
    fix = {"schema_version": "fix-unit-v2", "fix_id": proposal["fix_id"], "spec_id": proposal["spec_id"],
           "fix_type": proposal["fix_type"], "template_id": template.registry_name,
           "template_version": template.version, "target": copy.deepcopy(proposal["target"]),
           "params": copy.deepcopy(proposal.get("params") or {}),
           "prior_state": copy.deepcopy(proposal["prior"]),
           "apply": {"statements": list(apply), "transactional": True},
           "rollback": {"statements": list(rollback), "transactional": True},
           "verify": {"predicate": predicate_text}, "requires": "none"}
    from .shared import ROOT
    if (ROOT / "catalog/specs/contracts/fix-unit-v2.json").is_file():
        validate_contract(fix, "fix-unit-v2.json")
    return fix


def _object_fixes():
    from . import object_fixes
    return object_fixes


def predicate_text(fixes, proposal: dict) -> str:
    describe = getattr(fixes, "describe_predicate", None)
    text = describe(proposal) if describe else proposal.get("predicate")
    if not isinstance(text, str) or not text.strip():
        raise ContractError("Object fix has no reviewed predicate description")
    return text


class ObjectRemediationLoop:
    """Rehearse one per-object fix on a targeted stand-in (catalog_skeleton).

    fresh sandbox -> settings reconstruction -> stand-in -> reproduce (prior state
    and object signature equal the source) -> apply in one transaction -> verify
    (predicate true, other recreated objects and settings unchanged, health) ->
    roll back in one transaction -> exact object/setting equality -> cleanup.
    """

    def __init__(self, engine: SpecEngine, template: ApprovedTemplate, proposal: dict,
                 runtime_factory=DisposablePostgres, max_attempts: int = 3, fixes=None):
        if type(max_attempts) is not int or not 1 <= max_attempts <= 3:
            raise ContractError("Attempt limit must be 1, 2 or 3")
        self.engine = engine
        self.template = template
        self.proposal = copy.deepcopy(proposal)
        self.runtime_factory = runtime_factory
        self.max_attempts = max_attempts
        self.fixes = fixes

    def prepare(self, snapshot: dict, assessment: dict) -> dict:
        """Every check that needs no container. Returns the bound inputs of a run."""
        from . import catalog_skeleton
        fixes = self.fixes or _object_fixes()
        engine = self.engine
        actual = engine.bind_assessment(snapshot, assessment)
        if engine.gapped_settings(actual["findings"]):
            raise ContractError("Cannot establish regression coverage with gapped controls")
        proposal = self.proposal
        if not isinstance(proposal, dict) or not isinstance(proposal.get("fix_id"), str):
            raise ContractError("Object fix proposal is malformed")
        if proposal.get("rehearsable") is not True:
            raise ContractError("This fix cannot be rehearsed on a stand-in copy")
        # Never trust a supplied proposal: it must be exactly what the reviewed
        # resolver derives from this snapshot and the approved profile.
        if fixes.resolve(engine, snapshot, engine.policy_pin, proposal["fix_id"]) != proposal:
            raise ContractError("Object fix proposal differs from the evidence-derived proposal")
        if not fixes.prior_holds(proposal, snapshot) or fixes.predicate(proposal, snapshot):
            raise ContractError("The source evidence does not show the state this fix changes")
        plan = reconstruction_plan(snapshot, engine.specs)
        skeleton = catalog_skeleton.plan(snapshot, [proposal])
        apply, rollback = object_statements(fixes.render(proposal, self.template), proposal["fix_type"])
        fix = object_fix_unit(proposal, self.template, apply, rollback, predicate_text(fixes, proposal))
        return {"fixes": fixes, "actual": actual, "plan": plan, "skeleton": skeleton, "fix": fix,
                "apply": apply, "rollback": rollback,
                "source_signature": fixes.object_signature(proposal, snapshot)}

    def run(self, snapshot: dict, assessment: dict) -> dict:
        from . import catalog_skeleton
        snapshot = copy.deepcopy(snapshot)
        bound = self.prepare(snapshot, assessment)
        fixes, actual, plan, fix = bound["fixes"], bound["actual"], bound["plan"], bound["fix"]
        apply, rollback, source_signature = bound["apply"], bound["rollback"], bound["source_signature"]
        proposal, engine = self.proposal, self.engine
        key = catalog_skeleton.target_key(proposal)
        names = plan["names"]

        def attempt(state: LoopState):
            runtime = self.runtime_factory()
            record = {"attempt": len(state["attempts"]) + 1, "run_id": runtime.run_id,
                      "status": "FAILED", "phase": "create", "rollback_verified": False,
                      "template": self.template.identity(), "fix_unit_hash": digest(fix),
                      "rendered_apply_sql": "\n".join(apply)}
            # Task 2: terminal screenshots (no-op unless DBGUARD_SCREENSHOT_MODE=terminal).
            terminal_capture.begin(record)
            shots = terminal_capture.object_targets([proposal])
            terminal = False
            try:
                runtime.start()
                record["image_id"] = runtime.image_id
                record["phase"] = "reproduce"
                reconstruct(runtime, plan)
                record["skeleton"] = catalog_skeleton.build(runtime, snapshot, [proposal])
                before = engine.collect(runtime)
                before_report = engine.assess(before)
                record.update(before=before, before_assessment=before_report)
                if signature(before, names) != plan["signature"]:
                    raise ContractError("Reconstruction did not preserve configuration provenance")
                if before_report["findings"] != actual["findings"] or blocking_gaps(before):
                    raise ContractError("Reconstruction did not reproduce all scoped findings")
                if (not fixes.prior_holds(proposal, before) or fixes.predicate(proposal, before)
                        or fixes.object_signature(proposal, before) != source_signature):
                    raise ContractError("The stand-in copy does not reproduce the source object")
                baseline = catalog_skeleton.fingerprints(before, record["skeleton"])
                terminal_capture.stage(record, runtime, "before", shots)
                record["phase"] = "apply"
                try:
                    runtime.sql(in_transaction(apply))
                    record["phase"] = "reassess"
                    after = engine.collect(runtime)
                    after_report = engine.assess(after)
                    record.update(after=after, after_assessment=after_report,
                                  health_after_apply=runtime.health())
                    record["functional_checks"] = health_queries(runtime, "AFTER FIX")
                    regressions = [sid for sid, finding in before_report["findings"].items()
                                   if is_regression(finding["status"], after_report["findings"][sid]["status"])
                                   or sid in engine.gapped_settings(after_report["findings"])]
                    record["regressions"] = regressions
                    current = catalog_skeleton.fingerprints(after, record["skeleton"])
                    record["other_objects_changed"] = sorted(k for k in baseline if k != key and current[k] != baseline[k])
                    record["predicate_after_apply"] = bool(fixes.predicate(proposal, after))
                    if blocking_gaps(after):
                        raise RuntimeError("Post-apply collection has gaps")
                    if signature(after, names) != plan["signature"]:
                        raise RuntimeError("An object fix changed configuration settings")
                    if (not record["predicate_after_apply"] or regressions or record["other_objects_changed"]
                            or not record["health_after_apply"] or not record["functional_checks"]["passed"]):
                        raise RuntimeError("Fix failed acceptance: predicate/other objects/regression/health")
                    terminal_capture.stage(record, runtime, "after", shots)
                except Exception as exc:
                    record["apply_or_assessment_error"] = f"{type(exc).__name__}: {exc}"
                    raise
                finally:
                    # Also prove rollback after a failed apply (the transaction left nothing).
                    record["phase_before_rollback"] = record["phase"]
                    record["phase"] = "rollback"
                    runtime.sql(in_transaction(rollback))
                    restored = engine.collect(runtime)
                    restored_report = engine.assess(restored)
                    record.update(rollback=restored, rollback_assessment=restored_report,
                                  health_after_rollback=runtime.health())
                    now = catalog_skeleton.fingerprints(restored, record["skeleton"])
                    record["rollback_verified"] = bool(
                        fixes.object_signature(proposal, restored) == source_signature
                        and fixes.prior_holds(proposal, restored)
                        and all(now[k] == baseline[k] for k in baseline if k != key)
                        and _normalised(now.get(key)) == _normalised(baseline.get(key))
                        and signature(restored, names) == plan["signature"]
                        and restored_report["findings"] == before_report["findings"]
                        and not blocking_gaps(restored)
                        and record["health_after_rollback"])
                    if not record["rollback_verified"]:
                        raise RuntimeError("Exact rollback verification failed")
                    terminal_capture.stage(record, runtime, "rollback", shots)
                record.update(status="VERIFIED", phase="complete")
            except ContractError as exc:
                terminal = True
                record["error"] = str(exc)
            except Exception as exc:
                record["error"] = f"{type(exc).__name__}: {exc}"
            finally:
                terminal_capture.finish(record)
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
        graph.add_conditional_edges("test_fix", lambda state: "end" if state["done"] else "retry",
                                    {"end": END, "retry": "test_fix"})
        state = graph.compile().invoke({"attempts": [], "done": False, "status": "PENDING", "revisions": []},
                                       config={"recursion_limit": 12})
        return {"schema_version": "sandbox-run-v1", "kind": "object", "status": state["status"],
                "snapshot_hash": digest(snapshot), "spec_set_hash": engine.spec_set_hash,
                "spec_hashes": engine.hashes, "collector_hash": engine.collector_hash,
                "policy_profile": engine.policy_pin, "template": self.template.identity(),
                "proposal": copy.deepcopy(proposal), "fix_unit": fix,
                "source_object_signature": source_signature,
                "skeleton": catalog_skeleton.summary(bound["skeleton"]),
                "rendered_apply_sql": "\n".join(apply), "rendered_rollback_sql": "\n".join(rollback),
                "retry_mode": "repeat", "revisions": [], "fix_unit_hash": digest(fix),
                "attempts": state["attempts"], "regression_scope": list(engine.hashes),
                "risk_review": object_risk_review(proposal, self.template.risk_level),
                "limitations": ["PostgreSQL 17; approved per-object fix templates only",
                                "Rehearsed on a stand-in copy: the target object and the roles it needs, "
                                "with no rows, function bodies or real passwords",
                                "The application's use of the object was not rehearsed",
                                "No real-target execution by the sandbox"]}


def object_risk_review(proposal: dict, template_risk=None) -> dict:
    """Risk entry for ordering/bundles: the reviewed proposal risk, raised (never
    lowered) by the approved template's risk level."""
    from .catalog_skeleton import target_key
    ranks = {"low": 0, "medium": 1, "high": 2, "not_assessed": 3}
    risk = proposal.get("risk") if proposal.get("risk") in ranks else "not_assessed"
    if template_risk in ranks and ranks[template_risk] > ranks[risk]:
        risk = template_risk
    return {"spec_id": proposal["spec_id"], "fix_id": proposal["fix_id"], "kind": "object",
            "fix_type": proposal["fix_type"], "title": proposal.get("title"),
            "target": copy.deepcopy(proposal["target"]), "setting": None,
            "object_key": target_key(proposal), "operational_risk": risk,
            "reasoning": proposal.get("explanation"), "dependencies": [],
            "requires": "none", "dba_review_required": True,
            "unknowns": ["The application's use of this object is not reconstructed in the sandbox."],
            "manual_application_checks": ["Exercise the applications that use this object in a controlled test environment."]}
