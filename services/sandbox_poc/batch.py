"""Test each fix, then prove their ordered combination in one disposable sandbox."""

import io
import json
import hashlib
import uuid
import zipfile
from html import escape
from app.services.fix_unit_render import render_action
from app.services.spec_engine.policy import approval_text
from .planning import SANDBOX_LIMITS, recommend_order, fix_scope
from .provenance import reconstruct, reconstruction_plan, signature
from .shared import ContractError, blocking_gaps, digest, is_regression
from .review_bundle import (OBJECT_REHEARSAL_TEXT, PRELOAD_README, TLS_README, build_review_bundle,
                            is_fixture, object_fingerprint)
from .workflow import in_transaction, health_queries, _normalised
from . import catalog_skeleton
from . import history


def _object_fixes():
    from . import object_fixes
    return object_fixes


def request_fix_id(request) -> str:
    """Batch identity: the object fix id, else the setting fix id of the control."""
    fix_id = getattr(request, "object_fix_id", None)
    if fix_id:
        return fix_id
    return "control:" + request.control_id


def _request_matches(request, result) -> bool:
    fix_id = getattr(request, "object_fix_id", None)
    if is_object(result):
        return fix_id == result["fix_unit"]["fix_id"]
    return not fix_id and request.control_id == result["fix_unit"]["spec_id"]


def is_object(result) -> bool:
    return result.get("kind") == "object"


def is_catalog(result) -> bool:
    """W2B: a catalog-linked setting fix (3.2, 5.6, 6.10)."""
    return result.get("kind") == "catalog_setting"


def _catalog_scopes(engine, snapshot, requests) -> dict:
    """control_id -> evidence-derived scope for each catalog-linked request."""
    from . import catalog_fixes as cf
    return {r.control_id: cf.catalog_fix_scope(engine, snapshot, r.control_id) for r in requests
            if not getattr(r, "object_fix_id", None) and cf.is_catalog_fix(engine, r.control_id)}


def _catalog_step(engine, runtime, plan, scope, result, previous, applied_catalog, skeleton, templates, pending):
    """Apply one catalog-linked fix in the combined sandbox and verify it with its catalog check.

    The fix is re-derived from the combined sandbox's own collection (W2B rulings round 3),
    so a later preload fix keeps the libraries an earlier one added: its prior is the
    earlier fix's result, and its rollback restores exactly that list. ``pending`` keeps the
    re-derived rollback before any SQL runs, so a failed step is still rolled back exactly.
    """
    from . import catalog_fixes as cf
    template, list_template = templates
    prior = engine.assess(previous)
    scope = cf.catalog_fix_scope(engine, previous, result["fix_unit"]["spec_id"], prior)
    uses_list = any(c["template"] == cf.LIST_TEMPLATE for c in scope["changes"])
    fix = cf.build_fix(scope, template.version, list_template.version if uses_list else None)
    rendered = cf.rendered_statements(template, scope, list_template if uses_list else None)
    pending[fix["fix_id"]] = {"rollback_sql": cf.rollback_sql(fix), "fix_unit": fix}
    for sql in rendered:
        runtime.sql(sql)
    expected = {n: r["setting"] for n, r in signature(previous, plan["names"])["settings"].items()}
    expected.update({c["param"]: c["expected_value"] for c in fix["changes"]})
    runtime.activate(expected)
    after = engine.collect(runtime)
    report = engine.assess(after)
    regressions = [sid for sid, f in prior["findings"].items()
                   if is_regression(f["status"], report["findings"][sid]["status"])
                   or sid in engine.gapped_settings(report["findings"])]
    regressions += cf.catalog_regressions(engine, prior, report, [c["param"] for c in fix["changes"]], fix["spec_id"])
    checks = cf.functional_checks(runtime, fix, "AFTER COMBINED FIX " + fix["fix_id"])
    passing = [cf.proof(engine, s["spec"], after)["result"] == "PASS" for s in applied_catalog + [scope]]
    tls = cf.tls_evidence(runtime) if scope["tls"] else None
    if (not all(passing) or regressions or blocking_gaps(after) or not checks["passed"] or not runtime.health()
            or (tls is not None and not cf.tls_fixed(tls))
            or (skeleton and catalog_skeleton.fingerprints(after, skeleton)
                != catalog_skeleton.fingerprints(previous, skeleton))):
        raise ContractError("Combined target, regression or functional gate failed")
    step = {"fix_id": fix["fix_id"], "before": previous, "after": after, "assessment": report,
            "functional_checks": checks, "catalog_proof": cf.proof(engine, scope["spec"], after),
            "fix_unit": fix, "rendered_apply_statements": rendered, "rendered_rollback_sql": cf.rollback_sql(fix),
            "chained": fix != result["fix_unit"]}
    if tls is not None:
        step["tls_after"] = tls
    return step


def _catalog_rollback(engine, runtime, plan, scope, result, expected_snapshot, skeleton, pending) -> bool:
    from . import catalog_fixes as cf
    runtime.sql(pending[result["fix_unit"]["fix_id"]]["rollback_sql"])
    runtime.activate({n: r["setting"] for n, r in signature(expected_snapshot, plan["names"])["settings"].items()})
    restored = engine.collect(runtime)
    names = list(dict.fromkeys(result["names"] + [c["param"] for c in pending[result["fix_unit"]["fix_id"]]["fix_unit"]["changes"]]))
    return bool(
        signature(restored, plan["names"]) == signature(expected_snapshot, plan["names"])
        and cf.catalog_signature(restored, names) == cf.catalog_signature(expected_snapshot, names)
        and engine.assess(restored)["findings"] == engine.assess(expected_snapshot)["findings"]
        and cf.proof(engine, scope["spec"], restored) == cf.proof(engine, scope["spec"], expected_snapshot)
        and not blocking_gaps(restored) and runtime.health()
        and _objects_unchanged(skeleton, restored, expected_snapshot))


def object_proposal(engine, snapshot, request) -> dict:
    proposal = _object_fixes().resolve(engine, snapshot, engine.policy_pin, request.object_fix_id)
    if not isinstance(proposal, dict) or proposal.get("fix_id") != request.object_fix_id:
        raise ContractError("Selected object fix is not offered for this evidence")
    return proposal


def _attributes(proposal) -> set:
    """The (object, attribute) pairs one object fix changes."""
    key = catalog_skeleton.target_key(proposal)
    fix_type, target = proposal["fix_type"], proposal["target"]
    if fix_type == "role_connection_limit":
        return {(key, "connection_limit")}
    if fix_type == "role_drop_attribute":
        return {(key, "attribute:" + str(target["attribute"]))}
    if fix_type == "role_nologin":
        return {(key, "login")}
    if fix_type == "function_security_invoker":
        return {(key, "security")}
    if fix_type == "function_revoke_public_execute":
        return {(key, "acl:PUBLIC")}
    if fix_type == "table_revoke_dml":
        # One pair per revoked privilege: INSERT and UPDATE for the same grantee are
        # separate attributes (the engine splits proposals by grant option).
        return {(key, "acl:" + str(target["grantee"]) + ":" + privilege) for privilege in target["privileges"]}
    raise ContractError("Unsupported object fix type")


def object_conflicts(proposals) -> None:
    seen = set()
    for proposal in proposals:
        pairs = _attributes(proposal)
        if pairs & seen:
            raise ContractError("Two selected fixes change the same object attribute")
        seen |= pairs


def _objects_unchanged(skeleton, current, expected, except_key=None) -> bool:
    if not skeleton:
        return True
    now = catalog_skeleton.fingerprints(current, skeleton)
    want = catalog_skeleton.fingerprints(expected, skeleton)
    return all(now[k] == want[k] for k in want if k != except_key) and (
        except_key is None or _normalised(now.get(except_key)) == _normalised(want.get(except_key)))


def _object_step(engine, runtime, fixes, plan, skeleton, result, previous, applied_objects):
    """Apply one object fix (one transaction) in the combined sandbox and verify it."""
    proposal, fix = result["proposal"], result["fix_unit"]
    key = catalog_skeleton.target_key(proposal)
    runtime.sql(in_transaction(fix["apply"]["statements"]))
    after = engine.collect(runtime)
    report = engine.assess(after)
    prior = engine.assess(previous)
    regressions = [sid for sid, f in prior["findings"].items()
                   if is_regression(f["status"], report["findings"][sid]["status"])
                   or sid in engine.gapped_settings(report["findings"])]
    checks = health_queries(runtime, "AFTER COMBINED FIX " + fix["fix_id"])
    before_prints = catalog_skeleton.fingerprints(previous, skeleton)
    after_prints = catalog_skeleton.fingerprints(after, skeleton)
    others = sorted(k for k in before_prints if k != key and after_prints[k] != before_prints[k])
    # Every object fix applied so far still holds (per-object predicates).
    holding = all(fixes.predicate(r["proposal"], after) for r in applied_objects)
    if (not fixes.predicate(proposal, after) or not holding or regressions or others
            or blocking_gaps(after) or not checks["passed"] or not runtime.health()
            or signature(after, plan["names"]) != signature(previous, plan["names"])):
        raise ContractError("Combined target, regression or functional gate failed")
    return {"fix_id": fix["fix_id"], "before": previous, "after": after,
            "assessment": report, "functional_checks": checks}


def _object_rollback(engine, runtime, fixes, plan, skeleton, result, expected_snapshot):
    proposal = result["proposal"]
    runtime.sql(in_transaction(result["fix_unit"]["rollback"]["statements"]))
    restored = engine.collect(runtime)
    return bool(
        fixes.object_signature(proposal, restored) == fixes.object_signature(proposal, expected_snapshot)
        and signature(restored, plan["names"]) == signature(expected_snapshot, plan["names"])
        and engine.assess(restored)["findings"] == engine.assess(expected_snapshot)["findings"]
        and not blocking_gaps(restored)
        and _objects_unchanged(skeleton, restored, expected_snapshot, catalog_skeleton.target_key(proposal))
        and runtime.health())


def run_batch(requests, service, requested_order=None):
    if not 2 <= len(requests) <= 6:
        raise ContractError("Select between two and six distinct fixes")
    first = requests[0]
    if any(
        r.snapshot != first.snapshot or r.spec_set_hash != first.spec_set_hash
        or r.policy_profile_sha256 != first.policy_profile_sha256
        for r in requests
    ):
        raise ContractError("Batch fixes must share the same snapshot, exact specs and policy profile")
    keys = [request_fix_id(r) for r in requests]
    if len(set(keys)) != len(keys):
        raise ContractError("Duplicate fixes in batch")
    engine = service.validate_handoff(first)
    # Object fixes are re-derived from the shared evidence before anything runs, so
    # two fixes on the same object attribute are refused without a container.
    object_conflicts([object_proposal(engine, first.snapshot, r) for r in requests
                      if getattr(r, "object_fix_id", None)])
    scopes = _catalog_scopes(engine, first.snapshot, requests)
    # Approved templates for each catalog fix (the list template for a preload change).
    catalog_templates = {r.control_id: (service.resolve_template(r),
                                        service.resolve_template(r, r.list_template_ref)
                                        if getattr(r, "list_template_ref", None) is not None else None)
                         for r in requests if r.control_id in scopes}
    pending = {}
    results = []
    for r in requests:
        result = service.run(r)
        data = (
            build_review_bundle(r, result, engine)
            if result["status"] == "VERIFIED"
            else None
        )
        history.record(r, result, data)
        results.append(result)
        if result["status"] != "VERIFIED":
            return {
                "status": "FAILED",
                "individual_runs": results,
                "reason": "An individual fix failed; combined execution was not started",
            }, None
    ordered = recommend_order([r["risk_review"] for r in results])
    if requested_order:
        by_id = {f["fix_id"]: f for f in ordered}
        if len(requested_order) != len(ordered) or set(requested_order) != set(by_id):
            raise ContractError("Selected order must contain every fix exactly once")
        seen = set()
        for fid in requested_order:
            if not set(by_id[fid].get("dependencies", [])) <= seen:
                raise ContractError("Selected order violates a prerequisite dependency")
            seen.add(fid)
        ordered = [by_id[fid] for fid in requested_order]
    indexed = {r["fix_unit"]["fix_id"]: r for r in results}
    results = [indexed[f["fix_id"]] for f in ordered]
    runtime = service.runtime_factory()
    from . import catalog_fixes as cf
    extra = [n for scope in scopes.values() for n in cf.reconstruction_names(engine, first.snapshot, scope)]
    plan = (reconstruction_plan(first.snapshot, engine.specs, list(dict.fromkeys(extra))) if extra
            else reconstruction_plan(first.snapshot, engine.specs))
    record = {"status": "FAILED", "steps": [], "rollback": [], "run_id": runtime.run_id}
    applied = []
    objects = [r for r in results if is_object(r)]
    fixes = _object_fixes() if objects else None
    skeleton = None
    baseline = None  # the combined sandbox's own first collection (stand-in included)
    try:
        runtime.start()
        reconstruct(runtime, plan)
        if any(scope["tls"] for scope in scopes.values()):
            cf.enable_sandbox_tls(runtime, plan)
        if objects:
            # One stand-in holding every object target of the batch.
            skeleton = catalog_skeleton.build(runtime, first.snapshot, [r["proposal"] for r in objects])
            record["skeleton"] = skeleton
        before = engine.collect(runtime)
        baseline = before
        if (
            signature(before, plan["names"]) != plan["signature"]
            or engine.assess(before)["findings"]
            != engine.assess(first.snapshot)["findings"]
        ):
            raise ContractError("Combined baseline reproduction differs")
        for result in results:
            if is_catalog(result):
                scope = scopes[result["fix_unit"]["spec_id"]]
                if (cf.proof(engine, scope["spec"], before)["result"] != "FAIL"
                        or cf.catalog_signature(before, result["names"])
                        != cf.catalog_signature(first.snapshot, result["names"])):
                    raise ContractError("Combined baseline does not reproduce " + result["fix_unit"]["fix_id"])
        for result in objects:
            proposal = result["proposal"]
            if (not fixes.prior_holds(proposal, before) or fixes.predicate(proposal, before)
                    or fixes.object_signature(proposal, before) != result["source_object_signature"]):
                raise ContractError("Combined stand-in does not reproduce " + proposal["fix_id"])
        previous = before
        for result in results:
            # Mark before SQL so a partial apply is also rolled back.
            applied.append(result)
            if is_object(result):
                record["steps"].append(_object_step(engine, runtime, fixes, plan, skeleton, result,
                                                    previous, [r for r in applied if is_object(r)]))
                previous = record["steps"][-1]["after"]
                continue
            if is_catalog(result):
                applied_catalog = [scopes[r["fix_unit"]["spec_id"]] for r in applied[:-1] if is_catalog(r)]
                record["steps"].append(_catalog_step(engine, runtime, plan, scopes[result["fix_unit"]["spec_id"]],
                                                     result, previous, applied_catalog, skeleton,
                                                     catalog_templates[result["fix_unit"]["spec_id"]], pending))
                previous = record["steps"][-1]["after"]
                continue
            runtime.sql(result["rendered_apply_sql"])
            expected = {
                n: r["setting"]
                for n, r in signature(previous, plan["names"])["settings"].items()
            }
            expected[result["fix_unit"]["apply"]["param"]] = result["fix_unit"][
                "apply"
            ]["value"]
            runtime.activate(expected)
            after = engine.collect(runtime)
            report = engine.assess(after)
            prior = engine.assess(previous)
            regressions = [
                sid
                for sid, f in prior["findings"].items()
                if is_regression(f["status"], report["findings"][sid]["status"])
            ]
            from .workflow import setting_catalog_regressions
            regressions += setting_catalog_regressions(engine, prior, report, result["fix_unit"]["apply"]["param"],
                                                       result["fix_unit"]["spec_id"])
            from .evidence_capture import verify_runtime

            fix = result["fix_unit"]
            checks = verify_runtime(
                runtime,
                fix["spec_id"],
                fix["apply"]["param"],
                fix["apply"]["value"],
                "AFTER COMBINED FIX " + fix["fix_id"],
            )
            if (
                report["findings"][fix["spec_id"]]["status"] != "PASS"
                or regressions
                or blocking_gaps(after)
                or not checks["passed"]
                or (skeleton and catalog_skeleton.fingerprints(after, skeleton)
                    != catalog_skeleton.fingerprints(previous, skeleton))
            ):
                raise ContractError(
                    "Combined target, regression or functional gate failed"
                )
            record["steps"].append(
                {
                    "fix_id": fix["fix_id"],
                    "before": previous,
                    "after": after,
                    "assessment": report,
                    "functional_checks": checks,
                }
            )
            previous = after
        record["status"] = "VERIFIED"
    except Exception as exc:
        record["reason"] = str(exc)
        record["status"] = "FAILED"
    finally:
        try:
            for result in reversed(applied):
                # Desired baseline is the state immediately before this fix.
                idx = results.index(result)
                expected_snapshot = (
                    record["steps"][idx]["before"]
                    if idx < len(record["steps"])
                    else (
                        record["steps"][-1]["after"]
                        if record["steps"]
                        else (baseline or first.snapshot)
                    )
                )
                if is_object(result):
                    ok = _object_rollback(engine, runtime, fixes, plan, skeleton, result, expected_snapshot)
                    record["rollback"].append({"fix_id": result["fix_unit"]["fix_id"], "verified": ok})
                    if not ok:
                        raise ContractError("Combined exact rollback failed")
                    continue
                if is_catalog(result):
                    if result["fix_unit"]["fix_id"] not in pending:
                        continue  # nothing of this fix ran (it failed while being derived)
                    ok = _catalog_rollback(engine, runtime, plan, scopes[result["fix_unit"]["spec_id"]],
                                           result, expected_snapshot, skeleton, pending)
                    record["rollback"].append({"fix_id": result["fix_unit"]["fix_id"], "verified": ok})
                    if not ok:
                        raise ContractError("Combined exact rollback failed")
                    continue
                runtime.sql(result["rendered_rollback_sql"])
                expected = {
                    n: r["setting"]
                    for n, r in signature(expected_snapshot, plan["names"])[
                        "settings"
                    ].items()
                }
                runtime.activate(expected)
                restored = engine.collect(runtime)
                ok = (
                    signature(restored, plan["names"])
                    == signature(expected_snapshot, plan["names"])
                    and engine.assess(restored)["findings"]
                    == engine.assess(expected_snapshot)["findings"]
                    and runtime.health()
                    and _objects_unchanged(skeleton, restored, expected_snapshot)
                )
                record["rollback"].append(
                    {"fix_id": result["fix_unit"]["fix_id"], "verified": ok}
                )
                if not ok:
                    raise ContractError("Combined exact rollback failed")
        except Exception as exc:
            record.update(status="FAILED", rollback_error=str(exc))
        finally:
            try:
                record["cleanup"] = runtime.close()
            except Exception:
                record["cleanup"] = {"verified": False}
            if not record["cleanup"].get("verified"):
                record["status"] = "CLEANUP_FAILED"
    output = {
        "run_id": str(uuid.uuid4()),
        "status": record["status"],
        "individual_runs": [
            {
                "run_id": r["run_id"],
                "fix_id": r["fix_unit"]["fix_id"],
                "status": r["status"],
            }
            for r in results
        ],
        "order_source": "DBA_SELECTED" if requested_order else "RECOMMENDED",
        "recommended_order": [f["fix_id"] for f in ordered],
        "combined_test": record,
        "risk_reviews": ordered,
        "requires_dba_review": True,
    }
    output.update(
        schema_version="sandbox-batch-v1",
        snapshot_hash=digest(first.snapshot),
        spec_set_hash=engine.spec_set_hash,
        spec_hashes=engine.hashes,
        policy_profile=engine.policy_pin,
        fix_units=[r["fix_unit"] for r in results],
        demo_fixture_approval=any(is_fixture(r) for r in results),
    )
    if record["steps"]:
        output["sandbox_after_findings"] = {
            sid: f["status"]
            for sid, f in record["steps"][-1]["assessment"]["findings"].items()
        }
    if output["status"] != "VERIFIED":
        return output, None
    files = {}
    for result, step in zip(results, record["steps"]):
        handoff = next(r for r in requests if _request_matches(r, result))
        with zipfile.ZipFile(
            io.BytesIO(build_review_bundle(handoff, result, engine))
        ) as z:
            members = {name: z.read(name) for name in z.namelist()}
        config = json.loads(members["fix.json"])
        if is_object(result):
            # The runner's guard expects the preceding fixes to remain applied.
            config["prior"] = object_fingerprint(result["proposal"], step["before"])
            config["applied"] = object_fingerprint(result["proposal"], step["after"])
        elif is_catalog(result):
            if step.get("chained"):
                # Re-derived in the combined order: the list keeps the earlier fix's library.
                chained = step["fix_unit"]
                config["names"] = list(dict.fromkeys(config["names"] + [c["param"] for c in chained["changes"]]))
                config["apply_statements"] = [s for c in chained["changes"] for s in render_action(c["apply"])]
                config["rollback_statements"] = [s + ";" for c in reversed(chained["changes"])
                                                 for s in render_action(c["rollback"])]
                config["preload_added"] = list(chained["preload_added"])
                config["settings"] = [c["param"] for c in chained["changes"]]
                config["combined_order_fix_unit"] = chained
                note = ("<h2>Combined order</h2><p class=\"notice\">In this batch the fix was re-derived from "
                        "the state the preceding fixes leave, so its SQL differs from the isolated test above. "
                        "harden.sh runs this SQL:</p><pre>" + escape("\n".join(step["rendered_apply_statements"]))
                        + "</pre><p>Rollback:</p><pre>" + escape(step["rendered_rollback_sql"]) + "</pre></body>")
                members["report.html"] = members["report.html"].decode().replace("</body>", note, 1).encode()
            config["prior"] = cf.catalog_signature(step["before"], config["names"])
            config["applied"] = cf.catalog_signature(step["after"], config["names"])
        else:
            # The setting bundle's own scoped names (review_bundle: the setting specs), which
            # the runner fingerprints; plan["names"] also holds any catalog-fix settings.
            names = [sp["check"]["setting_name"] for sp in engine.specs
                     if "check" in sp and sp["check"].get("kind") != "catalog"]
            config["prior"] = signature(step["before"], names)
            config["applied"] = signature(step["after"], names)
        config["combined_run_id"] = output["run_id"]
        members["fix.json"] = json.dumps(config, indent=2).encode()
        manifest = json.loads(members["manifest.json"])
        manifest["files"]["fix.json"] = hashlib.sha256(members["fix.json"]).hexdigest()
        if is_catalog(result) and step.get("chained"):
            manifest["files"]["report.html"] = hashlib.sha256(members["report.html"]).hexdigest()
        members["manifest.json"] = json.dumps(manifest, indent=2).encode()
        prefix = result["fix_unit"]["fix_id"] + "/"
        files.update({prefix + k: v for k, v in members.items()})
    files["combined-evidence.json"] = json.dumps(output, indent=2).encode()
    # The per-fix files carry the scope line; repeat it on the combined front page.
    scope = ("DEMO FIXTURE APPROVAL — not human approval\n" if output.get("demo_fixture_approval")
             else "")
    files["README.txt"] = (
        scope + "All selected fixes passed individually and together in one disposable sandbox.\nApply one complete fix at a time in this order: "
        + ", ".join(output["recommended_order"])
        + "\n" + approval_text(engine.policy_pin)
        + "\nVerify each before proceeding. Roll back in REVERSE order.\nThe per-fix guard expects the preceding fixes to remain applied. If a DBA chooses another order, create and test a new batch.\nIndividual report.html files show isolated tests; combined-evidence.json records the combined states.\nTarget changes have NOT been performed.\n"
        + "".join(f"\nSANDBOX LIMIT ({f['fix_id']}): {SANDBOX_LIMITS[f['setting']]}\n"
                  for f in ordered if f.get("setting") in SANDBOX_LIMITS)
        + (OBJECT_REHEARSAL_TEXT if objects else "")
        + "".join(PRELOAD_README.format(libs=", ".join(r["fix_unit"]["preload_added"]))
                  for r in results if is_catalog(r) and r["fix_unit"]["preload_added"])
        + (TLS_README if any(scope["tls"] for scope in scopes.values()) else "")
    ).encode()
    files["report.html"] = (
        "<!doctype html><html><body><h1>Combined DBA review</h1>"
        + (f"<p>{escape(scope.strip())}</p>" if scope else "")
        + "<p>Sandbox verified. Target application NOT PERFORMED.</p><p>"
        + escape(approval_text(engine.policy_pin))
        + "</p><ol>"
        + "".join(
            '<li><a href="'
            + f["fix_id"]
            + '/report.html">'
            + f["fix_id"]
            + "</a> — "
            + f["operational_risk"]
            + "</li>"
            for f in ordered
        )
        + "</ol><p>Apply one fix at a time; verify each. Rollback must follow reverse order. Review combined-evidence.json for combined test evidence.</p></body></html>"
    ).encode()
    data = io.BytesIO()
    with zipfile.ZipFile(data, "w", zipfile.ZIP_DEFLATED) as z:
        for name, content in files.items():
            z.writestr(name, content)
    return output, data.getvalue()
