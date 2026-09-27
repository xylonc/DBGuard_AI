"""Test each fix, then prove their ordered combination in one disposable sandbox."""

import io
import json
import hashlib
import uuid
import zipfile
from .planning import recommend_order, fix_scope
from .provenance import reconstruct, reconstruction_plan, signature
from .shared import ContractError, digest
from .review_bundle import build_review_bundle, is_fixture
from . import history


def run_batch(requests, service, requested_order=None):
    if not 2 <= len(requests) <= 6:
        raise ContractError("Select between two and six distinct fixes")
    first = requests[0]
    if any(
        r.snapshot != first.snapshot or r.spec_set_hash != first.spec_set_hash
        for r in requests
    ):
        raise ContractError("Batch fixes must share the same snapshot and exact specs")
    controls = [r.control_id for r in requests]
    if len(set(controls)) != len(controls):
        raise ContractError("Duplicate controls in batch")
    engine = service.validate_handoff(first)
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
    plan = reconstruction_plan(first.snapshot, engine.specs)
    record = {"status": "FAILED", "steps": [], "rollback": [], "run_id": runtime.run_id}
    applied = []
    try:
        runtime.start()
        reconstruct(runtime, plan)
        before = engine.collect(runtime)
        if (
            signature(before, plan["names"]) != plan["signature"]
            or engine.assess(before)["findings"]
            != engine.assess(first.snapshot)["findings"]
        ):
            raise ContractError("Combined baseline reproduction differs")
        previous = before
        for result in results:
            # Mark before SQL so a partial apply is also rolled back.
            applied.append(result)
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
                if f["status"] == "PASS" and report["findings"][sid]["status"] != "PASS"
            ]
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
                or after["baseline"].get("gaps")
                or not checks["passed"]
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
                runtime.sql(result["rendered_rollback_sql"])
                # Desired baseline is the state immediately before this fix.
                idx = results.index(result)
                expected_snapshot = (
                    record["steps"][idx]["before"]
                    if idx < len(record["steps"])
                    else (
                        record["steps"][-1]["after"]
                        if record["steps"]
                        else first.snapshot
                    )
                )
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
        handoff = next(
            r for r in requests if r.control_id == result["fix_unit"]["spec_id"]
        )
        with zipfile.ZipFile(
            io.BytesIO(build_review_bundle(handoff, result, engine))
        ) as z:
            members = {name: z.read(name) for name in z.namelist()}
        config = json.loads(members["fix.json"])
        config["prior"] = signature(step["before"], plan["names"])
        config["applied"] = signature(step["after"], plan["names"])
        config["combined_run_id"] = output["run_id"]
        members["fix.json"] = json.dumps(config, indent=2).encode()
        manifest = json.loads(members["manifest.json"])
        manifest["files"]["fix.json"] = hashlib.sha256(members["fix.json"]).hexdigest()
        members["manifest.json"] = json.dumps(manifest, indent=2).encode()
        prefix = result["fix_unit"]["fix_id"] + "/"
        files.update({prefix + k: v for k, v in members.items()})
    files["combined-evidence.json"] = json.dumps(output, indent=2).encode()
    files["README.txt"] = (
        "All selected fixes passed individually and together in one disposable sandbox.\nApply one complete fix at a time in this order: "
        + ", ".join(output["recommended_order"])
        + "\nVerify each before proceeding. Roll back in REVERSE order.\nThe per-fix guard expects the preceding fixes to remain applied. If a DBA chooses another order, create and test a new batch.\nIndividual report.html files show isolated tests; combined-evidence.json records the combined states.\nTarget changes have NOT been performed.\n"
    ).encode()
    files["report.html"] = (
        "<!doctype html><html><body><h1>Combined DBA review</h1><p>Sandbox verified. Target application NOT PERFORMED.</p><ol>"
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
