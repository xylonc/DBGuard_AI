"""Read-only preflight. Readiness is not proof of sandbox execution or approval."""
from .review_bundle import canonical_apply, is_fixture
from .shared import ContractError, digest


def check_readiness(service, handoff, *, check_registry=False, allow_demo_fixtures=False):
    report = {
        "schema_version": "sandbox-readiness-v1",
        "status": "BLOCKED",
        "handoff": "NOT_CHECKED", "registry": "NOT_CHECKED",
        "sandbox_execution": "NOT_RUN",
        "ready_for_sandbox": False,
        "issues": [],
    }
    try:
        engine = service.validate_handoff(handoff)
    except ContractError as exc:
        report["handoff"] = "INVALID"
        report["issues"].append(str(exc))
        return report
    report.update(handoff="VALID", benchmark_id=handoff.benchmark_id,
                  snapshot_hash=digest(handoff.snapshot), spec_set_hash=engine.spec_set_hash,
                  findings=engine.bind_assessment(handoff.snapshot, handoff.assessment)["findings"])
    if handoff.retry_mode == 'adaptive' and service.reviser is None:
        report['issues'].append('Adaptive retries require a configured sandbox LLM reviewer')
        return report
    if not check_registry:
        report["status"] = "INPUT_VALID"
        return report
    try:
        template = service.resolve_template(handoff)
        # Confirm that the approved template fits this narrowly supported fix.
        canonical_apply(template.render())
        alternatives = [service.resolve_template(handoff, ref) for ref in handoff.retry_template_refs]
        if not allow_demo_fixtures and any(is_fixture({'template': alternative.identity()}) for alternative in alternatives):
            raise ContractError('Alternative candidates include demo/test approvals')
    except ContractError as exc:
        report["registry"] = "REJECTED"
        report["issues"].append(str(exc))
        return report
    except Exception:
        # Driver exceptions can expose connection strings or credentials.
        report["registry"] = "UNAVAILABLE"
        report["issues"].append("Registry lookup failed; check connectivity and SELECT permissions")
        return report
    report["template"] = template.identity()
    if is_fixture({"template": template.identity()}):
        report["registry"] = "FIXTURE_ONLY"
        if allow_demo_fixtures:
            report.update(status="READY_FOR_DEMO", ready_for_sandbox=True,
                          demo_fixture_approval=True,
                          approval_notice="DEMO_FIXTURE_ONLY; not human approval")
            return report
        report["issues"].append("Demo/test approvals cannot establish team-handoff readiness")
        return report
    report.update(status="READY_FOR_SANDBOX", registry="PINS_VERIFIED", ready_for_sandbox=True)
    return report
