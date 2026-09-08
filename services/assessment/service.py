"""Evaluate allowlisted criteria using an injected, restricted executor."""

from __future__ import annotations

from typing import Any, Protocol

from services.assessment.models import (
    AssessmentCriterion,
    AssessmentResult,
    AssessmentStatus,
    AssessmentSuite,
    BaselineCatalogStatus,
    CheckObservation,
    ObservationState,
    TemplateAssessmentReport,
)
from services.assessment.registry import (
    get_assessment_definition,
    get_baseline_catalog_status,
)


class AssessmentExecutor(Protocol):
    """Boundary a future twin adapter must implement.

    Only verifier IDs selected from the internal registry reach this boundary.
    The executor, not HERMES, owns the corresponding SQL or behavioural test.
    """

    def run_check(
        self,
        verifier_id: str,
        parameters: dict[str, Any],
    ) -> CheckObservation:
        ...


class AssessmentService:
    """Run one template's deterministic assessment definition."""

    def assess_template(
        self,
        template_name: str,
        template_version: int,
        parameters: dict[str, Any],
        executor: AssessmentExecutor,
        iteration: int = 1,
    ) -> TemplateAssessmentReport:
        if iteration < 1 or iteration > 3:
            raise ValueError("iteration must be between 1 and 3")

        definition = get_assessment_definition(template_name, template_version)
        validated = definition.validate_parameters(parameters)
        safe_parameters = validated.model_dump()
        results = [
            self._run_criterion(criterion, safe_parameters, executor)
            for criterion in definition.criteria
        ]
        suite_status = {
            suite: self._aggregate([result.status for result in results if result.suite == suite])
            for suite in AssessmentSuite
            if any(result.suite == suite for result in results)
        }
        baseline_catalog_status = get_baseline_catalog_status()
        overall_status = self._aggregate([result.status for result in results])
        if (
            overall_status == AssessmentStatus.PASS
            and baseline_catalog_status != BaselineCatalogStatus.READY
        ):
            overall_status = AssessmentStatus.UNKNOWN

        return TemplateAssessmentReport(
            template_name=definition.template_name,
            template_version=definition.template_version,
            iteration=iteration,
            parameters=safe_parameters,
            baseline_catalog_status=baseline_catalog_status,
            suite_status=suite_status,
            overall_status=overall_status,
            results=results,
        )

    def _run_criterion(
        self,
        criterion: AssessmentCriterion,
        parameters: dict[str, Any],
        executor: AssessmentExecutor,
    ) -> AssessmentResult:
        try:
            observation = executor.run_check(criterion.verifier_id, parameters)
        except Exception as exc:
            observation = CheckObservation(
                state=ObservationState.ERROR,
                detail=f"Verifier execution failed: {exc}",
            )

        if observation.state == ObservationState.ERROR:
            status = AssessmentStatus.ERROR
        elif observation.state == ObservationState.UNKNOWN:
            status = AssessmentStatus.UNKNOWN
        elif not observation.evidence:
            status = AssessmentStatus.UNKNOWN
            observation = observation.model_copy(
                update={"detail": f"{observation.detail} Evidence was not captured."}
            )
        elif missing_evidence_types := [
            evidence_type
            for evidence_type in criterion.evidence_types
            if evidence_type not in {item.evidence_type for item in observation.evidence}
        ]:
            status = AssessmentStatus.UNKNOWN
            missing = ", ".join(item.value for item in missing_evidence_types)
            observation = observation.model_copy(
                update={
                    "detail": (
                        f"{observation.detail} Required evidence was not captured: {missing}."
                    )
                }
            )
        elif observation.observed_value == criterion.expected_value:
            status = AssessmentStatus.PASS
        else:
            status = AssessmentStatus.FAIL

        return AssessmentResult(
            criterion_id=criterion.criterion_id,
            title=criterion.title,
            suite=criterion.suite,
            verifier_id=criterion.verifier_id,
            status=status,
            expected_value=criterion.expected_value,
            observed_value=observation.observed_value,
            detail=observation.detail,
            evidence=observation.evidence,
            remediation_template_name=criterion.remediation_template_name,
            remediation_template_version=criterion.remediation_template_version,
            reconcile_on_failure=criterion.reconcile_on_failure,
        )

    @staticmethod
    def _aggregate(statuses: list[AssessmentStatus]) -> AssessmentStatus:
        if not statuses:
            return AssessmentStatus.UNKNOWN
        precedence = (
            AssessmentStatus.ERROR,
            AssessmentStatus.FAIL,
            AssessmentStatus.UNKNOWN,
            AssessmentStatus.PENDING_HUMAN_EVIDENCE,
        )
        for status in precedence:
            if status in statuses:
                return status
        if all(status == AssessmentStatus.NOT_APPLICABLE for status in statuses):
            return AssessmentStatus.NOT_APPLICABLE
        return AssessmentStatus.PASS
