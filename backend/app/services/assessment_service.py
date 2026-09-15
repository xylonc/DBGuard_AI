"""Offline ASSESS evaluation service.

This module implements the assessment engine that evaluates snapshot JSON files
against control definitions. The engine is purely OFFLINE - it never connects
to a target database or runs live queries.

Usage:
    from catalog.controls.assess.registry import CONTROL_REGISTRY
    from app.services.assessment_service import AssessmentService

    service = AssessmentService(CONTROL_REGISTRY)
    report = service.evaluate("snap-abc123")

ABSENT vs. EMPTY invariant:
- [] = collected and empty (verified absence of data)
- null with a matching entry in gaps = could not collect (unknown evidence)
A gapped control MUST evaluate to GAPPED / MANUAL_REVIEW, NEVER a false PASS.
"""

from typing import Any

from app.models import (
    AssessmentReport,
    AssessmentSummary,
    Finding,
    FindingStatus,
)
from catalog.controls.assess.registry import ControlDefinition


class AssessmentService:
    """Offline assessment engine for evaluating controls against snapshot data."""

    def __init__(self, control_registry: dict[str, ControlDefinition]):
        """
        Initialize the assessment service.

        Args:
            control_registry: Dict mapping control IDs to their definitions.
        """
        self.control_registry = control_registry

    def evaluate(self, snapshot: dict[str, Any]) -> AssessmentReport:
        """
        Evaluate all controls against a snapshot and generate a report.

        Args:
            snapshot: Normalized snapshot dictionary from collector bundle.

        Returns:
            AssessmentReport containing all findings and summary counts.
        """
        findings: list[Finding] = []
        pass_count = 0
        fail_count = 0
        gapped_count = 0
        manual_review_count = 0

        for control_id, control in self.control_registry.items():
            finding = control.evaluate(snapshot)
            findings.append(finding)

            # Count by status
            if finding.status == FindingStatus.PASS:
                pass_count += 1
            elif finding.status == FindingStatus.FAIL:
                fail_count += 1
            elif finding.status == FindingStatus.GAPPED:
                gapped_count += 1
            elif finding.status == FindingStatus.MANUAL_REVIEW:
                manual_review_count += 1

        total = len(findings)
        summary = AssessmentSummary(
            total=total,
            pass_count=pass_count,
            fail_count=fail_count,
            gapped_count=gapped_count,
            manual_review_count=manual_review_count,
        )

        return AssessmentReport(
            snapshot_id=snapshot.get("snapshot_id", "unknown"),
            findings=findings,
            summary=summary,
        )

    def evaluate_control(
        self, snapshot: dict[str, Any], control_id: str
    ) -> Finding:
        """
        Evaluate a single control against a snapshot.

        Args:
            snapshot: Normalized snapshot dictionary.
            control_id: ID of the control to evaluate.

        Returns:
            Finding for the specified control.

        Raises:
            ValueError: If control_id is not found in registry.
        """
        if control_id not in self.control_registry:
            raise ValueError(f"Unknown control ID: {control_id}")

        control = self.control_registry[control_id]
        return control.evaluate(snapshot)
