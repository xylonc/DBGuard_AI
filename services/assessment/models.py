"""Typed, serializable assessment inputs and outputs."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, model_validator


class AssessmentSuite(str, Enum):
    """The two independent reasons DBGuard assesses a hardened twin."""

    BASELINE = "baseline"
    REQUIREMENT = "requirement"


class AssessmentStatus(str, Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    UNKNOWN = "UNKNOWN"
    ERROR = "ERROR"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    PENDING_HUMAN_EVIDENCE = "PENDING_HUMAN_EVIDENCE"


class BaselineCatalogStatus(str, Enum):
    """Whether the complete, approved baseline is available for assessment."""

    READY = "READY"
    NOT_READY = "NOT_READY"


class EvidenceType(str, Enum):
    QUERY_OUTPUT = "query_output"
    COMMAND_OUTPUT = "command_output"
    CONFIGURATION_EXCERPT = "configuration_excerpt"
    SCREENSHOT = "screenshot"


class ObservationState(str, Enum):
    OBSERVED = "observed"
    UNKNOWN = "unknown"
    ERROR = "error"


class EvidenceReference(BaseModel):
    """Reference to immutable evidence captured by a future twin executor."""

    model_config = ConfigDict(extra="forbid")

    evidence_id: str = Field(min_length=1, max_length=255)
    evidence_type: EvidenceType
    description: str = Field(min_length=1, max_length=1000)


class CheckObservation(BaseModel):
    """Executor observation before it is compared with the expected outcome."""

    model_config = ConfigDict(extra="forbid")

    state: ObservationState
    observed_value: bool | None = None
    detail: str = Field(min_length=1, max_length=4000)
    evidence: list[EvidenceReference] = Field(default_factory=list)

    @model_validator(mode="after")
    def state_matches_value(self):
        if self.state == ObservationState.OBSERVED and self.observed_value is None:
            raise ValueError("observed_value is required for an observed check")
        if self.state != ObservationState.OBSERVED and self.observed_value is not None:
            raise ValueError("unknown or errored checks cannot carry an observed_value")
        return self


class AssessmentCriterion(BaseModel):
    """A fixed, allowlisted check; it is never supplied by HERMES."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    criterion_id: str = Field(min_length=1, max_length=128)
    title: str = Field(min_length=1, max_length=512)
    suite: AssessmentSuite
    verifier_id: str = Field(min_length=1, max_length=128)
    expected_value: bool
    evidence_types: tuple[EvidenceType, ...]
    remediation_template_name: str | None = None
    remediation_template_version: int | None = Field(default=None, ge=1)
    reconcile_on_failure: bool = True

    @model_validator(mode="after")
    def remediation_version_requires_template(self):
        if self.remediation_template_version is not None and self.remediation_template_name is None:
            raise ValueError("remediation template version requires a template name")
        if not self.evidence_types:
            raise ValueError("at least one evidence type is required")
        return self


class AssessmentResult(BaseModel):
    """Normalized result consumed by reporting and future reconciliation."""

    model_config = ConfigDict(extra="forbid")

    criterion_id: str
    title: str
    suite: AssessmentSuite
    verifier_id: str
    status: AssessmentStatus
    expected_value: bool
    observed_value: bool | None = None
    detail: str
    evidence: list[EvidenceReference] = Field(default_factory=list)
    remediation_template_name: str | None = None
    remediation_template_version: int | None = None
    reconcile_on_failure: bool = True


class TemplateAssessmentReport(BaseModel):
    """Assessment of one compiled template application in a twin iteration."""

    model_config = ConfigDict(extra="forbid")

    template_name: str
    template_version: int = Field(ge=1)
    iteration: int = Field(ge=1, le=3)
    parameters: dict[str, Any]
    baseline_catalog_status: BaselineCatalogStatus
    suite_status: dict[AssessmentSuite, AssessmentStatus]
    overall_status: AssessmentStatus
    results: list[AssessmentResult]
