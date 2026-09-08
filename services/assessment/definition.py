"""Internal definition type shared by the assessment registry and verifiers."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from pydantic import BaseModel, ConfigDict

from services.assessment.models import AssessmentCriterion


class AssessmentParameters(BaseModel):
    """Base class for tightly validated verifier parameters."""

    model_config = ConfigDict(extra="forbid")


def validate_postgresql_identifier(value: str) -> str:
    """Reject identifiers PostgreSQL would truncate or cannot represent safely."""
    if not value or "\x00" in value:
        raise ValueError("PostgreSQL identifiers must be non-empty and contain no NUL bytes")
    if len(value.encode("utf-8")) > 63:
        raise ValueError("PostgreSQL identifiers must be at most 63 UTF-8 bytes")
    return value


@dataclass(frozen=True)
class TemplateAssessmentDefinition:
    """Allowlisted assessment definition tied to one template name."""

    template_name: str
    template_version: int
    parameter_model: type[AssessmentParameters]
    criteria: tuple[AssessmentCriterion, ...]

    def validate_parameters(self, parameters: dict[str, Any]) -> AssessmentParameters:
        """Return a typed parameter set and reject all unknown fields."""
        return self.parameter_model.model_validate(parameters)
