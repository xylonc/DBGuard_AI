"""Validated parameters and allowlisted checks for PUBLIC-schema revocation."""

from pydantic import field_validator

from services.assessment.definition import (
    AssessmentParameters,
    validate_postgresql_identifier,
)


class RevokePublicAccessParameters(AssessmentParameters):
    schema_name: str = "public"

    @field_validator("schema_name")
    @classmethod
    def identifier_is_lossless(cls, value: str) -> str:
        return validate_postgresql_identifier(value)


REVOKE_PUBLIC_ACCESS_VERIFIER_IDS = frozenset(
    {
        "public_has_schema_create",
        "public_has_schema_usage",
        "schema_owner_has_schema_usage",
    }
)
