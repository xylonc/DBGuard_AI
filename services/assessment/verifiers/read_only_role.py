"""Validated parameters and allowlisted checks for the read-only-role template."""

from pydantic import field_validator

from services.assessment.definition import (
    AssessmentParameters,
    validate_postgresql_identifier,
)


class ReadOnlyRoleParameters(AssessmentParameters):
    role_name: str
    database_name: str
    schema_name: str = "public"

    @field_validator("role_name", "database_name", "schema_name")
    @classmethod
    def identifiers_are_lossless(cls, value: str) -> str:
        return validate_postgresql_identifier(value)


# The future PostgreSQL executor must provide reviewed implementations for
# exactly these IDs. Catalogue content cannot add executable behaviour.
READ_ONLY_ROLE_VERIFIER_IDS = frozenset(
    {
        "role_exists",
        "role_can_connect_database",
        "role_has_schema_usage",
        "role_can_select_existing_probe_table",
        "role_can_select_future_probe_table",
        "role_can_insert_probe_table",
        "role_can_update_probe_table",
        "role_can_delete_probe_table",
        "role_can_truncate_probe_table",
        "role_can_create_in_schema",
        "role_is_superuser",
        "role_can_create_database",
        "role_can_create_role",
    }
)
