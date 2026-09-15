"""Control catalog for ASSESS evaluation engine.

This directory contains structured control definitions used by the offline
ASSESS evaluation engine. Each control defines:

- Metadata (ID, CIS title, description, severity)
- Rule evaluation function operating on normalized snapshot JSON
- Default TypedAction template generated upon failure

The ASSESS engine is purely OFFLINE. It evaluates snapshot JSON files stored
in DBGuard. It never connects to a target database or runs live queries.

ABSENT vs. EMPTY invariant:
- [] = collected and empty (verified absence of data)
- null with a matching entry in gaps = could not collect (unknown evidence)
A gapped control MUST evaluate to GAPPED / MANUAL_REVIEW, NEVER a false PASS.
"""

from typing import Any, Callable, Optional

from app.models import (
    AnyTypedAction,
    Finding,
    FindingStatus,
    ManualProcedureAction,
    RevokeSchemaPrivilegeAction,
    SetConfigParameterAction,
)


# ============================================================================
# Control Registry
# ============================================================================

ControlRule = Callable[[dict[str, Any]], Finding]


class ControlDefinition:
    """Definition of a single assessment control."""

    def __init__(
        self,
        control_id: str,
        cis_title: str,
        description: str,
        severity: str,
        rule_func: ControlRule,
        default_action: Optional[AnyTypedAction] = None,
        is_automatable: bool = True,
    ):
        self.control_id = control_id
        self.cis_title = cis_title
        self.description = description
        self.severity = severity
        self.rule_func = rule_func
        self.default_action = default_action
        self.is_automatable = is_automatable

    def evaluate(self, snapshot: dict[str, Any]) -> Finding:
        """Evaluate this control against a normalized snapshot."""
        return self.rule_func(snapshot)


# ============================================================================
# Control Implementations
# ============================================================================

def _build_control_registry() -> dict[str, ControlDefinition]:
    """Build the control registry with all implemented controls."""

    registry: dict[str, ControlDefinition] = {}

    # --------------------------------------------------------------------------
    # CIS-3.1.2: log_connections parameter state
    # --------------------------------------------------------------------------
    # Type: Fully Automatable SQL Parameter
    # Pass condition: pg_settings where name = 'log_connections' has setting = 'on'
    # Target Typed Action: SET_CONFIG_PARAMETER (name: "log_connections", value: "on")
    # --------------------------------------------------------------------------
    def _check_log_connections(snapshot: dict[str, Any]) -> Finding:
        """Check if log_connections is enabled."""
        settings = snapshot.get("settings", [])
        if settings is None:
            return Finding(
                control_id="CIS-3.1.2",
                status=FindingStatus.GAPPED,
                title="Ensure log_connections is enabled",
                rationale="Collector could not retrieve settings (settings section is null)",
                evidence_found=None,
                typed_action=None,
                is_gapped=True,
                severity="2B",
            )

        log_conn_setting = None
        for item in settings:
            if isinstance(item, dict) and item.get("name") == "log_connections":
                log_conn_setting = item.get("setting")
                break

        if log_conn_setting is None:
            # Settings is a list but log_connections not present
            return Finding(
                control_id="CIS-3.1.2",
                status=FindingStatus.PASS,
                title="Ensure log_connections is enabled",
                rationale="log_connections is not present in settings (defaults to off but not required to be on)",
                evidence_found={"log_connections": None},
                typed_action=None,
                is_gapped=False,
                severity="2B",
            )

        if log_conn_setting.lower() == "on":
            return Finding(
                control_id="CIS-3.1.2",
                status=FindingStatus.PASS,
                title="Ensure log_connections is enabled",
                rationale=f"log_connections is set to '{log_conn_setting}'",
                evidence_found={"log_connections": log_conn_setting},
                typed_action=None,
                is_gapped=False,
                severity="2B",
            )
        else:
            return Finding(
                control_id="CIS-3.1.2",
                status=FindingStatus.FAIL,
                title="Ensure log_connections is enabled",
                rationale=f"log_connections is set to '{log_conn_setting}', should be 'on'",
                evidence_found={"log_connections": log_conn_setting},
                typed_action=SetConfigParameterAction(
                    name="log_connections",
                    value="on",
                    description="Enable connection logging for security auditing",
                ),
                is_gapped=False,
                severity="2B",
            )

    registry["CIS-3.1.2"] = ControlDefinition(
        control_id="CIS-3.1.2",
        cis_title="3.1.2 Ensure log_connections is enabled",
        description="Enable logging of connection attempts for security auditing purposes.",
        severity="2B",
        rule_func=_check_log_connections,
        default_action=SetConfigParameterAction(
            name="log_connections",
            value="on",
            description="Enable connection logging for security auditing",
        ),
        is_automatable=True,
    )

    # --------------------------------------------------------------------------
    # CIS-4.1.1: Revoke PUBLIC schema CREATE grant
    # --------------------------------------------------------------------------
    # Type: Fully Automatable SQL Privilege
    # Pass condition: has_schema_privilege('public', 'public', 'CREATE') is false
    # Target Typed Action: REVOKE_SCHEMA_PRIVILEGE (schema: "public", privilege: "CREATE", grantee: "PUBLIC")
    # --------------------------------------------------------------------------
    def _check_public_schema_create(snapshot: dict[str, Any]) -> Finding:
        """Check if PUBLIC has CREATE privilege on public schema."""
        schemas = snapshot.get("schemas", [])
        if schemas is None:
            return Finding(
                control_id="CIS-4.1.1",
                status=FindingStatus.GAPPED,
                title="Ensure PUBLIC schema CREATE privilege is revoked",
                rationale="Collector could not retrieve schema information (schemas section is null)",
                evidence_found=None,
                typed_action=None,
                is_gapped=True,
                severity="2A",
            )

        # Look for public schema entry
        for schema in schemas:
            if isinstance(schema, dict) and schema.get("nspname") == "public":
                public_has_create = schema.get("public_has_create", False)
                if public_has_create:
                    return Finding(
                        control_id="CIS-4.1.1",
                        status=FindingStatus.FAIL,
                        title="Ensure PUBLIC schema CREATE privilege is revoked",
                        rationale="PUBLIC has CREATE privilege on public schema",
                        evidence_found={"public_has_create": True, "schema": "public"},
                        typed_action=RevokeSchemaPrivilegeAction(
                            schema_name="public",
                            privilege="CREATE",
                            grantee="PUBLIC",
                            description="Revoke CREATE privilege on public schema from PUBLIC role",
                        ),
                        is_gapped=False,
                        severity="2A",
                    )
                else:
                    return Finding(
                        control_id="CIS-4.1.1",
                        status=FindingStatus.PASS,
                        title="Ensure PUBLIC schema CREATE privilege is revoked",
                        rationale="PUBLIC does not have CREATE privilege on public schema",
                        evidence_found={"public_has_create": False, "schema": "public"},
                        typed_action=None,
                        is_gapped=False,
                        severity="2A",
                    )

        # Schema not found - this shouldn't happen for 'public' schema
        # But if it does, we should flag as FAIL with no data
        return Finding(
            control_id="CIS-4.1.1",
            status=FindingStatus.FAIL,
            title="Ensure PUBLIC schema CREATE privilege is revoked",
            rationale="Could not determine PUBLIC schema privileges (schema entry missing)",
            evidence_found=None,
            typed_action=RevokeSchemaPrivilegeAction(
                schema_name="public",
                privilege="CREATE",
                grantee="PUBLIC",
                description="Revoke CREATE privilege on public schema from PUBLIC role",
            ),
            is_gapped=False,
            severity="2A",
        )

    registry["CIS-4.1.1"] = ControlDefinition(
        control_id="CIS-4.1.1",
        cis_title="4.1.1 Revoke PUBLIC schema CREATE privilege",
        description="Revoke the CREATE privilege on the public schema from the PUBLIC role.",
        severity="2A",
        rule_func=_check_public_schema_create,
        default_action=RevokeSchemaPrivilegeAction(
            schema_name="public",
            privilege="CREATE",
            grantee="PUBLIC",
            description="Revoke CREATE privilege on public schema from PUBLIC role",
        ),
        is_automatable=True,
    )

    # --------------------------------------------------------------------------
    # CIS-2.1: Migrate md5 passwords to scram-sha-256
    # --------------------------------------------------------------------------
    # Type: Non-SQL / Operational Migration
    # Pass condition: pg_authid.rolpassword matching 'md5%' count == 0
    # Target Typed Action: MANUAL_PROCEDURE (steps: ["Set password_encryption='scram-sha-256'", "Rotate user credentials", "Update app configs"])
    # --------------------------------------------------------------------------
    def _check_password_encryption(snapshot: dict[str, Any]) -> Finding:
        """Check if any users still use MD5 password encryption."""
        password_types = snapshot.get("password_types", [])
        gaps = snapshot.get("gaps", [])

        # Check if password_types section is gapped
        if password_types is None:
            for gap in gaps:
                if isinstance(gap, dict) and gap.get("section") == "password_types":
                    return Finding(
                        control_id="CIS-2.1",
                        status=FindingStatus.MANUAL_REVIEW,
                        title="Ensure password encryption uses SCRAM-SHA-256",
                        rationale=(
                            f"Collector could not retrieve password types "
                            f"(gap: {gap.get('reason', 'unknown')})"
                        ),
                        evidence_found=None,
                        typed_action=ManualProcedureAction(
                            steps=[
                                "Set password_encryption='scram-sha-256' in postgresql.conf",
                                "Rotate all user credentials with new passwords",
                                "Update application connection strings to support SCRAM",
                                "Verify client driver compatibility",
                            ],
                            description="Migrate password encryption from MD5 to SCRAM-SHA-256",
                        ),
                        is_gapped=True,
                        severity="1",
                    )
            # No matching gap found but still null
            return Finding(
                control_id="CIS-2.1",
                status=FindingStatus.MANUAL_REVIEW,
                title="Ensure password encryption uses SCRAM-SHA-256",
                rationale="Collector could not retrieve password types (section unavailable without gap record)",
                evidence_found=None,
                typed_action=ManualProcedureAction(
                    steps=[
                        "Set password_encryption='scram-sha-256' in postgresql.conf",
                        "Rotate all user credentials with new passwords",
                        "Update application connection strings to support SCRAM",
                        "Verify client driver compatibility",
                    ],
                    description="Migrate password encryption from MD5 to SCRAM-SHA-256",
                ),
                is_gapped=False,
                severity="1",
            )

        # Count MD5 password entries
        md5_count = 0
        for entry in password_types:
            if isinstance(entry, dict):
                password_type = entry.get("password_type", "")
                if password_type == "md5":
                    md5_count += 1

        if md5_count > 0:
            return Finding(
                control_id="CIS-2.1",
                status=FindingStatus.MANUAL_REVIEW,
                title="Ensure password encryption uses SCRAM-SHA-256",
                rationale=f"{md5_count} user(s) still using MD5 password encryption (non-automatable migration required)",
                evidence_found={"md5_password_count": md5_count},
                typed_action=ManualProcedureAction(
                    steps=[
                        "Set password_encryption='scram-sha-256' in postgresql.conf",
                        "Rotate all user credentials with new passwords",
                        "Update application connection strings to support SCRAM",
                        "Verify client driver compatibility",
                    ],
                    description="Migrate password encryption from MD5 to SCRAM-SHA-256",
                ),
                is_gapped=False,
                severity="1",
            )
        else:
            return Finding(
                control_id="CIS-2.1",
                status=FindingStatus.PASS,
                title="Ensure password encryption uses SCRAM-SHA-256",
                rationale="All users use SCRAM-SHA-256 or other secure password encryption",
                evidence_found={"md5_password_count": 0},
                typed_action=None,
                is_gapped=False,
                severity="1",
            )

    registry["CIS-2.1"] = ControlDefinition(
        control_id="CIS-2.1",
        cis_title="2.1 Migrate authentication to SCRAM-SHA-256",
        description="Ensure all client authentication uses SCRAM-SHA-256 instead of deprecated MD5.",
        severity="1",
        rule_func=_check_password_encryption,
        default_action=ManualProcedureAction(
            steps=[
                "Set password_encryption='scram-sha-256' in postgresql.conf",
                "Rotate all user credentials with new passwords",
                "Update application connection strings to support SCRAM",
                "Verify client driver compatibility",
            ],
            description="Migrate password encryption from MD5 to SCRAM-SHA-256",
        ),
        is_automatable=False,
    )

    return registry


# Global control registry instance
CONTROL_REGISTRY: dict[str, ControlDefinition] = _build_control_registry()


def get_control(control_id: str) -> Optional[ControlDefinition]:
    """Get a control definition by its ID."""
    return CONTROL_REGISTRY.get(control_id)


def get_all_controls() -> list[ControlDefinition]:
    """Get all control definitions in the registry."""
    return list(CONTROL_REGISTRY.values())


def get_control_ids() -> list[str]:
    """Get all control IDs in the registry."""
    return list(CONTROL_REGISTRY.keys())
