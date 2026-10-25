"""Control catalog for ASSESS evaluation engine.

This directory contains structured control definitions used by the offline
ASSESS evaluation engine. Each control defines:

- Metadata (ID, CIS title, description, severity)
- Rule evaluation function operating on normalized snapshot JSON
- Template mapping for remediation (replaces TypedAction)

The ASSESS engine is purely OFFLINE. It evaluates snapshot JSON files stored
in DBGuard. It never connects to a target database or runs live queries.

ABSENT vs. EMPTY invariant:
- [] = collected and empty (verified absence of data)
- null with a matching entry in gaps = could not collect (unknown evidence)
A gapped control MUST evaluate to GAPPED / MANUAL_REVIEW, NEVER a false PASS.
"""

from typing import Any, Callable, Optional

from app.models import (
    ControlMetadata,
    Finding,
    FindingStatus,
)


# ============================================================================
# Control Registry
# ============================================================================

ControlRule = Callable[[dict[str, Any]], Finding]


class ControlDefinition:
    """Definition of a single assessment control.

    Controls now map to approved Jinja templates for remediation via
    the template_id field in ControlMetadata. The AI/Hermes agent proposes
    remediation by selecting from these approved templates.
    """

    def __init__(
        self,
        control_id: str,
        cis_title: str,
        description: str,
        severity: str,
        rule_func: ControlRule,
        template_id: Optional[str] = None,
        template_version: Optional[int] = None,
        is_automatable: bool = True,
        risk_level: str = "medium",
        requires_dba_review: bool = True,
    ):
        self.control_id = control_id
        self.cis_title = cis_title
        self.description = description
        self.severity = severity
        self.rule_func = rule_func
        self.template_id = template_id
        self.template_version = template_version
        self.is_automatable = is_automatable
        self.risk_level = risk_level
        self.requires_dba_review = requires_dba_review

    def evaluate(self, snapshot: dict[str, Any]) -> Finding:
        """Evaluate this control against a normalized snapshot."""
        return self.rule_func(snapshot)


# ============================================================================
# Control Implementations
# ============================================================================

# CIS rules come only from the reviewed spec catalog (catalog/specs/). The two
# checks below are DBGuard's own supplementary checks: they are useful, but they
# are not CIS PostgreSQL 17 recommendations, so they carry DBGuard IDs.
PUBLIC_SCHEMA_CREATE = "DBGUARD-PUBLIC-SCHEMA-CREATE"
MD5_PASSWORDS = "DBGUARD-MD5-PASSWORDS"

# Old IDs that earlier clients and stored proposals may still send. CIS-3.1.2
# was a mislabel: log_connections is CIS PG17 3.1.20 (3.1.2 is log destinations).
LEGACY_CONTROL_IDS = {
    "CIS-3.1.2": "cis-pg17-v1.1.0:3.1.20",
    "cis_postgres_16_log_connections": "cis-pg17-v1.1.0:3.1.20",
    "CIS-4.1.1": PUBLIC_SCHEMA_CREATE,
    "CIS-2.1": MD5_PASSWORDS,
}


def _build_supplementary_controls() -> dict[str, ControlDefinition]:
    """Build DBGuard's supplementary (non-CIS) controls."""

    registry: dict[str, ControlDefinition] = {}

    # --------------------------------------------------------------------------
    # DBGuard supplementary check (not a CIS PG17 recommendation):
    # revoke PUBLIC schema CREATE grant
    # --------------------------------------------------------------------------
    # Type: Fully Automatable SQL Privilege
    # Pass condition: has_schema_privilege('public', 'public', 'CREATE') is false
    # Template: REVOKE_SCHEMA_PRIVILEGE (maps to approved Jinja template)
    # --------------------------------------------------------------------------
    def _check_public_schema_create(snapshot: dict[str, Any]) -> Finding:
        """Check if PUBLIC has CREATE privilege on public schema."""
        schemas = snapshot.get("schemas")
        gaps = snapshot.get("gaps", [])
        
        # If schemas section is null/missing, this is a gap
        if schemas is None:
            # Check for matching gap record
            gap_reason = None
            for gap in gaps:
                if isinstance(gap, dict) and gap.get("section") == "schemas":
                    gap_reason = gap.get("reason", "unknown")
                    break
            
            if gap_reason:
                return Finding(
                    control_id=PUBLIC_SCHEMA_CREATE,
                    status=FindingStatus.GAPPED,
                    title="Ensure PUBLIC schema CREATE privilege is revoked",
                    rationale=f"Collector could not retrieve schema information (gap: {gap_reason})",
                    evidence_found=None,
                    control_metadata=None,
                    is_gapped=True,
                    severity="2A",
                    evidence_paths=["schemas"],
                )
            else:
                return Finding(
                    control_id=PUBLIC_SCHEMA_CREATE,
                    status=FindingStatus.GAPPED,
                    title="Ensure PUBLIC schema CREATE privilege is revoked",
                    rationale="Collector could not retrieve schema information (section unavailable without gap record - collector contract violation)",
                    evidence_found=None,
                    control_metadata=None,
                    is_gapped=True,
                    severity="2A",
                    evidence_paths=["schemas"],
                )

        # Look for public schema entry
        public_schema_entry = None
        for schema in schemas:
            if isinstance(schema, dict) and schema.get("nspname") == "public":
                public_schema_entry = schema
                break

        if public_schema_entry is None:
            # public schema not found in schemas - this should never happen
            # but if it does, it's a gap
            return Finding(
                control_id=PUBLIC_SCHEMA_CREATE,
                status=FindingStatus.GAPPED,
                title="Ensure PUBLIC schema CREATE privilege is revoked",
                rationale="public schema entry not found in schemas list (collector should always include public schema - this indicates collection failure)",
                evidence_found={"schemas_found": [s.get("nspname") for s in schemas if isinstance(s, dict) and s.get("nspname")]},
                control_metadata=None,
                is_gapped=True,
                severity="2A",
                evidence_paths=["schemas", "schemas[nspname='public'].nspname"],
            )

        # Entry exists, now check public_has_create
        public_has_create = public_schema_entry.get("public_has_create")
        
        if public_has_create is None:
            # Field is missing from the entry
            return Finding(
                control_id=PUBLIC_SCHEMA_CREATE,
                status=FindingStatus.GAPPED,
                title="Ensure PUBLIC schema CREATE privilege is revoked",
                rationale="public_has_create field is missing from public schema entry (collector contract violation)",
                evidence_found={"public_schema_found": True, "public_has_create": None},
                control_metadata=None,
                is_gapped=True,
                severity="2A",
                evidence_paths=["schemas[nspname='public'].nspname", "schemas[nspname='public'].public_has_create"],
            )
        
        if public_has_create:
            return Finding(
                control_id=PUBLIC_SCHEMA_CREATE,
                status=FindingStatus.FAIL,
                title="Ensure PUBLIC schema CREATE privilege is revoked",
                rationale="PUBLIC has CREATE privilege on public schema",
                evidence_found={"public_has_create": True, "schema": "public"},
                control_metadata=ControlMetadata(
                    template_id="REVOKE_SCHEMA_PRIVILEGE",
                    template_version=1,
                    is_automatable=True,
                    risk_level="low",
                    requires_dba_review=True,
                ),
                is_gapped=False,
                severity="2A",
                evidence_paths=["schemas[nspname='public'].nspname", "schemas[nspname='public'].public_has_create"],
            )
        else:
            return Finding(
                control_id=PUBLIC_SCHEMA_CREATE,
                status=FindingStatus.PASS,
                title="Ensure PUBLIC schema CREATE privilege is revoked",
                rationale="PUBLIC does not have CREATE privilege on public schema",
                evidence_found={"public_has_create": False, "schema": "public"},
                control_metadata=None,
                is_gapped=False,
                severity="2A",
                evidence_paths=["schemas[nspname='public'].nspname", "schemas[nspname='public'].public_has_create"],
            )

    registry[PUBLIC_SCHEMA_CREATE] = ControlDefinition(
        control_id=PUBLIC_SCHEMA_CREATE,
        cis_title="DBGuard supplementary check (not CIS): Revoke PUBLIC schema CREATE privilege",
        description="Revoke the CREATE privilege on the public schema from the PUBLIC role.",
        severity="2A",
        rule_func=_check_public_schema_create,
        template_id="REVOKE_SCHEMA_PRIVILEGE",
        template_version=1,
        is_automatable=True,
        risk_level="low",
        requires_dba_review=True,
    )

    # --------------------------------------------------------------------------
    # DBGuard supplementary check (not a CIS PG17 recommendation):
    # migrate md5 passwords to scram-sha-256
    # --------------------------------------------------------------------------
    # Type: Non-SQL / Operational Migration
    # Pass condition: pg_authid.rolpassword matching 'md5%' count == 0
    # Template: MANUAL_PROCEDURE (maps to approved Jinja template for manual review)
    # --------------------------------------------------------------------------
    def _check_password_encryption(snapshot: dict[str, Any]) -> Finding:
        """Check if any users still use MD5 password encryption.
        
        Note: This is a MANUAL_REVIEW control because migration requires
        each affected user to reset their password. We can detect md5
        passwords but cannot automate the migration.
        """
        password_types = snapshot.get("password_types")
        gaps = snapshot.get("gaps", [])

        # Check if password_types section is gapped
        if password_types is None:
            for gap in gaps:
                if isinstance(gap, dict) and gap.get("section") == "password_types":
                    return Finding(
                        control_id=MD5_PASSWORDS,
                        status=FindingStatus.MANUAL_REVIEW,
                        title="Ensure password encryption uses SCRAM-SHA-256",
                        rationale=(
                            f"Collector could not retrieve password types "
                            f"(gap: {gap.get('reason', 'unknown')})"
                        ),
                        evidence_found=None,
                        control_metadata=ControlMetadata(
                            template_id="MANUAL_PROCEDURE",
                            template_version=1,
                            is_automatable=False,
                            risk_level="high",
                            requires_dba_review=True,
                        ),
                        is_gapped=True,
                        severity="1",
                        evidence_paths=["password_types"],
                    )
            # No matching gap found but still null
            return Finding(
                control_id=MD5_PASSWORDS,
                status=FindingStatus.MANUAL_REVIEW,
                title="Ensure password encryption uses SCRAM-SHA-256",
                rationale="Collector could not retrieve password types (section unavailable without gap record)",
                evidence_found=None,
                control_metadata=ControlMetadata(
                    template_id="MANUAL_PROCEDURE",
                    template_version=1,
                    is_automatable=False,
                    risk_level="high",
                    requires_dba_review=True,
                ),
                is_gapped=False,
                severity="1",
                evidence_paths=["password_types"],
            )

        # Count MD5 password entries
        md5_count = 0
        scram_count = 0
        none_count = 0
        
        for entry in password_types:
            if isinstance(entry, dict):
                password_type = entry.get("password_type", "")
                if password_type == "md5":
                    md5_count += 1
                elif password_type == "scram-sha-256":
                    scram_count += 1
                elif password_type == "none":
                    none_count += 1

        if md5_count > 0:
            return Finding(
                control_id=MD5_PASSWORDS,
                status=FindingStatus.MANUAL_REVIEW,
                title="Ensure password encryption uses SCRAM-SHA-256",
                rationale=f"{md5_count} user(s) still using MD5 password encryption (non-automatable migration required - each affected user must reset password)",
                evidence_found={"md5_password_count": md5_count, "scram_password_count": scram_count, "none_password_count": none_count},
                control_metadata=ControlMetadata(
                    template_id="MANUAL_PROCEDURE",
                    template_version=1,
                    is_automatable=False,
                    risk_level="high",
                    requires_dba_review=True,
                ),
                is_gapped=False,
                severity="1",
                evidence_paths=["password_types"],
            )
        else:
            return Finding(
                control_id=MD5_PASSWORDS,
                status=FindingStatus.PASS,
                title="Ensure password encryption uses SCRAM-SHA-256",
                rationale=f"All login roles use SCRAM-SHA-256 ({scram_count} users), no MD5 passwords detected ({md5_count} found, {none_count} roles without passwords)",
                evidence_found={"md5_password_count": 0, "scram_password_count": scram_count, "none_password_count": none_count},
                control_metadata=None,
                is_gapped=False,
                severity="1",
                evidence_paths=["password_types"],
            )

    registry[MD5_PASSWORDS] = ControlDefinition(
        control_id=MD5_PASSWORDS,
        cis_title="DBGuard supplementary check (not CIS): Migrate authentication to SCRAM-SHA-256",
        description="Ensure all client authentication uses SCRAM-SHA-256 instead of deprecated MD5.",
        severity="1",
        rule_func=_check_password_encryption,
        template_id="MANUAL_PROCEDURE",
        template_version=1,
        is_automatable=False,
        risk_level="high",
        requires_dba_review=True,
    )

    return registry


def _build_control_registry() -> dict[str, ControlDefinition]:
    """Spec-derived CIS controls first, then DBGuard supplementary controls."""
    from catalog.controls.assess.spec_controls import load_spec_controls

    registry = load_spec_controls(ControlDefinition)
    supplementary = _build_supplementary_controls()
    if set(registry) & set(supplementary):
        raise ValueError("Supplementary control IDs must not collide with spec IDs")
    registry.update(supplementary)
    return registry


# Global control registry instance
CONTROL_REGISTRY: dict[str, ControlDefinition] = _build_control_registry()


def resolve_control_id(control_id: str) -> str:
    """Map a retired legacy ID to its current ID; other IDs are returned unchanged."""
    return LEGACY_CONTROL_IDS.get(control_id, control_id)


def get_control(control_id: str) -> Optional[ControlDefinition]:
    """Get a control definition by its current or legacy ID."""
    return CONTROL_REGISTRY.get(resolve_control_id(control_id))


def get_all_controls() -> list[ControlDefinition]:
    """Get all control definitions in the registry."""
    return list(CONTROL_REGISTRY.values())


def get_control_ids() -> list[str]:
    """Get all control IDs in the registry."""
    return list(CONTROL_REGISTRY.keys())
