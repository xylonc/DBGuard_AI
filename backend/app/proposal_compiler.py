"""Proposal Compiler service for DBGuardAI.

This module implements the ProposalCompiler that translates assessment findings
into compiled SQL proposals. The compiler is deterministic - SQL is generated
programmatically from validated TypedAction objects, never via free-form LLM
string hallucination or un-sanitized parameter interpolation.

Hard Invariants:
- PROPOSE is DETERMINISTIC. Remediation and rollback SQL MUST be generated
  programmatically from validated TypedAction objects.
- NON-SQL CONTROLS: Controls using ManualProcedureAction MUST NOT generate
  executable SQL strings. They must set is_executable_sql = False.
- SAFELY QUOTED IDENTIFIERS: All SQL generation must safely handle schema names,
  privilege types, and parameter values to prevent SQL injection vulnerabilities.
"""

import re
from typing import Optional

from app.models import (
    AnyTypedAction,
    AssessmentReport,
    Finding,
    FindingStatus,
    ManualProcedureAction,
    RevokeSchemaPrivilegeAction,
    SetConfigParameterAction,
)
from app.proposal_models import CompiledProposal, ProposalPackage


def _quote_identifier(value: str) -> str:
    """Safely quote a PostgreSQL identifier (schema name, table name, etc.).
    
    Uses double quotes and escapes internal double quotes by doubling them.
    This prevents SQL injection through identifier injection.
    
    Args:
        value: The identifier to quote
        
    Returns:
        Safely quoted identifier (e.g., '"public"' or '"my""table"')
    """
    # Escape double quotes by doubling them
    escaped = value.replace('"', '""')
    return f'"{escaped}"'


def _quote_value(value: str) -> str:
    """Safely quote a PostgreSQL literal value.
    
    Uses single quotes and escapes internal single quotes by doubling them.
    
    Args:
        value: The value to quote
        
    Returns:
        Safely quoted value (e.g., "'on'" or "'value''with''quotes'")
    """
    # Escape single quotes by doubling them
    escaped = value.replace("'", "''")
    return f"'{escaped}'"


# ============================================================================
# Deterministic SQL Generators
# ============================================================================


def generate_set_config_parameter_sql(action: SetConfigParameterAction) -> tuple[str, str]:
    """Generate remediation and rollback SQL for SET_CONFIG_PARAMETER action.
    
    Args:
        action: The SetConfigParameterAction with name and value
        
    Returns:
        Tuple of (remediation_sql, rollback_sql)
    """
    # Safely quote the parameter name and values
    param_name = _quote_identifier(action.name)
    remediation_value = _quote_value(action.value)
    
    # Determine rollback value based on action value
    if action.value.lower() == "on":
        rollback_value = _quote_value("off")
    elif action.value.lower() == "off":
        rollback_value = _quote_value("on")
    else:
        # For non-boolean values, use a placeholder - user should specify
        rollback_value = _quote_value(f"<original_{action.name}>")
    
    # Generate SQL with proper quoting
    remediation_sql = (
        f"ALTER SYSTEM SET {param_name} = {remediation_value};\n"
        "SELECT pg_reload_conf();"
    )
    rollback_sql = (
        f"ALTER SYSTEM SET {param_name} = {rollback_value};\n"
        "SELECT pg_reload_conf();"
    )
    
    return remediation_sql, rollback_sql


def generate_revoke_schema_privilege_sql(action: RevokeSchemaPrivilegeAction) -> tuple[str, str]:
    """Generate remediation and rollback SQL for REVOKE_SCHEMA_PRIVILEGE action.
    
    Args:
        action: The RevokeSchemaPrivilegeAction with schema_name, privilege, and grantee
        
    Returns:
        Tuple of (remediation_sql, rollback_sql)
    """
    # Safely quote all identifiers
    schema_name = _quote_identifier(action.schema_name)
    grantee = _quote_identifier(action.grantee)
    # Privilege type is validated against allowed values
    privilege = action.privilege.upper()
    
    # Validate privilege against known safe values
    allowed_privileges = {"SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE", 
                         "REFERENCES", "TRIGGER", "CREATE", "USAGE", "TEMPORARY"}
    if privilege not in allowed_privileges:
        raise ValueError(f"Invalid privilege type: {privilege}. Must be one of {allowed_privileges}")
    
    # Generate REVOKE (remediation) SQL
    remediation_sql = f"REVOKE {privilege} ON SCHEMA {schema_name} FROM {grantee};"
    
    # Generate GRANT (rollback) SQL
    rollback_sql = f"GRANT {privilege} ON SCHEMA {schema_name} TO {grantee};"
    
    return remediation_sql, rollback_sql


# ============================================================================
# Proposal Compiler
# ============================================================================


class ProposalCompiler:
    """Deterministic proposal compiler for assessment findings.
    
    This compiler translates Finding objects (containing TypedAction) into
    CompiledProposal objects with executable SQL or manual procedures.
    """
    
    def __init__(self):
        """Initialize the ProposalCompiler."""
        self._action_handlers: dict[str, callable] = {
            "SET_CONFIG_PARAMETER": self._handle_set_config_parameter,
            "REVOKE_SCHEMA_PRIVILEGE": self._handle_revoke_schema_privilege,
            "MANUAL_PROCEDURE": self._handle_manual_procedure,
        }
    
    def compile_finding(self, finding: Finding) -> Optional[CompiledProposal]:
        """Compile a single finding into a proposal.
        
        Args:
            finding: The Assessment finding to compile
            
        Returns:
            CompiledProposal if the finding is FAIL or MANUAL_REVIEW,
            None if the finding is PASS or GAPPED (no action needed)
        """
        # Only compile proposals for non-PASS findings
        if finding.status == FindingStatus.PASS:
            return None
        
        # For GAPPED findings, no remediation is possible
        if finding.status == FindingStatus.GAPPED:
            return None
        
        # Get the typed action from the finding
        if finding.typed_action is None:
            return None
        
        typed_action = finding.typed_action
        action_type = typed_action.action_type
        
        # Dispatch to the appropriate handler
        handler = self._action_handlers.get(action_type)
        if handler is None:
            raise ValueError(f"Unknown action type: {action_type}")
        
        return handler(finding, typed_action)
    
    def compile_report(self, report: AssessmentReport) -> ProposalPackage:
        """Compile all findings from an assessment report into a proposal package.
        
        Args:
            report: The AssessmentReport containing all findings
            
        Returns:
            ProposalPackage with all compiled proposals and summary
        """
        proposals: list[CompiledProposal] = []
        
        for finding in report.findings:
            proposal = self.compile_finding(finding)
            if proposal is not None:
                proposals.append(proposal)
        
        # Calculate summary counts
        executable_count = sum(1 for p in proposals if p.is_executable_sql)
        manual_count = sum(1 for p in proposals if not p.is_executable_sql)
        
        return ProposalPackage(
            snapshot_id=report.snapshot_id,
            proposals=proposals,
            summary={
                "total_proposals": len(proposals),
                "executable_count": executable_count,
                "manual_count": manual_count,
            },
        )
    
    # --------------------------------------------------------------------------
    # Action Handlers (deterministic SQL generation)
    # --------------------------------------------------------------------------
    
    def _handle_set_config_parameter(
        self,
        finding: Finding,
        action: SetConfigParameterAction,
    ) -> CompiledProposal:
        """Handle SET_CONFIG_PARAMETER action."""
        remediation_sql, rollback_sql = generate_set_config_parameter_sql(action)
        
        return CompiledProposal(
            control_id=finding.control_id,
            title=finding.title,
            is_executable_sql=True,
            remediation_sql=remediation_sql,
            rollback_sql=rollback_sql,
            requires_dba_review=True,
            risk_level="medium",  # Config changes need review
        )
    
    def _handle_revoke_schema_privilege(
        self,
        finding: Finding,
        action: RevokeSchemaPrivilegeAction,
    ) -> CompiledProposal:
        """Handle REVOKE_SCHEMA_PRIVILEGE action."""
        remediation_sql, rollback_sql = generate_revoke_schema_privilege_sql(action)
        
        return CompiledProposal(
            control_id=finding.control_id,
            title=finding.title,
            is_executable_sql=True,
            remediation_sql=remediation_sql,
            rollback_sql=rollback_sql,
            requires_dba_review=True,
            risk_level="high",  # Privilege changes are sensitive
        )
    
    def _handle_manual_procedure(
        self,
        finding: Finding,
        action: ManualProcedureAction,
    ) -> CompiledProposal:
        """Handle MANUAL_PROCEDURE action (non-SQL)."""
        return CompiledProposal(
            control_id=finding.control_id,
            title=finding.title,
            is_executable_sql=False,
            remediation_sql=None,
            rollback_sql=None,
            manual_steps=action.steps,
            requires_dba_review=True,
            risk_level="high",  # Manual procedures carry operational risk
        )
