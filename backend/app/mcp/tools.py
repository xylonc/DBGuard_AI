"""MCP Tool Handlers for DBGuardAI VALIDATE Phase.

This module implements the MCP (Model Context Protocol) tool endpoints
that HERMES can call to:
1. Propose and validate remediation SQL
2. Validate template parameters before rendering
3. Execute twin sandbox verification
4. Return complete ProposalReviewPackage

Tools are called by HERMES via MCP and executed in the trusted API boundary.
"""

import logging
from typing import Any, Dict, List, Optional, Tuple

from app.models import (
    ProposalReviewPackage,
    SetConfigTemplateParams,
    RevokePrivilegeTemplateParams,
    TwinExecutionResult,
)
from app.proposal_compiler import ProposalCompiler
from app.services.template_service import (
    safe_render_template,
    validate_params,
)
from app.services.twin_service import TwinExecutionService, build_proposal_review_package
from catalog.controls.assess.registry import CONTROL_REGISTRY, get_control

logger = logging.getLogger("dbguard.mcp-tools")


# ============================================================================
# Template Parameter Validation
# ============================================================================


def validate_template_params(
    template_name: str,
    parameters: Dict[str, Any],
) -> Tuple[bool, Dict[str, Any], Optional[str]]:
    """
    Validate template parameters against Pydantic schemas.
    
    Args:
        template_name: Template identifier (e.g., 'set_config_parameter')
        parameters: Raw parameter dictionary
        
    Returns:
        Tuple of (success, validated_params, error_message)
    """
    return validate_params(template_name, parameters)


# ============================================================================
# SQL Generation with Validation
# ============================================================================


def generate_and_validate_sql(
    template_name: str,
    sql_template: str,
    parameters: Dict[str, Any],
) -> Tuple[bool, str, Optional[str]]:
    """
    Validate parameters and render SQL template.
    
    Args:
        template_name: Template identifier
        sql_template: Jinja2 template string
        parameters: Template parameters
        
    Returns:
        Tuple of (success, rendered_sql, error_message)
    """
    return safe_render_template(template_name, sql_template, parameters)


# ============================================================================
# MCP Tool Handlers
# ============================================================================


def propose_and_validate_remediation(
    template_id: str,
    parameters: Dict[str, Any],
    snapshot_id: str,
) -> Tuple[bool, ProposalReviewPackage, Optional[str]]:
    """
    MCP Tool: Propose and validate remediation SQL.
    
    This is the main entry point for the VALIDATE phase workflow:
    1. Validates template parameters against Pydantic schemas
    2. Renders Jinja SQL template with validated parameters
    3. Executes twin sandbox verification
    4. Returns complete ProposalReviewPackage for DBA review
    
    Args:
        template_id: Template identifier (e.g., 'set_config_parameter_v1')
        parameters: Template parameters from user input
        snapshot_id: Source snapshot ID for audit trail
        
    Returns:
        Tuple of (success, ProposalReviewPackage, error_message)
    """
    try:
        # Step 1: Get the control definition
        control = get_control(template_id.split("_")[0])  # Extract control ID
        
        if not control:
            return False, None, f"Control '{template_id}' not found in registry"
        
        # Step 2: Validate template parameters
        template_name = template_id.split("_")[0]
        valid, validated_params, error = validate_params(template_name, parameters)
        
        if not valid:
            return False, None, f"Parameter validation failed: {error}"
        
        # Step 3: Get the SQL template (from template registry in production)
        # For now, use the default template strings
        default_templates = {
            "set_config_parameter": (
                "ALTER SYSTEM SET {{ param_name }} = '{{ param_value }}';\n"
                "SELECT pg_reload_conf();"
            ),
            "revoke_schema_privilege": (
                "REVOKE {{ privilege }} ON SCHEMA \"{{ schema_name }}\" FROM {{ grantee }};"
            ),
        }
        
        sql_template = default_templates.get(template_name)
        if not sql_template:
            return False, None, f"Unknown template: {template_name}"
        
        # Step 4: Validate and render SQL
        sql_valid, rendered_sql, render_error = safe_render_template(
            template_name, sql_template, validated_params
        )
        
        if not sql_valid:
            return False, None, f"SQL rendering failed: {render_error}"
        
        # Step 5: Generate rollback SQL
        rollback_sql = None
        if template_name == "set_config_parameter":
            # Generate rollback based on the parameter
            rollback_value = "off" if validated_params.get("param_value", "").lower() == "on" else "on"
            rollback_sql = (
                f"ALTER SYSTEM SET \"{validated_params['param_name']}\" = '{rollback_value}';\n"
                "SELECT pg_reload_conf();"
            )
        elif template_name == "revoke_schema_privilege":
            # Rollback is GRANT instead of REVOKE
            rollback_sql = (
                f"GRANT {validated_params['privilege']} ON SCHEMA \"{validated_params['schema_name']}\" "
                f"TO {validated_params['grantee']};"
            )
        
        # Step 6: Execute twin sandbox verification
        twin_service = TwinExecutionService()
        
        manual_procedure = None
        if control.default_action and hasattr(control.default_action, 'steps'):
            # Manual procedure control
            manual_procedure = control.default_action.steps
            twin_result = twin_service.verify_proposal_package(
                snapshot_id=snapshot_id,
                control_id=control.control_id,
                remediation_sql=None,
                rollback_sql=None,
                manual_procedure=manual_procedure,
            )
        else:
            # Executable SQL control
            twin_result = twin_service.verify_proposal_package(
                snapshot_id=snapshot_id,
                control_id=control.control_id,
                remediation_sql=rendered_sql,
                rollback_sql=rollback_sql,
                manual_procedure=None,
            )
        
        # Step 7: Build the proposal review package
        rag_justification = f"CIS {control.cis_title}: {control.description}. "
        rag_justification += f"Severity: {control.severity}. "
        rag_justification += f"Rationale: {control.default_action.description if control.default_action else 'Automated remediation'}"
        
        package = build_proposal_review_package(
            control_id=control.control_id,
            title=control.cis_title,
            remediation_sql=rendered_sql,
            rollback_sql=rollback_sql,
            manual_procedure=manual_procedure,
            twin_verification=twin_result,
            rag_justification=rag_justification,
            requires_dba_review=True,
            risk_level="high" if "CREATE" in rendered_sql or "REVOKE" in rendered_sql else "medium",
        )
        
        return True, package, None
        
    except Exception as e:
        logger.error(f"Proposal validation failed: {e}")
        return False, None, str(e)


def execute_remediation_in_twin(
    control_id: str,
    remediation_sql: str,
    snapshot_id: str,
) -> Tuple[bool, TwinExecutionResult, Optional[str]]:
    """
    MCP Tool: Execute remediation SQL in twin sandbox.
    
    Args:
        control_id: Control identifier (e.g., 'CIS-3.1.2')
        remediation_sql: SQL to execute
        snapshot_id: Source snapshot ID
        
    Returns:
        Tuple of (success, TwinExecutionResult, error_message)
    """
    try:
        twin_service = TwinExecutionService()
        twin_result = twin_service.verify_proposal_package(
            snapshot_id=snapshot_id,
            control_id=control_id,
            remediation_sql=remediation_sql,
            rollback_sql=None,  # Rollback happens automatically in verify_proposal_package
            manual_procedure=None,
        )
        return True, twin_result, None
    except Exception as e:
        logger.error(f"Twin execution failed: {e}")
        return False, None, str(e)


def get_proposal_for_review(
    control_id: str,
    snapshot_id: str,
) -> Tuple[bool, ProposalReviewPackage, Optional[str]]:
    """
    MCP Tool: Get a pre-compiled proposal for DBA review.
    
    This is used when the proposal has already been compiled but needs
    twin verification before final delivery.
    
    Args:
        control_id: Control identifier
        snapshot_id: Snapshot ID
        
    Returns:
        Tuple of (success, ProposalReviewPackage, error_message)
    """
    try:
        control = get_control(control_id)
        if not control:
            return False, None, f"Control '{control_id}' not found"
        
        # Get the default action to determine if SQL or manual
        action = control.default_action
        
        if action is None:
            return False, None, f"No default action defined for {control_id}"
        
        # Build package with placeholder for twin verification
        package = build_proposal_review_package(
            control_id=control.control_id,
            title=control.cis_title,
            remediation_sql=None,  # Will be filled by twin service
            rollback_sql=None,
            manual_procedure=action.steps if hasattr(action, "steps") else None,
            twin_verification=None,  # Will be filled by twin service
            rag_justification=f"CIS {control.cis_title}: {control.description}",
            requires_dba_review=True,
            risk_level="high" if "CREATE" in str(action) else "medium",
        )
        
        return True, package, None
        
    except Exception as e:
        logger.error(f"Failed to get proposal: {e}")
        return False, None, str(e)
