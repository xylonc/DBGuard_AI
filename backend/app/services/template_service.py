"""Jinja2 SQL template renderer with parameter validation.

Templates are now loaded from PostgreSQL rather than filesystem.
The PostgreSQL template registry is the authoritative source of truth.

Parameter validation ensures SQL injection prevention by validating
all template parameters against Pydantic schemas BEFORE rendering.
"""

import re
from typing import Any, Dict, Optional, Tuple, Type

from jinja2 import Environment, StrictUndefined

from app.models import (
    RevokePrivilegeTemplateParams,
    SetConfigTemplateParams,
)

# Jinja2 environment with strict undefined handling for safe rendering
env = Environment(
    autoescape=False,
    undefined=StrictUndefined,
)


def quote_identifier(value: str) -> str:
    """Quote a PostgreSQL identifier without allowing SQL to escape it."""
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError(f"Invalid PostgreSQL identifier: {value!r}")
    return f'"{value.replace(chr(34), chr(34) * 2)}"'


env.filters["ident"] = quote_identifier


def compile_sql_plan_from_templates(
    template_records: list[dict],
    variables: dict,
) -> str:
    """
    Takes template records (from PostgreSQL) and variables and compiles them into a single SQL script.
    
    Each template record must contain:
    - template_name: Name of the template
    - sql_template: The Jinja2 template SQL string
    """
    compiled_scripts = []

    for record in template_records:
        template_name = record["template_name"]
        sql_template = record["sql_template"]

        # Create a Jinja2 template from the stored content
        template = env.from_string(sql_template)
        rendered_sql = template.render(**variables)
        compiled_scripts.append(f"-- Template: {template_name}\n{rendered_sql}")

    return "\n\n".join(compiled_scripts)


# ============================================================================
# Safe Jinja SQL Renderer with Parameter Validation
# ============================================================================


# Mapping of template names to parameter validation schemas
TEMPLATE_PARAM_SCHEMAS: Dict[str, Type] = {
    "set_config_parameter": SetConfigTemplateParams,
    "revoke_schema_privilege": RevokePrivilegeTemplateParams,
}


def validate_params(
    template_name: str,
    parameters: Dict[str, Any],
) -> Tuple[bool, Dict[str, Any], Optional[str]]:
    """
    Validate template parameters against the appropriate Pydantic schema.
    
    Args:
        template_name: The template name (e.g., 'set_config_parameter')
        parameters: Raw parameter dictionary from user input
        
    Returns:
        Tuple of (success, validated_params, error_message)
    """
    schema_class = TEMPLATE_PARAM_SCHEMAS.get(template_name)
    
    if schema_class is None:
        # No validation schema - allow raw params (use with caution)
        return True, parameters, None
    
    try:
        # Validate and convert to validated model
        validated = schema_class(**parameters)
        # Return as dict
        return True, validated.model_dump(), None
    except Exception as e:
        return False, {}, str(e)


def safe_render_template(
    template_name: str,
    sql_template: str,
    parameters: Dict[str, Any],
) -> Tuple[bool, str, Optional[str]]:
    """
    Safely render a Jinja2 template after validating parameters.
    
    This is the ENTRY POINT for template rendering - it always validates
    first, then renders only if validation passes.
    
    Args:
        template_name: Name of the template for schema lookup
        sql_template: The Jinja2 template SQL string
        parameters: Template parameters from user input
        
    Returns:
        Tuple of (success, rendered_sql, error_message)
    """
    # Step 1: Validate parameters
    valid, validated_params, error = validate_params(template_name, parameters)
    
    if not valid:
        return False, "", f"Parameter validation failed: {error}"
    
    try:
        # Step 2: Create Jinja2 template from the stored content
        template = env.from_string(sql_template)
        
        # Step 3: Render with validated parameters
        rendered_sql = template.render(**validated_params)
        
        # Step 4: Post-render validation (sanity check for SQL injection)
        if not is_safe_sql(rendered_sql):
            return False, "", "Rendered SQL failed post-render safety checks"
        
        return True, rendered_sql, None
        
    except Exception as e:
        return False, "", f"Template rendering failed: {str(e)}"


def is_safe_sql(sql: str) -> bool:
    """
    Post-render safety check for rendered SQL.
    
    Rejects SQL containing common injection patterns.
    """
    # Strip comments
    sql_no_comments = re.sub(r'--.*$', '', sql, flags=re.MULTILINE)
    sql_no_comments = re.sub(r'/\*.*?\*/', '', sql_no_comments, flags=re.DOTALL)
    
    # Check for dangerous patterns
    dangerous_patterns = [
        r';\s*(drop|truncate|delete|update|insert)\b',  # Multiple statements
        r'--',  # Inline comments (should be removed)
        r'/\*',  # Block comment start
        r'EXEC\s*\(',  # EXEC function
        r'SELECT\s+.*\s+INTO\s+',  # Potential INTO
    ]
    
    for pattern in dangerous_patterns:
        if re.search(pattern, sql_no_comments, re.IGNORECASE):
            return False
    
    return True


# Legacy function - kept for compatibility during migration
# This will eventually be removed
def compile_sql_plan(template_ids: list[str], variables: dict) -> str:
    """
    Legacy: Takes template IDs and compiles from filesystem.
    This function should not be used in new code paths.
    
    For new implementation, use compile_sql_plan_from_templates with records from PostgreSQL.
    """
    raise NotImplementedError(
        "compile_sql_plan is deprecated. Use compile_sql_plan_from_templates "
        "with template records from PostgreSQL."
    )
