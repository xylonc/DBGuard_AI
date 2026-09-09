"""Jinja2 SQL template renderer.

Templates are now loaded from PostgreSQL rather than filesystem.
The PostgreSQL template registry is the authoritative source of truth.
"""

from jinja2 import Environment, StrictUndefined

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
