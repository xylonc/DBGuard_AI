"""Jinja2 SQL template renderer."""

import os
from jinja2 import Environment, FileSystemLoader, StrictUndefined

TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "..", "templates")
env = Environment(
    loader=FileSystemLoader(TEMPLATES_DIR),
    autoescape=False,
    undefined=StrictUndefined,
)


def quote_identifier(value: str) -> str:
    """Quote a PostgreSQL identifier without allowing SQL to escape it."""
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError(f"Invalid PostgreSQL identifier: {value!r}")
    return f'"{value.replace(chr(34), chr(34) * 2)}"'


env.filters["ident"] = quote_identifier


def compile_sql_plan(template_ids: list[str], variables: dict) -> str:
    """
    Takes template IDs and variables and compiles them into a single SQL script.
    """
    compiled_scripts = []

    for template_id in template_ids:
        file_name = f"{template_id}.sql.j2"
        template = env.get_template(file_name)
        rendered_sql = template.render(**variables)
        compiled_scripts.append(f"-- Template: {template_id}\n{rendered_sql}")

    return "\n\n".join(compiled_scripts)
