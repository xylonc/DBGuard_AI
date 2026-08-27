"""Jinja2 SQL template renderer."""

import os
from jinja2 import Environment, FileSystemLoader

TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "..", "templates")
env = Environment(loader=FileSystemLoader(TEMPLATES_DIR), autoescape=False)


def compile_sql_plan(template_ids: list[str], variables: dict) -> str:
    """
    Takes template IDs and variables and compiles them into a single SQL script.
    """
    compiled_scripts = []

    for template_id in template_ids:
        file_name = f"{template_id}.sql.j2"
        try:
            template = env.get_template(file_name)
            rendered_sql = template.render(**variables)
            compiled_scripts.append(f"-- Template: {template_id}\n{rendered_sql}")
        except Exception as e:
            compiled_scripts.append(f"-- ERROR rendering template {template_id}: {str(e)}")

    return "\n\n".join(compiled_scripts)
