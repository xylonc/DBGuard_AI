"""Fix unit SQL renderer.

render_action() converts typed actions (set_config, reset_config) to SQL.
This replaces the old SQL-parsing approach - actions are deterministic,
so we can render SQL from them and compare field values instead of parsing.

The renderer matches the set_config_parameter.sql.j2 template output.
"""

import re


def _quote_identifier(value: str) -> str:
    """Quote a PostgreSQL identifier without allowing SQL to escape it.

    Matches the template_service.ident filter.
    """
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError(f"Invalid PostgreSQL identifier: {value!r}")
    return f'"{value.replace(chr(34), chr(34) * 2)}"'


def render_action(action: dict) -> str:
    """Render a typed action to SQL.

    Args:
        action: Either {"action": "set_config", "param": <name>, "value": <str>}
                or {"action": "reset_config", "param": <name>}

    Returns:
        SQL string (ALTER SYSTEM SET or ALTER SYSTEM RESET)
    """
    action_type = action.get("action")
    param = action.get("param", "")

    if action_type == "set_config":
        value = action.get("value", "")
        # Escape single quotes in value by doubling them (SQL string literal)
        escaped_value = value.replace("'", "''")
        # Quote param name (ident filter in template)
        quoted_param = _quote_identifier(param)
        return f"ALTER SYSTEM SET {quoted_param} = '{escaped_value}'; SELECT pg_reload_conf();"
    elif action_type == "reset_config":
        # Quote param name (ident filter in template)
        quoted_param = _quote_identifier(param)
        return f"ALTER SYSTEM RESET {quoted_param}; SELECT pg_reload_conf();"
    else:
        raise ValueError(f"Unknown action type: {action_type!r}")
