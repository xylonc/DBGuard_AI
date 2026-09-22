"""Fix unit SQL renderer.

render_action() converts typed actions (set_config, reset_config) to SQL.
This replaces the old SQL-parsing approach - actions are deterministic,
so we can render SQL from them and compare field values instead of parsing.

The renderer matches the set_config_parameter.sql.j2 template output.

derive_rollback(prior_state, apply) computes the appropriate rollback action:
- apply set_config, prior from postgresql.auto.conf -> set_config(param, prior.value)
- apply set_config, prior from other/sourcefile=null -> reset_config(param)
- apply reset_config, prior from postgresql.auto.conf -> set_config(param, prior.value)
- apply reset_config, otherwise -> raises ValueError (no-op fix not allowed)
"""
import re

from app.services.template_service import env


def _quote_identifier(value: str) -> str:
    """Quote a PostgreSQL identifier without allowing SQL to escape it.

    Matches the template_service.ident filter.
    """
    if not isinstance(value, str) or not value or "\x00" in value:
        raise ValueError(f"Invalid PostgreSQL identifier: {value!r}")
    return f'"{value.replace(chr(34), chr(34) * 2)}"'


def derive_rollback(prior_state: dict, apply_action: dict) -> dict:
    """Compute the rollback action needed to restore prior_state.

    Args:
        prior_state: The current state before applying the fix.
        apply_action: The apply action (set_config or reset_config).

    Returns:
        The rollback action dict.

    Raises:
        ValueError: If no valid rollback exists (e.g., reset_config on non-auto.conf).
    """
    action_type = apply_action.get("action")
    param = apply_action.get("param", "")
    prior_value = prior_state.get("value", "")

    if action_type == "set_config":
        sourcefile = prior_state.get("sourcefile")
        if sourcefile and sourcefile.endswith("postgresql.auto.conf"):
            # Prior was in auto.conf, must set it back to prior value
            return {"action": "set_config", "param": param, "value": prior_value}
        else:
            # Prior was from postgresql.conf or default, use reset
            return {"action": "reset_config", "param": param}

    elif action_type == "reset_config":
        sourcefile = prior_state.get("sourcefile")
        if sourcefile and sourcefile.endswith("postgresql.auto.conf"):
            # Prior was in auto.conf, must set it back to prior value
            return {"action": "set_config", "param": param, "value": prior_value}
        else:
            # Reset on non-auto.conf is a no-op; can't rollback
            raise ValueError(
                f"RESET apply is a no-op when prior_state.sourcefile is not postgresql.auto.conf "
                f"({sourcefile!r}); no valid rollback exists"
            )

    else:
        raise ValueError(f"Unknown action type: {action_type!r}")


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


