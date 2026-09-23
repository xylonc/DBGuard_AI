"""Live tests for fix_unit apply/rollback against pg-target.

These tests verify the fix_unit contract by:
1. Reading current state via fresh_setting()
2. Applying a fix via run_action()
3. Verifying the change took effect
4. Rolling back and verifying the original state

Test 1 (test_set_config_live_default_prior): Tests with default prior (sourcefile NULL).
Test 2 (test_set_config_live_auto_conf_prior): Tests with ALTER SYSTEM prior (sourcefile ends with postgresql.auto.conf).
"""

import os
import pytest
from pathlib import Path
from typing import Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
sys_path = str(REPO_ROOT / "backend")
if sys_path not in __import__("sys").path:
    __import__("sys").path.insert(0, sys_path)

from app.services.fix_unit_render import derive_rollback
from app.services.fix_unit_validator import validate_fix_unit


def load_valid_fix_unit() -> dict:
    """Load the valid fix-unit-log_connections.json fixture."""
    import json
    path = REPO_ROOT / "tests" / "fixtures" / "phase0" / "fix-unit-log_connections.json"
    return json.loads(path.read_text(encoding="utf-8"))


def fresh_setting(param: str) -> Tuple[str, str, str | None]:
    """Read a setting from pg_settings with a fresh connection.

    Returns:
        Tuple of (setting, source, sourcefile) where sourcefile may be None.
    """
    pg_target_url = os.environ.get("PG_TARGET_URL")
    if not pg_target_url:
        raise RuntimeError("PG_TARGET_URL is not set")

    import psycopg2
    with psycopg2.connect(pg_target_url) as conn:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(
                "SELECT setting, source, sourcefile FROM pg_settings WHERE name = %s",
                (param,),
            )
            row = cur.fetchone()
            if row is None:
                raise RuntimeError(f"Setting {param!r} not found in pg_settings")
            setting, source, sourcefile = row
            return (setting, source, sourcefile)


def run_action(conn, action: dict):
    """Execute render_action(action) elements in order using the provided connection.

    Args:
        conn: psycopg2 connection with autocommit=True
        action: dict with keys "action", "param", and optionally "value"
    """
    from app.services.fix_unit_render import render_action

    statements = render_action(action)
    with conn.cursor() as cur:
        for stmt in statements:
            cur.execute(stmt)


def set_log_connections_via_alter_system(conn, value: str):
    """Set log_connections via ALTER SYSTEM + reload."""
    run_action(conn, {"action": "set_config", "param": "log_connections", "value": value})


@pytest.mark.live
class TestFixUnitLive:
    """Live apply/rollback tests against pg-target."""

    def test_set_config_live_default_prior(self, target_db, log_connections_reset):
        """Test set_config with default prior (sourcefile NULL).

        Expected:
        - Prior state: sourcefile must be NULL (default)
        - Rollback action must be reset_config
        - After rollback: both setting and sourcefile equal prior values
        - Finally block: restore to DEFAULT state (ALTER SYSTEM RESET)
        """
        # a. prior_state = fresh_setting("log_connections")
        prior_setting, prior_source, prior_sourcefile = fresh_setting("log_connections")

        # If sourcefile is not NULL at the start, FAIL with message
        if prior_sourcefile is not None:
            pytest.fail(
                f"target is not in its default state: log_connections={prior_setting!r}, "
                f"sourcefile={prior_sourcefile!r}. Expected sourcefile=None (default)."
            )

        # b. Build fix unit from valid_fix_unit with prior_state and precheck from (a)
        valid = load_valid_fix_unit()
        prior_value = prior_setting
        apply_action = {
            "action": "set_config",
            "param": "log_connections",
            "value": "on" if prior_value != "on" else "off",  # OPPOSITE of prior
        }
        rollback_action = derive_rollback(
            {"value": prior_value, "sourcefile": prior_sourcefile},
            apply_action
        )

        fix_unit = {
            **valid,
            "prior_state": {
                "value": prior_value,
                "source": prior_source,
                "context": "user",
                "sourcefile": prior_sourcefile,
            },
            "precheck": {
                "expected_value": prior_value,
                "query": "SHOW log_connections",
            },
            "apply": apply_action,
            "rollback": rollback_action,
        }

        errors = validate_fix_unit(fix_unit)
        assert errors == [], errors

        # c. run_action(target_db, apply)
        run_action(target_db, apply_action)

        # d. Assert via fresh_setting that value is now applied value
        # Note: log_connections applies to NEW sessions after reload;
        # current session keeps old value, so we check a new connection
        new_setting, _, _ = fresh_setting("log_connections")
        expected_value = apply_action["value"]
        assert new_setting == expected_value, (
            f"After apply, expected log_connections={expected_value!r}, "
            f"got {new_setting!r}"
        )

        # e. run_action(target_db, rollback); assert via fresh_setting
        run_action(target_db, rollback_action)

        # After rollback, both setting and sourcefile should equal prior values
        final_setting, final_source, final_sourcefile = fresh_setting("log_connections")
        assert final_setting == prior_value, (
            f"After rollback, expected log_connections={prior_value!r}, "
            f"got {final_setting!r}"
        )
        assert final_sourcefile == prior_sourcefile, (
            f"After rollback, expected sourcefile={prior_sourcefile!r}, "
            f"got {final_sourcefile!r}"
        )

        # f. Finally: restore to DEFAULT state (handled by log_connections_reset fixture)

    def test_set_config_live_auto_conf_prior(self, target_db, log_connections_reset):
        """Test set_config with ALTER SYSTEM prior (sourcefile ends with postgresql.auto.conf).

        Expected:
        - Prior state: sourcefile must end with postgresql.auto.conf
        - Rollback action must be set_config(param, prior.value)
        - After rollback: both setting and sourcefile equal prior values
        - Finally block: restore to DEFAULT state (ALTER SYSTEM RESET + reload)
        """
        # First, set log_connections via ALTER SYSTEM to ensure sourcefile ends with postgresql.auto.conf
        prior_setting, prior_source, prior_sourcefile = fresh_setting("log_connections")

        # If sourcefile doesn't end with postgresql.auto.conf, set it via ALTER SYSTEM first
        if prior_sourcefile is None or not prior_sourcefile.endswith("postgresql.auto.conf"):
            # Set log_connections to 'on' via ALTER SYSTEM
            set_log_connections_via_alter_system(target_db, "on")
            # Verify the state changed to auto.conf
            new_setting, new_source, new_sourcefile = fresh_setting("log_connections")
            if new_sourcefile is None or not new_sourcefile.endswith("postgresql.auto.conf"):
                pytest.fail(
                    f"Could not set log_connections via ALTER SYSTEM: "
                    f"got sourcefile={new_sourcefile!r}. Expected sourcefile ending with postgresql.auto.conf."
                )
            prior_setting, prior_source, prior_sourcefile = new_setting, new_source, new_sourcefile

        # a. prior_state = fresh_setting("log_connections")
        prior_value = prior_setting

        # b. Build fix unit
        valid = load_valid_fix_unit()
        apply_action = {
            "action": "set_config",
            "param": "log_connections",
            "value": "on" if prior_value != "on" else "off",  # OPPOSITE of prior
        }
        rollback_action = derive_rollback(
            {"value": prior_value, "sourcefile": prior_sourcefile},
            apply_action
        )

        # Assert rollback action is set_config (not reset_config)
        assert rollback_action["action"] == "set_config", (
            f"For prior from auto.conf, rollback must be set_config, got {rollback_action!r}"
        )

        fix_unit = {
            **valid,
            "prior_state": {
                "value": prior_value,
                "source": prior_source,
                "context": "user",
                "sourcefile": prior_sourcefile,
            },
            "precheck": {
                "expected_value": prior_value,
                "query": "SHOW log_connections",
            },
            "apply": apply_action,
            "rollback": rollback_action,
        }

        errors = validate_fix_unit(fix_unit)
        assert errors == [], errors

        # c. run_action(target_db, apply)
        run_action(target_db, apply_action)

        # d. Assert via fresh_setting that value is now applied value
        new_setting, _, _ = fresh_setting("log_connections")
        expected_value = apply_action["value"]
        assert new_setting == expected_value, (
            f"After apply, expected log_connections={expected_value!r}, "
            f"got {new_setting!r}"
        )

        # e. run_action(target_db, rollback); assert via fresh_setting
        run_action(target_db, rollback_action)

        final_setting, final_source, final_sourcefile = fresh_setting("log_connections")
        assert final_setting == prior_value, (
            f"After rollback, expected log_connections={prior_value!r}, "
            f"got {final_setting!r}"
        )
        assert final_sourcefile == prior_sourcefile, (
            f"After rollback, expected sourcefile={prior_sourcefile!r}, "
            f"got {final_sourcefile!r}"
        )

        # f. Finally: restore to DEFAULT state (handled by log_connections_reset fixture)
