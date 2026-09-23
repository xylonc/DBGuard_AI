"""Live tests against pg-target database.

This module provides:
- target_db fixture: psycopg2 connection via PG_TARGET_URL with autocommit=True
- fresh_setting(param): helper to read pg_settings with a fresh connection
- run_action(conn, action): helper to execute render_action(action) elements in order
"""

import os
import psycopg2
import pytest
from typing import Tuple


def pytest_configure(config):
    """Register the 'live' marker."""
    config.addinivalue_line(
        "markers", "live: marks tests that require a live pg-target database connection"
    )


@pytest.fixture(scope="module")
def target_db():
    """Create a psycopg2 connection to pg-target with autocommit=True.

    If PG_TARGET_URL is unset or the connection fails, fail with a clear message.
    """
    pg_target_url = os.environ.get("PG_TARGET_URL")
    if not pg_target_url:
        pytest.fail("PG_TARGET_URL is not set; cannot connect to pg-target")

    try:
        conn = psycopg2.connect(pg_target_url)
        conn.autocommit = True
        yield conn
        conn.close()
    except psycopg2.OperationalError as e:
        pytest.fail(f"Failed to connect to pg-target: {e}")


@pytest.fixture(scope="module")
def log_connections_reset(target_db):
    """Reset log_connections to default state after tests.
    
    Uses yield to ensure reset runs even if tests fail.
    """
    try:
        yield
    finally:
        # Reset log_connections to default (ALTER SYSTEM RESET + reload)
        with target_db.cursor() as cur:
            cur.execute("ALTER SYSTEM RESET log_connections")
            cur.execute("SELECT pg_reload_conf()")


def fresh_setting(param: str) -> Tuple[str, str, str | None]:
    """Read a setting from pg_settings with a fresh connection.

    Returns:
        Tuple of (setting, source, sourcefile) where sourcefile may be None.
    """
    pg_target_url = os.environ.get("PG_TARGET_URL")
    if not pg_target_url:
        raise RuntimeError("PG_TARGET_URL is not set")

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
