"""Tests for POST /api/v1/runs — acceptance contract validation.

Runs four scenarios from the spec:
  1. Valid collector evidence — accepted
  2. Missing required section — rejected (422)
  3. Wrong PostgreSQL major version — rejected (422)
  4. Bundle with gaps — accepted
"""

import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# Ensure the backend package is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tests.test_app import app  # noqa: E402

client = TestClient(app)

# ── fixtures ────────────────────────────────────────────────────────────────

# Smallest realistic bundle that satisfies every Pydantic model.
# Derived from the actual collector contract (collect.sql).

VALID_BUNDLE = {
    "envelope": {
        "schema_version": "0.2.0",
        "collector_version": "2.0.0-sql",
        "collected_at": "2025-01-01T00:00:00Z",
        "target_id": "testbox",
        "database": "postgres",
        "collected_by": "postgres",
        "is_superuser": True,
        "has_pg_monitor": False,
        "has_read_all_settings": True,
        "can_read_pg_authid": True,
        "deployment_type": "self-managed",
    },
    "identity": {
        "version_full": "PostgreSQL 16.x on x86_64-pc-linux-gnu",
        "server_version_num": 160003,
        "server_encoding": "UTF8",
        "lc_collate": "C.UTF-8",
        "lc_ctype": "C.UTF-8",
        "block_size": 8192,
        "wal_segment_size": "16777216",
        "data_checksums": "on",
        "data_directory": "/var/lib/postgresql/16/main",
        "system_identifier": "7384698992840567211",
    },
    "settings": [
        {
            "name": "max_connections",
            "setting": "100",
            "unit": None,
            "category": "Resource Usage",
            "context": "sighup",
            "vartype": "integer",
            "source": "configuration file",
            "sourcefile": "/etc/postgresql/16/main/postgresql.conf",
            "sourceline": 42,
            "boot_val": "100",
            "reset_val": "100",
            "pending_restart": False,
            "sanitised": False,
        }
    ],
    "roles": [
        {
            "rolname": "postgres",
            "oid": 10,
            "rolsuper": True,
            "rolinherit": True,
            "rolcreaterole": True,
            "rolcreatedb": True,
            "rolcanlogin": True,
            "rolreplication": False,
            "rolbypassrls": True,
            "rolconnlimit": -1,
            "rolvaliduntil": None,
            "is_predefined": True,
        }
    ],
    "role_memberships": [],
    "password_types": [
        {"rolname": "postgres", "password_type": "scram-sha-256", "rolvaliduntil": None},
        {"rolname": "md5_canary", "password_type": "md5", "rolvaliduntil": None},
    ],
    "role_settings": [],
    "databases": [
        {
            "datname": "postgres",
            "owner": "postgres",
            "encoding": "UTF8",
            "datcollate": "C.UTF-8",
            "datctype": "C.UTF-8",
            "datallowconn": True,
            "datconnlimit": -1,
            "datistemplate": False,
            "datacl": None,
        }
    ],
    "schemas": [
        {
            "nspname": "public",
            "owner": "postgres",
            "nspacl": None,
            "public_has_create": True,
            "public_has_usage": True,
        }
    ],
    "object_acls": [],
    "default_acls": [],
    "rls_policies": [],
    "extensions": [],
    "tablespaces": [
        {
            "spcname": "pg_default",
            "owner": "postgres",
            "acl": None,
            "location": None,
        }
    ],
    "foreign_servers": [],
    "event_triggers": [],
    "hba_rules": [],
    "ident_mappings": [],
    "file_settings": [],
    "replication": {
        "slots": [],
        "publications": [],
        "subscriptions": None,
        "primary_conninfo_parsed": None,
        "in_recovery": False,
    },
    "connections": [],
    "uptime": {
        "postmaster_start_time": "2025-01-01 00:00:00 UTC",
        "uptime_seconds": 3600,
    },
    "gaps": [],
    "redactions": [
        {
            "field": "pg_authid.rolpassword",
            "class": "S0",
            "note": "Password verifiers are never selected.",
        },
        {
            "field": "pg_settings.archive_command",
            "class": "S2",
            "note": "Command structure preserved; embedded credentials masked.",
        },
    ],
    "host_not_collected": [
        "pgdata_directory_permissions",
        "postgres_os_user_umask",
    ],
}


# ── helpers ─────────────────────────────────────────────────────────────────


def _post_run(bundle: dict) -> tuple[int, dict]:
    """POST to /api/v1/runs and return (status_code, response_body)."""
    r = client.post("/api/v1/runs", json={"target_evidence": bundle})
    return r.status_code, r.json() if r.status_code < 400 else r.json()


# ── tests ───────────────────────────────────────────────────────────────────


def test_01_valid_collector_evidence():
    """Test 1 — Valid collector evidence is accepted."""
    status, body = _post_run(VALID_BUNDLE)
    assert status == 200, f"Expected 200, got {status}"
    assert body["status"] == "validated"
    assert body["target_engine"] == "postgresql"
    assert body["target_major_version"] == 16
    assert body["collector_schema_version"] == "0.2.0"
    assert "run_id" in body
    import uuid
    uuid.UUID(body["run_id"])


def test_02_missing_required_section():
    """Test 2 — Missing required section (identity) is rejected."""
    bundle = dict(VALID_BUNDLE)
    del bundle["identity"]
    status, body = _post_run(bundle)
    assert status == 422, f"Expected 422, got {status}"
    assert "detail" in body
    detail_str = str(body["detail"])
    assert "identity" in detail_str, f"Expected 'identity' in error, got: {detail_str}"


def test_03_wrong_postgresql_major_version():
    """Test 3 — Non-PG16 server_version_num is rejected."""
    bundle = dict(VALID_BUNDLE)
    bundle["identity"] = dict(VALID_BUNDLE["identity"])
    bundle["identity"]["server_version_num"] = 150003  # PostgreSQL 15.3
    status, body = _post_run(bundle)
    assert status == 422, f"Expected 422, got {status}"
    detail_str = str(body["detail"])
    assert "15" in detail_str, f"Expected '15' in version error, got: {detail_str}"


def test_04_evidence_with_gaps():
    """Test 4 — Bundle with legitimate gaps is accepted."""
    bundle = dict(VALID_BUNDLE)
    bundle["gaps"] = [
        {
            "section": "password_types",
            "reason": "insufficient_privilege",
            "remediation": "Run grant_collector_role.sql, or grant the collector membership of a role that can read pg_authid.",
        },
        {
            "section": "hba_rules",
            "reason": "not_applicable_version",
            "remediation": "pg_hba_file_rules requires superuser or explicit SELECT.",
        },
    ]
    status, body = _post_run(bundle)
    assert status == 200, f"Expected 200, got {status}"
    assert body["status"] == "validated"
    import uuid
    uuid.UUID(body["run_id"])


# ── route registration tests ────────────────────────────────────────────────


def test_routes_are_registered():
    """Verify route registration on each router module.

    This test inspects the router objects directly — it does NOT
    import main.py (which would trigger heavy deps: vector_service
    → openai network call → timeout).

    The routes on the router objects are exactly what FastAPI will
    expose once include_router() is called, so this is authoritative.
    """
    from app.runs_endpoint import router as runs_router
    from app.templates_endpoint import router as templates_router

    # ── Runs endpoint ─────────────────────────────────────────────────
    runs_routes = [
        (r.path, frozenset(r.methods))
        for r in runs_router.routes
        if hasattr(r, "path") and hasattr(r, "methods")
    ]
    assert ("/api/v1/runs", frozenset({"POST"})) in runs_routes, \
        f"Missing POST /api/v1/runs — routes: {runs_routes}"

    # ── Template endpoints ────────────────────────────────────────────
    template_routes = [
        (r.path, frozenset(r.methods))
        for r in templates_router.routes
        if hasattr(r, "path") and hasattr(r, "methods")
    ]
    expected = [
        ("/api/v1/templates/ingest-all", frozenset({"POST"})),
        ("/api/v1/templates/ingest", frozenset({"POST"})),
        ("/api/v1/templates/search", frozenset({"GET"})),
    ]
    for path, methods in expected:
        assert (path, methods) in template_routes, \
            f"Missing {methods} {path} — routes: {template_routes}"

    # ── Health check (from main.py, verified by reading source file) ────
    # We read the file directly because importing main.py triggers the full
    # import chain (templates_endpoint → vector_service → openai),
    # which hangs in this environment.
    from pathlib import Path
    main_source = Path(__file__).resolve().parent.parent / "app" / "main.py"
    source = main_source.read_text()
    assert '@app.get("/api/v1/health")' in source, \
        "GET /api/v1/health endpoint not found in main.py"
    assert "app.include_router(runs_router)" in source, \
        "runs_router not included in main.py"
    assert "app.include_router(templates_router)" in source, \
        "templates_router not included in main.py"
