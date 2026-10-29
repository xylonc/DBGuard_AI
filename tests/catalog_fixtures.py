"""Baseline sections for catalog (F6) checks, shared by unit tests.

Every section comes from real collector output, deep-copied so a test can
change it freely:

- All sections are copied from tests/fixtures/phase1/snapshot-pg17-live.json,
  re-recorded from a disposable PG17 with the applied collector (never edited
  here). On that fresh cluster ``functions`` is ``[]`` and ``archiving`` has
  archive_mode off and zero counters.
- ``DRY_RUN_FUNCTIONS`` are two non-empty ``functions`` rows from the collector's
  Gate-1 dry run (a SET-clause function and a SECURITY DEFINER function), for
  tests that need rows. Their keys are checked against collector/collect.sql in
  test_catalog_checks.TestFixtures.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
LIVE_FIXTURE = REPO_ROOT / "tests" / "fixtures" / "phase1" / "snapshot-pg17-live.json"

# Collected by the collector; read by at least one catalog evaluator.
CATALOG_SECTIONS = ("identity", "roles", "role_memberships", "password_types", "databases",
                    "object_acls", "rls_policies", "hba_rules", "replication", "functions", "archiving")

# Dry run of the collector's functions section on a cluster with two such functions.
DRY_RUN_FUNCTIONS = [
    {"acl": ["postgres=X/postgres"], "kind": "f", "name": "cfg", "owner": "postgres",
     "schema": "public", "language": "sql", "extension": None, "prosecdef": False,
     "search_path": "public, pg_temp", "config_names": ["work_mem", "search_path"],
     "identity_args": ""},
    {"acl": ["=X/postgres", "postgres=X/postgres"], "kind": "f", "name": "sd", "owner": "postgres",
     "schema": "public", "language": "sql", "extension": None, "prosecdef": True,
     "search_path": None, "config_names": [], "identity_args": ""},
]


def live_snapshot() -> dict:
    """A deep copy of the real collector snapshot."""
    return json.loads(LIVE_FIXTURE.read_text(encoding="utf-8"))


def catalog_sections(connected: str | None = None) -> dict:
    """Baseline sections catalog evaluators read, from real collector output.

    ``connected`` is the snapshot's envelope.database. A real collector always
    lists the database it connected to (and the bootstrap superuser, oid 10), so
    the fixture's connected database row is renamed to match it.
    """
    snapshot = live_snapshot()
    baseline = snapshot["baseline"]
    sections = {name: copy.deepcopy(baseline[name]) for name in CATALOG_SECTIONS}
    if connected is not None:
        fixture_db = snapshot["envelope"]["database"]
        for row in sections["databases"]:
            if row["datname"] == fixture_db:
                row["datname"] = connected
        assert any(r["datname"] == connected for r in sections["databases"])
    assert any(str(r["oid"]) == "10" for r in sections["roles"])
    return sections
