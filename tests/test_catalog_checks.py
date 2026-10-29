"""Unit tests for the F6 `catalog` check kind (Tier A: no Docker, network or model).

Every snapshot here starts from the real collector fixture
(tests/fixtures/phase1/snapshot-pg17-live.json, re-recorded with the applied
collector, deep-copied, never edited). snap() adds two real dry-run `functions`
rows so 4.5 has rows to read (tests/catalog_fixtures.py). Tests change one thing
at a time in code.

Covered: each evaluator's reachable outcomes (result, explanation code and facts,
evidence content), the GAPPED rules (null / gapped / missing field / wrong major,
and `[]` is not GAPPED), the 7.4 decision order, validator and schema negatives,
"never a fix" (fix_scope, ASSESS metadata, sandbox manifest), assess() rows,
no secrets in any output, and purity.
"""
from __future__ import annotations

import copy
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import jsonschema
import pytest

from app.models import FindingStatus
from app.services.spec_engine import RecordsIndex, assess, load_spec, validate_spec
from app.services.spec_engine import catalog_checks
from app.services.spec_engine.catalog_checks import REGISTRY, WAL_ARCHIVE_MAX_AGE_HOURS, evaluate
from app.services.spec_engine.manifest import manifest_from_specs
from tests.catalog_fixtures import DRY_RUN_FUNCTIONS, catalog_sections, live_snapshot

REPO_ROOT = Path(__file__).resolve().parent.parent
SPEC_DIR = REPO_ROOT / "catalog" / "specs" / "cis-pg17-v1.1.0"
RECORDS = RecordsIndex.load(REPO_ROOT / "catalog" / "benchmarks" / "cis-pg17-v1.1.0" / "records.json")
ALL_SPECS = [load_spec(p) for p in sorted(SPEC_DIR.glob("*.yaml"))]
SPECS = {s["ref"]["recommendation"]: s for s in ALL_SPECS if s.get("check", {}).get("kind") == "catalog"}
CATALOG_RECS = ("4.3", "4.4", "4.5", "4.6", "4.7", "4.9", "4.10", "5.5", "7.1", "7.4")
EVALUATOR_OF = {"4.3": "roles_with_admin_attributes", "4.4": "login_roles", "4.5": "elevated_functions",
                "4.6": "table_dml_grants", "4.7": "rls_tables_and_bypass_roles", "4.9": "superuser_roles",
                "4.10": "login_roles_without_password", "5.5": "role_connection_limits",
                "7.1": "replication_roles", "7.4": "wal_archiving"}
SPEC_SCHEMA = json.loads((REPO_ROOT / "catalog" / "specs" / "schema.json").read_text(encoding="utf-8"))
REPORT_CONTRACT = json.loads(
    (REPO_ROOT / "catalog" / "specs" / "contracts" / "assessment-report-v1.json").read_text(encoding="utf-8"))

# The live fixture's collection time (envelope.collected_at). Read from the fixture,
# so a re-recording moves every 7.4 timestamp built relative to it.
COLLECTED_AT = live_snapshot()["envelope"]["collected_at"]
COLLECTED = datetime.fromisoformat(COLLECTED_AT.replace("Z", "+00:00"))


# ---------------------------------------------------------------------------
# Builders. Shapes match collector/collect.sql.
# ---------------------------------------------------------------------------

def snap() -> dict:
    """Live fixture (functions: [] on that fresh cluster) + two dry-run function rows."""
    s = live_snapshot()
    s["baseline"].update(catalog_sections())
    assert s["baseline"]["functions"] == []
    s["baseline"]["functions"] = copy.deepcopy(DRY_RUN_FUNCTIONS)
    return s


def only_connected_db(s: dict) -> dict:
    """Drop every connectable non-template database except the connected one."""
    connected = s["envelope"]["database"]
    s["baseline"]["databases"] = [d for d in s["baseline"]["databases"]
                                  if d["datname"] == connected or d["datistemplate"]]
    return s


def role(name, oid, *, login=True, limit=-1, superuser=False, createrole=False, createdb=False,
         replication=False, bypassrls=False, validuntil=None) -> dict:
    return {"is_predefined": name.startswith("pg_"), "oid": str(oid), "rolbypassrls": bypassrls,
            "rolcanlogin": login, "rolconnlimit": limit, "rolcreatedb": createdb,
            "rolcreaterole": createrole, "rolinherit": True, "rolname": name,
            "rolreplication": replication, "rolsuper": superuser, "rolvaliduntil": validuntil}


def predefined(s: dict) -> list[dict]:
    return [r for r in s["baseline"]["roles"] if r["rolname"].startswith("pg_")]


def function(name, *, schema="public", owner="postgres", prosecdef=True, search_path=None,
             config_names=(), acl=("=X/postgres", "postgres=X/postgres"), extension=None,
             identity_args="") -> dict:
    return {"acl": list(acl), "kind": "f", "name": name, "owner": owner, "schema": schema,
            "language": "sql", "extension": extension, "prosecdef": prosecdef,
            "search_path": search_path, "config_names": list(config_names), "identity_args": identity_args}


def iso(dt: datetime) -> str:
    return dt.isoformat()


def archiving(*, mode="on", library="", command=True, archived_count=10, failed_count=0,
              last_archived=COLLECTED - timedelta(minutes=5), last_failed=None,
              stats_reset=COLLECTED - timedelta(days=30)) -> dict:
    def t(v):
        return iso(v) if isinstance(v, datetime) else v
    return {"archive_mode": mode, "archive_library": library, "archive_command_is_set": command,
            "stat_archiver": {"archived_count": archived_count, "failed_count": failed_count,
                              "last_archived_wal": "0000000100000000000000AA" if last_archived else None,
                              "last_archived_time": t(last_archived),
                              "last_failed_wal": "0000000100000000000000AB" if last_failed else None,
                              "last_failed_time": t(last_failed), "stats_reset": t(stats_reset)}}


def run(rec: str, s: dict) -> dict:
    return evaluate(SPECS[rec], s)


def gap(section: str, reason: str = "insufficient_privilege") -> dict:
    return {"section": section, "reason": reason, "remediation": "test"}


def assert_gapped(out: dict, explanation: dict) -> None:
    assert out["result"] == "GAPPED"
    assert out["explanation"] == explanation
    assert out["evidence"] == []


# ---------------------------------------------------------------------------
# Test inputs themselves
# ---------------------------------------------------------------------------

class TestFixtures:
    def test_every_catalog_spec_is_installed_and_wired(self):
        assert set(SPECS) == set(CATALOG_RECS)
        for rec, name in EVALUATOR_OF.items():
            assert SPECS[rec]["check"]["evaluator"] == name
            assert REGISTRY[name].recommendation == rec
        assert set(REGISTRY) == set(EVALUATOR_OF.values())

    def test_builders_match_real_collector_row_keys(self):
        s = live_snapshot()
        assert set(role("x", 1)) == set(s["baseline"]["roles"][0])
        assert set(archiving()) == set(s["baseline"]["archiving"])
        assert set(archiving()["stat_archiver"]) == set(s["baseline"]["archiving"]["stat_archiver"])
        # The fixture's functions is [] (fresh cluster): check row keys against the collector SQL.
        sql = (REPO_ROOT / "collector" / "collect.sql").read_text(encoding="utf-8")
        body = sql[sql.index("CREATE FUNCTION pg_temp.sql_functions()"):]
        body = body[:body.index("LANGUAGE sql")]
        keys = set(re.findall(r"^\s*'([a-z_]+)',", body, flags=re.MULTILINE))
        assert set(function("x")) == keys == set(DRY_RUN_FUNCTIONS[0]) == set(DRY_RUN_FUNCTIONS[1])

    def test_collection_time_comes_from_the_recorded_fixture(self):
        assert COLLECTED_AT.endswith("Z")
        assert COLLECTED.tzinfo is not None
        assert live_snapshot()["envelope"]["collected_at"] == COLLECTED_AT

    def test_live_fixture_is_not_mutated_by_builders(self):
        s = snap()
        s["baseline"]["roles"].clear()
        assert live_snapshot()["baseline"]["roles"]


# ---------------------------------------------------------------------------
# GAPPED rules shared by every evaluator
# ---------------------------------------------------------------------------

REQUIRED = [(rec, section) for rec in CATALOG_RECS
            for section in REGISTRY[EVALUATOR_OF[rec]].required_sections]
ROLES_READERS = ("4.3", "4.4", "4.6", "4.7", "4.9", "4.10", "5.5", "7.1")
DATABASES_READERS = ("4.5", "4.6", "4.7")
# Sections (required or optional) where [] is a legitimate collected value
# (e.g. a fresh cluster has no SECURITY DEFINER functions, ACL'd tables,
# policies or replication slots). roles, databases and password_types are not
# in this list: [] there contradicts the bootstrap superuser / connected database.
LEGIT_EMPTY = [("4.5", "functions"), ("4.6", "object_acls"), ("4.6", "role_memberships"),
               ("4.7", "object_acls"), ("4.7", "rls_policies"), ("4.10", "hba_rules"),
               ("7.1", "hba_rules"), ("7.1", "replication.slots")]


class TestIncompleteListsNeverPass:
    """(1) roles must contain the bootstrap superuser; (2) databases must list the connected DB."""

    def test_partial_roles_cannot_pass_5_5(self):
        s = snap()
        # Every listed role has a limit, but the bootstrap superuser (oid 10) is missing.
        s["baseline"]["roles"] = [role("app", 16384, limit=20), role("etl", 16385, limit=5)] + predefined(s)
        assert_gapped(run("5.5", s), {"code": "field_missing", "section": "roles", "field": "oid"})
        s["baseline"]["roles"].append(role("postgres", 10, superuser=True, limit=3))
        assert run("5.5", s)["result"] == "PASS"

    def test_partial_roles_cannot_pass_4_10(self):
        s = snap()
        s["baseline"]["roles"] = [role("app", 16384)] + predefined(s)
        s["baseline"]["password_types"] = [{"rolname": "app", "password_type": "scram-sha-256",
                                            "rolvaliduntil": None}]
        assert_gapped(run("4.10", s), {"code": "field_missing", "section": "roles", "field": "oid"})

    def test_bootstrap_is_found_by_oid_not_by_name(self):
        s = snap()
        s["baseline"]["roles"] = [role("postgres", 16384, superuser=True, limit=3),
                                  role("cluster_admin", 10, superuser=True, limit=3)] + predefined(s)
        out = run("5.5", s)
        assert out["result"] == "PASS"
        s["baseline"]["roles"] = [role("postgres", 16384, superuser=True, limit=3)] + predefined(s)
        assert run("5.5", s)["explanation"] == {"code": "field_missing", "section": "roles", "field": "oid"}

    @pytest.mark.parametrize("oid", [10, "10"])
    def test_bootstrap_oid_as_number_or_text(self, oid):
        s = snap()
        s["baseline"]["roles"][0]["oid"] = oid
        assert run("5.5", s)["result"] == "FAIL"

    @pytest.mark.parametrize("rec", ROLES_READERS)
    def test_roles_without_bootstrap_are_gapped_for_every_roles_reader(self, rec):
        s = only_connected_db(snap())
        s["baseline"]["roles"] = predefined(s)
        assert_gapped(run(rec, s), {"code": "field_missing", "section": "roles", "field": "oid"})

    def test_databases_without_connected_db_cannot_pass_4_5(self):
        s = only_connected_db(snap())
        s["baseline"]["functions"] = []
        assert run("4.5", s)["result"] == "PASS"
        s["baseline"]["databases"] = [d for d in s["baseline"]["databases"] if d["datistemplate"]]
        assert_gapped(run("4.5", s), {"code": "field_missing", "section": "databases", "field": "datname"})

    @pytest.mark.parametrize("rec", DATABASES_READERS)
    def test_connected_db_missing_while_others_listed_is_gapped(self, rec):
        s = snap()
        s["baseline"]["databases"] = [d for d in s["baseline"]["databases"] if d["datname"] != "dbguard_sandbox"]
        assert {d["datname"] for d in s["baseline"]["databases"]} == {"postgres", "template0", "template1"}
        assert_gapped(run(rec, s), {"code": "field_missing", "section": "databases", "field": "datname"})

    def test_connected_db_must_match_exactly(self):
        s = only_connected_db(snap())
        s["baseline"]["functions"] = []
        s["envelope"]["database"] = "DBGUARD_SANDBOX"
        assert run("4.5", s)["explanation"] == {"code": "field_missing", "section": "databases",
                                                "field": "datname"}


class TestGapReasonAndCounters:
    """(4) gap_reason only when it is a string; negative archiver counters are unreadable."""

    @pytest.mark.parametrize("reason", [None, 42, {"detail": "x"}, ["insufficient_privilege"], True])
    def test_non_string_gap_reason_is_not_copied(self, reason):
        s = snap()
        s["baseline"]["functions"] = None
        s["baseline"]["gaps"] = [{"section": "functions", "reason": reason}]
        assert_gapped(run("4.5", s), {"code": "section_not_collected", "section": "functions"})

    def test_gap_record_without_reason_still_gaps(self):
        s = snap()
        s["baseline"]["gaps"] = [{"section": "roles"}]
        assert_gapped(run("5.5", s), {"code": "section_not_collected", "section": "roles"})

    def test_empty_string_gap_reason_is_a_string(self):
        s = snap()
        s["baseline"]["archiving"] = None
        s["baseline"]["gaps"] = [{"section": "archiving", "reason": ""}]
        assert run("7.4", s)["explanation"] == {"code": "section_not_collected", "section": "archiving",
                                                "gap_reason": ""}

    @pytest.mark.parametrize("field", ["archived_count", "failed_count"])
    @pytest.mark.parametrize("value", [-1, -100])
    def test_negative_counter_is_field_missing(self, field, value):
        s = wal()
        s["baseline"]["archiving"]["stat_archiver"][field] = value
        out = run("7.4", s)
        assert_gapped(out, {"code": "field_missing", "section": "archiving.stat_archiver", "field": field})
        assert out["evidence_paths"] == [f"archiving.stat_archiver.{field}"]

    @pytest.mark.parametrize("field", ["archived_count", "failed_count"])
    def test_zero_counter_is_readable(self, field):
        s = wal(archived_count=0, last_archived=None, stats_reset=None) if field == "archived_count" else wal()
        assert run("7.4", s)["result"] != "GAPPED"

    def test_negative_counter_does_not_mask_a_configuration_fail(self):
        s = wal(mode="off")
        s["baseline"]["archiving"]["stat_archiver"]["failed_count"] = -1
        assert run("7.4", s)["explanation"] == {"code": "archive_mode_off", "archive_mode": "off"}


class TestEvaluatorSectionLists:
    def test_reader_lists_match_the_registry(self):
        readers = lambda sec: tuple(r for r in CATALOG_RECS if sec in REGISTRY[EVALUATOR_OF[r]].required_sections)
        assert readers("roles") == ROLES_READERS
        assert readers("databases") == DATABASES_READERS
        for rec, section in LEGIT_EMPTY:
            entry = REGISTRY[EVALUATOR_OF[rec]]
            assert section.split(".")[0] in entry.required_sections + entry.optional_sections


class TestGappedRules:
    @pytest.mark.parametrize("rec", CATALOG_RECS)
    def test_wrong_pg_major_is_gapped_with_both_majors(self, rec):
        s = snap()
        s["baseline"]["identity"]["server_version_num"] = 160004
        out = run(rec, s)
        assert_gapped(out, {"code": "wrong_pg_major", "spec_pg_major": 17, "snapshot_pg_major": 16})
        assert out["evidence_paths"] == ["identity.server_version_num"]

    @pytest.mark.parametrize("rec", CATALOG_RECS)
    def test_identity_not_collected_is_gapped(self, rec):
        s = snap()
        s["baseline"]["identity"] = None
        assert_gapped(run(rec, s), {"code": "section_not_collected", "section": "identity"})

    @pytest.mark.parametrize("rec", CATALOG_RECS)
    def test_server_version_num_missing_is_field_missing(self, rec):
        s = snap()
        del s["baseline"]["identity"]["server_version_num"]
        assert_gapped(run(rec, s), {"code": "field_missing", "section": "identity",
                                    "field": "server_version_num"})

    @pytest.mark.parametrize("rec,section", REQUIRED)
    def test_null_section_with_gap_record_carries_gap_reason(self, rec, section):
        s = snap()
        s["baseline"][section] = None
        s["baseline"]["gaps"] = [gap(section)]
        out = run(rec, s)
        assert_gapped(out, {"code": "section_not_collected", "section": section,
                            "gap_reason": "insufficient_privilege"})
        assert out["evidence_paths"] == [section]

    @pytest.mark.parametrize("rec,section", REQUIRED)
    def test_absent_section_without_gap_record_has_no_gap_reason(self, rec, section):
        s = snap()
        del s["baseline"][section]
        assert_gapped(run(rec, s), {"code": "section_not_collected", "section": section})

    @pytest.mark.parametrize("rec,section", REQUIRED)
    def test_present_section_with_matching_gap_record_is_gapped(self, rec, section):
        """A gaps entry wins over data: the collector said it could not read the section."""
        s = snap()
        s["baseline"]["gaps"] = [gap(section, "permission denied for table pg_authid")]
        assert_gapped(run(rec, s), {"code": "section_not_collected", "section": section,
                                    "gap_reason": "permission denied for table pg_authid"})

    @pytest.mark.parametrize("rec,section", REQUIRED)
    def test_gap_record_for_another_section_does_not_gap(self, rec, section):
        s = snap()
        s["baseline"]["gaps"] = [gap("tablespaces")]
        assert run(rec, s)["result"] != "GAPPED"

    @pytest.mark.parametrize("rec,section", LEGIT_EMPTY)
    def test_collected_empty_list_is_not_section_not_collected(self, rec, section):
        """`[]` means collected and empty, never "not collected", where [] can be real."""
        s = only_connected_db(snap())
        if section == "replication.slots":
            s["baseline"]["replication"]["slots"] = []
        else:
            s["baseline"][section] = []
        out = run(rec, s)
        assert out["result"] != "GAPPED", out
        assert out["explanation"]["code"] not in ("section_not_collected", "field_missing")
        assert section not in out["explanation"].get("sections_not_collected", [])

    @pytest.mark.parametrize("rec", ROLES_READERS)
    def test_empty_roles_list_is_a_contract_violation(self, rec):
        """Every cluster has the bootstrap superuser, so roles == [] cannot be real."""
        s = only_connected_db(snap())
        s["baseline"]["roles"] = []
        out = run(rec, s)
        assert_gapped(out, {"code": "field_missing", "section": "roles", "field": "oid"})
        assert out["evidence_paths"] == ["roles.oid"]

    @pytest.mark.parametrize("rec", DATABASES_READERS)
    def test_empty_databases_list_is_a_contract_violation(self, rec):
        """The connected database is always listed, so databases == [] cannot be real."""
        s = snap()
        s["baseline"]["databases"] = []
        out = run(rec, s)
        assert_gapped(out, {"code": "field_missing", "section": "databases", "field": "datname"})
        assert out["evidence_paths"] == ["databases.datname"]

    def test_empty_password_types_with_login_roles_is_gapped_for_4_10(self):
        """password_types lists every login role; [] next to the bootstrap login role is incomplete."""
        s = snap()
        s["baseline"]["password_types"] = []
        assert_gapped(run("4.10", s), {"code": "field_missing", "section": "password_types",
                                       "field": "password_type"})

    @pytest.mark.parametrize("rec,section,field,mutate", [
        ("4.3", "roles", "rolbypassrls", lambda b: b["roles"][0].pop("rolbypassrls")),
        ("4.4", "roles", "rolcanlogin", lambda b: b["roles"][0].pop("rolcanlogin")),
        ("4.4", "roles", "rolvaliduntil", lambda b: b["roles"][0].pop("rolvaliduntil")),
        ("4.5", "functions", "extension", lambda b: b["functions"][0].pop("extension")),
        ("4.5", "functions", "acl", lambda b: b["functions"][0].update(acl=None)),
        ("4.5", "databases", "datallowconn", lambda b: b["databases"][1].pop("datallowconn")),
        # A membership row is read when its role matters (here pg_write_all_data).
        ("4.6", "role_memberships", "member", lambda b: b["role_memberships"].append(
            {"role": "pg_write_all_data", "grantor": "dbguard_poc", "admin_option": False})),
        ("4.6", "role_memberships", "role", lambda b: b["role_memberships"][0].pop("role")),
        ("4.7", "roles", "rolbypassrls", lambda b: b["roles"][0].pop("rolbypassrls")),
        ("4.9", "roles", "rolsuper", lambda b: b["roles"][0].pop("rolsuper")),
        ("4.9", "roles", "oid", lambda b: b["roles"][0].pop("oid")),
        ("4.10", "password_types", "password_type", lambda b: b["password_types"][0].pop("password_type")),
        ("5.5", "roles", "rolconnlimit", lambda b: b["roles"][0].pop("rolconnlimit")),
        ("5.5", "roles", "rolconnlimit", lambda b: b["roles"][0].update(rolconnlimit=True)),  # bool is not int
        ("5.5", "roles", "rolconnlimit", lambda b: b["roles"][0].update(rolconnlimit="-1")),
        ("7.1", "roles", "rolreplication", lambda b: b["roles"][0].pop("rolreplication")),
        ("7.4", "archiving", "archive_mode", lambda b: b["archiving"].pop("archive_mode")),
        ("7.4", "archiving", "archive_command_is_set",
         lambda b: b["archiving"].update(archive_command_is_set="true")),
    ])
    def test_required_field_missing_on_a_row_is_field_missing(self, rec, section, field, mutate):
        s = snap()
        mutate(s["baseline"])
        out = run(rec, s)
        assert_gapped(out, {"code": "field_missing", "section": section, "field": field})
        assert out["evidence_paths"] == [f"{section}.{field}"]

    def test_non_mapping_row_is_gapped(self):
        s = snap()
        s["baseline"]["roles"].append("dbguard_poc")
        assert_gapped(run("4.9", s), {"code": "field_missing", "section": "roles", "field": "row"})

    def test_wrong_section_shape_is_gapped_not_pass(self):
        s = snap()
        s["baseline"]["password_types"] = {"rolname": "dbguard_poc"}
        assert_gapped(run("4.10", s), {"code": "section_not_collected", "section": "password_types"})

    def test_gapped_result_drops_partial_sections_not_collected(self):
        """A GAPPED result has only the gap that caused it, no leftover optional-section notes."""
        s = snap()
        s["baseline"]["hba_rules"] = None
        s["baseline"]["gaps"] = [gap("hba_rules")]
        s["baseline"]["password_types"][0].pop("password_type")
        assert run("4.10", s)["explanation"] == {"code": "field_missing", "section": "password_types",
                                                 "field": "password_type"}

    def test_evaluate_rejects_a_non_catalog_or_rewired_spec(self):
        with pytest.raises(ValueError):
            evaluate(next(s for s in ALL_SPECS if s["spec_id"].endswith(":3.1.20")), snap())
        rewired = copy.deepcopy(SPECS["5.5"])
        rewired["check"]["evaluator"] = "superuser_roles"
        with pytest.raises(ValueError):
            evaluate(rewired, snap())
        unknown = copy.deepcopy(SPECS["5.5"])
        unknown["check"]["evaluator"] = "drop_everything"
        with pytest.raises(ValueError):
            evaluate(unknown, snap())


# ---------------------------------------------------------------------------
# 4.3 roles_with_admin_attributes: always MANUAL
# ---------------------------------------------------------------------------

class TestAdminAttributes43:
    def test_lists_non_predefined_roles_with_any_admin_attribute(self):
        s = snap()
        s["baseline"]["roles"] = [role("postgres", 10, superuser=True, createrole=True, createdb=True,
                                       replication=True, bypassrls=True),
                                  role("app_admin", 16384, createrole=True),
                                  role("etl", 16385, login=False, createdb=True),
                                  role("app", 16386)] + predefined(s)
        out = run("4.3", s)
        assert out["result"] == "MANUAL"
        assert out["explanation"] == {"code": "manual_review", "evidence_count": 3}
        assert out["evidence"] == [
            {"rolname": "app_admin", "rolsuper": False, "rolcreaterole": True, "rolcreatedb": False,
             "rolreplication": False, "rolbypassrls": False, "rolcanlogin": True, "bootstrap_superuser": False},
            {"rolname": "etl", "rolsuper": False, "rolcreaterole": False, "rolcreatedb": True,
             "rolreplication": False, "rolbypassrls": False, "rolcanlogin": False, "bootstrap_superuser": False},
            {"rolname": "postgres", "rolsuper": True, "rolcreaterole": True, "rolcreatedb": True,
             "rolreplication": True, "rolbypassrls": True, "rolcanlogin": True, "bootstrap_superuser": True},
        ]
        assert out["evidence_paths"] == ["roles"]

    def test_only_the_bootstrap_superuser_is_still_manual_never_pass(self):
        s = snap()
        s["baseline"]["roles"] = [role("postgres", 10, superuser=True), role("app", 16386)] + predefined(s)
        out = run("4.3", s)
        assert out["result"] == "MANUAL"
        assert out["explanation"] == {"code": "manual_review", "evidence_count": 1}
        assert [(e["rolname"], e["bootstrap_superuser"]) for e in out["evidence"]] == [("postgres", True)]

    def test_roles_without_the_bootstrap_superuser_are_gapped(self):
        s = snap()
        s["baseline"]["roles"] = [role("app", 16386)] + predefined(s)
        assert_gapped(run("4.3", s), {"code": "field_missing", "section": "roles", "field": "oid"})


# ---------------------------------------------------------------------------
# 4.4 login_roles: always MANUAL
# ---------------------------------------------------------------------------

class TestLoginRoles44:
    def test_lists_login_roles_with_validity_and_password_type(self):
        s = snap()
        s["baseline"]["roles"] = [role("dbguard_poc", 10, superuser=True),
                                  role("app", 16386, validuntil="2027-01-01T00:00:00+00:00"),
                                  role("group_only", 16387, login=False)] + predefined(s)
        s["baseline"]["password_types"] = [
            {"rolname": "app", "password_type": "md5", "rolvaliduntil": "2027-01-01T00:00:00+00:00"},
            {"rolname": "dbguard_poc", "password_type": "scram-sha-256", "rolvaliduntil": None}]
        out = run("4.4", s)
        assert out["result"] == "MANUAL"
        assert out["explanation"] == {"code": "manual_review", "evidence_count": 2}
        assert out["evidence"] == [
            {"rolname": "app", "rolsuper": False, "rolvaliduntil": "2027-01-01T00:00:00+00:00",
             "password_type": "md5"},
            {"rolname": "dbguard_poc", "rolsuper": True, "rolvaliduntil": None,
             "password_type": "scram-sha-256"}]

    def test_password_types_gapped_still_manual_and_shows_the_gap(self):
        s = snap()
        s["baseline"]["password_types"] = None
        s["baseline"]["gaps"] = [gap("password_types")]
        out = run("4.4", s)
        assert out["result"] == "MANUAL"
        assert out["evidence"] == [{"rolname": "dbguard_poc", "rolsuper": True, "rolvaliduntil": None,
                                    "password_type": None}]
        assert out["explanation"] == {"code": "manual_review", "evidence_count": 1,
                                      "sections_not_collected": ["password_types"]}


# ---------------------------------------------------------------------------
# 4.5 elevated_functions
# ---------------------------------------------------------------------------

class TestElevatedFunctions45:
    def test_empty_set_and_no_other_connectable_db_is_pass_empty_review_set(self):
        s = only_connected_db(snap())
        s["baseline"]["functions"] = []
        # template1 accepts connections and template0 does not: both are templates, so ignored.
        assert {(d["datname"], d["datallowconn"], d["datistemplate"]) for d in s["baseline"]["databases"]} == {
            ("dbguard_sandbox", True, False), ("template0", False, True), ("template1", True, True)}
        out = run("4.5", s)
        assert out["result"] == "PASS"
        assert out["explanation"] == {"code": "empty_review_set", "evidence_count": 0}
        assert out["evidence"] == []
        assert out["evidence_paths"] == ["functions", "databases", "envelope.database"]

    def test_empty_set_with_another_connectable_db_is_manual_never_pass(self):
        s = snap()  # the live fixture also has "postgres" (connectable, not a template)
        s["baseline"]["functions"] = []
        out = run("4.5", s)
        assert out["result"] == "MANUAL"
        assert out["explanation"] == {"code": "databases_not_covered", "evidence_count": 0,
                                      "databases": ["postgres"]}

    def test_non_connectable_non_template_db_is_ignored(self):
        s = only_connected_db(snap())
        s["baseline"]["databases"].append({**s["baseline"]["databases"][0], "datname": "frozen",
                                           "datallowconn": False})
        s["baseline"]["functions"] = []
        assert run("4.5", s)["result"] == "PASS"

    def test_other_dbs_listed_sorted_and_connected_db_excluded(self):
        s = snap()
        base = s["baseline"]["databases"][0]
        s["baseline"]["databases"] += [{**base, "datname": "zeta"}, {**base, "datname": "alpha"}]
        out = run("4.5", s)
        assert out["explanation"]["databases"] == ["alpha", "postgres", "zeta"]
        assert "dbguard_sandbox" not in out["explanation"]["databases"]

    def test_dry_run_functions_listed_with_owner_search_path_and_default_acl(self):
        s = only_connected_db(snap())
        out = run("4.5", s)
        assert out["result"] == "MANUAL"
        assert out["explanation"] == {"code": "manual_review", "evidence_count": 2}
        assert out["evidence"] == [
            {"schema": "public", "name": "cfg", "identity_args": "", "owner": "postgres", "prosecdef": False,
             "search_path": "public, pg_temp", "config_names": ["work_mem", "search_path"],
             "acl": ["postgres=X/postgres"], "extension": None},
            {"schema": "public", "name": "sd", "identity_args": "", "owner": "postgres", "prosecdef": True,
             "search_path": None, "config_names": [], "acl": ["=X/postgres", "postgres=X/postgres"],
             "extension": None}]
        # "=X/postgres": empty grantee = PUBLIC may EXECUTE the SECURITY DEFINER function.
        sd = out["evidence"][1]
        assert sd["prosecdef"] is True and "=X/postgres" in sd["acl"]

    def test_pgaudit_excluded_only_when_named_pgaudit_and_owned_by_pgaudit(self):
        s = only_connected_db(snap())
        s["baseline"]["functions"] = [
            function("pgaudit_ddl_command_end", extension="pgaudit"),   # excluded
            function("pgaudit_sql_drop", extension="pgaudit"),          # excluded
            function("pgaudit_helper", extension=None),                 # user function: in scope
            function("pgaudit_lookalike", extension="pageinspect"),     # other extension: in scope
            function("audit_wrapper", extension="pgaudit"),             # not named pgaudit%: in scope
        ]
        out = run("4.5", s)
        assert out["result"] == "MANUAL"
        assert [(e["name"], e["extension"]) for e in out["evidence"]] == [
            ("pgaudit_helper", None), ("pgaudit_lookalike", "pageinspect"), ("audit_wrapper", "pgaudit")]

    def test_only_pgaudit_extension_functions_is_pass(self):
        s = only_connected_db(snap())
        s["baseline"]["functions"] = [function("pgaudit_ddl_command_end", extension="pgaudit")]
        out = run("4.5", s)
        assert out["result"] == "PASS"
        assert out["explanation"]["code"] == "empty_review_set"

    def test_connected_database_missing_from_envelope_is_gapped(self):
        s = snap()
        del s["envelope"]["database"]
        assert_gapped(run("4.5", s), {"code": "field_missing", "section": "envelope", "field": "database"})

    def test_functions_section_gapped_carries_reason(self):
        s = snap()
        s["baseline"]["functions"] = None
        s["baseline"]["gaps"] = [gap("functions")]
        assert_gapped(run("4.5", s), {"code": "section_not_collected", "section": "functions",
                                      "gap_reason": "insufficient_privilege"})


# ---------------------------------------------------------------------------
# 4.6 table_dml_grants: always MANUAL
# ---------------------------------------------------------------------------

def table(name, acl, *, owner="app_owner", kind="r", rls=False, rls_forced=False, schema="public"):
    return {"schema": schema, "name": name, "kind": kind, "owner": owner, "acl": acl,
            "rls": rls, "rls_forced": rls_forced}


class TestTableDmlGrants46:
    def test_lists_dml_grantees_groups_superusers_and_write_all_data(self):
        s = only_connected_db(snap())
        b = s["baseline"]
        b["roles"] = [role("dbguard_poc", 10, superuser=True), role("app_owner", 16384),
                      role("app", 16385), role("writers", 16386, login=False), role("alice", 16387),
                      role("bob", 16388)] + predefined(s)
        b["role_memberships"] = [{"role": "writers", "member": "alice", "grantor": "dbguard_poc", "admin_option": False},
                                 {"role": "pg_write_all_data", "member": "bob", "grantor": "dbguard_poc",
                                  "admin_option": False}]
        b["object_acls"] = [
            table("orders", ["app_owner=arwdDxtm/app_owner", "=r/app_owner", "app=arw/app_owner",
                             "writers=d/app_owner"]),
            table("orders_view", ["=arwd/app_owner"], kind="v"),   # a view: not a pg_tables table
            table("audit", None, rls=True),                         # default ACL: owner only
        ]
        out = run("4.6", s)
        assert out["result"] == "MANUAL"
        assert out["explanation"] == {"code": "manual_review", "evidence_count": 5}
        base = {"type": "table_grant", "schema": "public", "table": "orders", "owner": "app_owner",
                "grantor": "app_owner"}
        assert out["evidence"] == [
            {**base, "privileges": ["INSERT", "UPDATE"], "grantee": "app", "via": None, "upper_bound": False},
            {**base, "privileges": ["DELETE"], "grantee": "writers", "via": None, "upper_bound": False},
            {**base, "privileges": ["DELETE"], "grantee": "alice", "via": "writers", "upper_bound": True},
            {"type": "superuser", "rolname": "dbguard_poc", "rolcanlogin": True},
            {"type": "pg_write_all_data_member", "rolname": "bob", "upper_bound": False},
        ]

    def test_public_dml_grant_is_shown_as_public(self):
        s = only_connected_db(snap())
        s["baseline"]["object_acls"] = [table("orders", ["app_owner=arwd/app_owner", "=w/app_owner"])]
        grants = [e for e in run("4.6", s)["evidence"] if e["type"] == "table_grant"]
        assert [(g["grantee"], g["privileges"]) for g in grants] == [("PUBLIC", ["UPDATE"])]

    def test_other_connectable_db_gives_databases_not_covered(self):
        out = run("4.6", snap())
        assert out["result"] == "MANUAL"
        assert out["explanation"]["code"] == "databases_not_covered"
        assert out["explanation"]["databases"] == ["postgres"]

    def test_unparseable_aclitem_is_gapped(self):
        s = snap()
        s["baseline"]["object_acls"] = [table("orders", ["app=arw"])]  # no grantor
        assert_gapped(run("4.6", s), {"code": "field_missing", "section": "object_acls", "field": "acl"})


# ---------------------------------------------------------------------------
# 4.7 rls_tables_and_bypass_roles: always MANUAL
# ---------------------------------------------------------------------------

def policy(tbl, name, *, cmd="SELECT", roles=("public",), schema="public"):
    return {"schema": schema, "table": tbl, "policy": name, "permissive": "PERMISSIVE",
            "roles": list(roles), "cmd": cmd, "qual": "(tenant = current_user)", "with_check": None}


class TestRls47:
    def test_rls_tables_policies_and_bypass_roles(self):
        s = only_connected_db(snap())
        b = s["baseline"]
        b["roles"] = [role("dbguard_poc", 10, superuser=True, bypassrls=True), role("app_owner", 16384),
                      role("auditor", 16385, bypassrls=True)] + predefined(s)
        b["object_acls"] = [table("accounts", None, rls=True, rls_forced=False),
                            table("ledger", None, owner="dbguard_poc", rls=True, rls_forced=True),
                            table("plain", ["app_owner=arwd/app_owner"])]
        b["rls_policies"] = [policy("accounts", "tenant_read"), policy("plain", "stale", cmd="ALL")]
        out = run("4.7", s)
        assert out["result"] == "MANUAL"
        assert out["explanation"] == {"code": "manual_review", "evidence_count": 6}
        assert out["evidence"] == [
            {"type": "rls_table", "schema": "public", "table": "accounts", "owner": "app_owner",
             "rls_forced": False, "policy_count": 1, "no_policies": False,
             "policies": [{"policy": "tenant_read", "cmd": "SELECT", "permissive": "PERMISSIVE",
                           "roles": ["public"]}]},
            {"type": "rls_table", "schema": "public", "table": "ledger", "owner": "dbguard_poc",
             "rls_forced": True, "policy_count": 0, "no_policies": True, "policies": []},
            {"type": "policy_without_rls", "schema": "public", "table": "plain", "policy": "stale",
             "cmd": "ALL", "permissive": "PERMISSIVE", "roles": ["public"]},
            {"type": "bypass_role", "rolname": "app_owner", "reasons": ["owner_of_non_forced_rls_table"],
             "rolsuper": False, "owned_non_forced_tables": ["public.accounts"]},
            {"type": "bypass_role", "rolname": "auditor", "reasons": ["bypassrls"], "rolsuper": False,
             "owned_non_forced_tables": []},
            {"type": "bypass_role", "rolname": "dbguard_poc", "reasons": ["bypassrls", "superuser"],
             "rolsuper": True, "owned_non_forced_tables": []},
        ]
        assert "tenant = current_user" not in json.dumps(out)  # policy expressions are never returned


# ---------------------------------------------------------------------------
# 4.9 superuser_roles: always MANUAL
# ---------------------------------------------------------------------------

class TestSuperusers49:
    def test_lists_every_superuser_with_login_and_bootstrap_flags(self):
        s = snap()
        s["baseline"]["roles"] = [role("postgres", 10, superuser=True), role("doug", 16384, superuser=True),
                                  role("break_glass", 16385, login=False, superuser=True),
                                  role("app", 16386)] + predefined(s)
        out = run("4.9", s)
        assert out["result"] == "MANUAL"
        assert out["explanation"] == {"code": "manual_review", "evidence_count": 3}
        assert out["evidence"] == [
            {"rolname": "break_glass", "rolcanlogin": False, "bootstrap_superuser": False},
            {"rolname": "doug", "rolcanlogin": True, "bootstrap_superuser": False},
            {"rolname": "postgres", "rolcanlogin": True, "bootstrap_superuser": True}]

    def test_integer_oid_from_collector_is_accepted(self):
        s = snap()
        s["baseline"]["roles"][0]["oid"] = 10
        assert run("4.9", s)["evidence"][0]["bootstrap_superuser"] is True


# ---------------------------------------------------------------------------
# 4.10 login_roles_without_password
# ---------------------------------------------------------------------------

def hba(line, *, users=("all",), databases=("all",), method="scram-sha-256", typ="host", error=None,
        options=None):
    return {"address": "all", "auth_method": method, "database": list(databases), "error": error,
            "line_number": line, "netmask": None, "options": options, "type": typ, "user_name": list(users)}


class TestLoginRolesWithoutPassword410:
    def _no_password(self, *rules):
        s = snap()
        s["baseline"]["roles"] = [role("dbguard_poc", 10, superuser=True), role("svc", 16384),
                                  role("nologin_group", 16385, login=False)] + predefined(s)
        s["baseline"]["password_types"] = [
            {"rolname": "dbguard_poc", "password_type": "scram-sha-256", "rolvaliduntil": None},
            {"rolname": "svc", "password_type": "none", "rolvaliduntil": None}]
        if rules:
            s["baseline"]["hba_rules"] = list(rules)
        return s

    def test_every_login_role_has_password_is_pass_empty_review_set(self):
        out = run("4.10", snap())
        assert out["result"] == "PASS"
        assert out["explanation"] == {"code": "empty_review_set", "evidence_count": 0}
        assert out["evidence"] == []

    def test_role_without_password_is_manual_with_matching_hba_rules_and_trust_highlighted(self):
        s = self._no_password(hba(10, users=("svc",), method="cert", typ="hostssl"),
                              hba(11, users=("bob",), method="trust"),          # another user: not shown
                              hba(12, users=("+admins",), method="md5"),        # group: may match
                              hba(13, method="trust", typ="local"),             # all: matches
                              hba(14, users=("svc",), method="ldap", error="bad option"))
        out = run("4.10", s)
        assert out["result"] == "MANUAL"
        assert out["explanation"] == {"code": "manual_review", "evidence_count": 1}
        [entry] = out["evidence"]
        assert entry["rolname"] == "svc" and entry["rolsuper"] is False
        assert [(r["line_number"], r["auth_method"], r["trust"], r["cis_named_non_password_method"],
                 r["has_error"]) for r in entry["hba_rules"]] == [
            (10, "cert", False, True, False), (12, "md5", False, False, False),
            (13, "trust", True, False, False), (14, "ldap", False, True, True)]

    def test_never_pass_from_hba_even_if_only_cert_rules_match(self):
        out = run("4.10", self._no_password(hba(10, users=("svc",), method="cert", typ="hostssl")))
        assert out["result"] == "MANUAL"
        assert out["evidence"][0]["hba_rules"][0]["cis_named_non_password_method"] is True

    def test_password_types_gapped_is_gapped(self):
        s = snap()
        s["baseline"]["password_types"] = None
        s["baseline"]["gaps"] = [gap("password_types", "must be superuser to read pg_authid")]
        assert_gapped(run("4.10", s), {"code": "section_not_collected", "section": "password_types",
                                       "gap_reason": "must be superuser to read pg_authid"})

    def test_hba_rules_gapped_with_non_empty_set_is_manual_with_gap_shown(self):
        s = self._no_password()
        s["baseline"]["hba_rules"] = None
        s["baseline"]["gaps"] = [gap("hba_rules")]
        out = run("4.10", s)
        assert out["result"] == "MANUAL"
        assert out["evidence"] == [{"rolname": "svc", "rolsuper": False, "hba_rules": None}]
        assert out["explanation"] == {"code": "manual_review", "evidence_count": 1,
                                      "sections_not_collected": ["hba_rules"]}

    def test_login_role_absent_from_password_types_is_gapped_not_pass(self):
        s = snap()
        s["baseline"]["roles"].append(role("ghost", 16390))
        assert_gapped(run("4.10", s), {"code": "field_missing", "section": "password_types",
                                       "field": "password_type"})


# ---------------------------------------------------------------------------
# 5.5 role_connection_limits
# ---------------------------------------------------------------------------

class TestConnectionLimits55:
    def test_fail_unlimited_connections_failing_roles_first(self):
        s = snap()
        s["baseline"]["roles"] = [
            role("postgres", 10, superuser=True, limit=-1),
            role("app", 16384, limit=20),
            role("pgbouncer", 16385, limit=-1),       # literal pg_ prefix only: in scope
            role("locked", 16386, limit=0),
            role("reporting", 16387, login=False, limit=-1),
            role("readers", 16388, login=False, limit=5),
        ] + predefined(s)                              # pg_* roles, all at -1, are out of scope
        assert all(r["rolconnlimit"] == -1 for r in predefined(s))
        out = run("5.5", s)
        assert out["result"] == "FAIL"
        assert out["explanation"] == {"code": "unlimited_connections", "role_count": 2}
        assert out["evidence"] == [
            {"type": "in_scope", "rolname": "pgbouncer", "rolconnlimit": -1, "rolsuper": False,
             "unlimited": True, "superuser_limit_not_enforced": False, "limit_zero_blocks_login": False},
            {"type": "in_scope", "rolname": "postgres", "rolconnlimit": -1, "rolsuper": True,
             "unlimited": True, "superuser_limit_not_enforced": True, "limit_zero_blocks_login": False},
            {"type": "in_scope", "rolname": "app", "rolconnlimit": 20, "rolsuper": False,
             "unlimited": False, "superuser_limit_not_enforced": False, "limit_zero_blocks_login": False},
            {"type": "in_scope", "rolname": "locked", "rolconnlimit": 0, "rolsuper": False,
             "unlimited": False, "superuser_limit_not_enforced": False, "limit_zero_blocks_login": True},
            {"type": "nologin_information_only", "rolname": "reporting", "rolconnlimit": -1},
        ]
        assert not any(e["rolname"].startswith("pg_") for e in out["evidence"])
        assert out["evidence_paths"] == ["roles"]

    def test_pass_when_every_login_role_has_a_limit_nologin_unlimited_is_information_only(self):
        s = snap()
        s["baseline"]["roles"] = [role("postgres", 10, superuser=True, limit=5), role("app", 16384, limit=20),
                                  role("reporting", 16387, login=False, limit=-1)] + predefined(s)
        out = run("5.5", s)
        assert out["result"] == "PASS"
        assert out["explanation"] == {"code": "connection_limits_set", "evidence_count": 3}
        assert out["evidence"] == [
            {"type": "in_scope", "rolname": "app", "rolconnlimit": 20, "rolsuper": False,
             "unlimited": False, "superuser_limit_not_enforced": False, "limit_zero_blocks_login": False},
            {"type": "in_scope", "rolname": "postgres", "rolconnlimit": 5, "rolsuper": True,
             "unlimited": False, "superuser_limit_not_enforced": True, "limit_zero_blocks_login": False},
            {"type": "nologin_information_only", "rolname": "reporting", "rolconnlimit": -1},
        ]

    def test_live_fixture_fails_on_the_bootstrap_superuser(self):
        out = run("5.5", snap())
        assert out["result"] == "FAIL"
        assert [e["rolname"] for e in out["evidence"]] == ["dbguard_poc"]

    def test_quote_constant_is_minus_one(self):
        assert REGISTRY["role_connection_limits"].quote_tokens == ("-1",)
        assert "`-1`" in SPECS["5.5"]["check"]["pass_condition_quote"]


# ---------------------------------------------------------------------------
# 7.1 replication_roles: always MANUAL
# ---------------------------------------------------------------------------

class TestReplicationRoles71:
    def test_lists_replication_and_superuser_roles_hba_slots_recovery_and_conninfo_user(self):
        s = snap()
        b = s["baseline"]
        b["roles"] = [role("postgres", 10, superuser=True), role("replicator", 16384, replication=True),
                      role("app", 16385)] + predefined(s)
        b["hba_rules"] = [hba(5, databases=("replication",), users=("replicator",), method="scram-sha-256"),
                          hba(6, databases=("all",), method="trust")]
        b["replication"]["slots"] = [{"slot_name": "standby1", "plugin": None, "slot_type": "physical",
                                      "database": None, "temporary": False, "active": True}]
        b["replication"]["primary_conninfo_parsed"] = {"user": "conninfo_user_x", "host": "primary.example",
                                                       "port": "6543", "application_name": "standby_app_x"}
        out = run("7.1", s)
        assert out["result"] == "MANUAL"
        assert out["explanation"] == {"code": "manual_review", "evidence_count": 5}
        assert out["evidence"] == [
            {"type": "replication_role", "rolname": "postgres", "rolreplication": False, "rolsuper": True,
             "rolcanlogin": True, "bootstrap_superuser": True},
            {"type": "replication_role", "rolname": "replicator", "rolreplication": True, "rolsuper": False,
             "rolcanlogin": True, "bootstrap_superuser": False},
            {"type": "replication_hba_rule", "line_number": 5, "connection_type": "host",
             "user_name": ["replicator"], "auth_method": "scram-sha-256", "has_error": False},
            {"type": "replication_slot", "slot_name": "standby1", "slot_type": "physical", "database": None,
             "active": True},
            {"type": "recovery_state", "in_recovery": False},
        ]
        # primary_conninfo_parsed is never read: its parser is not quote- or URI-aware,
        # so even "user" can hold part of a password.
        text = json.dumps(out)
        for value in ("conninfo_user_x", "primary.example", "6543", "standby_app_x", "primary_conninfo"):
            assert value not in text
        assert out["evidence_paths"] == ["roles", "hba_rules", "replication.slots", "replication.in_recovery"]

    def test_conninfo_user_that_matches_a_role_adds_no_evidence(self):
        s = snap()
        s["baseline"]["replication"]["primary_conninfo_parsed"] = {"user": "dbguard_poc", "host": "primary"}
        with_conninfo = run("7.1", s)
        s["baseline"]["replication"]["primary_conninfo_parsed"] = None
        assert with_conninfo == run("7.1", s)
        assert not any(e["type"] == "primary_conninfo_user" for e in with_conninfo["evidence"])

    def test_gapped_conninfo_is_not_reported_as_not_collected(self):
        """It is not read at all, so its gap does not appear either."""
        s = snap()
        s["baseline"]["replication"]["primary_conninfo_parsed"] = None
        s["baseline"]["gaps"] = [gap("replication.primary_conninfo_parsed")]
        out = run("7.1", s)
        assert out["result"] == "MANUAL"
        assert "primary_conninfo" not in json.dumps(out)

    def test_optional_sections_gapped_are_shown_not_guessed(self):
        s = snap()
        s["baseline"]["hba_rules"] = None
        s["baseline"]["replication"]["slots"] = None
        s["baseline"]["gaps"] = [gap("hba_rules"), gap("replication.slots")]
        out = run("7.1", s)
        assert out["result"] == "MANUAL"
        assert out["explanation"]["sections_not_collected"] == ["hba_rules", "replication.slots"]
        assert [e["type"] for e in out["evidence"]] == ["replication_role", "recovery_state"]


# ---------------------------------------------------------------------------
# 7.4 wal_archiving: decision order
# ---------------------------------------------------------------------------

def wal(**kwargs) -> dict:
    s = snap()
    in_recovery = kwargs.pop("in_recovery", False)
    s["baseline"]["archiving"] = archiving(**kwargs)
    s["baseline"]["replication"]["in_recovery"] = in_recovery
    return s


class TestWalArchiving74:
    def test_max_age_is_24_hours_and_the_spec_says_so(self):
        assert WAL_ARCHIVE_MAX_AGE_HOURS == 24
        assert any("24 hours" in entry for entry in SPECS["7.4"]["interpretation"])
        assert catalog_checks.ARCHIVE_FUTURE_TOLERANCE_SECONDS == 300

    def test_recorded_fixture_mode_off_is_fail(self):
        assert live_snapshot()["baseline"]["archiving"]["archive_mode"] == "off"
        out = run("7.4", snap())  # re-recorded collector output: archive_mode off
        assert out["result"] == "FAIL"
        assert out["explanation"] == {"code": "archive_mode_off", "archive_mode": "off"}
        assert out["evidence"] == [{"archive_mode": "off", "archive_library": "",
                                    "archive_command_is_set": False}]

    def test_mode_off_on_a_standby_is_fail_not_manual(self):
        out = run("7.4", wal(mode="off", in_recovery=True))
        assert out["result"] == "FAIL"
        assert out["explanation"]["code"] == "archive_mode_off"

    def test_configuration_fail_does_not_need_replication(self):
        s = wal(mode="off")
        s["baseline"]["replication"] = None
        s["baseline"]["gaps"] = [gap("replication")]
        assert run("7.4", s)["result"] == "FAIL"

    @pytest.mark.parametrize("mode", ["on", "always"])
    def test_on_and_always_are_accepted(self, mode):
        out = run("7.4", wal(mode=mode))
        assert out["result"] == "PASS"
        assert out["explanation"]["code"] == "archive_recent"

    @pytest.mark.parametrize("library", ["", None])
    def test_neither_command_nor_library_is_fail(self, library):
        out = run("7.4", wal(command=False, library=library))
        assert out["result"] == "FAIL"
        assert out["explanation"] == {"code": "archive_destination_missing"}

    def test_library_alone_is_a_valid_destination(self):
        assert run("7.4", wal(command=False, library="basic_archive"))["result"] == "PASS"

    def test_both_command_and_library_is_fail_even_with_healthy_counters(self):
        out = run("7.4", wal(command=True, library="basic_archive", failed_count=0))
        assert out["result"] == "FAIL"
        assert out["explanation"] == {"code": "archive_destination_conflict"}
        assert out["evidence"] == [{"archive_mode": "on", "archive_library": "basic_archive",
                                    "archive_command_is_set": True}]

    def test_standby_with_valid_configuration_is_manual(self):
        out = run("7.4", wal(in_recovery=True))
        assert out["result"] == "MANUAL"
        assert out["explanation"] == {"code": "archive_standby"}
        assert out["evidence"][0]["in_recovery"] is True

    def test_replication_gapped_after_configuration_passes_is_gapped(self):
        s = wal()
        s["baseline"]["replication"] = None
        s["baseline"]["gaps"] = [gap("replication")]
        assert_gapped(run("7.4", s), {"code": "section_not_collected", "section": "replication",
                                      "gap_reason": "insufficient_privilege"})

    def test_latest_attempt_failed_is_fail(self):
        archived = COLLECTED - timedelta(hours=2)
        failed = COLLECTED - timedelta(hours=1)
        out = run("7.4", wal(last_archived=archived, last_failed=failed, failed_count=3))
        assert out["result"] == "FAIL"
        assert out["explanation"] == {"code": "archive_latest_failed", "last_failed_time": iso(failed),
                                      "last_archived_time": iso(archived)}
        assert out["evidence"][0]["failed_count"] == 3

    def test_failures_with_no_success_ever_is_fail(self):
        failed = COLLECTED - timedelta(hours=1)
        out = run("7.4", wal(archived_count=0, last_archived=None, last_failed=failed, failed_count=3))
        assert out["result"] == "FAIL"
        assert out["explanation"] == {"code": "archive_latest_failed", "last_failed_time": iso(failed),
                                      "last_archived_time": None}

    def test_older_failure_before_recent_success_is_pass(self):
        out = run("7.4", wal(last_archived=COLLECTED - timedelta(minutes=5),
                             last_failed=COLLECTED - timedelta(hours=3), failed_count=1))
        assert out["result"] == "PASS"

    def test_collected_at_missing_is_gapped(self):
        s = wal()
        del s["envelope"]["collected_at"]
        assert_gapped(run("7.4", s), {"code": "field_missing", "section": "envelope", "field": "collected_at"})

    @pytest.mark.parametrize("value", ["yesterday", "2026-10-26T06:40:54"])  # unparseable / naive
    def test_collected_at_unusable_is_gapped(self, value):
        s = wal()
        s["envelope"]["collected_at"] = value
        assert run("7.4", s)["explanation"] == {"code": "field_missing", "section": "envelope",
                                                "field": "collected_at"}

    def test_stats_reset_recent_and_nothing_archived_since_is_manual(self):
        reset = COLLECTED - timedelta(hours=1)
        out = run("7.4", wal(archived_count=0, last_archived=None, stats_reset=reset))
        assert out["result"] == "MANUAL"
        assert out["explanation"] == {"code": "archive_stats_reset_recent", "stats_reset": iso(reset),
                                      "max_age_hours": 24}

    def test_never_archived_and_never_failed_is_manual(self):
        out = run("7.4", wal(archived_count=0, last_archived=None, stats_reset=None))
        assert out["result"] == "MANUAL"
        assert out["explanation"] == {"code": "archive_never_run", "archived_count": 0, "failed_count": 0}

    def test_old_stats_reset_and_never_archived_is_never_run(self):
        out = run("7.4", wal(archived_count=0, last_archived=None, stats_reset=COLLECTED - timedelta(days=3)))
        assert out["explanation"]["code"] == "archive_never_run"

    def test_archived_count_without_timestamp_is_manual(self):
        out = run("7.4", wal(archived_count=7, last_archived=None))
        assert out["result"] == "MANUAL"
        assert out["explanation"] == {"code": "archive_timestamp_missing", "field": "last_archived_time"}

    @pytest.mark.parametrize("seconds,code", [(300, "archive_recent"), (301, "archive_timestamp_after_collection")])
    def test_timestamp_after_collection_beyond_tolerance_is_manual(self, seconds, code):
        out = run("7.4", wal(last_archived=COLLECTED + timedelta(seconds=seconds)))
        assert out["explanation"]["code"] == code
        if code != "archive_recent":
            assert out["result"] == "MANUAL"
            assert out["explanation"] == {"code": code, "field": "last_archived_time",
                                          "collected_at": COLLECTED_AT}

    def test_last_success_older_than_24h_is_manual(self):
        archived = COLLECTED - timedelta(hours=24, seconds=1)
        out = run("7.4", wal(last_archived=archived))
        assert out["result"] == "MANUAL"
        assert out["explanation"] == {"code": "archive_older_than_max_age", "last_archived_time": iso(archived),
                                      "collected_at": COLLECTED_AT, "max_age_hours": 24}

    def test_last_success_exactly_24h_old_is_pass(self):
        archived = COLLECTED - timedelta(hours=24)
        out = run("7.4", wal(last_archived=archived))
        assert out["result"] == "PASS"
        assert out["explanation"]["code"] == "archive_recent"

    def test_recent_success_is_pass_with_full_evidence(self):
        archived = COLLECTED - timedelta(minutes=5)
        reset = COLLECTED - timedelta(days=30)
        out = run("7.4", wal(last_archived=archived, stats_reset=reset))
        assert out["result"] == "PASS"
        assert out["explanation"] == {"code": "archive_recent", "last_archived_time": iso(archived),
                                      "collected_at": COLLECTED_AT, "max_age_hours": 24}
        assert out["evidence"] == [{
            "archive_mode": "on", "archive_library": "", "archive_command_is_set": True, "in_recovery": False,
            "archived_count": 10, "failed_count": 0, "last_archived_wal": "0000000100000000000000AA",
            "last_failed_wal": None, "last_archived_time": iso(archived), "last_failed_time": None,
            "stats_reset": iso(reset)}]
        assert out["evidence_paths"] == ["archiving.archive_mode", "archiving.archive_library",
                                         "archiving.archive_command_is_set", "replication.in_recovery",
                                         "archiving.stat_archiver", "envelope.collected_at"]

    def test_unparseable_archiver_timestamp_is_gapped(self):
        s = wal()
        s["baseline"]["archiving"]["stat_archiver"]["last_archived_time"] = "not a time"
        assert_gapped(run("7.4", s), {"code": "field_missing", "section": "archiving.stat_archiver",
                                      "field": "last_archived_time"})

    def test_archiving_gapped_carries_reason(self):
        s = wal()
        s["baseline"]["archiving"] = None
        s["baseline"]["gaps"] = [gap("archiving")]
        assert_gapped(run("7.4", s), {"code": "section_not_collected", "section": "archiving",
                                      "gap_reason": "insufficient_privilege"})


# ---------------------------------------------------------------------------
# Validator and schema negatives
# ---------------------------------------------------------------------------

def spec(rec: str) -> dict:
    return copy.deepcopy(SPECS[rec])


def schema_errors(value: dict) -> list:
    return list(jsonschema.Draft202012Validator(SPEC_SCHEMA).iter_errors(value))


class TestCatalogValidation:
    @pytest.mark.parametrize("rec", CATALOG_RECS)
    def test_installed_catalog_specs_are_valid_and_match_schema(self, rec):
        assert validate_spec(SPECS[rec], RECORDS) == []
        assert schema_errors(SPECS[rec]) == []

    def test_unknown_evaluator(self):
        s = spec("4.9")
        s["check"]["evaluator"] = "run_any_sql"
        errors = validate_spec(s, RECORDS)
        assert len(errors) == 1 and errors[0].startswith("check.evaluator must be one of")

    def test_evaluator_wired_to_another_recommendation(self):
        s = spec("4.4")
        s["check"]["evaluator"] = "roles_with_admin_attributes"  # serves 4.3, same tier, no constants
        assert validate_spec(s, RECORDS) == [
            "check.evaluator 'roles_with_admin_attributes' serves recommendation '4.3', not '4.4'"]

    def test_connection_limits_as_manual_checklist_is_rejected(self):
        s = spec("5.5")
        s["tier"], s["reason"] = "manual_checklist", "test"
        assert validate_spec(s, RECORDS) == [
            "check.evaluator 'role_connection_limits' does not support tier 'manual_checklist' "
            "(allowed: ('automated',))"]

    def test_admin_attributes_as_automated_is_rejected(self):
        s = spec("4.3")
        s["tier"], s["reason"] = "automated", None
        assert validate_spec(s, RECORDS) == [
            "check.evaluator 'roles_with_admin_attributes' does not support tier 'automated' "
            "(allowed: ('manual_checklist',))"]

    @pytest.mark.parametrize("key,value", [("setting_name", "log_connections"), ("query", "SELECT 1"),
                                           ("sql", "DROP ROLE x")])
    def test_extra_check_key(self, key, value):
        s = spec("5.5")
        s["check"][key] = value
        assert validate_spec(s, RECORDS) == [f"Unknown check key: {key}"]

    @pytest.mark.parametrize("key", ["kind", "evaluator", "pass_condition_quote"])
    def test_missing_check_key(self, key):
        s = spec("4.9")
        del s["check"][key]
        errors = validate_spec(s, RECORDS)
        if key == "kind":
            # Without kind it is no longer a catalog check, so the generic rules reject it.
            assert "tier 'manual_checklist' must not have check present" in errors
        else:
            assert errors == [f"Missing required check key: {key}"]

    def test_quote_not_verbatim(self):
        s = spec("5.5")
        s["check"]["pass_condition_quote"] = "Any user with a connection limit of `-1` should be considered a pass."
        assert validate_spec(s, RECORDS) == ["pass_condition_quote not found in audit_procedure for '5.5'"]

    def test_whitespace_only_change_is_still_verbatim(self):
        s = spec("5.5")
        s["check"]["pass_condition_quote"] = "Any  user with a connection\nlimit of `-1` should be considered a failure."
        assert validate_spec(s, RECORDS) == []

    def test_quote_without_the_evaluator_constant(self):
        s = spec("5.5")
        s["check"]["pass_condition_quote"] = "Any user with a connection limit of"  # verbatim prefix
        assert validate_spec(s, RECORDS) == ["evaluator constant '-1' is not a whole token in pass_condition_quote"]

    def test_constant_inside_a_longer_word_is_not_a_token(self):
        s = spec("7.4")
        # Verbatim CIS text; "on" occurs only inside "functioning" and "one".
        s["check"]["pass_condition_quote"] = "To verify that WAL archiving is functioning successfully, one can:"
        assert "on" in s["check"]["pass_condition_quote"]
        assert validate_spec(s, RECORDS) == [
            f"evaluator constant {t!r} is not a whole token in pass_condition_quote"
            for t in ("archive_mode", "on", "archive_command", "archive_library")]

    @pytest.mark.parametrize("rec", ["5.5", "4.3"])  # automated and manual_checklist
    def test_proof_rejected(self, rec):
        s = spec(rec)
        s["proof"] = {"break": {"setting_name": "x", "value": "1"}, "fix": {"setting_name": "x", "value": "2"}}
        assert validate_spec(s, RECORDS) == ["check.kind 'catalog' must not have proof present"]
        assert schema_errors(s)

    @pytest.mark.parametrize("tier", ["parameterised", "needs_capability"])
    def test_check_on_parameterised_or_needs_capability_still_rejected(self, tier):
        s = spec("4.3")
        s["tier"] = tier
        assert f"tier {tier!r} must not have check present" in validate_spec(s, RECORDS)
        assert schema_errors(s)

    def test_setting_check_on_manual_checklist_still_rejected(self):
        s = next(copy.deepcopy(x) for x in ALL_SPECS if x["spec_id"].endswith(":3.1.12"))
        s["check"] = copy.deepcopy(next(x for x in ALL_SPECS if x["spec_id"].endswith(":3.1.20"))["check"])
        assert validate_spec(s, RECORDS) == ["tier 'manual_checklist' must not have check present"]
        assert schema_errors(s)

    # Wave 1b's interpretation rules (validate._interpretation_errors) apply to catalog specs too.
    @pytest.mark.parametrize("value,error", [
        ("a sentence", "interpretation must be a non-empty list of sentences"),
        ([], "interpretation must be a non-empty list of sentences"),
        ([""], "interpretation[0] must be a non-empty string"),
        (["ok", "   "], "interpretation[1] must be a non-empty string"),
        ([1], "interpretation[0] must be a non-empty string"),
        (None, "interpretation must be a non-empty list of sentences"),
        (["Uses SELECT here."], "interpretation[0] must not contain SQL (found 'SELECT')"),
        (["One; two."], "interpretation[0] must be one plain sentence (no ';', line breaks or code)"),
    ])
    def test_bad_interpretation_rejected(self, value, error):
        s = spec("5.5")
        s["interpretation"] = value
        assert validate_spec(s, RECORDS) == [error]
        # The SQL and ';' rules are enforced by validate.py only (schema.json says so).
        if not error.startswith("interpretation[0] must not") and "plain sentence" not in error:
            assert schema_errors(s)

    def test_interpretation_allowed_on_a_setting_spec(self):
        s = next(copy.deepcopy(x) for x in ALL_SPECS if x["spec_id"].endswith(":3.1.20"))
        s["interpretation"] = ["A plain sentence."]
        assert validate_spec(s, RECORDS) == []
        assert schema_errors(s) == []

    @pytest.mark.parametrize("mutate", [
        lambda s: s["check"].update(setting_name="log_connections"),
        lambda s: s["check"].pop("evaluator"),
        lambda s: s["check"].update(evaluator="Bad-Name; DROP"),
        lambda s: s["check"].update(pass_condition_quote=""),
        lambda s: s["check"].update(kind="catalogue"),
    ])
    def test_schema_rejects_bad_catalog_check_shapes(self, mutate):
        s = spec("4.9")
        mutate(s)
        assert schema_errors(s)
        assert validate_spec(s, RECORDS)


# ---------------------------------------------------------------------------
# Never a fix
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def sandbox_engine():
    from services.sandbox_poc.shared import ROOT, SpecEngine
    return SpecEngine.load(ROOT / "catalog/specs/cis-pg17-v1.1.0",
                           ROOT / "catalog/benchmarks/cis-pg17-v1.1.0/records.json")


class TestNeverAFix:
    @pytest.mark.parametrize("rec", CATALOG_RECS)
    def test_fix_scope_rejects_every_catalog_spec(self, sandbox_engine, rec):
        from services.sandbox_poc.planning import fix_scope
        from services.sandbox_poc.shared import ContractError
        with pytest.raises(ContractError):
            fix_scope(sandbox_engine, SPECS[rec]["spec_id"])

    def test_fix_scope_rejects_catalog_spec_carrying_a_reviewed_setting(self):
        """Even a forged catalog check naming a POLICIES setting gets no fix."""
        from services.sandbox_poc.planning import POLICIES, fix_scope
        from services.sandbox_poc.shared import ContractError
        assert "log_connections" in POLICIES
        forged = spec("5.5")
        forged["check"].update(setting_name="log_connections", query="SHOW log_connections",
                               operator="equals", expected=POLICIES["log_connections"][0])
        with pytest.raises(ContractError):
            fix_scope(SimpleNamespace(specs=[forged]), forged["spec_id"])

    def test_sandbox_manifest_holds_only_setting_checks(self, sandbox_engine):
        manifest = manifest_from_specs(ALL_SPECS, RECORDS)
        assert manifest["checks"]
        assert {c["kind"] for c in manifest["checks"]} == {"setting"}
        assert not {c["spec_id"] for c in manifest["checks"]} & {s["spec_id"] for s in SPECS.values()}
        assert len(manifest["checks"]) == 29
        assert sandbox_engine.manifest == manifest

    @pytest.mark.parametrize("rec,mutate,status", [
        ("4.10", lambda b: None, FindingStatus.PASS),
        ("5.5", lambda b: None, FindingStatus.FAIL),
        ("7.4", lambda b: None, FindingStatus.FAIL),
        ("4.9", lambda b: None, FindingStatus.MANUAL_REVIEW),
        ("5.5", lambda b: b.update(roles=None, gaps=[gap("roles")]), FindingStatus.GAPPED),
        ("7.4", lambda b: b.update(archiving=None, gaps=[gap("archiving")]), FindingStatus.GAPPED),
    ])
    def test_assess_findings_map_to_manual_procedure(self, rec, mutate, status):
        from catalog.controls.assess.registry import CONTROL_REGISTRY
        s = snap()
        mutate(s["baseline"])
        control = CONTROL_REGISTRY[SPECS[rec]["spec_id"]]
        assert control.template_id == "MANUAL_PROCEDURE" and control.is_automatable is False
        for snapshot in (s, {**s["baseline"], "envelope": s["envelope"]}):  # v0.3.0 and flat bundle
            finding = control.evaluate(snapshot)
            assert finding.status == status
            assert finding.control_metadata.template_id == "MANUAL_PROCEDURE"
            assert finding.control_metadata.is_automatable is False
            assert finding.is_gapped is (status == FindingStatus.GAPPED)
            assert finding.cis == {"recommendation": rec, "title": SPECS[rec]["ref"]["title"]}
            assert finding.explanation == run(rec, s)["explanation"]
            assert finding.evidence_found == run(rec, s)["evidence"]


# ---------------------------------------------------------------------------
# assess() rows
# ---------------------------------------------------------------------------

CATALOG_SPEC_LIST = [SPECS[r] for r in CATALOG_RECS]


class TestAssessRows:
    def test_catalog_rows_carry_evidence_explanation_and_cis_but_no_setting_keys(self):
        s = snap()
        report = assess(CATALOG_SPEC_LIST, s, RECORDS)
        assert len(report["results"]) == 10
        for row in report["results"]:
            rec = row["spec_id"].split(":")[1]
            out = run(rec, s)
            assert row["evidence"] == out["evidence"]
            assert row["evidence_paths"] == out["evidence_paths"]
            assert row["explanation"] == out["explanation"]
            assert row["reason_code"] == out["explanation"]["code"]
            assert row["cis"] == {"recommendation": rec, "title": SPECS[rec]["ref"]["title"]}
            assert not {"setting_name", "operator", "expected", "observed"} & set(row)

    def test_gapped_maps_to_not_collected_and_summary_counts_it(self):
        s = snap()
        s["baseline"]["roles"] = None
        s["baseline"]["gaps"] = [gap("roles")]
        report = assess(CATALOG_SPEC_LIST, s, RECORDS)
        rows = {r["spec_id"].split(":")[1]: r for r in report["results"]}
        roles_based = [r for r in CATALOG_RECS if "roles" in REGISTRY[EVALUATOR_OF[r]].required_sections]
        assert set(roles_based) == {"4.3", "4.4", "4.6", "4.7", "4.9", "4.10", "5.5", "7.1"}
        for rec in roles_based:
            assert rows[rec]["result"] == "NOT_COLLECTED"
            assert rows[rec]["reason_code"] == "section_not_collected"
            assert rows[rec]["explanation"] == {"code": "section_not_collected", "section": "roles",
                                                "gap_reason": "insufficient_privilege"}
        assert rows["7.4"]["result"] == "FAIL"   # archiving does not read roles
        assert rows["4.5"]["result"] == "MANUAL"  # nor do functions
        assert report["summary"]["NOT_COLLECTED"] == 8
        counted = {k: sum(1 for r in report["results"] if r["result"] == k) for k in report["summary"]}
        assert report["summary"] == counted

    def test_manual_rows_never_count_as_pass(self):
        report = assess(CATALOG_SPEC_LIST, snap(), RECORDS)
        assert report["summary"]["PASS"] == sum(1 for r in report["results"] if r["result"] == "PASS")
        assert {r["spec_id"].split(":")[1] for r in report["results"] if r["result"] == "PASS"} == {"4.10"}

    def test_full_report_with_catalog_rows_validates_assessment_contract(self):
        """PRODUCTION GAP: assessment-report-v1.json forbids the new row keys and reason codes.

        Result rows have additionalProperties: false and a closed reason_code enum, so
        every catalog row (evidence, evidence_paths, explanation, cis; reason codes such
        as manual_review) violates the contract that tests/live/test_e2e_break_fix.py
        and test_assess::TestAssessOutputShape hold every report to.
        """
        report = assess(ALL_SPECS, snap(), RECORDS)
        jsonschema.validate(report, REPORT_CONTRACT)


# ---------------------------------------------------------------------------
# No secrets anywhere in the output
# ---------------------------------------------------------------------------

SECRETS = (
    "SCRAM-SHA-256$4096:c2FsdHNhbHQ=$c3RvcmVkS2V5:c2VydmVyS2V5",
    "md5" + "0123456789abcdef0123456789abcdef",
    "SUPERSECRET_BODY", "SUPERSECRET_GUC", "SUPERSECRET_QUAL", "SUPERSECRET_CHECK",
    "SUPERSECRET_ARCH", "SUPERSECRET_CONN", "SUPERSECRET_HBA", "SUPERSECRET_SETTING",
    "SUPERSECRET_USERPART",
)


def secret_snapshot() -> dict:
    s = only_connected_db(snap())
    b = s["baseline"]
    b["roles"] = [role("postgres", 10, superuser=True), role("app_owner", 16384, limit=10),
                  role("svc", 16385, replication=True, limit=5)] + predefined(s)
    b["roles"][0]["rolpassword"] = SECRETS[0]
    b["roles"][1]["rolpassword"] = SECRETS[1]
    b["roles"][2]["passwd"] = SECRETS[0]
    b["password_types"] = [
        {"rolname": "postgres", "password_type": "scram-sha-256", "rolvaliduntil": None, "rolpassword": SECRETS[0]},
        {"rolname": "app_owner", "password_type": "md5", "rolvaliduntil": None, "rolpassword": SECRETS[1]},
        {"rolname": "svc", "password_type": "none", "rolvaliduntil": None}]
    b["functions"] = [{**function("sd", search_path="pg_catalog, public",
                                  config_names=("search_path", "myapp.password")),
                       "prosrc": "SELECT 'SUPERSECRET_BODY'", "proconfig": ["myapp.password=SUPERSECRET_GUC"]}]
    b["object_acls"] = [table("accounts", ["app_owner=arwd/app_owner", "svc=a/app_owner"], rls=True)]
    b["rls_policies"] = [{**policy("accounts", "p"), "qual": "(token = 'SUPERSECRET_QUAL')",
                          "with_check": "(token = 'SUPERSECRET_CHECK')"}]
    b["archiving"] = {**archiving(), "archive_command": "cp %p rclone://tok:SUPERSECRET_ARCH@bucket/%f"}
    # What the collector's non-quote-aware parser yields for user='svc pw=SUPERSECRET_USERPART'.
    b["replication"]["primary_conninfo_parsed"] = {"user": "'svc", "pw": "SUPERSECRET_USERPART'",
                                                   "host": "primary", "password": "SUPERSECRET_CONN"}
    b["hba_rules"].append(hba(200, users=("svc",), method="ldap",
                              options={"ldapbindpasswd": "SUPERSECRET_HBA"}))
    b["settings"] = [r if r["name"] != "archive_command" else {**r, "setting": "cp %p x:SUPERSECRET_SETTING@y"}
                     for r in b["settings"]]
    return s


class TestNoSecrets:
    @pytest.mark.parametrize("rec", CATALOG_RECS)
    def test_no_secret_in_evaluator_output(self, rec):
        out = run(rec, secret_snapshot())
        assert out["result"] != "GAPPED", out  # the evaluator actually read the planted rows
        text = json.dumps(out)
        assert [x for x in SECRETS if x in text] == []
        assert "rolpassword" not in text and "prosrc" not in text and "archive_command\"" not in text

    def test_secret_snapshot_reaches_evidence_rows(self):
        s = secret_snapshot()
        assert run("4.10", s)["evidence"][0]["hba_rules"][-1]["line_number"] == 200
        assert run("4.5", s)["evidence"][0]["config_names"] == ["search_path", "myapp.password"]
        assert run("4.7", s)["evidence"][0]["policies"][0]["policy"] == "p"
        ev71 = run("7.1", s)["evidence"]
        assert {"type": "replication_role", "rolname": "svc", "rolreplication": True, "rolsuper": False,
                "rolcanlogin": True, "bootstrap_superuser": False} in ev71
        assert not any(e["type"] == "primary_conninfo_user" for e in ev71)
        assert "'svc" not in json.dumps(ev71)
        assert run("7.4", s)["result"] == "PASS"

    def test_no_secret_in_assess_rows(self):
        report = assess(CATALOG_SPEC_LIST, secret_snapshot(), RECORDS)
        text = json.dumps(report["results"])
        assert [x for x in SECRETS if x in text] == []


# ---------------------------------------------------------------------------
# Purity
# ---------------------------------------------------------------------------

class TestPurity:
    @pytest.mark.parametrize("rec", CATALOG_RECS)
    def test_same_output_twice_and_input_unchanged(self, rec):
        s = secret_snapshot()
        before = copy.deepcopy(s)
        first = run(rec, s)
        second = run(rec, s)
        assert json.dumps(first, sort_keys=True) == json.dumps(second, sort_keys=True)
        assert s == before


# ---------------------------------------------------------------------------
# Wiring that must hold for the loop to run on real collector output
# ---------------------------------------------------------------------------

class TestCollectorProducesSections:
    def test_every_section_an_evaluator_reads_is_a_collector_baseline_key(self):
        """Every section in REGISTRY (incl. `functions` and `archiving`) is produced by collect.sql."""
        sql = (REPO_ROOT / "collector" / "collect.sql").read_text(encoding="utf-8")
        keys = set(re.findall(r"^'([a-z_]+)',", sql, flags=re.MULTILINE))
        assert {"roles", "databases", "hba_rules", "replication"} <= keys  # the pattern finds sections
        needed = {sec for e in REGISTRY.values() for sec in (*e.required_sections, *e.optional_sections)}
        assert sorted(needed - keys) == []

    def test_sandbox_findings_have_no_gapped_control_on_current_collector_output(self, sandbox_engine):
        """On the re-recorded collector output nothing is GAPPED, catalog included."""
        snapshot = live_snapshot()
        assert snapshot["envelope"]["collector_sha256"] == sandbox_engine.collector_hash
        findings = sandbox_engine.assess(snapshot)["findings"]
        assert sorted(k for k, v in findings.items() if v["status"] == "GAPPED") == []
        assert sandbox_engine.gapped_settings(findings) == []


# ---------------------------------------------------------------------------
# Frontend sentences exist for every code the evaluators emit
# ---------------------------------------------------------------------------

def test_every_emitted_explanation_code_has_a_frontend_sentence():
    source = (REPO_ROOT / "backend/app/services/spec_engine/catalog_checks.py").read_text(encoding="utf-8")
    emitted = set(re.findall(r'"code": "([a-z_]+)"', source))
    emitted |= set(re.findall(r'out\("(?:PASS|FAIL|MANUAL)", "([a-z_]+)"', source))
    emitted |= set(re.findall(r'_manual\(ctx, evidence, paths, "([a-z_]+)"', source))
    emitted.add("manual_review")  # _manual's default code
    assert {"section_not_collected", "field_missing", "wrong_pg_major", "empty_review_set",
            "unlimited_connections", "archive_recent", "databases_not_covered"} <= emitted
    explain = (REPO_ROOT / "frontend/src/live/explanations.ts").read_text(encoding="utf-8")
    sentences = set(re.findall(r"^  ([a-z_]+): \(", explain, flags=re.MULTILINE))
    assert sorted(emitted - sentences) == []


# ---------------------------------------------------------------------------
# 7.4 restore-test reminder: a fixed, reviewed notice on every 7.4 result
# ---------------------------------------------------------------------------

REMINDER = catalog_checks.RESTORE_TEST_REMINDER
EXPECTED_NOTICES = [{"code": "restore_test_reminder", "text": REMINDER}]


def _wal_gapped():
    s = snap()
    s["baseline"]["archiving"] = None
    s["baseline"]["gaps"] = [gap("archiving")]
    return s


def _wal_wrong_major():
    s = wal()
    s["baseline"]["identity"]["server_version_num"] = 160004
    return s


# Each 7.4 status, plus GAPPED from the early wrong-major return path.
WAL_BY_STATUS = [
    ("PASS", lambda: wal()),
    ("FAIL", lambda: snap()),                       # dry-run archiving: archive_mode off
    ("MANUAL", lambda: wal(in_recovery=True)),
    ("GAPPED", _wal_gapped),
    ("GAPPED", _wal_wrong_major),
]
ASSESS_RESULT = {"PASS": "PASS", "FAIL": "FAIL", "MANUAL": "MANUAL", "GAPPED": "NOT_COLLECTED"}
FINDING_STATUS = {"PASS": FindingStatus.PASS, "FAIL": FindingStatus.FAIL,
                  "MANUAL": FindingStatus.MANUAL_REVIEW, "GAPPED": FindingStatus.GAPPED}


class TestRestoreTestReminder:
    def test_constant_is_registered_for_7_4_only_and_read_only(self):
        assert isinstance(REMINDER, str) and REMINDER.strip()
        assert dict(catalog_checks.NOTICES) == {"7.4": (("restore_test_reminder", REMINDER),)}
        with pytest.raises(TypeError):
            catalog_checks.NOTICES["4.3"] = (("x", "y"),)
        assert catalog_checks.notices_for("7.4") == EXPECTED_NOTICES
        assert catalog_checks.notices_for("5.5") == []
        assert catalog_checks.notices_for(None) == []

    @pytest.mark.parametrize("status,build", WAL_BY_STATUS)
    def test_present_in_evaluate_for_every_status(self, status, build):
        out = run("7.4", build())
        assert out["result"] == status
        assert out["notices"] == EXPECTED_NOTICES
        assert out["notices"][0]["text"] is not None and out["notices"][0]["text"] == REMINDER

    @pytest.mark.parametrize("status,build", WAL_BY_STATUS)
    def test_present_in_assess_rows_and_report_validates(self, status, build):
        report = assess(ALL_SPECS, build(), RECORDS)
        rows = {r["spec_id"]: r for r in report["results"]}
        row = rows["cis-pg17-v1.1.0:7.4"]
        assert row["result"] == ASSESS_RESULT[status]
        assert row["notices"] == EXPECTED_NOTICES
        jsonschema.validate(report, REPORT_CONTRACT)
        # Only 7.4's row carries the reminder anywhere in the report.
        assert json.dumps(report).count(json.dumps(REMINDER)[1:-1]) == 1

    @pytest.mark.parametrize("status,build", WAL_BY_STATUS)
    def test_present_in_spec_controls_finding_rationale(self, status, build):
        from catalog.controls.assess.registry import CONTROL_REGISTRY
        from catalog.controls.assess.spec_controls import _CATALOG_RATIONALE
        s = build()
        control = CONTROL_REGISTRY["cis-pg17-v1.1.0:7.4"]
        for snapshot in (s, {**s["baseline"], "envelope": s["envelope"]}):  # v0.3.0 and flat bundle
            finding = control.evaluate(snapshot)
            assert finding.status == FINDING_STATUS[status]
            assert finding.rationale == f"{_CATALOG_RATIONALE[status]} {REMINDER}"
            assert finding.rationale.count(REMINDER) == 1

    @pytest.mark.parametrize("rec", [r for r in CATALOG_RECS if r != "7.4"])
    def test_absent_from_every_other_catalog_recommendation(self, rec):
        from catalog.controls.assess.registry import CONTROL_REGISTRY
        from catalog.controls.assess.spec_controls import _CATALOG_RATIONALE
        s = secret_snapshot()
        out = run(rec, s)
        assert out["notices"] == []
        gapped = snap()
        gapped["baseline"]["identity"]["server_version_num"] = 160004
        assert run(rec, gapped)["notices"] == []
        row = next(r for r in assess([SPECS[rec]], s, RECORDS)["results"])
        assert row["notices"] == []
        finding = CONTROL_REGISTRY[SPECS[rec]["spec_id"]].evaluate(s)
        assert finding.rationale == _CATALOG_RATIONALE[out["result"]]
        assert REMINDER not in json.dumps(out) and REMINDER not in finding.rationale

    def test_setting_rows_have_no_reminder(self):
        report = assess(ALL_SPECS, wal(), RECORDS)
        for row in report["results"]:
            if row["spec_id"] != "cis-pg17-v1.1.0:7.4":
                assert REMINDER not in json.dumps(row)

    def test_identical_for_different_snapshots(self):
        passing, failing = run("7.4", wal()), run("7.4", snap())
        assert passing["result"] != failing["result"]
        assert passing["evidence"] != failing["evidence"]
        assert passing["notices"] == failing["notices"] == EXPECTED_NOTICES

    def test_snapshot_cannot_inject_or_change_notices(self):
        s = wal()
        s["notices"] = [{"code": "restore_test_reminder", "text": "injected"}]
        s["baseline"]["notices"] = [{"code": "x", "text": "injected"}]
        s["baseline"]["archiving"]["notices"] = ["injected"]
        out = run("7.4", s)
        assert out["notices"] == EXPECTED_NOTICES
        assert "injected" not in json.dumps(out)

    def test_mutating_returned_notices_changes_nothing(self):
        first = run("7.4", wal())
        first["notices"][0]["text"] = "tampered"
        first["notices"][0]["code"] = "tampered"
        first["notices"].append({"code": "extra", "text": "extra"})
        assert catalog_checks.RESTORE_TEST_REMINDER == REMINDER
        assert dict(catalog_checks.NOTICES) == {"7.4": (("restore_test_reminder", REMINDER),)}
        assert run("7.4", wal())["notices"] == EXPECTED_NOTICES
        assert catalog_checks.notices_for("7.4") == EXPECTED_NOTICES

    def test_mutating_assess_row_notices_changes_nothing(self):
        row = next(r for r in assess([SPECS["7.4"]], wal(), RECORDS)["results"])
        row["notices"][0]["text"] = "tampered"
        assert next(r for r in assess([SPECS["7.4"]], wal(), RECORDS)["results"])["notices"] == EXPECTED_NOTICES


# ---------------------------------------------------------------------------
# Safeguard: the sandbox only changes settings, so no fixable setting may feed
# a catalog evaluator (Melvin's request).
# ---------------------------------------------------------------------------

def _sql_function_body(name: str) -> str:
    sql = (REPO_ROOT / "collector" / "collect.sql").read_text(encoding="utf-8")
    body = sql[sql.index(f"CREATE FUNCTION pg_temp.{name}()"):]
    return body[:body.index("LANGUAGE sql")]


class TestSettingInputsSafeguard:
    def test_setting_inputs_per_evaluator(self):
        assert {name: e.setting_inputs for name, e in REGISTRY.items()} == {
            "roles_with_admin_attributes": (), "login_roles": (), "elevated_functions": (),
            "table_dml_grants": (), "rls_tables_and_bypass_roles": (), "superuser_roles": (),
            "login_roles_without_password": ("hba_file",),
            "role_connection_limits": (),
            "replication_roles": ("hba_file", "primary_conninfo"),
            "wal_archiving": ("archive_mode", "archive_library", "archive_command", "wal_level"),
        }

    def test_no_fixable_setting_is_a_catalog_input(self):
        from services.sandbox_poc.planning import POLICIES
        assert POLICIES  # the allowlist is non-empty, so the check is not vacuous
        inputs = {s for e in REGISTRY.values() for s in e.setting_inputs}
        assert sorted(set(POLICIES) & inputs) == []

    def test_setting_inputs_are_settings_the_collector_reads(self):
        """Each input is a setting the collector reads: a pg_settings row in the recorded
        fixture (hba_file, primary_conninfo, archive_*) or a current_setting() call in
        sql_archiving (archive_library is not in the settings section)."""
        collected = {r["name"] for r in live_snapshot()["baseline"]["settings"]}
        collected |= set(re.findall(r"current_setting\('([a-z_]+)'", _sql_function_body("sql_archiving")))
        inputs = {s for e in REGISTRY.values() for s in e.setting_inputs}
        assert sorted(inputs - collected) == []

    def test_7_4_inputs_cover_the_settings_the_archiving_query_reads(self):
        """Every setting sql_archiving() reads is an input; wal_level is the one extra
        (archive_mode=on needs wal_level >= replica; the query does not read it)."""
        body = _sql_function_body("sql_archiving")
        read = re.findall(r"current_setting\('([a-z_]+)'", body)
        assert read  # the parser found the calls
        assert len(read) == len(set(read))
        inputs = REGISTRY["wal_archiving"].setting_inputs
        assert len(inputs) == len(set(inputs))
        assert set(read) <= set(inputs)
        assert set(inputs) - set(read) == {"wal_level"}
        assert "wal_level" not in body

    def test_no_fixable_setting_is_an_archiving_key(self):
        from services.sandbox_poc.planning import POLICIES
        body = _sql_function_body("sql_archiving")
        sql_keys = set(re.findall(r"'([a-z_]+)',\s", body))
        archiving = live_snapshot()["baseline"]["archiving"]
        fixture_keys = set(archiving) | set(archiving["stat_archiver"])
        assert "archive_mode" in sql_keys and "archived_count" in sql_keys  # parser sanity
        assert fixture_keys <= sql_keys
        assert sorted(set(POLICIES) & (sql_keys | fixture_keys)) == []

    def test_no_fixable_setting_is_named_in_the_evaluators(self):
        from services.sandbox_poc.planning import POLICIES
        source = (REPO_ROOT / "backend/app/services/spec_engine/catalog_checks.py").read_text(encoding="utf-8")
        assert [name for name in POLICIES if re.search(rf"\b{re.escape(name)}\b", source)] == []
