"""Wave 2b catalog evaluators (Gate W2B, rulings 1-9 and round 2). Tier A: no Docker, network or model.

3.2 pgaudit_enabled, 5.6 password_complexity_module, 6.10 tls_cipher_suites,
6.8 tls_enabled_and_enforced, 4.8 set_user_extension, 6.11 pgcrypto_extension,
5.3 local_hba_rules and 5.4 host_hba_rules, plus the shared E0 rules (settings
rows by name, the preload-list parser, connection visibility, hba options), the
pgaudit_log_classes policy key (E9) and the parameterised catalog tier (E11).

Every snapshot starts from the real collector fixture
(tests/fixtures/phase1/snapshot-pg17-live.json, stock postgres:17, nothing
preloaded, ssl off) and changes one thing at a time in code. Rows built here use
exactly the collector's keys (checked in TestBuilders). Unknown evidence is never
PASS: every GAPPED path is tested next to the readable FAIL that must win over it.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path
from types import SimpleNamespace

import jsonschema
import pytest
import yaml

from app.services.spec_engine import RecordsIndex, assess, load_spec, validate_spec
from app.services.spec_engine import catalog_checks as cc
from app.services.spec_engine.catalog_checks import (CIS_TLS12_CIPHERS, PGAUDIT_LOG_CLASSES, REGISTRY, evaluate,
                                                     names_pgaudit, pgaudit_log_classes, preload_items,
                                                     uses_policy_profile)
from app.services.spec_engine.policy import PolicyProfileError, load_default_profile, parse_profile
from tests.catalog_fixtures import live_snapshot

REPO_ROOT = Path(__file__).resolve().parent.parent
SPEC_DIR = REPO_ROOT / "catalog" / "specs" / "cis-pg17-v1.1.0"
RECORDS = RecordsIndex.load(REPO_ROOT / "catalog" / "benchmarks" / "cis-pg17-v1.1.0" / "records.json")
SPECS = {rec: load_spec(SPEC_DIR / f"{rec}.yaml") for rec in ("3.2", "4.8", "5.3", "5.4", "5.6", "6.8", "6.10", "6.11")}
REPORT_CONTRACT = json.loads((REPO_ROOT / "catalog/specs/contracts/assessment-report-v1.json").read_text())
CIS_LIST = ":".join(CIS_TLS12_CIPHERS)
WEAK = "AES256-SHA"


# ---------------------------------------------------------------------------
# Builders (collector row shapes)
# ---------------------------------------------------------------------------

def snap() -> dict:
    return live_snapshot()


def run(rec: str, s: dict, policy=None) -> dict:
    return evaluate(SPECS[rec], s, policy)


def gap(section: str, reason: str = "insufficient_privilege") -> dict:
    return {"section": section, "reason": reason, "remediation": "test"}


def setting(s: dict, name: str, value, *, source: str = "configuration file", **extra) -> dict:
    """Replace (or add) the settings row for name, keeping the collector's keys."""
    rows = s["baseline"]["settings"]
    template = next((r for r in rows if r["name"] == "ssl"), rows[0])
    row = {**copy.deepcopy(template), "name": name, "setting": value, "source": source,
           "sanitised": False, **extra}
    s["baseline"]["settings"] = [r for r in rows if r["name"] != name] + [row]
    return s


def drop_setting(s: dict, name: str) -> dict:
    s["baseline"]["settings"] = [r for r in s["baseline"]["settings"] if r["name"] != name]
    return s


def conn(*, addr="loopback", ssl=True, version="TLSv1.2", cipher=CIS_TLS12_CIPHERS[0],
         backend="client backend", count=1, user="app", db="appdb", visible=True) -> dict:
    tcp = addr in ("loopback", "private", "public")
    return {"application_name": "psql", "backend_type": backend, "client_addr_class": addr,
            "connection_count": count, "datname": db, "ssl": ssl if (tcp or addr == "unix_socket") else None,
            "tls_cipher": cipher if ssl else None, "tls_version": version if ssl else None,
            "usename": user, "visible": visible}


def hidden(count: int = 1) -> dict:
    """What the collector ships for a session the collecting role cannot see."""
    return {"application_name": "(none)", "backend_type": None, "client_addr_class": "not_visible",
            "connection_count": count, "datname": "appdb", "ssl": None, "tls_cipher": None,
            "tls_version": None, "usename": "other", "visible": False}


def hba(line, typ="hostssl", method="scram-sha-256", *, address="10.0.0.0", netmask="255.0.0.0",
        options=None, error=None, database=("all",), users=("all",)) -> dict:
    local = typ == "local"
    return {"address": None if local else address, "auth_method": method, "database": list(database),
            "error": error, "line_number": line, "netmask": None if local else netmask,
            "options": options, "type": typ, "user_name": list(users)}


def error_line(line, text="invalid authentication method \"bogus\"") -> dict:
    return {"address": None, "auth_method": None, "database": None, "error": text, "line_number": line,
            "netmask": None, "options": None, "type": None, "user_name": None}


def ident(line, map_name, sys_name, pg_username, error=None) -> dict:
    return {"error": error, "file_name": "/var/lib/postgresql/data/pg_ident.conf", "line_number": line,
            "map_name": map_name, "map_number": line, "pg_username": pg_username, "sys_name": sys_name}


def role(name, oid, *, login=True, superuser=False) -> dict:
    return {"is_predefined": name.startswith("pg_"), "oid": str(oid), "rolbypassrls": False,
            "rolcanlogin": login, "rolconnlimit": -1, "rolcreatedb": False, "rolcreaterole": False,
            "rolinherit": True, "rolname": name, "rolreplication": False, "rolsuper": superuser,
            "rolvaliduntil": None}


def member(role_name, member_name) -> dict:
    return {"admin_option": False, "grantor": "postgres", "inherit_option": True, "member": member_name,
            "role": role_name, "set_option": True}


def extension(name, default="1.0", installed=None) -> dict:
    return {"default_version": default, "installed_version": installed, "name": name}


def profile(approved=True, classes=("ddl", "role", "write"), **extra):
    doc = {"profile_id": "test-profile", "benchmark": "cis-pg17-v1.1.0",
           "approved_by": "Test Reviewer" if approved else None,
           "approved_at": "2026-11-05" if approved else None, "values": {}, **extra}
    if classes is not None:
        doc["pgaudit_log_classes"] = list(classes)
    return parse_profile(yaml.safe_dump(doc).encode(), RECORDS)


def tls_ok(s: dict) -> dict:
    """ssl on, only hostssl/local rules, one encrypted TCP session: 6.8 PASS, 6.10 PASS."""
    setting(s, "ssl", "on")
    setting(s, "ssl_ciphers", CIS_LIST)
    s["baseline"]["hba_rules"] = [hba(1, "local", "peer"), hba(2, "hostssl")]
    s["baseline"]["connections"] = [conn()]
    return s


def assert_gapped(out: dict, explanation: dict) -> None:
    assert out["result"] == "GAPPED", out
    assert out["explanation"] == explanation
    assert out["evidence"] == []


def assert_contract(s: dict, policy=None) -> dict:
    report = assess(list(SPECS.values()), s, RECORDS, policy)
    jsonschema.validate(report, REPORT_CONTRACT)
    return report


class TestBuilders:
    def test_rows_match_real_collector_keys(self):
        b = live_snapshot()["baseline"]
        assert set(conn()) == set(b["connections"][0]) == set(hidden())
        assert set(hba(1)) == set(b["hba_rules"][0]) == set(error_line(1))
        assert set(extension("x")) == set(b["available_extensions"][0])
        assert set(role("x", 1)) == set(b["roles"][0])

    def test_ident_and_membership_keys_match_the_collector(self):
        """ident_mappings is to_jsonb(pg_ident_file_mappings); role_memberships keys come from the SQL."""
        sql = (REPO_ROOT / "collector" / "collect.sql").read_text(encoding="utf-8")
        assert "FROM pg_ident_file_mappings t" in sql
        assert {"map_name", "sys_name", "pg_username", "line_number", "error"} <= set(ident(1, "m", "s", "u"))
        b = live_snapshot()["baseline"]
        if b["role_memberships"]:
            assert {"role", "member"} <= set(b["role_memberships"][0])

    def test_live_fixture_is_the_stock_image(self):
        settings = {r["name"]: r for r in live_snapshot()["baseline"]["settings"]}
        assert settings["shared_preload_libraries"]["setting"] == ""
        assert settings["dynamic_library_path"]["setting"] == "$libdir"
        assert settings["ssl"]["setting"] == "off"
        assert "pgaudit.log" not in settings


# ---------------------------------------------------------------------------
# E0: shared_preload_libraries parser (PostgreSQL SplitDirectoriesString)
# ---------------------------------------------------------------------------

class TestPreloadParser:
    @pytest.mark.parametrize("value,items", [
        ("", []), ("   ", []), (" \t\n", []),
        ("pgaudit", ["pgaudit"]),
        ("a,b", ["a", "b"]),
        ("  a ,\tb  ", ["a", "b"]),
        ('"a,b",c', ["a,b", "c"]),
        ('"say ""hi"""', ['say "hi"']),
        ("my lib, x", ["my lib", "x"]),          # inner spaces stay in an unquoted name
        ("PGAUDIT", ["PGAUDIT"]),                # never case-folded
        ("$libdir//pgaudit/", ["$libdir/pgaudit"]),
        ("/usr/lib//postgresql/17/lib/pgaudit.so", ["/usr/lib/postgresql/17/lib/pgaudit.so"]),
        ('"pgaudit" , passwordcheck', ["pgaudit", "passwordcheck"]),
    ])
    def test_split(self, value, items):
        assert preload_items(value) == items

    @pytest.mark.parametrize("value", [
        "a,,b", "a,", ",a", " , ", '"a', '"a"b', '"a" b', "a\x00b", "a\x01b", "a\x7fb",
        "./pgaudit", "$libdir/../pgaudit", "a/./b", '""', "x" * 1024, None, 7,
    ])
    def test_unreadable_lists_raise(self, value):
        with pytest.raises(ValueError):
            preload_items(value)

    @pytest.mark.parametrize("item", ["pgaudit", "$libdir/pgaudit", "pgaudit.so", "$libdir/pgaudit.so",
                                      "/usr/lib/postgresql/17/lib/pgaudit.so"])
    def test_names_pgaudit(self, item):
        assert names_pgaudit(item)

    @pytest.mark.parametrize("item", ["pgaudit2", "pgaudit.so.1", "PGAUDIT", "pgaudit.so.so", "xpgaudit",
                                      "pgaudit/x", "pg_audit", "pgaudit.dll", ""])
    def test_does_not_name_pgaudit(self, item):
        assert not names_pgaudit(item)


# ---------------------------------------------------------------------------
# E1: pgaudit.log as pgaudit reads it
# ---------------------------------------------------------------------------

class TestPgauditLogParser:
    @pytest.mark.parametrize("value,classes", [
        ("none", []), ("", []), ("  ", []),
        ("all", list(PGAUDIT_LOG_CLASSES)),
        ("ddl,role,write", ["write", "role", "ddl"]),
        ("DDL, Role ,WRITE", ["write", "role", "ddl"]),
        ("all,-read", [c for c in PGAUDIT_LOG_CLASSES if c != "read"]),
        ("-all,ddl", ["ddl"]),
        ("ddl,-ddl", []),
        ("-ddl,ddl", ["ddl"]),               # left to right
        ("-none", []),
        ("none,ddl", ["ddl"]),
        ('"ddl"', ["ddl"]),
        ('"DDL"', ["ddl"]),                  # quoted keeps case; pgaudit compares case-insensitively
        ('"-role",ddl', ["ddl"]),
        ("misc", ["misc"]),                  # misc does not add misc_set
        ("misc_set", ["misc_set"]),
    ])
    def test_classes(self, value, classes):
        assert pgaudit_log_classes(value) == classes

    @pytest.mark.parametrize("value", [
        "ddl write", "ddl,,write", "ddl,", ",ddl", "bogus", "ddl,bogus", "-", '""', '"ddl', "ddl\x00",
        "reads", "rol", "all;ddl", "ddl,ro le", None,
    ])
    def test_unparseable(self, value):
        with pytest.raises(ValueError):
            pgaudit_log_classes(value)


# ---------------------------------------------------------------------------
# E0: settings rows by name
# ---------------------------------------------------------------------------

class TestSettingRows:
    @pytest.mark.parametrize("rec,name", [("3.2", "shared_preload_libraries"), ("5.6", "shared_preload_libraries"),
                                          ("6.10", "ssl_ciphers")])
    def test_missing_row_is_field_missing(self, rec, name):
        s = drop_setting(snap(), name)
        out = run(rec, s)
        assert_gapped(out, {"code": "field_missing", "section": "settings", "field": name})
        assert out["evidence_paths"] == [f"settings.{name}"]

    @pytest.mark.parametrize("rec", ["3.2", "5.6", "6.10", "6.8"])
    def test_settings_not_collected(self, rec):
        s = snap()
        s["baseline"]["settings"] = None
        s["baseline"]["gaps"] = [gap("settings")]
        assert_gapped(run(rec, s), {"code": "section_not_collected", "section": "settings",
                                    "gap_reason": "insufficient_privilege"})

    @pytest.mark.parametrize("source", ["user", "database", "database user", "session", "client", "global",
                                        "", None, "weird"])
    def test_non_server_wide_source_is_session_override(self, source):
        s = setting(snap(), "shared_preload_libraries", "pgaudit", source=source)
        setting(s, "pgaudit.log", "all")
        out = run("3.2", s, profile())
        assert_gapped(out, {"code": "session_override", "setting_name": "shared_preload_libraries",
                            "source": source if isinstance(source, str) else None})

    @pytest.mark.parametrize("mutate", [lambda r: r.update(sanitised=True), lambda r: r.update(sanitised=None),
                                        lambda r: r.update(setting="***REDACTED*** (set, 7 characters)")])
    def test_sanitised_row_is_gapped(self, mutate):
        s = setting(snap(), "ssl_ciphers", CIS_LIST)
        mutate(next(r for r in s["baseline"]["settings"] if r["name"] == "ssl_ciphers"))
        assert_gapped(run("6.10", s), {"code": "redacted_secret_setting", "setting_name": "ssl_ciphers"})

    def test_duplicate_row_is_field_missing(self):
        s = snap()
        row = next(r for r in s["baseline"]["settings"] if r["name"] == "ssl_ciphers")
        s["baseline"]["settings"].append({**row, "setting": CIS_LIST})
        assert_gapped(run("6.10", s), {"code": "field_missing", "section": "settings", "field": "ssl_ciphers"})

    @pytest.mark.parametrize("value", [None, 1, ["a"], True])
    def test_non_string_value_is_field_missing(self, value):
        s = setting(snap(), "ssl_ciphers", value)
        assert_gapped(run("6.10", s), {"code": "field_missing", "section": "settings", "field": "ssl_ciphers"})


# ---------------------------------------------------------------------------
# 3.2 pgaudit_enabled (parameterised)
# ---------------------------------------------------------------------------

def pgaudit(preload="pgaudit", log="ddl,role,write", **log_extra) -> dict:
    s = setting(snap(), "shared_preload_libraries", preload, source="configuration file")
    if log is not None:
        setting(s, "pgaudit.log", log, **log_extra)
    return s


class TestPgaudit32:
    def test_stock_image_fails_not_preloaded_whatever_the_policy(self):
        for policy in (None, profile(approved=False), profile()):
            out = run("3.2", snap(), policy)
            assert out["result"] == "FAIL"
            assert out["explanation"] == {"code": "pgaudit_not_preloaded"}
            assert out["evidence"] == [{"type": "setting", "setting_name": "shared_preload_libraries", "value": "",
                                        "items": [], "pgaudit_preloaded": False}]
            assert out["evidence_paths"] == ["settings.shared_preload_libraries"]

    @pytest.mark.parametrize("preload", ["pg_stat_statements", "pgaudit2", "PGAUDIT", "pgaudit.so.1",
                                         '"pg_stat_statements,pgaudit"'])
    def test_other_libraries_fail(self, preload):
        assert run("3.2", pgaudit(preload), profile())["explanation"] == {"code": "pgaudit_not_preloaded"}

    @pytest.mark.parametrize("preload", ["pgaudit", "$libdir/pgaudit", "pgaudit.so", '"pgaudit"',
                                         "pg_stat_statements, pgaudit", "/usr/lib/postgresql/17/lib/pgaudit.so"])
    def test_preload_forms_that_count(self, preload):
        out = run("3.2", pgaudit(preload), profile())
        assert out["result"] == "PASS"
        assert out["evidence"][0]["pgaudit_preloaded"] is True

    @pytest.mark.parametrize("preload", ["pgaudit,,x", "pgaudit,", '"pgaudit', "./pgaudit", "pgaudit\x01"])
    def test_unparseable_preload_is_manual_never_pass(self, preload):
        out = run("3.2", pgaudit(preload), profile())
        assert out["result"] == "MANUAL"
        assert out["explanation"] == {"code": "preload_list_unparseable", "setting_name": "shared_preload_libraries"}

    @pytest.mark.parametrize("policy", [None, "unapproved", "approved"])
    def test_pgaudit_log_row_missing_is_fail(self, policy):
        policy = {None: None, "unapproved": profile(approved=False), "approved": profile()}[policy]
        out = run("3.2", pgaudit(log=None), policy)
        assert out["result"] == "FAIL"
        assert out["explanation"] == {"code": "pgaudit_log_missing"}
        assert out["evidence"][-1] == {"type": "setting", "setting_name": "pgaudit.log", "value": None}

    def test_session_override_comes_before_policy_missing(self):
        out = run("3.2", pgaudit(log="all", source="user"))
        assert_gapped(out, {"code": "session_override", "setting_name": "pgaudit.log", "source": "user"})

    def test_redacted_pgaudit_log_is_gapped(self):
        s = pgaudit(log="***REDACTED*** (set, 3 characters)")
        assert_gapped(run("3.2", s, profile()), {"code": "redacted_secret_setting", "setting_name": "pgaudit.log"})

    def test_policy_missing_cases(self):
        s = pgaudit(log="all")
        assert run("3.2", s)["explanation"] == {"code": "policy_missing", "case": "no_profile"}
        assert run("3.2", s, profile(approved=False))["explanation"] == {
            "code": "policy_missing", "case": "profile_unapproved", "profile_id": "test-profile"}
        assert run("3.2", s, profile(classes=None))["explanation"] == {
            "code": "policy_missing", "case": "no_value_for_spec", "profile_id": "test-profile"}
        for policy in (None, profile(approved=False), profile(classes=None)):
            assert run("3.2", s, policy)["result"] == "MANUAL"

    @pytest.mark.parametrize("policy", [
        SimpleNamespace(approved=True, profile_id="p", pgaudit_log_classes=["all"]),
        SimpleNamespace(approved=True, profile_id="p", pgaudit_log_classes=[]),
        SimpleNamespace(approved=True, profile_id="p", pgaudit_log_classes="ddl"),
        SimpleNamespace(approved=True, profile_id="p", pgaudit_log_classes=["ddl", "ddl"]),
        SimpleNamespace(approved="yes", profile_id="p", pgaudit_log_classes=["ddl"]),
        SimpleNamespace(approved=True, profile_id="p"),
    ])
    def test_hand_built_or_invalid_policy_values_are_never_used(self, policy):
        out = run("3.2", pgaudit(log="none"), policy)
        assert out["result"] == "MANUAL" and out["explanation"]["code"] == "policy_missing"

    def test_unapproved_reference_profile_is_policy_missing(self):
        reference = load_default_profile(RECORDS)
        assert reference.pgaudit_log_classes == ["ddl", "role", "write"] and not reference.approved
        assert run("3.2", pgaudit(log="all"), reference)["explanation"]["case"] == "profile_unapproved"

    def test_policy_missing_comes_before_unparseable(self):
        s = pgaudit(log="bogus")
        assert run("3.2", s)["explanation"]["code"] == "policy_missing"
        out = run("3.2", s, profile())
        assert out["result"] == "MANUAL"
        assert out["explanation"] == {"code": "pgaudit_log_unparseable", "setting_name": "pgaudit.log"}

    @pytest.mark.parametrize("log,result,missing", [
        ("ddl,role,write", "PASS", None),
        ("write,role,ddl", "PASS", None),
        ("all", "PASS", None),
        ("read,write,role,ddl,misc", "PASS", None),      # extra classes do not fail
        ("ddl,write", "FAIL", ["role"]),                  # the CIS remediation example
        ("none", "FAIL", ["write", "role", "ddl"]),       # pgaudit's default
        ("", "FAIL", ["write", "role", "ddl"]),
        ("all,-role", "FAIL", ["role"]),
        ("read,function,misc,misc_set", "FAIL", ["write", "role", "ddl"]),
    ])
    def test_classes_against_the_policy(self, log, result, missing):
        out = run("3.2", pgaudit(log=log), profile())
        assert out["result"] == result
        effective = pgaudit_log_classes(log)
        facts = {"policy_classes": ["write", "role", "ddl"], "effective_classes": effective}
        if missing is None:
            assert out["explanation"] == {"code": "pgaudit_log_classes_present", **facts}
        else:
            assert out["explanation"] == {"code": "pgaudit_log_classes_missing", **facts, "missing_classes": missing}
        assert out["evidence"][-1] == {"type": "setting", "setting_name": "pgaudit.log", "value": log,
                                       "effective_classes": effective}
        assert out["evidence_paths"] == ["settings.shared_preload_libraries", "settings.pgaudit.log"]

    def test_a_different_policy_changes_the_result(self):
        s = pgaudit(log="ddl,write")
        assert run("3.2", s, profile(classes=["ddl"]))["result"] == "PASS"
        assert run("3.2", s, profile(classes=["read"]))["explanation"]["missing_classes"] == ["read"]

    def test_policy_only_reaches_evaluators_with_policy_keys(self):
        assert {n for n, e in REGISTRY.items() if e.policy_keys} == {"pgaudit_enabled"}
        assert REGISTRY["pgaudit_enabled"].policy_keys == ("pgaudit_log_classes",)
        assert uses_policy_profile(SPECS["3.2"])
        assert not any(uses_policy_profile(SPECS[r]) for r in SPECS if r != "3.2")
        # A profile given to any other evaluator changes nothing.
        for rec in ("5.6", "6.10", "6.8", "4.8", "6.11", "5.3", "5.4"):
            assert run(rec, snap(), profile()) == run(rec, snap())


# ---------------------------------------------------------------------------
# 5.6 password_complexity_module
# ---------------------------------------------------------------------------

def pwcheck(preload, path="$libdir", path_source="default") -> dict:
    s = setting(snap(), "shared_preload_libraries", preload)
    return setting(s, "dynamic_library_path", path, source=path_source)


class TestPasswordcheck56:
    def test_stock_image_fails(self):
        out = run("5.6", snap())
        assert out["result"] == "FAIL"
        assert out["explanation"] == {"code": "passwordcheck_not_preloaded"}

    @pytest.mark.parametrize("preload", ["passwordcheck", "$libdir/passwordcheck", '"passwordcheck"',
                                         "pgaudit, passwordcheck", "$libdir//passwordcheck/"])
    def test_pass_with_libdir(self, preload):
        out = run("5.6", pwcheck(preload))
        assert out["result"] == "PASS"
        assert out["explanation"] == {"code": "passwordcheck_preloaded"}
        assert out["evidence"][-1] == {"type": "setting", "setting_name": "dynamic_library_path", "value": "$libdir"}

    @pytest.mark.parametrize("preload", ["passwordcheck.so", "/usr/lib/postgresql/17/lib/passwordcheck",
                                         "PasswordCheck", "passwordcheck2", "$libdir/passwordcheck.so"])
    def test_forms_cis_does_not_list_fail(self, preload):
        assert run("5.6", pwcheck(preload))["explanation"] == {"code": "passwordcheck_not_preloaded"}

    @pytest.mark.parametrize("path", ["/opt/lib:$libdir", "$libdir:/opt/lib", "", "$libdir ", "$LIBDIR"])
    def test_bare_item_needs_libdir(self, path):
        for preload in ("passwordcheck", "passwordcheck, $libdir/passwordcheck"):
            out = run("5.6", pwcheck(preload, path, "configuration file"))
            assert out["result"] == "FAIL"
            assert out["explanation"] == {"code": "dynamic_library_path_not_libdir", "dynamic_library_path": path}

    def test_libdir_form_with_custom_path_is_manual(self):
        out = run("5.6", pwcheck("$libdir/passwordcheck", "/opt/lib", "configuration file"))
        assert out["result"] == "MANUAL"
        assert out["explanation"] == {"code": "libdir_form_with_custom_library_path",
                                      "dynamic_library_path": "/opt/lib"}

    @pytest.mark.parametrize("source", ["database", "user", "session"])
    def test_library_path_session_override_is_gapped(self, source):
        out = run("5.6", pwcheck("passwordcheck", "$libdir", source))
        assert_gapped(out, {"code": "session_override", "setting_name": "dynamic_library_path", "source": source})

    def test_library_path_row_missing_is_gapped_but_not_before_the_fail(self):
        s = drop_setting(snap(), "dynamic_library_path")
        assert run("5.6", s)["explanation"] == {"code": "passwordcheck_not_preloaded"}
        setting(s, "shared_preload_libraries", "passwordcheck")
        assert_gapped(run("5.6", s), {"code": "field_missing", "section": "settings", "field": "dynamic_library_path"})

    @pytest.mark.parametrize("preload", ["passwordcheck,", '"passwordcheck', "a,,passwordcheck"])
    def test_unparseable_is_manual(self, preload):
        out = run("5.6", pwcheck(preload))
        assert out["result"] == "MANUAL"
        assert out["explanation"] == {"code": "preload_list_unparseable", "setting_name": "shared_preload_libraries"}


# ---------------------------------------------------------------------------
# E0: connections visibility (6.8 and 6.10)
# ---------------------------------------------------------------------------

class TestConnectionVisibility:
    @pytest.mark.parametrize("rec", ["6.10", "6.8"])
    @pytest.mark.parametrize("row", [
        hidden(),
        {**hidden(), "visible": True},                       # NULL backend_type is hidden, whatever visible says
        {**conn(), "backend_type": None},
        {**conn(), "visible": False},
        {**conn(), "client_addr_class": "not_visible"},
    ], ids=["hidden", "null-type-visible-true", "null-type-tcp", "visible-false", "class-not-visible"])
    def test_hidden_session_makes_tls_part_gapped(self, rec, row):
        s = tls_ok(snap())
        s["baseline"]["connections"].append(row)
        out = run(rec, s)
        assert_gapped(out, {"code": "connections_not_visible", "section": "connections",
                            "hidden_connection_count": 1, "tls_details_gap": False})
        assert out["evidence_paths"] == ["connections"]

    @pytest.mark.parametrize("rec", ["6.10", "6.8"])
    def test_tls_gap_record_alone_is_gapped(self, rec):
        s = tls_ok(snap())
        s["baseline"]["gaps"] = [gap("connections.tls")]
        assert_gapped(run(rec, s), {"code": "connections_not_visible", "section": "connections",
                                    "hidden_connection_count": 0, "tls_details_gap": True})

    def test_hidden_counts_are_summed(self):
        s = tls_ok(snap())
        s["baseline"]["connections"] += [hidden(3), hidden(2), {**hidden(), "connection_count": "x"}]
        assert run("6.10", s)["explanation"]["hidden_connection_count"] == 6

    @pytest.mark.parametrize("rec", ["6.10", "6.8"])
    def test_connections_not_collected(self, rec):
        s = tls_ok(snap())
        s["baseline"]["connections"] = None
        s["baseline"]["gaps"] = [gap("connections")]
        assert_gapped(run(rec, s), {"code": "section_not_collected", "section": "connections",
                                    "gap_reason": "insufficient_privilege"})

    @pytest.mark.parametrize("rec", ["6.10", "6.8"])
    def test_collected_empty_list_is_not_unknown(self, rec):
        s = tls_ok(snap())
        s["baseline"]["connections"] = []
        assert run(rec, s)["result"] == "PASS"

    @pytest.mark.parametrize("rec", ["6.10", "6.8"])
    @pytest.mark.parametrize("row,field", [
        ({**conn(), "ssl": None}, "ssl"),
        ({**conn(), "ssl": "true"}, "ssl"),
        ({**conn(), "tls_version": None}, "tls_version"),
        ({**conn(), "tls_cipher": None}, "tls_cipher"),
        ({**conn(), "client_addr_class": "intranet"}, "client_addr_class"),
        ({**conn(), "connection_count": 0}, "connection_count"),
        ({**conn(), "connection_count": True}, "connection_count"),
        ({k: v for k, v in conn().items() if k != "backend_type"}, "backend_type"),
        ({k: v for k, v in conn().items() if k != "visible"}, "visible"),
        ("a row", "row"),
    ])
    def test_unreadable_visible_row_is_field_missing(self, rec, row, field):
        s = tls_ok(snap())
        s["baseline"]["connections"].append(row)
        assert_gapped(run(rec, s), {"code": "field_missing", "section": "connections", "field": field})

    def test_unix_socket_rows_say_nothing_about_encryption(self):
        s = tls_ok(snap())
        s["baseline"]["connections"] += [conn(addr="unix_socket", ssl=False),
                                         {**conn(addr="unix_socket"), "ssl": None},
                                         conn(addr="unix_socket", ssl=True, cipher=WEAK)]
        assert run("6.8", s)["result"] == "PASS"
        assert run("6.10", s)["result"] == "PASS"


# ---------------------------------------------------------------------------
# 6.10 tls_cipher_suites
# ---------------------------------------------------------------------------

class TestCiphers610:
    def test_postgres_default_list_fails(self):
        out = run("6.10", snap())
        assert out["result"] == "FAIL"
        assert out["explanation"] == {"code": "unapproved_ciphers_configured",
                                      "other_items": ["HIGH", "MEDIUM", "+3DES", "!aNULL"]}

    @pytest.mark.parametrize("value", [
        CIS_LIST, ",".join(CIS_TLS12_CIPHERS), " ".join(CIS_TLS12_CIPHERS), ";".join(CIS_TLS12_CIPHERS),
        CIS_TLS12_CIPHERS[0], f"{CIS_TLS12_CIPHERS[1]}::{CIS_TLS12_CIPHERS[2]};, {CIS_TLS12_CIPHERS[3]}:",
        f"{CIS_LIST}:{CIS_TLS12_CIPHERS[0]}",
    ])
    def test_only_cis_ciphers_pass(self, value):
        s = setting(snap(), "ssl_ciphers", value)
        out = run("6.10", s)
        assert out["result"] == "PASS"
        assert out["explanation"] == {"code": "approved_ciphers_only"}

    @pytest.mark.parametrize("value,other", [
        (f"{CIS_LIST}:!aNULL", ["!aNULL"]),
        ("HIGH", ["HIGH"]),
        (CIS_TLS12_CIPHERS[0].lower(), [CIS_TLS12_CIPHERS[0].lower()]),
        (f"{CIS_TLS12_CIPHERS[0]}\t{CIS_TLS12_CIPHERS[1]}", [f"{CIS_TLS12_CIPHERS[0]}\t{CIS_TLS12_CIPHERS[1]}"]),
        (f"{CIS_TLS12_CIPHERS[0]}:@SECLEVEL=0", ["@SECLEVEL=0"]),
        (f"{WEAK}:{WEAK}", [WEAK]),
        (f"{CIS_TLS12_CIPHERS[0]}\x00HIGH", [f"{CIS_TLS12_CIPHERS[0]}\x00HIGH"]),
    ])
    def test_any_other_item_fails(self, value, other):
        out = run("6.10", setting(snap(), "ssl_ciphers", value))
        assert out["result"] == "FAIL"
        assert out["explanation"] == {"code": "unapproved_ciphers_configured", "other_items": other}

    @pytest.mark.parametrize("value", ["", ":", " ;,: "])
    def test_empty_is_manual(self, value):
        out = run("6.10", setting(snap(), "ssl_ciphers", value))
        assert out["result"] == "MANUAL"
        assert out["explanation"] == {"code": "ssl_ciphers_empty"}

    def test_empty_with_hidden_sessions_is_gapped(self):
        s = setting(snap(), "ssl_ciphers", "")
        s["baseline"]["connections"].append(hidden())
        assert run("6.10", s)["result"] == "GAPPED"

    @pytest.mark.parametrize("backend", ["client backend", "walsender"])
    @pytest.mark.parametrize("addr", ["loopback", "private", "public"])
    def test_tls12_session_with_another_cipher_fails(self, backend, addr):
        s = tls_ok(snap())
        s["baseline"]["connections"] += [conn(addr=addr, cipher=WEAK, backend=backend, count=2),
                                         conn(addr=addr, cipher="DHE-RSA-AES256-SHA", count=1)]
        out = run("6.10", s)
        assert out["result"] == "FAIL"
        assert out["explanation"] == {"code": "unapproved_cipher_in_use", "connection_count": 3,
                                      "ciphers": sorted(["DHE-RSA-AES256-SHA", WEAK])}
        assert out["evidence"][1] == {"type": "connection", "backend_type": backend, "usename": "app",
                                      "datname": "appdb", "client_addr_class": addr, "tls_version": "TLSv1.2",
                                      "tls_cipher": WEAK, "connection_count": 2}

    @pytest.mark.parametrize("version", ["TLSv1.3", "TLSv1.1", "TLSv1"])
    def test_only_tls12_sessions_are_compared(self, version):
        s = tls_ok(snap())
        s["baseline"]["connections"].append(conn(version=version, cipher="TLS_AES_256_GCM_SHA384"))
        assert run("6.10", s)["result"] == "PASS"

    def test_configuration_fail_is_reported_first_with_the_sessions_as_evidence(self):
        s = tls_ok(snap())
        setting(s, "ssl_ciphers", "HIGH")
        s["baseline"]["connections"].append(conn(cipher=WEAK))
        out = run("6.10", s)
        assert out["explanation"] == {"code": "unapproved_ciphers_configured", "other_items": ["HIGH"]}
        assert [e["type"] for e in out["evidence"]] == ["setting", "connection"]

    def test_readable_fail_wins_over_hidden_sessions_and_missing_sections(self):
        s = tls_ok(snap())
        s["baseline"]["connections"] += [hidden(4), conn(cipher=WEAK)]
        assert run("6.10", s)["explanation"]["code"] == "unapproved_cipher_in_use"
        s["baseline"]["gaps"] = [gap("connections.tls")]
        assert run("6.10", s)["explanation"]["code"] == "unapproved_cipher_in_use"
        s = setting(snap(), "ssl_ciphers", "HIGH")
        s["baseline"]["connections"] = None
        s["baseline"]["gaps"] = [gap("connections")]
        out = run("6.10", s)
        assert out["result"] == "FAIL"
        assert out["explanation"] == {"code": "unapproved_ciphers_configured", "other_items": ["HIGH"],
                                      "sections_not_collected": ["connections"]}

    def test_the_check_applies_with_ssl_off(self):
        s = tls_ok(snap())
        setting(s, "ssl", "off")
        assert run("6.10", s)["result"] == "PASS"
        setting(s, "ssl_ciphers", "HIGH")
        assert run("6.10", s)["result"] == "FAIL"


# ---------------------------------------------------------------------------
# 6.8 tls_enabled_and_enforced
# ---------------------------------------------------------------------------

class TestTls68:
    def test_stock_image_fails_ssl_and_host_rules(self):
        out = run("6.8", snap())
        assert out["result"] == "FAIL"
        assert out["explanation"] == {"code": "tls_not_enabled_or_enforced",
                                      "failing_parts": ["ssl_off", "non_tls_hba_rules"]}
        rules = [e for e in out["evidence"] if e["type"] == "hba_rule"]
        assert [r["line_number"] for r in rules] == [119, 121, 125, 126, 128]
        assert rules[0] == {"type": "hba_rule", "line_number": 119, "connection_type": "host", "database": ["all"],
                            "user_name": ["all"], "auth_method": "trust", "has_error": False,
                            "address": "127.0.0.1", "netmask": "255.255.255.255", "finding": "non_tls_hba_rule"}

    def test_pass(self):
        out = run("6.8", tls_ok(snap()))
        assert out["result"] == "PASS"
        assert out["explanation"] == {"code": "tls_enabled_and_enforced"}
        assert out["evidence"] == [{"type": "setting", "setting_name": "ssl", "value": "on"}]

    @pytest.mark.parametrize("typ", ["host", "hostnossl"])
    def test_non_tls_rule_fails(self, typ):
        s = tls_ok(snap())
        s["baseline"]["hba_rules"].append(hba(9, typ))
        out = run("6.8", s)
        assert out["explanation"] == {"code": "tls_not_enabled_or_enforced", "failing_parts": ["non_tls_hba_rules"]}

    @pytest.mark.parametrize("backend", ["client backend", "walsender"])
    @pytest.mark.parametrize("addr", ["loopback", "private", "public"])
    def test_unencrypted_tcp_session_fails(self, backend, addr):
        s = tls_ok(snap())
        s["baseline"]["connections"].append(conn(addr=addr, ssl=False, backend=backend, count=2))
        out = run("6.8", s)
        assert out["explanation"] == {"code": "tls_not_enabled_or_enforced",
                                      "failing_parts": ["unencrypted_tcp_connections"]}
        assert out["evidence"][-1] == {"type": "connection", "backend_type": backend, "usename": "app",
                                       "datname": "appdb", "client_addr_class": addr, "ssl": False,
                                       "connection_count": 2, "finding": "unencrypted_tcp_connection"}

    def test_every_failing_part_is_named(self):
        s = tls_ok(snap())
        setting(s, "ssl", "off")
        s["baseline"]["hba_rules"].append(hba(9, "hostnossl"))
        s["baseline"]["connections"].append(conn(ssl=False))
        assert run("6.8", s)["explanation"]["failing_parts"] == [
            "ssl_off", "non_tls_hba_rules", "unencrypted_tcp_connections"]

    @pytest.mark.parametrize("typ", ["hostgssenc", "hostnogssenc"])
    def test_gss_rule_is_manual_never_pass(self, typ):
        s = tls_ok(snap())
        s["baseline"]["hba_rules"].append(hba(9, typ, "gss"))
        out = run("6.8", s)
        assert out["result"] == "MANUAL"
        assert out["explanation"] == {"code": "gss_hba_rules", "evidence_count": 2, "rule_count": 1}
        assert out["evidence"][-1]["finding"] == "gss_hba_rule"

    def test_error_line_is_manual_and_gss_comes_first(self):
        s = tls_ok(snap())
        s["baseline"]["hba_rules"].append(error_line(9, "SUPERSECRET_ERRORTEXT"))
        out = run("6.8", s)
        assert out["explanation"] == {"code": "hba_rule_error", "evidence_count": 2, "rule_count": 1}
        assert "SUPERSECRET_ERRORTEXT" not in json.dumps(out)
        s["baseline"]["hba_rules"].append(hba(10, "hostgssenc", "gss"))
        assert run("6.8", s)["explanation"]["code"] == "gss_hba_rules"

    @pytest.mark.parametrize("value", ["true", "On", "", "1"])
    def test_unreadable_ssl_value_is_gapped(self, value):
        s = setting(tls_ok(snap()), "ssl", value)
        assert_gapped(run("6.8", s), {"code": "field_missing", "section": "settings", "field": "ssl"})

    def test_gapped_comes_before_manual(self):
        s = tls_ok(snap())
        s["baseline"]["hba_rules"].append(hba(9, "hostgssenc", "gss"))
        s["baseline"]["connections"].append(hidden())
        assert run("6.8", s)["explanation"]["code"] == "connections_not_visible"

    def test_hba_not_collected(self):
        s = tls_ok(snap())
        s["baseline"]["hba_rules"] = None
        s["baseline"]["gaps"] = [gap("hba_rules")]
        assert_gapped(run("6.8", s), {"code": "section_not_collected", "section": "hba_rules",
                                      "gap_reason": "insufficient_privilege"})

    def test_readable_fail_is_reported_with_the_unknown_parts(self):
        s = tls_ok(snap())
        setting(s, "ssl", "off")
        s["baseline"]["hba_rules"] = None
        s["baseline"]["gaps"] = [gap("hba_rules"), gap("connections.tls")]
        out = run("6.8", s)
        assert out["result"] == "FAIL"
        assert out["explanation"] == {"code": "tls_not_enabled_or_enforced", "failing_parts": ["ssl_off"],
                                      "unknown_parts": ["hba_rules", "connections"],
                                      "sections_not_collected": ["hba_rules"]}
        s = drop_setting(tls_ok(snap()), "ssl")
        s["baseline"]["hba_rules"].append(hba(9, "host"))
        assert run("6.8", s)["explanation"] == {"code": "tls_not_enabled_or_enforced",
                                                "failing_parts": ["non_tls_hba_rules"], "unknown_parts": ["ssl"]}

    def test_hidden_session_does_not_hide_a_visible_unencrypted_one(self):
        s = tls_ok(snap())
        s["baseline"]["connections"] += [hidden(), conn(ssl=False)]
        out = run("6.8", s)
        assert out["explanation"]["failing_parts"] == ["unencrypted_tcp_connections"]
        assert out["explanation"]["unknown_parts"] == ["connections"]

    def test_malformed_hba_row_is_gapped_unless_another_part_fails(self):
        s = tls_ok(snap())
        s["baseline"]["hba_rules"].append({**hba(9), "line_number": "9"})
        assert_gapped(run("6.8", s), {"code": "field_missing", "section": "hba_rules", "field": "line_number"})
        setting(s, "ssl", "off")
        assert run("6.8", s)["explanation"]["unknown_parts"] == ["hba_rules"]

    def test_a_tls_session_over_gss_is_not_counted_as_encrypted_by_6_8(self):
        """The CIS query reads pg_stat_ssl only: a GSS-encrypted TCP session without TLS fails."""
        s = tls_ok(snap())
        s["baseline"]["connections"].append(conn(ssl=False))
        assert run("6.8", s)["result"] == "FAIL"


# ---------------------------------------------------------------------------
# 4.8 set_user_extension
# ---------------------------------------------------------------------------

def with_set_user(s: dict, installed=None) -> dict:
    s["baseline"]["available_extensions"].append(extension("set_user", "4.1.0", installed))
    return s


class TestSetUser48:
    def test_not_available_fails(self):
        out = run("4.8", snap())
        assert out["result"] == "FAIL"
        facts = {"extension_name": "set_user", "available": False, "default_version": None,
                 "installed_version": None, "database": "dbguard_sandbox"}
        assert out["explanation"] == {"code": "set_user_not_available", **facts}
        assert out["evidence"] == [{"type": "extension", "name": "set_user", "available": False,
                                    "default_version": None, "installed_version": None,
                                    "database": "dbguard_sandbox"}]

    def test_not_available_fails_even_without_roles(self):
        s = snap()
        s["baseline"]["roles"] = None
        s["baseline"]["gaps"] = [gap("roles")]
        assert run("4.8", s)["explanation"]["code"] == "set_user_not_available"

    def test_bootstrap_login_superuser_is_listed(self):
        out = run("4.8", with_set_user(snap(), "4.1.0"))
        assert out["result"] == "MANUAL"
        assert out["explanation"] == {"code": "superuser_login_review", "evidence_count": 2,
                                      "extension_name": "set_user", "available": True, "default_version": "4.1.0",
                                      "installed_version": "4.1.0", "database": "dbguard_sandbox"}
        assert out["evidence"][1] == {"type": "superuser_login", "rolname": "dbguard_poc", "rolsuper": True,
                                      "superuser_ancestors": [], "bootstrap_superuser": True}

    def test_empty_list_passes(self):
        s = with_set_user(snap())
        s["baseline"]["roles"] = [role("postgres", 10, login=False, superuser=True), role("app", 16384),
                                  role("admins", 16385, login=False)]
        s["baseline"]["role_memberships"] = [member("admins", "app")]
        out = run("4.8", s)
        assert out["result"] == "PASS"
        assert out["explanation"]["code"] == "empty_review_set"
        assert out["explanation"]["evidence_count"] == 0

    def test_inherited_superuser_is_listed_with_its_path(self):
        s = with_set_user(snap())
        # alice inherits through admins; bob is a member of a non-superuser group only.
        s["baseline"]["roles"] = [role("postgres", 10, login=False, superuser=True), role("alice", 16384),
                                  role("admins", 16385, login=False), role("bob", 16386),
                                  role("staff", 16387, login=False)]
        s["baseline"]["role_memberships"] = [member("postgres", "admins"), member("admins", "alice"),
                                             member("staff", "bob")]
        out = run("4.8", s)
        assert out["result"] == "MANUAL"
        assert out["evidence"][1:] == [{"type": "superuser_login", "rolname": "alice", "rolsuper": False,
                                        "superuser_ancestors": [{"rolname": "postgres",
                                                                 "path": ["postgres", "admins", "alice"]}],
                                        "bootstrap_superuser": False}]

    def test_nologin_superusers_are_not_listed(self):
        s = with_set_user(snap())
        s["baseline"]["roles"] = [role("postgres", 10, login=False, superuser=True),
                                  role("ops", 16384, login=False, superuser=True)]
        s["baseline"]["role_memberships"] = []
        assert run("4.8", s)["result"] == "PASS"

    @pytest.mark.parametrize("section", ["roles", "role_memberships"])
    def test_roles_required_once_available(self, section):
        s = with_set_user(snap())
        s["baseline"][section] = None
        s["baseline"]["gaps"] = [gap(section)]
        assert_gapped(run("4.8", s), {"code": "section_not_collected", "section": section,
                                      "gap_reason": "insufficient_privilege"})

    def test_member_missing_from_roles_is_gapped(self):
        s = with_set_user(snap())
        s["baseline"]["role_memberships"] = [member("dbguard_poc", "ghost")]
        assert_gapped(run("4.8", s), {"code": "field_missing", "section": "roles", "field": "rolname"})

    def test_roles_without_bootstrap_is_gapped(self):
        s = with_set_user(snap())
        s["baseline"]["roles"] = [role("app", 16384)]
        assert_gapped(run("4.8", s), {"code": "field_missing", "section": "roles", "field": "oid"})

    @pytest.mark.parametrize("mutate,field", [
        (lambda rows: rows.append({"default_version": "1"}), "name"),
        (lambda rows: rows.append({"name": "set_user", "default_version": 1, "installed_version": None}),
         "default_version"),
        (lambda rows: rows.append("set_user"), "row"),
    ])
    def test_unreadable_extension_row(self, mutate, field):
        s = snap()
        mutate(s["baseline"]["available_extensions"])
        assert_gapped(run("4.8", s), {"code": "field_missing", "section": "available_extensions", "field": field})

    @pytest.mark.parametrize("rec", ["4.8", "6.11"])
    def test_extensions_not_collected(self, rec):
        s = snap()
        s["baseline"]["available_extensions"] = None
        s["baseline"]["gaps"] = [gap("available_extensions")]
        assert_gapped(run(rec, s), {"code": "section_not_collected", "section": "available_extensions",
                                    "gap_reason": "insufficient_privilege"})

    @pytest.mark.parametrize("rec", ["4.8", "6.11"])
    def test_collected_empty_extensions(self, rec):
        s = snap()
        s["baseline"]["available_extensions"] = []
        out = run(rec, s)
        assert out["result"] == ("FAIL" if rec == "4.8" else "MANUAL")
        assert out["explanation"]["available"] is False


# ---------------------------------------------------------------------------
# 6.11 pgcrypto_extension (manual_checklist)
# ---------------------------------------------------------------------------

class TestPgcrypto611:
    def test_available_not_installed(self):
        out = run("6.11", snap())
        assert out["result"] == "MANUAL"
        assert out["explanation"] == {"code": "manual_review", "evidence_count": 1,
                                      "installed_version_scope": "connected_database", "extension_name": "pgcrypto",
                                      "available": True, "default_version": "1.3", "installed_version": None,
                                      "database": "dbguard_sandbox"}

    @pytest.mark.parametrize("mutate", [
        lambda rows: [r.update(installed_version="1.3") for r in rows if r["name"] == "pgcrypto"],
        lambda rows: rows.__setitem__(slice(None), [r for r in rows if r["name"] != "pgcrypto"]),
    ])
    def test_always_manual(self, mutate):
        s = snap()
        mutate(s["baseline"]["available_extensions"])
        out = run("6.11", s)
        assert out["result"] == "MANUAL" and out["explanation"]["code"] == "manual_review"

    def test_missing_envelope_database_is_shown_as_null(self):
        s = snap()
        del s["envelope"]["database"]
        out = run("6.11", s)
        assert out["result"] == "MANUAL" and out["explanation"]["database"] is None


# ---------------------------------------------------------------------------
# 5.3 local_hba_rules and 5.4 host_hba_rules (manual_checklist)
# ---------------------------------------------------------------------------

class TestLocalRules53:
    def test_live_fixture(self):
        out = run("5.3", snap())
        assert out["result"] == "MANUAL"
        assert out["explanation"] == {"code": "manual_review", "evidence_count": 2, "highlight_count": 2}
        assert out["evidence"][0] == {"type": "hba_rule", "line_number": 117, "connection_type": "local",
                                      "database": ["all"], "user_name": ["all"], "auth_method": "trust",
                                      "has_error": False, "options": [],
                                      "highlights": ["auth_method_not_peer_or_reject"]}

    def test_highlights_and_selection(self):
        s = snap()
        s["baseline"]["hba_rules"] = [hba(1, "local", "peer"), hba(2, "local", "reject"), hba(3, "local", "md5"),
                                      hba(4, "local", "scram-sha-256"), hba(5, "host", "trust"), error_line(6)]
        out = run("5.3", s)
        assert [(e["line_number"], e["highlights"]) for e in out["evidence"]] == [
            (1, []), (2, []), (3, ["auth_method_not_peer_or_reject"]), (4, ["auth_method_not_peer_or_reject"]),
            (6, ["line_error"])]
        assert out["explanation"]["highlight_count"] == 3

    def test_options_show_values_only_for_the_allowlist(self):
        s = snap()
        s["baseline"]["hba_rules"] = [hba(1, "local", "peer", options=[
            "map=osmap", "clientcert=verify-full", "clientname=CN", "ldapbindpasswd=SUPERSECRET_UNMASKED",
            "ldapbindpasswd=***REDACTED***", "radiussecrets=SUPERSECRET_RADIUS", "ldapbinddn=cn=SUPERSECRET_DN",
            "Weird Name=SUPERSECRET_WEIRD", "SUPERSECRET_NOEQUALS", "=SUPERSECRET_EMPTYNAME"])]
        s["baseline"]["ident_mappings"] = []
        out = run("5.3", s)
        assert out["evidence"][0]["options"] == [
            {"name": "map", "value": "osmap"}, {"name": "clientcert", "value": "verify-full"},
            {"name": "clientname", "value": "CN"}, {"name": "ldapbindpasswd"}, {"name": "ldapbindpasswd"},
            {"name": "radiussecrets"}, {"name": "ldapbinddn"}, {"name": None}, {"name": None}, {"name": None}]
        text = json.dumps(out)
        assert "SUPERSECRET" not in text and "REDACTED" not in text

    def test_user_name_maps_are_shown_with_the_rule(self):
        s = snap()
        s["baseline"]["hba_rules"] = [hba(1, "local", "peer", options=["map=osmap"]), hba(2, "local", "peer")]
        s["baseline"]["ident_mappings"] = [ident(10, "osmap", "root", "postgres"), ident(11, "other", "x", "y"),
                                           ident(12, "osmap", "/^(.*)$", "\\1"),
                                           ident(13, None, None, None, error="bad line")]
        out = run("5.3", s)
        assert out["evidence"][0]["ident_mappings"] == [
            {"line_number": 10, "map_name": "osmap", "sys_name": "root", "pg_username": "postgres", "has_error": False},
            {"line_number": 12, "map_name": "osmap", "sys_name": "/^(.*)$", "pg_username": "\\1", "has_error": False}]
        assert "ident_mappings" not in out["evidence"][1]
        assert "bad line" not in json.dumps(out)

    def test_maps_not_collected_are_said_so(self):
        s = snap()
        s["baseline"]["hba_rules"] = [hba(1, "local", "peer", options=["map=osmap"])]
        s["baseline"]["ident_mappings"] = None
        s["baseline"]["gaps"] = [gap("ident_mappings")]
        out = run("5.3", s)
        assert out["result"] == "MANUAL"
        assert out["evidence"][0]["ident_mappings"] is None
        assert out["explanation"]["sections_not_collected"] == ["ident_mappings"]

    def test_maps_are_not_read_when_no_rule_uses_one(self):
        s = snap()
        s["baseline"]["ident_mappings"] = None
        s["baseline"]["gaps"] = [gap("ident_mappings")]
        out = run("5.3", s)
        assert "sections_not_collected" not in out["explanation"]

    def test_malformed_options_on_a_shown_rule_is_gapped_but_not_on_a_host_rule(self):
        s = snap()
        s["baseline"]["hba_rules"].append(hba(300, "host", options={"ldapbindpasswd": "x"}))
        assert run("5.3", s)["result"] == "MANUAL"
        s["baseline"]["hba_rules"].append(hba(301, "local", options="map=x"))
        assert_gapped(run("5.3", s), {"code": "field_missing", "section": "hba_rules", "field": "options"})

    def test_hba_not_collected(self):
        s = snap()
        s["baseline"]["hba_rules"] = None
        s["baseline"]["gaps"] = [gap("hba_rules")]
        assert_gapped(run("5.3", s), {"code": "section_not_collected", "section": "hba_rules",
                                      "gap_reason": "insufficient_privilege"})


class TestHostRules54:
    def test_live_fixture(self):
        out = run("5.4", snap())
        assert out["result"] == "MANUAL"
        assert [(e["line_number"], e["highlights"]) for e in out["evidence"]] == [
            (119, ["auth_method_not_for_remote"]), (121, ["auth_method_not_for_remote"]),
            (125, ["auth_method_not_for_remote"]), (126, ["auth_method_not_for_remote"]), (128, ["any_address"])]
        assert "options" not in out["evidence"][0]

    @pytest.mark.parametrize("method,highlights", [
        ("trust", ["auth_method_not_for_remote"]), ("password", ["auth_method_not_for_remote"]),
        ("ident", ["auth_method_not_for_remote"]), ("md5", ["auth_method_md5"]), ("scram-sha-256", []),
        ("cert", []), ("reject", []),
    ])
    def test_method_highlights(self, method, highlights):
        s = snap()
        s["baseline"]["hba_rules"] = [hba(1, "hostssl", method)]
        assert run("5.4", s)["evidence"][0]["highlights"] == highlights

    @pytest.mark.parametrize("address,netmask,any_address", [
        ("0.0.0.0", "0.0.0.0", True), ("::", "::", True), ("10.0.0.0", "0.0.0.0", True), ("all", None, True),
        ("10.0.0.0", "255.0.0.0", False), ("127.0.0.1", "255.255.255.255", False), ("samenet", None, False),
        (".example.com", None, False), ("::1", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", False),
        ("10.0.0.0", "not-a-mask", False),
    ])
    def test_any_address(self, address, netmask, any_address):
        s = snap()
        s["baseline"]["hba_rules"] = [hba(1, "hostssl", address=address, netmask=netmask)]
        out = run("5.4", s)
        assert ("any_address" in out["evidence"][0]["highlights"]) is any_address
        assert (out["evidence"][0]["address"], out["evidence"][0]["netmask"]) == (address, netmask)

    def test_every_host_type_and_error_lines_are_listed(self):
        s = snap()
        s["baseline"]["hba_rules"] = [hba(i, t) for i, t in enumerate(
            ("host", "hostssl", "hostnossl", "hostgssenc", "hostnogssenc", "local"), start=1)] + [error_line(7)]
        out = run("5.4", s)
        assert [e["line_number"] for e in out["evidence"]] == [1, 2, 3, 4, 5, 7]
        assert out["evidence"][-1]["highlights"] == ["line_error"]

    def test_no_secret_from_options_or_errors(self):
        s = snap()
        s["baseline"]["hba_rules"] = [hba(1, "host", "ldap", options=["ldapbindpasswd=SUPERSECRET_X"]),
                                      error_line(2, "SUPERSECRET_ERR")]
        assert "SUPERSECRET" not in json.dumps(run("5.4", s))


# ---------------------------------------------------------------------------
# Never PASS on unknown, across every Wave 2b evaluator
# ---------------------------------------------------------------------------

UNKNOWN_MUTATIONS = {
    "settings": lambda s: (s["baseline"].update(settings=None), s["baseline"].update(gaps=[gap("settings")])),
    "connections": lambda s: (s["baseline"].update(connections=None),
                              s["baseline"].update(gaps=[gap("connections")])),
    "hidden": lambda s: s["baseline"]["connections"].append(hidden()),
    "tls_gap": lambda s: s["baseline"].update(gaps=[gap("connections.tls")]),
    "hba": lambda s: (s["baseline"].update(hba_rules=None), s["baseline"].update(gaps=[gap("hba_rules")])),
    "extensions": lambda s: (s["baseline"].update(available_extensions=None),
                             s["baseline"].update(gaps=[gap("available_extensions")])),
    "roles": lambda s: (s["baseline"].update(roles=None), s["baseline"].update(gaps=[gap("roles")])),
    "wrong_major": lambda s: s["baseline"]["identity"].update(server_version_num=160004),
}


def passing(rec: str) -> tuple[dict, object]:
    """A snapshot (and policy) on which rec PASSes, where it can."""
    s = tls_ok(snap())
    if rec == "3.2":
        return pgaudit(log="all"), profile()
    if rec == "5.6":
        return pwcheck("passwordcheck"), None
    if rec == "4.8":
        s = with_set_user(snap())
        s["baseline"]["roles"] = [role("postgres", 10, login=False, superuser=True)]
        s["baseline"]["role_memberships"] = []
        return s, None
    return s, None


# The unknowns each evaluator reads (an unread section cannot change its result).
READS = {"3.2": ("settings", "wrong_major"), "5.6": ("settings", "wrong_major"),
         "6.10": ("settings", "connections", "hidden", "tls_gap", "wrong_major"),
         "6.8": ("settings", "connections", "hidden", "tls_gap", "hba", "wrong_major"),
         "4.8": ("extensions", "roles", "wrong_major")}


@pytest.mark.parametrize("rec,unknown", [(r, u) for r, us in READS.items() for u in us])
def test_unknown_evidence_never_passes(rec, unknown):
    s, policy = passing(rec)
    assert run(rec, s, policy)["result"] == "PASS"
    UNKNOWN_MUTATIONS[unknown](s)
    assert run(rec, s, policy)["result"] != "PASS"


@pytest.mark.parametrize("rec", ["6.11", "5.3", "5.4"])
@pytest.mark.parametrize("unknown", list(UNKNOWN_MUTATIONS))
def test_checklists_are_never_pass_or_fail(rec, unknown):
    s = tls_ok(snap())
    UNKNOWN_MUTATIONS[unknown](s)
    assert run(rec, s)["result"] in ("MANUAL", "GAPPED")


# ---------------------------------------------------------------------------
# Registry, validation (E11) and the assessment report
# ---------------------------------------------------------------------------

class TestRegistryAndValidation:
    def test_registry_entries(self):
        expected = {
            "pgaudit_enabled": ("3.2", ("parameterised",), ("settings",), ()),
            "password_complexity_module": ("5.6", ("automated",), ("settings",), ()),
            "tls_cipher_suites": ("6.10", ("automated",), ("settings",), ("connections",)),
            "tls_enabled_and_enforced": ("6.8", ("automated",), ("settings",), ("hba_rules", "connections")),
            "set_user_extension": ("4.8", ("automated",), ("available_extensions",), ("roles", "role_memberships")),
            "pgcrypto_extension": ("6.11", ("manual_checklist",), ("available_extensions",), ()),
            "local_hba_rules": ("5.3", ("manual_checklist",), ("hba_rules",), ("ident_mappings",)),
            "host_hba_rules": ("5.4", ("manual_checklist",), ("hba_rules",), ()),
        }
        for name, (rec, tiers, required, optional) in expected.items():
            entry = REGISTRY[name]
            assert (entry.recommendation, entry.tiers, entry.required_sections, entry.optional_sections) == (
                rec, tiers, required, optional), name
            assert SPECS[rec]["check"]["evaluator"] == name
            assert SPECS[rec]["tier"] in tiers

    @pytest.mark.parametrize("rec", list(SPECS))
    def test_quote_tokens_are_whole_tokens_and_dropping_one_fails(self, rec):
        spec = copy.deepcopy(SPECS[rec])
        assert validate_spec(spec, RECORDS) == []
        tokens = REGISTRY[spec["check"]["evaluator"]].quote_tokens
        if not tokens:
            return
        # A verbatim CIS sentence from the same audit text without the constants is refused.
        spec["check"]["pass_condition_quote"] = "this is a fail"
        errors = validate_spec(spec, RECORDS)
        assert any("evaluator constant" in e for e in errors) or any("not found" in e for e in errors)

    def test_cipher_constants_are_the_cis_four(self):
        quote = SPECS["6.10"]["check"]["pass_condition_quote"]
        for cipher in CIS_TLS12_CIPHERS:
            assert quote.count(cipher) == 2  # the list and the query

    def test_evaluate_rejects_a_rewired_spec(self):
        rewired = copy.deepcopy(SPECS["6.10"])
        rewired["check"]["evaluator"] = "tls_enabled_and_enforced"
        with pytest.raises(ValueError):
            evaluate(rewired, snap())


class TestAssessReport:
    def test_policy_profile_is_pinned_for_3_2(self):
        report = assess([SPECS["3.2"]], pgaudit(log="all"), RECORDS)
        assert report["inputs"]["policy_profile"] is None
        assert report["results"][0]["reason_code"] == "policy_missing"
        approved = profile()
        report = assess([SPECS["3.2"]], pgaudit(log="all"), RECORDS, approved)
        assert report["inputs"]["policy_profile"] == approved.pin()
        assert report["results"][0]["result"] == "PASS"
        assert "policy_profile" not in assess([SPECS["5.6"]], snap(), RECORDS)["inputs"]

    def test_assess_rows_equal_the_evaluator(self):
        s, policy = pgaudit(log="ddl"), profile()
        row = assess([SPECS["3.2"]], s, RECORDS, policy)["results"][0]
        out = run("3.2", s, policy)
        assert (row["result"], row["reason_code"], row["explanation"], row["evidence"]) == (
            "FAIL", "pgaudit_log_classes_missing", out["explanation"], out["evidence"])

    @pytest.mark.parametrize("build", [
        lambda: (snap(), None),
        lambda: (pgaudit(log="ddl"), profile()),
        lambda: (pgaudit(log="all"), profile()),
        lambda: (pgaudit(log="bogus"), profile()),
        lambda: (pgaudit(log="all"), profile(approved=False)),
        lambda: (pgaudit("pgaudit,"), None),
        lambda: (pwcheck("passwordcheck", "/x", "configuration file"), None),
        lambda: (pwcheck("$libdir/passwordcheck", "/x", "configuration file"), None),
        lambda: (pwcheck("passwordcheck"), None),
        lambda: (pwcheck("passwordcheck", "$libdir", "user"), None),
        lambda: (tls_ok(snap()), None),
        lambda: (setting(tls_ok(snap()), "ssl_ciphers", ""), None),
        lambda: (_with(tls_ok(snap()), connections=[conn(cipher=WEAK)]), None),
        lambda: (_with(tls_ok(snap()), connections=[hidden(2)]), None),
        lambda: (_with(tls_ok(snap()), hba_rules=[hba(1, "hostgssenc", "gss")]), None),
        lambda: (_with(tls_ok(snap()), hba_rules=[error_line(1)]), None),
        lambda: (_with(setting(tls_ok(snap()), "ssl", "off"), hba_rules=None, gaps=[gap("hba_rules")]), None),
        lambda: (with_set_user(snap()), None),
        lambda: (passing("4.8")[0], None),
    ])
    def test_every_report_validates_the_contract(self, build):
        s, policy = build()
        assert_contract(s, policy)


def _with(s: dict, **sections) -> dict:
    s["baseline"].update(sections)
    return s


# ---------------------------------------------------------------------------
# E9: the pgaudit_log_classes policy key
# ---------------------------------------------------------------------------

class TestPolicyKey:
    def test_reference_profile_carries_the_ruling_default_and_stays_unapproved(self):
        reference = load_default_profile(RECORDS)
        assert reference.pgaudit_log_classes == ["ddl", "role", "write"]
        assert reference.approved_by is None and not reference.approved
        text = (REPO_ROOT / "catalog/policies/cis-pg17-v1.1.0/reference.yaml").read_text()
        assert "W2B ruling 2" in text

    @pytest.mark.parametrize("value", [[], "ddl", ["all"], ["none"], ["ddl", "ddl"], ["DDL"], [1], {"ddl": 1},
                                       ["ddl", "-role"], [None], True])
    def test_invalid_values_are_refused(self, value):
        doc = {"profile_id": "p", "benchmark": "cis-pg17-v1.1.0", "approved_by": None, "approved_at": None,
               "values": {}, "pgaudit_log_classes": value}
        with pytest.raises(PolicyProfileError, match="pgaudit_log_classes"):
            parse_profile(yaml.safe_dump(doc).encode(), RECORDS)

    def test_absent_or_null_is_no_value(self):
        assert profile(classes=None).pgaudit_log_classes is None
        doc = {"profile_id": "p", "benchmark": "cis-pg17-v1.1.0", "approved_by": None, "approved_at": None,
               "values": {}, "pgaudit_log_classes": None}
        assert parse_profile(yaml.safe_dump(doc).encode(), RECORDS).pgaudit_log_classes is None

    def test_every_class_is_accepted(self):
        assert profile(classes=list(PGAUDIT_LOG_CLASSES)).pgaudit_log_classes == list(PGAUDIT_LOG_CLASSES)

    def test_approving_a_draft_keeps_the_key(self, tmp_path):
        from app.services.policy_profile_store import PolicyProfileStore
        specs = [load_spec(p) for p in sorted(SPEC_DIR.glob("*.yaml"))]
        store = PolicyProfileStore(tmp_path, RECORDS, specs)
        draft = store.create_draft(profile_id="draft", values={})
        assert draft.pgaudit_log_classes is None
        seed = load_default_profile(RECORDS)
        assert store.document(seed)["pgaudit_log_classes"] == ["ddl", "role", "write"]


# ---------------------------------------------------------------------------
# Offline ASSESS path (catalog/controls/assess/spec_controls.py)
# ---------------------------------------------------------------------------

class TestOfflineAssess:
    def test_3_2_uses_the_installed_profile_and_never_a_fix_template(self):
        from catalog.controls.assess.registry import CONTROL_REGISTRY
        control = CONTROL_REGISTRY["cis-pg17-v1.1.0:3.2"]
        assert control.template_id == "MANUAL_PROCEDURE" and control.is_automatable is False
        s = pgaudit(log="all")
        finding = control.evaluate({**s["baseline"], "envelope": s["envelope"]})
        # The installed reference profile is unapproved: never PASS.
        assert finding.explanation == {"code": "policy_missing", "case": "profile_unapproved",
                                       "profile_id": "cis-pg17-v1.1.0-reference"}
        assert finding.control_metadata.template_id == "MANUAL_PROCEDURE"
