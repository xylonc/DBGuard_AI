"""W2B gate 1: catalog-linked setting fixes for CIS 3.2 (pgaudit), 5.6 (passwordcheck) and
6.10 (ciphers), the failed-start loop fix and the bundle runner's preload guard.

Unit tests only (fake runtimes, fake psycopg2). The live rehearsals are in
tests/test_catalog_fixes_w2b_live.py.
"""
import copy
import importlib.util
import json
import re
import sys
import types
from types import SimpleNamespace

import pytest

from app.models import SetConfigTemplateParams
from app.services.setting_values import CIS_SSL_CIPHERS, CIS_TLS12_CIPHERS
from app.services.spec_engine import RecordsIndex, load_spec
from app.services.spec_engine import catalog_checks
from app.services.spec_engine.policy import parse_profile
from scripts.sandbox_poc import demo_template
from services.sandbox_poc import catalog_fixes as cf
from services.sandbox_poc import planning
from services.sandbox_poc.provenance import FILES
from services.sandbox_poc.runtime import SandboxStartError
from services.sandbox_poc.shared import ROOT, ContractError
from services.sandbox_poc.workflow import ROLLBACK_SKIPPED, list_template_action, template_action
from services.sandbox_poc.templates import ApprovedTemplate
from tests.catalog_fixtures import live_snapshot


def list_template():
    """Synthetic approval of the bundled set_config_list template (tests only)."""
    import hashlib
    sql = (ROOT / "backend/app/templates/set_config_list.sql.j2").read_text()
    return ApprovedTemplate("set_config_list", 1, sql, hashlib.sha256(sql.encode()).hexdigest(),
                            "TEST FIXTURE ONLY", ({"document_id": "demo-fixture", "demo_only": True},))

RECORDS = RecordsIndex.load(ROOT / "catalog/benchmarks/cis-pg17-v1.1.0/records.json")
SPEC_DIR = ROOT / "catalog/specs/cis-pg17-v1.1.0"
SID = {rec: f"cis-pg17-v1.1.0:{rec}" for rec in ("3.2", "5.6", "6.10", "6.8", "4.3")}
TEST_PROFILE = b"""profile_id: w2b-unit-test
benchmark: cis-pg17-v1.1.0
approved_by: Test Reviewer
approved_at: '2026-11-05'
values: {}
pgaudit_log_classes: [ddl, role, write]
"""


def profile(approved=True, classes="[ddl, role, write]"):
    text = TEST_PROFILE.replace(b"[ddl, role, write]", classes.encode())
    if not approved:
        text = text.replace(b"approved_by: Test Reviewer\napproved_at: '2026-11-05'",
                            b"approved_by: null\napproved_at: null")
    return parse_profile(text, RECORDS, "unit-test")


def spec(rec):
    return load_spec(SPEC_DIR / f"{rec}.yaml")


def baseline_snapshot(**settings):
    """The recorded PostgreSQL 17 collection (nothing preloaded, default ssl_ciphers),
    with settings rows overridden: name -> dict of row fields, or None to drop the row."""
    snap = live_snapshot()
    rows = snap["baseline"]["settings"]
    for name, fields in settings.items():
        rows[:] = [r for r in rows if r["name"] != name] + (
            [] if fields is None else [{**next((r for r in live_snapshot()["baseline"]["settings"]
                                                if r["name"] == name), {"name": name, "sanitised": False,
                                                                        "pending_restart": False}),
                                         **fields}])
    return snap


class FakeEngine:
    """Specs, policy and an upstream report from the real catalog evaluators."""

    def __init__(self, policy=None, recs=("3.2", "5.6", "6.10", "6.8")):
        self._specs = [spec(r) for r in recs]
        self.policy = policy
        self.hashes = {s["spec_id"]: "0" * 64 for s in self._specs}
        self.spec_set_hash, self.collector_hash = "1" * 64, "2" * 64
        self.catalog_ids = frozenset(self.hashes)

    @property
    def specs(self):
        return copy.deepcopy(self._specs)

    @property
    def policy_pin(self):
        return self.policy.pin() if self.policy is not None else None

    def assess(self, snapshot):
        results = [{"spec_id": s["spec_id"], "result": catalog_checks.evaluate(s, snapshot, self.policy)["result"],
                    "reason_code": catalog_checks.evaluate(s, snapshot, self.policy)["explanation"]["code"]}
                   for s in self._specs]
        return {"findings": {}, "upstream_report": {"results": results}}

    def bind_assessment(self, snapshot, supplied=None):
        return self.assess(snapshot)

    def gapped_settings(self, findings):
        return []

    def collect(self, runtime):
        return copy.deepcopy(runtime.snapshot)


# ---------------------------------------------------------------------------
# 1. Computed values: preload lists, quotes, duplicates
# ---------------------------------------------------------------------------

class TestPreloadLists:
    @pytest.mark.parametrize("value, items", [
        ("", []), ("   ", []), ("pgaudit", ["pgaudit"]), (" a , b ", ["a", "b"]),
        ('"a,b", c', ["a,b", "c"]), ('"a""b"', ['a"b']), ("$libdir/pgaudit", ["$libdir/pgaudit"]),
        ("pgaudit.so", ["pgaudit.so"]), ("a b, c", ["a b", "c"]), ("x'; DROP TABLE t; --", ["x'; DROP TABLE t; --"]),
    ])
    def test_split_like_postgresql(self, value, items):
        assert cf.split_preload_list(value) == items

    @pytest.mark.parametrize("value", ["a,,b", "a,", ",a", '"unclosed', '"x"y', "a\x01b", '""', None, 3])
    def test_unparseable_lists_are_none(self, value):
        assert cf.split_preload_list(value) is None

    @pytest.mark.parametrize("current, library, items, changed", [
        ("", "pgaudit", ["pgaudit"], True),
        ("pgaudit", "pgaudit", ["pgaudit"], False),
        ("$libdir/pgaudit", "pgaudit", ["$libdir/pgaudit"], False),
        ("pgaudit.so", "pgaudit", ["pgaudit.so"], False),
        ('"pgaudit"', "pgaudit", ["pgaudit"], False),
        ("pg_stat_statements, auto_explain", "pgaudit", ["pg_stat_statements", "auto_explain", "pgaudit"], True),
        ('"a,b", c', "pgaudit", ["a,b", "c", "pgaudit"], True),
        ("$libdir/passwordcheck", "passwordcheck", ["$libdir/passwordcheck"], False),
        ("passwordcheck", "passwordcheck", ["passwordcheck"], False),
        # Not a CIS 5.6 form, so it does not count; appending makes the list two items.
        ("passwordcheck.so", "passwordcheck", ["passwordcheck.so", "passwordcheck"], True),
        ("pgaudit", "passwordcheck", ["pgaudit", "passwordcheck"], True),
    ])
    def test_append_preserves_entries_and_order_never_duplicates(self, current, library, items, changed):
        assert cf.appended_preload(current, library) == (items, changed)
        assert len(set(items)) == len(items)

    def test_unparseable_current_list_is_refused(self):
        with pytest.raises(cf.CatalogFixRefused) as error:
            cf.appended_preload("a,,b", "pgaudit")
        assert error.value.code == "preload_list_unparseable"

    def test_list_text_quotes_like_postgresql(self):
        assert cf._list_text(["pg_stat_statements", "a,b", 'q"t', "$libdir/x"]) == \
            'pg_stat_statements, "a,b", "q""t", "$libdir/x"'

    @pytest.mark.parametrize("value", ["pgaudit,passwordcheck", "pgaudit, passwordcheck", "", '"pgaudit"',
                                       "$libdir/pgaudit", "x'; SELECT 1; --",
                                       "pgaudit", "passwordcheck", "pg_stat_statements"])
    def test_set_config_parameter_never_renders_the_preload_list(self, value):
        """Security review B1: a single literal replaces the whole list (and 'a,b' would be ONE
        quoted library name). shared_preload_libraries is written only by set_config_list."""
        with pytest.raises(Exception):
            SetConfigTemplateParams(param_name="shared_preload_libraries", param_value=value)

    def test_template_action_refuses_the_preload_list(self):
        with pytest.raises(ContractError, match="Unsupported setting action"):
            template_action("ALTER SYSTEM SET \"shared_preload_libraries\" = 'pgaudit';\nSELECT pg_reload_conf();",
                            "shared_preload_libraries")


# ---------------------------------------------------------------------------
# 2. Scope: the evidence-derived changes and every refusal reason
# ---------------------------------------------------------------------------

def scope_of(rec, snapshot, policy=None, fail=True):
    engine = FakeEngine(policy)
    report = engine.assess(snapshot)
    if fail is not None:
        for row in report["upstream_report"]["results"]:
            if row["spec_id"] == SID[rec]:
                row["result"] = "FAIL" if fail else "PASS"
    return cf.catalog_fix_scope(engine, snapshot, SID[rec], report)


def refused(rec, snapshot, policy=None, fail=True):
    with pytest.raises(cf.CatalogFixRefused) as error:
        scope_of(rec, snapshot, policy, fail)
    assert str(error.value).startswith(cf.REASONS[error.value.code])
    return error.value.code


class TestScope:
    def test_3_2_appends_pgaudit_and_sets_policy_classes_with_restart(self):
        scope = scope_of("3.2", baseline_snapshot(), profile())
        assert [(c["param"], c["value"]) for c in scope["changes"]] == [
            ("shared_preload_libraries", "pgaudit"), ("pgaudit.log", "ddl,role,write")]
        assert scope["changes"][0]["prior_state"] == {"value": "", "source": "default", "sourcefile": None,
                                                     "context": "postmaster"}
        assert scope["changes"][1]["prior_state"] is None  # not defined until pgaudit loads
        assert scope["changes"][1]["rollback"] == {"action": "reset_config", "param": "pgaudit.log"}
        assert scope["requires"] == "restart" and scope["preload_added"] == ["pgaudit"]

    def test_3_2_policy_order_is_kept(self):
        scope = scope_of("3.2", baseline_snapshot(), profile(classes="[write, ddl]"))
        assert scope["changes"][1]["value"] == "write,ddl"

    @pytest.mark.parametrize("policy", [None, "unapproved"])
    def test_3_2_without_an_approved_policy_is_company_policy_missing(self, policy):
        policy = profile(approved=False) if policy == "unapproved" else None
        assert refused("3.2", baseline_snapshot(), policy) == "policy_missing"
        assert cf.REASONS["policy_missing"].startswith("COMPANY POLICY MISSING")

    def test_3_2_already_preloaded_in_any_form_only_sets_pgaudit_log_with_reload(self):
        snap = baseline_snapshot(shared_preload_libraries={"setting": "$libdir/pgaudit"},
                                 **{"pgaudit.log": {"setting": "ddl", "source": "default", "context": "superuser",
                                                    "sourcefile": None}})
        scope = scope_of("3.2", snap, profile())
        assert [(c["param"], c["value"]) for c in scope["changes"]] == [("pgaudit.log", "ddl,role,write")]
        assert scope["requires"] == "reload" and scope["preload_added"] == []

    def test_3_2_preloaded_without_a_collected_pgaudit_log_is_refused(self):
        snap = baseline_snapshot(shared_preload_libraries={"setting": "pgaudit"})
        assert refused("3.2", snap, profile()) == "pgaudit_log_not_reconstructable"

    def test_3_2_pgaudit_log_in_a_file_while_not_loaded_is_refused(self):
        snap = baseline_snapshot()
        snap["baseline"]["file_settings"].append({"name": "pgaudit.log", "setting": "ddl", "sourcefile": FILES[0],
                                                  "sourceline": 99, "applied": True, "error": None})
        assert refused("3.2", snap, profile()) == "pgaudit_log_not_reconstructable"

    @pytest.mark.parametrize("current, values", [
        ("pg_stat_statements", ["pg_stat_statements", "passwordcheck"]),
        ("auto_explain, pg_stat_statements", ["auto_explain", "pg_stat_statements", "passwordcheck"]),
        ('pg_stat_statements, "$libdir/pgaudit"', ["pg_stat_statements", "$libdir/pgaudit", "passwordcheck"]),
    ])
    def test_a_non_empty_list_from_postgresql_conf_keeps_entries_and_resets_on_rollback(self, current, values):
        snap = baseline_snapshot(shared_preload_libraries={"setting": current, "source": "configuration file",
                                                           "sourcefile": FILES[0]})
        change = scope_of("5.6", snap)["changes"][0]
        assert change["template"] == "set_config_list"
        assert change["apply"] == {"action": "set_config_list", "param": "shared_preload_libraries", "values": values}
        assert change["value"] == cf._list_text(values)
        assert change["rollback"] == {"action": "reset_config", "param": "shared_preload_libraries"}

    @pytest.mark.parametrize("current", ['"a,b"', "auto explain", "$libdir/auto_explain", '"Pg_Stat"',
                                         "/usr/lib/postgresql/17/lib/foo"])
    def test_an_entry_the_list_template_cannot_write_is_refused(self, current):
        snap = baseline_snapshot(shared_preload_libraries={"setting": current, "source": "configuration file",
                                                           "sourcefile": FILES[0]})
        assert refused("5.6", snap) == "preload_list_unsupported"

    def test_an_auto_conf_prior_is_restored_exactly_with_the_list_template(self):
        """Sequential fixes: 5.6 after 3.2 was applied (pgaudit in postgresql.auto.conf)."""
        snap = baseline_snapshot(shared_preload_libraries={"setting": "pgaudit", "source": "configuration file",
                                                           "sourcefile": FILES[1]})
        change = scope_of("5.6", snap)["changes"][0]
        assert change["apply"]["values"] == ["pgaudit", "passwordcheck"]
        assert change["rollback"] == {"action": "set_config_list", "param": "shared_preload_libraries",
                                      "values": ["pgaudit"]}
        snap = baseline_snapshot(shared_preload_libraries={"setting": '"$libdir/passwordcheck"',
                                                           "source": "configuration file", "sourcefile": FILES[1]})
        change = scope_of("3.2", snap, profile())["changes"][0]
        assert change["apply"]["values"] == ["$libdir/passwordcheck", "pgaudit"]
        assert change["rollback"]["values"] == ["$libdir/passwordcheck"]

    @pytest.mark.parametrize("value", ["", "pg_stat_statements,auto_explain", "pg_stat_statements,  auto_explain"])
    def test_an_auto_conf_prior_that_cannot_be_written_back_identically_is_refused(self, value):
        snap = baseline_snapshot(shared_preload_libraries={"setting": value, "source": "configuration file",
                                                           "sourcefile": FILES[1]})
        assert refused("5.6", snap) == "preload_prior_unsupported"

    @pytest.mark.parametrize("value", ["a,,b", '"open'])
    def test_unparseable_preload_list_is_refused(self, value):
        snap = baseline_snapshot(shared_preload_libraries={"setting": value})
        assert refused("5.6", snap) == "preload_list_unparseable"

    @pytest.mark.parametrize("row", [None, {"sanitised": True}, {"setting": "***REDACTED*** (set, 7 characters)"}])
    def test_missing_or_redacted_preload_row_is_refused(self, row):
        snap = baseline_snapshot(shared_preload_libraries=row)
        assert refused("5.6", snap) == "setting_not_collected"

    def test_5_6_appends_passwordcheck_with_restart(self):
        scope = scope_of("5.6", baseline_snapshot())
        assert [(c["param"], c["value"]) for c in scope["changes"]] == [("shared_preload_libraries", "passwordcheck")]
        assert scope["requires"] == "restart" and scope["preload_added"] == ["passwordcheck"]

    @pytest.mark.parametrize("path", ["/opt/pg/lib", "$libdir:/opt/pg/lib", ""])
    def test_5_6_is_not_offered_unless_dynamic_library_path_is_libdir(self, path):
        snap = baseline_snapshot(dynamic_library_path={"setting": path, "source": "configuration file",
                                                       "sourcefile": FILES[0]})
        assert refused("5.6", snap) == "dynamic_library_path_not_libdir"

    def test_6_10_sets_the_exact_cis_cipher_list_with_reload(self):
        scope = scope_of("6.10", baseline_snapshot())
        assert [(c["param"], c["value"]) for c in scope["changes"]] == [("ssl_ciphers", CIS_SSL_CIPHERS)]
        assert CIS_SSL_CIPHERS == ":".join(catalog_checks.CIS_TLS12_CIPHERS) == ":".join(CIS_TLS12_CIPHERS)
        assert scope["requires"] == "reload" and scope["tls"] is True

    def test_source_must_be_fail(self):
        assert refused("6.10", baseline_snapshot(), fail=False) == "source_not_fail"

    def test_unlinked_catalog_and_setting_specs_are_not_catalog_fixes(self):
        engine = FakeEngine(recs=("4.3", "3.2"))
        assert cf.is_catalog_fix(engine, SID["3.2"])
        assert not cf.is_catalog_fix(engine, SID["4.3"])
        with pytest.raises(cf.CatalogFixRefused) as error:
            cf.catalog_fix_scope(engine, baseline_snapshot(), SID["4.3"], engine.assess(baseline_snapshot()))
        assert error.value.code == "not_linked"

    def test_fix_values_must_make_the_evaluator_itself_pass(self, monkeypatch):
        monkeypatch.setattr(cf, "_evaluate", lambda spec, snap, policy: {"result": "MANUAL",
                                                                         "explanation": {"code": "x"}})
        assert refused("6.10", baseline_snapshot()) == "fix_does_not_reach_pass"

    def test_3_2_pgaudit_log_set_per_database_cannot_reach_pass(self):
        snap = baseline_snapshot(shared_preload_libraries={"setting": "pgaudit"},
                                 **{"pgaudit.log": {"setting": "ddl", "source": "database", "context": "superuser",
                                                    "sourcefile": None}})
        assert refused("3.2", snap, profile(), fail=True) == "fix_does_not_reach_pass"

    def test_6_10_with_hidden_sessions_is_unknown_not_fixable(self):
        """connections.tls gap (no pg_read_all_stats) or a not_visible row: never a PASS claim."""
        gap = baseline_snapshot()
        gap["baseline"]["gaps"].append({"section": "connections.tls", "reason": "insufficient_privilege"})
        assert refused("6.10", gap) == "connections_not_visible"
        hidden = baseline_snapshot()
        hidden["baseline"]["connections"].append({**hidden["baseline"]["connections"][0], "visible": False,
                                                  "client_addr_class": "not_visible", "ssl": None,
                                                  "tls_version": None, "tls_cipher": None})
        assert refused("6.10", hidden) == "connections_not_visible"
        # The evaluator itself never says PASS for such evidence, even with CIS ciphers.
        fixed = cf.hypothetical(gap, scope_of("6.10", baseline_snapshot())["changes"], True)
        assert catalog_checks.evaluate(spec("6.10"), fixed)["result"] == "GAPPED"

    def test_connections_gaps_do_not_block_unrelated_setting_fixes(self):
        from services.sandbox_poc.shared import blocking_gaps
        snap = baseline_snapshot()
        from services.sandbox_poc import shared
        assert shared.CATALOG_ONLY_GAPS == {"connections.tls"}
        assert shared.CATALOG_ONLY_SECTIONS == {"functions", "archiving"}
        # The collector writes connections.tls (the only connections gap record) only for 6.8/6.10.
        sql = (ROOT / "collector/collect.sql").read_text()
        assert "'section','connections.tls'" in sql and "'section','connections'," not in sql
        snap["baseline"]["gaps"] = [{"section": "connections.tls", "reason": "insufficient_privilege"}]
        assert blocking_gaps(snap) == []
        snap["baseline"]["gaps"].append({"section": "file_settings"})
        assert blocking_gaps(snap) == [{"section": "file_settings"}]

    @pytest.mark.parametrize("ciphers", [CIS_SSL_CIPHERS, CIS_SSL_CIPHERS.replace(":", ","),
                                         ":".join(reversed(CIS_TLS12_CIPHERS))])
    def test_6_10_cis_ciphers_with_weak_live_sessions_is_not_a_config_fix(self, ciphers):
        """Security review N2: the FAIL comes only from established sessions; nothing to change."""
        snap = baseline_snapshot(ssl_ciphers={"setting": ciphers, "source": "configuration file",
                                              "sourcefile": FILES[0]})
        snap["baseline"]["connections"].append({**snap["baseline"]["connections"][0], "client_addr_class": "private",
                                                "ssl": True, "tls_version": "TLSv1.2",
                                                "tls_cipher": "ECDHE-RSA-AES256-SHA384"})
        assert catalog_checks.evaluate(spec("6.10"), snap)["explanation"]["code"] == "unapproved_cipher_in_use"
        assert refused("6.10", snap) == "ciphers_already_cis_sessions_must_reconnect"
        assert "keep their cipher until they reconnect" in cf.REASONS["ciphers_already_cis_sessions_must_reconnect"]

    def test_6_10_weak_live_sessions_still_get_the_fix(self):
        snap = baseline_snapshot()
        snap["baseline"]["connections"].append({**snap["baseline"]["connections"][0], "client_addr_class": "private",
                                                "ssl": True, "tls_version": "TLSv1.2",
                                                "tls_cipher": "ECDHE-RSA-AES256-SHA384"})
        assert scope_of("6.10", snap)["changes"][0]["value"] == CIS_SSL_CIPHERS

    def test_hypothetical_never_changes_the_source(self):
        snap = baseline_snapshot()
        before = copy.deepcopy(snap)
        scope_of("6.10", snap)
        scope_of("3.2", snap, profile())
        assert snap == before


# ---------------------------------------------------------------------------
# 3. Fix record, rendering, planning rules and risk
# ---------------------------------------------------------------------------

class TestFixAndPlanning:
    def test_fix_actions_and_rendering_use_the_approved_template(self):
        scope = scope_of("3.2", baseline_snapshot(), profile())
        with pytest.raises(ContractError, match="set_config_list"):
            cf.build_fix(scope, 1)
        fix = cf.build_fix(scope, 1, 1)
        assert fix["schema_version"] == "catalog-setting-fix-v1" and fix["template_id"] == "set_config_parameter"
        assert fix["list_template_id"] == "set_config_list"
        with pytest.raises(ContractError, match="set_config_list"):
            cf.rendered_statements(demo_template(), scope)
        rendered = cf.rendered_statements(demo_template(), scope, list_template())
        assert "ALTER SYSTEM SET \"shared_preload_libraries\" = 'pgaudit';" in rendered[0]
        assert "ALTER SYSTEM SET \"pgaudit.log\" = 'ddl,role,write';" in rendered[1]
        assert [list_template_action(rendered[0]), template_action(rendered[1], "pgaudit.log")] == \
            [c["apply"] for c in fix["changes"]]
        # Rollback in reverse order; both RESET (prior default / not defined).
        assert cf.rollback_sql(fix).splitlines() == [
            'ALTER SYSTEM RESET "pgaudit.log";', "SELECT pg_reload_conf();",
            'ALTER SYSTEM RESET "shared_preload_libraries";', "SELECT pg_reload_conf();"]

    def test_tampered_fix_rollback_is_refused(self):
        scope = scope_of("6.10", baseline_snapshot(
            ssl_ciphers={"setting": "HIGH:!aNULL", "source": "configuration file", "sourcefile": FILES[1]}))
        assert scope["changes"][0]["rollback"] == {"action": "set_config", "param": "ssl_ciphers",
                                                   "value": "HIGH:!aNULL"}
        scope["changes"][0]["rollback"] = {"action": "reset_config", "param": "ssl_ciphers"}
        with pytest.raises(ContractError):
            cf.build_fix(scope, 1)

    def test_tampered_list_rollback_is_refused(self):
        snap = baseline_snapshot(shared_preload_libraries={"setting": "pg_stat_statements", "source": "configuration file",
                                                           "sourcefile": FILES[1]})
        scope = scope_of("5.6", snap)
        cf.build_fix(scope, 1, 1)
        for bad in ({"action": "reset_config", "param": "shared_preload_libraries"},
                    {"action": "set_config_list", "param": "shared_preload_libraries", "values": ["pgaudit"]}):
            scope["changes"][0]["rollback"] = bad
            with pytest.raises(ContractError):
                cf.build_fix(scope, 1, 1)

    def test_fix_scope_refuses_the_computed_marker_for_any_setting_spec(self):
        fake = {"spec_id": "x:1", "check": {"kind": "setting", "setting_name": "shared_preload_libraries",
                                            "query": "SHOW shared_preload_libraries"}}
        with pytest.raises(ContractError, match="no supported, reviewed configuration policy"):
            planning.fix_scope(SimpleNamespace(specs=[fake], policy=None), "x:1")

    def test_3_2_and_5_6_are_ordered_and_chained(self):
        reviews = [{"fix_id": "fix-pgaudit", "setting": "shared_preload_libraries",
                    "settings": ["shared_preload_libraries", "pgaudit.log"], "operational_risk": "high"},
                   {"fix_id": "fix-passwordcheck", "setting": "shared_preload_libraries",
                    "settings": ["shared_preload_libraries"], "operational_risk": "high"}]
        with pytest.raises(ContractError, match="same setting"):
            planning.recommend_order(reviews)  # not marked catalog fixes: still refused
        chained = [{**r, "kind": "catalog_setting"} for r in reviews]
        assert [f["fix_id"] for f in planning.recommend_order(chained)] == ["fix-passwordcheck", "fix-pgaudit"]
        # Only shared_preload_libraries is chainable; pgaudit.log twice is still refused.
        with pytest.raises(ContractError, match="same setting"):
            planning.recommend_order([chained[0], {**chained[0], "fix_id": "fix-other", "settings": ["pgaudit.log"],
                                                   "setting": "pgaudit.log"}])

    @pytest.mark.parametrize("rec, policy, reviewed, operational, requires", [
        ("3.2", True, "high", "high", "restart"),
        ("5.6", False, "medium", "high", "restart"),   # the restart floor raises the reviewed medium
        ("6.10", False, "medium", "medium", "reload"),
    ])
    def test_risk_levels_follow_ruling_9(self, rec, policy, reviewed, operational, requires):
        engine = FakeEngine(profile() if policy else None)
        snap = baseline_snapshot()
        review = cf.catalog_risk_review(engine, snap, SID[rec], scope=scope_of(rec, snap, engine.policy))
        assert (review["reviewed_risk"], review["operational_risk"], review["requires"]) == (reviewed, operational, requires)
        assert review["kind"] == "catalog_setting" and review["dba_review_required"] is True
        assert review["reasoning"] == planning.CATALOG_FIX_LINKS[review_evaluator(rec)]["impact"]

    def test_model_review_can_only_raise_the_risk(self):
        engine = FakeEngine()
        snap = baseline_snapshot()
        advice = {"risk": "low", "reasoning": "fine", "affected_components": [], "prerequisites": [],
                  "unknowns": [], "check_ids": [], "manual_application_checks": []}
        review = cf.catalog_risk_review(engine, snap, SID["6.10"], reviewer=lambda ctx: advice,
                                        scope=scope_of("6.10", snap))
        assert review["operational_risk"] == "medium" and review["llm"]["status"] == "REVIEWED"
        review = cf.catalog_risk_review(engine, snap, SID["6.10"], reviewer=lambda ctx: {**advice, "risk": "high"},
                                        scope=scope_of("6.10", snap))
        assert review["operational_risk"] == "high"


def review_evaluator(rec):
    return {"3.2": "pgaudit_enabled", "5.6": "password_complexity_module", "6.10": "tls_cipher_suites"}[rec]


# ---------------------------------------------------------------------------
# 4. The catalog loop with a fake sandbox, and the failed-start loop fix
# ---------------------------------------------------------------------------

SET_RE = re.compile(r"""ALTER SYSTEM SET "([a-z_.]+)" = ('[^']*'(?:, '[^']*')*);""")
RESET_RE = re.compile(r"""ALTER SYSTEM RESET "([a-z_.]+)";""")


class FakeCatalogRuntime:
    """A sandbox whose settings follow ALTER SYSTEM SET/RESET; 'start' fails the restart."""
    count = 0

    def __init__(self, snapshot, fault=None):
        FakeCatalogRuntime.count += 1
        self.original, self.snapshot = copy.deepcopy(snapshot), copy.deepcopy(snapshot)
        self.run_id, self.image_id, self.fault = str(FakeCatalogRuntime.count), "sha256:test", fault
        self.executed, self.closed, self.tls, self.changed = [], False, False, False

    def start(self):
        if self.fault == "create":
            raise RuntimeError("create failed")

    def write_config(self, *args):
        pass

    def setting_sources(self, names):
        rows = {r["name"]: r for r in self.snapshot["baseline"]["settings"]}
        return {n: {"source": rows[n]["source"], "sourcefile": rows[n]["sourcefile"]} for n in names if n in rows}

    def restart(self):
        self.executed.append("RESTART")

    def enable_tls(self):
        self.tls = True
        self.executed.append("ENABLE_TLS")

    def activate(self, expected):
        if self.fault == "start" and self.changed:
            raise SandboxStartError("PostgreSQL failed to start after restart: shared_preload_libraries names "
                                    "'pgaudit', which is not installed in the sandbox image")

    def _rows(self):
        return self.snapshot["baseline"]["settings"]

    def sql(self, script):
        self.executed.append(script)
        for name, literals in SET_RE.findall(script):
            items = re.findall(r"'([^']*)'", literals)
            value = cf._list_text(items) if name == "shared_preload_libraries" else items[0]
            self.changed = True
            row = next((r for r in self._rows() if r["name"] == name), None)
            if row is None:
                row = {"name": name, "context": "superuser", "vartype": "string", "sanitised": False}
                self._rows().append(row)
            row.update(setting=value, source="configuration file", sourcefile=FILES[1], pending_restart=False)
        for name in RESET_RE.findall(script):
            original = next((r for r in self.original["baseline"]["settings"] if r["name"] == name), None)
            self._rows()[:] = [r for r in self._rows() if r["name"] != name] + ([copy.deepcopy(original)] if original else [])
        if script.startswith("SHOW "):
            name = script[5:].rstrip(";")
            return next(r["setting"] for r in self._rows() if r["name"] == name)
        return "1" if "SELECT 1" in script else "t"

    def _ciphers(self):
        return next(r["setting"] for r in self._rows() if r["name"] == "ssl_ciphers")

    def tls_probe(self, protocol="TLSv1.2"):
        assert self.tls
        return {"protocol": protocol, "cipher": "ECDHE-RSA-AES256-GCM-SHA384", "scope": "fake", "run_id": self.run_id}

    def tls_accepts_cipher(self, name):
        return name in CIS_TLS12_CIPHERS if self._ciphers() == CIS_SSL_CIPHERS else True

    def health(self):
        return True

    def close(self):
        self.closed = True
        return {"verified": True}


def run_loop(rec, fault=None, policy=None, snapshot=None):
    engine = FakeEngine(policy)
    snapshot = snapshot or baseline_snapshot()
    runtimes = []

    def factory():
        runtimes.append(FakeCatalogRuntime(snapshot, fault))
        return runtimes[-1]
    result = cf.CatalogFixLoop(engine, demo_template(), factory, control_id=SID[rec],
                               list_template=list_template()).run(snapshot, engine.assess(snapshot))
    return result, runtimes


class TestCatalogLoop:
    @pytest.mark.parametrize("rec, policy", [("3.2", True), ("5.6", False), ("6.10", False)])
    def test_fail_pass_exact_rollback(self, rec, policy):
        result, runtimes = run_loop(rec, policy=profile() if policy else None)
        assert result["status"] == "VERIFIED" and result["kind"] == "catalog_setting"
        attempt = result["attempts"][-1]
        assert [attempt["catalog_proof"][k]["result"] for k in ("before", "after", "rollback")] == ["FAIL", "PASS", "FAIL"]
        assert attempt["rollback_verified"] is True and attempt["regressions"] == []
        assert all(r.closed for r in runtimes) and len(runtimes) == 1
        assert ("ENABLE_TLS" in runtimes[0].executed) == (rec == "6.10")
        if rec == "6.10":
            assert any(attempt["tls_before"]["weak_accepted"].values())
            assert not any(attempt["tls_after"]["weak_accepted"].values())
            assert attempt["tls_rollback"]["weak_accepted"] == attempt["tls_before"]["weak_accepted"]
        if rec == "3.2":
            assert attempt["pgaudit_log_shown"] == "ddl,role,write"

    def test_failed_start_skips_rollback_sql_and_is_terminal(self):
        result, runtimes = run_loop("5.6", fault="start")
        assert result["status"] == "FAILED" and len(runtimes) == 1  # deterministic: no retry
        attempt = result["attempts"][0]
        assert attempt["error"].startswith("SandboxStartError: PostgreSQL failed to start")
        assert attempt["phase"] == "start_failed" and attempt["rollback_skipped"] == ROLLBACK_SKIPPED
        assert "rollback" not in attempt and attempt["rollback_verified"] is False
        assert not any("RESET" in sql for sql in runtimes[0].executed)
        assert runtimes[0].closed

    def test_a_missing_proof_never_passes(self, monkeypatch):
        real = cf.proof
        monkeypatch.setattr(cf, "proof", lambda engine, spec, snap: {**real(engine, spec, snap), "result": "FAIL"})
        result, runtimes = run_loop("6.10")
        assert result["status"] == "FAILED" and all(r.closed for r in runtimes)

    def test_adaptive_and_alternatives_are_refused_by_the_service(self):
        from services.sandbox_poc.service import SandboxService
        assert "Catalog-linked fixes have no alternative templates" in \
            open(ROOT / "services/sandbox_poc/service.py").read()
        assert SandboxService  # imported: the branch lives in validate_handoff


class TestSettingLoopFailedStart:
    def test_setting_loop_skips_rollback_sql_after_a_failed_start(self, monkeypatch):
        from test_sandbox_poc import FakeRuntime, engine as engine_fixture, snapshot as snapshot_fixture  # noqa: F401
        from services.sandbox_poc.workflow import RemediationLoop
        from services.sandbox_poc.shared import SpecEngine
        engine = SpecEngine.load(SPEC_DIR, ROOT / "catalog/benchmarks/cis-pg17-v1.1.0/records.json")
        snapshot = snapshot_fixture.__wrapped__(engine)

        class StartFails(FakeRuntime):
            applied = False

            def sql(self, sql):
                out = super().sql(sql)
                self.applied = self.applied or "ALTER SYSTEM SET" in sql
                return out

            def activate(self, expected):
                if self.applied:
                    raise SandboxStartError("PostgreSQL failed to start after restart: the server reported "
                                            "a fatal startup error")
        runtimes = []

        def factory():
            runtimes.append(StartFails(snapshot, len(runtimes) + 1))
            return runtimes[-1]
        engine.collect = lambda runtime: copy.deepcopy(runtime.snapshot)
        result = RemediationLoop(engine, demo_template(), factory).run(snapshot, engine.assess(snapshot))
        assert result["status"] == "FAILED" and len(runtimes) == 1
        attempt = result["attempts"][0]
        assert attempt["error"] == ("SandboxStartError: PostgreSQL failed to start after restart: the server "
                                    "reported a fatal startup error")
        assert attempt["phase"] == "start_failed" and attempt["rollback_skipped"] == ROLLBACK_SKIPPED
        assert not any("RESET" in sql for sql in runtimes[0].executed) and runtimes[0].closed
        assert "psql" not in json.dumps(attempt)


# ---------------------------------------------------------------------------
# 5. Bundle runner: the preload LOAD guard (fake psycopg2)
# ---------------------------------------------------------------------------

def load_runner():
    module_spec = importlib.util.spec_from_file_location(
        "runner_w2b_under_test", ROOT / "services/sandbox_poc/bundle_assets/runner.py")
    module = importlib.util.module_from_spec(module_spec)
    module_spec.loader.exec_module(module)
    return module


class FakePgError(Exception):
    def __init__(self, message):
        super().__init__("ERROR:  " + message)
        self.diag = SimpleNamespace(message_primary=message)


class LoadTarget:
    """Answers LOAD per library: None = loads, else the server's error message."""

    def __init__(self, outcomes, preload=""):
        self.outcomes, self.preload = outcomes, preload
        self.executed, self.rollbacks, self.closed, self.statements = [], 0, 0, []

    def connect(self, dsn, connect_timeout=10):
        target = self

        class Cursor:
            def __enter__(self): return self
            def __exit__(self, *a): return False

            def execute(self, sql, params=None):
                target.executed.append(sql)
                self.last = sql
                match = re.fullmatch(r"LOAD '([a-z_]+)'", sql)
                if match and target.outcomes.get(match[1]) is not None:
                    raise FakePgError(target.outcomes[match[1]])

            def fetchone(self):
                return (target.preload,)

        class Conn:
            autocommit = True
            def cursor(self): return Cursor()
            def rollback(self): target.rollbacks += 1
            def close(self): target.closed += 1
        return Conn()


@pytest.fixture
def runner(monkeypatch):
    fake = types.ModuleType("psycopg2")
    fake.Error = FakePgError
    monkeypatch.setitem(sys.modules, "psycopg2", fake)
    return load_runner(), fake


class TestRunnerPreloadGuard:
    def test_allowlist_matches_the_reviewed_links(self, runner):
        module, _ = runner
        libraries = {link["library"] for link in planning.CATALOG_FIX_LINKS.values() if link["library"]}
        assert set(module.PRELOAD_LOAD_TESTS) == libraries == {"pgaudit", "passwordcheck"}
        assert module.PRELOAD_LOAD_TESTS["pgaudit"] == ("LOAD 'pgaudit'", "pgaudit must be loaded via shared_preload_libraries")
        assert module.PRELOAD_LOAD_TESTS["passwordcheck"] == ("LOAD 'passwordcheck'", None)

    @pytest.mark.parametrize("library, outcome", [
        ("passwordcheck", None),
        ("pgaudit", "pgaudit must be loaded via shared_preload_libraries"),
    ])
    def test_loadable_library_passes_in_a_throwaway_session(self, runner, library, outcome):
        module, _ = runner
        target = LoadTarget({library: outcome})
        module.preload_guard("dsn", [library], connect=target.connect)
        assert f"LOAD '{library}'" in target.executed
        assert target.rollbacks == 1 and target.closed == 1

    @pytest.mark.parametrize("library, outcome", [
        ("pgaudit", 'could not access file "pgaudit": No such file or directory'),
        ("passwordcheck", 'could not access file "passwordcheck": No such file or directory'),
        ("passwordcheck", "pgaudit must be loaded via shared_preload_libraries"),  # only pgaudit's own error
        ("pgaudit", 'access to library "pgaudit" is not allowed'),
        ("pgaudit", "pgaudit must be loaded via shared_preload_libraries."),       # exact text only
    ])
    def test_anything_else_refuses_with_install_first(self, runner, library, outcome):
        module, _ = runner
        target = LoadTarget({library: outcome})
        with pytest.raises(RuntimeError) as error:
            module.preload_guard("dsn", [library], connect=target.connect)
        assert str(error.value) == f"Library {library} cannot be loaded on the target: install the package first; no SQL executed"
        assert target.rollbacks == 1 and target.closed == 1

    @pytest.mark.parametrize("library", ["set_user", "pgaudit'; DROP TABLE x; --", "$libdir/pgaudit", ""])
    def test_library_outside_the_allowlist_is_never_loaded(self, runner, library):
        module, _ = runner
        target = LoadTarget({})
        with pytest.raises(RuntimeError, match="outside the reviewed preload allowlist; no SQL executed"):
            module.preload_guard("dsn", [library], connect=target.connect)
        assert target.executed == []

    def test_additions_come_from_the_statements_not_only_fix_json(self, runner):
        module, _ = runner
        statements = ["ALTER SYSTEM SET \"shared_preload_libraries\" = 'pgaudit'", "SELECT pg_reload_conf()"]
        conn = LoadTarget({}).connect("dsn")
        # An edited fix.json without preload_added still gets the guard.
        assert module.preload_additions(conn, {"apply_statements": statements}) == ["pgaudit"]
        assert module.preload_additions(conn, {"apply_statements": statements, "preload_added": ["pgaudit"]}) == ["pgaudit"]
        assert module.preload_additions(LoadTarget({}, preload="pgaudit").connect("dsn"),
                                        {"apply_statements": statements}) == []
        assert module.preload_additions(conn, {"apply_statements": ["SELECT pg_reload_conf()"]}) == []
        for bad in ["ALTER SYSTEM SET \"shared_preload_libraries\" = 'pgaudit,set_user'",
                    "ALTER SYSTEM SET shared_preload_libraries = 'set_user'"]:
            with pytest.raises(RuntimeError, match="Unsupported shared_preload_libraries statement"):
                module.preload_additions(conn, {"apply_statements": [bad]})

    def test_apply_refuses_before_any_alter_system_when_the_library_is_missing(self, runner):
        module, fake = runner
        target = LoadTarget({"pgaudit": 'could not access file "pgaudit": No such file or directory'})
        fp = {"settings": {}, "file_settings": []}
        fake.connect = target.connect
        module.fingerprint = lambda conn, names: fp
        config = {"fix_id": "fix-pgaudit", "kind": "catalog_setting", "demo_fixture_approval": False,
                  "database": "appdb", "names": ["shared_preload_libraries"], "prior": fp, "applied": {"x": 1},
                  "requires": "restart", "preload_added": ["pgaudit"],
                  "apply_statements": ["ALTER SYSTEM SET \"shared_preload_libraries\" = 'pgaudit'",
                                       "SELECT pg_reload_conf()"]}

        class Major(LoadTarget):
            def connect(self, dsn, connect_timeout=10):
                conn = super().connect(dsn, connect_timeout)
                cursor_factory = conn.cursor

                def cursor():
                    cur = cursor_factory()
                    fetch = cur.fetchone

                    def fetchone():
                        last = cur.last
                        if "server_version_num" in last:
                            return (17, "appdb")
                        if "advisory" in last:
                            return (True,)
                        return fetch()
                    cur.fetchone = fetchone
                    return cur
                conn.cursor = cursor
                return conn
        target = Major({"pgaudit": 'could not access file "pgaudit": No such file or directory'})
        fake.connect = target.connect
        with pytest.raises(RuntimeError, match="install the package first; no SQL executed"):
            module.execute(config, "apply", "dsn")
        assert "LOAD 'pgaudit'" in target.executed
        assert not any(sql.startswith("ALTER SYSTEM") for sql in target.executed)


# ---------------------------------------------------------------------------
# 6. W2B rulings round 3: the set_config_list template
# ---------------------------------------------------------------------------

from pydantic import ValidationError  # noqa: E402

from app.models import SetConfigListTemplateParams  # noqa: E402
from app.services import template_service  # noqa: E402
from app.services.fix_unit_render import render_action  # noqa: E402
from services.sandbox_poc.handoff import SandboxHandoff, TemplateReference  # noqa: E402


class TestListTemplate:
    def test_renders_one_quoted_literal_per_item(self):
        sql = list_template().render_list("shared_preload_libraries",
                                          ["pg_stat_statements", "$libdir/passwordcheck", "pgaudit"])
        assert ("ALTER SYSTEM SET \"shared_preload_libraries\" = 'pg_stat_statements', "
                "'$libdir/passwordcheck', 'pgaudit';\nSELECT pg_reload_conf();") in sql
        action = list_template_action(sql)
        assert action["values"] == ["pg_stat_statements", "$libdir/passwordcheck", "pgaudit"]
        assert render_action(action)[0] + ";" in sql

    def test_is_registered_with_a_strict_schema_and_server_only(self):
        assert template_service.TEMPLATE_PARAM_SCHEMAS["set_config_list"] is SetConfigListTemplateParams
        assert template_service.SERVER_ONLY_TEMPLATES == {"set_config_list"}
        assert not template_service.SERVER_ONLY_TEMPLATES & template_service.OBJECT_FIX_TEMPLATES

    @pytest.mark.parametrize("params", [
        {"param_name": "search_path", "param_values": ["public"]},
        {"param_name": "shared_preload_libraries", "param_values": []},
        {"param_name": "shared_preload_libraries", "param_values": ["pgaudit", "pgaudit"]},
        {"param_name": "shared_preload_libraries", "param_values": ["pgaudit,passwordcheck"]},
        {"param_name": "shared_preload_libraries", "param_values": ["pgaudit'; SELECT 1; --"]},
        {"param_name": "shared_preload_libraries", "param_values": ['pg"audit']},
        {"param_name": "shared_preload_libraries", "param_values": ["$libdir/auto_explain"]},
        {"param_name": "shared_preload_libraries", "param_values": ["/tmp/evil.so"]},
        {"param_name": "shared_preload_libraries", "param_values": ["PGAUDIT"]},
        {"param_name": "shared_preload_libraries", "param_values": ["a" * 64]},
        {"param_name": "shared_preload_libraries", "param_values": ["pgaudit\n"]},
        {"param_name": "shared_preload_libraries", "param_values": "pgaudit"},
        {"param_name": "shared_preload_libraries", "param_values": [f"lib{i}" for i in range(33)]},
        {"param_name": "shared_preload_libraries", "param_values": ["pgaudit"], "extra": 1},
    ])
    def test_schema_refuses_everything_else(self, params):
        with pytest.raises(ValidationError):
            SetConfigListTemplateParams(**params)
        ok, _, _ = template_service.validate_params("set_config_list", params)
        assert ok is False

    @pytest.mark.parametrize("values", [["pgaudit"], ["pg_stat_statements", "pgaudit"],
                                        ["$libdir/pgaudit", "pgaudit.so", "$libdir/pgaudit.so", "$libdir/passwordcheck"]])
    def test_schema_accepts_plain_names_and_the_cis_forms(self, values):
        assert SetConfigListTemplateParams(param_name="shared_preload_libraries", param_values=values).param_values == values

    @pytest.mark.parametrize("sql", [
        "ALTER SYSTEM SET \"shared_preload_libraries\" = 'pgaudit,set_user';\nSELECT pg_reload_conf();",
        "ALTER SYSTEM SET \"search_path\" = 'public';\nSELECT pg_reload_conf();",
        "ALTER SYSTEM SET \"shared_preload_libraries\" = 'pgaudit';\nSELECT pg_reload_conf();\nDROP TABLE x;",
        "ALTER SYSTEM SET \"shared_preload_libraries\" = 'pgaudit', 'pgaudit';\nSELECT pg_reload_conf();",
        "ALTER SYSTEM SET \"shared_preload_libraries\" = pgaudit;\nSELECT pg_reload_conf();",
        "ALTER SYSTEM SET \"shared_preload_libraries\" = 'pg''audit';\nSELECT pg_reload_conf();",
    ])
    def test_parser_refuses_any_other_shape(self, sql):
        with pytest.raises(ContractError):
            list_template_action(sql)

    def test_only_a_list_template_object_can_render_lists(self):
        with pytest.raises(ContractError):
            demo_template().render_list("shared_preload_libraries", ["pgaudit"])
        with pytest.raises(ContractError):
            list_template().render("log_connections", "on")
        tampered = ApprovedTemplate("set_config_list", 1, list_template().sql + " ", list_template().sha256,
                                    "TEST FIXTURE ONLY", ({"document_id": "x"},))
        with pytest.raises(ContractError, match="pinned hash"):
            tampered.render_list("shared_preload_libraries", ["pgaudit"])

    def test_handoff_pins_the_list_template_only_for_catalog_fixes(self):
        ref = dict(version=1, sha256="a" * 64, evidence=[dict(document_id="d", version="1", sha256="b" * 64)])
        base = dict(schema_version="sandbox-handoff-v1", benchmark_id="cis-pg17-v1.1.0", spec_set_hash="c" * 64,
                    specs=[{}], snapshot={}, assessment={}, template_ref=TemplateReference(**ref),
                    control_id=SID["5.6"], retry_mode="repeat")
        assert SandboxHandoff(**base, list_template_ref=TemplateReference(registry_name="set_config_list", **ref))
        with pytest.raises(ValidationError):
            SandboxHandoff(**base, list_template_ref=TemplateReference(**ref))  # set_config_parameter
        with pytest.raises(ValidationError):  # never as the main template
            SandboxHandoff(**{**base, "template_ref": TemplateReference(registry_name="set_config_list", **ref)})
        with pytest.raises(ValidationError):  # environments must match
            SandboxHandoff(**base, list_template_ref=TemplateReference(registry_name="set_config_list",
                                                                        environment="prod", **ref))


class TestMcpRenderRefusal:
    def test_validate_and_render_refuses_set_config_parameter_for_the_preload_list(self, monkeypatch):
        """Security review B1: HERMES cannot render ALTER SYSTEM SET shared_preload_libraries."""
        from fastapi.testclient import TestClient
        from app import main
        # Reach parameter validation: a snapshot and an active approved template exist.
        monkeypatch.setattr(main.snapshot_store, "context",
                            lambda snapshot_id: SimpleNamespace(model_dump=lambda mode=None: {}))
        sql = (ROOT / "backend/app/templates/set_config_parameter.sql.j2").read_text()
        monkeypatch.setattr(main, "get_active_template_version", lambda name: {
            "template_name": "set_config_parameter", "version": 1, "sql_template": sql,
            "status": "active", "approved_by": "Test Reviewer", "risk_level": "low"}, raising=False)
        response = TestClient(main.app).post("/api/v1/proposals/validate-and-render", json={
            "snapshot_id": "snap-any", "proposal": {
                "control_id": "CIS-3.2", "template_id": "set_config_parameter", "reasoning": "x",
                "parameters": {"param_name": "shared_preload_libraries", "param_value": "pgaudit"}}})
        assert response.status_code == 422, response.text
        assert "Template parameter validation failed" in response.text
        assert "ALTER SYSTEM" not in response.text
        ok, _, error = template_service.validate_params(
            "set_config_parameter", {"param_name": "shared_preload_libraries", "param_value": "pgaudit"})
        assert ok is False and "Invalid config parameter name" in error

    def test_validate_and_render_refuses_the_list_template(self):
        from fastapi.testclient import TestClient
        from app.main import app
        response = TestClient(app).post("/api/v1/proposals/validate-and-render", json={
            "snapshot_id": "snap-any", "proposal": {
                "control_id": "CIS-3.2", "template_id": "set_config_list", "reasoning": "x",
                "parameters": {"param_name": "shared_preload_libraries", "param_values": ["pgaudit"]}}})
        assert response.status_code == 422
        assert "rendered only from server-side evidence for a reviewed catalog fix" in response.text


class TestListLoopAndRunner:
    def test_auto_conf_prior_is_restored_exactly_in_the_sandbox(self):
        snap = baseline_snapshot(shared_preload_libraries={"setting": "pg_stat_statements",
                                                           "source": "configuration file", "sourcefile": FILES[1]})
        snap["baseline"]["file_settings"].append({"name": "shared_preload_libraries", "setting": "pg_stat_statements",
                                                  "sourcefile": FILES[1], "sourceline": 3, "applied": True,
                                                  "error": None})
        result, runtimes = run_loop("5.6", snapshot=snap)
        assert result["status"] == "VERIFIED", result["attempts"][-1].get("error")
        assert "'pg_stat_statements', 'passwordcheck'" in result["rendered_apply_sql"]
        assert result["rendered_rollback_sql"].startswith(
            "ALTER SYSTEM SET \"shared_preload_libraries\" = 'pg_stat_statements';")
        assert result["list_template"]["registry_name"] == "set_config_list"

    def test_a_preload_fix_without_the_list_template_never_starts(self):
        engine, snap = FakeEngine(), baseline_snapshot()
        factory = lambda: pytest.fail("no sandbox may start")  # noqa: E731
        with pytest.raises(ContractError, match="set_config_list"):
            cf.CatalogFixLoop(engine, demo_template(), factory, control_id=SID["5.6"]).run(snap, engine.assess(snap))

    def test_runner_refuses_unknown_and_upper_case_statement_shapes(self, runner):
        """Security review N1: shared_preload_libraries matched case-insensitively; every other
        statement must be one of the rendered setting shapes."""
        module, _ = runner
        good = {"apply_statements": ["ALTER SYSTEM SET \"shared_preload_libraries\" = 'pg_stat_statements', 'pgaudit'",
                                     "SELECT pg_reload_conf()", "ALTER SYSTEM SET \"pgaudit.log\" = 'ddl,role,write'",
                                     "ALTER SYSTEM SET \"log_line_prefix\" = 'it''s %m'"],
                "rollback_statements": ['ALTER SYSTEM RESET "pgaudit.log";', "SELECT pg_reload_conf();",
                                        'ALTER SYSTEM RESET "shared_preload_libraries";',
                                        "ALTER SYSTEM SET \"shared_preload_libraries\" = 'pg_stat_statements';"]}
        module.check_setting_statements(good)
        for bad in ["ALTER SYSTEM SET \"SHARED_PRELOAD_LIBRARIES\" = 'pgaudit'",
                    "ALTER SYSTEM SET SHARED_PRELOAD_LIBRARIES = 'pgaudit'",
                    "alter system set \"shared_preload_libraries\" = 'pgaudit'"]:
            with pytest.raises(RuntimeError, match="Unsupported shared_preload_libraries statement"):
                module.check_setting_statements({"apply_statements": [bad]})
            with pytest.raises(RuntimeError, match="Unsupported shared_preload_libraries statement"):
                module.preload_additions(LoadTarget({}).connect("dsn"), {"apply_statements": [bad]})
        for bad in ["ALTER SYSTEM SET \"Log_Connections\" = 'on'", "DROP TABLE x",
                    "ALTER SYSTEM SET \"log_connections\" = 'on'; DROP TABLE x",
                    "SELECT pg_catalog.set_config('log_connections','on',false)",
                    "ALTER SYSTEM SET \"log_connections\" = on"]:
            with pytest.raises(RuntimeError, match="Unsupported statement in this bundle"):
                module.check_setting_statements({"rollback_statements": [bad]})

    def test_runner_guard_reads_the_list_statement(self, runner):
        module, _ = runner
        statement = "ALTER SYSTEM SET \"shared_preload_libraries\" = 'pg_stat_statements', 'pgaudit'"
        target = LoadTarget({}, preload="pg_stat_statements")
        assert module.preload_additions(target.connect("dsn"), {"apply_statements": [statement]}) == ["pgaudit"]
        both = "ALTER SYSTEM SET \"shared_preload_libraries\" = 'pgaudit', 'passwordcheck'"
        assert module.preload_additions(LoadTarget({}).connect("dsn"), {"apply_statements": [both]}) == \
            ["passwordcheck", "pgaudit"]
        # A CIS path form already loaded is not re-tested; quotes in the current value are ignored.
        cis = "ALTER SYSTEM SET \"shared_preload_libraries\" = '$libdir/passwordcheck', 'pgaudit'"
        assert module.preload_additions(LoadTarget({}, preload='"$libdir/passwordcheck"').connect("dsn"),
                                        {"apply_statements": [cis]}) == ["pgaudit"]
        for bad in ["ALTER SYSTEM SET \"shared_preload_libraries\" = 'pgaudit', 'pgaudit'",
                    "ALTER SYSTEM SET \"shared_preload_libraries\" = 'pgaudit', '/tmp/x.so'",
                    "ALTER SYSTEM SET \"shared_preload_libraries\" = 'pgaudit','passwordcheck'",
                    "ALTER SYSTEM SET \"shared_preload_libraries\" = 'pgaudit'; DROP TABLE t"]:
            with pytest.raises(RuntimeError, match="Unsupported shared_preload_libraries statement"):
                module.preload_additions(target.connect("dsn"), {"apply_statements": [bad]})
        # An added library outside the LOAD allowlist (here set_user) is refused before any LOAD.
        added = module.preload_additions(target.connect("dsn"), {"apply_statements": [
            "ALTER SYSTEM SET \"shared_preload_libraries\" = 'pg_stat_statements', 'set_user'"]})
        with pytest.raises(RuntimeError, match="outside the reviewed preload allowlist"):
            module.preload_guard("dsn", added, connect=target.connect)
