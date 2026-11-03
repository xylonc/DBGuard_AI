"""Wave 2a (F6): per-object fix proposals, resolution, rendering and evidence checks.

Unit level, no Docker. Snapshots start from real collector output
(tests/catalog_fixtures.py) with planted roles, functions and table grants.
Gate 1 rulings (docs/gates/W2A-gate1.md, "Accept all", 30 Oct 2026) are pinned
here: the six fix types, the safety list, the 5.5 superuser note and the risks.
"""
from __future__ import annotations

import copy
import hashlib
import re

import pytest

from app.models import (FunctionSecurityInvokerTemplateParams, RoleConnectionLimitTemplateParams,
                        RoleDropAttributeTemplateParams, RoleNologinTemplateParams,
                        TableRevokeDmlTemplateParams)
from app.services.spec_engine.policy import PolicyProfile
from app.services.template_service import quote_identifier
from services.sandbox_poc import object_fixes as of
from services.sandbox_poc.handoff import OBJECT_FIX_ID_PATTERN
from services.sandbox_poc.shared import ROOT, ContractError, SpecEngine, validate_contract
from services.sandbox_poc.templates import ApprovedTemplate
from tests.catalog_fixtures import live_snapshot

SPEC = "cis-pg17-v1.1.0:"
COLLECTOR = "collector"


@pytest.fixture(scope="module")
def engine():
    return SpecEngine.load(ROOT / "catalog/specs/cis-pg17-v1.1.0",
                           ROOT / "catalog/benchmarks/cis-pg17-v1.1.0/records.json")


def role(name, oid, **kw):
    row = {"is_predefined": name.startswith("pg_"), "oid": str(oid), "rolbypassrls": False,
           "rolcanlogin": True, "rolconnlimit": -1, "rolcreatedb": False, "rolcreaterole": False,
           "rolinherit": True, "rolname": name, "rolreplication": False, "rolsuper": False,
           "rolvaliduntil": None}
    row.update(kw)
    return row


def function(name, **kw):
    row = {"acl": ["=X/app_admin", "app_admin=X/app_admin"], "kind": "f", "name": name,
           "owner": "app_admin", "schema": "public", "language": "sql", "extension": None,
           "prosecdef": True, "search_path": None, "config_names": [], "identity_args": ""}
    row.update(kw)
    return row


def table(name, acl, **kw):
    row = {"schema": "app", "name": name, "kind": "r", "owner": "app_admin", "acl": acl,
           "rls": False, "rls_forced": False}
    row.update(kw)
    return row


@pytest.fixture
def snapshot():
    """Real collector snapshot plus planted objects for every fix type."""
    snap = live_snapshot()
    base = snap["baseline"]
    planted = [role("app_admin", 16384, rolcreaterole=True, rolcreatedb=True),
               role("web", 16385),
               role("old_report", 16386),
               role("su2", 16387, rolsuper=True),
               role(COLLECTOR, 16388, rolsuper=True),
               role("limited", 16389, rolconnlimit=5),
               role("nologin_grp", 16390, rolcanlogin=False, rolbypassrls=True),
               role("repl", 16391, rolreplication=True)]
    base["roles"] += planted
    base["password_types"] += [{"rolname": r["rolname"], "password_type": "scram-sha-256"}
                               for r in planted if r["rolcanlogin"] and r["rolname"] != "old_report"]
    base["password_types"].append({"rolname": "old_report", "password_type": "none"})
    snap["envelope"]["collected_by"] = COLLECTOR
    base["functions"] = [
        function("sd", identity_args="a integer, VARIADIC b text[]"),
        function("invoker_only", acl=["app_admin=X/app_admin"]),
        function("not_definer", prosecdef=False, config_names=["search_path"], search_path="public"),
    ]
    base["object_acls"] = [
        table("orders", ["app_admin=arwdDxtm/app_admin", "web=a*rw/app_admin", "=d/app_admin",
                         "old_report=r/app_admin"]),
    ]
    # The tables' schema, as a real collection lists it (the stand-in recreates it).
    base["schemas"].append({"nspacl": ["app_admin=UC/app_admin"], "nspname": "app", "owner": "app_admin",
                            "public_has_create": False, "public_has_usage": False})
    return snap


def approved(name, sql=None):
    sql = sql if sql is not None else (ROOT / f"backend/app/templates/{name}.sql.j2").read_text()
    return ApprovedTemplate(name, 1, sql, hashlib.sha256(sql.encode()).hexdigest(), "Unit Reviewer",
                            ({"document_id": "unit-doc"},))


def profile(limits, approved_by="Melvin Loo"):
    return PolicyProfile(profile_id="unit", benchmark="cis-pg17-v1.1.0", approved_by=approved_by,
                         approved_at="2026-10-30" if approved_by else None, values={}, sha256="a" * 64,
                         connection_limits=limits)


def with_policy(engine, policy):
    clone = copy.copy(engine)
    clone.policy = policy
    return clone


def by_type(proposals, fix_type):
    return [p for p in proposals if p["fix_type"] == fix_type]


def notes_for(plan, spec, code):
    return [n for n in plan["notes"] if n["spec_id"] == SPEC + spec and n["code"] == code]


# ---------------------------------------------------------------------------
# Fix types (Gate 1 table A)
# ---------------------------------------------------------------------------

class TestFixTypes:
    def test_six_types_templates_recommendations_and_ruled_risks(self):
        assert {t: (k.template, k.recommendations, k.risk) for t, k in of.FIX_TYPES.items()} == {
            "role_connection_limit": ("role_connection_limit", ("5.5",), "medium"),
            "role_drop_attribute": ("role_drop_attribute", ("4.3", "4.9"), "high"),
            "role_nologin": ("role_nologin", ("4.4", "4.10"), "high"),
            "function_security_invoker": ("function_security_invoker", ("4.5",), "high"),
            # Ruled "medium-high"; stored as the conservative "high".
            "function_revoke_public_execute": ("function_revoke_public_execute", ("4.5",), "high"),
            "table_revoke_dml": ("table_revoke_dml", ("4.6",), "high"),
        }
        assert all(k.explanation.strip() for k in of.FIX_TYPES.values())

    def test_not_offered_recommendations_never_get_proposals(self, engine, snapshot):
        """Gate 1 B: 4.7, 7.1 and 7.4 stay report-only."""
        plan = of.plan(engine, snapshot)
        specs = {p["spec_id"] for p in plan["proposals"]}
        assert not specs & {SPEC + r for r in ("4.7", "7.1", "7.4")}
        assert {r for k in of.FIX_TYPES.values() for r in k.recommendations} == {
            "4.3", "4.4", "4.5", "4.6", "4.9", "4.10", "5.5"}

    def test_each_type_is_proposed_from_evidence(self, engine, snapshot):
        engine = with_policy(engine, profile({"default_login_limit": 20, "roles": {"web": 50}}))
        props = of.proposals(engine, snapshot, engine.policy_pin)
        drops = {(p["spec_id"], p["target"]["role"], p["target"]["attribute"]) for p in by_type(props, "role_drop_attribute")}
        assert drops == {(SPEC + "4.3", "app_admin", "CREATEROLE"), (SPEC + "4.3", "app_admin", "CREATEDB"),
                         (SPEC + "4.3", "su2", "SUPERUSER"), (SPEC + "4.3", "nologin_grp", "BYPASSRLS"),
                         (SPEC + "4.3", "repl", "REPLICATION"), (SPEC + "4.9", "su2", "SUPERUSER")}
        nologin = {(p["spec_id"], p["target"]["role"]) for p in by_type(props, "role_nologin")}
        assert nologin == {(SPEC + "4.4", r) for r in ("app_admin", "web", "old_report", "su2", "limited", "repl")} | {
            (SPEC + "4.10", "old_report")}
        limits = {p["target"]["role"]: p["params"]["connection_limit"] for p in by_type(props, "role_connection_limit")}
        assert limits == {"web": 50, "app_admin": 20, "old_report": 20, "repl": 20}  # limited already has 5
        invoker = by_type(props, "function_security_invoker")
        assert [p["target"] for p in invoker] == [
            {"schema": "public", "name": "sd", "identity_args": "a integer, VARIADIC b text[]"},
            {"schema": "public", "name": "invoker_only", "identity_args": ""}]
        assert invoker[0]["params"]["arg_types"] == ["integer", "VARIADIC pg_catalog.text[]"]
        revoke = by_type(props, "function_revoke_public_execute")
        assert [p["target"]["name"] for p in revoke] == ["sd"]  # invoker_only: PUBLIC has no EXECUTE
        dml = {(p["target"]["grantee"], tuple(p["target"]["privileges"]), p["target"]["grant_option"])
               for p in by_type(props, "table_revoke_dml")}
        assert dml == {("PUBLIC", ("DELETE",), False), ("web", ("UPDATE",), False), ("web", ("INSERT",), True)}
        for p in props:
            assert p["risk"] == of.FIX_TYPES[p["fix_type"]].risk
            assert p["rehearsable"] is True and "not_rehearsable_reason" not in p
            assert set(p) <= {"fix_id", "spec_id", "fix_type", "target", "params", "prior", "title",
                              "explanation", "risk", "rehearsable", "not_rehearsable_reason", "note", "limit_source"}

    def test_prior_is_the_exact_evidence_value(self, engine, snapshot):
        engine = with_policy(engine, profile({"default_login_limit": 20, "roles": {}}))
        props = of.proposals(engine, snapshot, engine.policy_pin)
        priors = {(p["fix_type"], p["fix_id"]): p["prior"] for p in props}
        for (fix_type, _), prior in priors.items():
            if fix_type == "role_connection_limit":
                assert prior == {"rolconnlimit": -1}
            elif fix_type == "role_nologin":
                assert prior == {"rolcanlogin": True}
            elif fix_type == "function_security_invoker":
                assert prior == {"prosecdef": True}
        drop = next(p for p in props if p["target"].get("attribute") == "CREATEDB")
        assert drop["prior"] == {"rolcreatedb": True}
        revoke = by_type(props, "function_revoke_public_execute")[0]
        assert revoke["prior"] == {"acl": sorted(["=X/app_admin", "app_admin=X/app_admin"])}
        web_insert = next(p for p in by_type(props, "table_revoke_dml") if p["target"]["grant_option"])
        assert web_insert["prior"]["privileges"] == ["INSERT"] and web_insert["prior"]["grant_option"] is True
        assert web_insert["prior"]["acl"] == sorted(snapshot["baseline"]["object_acls"][0]["acl"])


# ---------------------------------------------------------------------------
# fix ids
# ---------------------------------------------------------------------------

class TestFixIds:
    def test_format_and_hash_of_canonical_target(self, engine, snapshot):
        for p in of.proposals(engine, snapshot):
            rec = p["spec_id"].split(":")[1]
            digest = hashlib.sha256(of._canonical(p["target"]).encode()).hexdigest()[:10]
            assert p["fix_id"] == f"fix-{rec}-{p['fix_type']}-{digest}"
            assert re.fullmatch(OBJECT_FIX_ID_PATTERN, p["fix_id"])

    def test_stable_across_calls_copies_and_row_order(self, engine, snapshot):
        first = [p["fix_id"] for p in of.proposals(engine, snapshot)]
        shuffled = copy.deepcopy(snapshot)
        shuffled["baseline"]["roles"].reverse()
        assert sorted(first) == sorted(p["fix_id"] for p in of.proposals(engine, shuffled))
        assert first == [p["fix_id"] for p in of.proposals(engine, copy.deepcopy(snapshot))]

    def test_unique_per_fix_and_target_sensitive(self, engine, snapshot):
        ids = [p["fix_id"] for p in of.proposals(engine, snapshot)]
        assert len(ids) == len(set(ids))
        assert of.fix_id_for("4.4", "role_nologin", {"role": "web"}) != of.fix_id_for("4.4", "role_nologin", {"role": "Web"})
        assert of.fix_id_for("4.4", "role_nologin", {"role": "web"}) != of.fix_id_for("4.10", "role_nologin", {"role": "web"})


# ---------------------------------------------------------------------------
# Safety list (Gate 1 C) and notes
# ---------------------------------------------------------------------------

class TestExclusions:
    def test_bootstrap_superuser_never_offered(self, engine, snapshot):
        engine = with_policy(engine, profile({"default_login_limit": 20, "roles": {}}))
        plan = of.plan(engine, snapshot, engine.policy_pin)
        bootstrap = next(r["rolname"] for r in snapshot["baseline"]["roles"] if r["oid"] == "10")
        assert not [p for p in plan["proposals"] if p["target"].get("role") == bootstrap]
        for rec in ("4.3", "4.4", "4.9", "5.5"):
            assert notes_for(plan, rec, "bootstrap_superuser") == [
                {"spec_id": SPEC + rec, "code": "bootstrap_superuser", "target": {"role": bootstrap},
                 "text": of.NOTE_TEXTS["bootstrap_superuser"]}]

    def test_bootstrap_is_by_oid_not_by_name(self, engine, snapshot):
        for row in snapshot["baseline"]["roles"]:
            if row["oid"] == "10":
                row["rolname"] = "renamed_boot"
        props = of.proposals(engine, snapshot)
        assert not [p for p in props if p["target"].get("role") == "renamed_boot"]

    def test_predefined_roles_never_offered(self, engine, snapshot):
        snapshot["baseline"]["roles"].append(role("pg_fake_admin", 9999, rolcreatedb=True, rolsuper=True))
        snapshot["baseline"]["password_types"].append({"rolname": "pg_fake_admin", "password_type": "none"})
        props = of.proposals(engine, snapshot)
        assert not [p for p in props if str(p["target"].get("role", "")).startswith("pg_")]

    def test_collecting_role_gets_a_note_not_a_proposal(self, engine, snapshot):
        plan = of.plan(engine, snapshot)
        assert not [p for p in plan["proposals"] if p["target"].get("role") == COLLECTOR
                    and p["fix_type"] in ("role_drop_attribute", "role_nologin")]
        for rec in ("4.3", "4.4", "4.9"):
            [note] = notes_for(plan, rec, "collecting_role")
            assert note["target"] == {"role": COLLECTOR} and note["text"] == of.NOTE_TEXTS["collecting_role"]

    def test_collecting_role_may_get_a_connection_limit_with_a_note(self, engine, snapshot):
        for row in snapshot["baseline"]["roles"]:
            if row["rolname"] == COLLECTOR:
                row["rolsuper"] = False
        engine = with_policy(engine, profile({"default_login_limit": 10, "roles": {}}))
        props = by_type(of.proposals(engine, snapshot, engine.policy_pin), "role_connection_limit")
        [mine] = [p for p in props if p["target"]["role"] == COLLECTOR]
        assert "collects with this account" in mine["note"]

    def test_unknown_collector_offers_no_access_removal(self, engine, snapshot):
        del snapshot["envelope"]["collected_by"]
        plan = of.plan(engine, snapshot)
        assert not by_type(plan["proposals"], "role_drop_attribute")
        assert not by_type(plan["proposals"], "role_nologin")
        assert notes_for(plan, "4.3", "collecting_role_unknown")
        assert by_type(plan["proposals"], "table_revoke_dml")  # other types unaffected

    def test_login_role_is_protected_like_the_collecting_role(self, engine, snapshot):
        # Collected after SET ROLE: the login account (session_user) differs from
        # collected_by (current_user), and NOLOGIN on it would break the next collection.
        def removals(plan, name):
            return [p for p in plan["proposals"] if p["target"].get("role") == name
                    and p["fix_type"] in ("role_drop_attribute", "role_nologin")]
        older = copy.deepcopy(snapshot)
        older["envelope"].pop("login_role", None)  # older snapshot: no login_role key
        assert removals(of.plan(engine, older), "su2")
        assert {"role": COLLECTOR} in [n["target"] for n in notes_for(of.plan(engine, older), "4.3", "collecting_role")]
        snapshot["envelope"]["login_role"] = "su2"
        plan = of.plan(engine, snapshot)
        assert not removals(plan, "su2") and not removals(plan, COLLECTOR)
        assert {"role": "su2"} in [n["target"] for n in notes_for(plan, "4.3", "collecting_role")]

    @pytest.mark.parametrize("bad", ["", None, 5])
    def test_unusable_login_role_makes_the_collector_unknown(self, engine, snapshot, bad):
        snapshot["envelope"]["login_role"] = bad
        plan = of.plan(engine, snapshot)
        assert not by_type(plan["proposals"], "role_drop_attribute")
        assert not by_type(plan["proposals"], "role_nologin")
        assert notes_for(plan, "4.3", "collecting_role_unknown")

    def test_superuser_gets_the_ruled_5_5_note(self, engine, snapshot):
        engine = with_policy(engine, profile({"default_login_limit": 20, "roles": {"su2": 3}}))
        plan = of.plan(engine, snapshot, engine.policy_pin)
        assert not [p for p in by_type(plan["proposals"], "role_connection_limit") if p["target"]["role"] == "su2"]
        [note] = [n for n in notes_for(plan, "5.5", "superuser_limit_not_enforced") if n["target"] == {"role": "su2"}]
        assert note["text"] == "limit not enforced; remove SUPERUSER first (fix #2)"

    @pytest.mark.parametrize("policy", [None, "draft"])
    def test_5_5_needs_an_approved_profile(self, engine, snapshot, policy):
        if policy == "draft":
            engine = with_policy(engine, profile({"default_login_limit": 20, "roles": {}}, approved_by=None))
        plan = of.plan(engine, snapshot, engine.policy_pin)
        assert not by_type(plan["proposals"], "role_connection_limit")
        [note] = notes_for(plan, "5.5", "policy_missing")
        assert note["text"].startswith("COMPANY POLICY MISSING")
        assert note["roles"] == ["app_admin", "old_report", "repl", "web"]

    def test_5_5_role_specific_else_default_else_policy_missing(self, engine, snapshot):
        engine = with_policy(engine, profile({"default_login_limit": None, "roles": {"web": 0}}))
        plan = of.plan(engine, snapshot, engine.policy_pin)
        [web] = by_type(plan["proposals"], "role_connection_limit")
        assert web["target"] == {"role": "web"} and web["params"] == {"role_name": "web", "connection_limit": 0}
        assert "stops this account from logging in" in web["note"]
        assert web["limit_source"] == {"source": "role", "profile": engine.policy_pin}
        assert notes_for(plan, "5.5", "policy_missing")[0]["roles"] == ["app_admin", "old_report", "repl"]

    def test_profile_pin_must_match_the_engine(self, engine, snapshot):
        with pytest.raises(ContractError):
            of.plan(engine, snapshot, {"profile_id": "other", "sha256": "b" * 64})
        engine = with_policy(engine, profile({"default_login_limit": 1, "roles": {}}))
        with pytest.raises(ContractError):
            of.plan(engine, snapshot, None)

    def test_extension_owned_functions_never_offered(self, engine, snapshot):
        snapshot["baseline"]["functions"].append(function("ext_fn", extension="pgaudit"))
        plan = of.plan(engine, snapshot)
        assert not [p for p in plan["proposals"] if p["target"].get("name") == "ext_fn"]
        [note] = notes_for(plan, "4.5", "extension_owned")
        assert note["extension"] == "pgaudit"

    def test_system_schema_and_non_functions_never_offered(self, engine, snapshot):
        snapshot["baseline"]["functions"] += [function("sys", schema="pg_catalog"), function("proc", kind="p")]
        plan = of.plan(engine, snapshot)
        assert not [p for p in plan["proposals"] if p["target"].get("name") in ("sys", "proc")]
        assert notes_for(plan, "4.5", "system_schema") and notes_for(plan, "4.5", "not_a_function")

    def test_only_security_definer_functions(self, engine, snapshot):
        props = of.proposals(engine, snapshot)
        assert not [p for p in props if p["target"].get("name") == "not_definer"]

    @pytest.mark.parametrize("args", ["anyelement", "a public.mytype", "integer, mood", '"Weird Name" integer',
                                      "INOUT x integer", "VARIADIC integer", "integer); DROP TABLE t; --",
                                      "numeric(10,2)"])
    def test_unlisted_argument_types_are_not_rehearsable(self, engine, snapshot, args):
        snapshot["baseline"]["functions"] = [function("odd", identity_args=args)]
        props = [p for p in of.proposals(engine, snapshot) if p["target"].get("name") == "odd"]
        assert {p["fix_type"] for p in props} == {"function_security_invoker", "function_revoke_public_execute"}
        for p in props:
            assert p["rehearsable"] is False and "built-in type" in p["not_rehearsable_reason"]
            assert p["params"]["arg_types"] is None
            with pytest.raises(ContractError):
                of.render(p, approved(p["fix_type"]))

    def test_other_languages_are_not_rehearsable(self, engine, snapshot):
        snapshot["baseline"]["functions"] = [function("cfn", language="c")]
        assert all(p["rehearsable"] is False for p in of.proposals(engine, snapshot) if p["fix_type"].startswith("function_"))

    def test_table_extension_evidence(self, engine, snapshot):
        snapshot["baseline"]["extensions"] = None
        plan = of.plan(engine, snapshot)
        assert not by_type(plan["proposals"], "table_revoke_dml")
        assert notes_for(plan, "4.6", "extension_evidence_missing")
        snapshot["baseline"]["extensions"] = [{"extname": "postgis", "owner": "x", "schema": "app", "version": "3"}]
        plan = of.plan(engine, snapshot)
        assert not by_type(plan["proposals"], "table_revoke_dml")
        assert notes_for(plan, "4.6", "possibly_extension_owned")

    def test_table_extension_field_is_preferred_when_collected(self, engine, snapshot):
        snapshot["baseline"]["extensions"] = None  # unused once rows carry the field
        snapshot["baseline"]["object_acls"][0]["extension"] = None
        assert by_type(of.proposals(engine, snapshot), "table_revoke_dml")
        snapshot["baseline"]["object_acls"][0]["extension"] = "postgis"
        plan = of.plan(engine, snapshot)
        assert not by_type(plan["proposals"], "table_revoke_dml") and notes_for(plan, "4.6", "extension_owned")

    def test_table_grants_only_what_is_proven(self, engine, snapshot):
        acl = snapshot["baseline"]["object_acls"][0]["acl"]
        acl[:] = ["app_admin=arwd/app_admin", "web=a/other", "old_report=r/app_admin", '"PUBLIC"=w/app_admin',
                  "pg_write_all_data=a/app_admin", "repl=w*/app_admin", "su2=w/repl"]
        plan = of.plan(engine, snapshot)
        assert by_type(plan["proposals"], "table_revoke_dml") == []
        assert {n["target"]["grantee"] for n in notes_for(plan, "4.6", "grantor_not_owner")} == {"web", "su2"}
        assert notes_for(plan, "4.6", "ambiguous_grantee") and notes_for(plan, "4.6", "predefined_role")
        assert notes_for(plan, "4.6", "dependent_grants")[0]["target"]["grantee"] == "repl"

    def test_owner_and_select_only_grants_are_ignored(self, engine, snapshot):
        snapshot["baseline"]["object_acls"][0]["acl"] = ["app_admin=arwd/app_admin", "web=r/app_admin"]
        assert by_type(of.proposals(engine, snapshot), "table_revoke_dml") == []

    @pytest.mark.parametrize("section,spec", [("roles", "4.3"), ("functions", "4.5"),
                                              ("object_acls", "4.6"), ("password_types", "4.10")])
    def test_gapped_evidence_offers_nothing(self, engine, snapshot, section, spec):
        snapshot["baseline"][section] = None
        snapshot["baseline"]["gaps"] = [{"section": section, "reason": "permission denied"}]
        plan = of.plan(engine, snapshot)
        assert not [p for p in plan["proposals"] if p["spec_id"] == SPEC + spec]
        assert notes_for(plan, spec, "evidence_not_collected")

    def test_grouped_view_per_spec(self, engine, snapshot):
        groups = of.grouped(engine, snapshot)
        assert [g["recommendation"] for g in groups] == ["4.3", "4.4", "4.5", "4.6", "4.9", "4.10", "5.5"]
        for g in groups:
            assert all(p["spec_id"] == g["spec_id"] for p in g["proposals"])
            assert all(n["spec_id"] == g["spec_id"] for n in g["notes"])
            assert g["title"]


# ---------------------------------------------------------------------------
# resolve
# ---------------------------------------------------------------------------

class TestResolve:
    def test_known_id_returns_the_same_proposal(self, engine, snapshot):
        for p in of.proposals(engine, snapshot):
            assert of.resolve(engine, snapshot, None, p["fix_id"]) == p

    @pytest.mark.parametrize("fix_id", [
        "fix-4.4-role_nologin-0000000000",            # well formed, unknown
        "fix-4.3-role_nologin-0000000000",
        "fix-4.4-role_nologin-ZZZZZZZZZZ",            # malformed hash
        "fix-log_connections",                        # a setting fix id
        "fix-4.4-drop_table-0123456789",
        "fix-4.4-role_nologin-0123456789; DROP ROLE x",
        "fix-4.4-role_nologin-" + "0" * 200,
        "", None, 42, ["fix-4.4-role_nologin-0000000000"],
    ])
    def test_unknown_malformed_or_forged_ids_are_refused(self, engine, snapshot, fix_id):
        with pytest.raises(ContractError):
            of.resolve(engine, snapshot, None, fix_id)

    def test_id_from_other_evidence_is_refused(self, engine, snapshot):
        web = next(p for p in of.proposals(engine, snapshot) if p["fix_type"] == "role_nologin"
                   and p["target"] == {"role": "web"})
        changed = copy.deepcopy(snapshot)
        for row in changed["baseline"]["roles"]:
            if row["rolname"] == "web":
                row["rolcanlogin"] = False
        with pytest.raises(ContractError):
            of.resolve(engine, changed, None, web["fix_id"])

    def test_a_limit_id_changes_with_the_profile_value(self, engine, snapshot):
        e1 = with_policy(engine, profile({"default_login_limit": 20, "roles": {}}))
        [p] = [p for p in of.proposals(e1, snapshot, e1.policy_pin) if p["target"] == {"role": "web"}
               and p["fix_type"] == "role_connection_limit"]
        e2 = with_policy(engine, profile({"default_login_limit": 30, "roles": {}}))
        # Same object and id, but the value comes from the engine's profile, never the client.
        assert of.resolve(e2, snapshot, e2.policy_pin, p["fix_id"])["params"]["connection_limit"] == 30
        with pytest.raises(ContractError):
            of.resolve(engine, snapshot, None, p["fix_id"])  # no approved profile: no proposal


# ---------------------------------------------------------------------------
# render
# ---------------------------------------------------------------------------

def find(props, fix_type, **target):
    return next(p for p in props if p["fix_type"] == fix_type
                and all(p["target"].get(k) == v for k, v in target.items()))


class TestRender:
    def test_each_type_renders_apply_and_exact_rollback(self, engine, snapshot):
        engine = with_policy(engine, profile({"default_login_limit": 20, "roles": {}}))
        props = of.proposals(engine, snapshot, engine.policy_pin)
        cases = {
            ("role_connection_limit", (("role", "web"),)): (
                'ALTER ROLE "web" CONNECTION LIMIT 20;', 'ALTER ROLE "web" CONNECTION LIMIT -1;'),
            ("role_drop_attribute", (("role", "su2"), ("attribute", "SUPERUSER"))): (
                'ALTER ROLE "su2" NOSUPERUSER;', 'ALTER ROLE "su2" SUPERUSER;'),
            ("role_nologin", (("role", "old_report"),)): (
                'ALTER ROLE "old_report" NOLOGIN;', 'ALTER ROLE "old_report" LOGIN;'),
            ("function_security_invoker", (("name", "sd"),)): (
                'ALTER FUNCTION "public"."sd"(integer, VARIADIC pg_catalog.text[]) SECURITY INVOKER;',
                'ALTER FUNCTION "public"."sd"(integer, VARIADIC pg_catalog.text[]) SECURITY DEFINER;'),
            ("function_revoke_public_execute", (("name", "sd"),)): (
                'REVOKE EXECUTE ON FUNCTION "public"."sd"(integer, VARIADIC pg_catalog.text[]) FROM PUBLIC;',
                'GRANT EXECUTE ON FUNCTION "public"."sd"(integer, VARIADIC pg_catalog.text[]) TO PUBLIC;'),
            ("table_revoke_dml", (("grantee", "web"), ("grant_option", True))): (
                'REVOKE INSERT ON TABLE "app"."orders" FROM "web";',
                'GRANT INSERT ON TABLE "app"."orders" TO "web" WITH GRANT OPTION;'),
            ("table_revoke_dml", (("grantee", "PUBLIC"),)): (
                'REVOKE DELETE ON TABLE "app"."orders" FROM PUBLIC;',
                'GRANT DELETE ON TABLE "app"."orders" TO PUBLIC;'),
        }
        for (fix_type, target), (apply, rollback) in cases.items():
            p = find(props, fix_type, **dict(target))
            assert of.render(p, approved(fix_type)) == {"apply": [apply], "rollback": [rollback]}

    def test_multi_privilege_revoke_and_regrant(self, engine, snapshot):
        snapshot["baseline"]["object_acls"][0]["acl"] = ["app_admin=arwd/app_admin", "web=awd/app_admin"]
        [p] = by_type(of.proposals(engine, snapshot), "table_revoke_dml")
        assert p["target"]["privileges"] == ["INSERT", "UPDATE", "DELETE"]
        assert of.render(p, approved("table_revoke_dml")) == {
            "apply": ['REVOKE INSERT, UPDATE, DELETE ON TABLE "app"."orders" FROM "web";'],
            "rollback": ['GRANT INSERT, UPDATE, DELETE ON TABLE "app"."orders" TO "web";']}

    def test_template_must_match_type_and_pinned_hash(self, engine, snapshot):
        p = find(of.proposals(engine, snapshot), "role_nologin", role="web")
        with pytest.raises(ContractError):
            of.render(p, approved("role_drop_attribute"))
        with pytest.raises(ContractError):
            of.render(p, approved("set_config_parameter"))
        tampered = approved("role_nologin")
        tampered = ApprovedTemplate("role_nologin", 1, tampered.sql + "\nDROP ROLE x;", tampered.sha256,
                                    "Unit Reviewer", ({"document_id": "unit-doc"},))
        with pytest.raises(ContractError, match="pinned hash"):
            of.render(p, tampered)
        unapproved = approved("role_nologin")
        unapproved = ApprovedTemplate("role_nologin", 1, unapproved.sql, unapproved.sha256, " ", ())
        with pytest.raises(ContractError):
            of.render(p, unapproved)

    def test_a_template_rendering_extra_statements_is_refused(self, engine, snapshot):
        p = find(of.proposals(engine, snapshot), "role_nologin", role="web")
        evil = ('{% if action == "apply" %}ALTER ROLE {{ role_name | ident }} NOLOGIN; ALTER ROLE x SUPERUSER;'
                '{% else %}ALTER ROLE {{ role_name | ident }} LOGIN;{% endif %}')
        with pytest.raises(ContractError):
            of.render(p, approved("role_nologin", evil))

    @pytest.mark.parametrize("name", ['we"ird', 'a""b', 'x; --comment', "--lead", "semi;colon",
                                      "Ünïcødé_rôle", "名前", "Mixed Case", 'a" NOLOGIN; ALTER ROLE "x'])
    def test_hostile_role_names_stay_one_quoted_identifier(self, engine, snapshot, name):
        snapshot["baseline"]["roles"].append(role(name, 17000, rolcreatedb=True))
        snapshot["baseline"]["password_types"].append({"rolname": name, "password_type": "scram-sha-256"})
        props = of.proposals(engine, snapshot)
        for fix_type, keyword in (("role_nologin", "NOLOGIN"), ("role_drop_attribute", "NOCREATEDB")):
            p = find(props, fix_type, role=name)
            assert p["rehearsable"] is True
            assert of.render(p, approved(fix_type))["apply"] == [f"ALTER ROLE {quote_identifier(name)} {keyword};"]

    # "; drop" trips the post-render safety check (template_service.is_safe_sql): fail closed.
    @pytest.mark.parametrize("name", ["x; drop role y", 'a" NOLOGIN; DROP ROLE "x', "a\nb", "tab\there", "nul\x00", "bidi‮evil",
                                      "zero​width", "x" * 64])
    def test_unrenderable_names_are_listed_but_not_rehearsable(self, engine, snapshot, name):
        snapshot["baseline"]["roles"].append(role(name, 17001))
        snapshot["baseline"]["password_types"].append({"rolname": name, "password_type": "scram-sha-256"})
        p = find(of.proposals(engine, snapshot), "role_nologin", role=name)
        assert p["rehearsable"] is False and p["not_rehearsable_reason"]
        with pytest.raises(ContractError):
            of.render(p, approved("role_nologin"))

    @pytest.mark.parametrize("schema,name", [('s"x', 'f"y'), ("s;--", "f; DROP"), ("ünï", "фн")])
    def test_hostile_function_and_table_names(self, engine, snapshot, schema, name):
        snapshot["baseline"]["functions"] = [function(name, schema=schema, identity_args="integer")]
        snapshot["baseline"]["object_acls"] = [table(name, ["app_admin=arwd/app_admin", "web=a/app_admin"], schema=schema)]
        props = of.proposals(engine, snapshot)
        for fix_type in ("function_security_invoker", "table_revoke_dml"):
            p = by_type(props, fix_type)[0]
            if not p["rehearsable"]:
                assert p["not_rehearsable_reason"]  # the post-render check refused it: fail closed
                continue
            [stmt] = of.render(p, approved(fix_type))["apply"]
            assert f"{quote_identifier(schema)}.{quote_identifier(name)}" in stmt

    def test_connection_limit_rollback_uses_prior_never_params(self, engine, snapshot):
        for row in snapshot["baseline"]["roles"]:
            if row["rolname"] == "web":
                row["rolconnlimit"] = -1
        engine = with_policy(engine, profile({"default_login_limit": 7, "roles": {}}))
        p = find(of.proposals(engine, snapshot, engine.policy_pin), "role_connection_limit", role="web")
        assert of.render(p, approved("role_connection_limit"))["rollback"] == ['ALTER ROLE "web" CONNECTION LIMIT -1;']


# ---------------------------------------------------------------------------
# predicate, prior_holds, object_signature
# ---------------------------------------------------------------------------

def mutate(snapshot, section, match, **changes):
    after = copy.deepcopy(snapshot)
    for row in after["baseline"][section]:
        if all(row.get(k) == v for k, v in match.items()):
            row.update(changes)
    return after


class TestEvidenceChecks:
    def test_role_predicates(self, engine, snapshot):
        engine = with_policy(engine, profile({"default_login_limit": 20, "roles": {}}))
        props = of.proposals(engine, snapshot, engine.policy_pin)
        cases = [(find(props, "role_nologin", role="web"), {"rolcanlogin": False}),
                 (find(props, "role_drop_attribute", role="su2"), {"rolsuper": False}),
                 (find(props, "role_connection_limit", role="web"), {"rolconnlimit": 20})]
        for p, change in cases:
            name = p["target"]["role"]
            assert of.prior_holds(p, snapshot) and not of.predicate(p, snapshot)
            after = mutate(snapshot, "roles", {"rolname": name}, **change)
            assert of.predicate(p, after) and not of.prior_holds(p, after)
        wrong = mutate(snapshot, "roles", {"rolname": "web"}, rolconnlimit=21)
        assert not of.predicate(cases[2][0], wrong)

    def test_function_predicates(self, engine, snapshot):
        props = of.proposals(engine, snapshot)
        invoker = find(props, "function_security_invoker", name="sd")
        revoke = find(props, "function_revoke_public_execute", name="sd")
        after = mutate(snapshot, "functions", {"name": "sd"}, prosecdef=False)
        assert of.predicate(invoker, after) and not of.prior_holds(invoker, after)
        after = mutate(snapshot, "functions", {"name": "sd"}, acl=["app_admin=X/app_admin"])
        assert of.predicate(revoke, after) and not of.prior_holds(revoke, after)
        reordered = mutate(snapshot, "functions", {"name": "sd"}, acl=["app_admin=X/app_admin", "=X/app_admin"])
        assert of.prior_holds(revoke, reordered) and not of.predicate(revoke, reordered)

    def test_table_predicate_needs_every_revoked_privilege_gone(self, engine, snapshot):
        p = find(of.proposals(engine, snapshot), "table_revoke_dml", grantee="web", grant_option=False)
        assert p["target"]["privileges"] == ["UPDATE"]
        base = ["app_admin=arwdDxtm/app_admin", "=d/app_admin", "old_report=r/app_admin"]
        assert of.predicate(p, mutate(snapshot, "object_acls", {"name": "orders"}, acl=base + ["web=a*r/app_admin"]))
        assert not of.predicate(p, mutate(snapshot, "object_acls", {"name": "orders"}, acl=base + ["web=w/other"]))
        assert not of.prior_holds(p, mutate(snapshot, "object_acls", {"name": "orders"},
                                            acl=base + ["web=a*r*w/app_admin"]))

    def test_missing_or_gapped_evidence_is_never_fixed_or_prior(self, engine, snapshot):
        p = find(of.proposals(engine, snapshot), "role_nologin", role="web")
        gone = copy.deepcopy(snapshot)
        gone["baseline"]["roles"] = [r for r in gone["baseline"]["roles"] if r["rolname"] != "web"]
        gapped = copy.deepcopy(snapshot)
        gapped["baseline"]["roles"] = None
        gapped["baseline"]["gaps"] = [{"section": "roles", "reason": "x"}]
        for snap in (gone, gapped):
            assert not of.predicate(p, snap) and not of.prior_holds(p, snap)
        assert of.object_signature(p, gone) == {"present": False}
        with pytest.raises(ContractError):
            of.object_signature(p, gapped)

    def test_signature_ignores_oid_and_acl_order(self, engine, snapshot):
        props = of.proposals(engine, snapshot)
        role_fix = find(props, "role_nologin", role="web")
        moved = mutate(snapshot, "roles", {"rolname": "web"}, oid="99999")
        assert of.object_signature(role_fix, moved) == of.object_signature(role_fix, snapshot)
        assert "oid" not in of.object_signature(role_fix, snapshot)
        revoke = find(props, "function_revoke_public_execute", name="sd")
        reordered = mutate(snapshot, "functions", {"name": "sd"}, acl=["app_admin=X/app_admin", "=X/app_admin"])
        assert of.object_signature(revoke, reordered) == of.object_signature(revoke, snapshot)
        changed = mutate(snapshot, "functions", {"name": "sd"}, owner="web")
        assert of.object_signature(revoke, changed) != of.object_signature(revoke, snapshot)

    def test_describe_predicate_for_each_type(self, engine, snapshot):
        engine = with_policy(engine, profile({"default_login_limit": 20, "roles": {}}))
        for p in of.proposals(engine, snapshot, engine.policy_pin):
            assert of.describe_predicate(p).strip()


# ---------------------------------------------------------------------------
# Template parameter schemas refuse anything outside the reviewed shapes
# ---------------------------------------------------------------------------

class TestParamSchemas:
    @pytest.mark.parametrize("schema,params", [
        (RoleNologinTemplateParams, {"role_name": "web", "action": "apply", "extra": 1}),
        (RoleNologinTemplateParams, {"role_name": "web"}),
        (RoleNologinTemplateParams, {"role_name": "web", "action": "drop"}),
        (RoleNologinTemplateParams, {"role_name": "", "action": "apply"}),
        (RoleNologinTemplateParams, {"role_name": "x" * 64, "action": "apply"}),
        (RoleNologinTemplateParams, {"role_name": "a\x00b", "action": "apply"}),
        (RoleNologinTemplateParams, {"role_name": "a\nb", "action": "apply"}),
        (RoleNologinTemplateParams, {"role_name": "a‮b", "action": "apply"}),
        (RoleNologinTemplateParams, {"role_name": 5, "action": "apply"}),
        (RoleConnectionLimitTemplateParams, {"role_name": "web", "connection_limit": True, "action": "apply"}),
        (RoleConnectionLimitTemplateParams, {"role_name": "web", "connection_limit": "10", "action": "apply"}),
        (RoleConnectionLimitTemplateParams, {"role_name": "web", "connection_limit": -2, "action": "apply"}),
        (RoleConnectionLimitTemplateParams, {"role_name": "web", "connection_limit": 2**31, "action": "apply"}),
        (RoleConnectionLimitTemplateParams, {"role_name": "web", "connection_limit": 1.5, "action": "apply"}),
        (RoleDropAttributeTemplateParams, {"role_name": "web", "attribute": "LOGIN", "action": "apply"}),
        (RoleDropAttributeTemplateParams, {"role_name": "web", "attribute": "superuser", "action": "apply"}),
        (RoleDropAttributeTemplateParams, {"role_name": "web", "attribute": "SUPERUSER; DROP", "action": "apply"}),
        (FunctionSecurityInvokerTemplateParams, {"schema_name": "s", "function_name": "f",
                                                 "arg_types": ["text"], "action": "apply"}),
        (FunctionSecurityInvokerTemplateParams, {"schema_name": "s", "function_name": "f",
                                                 "arg_types": ["integer) ; DROP TABLE t"], "action": "apply"}),
        (FunctionSecurityInvokerTemplateParams, {"schema_name": "s", "function_name": "f",
                                                 "arg_types": "integer", "action": "apply"}),
        (FunctionSecurityInvokerTemplateParams, {"schema_name": "s", "function_name": "f",
                                                 "arg_types": ["INOUT integer"], "action": "apply"}),
        (TableRevokeDmlTemplateParams, {"schema_name": "s", "table_name": "t", "grantee": None,
                                        "privileges": ["SELECT"], "grant_option": False, "action": "apply"}),
        (TableRevokeDmlTemplateParams, {"schema_name": "s", "table_name": "t", "grantee": None,
                                        "privileges": ["DELETE", "INSERT"], "grant_option": False, "action": "apply"}),
        (TableRevokeDmlTemplateParams, {"schema_name": "s", "table_name": "t", "grantee": None,
                                        "privileges": ["INSERT", "INSERT"], "grant_option": False, "action": "apply"}),
        (TableRevokeDmlTemplateParams, {"schema_name": "s", "table_name": "t", "grantee": None,
                                        "privileges": [], "grant_option": False, "action": "apply"}),
        (TableRevokeDmlTemplateParams, {"schema_name": "s", "table_name": "t", "grantee": None,
                                        "privileges": ["INSERT"], "grant_option": "yes", "action": "apply"}),
    ])
    def test_refused(self, schema, params):
        with pytest.raises(ValueError):
            schema(**params)

    def test_accepted_shapes(self):
        assert FunctionSecurityInvokerTemplateParams(
            schema_name="s", function_name="f", action="apply",
            arg_types=["integer", "pg_catalog.text[]", "VARIADIC pg_catalog.jsonb[]", "timestamp with time zone"])
        assert RoleConnectionLimitTemplateParams(role_name="web", connection_limit=-1, action="rollback")


# ---------------------------------------------------------------------------
# fix-unit v2 contract
# ---------------------------------------------------------------------------

def fix_unit(proposal, rendered):
    return {"schema_version": "fix-unit-v2", "fix_id": proposal["fix_id"], "spec_id": proposal["spec_id"],
            "fix_type": proposal["fix_type"], "template_id": of.FIX_TYPES[proposal["fix_type"]].template,
            "template_version": 1, "target": proposal["target"], "params": proposal["params"],
            "prior_state": proposal["prior"],
            "apply": {"statements": rendered["apply"], "transactional": True},
            "rollback": {"statements": rendered["rollback"], "transactional": True},
            "verify": {"predicate": of.describe_predicate(proposal)}, "requires": "none"}


class TestFixUnitV2:
    def test_every_real_proposal_validates(self, engine, snapshot):
        engine = with_policy(engine, profile({"default_login_limit": 20, "roles": {}}))
        props = of.proposals(engine, snapshot, engine.policy_pin)
        assert {p["fix_type"] for p in props} == set(of.FIX_TYPES)
        for p in props:
            validate_contract(fix_unit(p, of.render(p, approved(p["fix_type"]))), "fix-unit-v2.json")

    @pytest.mark.parametrize("change", [
        lambda u: u.update(requires="reload"),
        lambda u: u.update(template_id="role_drop_attribute"),
        lambda u: u.update(extra=True),
        lambda u: u["target"].update(role=""),
        lambda u: u["params"].update(connection_limit=-1),
        lambda u: u["apply"].update(transactional=False),
        lambda u: u["apply"].update(statements=["DROP ROLE x;"]),
        lambda u: u.update(fix_id="fix-log_connections"),
        lambda u: u.pop("verify"),
    ])
    def test_refusals(self, engine, snapshot, change):
        from jsonschema import ValidationError
        engine = with_policy(engine, profile({"default_login_limit": 20, "roles": {}}))
        p = find(of.proposals(engine, snapshot, engine.policy_pin), "role_connection_limit", role="web")
        unit = copy.deepcopy(fix_unit(p, of.render(p, approved("role_connection_limit"))))
        change(unit)
        with pytest.raises(ValidationError):
            validate_contract(unit, "fix-unit-v2.json")

    def test_v1_still_describes_settings_only(self):
        import json
        v1 = json.loads((ROOT / "catalog/specs/contracts/fix-unit-v1.json").read_text())
        assert v1["properties"]["template_id"]["pattern"] == "^(SET_CONFIG|REVOKE)_[a-z_]+$"


# ---------------------------------------------------------------------------
# Role expiry timezones (the collector prints the server's timezone; the sandbox is UTC)
# ---------------------------------------------------------------------------

class TestRoleExpiryTimezones:
    @pytest.mark.parametrize("value", ["2027-01-01T08:00:00+08:00", "2027-01-01T00:00:00+00:00",
                                       "2027-01-01T00:00:00Z", "2026-12-31T19:00:00-05:00",
                                       "2027-01-01T05:30:00+05:30", "2027-01-01 08:00:00+08"])
    def test_one_instant_one_form(self, value):
        assert of.utc_valid_until(value) == "2027-01-01T00:00:00.000000"

    def test_microseconds_kept(self):
        assert of.utc_valid_until("2027-01-01T08:00:00.123456+08:00") == "2027-01-01T00:00:00.123456"

    @pytest.mark.parametrize("value", [None, "infinity", "-infinity"])
    def test_null_and_infinities_are_kept(self, value):
        assert of.utc_valid_until(value) == value

    @pytest.mark.parametrize("value", ["2027-01-01T00:00:00", "tomorrow", "", 20270101, "Infinity "])
    def test_unreadable_or_naive_is_refused(self, value):
        with pytest.raises(ContractError):
            of.utc_valid_until(value)

    def test_signature_equal_across_offsets_and_different_for_another_instant(self, engine, snapshot):
        p = find(of.proposals(engine, snapshot), "role_nologin", role="web")
        source = mutate(snapshot, "roles", {"rolname": "web"}, rolvaliduntil="2027-01-01T08:00:00+08:00")
        sandbox = mutate(snapshot, "roles", {"rolname": "web"}, rolvaliduntil="2027-01-01T00:00:00+00:00")
        later = mutate(snapshot, "roles", {"rolname": "web"}, rolvaliduntil="2027-01-01T08:00:00+00:00")
        assert of.object_signature(p, source) == of.object_signature(p, sandbox)
        assert of.object_signature(p, source)["rolvaliduntil"] == "2027-01-01T00:00:00.000000"
        assert of.object_signature(p, source) != of.object_signature(p, later)

    def test_infinity_compares_equal_only_to_infinity(self, engine, snapshot):
        p = find(of.proposals(engine, snapshot), "role_nologin", role="web")
        inf = mutate(snapshot, "roles", {"rolname": "web"}, rolvaliduntil="infinity")
        assert of.object_signature(p, inf) == of.object_signature(p, copy.deepcopy(inf))
        assert of.object_signature(p, inf)["rolvaliduntil"] == "infinity"
        for other in ("-infinity", "2027-01-01T00:00:00+00:00", None):
            assert of.object_signature(p, inf) != of.object_signature(
                p, mutate(snapshot, "roles", {"rolname": "web"}, rolvaliduntil=other))

    def test_unreadable_expiry_never_compares(self, engine, snapshot):
        p = find(of.proposals(engine, snapshot), "role_nologin", role="web")
        with pytest.raises(ContractError):
            of.object_signature(p, mutate(snapshot, "roles", {"rolname": "web"}, rolvaliduntil="soon"))

    def test_prior_with_an_expiry_is_compared_in_utc(self, engine, snapshot):
        p = copy.deepcopy(find(of.proposals(engine, snapshot), "role_nologin", role="web"))
        p["prior"] = {"rolcanlogin": True, "rolvaliduntil": "2027-01-01T08:00:00+08:00"}
        assert of.prior_holds(p, mutate(snapshot, "roles", {"rolname": "web"},
                                        rolvaliduntil="2027-01-01T00:00:00+00:00"))
        assert not of.prior_holds(p, mutate(snapshot, "roles", {"rolname": "web"},
                                            rolvaliduntil="2027-01-01T08:00:00+00:00"))
        assert not of.prior_holds(p, mutate(snapshot, "roles", {"rolname": "web"}, rolvaliduntil="soon"))

    def test_offset_expiry_role_stays_rehearsable(self, engine, snapshot):
        snapshot = mutate(snapshot, "roles", {"rolname": "web"}, rolvaliduntil="2027-01-01T08:00:00+08:00")
        assert find(of.proposals(engine, snapshot), "role_nologin", role="web")["rehearsable"] is True


# ---------------------------------------------------------------------------
# Rehearsability agrees with the stand-in (catalog_skeleton.plan)
# ---------------------------------------------------------------------------

def _variants():
    """Fixture variants: the planted snapshot plus each case the stand-in refuses."""
    def other_settings(s):
        s["baseline"]["functions"].append(function("pinned", config_names=["work_mem", "search_path"],
                                                   search_path="public, pg_temp"))

    def function_grant_by_non_owner(s):
        s["baseline"]["functions"].append(function("granted", acl=["=X/app_admin", "app_admin=X/app_admin",
                                                                   "web=X/su2"]))

    def table_grant_by_non_owner(s):
        s["baseline"]["object_acls"][0]["acl"].append("limited=r/su2")

    def partitioned(s):
        s["baseline"]["object_acls"].append(table("parted", ["app_admin=arwdDxtm/app_admin", "web=w/app_admin"],
                                                  kind="p"))

    def expiry_offset(s):
        for row in s["baseline"]["roles"]:
            if row["rolname"] in ("web", "su2"):
                row["rolvaliduntil"] = "2027-06-30T23:59:59+09:30"

    def memberships_gapped(s):
        s["baseline"]["role_memberships"] = None
        s["baseline"]["gaps"] = [{"section": "role_memberships", "reason": "insufficient_privilege"}]

    def schema_missing(s):
        s["baseline"]["schemas"] = [r for r in s["baseline"]["schemas"] if r["nspname"] != "app"]

    return {"plain": lambda s: None, "other_settings": other_settings,
            "function_grant_by_non_owner": function_grant_by_non_owner,
            "table_grant_by_non_owner": table_grant_by_non_owner, "partitioned": partitioned,
            "expiry_offset": expiry_offset, "memberships_gapped": memberships_gapped,
            "schema_missing": schema_missing}


class TestRehearsableAgreesWithStandIn:
    @pytest.mark.parametrize("variant", list(_variants()))
    def test_every_rehearsable_proposal_passes_the_stand_in(self, engine, snapshot, variant):
        from services.sandbox_poc import catalog_skeleton
        _variants()[variant](snapshot)
        engine = with_policy(engine, profile({"default_login_limit": 20, "roles": {}}))
        props = of.proposals(engine, snapshot, engine.policy_pin)
        assert props
        for p in props:
            if p["rehearsable"]:
                catalog_skeleton.plan(snapshot, [p])  # never raises
                of.render(p, approved(p["fix_type"]))
            else:
                assert p["not_rehearsable_reason"]
                with pytest.raises(ContractError):
                    catalog_skeleton.plan(snapshot, [{**p, "rehearsable": True}])

    def test_function_pinning_other_settings(self, engine, snapshot):
        _variants()["other_settings"](snapshot)
        props = [p for p in of.proposals(engine, snapshot) if p["target"].get("name") == "pinned"]
        assert {p["fix_type"] for p in props} == {"function_security_invoker", "function_revoke_public_execute"}
        for p in props:
            assert p["rehearsable"] is False
            assert p["not_rehearsable_reason"] == "Stand-in refused: the function pins settings a stub cannot recreate"

    def test_function_acl_entry_granted_by_a_non_owner(self, engine, snapshot):
        _variants()["function_grant_by_non_owner"](snapshot)
        props = [p for p in of.proposals(engine, snapshot) if p["target"].get("name") == "granted"]
        assert {p["fix_type"] for p in props} == {"function_security_invoker", "function_revoke_public_execute"}
        assert all(p["rehearsable"] is False and "role other than the owner" in p["not_rehearsable_reason"]
                   for p in props)

    def test_table_acl_entry_for_another_grantee_granted_by_a_non_owner(self, engine, snapshot):
        _variants()["table_grant_by_non_owner"](snapshot)
        props = by_type(of.proposals(engine, snapshot), "table_revoke_dml")
        assert props and all(p["rehearsable"] is False and "role other than the owner" in p["not_rehearsable_reason"]
                             for p in props)

    def test_partitioned_table(self, engine, snapshot):
        _variants()["partitioned"](snapshot)
        props = [p for p in by_type(of.proposals(engine, snapshot), "table_revoke_dml")
                 if p["target"]["table"] == "parted"]
        assert props and all(p["rehearsable"] is False for p in props)
        assert props[0]["not_rehearsable_reason"] == "Stand-in refused: only ordinary tables have a stand-in"
        ordinary = [p for p in by_type(of.proposals(engine, snapshot), "table_revoke_dml")
                    if p["target"]["table"] == "orders"]
        assert ordinary and all(p["rehearsable"] is True for p in ordinary)

    def test_earlier_specific_reasons_win(self, engine, snapshot):
        snapshot["baseline"]["functions"] = [function("cfn", language="c", config_names=["work_mem"])]
        for p in of.proposals(engine, snapshot):
            if p["fix_type"].startswith("function_"):
                assert p["not_rehearsable_reason"] == "The sandbox can only stand in SQL or PL/pgSQL functions."


# ---------------------------------------------------------------------------
# object_acls.extension (collector field) versus the older-snapshot fallback
# ---------------------------------------------------------------------------

class TestTableExtensionField:
    def _two_tables(self, snapshot, with_field):
        base = snapshot["baseline"]
        base["extensions"] = [{"extname": "postgis", "owner": "app_admin", "schema": "app", "version": "3"}]
        base["object_acls"] = [
            table("orders", ["app_admin=arwdDxtm/app_admin", "web=w/app_admin"]),
            table("spatial_ref_sys", ["app_admin=arwdDxtm/app_admin", "web=w/app_admin"]),
        ]
        if with_field:
            base["object_acls"][0]["extension"] = None
            base["object_acls"][1]["extension"] = "postgis"
        return snapshot

    def test_field_present_excludes_only_the_extension_owned_table(self, engine, snapshot):
        plan = of.plan(engine, self._two_tables(snapshot, with_field=True))
        tables = {p["target"]["table"] for p in by_type(plan["proposals"], "table_revoke_dml")}
        assert tables == {"orders"}
        [owned] = notes_for(plan, "4.6", "extension_owned")
        assert owned["target"] == {"schema": "app", "table": "spatial_ref_sys"} and owned["extension"] == "postgis"
        assert not notes_for(plan, "4.6", "possibly_extension_owned")
        assert all(p["rehearsable"] for p in by_type(plan["proposals"], "table_revoke_dml"))

    def test_field_absent_falls_back_to_any_extension_in_schema(self, engine, snapshot):
        plan = of.plan(engine, self._two_tables(snapshot, with_field=False))
        assert by_type(plan["proposals"], "table_revoke_dml") == []
        assert {n["target"]["table"] for n in notes_for(plan, "4.6", "possibly_extension_owned")} == {
            "orders", "spatial_ref_sys"}
        assert not notes_for(plan, "4.6", "extension_owned")
