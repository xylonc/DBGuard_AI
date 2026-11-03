"""Wave 2a sandbox side: stand-in copy, object loop, batch and bundle runner (fake runtimes).

Proposals come from the engine's real object_fixes (resolve/render/predicate/
prior_holds/object_signature) and the real approved template files; only the
sandbox is fake. Live behaviour is proven in tests/test_object_sandbox_live.py.
"""
import copy
import hashlib
import importlib.util
import json
import re
import sys
import types
from unittest.mock import Mock

import pytest
import yaml

from app.services.spec_engine.policy import parse_profile
from services.sandbox_poc import catalog_skeleton as cs
from services.sandbox_poc import object_fixes
from services.sandbox_poc import workflow
from services.sandbox_poc.shared import ROOT, ContractError, SpecEngine
from services.sandbox_poc.templates import ApprovedTemplate
from tests.test_sandbox_poc import snapshot  # noqa: F401  (fixture)

BOOT = "dbguard_poc"
B = "cis-pg17-v1.1.0"


@pytest.fixture
def engine():
    """The real spec set with an approved test profile carrying 5.5 connection limits."""
    from app.services.spec_engine import RecordsIndex
    records = RecordsIndex.load(ROOT / f"catalog/benchmarks/{B}/records.json")
    doc = {"profile_id": "unit-object-fixes", "benchmark": B, "approved_by": "Test Reviewer",
           "approved_at": "2026-10-30", "values": {},
           "connection_limits": {"default_login_limit": None, "roles": {"web": 20}}}
    policy = parse_profile(yaml.safe_dump(doc).encode(), records)
    return SpecEngine.load(ROOT / f"catalog/specs/{B}", ROOT / f"catalog/benchmarks/{B}/records.json", policy)


# ---------------------------------------------------------------------------
# Evidence: roles, one table and one SECURITY DEFINER function whose owners and
# grantees do not exist in a fresh sandbox.
# ---------------------------------------------------------------------------

def _role(name, oid, **attrs):
    row = {"rolname": name, "oid": oid, "rolsuper": False, "rolinherit": True, "rolcreaterole": False,
           "rolcreatedb": False, "rolcanlogin": True, "rolreplication": False, "rolbypassrls": False,
           "rolconnlimit": -1, "rolvaliduntil": None, "is_predefined": False}
    row.update(attrs)
    return row


def plant(snapshot, app="app_admin", table_grantee="app_writer"):
    snapshot["envelope"]["collected_by"] = BOOT
    b = snapshot["baseline"]
    b["extensions"] = [{"extname": "plpgsql", "owner": BOOT, "schema": "pg_catalog", "version": "1.0"}]
    b["roles"] = b["roles"] + [_role(app, 50001, rolsuper=True, rolcreatedb=True),
                               _role("web", 50002, rolconnlimit=-1),
                               _role("tbl_owner", 50003, rolcanlogin=False),
                               _role(table_grantee, 50004)]
    b["password_types"] = b["password_types"] + [
        {"rolname": app, "password_type": "scram-sha-256", "rolvaliduntil": None},
        {"rolname": "web", "password_type": "none", "rolvaliduntil": None},
        {"rolname": table_grantee, "password_type": "md5", "rolvaliduntil": None}]
    b["object_acls"] = b["object_acls"] + [
        {"schema": "public", "name": "orders", "kind": "r", "owner": "tbl_owner",
         "acl": ["tbl_owner=arwdDxtm/tbl_owner", f"{table_grantee}=arwd/tbl_owner"],
         "rls": False, "rls_forced": False}]
    b["functions"] = [{"schema": "public", "name": "definer", "identity_args": "a integer", "kind": "f",
                       "language": "sql", "prosecdef": True, "config_names": ["search_path"],
                       "search_path": "pg_catalog, pg_temp", "owner": "fn_owner",
                       "acl": ["=X/fn_owner", "fn_owner=X/fn_owner"], "extension": None}]
    b["role_memberships"] = b["role_memberships"] + [
        {"role": "tbl_owner", "member": app, "grantor": BOOT, "admin_option": False}]
    return snapshot


def _rows(snapshot, section):
    return snapshot["baseline"].get(section) or []


def _find_role(snapshot, name):
    return next((r for r in _rows(snapshot, "roles") if r["rolname"] == name), None)


def _find_function(snapshot, t):
    return next((r for r in _rows(snapshot, "functions") if (r["schema"], r["name"], r["identity_args"])
                 == (t["schema"], t["name"], t["identity_args"])), None)


def _find_table(snapshot, t):
    return next((r for r in _rows(snapshot, "object_acls") if (r["schema"], r["name"]) == (t["schema"], t["table"])), None)


# The five fix kinds the tests use, picked from the engine's real proposals.
PICKS = [("role_connection_limit", lambda t: t["role"] == "web"),
         ("role_drop_attribute", lambda t: t.get("attribute") == "CREATEDB"),
         ("role_nologin", lambda t: True),
         ("function_security_invoker", lambda t: t["name"] == "definer"),
         ("table_revoke_dml", lambda t: t["table"] == "orders")]


def proposals_for(engine, snapshot, app="app_admin"):
    offered = object_fixes.proposals(engine, snapshot, engine.policy_pin)
    out = []
    for kind, match in PICKS:
        found = [p for p in offered if p["fix_type"] == kind and match(p["target"])
                 and (not kind.startswith("role_") or kind == "role_connection_limit" or p["target"]["role"] == app)]
        assert found, (kind, [p["fix_id"] for p in offered])
        out.append(found[0])
    return out


def object_template(name):
    sql = (ROOT / f"backend/app/templates/{name}.sql.j2").read_text()
    return ApprovedTemplate(name, 1, sql, hashlib.sha256(sql.encode()).hexdigest(), "unit-reviewer",
                            ({"document_id": "doc-1", "version": "1", "sha256": "a" * 64, "approved_by": "unit-reviewer"},),
                            "high")


def manual(kind, target, fix_id="fix-4.4-role_nologin-0000000000"):
    """A hand-made proposal for refusal tests (the skeleton must refuse it on its own)."""
    return {"fix_id": fix_id, "spec_id": f"{B}:4.4", "fix_type": kind, "target": target,
            "params": {}, "prior": {}, "rehearsable": True}


# ---------------------------------------------------------------------------
# Fake sandbox: reproduces the source exactly, then applies statement effects.
# ---------------------------------------------------------------------------

class ObjectRuntime:
    def __init__(self, snapshot, number, effects, fault=None):
        self.original = copy.deepcopy(snapshot)
        self.snapshot = copy.deepcopy(snapshot)
        self.run_id = f"obj-{number}"
        self.name = "fake-" + self.run_id
        self.image_id = "sha256:test"
        self.effects = effects  # [(apply_script, rollback_script, mutate(snapshot, applied))]
        self.fault = fault
        self.executed = []
        self.closed = False

    def start(self):
        if self.fault == "create":
            raise RuntimeError("partial creation failure")

    def write_config(self, *args):
        pass

    def activate(self, expected):
        pass

    def restart(self):
        pass

    def setting_sources(self, names):
        rows = {r["name"]: r for r in self.snapshot["baseline"]["settings"]}
        return {n: {"source": rows[n]["source"], "sourcefile": rows[n]["sourcefile"]} for n in names if n in rows}

    def health(self):
        return True

    def sql(self, script):
        self.executed.append(script)
        if script.startswith("BEGIN;\nCREATE ROLE") or ("ALTER ROLE" in script and "PASSWORD" in script):
            if self.fault == "reproduce" and script.startswith("BEGIN;\nCREATE ROLE"):
                for row in self.snapshot["baseline"]["roles"]:
                    if row["rolname"] in ("web", "app_admin"):
                        row["rolconnlimit"] = 7
            return ""
        for apply_script, rollback_script, mutate in self.effects:
            if script == apply_script:
                if self.fault == "apply_error":
                    raise RuntimeError("psql:<stdin>:2: ERROR: permission denied")
                if self.fault != "verify":
                    mutate(self.snapshot, True)
                if self.fault == "other":
                    _find_role(self.snapshot, "tbl_owner")["rolconnlimit"] = 99
                return ""
            if script == rollback_script:
                if self.fault != "rollback":
                    mutate(self.snapshot, False)
                if self.fault == "other":
                    _find_role(self.snapshot, "tbl_owner")["rolconnlimit"] = -1
                return ""
        return "t" if "count(*)" in script else "1"

    def close(self):
        self.closed = True
        if self.fault == "cleanup":
            return {"verified": False}
        return {"verified": True, "run_id": self.run_id}


def effect_for(proposal):
    rendered = object_fixes.render(proposal, object_template(proposal["fix_type"]))
    apply_s, rollback_s = workflow.object_statements(rendered, proposal["fix_type"])
    t, kind = proposal["target"], proposal["fix_type"]

    def mutate(snapshot, applied):
        if kind.startswith("role_"):
            row = _find_role(snapshot, t["role"])
            if kind == "role_connection_limit":
                row["rolconnlimit"] = proposal["params"]["connection_limit"] if applied else proposal["prior"]["rolconnlimit"]
            elif kind == "role_drop_attribute":
                row[object_fixes.ATTRIBUTE_COLUMNS[t["attribute"]]] = not applied
            else:
                row["rolcanlogin"] = not applied
        elif kind == "function_security_invoker":
            _find_function(snapshot, t)["prosecdef"] = not applied
        elif kind == "function_revoke_public_execute":
            row = _find_function(snapshot, t)
            others = [a for a in row["acl"] if not a.startswith("=")]
            row["acl"] = others if applied else others + [f"=X/{row['owner']}"]
        else:
            row = _find_table(snapshot, t)
            prefix = t["grantee"] + "="
            others = [a for a in row["acl"] if not a.startswith(prefix)]
            # GRANT re-appends the entry at the end (order differs, privileges equal).
            row["acl"] = others if applied else others + [f"{t['grantee']}=arwd/{row['owner']}"]
    return workflow.in_transaction(apply_s), workflow.in_transaction(rollback_s), mutate


@pytest.fixture
def planted(snapshot):  # noqa: F811
    return plant(snapshot)


@pytest.fixture
def props(engine, planted):
    return proposals_for(engine, planted)


def fake_factory(planted, effects, faults, runtimes):
    def factory():
        runtimes.append(ObjectRuntime(planted, len(runtimes) + 1, effects,
                                      faults[min(len(runtimes), len(faults) - 1)]))
        return runtimes[-1]
    return factory


def run_object(engine, planted, proposal, faults):
    runtimes = []
    engine.collect = lambda runtime: copy.deepcopy(runtime.snapshot)
    factory = fake_factory(planted, [effect_for(proposal)], faults, runtimes)
    result = workflow.ObjectRemediationLoop(engine, object_template(proposal["fix_type"]), proposal,
                                            factory).run(planted, engine.assess(planted))
    return result, runtimes


# ---------------------------------------------------------------------------
# 1. Stand-in SQL generation
# ---------------------------------------------------------------------------

class TestSkeletonPlan:
    def test_role_with_exact_attributes_limit_expiry_and_no_password_text(self, planted, props):
        _find_role(planted, "app_admin")["rolvaliduntil"] = "2027-01-01T00:00:00+00:00"
        plan = cs.plan(planted, [props[1]])
        assert plan["statements"][0] == (
            'CREATE ROLE "app_admin" WITH SUPERUSER NOCREATEROLE CREATEDB NOREPLICATION NOBYPASSRLS LOGIN '
            "INHERIT CONNECTION LIMIT -1 VALID UNTIL '2027-01-01T00:00:00+00:00';")
        assert plan["throwaway_passwords"] == {"app_admin": "scram-sha-256"}
        assert not any("PASSWORD" in s for s in plan["statements"])

    def test_role_without_source_password_gets_none(self, planted, props):
        plan = cs.plan(planted, [props[0]])
        assert plan["throwaway_passwords"] == {}
        assert plan["password_types"] == {"web": "none"}
        assert plan["statements"] == [
            'CREATE ROLE "web" WITH NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS LOGIN INHERIT CONNECTION LIMIT -1;']

    def test_table_stub_owner_and_exact_acl_order(self, planted, props):
        plan = cs.plan(planted, [props[4]])
        assert plan["statements"] == [
            'CREATE ROLE "tbl_owner" NOLOGIN;', 'CREATE ROLE "app_writer" NOLOGIN;',
            'CREATE TABLE "public"."orders" ();', 'ALTER TABLE "public"."orders" OWNER TO "tbl_owner";',
            'REVOKE ALL ON TABLE "public"."orders" FROM PUBLIC, "tbl_owner";',
            'GRANT INSERT, SELECT, UPDATE, DELETE, TRUNCATE, REFERENCES, TRIGGER, MAINTAIN ON TABLE "public"."orders" TO "tbl_owner";',
            'GRANT INSERT, SELECT, UPDATE, DELETE ON TABLE "public"."orders" TO "app_writer";']

    def test_function_stub_default_acl_left_alone(self, planted, props):
        plan = cs.plan(planted, [props[3]])
        assert plan["statements"] == [
            'CREATE ROLE "fn_owner" NOLOGIN;',
            'CREATE FUNCTION "public"."definer"("a" integer) RETURNS void LANGUAGE sql SECURITY DEFINER '
            'SET search_path = "pg_catalog", "pg_temp" AS \'\';',
            'ALTER FUNCTION "public"."definer"("a" integer) OWNER TO "fn_owner";']

    def test_function_stub_non_default_acl_and_grant_option(self, planted, props):
        planted["baseline"]["functions"][0]["acl"] = ["fn_owner=X/fn_owner", "app_writer=X*/fn_owner"]
        plan = cs.plan(planted, [props[3]])
        assert plan["statements"][-3:] == [
            'REVOKE ALL ON FUNCTION "public"."definer"("a" integer) FROM PUBLIC, "fn_owner";',
            'GRANT EXECUTE ON FUNCTION "public"."definer"("a" integer) TO "fn_owner";',
            'GRANT EXECUTE ON FUNCTION "public"."definer"("a" integer) TO "app_writer" WITH GRANT OPTION;']

    def test_new_schema_is_created_with_source_owner(self, planted, props):
        planted["baseline"]["object_acls"][-1]["schema"] = "sales"
        planted["baseline"]["schemas"] = planted["baseline"].get("schemas", []) + [
            {"nspname": "sales", "owner": "sch_owner", "nspacl": None, "public_has_create": False, "public_has_usage": False}]
        prop = copy.deepcopy(props[4])
        prop["target"]["schema"] = "sales"
        plan = cs.plan(planted, [prop])
        assert 'CREATE SCHEMA "sales" AUTHORIZATION "sch_owner";' in plan["statements"]
        assert 'CREATE ROLE "sch_owner" NOLOGIN;' in plan["statements"]

    @pytest.mark.parametrize("name", ['x"; DROP ROLE dbguard_poc; --', "semi;colon", "dash--dash",
                                      "ünïcødé_rôle", "back\\slash", "a" * 63, "$1", "'quoted'"])
    def test_hostile_names_are_always_quoted(self, engine, snapshot, name):  # noqa: F811
        planted = plant(snapshot, app=name, table_grantee="w_" + name[:50])
        offered = proposals_for(engine, planted, app=name)
        # The engine may mark a name its template refuses as not rehearsable; the
        # stand-in's own quoting is checked regardless.
        plan = cs.plan(planted, [{**p, "rehearsable": True} for p in offered])
        quoted = '"' + name.replace('"', '""') + '"'
        assert any(s.startswith("CREATE ROLE " + quoted + " WITH") for s in plan["statements"]), plan["statements"]
        for statement in plan["statements"]:
            # Every statement is exactly one SQL statement once quoted names are skipped.
            assert workflow._one_statement(statement), statement
        for proposal in [p for p in offered if p["rehearsable"]]:
            apply, rollback = workflow.object_statements(
                object_fixes.render(proposal, object_template(proposal["fix_type"])), proposal["fix_type"])
            assert all(workflow._one_statement(x) for x in apply + rollback)

    @pytest.mark.parametrize("name", ["", "nul\x00byte", "a" * 64, "ü" * 32, "line\nbreak", "zero​width"])
    def test_names_the_helper_refuses_stop_the_run(self, snapshot, name):  # noqa: F811
        planted = plant(snapshot, app=name)
        with pytest.raises(ContractError, match="Stand-in refused"):
            cs.plan(planted, [manual("role_nologin", {"role": name})])

    def test_engine_marks_unrenderable_names_not_rehearsable_and_skeleton_refuses(self, engine, snapshot):  # noqa: F811
        planted = plant(snapshot, app="zero​width")
        offered = [p for p in object_fixes.proposals(engine, planted, engine.policy_pin)
                   if p["target"].get("role") == "zero​width"]
        assert offered and not any(p["rehearsable"] for p in offered)
        with pytest.raises(ContractError, match="not rehearsable"):
            cs.plan(planted, offered[:1])

    def test_sandbox_role_bootstrap_and_predefined_targets_are_refused(self, planted):
        for role in (BOOT, "pg_monitor"):
            with pytest.raises(ContractError, match="sandbox's own role|predefined"):
                cs.plan(planted, [manual("role_nologin", {"role": role})])
        planted["baseline"]["roles"].append(_role("boot_copy", 10))
        with pytest.raises(ContractError, match="bootstrap"):
            cs.plan(planted, [manual("role_nologin", {"role": "boot_copy"})])

    def test_not_rehearsable_and_unknown_targets_are_refused(self, planted, props):
        with pytest.raises(ContractError, match="not rehearsable"):
            cs.plan(planted, [{**props[3], "rehearsable": False}])
        with pytest.raises(ContractError, match="not in the source evidence"):
            cs.plan(planted, [manual("role_nologin", {"role": "nobody"})])

    @pytest.mark.parametrize("mutate, message", [
        (lambda f: f.update(config_names=["work_mem", "search_path"]), "pins settings"),
        (lambda f: f.update(language="c"), "language"),
        (lambda f: f.update(extension="pgaudit"), "extension"),
        (lambda f: f.update(kind="p"), "plain functions"),
        (lambda f: f.update(acl=["=X/someone_else", "fn_owner=X/fn_owner"]), "other than the owner"),
    ])
    def test_function_stubs_refuse_what_they_cannot_recreate(self, planted, props, mutate, message):
        mutate(planted["baseline"]["functions"][0])
        with pytest.raises(ContractError, match=message):
            cs.plan(planted, [props[3]])

    def test_function_with_a_non_builtin_type_is_refused(self, planted, props):
        planted["baseline"]["functions"][0]["identity_args"] = "a public.mytype"
        prop = copy.deepcopy(props[3])
        prop["target"]["identity_args"] = "a public.mytype"
        with pytest.raises(ContractError, match="type a stub cannot recreate"):
            cs.plan(planted, [prop])

    def test_identity_args_parser(self):
        assert cs.parse_identity_args("a integer, VARIADIC b text[], double precision") == [
            (None, "a", "integer"), ("VARIADIC", "b", "text[]"), (None, None, "double precision")]
        for bad in ("INOUT a integer", "a integer DEFAULT 1", '"A" integer', "a public.t", "a integer; DROP",
                    "VARIADIC a integer", "anyelement"):
            with pytest.raises(ContractError):
                cs.parse_identity_args(bad)

    def test_search_path_parser(self):
        assert cs.parse_search_path('"$user", pg_catalog, "we ""ird"""') == ["$user", "pg_catalog", 'we "ird"']
        for bad in ('"unterminated', "a,,b", 'a "b"'):
            with pytest.raises(ContractError):
                cs.parse_search_path(bad)

    def test_only_needed_memberships(self, planted, props):
        plan = cs.plan(planted, [props[2], props[4]])  # app_admin (exact) and tbl_owner (owner dependency)
        assert plan["memberships"] == [{"role": "tbl_owner", "member": "app_admin", "admin_option": False}]
        assert 'GRANT "tbl_owner" TO "app_admin";' in plan["statements"]
        assert cs.plan(planted, [props[4]])["memberships"] == []


class RecordingRuntime:
    run_id = "rec"

    def __init__(self, fail_password=False):
        self.scripts = []
        self.fail_password = fail_password

    def sql(self, script):
        self.scripts.append(script)
        if self.fail_password and "PASSWORD" in script:
            secret = re.search(r"PASSWORD '([^']+)'", script)[1]
            raise RuntimeError(f"Docker exec failed: ERROR: near PASSWORD '{secret}'")
        return ""


def _secret(script):
    return re.search(r"PASSWORD '([^']+)'", script)[1]


class TestThrowawayPasswords:
    def test_password_only_on_stdin_never_in_summary(self, planted, props):
        runtime = RecordingRuntime()
        summary = cs.build(runtime, planted, [props[1]])
        assert len(runtime.scripts) == 2
        secret = _secret(runtime.scripts[1])
        assert len(secret) >= 40
        assert "SET log_statement = 'none';" in runtime.scripts[1]
        assert "\\set VERBOSITY terse" in runtime.scripts[1]
        assert secret not in json.dumps(summary) and secret not in runtime.scripts[0]
        assert summary["throwaway_password_roles"] == ["app_admin"]
        assert "throwaway_passwords" not in summary

    def test_md5_source_uses_md5_and_a_new_secret_each_time(self, planted):
        runtimes = [RecordingRuntime(), RecordingRuntime()]
        for runtime in runtimes:
            cs.build(runtime, planted, [manual("role_nologin", {"role": "app_writer"})])
        assert "SET password_encryption = 'md5';" in runtimes[0].scripts[1]
        assert _secret(runtimes[0].scripts[1]) != _secret(runtimes[1].scripts[1])

    def test_failure_message_never_carries_the_statement(self, planted, props):
        runtime = RecordingRuntime(fail_password=True)
        with pytest.raises(RuntimeError) as caught:
            cs.build(runtime, planted, [props[1]])
        assert _secret(runtime.scripts[1]) not in str(caught.value)
        assert caught.value.__cause__ is None and caught.value.__suppress_context__

    def test_loop_result_and_bundle_never_contain_a_password(self, engine, planted, props):
        result, runtimes = run_object(engine, planted, props[1], [None])
        assert result["status"] == "VERIFIED", result["attempts"][0].get("error")
        scripts = [s for s in runtimes[0].executed if "PASSWORD" in s]
        assert len(scripts) == 1
        assert _secret(scripts[0]) not in json.dumps(result)


# ---------------------------------------------------------------------------
# 2. Loop control flow
# ---------------------------------------------------------------------------

class TestObjectLoop:
    @pytest.mark.parametrize("index", range(5))
    def test_each_fix_type_verifies_and_cleans_up(self, engine, planted, props, index):
        result, runtimes = run_object(engine, planted, props[index], [None])
        attempt = result["attempts"][0]
        assert result["status"] == "VERIFIED", attempt.get("error")
        assert attempt["rollback_verified"] and attempt["cleanup"]["verified"]
        assert attempt["other_objects_changed"] == [] and attempt["regressions"] == []
        assert result["fix_unit"]["requires"] == "none"
        assert result["fix_unit"]["schema_version"] == "fix-unit-v2"
        assert result["fix_unit"]["apply"]["statements"] == result["rendered_apply_sql"].split("\n")
        # Apply and rollback each ran as exactly one transaction.
        executed = runtimes[0].executed
        assert workflow.in_transaction(result["fix_unit"]["apply"]["statements"]) in executed
        assert workflow.in_transaction(result["fix_unit"]["rollback"]["statements"]) in executed
        assert all(r.closed for r in runtimes)

    def test_function_revoke_public_execute(self, engine, planted):
        prop = next(p for p in object_fixes.proposals(engine, planted, engine.policy_pin)
                    if p["fix_type"] == "function_revoke_public_execute")
        result, _ = run_object(engine, planted, prop, [None])
        assert result["status"] == "VERIFIED", result["attempts"][0].get("error")
        # The re-granted PUBLIC entry comes back last: an ACL is compared as a set.
        restored = _find_function(result["attempts"][0]["rollback"], prop["target"])
        assert restored["acl"][-1].startswith("=X/")

    def test_reproduce_failure_is_terminal_and_cleaned(self, engine, planted, props):
        result, runtimes = run_object(engine, planted, props[0], ["reproduce"])
        assert result["status"] == "FAILED" and len(runtimes) == 1
        assert "does not reproduce the source object" in result["attempts"][0]["error"]
        assert runtimes[0].closed
        assert not any("CONNECTION LIMIT 20" in s for s in runtimes[0].executed)

    @pytest.mark.parametrize("fault, index", [("verify", 0), ("apply_error", 0), ("other", 4)])
    def test_verify_failures_retry_fresh_and_never_pass(self, engine, planted, props, fault, index):
        result, runtimes = run_object(engine, planted, props[index], [fault])
        assert result["status"] == "FAILED"
        assert len(runtimes) == 3 and len({r.run_id for r in runtimes}) == 3
        assert all(r.closed for r in runtimes)
        # Rollback is still exercised after a failed apply.
        rollback = workflow.in_transaction(result["fix_unit"]["rollback"]["statements"])
        assert all(rollback in r.executed for r in runtimes)

    def test_other_recreated_object_change_is_reported(self, engine, planted, props):
        # The table stand-in also recreates its owner tbl_owner; the fault changes that role.
        result, _ = run_object(engine, planted, props[4], ["other"])
        assert "role:tbl_owner" in result["attempts"][0]["other_objects_changed"]

    def test_rollback_mismatch_fails(self, engine, planted, props):
        result, _ = run_object(engine, planted, props[2], ["rollback"])
        assert result["status"] == "FAILED"
        assert result["attempts"][0]["rollback_verified"] is False
        assert "Exact rollback verification failed" in result["attempts"][0]["error"]

    def test_rollback_that_reorders_an_acl_is_still_exact(self, engine, planted, props):
        result, _ = run_object(engine, planted, props[4], [None])
        assert result["status"] == "VERIFIED"
        restored = _find_table(result["attempts"][0]["rollback"], {"schema": "public", "table": "orders"})
        assert restored["acl"][-1].startswith("app_writer=")  # re-appended, same privileges

    def test_cleanup_failure_is_terminal(self, engine, planted, props):
        result, runtimes = run_object(engine, planted, props[0], ["cleanup"])
        assert result["status"] == "CLEANUP_FAILED" and len(runtimes) == 1

    def test_inputs_are_checked_before_any_container(self, engine, planted, props):
        prop = props[0]
        factory = Mock(side_effect=AssertionError("no container"))
        template = object_template(prop["fix_type"])
        assessment = engine.assess(planted)
        for bad, message in (({**prop, "rehearsable": False}, "cannot be rehearsed"),
                             ({**prop, "params": {**prop["params"], "connection_limit": 1}}, "differs from the evidence-derived"),
                             ({**prop, "fix_id": "fix-5.5-role_connection_limit-ffffffffff"}, "Unknown object fix id")):
            with pytest.raises(ContractError, match=message):
                workflow.ObjectRemediationLoop(engine, template, bad, factory).run(planted, assessment)
        with pytest.raises(ContractError, match="does not match this object fix type"):
            workflow.ObjectRemediationLoop(engine, object_template("role_nologin"), prop, factory).run(planted, assessment)
        # The source no longer shows the problem (limit already set): not offered any more.
        fixed = copy.deepcopy(planted)
        _find_role(fixed, "web")["rolconnlimit"] = 20
        with pytest.raises(ContractError):
            workflow.ObjectRemediationLoop(engine, template, prop, factory).run(fixed, engine.assess(fixed))
        factory.assert_not_called()

    @pytest.mark.parametrize("statement", [
        "ALTER ROLE \"web\" CONNECTION LIMIT 20; DROP ROLE x;", "ALTER ROLE \"web\" NOLOGIN;\n\\! rm -rf /",
        "COMMIT; ALTER ROLE \"web\" NOLOGIN;", "DROP ROLE \"web\";", "ALTER ROLE \"web\" NOLOGIN -- x;",
        "ALTER ROLE \"web\" PASSWORD $$x$$;", "ALTER ROLE \"w;eb\" NOLOGIN; SELECT 1;", "ALTER ROLE \"web\" NOLOGIN"])
    def test_rendered_statements_outside_the_supported_shape_are_refused(self, statement):
        with pytest.raises(ContractError):
            workflow.object_statements({"apply": [statement], "rollback": ['ALTER ROLE "web" LOGIN;']}, "role_nologin")
        assert workflow.object_statements({"apply": ['ALTER ROLE "w;e""b--" NOLOGIN;'],
                                           "rollback": ['ALTER ROLE "w;e""b--" LOGIN;']}, "role_nologin")


# ---------------------------------------------------------------------------
# 3. Batch: object fixes alone, then combined in one sandbox
# ---------------------------------------------------------------------------

class TestBatchConflicts:
    def test_same_object_attribute_is_a_contract_error(self, engine, planted, props):
        from services.sandbox_poc.batch import object_conflicts
        object_conflicts(props)  # five different object attributes
        superuser = [p for p in object_fixes.proposals(engine, planted, engine.policy_pin)
                     if p["fix_type"] == "role_drop_attribute" and p["target"] == {"role": "app_admin", "attribute": "SUPERUSER"}]
        assert {p["spec_id"] for p in superuser} == {f"{B}:4.3", f"{B}:4.9"}  # two fix ids, one attribute
        with pytest.raises(ContractError, match="same object attribute"):
            object_conflicts(superuser)
        # Same role, different attributes is allowed (NOLOGIN + NOCREATEDB).
        object_conflicts([props[1], props[2]])

    def test_split_grant_option_proposals_on_one_grantee_do_not_conflict(self, engine, planted):
        from services.sandbox_poc.batch import object_conflicts
        _find_table(planted, {"schema": "public", "table": "orders"})["acl"][1] = "app_writer=a*rw/tbl_owner"
        table = [p for p in object_fixes.proposals(engine, planted, engine.policy_pin) if p["fix_type"] == "table_revoke_dml"]
        assert sorted(p["target"]["grant_option"] for p in table) == [False, True]
        object_conflicts(table)


def batch_service(engine, planted, faults_by_number=None):
    from dataclasses import replace
    from services.sandbox_poc.handoff import SandboxHandoff, TemplateReference, build_handoff
    from services.sandbox_poc.service import SandboxService
    proposals = proposals_for(engine, planted)[:3]
    effects = [effect_for(p) for p in proposals]
    runtimes = []

    def factory():
        n = len(runtimes) + 1
        runtimes.append(ObjectRuntime(planted, n, effects, (faults_by_number or {}).get(n)))
        return runtimes[-1]

    templates = {p["fix_type"]: object_template(p["fix_type"]) for p in proposals}
    refs = {name: TemplateReference(registry_name=name, version=1, sha256=t.sha256,
                                    evidence=[{"document_id": "doc-1", "version": "1", "sha256": "a" * 64}])
            for name, t in templates.items()}
    service = SandboxService("unused", runtime_factory=factory,
                             registry_loader=lambda url, version, sha, docs, env, **kw: templates[kw["registry_name"]])
    from scripts.sandbox_poc import demo_template
    setting = demo_template()
    setting_ref = TemplateReference(version=setting.version, sha256=setting.sha256,
                                    evidence=[{"document_id": "doc-1", "version": "1", "sha256": "a" * 64}])
    base = build_handoff(engine, planted, setting_ref).model_dump()
    requests = [SandboxHandoff(**{**base, "control_id": p["spec_id"], "object_fix_id": p["fix_id"],
                                  "template_ref": refs[p["fix_type"]].model_dump()}) for p in proposals]
    return service, requests, runtimes, proposals


class TestObjectBatch:
    def _run(self, engine, planted, monkeypatch, tmp_path, faults=None):
        from services.sandbox_poc import batch, profiles
        monkeypatch.setattr(profiles, "resolve_profile", lambda records, specs, ref: engine.policy)
        monkeypatch.setenv("DBGUARD_HISTORY_DIR", str(tmp_path))
        monkeypatch.setattr(SpecEngine, "collect", lambda self, runtime: copy.deepcopy(runtime.snapshot))
        service, requests, runtimes, proposals = batch_service(engine, planted, faults)
        output, data = batch.run_batch(requests, service)
        return output, data, runtimes, proposals

    def test_three_object_fixes_alone_then_combined(self, engine, planted, monkeypatch, tmp_path):
        output, data, runtimes, proposals = self._run(engine, planted, monkeypatch, tmp_path)
        assert output["status"] == "VERIFIED", output.get("combined_test", {}).get("reason") or output
        assert [r["status"] for r in output["individual_runs"]] == ["VERIFIED"] * 3
        combined = runtimes[-1]
        assert len(runtimes) == 4 and all(r.closed for r in runtimes)
        # One stand-in holding all three targets, each fix in its own transaction, reverse rollback.
        assert sum(s.startswith("BEGIN;\nCREATE ROLE") for s in combined.executed) == 1
        applied = [s for s in combined.executed if s.startswith("BEGIN;\nALTER ROLE")]
        order = output["recommended_order"]
        assert len(applied) == 6
        rollback_ids = [r["fix_id"] for r in output["combined_test"]["rollback"]]
        assert rollback_ids == list(reversed(order))
        assert all(r["verified"] for r in output["combined_test"]["rollback"])
        import io, zipfile
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            names = z.namelist()
            readme = z.read("README.txt").decode()
            for fix_id in order:
                config = json.loads(z.read(fix_id + "/fix.json"))
                assert config["kind"] == "object" and config["prior"] != config["applied"]
        assert "WHAT WAS NOT REHEARSED" in readme
        assert {n.split("/", 1)[1] for n in names if "/" in n} <= {
            "fix.json", "evidence.json", "report.html", "harden.sh", "runner.py", "risk-review.json",
            "verify.sh", "visual_evidence.py", "manifest.json", "README.txt"}

    def test_combined_rollback_mismatch_fails(self, engine, planted, monkeypatch, tmp_path):
        output, data, runtimes, _ = self._run(engine, planted, monkeypatch, tmp_path, {4: "rollback"})
        assert output["status"] == "FAILED" and data is None
        assert runtimes[-1].closed

    def test_combined_reproduce_failure(self, engine, planted, monkeypatch, tmp_path):
        output, data, runtimes, _ = self._run(engine, planted, monkeypatch, tmp_path, {4: "reproduce"})
        assert output["status"] == "FAILED" and data is None
        assert "does not reproduce" in output["combined_test"]["reason"]
        assert runtimes[-1].closed

    def test_duplicate_fix_ids_are_refused(self, engine, planted, monkeypatch, tmp_path):
        from services.sandbox_poc import batch, profiles
        monkeypatch.setattr(profiles, "resolve_profile", lambda records, specs, ref: engine.policy)
        service, requests, runtimes, _ = batch_service(engine, planted)
        with pytest.raises(ContractError, match="Duplicate"):
            batch.run_batch([requests[0], requests[0]], service)
        assert runtimes == []


# ---------------------------------------------------------------------------
# 4. Bundle runner object guard (fake psycopg2)
# ---------------------------------------------------------------------------

def load_runner():
    spec = importlib.util.spec_from_file_location(
        "runner_under_test", ROOT / "services/sandbox_poc/bundle_assets/runner.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


ROLE_ROW_PRIOR = (False, True, False, True, True, False, False, -1, None)
ROLE_ROW_APPLIED = (False, True, False, False, True, False, False, -1, None)


class FakeTarget:
    """A target whose role row changes when the apply statement runs (until commit)."""

    def __init__(self, row, after_apply=None, sysid="42", safety=(False, False, False)):
        self.row, self.after_apply, self.sysid = row, after_apply, sysid
        self.safety = safety  # (bootstrap superuser, pg_ role, connected account)
        self.executed, self.commits, self.rollbacks = [], 0, 0
        self.pending = None

    def connect(self, dsn, connect_timeout=10):
        target = self

        class Cursor:
            def __enter__(self): return self
            def __exit__(self, *a): return False

            def execute(self, sql, params=None):
                self.last = sql
                target.executed.append(sql)
                if sql.startswith("ALTER ROLE"):
                    target.pending = target.after_apply

            def fetchone(self):
                if "server_version_num" in self.last:
                    return (17, "appdb")
                if "advisory" in self.last:
                    return (True,)
                if "system_identifier" in self.last:
                    return (target.sysid,)
                return (1,)

            def fetchall(self):
                if "session_user" in self.last:
                    return [target.safety]
                if "pg_roles" in self.last:
                    return [target.pending or target.row]
                return [(1,)]

        class Conn:
            autocommit = True
            def cursor(self): return Cursor()
            def commit(self):
                target.commits += 1
                if target.pending:
                    target.row, target.pending = target.pending, None
            def rollback(self):
                target.rollbacks += 1
                target.pending = None
            def close(self): pass
        return Conn()


def role_config(runner):
    fields = runner.ROLE_FIELDS
    return {"kind": "object", "fix_id": "fix-4.3-role_drop_attribute-0000000002", "demo_fixture_approval": False,
            "database": "appdb", "system_identifier": "42", "target": {"role": "app", "attribute": "CREATEDB"},
            "prior": {"kind": "role", "rolname": "app", **dict(zip(fields, ROLE_ROW_PRIOR))},
            "applied": {"kind": "role", "rolname": "app", **dict(zip(fields, ROLE_ROW_APPLIED))},
            "apply_statements": ['ALTER ROLE "app" NOCREATEDB;'], "rollback_statements": ['ALTER ROLE "app" CREATEDB;']}


@pytest.fixture
def runner(monkeypatch):
    module = load_runner()
    fake = types.ModuleType("psycopg2")
    monkeypatch.setitem(sys.modules, "psycopg2", fake)
    return module, fake


class TestRunnerObjectGuard:
    def test_apply_commits_one_transaction_when_object_matches(self, runner):
        module, fake = runner
        target = FakeTarget(ROLE_ROW_PRIOR, ROLE_ROW_APPLIED)
        fake.connect = target.connect
        assert module.execute(role_config(module), "apply", "dsn")["verified"]
        assert target.commits == 1 and target.rollbacks == 0
        assert target.row == ROLE_ROW_APPLIED

    def test_changed_object_is_refused_before_any_sql(self, runner):
        module, fake = runner
        changed = (True,) + ROLE_ROW_PRIOR[1:]  # someone made the role a superuser
        target = FakeTarget(changed, ROLE_ROW_APPLIED)
        fake.connect = target.connect
        with pytest.raises(RuntimeError, match="Object drift detected; no SQL executed"):
            module.execute(role_config(module), "apply", "dsn")
        assert not any(s.startswith("ALTER ROLE") for s in target.executed)
        assert target.commits == 0

    def test_wrong_result_inside_the_transaction_is_rolled_back(self, runner):
        module, fake = runner
        target = FakeTarget(ROLE_ROW_PRIOR, (True,) + ROLE_ROW_APPLIED[1:])
        fake.connect = target.connect
        with pytest.raises(RuntimeError, match="rolled back"):
            module.execute(role_config(module), "apply", "dsn")
        assert target.commits == 0 and target.rollbacks == 1 and target.row == ROLE_ROW_PRIOR

    def test_rollback_requires_the_applied_state(self, runner):
        module, fake = runner
        target = FakeTarget(ROLE_ROW_PRIOR)
        fake.connect = target.connect
        with pytest.raises(RuntimeError, match="drift"):
            module.execute(role_config(module), "rollback", "dsn")
        assert target.commits == 0

    def test_cluster_identity_and_demo_guards(self, runner):
        module, fake = runner
        target = FakeTarget(ROLE_ROW_PRIOR, ROLE_ROW_APPLIED, sysid="other")
        fake.connect = target.connect
        with pytest.raises(RuntimeError, match="cluster identity"):
            module.execute(role_config(module), "status", "dsn")
        with pytest.raises(RuntimeError, match="Demo fixture"):
            module.execute({**role_config(module), "demo_fixture_approval": True}, "apply", "dsn")

    def test_status(self, runner):
        module, fake = runner
        fake.connect = FakeTarget(ROLE_ROW_PRIOR).connect
        assert module.execute(role_config(module), "status", "dsn") == {"matches_prior": True, "matches_applied": False}

    @pytest.mark.parametrize("safety,message", [
        ((True, False, False), "bootstrap superuser"),
        ((False, True, False), "built-in pg_ roles"),
        ((False, False, True), "account the runner is connected as"),
    ])
    @pytest.mark.parametrize("action,row", [("apply", ROLE_ROW_PRIOR), ("rollback", ROLE_ROW_APPLIED)])
    def test_protected_roles_are_refused_on_the_target(self, runner, safety, message, action, row):
        # The snapshot's safety list may be stale or not the DBA's; the runner re-checks.
        module, fake = runner
        target = FakeTarget(row, ROLE_ROW_APPLIED, safety=safety)
        fake.connect = target.connect
        with pytest.raises(RuntimeError, match=message):
            module.execute(role_config(module), action, "dsn")
        assert not any(s.startswith("ALTER ROLE") for s in target.executed)
        assert target.commits == 0

    def test_read_only_actions_skip_the_safety_refusal(self, runner):
        module, fake = runner
        fake.connect = FakeTarget(ROLE_ROW_PRIOR, safety=(False, False, True)).connect
        assert module.execute(role_config(module), "status", "dsn")["matches_prior"] is True

    def test_runner_pins_search_path_before_catalog_queries(self, runner):
        module, fake = runner
        target = FakeTarget(ROLE_ROW_PRIOR, ROLE_ROW_APPLIED)
        fake.connect = target.connect
        module.execute(role_config(module), "apply", "dsn")
        pins = [i for i, s in enumerate(target.executed) if s == "SET search_path = pg_catalog, pg_temp"]
        first_catalog = next(i for i, s in enumerate(target.executed) if "pg_catalog.pg_roles" in s)
        assert pins and pins[0] < first_catalog
        # Both the guarded connection and the fresh confirming connection are pinned.
        assert len(pins) == 2


def test_bundle_fingerprint_matches_runner_shape(planted, props):
    from services.sandbox_poc.review_bundle import object_fingerprint
    runner = load_runner()
    role = object_fingerprint(props[1], planted)
    assert set(role) == {"kind", "rolname", *runner.ROLE_FIELDS}
    table = object_fingerprint(props[4], planted)
    assert table["acl"] == sorted(table["acl"]) and table["relkind"] == "r"
    function = object_fingerprint(props[3], planted)
    assert set(function) == {"kind", "schema", "name", "identity_args", "prokind", "owner", "prosecdef",
                             "acl", "search_path", "config_names"}
    _find_role(planted, "app_admin")["rolvaliduntil"] = "2027-01-01T08:00:00+08:00"
    assert object_fingerprint(props[1], planted)["rolvaliduntil"] == "2027-01-01T00:00:00.000000"


class TestObjectReviewBundle:
    def _bundle_inputs(self, engine, planted, props, index=1):
        from scripts.sandbox_poc import demo_template
        from services.sandbox_poc.handoff import SandboxHandoff, TemplateReference, build_handoff
        prop = props[index]
        result, _ = run_object(engine, planted, prop, [None])
        assert result["status"] == "VERIFIED"
        result.update(run_id="unit-object-run", approval_source="registry", requires_dba_review=True)
        template = object_template(prop["fix_type"])
        setting = demo_template()
        doc = [{"document_id": "doc-1", "version": "1", "sha256": "a" * 64}]
        base = build_handoff(engine, planted, TemplateReference(version=setting.version, sha256=setting.sha256,
                                                                evidence=doc)).model_dump()
        ref = TemplateReference(registry_name=prop["fix_type"], version=1, sha256=template.sha256, evidence=doc)
        handoff = SandboxHandoff(**{**base, "control_id": prop["spec_id"], "object_fix_id": prop["fix_id"],
                                    "template_ref": ref.model_dump()})
        return handoff, result

    def test_bundle_members_guard_and_rehearsal_text(self, engine, planted, props):
        import io
        import zipfile
        from services.sandbox_poc.review_bundle import build_review_bundle
        handoff, result = self._bundle_inputs(engine, planted, props)
        with zipfile.ZipFile(io.BytesIO(build_review_bundle(handoff, result, engine))) as z:
            names = set(z.namelist())
            config = json.loads(z.read("fix.json"))
            readme = z.read("README.txt").decode()
            report = z.read("report.html").decode()
            manifest = json.loads(z.read("manifest.json"))
            everything = b"".join(z.read(n) for n in names)
        assert names == {"fix.json", "evidence.json", "report.html", "runner.py", "harden.sh", "risk-review.json",
                         "visual_evidence.py", "verify.sh", "manifest.json", "README.txt"}
        assert set(manifest["files"]) == names - {"manifest.json", "README.txt"}
        assert config["kind"] == "object" and config["requires"] == "none" and config["transactional"]
        assert config["apply_statements"] == ['ALTER ROLE "app_admin" NOCREATEDB;']
        assert config["rollback_statements"] == ['ALTER ROLE "app_admin" CREATEDB;']
        assert config["prior"]["rolcreatedb"] is True and config["applied"]["rolcreatedb"] is False
        assert config["predicate"] == object_fixes.describe_predicate(props[1])
        assert "WHAT WAS REHEARSED" in readme and "WHAT WAS NOT REHEARSED" in readme
        assert "no real data" in readme and "applications use the object" in readme
        assert "What was not rehearsed" in report
        assert not re.search(rb"PASSWORD\s+'", everything)

    @pytest.mark.parametrize("tamper, message", [
        (lambda r: r["fix_unit"]["apply"]["statements"].__setitem__(0, 'ALTER ROLE "app_admin" NOSUPERUSER;'), "fix-unit identity"),
        (lambda r: r.update(rendered_apply_sql='ALTER ROLE "app_admin" NOSUPERUSER;'), "rendered statements differ"),
        (lambda r: r["proposal"].update(risk="low"), "evidence-derived proposal"),
        (lambda r: r["attempts"][-1].update(other_objects_changed=["role:x"]), "regression evidence"),
        (lambda r: r["attempts"][-1]["cleanup"].update(verified=False), "cleanup"),
        (lambda r: r.update(status="FAILED"), "only VERIFIED"),
    ])
    def test_tampered_results_are_refused(self, engine, planted, props, tamper, message):
        from services.sandbox_poc.review_bundle import build_review_bundle
        handoff, result = self._bundle_inputs(engine, planted, props)
        tamper(result)
        with pytest.raises(ContractError, match=message):
            build_review_bundle(handoff, result, engine)

    def test_kind_must_match_the_handoff(self, engine, planted, props):
        from services.sandbox_poc.review_bundle import build_review_bundle
        handoff, result = self._bundle_inputs(engine, planted, props)
        with pytest.raises(ContractError, match="fix kind differs"):
            build_review_bundle(handoff, {**result, "kind": "setting"}, engine)
