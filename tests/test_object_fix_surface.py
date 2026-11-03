"""Wave 2a (F6): template allowlist, schemas for every template, API wiring and
the HERMES/MCP boundary for per-object fixes. Unit level, no Docker or registry.
"""
from __future__ import annotations

import copy
import hashlib
import inspect
import re

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.main import app
from app.services import template_service
from app.services.snapshot_service import SnapshotStore
from services.sandbox_poc import object_fixes as of
from services.sandbox_poc import router as routes
from services.sandbox_poc import templates as tpl
from services.sandbox_poc.handoff import (OBJECT_TEMPLATE_NAMES, SandboxHandoff, TemplateReference,
                                          build_handoff)
from services.sandbox_poc.planning import recommend_order
from services.sandbox_poc.service import SandboxService
from services.sandbox_poc.shared import ROOT, ContractError
from services.sandbox_poc.templates import ApprovedTemplate
from services.sandbox_poc.upstream import AlternativeTemplate, PrepareRequest, prepare_uploaded
from test_review_bundle import recorded, collector  # noqa: F401  (shared fixtures)
from test_sandbox_poc import engine, snapshot  # noqa: F401

TEMPLATE_DIR = ROOT / "backend/app/templates"
OBJECT_NAMES = set(OBJECT_TEMPLATE_NAMES)
EVIDENCE = [{"document_id": "unit-doc", "version": "1", "sha256": "b" * 64}]


def approved(name):
    sql = (TEMPLATE_DIR / f"{name}.sql.j2").read_text()
    return ApprovedTemplate(name, 1, sql, hashlib.sha256(sql.encode()).hexdigest(), "Unit Reviewer",
                            ({"document_id": "unit-doc"},))


def ref(name, version=1):
    sha = hashlib.sha256(name.encode()).hexdigest()  # identity only; content is not read here
    return TemplateReference(registry_name=name, version=version, sha256=sha,
                             evidence=EVIDENCE, environment="test")


# ---------------------------------------------------------------------------
# Every template has a strict schema; no schema means no render
# ---------------------------------------------------------------------------

class TestTemplateSchemas:
    def test_every_template_file_has_a_parameter_schema(self):
        names = {p.name.removesuffix(".sql.j2") for p in TEMPLATE_DIR.glob("*.sql.j2")}
        assert OBJECT_NAMES <= names
        assert names <= set(template_service.TEMPLATE_PARAM_SCHEMAS), names - set(template_service.TEMPLATE_PARAM_SCHEMAS)

    def test_every_schema_forbids_extra_parameters(self):
        for name, schema in template_service.TEMPLATE_PARAM_SCHEMAS.items():
            assert schema.model_config.get("extra") == "forbid", name

    def test_object_schemas_are_strict(self):
        for name in OBJECT_NAMES:
            assert template_service.TEMPLATE_PARAM_SCHEMAS[name].model_config.get("strict") is True, name

    def test_a_template_without_a_schema_is_refused(self):
        ok, params, error = template_service.validate_params("no_such_template", {"anything": "DROP TABLE x"})
        assert (ok, params) == (False, {}) and "No reviewed parameter schema" in error
        ok, sql, error = template_service.safe_render_template("no_such_template", "SELECT {{ x }};", {"x": "1"})
        assert not ok and sql == ""

    def test_existing_templates_still_render_with_their_schemas(self):
        ok, sql, _ = template_service.safe_render_template(
            "create_read_only_rule", (TEMPLATE_DIR / "create_read_only_rule.sql.j2").read_text(),
            {"role_name": "auditor", "database_name": "appdb"})
        assert ok and 'CREATE ROLE "auditor" WITH LOGIN;' in sql and 'SCHEMA "public"' in sql
        ok, sql, _ = template_service.safe_render_template(
            "revoke_public_access", (TEMPLATE_DIR / "revoke_public_access.sql.j2").read_text(), {})
        assert ok and 'REVOKE ALL ON SCHEMA "public" FROM PUBLIC;' in sql
        ok, _, _ = template_service.validate_params("revoke_public_access", {"schema_name": "a\nb"})
        assert not ok

    def test_pg_int_filter_refuses_non_integers(self):
        assert template_service.pg_int(5) == "5"
        for bad in (True, "5", 5.0, None):
            with pytest.raises(ValueError):
                template_service.pg_int(bad)


# ---------------------------------------------------------------------------
# Reviewed template-name allowlist (templates.py, handoff.py, upstream.py)
# ---------------------------------------------------------------------------

class TestTemplateAllowlist:
    ALLOWED = ["set_config_parameter", "set_config_parameter__log_connections_v2", *sorted(OBJECT_NAMES)]
    REFUSED = ["create_read_only_rule", "revoke_public_access", "role_nologin__v2", "role_nologinx",
               "ROLE_NOLOGIN", "set_config", "", "role_nologin; DROP"]

    @pytest.mark.parametrize("name", ALLOWED)
    def test_template_reference_accepts_the_reviewed_names(self, name):
        assert TemplateReference(registry_name=name, version=1, sha256="a" * 64, evidence=EVIDENCE)

    @pytest.mark.parametrize("name", REFUSED)
    def test_template_reference_refuses_others(self, name):
        with pytest.raises(ValidationError):
            TemplateReference(registry_name=name, version=1, sha256="a" * 64, evidence=EVIDENCE)

    @pytest.mark.parametrize("name", REFUSED)
    def test_registry_reads_refuse_unlisted_names_before_connecting(self, monkeypatch, name):
        import psycopg2
        monkeypatch.setattr(psycopg2, "connect", lambda *a, **k: pytest.fail("registry was contacted"))
        with pytest.raises(ContractError, match="allowlist"):
            tpl.from_registry("postgresql://unused", 1, "a" * 64, ["doc"], registry_name=name)
        with pytest.raises(ContractError, match="allowlist"):
            tpl.export_reference("postgresql://unused", 1, ["doc"], registry_name=name)

    def test_setting_render_is_unchanged_and_refuses_object_names(self):
        sql = approved("set_config_parameter").render("log_connections", "on")
        assert "ALTER SYSTEM SET \"log_connections\" = 'on';" in sql
        with pytest.raises(ContractError, match="Unsupported template identity"):
            approved("role_nologin").render("log_connections", "on")

    def test_render_object_refuses_setting_and_unknown_names(self):
        with pytest.raises(ContractError, match="Unsupported template identity"):
            approved("set_config_parameter").render_object({"role_name": "x", "action": "apply"})
        rogue = approved("create_read_only_rule")
        with pytest.raises(ContractError, match="Unsupported template identity"):
            rogue.render_object({"role_name": "x"})

    def test_render_object_validates_params_with_the_schema(self):
        template = approved("role_nologin")
        assert 'ALTER ROLE "x" NOLOGIN;' in template.render_object({"role_name": "x", "action": "apply"})
        for bad in ({"role_name": "x"}, {"role_name": "x", "action": "apply", "sql": "DROP"},
                    {"role_name": "", "action": "apply"}):
            with pytest.raises(ContractError):
                template.render_object(bad)

    @pytest.mark.parametrize("name", sorted(OBJECT_NAMES) + ["set_config_parameter"])
    def test_probe_renders_each_approved_template(self, name):
        approved(name).probe()

    def test_alternative_templates_stay_setting_only(self):
        with pytest.raises(ValidationError):
            AlternativeTemplate(registry_name="role_nologin", version=1)


# ---------------------------------------------------------------------------
# Handoff shape: object_fix_id binds the template; no adaptive retries
# ---------------------------------------------------------------------------

FIX_ID = "fix-4.4-role_nologin-0123456789"


def handoff_fields(**over):
    base = {"schema_version": "sandbox-handoff-v1", "benchmark_id": "cis-pg17-v1.1.0", "spec_set_hash": "c" * 64,
            "specs": [{}], "snapshot": {}, "assessment": {}, "template_ref": ref("role_nologin").model_dump(),
            "control_id": "cis-pg17-v1.1.0:4.4", "object_fix_id": FIX_ID}
    base.update(over)
    return base


class TestHandoffShape:
    def test_object_handoff_accepted(self):
        assert SandboxHandoff.model_validate(handoff_fields()).object_fix_id == FIX_ID

    @pytest.mark.parametrize("over", [
        {"object_fix_id": None},                                            # object template, no id
        {"template_ref": ref("role_drop_attribute").model_dump()},          # template of another type
        {"template_ref": ref("set_config_parameter").model_dump()},
        {"retry_mode": "adaptive"},
        {"retry_template_refs": [ref("set_config_parameter__alt").model_dump()]},
        {"object_fix_id": "fix-4.4-role_nologin-012345678"},
        {"object_fix_id": "fix-log_connections"},
        {"object_fix_id": FIX_ID + "\n"},
        {"unexpected": 1},
    ])
    def test_object_handoff_refusals(self, over):
        with pytest.raises(ValidationError):
            SandboxHandoff.model_validate(handoff_fields(**over))

    def test_setting_handoff_is_unchanged(self):
        assert SandboxHandoff.model_validate(handoff_fields(object_fix_id=None, control_id="cis-pg17-v1.1.0:3.1.20",
                                                            template_ref=ref("set_config_parameter").model_dump()))

    def test_prepare_request_is_strict(self):
        common = {"snapshot_id": "snap-abc", "template_version": 1, "evidence_ids": ["d"]}
        assert PrepareRequest(**common, object_fix_id=FIX_ID).object_fix_id == FIX_ID
        for bad in ({"object_fix_id": "fix-4.4-role_nologin-xyz"}, {"object_fix_id": 5},
                    {"object_target": {"role": "web"}}, {"params": {"connection_limit": 1}}):
            with pytest.raises(ValidationError):
                PrepareRequest(**common, **bad)

    def test_exported_contract_matches_the_model(self):
        import json
        expected = SandboxHandoff.model_json_schema()
        expected["$schema"] = "https://json-schema.org/draft/2020-12/schema"
        assert json.loads((ROOT / "catalog/specs/contracts/sandbox-handoff-v1.json").read_text()) == expected


# ---------------------------------------------------------------------------
# Ordering and batch uniqueness are keyed by fix id
# ---------------------------------------------------------------------------

def review(fix_id, fix_type=None, target=None, setting=None, risk="high"):
    return {"fix_id": fix_id, "setting": setting, "fix_type": fix_type, "target": target,
            "operational_risk": risk, "dependencies": []}


class TestOrdering:
    def test_several_object_fixes_for_one_control(self):
        fixes = [review("fix-4.3-role_drop_attribute-aaaaaaaaaa", "role_drop_attribute", {"role": "a", "attribute": "CREATEDB"}),
                 review("fix-4.3-role_drop_attribute-bbbbbbbbbb", "role_drop_attribute", {"role": "a", "attribute": "CREATEROLE"}),
                 review("fix-log_connections", setting="log_connections", risk="medium")]
        assert [f["fix_id"] for f in recommend_order(fixes)][0] == "fix-log_connections"

    def test_the_same_change_under_two_controls_is_refused(self):
        target = {"role": "su2", "attribute": "SUPERUSER"}
        with pytest.raises(ContractError, match="same object change"):
            recommend_order([review("fix-4.3-role_drop_attribute-aaaaaaaaaa", "role_drop_attribute", target),
                             review("fix-4.9-role_drop_attribute-aaaaaaaaaa", "role_drop_attribute", target)])

    def test_settings_keep_their_uniqueness_rule(self):
        with pytest.raises(ContractError, match="same setting"):
            recommend_order([review("fix-a", setting="log_connections"), review("fix-b", setting="log_connections")])

    def test_batch_request_unique_per_fix(self):
        common = {"snapshot_id": "snap-abc", "template_version": 1, "evidence_ids": ["d"]}
        two = [PrepareRequest(**common, object_fix_id="fix-4.3-role_drop_attribute-aaaaaaaaaa"),
               PrepareRequest(**common, object_fix_id="fix-4.3-role_drop_attribute-bbbbbbbbbb")]
        assert routes.BatchRequest(fixes=two)
        with pytest.raises(ValidationError):
            routes.BatchRequest(fixes=[two[0], two[0]])
        with pytest.raises(ValidationError):
            routes.BatchRequest(fixes=[PrepareRequest(**common), PrepareRequest(**common)])


# ---------------------------------------------------------------------------
# API wiring: fix plan, prepare, run (sandbox loop stubbed)
# ---------------------------------------------------------------------------

def planted(bundle):
    base = bundle["baseline"]
    row = {"is_predefined": False, "rolbypassrls": False, "rolcanlogin": True, "rolconnlimit": -1,
           "rolcreatedb": True, "rolcreaterole": False, "rolinherit": True, "rolreplication": False,
           "rolsuper": False, "rolvaliduntil": None}
    base["roles"] = base["roles"] + [{**row, "rolname": "web", "oid": "16385"}]
    base["password_types"] = base["password_types"] + [{"rolname": "web", "password_type": "none"}]
    return bundle


@pytest.fixture
def client(tmp_path, monkeypatch):
    store = SnapshotStore(tmp_path)
    monkeypatch.setattr("app.main.snapshot_store", store)
    app.dependency_overrides[routes.get_snapshot_store] = lambda: store
    app.dependency_overrides[routes.get_service] = lambda: SandboxService("unused")
    with TestClient(app) as c:
        c.store = store
        yield c
    app.dependency_overrides.clear()


def upload(client, bundle):
    response = client.post("/api/v1/snapshots", json=bundle)
    assert response.status_code == 201, response.text
    return response.json()["snapshot_id"]


class TestApi:
    def test_fix_plan_lists_object_proposals_grouped_by_spec(self, client, recorded):
        sid = upload(client, planted(collector(recorded)))
        plan = client.get(f"/api/v1/snapshots/{sid}/fix-plan").json()
        groups = {g["spec_id"]: g for g in plan["object_proposals"]}
        web = [p for g in groups.values() for p in g["proposals"] if p["target"].get("role") == "web"]
        assert {(p["spec_id"], p["fix_type"]) for p in web} == {
            ("cis-pg17-v1.1.0:4.3", "role_drop_attribute"), ("cis-pg17-v1.1.0:4.4", "role_nologin"),
            ("cis-pg17-v1.1.0:4.10", "role_nologin")}
        assert groups["cis-pg17-v1.1.0:5.5"]["notes"][-1]["code"] == "policy_missing"
        assert plan["recommended_order"]  # setting fixes unchanged
        assert all(m.get("kind") == "catalog" for m in plan["manual_review"] if m["spec_id"] in groups)

    def test_fix_plan_lists_the_approved_template_version_per_fix_type(self, client, recorded, monkeypatch):
        versions = {"role_nologin": 3, "role_drop_attribute": 2}
        monkeypatch.setattr("services.sandbox_poc.templates.approved_object_template_versions",
                            lambda url: {**dict.fromkeys(versions), **versions} if url == "unused" else {})
        sid = upload(client, planted(collector(recorded)))
        plan = client.get(f"/api/v1/snapshots/{sid}/fix-plan").json()
        proposals = [p for g in plan["object_proposals"] for p in g["proposals"]]
        # One version per offered fix type, beside the proposals (which stay exactly resolve()'s output).
        assert proposals and plan["object_template_versions"] == {"role_nologin": 3, "role_drop_attribute": 2}
        assert all("template_version" not in p for p in proposals)

    def test_fix_plan_template_version_is_null_when_the_registry_is_unavailable(self, client, recorded):
        sid = upload(client, planted(collector(recorded)))  # registry DSN "unused" cannot connect
        response = client.get(f"/api/v1/snapshots/{sid}/fix-plan")
        assert response.status_code == 200
        plan = response.json()
        types = {p["fix_type"] for g in plan["object_proposals"] for p in g["proposals"]}
        assert types and plan["object_template_versions"] == dict.fromkeys(sorted(types))

    def _prepare(self, client, recorded, monkeypatch, **request):
        sid = upload(client, planted(collector(recorded)))
        plan = client.get(f"/api/v1/snapshots/{sid}/fix-plan").json()
        fix = next(p for g in plan["object_proposals"] for p in g["proposals"]
                   if p["fix_type"] == "role_nologin" and p["spec_id"].endswith(":4.10"))
        seen = {}

        def export(url, version, evidence_ids, environment="dev", *, registry_name="set_config_parameter"):
            seen["registry_name"] = registry_name
            return ref(registry_name, version), approved(registry_name)
        monkeypatch.setattr("services.sandbox_poc.upstream.export_reference", export)
        body = {"snapshot_id": sid, "template_version": 1, "evidence_ids": ["unit-doc"],
                "object_fix_id": fix["fix_id"], **request}
        return fix, seen, PrepareRequest.model_validate(body)

    def test_prepare_resolves_the_id_server_side(self, client, recorded, monkeypatch):
        fix, seen, request = self._prepare(client, recorded, monkeypatch)
        handoff = prepare_uploaded(client.store, SandboxService("unused"), request)
        assert seen["registry_name"] == "role_nologin"
        assert (handoff.object_fix_id, handoff.control_id, handoff.retry_mode) == (
            fix["fix_id"], "cis-pg17-v1.1.0:4.10", "repeat")
        assert handoff.template_ref.registry_name == "role_nologin"

    @pytest.mark.parametrize("extra", [{"control_id": "cis-pg17-v1.1.0:4.4"},
                                       {"alternative_templates": [{"registry_name": "set_config_parameter__x", "version": 1}]},
                                       {"retry_template_versions": [2]}, {"retry_mode": "adaptive"}])
    def test_prepare_refusals(self, client, recorded, monkeypatch, extra):
        _, _, request = self._prepare(client, recorded, monkeypatch, **extra)
        with pytest.raises(ContractError):
            prepare_uploaded(client.store, SandboxService("unused"), request)

    def test_prepare_refuses_a_forged_id(self, client, recorded, monkeypatch):
        _, _, request = self._prepare(client, recorded, monkeypatch)
        forged = request.model_copy(update={"object_fix_id": "fix-4.10-role_nologin-0123456789"})
        with pytest.raises(ContractError, match="Unknown object fix id"):
            prepare_uploaded(client.store, SandboxService("unused"), forged)

    def test_prepare_endpoint_refuses_forged_ids(self, client, recorded):
        sid = upload(client, planted(collector(recorded)))
        response = client.post("/api/v1/sandbox/handoffs", json={
            "snapshot_id": sid, "template_version": 1, "evidence_ids": ["d"],
            "object_fix_id": "fix-4.10-role_nologin-0123456789"})
        assert response.status_code == 422

    def test_service_runs_the_object_loop_with_the_resolved_proposal(self, client, recorded, monkeypatch):
        fix, _, request = self._prepare(client, recorded, monkeypatch)
        handoff = prepare_uploaded(client.store, SandboxService("unused"), request)
        calls = {}

        class FakeLoop:
            def __init__(self, engine, template, proposal, runtime_factory=None):
                calls.update(template=template, proposal=proposal, runtime_factory=runtime_factory)

            def run(self, snapshot, assessment):
                calls["snapshot"] = snapshot
                return {"status": "VERIFIED", "fix_unit": {"fix_id": proposal_id()}}

        def proposal_id():
            return calls["proposal"]["fix_id"]
        monkeypatch.setattr("services.sandbox_poc.workflow.ObjectRemediationLoop", FakeLoop)
        factory = object()
        service = SandboxService("unused", registry_loader=lambda *a, **k: approved(k.get("registry_name")),
                                 runtime_factory=factory)
        result = service.run(handoff)
        assert calls["proposal"] == fix and calls["template"].registry_name == "role_nologin"
        assert calls["runtime_factory"] is factory
        assert result["status"] == "VERIFIED" and result["requires_dba_review"] is True and result["run_id"]

    def test_validate_handoff_refuses_a_tampered_id_or_control(self, client, recorded, monkeypatch):
        _, _, request = self._prepare(client, recorded, monkeypatch)
        handoff = prepare_uploaded(client.store, SandboxService("unused"), request)
        data = handoff.model_dump()
        for change in ({"object_fix_id": "fix-4.10-role_nologin-0123456789"},
                       {"control_id": "cis-pg17-v1.1.0:4.4"}):
            with pytest.raises(ContractError):
                SandboxService("unused").validate_handoff(SandboxHandoff.model_validate({**data, **change}))


# ---------------------------------------------------------------------------
# HERMES/MCP cannot reach object fixes
# ---------------------------------------------------------------------------

def _tool(module, name):
    fn = getattr(module, name)
    return getattr(fn, "fn", fn)


class TestMcpBoundary:
    @pytest.fixture
    def server(self):
        import importlib
        return importlib.import_module("services.dbguard_mcp.server")

    def test_prepare_tool_has_no_object_fix_parameter(self, server):
        params = set(inspect.signature(_tool(server, "prepare_sandbox_handoff")).parameters)
        assert "object_fix_id" not in params and not any("object" in p for p in params)

    def test_prepare_tool_never_sends_an_object_fix_id(self, server, monkeypatch):
        sent = {}
        monkeypatch.setattr(server, "_request_for", lambda backend, method, path, **kw: sent.update(kw) or {})
        _tool(server, "prepare_sandbox_handoff")("snap-abc", 1, ["d"], "test",
                                                 alternative_templates=[{"registry_name": "role_nologin", "version": 1}])
        assert "object_fix_id" not in sent["json"]
        # The alternative names it can send are setting templates only.
        with pytest.raises(ValidationError) as refused:
            PrepareRequest.model_validate(sent["json"])
        assert {e["loc"][0] for e in refused.value.errors()} == {"alternative_templates"}

    def test_render_endpoint_refuses_object_templates(self, client):
        for name in sorted(OBJECT_NAMES):
            response = client.post("/api/v1/proposals/validate-and-render", json={
                "snapshot_id": "snap-missing", "environment": "test",
                "proposal": {"control_id": "CIS-4.4", "template_id": name,
                             "parameters": {"role_name": "postgres", "action": "apply"},
                             "reasoning": "lock the account", "evidence_refs": []}})
            assert response.status_code == 422, (name, response.text)
            assert "Per-object fix templates" in response.json()["detail"]

    def test_object_template_names_match_the_render_refusal_set(self):
        assert template_service.OBJECT_FIX_TEMPLATES == OBJECT_NAMES == set(of.FIX_TYPES)


class TestApprovedTemplateVersions:
    def test_read_only_lookup_of_the_highest_active_approved_version(self, monkeypatch):
        from services.sandbox_poc import templates
        seen = {}

        class Cursor:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def execute(self, sql, params=None): seen.setdefault("sql", []).append((sql, params))
            def fetchall(self): return [("role_nologin", 4), ("table_revoke_dml", 1)]

        class Conn:
            def set_session(self, **kw): seen["session"] = kw
            def cursor(self): return Cursor()
            def close(self): seen["closed"] = True

        monkeypatch.setattr("psycopg2.connect", lambda url, connect_timeout: Conn())
        versions = templates.approved_object_template_versions("registry")
        assert versions == {**dict.fromkeys(templates.OBJECT_TEMPLATE_NAMES), "role_nologin": 4, "table_revoke_dml": 1}
        assert seen["session"]["readonly"] is True and seen["closed"]
        query, params = seen["sql"][-1]
        assert "status = 'active'" in query and "approved_by IS NOT NULL" in query and "max(version)" in query
        assert params == (sorted(templates.OBJECT_TEMPLATE_NAMES),)
