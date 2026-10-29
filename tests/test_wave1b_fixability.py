"""Wave 1b step 4 (fixability): no_item_in, interpretation, profile fixes and
connection_limits, the profile store, per-setting value rules, the restart
allowlist, fix ordering and NOT_APPLICABLE -> FAIL regressions.

No Docker, network or model. Approved profiles here are in-memory/tmp test
objects; the repository profile is never written.
"""
import copy
import hashlib
import json
from pathlib import Path
from types import SimpleNamespace

import jsonschema
import pytest
import yaml
from pydantic import ValidationError

from app.models import SetConfigTemplateParams
from app.services.policy_profile_store import (
    PolicyProfileStore,
    ProfileNotFoundError,
    ProfileStoreError,
    validate_approver_name,
)
from app.services.setting_values import (
    GLOBAL_FORBIDDEN,
    SETTING_VALUE_RULES,
    SettingValueError,
    check_setting_value,
)
from app.services.spec_engine import RecordsIndex, load_spec, validate_spec
from app.services.spec_engine.operators import evaluate, guc_list_items, no_item_in
from app.services.spec_engine.policy import (
    PolicyProfileError,
    default_profile_path,
    parse_profile,
    profile_value_errors,
    site_fix,
)
from scripts.sandbox_poc import demo_template
from services.sandbox_poc import planning
from services.sandbox_poc.planning import (
    FROM_PROFILE,
    POLICIES,
    SITE_FIX_MISSING,
    fix_scope,
    grounding,
    manual_fix_reference,
    recommend_order,
    risk_review,
)
from services.sandbox_poc.provenance import RESTART_SETTINGS, reconstruction_plan, setting_rows
from services.sandbox_poc.shared import ROOT, ContractError, SpecEngine, is_regression
from services.sandbox_poc.workflow import template_action
from test_sandbox_poc import engine, snapshot  # noqa: F401  shared fixtures

B = "cis-pg17-v1.1.0"
RECORDS = RecordsIndex.load(ROOT / f"catalog/benchmarks/{B}/records.json")
SPECS = [load_spec(p) for p in sorted((ROOT / f"catalog/specs/{B}").glob("*.yaml"))]
SPEC_SCHEMA = json.loads((ROOT / "catalog/specs/schema.json").read_text())


def spec_of(spec_id, specs=SPECS):
    return copy.deepcopy(next(s for s in specs if s["spec_id"] == spec_id))


def listen_spec():
    spec = spec_of(f"{B}:5.2")
    spec["check"]["operator"] = "no_item_in"
    return spec


def profile_doc(approved_by=None, approved_at=None, **extra):
    doc = {"profile_id": "test-profile", "benchmark": B, "approved_by": approved_by,
           "approved_at": approved_at, "values": {}}
    doc.update(extra)
    return doc


def profile(approved=True, **extra):
    doc = profile_doc("Test Reviewer" if approved else None, "2026-10-30" if approved else None, **extra)
    return parse_profile(yaml.safe_dump(doc).encode(), RECORDS)


# ---------------------------------------------------------------------------
# 1. no_item_in (listen_addresses, PG17 SplitGUCList)
# ---------------------------------------------------------------------------

class TestNoItemIn:
    BAD = ["*", "0.0.0.0"]

    @pytest.mark.parametrize("actual", ["*", "*, 10.0.0.1", " *", "0.0.0.0,10.1.1.1", '"*"',
                                        "10.0.0.1 ,\t*", "localhost,0.0.0.0"])
    def test_fails_if_any_entry_is_forbidden(self, actual):
        assert no_item_in(actual, self.BAD, setting_name="listen_addresses") is False

    @pytest.mark.parametrize("actual", ["localhost", "10.0.0.5", "", "   ", "localhost, 10.0.0.5",
                                        "::1", "db.example.com"])
    def test_passes_when_no_entry_is_forbidden(self, actual):
        assert no_item_in(actual, self.BAD, setting_name="listen_addresses") is True

    # "0.0.0.01" used to PASS (compared exactly); since the db-security-reviewer WARN on 5.2
    # a non-standard numeric form (glibc reads 0.0.0.01 as 0.0.0.1, 0.0.0.00 as 0.0.0.0) is
    # never assessed: it raises -> ERROR, never PASS.
    @pytest.mark.parametrize("actual", ['"*', "10.0.0.1 10.0.0.2", ",", "a,,b", "a,", "*;DROP",
                                        "a'b", "a\x00b", "(local)", '"a b"', "0.0.0.01"])
    def test_garbage_raises_never_passes(self, actual):
        with pytest.raises(ValueError):
            no_item_in(actual, self.BAD, setting_name="listen_addresses")

    def test_parser_follows_splitguclist(self):
        with pytest.raises(ValueError):  # '""' is a literal quote, not an address character
            guc_list_items('"a""b"', "listen_addresses")
        assert guc_list_items(" localhost ,  10.0.0.1", "listen_addresses") == ["localhost", "10.0.0.1"]
        assert guc_list_items('"localhost"', "listen_addresses") == ["localhost"]

    def test_unreviewed_setting_raises(self):
        with pytest.raises(ValueError):
            no_item_in("a", ["a"], setting_name="log_destination")

    def test_evaluate_and_spec_validation(self):
        spec = listen_spec()
        assert validate_spec(spec, RECORDS) == []
        jsonschema.validate(spec, SPEC_SCHEMA)
        assert evaluate(spec["check"], "*, 10.0.0.1") is False
        with pytest.raises(ValueError):
            evaluate(spec["check"], "garbage value")
        wrong = copy.deepcopy(spec)
        wrong["check"].update(setting_name="log_destination", query="SHOW log_destination")
        assert any("no reviewed list grammar" in e for e in validate_spec(wrong, RECORDS))

    def test_assessment_gives_error_not_pass_on_garbage(self):
        from test_spec_engine_wave1b import entry, run
        spec = listen_spec()
        for value, expected in (("*, 10.0.0.1", "FAIL"), ("localhost", "PASS"), ('"*', "ERROR")):
            row = run([spec], {spec["spec_id"]: entry(spec, result=value)})["results"][0]
            assert row["result"] == expected, value


# ---------------------------------------------------------------------------
# 2. interpretation
# ---------------------------------------------------------------------------

class TestInterpretation:
    def test_allowed_on_any_tier_and_hashed(self):
        from app.services.spec_engine import spec_sha256
        for spec_id in (f"{B}:5.2", f"{B}:3.1.2", f"{B}:7.2", f"{B}:6.10"):
            spec = spec_of(spec_id)
            before = spec_sha256(spec)
            spec["interpretation"] = ["DBGuard fails any listed address that is all interfaces."]
            assert validate_spec(spec, RECORDS) == [], spec_id
            jsonschema.validate(spec, SPEC_SCHEMA)
            assert spec_sha256(spec) != before

    @pytest.mark.parametrize("value", [[], "one sentence", [""], ["  "], [1],
                                       ["SELECT 1 is how it is checked"], ["a; b"], ["line\nbreak"],
                                       ["uses ```code```"], ["x" * 601], ["same", "same"]])
    def test_rejected(self, value):
        spec = spec_of(f"{B}:5.2")
        spec["interpretation"] = value
        assert validate_spec(spec, RECORDS)


# ---------------------------------------------------------------------------
# 3a/3b. profile fixes and connection_limits
# ---------------------------------------------------------------------------

class TestProfileExtensions:
    def test_fix_must_satisfy_operator_and_value_rule(self):
        specs = [listen_spec()]
        assert profile_value_errors(profile(fixes={f"{B}:5.2": "localhost"}), specs) == []
        assert profile_value_errors(profile(fixes={f"{B}:5.2": "localhost, 10.0.0.5"}), specs) == []
        # "10.0.0.5" alone: Gate 1 ruling on 5.2 requires localhost in the fix value
        for bad in ("*", "10.0.0.5, 0.0.0.0", "10.0.0.5'; SELECT 1", "::", "10.0.0.5"):
            assert profile_value_errors(profile(fixes={f"{B}:5.2": bad}), specs), bad

    def test_fix_only_for_automated_literal_specs(self):
        errors = profile_value_errors(profile(fixes={f"{B}:3.1.2": "stderr"}), [spec_of(f"{B}:3.1.2")])
        assert any("only for automated" in e for e in errors)
        with pytest.raises(PolicyProfileError, match="takes its fix from values"):
            profile(values={f"{B}:3.1.2": {"expected": ["stderr"], "fix": "stderr", "break": "csvlog"}},
                    fixes={f"{B}:3.1.2": "stderr"})

    def test_site_fix_needs_approval(self):
        spec = listen_spec()
        assert site_fix(spec, profile(fixes={f"{B}:5.2": "localhost, 10.0.0.5"})) == "localhost, 10.0.0.5"
        assert site_fix(spec, profile(approved=False, fixes={f"{B}:5.2": "localhost, 10.0.0.5"})) is None
        assert site_fix(spec, None) is None

    def test_connection_limits(self):
        ok = profile(connection_limits={"default_login_limit": 20, "roles": {"app_user": 50, "Report_1": 0}})
        assert ok.connection_limits["roles"]["app_user"] == 50
        assert profile(connection_limits={"default_login_limit": None, "roles": {}}).connection_limits
        for bad in ({"default_login_limit": -1, "roles": {}}, {"default_login_limit": True, "roles": {}},
                    {"default_login_limit": 1.5, "roles": {}}, {"default_login_limit": 1, "roles": {"a": -1}},
                    {"default_login_limit": 1, "roles": {"pg_monitor": 1}},
                    {"default_login_limit": 1, "roles": {"bad name": 1}},
                    {"default_login_limit": 1, "roles": {"x" * 64: 1}},
                    {"default_login_limit": 1, "roles": {"a;drop": 1}},
                    {"roles": {}}, {"default_login_limit": 1, "roles": {}, "extra": 1}, [1]):
            with pytest.raises(PolicyProfileError):
                profile(connection_limits=bad)

    def test_repository_profile_still_loads(self):
        from app.services.spec_engine.policy import load_default_profile
        seed = load_default_profile(RECORDS)
        assert seed is not None and seed.approved_by is None
        assert profile_value_errors(seed, SPECS, strict=True) == []


# ---------------------------------------------------------------------------
# 3a. fix_scope / fix plan for site-specific and policy fixes
# ---------------------------------------------------------------------------

def _engine(specs, policy=None):
    return SimpleNamespace(specs=specs, policy=policy, records=RECORDS,
                           policy_pin=policy.pin() if policy else None)


class TestFixScopeFromProfile:
    def test_5_2_has_no_fix_without_an_approved_value(self):
        spec = listen_spec()
        for policy in (None, profile(approved=False, fixes={f"{B}:5.2": "10.0.0.5"}), profile()):
            with pytest.raises(ContractError, match=SITE_FIX_MISSING):
                fix_scope(_engine([spec], policy), spec["spec_id"])
        manual = manual_fix_reference(_engine([spec]), spec)
        assert manual["cis_recommendation"] == "5.2"
        assert "listen_addresses" in manual["remediation_procedure"]

    def test_5_2_fix_from_approved_profile(self):
        spec = listen_spec()
        _, name, value = fix_scope(_engine([spec], profile(fixes={f"{B}:5.2": "localhost, 10.0.0.5"})),
                                   spec["spec_id"])
        assert (name, value) == ("listen_addresses", "localhost, 10.0.0.5")
        assert POLICIES["listen_addresses"][:2] == (FROM_PROFILE, "high")

    def test_policy_spec_fix_comes_from_profile_values(self):
        spec = spec_of(f"{B}:3.1.4")
        values = {f"{B}:3.1.4": {"expected": "/var/log/postgresql", "fix": "/var/log/postgresql", "break": "log"}}
        with pytest.raises(ContractError, match="policy_missing"):
            fix_scope(_engine([spec], profile(approved=False, values=values)), spec["spec_id"])
        _, name, value = fix_scope(_engine([spec], profile(values=values)), spec["spec_id"])
        assert (name, value) == ("log_directory", "/var/log/postgresql")

    def test_every_policy_and_site_setting_is_marked_from_profile(self):
        for spec in SPECS:
            check = spec.get("check") or {}
            name = check.get("setting_name")
            if name in POLICIES and spec["tier"] == "parameterised":
                assert POLICIES[name][0] == FROM_PROFILE, name
        assert POLICIES["listen_addresses"][0] == FROM_PROFILE
        # the marker can never be rendered as a value
        for name in POLICIES:
            with pytest.raises(SettingValueError):
                check_setting_value(name, FROM_PROFILE)

    def test_fixed_values_satisfy_their_specs(self):
        engine = _engine(SPECS)
        for spec_id, name, value in ((f"{B}:3.1.14", "log_min_messages", "warning"),
                                     (f"{B}:3.1.15", "log_min_error_statement", "error"),
                                     (f"{B}:3.1.24", "log_line_prefix",
                                      "%m [%p]: [%l-1] db=%d,user=%u,app=%a,client=%h"),
                                     (f"{B}:3.1.3", "logging_collector", "on")):
            assert fix_scope(engine, spec_id)[1:] == (name, value)

    def test_reference_profile_fix_values_work_once_approved(self):
        from app.services.spec_engine.policy import load_default_profile
        seed = load_default_profile(RECORDS)
        doc = yaml.safe_load(default_profile_path(B).read_bytes())
        doc.update(approved_by="Test Reviewer", approved_at="2026-10-30")
        approved = parse_profile(yaml.safe_dump(doc).encode(), RECORDS)
        engine = _engine(SPECS, approved)
        for spec_id, entry in seed.values.items():
            assert fix_scope(engine, spec_id)[2] == entry["fix"], spec_id

    def test_risk_texts(self):
        assert "docker logs goes quiet" in POLICIES["logging_collector"][2]
        assert "must exist and be writable by the postgres" in POLICIES["log_directory"][2]
        text = POLICIES["log_truncate_on_rotation"][2]
        assert "repeats within the rotation period" in text and POLICIES["log_truncate_on_rotation"][1] == "high"


# ---------------------------------------------------------------------------
# 3c. profile store
# ---------------------------------------------------------------------------

@pytest.fixture
def store(tmp_path):
    seed = tmp_path / "seed.yaml"
    seed.write_bytes(default_profile_path(B).read_bytes())
    return PolicyProfileStore(tmp_path / "profiles", RECORDS, SPECS, seed_path=seed)


VALUES = {f"{B}:3.1.2": {"expected": ["stderr"], "fix": "stderr", "break": "csvlog"}}


class TestProfileStore:
    def test_seed_is_listed_read_only(self, store):
        before = store.seed_path.read_bytes()
        [seed] = store.list()
        assert (seed["source"], seed["status"]) == ("seed", "draft")
        assert seed["profile_ref"] == hashlib.sha256(before).hexdigest()
        approved = store.approve(seed["profile_ref"], "Melvin Loo")
        assert store.seed_path.read_bytes() == before  # never written
        assert approved.approved_by == "Melvin Loo" and approved.sha256 != seed["profile_ref"]

    def test_draft_approve_lifecycle(self, store):
        draft = store.create_draft(profile_id="site-a", values=VALUES,
                                   fixes={f"{B}:5.2": "localhost, 10.0.0.5"},
                                   connection_limits={"default_login_limit": 10, "roles": {"app": 5}})
        assert draft.approved_by is None and draft.fixes == {f"{B}:5.2": "localhost, 10.0.0.5"}
        assert store.get(draft.sha256) == draft
        approved = store.approve(draft.sha256, "  Melvin Loo ")
        assert approved.approved and approved.approved_by == "Melvin Loo" and approved.approved_at
        assert approved.sha256 != draft.sha256
        assert approved.values == draft.values and approved.fixes == draft.fixes
        assert store.get(draft.sha256).approved_by is None  # the draft is unchanged
        statuses = {p["profile_ref"]: p["status"] for p in store.list()}
        assert statuses[draft.sha256] == "draft" and statuses[approved.sha256] == "approved"
        with pytest.raises(ProfileStoreError, match="already approved"):
            store.approve(approved.sha256, "Melvin Loo")
        # an edit of an approved profile is a new draft
        edit = store.create_draft(profile_id="site-a", values=VALUES, based_on=approved.sha256)
        assert edit.approved_by is None and edit.sha256 not in (draft.sha256, approved.sha256)

    def test_draft_cannot_carry_approval_and_invalid_drafts_are_refused(self, store):
        with pytest.raises(TypeError):
            store.create_draft(profile_id="x", values=VALUES, approved_by="Melvin Loo")
        with pytest.raises(ProfileStoreError):
            store.create_draft(profile_id="x", values={f"{B}:3.1.2": {"expected": ["stderr"],
                                                                     "fix": "csvlog", "break": "csvlog"}})
        with pytest.raises(ProfileStoreError):
            store.create_draft(profile_id="x", values={}, fixes={f"{B}:5.2": "*"})
        with pytest.raises(ProfileStoreError):
            store.create_draft(profile_id="x", values={f"{B}:9.9": VALUES[f"{B}:3.1.2"]})

    def test_dropped_in_approved_file_is_refused(self, store):
        draft = store.create_draft(profile_id="site-a", values=VALUES)
        forged = yaml.safe_dump(profile_doc("Melvin Loo", "2026-10-30", values=VALUES), sort_keys=True).encode()
        ref = hashlib.sha256(forged).hexdigest()
        (store.root / f"{ref}.yaml").write_bytes(forged)
        with pytest.raises(ProfileStoreError, match="no matching approval record"):
            store.get(ref)
        assert ref not in {p["profile_ref"] for p in store.list()}
        assert draft.sha256 in {p["profile_ref"] for p in store.list()}

    def test_tampered_object_and_bad_refs(self, store):
        draft = store.create_draft(profile_id="site-a", values=VALUES)
        (store.root / f"{draft.sha256}.yaml").write_bytes(b"profile_id: changed\n")
        with pytest.raises(ProfileStoreError, match="does not match its hash"):
            store.get(draft.sha256)
        for bad in ("../x", "0" * 63, "Z" * 64, None):
            with pytest.raises(ProfileNotFoundError):
                store.get(bad)

    @pytest.mark.parametrize("name", ["", "   ", "HERMES", "dbguard agent", "Claude", "LLM reviewer",
                                      "gpt-4o", "x" * 121, "Mel\nvin", "1234", "auto bot"])
    def test_approver_must_be_a_named_human(self, name):
        with pytest.raises(ProfileStoreError):
            validate_approver_name(name)

    def test_approval_is_not_on_the_mcp_surface(self):
        source = (ROOT / "services/dbguard_mcp/server.py").read_text()
        assert "policy-profiles" not in source and "approve" not in source.lower().replace("approved", "")


class TestEngineRecordsProfile:
    def test_default_is_no_profile(self, engine):
        assert engine.policy is None and engine.policy_pin is None

    def test_engine_with_store_profile_pins_it(self, store, snapshot):
        approved = store.approve(store.create_draft(profile_id="site-a", values=VALUES).sha256, "Melvin Loo")
        eng = SpecEngine(SPECS, RECORDS, approved)
        assert eng.policy_pin["sha256"] == approved.sha256
        snap = copy.deepcopy(snapshot)
        snap["envelope"]["manifest"]["sha256"] = eng.manifest_hash
        snap["envelope"]["collector_sha256"] = eng.collector_hash
        report = eng.assess(snap)["upstream_report"]
        assert report["inputs"]["policy_profile"]["sha256"] == approved.sha256


# ---------------------------------------------------------------------------
# 4. per-setting value rules
# ---------------------------------------------------------------------------

GOOD = {
    "log_line_prefix": ["%m [%p]: [%l-1] db=%d,user=%u,app=%a,client=%h", "%m [%p] ", "%t user@%d"],
    "log_filename": ["postgresql-%a.log", "postgresql-%Y-%m-%d_%H%M%S.log"],
    "log_directory": ["/var/log/postgresql", "log", "pg_log/sub", "/srv/pg-logs/"],
    "listen_addresses": ["localhost", "localhost, 10.0.0.5", "10.0.0.5,localhost", "localhost, ::1",
                         "localhost, db-1.example.com"],
    "log_timezone": ["UTC", "GMT", "Etc/UTC", "America/New_York", "Etc/GMT+5"],
    "log_destination": ["stderr", "stderr,csvlog", "csvlog, syslog"],
    "log_file_mode": ["0600", "0640"],
    "log_rotation_age": ["1d", "1h", "60min", "0"],
    "log_rotation_size": ["1GB", "0", "10MB", "512kB"],
    "syslog_ident": ["postgres", "pg-prod_1", "postgres.main", "a" * 63],
}
INJECTIONS = ["x'; SELECT pg_reload_conf(); --", "x\"", "x\\", "x;y", "x\ny", "x\x00", "x--y",
              "x/*y", "$$x$$", "x\r"]
BAD = {
    "log_line_prefix": ["%m (%p)", "%m #%p", "%m\t"],
    "log_filename": ["../postgresql.log", "a/b.log", "a b.log"],
    "log_directory": ["/var/log/../../etc", "..", "a b", "/var/log//x"],
    "listen_addresses": ["*", "::", "a,,b", "-host", "10.0.0.1 10.0.0.2", "10.0.0.5", "::1",
                         "db-1.example.com", "*, localhost", "localhost, 0.0.0.0", "localhost, ::"],
    "log_timezone": ["UTC 1", "/UTC", "1UTC"],
    "log_destination": ["Stderr", "stderr,,csvlog", "stderr;"],
    "log_file_mode": ["600", "0800", "06000", "1777"],
    "log_rotation_age": ["1 d", "1w", "-1", "1.5h"],
    "log_rotation_size": ["1gb", "1 GB", "-1", "1PB"],
    "syslog_ident": ["<from approved policy profile>", "post gres", "pg/prod", "pg:prod", "a" * 64],
}


class TestSettingValueRules:
    def test_table_covers_the_brief(self):
        assert set(GOOD) == set(SETTING_VALUE_RULES) == set(BAD)

    @pytest.mark.parametrize("name", sorted(GOOD))
    def test_good_values_pass_everywhere_and_render_safely(self, name):
        for value in GOOD[name]:
            check_setting_value(name, value)
            assert SetConfigTemplateParams(param_name=name, param_value=value).param_value == value
            sql = demo_template().render(name, value)
            assert f"= '{value}';" in sql
            assert template_action(sql, name) == {"action": "set_config", "param": name, "value": value}

    @pytest.mark.parametrize("name", sorted(GOOD))
    def test_injections_and_bad_values_are_refused_everywhere(self, name):
        for value in [GOOD[name][0] + inj for inj in INJECTIONS] + BAD[name] + [""]:
            with pytest.raises(SettingValueError):
                check_setting_value(name, value)
            with pytest.raises(ValidationError):
                SetConfigTemplateParams(param_name=name, param_value=value)

    def test_template_action_refuses_values_outside_the_rule(self):
        sql = "ALTER SYSTEM SET \"log_line_prefix\" = '%m $1';\nSELECT pg_reload_conf();"
        with pytest.raises(ContractError):
            template_action(sql, "log_line_prefix")
        sql = "ALTER SYSTEM SET \"log_connections\" = 'on--';\nSELECT pg_reload_conf();"
        with pytest.raises(ContractError):
            template_action(sql, "log_connections")

    def test_settings_without_entry_keep_existing_rules(self):
        check_setting_value("log_connections", "on")
        with pytest.raises(SettingValueError):
            check_setting_value("log_connections", "o n")  # legacy [a-zA-Z0-9_.]+
        # models keeps its historical rule (plus the global list) for settings without an entry
        assert SetConfigTemplateParams(param_name="random_page_cost", param_value="1.1")
        for frag in GLOBAL_FORBIDDEN:
            with pytest.raises(ValidationError):
                SetConfigTemplateParams(param_name="log_statement", param_value="ddl" + frag)

    def test_every_reviewed_fixed_value_passes_its_rule(self):
        for name, (value, *_rest) in POLICIES.items():
            if value != FROM_PROFILE:
                check_setting_value(name, value)
                SetConfigTemplateParams(param_name=name, param_value=value)


# ---------------------------------------------------------------------------
# 5. restart allowlist and grounding
# ---------------------------------------------------------------------------

class TestRestartAndGrounding:
    def test_reviewed_restart_set(self):
        assert RESTART_SETTINGS == {"logging_collector", "listen_addresses"}

    def test_reconstruction_accepts_only_reviewed_postmaster_settings(self, engine, snapshot):
        snap = copy.deepcopy(snapshot)
        rows = setting_rows(snap)
        rows["listen_addresses"]["context"] = "postmaster"
        rows["logging_collector"]["context"] = "postmaster"
        reconstruction_plan(snap, engine.specs)
        rows["log_connections"]["context"] = "postmaster"
        with pytest.raises(ContractError, match="unsupported"):
            reconstruction_plan(snap, engine.specs)

    def test_grounding_is_per_setting(self):
        facts, urls = grounding("listen_addresses")
        assert "restart" in facts and urls[-1].endswith("#GUC-LISTEN-ADDRESSES")
        facts, urls = grounding("log_directory")
        assert "writable" in facts and urls[-1].endswith("#GUC-LOG-DIRECTORY")
        assert "log_connections" not in grounding("log_directory")[0]
        for name in POLICIES:
            assert grounding(name)[1][0].endswith("config-setting.html")

    def test_llm_prompt_uses_server_side_grounding(self, monkeypatch):
        sent = {}

        class Resp:
            def raise_for_status(self):
                pass

            def json(self):
                return {"choices": [{"message": {"content": json.dumps(
                    {"risk": "high", "reasoning": "r", "affected_components": [], "prerequisites": [],
                     "unknowns": [], "check_ids": [], "manual_application_checks": []})}}]}

        monkeypatch.setattr(planning.httpx, "post", lambda url, **kw: sent.update(kw) or Resp())
        planning.LLMRiskReviewer("http://x", "m", "")({"setting": "listen_addresses"})
        system = sent["json"]["messages"][0]["content"]
        assert grounding("listen_addresses")[0] in system


# ---------------------------------------------------------------------------
# 7. fix ordering
# ---------------------------------------------------------------------------

class TestFixOrdering:
    def test_collector_first_when_it_is_failing(self, engine, snapshot):
        snap = copy.deepcopy(snapshot)
        rows = setting_rows(snap)
        rows["logging_collector"]["setting"] = "off"
        rows["log_truncate_on_rotation"]["setting"] = "off"
        truncate = risk_review(engine, snap, f"{B}:3.1.7")
        collector = risk_review(engine, snap, f"{B}:3.1.3")
        assert truncate["dependencies"] == ["fix-logging_collector"]
        low = {"fix_id": "fix-log_hostname", "setting": "log_hostname", "operational_risk": "low",
               "dependencies": []}
        order = [f["fix_id"] for f in recommend_order([truncate, low, collector])]
        assert order.index("fix-logging_collector") < order.index("fix-log_truncate_on_rotation")

    def test_no_dependency_when_collector_already_on(self, engine, snapshot):
        snap = copy.deepcopy(snapshot)
        setting_rows(snap)["log_truncate_on_rotation"]["setting"] = "off"
        assert risk_review(engine, snap, f"{B}:3.1.7")["dependencies"] == []

    def test_reviewed_dependency_list(self):
        assert set(planning.FIX_DEPENDENCIES) == {"log_truncate_on_rotation", "log_directory", "log_filename",
                                                  "log_file_mode", "log_rotation_age", "log_rotation_size"}
        assert all(v == ("logging_collector",) for v in planning.FIX_DEPENDENCIES.values())


# ---------------------------------------------------------------------------
# 8. NOT_APPLICABLE -> FAIL is a regression
# ---------------------------------------------------------------------------

class TestNotApplicableRegression:
    @pytest.mark.parametrize("before,after,regressed", [
        ("NOT_APPLICABLE", "FAIL", True), ("NOT_APPLICABLE", "MANUAL_REVIEW", True),
        ("NOT_APPLICABLE", "GAPPED", True), ("NOT_APPLICABLE", "NOT_APPLICABLE", False),
        ("NOT_APPLICABLE", "PASS", False), ("PASS", "FAIL", True), ("PASS", "NOT_APPLICABLE", True),
        ("FAIL", "FAIL", False), ("MANUAL_REVIEW", "FAIL", False), ("PASS", "PASS", False)])
    def test_rule(self, before, after, regressed):
        assert is_regression(before, after) is regressed

    def test_condition_change_in_loop_is_a_regression(self, engine, snapshot):
        """A fix that turns log_destination to syslog makes 3.1.11 applicable and FAILing."""
        from app.services.spec_engine.manifest import condition_check_id
        from test_sandbox_poc import run_fake, FakeRuntime
        snap = copy.deepcopy(snapshot)
        snap["checks"][f"{B}:3.1.11"]["result"] = "off"  # N/A before: stderr only
        assert engine.assess(snap)["findings"][f"{B}:3.1.11"]["status"] == "NOT_APPLICABLE"
        original_sql = FakeRuntime.sql

        def sql(self, script):
            out = original_sql(self, script)
            if "RESET" not in script and self.fault == "syslog":
                for key in (condition_check_id(f"{B}:3.1.10"), condition_check_id(f"{B}:3.1.11"),
                            condition_check_id(f"{B}:3.1.13")):
                    self.snapshot["checks"][key]["result"] = "stderr,syslog"
            return out
        FakeRuntime.sql = sql
        try:
            result, _ = run_fake(engine, snap, ["syslog"])
        finally:
            FakeRuntime.sql = original_sql
        assert result["status"] == "FAILED"
        assert f"{B}:3.1.11" in result["attempts"][0]["regressions"]


class TestProvenanceDuplicates:
    def test_identical_superseded_line_is_not_provenance_but_a_different_value_is(self):
        from services.sandbox_poc.provenance import FILES, signature
        row = {"name": "log_timezone", "setting": "Etc/UTC", "context": "sighup", "source": "configuration file",
               "sourcefile": FILES[0], "pending_restart": False}
        line = {"name": "log_timezone", "setting": "Etc/UTC", "sourcefile": FILES[0], "applied": True, "error": None}
        base = {"baseline": {"settings": [row], "file_settings": [line]}}
        same = {"baseline": {"settings": [row], "file_settings": [{**line, "applied": False}, line]}}
        other = {"baseline": {"settings": [row], "file_settings": [{**line, "applied": False, "setting": "GMT"}, line]}}
        assert signature(same, ["log_timezone"]) == signature(base, ["log_timezone"])
        assert signature(other, ["log_timezone"]) != signature(base, ["log_timezone"])
