"""Tests for JSON Schema validation and fix_unit_validator of contract files.

Tests:
- snapshot-v0.3.0.json schema validates its valid/invalid examples
- fix-unit-v1.json schema validates its examples
- validate_fix_unit enforces cross-field rules (precheck==prior_state, rollback)
- Every spec YAML validates against catalog/specs/schema.json

Conventions:
- Parameterise over files found on disk
- Each test targets exactly one rule, verifies the error message names it
- Schema files themselves must validate as valid JSON Schema (check_schema)
"""
import copy
import json
import re
from pathlib import Path

import jsonschema
import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys_path = str(REPO_ROOT / "backend")
if sys_path not in __import__("sys").path:
    __import__("sys").path.insert(0, sys_path)

from app.services.fix_unit_render import derive_rollback, render_action
from app.services.fix_unit_validator import validate_fix_unit

# ---------------------------------------------------------------------------#
# Schema loaders
# ---------------------------------------------------------------------------#


def load_contract_schema(name: str) -> dict:
    path = REPO_ROOT / "catalog" / "specs" / "contracts" / name
    return json.loads(path.read_text(encoding="utf-8"))


def load_spec_schema() -> dict:
    path = REPO_ROOT / "catalog" / "specs" / "schema.json"
    return json.loads(path.read_text(encoding="utf-8"))


def load_validator(name: str) -> jsonschema.Draft202012Validator:
    if name == "schema.json":
        schema = load_spec_schema()
    else:
        schema = load_contract_schema(name)
    jsonschema.Draft202012Validator.check_schema(schema)
    return jsonschema.Draft202012Validator(schema)


def load_example(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------------------#
# snapshot-v0.3.0.json tests
# ---------------------------------------------------------------------------#

SNAPSHOT_DIR = REPO_ROOT / "tests" / "fixtures" / "phase0"


@pytest.fixture(scope="module")
def snapshot_validator():
    return load_validator("snapshot-v0.3.0.json")


class TestSnapshotSchema:
    """Test snapshot-v0.3.0.json schema and its examples."""

    def test_schema_is_valid_json_schema(self, snapshot_validator):
        """The schema itself validates as a valid JSON Schema."""
        valid = snapshot_validator.is_valid({
            "envelope": {
                "schema_version": "0.2.0",
                "database": "test",
                "target_id": "test"
            },
            "baseline": {},
            "checks": {}
        })
        assert valid

    @pytest.mark.parametrize(
        "path",
        sorted(SNAPSHOT_DIR.glob("snapshot-v0.3.0-valid.json")),
        ids=lambda p: p.name,
    )
    def test_snapshot_valid_example(self, snapshot_validator, path):
        """Valid snapshot example passes validation."""
        assert snapshot_validator.is_valid(load_example(path))

    @pytest.mark.parametrize(
        "path",
        sorted(SNAPSHOT_DIR.glob("snapshot-v0.3.0-invalid-*.json")),
        ids=lambda p: p.name,
    )
    def test_snapshot_invalid_examples(self, snapshot_validator, path):
        """Invalid snapshot examples fail with expected error mentioning rule name."""
        valid = snapshot_validator.is_valid(load_example(path))
        assert not valid, f"{path.name} should fail validation"

        errors = list(snapshot_validator.iter_errors(load_example(path)))

        match = re.search(r"invalid-(.+)\.json$", path.name)
        assert match, f"Filename {path.name} doesn't match expected pattern"
        rule = match.group(1)

        found = False
        for err in errors:
            err_str = str(err)
            field_name = rule.replace("no-", "")
            if field_name.lower() in err_str.lower():
                found = True
                break
        assert found, f"No error mentioned {rule}: {[str(e) for e in errors]}"


# ---------------------------------------------------------------------------#
# fix-unit-v1.json tests
# ---------------------------------------------------------------------------#


@pytest.fixture(scope="module")
def fix_unit_validator():
    return load_validator("fix-unit-v1.json")


@pytest.fixture(scope="module")
def valid_fix_unit():
    return load_example(SNAPSHOT_DIR / "fix-unit-log_connections.json")


class TestFixUnitSchema:
    """Test fix-unit-v1.json schema and its examples."""

    def test_schema_is_valid_json_schema(self, fix_unit_validator):
        """The schema itself validates as a valid JSON Schema."""
        valid_example = load_example(SNAPSHOT_DIR / "fix-unit-log_connections.json")
        assert fix_unit_validator.is_valid(valid_example)

    def test_fix_unit_log_connections_valid(self, fix_unit_validator, valid_fix_unit):
        """The committed fix-unit-log_connections.json is valid."""
        assert fix_unit_validator.is_valid(valid_fix_unit)

    def test_validate_fix_unit_valid_returns_empty(self, valid_fix_unit):
        """Valid fix unit returns no errors from validate_fix_unit."""
        errors = validate_fix_unit(valid_fix_unit)
        assert errors == [], errors

    @pytest.mark.parametrize(
        "path",
        sorted(SNAPSHOT_DIR.glob("fix-unit-invalid-bad-requires.json")),
        ids=lambda p: p.name,
    )
    def test_fix_unit_invalid_bad_requires(self, fix_unit_validator, path):
        """fix-unit-invalid-bad-requires.json fails JSON Schema validation."""
        valid = fix_unit_validator.is_valid(load_example(path))
        assert not valid, f"{path.name} should fail JSON Schema validation"

        errors = list(fix_unit_validator.iter_errors(load_example(path)))
        found = False
        for err in errors:
            if "maybe" in str(err) and "enum" in str(err).lower():
                found = True
                break
        assert found, f"Expected enum violation for 'maybe': {[str(e) for e in errors]}"

    @pytest.mark.parametrize(
        "path",
        sorted(SNAPSHOT_DIR.glob("fix-unit-invalid-missing-rollback.json")),
        ids=lambda p: p.name,
    )
    def test_fix_unit_invalid_missing_rollback(self, fix_unit_validator, path):
        """fix-unit-invalid-missing-rollback.json fails JSON Schema validation."""
        valid = fix_unit_validator.is_valid(load_example(path))
        assert not valid, f"{path.name} should fail JSON Schema validation"

        errors = list(fix_unit_validator.iter_errors(load_example(path)))
        found = False
        for err in errors:
            if "rollback" in str(err) and "required" in str(err).lower():
                found = True
                break
        assert found, f"Expected missing rollback error: {[str(e) for e in errors]}"

    def test_validate_fix_unit_precheck_mismatch(self, valid_fix_unit):
        """precheck.expected_value must equal prior_state.value."""
        bad = copy.deepcopy(valid_fix_unit)
        bad["precheck"]["expected_value"] = "different_value"

        errors = validate_fix_unit(bad)
        assert len(errors) == 1, errors
        assert "precheck.expected_value" in errors[0]
        assert "different_value" in errors[0]
        assert "prior_state.value" in errors[0]
        assert "off" in errors[0]

    def test_derive_rollback_set_config_auto_conf(self, valid_fix_unit):
        """set_config apply with prior from auto.conf -> rollback is set_config(prior.value)."""
        bad = copy.deepcopy(valid_fix_unit)
        bad["prior_state"]["sourcefile"] = "/var/lib/postgresql/data/postgresql.auto.conf"
        bad["rollback"]["action"] = "set_config"
        bad["rollback"]["value"] = "off"  # Must match prior.value

        errors = validate_fix_unit(bad)
        assert errors == [], errors

    def test_derive_rollback_set_config_postgresql_conf(self, valid_fix_unit):
        """set_config apply with prior from postgresql.conf -> rollback is reset_config."""
        bad = copy.deepcopy(valid_fix_unit)
        bad["prior_state"]["sourcefile"] = "/var/lib/postgresql/data/postgresql.conf"

        errors = validate_fix_unit(bad)
        assert errors == [], errors

    def test_derive_rollback_reset_config_auto_conf(self, valid_fix_unit):
        """reset_config apply with prior from auto.conf -> rollback is set_config(prior.value)."""
        # For reset_config, prior must be from auto.conf
        bad = copy.deepcopy(valid_fix_unit)
        bad["prior_state"]["sourcefile"] = "/var/lib/postgresql/data/postgresql.auto.conf"
        bad["apply"] = {"action": "reset_config", "param": "log_connections"}
        bad["rollback"]["action"] = "set_config"
        bad["rollback"]["param"] = "log_connections"
        bad["rollback"]["value"] = "off"  # Prior value to restore

        errors = validate_fix_unit(bad)
        assert errors == [], errors

    def test_derive_rollback_reset_config_non_auto_conf_error(self, valid_fix_unit):
        """reset_config apply with prior not from auto.conf -> error (no-op)."""
        bad = copy.deepcopy(valid_fix_unit)
        bad["apply"] = {"action": "reset_config", "param": "log_connections"}

        errors = validate_fix_unit(bad)
        assert len(errors) == 1, errors
        assert "no valid rollback exists" in errors[0]

    def test_rollback_reset_config_on_different_param_rejected(self, valid_fix_unit):
        """rollback reset_config on different param than apply -> rejected."""
        bad = copy.deepcopy(valid_fix_unit)
        bad["rollback"]["param"] = "log_disconnections"

        errors = validate_fix_unit(bad)
        assert len(errors) == 1, errors
        assert "rollback param 'log_disconnections' does not match apply param 'log_connections'" in errors[0]

    def test_rollback_set_config_when_prior_from_postgresql_conf_rejected(self, valid_fix_unit):
        """rollback set_config when prior from postgresql.conf -> should be reset_config."""
        bad = copy.deepcopy(valid_fix_unit)
        bad["prior_state"]["sourcefile"] = "/var/lib/postgresql/data/postgresql.conf"
        bad["rollback"]["action"] = "set_config"
        bad["rollback"]["value"] = "off"  # This is wrong - should be reset_config

        errors = validate_fix_unit(bad)
        assert len(errors) == 1, errors
        assert "rollback action 'set_config' does not match expected 'reset_config'" in errors[0]

    def test_rollback_value_mismatch(self, valid_fix_unit):
        """'false' rollback vs prior 'off' -> rejected."""
        # Use a case where rollback should be set_config to test value mismatch
        # Prior must be from auto.conf for set_config rollback to be valid
        bad = copy.deepcopy(valid_fix_unit)
        bad["prior_state"]["sourcefile"] = "/var/lib/postgresql/data/postgresql.auto.conf"
        bad["rollback"]["action"] = "set_config"
        bad["rollback"]["value"] = "false"  # Wrong value

        errors = validate_fix_unit(bad)
        assert len(errors) == 1, errors
        assert "rollback value 'false' does not match prior_state.value 'off'" in errors[0]

    def test_set_config_no_op_apply(self, valid_fix_unit):
        """set_config no-op apply (value == prior) -> rejected."""
        # Prior must be from auto.conf for set_config rollback to be valid
        bad = copy.deepcopy(valid_fix_unit)
        bad["prior_state"]["sourcefile"] = "/var/lib/postgresql/data/postgresql.auto.conf"
        bad["apply"]["value"] = "off"  # Same as prior_state.value
        bad["rollback"]["action"] = "set_config"
        bad["rollback"]["value"] = "off"

        errors = validate_fix_unit(bad)
        assert len(errors) == 1, errors
        assert "apply is a no-op: apply.value 'off' equals prior_state.value 'off'" in errors[0]

    def test_render_action_set_config(self):
        """render_action correctly renders set_config."""
        action = {"action": "set_config", "param": "log_connections", "value": "on"}
        sql = render_action(action)
        assert "ALTER SYSTEM SET" in sql
        assert '"log_connections"' in sql  # Quoted
        assert "= 'on'" in sql

    def test_render_action_reset_config(self):
        """render_action correctly renders reset_config."""
        action = {"action": "reset_config", "param": "log_connections"}
        sql = render_action(action)
        assert "ALTER SYSTEM RESET" in sql
        assert '"log_connections"' in sql  # Quoted

    def test_render_action_single_quote_escaped(self):
        """render_action doubles single quotes in value."""
        action = {"action": "set_config", "param": "log_connections", "value": "it's on"}
        sql = render_action(action)
        assert "= 'it''s on'" in sql  # Single quote doubled

    def test_render_action_matches_template(self):
        """render_action output matches set_config_parameter.sql.j2 for same inputs."""
        from app.services.template_service import env

        param = "log_connections"
        value = "on"

        action = {"action": "set_config", "param": param, "value": value}
        rendered = render_action(action)

        template_str = "ALTER SYSTEM SET {{ param_name | ident }} = '{{ param_value }}'; SELECT pg_reload_conf();"
        template = env.from_string(template_str)
        template_sql = template.render(param_name=param, param_value=value)

        assert rendered == template_sql, f"Rendered: {rendered!r}\\nExpected: {template_sql!r}"


# ---------------------------------------------------------------------------#
# schema.json - bind to spec YAML files
# ---------------------------------------------------------------------------#


@pytest.fixture(scope="module")
def spec_schema_validator():
    return load_validator("schema.json")


class TestSpecSchema:
    """Test that all spec YAML files validate against schema.json."""

    def test_schema_is_valid_json_schema(self, spec_schema_validator):
        """The schema.json itself validates as a valid JSON Schema."""
        pass

    @pytest.mark.parametrize(
        "yaml_path",
        sorted((REPO_ROOT / "catalog" / "specs" / "cis-pg17-v1.1.0").glob("*.yaml")),
        ids=lambda p: p.name,
    )
    def test_all_specs_validate_against_schema(self, spec_schema_validator, yaml_path):
        """Every YAML spec in cis-pg17-v1.1.0 validates against schema.json."""
        yaml_content = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        errors = list(spec_schema_validator.iter_errors(yaml_content))
        assert errors == [], [str(e) for e in errors]
