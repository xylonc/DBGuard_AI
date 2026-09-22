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
        # The schema requires specific fields, so we test with minimal valid data
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

        # Get all validation errors
        errors = list(snapshot_validator.iter_errors(load_example(path)))

        # Check that at least one error mentions the rule from filename
        # Filename pattern: snapshot-v0.3.0-invalid-<rule>.json
        match = re.search(r"invalid-(.+)\.json$", path.name)
        assert match, f"Filename {path.name} doesn't match expected pattern"
        rule = match.group(1)

        # The error messages mention the missing/invalid field:
        # "no-result" -> "'result' is a required property"
        # "no-error" -> "'error' is a required property"
        # We check if the rule (without prefix) appears in the error
        found = False
        for err in errors:
            err_str = str(err)
            # The rule in the filename is like "no-result" or "no-error"
            # We need to match "result" or "error" in the error message
            # Extract the relevant part: remove "no-" prefix if present
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

    def test_validate_fix_unit_bad_rollback(self, valid_fix_unit):
        """rollback must contain prior_state.value or be ALTER SYSTEM RESET for non-auto.conf."""
        bad = copy.deepcopy(valid_fix_unit)
        bad["rollback"] = "ALTER SYSTEM SET log_connections = 'wrong'; SELECT pg_reload_conf();"

        errors = validate_fix_unit(bad)
        assert len(errors) == 1, errors
        assert "rollback" in errors[0]
        assert "off" in errors[0]

    def test_validate_fix_unit_bad_rollback_substring_bug(self, valid_fix_unit):
        """Rollback SET value 'false' does not match prior_state.value 'off'.

        This test verifies exact string comparison: 'false' != 'off' fails validation.
        The substring bug was: `if prior_state_value not in rollback:` would match
        because 'on' appears in 'log_connections', incorrectly passing for wrong values.
        """
        bad = copy.deepcopy(valid_fix_unit)
        bad["rollback"] = "ALTER SYSTEM SET log_connections = 'false'; SELECT pg_reload_conf();"

        errors = validate_fix_unit(bad)
        assert len(errors) == 1, errors
        assert "SET value" in errors[0]
        assert "false" in errors[0]
        assert "off" in errors[0]

    def test_validate_fix_unit_good_rollback_value_match(self, valid_fix_unit):
        """Rollback SET value 'off' matches prior_state.value 'off'."""
        good = copy.deepcopy(valid_fix_unit)
        good["rollback"] = "ALTER SYSTEM SET log_connections = 'off'; SELECT pg_reload_conf();"

        errors = validate_fix_unit(good)
        assert errors == [], errors

    def test_validate_fix_unit_rollback_different_param(self, valid_fix_unit):
        """Rollback targets different parameter than apply."""
        bad = copy.deepcopy(valid_fix_unit)
        bad["rollback"] = "ALTER SYSTEM SET log_checkpoints = 'off'; SELECT pg_reload_conf();"

        errors = validate_fix_unit(bad)
        assert len(errors) == 1, errors
        assert "rollback targets parameter 'log_checkpoints' but apply uses 'log_connections'" in errors[0]

    def test_validate_fix_unit_unparseable_rollback(self, valid_fix_unit):
        """Rollback is unparseable text."""
        bad = copy.deepcopy(valid_fix_unit)
        bad["rollback"] = "some random text that is not valid SQL"

        errors = validate_fix_unit(bad)
        assert len(errors) == 1, errors
        assert "rollback must be ALTER SYSTEM SET param = value or ALTER SYSTEM RESET" in errors[0]

    def test_validate_fix_unit_substring_bug_on_in_log_connections(self, valid_fix_unit):
        """Substring bug: prior 'on' appears in 'log_connections', would incorrectly pass.
        
        The bug was: `if prior_state_value not in rollback:` would match because
        'on' is a substring of 'log_connections'. The correct parser extracts
        the SET value 'off' which does NOT match prior_state.value 'on'.
        
        Test case: prior_state.value='on', rollback sets log_connections='off'
        - Substring bug: 'on' in "ALTER SYSTEM SET log_connections = 'off'" -> True (bug! passes)
        - Parser: 'off' != 'on' -> reject (correct)
        """
        bad = copy.deepcopy(valid_fix_unit)
        bad["prior_state"]["value"] = "on"
        bad["precheck"]["expected_value"] = "on"  # Must match prior_state
        bad["rollback"] = "ALTER SYSTEM SET log_connections = 'off'; SELECT pg_reload_conf();"
        
        errors = validate_fix_unit(bad)
        # With correct parser, this should be rejected: 'off' != 'on'
        assert len(errors) == 1, errors
        assert "rollback SET value 'off' does not match prior_state.value 'on'" in errors[0]

    def test_validate_fix_unit_substring_bug_wrong_parameter(self, valid_fix_unit):
        """Substring bug: prior 'off' matches 'log_disconnections' substring.
        
        prior 'off' + rollback for log_disconnections = 'off' should be REJECTED
        because we're resetting a different parameter (log_connections vs log_disconnections).
        
        The parser correctly identifies log_disconnections != log_connections.
        The substring check 'off' in rollback would incorrectly pass.
        """
        bad = copy.deepcopy(valid_fix_unit)
        bad["rollback"] = "ALTER SYSTEM SET log_disconnections = 'off'; SELECT pg_reload_conf();"
        # With correct parser: param 'log_disconnections' != 'log_connections' -> reject
        # With substring bug: 'off' in rollback -> True (bug! passes)
        
        errors = validate_fix_unit(bad)
        assert len(errors) == 1, errors
        assert "rollback targets parameter 'log_disconnections' but apply uses 'log_connections'" in errors[0]

    def test_validate_fix_unit_substring_bug_with_comment(self, valid_fix_unit):
        """Substring bug: comment '-- was off' causes false match.
        
        prior 'off' + rollback with comment containing '-- was off' should be REJECTED
        because the actual SET value is 'on', not 'off'.
        
        The parser extracts 'on' from ALTER SYSTEM SET and compares.
        The substring check 'off' in rollback would match the comment!
        """
        bad = copy.deepcopy(valid_fix_unit)
        bad["rollback"] = "-- was off\nALTER SYSTEM SET log_connections = 'on'; SELECT pg_reload_conf();"
        # With correct parser: 'on' != 'off' -> reject (correct)
        # With substring bug: 'off' in comment -> True (bug! passes)
        
        errors = validate_fix_unit(bad)
        assert len(errors) == 1, errors
        assert "rollback SET value 'on' does not match prior_state.value 'off'" in errors[0]

    def test_validate_fix_unit_rollback_forms_accepted(self, valid_fix_unit):
        """Various acceptable rollback forms should be accepted."""
        # Test = 'off' (quoted)
        good1 = copy.deepcopy(valid_fix_unit)
        good1["rollback"] = "ALTER SYSTEM SET log_connections = 'off'; SELECT pg_reload_conf();"
        errors1 = validate_fix_unit(good1)
        assert errors1 == [], errors1
        
        # Test = off (unquoted)
        good2 = copy.deepcopy(valid_fix_unit)
        good2["rollback"] = "ALTER SYSTEM SET log_connections = off; SELECT pg_reload_conf();"
        errors2 = validate_fix_unit(good2)
        assert errors2 == [], errors2
        
        # Test lowercase keywords
        good3 = copy.deepcopy(valid_fix_unit)
        good3["rollback"] = "alter system set log_connections = 'off'; select pg_reload_conf();"
        errors3 = validate_fix_unit(good3)
        assert errors3 == [], errors3


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
