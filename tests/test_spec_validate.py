"""Tests for the spec validator.

Conventions used throughout:
- Every variant starts from copy.deepcopy(VALID_3120_SPEC) and breaks ONE rule.
- assert_only_error() checks the rule fired AND nothing else did. A test that
  only checks "some expected message is present" can pass for the wrong reason.
- Every file read/write passes encoding="utf-8" (Windows defaults to cp1252,
  which cannot decode the curly quotes in the CIS text).
"""

import copy
import json
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "backend"))

from app.services.spec_engine import RecordsIndex, RecordsIntegrityError, load_spec, spec_sha256, validate_spec
from app.services.spec_engine.operators import equals, in_, not_equals

RECORDS_PATH = REPO_ROOT / "catalog" / "benchmarks" / "cis-pg17-v1.1.0" / "records.json"
SPEC_DIR = REPO_ROOT / "catalog" / "specs" / "cis-pg17-v1.1.0"

VALID_3120_SPEC = {
    "spec_id": "cis-pg17-v1.1.0:3.1.20",
    "schema_version": 1,
    "authored_by": "human",
    "ref": {
        "benchmark": "CIS PostgreSQL 17 Benchmark",
        "benchmark_version": "1.1.0",
        "pg_major": 17,
        "recommendation": "3.1.20",
        "title": "Ensure 'log_connections' is enabled",
        "source_sha256": "4e2afdf9a6c40bba3b2dfd7c36f5929b9260cae9e0d6af243f4f79bd4db7c3c0",
    },
    "tier": "automated",
    "reason": None,
    "check": {
        "kind": "setting",
        "setting_name": "log_connections",
        "query": "SHOW log_connections",
        "operator": "equals",
        "expected": "on",
        "pass_condition_quote": "If not configured to `on`, this is a fail.",
    },
    "proof": {
        "break": {"setting_name": "log_connections", "value": "off"},
        "fix": {"setting_name": "log_connections", "value": "on"},
    },
}

# YAML text of the valid spec. {expected_line} lets a test inject raw YAML.
SPEC_YAML_TEMPLATE = """\
spec_id: "cis-pg17-v1.1.0:3.1.20"
schema_version: 1
authored_by: human
ref:
  benchmark: "CIS PostgreSQL 17 Benchmark"
  benchmark_version: "1.1.0"
  pg_major: 17
  recommendation: "3.1.20"
  title: "Ensure 'log_connections' is enabled"
  source_sha256: "4e2afdf9a6c40bba3b2dfd7c36f5929b9260cae9e0d6af243f4f79bd4db7c3c0"
tier: automated
reason: null
check:
  kind: setting
  setting_name: log_connections
  query: "SHOW log_connections"
  operator: equals
{expected_line}
  pass_condition_quote: "If not configured to `on`, this is a fail."
proof:
  break: {{ setting_name: log_connections, value: "off" }}
  fix: {{ setting_name: log_connections, value: "on" }}
"""


def load_records():
    return RecordsIndex.load(RECORDS_PATH)


def write_spec_yaml(tmp_path, expected_line='  expected: "on"', name="spec.yaml"):
    path = tmp_path / name
    path.write_text(SPEC_YAML_TEMPLATE.format(expected_line=expected_line), encoding="utf-8")
    return path


def assert_only_error(errors, substring):
    """Exactly one error, and it is the one this test targets."""
    assert len(errors) == 1, errors
    assert substring in errors[0], errors


# ---------------------------------------------------------------------------
# Valid specs
# ---------------------------------------------------------------------------

class TestValidSpecs:

    def test_committed_3120_file_matches_reference_and_validates(self):
        """The committed 3.1.20.yaml is exactly the hand-written spec, and is valid."""
        spec = load_spec(SPEC_DIR / "3.1.20.yaml")
        assert spec == VALID_3120_SPEC
        assert validate_spec(spec, load_records()) == []

    @pytest.mark.parametrize("spec_path", sorted(SPEC_DIR.glob("*.yaml")), ids=lambda p: p.name)
    def test_every_committed_spec_validates(self, spec_path):
        """Every spec in the benchmark directory validates with zero errors."""
        errors = validate_spec(load_spec(spec_path), load_records())
        assert errors == [], errors

    def test_non_automated_spec_without_check_or_proof_is_valid(self):
        """A non-automated spec needs a reason and must NOT need check or proof."""
        spec = copy.deepcopy(VALID_3120_SPEC)
        spec["tier"] = "needs_capability"
        spec["reason"] = "example reason"
        del spec["check"]
        del spec["proof"]
        assert validate_spec(spec, load_records()) == []

    def test_quote_with_different_whitespace_accepted(self):
        """Newlines vs single spaces in the quote are normalised away."""
        spec = copy.deepcopy(VALID_3120_SPEC)
        spec["check"]["pass_condition_quote"] = "If not\nconfigured to `on`,\nthis is a fail."
        assert validate_spec(spec, load_records()) == []


# ---------------------------------------------------------------------------
# Shape
# ---------------------------------------------------------------------------

class TestShape:

    def test_unknown_top_level_key(self):
        spec = copy.deepcopy(VALID_3120_SPEC)
        spec["status"] = "approved"
        assert_only_error(validate_spec(spec, load_records()), "status")

    def test_unknown_key_inside_check(self):
        spec = copy.deepcopy(VALID_3120_SPEC)
        spec["check"]["unknown_key"] = "value"
        assert_only_error(validate_spec(spec, load_records()), "unknown_key")

    def test_unquoted_yaml_boolean_rejected(self, tmp_path):
        """`expected: on` without quotes loads as True and must be rejected."""
        spec = load_spec(write_spec_yaml(tmp_path, expected_line="  expected: on"))
        assert spec["check"]["expected"] is True
        errors = validate_spec(spec, load_records())
        assert any("check.expected must be a string" in e for e in errors), errors

    def test_duplicate_key_rejected_by_loader(self, tmp_path):
        path = write_spec_yaml(tmp_path, expected_line='  expected: "on"\n  expected: "off"')
        with pytest.raises(yaml.YAMLError):
            load_spec(path)

    def test_two_errors_both_returned(self):
        spec = copy.deepcopy(VALID_3120_SPEC)
        spec["unknown_key"] = "value"
        spec["schema_version"] = 2
        errors = validate_spec(spec, load_records())
        joined = " | ".join(errors)
        assert "unknown_key" in joined, errors
        assert "schema_version" in joined, errors


# ---------------------------------------------------------------------------
# Traceability to records.json
# ---------------------------------------------------------------------------

class TestTraceability:

    def test_spec_id_wrong_benchmark_version(self):
        """spec_id must be version-qualified; a pg16 prefix is rejected."""
        spec = copy.deepcopy(VALID_3120_SPEC)
        spec["spec_id"] = "cis-pg16-v1.1.0:3.1.20"
        assert_only_error(validate_spec(spec, load_records()), "spec_id")

    def test_wrong_title(self):
        spec = copy.deepcopy(VALID_3120_SPEC)
        spec["ref"]["title"] = "Ensure log_connections is enabled"  # quotes removed
        assert_only_error(validate_spec(spec, load_records()), "title")

    def test_wrong_source_sha256(self):
        spec = copy.deepcopy(VALID_3120_SPEC)
        spec["ref"]["source_sha256"] = "0" * 64
        assert_only_error(validate_spec(spec, load_records()), "source_sha256")

    def test_nonexistent_recommendation(self):
        spec = copy.deepcopy(VALID_3120_SPEC)
        spec["spec_id"] = "cis-pg17-v1.1.0:99.99.99"
        spec["ref"]["recommendation"] = "99.99.99"
        errors = validate_spec(spec, load_records())
        assert any("not found in records" in e for e in errors), errors


# ---------------------------------------------------------------------------
# Automated check rules
# ---------------------------------------------------------------------------

class TestAutomatedCheck:

    def test_invented_quote(self):
        spec = copy.deepcopy(VALID_3120_SPEC)
        spec["check"]["pass_condition_quote"] = "If not configured to `on`, this is a critical fail."
        errors = validate_spec(spec, load_records())
        assert any("pass_condition_quote not found in audit_procedure" in e for e in errors), errors

    def test_expected_only_inside_longer_word(self):
        """'If not configured to' IS in the audit text, but 'on' only appears
        inside 'configured'. Only the whole-token rule can reject this."""
        spec = copy.deepcopy(VALID_3120_SPEC)
        spec["check"]["pass_condition_quote"] = "If not configured to"
        assert_only_error(validate_spec(spec, load_records()), "whole token")

    def test_setting_name_injection(self):
        spec = copy.deepcopy(VALID_3120_SPEC)
        spec["check"]["setting_name"] = "log_connections; DROP ROLE x"
        errors = validate_spec(spec, load_records())
        assert any("setting_name must match pattern" in e for e in errors), errors

    def test_query_not_show_setting_name(self):
        spec = copy.deepcopy(VALID_3120_SPEC)
        spec["check"]["query"] = "SELECT log_connections"
        assert_only_error(validate_spec(spec, load_records()), "SHOW log_connections")

    def test_break_value_already_satisfies_check(self):
        spec = copy.deepcopy(VALID_3120_SPEC)
        spec["proof"]["break"]["value"] = "on"
        assert_only_error(validate_spec(spec, load_records()), "already satisfies check")

    def test_fix_value_does_not_satisfy_check(self):
        spec = copy.deepcopy(VALID_3120_SPEC)
        spec["proof"]["fix"]["value"] = "off"
        assert_only_error(validate_spec(spec, load_records()), "does not satisfy check")

    def test_fix_setting_name_mismatch(self):
        spec = copy.deepcopy(VALID_3120_SPEC)
        spec["proof"]["fix"]["setting_name"] = "log_disconnections"
        assert_only_error(validate_spec(spec, load_records()), "proof.fix.setting_name")


    def test_not_equals_spec_valid_and_its_rules_enforced(self):
        """3.1.25 uses not_equals. The old validator rejected the valid spec,
        accepted a fix value that fails, and never checked the expected token."""
        spec = copy.deepcopy(VALID_3120_SPEC)
        spec["spec_id"] = "cis-pg17-v1.1.0:3.1.25"
        spec["ref"]["recommendation"] = "3.1.25"
        spec["ref"]["title"] = "Ensure 'log_statement' is set correctly"
        spec["ref"]["source_sha256"] = "b856a2cee96bad6507bf469ab6c2de9ba2e44cf1e2114b1a070d2e62a3cb125f"
        spec["check"].update(
            setting_name="log_statement",
            query="SHOW log_statement",
            operator="not_equals",
            expected="none",
            pass_condition_quote="If `log_statement` is set to `none` then this is a fail.",
        )
        spec["proof"] = {
            "break": {"setting_name": "log_statement", "value": "none"},
            "fix": {"setting_name": "log_statement", "value": "ddl"},
        }
        assert validate_spec(spec, load_records()) == []

        bad_fix = copy.deepcopy(spec)
        bad_fix["proof"]["fix"]["value"] = "none"
        assert_only_error(validate_spec(bad_fix, load_records()), "does not satisfy check")

        invented = copy.deepcopy(spec)
        invented["check"]["expected"] = "all"
        invented["proof"]["break"]["value"] = "all"
        assert_only_error(validate_spec(invented, load_records()), "whole token")

# ---------------------------------------------------------------------------
# Non-automated tiers
# ---------------------------------------------------------------------------

class TestNonAutomatedTier:

    def test_check_present_rejected(self):
        spec = copy.deepcopy(VALID_3120_SPEC)
        spec["tier"] = "manual_checklist"
        spec["reason"] = "needs human review"
        del spec["proof"]
        assert_only_error(validate_spec(spec, load_records()), "must not have check present")

    def test_empty_reason_rejected(self):
        spec = copy.deepcopy(VALID_3120_SPEC)
        spec["tier"] = "parameterised"
        spec["reason"] = ""
        del spec["check"]
        del spec["proof"]
        assert_only_error(validate_spec(spec, load_records()), "reason")

    def test_automated_check_kind_manual_checklist_rejected(self):
        spec = copy.deepcopy(VALID_3120_SPEC)
        spec["check"]["kind"] = "manual_checklist"
        assert_only_error(validate_spec(spec, load_records()), "check.kind")

    def test_automated_check_kind_needs_capability_rejected(self):
        spec = copy.deepcopy(VALID_3120_SPEC)
        spec["check"]["kind"] = "needs_capability"
        assert_only_error(validate_spec(spec, load_records()), "check.kind")


# ---------------------------------------------------------------------------
# Operators
# ---------------------------------------------------------------------------

class TestOperators:

    def test_equals(self):
        assert equals("on", "on") is True
        assert equals("on", "off") is False
        assert equals("On", "on") is False  # no case folding

    def test_not_equals(self):
        assert not_equals("ddl", "none") is True
        assert not_equals("none", "none") is False

    def test_in(self):
        assert in_("TLSv1.2", ["TLSv1.2", "TLSv1.3"]) is True
        assert in_("TLSv1.1", ["TLSv1.2", "TLSv1.3"]) is False

    @pytest.mark.parametrize("actual", [123, None, [], True])
    def test_non_string_actual_raises(self, actual):
        with pytest.raises(TypeError):
            equals(actual, "on")
        with pytest.raises(TypeError):
            not_equals(actual, "on")
        with pytest.raises(TypeError):
            in_(actual, ["on"])


# ---------------------------------------------------------------------------
# records.json integrity
# ---------------------------------------------------------------------------

class TestRecordsIntegrity:

    def test_real_records_load(self):
        load_records()

    def test_edited_audit_procedure_rejected(self, tmp_path):
        data = json.loads(RECORDS_PATH.read_text(encoding="utf-8"))
        for record in data["records"]:
            if record["recommendation"] == "3.1.20":
                text = record["audit_procedure"]
                record["audit_procedure"] = text[:5] + "X" + text[6:]
                break
        else:
            pytest.fail("3.1.20 not found in records.json")

        tampered = tmp_path / "records.json"
        tampered.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

        with pytest.raises(RecordsIntegrityError) as exc_info:
            RecordsIndex.load(tampered)
        assert "source_sha256" in str(exc_info.value)


# ---------------------------------------------------------------------------
# Hashing
# ---------------------------------------------------------------------------

class TestHashing:

    def test_crlf_file_gives_same_spec_sha256(self, tmp_path):
        lf_path = write_spec_yaml(tmp_path, name="lf.yaml")
        crlf_path = tmp_path / "crlf.yaml"
        crlf_path.write_bytes(lf_path.read_bytes().replace(b"\n", b"\r\n"))
        assert b"\r\n" in crlf_path.read_bytes()
        assert spec_sha256(load_spec(lf_path)) == spec_sha256(load_spec(crlf_path))

    def test_any_edit_changes_spec_sha256(self):
        edited = copy.deepcopy(VALID_3120_SPEC)
        edited["check"]["expected"] = "off"
        assert spec_sha256(edited) != spec_sha256(VALID_3120_SPEC)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

class TestValidateSpecsScript:

    def run_cli(self, target):
        return subprocess.run(
            [sys.executable, str(REPO_ROOT / "scripts" / "validate_specs.py"), str(target)],
            capture_output=True, text=True, encoding="utf-8",
        )

    def test_exit_0_on_real_directory(self):
        result = self.run_cli(SPEC_DIR)
        assert result.returncode == 0, result.stdout + result.stderr

    def test_nonzero_on_directory_with_invalid_spec(self, tmp_path):
        write_spec_yaml(tmp_path, expected_line='  expected: "enabled"')
        result = self.run_cli(tmp_path)
        assert result.returncode != 0, result.stdout + result.stderr

    def test_cli_reports_ok_for_every_committed_spec(self):
        result = self.run_cli(SPEC_DIR)
        spec_files = sorted(SPEC_DIR.glob("*.yaml"))
        assert len(spec_files) == 6, [p.name for p in spec_files]
        ok_lines = [line for line in result.stdout.splitlines() if line.startswith("OK ")]
        assert len(ok_lines) == 6, result.stdout
        assert result.returncode == 0, result.stdout

    def test_cli_fails_on_empty_directory(self, tmp_path):
        result = self.run_cli(tmp_path)
        assert result.returncode != 0, result.stdout
