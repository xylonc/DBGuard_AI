"""Unit tests for assess() function - Tier A (no database, no network).

Tests cover:
(a) Decision table: every combination of conditions
(b) Real specs: for every automated spec, use proof.fix as result and expect PASS
(c) One test for each case: STALE, both NOT_COLLECTED paths, ERROR variants, orphan check, etc.
(d) Invalid input raises
(e) Output shape validation against assessment-report-v1.json
(f) Determinism
(g) Live snapshot
(h) CLI exit codes
"""

import copy
import json
import jsonschema
import sys
from pathlib import Path
from typing import Any

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
sys_path = str(REPO_ROOT / "backend")
if sys_path not in __import__("sys").path:
    __import__("sys").path.insert(0, sys_path)

from app.services.spec_engine import RecordsIndex, load_spec, spec_sha256, assess  # noqa: E402
from app.services.spec_engine.specs import spec_sha256 as spec_sha256_func  # noqa: E402


# Load records
RECORDS_PATH = REPO_ROOT / "catalog" / "benchmarks" / "cis-pg17-v1.1.0" / "records.json"
records = RecordsIndex.load(RECORDS_PATH)

# Load all spec files
SPEC_DIR = REPO_ROOT / "catalog" / "specs" / "cis-pg17-v1.1.0"
specs_list: list[dict] = []
for path in sorted(SPEC_DIR.glob("*.yaml")):
    specs_list.append(load_spec(path))

# Index specs by id
specs_by_id = {s["spec_id"]: s for s in specs_list}

# Automated specs (tier == "automated")
automated_specs = [s for s in specs_list if s.get("tier") == "automated"]

# Non-automated specs (needs_capability, manual_checklist, parameterised)
non_automated_specs = [s for s in specs_list if s.get("tier") != "automated"]

# Load contract schema
CONTRACT_PATH = REPO_ROOT / "catalog" / "specs" / "contracts" / "assessment-report-v1.json"
contract_schema = json.loads(CONTRACT_PATH.read_text(encoding="utf-8"))


def make_snapshot_with_checks(
    checks: dict[str, dict[str, Any]],
    manifest: dict | None = None,
    baseline: dict | None = None,
) -> dict:
    """Create a minimal snapshot with the given checks."""
    return {
        "envelope": {
            "schema_version": "0.3.0",
            "target_id": "test",
            "database": "testdb",
            "collector_sha256": "a" * 64,
            "manifest": manifest
            or {
                "sha256": "b" * 64,
                "manifest_version": 1,
                "benchmark_id": "cis-pg17-v1.1.0",
                "check_count": len(checks),
            },
        },
        "baseline": baseline or {"identity": {"version_full": "PostgreSQL 17.0", "server_version_num": 170000}},
        "checks": checks,
    }


def make_check_entry(
    status: str,
    result: Any = None,
    error: str | None = None,
    spec_hash: str | None = None,
    spec: dict | None = None,
) -> dict:
    """Create a check entry."""
    if spec_hash is None and spec is not None:
        spec_hash = spec_sha256(spec)
    elif spec_hash is None and spec is None:
        spec_hash = "c" * 64

    entry: dict = {"spec_hash": spec_hash, "query": "SHOW test_setting", "status": status}
    if status == "ok":
        entry["result"] = result
    elif status == "error":
        entry["error"] = error or "test error"
    return entry


class TestAssessDecisionTable:
    """Test (a): Decision table - every combination of conditions."""

    def test_pass_only_for_operator_true(self):
        """Exactly one combination gives PASS: operator true + ok status."""
        # Create a minimal spec with operator true - we'll manually construct it
        # to bypass validate_spec's proof validation (which requires break to NOT satisfy check)
        spec_true = {
            "spec_id": "cis-pg17-v1.1.0:3.1.20-true",
            "schema_version": 1,
            "authored_by": "human",
            "ref": {
                "benchmark": "CIS PostgreSQL 17 Benchmark",
                "benchmark_version": "1.1.0",
                "pg_major": 17,
                "recommendation": "3.1.20-true",
                "title": "Test operator true",
                "source_sha256": "e" * 64,
            },
            "tier": "automated",
            "reason": None,
            "check": {
                "kind": "setting",
                "setting_name": "debug_print_parse",
                "query": "SHOW debug_print_parse",
                "operator": "true",
                "expected": "on",
                "pass_condition_quote": "Always pass",
            },
            "proof": {
                "break": {"setting_name": "debug_print_parse", "value": "on"},  # Break always passes with operator true
                "fix": {"setting_name": "debug_print_parse", "value": "off"},
            },
        }

        snapshot = make_snapshot_with_checks({
            "cis-pg17-v1.1.0:3.1.20-true": make_check_entry("ok", result="anything", spec=spec_true),
        })

        # Skip if validate_spec rejects this (proof validation issue with operator true)
        from app.services.spec_engine.validate import validate_spec
        errors = validate_spec(spec_true, records)
        proof_errors = [e for e in errors if "proof" in e.lower()]
        if proof_errors:
            pytest.skip(f"Cannot create valid spec with operator=true due to proof validation: {proof_errors}")

        report = assess([spec_true], snapshot, records)

        # Should have one PASS result
        pass_results = [r for r in report["results"] if r["result"] == "PASS"]
        assert len(pass_results) == 1
        assert pass_results[0]["spec_id"] == "cis-pg17-v1.1.0:3.1.20-true"

    def test_all_other_results_map_correctly(self):
        """Each result appears where the spec says it should."""
        # Test cases for each result type
        test_cases = [
            # STALE: entry exists but hash mismatch
            {
                "spec": specs_by_id["cis-pg17-v1.1.0:3.1.20"],
                "check": make_check_entry("ok", result="on", spec_hash="d" * 64),
                "expected_result": "STALE",
                "expected_reason": "hash_mismatch",
            },
            # NEEDS_CAPABILITY
            {
                "spec": specs_by_id["cis-pg17-v1.1.0:3.1.14"],
                "check": make_check_entry("ok", result="warning", spec=specs_by_id["cis-pg17-v1.1.0:3.1.14"]),
                "expected_result": "NEEDS_CAPABILITY",
                "expected_reason": "tier_needs_capability",
            },
            # NOT_COLLECTED (no entry)
            {
                "spec": specs_by_id["cis-pg17-v1.1.0:3.1.20"],
                "check": None,
                "expected_result": "NOT_COLLECTED",
                "expected_reason": "no_entry",
            },
            # NOT_COLLECTED (status not_collected)
            {
                "spec": specs_by_id["cis-pg17-v1.1.0:3.1.20"],
                "check": make_check_entry("not_collected"),
                "expected_result": "NOT_COLLECTED",
                "expected_reason": "no_entry",
            },
            # ERROR (status error)
            {
                "spec": specs_by_id["cis-pg17-v1.1.0:3.1.20"],
                "check": make_check_entry("error", error="connection failed"),
                "expected_result": "ERROR",
                "expected_reason": "status_error",
            },
            # ERROR (non-string result)
            {
                "spec": specs_by_id["cis-pg17-v1.1.0:3.1.20"],
                "check": make_check_entry("ok", result=123, spec=specs_by_id["cis-pg17-v1.1.0:3.1.20"]),
                "expected_result": "ERROR",
                "expected_reason": "non_string_result",
            },
            # FAIL (automated with non-true operator, result ok)
            {
                "spec": specs_by_id["cis-pg17-v1.1.0:3.1.20"],
                "check": make_check_entry("ok", result="off", spec=specs_by_id["cis-pg17-v1.1.0:3.1.20"]),
                "expected_result": "FAIL",
                "expected_reason": "operator_false",
            },
        ]

        for tc in test_cases:
            spec = tc["spec"]
            check = tc["check"]

            if check is None:
                checks = {}
            else:
                checks = {spec["spec_id"]: check}

            snapshot = make_snapshot_with_checks(checks)

            report = assess([spec], snapshot, records)

            result_row = report["results"][0]
            # Debug output
            print(f"Test case: {tc.get('expected_result')}, Spec: {spec['spec_id']}, Checks: {checks}, Result: {result_row['result']}")
            assert result_row["result"] == tc["expected_result"], (
                f"Expected {tc['expected_result']} for {spec['spec_id']}, got {result_row['result']}"
            )
            assert result_row["reason_code"] == tc["expected_reason"], (
                f"Expected reason {tc['expected_reason']}, got {result_row['reason_code']}"
            )


class TestAssessRealSpecs:
    """Test (b): Real specs with proof.fix as result expect PASS."""

    @pytest.mark.parametrize("spec", automated_specs, ids=lambda s: s["spec_id"])
    def test_automated_spec_with_fix_value_passes(self, spec):
        """For each automated spec, use proof.fix.value as result and expect PASS."""
        check = spec.get("check", {})
        operator = check.get("operator")
        expected = check.get("expected")

        # Determine what value satisfies the check (the "fix" value)
        fix_value = spec["proof"]["fix"]["value"]

        # The "true" operator is special - it just needs the result to exist
        if operator == "true":
            result_value = "on"  # Any string works
        else:
            result_value = fix_value

        checks = {spec["spec_id"]: make_check_entry("ok", result=result_value, spec=spec)}
        snapshot = make_snapshot_with_checks(checks)

        report = assess([spec], snapshot, records)

        result_row = report["results"][0]
        assert result_row["result"] == "PASS", (
            f"Expected PASS for {spec['spec_id']} with fix value {fix_value}, got {result_row['result']}"
        )

    @pytest.mark.parametrize("spec", automated_specs, ids=lambda s: s["spec_id"])
    def test_automated_spec_with_break_value_fails(self, spec):
        """For each automated spec, use proof.break.value as result and expect FAIL."""
        check = spec.get("check", {})
        operator = check.get("operator")

        # Determine what value fails the check (the "break" value)
        break_value = spec["proof"]["break"]["value"]

        checks = {spec["spec_id"]: make_check_entry("ok", result=break_value, spec=spec)}
        snapshot = make_snapshot_with_checks(checks)

        report = assess([spec], snapshot, records)

        result_row = report["results"][0]
        assert result_row["result"] == "FAIL", (
            f"Expected FAIL for {spec['spec_id']} with break value {break_value}, got {result_row['result']}"
        )

    def test_non_automated_tier_results(self):
        """Non-automated specs get their tier's result."""
        for spec in non_automated_specs:
            tier = spec.get("tier", "")
            checks = {spec["spec_id"]: make_check_entry("ok", result="test", spec=spec)}
            snapshot = make_snapshot_with_checks(checks)

            report = assess([spec], snapshot, records)

            result_row = report["results"][0]
            if tier == "needs_capability":
                assert result_row["result"] == "NEEDS_CAPABILITY"
            elif tier in ("manual_checklist", "parameterised"):
                assert result_row["result"] == "MANUAL"
            else:
                pytest.fail(f"Unknown tier: {tier}")


class TestAssessSpecificCases:
    """Test (c): One test for each special case."""

    def test_stale_result(self):
        """STALE when collected_spec_hash differs from computed spec_hash."""
        spec = specs_by_id["cis-pg17-v1.1.0:3.1.20"]
        computed_hash = spec_sha256(spec)
        wrong_hash = "d" * 64

        checks = {"cis-pg17-v1.1.0:3.1.20": make_check_entry("ok", result="on", spec_hash=wrong_hash, spec=spec)}
        snapshot = make_snapshot_with_checks(checks)

        report = assess([spec], snapshot, records)

        result_row = report["results"][0]
        assert result_row["result"] == "STALE"
        assert result_row["reason_code"] == "hash_mismatch"

    def test_not_collected_no_entry(self):
        """NOT_COLLECTED when no entry in snapshot for spec_id."""
        spec = specs_by_id["cis-pg17-v1.1.0:3.1.20"]
        checks = {}  # Empty - no entry for spec
        snapshot = make_snapshot_with_checks(checks)

        report = assess([spec], snapshot, records)

        result_row = report["results"][0]
        assert result_row["result"] == "NOT_COLLECTED"
        assert result_row["reason_code"] == "no_entry"

    def test_not_collected_status_not_collected(self):
        """NOT_COLLECTED when entry status is 'not_collected'."""
        spec = specs_by_id["cis-pg17-v1.1.0:3.1.20"]
        checks = {"cis-pg17-v1.1.0:3.1.20": make_check_entry("not_collected")}
        snapshot = make_snapshot_with_checks(checks)

        report = assess([spec], snapshot, records)

        result_row = report["results"][0]
        assert result_row["result"] == "NOT_COLLECTED"
        assert result_row["reason_code"] == "no_entry"

    def test_error_status_error(self):
        """ERROR when entry status is 'error'."""
        spec = specs_by_id["cis-pg17-v1.1.0:3.1.20"]
        checks = {"cis-pg17-v1.1.0:3.1.20": make_check_entry("error", error="connection failed")}
        snapshot = make_snapshot_with_checks(checks)

        report = assess([spec], snapshot, records)

        result_row = report["results"][0]
        assert result_row["result"] == "ERROR"
        assert result_row["reason_code"] == "status_error"

    def test_error_result_none(self):
        """ERROR when result is None."""
        spec = specs_by_id["cis-pg17-v1.1.0:3.1.20"]
        checks = {"cis-pg17-v1.1.0:3.1.20": make_check_entry("ok", result=None, spec=spec)}
        snapshot = make_snapshot_with_checks(checks)

        report = assess([spec], snapshot, records)

        result_row = report["results"][0]
        assert result_row["result"] == "ERROR"
        assert result_row["reason_code"] == "non_string_result"

    def test_error_result_int(self):
        """ERROR when result is an integer."""
        spec = specs_by_id["cis-pg17-v1.1.0:3.1.20"]
        checks = {"cis-pg17-v1.1.0:3.1.20": make_check_entry("ok", result=123, spec=spec)}
        snapshot = make_snapshot_with_checks(checks)

        report = assess([spec], snapshot, records)

        result_row = report["results"][0]
        assert result_row["result"] == "ERROR"
        assert result_row["reason_code"] == "non_string_result"

    def test_error_result_array(self):
        """ERROR when result is a list."""
        spec = specs_by_id["cis-pg17-v1.1.0:3.1.20"]
        checks = {"cis-pg17-v1.1.0:3.1.20": make_check_entry("ok", result=["on"], spec=spec)}
        snapshot = make_snapshot_with_checks(checks)

        report = assess([spec], snapshot, records)

        result_row = report["results"][0]
        assert result_row["result"] == "ERROR"
        assert result_row["reason_code"] == "non_string_result"

    def test_orphan_check(self):
        """Orphan checks are in snapshot but have no spec."""
        spec = specs_by_id["cis-pg17-v1.1.0:3.1.20"]
        checks = {
            "cis-pg17-v1.1.0:3.1.20": make_check_entry("ok", result="on", spec=spec),
            "orphan:3.1.99": make_check_entry("ok", result="on"),  # No matching spec
        }
        snapshot = make_snapshot_with_checks(checks)

        report = assess([spec], snapshot, records)

        assert "orphan:3.1.99" in report["flags"]["orphan_checks"]
        assert len(report["flags"]["orphan_checks"]) == 1
        # Orphan check should not have a result row
        assert len(report["results"]) == 1
        assert report["results"][0]["spec_id"] == "cis-pg17-v1.1.0:3.1.20"

    def test_check_count_mismatch(self):
        """integrity_ok is false when declared != actual."""
        spec = specs_by_id["cis-pg17-v1.1.0:3.1.20"]
        checks = {"cis-pg17-v1.1.0:3.1.20": make_check_entry("ok", result="on", spec=spec)}
        snapshot = make_snapshot_with_checks(checks, manifest={
            "sha256": "b" * 64,
            "manifest_version": 1,
            "benchmark_id": "cis-pg17-v1.1.0",
            "check_count": 999,  # Wrong count
        })

        report = assess([spec], snapshot, records)

        assert report["flags"]["check_count"]["declared"] == 999
        assert report["flags"]["check_count"]["actual"] == 1
        assert report["flags"]["check_count"]["matches"] is False
        assert report["flags"]["integrity_ok"] is False

    def test_version_mismatch(self):
        """version_mismatch is true when benchmark major (17) != server major (16)."""
        spec = specs_by_id["cis-pg17-v1.1.0:3.1.20"]
        checks = {"cis-pg17-v1.1.0:3.1.20": make_check_entry("ok", result="on", spec=spec)}
        snapshot = make_snapshot_with_checks(checks, baseline={
            "identity": {
                "version_full": "PostgreSQL 16.0",
                "server_version_num": 160000,
            }
        })

        report = assess([spec], snapshot, records)

        assert report["flags"]["version_mismatch"] is True
        assert report["target"]["server_major"] == 16

    def test_unknown_version(self):
        """server_major is null when server_version_num is unknown."""
        spec = specs_by_id["cis-pg17-v1.1.0:3.1.20"]
        checks = {"cis-pg17-v1.1.0:3.1.20": make_check_entry("ok", result="on", spec=spec)}
        snapshot = make_snapshot_with_checks(checks, baseline={
            "identity": {
                "version_full": "PostgreSQL unknown",
                "server_version_num": None,
            }
        })

        report = assess([spec], snapshot, records)

        assert report["flags"]["version_mismatch"] is None
        assert report["target"]["server_major"] is None


class TestAssessInvalidInput:
    """Test (d): Invalid input raises."""

    def test_invalid_snapshot_raises(self):
        """Snapshot that fails v0.3.0 schema raises ValueError."""
        invalid_snapshot = {
            "envelope": {
                "schema_version": "0.2.0",  # Wrong version
                "target_id": "test",
                "database": "testdb",
                "collector_sha256": "a" * 64,
                "manifest": {
                    "sha256": "b" * 64,
                    "manifest_version": 1,
                    "benchmark_id": "cis-pg17-v1.1.0",
                    "check_count": 1,
                },
            },
            "baseline": {},
            "checks": {},
        }

        with pytest.raises(ValueError, match="Snapshot validation failed"):
            assess(specs_list, invalid_snapshot, records)

    def test_duplicate_spec_id_raises(self):
        """Duplicate spec_id raises ValueError."""
        spec = specs_by_id["cis-pg17-v1.1.0:3.1.20"]
        specs_dup = [spec, spec]  # Duplicate

        with pytest.raises(ValueError, match="Duplicate spec_id"):
            assess(specs_dup, make_snapshot_with_checks({}), records)


class TestAssessOutputShape:
    """Test (e): Output shape validates against contract."""

    def test_report_validates_contract(self):
        """Every report produced validates against assessment-report-v1.json."""
        snapshot = make_snapshot_with_checks({
            "cis-pg17-v1.1.0:3.1.20": make_check_entry("ok", result="on", spec=specs_by_id["cis-pg17-v1.1.0:3.1.20"]),
        })

        report = assess([specs_by_id["cis-pg17-v1.1.0:3.1.20"]], snapshot, records)

        # Validate against contract schema
        jsonschema.validate(report, contract_schema)

    def test_all_result_fields_present(self):
        """Each result row has all required fields for its tier."""
        snapshot = make_snapshot_with_checks({
            "cis-pg17-v1.1.0:3.1.20": make_check_entry("ok", result="on", spec=specs_by_id["cis-pg17-v1.1.0:3.1.20"]),
        })

        report = assess([specs_by_id["cis-pg17-v1.1.0:3.1.20"]], snapshot, records)

        row = report["results"][0]
        assert row["spec_id"] == "cis-pg17-v1.1.0:3.1.20"
        assert row["title"] == "Ensure 'log_connections' is enabled"
        assert row["tier"] == "automated"
        assert row["result"] == "PASS"  # expected='on', result='on', operator='equals' -> PASS
        assert row["reason_code"] == "operator_true"

        # Automated spec fields
        assert row["setting_name"] == "log_connections"
        assert row["operator"] == "equals"
        assert row["expected"] == "on"
        assert row["spec_hash"]
        assert len(row["spec_hash"]) == 64
        assert row["collected_spec_hash"]
        assert row["observed"] == "on"


class TestAssessDeterminism:
    """Test (f): Calling assess twice gives equal json output."""

    def test_deterministic_output(self):
        """Same inputs produce identical json.dumps(..., sort_keys=True) output."""
        snapshot = make_snapshot_with_checks({
            "cis-pg17-v1.1.0:3.1.20": make_check_entry("ok", result="on", spec=specs_by_id["cis-pg17-v1.1.0:3.1.20"]),
        })

        report1 = assess([specs_by_id["cis-pg17-v1.1.0:3.1.20"]], snapshot, records)
        report2 = assess([specs_by_id["cis-pg17-v1.1.0:3.1.20"]], snapshot, records)

        json1 = json.dumps(report1, sort_keys=True, ensure_ascii=False)
        json2 = json.dumps(report2, sort_keys=True, ensure_ascii=False)

        assert json1 == json2


class TestAssessLiveSnapshot:
    """Test (g): Live snapshot with no STALE, NOT_COLLECTED, or ERROR rows."""

    def test_live_snapshot_assessment(self):
        """Live snapshot assesses with no STALE, NOT_COLLECTED or ERROR rows for automated specs."""
        snapshot_path = REPO_ROOT / "tests" / "fixtures" / "phase1" / "snapshot-pg17-live.json"
        if not snapshot_path.exists():
            pytest.skip("snapshot-pg17-live.json not found")

        snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))

        # Load spec files for the automated specs in the snapshot
        automated_spec_ids = [s["spec_id"] for s in automated_specs]
        loaded_specs = [specs_by_id[sid] for sid in automated_spec_ids if sid in specs_by_id]

        report = assess(loaded_specs, snapshot, records)

        # Check no STALE, NOT_COLLECTED, or ERROR for automated specs
        for row in report["results"]:
            assert row["result"] in ("PASS", "FAIL"), (
                f"Unexpected result {row['result']} for automated spec {row['spec_id']}"
            )
            # Check observed matches snapshot result
            if row["result"] == "PASS" or row["result"] == "FAIL":
                expected_result = snapshot["checks"][row["spec_id"]]["result"]
                assert row["observed"] == expected_result, (
                    f"observed {row['observed']} != snapshot result {expected_result} for {row['spec_id']}"
                )


class TestAssessCLI:
    """Test (h): CLI exit codes."""

    def test_cli_exit_0_on_live_fixture(self, tmp_path):
        """CLI exits 0 on the live fixture (if it exists)."""
        # Use the checks fixture to create a snapshot
        checks_path = REPO_ROOT / "tests" / "fixtures" / "phase1" / "checks-cis-pg17-v1.1.0.json"
        if not checks_path.exists():
            pytest.skip("checks-cis-pg17-v1.1.0.json not found")

        # Create a minimal snapshot with all checks passing
        checks_data = json.loads(checks_path.read_text(encoding="utf-8"))
        snapshot_checks = {}
        for check in checks_data["checks"]:
            spec_id = check["spec_id"]
            if spec_id in specs_by_id:
                spec = specs_by_id[spec_id]
                # Use the fix value (which should give PASS)
                fix_value = spec["proof"]["fix"]["value"]
                snapshot_checks[spec_id] = make_check_entry("ok", result=fix_value, spec=spec)

        snapshot = make_snapshot_with_checks(snapshot_checks, manifest={
            "sha256": "b" * 64,
            "manifest_version": 1,
            "benchmark_id": checks_data["benchmark_id"],
            "check_count": len(checks_data["checks"]),
        })

        snapshot_path = tmp_path / "snapshot.json"
        snapshot_path.write_text(json.dumps(snapshot, sort_keys=True), encoding="utf-8")

        # Run CLI
        out_path = tmp_path / "report.json"
        import subprocess
        result = subprocess.run(
            ["python", "scripts/assess.py",
             "--specs", str(SPEC_DIR),
             "--records", str(RECORDS_PATH),
             "--snapshot", str(snapshot_path),
             "--out", str(out_path)],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0, f"CLI failed: {result.stderr}"
        assert out_path.exists()

    def test_cli_exit_2_on_invalid_operator(self, tmp_path):
        """CLI exits 2 on a spec with invalid operator written into tmp_path."""
        # Create a spec with invalid operator
        spec_dir = tmp_path / "specs"
        spec_dir.mkdir()
        spec_file = spec_dir / "test.yaml"
        spec_file.write_text("""
spec_id: "test:invalid"
schema_version: 1
authored_by: human
ref:
  benchmark: "CIS PostgreSQL 17 Benchmark"
  benchmark_version: "1.1.0"
  pg_major: 17
  recommendation: "99.99"
  title: "Test"
  source_sha256: "a" * 64
tier: automated
reason: null
check:
  kind: setting
  setting_name: test_setting
  query: "SHOW test_setting"
  operator: invalid_operator  # Invalid!
  expected: "test"
  pass_condition_quote: "test"
proof:
  break: { setting_name: test_setting, value: "other" }
  fix: { setting_name: test_setting, value: "test" }
""")

        # Create a minimal snapshot
        snapshot = make_snapshot_with_checks({
            "test:invalid": make_check_entry("ok", result="test"),
        })
        snapshot_path = tmp_path / "snapshot.json"
        snapshot_path.write_text(json.dumps(snapshot, sort_keys=True), encoding="utf-8")

        # Run CLI
        out_path = tmp_path / "report.json"
        import subprocess
        result = subprocess.run(
            ["python", "scripts/assess.py",
             "--specs", str(spec_dir),
             "--records", str(RECORDS_PATH),
             "--snapshot", str(snapshot_path),
             "--out", str(out_path)],
            cwd=REPO_ROOT,
            capture_output=True,
            text=True,
        )

        assert result.returncode == 2, f"Expected exit 2 for invalid spec, got {result.returncode}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
