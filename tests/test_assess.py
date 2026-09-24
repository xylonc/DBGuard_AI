"""Unit tests for assess() function - Tier A (no database, no network).

Tests cover:
(a) Decision table: property test over all combinations
(b) Real specs: for every automated spec, use proof values
(c) One test for each case: STALE, both NOT_COLLECTED paths, ERROR variants, etc.
(d) Invalid input raises
(e) Output shape validation
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

from app.services.spec_engine import RecordsIndex, load_spec, spec_sha256, assess


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
    """Test (a): Property test over all combinations of conditions."""

    def test_pass_only_when_automated_hash_matches_and_result_ok_on(self):
        """PASS exactly when: automated tier + entry present + hash matches + status ok + result='on'.
        
        All other combinations must NOT give PASS.
        """
        # Use 3.1.20 spec (operator equals, expected "on")
        spec = specs_by_id["cis-pg17-v1.1.0:3.1.20"]
        computed_hash = spec_sha256(spec)

        # All possible values
        tiers = ["automated", "parameterised", "manual_checklist", "needs_capability"]
        entries = [None, "present"]  # None = no entry, "present" = entry exists
        hash_match = [True, False]
        statuses = ["ok", "error", "not_collected"]
        results = ["on", "off", 123]  # on/off strings, int

        # Track which combinations give PASS
        pass_combinations = []

        for tier in tiers:
            for entry_present in entries:
                for match in hash_match:
                    for status in statuses:
                        for result in results:
                            # Build spec with specified tier
                            spec_copy = copy.deepcopy(spec)
                            spec_copy["tier"] = tier
                            # Remove check and proof for non-automated specs
                            if tier != "automated":
                                spec_copy["reason"] = "test reason for non-automated"
                                if "check" in spec_copy:
                                    del spec_copy["check"]
                                if "proof" in spec_copy:
                                    del spec_copy["proof"]

                            # Build check entry
                            if entry_present is None:
                                checks = {}
                            else:
                                # Build spec_hash based on match flag
                                check_spec_hash = computed_hash if match else "d" * 64
                                entry = make_check_entry(status, result=result, spec_hash=check_spec_hash, spec=spec_copy)
                                # For non-automated specs, we still create an entry but it should return tier result first
                                checks = {spec_copy["spec_id"]: entry}

                            snapshot = make_snapshot_with_checks(checks)

                            report = assess([spec_copy], snapshot, records)
                            result_row = report["results"][0]

                            is_pass = result_row["result"] == "PASS"
                            if is_pass:
                                pass_combinations.append({
                                    "tier": tier,
                                    "entry_present": entry_present,
                                    "hash_match": match,
                                    "status": status,
                                    "result": result,
                                })

        # PASS should happen exactly once: automated + present + match + ok + "on"
        assert len(pass_combinations) == 1, f"Expected 1 PASS combination, got {len(pass_combinations)}: {pass_combinations}"
        pc = pass_combinations[0]
        assert pc["tier"] == "automated"
        assert pc["entry_present"] == "present"
        assert pc["hash_match"] is True
        assert pc["status"] == "ok"
        assert pc["result"] == "on"


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

        # Determine result_value based on operator
        if operator == "equals":
            result_value = fix_value
        elif operator == "not_equals":
            result_value = fix_value
        elif operator == "in":
            result_value = fix_value
        else:
            pytest.fail(f"Unknown operator {operator}")

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
            # Create a simple non-automated spec copy
            spec_copy = copy.deepcopy(spec)
            if "check" in spec_copy:
                del spec_copy["check"]
            if "proof" in spec_copy:
                del spec_copy["proof"]
            spec_copy["reason"] = "test reason"

            checks = {spec_copy["spec_id"]: make_check_entry("ok", result="test", spec=spec_copy)}
            snapshot = make_snapshot_with_checks(checks)

            report = assess([spec_copy], snapshot, records)

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
        """STALE when entry status is 'not_collected' but hash doesn't match (hash precedence)."""
        spec = specs_by_id["cis-pg17-v1.1.0:3.1.20"]
        checks = {"cis-pg17-v1.1.0:3.1.20": make_check_entry("not_collected")}
        snapshot = make_snapshot_with_checks(checks)

        report = assess([spec], snapshot, records)

        result_row = report["results"][0]
        assert result_row["result"] == "STALE"
        assert result_row["reason_code"] == "hash_mismatch"

    def test_hash_match_status_not_collected(self):
        """NOT_COLLECTED when entry status is 'not_collected' and hash matches."""
        spec = specs_by_id["cis-pg17-v1.1.0:3.1.20"]
        checks = {"cis-pg17-v1.1.0:3.1.20": make_check_entry("not_collected", spec=spec)}
        snapshot = make_snapshot_with_checks(checks)

        report = assess([spec], snapshot, records)

        result_row = report["results"][0]
        assert result_row["result"] == "NOT_COLLECTED"
        assert result_row["reason_code"] == "status_not_collected"

    def test_error_status_error(self):
        """STALE when entry status is 'error' but hash doesn't match (hash precedence)."""
        spec = specs_by_id["cis-pg17-v1.1.0:3.1.20"]
        checks = {"cis-pg17-v1.1.0:3.1.20": make_check_entry("error", error="connection failed")}
        snapshot = make_snapshot_with_checks(checks)

        report = assess([spec], snapshot, records)

        result_row = report["results"][0]
        assert result_row["result"] == "STALE"
        assert result_row["reason_code"] == "hash_mismatch"

    def test_hash_match_status_error(self):
        """ERROR when entry status is 'error' and hash matches."""
        spec = specs_by_id["cis-pg17-v1.1.0:3.1.20"]
        checks = {"cis-pg17-v1.1.0:3.1.20": make_check_entry("error", error="connection failed", spec=spec)}
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
        assert row["result"] == "PASS"
        assert row["reason_code"] == "operator_true"

        # Automated spec fields
        assert row["setting_name"] == "log_connections"
        assert row["operator"] == "equals"
        assert row["expected"] == "on"
        assert row["spec_hash"] is not None
        assert row["collected_spec_hash"] is not None
        assert row["observed"] == "on"


class TestAssessDeterminism:
    """Test (f): Determinism - same inputs produce identical output."""

    def test_deterministic_output(self):
        """Calling assess twice gives equal json.dumps(..., sort_keys=True) output."""
        snapshot = make_snapshot_with_checks({
            "cis-pg17-v1.1.0:3.1.20": make_check_entry("ok", result="on", spec=specs_by_id["cis-pg17-v1.1.0:3.1.20"]),
        })

        report1 = assess([specs_by_id["cis-pg17-v1.1.0:3.1.20"]], snapshot, records)
        report2 = assess([specs_by_id["cis-pg17-v1.1.0:3.1.20"]], snapshot, records)

        json1 = json.dumps(report1, sort_keys=True)
        json2 = json.dumps(report2, sort_keys=True)

        assert json1 == json2


class TestAssessLiveSnapshot:
    """Test (g): Live snapshot assessment."""

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


class TestAssessCLI:
    """Test (h): CLI exit codes."""

    def test_cli_exit_0_on_live_fixture(self, tmp_path):
        """CLI exits 0 on valid live fixture."""
        import subprocess
        result = subprocess.run(
            [
                "uv", "run", "python", "scripts/assess.py",
                "--specs", "catalog/specs/cis-pg17-v1.1.0",
                "--records", "catalog/benchmarks/cis-pg17-v1.1.0/records.json",
                "--snapshot", "tests/fixtures/phase1/snapshot-pg17-live.json",
                "--out", str(tmp_path / "report.json"),
            ],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
        )
        assert result.returncode == 0, f"CLI failed with exit code {result.returncode}: {result.stderr}"

    def test_cli_exit_2_on_invalid_operator(self, tmp_path):
        """CLI exits 2 on a spec with invalid operator written into tmp_path."""
        import subprocess

        # Create a spec with invalid operator
        invalid_spec_dir = tmp_path / "invalid_specs"
        invalid_spec_dir.mkdir()
        invalid_spec = invalid_spec_dir / "3.1.20.yaml"
        invalid_spec.write_text("""spec_id: "cis-pg17-v1.1.0:3.1.20"
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
  operator: invalid_operator  # Invalid!
  expected: "on"
  pass_condition_quote: "The value must be 'on'."
""")

        result = subprocess.run(
            [
                "uv", "run", "python", "scripts/assess.py",
                "--specs", str(invalid_spec_dir),
                "--records", "catalog/benchmarks/cis-pg17-v1.1.0/records.json",
                "--snapshot", "tests/fixtures/phase1/snapshot-pg17-live.json",
            ],
            capture_output=True,
            text=True,
            cwd=REPO_ROOT,
        )
        assert result.returncode == 2, f"Expected exit code 2, got {result.returncode}: {result.stderr}"
