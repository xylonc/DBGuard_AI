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
from app.services.spec_engine.operators import OPERATORS
from app.services.spec_engine.manifest import condition_check_id


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

# Automated setting checks: the only specs with a proof (break/fix values) and a
# manifest entry. Catalog checks (F6) read baseline sections and never have a proof;
# they are covered by tests/test_catalog_checks.py.
setting_specs = [s for s in automated_specs if s["check"]["kind"] == "setting"]
catalog_specs = [s for s in specs_list if s.get("check", {}).get("kind") == "catalog"]

# Non-automated specs (needs_capability, manual_checklist, parameterised)
non_automated_specs = [s for s in specs_list if s.get("tier") != "automated"]

# applies_when condition evidence, written out (not read from the spec): every
# committed condition is "logs go to syslog" (3.1.10, 3.1.11, 3.1.13 read log_destination).
CONDITION_TRUE = {"log_destination": "stderr,syslog"}
CONDITION_FALSE = {"log_destination": "stderr"}


def checks_for(spec: dict, result: Any, condition: dict | None = CONDITION_TRUE) -> dict:
    """Check entries for spec; a spec with applies_when also gets its condition entry."""
    checks = {spec["spec_id"]: make_check_entry("ok", result=result, spec=spec)}
    if "applies_when" in spec and condition is not None:
        name = spec["applies_when"]["setting_name"]
        assert name in condition, f"no written-out condition value for {name}"
        checks[condition_check_id(spec["spec_id"])] = make_check_entry(
            "ok", result=condition[name], spec=spec)
    return checks

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

    @pytest.mark.parametrize("spec", setting_specs, ids=lambda s: s["spec_id"])
    def test_automated_spec_with_fix_value_passes(self, spec):
        """For each automated spec, use proof.fix.value as result and expect PASS."""
        check = spec.get("check", {})
        operator = check.get("operator")
        expected = check.get("expected")

        # Determine what value satisfies the check (the "fix" value)
        fix_value = spec["proof"]["fix"]["value"]

        # Every operator in the one registry is evaluated with the proof value itself;
        # an operator outside the registry is a failure, not a skip.
        if operator not in OPERATORS:
            pytest.fail(f"Unknown operator {operator}")
        result_value = fix_value

        # A spec with applies_when is tested where it applies (condition true).
        checks = checks_for(spec, result_value)
        snapshot = make_snapshot_with_checks(checks)

        report = assess([spec], snapshot, records)

        result_row = report["results"][0]
        assert result_row["result"] == "PASS", (
            f"Expected PASS for {spec['spec_id']} with fix value {fix_value}, got {result_row['result']}"
        )

    @pytest.mark.parametrize("spec", setting_specs, ids=lambda s: s["spec_id"])
    def test_automated_spec_with_break_value_fails(self, spec):
        """For each automated spec, use proof.break.value as result and expect FAIL."""
        check = spec.get("check", {})
        operator = check.get("operator")

        # Determine what value fails the check (the "break" value)
        break_value = spec["proof"]["break"]["value"]

        checks = checks_for(spec, break_value)
        snapshot = make_snapshot_with_checks(checks)

        report = assess([spec], snapshot, records)

        result_row = report["results"][0]
        assert result_row["result"] == "FAIL", (
            f"Expected FAIL for {spec['spec_id']} with break value {break_value}, got {result_row['result']}"
        )

    @pytest.mark.parametrize("spec", [s for s in automated_specs if "applies_when" in s],
                             ids=lambda s: s["spec_id"])
    def test_automated_spec_with_false_condition_is_not_applicable(self, spec):
        """Where the condition is false, neither the fix nor the break value gives PASS or FAIL."""
        for value in (spec["proof"]["fix"]["value"], spec["proof"]["break"]["value"]):
            snapshot = make_snapshot_with_checks(checks_for(spec, value, CONDITION_FALSE))
            row = assess([spec], snapshot, records)["results"][0]
            assert (row["result"], row["reason_code"]) == ("NOT_APPLICABLE", "condition_false")
            # without the condition entry the result is unknown, never PASS/FAIL/N-A
            snapshot = make_snapshot_with_checks(checks_for(spec, value, None))
            row = assess([spec], snapshot, records)["results"][0]
            assert (row["result"], row["reason_code"]) == ("NOT_COLLECTED", "condition_no_entry")

    def test_committed_applies_when_specs(self):
        """The syslog condition is on exactly 3.1.10, 3.1.11 and 3.1.13 (Gate 1 ruling A6)."""
        assert sorted(s["spec_id"] for s in specs_list if "applies_when" in s) == [
            "cis-pg17-v1.1.0:3.1.10", "cis-pg17-v1.1.0:3.1.11", "cis-pg17-v1.1.0:3.1.13"]
    def test_setting_specs_cover_every_automated_spec_with_proof(self):
        """The break/fix parametrisation only drops catalog specs, never a setting spec."""
        assert len(setting_specs) == 17
        assert {s["spec_id"] for s in automated_specs} - {s["spec_id"] for s in setting_specs} == {
            "cis-pg17-v1.1.0:5.5", "cis-pg17-v1.1.0:7.4"}
        assert all("proof" in s for s in setting_specs)

    @pytest.mark.parametrize("spec", catalog_specs, ids=lambda s: s["spec_id"])
    def test_catalog_spec_has_no_proof_and_rejects_one(self, spec):
        """Catalog checks never get a fix, so a proof on one is a validation error."""
        from app.services.spec_engine import validate_spec
        assert "proof" not in spec
        assert validate_spec(spec, records) == []
        with_proof = copy.deepcopy(spec)
        with_proof["proof"] = {"break": {"setting_name": "x", "value": "1"},
                               "fix": {"setting_name": "x", "value": "2"}}
        assert validate_spec(with_proof, records) == ["check.kind 'catalog' must not have proof present"]

    def test_non_automated_tier_results(self):
        """Non-automated specs get their tier's result, even with compliant-looking evidence.

        The committed spec is used as-is (a policy spec keeps its check and, for 3.1.10 and
        3.1.13, its applies_when) and every entry it owns is supplied, condition true, so
        only the tier (or the missing approved profile) can decide the result.
        """
        expected = {
            "needs_capability": ("NEEDS_CAPABILITY", "tier_needs_capability"),
            "manual_checklist": ("MANUAL", "tier_manual"),
        }
        seen_tiers = set()
        # Catalog checks (F6) are decided by their evaluator, not the tier: they are
        # covered in test_catalog_checks.py. Here they must still never PASS or read
        # as a plain MANUAL on a snapshot without their catalog sections.
        catalog_manual = [s for s in non_automated_specs if s["spec_id"] in {c["spec_id"] for c in catalog_specs}]
        assert sorted(s["ref"]["recommendation"] for s in catalog_manual) == [
            "4.10", "4.3", "4.4", "4.5", "4.6", "4.7", "4.9", "7.1"]
        for spec in catalog_manual:
            row = assess([copy.deepcopy(spec)], make_snapshot_with_checks({}), records)["results"][0]
            assert (row["result"], row["reason_code"]) == ("NOT_COLLECTED", "section_not_collected"), spec["spec_id"]
        for spec in non_automated_specs:
            if spec in catalog_manual:
                continue
            tier = spec.get("tier", "")
            seen_tiers.add(tier)
            spec_copy = copy.deepcopy(spec)
            checks = checks_for(spec_copy, "test")
            snapshot = make_snapshot_with_checks(checks)

            report = assess([spec_copy], snapshot, records)

            result_row = report["results"][0]
            got = (result_row["result"], result_row["reason_code"])
            if tier in expected:
                assert got == expected[tier], spec["spec_id"]
            elif tier == "parameterised":
                # With no policy profile supplied: MANUAL, and never PASS
                if spec.get("check", {}).get("expected_from") == "policy":
                    assert got == ("MANUAL", "policy_missing"), spec["spec_id"]
                else:
                    assert got == ("MANUAL", "tier_manual"), spec["spec_id"]
            else:
                pytest.fail(f"Unknown tier: {tier}")
        assert seen_tiers == {"needs_capability", "manual_checklist", "parameterised"}


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

    def test_decide_unknown_tier(self):
        """_decide raises ValueError for unknown tier."""
        spec = copy.deepcopy(specs_by_id["cis-pg17-v1.1.0:3.1.20"])
        spec["tier"] = "automatd"  # Typo - not a valid tier
        entry = make_check_entry("ok", result="on", spec=spec)
        from app.services.spec_engine.assess import _decide

        with pytest.raises(ValueError) as exc_info:
            _decide(spec, entry, spec_sha256(spec))
        assert "unknown tier" in str(exc_info.value)

    def test_decide_unknown_status(self):
        """_decide raises ValueError for unknown status."""
        spec = specs_by_id["cis-pg17-v1.1.0:3.1.20"]
        entry = make_check_entry("partial", result="on", spec=spec)
        from app.services.spec_engine.assess import _decide

        with pytest.raises(ValueError) as exc_info:
            _decide(spec, entry, spec_sha256(spec))
        assert "unknown status" in str(exc_info.value)

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
        assert snapshot_path.exists(), f"Live fixture path does not exist: {snapshot_path}"

        snapshot = json.loads(snapshot_path.read_text(encoding="utf-8"))

        # Load spec files for the automated setting specs in the snapshot
        automated_spec_ids = [s["spec_id"] for s in setting_specs]
        loaded_specs = [specs_by_id[sid] for sid in automated_spec_ids if sid in specs_by_id]

        report = assess(loaded_specs, snapshot, records)

        assert {row["spec_id"] for row in report["results"]} == set(automated_spec_ids)
        # Check no STALE, NOT_COLLECTED, or ERROR for automated specs. NOT_APPLICABLE is
        # allowed only for a spec with applies_when whose collected condition is false.
        for row in report["results"]:
            if "applies_when" in specs_by_id[row["spec_id"]] and row["result"] == "NOT_APPLICABLE":
                assert row["reason_code"] == "condition_false", row
                continue
            assert row["result"] in ("PASS", "FAIL"), (
                f"Unexpected result {row['result']} for automated spec {row['spec_id']}"
            )

    def test_live_snapshot_catalog_outcomes(self):
        """Catalog specs on the real collector fixture, checked against the fixture's data.

        The fixture was re-recorded from a disposable PG17 with the applied collector,
        so it has `functions` and `archiving`. Every catalog spec is now evaluated:
        none is NOT_COLLECTED.
        """
        snapshot = json.loads((REPO_ROOT / "tests" / "fixtures" / "phase1" / "snapshot-pg17-live.json")
                              .read_text(encoding="utf-8"))
        baseline = snapshot["baseline"]
        assert baseline["gaps"] == []
        rows = {r["spec_id"].split(":")[1]: r for r in assess(catalog_specs, snapshot, records)["results"]}
        assert set(rows) == {"4.3", "4.4", "4.5", "4.6", "4.7", "4.9", "4.10", "5.5", "7.1", "7.4"}
        assert not [rec for rec, r in rows.items() if r["result"] == "NOT_COLLECTED"]

        # 4.5: a fresh cluster has no SECURITY DEFINER / SET-clause function, but the
        # postgres database is connectable and not covered, so MANUAL (never PASS).
        assert baseline["functions"] == []
        assert [(d["datname"], d["datallowconn"], d["datistemplate"]) for d in baseline["databases"]] == [
            ("dbguard_sandbox", True, False), ("postgres", True, False),
            ("template0", False, True), ("template1", True, True)]
        assert rows["4.5"]["result"] == "MANUAL"
        assert rows["4.5"]["explanation"] == {"code": "databases_not_covered", "evidence_count": 0,
                                              "databases": ["postgres"]}
        assert rows["4.5"]["evidence"] == []

        # 7.4: the collector reports archive_mode off with zero archiver counters.
        assert baseline["archiving"]["archive_mode"] == "off"
        assert baseline["archiving"]["archive_command_is_set"] is False
        assert baseline["archiving"]["stat_archiver"]["archived_count"] == 0
        assert baseline["archiving"]["stat_archiver"]["failed_count"] == 0
        assert rows["7.4"]["result"] == "FAIL"
        assert rows["7.4"]["reason_code"] == "archive_mode_off"
        assert rows["7.4"]["explanation"] == {"code": "archive_mode_off", "archive_mode": "off"}
        assert rows["7.4"]["evidence"] == [{"archive_mode": "off", "archive_library": "",
                                            "archive_command_is_set": False}]

        # The fixture's only non-predefined role is the bootstrap superuser (oid 10).
        own = [r for r in baseline["roles"] if not r["rolname"].startswith("pg_")]
        assert [(r["rolname"], r["oid"], r["rolcanlogin"], r["rolconnlimit"], r["rolsuper"]) for r in own] == [
            ("dbguard_poc", "10", True, -1, True)]

        # 5.5: dbguard_poc logs in with rolconnlimit -1 -> FAIL; pg_* roles are out of scope.
        assert rows["5.5"]["result"] == "FAIL"
        assert rows["5.5"]["reason_code"] == "unlimited_connections"
        assert rows["5.5"]["explanation"] == {"code": "unlimited_connections", "role_count": 1}
        assert rows["5.5"]["evidence"] == [{
            "type": "in_scope", "rolname": "dbguard_poc", "rolconnlimit": -1, "rolsuper": True,
            "unlimited": True, "superuser_limit_not_enforced": True, "limit_zero_blocks_login": False}]

        # 4.10: password_types says dbguard_poc has scram-sha-256 -> nothing to review.
        assert baseline["password_types"] == [
            {"password_type": "scram-sha-256", "rolname": "dbguard_poc", "rolvaliduntil": None}]
        assert rows["4.10"]["result"] == "PASS"
        assert rows["4.10"]["explanation"] == {"code": "empty_review_set", "evidence_count": 0}

        # 4.3 / 4.9: the one admin role, flagged as the bootstrap superuser.
        assert rows["4.3"]["result"] == "MANUAL"
        assert rows["4.3"]["evidence"] == [{
            "rolname": "dbguard_poc", "rolsuper": True, "rolcreaterole": True, "rolcreatedb": True,
            "rolreplication": True, "rolbypassrls": True, "rolcanlogin": True, "bootstrap_superuser": True}]
        assert rows["4.9"]["evidence"] == [
            {"rolname": "dbguard_poc", "rolcanlogin": True, "bootstrap_superuser": True}]
        assert rows["4.4"]["evidence"] == [{"rolname": "dbguard_poc", "rolsuper": True,
                                            "rolvaliduntil": None, "password_type": "scram-sha-256"}]

        # 4.6 / 4.7: connected to dbguard_sandbox; postgres also accepts connections
        # (template0/template1 are templates and are not listed).
        assert snapshot["envelope"]["database"] == "dbguard_sandbox"
        for rec in ("4.6", "4.7"):
            assert rows[rec]["result"] == "MANUAL"
            assert rows[rec]["explanation"]["code"] == "databases_not_covered"
            assert rows[rec]["explanation"]["databases"] == ["postgres"]
        assert baseline["object_acls"] == [] and baseline["rls_policies"] == []
        assert rows["4.6"]["evidence"] == [{"type": "superuser", "rolname": "dbguard_poc", "rolcanlogin": True}]
        assert rows["4.7"]["evidence"] == [{"type": "bypass_role", "rolname": "dbguard_poc",
                                            "reasons": ["bypassrls", "superuser"], "rolsuper": True,
                                            "owned_non_forced_tables": []}]

        # 7.1: the replication superuser, the three hba lines for database "replication"
        # (124, 125, 126, all trust) and the recovery state. No primary_conninfo.
        assert rows["7.1"]["result"] == "MANUAL"
        hba_lines = [r["line_number"] for r in baseline["hba_rules"] if r["database"] == ["replication"]]
        assert hba_lines == [124, 125, 126]
        ev = rows["7.1"]["evidence"]
        assert [e["type"] for e in ev] == ["replication_role"] + ["replication_hba_rule"] * 3 + ["recovery_state"]
        assert [e["line_number"] for e in ev if e["type"] == "replication_hba_rule"] == hba_lines
        assert all(e["auth_method"] == "trust" for e in ev if e["type"] == "replication_hba_rule")
        assert ev[-1] == {"type": "recovery_state", "in_recovery": False}


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
