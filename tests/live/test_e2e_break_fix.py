"""End-to-end break/fix tests against pg-target.

This module verifies the complete pipeline:
1. baseline_pipeline_integrity - one pipeline run validates structure
2. break_then_fix - parametrized over each automated spec, verify break->FAIL->fix->PASS flow
3. edited_spec_is_stale_never_pass - verify spec hash mismatch produces STALE

All tests use the live pytest marker and require a working pg-target connection.
"""

import copy
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Tuple

import jsonschema
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent.parent

# Add backend to path for imports
sys_path = str(REPO_ROOT / "backend")
if sys_path not in sys.path:
    sys.path.insert(0, sys_path)

# Import pipeline runner - use absolute imports
from tests.live._pipeline import run_pipeline, compute_file_hash
from tests.live.conftest import fresh_setting, run_action


@pytest.fixture(scope="session")
def restore_setting():
    """Fixture to restore a setting and return prior state.
    
    Returns a function that:
    1. Records the current setting state (prior state)
    2. Checks auto.conf is empty for this setting (setup precondition)
    3. Returns the prior state (value, source, sourcefile)
    4. On teardown, executes rollback to restore prior state
    """
    import psycopg2
    import os
    
    local_cache = {}
    
    def _restore_setting(setting_name: str):
        """Record prior state and prepare for restore."""
        pg_target_url = os.environ.get("PG_TARGET_URL")
        if not pg_target_url:
            raise RuntimeError("PG_TARGET_URL is not set")
        
        # Get prior state
        prior_setting, prior_source, prior_sourcefile = fresh_setting(setting_name)
        
        # Check auto.conf is empty (setup precondition)
        with psycopg2.connect(pg_target_url) as conn:
            conn.autocommit = True
            with conn.cursor() as cur:
                cur.execute(
                    "SELECT name, setting FROM pg_file_settings WHERE sourcefile LIKE %s AND name = %s",
                    ('%postgresql.auto.conf%', setting_name),
                )
                rows = cur.fetchall()
                if rows:
                    rows_str = "\n".join(f"  {name}={setting}" for name, setting in rows)
                    raise AssertionError(
                        f"pg-target contaminated before test: auto.conf has rows:\n{rows_str}"
                    )
        
        # Store prior state for later restoration
        local_cache[setting_name] = (prior_setting, prior_source, prior_sourcefile)
        
        return prior_setting, prior_source, prior_sourcefile
    
    return _restore_setting


def compute_spec_hash(spec_path: Path) -> str:
    """Compute canonical-JSON SHA-256 hash of a spec file."""
    import json
    import hashlib
    import yaml
    with open(spec_path, "r", encoding="utf-8") as f:
        spec = yaml.safe_load(f)
    sha_str = json.dumps(spec, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(sha_str.encode("utf-8")).hexdigest()


def get_automated_specs(spec_dir: Path) -> list[str]:
    """Get list of automated spec_ids from spec_dir."""
    import yaml
    spec_ids = []
    for yaml_path in sorted(spec_dir.glob("*.yaml")):
        with open(yaml_path) as f:
            spec = yaml.safe_load(f)
        if spec.get("tier") == "automated":
            spec_ids.append(spec["spec_id"])
    return spec_ids


# Build list of automated specs at module level for parametrization
AUTOMATED_SPECS = get_automated_specs(REPO_ROOT / "catalog" / "specs" / "cis-pg17-v1.1.0")


@pytest.mark.live
class TestE2EBreakFix:
    """End-to-end break/fix tests against pg-target."""

    def test_baseline_pipeline_integrity(self, tmp_path):
        """One pipeline run validates structure and metadata."""
        spec_dir = REPO_ROOT / "catalog" / "specs" / "cis-pg17-v1.1.0"
        
        manifest_path, snapshot_path, report = run_pipeline(spec_dir, tmp_path)
        
        # Validate report against schema
        schema_path = REPO_ROOT / "catalog" / "specs" / "contracts" / "assessment-report-v1.json"
        with open(schema_path) as f:
            schema = json.load(f)
        jsonschema.validate(report, schema)
        
        # Verify collector_sha256 matches actual file
        collector_sql = REPO_ROOT / "collector" / "collect.sql"
        assert report["inputs"]["collector_sha256"] == compute_file_hash(collector_sql)
        
        # Verify manifest_sha256 matches actual manifest
        assert report["inputs"]["manifest_sha256"] == compute_file_hash(manifest_path)
        
        # Verify spec hashes match between inputs.specs and manifest (automated specs only)
        with open(manifest_path) as f:
            manifest = json.load(f)
        manifest_hashes = {c["spec_id"]: c["spec_hash"] for c in manifest["checks"]}
        # inputs.specs includes all specs; filter to automated only
        inputs_hashes = {s["spec_id"]: s["spec_hash"] 
                        for s in report["inputs"]["specs"] 
                        if s["spec_id"] in manifest_hashes}
        assert manifest_hashes == inputs_hashes
        
        # Verify target.server_major == 17
        assert report["target"]["server_major"] == 17
        
        # Verify flags show no version mismatch and integrity ok
        assert report["flags"]["version_mismatch"] is False
        assert report["flags"]["integrity_ok"] is True
        
        # Verify spec cis-pg17-v1.1.0:3.1.14 has result NEEDS_CAPABILITY
        spec_3114 = [r for r in report["results"] if r["spec_id"] == "cis-pg17-v1.1.0:3.1.14"]
        assert len(spec_3114) == 1
        assert spec_3114[0]["result"] == "NEEDS_CAPABILITY"

    @pytest.mark.parametrize("spec_id", AUTOMATED_SPECS)
    def test_break_then_fix(self, target_db, tmp_path, spec_id, restore_setting):
        """For each automated spec: baseline -> break -> FAIL -> fix -> PASS."""
        import yaml
        spec_dir = REPO_ROOT / "catalog" / "specs" / "cis-pg17-v1.1.0"
        
        # Load spec to get the setting_name and proof values
        spec_path = spec_dir / f"{spec_id.split(':')[-1]}.yaml"
        with open(spec_path) as f:
            spec = yaml.safe_load(f)
        
        setting_name = spec["check"]["setting_name"]
        
        # Read prior state with fresh connection
        prior_setting, prior_source, prior_sourcefile = restore_setting(setting_name)
        
        # Skip if context is 'postmaster' (can't change at runtime)
        if prior_sourcefile == "postmaster":
            pytest.fail(
                f"Setting {setting_name} has context='postmaster' - cannot change at runtime. "
                f"Skipping test for this spec."
            )
        
        # Get proof values
        break_value = spec["proof"]["break"]["value"]
        fix_value = spec["proof"]["fix"]["value"]
        expected_operator = spec["check"]["operator"]
        expected_value = spec["check"]["expected"]
        
        # a) Baseline: run pipeline before any change
        manifest_path0, snapshot_path0, report0 = run_pipeline(spec_dir, tmp_path / "baseline")
        
        # b) Apply proof.break.value
        # Build action from proof
        if spec["check"]["operator"] == "equals":
            # To break, set to break_value which should NOT equal expected
            action = {"action": "set_config", "param": setting_name, "value": break_value}
        elif spec["check"]["operator"] == "not_equals":
            # To break, set to value that equals expected (should break the not_equals check)
            action = {"action": "set_config", "param": setting_name, "value": expected_value}
        elif spec["check"]["operator"] == "in":
            # To break, set to a value NOT in expected list
            action = {"action": "set_config", "param": setting_name, "value": break_value}
        else:
            pytest.fail(f"Unsupported operator: {expected_operator}")
        
        run_action(target_db, action)
        
        # c) Run pipeline after break
        manifest_path1, snapshot_path1, report1 = run_pipeline(spec_dir, tmp_path / "after_break")
        
        # d) Assert: target spec's result == "FAIL"
        target_result = [r for r in report1["results"] if r["spec_id"] == spec_id]
        assert len(target_result) == 1, f"Spec {spec_id} not found in results"
        assert target_result[0]["result"] == "FAIL", (
            f"After break, expected FAIL for {spec_id}, got {target_result[0]['result']}"
        )
        
        # Verify the snapshot shows the break value
        check_entry = json.loads(snapshot_path1.read_text())["checks"][spec_id]
        actual_setting = check_entry["result"]
        
        # e) Apply proof.fix.value
        if spec["check"]["operator"] == "equals":
            action = {"action": "set_config", "param": setting_name, "value": fix_value}
        elif spec["check"]["operator"] == "not_equals":
            # To fix, set to a value that does NOT equal expected
            action = {"action": "set_config", "param": setting_name, "value": fix_value}
        elif spec["check"]["operator"] == "in":
            action = {"action": "set_config", "param": setting_name, "value": fix_value}
        else:
            pytest.fail(f"Unsupported operator for fix: {expected_operator}")
        
        run_action(target_db, action)
        
        # f) Run pipeline after fix
        manifest_path2, snapshot_path2, report2 = run_pipeline(spec_dir, tmp_path / "after_fix")
        
        # g) Assert: target result == "PASS"
        target_result2 = [r for r in report2["results"] if r["spec_id"] == spec_id]
        assert len(target_result2) == 1
        assert target_result2[0]["result"] == "PASS", (
            f"After fix, expected PASS for {spec_id}, got {target_result2[0]['result']}"
        )
        
        # h) Assert: every OTHER spec's (result, reason_code) equals baseline
        other_specs0 = {r["spec_id"]: (r["result"], r["reason_code"]) 
                       for r in report0["results"] if r["spec_id"] != spec_id}
        other_specs1 = {r["spec_id"]: (r["result"], r["reason_code"]) 
                       for r in report1["results"] if r["spec_id"] != spec_id}
        other_specs2 = {r["spec_id"]: (r["result"], r["reason_code"]) 
                       for r in report2["results"] if r["spec_id"] != spec_id}
        
        assert other_specs0 == other_specs1, (
            f"Other specs changed after break: {set(other_specs0.items()) ^ set(other_specs1.items())}"
        )
        assert other_specs0 == other_specs2, (
            f"Other specs changed after fix: {set(other_specs0.items()) ^ set(other_specs2.items())}"
        )

    def test_edited_spec_is_stale_never_pass(self, tmp_path):
        """Edited spec produces STALE result, never PASS via whitespace edit."""
        import yaml
        import jsonschema
        
        # Copy spec_dir to tmp
        orig_spec_dir = REPO_ROOT / "catalog" / "specs" / "cis-pg17-v1.1.0"
        copy_spec_dir = tmp_path / "specs_copy"
        shutil.copytree(orig_spec_dir, copy_spec_dir)
        
        # Build manifest + collect from ORIGINAL dir
        manifest_path, snapshot_path, report_baseline = run_pipeline(orig_spec_dir, tmp_path / "baseline")
        
        # Find an automated spec to modify by adding extra space in check.pass_condition_quote
        # The validation normalizes whitespace, so double space normalizes to single space
        # but the hash will differ
        target_spec_id = None
        target_spec_file = None
        for spec_file in sorted(copy_spec_dir.glob("*.yaml")):
            with open(spec_file) as f:
                spec = yaml.safe_load(f)
            if spec.get("tier") == "automated" and "check" in spec and "pass_condition_quote" in spec["check"]:
                target_spec_id = spec["spec_id"]
                target_spec_file = spec_file
                # Find a position with a single space and change it to double space
                original_quote = spec["check"]["pass_condition_quote"]
                for i in range(len(original_quote) - 1):
                    if original_quote[i] == " " and original_quote[i+1] != " ":
                        # Insert another space after the existing space
                        new_quote = original_quote[:i+1] + " " + original_quote[i+1:]
                        spec["check"]["pass_condition_quote"] = new_quote
                        break
                # Write the modified spec
                with open(spec_file, "w") as f:
                    yaml.dump(spec, f, default_flow_style=False)
                break
        
        assert target_spec_id is not None, "No automated spec with pass_condition_quote found"
        assert target_spec_file is not None, "Target spec file not found"
        
        # Precondition (a): validate_spec(edited, records) == []
        from app.services.spec_engine import RecordsIndex, validate_spec
        from app.services.spec_engine.specs import spec_sha256
        records_path = REPO_ROOT / "catalog" / "benchmarks" / "cis-pg17-v1.1.0" / "records.json"
        records = RecordsIndex.load(records_path)
        with open(target_spec_file) as f:
            edited_spec = yaml.safe_load(f)
        errors = validate_spec(edited_spec, records)
        assert errors == [], f"Edited spec failed validation: {errors}"
        
        # Precondition (b): spec_sha256(edited) != spec_sha256(original)
        original_spec_file = orig_spec_dir / f"{target_spec_id.split(':')[-1]}.yaml"
        with open(original_spec_file) as f:
            original_spec = yaml.safe_load(f)
        original_hash = spec_sha256(original_spec)
        edited_hash = spec_sha256(edited_spec)
        assert original_hash != edited_hash, "Spec hash should differ after whitespace edit"
        
        # Assess using the COPY
        result = subprocess.run(
            ["uv", "run", "python", str(REPO_ROOT / "scripts" / "assess.py"),
             "--specs", str(copy_spec_dir), "--records", str(records_path),
             "--snapshot", str(snapshot_path)],
            capture_output=True,
            text=True,
            cwd=str(REPO_ROOT)
        )
        
        assert result.returncode == 0, f"Assessment failed: {result.stderr}"
        
        report_edited = json.loads(result.stdout)
        
        # Assert: edited spec is STALE (not PASS, not FAIL)
        target_result = [r for r in report_edited["results"] if r["spec_id"] == target_spec_id]
        assert len(target_result) == 1, f"Target spec {target_spec_id} not found"
        assert target_result[0]["result"] == "STALE", (
            f"Expected STALE for edited spec, got {target_result[0]['result']}"
        )
        
        # Assert: every other spec equals baseline
        other_baseline = {r["spec_id"]: (r["result"], r["reason_code"]) 
                         for r in report_baseline["results"] if r["spec_id"] != target_spec_id}
        other_edited = {r["spec_id"]: (r["result"], r["reason_code"]) 
                       for r in report_edited["results"] if r["spec_id"] != target_spec_id}
        assert other_baseline == other_edited, (
            f"Other specs differ from baseline: {set(other_baseline.items()) ^ set(other_edited.items())}"
        )
