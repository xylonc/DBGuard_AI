"""Cross-contract validation tests.

These tests verify contract compliance across different contract types:
- snapshot, spec, fix-unit

Rules tested:
1. Every check_id in an example spec appears in the checks of a valid example snapshot
2. A fix_unit's spec_id resolves to an existing spec
"""

import json
import os
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parent.parent
sys_path = str(REPO_ROOT / "backend")
if sys_path not in __import__("sys").path:
    __import__("sys").path.insert(0, sys_path)


def load_json(path: Path) -> dict:
    """Load a JSON file."""
    return json.loads(path.read_text(encoding="utf-8"))


def load_yaml(path: Path) -> dict:
    """Load a YAML file."""
    import yaml

    return yaml.safe_load(path.read_text(encoding="utf-8"))


def get_spec_ids_from_specs_dir() -> set[str]:
    """Get all spec_ids from the specs directory."""
    specs_dir = REPO_ROOT / "catalog" / "specs" / "cis-pg17-v1.1.0"
    spec_ids = set()
    for yaml_file in specs_dir.glob("*.yaml"):
        spec = load_yaml(yaml_file)
        if "spec_id" in spec:
            spec_ids.add(spec["spec_id"])
    return spec_ids


def get_check_ids_from_snapshot(snapshot: dict) -> set[str]:
    """Get all check_ids from a snapshot's checks object."""
    return set(snapshot.get("checks", {}).keys())


def test_snapshot_checks_match_specs():
    """Every check_id in an example spec appears in the checks of a valid example snapshot."""
    # Load valid snapshot
    snapshot_path = REPO_ROOT / "tests" / "fixtures" / "phase0" / "snapshot-v0.3.0-valid.json"
    snapshot = load_json(snapshot_path)

    # Get check_ids from snapshot
    snapshot_check_ids = get_check_ids_from_snapshot(snapshot)

    # Get spec_ids
    spec_ids = get_spec_ids_from_specs_dir()

    # The snapshot should have a check for spec_id "cis-pg17-v1.1.0:3.1.20"
    # which is one of the specs in the directory
    expected_spec_id = "cis-pg17-v1.1.0:3.1.20"

    assert expected_spec_id in spec_ids, f"Spec {expected_spec_id} not found in specs directory"
    assert expected_spec_id in snapshot_check_ids, (
        f"Check {expected_spec_id} not found in snapshot checks: {snapshot_check_ids}"
    )


def test_fix_unit_spec_id_resolves_to_existing_spec():
    """A fix_unit's spec_id resolves to an existing spec."""
    # Load valid fix_unit
    fix_unit_path = REPO_ROOT / "tests" / "fixtures" / "phase0" / "fix-unit-log_connections.json"
    fix_unit = load_json(fix_unit_path)

    fix_unit_spec_id = fix_unit.get("spec_id")
    assert fix_unit_spec_id is not None, "fix_unit missing spec_id"

    # Get spec_ids from directory
    spec_ids = get_spec_ids_from_specs_dir()

    assert fix_unit_spec_id in spec_ids, (
        f"fix_unit spec_id {fix_unit_spec_id!r} does not resolve to any spec in the specs directory. "
        f"Available spec_ids: {spec_ids}"
    )


def test_fix_unit_spec_id_prefix_matches_benchmark():
    """fix_unit spec_id prefix matches RecordsIndex.benchmark_id."""
    # Load valid fix_unit
    fix_unit_path = REPO_ROOT / "tests" / "fixtures" / "phase0" / "fix-unit-log_connections.json"
    fix_unit = load_json(fix_unit_path)

    fix_unit_spec_id = fix_unit.get("spec_id")
    assert fix_unit_spec_id is not None, "fix_unit missing spec_id"

    # Load records.json to get benchmark_id
    records_path = REPO_ROOT / "catalog" / "benchmarks" / "cis-pg17-v1.1.0" / "records.json"
    records = load_json(records_path)

    benchmark_id = records.get("benchmark_id")
    if benchmark_id is None:
        # Extract from directory name
        benchmark_id = records_path.parent.name

    # spec_id should be prefix:recommendation
    prefix = fix_unit_spec_id.split(":")[0]

    assert prefix == benchmark_id, (
        f"fix_unit spec_id prefix {prefix!r} does not match benchmark_id {benchmark_id!r}"
    )


def test_all_specs_validate_against_schema():
    """Every spec in the specs directory validates against schema.json."""
    import jsonschema

    schema_path = REPO_ROOT / "catalog" / "specs" / "schema.json"
    schema = load_json(schema_path)

    specs_dir = REPO_ROOT / "catalog" / "specs" / "cis-pg17-v1.1.0"
    validator = jsonschema.Draft202012Validator(schema)

    for yaml_file in specs_dir.glob("*.yaml"):
        spec = load_yaml(yaml_file)
        errors = list(validator.iter_errors(spec))
        assert errors == [], (
            f"Spec {yaml_file.name} failed validation: {[str(e) for e in errors]}"
        )
