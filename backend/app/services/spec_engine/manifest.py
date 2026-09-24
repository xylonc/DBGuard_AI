"""Manifest builder: converts CIS control specs into a check manifest.

The manifest is a plain JSON list of checks the collector must look up.
It never contains SQL built from spec text - only the query field from the spec.
"""
import json
from pathlib import Path

from .validate import validate_spec
from .records import RecordsIndex
from .specs import load_spec, spec_sha256


def build_manifest(spec_dir: Path, records: RecordsIndex) -> dict:
    """Build a check manifest from spec files in a directory.

    Args:
        spec_dir: Path to directory containing .yaml spec files.
        records: Loaded RecordsIndex for validation.

    Returns:
        A manifest dict with manifest_version, benchmark_id, and checks list.

    Raises:
        ValueError: If any spec fails validation. The error message lists
                    every failing file and its errors.
        ValueError: If the directory contains no .yaml files.
    """
    # Find all .yaml files
    yaml_files = sorted(spec_dir.glob("*.yaml"))
    if not yaml_files:
        raise ValueError(f"No .yaml spec files found in {spec_dir}")

    # Load and validate all specs
    valid_specs: list[tuple[Path, dict]] = []
    all_errors: list[tuple[Path, list[str]]] = []

    for spec_path in yaml_files:
        spec = load_spec(spec_path)
        errors = validate_spec(spec, records)
        if errors:
            all_errors.append((spec_path, errors))
        else:
            valid_specs.append((spec_path, spec))

    # If any spec failed, raise one error listing all failures
    if all_errors:
        error_lines = ["Some specs failed validation:"]
        for path, errs in all_errors:
            error_lines.append(f"  {path.name}:")
            for err in errs:
                error_lines.append(f"    - {err}")
        raise ValueError("\n".join(error_lines))

    # Filter to only automated tier specs
    automated_specs = [
        (path, spec) for path, spec in valid_specs
        if spec.get("tier") == "automated"
    ]

    # Build checks list
    checks: list[dict] = []
    for spec_path, spec in automated_specs:
        check = spec["check"]
        checks.append({
            "spec_id": spec["spec_id"],
            "spec_hash": spec_sha256(spec),
            "kind": check["kind"],
            "setting_name": check["setting_name"],
            "query": check["query"],
        })

    # Sort by spec_id for deterministic output
    checks.sort(key=lambda c: c["spec_id"])

    manifest = {
        "manifest_version": 1,
        "benchmark_id": records.benchmark_id,
        "checks": checks,
    }

    # Validate against schema before returning
    schema_path = spec_dir.parent.parent / "specs" / "contracts" / "check-manifest-v1.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    _validate_manifest(manifest, schema)

    return manifest


def _validate_manifest(manifest: dict, schema: dict) -> None:
    """Simple JSON Schema validation for check-manifest-v1.json."""
    # Top-level required fields
    for field in ["manifest_version", "benchmark_id", "checks"]:
        assert field in manifest, f"Missing top-level field: {field}"

    assert manifest["manifest_version"] == 1, f"manifest_version must be 1, got {manifest['manifest_version']}"

    # Each check
    for check in manifest["checks"]:
        for field in ["spec_id", "spec_hash", "kind", "setting_name", "query"]:
            assert field in check, f"Missing check field: {field}"
        assert check["kind"] == "setting", f"kind must be 'setting', got {check['kind']}"
        assert isinstance(check["spec_hash"], str), "spec_hash must be a string"
        assert len(check["spec_hash"]) == 64, "spec_hash must be 64 chars"
        assert all(c in "0123456789abcdef" for c in check["spec_hash"]), "spec_hash must be hex"
