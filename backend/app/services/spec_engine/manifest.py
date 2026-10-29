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

    return manifest_from_specs([spec for _, spec in valid_specs], records)


# Manifest/snapshot key for a spec's applies_when evidence. '#' never occurs in
# a spec_id (see schema.json), so it cannot collide with a real spec.
CONDITION_SUFFIX = "#applies_when"


def condition_check_id(spec_id: str) -> str:
    return spec_id + CONDITION_SUFFIX


def collects_evidence(spec: dict) -> bool:
    """Automated specs and parameterised specs with a policy check are collected.

    Catalog checks (F6) read the collected baseline sections, not a manifest query.
    """
    return (spec.get("tier") in ("automated", "parameterised") and isinstance(spec.get("check"), dict)
            and spec["check"].get("kind") == "setting")


def manifest_from_specs(specs: list[dict], records: RecordsIndex) -> dict:
    """Build the same manifest from exact handoff specs, without temporary files."""
    if not specs or len({s["spec_id"] for s in specs}) != len(specs):
        raise ValueError("Specs must be nonempty with unique IDs")
    for spec in specs:
        errors = validate_spec(spec, records)
        if errors:
            raise ValueError("; ".join(errors))
    checks = []
    for spec in specs:
        if not collects_evidence(spec):
            continue
        spec_hash = spec_sha256(spec)
        checks.append({"spec_id": spec["spec_id"], "spec_hash": spec_hash,
                       **{key: spec["check"][key] for key in ("kind", "setting_name", "query")}})
        condition = spec.get("applies_when")
        if condition is not None:
            # The condition setting is collected like any check, under its own key
            # and pinned to the same spec hash, so a missing or stale condition is
            # visible to the assessor instead of being read as "does not apply".
            checks.append({"spec_id": condition_check_id(spec["spec_id"]), "spec_hash": spec_hash,
                           "kind": "setting", "setting_name": condition["setting_name"],
                           "query": "SHOW " + condition["setting_name"]})
    checks.sort(key=lambda check: check["spec_id"])
    manifest = {"manifest_version": 1, "benchmark_id": records.benchmark_id, "checks": checks}
    schema_path = Path(__file__).resolve().parents[4] / "catalog/specs/contracts/check-manifest-v1.json"
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    _validate_manifest(manifest, schema)
    return manifest


def manifest_text(manifest: dict) -> str:
    """Canonical bytes shared with the manifest CLI and collector hash binding."""
    return json.dumps(manifest, sort_keys=True, indent=2, ensure_ascii=False) + "\n"


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
