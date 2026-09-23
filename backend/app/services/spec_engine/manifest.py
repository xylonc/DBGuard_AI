"""Manifest builder: converts CIS control specs into a check manifest.

The manifest is a plain JSON list of checks the collector must look up.
It never contains SQL built from spec text - only the query field from the spec.
"""
import json
from pathlib import Path

from .validate import validate_spec
from .records import RecordsIndex
from .specs import load_spec, spec_sha256

RECORDS_PATH = Path(__file__).resolve().parent.parent.parent.parent / "catalog" / "benchmarks" / "cis-pg17-v1.1.0" / "records.json"


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
    """
    # Load and validate all specs
    valid_specs: list[tuple[Path, dict]] = []
    all_errors: list[tuple[Path, list[str]]] = []

    for spec_path in sorted(spec_dir.glob("*.yaml")):
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

    return {
        "manifest_version": 1,
        "benchmark_id": records.benchmark_id,
        "checks": checks,
    }


def main(spec_dir: Path, out_path: Path) -> int:
    """CLI entry point for building a check manifest.

    Args:
        spec_dir: Path to directory containing .yaml spec files.
        out_path: Path where the JSON manifest will be written.

    Returns:
        0 on success, 1 on error.
    """
    try:
        records = RecordsIndex.load(RECORDS_PATH)
    except (OSError, ValueError, KeyError) as exc:
        print(f"FAIL: cannot load records from {RECORDS_PATH}: {exc}")
        return 1

    try:
        manifest = build_manifest(spec_dir, records)
    except ValueError as exc:
        print(f"FAIL: {exc}")
        return 1

    # Write as UTF-8 JSON with sorted keys, 2-space indent, trailing newline
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(manifest, sort_keys=True, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote manifest to {out_path}")
    return 0


if __name__ == "__main__":
    import sys
    if len(sys.argv) != 3:
        print("Usage: python -m app.services.spec_engine.manifest <spec_dir> <out_file>")
        sys.exit(1)
    spec_dir = Path(sys.argv[1])
    out_path = Path(sys.argv[2])
    sys.exit(main(spec_dir, out_path))
