#!/usr/bin/env python3
"""Validate spec files against the parsed benchmark records.

Usage:
    python scripts/validate_specs.py <spec.yaml | directory>

This script contains NO validation rules. Every rule lives in
backend/app/services/spec_engine, so the CLI and the tests can never disagree.

Exit code: 0 if every spec is valid, 1 if any spec is invalid, 2 on bad usage.
"""

import sys
from pathlib import Path
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "backend"))

from app.services.spec_engine import (  # noqa: E402
    PolicyProfileError,
    RecordsIndex,
    RecordsIntegrityError,
    load_default_profile,
    load_spec,
    validate_spec,
)
from app.services.spec_engine.policy import default_profile_path, profile_value_errors  # noqa: E402

RECORDS_PATH = REPO_ROOT / "catalog" / "benchmarks" / "cis-pg17-v1.1.0" / "records.json"


def main(argv: list[str]) -> int:
    # Never crash on non-ASCII text in a Windows console.
    sys.stdout.reconfigure(encoding="utf-8", errors="backslashreplace")
    if len(argv) != 2:
        print("Usage: python scripts/validate_specs.py <spec.yaml | directory>")
        return 2
    target = Path(argv[1])
    if target.is_file():
        files = [target]
    elif target.is_dir():
        files = sorted(target.glob("*.yaml"))
    else:
        print(f"FAIL {target}: path does not exist")
        return 2
    if not files:
        # An empty directory must not look like a passing run.
        print(f"FAIL {target}: no .yaml spec files found")
        return 1
    try:
        records = RecordsIndex.load(RECORDS_PATH)
    except (OSError, ValueError, KeyError, RecordsIntegrityError) as exc:
        print(f"FAIL {RECORDS_PATH}: cannot load records: {exc}")
        return 1
    all_valid = True
    specs = []
    for path in files:
        try:
            spec = load_spec(path)
        except (OSError, yaml.YAMLError) as exc:
            print(f"FAIL {path}: cannot load spec: {exc}")
            all_valid = False
            continue
        specs.append(spec)
        errors = validate_spec(spec, records)
        if errors:
            all_valid = False
            print(f"FAIL {path}:")
            for error in errors:
                print(f"  - {error}")
        else:
            print(f"OK {path}")
    if target.is_dir() and target.resolve() == (REPO_ROOT / "catalog" / "specs" / records.benchmark_id).resolve():
        # The installed catalog directory also checks the installed policy profile:
        # every value must belong to a policy spec, fix must pass and break fail.
        profile_path = default_profile_path(records.benchmark_id)
        try:
            profile = load_default_profile(records)
        except (OSError, PolicyProfileError) as exc:
            print(f"FAIL {profile_path}: {exc}")
            return 1
        if profile is not None:
            errors = profile_value_errors(profile, specs, strict=True)
            if errors:
                all_valid = False
                print(f"FAIL {profile_path}:")
                for error in errors:
                    print(f"  - {error}")
            else:
                state = f"approved by {profile.approved_by}" if profile.approved else "UNAPPROVED"
                print(f"PROFILE {profile_path}: valid ({len(profile.values)} values, {state})")
    return 0 if all_valid else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
