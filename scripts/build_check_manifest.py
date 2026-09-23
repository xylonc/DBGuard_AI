#!/usr/bin/env python3
"""Build a check manifest from CIS control specs.

Usage:
    python scripts/build_check_manifest.py --specs <dir> --out <file>

The manifest is written as UTF-8 JSON with sorted keys, 2-space indent,
and a trailing newline. Exit code is non-zero on any error.

Constraints:
- Only includes tier: automated specs.
- Never generates SQL - uses the query field from the spec.
- Output is sorted by spec_id for deterministic results.
"""
import argparse
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "backend"))

from app.services.spec_engine import RecordsIndex, RecordsIntegrityError, build_manifest  # noqa: E402

RECORDS_PATH = REPO_ROOT / "catalog" / "benchmarks" / "cis-pg17-v1.1.0" / "records.json"


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build a check manifest from CIS control specs."
    )
    parser.add_argument(
        "--specs",
        required=True,
        type=Path,
        help="Directory containing .yaml spec files",
    )
    parser.add_argument(
        "--out",
        required=True,
        type=Path,
        help="Output path for the JSON manifest",
    )
    args = parser.parse_args()

    try:
        records = RecordsIndex.load(RECORDS_PATH)
    except (OSError, ValueError, KeyError, RecordsIntegrityError) as exc:
        print(f"FAIL: cannot load records from {RECORDS_PATH}: {exc}", file=sys.stderr)
        return 1

    try:
        manifest = build_manifest(args.specs, records)
    except ValueError as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        return 1

    # Write as UTF-8 JSON with sorted keys, 2-space indent, trailing newline
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(
        __import__("json").dumps(manifest, sort_keys=True, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print(f"Wrote manifest to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
