#!/usr/bin/env python3
"""Assessment CLI: assess specs against a snapshot.

Usage:
    python scripts/assess.py --specs DIR --records PATH --snapshot PATH [--out PATH]

Exit codes:
    0: Report written successfully
    1: Any other error (not input validation)
    2: Invalid input (spec, snapshot, or duplicate spec_id)

The report is written as UTF-8 JSON with sorted keys, 2-space indent,
and a trailing newline.
"""

import argparse
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
sys.path.insert(0, str(REPO_ROOT / "backend"))

from app.services.spec_engine import RecordsIndex, load_spec, assess  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Assess CIS control specs against a snapshot."
    )
    parser.add_argument(
        "--specs",
        required=True,
        type=Path,
        help="Directory containing .yaml spec files",
    )
    parser.add_argument(
        "--records",
        required=True,
        type=Path,
        help="Path to records.json file",
    )
    parser.add_argument(
        "--snapshot",
        required=True,
        type=Path,
        help="Path to snapshot JSON file",
    )
    parser.add_argument(
        "--out",
        type=Path,
        help="Output path for the report JSON (default: stdout)",
    )
    args = parser.parse_args()

    # Validate paths
    if not args.specs.exists():
        print(f"FAIL: --specs directory does not exist: {args.specs}", file=sys.stderr)
        return 2

    if not args.records.exists():
        print(f"FAIL: --records file does not exist: {args.records}", file=sys.stderr)
        return 2

    if not args.snapshot.exists():
        print(f"FAIL: --snapshot file does not exist: {args.snapshot}", file=sys.stderr)
        return 2

    # Load records
    try:
        records = RecordsIndex.load(args.records)
    except (OSError, ValueError, KeyError) as exc:
        print(f"FAIL: cannot load records from {args.records}: {exc}", file=sys.stderr)
        return 2

    # Load snapshot
    try:
        snapshot_text = args.snapshot.read_text(encoding="utf-8")
        snapshot = json.loads(snapshot_text)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"FAIL: cannot load snapshot from {args.snapshot}: {exc}", file=sys.stderr)
        return 2

    # Load specs
    yaml_files = sorted(args.specs.glob("*.yaml"))
    if not yaml_files:
        print(f"FAIL: no .yaml spec files found in {args.specs}", file=sys.stderr)
        return 2

    specs: list[dict] = []
    for spec_path in yaml_files:
        try:
            spec = load_spec(spec_path)
            specs.append(spec)
        except Exception as exc:
            print(f"FAIL: cannot load spec from {spec_path}: {exc}", file=sys.stderr)
            return 2

    # Run assessment (includes all validation)
    try:
        report = assess(specs, snapshot, records)
    except ValueError as exc:
        print(f"FAIL: assessment failed: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:
        print(f"FAIL: unexpected error: {exc}", file=sys.stderr)
        return 1

    # Write output
    report_json = json.dumps(report, sort_keys=True, indent=2, ensure_ascii=False) + "\n"

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(report_json, encoding="utf-8")
        print(f"Wrote report to {args.out}")
    else:
        print(report_json, end="")

    return 0


if __name__ == "__main__":
    sys.exit(main())
