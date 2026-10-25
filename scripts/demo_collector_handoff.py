#!/usr/bin/env python3
"""Run Xylon's collector on a disposable PG17 target and export the review evidence."""
import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT/'backend')]


def main():
    from services.sandbox_poc.collector_demo import run_collector_demo
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output-dir', type=Path, required=True, help='A new directory; existing files are never overwritten')
    args = parser.parse_args()
    if args.output_dir.exists():
        parser.error('Output directory already exists; choose a new directory')
    print('Using Xylon\'s collector and owned disposable PG17 databases.', flush=True)
    print('Approval records are DEMO_FIXTURE_ONLY; no LLM or existing registry is used.', flush=True)
    result = run_collector_demo(args.output_dir)
    print(f"Result: {result['status']}. Evidence: {args.output_dir}")
    print(f"Fixture cleanup verified: {result['fixture_cleanup_verified']}")
    return 0 if result['status'] == 'VERIFIED' else 2


if __name__ == '__main__':
    raise SystemExit(main())
