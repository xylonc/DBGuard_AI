#!/usr/bin/env python3
"""Build an API request from a v0.3 snapshot, exact specs and approved references."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "backend")]

from services.sandbox_poc.handoff import SandboxHandoff, TemplateReference, build_handoff
from services.sandbox_poc.shared import SpecEngine
from services.sandbox_poc.collector_intake import from_collector_bundle


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--snapshot", type=Path)
    source.add_argument("--collector-bundle", type=Path, help="Alias for native v0.3 collector output; v0.2 requires recollection")
    parser.add_argument("--template-ref", type=Path, required=True)
    parser.add_argument("--spec-dir", type=Path, required=True)
    parser.add_argument("--records", type=Path, required=True)
    parser.add_argument("--assessment", type=Path, help="Optional assessment-report-v1 from scripts/assess.py; must match exact snapshot and specs")
    parser.add_argument('--retry-mode', choices=['repeat', 'adaptive'], default='repeat')
    parser.add_argument('--retry-template-ref', type=Path, action='append', default=[], help='Additional exact approved candidate reference; at most two')
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    engine = SpecEngine.load(args.spec_dir, args.records)
    snapshot = json.loads((args.snapshot or args.collector_bundle).read_text())
    if args.collector_bundle:
        snapshot = from_collector_bundle(snapshot, engine)
    request = build_handoff(engine, snapshot,
                            TemplateReference.model_validate_json(args.template_ref.read_text()),
                            assessment=json.loads(args.assessment.read_text()) if args.assessment else None)
    if len(args.retry_template_ref) > 2:
        parser.error('At most two approved alternative references are supported')
    request.retry_mode = args.retry_mode
    request.retry_template_refs = [TemplateReference.model_validate_json(p.read_text()) for p in args.retry_template_ref]
    request = SandboxHandoff.model_validate(request.model_dump())
    with args.output.open("x") as output:
        output.write(request.model_dump_json(indent=2) + "\n")
    print(f"Handoff written: {args.output}")


if __name__ == "__main__":
    main()
