#!/usr/bin/env python3
"""Build an API request from a v0.3 snapshot, exact specs and approved references."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "backend")]

from services.sandbox_poc.handoff import TemplateReference, build_handoff
from services.sandbox_poc.shared import SpecEngine


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--snapshot", type=Path, required=True)
    parser.add_argument("--template-ref", type=Path, required=True)
    parser.add_argument("--spec-dir", type=Path, required=True)
    parser.add_argument("--records", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    engine = SpecEngine.load(args.spec_dir, args.records)
    request = build_handoff(engine, json.loads(args.snapshot.read_text()),
                            TemplateReference.model_validate_json(args.template_ref.read_text()))
    args.output.write_text(request.model_dump_json(indent=2) + "\n")
    print(f"Handoff written: {args.output}")


if __name__ == "__main__":
    main()
