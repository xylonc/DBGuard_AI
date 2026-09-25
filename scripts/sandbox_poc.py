#!/usr/bin/env python3
"""Local entry point; creates disposable databases, never remediates a target."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import signal
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "backend")]

from services.sandbox_poc.runtime import DisposablePostgres
from services.sandbox_poc.shared import SpecEngine
from services.sandbox_poc.templates import ApprovedTemplate, from_registry
from services.sandbox_poc.workflow import RemediationLoop


def demo_template() -> ApprovedTemplate:
    """Synthetic approval for disposable demos only; never alters the registry."""
    sql = (ROOT / "backend/app/templates/set_config_parameter.sql.j2").read_text()
    return ApprovedTemplate("set_config_parameter", 1, sql, hashlib.sha256(sql.encode()).hexdigest(),
                            "TEST FIXTURE ONLY", ({"document_id": "demo-fixture", "demo_only": True},))


def run_demo(engine: SpecEngine, image: str, source: str, runtime_factory=None) -> dict:
    target = DisposablePostgres(image)
    result = None
    try:
        target.start()
        underlying = "on" if source == "auto" else "off"
        target.write_config("postgresql.conf", f"\nlog_connections = '{underlying}'\nlog_disconnections = 'on'\n")
        if source == "auto":
            target.sql("ALTER SYSTEM SET log_connections = 'off';")
        target.activate({"log_connections": "off", "log_disconnections": "on"})
        snapshot = engine.collect(target)
        assessment = engine.assess(snapshot)
        result = RemediationLoop(engine, demo_template(), runtime_factory or
                                 (lambda: DisposablePostgres(image))).run(snapshot, assessment)
        result.update(demo_only=True, source_snapshot=snapshot, source_assessment=assessment)
    finally:
        try:
            cleanup = target.close()
        except Exception as exc:
            if result is None:
                raise
            cleanup = {"verified": False, "error": str(exc)}
            result["status"] = "CLEANUP_FAILED"
        if result is not None:
            result["demo_target_cleanup"] = cleanup
    return result


def main() -> int:
    def terminate(signum, frame):
        raise KeyboardInterrupt("Termination requested; cleaning up disposable databases")
    signal.signal(signal.SIGTERM, terminate)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("demo", "validate"))
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--image", default="postgres:17-bookworm")
    parser.add_argument("--prior-source", choices=("conf", "auto"), default="conf")
    parser.add_argument("--spec-dir", type=Path, default=ROOT / "catalog/specs/cis-pg17-v1.1.0")
    parser.add_argument("--records", type=Path, default=ROOT / "catalog/benchmarks/cis-pg17-v1.1.0/records.json")
    parser.add_argument("--input", type=Path, help="JSON containing snapshot, assessment and template_ref")
    args = parser.parse_args()
    engine = SpecEngine.load(args.spec_dir, args.records)
    if args.mode == "demo":
        result = run_demo(engine, args.image, args.prior_source)
    else:
        if not args.input or not os.environ.get("DATABASE_URL"):
            parser.error("validate requires --input and DATABASE_URL for read-only registry access")
        data = json.loads(args.input.read_text())
        ref = data["template_ref"]
        template = from_registry(os.environ["DATABASE_URL"], ref["version"], ref["sha256"],
                                 ref["evidence_refs"], ref.get("environment", "dev"))
        result = RemediationLoop(engine, template, lambda: DisposablePostgres(args.image)).run(
            data["snapshot"], data["assessment"])
        result["demo_only"] = False
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps({"status": result["status"], "attempts": len(result["attempts"]),
                      "evidence": str(args.output.resolve()), "demo_only": result["demo_only"]}))
    return 0 if result["status"] == "VERIFIED" else 1


if __name__ == "__main__":
    raise SystemExit(main())
