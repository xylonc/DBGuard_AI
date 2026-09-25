#!/usr/bin/env python3
"""Validate an upstream handoff, then serve its review UI or run/export a bundle."""
import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT/'backend')]


def main():
    from app.config import settings
    from services.sandbox_poc.handoff import SandboxHandoff
    from services.sandbox_poc.service import SandboxService
    from services.sandbox_poc.review_bundle import build_review_bundle
    from services.sandbox_poc.readiness import check_readiness
    from services.sandbox_poc.adaptive import LLMReviser
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--handoff', type=Path, required=True)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--check-only', action='store_true', help='Validate contracts without registry/Docker access')
    mode.add_argument('--check-registry', action='store_true', help='Read-only input and approval check; does not start Docker')
    mode.add_argument('--output', type=Path, help='Run once and save a new review ZIP instead of serving UI')
    parser.add_argument('--readiness-output', type=Path, help='Save the check-only/check-registry JSON report to a new file')
    parser.add_argument('--port', type=int, default=8011)
    args = parser.parse_args()
    if args.readiness_output and not (args.check_only or args.check_registry):
        parser.error('--readiness-output requires --check-only or --check-registry')
    if args.readiness_output and args.readiness_output.exists():
        parser.error('Readiness output already exists; choose a new file')
    handoff = SandboxHandoff.model_validate_json(args.handoff.read_text())
    reviser = LLMReviser(settings.sandbox_llm_base_url, settings.sandbox_llm_model,
                        settings.sandbox_llm_api_key) if settings.sandbox_llm_enabled else None
    service = SandboxService(settings.database_url, settings.sandbox_poc_image, reviser=reviser)
    if args.check_only or args.check_registry:
        report = check_readiness(service, handoff, check_registry=args.check_registry)
        rendered = json.dumps(report, indent=2) + '\n'
        if args.readiness_output:
            with args.readiness_output.open('x') as output:
                output.write(rendered)
        print(rendered, end='')
        return 2 if report['status'] == 'BLOCKED' else 0
    engine = service.validate_handoff(handoff)
    if not settings.sandbox_poc_enabled:
        parser.error('Set SANDBOX_POC_ENABLED=true on the local Docker host before execution')
    if args.output:
        # Refuse an existing output before allocating Docker resources.
        if args.output.exists():
            parser.error('Output already exists; choose a new file')
        result = service.run(handoff)
        data = build_review_bundle(handoff, result, engine)
        with args.output.open('xb') as output:
            output.write(data)
        print(f'Review bundle saved: {args.output}. DBA review is required; source was not modified.')
    else:
        import uvicorn
        from services.sandbox_poc.review_api import create_app
        uvicorn.run(create_app(handoff), host='127.0.0.1', port=args.port)


if __name__ == '__main__':
    raise SystemExit(main())
