#!/usr/bin/env python3
"""Export exact existing registry identities without approving or modifying rows."""
import argparse
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT), str(ROOT / "backend")]


def main():
    from services.sandbox_poc.templates import export_reference
    from services.sandbox_poc.review_bundle import canonical_apply, is_fixture
    from services.sandbox_poc.shared import ContractError
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--template-version", type=int, required=True)
    parser.add_argument("--evidence-id", action="append", required=True)
    parser.add_argument("--environment", choices=["dev", "test", "prod"], default="dev")
    parser.add_argument("--registry-env", default="DATABASE_URL", help="Environment variable holding the registry DSN")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        parser.error("Output already exists; choose a new file")
    dsn = os.environ.get(args.registry_env)
    if not dsn:
        parser.error("The selected registry environment variable is not set")
    try:
        ref, template = export_reference(dsn, args.template_version, args.evidence_id, args.environment)
        canonical_apply(template.render())
        if is_fixture({"template": template.identity()}):
            raise ContractError("Demo/test records are not team approvals")
    except ContractError as exc:
        parser.error(str(exc))
    except Exception:
        parser.error("Registry reference export failed; check connectivity, permissions and record metadata")
    with args.output.open("x") as output:
        output.write(ref.model_dump_json(indent=2) + "\n")
    print(f"Pinned reference saved: {args.output}. No approvals or database rows were changed.")


if __name__ == "__main__":
    main()
