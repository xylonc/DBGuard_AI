#!/usr/bin/env python3
"""DBGuardAI — Schema validator

Validates a collector bundle (envelope.json + sections/) against the pydantic
models in manifest.py.

Usage:
    python3 test/validate_schema.py <bundle-dir>
"""

import json
import sys
from pathlib import Path

# manifest.py lives at the repo root (one level up from collector/)
_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT))

from manifest import (  # noqa: E402
    CollectionStatus,
    Envelope,
    GapReason,
    RedactionClass,
)


def validate_section_json(bundle_dir: Path, section_name: str, field_name: str,
                          expected_list: bool = True) -> list[str]:
    """Validate a section file exists, is valid JSON, and has expected structure."""
    errors: list[str] = []
    path = bundle_dir / "sections" / f"{section_name}.json"

    if not path.exists():
        errors.append(f"Missing section: {section_name}.json")
        return errors

    try:
        data = json.loads(path.read_text())
    except json.JSONDecodeError as exc:
        errors.append(f"Invalid JSON in {section_name}.json: {exc}")
        return errors

    if expected_list and not isinstance(data, list):
        errors.append(
            f"{field_name} expected a JSON array, got {type(data).__name__}: "
            f"{data}"
        )

    if isinstance(data, list) and field_name == "log_connections" and len(data) == 1:
        # log_connections returns a single object or []
        pass

    return errors


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 validate_schema.py <bundle-dir>")
        sys.exit(1)

    bundle_dir = Path(sys.argv[1])
    envelope_path = bundle_dir / "envelope.json"

    print(f"Validating bundle: {bundle_dir}")
    print(f"Schema: manifest.py (collector spec v0.2.0)")
    print()

    errors: list[str] = []

    # ── Envelope ──────────────────────────────────────────────────────────
    if not envelope_path.exists():
        errors.append("FATAL: envelope.json not found")
        for e in errors:
            print(e)
        sys.exit(1)

    try:
        envelope_data = json.loads(envelope_path.read_text())
    except json.JSONDecodeError as exc:
        print(f"FATAL: envelope.json is not valid JSON: {exc}")
        sys.exit(1)

    # Check envelope model
    try:
        env = Envelope.model_validate(envelope_data.get("envelope", envelope_data))
        print(f"Envelope: VALID")
        print(f"  schema_version  = {env.schema_version}")
        print(f"  collector_version = {env.collector_version}")
        print(f"  status          = {env.status}")
        print(f"  gaps            = {len(env.gaps)}")
        print(f"  redactions      = {len(env.redactions)}")
    except Exception as exc:
        errors.append(f"Envelope validation failed: {exc}")

    # ── Sections ─────────────────────────────────────────────────────────
    sections_to_check = [
        ("log_connections", "CIS 5.1 log_connections setting"),
        ("public_schema_acl", "CIS 5.2 public schema ACL"),
        ("password_storage", "CIS 5.3 password storage"),
    ]

    for section_name, description in sections_to_check:
        result = validate_section_json(bundle_dir, section_name, description)
        if result:
            for e in result:
                errors.append(e)
        else:
            # Check that the section has actual content (not just [])
            path = bundle_dir / "sections" / f"{section_name}.json"
            data = json.loads(path.read_text())
            if data:
                print(f"Section {section_name}: VALID ({len(data)} entries)")
            else:
                errors.append(
                    f"Section {section_name} is empty [] — no data collected"
                )

    # ── SHA256SUMS ────────────────────────────────────────────────────────
    sha_path = bundle_dir / "SHA256SUMS"
    if sha_path.exists():
        lines = sha_path.read_text().strip().splitlines()
        print(f"SHA256SUMS: present ({len(lines)} entries)")
        if len(lines) == 0:
            errors.append("SHA256SUMS is empty")
    else:
        errors.append("SHA256SUMS not found")

    # ── Summary ───────────────────────────────────────────────────────────
    print()
    if errors:
        print("ERRORS:")
        for e in errors:
            print(f"  - {e}")
        sys.exit(1)
    else:
        print("All validations passed!")
        sys.exit(0)


if __name__ == "__main__":
    main()
