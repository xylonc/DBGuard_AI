#!/usr/bin/env python3
"""DBGuardAI — Schema validator (development throwaway)

Validates a collector bundle directory against the pydantic models from
manifest.py. Exits 0 if valid, 1 if invalid, printing errors to stdout.

Usage:
    python validate_schema.py <bundle-dir>
"""

import json
import sys
import traceback
from pathlib import Path

try:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
    from manifest import Manifest, SCHEMA_VERSION
except ImportError:
    print("FATAL: Cannot import manifest.py. Ensure this script runs from the collector/test/ directory.")
    sys.exit(1)


def validate_section(model_class, data, section_name):
    """Validate a section's JSON data against a pydantic model."""
    try:
        model_class.model_validate(data)
        return True, []
    except Exception as e:
        return False, [f"  {section_name}: {e}"]


def validate_bundle(bundle_dir):
    """Validate all sections of a collector bundle."""
    bundle_path = Path(bundle_dir)
    sections_dir = bundle_path / "sections"
    envelope_path = bundle_path / "envelope.json"

    errors = []

    if not envelope_path.exists():
        errors.append("FATAL: envelope.json not found")
        return errors

    with open(envelope_path) as f:
        envelope = json.load(f)

    # Check schema version
    if envelope.get('envelope', {}).get('schema_version') != SCHEMA_VERSION:
        errors.append(
            f"SCHEMA MISMATCH: envelope version {envelope.get('envelope', {}).get('schema_version')} "
            f"!= expected {SCHEMA_VERSION}"
        )

    # Check top-level model validation
    try:
        Manifest.model_validate(envelope)
        print("Envelope: VALID")
    except Exception as e:
        errors.append(f"Envelope: {e}")

    # Validate each section
    section_validators = {
        'instance': (lambda d: d is not None, "section:instance"),
        'configuration': (lambda d: d is not None, "section:configuration"),
        'authentication': (lambda d: d is not None, "section:authentication"),
        'privileges': (lambda d: d is not None, "section:privileges"),
        'structure': (lambda d: d is not None, "section:structure"),
        'logging': (lambda d: d is not None, "section:logging"),
        'replication': (lambda d: d is not None, "section:replication"),
        'operational': (lambda d: d is not None, "section:operational"),
    }

    for section_name, (validator, label) in section_validators.items():
        section_file = sections_dir / f"{section_name}.json"
        if not section_file.exists():
            errors.append(f"Missing section file: {section_name}.json")
            continue

        with open(section_file) as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError as e:
                errors.append(f"Invalid JSON in {section_name}.json: {e}")
                continue

        if not validator(data):
            errors.append(f"Invalid structure in {section_name}: {data}")
        else:
            print(f"Section {section_name}: VALID ({type(data).__name__}, {len(str(data))} chars)")

    # Check SHA256SUMS
    sha_file = bundle_path / "SHA256SUMS"
    if sha_file.exists():
        print("SHA256SUMS: present")
        with open(sha_file) as f:
            lines = f.readlines()
        if len(lines) > 0:
            print(f"  Contains {len(lines)} checksums")
        else:
            errors.append("SHA256SUMS is empty")
    else:
        errors.append("SHA256SUMS not found")

    return errors


def main():
    if len(sys.argv) < 2:
        print("Usage: python validate_schema.py <bundle-dir>")
        sys.exit(1)

    bundle_dir = sys.argv[1]

    print(f"Validating bundle: {bundle_dir}")
    print(f"Expected schema version: {SCHEMA_VERSION}")
    print("")

    errors = validate_bundle(bundle_dir)

    if errors:
        print("\nERRORS:")
        for err in errors:
            print(err)
        sys.exit(1)
    else:
        print("\nAll validations passed!")
        sys.exit(0)


if __name__ == '__main__':
    main()
