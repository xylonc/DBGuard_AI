"""Assessment engine: pure function from validated specs + snapshot to report.

This module implements the assessment engine as a pure function:
- assess(specs, snapshot, records) -> dict

It uses no database, no network, and no clock. The same inputs always
produce identical output.
"""

import json
import os
from pathlib import Path
from typing import Any

from jsonschema import Draft7Validator

from .operators import equals, in_, not_equals
from .records import RecordsIndex
from .specs import spec_sha256
from .validate import OPERATORS, validate_spec

# Compute REPO_ROOT from this file's location
# assess.py is at backend/app/services/spec_engine/assess.py
# So parent.parent.parent.parent.parent = backend/../ = /workspace/DBGuardAI
REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent.parent


def _validate_snapshot(snapshot: dict[str, Any], schema_path: Path) -> list[str]:
    """Validate snapshot against v0.3.0 JSON Schema using jsonschema.

    Returns a list of error messages. Empty list means valid.
    """
    errors: list[str] = []
    try:
        with open(schema_path, "r", encoding="utf-8") as f:
            schema = json.load(f)
        validator = Draft7Validator(schema)
        for error in validator.iter_errors(snapshot):
            errors.append(error.message)
    except Exception as e:
        errors.append(f"JSON schema validation error: {e}")
    return errors


def _decide(spec: dict[str, Any], entry: dict[str, Any] | None, spec_hash: str) -> tuple[str, str]:
    """Decide result for a single spec based on entry and hash.

    Returns (result, reason_code) at the first match, returning at the first
    condition that matches in this order:

    1. tier manual_checklist or parameterised -> ("MANUAL", "tier_manual")
    2. tier needs_capability -> ("NEEDS_CAPABILITY", "tier_needs_capability")
    3. no entry -> ("NOT_COLLECTED", "no_entry")
    4. entry spec_hash != spec_hash -> ("STALE", "hash_mismatch")
    5. status not_collected -> ("NOT_COLLECTED", "status_not_collected")
    6. status error -> ("ERROR", "status_error")
    7. result is not a str -> ("ERROR", "non_string_result")
    8. ok = OPERATORS[operator](result, expected) -> ("PASS", "operator_true") if ok else ("FAIL", "operator_false")
    """
    tier = spec.get("tier", "")

    # 1. tier manual_checklist or parameterised
    if tier in ("manual_checklist", "parameterised"):
        return ("MANUAL", "tier_manual")

    # 2. tier needs_capability
    if tier == "needs_capability":
        return ("NEEDS_CAPABILITY", "tier_needs_capability")

    # Allow-list automated tier (only automated specs reach the operator check)
    if tier != "automated":
        raise ValueError(f"unknown tier: {tier!r}")

    # 3. no entry
    if entry is None:
        return ("NOT_COLLECTED", "no_entry")

    # 4. hash mismatch (checked before status to report stale data regardless of status)
    collected_spec_hash = entry.get("spec_hash")
    if collected_spec_hash != spec_hash:
        return ("STALE", "hash_mismatch")

    # 5. status not_collected
    status = entry.get("status")
    if status == "not_collected":
        return ("NOT_COLLECTED", "status_not_collected")

    # 6. status error
    if status == "error":
        return ("ERROR", "status_error")

    if status != "ok":
        raise ValueError(f"unknown status: {status!r}")

    result_value = entry.get("result")

    # 7. result is not a str
    if not isinstance(result_value, str):
        return ("ERROR", "non_string_result")

    check = spec.get("check", {})
    operator = check.get("operator")
    expected = check.get("expected")

    ok = OPERATORS[operator](result_value, expected)
    return ("PASS", "operator_true") if ok else ("FAIL", "operator_false")


def assess(specs: list[dict[str, Any]], snapshot: dict[str, Any], records: RecordsIndex) -> dict[str, Any]:
    """Assess specs against a snapshot.

    Args:
        specs: List of validated spec dicts.
        snapshot: A snapshot dict that passes v0.3.0 JSON Schema validation.
        records: RecordsIndex for validation.

    Returns:
        An assessment report dict.

    Raises:
        ValueError: If snapshot fails v0.3.0 validation, any spec fails validate_spec,
                   or there are duplicate spec_ids.
    """
    # Validate inputs first
    schema_path = REPO_ROOT / "catalog" / "specs" / "contracts" / "snapshot-v0.3.0.json"
    snapshot_errors = _validate_snapshot(snapshot, schema_path)
    if snapshot_errors:
        raise ValueError("Snapshot validation failed:\n" + "\n".join(snapshot_errors))

    # Validate specs and check for duplicate spec_ids
    seen_spec_ids: set[str] = set()
    for i, spec in enumerate(specs):
        if not isinstance(spec, dict):
            raise ValueError(f"spec[{i}] must be a mapping")
        spec_id = spec.get("spec_id")
        if spec_id is None:
            raise ValueError(f"spec[{i}] missing spec_id")
        if spec_id in seen_spec_ids:
            raise ValueError(f"Duplicate spec_id: {spec_id}")
        seen_spec_ids.add(spec_id)

    spec_errors: list[str] = []
    for i, spec in enumerate(specs):
        spec_id = spec.get("spec_id")
        spec_errors.extend([f"spec[{i}] ({spec_id or 'unknown'}): {e}" for e in validate_spec(spec, records)])
    if spec_errors:
        raise ValueError("Spec validation failed:\n" + "\n".join(spec_errors))

    # Build checks index from snapshot
    snapshot_checks: dict[str, dict[str, Any]] = snapshot.get("checks", {})

    # Build spec index by spec_id
    spec_by_id: dict[str, dict[str, Any]] = {}
    for spec in specs:
        spec_by_id[spec["spec_id"]] = spec

    # Compute results for each spec
    results: list[dict[str, Any]] = []

    # Track orphan checks (in snapshot but no spec)
    orphan_checks: list[str] = []

    for spec in specs:
        spec_id = spec["spec_id"]
        spec_hash = spec_sha256(spec)
        tier = spec.get("tier", "")
        title = ""

        # Extract title from ref
        ref = spec.get("ref", {})
        if isinstance(ref, dict):
            title = ref.get("title", "")

        # Determine result using _decide
        entry = snapshot_checks.get(spec_id)
        result, reason_code = _decide(spec, entry, spec_hash)

        # Build result row
        row: dict[str, Any] = {
            "spec_id": spec_id,
            "title": title,
            "tier": tier,
            "result": result,
            "reason_code": reason_code,
        }

        if tier == "automated" and entry is not None:
            check = spec.get("check", {})
            setting_name = check.get("setting_name")
            operator = check.get("operator")
            expected = check.get("expected")

            row["setting_name"] = setting_name
            row["operator"] = operator
            row["expected"] = expected
            row["spec_hash"] = spec_hash
            row["collected_spec_hash"] = entry.get("spec_hash")

            if entry.get("status") == "ok":
                row["observed"] = entry.get("result")

        results.append(row)

    # Find orphan checks (in snapshot but no spec)
    for spec_id in snapshot_checks:
        if spec_id not in spec_by_id:
            orphan_checks.append(spec_id)
    orphan_checks.sort()

    # Compute check_count
    env = snapshot.get("envelope", {})
    manifest = env.get("manifest", {})
    declared = manifest.get("check_count")
    actual = len(snapshot_checks)
    matches = declared == actual if isinstance(declared, int) else None

    # Compute summary counts
    summary = {
        "PASS": 0,
        "FAIL": 0,
        "MANUAL": 0,
        "NEEDS_CAPABILITY": 0,
        "NOT_COLLECTED": 0,
        "STALE": 0,
        "ERROR": 0,
    }
    for row in results:
        res = row["result"]
        if res in summary:
            summary[res] += 1

    # Compute server version
    baseline = snapshot.get("baseline", {})
    identity = baseline.get("identity", {})
    server_version_num = identity.get("server_version_num")
    server_major = server_version_num // 10000 if isinstance(server_version_num, int) else None

    # Determine version mismatch
    benchmark_id = manifest.get("benchmark_id")
    version_mismatch = None

    if benchmark_id and server_major:
        if benchmark_id.startswith("cis-pg"):
            try:
                benchmark_major = int(benchmark_id.split("-")[1][2:])
                version_mismatch = benchmark_major != server_major
            except (ValueError, IndexError):
                pass

    # Build report
    report = {
        "report_version": 1,
        "target": {
            "target_id": env.get("target_id"),
            "database": env.get("database"),
            "server_version": identity.get("version_full"),
            "server_major": server_major,
        },
        "inputs": {
            "collector_sha256": env.get("collector_sha256"),
            "manifest_sha256": manifest.get("sha256"),
            "benchmark_id": benchmark_id,
            "specs": [{"spec_id": s["spec_id"], "spec_hash": spec_sha256(s)} for s in specs],
        },
        "flags": {
            "version_mismatch": version_mismatch,
            "check_count": {
                "declared": declared,
                "actual": actual,
                "matches": matches,
            },
            "orphan_checks": orphan_checks,
            "integrity_ok": matches,
        },
        "summary": summary,
        "results": results,
    }

    return report
