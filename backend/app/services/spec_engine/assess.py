"""Assessment engine: pure function from validated specs + snapshot to report.

This module implements the assessment engine as a pure function:
- assess(specs, snapshot, records) -> dict

It uses no database, no network, and no clock. The same inputs always
produce identical output.
"""

import json
from pathlib import Path
from typing import Any

from .operators import equals, in_, not_equals, true
from .records import RecordsIndex
from .specs import spec_sha256
from .validate import validate_spec


def _validate_snapshot(snapshot: dict[str, Any]) -> list[str]:
    """Validate snapshot against v0.3.0 JSON Schema.

    Returns a list of error messages. Empty list means valid.
    """
    errors: list[str] = []

    # Basic structure check
    if not isinstance(snapshot, dict):
        errors.append("Snapshot must be a mapping")
        return errors

    # Required top-level keys
    for key in ("envelope", "baseline", "checks"):
        if key not in snapshot:
            errors.append(f"Missing required top-level key: {key}")

    if errors:
        return errors

    envelope = snapshot.get("envelope", {})
    if not isinstance(envelope, dict):
        errors.append("envelope must be a mapping")
        return errors

    # Required envelope keys
    for key in ("schema_version", "database", "target_id", "collector_sha256", "manifest"):
        if key not in envelope:
            errors.append(f"Missing required envelope key: {key}")

    if "schema_version" in envelope and envelope["schema_version"] != "0.3.0":
        errors.append(f"envelope.schema_version must be '0.3.0', got {envelope['schema_version']!r}")

    manifest = envelope.get("manifest", {})
    if isinstance(manifest, dict):
        for key in ("sha256", "manifest_version", "benchmark_id", "check_count"):
            if key not in manifest:
                errors.append(f"Missing required manifest key: {key}")

    if errors:
        return errors

    # Validate checks structure
    checks = snapshot.get("checks", {})
    if not isinstance(checks, dict):
        errors.append("checks must be a mapping")
        return errors

    # Validate each check entry
    for spec_id, entry in checks.items():
        if not isinstance(entry, dict):
            errors.append(f"checks[{spec_id}] must be a mapping")
            continue

        # Required check entry keys
        for key in ("spec_hash", "query", "status"):
            if key not in entry:
                errors.append(f"checks[{spec_id}] missing required key: {key}")

        status = entry.get("status")
        if status == "ok" and "result" not in entry:
            errors.append(f"checks[{spec_id}] with status='ok' must have 'result'")
        if status == "error" and "error" not in entry:
            errors.append(f"checks[{spec_id}] with status='error' must have 'error'")
        if status == "not_collected" and "result" in entry:
            errors.append(f"checks[{spec_id}] with status='not_collected' must not have 'result'")

        if status not in ("ok", "error", "not_collected"):
            errors.append(f"checks[{spec_id}] status must be one of 'ok', 'error', 'not_collected', got {status!r}")

        # spec_hash must be 64-char hex
        spec_hash = entry.get("spec_hash")
        if isinstance(spec_hash, str):
            if len(spec_hash) != 64 or not all(c in "0123456789abcdef" for c in spec_hash):
                errors.append(f"checks[{spec_id}] spec_hash must be 64-char hex string")

    return errors


def _validate_specs(specs: list[dict[str, Any]], records: RecordsIndex) -> list[str]:
    """Validate all specs against validate_spec and check for duplicate spec_ids.

    Returns a list of error messages. Empty list means valid.
    """
    errors: list[str] = []
    seen_spec_ids: set[str] = set()

    for i, spec in enumerate(specs):
        if not isinstance(spec, dict):
            errors.append(f"spec[{i}] must be a mapping")
            continue

        # Check for duplicate spec_id
        spec_id = spec.get("spec_id")
        if spec_id is None:
            errors.append(f"spec[{i}] missing spec_id")
        elif spec_id in seen_spec_ids:
            errors.append(f"Duplicate spec_id: {spec_id}")
        else:
            seen_spec_ids.add(spec_id)

        # Validate against validate_spec
        spec_errors = validate_spec(spec, records)
        for err in spec_errors:
            errors.append(f"spec[{i}] ({spec_id or 'unknown'}): {err}")

    return errors


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
    snapshot_errors = _validate_snapshot(snapshot)
    if snapshot_errors:
        raise ValueError("Snapshot validation failed:\n" + "\n".join(snapshot_errors))

    spec_errors = _validate_specs(specs, records)
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
        title = spec.get("title", "")

        # Determine result based on tier and check entry
        entry = snapshot_checks.get(spec_id)

        # Compute collected_spec_hash if entry exists (needed for output row)
        collected_spec_hash = entry.get("spec_hash") if entry else None

        # Extract title from ref
        title = ""
        ref = spec.get("ref", {})
        if isinstance(ref, dict):
            title = ref.get("title", "")

        # Check for tier-based results FIRST (before entry checks)
        if tier in ("manual_checklist", "parameterised"):
            result = "MANUAL"
            reason_code = "tier_manual"
        elif tier == "needs_capability":
            result = "NEEDS_CAPABILITY"
            reason_code = "tier_needs_capability"
        elif entry is None:
            # No entry in snapshot for this spec_id
            result = "NOT_COLLECTED"
            reason_code = "no_entry"
        elif entry.get("status") == "not_collected":
            # Entry exists but status is not_collected
            result = "NOT_COLLECTED"
            reason_code = "no_entry"
        elif entry.get("status") == "error":
            # Entry exists with error status
            result = "ERROR"
            reason_code = "status_error"
        elif entry is not None:
            # Entry exists - check hash (only if status is ok)
            collected_spec_hash = entry.get("spec_hash")

            if collected_spec_hash != spec_hash:
                result = "STALE"
                reason_code = "hash_mismatch"
            elif entry.get("status") == "ok":
                # status is ok, check result type
                result_value = entry.get("result")
                if not isinstance(result_value, str):
                    result = "ERROR"
                    reason_code = "non_string_result"
                else:
                    # For automated specs, check the operator
                    check = spec.get("check", {})
                    operator = check.get("operator")
                    expected = check.get("expected")

                    if operator == "true":
                        result = "PASS"
                        reason_code = "operator_true"
                    elif operator == "equals":
                        if equals(result_value, expected):
                            result = "PASS"
                            reason_code = "operator_true"
                        else:
                            result = "FAIL"
                            reason_code = "operator_false"
                    elif operator == "not_equals":
                        if not_equals(result_value, expected):
                            result = "PASS"
                            reason_code = "operator_true"
                        else:
                            result = "FAIL"
                            reason_code = "operator_false"
                    elif operator == "in":
                        if isinstance(expected, list) and in_(result_value, expected):
                            result = "PASS"
                            reason_code = "operator_true"
                        else:
                            result = "FAIL"
                            reason_code = "operator_false"
                    else:
                        result = "ERROR"
                        reason_code = "unknown_operator"
            else:
                # Unexpected status
                result = "ERROR"
                reason_code = "status_error"
        else:
            # Should not reach here
            result = "ERROR"
            reason_code = "unknown_error"

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
            row["collected_spec_hash"] = collected_spec_hash

            if entry.get("status") == "ok":
                row["observed"] = entry.get("result")

        results.append(row)

    # Find orphan checks (in snapshot but no spec)
    for spec_id in snapshot_checks:
        if spec_id not in spec_by_id:
            orphan_checks.append(spec_id)
    orphan_checks.sort()

    # Compute check_count
    declared = snapshot.get("envelope", {}).get("manifest", {}).get("check_count")
    actual = len(snapshot_checks)
    matches = declared == actual if declared is not None else None

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
    env = snapshot.get("envelope", {})
    manifest = env.get("manifest", {})
    benchmark_id = manifest.get("benchmark_id")  # e.g., "cis-pg17-v1.1.0"
    version_mismatch = None

    if benchmark_id and server_major:
        # Extract major version from benchmark_id (e.g., "cis-pg17-v1.1.0" -> 17)
        if benchmark_id.startswith("cis-pg"):
            try:
                benchmark_major = int(benchmark_id.split("-")[1][2:])  # "pg17" -> 17
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
            "benchmark_id": manifest.get("benchmark_id"),
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
