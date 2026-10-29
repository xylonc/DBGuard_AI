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

from . import catalog_checks
from .manifest import collects_evidence, condition_check_id
from .operators import evaluate
from .policy import PolicyProfile, policy_entry, profile_value_errors, site_fix
from .records import RecordsIndex
from .redaction import is_redacted
from .sources import session_override
from .specs import spec_sha256
from .validate import uses_policy, validate_spec

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


def _entry_problem(entry: dict[str, Any] | None, spec_hash: str, prefix: str = "") -> tuple[str, str] | None:
    """Missing, stale, not-collected or errored evidence; None when status is ok."""
    if entry is None:
        return ("NOT_COLLECTED", prefix + "no_entry")
    if entry.get("spec_hash") != spec_hash:
        return ("STALE", prefix + "hash_mismatch")
    status = entry.get("status")
    if status == "not_collected":
        return ("NOT_COLLECTED", prefix + "status_not_collected")
    if status == "error":
        return ("ERROR", prefix + "status_error")
    if status != "ok":
        raise ValueError(f"unknown status: {status!r}")
    if not isinstance(entry.get("result"), str):
        return ("ERROR", prefix + "non_string_result")
    # The collector never ships a secret-bearing value; no operator may see the marker.
    if is_redacted(entry["result"]):
        return ("NOT_COLLECTED", prefix + "redacted_secret_setting")
    return None


def _decide(spec: dict[str, Any], entry: dict[str, Any] | None, spec_hash: str,
            condition: dict[str, Any] | None = None,
            policy: PolicyProfile | None = None,
            settings: Any = None) -> tuple[str, str]:
    """Decide result for a single spec based on entry and hash.

    Returns (result, reason_code) at the first condition that matches, in this order:

    1. tier manual_checklist, or parameterised without a policy check -> ("MANUAL", "tier_manual")
    2. tier needs_capability -> ("NEEDS_CAPABILITY", "tier_needs_capability")
    3. parameterised policy check with no approved profile value -> ("MANUAL", "policy_missing")
    4. main entry: missing -> NOT_COLLECTED no_entry; spec_hash differs -> STALE hash_mismatch;
       status not_collected -> NOT_COLLECTED status_not_collected; status error -> ERROR
       status_error; result not a str -> ERROR non_string_result; result is the collector's
       redaction marker (redaction.is_redacted) -> NOT_COLLECTED redacted_secret_setting
    4b. the checked setting's baseline.settings row has a per-role/database/session
       source (sources.session_override) -> NOT_COLLECTED session_override
    5. applies_when only: the same six checks on the condition entry, with reason codes
       prefixed "condition_" (condition_no_entry, condition_hash_mismatch, ...)
    5b. applies_when only: the condition setting's row has such a source ->
       NOT_COLLECTED condition_session_override
    6. applies_when only: condition operator cannot interpret the value -> ERROR
       condition_operator_error; condition false -> ("NOT_APPLICABLE", "condition_false")
    7. operator cannot interpret the value -> ("ERROR", "operator_error")
    8. ok = operator(result, expected) -> ("PASS", "operator_true") if ok else ("FAIL", "operator_false")

    Every evidence problem is decided before the condition, so NOT_APPLICABLE is
    only ever given on clean, current evidence for both settings, and nothing
    about a missing condition or a missing policy can produce PASS. ``settings`` is
    baseline.settings; a missing section, row or source keeps steps 4b/5b silent.
    """
    tier = spec.get("tier", "")
    expected = None

    if tier == "manual_checklist" or (tier == "parameterised" and not uses_policy(spec)):
        return ("MANUAL", "tier_manual")
    if tier == "needs_capability":
        return ("NEEDS_CAPABILITY", "tier_needs_capability")
    if tier == "parameterised":
        value = policy_entry(spec, policy)
        if value is None:
            return ("MANUAL", "policy_missing")
        expected = value["expected"]
    elif tier != "automated":
        # Allow-list: only automated and policy specs reach the operator check
        raise ValueError(f"unknown tier: {tier!r}")

    problem = _entry_problem(entry, spec_hash)
    if problem:
        return problem
    if session_override(settings, spec["check"]["setting_name"]):
        return ("NOT_COLLECTED", "session_override")

    applies_when = spec.get("applies_when")
    if applies_when is not None:
        problem = _entry_problem(condition, spec_hash, "condition_")
        if problem:
            return problem
        if session_override(settings, applies_when["setting_name"]):
            return ("NOT_COLLECTED", "condition_session_override")
        try:
            applies = evaluate(applies_when, condition["result"])
        except (TypeError, ValueError):
            return ("ERROR", "condition_operator_error")
        if not applies:
            return ("NOT_APPLICABLE", "condition_false")

    try:
        ok = evaluate(spec["check"], entry["result"], expected)
    except (TypeError, ValueError):
        return ("ERROR", "operator_error")
    return ("PASS", "operator_true") if ok else ("FAIL", "operator_false")


# ---- structured explanations ---------------------------------------------------
# Results the UI must explain to a DBA carry `cis` and `explanation` alongside
# result/reason_code. Explanations hold facts only (spec fields, collected values,
# verbatim CIS quotes, collector-reported errors); the UI renders the sentence.
EXPLAINED_RESULTS = ("NOT_APPLICABLE", "NOT_COLLECTED", "STALE", "ERROR")


def _evidence_facts(reason: str, setting_name: str, entry: dict[str, Any] | None,
                    spec_hash: str, rule: dict[str, Any], settings: Any = None) -> dict[str, Any]:
    """Facts for a main- or condition-evidence problem (reason without 'condition_')."""
    if reason == "session_override":
        return {"code": "session_override", **session_override(settings, setting_name)}
    if reason in ("no_entry", "status_not_collected"):
        return {"code": "not_collected", "setting_name": setting_name,
                "entry_status": "missing" if reason == "no_entry" else "not_collected"}
    if reason == "hash_mismatch":
        return {"code": "stale_spec_hash", "setting_name": setting_name, "spec_hash": spec_hash,
                "collected_spec_hash": entry.get("spec_hash")}
    if reason == "status_error":
        error = entry.get("error")
        return {"code": "collector_error", "setting_name": setting_name,
                "error": error if isinstance(error, str) else None}
    if reason == "non_string_result":
        return {"code": "unit_or_non_text_value", "setting_name": setting_name}
    if reason == "redacted_secret_setting":
        return {"code": "redacted_secret_setting", "setting_name": setting_name}
    if reason == "operator_error":
        facts = {"code": "uninterpretable_value", "setting_name": setting_name,
                 "operator": rule["operator"], "actual": entry["result"]}
        if "direction" in rule:
            facts["direction"] = rule["direction"]
        return facts
    raise ValueError(f"no explanation for reason {reason!r}")


def _condition_facts(applies_when: dict[str, Any]) -> dict[str, Any]:
    facts = {key: applies_when[key] for key in ("setting_name", "operator", "expected", "direction")
             if key in applies_when}
    facts["condition_quote"] = applies_when["condition_quote"]
    return facts


def _explain(spec: dict[str, Any], result: str, reason_code: str, entry: dict[str, Any] | None,
             condition: dict[str, Any] | None, spec_hash: str,
             policy: PolicyProfile | None, settings: Any = None) -> dict[str, Any] | None:
    if reason_code == "policy_missing":
        case = ("no_profile" if policy is None else
                "profile_unapproved" if not policy.approved else "no_value_for_spec")
        facts = {"code": "policy_missing", "case": case}
        if policy is not None:
            facts["profile_id"] = policy.profile_id
        return facts
    if result not in EXPLAINED_RESULTS:
        return None
    applies_when = spec.get("applies_when")
    if reason_code == "condition_false":
        return {"code": "condition_false", **_condition_facts(applies_when),
                "actual": condition["result"]}
    if reason_code.startswith("condition_"):
        inner = _evidence_facts(reason_code.removeprefix("condition_"),
                                applies_when["setting_name"], condition, spec_hash, applies_when,
                                settings)
        cause = inner.pop("code")
        inner.pop("setting_name")
        return {"code": "condition_unknown", "cause": cause, "evidence": "condition",
                **_condition_facts(applies_when), **inner}
    facts = _evidence_facts(reason_code, spec["check"]["setting_name"], entry, spec_hash, spec["check"],
                            settings)
    return {**facts, "evidence": "check"}


def assess(specs: list[dict[str, Any]], snapshot: dict[str, Any], records: RecordsIndex,
           policy: PolicyProfile | None = None) -> dict[str, Any]:
    """Assess specs against a snapshot.

    Args:
        specs: List of validated spec dicts.
        snapshot: A snapshot dict that passes v0.3.0 JSON Schema validation.
        records: RecordsIndex for validation.
        policy: Optional policy profile for parameterised specs with
            ``expected_from: policy``. Its values are validated against the specs;
            unless it is approved, those specs are MANUAL (policy_missing).

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
    if policy is not None:
        policy_errors = profile_value_errors(policy, specs)
        if policy_errors:
            raise ValueError("Policy profile validation failed:\n" + "\n".join(policy_errors))

    # Build checks index from snapshot
    snapshot_checks: dict[str, dict[str, Any]] = snapshot.get("checks", {})

    # Keys a spec may own in the snapshot: its own and, with applies_when, its condition's
    owned_keys: set[str] = set()
    for spec in specs:
        owned_keys.add(spec["spec_id"])
        if "applies_when" in spec:
            owned_keys.add(condition_check_id(spec["spec_id"]))

    # Compute results for each spec
    results: list[dict[str, Any]] = []
    # pg_settings rows, for the source of each checked value (null when not collected)
    settings = (snapshot.get("baseline") or {}).get("settings")

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
        condition = snapshot_checks.get(condition_check_id(spec_id))
        catalog = _catalog_outcome(spec, snapshot)  # F6 block below; None for setting checks
        if catalog is None:
            result, reason_code = _decide(spec, entry, spec_hash, condition, policy, settings)
        else:
            result, reason_code = catalog["result"], catalog["reason_code"]

        # Build result row
        row: dict[str, Any] = {
            "spec_id": spec_id,
            "title": title,
            "tier": tier,
            "result": result,
            "reason_code": reason_code,
        }
        if catalog is not None:
            row.update(catalog["row"])
        else:
            explanation = _explain(spec, result, reason_code, entry, condition, spec_hash, policy, settings)
            if explanation is not None:
                row["cis"] = {"recommendation": ref.get("recommendation"), "title": title}
                row["explanation"] = explanation

        if catalog is None and collects_evidence(spec) and entry is not None:
            check = spec.get("check", {})
            row["setting_name"] = check.get("setting_name")
            row["operator"] = check.get("operator")
            if "direction" in check:
                row["direction"] = check["direction"]
            if uses_policy(spec):
                row["expected_from"] = "policy"
                value = policy_entry(spec, policy)
                if value is not None:
                    row["expected"] = value["expected"]
            else:
                row["expected"] = check.get("expected")
            row["spec_hash"] = spec_hash
            row["collected_spec_hash"] = entry.get("spec_hash")

            # observed is a SHOW string; a non-string result is reported by reason_code only
            if entry.get("status") == "ok" and isinstance(entry.get("result"), str):
                row["observed"] = entry.get("result")

            applies_when = spec.get("applies_when")
            if applies_when is not None:
                row["condition"] = {key: applies_when[key] for key in
                                    ("setting_name", "operator", "expected", "direction")
                                    if key in applies_when}
                if (condition is not None and condition.get("status") == "ok"
                        and isinstance(condition.get("result"), str)):
                    row["condition"]["observed"] = condition.get("result")

        results.append(row)

    # Find orphan checks (in snapshot but no spec)
    for spec_id in snapshot_checks:
        if spec_id not in owned_keys:
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
        "NOT_APPLICABLE": 0,
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

    # Pin the policy profile when a spec depends on it (null = none supplied), and
    # whenever an approved profile is used for anything else, such as a site-specific
    # fix value for a spec in this set (fixes[spec], e.g. 5.2 listen_addresses).
    inputs_extra: dict[str, Any] = {}
    uses_site_fix = (policy is not None and policy.approved
                     and any(site_fix(s, policy) is not None for s in specs))
    if any(uses_policy(s) for s in specs) or uses_site_fix:
        inputs_extra["policy_profile"] = policy.pin() if policy is not None else None

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
            **inputs_extra,
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


# ---- F6: catalog check kind -------------------------------------------------
# Kept in one block so it rebases cleanly onto the main branch's assess.py.

_CATALOG_RESULTS = {"PASS": "PASS", "FAIL": "FAIL", "MANUAL": "MANUAL", "GAPPED": "NOT_COLLECTED"}


def _catalog_outcome(spec: dict[str, Any], snapshot: dict[str, Any]) -> dict[str, Any] | None:
    """Result for a catalog check, or None when the spec is not one.

    GAPPED maps to NOT_COLLECTED; reason_code is the explanation code. The row
    gains evidence, evidence_paths, explanation, cis and notices, never setting keys.
    """
    check = spec.get("check")
    if not (isinstance(check, dict) and check.get("kind") == "catalog"):
        return None
    outcome = catalog_checks.evaluate(spec, snapshot)
    ref = spec.get("ref", {})
    return {
        "result": _CATALOG_RESULTS[outcome["result"]],
        "reason_code": outcome["explanation"]["code"],
        "row": {
            "evidence": outcome["evidence"],
            "evidence_paths": outcome["evidence_paths"],
            "explanation": outcome["explanation"],
            "cis": {"recommendation": ref.get("recommendation"), "title": ref.get("title")},
            "notices": outcome["notices"],
        },
    }
