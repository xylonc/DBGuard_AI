"""Spec validation: shape, traceability to records.json, and automated-check rules.

validate_spec() returns ALL errors it can find. An empty list means the spec is valid.
"""

import re
from typing import Any

from .operators import equals, in_, not_equals
from .records import RecordsIndex

TIERS = ("automated", "parameterised", "manual_checklist", "needs_capability")
OPERATORS = {"equals": equals, "not_equals": not_equals, "in": in_}
CHECK_KINDS = ("setting",)

TOP_REQUIRED = ("spec_id", "schema_version", "authored_by", "ref", "tier", "reason")
AUTOMATED_ONLY = ("check", "proof")  # required when tier == automated, forbidden otherwise
REF_KEYS = ("benchmark", "benchmark_version", "pg_major", "recommendation", "title", "source_sha256")
CHECK_KEYS = ("kind", "setting_name", "query", "operator", "expected", "pass_condition_quote")
PROOF_KEYS = ("break", "fix")
PROOF_STEP_KEYS = ("setting_name", "value")

SETTING_NAME_RE = re.compile(r"[a-z_][a-z0-9_.]*")


def _normalize_whitespace(text: str) -> str:
    """Collapse every whitespace run to one space."""
    return re.sub(r"\s+", " ", text).strip()


def _is_whole_token(value: str, text: str) -> bool:
    """value appears in text, not preceded or followed by [A-Za-z0-9_]."""
    pattern = rf"(?<![A-Za-z0-9_]){re.escape(value)}(?![A-Za-z0-9_])"
    return re.search(pattern, text) is not None


def _is_str(value: Any) -> bool:
    return isinstance(value, str)


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _check_keys(obj: dict, required, allowed, where: str, errors: list[str]) -> None:
    for key in required:
        if key not in obj:
            errors.append(f"Missing required {where} key: {key}")
    for key in obj:
        if key not in allowed:
            errors.append(f"Unknown {where} key: {key}")


def validate_spec(spec: Any, records: RecordsIndex) -> list[str]:
    if not isinstance(spec, dict):
        return ["spec must be a mapping"]

    errors: list[str] = []

    # ---- top level ---------------------------------------------------------
    _check_keys(spec, TOP_REQUIRED, TOP_REQUIRED + AUTOMATED_ONLY, "top-level", errors)

    if "schema_version" in spec and not (_is_int(spec["schema_version"]) and spec["schema_version"] == 1):
        errors.append(f"schema_version must be 1, got {spec['schema_version']!r}")

    if "authored_by" in spec and spec["authored_by"] not in ("human", "agent"):
        errors.append(f"authored_by must be 'human' or 'agent', got {spec['authored_by']!r}")

    tier = spec.get("tier")
    tier_valid = _is_str(tier) and tier in TIERS
    if "tier" in spec and not tier_valid:
        errors.append(f"tier must be one of {TIERS}, got {tier!r}")

    # ---- ref and traceability ----------------------------------------------
    record = None
    ref = spec.get("ref")
    if "ref" in spec and not isinstance(ref, dict):
        errors.append("ref must be a mapping")
    if isinstance(ref, dict):
        _check_keys(ref, REF_KEYS, REF_KEYS, "ref", errors)
        for key in ("benchmark", "benchmark_version", "recommendation", "title", "source_sha256"):
            if key in ref and not _is_str(ref[key]):
                errors.append(f"ref.{key} must be a string")
        if "pg_major" in ref and not _is_int(ref["pg_major"]):
            errors.append("ref.pg_major must be an integer")

        # spec_id is derived from ref, so it is version-qualified and never hardcoded.
        # The prefix must match the RecordsIndex.benchmark_id (from the records.json directory).
        if "spec_id" in spec and all(k in ref for k in ("pg_major", "benchmark_version", "recommendation")):
            actual_prefix = spec["spec_id"].split(":")[0]
            expected_prefix = records.benchmark_id
            expected_id = f"{expected_prefix}:{ref['recommendation']}"
            if spec["spec_id"] != expected_id:
                if actual_prefix != expected_prefix:
                    errors.append(f"spec_id prefix mismatch: expected {expected_prefix!r}, got {actual_prefix!r}")
                else:
                    errors.append(f"spec_id mismatch: expected {expected_id!r}, got {spec['spec_id']!r}")

        if _is_str(ref.get("benchmark")) and ref["benchmark"] != records.benchmark:
            errors.append(f"ref.benchmark mismatch: expected {records.benchmark!r}, got {ref['benchmark']!r}")
        if _is_str(ref.get("benchmark_version")) and ref["benchmark_version"] != records.benchmark_version:
            errors.append(
                f"ref.benchmark_version mismatch: expected {records.benchmark_version!r}, "
                f"got {ref['benchmark_version']!r}"
            )

        rec = ref.get("recommendation")
        if _is_str(rec):
            if rec not in records:
                errors.append(f"Recommendation {rec!r} not found in records")
            else:
                record = records[rec]
                if "title" in ref and ref["title"] != record["title"]:
                    errors.append(f"ref.title mismatch: expected {record['title']!r}, got {ref['title']!r}")
                if "source_sha256" in ref and ref["source_sha256"] != record["source_sha256"]:
                    errors.append(
                        f"ref.source_sha256 mismatch for {rec}: expected {record['source_sha256']!r}, "
                        f"got {ref['source_sha256']!r}"
                    )

    # ---- reason and tier-dependent keys ------------------------------------
    if "reason" in spec and tier_valid:
        if tier == "automated":
            if spec["reason"] is not None:
                errors.append("tier 'automated' requires reason to be null")
        elif not (_is_str(spec["reason"]) and spec["reason"].strip()):
            errors.append(f"tier {tier!r} requires reason to be a non-empty string")

    if tier_valid and tier != "automated":
        for key in AUTOMATED_ONLY:
            if key in spec:
                errors.append(f"tier {tier!r} must not have {key} present")
        return errors

    if tier == "automated":
        for key in AUTOMATED_ONLY:
            if key not in spec:
                errors.append(f"tier 'automated' requires {key}")

    # ---- check -------------------------------------------------------------
    check = spec.get("check")
    check_usable = False  # True only if break/fix can be compared with the real operator
    if "check" in spec and not isinstance(check, dict):
        errors.append("check must be a mapping")
        check = None
    if isinstance(check, dict):
        _check_keys(check, CHECK_KEYS, CHECK_KEYS, "check", errors)

        if "kind" in check and check["kind"] not in CHECK_KINDS:
            errors.append(f"check.kind must be one of {CHECK_KINDS}, got {check['kind']!r}")

        setting_name = check.get("setting_name")
        name_ok = _is_str(setting_name) and SETTING_NAME_RE.fullmatch(setting_name) is not None
        if "setting_name" in check and not name_ok:
            errors.append(f"check.setting_name must match pattern ^[a-z_][a-z0-9_.]*$, got {setting_name!r}")

        if name_ok and "query" in check and check["query"] != "SHOW " + setting_name:
            errors.append(f"check.query must be 'SHOW {setting_name}', got {check['query']!r}")

        operator = check.get("operator")
        operator_ok = _is_str(operator) and operator in OPERATORS
        if "operator" in check and not operator_ok:
            errors.append(f"check.operator must be one of {tuple(OPERATORS)}, got {operator!r}")

        # Every operator's expected value(s) must be non-empty strings.
        expected = check.get("expected")
        expected_values = None
        if "expected" in check and operator_ok:
            if operator == "in":
                if isinstance(expected, list) and expected and all(_is_str(v) and v for v in expected):
                    expected_values = expected
                else:
                    errors.append("check.expected must be a non-empty list of non-empty strings when operator is 'in'")
            elif _is_str(expected) and expected:
                expected_values = [expected]
            else:
                errors.append(f"check.expected must be a string, got {type(expected).__name__}")

        quote = check.get("pass_condition_quote")
        if "pass_condition_quote" in check:
            if not (_is_str(quote) and quote.strip()):
                errors.append("check.pass_condition_quote must be a non-empty string")
            else:
                normalized_quote = _normalize_whitespace(quote)
                if record is not None:
                    audit = record.get("audit_procedure") or ""
                    if normalized_quote not in _normalize_whitespace(audit):
                        errors.append(f"pass_condition_quote not found in audit_procedure for {ref['recommendation']!r}")
                # Applies to ALL operators, including not_equals.
                for value in expected_values or []:
                    if not _is_whole_token(value, normalized_quote):
                        errors.append(f"expected value {value!r} is not a whole token in pass_condition_quote")

        check_usable = name_ok and operator_ok and expected_values is not None

    # ---- proof -------------------------------------------------------------
    if "proof" in spec:
        proof = spec["proof"]
        if not isinstance(proof, dict):
            errors.append("proof must be a mapping")
        else:
            _check_keys(proof, PROOF_KEYS, PROOF_KEYS, "proof", errors)
            for phase in PROOF_KEYS:
                if phase not in proof:
                    continue
                step = proof[phase]
                if not isinstance(step, dict):
                    errors.append(f"proof.{phase} must be a mapping")
                    continue
                _check_keys(step, PROOF_STEP_KEYS, PROOF_STEP_KEYS, f"proof.{phase}", errors)

                if "setting_name" in step and isinstance(check, dict) and step["setting_name"] != check.get("setting_name"):
                    errors.append(
                        f"proof.{phase}.setting_name ({step['setting_name']!r}) does not "
                        f"match check.setting_name ({check.get('setting_name')!r})"
                    )

                if "value" not in step:
                    continue
                value = step["value"]
                if not _is_str(value):
                    errors.append(f"proof.{phase}.value must be a string, got {type(value).__name__}")
                    continue
                if not check_usable:
                    continue

                satisfied = OPERATORS[check["operator"]](value, check["expected"])
                if phase == "break" and satisfied:
                    errors.append(f"proof.break.value ({value!r}) already satisfies check (operator: {check['operator']})")
                if phase == "fix" and not satisfied:
                    errors.append(f"proof.fix.value ({value!r}) does not satisfy check (operator: {check['operator']})")

    return errors