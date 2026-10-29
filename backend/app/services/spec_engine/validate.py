"""Spec validation: shape, traceability to records.json, and automated-check rules.

validate_spec() returns ALL errors it can find. An empty list means the spec is valid.

Schema versions:
- 1: the original contract (tier automated with check + proof, or a reasoned manual tier).
- 2: required exactly when a spec uses a v2 feature, and only then:
  * ``applies_when``: a condition on another setting; condition false gives NOT_APPLICABLE;
  * ``check.expected_from: policy`` on a ``parameterised`` spec: the expected value,
    fix and break come from the approved policy profile, never from the spec.
"""

import re
from typing import Any

from .operators import (
    EXPECTED_SHAPE,
    GUC_LIST_SETTINGS,
    LOG_LINE_PREFIX_ESCAPES,
    OPERATOR_PARAMS,
    OPERATORS,
    SEVERITY_DIRECTIONS,
    SEVERITY_SCALES,
    evaluate,
)
from .catalog_checks import REGISTRY as CATALOG_REGISTRY
from .records import RecordsIndex
from .redaction import COLLECTOR_SECRET_SETTINGS, collector_redacts
from .sources import COLLECTOR_PINNED_SETTINGS

TIERS = ("automated", "parameterised", "manual_checklist", "needs_capability")
CHECK_KINDS = ("setting", "catalog")
SCHEMA_VERSIONS = (1, 2)

TOP_REQUIRED = ("spec_id", "schema_version", "authored_by", "ref", "tier", "reason")
AUTOMATED_ONLY = ("check", "proof")  # required when tier == automated
V2_TOP = ("applies_when",)
OPTIONAL_TOP = ("interpretation",)  # any tier, any schema_version
REF_KEYS = ("benchmark", "benchmark_version", "pg_major", "recommendation", "title", "source_sha256")
CHECK_BASE_KEYS = ("kind", "setting_name", "query", "operator", "pass_condition_quote")
CHECK_KEYS = CHECK_BASE_KEYS + ("expected",)  # v1 automated check (kept for callers/tests)
EXPECTED_SOURCES = ("policy",)  # allowed values of check.expected_from
APPLIES_WHEN_KEYS = ("setting_name", "operator", "expected", "condition_quote")
PROOF_KEYS = ("break", "fix")
PROOF_STEP_KEYS = ("setting_name", "value")

SETTING_NAME_RE = re.compile(r"[a-z_][a-z0-9_.]*")
LIST_ITEM_RE = re.compile(r"[a-z0-9_]+")  # contains_items items: lower-case bare names

# The built-in settings whose values the collector redacts (collector/collect.sql
# pg_temp.is_secret_setting; see redaction.py, which also covers unreviewed dotted
# names). A check or condition on a redacted setting would be decided on the
# marker text, so neither check nor applies_when may use one. A test pins the
# lists to the collector source.
SANITISED_SETTINGS = COLLECTOR_SECRET_SETTINGS


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


def uses_policy(spec: Any) -> bool:
    """True when the spec takes its expected value from the policy profile."""
    return (isinstance(spec, dict) and isinstance(spec.get("check"), dict)
            and spec["check"].get("expected_from") == "policy")


def _v2_features(spec: dict) -> list[str]:
    used = [key for key in V2_TOP if key in spec]
    if isinstance(spec.get("check"), dict) and "expected_from" in spec["check"]:
        used.append("check.expected_from")
    return used


def expected_errors(operator: str, setting_name: Any, expected: Any, where: str) -> list[str]:
    """Shape and per-operator rules for an expected value (spec, applies_when or profile).

    ``operator`` must already be a known operator.
    """
    if EXPECTED_SHAPE[operator] == "list":
        if not (isinstance(expected, list) and expected and all(_is_str(v) and v for v in expected)):
            return [f"{where} must be a non-empty list of non-empty strings when operator is {operator!r}"]
        if len(set(expected)) != len(expected):
            return [f"{where} must not repeat items"]
    elif not (_is_str(expected) and expected):
        return [f"{where} must be a string, got {type(expected).__name__}"]

    errors: list[str] = []
    if operator == "contains_items":
        for item in expected:
            if not LIST_ITEM_RE.fullmatch(item):
                errors.append(f"{where} item {item!r} must be a lower-case name matching ^[a-z0-9_]+$")
    elif operator == "contains_escapes":
        for item in expected:
            if item not in LOG_LINE_PREFIX_ESCAPES:
                errors.append(f"{where} item {item!r} is not a PostgreSQL 17 log_line_prefix escape "
                              f"(one of {sorted(LOG_LINE_PREFIX_ESCAPES)})")
    elif operator == "severity":
        scale = SEVERITY_SCALES.get(setting_name)
        if scale is not None and expected not in scale:
            errors.append(f"{where} {expected!r} is not a {setting_name} level {scale}")
    elif operator == "no_item_in":
        item_re = GUC_LIST_SETTINGS.get(setting_name)
        for item in expected if item_re is not None else []:
            if not item_re.fullmatch(item):
                errors.append(f"{where} item {item!r} is not a valid {setting_name} element")
    return errors


def _operator_errors(obj: dict, where: str) -> tuple[bool, list[str]]:
    """Operator name and operator parameters (e.g. severity.direction)."""
    errors: list[str] = []
    operator = obj.get("operator")
    operator_ok = _is_str(operator) and operator in OPERATORS
    if "operator" in obj and not operator_ok:
        errors.append(f"{where}.operator must be one of {tuple(OPERATORS)}, got {operator!r}")
    for op, params in OPERATOR_PARAMS.items():
        for param in params:
            if operator_ok and operator == op and param not in obj:
                errors.append(f"Missing required {where} key: {param} (operator {op!r})")
            elif param in obj and operator != op:
                errors.append(f"{where}.{param} is only allowed with operator {op!r}")
    if operator == "severity":
        if "direction" in obj and obj["direction"] not in SEVERITY_DIRECTIONS:
            errors.append(f"{where}.direction must be one of {SEVERITY_DIRECTIONS}, got {obj['direction']!r}")
        if obj.get("setting_name") not in SEVERITY_SCALES:
            errors.append(f"{where}.operator 'severity' has no reviewed scale for setting "
                          f"{obj.get('setting_name')!r} (reviewed: {sorted(SEVERITY_SCALES)})")
    if operator == "no_item_in" and obj.get("setting_name") not in GUC_LIST_SETTINGS:
        errors.append(f"{where}.operator 'no_item_in' has no reviewed list grammar for setting "
                      f"{obj.get('setting_name')!r} (reviewed: {sorted(GUC_LIST_SETTINGS)})")
    return operator_ok, errors


# interpretation: plain sentences recording where DBGuard reads CIS more strictly,
# more narrowly or more widely. Never SQL: no ';', no line breaks, no code fences,
# no upper-case SQL statement keywords. Hashed with the rest of the spec.
INTERPRETATION_MAX = 600
_INTERPRETATION_SQL_RE = re.compile(
    r"\b(SELECT|INSERT|UPDATE|DELETE|ALTER|CREATE|DROP|GRANT|REVOKE|TRUNCATE|COPY|EXECUTE|"
    r"FROM|WHERE|LIKE|UNION)\b")


def _interpretation_errors(value: Any) -> list[str]:
    if not (isinstance(value, list) and value):
        return ["interpretation must be a non-empty list of sentences"]
    errors: list[str] = []
    for i, line in enumerate(value):
        where = f"interpretation[{i}]"
        if not (_is_str(line) and line.strip()):
            errors.append(f"{where} must be a non-empty string")
            continue
        if len(line) > INTERPRETATION_MAX:
            errors.append(f"{where} must be at most {INTERPRETATION_MAX} characters")
        if any(c in line for c in ";\n\r\x00") or "```" in line:
            errors.append(f"{where} must be one plain sentence (no ';', line breaks or code)")
        match = _INTERPRETATION_SQL_RE.search(line)
        if match:
            errors.append(f"{where} must not contain SQL (found {match.group(1)!r})")
    if len(set(value)) != len(value) and not errors:
        errors.append("interpretation must not repeat sentences")
    return errors


def _record_text(record: dict | None, *fields: str) -> list[str]:
    if record is None:
        return []
    return [_normalize_whitespace(record.get(f) or "") for f in fields]


def validate_spec(spec: Any, records: RecordsIndex) -> list[str]:
    if not isinstance(spec, dict):
        return ["spec must be a mapping"]

    errors: list[str] = []

    # ---- top level ---------------------------------------------------------
    _check_keys(spec, TOP_REQUIRED, TOP_REQUIRED + AUTOMATED_ONLY + V2_TOP + OPTIONAL_TOP,
                "top-level", errors)
    if "interpretation" in spec:
        errors.extend(_interpretation_errors(spec["interpretation"]))

    if "schema_version" in spec:
        version = spec["schema_version"]
        used = _v2_features(spec)
        if not (_is_int(version) and version in SCHEMA_VERSIONS):
            errors.append(f"schema_version must be 1 or 2, got {version!r}")
        elif used and version != 2:
            errors.append(f"schema_version must be 2 when {', '.join(used)} is used, got {version!r}")
        elif not used and version != 1:
            errors.append(f"schema_version must be 1 for a spec without applies_when or "
                          f"check.expected_from, got {version!r}")

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

    # F6: a catalog check has its own rules (block below), then stops here.
    if _is_catalog_check(spec):
        _validate_catalog_spec(spec, record, tier, tier_valid, errors)
        return errors

    # Which tiers may carry a check: automated (literal expected + proof) and
    # parameterised (expected_from: policy, no proof). Everything else has none.
    policy_check = tier == "parameterised" and "check" in spec
    if tier_valid and tier != "automated" and not policy_check:
        for key in AUTOMATED_ONLY + V2_TOP:
            if key in spec:
                errors.append(f"tier {tier!r} must not have {key} present")
        return errors

    if tier == "automated":
        for key in AUTOMATED_ONLY:
            if key not in spec:
                errors.append(f"tier 'automated' requires {key}")
    if policy_check and "proof" in spec:
        errors.append("tier 'parameterised' must not have proof present (break/fix come from the policy profile)")

    # ---- check -------------------------------------------------------------
    check = spec.get("check")
    check_usable = False  # True only if break/fix can be compared with the real operator
    if "check" in spec and not isinstance(check, dict):
        errors.append("check must be a mapping")
        check = None
    if isinstance(check, dict):
        # Operator parameters (severity.direction) are checked by _operator_errors.
        all_params = tuple(p for ps in OPERATOR_PARAMS.values() for p in ps)
        required = CHECK_BASE_KEYS + (("expected_from",) if policy_check else ("expected",))
        _check_keys(check, required, required + all_params, "check", errors)

        if "kind" in check and check["kind"] not in CHECK_KINDS:
            errors.append(f"check.kind must be one of {CHECK_KINDS}, got {check['kind']!r}")
        if policy_check and "expected_from" in check and check["expected_from"] not in EXPECTED_SOURCES:
            errors.append(f"check.expected_from must be one of {EXPECTED_SOURCES}, got {check['expected_from']!r}")

        setting_name = check.get("setting_name")
        name_ok = _is_str(setting_name) and SETTING_NAME_RE.fullmatch(setting_name) is not None
        if "setting_name" in check and not name_ok:
            errors.append(f"check.setting_name must match pattern ^[a-z_][a-z0-9_.]*$, got {setting_name!r}")

        if name_ok and "query" in check and check["query"] != "SHOW " + setting_name:
            errors.append(f"check.query must be 'SHOW {setting_name}', got {check['query']!r}")
        if name_ok and setting_name in COLLECTOR_PINNED_SETTINGS:
            errors.append(f"check.setting_name {setting_name!r} is set by the collector in its own session; "
                          "the collected value would be the collector's, not the server's")
        if name_ok and collector_redacts(setting_name):
            errors.append(f"check.setting_name {setting_name!r} is masked by the collector (its value can "
                          "carry a secret), so it can never be checked")

        operator = check.get("operator")
        operator_ok, op_errors = _operator_errors(check, "check")
        errors.extend(op_errors)

        # Every operator's expected value(s) must be non-empty strings of the right shape.
        expected = check.get("expected")
        expected_values = None
        if "expected" in check and operator_ok:
            shape_errors = expected_errors(operator, setting_name, expected, "check.expected")
            if shape_errors:
                errors.extend(shape_errors)
            else:
                expected_values = expected if isinstance(expected, list) else [expected]

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
                # Applies to ALL operators, including not_equals. Policy values are not
                # in the spec, so for expected_from the quote is checked for verbatim only.
                for value in expected_values or []:
                    if not _is_whole_token(value, normalized_quote):
                        errors.append(f"expected value {value!r} is not a whole token in pass_condition_quote")

        check_usable = (name_ok and operator_ok and expected_values is not None
                        and not op_errors and not policy_check)

    # ---- applies_when (schema_version 2) ----------------------------------
    if "applies_when" in spec:
        errors.extend(_applies_when_errors(spec["applies_when"], check, record, ref))

    # ---- proof -------------------------------------------------------------
    if "proof" in spec and not policy_check:
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
                errors.extend(proof_value_errors(check, phase, value))

    return errors


def proof_value_errors(check: dict, phase: str, value: str, expected=None, where: str = "proof") -> list[str]:
    """break must fail and fix must pass the check's operator (shared with policy profiles)."""
    try:
        satisfied = evaluate(check, value, expected)
    except (TypeError, ValueError) as exc:
        return [f"{where}.{phase}.value ({value!r}) cannot be evaluated by operator "
                f"{check['operator']!r}: {exc}"]
    if phase == "break" and satisfied:
        return [f"{where}.break.value ({value!r}) already satisfies check (operator: {check['operator']})"]
    if phase == "fix" and not satisfied:
        return [f"{where}.fix.value ({value!r}) does not satisfy check (operator: {check['operator']})"]
    return []


def _applies_when_errors(cond: Any, check: Any, record: dict | None, ref: Any) -> list[str]:
    if not isinstance(cond, dict):
        return ["applies_when must be a mapping"]
    errors: list[str] = []
    all_params = tuple(p for ps in OPERATOR_PARAMS.values() for p in ps)
    _check_keys(cond, APPLIES_WHEN_KEYS, APPLIES_WHEN_KEYS + all_params, "applies_when", errors)
    if not isinstance(check, dict):
        errors.append("applies_when requires a check")

    name = cond.get("setting_name")
    name_ok = _is_str(name) and SETTING_NAME_RE.fullmatch(name) is not None
    if "setting_name" in cond and not name_ok:
        errors.append(f"applies_when.setting_name must match pattern ^[a-z_][a-z0-9_.]*$, got {name!r}")
    if name_ok and isinstance(check, dict) and name == check.get("setting_name"):
        errors.append("applies_when.setting_name must differ from check.setting_name")
    if name_ok and collector_redacts(name):
        errors.append(f"applies_when.setting_name {name!r} is masked by the collector and cannot decide a condition")
    if name_ok and name in COLLECTOR_PINNED_SETTINGS:
        errors.append(f"applies_when.setting_name {name!r} is set by the collector in its own session "
                      "and cannot decide a condition")

    operator_ok, op_errors = _operator_errors(cond, "applies_when")
    errors.extend(op_errors)
    if "expected" in cond and operator_ok:
        errors.extend(expected_errors(cond["operator"], name, cond["expected"], "applies_when.expected"))

    quote = cond.get("condition_quote")
    if "condition_quote" in cond:
        if not (_is_str(quote) and quote.strip()):
            errors.append("applies_when.condition_quote must be a non-empty string")
        elif record is not None:
            # Verbatim (whitespace-normalised) from the CIS text that states the condition.
            sources = _record_text(record, "audit_procedure", "description", "rationale")
            if not any(_normalize_whitespace(quote) in text for text in sources):
                errors.append("applies_when.condition_quote not found in audit_procedure, description or "
                              f"rationale for {ref['recommendation']!r}")
    return errors


# ---- F6: catalog check kind ------------------------------------------------
# Kept in one block so it rebases cleanly onto the main branch's validate.py.
# A catalog check names a fixed evaluator from catalog_checks.REGISTRY; it has
# no SQL, no setting and never a proof, because catalog checks never get a fix.

CATALOG_CHECK_KEYS = ("kind", "evaluator", "pass_condition_quote")
CATALOG_TIERS = ("automated", "manual_checklist")


def _is_catalog_check(spec: dict) -> bool:
    check = spec.get("check")
    return isinstance(check, dict) and check.get("kind") == "catalog"


def _validate_catalog_spec(spec: dict, record, tier, tier_valid: bool, errors: list[str]) -> None:
    if "proof" in spec:
        errors.append("check.kind 'catalog' must not have proof present")
    if "applies_when" in spec:
        errors.append("check.kind 'catalog' must not have applies_when present")
    if tier_valid and tier not in CATALOG_TIERS:
        # parameterised and needs_capability keep the old rule: no check at all.
        errors.append(f"tier {tier!r} must not have check present")
    _validate_catalog_check(spec, spec["check"], record, tier if tier_valid else None, errors)


def _validate_catalog_check(spec: dict, check: dict, record, tier, errors: list[str]) -> None:
    _check_keys(check, CATALOG_CHECK_KEYS, CATALOG_CHECK_KEYS, "check", errors)
    ref = spec.get("ref") if isinstance(spec.get("ref"), dict) else {}

    evaluator = check.get("evaluator")
    entry = CATALOG_REGISTRY.get(evaluator) if _is_str(evaluator) else None
    if "evaluator" in check and entry is None:
        errors.append(f"check.evaluator must be one of {tuple(CATALOG_REGISTRY)}, got {evaluator!r}")
    if entry is not None:
        if ref.get("recommendation") != entry.recommendation:
            errors.append(
                f"check.evaluator {evaluator!r} serves recommendation {entry.recommendation!r}, "
                f"not {ref.get('recommendation')!r}"
            )
        if tier is not None and tier not in entry.tiers:
            errors.append(f"check.evaluator {evaluator!r} does not support tier {tier!r} (allowed: {entry.tiers})")

    if "pass_condition_quote" not in check:
        return
    quote = check["pass_condition_quote"]
    if not (_is_str(quote) and quote.strip()):
        errors.append("check.pass_condition_quote must be a non-empty string")
        return
    normalized_quote = _normalize_whitespace(quote)
    if record is not None:
        audit = record.get("audit_procedure") or ""
        if normalized_quote not in _normalize_whitespace(audit):
            errors.append(f"pass_condition_quote not found in audit_procedure for {ref.get('recommendation')!r}")
    for token in entry.quote_tokens if entry is not None else ():
        if not _is_whole_token(token, normalized_quote):
            errors.append(f"evaluator constant {token!r} is not a whole token in pass_condition_quote")
