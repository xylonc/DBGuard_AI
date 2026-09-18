"""Fix unit validation: cross-field rules that JSON Schema cannot express.

validate_fix_unit() returns ALL errors it can find. An empty list means the fix unit is valid.

Rules:
1. JSON Schema validation of fix_unit against catalog/specs/contracts/fix-unit-v1.json
2. precheck.expected_value must equal prior_state.value (compare-and-swap safety)
3. rollback must restore prior_state.value:
   - For ALTER SYSTEM SET: parses the statement and compares the SET value to prior_state.value
   - For ALTER SYSTEM RESET: accepted only when prior_state.sourcefile doesn't end in postgresql.auto.conf
     (RESET drops the value from auto.conf, so it's safe only when prior value came from postgres.conf
     or a default - not when it was explicitly set via ALTER SYSTEM in auto.conf)
"""
import json
import re

from jsonschema import Draft202012Validator

REPO_ROOT = __file__.rsplit("/", 4)[0]
CONTRACTS_DIR = f"{REPO_ROOT}/catalog/specs/contracts"
FIX_UNIT_SCHEMA = json.load(open(f"{CONTRACTS_DIR}/fix-unit-v1.json"))
FIX_UNIT_VALIDATOR = Draft202012Validator(FIX_UNIT_SCHEMA)

# Pattern to parse ALTER SYSTEM SET param_name = 'value'
ALTER_SYSTEM_SET_RE = re.compile(
    r"ALTER\s+SYSTEM\s+SET\s+([a-z_][a-z0-9_.]*)\s*=\s*('[^']*'|[0-9]+|on|off|true|false|null)\s*;",
    re.IGNORECASE
)


def _extract_set_value(rollback: str) -> tuple[str, str] | None:
    """Parse ALTER SYSTEM SET statement, return (param_name, value) or None if unparseable.

    The value is returned unquoted (strips surrounding single quotes).
    """
    match = ALTER_SYSTEM_SET_RE.search(rollback)
    if not match:
        return None
    param_name = match.group(1).lower()
    raw_value = match.group(2)
    # Strip surrounding single quotes if present
    value = raw_value.strip("'")
    return param_name, value


def validate_fix_unit(fix_unit: dict) -> list[str]:
    """Validate a fix unit against contract rules.

    Returns a list of error strings. Empty list means valid.
    """
    errors: list[str] = []

    # Rule 1: JSON Schema validation (must come first so we can use its errors as base)
    schema_errors = list(FIX_UNIT_VALIDATOR.iter_errors(fix_unit))
    for err in schema_errors:
        errors.append(str(err))

    # If schema validation failed, don't proceed with additional checks
    if schema_errors:
        return errors

    # Rule 2: precheck expected_value must equal prior_state.value
    prior_state_value = fix_unit.get("prior_state", {}).get("value")
    precheck_expected_value = fix_unit.get("precheck", {}).get("expected_value")

    if prior_state_value is not None and precheck_expected_value is not None:
        if prior_state_value != precheck_expected_value:
            errors.append(
                f"precheck.expected_value ({precheck_expected_value!r}) must equal "
                f"prior_state.value ({prior_state_value!r})"
            )

    # Rule 3: rollback must restore prior_state.value
    rollback = fix_unit.get("rollback", "")
    prior_state = fix_unit.get("prior_state", {})
    prior_state_value = prior_state.get("value")

    if prior_state_value and rollback:
        rollback = rollback.strip()
        # Parse ALTER SYSTEM SET or ALTER SYSTEM RESET
        parsed = _extract_set_value(rollback)
        if parsed is not None:
            # ALTER SYSTEM SET case: compare extracted value to prior_state.value
            param_name, set_value = parsed
            # Compare against apply statement's parameter name to ensure consistency
            apply = fix_unit.get("apply", "")
            apply_param = None
            apply_match = ALTER_SYSTEM_SET_RE.search(apply)
            if apply_match:
                apply_param = apply_match.group(1).lower()
            if apply_param and param_name != apply_param:
                errors.append(
                    f"rollback targets parameter {param_name!r} but apply uses {apply_param!r}"
                )
            elif set_value != prior_state_value:
                errors.append(
                    f"rollback SET value {set_value!r} does not match prior_state.value {prior_state_value!r}"
                )
        elif rollback.upper().strip().startswith("ALTER SYSTEM RESET"):
            # ALTER SYSTEM RESET case: only valid when sourcefile doesn't end in auto.conf
            sourcefile = prior_state.get("sourcefile")
            is_auto_conf = sourcefile and sourcefile.endswith("postgresql.auto.conf")
            if is_auto_conf:
                errors.append(
                    f"RESET rollback is invalid when prior_state.sourcefile ends in postgresql.auto.conf "
                    f"({sourcefile!r}): RESET would drop the value instead of restoring it"
                )
        else:
            # Unparseable rollback statement
            errors.append(
                f"rollback must be ALTER SYSTEM SET param = value or ALTER SYSTEM RESET; got: {rollback!r}"
            )

    return errors
