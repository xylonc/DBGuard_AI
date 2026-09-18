"""Fix unit validation: cross-field rules that JSON Schema cannot express.

validate_fix_unit() returns ALL errors it can find. An empty list means the fix unit is valid.

Rules:
1. JSON Schema validation of fix_unit against catalog/specs/contracts/fix-unit-v1.json
2. precheck.expected_value must equal prior_state.value (compare-and-swap safety)
3. rollback must restore prior_state.value, either:
   - Contains prior_state.value in the rollback SQL, OR
   - Is ALTER SYSTEM RESET when sourcefile doesn't end in postgresql.auto.conf
"""
import json

from jsonschema import Draft202012Validator

REPO_ROOT = __file__.rsplit("/", 4)[0]
CONTRACTS_DIR = f"{REPO_ROOT}/catalog/specs/contracts"
FIX_UNIT_SCHEMA = json.load(open(f"{CONTRACTS_DIR}/fix-unit-v1.json"))
FIX_UNIT_VALIDATOR = Draft202012Validator(FIX_UNIT_SCHEMA)


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
        # Check 3a: rollback contains prior_state.value
        if prior_state_value not in rollback:
            # Check 3b: ALTER SYSTEM RESET when sourcefile doesn't end in postgresql.auto.conf
            sourcefile = prior_state.get("sourcefile")
            is_reset_command = rollback.strip().upper().startswith("ALTER SYSTEM RESET")
            is_auto_conf = sourcefile and sourcefile.endswith("postgresql.auto.conf")

            if not (is_reset_command and not is_auto_conf):
                errors.append(
                    f"rollback must restore prior_state.value ({prior_state_value!r}), "
                    f"but it is not present in the rollback SQL and is not a RESET command "
                    f"for non-auto.conf sources"
                )

    return errors
