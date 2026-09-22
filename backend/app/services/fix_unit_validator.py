"""Fix unit validation: cross-field rules that JSON Schema cannot express.

validate_fix_unit() returns ALL errors it can find. An empty list means the fix unit is valid.

Rules:
1. JSON Schema validation of fix_unit against catalog/specs/contracts/fix-unit-v1.json
2. precheck.expected_value must equal prior_state.value (compare-and-swap safety)
3. rollback must equal derive_rollback(prior_state, apply):
   - derive_rollback computes the appropriate rollback action based on prior state and apply
   - set_config apply on auto.conf -> rollback is set_config(param, prior.value)
   - set_config apply on non-auto.conf -> rollback is reset_config(param)
   - reset_config apply on auto.conf -> rollback is set_config(param, prior.value)
   - reset_config apply on non-auto.conf -> raises ValueError (no-op, no valid rollback)
   - rollback param must match apply param
   - rollback value must equal prior_state.value (for set_config rollback)
   - set_config apply with apply.value == prior_state.value is an error (no-op)
   - reset_config apply on non-auto.conf is an error (no-op)
"""
import json
from pathlib import Path

from jsonschema import Draft202012Validator

REPO_ROOT = Path(__file__).resolve().parents[3]
CONTRACTS_DIR = REPO_ROOT / "catalog" / "specs" / "contracts"
FIX_UNIT_SCHEMA = json.load(open(CONTRACTS_DIR / "fix-unit-v1.json", encoding="utf-8"))
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
    prior_state = fix_unit.get("prior_state", {})
    prior_state_value = prior_state.get("value")
    precheck_expected_value = fix_unit.get("precheck", {}).get("expected_value")

    if prior_state_value is not None and precheck_expected_value is not None:
        if prior_state_value != precheck_expected_value:
            errors.append(
                f"precheck.expected_value ({precheck_expected_value!r}) must equal "
                f"prior_state.value ({prior_state_value!r})"
            )

    # Rule 3: rollback must equal derive_rollback(prior_state, apply)
    apply_action = fix_unit.get("apply")
    rollback_action = fix_unit.get("rollback")

    if apply_action and rollback_action:
        apply_type = apply_action.get("action")
        apply_param = apply_action.get("param")
        apply_value = apply_action.get("value", "")

        rollback_type = rollback_action.get("action")
        rollback_param = rollback_action.get("param")
        rollback_value = rollback_action.get("value", "")

        # Check that rollback matches what derive_rollback would compute
        # Import after REPO_ROOT is defined
        from app.services.fix_unit_render import derive_rollback

        try:
            expected_rollback = derive_rollback(prior_state, apply_action)
        except ValueError as e:
            errors.append(str(e))
            # If derive_rollback raises, we can't continue validation
            return errors

        # Rollback action must match exactly
        if rollback_type != expected_rollback["action"]:
            errors.append(
                f"rollback action {rollback_type!r} does not match expected {expected_rollback['action']!r}"
            )

        # Rollback param must match apply param
        if rollback_param != apply_param:
            errors.append(
                f"rollback param {rollback_param!r} does not match apply param {apply_param!r}"
            )

        # For set_config rollback, value must equal prior_state.value
        if rollback_type == "set_config":
            if rollback_value != prior_state_value:
                errors.append(
                    f"rollback value {rollback_value!r} does not match prior_state.value {prior_state_value!r}"
                )

        # Check for no-op cases
        # set_config with apply.value == prior_state.value is a no-op
        if apply_type == "set_config" and apply_value == prior_state_value:
            errors.append(
                f"apply is a no-op: apply.value {apply_value!r} equals prior_state.value {prior_state_value!r}"
            )


    return errors
