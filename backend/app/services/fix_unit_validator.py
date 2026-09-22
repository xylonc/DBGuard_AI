"""Fix unit validation: cross-field rules that JSON Schema cannot express.

validate_fix_unit() returns ALL errors it can find. An empty list means the fix unit is valid.

Rules:
1. JSON Schema validation of fix_unit against catalog/specs/contracts/fix-unit-v1.json
2. precheck.expected_value must equal prior_state.value (compare-and-swap safety)
3. rollback must restore prior_state.value:
   - rollback.action must be compatible with apply.action:
     * set_config + reset_config is valid (revert to default)
     * reset_config + set_config is NOT valid (can't set a default value from reset)
     * set_config + set_config is valid (revert to prior value)
   - rollback.param must match apply.param
   - set_config: rollback.value == prior_state.value (exact string compare)
   - reset_config: invalid when prior_state.sourcefile ends in postgresql.auto.conf
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

    # Rule 3: rollback must restore prior_state.value
    # apply and rollback are now typed actions, not SQL strings
    apply_action = fix_unit.get("apply")
    rollback_action = fix_unit.get("rollback")

    if apply_action and rollback_action:
        apply_type = apply_action.get("action")
        rollback_type = rollback_action.get("action")
        apply_param = apply_action.get("param")
        rollback_param = rollback_action.get("param")

        # Action type compatibility:
        # - set_config + set_config: valid (revert to prior value)
        # - set_config + reset_config: valid (revert to default)
        # - reset_config + set_config: invalid (can't set from reset)
        # - reset_config + reset_config: invalid (already reset)
        if apply_type == "set_config":
            if rollback_type not in ("set_config", "reset_config"):
                errors.append(
                    f"rollback action {rollback_type!r} is not compatible with apply action {apply_type!r}"
                )
        elif apply_type == "reset_config":
            if rollback_type != "set_config":
                errors.append(
                    f"rollback action {rollback_type!r} is not compatible with apply action {apply_type!r}"
                )

        # Check parameter names match (when rollback is set_config)
        if rollback_type == "set_config" and apply_param != rollback_param:
            errors.append(
                f"rollback param {rollback_param!r} does not match apply param {apply_param!r}"
            )

        # Value check for set_config rollback (only when rollback is set_config)
        if rollback_type == "set_config":
            rollback_value = rollback_action.get("value", "")
            # Use is not None check, not truthiness: empty string prior value must be checked
            if prior_state_value is not None:
                if rollback_value != prior_state_value:
                    errors.append(
                        f"rollback value {rollback_value!r} does not match prior_state.value {prior_state_value!r}"
                    )

        # Check sourcefile for reset_config rollback (only valid when not in auto.conf)
        elif rollback_type == "reset_config":
            sourcefile = prior_state.get("sourcefile")
            # Use is not None check, not truthiness: empty string sourcefile means None
            if sourcefile is not None and sourcefile.endswith("postgresql.auto.conf"):
                errors.append(
                    f"RESET rollback is invalid when prior_state.sourcefile ends in postgresql.auto.conf "
                    f"({sourcefile!r}): RESET would drop the value instead of restoring it"
                )

    return errors
