"""Operators for spec validation checks."""

def _validate_actual_is_string(actual: str) -> None:
    """Validate that actual is a string, raise TypeError if not."""
    if not isinstance(actual, str):
        raise TypeError(f"actual must be a string, got {type(actual).__name__}")


def equals(actual: str, expected: str) -> bool:
    """Check if actual equals expected (exact string comparison)."""
    _validate_actual_is_string(actual)
    return actual == expected


def not_equals(actual: str, expected: str) -> bool:
    """Check if actual does not equal expected (exact string comparison)."""
    _validate_actual_is_string(actual)
    return actual != expected


def in_(actual: str, expected: list[str]) -> bool:
    """Check if actual is a member of expected list."""
    _validate_actual_is_string(actual)
    return actual in expected


def true(actual: str, expected: str) -> bool:
    """Operator that always returns True (pass_condition always satisfied)."""
    _validate_actual_is_string(actual)
    return True
