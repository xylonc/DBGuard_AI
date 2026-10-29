"""Settings the collector never ships the value of, and the marker it ships instead.

collector/collect.sql pg_temp.sanitise_setting replaces the value of a
secret-bearing setting with ``***REDACTED*** (set, N characters)`` in settings,
file_settings, role_settings and every manifest check result. The engine must
never evaluate an operator on that text: a ``not_equals`` or ``not_in`` rule
would PASS on it. A redacted value is NOT_COLLECTED (GAPPED), never PASS or FAIL.

The two lists mirror pg_temp.is_secret_setting exactly (a test parses the
collector and compares), so a spec can be rejected up front when the collector
would redact its setting:
- the seven built-in settings whose text can carry a secret;
- every dotted (custom or extension) name except the reviewed ones below.
A plain name the server does not know is also redacted by the collector; SHOW on
it errors, and any marker that still arrives is caught by ``is_redacted``.
"""

import string
from typing import Any

REDACTED_PREFIX = "***REDACTED***"

COLLECTOR_SECRET_SETTINGS = frozenset({
    "archive_command", "restore_command", "archive_cleanup_command",
    "recovery_end_command", "primary_conninfo", "ssl_passphrase_command",
    "krb_server_keyfile",
})

# Reviewed extension settings whose values CIS checks need and which carry no secrets.
COLLECTOR_REVIEWED_CUSTOM_SETTINGS = frozenset({
    "pgaudit.log", "pgaudit.log_catalog", "pgaudit.log_client",
    "pgaudit.log_level", "pgaudit.log_parameter",
    "pgaudit.log_parameter_max_size", "pgaudit.log_relation",
    "pgaudit.log_rows", "pgaudit.log_statement",
    "pgaudit.log_statement_once", "pgaudit.role",
    "set_user.block_alter_system", "set_user.block_copy_program",
    "set_user.block_log_statement", "set_user.exit_on_error",
    "set_user.nosuperuser_target_allowlist",
    "set_user.superuser_allowlist", "set_user.superuser_audit_tag",
    "pg_stat_statements.max", "pg_stat_statements.track",
    "pg_stat_statements.track_utility", "pg_stat_statements.track_planning",
    "pg_stat_statements.save",
    "plpgsql.variable_conflict", "plpgsql.print_strict_params",
    "plpgsql.check_asserts", "plpgsql.extra_warnings", "plpgsql.extra_errors",
})


def is_redacted(value: Any) -> bool:
    """True for the collector's redaction marker (a value DBGuard deliberately never read)."""
    return isinstance(value, str) and value.startswith(REDACTED_PREFIX)


# lower(... COLLATE "C") folds ASCII only, so look-alike characters (U+212A KELVIN
# SIGN, U+0130) never fold onto a reviewed name. str.lower() would fold them.
_ASCII_LOWER = str.maketrans(string.ascii_uppercase, string.ascii_lowercase)


def collector_redacts(name: str) -> bool:
    """True when the collector would redact this (known) setting's value."""
    lowered = name.translate(_ASCII_LOWER)
    if lowered in COLLECTOR_SECRET_SETTINGS:
        return True
    return "." in lowered and lowered not in COLLECTOR_REVIEWED_CUSTOM_SETTINGS
