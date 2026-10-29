"""Reviewed per-setting value rules for SET_CONFIG fix values.

One table, used by every place a fix value can enter rendered SQL:
- ``SetConfigTemplateParams`` (backend/app/models.py), before the approved
  set_config_parameter template is rendered;
- ``template_action`` (services/sandbox_poc/workflow.py), when the rendered
  statement is parsed back into a typed action;
- policy-profile ``fix``/``break`` values and site-specific ``fixes``
  (backend/app/services/spec_engine/policy.py).

The template renders ``ALTER SYSTEM SET {{ name | ident }} = '{{ value | literal }}'``
(``literal`` doubles single quotes; PostgreSQL 17 has standard_conforming_strings
on, so a backslash is not an escape). Values are still restricted much further
than that: every value is checked against GLOBAL_FORBIDDEN, then against the
setting's own rule: SETTING_ALLOWED_VALUES for boolean and enum settings,
SETTING_VALUE_RULES for free-form ones. A setting without an entry in either
keeps the caller's existing rule.
"""

from __future__ import annotations

import ipaddress
import re

# Never allowed in any value, whatever the setting (quote breakouts, statement
# separators, comments, dollar quoting, escapes, line breaks and NUL).
GLOBAL_FORBIDDEN = ("'", '"', "\\", ";", "\n", "\r", "\x00", "--", "/*", "$")

# The rule the sandbox loop always applied (workflow.template_action).
LEGACY_RE = re.compile(r"[a-zA-Z0-9_.]+")

# IPv4, IPv6 (e.g. ::1), host name, localhost; "::" (all IPv6 interfaces) cannot match
_HOST = r"[A-Za-z0-9:](?:[A-Za-z0-9.:-]*[A-Za-z0-9])?"
_PATH_PART = r"[A-Za-z0-9_.-]+"

# Reviewed per setting. Each pattern must match the WHOLE value (fullmatch).
SETTING_VALUE_RULES: dict[str, re.Pattern] = {
    # 3.1.24: '%' escapes, space and []:=,-@. plus letters/digits
    "log_line_prefix": re.compile(r"[A-Za-z0-9%\[\]:=,@. -]+"),
    # 3.1.5: strftime pattern; '%', '-', '_', '.'
    "log_filename": re.compile(r"[A-Za-z0-9%_.-]+"),
    # 3.1.4: absolute or relative path; '/', '-', '_', '.'; no '..' segment (checked below)
    "log_directory": re.compile(rf"/?{_PATH_PART}(?:/{_PATH_PART})*/?"),
    # 5.2: comma-separated IPs/host names, optional spaces; never '*' (a fix must not
    # listen everywhere, and no_item_in would refuse it anyway). Checked item by item
    # first by listen_addresses_errors (localhost required, Gate 1 ruling on 5.2).
    "listen_addresses": re.compile(rf"{_HOST}(?: *, *{_HOST})*"),
    # 3.1.26: tz names such as UTC, Etc/UTC, America/New_York, Etc/GMT+5
    "log_timezone": re.compile(r"[A-Za-z][A-Za-z0-9_+-]*(?:/[A-Za-z0-9_+-]+)*"),
    # 3.1.2: destination names separated by ',' and optional spaces
    "log_destination": re.compile(r"[a-z]+(?: *, *[a-z]+)*"),
    # 3.1.6: four octal digits (PostgreSQL accepts 0000-0777)
    "log_file_mode": re.compile(r"0[0-7]{3}"),
    # 3.1.8: duration, digits plus an optional PostgreSQL time unit
    "log_rotation_age": re.compile(r"[0-9]+(?:us|ms|s|min|h|d)?"),
    # 3.1.9: size, digits plus an optional PostgreSQL memory unit
    "log_rotation_size": re.compile(r"[0-9]+(?:B|kB|MB|GB|TB)?"),
    # 3.1.13: syslog program name; letters, digits, '_', '.', '-', 1-63 characters
    # (no space, '/', ':' or '<', so the FROM_PROFILE marker can never pass)
    "syslog_ident": re.compile(r"[A-Za-z0-9_.-]{1,63}"),
}


# Reviewed allowed values for every allowlisted boolean and enum setting (the
# SetConfigTemplateParams allowlist and POLICIES), from the PostgreSQL 17 docs and
# pg_settings.enumvals. Exact, case-sensitive match; a value is never rewritten, so
# the recorded apply value is always the literal that ran:
# - booleans accept the eight lowercase whole-word spellings PostgreSQL documents
#   (on, off, true, false, yes, no, 1, 0). Upper/mixed case and unique prefixes
#   (t, tr, y, of, ...) are refused: PostgreSQL accepts them, but they are needless
#   ambiguity in a reviewed fix. A reviewed fix value is still always on/off, because
#   planning.fix_scope requires it to satisfy the spec operator, which compares with
#   the canonical SHOW spelling.
# - enums accept only the visible enumvals in their canonical case (PostgreSQL
#   matches case-insensitively, but SHOW returns this spelling). Hidden aliases are
#   refused: 'debug' (= debug2) for the message levels, and '' (any version) for
#   ssl_min_protocol_version.
# Whether a value is compliant is the spec operator's job (planning.fix_scope); this
# table only says which values PostgreSQL 17 itself accepts for the setting.
_BOOL = frozenset({"on", "off", "true", "false", "yes", "no", "1", "0"})
_SERVER_MESSAGE_LEVELS = frozenset({"debug5", "debug4", "debug3", "debug2", "debug1", "info",
                                    "notice", "warning", "error", "log", "fatal", "panic"})
SETTING_ALLOWED_VALUES: dict[str, frozenset[str]] = {
    # vartype bool (PostgreSQL 17)
    "log_connections": _BOOL,
    "log_disconnections": _BOOL,
    "log_checkpoints": _BOOL,
    "log_lock_waits": _BOOL,
    "log_hostname": _BOOL,
    "log_truncate_on_rotation": _BOOL,
    "logging_collector": _BOOL,
    "syslog_sequence_numbers": _BOOL,
    "debug_print_parse": _BOOL,
    "debug_print_rewritten": _BOOL,
    "debug_print_plan": _BOOL,
    "debug_pretty_print": _BOOL,
    # vartype enum (PostgreSQL 17 pg_settings.enumvals, hidden aliases excluded)
    "log_statement": frozenset({"none", "ddl", "mod", "all"}),
    "log_error_verbosity": frozenset({"terse", "default", "verbose"}),
    "log_min_messages": _SERVER_MESSAGE_LEVELS,
    "log_min_error_statement": _SERVER_MESSAGE_LEVELS,
    "syslog_facility": frozenset(f"local{n}" for n in range(8)),
    "ssl_min_protocol_version": frozenset({"TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"}),
    "password_encryption": frozenset({"md5", "scram-sha-256"}),
}


def has_value_rule(name: str) -> bool:
    """True if setting ``name`` has a reviewed value rule or allowed-value set."""
    return name in SETTING_VALUE_RULES or name in SETTING_ALLOWED_VALUES


class SettingValueError(ValueError):
    """The value is not allowed for this setting."""


def forbidden_fragment(value: str) -> str | None:
    """The first globally forbidden fragment in value, or None."""
    return next((frag for frag in GLOBAL_FORBIDDEN if frag in value), None)


def check_setting_value(name: str, value, fallback: re.Pattern | None = LEGACY_RE) -> str:
    """Return value if it is allowed for setting ``name``; raise SettingValueError.

    ``fallback`` is the caller's existing rule for settings without an entry in
    SETTING_ALLOWED_VALUES or SETTING_VALUE_RULES (None means: no further rule
    beyond GLOBAL_FORBIDDEN).
    """
    if not isinstance(value, str) or value == "":
        raise SettingValueError(f"value for {name} must be a non-empty string")
    fragment = forbidden_fragment(value)
    if fragment is not None:
        raise SettingValueError(f"value for {name} contains a forbidden fragment {fragment!r}")
    if name == "listen_addresses":
        problem = listen_addresses_error(value)
        if problem is not None:
            raise SettingValueError(problem)
    allowed = SETTING_ALLOWED_VALUES.get(name)
    if allowed is not None:
        if value not in allowed:
            raise SettingValueError(
                f"value {value!r} is not allowed for {name}; allowed: {', '.join(sorted(allowed))}")
        return value
    rule = SETTING_VALUE_RULES.get(name, fallback)
    if rule is not None and not rule.fullmatch(value):
        raise SettingValueError(f"value {value!r} is not allowed for {name}")
    if name == "log_directory" and ".." in value.split("/"):
        raise SettingValueError("log_directory must not contain a '..' segment")
    return value


# 5.2 fix values (Gate 1 ruling, Melvin: "Require localhost in the value"). The
# sandbox runs with --network none, so after the restart PostgreSQL can bind only
# loopback; it keeps running as long as one listed address binds, so a fix value
# must list localhost. The site IP itself is never bound in the sandbox: the DBA
# confirms it on the host (planning.LISTEN_ADDRESSES_SANDBOX_LIMIT).
LISTEN_ALL_INTERFACES = ("*", "0.0.0.0")
# Labels start with a letter (stricter than RFC 1123, which allows a leading digit):
# no label can then be read as part of a numeric IPv4 form such as 0x0 or 127.1.
_HOSTNAME_LABEL_RE = re.compile(r"[A-Za-z](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
_LISTEN_EXAMPLE = "for example 'localhost, 10.0.0.5'"


def _is_hostname(item: str) -> bool:
    """Host name: dot-separated labels of letters, digits and inner hyphens.

    Every label starts with a letter (reviewed rule for 5.2, stricter than RFC
    1123), so no numeric form such as 10.0.0, 10.0.0.256, 0 or 0x0 is accepted as
    a host name. The last-label check is kept as a second guard.
    """
    labels = item.split(".")
    return (len(item) <= 253 and all(_HOSTNAME_LABEL_RE.fullmatch(label) for label in labels)
            and not labels[-1].isdigit())


def listen_addresses_error(value: str) -> str | None:
    """Why value cannot be a listen_addresses fix, or None if it can.

    The value is split exactly as the 5.2 check reads it (operators.guc_list_items,
    PostgreSQL 17 SplitGUCList). It must list localhost, must not list '*' or
    0.0.0.0 (or another all-interfaces address such as ::), and every other item
    must be a strict IPv4/IPv6 address or a host name whose labels start with a
    letter. An item made only of [0-9a-fA-FxX.] that is not a strict address
    (0x0, 0, 0.0x0, 0.0.0.00: glibc reads them as 0.0.0.0) is refused.
    """
    # Imported here: spec_engine imports this module (policy.py).
    from app.services.spec_engine.operators import guc_list_items, is_nonstandard_numeric_address

    try:
        items = guc_list_items(value, "listen_addresses")
    except ValueError as exc:
        return (f"listen_addresses value {value!r} is not a valid comma-separated address list "
                f"({exc}); use addresses separated by commas, {_LISTEN_EXAMPLE}")
    if not items:
        return f"listen_addresses value must list at least localhost, {_LISTEN_EXAMPLE}"
    wildcards = [item for item in items if item in LISTEN_ALL_INTERFACES]
    if wildcards:
        return (f"listen_addresses value must not contain {wildcards[0]!r}: {wildcards[0]!r} listens "
                f"on all interfaces and fails CIS 5.2; list specific addresses, {_LISTEN_EXAMPLE}")
    if "localhost" not in items:
        return ("listen_addresses value must include localhost as one of its items, "
                f"{_LISTEN_EXAMPLE}: the sandbox has no network, so PostgreSQL can only start "
                "on loopback after the restart")
    for item in items:
        if item == "localhost":
            continue
        if is_nonstandard_numeric_address(item):
            return (f"listen_addresses item {item!r} is not a valid IPv4 address, IPv6 address "
                    "or host name: it is a non-standard numeric form (hex, octal, leading zeros "
                    "or fewer than four parts) that the operating system can read as an IP "
                    "address, for example 0x0 or 0 as 0.0.0.0 (all interfaces); write an IPv4 "
                    "address as four decimal numbers without leading zeros, for example 10.0.0.5")
        try:
            address = ipaddress.ip_address(item)
        except ValueError:
            if _is_hostname(item):
                continue
            return (f"listen_addresses item {item!r} is not a valid IPv4 address, IPv6 address "
                    "or host name (each host-name label must start with a letter)")
        if address.is_unspecified or getattr(address, "scope_id", None):
            return (f"listen_addresses item {item!r} is not allowed: list a specific address "
                    "(not an all-interfaces address or one with a zone index)")
    return None
