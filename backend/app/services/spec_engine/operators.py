"""Operators for spec checks: the one rulebook for comparing a SHOW value.

Every caller (spec validation, the assessor, the offline ASSESS controls and
the sandbox fix policy) evaluates a check through ``evaluate`` so no copy of
an operator's semantics exists elsewhere.

Rules shared by every operator:
- ``actual`` must be a str (the exact SHOW output); anything else is TypeError.
- ``expected`` must have the operator's shape (see ``EXPECTED_SHAPE``);
  anything else is TypeError.
- A value an operator cannot interpret (unknown severity level, unparseable
  list) raises ValueError. Callers turn TypeError/ValueError into ERROR,
  never PASS.
"""

import ipaddress
import re


def _validate_actual_is_string(actual: str) -> None:
    """Validate that actual is a string, raise TypeError if not."""
    if not isinstance(actual, str):
        raise TypeError(f"actual must be a string, got {type(actual).__name__}")


def _require_str(expected) -> None:
    if not isinstance(expected, str):
        raise TypeError(f"expected must be a string, got {type(expected).__name__}")


def _require_str_list(expected) -> None:
    if not (isinstance(expected, list) and all(isinstance(v, str) for v in expected)):
        raise TypeError(f"expected must be a list of strings, got {type(expected).__name__}")


def equals(actual: str, expected: str) -> bool:
    """Check if actual equals expected (exact string comparison)."""
    _validate_actual_is_string(actual)
    _require_str(expected)
    return actual == expected


def not_equals(actual: str, expected: str) -> bool:
    """Check if actual does not equal expected (exact string comparison)."""
    _validate_actual_is_string(actual)
    _require_str(expected)
    return actual != expected


def in_(actual: str, expected: list[str]) -> bool:
    """Check if actual is a member of expected list (exact string comparison)."""
    _validate_actual_is_string(actual)
    _require_str_list(expected)
    return actual in expected


# ---- Wave 1b operators -------------------------------------------------------


def not_in(actual: str, expected: list[str]) -> bool:
    """Check that actual is NOT a member of expected list (exact string comparison).

    Exact comparison only: SHOW listen_addresses = '*, 10.0.0.1' is not the
    member '*'. A spec that needs list semantics must use contains_items or
    (for listen_addresses) no_item_in.
    """
    _validate_actual_is_string(actual)
    _require_str_list(expected)
    return actual not in expected


# Tokenisation for list-valued string settings such as log_destination.
#
# PG17 stores and SHOWs log_destination exactly as written (verified on 17.11:
# ALTER SYSTEM SET log_destination = ' Stderr , CSVLOG' -> SHOW ' Stderr , CSVLOG').
# The server parses it with SplitIdentifierString (comma separated, surrounding
# whitespace ignored, unquoted names downcased, double-quoted names kept) and
# matches destinations case-insensitively. We follow those semantics so a
# condition such as "log_destination includes syslog" can never be read as
# false for 'SYSLOG' (which would wrongly make a control NOT_APPLICABLE).
# Anything outside the plain forms below raises ValueError -> ERROR, never PASS.
_LIST_ITEM_RE = re.compile(r'[A-Za-z0-9_]+|"[A-Za-z0-9_]+"')


def list_items(actual: str) -> set[str]:
    """Split a comma-separated SHOW value into lower-cased items."""
    _validate_actual_is_string(actual)
    if actual.strip() == "":
        return set()
    items = set()
    for raw in actual.split(","):
        token = raw.strip()
        if not _LIST_ITEM_RE.fullmatch(token):
            raise ValueError(f"unparseable list item {token!r}")
        items.add(token.strip('"').lower())
    return items


def contains_items(actual: str, expected: list[str]) -> bool:
    """Every expected item is one of the comma-separated items in actual.

    Items are compared after trimming whitespace, removing double quotes and
    lower-casing (PostgreSQL's own reading of log_destination). Expected items
    must already be lower-case (enforced by spec validation).
    """
    _require_str_list(expected)
    return {item.lower() for item in expected} <= list_items(actual)


# Escapes for log_line_prefix, PostgreSQL 17 (runtime-config-logging.html#GUC-LOG-LINE-PREFIX).
# %q (stop for non-session processes) and %% (literal percent) are not
# status escapes and may not be required by a spec.
LOG_LINE_PREFIX_ESCAPES = frozenset(
    "%" + c for c in "audrhLbpPtmnieclsvxQ"
)


def line_prefix_escapes(actual: str) -> set[str]:
    """Return the escapes printed for EVERY process, mirroring PG17 elog.c.

    Scanner (log_status_format / process_log_prefix_padding):
    - '%%' is a literal percent, not an escape;
    - '%' may be followed by an optional '-' and digits (padding), then the
      escape character, so '%-10u' is the %u escape;
    - a '%' (or padding) at the end of the string is ignored;
    - unknown escape characters are ignored, like the server does.
    Escapes after the first %q are only printed by session processes, so they
    are NOT counted: a required escape must appear before any %q.
    """
    _validate_actual_is_string(actual)
    found: set[str] = set()
    i, n = 0, len(actual)
    while i < n:
        if actual[i] != "%":
            i += 1
            continue
        i += 1
        if i >= n:
            break
        if actual[i] == "%":
            i += 1
            continue
        if actual[i] <= "9":  # padding: optional '-' then digits
            if actual[i] == "-":
                i += 1
                if i >= n:
                    break
            while i < n and "0" <= actual[i] <= "9":
                i += 1
            if i >= n:
                break
        escape = "%" + actual[i]
        i += 1
        if escape == "%q":
            break
        if escape in LOG_LINE_PREFIX_ESCAPES:
            found.add(escape)
    return found


def contains_escapes(actual: str, expected: list[str]) -> bool:
    """Every expected escape (e.g. '%m', '%p') is used in actual before any %q."""
    _require_str_list(expected)
    return set(expected) <= line_prefix_escapes(actual)


# GUC list parsing for listen_addresses, mirroring PostgreSQL 17.
#
# postmaster.c reads listen_addresses with SplitGUCList(rawstring, ',', ...)
# (utils/adt/varlena.c) and treats an element equal to "*" as "all interfaces":
# - leading/trailing whitespace (scanner_isspace: space, \t, \n, \r, \v, \f)
#   around each element is skipped; an empty or all-whitespace string is the
#   empty list (no TCP/IP listening);
# - an element may be double-quoted, '""' inside quotes is a literal '"', and
#   the quotes are removed (so '"*"' is also "all interfaces");
# - an unquoted element ends at ',' or whitespace and must not be empty;
# - anything else (unclosed quote, '10.0.0.1 10.0.0.2', ',,') is a syntax error
#   that stops the server.
# Elements are NOT case-folded. On top of PG's grammar we only accept elements
# that look like '*', a host name or an IPv4/IPv6 address; anything else raises
# ValueError -> ERROR, never PASS. Reviewed per setting: a spec may only use
# no_item_in on a setting listed in GUC_LIST_SETTINGS.
_GUC_SPACE = " \t\n\r\v\f"
_ADDRESS_ITEM_RE = re.compile(r"\*|[A-Za-z0-9.:%_-]+")
GUC_LIST_SETTINGS = {"listen_addresses": _ADDRESS_ITEM_RE}


def guc_list_items(actual: str, setting_name: str) -> list[str]:
    """Split a SHOW value the way PostgreSQL 17 SplitGUCList does (see above)."""
    _validate_actual_is_string(actual)
    if setting_name not in GUC_LIST_SETTINGS:
        raise ValueError(f"no reviewed list grammar for setting {setting_name!r}")
    item_re = GUC_LIST_SETTINGS[setting_name]
    items: list[str] = []
    i, n = 0, len(actual)
    while i < n and actual[i] in _GUC_SPACE:
        i += 1
    if i == n:
        return items
    while True:
        if actual[i] == '"':
            chars = []
            i += 1
            while True:
                if i >= n:
                    raise ValueError("unclosed double quote in list")
                if actual[i] == '"':
                    if i + 1 < n and actual[i + 1] == '"':
                        chars.append('"')
                        i += 2
                        continue
                    i += 1
                    break
                chars.append(actual[i])
                i += 1
            item = "".join(chars)
        else:
            start = i
            while i < n and actual[i] != "," and actual[i] not in _GUC_SPACE:
                i += 1
            if i == start:
                raise ValueError("empty list element")
            item = actual[start:i]
        while i < n and actual[i] in _GUC_SPACE:
            i += 1
        if not item_re.fullmatch(item):
            raise ValueError(f"unparseable {setting_name} element {item!r}")
        items.append(item)
        if i == n:
            return items
        if actual[i] != ",":
            raise ValueError(f"invalid {setting_name} list syntax")
        i += 1
        while i < n and actual[i] in _GUC_SPACE:
            i += 1
        if i == n:
            raise ValueError("empty list element after ','")


# Non-standard numeric address forms. PostgreSQL resolves each listen_addresses item
# with getaddrinfo, and glibc reads IPv4 text the way inet_aton does: hex (0x0),
# octal (leading zero, 0.0.0.00), and one to three parts (0, 0.0x0, 127.1) are all
# addresses, so '0', '0x0', '0.0x0' and '0.0.0.00' all mean 0.0.0.0. Python's
# ipaddress accepts only the strict dotted-decimal / RFC 4291 text. An item made only
# of [0-9a-fA-FxX.] that ipaddress rejects is therefore treated as possibly an
# all-interfaces address: never PASS (check side) and never a fix value (value side,
# setting_values.listen_addresses_error). IPv6 forms contain ':' and are not covered
# here; '::' is out of 5.2's scope (spec interpretation).
_NUMERIC_ISH_RE = re.compile(r"[0-9a-fA-FxX.]+")


def is_nonstandard_numeric_address(item: str) -> bool:
    """True if item is numeric-looking text that strict ipaddress parsing rejects."""
    if not _NUMERIC_ISH_RE.fullmatch(item):
        return False
    try:
        ipaddress.ip_address(item)
    except ValueError:
        return True
    return False


def no_item_in(actual: str, expected: list[str], *, setting_name: str) -> bool:
    """True when NO element of the list setting is one of expected.

    5.2: SHOW listen_addresses = '*, 10.0.0.1' FAILs (it contains '*'), while
    '' (no TCP listening) and 'localhost' PASS. Elements are compared exactly.
    For listen_addresses, an element in a non-standard numeric form (e.g. '0x0',
    '0', '0.0.0.00', which the OS may read as 0.0.0.0) raises ValueError -> ERROR,
    never PASS, unless an expected element already makes the result FAIL.
    """
    _require_str_list(expected)
    items = guc_list_items(actual, setting_name)
    if set(expected) & set(items):
        return False
    if setting_name == "listen_addresses":
        ambiguous = [item for item in items if is_nonstandard_numeric_address(item)]
        if ambiguous:
            raise ValueError(
                f"listen_addresses element {ambiguous[0]!r} is a non-standard numeric address "
                "form that the operating system may read as an IP address (possibly 0.0.0.0); "
                "it cannot be assessed")
    return True


# Severity ordering, most verbose first. Source: PostgreSQL 17 docs,
# https://www.postgresql.org/docs/17/runtime-config-logging.html#RUNTIME-CONFIG-LOGGING-WHEN
# log_min_messages: "Valid values are DEBUG5, DEBUG4, DEBUG3, DEBUG2, DEBUG1,
# INFO, NOTICE, WARNING, ERROR, LOG, FATAL, and PANIC. Each level includes all
# the levels that follow it. The later the level, the fewer messages are sent".
# log_min_error_statement lists the same values. Cross-checked against
# pg_settings.enumvals on PostgreSQL 17.11 (both settings report exactly this
# list; SHOW returns the lower-case canonical name, e.g. the alias 'debug'
# shows as 'debug2'). Each setting keeps its own table so a future setting with
# a different scale (client_min_messages) cannot silently reuse this one.
SERVER_MESSAGE_LEVELS = (
    "debug5", "debug4", "debug3", "debug2", "debug1",
    "info", "notice", "warning", "error", "log", "fatal", "panic",
)
SEVERITY_SCALES = {
    "log_min_messages": SERVER_MESSAGE_LEVELS,
    "log_min_error_statement": SERVER_MESSAGE_LEVELS,
}
SEVERITY_DIRECTIONS = ("at_or_more_verbose", "at_or_less_verbose")


def severity(actual: str, expected: str, *, setting_name: str, direction: str) -> bool:
    """Compare two levels on the setting's fixed scale.

    at_or_more_verbose: actual is expected or earlier in the list (logs at least
    as much). at_or_less_verbose: actual is expected or later (logs at most as
    much). Which direction a benchmark means is a human ruling recorded in the spec.
    """
    _validate_actual_is_string(actual)
    _require_str(expected)
    if setting_name not in SEVERITY_SCALES:
        raise ValueError(f"no reviewed severity scale for setting {setting_name!r}")
    if direction not in SEVERITY_DIRECTIONS:
        raise ValueError(f"unknown severity direction {direction!r}")
    scale = SEVERITY_SCALES[setting_name]
    if actual not in scale:
        raise ValueError(f"unknown {setting_name} level {actual!r}")
    if expected not in scale:
        raise ValueError(f"unknown {setting_name} level {expected!r}")
    if direction == "at_or_more_verbose":
        return scale.index(actual) <= scale.index(expected)
    return scale.index(actual) >= scale.index(expected)


# ---- registry ------------------------------------------------------------------

OPERATORS = {
    "equals": equals,
    "not_equals": not_equals,
    "in": in_,
    "not_in": not_in,
    "contains_items": contains_items,
    "contains_escapes": contains_escapes,
    "severity": severity,
    "no_item_in": no_item_in,
}

# Shape of check.expected per operator: one non-empty string or a non-empty list.
EXPECTED_SHAPE = {
    "equals": "str",
    "not_equals": "str",
    "in": "list",
    "not_in": "list",
    "contains_items": "list",
    "contains_escapes": "list",
    "severity": "str",
    "no_item_in": "list",
}

# Extra check keys an operator needs (required for it, forbidden for the rest).
OPERATOR_PARAMS = {"severity": ("direction",)}

# Operators that read check.setting_name to pick a reviewed per-setting table.
SETTING_TABLE_OPERATORS = {"severity": SEVERITY_SCALES, "no_item_in": GUC_LIST_SETTINGS}


def evaluate(check: dict, actual: str, expected=None) -> bool:
    """Evaluate a check (or applies_when) mapping against a SHOW value.

    ``expected`` overrides check['expected'] (used for policy-profile values).
    Raises TypeError/ValueError on anything it cannot interpret.
    """
    operator = check.get("operator")
    if operator not in OPERATORS:
        raise ValueError(f"unknown operator {operator!r}")
    if expected is None:
        expected = check.get("expected")
    if operator == "severity":
        return severity(actual, expected, setting_name=check.get("setting_name"),
                        direction=check.get("direction"))
    if operator == "no_item_in":
        return no_item_in(actual, expected, setting_name=check.get("setting_name"))
    return OPERATORS[operator](actual, expected)


def describe_expected(check: dict, expected=None) -> str:
    """Human-readable form of what the check accepts, for FAIL rationales."""
    operator = check["operator"]
    if expected is None:
        expected = check["expected"]
    quoted = lambda values: ", ".join(f"'{v}'" for v in values)  # noqa: E731
    if operator == "equals":
        return f"'{expected}'"
    if operator == "not_equals":
        return f"anything other than '{expected}'"
    if operator == "in":
        return "one of " + quoted(expected)
    if operator == "not_in":
        return "none of " + quoted(expected)
    if operator == "contains_items":
        return "a list including " + quoted(expected)
    if operator == "no_item_in":
        return "a list with none of " + quoted(expected)
    if operator == "contains_escapes":
        return "a prefix including the escapes " + quoted(expected)
    if operator == "severity":
        word = "or more verbose" if check.get("direction") == "at_or_more_verbose" else "or less verbose"
        return f"'{expected}' {word}"
    raise ValueError(f"unknown operator {operator!r}")
