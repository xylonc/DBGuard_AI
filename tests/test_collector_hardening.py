"""collect.sql pins its own session before it runs anything (no Docker).

A target controls per-role and per-database defaults. Two of them change what
the collector's own SQL means:

  * search_path: an object the target created (evil.current_setting) shadows
    the built-in, so the collector reports the attacker's values;
  * standard_conforming_strings = off: backslashes in '...' literals become
    escapes, the masking regexes (\\s, \\S+, \\1) stop matching, and secrets in
    archive_command / primary_conninfo reach the bundle.

The fix is two plain SET statements that must run before any DO, CREATE or
SELECT, and before any masking helper is defined or used. The live proof is
tests/test_collector_hardening_live.py; this file checks the text itself, and
checks that the checker rejects the plausible wrong versions.

Secret-bearing settings (archive_command, primary_conninfo and five others,
plus every custom or extension setting except an exact list of reviewed
extension settings, as decided by is_secret_setting) are never shipped as text: sanitise_setting
returns only "***REDACTED*** (set, N characters)", whatever the case of the
name, in settings, file_settings, role_settings and manifest checks.
parse_conninfo returns only allowlisted connection keys, their values still
passed through mask_secrets. Row-level security policy expressions ship as the
same marker. All of it is checked below, and so is every wrong version a
reviewer has blocked so far.
"""
import json
import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
COLLECT_SQL = ROOT / "collector" / "collect.sql"

PIN_SEARCH_PATH = "SET search_path = pg_catalog, pg_temp"
PIN_SCS = "SET standard_conforming_strings = on"
PINNED_SETTINGS = ("search_path", "standard_conforming_strings")
# Every function collect.sql defines. All live in pg_temp and are called
# qualified, so neither a target schema nor search_path can substitute them.
HELPERS = ("mask_secrets", "is_secret_setting", "sanitise_setting", "parse_conninfo", "try_jsonb",
           "try_reason", "run_checks", "sql_password_types", "sql_hba", "sql_ident", "sql_file_settings",
           "sql_functions", "sql_archiving")
MASKING_HELPERS = ("mask_secrets", "is_secret_setting", "sanitise_setting", "parse_conninfo")
META_LINE = re.compile(r"[ \t]*\\")
DOLLAR_TAG = re.compile(r"\$([A-Za-z_][A-Za-z_0-9]*)?\$")


def top_level_statements(text: str) -> list[str]:
    """Split psql input into SQL statements, as psql would send them.

    Drops `--` comments and psql meta-command lines (\\set, \\pset). Keeps
    '...' literals (with '' escapes; backslash is literal because the file
    runs with standard_conforming_strings on), $tag$...$tag$ bodies and
    psql :'var' interpolations intact, so a `--` or `;` inside them neither
    starts a comment nor ends a statement. Whitespace is collapsed.
    """
    out, buf, i, n = [], [], 0, len(text)
    at_line_start = True
    while i < n:
        c = text[i]
        if at_line_start and not "".join(buf).strip() and META_LINE.match(text, i):
            i = text.find("\n", i)  # psql meta-command: whole line, never SQL
            i = n if i == -1 else i + 1
            continue
        at_line_start = False
        if text.startswith("--", i):
            j = text.find("\n", i)
            i = n if j == -1 else j
            buf.append(" ")
            continue
        if c == "'":
            j = i + 1
            while j < n:
                if text[j] == "'" and text.startswith("''", j):
                    j += 2
                elif text[j] == "'":
                    break
                else:
                    j += 1
            buf.append(text[i:j + 1])
            i = j + 1
            continue
        m = DOLLAR_TAG.match(text, i) if c == "$" else None
        if m:
            tag = m.group(0)
            j = text.find(tag, i + len(tag))
            assert j != -1, f"unterminated dollar quote {tag}"
            buf.append(text[i:j + len(tag)])
            i = j + len(tag)
            continue
        if c == ";":
            stmt = " ".join("".join(buf).split())
            if stmt:
                out.append(stmt)
            buf = []
        else:
            buf.append(c)
            if c == "\n":
                at_line_start = True
        i += 1
    tail = " ".join("".join(buf).split())
    if tail:
        out.append(tail)
    return out


def strip_comments(text: str) -> str:
    """The SQL with comments and meta-commands removed, statements rejoined."""
    return ";\n".join(top_level_statements(text))


def hardening_problems(text: str) -> list[str]:
    """Every way `text` fails to pin the session first. [] means hardened."""
    problems = []
    stmts = top_level_statements(text)
    if stmts[:2] != [PIN_SEARCH_PATH, PIN_SCS]:
        problems.append(f"first two statements must be the pins, got {stmts[:2]!r}")
    first = {
        kw: next((k for k, s in enumerate(stmts) if re.match(rf"{kw}\b", s, re.I)), None)
        for kw in ("DO", "CREATE", "SELECT")
    }
    for kw, idx in first.items():
        if idx is None:
            problems.append(f"no {kw} statement found; the parser or the file changed")
    for pin in (PIN_SEARCH_PATH, PIN_SCS):
        if pin not in stmts:
            problems.append(f"missing {pin!r}")
            continue
        at = stmts.index(pin)
        for kw, idx in first.items():
            if idx is not None and idx < at:
                problems.append(f"{pin!r} runs after the first {kw}")
        for name in MASKING_HELPERS:
            use = next((k for k, s in enumerate(stmts) if name in s), None)
            if use is not None and use < at:
                problems.append(f"{pin!r} runs after {name} is defined or used")
    # Nothing later may undo the pins: no second SET, no SET LOCAL/SESSION,
    # no RESET, no set_config() on either name.
    for k, s in enumerate(stmts):
        if s in (PIN_SEARCH_PATH, PIN_SCS) and k < 2:
            continue
        for name in PINNED_SETTINGS:
            if re.search(rf"\b(SET|RESET)\b(\s+(LOCAL|SESSION))?\s+{name}\b", s, re.I):
                problems.append(f"statement {k} changes {name}: {s[:80]!r}")
            if re.search(rf"set_config\s*\(\s*'{name}'", s, re.I):
                problems.append(f"statement {k} calls set_config on {name}")
        if re.search(r"\bRESET\s+ALL\b|\bDISCARD\s+ALL\b", s, re.I):
            problems.append(f"statement {k} resets the session: {s[:80]!r}")
    return problems


def strip_line_comments(code: str) -> str:
    """`code` with every `--` comment removed, including those inside $$
    function bodies (which top_level_statements keeps whole). '...' literals,
    with '' escapes, are copied intact, so '--password' is not a comment."""
    out, i, n = [], 0, len(code)
    while i < n:
        if code.startswith("--", i):
            j = code.find("\n", i)
            i = n if j == -1 else j
        elif code[i] == "'":
            j = i + 1
            while j < n:
                if code.startswith("''", j):
                    j += 2
                elif code[j] == "'":
                    break
                else:
                    j += 1
            out.append(code[i:j + 1])
            i = j + 1
        else:
            out.append(code[i])
            i += 1
    return "".join(out)


def unqualified_helper_calls(text: str) -> list[str]:
    # A helper named in a comment inside a function body is not a call. Strip
    # those first, on the raw text: strip_comments collapses newlines, after
    # which a '--' would run to the end of the whole statement.
    code = strip_comments(strip_line_comments(text))
    return [m.group(0) for name in HELPERS
            for m in re.finditer(rf"(?<![\w.])(\w+\.)?{name}\b", code)
            if m.group(1) != "pg_temp."]


@pytest.fixture(scope="module")
def sql() -> str:
    return COLLECT_SQL.read_text(encoding="utf-8")


class TestCollectSqlPinsItsSession:

    def test_pins_are_the_first_two_statements(self, sql):
        stmts = top_level_statements(sql)
        assert stmts[0] == PIN_SEARCH_PATH
        assert stmts[1] == PIN_SCS

    def test_no_hardening_problems(self, sql):
        assert hardening_problems(sql) == []

    def test_pins_precede_first_do_create_select_by_text_position(self, sql):
        """Same property as above, measured on raw offsets, independent of the splitter."""
        code = strip_comments(sql)
        sp, scs = code.index(PIN_SEARCH_PATH), code.index(PIN_SCS)
        for pattern in (r"^DO\b", r"^CREATE\b", r"^SELECT\b", r"\bSELECT\b"):
            first = re.search(pattern, code, re.M)
            assert first, pattern
            assert sp < first.start() and scs < first.start(), pattern
        for name in MASKING_HELPERS:
            assert sp < code.index(name) and scs < code.index(name), name

    def test_search_path_puts_pg_temp_last_explicitly(self, sql):
        """Leaving pg_temp out does not remove it: PostgreSQL then searches it
        FIRST for relations. It has to be named, and named after pg_catalog."""
        stmt = top_level_statements(sql)[0]
        value = [p.strip() for p in stmt.split("=", 1)[1].split(",")]
        assert value == ["pg_catalog", "pg_temp"]

    def test_every_helper_is_created_in_pg_temp(self, sql):
        creates = [s for s in top_level_statements(sql) if re.match(r"CREATE\b", s, re.I)]
        assert len(creates) == len(HELPERS)
        for s in creates:
            assert re.match(r"CREATE FUNCTION pg_temp\.\w+\(", s), s[:80]
        created = {re.match(r"CREATE FUNCTION pg_temp\.(\w+)\(", s).group(1) for s in creates}
        assert created == set(HELPERS)

    def test_every_helper_call_is_schema_qualified(self, sql):
        assert unqualified_helper_calls(sql) == []


class TestTheCheckerCatchesWrongVersions:
    """Each mutation is a plausible wrong fix. The checker must reject all of them."""

    @staticmethod
    def _without_pins(sql: str) -> str:
        out = sql.replace(PIN_SEARCH_PATH + ";\n", "").replace(PIN_SCS + ";\n", "")
        assert PIN_SEARCH_PATH not in out and PIN_SCS not in out
        return out

    def test_splitter_keeps_literals_with_comment_and_semicolon_intact(self):
        text = "\\set QUIET on\n-- a; comment\nSET a = 1;\nSELECT '(--password; x)' -- tail\n, $q$ a; -- b $q$;\n"
        assert top_level_statements(text) == ["SET a = 1", "SELECT '(--password; x)' , $q$ a; -- b $q$"]

    def test_old_collector_without_pins_is_rejected(self, sql):
        problems = hardening_problems(self._without_pins(sql))
        assert any("missing 'SET search_path" in p for p in problems), problems
        assert any("missing 'SET standard_conforming_strings" in p for p in problems), problems

    @pytest.mark.parametrize("anchor", ["DO $$", "CREATE FUNCTION pg_temp.mask_secrets"])
    def test_pins_moved_below_first_statement_are_rejected(self, sql, anchor):
        bare = self._without_pins(sql)
        at = bare.index(anchor)
        if anchor == "DO $$":
            # after the whole managed-platform DO block
            at = bare.index("$$;", at) + len("$$;\n")
        moved = bare[:at] + f"{PIN_SEARCH_PATH};\n{PIN_SCS};\n" + bare[at:]
        assert hardening_problems(moved), anchor

    def test_only_one_pin_is_rejected(self, sql):
        assert hardening_problems(sql.replace(PIN_SCS + ";\n", ""))
        assert hardening_problems(sql.replace(PIN_SEARCH_PATH + ";\n", ""))

    @pytest.mark.parametrize("wrong", [
        "SET LOCAL search_path = pg_catalog, pg_temp",     # ends with the implicit transaction
        "SET search_path = pg_catalog",                     # pg_temp implicitly searched first
        "SET search_path = pg_temp, pg_catalog",            # temp objects shadow built-ins
        "SET search_path = public, pg_catalog, pg_temp",    # target-writable schema first
        "SET search_path TO DEFAULT",                        # back to the target's value
    ])
    def test_wrong_search_path_pin_is_rejected(self, sql, wrong):
        assert hardening_problems(sql.replace(PIN_SEARCH_PATH, wrong, 1))

    @pytest.mark.parametrize("wrong", [
        "SET LOCAL standard_conforming_strings = on",
        "SET standard_conforming_strings = off",
        "SET escape_string_warning = off",
    ])
    def test_wrong_scs_pin_is_rejected(self, sql, wrong):
        assert hardening_problems(sql.replace(PIN_SCS, wrong, 1))

    @pytest.mark.parametrize("undo", [
        "RESET search_path;",
        "SET search_path = evil, pg_catalog;",
        "SET SESSION standard_conforming_strings = off;",
        "SELECT set_config('search_path', 'public', false);",
        "RESET ALL;",
        "DISCARD ALL;",
    ])
    def test_a_later_statement_undoing_the_pins_is_rejected(self, sql, undo):
        at = sql.index("CREATE FUNCTION pg_temp.mask_secrets")
        assert hardening_problems(sql[:at] + undo + "\n" + sql[at:]), undo

    def test_unqualified_helper_call_is_caught(self, sql):
        # sanitise_setting no longer calls mask_secrets, so the unqualified
        # call is planted in run_checks' call of sanitise_setting instead.
        call = "pg_temp.sanitise_setting(v_name, current_setting(v_name))"
        assert sql.count(call) == 1
        bad = sql.replace(call, "sanitise_setting(v_name, current_setting(v_name))", 1)
        assert unqualified_helper_calls(bad) == ["sanitise_setting"]
        call = "pg_temp.mask_secrets(substring(val from position('=' in val) + 1))"
        assert sql.count(call) == 1
        bad = sql.replace(call, "mask_secrets(substring(val from position('=' in val) + 1))", 1)
        assert unqualified_helper_calls(bad) == ["mask_secrets"]

    def test_comment_stripping_inside_bodies_hides_no_real_call(self, sql):
        """Comments inside $$ bodies are ignored, but a call inside a body, or
        on the same line after a '--' that sits in a literal, is still caught."""
        call ="pg_temp.mask_secrets(trim(both '''' from m[2]))"
        assert call in sql
        bad = sql.replace(call, "mask_secrets(trim(both '''' from m[2]))", 1)
        assert unqualified_helper_calls(bad) == ["mask_secrets"]
        assert strip_line_comments("SELECT '--x', f(1) -- mask_secrets\n") == "SELECT '--x', f(1) \n"
        assert strip_line_comments("SELECT 'it''s -- ok' || g()") == "SELECT 'it''s -- ok' || g()"


# ---------------------------------------------------------------------------
# parse_conninfo never returns a secret key, in URI or keyword form: only
# allowlisted connection keys leave it, and a URI that cannot be read safely
# ('@' after the userinfo; whitespace or '=' in user, host or dbname) is
# reported as {unparsed: true}. The live proof (planted secrets, real
# collector) is
# tests/test_collector_hardening_live.py::test_primary_conninfo_never_leaks_and_parses_exactly;
# these text checks fail fast if a guard is loosened.
# ---------------------------------------------------------------------------

REQUIRED_SECRET_KEYS = {"password", "passfile", "sslpassword"}

# origin/main's (and 03a618c's: identical) two masking helpers, verbatim from
# "CREATE FUNCTION" up to "$$ LANGUAGE". Swapped into today's file, each must
# be rejected by the checkers below.
MAIN_MASK_SECRETS = r"""CREATE FUNCTION pg_temp.mask_secrets(v text) RETURNS text AS $$
    SELECT CASE WHEN $1 IS NULL THEN NULL ELSE
        regexp_replace(
        regexp_replace(
        regexp_replace(
        regexp_replace($1,
            '(password\s*=\s*)(''[^'']*''|"[^"]*"|\S+)', '\1***REDACTED***', 'gi'),
            '(passfile\s*=\s*)(\S+)',                    '\1***REDACTED***', 'gi'),
            '(--password[= ])(\S+)',                     '\1***REDACTED***', 'gi'),
            '://([^:/@\s]+):([^@/\s]+)@',                '://\1:***REDACTED***@', 'g')
    END;
"""
MAIN_PARSE_CONNINFO = r"""CREATE FUNCTION pg_temp.parse_conninfo(v text) RETURNS jsonb AS $$
DECLARE
    kv   text[];
    part text;
    k    text;
    val  text;
    out  jsonb := '{}'::jsonb;
BEGIN
    IF v IS NULL OR v = '' THEN RETURN NULL; END IF;
    kv := regexp_split_to_array(v, '\s+');
    FOREACH part IN ARRAY kv LOOP
        IF position('=' in part) > 0 THEN
            k   := lower(split_part(part, '=', 1));
            val := substring(part from position('=' in part) + 1);
            IF k NOT IN ('password','passfile') THEN
                out := out || jsonb_build_object(k, trim(both '''"' from val));
            END IF;
        END IF;
    END LOOP;
    RETURN out;
END;
"""


def parse_conninfo_body(text: str) -> str:
    start = text.index("CREATE FUNCTION pg_temp.parse_conninfo(")
    end = text.index("$$ LANGUAGE", start)
    return text[start:end]


# The reviewed allowlist (Melvin's "never ship raw text" design): known libpq
# connection keys that name a place, a mode or a timeout, never a credential.
# Anything else (options, password, passfile, sslpassword, unknown keys) is
# dropped. Pinned exactly: widening it is a review decision, not a refactor.
EXPECTED_ALLOWED_KEYS = {
    "host", "hostaddr", "port", "user", "dbname", "application_name",
    "sslmode", "sslrootcert", "sslcert", "sslkey", "sslcrl", "sslcrldir", "sslsni",
    "gssencmode", "channel_binding", "target_session_attrs", "load_balance_hosts",
    "connect_timeout", "keepalives", "keepalives_idle", "keepalives_interval",
    "keepalives_count", "tcp_user_timeout", "krbsrvname", "service", "requiressl",
    "replication",
    # Added after db-security-reviewer's third pass: TLS / auth policy and
    # naming keys whose values are modes, versions or names, never secrets.
    "ssl_min_protocol_version", "ssl_max_protocol_version", "require_auth", "sslcertmode",
    "sslnegotiation", "sslcompression", "gssdelegation", "fallback_application_name",
}
ADDED_ALLOWED_KEYS = {"ssl_min_protocol_version", "ssl_max_protocol_version", "require_auth", "sslcertmode",
                      "sslnegotiation", "sslcompression", "gssdelegation", "fallback_application_name"}
# Keys parse_conninfo may emit by name rather than through `k`.
LITERAL_EMIT_KEYS = {"user", "host", "dbname", "unparsed"}


def conninfo_allowed_keys(code: str) -> set[str] | None:
    m = re.search(r"allowed\s+text\[\]\s*:=\s*ARRAY\[([^\]]*)\]", code)
    return None if m is None else {s.strip().strip("'").lower() for s in m.group(1).split(",")}


def unparsed_condition(code: str) -> str | None:
    """The condition of the IF whose body returns {unparsed: true}."""
    at = code.find("RETURN jsonb_build_object('unparsed', true)")
    if at == -1:
        return None
    m = re.fullmatch(r"IF\s+(.*?)\s+THEN\s*", code[code.rfind("IF ", 0, at):at], re.S)
    return m.group(1) if m else None


def unparsed_disjuncts(code: str) -> list[str]:
    """That condition split at top-level OR (outside parentheses and '...')."""
    cond = unparsed_condition(code)
    if cond is None:
        return []
    parts, depth, buf, i = [], 0, [], 0
    while i < len(cond):
        c = cond[i]
        if c == "'":
            j = cond.index("'", i + 1)
            buf.append(cond[i:j + 1])
            i = j + 1
            continue
        depth += (c == "(") - (c == ")")
        if depth == 0 and re.match(r"\s+OR\s+", cond[i:]):
            parts.append(" ".join("".join(buf).split()))
            buf, i = [], i + re.match(r"\s+OR\s+", cond[i:]).end()
            continue
        buf.append(c)
        i += 1
    parts.append(" ".join("".join(buf).split()))
    return parts


# The query part (m[4]) of URIs the N1 rule must report as unparsed, and of
# URIs it must still parse.
QUERY_MALFORMED_PROBES = [
    ("sslmode=require password=correct SECRETQ33", "the reviewer's N1 input"),
    ("application_name=standby1 SECRETWS43", "whitespace"),
    ("application_name=a\tSECRETTAB", "a tab"),
    ("application_name=standby1=SECRETEQ38", "a second '='"),
    ("sslmode=require&application_name=a=b=SECRETEQ", "a second '=' after '&'"),
]
QUERY_WELL_FORMED_PROBES = [
    "sslmode=require&application_name=standby1",
    "application_name=sub1",
    "pass%77ord=SECRETPCT12",
    "",
]


def conninfo_problems(text: str) -> list[str]:
    """Every way parse_conninfo can return a secret. [] means guarded."""
    body = parse_conninfo_body(text)
    code = "\n".join(line.split("--", 1)[0] for line in body.splitlines())
    problems = []
    m = re.search(r"secret\s+text\[\]\s*:=\s*ARRAY\[([^\]]*)\]", code)
    if not m:
        return ["no secret key list declared"]
    declared = {s.strip().strip("'").lower() for s in m.group(1).split(",")}
    if not REQUIRED_SECRET_KEYS <= declared:
        problems.append(f"secret list misses {sorted(REQUIRED_SECRET_KEYS - declared)}")
    if not re.search(r"postgres\(ql\)\?://", code):
        problems.append("no URI-form branch")
    if "regexp_split_to_array" in code:
        problems.append("keyword form split on whitespace: quoted values break apart")
    allowed = conninfo_allowed_keys(code)
    if allowed is None:
        problems.append("no allowed key list declared")
    else:
        if allowed != EXPECTED_ALLOWED_KEYS:
            problems.append(f"allowed list is not the reviewed allowlist: extra {sorted(allowed - EXPECTED_ALLOWED_KEYS)}, "
                            f"missing {sorted(EXPECTED_ALLOWED_KEYS - allowed)}")
        if allowed & (REQUIRED_SECRET_KEYS | declared):
            problems.append(f"allowed list contains secret keys {sorted(allowed & (REQUIRED_SECRET_KEYS | declared))}")
    # The only keys emitted by name are the URI parts and the unparsed marker.
    for lit in re.finditer(r"jsonb_build_object\(\s*'([^']*)'", code):
        if lit.group(1) not in LITERAL_EMIT_KEYS:
            problems.append(f"emits literal key {lit.group(1)!r}")
    emits = [e.start() for e in re.finditer(r"jsonb_build_object\(\s*k\s*,", code)]
    if len(emits) < 2:
        problems.append(f"expected a keyed emit in both branches, found {len(emits)}")
    for at in emits:
        guard = code[code.rfind("IF ", 0, at):at]
        if not re.search(r"k\s*<>\s*ALL\s*\(\s*secret\s*\)", guard):
            problems.append(f"unguarded emit: {code[at:at + 60]!r}")
        if not re.search(r"k\s*=\s*ANY\s*\(\s*allowed\s*\)", guard):
            problems.append(f"emit not restricted to the allowlist: {code[at:at + 60]!r}")
        if re.search(r"\bOR\b", guard):
            problems.append(f"emit guard has an OR (a branch bypasses the lists): {guard!r}")
        # A non-secret key can still carry one (options='-c app.password=x'):
        # every returned value goes through mask_secrets.
        if not re.match(r"jsonb_build_object\(\s*k\s*,\s*pg_temp\.mask_secrets\(", code[at:]):
            problems.append(f"emit without mask_secrets: {code[at:at + 60]!r}")
    # From the URI userinfo only the part before ':' (the user) may be emitted.
    uri_start = code.find("://' THEN")
    uri_end = code.find("FOR m IN", uri_start)
    if uri_start == -1 or uri_end == -1:
        problems.append("cannot locate the URI branch before the keyword loop")
        uri_start = uri_end = 0
    uri = code[uri_start:uri_end]
    # libpq percent-decodes query keywords (pass%77ord is password), so the
    # URI branch's emit must drop any key containing '%'.
    uri_emit = uri.find("jsonb_build_object(k,")
    if uri_emit == -1 or not re.search(r"position\(\s*'%'\s+in\s+k\s*\)\s*=\s*0",
                                       uri[uri.rfind("IF ", 0, uri_emit):uri_emit]):
        problems.append("URI query keys containing '%' are not dropped")
    # An '@' after the userinfo (e.g. a '/' inside the password) must make the
    # whole result {unparsed: true}, checked over host, path and query. So
    # must whitespace or '=' in the user, host or dbname (a mixed string such
    # as '.../postgres password=x'). Both are disjuncts of the one IF whose
    # body returns {unparsed: true}.
    disjuncts = unparsed_disjuncts(uri)
    at_check = next((re.fullmatch(r"position\(\s*'@'\s+in\s+(.*)\)\s*>\s*0", d, re.S)
                     for d in disjuncts if re.match(r"position\(\s*'@'", d)), None)
    if not at_check:
        problems.append("no '@'-after-userinfo check returning {unparsed: true}")
    else:
        for group in ("m[2]", "m[3]", "m[4]"):
            if group not in at_check.group(1):
                problems.append(f"'@'-after-userinfo check misses {group}")
    ws_check = next((re.fullmatch(r"(.*?)\s*~\s*'\[\\s=\]'", d, re.S) for d in disjuncts
                     if re.search(r"~\s*'\[\\s=\]'$", d)), None)
    if not ws_check:
        problems.append("no whitespace/'=' check on user, host and dbname returning {unparsed: true}")
    else:
        for part, group in (("user", "m[1]"), ("host", "m[2]"), ("dbname", "m[3]")):
            if group not in ws_check.group(1):
                problems.append(f"whitespace/'=' check misses the {part} ({group})")
    # db-security-reviewer N1: a query parameter with whitespace or a second
    # '=' ('?sslmode=require password=x SECRET', '?application_name=a=SECRET')
    # is malformed. Masking it would ship the fragments around the mask, so
    # the whole result must be {unparsed: true}. The rule is read out of the
    # SQL and run on probes (ARE and Python agree on \s, [^&] and '|').
    q_check = next((re.fullmatch(r"coalesce\(m\[4\],\s*''\)\s*~\s*'((?:[^']|'')*)'", d, re.S)
                    for d in disjuncts if re.match(r"coalesce\(m\[4\]", d)), None)
    if not q_check:
        problems.append("no query whitespace/second-'=' check returning {unparsed: true}")
    else:
        q_re = q_check.group(1).replace("''", "'")
        for probe, what in QUERY_MALFORMED_PROBES:
            if not re.search(q_re, probe):
                problems.append(f"query check misses {what}: {probe!r}")
        for probe in QUERY_WELL_FORMED_PROBES:
            if re.search(q_re, probe):
                problems.append(f"query check rejects a well-formed query: {probe!r}")
    if disjuncts and unparsed_condition(uri) and re.search(r"\bAND\b", unparsed_condition(uri)):
        problems.append("unparsed condition has an AND: each check must stand alone")
    for use in re.finditer(r"m\[1\]", code[uri_start:uri_end]):
        at = uri_start + use.start()
        ctx = code[max(0, at - 12):at + len("m[1] IS NOT NULL")]
        if not ("split_part(m[1], ':', 1)" in ctx or "m[1] IS NOT NULL" in ctx):
            problems.append(f"URI userinfo used whole: {ctx!r}")
    return problems


class TestParseConninfoDropsSecrets:

    def test_secret_list_contains_password_passfile_sslpassword(self, sql):
        m = re.search(r"secret\s+text\[\]\s*:=\s*ARRAY\[([^\]]*)\]", parse_conninfo_body(sql))
        assert m
        declared = {s.strip().strip("'") for s in m.group(1).split(",")}
        assert REQUIRED_SECRET_KEYS <= declared

    def test_no_conninfo_problems(self, sql):
        assert conninfo_problems(sql) == []

    @pytest.mark.parametrize("old, new", [
        ("ARRAY['password','passfile','sslpassword']", "ARRAY['password','passfile']"),  # main's list
        ("ARRAY['password','passfile','sslpassword']", "ARRAY['password']"),
    ])
    def test_shorter_secret_list_is_rejected(self, sql, old, new):
        assert old in sql
        problems = conninfo_problems(sql.replace(old, new, 1))
        assert any("secret list misses" in p for p in problems), problems

    @pytest.mark.parametrize("guard, unguarded", [
        ("IF k = ANY (allowed) AND k <> ALL (secret) AND position('%' in k) = 0 THEN",   # URI query
         "IF k = ANY (allowed) AND position('%' in k) = 0 THEN"),
        ("IF k = ANY (allowed) AND k <> ALL (secret) THEN",                              # keyword form
         "IF true THEN"),
    ])
    def test_dropping_a_branch_guard_is_rejected(self, sql, guard, unguarded):
        body = parse_conninfo_body(sql)
        assert body.count(guard) == 1
        bad = sql.replace(guard, unguarded, 1)
        assert any("unguarded emit" in p for p in conninfo_problems(bad))

    def test_keeping_percent_encoded_query_keys_is_rejected(self, sql):
        guard = "IF k = ANY (allowed) AND k <> ALL (secret) AND position('%' in k) = 0 THEN"
        assert guard in sql
        bad = sql.replace(guard, "IF k = ANY (allowed) AND k <> ALL (secret) THEN", 1)
        assert "URI query keys containing '%' are not dropped" in conninfo_problems(bad)

    # -- allowlist: only reviewed connection keys leave parse_conninfo -------

    def test_allowed_list_is_exactly_the_reviewed_allowlist(self, sql):
        assert conninfo_allowed_keys(parse_conninfo_body(sql)) == EXPECTED_ALLOWED_KEYS
        assert not EXPECTED_ALLOWED_KEYS & REQUIRED_SECRET_KEYS
        assert "options" not in EXPECTED_ALLOWED_KEYS  # options='-c x.password=...' carries settings

    @pytest.mark.parametrize("guard, without_allowlist", [
        ("IF k = ANY (allowed) AND k <> ALL (secret) AND position('%' in k) = 0 THEN",
         "IF k <> ALL (secret) AND position('%' in k) = 0 THEN"),
        ("IF k = ANY (allowed) AND k <> ALL (secret) THEN",
         "IF k <> ALL (secret) THEN"),
        # An OR re-opens the emit to every key the other side lets through.
        ("IF k = ANY (allowed) AND k <> ALL (secret) THEN",
         "IF k = ANY (allowed) OR k <> ALL (secret) THEN"),
    ])
    def test_emitting_keys_outside_the_allowlist_is_rejected(self, sql, guard, without_allowlist):
        assert parse_conninfo_body(sql).count(guard) == 1
        problems = conninfo_problems(sql.replace(guard, without_allowlist, 1))
        assert any(p.startswith("emit not restricted to the allowlist") or p.startswith("emit guard has an OR")
                   for p in problems), problems

    @pytest.mark.parametrize("old, new, expect", [
        ("'keepalives_count','tcp_user_timeout',", "'keepalives_count','tcp_user_timeout','options',",
         "allowed list is not the reviewed allowlist: extra ['options']"),
        # (The anchor was "'replication'];" until the allowlist additions
        # made fallback_application_name the last entry.)
        ("'fallback_application_name'];", "'fallback_application_name','sslpassword'];",
         "allowed list contains secret keys ['sslpassword']"),
        ("'fallback_application_name'];", "'fallback_application_name','password'];",
         "allowed list contains secret keys ['password']"),
        # Back to the pre-addition list: a narrower list is a review decision too.
        ("'replication','ssl_min_protocol_version',", "'replication',",
         "allowed list is not the reviewed allowlist: extra [], missing ['ssl_min_protocol_version']"),
    ])
    def test_widening_the_allowlist_is_rejected(self, sql, old, new, expect):
        assert parse_conninfo_body(sql).count(old) == 1
        problems = conninfo_problems(sql.replace(old, new, 1))
        assert any(p.startswith(expect) for p in problems), problems

    def test_missing_allowlist_is_rejected(self, sql):
        body = parse_conninfo_body(sql)
        decl = re.search(r"\s*allowed text\[\] := ARRAY\[[^\]]*\];", body).group(0)
        problems = conninfo_problems(sql.replace(decl, "", 1))
        assert "no allowed key list declared" in problems, problems

    def test_emitting_a_new_literal_key_is_rejected(self, sql):
        old = "IF m[2] <> '' THEN out := out || jsonb_build_object('host', m[2]); END IF;"
        assert sql.count(old) == 1
        bad = sql.replace(old, old + "\n        out := out || jsonb_build_object('userinfo', m[1]);", 1)
        assert "emits literal key 'userinfo'" in conninfo_problems(bad)

    # -- whitespace or '=' in user/host/dbname means unparsed ----------------

    WS_CHECK = "coalesce(split_part(m[1], ':', 1), '') || coalesce(m[2], '') || coalesce(m[3], '') ~ '[\\s=]'"

    def test_whitespace_check_is_present(self, sql):
        assert self.WS_CHECK in parse_conninfo_body(sql)

    @pytest.mark.parametrize("part, group", [("user", "coalesce(split_part(m[1], ':', 1), '')"),
                                             ("host", "coalesce(m[2], '')"),
                                             ("dbname", "coalesce(m[3], '')")])
    def test_whitespace_check_missing_a_part_is_rejected(self, sql, part, group):
        assert self.WS_CHECK in sql
        new = self.WS_CHECK.replace(group + " || ", "", 1) if self.WS_CHECK.startswith(group) \
            else self.WS_CHECK.replace(" || " + group, "", 1)
        assert new != self.WS_CHECK
        problems = conninfo_problems(sql.replace(self.WS_CHECK, new, 1))
        assert any(p.startswith(f"whitespace/'=' check misses the {part}") for p in problems), problems

    def test_dropping_the_whitespace_check_is_rejected(self, sql):
        """The previous delta: only the '@' check, so '.../postgres password=x' parsed."""
        old = "\n           OR " + self.WS_CHECK
        assert sql.count(old) == 1
        problems = conninfo_problems(sql.replace(old, "", 1))
        assert "no whitespace/'=' check on user, host and dbname returning {unparsed: true}" in problems, problems

    def test_whitespace_check_without_equals_is_rejected(self, sql):
        problems = conninfo_problems(sql.replace(self.WS_CHECK, self.WS_CHECK.replace("'[\\s=]'", "'\\s'"), 1))
        assert "no whitespace/'=' check on user, host and dbname returning {unparsed: true}" in problems, problems

    def test_unparsed_checks_joined_by_and_are_rejected(self, sql):
        old = "\n           OR " + self.WS_CHECK
        problems = conninfo_problems(sql.replace(old, "\n           AND " + self.WS_CHECK, 1))
        assert "unparsed condition has an AND: each check must stand alone" in problems, problems

    def test_allowlist_additions_are_in_the_sql_and_not_secret(self, sql):
        allowed = conninfo_allowed_keys(parse_conninfo_body(sql))
        assert ADDED_ALLOWED_KEYS <= allowed
        assert len(ADDED_ALLOWED_KEYS) == 8
        assert not ADDED_ALLOWED_KEYS & conninfo_secret_keys(parse_conninfo_body(sql))
        assert not any("pass" in k or "secret" in k or "key" == k for k in ADDED_ALLOWED_KEYS)

    # -- N1: a query parameter with whitespace or a second '=' is unparsed ----

    Q_CHECK = "coalesce(m[4], '') ~ '\\s|=[^&]*='"

    def test_query_check_is_present(self, sql):
        assert parse_conninfo_body(sql).count(self.Q_CHECK) == 1
        assert self.Q_CHECK in unparsed_disjuncts(parse_conninfo_body(sql))

    def test_dropping_the_query_check_is_rejected(self, sql):
        old = "\n           OR " + self.Q_CHECK
        assert sql.count(old) == 1
        problems = conninfo_problems(sql.replace(old, "", 1))
        assert "no query whitespace/second-'=' check returning {unparsed: true}" in problems, problems

    @pytest.mark.parametrize("new_re, expect", [
        ("'=[^&]*='", "query check misses whitespace"),            # second '=' only
        ("'\\s'", "query check misses a second '='"),               # whitespace only
        ("'\\s|=[^&]*=&'", "query check misses a second '='"),     # anchored wrongly
        ("'\\s|='", "query check rejects a well-formed query"),     # every query unparsed
        ("' |=[^&]*='", "query check misses a tab"),                 # space, not \s
    ])
    def test_wrong_query_checks_are_rejected(self, sql, new_re, expect):
        old = "'\\s|=[^&]*='"
        assert parse_conninfo_body(sql).count(old) == 1
        problems = conninfo_problems(sql.replace(old, new_re, 1))
        assert any(p.startswith(expect) for p in problems), problems

    def test_query_check_joined_by_and_is_rejected(self, sql):
        old = "\n           OR " + self.Q_CHECK
        problems = conninfo_problems(sql.replace(old, "\n           AND " + self.Q_CHECK, 1))
        assert "unparsed condition has an AND: each check must stand alone" in problems, problems

    @pytest.mark.parametrize("old, new", [
        ("pg_temp.mask_secrets(substring(val from position('=' in val) + 1))",
         "substring(val from position('=' in val) + 1)"),
        ("pg_temp.mask_secrets(trim(both '''' from m[2]))", "trim(both '''' from m[2])"),
    ])
    def test_returning_an_unmasked_value_is_rejected(self, sql, old, new):
        assert old in sql
        problems = conninfo_problems(sql.replace(old, new, 1))
        assert any("emit without mask_secrets" in p for p in problems), problems

    @pytest.mark.parametrize("group", ["m[2]", "m[3]", "m[4]"])
    def test_at_check_missing_a_group_is_rejected(self, sql, group):
        old = "coalesce(m[2], '') || coalesce(m[3], '') || coalesce(m[4], '')"
        assert old in sql
        new = " || ".join(p for p in old.split(" || ") if group not in p)
        problems = conninfo_problems(sql.replace(old, new, 1))
        assert f"'@'-after-userinfo check misses {group}" in problems, problems

    def test_dropping_the_at_check_is_rejected(self, sql):
        old = "RETURN jsonb_build_object('unparsed', true);"
        assert sql.count(old) == 1
        problems = conninfo_problems(sql.replace(old, "NULL;", 1))
        assert "no '@'-after-userinfo check returning {unparsed: true}" in problems, problems

    def test_main_parse_conninfo_is_rejected(self, sql):
        bad = sql.replace(parse_conninfo_body(sql), MAIN_PARSE_CONNINFO, 1)
        assert bad != sql
        assert conninfo_problems(bad) == ["no secret key list declared"]

    def test_emitting_the_whole_userinfo_is_rejected(self, sql):
        old = "jsonb_build_object('user', split_part(m[1], ':', 1))"
        assert old in sql
        bad = sql.replace(old, "jsonb_build_object('user', m[1])", 1)
        assert any("URI userinfo used whole" in p for p in conninfo_problems(bad))

    def test_whitespace_split_parser_is_rejected(self, sql):
        body = parse_conninfo_body(sql)
        bad = sql.replace(body, body.replace("regexp_matches(v,", "regexp_split_to_array(v,", 1), 1)
        assert bad != sql
        assert any("split on whitespace" in p for p in conninfo_problems(bad))


# ---------------------------------------------------------------------------
# sanitise_setting: the raw text of a secret-bearing setting never ships.
# Masking free text missed real credential formats (a space inside a URI
# password, a mixed URI + keyword string, a cloud key in archive_command), so
# for a secret-bearing name only "is it set, and how long" leaves the server:
#   NULL -> NULL; '' and '(disabled)' unchanged;
#   anything else -> '***REDACTED*** (set, N characters)'.
#
# Which names are secret-bearing is decided by pg_temp.is_secret_setting:
#   * the seven names below, compared case-insensitively, as current_setting()
#     does: a manifest check with setting_name 'PRIMARY_CONNINFO' reads the
#     same secret;
#   * every dotted (custom or extension) name, such as pgrst.jwt_secret or
#     app.jwt_secret, unless it is (case-insensitively) one of an exact list
#     of reviewed pgaudit, set_user, pg_stat_statements and plpgsql settings
#     whose values CIS checks need (db-security-reviewer B1: these values
#     used to ship raw in settings, file_settings and role_settings). Exact
#     names, not prefixes: with a prefix rule a planted pgaudit.jwt_secret
#     shipped raw (test-writer's live probe of the previous delta).
# The same predicate drives the settings rows' 'sanitised' flag, and every
# route a setting value takes (settings, file_settings, role_settings,
# manifest checks) goes through sanitise_setting.
#
# Both functions are read out of collect.sql and evaluated by small models
# that accept only the shapes below (anything else is reported, never
# guessed). The live proof is tests/test_collector_hardening_live.py (rows,
# file_settings, role_settings and manifest checks on a real PG17).
# ---------------------------------------------------------------------------

SANITISED_NAMES = {"archive_command", "restore_command", "archive_cleanup_command",
                   "recovery_end_command", "primary_conninfo", "ssl_passphrase_command",
                   "krb_server_keyfile"}
# Extension settings that stay readable. Pinned exactly: widening it is a
# review decision, not a refactor. (auto_explain is no longer exempt.)
REVIEWED_SETTINGS = {
    "pgaudit.log", "pgaudit.log_catalog", "pgaudit.log_client", "pgaudit.log_level", "pgaudit.log_parameter",
    "pgaudit.log_parameter_max_size", "pgaudit.log_relation", "pgaudit.log_rows", "pgaudit.log_statement",
    "pgaudit.log_statement_once", "pgaudit.role",
    "set_user.block_alter_system", "set_user.block_copy_program", "set_user.block_log_statement",
    "set_user.exit_on_error", "set_user.nosuperuser_target_allowlist", "set_user.superuser_allowlist",
    "set_user.superuser_audit_tag",
    "pg_stat_statements.max", "pg_stat_statements.track", "pg_stat_statements.track_utility",
    "pg_stat_statements.track_planning", "pg_stat_statements.save",
    "plpgsql.variable_conflict", "plpgsql.print_strict_params", "plpgsql.check_asserts",
    "plpgsql.extra_warnings", "plpgsql.extra_errors",
}
REVIEWED_EXTENSIONS = {"pgaudit", "set_user", "pg_stat_statements", "plpgsql"}
# A reviewed name never looks like it holds a credential.
SECRET_LOOKING = re.compile(r"secret|key|pass|token|jwt|cred|auth|cert|salt|dsn|conn", re.I)
# The previous delta's dotted rule (prefixes), verbatim; swapped in, it must be rejected.
PREFIX_DOTTED_RULE = ("OR (position('.' in $1) > 0 AND split_part(lower($1), '.', 1) NOT IN "
                      "('pgaudit','set_user','pg_stat_statements','auto_explain','plpgsql'))")
SANITISE_MARKER_PREFIX = "***REDACTED*** (set, "
SANITISE_MARKER_SUFFIX = " characters)"


def redaction_marker(value: str) -> str:
    return f"{SANITISE_MARKER_PREFIX}{len(value)}{SANITISE_MARKER_SUFFIX}"


AWS_ARCHIVE_COMMAND = "AWS_SECRET_ACCESS_KEY=SECRETAWS20 aws s3 cp %p s3://b/%f"
URI_WS_PASSWORD = "postgresql://rep:correct SECRETWS16 horse@primary/postgres"
URI_QUERY_WS_PASSWORD = "postgresql://h/db?password=my SECRETWS17"
URI_MIXED_FORM = "postgresql://rep@primary/postgres password=SECRETMIX18"
URI_QUERY_FRAGMENT = "postgresql://rep@primary/postgres?sslmode=require password=correct SECRETQ33"
# Every key added to the allowlist after the third review, in keyword form.
ALLOWLIST_ADDITIONS_CONNINFO = (
    "host=primary user=rep password=SECRETNEW42 ssl_min_protocol_version=TLSv1.2 "
    "ssl_max_protocol_version=TLSv1.3 require_auth=scram-sha-256 sslcertmode=allow "
    "sslnegotiation=postgres sslcompression=0 gssdelegation=0 fallback_application_name=fb1")
ALLOWLIST_ADDITIONS_PARSED = {
    "host": "primary", "user": "rep", "ssl_min_protocol_version": "TLSv1.2",
    "ssl_max_protocol_version": "TLSv1.3", "require_auth": "scram-sha-256", "sslcertmode": "allow",
    "sslnegotiation": "postgres", "sslcompression": "0", "gssdelegation": "0",
    "fallback_application_name": "fb1"}

# (id, name, value, exact result, secret that must not survive)
SANITISE_CASES = [
    # The format, pinned by literal rather than by redaction_marker().
    ("marker-literal", "archive_command", "cp %p /x/%f", "***REDACTED*** (set, 11 characters)", None),
    ("aws-key-in-archive-command", "archive_command", AWS_ARCHIVE_COMMAND,
     "***REDACTED*** (set, 56 characters)", "SECRETAWS20"),
    ("uri-password-with-whitespace", "primary_conninfo", URI_WS_PASSWORD,
     redaction_marker(URI_WS_PASSWORD), "SECRETWS16"),
    ("uri-query-password-with-space", "primary_conninfo", URI_QUERY_WS_PASSWORD,
     redaction_marker(URI_QUERY_WS_PASSWORD), "SECRETWS17"),
    ("uri-mixed-with-keyword-password", "primary_conninfo", URI_MIXED_FORM,
     redaction_marker(URI_MIXED_FORM), "SECRETMIX18"),
    # Names compare case-insensitively.
    ("upper-case-name", "PRIMARY_CONNINFO", "host=x password=SECRETUPPER21 user=rep",
     redaction_marker("host=x password=SECRETUPPER21 user=rep"), "SECRETUPPER21"),
    ("mixed-case-name", "Archive_Command", "cp %p rclone://u:SECRETMIXCASE22@b/%f",
     redaction_marker("cp %p rclone://u:SECRETMIXCASE22@b/%f"), "SECRETMIXCASE22"),
    # Every other name in the set.
    ("restore-command", "restore_command", "aws s3 cp s3://b/%f %p --sse-c-key SECRETRC23",
     redaction_marker("aws s3 cp s3://b/%f %p --sse-c-key SECRETRC23"), "SECRETRC23"),
    ("archive-cleanup-command", "archive_cleanup_command", "pg_archivecleanup -x token=SECRETAC24 /a %r",
     redaction_marker("pg_archivecleanup -x token=SECRETAC24 /a %r"), "SECRETAC24"),
    ("recovery-end-command", "recovery_end_command", "notify --key SECRETRE25",
     redaction_marker("notify --key SECRETRE25"), "SECRETRE25"),
    ("ssl-passphrase-command", "ssl_passphrase_command", "echo SECRETPP26",
     redaction_marker("echo SECRETPP26"), "SECRETPP26"),
    ("krb-server-keyfile", "krb_server_keyfile", "/etc/SECRETKRB27.keytab",
     redaction_marker("/etc/SECRETKRB27.keytab"), "SECRETKRB27"),
    # Even a harmless value is not shipped: the text is never judged.
    ("harmless-value-still-redacted", "archive_command", "pgbackrest --stanza=main archive-push %p",
     redaction_marker("pgbackrest --stanza=main archive-push %p"), "pgbackrest"),
    # Not set / disabled stay readable: the assessment needs to know that.
    ("disabled", "archive_command", "(disabled)", "(disabled)", None),
    ("empty", "primary_conninfo", "", "", None),
    ("null", "primary_conninfo", None, None, None),
    # Other settings are not touched.
    ("other-setting", "log_connections", "on", "on", None),
    ("other-setting-upper", "LOG_CONNECTIONS", "on", "on", None),
    ("search-path-visible", "search_path", "evil, public", "evil, public", None),
    # db-security-reviewer B1: custom and extension (dotted) settings. These
    # are the main session's live smoke values, plus the edges of the rule.
    ("dotted-pgrst-jwt-secret", "pgrst.jwt_secret", "SECRETJWT30",
     "***REDACTED*** (set, 11 characters)", "SECRETJWT30"),
    ("dotted-app-jwt-secret", "app.jwt_secret", "SECRETAPPDB31",
     "***REDACTED*** (set, 13 characters)", "SECRETAPPDB31"),
    ("dotted-system-key", "app.jwt_key", "SECRETCONF32", redaction_marker("SECRETCONF32"), "SECRETCONF32"),
    ("dotted-upper-case", "APP.Token", "SECRETUPC35", redaction_marker("SECRETUPC35"), "SECRETUPC35"),
    # A prefix that merely starts with, or ends in, a reviewed one is not reviewed.
    ("dotted-prefix-extends-reviewed", "pgaudit_x.key", "SECRETPFX36", redaction_marker("SECRETPFX36"),
     "SECRETPFX36"),
    ("dotted-prefix-starts-with-reviewed", "pgauditx.key", "SECRETPFX44", redaction_marker("SECRETPFX44"),
     "SECRETPFX44"),
    ("dotted-prefix-ends-in-reviewed", "x_plpgsql.key", "SECRETPFX46", redaction_marker("SECRETPFX46"),
     "SECRETPFX46"),
    # Only the text before the FIRST '.' is the prefix.
    ("dotted-reviewed-name-second", "app.pgaudit", "SECRETSEC45", redaction_marker("SECRETSEC45"),
     "SECRETSEC45"),
    # An unreviewed extension's setting is redacted even when harmless.
    ("dotted-unreviewed-extension", "pg_trgm.similarity_threshold", "0.437", redaction_marker("0.437"), "0.437"),
    ("dotted-empty", "app.jwt_secret", "", "", None),
    ("dotted-null", "app.jwt_secret", None, None, None),
    # Reviewed prefixes stay readable, whatever the case.
    ("reviewed-pgaudit", "pgaudit.log", "ddl", "ddl", None),
    ("reviewed-pgaudit-upper", "PGAUDIT.LOG", "read", "read", None),
    ("reviewed-set-user", "set_user.block_log_statement", "on", "on", None),
    ("reviewed-pg-stat-statements", "pg_stat_statements.track", "all", "all", None),
    ("reviewed-plpgsql", "plpgsql.variable_conflict", "use_column", "use_column", None),
    ("reviewed-plpgsql-extra-errors", "plpgsql.extra_errors", "all", "all", None),
    ("reviewed-pgaudit-role", "pgaudit.role", "auditor", "auditor", None),
    # (Was "reviewed-auto-explain": visible. auto_explain is no longer exempt.)
    ("auto-explain-not-reviewed", "auto_explain.log_min_duration", "250", redaction_marker("250"), "250"),
    # Exact names, not prefixes: an unreviewed name under a reviewed prefix
    # is redacted. With the prefix rule these shipped raw.
    ("reviewed-prefix-unreviewed-name", "pgaudit.jwt_secret", "SECRETRESID40",
     "***REDACTED*** (set, 13 characters)", "SECRETRESID40"),
    ("plpgsql-unreviewed-name", "plpgsql.jwt_key", "SECRETPLK48", redaction_marker("SECRETPLK48"), "SECRETPLK48"),
    ("set-user-unreviewed-name", "set_user.api_token", "SECRETSU49", redaction_marker("SECRETSU49"), "SECRETSU49"),
    ("pg-stat-statements-unreviewed-name", "PG_STAT_STATEMENTS.Secret", "SECRETPSS51",
     redaction_marker("SECRETPSS51"), "SECRETPSS51"),
    # A reviewed name plus a suffix, or cut short, is not the reviewed name.
    ("reviewed-name-with-suffix", "pgaudit.log_key", "SECRETSFX52", redaction_marker("SECRETSFX52"), "SECRETSFX52"),
    ("reviewed-name-prefix-only", "pgaudit.lo", "SECRETSHORT53", redaction_marker("SECRETSHORT53"), "SECRETSHORT53"),
    # db-security-reviewer N1: look-alikes that the database collation's
    # lower() folds onto a reviewed name (U+212A KELVIN SIGN -> 'k', U+0130
    # LATIN CAPITAL LETTER I WITH DOT ABOVE -> 'i'). lower(... COLLATE "C")
    # folds ASCII only, so they stay unreviewed.
    ("lookalike-kelvin", "set_user.blocK_copy_program", "SECRETKEL62", redaction_marker("SECRETKEL62"),
     "SECRETKEL62"),
    ("lookalike-dotted-capital-i", "pgaudİt.log", "SECRETDOT63", redaction_marker("SECRETDOT63"), "SECRETDOT63"),
    # db-security-reviewer B2: a plain (undotted) name the server does not
    # know, e.g. a line appended to postgresql.conf, or a typo.
    ("unknown-plain-name", "jwt_secret", "SECRETUNK60", "***REDACTED*** (set, 11 characters)", "SECRETUNK60"),
    ("unknown-plain-upper", "JWT_SECRET", "SECRETUNK65", redaction_marker("SECRETUNK65"), "SECRETUNK65"),
    ("typo-restore-comand", "restore_comand", "aws s3 cp --sse-c-key SECRETTYPO61 %f %p",
     redaction_marker("aws s3 cp --sse-c-key SECRETTYPO61 %f %p"), "SECRETTYPO61"),
    # Known plain names stay visible, whatever the case.
    ("known-log-statement", "log_statement", "ddl", "ddl", None),
    ("known-upper", "LOG_STATEMENT", "ddl", "ddl", None),
    # pg_settings spells these in mixed case; postgresql.conf (and so
    # pg_file_settings) usually in lower case. Both are known settings.
    ("known-mixed-case-datestyle", "DateStyle", "ISO, MDY", "ISO, MDY", None),
    ("known-file-name-timezone", "timezone", "Etc/UTC", "Etc/UTC", None),
    # db-security-reviewer N2: a NULL name fails closed.
    ("null-name", None, "SECRETNULL64", redaction_marker("SECRETNULL64"), "SECRETNULL64"),
]
LOOKALIKE_CASES = {"lookalike-kelvin", "lookalike-dotted-capital-i"}
UNKNOWN_NAME_CASES = {"unknown-plain-name", "unknown-plain-upper", "typo-restore-comand"}
# Plain names the model's pg_settings knows, spelled as pg_settings reports
# them (DateStyle and TimeZone are mixed case there).
PG_SETTINGS_NAMES = SANITISED_NAMES | {"log_connections", "log_statement", "search_path",
                                       "standard_conforming_strings", "ssl_ciphers", "DateStyle", "TimeZone"}
DOTTED_SECRET_CASES = {"dotted-pgrst-jwt-secret", "dotted-app-jwt-secret", "dotted-system-key",
                       "dotted-upper-case", "dotted-prefix-extends-reviewed", "dotted-prefix-starts-with-reviewed",
                       "dotted-prefix-ends-in-reviewed", "dotted-reviewed-name-second",
                       "dotted-unreviewed-extension", "auto-explain-not-reviewed",
                       "reviewed-prefix-unreviewed-name", "plpgsql-unreviewed-name", "set-user-unreviewed-name",
                       "pg-stat-statements-unreviewed-name", "reviewed-name-with-suffix", "reviewed-name-prefix-only",
                       "lookalike-kelvin", "lookalike-dotted-capital-i"}
# The dotted secrets the previous delta's prefix rule let through.
PREFIX_RULE_LEAKS = {"auto-explain-not-reviewed", "reviewed-prefix-unreviewed-name", "plpgsql-unreviewed-name",
                     "set-user-unreviewed-name", "pg-stat-statements-unreviewed-name", "reviewed-name-with-suffix",
                     "reviewed-name-prefix-only", "lookalike-kelvin", "lookalike-dotted-capital-i"}

# origin/main's (and 03a618c's: identical) sanitise_setting, verbatim.
MAIN_SANITISE_SETTING = r"""CREATE FUNCTION pg_temp.sanitise_setting(p_name text, p_value text)
RETURNS text AS $$
    SELECT CASE
        WHEN $1 IN ('archive_command','restore_command','archive_cleanup_command',
                    'recovery_end_command','primary_conninfo',
                    'ssl_passphrase_command','krb_server_keyfile')
        THEN pg_temp.mask_secrets($2)
        ELSE $2
    END;
"""
# The previous delta's condition (before is_secret_setting): the seven names
# only, case-insensitive. Dotted names went through unredacted.
SEVEN_NAMES_CONDITION = ("WHEN lower($1) IN ('archive_command','restore_command','archive_cleanup_command',"
                         "'recovery_end_command','primary_conninfo','ssl_passphrase_command','krb_server_keyfile')")
# origin/main's (and 03a618c's) 'sanitised' flag, whitespace-collapsed.
MAIN_SANITISED_FLAG = ("'sanitised', s.name IN ('archive_command','restore_command', "
                       "'archive_cleanup_command','recovery_end_command', "
                       "'primary_conninfo','ssl_passphrase_command', 'krb_server_keyfile')")
SANITISED_FLAG = "'sanitised', pg_temp.is_secret_setting(s.name)"

# Every route by which a setting's value reaches the bundle.
SANITISED_ROUTES = {
    "settings.setting": "'setting', pg_temp.sanitise_setting(s.name, s.setting)",
    # db-security-reviewer N4: boot_val (krb_server_keyfile's is a path).
    "settings.boot_val": "'boot_val', pg_temp.sanitise_setting(s.name, s.boot_val)",
    "settings.reset_val": "'reset_val', pg_temp.sanitise_setting(s.name, s.reset_val)",
    "file_settings.setting": "'setting', pg_temp.sanitise_setting(name, setting)",
    "run_checks.result": "v_result := pg_temp.sanitise_setting(v_name, current_setting(v_name))",
}
# role_settings: each "name=value" entry of pg_db_role_setting.setconfig is
# rebuilt, in order, as name || '=' || sanitise_setting(name, value), where
# name is the text before the first '=' and value everything after it. On
# main (= 03a618c) the array shipped raw: 'settings', s.setconfig.
ROLE_SETTINGS_ROUTE = (
    "'settings', (SELECT jsonb_agg( split_part(c, '=', 1) || '=' || "
    "pg_temp.sanitise_setting(split_part(c, '=', 1), substring(c from position('=' in c) + 1)) "
    "ORDER BY ord) FROM unnest(s.setconfig) WITH ORDINALITY AS u(c, ord))")
MAIN_ROLE_SETTINGS_ROUTE = "'settings', s.setconfig"


def function_body(text: str, name: str) -> str:
    start = text.index(f"CREATE FUNCTION pg_temp.{name}(")
    end = text.index("$$ LANGUAGE", start)
    return text[start:end]


def sanitise_setting_body(text: str) -> str:
    return function_body(text, "sanitise_setting")


def is_secret_setting_body(text: str) -> str:
    return function_body(text, "is_secret_setting")


def flat_code(code: str) -> str:
    """`code` without `--` comments, whitespace collapsed."""
    return " ".join(strip_line_comments(code).split())


def ws_replace(text: str, old: str, new: str) -> tuple[str, int]:
    """Replace `old` once in `text`, whatever the whitespace between its words."""
    pattern = r"\s+".join(re.escape(w) for w in old.split())
    return re.subn(pattern, lambda _: new, text, count=1)


LOWER_C = 'lower($1 COLLATE "C")'
FOLD = r'lower\(\$1 COLLATE "C"\)|lower\(\$1\)|upper\(\$1\)|\$1'
SECRET_PREDICATE_SHAPE = re.compile(
    rf"SELECT (?P<subject>{FOLD}) IN \((?P<names>[^)]*)\)"
    r"(?P<dotted> OR \(position\('\.' in \$1\) > 0 AND "
    rf"(?:split_part\((?P<psubject>{FOLD}), '\.', (?P<field>\d+)\)"
    rf"|(?P<esubject>{FOLD})) "
    r"(?P<neg>NOT )?IN \( ?(?P<prefixes>[^)]*)\)\))?"
    r"(?P<unknown> OR \((?:position\('\.' in \$1\) (?P<uop>=|>) 0 AND )?"
    r"NOT EXISTS \(SELECT 1 FROM pg_catalog\.pg_settings p WHERE "
    rf"(?P<pname>p\.name|lower\(p\.name COLLATE \"C\"\)|lower\(p\.name\)) = (?P<usubject>{FOLD})\)\))?;?")
SANITISE_SHAPE = re.compile(
    r"SELECT CASE WHEN (?:(?P<pred>coalesce\(pg_temp\.is_secret_setting\(\$1\), (?P<nulldefault>true|false)\)"
    r"|pg_temp\.is_secret_setting\(\$1\))"
    rf"|(?P<subject>{FOLD}) IN \((?P<names>[^)]*)\)) "
    r"THEN (?P<then>.*) ELSE \$2 END;?")
REDACT_SHAPE = re.compile(
    r"CASE WHEN \$2 IS NULL THEN NULL WHEN \$2 IN \((?P<keep>'[^']*'(?:, *'[^']*')*)\) THEN \$2 "
    r"ELSE '(?P<prefix>[^']*)' \|\| length\((?P<arg>\$[12])\) \|\| '(?P<suffix>[^']*)' END")
CASE_FOLD = {
    # The C collation folds ASCII letters only.
    LOWER_C: lambda x: "".join(c.lower() if "A" <= c <= "Z" else c for c in x),
    # The database collation (en_US.utf8 here, libc): full Unicode folding,
    # U+212A -> 'k' and U+0130 -> 'i' as glibc's towlower does.
    "lower($1)": lambda x: x.replace("İ", "i").lower(),
    "upper($1)": str.upper,
    "$1": lambda x: x,
}


def function_volatility(text: str, name: str) -> str | None:
    start = text.index(f"CREATE FUNCTION pg_temp.{name}(")
    m = re.compile(r"\$\$ LANGUAGE \w+\s*(IMMUTABLE|STABLE|VOLATILE)?\s*;").search(text, start)
    return m.group(1) if m else None


def is_secret_model(text: str, name: str | None) -> bool | None:
    """is_secret_setting(name) as collect.sql defines it, against a pg_settings
    holding PG_SETTINGS_NAMES (None for a NULL name, as SQL gives). Raises
    ValueError on any shape the model does not know."""
    body = flat_code(is_secret_setting_body(text))
    body = body[body.index("$$") + 2:].strip()
    shape = SECRET_PREDICATE_SHAPE.fullmatch(body)
    if not shape:
        raise ValueError(f"unrecognised is_secret_setting body: {body[:160]!r}")
    if name is None:
        return None
    if CASE_FOLD[shape["subject"]](name) in sql_literals(shape["names"]):
        return True
    if shape["unknown"] is not None:
        applies = {"=": "." not in name, ">": "." in name, None: True}[shape["uop"]]
        pfold = {"p.name": CASE_FOLD["$1"], 'lower(p.name COLLATE "C")': CASE_FOLD[LOWER_C],
                 "lower(p.name)": CASE_FOLD["lower($1)"]}[shape["pname"]]
        if applies and CASE_FOLD[shape["usubject"]](name) not in {pfold(n) for n in PG_SETTINGS_NAMES}:
            return True
    if shape["dotted"] is None or "." not in name:
        return False
    if shape["field"] is None:
        # Exact-name rule: the whole (case-folded) name against the list.
        in_list = CASE_FOLD[shape["esubject"]](name) in sql_literals(shape["prefixes"])
    else:
        # Prefix rule. split_part(x, '.', n): the n-th '.'-separated field,
        # '' past the end.
        fields = CASE_FOLD[shape["psubject"]](name).split(".")
        n = int(shape["field"])
        field = fields[n - 1] if 1 <= n <= len(fields) else ""
        in_list = field in sql_literals(shape["prefixes"])
    return not in_list if shape["neg"] else in_list


def sanitise_model(text: str, name: str, value: str | None) -> str | None:
    """sanitise_setting(name, value) as collect.sql defines it. Raises
    ValueError on any shape the model does not know."""
    body = flat_code(sanitise_setting_body(text))
    body = body[body.index("$$") + 2:].strip()
    shape = SANITISE_SHAPE.fullmatch(body)
    if not shape:
        raise ValueError(f"unrecognised sanitise_setting body: {body[:120]!r}")
    if shape["pred"]:
        secret = is_secret_model(text, name)
        if secret is None:
            # CASE WHEN NULL takes the ELSE branch; coalesce decides first.
            secret = shape["nulldefault"] == "true"
    else:
        secret = name is not None and CASE_FOLD[shape["subject"]](name) in sql_literals(shape["names"])
    if not secret:
        return value
    then = shape["then"]
    if then == "pg_temp.mask_secrets($2)":
        return None if value is None else mask_model(text, value)
    redact = REDACT_SHAPE.fullmatch(then)
    if not redact:
        raise ValueError(f"unrecognised THEN branch: {then[:120]!r}")
    if value is None:
        return None
    if value in sql_literals(redact["keep"]):
        return value
    measured = value if redact["arg"] == "$2" else name
    if measured is None:
        return None  # length(NULL) makes the whole concatenation NULL
    return f"{redact['prefix']}{len(measured)}{redact['suffix']}"


def role_settings_model(text: str, setconfig: list[str]) -> list[str]:
    """role_settings' settings for one pg_db_role_setting row, given the
    pinned ROLE_SETTINGS_ROUTE (role_settings_problems checks the pin)."""
    out = []
    for entry in setconfig:
        name, value = entry.split("=", 1)[0], entry[entry.find("=") + 1:]
        out.append(f"{name}={sanitise_model(text, name, value)}")
    return out


def is_secret_problems(text: str) -> list[str]:
    """Every way is_secret_setting misclassifies a name. [] means right."""
    problems = []
    body = flat_code(is_secret_setting_body(text))
    shape = SECRET_PREDICATE_SHAPE.fullmatch(body[body.index("$$") + 2:].strip())
    if not shape:
        return ["is_secret_setting has an unrecognised shape"]
    names = set(sql_literals(shape["names"]))
    if names != SANITISED_NAMES:
        problems.append(f"sanitised names differ: missing {sorted(SANITISED_NAMES - names)}, "
                        f"extra {sorted(names - SANITISED_NAMES)}")
    if shape["subject"] in ("$1", "upper($1)"):
        problems.append(f"names compared as {shape['subject']}, not lower($1): case-sensitive")
    # N1: every lower() in the predicate folds under the C collation.
    lowers = re.findall(r"lower\(([^)]*)\)", body)
    if not lowers or any(not x.endswith(' COLLATE "C"') for x in lowers):
        problems.append('a lower() in is_secret_setting lacks COLLATE "C": look-alikes fold onto reviewed names')
    # B2: plain names the server does not know.
    if shape["unknown"] is None:
        problems.append("is_secret_setting has no rule for plain names the server does not know")
    else:
        if shape["uop"] != "=":
            problems.append("unknown-name rule is not limited to plain (undotted) names: "
                            "reviewed placeholders would be redacted")
        if shape["usubject"] != LOWER_C:
            problems.append('unknown-name rule does not compare p.name = lower($1 COLLATE "C")')
        if shape["pname"] == "p.name":
            # pg_settings spells some names in mixed case (DateStyle,
            # IntervalStyle, TimeZone); compared with a lower-cased argument
            # they are never found, so they are redacted and flagged.
            problems.append("unknown-name rule compares p.name case-sensitively: "
                            "DateStyle and TimeZone are treated as unknown")
    if function_volatility(text, "is_secret_setting") != "STABLE":
        problems.append("is_secret_setting reads pg_settings: it must be STABLE")
    if shape["dotted"] is None:
        problems.append("is_secret_setting has no rule for dotted (custom and extension) names")
    else:
        listed = set(sql_literals(shape["prefixes"]))
        if shape["field"] is not None:
            problems.append("dotted rule matches prefixes, not exact reviewed names")
        else:
            if listed != REVIEWED_SETTINGS:
                problems.append(f"reviewed setting list differs: extra {sorted(listed - REVIEWED_SETTINGS)}, "
                                f"missing {sorted(REVIEWED_SETTINGS - listed)}")
            looking = sorted(n for n in listed if SECRET_LOOKING.search(n))
            if looking:
                problems.append(f"reviewed setting list contains secret-looking names {looking}")
            if (shape["esubject"], shape["neg"]) != (LOWER_C, "NOT "):
                problems.append('dotted rule is not: lower($1 COLLATE "C") NOT IN (reviewed settings)')
    return problems


def sanitise_problems(text: str) -> list[str]:
    """Every way a secret-bearing setting's text can reach the bundle. [] means right."""
    problems = []
    body = strip_line_comments(sanitise_setting_body(text))
    if "mask_secrets" in body:
        problems.append("sanitise_setting calls mask_secrets: raw text, partly masked, would ship")
    shape = SANITISE_SHAPE.search(" ".join(body.split()))
    if not shape:
        problems.append("sanitise_setting has an unrecognised shape")
    elif shape["pred"]:
        if shape["nulldefault"] != "true":
            problems.append("sanitise_setting does not fail closed on a NULL name: "
                            "want coalesce(pg_temp.is_secret_setting($1), true)")
        problems += is_secret_problems(text)
    else:
        problems.append("sanitise_setting does not call pg_temp.is_secret_setting($1): "
                        "custom and extension settings ship raw")
        names = set(sql_literals(shape["names"]))
        if names != SANITISED_NAMES:
            problems.append(f"sanitised names differ: missing {sorted(SANITISED_NAMES - names)}, "
                            f"extra {sorted(names - SANITISED_NAMES)}")
        if shape["subject"] != "lower($1)":
            problems.append(f"names compared as {shape['subject']}, not lower($1): case-sensitive")
    if function_volatility(text, "sanitise_setting") != "STABLE":
        problems.append("sanitise_setting calls a STABLE function: it must be STABLE")
    flat = flat_code(text)
    if flat.count(SANITISED_FLAG) != 1:
        problems.append("settings 'sanitised' flag is not pg_temp.is_secret_setting(s.name)")
    for where, route in SANITISED_ROUTES.items():
        if route not in flat:
            problems.append(f"{where} does not go through sanitise_setting")
    if flat.count(ROLE_SETTINGS_ROUTE) != 1 or len(re.findall(r"\bsetconfig\b", flat)) != 1:
        problems.append("role_settings.settings does not go through sanitise_setting entry by entry")
    for case_id, name, value, want, secret in SANITISE_CASES:
        try:
            got = sanitise_model(text, name, value)
        except ValueError as exc:
            problems.append(f"{case_id}: {exc}")
            continue
        if secret is not None and got is not None and secret.lower() in got.lower():
            problems.append(f"{case_id}: secret survives: {got!r}")
        elif got != want:
            problems.append(f"{case_id}: got {got!r}, want {want!r}")
    return problems


# (id, setconfig as pg_db_role_setting stores it, exact role_settings entries)
ROLE_SETTINGS_CASES = [
    # The main session's live smoke: the secret is redacted, the hostile
    # search_path stays visible as evidence, order is kept.
    ("pgrst-authenticator", ["search_path=evil, public", "pgrst.jwt_secret=SECRETJWT30"],
     ["search_path=evil, public", "pgrst.jwt_secret=***REDACTED*** (set, 11 characters)"]),
    ("database-app-secret", ["app.jwt_secret=SECRETAPPDB31"],
     ["app.jwt_secret=***REDACTED*** (set, 13 characters)"]),
    # Only the first '=' splits name from value; the length is the whole value's.
    ("value-with-equals", ["app.dsn=host=x password=SECRETDSN47", "log_statement=all"],
     [f"app.dsn={redaction_marker('host=x password=SECRETDSN47')}", "log_statement=all"]),
    ("reviewed-prefixes-visible", ["pgaudit.log=read", "plpgsql.variable_conflict=use_column",
                                   "pgaudit_x.key=SECRETPFX36"],
     ["pgaudit.log=read", "plpgsql.variable_conflict=use_column",
      f"pgaudit_x.key={redaction_marker('SECRETPFX36')}"]),
    ("standard-setting-untouched", ["standard_conforming_strings=off"], ["standard_conforming_strings=off"]),
]


class TestSanitiseSettingNeverShipsText:

    def test_marker_helper_matches_the_literal(self):
        assert redaction_marker("cp %p /x/%f") == "***REDACTED*** (set, 11 characters)"
        assert len(AWS_ARCHIVE_COMMAND) == 56

    def test_no_sanitise_problems(self, sql):
        assert sanitise_problems(sql) == []

    @pytest.mark.parametrize("case_id, name, value, want, secret", SANITISE_CASES,
                             ids=[c[0] for c in SANITISE_CASES])
    def test_sanitise_model_output(self, sql, case_id, name, value, want, secret):
        got = sanitise_model(sql, name, value)
        assert got == want
        if secret is not None:
            assert secret in value
            assert secret.lower() not in got.lower()

    def test_never_calls_mask_secrets(self, sql):
        body = strip_line_comments(sanitise_setting_body(sql))
        assert "mask_secrets" not in body
        assert "'***REDACTED*** (set, ' || length($2) || ' characters)'" in body

    def test_names_compare_case_insensitively(self, sql):
        # (Was: "WHEN lower($1) IN (" in sanitise_setting. The list moved into
        # is_secret_setting, which sanitise_setting now calls, fail-closed,
        # and the fold is now in the C collation.)
        assert "WHEN coalesce(pg_temp.is_secret_setting($1), true)" in flat_code(sanitise_setting_body(sql))
        assert 'SELECT lower($1 COLLATE "C") IN (' in flat_code(is_secret_setting_body(sql))
        for name in SANITISED_NAMES:
            assert name == name.lower()
            for variant in (name.upper(), name.title()):
                assert sanitise_model(sql, variant, "x SECRETCASE y") == redaction_marker("x SECRETCASE y")

    def test_every_route_goes_through_sanitise_setting(self, sql):
        flat = " ".join(sql.split())
        for where, route in SANITISED_ROUTES.items():
            assert flat.count(route) == 1, where

    def test_main_sanitise_setting_is_rejected(self, sql):
        """main's (= 03a618c's) mask-based sanitise_setting, swapped in verbatim."""
        bad = sql.replace(sanitise_setting_body(sql), MAIN_SANITISE_SETTING, 1)
        assert bad != sql
        problems = sanitise_problems(bad)
        assert "sanitise_setting calls mask_secrets: raw text, partly masked, would ship" in problems
        assert "names compared as $1, not lower($1): case-sensitive" in problems
        leaked = {p.split(":", 1)[0] for p in problems if "secret survives" in p}
        assert {"aws-key-in-archive-command", "uri-password-with-whitespace", "uri-query-password-with-space",
                "upper-case-name", "restore-command", "recovery-end-command", "ssl-passphrase-command",
                "krb-server-keyfile", "harmless-value-still-redacted"} <= leaked, problems
        # mask_secrets does catch "password=" in the mixed form, but the masked
        # text (URI structure included) still ships instead of the marker.
        assert any(p.startswith("uri-mixed-with-keyword-password: got 'postgresql://rep@primary/postgres password=")
                   for p in problems), problems
        # B1: every dotted secret shipped raw.
        assert "sanitise_setting does not call pg_temp.is_secret_setting($1): " \
               "custom and extension settings ship raw" in problems
        assert DOTTED_SECRET_CASES <= leaked, problems

    def test_seven_names_only_is_rejected(self, sql):
        """The previous delta (db-security-reviewer B1): the seven names,
        case-insensitively, but every dotted setting's value shipped raw."""
        # (Anchor was "WHEN pg_temp.is_secret_setting($1)"; the leaked set
        # now also has the unknown plain names and the NULL name, which that
        # version let through too.)
        old = "WHEN coalesce(pg_temp.is_secret_setting($1), true)"
        assert sql.count(old) == 1
        problems = sanitise_problems(sql.replace(old, SEVEN_NAMES_CONDITION, 1))
        assert "sanitise_setting does not call pg_temp.is_secret_setting($1): " \
               "custom and extension settings ship raw" in problems
        leaked = {p.split(":", 1)[0] for p in problems if "secret survives" in p}
        assert leaked == DOTTED_SECRET_CASES | UNKNOWN_NAME_CASES | {"null-name"}, problems
        # The seven names themselves are still redacted in that version.
        assert not any(p.startswith(("upper-case-name", "restore-command", "aws-key")) for p in problems)

    def test_case_sensitive_names_are_rejected(self, sql):
        # (Anchor was "WHEN lower($1) IN (" in sanitise_setting; the list is
        # now in is_secret_setting, folded in the C collation.)
        old = 'SELECT lower($1 COLLATE "C") IN ('  # noqa: Q000
        assert sql.count(old) == 1
        problems = sanitise_problems(sql.replace(old, "SELECT $1 IN (", 1))
        assert "names compared as $1, not lower($1): case-sensitive" in problems
        assert any(p.startswith("upper-case-name: secret survives") for p in problems), problems
        assert any(p.startswith("mixed-case-name: secret survives") for p in problems), problems

    @pytest.mark.parametrize("name", sorted(SANITISED_NAMES))
    def test_dropping_a_name_is_rejected(self, sql, name):
        # (Was applied to sanitise_setting's body; the list is now in
        # is_secret_setting's.)
        body = is_secret_setting_body(sql)
        dropped = re.sub(rf"'{name}',\s*|,\s*'{name}'", "", body, count=1)
        assert dropped != body
        problems = sanitise_problems(sql.replace(body, dropped, 1))
        assert any(p.startswith("sanitised names differ") for p in problems), problems
        assert any("secret survives" in p for p in problems), problems

    @pytest.mark.parametrize("old, new, expect", [
        # Shipping the value itself.
        ("ELSE '***REDACTED*** (set, ' || length($2) || ' characters)'", "ELSE $2", "unrecognised THEN branch"),
        # Shipping the value after the marker. (Anchor was "|| ' characters)'",
        # which rls_policies now also contains.)
        ("length($2) || ' characters)'", "length($2) || ' characters) ' || $2", "unrecognised THEN branch"),
        # Measuring the name, not the value.
        ("length($2)", "length($1)", "aws-key-in-archive-command: got"),
        # Passing more values through unredacted.
        ("WHEN $2 IN ('', '(disabled)')", "WHEN $2 IN ('', '(disabled)', 'echo SECRETPP26')",
         "ssl-passphrase-command: secret survives"),
    ])
    def test_leaky_redaction_is_rejected(self, sql, old, new, expect):
        assert sql.count(old) == 1
        problems = sanitise_problems(sql.replace(old, new, 1))
        assert any(expect in p for p in problems), problems

    # (Replaces test_sanitised_flag_missing_a_name_is_rejected, whose anchor,
    # the inline seven-name list, no longer exists: the flag must now be the
    # predicate itself.)
    @pytest.mark.parametrize("new", [
        MAIN_SANITISED_FLAG,                                               # main's list: no dotted names
        "'sanitised', s.name IN ('archive_command')",                      # a name missing
        "'sanitised', pg_temp.is_secret_setting(s.setting)",               # wrong argument
        "'sanitised', false",
    ])
    def test_sanitised_flag_not_using_the_predicate_is_rejected(self, sql, new):
        bad, n = ws_replace(sql, SANITISED_FLAG, new)
        assert n == 1
        problems = sanitise_problems(bad)
        assert "settings 'sanitised' flag is not pg_temp.is_secret_setting(s.name)" in problems, problems

    def test_sanitised_flag_agrees_with_the_redaction(self, sql):
        """Every name whose value is redacted is flagged, and no other."""
        for case_id, name, value, want, _ in SANITISE_CASES:
            if value in (None, "", "(disabled)") or name is None:  # pg_settings names are never NULL
                continue
            assert is_secret_model(sql, name) == (want != value), case_id

    @pytest.mark.parametrize("where", sorted(SANITISED_ROUTES))
    def test_a_route_bypassing_sanitise_setting_is_rejected(self, sql, where):
        route = SANITISED_ROUTES[where]
        raw = re.sub(r"pg_temp\.sanitise_setting\(\s*[\w.]+\s*,\s*(.*)\)$", r"\1", route)
        assert raw != route
        # Match the route in the file whatever its column alignment.
        pattern = r"\s+".join(re.escape(w) for w in route.split())
        bad, n = re.subn(pattern, lambda _: raw, sql, count=1)
        assert n == 1, where
        problems = sanitise_problems(bad)
        assert f"{where} does not go through sanitise_setting" in problems, problems


class TestIsSecretSetting:
    """The predicate behind sanitise_setting and the 'sanitised' flag."""

    def test_reviewed_names_are_in_the_sql(self, sql):
        body = flat_code(is_secret_setting_body(sql))
        shape = SECRET_PREDICATE_SHAPE.fullmatch(body[body.index("$$") + 2:].strip())
        assert shape
        assert set(sql_literals(shape["names"])) == SANITISED_NAMES
        assert set(sql_literals(shape["prefixes"])) == REVIEWED_SETTINGS
        assert len(sql_literals(shape["prefixes"])) == len(REVIEWED_SETTINGS) == 28
        assert (shape["subject"], shape["esubject"], shape["field"], shape["neg"]) == \
               (LOWER_C, LOWER_C, None, "NOT ")
        assert (shape["uop"], shape["usubject"]) == ("=", LOWER_C)

    def test_reviewed_list_is_lower_case_and_from_reviewed_extensions(self):
        for name in REVIEWED_SETTINGS:
            assert name == name.lower(), name
            assert name.split(".", 1)[0] in REVIEWED_EXTENSIONS, name
            assert name.count(".") == 1, name
            assert not SECRET_LOOKING.search(name), name
        assert not any(n.startswith("auto_explain.") for n in REVIEWED_SETTINGS)

    def test_no_is_secret_problems(self, sql):
        assert is_secret_problems(sql) == []

    @pytest.mark.parametrize("name, want", [
        ("primary_conninfo", True), ("KRB_SERVER_KEYFILE", True),
        ("pgrst.jwt_secret", True), ("app.jwt_secret", True), ("APP.Token", True),
        ("pgaudit_x.key", True), ("pgauditx.key", True), ("x_plpgsql.key", True), ("app.pgaudit", True),
        ("pg_trgm.similarity_threshold", True),
        # Unreviewed names under reviewed prefixes (were False with the prefix rule).
        ("pgaudit.jwt_secret", True), ("plpgsql.jwt_key", True), ("set_user.api_token", True),
        ("pg_stat_statements.secret", True), ("pgaudit.log_key", True), ("pgaudit.lo", True),
        ("pgaudit.", True),
        # (Was False: auto_explain was a reviewed prefix.)
        ("auto_explain.log_analyze", True),
        ("pgaudit.log", False), ("PGAUDIT.LOG", False), ("Set_User.block_log_statement", False),
        ("pg_stat_statements.track", False), ("plpgsql.variable_conflict", False),
        ("plpgsql.extra_errors", False), ("pgaudit.role", False),
        ("search_path", False), ("log_connections", False), ("ssl_ciphers", False),
    ])
    def test_model(self, sql, name, want):
        assert is_secret_model(sql, name) is want

    @pytest.mark.parametrize("name", sorted(REVIEWED_SETTINGS))
    def test_every_reviewed_name_is_visible_in_any_case(self, sql, name):
        assert is_secret_model(sql, name) is False
        assert is_secret_model(sql, name.upper()) is False
        assert sanitise_model(sql, name, "on") == "on"

    def test_previous_prefix_rule_is_rejected(self, sql):
        """The previous delta, swapped in verbatim: a planted
        pgaudit.jwt_secret (and every other unreviewed name under the five
        prefixes) shipped raw."""
        body = is_secret_setting_body(sql)
        # (The pattern ended at "))" before ";"; the unknown-name clause now follows.)
        bad_body, n = re.subn(r"OR \(position\('\.' in \$1\) > 0.*?'plpgsql\.extra_errors'\)\)",
                              lambda _: PREFIX_DOTTED_RULE, body, count=1, flags=re.S)
        assert n == 1
        problems = sanitise_problems(sql.replace(body, bad_body, 1))
        assert "dotted rule matches prefixes, not exact reviewed names" in problems, problems
        leaked = {p.split(":", 1)[0] for p in problems if "secret survives" in p}
        assert leaked == PREFIX_RULE_LEAKS, problems

    @pytest.mark.parametrize("old, new", [
        # Prefix match on the reviewed extensions.
        ('lower($1 COLLATE "C") NOT IN ( \'pgaudit.log\',',
         "split_part(lower($1), '.', 1) NOT IN ('pgaudit','set_user','pg_stat_statements','plpgsql') "
         'AND lower($1 COLLATE "C") NOT IN ( \'pgaudit.log\','),
        # Prefix match by LIKE.
        ('lower($1 COLLATE "C") NOT IN ( \'pgaudit.log\',',
         'lower($1) NOT LIKE \'pgaudit.%\' AND lower($1 COLLATE "C") NOT IN ( \'pgaudit.log\','),
    ])
    def test_other_prefix_matches_are_rejected(self, sql, old, new):
        """Any shape the model does not know is reported, so a prefix match
        bolted onto the exact list cannot pass silently."""
        body = is_secret_setting_body(sql)
        bad_body, n = ws_replace(body, old, new)
        assert n == 1
        problems = sanitise_problems(sql.replace(body, bad_body, 1))
        assert "is_secret_setting has an unrecognised shape" in problems, problems

    @pytest.mark.parametrize("name", sorted(REVIEWED_SETTINGS))
    def test_dropping_a_reviewed_name_is_rejected(self, sql, name):
        body = is_secret_setting_body(sql)
        dropped = re.sub(rf"'{re.escape(name)}',\s*|,\s*'{re.escape(name)}'", "", body, count=1)
        assert dropped != body
        problems = sanitise_problems(sql.replace(body, dropped, 1))
        assert f"reviewed setting list differs: extra [], missing [{name!r}]" in problems, problems

    @pytest.mark.parametrize("added, leaks", [
        ("pgaudit.jwt_secret", {"reviewed-prefix-unreviewed-name"}),
        ("plpgsql.jwt_key", {"plpgsql-unreviewed-name"}),
        ("set_user.api_token", {"set-user-unreviewed-name"}),
        ("pg_stat_statements.secret", {"pg-stat-statements-unreviewed-name"}),
        ("pgrst.jwt_secret", {"dotted-pgrst-jwt-secret"}),
        ("app.jwt_key", {"dotted-system-key"}),
        ("pgaudit.log_key", {"reviewed-name-with-suffix"}),
        ("pgaudit.password", set()),
        ("set_user.credentials", set()),
        ("pgaudit.auth_dsn", set()),
    ])
    def test_adding_a_secret_looking_name_is_rejected(self, sql, added, leaks):
        old = "'plpgsql.extra_errors'))"
        body = is_secret_setting_body(sql)
        assert body.count(old) == 1
        problems = sanitise_problems(sql.replace(body, body.replace(old, f"'plpgsql.extra_errors','{added}'))", 1), 1))
        assert f"reviewed setting list differs: extra [{added!r}], missing []" in problems, problems
        assert f"reviewed setting list contains secret-looking names [{added!r}]" in problems, problems
        leaked = {p.split(":", 1)[0] for p in problems if "secret survives" in p}
        assert leaked == leaks, problems

    def test_adding_an_unreviewed_harmless_name_is_still_rejected(self, sql):
        """Widening is a review decision even for a harmless-looking name."""
        old = "'plpgsql.extra_errors'))"
        body = is_secret_setting_body(sql)
        problems = sanitise_problems(sql.replace(body, body.replace(old, "'plpgsql.extra_errors','auto_explain.log_min_duration'))", 1), 1))
        assert "reviewed setting list differs: extra ['auto_explain.log_min_duration'], missing []" in problems
        assert any(p.startswith("auto-explain-not-reviewed: secret survives") for p in problems), problems

    def test_case_sensitive_exact_names_are_rejected(self, sql):
        """lower() dropped: PGAUDIT.LOG is redacted. Not a leak, but not the
        reviewed rule either. (Message was "dotted rule is not: lower($1) NOT
        IN (reviewed settings)"; the rule now names the C collation.)"""
        body = is_secret_setting_body(sql)
        bad_body, n = ws_replace(body, 'AND lower($1 COLLATE "C") NOT IN (', "AND $1 NOT IN (")
        assert n == 1
        problems = sanitise_problems(sql.replace(body, bad_body, 1))
        assert 'dotted rule is not: lower($1 COLLATE "C") NOT IN (reviewed settings)' in problems, problems
        assert any(p.startswith("reviewed-pgaudit-upper: got '***REDACTED***") for p in problems), problems

    def test_inverting_the_rule_is_rejected(self, sql):
        body = is_secret_setting_body(sql)
        bad_body, n = ws_replace(body, 'AND lower($1 COLLATE "C") NOT IN (', 'AND lower($1 COLLATE "C") IN (')
        assert n == 1
        problems = sanitise_problems(sql.replace(body, bad_body, 1))
        assert 'dotted rule is not: lower($1 COLLATE "C") NOT IN (reviewed settings)' in problems, problems
        leaked = {p.split(":", 1)[0] for p in problems if "secret survives" in p}
        assert leaked == DOTTED_SECRET_CASES, problems

    def test_dropping_the_dotted_rule_is_rejected(self, sql):
        body = is_secret_setting_body(sql)
        # (The pattern ended at "))" before ";"; the unknown-name clause now follows.)
        bad_body, n = re.subn(r"\s+OR \(position\('\.' in \$1\) > 0.*?'plpgsql\.extra_errors'\)\)", "", body,
                              count=1, flags=re.S)
        assert n == 1
        problems = sanitise_problems(sql.replace(body, bad_body, 1))
        assert "is_secret_setting has no rule for dotted (custom and extension) names" in problems, problems
        leaked = {p.split(":", 1)[0] for p in problems if "secret survives" in p}
        assert leaked == DOTTED_SECRET_CASES, problems

    @pytest.mark.parametrize("old, new", [
        ("') OR (position", "') AND (position"),                          # dotted names only
        ("position('.' in $1) > 0 AND ", ""),                             # every name dotted-checked
    ])
    def test_unknown_predicate_shapes_are_rejected(self, sql, old, new):
        body = is_secret_setting_body(sql)
        bad_body, n = ws_replace(body, old, new)
        assert n == 1, old
        problems = sanitise_problems(sql.replace(body, bad_body, 1))
        assert "is_secret_setting has an unrecognised shape" in problems, problems
        assert any("unrecognised is_secret_setting body" in p for p in problems), problems


class TestUnknownNamesCollationAndFailClosed:
    """db-security-reviewer B2 (unknown plain names), N1 (look-alikes under
    the database collation), N2 (a NULL name), N4 (boot_val), and the
    volatility the pg_settings lookup needs."""

    @staticmethod
    def _leaked(problems):
        return {p.split(":", 1)[0] for p in problems if "secret survives" in p}

    def test_unknown_clause_is_present(self, sql):
        body = flat_code(is_secret_setting_body(sql))
        assert body.count("OR (position('.' in $1) = 0 AND NOT EXISTS (SELECT 1 FROM pg_catalog.pg_settings p "
                          "WHERE ") == 1
        shape = SECRET_PREDICATE_SHAPE.fullmatch(body[body.index("$$") + 2:].strip())
        assert shape and (shape["uop"], shape["usubject"]) == ("=", LOWER_C)

    def test_unknown_clause_finds_mixed_case_settings(self, sql):
        """DateStyle / TimeZone are known settings: visible in settings
        (pg_settings spelling) and in file_settings (postgresql.conf spelling)."""
        body = flat_code(is_secret_setting_body(sql))
        shape = SECRET_PREDICATE_SHAPE.fullmatch(body[body.index("$$") + 2:].strip())
        assert shape["pname"] == 'lower(p.name COLLATE "C")', shape["pname"]
        for name in ("DateStyle", "datestyle", "TimeZone", "timezone"):
            assert is_secret_model(sql, name) is False, name

    def test_every_lower_is_in_the_c_collation(self, sql):
        lowers = re.findall(r"lower\([^)]*\)", flat_code(is_secret_setting_body(sql)))
        assert lowers.count(LOWER_C) == 3
        assert all(x.endswith(' COLLATE "C")') for x in lowers), lowers

    def test_fail_closed_and_volatility(self, sql):
        assert "WHEN coalesce(pg_temp.is_secret_setting($1), true)" in flat_code(sanitise_setting_body(sql))
        assert function_volatility(sql, "is_secret_setting") == "STABLE"
        assert function_volatility(sql, "sanitise_setting") == "STABLE"

    def test_lookalikes_fold_onto_reviewed_names_under_the_database_collation(self):
        """The precondition of N1, in the model: the database's lower() maps
        both look-alikes onto reviewed names, the C collation does not."""
        for name, reviewed in (("set_user.blocK_copy_program", "set_user.block_copy_program"),
                               ("pgaudİt.log", "pgaudit.log")):
            assert CASE_FOLD["lower($1)"](name) == reviewed in REVIEWED_SETTINGS
            assert CASE_FOLD[LOWER_C](name) not in REVIEWED_SETTINGS

    def test_dropping_the_unknown_clause_is_rejected(self, sql):
        body = is_secret_setting_body(sql)
        bad_body, n = re.subn(r"\s+OR \(position\('\.' in \$1\) = 0.*?\)\)\)(?=;)", "", body, count=1, flags=re.S)
        assert n == 1
        problems = sanitise_problems(sql.replace(body, bad_body, 1))
        assert "is_secret_setting has no rule for plain names the server does not know" in problems, problems
        assert self._leaked(problems) == UNKNOWN_NAME_CASES, problems

    @pytest.mark.parametrize("old, new", [
        ("position('.' in $1) = 0 AND NOT EXISTS", "NOT EXISTS"),                        # every name
        ("position('.' in $1) = 0 AND NOT EXISTS", "position('.' in $1) > 0 AND NOT EXISTS"),  # dotted only
    ])
    def test_unknown_clause_on_dotted_names_is_rejected(self, sql, old, new):
        """Placeholders are never in pg_settings: applied to dotted names the
        rule redacts reviewed settings such as pgaudit.log."""
        body = is_secret_setting_body(sql)
        bad_body, n = ws_replace(body, old, new)
        assert n == 1
        problems = sanitise_problems(sql.replace(body, bad_body, 1))
        assert ("unknown-name rule is not limited to plain (undotted) names: "
                "reviewed placeholders would be redacted") in problems, problems
        assert any(p.startswith("reviewed-pgaudit: got '***REDACTED***") for p in problems), problems

    def test_dotted_only_unknown_rule_also_loses_the_plain_names(self, sql):
        body = is_secret_setting_body(sql)
        bad_body, _ = ws_replace(body, "position('.' in $1) = 0 AND NOT EXISTS", "position('.' in $1) > 0 AND NOT EXISTS")
        assert self._leaked(sanitise_problems(sql.replace(body, bad_body, 1))) == UNKNOWN_NAME_CASES

    def test_unknown_clause_without_lower_is_rejected(self, sql):
        """p.name = $1: LOG_STATEMENT is not found and gets redacted."""
        body = is_secret_setting_body(sql)
        bad_body, n = re.subn(r'WHERE (p\.name|lower\(p\.name COLLATE "C"\)) = lower\(\$1 COLLATE "C"\)',
                              r"WHERE \1 = $1", body, count=1)
        assert n == 1
        problems = sanitise_problems(sql.replace(body, bad_body, 1))
        assert 'unknown-name rule does not compare p.name = lower($1 COLLATE "C")' in problems, problems
        assert any(p.startswith("known-upper: got '***REDACTED***") for p in problems), problems

    def test_unqualified_pg_settings_is_rejected(self, sql):
        body = is_secret_setting_body(sql)
        bad_body, n = ws_replace(body, "FROM pg_catalog.pg_settings p", "FROM pg_settings p")
        assert n == 1
        assert "is_secret_setting has an unrecognised shape" in sanitise_problems(sql.replace(body, bad_body, 1))

    @pytest.mark.parametrize("which, leaks", [
        (0, set()),               # the seven names: a look-alike of those is unknown, so still redacted
        (1, LOOKALIKE_CASES),     # the reviewed list: both look-alikes fold onto reviewed names
        (2, set()),               # the unknown-name lookup: over-redaction at most
    ])
    def test_a_lower_without_the_c_collation_is_rejected(self, sql, which, leaks):
        body = is_secret_setting_body(sql)
        at = [m.start() for m in re.finditer(re.escape(LOWER_C), body)]
        assert len(at) == 3
        bad_body = body[:at[which]] + "lower($1)" + body[at[which] + len(LOWER_C):]
        problems = sanitise_problems(sql.replace(body, bad_body, 1))
        assert 'a lower() in is_secret_setting lacks COLLATE "C": look-alikes fold onto reviewed names' in problems
        assert self._leaked(problems) == leaks, problems

    @pytest.mark.parametrize("new", ["WHEN pg_temp.is_secret_setting($1)",
                                     "WHEN coalesce(pg_temp.is_secret_setting($1), false)"])
    def test_failing_open_on_a_null_name_is_rejected(self, sql, new):
        old = "WHEN coalesce(pg_temp.is_secret_setting($1), true)"
        assert sql.count(old) == 1
        problems = sanitise_problems(sql.replace(old, new, 1))
        assert ("sanitise_setting does not fail closed on a NULL name: "
                "want coalesce(pg_temp.is_secret_setting($1), true)") in problems, problems
        assert self._leaked(problems) == {"null-name"}, problems

    @pytest.mark.parametrize("fn, msg", [
        ("is_secret_setting", "is_secret_setting reads pg_settings: it must be STABLE"),
        ("sanitise_setting", "sanitise_setting calls a STABLE function: it must be STABLE"),
    ])
    @pytest.mark.parametrize("volatility", ["IMMUTABLE", ""])
    def test_wrong_volatility_is_rejected(self, sql, fn, msg, volatility):
        start = sql.index(f"CREATE FUNCTION pg_temp.{fn}(")
        end = sql.index("$$ LANGUAGE sql STABLE;", start)
        bad = sql[:end] + f"$$ LANGUAGE sql {volatility}".rstrip() + ";" + sql[end + len("$$ LANGUAGE sql STABLE;"):]
        assert msg in sanitise_problems(bad)

    def test_boot_val_route_is_pinned(self, sql):
        assert flat_code(sql).count(SANITISED_ROUTES["settings.boot_val"]) == 1
        assert len(re.findall(r"\bs\.boot_val\b", flat_code(sql))) == 1

    def test_raw_boot_val_is_rejected(self, sql):
        bad, n = ws_replace(sql, SANITISED_ROUTES["settings.boot_val"], "'boot_val', s.boot_val")
        assert n == 1
        assert "settings.boot_val does not go through sanitise_setting" in sanitise_problems(bad)


class TestRoleSettingsGoThroughSanitiseSetting:

    def test_route_is_pinned(self, sql):
        assert flat_code(sql).count(ROLE_SETTINGS_ROUTE) == 1
        assert len(re.findall(r"\bsetconfig\b", flat_code(sql))) == 1

    @pytest.mark.parametrize("case_id, setconfig, want", ROLE_SETTINGS_CASES, ids=[c[0] for c in ROLE_SETTINGS_CASES])
    def test_model_output(self, sql, case_id, setconfig, want):
        got = role_settings_model(sql, setconfig)
        assert got == want
        for secret in re.findall(r"SECRET\w+", " ".join(setconfig)):
            assert secret.lower() not in " ".join(got).lower()

    @pytest.mark.parametrize("new", [
        MAIN_ROLE_SETTINGS_ROUTE,                                   # main / 03a618c: the raw array
        # The whole entry as the name: harmless names lose their value too,
        # and the value measured is the whole entry.
        "'settings', (SELECT jsonb_agg( split_part(c, '=', 1) || '=' || pg_temp.sanitise_setting(c, "
        "substring(c from position('=' in c) + 1)) ORDER BY ord) FROM unnest(s.setconfig) WITH ORDINALITY AS u(c, ord))",
        # The value cut at its second '=' (split_part(c, '=', 2)).
        "'settings', (SELECT jsonb_agg( split_part(c, '=', 1) || '=' || pg_temp.sanitise_setting(split_part(c, '=', 1), "
        "split_part(c, '=', 2)) ORDER BY ord) FROM unnest(s.setconfig) WITH ORDINALITY AS u(c, ord))",
        # Order lost.
        "'settings', (SELECT jsonb_agg( split_part(c, '=', 1) || '=' || pg_temp.sanitise_setting(split_part(c, '=', 1), "
        "substring(c from position('=' in c) + 1))) FROM unnest(s.setconfig) WITH ORDINALITY AS u(c, ord))",
        # Raw value next to the redacted one.
        "'settings', (SELECT jsonb_agg( split_part(c, '=', 1) || '=' || pg_temp.sanitise_setting(split_part(c, '=', 1), "
        "substring(c from position('=' in c) + 1)) ORDER BY ord) FROM unnest(s.setconfig) WITH ORDINALITY AS u(c, ord)), "
        "'raw', s.setconfig",
    ])
    def test_wrong_routes_are_rejected(self, sql, new):
        bad, n = ws_replace(sql, ROLE_SETTINGS_ROUTE, new)
        assert n == 1
        assert "role_settings.settings does not go through sanitise_setting entry by entry" in sanitise_problems(bad)


# ---------------------------------------------------------------------------
# rls_policies: a policy expression can embed literals (USING (api_key =
# 'x')), so qual and with_check ship only as NULL or the set-and-length
# marker (db-security-reviewer N2). On main (= 03a618c) both shipped raw.
# ---------------------------------------------------------------------------

RLS_FIELD = re.compile(
    r"'(?P<field>qual|with_check)', (?P<expr>CASE WHEN (?P<c1>\w+) IS NULL THEN NULL "
    r"ELSE '(?P<prefix>[^']*)' \|\| length\((?P<c2>\w+)\) \|\| '(?P<suffix>[^']*)' END)")
MAIN_RLS_FIELDS = "'qual', qual, 'with_check', with_check"
RLS_QUAL = "'qual', CASE WHEN qual IS NULL THEN NULL ELSE '***REDACTED*** (set, ' || length(qual) || ' characters)' END"
RLS_WITH_CHECK = ("'with_check', CASE WHEN with_check IS NULL THEN NULL "
                  "ELSE '***REDACTED*** (set, ' || length(with_check) || ' characters)' END")
# (id, qual, with_check as pg_policies holds them, exact shipped pair)
RLS_CASES = [
    ("literal-in-both", "(api_key = 'SECRETRLS34'::text)", "(api_key <> 'SECRETWC37'::text)",
     ("***REDACTED*** (set, 31 characters)", "***REDACTED*** (set, 31 characters)")),
    ("select-policy-no-with-check", "true", None, ("***REDACTED*** (set, 4 characters)", None)),
    ("insert-policy-no-qual", None, "(owner = CURRENT_USER)", (None, redaction_marker("(owner = CURRENT_USER)"))),
]


def rls_block(text: str) -> str:
    code = strip_line_comments(text)
    start = code.index("'rls_policies',")
    return " ".join(code[start:code.index("FROM pg_policies", start)].split())


def code_without_literals(text: str) -> str:
    """The SQL without comments, every '...' literal emptied."""
    code = strip_line_comments(text)
    out, i, n = [], 0, len(code)
    while i < n:
        if code[i] == "'":
            j = i + 1
            while j < n and not (code[j] == "'" and not code.startswith("''", j)):
                j += 2 if code.startswith("''", j) else 1
            out.append("''")
            i = j + 1
        else:
            out.append(code[i])
            i += 1
    return "".join(out)


def rls_model(text: str, qual: str | None, with_check: str | None) -> tuple:
    block = rls_block(text)
    row = {"qual": qual, "with_check": with_check}
    out = []
    for field in ("qual", "with_check"):
        m = next((m for m in RLS_FIELD.finditer(block) if m["field"] == field), None)
        if m is None:
            raise ValueError(f"rls_policies.{field}: unrecognised or raw")
        if row[m["c1"]] is None:
            out.append(None)
        else:
            out.append(f"{m['prefix']}{len(row[m['c2']] or '')}{m['suffix']}")
    return tuple(out)


def rls_problems(text: str) -> list[str]:
    problems = []
    block = rls_block(text)
    for field in ("qual", "with_check"):
        found = [m for m in RLS_FIELD.finditer(block) if m["field"] == field]
        if len(found) != 1:
            problems.append(f"rls_policies.{field} is not redacted (raw or unrecognised shape)")
            continue
        m = found[0]
        if (m["c1"], m["c2"]) != (field, field):
            problems.append(f"rls_policies.{field} tests or measures another column: {m['expr']!r}")
        if (m["prefix"], m["suffix"]) != (SANITISE_MARKER_PREFIX, SANITISE_MARKER_SUFFIX):
            problems.append(f"rls_policies.{field} marker differs: {m['expr']!r}")
    rest = RLS_FIELD.sub("", block)
    if re.search(r"\b(qual|with_check)\b", rest):
        problems.append("rls_policies ships qual or with_check outside the redaction")
    code = code_without_literals(text)
    if len(re.findall(r"\bpg_polic(?:y|ies)\b", code)) != 1:
        problems.append("policies are read somewhere other than rls_policies")
    if re.search(r"\b(polqual|polwithcheck)\b", code):
        problems.append("policy expressions are read from pg_policy directly")
    for case_id, qual, with_check, want in RLS_CASES:
        try:
            got = rls_model(text, qual, with_check)
        except ValueError as exc:
            problems.append(f"{case_id}: {exc}")
            continue
        for secret in re.findall(r"SECRET\w+", f"{qual} {with_check}"):
            if secret.lower() in json.dumps(got).lower():
                problems.append(f"{case_id}: secret survives: {got!r}")
        if got != want:
            problems.append(f"{case_id}: got {got!r}, want {want!r}")
    return problems


class TestRlsPolicyExpressionsAreRedacted:

    def test_fields_are_pinned(self, sql):
        block = rls_block(sql)
        assert block.count(RLS_QUAL) == 1 and block.count(RLS_WITH_CHECK) == 1

    def test_no_rls_problems(self, sql):
        assert rls_problems(sql) == []

    @pytest.mark.parametrize("case_id, qual, with_check, want", RLS_CASES, ids=[c[0] for c in RLS_CASES])
    def test_model_output(self, sql, case_id, qual, with_check, want):
        assert rls_model(sql, qual, with_check) == want

    def test_main_rls_policies_is_rejected(self, sql):
        bad, n = ws_replace(sql, RLS_QUAL + ", " + RLS_WITH_CHECK, MAIN_RLS_FIELDS)
        assert n == 1
        problems = rls_problems(bad)
        assert "rls_policies.qual is not redacted (raw or unrecognised shape)" in problems
        assert "rls_policies.with_check is not redacted (raw or unrecognised shape)" in problems
        assert "rls_policies ships qual or with_check outside the redaction" in problems

    @pytest.mark.parametrize("old, new, expect", [
        (RLS_QUAL, "'qual', CASE WHEN qual IS NULL THEN NULL ELSE qual END",
         "rls_policies.qual is not redacted (raw or unrecognised shape)"),
        (RLS_QUAL, RLS_QUAL.replace("length(qual)", "length(with_check)"),
         "rls_policies.qual tests or measures another column"),
        (RLS_WITH_CHECK, RLS_WITH_CHECK.replace("WHEN with_check IS NULL", "WHEN qual IS NULL"),
         "rls_policies.with_check tests or measures another column"),
        (RLS_QUAL, RLS_QUAL.replace("' characters)'", "' characters) ' || qual"),
         "rls_policies.qual is not redacted (raw or unrecognised shape)"),
        (RLS_QUAL, RLS_QUAL + ", 'qual_text', qual", "rls_policies ships qual or with_check outside the redaction"),
    ])
    def test_wrong_redactions_are_rejected(self, sql, old, new, expect):
        bad, n = ws_replace(sql, old, new)
        assert n == 1
        problems = rls_problems(bad)
        assert any(p.startswith(expect) for p in problems), problems

    def test_a_second_route_to_policy_expressions_is_rejected(self, sql):
        anchor = "'extensions', ("
        assert sql.count(anchor) == 1
        extra = ("'policy_exprs', (SELECT jsonb_agg(pg_get_expr(polqual, polrelid)) FROM pg_policy),\n\n")
        problems = rls_problems(sql.replace(anchor, extra + anchor, 1))
        assert "policies are read somewhere other than rls_policies" in problems, problems
        assert "policy expressions are read from pg_policy directly" in problems, problems


# ---------------------------------------------------------------------------
# The bundle's own 'redactions' list says what was withheld: the two classes
# added for B1 and N2 are listed, as S0 (never shipped), and the custom
# settings note names exactly the extensions whose settings the SQL reviews.
# ---------------------------------------------------------------------------

REDACTION_ENTRY = re.compile(r"jsonb_build_object\('field','([^']*)','class','([^']*)',\s*'note','((?:[^']|'')*)'\)")


class TestRedactionsListTheNewClasses:

    def test_new_entries_are_s0(self, sql):
        entries = {f: (c, n) for f, c, n in REDACTION_ENTRY.findall(sql)}
        assert entries["custom and extension settings"][0] == "S0"
        assert entries["pg_policies.qual and with_check"][0] == "S0"
        assert entries["pg_settings.archive_command"][0] == "S0"
        assert entries["pg_settings.primary_conninfo"][0] == "S0"

    # (Was ..._names_exactly_the_reviewed_prefixes, matching "except reviewed
    # prefixes ..."; the note now describes the exact-name list.)
    def test_custom_settings_note_names_exactly_the_reviewed_extensions(self, sql):
        note = {f: n for f, _, n in REDACTION_ENTRY.findall(sql)}["custom and extension settings"]
        m = re.search(r"except an exact list of reviewed (.*) settings\.$", note)
        assert m, note
        named = set(m.group(1).replace(" and ", ", ").split(", "))
        assert named == REVIEWED_EXTENSIONS
        assert "auto_explain" not in note
        for route in ("settings", "file_settings", "role_settings"):
            assert route in note


# ---------------------------------------------------------------------------
# mask_secrets: five regexp_replace rules. Like libpq, backslash escapes apply
# in quoted AND unquoted values; a URI password may have an empty user name
# and may contain '/', '?' or '#' (it ends only at '@'); and libpq percent-
# decodes URI query keywords, so the value of any query parameter whose name
# contains '%' (pass%77ord=) is masked. On main (= 03a618c here),
# password='it\'s SECRET' kept "SECRET'", password=abc\ SECRET kept SECRET,
# and postgresql://:SECRET@host, rclone://u:a/SECRET@b and ?pass%77ord=SECRET
# were not masked at all.
#
# The rules are read out of collect.sql and run with Python's re as a model.
# PostgreSQL's ARE engine takes the longest match of an alternation where
# Python takes the first that matches, so every input below has its quoted
# value followed by whitespace or the end of the string: there the quoted
# alternative is also the longest, and both engines agree (the guard test
# below enforces this).
#
# Since the "never ship raw text" design, mask_secrets runs only on the values
# parse_conninfo returns for allowlisted keys (settings rows and manifest
# checks get the redaction marker instead, see TestSanitiseSettingNeverShipsText).
# Its rules did not change, and an allowlisted value such as application_name
# can hold any of these texts, so every case below is kept, the
# archive-command-shaped ones included. The live proof on PostgreSQL's own
# regex engine is
# tests/test_collector_hardening_live.py::test_primary_conninfo_never_leaks_and_parses_exactly
# (application_name carrying a password) and
# ::test_subscription_conninfo_with_question_mark_in_password_never_leaks.
# ---------------------------------------------------------------------------

MASK_RE_REDACTED = "***REDACTED***"
# The rule text as the regex engine sees it (SQL '' already undone).
PASSWORD_SINGLE_QUOTED = r"'(?:[^'\\]|\\.)*'"
PASSWORD_DOUBLE_QUOTED = r'"(?:[^"\\]|\\.)*"'
PASSWORD_UNQUOTED = r"(?:[^\s\\]|\\.)+"
URI_RULE = r"://([^:/@\s]*):([^@\s]+)@"
PCT_RULE = r"([?&][^=&\s]*%[^=&\s]*=)[^&\s]*"
R = MASK_RE_REDACTED

# (id, input, exact masked output, secret that must not survive)
MASK_CASES = [
    ("uri-empty-user", "postgresql://:SECRETNOUSER5@db.example/postgres",
     f"postgresql://:{R}@db.example/postgres", "SECRETNOUSER5"),
    ("keyword-escaped-single-quote", r"host=x user=rep password='it\'s SECRETESC9' application_name=s1",
     f"host=x user=rep password={R} application_name=s1", "SECRETESC9"),
    ("archive-uri-empty-user", "cp %p rclone://:SECRETARCH6@bucket/%f",
     f"cp %p rclone://:{R}@bucket/%f", "SECRETARCH6"),
    ("escaped-double-quote", r'run --opt password="say \"SECRETDQ7\" now" %p',
     f"run --opt password={R} %p", "SECRETDQ7"),
    ("escaped-backslash-then-close", r"password='ab\\' host=x next=1",
     f"password={R} host=x next=1", None),  # ab\\ is the whole value
    # The URI password ends only at '@': '?', '#' and '/' are part of it.
    ("uri-password-question-mark", "postgresql://rep:Sec?SECRETQM7@db/postgres",
     f"postgresql://rep:{R}@db/postgres", "SECRETQM7"),
    ("uri-password-hash", "postgresql://rep:Sec#SECRETHASH8@db/postgres",
     f"postgresql://rep:{R}@db/postgres", "SECRETHASH8"),
    ("uri-password-slash", "postgresql://rep:pa/SECRETSLASH13@db/x",
     f"postgresql://rep:{R}@db/x", "SECRETSLASH13"),
    ("archive-uri-password-slash", "cp %p rclone://u:a/SECRETARCHSL@bucket/%f",
     f"cp %p rclone://u:{R}@bucket/%f", "SECRETARCHSL"),
    # Over-redaction is the accepted price: a port followed by an '@' later in
    # the URL is masked up to that '@'.
    ("uri-port-then-at-over-redacted", "curl https://host:8443/p?u=a@b",
     f"curl https://host:{R}@b", None),
    # Unquoted values honour backslash escapes; a quote or '=' inside one is literal.
    ("keyword-unquoted-escaped-space", r"host=x user=rep password=abc\ SECRETUNQ10 application_name=s1",
     f"host=x user=rep password={R} application_name=s1", "SECRETUNQ10"),
    ("keyword-unquoted-inner-quote", "host=x user=rep password=ab'cd=SECRETAPOS11 application_name=s1",
     f"host=x user=rep password={R} application_name=s1", "SECRETAPOS11"),
    # An escaped backslash does not escape the space after it: the value ends there.
    ("keyword-unquoted-escaped-backslash", r"password=ab\\ host=x",
     f"password={R} host=x", None),
    # A password inside another keyword's quoted value. The closing quote is
    # eaten with the secret (over-redaction), matching the live collector.
    ("keyword-options-password", "host=x user=rep options='-c app.password=SECRETOPT14'",
     f"host=x user=rep options='-c app.password={R}", "SECRETOPT14"),
    # Percent-encoded query keys: the value is masked whatever the key decodes to.
    ("uri-query-percent-key", "postgresql://rep@db/postgres?pass%77ord=SECRETPCT12",
     f"postgresql://rep@db/postgres?pass%77ord={R}", "SECRETPCT12"),
    ("uri-query-percent-key-after-amp",
     "postgresql://db/postgres?sslmode=require&pass%77ord=SECRETPCT13&application_name=a",
     f"postgresql://db/postgres?sslmode=require&pass%77ord={R}&application_name=a", "SECRETPCT13"),
    ("uri-query-percent-in-value-only-untouched",
     "postgresql://rep@db/postgres?application_name=s%201&sslmode=require",
     "postgresql://rep@db/postgres?application_name=s%201&sslmode=require", None),
    # Behaviour that was already right and must stay right.
    ("uri-user-password", "cp %p rclone://user:s3cr3tXYZ@bucket/%f",
     f"cp %p rclone://user:{R}@bucket/%f", "s3cr3tXYZ"),
    ("keyword-bare", "password=hunter2XYZ host=x user=rep",
     f"password={R} host=x user=rep", "hunter2XYZ"),
    ("keyword-quoted-space-equals", "host=x user=rep password='ab cd=SECRETQ2' application_name=s1",
     f"host=x user=rep password={R} application_name=s1", "SECRETQ2"),
    ("keyword-case-insensitive", "PASSWORD=SECRETUP8 host=x",
     f"PASSWORD={R} host=x", "SECRETUP8"),
    ("uri-user-only-untouched", "postgresql://rep@db.example/postgres",
     "postgresql://rep@db.example/postgres", None),
    ("no-secret-untouched", "pgbackrest --stanza=main archive-push %p",
     "pgbackrest --stanza=main archive-push %p", None),
]


def mask_secrets_body(text: str) -> str:
    start = text.index("CREATE FUNCTION pg_temp.mask_secrets(")
    end = text.index("$$ LANGUAGE", start)
    return text[start:end]


def sql_literals(code: str) -> list[str]:
    """Every '...' literal in `code`, unescaped ('' -> '; backslash literal,
    as under standard_conforming_strings = on). `--` outside a literal starts
    a comment; inside one (e.g. '--password') it does not."""
    out, i, n = [], 0, len(code)
    while i < n:
        if code.startswith("--", i):
            j = code.find("\n", i)
            i = n if j == -1 else j
        elif code[i] == "'":
            buf, j = [], i + 1
            while True:
                assert j < n, "unterminated literal"
                if code.startswith("''", j):
                    buf.append("'")
                    j += 2
                elif code[j] == "'":
                    break
                else:
                    buf.append(code[j])
                    j += 1
            out.append("".join(buf))
            i = j + 1
        else:
            i += 1
    return out


def mask_rules(text: str) -> list[tuple[str, str, str]]:
    """(pattern, replacement, flags) of each regexp_replace, innermost first."""
    lits = sql_literals(mask_secrets_body(text))
    assert len(lits) % 3 == 0, lits
    return [tuple(lits[k:k + 3]) for k in range(0, len(lits), 3)]


def mask_model(text: str, value: str) -> str:
    for pattern, repl, flags in mask_rules(text):
        assert set(flags) <= {"g", "i"}, flags
        value = re.sub(pattern, repl, value, count=0 if "g" in flags else 1,
                       flags=re.I if "i" in flags else 0)
    return value


def mask_problems(text: str) -> list[str]:
    """Every way mask_secrets misses a secret form libpq accepts. [] means right."""
    problems = []
    rules = mask_rules(text)
    if len(rules) != 5:
        problems.append(f"expected 5 mask rules, found {len(rules)}")
    else:
        password, uri, pct = rules[0][0], rules[3][0], rules[4][0]
        if not password.lower().startswith("(password"):
            problems.append(f"first rule is not the password rule: {password!r}")
        for alt, what in ((PASSWORD_SINGLE_QUOTED, "single-quoted"), (PASSWORD_DOUBLE_QUOTED, "double-quoted"),
                          (PASSWORD_UNQUOTED, "unquoted")):
            if alt not in password:
                problems.append(f"password rule lacks the escape-aware {what} alternative")
        if uri != URI_RULE:
            problems.append(f"URI rule {uri!r} is not {URI_RULE!r} "
                            "(empty user must be allowed; '/', '?', '#' belong to the password)")
        if pct != PCT_RULE:
            problems.append(f"percent-key rule {pct!r} is not {PCT_RULE!r}")
    # The behaviour model runs whatever rules exist, so a missing rule shows
    # up as the secrets it lets through.
    for case_id, value, want, secret in MASK_CASES:
        got = mask_model(text, value)
        if secret is not None and secret.lower() in got.lower():
            problems.append(f"{case_id}: secret survives: {got!r}")
        elif got != want:
            problems.append(f"{case_id}: got {got!r}, want {want!r}")
    return problems


# Patterns as they appear in the SQL text.
MAIN_PASSWORD_SQL = r"""'(password\s*=\s*)(''[^'']*''|"[^"]*"|\S+)'"""
MAIN_URI_SQL = r"""'://([^:/@\s]+):([^@/\s]+)@'"""
BRANCH_PASSWORD_SQL = r"""'(password\s*=\s*)(''(?:[^''\\]|\\.)*''|"(?:[^"\\]|\\.)*"|(?:[^\s\\]|\\.)+)'"""
BRANCH_URI_SQL = r"""'://([^:/@\s]*):([^@\s]+)@'"""
BRANCH_PCT_SQL = r"""'([?&][^=&\s]*%[^=&\s]*=)[^&\s]*'"""
# The URI rule of the delta db-security-reviewer blocked: the password
# stopped at '/'.
SLASH_STOPPING_URI_SQL = r"""'://([^:/@\s]*):([^@/\s]+)@'"""


def quoted_values_end_cleanly(value: str, key: str) -> bool:
    """Every quoted value after `key=` is followed by whitespace or the end."""
    for m in re.finditer(rf"""{key}\s*=\s*('(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")""", value, re.I):
        end = m.end(1)
        if not (end == len(value) or value[end].isspace()):
            return False
    return True


class TestMaskSecretsEscapesAndEmptyUser:

    def test_model_inputs_are_unambiguous_between_engines(self):
        # A closing quote followed by a non-space would let PostgreSQL's
        # longest-match prefer the unquoted alternative where Python takes the
        # quoted one.
        for case_id, value, _, _ in MASK_CASES:
            for m in re.finditer(r"""password\s*=\s*('(?:[^'\\]|\\.)*'|"(?:[^"\\]|\\.)*")""", value, re.I):
                end = m.end(1)
                assert end == len(value) or value[end].isspace(), case_id
        for case_id, value, _, _ in KW_PARSE_CASES:
            assert quoted_values_end_cleanly(value, r"[A-Za-z_]+"), case_id

    def test_engine_guard_rejects_an_ambiguous_input(self):
        assert not quoted_values_end_cleanly("password='ab'cd host=x", "password")
        assert quoted_values_end_cleanly("password='ab' host=x", "password")

    def test_rules_are_read_from_the_sql(self, sql):
        rules = mask_rules(sql)
        assert [r[2] for r in rules] == ["gi", "gi", "gi", "g", "g"]
        assert rules[3] == (URI_RULE, rf"://\1:{MASK_RE_REDACTED}@", "g")
        assert rules[4] == (PCT_RULE, rf"\1{MASK_RE_REDACTED}", "g")

    def test_password_rule_has_escape_aware_alternatives(self, sql):
        password = mask_rules(sql)[0][0]
        assert PASSWORD_SINGLE_QUOTED in password
        assert PASSWORD_DOUBLE_QUOTED in password
        assert PASSWORD_UNQUOTED in password

    def test_uri_rule_allows_an_empty_user_and_any_password_char_but_at(self, sql):
        assert mask_rules(sql)[3][0] == URI_RULE

    @pytest.mark.parametrize("case_id, value, want, secret", MASK_CASES, ids=[c[0] for c in MASK_CASES])
    def test_mask_model_output(self, sql, case_id, value, want, secret):
        got = mask_model(sql, value)
        assert got == want
        if secret is not None:
            assert secret in value
            assert secret.lower() not in got.lower()

    def test_no_mask_problems(self, sql):
        assert mask_problems(sql) == []

    def test_mains_password_pattern_is_rejected(self, sql):
        assert BRANCH_PASSWORD_SQL in sql
        bad = sql.replace(BRANCH_PASSWORD_SQL, MAIN_PASSWORD_SQL, 1)
        problems = mask_problems(bad)
        assert any("escape-aware single-quoted" in p for p in problems), problems
        assert any("escape-aware double-quoted" in p for p in problems), problems
        assert any("escape-aware unquoted" in p for p in problems), problems
        assert any(p.startswith("keyword-escaped-single-quote: secret survives") for p in problems), problems
        assert any(p.startswith("escaped-double-quote: secret survives") for p in problems), problems
        assert any(p.startswith("keyword-unquoted-escaped-space: secret survives") for p in problems), problems

    def test_mains_uri_pattern_is_rejected(self, sql):
        assert BRANCH_URI_SQL in sql
        bad = sql.replace(BRANCH_URI_SQL, MAIN_URI_SQL, 1)
        problems = mask_problems(bad)
        assert any("empty user must be allowed" in p for p in problems), problems
        assert any(p.startswith("uri-empty-user: secret survives") for p in problems), problems
        assert any(p.startswith("archive-uri-empty-user: secret survives") for p in problems), problems
        assert any(p.startswith("uri-password-slash: secret survives") for p in problems), problems

    def test_escape_aware_single_quote_only_is_rejected(self, sql):
        bad = sql.replace(BRANCH_PASSWORD_SQL,
                          r"""'(password\s*=\s*)(''(?:[^''\\]|\\.)*''|"[^"]*"|(?:[^\s\\]|\\.)+)'""", 1)
        assert bad != sql
        problems = mask_problems(bad)
        assert any(p.startswith("escaped-double-quote: secret survives") for p in problems), problems

    def test_unquoted_value_without_escapes_is_rejected(self, sql):
        """The previous delta's unquoted alternative, \\S+, stops at 'abc\\'."""
        bad = sql.replace(BRANCH_PASSWORD_SQL,
                          r"""'(password\s*=\s*)(''(?:[^''\\]|\\.)*''|"(?:[^"\\]|\\.)*"|\S+)'""", 1)
        assert bad != sql
        problems = mask_problems(bad)
        assert any("escape-aware unquoted" in p for p in problems), problems
        assert any(p.startswith("keyword-unquoted-escaped-space: secret survives") for p in problems), problems

    def test_unquoted_value_escaping_whitespace_unconditionally_is_rejected(self, sql):
        """Over-consuming past an escaped backslash swallows the next keyword."""
        bad = sql.replace(BRANCH_PASSWORD_SQL,
                          r"""'(password\s*=\s*)(''(?:[^''\\]|\\.)*''|"(?:[^"\\]|\\.)*"|(?:\\\s|[^\s])+)'""", 1)
        assert bad != sql
        problems = mask_problems(bad)
        assert any(p.startswith("keyword-unquoted-escaped-backslash: got") for p in problems), problems

    def test_uri_password_stopping_at_slash_is_rejected(self, sql):
        assert BRANCH_URI_SQL in sql
        problems = mask_problems(sql.replace(BRANCH_URI_SQL, SLASH_STOPPING_URI_SQL, 1))
        assert any("belong to the password" in p for p in problems), problems
        assert any(p.startswith("uri-password-slash: secret survives") for p in problems), problems
        assert any(p.startswith("archive-uri-password-slash: secret survives") for p in problems), problems

    def test_uri_password_stopping_at_question_mark_or_hash_is_rejected(self, sql):
        problems = mask_problems(sql.replace(BRANCH_URI_SQL, r"""'://([^:/@\s]*):([^@?#\s]+)@'""", 1))
        assert any(p.startswith("uri-password-question-mark: secret survives") for p in problems), problems
        assert any(p.startswith("uri-password-hash: secret survives") for p in problems), problems

    def test_uri_user_of_at_most_one_char_is_rejected(self, sql):
        bad = sql.replace(BRANCH_URI_SQL, r"""'://([^:/@\s]?):([^@\s]+)@'""", 1)
        assert bad != sql
        problems = mask_problems(bad)
        assert any(p.startswith("uri-user-password: secret survives") for p in problems), problems

    def test_uri_replacement_restoring_the_password_is_rejected(self, sql):
        """The pattern alone is not enough: the replacement must drop group 2."""
        old = r"""'://\1:***REDACTED***@'"""
        assert old in sql
        problems = mask_problems(sql.replace(old, r"""'://\1:\2@'""", 1))
        assert any(p.startswith("uri-empty-user: secret survives") for p in problems), problems

    def test_percent_key_rule_only_after_question_mark_is_rejected(self, sql):
        assert BRANCH_PCT_SQL in sql
        problems = mask_problems(sql.replace(BRANCH_PCT_SQL, r"""'([?][^=&\s]*%[^=&\s]*=)[^&\s]*'""", 1))
        assert any("percent-key rule" in p for p in problems), problems
        assert any(p.startswith("uri-query-percent-key-after-amp: secret survives") for p in problems), problems

    def test_percent_key_rule_masking_on_value_percent_is_rejected(self, sql):
        """Keying on a '%' anywhere (not in the name) over-masks plain parameters."""
        problems = mask_problems(sql.replace(BRANCH_PCT_SQL, r"""'([?&][^=&\s]*=)([^&\s]*%[^&\s]*)'""", 1))
        assert any(p.startswith("uri-query-percent-in-value-only-untouched: got") for p in problems), problems

    def test_missing_percent_key_rule_is_rejected(self, sql):
        body = mask_secrets_body(sql)
        uri_end = body.index(r"'://\1:***REDACTED***@', 'g')") + len(r"'://\1:***REDACTED***@', 'g')")
        four = body[:uri_end] + body[body.index("\n    END;"):]
        four = four.replace("regexp_replace(\n", "", 1)
        problems = mask_problems(sql.replace(body, four, 1))
        assert "expected 5 mask rules, found 4" in problems, problems
        assert any(p.startswith("uri-query-percent-key: secret survives") for p in problems), problems
        assert any(p.startswith("uri-query-percent-key-after-amp: secret survives") for p in problems), problems

    def test_main_collector_is_rejected(self, sql):
        """Both of main's patterns at once."""
        bad = sql.replace(BRANCH_PASSWORD_SQL, MAIN_PASSWORD_SQL, 1).replace(BRANCH_URI_SQL, MAIN_URI_SQL, 1)
        leaked = {p.split(":", 1)[0] for p in mask_problems(bad) if "secret survives" in p}
        assert {"uri-empty-user", "keyword-escaped-single-quote", "archive-uri-empty-user",
                "escaped-double-quote"} <= leaked

    def test_main_mask_secrets_function_is_rejected(self, sql):
        """main's (= 03a618c's) whole mask_secrets, swapped in verbatim."""
        bad = sql.replace(mask_secrets_body(sql), MAIN_MASK_SECRETS, 1)
        assert bad != sql
        problems = mask_problems(bad)
        assert "expected 5 mask rules, found 4" in problems, problems
        leaked = {p.split(":", 1)[0] for p in problems if "secret survives" in p}
        assert {"uri-empty-user", "keyword-escaped-single-quote", "archive-uri-empty-user",
                "escaped-double-quote", "uri-password-slash", "archive-uri-password-slash",
                "keyword-unquoted-escaped-space", "uri-query-percent-key",
                "uri-query-percent-key-after-amp"} <= leaked, problems


# ---------------------------------------------------------------------------
# parse_conninfo's two regexes, read out of collect.sql and run with Python's
# re: the URI regex must split userinfo / host / path / query the way libpq
# does (userinfo ends only at '@' or '/'), and the keyword regex must consume
# each value whole (quoted with \' escapes, or unquoted with backslash escapes,
# inner quotes and '=' literal). The PL/pgSQL around them (secret keys, '%'
# keys, the '@'-means-unparsed check, mask_secrets on every value) is checked
# structurally by conninfo_problems above; the live tests run all of it on
# PostgreSQL.
#
# Engines: the URI regex has no alternation, only greedy optional groups, which
# ARE and Python resolve the same way. The keyword regex's two value
# alternatives cannot start with the same character (only the quoted one
# starts with '), so leftmost-longest and leftmost-first agree; the guard in
# TestMaskSecretsEscapesAndEmptyUser also keeps every quoted input followed by
# whitespace or the end.
# ---------------------------------------------------------------------------

URI_PARSE_SQL = r"""'^[A-Za-z]+://(?:([^@/]*)@)?([^/?#]*)(?:/([^?#]*))?(?:\?([^#]*))?'"""
KW_PARSE_SQL = r"""'([A-Za-z_]+)\s*=\s*(''(?:[^''\\]|\\.)*''|(?:[^\s''\\]|\\.)(?:[^\s\\]|\\.)*)'"""

# (id, input, secret, (userinfo, host, path, query) as regexp_match returns them)
URI_PARSE_CASES = [
    ("uri-userinfo-password",
     "postgresql://rep:SECRETURI1@db.example:5432/postgres?sslmode=require&application_name=standby1",
     "SECRETURI1", ("rep:SECRETURI1", "db.example:5432", "postgres", "sslmode=require&application_name=standby1")),
    ("uri-password-question-mark", "postgresql://rep:Sec?SECRETQM7@db/postgres",
     "SECRETQM7", ("rep:Sec?SECRETQM7", "db", "postgres", None)),
    ("uri-password-hash", "postgresql://rep:Sec#SECRETHASH8@db/postgres",
     "SECRETHASH8", ("rep:Sec#SECRETHASH8", "db", "postgres", None)),
    ("uri-empty-user", "postgresql://:SECRETNOUSER5@db.example/postgres",
     "SECRETNOUSER5", (":SECRETNOUSER5", "db.example", "postgres", None)),
    ("uri-query-sslpassword", "postgres://rep@db.example/postgres?sslpassword=SECRETSSL4&sslmode=require",
     "SECRETSSL4", ("rep", "db.example", "postgres", "sslpassword=SECRETSSL4&sslmode=require")),
    ("uri-query-percent-key", "postgresql://rep@db/postgres?pass%77ord=SECRETPCT12",
     "SECRETPCT12", ("rep", "db", "postgres", "pass%77ord=SECRETPCT12")),
    ("subscription-password-question-mark",
     "postgresql://rep:Sub?SECRETSUB15@db.example/postgres?application_name=sub1",
     "SECRETSUB15", ("rep:Sub?SECRETSUB15", "db.example", "postgres", "application_name=sub1")),
    # The '@' lands after the userinfo: parse_conninfo must answer {unparsed: true}.
    ("uri-password-slash", "postgresql://rep:pa/SECRETSLASH13@db/x",
     "SECRETSLASH13", (None, "rep:pa", "SECRETSLASH13@db/x", None)),
    ("uri-double-at", "postgresql://rep:a@SECRETDA@db/x",
     "SECRETDA", ("rep:a", "SECRETDA@db", "x", None)),
    ("uri-no-userinfo-fragment", "postgresql://db/postgres#frag",
     None, (None, "db", "postgres", None)),
    # Whitespace inside the URI password: libpq reads it, the user is "rep".
    ("uri-password-whitespace", URI_WS_PASSWORD,
     "SECRETWS16", ("rep:correct SECRETWS16 horse", "primary", "postgres", None)),
    # A password with a space in the query: only the allowlist keeps it out.
    ("uri-query-password-space", URI_QUERY_WS_PASSWORD,
     "SECRETWS17", (None, "h", "db", "password=my SECRETWS17")),
    # URI followed by a keyword pair: the path swallows the password. The
    # whitespace in the dbname must make parse_conninfo answer {unparsed: true}.
    ("uri-mixed-with-keyword-password", URI_MIXED_FORM,
     "SECRETMIX18", ("rep", "primary", "postgres password=SECRETMIX18", None)),
    # N1: the query swallows the fragments; the query rule makes it unparsed.
    ("uri-query-allowlisted-value-with-whitespace", URI_QUERY_FRAGMENT,
     "SECRETQ33", ("rep", "primary", "postgres", "sslmode=require password=correct SECRETQ33")),
]


def uri_unparsed(groups) -> bool:
    """The required rule: an '@' after the userinfo, whitespace or '=' in the
    user, host or dbname, or a query parameter with whitespace or a second
    '=' (db-security-reviewer N1), means {unparsed: true}."""
    user = (groups[0] or "").split(":", 1)[0]
    return ("@" in "".join(g or "" for g in groups[1:])
            or re.search(r"[\s=]", user + (groups[1] or "") + (groups[2] or "")) is not None
            or re.search(r"\s|=[^&]*=", groups[3] or "") is not None)

# (id, input, secret, [(key, raw value)] as regexp_matches(..., 'g') returns them)
KW_PARSE_CASES = [
    ("keyword-quoted-space-equals", "host=x user=rep password='ab cd=SECRETQ2' application_name=s1",
     "SECRETQ2", [("host", "x"), ("user", "rep"), ("password", "'ab cd=SECRETQ2'"), ("application_name", "s1")]),
    ("keyword-escaped-quote", r"host=x user=rep password='it\'s SECRETESC9' application_name=s1",
     "SECRETESC9", [("host", "x"), ("user", "rep"), ("password", r"'it\'s SECRETESC9'"),
                    ("application_name", "s1")]),
    ("keyword-unquoted-escaped-space", r"host=x user=rep password=abc\ SECRETUNQ10 application_name=s1",
     "SECRETUNQ10", [("host", "x"), ("user", "rep"), ("password", r"abc\ SECRETUNQ10"),
                     ("application_name", "s1")]),
    ("keyword-unquoted-inner-quote", "host=x user=rep password=ab'cd=SECRETAPOS11 application_name=s1",
     "SECRETAPOS11", [("host", "x"), ("user", "rep"), ("password", "ab'cd=SECRETAPOS11"),
                      ("application_name", "s1")]),
    # Same, but the text after the quote looks like an allowlisted key: a
    # parser that splits at the quote would return the secret as sslmode.
    ("keyword-unquoted-inner-quote-allowlisted-tail",
     "host=x user=rep password=ab'sslmode=SECRETAPOS31 application_name=s1",
     "SECRETAPOS31", [("host", "x"), ("user", "rep"), ("password", "ab'sslmode=SECRETAPOS31"),
                      ("application_name", "s1")]),
    ("keyword-sslpassword", "host=x user=rep sslpassword=SECRETSSL3 sslmode=verify-full",
     "SECRETSSL3", [("host", "x"), ("user", "rep"), ("sslpassword", "SECRETSSL3"), ("sslmode", "verify-full")]),
    ("keyword-options-password", "host=x user=rep options='-c app.password=SECRETOPT14'",
     "SECRETOPT14", [("host", "x"), ("user", "rep"), ("options", "'-c app.password=SECRETOPT14'")]),
    ("keyword-spaces-around-equals", "password = 'sp SECRETSP16' host=x",
     "SECRETSP16", [("password", "'sp SECRETSP16'"), ("host", "x")]),
    ("keyword-upper-case-key", "PASSWORD=SECRETUP8 host=x",
     "SECRETUP8", [("PASSWORD", "SECRETUP8"), ("host", "x")]),
    ("keyword-unquoted-escaped-backslash", r"host=x password=ab\\ user=rep",
     None, [("host", "x"), ("password", r"ab\\"), ("user", "rep")]),
    # An allowlisted key whose value carries a password: kept, but masked.
    ("keyword-application-name-password", "host=x user=rep application_name='a password=SECRETAPP19'",
     "SECRETAPP19", [("host", "x"), ("user", "rep"), ("application_name", "'a password=SECRETAPP19'")]),
]


def parse_conninfo_regexes(text: str) -> tuple[str | None, str | None]:
    """(URI regex, keyword regex) as the engine sees them, or None if absent."""
    body = parse_conninfo_body(text)
    uri = re.search(r"regexp_match\(\s*v\s*,\s*'((?:[^']|'')*)'\s*\)", body)
    kw = re.search(r"regexp_matches\(\s*v\s*,\s*'((?:[^']|'')*)'\s*,\s*'g'\s*\)", body)
    return (uri.group(1).replace("''", "'") if uri else None,
            kw.group(1).replace("''", "'") if kw else None)


def parser_regex_problems(text: str) -> list[str]:
    """Every way parse_conninfo's regexes split a conninfo wrongly. [] means right."""
    problems = []
    uri_re, kw_re = parse_conninfo_regexes(text)
    if uri_re is None:
        problems.append("no URI regexp_match(v, ...) in parse_conninfo")
    else:
        for case_id, value, secret, want in URI_PARSE_CASES:
            m = re.match(uri_re, value)
            got = m.groups() if m else None
            if got is None or len(got) != 4:
                problems.append(f"{case_id}: URI regex gives {got!r}")
                continue
            # Only the user name leaves the userinfo, and host/path are
            # returned unless the URI is unparsed ('@' after the userinfo, or
            # whitespace or '=' in user/host/dbname).
            exposed = [(got[0] or "").split(":", 1)[0]]
            if not uri_unparsed(got):
                exposed += [got[1] or "", got[2] or ""]
            if secret is not None and any(secret in e for e in exposed):
                problems.append(f"{case_id}: secret survives: {got!r}")
            elif got != want:
                problems.append(f"{case_id}: URI groups {got!r}, want {want!r}")
    if kw_re is None:
        problems.append("no keyword regexp_matches(v, ..., 'g') in parse_conninfo")
    else:
        for case_id, value, secret, want in KW_PARSE_CASES:
            got = [m.groups() for m in re.finditer(kw_re, value)]
            if any(len(g) != 2 for g in got):
                problems.append(f"{case_id}: keyword regex gives {got!r}")
                continue
            allowed = conninfo_allowed_keys(parse_conninfo_body(text)) or set()
            returned = [mask_model(text, v.strip("'")) for k, v in got
                        if k.lower() in allowed and k.lower() not in REQUIRED_SECRET_KEYS]
            if secret is not None and any(secret.lower() in v.lower() for v in returned):
                problems.append(f"{case_id}: secret survives: {got!r}")
            elif got != want:
                problems.append(f"{case_id}: keyword pairs {got!r}, want {want!r}")
    return problems


class TestParseConninfoRegexes:

    def test_regexes_are_read_from_the_sql(self, sql):
        assert parse_conninfo_regexes(sql) == (URI_PARSE_SQL[1:-1].replace("''", "'"),
                                               KW_PARSE_SQL[1:-1].replace("''", "'"))

    @pytest.mark.parametrize("case_id, value, secret, want", URI_PARSE_CASES, ids=[c[0] for c in URI_PARSE_CASES])
    def test_uri_regex_groups(self, sql, case_id, value, secret, want):
        uri_re, _ = parse_conninfo_regexes(sql)
        m = re.match(uri_re, value)
        assert m and m.groups() == want
        if secret is not None:
            assert secret in value
            user = (want[0] or "").split(":", 1)[0]
            assert secret not in user
            # The secret reaches host or path only when the URI is unparsed:
            # an '@' after the userinfo, or whitespace or '=' in user/host/dbname.
            for group in want[1:3]:
                assert secret not in (group or "") or uri_unparsed(want)

    @pytest.mark.parametrize("case_id, value, secret, want", KW_PARSE_CASES, ids=[c[0] for c in KW_PARSE_CASES])
    def test_keyword_regex_pairs(self, sql, case_id, value, secret, want):
        _, kw_re = parse_conninfo_regexes(sql)
        got = [m.groups() for m in re.finditer(kw_re, value)]
        assert got == want
        if secret is not None:
            assert secret in value
            for k, v in got:
                if k.lower() not in REQUIRED_SECRET_KEYS:
                    assert secret.lower() not in mask_model(sql, v.strip("'")).lower(), k

    def test_no_parser_regex_problems(self, sql):
        assert parser_regex_problems(sql) == []

    def test_userinfo_stopping_at_question_mark_or_hash_is_rejected(self, sql):
        assert URI_PARSE_SQL in sql
        bad = sql.replace(URI_PARSE_SQL, URI_PARSE_SQL.replace("(?:([^@/]*)@)?", "(?:([^@/?#]*)@)?", 1), 1)
        assert bad != sql
        problems = parser_regex_problems(bad)
        assert any(p.startswith("uri-password-question-mark: URI groups") for p in problems), problems
        assert any(p.startswith("uri-password-hash: URI groups") for p in problems), problems
        assert any(p.startswith("subscription-password-question-mark: URI groups") for p in problems), problems

    def test_userinfo_crossing_slash_is_rejected(self, sql):
        bad = sql.replace(URI_PARSE_SQL, URI_PARSE_SQL.replace("(?:([^@/]*)@)?", "(?:([^@]*)@)?", 1), 1)
        assert bad != sql
        problems = parser_regex_problems(bad)
        assert any(p.startswith("uri-password-slash: URI groups") for p in problems), problems

    def test_userinfo_taking_the_last_at_is_rejected(self, sql):
        """Greedy userinfo up to the LAST '@' would swallow a host-side '@'."""
        bad = sql.replace(URI_PARSE_SQL, URI_PARSE_SQL.replace("(?:([^@/]*)@)?", "(?:([^/]*)@)?", 1), 1)
        assert bad != sql
        problems = parser_regex_problems(bad)
        assert any(p.startswith("uri-double-at: URI groups") for p in problems), problems

    def test_unquoted_value_stopping_at_a_quote_is_rejected(self, sql):
        assert KW_PARSE_SQL in sql
        bad = sql.replace(KW_PARSE_SQL, r"""'([A-Za-z_]+)\s*=\s*(''(?:[^''\\]|\\.)*''|[^\s'']+)'""", 1)
        problems = parser_regex_problems(bad)
        # Since the allowlist, the split-off "cd=SECRET" is dropped (key cd is
        # not allowed), so this input shows as wrong pairs rather than a leak...
        assert any(p.startswith("keyword-unquoted-inner-quote: keyword pairs") for p in problems), problems
        # ...and the leak itself is proven where the tail is an allowlisted key.
        assert any(p.startswith("keyword-unquoted-inner-quote-allowlisted-tail: secret survives")
                   for p in problems), problems

    def test_unquoted_value_without_escapes_is_rejected(self, sql):
        bad = sql.replace(KW_PARSE_SQL, r"""'([A-Za-z_]+)\s*=\s*(''(?:[^''\\]|\\.)*''|[^\s'']\S*)'""", 1)
        problems = parser_regex_problems(bad)
        assert any(p.startswith("keyword-unquoted-escaped-space: keyword pairs") for p in problems), problems

    def test_quoted_value_without_escapes_is_rejected(self, sql):
        bad = sql.replace(KW_PARSE_SQL,
                          r"""'([A-Za-z_]+)\s*=\s*(''[^'']*''|(?:[^\s''\\]|\\.)(?:[^\s\\]|\\.)*)'""", 1)
        problems = parser_regex_problems(bad)
        assert any(p.startswith("keyword-escaped-quote: keyword pairs") for p in problems), problems

    def test_returned_values_not_masked_would_leak_application_name_password(self, sql):
        """The keyword regex keeps application_name='a password=x' whole, and
        application_name is allowlisted; only mask_secrets on the returned
        value stops the leak. With a mask that lacks the password rule, the
        parser check must see the secret. (This used options='-c
        app.password=x'; options is no longer returned at all, see below.)"""
        rules_sql = BRANCH_PASSWORD_SQL
        assert rules_sql in sql
        bad = sql.replace(rules_sql, r"""'(nomatch-password\s*=\s*)(x)'""", 1)
        problems = parser_regex_problems(bad)
        assert any(p.startswith("keyword-application-name-password: secret survives") for p in problems), problems

    def test_options_is_not_returned_even_without_a_mask(self, sql):
        """options is outside the allowlist: with no password rule at all, its
        secret still cannot leave through the parsed output."""
        bad = sql.replace(BRANCH_PASSWORD_SQL, r"""'(nomatch-password\s*=\s*)(x)'""", 1)
        problems = parser_regex_problems(bad)
        assert not any(p.startswith("keyword-options-password") for p in problems), problems
        assert parse_model(bad, "host=x user=rep options='-c app.password=SECRETOPT14'") == {"host": "x", "user": "rep"}

    def test_main_parse_conninfo_has_neither_regex(self, sql):
        bad = sql.replace(parse_conninfo_body(sql), MAIN_PARSE_CONNINFO, 1)
        assert parser_regex_problems(bad) == ["no URI regexp_match(v, ...) in parse_conninfo",
                                              "no keyword regexp_matches(v, ..., 'g') in parse_conninfo"]


# ---------------------------------------------------------------------------
# parse_conninfo end to end, as a model: collect.sql's own URI and keyword
# regexes, its allowed and secret key lists and its mask rules, with the
# required unparsed rule (uri_unparsed; conninfo_problems checks the SQL has
# it). Exact dicts, so a key that should be dropped, or a value that should be
# masked, shows up as a difference. The live tests pin the same dicts on PG17.
# ---------------------------------------------------------------------------

def conninfo_secret_keys(code: str) -> set[str]:
    m = re.search(r"secret\s+text\[\]\s*:=\s*ARRAY\[([^\]]*)\]", code)
    return set() if m is None else {s.strip().strip("'").lower() for s in m.group(1).split(",")}


def parse_model(text: str, value: str | None) -> dict | None:
    if value is None or value == "":
        return None
    body = parse_conninfo_body(text)
    uri_re, kw_re = parse_conninfo_regexes(text)
    allowed = conninfo_allowed_keys(body) or set()
    secret = conninfo_secret_keys(body)
    out: dict = {}
    if re.match(r"^postgres(ql)?://", value, re.I):
        m = re.match(uri_re, value)
        if m is None or uri_unparsed(m.groups()):
            return {"unparsed": True}
        userinfo, host, path, query = m.groups()
        if userinfo is not None and userinfo.split(":", 1)[0]:
            out["user"] = userinfo.split(":", 1)[0]
        if host:
            out["host"] = host
        if path:
            out["dbname"] = path
        for part in (query.split("&") if query else []):
            k = part.split("=", 1)[0].lower()
            if k in allowed and k not in secret and "%" not in k:
                out[k] = mask_model(text, part[part.find("=") + 1:])
        return out
    for m in re.finditer(kw_re, value):
        k = m.group(1).lower()
        if k in allowed and k not in secret:
            out[k] = mask_model(text, m.group(2).strip("'"))
    return out


# (id, conninfo, secret, exact parse_conninfo result)
PARSE_CASES = [
    ("uri-userinfo-password",
     "postgresql://rep:SECRETURI1@db.example:5432/postgres?sslmode=require&application_name=standby1",
     "SECRETURI1", {"user": "rep", "host": "db.example:5432", "dbname": "postgres",
                    "sslmode": "require", "application_name": "standby1"}),
    ("keyword-quoted-password", "host=x user=rep password='ab cd=SECRETQ2' application_name=s1",
     "SECRETQ2", {"host": "x", "user": "rep", "application_name": "s1"}),
    ("keyword-sslpassword", "host=x user=rep sslpassword=SECRETSSL3 sslmode=verify-full",
     "SECRETSSL3", {"host": "x", "user": "rep", "sslmode": "verify-full"}),
    ("uri-query-sslpassword", "postgres://rep@db.example/postgres?sslpassword=SECRETSSL4&sslmode=require",
     "SECRETSSL4", {"user": "rep", "host": "db.example", "dbname": "postgres", "sslmode": "require"}),
    ("uri-empty-user", "postgresql://:SECRETNOUSER5@db.example/postgres",
     "SECRETNOUSER5", {"host": "db.example", "dbname": "postgres"}),
    ("uri-query-percent-key", "postgresql://rep@db/postgres?pass%77ord=SECRETPCT12",
     "SECRETPCT12", {"host": "db", "user": "rep", "dbname": "postgres"}),
    ("uri-password-slash", "postgresql://rep:pa/SECRETSLASH13@db/x", "SECRETSLASH13", {"unparsed": True}),
    # options is outside the allowlist now: dropped, not masked.
    ("keyword-options-password", "host=x user=rep options='-c app.password=SECRETOPT14'",
     "SECRETOPT14", {"host": "x", "user": "rep"}),
    ("keyword-application-name-password", "host=x user=rep application_name='a password=SECRETAPP19'",
     "SECRETAPP19", {"host": "x", "user": "rep", "application_name": f"a password={MASK_RE_REDACTED}"}),
    ("unknown-keyword-dropped", "host=x user=rep x_token=SECRETUNK28 port=5433",
     "SECRETUNK28", {"host": "x", "user": "rep", "port": "5433"}),
    ("unknown-query-key-dropped", "postgresql://rep@db/postgres?x_token=SECRETUNK29&port=5433",
     "SECRETUNK29", {"user": "rep", "host": "db", "dbname": "postgres", "port": "5433"}),
    # db-security-reviewer's F2 / F3 cases.
    ("uri-password-whitespace", URI_WS_PASSWORD, "SECRETWS16",
     {"host": "primary", "user": "rep", "dbname": "postgres"}),
    # Was {"host": "h", "dbname": "db"} (the allowlist dropped the password
    # key); since N1 a query with whitespace is unparsed as a whole.
    ("uri-query-password-space", URI_QUERY_WS_PASSWORD, "SECRETWS17", {"unparsed": True}),
    ("uri-mixed-with-keyword-password", URI_MIXED_FORM, "SECRETMIX18", {"unparsed": True}),
    ("uri-host-with-equals", "postgresql://rep@a=SECRETEQ30/postgres", "SECRETEQ30", {"unparsed": True}),
    # db-security-reviewer N1: an allowlisted query value carrying fragments.
    # Before, sslmode came back as "require password=***REDACTED*** SECRETQ33".
    ("uri-query-allowlisted-value-with-whitespace", URI_QUERY_FRAGMENT, "SECRETQ33", {"unparsed": True}),
    ("uri-query-allowlisted-value-with-second-equals",
     "postgresql://rep@primary/postgres?application_name=standby1=SECRETEQ38", "SECRETEQ38",
     {"unparsed": True}),
    ("uri-query-second-equals-after-amp",
     "postgresql://rep@primary/postgres?sslmode=require&application_name=a=b=SECRETEQ40", "SECRETEQ40",
     {"unparsed": True}),
    # Well-formed queries still parse, the new allowlisted keys included.
    ("uri-query-new-allowlisted-keys",
     "postgresql://rep:SECRETNEW41@primary/postgres?require_auth=scram-sha-256&sslnegotiation=postgres"
     "&ssl_min_protocol_version=TLSv1.3", "SECRETNEW41",
     {"user": "rep", "host": "primary", "dbname": "postgres", "require_auth": "scram-sha-256",
      "sslnegotiation": "postgres", "ssl_min_protocol_version": "TLSv1.3"}),
    ("keyword-new-allowlisted-keys", ALLOWLIST_ADDITIONS_CONNINFO, "SECRETNEW42", ALLOWLIST_ADDITIONS_PARSED),
]


def parse_problems(text: str) -> list[str]:
    problems = []
    for case_id, value, secret, want in PARSE_CASES:
        got = parse_model(text, value)
        if any(k not in EXPECTED_ALLOWED_KEYS | {"unparsed"} for k in (got or {})):
            problems.append(f"{case_id}: key outside the allowlist: {sorted(got)}")
        if secret is not None and secret.lower() in json.dumps(got).lower():
            problems.append(f"{case_id}: secret survives: {got!r}")
        elif got != want:
            problems.append(f"{case_id}: got {got!r}, want {want!r}")
    return problems


class TestParseConninfoModel:

    @pytest.mark.parametrize("case_id, value, secret, want", PARSE_CASES, ids=[c[0] for c in PARSE_CASES])
    def test_parse_model_output(self, sql, case_id, value, secret, want):
        assert secret in value
        got = parse_model(sql, value)
        assert got == want
        assert secret.lower() not in json.dumps(got).lower()
        assert set(got) <= EXPECTED_ALLOWED_KEYS | {"unparsed"}

    def test_no_parse_problems(self, sql):
        assert parse_problems(sql) == []

    def test_empty_and_null_are_null(self, sql):
        assert parse_model(sql, "") is None and parse_model(sql, None) is None

    def test_without_the_allowlist_unknown_keys_leak(self, sql):
        """The previous delta: every non-secret key was returned."""
        body = parse_conninfo_body(sql)
        open_list = body.replace("IF k = ANY (allowed) AND k <> ALL (secret) AND position('%' in k) = 0 THEN",
                                 "IF k <> ALL (secret) AND position('%' in k) = 0 THEN", 1) \
                        .replace("IF k = ANY (allowed) AND k <> ALL (secret) THEN", "IF k <> ALL (secret) THEN", 1)
        assert open_list != body
        bad = sql.replace(body, open_list, 1)
        # The model reads the lists, not the guards: emulate the open list.
        allowed_decl = re.search(r"allowed text\[\] := ARRAY\[[^\]]*\]", bad).group(0)
        bad = bad.replace(allowed_decl, allowed_decl[:-1] + ",'options','x_token']", 1)
        problems = parse_problems(bad)
        assert any(p.startswith("unknown-keyword-dropped: key outside the allowlist") for p in problems), problems
        assert any(p.startswith("unknown-keyword-dropped: secret survives") for p in problems), problems
        assert any(p.startswith("unknown-query-key-dropped: secret survives") for p in problems), problems
        assert any(p.startswith("keyword-options-password: key outside the allowlist") for p in problems), problems
        # ...and conninfo_problems rejects the same file outright.
        cp = conninfo_problems(bad)
        assert any(p.startswith("emit not restricted to the allowlist") for p in cp), cp
        assert any(p.startswith("allowed list is not the reviewed allowlist") for p in cp), cp
