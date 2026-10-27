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
"""
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
HELPERS = ("mask_secrets", "sanitise_setting", "parse_conninfo", "try_jsonb", "try_reason",
           "run_checks", "sql_password_types", "sql_hba", "sql_ident", "sql_file_settings")
MASKING_HELPERS = ("mask_secrets", "sanitise_setting", "parse_conninfo")
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


def unqualified_helper_calls(text: str) -> list[str]:
    code = strip_comments(text)
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
        bad = sql.replace("THEN pg_temp.mask_secrets($2)", "THEN mask_secrets($2)", 1)
        assert bad != sql
        assert unqualified_helper_calls(bad) == ["mask_secrets"]
