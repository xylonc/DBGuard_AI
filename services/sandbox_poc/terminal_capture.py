"""Before / after-fix / after-rollback screenshots of a real terminal (VHS) in sandbox tests.

Task 2, Gate 1 (Melvin, 7 Nov 2026; decision 4 as tightened is binding):

- VHS types into a real shell on THIS computer, so nothing evidence-derived reaches it.
  The stage's read-only SQL is written INSIDE the run-owned sandbox first
  (DisposablePostgres.write_evidence_sql: constant argv, content on stdin only), and the
  tape types exactly one fixed command whose only variable is the container name:
  ``<docker> exec -i <container> psql -X -e -v ON_ERROR_STOP=1 -U dbguard_poc
  -d dbguard_sandbox -f /var/run/postgresql/dbguard-<stage>.sql``.
- The container name must fullmatch ``dbguard-poc-<32 hex>``, equal the runtime's own name
  and carry the run's label (runtime._assert_owned()). ``<docker>`` is resolved once and
  must be one of the standard system paths (DOCKER_PATHS), never a per-user path that
  would show a user name. ``<stage>`` comes from a fixed dict.
- Second layer: the typed line must match a strict allowlist and contain none of quote,
  backslash, backtick, ``$ ; | & < >``, newline or control characters; the whole tape must
  equal the fixed template line for line. Any doubt means no terminal picture, never
  typing something unchecked.
- SQL is rendered only from the fixed templates below. Names go through the reviewed
  helpers (catalog_skeleton.ident's identifier check, template_service.literal); setting
  names must match ``[a-z_][a-z0-9_.]*`` and must not be a setting the collector redacts.
  Never pg_authid, passwords, hashes, keys, certificates, DSNs or environment values.
- Raw output: the same check queries are run through runtime.sql first. The collector's
  redaction rules are applied to it; if they would change anything, the terminal (which
  cannot be redacted) is refused and the rendered picture shows the redacted text. The
  raw output and its sha256 stay in the evidence JSON and are the authority; the picture
  shows run ID, stage, target ID, UTC time and that sha256.
- VHS runs with a private, read-only HOME whose rod cache only links the existing browser,
  so go-rod can never download one during a capture; no browser means no terminal picture.
  When the recording ends or times out, VHS's process group, its descendants and anything
  working in its private folder are killed before VHS is reaped.
- A capture problem never raises into a loop, never changes PASS/FAIL and never blocks
  rollback or cleanup: every failure becomes an UNAVAILABLE shot with a reason, and the
  rendered capture (bundle_assets/visual_evidence.capture) is the fallback per stage.

Nothing here reads HERMES or model output: inputs are the runtime, a fixed stage name and
targets taken from the server-side fix unit or evidence-derived proposal.
"""
from __future__ import annotations

import base64
import functools
import hashlib
import json
import os
import re
import shutil
import signal
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

STAGES = {"before": "BEFORE", "after": "AFTER FIX", "rollback": "AFTER ROLLBACK"}
SQL_PATHS = {stage: f"/var/run/postgresql/dbguard-{stage}.sql" for stage in STAGES}

READ_ONLY_LINE = "SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY;"
SENTINEL_TEXT = "end of dbguard evidence"
SENTINEL_SHOWN = SENTINEL_TEXT.upper()  # only psql's output row is upper case, never the echo

CONTAINER_NAME = re.compile(r"dbguard-poc-[0-9a-f]{32}")
# Review N1: the typed docker path is pictured and stored, so only standard system paths are
# allowed; a per-user install (~/.docker/bin, ~/.orbstack/bin) would show the user name.
DOCKER_PATHS = ("/usr/local/bin/docker", "/opt/homebrew/bin/docker", "/usr/bin/docker")
DOCKER_PATH = re.compile(r"/[A-Za-z0-9/._-]+")  # tool folders (vhs, ttyd, ffmpeg)
SETTING_NAME = re.compile(r"[a-z_][a-z0-9_.]*")
# Everything the typed line may contain (the fixed command has no quotes at all).
TYPED_ALLOWED = re.compile(r"[A-Za-z0-9 /._=-]+")
FORBIDDEN_TYPED = frozenset("'\"`\\$;|&<>\n\r")
VHS_TIMEOUT_SECONDS = 60
MAX_SQL_BYTES = 64 * 1024

# Fixed geometry: one preset for a single fix and a taller one for a combined test.
GEOMETRY = {"single": (1400, 1100), "combined": (1400, 2000)}

TAPE_TEMPLATE = """Set Shell "bash"
Set FontSize 14
Set Width {width}
Set Height {height}
Set Padding 24
Set TypingSpeed 5ms
Hide
Type "exec env -i PATH=/usr/bin:/bin TERM=xterm-256color HISTFILE=/dev/null PS1='sandbox$ ' bash --norc --noprofile"
Enter
Type "clear"
Enter
Sleep 300ms
Show
Type "{typed}"
Enter
Wait+Screen@45s /{sentinel}/
Wait+Line@10s /sandbox/
Sleep 500ms
Screenshot shot.png
Sleep 500ms
"""

TYPED_TEMPLATE = ("{docker} exec -i {container} psql -X -e -v ON_ERROR_STOP=1 -U dbguard_poc "
                  "-d dbguard_sandbox -f {path}")


class CaptureRefused(Exception):
    """A safety check refused this terminal picture; the message is a fixed reason."""


# ---------------------------------------------------------------------------
# Mode and tools
# ---------------------------------------------------------------------------

def screenshot_mode() -> str:
    """``terminal`` only when DBGUARD_SCREENSHOTS=true and DBGUARD_SCREENSHOT_MODE=terminal."""
    if os.environ.get("DBGUARD_SCREENSHOTS") != "true":
        return "disabled"
    return "terminal" if os.environ.get("DBGUARD_SCREENSHOT_MODE") == "terminal" else "rendered"


def enabled() -> bool:
    return screenshot_mode() == "terminal"


_VERSION_TEXT = re.compile(r"[ -~]{1,120}")


def _version(path: str | None, flag: str) -> str | None:
    if not path:
        return None
    try:
        out = subprocess.run([path, flag], capture_output=True, text=True, timeout=10,
                             env={"PATH": "/usr/bin:/bin"})
    except (OSError, subprocess.SubprocessError):
        return None
    line = ((out.stdout or out.stderr or "").strip().splitlines() or [""])[0].strip()
    return line if out.returncode == 0 and _VERSION_TEXT.fullmatch(line) else None


def tools() -> dict:
    """Installed versions of vhs, ttyd and ffmpeg, and the browser VHS will use (its path
    shown with ~ for the home folder); None when missing or unreadable."""
    return {"vhs": _version(shutil.which("vhs"), "--version"),
            "ttyd": _version(shutil.which("ttyd"), "--version"),
            "ffmpeg": _version(shutil.which("ffmpeg"), "-version"),
            "browser": browser_info()}


@functools.lru_cache(maxsize=1)
def docker_path() -> str:
    """The docker CLI, resolved once; refused unless it is one of the standard system paths."""
    path = shutil.which("docker")
    if path not in DOCKER_PATHS:
        raise CaptureRefused("The docker CLI is not at a standard path (" + ", ".join(DOCKER_PATHS)
                             + "); a per-user path could show the user name, so no terminal picture")
    return path


# ---------------------------------------------------------------------------
# The browser VHS uses (review N3): never downloaded during a capture
# ---------------------------------------------------------------------------

# go-rod's launcher.LookPath() candidates, checked first by VHS; else rod's own cache.
SYSTEM_BROWSERS = (
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Chromium.app/Contents/MacOS/Chromium",
    "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
    "/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary",
    "/usr/bin/google-chrome-stable", "/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser",
    "/usr/bin/microsoft-edge", "/snap/bin/chromium",
)
ROD_EXECUTABLES = ("Chromium.app/Contents/MacOS/Chromium", "chrome-linux/chrome", "chrome")
ROD_REVISION = re.compile(r"chromium-[0-9]{1,12}")
BROWSER_SETUP = ("The terminal browser is not set up: VHS needs its Chromium in ~/.cache/rod/browser (or a "
                 "system Chrome/Chromium) and DBGuard never lets it download one during a capture. Set it up "
                 "once while online by running VHS on any small tape (for example `vhs` with a tape that only "
                 "types `echo ok`), then retry")


def _rod_root() -> Path:
    return Path.home() / ".cache" / "rod" / "browser"


def _rod_executable(folder: Path) -> Path | None:
    for rel in ROD_EXECUTABLES:
        candidate = folder / rel
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return candidate
    return None


def terminal_browser() -> dict | None:
    """The browser VHS will start without downloading: a system browser, else rod's cache."""
    for path in SYSTEM_BROWSERS:
        if os.path.isfile(path) and os.access(path, os.X_OK):
            return {"source": "system", "executable": path, "revisions": []}
    root = _rod_root()
    try:
        folders = sorted((d for d in root.iterdir()
                          if ROD_REVISION.fullmatch(d.name) and d.is_dir() and not d.is_symlink()
                          and _rod_executable(d)), key=lambda d: int(d.name.split("-")[1]))
    except OSError:
        return None
    if not folders:
        return None
    return {"source": "rod-cache", "executable": str(_rod_executable(folders[-1])),
            "revisions": [d.name for d in folders], "root": str(root)}


def _display_path(path: str) -> str:
    """A path for evidence: the home folder (which holds the user name) shown as ~."""
    home = str(Path.home())
    return "~" + path[len(home):] if path.startswith(home + "/") else path


@functools.lru_cache(maxsize=8)
def _browser_version(executable: str) -> str | None:
    return _version(executable, "--version")


def browser_info() -> dict | None:
    browser = terminal_browser()
    if browser is None:
        return None
    return {"source": browser["source"], "path": _display_path(browser["executable"]),
            "version": _browser_version(browser["executable"])}


# ---------------------------------------------------------------------------
# Targets and fixed SQL templates
# ---------------------------------------------------------------------------

def setting_targets(names) -> dict:
    return {"settings": list(dict.fromkeys(names)), "objects": []}


def object_targets(proposals) -> dict:
    return {"settings": [], "objects": [p for p in proposals]}


def merge_targets(*targets) -> dict:
    return {"settings": list(dict.fromkeys(n for t in targets for n in t["settings"])),
            "objects": [o for t in targets for o in t["objects"]]}


def _lit(value) -> str:
    """A reviewed SQL string literal for an evidence name.

    catalog_skeleton.ident() applies the identifier check every fix template uses (no
    NUL, control or invisible characters, at most 63 bytes); template_service.literal
    doubles quotes. A backslash is refused outright, so psql never sees one.
    """
    from app.services.template_service import literal
    from .catalog_skeleton import ident
    from .shared import ContractError
    if not isinstance(value, str) or "\\" in value:
        raise CaptureRefused("An object name cannot be shown safely in a terminal picture")
    try:
        ident(value)
    except ContractError:
        raise CaptureRefused("An object name cannot be shown safely in a terminal picture") from None
    return "'" + literal(value) + "'"


def _setting_name(name) -> str:
    from app.services.spec_engine.redaction import collector_redacts
    if not isinstance(name, str) or not SETTING_NAME.fullmatch(name):
        raise CaptureRefused("Unsupported setting name")
    if collector_redacts(name):
        raise CaptureRefused("The collector redacts this setting's value; it is never shown")
    return name


ROLE_COLUMNS = ("rolname, rolsuper, rolcreaterole, rolcreatedb, rolreplication, rolbypassrls, "
                "rolcanlogin, rolconnlimit")


def _setting_queries(name: str, defined: bool) -> list[tuple[str, str]]:
    name = _setting_name(name)
    shown = (f"SHOW {name};" if defined else
             f"SELECT pg_catalog.current_setting({_lit(name)}, true) AS \"{name}\";")
    return [(f"Effective value of {name}", shown),
            (f"Value and source of {name}",
             f"SELECT name, setting, source FROM pg_catalog.pg_settings WHERE name = {_lit(name)};")]


def _object_queries(proposal: dict) -> list[tuple[str, str]]:
    from .catalog_skeleton import FUNCTION_FIX_TYPES, ROLE_FIX_TYPES, TABLE_FIX_TYPES
    if not isinstance(proposal, dict) or not isinstance(proposal.get("target"), dict):
        raise CaptureRefused("Object fix target is malformed")
    fix_type, target = proposal.get("fix_type"), proposal["target"]
    if fix_type in ROLE_FIX_TYPES:
        role = _lit(target.get("role"))
        return [("Role attributes", f"SELECT {ROLE_COLUMNS} FROM pg_catalog.pg_roles WHERE rolname = {role};")]
    if fix_type in FUNCTION_FIX_TYPES:
        args = target.get("identity_args")
        args_lit = "''" if args == "" else _lit(args)
        return [("Function security and EXECUTE privileges",
                 "SELECT n.nspname AS schema_name, p.proname AS function_name, "
                 "pg_catalog.pg_get_function_identity_arguments(p.oid) AS identity_args, p.prosecdef, p.proacl "
                 "FROM pg_catalog.pg_proc p JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace "
                 f"WHERE n.nspname = {_lit(target.get('schema'))} AND p.proname = {_lit(target.get('name'))} "
                 f"AND pg_catalog.pg_get_function_identity_arguments(p.oid) = {args_lit};")]
    if fix_type in TABLE_FIX_TYPES:
        grantee = target.get("grantee")
        who = ("0" if grantee == "PUBLIC" else
               f"(SELECT oid FROM pg_catalog.pg_roles WHERE rolname = {_lit(grantee)})")
        return [("Table privileges granted to this grantee",
                 "SELECT n.nspname AS schema_name, c.relname AS table_name, "
                 "CASE WHEN a.grantee = 0 THEN 'PUBLIC' ELSE pg_catalog.pg_get_userbyid(a.grantee) END AS grantee, "
                 "a.privilege_type, a.is_grantable "
                 "FROM pg_catalog.pg_class c JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace "
                 "CROSS JOIN LATERAL pg_catalog.aclexplode(c.relacl) a "
                 f"WHERE n.nspname = {_lit(target.get('schema'))} AND c.relname = {_lit(target.get('table'))} "
                 f"AND a.grantee = {who} ORDER BY a.privilege_type;")]
    raise CaptureRefused("Unsupported object fix type")


def _identity_query(run_id: str) -> tuple[str, str]:
    if not re.fullmatch(r"[0-9a-f]{32}", run_id or ""):
        raise CaptureRefused("Unexpected sandbox run ID")
    return ("Database identity",
            "SELECT current_database() AS database, pg_catalog.current_setting('server_version') AS server_version, "
            f"'{run_id}' AS run_id;")


def check_queries(runtime, targets: dict) -> list[tuple[str, str]]:
    """(title, sql) for one stage: identity, then each setting, then each object."""
    queries = [_identity_query(runtime.run_id)]
    for name in targets.get("settings", []):
        name = _setting_name(name)
        # SHOW errors on a custom setting that is not defined (pgaudit.log before 3.2's fix).
        defined = runtime.sql(f"{READ_ONLY_LINE}\nSELECT pg_catalog.current_setting({_lit(name)}, true) IS NOT NULL;")
        queries += _setting_queries(name, defined.strip() == "t")
    for proposal in targets.get("objects", []):
        queries += _object_queries(proposal)
    return queries


def stamp_query(stage: str, runtime, captured_at: str, raw_sha: str) -> str:
    if (stage not in STAGES or not re.fullmatch(r"[0-9a-f]{64}", raw_sha)
            or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", captured_at)
            or not CONTAINER_NAME.fullmatch(runtime.name)):
        raise CaptureRefused("Evidence stamp values are malformed")
    rows = (("stage", STAGES[stage]), ("target_id", runtime.name), ("captured_utc", captured_at),
            ("raw_output_sha256", raw_sha))
    values = ", ".join(f"('{k}', '{v}')" for k, v in rows)
    return f"SELECT item, value FROM (VALUES {values}) AS dbguard_evidence(item, value);"


def evidence_sql(stamp: str, queries: list[tuple[str, str]]) -> str:
    body = [READ_ONLY_LINE, "SET standard_conforming_strings = on;", stamp, *[q for _, q in queries],
            f"SELECT pg_catalog.upper('{SENTINEL_TEXT}') AS status;"]
    sql = "\n".join(body) + "\n"
    check_sql(sql)
    return sql


_SQL_FORBIDDEN = re.compile(r"[\\\x00-\x09\x0b-\x1f\x7f]")
_SQL_NEVER = re.compile(r"\b(?:pg_authid|rolpassword|pg_shadow|pg_user_mappings?|pg_read_(?:binary_)?file|"
                        r"pg_ls_\w+|pg_stat_file|lo_\w+|copy|ssl_key_file|pg_hba_file_rules|"
                        # review N4c: nothing that changes configuration, sessions or read-only mode
                        r"pg_reload_conf|set_config|pg_terminate_backend|pg_cancel_backend|"
                        r"default_transaction_read_only|"
                        # re-review: unicode escapes and SQL-as-text / OID-cast routes
                        r"uescape|\w*to_xml\w*|xmlschema|regclass|regproc\w*)\b|\bread\s+write\b", re.I)
_FIXED_SET = "SET standard_conforming_strings = on"


def _sql_statements(sql: str) -> list[str]:
    """The statements of the file with every '...' literal emptied to ''.

    Fail closed: an unterminated quote, a comment, a dollar sign outside a literal
    (dollar quoting would hide text from the checks; review N4a) or text after the last
    semicolon is refused. Double-quoted identifiers are kept (and checked) as text."""
    statements, current, i, n = [], [], 0, len(sql)
    while i < n:
        ch = sql[i]
        if ch in "'\"":
            j = i + 1
            while True:
                k = sql.find(ch, j)
                if k < 0:
                    raise CaptureRefused("The evidence SQL has an unterminated quote")
                if sql[k + 1:k + 2] == ch:
                    j = k + 2
                    continue
                break
            current.append("''" if ch == "'" else sql[i:k + 1])
            i = k + 1
            continue
        if ch == "$":
            raise CaptureRefused("The evidence SQL has a dollar sign outside a string literal")
        if ch == "&":  # re-review: U&"..." unicode-escaped identifiers (and & operators)
            raise CaptureRefused("The evidence SQL has an ampersand outside a string literal")
        if sql.startswith("--", i) or sql.startswith("/*", i):
            raise CaptureRefused("The evidence SQL contains a comment")
        if ch == ";":
            statements.append("".join(current).strip())
            current = []
        else:
            current.append(ch)
        i += 1
    if "".join(current).strip():
        raise CaptureRefused("The evidence SQL has text after its last statement")
    return statements


def check_sql(sql: str) -> None:
    """Second look at the rendered file before it is written into the sandbox.

    Read-only first statement; then only the fixed SET, SELECT or SHOW statements (review
    N4b); no backslash or control characters; no dollar quoting or comments; no
    secret-bearing catalog, file function or configuration/session-changing call outside
    literals; at most 64 KiB."""
    if (not isinstance(sql, str) or not sql.startswith(READ_ONLY_LINE + "\n")
            or len(sql.encode("utf-8")) > MAX_SQL_BYTES or _SQL_FORBIDDEN.search(sql)):
        raise CaptureRefused("The evidence SQL is outside the reviewed template")
    statements = _sql_statements(sql)
    if not statements or statements[0] + ";" != READ_ONLY_LINE:
        raise CaptureRefused("The evidence SQL does not start read-only")
    for statement in statements[1:]:
        if statement != _FIXED_SET and not statement.startswith(("SELECT ", "SHOW ")):
            raise CaptureRefused("The evidence SQL has a statement outside the reviewed template")
    if _SQL_NEVER.search("\n".join(statements)):
        raise CaptureRefused("The evidence SQL names a secret-bearing catalog, a file function or a "
                             "configuration or session change")


# ---------------------------------------------------------------------------
# Redaction (collector rules)
# ---------------------------------------------------------------------------

# Python port of collector/collect.sql pg_temp.mask_secrets (same patterns, same order).
_MASKS = (
    (re.compile(r"(password\s*=\s*)('(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"|(?:[^\s\\]|\\.)+)", re.I), r"\1***REDACTED***"),
    (re.compile(r"(passfile\s*=\s*)(\S+)", re.I), r"\1***REDACTED***"),
    (re.compile(r"(--password[= ])(\S+)", re.I), r"\1***REDACTED***"),
    (re.compile(r"://([^:/@\s]*):([^@\s]+)@"), r"://\1:***REDACTED***@"),
    (re.compile(r"([?&][^=&\s]*%[^=&\s]*=)[^&\s]*"), r"\1***REDACTED***"),
)


def redact(text: str) -> str:
    for pattern, replacement in _MASKS:
        text = pattern.sub(replacement, text)
    return text


def raw_output(runtime, queries) -> tuple[list[dict], bool]:
    """Each check run in a fresh read-only session, redacted with the collector's rules."""
    out, changed = [], False
    for title, sql in queries:
        text = runtime.sql(READ_ONLY_LINE + "\n" + sql)
        masked = redact(text)
        changed = changed or masked != text
        out.append({"title": title, "query": sql, "output": masked})
    return out, changed


def _digest(raw: list[dict]) -> str:
    return hashlib.sha256(json.dumps(raw, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


# ---------------------------------------------------------------------------
# Tape builder (the only place that produces text typed into the host shell)
# ---------------------------------------------------------------------------

def check_typed(line: str) -> None:
    if (not isinstance(line, str) or not TYPED_ALLOWED.fullmatch(line)
            or any(ch in FORBIDDEN_TYPED or ord(ch) < 32 or ord(ch) == 127 for ch in line)):
        raise CaptureRefused("The typed command contains a character outside the fixed template")


def typed_command(runtime, stage: str) -> str:
    from .runtime import DisposablePostgres
    if not isinstance(runtime, DisposablePostgres):
        raise CaptureRefused("Not a disposable sandbox runtime")
    if stage not in SQL_PATHS:
        raise CaptureRefused("Unknown evidence stage")
    name = runtime.name
    if not isinstance(name, str) or not CONTAINER_NAME.fullmatch(name) or name != f"dbguard-poc-{runtime.run_id}":
        raise CaptureRefused("The container name is not this run's sandbox")
    runtime._assert_owned()  # started by this session and carrying this run's label
    line = TYPED_TEMPLATE.format(docker=docker_path(), container=name, path=SQL_PATHS[stage])
    check_typed(line)
    return line


def build_tape(typed: str, geometry: str = "single") -> str:
    """The tape text: the fixed template with the checked typed command and a fixed geometry."""
    check_typed(typed)
    width, height = GEOMETRY[geometry]
    tape = TAPE_TEMPLATE.format(width=width, height=height, typed=typed, sentinel=SENTINEL_SHOWN)
    check_tape(tape, typed)
    return tape


def check_tape(tape: str, typed: str) -> None:
    """The tape equals the fixed template line for line; only the one Type line varies."""
    if any((ord(ch) < 32 and ch != "\n") or ord(ch) == 127 or ord(ch) > 126 for ch in tape):
        raise CaptureRefused("The tape contains a control or non-ASCII character")
    expected = [TAPE_TEMPLATE.format(width=w, height=h, typed="\0", sentinel=SENTINEL_SHOWN).splitlines()
                for w, h in GEOMETRY.values()]
    lines = tape.splitlines()
    for template_lines in expected:
        if len(lines) == len(template_lines) and all(
                line == want or (want == 'Type "\0"' and line == f'Type "{typed}"')
                for line, want in zip(lines, template_lines)):
            if sum(line.startswith("Type ") for line in lines) == 3:
                return
    raise CaptureRefused("The tape differs from the fixed template")


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

def _run_vhs(tape: str) -> bytes:
    vhs = shutil.which("vhs")
    if not vhs:
        raise CaptureRefused("VHS is not installed")
    for tool in ("ttyd", "ffmpeg"):
        if not shutil.which(tool):
            raise CaptureRefused(f"{tool} is not installed")
    dirs = []
    for tool in ("vhs", "ttyd", "ffmpeg"):
        folder = os.path.dirname(shutil.which(tool))
        if not DOCKER_PATH.fullmatch(folder):
            raise CaptureRefused("A capture tool path contains unexpected characters")
        dirs.append(folder)
    browser = terminal_browser()
    if browser is None:
        raise CaptureRefused(BROWSER_SETUP)
    workdir = tempfile.mkdtemp(prefix="dbguard-vhs-")
    try:
        os.chmod(workdir, 0o700)
        (Path(workdir) / "stage.tape").write_text(tape)
        home = _browser_home(workdir, browser)
        # Minimal environment: the tools' folders, a private read-only HOME whose rod cache
        # holds only links to the existing browser (so nothing can be downloaded into it),
        # and a private TMPDIR so the browser profile is deleted with this folder.
        env = {"PATH": ":".join(dict.fromkeys(dirs + ["/usr/bin", "/bin"])), "HOME": home, "TMPDIR": workdir}
        process = subprocess.Popen([vhs, "stage.tape"], cwd=workdir, env=env, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                   start_new_session=True)
        try:
            finished = _wait_unreaped(process, VHS_TIMEOUT_SECONDS)
        finally:
            # Review N2: VHS is still running or an unreaped zombie here, so its process-group
            # ID cannot have been reused; ttyd, the browser and the recorded shell are killed.
            _stop_recording(process, workdir)
            code = None
            try:
                code = process.wait(timeout=10)  # reaped only now
            except subprocess.SubprocessError:
                pass
        if not finished:
            raise CaptureRefused(f"VHS did not finish within {VHS_TIMEOUT_SECONDS} seconds")
        if code != 0:
            raise CaptureRefused("VHS failed: the evidence query did not finish, or the terminal or its "
                                 "browser did not start")
        shot = Path(workdir) / "shot.png"
        if not shot.is_file():
            raise CaptureRefused("VHS finished without writing the screenshot")
        png = shot.read_bytes()
        if not png.startswith(b"\x89PNG\r\n\x1a\n"):
            raise CaptureRefused("VHS wrote something that is not a PNG")
        return png
    finally:
        # Re-review: restore the private HOME's permissions from its fixed paths (not from
        # _browser_home's return value), so a failure part-way through still cleans up.
        for folder in _home_folders(workdir):
            try:
                if os.path.isdir(folder) and not os.path.islink(folder):
                    os.chmod(folder, 0o700)
            except OSError:
                pass
        shutil.rmtree(workdir, ignore_errors=True)


def _home_folders(workdir: str) -> list[str]:
    """The private HOME's folders, innermost first (fixed paths under this run's folder)."""
    home = Path(workdir) / "home"
    rod = home / ".cache" / "rod" / "browser"
    return [str(rod), str(rod.parent), str(rod.parent.parent), str(home)]


def _browser_home(workdir: str, browser: dict) -> str:
    """A private HOME for VHS. go-rod looks for its browser in $HOME/.cache/rod/browser and
    downloads one there when its revision is missing; here that folder only holds links to
    the existing revisions and is made read-only, so a download can never be stored.
    The caller restores permissions and removes the folder, also after a failure here."""
    folders = _home_folders(workdir)
    rod = Path(folders[0])
    rod.mkdir(parents=True, mode=0o700)
    if browser.get("source") == "rod-cache":
        root = Path(browser["root"])
        for name in browser["revisions"]:
            if ROD_REVISION.fullmatch(name):
                (rod / name).symlink_to(root / name, target_is_directory=True)
    for folder in folders:
        os.chmod(folder, 0o500)
    return folders[-1]


def _wait_unreaped(process, timeout: float) -> bool:
    """Wait for VHS to exit without reaping it (WNOWAIT), so its PID stays reserved."""
    deadline = time.monotonic() + timeout
    while True:
        if os.waitid(os.P_PID, process.pid, os.WEXITED | os.WNOWAIT | os.WNOHANG) is not None:
            return True
        if time.monotonic() >= deadline:
            return False
        time.sleep(0.1)


def _stop_recording(process, workdir: str) -> None:
    """SIGKILL everything this recording started, found safely: VHS's process group (VHS
    is not reaped yet), its descendants, and any process of this user whose command line
    or working folder is inside this run's private folder (ttyd and the recorded shell run
    there; the browser's profile is there). Never this process or its ancestors."""
    try:
        targets = _recording_processes(process.pid, workdir)
    except Exception:
        targets = set()
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        pass
    for pid in sorted(targets):
        try:
            os.kill(pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):
            pass


def _recording_processes(leader: int, workdir: str) -> set[int]:
    markers = {workdir, os.path.realpath(workdir)}
    uid = os.getuid()
    out = subprocess.run(["/bin/ps", "-ww", "-axo", "pid=,ppid=,pgid=,uid=,command="], capture_output=True,
                         text=True, timeout=10, env={"PATH": "/usr/bin:/bin"}).stdout
    rows = {}
    for line in out.splitlines():
        parts = line.split(None, 4)
        if len(parts) >= 4 and all(x.lstrip("-").isdigit() for x in parts[:4]) and int(parts[3]) == uid:
            rows[int(parts[0])] = (int(parts[1]), int(parts[2]), parts[4] if len(parts) == 5 else "")
    children = {}
    for pid, (ppid, _, _) in rows.items():
        children.setdefault(ppid, []).append(pid)
    found, stack = set(), [leader]
    while stack:
        for child in children.get(stack.pop(), []):
            if child not in found:
                found.add(child)
                stack.append(child)
    found |= {pid for pid, (_, pgid, command) in rows.items()
              if pgid == leader or any(m in command for m in markers)}
    try:  # re-review: a lsof failure or timeout keeps the ps-derived targets above
        found |= _processes_working_in(markers, uid)
    except Exception:
        pass
    keep, pid = {os.getpid()}, os.getpid()
    while pid in rows and pid > 1:  # this process and its ancestors are never targets
        pid = rows[pid][0]
        keep.add(pid)
    return {pid for pid in found if pid not in keep and pid != leader and pid > 1}


def _processes_working_in(markers: set[str], uid: int) -> set[int]:
    lsof = next((p for p in ("/usr/sbin/lsof", "/usr/bin/lsof", "/sbin/lsof") if os.path.exists(p)), None)
    if lsof is None:
        return set()
    out = subprocess.run([lsof, "-a", "-d", "cwd", "-u", str(uid), "-Fpn"], capture_output=True, text=True,
                         timeout=10, env={"PATH": "/usr/bin:/bin"}).stdout
    found, pid = set(), None
    for line in out.splitlines():
        if line.startswith("p") and line[1:].isdigit():
            pid = int(line[1:])
        elif line.startswith("n") and pid is not None and any(
                line[1:] == m or line[1:].startswith(m + "/") for m in markers):
            found.add(pid)
    return found


# ---------------------------------------------------------------------------
# One stage
# ---------------------------------------------------------------------------

def _unavailable(mode: str, reason: str, base: dict) -> dict:
    return {"status": "UNAVAILABLE", "mode": mode, "format": "png", "reason": reason, **base}


def _rendered(stage: str, runtime, raw: list[dict], base: dict, reason: str) -> dict:
    from .bundle_assets.visual_evidence import capture
    evidence = {"scope": "DISPOSABLE SANDBOX · " + STAGES[stage], "run_id": runtime.run_id,
                "target_id": runtime.name, "stage": STAGES[stage], "captured_at": base["captured_at"],
                "raw_output_sha256": base["raw_output_sha256"], "queries": raw}
    try:
        shot = capture(evidence)
    except Exception:
        return _unavailable("rendered", reason + " Rendered capture also failed (browser unavailable).", base)
    return {"status": "CAPTURED", "mode": "rendered", "format": "png", "sha256": shot["sha256"],
            "png_base64": shot["png_base64"], "reason": reason, **base}


def capture_stage(runtime, stage: str, targets: dict, geometry: str = "single") -> dict:
    """One stage's picture: terminal (VHS) first, else rendered. Never raises."""
    try:
        return _capture_stage(runtime, stage, targets, geometry)
    except Exception:
        return {"status": "UNAVAILABLE", "mode": "terminal", "format": "png",
                "reason": "Screenshot capture failed; query evidence retained."}


def _capture_stage(runtime, stage, targets, geometry) -> dict:
    known = isinstance(stage, str) and stage in STAGES
    base = {"stage": stage if known else None, "stage_label": STAGES[stage] if known else None,
            "run_id": getattr(runtime, "run_id", None), "target_id": getattr(runtime, "name", None),
            "tools": {"vhs": None, "ttyd": None, "ffmpeg": None, "browser": None}}
    try:
        base["tools"] = tools()
        from .runtime import DisposablePostgres
        if not known or not isinstance(runtime, DisposablePostgres):
            return _unavailable("terminal", "Not a disposable sandbox stage; nothing was captured.", base)
        if not isinstance(targets, dict):
            raise CaptureRefused("The fix's settings and objects could not be listed")
        queries = check_queries(runtime, targets)
        raw, redacted = raw_output(runtime, queries)
        captured_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        base.update(captured_at=captured_at, raw_output=raw, raw_output_sha256=_digest(raw), redacted=redacted)
        sql = evidence_sql(stamp_query(stage, runtime, captured_at, base["raw_output_sha256"]), queries)
        base["sql"] = sql
    except Exception as exc:
        reason = str(exc) if isinstance(exc, CaptureRefused) else "The stage's evidence queries could not be run"
        return _unavailable("terminal", reason + "; no picture was taken.", base)
    try:
        if redacted:
            raise CaptureRefused("The output matched the collector's redaction rules; a terminal cannot be redacted")
        # Review N5: psql -e echoes every query, WHERE literals included.
        if redact(sql) != sql:
            raise CaptureRefused("The query text matched the collector's redaction rules; psql would echo it")
        if base["tools"]["vhs"] is None or base["tools"]["ttyd"] is None or base["tools"]["ffmpeg"] is None:
            raise CaptureRefused("VHS, ttyd or ffmpeg is not installed")
        typed = typed_command(runtime, stage)
        tape = build_tape(typed, geometry)
        runtime.write_evidence_sql(stage, sql)
        typed = typed_command(runtime, stage)  # ownership re-checked right before recording
        png = _run_vhs(tape)
    except Exception as exc:
        reason = str(exc) if isinstance(exc, CaptureRefused) else "Terminal capture failed"
        return _rendered(stage, runtime, base["raw_output"], base,
                         f"Terminal capture UNAVAILABLE: {reason}. Rendered capture of the same queries used instead.")
    return {"status": "CAPTURED", "mode": "terminal", "format": "png",
            "sha256": hashlib.sha256(png).hexdigest(), "png_base64": base64.b64encode(png).decode(),
            "typed_command": typed, **base}


# ---------------------------------------------------------------------------
# Loop wiring helpers (all no-ops unless terminal mode is on; none of them raise)
# ---------------------------------------------------------------------------

def begin(record: dict) -> None:
    if enabled():
        record["terminal_evidence"] = {"mode": "terminal", "stages": {}}


def stage(record: dict, runtime, name: str, targets: dict, geometry: str = "single") -> None:
    evidence = record.get("terminal_evidence")
    if not isinstance(evidence, dict):
        return
    try:
        evidence["stages"][name] = capture_stage(runtime, name, targets, geometry)
    except Exception:
        evidence["stages"][name] = {"status": "UNAVAILABLE", "mode": "terminal", "format": "png",
                                    "reason": "Screenshot capture failed; query evidence retained."}


def finish(record: dict) -> None:
    """Every stage has a shot: a stage the attempt never reached is UNAVAILABLE."""
    evidence = record.get("terminal_evidence")
    if not isinstance(evidence, dict):
        return
    try:
        for name in STAGES:
            evidence["stages"].setdefault(name, {
                "status": "UNAVAILABLE", "mode": "terminal", "format": "png", "stage": name,
                "stage_label": STAGES[name],
                "reason": "The test did not reach this stage, so no picture was taken."})
    except Exception:
        pass
