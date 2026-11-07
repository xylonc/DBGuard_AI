"""Task 2 terminal (VHS) screenshots: hostile inputs, SQL guard, redaction, the VHS runner
and the shot contract (Gate 1, decision 4 as tightened).

No Docker, VHS, browser or model: the runtime is a DisposablePostgres whose docker and
psql calls are replaced by recorders, ``_run_vhs`` / ``subprocess.Popen`` are recorders
and the rendered fallback is a fake. Every refusal test checks that nothing was typed,
no tape was built, no SQL file was written and no VHS process was started.
"""
import base64
import hashlib
import json
import os
import re
import signal
import subprocess
import uuid
from pathlib import Path

import pytest

from services.sandbox_poc import runtime as runtime_module
from services.sandbox_poc import terminal_capture as tc
from services.sandbox_poc.bundle_assets import visual_evidence
from services.sandbox_poc.runtime import DisposablePostgres
from services.sandbox_poc.shared import ContractError

DOCKER = "/usr/local/bin/docker"
TOOL_DIR = "/opt/homebrew/bin"
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00\x00\x00\rIHDR" + b"terminal-picture"
RENDERED_PNG = b"\x89PNG\r\n\x1a\n" + b"rendered-picture"
TOOLS = {"vhs": "vhs version 0.12.1", "ttyd": "ttyd version 1.7.7", "ffmpeg": "ffmpeg version 9.0.2"}
TYPED_RE = re.compile(r"[A-Za-z0-9 /._=-]+")
LITERALS = re.compile(r"'(?:[^']|'')*'")
REAL_RUN_VHS = tc._run_vhs  # captured before any fixture replaces it


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def expected_typed(runtime, stage):
    return (f"{DOCKER} exec -i {runtime.name} psql -X -e -v ON_ERROR_STOP=1 -U dbguard_poc "
            f"-d dbguard_sandbox -f /var/run/postgresql/dbguard-{stage}.sql")


class Rig:
    """Recorders for everything that could reach the host shell, the sandbox or a browser."""

    def __init__(self):
        self.tapes, self.writes, self.popen, self.rendered, self.sql_seen = [], [], [], [], []
        self.outputs = {}          # substring of a check query -> its raw output
        self.rendered_fails = False


@pytest.fixture
def rig(monkeypatch):
    rig = Rig()
    paths = {"docker": DOCKER, "vhs": f"{TOOL_DIR}/vhs", "ttyd": f"{TOOL_DIR}/ttyd", "ffmpeg": f"{TOOL_DIR}/ffmpeg"}
    rig.paths = paths
    monkeypatch.setattr(tc.shutil, "which", lambda name: paths.get(name))
    tc.docker_path.cache_clear()
    monkeypatch.setattr(tc, "tools", lambda: dict(TOOLS))

    def run_vhs(tape):
        rig.tapes.append(tape)
        return PNG
    monkeypatch.setattr(tc, "_run_vhs", run_vhs)

    def popen(*args, **kwargs):
        rig.popen.append((args, kwargs))
        raise AssertionError("VHS must not be started")
    monkeypatch.setattr(tc.subprocess, "Popen", popen)
    monkeypatch.setattr(runtime_module, "docker",
                        lambda *args, stdin=None, **kw: rig.writes.append((args, stdin)) or "")

    def rendered(evidence):
        rig.rendered.append(evidence)
        if rig.rendered_fails:
            raise RuntimeError("Evidence browser unavailable; install playwright chromium")
        return {"status": "CAPTURED", "format": "png", "sha256": sha(RENDERED_PNG),
                "png_base64": base64.b64encode(RENDERED_PNG).decode(), "query_evidence": evidence}
    monkeypatch.setattr(visual_evidence, "capture", rendered)

    runtime = DisposablePostgres()
    runtime.started = True
    monkeypatch.setattr(runtime, "_assert_owned", lambda: None)

    def sql(script):
        rig.sql_seen.append(script)
        if "IS NOT NULL" in script:
            return "t"
        for key, out in rig.outputs.items():
            if key in script:
                return out
        return "value|configuration file"
    monkeypatch.setattr(runtime, "sql", sql)
    rig.runtime = runtime
    yield rig
    tc.docker_path.cache_clear()


def assert_nothing_typed(rig, shot):
    """No terminal picture: nothing typed, no tape, no SQL file written, no VHS process."""
    assert rig.tapes == [] and rig.writes == [] and rig.popen == []
    assert "typed_command" not in shot
    assert shot["status"] == "UNAVAILABLE" or shot["mode"] == "rendered"
    assert shot.get("reason")


def other_run_id(runtime):
    other = uuid.uuid4().hex
    return other if other != runtime.run_id else uuid.uuid4().hex


# ---------------------------------------------------------------------------
# Happy path (the reference the refusals are measured against)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("stage, label", [("before", "BEFORE"), ("after", "AFTER FIX"), ("rollback", "AFTER ROLLBACK")])
def test_terminal_stage_types_one_fixed_command_and_writes_sql_inside_the_sandbox(rig, stage, label):
    runtime = rig.runtime
    shot = tc.capture_stage(runtime, stage, tc.setting_targets(["log_connections"]))
    assert shot["status"] == "CAPTURED" and shot["mode"] == "terminal" and shot["format"] == "png"
    assert base64.b64decode(shot["png_base64"]) == PNG and shot["sha256"] == sha(PNG)
    assert shot["typed_command"] == expected_typed(runtime, stage)
    assert TYPED_RE.fullmatch(shot["typed_command"])
    # The tape is the fixed template around exactly that one typed line.
    assert rig.tapes == [tc.build_tape(shot["typed_command"])]
    # The SQL travelled on stdin to a constant argv inside this run's container, nowhere else.
    assert rig.writes == [(("exec", "-i", runtime.name, "tee", f"/var/run/postgresql/dbguard-{stage}.sql"),
                           shot["sql"])]
    sql = shot["sql"]
    assert sql.splitlines()[0] == tc.READ_ONLY_LINE
    assert "SHOW log_connections;" in sql
    assert "FROM pg_catalog.pg_settings WHERE name = 'log_connections';" in sql
    assert f"'{runtime.run_id}' AS run_id" in sql and f"'{label}'" in sql and f"'{runtime.name}'" in sql
    assert shot["raw_output_sha256"] == tc._digest(shot["raw_output"]) and shot["raw_output_sha256"] in sql
    # Raw output was read first, each query in a fresh read-only session.
    assert rig.sql_seen and all(s.startswith(tc.READ_ONLY_LINE + "\n") for s in rig.sql_seen)
    assert rig.popen == [] and rig.rendered == []


# ---------------------------------------------------------------------------
# 1. Hostile container names, docker paths and stage names never reach the typed line
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("name", [
    "dbguard-poc-x; touch /tmp/pwned", "dbguard-poc-$(id)", "dbguard-poc-`id`",
    "dbguard-poc-" + "A" * 32, "dbguard-poc-" + "0" * 31, "dbguard-poc-" + "0" * 33,
    "dbguard-poc-" + "0" * 32 + "\n", "dbguard-poc-" + "0" * 32 + " ; id", "other-" + "0" * 32,
    "dbguard-poc-" + "0" * 31 + "'", 'dbguard-poc-"' + "0" * 31, "dbguard-poc-" + "０" * 32, "", None])
def test_hostile_container_name_is_refused_before_anything_is_typed(rig, name):
    rig.runtime.name = name
    shot = tc.capture_stage(rig.runtime, "before", tc.setting_targets(["log_connections"]))
    assert_nothing_typed(rig, shot)


def test_a_well_formed_name_of_another_run_is_refused(rig):
    rig.runtime.name = "dbguard-poc-" + other_run_id(rig.runtime)
    with pytest.raises(tc.CaptureRefused):
        tc.typed_command(rig.runtime, "before")
    shot = tc.capture_stage(rig.runtime, "before", tc.setting_targets(["log_connections"]))
    assert_nothing_typed(rig, shot)
    assert shot["mode"] == "rendered" and "not this run's sandbox" in shot["reason"]


def test_a_failed_ownership_check_means_no_terminal_picture(rig, monkeypatch):
    def not_owned():
        raise RuntimeError("Container ownership mismatch; refusing access")
    monkeypatch.setattr(rig.runtime, "_assert_owned", not_owned)
    shot = tc.capture_stage(rig.runtime, "after", tc.setting_targets(["log_connections"]))
    assert_nothing_typed(rig, shot)
    assert shot["mode"] == "rendered" and shot["status"] == "CAPTURED"
    assert shot["reason"].startswith("Terminal capture UNAVAILABLE")


def test_ownership_is_rechecked_after_the_sql_write_and_before_recording(rig, monkeypatch):
    calls = []

    def owned_twice():
        calls.append(1)
        if len(calls) >= 3:  # typed_command, write_evidence_sql, then the re-check
            raise RuntimeError("Container ownership mismatch; refusing access")
    monkeypatch.setattr(rig.runtime, "_assert_owned", owned_twice)
    shot = tc.capture_stage(rig.runtime, "after", tc.setting_targets(["log_connections"]))
    assert len(calls) == 3 and len(rig.writes) == 1
    assert rig.tapes == [] and rig.popen == [] and "typed_command" not in shot
    assert shot["mode"] == "rendered"


@pytest.mark.parametrize("path", [
    None, "docker", "./docker", "/usr/local/bin/my docker", "/usr/local/bin/doc'ker", '/usr/local/bin/doc"ker',
    "/opt/$HOME/docker", "/usr/bin/docker;id", "/usr/bin/`id`/docker", "/usr/bin/docker\n", "/usr/bin/doc\nker",
    "/usr/bin/docker|tee", "/usr/bin/docker&", "/usr/bin/dockér", "/usr/bin/docker\x00"])
def test_hostile_docker_path_is_refused(rig, path):
    rig.paths["docker"] = path
    tc.docker_path.cache_clear()
    with pytest.raises(tc.CaptureRefused):
        tc.docker_path()
    shot = tc.capture_stage(rig.runtime, "before", tc.setting_targets(["log_connections"]))
    assert_nothing_typed(rig, shot)
    assert shot["mode"] == "rendered"


@pytest.mark.parametrize("stage", ["during", "before;id", "before ", " before", "BEFORE", "../etc/passwd",
                                   "before\n", "", None, "rollback/../after"])
def test_stage_outside_the_fixed_three_is_refused(rig, stage):
    with pytest.raises(tc.CaptureRefused):
        tc.typed_command(rig.runtime, stage)
    with pytest.raises(ContractError):
        rig.runtime.write_evidence_sql(stage, tc.READ_ONLY_LINE + "\nSELECT 1;\n")
    shot = tc.capture_stage(rig.runtime, stage, tc.setting_targets(["log_connections"]))
    assert_nothing_typed(rig, shot)
    assert shot["status"] == "UNAVAILABLE" and "png_base64" not in shot


def test_typed_line_never_contains_anything_but_the_allowlist(rig):
    for stage in tc.STAGES:
        line = tc.typed_command(rig.runtime, stage)
        assert TYPED_RE.fullmatch(line) and not set(line) & tc.FORBIDDEN_TYPED
        assert line.count(" ") == expected_typed(rig.runtime, stage).count(" ")


@pytest.mark.parametrize("tamper", [
    lambda t, typed: t.replace(f'Type "{typed}"', f'Type "{typed} ; id"'),
    lambda t, typed: t.replace("Hide\n", "Hide\nType \"id\"\nEnter\n"),
    lambda t, typed: t.replace("Screenshot shot.png", "Screenshot /tmp/shot.png"),
    lambda t, typed: t.replace("Set Shell \"bash\"", "Set Shell \"zsh\""),
    lambda t, typed: t.replace("bash --norc --noprofile", "bash"),
    lambda t, typed: t + "Output out.gif\n",
    lambda t, typed: t.replace("Set FontSize 14", "Set FontSize 14\x1b"),
    lambda t, typed: t.replace("Set FontSize 14", "Set FontSize 1４"),
    lambda t, typed: t.replace("Set Height 1100", "Set Height 1101"),
    lambda t, typed: t.replace("Set Width 1400", "Set Width 1400 "),
])
def test_tampered_tapes_are_refused(rig, tamper):
    typed = tc.typed_command(rig.runtime, "before")
    tape = tc.build_tape(typed)
    with pytest.raises(tc.CaptureRefused):
        tc.check_tape(tamper(tape, typed), typed)


def test_both_geometries_build_a_valid_tape(rig):
    typed = tc.typed_command(rig.runtime, "after")
    for geometry, (width, height) in tc.GEOMETRY.items():
        tape = tc.build_tape(typed, geometry)
        assert f"Set Width {width}\n" in tape and f"Set Height {height}\n" in tape
        tc.check_tape(tape, typed)
    with pytest.raises(KeyError):
        tc.build_tape(typed, "huge")


# ---------------------------------------------------------------------------
# 2. Hostile object names end up only inside the SQL file, as quoted literals
# ---------------------------------------------------------------------------

HOSTILE_OK = ["o'brien", 'q"uote', "semi;colon", "dash--dash", "dollar$1", "$$dq$$", "back`tick",
              "ünïcødé_rôle", "x'); DROP ROLE dbguard_poc; --", "a b|c&d<e>f", "it's", "w2a \"q\";--rôle",
              "x' OR '1'='1"]
HOSTILE_REFUSED = ["back\\slash", "new\nline", "cr\rname", "nul\x00byte", "tab\tname", "esc\x1bname",
                   "zero​width", "rlo‮name", "", "a" * 64, None, 42, ["x"]]


def object_proposals(name):
    return [{"fix_type": "role_nologin", "target": {"role": name}},
            {"fix_type": "role_drop_attribute", "target": {"role": name, "attribute": "CREATEDB"}},
            {"fix_type": "function_security_invoker",
             "target": {"schema": name, "name": name, "identity_args": name}},
            {"fix_type": "table_revoke_dml", "target": {"schema": name, "table": name, "grantee": name}}]


def literal(name):
    return "'" + name.replace("'", "''") + "'"


@pytest.mark.parametrize("name", HOSTILE_OK)
def test_hostile_object_names_appear_only_as_literals_in_the_sql_file(rig, name):
    shot = tc.capture_stage(rig.runtime, "after", tc.object_targets(object_proposals(name)))
    assert shot["status"] == "CAPTURED" and shot["mode"] == "terminal", shot.get("reason")
    typed = shot["typed_command"]
    assert typed == expected_typed(rig.runtime, "after") and TYPED_RE.fullmatch(typed)
    assert len(rig.tapes) == 1 and name not in rig.tapes[0] and name not in typed
    sql = shot["sql"]
    tc.check_sql(sql)
    assert sql.count(literal(name)) >= 4
    # Remove every literal: the name (and nothing from it) is left in the SQL text.
    assert name not in LITERALS.sub("''", sql)
    # The file written into the sandbox is exactly that SQL, on stdin only.
    (args, stdin), = rig.writes
    assert stdin == sql and not any(name in a for a in args)


@pytest.mark.parametrize("name", HOSTILE_REFUSED)
@pytest.mark.parametrize("index", range(4))
def test_names_that_cannot_be_quoted_safely_are_refused(rig, name, index):
    shot = tc.capture_stage(rig.runtime, "before", tc.object_targets([object_proposals(name)[index]]))
    assert_nothing_typed(rig, shot)
    assert shot["status"] == "UNAVAILABLE" and "png_base64" not in shot and "sql" not in shot
    assert rig.rendered == []  # nothing safe to render either: refused before any query ran


def test_public_grantee_and_empty_identity_args_are_fixed_text():
    table = tc._object_queries({"fix_type": "table_revoke_dml",
                                "target": {"schema": "public", "table": "orders", "grantee": "PUBLIC"}})[0][1]
    assert "AND a.grantee = 0 ORDER BY" in table
    function = tc._object_queries({"fix_type": "function_revoke_public_execute",
                                   "target": {"schema": "public", "name": "f", "identity_args": ""}})[0][1]
    assert function.endswith("pg_catalog.pg_get_function_identity_arguments(p.oid) = '';")


@pytest.mark.parametrize("proposal", [None, "role", {"fix_type": "role_nologin"},
                                      {"fix_type": "role_nologin", "target": "web"},
                                      {"fix_type": "alter_system", "target": {"role": "web"}},
                                      {"fix_type": "ROLE_NOLOGIN", "target": {"role": "web"}}])
def test_malformed_or_unknown_object_targets_are_refused(proposal):
    with pytest.raises(tc.CaptureRefused):
        tc._object_queries(proposal)


def test_object_queries_never_read_secret_catalogs():
    for proposal in object_proposals("web"):
        for _, sql in tc._object_queries(proposal):
            assert not re.search(r"pg_authid|rolpassword|pg_shadow|password", sql, re.I)


# ---------------------------------------------------------------------------
# 3. check_sql and setting names
# ---------------------------------------------------------------------------

PREFIX = tc.READ_ONLY_LINE + "\n"


@pytest.mark.parametrize("statement", [
    "SELECT * FROM pg_authid;", "SELECT * FROM PG_AUTHID;", "SELECT * FROM pg_catalog.pg_authid;",
    "SELECT rolpassword FROM pg_catalog.pg_roles;", "SELECT * FROM pg_shadow;",
    "SELECT * FROM pg_user_mapping;", "SELECT * FROM pg_user_mappings;",
    "SELECT pg_read_file('/etc/passwd');", "SELECT pg_read_binary_file('x');",
    "SELECT pg_ls_dir('.');", "SELECT pg_ls_waldir();", "SELECT pg_stat_file('x');",
    "SELECT lo_import('/etc/passwd');", "SELECT lo_export(1, '/tmp/x');", "SELECT lo_get(1);",
    "COPY t TO STDOUT;", "copy (select 1) to program 'id';", "Copy t FROM '/x';",
    "SHOW ssl_key_file;", "SELECT * FROM pg_hba_file_rules;",
    "SELECT 'x' FROM pg_authid WHERE 'a' = 'pg_authid';",  # a literal does not hide a real name
    "SELECT 'it''s'; COPY t TO STDOUT;",
])
def test_check_sql_refuses_secret_catalogs_and_file_functions(statement):
    with pytest.raises(tc.CaptureRefused):
        tc.check_sql(PREFIX + statement + "\n")


@pytest.mark.parametrize("sql", [
    "SELECT 1;\n", " " + PREFIX + "SELECT 1;\n", tc.READ_ONLY_LINE + " SELECT 1;\n", PREFIX.lower() + "SELECT 1;\n",
    "SELECT 1;\n" + PREFIX, PREFIX.rstrip("\n"), "", None, PREFIX.encode() + b"SELECT 1;\n",
    PREFIX + "SELECT 1; \\! id\n", PREFIX + "\\copy t to x\n", PREFIX + "SELECT 1;\t\n", PREFIX + "SELECT 1;\r\n",
    PREFIX + "SELECT 1;\x00\n", PREFIX + "SELECT 1;\x1b[2J\n", PREFIX + "SELECT 1;\x7f\n",
    PREFIX + "SELECT 'a\\'';\n"])
def test_check_sql_refuses_missing_read_only_prefix_backslash_and_control_characters(sql):
    with pytest.raises(tc.CaptureRefused):
        tc.check_sql(sql)


def test_check_sql_size_cap_is_64_kib_in_bytes():
    # Padding sits inside one SELECT literal: review N4b refuses statements other than SET/SELECT/SHOW.
    room = tc.MAX_SQL_BYTES - len(PREFIX.encode()) - len("SELECT '';")
    tc.check_sql(PREFIX + "SELECT '" + "a" * room + "';")
    with pytest.raises(tc.CaptureRefused):
        tc.check_sql(PREFIX + "SELECT '" + "a" * (room + 1) + "';")
    with pytest.raises(tc.CaptureRefused):
        tc.check_sql(PREFIX + "SELECT '" + "é" * (room // 2 + 1) + "';")


def test_check_sql_allows_names_that_are_only_data_inside_literals():
    tc.check_sql(PREFIX + "SELECT 1 WHERE 'pg_authid' = 'copy' AND 'lo_import' <> 'x''pg_shadow';\n")


def test_check_sql_is_not_fooled_by_dollar_quoting():
    with pytest.raises(tc.CaptureRefused):
        tc.check_sql(PREFIX + "SELECT $$'$$;\nSELECT rolpassword FROM pg_authid;\nSELECT $$'$$;\n")


@pytest.mark.parametrize("name", [
    "archive_command", "restore_command", "archive_cleanup_command", "recovery_end_command", "primary_conninfo",
    "ssl_passphrase_command", "krb_server_keyfile", "myext.api_token", "app.jwt_secret", "ARCHIVE_COMMAND",
    "Log_connections", "log connections", "log_connections;", "log_connections; SELECT 1", "1abc", "",
    "log-connections", "log_connections\n", "pgaudit.log'", 'pgaudit."log"', None, 7])
def test_setting_names_must_be_plain_and_never_collector_redacted(rig, name):
    with pytest.raises(tc.CaptureRefused):
        tc._setting_name(name)
    shot = tc.capture_stage(rig.runtime, "after", tc.setting_targets([name]))
    assert_nothing_typed(rig, shot)
    assert shot["status"] == "UNAVAILABLE" and "sql" not in shot
    # The refused name was never even queried for its raw output.
    assert not any(isinstance(name, str) and name and name in s for s in rig.sql_seen)


@pytest.mark.parametrize("name", ["log_connections", "pgaudit.log", "shared_preload_libraries", "ssl_ciphers",
                                  "password_encryption", "log_line_prefix"])
def test_reviewed_setting_names_are_accepted(name):
    assert tc._setting_name(name) == name
    assert len(tc._setting_queries(name, True)) == 2


# ---------------------------------------------------------------------------
# 4. Redaction: any output the collector would mask means no terminal picture
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("raw, secret", [
    ("value|host=db password=hunter2|configuration file", "hunter2"),
    ("passfile=/root/.pgpass", "/root/.pgpass"),
    ("--password=hunter2", "hunter2"),
    ("postgresql://app:hunter2@db/prod", "hunter2"),
    ("https://vault/?tok%65n=hunter2", "hunter2"),
])
def test_output_the_collector_would_redact_is_never_put_in_a_terminal(rig, raw, secret):
    rig.outputs["pg_settings"] = raw
    shot = tc.capture_stage(rig.runtime, "after", tc.setting_targets(["log_connections"]))
    assert rig.tapes == [] and rig.writes == [] and rig.popen == []
    assert shot["status"] == "CAPTURED" and shot["mode"] == "rendered" and shot["redacted"] is True
    assert "redaction" in shot["reason"] and "typed_command" not in shot
    assert base64.b64decode(shot["png_base64"]) == RENDERED_PNG
    evidence, = rig.rendered
    assert "***REDACTED***" in json.dumps(evidence)
    assert secret not in json.dumps(evidence) and secret not in json.dumps(shot)


def test_clean_output_is_not_marked_redacted(rig):
    shot = tc.capture_stage(rig.runtime, "after", tc.setting_targets(["log_connections"]))
    assert shot["redacted"] is False and shot["mode"] == "terminal"


def test_rendered_fallback_failure_is_unavailable_with_both_reasons(rig):
    rig.outputs["pg_settings"] = "password=hunter2"
    rig.rendered_fails = True
    shot = tc.capture_stage(rig.runtime, "after", tc.setting_targets(["log_connections"]))
    assert shot["status"] == "UNAVAILABLE" and shot["mode"] == "rendered"
    assert "png_base64" not in shot and "sha256" not in shot
    assert "redaction" in shot["reason"] and "Rendered capture also failed" in shot["reason"]
    assert "hunter2" not in json.dumps(shot)


def test_missing_capture_tools_fall_back_to_rendered_without_typing(rig, monkeypatch):
    monkeypatch.setattr(tc, "tools", lambda: {**TOOLS, "ttyd": None})
    shot = tc.capture_stage(rig.runtime, "before", tc.setting_targets(["log_connections"]))
    assert_nothing_typed(rig, shot)
    assert shot["mode"] == "rendered" and "not installed" in shot["reason"]
    assert shot["tools"]["ttyd"] is None


# ---------------------------------------------------------------------------
# 5. _run_vhs: list argv, no shell, private 0700 folder, minimal env, timeout
# ---------------------------------------------------------------------------

class FakeProcess:
    instances = []

    def __init__(self, args, behaviour, **kwargs):
        self.args, self.kwargs, self.behaviour, self.pid = args, kwargs, behaviour, 424242
        cwd = kwargs["cwd"]
        self.cwd_mode = os.stat(cwd).st_mode & 0o777
        self.tape = Path(cwd, "stage.tape").read_text()
        self.waits = []
        if behaviour == "ok":
            Path(cwd, "shot.png").write_bytes(PNG)
        elif behaviour == "not_png":
            Path(cwd, "shot.png").write_bytes(b"GIF89a" + b"0" * 10)
        FakeProcess.instances.append(self)

    def wait(self, timeout=None):
        self.waits.append(timeout)
        if self.behaviour == "timeout" and len(self.waits) == 1:
            raise subprocess.TimeoutExpired(self.args, timeout)
        return 3 if self.behaviour == "exit" else 0


@pytest.fixture
def vhs(monkeypatch, tmp_path):
    """_run_vhs with Popen, mkdtemp and killpg recorded (no process is started)."""
    paths = {"vhs": f"{TOOL_DIR}/vhs", "ttyd": f"{TOOL_DIR}/ttyd", "ffmpeg": "/usr/local/bin/ffmpeg"}
    monkeypatch.setattr(tc.shutil, "which", lambda name: paths.get(name))
    state = {"behaviour": "ok", "dirs": [], "killed": [], "paths": paths}
    real_mkdtemp = tc.tempfile.mkdtemp

    def mkdtemp(**kwargs):
        path = real_mkdtemp(dir=tmp_path, **kwargs)
        state["dirs"].append(path)
        return path
    monkeypatch.setattr(tc.tempfile, "mkdtemp", mkdtemp)
    FakeProcess.instances = []

    def popen(args, **kwargs):
        if state["behaviour"] == "oserror":
            raise OSError("exec failed")
        return FakeProcess(args, state["behaviour"], **kwargs)
    monkeypatch.setattr(tc.subprocess, "Popen", popen)
    monkeypatch.setattr(tc.os, "killpg", lambda pid, sig: state["killed"].append((pid, sig)))
    # Review N2/N3: the fake process is not a real child (os.waitid cannot see it), so the
    # unreaped wait, the process sweep and the browser lookup are recorded here instead.
    state["waited"], state["events"] = [], []

    def wait_unreaped(process, timeout):
        state["waited"].append(timeout)
        state["events"].append("waited")
        return state["behaviour"] != "timeout"
    monkeypatch.setattr(tc, "_wait_unreaped", wait_unreaped)
    monkeypatch.setattr(tc, "_recording_processes", lambda leader, workdir: state["events"].append("swept") or set())
    monkeypatch.setattr(tc, "terminal_browser", lambda: {"source": "system", "executable": "/usr/bin/chromium",
                                                          "revisions": []})
    for key, value in {"DBGUARD_DSN": "postgresql://app:hunter2@db/prod", "OPENAI_API_KEY": "sk-unit-secret",
                       "ANTHROPIC_API_KEY": "sk-ant-unit", "AWS_SECRET_ACCESS_KEY": "aws-unit-secret",
                       "PGPASSWORD": "pg-unit-secret", "DBGUARD_SCREENSHOT_MODE": "terminal"}.items():
        monkeypatch.setenv(key, value)
    return state


TAPE = tc.TAPE_TEMPLATE.format(width=1400, height=1100, typed=f"{DOCKER} exec -i dbguard-poc-{'0' * 32} psql",
                               sentinel=tc.SENTINEL_SHOWN)


def test_run_vhs_uses_a_list_argv_private_folder_and_minimal_environment(vhs):
    assert tc._run_vhs(TAPE) == PNG
    process, = FakeProcess.instances
    assert process.args == [f"{TOOL_DIR}/vhs", "stage.tape"]
    assert process.kwargs.get("shell", False) is False
    assert process.kwargs["start_new_session"] is True
    assert process.kwargs["stdin"] is subprocess.DEVNULL
    folder, = vhs["dirs"]
    assert process.kwargs["cwd"] == folder and process.cwd_mode == 0o700
    assert process.tape == TAPE
    env = process.kwargs["env"]
    assert set(env) <= {"PATH", "HOME", "TMPDIR"} and env["TMPDIR"] == folder
    # Re-review: HOME is the private read-only home inside this folder, never the real one.
    assert env["HOME"] == os.path.join(folder, "home") and env["HOME"] != str(Path.home())
    assert env["PATH"].split(":") == [TOOL_DIR, "/usr/local/bin", "/usr/bin", "/bin"]
    leaked = [v for v in ("hunter2", "sk-unit-secret", "sk-ant-unit", "aws-unit-secret", "pg-unit-secret")
              if any(v in value for value in env.values())]
    assert leaked == [] and not any(k.startswith("DBGUARD_") or k.endswith("_KEY") for k in env)
    assert vhs["waited"] == [tc.VHS_TIMEOUT_SECONDS]
    # ttyd and the browser must not outlive the recording: the whole group is killed, and
    # (review N2) only before VHS is reaped, so the group ID cannot have been reused.
    assert vhs["killed"] == [(process.pid, signal.SIGKILL)]
    assert vhs["events"] == ["waited", "swept"] and len(process.waits) == 1
    assert not os.path.exists(folder)


def test_run_vhs_timeout_kills_the_process_group_and_removes_the_folder(vhs):
    vhs["behaviour"] = "timeout"
    with pytest.raises(tc.CaptureRefused, match="did not finish"):
        tc._run_vhs(TAPE)
    process, = FakeProcess.instances
    assert (process.pid, signal.SIGKILL) in vhs["killed"]
    assert not os.path.exists(vhs["dirs"][0])


@pytest.mark.parametrize("behaviour, message", [("missing", "without writing"), ("not_png", "not a PNG"),
                                                ("exit", "VHS failed")])
def test_run_vhs_refuses_a_missing_or_non_png_picture_or_a_failed_exit(vhs, behaviour, message):
    vhs["behaviour"] = behaviour
    with pytest.raises(tc.CaptureRefused, match=message):
        tc._run_vhs(TAPE)
    assert not os.path.exists(vhs["dirs"][0])


def test_run_vhs_removes_the_folder_when_the_process_cannot_start(vhs):
    vhs["behaviour"] = "oserror"
    with pytest.raises(OSError):
        tc._run_vhs(TAPE)
    assert len(vhs["dirs"]) == 1 and not os.path.exists(vhs["dirs"][0])


@pytest.mark.parametrize("tool", ["vhs", "ttyd", "ffmpeg"])
def test_run_vhs_refuses_when_a_tool_is_missing(vhs, tool):
    vhs["paths"][tool] = None
    with pytest.raises(tc.CaptureRefused, match="not installed"):
        tc._run_vhs(TAPE)
    assert FakeProcess.instances == [] and vhs["dirs"] == []


@pytest.mark.parametrize("path", ["/opt/home brew/bin/vhs", "/opt/$X/vhs", "/opt/`id`/vhs", "/opt/a;b/vhs"])
def test_run_vhs_refuses_tool_folders_with_unexpected_characters(vhs, path):
    vhs["paths"]["vhs"] = path
    with pytest.raises(tc.CaptureRefused):
        tc._run_vhs(TAPE)
    assert FakeProcess.instances == [] and vhs["dirs"] == []


@pytest.mark.parametrize("behaviour", ["timeout", "missing", "not_png", "exit", "oserror"])
def test_vhs_failures_become_a_rendered_fallback_never_an_exception(rig, vhs, monkeypatch, behaviour):
    # The real runner (rig replaced it): every failure is a fallback with a reason.
    monkeypatch.setattr(tc, "_run_vhs", REAL_RUN_VHS)
    vhs["paths"]["docker"] = DOCKER
    tc.docker_path.cache_clear()
    vhs["behaviour"] = behaviour
    shot = tc.capture_stage(rig.runtime, "after", tc.setting_targets(["log_connections"]))
    assert shot["status"] == "CAPTURED" and shot["mode"] == "rendered"
    assert shot["reason"].startswith("Terminal capture UNAVAILABLE") and "typed_command" not in shot
    assert all(not os.path.exists(d) for d in vhs["dirs"])


# ---------------------------------------------------------------------------
# write_evidence_sql: constant argv, stdin only, read-only prefix, 64 KiB
# ---------------------------------------------------------------------------

def test_write_evidence_sql_keeps_content_off_the_argv(rig):
    content = PREFIX + "SELECT '$(id); `id` | rm -rf / && echo';\n"
    rig.runtime.write_evidence_sql("rollback", content)
    (args, stdin), = rig.writes
    assert args == ("exec", "-i", rig.runtime.name, "tee", "/var/run/postgresql/dbguard-rollback.sql")
    assert stdin == content
    assert set(runtime_module.EVIDENCE_SQL_COMMANDS) == {"before", "after", "rollback"}
    assert all(cmd == ("tee", f"/var/run/postgresql/dbguard-{s}.sql")
               for s, cmd in runtime_module.EVIDENCE_SQL_COMMANDS.items())


def test_write_evidence_sql_size_cap_and_ownership(rig, monkeypatch):
    room = 64 * 1024 - len(PREFIX.encode())
    rig.runtime.write_evidence_sql("before", PREFIX + "a" * room)
    for body in (PREFIX + "a" * (room + 1), PREFIX + "é" * (room // 2 + 1), b"bytes", None,
                 PREFIX + "SELECT 1;\r\n", PREFIX + "SELECT 1;\x1b\n"):
        with pytest.raises(ContractError):
            rig.runtime.write_evidence_sql("before", body)
    assert len(rig.writes) == 1

    def not_owned():
        raise RuntimeError("Container ownership mismatch; refusing access")
    monkeypatch.setattr(rig.runtime, "_assert_owned", not_owned)
    with pytest.raises(RuntimeError):
        rig.runtime.write_evidence_sql("before", PREFIX + "SELECT 1;\n")
    assert len(rig.writes) == 1


# ---------------------------------------------------------------------------
# 9. Shot data shape (the contract shotViews.ts and the bundles read)
# ---------------------------------------------------------------------------

COMMON = {"status", "mode", "format", "stage", "stage_label", "run_id", "target_id", "tools"}


def test_terminal_shot_shape(rig):
    shot = tc.capture_stage(rig.runtime, "before", tc.setting_targets(["log_connections"]))
    assert COMMON | {"sha256", "png_base64", "typed_command", "sql", "captured_at", "raw_output",
                     "raw_output_sha256", "redacted"} <= set(shot)
    assert "reason" not in shot
    assert (shot["status"], shot["mode"], shot["format"], shot["stage"], shot["stage_label"]) == (
        "CAPTURED", "terminal", "png", "before", "BEFORE")
    assert shot["tools"] == TOOLS and set(shot["tools"]) == {"vhs", "ttyd", "ffmpeg"}
    assert re.fullmatch(r"[0-9a-f]{64}", shot["sha256"]) and re.fullmatch(r"[0-9a-f]{64}", shot["raw_output_sha256"])
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", shot["captured_at"])
    assert shot["run_id"] == rig.runtime.run_id and shot["target_id"] == rig.runtime.name
    assert all(set(row) == {"title", "query", "output"} for row in shot["raw_output"])
    json.dumps(shot)  # JSON-serialisable as stored in the attempt record


def test_rendered_fallback_shape(rig, monkeypatch):
    monkeypatch.setattr(tc, "tools", lambda: {"vhs": None, "ttyd": None, "ffmpeg": None})
    shot = tc.capture_stage(rig.runtime, "rollback", tc.setting_targets(["log_connections"]))
    assert COMMON | {"sha256", "png_base64", "sql", "reason", "raw_output_sha256"} <= set(shot)
    assert (shot["status"], shot["mode"], shot["stage_label"]) == ("CAPTURED", "rendered", "AFTER ROLLBACK")
    assert "typed_command" not in shot and shot["sha256"] == sha(base64.b64decode(shot["png_base64"]))
    evidence, = rig.rendered
    assert evidence["raw_output_sha256"] == shot["raw_output_sha256"] and evidence["stage"] == "AFTER ROLLBACK"
    assert evidence["target_id"] == rig.runtime.name and evidence["run_id"] == rig.runtime.run_id


def test_unavailable_shapes_have_no_picture_fields(rig, monkeypatch):
    refused = tc.capture_stage(rig.runtime, "during", tc.setting_targets(["log_connections"]))
    no_targets = tc.capture_stage(rig.runtime, "after", None)
    rig.rendered_fails = True
    monkeypatch.setattr(tc, "tools", lambda: {"vhs": None, "ttyd": None, "ffmpeg": None})
    both_failed = tc.capture_stage(rig.runtime, "after", tc.setting_targets(["log_connections"]))
    for shot in (refused, no_targets, both_failed):
        assert shot["status"] == "UNAVAILABLE" and shot["format"] == "png"
        assert shot["mode"] in ("terminal", "rendered") and isinstance(shot["reason"], str) and shot["reason"]
        assert not {"png_base64", "sha256", "typed_command"} & set(shot)
        assert set(shot["tools"]) == {"vhs", "ttyd", "ffmpeg"}


def test_sql_queries_that_fail_mean_unavailable_without_a_picture(rig, monkeypatch):
    def broken(script):
        raise RuntimeError("Docker exec failed: psql: error: connection to server failed")
    monkeypatch.setattr(rig.runtime, "sql", broken)
    shot = tc.capture_stage(rig.runtime, "after", tc.setting_targets(["log_connections"]))
    assert_nothing_typed(rig, shot)
    assert shot["status"] == "UNAVAILABLE" and "could not be run" in shot["reason"]
    assert "connection to server" not in shot["reason"]  # no raw server diagnostics in the record
