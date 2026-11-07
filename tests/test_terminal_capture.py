"""Task 2 terminal (VHS) screenshots: tape builder refusals and fixed-template guards.

No Docker, VHS or browser: every check here runs before anything is typed or executed.
"""
import base64
import json
import subprocess
import os
from pathlib import Path
import hashlib

import pytest

from services.sandbox_poc import runtime as runtime_module
from services.sandbox_poc import terminal_capture as tc
from services.sandbox_poc.review_bundle import stage_screenshots
from services.sandbox_poc.runtime import DisposablePostgres
from services.sandbox_poc.shared import ContractError

DOCKER = "/usr/local/bin/docker"


@pytest.fixture
def owned(monkeypatch):
    """A DisposablePostgres that believes it is started and owned (no Docker call)."""
    monkeypatch.setattr(tc.shutil, "which", lambda name: DOCKER if name == "docker" else None)
    tc.docker_path.cache_clear()
    runtime = DisposablePostgres()
    runtime.started = True
    monkeypatch.setattr(runtime, "_assert_owned", lambda: None)
    yield runtime
    tc.docker_path.cache_clear()


def typed_for(runtime, stage="before"):
    return (f"{DOCKER} exec -i {runtime.name} psql -X -e -v ON_ERROR_STOP=1 -U dbguard_poc "
            f"-d dbguard_sandbox -f /var/run/postgresql/dbguard-{stage}.sql")


def test_typed_command_is_exactly_the_fixed_template(owned):
    for stage in ("before", "after", "rollback"):
        assert tc.typed_command(owned, stage) == typed_for(owned, stage)


def test_tape_is_the_fixed_template_with_one_typed_line(owned):
    typed = tc.typed_command(owned, "after")
    tape = tc.build_tape(typed)
    lines = tape.splitlines()
    assert f'Type "{typed}"' in lines
    assert [line for line in lines if line.startswith("Type ")] == [
        "Type \"exec env -i PATH=/usr/bin:/bin TERM=xterm-256color HISTFILE=/dev/null PS1='sandbox$ ' "
        "bash --norc --noprofile\"", 'Type "clear"', f'Type "{typed}"']
    assert lines.index("Hide") < lines.index('Type "clear"') < lines.index("Show") < lines.index(f'Type "{typed}"')
    assert "Screenshot shot.png" in lines


@pytest.mark.parametrize("bad", ["'", '"', "`", "\\", "$", ";", "|", "&", "<", ">", "\n", "\r", "\x00", "\x1b",
                                 "\x7f", "‮", "é", "(", "*", "#", "~"])
def test_typed_line_refuses_shell_and_tape_characters(owned, bad):
    with pytest.raises(tc.CaptureRefused):
        tc.check_typed(typed_for(owned) + bad + "x")
    with pytest.raises(tc.CaptureRefused):
        tc.build_tape(typed_for(owned) + bad)


@pytest.mark.parametrize("name", [
    "dbguard-poc-x; touch /tmp/pwned", "dbguard-poc-" + "A" * 32, "dbguard-poc-" + "0" * 31,
    "other-" + "0" * 32, "dbguard-poc-" + "0" * 32 + "\n", "dbguard-poc-$(id)"])
def test_container_name_must_match_pattern(owned, name):
    owned.name = name
    with pytest.raises(tc.CaptureRefused):
        tc.typed_command(owned, "before")


def test_container_name_must_be_this_runs_own(owned):
    owned.name = "dbguard-poc-" + ("0" * 32 if owned.run_id != "0" * 32 else "1" * 32)
    with pytest.raises(tc.CaptureRefused):
        tc.typed_command(owned, "before")


def test_unknown_stage_and_unowned_container_are_refused(owned, monkeypatch):
    for stage in ("during", "before;", "../etc", ""):
        with pytest.raises(tc.CaptureRefused):
            tc.typed_command(owned, stage)

    def not_owned():
        raise RuntimeError("Container ownership mismatch; refusing access")
    monkeypatch.setattr(owned, "_assert_owned", not_owned)
    with pytest.raises(RuntimeError):
        tc.typed_command(owned, "before")


def test_only_a_disposable_sandbox_runtime_is_accepted():
    class Fake:
        run_id = "0" * 32
        name = "dbguard-poc-" + "0" * 32
    with pytest.raises(tc.CaptureRefused):
        tc.typed_command(Fake(), "before")
    shot = tc.capture_stage(Fake(), "before", tc.setting_targets(["log_connections"]))
    assert shot["status"] == "UNAVAILABLE" and "png_base64" not in shot and shot["reason"]


@pytest.mark.parametrize("path", [None, "docker", "/usr/local/bin/my docker", "/usr/bin/docker;id", "/opt/$HOME/docker"])
def test_docker_path_must_be_absolute_and_plain(monkeypatch, path):
    monkeypatch.setattr(tc.shutil, "which", lambda name: path)
    tc.docker_path.cache_clear()
    try:
        with pytest.raises(tc.CaptureRefused):
            tc.docker_path()
    finally:
        tc.docker_path.cache_clear()


def test_tampered_tape_is_refused(owned):
    typed = tc.typed_command(owned, "before")
    tape = tc.build_tape(typed)
    for tampered in (tape + 'Type "id"\n', tape.replace("Hide\n", ""), tape.replace("Sleep 300ms", "Sleep 3s"),
                     tape.replace('Type "clear"', 'Type "env"'), tape.replace("Set Width 1400", "Set Width 1401")):
        with pytest.raises(tc.CaptureRefused):
            tc.check_tape(tampered, typed)


@pytest.mark.parametrize("name", ["archive_command", "primary_conninfo", "app.jwt_secret", "Log_connections",
                                  "log_connections; SELECT 1", "1abc", ""])
def test_setting_names_must_be_plain_and_not_redacted(name):
    with pytest.raises(tc.CaptureRefused):
        tc._setting_queries(name, True)


def test_reviewed_custom_setting_is_shown():
    assert tc._setting_queries("pgaudit.log", False)[0][1] == (
        "SELECT pg_catalog.current_setting('pgaudit.log', true) AS \"pgaudit.log\";")
    assert tc._setting_queries("log_connections", True)[0][1] == "SHOW log_connections;"


def test_object_names_are_literals_and_refuse_backslash_or_control():
    sql = tc._object_queries({"fix_type": "role_nologin", "target": {"role": "o'brien"}})[0][1]
    assert sql.endswith("WHERE rolname = 'o''brien';") and "pg_authid" not in sql and "password" not in sql
    for bad in ("a\\b", "a\nb", "a\x00b", "", None):
        with pytest.raises(tc.CaptureRefused):
            tc._object_queries({"fix_type": "role_nologin", "target": {"role": bad}})
    with pytest.raises(tc.CaptureRefused):
        tc._object_queries({"fix_type": "drop_everything", "target": {}})


def test_evidence_sql_starts_read_only_and_refuses_secret_catalogs(owned):
    stamp = tc.stamp_query("before", owned, "2026-11-07T00:00:00Z", "0" * 64)
    sql = tc.evidence_sql(stamp, [("x", "SELECT 1;")])
    assert sql.startswith("SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY;\n")
    for query in ("SELECT rolpassword FROM pg_authid;", "SELECT pg_read_file('x');", "COPY t TO STDOUT;",
                  "SELECT 1; \\! id", "SELECT 1;\x1b"):
        with pytest.raises(tc.CaptureRefused):
            tc.evidence_sql(stamp, [("x", query)])
    with pytest.raises(tc.CaptureRefused):
        tc.stamp_query("before", owned, "now()", "0" * 64)


def test_write_evidence_sql_uses_a_constant_argv(owned, monkeypatch):
    calls = []
    monkeypatch.setattr(runtime_module, "docker", lambda *args, stdin=None, **kw: calls.append((args, stdin)) or "")
    content = "SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY;\nSELECT 1;\n"
    owned.write_evidence_sql("after", content)
    assert calls == [(("exec", "-i", owned.name, "tee", "/var/run/postgresql/dbguard-after.sql"), content)]
    for stage, body in (("during", content), ("after", "SELECT 1;\n"), ("after", content + "\\! id\n"),
                        ("after", content + "\x00"), (None, content)):
        with pytest.raises(ContractError):
            owned.write_evidence_sql(stage, body)
    assert len(calls) == 1


def test_mode_is_terminal_only_when_both_switches_are_set(monkeypatch):
    monkeypatch.delenv("DBGUARD_SCREENSHOTS", raising=False)
    monkeypatch.setenv("DBGUARD_SCREENSHOT_MODE", "terminal")
    assert not tc.enabled()
    monkeypatch.setenv("DBGUARD_SCREENSHOTS", "true")
    assert tc.enabled()
    monkeypatch.setenv("DBGUARD_SCREENSHOT_MODE", "rendered")
    assert not tc.enabled() and tc.screenshot_mode() == "rendered"
    record = {}
    tc.begin(record)
    assert "terminal_evidence" not in record


def test_unreached_stages_are_unavailable(monkeypatch):
    monkeypatch.setenv("DBGUARD_SCREENSHOTS", "true")
    monkeypatch.setenv("DBGUARD_SCREENSHOT_MODE", "terminal")
    record = {}
    tc.begin(record)
    tc.finish(record)
    stages = record["terminal_evidence"]["stages"]
    assert set(stages) == {"before", "after", "rollback"}
    assert all(s["status"] == "UNAVAILABLE" and "png_base64" not in s for s in stages.values())


def test_collector_redaction_rules_mask_secrets():
    assert tc.redact("host=x password=s3cr3t") == "host=x password=***REDACTED***"
    assert tc.redact("postgresql://u:pw@h/db") == "postgresql://u:***REDACTED***@h/db"
    assert tc.redact("off") == "off"


def test_bundle_refuses_a_screenshot_whose_hash_differs():
    png = b"\x89PNG\r\n\x1a\n" + b"0" * 16
    shot = {"status": "CAPTURED", "mode": "terminal", "png_base64": base64.b64encode(png).decode(),
            "sha256": hashlib.sha256(png).hexdigest(), "typed_command": "x"}
    files, html, text = stage_screenshots({"stages": {"before": shot}})
    assert files == {"screenshots/before.png": png} and "screenshots/before.png" in html and "typed: x" in text
    with pytest.raises(ContractError):
        stage_screenshots({"stages": {"before": {**shot, "sha256": "0" * 64}}})


# ---------------------------------------------------------------------------
# Security review notes (N1, N3, N4, N5, N9, N10)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("path", ["/Users/alice/.docker/bin/docker", "/Users/alice/.orbstack/bin/docker",
                                  "/home/alice/bin/docker", "/usr/local/bin/docker2", "/opt/docker/bin/docker"])
def test_n1_docker_outside_the_standard_paths_is_refused(monkeypatch, path):
    monkeypatch.setattr(tc.shutil, "which", lambda name: path)
    tc.docker_path.cache_clear()
    try:
        with pytest.raises(tc.CaptureRefused, match="standard path"):
            tc.docker_path()
    finally:
        tc.docker_path.cache_clear()


@pytest.mark.parametrize("path", ["/usr/local/bin/docker", "/opt/homebrew/bin/docker", "/usr/bin/docker"])
def test_n1_standard_docker_paths_are_accepted(monkeypatch, path):
    monkeypatch.setattr(tc.shutil, "which", lambda name: path)
    tc.docker_path.cache_clear()
    try:
        assert tc.docker_path() == path
    finally:
        tc.docker_path.cache_clear()


def test_n3_no_browser_means_no_recording_and_no_folder(monkeypatch):
    monkeypatch.setattr(tc.shutil, "which", lambda name: "/opt/homebrew/bin/" + name)
    monkeypatch.setattr(tc, "terminal_browser", lambda: None)
    monkeypatch.setattr(tc.tempfile, "mkdtemp", lambda **kw: pytest.fail("no folder may be created"))
    monkeypatch.setattr(tc.subprocess, "Popen", lambda *a, **kw: pytest.fail("VHS must not start"))
    with pytest.raises(tc.CaptureRefused, match="terminal browser is not set up"):
        tc._run_vhs("tape")


def test_n3_rod_cache_is_found_and_shown_without_the_home_folder(monkeypatch, tmp_path):
    exe = tmp_path / ".cache/rod/browser/chromium-1321438/chrome-linux/chrome"
    exe.parent.mkdir(parents=True)
    exe.write_text("#!/bin/sh\necho Chromium 128.0.6568.0\n")
    exe.chmod(0o755)
    (tmp_path / ".cache/rod/browser/chromium-9/chrome-linux").mkdir(parents=True)  # no executable: ignored
    monkeypatch.setattr(tc, "SYSTEM_BROWSERS", ())
    monkeypatch.setattr(tc.Path, "home", classmethod(lambda cls: tmp_path))
    tc._browser_version.cache_clear()
    browser = tc.terminal_browser()
    assert browser["source"] == "rod-cache" and browser["revisions"] == ["chromium-1321438"]
    info = tc.browser_info()
    assert info["path"] == "~/.cache/rod/browser/chromium-1321438/chrome-linux/chrome"
    assert str(tmp_path) not in json.dumps(info)
    tc._browser_version.cache_clear()


def test_n3_private_home_holds_only_read_only_links_to_the_browser(tmp_path):
    real = tmp_path / "real/chromium-1321438"
    real.mkdir(parents=True)
    work = tmp_path / "work"
    work.mkdir()
    home = tc._browser_home(str(work), {"source": "rod-cache", "root": str(real.parent),
                                        "revisions": ["chromium-1321438"]})
    locked = tc._home_folders(str(work))
    assert home == str(work / "home")
    rod = Path(home) / ".cache/rod/browser"
    try:
        assert sorted(p.name for p in rod.iterdir()) == ["chromium-1321438"]
        assert (rod / "chromium-1321438").is_symlink()
        if os.geteuid() != 0:
            with pytest.raises(PermissionError):  # a download could not be stored here
                (rod / "chromium-99.zip").write_bytes(b"x")
    finally:
        for folder in locked:
            os.chmod(folder, 0o700)


@pytest.mark.parametrize("body", [
    "SELECT $$x$$;", "SELECT $1;", "SELECT 1; -- note", "SELECT 1 /* c */;", "UPDATE t SET a = 1;", "BEGIN;",
    "SELECT pg_reload_conf();", "SELECT set_config('a', 'b', false);", "SELECT pg_terminate_backend(1);",
    "SELECT pg_cancel_backend(1);", "SET default_transaction_read_only = off;",
    "SET SESSION CHARACTERISTICS AS TRANSACTION READ WRITE;", "SELECT 'unterminated;", "SELECT 1; SELECT 2",
    "SET standard_conforming_strings = off;", "SELECT \"pg_authid\";"])
def test_n4_check_sql_refuses_dollar_comments_writes_and_session_changes(body):
    with pytest.raises(tc.CaptureRefused):
        tc.check_sql(tc.READ_ONLY_LINE + "\n" + body + "\n")


def test_n4_check_sql_allows_hostile_text_inside_literals():
    tc.check_sql(tc.READ_ONLY_LINE + "\nSET standard_conforming_strings = on;\n"
                 "SELECT 'a;$b -- /* READ WRITE set_config pg_reload_conf';\nSHOW log_connections;\n")
    with pytest.raises(tc.CaptureRefused):  # only SET (the fixed one), SELECT or SHOW statements
        tc.check_sql(tc.READ_ONLY_LINE + "\nx;\n")
    with pytest.raises(tc.CaptureRefused):  # the read-only line must come first
        tc.check_sql("SELECT 1;\n" + tc.READ_ONLY_LINE + "\n")


class _Mini:
    """A started DisposablePostgres whose docker and psql calls are recorded."""

    def __init__(self, monkeypatch):
        from services.sandbox_poc.bundle_assets import visual_evidence
        self.runtime = DisposablePostgres()
        self.runtime.started = True
        monkeypatch.setattr(self.runtime, "_assert_owned", lambda: None)
        monkeypatch.setattr(self.runtime, "sql", lambda script: "t" if "IS NOT NULL" in script else "x|f")
        self.writes, self.tapes = [], []
        monkeypatch.setattr(runtime_module, "docker", lambda *a, stdin=None, **kw: self.writes.append(a) or "")
        monkeypatch.setattr(tc, "tools", lambda: {"vhs": "v", "ttyd": "t", "ffmpeg": "f", "browser": None})
        monkeypatch.setattr(tc, "_run_vhs", lambda tape: self.tapes.append(tape) or b"\x89PNG\r\n\x1a\n")
        png = b"\x89PNG\r\n\x1a\nrendered"
        monkeypatch.setattr(visual_evidence, "capture", lambda ev: {
            "sha256": hashlib.sha256(png).hexdigest(), "png_base64": base64.b64encode(png).decode()})
        monkeypatch.setattr(tc.shutil, "which", lambda name: DOCKER if name == "docker" else None)
        tc.docker_path.cache_clear()


def test_n5_query_text_matching_redaction_rules_is_never_typed(monkeypatch):
    mini = _Mini(monkeypatch)
    try:
        shot = tc.capture_stage(mini.runtime, "after", tc.object_targets(
            [{"fix_type": "role_nologin", "target": {"role": "x password=hunter2"}}]))
    finally:
        tc.docker_path.cache_clear()
    assert shot["mode"] == "rendered" and "psql would echo it" in shot["reason"]
    assert mini.tapes == [] and mini.writes == [] and "typed_command" not in shot


@pytest.mark.parametrize("stage", [["before"], {"x": 1}, None, 3, "during"])
def test_n10_capture_stage_never_raises_on_a_malformed_stage(monkeypatch, stage):
    mini = _Mini(monkeypatch)
    try:
        shot = tc.capture_stage(mini.runtime, stage, tc.setting_targets(["log_connections"]))
    finally:
        tc.docker_path.cache_clear()
    assert shot["status"] == "UNAVAILABLE" and "png_base64" not in shot and mini.tapes == []


def test_n10_malformed_base64_is_a_contract_error():
    shot = {"status": "CAPTURED", "mode": "terminal", "png_base64": "not base64 !!", "sha256": "0" * 64}
    with pytest.raises(ContractError):
        stage_screenshots({"stages": {"after": shot}})


def test_n9_bundle_evidence_keeps_member_names_and_hashes_not_base64():
    from services.sandbox_poc.review_bundle import bundled_result
    shot = {"status": "CAPTURED", "mode": "terminal", "png_base64": "QUJD", "sha256": "a" * 64}
    result = {"attempts": [{"terminal_evidence": {"stages": {"after": dict(shot)}}},
                           {"terminal_evidence": {"stages": {"before": dict(shot), "after": dict(shot),
                                                             "rollback": {"status": "UNAVAILABLE"}}}}]}
    out = bundled_result(result)
    assert "QUJD" not in json.dumps(out) and result["attempts"][1]["terminal_evidence"]["stages"]["after"]["png_base64"]
    final = out["attempts"][1]["terminal_evidence"]["stages"]
    assert final["before"]["png_member"] == "screenshots/before.png" and final["after"]["sha256"] == "a" * 64
    assert "png_member" not in out["attempts"][0]["terminal_evidence"]["stages"]["after"]
    assert final["rollback"] == {"status": "UNAVAILABLE"}


# ---------------------------------------------------------------------------
# Security re-review notes
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("body", [
    """SELECT U&"rolp!0061ssword" UESCAPE '!' FROM pg_catalog.U&"pg!0061uthid" UESCAPE '!';""",
    "SELECT query_to_xml('SELECT rolpassword FROM pg_authid', true, false, '');",
    "SELECT table_to_xml('x', true, false, '');", "SELECT cursor_to_xml('c', 1, true, false, '');",
    "SELECT xmlschema();", "SELECT 'pg_authid'::regclass;", "SELECT 'f'::regprocedure;",
    "SELECT 1 & 3;", "SELECT \"x\" UESCAPE;"])
def test_rereview_check_sql_refuses_unicode_escapes_and_sql_as_text(body):
    with pytest.raises(tc.CaptureRefused):
        tc.check_sql(tc.READ_ONLY_LINE + "\n" + body + "\n")


def test_rereview_every_real_template_still_passes():
    class Runtime(DisposablePostgres):
        def sql(self, script):
            return "t"
    runtime = Runtime()
    hostile = "x' & U&\"y\" UESCAPE '!' query_to_xml regclass"
    targets = tc.merge_targets(
        tc.setting_targets(["log_connections", "pgaudit.log", "shared_preload_libraries", "ssl_ciphers"]),
        tc.object_targets([
            {"fix_type": "role_nologin", "target": {"role": hostile}},
            {"fix_type": "role_drop_attribute", "target": {"role": "w2a_admin", "attribute": "CREATEDB"}},
            {"fix_type": "role_connection_limit", "target": {"role": "w2a_web"}},
            {"fix_type": "function_security_invoker", "target": {"schema": "s", "name": "f", "identity_args": ""}},
            {"fix_type": "function_revoke_public_execute",
             "target": {"schema": "s", "name": hostile, "identity_args": "a integer"}},
            {"fix_type": "table_revoke_dml", "target": {"schema": "s", "table": "t", "grantee": "PUBLIC"}},
            {"fix_type": "table_revoke_dml", "target": {"schema": "s", "table": "t", "grantee": hostile}}]))
    for defined in ("t", "f"):
        Runtime.sql = lambda self, script, d=defined: d
        for stage in tc.STAGES:
            stamp = tc.stamp_query(stage, runtime, "2026-11-07T00:00:00Z", "0" * 64)
            sql = tc.evidence_sql(stamp, tc.check_queries(runtime, targets))  # runs check_sql
            assert sql.count("SHOW ") == (4 if defined == "t" else 0)


def test_rereview_lsof_failure_keeps_the_ps_targets(monkeypatch, tmp_path):
    folder = str(tmp_path / "dbguard-vhs-x")
    ps = (f"  10     1    10  {os.getuid()} vhs stage.tape\n"
          f"  11    10    10  {os.getuid()} ttyd --port 1\n"
          f"  12    11    12  {os.getuid()} bash --norc --noprofile\n"
          f"  13     1    13  {os.getuid()} Chromium --user-data-dir={folder}/rod/user-data/1\n"
          f"  14     1    14  {os.getuid()} unrelated\n")
    calls = []

    def run(args, **kwargs):
        calls.append(args)
        if args[0] == "/bin/ps":
            assert "-ww" in args
            return subprocess.CompletedProcess(args, 0, ps, "")
        raise subprocess.TimeoutExpired(args, 10)
    monkeypatch.setattr(tc.subprocess, "run", run)
    assert tc._recording_processes(10, folder) == {11, 12, 13}
    assert any(a[0].endswith("lsof") for a in calls) or not any(
        os.path.exists(p) for p in ("/usr/sbin/lsof", "/usr/bin/lsof", "/sbin/lsof"))


def test_rereview_browser_home_failure_part_way_is_still_cleaned_up(monkeypatch, tmp_path):
    monkeypatch.setattr(tc.shutil, "which", lambda name: "/opt/homebrew/bin/" + name)
    monkeypatch.setattr(tc, "terminal_browser", lambda: {"source": "system", "executable": "/usr/bin/chromium",
                                                          "revisions": []})
    folders = []
    real_mkdtemp = tc.tempfile.mkdtemp
    monkeypatch.setattr(tc.tempfile, "mkdtemp", lambda **kw: folders.append(real_mkdtemp(dir=tmp_path, **kw))
                        or folders[-1])
    real_chmod, count = os.chmod, []

    def chmod(path, mode):
        if mode == 0o500:
            count.append(path)
            if len(count) == 3:
                raise OSError("injected failure part-way through")
        real_chmod(path, mode)
    monkeypatch.setattr(tc.os, "chmod", chmod)
    monkeypatch.setattr(tc.subprocess, "Popen", lambda *a, **kw: pytest.fail("VHS must not start"))
    with pytest.raises(OSError, match="part-way"):
        tc._run_vhs("tape")
    assert len(count) == 3 and not os.path.exists(folders[0])
