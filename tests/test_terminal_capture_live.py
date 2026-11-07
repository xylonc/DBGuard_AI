"""Live Task 2 terminal (VHS) screenshots on real disposable PostgreSQL 17 sandboxes.

    DBGUARD_POC_LIVE=1 .venv-demo/bin/python -m pytest tests/test_terminal_capture_live.py

Needs Docker, VHS, ttyd and ffmpeg (Homebrew) and the Playwright Chromium for the
fallback test. Each test records every sandbox it creates and checks, by that run's own
label, that none remains; it never lists or touches anyone else's containers (a demo
stack may be running). Pictures are written to DBGUARD_TEST_EVIDENCE_DIR when set.
"""
import base64
import copy
import hashlib
import io
import json
import os
import re
import shutil
import struct
import zipfile
from pathlib import Path

import pytest

from services.sandbox_poc import terminal_capture as tc
from services.sandbox_poc.runtime import LABEL, DisposablePostgres, docker
from services.sandbox_poc.shared import ROOT, SpecEngine
from services.sandbox_poc.workflow import CONTROL, ObjectRemediationLoop
from tests.test_object_sandbox_live import ODD, fixture_template, pick, source  # noqa: F401  (fixture)

pytestmark = pytest.mark.skipif(os.environ.get("DBGUARD_POC_LIVE") != "1",
                                reason="Set DBGUARD_POC_LIVE=1 with Docker, VHS, ttyd and ffmpeg")

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
TYPED_RE = re.compile(r"[A-Za-z0-9 /._=-]+")
STAGES = ("before", "after", "rollback")


class Recorder:
    """A runtime factory that remembers every sandbox it created (cleanup is checked by run ID)."""

    def __init__(self):
        self.created = []

    def __call__(self, image=None):
        runtime = DisposablePostgres(image)
        self.created.append(runtime)
        return runtime


def assert_removed(created):
    assert created
    left = [r.run_id for r in created if docker("ps", "-aq", "--filter", f"label={LABEL}={r.run_id}")]
    assert left == [], f"run-labelled sandboxes remain: {left}"


@pytest.fixture
def terminal_mode(monkeypatch, tmp_path):
    missing = [tool for tool in ("vhs", "ttyd", "ffmpeg") if not shutil.which(tool)]
    if missing:
        pytest.skip(f"not installed: {', '.join(missing)}")
    monkeypatch.setenv("DBGUARD_SCREENSHOTS", "true")
    monkeypatch.setenv("DBGUARD_SCREENSHOT_MODE", "terminal")
    monkeypatch.setenv("DBGUARD_HISTORY_DIR", str(tmp_path / "history"))
    tc.docker_path.cache_clear()
    yield
    tc.docker_path.cache_clear()


def save(name, shots):
    out = os.environ.get("DBGUARD_TEST_EVIDENCE_DIR")
    if not out:
        return
    folder = Path(out) / "terminal-capture"
    folder.mkdir(parents=True, exist_ok=True)
    for stage, shot in shots.items():
        if shot.get("png_base64"):
            (folder / f"{name}-{stage}.png").write_bytes(base64.b64decode(shot["png_base64"]))
    (folder / f"{name}.json").write_text(json.dumps(
        {s: {k: v for k, v in shot.items() if k != "png_base64"} for s, shot in shots.items()}, indent=2))


def assert_terminal_stages(evidence, run_id, geometry="single"):
    """Three CAPTURED terminal pictures of this run's own sandbox, each a valid PNG."""
    assert evidence["mode"] == "terminal"
    stages = evidence["stages"]
    assert set(stages) == set(STAGES)
    for stage in STAGES:
        shot = stages[stage]
        assert shot["status"] == "CAPTURED" and shot["mode"] == "terminal", (stage, shot.get("reason"))
        png = base64.b64decode(shot["png_base64"], validate=True)
        assert png.startswith(PNG_MAGIC) and png[12:16] == b"IHDR"
        width, height = struct.unpack(">II", png[16:24])
        assert width >= 600 and height >= 400
        assert hashlib.sha256(png).hexdigest() == shot["sha256"]
        assert shot["typed_command"] == tc.TYPED_TEMPLATE.format(
            docker=tc.docker_path(), container=f"dbguard-poc-{run_id}", path=tc.SQL_PATHS[stage])
        assert TYPED_RE.fullmatch(shot["typed_command"])
        assert shot["target_id"] == f"dbguard-poc-{run_id}" and shot["run_id"] == run_id
        assert shot["sql"].startswith(tc.READ_ONLY_LINE + "\n") and shot["redacted"] is False
        assert shot["raw_output_sha256"] == tc._digest(shot["raw_output"]) and shot["raw_output_sha256"] in shot["sql"]
        assert all(shot["tools"][t] for t in ("vhs", "ttyd", "ffmpeg"))
        assert not re.search(r"pg_authid|rolpassword|PASSWORD\s+'", json.dumps(shot), re.I)
    return stages


def output_of(shot, title):
    return next(row["output"] for row in shot["raw_output"] if row["title"] == title)


def engine():
    return SpecEngine.load(ROOT / "catalog/specs/cis-pg17-v1.1.0",
                           ROOT / "catalog/benchmarks/cis-pg17-v1.1.0/records.json")


def run_setting_demo(monkeypatch):
    import scripts.sandbox_poc as sandbox_script
    recorder = Recorder()
    monkeypatch.setattr(sandbox_script, "DisposablePostgres", recorder)  # the demo source too
    try:
        result = sandbox_script.run_demo(engine(), None, "conf", recorder)
    finally:
        assert_removed(recorder.created)
    assert result["status"] == "VERIFIED", result["attempts"][-1].get("error")
    assert result["demo_target_cleanup"]["verified"] is True
    attempt = result["attempts"][-1]
    findings = [attempt[k]["findings"][CONTROL]["status"]
                for k in ("before_assessment", "after_assessment", "rollback_assessment")]
    assert findings == ["FAIL", "PASS", "FAIL"]
    assert attempt["rollback_verified"] is True and attempt["cleanup"]["verified"] is True
    assert not attempt["regressions"]
    return result, attempt


# ---------------------------------------------------------------------------
# Setting fix (3.1.20 log_connections)
# ---------------------------------------------------------------------------

def test_setting_fix_produces_three_terminal_pictures(terminal_mode, monkeypatch):
    result, attempt = run_setting_demo(monkeypatch)
    stages = assert_terminal_stages(attempt["terminal_evidence"], attempt["run_id"])
    save("setting-3.1.20", stages)
    effective = "Effective value of log_connections"
    assert [output_of(stages[s], effective) for s in STAGES] == ["off", "on", "off"]
    for stage in STAGES:
        assert "SHOW log_connections;" in stages[stage]["sql"]
    # The upstream summary (what the UI receives) carries the same pictures.
    from services.sandbox_poc.upstream import result_summary
    summary = result_summary({**result, "template": result.get("template") or {}})
    assert summary["attempts"][-1]["terminal_evidence"] == attempt["terminal_evidence"]


# ---------------------------------------------------------------------------
# Object fix on a hostile role name (quote, semicolon, comment marker, non-ASCII)
# ---------------------------------------------------------------------------

def test_object_fix_on_a_hostile_name_produces_three_terminal_pictures(terminal_mode, source):  # noqa: F811
    proposal = pick(source, "role_drop_attribute", role=ODD, attribute="CREATEDB")
    engine_, snapshot = source["engine"], source["snapshot"]
    recorder = Recorder()
    try:
        result = ObjectRemediationLoop(engine_, fixture_template("role_drop_attribute"), proposal, recorder).run(
            snapshot, engine_.assess(snapshot))
    finally:
        assert_removed(recorder.created)
    attempt = result["attempts"][-1]
    assert result["status"] == "VERIFIED", attempt.get("error")
    assert attempt["rollback_verified"] is True and attempt["cleanup"]["verified"] is True
    stages = assert_terminal_stages(attempt["terminal_evidence"], attempt["run_id"])
    save("object-role_drop_attribute", stages)
    quoted = "'" + ODD.replace("'", "''") + "'"
    for stage in STAGES:
        shot = stages[stage]
        assert ODD not in shot["typed_command"] and quoted in shot["sql"]
        assert "FROM pg_catalog.pg_roles WHERE rolname = " + quoted in shot["sql"]
    # rolname|rolsuper|rolcreaterole|rolcreatedb|...: CREATEDB is dropped, then restored.
    createdb = [output_of(stages[s], "Role attributes").split("|")[3] for s in STAGES]
    assert createdb == ["t", "f", "t"]


# ---------------------------------------------------------------------------
# Combined test (two object fixes): three pictures for the whole batch
# ---------------------------------------------------------------------------

def test_combined_test_produces_three_terminal_pictures(terminal_mode, source, monkeypatch, tmp_path):  # noqa: F811
    from services.sandbox_poc import batch, profiles
    from services.sandbox_poc.handoff import SandboxHandoff, TemplateReference, build_handoff
    from services.sandbox_poc.service import SandboxService
    engine_, snapshot, resources = source["engine"], source["snapshot"], source["resources"]
    chosen = [pick(source, "role_connection_limit", role="w2a_web"),
              pick(source, "table_revoke_dml", table="orders", grantee="w2a_app")]
    templates = {p["fix_type"]: fixture_template(p["fix_type"]) for p in chosen}
    monkeypatch.setattr(profiles, "resolve_profile", lambda records, specs, ref: engine_.policy)
    recorder = Recorder()
    service = SandboxService("unused", runtime_factory=recorder,
                             registry_loader=lambda url, version, sha, docs, env, **kw: templates[kw["registry_name"]])
    base = build_handoff(engine_, snapshot, resources.handoff.template_ref).model_dump()
    requests = []
    for p in chosen:
        ref = TemplateReference(registry_name=p["fix_type"], version=1, sha256=templates[p["fix_type"]].sha256,
                                evidence=[{"document_id": "live-doc", "version": "1", "sha256": "b" * 64}])
        requests.append(SandboxHandoff(**{**base, "control_id": p["spec_id"], "object_fix_id": p["fix_id"],
                                          "template_ref": ref.model_dump()}))
    try:
        output, data = batch.run_batch(requests, service)
    finally:
        assert_removed(recorder.created)
    combined = output["combined_test"]
    assert output["status"] == "VERIFIED", combined.get("reason") or combined.get("rollback_error")
    assert all(r["verified"] for r in combined["rollback"]) and combined["cleanup"]["verified"]
    assert len(recorder.created) == 3 and recorder.created[-1].run_id == combined["run_id"]
    stages = assert_terminal_stages(combined["terminal_evidence"], combined["run_id"], "combined")
    save("combined-objects", stages)
    # One picture per stage for the whole batch, showing both objects.
    for stage in STAGES:
        titles = [row["title"] for row in stages[stage]["raw_output"]]
        assert titles.count("Role attributes") == 1 and titles.count("Table privileges granted to this grantee") == 1
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        assert z.testzip() is None
        files = {name: z.read(name) for name in z.namelist()}
    manifest = json.loads(files["manifest.json"])
    for stage in STAGES:
        name = f"screenshots/combined-{stage}.png"
        assert hashlib.sha256(files[name]).hexdigest() == manifest["files"][name] == stages[stage]["sha256"]
    for run in output["individual_runs"]:
        fix_manifest = json.loads(files[run["fix_id"] + "/manifest.json"])
        for stage in STAGES:
            member = f"screenshots/{stage}.png"
            assert hashlib.sha256(files[run["fix_id"] + "/" + member]).hexdigest() == fix_manifest["files"][member]


# ---------------------------------------------------------------------------
# Fallback: VHS hidden from PATH -> rendered picture with the reason
# ---------------------------------------------------------------------------

def test_vhs_missing_falls_back_to_rendered_pictures_with_the_reason(terminal_mode, monkeypatch):
    monkeypatch.setenv("PATH", "/usr/local/bin:/usr/bin:/bin")
    assert tc.tools()["vhs"] is None, "VHS must be hidden for this test"
    result, attempt = run_setting_demo(monkeypatch)
    stages = attempt["terminal_evidence"]["stages"]
    save("fallback-setting", stages)
    assert set(stages) == set(STAGES)
    for stage in STAGES:
        shot = stages[stage]
        assert shot["status"] == "CAPTURED" and shot["mode"] == "rendered", shot.get("reason")
        assert "Terminal capture UNAVAILABLE: VHS, ttyd or ffmpeg is not installed" in shot["reason"]
        assert "typed_command" not in shot and shot["tools"]["vhs"] is None
        png = base64.b64decode(shot["png_base64"], validate=True)
        assert png.startswith(PNG_MAGIC) and hashlib.sha256(png).hexdigest() == shot["sha256"]


# ---------------------------------------------------------------------------
# Review N2: a VHS timeout leaves no ttyd, browser or recorded shell behind
# ---------------------------------------------------------------------------

def _marked_processes(folder):
    """{pid: command} of this user's live processes started for one recording, found only
    by that recording's private folder: in the command line (the browser profile lives
    there) or as the working folder (ttyd and the recorded shell run there)."""
    import subprocess
    markers = {folder, os.path.realpath(folder)}
    out = subprocess.run(["/bin/ps", "-ww", "-axo", "pid=,uid=,stat=,command="], capture_output=True, text=True).stdout
    live = {}
    for line in out.splitlines():
        parts = line.split(None, 3)
        if len(parts) == 4 and parts[0].isdigit() and int(parts[1]) == os.getuid() and not parts[2].startswith("Z"):
            live[int(parts[0])] = parts[3]
    found = {pid: cmd for pid, cmd in live.items() if any(m in cmd for m in markers)}
    lsof = subprocess.run(["/usr/sbin/lsof", "-a", "-d", "cwd", "-u", str(os.getuid()), "-Fpn"],
                          capture_output=True, text=True).stdout
    pid = None
    for line in lsof.splitlines():
        if line.startswith("p"):
            pid = int(line[1:])
        elif line.startswith("n") and any(line[1:] == m or line[1:].startswith(m + "/") for m in markers):
            if pid in live:
                found[pid] = live[pid]
    found.pop(os.getpid(), None)
    return found


def test_vhs_timeout_leaves_no_recording_process_behind(terminal_mode, monkeypatch):
    import threading
    import time
    # The sentinel never appears, so VHS waits (up to 45 s) while DBGuard's timeout fires
    # mid-recording, with ttyd, the browser and the recorded shell all running.
    monkeypatch.setattr(tc, "SENTINEL_SHOWN", "DBGUARD SENTINEL THAT NEVER APPEARS")
    monkeypatch.setattr(tc, "VHS_TIMEOUT_SECONDS", 10)
    folders, real_mkdtemp = [], tc.tempfile.mkdtemp
    monkeypatch.setattr(tc.tempfile, "mkdtemp", lambda **kw: folders.append(real_mkdtemp(**kw)) or folders[-1])
    seen, stop = {}, threading.Event()

    def sample():
        while not stop.is_set():
            if folders:
                seen.update(_marked_processes(folders[0]))
            time.sleep(0.2)

    runtime = DisposablePostgres()
    try:
        runtime.start()
        sampler = threading.Thread(target=sample, daemon=True)
        sampler.start()
        started = time.monotonic()
        shot = tc.capture_stage(runtime, "after", tc.setting_targets(["log_connections"]))
        elapsed = time.monotonic() - started
        stop.set()
        sampler.join(5)
    finally:
        stop.set()
        runtime.close()
    assert_removed([runtime])
    assert shot["status"] == "CAPTURED" and shot["mode"] == "rendered", shot.get("reason")
    assert "VHS did not finish within 10 seconds" in shot["reason"] and "typed_command" not in shot
    assert elapsed < 45, "the recording was not cut short by DBGuard's timeout"
    # Proof the recording was really running when it was stopped ...
    commands = " ".join(seen.values())
    assert "ttyd" in commands, seen
    assert re.search(r"Chromium|chrome|headless_shell", commands), seen
    # ... and that nothing it started survives (checked by PID and by the folder marker).
    time.sleep(1)
    still = {pid: cmd for pid, cmd in _marked_processes(folders[0]).items()}
    import subprocess
    alive = [pid for pid in seen if subprocess.run(["/bin/ps", "-o", "stat=", "-p", str(pid)], capture_output=True,
                                                    text=True).stdout.strip()[:1] not in ("", "Z")]
    assert still == {} and alive == [], (still, {p: seen[p] for p in alive})
    assert not os.path.exists(folders[0])
