"""Task 2 terminal screenshots: wiring into the setting and catalog loops, bundles, the DBA
runner's manifest allowlist, result_summary, the MCP image filter and the demo switch.

Fake runtimes only (no Docker, VHS, browser or model). capture_stage is replaced by a
recorder, so these tests check WHEN a stage is taken (after reproduce, after acceptance,
after a verified rollback, always before cleanup) and that capture never changes a verdict.
"""
import asyncio
import base64
import copy
import hashlib
import io
import json
import shutil
import subprocess
import sys
import zipfile
from unittest.mock import Mock

import pytest

from services.sandbox_poc import terminal_capture as tc
from services.sandbox_poc.handoff import SandboxHandoff
from services.sandbox_poc.review_bundle import (COMBINED_SCREENSHOT_MEMBERS, SCREENSHOT_MEMBERS,
                                                build_review_bundle, stage_screenshots)
from services.sandbox_poc.shared import ROOT, ContractError
from services.sandbox_poc.upstream import result_summary
from tests.test_review_bundle import recorded  # noqa: F401  (fixture)
from tests.test_sandbox_poc import engine, run_fake, snapshot  # noqa: F401  (fixtures)

PNG_MAGIC = b"\x89PNG\r\n\x1a\n"
RUNNER = ROOT / "services/sandbox_poc/bundle_assets/runner.py"
TERMINAL_ENV = {"DBGUARD_SCREENSHOTS": "true", "DBGUARD_SCREENSHOT_MODE": "terminal"}


def sha(data):
    return hashlib.sha256(data).hexdigest()


def png_for(stage):
    return PNG_MAGIC + b"\x00\x00\x00\rIHDR" + stage.encode() * 4


def fake_shot(stage, mode="terminal"):
    png = png_for(stage)
    shot = {"status": "CAPTURED", "mode": mode, "format": "png", "stage": stage,
            "stage_label": tc.STAGES[stage], "sha256": sha(png), "png_base64": base64.b64encode(png).decode(),
            "sql": tc.READ_ONLY_LINE + "\nSELECT 1;\n", "tools": {"vhs": "v", "ttyd": "t", "ffmpeg": "f"},
            "captured_at": "2026-11-07T00:00:00Z", "raw_output_sha256": "0" * 64, "target_id": "dbguard-poc-x"}
    if mode == "terminal":
        shot["typed_command"] = "/usr/local/bin/docker exec -i dbguard-poc-x psql -f /var/run/postgresql/x.sql"
    else:
        shot["reason"] = "Terminal capture UNAVAILABLE: VHS is not installed."
    return shot


@pytest.fixture
def terminal(monkeypatch):
    for key, value in TERMINAL_ENV.items():
        monkeypatch.setenv(key, value)


class Spy:
    def __init__(self, raises=None):
        self.calls, self.raises = [], raises

    def __call__(self, runtime, stage, targets, geometry="single"):
        self.calls.append({"stage": stage, "targets": copy.deepcopy(targets), "geometry": geometry,
                           "closed": runtime.closed, "executed": len(runtime.executed)})
        if self.raises:
            raise self.raises
        return fake_shot(stage)


@pytest.fixture
def spy(monkeypatch):
    spy = Spy()
    monkeypatch.setattr(tc, "capture_stage", spy)
    return spy


def verdict(result, runtimes):
    return (result["status"], len(result["attempts"]),
            [(a["status"], a["phase"], a["rollback_verified"], a.get("error"), a.get("cleanup"),
              a.get("apply_or_assessment_error"), a.get("regressions")) for a in result["attempts"]],
            [r.closed for r in runtimes])


# ---------------------------------------------------------------------------
# 6. Setting loop lifecycle
# ---------------------------------------------------------------------------

def test_setting_loop_takes_three_stages_in_order_and_before_cleanup(engine, snapshot, terminal, spy):  # noqa: F811
    result, runtimes = run_fake(engine, snapshot, [None])
    assert result["status"] == "VERIFIED"
    attempt, = result["attempts"]
    assert [c["stage"] for c in spy.calls] == ["before", "after", "rollback"]
    assert all(c["targets"] == {"settings": ["log_connections"], "objects": []} for c in spy.calls)
    assert all(c["geometry"] == "single" and c["closed"] is False for c in spy.calls)
    executed = runtimes[0].executed
    apply = next(i for i, s in enumerate(executed) if 'ALTER SYSTEM SET "log_connections"' in s)
    reset = next(i for i, s in enumerate(executed) if i > apply and "RESET" in s)
    before, after, rollback = (c["executed"] for c in spy.calls)
    assert before <= apply < after <= reset < rollback
    assert attempt["terminal_evidence"] == {"mode": "terminal",
                                            "stages": {s: fake_shot(s) for s in ("before", "after", "rollback")}}


@pytest.mark.parametrize("fault", [None, "apply", "regression", "gap", "rollback", "health", "create",
                                   "cleanup", "cleanup_unverified"])
def test_capture_failures_never_change_the_setting_verdict(engine, snapshot, monkeypatch, fault):  # noqa: F811
    monkeypatch.delenv("DBGUARD_SCREENSHOT_MODE", raising=False)
    baseline = verdict(*run_fake(engine, copy.deepcopy(snapshot), [fault]))
    for key, value in TERMINAL_ENV.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(tc, "capture_stage", Spy(raises=RuntimeError("VHS exploded")))
    result, runtimes = run_fake(engine, copy.deepcopy(snapshot), [fault])
    assert verdict(result, runtimes) == baseline
    for attempt in result["attempts"]:
        stages = attempt["terminal_evidence"]["stages"]
        assert set(stages) == {"before", "after", "rollback"}
        assert all(s["status"] == "UNAVAILABLE" and "png_base64" not in s and s["reason"] for s in stages.values())


@pytest.mark.parametrize("fault", ["apply", "regression", "rollback", "health", "create"])
def test_unreached_stages_are_unavailable_and_a_rollback_picture_means_a_verified_rollback(
        engine, snapshot, terminal, spy, fault):  # noqa: F811
    result, runtimes = run_fake(engine, snapshot, [fault])
    assert result["status"] == "FAILED" and all(r.closed for r in runtimes)
    for attempt in result["attempts"]:
        stages = attempt["terminal_evidence"]["stages"]
        assert set(stages) == {"before", "after", "rollback"}
        for name, shot in stages.items():
            if shot["status"] != "CAPTURED":
                assert shot == {"status": "UNAVAILABLE", "mode": "terminal", "format": "png", "stage": name,
                                "stage_label": tc.STAGES[name],
                                "reason": "The test did not reach this stage, so no picture was taken."}
        if "apply_or_assessment_error" in attempt or fault == "create":
            assert stages["after"]["status"] == "UNAVAILABLE"
        if stages["rollback"]["status"] == "CAPTURED":
            assert attempt["rollback_verified"] is True
    if fault == "create":
        assert spy.calls == []


@pytest.mark.parametrize("env", [{"DBGUARD_SCREENSHOTS": "true"},
                                 {"DBGUARD_SCREENSHOTS": "true", "DBGUARD_SCREENSHOT_MODE": "rendered"},
                                 {"DBGUARD_SCREENSHOTS": "true", "DBGUARD_SCREENSHOT_MODE": "Terminal"},
                                 {"DBGUARD_SCREENSHOTS": "true", "DBGUARD_SCREENSHOT_MODE": "terminal "},
                                 {"DBGUARD_SCREENSHOT_MODE": "terminal"},
                                 {"DBGUARD_SCREENSHOTS": "1", "DBGUARD_SCREENSHOT_MODE": "terminal"}, {}])
def test_rendered_or_disabled_mode_is_exactly_todays_behaviour(engine, snapshot, monkeypatch, spy, env):  # noqa: F811
    for key in ("DBGUARD_SCREENSHOTS", "DBGUARD_SCREENSHOT_MODE"):
        monkeypatch.delenv(key, raising=False)
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    assert not tc.enabled()
    result, _ = run_fake(engine, snapshot, [None])
    assert result["status"] == "VERIFIED" and spy.calls == []
    assert all("terminal_evidence" not in a for a in result["attempts"])
    assert "terminal_evidence" not in json.dumps(result)
    record = {}
    tc.begin(record)
    tc.stage(record, object(), "before", tc.setting_targets(["log_connections"]))
    tc.finish(record)
    assert record == {}


def test_a_fake_runtime_is_never_recorded_and_vhs_never_runs(engine, snapshot, terminal, monkeypatch):  # noqa: F811
    started = []
    monkeypatch.setattr(tc, "tools", lambda: {"vhs": "v", "ttyd": "t", "ffmpeg": "f"})
    monkeypatch.setattr(tc, "_run_vhs", lambda tape: started.append(tape))
    monkeypatch.setattr(tc.subprocess, "Popen", lambda *a, **k: started.append(a))
    result, _ = run_fake(engine, snapshot, [None])
    assert result["status"] == "VERIFIED" and started == []
    stages = result["attempts"][0]["terminal_evidence"]["stages"]
    assert all(s["status"] == "UNAVAILABLE" and "Not a disposable sandbox" in s["reason"] for s in stages.values())


def test_stage_and_finish_never_raise_on_odd_records(terminal, spy):
    for record in ({}, {"terminal_evidence": None}, {"terminal_evidence": "x"}, {"terminal_evidence": []}):
        tc.stage(record, object(), "before", {})
        tc.finish(record)
    broken = {"terminal_evidence": {"mode": "terminal", "stages": None}}
    tc.finish(broken)  # swallowed: a capture problem never reaches the loop
    record = {}
    tc.begin(record)
    tc.stage(record, Mock(closed=False, executed=[]), "before", None)
    assert record["terminal_evidence"]["stages"]["before"]["status"] == "CAPTURED"  # spy decides


# ---------------------------------------------------------------------------
# 6. Catalog-linked loop (3.2, 5.6, 6.10)
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("rec, policy", [("3.2", True), ("5.6", False), ("6.10", False)])
def test_catalog_loop_records_each_changed_setting(terminal, spy, rec, policy):
    from tests.test_catalog_fixes_w2b import profile, run_loop
    result, runtimes = run_loop(rec, policy=profile() if policy else None)
    assert result["status"] == "VERIFIED"
    params = [c["param"] for c in result["fix_unit"]["changes"]]
    assert params and [c["stage"] for c in spy.calls] == ["before", "after", "rollback"]
    assert all(c["targets"] == {"settings": params, "objects": []} and not c["closed"] for c in spy.calls)
    if rec == "3.2":
        assert params == ["shared_preload_libraries", "pgaudit.log"]
    attempt = result["attempts"][-1]
    assert set(attempt["terminal_evidence"]["stages"]) == {"before", "after", "rollback"}
    assert all(s["status"] == "CAPTURED" for s in attempt["terminal_evidence"]["stages"].values())
    sets = [i for i, s in enumerate(runtimes[0].executed) if "ALTER SYSTEM SET" in s]
    resets = [i for i, s in enumerate(runtimes[0].executed) if "ALTER SYSTEM RESET" in s]
    before, after, rollback = (c["executed"] for c in spy.calls)
    assert before <= sets[0] and sets[-1] < after <= min(i for i in resets if i > sets[-1]) < rollback


@pytest.mark.parametrize("raises", [None, RuntimeError("VHS exploded")])
def test_catalog_failed_start_keeps_its_verdict_and_marks_later_stages_unreached(monkeypatch, raises):
    from tests.test_catalog_fixes_w2b import run_loop
    monkeypatch.delenv("DBGUARD_SCREENSHOT_MODE", raising=False)
    base_result, base_runtimes = run_loop("5.6", fault="start")
    for key, value in TERMINAL_ENV.items():
        monkeypatch.setenv(key, value)
    monkeypatch.setattr(tc, "capture_stage", Spy(raises=raises))
    result, runtimes = run_loop("5.6", fault="start")
    strip = lambda r: [{k: v for k, v in a.items() if k not in ("run_id", "terminal_evidence")}  # noqa: E731
                       for a in r["attempts"]]
    assert result["status"] == base_result["status"] == "FAILED"
    assert json.dumps(strip(result), sort_keys=True, default=str) == json.dumps(strip(base_result), sort_keys=True,
                                                                                default=str)
    assert not any("RESET" in s for s in runtimes[0].executed) and runtimes[0].closed
    stages = result["attempts"][0]["terminal_evidence"]["stages"]
    assert stages["before"]["status"] == ("UNAVAILABLE" if raises else "CAPTURED")
    for name in ("after", "rollback"):
        assert stages[name]["status"] == "UNAVAILABLE" and "did not reach" in stages[name]["reason"]


# ---------------------------------------------------------------------------
# result_summary pass-through
# ---------------------------------------------------------------------------

def test_result_summary_passes_terminal_evidence_through_unchanged():
    evidence = {"mode": "terminal", "stages": {"before": fake_shot("before")}}
    result = {"status": "VERIFIED", "fix_unit": {"spec_id": "s"},
              "template": {"approved_by": "Unit Reviewer", "evidence": [{"approved_by": "Unit Reviewer"}]},
              "attempts": [{"attempt": 1, "status": "FAILED", "terminal_evidence": {"mode": "terminal", "stages": {}}},
                           {"attempt": 2, "status": "VERIFIED", "terminal_evidence": evidence},
                           {"attempt": 3, "status": "VERIFIED"}]}
    attempts = result_summary(result)["attempts"]
    assert attempts[1]["terminal_evidence"] == evidence and attempts[0]["terminal_evidence"]["stages"] == {}
    assert "terminal_evidence" not in attempts[2]


# ---------------------------------------------------------------------------
# 7. Bundles: stage_screenshots and the setting bundle
# ---------------------------------------------------------------------------

def evidence(**stages):
    return {"mode": "terminal", "stages": stages}


def test_stage_screenshots_lists_captured_stages_with_matching_hashes():
    shots = evidence(before=fake_shot("before"), after=fake_shot("after", "rendered"),
                     rollback={"status": "UNAVAILABLE", "mode": "terminal", "format": "png",
                               "reason": "The test did not reach this stage, so no picture was taken."})
    files, html, text = stage_screenshots(shots)
    assert files == {"screenshots/before.png": png_for("before"), "screenshots/after.png": png_for("after")}
    assert "screenshots/before.png" in html and "screenshots/after.png" in html
    assert "Screenshot UNAVAILABLE: The test did not reach this stage" in html
    assert "screenshot UNAVAILABLE (The test did not reach this stage" in text
    assert f"PNG sha256 {sha(png_for('before'))}" in text and "real terminal (VHS)" in text
    assert "rendered evidence viewer" in text
    combined, _, _ = stage_screenshots(shots, "combined-")
    assert set(combined) == {"screenshots/combined-before.png", "screenshots/combined-after.png"}


@pytest.mark.parametrize("tamper", ["bytes", "not_png", "empty", "missing", "sha"])
def test_stage_screenshots_refuses_tampered_or_non_png_data(tamper):
    shot = fake_shot("after")
    if tamper == "bytes":
        shot["png_base64"] = base64.b64encode(png_for("after") + b"x").decode()
    elif tamper == "not_png":
        gif = b"GIF89a" + b"0" * 16
        shot.update(png_base64=base64.b64encode(gif).decode(), sha256=sha(gif))
    elif tamper == "empty":
        shot.update(png_base64="", sha256=sha(b""))
    elif tamper == "missing":
        del shot["png_base64"]
    else:
        shot["sha256"] = "0" * 64
    with pytest.raises(ContractError):
        stage_screenshots(evidence(after=shot))


def test_stage_screenshots_refuses_malformed_base64():
    shot = {**fake_shot("after"), "png_base64": "not base64 !!"}
    with pytest.raises((ContractError, ValueError)):  # binascii.Error is a ValueError
        stage_screenshots(evidence(after=shot))


@pytest.mark.parametrize("prefix", ["../", "x/", "combined-../", "/"])
def test_stage_screenshots_refuses_a_member_name_outside_the_fixed_set(prefix):
    with pytest.raises(ContractError):
        stage_screenshots(evidence(before=fake_shot("before")), prefix)


def test_stage_screenshots_ignores_unknown_stages_and_escapes_text():
    hostile = {**fake_shot("before"), "typed_command": "<script>alert(1)</script>", "reason": "<img src=x>"}
    files, html, _ = stage_screenshots(evidence(**{"before": hostile, "../evil": fake_shot("after"),
                                                   "during": fake_shot("after")}))
    assert set(files) == {"screenshots/before.png"}
    assert "<script>" not in html and "&lt;script&gt;" in html and "<img src=x>" not in html
    assert stage_screenshots(None) == ({}, "", "") and stage_screenshots({"stages": []}) == ({}, "", "")
    assert stage_screenshots({"mode": "terminal", "stages": {}}) == ({}, "", "")


def test_member_names_are_exactly_the_fixed_six():
    assert SCREENSHOT_MEMBERS == ("screenshots/before.png", "screenshots/after.png", "screenshots/rollback.png")
    assert COMBINED_SCREENSHOT_MEMBERS == ("screenshots/combined-before.png", "screenshots/combined-after.png",
                                           "screenshots/combined-rollback.png")


BASE_MEMBERS = {"harden.sh", "runner.py", "fix.json", "manifest.json", "evidence.json", "report.html", "README.txt",
                "risk-review.json", "visual_evidence.py", "verify.sh"}


def setting_bundle(recorded, engine, stages):  # noqa: F811
    result = copy.deepcopy(recorded["result"])
    if stages is not None:
        result["attempts"][-1]["terminal_evidence"] = evidence(**stages)
    data = build_review_bundle(SandboxHandoff(**recorded["handoff"]), result, engine)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        return data, {name: archive.read(name) for name in archive.namelist()}


def test_setting_bundle_lists_captured_stage_screenshots_in_its_manifest(recorded, engine, tmp_path):  # noqa: F811
    stages = {s: fake_shot(s) for s in ("before", "after", "rollback")}
    data, files = setting_bundle(recorded, engine, stages)
    assert set(files) == BASE_MEMBERS | set(SCREENSHOT_MEMBERS)
    manifest = json.loads(files["manifest.json"])
    for stage in ("before", "after", "rollback"):
        name = f"screenshots/{stage}.png"
        assert files[name] == png_for(stage)
        assert manifest["files"][name] == sha(files[name]) == stages[stage]["sha256"]
        assert name in files["README.txt"].decode() and f'src="{name}"' in files["report.html"].decode()
    # The exported runner accepts these members and their hashes (it then stops at the DSN).
    folder = tmp_path / "bundle"
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        archive.extractall(folder)
    out = run_runner(folder, json.loads(files["fix.json"])["fix_id"])
    assert out.returncode == 1 and "Set DBGUARD_DSN explicitly" in out.stderr, out.stderr


def test_setting_bundle_without_terminal_evidence_is_unchanged(recorded, engine):  # noqa: F811
    _, files = setting_bundle(recorded, engine, None)
    assert set(files) == BASE_MEMBERS
    assert b"Sandbox screenshots" not in files["report.html"] and b"screenshots/" not in files["README.txt"]


def test_setting_bundle_with_only_unavailable_stages_explains_why(recorded, engine):  # noqa: F811
    stages = {s: {"status": "UNAVAILABLE", "mode": "terminal", "format": "png", "stage": s,
                  "reason": "VHS, ttyd or ffmpeg is not installed"} for s in ("before", "after", "rollback")}
    _, files = setting_bundle(recorded, engine, stages)
    assert set(files) == BASE_MEMBERS
    assert files["README.txt"].decode().count("screenshot UNAVAILABLE (VHS, ttyd or ffmpeg is not installed)") == 3


@pytest.mark.parametrize("tamper", ["bytes", "not_png"])
def test_setting_bundle_refuses_a_tampered_screenshot(recorded, engine, tamper):  # noqa: F811
    shot = fake_shot("after")
    if tamper == "bytes":
        shot["png_base64"] = base64.b64encode(png_for("after")[:-1] + b"Z").decode()
    else:
        jpeg = b"\xff\xd8\xff\xe0" + b"0" * 16
        shot.update(png_base64=base64.b64encode(jpeg).decode(), sha256=sha(jpeg))
    with pytest.raises(ContractError):
        setting_bundle(recorded, engine, {"after": shot})


# ---------------------------------------------------------------------------
# 7. The DBA runner's manifest allowlist
# ---------------------------------------------------------------------------

def run_runner(folder, fix_id, *args):
    env = {"PATH": "/usr/bin:/bin"}  # no DBGUARD_DSN: the runner stops before any connection
    return subprocess.run([sys.executable, "-I", str(folder / "runner.py"), "status", fix_id, *args],
                          cwd=folder, env=env, capture_output=True, text=True, timeout=60)


def fake_bundle(tmp_path, members):
    folder = tmp_path / "bundle"
    folder.mkdir()
    shutil.copy(RUNNER, folder / "runner.py")
    (folder / "fix.json").write_text(json.dumps({"fix_id": "fix-unit"}))
    files = {"fix.json": (folder / "fix.json").read_bytes(), "runner.py": (folder / "runner.py").read_bytes()}
    for name in members:
        path = folder / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(png_for(name))
        files[name] = png_for(name)
    (folder / "manifest.json").write_text(json.dumps({"files": {n: sha(d) for n, d in files.items()}}))
    return folder


def test_runner_accepts_exactly_the_three_stage_screenshots(tmp_path):
    folder = fake_bundle(tmp_path, list(SCREENSHOT_MEMBERS))
    out = run_runner(folder, "fix-unit")
    assert out.returncode == 1 and "Set DBGUARD_DSN explicitly" in out.stderr, out.stderr


@pytest.mark.parametrize("member", [
    "screenshots/../x.png", "screenshots/before.PNG", "screenshots/other.png", "screenshots/before.png/",
    "../screenshots/before.png", "/screenshots/before.png", "screenshots//before.png", "before.png",
    "screenshots/combined-before.png", "screenshots/before.png.exe", "screenshots\\before.png"])
def test_runner_rejects_any_other_screenshot_member(tmp_path, member):
    folder = tmp_path / "bundle"
    folder.mkdir()
    shutil.copy(RUNNER, folder / "runner.py")
    (folder / "manifest.json").write_text(json.dumps({"files": {member: "0" * 64}}))
    out = run_runner(folder, "fix-unit")
    assert out.returncode == 1 and out.stderr.strip() == "Unexpected bundle member", out.stderr


def test_runner_refuses_a_changed_screenshot(tmp_path):
    folder = fake_bundle(tmp_path, list(SCREENSHOT_MEMBERS))
    (folder / "screenshots/after.png").write_bytes(PNG_MAGIC + b"edited")
    out = run_runner(folder, "fix-unit")
    assert out.returncode == 1 and out.stderr.strip() == "Bundle content changed: screenshots/after.png"


# ---------------------------------------------------------------------------
# 8. MCP: screenshot image data never reaches the model
# ---------------------------------------------------------------------------

def handoff_payload():
    shot = fake_shot("after")
    return {"handoff_id": "h-1", "status": "VERIFIED",
            "result": {"attempts": [
                {"attempt": 1, "terminal_evidence": {"mode": "terminal", "stages": {
                    "before": fake_shot("before"), "after": shot,
                    "rollback": {"status": "UNAVAILABLE", "mode": "terminal", "format": "png", "reason": "r"}}}},
                {"attempt": 2, "functional_checks": {"screenshot": {"status": "CAPTURED", "png_base64": "QUJD",
                                                                    "sha256": "a" * 64}}}]},
            "list": [[{"png_base64": "QUJD"}], "png_base64"],
            "empty": {"png_base64": ""}, "none": {"png_base64": None}, "png_base64_note": "QUJD"}


def test_without_images_replaces_only_png_data():
    from services.dbguard_mcp.server import IMAGE_OMITTED, _without_images
    payload = handoff_payload()
    original = copy.deepcopy(payload)
    out = _without_images(payload)
    assert payload == original  # the input is not mutated
    stages = out["result"]["attempts"][0]["terminal_evidence"]["stages"]
    from services.dbguard_mcp.server import EVIDENCE_OMITTED
    for stage in ("before", "after"):
        shot = original["result"]["attempts"][0]["terminal_evidence"]["stages"][stage]
        # Review N6: raw output, the SQL file and the typed command are omitted too.
        expected = {**shot, "png_base64": IMAGE_OMITTED,
                    **{k: EVIDENCE_OMITTED for k in ("raw_output", "sql", "typed_command") if shot.get(k)}}
        assert stages[stage] == expected  # sha256, status, mode, reason ... intact
    assert stages["rollback"] == original["result"]["attempts"][0]["terminal_evidence"]["stages"]["rollback"]
    assert out["result"]["attempts"][1]["functional_checks"]["screenshot"] == {
        "status": "CAPTURED", "png_base64": IMAGE_OMITTED, "sha256": "a" * 64}
    assert out["list"] == [[{"png_base64": IMAGE_OMITTED}], "png_base64"]
    assert out["empty"] == {"png_base64": ""} and out["none"] == {"png_base64": None}
    assert out["png_base64_note"] == "QUJD" and out["handoff_id"] == "h-1" and out["status"] == "VERIFIED"
    for scalar in (None, 1, "x", True, []):
        assert _without_images(scalar) == scalar
    text = json.dumps(out)
    assert fake_shot("after")["png_base64"] not in text and fake_shot("before")["png_base64"] not in text


@pytest.mark.parametrize("tool, method", [("run_sandbox_handoff", "POST"), ("get_sandbox_handoff_status", "GET")])
@pytest.mark.parametrize("backend", ["default", "demo"])
def test_both_handoff_tools_strip_images(monkeypatch, tool, method, backend):
    from services.dbguard_mcp import server
    monkeypatch.setenv("DBGUARD_DEMO_API_URL", "http://demo-api.invalid")
    payload = handoff_payload()
    response = Mock(status_code=200)
    response.json.return_value = copy.deepcopy(payload)
    request = Mock(return_value=response)
    monkeypatch.setattr(server.requests, "request", request)
    direct = getattr(server, tool)("h-1", backend=backend)
    assert request.call_args.args[0] == method and "/api/v1/sandbox/handoffs/h-1" in request.call_args.args[1]
    assert direct == server._without_images(payload) and direct["result"] != payload["result"]
    # Through the registered MCP tool as the model would call it.
    response.json.return_value = copy.deepcopy(payload)
    via_mcp = asyncio.run(server.mcp.call_tool(tool, {"handoff_id": "h-1", "backend": backend}))
    text = str(via_mcp)
    assert fake_shot("after")["png_base64"] not in text and fake_shot("before")["png_base64"] not in text
    assert "QUJD" in text  # only the unrelated *_note field keeps its value
    assert fake_shot("after")["sha256"] in text


def test_mcp_tool_surface_is_unchanged_by_the_image_filter():
    import inspect
    from services.dbguard_mcp import server
    tools = asyncio.run(server.mcp.list_tools())
    # The filter adds no tool: exactly the existing eleven operations.
    assert sorted(t.name for t in tools) == [
        "get_demo_workflow_context", "get_fix_risk_plan", "get_sandbox_handoff_status", "get_snapshot_assessment",
        "get_snapshot_context", "get_snapshot_spec_assessment", "prepare_sandbox_handoff", "run_sandbox_handoff",
        "search_approved_knowledge", "search_approved_templates", "validate_and_render_proposal"]
    for tool in ("run_sandbox_handoff", "get_sandbox_handoff_status"):
        assert list(inspect.signature(getattr(server, tool)).parameters) == ["handoff_id", "backend"]
        schema = next(t for t in tools if t.name == tool).input_schema
        assert set(schema["properties"]) == {"handoff_id", "backend"}


# ---------------------------------------------------------------------------
# The demo switches terminal mode on (the default stays rendered)
# ---------------------------------------------------------------------------

def test_demo_enables_terminal_mode_alongside_screenshots():
    text = (ROOT / "scripts/demo.py").read_text()
    on = text.index("self.env['DBGUARD_SCREENSHOTS'] = 'true'")
    # Re-review: terminal is the demo default, but an explicit environment / .env.demo value wins.
    mode = text.index("self.env.setdefault('DBGUARD_SCREENSHOT_MODE', 'terminal')")
    assert 0 < mode - on < 300
    assert "self.env['DBGUARD_SCREENSHOT_MODE']" not in text


def test_demo_notice_names_the_variable_and_prints_only_in_terminal_mode():
    import importlib.util
    spec = importlib.util.spec_from_file_location("demo_script_under_test", ROOT / "scripts/demo.py")
    demo = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(demo)
    assert "DBGUARD_SCREENSHOT_MODE=rendered" in demo.TERMINAL_SCREENSHOT_NOTICE
    assert "127.0.0.1" in demo.TERMINAL_SCREENSHOT_NOTICE
    text = (ROOT / "scripts/demo.py").read_text()
    guard = text.index("if self.env.get('DBGUARD_SCREENSHOT_MODE') == 'terminal':")
    assert text.index("print(TERMINAL_SCREENSHOT_NOTICE", guard) - guard < 120
    assert text.count("print(TERMINAL_SCREENSHOT_NOTICE") == 1
