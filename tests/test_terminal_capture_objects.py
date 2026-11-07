"""Task 2 terminal screenshots: the per-object loop and combined (batch) tests.

Fake object sandboxes from test_object_sandbox (no Docker, VHS or browser). A combined
test takes three pictures for the whole batch (before once, after all fixes, after the
rollback), with the taller geometry, and its bundle lists them in a top-level manifest.
"""
import base64
import copy
import hashlib
import io
import json
import subprocess
import sys
import zipfile

import pytest

from services.sandbox_poc import batch as batch_module
from services.sandbox_poc import profiles
from services.sandbox_poc import terminal_capture as tc
from services.sandbox_poc.shared import SpecEngine
from tests.test_object_sandbox import (batch_service, engine, planted, props, run_object,  # noqa: F401
                                       snapshot)

TERMINAL_ENV = {"DBGUARD_SCREENSHOTS": "true", "DBGUARD_SCREENSHOT_MODE": "terminal"}
PNG_MAGIC = b"\x89PNG\r\n\x1a\n"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def png_for(run_id, stage):
    return PNG_MAGIC + f"{run_id}:{stage}".encode()


class Spy:
    def __init__(self, raises=None):
        self.calls, self.raises = [], raises

    def __call__(self, runtime, stage, targets, geometry="single"):
        self.calls.append({"run_id": runtime.run_id, "stage": stage, "targets": copy.deepcopy(targets),
                           "geometry": geometry, "closed": runtime.closed, "executed": len(runtime.executed)})
        if self.raises:
            raise self.raises
        png = png_for(runtime.run_id, stage)
        return {"status": "CAPTURED", "mode": "terminal", "format": "png", "stage": stage,
                "stage_label": tc.STAGES[stage], "sha256": sha(png), "png_base64": base64.b64encode(png).decode(),
                "typed_command": "docker exec -i x psql", "sql": tc.READ_ONLY_LINE + "\nSELECT 1;\n",
                "tools": {"vhs": "v", "ttyd": "t", "ffmpeg": "f"}}


def set_terminal(monkeypatch, on=True):
    for key, value in TERMINAL_ENV.items():
        if on:
            monkeypatch.setenv(key, value)
        else:
            monkeypatch.delenv(key, raising=False)


def verdict(result, runtimes):
    return (result["status"], len(result["attempts"]),
            [(a["status"], a["phase"], a["rollback_verified"], a.get("error"), a.get("cleanup"),
              a.get("apply_or_assessment_error")) for a in result["attempts"]],
            [r.closed for r in runtimes])


# ---------------------------------------------------------------------------
# Per-object loop
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("index", range(5))
def test_object_loop_records_the_one_object_at_three_stages(engine, planted, props, monkeypatch, index):  # noqa: F811
    set_terminal(monkeypatch)
    spy = Spy()
    monkeypatch.setattr(tc, "capture_stage", spy)
    proposal = props[index]
    result, runtimes = run_object(engine, planted, proposal, [None])
    assert result["status"] == "VERIFIED"
    assert [c["stage"] for c in spy.calls] == ["before", "after", "rollback"]
    assert all(c["targets"] == {"settings": [], "objects": [proposal]} and c["geometry"] == "single"
               and c["closed"] is False for c in spy.calls)
    executed = runtimes[0].executed
    apply = next(i for i, s in enumerate(executed) if s.startswith("BEGIN;\n") and "CREATE ROLE" not in s)
    rollback = max(i for i, s in enumerate(executed) if s.startswith("BEGIN;\n"))
    before, after, back = (c["executed"] for c in spy.calls)
    assert before <= apply < after <= rollback < back
    stages = result["attempts"][-1]["terminal_evidence"]["stages"]
    assert [stages[s]["sha256"] for s in ("before", "after", "rollback")] == [
        sha(png_for(runtimes[0].run_id, s)) for s in ("before", "after", "rollback")]


@pytest.mark.parametrize("fault", [None, "apply_error", "verify", "rollback", "other", "reproduce", "create",
                                   "cleanup"])
def test_capture_failures_never_change_the_object_verdict(engine, planted, props, monkeypatch, fault):  # noqa: F811
    set_terminal(monkeypatch, on=False)
    baseline = verdict(*run_object(engine, copy.deepcopy(planted), props[1], [fault]))
    set_terminal(monkeypatch)
    monkeypatch.setattr(tc, "capture_stage", Spy(raises=RuntimeError("VHS exploded")))
    result, runtimes = run_object(engine, copy.deepcopy(planted), props[1], [fault])
    assert verdict(result, runtimes) == baseline
    for attempt in result["attempts"]:
        stages = attempt["terminal_evidence"]["stages"]
        assert set(stages) == {"before", "after", "rollback"}
        assert all(s["status"] == "UNAVAILABLE" and "png_base64" not in s for s in stages.values())


@pytest.mark.parametrize("fault", ["apply_error", "verify", "rollback", "reproduce", "create"])
def test_object_unreached_stages_are_unavailable(engine, planted, props, monkeypatch, fault):  # noqa: F811
    set_terminal(monkeypatch)
    monkeypatch.setattr(tc, "capture_stage", Spy())
    result, runtimes = run_object(engine, planted, props[1], [fault])
    assert result["status"] != "VERIFIED" and all(r.closed for r in runtimes)
    for attempt in result["attempts"]:
        stages = attempt["terminal_evidence"]["stages"]
        if stages["rollback"]["status"] == "CAPTURED":
            assert attempt["rollback_verified"] is True
        if stages["after"]["status"] == "CAPTURED":
            assert attempt.get("predicate_after_apply") and "apply_or_assessment_error" not in attempt
        for name, shot in stages.items():
            if shot["status"] != "CAPTURED":
                assert shot["reason"] == "The test did not reach this stage, so no picture was taken."
    if fault in ("reproduce", "create"):
        assert all(s["status"] == "UNAVAILABLE" for a in result["attempts"]
                   for s in a["terminal_evidence"]["stages"].values())


def test_object_loop_in_rendered_mode_has_no_terminal_evidence(engine, planted, props, monkeypatch):  # noqa: F811
    set_terminal(monkeypatch, on=False)
    monkeypatch.setenv("DBGUARD_SCREENSHOTS", "true")
    spy = Spy()
    monkeypatch.setattr(tc, "capture_stage", spy)
    result, _ = run_object(engine, planted, props[0], [None])
    assert result["status"] == "VERIFIED" and spy.calls == []
    assert "terminal_evidence" not in json.dumps(result)


# ---------------------------------------------------------------------------
# Combined (batch) test
# ---------------------------------------------------------------------------

def run_batch(engine, planted, monkeypatch, tmp_path, faults=None):  # noqa: F811
    monkeypatch.setattr(profiles, "resolve_profile", lambda records, specs, ref: engine.policy)
    monkeypatch.setenv("DBGUARD_HISTORY_DIR", str(tmp_path / "history"))
    monkeypatch.setattr(SpecEngine, "collect", lambda self, runtime: copy.deepcopy(runtime.snapshot))
    service, requests, runtimes, proposals = batch_service(engine, copy.deepcopy(planted), faults)
    output, data = batch_module.run_batch(requests, service)
    return output, data, runtimes, proposals


def test_combined_test_takes_three_pictures_for_the_whole_batch(engine, planted, monkeypatch, tmp_path):  # noqa: F811
    set_terminal(monkeypatch)
    spy = Spy()
    monkeypatch.setattr(tc, "capture_stage", spy)
    output, data, runtimes, proposals = run_batch(engine, planted, monkeypatch, tmp_path)
    combined = output["combined_test"]
    assert output["status"] == "VERIFIED", combined.get("reason") or combined.get("rollback_error")
    combined_id = runtimes[-1].run_id
    assert combined["run_id"] == combined_id
    combined_calls = [c for c in spy.calls if c["run_id"] == combined_id]
    # Before once, after all fixes, after the rollback: not one per step.
    assert [c["stage"] for c in combined_calls] == ["before", "after", "rollback"]
    assert all(c["geometry"] == "combined" and c["closed"] is False for c in combined_calls)
    assert all(c["targets"]["settings"] == [] and
               sorted(p["fix_id"] for p in c["targets"]["objects"]) == sorted(p["fix_id"] for p in proposals)
               for c in combined_calls)
    executed = runtimes[-1].executed
    applies = [i for i, s in enumerate(executed) if s.startswith("BEGIN;\nALTER") or s.startswith("BEGIN;\nREVOKE")]
    before, after, back = (c["executed"] for c in combined_calls)
    assert before <= applies[0] and applies[len(proposals) - 1] < after < back
    # Each individual run took its own three single-geometry pictures.
    for runtime in runtimes[:-1]:
        own = [c for c in spy.calls if c["run_id"] == runtime.run_id]
        assert [c["stage"] for c in own] == ["before", "after", "rollback"]
        assert all(c["geometry"] == "single" for c in own)
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        files = {name: z.read(name) for name in z.namelist()}
    manifest = json.loads(files["manifest.json"])
    shots = {f"screenshots/combined-{s}.png": png_for(combined_id, s) for s in ("before", "after", "rollback")}
    assert set(manifest["files"]) == {"combined-evidence.json", "report.html", *shots}
    for name, png in shots.items():
        assert files[name] == png and manifest["files"][name] == sha(png)
        assert name in files["README.txt"].decode() and f'src="{name}"' in files["report.html"].decode()
    assert manifest["files"]["report.html"] == sha(files["report.html"])
    assert manifest["files"]["combined-evidence.json"] == sha(files["combined-evidence.json"])
    assert not any(n.startswith("screenshots/") and n not in shots for n in files)
    # Per-fix folders carry that fix's own isolated-test pictures in their own manifest.
    sandboxes = []
    for result in output["individual_runs"]:
        prefix = result["fix_id"] + "/"
        fix_manifest = json.loads(files[prefix + "manifest.json"])
        sandbox = json.loads(files[prefix + "evidence.json"])["result"]["attempts"][-1]["run_id"]
        sandboxes.append(sandbox)
        for stage in ("before", "after", "rollback"):
            member = f"screenshots/{stage}.png"
            assert files[prefix + member] == png_for(sandbox, stage)
            assert fix_manifest["files"][member] == sha(files[prefix + member])
    assert sorted(sandboxes) == sorted(r.run_id for r in runtimes[:-1])
    # The per-fix DBA runner accepts its manifest, screenshots included (then stops at the DSN).
    folder = tmp_path / "unzipped"
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        z.extractall(folder)
    first = folder / output["individual_runs"][0]["fix_id"]
    out = subprocess.run([sys.executable, "-I", str(first / "runner.py"), "status", output["individual_runs"][0]["fix_id"]],
                         cwd=first, env={"PATH": "/usr/bin:/bin"}, capture_output=True, text=True, timeout=60)
    assert out.returncode == 1 and "Set DBGUARD_DSN explicitly" in out.stderr, out.stderr


def test_combined_capture_failure_keeps_the_batch_verdict_and_adds_no_files(engine, planted, monkeypatch, tmp_path):  # noqa: F811
    set_terminal(monkeypatch, on=False)
    base, base_data, base_runtimes, _ = run_batch(engine, planted, monkeypatch, tmp_path)
    set_terminal(monkeypatch)
    monkeypatch.setattr(tc, "capture_stage", Spy(raises=RuntimeError("VHS exploded")))
    output, data, runtimes, _ = run_batch(engine, planted, monkeypatch, tmp_path)
    assert output["status"] == base["status"] == "VERIFIED"
    assert [r["status"] for r in output["individual_runs"]] == [r["status"] for r in base["individual_runs"]]
    assert output["combined_test"]["rollback"] == base["combined_test"]["rollback"]
    assert all(r.closed for r in runtimes)
    stages = output["combined_test"]["terminal_evidence"]["stages"]
    assert set(stages) == {"before", "after", "rollback"}
    assert all(s["status"] == "UNAVAILABLE" for s in stages.values())
    with zipfile.ZipFile(io.BytesIO(data)) as z, zipfile.ZipFile(io.BytesIO(base_data)) as b:
        assert set(z.namelist()) == set(b.namelist())
        assert not any("screenshots/" in n for n in z.namelist()) and "manifest.json" not in z.namelist()


def test_combined_failure_marks_unreached_stages_and_keeps_its_verdict(engine, planted, monkeypatch, tmp_path):  # noqa: F811
    set_terminal(monkeypatch, on=False)
    base, _, _, _ = run_batch(engine, planted, monkeypatch, tmp_path, faults={4: "apply_error"})
    set_terminal(monkeypatch)
    monkeypatch.setattr(tc, "capture_stage", Spy())
    output, data, runtimes, _ = run_batch(engine, planted, monkeypatch, tmp_path, faults={4: "apply_error"})
    assert output["status"] == base["status"] != "VERIFIED" and data is None
    assert output["combined_test"].get("reason") == base["combined_test"].get("reason")
    assert all(r.closed for r in runtimes)
    stages = output["combined_test"]["terminal_evidence"]["stages"]
    assert stages["before"]["status"] == "CAPTURED"
    assert stages["after"]["status"] == "UNAVAILABLE" and "did not reach" in stages["after"]["reason"]


def test_combined_targets_merge_settings_catalog_changes_and_objects():
    setting = {"kind": "setting", "fix_unit": {"apply": {"param": "log_connections"}}}
    catalog = {"kind": "catalog_setting", "fix_unit": {"changes": [{"param": "shared_preload_libraries"},
                                                                   {"param": "pgaudit.log"}]}}
    again = {"kind": "setting", "fix_unit": {"apply": {"param": "log_connections"}}}
    obj = {"kind": "object", "proposal": {"fix_type": "role_nologin", "target": {"role": "web"}}}
    assert batch_module._combined_targets([setting, catalog, again, obj]) == {
        "settings": ["log_connections", "shared_preload_libraries", "pgaudit.log"],
        "objects": [obj["proposal"]]}
    # Anything malformed means no terminal picture at all (None is refused by capture_stage).
    assert batch_module._combined_targets([{"kind": "setting", "fix_unit": {}}]) is None
    assert tc.capture_stage(object(), "before", None)["status"] == "UNAVAILABLE"
