"""Live Task 2 terminal (VHS) screenshots for a catalog-linked fix (CIS 3.2, pgaudit).

    DBGUARD_POC_LIVE=1 .venv-demo/bin/python -m pytest tests/test_terminal_capture_catalog_live.py

Uses the W2B live fixtures (pinned pgaudit image, in-file TEST profile). 3.2 changes two
settings and needs a restart; pgaudit.log is undefined before the fix, so the picture
reads it with current_setting(..., true) instead of SHOW. Cleanup is checked by this
test's own run IDs only.
"""
import base64
import hashlib
import json
import os

import pytest

from scripts.sandbox_poc import demo_template
from services.sandbox_poc import catalog_fixes as cf
from tests.test_catalog_fixes_w2b import list_template
from tests.test_catalog_fixes_w2b_live import SID, assert_proof, bundle, engine, image, source  # noqa: F401
from tests.test_terminal_capture_live import (STAGES, Recorder, assert_removed, assert_terminal_stages,  # noqa: F401
                                              output_of, save, terminal_mode)

pytestmark = pytest.mark.skipif(os.environ.get("DBGUARD_POC_LIVE") != "1",
                                reason="Set DBGUARD_POC_LIVE=1 with Docker, VHS, ttyd and ffmpeg")


def test_3_2_catalog_fix_produces_three_terminal_pictures(terminal_mode, engine, source, image):  # noqa: F811
    snapshot, assessment = source
    recorder = Recorder()
    try:
        result = cf.CatalogFixLoop(engine, demo_template(), lambda: recorder(image), control_id=SID["3.2"],
                                   list_template=list_template()).run(snapshot, assessment)
    finally:
        assert_removed(recorder.created)
    attempt = assert_proof(result)  # FAIL -> PASS -> FAIL, rollback verified, cleanup verified
    assert attempt["pgaudit_log_shown"] == "ddl,role,write"
    stages = assert_terminal_stages(attempt["terminal_evidence"], attempt["run_id"])
    save("catalog-3.2", stages)
    pgaudit = "Effective value of pgaudit.log"
    assert [output_of(stages[s], pgaudit) for s in STAGES] == ["", "ddl,role,write", ""]
    assert "SELECT pg_catalog.current_setting('pgaudit.log', true)" in stages["before"]["sql"]
    preload = [output_of(stages[s], "Effective value of shared_preload_libraries") for s in STAGES]
    assert "pgaudit" not in preload[0] and "pgaudit" in preload[1] and preload[2] == preload[0]
    # The DBA bundle lists the three pictures with matching hashes in its manifest.
    files = bundle(engine, source, "3.2", result)
    manifest = json.loads(files["manifest.json"])
    for stage in STAGES:
        name = f"screenshots/{stage}.png"
        png = files[name]
        assert png == base64.b64decode(stages[stage]["png_base64"])
        assert hashlib.sha256(png).hexdigest() == manifest["files"][name] == stages[stage]["sha256"]
    assert "screenshots/after.png" in files["README.txt"].decode()
