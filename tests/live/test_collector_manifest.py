"""Live tests: the collector answers a check manifest (snapshot v0.3.0).

Every test runs the REAL wrapper, `bash collector/dbguard-collect.sh`, against
pg-target, exactly as a DBA would run it. Connection details come from
PG_TARGET_URL and are passed as libpq environment variables; the URL is never
printed, not even on failure.

What these tests pin down:
  * output validates against snapshot-v0.3.0.json, shape {envelope, baseline, checks}
  * provenance: the envelope hashes match the actual files
  * the manifest is data only: an injection attempt is just an unknown setting
  * redaction: a secret in a sensitive setting appears nowhere in the output
  * runtime problems (unknown setting, unsupported kind) fail ONE check;
    a malformed manifest refuses the WHOLE run and writes nothing
"""
import copy
import hashlib
import json
import os
import subprocess
import time
from pathlib import Path
from urllib.parse import unquote, urlsplit

import jsonschema
import psycopg2
import pytest

pytestmark = pytest.mark.live

REPO_ROOT = Path(__file__).resolve().parents[2]
COLLECTOR = REPO_ROOT / "collector" / "dbguard-collect.sh"
COLLECT_SQL = REPO_ROOT / "collector" / "collect.sql"
SCHEMA = json.loads(
    (REPO_ROOT / "catalog" / "specs" / "contracts" / "snapshot-v0.3.0.json").read_text(encoding="utf-8")
)
GOLDEN = json.loads(
    (REPO_ROOT / "tests" / "fixtures" / "phase1" / "checks-cis-pg17-v1.1.0.json").read_text(encoding="utf-8")
)
DEFAULT_MANIFEST_TEXT = '{"manifest_version":1,"checks":[]}'
FAKE_SECRET = "s3cr3t-9f8e7d6c"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _target_url() -> str:
    url = os.environ.get("PG_TARGET_URL")
    if not url:
        pytest.fail("PG_TARGET_URL is not set")
    return url


def _libpq_env() -> dict:
    """PG* variables for the wrapper. Never includes the URL in any message."""
    parts = urlsplit(_target_url())
    if parts.hostname is None or parts.username is None:
        pytest.fail("PG_TARGET_URL could not be parsed (value not shown)")
    env = os.environ.copy()
    env.update(
        PGHOST=parts.hostname,
        PGPORT=str(parts.port or 5432),
        PGUSER=unquote(parts.username),
        PGPASSWORD=unquote(parts.password or ""),
        PGDATABASE=parts.path.lstrip("/") or "postgres",
    )
    return env


def _sql(query: str, fetch: bool = False):
    """Run one statement on a fresh autocommit connection (ALTER SYSTEM needs it)."""
    conn = psycopg2.connect(_target_url())
    try:
        conn.autocommit = True
        with conn.cursor() as cur:
            cur.execute(query)
            return cur.fetchone()[0] if fetch else None
    finally:
        conn.close()


def _set_and_wait(setting_name: str, value: str | None) -> None:
    """ALTER SYSTEM SET (or RESET when value is None), reload, and wait until a
    NEW connection sees it -- the collector opens a new connection, and a reload
    is asynchronous."""
    if value is None:
        _sql(f"ALTER SYSTEM RESET {setting_name}")
    else:
        _sql(f"ALTER SYSTEM SET {setting_name} = '{value.replace(chr(39), chr(39) * 2)}'")
    _sql("SELECT pg_reload_conf()")
    want = value if value is not None else _sql(f"SELECT boot_val FROM pg_settings WHERE name = '{setting_name}'", fetch=True)
    for _ in range(50):
        if _sql(f"SHOW {setting_name}", fetch=True) == want:
            return
        time.sleep(0.1)
    pytest.fail(f"{setting_name} did not take effect after reload")


def run_collector(tmp_path: Path, manifest: dict | None):
    """Run the real wrapper. Returns (CompletedProcess, out_path, manifest_path)."""
    out = tmp_path / "snapshot.json"
    cmd = ["bash", str(COLLECTOR), "-t", "live-test", "-o", str(out)]
    manifest_path = None
    if manifest is not None:
        manifest_path = tmp_path / "manifest.json"
        manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
        cmd += ["-m", str(manifest_path)]
    proc = subprocess.run(cmd, capture_output=True, text=True, env=_libpq_env(), timeout=120)
    return proc, out, manifest_path


def collect_ok(tmp_path: Path, manifest: dict | None) -> tuple[dict, Path | None]:
    """Run the collector, require success, validate against the contract."""
    proc, out, manifest_path = run_collector(tmp_path, manifest)
    assert proc.returncode == 0, f"collector failed (exit {proc.returncode}):\n{proc.stderr}"
    snapshot = json.loads(out.read_text(encoding="utf-8"))
    jsonschema.validate(snapshot, SCHEMA)
    return snapshot, manifest_path


def entry(spec_id: str, setting_name: str, kind: str = "setting") -> dict:
    return {
        "spec_id": spec_id,
        "spec_hash": "0" * 64,
        "kind": kind,
        "setting_name": setting_name,
        "query": f"SHOW {setting_name}",
    }


# ---------------------------------------------------------------------------
# happy path, shape and provenance
# ---------------------------------------------------------------------------

class TestCollectorManifest:

    def test_golden_manifest_answers_every_check(self, target_db, tmp_path):
        snapshot, _ = collect_ok(tmp_path, GOLDEN)

        assert set(snapshot) == {"envelope", "baseline", "checks"}
        assert set(snapshot["checks"]) == {c["spec_id"] for c in GOLDEN["checks"]}
        for c in GOLDEN["checks"]:
            got = snapshot["checks"][c["spec_id"]]
            assert got["status"] == "ok", (c["spec_id"], got)
            assert got["spec_hash"] == c["spec_hash"]
            assert got["query"] == c["query"]
            # the answer equals what SHOW returns on a fresh connection
            assert got["result"] == _sql(f"SHOW {c['setting_name']}", fetch=True), c["spec_id"]

    def test_provenance_matches_the_actual_files(self, target_db, tmp_path):
        snapshot, manifest_path = collect_ok(tmp_path, GOLDEN)
        env = snapshot["envelope"]

        assert env["schema_version"] == "0.3.0"
        assert env["collector_sha256"] == hashlib.sha256(COLLECT_SQL.read_bytes()).hexdigest()
        assert env["manifest"]["sha256"] == hashlib.sha256(manifest_path.read_bytes()).hexdigest()
        assert env["manifest"]["manifest_version"] == 1
        assert env["manifest"]["benchmark_id"] == GOLDEN["benchmark_id"]
        assert env["manifest"]["check_count"] == len(GOLDEN["checks"]) == len(snapshot["checks"])

    def test_no_manifest_collects_baseline_only(self, target_db, tmp_path):
        snapshot, _ = collect_ok(tmp_path, None)

        assert snapshot["checks"] == {}
        assert "settings" in snapshot["baseline"]
        m = snapshot["envelope"]["manifest"]
        assert m["check_count"] == 0
        assert m["benchmark_id"] is None
        assert m["sha256"] == hashlib.sha256(DEFAULT_MANIFEST_TEXT.encode()).hexdigest()

    # -----------------------------------------------------------------------
    # runtime problems: ONE check fails, the rest still run
    # -----------------------------------------------------------------------

    def test_unknown_setting_fails_only_its_own_check(self, target_db, tmp_path):
        """The bad entry sits in the MIDDLE. If per-check state were not reset,
        the entry after it would inherit its error, or it would inherit the
        previous entry's value as its 'error'."""
        manifest = copy.deepcopy(GOLDEN)
        manifest["checks"].insert(1, entry("test:unknown", "no_such_setting_xyz"))

        snapshot, _ = collect_ok(tmp_path, manifest)

        bad = snapshot["checks"]["test:unknown"]
        assert bad["status"] == "error"
        assert "unrecognized configuration parameter" in bad["error"], bad
        assert "result" not in bad
        for c in GOLDEN["checks"]:
            got = snapshot["checks"][c["spec_id"]]
            assert got["status"] == "ok", (c["spec_id"], got)
            assert "error" not in got

    def test_unsupported_kind_fails_only_its_own_check(self, target_db, tmp_path):
        manifest = {
            "manifest_version": 1,
            "benchmark_id": "test",
            "checks": [
                entry("test:good", "log_connections"),
                entry("test:future", "log_connections", kind="role_attribute"),
                entry("test:good2", "log_disconnections"),
            ],
        }
        snapshot, _ = collect_ok(tmp_path, manifest)

        assert snapshot["checks"]["test:future"] == {
            "spec_hash": "0" * 64,
            "query": "SHOW log_connections",
            "status": "error",
            "error": "unsupported kind: role_attribute",
        }
        assert snapshot["checks"]["test:good"]["status"] == "ok"
        assert snapshot["checks"]["test:good2"]["status"] == "ok"

    # -----------------------------------------------------------------------
    # safety: the manifest is data, secrets stay out
    # -----------------------------------------------------------------------

    def test_injection_is_just_an_unknown_setting(self, target_db, tmp_path):
        before = _sql("SELECT count(*) FROM dbguard_canary", fetch=True)
        assert before > 0

        hostile = "log_connections'); DROP TABLE dbguard_canary; --"
        manifest = {"manifest_version": 1, "benchmark_id": "test",
                    "checks": [entry("test:injection", hostile)]}
        snapshot, _ = collect_ok(tmp_path, manifest)

        got = snapshot["checks"]["test:injection"]
        assert got["status"] == "error"
        assert "unrecognized configuration parameter" in got["error"]
        assert _sql("SELECT count(*) FROM dbguard_canary", fetch=True) == before

    @pytest.mark.parametrize(
        "setting_name, value",
        [
            # shapes that sanitise_setting/mask_secrets actually redact
            # not archive_command: SHOW displays it as "(disabled)" while archive_mode=off
            ("archive_cleanup_command", f"cp rclone://backup:{FAKE_SECRET}@bucket/%r /tmp"),
            ("ssl_passphrase_command", f"echo password={FAKE_SECRET}"),
        ],
    )
    def test_secret_in_sensitive_setting_never_reaches_output(self, target_db, tmp_path, setting_name, value):
        _set_and_wait(setting_name, value)
        try:
            manifest = {"manifest_version": 1, "benchmark_id": "test",
                        "checks": [entry("test:secret", setting_name)]}
            proc, out, _ = run_collector(tmp_path, manifest)
            assert proc.returncode == 0, proc.stderr

            raw = out.read_text(encoding="utf-8")
            # anywhere in the file: checks AND baseline
            assert FAKE_SECRET not in raw
            got = json.loads(raw)["checks"]["test:secret"]
            assert got["status"] == "ok"
            assert "***REDACTED***" in got["result"], got
        finally:
            _set_and_wait(setting_name, None)

    # -----------------------------------------------------------------------
    # malformed manifest: the WHOLE run refuses and writes nothing
    # -----------------------------------------------------------------------

    @pytest.mark.parametrize(
        "field, expected",
        [
            ("spec_id", "entry 1 has no spec_id"),
            ("spec_hash", "has no spec_hash"),
            ("kind", "has no kind"),
            ("query", "has no query"),
            ("setting_name", "has no setting_name"),
        ],
    )
    def test_missing_field_refuses_whole_run(self, target_db, tmp_path, field, expected):
        bad = entry("test:bad", "log_connections")
        del bad[field]
        proc, out, _ = run_collector(tmp_path, {"manifest_version": 1, "benchmark_id": "t", "checks": [bad]})

        assert proc.returncode != 0
        assert "MANIFEST_INVALID" in proc.stderr and expected in proc.stderr, proc.stderr
        assert not out.exists(), "a refused run must not write a snapshot"

    def test_duplicate_spec_id_refuses_whole_run(self, target_db, tmp_path):
        manifest = {"manifest_version": 1, "benchmark_id": "t",
                    "checks": [entry("test:dup", "log_connections"), entry("test:dup", "log_statement")]}
        proc, out, _ = run_collector(tmp_path, manifest)

        assert proc.returncode != 0
        assert "MANIFEST_INVALID" in proc.stderr and "repeats spec_id" in proc.stderr, proc.stderr
        assert not out.exists()

    def test_unknown_manifest_version_refuses_whole_run(self, target_db, tmp_path):
        proc, out, _ = run_collector(tmp_path, {"manifest_version": 2, "benchmark_id": "t", "checks": []})

        assert proc.returncode != 0
        assert "MANIFEST_INVALID" in proc.stderr and "manifest_version must be 1" in proc.stderr, proc.stderr
        assert not out.exists()
